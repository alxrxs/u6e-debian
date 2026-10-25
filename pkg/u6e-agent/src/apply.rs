//! A new Wi-Fi configuration from the deploy runner, relayed by the
//! controller (`ApplyConfig`), applied the least disruptive way each radio
//! allows. It is the only way the radios' configuration changes, so the hash
//! the snapshots carry always says what runs.
//!
//! Nothing is installed before the whole request passes: the runner's
//! signature over it, for this AP, with a sequence number past the last one
//! applied and the image's build time and within its validity by a
//! synchronized clock (no replay, not even after a reboot), its SHA-256, each
//! radio's file, and any new channel or power one the radio may take now
//! (nl80211's channels and rules; never a DFS channel that needs a CAC
//! first). The installed configuration is the root helper's alone (it holds
//! the secrets), so the helper says how each radio takes the new one
//! (`wificonf::class`): nothing; BSS settings hostapd rereads at each use,
//! which the agent `SET`s on their BSS before rebuilding its beacons; the
//! channel or width, a channel switch announcement; the power alone, which
//! the helper sets; anything else, a restart of u6e-wifi by the helper, after
//! every client is asked to move to the other AP.
//! hostapd's own reloads would not do: RELOAD re-reads no file and
//! deauthenticates every station of the radio; RELOAD_CONFIG re-reads it but
//! deauthenticates the stations of every BSS without an unchanged
//! `config_id`, keeps the old channel, and re-keys every BSS's group without
//! telling its stations, which breaks beacon protection (hostapd.c
//! `hostapd_reload_config`, wpa_auth.c `wpa_reconfig`). A step that fails is
//! undone and the helper puts the previous configuration back.
//!
//! The configuration passes through the agent in memory only: it goes to the
//! helper's socket, nowhere else, is never shown (`RadioConfig`'s `Debug`
//! leaves the text out) and is wiped when dropped. Applies run on a thread
//! of their own ([`Worker`]): a restart takes the better part of a minute,
//! and the link goes on meanwhile.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use u6e_proto::config;
use u6e_proto::msg::{Band, ConfigApplied, Mechanism, RadioApplied, SignedConfig, Snapshot};

use crate::command::steer_request;
use crate::helper::{self, Reply, Request};
use crate::link::ConfigApplier;
use crate::neighbors::{Hostapd, Target};
use crate::nl80211::{self, Nl80211};
use crate::regdomain::{self, RadioState, Switch};
use crate::wificonf::{self, Class, Conf, Set};

/// Beacons a channel switch is announced in before it happens.
pub const CS_COUNT: u32 = 5;
/// How long a switch may take: [`CS_COUNT`] beacons and some.
const SWITCH_WAIT: Duration = Duration::from_secs(2);
/// Time the steered clients get to move before u6e-wifi restarts.
const STEER_GRACE: Duration = Duration::from_secs(3);
const DETAIL_MAX: usize = 1000;

/// What reads a radio's channels, capabilities and rules.
pub trait Phy: Send {
    fn radio(&mut self, band: Band) -> Result<RadioState, String>;
}

/// [`Phy`] by nl80211; a socket that fails is opened afresh next time.
#[derive(Default)]
pub struct NlPhy {
    nl: Option<Nl80211>,
}

impl Phy for NlPhy {
    fn radio(&mut self, band: Band) -> Result<RadioState, String> {
        let r = self.read(band);
        if r.is_err() {
            self.nl = None;
        }
        r.map_err(|e| format!("{}: nl80211: {e}", wificonf::iface(band)))
    }
}

impl NlPhy {
    fn read(&mut self, band: Band) -> io::Result<RadioState> {
        let nl = match &mut self.nl {
            Some(nl) => nl,
            None => self.nl.insert(Nl80211::open()?),
        };
        let name = wificonf::iface(band);
        let iface = nl
            .interfaces()?
            .into_iter()
            .find(|i| i.name == name)
            .ok_or_else(|| io::Error::other("no such interface"))?;
        let caps = nl80211::parse_band(nl.dump_wiphy(iface.wiphy)?, band);
        let rules = nl80211::parse_reg(nl.get_reg(iface.wiphy)?);
        Ok(RadioState {
            caps,
            rules,
            freq_mhz: iface.freq_mhz,
            width_mhz: iface.width_mhz,
            center_mhz: iface.center_mhz,
        })
    }
}

/// Switches the radio of `band` as `s` says, announced over [`CS_COUNT`]
/// beacons, and waits up to `wait` for it to operate there. The modes of
/// the switch are those the radio runs.
fn switch(h: &mut Hostapd, band: Band, s: &Switch, wait: Duration) -> Result<String, String> {
    let iface = wificonf::iface(band);
    let status = h
        .try_request(iface, "STATUS")
        .map_err(|e| format!("{iface}: {e}"))?;
    let mut cmd = format!("CHAN_SWITCH {CS_COUNT} {}", s.freq_mhz);
    if s.width_mhz > 20 {
        cmd += &format!(
            " sec_channel_offset={} center_freq1={} bandwidth={}",
            s.sec_offset, s.center_mhz, s.width_mhz
        );
    }
    // 6 GHz is HE only.
    for (mode, flag) in [
        ("ieee80211n", "ht"),
        ("ieee80211ac", "vht"),
        ("ieee80211ax", "he"),
    ] {
        let on = status.lines().any(|l| l.strip_prefix(mode) == Some("=1"));
        if on && (band != Band::B6 || flag == "he") {
            cmd += " ";
            cmd += flag;
        }
    }
    ask(h, iface, &cmd)?;
    let want = format!("freq={}", s.freq_mhz);
    let end = Instant::now() + wait;
    loop {
        if h.request(iface, "STATUS").lines().any(|l| l == want) {
            return Ok(format!("{iface}: on {} MHz", s.freq_mhz));
        }
        if Instant::now() >= end {
            return Err(format!(
                "{iface}: not on {} MHz after the switch",
                s.freq_mhz
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// hostapd's reply to `cmd` on `iface`, a success when it is "OK".
fn ask(h: &mut Hostapd, iface: &str, cmd: &str) -> Result<String, String> {
    match h.try_request(iface, cmd) {
        Ok(r) if r.trim_end() == "OK" => Ok(format!("{iface}: OK")),
        Ok(r) => Err(format!("{iface}: {cmd}: {}", r.trim_end())),
        Err(e) if e.kind() == io::ErrorKind::TimedOut => Err(format!("{iface}: no answer")),
        Err(e) => Err(format!("{iface}: {e}")),
    }
}

/// One radio's part of an apply, checked.
struct Step {
    band: Band,
    /// The proposed configuration, parsed: its BSSs.
    new: Conf,
    class: Class,
    /// For a channel switch: the radio now, and the switch.
    switch: Option<(RadioState, Switch)>,
}

/// What undoes a step that was taken.
enum Undo {
    Set(Set),
    Switch(Band, Switch),
}

pub struct Apply {
    hostapd: Hostapd,
    helper: helper::Client,
    phy: Box<dyn Phy>,
    /// The other APs' BSSs, from the 802.11k rounds: where clients go.
    targets: Arc<Mutex<Vec<Target>>>,
    /// The deploy runner's public key, as the image pins it; without one,
    /// no configuration is taken.
    runner: Option<[u8; 32]>,
    /// This AP's name, which a configuration must be signed for.
    ap: String,
    /// The last sequence number sent to the helper, whose own record (which
    /// outlasts the agent) is the one that counts.
    last_seq: u64,
    /// The image's build time: no sequence number at or below it applies.
    floor: u64,
    /// The time a configuration's validity is judged by
    /// ([`wificonf::now_ms`]).
    now: fn() -> Option<u64>,
    steer_grace: Duration,
    switch_wait: Duration,
}

impl Apply {
    pub fn new(
        hostapd: Hostapd,
        helper: helper::Client,
        phy: Box<dyn Phy>,
        targets: Arc<Mutex<Vec<Target>>>,
        runner: Option<[u8; 32]>,
        ap: String,
        floor: u64,
    ) -> Self {
        Apply {
            hostapd,
            helper,
            phy,
            targets,
            runner,
            ap,
            last_seq: 0,
            floor,
            now: wificonf::now_ms,
            steer_grace: STEER_GRACE,
            switch_wait: SWITCH_WAIT,
        }
    }

    /// Applies `c`, with `last` the snapshot the link sent last (the clients
    /// to steer before a restart).
    pub fn run(&mut self, c: SignedConfig, last: Option<&Snapshot>) -> ConfigApplied {
        let mut done = ConfigApplied {
            sha256: c.sha256,
            ok: false,
            radios: Vec::new(),
            detail: String::new(),
        };
        match self.check(&c) {
            Ok((installed, steps)) => self.carry_out(c, installed, steps, last, &mut done),
            Err(why) => done.detail = format!("refused: {why}"),
        }
        if done.detail.len() > DETAIL_MAX {
            let mut cut = DETAIL_MAX;
            while !done.detail.is_char_boundary(cut) {
                cut -= 1;
            }
            done.detail.truncate(cut);
        }
        done
    }

    /// The request checked whole, with the installed configuration's hash
    /// and each radio's step; the error says why it is refused.
    fn check(&mut self, c: &SignedConfig) -> Result<(Option<[u8; 32]>, Vec<Step>), String> {
        let runner = self
            .runner
            .ok_or("no deploy runner key in this image: live configuration is off")?;
        config::verify(&runner, &self.ap, c)?;
        let (last, floor) = (self.last_seq, self.floor);
        if let Some(why) = config::replayed(c.seq, last, "the last applied", floor) {
            return Err(why);
        }
        if let Some(why) = config::expired(c, (self.now)()) {
            return Err(why);
        }
        let bands: Vec<Band> = c.radios.iter().map(|r| r.radio).collect();
        if bands.is_empty() || !bands.windows(2).all(|w| (w[0] as u8) < (w[1] as u8)) {
            return Err("the radios must be listed once each, in band order".into());
        }
        let mut news = Vec::new();
        for r in &c.radios {
            let name = wificonf::iface(r.radio);
            news.push(wificonf::parse(r.radio, &r.text).map_err(|e| format!("{name}: {e}"))?);
        }
        let Reply::Classified { installed, radios } =
            self.helper.ask(&Request::Classify(c.clone()))?
        else {
            return Err("the config helper did not classify it".into());
        };
        if radios.iter().map(|(b, _)| *b).ne(bands.iter().copied()) {
            return Err("the config helper classified other radios".into());
        }
        let mut steps = Vec::new();
        for ((band, class), (new, r)) in radios.into_iter().zip(news.into_iter().zip(&c.radios)) {
            let name = wificonf::iface(band);
            let goes = wificonf::target(band, &new.bsss[0]);
            let moves = match &class {
                Class::Channel => true,
                Class::Restart { moved, .. } => *moved && goes.is_some(),
                _ => false,
            };
            let mut switch = None;
            if moves || matches!(class, Class::Power | Class::Restart { .. }) {
                let now = self.phy.radio(band)?;
                let mut there = now.clone();
                if moves {
                    let to = goes.ok_or(format!("{name}: the new channel cannot be told"))?;
                    let s = regdomain::check_switch(band, &now, to)
                        .map_err(|e| format!("{name}: {e}"))?;
                    (there.freq_mhz, there.center_mhz, there.width_mhz) =
                        (s.freq_mhz, s.center_mhz, s.width_mhz);
                    switch = Some((now, s));
                }
                regdomain::check_power(&there, r.txpower_dbm)
                    .map_err(|e| format!("{name}: {e}"))?;
            }
            steps.push(Step {
                band,
                new,
                class,
                switch,
            });
        }
        Ok((installed, steps))
    }

    fn carry_out(
        &mut self,
        c: SignedConfig,
        installed: Option<[u8; 32]>,
        steps: Vec<Step>,
        last: Option<&Snapshot>,
        done: &mut ConfigApplied,
    ) {
        let each = |m| {
            steps
                .iter()
                .map(|s| RadioApplied {
                    radio: s.band,
                    mechanism: m,
                })
                .collect()
        };
        let restart = steps.iter().find_map(|s| match &s.class {
            Class::Restart { reason, .. } => Some(reason.clone()),
            _ => None,
        });
        let unchanged = steps.iter().all(|s| s.class == Class::Unchanged);
        if unchanged && installed == Some(c.sha256) {
            done.ok = true;
            done.radios = each(Mechanism::Unchanged);
            done.detail = "unchanged".into();
            return;
        }
        let seq = c.seq;
        let install = Request::Install {
            config: c,
            expect: installed,
            restart: restart.is_some(),
        };
        if let Some(why) = restart {
            let steered = self.steer_all(last);
            if steered > 0 {
                thread::sleep(self.steer_grace);
            }
            self.last_seq = seq;
            done.radios = each(Mechanism::Restart);
            let (ok, said) = match self.helper.ask(&install) {
                Ok(Reply::Done(d)) => (true, d),
                Ok(_) => (false, "the config helper answered something else".into()),
                Err(d) => (false, d),
            };
            done.ok = ok;
            done.detail = format!("restart ({why}), {steered} clients steered first: {said}");
            return;
        }
        self.last_seq = seq;
        if let Err(d) = self.helper.ask(&install) {
            done.detail = d;
            return;
        }
        drop(install);
        let mut undo = Vec::new();
        for s in &steps {
            let r = self.step(s, &mut undo);
            let mechanism = match (&r, &s.class) {
                (Ok(m), _) => *m,
                (Err(_), Class::Channel) => Mechanism::ChannelSwitch,
                (Err(_), _) => Mechanism::InPlace,
            };
            done.radios.push(RadioApplied {
                radio: s.band,
                mechanism,
            });
            if let Err(e) = r {
                done.detail = format!("{e}; {}", self.undo(undo));
                return;
            }
        }
        done.ok = true;
        done.detail = "installed".into();
    }

    /// Takes one radio's step; what it took goes on `undo`.
    fn step(&mut self, s: &Step, undo: &mut Vec<Undo>) -> Result<Mechanism, String> {
        match &s.class {
            Class::Unchanged | Class::Restart { .. } => Ok(Mechanism::Unchanged),
            // The helper set it.
            Class::Power => Ok(Mechanism::Power),
            Class::InPlace(sets) => {
                for set in sets {
                    let cmd = format!("SET {} {}", set.key, set.value);
                    ask(&mut self.hostapd, &set.iface, &cmd)?;
                    undo.push(Undo::Set(set.clone()));
                }
                self.update_beacons(&s.new)?;
                Ok(Mechanism::InPlace)
            }
            Class::Channel => {
                let Some((now, sw)) = &s.switch else {
                    return Err("no switch was checked".into());
                };
                if now.runs(sw) {
                    return Ok(Mechanism::Unchanged);
                }
                switch(&mut self.hostapd, s.band, sw, self.switch_wait)?;
                undo.push(Undo::Switch(s.band, now.here()));
                Ok(Mechanism::ChannelSwitch)
            }
        }
    }

    /// Rebuilds the beacons of a radio's BSSs, its own last: in a Multiple
    /// BSSID set its beacon carries the others'.
    fn update_beacons(&mut self, radio: &Conf) -> Result<(), String> {
        for bss in radio.bsss.iter().rev() {
            ask(&mut self.hostapd, &bss.iface, "UPDATE_BEACON")?;
        }
        Ok(())
    }

    /// Undoes what was taken, last first, and has the helper put the
    /// previous configuration back; says how that went.
    fn undo(&mut self, undo: Vec<Undo>) -> String {
        let mut failed = Vec::new();
        let mut beacons = Vec::new();
        for u in undo.into_iter().rev() {
            let r = match u {
                Undo::Set(s) => {
                    beacons.push(s.iface.clone());
                    let cmd = format!("SET {} {}", s.key, s.old);
                    ask(&mut self.hostapd, &s.iface, &cmd)
                }
                Undo::Switch(band, back) => {
                    switch(&mut self.hostapd, band, &back, self.switch_wait)
                }
            };
            failed.extend(r.err());
        }
        beacons.dedup();
        for b in beacons {
            failed.extend(ask(&mut self.hostapd, &b, "UPDATE_BEACON").err());
        }
        failed.extend(self.helper.ask(&Request::Revert).err());
        if failed.is_empty() {
            "undone, the previous configuration is back".into()
        } else {
            format!("undoing it failed too: {}", failed.join("; "))
        }
    }

    /// Asks every client of `last` to move to the other AP's BSS of its
    /// SSID, of its band if there is one; the number asked.
    fn steer_all(&mut self, last: Option<&Snapshot>) -> usize {
        let Some(s) = last else { return 0 };
        let targets = crate::lock(&self.targets).clone();
        let ours: Vec<[u8; 6]> = s.bsss.iter().map(|b| b.bssid).collect();
        let mut asked = 0;
        for sta in &s.stations {
            let Some(bss) = s.bsss.get(usize::from(sta.bss)) else {
                continue;
            };
            let Some(own) = targets.iter().find(|t| t.nr.bssid == bss.bssid) else {
                continue;
            };
            let band = band_group(own.nr.op_class);
            let to = targets
                .iter()
                .filter(|t| t.ssid == own.ssid && !ours.contains(&t.nr.bssid))
                .max_by_key(|t| band_group(t.nr.op_class) == band);
            if let Some(t) = to {
                let req = steer_request(sta.mac, &t.nr, true);
                asked += usize::from(ask(&mut self.hostapd, &bss.ifname, &req).is_ok());
            }
        }
        asked
    }
}

/// The band of a global operating class (802.11-2024 Table E-4): 2.4, 5 or
/// 6 GHz, or another.
fn band_group(op_class: u8) -> u8 {
    match op_class {
        81..=84 => 0,
        115..=130 => 1,
        131..=137 => 2,
        _ => 3,
    }
}

/// What applies a configuration: an [`Apply`], or a test's.
pub trait Runner: FnMut(SignedConfig, Option<&Snapshot>) -> ConfigApplied + Send {}

impl<F: FnMut(SignedConfig, Option<&Snapshot>) -> ConfigApplied + Send> Runner for F {}

/// Runs each apply on a thread of its own, one at a time, so the link goes
/// on while a restart takes the better part of a minute; the answers wait
/// here, across sessions, until the link takes them.
pub struct Worker<R> {
    runner: Arc<Mutex<R>>,
    busy: Arc<AtomicBool>,
    done: Arc<Mutex<Vec<ConfigApplied>>>,
    wake_rx: UnixStream,
    wake_tx: Arc<UnixStream>,
}

impl<R: Runner + 'static> Worker<R> {
    pub fn new(runner: R) -> io::Result<Self> {
        let (wake_rx, wake_tx) = UnixStream::pair()?;
        wake_rx.set_nonblocking(true)?;
        Ok(Worker {
            runner: Arc::new(Mutex::new(runner)),
            busy: Arc::new(AtomicBool::new(false)),
            done: Arc::default(),
            wake_rx,
            wake_tx: Arc::new(wake_tx),
        })
    }
}

fn refusal(sha256: [u8; 32], why: &str) -> ConfigApplied {
    ConfigApplied {
        sha256,
        ok: false,
        radios: Vec::new(),
        detail: format!("refused: {why}"),
    }
}

impl<R: Runner + 'static> ConfigApplier for Worker<R> {
    fn submit(&mut self, c: SignedConfig, last: Option<&Snapshot>) -> Option<ConfigApplied> {
        if self.busy.swap(true, Ordering::AcqRel) {
            return Some(refusal(c.sha256, "another configuration is being applied"));
        }
        let sha256 = c.sha256;
        let (runner, busy) = (Arc::clone(&self.runner), Arc::clone(&self.busy));
        let (done, wake) = (Arc::clone(&self.done), Arc::clone(&self.wake_tx));
        let last = last.cloned();
        let spawned = thread::Builder::new().name("apply".into()).spawn(move || {
            let answer = {
                let mut run = crate::lock(&runner);
                (*run)(c, last.as_ref())
            };
            crate::lock(&done).push(answer);
            busy.store(false, Ordering::Release);
            // A full pipe already wakes the link.
            let _ = (&*wake).write(&[1]);
        });
        match spawned {
            Ok(_) => None,
            Err(e) => {
                self.busy.store(false, Ordering::Release);
                Some(refusal(sha256, &format!("no thread to apply it on: {e}")))
            }
        }
    }

    fn fd(&self) -> RawFd {
        self.wake_rx.as_raw_fd()
    }

    fn take(&mut self) -> Vec<ConfigApplied> {
        let mut buf = [0; 64];
        while matches!((&self.wake_rx).read(&mut buf), Ok(n) if n > 0) {}
        std::mem::take(&mut *crate::lock(&self.done))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use std::os::unix::net::{UnixDatagram, UnixListener};
    use std::path::PathBuf;
    use std::sync::mpsc;

    use u6e_proto::config::config_sha256;
    use u6e_proto::msg::{Bss, RadioConfig, RateMode, Station};

    use crate::helper::Server;
    use crate::helper::tests::{iw, logs, runner, runner_public, signed, stranger, with5};
    use crate::neighbors::Element;
    use crate::regdomain::tests::{radio5, radio6};
    use crate::regdomain::{BandCaps, Channel};
    use crate::testdir::TestDir;
    use crate::wificonf::tests::{WLAN5, WLAN6, edit, fixture};

    const BSSS: [&str; 7] = [
        "wlan24", "wlan24-1", "wlan5", "wlan5-1", "wlan5-2", "wlan6", "wlan6-1",
    ];

    /// What the fake hostapds answer: a command that fails, and where each
    /// radio operates.
    #[derive(Default)]
    struct Hostapds {
        fail: Option<String>,
        freq: HashMap<String, u32>,
        log: Vec<String>,
    }

    impl Hostapds {
        fn answer(&mut self, iface: &str, req: &str) -> String {
            let radio = iface.split('-').next().unwrap_or(iface).to_owned();
            if req == "STATUS" {
                let freq = self.freq.get(&radio).copied().unwrap_or(0);
                return format!(
                    "state=ENABLED\nfreq={freq}\nieee80211n=1\nieee80211ac=1\nieee80211ax=1\n"
                );
            }
            self.log.push(format!("{iface} {req}"));
            if self.fail.as_deref() == Some(req) {
                return "FAIL\n".into();
            }
            if let Some(rest) = req.strip_prefix("CHAN_SWITCH ") {
                let freq = rest
                    .split(' ')
                    .nth(1)
                    .and_then(|f| f.parse().ok())
                    .unwrap_or(0);
                self.freq.insert(radio, freq);
            }
            "OK\n".into()
        }
    }

    /// A fixed radio state per band, as the AP's three radios are in the
    /// fixture: 2.4 GHz on 13, 5 GHz on 149 at 80 MHz, 6 GHz on 53 at 160.
    struct FakePhy;

    impl Phy for FakePhy {
        fn radio(&mut self, band: Band) -> Result<RadioState, String> {
            Ok(match band {
                Band::B24 => RadioState {
                    caps: BandCaps {
                        channels: (1..=13)
                            .map(|ch| Channel {
                                freq_mhz: regdomain::freq(Band::B24, ch).unwrap(),
                                max_power_mbm: 2000,
                                ..Channel::default()
                            })
                            .collect(),
                        max_width_mhz: 40,
                    },
                    rules: vec![regdomain::RegRule {
                        start_khz: 2_400_000,
                        end_khz: 2_483_500,
                        max_bw_khz: 40_000,
                        max_eirp_mbm: 2000,
                        flags: 0,
                    }],
                    freq_mhz: 2472,
                    width_mhz: 20,
                    center_mhz: 2472,
                },
                Band::B5 => radio5(),
                Band::B6 => radio6(),
            })
        }
    }

    /// Fake hostapds on every BSS, the real helper behind a socket (its
    /// commands logging), and an apply for "ap1".
    struct Rig {
        _t: TestDir,
        conf: PathBuf,
        hostapds: Arc<Mutex<Hostapds>>,
        helper_log: PathBuf,
        apply: Apply,
    }

    impl Rig {
        fn new() -> Self {
            let t = TestDir::new();
            let ctrl = t.path().join("hostapd");
            let (conf, state) = (t.path().join("wifi"), t.path().join("state"));
            for d in [&ctrl, &conf, &state] {
                fs::create_dir_all(d).unwrap();
            }
            wificonf::stage(&conf, &fixture())
                .unwrap()
                .commit()
                .unwrap();
            let hostapds = Arc::new(Mutex::new(Hostapds::default()));
            hostapds.lock().unwrap().freq = [("wlan24", 2472), ("wlan5", 5745), ("wlan6", 6215)]
                .map(|(i, f)| (i.to_owned(), f))
                .into();
            for iface in BSSS {
                let server = UnixDatagram::bind(ctrl.join(iface)).unwrap();
                let hostapds = Arc::clone(&hostapds);
                thread::spawn(move || {
                    let mut buf = [0; 4096];
                    while let Ok((n, from)) = server.recv_from(&mut buf) {
                        let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                        let r = hostapds.lock().unwrap().answer(iface, &req);
                        if let Some(p) = from.as_pathname() {
                            let _ = server.send_to(r.as_bytes(), p);
                        }
                    }
                });
            }
            let helper_log = t.path().join("helper.log");
            let server = Server {
                dir: conf.clone(),
                state,
                hostapd: ctrl.clone(),
                render: logs(&helper_log, "render"),
                restart: logs(&helper_log, "restart"),
                iw: iw(t.path(), &helper_log),
                up_wait: Duration::from_secs(2),
                runner: Some(runner_public()),
                ap: "ap1".into(),
                floor: 0,
                now: || Some(0),
            };
            let sock = t.path().join("sock");
            let listener = UnixListener::bind(&sock).unwrap();
            thread::spawn(move || {
                for mut conn in listener.incoming().flatten() {
                    let _ = server.serve(&mut conn);
                }
            });
            let targets = Arc::new(Mutex::new(vec![
                // This AP's wlan5 (02:..:15), and the other AP's BSSs of its
                // SSID on 5 GHz (op class 128) and 6 GHz (op class 134).
                target("73736964", "02000000001500000000809b0e"),
                target("73736964", "02000000002600000000869b0e"),
                target("73736964", "02000000002500000000809b0e"),
            ]));
            let apply = Apply {
                hostapd: Hostapd::bind(&t.path().join("run"), "apply", &ctrl).unwrap(),
                helper: helper::Client {
                    socket: sock,
                    wait: Duration::from_secs(10),
                },
                phy: Box::new(FakePhy),
                targets,
                runner: Some(runner_public()),
                ap: "ap1".into(),
                last_seq: 0,
                floor: 0,
                now: || Some(0),
                steer_grace: Duration::ZERO,
                switch_wait: Duration::from_secs(2),
            };
            Rig {
                _t: t,
                conf,
                hostapds,
                helper_log,
                apply,
            }
        }

        fn run(&mut self, c: SignedConfig) -> ConfigApplied {
            let snap = snapshot();
            self.apply.run(c, Some(&snap))
        }

        fn requests(&self) -> Vec<String> {
            self.hostapds.lock().unwrap().log.clone()
        }

        fn helper(&self) -> String {
            fs::read_to_string(&self.helper_log).unwrap_or_default()
        }

        fn installed(&self) -> Vec<RadioConfig> {
            wificonf::read(&self.conf).unwrap()
        }
    }

    fn target(ssid: &str, nr: &str) -> Target {
        Target {
            ssid: ssid.into(),
            nr: Element::parse(nr).unwrap(),
        }
    }

    /// A client on this AP's wlan5.
    fn snapshot() -> Snapshot {
        Snapshot {
            seq: 1,
            uptime_s: 0,
            load_milli: 0,
            mem_avail_kb: 0,
            nss_load_pct: 0,
            temps: Vec::new(),
            radios: Vec::new(),
            bsss: vec![Bss {
                ifname: "wlan5".into(),
                bssid: [0x02, 0, 0, 0, 0, 0x15],
                ssid: "ssid".into(),
                phy: "radio5".into(),
                vlan: 0,
            }],
            stations: vec![Station {
                mac: [0x02, 0, 0, 0, 0, 0x01],
                bss: 0,
                signal: -60,
                signal_avg: -60,
                rx_bytes: 0,
                tx_bytes: 0,
                rx_packets: 0,
                tx_packets: 0,
                tx_retries: 0,
                tx_failed: 0,
                tx_rate_kbps: 0,
                rx_rate_kbps: 0,
                tx_mcs: 0,
                rx_mcs: 0,
                tx_mode: RateMode::He,
                rx_mode: RateMode::He,
                tx_nss: 0,
                rx_nss: 0,
                tx_airtime_us: 0,
                rx_airtime_us: 0,
                inactive_ms: 0,
                connected_s: 0,
                vlan: 0,
            }],
            config_sha256: None,
        }
    }

    fn mechanisms(c: &ConfigApplied) -> Vec<Mechanism> {
        c.radios.iter().map(|r| r.mechanism).collect()
    }

    /// wlan5 moved to channel 36, 80 MHz.
    fn on36() -> String {
        let text = edit(WLAN5, "channel=149", "channel=36");
        let text = edit(
            &text,
            "vht_oper_centr_freq_seg0_idx=",
            "vht_oper_centr_freq_seg0_idx=42",
        );
        edit(
            &text,
            "he_oper_centr_freq_seg0_idx=",
            "he_oper_centr_freq_seg0_idx=42",
        )
    }

    use Mechanism::{ChannelSwitch, InPlace, Power, Restart, Unchanged};

    /// The controller relays configurations but cannot make one: whatever
    /// the runner did not sign for this AP, or signed for it before, is
    /// refused before the helper hears of it.
    #[test]
    fn a_configuration_the_runner_did_not_sign_now_for_this_ap_is_refused() {
        let mut r = Rig::new();
        let new = || with5(&edit(WLAN5, "dtim_period=3", "dtim_period=1"), 23);
        let mut unsigned = signed(1, new());
        unsigned.signature.clear();
        let mut altered = signed(1, fixture());
        altered.radios[1].text = new()[1].text.clone();
        for (c, why) in [
            (
                config::sign(&stranger(), "ap1", 1, new()),
                "not signed by the deploy runner",
            ),
            (unsigned, "not signed by the deploy runner"),
            (
                config::sign(&runner(), "ap2", 1, new()),
                "for another AP (ap2)",
            ),
            (altered, "the configuration does not match its SHA-256"),
        ] {
            let sha = c.sha256;
            let done = r.run(c);
            assert_eq!(
                (done.ok, done.sha256, done.radios.len(), done.detail),
                (false, sha, 0, format!("refused: {why}"))
            );
        }
        assert!(r.requests().is_empty());
        assert_eq!((r.helper(), r.installed()), (String::new(), fixture()));

        // Applied, then the same again, or an older one: a replay.
        assert!(r.run(signed(5, new())).ok);
        for seq in [5, 4] {
            let done = r.run(signed(seq, fixture()));
            assert_eq!(
                done.detail,
                format!("refused: replayed: sequence {seq} is not past 5, the last applied")
            );
        }
        // An agent started afresh does not know; the helper does.
        r.apply.last_seq = 0;
        let done = r.run(signed(3, fixture()));
        assert_eq!(
            done.detail,
            "refused: replayed: sequence 3 is not past 5, the last installed"
        );
        assert_eq!(r.installed(), new());

        // An agent of an image built after the configuration was signed, as
        // after a reboot into a newer image: refused before the helper.
        let mut newer = Rig::new();
        newer.apply.floor = 100;
        let done = newer.run(signed(50, new()));
        assert_eq!(
            done.detail,
            "refused: replayed: sequence 50 is not past 100, this image's build time"
        );
        assert!(newer.requests().is_empty());
        assert_eq!(newer.helper(), String::new());

        // Past its validity, or with a clock not yet synchronized: refused
        // before the helper, which would refuse it too.
        for (now, why) in [
            (
                (|| Some(u64::MAX)) as fn() -> Option<u64>,
                "refused: expired: valid until 600060, now 18446744073709551615",
            ),
            (
                || None,
                "refused: the clock is not synchronized, so no configuration applies",
            ),
        ] {
            let mut late = Rig::new();
            late.apply.now = now;
            assert_eq!(late.run(signed(60, new())).detail, why);
            assert!(late.requests().is_empty());
            assert_eq!(late.helper(), String::new());
        }

        let mut keyless = Rig::new();
        keyless.apply.runner = None;
        let done = keyless.run(signed(1, new()));
        assert_eq!(
            done.detail,
            "refused: no deploy runner key in this image: live configuration is off"
        );
    }

    #[test]
    fn what_the_ap_could_not_take_is_refused_before_anything() {
        let mut r = Rig::new();
        let refused = |r: &mut Rig, radios: Vec<RadioConfig>| {
            let done = r.run(signed(1, radios));
            assert!(!done.ok);
            done.detail
        };
        assert_eq!(
            refused(&mut r, fixture()[..2].to_vec()),
            "refused: the radios must be those installed, in order"
        );
        let mut twice = fixture();
        twice[2] = twice[1].clone();
        assert_eq!(
            refused(&mut r, twice),
            "refused: the radios must be listed once each, in band order"
        );
        let bad = edit(WLAN5, "ctrl_interface=", "ctrl_interface=/etc");
        assert_eq!(
            refused(&mut r, with5(&bad, 23)),
            "refused: wlan5: line 26: ctrl_interface is not allowed so"
        );
        assert_eq!(
            refused(&mut r, with5(WLAN5, 31)),
            "refused: wlan5: 31 dBm is above the 30 dBm allowed on the radio's channel"
        );
        assert!(r.requests().is_empty());
        assert_eq!((r.helper(), r.installed()), (String::new(), fixture()));
    }

    #[test]
    fn the_same_configuration_changes_nothing() {
        let mut r = Rig::new();
        let done = r.run(signed(1, fixture()));
        assert_eq!((done.ok, done.detail.as_str()), (true, "unchanged"));
        assert_eq!(mechanisms(&done), [Unchanged, Unchanged, Unchanged]);
        assert!(r.requests().is_empty());
        assert_eq!(r.helper(), "");
    }

    /// The live proof's change: settings hostapd rereads, set on the BSSs
    /// they changed on, the radio's beacons rebuilt; no reload, no restart.
    #[test]
    fn bss_settings_are_set_in_place_and_the_beacons_rebuilt() {
        let mut r = Rig::new();
        let text = WLAN5.replacen("bss_load_update_period=50", "bss_load_update_period=60", 2);
        let new = with5(&text, 23);
        let done = r.run(signed(1, new.clone()));
        assert_eq!((done.ok, done.detail.as_str()), (true, "installed"));
        assert_eq!(mechanisms(&done), [Unchanged, InPlace, Unchanged]);
        assert_eq!(
            r.requests(),
            [
                "wlan5 SET bss_load_update_period 60",
                "wlan5-1 SET bss_load_update_period 60",
                "wlan5-2 UPDATE_BEACON",
                "wlan5-1 UPDATE_BEACON",
                "wlan5 UPDATE_BEACON",
            ]
        );
        assert_eq!(r.helper(), "render\n");
        assert_eq!(r.installed(), new);
    }

    /// A power alone is set by the helper through nl80211, within what the
    /// radio's channel allows.
    #[test]
    fn a_power_change_alone_is_set() {
        let mut r = Rig::new();
        let new = with5(WLAN5, 20);
        let done = r.run(signed(1, new.clone()));
        assert!(done.ok, "{}", done.detail);
        assert_eq!(mechanisms(&done), [Unchanged, Power, Unchanged]);
        assert!(r.requests().is_empty());
        assert_eq!(r.helper(), "render\niw dev wlan5 set txpower fixed 2000\n");
        assert_eq!(r.installed(), new);
    }

    /// A step hostapd refuses is undone with the steps before it, and the
    /// helper puts the previous configuration back.
    #[test]
    fn a_refused_step_is_undone() {
        let mut r = Rig::new();
        r.hostapds.lock().unwrap().fail = Some("SET dtim_period 1".into());
        let text = edit(WLAN5, "dtim_period=3", "dtim_period=1");
        let text = text.replacen("bss_load_update_period=50", "bss_load_update_period=60", 1);
        let done = r.run(signed(1, with5(&text, 23)));
        assert!(!done.ok);
        assert_eq!(
            done.detail,
            "wlan5: SET dtim_period 1: FAIL; undone, the previous configuration is back"
        );
        assert_eq!(mechanisms(&done), [Unchanged, InPlace]);
        assert_eq!(
            r.requests(),
            [
                "wlan5 SET bss_load_update_period 60",
                "wlan5 SET dtim_period 1",
                "wlan5 SET bss_load_update_period 50",
                "wlan5 UPDATE_BEACON",
            ]
        );
        assert_eq!(r.installed(), fixture());
        assert_eq!(r.helper(), "render\nrender\n");
    }

    #[test]
    fn a_channel_change_is_announced_and_followed() {
        let mut r = Rig::new();
        let new = with5(&on36(), 23);
        let done = r.run(signed(1, new.clone()));
        assert_eq!((done.ok, done.detail.as_str()), (true, "installed"));
        assert_eq!(mechanisms(&done), [Unchanged, ChannelSwitch, Unchanged]);
        assert_eq!(
            r.requests(),
            [
                "wlan5 CHAN_SWITCH 5 5180 sec_channel_offset=1 center_freq1=5210 bandwidth=80 ht vht he"
            ]
        );
        assert_eq!(r.hostapds.lock().unwrap().freq["wlan5"], 5180);
        assert_eq!(r.installed(), new);
    }

    #[test]
    fn a_6ghz_switch_is_he_alone() {
        let mut r = Rig::new();
        let mut new = fixture();
        new[2].text = edit(WLAN6, "channel=", "channel=33");
        let done = r.run(signed(1, new));
        assert!(done.ok, "{}", done.detail);
        assert_eq!(
            r.requests(),
            ["wlan6 CHAN_SWITCH 5 6115 sec_channel_offset=1 center_freq1=6185 bandwidth=160 he"]
        );
    }

    /// A move onto a DFS channel would take the radio off the air for its
    /// CAC: refused, nothing touched.
    #[test]
    fn a_move_that_needs_a_cac_is_refused() {
        let mut r = Rig::new();
        let text = edit(WLAN5, "channel=149", "channel=100");
        let text = edit(
            &text,
            "vht_oper_centr_freq_seg0_idx=",
            "vht_oper_centr_freq_seg0_idx=106",
        );
        let text = edit(
            &text,
            "he_oper_centr_freq_seg0_idx=",
            "he_oper_centr_freq_seg0_idx=106",
        );
        let done = r.run(signed(1, with5(&text, 23)));
        assert!(!done.ok);
        assert!(
            done.detail
                .starts_with("refused: wlan5: channel 100 is a DFS channel without a CAC"),
            "{}",
            done.detail
        );
        // The same move with other changes, which would restart, too.
        let text = edit(&text, "ssid=", "ssid=other");
        assert!(
            r.run(signed(2, with5(&text, 23)))
                .detail
                .contains("DFS channel without a CAC")
        );
        assert!(r.requests().is_empty());
        assert_eq!((r.helper(), r.installed()), (String::new(), fixture()));
    }

    /// A radio already where the configuration puts it only has its
    /// configuration installed.
    #[test]
    fn a_radio_already_on_the_new_channel_is_left_alone() {
        let text = edit(WLAN5, "channel=149", "channel=157");
        let mut r = Rig::new();
        r.apply.phy = Box::new(On157);
        let done = r.run(signed(1, with5(&text, 23)));
        assert_eq!(mechanisms(&done), [Unchanged, Unchanged, Unchanged]);
        assert!(r.requests().is_empty());
        assert_eq!(r.installed(), with5(&text, 23));
    }

    struct On157;

    impl Phy for On157 {
        fn radio(&mut self, band: Band) -> Result<RadioState, String> {
            let mut r = FakePhy.radio(band)?;
            r.freq_mhz = 5785;
            Ok(r)
        }
    }

    /// A radio switched before another's step failed is switched back.
    #[test]
    fn a_switch_is_undone_when_a_later_radio_fails() {
        let mut r = Rig::new();
        r.hostapds.lock().unwrap().fail = Some("SET dtim_period 1".into());
        let mut new = with5(&on36(), 23);
        new[2].text = edit(WLAN6, "dtim_period=3", "dtim_period=1");
        let done = r.run(signed(1, new));
        assert!(!done.ok);
        assert_eq!(mechanisms(&done), [Unchanged, ChannelSwitch, InPlace]);
        assert!(
            done.detail
                .ends_with("undone, the previous configuration is back"),
            "{}",
            done.detail
        );
        let switches: Vec<String> = r
            .requests()
            .into_iter()
            .filter(|q| q.contains("CHAN_SWITCH"))
            .collect();
        assert_eq!(
            switches,
            [
                "wlan5 CHAN_SWITCH 5 5180 sec_channel_offset=1 center_freq1=5210 bandwidth=80 ht vht he",
                "wlan5 CHAN_SWITCH 5 5745 sec_channel_offset=1 center_freq1=5775 bandwidth=80 ht vht he",
            ]
        );
        assert_eq!(r.hostapds.lock().unwrap().freq["wlan5"], 5745);
        assert_eq!(r.installed(), fixture());
    }

    /// Anything else restarts u6e-wifi, the clients first asked to move to
    /// the other AP's BSS of their SSID and band.
    #[test]
    fn anything_else_restarts_after_steering_the_clients() {
        let mut r = Rig::new();
        let new = with5(&edit(WLAN5, "ssid=", "ssid=other"), 20);
        let done = r.run(signed(1, new.clone()));
        assert!(done.ok, "{}", done.detail);
        assert_eq!(mechanisms(&done), [Restart, Restart, Restart]);
        assert_eq!(
            done.detail,
            "restart (wlan5: ssid changed), 1 clients steered first: installed and restarted"
        );
        let reqs = r.requests();
        assert!(
            reqs[0].starts_with("wlan5 BSS_TM_REQ 02:00:00:00:00:01 neighbor=02:00:00:00:00:25,"),
            "{reqs:?}"
        );
        assert_eq!(r.helper(), "restart\n");
        assert_eq!(r.installed(), new);
        assert_eq!(config_sha256(&r.installed()), done.sha256);
    }

    /// One apply at a time, each on its own thread; answers wait for the
    /// link.
    #[test]
    fn the_worker_runs_one_apply_at_a_time_off_the_link() {
        let (go, wait) = mpsc::channel::<()>();
        let wait = Mutex::new(wait);
        let mut w = Worker::new(move |c: SignedConfig, _: Option<&Snapshot>| {
            let _ = wait.lock().unwrap().recv();
            ConfigApplied {
                sha256: c.sha256,
                ok: true,
                radios: Vec::new(),
                detail: "done".into(),
            }
        })
        .unwrap();
        let first = signed(1, fixture());
        let sha = first.sha256;
        assert_eq!(w.submit(first, None), None);
        let busy = w.submit(signed(2, fixture()), None).unwrap();
        assert_eq!(
            (busy.ok, busy.detail.as_str()),
            (false, "refused: another configuration is being applied")
        );
        assert!(w.take().is_empty());
        go.send(()).unwrap();
        let mut p = libc::pollfd {
            fd: w.fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        assert_eq!(unsafe { libc::poll(&mut p, 1, 5000) }, 1);
        let done = w.take();
        assert_eq!((done.len(), done[0].sha256, done[0].ok), (1, sha, true));
        assert!(w.take().is_empty());
        // Free again.
        assert_eq!(w.submit(signed(3, fixture()), None), None);
        go.send(()).unwrap();
    }
}
