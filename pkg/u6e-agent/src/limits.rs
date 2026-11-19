//! The agent's side of the rate limits (`u6e-shaper`, a helper on a socket
//! of the agent's group). The controller gives the whole set
//! (`SyncLimits`); the agent keeps it across sessions, so the limits stay
//! while the controller is away, and gives none to the helper until the
//! controller has given one, so a restarted agent never wipes the NSS's.
//! Each tick it resolves the set against the AP as the snapshot and sysfs
//! show it: a client limit on the BSSs of the SSID the client is on now, an
//! SSID's on its BSSs, every port with its index (a netdev made again has
//! lost its tree); a client that is not here, or an SSID with no BSS here,
//! waits. The helper is asked again whenever that changes, also while the
//! controller is away (between dials), so the limits follow a client that
//! roams and a BSS made again: then the uplink's tree is not built, and a
//! limit that needs it waits until the next session syncs again. A set that
//! is empty starts no helper while there is nothing in place to undo.
//!
//! A sync that built the uplink's tree is confirmed only once the controller
//! has acknowledged, by TCP, the bytes the agent sent after it: the uplink
//! still carries the link. Unconfirmed within 10 s, the helper undoes it,
//! and the same shaping is not tried again until the controller gives a
//! new set; nor is a shaping the helper could not be asked for or refused.
//! Once a minute the helper's counters are read: a limit whose classes
//! counted nothing while the client moved a megabyte in that direction is
//! not enforced by the NSS, and says so.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use u6e_proto::frame::{read_frame, write_frame};
use u6e_proto::msg::{
    AgentMsg, CommandResult, Limit, LimitState, LimitStatus, LimitTarget, Rate, Snapshot,
    check_limits,
};
use u6e_proto::netdev::{port_of, vlan};
use u6e_proto::shaper::{ClientSpec, Netdev, Outcome, Reply, Request, SOCKET, Spec, SsidSpec};
use u6e_proto::text;

/// The longest a sync may take: a tree is about 2 ms a firmware node.
const WAIT: Duration = Duration::from_secs(10);
/// How long a sync that built the uplink's tree waits for the controller's
/// acknowledgement; the helper waits 20 s for the confirmation.
const CONFIRM_WAIT: Duration = Duration::from_secs(10);
const COUNT_EVERY: Duration = Duration::from_secs(60);
/// What a client moves in a direction while its class counts nothing
/// before that direction is said not to be enforced.
const UNCOUNTED: u64 = 1 << 20;
const DETAIL_MAX: usize = 200;

/// A sync that built the uplink's tree, waiting for its confirmation.
struct Pending {
    conn: UnixStream,
    since: Instant,
    /// The session sent something after it, which the controller is to
    /// acknowledge.
    wrote: bool,
}

/// One count: each enforced client's class bytes and station bytes.
struct Count {
    at: Instant,
    clients: Vec<([u8; 6], u64, u64, u64, u64)>,
}

pub struct Limits {
    socket: PathBuf,
    net: PathBuf,
    given: Option<Vec<Limit>>,
    synced: Option<Spec>,
    /// The last sync was made with no controller to confirm with.
    away: bool,
    /// A spec undone for want of a confirmation, or that failed.
    failed: Option<Spec>,
    states: Vec<LimitState>,
    /// What this session was sent last.
    sent: Option<Vec<LimitState>>,
    pending: Option<Pending>,
    count: Option<Count>,
    failure: String,
}

impl Default for Limits {
    fn default() -> Self {
        Limits::new(SOCKET.into(), "/sys/class/net".into())
    }
}

fn state(target: LimitTarget, status: LimitStatus, detail: impl Into<String>) -> LimitState {
    LimitState {
        target,
        status,
        detail: detail.into(),
        down_bytes: 0,
        up_bytes: 0,
    }
}

/// The AP's Wi-Fi ports and VLAN netdevs in `net`, by name, with their
/// indices.
fn netdevs(net: &Path) -> Vec<Netdev> {
    let Ok(dir) = fs::read_dir(net) else {
        return Vec::new();
    };
    let mut out: Vec<Netdev> = dir
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            if !u6e_proto::netdev::wifi_port(&name) && !vlan(&name) {
                return None;
            }
            let index = fs::read_to_string(e.path().join("ifindex")).ok()?;
            Some(Netdev {
                name,
                ifindex: index.trim().parse().ok()?,
            })
        })
        .collect();
    out.sort();
    out
}

/// What the helper is to shape for `limits` on the AP `snap` and `devs`
/// show, and the limits that wait, with why.
fn resolve(
    limits: &[Limit],
    snap: &Snapshot,
    devs: &[Netdev],
) -> (Spec, Vec<(LimitTarget, String)>) {
    let mut waiting = Vec::new();
    let ssid_of = |m: [u8; 6]| {
        let st = snap.stations.iter().find(|s| s.mac == m)?;
        snap.bsss.get(usize::from(st.bss)).map(|b| b.ssid.clone())
    };
    let vaps = |ssid: &str| -> Vec<Netdev> {
        let names = snap
            .bsss
            .iter()
            .filter(|b| b.ssid == ssid)
            .map(|b| &b.ifname);
        names
            .filter_map(|n| devs.iter().find(|d| d.name == *n).cloned())
            .collect()
    };
    let mut wanted: Vec<(String, Rate)> = Vec::new();
    let mut clients: Vec<([u8; 6], Rate, String)> = Vec::new();
    for l in limits {
        match &l.target {
            LimitTarget::Ssid(s) if vaps(s).is_empty() => {
                waiting.push((l.target.clone(), "no BSS of it on this AP".into()));
            }
            LimitTarget::Ssid(s) => wanted.push((s.clone(), l.rate)),
            LimitTarget::Client(m) => match ssid_of(*m).filter(|s| !vaps(s).is_empty()) {
                Some(s) => clients.push((*m, l.rate, s)),
                None => waiting.push((l.target.clone(), "not on this AP".into())),
            },
        }
    }
    let mut names: BTreeSet<String> = wanted.iter().map(|(s, _)| s.clone()).collect();
    names.extend(clients.iter().map(|(_, _, s)| s.clone()));
    let ssids: Vec<SsidSpec> = names
        .iter()
        .map(|s| {
            let v = vaps(s);
            let ports = devs
                .iter()
                .filter(|d| v.iter().any(|vap| port_of(&d.name, &vap.name)))
                .cloned()
                .collect();
            let rate = wanted.iter().find(|(n, _)| n == s).map(|(_, r)| *r);
            SsidSpec {
                ssid: s.clone(),
                rate: rate.unwrap_or_default(),
                vaps: v,
                ports,
            }
        })
        .collect();
    clients.sort_by_key(|(m, ..)| *m);
    let clients = clients
        .into_iter()
        .map(|(mac, rate, s)| ClientSpec {
            mac,
            rate,
            ssid: ssids.iter().position(|x| x.ssid == s).expect("listed"),
        })
        .collect();
    let used: BTreeSet<u16> = snap
        .bsss
        .iter()
        .map(|b| b.vlan)
        .chain(snap.stations.iter().map(|s| s.vlan))
        .filter(|v| *v != 0)
        .collect();
    let vlans = devs
        .iter()
        .filter(|d| used.iter().any(|v| d.name == format!("vlan{v}")))
        .cloned()
        .collect();
    (
        Spec {
            ssids,
            clients,
            vlans,
        },
        waiting,
    )
}

fn cut(s: String) -> String {
    text::clean(&s).chars().take(DETAIL_MAX).collect()
}

impl Limits {
    pub fn new(socket: PathBuf, net: PathBuf) -> Self {
        Limits {
            socket,
            net,
            given: None,
            synced: None,
            away: false,
            failed: None,
            states: Vec::new(),
            sent: None,
            pending: None,
            count: None,
            failure: String::new(),
        }
    }

    /// The controller's `SyncLimits`: the set is kept and synced at once;
    /// what came of it in the result.
    pub fn command(
        &mut self,
        id: u64,
        limits: Vec<Limit>,
        last: Option<&Snapshot>,
    ) -> CommandResult {
        if let Err(why) = check_limits(&limits) {
            return CommandResult {
                id,
                ok: false,
                detail: cut(format!("refused: {why}")),
            };
        }
        self.given = Some(limits);
        self.failed = None;
        if let Some(snap) = last {
            self.sync(snap, false);
        }
        let count = |s: LimitStatus| self.states.iter().filter(|x| x.status == s).count();
        let refused = self
            .states
            .iter()
            .find(|s| s.status == LimitStatus::Refused);
        let detail = format!(
            "{} enforced, {} waiting, {} refused{}",
            count(LimitStatus::Enforced),
            count(LimitStatus::Waiting),
            count(LimitStatus::Refused),
            refused.map_or(String::new(), |r| format!(": {}", r.detail))
        );
        CommandResult {
            id,
            ok: refused.is_none(),
            detail: cut(detail),
        }
    }

    /// Whether the controller has given a set, which is kept.
    pub fn kept(&self) -> bool {
        self.given.is_some()
    }

    /// A tick in a session: the set synced again if the AP changed under
    /// it, and counted once a minute.
    pub fn tick(&mut self, snap: &Snapshot) {
        self.step(snap, false);
    }

    /// A tick with no session: the set synced again if the AP changed under
    /// it, the uplink's tree left as it is.
    pub fn tick_away(&mut self, snap: &Snapshot) {
        self.step(snap, true);
    }

    fn step(&mut self, snap: &Snapshot, away: bool) {
        if self.given.is_none() || self.pending.is_some() {
            return;
        }
        let (spec, _) = resolve(
            self.given.as_deref().unwrap_or_default(),
            snap,
            &netdevs(&self.net),
        );
        if self.synced.as_ref() != Some(&spec) && self.failed.as_ref() != Some(&spec) {
            self.sync(snap, away);
        } else if !away
            && self
                .count
                .as_ref()
                .is_none_or(|c| c.at.elapsed() >= COUNT_EVERY)
            && self
                .states
                .iter()
                .any(|s| s.status == LimitStatus::Enforced || s.status == LimitStatus::NotEnforced)
        {
            self.counted(snap);
        }
    }

    fn note(&mut self, failure: Option<String>) {
        match failure {
            Some(e) if e != self.failure => {
                eprintln!("u6e-agent: rate limits: {e}");
                self.failure = e;
            }
            Some(_) => {}
            None => self.failure.clear(),
        }
    }

    fn ask(&self, req: &Request) -> io::Result<(UnixStream, Reply)> {
        let mut sock = UnixStream::connect(&self.socket)?;
        sock.set_read_timeout(Some(WAIT))?;
        sock.set_write_timeout(Some(WAIT))?;
        write_frame(&mut sock, req)?;
        let reply = read_frame(&mut sock)?;
        Ok((sock, reply))
    }

    fn sync(&mut self, snap: &Snapshot, away: bool) {
        let given = self.given.clone().unwrap_or_default();
        let (spec, waiting) = resolve(&given, snap, &netdevs(&self.net));
        // Nothing to make and nothing a helper left to undo: none is started.
        if given.is_empty()
            && self.synced.is_none()
            && !self.socket.with_file_name("state").exists()
        {
            self.synced = Some(spec);
            self.states.clear();
            return;
        }
        let req = if away {
            Request::SyncAway(spec.clone())
        } else {
            Request::Sync(spec.clone())
        };
        let outcomes = match self.ask(&req) {
            Ok((conn, Reply::Synced { outcomes, confirm })) => {
                if confirm {
                    self.pending = Some(Pending {
                        conn,
                        since: Instant::now(),
                        wrote: false,
                    });
                }
                self.note(None);
                Ok(outcomes)
            }
            Ok((_, Reply::Refused(why))) => Err(format!("the shaper refused: {why}")),
            Ok((_, other)) => Err(format!("the shaper answered {other:?}")),
            Err(e) => Err(format!("no shaper: {e}")),
        };
        if let Err(e) = &outcomes {
            self.note(Some(e.clone()));
        }
        // A failure is not tried again every tick: the next change of the
        // AP or of the set is.
        if outcomes.is_ok() {
            self.synced = Some(spec);
        } else {
            self.synced = None;
            self.failed = Some(spec);
        }
        self.away = away;
        self.count = None;
        self.states = given
            .iter()
            .map(|l| {
                if let Some((_, why)) = waiting.iter().find(|(t, _)| *t == l.target) {
                    return state(l.target.clone(), LimitStatus::Waiting, why.clone());
                }
                let o = outcomes
                    .as_ref()
                    .map(|o| o.iter().find(|x| x.target == l.target));
                match o {
                    Ok(Some(o)) => from_outcome(o),
                    Ok(None) => state(
                        l.target.clone(),
                        LimitStatus::Refused,
                        "the shaper did not answer for it",
                    ),
                    Err(e) => state(l.target.clone(), LimitStatus::Refused, cut(e.clone())),
                }
            })
            .collect();
    }

    /// Reads the counters, and says which limits the NSS does not enforce.
    fn counted(&mut self, snap: &Snapshot) {
        let outcomes = match self.ask(&Request::Counters) {
            Ok((_, Reply::Counters(o))) => o,
            Ok((_, other)) => return self.note(Some(format!("the shaper's counters: {other:?}"))),
            Err(e) => return self.note(Some(format!("the shaper's counters: {e}"))),
        };
        let prev = self.count.take();
        let mut count = Count {
            at: Instant::now(),
            clients: Vec::new(),
        };
        let given = self.given.clone().unwrap_or_default();
        for s in &mut self.states {
            let Some(o) = outcomes.iter().find(|o| o.target == s.target && o.ok) else {
                continue;
            };
            (s.down_bytes, s.up_bytes) = (o.down_bytes, o.up_bytes);
            let LimitTarget::Client(m) = s.target else {
                continue;
            };
            let Some(st) = snap.stations.iter().find(|st| st.mac == m) else {
                continue;
            };
            count
                .clients
                .push((m, o.down_bytes, o.up_bytes, st.tx_bytes, st.rx_bytes));
            let rate = given.iter().find(|l| l.target == s.target).map(|l| l.rate);
            let before = prev
                .as_ref()
                .and_then(|p| p.clients.iter().find(|c| c.0 == m));
            let (Some(rate), Some(&(_, d0, u0, tx0, rx0))) = (rate, before) else {
                continue;
            };
            let moved = |now: u64, then: u64| now.saturating_sub(then);
            let down = rate.down_kbit.is_some()
                && moved(st.tx_bytes, tx0) >= UNCOUNTED
                && o.down_bytes == d0;
            let up =
                rate.up_kbit.is_some() && moved(st.rx_bytes, rx0) >= UNCOUNTED && o.up_bytes == u0;
            if down || up {
                let (dir, n) = if down {
                    ("received", moved(st.tx_bytes, tx0))
                } else {
                    ("sent", moved(st.rx_bytes, rx0))
                };
                s.status = LimitStatus::NotEnforced;
                s.detail = format!("its NSS class counted none of the {n} B it {dir} in a minute");
            } else {
                s.status = LimitStatus::Enforced;
                s.detail = o.detail.clone();
            }
        }
        self.count = Some(count);
        self.note(None);
    }

    /// The states, if this session has not had them as they are.
    pub fn update(&mut self) -> Option<AgentMsg> {
        if self.given.is_none() || self.sent.as_ref() == Some(&self.states) {
            return None;
        }
        self.sent = Some(self.states.clone());
        Some(AgentMsg::Limits(self.states.clone()))
    }

    /// A new session: it is sent the states, and a sync made away is made
    /// again, the uplink's tree with it.
    pub fn session(&mut self) {
        self.sent = None;
        if self.away {
            self.synced = None;
            self.away = false;
        }
    }

    /// The session sent something the controller is to acknowledge.
    pub fn wrote(&mut self) {
        if let Some(p) = &mut self.pending {
            p.wrote = true;
        }
    }

    /// When a waiting confirmation is to be looked at again.
    pub fn deadline(&self) -> Option<Instant> {
        let p = self.pending.as_ref()?;
        Some((Instant::now() + Duration::from_millis(100)).min(p.since + CONFIRM_WAIT))
    }

    /// Confirms a sync once `unacked` (the link's bytes the controller has
    /// not acknowledged) is none after the session wrote; past the wait,
    /// lets the helper undo it.
    pub fn confirm(&mut self, unacked: io::Result<usize>) {
        let Some(p) = &mut self.pending else {
            return;
        };
        if p.wrote && matches!(unacked, Ok(0)) {
            let mut p = self.pending.take().expect("pending");
            let done = write_frame(&mut p.conn, &Request::Confirm)
                .and_then(|()| read_frame::<_, Reply>(&mut p.conn));
            match done {
                Ok(Reply::Done) => {}
                other => self.note(Some(format!("the shaper's confirmation: {other:?}"))),
            }
        } else if p.since.elapsed() >= CONFIRM_WAIT {
            self.pending = None;
            self.failed = self.synced.take();
            let why =
                "undone: the controller did not hear the AP once its shaper tree was in place";
            eprintln!("u6e-agent: rate limits: {why}");
            for s in self
                .states
                .iter_mut()
                .filter(|s| s.status == LimitStatus::Enforced)
            {
                s.status = LimitStatus::Refused;
                s.detail = why.into();
            }
        }
    }
}

fn from_outcome(o: &Outcome) -> LimitState {
    let status = if o.ok {
        LimitStatus::Enforced
    } else {
        LimitStatus::Refused
    };
    LimitState {
        target: o.target.clone(),
        status,
        detail: cut(o.detail.clone()),
        down_bytes: o.down_bytes,
        up_bytes: o.up_bytes,
    }
}

/// The bytes the controller has not acknowledged on the socket `fd`.
pub fn unacked(fd: std::os::fd::RawFd) -> io::Result<usize> {
    let mut n: libc::c_int = 0;
    // SAFETY: TIOCOUTQ (SIOCOUTQ) writes one int through the pointer.
    if unsafe { libc::ioctl(fd, libc::TIOCOUTQ, &mut n) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::tests::station;
    use crate::testdir::TestDir;
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc::{Receiver, channel};
    use std::thread;
    use u6e_proto::msg::Bss;

    const C1: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const C2: [u8; 6] = [2, 0, 0, 0, 0, 2];

    fn bss(ifname: &str, ssid: &str) -> Bss {
        Bss {
            ifname: ifname.into(),
            bssid: [2, 0, 0, 0, 1, 1],
            ssid: ssid.into(),
            phy: String::new(),
            vlan: 42,
        }
    }

    /// An AP with "ent" on wlan5 and wlan6, "guest" on wlan5-1; C1 on
    /// wlan5's VLAN 43 netdev.
    fn snap() -> Snapshot {
        let mut c1 = station(C1, 0);
        c1.vlan = 43;
        Snapshot {
            seq: 1,
            uptime_s: 0,
            load_milli: 0,
            mem_avail_kb: 0,
            nss_load_pct: 0,
            temps: Vec::new(),
            radios: Vec::new(),
            bsss: vec![
                bss("wlan5", "ent"),
                bss("wlan6", "ent"),
                bss("wlan5-1", "guest"),
            ],
            stations: vec![c1],
            config_sha256: None,
            clock_synced: true,
            power_limits: Vec::new(),
            auth: Vec::new(),
            offload_held: false,
        }
    }

    /// A sysfs of the AP's netdevs, each with its index.
    fn sysfs(t: &TestDir, devs: &[(&str, u32)]) -> PathBuf {
        let net = t.path().join("net");
        let _ = fs::remove_dir_all(&net);
        for (n, i) in devs {
            fs::create_dir_all(net.join(n)).unwrap();
            fs::write(net.join(n).join("ifindex"), format!("{i}\n")).unwrap();
        }
        net
    }

    const DEVS: [(&str, u32); 8] = [
        ("wlan5", 10),
        ("wlan5.43", 11),
        ("wlan6", 12),
        ("wlan5-1", 13),
        ("vlan42", 20),
        ("vlan43", 21),
        ("vlan11", 22),
        ("lan", 2),
    ];

    fn limit(target: LimitTarget, down: Option<u32>, up: Option<u32>) -> Limit {
        Limit {
            target,
            rate: Rate {
                down_kbit: down,
                up_kbit: up,
            },
        }
    }

    fn nd(name: &str, ifindex: u32) -> Netdev {
        Netdev {
            name: name.into(),
            ifindex,
        }
    }

    #[test]
    fn a_limit_resolves_to_the_bsss_of_the_ssid_the_client_is_on() {
        let t = TestDir::new();
        let devs = netdevs(&sysfs(&t, &DEVS));
        assert!(
            !devs.iter().any(|d| d.name == "lan"),
            "not a Wi-Fi port or VLAN"
        );
        let limits = [
            limit(LimitTarget::Client(C1), Some(1_000), None),
            limit(LimitTarget::Client(C2), Some(1_000), None),
            limit(LimitTarget::Ssid("guest".into()), None, Some(500)),
            limit(LimitTarget::Ssid("gone".into()), None, Some(500)),
        ];
        let (spec, waiting) = resolve(&limits, &snap(), &devs);
        assert_eq!(
            waiting,
            [
                (LimitTarget::Client(C2), "not on this AP".to_owned()),
                (
                    LimitTarget::Ssid("gone".into()),
                    "no BSS of it on this AP".to_owned()
                )
            ]
        );
        let names: Vec<&str> = spec.ssids.iter().map(|s| s.ssid.as_str()).collect();
        assert_eq!(names, ["ent", "guest"]);
        let ent = &spec.ssids[0];
        assert_eq!(ent.rate, Rate::default());
        assert_eq!(ent.vaps, [nd("wlan5", 10), nd("wlan6", 12)]);
        assert_eq!(
            ent.ports,
            [nd("wlan5", 10), nd("wlan5.43", 11), nd("wlan6", 12)]
        );
        assert_eq!(spec.ssids[1].ports, [nd("wlan5-1", 13)]);
        assert_eq!((spec.clients[0].mac, spec.clients[0].ssid), (C1, 0));
        // The BSSs' VLAN and the client's, not the management one.
        assert_eq!(spec.vlans, [nd("vlan42", 20), nd("vlan43", 21)]);
    }

    /// A helper that answers each connection by `answer`, and tells the
    /// test each request it took.
    fn helper(
        t: &TestDir,
        mut answer: impl FnMut(Request, &mut UnixStream) + Send + 'static,
    ) -> (PathBuf, Receiver<Request>) {
        let path = t.path().join("shaper.sock");
        let l = UnixListener::bind(&path).unwrap();
        let (tx, rx) = channel();
        thread::spawn(move || {
            for c in l.incoming() {
                let mut c = c.unwrap();
                let Ok(req) = read_frame::<_, Request>(&mut c) else {
                    continue;
                };
                let _ = tx.send(req.clone());
                answer(req, &mut c);
            }
        });
        (path, rx)
    }

    fn ok(target: LimitTarget) -> Outcome {
        Outcome {
            target,
            ok: true,
            detail: "download on wlan5".into(),
            down_bytes: 0,
            up_bytes: 0,
        }
    }

    #[test]
    fn nothing_is_synced_before_the_controller_gives_a_set_and_then_on_a_change() {
        let t = TestDir::new();
        let net = sysfs(&t, &DEVS);
        let (sock, rx) = helper(&t, |req, c| {
            let reply = match req {
                Request::Sync(spec) => {
                    let outcomes = spec
                        .clients
                        .iter()
                        .map(|c| ok(LimitTarget::Client(c.mac)))
                        .collect();
                    Reply::Synced {
                        outcomes,
                        confirm: false,
                    }
                }
                _ => Reply::Counters(Vec::new()),
            };
            write_frame(c, &reply).unwrap();
        });
        let mut l = Limits::new(sock, net.clone());
        l.tick(&snap());
        assert!(l.update().is_none());
        assert!(
            rx.try_recv().is_err(),
            "a restarted agent leaves the NSS alone"
        );
        let r = l.command(
            9,
            vec![limit(LimitTarget::Client(C1), Some(1_000), None)],
            Some(&snap()),
        );
        assert!(
            r.ok && r.detail == "1 enforced, 0 waiting, 0 refused",
            "{r:?}"
        );
        assert!(matches!(rx.recv().unwrap(), Request::Sync(_)));
        let Some(AgentMsg::Limits(s)) = l.update() else {
            panic!()
        };
        assert_eq!(s[0].status, LimitStatus::Enforced);
        assert!(l.update().is_none(), "sent once");
        // The same AP: nothing to sync, the counters read.
        l.tick(&snap());
        assert_eq!(rx.recv().unwrap(), Request::Counters);
        l.tick(&snap());
        assert!(rx.try_recv().is_err(), "once a minute");
        // wlan5 made again: a new index, a sync.
        let mut devs = DEVS;
        devs[0].1 = 40;
        sysfs(&t, &devs);
        l.tick(&snap());
        let Ok(Request::Sync(spec)) = rx.recv() else {
            panic!()
        };
        assert_eq!(spec.ssids[0].vaps[0], nd("wlan5", 40));
        // The client roams to the guest SSID's BSS: a sync there.
        let mut roamed = snap();
        roamed.stations[0].bss = 2;
        l.tick(&roamed);
        let Ok(Request::Sync(spec)) = rx.recv() else {
            panic!()
        };
        assert_eq!(spec.ssids[spec.clients[0].ssid].ssid, "guest");
        // A new session is sent the states again.
        l.session();
        assert!(l.update().is_some());
    }

    /// A helper's answer to a sync, made away or not: every client limit
    /// enforced, nothing to confirm.
    fn enforced(req: &Request) -> Reply {
        match req {
            Request::Sync(spec) | Request::SyncAway(spec) => Reply::Synced {
                outcomes: spec
                    .clients
                    .iter()
                    .map(|c| ok(LimitTarget::Client(c.mac)))
                    .collect(),
                confirm: false,
            },
            _ => Reply::Counters(Vec::new()),
        }
    }

    #[test]
    fn away_the_limits_follow_the_ap_and_the_next_session_syncs_them_again() {
        let t = TestDir::new();
        let (sock, rx) = helper(&t, |req, c| write_frame(c, &enforced(&req)).unwrap());
        let mut l = Limits::new(sock, sysfs(&t, &DEVS));
        // Nothing is kept before the controller gives a set.
        l.tick_away(&snap());
        assert!(!l.kept() && rx.try_recv().is_err());
        l.command(
            1,
            vec![limit(LimitTarget::Client(C1), Some(1_000), Some(500))],
            Some(&snap()),
        );
        assert!(matches!(rx.recv().unwrap(), Request::Sync(_)));
        // The controller goes; the client roams to the guest SSID's BSS.
        let mut roamed = snap();
        roamed.stations[0].bss = 2;
        l.tick_away(&roamed);
        let Ok(Request::SyncAway(spec)) = rx.recv() else {
            panic!()
        };
        assert_eq!(spec.ssids[spec.clients[0].ssid].ssid, "guest");
        l.tick_away(&roamed);
        assert!(rx.try_recv().is_err(), "nothing changed, nothing asked");
        // The next session syncs it again, the uplink's tree with it.
        l.session();
        l.tick(&roamed);
        assert!(matches!(rx.recv().unwrap(), Request::Sync(_)));
        l.tick(&roamed);
        assert_eq!(rx.recv().unwrap(), Request::Counters);
    }

    #[test]
    fn a_failed_sync_is_not_tried_again_every_tick() {
        let t = TestDir::new();
        let (sock, rx) = helper(&t, |_, c| {
            write_frame(c, &Reply::Refused("busy".into())).unwrap();
        });
        let mut l = Limits::new(sock, sysfs(&t, &DEVS));
        let r = l.command(
            1,
            vec![limit(LimitTarget::Client(C1), Some(1_000), None)],
            Some(&snap()),
        );
        assert!(!r.ok && r.detail.contains("busy"), "{r:?}");
        assert!(rx.recv().is_ok());
        for _ in 0..3 {
            l.tick(&snap());
            l.tick_away(&snap());
        }
        assert!(
            rx.try_recv().is_err(),
            "the helper is not started each tick"
        );
        // A change of the AP is tried.
        let mut roamed = snap();
        roamed.stations[0].bss = 2;
        l.tick(&roamed);
        assert!(rx.recv().is_ok());
    }

    #[test]
    fn an_empty_set_starts_no_helper_unless_one_left_shaping_in_place() {
        let t = TestDir::new();
        let (sock, rx) = helper(&t, |req, c| write_frame(c, &enforced(&req)).unwrap());
        let mut l = Limits::new(sock.clone(), sysfs(&t, &DEVS));
        let r = l.command(1, Vec::new(), Some(&snap()));
        assert!(
            r.ok && r.detail == "0 enforced, 0 waiting, 0 refused",
            "{r:?}"
        );
        l.tick(&snap());
        assert!(rx.try_recv().is_err(), "no helper for nothing");
        assert!(matches!(l.update(), Some(AgentMsg::Limits(s)) if s.is_empty()));
        // A helper's state from before the agent restarted: it is undone.
        fs::write(sock.with_file_name("state"), "").unwrap();
        let mut again = Limits::new(sock, sysfs(&t, &DEVS));
        again.command(2, Vec::new(), Some(&snap()));
        assert!(matches!(rx.recv().unwrap(), Request::Sync(s) if s.clients.is_empty()));
    }

    #[test]
    fn a_bad_set_is_refused_and_no_shaper_refuses_every_limit() {
        let t = TestDir::new();
        let mut l = Limits::new(t.path().join("none.sock"), sysfs(&t, &DEVS));
        let twice = vec![
            limit(LimitTarget::Client(C1), Some(1_000), None),
            limit(LimitTarget::Client(C1), None, Some(1_000)),
        ];
        assert!(!l.command(1, twice, Some(&snap())).ok);
        assert!(l.update().is_none(), "nothing was given");
        let r = l.command(
            2,
            vec![limit(LimitTarget::Client(C1), Some(1_000), None)],
            Some(&snap()),
        );
        assert!(!r.ok && r.detail.contains("no shaper"), "{r:?}");
        let Some(AgentMsg::Limits(s)) = l.update() else {
            panic!()
        };
        assert_eq!(s[0].status, LimitStatus::Refused);
    }

    #[test]
    fn a_tree_is_confirmed_only_once_the_controller_acknowledged() {
        let t = TestDir::new();
        let (sock, rx) = helper(&t, |req, c| {
            if let Request::Sync(spec) = req {
                let outcomes = spec
                    .clients
                    .iter()
                    .map(|c| ok(LimitTarget::Client(c.mac)))
                    .collect();
                write_frame(
                    c,
                    &Reply::Synced {
                        outcomes,
                        confirm: true,
                    },
                )
                .unwrap();
                if let Ok(Request::Confirm) = read_frame::<_, Request>(c) {
                    write_frame(c, &Reply::Done).unwrap();
                }
            }
        });
        let mut l = Limits::new(sock, sysfs(&t, &DEVS));
        l.command(
            1,
            vec![limit(LimitTarget::Client(C1), None, Some(1_000))],
            Some(&snap()),
        );
        let _ = rx.recv();
        assert!(l.deadline().is_some());
        // Bytes not acknowledged yet, or nothing written since: no confirmation.
        l.confirm(Ok(0));
        l.wrote();
        l.confirm(Ok(120));
        assert!(l.pending.is_some());
        l.confirm(Ok(0));
        assert!(l.pending.is_none() && l.deadline().is_none());
        assert_eq!(l.states[0].status, LimitStatus::Enforced);
    }

    #[test]
    fn an_unconfirmed_tree_is_undone_and_not_tried_again_until_a_new_set() {
        let t = TestDir::new();
        let (sock, rx) = helper(&t, |req, c| {
            if let Request::Sync(spec) = req {
                let outcomes = spec
                    .clients
                    .iter()
                    .map(|c| ok(LimitTarget::Client(c.mac)))
                    .collect();
                write_frame(
                    c,
                    &Reply::Synced {
                        outcomes,
                        confirm: true,
                    },
                )
                .unwrap();
            }
        });
        let mut l = Limits::new(sock, sysfs(&t, &DEVS));
        let set = vec![limit(LimitTarget::Client(C1), None, Some(1_000))];
        l.command(1, set.clone(), Some(&snap()));
        let _ = rx.recv();
        l.pending.as_mut().unwrap().since -= CONFIRM_WAIT;
        l.wrote();
        l.confirm(Ok(77));
        assert!(l.pending.is_none());
        assert_eq!(l.states[0].status, LimitStatus::Refused);
        assert!(l.states[0].detail.starts_with("undone"));
        l.tick(&snap());
        assert!(
            rx.try_recv().is_err(),
            "the same shaping is not tried again"
        );
        l.command(2, set, Some(&snap()));
        assert!(rx.recv().is_ok(), "a new set is");
    }

    #[test]
    fn a_class_that_counts_nothing_while_the_client_moves_traffic_is_not_enforced() {
        let t = TestDir::new();
        let bytes = std::sync::Arc::new(std::sync::Mutex::new(0u64));
        let b = bytes.clone();
        let (sock, _rx) = helper(&t, move |req, c| {
            let o = |down_bytes| Outcome {
                down_bytes,
                ..ok(LimitTarget::Client(C1))
            };
            let reply = match req {
                Request::Sync(_) => Reply::Synced {
                    outcomes: vec![o(0)],
                    confirm: false,
                },
                _ => Reply::Counters(vec![o(*b.lock().unwrap())]),
            };
            write_frame(c, &reply).unwrap();
        });
        let mut l = Limits::new(sock, sysfs(&t, &DEVS));
        let mut s = snap();
        l.command(
            1,
            vec![limit(LimitTarget::Client(C1), Some(1_000), None)],
            Some(&s),
        );
        l.tick(&s);
        assert!(l.count.is_some());
        // A minute on: 5 MB to the client, nothing through its class.
        l.count.as_mut().unwrap().at -= COUNT_EVERY;
        s.stations[0].tx_bytes += 5 << 20;
        l.tick(&s);
        assert_eq!(
            l.states[0].status,
            LimitStatus::NotEnforced,
            "{:?}",
            l.states[0]
        );
        assert!(l.states[0].detail.contains("received"));
        // Its class counts again: enforced, with its bytes.
        l.count.as_mut().unwrap().at -= COUNT_EVERY;
        s.stations[0].tx_bytes += 5 << 20;
        *bytes.lock().unwrap() = 5 << 20;
        l.tick(&s);
        assert_eq!(l.states[0].status, LimitStatus::Enforced);
        assert_eq!(l.states[0].down_bytes, 5 << 20);
    }
}
