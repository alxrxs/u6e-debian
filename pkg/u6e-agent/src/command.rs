//! The operator's commands, carried out through hostapd's control sockets:
//! kick (deauthenticate), block and unblock (every BSS's deny ACL) and steer
//! (an 802.11v BSS Transition Management Request). All a command names is
//! checked before hostapd is told to do anything: the address must be a
//! station's, the station must be associated with a BSS of this AP as
//! hostapd has it at that moment (a snapshot can be a tick old, and a client
//! that changed bands since is no longer where it says), and a steer target
//! must be a BSS of the latest 802.11k round, of the station's SSID.
//! Blocks live in RAM: on each connection the controller sends the whole set
//! (`SyncBlocks`), which every BSS's deny ACL is made to hold exactly, and
//! they go back onto a BSS whose hostapd started again without them.

use std::collections::BTreeSet;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use u6e_proto::mac;
use u6e_proto::msg::{Command, CommandKind, CommandResult, Snapshot};

use crate::collect;
use crate::neighbors::{Element, Hostapd, Target};

/// TBTTs a steered client has before hostapd disassociates it, and for which
/// the candidate list stays valid: ~10 s at the default beacon interval, time
/// for a few scans and a reassociation, short enough that a client ignoring
/// the request is moved anyway. hostapd's default validity, 1 TBTT, expires
/// before a client's scan ends.
const STEER_TBTT: u16 = 100;
/// "Deauthenticated because sending STA is leaving": the client may come back.
const KICK_REASON: u16 = 3;
const DETAIL_MAX: usize = 200;
const NOT_HERE: &str = "not associated here";
/// The most blocks a sync may set: each one is a request to every BSS.
pub const SYNC_MAX: usize = 1024;

/// The blocked addresses, held while each is in every BSS's deny ACL.
pub type Blocks = Mutex<BTreeSet<[u8; 6]>>;

pub struct Commands {
    hostapd: Hostapd,
    /// hostapd's control socket directory: one socket per BSS.
    dir: PathBuf,
    targets: Arc<Mutex<Vec<Target>>>,
    blocks: Arc<Blocks>,
}

/// What a command came to: the replies (or the refusal), and whether every
/// part of it worked.
type Outcome = Result<String, String>;

impl Commands {
    /// Commands for the hostapds of `dir`, through a client bound in `run`.
    pub fn open(
        run: &Path,
        dir: &Path,
        targets: Arc<Mutex<Vec<Target>>>,
        blocks: Arc<Blocks>,
    ) -> io::Result<Self> {
        Ok(Commands {
            hostapd: Hostapd::bind(run, "command", dir)?,
            dir: dir.to_owned(),
            targets,
            blocks,
        })
    }

    /// Carries out `c` where hostapd has its station now. `last`, the
    /// snapshot the link sent last, names the BSSs' BSSIDs for a steer, and
    /// the stations a sync looks for.
    pub fn run(&mut self, c: &Command, last: Option<&Snapshot>) -> CommandResult {
        let (ok, detail) = match self.carry_out(&c.kind, last) {
            Ok(d) => (true, d),
            Err(d) => (false, d),
        };
        CommandResult {
            id: c.id,
            ok,
            detail: detail.chars().take(DETAIL_MAX).collect(),
        }
    }

    fn carry_out(&mut self, kind: &CommandKind, last: Option<&Snapshot>) -> Outcome {
        match *kind {
            CommandKind::Kick { mac } => {
                let mac = station(mac)?;
                let iface = self.current_bss(mac)?;
                self.kick(&iface, mac)
            }
            CommandKind::Block { mac } => {
                let mac = station(mac)?;
                // Looked up first: a deny ACL entry makes hostapd drop the
                // station, after which it is on no BSS to kick it from.
                let on = self.current_bss(mac);
                // Held through the change, so a reassertion never interleaves.
                let blocks = Arc::clone(&self.blocks);
                let mut held = crate::lock(&blocks);
                held.insert(mac);
                let acl = self.on_every_bss(&format!("DENY_ACL ADD_MAC {}", mac::format(mac)));
                let kick = match on {
                    Ok(iface) => self.kick(&iface, mac),
                    Err(e) if e == NOT_HERE => Ok(e),
                    Err(e) => Err(e),
                };
                let label = |d| format!("kick: {d}");
                both(acl, kick.map(label).map_err(label))
            }
            CommandKind::Unblock { mac } => {
                let mac = station(mac)?;
                let blocks = Arc::clone(&self.blocks);
                let mut held = crate::lock(&blocks);
                held.remove(&mac);
                self.on_every_bss(&format!("DENY_ACL DEL_MAC {}", mac::format(mac)))
            }
            CommandKind::SyncBlocks { ref macs } => self.sync(macs, last),
            CommandKind::Steer { mac, target_bssid } => {
                let mac = station(mac)?;
                let targets = crate::lock(&self.targets).clone();
                let find = |bssid| targets.iter().find(|t| t.nr.bssid == bssid);
                let target = find(target_bssid).ok_or("unknown target")?;
                let iface = self.current_bss(mac)?;
                let bss = last
                    .and_then(|s| s.bsss.iter().find(|b| b.ifname == iface))
                    .ok_or_else(|| format!("{iface}: not in the last snapshot"))?;
                if bss.bssid == target_bssid {
                    return Err("already on the target".into());
                }
                if find(bss.bssid).map(|t| &t.ssid) != Some(&target.ssid) {
                    return Err("the target serves another SSID".into());
                }
                self.ask(&bss.ifname, &steer_request(mac, &target.nr))
            }
        }
    }

    /// Makes the blocks exactly `macs`. Each BSS's deny ACL gets those it
    /// lacks and loses those it holds beyond them: hostapd's own list, so a
    /// block an earlier agent left there goes too. A client of `macs` the
    /// last snapshot has on the AP is kicked where hostapd has it now.
    fn sync(&mut self, macs: &[[u8; 6]], last: Option<&Snapshot>) -> Outcome {
        if macs.len() > SYNC_MAX {
            return Err(format!("more than {SYNC_MAX} blocks"));
        }
        for &m in macs {
            station(m)?;
        }
        let want: BTreeSet<[u8; 6]> = macs.iter().copied().collect();
        let on: Vec<([u8; 6], String)> = want
            .iter()
            .filter(|&&m| listed(last, m))
            .filter_map(|&m| Some((m, self.current_bss(m).ok()?)))
            .collect();
        let blocks = Arc::clone(&self.blocks);
        let mut held = crate::lock(&blocks);
        held.clone_from(&want);
        let acl = collect::bss_order(&self.dir)
            .iter()
            .map(|iface| self.sync_bss(iface, &want))
            .reduce(both)
            .unwrap_or_else(|| Err("no BSS".into()));
        let label = |d| format!("kick: {d}");
        on.iter()
            .map(|(m, iface)| self.kick(iface, *m).map(label).map_err(label))
            .fold(acl, both)
    }

    /// The BSS `mac` is associated with now, by hostapd's `STA`: of the BSSs
    /// that list it as associated, the one it joined last (an entry lingers
    /// on the old BSS for a moment after a roam). Not here when every BSS
    /// answered and none has it, the silent ones' failures otherwise.
    fn current_bss(&mut self, mac: [u8; 6]) -> Result<String, String> {
        let cmd = format!("STA {}", mac::format(mac));
        let mut newest: Option<(u64, String)> = None;
        let mut silent = Vec::new();
        for iface in collect::bss_order(&self.dir) {
            match self.request(&iface, &cmd) {
                Ok(reply) => {
                    let Some(age) = associated_for(&reply, mac) else {
                        continue;
                    };
                    if newest.as_ref().is_none_or(|(a, _)| age < *a) {
                        newest = Some((age, iface));
                    }
                }
                Err(e) => silent.push(e),
            }
        }
        match newest {
            Some((_, iface)) => Ok(iface),
            None if silent.is_empty() => Err(NOT_HERE.into()),
            None => Err(silent.join("; ")),
        }
    }

    /// One BSS's deny ACL made to hold exactly `want`.
    fn sync_bss(&mut self, iface: &str, want: &BTreeSet<[u8; 6]>) -> Outcome {
        let listed = deny_list(&self.request(iface, "DENY_ACL SHOW")?);
        let mut fails = Vec::new();
        let (mut added, mut removed) = (0, 0);
        for m in want.difference(&listed) {
            match self.ask(iface, &format!("DENY_ACL ADD_MAC {}", mac::format(*m))) {
                Ok(_) => added += 1,
                Err(e) => fails.push(e),
            }
        }
        for m in listed.difference(want) {
            match self.ask(iface, &format!("DENY_ACL DEL_MAC {}", mac::format(*m))) {
                Ok(_) => removed += 1,
                Err(e) => fails.push(e),
            }
        }
        match fails.into_iter().next() {
            None => Ok(format!("{iface}: {added} added, {removed} removed")),
            Some(first) => Err(first),
        }
    }

    fn kick(&mut self, iface: &str, mac: [u8; 6]) -> Outcome {
        let cmd = format!("DEAUTHENTICATE {} reason={KICK_REASON}", mac::format(mac));
        self.ask(iface, &cmd)
    }

    /// `cmd` on every BSS, each one tried whatever the others answered.
    fn on_every_bss(&mut self, cmd: &str) -> Outcome {
        collect::bss_order(&self.dir)
            .iter()
            .map(|iface| self.ask(iface, cmd))
            .reduce(both)
            .unwrap_or_else(|| Err("no BSS".into()))
    }

    /// hostapd's reply to `cmd` on `iface`, a success when it is "OK".
    fn ask(&mut self, iface: &str, cmd: &str) -> Outcome {
        match self.request(iface, cmd)? {
            r if r.trim_end() == "OK" => Ok(format!("{iface}: OK")),
            r => Err(format!("{iface}: {}", r.trim_end())),
        }
    }

    /// hostapd's reply to `cmd` on `iface`, whatever it says.
    fn request(&mut self, iface: &str, cmd: &str) -> Outcome {
        self.hostapd
            .try_request(iface, cmd)
            .map_err(|e| match e.kind() {
                ErrorKind::TimedOut => format!("{iface}: no answer"),
                _ => format!("{iface}: {e}"),
            })
    }
}

/// The addresses of a `DENY_ACL SHOW` reply: "<address> VLAN_ID=<n>" each.
fn deny_list(reply: &str) -> BTreeSet<[u8; 6]> {
    reply
        .lines()
        .filter_map(|l| mac::parse(l.split(' ').next()?))
        .collect()
}

/// Puts each held block back on a BSS whose deny ACL lacks it, as after a
/// Wi-Fi restart; asks hostapd nothing while none is held.
pub fn reassert(h: &mut Hostapd, blocks: &Blocks, dir: &Path) {
    let held = crate::lock(blocks);
    if held.is_empty() {
        return;
    }
    for iface in collect::bss_order(dir) {
        let Ok(list) = h.try_request(&iface, "DENY_ACL SHOW") else {
            continue;
        };
        for m in held.difference(&deny_list(&list)) {
            h.request(&iface, &format!("DENY_ACL ADD_MAC {}", mac::format(*m)));
        }
    }
}

/// An individual address: hostapd deauthenticates every station on
/// `DEAUTHENTICATE ff:ff:ff:ff:ff:ff`, and no station has a group address.
fn station_address(m: [u8; 6]) -> bool {
    m[0] & 1 == 0 && m != [0; 6]
}

/// `m`, refused unless it is a station's address.
fn station(m: [u8; 6]) -> Result<[u8; 6], String> {
    if station_address(m) {
        Ok(m)
    } else {
        Err("not a station address".into())
    }
}

/// Whether `last` has `mac` among its stations.
fn listed(last: Option<&Snapshot>, mac: [u8; 6]) -> bool {
    last.is_some_and(|s| s.stations.iter().any(|st| st.mac == mac))
}

/// How long `mac` has been connected, in seconds, by hostapd's answer to
/// `STA <mac>`: its address, then `flags=[AUTH][ASSOC]...` and, among the
/// rest, `connected_time=`. `None` unless that answer is about `mac` and it
/// is associated ("FAIL" for a station hostapd does not know).
fn associated_for(reply: &str, mac: [u8; 6]) -> Option<u64> {
    let mut lines = reply.lines();
    if lines.next().and_then(mac::parse) != Some(mac) {
        return None;
    }
    let mut assoc = false;
    let mut age = u64::MAX;
    for l in lines {
        if let Some(flags) = l.strip_prefix("flags=") {
            assoc = flags.contains("[ASSOC]");
        } else if let Some(t) = l.strip_prefix("connected_time=") {
            age = t.parse().unwrap_or(u64::MAX);
        }
    }
    assoc.then_some(age)
}

/// A request naming `to` as the one candidate, most preferred (its BSS
/// Transition Candidate Preference subelement, 255), every other BSS excluded
/// (abridged), with disassociation after [`STEER_TBTT`].
fn steer_request(mac: [u8; 6], to: &Element) -> String {
    format!(
        "BSS_TM_REQ {} neighbor={},0x{:08x},{},{},{},0301ff pref=1 abridged=1 \
         disassoc_imminent=1 disassoc_timer={STEER_TBTT} valid_int={STEER_TBTT}",
        mac::format(mac),
        mac::format(to.bssid),
        to.bssid_info,
        to.op_class,
        to.channel,
        to.phy_type,
    )
}

/// Both parts' details; a success only when both are.
fn both(a: Outcome, b: Outcome) -> Outcome {
    let ok = a.is_ok() && b.is_ok();
    let (Ok(a) | Err(a)) = a;
    let (Ok(b) | Err(b)) = b;
    let d = a + "; " + &b;
    if ok { Ok(d) } else { Err(d) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::net::UnixDatagram;
    use std::thread;
    use std::time::{Duration, Instant};

    use u6e_proto::msg::{Bss, RateMode, Station};

    use crate::testdir::TestDir;

    const STA: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
    const BSSS: [&str; 4] = ["wlan24", "wlan5", "wlan5-1", "wlan6"];
    /// The SSID of every BSS here, in hex as the neighbor reports carry it.
    const SSID: &str = "73736964";
    /// A neighbor report element hostapd built on an AP (5 GHz, channel 149,
    /// HE, an 80 MHz Wide Bandwidth Channel subelement), on a documentation
    /// BSSID.
    const NR: &str = "02000000000aff5c000080950e0603029b00";
    const TARGET: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0a];

    /// Whether a fake hostapd answers a request, and with what.
    type Reply = fn(&str, &str) -> Option<String>;

    fn ok(_: &str, _: &str) -> Option<String> {
        Some("OK\n".into())
    }

    /// A station hostapd has on a BSS: the BSS, its address, its flags and
    /// its `connected_time`.
    type Entry = (&'static str, [u8; 6], &'static str, u64);

    const ASSOC: &str = "[AUTH][ASSOC][AUTHORIZED]";

    /// hostapds at `BSSS` answering with `reply` (`STA` from the stations in
    /// `on`, unless `reply` keeps the BSS silent), the requests they got, and
    /// commands for them.
    struct Rig {
        t: TestDir,
        log: Arc<Mutex<Vec<String>>>,
        on: Arc<Mutex<Vec<Entry>>>,
        targets: Arc<Mutex<Vec<Target>>>,
        blocks: Arc<Blocks>,
        cmds: Commands,
    }

    /// hostapd's answer to `STA <mac>` on `iface`, in its layout.
    fn sta_reply(on: &[Entry], iface: &str, req: &str) -> String {
        let mac = req.strip_prefix("STA ").and_then(mac::parse);
        on.iter().find(|e| e.0 == iface && Some(e.1) == mac).map_or(
            "FAIL\n".into(),
            |&(_, m, flags, age)| {
                format!(
                    "{}\nflags={flags}\naid=1\ncapability=0x0\nconnected_time={age}\n",
                    mac::format(m)
                )
            },
        )
    }

    impl Rig {
        fn new(reply: Reply) -> Self {
            let t = TestDir::new();
            let dir = t.path().join("hostapd");
            fs::create_dir_all(&dir).unwrap();
            let log = Arc::new(Mutex::new(Vec::new()));
            // `STA` on wlan5-1, as the snapshot has it.
            let on = Arc::new(Mutex::new(vec![("wlan5-1", STA, ASSOC, 60)]));
            for iface in BSSS {
                let server = UnixDatagram::bind(dir.join(iface)).unwrap();
                let (log, on) = (Arc::clone(&log), Arc::clone(&on));
                thread::spawn(move || {
                    let mut buf = [0; 4096];
                    while let Ok((n, from)) = server.recv_from(&mut buf) {
                        let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                        log.lock().unwrap().push(format!("{iface} {req}"));
                        let r = reply(iface, &req).map(|r| match req.starts_with("STA ") {
                            true => sta_reply(&on.lock().unwrap(), iface, &req),
                            false => r,
                        });
                        if let (Some(r), Some(p)) = (r, from.as_pathname()) {
                            let _ = server.send_to(r.as_bytes(), p);
                        }
                    }
                });
            }
            let targets = Arc::new(Mutex::new(vec![
                target(SSID, NR),
                // The station's own BSS, its 2.4 GHz one, and a BSS of
                // another SSID.
                target(SSID, "020000000012ff5c000080950e0603029b00"),
                target(SSID, "020000000010ff5c000080950e0603029b00"),
                target("6f74686572", "02000000000bff5c000080950e0603029b00"),
            ]));
            let blocks = Arc::new(Blocks::default());
            let cmds = Commands::open(
                &t.path().join("run"),
                &dir,
                Arc::clone(&targets),
                Arc::clone(&blocks),
            )
            .unwrap();
            Rig {
                t,
                log,
                on,
                targets,
                blocks,
                cmds,
            }
        }

        fn run(&mut self, kind: CommandKind) -> CommandResult {
            self.cmds.run(&Command { id: 7, kind }, Some(&snapshot()))
        }

        /// The requests that act, the `STA` lookups left out.
        fn requests(&self) -> Vec<String> {
            self.all_requests()
                .into_iter()
                .filter(|r| !r.contains(" STA "))
                .collect()
        }

        fn all_requests(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
        }

        /// What hostapd has of the station now, whatever the snapshot says.
        fn station_on(&self, entries: &[Entry]) {
            *self.on.lock().unwrap() = entries.to_vec();
        }
    }

    fn target(ssid: &str, nr: &str) -> Target {
        Target {
            ssid: ssid.into(),
            nr: Element::parse(nr).unwrap(),
        }
    }

    /// `STA` on wlan5-1; each BSS's BSSID is 02:00:00:00:00:1<index>.
    fn snapshot() -> Snapshot {
        let bsss = BSSS
            .iter()
            .zip(0x10..)
            .map(|(name, last)| Bss {
                ifname: (*name).into(),
                bssid: [0x02, 0, 0, 0, 0, last],
                ssid: "ssid".into(),
                phy: String::new(),
                vlan: 0,
            })
            .collect();
        Snapshot {
            seq: 1,
            uptime_s: 0,
            load_milli: 0,
            mem_avail_kb: 0,
            nss_load_pct: 0,
            temps: Vec::new(),
            radios: Vec::new(),
            bsss,
            stations: vec![station(STA, 2)],
        }
    }

    fn station(mac: [u8; 6], bss: u16) -> Station {
        Station {
            mac,
            bss,
            signal: -50,
            signal_avg: -50,
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
            tx_mode: RateMode::Legacy,
            rx_mode: RateMode::Legacy,
            tx_nss: 0,
            rx_nss: 0,
            tx_airtime_us: 0,
            rx_airtime_us: 0,
            inactive_ms: 0,
            connected_s: 0,
            vlan: 0,
        }
    }

    fn kinds(mac: [u8; 6]) -> [CommandKind; 5] {
        [
            CommandKind::Kick { mac },
            CommandKind::Block { mac },
            CommandKind::Unblock { mac },
            CommandKind::Steer {
                mac,
                target_bssid: TARGET,
            },
            CommandKind::SyncBlocks {
                macs: vec![STA, mac],
            },
        ]
    }

    /// A command's address is six bytes: the controller makes them only from
    /// text `mac::parse` takes whole, and the agent writes them back as
    /// exactly six pairs of hex digits. A group or zero address (`ff:..:ff`
    /// would kick every station) is refused before any request.
    #[test]
    fn command_mac_validation() {
        for s in [
            "02:00:00:00:00:01 ;REMOVE_NEIGHBOR 02:00:00:00:00:02",
            "02:00:00:00:00:01\nDENY_ACL CLEAR",
            "02:00:00:00:00:01 reason=1",
            "02:00:00:00:00",
            "02:00:00:00:00:01:02",
            "02:00:00:00:00:001",
        ] {
            assert_eq!(mac::parse(s), None, "{s:?}");
        }
        let mixed = Some([0x02, 0, 0, 0xab, 0xcd, 0xef]);
        assert_eq!(mac::parse("02:00:00:AB:cd:EF"), mixed);
        assert_eq!(mac::parse("02:00:00:ab:CD:ef"), mixed);

        let mut r = Rig::new(ok);
        let groups = [
            [0xff; 6],
            [0x01, 0, 0x5e, 0, 0, 1],
            [0x33, 0x33, 0, 0, 0, 1],
            [0; 6],
        ];
        for mac in groups {
            for kind in kinds(mac) {
                let res = r.run(kind);
                assert_eq!(
                    (res.ok, res.detail.as_str()),
                    (false, "not a station address")
                );
            }
        }
        assert!(r.requests().is_empty());
        assert!(r.blocks.lock().unwrap().is_empty());

        // Each byte goes out as two lowercase hex digits, and nothing else.
        let mac = [0x02, 0xff, 0x0a, 0xa0, 0x7f, 0x80];
        let mut snap = snapshot();
        snap.stations = vec![station(mac, 2)];
        r.station_on(&[("wlan5-1", mac, ASSOC, 1)]);
        let kick = Command {
            id: 1,
            kind: CommandKind::Kick { mac },
        };
        assert!(r.cmds.run(&kick, Some(&snap)).ok);
        assert_eq!(
            r.requests(),
            ["wlan5-1 DEAUTHENTICATE 02:ff:0a:a0:7f:80 reason=3"]
        );
    }

    #[test]
    fn steer_to_unknown_bssid_refused() {
        let mut r = Rig::new(ok);
        let steer = |target_bssid| CommandKind::Steer {
            mac: STA,
            target_bssid,
        };
        for (to, why) in [
            ([0x02, 0, 0, 0, 0, 0x99], "unknown target"),
            ([0x02, 0, 0, 0, 0, 0x0b], "the target serves another SSID"),
            ([0x02, 0, 0, 0, 0, 0x12], "already on the target"),
        ] {
            let res = r.run(steer(to));
            assert_eq!((res.ok, res.detail.as_str()), (false, why));
        }
        // The target's AP stopped answering, so the next round dropped it.
        r.targets.lock().unwrap().retain(|t| t.nr.bssid != TARGET);
        let res = r.run(steer(TARGET));
        assert_eq!((res.ok, res.detail.as_str()), (false, "unknown target"));
        assert!(r.requests().is_empty());
    }

    /// Not here is hostapd's word: a station of the snapshot that has left
    /// since, or is only authenticated, is refused after the lookups alone.
    #[test]
    fn a_station_not_here_is_refused_before_any_request() {
        let mut r = Rig::new(ok);
        let kinds = |mac| {
            [
                CommandKind::Kick { mac },
                CommandKind::Steer {
                    mac,
                    target_bssid: TARGET,
                },
            ]
        };
        let away = [0x02, 0, 0, 0, 0, 0x99];
        for kind in kinds(away) {
            let res = r.run(kind);
            assert_eq!(
                (res.ok, res.detail.as_str()),
                (false, "not associated here")
            );
        }
        for on in [&[][..], &[("wlan5-1", STA, "[AUTH]", 1)]] {
            r.station_on(on);
            for kind in kinds(STA) {
                let res = r.run(kind);
                assert_eq!(
                    (res.ok, res.detail.as_str()),
                    (false, "not associated here")
                );
            }
        }
        assert!(r.requests().is_empty());
        // Each lookup asked every BSS.
        assert_eq!(r.all_requests().len(), 6 * BSSS.len());
    }

    #[test]
    fn kick_goes_to_the_bss_the_station_is_on() {
        let mut r = Rig::new(ok);
        let res = r.run(CommandKind::Kick { mac: STA });
        let done = CommandResult {
            id: 7,
            ok: true,
            detail: "wlan5-1: OK".into(),
        };
        assert_eq!(res, done);
        assert_eq!(
            r.requests(),
            ["wlan5-1 DEAUTHENTICATE 02:00:00:00:00:01 reason=3"]
        );
    }

    /// The station changed bands since the snapshot, which still has it on
    /// wlan5-1: the kick goes where hostapd has it now. Without a snapshot
    /// as well.
    #[test]
    fn kick_follows_a_station_that_moved_since_the_snapshot() {
        let mut r = Rig::new(ok);
        r.station_on(&[("wlan24", STA, ASSOC, 2)]);
        let res = r.run(CommandKind::Kick { mac: STA });
        assert_eq!((res.ok, res.detail.as_str()), (true, "wlan24: OK"));
        let kick = Command {
            id: 1,
            kind: CommandKind::Kick { mac: STA },
        };
        assert!(r.cmds.run(&kick, None).ok);
        assert_eq!(
            r.requests(),
            ["wlan24 DEAUTHENTICATE 02:00:00:00:00:01 reason=3"; 2]
        );
    }

    /// Moments after a roam the old BSS can still list the station: the one
    /// it joined last is where it is.
    #[test]
    fn of_two_associations_the_newest_counts() {
        let mut r = Rig::new(ok);
        r.station_on(&[("wlan24", STA, ASSOC, 0), ("wlan5-1", STA, ASSOC, 300)]);
        let res = r.run(CommandKind::Kick { mac: STA });
        assert_eq!((res.ok, res.detail.as_str()), (true, "wlan24: OK"));
        r.station_on(&[("wlan24", STA, ASSOC, 300), ("wlan6", STA, ASSOC, 1)]);
        let res = r.run(CommandKind::Kick { mac: STA });
        assert_eq!((res.ok, res.detail.as_str()), (true, "wlan6: OK"));
    }

    #[test]
    fn hostapds_sta_answer_is_read_for_its_station_only() {
        let sta = "02:00:00:00:00:01\nflags=[AUTH][ASSOC][AUTHORIZED][WMM][HE]\naid=3\n\
                   rx_packets=10\nconnected_time=42\nsupported_rates=0c 12\n";
        assert_eq!(associated_for(sta, STA), Some(42));
        assert_eq!(associated_for(sta, [0x02, 0, 0, 0, 0, 0x02]), None);
        assert_eq!(associated_for("FAIL\n", STA), None);
        assert_eq!(associated_for("", STA), None);
        let no_time = "02:00:00:00:00:01\nflags=[AUTH][ASSOC]\n";
        assert_eq!(associated_for(no_time, STA), Some(u64::MAX));
        let auth_only = "02:00:00:00:00:01\nflags=[AUTH]\nconnected_time=1\n";
        assert_eq!(associated_for(auth_only, STA), None);
    }

    #[test]
    fn block_denies_on_every_bss_then_kicks() {
        let mut r = Rig::new(ok);
        let res = r.run(CommandKind::Block { mac: STA });
        assert_eq!(
            (res.ok, res.detail.as_str()),
            (
                true,
                "wlan24: OK; wlan5: OK; wlan5-1: OK; wlan6: OK; kick: wlan5-1: OK"
            )
        );
        let mut want: Vec<String> = BSSS
            .iter()
            .map(|b| format!("{b} DENY_ACL ADD_MAC 02:00:00:00:00:01"))
            .collect();
        want.push("wlan5-1 DEAUTHENTICATE 02:00:00:00:00:01 reason=3".into());
        assert_eq!(r.requests(), want);
        assert!(r.blocks.lock().unwrap().contains(&STA));

        // A client blocked while elsewhere is denied here all the same.
        let away = [0x02, 0, 0, 0, 0, 0x99];
        let res = r.run(CommandKind::Block { mac: away });
        assert!(res.ok);
        assert!(res.detail.ends_with("wlan6: OK; kick: not associated here"));
        assert_eq!(r.requests().len(), want.len() + BSSS.len());
    }

    #[test]
    fn unblock_allows_on_every_bss() {
        let mut r = Rig::new(ok);
        r.run(CommandKind::Block { mac: STA });
        r.log.lock().unwrap().clear();
        let res = r.run(CommandKind::Unblock { mac: STA });
        assert_eq!(
            (res.ok, res.detail.as_str()),
            (true, "wlan24: OK; wlan5: OK; wlan5-1: OK; wlan6: OK")
        );
        let want: Vec<String> = BSSS
            .iter()
            .map(|b| format!("{b} DENY_ACL DEL_MAC 02:00:00:00:00:01"))
            .collect();
        assert_eq!(r.requests(), want);
        assert!(r.blocks.lock().unwrap().is_empty());
    }

    #[test]
    fn steer_request_is_built_from_the_targets_element() {
        let mut r = Rig::new(ok);
        let res = r.run(CommandKind::Steer {
            mac: STA,
            target_bssid: TARGET,
        });
        assert_eq!((res.ok, res.detail.as_str()), (true, "wlan5-1: OK"));
        assert_eq!(
            r.requests(),
            ["wlan5-1 BSS_TM_REQ 02:00:00:00:00:01 \
              neighbor=02:00:00:00:00:0a,0x00005cff,128,149,14,0301ff \
              pref=1 abridged=1 disassoc_imminent=1 disassoc_timer=100 valid_int=100"]
        );
    }

    /// The snapshot has the station on wlan5-1, but it changed bands since:
    /// the request goes to wlan24, and wlan5-1 is a target like any other.
    #[test]
    fn steer_follows_a_station_that_moved_since_the_snapshot() {
        let mut r = Rig::new(ok);
        r.station_on(&[("wlan24", STA, ASSOC, 2)]);
        let res = r.run(CommandKind::Steer {
            mac: STA,
            target_bssid: [0x02, 0, 0, 0, 0, 0x12],
        });
        assert_eq!((res.ok, res.detail.as_str()), (true, "wlan24: OK"));
        let reqs = r.requests();
        assert_eq!(reqs.len(), 1);
        assert!(
            reqs[0].starts_with("wlan24 BSS_TM_REQ 02:00:00:00:00:01 neighbor=02:00:00:00:00:12,"),
            "{reqs:?}"
        );
        // Moved onto the target itself: nothing to ask.
        r.station_on(&[("wlan5-1", STA, ASSOC, 0)]);
        let res = r.run(CommandKind::Steer {
            mac: STA,
            target_bssid: [0x02, 0, 0, 0, 0, 0x12],
        });
        assert_eq!(
            (res.ok, res.detail.as_str()),
            (false, "already on the target")
        );
        assert_eq!(r.requests().len(), 1);
    }

    #[test]
    fn a_refusal_from_hostapd_fails_the_command_with_its_text() {
        let mut r =
            Rig::new(|iface, _| Some(if iface == "wlan5" { "FAIL\n" } else { "OK\n" }.into()));
        let res = r.run(CommandKind::Block { mac: STA });
        assert_eq!(
            (res.ok, res.detail.as_str()),
            (
                false,
                "wlan24: OK; wlan5: FAIL; wlan5-1: OK; wlan6: OK; kick: wlan5-1: OK"
            )
        );
        // Held all the same: the reassertion tries the BSS that refused again.
        assert!(r.blocks.lock().unwrap().contains(&STA));

        let mut r = Rig::new(|_, _| Some("UNKNOWN COMMAND\n".into()));
        let res = r.run(CommandKind::Kick { mac: STA });
        assert_eq!(
            (res.ok, res.detail.as_str()),
            (false, "wlan5-1: UNKNOWN COMMAND")
        );
    }

    #[test]
    fn a_silent_hostapd_fails_its_part_in_time() {
        let mut r = Rig::new(|iface, _| (iface != "wlan5-1").then(|| "OK\n".into()));
        let start = Instant::now();
        let res = r.run(CommandKind::Kick { mac: STA });
        assert_eq!((res.ok, res.detail.as_str()), (false, "wlan5-1: no answer"));
        let res = r.run(CommandKind::Unblock { mac: STA });
        assert_eq!(
            (res.ok, res.detail.as_str()),
            (
                false,
                "wlan24: OK; wlan5: OK; wlan5-1: no answer; wlan6: OK"
            )
        );
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_long_answer_is_cut_to_the_detail_limit() {
        let mut r = Rig::new(|_, _| Some("x".repeat(500)));
        let res = r.run(CommandKind::Kick { mac: STA });
        assert!(!res.ok);
        assert_eq!(res.detail.chars().count(), DETAIL_MAX);
        assert!(res.detail.starts_with("wlan5-1: xxx"));
    }

    /// A stale block (a client unblocked while the AP could not be told) is
    /// on wlan5 and wlan6, `STA` is new: the sync adds `STA` where it is
    /// missing, removes the stale one, and kicks `STA`.
    #[test]
    fn sync_makes_the_blocks_exactly_the_list() {
        fn acl(iface: &str, req: &str) -> Option<String> {
            match (iface, req) {
                ("wlan5" | "wlan6", "DENY_ACL SHOW") => {
                    Some("02:00:00:00:00:55 VLAN_ID=0\n".into())
                }
                ("wlan24", "DENY_ACL SHOW") => Some("02:00:00:00:00:01 VLAN_ID=0\n".into()),
                (_, "DENY_ACL SHOW") => Some(String::new()),
                _ => Some("OK\n".into()),
            }
        }
        let stale = [0x02, 0, 0, 0, 0, 0x55];
        let mut r = Rig::new(acl);
        r.blocks.lock().unwrap().insert(stale);
        let res = r.run(CommandKind::SyncBlocks { macs: vec![STA] });
        assert_eq!(
            (res.ok, res.detail.as_str()),
            (
                true,
                "wlan24: 0 added, 0 removed; wlan5: 1 added, 1 removed; \
                 wlan5-1: 1 added, 0 removed; wlan6: 1 added, 1 removed; kick: wlan5-1: OK"
            )
        );
        let add = |b| format!("{b} DENY_ACL ADD_MAC 02:00:00:00:00:01");
        let del = |b| format!("{b} DENY_ACL DEL_MAC 02:00:00:00:00:55");
        let show = |b| format!("{b} DENY_ACL SHOW");
        assert_eq!(
            r.requests(),
            [
                show("wlan24"),
                show("wlan5"),
                add("wlan5"),
                del("wlan5"),
                show("wlan5-1"),
                add("wlan5-1"),
                show("wlan6"),
                add("wlan6"),
                del("wlan6"),
                "wlan5-1 DEAUTHENTICATE 02:00:00:00:00:01 reason=3".into(),
            ]
        );
        assert_eq!(*r.blocks.lock().unwrap(), BTreeSet::from([STA]));
    }

    /// What the ACLs hold already is asked for and left alone.
    #[test]
    fn sync_again_changes_nothing() {
        fn acl(_: &str, req: &str) -> Option<String> {
            match req {
                "DENY_ACL SHOW" => Some("02:00:00:00:00:99 VLAN_ID=0\n".into()),
                _ => Some("OK\n".into()),
            }
        }
        let mut r = Rig::new(acl);
        let away = [0x02, 0, 0, 0, 0, 0x99];
        for _ in 0..2 {
            let res = r.run(CommandKind::SyncBlocks { macs: vec![away] });
            assert!(res.ok, "{}", res.detail);
        }
        let shows: Vec<String> = BSSS.iter().map(|b| format!("{b} DENY_ACL SHOW")).collect();
        assert_eq!(r.requests(), [shows.clone(), shows].concat());
        // An empty list clears every block.
        r.log.lock().unwrap().clear();
        assert!(r.run(CommandKind::SyncBlocks { macs: Vec::new() }).ok);
        assert_eq!(r.requests().len(), 2 * BSSS.len());
        assert!(r.blocks.lock().unwrap().is_empty());
    }

    #[test]
    fn a_sync_beyond_the_cap_is_refused_before_any_request() {
        let mut r = Rig::new(ok);
        r.blocks.lock().unwrap().insert(STA);
        let macs: Vec<[u8; 6]> = (0..=SYNC_MAX as u16)
            .map(|i| {
                let [hi, lo] = i.to_be_bytes();
                [0x02, 0, 0, 0, hi, lo]
            })
            .collect();
        let res = r.run(CommandKind::SyncBlocks { macs });
        assert_eq!(
            (res.ok, res.detail.as_str()),
            (false, "more than 1024 blocks")
        );
        assert!(r.requests().is_empty());
        assert_eq!(*r.blocks.lock().unwrap(), BTreeSet::from([STA]));
    }

    /// A hostapd started again has an empty deny ACL: each held block goes
    /// back on, only where it is missing.
    #[test]
    fn held_blocks_go_back_on_a_bss_that_lost_them() {
        fn acl(iface: &str, req: &str) -> Option<String> {
            match (iface, req) {
                ("wlan5", "DENY_ACL SHOW") => Some(String::new()),
                (_, "DENY_ACL SHOW") => Some("02:00:00:00:00:01 VLAN_ID=0\n".into()),
                _ => Some("OK\n".into()),
            }
        }
        let r = Rig::new(acl);
        let dir = r.t.path().join("hostapd");
        let mut h = Hostapd::bind(&r.t.path().join("run"), "ctrl", &dir).unwrap();
        reassert(&mut h, &r.blocks, &dir);
        assert!(r.requests().is_empty());

        r.blocks.lock().unwrap().insert(STA);
        reassert(&mut h, &r.blocks, &dir);
        let mut want: Vec<String> = BSSS.iter().map(|b| format!("{b} DENY_ACL SHOW")).collect();
        want.insert(2, "wlan5 DENY_ACL ADD_MAC 02:00:00:00:00:01".into());
        assert_eq!(r.requests(), want);
    }
}
