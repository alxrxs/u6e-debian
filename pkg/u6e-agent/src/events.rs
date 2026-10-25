//! What happens between two snapshots: stations associating and leaving, EAP
//! results, a radio going up or down (hostapd's event stream, one attached
//! control socket per BSS) and a Wi-Fi firmware crash (the kernel log). One
//! thread owns all the sockets; it re-attaches to a hostapd that restarted
//! and picks up BSSs that appear, so nothing has to restart it.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::os::fd::AsRawFd;
use std::sync::mpsc::{SyncSender, TrySendError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use u6e_proto::mac;
use u6e_proto::msg::{Event, EventKind};

use crate::clientsock::ClientSocket;
use crate::collect::{self, Paths};
use crate::kmsg::{self, Kmsg};

/// How often the set of hostapd sockets and the kernel log are looked at when
/// nothing arrives.
const RESCAN_MS: i32 = 1000;
/// How long hostapd has to confirm an ATTACH. A BSS that does not is tried
/// again after a wait that doubles up to `RETRY_MAX`, so a hung hostapd's
/// queue does not fill with them.
const ATTACH_TIMEOUT: Duration = Duration::from_secs(1);
const RETRY_MIN: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(30);
/// How often each attached socket is checked for a hostapd that went away.
const PROBE_EVERY: Duration = Duration::from_secs(2);

pub struct Events;

impl Events {
    /// Starts the thread; events go to `tx`, which drops them when it is full
    /// (the next snapshot carries the state anyway) and ends the thread when
    /// its receiver is gone.
    pub fn spawn(tx: SyncSender<Event>) -> io::Result<()> {
        Self::spawn_with(tx, Paths::default())
    }

    pub fn spawn_with(tx: SyncSender<Event>, paths: Paths) -> io::Result<()> {
        thread::Builder::new()
            .name("events".into())
            .spawn(move || run(&tx, &paths))?;
        Ok(())
    }
}

/// A control socket attached to one hostapd BSS socket; it is connected to
/// that very socket, not to the path, so a hostapd that restarted is noticed
/// even when its new socket file takes the old one's place.
struct Attached {
    sock: ClientSocket,
    /// When ATTACH was sent, until hostapd confirms it. The answer comes
    /// through the poll loop like any event, so one silent hostapd holds up
    /// nobody else's.
    pending: Option<Instant>,
}

/// When a BSS whose hostapd did not confirm ATTACH is tried again.
struct Retry {
    at: Instant,
    wait: Duration,
}

impl Attached {
    /// Whether events still flow: the hostapd behind the socket is still
    /// there (a datagram to a closed peer is refused; hostapd answers the PING,
    /// and the answer is ignored), and so is the path it sends them to.
    fn alive(&self) -> bool {
        if !self.sock.reachable() {
            return false;
        }
        match self.sock.send(b"PING") {
            Ok(_) => true,
            Err(e) => e.kind() == io::ErrorKind::WouldBlock,
        }
    }
}

/// Sends ATTACH to the BSS socket `name`; hostapd's OK arrives later.
fn attach(paths: &Paths, name: &str) -> Option<Attached> {
    let sock = ClientSocket::bind(&paths.run, &format!("ev-{name}")).ok()?;
    sock.set_nonblocking(true).ok()?;
    sock.connect(paths.hostapd.join(name)).ok()?;
    sock.send(b"ATTACH").ok()?;
    Some(Attached {
        sock,
        pending: Some(Instant::now()),
    })
}

fn run(tx: &SyncSender<Event>, paths: &Paths) {
    let mut kmsg = Kmsg::open(&paths.kmsg, true);
    let mut attached: BTreeMap<String, Attached> = BTreeMap::new();
    let mut retry: BTreeMap<String, Retry> = BTreeMap::new();
    let mut radios = HashMap::new();
    let mut buf = vec![0; 4096];
    let mut last_probe = Instant::now();
    loop {
        let order = collect::bss_order(&paths.hostapd);
        let now = Instant::now();
        let probe = now.duration_since(last_probe) >= PROBE_EVERY;
        if probe {
            last_probe = now;
        }
        attached.retain(|name, a| {
            let unconfirmed = a
                .pending
                .is_some_and(|sent| now.duration_since(sent) >= ATTACH_TIMEOUT);
            if unconfirmed {
                let wait = retry
                    .get(name)
                    .map_or(RETRY_MIN, |r| (r.wait * 2).min(RETRY_MAX));
                retry.insert(
                    name.clone(),
                    Retry {
                        at: now + wait,
                        wait,
                    },
                );
            }
            let dead = probe && a.pending.is_none() && !a.alive();
            order.contains(name) && !unconfirmed && !dead
        });
        retry.retain(|name, _| order.contains(name));
        for name in &order {
            let due = retry.get(name).is_none_or(|r| now >= r.at);
            if due
                && !attached.contains_key(name)
                && let Some(a) = attach(paths, name)
            {
                attached.insert(name.clone(), a);
            }
        }

        let mut fds: Vec<libc::pollfd> = attached
            .values()
            .map(|a| libc::pollfd {
                fd: a.sock.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, RESCAN_MS) };

        let mut events = Vec::new();
        for ((name, a), fd) in attached.iter_mut().zip(&fds) {
            if fd.revents == 0 {
                continue;
            }
            let bss = order.iter().position(|n| n == name).unwrap_or(0) as u16;
            while let Ok(n) = a.sock.recv(&mut buf) {
                if a.pending.is_some() {
                    if buf[..n].starts_with(b"OK") {
                        a.pending = None;
                        retry.remove(name);
                        // It may have come up before the attachment: its
                        // radio's next event is news either way.
                        radios.remove(&collect::phy_of(&paths.sys(), name));
                    }
                    continue;
                }
                let msg = String::from_utf8_lossy(&buf[..n]);
                events.extend(parse(&msg, bss, || collect::phy_of(&paths.sys(), name)));
            }
        }
        events.retain(|kind| changes_radio(&mut radios, kind));
        for msg in kmsg.drain() {
            if kmsg::is_fw_crash(&msg) {
                events.extend(
                    kmsg::crashed_phy(&paths.sys(), &msg).map(|phy| EventKind::FwCrash { phy }),
                );
            }
        }
        for kind in events {
            match tx.try_send(Event {
                at_ms: now_ms(),
                kind,
            }) {
                Err(TrySendError::Disconnected(_)) => return,
                Ok(()) | Err(TrySendError::Full(_)) => {}
            }
        }
    }
}

/// Whether `kind` is to be reported: anything but a radio event, and a radio
/// event that changes what was last reported of that radio. hostapd reports
/// AP-DISABLED from every BSS of a radio that stops.
fn changes_radio(last: &mut HashMap<String, bool>, kind: &EventKind) -> bool {
    let (phy, up) = match kind {
        EventKind::RadioUp { phy } => (phy, true),
        EventKind::RadioDown { phy } => (phy, false),
        _ => return true,
    };
    last.insert(phy.clone(), up) != Some(up)
}

/// Milliseconds since the epoch, as the AP's clock has it.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// The event a hostapd message reports, "<3>NAME [MAC ...]" (the priority
/// prefix stripped); none for what is not one of ours. `phy` names the phy of
/// the BSS, for the events about the radio.
fn parse(msg: &str, bss: u16, phy: impl FnOnce() -> String) -> Option<EventKind> {
    let msg = msg
        .strip_prefix('<')
        .and_then(|m| m.split_once('>'))
        .map_or(msg, |(_, m)| m);
    let mut f = msg.split_whitespace();
    let name = f.next()?;
    let station = |f: &mut std::str::SplitWhitespace| mac::parse(f.next()?);
    Some(match name {
        "AP-STA-CONNECTED" => EventKind::Assoc {
            mac: station(&mut f)?,
            bss,
        },
        "AP-STA-DISCONNECTED" => EventKind::Disassoc {
            mac: station(&mut f)?,
            bss,
        },
        // The 2 forms are hostapd relaying to a RADIUS server, the plain
        // ones its own EAP server.
        "CTRL-EVENT-EAP-SUCCESS" | "CTRL-EVENT-EAP-SUCCESS2" => EventKind::EapOk {
            mac: station(&mut f)?,
            bss,
        },
        "CTRL-EVENT-EAP-FAILURE"
        | "CTRL-EVENT-EAP-FAILURE2"
        | "CTRL-EVENT-EAP-TIMEOUT-FAILURE"
        | "CTRL-EVENT-EAP-TIMEOUT-FAILURE2" => EventKind::EapFail {
            mac: station(&mut f)?,
            bss,
        },
        "AP-ENABLED" => EventKind::RadioUp { phy: phy() },
        "AP-DISABLED" => EventKind::RadioDown { phy: phy() },
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixDatagram;
    use std::path::{Path, PathBuf};
    use std::sync::mpsc::sync_channel;

    const STA: [u8; 6] = [2, 0, 0, 0, 0, 8];
    const WAIT: Duration = Duration::from_secs(5);

    fn phy1() -> String {
        "phy1".into()
    }

    #[test]
    fn parses_what_hostapd_reports() {
        let a = "02:00:00:00:00:08";
        assert_eq!(
            parse(&format!("<3>AP-STA-CONNECTED {a} auth_alg=open"), 2, phy1),
            Some(EventKind::Assoc { mac: STA, bss: 2 })
        );
        assert_eq!(
            parse(&format!("AP-STA-DISCONNECTED {a}"), 0, phy1),
            Some(EventKind::Disassoc { mac: STA, bss: 0 })
        );
        assert_eq!(
            parse(&format!("<3>CTRL-EVENT-EAP-SUCCESS {a}"), 1, phy1),
            Some(EventKind::EapOk { mac: STA, bss: 1 })
        );
        assert_eq!(
            parse(&format!("<3>CTRL-EVENT-EAP-FAILURE {a}"), 1, phy1),
            Some(EventKind::EapFail { mac: STA, bss: 1 })
        );
        assert_eq!(
            parse("<3>AP-ENABLED", 0, phy1),
            Some(EventKind::RadioUp { phy: "phy1".into() })
        );
        assert_eq!(
            parse("<3>AP-DISABLED", 0, phy1),
            Some(EventKind::RadioDown { phy: "phy1".into() })
        );
    }

    /// With an external RADIUS server hostapd only relays EAP, and reports
    /// its results with a 2 suffix.
    #[test]
    fn reports_the_eap_results_of_a_radius_server() {
        let a = "02:00:00:00:00:08";
        for (name, ok) in [
            ("CTRL-EVENT-EAP-SUCCESS2", true),
            ("CTRL-EVENT-EAP-FAILURE2", false),
            ("CTRL-EVENT-EAP-TIMEOUT-FAILURE", false),
            ("CTRL-EVENT-EAP-TIMEOUT-FAILURE2", false),
        ] {
            let want = if ok {
                EventKind::EapOk { mac: STA, bss: 1 }
            } else {
                EventKind::EapFail { mac: STA, bss: 1 }
            };
            assert_eq!(parse(&format!("<3>{name} {a}"), 1, phy1), Some(want));
        }
    }

    /// hostapd says AP-DISABLED for every BSS of a radio that stops, and
    /// AP-ENABLED once; the radio's events are its changes of state.
    #[test]
    fn one_radio_stopping_is_one_event() {
        let up = |p: &str| EventKind::RadioUp { phy: p.into() };
        let down = |p: &str| EventKind::RadioDown { phy: p.into() };
        let assoc = EventKind::Assoc { mac: STA, bss: 0 };
        let mut radios = HashMap::new();
        let kept: Vec<bool> = [
            down("phy1"),
            down("phy1"),
            assoc.clone(),
            down("phy1"),
            down("phy2"),
            up("phy1"),
            up("phy1"),
            assoc,
            down("phy1"),
        ]
        .iter()
        .map(|k| changes_radio(&mut radios, k))
        .collect();
        assert_eq!(
            kept,
            [true, false, true, false, true, true, false, true, true]
        );
    }

    /// The events of one boot of a real AP, as hostapd logged them.
    #[test]
    fn parses_a_recorded_event_stream() {
        let order = ["wlan24", "wlan5", "wlan6"];
        let mut got = Vec::new();
        for l in include_str!("../tests/fixtures/hostapd-events.txt").lines() {
            let Some((ifname, msg)) = l.split_once(' ').filter(|_| !l.starts_with('#')) else {
                continue;
            };
            let bss = order.iter().position(|n| *n == ifname).unwrap() as u16;
            got.extend(parse(msg, bss, || format!("phy-{ifname}")));
        }
        let count = |f: fn(&EventKind) -> bool| got.iter().filter(|k| f(k)).count();
        assert_eq!(count(|k| matches!(k, EventKind::Assoc { .. })), 15);
        assert_eq!(count(|k| matches!(k, EventKind::Disassoc { .. })), 10);
        assert_eq!(count(|k| matches!(k, EventKind::RadioUp { .. })), 3);
        let sta = |n| [2, 0, 0, 0, 0, n];
        let eap: Vec<_> = got
            .iter()
            .filter(|k| matches!(k, EventKind::EapOk { .. } | EventKind::EapFail { .. }))
            .cloned()
            .collect();
        assert_eq!(
            eap,
            [
                EventKind::EapOk {
                    mac: sta(6),
                    bss: 1
                },
                EventKind::EapFail {
                    mac: sta(2),
                    bss: 1
                },
                EventKind::EapFail {
                    mac: sta(2),
                    bss: 1
                },
                EventKind::EapOk {
                    mac: sta(2),
                    bss: 1
                },
            ]
        );
        assert_eq!(got.len(), 15 + 10 + 3 + 4);
    }

    #[test]
    fn ignores_everything_else() {
        for m in [
            "<3>CTRL-EVENT-EAP-SUCCESSX 02:00:00:00:00:08",
            "<3>CTRL-EVENT-EAP-RETRANSMIT2 02:00:00:00:00:08",
            "<3>AP-STA-CONNECTED",
            "<3>AP-STA-CONNECTED 02:00:00:00:00",
            "<3>AP-STA-CONNECTED 02:00:00:00:00:08:09",
            "<3>WPS-PIN-NEEDED",
            "",
        ] {
            assert_eq!(parse(m, 0, phy1), None, "{m}");
        }
    }

    /// A stand-in for hostapd's control socket: answers ATTACH and remembers
    /// who attached, so the test can push events to it.
    struct FakeHostapd {
        sock: UnixDatagram,
        client: Option<PathBuf>,
    }

    impl FakeHostapd {
        fn bind(path: &Path) -> Self {
            let sock = UnixDatagram::bind(path).unwrap();
            sock.set_read_timeout(Some(WAIT)).unwrap();
            FakeHostapd { sock, client: None }
        }

        fn wait_attach(&mut self) {
            let mut buf = [0; 64];
            let (mut n, mut from) = self.sock.recv_from(&mut buf).unwrap();
            // The liveness probes of an earlier attachment.
            while &buf[..n] == b"PING" {
                (n, from) = self.sock.recv_from(&mut buf).unwrap();
            }
            assert_eq!(&buf[..n], b"ATTACH");
            let client = from.as_pathname().unwrap().to_owned();
            self.sock.send_to(b"OK\n", &client).unwrap();
            self.client = Some(client);
        }

        fn event(&self, msg: &str) {
            self.sock
                .send_to(msg.as_bytes(), self.client.as_ref().unwrap())
                .unwrap();
        }
    }

    fn paths(t: &TestDir) -> Paths {
        let p = Paths {
            root: t.path().join("root"),
            hostapd: t.path().join("hostapd"),
            kmsg: t.path().join("kmsg"),
            run: t.path().join("run"),
        };
        fs::create_dir_all(&p.hostapd).unwrap();
        fs::create_dir_all(p.sys().join("class/net/wlan6")).unwrap();
        symlink(
            "../../ieee80211/phy2",
            p.sys().join("class/net/wlan6/phy80211"),
        )
        .unwrap();
        p
    }

    /// A hostapd starting up or hung does not answer ATTACH; the BSSs of one
    /// that does are not held up by it.
    #[test]
    fn a_silent_hostapd_does_not_hold_up_the_others() {
        let t = TestDir::new();
        let paths = paths(&t);
        let _silent: Vec<_> = ["wlan24", "wlan24-1"]
            .map(|n| UnixDatagram::bind(paths.hostapd.join(n)).unwrap())
            .into();
        let mut h = FakeHostapd::bind(&paths.hostapd.join("wlan5"));
        let (tx, rx) = sync_channel(16);
        Events::spawn_with(tx, paths.clone()).unwrap();
        h.wait_attach();
        for _ in 0..6 {
            let sent = Instant::now();
            h.event("<3>AP-STA-CONNECTED 02:00:00:00:00:08");
            assert_eq!(
                rx.recv_timeout(WAIT).unwrap().kind,
                EventKind::Assoc { mac: STA, bss: 2 }
            );
            assert!(
                sent.elapsed() < Duration::from_millis(500),
                "{:?}",
                sent.elapsed()
            );
            thread::sleep(Duration::from_millis(400));
        }
    }

    #[test]
    fn a_radio_reported_down_twice_is_one_event() {
        let t = TestDir::new();
        let paths = paths(&t);
        let mut h = FakeHostapd::bind(&paths.hostapd.join("wlan6"));
        let (tx, rx) = sync_channel(16);
        Events::spawn_with(tx, paths.clone()).unwrap();
        h.wait_attach();
        h.event("<3>AP-DISABLED");
        h.event("<3>AP-DISABLED");
        h.event("<3>AP-STA-DISCONNECTED 02:00:00:00:00:08");
        let got: Vec<_> = (0..2)
            .map(|_| rx.recv_timeout(WAIT).unwrap().kind)
            .collect();
        assert_eq!(
            got,
            [
                EventKind::RadioDown { phy: "phy2".into() },
                EventKind::Disassoc { mac: STA, bss: 0 }
            ]
        );
        // A hostapd that restarted may have come up before it was attached
        // to: what it says next is news.
        let sock = paths.hostapd.join("wlan6");
        drop(h);
        fs::remove_file(&sock).unwrap();
        let mut h = FakeHostapd::bind(&sock);
        h.wait_attach();
        h.event("<3>AP-DISABLED");
        assert_eq!(
            rx.recv_timeout(WAIT).unwrap().kind,
            EventKind::RadioDown { phy: "phy2".into() }
        );
    }

    #[test]
    fn an_unanswered_attach_is_tried_less_and_less_often() {
        let t = TestDir::new();
        let paths = paths(&t);
        let silent = UnixDatagram::bind(paths.hostapd.join("wlan5")).unwrap();
        silent.set_nonblocking(true).unwrap();
        let (tx, _rx) = sync_channel(16);
        Events::spawn_with(tx, paths).unwrap();
        thread::sleep(Duration::from_secs(6));
        let mut buf = [0; 16];
        let mut attaches = 0;
        while let Ok(n) = silent.recv(&mut buf) {
            attaches += usize::from(&buf[..n] == b"ATTACH");
        }
        // Sent at 0, about 2 and about 5 s; once a second without a backoff.
        assert!((2..=3).contains(&attaches), "{attaches} in 6 s");
    }

    /// hostapd sends events to the client's path: with it removed they are
    /// lost, so the thread attaches again from a new one.
    #[test]
    fn a_removed_client_path_attaches_again() {
        let t = TestDir::new();
        let paths = paths(&t);
        let mut h = FakeHostapd::bind(&paths.hostapd.join("wlan5"));
        let (tx, rx) = sync_channel(16);
        Events::spawn_with(tx, paths.clone()).unwrap();
        h.wait_attach();
        let first = h.client.clone().unwrap();
        fs::remove_file(&first).unwrap();
        h.wait_attach();
        assert_ne!(h.client.as_ref(), Some(&first));
        h.event("<3>AP-STA-CONNECTED 02:00:00:00:00:08");
        assert_eq!(
            rx.recv_timeout(WAIT).unwrap().kind,
            EventKind::Assoc { mac: STA, bss: 0 }
        );
    }

    #[test]
    fn hostapd_restart_reattaches() {
        let t = TestDir::new();
        let paths = paths(&t);
        let (sock5, sock6) = (paths.hostapd.join("wlan5"), paths.hostapd.join("wlan6"));
        let mut first = FakeHostapd::bind(&sock5);
        let mut other = FakeHostapd::bind(&sock6);
        let (tx, rx) = sync_channel(16);
        Events::spawn_with(tx, paths.clone()).unwrap();

        first.wait_attach();
        other.wait_attach();
        first.event("<3>AP-STA-CONNECTED 02:00:00:00:00:08");
        assert_eq!(
            rx.recv_timeout(WAIT).unwrap().kind,
            EventKind::Assoc { mac: STA, bss: 0 }
        );
        other.event("<3>AP-DISABLED");
        assert_eq!(
            rx.recv_timeout(WAIT).unwrap().kind,
            EventKind::RadioDown { phy: "phy2".into() }
        );

        // hostapd restarts: the socket disappears and a new one takes its place.
        drop(first);
        fs::remove_file(&sock5).unwrap();
        let mut second = FakeHostapd::bind(&sock5);
        second.wait_attach();
        second.event("<3>AP-STA-DISCONNECTED 02:00:00:00:00:08");
        assert_eq!(
            rx.recv_timeout(WAIT).unwrap().kind,
            EventKind::Disassoc { mac: STA, bss: 0 }
        );

        // A BSS that appears later is attached too, and sorts into the indices.
        let mut early = FakeHostapd::bind(&paths.hostapd.join("wlan24"));
        early.wait_attach();
        early.event("<3>CTRL-EVENT-EAP-FAILURE 02:00:00:00:00:08");
        assert_eq!(
            rx.recv_timeout(WAIT).unwrap().kind,
            EventKind::EapFail { mac: STA, bss: 0 }
        );
        second.event("<3>CTRL-EVENT-EAP-SUCCESS 02:00:00:00:00:08");
        assert_eq!(
            rx.recv_timeout(WAIT).unwrap().kind,
            EventKind::EapOk { mac: STA, bss: 1 }
        );
    }

    #[test]
    fn a_firmware_crash_becomes_an_event() {
        let t = TestDir::new();
        let paths = paths(&t);
        let phy = paths.sys().join("class/ieee80211/phy1");
        fs::create_dir_all(&phy).unwrap();
        symlink("../../../0000:01:00.0", phy.join("device")).unwrap();
        fs::write(
            &paths.kmsg,
            "6,1,1,-;old line\n4,2,2,-;ath11k_pci 0000:01:00.0: firmware crashed: x\n",
        )
        .unwrap();
        let log = paths.kmsg.clone();
        let mut h = FakeHostapd::bind(&paths.hostapd.join("wlan6"));
        let (tx, rx) = sync_channel(16);
        Events::spawn_with(tx, paths).unwrap();
        // The thread opens the log before it attaches to anything.
        h.wait_attach();
        let mut f = fs::OpenOptions::new().append(true).open(log).unwrap();
        io::Write::write_all(
            &mut f,
            b"4,3,3,-;ath11k_pci 0000:01:00.0: firmware crashed: y\n",
        )
        .unwrap();
        assert_eq!(
            rx.recv_timeout(WAIT).unwrap().kind,
            EventKind::FwCrash { phy: "phy1".into() }
        );
        assert!(
            rx.recv_timeout(Duration::from_millis(1500)).is_err(),
            "the backlog is not replayed"
        );
    }
}
