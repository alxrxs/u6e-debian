//! 802.11k across APs. Every round (10 s): read this AP's own neighbor report
//! entries (of the radios that are up) from hostapd, serve them to the other
//! APs, read theirs, and make each BSS's neighbor list carry the other APs'
//! BSSs of its SSID, changing hostapd only where something differs. An AP that
//! stops answering drops out within a round.

pub const ROUND_SECS: u64 = 10;

use std::collections::{HashMap, HashSet};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{fs, thread};

use u6e_proto::mac;

use crate::clientsock::{self, ClientSocket};

pub const HOSTAPD: &str = "/run/hostapd";
const ROUND: Duration = Duration::from_secs(ROUND_SECS);
const TIMEOUT: Duration = Duration::from_secs(3);
/// How long hostapd has to answer a control request.
const ANSWER_WAIT: Duration = Duration::from_secs(1);

/// A neighbor report entry: BSSID, and SSID and element in hex.
struct Entry {
    bssid: String,
    ssid: String,
    nr: String,
}

fn hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_hexdigit())
}

fn bssid(s: &str) -> bool {
    mac::parse(s).is_some()
}

/// The BSS's own entry in SHOW_NEIGHBOR: "<BSSID> ssid=<hex> nr=<hex> ... stat".
fn own_entry(line: &str) -> Option<Entry> {
    let mut f = line.split(' ');
    let (b, s, n) = (
        f.next()?,
        f.next()?.strip_prefix("ssid=")?,
        f.next()?.strip_prefix("nr=")?,
    );
    (bssid(b) && hex(s) && hex(n) && f.next_back()? == "stat").then(|| Entry {
        bssid: b.into(),
        ssid: s.into(),
        nr: n.into(),
    })
}

/// A line a peer served: "<BSSID> <SSID hex> <element hex>"; nothing else
/// reaches hostapd.
fn peer_entry(line: &str) -> Option<Entry> {
    let mut f = line.split(' ');
    let (b, s, n) = (f.next()?, f.next()?, f.next()?);
    (f.next().is_none() && bssid(b) && hex(s) && hex(n)).then(|| Entry {
        bssid: b.into(),
        ssid: s.into(),
        nr: n.into(),
    })
}

/// A client of hostapd's control interfaces, bound at its own socket path.
pub struct Hostapd {
    sock: ClientSocket,
    dir: PathBuf,
    buf: Vec<u8>,
}

impl Hostapd {
    pub fn open() -> io::Result<Self> {
        Self::bind(&clientsock::run_dir(), "ctrl", Path::new(HOSTAPD))
    }

    /// A client named after `what` in `run`, talking to the sockets in `dir`.
    pub fn bind(run: &Path, what: &str, dir: &Path) -> io::Result<Self> {
        Ok(Hostapd {
            sock: Self::ready(ClientSocket::bind(run, what)?)?,
            dir: dir.to_owned(),
            buf: vec![0; 65536],
        })
    }

    /// Never blocking: a hung hostapd stops reading, and once its queue is
    /// full a blocking send would wait for as long as it hangs.
    fn ready(sock: ClientSocket) -> io::Result<ClientSocket> {
        sock.set_nonblocking(true)?;
        Ok(sock)
    }

    /// One control interface request. `TimedOut` is a hostapd that does not
    /// answer (busy or hung); any other error, one that is not there. A
    /// reply left over from a request that timed out is discarded first.
    pub fn try_request(&mut self, iface: &str, cmd: &str) -> io::Result<String> {
        if !self.sock.reachable() {
            self.sock = self.sock.rebind().and_then(Self::ready)?;
        }
        while self.sock.recv(&mut self.buf).is_ok() {}
        let silent = |e: io::Error| match e.kind() {
            ErrorKind::WouldBlock => ErrorKind::TimedOut.into(),
            _ => e,
        };
        self.sock
            .send_to(cmd.as_bytes(), self.dir.join(iface))
            .map_err(silent)?;
        if !readable(&*self.sock, ANSWER_WAIT) {
            return Err(ErrorKind::TimedOut.into());
        }
        let n = self.sock.recv(&mut self.buf).map_err(silent)?;
        Ok(String::from_utf8_lossy(&self.buf[..n]).into_owned())
    }

    /// [`Self::try_request`], "" when there is no answer.
    pub fn request(&mut self, iface: &str, cmd: &str) -> String {
        self.try_request(iface, cmd).unwrap_or_default()
    }
}

/// Whether `fd` becomes readable within `wait`.
fn readable(fd: &impl AsRawFd, wait: Duration) -> bool {
    let mut p = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = i32::try_from(wait.as_millis()).unwrap_or(i32::MAX);
    // SAFETY: one valid pollfd for the call.
    unsafe { libc::poll(&mut p, 1, ms) > 0 }
}

/// Whether a radio's STATUS says it is serving.
pub fn enabled(status: &str) -> bool {
    status.lines().any(|l| l == "state=ENABLED")
}

fn fetch(peer: &SocketAddr) -> Vec<Entry> {
    let Ok(s) = TcpStream::connect_timeout(peer, TIMEOUT) else {
        return Vec::new();
    };
    let _ = s.set_read_timeout(Some(TIMEOUT));
    let mut data = String::new();
    let _ = s.take(65536).read_to_string(&mut data);
    data.lines().filter_map(peer_entry).collect()
}

/// One round; returns each BSS's number of stations.
pub fn round(h: &mut Hostapd, own: &Mutex<String>, peers: &[SocketAddr]) -> Vec<(String, u32)> {
    let ifaces: Vec<String> = fs::read_dir(HOSTAPD)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_socket()))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    let (mut lists, mut mine, mut up) = (Vec::new(), HashSet::new(), String::new());
    let mut stations = Vec::new();
    for iface in ifaces {
        let list = h.request(&iface, "SHOW_NEIGHBOR");
        let status = h.request(&iface, "STATUS");
        let serving = enabled(&status);
        stations.push((iface.clone(), num_sta(&status, &iface)));
        let mut ssid = None;
        for e in list.lines().filter_map(own_entry) {
            if serving {
                up += &format!("{} {} {}\n", e.bssid, e.ssid, e.nr);
            }
            mine.insert(e.bssid);
            ssid.get_or_insert(e.ssid);
        }
        lists.push((iface, list, ssid));
    }
    *own.lock().unwrap() = up;

    let theirs: Vec<Entry> = peers.iter().flat_map(fetch).collect();
    for (iface, list, ssid) in lists {
        if let Some(ssid) = ssid {
            for cmd in changes(&list, &ssid, &mine, &theirs) {
                h.request(&iface, &cmd);
            }
        }
    }
    stations
}

/// The hostapd commands that make a BSS's neighbor list (its SHOW_NEIGHBOR
/// output) carry exactly the other APs' BSSs of its SSID, besides this AP's
/// own; none when it already does.
fn changes(list: &str, ssid: &str, mine: &HashSet<String>, theirs: &[Entry]) -> Vec<String> {
    let want: HashMap<&str, &Entry> = theirs
        .iter()
        .filter(|e| e.ssid == ssid)
        .map(|e| (e.bssid.as_str(), e))
        .collect();
    let have: HashMap<&str, &str> = list.lines().filter_map(|l| l.split_once(' ')).collect();
    let mut cmds: Vec<String> = have
        .keys()
        .filter(|b| !mine.contains(**b) && !want.contains_key(**b))
        .map(|b| format!("REMOVE_NEIGHBOR {b}"))
        .collect();
    for (b, e) in &want {
        let line = format!("ssid={} nr={}", e.ssid, e.nr);
        if have.get(b) != Some(&line.as_str()) {
            cmds.push(format!("SET_NEIGHBOR {b} {line}"));
        }
    }
    cmds.sort();
    cmds
}

/// A BSS's station count in its radio's STATUS: "bss[i]=<name>" and
/// "num_sta[i]=<n>".
fn num_sta(status: &str, iface: &str) -> u32 {
    let field = |key: &str| status.lines().find_map(|l| l.strip_prefix(key));
    let i = status
        .lines()
        .find_map(|l| l.strip_prefix("bss[")?.strip_suffix(&format!("]={iface}")));
    i.and_then(|i| field(&format!("num_sta[{i}]=")))
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

/// Serve this AP's entries to whoever connects. The management address may
/// come up after us, so binding is retried every round.
pub fn serve(addr: SocketAddr, own: Arc<Mutex<String>>) {
    let listener = loop {
        match TcpListener::bind(addr) {
            Ok(l) => break l,
            Err(_) => thread::sleep(ROUND),
        }
    };
    for conn in listener.incoming().flatten() {
        let data = own.lock().unwrap().clone();
        let _ = conn.set_write_timeout(Some(TIMEOUT));
        let _ = (&conn).write_all(data.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    const OWN: &str = "aa:aa:aa:aa:aa:01 ssid=4775657374 nr=aa01 stat";

    fn peer(b: &str, s: &str, n: &str) -> Entry {
        peer_entry(&format!("{b} {s} {n}")).unwrap()
    }

    #[test]
    fn parses_own_and_peer_entries() {
        let e = own_entry(OWN).unwrap();
        assert_eq!(
            (e.bssid.as_str(), e.ssid.as_str(), e.nr.as_str()),
            ("aa:aa:aa:aa:aa:01", "4775657374", "aa01")
        );
        assert!(own_entry("bb:bb:bb:bb:bb:01 ssid=4775657374 nr=bb01").is_none());
        assert!(peer_entry("bb:bb:bb:bb:bb:01 4775657374 bb01").is_some());
    }

    #[test]
    fn rejects_what_could_change_a_command() {
        for l in [
            "bb:bb:bb:bb:bb:01 4775657374 bb01 extra",
            "bb:bb:bb:bb:bb:01 47756573 74 bb01",
            "bb:bb:bb:bb:bb:01 4775657374 bb01;REMOVE_NEIGHBOR",
            "bb:bb:bb:bb:bb:0 4775657374 bb01",
            "bbbb:bb:bb:bb::01 4775657374 bb01",
            "bb:bb:bb:bb:bb:01  bb01",
        ] {
            assert!(peer_entry(l).is_none(), "{l}");
        }
    }

    #[test]
    fn adds_updates_and_removes() {
        let mine = HashSet::from([
            "aa:aa:aa:aa:aa:01".to_string(),
            "aa:aa:aa:aa:aa:02".to_string(),
        ]);
        let list = format!(
            "{OWN}\naa:aa:aa:aa:aa:02 ssid=4775657374 nr=aa02\n\
             bb:bb:bb:bb:bb:01 ssid=4775657374 nr=old\ncc:cc:cc:cc:cc:01 ssid=4775657374 nr=cc01"
        );
        let theirs = [
            peer("bb:bb:bb:bb:bb:01", "4775657374", "bb01"),
            peer("bb:bb:bb:bb:bb:02", "4775657374", "bb02"),
            peer("bb:bb:bb:bb:bb:03", "49726978", "bb03"),
        ];
        assert_eq!(
            changes(&list, "4775657374", &mine, &theirs),
            [
                "REMOVE_NEIGHBOR cc:cc:cc:cc:cc:01",
                "SET_NEIGHBOR bb:bb:bb:bb:bb:01 ssid=4775657374 nr=bb01",
                "SET_NEIGHBOR bb:bb:bb:bb:bb:02 ssid=4775657374 nr=bb02",
            ]
        );
    }

    #[test]
    fn converged_needs_nothing() {
        let mine = HashSet::from(["aa:aa:aa:aa:aa:01".to_string()]);
        let list = format!("{OWN}\nbb:bb:bb:bb:bb:01 ssid=4775657374 nr=bb01");
        let theirs = [peer("bb:bb:bb:bb:bb:01", "4775657374", "bb01")];
        assert!(changes(&list, "4775657374", &mine, &theirs).is_empty());
    }

    #[test]
    fn counts_the_stations_of_its_own_bss() {
        let status = "state=ENABLED\nbss[0]=wlan5\nnum_sta[0]=8\nbss[1]=wlan5-1\nnum_sta[1]=3\nbss[2]=wlan5-2\nnum_sta[2]=1";
        assert_eq!(num_sta(status, "wlan5-1"), 3);
        assert_eq!(num_sta(status, "wlan5"), 8);
        assert_eq!(num_sta(status, "wlan6"), 0);
    }

    /// A hostapd at `<dir>/wlan5` that answers every request.
    fn answering_hostapd(dir: &Path) {
        fs::create_dir_all(dir).unwrap();
        let server = UnixDatagram::bind(dir.join("wlan5")).unwrap();
        thread::spawn(move || {
            let mut buf = [0; 64];
            while let Ok((_, from)) = server.recv_from(&mut buf) {
                if let Some(p) = from.as_pathname() {
                    let _ = server.send_to(b"state=ENABLED", p);
                }
            }
        });
    }

    /// `u6e-agent --print-snapshot` beside the resident agent.
    #[test]
    fn a_second_client_does_not_deafen_the_first() {
        let t = crate::testdir::TestDir::new();
        let dir = t.path().join("hostapd");
        answering_hostapd(&dir);
        let mut resident = Hostapd::bind(t.path(), "collect", &dir).unwrap();
        assert_eq!(resident.request("wlan5", "STATUS"), "state=ENABLED");
        drop(Hostapd::bind(t.path(), "collect", &dir).unwrap());
        assert_eq!(resident.request("wlan5", "STATUS"), "state=ENABLED");
    }

    /// A hung hostapd stops reading its socket; once its queue is full, a
    /// blocking send would wait as long as it hangs.
    #[test]
    fn a_hostapd_that_reads_nothing_does_not_block_a_request() {
        let t = crate::testdir::TestDir::new();
        let dir = t.path().join("hostapd");
        fs::create_dir_all(&dir).unwrap();
        let hung = UnixDatagram::bind(dir.join("wlan5")).unwrap();
        // Senders until one cannot send at all: then the queue is full, not
        // just a sender's buffer.
        let mut fillers = Vec::new();
        loop {
            let f = UnixDatagram::unbound().unwrap();
            f.set_nonblocking(true).unwrap();
            if f.send_to(b"x", dir.join("wlan5")).is_err() {
                break;
            }
            while f.send_to(b"x", dir.join("wlan5")).is_ok() {}
            fillers.push(f);
        }
        let mut h = Hostapd::bind(t.path(), "ctrl", &dir).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || tx.send(h.try_request("wlan5", "STATUS").is_err()));
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)), Ok(true));
        drop(hung);
    }

    #[test]
    fn a_silent_answer_is_told_from_a_refusal() {
        let t = crate::testdir::TestDir::new();
        let dir = t.path().join("hostapd");
        fs::create_dir_all(&dir).unwrap();
        let _silent = UnixDatagram::bind(dir.join("wlan5")).unwrap();
        let mut h = Hostapd::bind(t.path(), "ctrl", &dir).unwrap();
        let e = h.try_request("wlan5", "STATUS").unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::TimedOut);
        let e = h.try_request("wlan6", "STATUS").unwrap_err();
        assert_ne!(e.kind(), std::io::ErrorKind::TimedOut);
    }

    /// hostapd answers to the client's path; with the path gone (the run
    /// directory emptied by hand, say) the client binds a new one.
    #[test]
    fn a_client_whose_path_was_removed_binds_again() {
        let t = crate::testdir::TestDir::new();
        let (run, dir) = (t.path().join("run"), t.path().join("hostapd"));
        answering_hostapd(&dir);
        let mut h = Hostapd::bind(&run, "ctrl", &dir).unwrap();
        fs::remove_dir_all(&run).unwrap();
        assert_eq!(h.request("wlan5", "STATUS"), "state=ENABLED");
    }

    #[test]
    fn a_silent_peer_drops_out() {
        let mine = HashSet::from(["aa:aa:aa:aa:aa:01".to_string()]);
        let list = format!("{OWN}\nbb:bb:bb:bb:bb:01 ssid=4775657374 nr=bb01");
        assert_eq!(
            changes(&list, "4775657374", &mine, &[]),
            ["REMOVE_NEIGHBOR bb:bb:bb:bb:bb:01"]
        );
    }
}
