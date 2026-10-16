//! 802.11k across APs. Every 10 s: read this AP's own neighbor report entries
//! (of the radios that are up) from hostapd, serve them to the other APs, read
//! theirs, and make each BSS's neighbor list carry the other APs' BSSs of its
//! SSID, changing hostapd only where something differs. An AP that stops
//! answering drops out within a round. One process; it forks nothing.
//!
//!   u6e-neighbors <listen address> <port> [<peer address>...]

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixDatagram;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{env, fs, process, thread};

const HOSTAPD: &str = "/run/hostapd";
const CTRL: &str = "/run/u6e-neighbors/ctrl";
const ROUND: Duration = Duration::from_secs(10);
const TIMEOUT: Duration = Duration::from_secs(3);

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
    s.len() == 17 && s.bytes().all(|c| c.is_ascii_hexdigit() || c == b':')
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

struct Hostapd {
    sock: UnixDatagram,
    buf: Vec<u8>,
}

impl Hostapd {
    /// One control interface request; "" when hostapd does not answer. A
    /// reply left over from a request that timed out is discarded first.
    fn request(&mut self, iface: &str, cmd: &str) -> String {
        let _ = self.sock.set_nonblocking(true);
        while self.sock.recv(&mut self.buf).is_ok() {}
        let _ = self.sock.set_nonblocking(false);
        if self
            .sock
            .send_to(cmd.as_bytes(), format!("{HOSTAPD}/{iface}"))
            .is_err()
        {
            return String::new();
        }
        match self.sock.recv(&mut self.buf) {
            Ok(n) => String::from_utf8_lossy(&self.buf[..n]).into_owned(),
            Err(_) => String::new(),
        }
    }
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

fn round(h: &mut Hostapd, own: &Mutex<String>, peers: &[SocketAddr]) {
    let ifaces: Vec<String> = fs::read_dir(HOSTAPD)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_socket()))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    let (mut lists, mut mine, mut up) = (Vec::new(), HashSet::new(), String::new());
    for iface in ifaces {
        let list = h.request(&iface, "SHOW_NEIGHBOR");
        let enabled = h
            .request(&iface, "STATUS")
            .lines()
            .any(|l| l == "state=ENABLED");
        let mut ssid = None;
        for e in list.lines().filter_map(own_entry) {
            if enabled {
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

/// Serve this AP's entries to whoever connects. The management address may
/// come up after us, so binding is retried every round.
fn serve(addr: SocketAddr, own: Arc<Mutex<String>>) {
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

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let parse = |a: &String| a.parse::<IpAddr>().ok();
    let (Some(listen), Some(port)) = (
        args.first().and_then(parse),
        args.get(1).and_then(|p| p.parse::<u16>().ok()),
    ) else {
        eprintln!("usage: u6e-neighbors <listen address> <port> [<peer address>...]");
        process::exit(2);
    };
    let Some(peers) = args[2..]
        .iter()
        .map(|a| parse(a).map(|ip| SocketAddr::new(ip, port)))
        .collect::<Option<Vec<_>>>()
    else {
        eprintln!("u6e-neighbors: a peer is not an IP address");
        process::exit(2);
    };

    let _ = fs::remove_file(CTRL);
    let sock = UnixDatagram::bind(CTRL).unwrap_or_else(|e| {
        eprintln!("u6e-neighbors: {CTRL}: {e}");
        process::exit(1);
    });
    let _ = sock.set_read_timeout(Some(Duration::from_secs(1)));
    let mut h = Hostapd {
        sock,
        buf: vec![0; 65536],
    };

    let own = Arc::new(Mutex::new(String::new()));
    let served = Arc::clone(&own);
    thread::spawn(move || serve(SocketAddr::new(listen, port), served));
    loop {
        round(&mut h, &own, &peers);
        thread::sleep(ROUND);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn a_silent_peer_drops_out() {
        let mine = HashSet::from(["aa:aa:aa:aa:aa:01".to_string()]);
        let list = format!("{OWN}\nbb:bb:bb:bb:bb:01 ssid=4775657374 nr=bb01");
        assert_eq!(
            changes(&list, "4775657374", &mine, &[]),
            ["REMOVE_NEIGHBOR bb:bb:bb:bb:bb:01"]
        );
    }
}
