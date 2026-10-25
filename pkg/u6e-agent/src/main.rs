//! The AP's resident agent: the neighbor report exchange between APs, the
//! management network check and the state line for the syslog collector. One
//! process, which starts no other; it runs as its own user, with no
//! capabilities (see prep-rootfs.sh for the unit).
//!
//!   u6e-agent --listen <address> --port <port> --gateway <address> [--arm]
//!             [--peer <address>]...
//!             [--controller <host:port> --key <path> --controller-key <hex>]
//!   u6e-agent --print-snapshot
//!
//! With the three controller options it also streams telemetry to the
//! controller (see `link`).

mod clientsock;
mod collect;
mod events;
mod kmsg;
mod link;
mod neighbors;
mod netcheck;
mod nl80211;
mod passed;
mod rates;
mod stats;
#[cfg(test)]
mod testdir;

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use std::{env, process, thread};

use u6e_proto::tls::Identity;

/// The state line: first 2 minutes after start, then every 5.
const STATS_FIRST: Duration = Duration::from_secs(120);
const STATS_EVERY: Duration = Duration::from_secs(300);

/// Where and as whom the telemetry link connects.
struct LinkArgs {
    controller: String,
    key: String,
    controller_key: [u8; 32],
}

struct Args {
    listen: IpAddr,
    port: u16,
    gateway: Ipv4Addr,
    arm: bool,
    peers: Vec<IpAddr>,
    link: Option<LinkArgs>,
}

/// The 32 bytes of a 64-digit hex string.
fn parse_key(hex: &str) -> Option<[u8; 32]> {
    // from_str_radix alone would also take a sign.
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut key = [0; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(key)
}

fn args() -> Option<Args> {
    let (mut listen, mut port, mut gateway, mut arm, mut peers) =
        (None, None, None, false, Vec::new());
    let (mut controller, mut key, mut controller_key) = (None, None, None);
    let mut a = env::args().skip(1);
    while let Some(k) = a.next() {
        match k.as_str() {
            "--listen" => listen = Some(a.next()?.parse().ok()?),
            "--port" => port = Some(a.next()?.parse().ok()?),
            "--gateway" => gateway = Some(a.next()?.parse().ok()?),
            "--arm" => arm = true,
            "--peer" => peers.push(a.next()?.parse().ok()?),
            "--controller" => controller = Some(a.next()?),
            "--key" => key = Some(a.next()?),
            "--controller-key" => controller_key = Some(parse_key(&a.next()?)?),
            _ => return None,
        }
    }
    let link = match (controller, key, controller_key) {
        (Some(controller), Some(key), Some(controller_key)) => Some(LinkArgs {
            controller,
            key,
            controller_key,
        }),
        (None, None, None) => None,
        _ => return None,
    };
    Some(Args {
        listen: listen?,
        port: port?,
        gateway: gateway?,
        arm,
        peers,
        link,
    })
}

/// Starts the telemetry link and the events thread that feeds it. The
/// agent's other duties do not depend on either, so a failure here is
/// logged and they carry on.
fn start_link(l: LinkArgs, collector: &Arc<Mutex<collect::Collector>>) {
    let identity = fs::read_to_string(&l.key)
        .map_err(|e| e.to_string())
        .and_then(|pem| Identity::from_pem(&pem).map_err(|e| e.to_string()));
    let identity = match identity {
        Ok(i) => i,
        Err(e) => {
            eprintln!("u6e-agent: {}: {e}; no link to the controller", l.key);
            return;
        }
    };
    let (tx, rx) = sync_channel(256);
    if let Err(e) = events::Events::spawn(tx) {
        eprintln!("u6e-agent: events: {e}; the link carries snapshots only");
    }
    let cfg = link::Config::new(
        l.controller,
        identity,
        l.controller_key,
        link::local_hello(),
    );
    let collector = Arc::clone(collector);
    spawn_or_log("link", move || {
        link::run(
            cfg,
            move |seq| {
                let mut c = lock(&collector);
                c.snapshot(seq)
            },
            rx,
        )
    });
}

/// Starts a thread for a duty the 802.11k exchange and the network check do
/// not depend on; if it cannot start (no threads left), that is logged and
/// they carry on.
fn spawn_or_log(name: &str, f: impl FnOnce() + Send + 'static) {
    if let Err(e) = thread::Builder::new().name(name.into()).spawn(f) {
        eprintln!("u6e-agent: {name}: {e}; carrying on without it");
    }
}

fn main() {
    let nss_load = passed::take(collect::NSS_LOAD_NAME);
    if env::args().nth(1).as_deref() == Some("--print-snapshot") {
        let mut c = collect::Collector::new(nss_load);
        println!("{:#?}", c.snapshot(0));
        let ok = c.has_nl80211();
        // Its client sockets go with it; exit would skip that.
        drop(c);
        if !ok {
            process::exit(1);
        }
        return;
    }
    let Some(a) = args() else {
        eprintln!(
            "usage: u6e-agent --listen <address> --port <port> --gateway <address> [--arm] [--peer <address>]... [--controller <host:port> --key <path> --controller-key <hex>]"
        );
        process::exit(2);
    };
    let mut h = neighbors::Hostapd::open().unwrap_or_else(|e| {
        eprintln!("u6e-agent: hostapd control socket: {e}");
        process::exit(1);
    });
    let collector = Arc::new(Mutex::new(collect::Collector::new(nss_load)));
    let peers: Vec<SocketAddr> = a
        .peers
        .iter()
        .map(|&ip| SocketAddr::new(ip, a.port))
        .collect();

    let own = Arc::new(Mutex::new(String::new()));
    let served = Arc::clone(&own);
    let listen = SocketAddr::new(a.listen, a.port);
    thread::spawn(move || neighbors::serve(listen, served));
    let (gateway, arm) = (a.gateway, a.arm);
    thread::spawn(move || netcheck::run(gateway, arm));
    if let Some(l) = a.link {
        start_link(l, &collector);
    }

    let stations = Arc::new(Mutex::new(Vec::new()));
    let counted = Arc::clone(&stations);
    spawn_or_log("state line", move || {
        state_lines(&collector, &counted, STATS_FIRST, STATS_EVERY, |l| {
            println!("{l}");
        })
    });
    loop {
        let counts = neighbors::round(&mut h, &own, &peers);
        *lock(&stations) = counts;
        thread::sleep(Duration::from_secs(neighbors::ROUND_SECS));
    }
}

/// Prints the state line, on a thread of its own: a snapshot can wait on the
/// collector (the link's, or a slow kernel), and the 802.11k rounds must not.
/// `stations` holds the latest round's stations per BSS.
fn state_lines(
    collector: &Mutex<collect::Collector>,
    stations: &Mutex<Vec<(String, u32)>>,
    first: Duration,
    every: Duration,
    mut emit: impl FnMut(String),
) -> ! {
    thread::sleep(first);
    loop {
        let line = {
            let mut c = lock(collector);
            let snap = c.snapshot(0);
            stats::line(&snap, c.fw_crashes(), &lock(stations))
        };
        emit(line);
        thread::sleep(every);
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_state_line_counts_the_latest_round() {
        let t = testdir::TestDir::new();
        let paths = collect::Paths {
            root: t.path().join("root"),
            hostapd: t.path().join("hostapd"),
            kmsg: t.path().join("kmsg"),
            run: t.path().join("run"),
        };
        let collector = Arc::new(Mutex::new(collect::Collector::with_paths(paths)));
        let stations = Arc::new(Mutex::new(vec![("wlan5".to_owned(), 3)]));
        let (tx, rx) = std::sync::mpsc::channel();
        let (c, s) = (Arc::clone(&collector), Arc::clone(&stations));
        let every = Duration::from_millis(20);
        thread::spawn(move || {
            state_lines(&c, &s, Duration::ZERO, every, |l| {
                // The thread outlives the test.
                let _ = tx.send(l);
            })
        });
        let wait = Duration::from_secs(5);
        assert!(rx.recv_timeout(wait).unwrap().contains("clients: wlan5=3 "));
        *stations.lock().unwrap() = vec![("wlan5".to_owned(), 4)];
        while !rx.recv_timeout(wait).unwrap().contains("clients: wlan5=4 ") {}
    }

    #[test]
    fn controller_key_is_64_hex_digits() {
        let hex = "00ff".repeat(16);
        let key = parse_key(&hex).unwrap();
        assert_eq!((key[0], key[1], key[31]), (0x00, 0xff, 0xff));
        assert_eq!(parse_key(&hex[2..]), None);
        assert_eq!(parse_key(&format!("{}zz", &hex[2..])), None);
        assert_eq!(parse_key(&format!("+f{}", &hex[2..])), None);
    }
}
