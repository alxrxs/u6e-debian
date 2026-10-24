//! The AP's resident agent: the neighbor report exchange between APs, the
//! management network check and the state line for the syslog collector. One
//! process; it starts a process only for u6e-arm/u6e-fallback.service.
//!
//!   u6e-agent --listen <address> --port <port> --gateway <address> [--arm]
//!             [--peer <address>]...
//!             [--controller <host:port> --key <path> --controller-key <hex>]
//!   u6e-agent --print-snapshot
//!
//! With the three controller options it also streams telemetry to the
//! controller (see `link`).

mod collect;
mod events;
mod kmsg;
mod link;
mod neighbors;
mod netcheck;
mod nl80211;
mod stats;
#[cfg(test)]
mod testdir;

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use std::{env, process, thread};

use u6e_proto::tls::Identity;

/// The state line: first 2 minutes after start, then every 5 (in rounds).
const STATS_FIRST: u64 = 120 / neighbors::ROUND_SECS;
const STATS_EVERY: u64 = 300 / neighbors::ROUND_SECS;

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
    let cfg = link::Config {
        controller: l.controller,
        identity,
        controller_key: l.controller_key,
        hello: link::local_hello(),
    };
    let collector = Arc::clone(collector);
    thread::spawn(move || {
        link::run(
            cfg,
            move |seq| {
                let mut c = collector.lock().unwrap_or_else(PoisonError::into_inner);
                c.snapshot(seq)
            },
            rx,
        )
    });
}

fn main() {
    if env::args().nth(1).as_deref() == Some("--print-snapshot") {
        let mut c = collect::Collector::new();
        println!("{:#?}", c.snapshot(0));
        if !c.has_nl80211() {
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
    let collector = Arc::new(Mutex::new(collect::Collector::new()));
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

    for n in 0.. {
        let stations = neighbors::round(&mut h, &own, &peers);
        if n >= STATS_FIRST && (n - STATS_FIRST).is_multiple_of(STATS_EVERY) {
            let mut c = collector.lock().unwrap_or_else(PoisonError::into_inner);
            let snap = c.snapshot(0);
            println!("{}", stats::line(&snap, c.fw_crashes(), &stations));
        }
        thread::sleep(Duration::from_secs(neighbors::ROUND_SECS));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
