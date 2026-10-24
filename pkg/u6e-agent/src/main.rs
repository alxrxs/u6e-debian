//! The AP's resident agent: the neighbor report exchange between APs, the
//! management network check and the state line for the syslog collector. One
//! process; it starts a process only for u6e-arm/u6e-fallback.service.
//!
//!   u6e-agent --listen <address> --port <port> --gateway <address> [--arm]
//!             [--peer <address>]...
//!   u6e-agent --print-snapshot

mod collect;
#[allow(dead_code, reason = "the link starts the events thread")]
mod events;
#[allow(dead_code, reason = "used by the events thread")]
mod kmsg;
mod neighbors;
mod netcheck;
mod nl80211;
mod stats;
#[cfg(test)]
mod testdir;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{env, process, thread};

/// The state line: first 2 minutes after start, then every 5 (in rounds).
const STATS_FIRST: u64 = 120 / neighbors::ROUND_SECS;
const STATS_EVERY: u64 = 300 / neighbors::ROUND_SECS;

struct Args {
    listen: IpAddr,
    port: u16,
    gateway: Ipv4Addr,
    arm: bool,
    peers: Vec<IpAddr>,
}

fn args() -> Option<Args> {
    let (mut listen, mut port, mut gateway, mut arm, mut peers) =
        (None, None, None, false, Vec::new());
    let mut a = env::args().skip(1);
    while let Some(k) = a.next() {
        match k.as_str() {
            "--listen" => listen = Some(a.next()?.parse().ok()?),
            "--port" => port = Some(a.next()?.parse().ok()?),
            "--gateway" => gateway = Some(a.next()?.parse().ok()?),
            "--arm" => arm = true,
            "--peer" => peers.push(a.next()?.parse().ok()?),
            _ => return None,
        }
    }
    Some(Args {
        listen: listen?,
        port: port?,
        gateway: gateway?,
        arm,
        peers,
    })
}

fn main() {
    if env::args().nth(1).as_deref() == Some("--print-snapshot") {
        let mut c = collect::Collector::new().unwrap_or_else(|e| {
            eprintln!("u6e-agent: collectors: {e}");
            process::exit(1);
        });
        println!("{:#?}", c.snapshot(0));
        return;
    }
    let Some(a) = args() else {
        eprintln!(
            "usage: u6e-agent --listen <address> --port <port> --gateway <address> [--arm] [--peer <address>]..."
        );
        process::exit(2);
    };
    let mut h = neighbors::Hostapd::open().unwrap_or_else(|e| {
        eprintln!("u6e-agent: hostapd control socket: {e}");
        process::exit(1);
    });
    let mut collector = collect::Collector::new().unwrap_or_else(|e| {
        eprintln!("u6e-agent: collectors: {e}");
        process::exit(1);
    });
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

    for n in 0.. {
        let stations = neighbors::round(&mut h, &own, &peers);
        if n >= STATS_FIRST && (n - STATS_FIRST).is_multiple_of(STATS_EVERY) {
            let snap = collector.snapshot(0);
            println!("{}", stats::line(&snap, collector.fw_crashes(), &stations));
        }
        thread::sleep(Duration::from_secs(neighbors::ROUND_SECS));
    }
}
