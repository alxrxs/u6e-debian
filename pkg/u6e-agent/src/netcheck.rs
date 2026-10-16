//! The management network: from 3 minutes after boot, once a minute, the
//! gateway must resolve over ARP (not ICMP: a gateway may well drop pings).
//! The first time it does, a persistent image re-arms its boot
//! (u6e-arm.service); when it does not, u6e-fallback.service disarms it, keeps
//! the evidence in pstore and reboots into stock.

use std::net::{Ipv4Addr, UdpSocket};
use std::process::Command;
use std::time::Duration;
use std::{fs, thread};

const FIRST_CHECK_SECS: f64 = 180.0;
const INTERVAL: Duration = Duration::from_secs(60);

/// Whether /proc/net/arp holds a resolved entry (ATF_COM: REACHABLE, STALE,
/// DELAY or PROBE) for the gateway.
fn resolved(arp: &str, gw: Ipv4Addr) -> bool {
    let gw = gw.to_string();
    arp.lines().skip(1).any(|l| {
        let mut f = l.split_whitespace();
        f.next() == Some(gw.as_str())
            && f.nth(1)
                .and_then(|x| u32::from_str_radix(x.trim_start_matches("0x"), 16).ok())
                .is_some_and(|flags| flags & 0x2 != 0)
    })
}

/// A datagram to the gateway makes the kernel confirm its entry, or fail it.
fn reachable(gw: Ipv4Addr) -> bool {
    if let Ok(s) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
        let _ = s.send_to(&[0], (gw, 9));
    }
    thread::sleep(Duration::from_secs(2));
    fs::read_to_string("/proc/net/arp").is_ok_and(|a| resolved(&a, gw))
}

fn start(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["start", unit])
        .status()
        .is_ok_and(|s| s.success())
}

fn uptime() -> f64 {
    fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|u| u.split(' ').next()?.parse().ok())
        .unwrap_or(0.0)
}

pub fn run(gw: Ipv4Addr, arm: bool) {
    let wait = FIRST_CHECK_SECS - uptime();
    if wait > 0.0 {
        thread::sleep(Duration::from_secs_f64(wait));
    }
    let mut armed = !arm;
    loop {
        if reachable(gw) {
            if !armed {
                armed = start("u6e-arm.service");
            }
        } else {
            eprintln!("no gateway at {gw}: back to stock");
            start("u6e-fallback.service");
        }
        thread::sleep(INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARP: &str =
        "IP address       HW type     Flags       HW address            Mask     Device
10.57.1.1        0x1         0x2         a2:ad:51:1e:93:ac     *        vlan11
10.57.1.16       0x1         0x0         00:00:00:00:00:00     *        vlan11
";

    #[test]
    fn a_resolved_gateway_is_reachable() {
        assert!(resolved(ARP, Ipv4Addr::new(10, 57, 1, 1)));
    }

    #[test]
    fn a_failed_or_missing_entry_is_not() {
        assert!(!resolved(ARP, Ipv4Addr::new(10, 57, 1, 16)));
        assert!(!resolved(ARP, Ipv4Addr::new(10, 57, 1, 2)));
        assert!(!resolved(ARP, Ipv4Addr::new(10, 57, 1, 11)));
    }
}
