//! The connections the simulated clients keep open, as the agent's ECM reader
//! reports them: a set that stays put for each client, so that a connection
//! can be followed from one report to the next, its bytes shared out from the
//! client's own traffic. Nearly all of them are offloaded to the NSS
//! hardware; a few DNS lookups and one other connection take the CPU's path,
//! as short-lived connections do. Addresses are documentation ones, over
//! IPv4 and IPv6.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use u6e_proto::msg::{ClientFlows, Flow};

/// The largest connections a summary carries per client.
pub const TOP: usize = 8;

const TCP: u8 = 6;
const UDP: u8 = 17;
const ESP: u8 = 50;

/// What one client's connections are made from.
pub struct Traffic {
    pub mac: [u8; 6],
    pub last: u8,
    /// Connections it usually keeps open.
    pub conns: u32,
    /// Bytes it received and sent since it joined.
    pub down: f64,
    pub up: f64,
    pub connected_s: f64,
    /// Seconds since the replay started.
    pub t: f64,
}

/// The client's connections: totals over all of them, and the `top` largest
/// (`usize::MAX` for every one, as the whole table lists them).
pub fn client(tr: &Traffic, top: usize) -> ClientFlows {
    let wobble = 1.0 + 0.15 * (tr.t / 37.0 + f64::from(tr.last)).sin();
    let n = (f64::from(tr.conns) * wobble).round().max(1.0) as usize;
    // Bytes fall off with rank, so a handful of connections carry most.
    let weight = |i: usize| 1.0 / ((i + 1) as f64).powf(1.3);
    let total: f64 = (0..n).map(weight).sum();
    let all: Vec<Flow> = (0..n).map(|i| flow(tr, i, weight(i) / total)).collect();
    ClientFlows {
        mac: tr.mac,
        conns: n as u32,
        offloaded: all.iter().filter(|f| f.offloaded).count() as u32,
        tx_bytes: all.iter().map(|f| f.tx_bytes).sum(),
        rx_bytes: all.iter().map(|f| f.rx_bytes).sum(),
        tx_packets: all.iter().map(|f| f.tx_packets).sum(),
        rx_packets: all.iter().map(|f| f.rx_packets).sum(),
        top: all.into_iter().take(top).collect(),
    }
}

/// `2001:db8:<net>:<sub>::<host>`.
fn doc6(net: u16, sub: u16, host: u16) -> IpAddr {
    Ipv6Addr::new(0x2001, 0xdb8, net, sub, 0, 0, 0, host).into()
}

/// Connection `i` of a client, carrying `share` of its bytes.
fn flow(tr: &Traffic, i: usize, share: f64) -> Flow {
    let last = usize::from(tr.last);
    let v6 = (i + last).is_multiple_of(3);
    let own = if v6 {
        doc6(0x10, 0, tr.last.into())
    } else {
        Ipv4Addr::new(192, 0, 2, 10 + tr.last).into()
    };
    let host = ((i * 37 + last * 11) % 253 + 1) as u8;
    let remote = |port: u16| -> IpAddr {
        match (v6, port) {
            (false, 53) => Ipv4Addr::new(198, 51, 100, 53).into(),
            (true, 53) => doc6(0x53, 0, 0x53),
            (false, _) if i.is_multiple_of(2) => Ipv4Addr::new(198, 51, 100, host).into(),
            (false, _) => Ipv4Addr::new(203, 0, 113, host).into(),
            (true, _) => doc6(0xf00, (i % 4) as u16, host.into()),
        }
    };
    let (proto, port) = match (i % 10, tr.last) {
        (1, 2) => (ESP, 0),
        (6, _) => (UDP, 443),
        (7, _) => (TCP, 993),
        (8, _) => (UDP, 53),
        (9, _) => (TCP, 5223),
        _ => (TCP, 443),
    };
    let local = if proto == ESP {
        0
    } else {
        49_152 + ((last * 7_919 + i * 104_729) % 16_384) as u16
    };
    // One client takes an SSH connection from outside.
    let inbound = tr.last == 8 && i == 3;
    let (src, sport, dst, dport) = if inbound {
        (
            doc6(0xf00, 0x22, 0x22),
            52_114,
            doc6(0x10, 0, tr.last.into()),
            22,
        )
    } else {
        (own, local, remote(port), port)
    };
    // The first few lookups and one other connection are still on the CPU.
    let offloaded = !(port == 53 && i < 20) && i != 11;
    let rx_bytes = (tr.down * 0.94 * share) as u64;
    let tx_bytes = (tr.up * 0.94 * share) as u64;
    let lifetime = 60.0 + ((i * 977 + last * 131) % 3_600) as f64;
    let age = ((tr.t + (i * 53) as f64) % lifetime).min(tr.connected_s);
    Flow {
        proto,
        src,
        sport,
        dst,
        dport,
        tx_bytes,
        rx_bytes,
        tx_packets: tx_bytes / 420,
        rx_packets: rx_bytes / 1_150,
        offloaded,
        age_s: age as u32,
        client_is_src: !inbound,
    }
}
