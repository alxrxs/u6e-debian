//! The four guards' rules, applied to each frame of interest:
//!
//! - ARP inspection: an ARP frame from a client names the client's own MAC
//!   as its sender and, unless it probes (0.0.0.0) or is link-local, an
//!   address bound to that MAC.
//! - Rogue DHCP: no DHCP or DHCPv6 server message comes from a client.
//! - RA guard: a client's router advertisement offers no default route (its
//!   router lifetime is 0), no prefix to configure or treat as on link, and
//!   no route but to a unique local prefix of /48 or longer: what a Thread
//!   border router advertises for its mesh, which phones and speakers on
//!   the network legitimately do.
//! - IP source guard: a connection a client opens comes from an address
//!   bound to its MAC, or a link-local one (asking for a lease from 0.0.0.0
//!   is DHCP, which this guard does not look at).
//!
//! The uplink's DHCP acknowledgements bind addresses, a client's release or
//! decline unbinds one. A violation is recorded at most once a minute per
//! client and guard, with the number of repeats in between, in a record of
//! the newest [`RECORD`]. A client whose advertisement broke the RA guard is
//! remembered for an hour: enforcing, its advertisements are dropped.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use u6e_proto::mac;
use u6e_proto::msg::{Event, EventKind, Guard, Violation};

use crate::bindings::Bindings;
use crate::dhcp;
use crate::frame::{Frame, Ra, What};
use crate::ports::Port;

/// Violations kept for the agent.
pub const RECORD: usize = 256;
/// The least time between two reports of one client and guard.
pub const QUIET_MS: u64 = 60_000;
/// How long a client that sent a rogue advertisement stays one.
pub const RA_OFFENDER_MS: u64 = 3_600_000;
/// A lease acknowledged without its length.
const LEASE_DEFAULT_S: u64 = 3600;
/// Clients tracked by the rate limit at most.
const QUIET_CAP: usize = 4096;

#[derive(Debug, Default)]
pub struct Guards {
    pub bindings: Bindings,
    /// The VLANs enforced on.
    pub enforce: Vec<u16>,
    /// The clients that sent a rogue advertisement, until when.
    pub ra_offenders: BTreeMap<[u8; 6], u64>,
    /// The violations, numbered, the newest last.
    pub record: VecDeque<(u64, Event)>,
    next: u64,
    /// When each client and guard was last reported, and the repeats since.
    quiet: HashMap<([u8; 6], Guard), (u64, u32)>,
}

impl Guards {
    /// Applies the rules to `frame`, which came in on `port` at `now_ms`.
    pub fn take(&mut self, port: &Port, frame: &Frame, now_ms: u64) {
        if !port.wifi {
            self.uplink(frame, now_ms);
            return;
        }
        let src = frame.src;
        match &frame.what {
            What::Arp { sha, spa } => self.arp(port, src, *sha, *spa, now_ms),
            What::Dhcp {
                src: ip,
                server: true,
                msg,
            } => {
                let kind = msg.kind.map_or("BOOTREPLY".into(), dhcp_name);
                let detail = format!(
                    "answers as a DHCP server ({kind} for {})",
                    mac::format(msg.chaddr)
                );
                self.violate(
                    port,
                    Guard::Dhcp,
                    src,
                    Some((*ip).into()),
                    detail,
                    true,
                    now_ms,
                );
            }
            What::Dhcp {
                server: false, msg, ..
            } => {
                if matches!(msg.kind, Some(dhcp::RELEASE | dhcp::DECLINE)) {
                    self.bindings.release(msg.chaddr, msg.ciaddr, now_ms);
                }
            }
            What::Dhcp6Server { src: ip, kind } => {
                let detail = format!("answers as a DHCPv6 server (message type {kind})");
                self.violate(
                    port,
                    Guard::Dhcp,
                    src,
                    Some((*ip).into()),
                    detail,
                    true,
                    now_ms,
                );
            }
            What::Ra(ra) => {
                if let Some(why) = rogue(ra) {
                    let dropped = self.ra_offenders.get(&src).is_some_and(|&u| u > now_ms);
                    self.ra_offenders.insert(src, now_ms + RA_OFFENDER_MS);
                    let detail = format!("advertises itself as a router: {why}");
                    self.violate(port, Guard::Ra, src, None, detail, dropped, now_ms);
                }
            }
            What::Conn { src: ip } => {
                if !ip.is_link_local() && !self.bindings.bound(src, *ip, now_ms) {
                    let detail = self.unbound(src, *ip, now_ms);
                    self.violate(
                        port,
                        Guard::Source,
                        src,
                        Some((*ip).into()),
                        detail,
                        true,
                        now_ms,
                    );
                }
            }
        }
    }

    /// A DHCP server's acknowledgement binds the address it assigns.
    fn uplink(&mut self, frame: &Frame, now_ms: u64) {
        let What::Dhcp {
            server: true, msg, ..
        } = &frame.what
        else {
            return;
        };
        if msg.kind == Some(dhcp::ACK) && !msg.yiaddr.is_unspecified() {
            let lease = msg.lease_s.map_or(LEASE_DEFAULT_S, u64::from);
            let until = now_ms.saturating_add(lease.saturating_mul(1000));
            self.bindings.learn(msg.chaddr, msg.yiaddr, until, now_ms);
        }
    }

    fn arp(&mut self, port: &Port, src: [u8; 6], sha: [u8; 6], spa: Ipv4Addr, now_ms: u64) {
        let detail = if sha != src {
            format!("names {} as its sender", mac::format(sha))
        } else if exempt(spa) || self.bindings.bound(src, spa, now_ms) {
            return;
        } else {
            self.unbound(src, spa, now_ms)
        };
        self.violate(
            port,
            Guard::Arp,
            src,
            Some(spa.into()),
            detail,
            true,
            now_ms,
        );
    }

    /// Why `ip` is not `mac`'s.
    fn unbound(&self, mac: [u8; 6], ip: Ipv4Addr, now_ms: u64) -> String {
        match self.bindings.owner(ip, mac, now_ms) {
            Some(other) => format!("uses {ip}, bound to {}", mac::format(other)),
            None => format!("uses {ip}, bound to no client"),
        }
    }

    /// Records a violation unless the client was reported for this guard in
    /// the last minute; `drops` says whether enforcing would drop the frame.
    #[allow(clippy::too_many_arguments)]
    fn violate(
        &mut self,
        port: &Port,
        guard: Guard,
        mac: [u8; 6],
        ip: Option<IpAddr>,
        detail: String,
        drops: bool,
        now_ms: u64,
    ) {
        if let Some((last, repeats)) = self.quiet.get_mut(&(mac, guard))
            && now_ms.saturating_sub(*last) < QUIET_MS
        {
            *repeats = repeats.saturating_add(1);
            return;
        }
        if self.quiet.len() >= QUIET_CAP {
            self.quiet
                .retain(|_, (last, _)| now_ms.saturating_sub(*last) < QUIET_MS);
        }
        let repeats = self
            .quiet
            .insert((mac, guard), (now_ms, 0))
            .map_or(0, |(_, r)| r);
        let v = Violation {
            guard,
            mac,
            ifname: port.name.clone(),
            vlan: port.vlan,
            ip,
            detail,
            dropped: drops && self.enforce.contains(&port.vlan),
            repeats,
        };
        if self.record.len() == RECORD {
            self.record.pop_front();
        }
        self.next += 1;
        let ev = Event {
            at_ms: now_ms,
            kind: EventKind::GuardViolation(v),
        };
        self.record.push_back((self.next, ev));
    }

    /// The violations numbered after `after`.
    pub fn after(&self, after: u64) -> Vec<(u64, Event)> {
        let newer = self.record.iter().filter(|(n, _)| *n > after);
        newer.cloned().collect()
    }

    /// Forgets the offenders and bindings whose time is up.
    pub fn expire(&mut self, now_ms: u64) {
        self.bindings.expire(now_ms);
        self.ra_offenders.retain(|_, &mut until| until > now_ms);
    }
}

/// The sender addresses of an ARP frame no binding is needed for: a probe's,
/// and link-local ones.
fn exempt(ip: Ipv4Addr) -> bool {
    ip.is_unspecified() || ip.is_link_local()
}

/// What makes `ra` a router's, if anything.
fn rogue(ra: &Ra) -> Option<String> {
    let mut why = Vec::new();
    if ra.lifetime > 0 {
        why.push(format!("a default route for {} s", ra.lifetime));
    }
    for (prefix, len, flags) in &ra.prefixes {
        if *flags != 0 {
            why.push(format!("the prefix {prefix}/{len}"));
        }
    }
    let ula = |p: &Ipv6Addr| p.segments()[0] & 0xfe00 == 0xfc00;
    for (prefix, len) in &ra.routes {
        if !(ula(prefix) && *len >= 48) {
            why.push(format!("a route to {prefix}/{len}"));
        }
    }
    (!why.is_empty()).then(|| why.join(", "))
}

fn dhcp_name(kind: u8) -> String {
    match kind {
        2 => "OFFER".into(),
        dhcp::ACK => "ACK".into(),
        6 => "NAK".into(),
        k => format!("type {k}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{self, tests::*};

    const OTHER: [u8; 6] = [2, 0, 0, 0, 0, 2];

    fn port(wifi: bool, vlan: u16) -> Port {
        Port {
            ifindex: 3,
            name: if wifi { "wlan5" } else { "vlan42" }.into(),
            vlan,
            wifi,
        }
    }

    fn take(g: &mut Guards, wifi: bool, bytes: Vec<u8>, now_ms: u64) {
        let f = frame::parse(&bytes).expect("a frame of interest");
        g.take(&port(wifi, 42), &f, now_ms);
    }

    fn violations(g: &Guards) -> Vec<Violation> {
        let all = g.record.iter().map(|(_, e)| match &e.kind {
            EventKind::GuardViolation(v) => v.clone(),
            k => panic!("{k:?}"),
        });
        all.collect()
    }

    /// A DHCP ACK of 192.0.2.10 to CLIENT, as the uplink brings it.
    fn ack(g: &mut Guards, now_ms: u64) {
        let m = crate::dhcp::tests::message(2, dhcp::ACK, [192, 0, 2, 10], Some(600));
        let f = ipv4_frame([2, 0, 0, 0, 0, 0xfe], [192, 0, 2, 1], 17, &udp(67, 68, &m));
        take(g, false, f, now_ms);
    }

    #[test]
    fn arp_names_only_the_senders_own_bound_address() {
        let mut g = Guards::default();
        ack(&mut g, 0);
        for ok in [
            arp_frame(CLIENT, CLIENT, [192, 0, 2, 10], 2),
            arp_frame(CLIENT, CLIENT, [0, 0, 0, 0], 1),
            arp_frame(CLIENT, CLIENT, [169, 254, 7, 7], 1),
        ] {
            take(&mut g, true, ok, 1000);
        }
        assert!(g.record.is_empty());
        take(
            &mut g,
            true,
            arp_frame(OTHER, OTHER, [192, 0, 2, 10], 2),
            1000,
        );
        take(
            &mut g,
            true,
            arp_frame(CLIENT, CLIENT, [192, 0, 2, 99], 2),
            1000,
        );
        take(
            &mut g,
            true,
            arp_frame(CLIENT, OTHER, [192, 0, 2, 10], 2),
            70_000,
        );
        let details: Vec<_> = violations(&g)
            .into_iter()
            .map(|v| (v.guard, v.detail, v.dropped))
            .collect();
        assert_eq!(
            details,
            [
                (
                    Guard::Arp,
                    "uses 192.0.2.10, bound to 02:00:00:00:00:01".into(),
                    false
                ),
                (
                    Guard::Arp,
                    "uses 192.0.2.99, bound to no client".into(),
                    false
                ),
                (
                    Guard::Arp,
                    "names 02:00:00:00:00:02 as its sender".into(),
                    false
                ),
            ]
        );
        // The lease ends after its 600 s.
        g.expire(600_000);
        assert!(g.bindings.list(600_000).is_empty());
    }

    #[test]
    fn reports_are_once_a_minute_per_client_and_guard_with_the_repeats() {
        let mut g = Guards::default();
        for t in [0, 10_000, 20_000, 59_999] {
            take(
                &mut g,
                true,
                arp_frame(CLIENT, CLIENT, [192, 0, 2, 99], 2),
                t,
            );
        }
        take(
            &mut g,
            true,
            ipv4_frame(CLIENT, [192, 0, 2, 99], 6, &tcp(0x02)),
            1,
        );
        take(
            &mut g,
            true,
            arp_frame(CLIENT, CLIENT, [192, 0, 2, 99], 2),
            60_000,
        );
        let seen: Vec<_> = violations(&g)
            .into_iter()
            .map(|v| (v.guard, v.repeats))
            .collect();
        assert_eq!(seen, [(Guard::Arp, 0), (Guard::Source, 0), (Guard::Arp, 3)]);
        assert_eq!(g.after(1).len(), 2);
        assert_eq!(g.after(3), []);
    }

    #[test]
    fn the_record_keeps_the_newest() {
        let mut g = Guards::default();
        for i in 0..300u64 {
            let mac = [2, 0, 0, 0, (i >> 8) as u8, i as u8];
            take(&mut g, true, arp_frame(mac, mac, [192, 0, 2, 99], 2), i);
        }
        assert_eq!(g.record.len(), RECORD);
        assert_eq!(g.record.front().unwrap().0, 300 - RECORD as u64 + 1);
    }

    #[test]
    fn a_client_never_answers_as_a_dhcp_server() {
        let mut g = Guards {
            enforce: vec![42],
            ..Guards::default()
        };
        let offer = crate::dhcp::tests::message(2, 2, [192, 0, 2, 50], Some(60));
        take(
            &mut g,
            true,
            ipv4_frame(CLIENT, [192, 0, 2, 66], 17, &udp(67, 68, &offer)),
            0,
        );
        take(
            &mut g,
            true,
            ipv6_frame(OTHER, 17, &udp(547, 546, &[2, 0, 0, 1])),
            0,
        );
        let v = violations(&g);
        assert_eq!(
            (v[0].guard, v[0].dropped, v[0].ip),
            (Guard::Dhcp, true, Some("192.0.2.66".parse().unwrap()))
        );
        assert_eq!(
            v[0].detail,
            "answers as a DHCP server (OFFER for 02:00:00:00:00:01)"
        );
        assert_eq!(v[1].detail, "answers as a DHCPv6 server (message type 2)");
        // A rogue server's ACK binds nothing.
        assert!(g.bindings.list(0).is_empty());
    }

    #[test]
    fn a_release_unbinds_the_address() {
        let mut g = Guards::default();
        ack(&mut g, 0);
        let mut rel = crate::dhcp::tests::message(1, dhcp::RELEASE, [0; 4], None);
        rel[12..16].copy_from_slice(&[192, 0, 2, 10]);
        take(
            &mut g,
            true,
            ipv4_frame(CLIENT, [192, 0, 2, 10], 17, &udp(68, 67, &rel)),
            1,
        );
        assert!(g.bindings.list(1).is_empty());
        assert!(g.record.is_empty());
    }

    #[test]
    fn only_routers_advertisements_break_the_ra_guard() {
        let mut g = Guards::default();
        let ra = |lifetime, opts: &[Vec<u8>]| ipv6_frame(CLIENT, 58, &ra_body(lifetime, opts));
        // A Thread border router: its mesh's unique local route alone.
        take(&mut g, true, ra(0, &[rio("fdba:97ab:f6e9:1::", 64)]), 0);
        // A prefix with neither flag configures nothing.
        take(&mut g, true, ra(0, &[pio("2001:db8:2::", 64, 0)]), 0);
        assert!(g.record.is_empty() && g.ra_offenders.is_empty());
        take(
            &mut g,
            true,
            ra(1800, &[pio("2001:db8:1::", 64, 0xc0), rio("::", 0)]),
            1,
        );
        let v = &violations(&g)[0];
        assert_eq!(
            (v.guard, v.dropped, v.detail.as_str()),
            (
                Guard::Ra,
                false,
                "advertises itself as a router: a default route for 1800 s, the prefix 2001:db8:1::/64, a route to ::/0"
            )
        );
        // Enforcing, the offender's next advertisements are dropped.
        g.enforce = vec![42];
        take(&mut g, true, ra(0, &[rio("2001:db8:3::", 48)]), 70_000);
        assert!(violations(&g)[1].dropped);
        assert_eq!(g.ra_offenders[&CLIENT], 70_000 + RA_OFFENDER_MS);
        g.expire(70_000 + RA_OFFENDER_MS);
        assert!(g.ra_offenders.is_empty());
    }

    #[test]
    fn connections_come_from_bound_addresses() {
        let mut g = Guards::default();
        ack(&mut g, 0);
        g.enforce = vec![42];
        for ok in [
            ipv4_frame(CLIENT, [192, 0, 2, 10], 6, &tcp(0x02)),
            ipv4_frame(CLIENT, [169, 254, 1, 1], 17, &udp(5353, 5353, &[])),
        ] {
            take(&mut g, true, ok, 1);
        }
        assert!(g.record.is_empty());
        take(
            &mut g,
            true,
            ipv4_frame(OTHER, [192, 0, 2, 10], 17, &udp(50_000, 53, &[])),
            1,
        );
        let v = &violations(&g)[0];
        assert_eq!(
            (v.guard, v.mac, v.dropped, v.vlan, v.ifname.as_str()),
            (Guard::Source, OTHER, true, 42, "wlan5")
        );
        assert_eq!(v.detail, "uses 192.0.2.10, bound to 02:00:00:00:00:01");
        // What a client's uplink port carries never counts against it.
        take(
            &mut g,
            false,
            ipv4_frame(OTHER, [192, 0, 2, 77], 6, &tcp(0x02)),
            2,
        );
        assert_eq!(g.record.len(), 1);
    }
}
