//! The client guards' rules. Each names only what is provably wrong, so that
//! enforcing (`enforce`) drops exactly the frames reporting reports, and a
//! client the guards know nothing of (a static address nobody listed, a
//! lease from before the AP's seed) is never in the way:
//!
//! - ARP inspection: no client's ARP names as its sender an address bound to
//!   another MAC, nor, when either MAC holds an address, another MAC than
//!   the frame's own.
//! - Rogue DHCP: no DHCP or DHCPv6 server message comes from a client, and
//!   on the uplink only the site's servers' acknowledgements, through its
//!   relays, bind addresses (any other server message is reported).
//! - RA guard: a client's router advertisement offers no default route (its
//!   router lifetime is 0), sits behind no extension header, names no DNS
//!   server or domain, and no prefix or route but a unique local one (a
//!   route of /48 or longer): what a Thread border router advertises for its
//!   mesh, as phones and speakers on the network do.
//! - IP source guard: no connection a client opens comes from an address
//!   bound to another MAC.
//! - VLAN tags: no client sends a tagged frame (the ports are untagged).
//!
//! A violation is recorded at most once a minute per client and guard, with
//! the repeats in between, in a record of the newest [`RECORD`]; it says
//! whether enforcing dropped the frame. A client whose advertisement broke
//! the RA guard is remembered for an hour: enforcing, all its advertisements
//! are dropped (a lifetime-0 rogue one is told from a border router's only
//! by what flower cannot read).

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use u6e_proto::mac;
use u6e_proto::msg::{Event, EventKind, Guard, Violation};

use crate::bindings::{Bindings, Clock};
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
const LEASE_DEFAULT_MS: u64 = 3_600_000;
/// Clients tracked by the rate limit at most.
const QUIET_CAP: usize = 4096;

#[derive(Debug, Default)]
pub struct Guards {
    pub bindings: Bindings,
    /// The VLANs enforced on.
    pub enforce: Vec<u16>,
    /// The site's DHCP servers and relays: only their acknowledgements bind.
    pub dhcp_servers: Vec<Ipv4Addr>,
    pub dhcp_relays: Vec<Ipv4Addr>,
    /// The clients that sent a rogue advertisement, until when (boot clock).
    pub ra_offenders: BTreeMap<[u8; 6], u64>,
    /// The violations, numbered, the newest last.
    pub record: VecDeque<(u64, Event)>,
    next: u64,
    /// When each client and guard was last reported (boot clock), and the
    /// repeats since.
    quiet: HashMap<([u8; 6], Guard), (u64, u32)>,
}

/// One violation as found, before it is recorded.
struct Found {
    guard: Guard,
    ip: Option<IpAddr>,
    detail: String,
    /// Whether the enforcing filters drop the frame.
    drops: bool,
}

impl Guards {
    /// Applies the rules to `frame`, which came in on `port`.
    pub fn take(&mut self, port: &Port, frame: &Frame, now: Clock) {
        let found = if port.wifi {
            self.client_frame(frame, now)
        } else {
            self.uplink_frame(frame, now)
        };
        if let Some(f) = found {
            self.record(port, frame.src, f, now);
        }
    }

    /// What a DHCP server's answer on the uplink does: the site's
    /// acknowledgement binds the address it assigns, any other server's
    /// message is reported.
    fn uplink_frame(&mut self, frame: &Frame, now: Clock) -> Option<Found> {
        let What::Dhcp {
            src,
            server: true,
            msg,
        } = &frame.what
        else {
            return None;
        };
        if self.dhcp_servers.is_empty() {
            return None;
        }
        let sid = msg.server_id;
        let sites = sid.is_some_and(|s| self.dhcp_servers.contains(&s))
            && (self.dhcp_servers.contains(src) || self.dhcp_relays.contains(src));
        if !sites {
            let sid = sid.map_or("none".into(), |s| s.to_string());
            let detail =
                format!("answers as a DHCP server on the uplink (server {sid}), not the site's");
            return Some(Found {
                guard: Guard::Dhcp,
                ip: Some((*src).into()),
                detail,
                drops: false,
            });
        }
        if msg.kind == Some(dhcp::ACK) && !msg.yiaddr.is_unspecified() {
            let lease = msg
                .lease_s
                .map_or(LEASE_DEFAULT_MS, |s| u64::from(s) * 1000);
            self.bindings.learn(msg.chaddr, msg.yiaddr, lease, now);
        }
        None
    }

    fn client_frame(&mut self, frame: &Frame, now: Clock) -> Option<Found> {
        let src = frame.src;
        let found = |guard, ip: Option<IpAddr>, detail: String, drops| Found {
            guard,
            ip,
            detail,
            drops,
        };
        match &frame.what {
            What::Tagged { vid } => {
                let detail = format!("sends frames tagged for VLAN {vid}");
                Some(found(Guard::Tag, None, detail, true))
            }
            What::Arp { sha, spa } => {
                if let Some(other) = self.bindings.owner(*spa, src, now) {
                    let detail = format!("claims {spa}, bound to {}", mac::format(other));
                    return Some(found(Guard::Arp, Some((*spa).into()), detail, true));
                }
                let lies = *sha != src
                    && (self.bindings.holds_any(src, now) || self.bindings.holds_any(*sha, now));
                lies.then(|| {
                    let detail = format!("names {} as its sender", mac::format(*sha));
                    found(Guard::Arp, Some((*spa).into()), detail, true)
                })
            }
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
                Some(found(Guard::Dhcp, Some((*ip).into()), detail, true))
            }
            What::Dhcp {
                server: false, msg, ..
            } => {
                if matches!(msg.kind, Some(dhcp::RELEASE | dhcp::DECLINE)) {
                    self.bindings.release(msg.chaddr, msg.ciaddr, now);
                }
                None
            }
            What::Dhcp6Server { src: ip, kind } => {
                let detail = format!("answers as a DHCPv6 server (message type {kind})");
                Some(found(Guard::Dhcp, Some((*ip).into()), detail, true))
            }
            What::Ra(ra) => {
                let why = rogue(ra)?;
                let offender = self
                    .ra_offenders
                    .get(&src)
                    .is_some_and(|&u| u > now.boot_ms);
                self.ra_offenders.insert(src, now.boot_ms + RA_OFFENDER_MS);
                let drops = offender || ra.lifetime != 0 || !ra.ext.is_empty();
                let detail = format!("advertises itself as a router: {why}");
                Some(found(Guard::Ra, None, detail, drops))
            }
            What::Conn { src: ip } => {
                let other = self.bindings.owner(*ip, src, now)?;
                let detail = format!("uses {ip}, bound to {}", mac::format(other));
                Some(found(Guard::Source, Some((*ip).into()), detail, true))
            }
        }
    }

    /// Records `f`, unless the client was reported for its guard in the
    /// last minute.
    fn record(&mut self, port: &Port, mac: [u8; 6], f: Found, now: Clock) {
        if let Some((last, repeats)) = self.quiet.get_mut(&(mac, f.guard))
            && now.boot_ms.saturating_sub(*last) < QUIET_MS
        {
            *repeats = repeats.saturating_add(1);
            return;
        }
        if self.quiet.len() >= QUIET_CAP {
            let fresh = |last: u64| now.boot_ms.saturating_sub(last) < QUIET_MS;
            self.quiet.retain(|_, (last, _)| fresh(*last));
        }
        let repeats = self.quiet.insert((mac, f.guard), (now.boot_ms, 0));
        let v = Violation {
            guard: f.guard,
            mac,
            ifname: port.name.clone(),
            vlan: port.vlan,
            ip: f.ip,
            detail: f.detail,
            dropped: f.drops && port.wifi && self.enforce.contains(&port.vlan),
            repeats: repeats.map_or(0, |(_, r)| r),
        };
        if self.record.len() == RECORD {
            self.record.pop_front();
        }
        self.next += 1;
        let ev = Event {
            at_ms: now.wall_ms,
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
    pub fn expire(&mut self, now: Clock) {
        self.bindings.expire(now);
        self.ra_offenders
            .retain(|_, &mut until| until > now.boot_ms);
    }
}

/// What makes `ra` a router's, if anything.
fn rogue(ra: &Ra) -> Option<String> {
    let ula = |p: &Ipv6Addr| p.segments()[0] & 0xfe00 == 0xfc00;
    let mut why = Vec::new();
    if ra.lifetime > 0 {
        why.push(format!("a default route for {} s", ra.lifetime));
    }
    if !ra.ext.is_empty() {
        why.push("behind an extension header".into());
    }
    if ra.dns {
        why.push("DNS servers or domains".into());
    }
    for (prefix, len, _) in ra.prefixes.iter().filter(|(p, ..)| !ula(p)) {
        why.push(format!("the prefix {prefix}/{len}"));
    }
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
pub mod tests {
    use super::*;
    use crate::frame::{self, tests::*};

    pub const OTHER: [u8; 6] = [2, 0, 0, 0, 0, 2];
    const ROUTER: [u8; 6] = [2, 0, 0, 0, 0, 0xfe];
    pub const SERVER: [u8; 4] = [192, 0, 2, 53];
    pub const RELAY: [u8; 4] = [192, 0, 2, 2];

    fn port(wifi: bool, vlan: u16) -> Port {
        Port {
            ifindex: 3,
            name: if wifi { "wlan5" } else { "vlan42" }.into(),
            vlan,
            wifi,
        }
    }

    pub fn now(ms: u64) -> Clock {
        Clock {
            wall_ms: ms,
            boot_ms: ms,
        }
    }

    /// Guards that trust SERVER through RELAY, enforcing on `enforce`.
    pub fn guards(enforce: &[u16]) -> Guards {
        Guards {
            enforce: enforce.to_vec(),
            dhcp_servers: vec![SERVER.into()],
            dhcp_relays: vec![RELAY.into()],
            ..Guards::default()
        }
    }

    fn take(g: &mut Guards, wifi: bool, bytes: Vec<u8>, ms: u64) {
        let f = frame::parse(&bytes).expect("a frame of interest");
        g.take(&port(wifi, 42), &f, now(ms));
    }

    fn violations(g: &Guards) -> Vec<Violation> {
        let all = g.record.iter().map(|(_, e)| match &e.kind {
            EventKind::GuardViolation(v) => v.clone(),
            k => panic!("{k:?}"),
        });
        all.collect()
    }

    /// A DHCP answer of `kind` assigning 192.0.2.10 to CLIENT, from `src`
    /// naming `server`, as the uplink brings it.
    pub fn answer(kind: u8, src: [u8; 4], server: [u8; 4]) -> Vec<u8> {
        let m = crate::dhcp::tests::answer(kind, [192, 0, 2, 10], 600, server);
        ipv4_frame(ROUTER, src, 17, &udp(67, 68, &m))
    }

    #[test]
    fn only_the_sites_acknowledgements_bind() {
        let mut g = guards(&[42]);
        take(&mut g, false, answer(dhcp::ACK, RELAY, SERVER), 0);
        take(&mut g, false, answer(dhcp::ACK, SERVER, SERVER), 0);
        assert_eq!(g.bindings.list(now(0)).len(), 1);
        assert!(g.record.is_empty());
        // Another server, through the relay or not, binds nothing.
        let mut h = guards(&[42]);
        take(
            &mut h,
            false,
            answer(dhcp::ACK, [192, 0, 2, 66], [192, 0, 2, 66]),
            0,
        );
        take(&mut h, false, answer(dhcp::ACK, RELAY, [192, 0, 2, 66]), 0);
        assert!(h.bindings.list(now(0)).is_empty());
        let v = &violations(&h)[0];
        assert_eq!((v.guard, v.dropped), (Guard::Dhcp, false));
        assert_eq!(
            v.detail,
            "answers as a DHCP server on the uplink (server 192.0.2.66), not the site's"
        );
        // Unconfigured, nothing is learnt or reported.
        let mut u = Guards::default();
        take(&mut u, false, answer(dhcp::ACK, RELAY, SERVER), 0);
        assert!(u.bindings.list(now(0)).is_empty() && u.record.is_empty());
    }

    #[test]
    fn arp_may_not_claim_another_clients_address_or_mac() {
        let mut g = guards(&[42]);
        take(&mut g, false, answer(dhcp::ACK, RELAY, SERVER), 0);
        for ok in [
            arp_frame(CLIENT, CLIENT, [192, 0, 2, 10], 2),
            arp_frame(CLIENT, CLIENT, [0, 0, 0, 0], 1),
            arp_frame(CLIENT, CLIENT, [169, 254, 7, 7], 1),
            // Unbound: the guards know nothing against it.
            arp_frame(OTHER, OTHER, [192, 0, 2, 99], 2),
            arp_frame(OTHER, [2, 0, 0, 0, 0, 3], [192, 0, 2, 99], 2),
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
            arp_frame(CLIENT, OTHER, [192, 0, 2, 10], 2),
            1000,
        );
        take(
            &mut g,
            true,
            arp_frame([2, 0, 0, 0, 0, 3], CLIENT, [192, 0, 2, 99], 2),
            1000,
        );
        let seen: Vec<_> = violations(&g)
            .into_iter()
            .map(|v| (v.mac, v.detail, v.dropped))
            .collect();
        assert_eq!(
            seen,
            [
                (
                    OTHER,
                    "claims 192.0.2.10, bound to 02:00:00:00:00:01".into(),
                    true
                ),
                (CLIENT, "names 02:00:00:00:00:02 as its sender".into(), true),
                (
                    [2, 0, 0, 0, 0, 3],
                    "names 02:00:00:00:00:01 as its sender".into(),
                    true
                ),
            ]
        );
        // The lease ends after its 600 s.
        g.expire(now(600_000));
        assert!(g.bindings.list(now(600_000)).is_empty());
    }

    #[test]
    fn reports_are_once_a_minute_per_client_and_guard_with_the_repeats() {
        let mut g = guards(&[]);
        take(&mut g, false, answer(dhcp::ACK, RELAY, SERVER), 0);
        for t in [0, 10_000, 20_000, 59_999] {
            take(&mut g, true, arp_frame(OTHER, OTHER, [192, 0, 2, 10], 2), t);
        }
        take(
            &mut g,
            true,
            ipv4_frame(OTHER, [192, 0, 2, 10], 6, &tcp(0x02)),
            1,
        );
        take(
            &mut g,
            true,
            arp_frame(OTHER, OTHER, [192, 0, 2, 10], 2),
            60_000,
        );
        let seen: Vec<_> = violations(&g)
            .into_iter()
            .map(|v| (v.guard, v.repeats, v.dropped))
            .collect();
        assert_eq!(
            seen,
            [
                (Guard::Arp, 0, false),
                (Guard::Source, 0, false),
                (Guard::Arp, 3, false)
            ]
        );
        assert_eq!(g.after(1).len(), 2);
        assert_eq!(g.after(3), []);
    }

    #[test]
    fn the_record_keeps_the_newest() {
        let mut g = Guards::default();
        for i in 0..300u64 {
            let mac = [2, 0, 0, 0, (i >> 8) as u8, i as u8];
            take(&mut g, true, tagged(mac), i);
        }
        assert_eq!(g.record.len(), RECORD);
        assert_eq!(g.record.front().unwrap().0, 300 - RECORD as u64 + 1);
    }

    /// An ARP frame from `mac` tagged for VLAN 0.
    fn tagged(mac: [u8; 6]) -> Vec<u8> {
        let mut f = arp_frame(mac, mac, [0; 4], 1);
        f.splice(12..12, [0x81, 0, 0, 0]);
        f
    }

    #[test]
    fn a_tagged_frame_from_a_client_is_a_violation() {
        let mut g = guards(&[42]);
        take(&mut g, true, tagged(CLIENT), 0);
        let v = &violations(&g)[0];
        assert_eq!(
            (v.guard, v.dropped, v.detail.as_str()),
            (Guard::Tag, true, "sends frames tagged for VLAN 0")
        );
    }

    #[test]
    fn a_client_never_answers_as_a_dhcp_server() {
        let mut g = guards(&[42]);
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
        // A client's server answers bind nothing.
        assert!(g.bindings.list(now(0)).is_empty());
    }

    #[test]
    fn a_release_unbinds_the_address() {
        let mut g = guards(&[]);
        take(&mut g, false, answer(dhcp::ACK, RELAY, SERVER), 0);
        let mut rel = crate::dhcp::tests::message(1, dhcp::RELEASE, [0; 4], None);
        rel[12..16].copy_from_slice(&[192, 0, 2, 10]);
        take(
            &mut g,
            true,
            ipv4_frame(CLIENT, [192, 0, 2, 10], 17, &udp(68, 67, &rel)),
            1,
        );
        assert!(g.bindings.list(now(1)).is_empty());
        assert!(g.record.is_empty());
    }

    #[test]
    fn only_routers_advertisements_break_the_ra_guard() {
        let mut g = guards(&[]);
        let ra = |mac, lifetime, opts: &[Vec<u8>]| ipv6_frame(mac, 58, &ra_body(lifetime, opts));
        // A Thread border router: its mesh's unique local route and prefix.
        take(
            &mut g,
            true,
            ra(
                CLIENT,
                0,
                &[rio("fdba:97ab:f6e9:1::", 64), pio("fd12:3456::", 64, 0xc0)],
            ),
            0,
        );
        assert!(g.record.is_empty() && g.ra_offenders.is_empty());
        let rdnss = vec![
            25, 3, 0, 0, 0, 0, 0, 1, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53,
        ];
        take(&mut g, true, ra(OTHER, 0, &[rdnss]), 0);
        take(
            &mut g,
            true,
            ra(ROUTER, 1800, &[pio("2001:db8:1::", 64, 0), rio("::", 0)]),
            0,
        );
        let (nh, payload) = behind(&[(0, 0)], 58, &ra_body(0, &[]));
        take(
            &mut g,
            true,
            ipv6_frame([2, 0, 0, 0, 0, 3], nh, &payload),
            0,
        );
        let seen: Vec<_> = violations(&g)
            .into_iter()
            .map(|v| (v.detail, v.dropped))
            .collect();
        assert_eq!(
            seen,
            [
                ("advertises itself as a router: DNS servers or domains".into(), false),
                (
                    "advertises itself as a router: a default route for 1800 s, the prefix 2001:db8:1::/64, a route to ::/0".into(),
                    false
                ),
                ("advertises itself as a router: behind an extension header".into(), false),
            ]
        );
        // Enforcing: a default route or an extension header is dropped at
        // once, a content-rogue one from its sender's next.
        let mut e = guards(&[42]);
        take(
            &mut e,
            true,
            ra(OTHER, 0, &[vec![31, 1, 0, 0, 0, 0, 0, 1]]),
            0,
        );
        take(&mut e, true, ra(ROUTER, 1800, &[]), 0);
        take(
            &mut e,
            true,
            ipv6_frame([2, 0, 0, 0, 0, 3], nh, &payload),
            0,
        );
        take(
            &mut e,
            true,
            ra(OTHER, 0, &[rio("fdba:97ab:f6e9:1::", 64)]),
            70_000,
        );
        let dropped: Vec<_> = violations(&e).into_iter().map(|v| v.dropped).collect();
        assert_eq!(dropped, [false, true, true]);
        assert_eq!(e.ra_offenders[&OTHER], RA_OFFENDER_MS);
        // The fourth, the offender's border-router-shaped one, is not rogue
        // in itself: it is dropped by the offender filter, and not reported.
        e.expire(now(RA_OFFENDER_MS + 1));
        assert!(e.ra_offenders.is_empty());
    }

    #[test]
    fn connections_from_another_clients_address_break_the_source_guard() {
        let mut g = guards(&[42]);
        take(&mut g, false, answer(dhcp::ACK, RELAY, SERVER), 0);
        for ok in [
            ipv4_frame(CLIENT, [192, 0, 2, 10], 6, &tcp(0x02)),
            ipv4_frame(CLIENT, [169, 254, 1, 1], 17, &udp(5353, 5353, &[])),
            // Unbound (a static address, a lease the seed has not brought).
            ipv4_frame(OTHER, [192, 0, 2, 77], 6, &tcp(0x02)),
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
    }
}
