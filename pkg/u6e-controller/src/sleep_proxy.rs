//! Bonjour Sleep Proxy: a device (a HomePod, an Apple TV) answering for one
//! that sleeps claims the sleeper's IPv4 address in ARP and sends from it,
//! which ARP inspection and the IP source guard report as a client using
//! another's address. Such a report is a sleep proxy's, not a violation,
//! when the client advertises `_sleep-proxy._udp` itself (an offer within
//! its TTL) and its newest address record for that address stands (within
//! its TTL, at most [`RECORD_MAX_MS`]) and is newer than any its bound owner
//! sent of it: the owner announcing its own again ends it. Any other report,
//! and those of the other guards, stays a violation. The APs' guards know
//! nothing of this: where they enforce, they drop the proxy's frames still.
//!
//! Whether each client answers for an address is remembered, so the change
//! goes on the proxy's and the owner's timelines once: at most [`PAIRS`]
//! pairs, the least recently reported dropped.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use u6e_proto::msg::{Binding, Guard, MdnsAddr, Violation};

use crate::services::{Site, live};

/// The service type a sleep proxy advertises.
pub const SERVICE: &str = "_sleep-proxy._udp.local";
/// The longest an address record counts as answered for, whatever TTL it
/// gave.
pub const RECORD_MAX_MS: u64 = 2 * 3600 * 1000;
/// The (proxy, address) pairs remembered, at most.
pub const PAIRS: usize = 256;

/// The device `v`'s client answers for as its sleep proxy, at `now_ms`, by
/// the reporting AP's `bindings` and the site's mDNS; `None` when `v` is a
/// violation.
pub fn owner(v: &Violation, bindings: &[Binding], site: &Site, now_ms: u64) -> Option<[u8; 6]> {
    let ip = address(v)?;
    let owner = bindings.iter().find(|b| b.ip == ip && b.mac != v.mac)?.mac;
    let offers = site
        .offers
        .iter()
        .any(|(_, o)| o.mac == v.mac && o.service.eq_ignore_ascii_case(SERVICE) && live(o, now_ms));
    let record = |mac| {
        let d = site.device(mac)?;
        d.addrs
            .iter()
            .find(|a| a.ip == IpAddr::V4(ip) && a.ttl_s > 0)
    };
    let answers = record(v.mac).filter(|a| stands(a, now_ms))?;
    let owner_since = record(owner).is_some_and(|o| o.at_ms >= answers.at_ms);
    (offers && !owner_since).then_some(owner)
}

/// The IPv4 address `v` names, when it is ARP inspection's or the IP source
/// guard's: the only reports a sleep proxy makes.
pub fn address(v: &Violation) -> Option<Ipv4Addr> {
    match (v.guard, v.ip?) {
        (Guard::Arp | Guard::Source, IpAddr::V4(ip)) => Some(ip),
        _ => None,
    }
}

/// Whether `a` still stands at `now_ms`.
fn stands(a: &MdnsAddr, now_ms: u64) -> bool {
    a.at_ms + (u64::from(a.ttl_s) * 1000).min(RECORD_MAX_MS) > now_ms
}

/// A change of whether a client answers for an address as a sleep proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Turn {
    pub proxy: [u8; 6],
    pub owner: [u8; 6],
    pub ip: Ipv4Addr,
    pub answering: bool,
}

/// Which clients answer for which address, as their last report had it.
#[derive(Debug, Default)]
pub struct Pairs {
    answering: HashMap<([u8; 6], Ipv4Addr), ([u8; 6], u64)>,
}

impl Pairs {
    /// Takes a report of `proxy` using `ip` at `at_ms`, a sleep proxy's for
    /// `owner` or a violation (`None`): the change it makes, if any.
    pub fn report(
        &mut self,
        proxy: [u8; 6],
        ip: Ipv4Addr,
        owner: Option<[u8; 6]>,
        at_ms: u64,
    ) -> Option<Turn> {
        let key = (proxy, ip);
        let Some(owner) = owner else {
            let (owner, _) = self.answering.remove(&key)?;
            return Some(Turn {
                proxy,
                owner,
                ip,
                answering: false,
            });
        };
        let was = self.answering.insert(key, (owner, at_ms));
        if self.answering.len() > PAIRS {
            let oldest = self.answering.iter().min_by_key(|(_, (_, at))| *at);
            if let Some(k) = oldest.map(|(k, _)| *k) {
                self.answering.remove(&k);
            }
        }
        (was.map(|(o, _)| o) != Some(owner)).then_some(Turn {
            proxy,
            owner,
            ip,
            answering: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use u6e_proto::msg::{MdnsDevice, MdnsOffer, Withdrawn};

    use super::*;

    /// The proxy (a speaker), the sleeper whose address it answers for, and
    /// another device.
    const PROXY: [u8; 6] = [2, 0, 0, 0, 0, 0x0e];
    const OWNER: [u8; 6] = [2, 0, 0, 0, 0, 0x01];
    const OTHER: [u8; 6] = [2, 0, 0, 0, 0, 0x04];
    const NOW: u64 = 1_800_000_000_000;

    fn ip() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn bindings() -> Vec<Binding> {
        let bind = |mac, last| Binding {
            mac,
            ip: Ipv4Addr::new(192, 0, 2, last),
            expires_ms: None,
        };
        vec![bind(OWNER, 10), bind(PROXY, 14)]
    }

    fn report(guard: Guard) -> Violation {
        Violation {
            guard,
            mac: PROXY,
            ifname: "wlan5.42".into(),
            vlan: 42,
            ip: Some(ip().into()),
            detail: "claims 192.0.2.10, bound to 02:00:00:00:00:01".into(),
            dropped: false,
            repeats: 0,
        }
    }

    /// A device and the address records it sent: (address, TTL, how long
    /// ago).
    fn device(mac: [u8; 6], records: &[(Ipv4Addr, u32, u64)]) -> MdnsDevice {
        MdnsDevice {
            mac,
            port: "wlan5.42".into(),
            vlan: 42,
            wifi: true,
            host: String::new(),
            addrs: (records.iter())
                .map(|&(ip, ttl_s, ago)| MdnsAddr {
                    ip: ip.into(),
                    ttl_s,
                    at_ms: NOW - ago,
                })
                .collect(),
            first_ms: 0,
            last_ms: NOW,
            queries: 0,
            responses: 1,
        }
    }

    fn offer(mac: [u8; 6], service: &str, ttl_s: u32, ago: u64) -> MdnsOffer {
        MdnsOffer {
            mac,
            instance: format!("70-35-60-63.1 Speaker.{service}"),
            service: service.into(),
            target: "Speaker.local".into(),
            port: 61_000,
            txt: Vec::new(),
            first_ms: 0,
            ttl_s,
            announced_ms: NOW - ago,
            withdrawn: None,
            answered: 0,
            missed: 0,
            missed_in_row: 0,
            answered_ms: None,
            missed_ms: None,
            missed_by: None,
        }
    }

    /// The live case: the speaker offers a sleep proxy and answered for the
    /// sleeper's address 30 s ago, the sleeper last an hour ago.
    fn proxying() -> (Vec<MdnsDevice>, Vec<MdnsOffer>) {
        let own = Ipv4Addr::new(192, 0, 2, 14);
        let devices = vec![
            device(PROXY, &[(own, 120, 5000), (ip(), 120, 30_000)]),
            device(OWNER, &[(ip(), 120, 3_600_000)]),
        ];
        (devices, vec![offer(PROXY, SERVICE, 4500, 60_000)])
    }

    fn judge(devices: &[MdnsDevice], offers: &[MdnsOffer], v: &Violation) -> Option<[u8; 6]> {
        let site = Site {
            devices: devices.iter().map(|d| ("ap1", d)).collect(),
            offers: offers.iter().map(|o| ("ap1", o)).collect(),
            queries: Vec::new(),
        };
        owner(v, &bindings(), &site, NOW)
    }

    #[test]
    fn a_sleep_proxy_answering_for_the_address_is_no_violation() {
        let (devices, offers) = proxying();
        for guard in [Guard::Arp, Guard::Source] {
            assert_eq!(judge(&devices, &offers, &report(guard)), Some(OWNER));
        }
        // The service type's case does not matter.
        let mut loud = offers.clone();
        loud[0].service = SERVICE.to_ascii_uppercase();
        assert_eq!(judge(&devices, &loud, &report(Guard::Arp)), Some(OWNER));
    }

    #[test]
    fn the_other_guards_reports_stay_violations() {
        let (devices, offers) = proxying();
        for guard in [Guard::Dhcp, Guard::Ra, Guard::Tag] {
            assert_eq!(judge(&devices, &offers, &report(guard)), None);
        }
    }

    #[test]
    fn a_proxy_that_does_not_answer_for_the_address_is_a_violation() {
        let (mut devices, offers) = proxying();
        devices[0].addrs.retain(|a| a.ip != IpAddr::V4(ip()));
        assert_eq!(judge(&devices, &offers, &report(Guard::Arp)), None);
        // Nor one whose record ran out, said goodbye, or is past the cap
        // whatever its TTL.
        for (ttl, ago) in [(120, 121_000), (0, 1000), (u32::MAX, RECORD_MAX_MS)] {
            let (mut devices, offers) = proxying();
            (devices[0].addrs[1].ttl_s, devices[0].addrs[1].at_ms) = (ttl, NOW - ago);
            let got = judge(&devices, &offers, &report(Guard::Arp));
            assert_eq!(got, None, "TTL {ttl}, {ago} ms ago");
        }
    }

    #[test]
    fn answering_for_the_address_without_offering_a_sleep_proxy_is_a_violation() {
        let (devices, _) = proxying();
        let airplay = [offer(PROXY, "_airplay._tcp.local", 4500, 60_000)];
        assert_eq!(judge(&devices, &airplay, &report(Guard::Arp)), None);
        // An offer past its TTL, or withdrawn, is none.
        let lapsed = [offer(PROXY, SERVICE, 30, 60_000)];
        assert_eq!(judge(&devices, &lapsed, &report(Guard::Arp)), None);
        let mut gone = offer(PROXY, SERVICE, 4500, 60_000);
        gone.withdrawn = Some(Withdrawn::Goodbye);
        assert_eq!(judge(&devices, &[gone], &report(Guard::Arp)), None);
    }

    #[test]
    fn another_devices_sleep_proxy_offer_does_not_count() {
        let (devices, _) = proxying();
        let elsewhere = [offer(OTHER, SERVICE, 4500, 60_000)];
        assert_eq!(judge(&devices, &elsewhere, &report(Guard::Arp)), None);
    }

    #[test]
    fn the_owner_announcing_its_address_again_ends_it() {
        let (mut devices, offers) = proxying();
        devices[1].addrs[0].at_ms = NOW - 10_000;
        assert_eq!(judge(&devices, &offers, &report(Guard::Arp)), None);
        // Its goodbye is no announcement.
        devices[1].addrs[0].ttl_s = 0;
        assert_eq!(judge(&devices, &offers, &report(Guard::Arp)), Some(OWNER));
    }

    #[test]
    fn an_address_of_nobody_else_or_of_ipv6_is_a_violation() {
        let (devices, offers) = proxying();
        for ip in ["192.0.2.14", "192.0.2.99", "2001:db8::10"] {
            let mut v = report(Guard::Source);
            v.ip = Some(ip.parse().unwrap());
            assert_eq!(judge(&devices, &offers, &v), None, "{ip}");
        }
    }

    #[test]
    fn each_change_is_one_turn_and_the_pairs_are_bounded() {
        let mut p = Pairs::default();
        let turn = |answering| Turn {
            proxy: PROXY,
            owner: OWNER,
            ip: ip(),
            answering,
        };
        assert_eq!(p.report(PROXY, ip(), None, 1), None);
        assert_eq!(p.report(PROXY, ip(), Some(OWNER), 2), Some(turn(true)));
        assert_eq!(p.report(PROXY, ip(), Some(OWNER), 3), None);
        assert_eq!(p.report(PROXY, ip(), None, 4), Some(turn(false)));
        assert_eq!(p.report(PROXY, ip(), None, 5), None);
        assert_eq!(p.report(PROXY, ip(), Some(OWNER), 6), Some(turn(true)));
        for i in 0..2 * PAIRS as u32 {
            let ip = Ipv4Addr::from(0xc633_6400 + i);
            p.report(OTHER, ip, Some(OWNER), 10 + u64::from(i));
            assert!(p.answering.len() <= PAIRS);
        }
        // The least recently reported went first.
        assert!(!p.answering.contains_key(&(PROXY, ip())));
    }
}
