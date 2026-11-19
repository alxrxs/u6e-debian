//! What the agent asks is checked before anything runs: every netdev name is
//! one of the AP's own kinds (a BSS's `wlan5-1`, its per-VLAN `wlan5-1.42`,
//! a client VLAN's `vlan42`), each port belongs to a BSS of its SSID, a BSS
//! carries one SSID, every client is a station of a listed SSID, each rate
//! is in range, and the counts are bounded. A name that passes is safe in an
//! argument vector and in the nftables ruleset as it is.

use std::collections::BTreeSet;

use u6e_proto::mac;
use u6e_proto::msg::{CLIENT_LIMITS_MAX, Rate, SSID_LIMITS_MAX, SSID_MAX};
use u6e_proto::shaper::Spec;

/// The most VLAN netdevs, and ports of an SSID, a spec names.
const VLANS_MAX: usize = 64;
const PORTS_MAX: usize = 128;

/// A BSS's netdev: `wlan24`, `wlan5`, `wlan6`, each with an optional `-1`
/// to `-7` for the radio's further BSSs.
pub fn vap(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("wlan") else {
        return false;
    };
    let (band, extra) = match rest.split_once('-') {
        Some((b, e)) => (b, Some(e)),
        None => (rest, None),
    };
    matches!(band, "24" | "5" | "6")
        && extra.is_none_or(|e| e.len() == 1 && (b'1'..=b'7').contains(&e.as_bytes()[0]))
}

/// `name` is `vap` itself or one of its per-VLAN netdevs (`<vap>.<vid>`).
pub fn port_of(name: &str, vap: &str) -> bool {
    match name.strip_prefix(vap) {
        Some("") => true,
        Some(rest) => rest.strip_prefix('.').is_some_and(vid),
        None => false,
    }
}

/// A client VLAN's netdev, `vlan<vid>`.
pub fn vlan(name: &str) -> bool {
    name.strip_prefix("vlan").is_some_and(vid)
}

/// A VLAN id as written in a netdev name: 1 to 4 digits, no leading zero.
fn vid(s: &str) -> bool {
    (1..=4).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit()) && !s.starts_with('0')
}

/// An SSID's own limit may be none at all (only its clients are limited).
fn rate_ok(r: &Rate) -> bool {
    *r == Rate::default() || r.valid()
}

/// Why `spec` is refused, if it is.
pub fn check(spec: &Spec) -> Result<(), String> {
    if spec.ssids.len() > SSID_LIMITS_MAX || spec.clients.len() > CLIENT_LIMITS_MAX {
        return Err("too many SSIDs or clients".into());
    }
    if spec.vlans.len() > VLANS_MAX || !spec.vlans.iter().all(|v| vlan(&v.name)) {
        return Err("a VLAN netdev that is none of the AP's".into());
    }
    let (mut names, mut vaps) = (BTreeSet::new(), BTreeSet::new());
    for s in &spec.ssids {
        if s.ssid.is_empty() || s.ssid.len() > SSID_MAX || !names.insert(&s.ssid) {
            return Err("an SSID is 1 to 32 bytes, each listed once".into());
        }
        if !rate_ok(&s.rate) {
            return Err(format!("{:?}: a rate out of range", s.ssid));
        }
        if s.vaps.is_empty() || s.ports.len() > PORTS_MAX {
            return Err(format!("{:?}: no BSS, or too many ports", s.ssid));
        }
        for v in &s.vaps {
            if !vap(&v.name) || !vaps.insert(&v.name) {
                return Err(format!(
                    "{:?}: {:?} is no BSS of the AP's, or another SSID's",
                    s.ssid, v.name
                ));
            }
        }
        let own = |p: &str| s.vaps.iter().any(|v| port_of(p, &v.name));
        if let Some(p) = s.ports.iter().find(|p| !own(&p.name)) {
            return Err(format!("{:?}: {:?} is no port of its BSSs", s.ssid, p.name));
        }
    }
    let mut macs = BTreeSet::new();
    for c in &spec.clients {
        if !mac::is_station(c.mac) || !macs.insert(c.mac) {
            return Err(format!(
                "{} is no station's address, or listed twice",
                mac::format(c.mac)
            ));
        }
        if !c.rate.valid() || c.ssid >= spec.ssids.len() {
            return Err(format!(
                "{}: a rate out of range, or no such SSID",
                mac::format(c.mac)
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use u6e_proto::shaper::{ClientSpec, Netdev, SsidSpec};

    pub fn nd(name: &str, ifindex: u32) -> Netdev {
        Netdev {
            name: name.into(),
            ifindex,
        }
    }

    pub fn rate(down: Option<u32>, up: Option<u32>) -> Rate {
        Rate {
            down_kbit: down,
            up_kbit: up,
        }
    }

    /// An SSID on wlan5 and wlan6 with their VLAN 42 netdevs, and one client.
    pub fn spec() -> Spec {
        Spec {
            ssids: vec![SsidSpec {
                ssid: "ssid-a".into(),
                rate: Rate::default(),
                vaps: vec![nd("wlan5", 10), nd("wlan6", 11)],
                ports: vec![nd("wlan5", 10), nd("wlan5.42", 20), nd("wlan6", 11)],
            }],
            clients: vec![ClientSpec {
                mac: [2, 0, 0, 0, 0, 1],
                rate: rate(Some(20_000), Some(5_000)),
                ssid: 0,
            }],
            vlans: vec![nd("vlan42", 30)],
        }
    }

    #[test]
    fn names_are_the_aps_own_kinds() {
        for ok in ["wlan24", "wlan5", "wlan6", "wlan5-1", "wlan24-7"] {
            assert!(vap(ok), "{ok}");
        }
        for bad in [
            "wlan4", "wlan5-0", "wlan5-8", "wlan5-12", "wlan5.42", "lan", "wlan", "wlan5 x",
            "wlan5-",
        ] {
            assert!(!vap(bad), "{bad}");
        }
        assert!(port_of("wlan5-1.42", "wlan5-1") && port_of("wlan5", "wlan5"));
        for bad in [
            "wlan5-1.042",
            "wlan5-1.",
            "wlan5-1.12345",
            "wlan5-12",
            "wlan5-1.4x",
            "wlan6.42",
        ] {
            assert!(!port_of(bad, "wlan5-1"), "{bad}");
        }
        assert!(vlan("vlan42") && vlan("vlan4094"));
        for bad in ["vlan", "vlan0", "vlan042", "vlan12345", "vlan42;", "br42"] {
            assert!(!vlan(bad), "{bad}");
        }
    }

    #[test]
    fn a_good_spec_passes_and_each_misuse_is_refused() {
        assert_eq!(check(&spec()), Ok(()));
        let mut empty = spec();
        empty.clients.clear();
        empty.ssids[0].rate = rate(Some(1_000), None);
        assert_eq!(check(&empty), Ok(()));
        type Misuse = Box<dyn Fn(&mut Spec)>;
        let cases: Vec<Misuse> = vec![
            Box::new(|s| s.vlans.push(nd("br42", 1))),
            Box::new(|s| s.ssids[0].vaps.push(nd("wlan5.42", 1))),
            Box::new(|s| s.ssids[0].ports.push(nd("wlan24.42", 1))),
            Box::new(|s| s.ssids[0].ports.push(nd("lan", 1))),
            Box::new(|s| s.ssids[0].vaps.clear()),
            Box::new(|s| s.ssids[0].ssid.clear()),
            Box::new(|s| s.ssids[0].rate = rate(Some(10), None)),
            Box::new(|s| {
                let mut twin = s.ssids[0].clone();
                twin.ssid = "ssid-b".into();
                s.ssids.push(twin);
            }),
            Box::new(|s| s.clients[0].mac = [0xff; 6]),
            Box::new(|s| s.clients[0].rate = rate(None, None)),
            Box::new(|s| s.clients[0].rate = rate(Some(0), None)),
            Box::new(|s| s.clients[0].ssid = 1),
            Box::new(|s| {
                let c = s.clients[0].clone();
                s.clients.push(c);
            }),
            Box::new(|s| {
                s.clients = (0..=CLIENT_LIMITS_MAX as u8)
                    .map(|i| ClientSpec {
                        mac: [2, 0, 0, 0, 1, i],
                        rate: rate(Some(100), None),
                        ssid: 0,
                    })
                    .collect();
            }),
        ];
        for (i, f) in cases.iter().enumerate() {
            let mut s = spec();
            f(&mut s);
            assert!(check(&s).is_err(), "case {i}");
        }
    }
}
