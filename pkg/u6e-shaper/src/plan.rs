//! The shaping a spec asks for, worked out without touching anything.
//!
//! Download is shaped on each BSS's netdev (an AP/VLAN netdev takes no
//! shaper: its firmware node refuses one), upload on the uplink, by NSS
//! `nsshtb` trees of the shape the firmware was seen to take: a root (`1:`
//! on a BSS, `2:` on the uplink), a line-rate class (`x:1`), and under it
//! the default class (`x:ffff`, with the `set_default` leaf the unlimited
//! traffic goes to) and one class per limit, each with its own leaf. A
//! client's own limit replaces its SSID's, direction by direction: on a BSS
//! the SSID's download limit is the default class's rate, which only the
//! clients without one of their own share; on the uplink the SSID's upload
//! has a class of its own (`2:100+k`), and a client's own a class beside it
//! (`1:1000+n`, `2:1000+n`), its slot `n` kept as long as it is limited so
//! that the classes its connections are tagged with stay.
//!
//! The NSS takes a connection's class from its QoS tag, which ECM takes
//! from the first packet of each direction (`skb->priority`, our ECM patch
//! 903): the nftables `netdev` table tags the limited clients' packets as
//! they come in from the Wi-Fi ports (upload) and the VLAN netdevs
//! (download), both directions, an unlimited direction with its tree's
//! default, so every connection of the client opts in by its first packet;
//! and the ports of an SSID with an upload limit with its class.

use serde::{Deserialize, Serialize};
use u6e_proto::mac;
use u6e_proto::msg::{CLIENT_LIMITS_MAX, LimitTarget, SSID_LIMITS_MAX};
use u6e_proto::shaper::{Netdev, Spec};

pub const DOWN: u16 = 1;
pub const UP: u16 = 2;
pub const TOP: u16 = 1;
pub const DEFAULT: u16 = 0xffff;
/// Faster than any port of the AP: the line-rate classes'.
pub const LINE_KBIT: u32 = 2_400_000;
/// The uplink, where every client's upload leaves the AP and the NSS shapes
/// it (ECM folds the VLAN into the connection's rule on the GMAC).
pub const UPLINK: &str = "lan";

/// The slots of the limited clients and SSIDs, which name their classes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Slots {
    pub clients: Vec<([u8; 6], u16)>,
    pub ssids: Vec<(String, u16)>,
}

/// The lowest of `0..max` none of `taken` holds.
fn free(taken: &[u16], max: usize) -> u16 {
    (0..max as u16)
        .find(|s| !taken.contains(s))
        .expect("a free slot")
}

impl Slots {
    /// The slots of `spec`'s clients and limited SSIDs: each keeps the one it
    /// had, a new one takes the lowest free.
    pub fn assign(&self, spec: &Spec) -> Slots {
        let mut clients: Vec<([u8; 6], u16)> = self
            .clients
            .iter()
            .filter(|(m, _)| spec.clients.iter().any(|c| c.mac == *m))
            .copied()
            .collect();
        for c in &spec.clients {
            if !clients.iter().any(|(m, _)| *m == c.mac) {
                let taken: Vec<u16> = clients.iter().map(|(_, s)| *s).collect();
                clients.push((c.mac, free(&taken, CLIENT_LIMITS_MAX)));
            }
        }
        let limited = spec.ssids.iter().filter(|s| s.rate.up_kbit.is_some());
        let mut ssids: Vec<(String, u16)> = self
            .ssids
            .iter()
            .filter(|(n, _)| limited.clone().any(|s| s.ssid == *n))
            .cloned()
            .collect();
        for s in limited {
            if !ssids.iter().any(|(n, _)| *n == s.ssid) {
                let taken: Vec<u16> = ssids.iter().map(|(_, k)| *k).collect();
                ssids.push((s.ssid.clone(), free(&taken, SSID_LIMITS_MAX)));
            }
        }
        Slots { clients, ssids }
    }

    fn client(&self, m: [u8; 6]) -> u16 {
        self.clients
            .iter()
            .find(|(c, _)| *c == m)
            .map(|(_, s)| *s)
            .expect("slotted")
    }

    fn ssid(&self, name: &str) -> Option<u16> {
        self.ssids.iter().find(|(n, _)| n == name).map(|(_, k)| *k)
    }
}

pub fn client_minor(slot: u16) -> u16 {
    0x1000 + slot
}

pub fn ssid_minor(slot: u16) -> u16 {
    0x100 + slot
}

/// A tree's root: on `dev`, of `major`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tree {
    pub dev: Netdev,
    pub major: u16,
    /// The default class's rate: an SSID's download limit, or the line's.
    pub default_kbit: u32,
}

/// A limit's class, under `major:1`, with its leaf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Class {
    pub dev: String,
    pub major: u16,
    pub minor: u16,
    pub kbit: u32,
}

/// What one limit needs: the trees it shapes in, its classes, and the
/// default class rates it sets (an SSID's download, per BSS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetPlan {
    pub target: LimitTarget,
    pub trees: Vec<(Netdev, u16)>,
    pub classes: Vec<Class>,
    pub defaults: Vec<(String, u32)>,
}

/// Each limit's plan, the SSIDs' first; `uplink` is the uplink's netdev.
pub fn targets(spec: &Spec, slots: &Slots, uplink: &Netdev) -> Vec<TargetPlan> {
    let mut out = Vec::new();
    for s in &spec.ssids {
        if s.rate.down_kbit.is_none() && s.rate.up_kbit.is_none() {
            continue;
        }
        let mut p = TargetPlan {
            target: LimitTarget::Ssid(s.ssid.clone()),
            trees: Vec::new(),
            classes: Vec::new(),
            defaults: Vec::new(),
        };
        if let Some(k) = s.rate.down_kbit {
            for v in &s.vaps {
                p.trees.push((v.clone(), DOWN));
                p.defaults.push((v.name.clone(), k));
            }
        }
        if let Some(k) = s.rate.up_kbit {
            p.trees.push((uplink.clone(), UP));
            let slot = slots.ssid(&s.ssid).expect("slotted");
            p.classes.push(Class {
                dev: uplink.name.clone(),
                major: UP,
                minor: ssid_minor(slot),
                kbit: k,
            });
        }
        out.push(p);
    }
    for c in &spec.clients {
        let minor = client_minor(slots.client(c.mac));
        let mut p = TargetPlan {
            target: LimitTarget::Client(c.mac),
            trees: Vec::new(),
            classes: Vec::new(),
            defaults: Vec::new(),
        };
        if let Some(k) = c.rate.down_kbit {
            for v in &spec.ssids[c.ssid].vaps {
                p.trees.push((v.clone(), DOWN));
                p.classes.push(Class {
                    dev: v.name.clone(),
                    major: DOWN,
                    minor,
                    kbit: k,
                });
            }
        }
        if let Some(k) = c.rate.up_kbit {
            p.trees.push((uplink.clone(), UP));
            p.classes.push(Class {
                dev: uplink.name.clone(),
                major: UP,
                minor,
                kbit: k,
            });
        }
        out.push(p);
    }
    out
}

/// A class as a QoS tag (`skb->priority`).
pub fn tag(major: u16, minor: u16) -> u32 {
    u32::from(major) << 16 | u32::from(minor)
}

/// What the packets are tagged with: each limited client's download and
/// upload tag, each upload-limited SSID's tag and ports, and the netdevs
/// each chain hooks.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tags {
    pub clients: Vec<([u8; 6], u32, u32)>,
    pub ssids: Vec<(String, u32, Vec<String>)>,
    pub up_devs: Vec<String>,
    pub down_devs: Vec<String>,
}

/// The tags of the limits `ok` says are in place.
pub fn tags(spec: &Spec, slots: &Slots, ok: impl Fn(&LimitTarget) -> bool) -> Tags {
    let mut t = Tags::default();
    let ssid_up = |i: usize| {
        let s = &spec.ssids[i];
        let on = s.rate.up_kbit.is_some() && ok(&LimitTarget::Ssid(s.ssid.clone()));
        on.then(|| tag(UP, ssid_minor(slots.ssid(&s.ssid).expect("slotted"))))
    };
    let mut hooked = vec![false; spec.ssids.len()];
    for c in spec
        .clients
        .iter()
        .filter(|c| ok(&LimitTarget::Client(c.mac)))
    {
        let minor = client_minor(slots.client(c.mac));
        let down = tag(
            DOWN,
            if c.rate.down_kbit.is_some() {
                minor
            } else {
                DEFAULT
            },
        );
        let up = match c.rate.up_kbit {
            Some(_) => tag(UP, minor),
            None => ssid_up(c.ssid).unwrap_or(tag(UP, DEFAULT)),
        };
        t.clients.push((c.mac, down, up));
        hooked[c.ssid] = true;
    }
    for (i, s) in spec.ssids.iter().enumerate() {
        if let Some(up) = ssid_up(i) {
            let ports = s.ports.iter().map(|p| p.name.clone()).collect();
            t.ssids.push((s.ssid.clone(), up, ports));
            hooked[i] = true;
        }
    }
    for (s, _) in spec.ssids.iter().zip(&hooked).filter(|(_, h)| **h) {
        t.up_devs.extend(s.ports.iter().map(|p| p.name.clone()));
    }
    if !t.clients.is_empty() {
        t.down_devs = spec.vlans.iter().map(|v| v.name.clone()).collect();
    }
    t.up_devs.sort();
    t.up_devs.dedup();
    t.down_devs.sort();
    t
}

/// The table's name, its family's.
pub const TABLE: &str = "netdev u6e-shaper";

fn classid(t: u32) -> String {
    format!("{:x}:{:x}", t >> 16, t & 0xffff)
}

fn names(devs: &[String]) -> String {
    let quoted: Vec<String> = devs.iter().map(|d| format!("\"{d}\"")).collect();
    quoted.join(", ")
}

/// The nftables script that makes the table `t` (or no table, without a
/// rule), whatever was there: one transaction.
pub fn ruleset(t: &Tags) -> String {
    let mut s = format!("table {TABLE}\ndelete table {TABLE}\n");
    if t.clients.is_empty() && t.ssids.is_empty() {
        return s;
    }
    let hook = |devs: &[String]| {
        format!(
            "\t\ttype filter hook ingress devices = {{ {} }} priority 0; policy accept;\n",
            names(devs)
        )
    };
    s += &format!("table {TABLE} {{\n");
    if !t.up_devs.is_empty() {
        s += "\tchain up {\n";
        s += &hook(&t.up_devs);
        for (m, _, up) in &t.clients {
            s += &format!(
                "\t\tether saddr {} meta priority set {} accept\n",
                mac::format(*m),
                classid(*up)
            );
        }
        for (_, up, ports) in &t.ssids {
            s += &format!(
                "\t\tiifname {{ {} }} meta priority set {}\n",
                names(ports),
                classid(*up)
            );
        }
        s += "\t}\n";
    }
    if !t.down_devs.is_empty() {
        s += "\tchain down {\n";
        s += &hook(&t.down_devs);
        for (m, down, _) in &t.clients {
            s += &format!(
                "\t\tether daddr {} meta priority set {} accept\n",
                mac::format(*m),
                classid(*down)
            );
        }
        s += "\t}\n";
    }
    s + "}\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::tests::{nd, rate, spec};
    use u6e_proto::shaper::ClientSpec;

    const C1: [u8; 6] = [2, 0, 0, 0, 0, 1];

    fn lan() -> Netdev {
        nd(UPLINK, 2)
    }

    #[test]
    fn slots_stay_with_their_clients() {
        let mut s = spec();
        let more = |last| ClientSpec {
            mac: [2, 0, 0, 0, 0, last],
            rate: rate(Some(100), None),
            ssid: 0,
        };
        s.clients.extend([more(2), more(3)]);
        let a = Slots::default().assign(&s);
        assert_eq!(
            a.clients,
            vec![(C1, 0), ([2, 0, 0, 0, 0, 2], 1), ([2, 0, 0, 0, 0, 3], 2)]
        );
        // The first leaves: the others keep theirs, a newcomer takes the hole.
        s.clients.remove(0);
        s.clients.push(more(4));
        let b = a.assign(&s);
        assert_eq!(
            b.clients,
            vec![
                ([2, 0, 0, 0, 0, 2], 1),
                ([2, 0, 0, 0, 0, 3], 2),
                ([2, 0, 0, 0, 0, 4], 0)
            ]
        );
        // SSIDs are slotted only for an upload limit.
        assert!(b.ssids.is_empty());
        s.ssids[0].rate = rate(Some(1_000), Some(500));
        assert_eq!(b.assign(&s).ssids, vec![("ssid-a".into(), 0)]);
    }

    #[test]
    fn a_client_is_shaped_on_every_bss_of_its_ssid_and_the_uplink() {
        let s = spec();
        let slots = Slots::default().assign(&s);
        let p = targets(&s, &slots, &lan());
        assert_eq!(p.len(), 1);
        let c = &p[0];
        assert_eq!(c.target, LimitTarget::Client(C1));
        assert_eq!(
            c.trees,
            vec![
                (nd("wlan5", 10), DOWN),
                (nd("wlan6", 11), DOWN),
                (lan(), UP)
            ]
        );
        let class = |dev: &str, major, kbit| Class {
            dev: dev.into(),
            major,
            minor: 0x1000,
            kbit,
        };
        assert_eq!(
            c.classes,
            vec![
                class("wlan5", DOWN, 20_000),
                class("wlan6", DOWN, 20_000),
                class("lan", UP, 5_000)
            ]
        );
        assert!(c.defaults.is_empty());
    }

    #[test]
    fn one_direction_needs_only_its_trees() {
        let mut s = spec();
        s.clients[0].rate = rate(Some(20_000), None);
        let p = targets(&s, &Slots::default().assign(&s), &lan());
        assert!(p[0].trees.iter().all(|(_, m)| *m == DOWN));
        s.clients[0].rate = rate(None, Some(5_000));
        let p = targets(&s, &Slots::default().assign(&s), &lan());
        assert_eq!(p[0].trees, vec![(lan(), UP)]);
    }

    #[test]
    fn an_ssid_limits_its_default_class_and_its_own_upload_class() {
        let mut s = spec();
        s.ssids[0].rate = rate(Some(50_000), Some(10_000));
        let slots = Slots::default().assign(&s);
        let p = targets(&s, &slots, &lan());
        let ssid = &p[0];
        assert_eq!(ssid.target, LimitTarget::Ssid("ssid-a".into()));
        assert_eq!(
            ssid.defaults,
            vec![("wlan5".into(), 50_000), ("wlan6".into(), 50_000)]
        );
        assert_eq!(
            ssid.classes,
            vec![Class {
                dev: "lan".into(),
                major: UP,
                minor: 0x100,
                kbit: 10_000
            }]
        );
        assert_eq!(p[1].target, LimitTarget::Client(C1));
    }

    #[test]
    fn a_limited_client_is_tagged_both_ways_its_ssid_on_its_ports() {
        let mut s = spec();
        s.ssids[0].rate = rate(None, Some(10_000));
        s.clients[0].rate = rate(Some(20_000), None);
        let slots = Slots::default().assign(&s);
        let t = tags(&s, &slots, |_| true);
        // No upload limit of its own: its SSID's class.
        assert_eq!(t.clients, vec![(C1, 0x0001_1000, 0x0002_0100)]);
        assert_eq!(
            t.ssids,
            vec![(
                "ssid-a".into(),
                0x0002_0100,
                vec!["wlan5".into(), "wlan5.42".into(), "wlan6".into()]
            )]
        );
        assert_eq!(t.up_devs, ["wlan5", "wlan5.42", "wlan6"]);
        assert_eq!(t.down_devs, ["vlan42"]);
        // The SSID refused: the client's upload goes to the default.
        let t = tags(&s, &slots, |t| matches!(t, LimitTarget::Client(_)));
        assert_eq!(t.clients, vec![(C1, 0x0001_1000, 0x0002_ffff)]);
        assert!(t.ssids.is_empty());
        // Nothing in place: no table.
        let none = tags(&s, &slots, |_| false);
        assert_eq!(none, Tags::default());
        assert_eq!(
            ruleset(&none),
            "table netdev u6e-shaper\ndelete table netdev u6e-shaper\n"
        );
    }

    #[test]
    fn the_ruleset_replaces_the_table_whole() {
        let mut s = spec();
        s.ssids[0].rate = rate(None, Some(10_000));
        let slots = Slots::default().assign(&s);
        let want = "table netdev u6e-shaper
delete table netdev u6e-shaper
table netdev u6e-shaper {
\tchain up {
\t\ttype filter hook ingress devices = { \"wlan5\", \"wlan5.42\", \"wlan6\" } priority 0; policy accept;
\t\tether saddr 02:00:00:00:00:01 meta priority set 2:1000 accept
\t\tiifname { \"wlan5\", \"wlan5.42\", \"wlan6\" } meta priority set 2:100
\t}
\tchain down {
\t\ttype filter hook ingress devices = { \"vlan42\" } priority 0; policy accept;
\t\tether daddr 02:00:00:00:00:01 meta priority set 1:1000 accept
\t}
}
";
        assert_eq!(ruleset(&tags(&s, &slots, |_| true)), want);
    }

    /// The ruleset as nftables takes it, in a network namespace of the
    /// test's own with dummy netdevs of the AP's names. It needs
    /// CAP_SYS_ADMIN and CAP_NET_ADMIN, and nft; without them it says so and
    /// passes.
    #[test]
    fn nftables_takes_the_ruleset_and_takes_it_away() {
        use crate::host::{Host, System};
        use std::process::Command;
        let run = |args: &[&str]| Command::new(args[0]).args(&args[1..]).output();
        let made = std::thread::spawn(move || {
            // SAFETY: unshare affects this thread alone, which holds nothing else.
            if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
                return false;
            }
            for d in ["wlan5", "wlan5.42", "wlan6", "vlan42"] {
                let ok = run(&["ip", "link", "add", d, "type", "dummy"])
                    .is_ok_and(|o| o.status.success());
                assert!(ok, "ip link add {d}");
            }
            let mut s = spec();
            s.ssids[0].rate = rate(None, Some(10_000));
            let t = tags(&s, &Slots::default().assign(&s), |_| true);
            let mut h = System::default();
            if !h.nft.exists() {
                return false;
            }
            h.nft(&ruleset(&t)).unwrap();
            // Twice: the script replaces what is there.
            h.nft(&ruleset(&t)).unwrap();
            let listed = run(&["nft", "list", "table", "netdev", "u6e-shaper"]).unwrap();
            let listed = String::from_utf8(listed.stdout).unwrap();
            assert!(
                listed.contains("ether saddr 02:00:00:00:00:01 meta priority set 2:1000 accept"),
                "{listed}"
            );
            assert!(listed.contains("meta priority set 2:100"), "{listed}");
            h.nft(&ruleset(&Tags::default())).unwrap();
            let gone = run(&["nft", "list", "ruleset"]).unwrap();
            assert!(gone.stdout.is_empty());
            // A netdev that is not there is refused, with nft's reason.
            let mut bad = t.clone();
            bad.up_devs.push("wlan24".into());
            assert!(h.nft(&ruleset(&bad)).is_err());
            true
        });
        if !made.join().expect("the test passed") {
            eprintln!("skipped: no network namespace of its own, or no nft");
        }
    }
}
