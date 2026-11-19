//! A sync: the shaping in place made the spec's, one limit at a time, and
//! never half of one. The trees come first, each built whole or not at all
//! (the firmware refuses one past its interface shapers); a limit whose tree
//! was refused is refused with the firmware's reason, and so is one whose
//! class it refuses, its own classes taken back. Classes no limit wants go
//! before any is added (they free the firmware's nodes), trees no limit in
//! place uses go last, with them their classes. Then the packets' tags, as
//! one nftables transaction, and the connections whose tags changed are
//! decelerated, so ECM accelerates them again with the new ones.
//!
//! A tree is built only where none is: an existing tree's classes change in
//! place, which leaves its other classes' traffic alone. A netdev made again
//! (a new index) has lost its tree, so it is built again.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use u6e_proto::ecm::{DEFUNCT_BY_IFACE, DEFUNCT_BY_MAC};
use u6e_proto::mac;
use u6e_proto::msg::LimitTarget;
use u6e_proto::netdev::vap;
use u6e_proto::shaper::{Netdev, Outcome, Spec};

use crate::check;
use crate::host::Host;
use crate::plan::{
    self, Class, DEFAULT, DOWN, LINE_KBIT, Slots, TOP, Tags, TargetPlan, Tree, UP, UPLINK,
};

/// What is in place, as the last sync left it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub spec: Spec,
    pub slots: Slots,
    pub trees: Vec<Tree>,
    pub classes: Vec<Class>,
    pub tags: Tags,
    pub outcomes: Vec<Outcome>,
}

/// What a sync came to: the state it left, and whether it built the
/// uplink's tree (which the agent then confirms, or the sync is undone: a
/// tree there carries the agent's own link).
#[derive(Debug)]
pub struct Synced {
    pub state: State,
    pub built: bool,
}

/// Why a limit waits when the agent has no controller to confirm with.
pub const UPLINK_WAITS: &str = "the uplink's tree waits for the controller's link";

/// A class's rate arguments: rate and ceiling the same (a hard limit), the
/// burst 10 ms of it, between 4 and 64 KiB.
fn rate_args(kbit: u32) -> Vec<String> {
    let burst = (u64::from(kbit) * 1000 / 8 / 100).clamp(4096, 65_536);
    let (r, b) = (format!("{kbit}kbit"), burst.to_string());
    ["rate", &r, "burst", &b, "crate", &r, "cburst", &b]
        .map(String::from)
        .to_vec()
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).to_owned()).collect()
}

fn id(major: u16, minor: u16) -> String {
    format!("{major:x}:{minor:x}")
}

/// The leaf's handle under class `minor` of tree `major`: the default's
/// `<major>fff:`, a limit's its minor.
fn leaf(major: u16, minor: u16) -> String {
    if minor == DEFAULT {
        format!("{major:x}fff:")
    } else {
        format!("{minor:x}:")
    }
}

fn add_class<H: Host>(
    h: &mut H,
    dev: &str,
    major: u16,
    parent: &str,
    minor: u16,
    kbit: u32,
) -> Result<(), String> {
    let mut a = argv(&[
        "class",
        "add",
        "dev",
        dev,
        "parent",
        parent,
        "classid",
        &id(major, minor),
        "nsshtb",
    ]);
    a.extend(rate_args(kbit));
    h.tc(&a)?;
    let qdisc = if minor == DEFAULT {
        "nssfq_codel target 5ms interval 100ms set_default accel_mode 0"
    } else {
        "nsscodel target 5ms interval 100ms limit 1000 accel_mode 0"
    };
    let mut q = argv(&[
        "qdisc",
        "add",
        "dev",
        dev,
        "parent",
        &id(major, minor),
        "handle",
        &leaf(major, minor),
    ]);
    q.extend(qdisc.split(' ').map(String::from));
    if let Err(e) = h.tc(&q) {
        let _ = h.tc(&argv(&[
            "class",
            "del",
            "dev",
            dev,
            "classid",
            &id(major, minor),
        ]));
        return Err(e);
    }
    Ok(())
}

fn del_class<H: Host>(h: &mut H, c: &Class) -> Result<(), String> {
    let cid = id(c.major, c.minor);
    h.tc(&argv(&[
        "qdisc",
        "del",
        "dev",
        &c.dev,
        "parent",
        &cid,
        "handle",
        &leaf(c.major, c.minor),
    ]))?;
    h.tc(&argv(&["class", "del", "dev", &c.dev, "classid", &cid]))
        .map(drop)
}

fn change_class<H: Host>(
    h: &mut H,
    dev: &str,
    major: u16,
    minor: u16,
    kbit: u32,
) -> Result<(), String> {
    let mut a = argv(&[
        "class",
        "change",
        "dev",
        dev,
        "parent",
        &id(major, TOP),
        "classid",
        &id(major, minor),
        "nsshtb",
    ]);
    a.extend(rate_args(kbit));
    h.tc(&a).map(drop)
}

fn del_root<H: Host>(h: &mut H, dev: &str) -> Result<(), String> {
    h.tc(&argv(&["qdisc", "del", "dev", dev, "root"])).map(drop)
}

/// Whether `dev`'s root is an NSS qdisc.
fn nss_root<H: Host>(h: &mut H, dev: &str) -> bool {
    h.tc(&argv(&["qdisc", "show", "dev", dev, "root"]))
        .is_ok_and(|out| out.starts_with("qdisc nss"))
}

/// Builds the tree `major:` on `dev` whole: root, line-rate class, default
/// class and its leaf; nothing of it stays when a step is refused.
fn build<H: Host>(h: &mut H, dev: &str, major: u16) -> Result<(), String> {
    if nss_root(h, dev) {
        // A tree no state knows of (the state's file was lost): made afresh.
        del_root(h, dev)?;
    }
    let root = argv(&[
        "qdisc",
        "add",
        "dev",
        dev,
        "root",
        "handle",
        &format!("{major:x}:"),
        "nsshtb",
        "accel_mode",
        "0",
    ]);
    h.tc(&root).map_err(|e| {
        format!(
            "the NSS firmware took no shaper on {dev} ({e}); it has one interface shaper \
             unless the image gives it memory for more (NSS_SHAPERS)"
        )
    })?;
    let rest = add_class(h, dev, major, &format!("{major:x}:"), TOP, LINE_KBIT)
        .and_then(|()| add_class(h, dev, major, &id(major, TOP), DEFAULT, LINE_KBIT));
    if let Err(e) = rest {
        let _ = del_root(h, dev);
        return Err(format!("the NSS firmware refused {dev}'s tree: {e}"));
    }
    Ok(())
}

/// The bytes `tc` counted for class `major:minor` of `dev`.
fn class_bytes<H: Host>(h: &mut H, dev: &str, major: u16, minor: u16) -> u64 {
    let out = h.tc(&argv(&[
        "-s",
        "class",
        "show",
        "dev",
        dev,
        "classid",
        &id(major, minor),
    ]));
    let out = out.unwrap_or_default();
    let sent = out.split("Sent ").nth(1).and_then(|r| r.split(' ').next());
    sent.and_then(|n| n.parse().ok()).unwrap_or(0)
}

/// What a limit in place is shaped on, for its outcome.
fn where_(p: &TargetPlan) -> String {
    let devs = |major| {
        let d: Vec<&str> = p
            .trees
            .iter()
            .filter(|(_, m)| *m == major)
            .map(|(d, _)| d.name.as_str())
            .collect();
        d.join(", ")
    };
    let (down, up) = (devs(DOWN), devs(UP));
    match (down.is_empty(), up.is_empty()) {
        (false, false) => format!("download on {down}, upload on {up}"),
        (false, true) => format!("download on {down}"),
        _ => format!("upload on {up}"),
    }
}

/// The bytes the classes of a limit in place passed, per direction: a
/// client's own classes; an SSID's default classes (its clients without a
/// limit of their own) and its upload class.
fn counted<H: Host>(h: &mut H, p: &TargetPlan) -> (u64, u64) {
    let (mut down, mut up) = (0, 0);
    for (dev, _) in &p.defaults {
        down += class_bytes(h, dev, DOWN, DEFAULT);
    }
    for c in &p.classes {
        let n = class_bytes(h, &c.dev, c.major, c.minor);
        if c.major == DOWN { down += n } else { up += n }
    }
    (down, up)
}

/// Each limit's outcome, its bytes counted again.
pub fn counters<H: Host>(h: &mut H, state: &State) -> Vec<Outcome> {
    let uplink = uplink(h);
    let plans = plan::targets(&state.spec, &state.slots, &uplink);
    let mut out = state.outcomes.clone();
    for o in out.iter_mut().filter(|o| o.ok) {
        if let Some(p) = plans.iter().find(|p| p.target == o.target) {
            (o.down_bytes, o.up_bytes) = counted(h, p);
        }
    }
    out
}

fn uplink<H: Host>(h: &mut H) -> Netdev {
    let found = h.netdevs().into_iter().find(|d| d.name == UPLINK);
    found.unwrap_or(Netdev {
        name: UPLINK.into(),
        ifindex: 0,
    })
}

fn same(a: &Class, b: &Class) -> bool {
    a.dev == b.dev && a.major == b.major && a.minor == b.minor
}

/// One limit's classes and default rates put in place, or none of them.
fn place<H: Host>(
    h: &mut H,
    p: &TargetPlan,
    classes: &mut Vec<Class>,
    trees: &mut [Tree],
) -> Result<(), String> {
    let mut added: Vec<Class> = Vec::new();
    let mut changed: Vec<(usize, u32)> = Vec::new();
    let mut defaults: Vec<(usize, u32)> = Vec::new();
    let mut result = Ok(());
    for c in &p.classes {
        let step = match classes.iter().position(|x| same(x, c)) {
            Some(i) if classes[i].kbit == c.kbit => Ok(()),
            Some(i) => change_class(h, &c.dev, c.major, c.minor, c.kbit).map(|()| {
                changed.push((i, classes[i].kbit));
                classes[i].kbit = c.kbit;
            }),
            None => add_class(h, &c.dev, c.major, &id(c.major, TOP), c.minor, c.kbit)
                .map(|()| added.push(c.clone())),
        };
        if let Err(e) = step {
            result = Err(format!(
                "the NSS firmware refused a class on {}: {e}",
                c.dev
            ));
            break;
        }
    }
    if result.is_ok() {
        for (dev, kbit) in &p.defaults {
            let Some(i) = trees
                .iter()
                .position(|t| t.dev.name == *dev && t.major == DOWN)
            else {
                continue;
            };
            if trees[i].default_kbit == *kbit {
                continue;
            }
            if let Err(e) = change_class(h, dev, DOWN, DEFAULT, *kbit) {
                result = Err(format!(
                    "the NSS firmware refused {dev}'s default class: {e}"
                ));
                break;
            }
            defaults.push((i, trees[i].default_kbit));
            trees[i].default_kbit = *kbit;
        }
    }
    if result.is_err() {
        for c in &added {
            let _ = del_class(h, c);
        }
        for (i, kbit) in changed {
            let c = classes[i].clone();
            let _ = change_class(h, &c.dev, c.major, c.minor, kbit);
            classes[i].kbit = kbit;
        }
        for (i, kbit) in defaults {
            let _ = change_class(h, &trees[i].dev.name, DOWN, DEFAULT, kbit);
            trees[i].default_kbit = kbit;
        }
    } else {
        classes.extend(added);
    }
    result
}

/// Makes the shaping `spec`'s, from `cur`.
/// Makes the shaping `spec`'s; `away`, the agent has no controller to
/// confirm with, so the uplink's tree is not built (its limits wait).
pub fn sync<H: Host>(h: &mut H, cur: &State, spec: &Spec, away: bool) -> Result<Synced, String> {
    check::check(spec)?;
    let devs = h.netdevs();
    let exists = |n: &Netdev| devs.contains(n);
    // Ports and VLANs that went since the agent looked are left out.
    let mut spec = spec.clone();
    for s in &mut spec.ssids {
        s.ports.retain(|p| exists(p));
    }
    spec.vlans.retain(|v| exists(v));
    let slots = cur.slots.assign(&spec);
    let uplink = devs.iter().find(|d| d.name == UPLINK).cloned();
    let uplink = uplink.unwrap_or(Netdev {
        name: UPLINK.into(),
        ifindex: 0,
    });
    let plans = plan::targets(&spec, &slots, &uplink);
    let mut refused: BTreeMap<LimitTarget, String> = BTreeMap::new();
    for p in &plans {
        if let Some((d, _)) = p.trees.iter().find(|(d, _)| !exists(d)) {
            refused.insert(p.target.clone(), format!("{} is not on the AP", d.name));
        }
    }

    // The trees, those in place kept.
    let mut wanted: Vec<(Netdev, u16)> = Vec::new();
    for p in plans.iter().filter(|p| !refused.contains_key(&p.target)) {
        for t in &p.trees {
            if !wanted.contains(t) {
                wanted.push(t.clone());
            }
        }
    }
    let mut trees: Vec<Tree> = Vec::new();
    let mut built: Vec<(String, u16)> = Vec::new();
    for (dev, major) in wanted {
        if let Some(t) = cur.trees.iter().find(|t| t.dev == dev && t.major == major) {
            trees.push(t.clone());
            continue;
        }
        if away && dev.name == UPLINK {
            for p in plans
                .iter()
                .filter(|p| p.trees.contains(&(dev.clone(), major)))
            {
                refused
                    .entry(p.target.clone())
                    .or_insert_with(|| UPLINK_WAITS.into());
            }
            continue;
        }
        match build(h, &dev.name, major) {
            Ok(()) => {
                built.push((dev.name.clone(), major));
                trees.push(Tree {
                    dev,
                    major,
                    default_kbit: LINE_KBIT,
                });
            }
            Err(e) => {
                for p in plans
                    .iter()
                    .filter(|p| p.trees.contains(&(dev.clone(), major)))
                {
                    refused.entry(p.target.clone()).or_insert_with(|| e.clone());
                }
            }
        }
    }

    // The classes of the trees kept; those no limit wants go first.
    let on_tree = |c: &Class, trees: &[Tree]| {
        trees
            .iter()
            .any(|t| t.dev.name == c.dev && t.major == c.major)
    };
    let kept: Vec<Tree> = trees
        .iter()
        .filter(|t| cur.trees.contains(t))
        .cloned()
        .collect();
    let mut classes: Vec<Class> = cur
        .classes
        .iter()
        .filter(|c| on_tree(c, &kept))
        .cloned()
        .collect();
    let want: Vec<Class> = plans
        .iter()
        .filter(|p| !refused.contains_key(&p.target))
        .flat_map(|p| p.classes.clone())
        .collect();
    let mut stale = Vec::new();
    classes.retain(|c| {
        let keep = want.iter().any(|w| same(w, c));
        if !keep {
            stale.push(c.clone());
        }
        keep
    });
    for c in &stale {
        if let Err(e) = del_class(h, c) {
            eprintln!("u6e-shaper: {} class {}: {e}", c.dev, id(c.major, c.minor));
        }
    }
    for p in &plans {
        if !refused.contains_key(&p.target)
            && let Err(e) = place(h, p, &mut classes, &mut trees)
        {
            refused.insert(p.target.clone(), e);
        }
    }
    // A default class no SSID in place limits runs at the line's rate again.
    let limited: Vec<String> = plans
        .iter()
        .filter(|p| !refused.contains_key(&p.target))
        .flat_map(|p| p.defaults.iter().map(|(d, _)| d.clone()))
        .collect();
    for t in trees
        .iter_mut()
        .filter(|t| t.major == DOWN && t.default_kbit != LINE_KBIT)
    {
        if !limited.contains(&t.dev.name) {
            match change_class(h, &t.dev.name, DOWN, DEFAULT, LINE_KBIT) {
                Ok(()) => t.default_kbit = LINE_KBIT,
                Err(e) => eprintln!("u6e-shaper: {}'s default class: {e}", t.dev.name),
            }
        }
    }

    // The packets' tags.
    let ok = |t: &LimitTarget| !refused.contains_key(t);
    let mut tags = plan::tags(&spec, &slots, ok);
    if tags != cur.tags
        && let Err(e) = h.nft(&plan::ruleset(&tags))
    {
        let why = format!("nftables refused the tags: {e}");
        for p in &plans {
            refused
                .entry(p.target.clone())
                .or_insert_with(|| why.clone());
        }
        tags = cur.tags.clone();
    }

    // Trees no limit in place uses, those of before that went too.
    let used: Vec<(String, u16)> = plans
        .iter()
        .filter(|p| !refused.contains_key(&p.target))
        .flat_map(|p| p.trees.iter().map(|(d, m)| (d.name.clone(), *m)))
        .collect();
    let gone: Vec<Tree> = trees
        .iter()
        .filter(|t| !used.contains(&(t.dev.name.clone(), t.major)))
        .cloned()
        .chain(
            cur.trees
                .iter()
                .filter(|t| !trees.contains(t) && exists(&t.dev))
                .cloned(),
        )
        .collect();
    for t in &gone {
        if let Err(e) = del_root(h, &t.dev.name) {
            eprintln!("u6e-shaper: {}'s tree: {e}", t.dev.name);
        }
    }
    trees.retain(|t| used.contains(&(t.dev.name.clone(), t.major)));
    classes.retain(|c| on_tree(c, &trees));
    built.retain(|b| trees.iter().any(|t| (t.dev.name.clone(), t.major) == *b));

    decelerate(h, &cur.tags, &tags);

    let mut outcomes = Vec::new();
    for p in &plans {
        let o = match refused.get(&p.target) {
            Some(why) => Outcome {
                target: p.target.clone(),
                ok: false,
                detail: why.clone(),
                down_bytes: 0,
                up_bytes: 0,
            },
            None => {
                let (down_bytes, up_bytes) = counted(h, p);
                Outcome {
                    target: p.target.clone(),
                    ok: true,
                    detail: where_(p),
                    down_bytes,
                    up_bytes,
                }
            }
        };
        outcomes.push(o);
    }
    let state = State {
        spec,
        slots,
        trees,
        classes,
        tags,
        outcomes,
    };
    Ok(Synced {
        state,
        built: built.iter().any(|(d, _)| d == UPLINK),
    })
}

/// Decelerates the connections whose tags changed from `old` to `new`: a
/// client's by its MAC, an SSID's by each of its ports.
fn decelerate<H: Host>(h: &mut H, old: &Tags, new: &Tags) {
    let mut macs: Vec<[u8; 6]> = Vec::new();
    for (m, down, up) in &new.clients {
        if !old.clients.contains(&(*m, *down, *up)) {
            macs.push(*m);
        }
    }
    for (m, ..) in &old.clients {
        if !new.clients.iter().any(|(n, ..)| n == m) {
            macs.push(*m);
        }
    }
    let mut ports: Vec<&String> = Vec::new();
    for (name, up, p) in &new.ssids {
        if !old.ssids.iter().any(|(n, u, _)| n == name && u == up) {
            ports.extend(p);
        }
    }
    for (name, _, p) in &old.ssids {
        if !new.ssids.iter().any(|(n, ..)| n == name) {
            ports.extend(p);
        }
    }
    for m in macs {
        if let Err(e) = h.sysctl(DEFUNCT_BY_MAC, &format!("{}\n", mac::format(m))) {
            eprintln!("u6e-shaper: {e}");
        }
    }
    ports.sort();
    ports.dedup();
    for p in ports {
        // A port that went has no connection left to decelerate.
        let _ = h.sysctl(DEFUNCT_BY_IFACE, &format!("{p}\n"));
    }
}

/// Takes every shaper and tag down, whatever any state says: the NSS roots
/// of the uplink and of every BSS, and the table.
pub fn teardown<H: Host>(h: &mut H) {
    let script = plan::ruleset(&Tags::default());
    if let Err(e) = h.nft(&script) {
        eprintln!("u6e-shaper: the tags' table: {e}");
    }
    let devs = h.netdevs();
    for d in devs.iter().filter(|d| d.name == UPLINK || vap(&d.name)) {
        if nss_root(h, &d.name)
            && let Err(e) = del_root(h, &d.name)
        {
            eprintln!("u6e-shaper: {}'s tree: {e}", d.name);
        }
    }
}

/// Puts back the shaping of `prev` from nothing: every tree and the tags
/// are taken down, then `prev`'s spec is synced as on an empty AP, so what
/// a sync that was not confirmed, or that the helper died in, did is gone
/// whatever it was. Every limit lapses meanwhile, not only those that sync
/// changed, until the trees are built again.
pub fn revert<H: Host>(h: &mut H, prev: &State) -> State {
    teardown(h);
    let from = State {
        slots: prev.slots.clone(),
        ..State::default()
    };
    match sync(h, &from, &prev.spec, false) {
        Ok(s) => s.state,
        Err(e) => {
            eprintln!("u6e-shaper: the shaping before could not be put back: {e}");
            State::default()
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::check::tests::{nd, rate, spec};
    use std::collections::BTreeSet;

    /// The AP as the tests see it: the netdevs, the trees and classes `tc`
    /// made, the table, and what was decelerated; `refuse` names what the
    /// firmware refuses (a root on a netdev, a class id).
    #[derive(Default)]
    pub struct Fake {
        pub devs: Vec<Netdev>,
        pub roots: BTreeSet<String>,
        pub classes: BTreeSet<(String, String)>,
        pub table: Option<String>,
        pub decel: Vec<String>,
        pub refuse: Vec<String>,
        pub log: Vec<String>,
        pub nft_fails: bool,
    }

    impl Fake {
        pub fn new() -> Self {
            let devs = ["lan", "wlan5", "wlan5.42", "wlan6", "vlan42"]
                .iter()
                .zip([2, 10, 20, 11, 30])
                .map(|(n, i)| nd(n, i))
                .collect();
            Fake {
                devs,
                ..Fake::default()
            }
        }
    }

    impl Host for Fake {
        fn tc(&mut self, a: &[String]) -> Result<String, String> {
            self.log.push(a.join(" "));
            let s: Vec<&str> = a.iter().map(String::as_str).collect();
            match s[..] {
                ["qdisc", "show", "dev", d, "root"] => Ok(if self.roots.contains(d) {
                    "qdisc nsshtb 1: root refcnt 2 \n".to_owned()
                } else {
                    "qdisc noqueue 0: root refcnt 2 \n".into()
                }),
                ["qdisc", "add", "dev", d, "root", ..] => {
                    if self.refuse.iter().any(|r| r == d) || self.roots.contains(d) {
                        return Err("RTNETLINK answers: Invalid argument".into());
                    }
                    self.roots.insert(d.into());
                    Ok(String::new())
                }
                ["qdisc", "del", "dev", d, "root"] => {
                    self.roots.remove(d);
                    self.classes.retain(|(dev, _)| dev != d);
                    Ok(String::new())
                }
                ["class", "add", "dev", d, "parent", _, "classid", c, ..] => {
                    if self.refuse.iter().any(|r| r == c) {
                        return Err("RTNETLINK answers: No space left on device".into());
                    }
                    assert!(self.roots.contains(d), "a class on {d} without a tree");
                    self.classes.insert((d.into(), c.into()));
                    Ok(String::new())
                }
                ["class", "del", "dev", d, "classid", c] => {
                    self.classes.remove(&(d.into(), c.into()));
                    Ok(String::new())
                }
                ["class", "change", "dev", d, "parent", _, "classid", c, ..] => {
                    assert!(
                        self.classes.contains(&(d.into(), c.into())),
                        "change of no class"
                    );
                    Ok(String::new())
                }
                ["-s", "class", "show", "dev", d, "classid", c] => {
                    Ok(if self.classes.contains(&(d.into(), c.into())) {
                        format!(
                            "class nsshtb {c} root rate 1Kbit\n Sent 1234 bytes 9 pkt (dropped 0, overlimits 0 requeues 0)\n"
                        )
                    } else {
                        String::new()
                    })
                }
                ["qdisc", "add", ..] | ["qdisc", "del", ..] => Ok(String::new()),
                _ => panic!("tc {s:?}"),
            }
        }

        fn nft(&mut self, script: &str) -> Result<(), String> {
            if self.nft_fails {
                return Err("Error: syntax error".into());
            }
            let body = script
                .split_once("delete table netdev u6e-shaper\n")
                .unwrap()
                .1;
            self.table = (!body.is_empty()).then(|| body.to_owned());
            Ok(())
        }

        fn sysctl(&mut self, path: &str, value: &str) -> Result<(), String> {
            assert!(value.ends_with('\n'), "ECM drops the last byte");
            self.decel.push(format!(
                "{} {}",
                path.rsplit('/').next().unwrap(),
                value.trim()
            ));
            Ok(())
        }

        fn netdevs(&mut self) -> Vec<Netdev> {
            self.devs.clone()
        }
    }

    const C1: &str = "02:00:00:00:00:01";

    fn synced(h: &mut Fake, cur: &State, s: &Spec) -> Synced {
        sync(h, cur, s, false).unwrap()
    }

    #[test]
    fn a_client_limit_builds_its_trees_classes_and_tags() {
        let mut h = Fake::new();
        let out = synced(&mut h, &State::default(), &spec());
        assert!(out.built);
        assert_eq!(
            h.roots,
            BTreeSet::from(["lan".into(), "wlan5".into(), "wlan6".into()])
        );
        let classes: BTreeSet<_> = h.classes.iter().map(|(d, c)| format!("{d} {c}")).collect();
        let want = [
            "lan 2:1",
            "lan 2:ffff",
            "lan 2:1000",
            "wlan5 1:1",
            "wlan5 1:ffff",
            "wlan5 1:1000",
            "wlan6 1:1",
            "wlan6 1:ffff",
            "wlan6 1:1000",
        ];
        assert_eq!(classes, want.iter().map(|s| (*s).to_owned()).collect());
        let table = h.table.as_deref().unwrap();
        assert!(table.contains(&format!("ether saddr {C1} meta priority set 2:1000 accept")));
        assert!(table.contains(&format!("ether daddr {C1} meta priority set 1:1000 accept")));
        assert_eq!(h.decel, [format!("defunct_by_mac {C1}")]);
        let o = &out.state.outcomes[0];
        assert!(o.ok, "{o:?}");
        assert_eq!(o.detail, "download on wlan5, wlan6, upload on lan");
        assert_eq!((o.down_bytes, o.up_bytes), (2468, 1234));
        // The same spec again changes nothing.
        h.log.clear();
        h.decel.clear();
        let again = synced(&mut h, &out.state, &spec());
        assert!(!again.built);
        assert!(h.log.iter().all(|l| l.starts_with("-s ")), "{:?}", h.log);
        assert!(h.decel.is_empty());
        assert_eq!(again.state.trees, out.state.trees);
    }

    #[test]
    fn a_rate_change_changes_the_class_in_place() {
        let mut h = Fake::new();
        let first = synced(&mut h, &State::default(), &spec());
        let mut s = spec();
        s.clients[0].rate = rate(Some(30_000), Some(5_000));
        h.log.clear();
        let out = synced(&mut h, &first.state, &s);
        assert!(!out.built);
        let changes: Vec<&String> = h
            .log
            .iter()
            .filter(|l| l.starts_with("class change"))
            .collect();
        assert_eq!(changes.len(), 2, "{:?}", h.log);
        assert!(
            !h.log
                .iter()
                .any(|l| l.contains(" add ") || l.contains(" del "))
        );
        // Same tags: nothing to decelerate.
        assert_eq!(h.decel.len(), 1);
    }

    #[test]
    fn a_refused_uplink_tree_refuses_only_the_limits_that_need_it() {
        let mut h = Fake::new();
        h.refuse.push("lan".into());
        let mut s = spec();
        s.clients.push(u6e_proto::shaper::ClientSpec {
            mac: [2, 0, 0, 0, 0, 2],
            rate: rate(Some(1_000), None),
            ssid: 0,
        });
        let out = synced(&mut h, &State::default(), &s);
        let [both, down] = &out.state.outcomes[..] else {
            panic!()
        };
        assert!(!both.ok && both.detail.contains("NSS_SHAPERS"), "{both:?}");
        assert!(down.ok, "{down:?}");
        assert!(!h.roots.contains("lan"));
        // The refused client has no class and no tag.
        assert!(!h.classes.iter().any(|(_, c)| c == "1:1000"));
        let table = h.table.unwrap();
        assert!(!table.contains(C1) && table.contains("02:00:00:00:00:02"));
    }

    #[test]
    fn a_refused_class_takes_its_limits_other_classes_back() {
        let mut h = Fake::new();
        h.refuse.push("2:1000".into());
        let out = synced(&mut h, &State::default(), &spec());
        assert!(!out.state.outcomes[0].ok);
        assert!(
            h.classes.iter().all(|(_, c)| !c.ends_with(":1000")),
            "{:?}",
            h.classes
        );
        // No limit uses a tree: none stays.
        assert!(h.roots.is_empty(), "{:?}", h.roots);
        assert!(!out.built && out.state.trees.is_empty());
        assert_eq!(h.table, None);
    }

    #[test]
    fn a_netdev_made_again_gets_its_tree_again() {
        let mut h = Fake::new();
        let first = synced(&mut h, &State::default(), &spec());
        // wlan5 came back with a new index, without its tree.
        h.roots.remove("wlan5");
        h.classes.retain(|(d, _)| d != "wlan5");
        h.devs.retain(|d| d.name != "wlan5");
        h.devs.push(nd("wlan5", 40));
        let mut s = spec();
        s.ssids[0].vaps[0].ifindex = 40;
        s.ssids[0].ports[0].ifindex = 40;
        let out = synced(&mut h, &first.state, &s);
        // A BSS's tree carries no link of the agent's: nothing to confirm.
        assert!(!out.built && out.state.outcomes[0].ok);
        assert!(
            h.roots.contains("wlan5") && h.classes.contains(&("wlan5".into(), "1:1000".into()))
        );
    }

    #[test]
    fn away_no_uplink_tree_is_built_and_its_limits_wait() {
        let mut h = Fake::new();
        let out = sync(&mut h, &State::default(), &spec(), true).unwrap();
        assert!(!out.built && h.roots.is_empty(), "{:?}", h.roots);
        let o = &out.state.outcomes[0];
        assert!(!o.ok && o.detail == UPLINK_WAITS, "{o:?}");
        // A download limit needs none: it is made away too.
        let mut down = spec();
        down.clients[0].rate = rate(Some(30_000), None);
        let out = sync(&mut h, &out.state, &down, true).unwrap();
        assert!(!out.built && out.state.outcomes[0].ok);
        assert!(h.roots.contains("wlan5") && !h.roots.contains("lan"));
        // With the controller there, the uplink's is built, to be confirmed;
        // away again, the tree in place is kept and its classes changed.
        let out = synced(&mut h, &out.state, &spec());
        assert!(out.built && h.roots.contains("lan") && out.state.outcomes[0].ok);
        let mut slower = spec();
        slower.clients[0].rate = rate(Some(30_000), Some(1_000));
        let out = sync(&mut h, &out.state, &slower, true).unwrap();
        assert!(!out.built && out.state.outcomes[0].ok && h.roots.contains("lan"));
    }

    #[test]
    fn the_last_limit_gone_takes_everything_down() {
        let mut h = Fake::new();
        let first = synced(&mut h, &State::default(), &spec());
        h.decel.clear();
        let out = synced(&mut h, &first.state, &Spec::default());
        assert!(h.roots.is_empty() && h.classes.is_empty() && h.table.is_none());
        assert_eq!(h.decel, [format!("defunct_by_mac {C1}")]);
        assert_eq!(out.state.trees, Vec::new());
    }

    #[test]
    fn an_ssid_limit_sets_its_default_classes_and_tags_its_ports() {
        let mut h = Fake::new();
        let mut s = spec();
        s.clients.clear();
        s.ssids[0].rate = rate(Some(50_000), Some(10_000));
        let out = synced(&mut h, &State::default(), &s);
        assert!(out.state.outcomes[0].ok, "{:?}", out.state.outcomes);
        assert!(
            out.state
                .trees
                .iter()
                .filter(|t| t.major == DOWN)
                .all(|t| t.default_kbit == 50_000)
        );
        assert!(h.classes.contains(&("lan".into(), "2:100".into())));
        let table = h.table.clone().unwrap();
        assert!(
            table
                .contains("iifname { \"wlan5\", \"wlan5.42\", \"wlan6\" } meta priority set 2:100")
        );
        let mut ifaces: Vec<&String> = h.decel.iter().collect();
        ifaces.sort();
        assert_eq!(
            ifaces,
            [
                "defunct_by_iface wlan5",
                "defunct_by_iface wlan5.42",
                "defunct_by_iface wlan6"
            ]
        );
        // Its download limit dropped: the default classes run at the line's rate.
        s.ssids[0].rate = rate(None, Some(10_000));
        h.log.clear();
        let out = synced(&mut h, &out.state, &s);
        assert!(h.roots.contains("lan") && !h.roots.contains("wlan5"));
        assert!(out.state.trees.iter().all(|t| t.major == UP));
    }

    #[test]
    fn a_failed_table_refuses_and_keeps_the_old_tags() {
        let mut h = Fake::new();
        h.nft_fails = true;
        let out = synced(&mut h, &State::default(), &spec());
        assert!(
            out.state
                .outcomes
                .iter()
                .all(|o| !o.ok && o.detail.contains("nftables"))
        );
        assert_eq!(out.state.tags, Tags::default());
        assert!(h.roots.is_empty(), "nothing is left that tags nothing");
    }

    #[test]
    fn a_vanished_port_is_left_out_and_a_vanished_bss_refuses() {
        let mut h = Fake::new();
        h.devs.retain(|d| d.name != "wlan5.42");
        let out = synced(&mut h, &State::default(), &spec());
        assert!(out.state.outcomes[0].ok);
        assert!(!h.table.clone().unwrap().contains("wlan5.42"));
        h.devs.retain(|d| d.name != "wlan6");
        let out = synced(&mut h, &State::default(), &spec());
        assert!(!out.state.outcomes[0].ok && out.state.outcomes[0].detail.contains("wlan6"));
    }

    #[test]
    fn revert_puts_back_the_state_before_from_nothing() {
        let mut h = Fake::new();
        let mut s = spec();
        s.clients[0].rate = rate(Some(20_000), None);
        let before = synced(&mut h, &State::default(), &s).state;
        let (roots, classes, table) = (h.roots.clone(), h.classes.clone(), h.table.clone());
        let after = synced(&mut h, &before, &spec());
        assert!(after.built && h.roots.contains("lan"));
        // A tree no state knows of is taken down too.
        h.roots.insert("wlan24".into());
        h.devs.push(nd("wlan24", 50));
        let back = revert(&mut h, &before);
        assert_eq!(
            (h.roots.clone(), h.classes.clone(), h.table.clone()),
            (roots, classes, table)
        );
        assert_eq!(back.slots, before.slots);
        assert_eq!(back.tags, before.tags);
    }

    #[test]
    fn a_bad_spec_runs_nothing() {
        let mut h = Fake::new();
        let mut s = spec();
        s.ssids[0].ports.push(nd("lan", 2));
        assert!(sync(&mut h, &State::default(), &s, false).is_err());
        assert!(h.log.is_empty() && h.decel.is_empty() && h.table.is_none());
    }
}
