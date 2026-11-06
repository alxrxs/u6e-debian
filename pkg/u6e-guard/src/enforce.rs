//! Enforcement: the Wi-Fi ports of the VLANs the guards enforce on get an
//! ingress qdisc on one shared filter block (the kernel has no bridge
//! nftables), whose filters drop exactly what `rules` reports, never a
//! client:
//!
//! - chain 0: any VLAN-tagged frame; DHCP and DHCPv6 server messages; the
//!   router advertisements of the clients that sent a rogue one in the last
//!   hour, and every advertisement but one with router lifetime 0 and no
//!   extension header (u32 reads the field; flower sees through extension
//!   headers); a DHCP client's message always passes; ARP goes on to chain
//!   1, IPv4 to chain 3;
//! - chain 1: ARP whose sender address is bound, from another MAC than its
//!   own (an address two MACs hold is either's);
//! - chain 2: ARP from a MAC that holds an address naming another sender, or
//!   naming as its sender a MAC that holds one;
//! - chain 3: IPv4 from a bound address, from another MAC than its own.
//!
//! Each guard's drops go through one standalone, counted action, so the
//! counts outlive the filters. A binding's filters are added and removed
//! with it, each by its own handle, the passes before the drops. Nothing is
//! left behind: `clear` (the unit's first and last step) removes the
//! guards' qdiscs and actions, and fails loudly when it cannot.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use u6e_proto::mac;
use u6e_proto::msg::{Binding, Guard};

use crate::ports::Port;

/// The shared block of the guards' filters.
pub const BLOCK: u32 = 64;
/// Each guard's counted drop action.
const ACTIONS: [(Guard, u32); 5] = [
    (Guard::Arp, 64_001),
    (Guard::Dhcp, 64_002),
    (Guard::Ra, 64_003),
    (Guard::Source, 64_004),
    (Guard::Tag, 64_005),
];

fn drop_by(g: Guard) -> String {
    let index = ACTIONS.iter().find(|(a, _)| *a == g).map_or(0, |(_, i)| *i);
    format!("action gact index {index}")
}

/// A filter of the block: its protocol, chain, priority and handle.
fn filter(proto: &str, chain: u8, prio: u8, handle: u32) -> String {
    format!("block {BLOCK} protocol {proto} chain {chain} prio {prio} handle {handle}")
}

/// The filters that never change.
fn fixed() -> Vec<String> {
    let f = |proto: &str, chain: u8, prio: u8, rest: &str| {
        format!("filter add block {BLOCK} protocol {proto} chain {chain} prio {prio} {rest}")
    };
    let lifetime_0 =
        "u32 match u8 58 0xff at 6 match u8 134 0xff at 40 match u16 0 0xffff at 46 action ok";
    vec![
        f("802.1q", 0, 1, &format!("matchall {}", drop_by(Guard::Tag))),
        f(
            "802.1ad",
            0,
            2,
            &format!("matchall {}", drop_by(Guard::Tag)),
        ),
        f(
            "ip",
            0,
            3,
            &format!(
                "flower ip_proto udp src_port 67 dst_port 68 {}",
                drop_by(Guard::Dhcp)
            ),
        ),
        f(
            "ipv6",
            0,
            4,
            &format!("flower ip_proto udp src_port 547 {}", drop_by(Guard::Dhcp)),
        ),
        f("ipv6", 0, 7, lifetime_0),
        f(
            "ipv6",
            0,
            8,
            &format!("flower ip_proto icmpv6 type 134 {}", drop_by(Guard::Ra)),
        ),
        f(
            "ip",
            0,
            9,
            "flower ip_proto udp src_port 68 dst_port 67 action ok",
        ),
        f("arp", 0, 10, "matchall action goto chain 1"),
        f("ip", 0, 11, "matchall action goto chain 3"),
        f("arp", 1, 3, "matchall action goto chain 2"),
    ]
}

/// What the block holds beyond its fixed filters, each with its handle.
#[derive(Debug, Default, Clone, PartialEq)]
struct Held {
    pairs: BTreeMap<([u8; 6], Ipv4Addr), u32>,
    ips: BTreeMap<Ipv4Addr, u32>,
    macs: BTreeMap<[u8; 6], u32>,
    ra: BTreeMap<[u8; 6], u32>,
}

/// The lines that add, or (`add` false) delete, the filters of one key.
fn pair_lines(add: bool, (m, ip): ([u8; 6], Ipv4Addr), h: u32) -> Vec<String> {
    let m = mac::format(m);
    if add {
        vec![
            format!(
                "filter add {} flower src_mac {m} arp_sip {ip} action goto chain 2",
                filter("arp", 1, 1, h)
            ),
            format!(
                "filter add {} flower src_mac {m} src_ip {ip} action ok",
                filter("ip", 3, 1, h)
            ),
        ]
    } else {
        vec![
            format!("filter del {} flower", filter("arp", 1, 1, h)),
            format!("filter del {} flower", filter("ip", 3, 1, h)),
        ]
    }
}

fn ip_lines(add: bool, ip: Ipv4Addr, h: u32) -> Vec<String> {
    if add {
        vec![
            format!(
                "filter add {} flower arp_sip {ip} {}",
                filter("arp", 1, 2, h),
                drop_by(Guard::Arp)
            ),
            format!(
                "filter add {} flower src_ip {ip} {}",
                filter("ip", 3, 2, h),
                drop_by(Guard::Source)
            ),
        ]
    } else {
        vec![
            format!("filter del {} flower", filter("arp", 1, 2, h)),
            format!("filter del {} flower", filter("ip", 3, 2, h)),
        ]
    }
}

fn mac_lines(add: bool, m: [u8; 6], h: u32) -> Vec<String> {
    let m = mac::format(m);
    if add {
        vec![
            format!(
                "filter add {} flower src_mac {m} arp_sha {m} action ok",
                filter("arp", 2, 1, h)
            ),
            format!(
                "filter add {} flower src_mac {m} {}",
                filter("arp", 2, 2, h),
                drop_by(Guard::Arp)
            ),
            format!(
                "filter add {} flower arp_sha {m} {}",
                filter("arp", 2, 3, h),
                drop_by(Guard::Arp)
            ),
        ]
    } else {
        // The drops go before the pass.
        vec![
            format!("filter del {} flower", filter("arp", 2, 3, h)),
            format!("filter del {} flower", filter("arp", 2, 2, h)),
            format!("filter del {} flower", filter("arp", 2, 1, h)),
        ]
    }
}

fn ra_lines(add: bool, m: [u8; 6], h: u32) -> Vec<String> {
    if add {
        let m = mac::format(m);
        vec![format!(
            "filter add {} flower src_mac {m} ip_proto icmpv6 type 134 {}",
            filter("ipv6", 0, 5, h),
            drop_by(Guard::Ra)
        )]
    } else {
        vec![format!("filter del {} flower", filter("ipv6", 0, 5, h))]
    }
}

/// Runs `tc -batch` with `lines`.
fn batch(tc: &Path, lines: &[String]) -> io::Result<()> {
    if lines.is_empty() {
        return Ok(());
    }
    let mut child = Command::new(tc)
        .args(["-batch", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().expect("piped");
    for l in lines {
        writeln!(stdin, "{l}")?;
    }
    drop(stdin);
    let out = child.wait_with_output()?;
    if out.status.success() {
        return Ok(());
    }
    let why = String::from_utf8_lossy(&out.stderr);
    Err(io::Error::other(format!("tc: {}", why.trim())))
}

fn output(tc: &Path, args: &[&str]) -> io::Result<String> {
    let out = Command::new(tc).args(args).output()?;
    if !out.status.success() {
        let why = String::from_utf8_lossy(&out.stderr);
        return Err(io::Error::other(format!(
            "tc {}: {}",
            args.join(" "),
            why.trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Each `index` of `tc -s actions ls action gact` with the count of the
/// `dropped` it is followed by.
fn counts(text: &str) -> BTreeMap<u32, u64> {
    let mut out = BTreeMap::new();
    let mut index = None;
    for l in text.lines() {
        let mut words = l.split_whitespace();
        while let Some(w) = words.next() {
            if w == "index" {
                index = words.next().and_then(|i| i.parse().ok());
            } else if w == "(dropped"
                && let (Some(i), Some(n)) = (index.take(), words.next())
            {
                out.insert(i, n.trim_end_matches(',').parse().unwrap_or(0));
            }
        }
    }
    out
}

/// How long the actions may stay bound once their qdiscs are gone: the
/// kernel frees the block's filters a moment later.
const UNBIND_WAIT: Duration = Duration::from_secs(2);

/// Removes the guards' qdiscs, wherever they are, and then their actions.
pub fn clear(tc: &Path) -> io::Result<()> {
    let block = format!("ingress_block {BLOCK}");
    let qdiscs = output(tc, &["qdisc", "show"])?;
    let lines: Vec<String> = qdiscs
        .lines()
        .filter(|l| l.contains(&block))
        .filter_map(|l| l.split_whitespace().skip_while(|w| *w != "dev").nth(1))
        .map(|dev| format!("qdisc del dev {dev} ingress"))
        .collect();
    batch(tc, &lines)?;
    let deadline = Instant::now() + UNBIND_WAIT;
    loop {
        let actions = counts(&output(tc, &["-s", "actions", "ls", "action", "gact"])?);
        let ours = ACTIONS.iter().filter(|(_, i)| actions.contains_key(i));
        let lines: Vec<String> = ours
            .map(|(_, i)| format!("actions delete action gact index {i}"))
            .collect();
        match batch(tc, &lines) {
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
            done => return done,
        }
    }
}

/// What the guards have made `tc` hold.
#[derive(Debug)]
pub struct Enforcer {
    tc: PathBuf,
    /// The ports with the guards' qdisc, by name and interface index (a port
    /// made again under its name has none).
    attached: BTreeSet<(String, i32)>,
    /// The block's filters, while it exists.
    held: Option<Held>,
    next: u32,
    actions: bool,
}

impl Enforcer {
    pub fn new(tc: PathBuf) -> Self {
        Enforcer {
            tc,
            attached: BTreeSet::new(),
            held: None,
            next: 1,
            actions: false,
        }
    }

    fn handle(&mut self) -> u32 {
        self.next += 1;
        self.next
    }

    /// Makes the Wi-Fi ports of the VLANs `enforce`, and only those, drop
    /// what the rules forbid for `bindings` and the advertisers `ra`.
    pub fn sync(
        &mut self,
        ports: &[Port],
        enforce: &[u16],
        bindings: &[Binding],
        ra: &[[u8; 6]],
    ) -> io::Result<()> {
        let lines = self.plan(ports, enforce, bindings, ra);
        let done = batch(&self.tc, &lines.0);
        match done {
            Ok(()) => {
                (self.attached, self.held, self.actions) = lines.1;
                Ok(())
            }
            Err(e) => {
                // Unknown state: back to dropping nothing, and all again
                // next time.
                let _ = clear(&self.tc);
                self.attached.clear();
                self.held = None;
                self.actions = false;
                Err(e)
            }
        }
    }

    /// The lines that bring `tc` to what is wanted, and the state after.
    #[allow(clippy::type_complexity)]
    fn plan(
        &mut self,
        ports: &[Port],
        enforce: &[u16],
        bindings: &[Binding],
        ra: &[[u8; 6]],
    ) -> (Vec<String>, (BTreeSet<(String, i32)>, Option<Held>, bool)) {
        let present: BTreeSet<(String, i32)> =
            ports.iter().map(|p| (p.name.clone(), p.ifindex)).collect();
        let want: BTreeSet<(String, i32)> = ports
            .iter()
            .filter(|p| p.wifi && enforce.contains(&p.vlan))
            .map(|p| (p.name.clone(), p.ifindex))
            .collect();
        // A port that went took its qdisc with it.
        let still: BTreeSet<_> = self.attached.intersection(&present).cloned().collect();
        let mut lines: Vec<String> = still
            .difference(&want)
            .map(|(name, _)| format!("qdisc del dev {name} ingress"))
            .collect();
        if want.is_empty() {
            return (lines, (want, None, self.actions));
        }
        if !self.actions {
            lines.extend(
                ACTIONS
                    .iter()
                    .map(|(_, i)| format!("actions add action drop index {i}")),
            );
        }
        lines.extend(
            want.difference(&still)
                .map(|(name, _)| format!("qdisc add dev {name} ingress_block {BLOCK} ingress")),
        );
        // Without a port left the block went, and its filters with it.
        let fresh = still.intersection(&want).next().is_none();
        let old = if fresh { None } else { self.held.clone() };
        if old.is_none() {
            lines.extend(fixed());
        }
        let old = old.unwrap_or_default();
        let pairs: BTreeSet<([u8; 6], Ipv4Addr)> = bindings.iter().map(|b| (b.mac, b.ip)).collect();
        let ips: BTreeSet<Ipv4Addr> = pairs.iter().map(|(_, ip)| *ip).collect();
        let macs: BTreeSet<[u8; 6]> = pairs.iter().map(|(m, _)| *m).collect();
        let ra: BTreeSet<[u8; 6]> = ra.iter().copied().collect();
        let mut held = Held::default();
        let mut adds = Vec::new();
        let mut dels = Vec::new();
        // Passes are added before drops and deleted after them, so no
        // client's own frames are dropped in between.
        for p in &pairs {
            let h = old.pairs.get(p).copied().unwrap_or_else(|| {
                let h = self.handle();
                adds.extend(pair_lines(true, *p, h));
                h
            });
            held.pairs.insert(*p, h);
        }
        for ip in &ips {
            let h = old.ips.get(ip).copied().unwrap_or_else(|| {
                let h = self.handle();
                adds.extend(ip_lines(true, *ip, h));
                h
            });
            held.ips.insert(*ip, h);
        }
        for m in &macs {
            let h = old.macs.get(m).copied().unwrap_or_else(|| {
                let h = self.handle();
                adds.extend(mac_lines(true, *m, h));
                h
            });
            held.macs.insert(*m, h);
        }
        for m in &ra {
            let h = old.ra.get(m).copied().unwrap_or_else(|| {
                let h = self.handle();
                adds.extend(ra_lines(true, *m, h));
                h
            });
            held.ra.insert(*m, h);
        }
        dels.extend(
            old.ra
                .iter()
                .filter(|(m, _)| !ra.contains(*m))
                .flat_map(|(m, h)| ra_lines(false, *m, *h)),
        );
        dels.extend(
            old.ips
                .iter()
                .filter(|(ip, _)| !ips.contains(*ip))
                .flat_map(|(ip, h)| ip_lines(false, *ip, *h)),
        );
        dels.extend(
            old.macs
                .iter()
                .filter(|(m, _)| !macs.contains(*m))
                .flat_map(|(m, h)| mac_lines(false, *m, *h)),
        );
        dels.extend(
            old.pairs
                .iter()
                .filter(|(p, _)| !pairs.contains(*p))
                .flat_map(|(p, h)| pair_lines(false, *p, *h)),
        );
        lines.extend(adds);
        lines.extend(dels);
        (lines, (want, Some(held), true))
    }

    /// The frames each guard's filters dropped since they were set up.
    pub fn dropped(&self) -> io::Result<Vec<(Guard, u64)>> {
        if !self.actions {
            return Ok(Vec::new());
        }
        let counts = counts(&output(
            &self.tc,
            &["-s", "actions", "ls", "action", "gact"],
        )?);
        let ours = ACTIONS
            .iter()
            .map(|(g, i)| (*g, counts.get(i).copied().unwrap_or(0)));
        Ok(ours.collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(last: u8, ip: [u8; 4]) -> Binding {
        Binding {
            mac: [2, 0, 0, 0, 0, last],
            ip: ip.into(),
            expires_ms: None,
        }
    }

    fn port(name: &str, ifindex: i32, vlan: u16, wifi: bool) -> Port {
        Port {
            ifindex,
            name: name.into(),
            vlan,
            wifi,
        }
    }

    #[test]
    fn the_drop_counts_are_read_from_tc() {
        let text = "\taction order 0: gact action drop\n\t random type none pass val 0\n\t index 64001 ref 3 bind 2\n\tAction statistics:\n\tSent 84 bytes 3 pkt (dropped 3, overlimits 0 requeues 0)\n\t index 7 ref 1 bind 1\n\tSent 1 bytes 1 pkt (dropped 0, overlimits 0 requeues 0)\n";
        assert_eq!(counts(text), BTreeMap::from([(7, 0), (64_001, 3)]));
    }

    #[test]
    fn a_binding_adds_and_removes_only_its_own_filters() {
        let mut e = Enforcer::new("/bin/false".into());
        let ports = [port("vlan42", 7, 42, false), port("wlan5", 10, 42, true)];
        let (first, state) = e.plan(&ports, &[42], &[b(1, [192, 0, 2, 10])], &[]);
        (e.attached, e.held, e.actions) = state;
        assert!(
            first
                .iter()
                .any(|l| l.starts_with("actions add action drop index 64005"))
        );
        assert!(first.contains(&"qdisc add dev wlan5 ingress_block 64 ingress".to_owned()));
        assert!(!first.iter().any(|l| l.contains("vlan42")));
        // One more binding of the same MAC: its pair and address only.
        let (next, state) = e.plan(
            &ports,
            &[42],
            &[b(1, [192, 0, 2, 10]), b(1, [192, 0, 2, 11])],
            &[],
        );
        (e.attached, e.held, e.actions) = state;
        assert_eq!(next.len(), 4, "{next:#?}");
        assert!(
            next.iter()
                .all(|l| l.starts_with("filter add") && l.contains("192.0.2.11"))
        );
        // Its loss deletes them again, the drops first.
        let (gone, state) = e.plan(&ports, &[42], &[b(1, [192, 0, 2, 10])], &[]);
        (e.attached, e.held, e.actions) = state;
        assert_eq!(gone.len(), 4);
        assert!(gone[0].contains("prio 2") && gone[3].contains("prio 1"));
        assert!(gone.iter().all(|l| l.starts_with("filter del")));
        // Nothing changed: nothing to run.
        assert_eq!(
            e.plan(&ports, &[42], &[b(1, [192, 0, 2, 10])], &[]).0,
            Vec::<String>::new()
        );
        // Leaving enforcement removes the qdisc; the block goes with it.
        let (off, state) = e.plan(&ports, &[], &[b(1, [192, 0, 2, 10])], &[]);
        (e.attached, e.held, e.actions) = state;
        assert_eq!(off, ["qdisc del dev wlan5 ingress"]);
        assert!(e.held.is_none() && e.actions);
        // Back on: the block is built whole again, the actions kept.
        let (again, _) = e.plan(
            &ports,
            &[42],
            &[b(1, [192, 0, 2, 10])],
            &[[2, 0, 0, 0, 0, 9]],
        );
        assert!(!again.iter().any(|l| l.starts_with("actions add")));
        assert!(
            again
                .iter()
                .any(|l| l.contains("matchall action goto chain 1"))
        );
        assert!(
            again
                .iter()
                .any(|l| l.contains("src_mac 02:00:00:00:00:09 ip_proto icmpv6 type 134"))
        );
    }

    /// A stand-in for tc that logs its arguments and stdin, prints `out`
    /// for a `show` or `ls`, and fails a batch holding `fail`.
    fn fake_tc(dir: &Path, out: &str) -> PathBuf {
        let tc = dir.join("tc");
        let log = dir.join("log");
        let script = format!(
            "#!/bin/sh\ncase \"$*\" in *show*|*ls*) printf '%s' '{out}'; exit 0;; esac\nin=$(cat)\n\
             printf '%s\\n%s\\n--\\n' \"$*\" \"$in\" >> {}\n\
             case \"$in\" in *fail*) echo 'Error: Cannot find device \"fail0\"' >&2; exit 1;; esac\n",
            log.display()
        );
        std::fs::write(&tc, script).unwrap();
        std::fs::set_permissions(&tc, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        tc
    }

    #[test]
    fn clear_removes_the_guards_qdiscs_and_actions_and_says_why_it_cannot() {
        let t = crate::testdir::TestDir::new();
        let shown = "qdisc ingress ffff: dev wlan5 parent ffff:fff1 ingress_block 64 ----------------\n\
                     qdisc ingress ffff: dev eth9 parent ffff:fff1 ----------------\n\
                     \t index 64001 ref 1 bind 0\n\tSent 0 bytes 0 pkt (dropped 0, overlimits 0)\n";
        let tc = fake_tc(t.path(), shown);
        clear(&tc).unwrap();
        let log = std::fs::read_to_string(t.path().join("log")).unwrap();
        assert_eq!(
            log,
            "-batch -\nqdisc del dev wlan5 ingress\n--\n-batch -\nactions delete action gact index 64001\n--\n"
        );
        let failing = "qdisc ingress ffff: dev fail0 parent ffff:fff1 ingress_block 64\n";
        let tc = fake_tc(t.path(), failing);
        let e = clear(&tc).unwrap_err();
        assert_eq!(e.to_string(), "tc: Error: Cannot find device \"fail0\"");
    }

    #[test]
    fn a_failed_batch_leaves_nothing_dropping() {
        let t = crate::testdir::TestDir::new();
        let tc = fake_tc(t.path(), "");
        let mut e = Enforcer::new(tc);
        let ports = [port("fail0", 10, 42, true)];
        assert!(e.sync(&ports, &[42], &[], &[]).is_err());
        assert!(e.attached.is_empty() && e.held.is_none() && !e.actions);
    }
}
