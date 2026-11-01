//! Enforcement: the Wi-Fi ports of the VLANs the guards enforce on get an
//! ingress qdisc on one shared filter block, whose flower filters drop what
//! the rules forbid (the kernel has no bridge nftables). Only the offending
//! frames go, never the client:
//!
//! - DHCP and DHCPv6 server messages from a client;
//! - router advertisements from a client that sent a rogue one in the last
//!   hour (the first passes: what makes one rogue is past what flower reads);
//! - ARP whose sender is not a bound pair of the frame's MAC and address
//!   (probes and link-local senders pass);
//! - IPv4 from a source not bound to the frame's MAC (link-local, and a
//!   lease asked for from 0.0.0.0, pass). Offloaded connections never reach
//!   the host, so this checks a connection's first packets, which is what
//!   stops it: ECM offloads only what it saw pass.
//!
//! Every change is one `tc -batch`; the filters are replaced whole when the
//! bindings change. Nothing is left behind: a port that leaves enforcement
//! loses its qdisc, and `clear` (the unit's last step, however the guards
//! ended) removes every Wi-Fi port's, so a guard that is not running drops
//! nothing.

use std::collections::BTreeSet;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use u6e_proto::mac;
use u6e_proto::msg::Binding;

use crate::ports::Port;

/// The shared block of the guards' filters.
pub const BLOCK: u32 = 64;

/// The filters for `bindings` and the rogue advertisers `ra`.
pub fn filters(bindings: &[Binding], ra: &[[u8; 6]]) -> Vec<String> {
    let add = |proto: &str, prio: u16, matches: &str, action: &str| {
        format!(
            "filter add block {BLOCK} protocol {proto} prio {prio} flower {matches}action {action}"
        )
    };
    let mut out = vec![
        add("ip", 1, "ip_proto udp src_port 67 dst_port 68 ", "drop"),
        add("ipv6", 2, "ip_proto udp src_port 547 ", "drop"),
    ];
    for m in ra {
        let m = mac::format(*m);
        out.push(add(
            "ipv6",
            3,
            &format!("src_mac {m} ip_proto icmpv6 type 134 "),
            "drop",
        ));
    }
    // One pass per bound pair; the same pairs answer ARP and send IPv4.
    let pairs: BTreeSet<([u8; 6], Ipv4Addr)> = bindings.iter().map(|b| (b.mac, b.ip)).collect();
    for (m, ip) in &pairs {
        let m = mac::format(*m);
        out.push(add(
            "arp",
            10,
            &format!("src_mac {m} arp_sha {m} arp_sip {ip} "),
            "ok",
        ));
    }
    out.extend([
        add("arp", 11, "arp_sip 0.0.0.0/32 ", "ok"),
        add("arp", 12, "arp_sip 169.254.0.0/16 ", "ok"),
        add("arp", 13, "", "drop"),
    ]);
    for (m, ip) in &pairs {
        let m = mac::format(*m);
        out.push(add("ip", 20, &format!("src_mac {m} src_ip {ip} "), "ok"));
    }
    out.extend([
        add(
            "ip",
            21,
            "ip_proto udp src_ip 0.0.0.0/32 src_port 68 dst_port 67 ",
            "ok",
        ),
        add("ip", 22, "src_ip 169.254.0.0/16 ", "ok"),
        add("ip", 23, "", "drop"),
    ]);
    out
}

/// Runs `tc -batch` with `lines`; with `force`, past the lines that fail.
fn batch(tc: &Path, lines: &[String], force: bool) -> io::Result<()> {
    let mut cmd = Command::new(tc);
    if force {
        cmd.arg("-force");
    }
    let mut child = cmd
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
    if out.status.success() || force {
        return Ok(());
    }
    let why = String::from_utf8_lossy(&out.stderr);
    Err(io::Error::other(format!("tc: {}", why.trim())))
}

/// Removes the ingress qdisc of every Wi-Fi port in `ports`.
pub fn clear(tc: &Path, ports: &[Port]) -> io::Result<()> {
    let wifi = ports.iter().filter(|p| p.wifi);
    let lines: Vec<String> = wifi
        .map(|p| format!("qdisc del dev {} ingress", p.name))
        .collect();
    if lines.is_empty() {
        return Ok(());
    }
    batch(tc, &lines, true)
}

/// What the guards have made `tc` hold.
#[derive(Debug)]
pub struct Enforcer {
    tc: PathBuf,
    /// The ports with the guards' qdisc, by name and interface index (a port
    /// made again under its name has none).
    attached: BTreeSet<(String, i32)>,
    filters: Vec<String>,
}

impl Enforcer {
    pub fn new(tc: PathBuf) -> Self {
        Enforcer {
            tc,
            attached: BTreeSet::new(),
            filters: Vec::new(),
        }
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
        let present: BTreeSet<(String, i32)> =
            ports.iter().map(|p| (p.name.clone(), p.ifindex)).collect();
        let want: BTreeSet<(String, i32)> = ports
            .iter()
            .filter(|p| p.wifi && enforce.contains(&p.vlan))
            .map(|p| (p.name.clone(), p.ifindex))
            .collect();
        let filters = if want.is_empty() {
            Vec::new()
        } else {
            filters(bindings, ra)
        };
        // A port that went took its qdisc with it.
        let mut lines: Vec<String> = (self.attached.intersection(&present))
            .filter(|p| !want.contains(*p))
            .map(|(name, _)| format!("qdisc del dev {name} ingress"))
            .collect();
        let added = want
            .difference(&self.attached)
            .map(|(name, _)| format!("qdisc add dev {name} ingress_block {BLOCK} ingress"));
        lines.extend(added);
        if !want.is_empty() && (filters != self.filters || self.attached.is_disjoint(&want)) {
            lines.push(format!("filter del block {BLOCK}"));
            lines.extend(filters.iter().cloned());
        }
        if lines.is_empty() {
            return Ok(());
        }
        if let Err(e) = batch(&self.tc, &lines, false) {
            // Unknown state: back to dropping nothing, and all again next time.
            let _ = clear(&self.tc, ports);
            self.attached.clear();
            self.filters.clear();
            return Err(e);
        }
        self.attached = want;
        self.filters = filters;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_filters_pass_the_bound_pairs_and_drop_the_rest() {
        let b = |last: u8, ip: [u8; 4]| Binding {
            mac: [2, 0, 0, 0, 0, last],
            ip: ip.into(),
            expires_ms: None,
        };
        let f = filters(
            &[
                b(1, [192, 0, 2, 10]),
                b(1, [192, 0, 2, 10]),
                b(2, [192, 0, 2, 11]),
            ],
            &[[2, 0, 0, 0, 0, 9]],
        );
        let block = "filter add block 64 protocol";
        let want = [
            "ip prio 1 flower ip_proto udp src_port 67 dst_port 68 action drop",
            "ipv6 prio 2 flower ip_proto udp src_port 547 action drop",
            "ipv6 prio 3 flower src_mac 02:00:00:00:00:09 ip_proto icmpv6 type 134 action drop",
            "arp prio 10 flower src_mac 02:00:00:00:00:01 arp_sha 02:00:00:00:00:01 arp_sip 192.0.2.10 action ok",
            "arp prio 10 flower src_mac 02:00:00:00:00:02 arp_sha 02:00:00:00:00:02 arp_sip 192.0.2.11 action ok",
            "arp prio 11 flower arp_sip 0.0.0.0/32 action ok",
            "arp prio 12 flower arp_sip 169.254.0.0/16 action ok",
            "arp prio 13 flower action drop",
            "ip prio 20 flower src_mac 02:00:00:00:00:01 src_ip 192.0.2.10 action ok",
            "ip prio 20 flower src_mac 02:00:00:00:00:02 src_ip 192.0.2.11 action ok",
            "ip prio 21 flower ip_proto udp src_ip 0.0.0.0/32 src_port 68 dst_port 67 action ok",
            "ip prio 22 flower src_ip 169.254.0.0/16 action ok",
            "ip prio 23 flower action drop",
        ];
        let want: Vec<String> = want.iter().map(|w| format!("{block} {w}")).collect();
        assert_eq!(f, want);
    }

    /// A stand-in for tc that appends each batch to a file, and fails one
    /// holding `fail`.
    fn fake_tc(dir: &Path) -> PathBuf {
        let tc = dir.join("tc");
        let log = dir.join("log");
        let script = format!(
            "#!/bin/sh\nin=$(cat)\nprintf '%s\\n%s\\n--\\n' \"$*\" \"$in\" >> {}\ncase \"$in\" in *fail*) exit 1;; esac\n",
            log.display()
        );
        std::fs::write(&tc, script).unwrap();
        std::fs::set_permissions(&tc, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        tc
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
    fn only_the_enforced_vlans_ports_get_the_qdisc() {
        let t = crate::testdir::TestDir::new();
        let tc = fake_tc(t.path());
        let log = || std::fs::read_to_string(t.path().join("log")).unwrap_or_default();
        let mut e = Enforcer::new(tc.clone());
        let ports = [
            port("vlan42", 7, 42, false),
            port("wlan5", 10, 42, true),
            port("wlan5.43", 20, 43, true),
        ];
        // Alerting only: tc is never run.
        e.sync(&ports, &[], &[], &[]).unwrap();
        assert_eq!(log(), String::new());
        e.sync(&ports, &[43], &[], &[]).unwrap();
        let first = log();
        assert!(first.starts_with(
            "-batch -\nqdisc add dev wlan5.43 ingress_block 64 ingress\nfilter del block 64\n"
        ));
        assert!(!first.contains("wlan5 ") && !first.contains("vlan42"));
        // Nothing changed: nothing run.
        e.sync(&ports, &[43], &[], &[]).unwrap();
        assert_eq!(log(), first);
        // A Wi-Fi restart made the port again: it gets its qdisc again.
        let again = [
            port("vlan42", 7, 42, false),
            port("wlan5", 10, 42, true),
            port("wlan5.43", 30, 43, true),
        ];
        e.sync(&again, &[43], &[], &[]).unwrap();
        assert!(log()[first.len()..].starts_with(
            "-batch -\nqdisc add dev wlan5.43 ingress_block 64 ingress\nfilter del block 64\n"
        ));
        // Leaving enforcement removes it.
        let before = log().len();
        e.sync(&again, &[], &[], &[]).unwrap();
        assert_eq!(
            &log()[before..],
            "-batch -\nqdisc del dev wlan5.43 ingress\n--\n"
        );
        assert!(e.attached.is_empty());
    }

    #[test]
    fn a_failed_batch_leaves_nothing_dropping() {
        let t = crate::testdir::TestDir::new();
        let tc = fake_tc(t.path());
        let mut e = Enforcer::new(tc);
        let ports = [port("fail0", 10, 42, true)];
        assert!(e.sync(&ports, &[42], &[], &[]).is_err());
        assert!(e.attached.is_empty());
        let log = std::fs::read_to_string(t.path().join("log")).unwrap();
        assert!(
            log.ends_with("-force -batch -\nqdisc del dev fail0 ingress\n--\n"),
            "{log}"
        );
    }
}
