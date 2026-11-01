//! The bridge ports the guards watch, from sysfs: each VLAN's bridge is
//! `br<vid>` (`boot/wifi-up.sh`), its Wi-Fi ports the BSSs and the per-VLAN
//! interfaces hostapd makes for its RADIUS-assigned clients (each with a
//! `phy80211`), its other port the uplink's VLAN interface, where the DHCP
//! servers' answers come in. Interfaces come and go with clients and Wi-Fi
//! restarts, so they are looked at again every few seconds.

use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Port {
    pub ifindex: i32,
    pub name: String,
    pub vlan: u16,
    /// A Wi-Fi port, its clients' side; else the uplink.
    pub wifi: bool,
}

/// The ports of the VLAN bridges under `net` (`/sys/class/net`), by name.
pub fn scan(net: &Path) -> io::Result<Vec<Port>> {
    let mut ports = Vec::new();
    for entry in fs::read_dir(net)? {
        let dir = entry?.path();
        let Some(master) = fs::read_link(dir.join("master")).ok() else {
            continue;
        };
        let master = master
            .file_name()
            .and_then(|m| m.to_str())
            .unwrap_or_default();
        let Some(vlan) = master.strip_prefix("br").and_then(|v| v.parse().ok()) else {
            continue;
        };
        let ifindex = fs::read_to_string(dir.join("ifindex"))
            .ok()
            .and_then(|i| i.trim().parse().ok());
        let (Some(ifindex), Some(name)) = (ifindex, dir.file_name().and_then(|n| n.to_str()))
        else {
            continue;
        };
        ports.push(Port {
            ifindex,
            name: name.to_owned(),
            vlan,
            wifi: fs::symlink_metadata(dir.join("phy80211")).is_ok(),
        });
    }
    ports.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;
    use std::os::unix::fs::symlink;

    fn netdev(net: &Path, name: &str, ifindex: i32, master: Option<&str>, wifi: bool) {
        let d = net.join(name);
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("ifindex"), format!("{ifindex}\n")).unwrap();
        if let Some(m) = master {
            symlink(format!("../{m}"), d.join("master")).unwrap();
        }
        if wifi {
            symlink("../../ieee80211/radio5", d.join("phy80211")).unwrap();
        }
    }

    #[test]
    fn the_vlan_bridges_ports_are_found() {
        let t = TestDir::new();
        let net = t.path();
        netdev(net, "lan", 2, None, false);
        netdev(net, "br42", 3, None, false);
        netdev(net, "vlan42", 7, Some("br42"), false);
        netdev(net, "wlan5", 10, Some("br42"), true);
        netdev(net, "wlan5.43", 20, Some("br43"), true);
        netdev(net, "wlan24", 8, None, true);
        netdev(net, "tap0", 30, Some("bridge"), false);
        let port = |name: &str, ifindex, vlan, wifi| Port {
            ifindex,
            name: name.into(),
            vlan,
            wifi,
        };
        assert_eq!(
            scan(net).unwrap(),
            [
                port("vlan42", 7, 42, false),
                port("wlan5", 10, 42, true),
                port("wlan5.43", 20, 43, true),
            ]
        );
    }
}
