//! The names of the AP's own netdevs, as its helpers accept them: a BSS's
//! (`wlan5-1`), its per-VLAN netdev's (`wlan5-1.42`) and a client VLAN's
//! (`vlan42`). A name that passes is safe in an argument vector and in an
//! nftables ruleset as it is.

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

/// A Wi-Fi port: a BSS's netdev or one of its per-VLAN netdevs.
pub fn wifi_port(name: &str) -> bool {
    let base = name.split_once('.').map_or(name, |(b, _)| b);
    vap(base) && port_of(name, base)
}

/// A client VLAN's netdev, `vlan<vid>`.
pub fn vlan(name: &str) -> bool {
    name.strip_prefix("vlan").is_some_and(vid)
}

/// A VLAN id as written in a netdev name: 1 to 4 digits, no leading zero.
fn vid(s: &str) -> bool {
    (1..=4).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit()) && !s.starts_with('0')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_the_aps_own_kinds() {
        for ok in ["wlan24", "wlan5", "wlan6", "wlan5-1", "wlan24-7"] {
            assert!(vap(ok) && wifi_port(ok), "{ok}");
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
        assert!(wifi_port("wlan6-1.4094") && wifi_port("wlan24.42"));
        for bad in [
            "wlan6.0",
            "wlan7.42",
            "mirror.0",
            "vlan42",
            "wlan5.42.1",
            "lan",
        ] {
            assert!(!wifi_port(bad), "{bad}");
        }
        assert!(vlan("vlan42") && vlan("vlan4094"));
        for bad in ["vlan", "vlan0", "vlan042", "vlan12345", "vlan42;", "br42"] {
            assert!(!vlan(bad), "{bad}");
        }
    }
}
