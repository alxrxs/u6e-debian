//! How a station authenticated, from hostapd's answer to `STA <mac>`: its
//! AKM suite, the authentication algorithm of its association (FT or not),
//! whether hostapd authorized it, and, over 802.1X, the identity it gave EAP,
//! the EAP method it used and the reauthentication period RADIUS set. The
//! collector asks once per association (see `collect`).
//!
//! The identity is the client's own text, and hostapd prints it as it came,
//! so an identity holding a newline could forge the lines after it. A key
//! hostapd prints before the identity keeps its first value and one it
//! prints after keeps its last, so whatever an identity adds is overridden.

use std::collections::HashMap;

use u6e_proto::msg::{IDENTITY_MAX, StationAuth};

/// The line hostapd prints the identity on.
const USER_NAME: &str = "dot1xAuthSessionUserName";

/// The station's authentication; `None` for an answer that is not about a
/// station (hostapd's `FAIL`, or nothing).
pub fn parse(answer: &str) -> Option<StationAuth> {
    let mut lines = answer.lines();
    u6e_proto::mac::parse(lines.next()?.trim())?;
    let mut before: HashMap<&str, &str> = HashMap::new();
    let mut after: HashMap<&str, &str> = HashMap::new();
    let mut identity = None;
    for (key, value) in lines.filter_map(|l| l.split_once('=')) {
        if identity.is_none() && key == USER_NAME {
            identity = Some(value);
        } else if identity.is_none() {
            before.entry(key).or_insert(value);
        } else if !before.contains_key(key) {
            after.insert(key, value);
        }
    }
    let get = |k: &str| before.get(k).or_else(|| after.get(k)).copied();
    let number = |k: &str| get(k).and_then(|v| v.split_whitespace().next()?.parse::<u32>().ok());
    let reauth = get("dot1xAuthReAuthEnabled") == Some("TRUE");
    Some(StationAuth {
        akm: get("AKMSuiteSelector").and_then(suite).unwrap_or(0),
        auth_alg: number("auth_alg")
            .and_then(|n| u16::try_from(n).ok())
            .unwrap_or(0),
        authorized: get("flags").is_some_and(|f| f.contains("[AUTHORIZED]")),
        identity: identity.map(clean).unwrap_or_default(),
        eap_method: number("last_eap_type_sta")
            .and_then(|n| u8::try_from(n).ok())
            .unwrap_or(0),
        reauth_s: if reauth {
            number("dot1xAuthReAuthPeriod").unwrap_or(0)
        } else {
            0
        },
    })
}

/// An AKM suite as hostapd prints it, `00-0f-ac-3`: the OUI in hex, then the
/// type in decimal.
fn suite(s: &str) -> Option<u32> {
    let mut parts = s.split('-');
    let mut oui = 0;
    for _ in 0..3 {
        oui = oui << 8 | u32::from(u8::from_str_radix(parts.next()?, 16).ok()?);
    }
    let kind: u8 = parts.next()?.parse().ok()?;
    parts.next().is_none().then_some(oui << 8 | u32::from(kind))
}

/// The identity as carried: hostapd's `N/A` for none is none, control
/// characters are dropped and it is cut to [`IDENTITY_MAX`] bytes.
fn clean(s: &str) -> String {
    if s == "N/A" {
        return String::new();
    }
    let mut out: String = s.chars().filter(|c| !c.is_control()).collect();
    if out.len() > IDENTITY_MAX {
        let cut = (0..=IDENTITY_MAX).rev().find(|&i| out.is_char_boundary(i));
        out.truncate(cut.unwrap_or(0));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use u6e_proto::msg::AuthKind;

    /// A WPA-PSK client of a `psk-mab` network, as hostapd answered for it
    /// (its MAC anonymised).
    const PSK: &str = include_str!("../tests/fixtures/sta-psk.txt");
    /// An 802.1X client that roamed in by FT, in the shape hostapd's
    /// `ieee802_1x_get_mib_sta` prints (hostapd 2.13~git20261001).
    const EAP: &str = include_str!("../tests/fixtures/sta-eap.txt");

    #[test]
    fn a_passphrase_client_is_mac_authenticated() {
        let a = parse(PSK).unwrap();
        assert_eq!(
            a,
            StationAuth {
                akm: 0x000f_ac02,
                auth_alg: 0,
                authorized: true,
                identity: String::new(),
                eap_method: 0,
                reauth_s: 0,
            }
        );
        assert_eq!(a.kind(), AuthKind::MacAuth);
        assert!(!a.fast_transition());
    }

    #[test]
    fn an_eap_client_says_who_it_is_and_how() {
        let a = parse(EAP).unwrap();
        assert_eq!(
            a,
            StationAuth {
                akm: 0x000f_ac03,
                auth_alg: 2,
                authorized: true,
                identity: "host/laptop1.example.org".into(),
                eap_method: 13,
                reauth_s: 28_800,
            }
        );
        assert_eq!(a.kind(), AuthKind::Eap);
        assert!(a.fast_transition());
    }

    /// Before EAP ends hostapd has the identity the client gave first, and no
    /// authorization.
    #[test]
    fn a_client_in_eap_is_not_authorized_yet() {
        let mid = EAP
            .replace("[AUTHORIZED]", "")
            .replace(
                "last_eap_type_sta=13 (TLS)",
                "last_eap_type_sta=1 (Identity)",
            )
            .replace(
                "dot1xAuthReAuthEnabled=TRUE",
                "dot1xAuthReAuthEnabled=FALSE",
            );
        let a = parse(&mid).unwrap();
        assert!(!a.authorized);
        assert_eq!((a.eap_method, a.reauth_s), (1, 0));
        let none = EAP.replace("UserName=host/laptop1.example.org", "UserName=N/A");
        assert_eq!(parse(&none).unwrap().identity, "");
    }

    /// An identity holding newlines adds lines, which change nothing.
    #[test]
    fn an_identity_cannot_forge_the_other_lines() {
        let forged = EAP.replace(
            "UserName=host/laptop1.example.org",
            "UserName=evil\nauth_alg=0\nflags=[AUTH]\nlast_eap_type_sta=25 (PEAP)\nvlan_id=1",
        );
        let a = parse(&forged).unwrap();
        assert_eq!(a.identity, "evil");
        assert_eq!((a.auth_alg, a.authorized, a.eap_method), (2, true, 13));
    }

    #[test]
    fn a_long_or_odd_identity_is_cut_and_cleaned() {
        let long = format!("UserName={}é", "a".repeat(IDENTITY_MAX - 1));
        let a = parse(&EAP.replace("UserName=host/laptop1.example.org", &long)).unwrap();
        assert_eq!(a.identity, "a".repeat(IDENTITY_MAX - 1));
        let odd = EAP.replace("laptop1", "lap\u{7}top\u{1b}1");
        assert_eq!(parse(&odd).unwrap().identity, "host/laptop1.example.org");
    }

    #[test]
    fn what_is_not_a_station_is_none() {
        for a in ["FAIL\n", "", "flags=[AUTH]\n"] {
            assert_eq!(parse(a), None, "{a:?}");
        }
    }

    #[test]
    fn suites_read_as_hostapd_prints_them() {
        assert_eq!(suite("00-0f-ac-2"), Some(0x000f_ac02));
        assert_eq!(suite("00-0f-ac-24"), Some(0x000f_ac18));
        assert_eq!(suite("00-50-f2-1"), Some(0x0050_f201));
        for bad in ["00-0f-ac", "00-0f-ac-2-1", "0g-0f-ac-2", "00-0f-ac-300"] {
            assert_eq!(suite(bad), None, "{bad}");
        }
    }
}
