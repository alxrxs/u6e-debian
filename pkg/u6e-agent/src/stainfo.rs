//! How a station authenticated, from hostapd's answer to `STA <mac>`: its
//! AKM suite, the authentication algorithm of its association (FT or not),
//! whether hostapd authorized it, and, over 802.1X, the identity it gave EAP,
//! the EAP method it used and the reauthentication period RADIUS set; and
//! what it said it supports when it associated (its newest PHY mode, its
//! streams, highest MCS and widest channel). The collector asks once per
//! association (see `collect`).
//!
//! The identity is the client's own text, and hostapd prints it as it came,
//! so an identity holding a newline could forge the lines after it. A key
//! hostapd prints before the identity keeps its first value and one it
//! prints after keeps its last, so whatever an identity adds is overridden.
//! The capability lines come after it, but which of them count goes by the
//! flags, which come before: an identity can claim no mode its client did
//! not, and the client's own lines, printed later, win.

use std::collections::HashMap;

use u6e_proto::msg::{Band, IDENTITY_MAX, RateMode, StationAuth, StationCaps};
use u6e_proto::text;

/// The line hostapd prints the identity on.
const USER_NAME: &str = "dot1xAuthSessionUserName";

/// The longest hex value read: an HE capabilities element is 54 bytes.
const HEX_MAX: usize = 128;

/// The authentication of the station `mac`, and what it supports on `band`
/// when the answer says; `None` for an answer that is not about it
/// (hostapd's `FAIL`, nothing, or a late answer to an earlier question about
/// another station).
pub fn parse(
    answer: &str,
    mac: [u8; 6],
    band: Option<Band>,
) -> Option<(StationAuth, Option<StationCaps>)> {
    let mut lines = answer.lines();
    (u6e_proto::mac::parse(lines.next()?.trim())? == mac).then_some(())?;
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
    let auth = StationAuth {
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
    };
    Some((auth, band.and_then(|b| caps(get, b))))
}

/// What the station supports on `band`, by the newest mode its flags name
/// that its capability lines describe; `None` when they describe none of
/// the modes the flags name.
fn caps<'a>(get: impl Fn(&str) -> Option<&'a str>, band: Band) -> Option<StationCaps> {
    let flags = get("flags").unwrap_or_default();
    let has = |f: &str| flags.contains(f);
    let he = || {
        let c = hex(get("he_capab")?)?;
        // MAC (6 bytes) and PHY capabilities (11), then the receive HE-MCS
        // map up to 80 MHz; the PHY's first byte holds the widths.
        let phy0 = *c.get(6)?;
        let (nss, code) = streams(u16::from_le_bytes([*c.get(17)?, *c.get(18)?]))?;
        let width_mhz = match band {
            Band::B24 if phy0 & 0x02 != 0 => 40,
            Band::B24 => 20,
            _ if phy0 & 0x08 != 0 => 160,
            _ if phy0 & 0x04 != 0 => 80,
            _ => 20,
        };
        Some(StationCaps {
            mode: RateMode::He,
            nss,
            mcs: [7, 9, 11][usize::from(code)],
            width_mhz,
        })
    };
    let vht = || {
        let (nss, code) = streams(u16::from_str_radix(get("rx_vht_mcs_map")?, 16).ok()?)?;
        let info = u32::from_str_radix(get("vht_caps_info")?.strip_prefix("0x")?, 16).ok()?;
        // Its supported channel width set: 0 is up to 80 MHz. Extended NSS
        // BW support (bits 30-31) is not read: it gives such a client 160 MHz
        // with only a half or three quarters of its streams, which is never
        // faster than 80 MHz with all of them for a client of fewer than
        // four, and the best rate is all the width is for.
        let width_mhz = if info >> 2 & 3 == 0 { 80 } else { 160 };
        Some(StationCaps {
            mode: RateMode::Vht,
            nss,
            mcs: [7, 8, 9][usize::from(code)],
            width_mhz,
        })
    };
    let ht = || {
        // A byte of MCS indices per stream.
        let set = hex(get("ht_mcs_bitmask")?)?;
        let nss = set.iter().take(4).take_while(|&&b| b != 0).count() as u8;
        let info = u16::from_str_radix(get("ht_caps_info")?.strip_prefix("0x")?, 16).ok()?;
        (nss > 0).then_some(StationCaps {
            mode: RateMode::Ht,
            nss,
            mcs: 7,
            width_mhz: if info & 0x02 == 0 { 20 } else { 40 },
        })
    };
    let modern = has("[HE]") || has("[VHT]") || has("[HT]");
    let legacy = StationCaps {
        mode: RateMode::Legacy,
        nss: 1,
        mcs: 0,
        width_mhz: 20,
    };
    has("[HE]")
        .then(he)
        .flatten()
        .or_else(|| (has("[VHT]") && band != Band::B24).then(vht).flatten())
        .or_else(|| has("[HT]").then(ht).flatten())
        .or((!modern).then_some(legacy))
}

/// The streams a VHT or HE MCS map supports (2 bits each, from the first, 3
/// for none) and the highest of their codes (0 to 2); `None` for none.
fn streams(map: u16) -> Option<(u8, u8)> {
    let codes = (0..8).map(|i| (map >> (2 * i) & 3) as u8);
    let (n, top) = codes
        .take_while(|&c| c != 3)
        .fold((0, 0), |(n, top), c| (n + 1, top.max(c)));
    (n > 0).then_some((n, top))
}

/// `s` as hex bytes, at most [`HEX_MAX`] digits.
fn hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || s.len() > HEX_MAX {
        return None;
    }
    let digit = |d| u8::from_str_radix(std::str::from_utf8(d).ok()?, 16).ok();
    s.as_bytes().chunks(2).map(digit).collect()
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

/// The identity as carried: hostapd's `N/A` for none is none, control and
/// format characters are dropped (`u6e_proto::text`) and it is cut to
/// [`IDENTITY_MAX`] bytes.
fn clean(s: &str) -> String {
    if s == "N/A" {
        return String::new();
    }
    let mut out = text::clean(s);
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
    /// A phone of 2×2 HE (Wi-Fi 6E) that roamed in by FT with SAE, and a
    /// client of 1×1 VHT with a passphrase, as hostapd answered for them on
    /// 5 GHz (their MACs anonymised).
    const HE: &str = include_str!("../tests/fixtures/sta-he.txt");
    const VHT: &str = include_str!("../tests/fixtures/sta-vht.txt");
    /// An 802.1X client that roamed in by FT, in the shape hostapd's
    /// `ieee802_1x_get_mib_sta` prints (hostapd 2.13~git20261001).
    const EAP: &str = include_str!("../tests/fixtures/sta-eap.txt");
    const PSK_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x21];
    const EAP_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x22];

    fn eap(answer: &str) -> Option<StationAuth> {
        parse(answer, EAP_MAC, None).map(|(a, _)| a)
    }

    fn caps(answer: &str, last: u8, band: Band) -> Option<StationCaps> {
        parse(answer, [2, 0, 0, 0, 0, last], Some(band))?.1
    }

    fn sc(mode: RateMode, nss: u8, mcs: u8, width_mhz: u16) -> Option<StationCaps> {
        Some(StationCaps {
            mode,
            nss,
            mcs,
            width_mhz,
        })
    }

    #[test]
    fn a_passphrase_client_is_mac_authenticated() {
        let (a, _) = parse(PSK, PSK_MAC, None).unwrap();
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
        let a = eap(EAP).unwrap();
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
        let a = eap(&mid).unwrap();
        assert!(!a.authorized);
        assert_eq!((a.eap_method, a.reauth_s), (1, 0));
        let none = EAP.replace("UserName=host/laptop1.example.org", "UserName=N/A");
        assert_eq!(eap(&none).unwrap().identity, "");
    }

    /// An identity holding newlines adds lines, which change nothing.
    #[test]
    fn an_identity_cannot_forge_the_other_lines() {
        let forged = EAP.replace(
            "UserName=host/laptop1.example.org",
            "UserName=evil\nauth_alg=0\nflags=[AUTH]\nlast_eap_type_sta=25 (PEAP)\nvlan_id=1",
        );
        let a = eap(&forged).unwrap();
        assert_eq!(a.identity, "evil");
        assert_eq!((a.auth_alg, a.authorized, a.eap_method), (2, true, 13));
    }

    #[test]
    fn a_long_or_odd_identity_is_cut_and_cleaned() {
        let long = format!("UserName={}é", "a".repeat(IDENTITY_MAX - 1));
        let a = eap(&EAP.replace("UserName=host/laptop1.example.org", &long)).unwrap();
        assert_eq!(a.identity, "a".repeat(IDENTITY_MAX - 1));
        let odd = EAP.replace("laptop1", "lap\u{7}top\u{1b}1\u{202e}\u{200b}");
        assert_eq!(eap(&odd).unwrap().identity, "host/laptop1.example.org");
    }

    #[test]
    fn what_is_not_a_station_is_none() {
        for a in ["FAIL\n", "", "flags=[AUTH]\n"] {
            assert_eq!(eap(a), None, "{a:?}");
        }
    }

    /// An answer about another station (a late one to an earlier question)
    /// is no answer about this one.
    #[test]
    fn an_answer_about_another_station_is_none() {
        assert_eq!(parse(PSK, EAP_MAC, None), None);
        assert_eq!(
            eap(&EAP.replacen("02:00:00:00:00:22", "02:00:00:00:00:23", 1)),
            None
        );
    }

    /// The newest mode the flags name and the lines describe: HE's own
    /// widths for the band, VHT's on 5 and 6 GHz alone, HT's 40 MHz bit,
    /// and the streams and highest MCS of the receive map.
    #[test]
    fn what_a_client_supports_is_read_by_its_newest_mode() {
        use RateMode::{He, Ht, Legacy, Vht};
        assert_eq!(caps(HE, 0x23, Band::B5), sc(He, 2, 11, 160));
        assert_eq!(caps(HE, 0x23, Band::B6), sc(He, 2, 11, 160));
        // The same phone on 2.4 GHz: HE without 40 MHz there.
        assert_eq!(caps(HE, 0x23, Band::B24), sc(He, 2, 11, 20));
        // Of 80 MHz only (bit 2 of the PHY's first byte, not bit 3), and of
        // 20 MHz only.
        let phy0 = |b: &str| {
            HE.replace(
                "he_capab=0174889845884c",
                &format!("he_capab=017488984588{b}"),
            )
        };
        assert_eq!(caps(&phy0("44"), 0x23, Band::B5), sc(He, 2, 11, 80));
        assert_eq!(caps(&phy0("40"), 0x23, Band::B6), sc(He, 2, 11, 20));
        assert_eq!(caps(VHT, 0x24, Band::B5), sc(Vht, 1, 9, 80));
        let two = VHT.replace("rx_vht_mcs_map=fffe", "rx_vht_mcs_map=fffa");
        assert_eq!(caps(&two, 0x24, Band::B5), sc(Vht, 2, 9, 80));
        let wide = VHT.replace("vht_caps_info=0x33907120", "vht_caps_info=0x33907124");
        assert_eq!(caps(&wide, 0x24, Band::B5), sc(Vht, 1, 9, 160));
        // Extended NSS BW support on a width set of 80 MHz stays 80.
        let ext = VHT.replace("vht_caps_info=0x33907120", "vht_caps_info=0xf3907120");
        assert_eq!(caps(&ext, 0x24, Band::B5), sc(Vht, 1, 9, 80));
        assert_eq!(caps(PSK, 0x21, Band::B24), sc(Ht, 1, 7, 40));
        let narrow = PSK.replace("ht_caps_info=0x116e", "ht_caps_info=0x116c");
        assert_eq!(caps(&narrow, 0x21, Band::B24), sc(Ht, 1, 7, 20));
        // A VHT client on 2.4 GHz is an HT one; one of no modern mode is
        // legacy.
        assert_eq!(caps(VHT, 0x24, Band::B24), sc(Ht, 1, 7, 40));
        let old = PSK.replace("[HT]", "");
        assert_eq!(caps(&old, 0x21, Band::B24), sc(Legacy, 1, 0, 20));
        // Without a band, nothing is said.
        assert_eq!(parse(HE, [2, 0, 0, 0, 0, 0x23], None).unwrap().1, None);
    }

    /// The client writes its capabilities, and hostapd prints them as hex:
    /// lines that are short, odd, oversized or of no stream fall back to
    /// the next mode the flags name, or to nothing, never a panic.
    #[test]
    fn capabilities_that_do_not_read_say_nothing_false() {
        use RateMode::{Ht, Vht};
        let he = "he_capab=0174889845884c7fc249fd095f0c047e00fafffafffafffaff";
        for bad in [
            "he_capab=0174".to_owned(),
            "he_capab=0174889845884c7fc249fd095f0c047e00fafffafffafffaf".to_owned(),
            "he_capab=zz74889845884c7fc249fd095f0c047e00fafffafffafffaff".to_owned(),
            "he_capab=0174889845884c7fc249fd095f0c047e00ffffffffffffffff".to_owned(),
            format!("he_capab={}", "ff".repeat(200)),
        ] {
            let a = HE.replace(he, &bad);
            assert_eq!(caps(&a, 0x23, Band::B5), sc(Vht, 2, 9, 160), "{bad}");
        }
        let none = VHT
            .replace("rx_vht_mcs_map=fffe", "rx_vht_mcs_map=ffff")
            .replace("ht_mcs_bitmask=ff000000000000000000", "ht_mcs_bitmask=00");
        assert_eq!(caps(&none, 0x24, Band::B5), None);
        let ht_only = VHT.replace("rx_vht_mcs_map=fffe", "rx_vht_mcs_map=x");
        assert_eq!(caps(&ht_only, 0x24, Band::B5), sc(Ht, 1, 7, 40));
        // An identity cannot make an HT client an HE one: the flags come
        // first, and its own lines last.
        let real = format!(
            "{}ht_mcs_bitmask=ff000000000000000000\nht_caps_info=0x116c\n",
            EAP.replace("[VHT][HE]", "")
        );
        let forged = real.replace(
            "UserName=host/laptop1.example.org",
            &format!("UserName=x\nflags=[HT][HE]\n{he}\nht_caps_info=0x116e"),
        );
        let read = |a: &str| parse(a, EAP_MAC, Some(Band::B5)).unwrap().1;
        assert_eq!(read(&real), sc(Ht, 1, 7, 20));
        assert_eq!(read(&forged), read(&real));
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
