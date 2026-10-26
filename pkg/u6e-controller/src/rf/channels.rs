//! The channel geometry of the three bands: which channel numbers exist, the
//! 20 MHz channels of the block a primary and a width make, the frequencies
//! that block spans, which 6 GHz primaries are preferred scanning channels
//! (PSC), and the hostapd keys that state a primary and a width, as the site
//! file spells them.

use u6e_proto::msg::Band;

/// The widths the planner knows, MHz.
pub const WIDTHS: [u16; 4] = [20, 40, 80, 160];

/// The band as the site file keys it (`"24"`, `"5"`, `"6"`).
pub fn site_key(band: Band) -> &'static str {
    match band {
        Band::B24 => "24",
        Band::B5 => "5",
        Band::B6 => "6",
    }
}

pub fn from_site_key(key: &str) -> Option<Band> {
    match key {
        "24" => Some(Band::B24),
        "5" => Some(Band::B5),
        "6" => Some(Band::B6),
        _ => None,
    }
}

pub const BANDS: [Band; 3] = [Band::B24, Band::B5, Band::B6];

/// Whether `ch` is a 20 MHz channel of `band`.
pub fn exists(band: Band, ch: u16) -> bool {
    match band {
        Band::B24 => (1..=13).contains(&ch),
        Band::B5 => {
            (ch.is_multiple_of(4) && ((36..=64).contains(&ch) || (100..=144).contains(&ch)))
                || (ch % 4 == 1 && (149..=177).contains(&ch))
        }
        Band::B6 => ch % 4 == 1 && (1..=233).contains(&ch),
    }
}

/// Every 20 MHz channel of `band`, lowest first.
pub fn all(band: Band) -> impl Iterator<Item = u16> {
    (1..=233).filter(move |&c| exists(band, c))
}

/// The centre frequency of a 20 MHz channel, MHz.
pub fn mhz(band: Band, ch: u16) -> u32 {
    let ch = u32::from(ch);
    match band {
        Band::B24 => 2407 + 5 * ch,
        Band::B5 => 5000 + 5 * ch,
        Band::B6 => 5950 + 5 * ch,
    }
}

/// The 20 MHz channels of the block of `width` MHz that holds `primary`,
/// lowest first, or `None` when there is no such block. 2.4 GHz has only 20
/// MHz blocks here: its 40 MHz channels overlap every other one.
pub fn block(band: Band, primary: u16, width: u16) -> Option<Vec<u16>> {
    if !exists(band, primary) || !WIDTHS.contains(&width) {
        return None;
    }
    let n = width / 20;
    let base = match band {
        Band::B24 if width == 20 => return Some(vec![primary]),
        Band::B24 => return None,
        Band::B5 if primary < 100 => 36,
        Band::B5 if primary < 149 => 100,
        Band::B5 => 149,
        Band::B6 => 1,
    };
    let start = base + (primary - base) / 4 / n * n * 4;
    let chans: Vec<u16> = (0..n).map(|i| start + 4 * i).collect();
    chans.iter().all(|&c| exists(band, c)).then_some(chans)
}

/// The channel number at the centre of a block (hostapd's
/// `*_oper_centr_freq_seg0_idx`).
pub fn centre(chans: &[u16]) -> u16 {
    (chans[0] + chans[chans.len() - 1]) / 2
}

/// The frequencies the block spans, MHz.
pub fn span(band: Band, chans: &[u16]) -> (u32, u32) {
    (
        mhz(band, chans[0]) - 10,
        mhz(band, chans[chans.len() - 1]) + 10,
    )
}

/// Whether two blocks of one band share any frequency.
pub fn overlap(band: Band, a: &[u16], b: &[u16]) -> bool {
    let (a, b) = (span(band, a), span(band, b));
    a.0 < b.1 && b.0 < a.1
}

/// Whether a 6 GHz channel is a preferred scanning channel: clients that
/// look for 6 GHz BSSs only there find a BSS whose primary it is.
pub fn psc(ch: u16) -> bool {
    ch % 16 == 5
}

/// A key's new value in the site file, as YAML text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub name: &'static str,
    pub value: String,
}

fn key(name: &'static str, value: impl ToString) -> Key {
    Key {
        name,
        value: value.to_string(),
    }
}

/// `ht_capab` with its HT40 flag as `primary` at `width` needs it: `[HT40+]`
/// when the primary is the lower half of its 40 MHz pair, `[HT40-]` when the
/// upper, none at 20 MHz; its other flags are kept.
pub fn ht_capab(old: &str, band: Band, primary: u16, width: u16) -> String {
    let mut out = old.replace("[HT40+]", "").replace("[HT40-]", "");
    if width >= 40 {
        let pair = block(band, primary, 40).unwrap_or_default();
        let flag = if pair.first() == Some(&primary) {
            "[HT40+]"
        } else {
            "[HT40-]"
        };
        out.insert_str(0, flag);
    }
    out
}

/// The hostapd keys that state `primary` at `width` on `band` (each block of
/// `block`), other than `ht_capab`, whose old value [`ht_capab`] edits.
pub fn keys(band: Band, chans: &[u16], primary: u16) -> Vec<Key> {
    let width = chans.len() as u16 * 20;
    let seg0 = centre(chans);
    let chwidth = match width {
        80 => 1,
        160 => 2,
        _ => 0,
    };
    match band {
        Band::B24 => vec![key("channel", primary)],
        Band::B5 => vec![
            key("channel", primary),
            key("vht_oper_chwidth", chwidth),
            key("vht_oper_centr_freq_seg0_idx", seg0),
            key("he_oper_chwidth", chwidth),
            key("he_oper_centr_freq_seg0_idx", seg0),
        ],
        Band::B6 => vec![
            key("op_class", 131 + (width / 20).trailing_zeros()),
            key("channel", primary),
            key("he_oper_chwidth", chwidth),
            key("he_oper_centr_freq_seg0_idx", seg0),
        ],
    }
}

/// The width the site file's keys of a radio state, MHz, or `None` when they
/// state one the planner does not handle (80+80, or 40 MHz on 2.4 GHz).
pub fn width_of(band: Band, get: impl Fn(&str) -> Option<String>) -> Option<u16> {
    let num = |k: &str| get(k).and_then(|v| v.parse::<u16>().ok());
    let ht40 = get("ht_capab").is_some_and(|v| v.contains("[HT40"));
    let chwidth = |k| match num(k) {
        None | Some(0) => Some(if ht40 { 40 } else { 20 }),
        Some(1) => Some(80),
        Some(2) => Some(160),
        _ => None,
    };
    match band {
        Band::B24 => (!ht40).then_some(20),
        // HE's width is the one an HE radio runs; VHT's stands without it.
        Band::B5 if get("he_oper_chwidth").is_some() => chwidth("he_oper_chwidth"),
        Band::B5 => chwidth("vht_oper_chwidth"),
        Band::B6 => match num("op_class") {
            Some(c @ 131..=134) => Some(20 << (c - 131)),
            Some(_) => None,
            None => match num("he_oper_chwidth") {
                Some(1) => Some(80),
                Some(2) => Some(160),
                _ => Some(20),
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_follow_the_channel_plan() {
        assert_eq!(block(Band::B5, 44, 40), Some(vec![44, 48]));
        assert_eq!(block(Band::B5, 44, 80), Some(vec![36, 40, 44, 48]));
        assert_eq!(block(Band::B5, 153, 80), Some(vec![149, 153, 157, 161]));
        assert_eq!(block(Band::B5, 132, 80), Some(vec![132, 136, 140, 144]));
        assert_eq!(block(Band::B5, 165, 160).map(|b| b.len()), Some(8));
        // 132-160 is no block: 148 is no channel.
        assert_eq!(block(Band::B5, 132, 160), None);
        assert_eq!(block(Band::B5, 37, 20), None);
        assert_eq!(block(Band::B6, 37, 160).map(|b| centre(&b)), Some(47));
        assert_eq!(block(Band::B6, 85, 160).map(|b| centre(&b)), Some(79));
        assert_eq!(block(Band::B24, 13, 20), Some(vec![13]));
        assert_eq!(block(Band::B24, 1, 40), None);
        assert_eq!(block(Band::B24, 14, 20), None);
    }

    #[test]
    fn spans_overlap_when_they_share_spectrum() {
        let b24 = |c| block(Band::B24, c, 20).unwrap();
        assert!(overlap(Band::B24, &b24(13), &b24(13)));
        assert!(overlap(Band::B24, &b24(13), &b24(10)));
        assert!(!overlap(Band::B24, &b24(13), &b24(9)));
        let b6 = |c, w| block(Band::B6, c, w).unwrap();
        assert!(!overlap(Band::B6, &b6(37, 160), &b6(85, 160)));
        assert!(overlap(Band::B6, &b6(37, 160), &b6(53, 20)));
        assert_eq!(span(Band::B6, &b6(37, 160)), (6105, 6265));
    }

    #[test]
    fn psc_are_every_fourth_6ghz_channel_from_5() {
        let pscs: Vec<_> = all(Band::B6).filter(|&c| psc(c)).take(4).collect();
        assert_eq!(pscs, [5, 21, 37, 53]);
        assert_eq!(all(Band::B6).filter(|&c| psc(c)).count(), 15);
    }

    #[test]
    fn keys_state_primary_and_width() {
        let b = block(Band::B5, 149, 80).unwrap();
        let k: Vec<_> = keys(Band::B5, &b, 149)
            .into_iter()
            .map(|k| format!("{}={}", k.name, k.value))
            .collect();
        assert_eq!(
            k,
            [
                "channel=149",
                "vht_oper_chwidth=1",
                "vht_oper_centr_freq_seg0_idx=155",
                "he_oper_chwidth=1",
                "he_oper_centr_freq_seg0_idx=155"
            ]
        );
        let b = block(Band::B6, 37, 80).unwrap();
        let op = keys(Band::B6, &b, 37);
        assert_eq!((op[0].name, op[0].value.as_str()), ("op_class", "133"));
        assert_eq!(op[3].value, "39");
        assert_eq!(
            ht_capab("[HT40+][SHORT-GI-40]", Band::B5, 48, 80),
            "[HT40-][SHORT-GI-40]"
        );
        assert_eq!(ht_capab("[HT40+]", Band::B5, 44, 20), "");
        assert_eq!(ht_capab("", Band::B5, 149, 40), "[HT40+]");
    }

    #[test]
    fn widths_read_back_from_the_keys() {
        fn site(pairs: &[(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
            move |k| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| v.to_string())
            }
        }
        const W5: [(&str, &str); 3] = [
            ("ht_capab", "[HT40+]"),
            ("vht_oper_chwidth", "1"),
            ("he_oper_chwidth", "1"),
        ];
        assert_eq!(width_of(Band::B5, site(&W5)), Some(80));
        assert_eq!(
            width_of(Band::B5, site(&[("ht_capab", "[HT40-]")])),
            Some(40)
        );
        assert_eq!(width_of(Band::B5, site(&[])), Some(20));
        assert_eq!(width_of(Band::B5, site(&[("he_oper_chwidth", "3")])), None);
        assert_eq!(width_of(Band::B6, site(&[("op_class", "134")])), Some(160));
        assert_eq!(width_of(Band::B24, site(&[("channel", "13")])), Some(20));
        assert_eq!(width_of(Band::B24, site(&[("ht_capab", "[HT40+]")])), None);
        for w in WIDTHS {
            let b = block(Band::B6, 37, w).unwrap();
            let k = keys(Band::B6, &b, 37);
            let get = |n: &str| k.iter().find(|k| k.name == n).map(|k| k.value.clone());
            assert_eq!(width_of(Band::B6, get), Some(w));
        }
    }
}
