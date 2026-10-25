//! What a radio may be switched to, judged from what nl80211 says of it: its
//! channels with their flags and power limits, the widths it supports, and
//! the regulatory rules in force. A channel switch is allowed only onto a
//! block of 20 MHz channels that are all enabled, the width allowed on each
//! and by the rules, and none a DFS channel still needing its CAC (hostapd
//! would take the radio off the air for it); a transmit power only up to the
//! least the radio's channels and their rules allow.

use u6e_proto::msg::Band;

/// The kernel's `NL80211_RRF_AUTO_BW`: the rule's width may be exceeded by
/// joining it with the next rule.
pub const RRF_AUTO_BW: u32 = 1 << 11;

/// One 20 MHz channel of a radio, as its wiphy lists it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Channel {
    pub freq_mhz: u32,
    pub disabled: bool,
    pub no_ir: bool,
    pub radar: bool,
    /// A DFS channel whose CAC is done (`NL80211_DFS_AVAILABLE`).
    pub dfs_available: bool,
    pub max_power_mbm: u32,
    pub no_ht40_minus: bool,
    pub no_ht40_plus: bool,
    pub no_80mhz: bool,
    pub no_160mhz: bool,
}

/// A radio's channels in one band and the widest channel it supports there.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BandCaps {
    pub channels: Vec<Channel>,
    pub max_width_mhz: u16,
}

/// One rule of the regulatory domain.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegRule {
    pub start_khz: u32,
    pub end_khz: u32,
    pub max_bw_khz: u32,
    pub max_eirp_mbm: u32,
    pub flags: u32,
}

/// A radio as nl80211 shows it now: what it may do and where it operates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RadioState {
    pub caps: BandCaps,
    pub rules: Vec<RegRule>,
    pub freq_mhz: u32,
    pub width_mhz: u16,
    pub center_mhz: u32,
}

impl RadioState {
    /// Whether the radio already operates where `s` puts it.
    pub fn runs(&self, s: &Switch) -> bool {
        self.freq_mhz == s.freq_mhz
            && self.width_mhz == s.width_mhz
            && (s.width_mhz == 20 || self.center_mhz == s.center_mhz)
    }

    /// Where the radio operates now, as a switch back there says it.
    pub fn here(&self) -> Switch {
        Switch {
            freq_mhz: self.freq_mhz,
            center_mhz: self.center_mhz,
            width_mhz: self.width_mhz,
            sec_offset: sec_offset(self.freq_mhz, self.center_mhz, self.width_mhz),
        }
    }
}

/// The side of the secondary 20 MHz channel of a primary at `freq_mhz` in
/// the block of `width_mhz` centred at `center_mhz`: above it when the
/// primary is the lower of its 40 MHz pair.
fn sec_offset(freq_mhz: u32, center_mhz: u32, width_mhz: u16) -> i8 {
    if width_mhz <= 20 {
        return 0;
    }
    let first = center_mhz.saturating_sub(u32::from(width_mhz) / 2) + 10;
    if (freq_mhz.saturating_sub(first) / 20).is_multiple_of(2) {
        1
    } else {
        -1
    }
}

/// Where a radio is asked to operate: its primary channel and the block
/// around it, by channel numbers as hostapd's configuration names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    pub channel: u16,
    pub width_mhz: u16,
    pub center_channel: u16,
}

/// A target checked, in the terms of hostapd's `CHAN_SWITCH`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Switch {
    pub freq_mhz: u32,
    pub center_mhz: u32,
    pub width_mhz: u16,
    /// Where the secondary 20 MHz channel is: 1 above, -1 below, 0 none.
    pub sec_offset: i8,
}

pub fn band_of(freq_mhz: u32) -> Band {
    match freq_mhz {
        ..3000 => Band::B24,
        3000..5925 => Band::B5,
        _ => Band::B6,
    }
}

pub fn channel_of(freq_mhz: u32) -> u16 {
    let (f, base) = match band_of(freq_mhz) {
        Band::B24 if freq_mhz == 2484 => return 14,
        Band::B24 => (freq_mhz, 2407),
        Band::B5 => (freq_mhz, 5000),
        Band::B6 if freq_mhz == 5935 => return 2,
        Band::B6 => (freq_mhz, 5950),
    };
    (f.saturating_sub(base) / 5) as u16
}

/// The centre frequency of channel `ch` of `band`; `None` for no channel.
pub fn freq(band: Band, ch: u16) -> Option<u32> {
    let ch = u32::from(ch);
    match band {
        Band::B24 if ch == 14 => Some(2484),
        Band::B24 => (1..=13).contains(&ch).then(|| 2407 + 5 * ch),
        Band::B5 => (32..=177).contains(&ch).then(|| 5000 + 5 * ch),
        Band::B6 if ch == 2 => Some(5935),
        Band::B6 => (1..=233).contains(&ch).then(|| 5950 + 5 * ch),
    }
}

/// The 5 GHz blocks of each width, by their centre channel.
const CENTERS_5: [(u16, &[u16]); 3] = [
    (
        40,
        &[
            38, 46, 54, 62, 102, 110, 118, 126, 134, 142, 151, 159, 167, 175,
        ],
    ),
    (80, &[42, 58, 106, 122, 138, 155, 171]),
    (160, &[50, 114, 163]),
];

/// Whether `center` is the centre of a block of `width` in `band`.
fn block_center(band: Band, width: u16, center: u16, primary: u16) -> bool {
    match (band, width) {
        (_, 20) => center == primary,
        (Band::B24, 40) => center + 2 == primary || primary + 2 == center,
        (Band::B5, _) => CENTERS_5
            .iter()
            .any(|(w, cs)| *w == width && cs.contains(&center)),
        // 802.11ax-2021 27.3.23.2: the 6 GHz blocks are aligned from channel 1.
        (Band::B6, 40) => center % 8 == 3,
        (Band::B6, 80) => center % 16 == 7,
        (Band::B6, 160) => center % 32 == 15,
        _ => false,
    }
}

/// Checks that `t` is somewhere the radio may switch to, and returns the
/// switch; the error says why not.
pub fn check_switch(band: Band, r: &RadioState, t: Target) -> Result<Switch, String> {
    let ch = t.channel;
    let w = t.width_mhz;
    if ![20, 40, 80, 160].contains(&w) {
        return Err(format!("no {w} MHz channels"));
    }
    if w > r.caps.max_width_mhz {
        let max = r.caps.max_width_mhz;
        return Err(format!("the radio supports up to {max} MHz"));
    }
    let freq_mhz = freq(band, ch).ok_or(format!("no channel {ch} in the band"))?;
    let center_mhz = freq(band, t.center_channel)
        .filter(|_| block_center(band, w, t.center_channel, ch))
        .ok_or(format!(
            "channel {} is no {w} MHz block's centre",
            t.center_channel
        ))?;
    let half = u32::from(w) / 2;
    if freq_mhz.abs_diff(center_mhz) >= half.max(10) && w > 20 {
        return Err(format!("channel {ch} is outside that block"));
    }
    let first = center_mhz - half + 10;
    let subs: Vec<u32> = (0..u32::from(w) / 20).map(|i| first + 20 * i).collect();
    for &f in &subs {
        let c = r.caps.channels.iter().find(|c| c.freq_mhz == f);
        let n = channel_of(f);
        let c = c
            .filter(|c| !c.disabled)
            .ok_or(format!("channel {n} is not enabled"))?;
        if c.radar && !c.dfs_available {
            return Err(format!(
                "channel {n} is a DFS channel without a CAC: switching there would take the radio off the air while one runs"
            ));
        }
        if c.no_ir && !c.radar {
            return Err(format!("channel {n} may not be transmitted on first"));
        }
        let flagged = match w {
            80 => c.no_80mhz,
            160 => c.no_160mhz,
            _ => false,
        };
        if flagged {
            return Err(format!("channel {n} allows no {w} MHz"));
        }
        let rule =
            rule_of(&r.rules, f).ok_or(format!("channel {n} is outside the regulatory domain"))?;
        if rule.max_bw_khz < u32::from(w) * 1000 && rule.flags & RRF_AUTO_BW == 0 {
            return Err(format!(
                "the regulatory domain allows no {w} MHz on channel {n}"
            ));
        }
    }
    let sec_offset = sec_offset(freq_mhz, center_mhz, w);
    if w == 40 || band != Band::B6 && w > 20 {
        let p = r.caps.channels.iter().find(|c| c.freq_mhz == freq_mhz);
        let refused = p.is_some_and(|c| match sec_offset {
            1 => c.no_ht40_plus,
            _ => c.no_ht40_minus,
        });
        if refused {
            return Err(format!(
                "channel {ch} allows no secondary channel on that side"
            ));
        }
    }
    Ok(Switch {
        freq_mhz,
        center_mhz,
        width_mhz: w,
        sec_offset,
    })
}

/// Checks that `dbm` is within what the radio's channels and their rules
/// allow where it operates now.
pub fn check_power(r: &RadioState, dbm: i8) -> Result<(), String> {
    if dbm < 0 {
        return Err("a transmit power below 0 dBm".into());
    }
    let half = u32::from(r.width_mhz.max(20)) / 2;
    let center = if r.center_mhz == 0 {
        r.freq_mhz
    } else {
        r.center_mhz
    };
    let first = center.saturating_sub(half) + 10;
    let mut limit = u32::MAX;
    for f in (0..u32::from(r.width_mhz.max(20)) / 20).map(|i| first + 20 * i) {
        let n = channel_of(f);
        let c = r
            .caps
            .channels
            .iter()
            .find(|c| c.freq_mhz == f)
            .ok_or(format!("channel {n} is not the radio's"))?;
        let rule =
            rule_of(&r.rules, f).ok_or(format!("channel {n} is outside the regulatory domain"))?;
        limit = limit.min(c.max_power_mbm).min(rule.max_eirp_mbm);
    }
    let mbm = u32::from(dbm.unsigned_abs()) * 100;
    if mbm > limit {
        return Err(format!(
            "{dbm} dBm is above the {} dBm allowed on the radio's channel",
            limit / 100
        ));
    }
    Ok(())
}

/// The rule a 20 MHz channel lies within.
fn rule_of(rules: &[RegRule], freq_mhz: u32) -> Option<&RegRule> {
    let (lo, hi) = ((freq_mhz - 10) * 1000, (freq_mhz + 10) * 1000);
    rules.iter().find(|r| r.start_khz <= lo && hi <= r.end_khz)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A 5 GHz radio as an ETSI-like domain allows it: 36-48 and 149-165
    /// free, 52-64 and 100-140 DFS (none with a CAC done), 80 MHz at most
    /// below 5490 MHz and 160 MHz above; 23 dBm channel limits, 30 dBm on
    /// 149 up.
    pub fn radio5() -> RadioState {
        let mut channels = Vec::new();
        for ch in (36..=64)
            .step_by(4)
            .chain((100..=144).step_by(4))
            .chain((149..=165).step_by(4))
        {
            let f = freq(Band::B5, ch).unwrap();
            channels.push(Channel {
                freq_mhz: f,
                radar: (52..=144).contains(&ch),
                no_ir: (52..=144).contains(&ch),
                max_power_mbm: if ch >= 149 { 3000 } else { 2300 },
                no_160mhz: ch >= 149,
                no_ht40_plus: ch == 165,
                no_ht40_minus: ch == 165,
                ..Channel::default()
            });
        }
        let rule = |lo: u32, hi: u32, bw: u32, eirp: u32, flags: u32| RegRule {
            start_khz: lo * 1000,
            end_khz: hi * 1000,
            max_bw_khz: bw * 1000,
            max_eirp_mbm: eirp,
            flags,
        };
        RadioState {
            caps: BandCaps {
                channels,
                max_width_mhz: 160,
            },
            rules: vec![
                rule(5170, 5250, 80, 2300, RRF_AUTO_BW),
                rule(5250, 5330, 80, 2000, RRF_AUTO_BW | 1 << 4),
                rule(5490, 5730, 160, 2700, 1 << 4),
                rule(5735, 5835, 80, 3000, 0),
            ],
            freq_mhz: 5745,
            width_mhz: 80,
            center_mhz: 5775,
        }
    }

    /// A 6 GHz radio: channels 1-93, 160 MHz, 24 dBm.
    pub fn radio6() -> RadioState {
        let channels = (1..=93)
            .step_by(4)
            .map(|ch| Channel {
                freq_mhz: freq(Band::B6, ch).unwrap(),
                max_power_mbm: 2400,
                ..Channel::default()
            })
            .collect();
        RadioState {
            caps: BandCaps {
                channels,
                max_width_mhz: 160,
            },
            rules: vec![RegRule {
                start_khz: 5_945_000,
                end_khz: 6_425_000,
                max_bw_khz: 160_000,
                max_eirp_mbm: 2400,
                flags: 0,
            }],
            freq_mhz: 6215,
            width_mhz: 160,
            center_mhz: 6185,
        }
    }

    fn target(channel: u16, width_mhz: u16, center_channel: u16) -> Target {
        Target {
            channel,
            width_mhz,
            center_channel,
        }
    }

    #[test]
    fn channels_and_frequencies_agree() {
        for (band, ch, f) in [
            (Band::B24, 1, 2412),
            (Band::B24, 13, 2472),
            (Band::B24, 14, 2484),
            (Band::B5, 36, 5180),
            (Band::B5, 165, 5825),
            (Band::B6, 1, 5955),
            (Band::B6, 2, 5935),
            (Band::B6, 85, 6375),
            (Band::B6, 233, 7115),
        ] {
            assert_eq!(freq(band, ch), Some(f));
            assert_eq!((band_of(f), channel_of(f)), (band, ch));
        }
        // 6 GHz channel 2 sits below channel 1, and 5925 MHz is 6 GHz.
        assert_eq!(band_of(5925), Band::B6);
        assert_eq!(freq(Band::B24, 15), None);
        assert_eq!(freq(Band::B6, 234), None);
    }

    #[test]
    fn a_switch_within_the_rules_says_how() {
        let r = radio5();
        let s = |t| check_switch(Band::B5, &r, t);
        assert_eq!(
            s(target(36, 80, 42)),
            Ok(Switch {
                freq_mhz: 5180,
                center_mhz: 5210,
                width_mhz: 80,
                sec_offset: 1
            })
        );
        assert_eq!(s(target(44, 80, 42)).map(|s| s.sec_offset), Ok(1));
        assert_eq!(s(target(48, 80, 42)).map(|s| s.sec_offset), Ok(-1));
        assert_eq!(s(target(157, 80, 155)).map(|s| s.sec_offset), Ok(1));
        assert_eq!(s(target(153, 40, 151)).map(|s| s.sec_offset), Ok(-1));
        assert_eq!(s(target(165, 20, 165)).map(|s| s.sec_offset), Ok(0));
        let r6 = radio6();
        assert_eq!(
            check_switch(Band::B6, &r6, target(37, 160, 47)),
            Ok(Switch {
                freq_mhz: 6135,
                center_mhz: 6185,
                width_mhz: 160,
                sec_offset: -1
            })
        );
        assert_eq!(
            check_switch(Band::B6, &r6, target(33, 160, 47)).map(|s| s.sec_offset),
            Ok(1)
        );
        assert_eq!(
            check_switch(Band::B6, &r6, target(5, 80, 7)).map(|s| s.sec_offset),
            Ok(-1)
        );
    }

    #[test]
    fn a_switch_outside_the_rules_is_refused_with_why() {
        let r = radio5();
        let s = |t| check_switch(Band::B5, &r, t).unwrap_err();
        assert!(s(target(100, 80, 106)).contains("DFS channel without a CAC"));
        assert!(s(target(36, 160, 50)).contains("DFS channel without a CAC"));
        assert_eq!(s(target(149, 160, 163)), "channel 149 allows no 160 MHz");
        assert_eq!(
            s(target(36, 80, 46)),
            "channel 46 is no 80 MHz block's centre"
        );
        assert_eq!(s(target(36, 80, 58)), "channel 36 is outside that block");
        assert_eq!(s(target(36, 320, 50)), "no 320 MHz channels");
        assert_eq!(s(target(169, 20, 169)), "channel 169 is not enabled");
        assert_eq!(s(target(250, 20, 250)), "no channel 250 in the band");
        assert_eq!(
            s(target(165, 40, 167)),
            "channel 169 is not enabled",
            "its block's upper half"
        );
        let mut narrow = radio5();
        narrow.caps.max_width_mhz = 80;
        assert_eq!(
            check_switch(Band::B5, &narrow, target(36, 160, 50)).unwrap_err(),
            "the radio supports up to 80 MHz"
        );
        let mut strict = radio5();
        strict.rules[0].flags = 0;
        strict.rules[0].max_bw_khz = 40_000;
        assert_eq!(
            check_switch(Band::B5, &strict, target(36, 80, 42)).unwrap_err(),
            "the regulatory domain allows no 80 MHz on channel 36"
        );
        let mut no_rule = radio5();
        no_rule.rules.pop();
        assert_eq!(
            check_switch(Band::B5, &no_rule, target(149, 20, 149)).unwrap_err(),
            "channel 149 is outside the regulatory domain"
        );
    }

    /// A DFS channel whose CAC is done (the radio was there, or a CAC ran)
    /// takes a switch at once.
    #[test]
    fn a_dfs_channel_with_its_cac_done_takes_a_switch() {
        let mut r = radio5();
        for c in &mut r.caps.channels {
            if (5490..=5570).contains(&c.freq_mhz) {
                c.dfs_available = true;
            }
        }
        assert!(check_switch(Band::B5, &r, target(100, 80, 106)).is_ok());
        assert!(check_switch(Band::B5, &r, target(116, 80, 122)).is_err());
    }

    #[test]
    fn power_is_held_to_the_least_limit_of_the_block() {
        let r = radio5();
        assert_eq!(check_power(&r, 30), Ok(()));
        assert_eq!(
            check_power(&r, 31).unwrap_err(),
            "31 dBm is above the 30 dBm allowed on the radio's channel"
        );
        assert_eq!(
            check_power(&r, -1).unwrap_err(),
            "a transmit power below 0 dBm"
        );
        let mut low = radio5();
        low.freq_mhz = 5180;
        low.center_mhz = 5210;
        assert_eq!(check_power(&low, 23), Ok(()));
        assert!(check_power(&low, 24).is_err());
        let mut capped = radio5();
        capped.rules[3].max_eirp_mbm = 2000;
        assert!(check_power(&capped, 21).is_err());
        assert_eq!(check_power(&radio6(), 24), Ok(()));
        assert!(check_power(&radio6(), 25).is_err());
    }
}
