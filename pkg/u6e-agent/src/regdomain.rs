//! What a radio may be switched to, judged from what nl80211 says of it: its
//! channels with their flags and power limits, the widths it supports, and
//! the regulatory rules in force. A channel switch is allowed only onto a
//! block of 20 MHz channels that are all enabled, the width allowed on each
//! and by the rules, and none a DFS channel still needing its CAC (hostapd
//! would take the radio off the air for it). A transmit power is held to its
//! primary channel's limit by the radio's own rules (a self-managed radio's,
//! which `GET_REG` of its wiphy returns, else the kernel's), as the driver
//! holds it.

use u6e_proto::msg::{Band, PowerLimit};

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
            cac: false,
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
    /// A channel of it is a DFS channel without a CAC: the radio must check
    /// for radar first, off the air, which a channel switch cannot do.
    pub cac: bool,
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
    let mut cac = false;
    for &f in &subs {
        let c = r.caps.channels.iter().find(|c| c.freq_mhz == f);
        let n = channel_of(f);
        let c = c
            .filter(|c| !c.disabled)
            .ok_or(format!("channel {n} is not enabled"))?;
        cac |= c.radar && !c.dfs_available;
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
        cac,
    })
}

/// The most the radio transmits where it operates now: its primary
/// channel's limit and that channel's rule, the one mac80211 holds a fixed
/// power to whatever the width (`ieee80211_chandef_max_power`), and the one
/// the controller's planner plans by.
pub fn power_limit(r: &RadioState) -> Result<i8, String> {
    let n = channel_of(r.freq_mhz);
    let c = r
        .caps
        .channels
        .iter()
        .find(|c| c.freq_mhz == r.freq_mhz)
        .ok_or(format!("channel {n} is not the radio's"))?;
    limit_of(c, &r.rules).ok_or(format!("channel {n} is outside the regulatory domain"))
}

/// The most a radio sends with `c` as its primary channel, by `rules`.
fn limit_of(c: &Channel, rules: &[RegRule]) -> Option<i8> {
    let rule = rule_of(rules, c.freq_mhz)?;
    let mbm = c.max_power_mbm.min(rule.max_eirp_mbm);
    Some(i8::try_from(mbm / 100).unwrap_or(i8::MAX))
}

/// The most a radio of `caps` and `rules` sends with the channel at
/// `freq_mhz` as its primary; none for a channel it does not have.
pub fn limit_at(caps: &BandCaps, rules: &[RegRule], freq_mhz: u32) -> Option<i8> {
    let c = caps.channels.iter().find(|c| c.freq_mhz == freq_mhz)?;
    limit_of(c, rules)
}

/// What a radio of limit `limit` that was asked for `asked` dBm and sends at
/// `sends` dBm sends at most: less than its limit only while it sends less
/// than asked, held there by itself.
pub fn held_to(limit: i8, asked: Option<i8>, sends: i8) -> i8 {
    if asked.is_some_and(|a| sends < a) && (1..limit).contains(&sends) {
        sends
    } else {
        limit
    }
}

/// The limits of a radio of `band` for the controller's planner: its enabled
/// channels in runs of one limit, in channel order.
pub fn power_limits(band: Band, caps: &BandCaps, rules: &[RegRule]) -> Vec<PowerLimit> {
    let mut runs: Vec<PowerLimit> = Vec::new();
    for c in caps.channels.iter().filter(|c| !c.disabled) {
        let Some(dbm) = limit_of(c, rules) else {
            continue;
        };
        let ch = channel_of(c.freq_mhz);
        match runs.last_mut() {
            Some(l) if l.dbm == dbm => l.last = ch,
            _ => runs.push(PowerLimit {
                band,
                first: ch,
                last: ch,
                dbm,
            }),
        }
    }
    runs
}

/// `dbm` as the radio transmits it: held to [`power_limit`], with a note
/// when that lowered it. A power above the limit is never refused: the
/// driver clamps it so, and only the note tells.
pub fn clamp_power(r: &RadioState, dbm: i8) -> Result<(i8, Option<String>), String> {
    if dbm < 0 {
        return Err("a transmit power below 0 dBm".into());
    }
    let limit = power_limit(r)?;
    if dbm <= limit {
        return Ok((dbm, None));
    }
    let n = channel_of(r.freq_mhz);
    let note = format!("{dbm} dBm clamped to {limit} dBm, the most channel {n} allows");
    Ok((limit, Some(note)))
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
                sec_offset: 1,
                cac: false
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
                sec_offset: -1,
                cac: false
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
        // A DFS channel without a CAC is a switch that needs one.
        let cac = |t| check_switch(Band::B5, &r, t).map(|s| s.cac);
        assert_eq!(cac(target(100, 80, 106)), Ok(true));
        assert_eq!(cac(target(36, 160, 50)), Ok(true));
        assert_eq!(cac(target(36, 80, 42)), Ok(false));
        let s = |t| check_switch(Band::B5, &r, t).unwrap_err();
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
    /// takes a switch at once; one whose CAC is not, a radar check first.
    #[test]
    fn a_dfs_channel_with_its_cac_done_takes_a_switch() {
        let mut r = radio5();
        for c in &mut r.caps.channels {
            if (5490..=5570).contains(&c.freq_mhz) {
                c.dfs_available = true;
            }
        }
        let cac = |t| check_switch(Band::B5, &r, t).map(|s| s.cac);
        assert_eq!(cac(target(100, 80, 106)), Ok(false));
        assert_eq!(cac(target(116, 80, 122)), Ok(true));
    }

    /// Power is held to the primary channel's limit, never refused for
    /// being above it.
    #[test]
    fn power_is_held_to_the_primary_channels_limit() {
        let r = radio5();
        assert_eq!(clamp_power(&r, 30), Ok((30, None)));
        assert_eq!(
            clamp_power(&r, 31),
            Ok((
                30,
                Some("31 dBm clamped to 30 dBm, the most channel 149 allows".into())
            ))
        );
        assert_eq!(
            clamp_power(&r, -1).unwrap_err(),
            "a transmit power below 0 dBm"
        );
        let mut capped = radio5();
        capped.rules[3].max_eirp_mbm = 2000;
        assert_eq!(clamp_power(&capped, 21).map(|p| p.0), Ok(20));
        assert_eq!(clamp_power(&radio6(), 24), Ok((24, None)));
        assert_eq!(clamp_power(&radio6(), 25).map(|p| p.0), Ok(24));
    }

    /// Less than its limit only while it sends less than asked: held there
    /// by itself (a 6 GHz radio by its power spectral density).
    #[test]
    fn a_radio_sending_less_than_asked_is_held_there() {
        assert_eq!(held_to(30, Some(26), 19), 19);
        assert_eq!(held_to(23, Some(26), 23), 23);
        assert_eq!(held_to(23, Some(20), 20), 23);
        assert_eq!(held_to(23, None, 19), 23);
        assert_eq!(held_to(23, Some(26), 0), 23);
    }

    /// The QCN9074's own KR rules, as `GET_REG` of its self-managed wiphy
    /// returns them: 5170-5835 MHz at 23 dBm, channel 48 among them.
    fn self_managed_kr5() -> RadioState {
        let mut r = radio5();
        r.rules = vec![RegRule {
            start_khz: 5_170_000,
            end_khz: 5_835_000,
            max_bw_khz: 160_000,
            max_eirp_mbm: 2300,
            flags: 0,
        }];
        for c in &mut r.caps.channels {
            c.max_power_mbm = 2300;
        }
        (r.freq_mhz, r.center_mhz, r.width_mhz) = (5220, 5210, 80);
        r
    }

    /// A self-managed radio is held by its own rules: 23 dBm across 36-48,
    /// channel 48 too, and the hallway's 36-48 block on 44 at 23 applies.
    #[test]
    fn a_self_managed_radio_takes_its_own_rules() {
        let mut r = self_managed_kr5();
        assert_eq!(clamp_power(&r, 23), Ok((23, None)));
        assert_eq!(clamp_power(&r, 26).map(|p| p.0), Ok(23));
        r.freq_mhz = 5240;
        assert_eq!(power_limit(&r), Ok(23));
        let limits = power_limits(Band::B5, &r.caps, &r.rules);
        assert_eq!(
            limits,
            [PowerLimit {
                band: Band::B5,
                first: 36,
                last: 165,
                dbm: 23
            }]
        );
    }

    /// The hallway's block under the kernel's KR rules: 36-48 at 80 MHz on
    /// primary 44, where channel 48 allows only 17 dBm. 23 dBm is what
    /// channel 44 allows, and applies.
    #[test]
    fn a_block_with_a_lower_channel_takes_its_primarys_power() {
        let mut r = radio5();
        for c in &mut r.caps.channels {
            if c.freq_mhz == 5240 {
                c.max_power_mbm = 1700;
            }
        }
        (r.freq_mhz, r.center_mhz, r.width_mhz) = (5220, 5210, 80);
        assert_eq!(power_limit(&r), Ok(23));
        assert_eq!(clamp_power(&r, 23), Ok((23, None)));
        assert_eq!(clamp_power(&r, 26).map(|p| p.0), Ok(23));
        r.freq_mhz = 5240;
        assert_eq!(power_limit(&r), Ok(17));
        let limits = power_limits(Band::B5, &r.caps, &r.rules);
        let run = |first, last, dbm| PowerLimit {
            band: Band::B5,
            first,
            last,
            dbm,
        };
        assert_eq!(
            limits[..3],
            [run(36, 44, 23), run(48, 48, 17), run(52, 64, 20)]
        );
    }
}
