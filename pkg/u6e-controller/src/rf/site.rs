//! The site file as the RF planner reads and edits it: u6e-debian's site
//! description, every AP's radios under `u6e.aps.<ap>.radios.<band>` as
//! hostapd keys (an AP without its own takes the fleet's,
//! `u6e.wifi.radios.<band>`), their transmit power in dBm under
//! `u6e.aps.<ap>.txpower.<band>`, else the fleet's `u6e.wifi.txpower.<band>`,
//! and the country under `u6e.wifi.country`. Bands are keyed `"24"`, `"5"`
//! and `"6"`.
//!
//! The site keeps a setting from the planner with a comment holding
//! `planner: fixed` on its line: on an AP's own line it keeps all of the AP's
//! radios, on a radio's line the radio, on its `channel` line its channel and
//! width, and on a `txpower` line the power of the bands that line holds.
//! An edit changes only the keys that state what changed (the channel's and
//! width's, or the AP's own power for that band), adding those missing; it
//! is checked against what the plan read, so a file changed since is refused.

use std::collections::BTreeMap;

use u6e_proto::msg::Band;

use super::channels::{self, BANDS};
use super::yaml::{self, Doc, Error};

pub const ROOT: &str = "u6e";
/// The comment that keeps a setting from the planner.
pub const PIN: &str = "planner: fixed";

/// What keeps a radio's settings as they are.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Pins {
    pub radio: bool,
    pub channel: bool,
    pub power: bool,
}

/// One radio as the site file states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteRadio {
    pub band: Band,
    pub channel: u16,
    /// MHz; `None` for a width the planner does not handle.
    pub width: Option<u16>,
    /// dBm; `None` when the file states none.
    pub power: Option<i32>,
    /// Whether the AP takes the fleet's settings for the band.
    pub inherited: bool,
    pub pins: Pins,
}

/// The site file's country and its APs' radios, by AP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    pub country: Option<String>,
    pub aps: BTreeMap<String, Vec<SiteRadio>>,
}

fn pinned(doc: &Doc, path: &[&str]) -> Result<bool, Error> {
    Ok(doc.comment(path)?.is_some_and(|c| c.contains(PIN)))
}

/// Where a radio's keys are, and whether that is the fleet's.
fn radio_path<'a>(
    doc: &Doc,
    ap: &'a str,
    band: &'a str,
) -> Result<Option<(Vec<&'a str>, bool)>, Error> {
    let own = vec![ROOT, "aps", ap, "radios", band];
    if doc.has(&own)? {
        return Ok(Some((own, false)));
    }
    let fleet = vec![ROOT, "wifi", "radios", band];
    Ok(doc.has(&fleet)?.then_some((fleet, true)))
}

/// Where the power of `ap`'s radio on `band` is stated.
fn power_path<'a>(doc: &Doc, ap: &'a str, band: &'a str) -> Result<Vec<&'a str>, Error> {
    let own = vec![ROOT, "aps", ap, "txpower", band];
    if doc.has(&own)? {
        return Ok(own);
    }
    Ok(vec![ROOT, "wifi", "txpower", band])
}

fn number<T: std::str::FromStr>(doc: &Doc, path: &[&str]) -> Result<Option<T>, Error> {
    match doc.get(path)? {
        None => Ok(None),
        Some(v) => v
            .parse()
            .map(Some)
            .map_err(|_| Error(format!("{} is not a number: {v}", path.join(".")))),
    }
}

/// Reads the site file.
pub fn read(text: &str) -> Result<Site, Error> {
    let doc = Doc::parse(text)?;
    let country = doc.get(&[ROOT, "wifi", "country"])?;
    let mut aps = BTreeMap::new();
    for (ap, _) in doc.entries(&[ROOT, "aps"])? {
        let ap_pinned = pinned(&doc, &[ROOT, "aps", &ap])?;
        let mut radios = Vec::new();
        for band in BANDS {
            let key = channels::site_key(band);
            let Some((path, inherited)) = radio_path(&doc, &ap, key)? else {
                continue;
            };
            let at = |k: &'static str| [path.as_slice(), &[k]].concat();
            let Some(channel) = number(&doc, &at("channel"))? else {
                return Err(Error(format!("{} has no channel", path.join("."))));
            };
            let width = channels::width_of(band, |k| doc.get(&at_key(&path, k)).ok().flatten());
            let power_at = power_path(&doc, &ap, key)?;
            let pins = Pins {
                radio: ap_pinned || pinned(&doc, &path)?,
                channel: pinned(&doc, &at("channel"))?,
                power: pinned(&doc, &power_at)?,
            };
            radios.push(SiteRadio {
                band,
                channel,
                width,
                power: number(&doc, &power_at)?,
                inherited,
                pins,
            });
        }
        aps.insert(ap, radios);
    }
    Ok(Site { country, aps })
}

fn at_key<'a>(path: &[&'a str], key: &'a str) -> Vec<&'a str> {
    [path, &[key]].concat()
}

/// A radio's setting: its primary channel, width and power.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setting {
    pub channel: u16,
    pub width: u16,
    pub power: Option<i32>,
}

/// One radio's change, from what the file states now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub ap: String,
    pub band: Band,
    pub from: Setting,
    pub to: Setting,
}

/// The site file with `changes` made, or why not: a radio whose file no
/// longer states `from`, or a setting with no block.
pub fn edit(text: &str, changes: &[Change]) -> Result<String, Error> {
    let site = read(text)?;
    let mut doc = Doc::parse(text)?;
    for c in changes {
        let key = channels::site_key(c.band);
        let now = site
            .aps
            .get(&c.ap)
            .and_then(|r| r.iter().find(|r| r.band == c.band))
            .ok_or_else(|| Error(format!("{} has no {key} radio in the site file", c.ap)))?;
        let stated = Setting {
            channel: now.channel,
            width: now.width.unwrap_or(0),
            power: now.power,
        };
        if stated != c.from {
            return Err(Error(format!(
                "the site file changed: {}'s {key} radio is no longer as planned",
                c.ap
            )));
        }
        let own = vec![ROOT, "aps", c.ap.as_str(), "radios", key];
        if (c.from.channel, c.from.width) != (c.to.channel, c.to.width) {
            if now.inherited {
                // The AP gets its own copy of the fleet's radio first.
                for (k, raw) in doc.entries(&[ROOT, "wifi", "radios", key])? {
                    doc.set(&at_key(&own, &k), &raw)?;
                }
            }
            let chans = channels::block(c.band, c.to.channel, c.to.width).ok_or_else(|| {
                Error(format!(
                    "no {} MHz block holds channel {}",
                    c.to.width, c.to.channel
                ))
            })?;
            for k in channels::keys(c.band, &chans, c.to.channel) {
                let path = at_key(&own, k.name);
                let needed = c.to.width > 20 || matches!(k.name, "channel" | "op_class");
                if needed || doc.has(&path)? {
                    doc.set(&path, &k.value)?;
                }
            }
            if c.band == Band::B5 {
                let path = at_key(&own, "ht_capab");
                let old = doc.get(&path)?.unwrap_or_default();
                let new = channels::ht_capab(&old, c.band, c.to.channel, c.to.width);
                if new != old {
                    doc.set(&path, &yaml::quoted(&new))?;
                }
            }
        }
        if c.from.power != c.to.power {
            let Some(p) = c.to.power else {
                return Err(Error("a power cannot be taken away".into()));
            };
            doc.set(&[ROOT, "aps", &c.ap, "txpower", key], &p.to_string())?;
        }
    }
    Ok(doc.text())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A site file of the shape the planner edits, with documentation values.
    pub const SITE: &str = include_str!("../../tests/fixtures/site.yml");

    #[test]
    fn reads_radios_power_and_pins() {
        let s = read(SITE).unwrap();
        assert_eq!(s.country.as_deref(), Some("KR"));
        let ap1 = &s.aps["ap1"];
        let ap2 = &s.aps["ap2"];
        let r = |rs: &[SiteRadio], b| rs.iter().find(|r| r.band == b).cloned().unwrap();
        let a24 = r(ap1, Band::B24);
        assert_eq!(
            (a24.channel, a24.width, a24.power, a24.inherited),
            (6, Some(20), Some(20), true)
        );
        let a5 = r(ap1, Band::B5);
        assert_eq!(
            (a5.channel, a5.width, a5.pins),
            (36, Some(80), Pins::default())
        );
        let b5 = r(ap2, Band::B5);
        assert_eq!((b5.channel, b5.width), (149, Some(80)));
        assert_eq!(
            b5.pins,
            Pins {
                channel: true,
                ..Pins::default()
            }
        );
        let b6 = r(ap2, Band::B6);
        assert_eq!((b6.channel, b6.width, b6.power), (69, Some(160), Some(18)));
        assert_eq!(r(ap1, Band::B6).width, Some(160));
    }

    fn change(ap: &str, band: Band, from: (u16, u16, i32), to: (u16, u16, i32)) -> Change {
        let s = |(channel, width, p): (u16, u16, i32)| Setting {
            channel,
            width,
            power: Some(p),
        };
        Change {
            ap: ap.into(),
            band,
            from: s(from),
            to: s(to),
        }
    }

    /// The (old, new) pairs of the lines an in-place edit changed.
    fn changed(a: &str, b: &str) -> Vec<(String, String)> {
        assert_eq!(a.lines().count(), b.lines().count());
        let pairs = a.lines().zip(b.lines()).filter(|(x, y)| x != y);
        pairs
            .map(|(x, y)| (x.trim().to_owned(), y.trim().to_owned()))
            .collect()
    }

    #[test]
    fn a_channel_and_width_change_edits_only_their_keys() {
        let out = edit(SITE, &[change("ap1", Band::B5, (36, 80, 23), (44, 40, 23))]).unwrap();
        let pair = |a: &str, b: &str| (a.to_owned(), b.to_owned());
        assert_eq!(
            changed(SITE, &out),
            [
                pair("channel: 36", "channel: 44"),
                pair("vht_oper_chwidth: 1", "vht_oper_chwidth: 0"),
                pair(
                    "vht_oper_centr_freq_seg0_idx: 42",
                    "vht_oper_centr_freq_seg0_idx: 46"
                ),
                pair("he_oper_chwidth: 1", "he_oper_chwidth: 0"),
                pair(
                    "he_oper_centr_freq_seg0_idx: 42",
                    "he_oper_centr_freq_seg0_idx: 46"
                ),
            ]
        );
        let r = read(&out).unwrap();
        let a5 = r.aps["ap1"].iter().find(|r| r.band == Band::B5).unwrap();
        assert_eq!((a5.channel, a5.width), (44, Some(40)));
        // HT40+ stays: 44 is the lower half of 44-48; 48 flips it.
        let out = edit(SITE, &[change("ap1", Band::B5, (36, 80, 23), (48, 40, 23))]).unwrap();
        assert!(
            changed(SITE, &out).contains(&pair("ht_capab: \"[HT40+]\"", "ht_capab: \"[HT40-]\""))
        );
        // 6 GHz states its width in its operating class too.
        let out = edit(
            SITE,
            &[change("ap1", Band::B6, (37, 160, 18), (37, 80, 18))],
        )
        .unwrap();
        assert_eq!(
            changed(SITE, &out),
            [
                pair("op_class: 134", "op_class: 133"),
                pair("he_oper_chwidth: 2", "he_oper_chwidth: 1"),
                pair(
                    "he_oper_centr_freq_seg0_idx: 47",
                    "he_oper_centr_freq_seg0_idx: 39"
                ),
            ]
        );
    }

    #[test]
    fn an_inherited_radio_gets_its_own_copy_and_power_its_own_key() {
        let out = edit(
            SITE,
            &[
                change("ap2", Band::B24, (6, 20, 20), (1, 20, 20)),
                change("ap1", Band::B6, (37, 160, 18), (37, 160, 21)),
            ],
        )
        .unwrap();
        let want = SITE
            .replace(
                "          he_6ghz_reg_pwr_type: 0\n    ap2:",
                "          he_6ghz_reg_pwr_type: 0\n      txpower:\n        \"6\": 21\n    ap2:",
            )
            .replace(
                "          he_6ghz_reg_pwr_type: 0\n\n  # The test client",
                "          he_6ghz_reg_pwr_type: 0\n        \"24\":\n          hw_mode: g\n          channel: 1\n\n  # The test client",
            );
        assert_eq!(out, want);
        let r = read(&out).unwrap();
        let get = |ap: &str, b| r.aps[ap].iter().find(|r| r.band == b).cloned().unwrap();
        assert_eq!(
            (
                get("ap2", Band::B24).channel,
                get("ap2", Band::B24).inherited
            ),
            (1, false)
        );
        assert_eq!(get("ap1", Band::B24).channel, 6);
        assert_eq!(get("ap1", Band::B6).power, Some(21));
        assert_eq!(get("ap2", Band::B6).power, Some(18));
    }

    #[test]
    fn a_file_changed_since_the_plan_is_refused() {
        let stale = change("ap1", Band::B5, (40, 80, 23), (44, 40, 23));
        assert!(
            edit(SITE, &[stale])
                .unwrap_err()
                .0
                .contains("no longer as planned")
        );
        let none = change("ap9", Band::B5, (36, 80, 23), (44, 40, 23));
        assert!(edit(SITE, &[none]).is_err());
    }
}
