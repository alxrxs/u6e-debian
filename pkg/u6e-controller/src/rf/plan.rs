//! The RF planner's scoring: for each radio of the site file, the setting
//! (primary channel, width, power) its measured hours say serves its clients
//! best within the site's constraints, with the effect it predicts.
//!
//! - **Constraints.** A setting is one of the country's channels in the
//!   configured table (DFS ones only when allowed), at a configured width, on
//!   a 6 GHz preferred scanning channel (PSC), sharing no spectrum with a
//!   radio of another AP of the site, and at no more power than the table
//!   allows. What the site file keeps (`planner: fixed`), a radio whose AP is
//!   away or runs other than the file says, keeps its channel; its spectrum
//!   is then taken first, so the others plan around it.
//! - **Score.** The airtime-fair (harmonic mean) throughput of its clients:
//!   for each signal bin of the window's client time, the Shannon rate (with
//!   a 6 dB implementation gap, capped at 1024-QAM 5/6) at the width and the
//!   SNR there (signal less noise, less 3 dB per doubling of the width, plus
//!   the change of power), times the air left by other networks (the foreign
//!   busy share). Busy predicted = foreign busy + its own airtime, scaled by
//!   how much faster its clients' frames go.
//! - **Power** is a rule, as the score always wants more of it: the weakest
//!   tenth of the clients is brought to 25 dB SNR within the limit, and power
//!   is given back when even that tenth is 15 dB above it.
//! - **Measured only.** Without scans of other channels, a channel's foreign
//!   busy is known only where one of the site's radios spent hours, so a
//!   radio moves only onto measured spectrum, or off a conflict; and only for
//!   a 15 % better score. Nothing here is applied: a plan is a proposal.

use std::collections::BTreeMap;

use u6e_proto::msg::{Band, Radio, Snapshot};

use super::channels::{self, BANDS};
use super::history::{self, History, Hour, RSSI_BINS};
use super::site::{Setting, Site, SiteRadio};

/// A range of a band's channels a country allows, with its power limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowed {
    pub lo: u16,
    pub hi: u16,
    pub max_dbm: i32,
    pub dfs: bool,
}

/// What the planner may choose from (see `config`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rules {
    pub window_hours: u64,
    pub dfs: bool,
    /// The widths per band, in `BANDS`' order.
    pub widths: [Vec<u16>; 3],
    /// Per country, its channels per band.
    pub countries: BTreeMap<String, [Vec<Allowed>; 3]>,
}

/// The SNR the weakest tenth of a radio's clients is brought to, dB.
pub const TARGET_SNR: f64 = 25.0;
/// How much better a setting must score before a radio is moved to it.
pub const GAIN: f64 = 0.15;
/// How far above the target the weakest tenth must be before power goes.
pub const HEADROOM: f64 = 15.0;
/// The most power is lowered below the limit, dB.
pub const POWER_RANGE: i32 = 6;
/// A power change smaller than this is not proposed, dB.
pub const DEADBAND: f64 = 2.0;
/// The rate bound: Shannon's, less an implementation gap, up to the bits a
/// symbol of 1024-QAM 5/6 carries.
const GAP_DB: f64 = 6.0;
const CAP_BITS: f64 = 8.3;

fn band_index(b: Band) -> usize {
    BANDS.iter().position(|x| *x == b).expect("a band")
}

fn band_name(b: Band) -> &'static str {
    match b {
        Band::B24 => "2.4 GHz",
        Band::B5 => "5 GHz",
        Band::B6 => "6 GHz",
    }
}

/// What the window measured of one radio on one channel and width.
#[derive(Debug, Clone, PartialEq)]
pub struct Measure {
    /// The hours that hold some of it.
    pub hours: usize,
    pub busy: f64,
    /// Its own transmissions and its clients' frames to it, % of the time.
    pub own: f64,
    /// The rest of the busy time: other networks and interference.
    pub foreign: f64,
    pub noise: f64,
    /// The clients associated on average.
    pub clients: f64,
    /// Client-seconds per signal bin.
    pub rssi: [f64; RSSI_BINS],
}

fn measure<'a>(hours: impl Iterator<Item = &'a Hour>) -> Option<Measure> {
    let (mut n, mut secs, mut active, mut busy, mut own, mut noise) =
        (0, 0.0, 0u64, 0u64, 0u64, 0.0);
    let mut rssi = [0.0; RSSI_BINS];
    for h in hours {
        n += 1;
        secs += h.secs;
        active += h.active_ms;
        busy += h.busy_ms;
        own += (h.tx_ms + h.own_rx_ms).min(h.busy_ms);
        noise += h.noise;
        for (a, b) in rssi.iter_mut().zip(h.rssi) {
            *a += f64::from(b);
        }
    }
    if active == 0 || secs <= 0.0 {
        return None;
    }
    let pct = |ms: u64| ms as f64 * 100.0 / active as f64;
    Some(Measure {
        hours: n,
        busy: pct(busy),
        own: pct(own),
        foreign: pct(busy - own),
        noise: noise / secs,
        clients: rssi.iter().sum::<f64>() / secs,
        rssi,
    })
}

/// Foreign busy time and survey time per band and 20 MHz channel, ms, from
/// every radio's hours: a radio's survey stands for its whole block.
type Spectrum = [BTreeMap<u16, (f64, f64)>; 3];

fn spectrum(history: &History) -> Spectrum {
    let mut s: Spectrum = Default::default();
    for (_, radio) in history.all() {
        let b = band_index(radio.band);
        for h in &radio.hours {
            let Some(chans) = channels::block(radio.band, h.channel, h.width) else {
                continue;
            };
            let own = (h.tx_ms + h.own_rx_ms).min(h.busy_ms);
            for c in chans {
                let e = s[b].entry(c).or_default();
                e.0 += (h.busy_ms - own) as f64;
                e.1 += h.active_ms as f64;
            }
        }
    }
    s
}

/// The foreign busy % of a block: its busiest channel's, when every one of
/// them was measured.
fn foreign_of(s: &Spectrum, band: Band, chans: &[u16]) -> Option<f64> {
    let per = chans.iter().map(|c| {
        let (f, a) = s[band_index(band)].get(c)?;
        (*a > 0.0).then(|| f * 100.0 / a)
    });
    per.collect::<Option<Vec<f64>>>()?
        .into_iter()
        .reduce(f64::max)
}

/// The clients as (SNR, client-seconds), or one nominal client at the
/// target when none was heard.
fn clients(m: Option<&Measure>) -> (Vec<(f64, f64)>, bool) {
    let heard: Vec<_> = m
        .map(|m| {
            let bins = m.rssi.iter().enumerate().filter(|(_, w)| **w > 0.0);
            bins.map(|(i, w)| (history::bin_dbm(i) - m.noise, *w))
                .collect()
        })
        .unwrap_or_default();
    if heard.is_empty() {
        (vec![(TARGET_SNR, 1.0)], false)
    } else {
        (heard, true)
    }
}

/// The SNR of the weakest tenth of the client time.
fn tenth(clients: &[(f64, f64)]) -> f64 {
    let total: f64 = clients.iter().map(|c| c.1).sum();
    let mut sorted = clients.to_vec();
    sorted.sort_by(|a, b| a.0.total_cmp(&b.0));
    let mut seen = 0.0;
    for (snr, w) in &sorted {
        seen += w;
        if seen >= total * 0.1 {
            return *snr;
        }
    }
    sorted.last().map_or(TARGET_SNR, |c| c.0)
}

/// The rate of `width` MHz at `snr` dB, Mbit/s by the bound above.
fn rate(width: u16, snr: f64) -> f64 {
    let s = 10f64.powf((snr - GAP_DB) / 10.0);
    f64::from(width) * (1.0 + s).log2().min(CAP_BITS)
}

/// How a width and a power change move the SNR, dB.
fn snr_change(from: u16, to: u16, dpower: i32) -> f64 {
    f64::from(dpower) - 10.0 * (f64::from(to) / f64::from(from)).log10()
}

/// The score of a setting and how its airtime compares with now's.
fn score(clients: &[(f64, f64)], from: u16, to: u16, dpower: i32, foreign: f64) -> (f64, f64) {
    let d = snr_change(from, to, dpower);
    let (mut w, mut now, mut then) = (0.0, 0.0, 0.0);
    for (snr, weight) in clients {
        w += weight;
        now += weight / rate(from, *snr);
        then += weight / rate(to, snr + d);
    }
    ((1.0 - foreign / 100.0).max(0.0) * w / then, then / now)
}

/// One radio's proposal.
#[derive(Debug, Clone, PartialEq)]
pub struct Proposal {
    pub ap: String,
    /// The radio's name, as its AP names it (`radio5`).
    pub radio: String,
    pub band: Band,
    pub current: Setting,
    pub proposed: Setting,
    /// What the window measured on its current setting.
    pub measure: Option<Measure>,
    pub predicted_busy: Option<f64>,
    /// The weakest tenth's SNR now and the change the proposal makes to it.
    pub snr: Option<f64>,
    pub snr_change: f64,
    /// Whether the prediction rests on measured spectrum.
    pub measured: bool,
    /// Why its channel stays, if something keeps it.
    pub kept: Option<String>,
    pub reason: String,
}

impl Proposal {
    pub fn key(&self) -> String {
        format!("{}/{}", self.ap, self.radio)
    }

    pub fn changes(&self) -> bool {
        self.current != self.proposed
    }
}

/// The proposals, with what the plan as a whole should say.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    pub radios: Vec<Proposal>,
    pub notes: Vec<String>,
}

/// One radio being decided.
struct Item<'a> {
    ap: &'a str,
    site: &'a SiteRadio,
    live: Option<&'a Radio>,
    measure: Option<Measure>,
    /// Why its channel stays.
    kept: Option<String>,
    /// Whether its power stays.
    power_kept: bool,
}

struct Ctx<'a> {
    rules: &'a Rules,
    table: Option<(&'a str, &'a [Vec<Allowed>; 3])>,
    spectrum: Spectrum,
    /// The blocks already decided: band, channels, whose.
    taken: Vec<(Band, Vec<u16>, String)>,
}

impl Ctx<'_> {
    /// The block and power limit of a setting the radio of `ap` may have,
    /// or why it may not.
    fn allowed(
        &self,
        ap: &str,
        band: Band,
        primary: u16,
        width: u16,
    ) -> Result<(Vec<u16>, i32), String> {
        let Some((country, table)) = self.table else {
            return Err("there is no channel table for the site's country".into());
        };
        if !self.rules.widths[band_index(band)].contains(&width) {
            return Err(format!("{width} MHz is not a width it may use"));
        }
        let chans = channels::block(band, primary, width)
            .ok_or_else(|| format!("no {width} MHz block holds channel {primary}"))?;
        if band == Band::B6 && !channels::psc(primary) {
            return Err(format!(
                "channel {primary} is no preferred scanning channel"
            ));
        }
        let mut max = i32::MAX;
        for c in &chans {
            let range = table[band_index(band)]
                .iter()
                .find(|r| (r.lo..=r.hi).contains(c));
            let Some(r) = range else {
                return Err(format!("channel {c} is not one {country} allows here"));
            };
            if r.dfs && !self.rules.dfs {
                return Err(format!("channel {c} needs DFS"));
            }
            max = max.min(r.max_dbm);
        }
        let clash = self.taken.iter().find(|(b, other, who)| {
            *b == band && who != ap && channels::overlap(band, &chans, other)
        });
        if let Some((_, other, who)) = clash {
            return Err(format!(
                "it would share spectrum with {who}'s channel {}",
                other[0]
            ));
        }
        Ok((chans, max))
    }
}

/// The power to propose at a setting whose limit is `max`, and why, for
/// clients whose weakest tenth is at `tenth` dB there.
fn power(
    now: Option<i32>,
    max: i32,
    kept: bool,
    tenth: Option<f64>,
    country: &str,
) -> (Option<i32>, Option<String>) {
    let Some(p) = now else {
        return (None, None);
    };
    if p > max {
        let why = format!("{p} dBm is above the {max} dBm {country} allows");
        return if kept {
            (now, Some(format!("{why}, but its power is kept")))
        } else {
            (Some(max), Some(why))
        };
    }
    let Some(s) = tenth.filter(|_| !kept) else {
        return (now, None);
    };
    let want = TARGET_SNR - s;
    if want > DEADBAND && p < max {
        let next = (p + want.ceil() as i32).min(max);
        let why = format!(
            "the weakest tenth of its clients is at {s:.0} dB SNR, under the {TARGET_SNR:.0} dB aimed at"
        );
        return (Some(next), Some(why));
    }
    let spare = -want - HEADROOM;
    let floor = (max - POWER_RANGE).min(p);
    if spare > DEADBAND && p > floor {
        let next = (p - spare.floor() as i32).max(floor);
        let why = format!(
            "even the weakest tenth of its clients is at {s:.0} dB SNR: less power reaches fewer neighbours"
        );
        return (Some(next), Some(why));
    }
    (now, None)
}

/// The plan for the radios of `site`. `live` holds the snapshot of each AP
/// this controller serves (none while it is away); an AP of the site it does
/// not serve keeps its spectrum.
pub fn plan(
    site: &Site,
    live: &BTreeMap<String, Option<&Snapshot>>,
    history: &History,
    rules: &Rules,
) -> Plan {
    let country = site.country.as_deref().unwrap_or("");
    let table = rules
        .countries
        .get_key_value(country)
        .map(|(c, t)| (c.as_str(), t));
    let mut notes = vec![format!(
        "No AP reports scans of other channels: the plan rests on each radio's survey of its own \
         channel and its clients' signal over the last {} h, and moves a radio only onto spectrum \
         one of the site's radios has measured, or off a conflict.",
        rules.window_hours
    )];
    if table.is_none() {
        notes.push(format!("The configuration has no channel table for the site's country ({country:?}): nothing is proposed."));
    }
    let mut items = Vec::new();
    for (ap, radios) in &site.aps {
        let snap = live.get(ap);
        for sr in radios {
            let radio = snap
                .copied()
                .flatten()
                .and_then(|s| s.radios.iter().find(|r| r.band == sr.band));
            let width = sr.width.unwrap_or(20);
            let hours = history
                .of(ap)
                .filter(|(_, h)| h.band == sr.band)
                .flat_map(|(_, h)| &h.hours);
            // Measured on what it runs: a radio out of step with the site file
            // runs other than the file says.
            let runs = radio.map_or((sr.channel, width), |r| (r.channel, r.width_mhz));
            let measure = measure(hours.filter(|h| (h.channel, h.width) == runs));
            // What keeps the whole radio as it is.
            let whole = match (snap, radio) {
                (None, _) => Some(format!("{ap} is not one of this controller's APs")),
                (Some(None), _) => Some(format!("{ap} is not connected")),
                (_, None) => Some(format!("{ap} reports no {} radio", band_name(sr.band))),
                (_, Some(r)) if !r.up => Some("the radio is down".into()),
                _ if sr.width.is_none() => {
                    Some("its width is one the planner does not handle".into())
                }
                (_, Some(r)) if (r.channel, r.width_mhz) != (sr.channel, width) => Some(format!(
                    "it runs channel {} at {} MHz, but the site file says channel {} at {width} MHz: \
                     that change has not reached it yet",
                    r.channel, r.width_mhz, sr.channel
                )),
                _ if sr.pins.radio => Some("the site file keeps it (planner: fixed)".into()),
                _ => None,
            };
            let power_kept = sr.pins.power || whole.is_some();
            let channel = sr
                .pins
                .channel
                .then(|| "the site file keeps its channel (planner: fixed)".to_owned());
            let kept = whole.or(channel);
            items.push(Item {
                ap,
                site: sr,
                live: radio,
                measure,
                kept,
                power_kept,
            });
        }
    }
    // What stays takes its spectrum first; then the busiest radios choose.
    let clients_of = |i: &Item| i.measure.as_ref().map_or(0.0, |m| m.clients);
    items.sort_by(|a, b| {
        let (ba, bb) = (band_index(a.site.band), band_index(b.site.band));
        (a.kept.is_none().cmp(&b.kept.is_none()))
            .then(clients_of(b).total_cmp(&clients_of(a)))
            .then((a.ap, ba).cmp(&(b.ap, bb)))
    });
    let mut ctx = Ctx {
        rules,
        table,
        spectrum: spectrum(history),
        taken: Vec::new(),
    };
    let mut radios = Vec::new();
    for item in &items {
        let p = decide(&ctx, item, country);
        let chans = channels::block(p.band, p.proposed.channel, p.proposed.width)
            .unwrap_or_else(|| vec![p.proposed.channel]);
        ctx.taken.push((p.band, chans, item.ap.to_owned()));
        radios.push(p);
    }
    radios.sort_by(|a, b| (&a.ap, band_index(a.band)).cmp(&(&b.ap, band_index(b.band))));
    Plan { radios, notes }
}

/// A setting a radio may take, as it would score.
#[derive(Debug, Clone)]
struct Candidate {
    primary: u16,
    width: u16,
    power: Option<i32>,
    power_why: Option<String>,
    foreign: f64,
    measured: bool,
    score: f64,
}

fn delta(to: Option<i32>, from: Option<i32>) -> i32 {
    to.zip(from).map_or(0, |(a, b)| a - b)
}

/// What the radio would be at `at` (primary, width), if it may be.
fn candidate(
    ctx: &Ctx,
    item: &Item,
    clients: &[(f64, f64)],
    tenth: Option<f64>,
    at: (u16, u16),
    country: &str,
) -> Option<Candidate> {
    let sr = item.site;
    let (primary, width) = at;
    let from = sr.width.unwrap_or(20);
    let (chans, max) = ctx.allowed(item.ap, sr.band, primary, width).ok()?;
    let now = item.measure.as_ref().map(|m| m.foreign);
    let (foreign, measured) = if at == (sr.channel, from) {
        (now, now.is_some())
    } else {
        let there = foreign_of(&ctx.spectrum, sr.band, &chans);
        (there.or(now), there.is_some() && now.is_some())
    };
    let foreign = foreign.unwrap_or(0.0);
    let tenth = tenth.map(|t| t + snr_change(from, width, 0));
    let (power, power_why) = power(sr.power, max, item.power_kept, tenth, country);
    let score = score(clients, from, width, delta(power, sr.power), foreign).0;
    Some(Candidate {
        primary,
        width,
        power,
        power_why,
        foreign,
        measured,
        score,
    })
}

/// Whether `a` is a better setting than `b`: measured first when
/// `measured_first`, then by score; a tie keeps `b`, the lower channel.
fn better(a: &Candidate, b: &Candidate, measured_first: bool) -> bool {
    if measured_first && a.measured != b.measured {
        return a.measured;
    }
    a.score > b.score
}

/// The setting a radio is to take, and why.
fn choose(
    ctx: &Ctx,
    item: &Item,
    clients: &[(f64, f64)],
    tenth: Option<f64>,
    country: &str,
) -> (Option<Candidate>, Vec<String>) {
    let sr = item.site;
    let width = sr.width.unwrap_or(20);
    let here = ctx.allowed(item.ap, sr.band, sr.channel, width).map(drop);
    let stay = candidate(ctx, item, clients, tenth, (sr.channel, width), country);
    if let Some(kept) = &item.kept {
        let mut why = vec![kept.clone()];
        why.extend(here.err().map(|e| format!("though {e}")));
        return (stay, why);
    }
    let widths = &ctx.rules.widths[band_index(sr.band)];
    let all: Vec<Candidate> = channels::all(sr.band)
        .flat_map(|p| widths.iter().map(move |&w| (p, w)))
        .filter_map(|at| candidate(ctx, item, clients, tenth, at, country))
        .collect();
    let Some(stay) = stay else {
        // It may not stay: the best it may have, measured or not.
        let e = here.err().unwrap_or_default();
        let best = all
            .into_iter()
            .reduce(|a, b| if better(&b, &a, true) { b } else { a });
        let Some(best) = best else {
            return (
                None,
                vec![format!("{e}, and no setting it may use is left")],
            );
        };
        let mut why = vec![format!("{e}: it moves")];
        if !best.measured {
            why.push("onto spectrum none of the site's radios has measured".into());
        }
        return (Some(best), why);
    };
    // A move it is free not to make must rest on measurements and be worth it.
    let moves = all
        .iter()
        .filter(|c| c.measured && (c.primary, c.width) != (sr.channel, width));
    match moves.reduce(|a, b| if better(b, a, false) { b } else { a }) {
        Some(b) if b.score >= stay.score * (1.0 + GAIN) => {
            let why = format!(
                "channel {} at {} MHz measured {:.0} % busy with other networks, against {:.0} % on its own: \
                 {:.0} % more for its clients",
                b.primary,
                b.width,
                b.foreign,
                stay.foreign,
                (b.score / stay.score - 1.0) * 100.0
            );
            (Some(b.clone()), vec![why])
        }
        _ => (Some(stay), Vec::new()),
    }
}

fn decide(ctx: &Ctx, item: &Item, country: &str) -> Proposal {
    let sr = item.site;
    let width = sr.width.unwrap_or(20);
    let current = Setting {
        channel: sr.channel,
        width,
        power: sr.power,
    };
    let m = item.measure.as_ref();
    let (clients, heard) = clients(m);
    let tenth = heard.then(|| tenth(&clients));
    let (chosen, mut why) = choose(ctx, item, &clients, tenth, country);
    let radio = item.live.map_or_else(
        || format!("radio{}", channels::site_key(sr.band)),
        |r| r.phy.clone(),
    );
    let mut p = Proposal {
        ap: item.ap.to_owned(),
        radio,
        band: sr.band,
        current,
        proposed: current,
        measure: item.measure.clone(),
        predicted_busy: m.map(|m| m.busy),
        snr: tenth,
        snr_change: 0.0,
        measured: m.is_some(),
        kept: item.kept.clone(),
        reason: String::new(),
    };
    if let Some(c) = chosen {
        let dp = delta(c.power, sr.power);
        p.proposed = Setting {
            channel: c.primary,
            width: c.width,
            power: c.power,
        };
        p.snr_change = snr_change(width, c.width, dp);
        p.measured = c.measured;
        if let Some(m) = m {
            let airtime = score(&clients, width, c.width, dp, c.foreign).1;
            p.predicted_busy = Some((c.foreign + m.own * airtime).min(100.0));
        }
        why.extend(c.power_why);
    }
    if m.is_none() && item.kept.is_none() && !p.changes() {
        why.push(format!(
            "nothing was measured on it in the last {} h",
            ctx.rules.window_hours
        ));
    }
    if why.is_empty() {
        why.push(format!(
            "no setting it may use scores {:.0} % better",
            GAIN * 100.0
        ));
    }
    p.reason = why.join("; ");
    p
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use u6e_proto::msg::{Bss, RateMode, Station};

    use super::*;
    use crate::rf::site;

    const SITE: &str = include_str!("../../tests/fixtures/site.yml");

    fn allowed(lo: u16, hi: u16, max_dbm: i32, dfs: bool) -> Allowed {
        Allowed {
            lo,
            hi,
            max_dbm,
            dfs,
        }
    }

    fn rules() -> Rules {
        let kr = [
            vec![allowed(1, 13, 23, false)],
            vec![
                allowed(36, 48, 23, false),
                allowed(52, 64, 20, true),
                allowed(149, 177, 23, false),
            ],
            vec![allowed(1, 93, 24, false)],
        ];
        Rules {
            window_hours: 24,
            dfs: false,
            widths: [vec![20], vec![20, 40, 80], vec![20, 40, 80, 160]],
            countries: [("KR".to_owned(), kr)].into(),
        }
    }

    /// One radio of a simulated AP over a minute: its channel and width, the
    /// share of the minute busy and its own share of that, and its clients'
    /// signals.
    struct Sim {
        band: Band,
        channel: u16,
        width: u16,
        busy: u64,
        own: u64,
        signals: Vec<i8>,
    }

    fn sim(band: Band, channel: u16, width: u16, busy: u64, own: u64, signals: &[i8]) -> Sim {
        Sim {
            band,
            channel,
            width,
            busy,
            own,
            signals: signals.to_vec(),
        }
    }

    /// The radios of the fixture's ap1 and ap2 as their site file says.
    fn fixture(ap: &str) -> Vec<Sim> {
        match ap {
            "ap1" => vec![
                sim(Band::B24, 6, 20, 30, 10, &[-60]),
                sim(Band::B5, 36, 80, 20, 10, &[-55]),
                sim(Band::B6, 37, 160, 5, 2, &[-50]),
            ],
            _ => vec![
                sim(Band::B24, 6, 20, 30, 10, &[]),
                sim(Band::B5, 149, 80, 20, 10, &[-55]),
                sim(Band::B6, 69, 160, 5, 2, &[-50]),
            ],
        }
    }

    fn station(mac: [u8; 6], bss: u16, signal: i8) -> Station {
        Station {
            mac,
            bss,
            signal,
            signal_avg: signal,
            rx_bytes: 0,
            tx_bytes: 0,
            rx_packets: 0,
            tx_packets: 0,
            tx_retries: 0,
            tx_failed: 0,
            tx_rate_kbps: 0,
            rx_rate_kbps: 0,
            tx_mcs: 0,
            rx_mcs: 0,
            tx_mode: RateMode::He,
            rx_mode: RateMode::He,
            tx_nss: 2,
            rx_nss: 2,
            tx_airtime_us: 0,
            rx_airtime_us: 0,
            inactive_ms: 0,
            connected_s: 0,
            vlan: 0,
        }
    }

    /// Two snapshots a minute apart of an AP with these radios: the first
    /// with every counter at zero.
    fn snapshots(radios: &[Sim]) -> (Snapshot, Snapshot) {
        let snap = |minute: u64| {
            let mut stations = Vec::new();
            let mut bsss = Vec::new();
            let mut list = Vec::new();
            for (i, r) in radios.iter().enumerate() {
                let phy = format!("radio{}", channels::site_key(r.band));
                bsss.push(Bss {
                    ifname: format!("wlan{i}"),
                    bssid: [2, 0, 0, 0, 1, i as u8],
                    ssid: "ssid-a".into(),
                    phy: phy.clone(),
                    vlan: 0,
                });
                for (j, s) in r.signals.iter().enumerate() {
                    stations.push(station([2, 0, 0, 0, i as u8, j as u8], i as u16, *s));
                }
                let ms = minute * 60_000;
                list.push(Radio {
                    phy,
                    band: r.band,
                    channel: r.channel,
                    width_mhz: r.width,
                    txpower_mbm: 2000,
                    noise_dbm: -95,
                    active_ms: ms,
                    busy_ms: ms * r.busy / 100,
                    rx_ms: 0,
                    tx_ms: ms * r.own / 100,
                    up: true,
                });
            }
            Snapshot {
                seq: minute + 1,
                uptime_s: 0,
                load_milli: 0,
                mem_avail_kb: 0,
                nss_load_pct: 0,
                temps: Vec::new(),
                radios: list,
                bsss,
                stations,
                config_sha256: None,
                clock_synced: true,
            }
        };
        (snap(0), snap(1))
    }

    const NOW: u64 = 500_000 * 3600;

    /// The AP's minute, `hours_ago`, in the history; its later snapshot.
    fn seed(h: &mut History, ap: &str, radios: &[Sim], hours_ago: u64) -> Snapshot {
        let (a, b) = snapshots(radios);
        let at = UNIX_EPOCH + Duration::from_secs(NOW - hours_ago * 3600);
        h.observe(ap, &a, at, &b, at + Duration::from_secs(60));
        b
    }

    fn run(site: &str, snaps: &[(&str, Option<&Snapshot>)], h: &History, rules: &Rules) -> Plan {
        let site = site::read(site).unwrap();
        let live = snaps.iter().map(|(a, s)| (a.to_string(), *s)).collect();
        plan(&site, &live, h, rules)
    }

    fn of<'a>(p: &'a Plan, key: &str) -> &'a Proposal {
        p.radios
            .iter()
            .find(|r| r.key() == key)
            .unwrap_or_else(|| panic!("no {key}"))
    }

    fn at(s: &Setting) -> (u16, u16, Option<i32>) {
        (s.channel, s.width, s.power)
    }

    #[test]
    fn two_aps_on_one_channel_part_and_the_busier_one_stays() {
        let mut h = History::new(24);
        let a = seed(&mut h, "ap1", &fixture("ap1"), 0);
        let b = seed(&mut h, "ap2", &fixture("ap2"), 0);
        let p = run(SITE, &[("ap1", Some(&a)), ("ap2", Some(&b))], &h, &rules());
        let stay = of(&p, "ap1/radio24");
        assert!(!stay.changes(), "{stay:?}");
        let moved = of(&p, "ap2/radio24");
        assert!(moved.changes());
        let ch = moved.proposed.channel;
        assert!(ch <= 2 || ch >= 10, "channel {ch} still overlaps 6");
        assert!(
            moved.reason.contains("share spectrum with ap1's channel 6"),
            "{}",
            moved.reason
        );
        assert!(
            moved
                .reason
                .contains("none of the site's radios has measured")
        );
        assert!(!moved.measured);
        // Nothing else had a reason to change.
        let changed: Vec<_> = p
            .radios
            .iter()
            .filter(|r| r.changes())
            .map(Proposal::key)
            .collect();
        assert_eq!(changed, ["ap2/radio24"]);
        assert!(p.notes[0].contains("No AP reports scans"));
    }

    #[test]
    fn what_the_site_keeps_stays_and_6ghz_keeps_to_psc() {
        let mut h = History::new(24);
        let a = seed(&mut h, "ap1", &fixture("ap1"), 0);
        let b = seed(&mut h, "ap2", &fixture("ap2"), 0);
        let p = run(SITE, &[("ap1", Some(&a)), ("ap2", Some(&b))], &h, &rules());
        let kept = of(&p, "ap2/radio5");
        assert_eq!(
            kept.kept.as_deref(),
            Some("the site file keeps its channel (planner: fixed)")
        );
        assert_eq!(at(&kept.proposed), (149, 80, Some(23)));
        // ap1's 6 GHz radio had no move worth making, and no 6 GHz radio
        // was offered a primary off the PSC.
        for r in p.radios.iter().filter(|r| r.band == Band::B6) {
            assert!(channels::psc(r.proposed.channel), "{r:?}");
        }
        // A whole AP kept: none of its radios changes.
        let pinned = SITE.replace("    ap2:\n", "    ap2:  # planner: fixed\n");
        let p = run(
            &pinned,
            &[("ap1", Some(&a)), ("ap2", Some(&b))],
            &h,
            &rules(),
        );
        assert!(
            p.radios
                .iter()
                .filter(|r| r.ap == "ap2")
                .all(|r| !r.changes())
        );
        // ap1 moves its 2.4 GHz radio instead.
        assert!(of(&p, "ap1/radio24").changes());
    }

    #[test]
    fn power_follows_the_weakest_clients_within_the_limit() {
        let mut h = History::new(24);
        let mut ap1 = fixture("ap1");
        // 6 GHz clients at 16 dB SNR: power goes from 18 to the 24 dBm limit.
        ap1[2].signals = vec![-80, -80, -50];
        let a = seed(&mut h, "ap1", &ap1, 0);
        let b = seed(&mut h, "ap2", &fixture("ap2"), 0);
        let p = run(SITE, &[("ap1", Some(&a)), ("ap2", Some(&b))], &h, &rules());
        let r6 = of(&p, "ap1/radio6");
        assert_eq!(at(&r6.proposed), (37, 160, Some(24)));
        // -80 dBm falls in the -80 to -78 bin: 16 dB over the -95 dBm floor.
        assert_eq!(r6.snr, Some(16.0));
        assert_eq!(r6.snr_change, 6.0);
        assert!(
            r6.reason
                .contains("weakest tenth of its clients is at 16 dB SNR"),
            "{}",
            r6.reason
        );
        // Faster frames take less air: the busy share predicted is lower.
        assert!(r6.predicted_busy.unwrap() < r6.measure.as_ref().unwrap().busy);
        // Above the table's limit: down to it, even with no client.
        let mut low = rules();
        low.countries.get_mut("KR").unwrap()[0] = vec![allowed(1, 13, 17, false)];
        let p = run(SITE, &[("ap1", Some(&a)), ("ap2", Some(&b))], &h, &low);
        let r24 = of(&p, "ap2/radio24");
        assert_eq!(r24.proposed.power, Some(17));
        assert!(
            r24.reason.contains("20 dBm is above the 17 dBm KR allows"),
            "{}",
            r24.reason
        );
        // Clients all close by give power back, at most 6 dB under the limit.
        let mut close = fixture("ap1");
        close[1].signals = vec![-30; 4];
        let mut h = History::new(24);
        let a = seed(&mut h, "ap1", &close, 0);
        let b = seed(&mut h, "ap2", &fixture("ap2"), 0);
        let p = run(SITE, &[("ap1", Some(&a)), ("ap2", Some(&b))], &h, &rules());
        assert_eq!(of(&p, "ap1/radio5").proposed.power, Some(23 - POWER_RANGE));
    }

    #[test]
    fn a_measured_quieter_channel_wins_when_it_is_worth_it() {
        let mut h = History::new(24);
        // ap1's 5 GHz radio spent an hour on 165-177, far quieter than its
        // own 36-48 now.
        let mut before = fixture("ap1");
        before[1] = sim(Band::B5, 165, 80, 8, 4, &[-55]);
        seed(&mut h, "ap1", &before, 3);
        let mut now = fixture("ap1");
        now[1].busy = 50;
        let a = seed(&mut h, "ap1", &now, 0);
        let b = seed(&mut h, "ap2", &fixture("ap2"), 0);
        let p = run(SITE, &[("ap1", Some(&a)), ("ap2", Some(&b))], &h, &rules());
        let r5 = of(&p, "ap1/radio5");
        assert_eq!(at(&r5.proposed), (165, 80, Some(23)), "{}", r5.reason);
        assert!(r5.measured);
        assert!(
            r5.reason
                .contains("measured 4 % busy with other networks, against 40 % on its own"),
            "{}",
            r5.reason
        );
        assert!(r5.predicted_busy.unwrap() < 20.0);
        // Not worth it: the same channel only a little quieter stays put.
        let mut h = History::new(24);
        let mut before = fixture("ap1");
        before[1] = sim(Band::B5, 165, 80, 15, 4, &[-55]);
        seed(&mut h, "ap1", &before, 3);
        let mut now = fixture("ap1");
        now[1].busy = 22;
        let a = seed(&mut h, "ap1", &now, 0);
        let p = run(SITE, &[("ap1", Some(&a)), ("ap2", Some(&b))], &h, &rules());
        assert!(!of(&p, "ap1/radio5").changes());
        // DFS channels are not offered unless the configuration allows them.
        assert!(
            p.radios
                .iter()
                .all(|r| !(52..=64).contains(&r.proposed.channel))
        );
    }

    #[test]
    fn a_radio_out_of_step_or_away_or_unmeasured_keeps_its_setting() {
        let h = History::new(24);
        let mut ahead = fixture("ap1");
        ahead[1].channel = 44;
        let (_, a) = snapshots(&ahead);
        let (_, b) = snapshots(&fixture("ap2"));
        let p = run(SITE, &[("ap1", Some(&a)), ("ap2", Some(&b))], &h, &rules());
        let r5 = of(&p, "ap1/radio5");
        assert!(!r5.changes());
        assert!(
            r5.reason
                .contains("it runs channel 44 at 80 MHz, but the site file says channel 36"),
            "{}",
            r5.reason
        );
        let r6 = of(&p, "ap1/radio6");
        assert!(!r6.changes());
        assert_eq!(r6.reason, "nothing was measured on it in the last 24 h");
        assert!(r6.measure.is_none() && r6.predicted_busy.is_none());
        // ap2 away: its spectrum is kept, so ap1 moves off its 2.4 GHz channel.
        let p = run(SITE, &[("ap1", Some(&a)), ("ap2", None)], &h, &rules());
        assert_eq!(
            of(&p, "ap2/radio24").kept.as_deref(),
            Some("ap2 is not connected")
        );
        assert!(of(&p, "ap1/radio24").changes());
        // An AP of the site that this controller does not serve, likewise.
        let p = run(SITE, &[("ap1", Some(&a))], &h, &rules());
        assert_eq!(
            of(&p, "ap2/radio6").kept.as_deref(),
            Some("ap2 is not one of this controller's APs")
        );
        // No table for the country: nothing it may use.
        let mut none = rules();
        none.countries.clear();
        let p = run(SITE, &[("ap1", Some(&a)), ("ap2", Some(&b))], &h, &none);
        assert!(p.notes[1].contains("no channel table"));
        assert!(
            p.radios
                .iter()
                .filter(|r| r.kept.is_none())
                .all(|r| r.reason.contains("no setting it may use is left"))
        );
    }

    #[test]
    fn the_score_prefers_air_and_width_and_the_tenth_is_the_weakest() {
        let one = [(30.0, 1.0)];
        assert!(score(&one, 80, 80, 0, 10.0).0 > score(&one, 80, 80, 0, 40.0).0);
        assert!(score(&one, 40, 80, 0, 10.0).0 > score(&one, 40, 40, 0, 10.0).0);
        let (_, airtime) = score(&one, 40, 80, 0, 0.0);
        assert!(airtime < 0.6, "{airtime}");
        let spread: Vec<_> = (0..10).map(|i| (f64::from(i) * 5.0, 1.0)).collect();
        assert_eq!(tenth(&spread), 0.0);
        assert_eq!(tenth(&[(12.0, 9.0), (40.0, 1.0)]), 12.0);
    }
}
