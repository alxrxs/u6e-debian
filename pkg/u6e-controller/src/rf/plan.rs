//! The RF planner's scoring: for each radio of the site file, the setting
//! (primary channel, width, power) its measured hours say serves its clients
//! best within the site's constraints, with the effect it predicts.
//!
//! - **Constraints.** A setting is one of the country's channels in the
//!   configured table (DFS ones only when allowed, and then taken there by
//!   the next configuration push, which runs the radar check a live switch
//!   cannot), at a configured width, on a 6 GHz
//!   preferred scanning channel (PSC), sharing no spectrum with a radio of
//!   another AP of the site, with the primary of any 20/40 MHz network of
//!   others the AP hears in its block (802.11 20/40 coexistence), and at no
//!   more power than the radio's own limit there: its primary channel's, as
//!   its AP reports it from the radio's own regulatory rules, or what it
//!   sends on its channel now when it holds itself below that. What the site file keeps (`planner:
//!   fixed`), a radio whose AP is away or runs other than the file says,
//!   keeps its channel; its spectrum is then taken first, so the others plan
//!   around it. `no_pri_sec_switch` keeps a radio's primary channel.
//! - **Score.** The airtime-fair (harmonic mean) throughput of its clients:
//!   for each signal bin of the window's client time, the Shannon rate (with
//!   a 6 dB implementation gap, capped at 1024-QAM 5/6) at the width and the
//!   SNR the clients hear (below), times the air left by other networks (the
//!   foreign busy share). Busy predicted = foreign busy + its own airtime,
//!   scaled by how much faster its clients' frames go.
//! - **Power.** The AP hears its clients (their signal is the uplink, which
//!   its own power does not change); what they hear of it is estimated from
//!   the path loss, their signal less the power a client is assumed to send
//!   at (`client_dbm`). Power is set so that the weakest tenth of the clients
//!   hear it at 25 dB SNR or more, and given back while even that tenth would
//!   hear it 15 dB above, within the limit and 6 dB under it. A change under
//!   3 dB is not proposed, and a power above the limit counts as the limit
//!   (the radio is held there: "clamped", never "not as planned"), so no
//!   change is proposed whose effect would be only that, and a plan applied
//!   is planned again as it is. A radio whose AP reports no limit keeps its
//!   power.
//! - **Measured only.** Without scans of other channels, a channel's foreign
//!   busy is known only where one of the site's radios spent hours, so a
//!   radio moves only onto measured spectrum, or off a conflict; and only for
//!   a 15 % better score. Nothing here is applied: a plan is a proposal.
//!   Proposals that move onto spectrum another radio leaves form a group,
//!   applied together or not at all.

use std::collections::BTreeMap;

use u6e_proto::msg::{Band, PowerLimit, Radio, Snapshot};

use super::channels::{self, BANDS};
use super::history::{self, History, Hour, RSSI_BINS};
use super::site::{Setting, Site, SiteRadio};

/// A range of a band's channels a country allows, and whether they need a
/// radar check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowed {
    pub lo: u16,
    pub hi: u16,
    pub dfs: bool,
}

/// What the planner may choose from (see `config`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rules {
    pub window_hours: u64,
    pub dfs: bool,
    /// The power a client is taken to send at, dBm.
    pub client_dbm: i32,
    /// The widths per band, in `BANDS`' order.
    pub widths: [Vec<u16>; 3],
    /// Per country, its channels per band.
    pub countries: BTreeMap<String, [Vec<Allowed>; 3]>,
}

/// A 20/40 MHz network of others an AP hears: its primary and secondary
/// channels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbour {
    pub band: Band,
    pub primary: u16,
    pub secondary: u16,
}

/// What a plan is made from.
pub struct Inputs<'a> {
    pub site: &'a Site,
    /// The snapshot of each AP this controller serves, none while it is
    /// away; an AP of the site it does not serve keeps its spectrum.
    pub live: &'a BTreeMap<String, Option<&'a Snapshot>>,
    pub history: &'a History,
    /// The 20/40 MHz networks of others each AP hears, by AP.
    pub neighbours: &'a BTreeMap<String, Vec<Neighbour>>,
    pub rules: &'a Rules,
}

/// The SNR the weakest tenth of a radio's clients is to hear it at, dB.
pub const TARGET_SNR: f64 = 25.0;
/// How much better a setting must score before a radio is moved to it.
pub const GAIN: f64 = 0.15;
/// How far above the target the weakest tenth may hear it before power goes.
pub const HEADROOM: f64 = 15.0;
/// The most power is lowered below the limit, dB.
pub const POWER_RANGE: i32 = 6;
/// The least power change proposed, dB.
pub const HYSTERESIS: i32 = 3;
/// The rate bound: Shannon's, less an implementation gap, up to the bits a
/// symbol of 1024-QAM 5/6 carries.
const GAP_DB: f64 = 6.0;
const CAP_BITS: f64 = 8.3;
/// A transmit power the radio reports this far from the file's is not yet
/// the file's, dB.
pub(crate) const POWER_SLACK: i32 = 2;

fn band_index(b: Band) -> usize {
    BANDS.iter().position(|x| *x == b).expect("a band")
}

pub fn band_name(b: Band) -> &'static str {
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

/// The clients as (the SNR the AP hears them at, client-seconds); empty
/// when none was heard.
fn clients(m: Option<&Measure>) -> Vec<(f64, f64)> {
    m.map(|m| {
        let bins = m.rssi.iter().enumerate().filter(|(_, w)| **w > 0.0);
        bins.map(|(i, w)| (history::bin_dbm(i) - m.noise, *w))
            .collect()
    })
    .unwrap_or_default()
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

/// What a wider channel costs every client's SNR, dB.
fn widening(from: u16, to: u16) -> f64 {
    10.0 * (f64::from(to) / f64::from(from)).log10()
}

/// The score of a setting and how its airtime compares with now's: the
/// clients hear the radio `now_db` and then `then_db` above the SNR it hears
/// them at.
fn score(
    clients: &[(f64, f64)],
    from: u16,
    to: u16,
    now_db: f64,
    then_db: f64,
    foreign: f64,
) -> (f64, f64) {
    let (mut w, mut now, mut then) = (0.0, 0.0, 0.0);
    for (snr, weight) in clients {
        w += weight;
        now += weight / rate(from, snr + now_db);
        then += weight / rate(to, snr + then_db);
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
    /// As the site file states it.
    pub current: Setting,
    pub proposed: Setting,
    /// What the radio runs, as its AP reports it.
    pub runs: Option<Setting>,
    /// What the window measured on what it runs.
    pub measure: Option<Measure>,
    pub predicted_busy: Option<f64>,
    /// The SNR the weakest tenth of its clients hears it at now, and the
    /// change the proposal makes to it.
    pub snr: Option<f64>,
    pub snr_change: f64,
    /// Whether the prediction rests on measured spectrum.
    pub measured: bool,
    /// Why its channel stays, if something keeps it.
    pub kept: Option<String>,
    /// It runs other than the site file says: a change not taken to it yet.
    pub pending: bool,
    /// What the site file says it runs, as the radio would take it: its
    /// power no more than its primary channel allows (the driver's limit),
    /// and whether its block needs a radar check (DFS).
    pub planned_power: Option<i32>,
    pub planned_dfs: bool,
    /// Why it is not moved live (a block that needs a radar check), when it
    /// is not.
    pub restart: Option<String>,
    /// The proposals it is applied with or not at all, by group number.
    pub group: Option<u32>,
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
    pending: bool,
    /// The site file's power as the radio would take it, and whether its
    /// block needs DFS.
    planned_power: Option<i32>,
    planned_dfs: bool,
    /// Whether its power stays.
    power_kept: bool,
}

struct Ctx<'a> {
    rules: &'a Rules,
    country: &'a str,
    table: Option<&'a [Vec<Allowed>; 3]>,
    live: &'a BTreeMap<String, Option<&'a Snapshot>>,
    neighbours: &'a BTreeMap<String, Vec<Neighbour>>,
    spectrum: Spectrum,
    /// The blocks already decided: band, channels, whose.
    taken: Vec<(Band, Vec<u16>, String)>,
}

/// Where a radio may be: its block, its power limit when its AP reports
/// one, and whether that needs a radar check.
struct Place {
    chans: Vec<u16>,
    max: Option<i32>,
    dfs: bool,
}

/// `p` as a radio held to `max` sends it.
fn capped(p: i32, max: Option<i32>) -> i32 {
    max.map_or(p, |m| p.min(m))
}

impl Ctx<'_> {
    /// Whether a block in the table needs DFS, or why it is not one.
    fn dfs_of(&self, band: Band, chans: &[u16]) -> Result<bool, String> {
        let Some(table) = self.table else {
            return Err("there is no channel table for the site's country".into());
        };
        let mut dfs = false;
        for c in chans {
            let range = table[band_index(band)]
                .iter()
                .find(|r| (r.lo..=r.hi).contains(c));
            let Some(r) = range else {
                return Err(format!(
                    "channel {c} is not one {} allows here",
                    self.country
                ));
            };
            dfs |= r.dfs;
        }
        Ok(dfs)
    }

    /// The most the radio of `band` of `ap` sends with `primary` as its
    /// primary channel, as its AP reports it: what it sends there now when
    /// it holds itself lower, else the radio's own limit; none unreported.
    fn power_limit(&self, ap: &str, band: Band, primary: u16) -> Option<i32> {
        let snap = self.live.get(ap).copied().flatten()?;
        let radio = snap.radios.iter().find(|r| r.band == band);
        if let Some(r) = radio.filter(|r| r.up && r.channel == primary && r.max_txpower_dbm > 0) {
            return Some(i32::from(r.max_txpower_dbm));
        }
        let within = |l: &&PowerLimit| l.band == band && (l.first..=l.last).contains(&primary);
        snap.power_limits
            .iter()
            .find(within)
            .map(|l| i32::from(l.dbm))
    }

    /// Where the radio of `ap` may be at `primary` and `width`, or why not.
    fn allowed(&self, ap: &str, band: Band, primary: u16, width: u16) -> Result<Place, String> {
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
        let dfs = self.dfs_of(band, &chans)?;
        let max = self.power_limit(ap, band, primary);
        if dfs && !self.rules.dfs {
            return Err("its channels need DFS".into());
        }
        let heard = self.neighbours.get(ap).into_iter().flatten();
        let mut theirs = heard.filter(|n| {
            n.band == band
                && band != Band::B6
                && width >= 40
                && (chans.contains(&n.primary) || chans.contains(&n.secondary))
        });
        if let Some(n) = theirs.find(|n| n.primary != primary) {
            return Err(format!(
                "a 20/40 MHz network of others on {} and {} has {} as its primary, which 20/40 \
                 coexistence makes this one's too",
                n.primary, n.secondary, n.primary
            ));
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
        Ok(Place { chans, max, dfs })
    }
}

/// The power to propose at a limit of `max` and why: `now` is the file's,
/// `tenth` the SNR the AP hears the weakest tenth of its clients at, less
/// what a wider channel costs; none when no client was heard.
fn power(
    now: Option<i32>,
    max: Option<i32>,
    kept: bool,
    tenth: Option<f64>,
    client: i32,
) -> (Option<i32>, Option<String>) {
    let (Some(p), Some(t), Some(max)) = (now, tenth.filter(|_| !kept), max) else {
        return (now, None);
    };
    // Above the limit, the driver holds it at the limit.
    let p0 = p.min(max);
    let hears = |power: i32| t + f64::from(power - client);
    let low = (TARGET_SNR - hears(0)).ceil() as i32;
    let high = (TARGET_SNR + HEADROOM - hears(0)).floor() as i32;
    let next = if p0 < low {
        low.min(max)
    } else if p0 > high {
        high.max(max - POWER_RANGE).min(p0)
    } else {
        p0
    };
    if (next - p0).abs() < HYSTERESIS {
        return (now, None);
    }
    let heard = hears(p0);
    let why = if next > p0 {
        format!(
            "the weakest tenth of its clients would hear it at {heard:.0} dB SNR, under the \
             {TARGET_SNR:.0} dB aimed at"
        )
    } else {
        format!(
            "the weakest tenth of its clients would hear it at {heard:.0} dB SNR, more than \
             {HEADROOM:.0} dB over the {TARGET_SNR:.0} dB aimed at: less power reaches fewer neighbours"
        )
    };
    (Some(next), Some(why))
}

/// What the radio runs, from its AP's report.
fn runs(r: &Radio) -> Setting {
    Setting {
        channel: r.channel,
        width: r.width_mhz,
        power: Some((r.txpower_mbm + 50).div_euclid(100)),
    }
}

/// The plan for the radios of the site file.
pub fn plan(inputs: &Inputs) -> Plan {
    let Inputs {
        site,
        live,
        history,
        neighbours,
        rules,
    } = inputs;
    let country = site.country.as_deref().unwrap_or("");
    let table = rules.countries.get(country);
    let mut notes = vec![format!(
        "No AP reports scans of other channels: the plan rests on each radio's survey of its own \
         channel and its clients' signal over the last {} h, and moves a radio only onto spectrum \
         one of the site's radios has measured, or off a conflict. What clients hear of an AP is \
         estimated with clients sending at {} dBm.",
        rules.window_hours, rules.client_dbm
    )];
    if table.is_none() {
        notes.push(format!(
            "The configuration has no channel table for the site's country ({country:?}): nothing \
             is proposed."
        ));
    }
    let mut ctx = Ctx {
        rules,
        country,
        table,
        live,
        neighbours,
        spectrum: spectrum(history),
        taken: Vec::new(),
    };
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
            let on = radio.map_or((sr.channel, width), |r| (r.channel, r.width_mhz));
            let measure = measure(hours.filter(|h| (h.channel, h.width) == on));
            // A power above the limit is the limit: the radio is held
            // there, clamped, which is never out of step.
            let limit = ctx.power_limit(ap, sr.band, sr.channel);
            let stated = sr.power.map(|p| capped(p, limit));
            if let (Some(p), Some(s)) = (sr.power, stated)
                && s < p
            {
                notes.push(format!(
                    "{ap}'s {} radio: the site file's {p} dBm is clamped to {s} dBm, the most it \
                     sends on channel {}",
                    band_name(sr.band),
                    sr.channel
                ));
            }
            let dfs = channels::block(sr.band, sr.channel, width)
                .and_then(|b| ctx.dfs_of(sr.band, &b).ok())
                .unwrap_or(false);
            let mut pending = false;
            // What keeps the whole radio as it is.
            let whole = match (snap, radio) {
                (None, _) => Some(format!("{ap} is not one of this controller's APs")),
                (Some(None), _) => Some(format!("{ap} is not connected")),
                (_, None) => Some(format!("{ap} reports no {} radio", band_name(sr.band))),
                (_, Some(r)) if !r.up => Some("the radio is down".into()),
                _ if sr.width.is_none() => {
                    Some("its width is one the planner does not handle".into())
                }
                (_, Some(r)) if (r.channel, r.width_mhz) != (sr.channel, width) => {
                    pending = true;
                    Some(format!(
                        "not as planned: it runs channel {} at {} MHz, the site file says \
                         channel {} at {width} MHz",
                        r.channel, r.width_mhz, sr.channel
                    ))
                }
                (_, Some(r))
                    if stated
                        .zip(runs(r).power)
                        .is_some_and(|(s, l)| (s - l).abs() >= POWER_SLACK) =>
                {
                    pending = true;
                    Some(format!(
                        "not as planned: it sends at {} dBm, the site file says {} dBm",
                        runs(r).power.unwrap_or_default(),
                        stated.unwrap_or_default()
                    ))
                }
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
                pending,
                planned_power: stated,
                planned_dfs: dfs,
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
    let mut radios = Vec::new();
    for item in &items {
        let p = decide(&ctx, item);
        let chans = channels::block(p.band, p.proposed.channel, p.proposed.width)
            .unwrap_or_else(|| vec![p.proposed.channel]);
        ctx.taken.push((p.band, chans, item.ap.to_owned()));
        radios.push(p);
    }
    group(&mut radios);
    radios.sort_by(|a, b| (&a.ap, band_index(a.band)).cmp(&(&b.ap, band_index(b.band))));
    Plan { radios, notes }
}

/// A radio's block at `s`, or its primary alone when it has none.
fn block_of(band: Band, s: &Setting) -> Vec<u16> {
    channels::block(band, s.channel, s.width).unwrap_or_else(|| vec![s.channel])
}

/// Groups the proposals that move onto spectrum another proposal frees:
/// applied alone, either would share it with a radio still there.
fn group(radios: &mut [Proposal]) {
    let n = radios.len();
    let mut of: Vec<usize> = (0..n).collect();
    fn root(of: &mut [usize], mut i: usize) -> usize {
        while of[i] != i {
            of[i] = of[of[i]];
            i = of[i];
        }
        i
    }
    for b in 0..n {
        if !radios[b].changes() {
            continue;
        }
        let to = block_of(radios[b].band, &radios[b].proposed);
        for a in 0..n {
            let other = &radios[a];
            let leaves = a != b
                && other.ap != radios[b].ap
                && other.band == radios[b].band
                && other.changes()
                && channels::overlap(other.band, &to, &block_of(other.band, &other.current));
            if leaves {
                let (ra, rb) = (root(&mut of, a), root(&mut of, b));
                of[ra] = rb;
            }
        }
    }
    let roots: Vec<usize> = (0..n).map(|i| root(&mut of, i)).collect();
    let mut numbers = BTreeMap::new();
    for (p, r) in radios.iter_mut().zip(&roots) {
        if roots.iter().filter(|&o| o == r).count() > 1 {
            let next = numbers.len() as u32 + 1;
            p.group = Some(*numbers.entry(*r).or_insert(next));
        }
    }
}

/// Why giving the radios of `chosen` (AP, band, setting) their settings would
/// put one of them on spectrum another AP's radio of the site has, if it
/// would; a clash between two radios left as they are is not this one's.
pub fn clash(site: &Site, chosen: &[(String, Band, Setting)]) -> Option<String> {
    let mut all = Vec::new();
    for (ap, radios) in &site.aps {
        for r in radios {
            let new = chosen.iter().find(|(a, b, _)| a == ap && *b == r.band);
            let set = new.map_or(
                Setting {
                    channel: r.channel,
                    width: r.width.unwrap_or(20),
                    power: r.power,
                },
                |(_, _, s)| *s,
            );
            all.push((ap.as_str(), r.band, set, new.is_some()));
        }
    }
    for (i, (a, band, s, moved)) in all.iter().enumerate() {
        for (b, other_band, t, other_moved) in &all[i + 1..] {
            let shared = a != b
                && band == other_band
                && (*moved || *other_moved)
                && channels::overlap(*band, &block_of(*band, s), &block_of(*band, t));
            if shared {
                return Some(format!(
                    "{a}'s {} radio on channel {} would share spectrum with {b}'s on channel {}",
                    band_name(*band),
                    s.channel,
                    t.channel
                ));
            }
        }
    }
    None
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
    dfs: bool,
    score: f64,
}

/// What its clients hear of the radio over what it hears of them, at
/// `power` (as much as they send when it is not known), dB.
fn heard_over(power: Option<i32>, client: i32) -> f64 {
    f64::from(power.map_or(0, |p| p - client))
}

/// What the radio would be at `at` (primary, width), if it may be.
fn candidate(ctx: &Ctx, item: &Item, clients: &[(f64, f64)], at: (u16, u16)) -> Option<Candidate> {
    let sr = item.site;
    let (primary, width) = at;
    let from = sr.width.unwrap_or(20);
    let place = ctx.allowed(item.ap, sr.band, primary, width).ok()?;
    let now = item.measure.as_ref().map(|m| m.foreign);
    // Its own block is what it measured itself, whatever the primary.
    let own = channels::block(sr.band, sr.channel, from).is_some_and(|b| b == place.chans);
    let (foreign, measured) = if own {
        (now, now.is_some())
    } else {
        let there = foreign_of(&ctx.spectrum, sr.band, &place.chans);
        (there.or(now), there.is_some() && now.is_some())
    };
    let client = ctx.rules.client_dbm;
    let tenth = (!clients.is_empty()).then(|| tenth(clients) - widening(from, width));
    let (power, power_why) = power(sr.power, place.max, item.power_kept, tenth, client);
    let now_db = heard_over(sr.power.map(|p| capped(p, place.max)), client);
    let then_db = heard_over(power.map(|p| capped(p, place.max)), client) - widening(from, width);
    // With no client heard, one at the target SNR stands in.
    let nominal = [(TARGET_SNR - now_db, 1.0)];
    let scored = if clients.is_empty() {
        &nominal[..]
    } else {
        clients
    };
    let score = score(scored, from, width, now_db, then_db, foreign.unwrap_or(0.0)).0;
    Some(Candidate {
        primary,
        width,
        power,
        power_why,
        foreign: foreign.unwrap_or(0.0),
        measured,
        dfs: place.dfs,
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
fn choose(ctx: &Ctx, item: &Item, clients: &[(f64, f64)]) -> (Option<Candidate>, Vec<String>) {
    let sr = item.site;
    let width = sr.width.unwrap_or(20);
    let here = ctx.allowed(item.ap, sr.band, sr.channel, width).map(drop);
    let stay = candidate(ctx, item, clients, (sr.channel, width));
    if let Some(kept) = &item.kept {
        let mut why = vec![kept.clone()];
        why.extend(here.err().map(|e| format!("though {e}")));
        return (stay, why);
    }
    let widths = &ctx.rules.widths[band_index(sr.band)];
    // `no_pri_sec_switch` keeps the primary: only the width may change.
    let primaries: Vec<u16> = if sr.pins.primary {
        vec![sr.channel]
    } else {
        channels::all(sr.band).collect()
    };
    let all: Vec<Candidate> = primaries
        .into_iter()
        .flat_map(|p| widths.iter().map(move |&w| (p, w)))
        .filter_map(|at| candidate(ctx, item, clients, at))
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
        let onto = if best.measured {
            ""
        } else {
            ", onto spectrum none of the site's radios has measured"
        };
        return (Some(best), vec![format!("{e}, so it moves{onto}")]);
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

fn decide(ctx: &Ctx, item: &Item) -> Proposal {
    let sr = item.site;
    let width = sr.width.unwrap_or(20);
    let current = Setting {
        channel: sr.channel,
        width,
        power: sr.power,
    };
    let m = item.measure.as_ref();
    let clients = clients(m);
    let (chosen, mut why) = choose(ctx, item, &clients);
    let radio = item.live.map_or_else(
        || format!("radio{}", channels::site_key(sr.band)),
        |r| r.phy.clone(),
    );
    let client = ctx.rules.client_dbm;
    let limit = ctx.power_limit(item.ap, sr.band, sr.channel);
    let p_now = sr.power.map(|p| capped(p, limit));
    let mut p = Proposal {
        ap: item.ap.to_owned(),
        radio,
        band: sr.band,
        current,
        proposed: current,
        runs: item.live.map(runs),
        measure: item.measure.clone(),
        predicted_busy: m.map(|m| m.busy),
        snr: (!clients.is_empty()).then(|| tenth(&clients) + heard_over(p_now, client)),
        snr_change: 0.0,
        measured: m.is_some(),
        kept: item.kept.clone(),
        pending: item.pending,
        planned_power: item.planned_power,
        planned_dfs: item.planned_dfs,
        restart: None,
        group: None,
        reason: String::new(),
    };
    if let Some(c) = chosen {
        p.proposed = Setting {
            channel: c.primary,
            width: c.width,
            power: c.power,
        };
        let now_db = heard_over(p_now, client);
        let then_db =
            heard_over(c.power.map(|x| capped(x, limit)), client) - widening(width, c.width);
        p.snr_change = then_db - now_db;
        p.measured = c.measured;
        if let Some(m) = m.filter(|_| !clients.is_empty()) {
            let airtime = score(&clients, width, c.width, now_db, then_db, c.foreign).1;
            p.predicted_busy = Some((c.foreign + m.own * airtime).min(100.0));
        }
        let moves = block_of(sr.band, &p.proposed) != block_of(sr.band, &current);
        if c.dfs && moves {
            p.restart = Some(
                "a DFS channel: it needs a radar check (CAC), which a live channel switch cannot \
                 run, so it takes effect with the next configuration push"
                    .into(),
            );
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
        let primary = if sr.pins.primary {
            " (its primary channel is kept: no_pri_sec_switch)"
        } else {
            ""
        };
        why.push(format!(
            "no setting it may use scores {:.0} % better{primary}",
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

    fn allowed(lo: u16, hi: u16, dfs: bool) -> Allowed {
        Allowed { lo, hi, dfs }
    }

    fn rules() -> Rules {
        let zz = [
            vec![allowed(1, 13, false)],
            vec![
                allowed(36, 48, false),
                allowed(52, 64, true),
                allowed(149, 177, false),
            ],
            vec![allowed(1, 93, false)],
        ];
        Rules {
            window_hours: 24,
            dfs: false,
            client_dbm: 15,
            widths: [vec![20], vec![20, 40, 80], vec![20, 40, 80, 160]],
            countries: [("ZZ".to_owned(), zz)].into(),
        }
    }

    /// One radio of a simulated AP over a minute: its channel, width and
    /// power, the share of the minute busy and its own share of that, and
    /// its clients' signals.
    #[derive(Clone)]
    struct Sim {
        band: Band,
        channel: u16,
        width: u16,
        dbm: i32,
        busy: u64,
        own: u64,
        signals: Vec<i8>,
    }

    fn sim(
        band: Band,
        channel: u16,
        width: u16,
        dbm: i32,
        busy: u64,
        own: u64,
        signals: &[i8],
    ) -> Sim {
        Sim {
            band,
            channel,
            width,
            dbm,
            busy,
            own,
            signals: signals.to_vec(),
        }
    }

    /// The radios of the fixture's ap1 and ap2 as their site file says, with
    /// clients that ask for no power change.
    fn fixture(ap: &str) -> Vec<Sim> {
        match ap {
            "ap1" => vec![
                sim(Band::B24, 6, 20, 20, 30, 10, &[-60]),
                sim(Band::B5, 36, 80, 23, 20, 10, &[-70]),
                sim(Band::B6, 37, 160, 18, 5, 2, &[-68]),
            ],
            _ => vec![
                sim(Band::B24, 6, 20, 20, 30, 10, &[]),
                sim(Band::B5, 149, 80, 23, 20, 10, &[-70]),
                sim(Band::B6, 69, 160, 18, 5, 2, &[-68]),
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

    fn limit(band: Band, first: u16, last: u16, dbm: i8) -> PowerLimit {
        PowerLimit {
            band,
            first,
            last,
            dbm,
        }
    }

    /// The power limits a simulated AP reports: as a radio of its own rules
    /// would, by band.
    fn limits() -> Vec<PowerLimit> {
        vec![
            limit(Band::B24, 1, 13, 23),
            limit(Band::B5, 36, 64, 23),
            limit(Band::B5, 100, 144, 20),
            limit(Band::B5, 149, 177, 23),
            limit(Band::B6, 1, 93, 24),
        ]
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
                    txpower_mbm: r.dbm * 100,
                    noise_dbm: -95,
                    active_ms: ms,
                    busy_ms: ms * r.busy / 100,
                    rx_ms: 0,
                    tx_ms: ms * r.own / 100,
                    up: true,
                    max_txpower_dbm: 0,
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
                power_limits: limits(),
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

    fn run_with(
        site: &str,
        snaps: &[(&str, Option<&Snapshot>)],
        h: &History,
        rules: &Rules,
        neighbours: &BTreeMap<String, Vec<Neighbour>>,
    ) -> Plan {
        let site = site::read(site).unwrap();
        let live = snaps.iter().map(|(a, s)| (a.to_string(), *s)).collect();
        plan(&Inputs {
            site: &site,
            live: &live,
            history: h,
            neighbours,
            rules,
        })
    }

    fn run(site: &str, snaps: &[(&str, Option<&Snapshot>)], h: &History, rules: &Rules) -> Plan {
        run_with(site, snaps, h, rules, &BTreeMap::new())
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

    fn changed(p: &Plan) -> Vec<String> {
        p.radios
            .iter()
            .filter(|r| r.changes())
            .map(Proposal::key)
            .collect()
    }

    /// Both APs as the fixture has them, measured now.
    fn both(h: &mut History, ap1: &[Sim], ap2: &[Sim]) -> (Snapshot, Snapshot) {
        (seed(h, "ap1", ap1, 0), seed(h, "ap2", ap2, 0))
    }

    #[test]
    fn two_aps_on_one_channel_part_and_the_busier_one_stays() {
        let mut h = History::new(24);
        let (a, b) = both(&mut h, &fixture("ap1"), &fixture("ap2"));
        let p = run(SITE, &[("ap1", Some(&a)), ("ap2", Some(&b))], &h, &rules());
        assert!(!of(&p, "ap1/radio24").changes());
        let moved = of(&p, "ap2/radio24");
        let ch = moved.proposed.channel;
        assert!(ch <= 2 || ch >= 10, "channel {ch} still overlaps 6");
        assert_eq!(
            moved.reason,
            "it would share spectrum with ap1's channel 6, so it moves, onto spectrum none of \
             the site's radios has measured"
        );
        assert!(!moved.measured);
        assert_eq!(changed(&p), ["ap2/radio24"]);
        // It frees nothing another proposal takes: no group.
        assert_eq!(moved.group, None);
        assert!(p.notes[0].contains("No AP reports scans"));
    }

    #[test]
    fn what_the_site_keeps_stays_and_6ghz_keeps_to_psc() {
        let mut h = History::new(24);
        let (a, b) = both(&mut h, &fixture("ap1"), &fixture("ap2"));
        let p = run(SITE, &[("ap1", Some(&a)), ("ap2", Some(&b))], &h, &rules());
        let kept = of(&p, "ap2/radio5");
        assert_eq!(
            kept.kept.as_deref(),
            Some("the site file keeps its channel (planner: fixed)")
        );
        assert_eq!(at(&kept.proposed), (149, 80, Some(23)));
        for r in p.radios.iter().filter(|r| r.band == Band::B6) {
            assert!(channels::psc(r.proposed.channel), "{r:?}");
        }
        // A whole AP kept: none of its radios changes, and ap1 moves its
        // 2.4 GHz radio instead.
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
        assert!(of(&p, "ap1/radio24").changes());
    }

    #[test]
    fn no_pri_sec_switch_keeps_the_primary_and_neighbours_set_it() {
        let mut h = History::new(24);
        // ap1's 5 GHz radio spent an hour on 165-177, far quieter than its
        // own 36-48 now: a move it would make, but for the primary kept.
        let mut before = fixture("ap1");
        before[1] = sim(Band::B5, 165, 80, 23, 8, 4, &[-70]);
        seed(&mut h, "ap1", &before, 3);
        let mut now = fixture("ap1");
        now[1].busy = 50;
        let (a, b) = both(&mut h, &now, &fixture("ap2"));
        let snaps = [("ap1", Some(&a)), ("ap2", Some(&b))];
        assert_eq!(
            of(&run(SITE, &snaps, &h, &rules()), "ap1/radio5")
                .proposed
                .channel,
            165
        );
        let kept = SITE.replace(
            "          channel: 36\n",
            "          channel: 36\n          no_pri_sec_switch: 1\n",
        );
        let r5 = of(&run(&kept, &snaps, &h, &rules()), "ap1/radio5").clone();
        assert_eq!(r5.proposed.channel, 36);
        assert!(
            r5.reason.contains("its primary channel is kept"),
            "{}",
            r5.reason
        );
        // A 20/40 MHz network of others on 165 and 169 heard by ap1: the
        // block there must take its primary, whichever it is.
        let heard = |primary, secondary| {
            [(
                "ap1".to_owned(),
                vec![Neighbour {
                    band: Band::B5,
                    primary,
                    secondary,
                }],
            )]
            .into()
        };
        let p = run_with(SITE, &snaps, &h, &rules(), &heard(165, 169));
        assert_eq!(of(&p, "ap1/radio5").proposed.channel, 165);
        let p = run_with(SITE, &snaps, &h, &rules(), &heard(169, 165));
        assert_eq!(at(&of(&p, "ap1/radio5").proposed), (169, 80, Some(23)));
    }

    #[test]
    fn power_follows_what_clients_hear_and_holds_once_applied() {
        let mut h = History::new(24);
        let mut ap1 = fixture("ap1");
        // 6 GHz clients heard at 16 dB SNR (-80 dBm falls in the bin from
        // -80 to -78, over -95 dBm noise): sending at 15 dBm, they hear the
        // AP's 18 dBm at 19 dB, so power goes to the 24 dBm limit.
        ap1[2].signals = vec![-80, -80, -50];
        let (a, b) = both(&mut h, &ap1, &fixture("ap2"));
        let p = run(SITE, &[("ap1", Some(&a)), ("ap2", Some(&b))], &h, &rules());
        let r6 = of(&p, "ap1/radio6");
        assert_eq!(at(&r6.proposed), (37, 160, Some(24)));
        assert_eq!((r6.snr, r6.snr_change), (Some(19.0), 6.0));
        assert!(
            r6.reason
                .contains("would hear it at 19 dB SNR, under the 25 dB"),
            "{}",
            r6.reason
        );
        assert!(r6.predicted_busy.unwrap() < r6.measure.as_ref().unwrap().busy);
        // Applied: the same hours planned again with the file at 24 dBm and
        // the radio sending at it propose nothing.
        let applied = SITE.replace("\"6\": 18}", "\"6\": 24}");
        let mut ap2 = fixture("ap2");
        (ap1[2].dbm, ap2[2].dbm) = (24, 24);
        let mut h = History::new(24);
        let (a, b) = both(&mut h, &ap1, &ap2);
        let p = run(
            &applied,
            &[("ap1", Some(&a)), ("ap2", Some(&b))],
            &h,
            &rules(),
        );
        assert!(
            !of(&p, "ap1/radio6").changes(),
            "{}",
            of(&p, "ap1/radio6").reason
        );
        // Clients all close by give power back, at most 6 dB under the
        // limit; applied, it holds there too.
        let mut close = fixture("ap1");
        close[1].signals = vec![-30; 4];
        let mut h = History::new(24);
        let (a, b) = both(&mut h, &close, &fixture("ap2"));
        let p = run(SITE, &[("ap1", Some(&a)), ("ap2", Some(&b))], &h, &rules());
        assert_eq!(of(&p, "ap1/radio5").proposed.power, Some(23 - POWER_RANGE));
        close[1].dbm = 23 - POWER_RANGE;
        let mut h = History::new(24);
        let (a, b) = both(&mut h, &close, &fixture("ap2"));
        let lowered = SITE.replace("      radios:\n        \"5\":\n          hw_mode: a\n          channel: 36\n", "      txpower: {\"5\": 17}\n      radios:\n        \"5\":\n          hw_mode: a\n          channel: 36\n");
        let p = run(
            &lowered,
            &[("ap1", Some(&a)), ("ap2", Some(&b))],
            &h,
            &rules(),
        );
        assert!(
            !of(&p, "ap1/radio5").changes(),
            "{}",
            of(&p, "ap1/radio5").reason
        );
    }

    #[test]
    fn a_power_above_the_limit_counts_as_the_limit() {
        let mut h = History::new(24);
        // The radios' own rules hold them at 17 dBm, the file says 20.
        let (mut ap1, mut ap2) = (fixture("ap1"), fixture("ap2"));
        (ap1[0].dbm, ap2[0].dbm) = (17, 17);
        let (mut a, mut b) = both(&mut h, &ap1, &ap2);
        for s in [&mut a, &mut b] {
            s.power_limits[0] = limit(Band::B24, 1, 13, 17);
        }
        let p = run(SITE, &[("ap1", Some(&a)), ("ap2", Some(&b))], &h, &rules());
        assert!(!of(&p, "ap1/radio24").changes());
        assert!(!of(&p, "ap1/radio24").pending);
        assert_eq!(of(&p, "ap1/radio24").planned_power, Some(17));
        assert!(p.notes.iter().any(|n| n
            == "ap1's 2.4 GHz radio: the site file's 20 dBm is clamped to 17 dBm, the most it \
                sends on channel 6"));
        // ap2's moves for its channel alone, its power as the file has it.
        assert_eq!(of(&p, "ap2/radio24").proposed.power, Some(20));
    }

    /// A radio that holds itself below its rules' limit (a 6 GHz one by its
    /// power spectral density) sends less than the file says: clamped, so
    /// neither out of step nor raised, nor lowered for nothing.
    #[test]
    fn a_radio_held_below_its_limit_is_clamped_not_out_of_step() {
        let mut h = History::new(24);
        let (mut ap1, ap2) = (fixture("ap1"), fixture("ap2"));
        ap1[2].dbm = 19;
        let (mut a, b) = both(&mut h, &ap1, &ap2);
        a.radios[2].max_txpower_dbm = 19;
        let raised = SITE.replace(
            "      radios:\n        \"5\":\n          hw_mode: a\n          channel: 36\n",
            "      txpower: {\"6\": 26}\n      radios:\n        \"5\":\n          hw_mode: a\n          channel: 36\n",
        );
        let p = run(
            &raised,
            &[("ap1", Some(&a)), ("ap2", Some(&b))],
            &h,
            &rules(),
        );
        let r6 = of(&p, "ap1/radio6");
        assert!(!r6.pending, "{:?}", r6.kept);
        assert_eq!(r6.planned_power, Some(19));
        assert_eq!(r6.proposed.power, r6.current.power);
        assert!(
            p.notes
                .iter()
                .any(|n| n.contains("26 dBm is clamped to 19 dBm"))
        );
    }

    /// An AP that reports no limit: its radios keep their power.
    #[test]
    fn without_a_reported_limit_power_stays() {
        let mut h = History::new(24);
        let (mut ap1, ap2) = (fixture("ap1"), fixture("ap2"));
        // A client that would want more power.
        ap1[1].signals = vec![-88];
        let (mut a, b) = both(&mut h, &ap1, &ap2);
        a.power_limits.clear();
        let p = run(SITE, &[("ap1", Some(&a)), ("ap2", Some(&b))], &h, &rules());
        let r5 = of(&p, "ap1/radio5");
        assert_eq!(r5.proposed.power, r5.current.power, "{}", r5.reason);
    }

    #[test]
    fn a_measured_quieter_channel_wins_when_it_is_worth_it() {
        let mut h = History::new(24);
        let mut before = fixture("ap1");
        before[1] = sim(Band::B5, 165, 80, 23, 8, 4, &[-70]);
        seed(&mut h, "ap1", &before, 3);
        let mut now = fixture("ap1");
        now[1].busy = 50;
        let (a, b) = both(&mut h, &now, &fixture("ap2"));
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
        assert_eq!(r5.restart, None);
        // Not worth it: a block only a little quieter.
        let mut h = History::new(24);
        let mut before = fixture("ap1");
        before[1] = sim(Band::B5, 165, 80, 23, 15, 4, &[-70]);
        seed(&mut h, "ap1", &before, 3);
        let mut now = fixture("ap1");
        now[1].busy = 22;
        let (a, b) = both(&mut h, &now, &fixture("ap2"));
        let p = run(SITE, &[("ap1", Some(&a)), ("ap2", Some(&b))], &h, &rules());
        assert!(!of(&p, "ap1/radio5").changes());
        assert!(
            p.radios
                .iter()
                .all(|r| !(52..=64).contains(&r.proposed.channel))
        );
    }

    #[test]
    fn a_dfs_move_is_marked_a_restart_with_a_radar_check() {
        let mut h = History::new(24);
        let mut before = fixture("ap1");
        before[1] = sim(Band::B5, 52, 80, 20, 6, 3, &[-70]);
        seed(&mut h, "ap1", &before, 3);
        let mut now = fixture("ap1");
        now[1].busy = 50;
        let (a, b) = both(&mut h, &now, &fixture("ap2"));
        let mut dfs = rules();
        dfs.dfs = true;
        let p = run(SITE, &[("ap1", Some(&a)), ("ap2", Some(&b))], &h, &dfs);
        let r5 = of(&p, "ap1/radio5");
        assert_eq!(r5.proposed.channel, 52, "{}", r5.reason);
        assert!(r5.restart.as_deref().unwrap().contains("radar check (CAC)"));
    }

    /// ap1's 6 GHz radio moves onto the block ap2's leaves for a quieter one:
    /// applied alone, either would share spectrum, so they are one group.
    #[test]
    fn proposals_that_free_each_others_spectrum_are_one_group() {
        let mut h = History::new(24);
        // ap2 spent hours on 1-29; ap1 on 65-93 (quiet now, ap2's today).
        let mut ap2_before = fixture("ap2");
        ap2_before[2] = sim(Band::B6, 5, 160, 18, 2, 1, &[-68]);
        seed(&mut h, "ap2", &ap2_before, 5);
        let mut ap1_before = fixture("ap1");
        ap1_before[2] = sim(Band::B6, 69, 160, 18, 2, 1, &[-68]);
        seed(&mut h, "ap1", &ap1_before, 4);
        // ap2, with more clients, chooses first.
        let (mut ap1, mut ap2) = (fixture("ap1"), fixture("ap2"));
        ap1[2].busy = 60;
        ap2[2].busy = 60;
        ap2[2].signals = vec![-68; 3];
        let (a, b) = both(&mut h, &ap1, &ap2);
        let p = run(SITE, &[("ap1", Some(&a)), ("ap2", Some(&b))], &h, &rules());
        let (r1, r2) = (of(&p, "ap1/radio6"), of(&p, "ap2/radio6"));
        assert_eq!(
            (r1.proposed.channel, r2.proposed.channel),
            (69, 5),
            "{} | {}",
            r1.reason,
            r2.reason
        );
        assert!(r1.group.is_some() && r1.group == r2.group);
        // Applied alone, ap1's would share ap2's spectrum.
        let site = site::read(SITE).unwrap();
        let alone = [("ap1".to_owned(), Band::B6, r1.proposed)];
        assert_eq!(
            clash(&site, &alone).as_deref(),
            Some("ap1's 6 GHz radio on channel 69 would share spectrum with ap2's on channel 69")
        );
        let together = [alone[0].clone(), ("ap2".to_owned(), Band::B6, r2.proposed)];
        assert_eq!(clash(&site, &together), None);
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
        assert!(!r5.changes() && r5.pending);
        assert_eq!(
            r5.kept.as_deref(),
            Some(
                "not as planned: it runs channel 44 at 80 MHz, the site file says channel 36 at 80 MHz"
            )
        );
        assert_eq!(r5.runs.map(|s| s.channel), Some(44));
        let r6 = of(&p, "ap1/radio6");
        assert!(!r6.changes());
        assert_eq!(r6.reason, "nothing was measured on it in the last 24 h");
        // Power the radio does not send at yet is out of step too.
        let mut quiet = fixture("ap1");
        quiet[2].dbm = 12;
        let (_, a) = snapshots(&quiet);
        let p = run(SITE, &[("ap1", Some(&a)), ("ap2", Some(&b))], &h, &rules());
        let r6 = of(&p, "ap1/radio6");
        assert!(r6.pending);
        assert_eq!(
            r6.kept.as_deref(),
            Some("not as planned: it sends at 12 dBm, the site file says 18 dBm")
        );
        // ap2 away: its spectrum is kept, so ap1 moves off its 2.4 GHz channel.
        let (_, a) = snapshots(&fixture("ap1"));
        let p = run(SITE, &[("ap1", Some(&a)), ("ap2", None)], &h, &rules());
        assert_eq!(
            of(&p, "ap2/radio24").kept.as_deref(),
            Some("ap2 is not connected")
        );
        assert!(of(&p, "ap1/radio24").changes());
        let p = run(SITE, &[("ap1", Some(&a))], &h, &rules());
        assert_eq!(
            of(&p, "ap2/radio6").kept.as_deref(),
            Some("ap2 is not one of this controller's APs")
        );
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
        assert!(score(&one, 80, 80, 0.0, 0.0, 10.0).0 > score(&one, 80, 80, 0.0, 0.0, 40.0).0);
        let wider = -widening(40, 80);
        assert!(score(&one, 40, 80, 0.0, wider, 10.0).0 > score(&one, 40, 40, 0.0, 0.0, 10.0).0);
        let (_, airtime) = score(&one, 40, 80, 0.0, wider, 0.0);
        assert!(airtime < 0.6, "{airtime}");
        let spread: Vec<_> = (0..10).map(|i| (f64::from(i) * 5.0, 1.0)).collect();
        assert_eq!(tenth(&spread), 0.0);
        assert_eq!(tenth(&[(12.0, 9.0), (40.0, 1.0)]), 12.0);
    }

    /// The power a radio sends at is limited by its primary channel's
    /// limit, which is what the driver applies: a block whose other channels
    /// allow less does not make a radio at the site file's power out of step.
    #[test]
    fn the_power_in_step_is_by_the_primary_channels_limit() {
        let h = History::new(24);
        let (_, mut a) = snapshots(&fixture("ap1"));
        let (_, b) = snapshots(&fixture("ap2"));
        // A radio of the kernel's rules: 44-48 allow 17 dBm, 36-40 23.
        a.power_limits[1] = limit(Band::B5, 36, 40, 23);
        a.power_limits.insert(2, limit(Band::B5, 44, 48, 17));
        let p = run(SITE, &[("ap1", Some(&a)), ("ap2", Some(&b))], &h, &rules());
        let r5 = of(&p, "ap1/radio5");
        assert!(!r5.pending, "{:?}", r5.kept);
        assert_eq!(r5.planned_power, Some(23));
    }
}
