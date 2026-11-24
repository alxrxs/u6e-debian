//! The Wi-Fi experience score: how well the Wi-Fi serves a client now, from
//! 0 to 100, from five parts each from 0 to 100, every one shown with the
//! figure it comes from. All of it is worked out from the client's AP's last
//! two snapshots and what `roaming` knows of the client, so it costs the APs
//! nothing:
//!
//! - signal: its average signal, −60 dBm and better 100, −80 and worse 0;
//! - retries: its retries as a share of every transmission to it (the frames
//!   sent and their retries), 0 % 100, 40 % and more 0, when at least
//!   [`FRAMES_MIN`] frames were sent;
//! - contention: the share of its radio's time busy with anything but the
//!   radio's own transmissions, 20 % and less 100, 70 % and more 0;
//! - rate: the AP's last transmit rate to it over the best its capabilities
//!   allow on its radio ([`best_rate_kbps`]), three quarters and more 100,
//!   when at least [`FRAMES_MIN`] were sent and its capabilities have a best
//!   rate;
//! - roaming: 100, less its share of the last hour spent sticky (its last
//!   twelve 5-minute buckets, so up to 5 minutes more), less 25 for each roam
//!   of it that failed in the last hour.
//!
//! The score is the mean of the parts it has, weighted ([`WEIGHTS`]), but
//! never more than [`ABOVE_WORST`] above its worst part, so that one bad part
//! does not hide behind good ones. A part without its figure (an idle client
//! sends no frames) is left out, not counted as 0. An AP's score is the mean
//! of its clients' scores, each of its parts the mean of theirs; an AP
//! without clients has none.
//!
//! Under the NSS offload an AP's retry counter seldom moves (measured: 7 of
//! 674 readings of 17 clients over 10 minutes above 0 %, at most 3.9 %), so
//! the retries part is mostly 100: it says what the counter says.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};
use u6e_proto::msg::{RateMode, Snapshot, Station, StationCaps};

use crate::roaming::Facts;
use crate::state::{ClientView, State};

/// The parts, in the order they are shown.
pub const PARTS: [&str; 5] = ["signal", "retries", "contention", "rate", "roaming"];
/// Each part's weight, in [`PARTS`]' order.
pub const WEIGHTS: [f64; 5] = [30.0, 20.0, 15.0, 20.0, 15.0];
/// The most the score is above its worst part.
pub const ABOVE_WORST: f64 = 40.0;
/// The fewest frames sent to a client in the window for its retries and its
/// rate to say anything.
pub const FRAMES_MIN: u64 = 20;
/// What each of a client's failed roams in the last hour costs.
const PER_FAILURE: f64 = 25.0;

/// What a client's parts are worked out from.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Inputs {
    /// Its average signal, dBm.
    pub signal: i8,
    /// Frames the AP sent it in the window, and of those, retries.
    pub sent: u64,
    pub retries: u64,
    /// The AP's last transmit rate to it, kbit/s.
    pub tx_rate_kbps: u32,
    /// What it supports, and its radio's width.
    pub caps: Option<StationCaps>,
    pub radio_width_mhz: u16,
    /// Of its radio's time in the window, the share busy with anything but
    /// the radio's own transmissions, 0 to 1.
    pub contention: Option<f64>,
    /// Its share of the last hour spent sticky, 0 to 1, and its failed
    /// roams in the last hour.
    pub sticky: f64,
    pub failed_roams: u32,
}

/// The parts in [`PARTS`]' order, each with the figure it came from; `None`
/// for a part without one.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Parts(pub [Option<Part>; 5]);

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Part {
    pub score: f64,
    /// The figure: dBm, a percentage, or the rate's share in percent.
    pub value: f64,
}

/// `x` mapped linearly from `zero` (0) to `full` (100), clamped.
fn scale(x: f64, zero: f64, full: f64) -> f64 {
    ((x - zero) / (full - zero) * 100.0).clamp(0.0, 100.0)
}

/// The parts of a client.
pub fn parts(i: &Inputs) -> Parts {
    let signal = f64::from(i.signal);
    let busy = i.sent >= FRAMES_MIN;
    let retries = busy.then(|| i.retries as f64 * 100.0 / (i.sent + i.retries) as f64);
    let best = i.caps.and_then(|c| best_rate_kbps(c, i.radio_width_mhz));
    let share = best
        .filter(|&b| busy && b > 0 && i.tx_rate_kbps > 0)
        .map(|b| f64::from(i.tx_rate_kbps) * 100.0 / f64::from(b));
    let roaming = 100.0 - i.sticky * 100.0 - PER_FAILURE * f64::from(i.failed_roams);
    let part = |score: f64, value: f64| Part {
        score: score.round(),
        value: (value * 10.0).round() / 10.0,
    };
    Parts([
        Some(part(scale(signal, -80.0, -60.0), signal)),
        retries.map(|r| part(scale(r, 40.0, 0.0), r)),
        i.contention
            .map(|c| part(scale(c * 100.0, 70.0, 20.0), c * 100.0)),
        share.map(|s| part(scale(s, 0.0, 75.0), s)),
        Some(part(roaming.clamp(0.0, 100.0), i.sticky * 100.0)),
    ])
}

/// The score of `parts`: their weighted mean, at most [`ABOVE_WORST`] above
/// the worst of them; `None` without any.
pub fn score(parts: &Parts) -> Option<u8> {
    let present = || {
        parts
            .0
            .iter()
            .zip(WEIGHTS)
            .filter_map(|(p, w)| Some((p.as_ref()?.score, w)))
    };
    let weight: f64 = present().map(|(_, w)| w).sum();
    let worst = present().map(|(s, _)| s).reduce(f64::min)?;
    let mean = present().map(|(s, w)| s * w).sum::<f64>() / weight;
    Some(mean.min(worst + ABOVE_WORST).round() as u8)
}

/// Data subcarriers and the symbol time in nanoseconds (short guard
/// interval; HE's 0.8 µs) of a mode at a width.
fn ofdm(mode: RateMode, width_mhz: u16) -> Option<(u32, u32)> {
    let he = mode == RateMode::He;
    let sd = match (he, width_mhz) {
        (false, 20) => 52,
        (false, 40) => 108,
        (false, 80) => 234,
        (false, 160) => 468,
        (true, 20) => 234,
        (true, 40) => 468,
        (true, 80) => 980,
        (true, 160) => 1960,
        _ => return None,
    };
    Some((sd, if he { 13_600 } else { 3_600 }))
}

/// The bits per subcarrier and the coding rate (numerator, denominator) of
/// an MCS index (0 to 11).
fn modulation(mcs: u8) -> Option<(u32, u32, u32)> {
    const TABLE: [(u32, u32, u32); 12] = [
        (1, 1, 2),
        (2, 1, 2),
        (2, 3, 4),
        (4, 1, 2),
        (4, 3, 4),
        (6, 2, 3),
        (6, 3, 4),
        (6, 5, 6),
        (8, 3, 4),
        (8, 5, 6),
        (10, 3, 4),
        (10, 5, 6),
    ];
    TABLE.get(usize::from(mcs)).copied()
}

/// The best rate, kbit/s, a client of `caps` gets on a radio of
/// `radio_width_mhz`: its mode, streams and highest MCS on the narrower of
/// its and the radio's widths, with the short guard interval; 54 Mbit/s for
/// a legacy client; none for a width or MCS no table holds.
pub fn best_rate_kbps(caps: StationCaps, radio_width_mhz: u16) -> Option<u32> {
    if caps.mode == RateMode::Legacy {
        return Some(54_000);
    }
    let width = caps.width_mhz.min(radio_width_mhz);
    let (sd, ns) = ofdm(caps.mode, width)?;
    let (bits, num, den) = modulation(caps.mcs)?;
    let bits = u64::from(sd * bits * num) * u64::from(caps.nss.max(1));
    Some((bits * 1_000_000 / u64::from(den * ns)) as u32)
}

/// A client's parts and score, and its failed roams in the last hour, which
/// its roaming part's figure (its sticky share) does not say.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Experience {
    pub parts: Parts,
    pub score: Option<u8>,
    pub failed_roams: u32,
}

/// An AP's: the mean of its clients' scores, each part's mean, its clients
/// counted, and its three weakest (MAC and score, lowest first).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ApExperience {
    pub score: Option<u8>,
    pub parts: [Option<f64>; 5],
    pub clients: usize,
    pub weakest: Vec<([u8; 6], u8)>,
}

/// Every associated client's experience, by MAC, and each AP's.
#[derive(Debug, Default)]
pub struct Site {
    pub clients: BTreeMap<[u8; 6], Experience>,
    pub aps: BTreeMap<String, ApExperience>,
}

/// The weakest clients an AP names.
const WEAKEST: usize = 3;

/// The experience of every associated client and of each AP with clients,
/// at `now_ms`.
pub fn site(state: &State, now_ms: u64) -> Site {
    let mut site = Site::default();
    let mut by_ap: BTreeMap<String, Vec<([u8; 6], Experience)>> = BTreeMap::new();
    let clients = state.clients();
    let macs = clients.iter().map(|c| &c.station.mac);
    let facts = state.roaming.all_facts(macs, now_ms);
    for c in clients {
        let Some(i) = inputs(state, &c, facts.get(&c.station.mac)) else {
            continue;
        };
        let parts = parts(&i);
        let e = Experience {
            score: score(&parts),
            parts,
            failed_roams: i.failed_roams,
        };
        by_ap
            .entry(c.ap)
            .or_default()
            .push((c.station.mac, e.clone()));
        site.clients.insert(c.station.mac, e);
    }
    for (ap, list) in by_ap {
        let mean = |v: Vec<f64>| (!v.is_empty()).then(|| v.iter().sum::<f64>() / v.len() as f64);
        let scores: Vec<f64> = list
            .iter()
            .filter_map(|(_, e)| e.score)
            .map(f64::from)
            .collect();
        let part = |i: usize| {
            let v = list.iter().filter_map(|(_, e)| Some(e.parts.0[i]?.score));
            mean(v.collect()).map(|m| m.round())
        };
        let mut weakest: Vec<([u8; 6], u8)> = list
            .iter()
            .filter_map(|(m, e)| Some((*m, e.score?)))
            .collect();
        weakest.sort_by_key(|&(m, s)| (s, m));
        weakest.truncate(WEAKEST);
        let a = ApExperience {
            score: mean(scores).map(|m| m.round() as u8),
            parts: [0, 1, 2, 3, 4].map(part),
            clients: list.len(),
            weakest,
        };
        site.aps.insert(ap, a);
    }
    site
}

/// What a client's parts come from: its station in its AP's last two
/// snapshots, its radio's survey between them, what it supports, and what
/// `roaming` says of it.
fn inputs(state: &State, c: &ClientView, facts: Option<&Facts>) -> Option<Inputs> {
    let ap = state.ap(&c.ap)?;
    let snap = ap.snapshot.as_ref()?;
    let st = &c.station;
    let phy = &snap.bsss.get(usize::from(st.bss))?.phy;
    let radio = snap.radios.iter().find(|r| &r.phy == phy)?;
    let prev = ap.previous.as_ref().map(|(p, _)| p);
    let was = prev.and_then(|p| station(p, &st.mac));
    let moved = |a: u64, b: u64| b.checked_sub(a);
    let sent = was.and_then(|w| moved(w.tx_packets, st.tx_packets));
    let retries = was.and_then(|w| moved(w.tx_retries.into(), st.tx_retries.into()));
    let before = prev.and_then(|p| p.radios.iter().find(|r| &r.phy == phy));
    let contention = before.and_then(|b| {
        let active = moved(b.active_ms, radio.active_ms).filter(|&a| a > 0)?;
        let busy = moved(b.busy_ms, radio.busy_ms)?;
        let own = moved(b.tx_ms, radio.tx_ms)?;
        Some((busy.saturating_sub(own) as f64 / active as f64).min(1.0))
    });
    let caps = snap.caps.binary_search_by_key(&st.mac, |(m, _)| *m);
    Some(Inputs {
        signal: if st.signal_avg != 0 {
            st.signal_avg
        } else {
            st.signal
        },
        sent: sent.unwrap_or(0),
        retries: retries.unwrap_or(0),
        tx_rate_kbps: st.tx_rate_kbps,
        caps: caps.ok().map(|i| snap.caps[i].1),
        radio_width_mhz: radio.width_mhz,
        contention,
        sticky: facts.map_or(0.0, |f| f.sticky_share),
        failed_roams: facts.map_or(0, |f| f.failed_hour),
    })
}

fn station<'a>(s: &'a Snapshot, mac: &[u8; 6]) -> Option<&'a Station> {
    let i = s.stations.binary_search_by_key(mac, |t| t.mac).ok()?;
    Some(&s.stations[i])
}

/// A client's experience as the UI and the API show it: the score, each
/// present part's score and figure by name, and its failed roams in the
/// last hour.
pub fn json(e: &Experience) -> Value {
    json!({ "score": e.score, "parts": parts_json(&e.parts), "failed_roams": e.failed_roams })
}

/// An AP's experience as the UI and the API show it.
pub fn ap_json(a: &ApExperience) -> Value {
    let parts: Map<String, Value> = PARTS
        .iter()
        .zip(a.parts)
        .filter_map(|(name, p)| Some(((*name).into(), p?.into())))
        .collect();
    let weakest: Vec<Value> = a
        .weakest
        .iter()
        .map(|(m, s)| json!({ "mac": u6e_proto::mac::format(*m), "score": s }))
        .collect();
    json!({ "score": a.score, "parts": parts, "clients": a.clients, "weakest": weakest })
}

fn parts_json(parts: &Parts) -> Value {
    let o: Map<String, Value> = PARTS
        .iter()
        .zip(&parts.0)
        .filter_map(|(name, p)| {
            let p = p.as_ref()?;
            Some((
                (*name).into(),
                json!({ "score": p.score, "value": p.value }),
            ))
        })
        .collect();
    Value::Object(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(mode: RateMode, nss: u8, mcs: u8, width_mhz: u16) -> Option<StationCaps> {
        Some(StationCaps {
            mode,
            nss,
            mcs,
            width_mhz,
        })
    }

    /// Each part's score, `None` for one left out.
    fn scores(p: &Parts) -> [Option<f64>; 5] {
        p.0.map(|p| p.map(|p| p.score))
    }

    /// The rate tables give the rates the APs report at the top MCS:
    /// HT MCS 7 of one stream at 20 MHz, VHT MCS 9 of two at 80 MHz, HE MCS
    /// 9 of two at 160 MHz (as the phone of the recorded cases was sent at),
    /// and HE MCS 11 of two at 160 MHz.
    #[test]
    fn the_best_rate_is_the_standards_rate_at_the_narrower_width() {
        let best = |c: Option<StationCaps>, w| best_rate_kbps(c.unwrap(), w);
        assert_eq!(best(caps(RateMode::Ht, 1, 7, 40), 20), Some(72_222));
        assert_eq!(best(caps(RateMode::Ht, 1, 7, 40), 40), Some(150_000));
        assert_eq!(best(caps(RateMode::Vht, 2, 9, 80), 80), Some(866_666));
        assert_eq!(best(caps(RateMode::Vht, 1, 9, 160), 80), Some(433_333));
        assert_eq!(best(caps(RateMode::He, 2, 9, 160), 160), Some(1_921_568));
        assert_eq!(best(caps(RateMode::He, 2, 11, 160), 160), Some(2_401_960));
        assert_eq!(best(caps(RateMode::He, 2, 11, 160), 80), Some(1_200_980));
        assert_eq!(best(caps(RateMode::Legacy, 1, 0, 20), 20), Some(54_000));
        // Nothing a table holds: a width no radio has, an MCS past 11; such
        // a client has no rate part.
        assert_eq!(best(caps(RateMode::He, 2, 11, 160), 10), None);
        assert_eq!(best(caps(RateMode::He, 2, 12, 80), 80), None);
        let odd = Inputs {
            signal: -60,
            sent: 100,
            retries: 0,
            tx_rate_kbps: 6000,
            caps: caps(RateMode::He, 2, 12, 80),
            radio_width_mhz: 80,
            contention: None,
            sticky: 0.0,
            failed_roams: 0,
        };
        assert_eq!(parts(&odd).0[3], None);
    }

    #[test]
    fn each_part_runs_from_its_zero_to_its_full_mark() {
        let at = |signal, retries, contention, rate_kbps| Inputs {
            signal,
            sent: 100,
            retries,
            tx_rate_kbps: rate_kbps,
            caps: caps(RateMode::Vht, 1, 9, 80),
            radio_width_mhz: 80,
            contention: Some(contention),
            sticky: 0.0,
            failed_roams: 0,
        };
        let best = 433_333;
        assert_eq!(
            scores(&parts(&at(-60, 0, 0.2, best))),
            [
                Some(100.0),
                Some(100.0),
                Some(100.0),
                Some(100.0),
                Some(100.0)
            ]
        );
        assert_eq!(
            scores(&parts(&at(-80, 67, 0.7, 1))),
            [Some(0.0), Some(0.0), Some(0.0), Some(0.0), Some(100.0)]
        );
        // Half way: -70 dBm, 20 % retries (25 of 125), 45 % busy, 37.5 %
        // of the best rate.
        let half = parts(&at(-70, 25, 0.45, best * 375 / 1000));
        assert_eq!(
            scores(&half),
            [Some(50.0), Some(50.0), Some(50.0), Some(50.0), Some(100.0)]
        );
        assert_eq!(half.0[1].unwrap().value, 20.0);
        assert_eq!(half.0[2].unwrap().value, 45.0);
        // The roaming part: 15 minutes sticky and a failed roam.
        let mut i = at(-60, 0, 0.2, best);
        i.sticky = 0.25;
        i.failed_roams = 1;
        assert_eq!(parts(&i).0[4].unwrap().score, 50.0);
        i.failed_roams = 5;
        assert_eq!(parts(&i).0[4].unwrap().score, 0.0);
    }

    /// An idle client (fewer than 20 frames sent it) has no retries or rate
    /// part, one of unknown capabilities no rate part, one before its radio's
    /// second survey no contention part; the score is of the parts it has.
    #[test]
    fn a_part_without_its_figure_is_left_out() {
        let idle = Inputs {
            signal: -60,
            sent: 19,
            retries: 0,
            tx_rate_kbps: 6000,
            caps: caps(RateMode::He, 2, 11, 80),
            radio_width_mhz: 80,
            contention: None,
            sticky: 0.0,
            failed_roams: 0,
        };
        let p = parts(&idle);
        assert_eq!(scores(&p), [Some(100.0), None, None, None, Some(100.0)]);
        assert_eq!(score(&p), Some(100));
        let unknown = Inputs {
            sent: 20,
            caps: None,
            ..idle
        };
        assert_eq!(scores(&parts(&unknown))[3], None);
        assert_eq!(score(&Parts::default()), None);
    }

    /// One bad part is not hidden by good ones: the score is at most 40
    /// above the worst.
    #[test]
    fn the_score_is_never_far_above_its_worst_part() {
        let part = |score| Some(Part { score, value: 0.0 });
        let good_but_one = Parts([
            part(0.0),
            part(100.0),
            part(100.0),
            part(100.0),
            part(100.0),
        ]);
        assert_eq!(score(&good_but_one), Some(40));
        let even = Parts([part(60.0), part(80.0), part(100.0), part(80.0), part(100.0)]);
        // (60·30 + 80·20 + 100·15 + 80·20 + 100·15) / 100 = 80.
        assert_eq!(score(&even), Some(80));
    }

    /// Clients as the controller saw them on 2026-11-23 (10 minutes of its
    /// live state, 40 readings of 17 clients; the median of each figure),
    /// each pinned to its parts and score; and the speakers' complaint:
    /// one stuck far for 50 minutes of the hour, with a failed roam.
    #[test]
    fn recorded_clients_score_as_pinned() {
        struct Case {
            what: &'static str,
            inputs: Inputs,
            parts: [Option<f64>; 5],
            score: u8,
        }
        let client = |signal, sent, tx_rate_kbps, c, width, contention| Inputs {
            signal,
            sent,
            retries: 0,
            tx_rate_kbps,
            caps: c,
            radio_width_mhz: width,
            contention: Some(contention),
            sticky: 0.0,
            failed_roams: 0,
        };
        let cases = [
            Case {
                what: "a phone of 2x2 HE, weak on 5 GHz, sent at HE MCS 6",
                inputs: client(
                    -74,
                    2000,
                    648_500,
                    caps(RateMode::He, 2, 11, 160),
                    80,
                    0.049,
                ),
                parts: [
                    Some(30.0),
                    Some(100.0),
                    Some(100.0),
                    Some(72.0),
                    Some(100.0),
                ],
                score: 70,
            },
            Case {
                what: "a tablet of 2x2 VHT at its best rate",
                inputs: client(-53, 40, 866_700, caps(RateMode::Vht, 2, 9, 80), 80, 0.049),
                parts: [Some(100.0); 5],
                score: 100,
            },
            Case {
                what: "a tablet of 2x2 VHT at -73 dBm, sent at VHT MCS 7",
                inputs: client(-73, 400, 585_100, caps(RateMode::Vht, 2, 9, 80), 80, 0.049),
                parts: [
                    Some(35.0),
                    Some(100.0),
                    Some(100.0),
                    Some(90.0),
                    Some(100.0),
                ],
                score: 75,
            },
            Case {
                what: "a plug on 2.4 GHz at -77 dBm, sent at 24 Mbit/s legacy",
                inputs: client(-77, 30, 24_000, caps(RateMode::Ht, 1, 7, 20), 20, 0.135),
                parts: [
                    Some(15.0),
                    Some(100.0),
                    Some(100.0),
                    Some(44.0),
                    Some(100.0),
                ],
                score: 55,
            },
            Case {
                what: "the plug at -78 dBm the reading its retries showed, 2 of 51 frames",
                inputs: Inputs {
                    retries: 2,
                    ..client(-78, 49, 24_000, caps(RateMode::Ht, 1, 7, 20), 20, 0.135)
                },
                parts: [Some(10.0), Some(90.0), Some(100.0), Some(44.0), Some(100.0)],
                score: 50,
            },
            Case {
                what: "an idle speaker on 5 GHz",
                inputs: client(-55, 3, 72_200, caps(RateMode::Ht, 1, 7, 20), 80, 0.021),
                parts: [Some(100.0), None, Some(100.0), None, Some(100.0)],
                score: 100,
            },
            Case {
                what: "a speaker stuck far for 50 minutes of the hour, one roam failed",
                inputs: Inputs {
                    sticky: 50.0 / 60.0,
                    failed_roams: 1,
                    ..client(-78, 3, 72_200, caps(RateMode::Ht, 1, 7, 20), 80, 0.021)
                },
                parts: [Some(10.0), None, Some(100.0), None, Some(0.0)],
                score: 30,
            },
        ];
        for c in cases {
            let p = parts(&c.inputs);
            assert_eq!(scores(&p), c.parts, "{}", c.what);
            assert_eq!(score(&p), Some(c.score), "{}", c.what);
        }
    }
}
