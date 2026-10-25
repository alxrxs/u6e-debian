//! A station's link rate across the legacy samples between its data frames.
//! nl80211 reports the rate of the last frame each way, so an HT/VHT/HE client
//! reads "6 Mbps legacy" whenever a management or control frame went last;
//! while its last HT/VHT/HE sample is recent, that is the rate it is on.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use u6e_proto::msg::{RateMode, Station};

/// How long an HT/VHT/HE sample stands in for the legacy ones after it: four
/// of the agent's 15 s idle ticks, so a legacy sample at an idle tick is held
/// too, not only those of the 2 s watched tick.
const HOLD: Duration = Duration::from_secs(60);

/// One direction's rate: kbit/s, mode, MCS and spatial streams.
type Rate = (u32, RateMode, u8, u8);

/// The last HT/VHT/HE sample of each station, transmit then receive.
#[derive(Debug, Default)]
pub struct RateHold {
    last: HashMap<[u8; 6], [Option<(Rate, Instant)>; 2]>,
}

impl RateHold {
    /// Replaces each legacy rate in `stations` by the station's last
    /// HT/VHT/HE one of that direction, if it is younger than [`HOLD`].
    /// Stations that are gone are forgotten.
    pub fn apply(&mut self, stations: &mut [Station], now: Instant) {
        let mut next = HashMap::with_capacity(stations.len());
        for s in stations {
            let [tx, rx] = self.last.get(&s.mac).copied().unwrap_or_default();
            let (rate, tx) = hold((s.tx_rate_kbps, s.tx_mode, s.tx_mcs, s.tx_nss), tx, now);
            (s.tx_rate_kbps, s.tx_mode, s.tx_mcs, s.tx_nss) = rate;
            let (rate, rx) = hold((s.rx_rate_kbps, s.rx_mode, s.rx_mcs, s.rx_nss), rx, now);
            (s.rx_rate_kbps, s.rx_mode, s.rx_mcs, s.rx_nss) = rate;
            next.insert(s.mac, [tx, rx]);
        }
        self.last = next;
    }
}

/// The rate to report for the sample `cur`, and the HT/VHT/HE sample to keep.
fn hold(cur: Rate, last: Option<(Rate, Instant)>, now: Instant) -> (Rate, Option<(Rate, Instant)>) {
    if cur.1 != RateMode::Legacy {
        return (cur, Some((cur, now)));
    }
    match last {
        Some((rate, at)) if now.duration_since(at) < HOLD => (rate, last),
        _ => (cur, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEGACY: Rate = (6_000, RateMode::Legacy, 0, 0);
    const HE: Rate = (648_500, RateMode::He, 6, 2);
    const VHT: Rate = (866_700, RateMode::Vht, 9, 2);

    fn station(mac: u8, tx: Rate, rx: Rate) -> Station {
        Station {
            mac: [2, 0, 0, 0, 0, mac],
            bss: 0,
            signal: -50,
            signal_avg: -50,
            rx_bytes: 0,
            tx_bytes: 0,
            rx_packets: 0,
            tx_packets: 0,
            tx_retries: 0,
            tx_failed: 0,
            tx_rate_kbps: tx.0,
            rx_rate_kbps: rx.0,
            tx_mcs: tx.2,
            rx_mcs: rx.2,
            tx_mode: tx.1,
            rx_mode: rx.1,
            tx_nss: tx.3,
            rx_nss: rx.3,
            tx_airtime_us: 0,
            rx_airtime_us: 0,
            inactive_ms: 0,
            connected_s: 0,
            vlan: 42,
        }
    }

    fn rates(s: &Station) -> (Rate, Rate) {
        (
            (s.tx_rate_kbps, s.tx_mode, s.tx_mcs, s.tx_nss),
            (s.rx_rate_kbps, s.rx_mode, s.rx_mcs, s.rx_nss),
        )
    }

    /// Feeds one sample of one station `secs` after `t0` and reads it back.
    fn sample(h: &mut RateHold, t0: Instant, secs: u64, tx: Rate, rx: Rate) -> (Rate, Rate) {
        let mut s = [station(1, tx, rx)];
        h.apply(&mut s, t0 + Duration::from_secs(secs));
        rates(&s[0])
    }

    /// The flap measured on an AP: an HE client between its data frames.
    #[test]
    fn a_legacy_sample_after_a_recent_he_one_reads_as_the_he_rate() {
        let (mut h, t0) = (RateHold::default(), Instant::now());
        assert_eq!(sample(&mut h, t0, 0, HE, HE), (HE, HE));
        assert_eq!(sample(&mut h, t0, 15, LEGACY, LEGACY), (HE, HE));
        assert_eq!(sample(&mut h, t0, 45, LEGACY, LEGACY), (HE, HE));
    }

    #[test]
    fn a_held_rate_lapses_after_the_hold() {
        let (mut h, t0) = (RateHold::default(), Instant::now());
        sample(&mut h, t0, 0, HE, HE);
        assert_eq!(sample(&mut h, t0, 59, LEGACY, LEGACY), (HE, HE));
        assert_eq!(sample(&mut h, t0, 60, LEGACY, LEGACY), (LEGACY, LEGACY));
        assert_eq!(
            sample(&mut h, t0, 61, LEGACY, LEGACY),
            (LEGACY, LEGACY),
            "a lapsed rate is not held again"
        );
    }

    /// The hold counts from the newest HT/VHT/HE sample, which always shows.
    #[test]
    fn every_non_legacy_sample_shows_and_restarts_the_hold() {
        let (mut h, t0) = (RateHold::default(), Instant::now());
        sample(&mut h, t0, 0, HE, HE);
        assert_eq!(sample(&mut h, t0, 50, VHT, HE), (VHT, HE));
        assert_eq!(sample(&mut h, t0, 100, LEGACY, LEGACY), (VHT, HE));
    }

    #[test]
    fn each_direction_holds_its_own_rate() {
        let (mut h, t0) = (RateHold::default(), Instant::now());
        sample(&mut h, t0, 0, HE, LEGACY);
        assert_eq!(sample(&mut h, t0, 2, LEGACY, LEGACY), (HE, LEGACY));
        sample(&mut h, t0, 4, LEGACY, VHT);
        assert_eq!(sample(&mut h, t0, 6, LEGACY, LEGACY), (HE, VHT));
    }

    #[test]
    fn a_legacy_client_keeps_its_rates() {
        let (mut h, t0) = (RateHold::default(), Instant::now());
        let g = (54_000, RateMode::Legacy, 0, 0);
        assert_eq!(sample(&mut h, t0, 0, g, LEGACY), (g, LEGACY));
        assert_eq!(sample(&mut h, t0, 2, LEGACY, g), (LEGACY, g));
    }

    /// A station that left and associates again starts afresh, and one
    /// station's rate never stands in for another's.
    #[test]
    fn stations_are_held_apart_and_forgotten_when_gone() {
        let (mut h, t0) = (RateHold::default(), Instant::now());
        let mut both = [station(1, HE, HE), station(2, LEGACY, LEGACY)];
        h.apply(&mut both, t0);
        assert_eq!(rates(&both[1]), (LEGACY, LEGACY));
        h.apply(
            &mut [station(2, LEGACY, LEGACY)],
            t0 + Duration::from_secs(2),
        );
        assert_eq!(sample(&mut h, t0, 4, LEGACY, LEGACY), (LEGACY, LEGACY));
    }
}
