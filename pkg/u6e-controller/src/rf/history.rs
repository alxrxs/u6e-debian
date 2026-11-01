//! What each radio's snapshots said over the last hours, for the RF planner:
//! per hour and per channel the radio was on, the survey's time (active,
//! busy, transmitting), the airtime its own clients took sending, the noise
//! floor, and how long its clients spent at each signal. It is built from
//! each pair of consecutive snapshots as they come, kept in RAM only, and an
//! hour past the window is dropped; a controller that restarts starts over.

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use u6e_proto::msg::{Band, Radio, Snapshot};

/// The hours kept unless the configuration says otherwise.
pub const WINDOW: u64 = 24;
/// The signal histogram's lowest bin and its width, dBm; a signal outside
/// it counts in the bin at its end.
pub const RSSI_FLOOR: i16 = -100;
pub const RSSI_STEP: i16 = 2;
pub const RSSI_BINS: usize = 40;
/// Two snapshots further apart than this are not compared: the counters
/// between them say nothing of any one hour.
const GAP: Duration = Duration::from_secs(600);

/// One radio's hour on one channel and width.
#[derive(Debug, Clone, PartialEq)]
pub struct Hour {
    /// Hours since the Unix epoch.
    pub hour: u64,
    pub channel: u16,
    pub width: u16,
    /// The wall time the counters cover, s.
    pub secs: f64,
    pub active_ms: u64,
    pub busy_ms: u64,
    pub tx_ms: u64,
    /// What its clients' frames to it took of the air.
    pub own_rx_ms: u64,
    /// The noise floor over `secs`, dBm·s.
    pub noise: f64,
    /// Client-seconds at each signal (from [`RSSI_FLOOR`], [`RSSI_STEP`] dB a bin).
    pub rssi: [f32; RSSI_BINS],
}

impl Hour {
    fn new(hour: u64, r: &Radio) -> Hour {
        Hour {
            hour,
            channel: r.channel,
            width: r.width_mhz,
            secs: 0.0,
            active_ms: 0,
            busy_ms: 0,
            tx_ms: 0,
            own_rx_ms: 0,
            noise: 0.0,
            rssi: [0.0; RSSI_BINS],
        }
    }
}

/// The bin of a signal.
pub fn bin(dbm: i8) -> usize {
    let i = (i16::from(dbm) - RSSI_FLOOR).div_euclid(RSSI_STEP);
    i.clamp(0, RSSI_BINS as i16 - 1) as usize
}

/// The signal at the middle of bin `i`, dBm.
pub fn bin_dbm(i: usize) -> f64 {
    f64::from(RSSI_FLOOR) + (i as f64 + 0.5) * f64::from(RSSI_STEP)
}

/// One radio's hours, oldest first.
#[derive(Debug, Clone)]
pub struct RadioHistory {
    pub band: Band,
    pub hours: VecDeque<Hour>,
}

/// Every radio's hours, by AP and radio name.
#[derive(Debug, Clone)]
pub struct History {
    window: u64,
    radios: BTreeMap<(String, String), RadioHistory>,
}

fn hour_of(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() / 3600)
}

impl History {
    /// A history keeping `window` hours (the current one included).
    pub fn new(window: u64) -> History {
        History {
            window: window.max(1),
            radios: BTreeMap::new(),
        }
    }

    pub fn window(&self) -> u64 {
        self.window
    }

    /// The radios of `ap` with their hours.
    pub fn of<'a>(&'a self, ap: &'a str) -> impl Iterator<Item = (&'a str, &'a RadioHistory)> + 'a {
        let radios = self.radios.iter().filter(move |((a, _), _)| a == ap);
        radios.map(|((_, phy), h)| (phy.as_str(), h))
    }

    /// Every radio's hours.
    pub fn all(&self) -> impl Iterator<Item = (&str, &RadioHistory)> {
        self.radios.iter().map(|((ap, _), h)| (ap.as_str(), h))
    }

    /// Takes in what changed between two snapshots of `ap`, `prev` at
    /// `then` and `now` at `at`, into the hour of `at`.
    pub fn observe(
        &mut self,
        ap: &str,
        prev: &Snapshot,
        then: SystemTime,
        now: &Snapshot,
        at: SystemTime,
    ) {
        let Some(secs) = at
            .duration_since(then)
            .ok()
            .filter(|d| !d.is_zero() && *d <= GAP)
        else {
            return;
        };
        let secs = secs.as_secs_f64();
        let hour = hour_of(at);
        for r in now.radios.iter().filter(|r| r.up) {
            let Some(p) = prev.radios.iter().find(|p| p.phy == r.phy) else {
                continue;
            };
            // A channel change or a restarted counter: the deltas are of no
            // one channel.
            if (p.channel, p.width_mhz, p.up) != (r.channel, r.width_mhz, true) {
                continue;
            }
            let moved = |a: u64, b: u64| b.checked_sub(a);
            let (Some(active), Some(busy), Some(tx)) = (
                moved(p.active_ms, r.active_ms),
                moved(p.busy_ms, r.busy_ms),
                moved(p.tx_ms, r.tx_ms),
            ) else {
                continue;
            };
            let on_radio = |s: &Snapshot, bss: u16| {
                s.bsss.get(usize::from(bss)).is_some_and(|b| b.phy == r.phy)
            };
            let mut own_rx_us = 0;
            let mut rssi = [0.0f32; RSSI_BINS];
            for st in now.stations.iter().filter(|st| on_radio(now, st.bss)) {
                rssi[bin(st.signal_avg)] += secs as f32;
                let before = prev.stations.binary_search_by_key(&st.mac, |s| s.mac).ok();
                let before = before
                    .map(|i| &prev.stations[i])
                    .filter(|b| on_radio(prev, b.bss));
                if let Some(b) = before {
                    own_rx_us += st.rx_airtime_us.saturating_sub(b.rx_airtime_us);
                }
            }
            let key = (ap.to_owned(), r.phy.clone());
            let radio = self.radios.entry(key).or_insert_with(|| RadioHistory {
                band: r.band,
                hours: VecDeque::new(),
            });
            radio.band = r.band;
            let same =
                |h: &&mut Hour| (h.hour, h.channel, h.width) == (hour, r.channel, r.width_mhz);
            let h = match radio.hours.iter_mut().rev().find(same) {
                Some(h) => h,
                None => {
                    radio.hours.push_back(Hour::new(hour, r));
                    radio.hours.back_mut().expect("just pushed")
                }
            };
            h.secs += secs;
            h.active_ms += active;
            h.busy_ms += busy.min(active);
            h.tx_ms += tx.min(active);
            h.own_rx_ms += own_rx_us / 1000;
            h.noise += f64::from(r.noise_dbm) * secs;
            for (a, b) in h.rssi.iter_mut().zip(rssi) {
                *a += b;
            }
        }
        self.prune(hour);
    }

    /// Drops the hours that have left the window ending at `hour`.
    fn prune(&mut self, hour: u64) {
        let oldest = hour.saturating_sub(self.window - 1);
        for radio in self.radios.values_mut() {
            radio.hours.retain(|h| h.hour >= oldest);
        }
        self.radios.retain(|_, r| !r.hours.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use u6e_proto::msg::{Bss, RateMode, Station};

    fn radio(channel: u16, active: u64, busy: u64, tx: u64) -> Radio {
        Radio {
            phy: "radio5".into(),
            band: Band::B5,
            channel,
            width_mhz: 80,
            txpower_mbm: 2300,
            noise_dbm: -95,
            active_ms: active,
            busy_ms: busy,
            rx_ms: 0,
            tx_ms: tx,
            up: true,
            max_txpower_dbm: 0,
        }
    }

    fn station(last: u8, signal: i8, rx_air_us: u64) -> Station {
        Station {
            mac: [2, 0, 0, 0, 0, last],
            bss: 0,
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
            tx_mode: RateMode::Legacy,
            rx_mode: RateMode::Legacy,
            tx_nss: 0,
            rx_nss: 0,
            tx_airtime_us: 0,
            rx_airtime_us: rx_air_us,
            inactive_ms: 0,
            connected_s: 0,
            vlan: 0,
        }
    }

    fn snap(radios: Vec<Radio>, stations: Vec<Station>) -> Snapshot {
        Snapshot {
            seq: 1,
            uptime_s: 0,
            load_milli: 0,
            mem_avail_kb: 0,
            nss_load_pct: 0,
            temps: Vec::new(),
            radios,
            bsss: vec![Bss {
                ifname: "wlan5".into(),
                bssid: [2, 0, 0, 0, 1, 0],
                ssid: "ssid-a".into(),
                phy: "radio5".into(),
                vlan: 0,
            }],
            stations,
            config_sha256: None,
            clock_synced: true,
            power_limits: Vec::new(),
        }
    }

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn deltas_land_in_their_hour_and_channel() {
        let mut h = History::new(24);
        let t0 = 1000 * 3600;
        let a = snap(vec![radio(36, 0, 0, 0)], vec![station(1, -61, 0)]);
        let b = snap(
            vec![radio(36, 10_000, 4000, 1000)],
            vec![station(1, -61, 500_000)],
        );
        h.observe("ap1", &a, at(t0), &b, at(t0 + 10));
        // A restarted counter and a channel change add nothing.
        let c = snap(vec![radio(36, 5, 0, 0)], vec![]);
        h.observe("ap1", &b, at(t0 + 10), &c, at(t0 + 20));
        let d = snap(vec![radio(52, 20_000, 0, 0)], vec![]);
        h.observe("ap1", &c, at(t0 + 20), &d, at(t0 + 30));
        let e = snap(vec![radio(52, 30_000, 1000, 0)], vec![]);
        h.observe("ap1", &d, at(t0 + 30), &e, at(t0 + 3600));
        let (phy, r) = h.of("ap1").next().unwrap();
        assert_eq!(phy, "radio5");
        let got: Vec<_> = r
            .hours
            .iter()
            .map(|h| (h.hour, h.channel, h.active_ms, h.busy_ms))
            .collect();
        assert_eq!(got, [(1000, 36, 10_000, 4000)]);
        let first = &r.hours[0];
        assert_eq!((first.tx_ms, first.own_rx_ms), (1000, 500));
        assert_eq!(first.noise / first.secs, -95.0);
        assert_eq!(first.rssi[bin(-61)], 10.0);
        // A gap longer than ten minutes is not one interval.
        assert_eq!(r.hours.len(), 1);
        let f = snap(vec![radio(52, 40_000, 2000, 0)], vec![]);
        h.observe("ap1", &e, at(t0 + 3600), &f, at(t0 + 3660));
        let r = h.of("ap1").next().unwrap().1;
        assert_eq!(
            r.hours.back().map(|h| (h.hour, h.channel)),
            Some((1001, 52))
        );
    }

    #[test]
    fn hours_leave_with_the_window() {
        let mut h = History::new(2);
        let a = snap(vec![radio(36, 0, 0, 0)], vec![]);
        let b = snap(vec![radio(36, 1000, 0, 0)], vec![]);
        for hour in 0..4 {
            let t = (500 + hour) * 3600;
            h.observe("ap1", &a, at(t), &b, at(t + 10));
        }
        let hours: Vec<_> = h
            .of("ap1")
            .next()
            .unwrap()
            .1
            .hours
            .iter()
            .map(|h| h.hour)
            .collect();
        assert_eq!(hours, [502, 503]);
    }

    #[test]
    fn signals_bin_and_clamp() {
        assert_eq!(bin(-100), 0);
        assert_eq!(bin(-99), 0);
        assert_eq!(bin(-98), 1);
        assert_eq!(bin(-127), 0);
        assert_eq!(bin(0), RSSI_BINS - 1);
        assert_eq!(bin_dbm(bin(-61)), -61.0);
    }
}
