//! Delta coding of snapshots: only the fields that changed since the previous
//! tick, as zigzag-varint differences under a change mask.

use std::collections::HashMap;

use crate::msg::{Band, FieldDelta, Radio, RecDelta, Snapshot, SnapshotDelta, Station};

/// The base of a delta is not the snapshot it is applied to, or the delta is
/// inconsistent with it: the receiver asks for a key frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gap;

const SCALARS: usize = 4;
const MAX_TEMPS: usize = 32 - SCALARS;

/// Whether [`diff`] can express the change from `prev` to `next`: the same
/// temperature zones (at most 28) and the same radios, which do not change
/// while a connection lives. Otherwise the sender sends a key frame.
pub fn same_shape(prev: &Snapshot, next: &Snapshot) -> bool {
    next.temps.len() <= MAX_TEMPS
        && prev.temps.len() == next.temps.len()
        && prev
            .temps
            .iter()
            .zip(&next.temps)
            .all(|(a, b)| a.zone == b.zone)
        && prev.radios.len() == next.radios.len()
        && prev
            .radios
            .iter()
            .zip(&next.radios)
            .all(|(a, b)| a.phy == b.phy)
}

/// The difference from `prev` to `next` (which must have the same shape),
/// stations matched by MAC. `next.stations` must be sorted by MAC.
pub fn diff(prev: &Snapshot, next: &Snapshot) -> SnapshotDelta {
    debug_assert!(same_shape(prev, next));
    let (mask, vals) = diff_fields(&scalar_fields(prev), &scalar_fields(next));
    let radios = prev
        .radios
        .iter()
        .zip(&next.radios)
        .enumerate()
        .filter_map(|(i, (a, b))| rec_delta(i, &radio_fields(a), &radio_fields(b)))
        .collect();

    let next_by_mac: HashMap<_, _> = next.stations.iter().map(|s| (s.mac, s)).collect();
    let prev_macs: HashMap<_, _> = prev.stations.iter().map(|s| (s.mac, ())).collect();
    let stations = prev
        .stations
        .iter()
        .enumerate()
        .filter_map(|(i, a)| {
            rec_delta(
                i,
                &station_fields(a),
                &station_fields(next_by_mac.get(&a.mac)?),
            )
        })
        .collect();
    let removed = prev
        .stations
        .iter()
        .map(|s| s.mac)
        .filter(|m| !next_by_mac.contains_key(m))
        .collect();
    let added = next
        .stations
        .iter()
        .filter(|s| !prev_macs.contains_key(&s.mac))
        .cloned()
        .collect();

    SnapshotDelta {
        seq: next.seq,
        base: prev.seq,
        scalars: FieldDelta { mask, vals },
        radios,
        stations,
        removed,
        added,
        bsss: (prev.bsss != next.bsss).then(|| next.bsss.clone()),
    }
}

/// Rebuilds the snapshot `d` was made from, given the one it was made against.
pub fn apply(base: &Snapshot, d: &SnapshotDelta) -> Result<Snapshot, Gap> {
    if d.base != base.seq {
        return Err(Gap);
    }
    let mut next = base.clone();
    next.seq = d.seq;

    let mut f = scalar_fields(base);
    apply_fields(&mut f, d.scalars.mask, &d.scalars.vals)?;
    next.uptime_s = f[0] as u32;
    next.load_milli = f[1] as u32;
    next.mem_avail_kb = f[2] as u32;
    next.nss_load_pct = f[3] as u8;
    for (t, &v) in next.temps.iter_mut().zip(&f[SCALARS..]) {
        t.milli_c = v as i32;
    }

    for r in &d.radios {
        let radio = next.radios.get_mut(usize::from(r.idx)).ok_or(Gap)?;
        let mut f = radio_fields(radio);
        apply_fields(&mut f, r.mask, &r.vals)?;
        *radio = radio_from(&radio.phy, &f)?;
    }
    if let Some(bsss) = &d.bsss {
        next.bsss.clone_from(bsss);
    }

    for r in &d.stations {
        let sta = next.stations.get_mut(usize::from(r.idx)).ok_or(Gap)?;
        let mut f = station_fields(sta);
        apply_fields(&mut f, r.mask, &r.vals)?;
        *sta = station_from(sta.mac, &f);
    }
    for mac in &d.removed {
        let at = next
            .stations
            .iter()
            .position(|s| s.mac == *mac)
            .ok_or(Gap)?;
        next.stations.remove(at);
    }
    next.stations.extend(d.added.iter().cloned());
    next.stations.sort_by_key(|s| s.mac);
    if next.stations.windows(2).any(|w| w[0].mac == w[1].mac) {
        return Err(Gap);
    }
    Ok(next)
}

/// The mask and differences of the fields that differ. Differences wrap, so
/// counters at the edge of their range and counters that restart round-trip.
fn diff_fields(a: &[i64], b: &[i64]) -> (u32, Vec<i64>) {
    let mut mask = 0;
    let mut vals = Vec::new();
    for (i, (x, y)) in a.iter().zip(b).enumerate() {
        if x != y {
            mask |= 1 << i;
            vals.push(y.wrapping_sub(*x));
        }
    }
    (mask, vals)
}

fn apply_fields(fields: &mut [i64], mask: u32, vals: &[i64]) -> Result<(), Gap> {
    let in_range = fields.len() >= 32 || mask >> fields.len() == 0;
    if !in_range || mask.count_ones() as usize != vals.len() {
        return Err(Gap);
    }
    let set = (0..fields.len()).filter(|i| mask >> i & 1 == 1);
    for (i, v) in set.zip(vals) {
        fields[i] = fields[i].wrapping_add(*v);
    }
    Ok(())
}

fn rec_delta(idx: usize, a: &[i64], b: &[i64]) -> Option<RecDelta> {
    let (mask, vals) = diff_fields(a, b);
    (mask != 0).then_some(RecDelta {
        idx: idx as u16,
        mask,
        vals,
    })
}

fn scalar_fields(s: &Snapshot) -> Vec<i64> {
    let head = [
        s.uptime_s.into(),
        s.load_milli.into(),
        s.mem_avail_kb.into(),
        s.nss_load_pct.into(),
    ];
    head.into_iter()
        .chain(s.temps.iter().map(|t| t.milli_c.into()))
        .collect()
}

fn radio_fields(r: &Radio) -> [i64; 10] {
    [
        r.band as i64,
        r.channel.into(),
        r.width_mhz.into(),
        r.txpower_mbm.into(),
        r.noise_dbm.into(),
        r.active_ms as i64,
        r.busy_ms as i64,
        r.rx_ms as i64,
        r.tx_ms as i64,
        r.up.into(),
    ]
}

fn radio_from(phy: &str, f: &[i64; 10]) -> Result<Radio, Gap> {
    let band = [Band::B24, Band::B5, Band::B6]
        .get(usize::try_from(f[0]).map_err(|_| Gap)?)
        .copied()
        .ok_or(Gap)?;
    Ok(Radio {
        phy: phy.to_owned(),
        band,
        channel: f[1] as u16,
        width_mhz: f[2] as u16,
        txpower_mbm: f[3] as i32,
        noise_dbm: f[4] as i8,
        active_ms: f[5] as u64,
        busy_ms: f[6] as u64,
        rx_ms: f[7] as u64,
        tx_ms: f[8] as u64,
        up: f[9] != 0,
    })
}

fn station_fields(s: &Station) -> [i64; 18] {
    [
        s.bss.into(),
        s.signal.into(),
        s.signal_avg.into(),
        s.rx_bytes as i64,
        s.tx_bytes as i64,
        s.rx_packets as i64,
        s.tx_packets as i64,
        s.tx_retries.into(),
        s.tx_failed.into(),
        s.tx_rate_kbps.into(),
        s.rx_rate_kbps.into(),
        s.tx_mcs.into(),
        s.rx_mcs.into(),
        s.tx_airtime_us as i64,
        s.rx_airtime_us as i64,
        s.inactive_ms.into(),
        s.connected_s.into(),
        s.vlan.into(),
    ]
}

fn station_from(mac: [u8; 6], f: &[i64; 18]) -> Station {
    Station {
        mac,
        bss: f[0] as u16,
        signal: f[1] as i8,
        signal_avg: f[2] as i8,
        rx_bytes: f[3] as u64,
        tx_bytes: f[4] as u64,
        rx_packets: f[5] as u64,
        tx_packets: f[6] as u64,
        tx_retries: f[7] as u32,
        tx_failed: f[8] as u32,
        tx_rate_kbps: f[9] as u32,
        rx_rate_kbps: f[10] as u32,
        tx_mcs: f[11] as u8,
        rx_mcs: f[12] as u8,
        tx_airtime_us: f[13] as u64,
        rx_airtime_us: f[14] as u64,
        inactive_ms: f[15] as u32,
        connected_s: f[16] as u32,
        vlan: f[17] as u16,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::{Band, Bss, Radio, Station, Temp};

    struct Rng(u64);

    impl Rng {
        fn next(&mut self, m: u64) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0 % m
        }
    }

    fn bsss() -> Vec<Bss> {
        (0..7)
            .map(|i| Bss {
                ifname: format!("wl{i}"),
                bssid: [0x02, 0, 0, 0, 0, i as u8],
                ssid: format!("net{}", i % 3),
                phy: format!("phy{}", i % 3),
                vlan: 10 + i as u16,
            })
            .collect()
    }

    /// 20 stations of three radios and seven BSSs, the measured sample (random
    /// counters, signals and rates) and the same stations 2 s later with three
    /// of them busy.
    fn fixture() -> (Snapshot, Snapshot) {
        let mut rng = Rng(0x1234_5678);
        let r = &mut |m| rng.next(m);
        let bsss = bsss();
        let mut a: Vec<Station> = (0..20)
            .map(|i| {
                let mac = [0xac, 0xbc, 0xb5, r(256) as u8, r(256) as u8, i as u8];
                let bss = r(7) as u16;
                Station {
                    mac,
                    bss,
                    signal: -40 - r(40) as i8,
                    signal_avg: -40 - r(40) as i8,
                    rx_bytes: 10_000_000 + r(5_000_000_000),
                    tx_bytes: 10_000_000 + r(20_000_000_000),
                    rx_packets: 100_000 + r(10_000_000),
                    tx_packets: 100_000 + r(20_000_000),
                    tx_retries: r(50_000) as u32,
                    tx_failed: r(500) as u32,
                    tx_rate_kbps: 72_200 + r(1_100_000) as u32,
                    rx_rate_kbps: 72_200 + r(1_100_000) as u32,
                    tx_mcs: r(12) as u8,
                    rx_mcs: r(12) as u8,
                    tx_airtime_us: r(100_000_000_000),
                    rx_airtime_us: r(10_000_000_000),
                    inactive_ms: r(10_000) as u32,
                    connected_s: r(100_000) as u32,
                    vlan: bsss[bss as usize].vlan,
                }
            })
            .collect();
        let mut b: Vec<Station> = a
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let mut t = s.clone();
                let k = if i % 7 == 0 { 1000 } else { 1 };
                t.rx_bytes += r(20_000 * k);
                t.tx_bytes += r(60_000 * k);
                t.rx_packets += r(30 * k);
                t.tx_packets += r(60 * k);
                t.tx_airtime_us += r(5_000 * k);
                t.rx_airtime_us += r(2_000 * k);
                t.inactive_ms = r(2000) as u32;
                t.connected_s += 2;
                if i % 7 == 0 {
                    t.signal += r(3) as i8 - 1;
                    t.tx_retries += r(40) as u32;
                    t.tx_rate_kbps = 72_200 + r(1_100_000) as u32;
                }
                t
            })
            .collect();
        a.sort_by_key(|s| s.mac);
        b.sort_by_key(|s| s.mac);

        let radios = [
            ("phy0", Band::B24, 6, 20),
            ("phy1", Band::B5, 36, 80),
            ("phy2", Band::B6, 37, 160),
        ]
        .iter()
        .map(|&(phy, band, channel, width_mhz)| Radio {
            phy: phy.into(),
            band,
            channel,
            width_mhz,
            txpower_mbm: 2300,
            noise_dbm: -95,
            active_ms: 1_000_000_000 + r(1_000_000),
            busy_ms: 100_000_000 + r(1_000_000),
            rx_ms: 50_000_000 + r(1_000_000),
            tx_ms: 20_000_000 + r(1_000_000),
            up: true,
        })
        .collect::<Vec<_>>();
        let temps = ["cpu", "nss", "phy0"].map(|z| Temp {
            zone: z.into(),
            milli_c: 55_000 + r(5_000) as i32,
        });
        let first = Snapshot {
            seq: 100,
            uptime_s: 86_400,
            load_milli: 120,
            mem_avail_kb: 700_000,
            nss_load_pct: 3,
            temps: temps.to_vec(),
            radios,
            bsss,
            stations: a,
        };
        let mut second = first.clone();
        second.seq += 1;
        second.uptime_s += 2;
        second.load_milli = 150;
        second.mem_avail_kb -= 12;
        second.temps[0].milli_c += 250;
        for rd in &mut second.radios {
            rd.active_ms += 2000;
            rd.busy_ms += 300 + r(200);
            rd.rx_ms += 100 + r(100);
            rd.tx_ms += 50 + r(100);
            rd.noise_dbm += r(3) as i8 - 1;
        }
        second.stations = b;
        (first, second)
    }

    fn roundtrips(prev: &Snapshot, next: &Snapshot) {
        let d = diff(prev, next);
        assert_eq!(&apply(prev, &d).unwrap(), next);
        let wire = postcard::to_stdvec(&d).unwrap();
        let d2: SnapshotDelta = postcard::from_bytes(&wire).unwrap();
        assert_eq!(&apply(prev, &d2).unwrap(), next);
    }

    fn successor(prev: &Snapshot) -> Snapshot {
        let mut next = prev.clone();
        next.seq += 1;
        next
    }

    #[test]
    fn unchanged() {
        let (a, _) = fixture();
        roundtrips(&a, &successor(&a));
    }

    #[test]
    fn counters_moved() {
        let (a, b) = fixture();
        roundtrips(&a, &b);
    }

    #[test]
    fn counter_going_backwards_or_wrapping() {
        let (a, _) = fixture();
        let mut n = successor(&a);
        n.stations[0].rx_bytes = 5;
        n.stations[1].tx_bytes = u64::MAX;
        n.stations[2].rx_bytes = 0;
        n.radios[0].busy_ms = 1;
        roundtrips(&a, &n);
    }

    #[test]
    fn station_added() {
        let (a, _) = fixture();
        let mut n = successor(&a);
        let mut s = n.stations[3].clone();
        s.mac = [0x02, 0, 0, 0, 0, 0x99];
        n.stations.push(s);
        n.stations.sort_by_key(|s| s.mac);
        roundtrips(&a, &n);
    }

    #[test]
    fn station_removed() {
        let (a, _) = fixture();
        let mut n = successor(&a);
        n.stations.remove(4);
        n.stations.remove(0);
        roundtrips(&a, &n);
    }

    #[test]
    fn station_roamed_to_another_bss() {
        let (a, _) = fixture();
        let mut n = successor(&a);
        n.stations[5].bss = (n.stations[5].bss + 1) % 7;
        n.stations[5].vlan += 1;
        roundtrips(&a, &n);
    }

    #[test]
    fn radio_channel_changed() {
        let (a, _) = fixture();
        let mut n = successor(&a);
        n.radios[1].channel = 149;
        n.radios[1].up = false;
        n.radios[2].band = Band::B5;
        roundtrips(&a, &n);
    }

    #[test]
    fn bss_list_changed() {
        let (a, _) = fixture();
        let mut n = successor(&a);
        n.bsss.pop();
        n.bsss[0].ssid = "other".into();
        roundtrips(&a, &n);
    }

    #[test]
    fn scalars_and_temps_changed() {
        let (a, _) = fixture();
        let mut n = successor(&a);
        n.uptime_s += 1;
        n.nss_load_pct = 90;
        n.temps[2].milli_c -= 1000;
        roundtrips(&a, &n);
    }

    #[test]
    fn shape_changes_are_detected() {
        let (a, _) = fixture();
        assert!(same_shape(&a, &successor(&a)));
        let mut n = successor(&a);
        n.temps.pop();
        assert!(!same_shape(&a, &n));
        let mut n = successor(&a);
        n.radios.pop();
        assert!(!same_shape(&a, &n));
        let mut n = successor(&a);
        n.radios[0].phy = "phy9".into();
        assert!(!same_shape(&a, &n));
    }

    #[test]
    fn gap_requests_key_frame() {
        let (a, b) = fixture();
        let mut d = diff(&a, &b);
        d.base += 1;
        assert_eq!(apply(&a, &d), Err(Gap));
    }

    #[test]
    fn inconsistent_delta_is_a_gap() {
        let (a, b) = fixture();
        let mut d = diff(&a, &b);
        d.stations[0].idx = 999;
        assert_eq!(apply(&a, &d), Err(Gap));
        let mut d = diff(&a, &b);
        d.stations[0].vals.pop();
        assert_eq!(apply(&a, &d), Err(Gap));
        let mut d = diff(&a, &b);
        d.removed.push([9; 6]);
        assert_eq!(apply(&a, &d), Err(Gap));
        let mut d = diff(&a, &b);
        d.radios[0].mask = 1 << 31;
        assert_eq!(apply(&a, &d), Err(Gap));
    }

    fn wire_len(v: &impl serde::Serialize) -> usize {
        postcard::to_stdvec(v).unwrap().len()
    }

    /// The 20 stations alone keep to the measured prototype's budget (1125 B
    /// full, 426 B delta); the BSS list, radios, temperatures and each
    /// station's VLAN come on top, and the whole frames stay within what this
    /// fixture measures.
    #[test]
    fn delta_is_small() {
        let (a, b) = fixture();
        let d = diff(&a, &b);
        println!(
            "full {} B (stations {}, bsss {}, radios {}), delta {} B (stations {}, radios {}, scalars {})",
            wire_len(&a),
            wire_len(&a.stations),
            wire_len(&a.bsss),
            wire_len(&a.radios),
            wire_len(&d),
            wire_len(&d.stations),
            wire_len(&d.radios),
            wire_len(&d.scalars),
        );
        assert!(
            wire_len(&d.stations) <= 450,
            "station deltas {} B",
            wire_len(&d.stations)
        );
        assert!(
            wire_len(&a.stations) <= 1200,
            "stations {} B",
            wire_len(&a.stations)
        );
        assert!(wire_len(&d) <= 500, "delta {} B", wire_len(&d));
        assert!(wire_len(&a) <= 1400, "full {} B", wire_len(&a));
    }

    #[test]
    fn unchanged_is_tiny() {
        let (a, _) = fixture();
        let n = successor(&a);
        let size = postcard::to_stdvec(&diff(&a, &n)).unwrap().len();
        assert!(size <= 16, "{size} B");
    }
}
