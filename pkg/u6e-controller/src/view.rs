//! The state as the web UI reads it: JSON keyed by name (APs, radios, BSSs,
//! clients by MAC, temperatures by zone), so that a change goes out as a JSON
//! merge patch (RFC 7386) of only the fields that changed. Rates, utilization
//! and retry ratios are worked out here from the counters of the AP's last two
//! snapshots, and rounded so that a steady value is not resent.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};
use u6e_proto::PROTOCOL;
use u6e_proto::msg::{Band, Event, EventKind, Radio, RateMode, Snapshot, Station};

use crate::state::{Ap, ClientView, State};

/// The APs and clients of the APs `wanted` says yes to, as one object.
pub fn view(state: &State, wanted: impl Fn(&str) -> bool) -> Value {
    json!({
        "aps": aps(state, &wanted),
        "clients": clients(state, &wanted),
    })
}

/// Every wanted AP by name.
pub fn aps(state: &State, wanted: impl Fn(&str) -> bool) -> Value {
    let aps = state
        .aps()
        .filter(|(name, _)| wanted(name))
        .map(|(name, ap)| (name.to_owned(), ap_view(ap)))
        .collect();
    Value::Object(aps)
}

/// Every client of a wanted AP by MAC.
pub fn clients(state: &State, wanted: impl Fn(&str) -> bool) -> Value {
    let clients = state
        .clients()
        .iter()
        .filter(|c| wanted(&c.ap))
        .map(|c| (mac(&c.station.mac), client_view(state, c)))
        .collect();
    Value::Object(clients)
}

/// The events of `ap`, or of every AP, oldest first.
pub fn events(state: &State, ap: Option<&str>) -> Vec<Value> {
    let mut out: Vec<(u64, Value)> = Vec::new();
    for (name, a) in state.aps().filter(|(n, _)| ap.is_none_or(|ap| ap == *n)) {
        let at = a
            .events
            .iter()
            .filter_map(|ev| Some((ev.at_ms, event(name, a, ev)?)));
        out.extend(at);
    }
    // Stable: one AP's events keep the order they came in.
    out.sort_by_key(|(at, _)| *at);
    out.into_iter().map(|(_, v)| v).collect()
}

/// One event as the UI shows it, its BSS named; `None` for a kind this
/// controller does not know.
pub fn event(ap_name: &str, ap: &Ap, ev: &Event) -> Option<Value> {
    let mut o = Map::new();
    o.insert("ap".into(), ap_name.into());
    o.insert("at".into(), ev.at_ms.into());
    let (kind, who) = match &ev.kind {
        EventKind::Assoc { mac, bss } => ("assoc", Ok((mac, *bss))),
        EventKind::Disassoc { mac, bss } => ("disassoc", Ok((mac, *bss))),
        EventKind::EapOk { mac, bss } => ("eap-ok", Ok((mac, *bss))),
        EventKind::EapFail { mac, bss } => ("eap-fail", Ok((mac, *bss))),
        EventKind::RadioUp { phy } => ("radio-up", Err(phy)),
        EventKind::RadioDown { phy } => ("radio-down", Err(phy)),
        EventKind::FwCrash { phy } => ("fw-crash", Err(phy)),
        _ => return None,
    };
    o.insert("kind".into(), kind.into());
    match who {
        Ok((m, bss)) => {
            o.insert("mac".into(), mac(m).into());
            // The BSS list as it is now; it changes only with the AP's config.
            let snap = ap.snapshot.as_ref();
            if let Some(b) = snap.and_then(|s| s.bsss.get(usize::from(bss))) {
                o.insert("bss".into(), b.ifname.clone().into());
                o.insert("ssid".into(), b.ssid.clone().into());
                if let Some(r) = snap.and_then(|s| s.radios.iter().find(|r| r.phy == b.phy)) {
                    o.insert("band".into(), band(r.band).into());
                }
            }
        }
        Err(phy) => {
            o.insert("phy".into(), phy.clone().into());
        }
    }
    Some(Value::Object(o))
}

/// The merge patch that turns `old` into `new`, or `None` when they are
/// equal. The views hold no nulls, so a null in a patch always means
/// "removed".
pub fn diff(old: &Value, new: &Value) -> Option<Value> {
    let (Value::Object(a), Value::Object(b)) = (old, new) else {
        return (old != new).then(|| new.clone());
    };
    let mut patch = Map::new();
    for (k, v) in b {
        match a.get(k) {
            Some(was) => {
                if let Some(p) = diff(was, v) {
                    patch.insert(k.clone(), p);
                }
            }
            None => {
                patch.insert(k.clone(), v.clone());
            }
        }
    }
    for k in a.keys().filter(|k| !b.contains_key(*k)) {
        patch.insert(k.clone(), Value::Null);
    }
    (!patch.is_empty()).then_some(Value::Object(patch))
}

pub fn mac(m: &[u8; 6]) -> String {
    m.map(|b| format!("{b:02x}")).join(":")
}

pub fn band(b: Band) -> &'static str {
    match b {
        Band::B24 => "2.4",
        Band::B5 => "5",
        Band::B6 => "6",
    }
}

fn unix_ms(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

/// `part` as a percentage of `whole`, when there is a whole.
fn pct(part: u64, whole: u64) -> Option<f64> {
    (whole > 0).then(|| round1(part.min(whole) as f64 * 100.0 / whole as f64))
}

/// How far a counter moved; `None` if it went back (a restarted counter).
fn moved(prev: u64, now: u64) -> Option<u64> {
    now.checked_sub(prev)
}

fn ap_view(ap: &Ap) -> Value {
    let mut o = Map::new();
    o.insert("up".into(), ap.is_up().into());
    if let Some(h) = &ap.hello {
        let image = h.manifest.lines().find_map(|l| l.strip_prefix("image:"));
        o.insert("image".into(), image.unwrap_or_default().trim().into());
        o.insert("manifest".into(), h.manifest.clone().into());
        o.insert("kernel".into(), h.kernel.clone().into());
        o.insert("hostapd".into(), h.hostapd.clone().into());
        o.insert("agent".into(), h.agent.clone().into());
    }
    if let Some(p) = ap.mismatch() {
        o.insert("mismatch".into(), json!({"ap": p, "controller": PROTOCOL}));
    }
    if let Some(t) = ap.connected_since {
        o.insert("since".into(), unix_ms(t).into());
    }
    // While up, the agent is heard every tick: only an AP that is down
    // needs to say when.
    if let (false, Some(t)) = (ap.is_up(), ap.last_seen) {
        o.insert("seen".into(), unix_ms(t).into());
    }
    if !ap.crashes.is_empty() {
        let crashes = ap.crashes.iter().map(|(p, n)| (p.clone(), (*n).into()));
        o.insert("crashes".into(), Value::Object(crashes.collect()));
    }
    if let Some(s) = &ap.snapshot {
        let prev = ap.previous.as_ref().map(|(p, _)| p);
        o.insert("uptime".into(), s.uptime_s.into());
        o.insert("load".into(), (f64::from(s.load_milli) / 1000.0).into());
        o.insert("mem_kb".into(), s.mem_avail_kb.into());
        o.insert("nss".into(), s.nss_load_pct.into());
        let temps = s
            .temps
            .iter()
            .map(|t| (t.zone.clone(), round1(f64::from(t.milli_c) / 1000.0).into()));
        o.insert("temps".into(), Value::Object(temps.collect()));
        let radios = s.radios.iter().map(|r| {
            let before = prev.and_then(|p| p.radios.iter().find(|x| x.phy == r.phy));
            (r.phy.clone(), radio_view(s, r, before))
        });
        o.insert("radios".into(), Value::Object(radios.collect()));
        let bsss = s.bsss.iter().enumerate().map(|(i, b)| {
            let n = s
                .stations
                .iter()
                .filter(|t| usize::from(t.bss) == i)
                .count();
            let v = json!({
                "ssid": b.ssid,
                "phy": b.phy,
                "vlan": b.vlan,
                "bssid": mac(&b.bssid),
                "clients": n,
            });
            (b.ifname.clone(), v)
        });
        o.insert("bsss".into(), Value::Object(bsss.collect()));
    }
    Value::Object(o)
}

fn radio_view(s: &Snapshot, r: &Radio, before: Option<&Radio>) -> Value {
    let clients = s
        .stations
        .iter()
        .filter(|t| {
            s.bsss
                .get(usize::from(t.bss))
                .is_some_and(|b| b.phy == r.phy)
        })
        .count();
    let mut o = json!({
        "band": band(r.band),
        "channel": r.channel,
        "width": r.width_mhz,
        "txpower": f64::from(r.txpower_mbm) / 100.0,
        "noise": r.noise_dbm,
        "up": r.up,
        "clients": clients,
    });
    // Survey times are the radio's own clock, so they need no wall time.
    let util = before.and_then(|b| {
        let active = moved(b.active_ms, r.active_ms)?;
        let share = |p: u64, n: u64| pct(moved(p, n)?, active);
        Some(json!({
            "busy": share(b.busy_ms, r.busy_ms)?,
            "rx": share(b.rx_ms, r.rx_ms)?,
            "tx": share(b.tx_ms, r.tx_ms)?,
        }))
    });
    if let Some(u) = util {
        o["util"] = u;
    }
    o
}

fn rate(kbps: u32, mode: RateMode, mcs: u8, nss: u8) -> Value {
    let mut o = json!({ "mbps": round1(f64::from(kbps) / 1000.0) });
    let mode = match mode {
        RateMode::Legacy => return o,
        RateMode::Ht => "HT",
        RateMode::Vht => "VHT",
        RateMode::He => "HE",
    };
    o["mode"] = mode.into();
    o["mcs"] = mcs.into();
    if nss > 0 {
        o["nss"] = nss.into();
    }
    o
}

fn client_view(state: &State, c: &ClientView) -> Value {
    let st = &c.station;
    let ap = state.ap(&c.ap);
    let snap = ap.and_then(|a| a.snapshot.as_ref());
    let band = snap.and_then(|s| {
        let phy = &s.bsss.get(usize::from(st.bss))?.phy;
        Some(band(s.radios.iter().find(|r| &r.phy == phy)?.band))
    });
    let mut o = json!({
        "ap": c.ap,
        "bss": c.bss,
        "ssid": c.ssid,
        "vlan": st.vlan,
        "signal": st.signal,
        "signal_avg": st.signal_avg,
        "tx": rate(st.tx_rate_kbps, st.tx_mode, st.tx_mcs, st.tx_nss),
        "rx": rate(st.rx_rate_kbps, st.rx_mode, st.rx_mcs, st.rx_nss),
        "connected": st.connected_s,
        // Whole seconds: the milliseconds would change every tick.
        "idle": st.inactive_ms / 1000,
        "rx_bytes": st.rx_bytes,
        "tx_bytes": st.tx_bytes,
    });
    if let Some(b) = band {
        o["band"] = b.into();
    }
    let rates = ap.and_then(|a| {
        let (prev, then) = a.previous.as_ref()?;
        let secs = a.snapshot_at?.duration_since(*then).ok()?.as_secs_f64();
        let was = prev
            .stations
            .binary_search_by_key(&st.mac, |s| s.mac)
            .ok()?;
        Some(counters(&prev.stations[was], st, secs))
    });
    if let (Some(Value::Object(rates)), Value::Object(o)) = (rates, &mut o) {
        o.extend(rates);
    }
    o
}

/// What the counters say of the `secs` between two snapshots of a station:
/// throughput each way (`down` is to the client), the share of the time it
/// used the air, and how many of the AP's transmissions to it were retries.
fn counters(prev: &Station, now: &Station, secs: f64) -> Value {
    let mut o = Map::new();
    if secs <= 0.0 {
        return Value::Object(o);
    }
    let bps = |p, n| moved(p, n).map(|b| ((b * 8) as f64 / secs).round() as u64);
    if let Some(v) = bps(prev.tx_bytes, now.tx_bytes) {
        o.insert("down".into(), v.into());
    }
    if let Some(v) = bps(prev.rx_bytes, now.rx_bytes) {
        o.insert("up".into(), v.into());
    }
    let air = moved(prev.tx_airtime_us, now.tx_airtime_us)
        .zip(moved(prev.rx_airtime_us, now.rx_airtime_us))
        .map(|(t, r)| t + r);
    if let Some(us) = air {
        let share = round1((us as f64 / (secs * 1e4)).min(100.0));
        o.insert("airtime".into(), share.into());
    }
    let retries = moved(prev.tx_retries.into(), now.tx_retries.into());
    let sent = moved(prev.tx_packets, now.tx_packets);
    if let Some(p) = retries.zip(sent).and_then(|(r, s)| pct(r, r + s)) {
        o.insert("retries".into(), p.into());
    }
    Value::Object(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_is_a_merge_patch_of_what_changed() {
        let a = json!({"x": 1, "o": {"k": 1, "gone": 2, "same": {"v": 1}}, "drop": 3});
        let b = json!({"x": 1, "o": {"k": 2, "same": {"v": 1}, "new": [1]}, "add": {}});
        assert_eq!(
            diff(&a, &b),
            Some(json!({"o": {"k": 2, "gone": null, "new": [1]}, "drop": null, "add": {}}))
        );
        assert_eq!(diff(&a, &a.clone()), None);
        assert_eq!(diff(&json!(1), &json!({"a": 1})), Some(json!({"a": 1})));
    }

    fn station(tx_packets: u64, tx_retries: u32, tx_bytes: u64, air_us: u64) -> Station {
        Station {
            mac: [2, 0, 0, 0, 0, 1],
            bss: 0,
            signal: -50,
            signal_avg: -50,
            rx_bytes: 0,
            tx_bytes,
            rx_packets: 0,
            tx_packets,
            tx_retries,
            tx_failed: 0,
            tx_rate_kbps: 0,
            rx_rate_kbps: 0,
            tx_mcs: 0,
            rx_mcs: 0,
            tx_mode: RateMode::Legacy,
            rx_mode: RateMode::Legacy,
            tx_nss: 0,
            rx_nss: 0,
            tx_airtime_us: air_us,
            rx_airtime_us: 0,
            inactive_ms: 0,
            connected_s: 0,
            vlan: 0,
        }
    }

    #[test]
    fn mac_is_lower_hex() {
        assert_eq!(mac(&[0x02, 0, 0, 0xab, 0, 0x2f]), "02:00:00:ab:00:2f");
    }

    #[test]
    fn counters_become_rates() {
        let a = station(1000, 10, 1_000_000, 0);
        let b = station(1090, 20, 1_250_000, 500_000);
        assert_eq!(
            counters(&a, &b, 2.0),
            json!({"down": 1_000_000, "up": 0, "airtime": 25.0, "retries": 10.0})
        );
        // Idle: nothing sent, so no retry ratio; a restarted counter says
        // nothing either.
        let c = station(0, 20, 1_250_000, 500_000);
        assert_eq!(
            counters(&b, &c, 2.0),
            json!({"down": 0, "up": 0, "airtime": 0.0})
        );
    }

    #[test]
    fn rates_say_their_mode() {
        assert_eq!(rate(6000, RateMode::Legacy, 0, 0), json!({"mbps": 6.0}));
        assert_eq!(
            rate(144_400, RateMode::Ht, 15, 0),
            json!({"mbps": 144.4, "mode": "HT", "mcs": 15})
        );
        assert_eq!(
            rate(1_201_000, RateMode::He, 11, 2),
            json!({"mbps": 1201.0, "mode": "HE", "mcs": 11, "nss": 2})
        );
    }
}
