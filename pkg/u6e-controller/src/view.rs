//! The state as the web UI reads it: JSON keyed by name (APs, radios, BSSs,
//! clients by MAC, temperatures by zone), so that a change goes out as a JSON
//! merge patch (RFC 7386) of only the fields that changed. Rates, utilization
//! and retry ratios are worked out here from the counters of the AP's last two
//! snapshots, and rounded so that a steady value is not resent. A client
//! carries who it is (`identity`): its `name` (the DHCP server's device for
//! it, the host name of its lease, or the reverse DNS of its addresses; the
//! UI shows its MAC without one), each of those, its `vendor`, `addresses`
//! and `lease_expires`. A flow's far end carries its DNS name
//! (`remote_name`) once one was looked up, and the addresses its AP's client
//! guards bind to it (`bound`); a guard's violation is an event of kind
//! `guard` (its `guard`, `detail`, whether its frame was `dropped`, and the
//! `repeats` since the last one reported), a change of a service a device
//! offers over mDNS one of kind `service` (`services::event_json`), on the
//! timeline too when the device is a client; a client's query for BSS
//! transition candidates is an event of kind `btm-query` (its `reason`), its
//! answer to a request one of kind `btm-response` (its `status`, and the
//! `target` it named). Each client and each AP with clients carries its
//! Wi-Fi experience (`experience`: its score and parts). An associated
//! client carries how
//! it authenticated (`auth`: the method, its EAP identity and the expiry of
//! the client certificate RADIUS last accepted for it, whether it came by a
//! fast transition); its sessions and timeline are `history`, the clients
//! that fail to get on `auth_problems`. The clients the policy blocks are
//! listed whole (`blocked`), associated or not, so that one kept off every AP
//! can still be found and unblocked; an associated client says it too.
//!
//! Each AP's Wi-Fi configuration is shown by hash only (`config`): the one it
//! reports installed, the one it last acknowledged, the latest one signed for
//! it and the one sent to it last, whether it drifts (runs another than the
//! latest), and how the last one went. Beside the APs are what the
//! controller manages (`manage`: whether it signs configurations, the VLANs
//! the client guards enforce on as sent (none without the leases) and their
//! static clients, and, when it rolls
//! images out, each AP's kept images and those it runs) and the image
//! rollouts with their step, gate, result and log (`rollouts`).

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};
use u6e_proto::PROTOCOL;
use u6e_proto::mac;
use u6e_proto::msg::{
    AuthKind, Band, Event, EventKind, Flow, Flows, Guard, Radio, RateMode, Snapshot, Station,
    StationAuth, Violation,
};

use crate::experience;
use crate::names;
use crate::policy::{ConfigId, Phase};
use crate::services;
use crate::sessions::Session;
use crate::state::{Action, Ap, ClientView, Rollout, State, mechanism_name, outcome_name};
use crate::timeline::{EapStep, End, Entry, Place, What};

/// The APs and clients of the APs `wanted` says yes to, and the clients
/// blocked, as one object, with their flows when `flows` and the captures
/// for an `admin` (who captured whom is no one else's).
pub fn view(state: &State, wanted: impl Fn(&str) -> bool, flows: bool, admin: bool) -> Value {
    let site = experience::site(state, unix_ms(SystemTime::now()));
    let mut v = json!({
        "aps": aps_of(state, &site, &wanted),
        "clients": clients_of(state, &site, &wanted),
        "blocked": blocked(state),
        "config": config(state),
        "manage": manage(state),
        "rollouts": rollouts(state, LIVE_LOG),
        "limits": crate::limits::view(state),
    });
    if admin {
        v["captures"] = crate::captures::view(state);
    }
    if flows {
        v["flows"] = self::flows(state, &wanted, None);
    }
    v
}

/// Every client the policy blocks, by MAC, in order.
pub fn blocked(state: &State) -> Value {
    state.blocked.iter().map(|m| mac::format(*m)).collect()
}

/// The latest flows of every wanted AP that has sent some, by AP; of one
/// client only with `client`.
pub fn flows(state: &State, wanted: impl Fn(&str) -> bool, client: Option<[u8; 6]>) -> Value {
    let aps = state.aps().filter(|(name, _)| wanted(name));
    let with = aps.filter_map(|(name, ap)| {
        let (f, at) = ap.flows.as_ref()?;
        Some((name.to_owned(), flows_of(state, f, *at, client)))
    });
    Value::Object(with.collect())
}

/// One AP's flows, as they came at `at`: its clients by MAC, named when
/// they can be.
pub fn flows_of(state: &State, f: &Flows, at: SystemTime, client: Option<[u8; 6]>) -> Value {
    let clients = f
        .clients
        .iter()
        .filter(|c| client.is_none_or(|m| m == c.mac))
        .map(|c| {
            let mut o = json!({
                "conns": c.conns,
                "offloaded": c.offloaded,
                "tx_bytes": c.tx_bytes,
                "rx_bytes": c.rx_bytes,
                "tx_packets": c.tx_packets,
                "rx_packets": c.rx_packets,
                "top": c.top.iter().map(|f| flow(state, f)).collect::<Vec<_>>(),
            });
            if let Some(name) = state.identity(&c.mac).name() {
                o["name"] = name.into();
            }
            (mac::format(c.mac), o)
        });
    json!({
        "at": unix_ms(at),
        "seq": f.seq,
        "complete": f.complete,
        "clients": Value::Object(clients.collect()),
    })
}

/// One connection; `src` opened it, the client is the end
/// `client_is_src` says, and tx/rx are the client's.
fn flow(state: &State, f: &Flow) -> Value {
    let mut o = json!({
        "proto": f.proto,
        "src": f.src.to_string(),
        "sport": f.sport,
        "dst": f.dst.to_string(),
        "dport": f.dport,
        "tx_bytes": f.tx_bytes,
        "rx_bytes": f.rx_bytes,
        "tx_packets": f.tx_packets,
        "rx_packets": f.rx_packets,
        "offloaded": f.offloaded,
        "age": f.age_s,
        "client_is_src": f.client_is_src,
    });
    if let Some(name) = state.dns_name(&names::remote(f)) {
        o["remote_name"] = name.into();
    }
    o
}

/// What the controller manages: whether it signs configurations, and, when
/// it rolls images out, each AP's kept images (oldest first) and the image it
/// runs (and the other it may run, after a rollout that failed part way).
pub fn manage(state: &State) -> Value {
    let guards = &state.guards;
    let mut o = json!({
        "configs": state.signer.is_some(),
        "guards": { "enforce": state.guard_mode().enforce, "statics": guards.statics.len() },
    });
    if let Some(kept) = &state.kept {
        let aps = state.aps().map(|(name, _)| {
            let runs = state.images.get(name);
            let mut ap = json!({ "kept": kept.get(name).cloned().unwrap_or_default() });
            if let Some(r) = runs.and_then(|i| i.running.as_ref()) {
                ap["running"] = r.clone().into();
            }
            if let Some(e) = runs.and_then(|i| i.either.as_ref()) {
                ap["either"] = e.clone().into();
            }
            if let Some(h) = state.held(name) {
                ap["held"] = json!({ "reason": h.reason, "until": h.until_ms });
            }
            (name.to_owned(), ap)
        });
        o["images"] = Value::Object(aps.collect());
    }
    o
}

/// Lines of a rollout's log in the live view: a merge patch replaces an
/// array whole, so each new line resends them all.
const LIVE_LOG: usize = 20;

/// The rollouts, each by its id, with the last `log` lines of each.
pub fn rollouts(state: &State, log: usize) -> Value {
    let all = state
        .rollouts
        .iter()
        .map(|r| (r.id.to_string(), rollout(r, log)));
    Value::Object(all.collect())
}

fn rollout(r: &Rollout, log: usize) -> Value {
    let skip = r.log.len().saturating_sub(log);
    let mut o = json!({
        "id": r.id,
        "ap": r.ap,
        "image": r.image_id,
        "previous": r.previous,
        "user": r.user,
        "at": unix_ms(r.at),
        "phase": phase(&r.phase),
        "log": r.log.iter().skip(skip).collect::<Vec<_>>(),
    });
    if let Some((healthy, detail)) = &r.gate {
        o["gate"] = json!({ "healthy": healthy, "detail": detail });
    }
    if let Some((outcome, detail)) = &r.result {
        o["result"] = json!({ "outcome": outcome_name(*outcome), "detail": detail });
    }
    o
}

/// A rollout's step, by the name the policy file gives it, and its gate's
/// deadline.
fn phase(p: &Phase) -> Value {
    match p {
        Phase::Checking => json!({ "step": "checking" }),
        Phase::Staging => json!({ "step": "staging" }),
        Phase::Gate { deadline_ms } => json!({ "step": "gate", "deadline": deadline_ms }),
        Phase::RollingBack { why } => json!({ "step": "rolling_back", "why": why }),
    }
}

/// Every AP's configuration, by AP, as `config_of` shows it.
pub fn config(state: &State) -> Value {
    let aps = state
        .aps()
        .map(|(n, a)| (n.to_owned(), Value::Object(config_of(a))));
    Value::Object(aps.collect())
}

/// An AP's configuration, by hash, as far as it is known: installed (while
/// connected), acknowledged, the latest signed (with whether it drifts
/// from that) and sent last, and how the last one went. An AP that reports
/// no hash and was never sent a configuration has none of it.
pub fn config_of(ap: &Ap) -> Map<String, Value> {
    let id = |c: ConfigId| json!({ "sha256": mac::hex(&c.sha256), "seq": c.seq });
    let mut o = Map::new();
    if let Some(h) = ap.installed() {
        o.insert("installed".into(), mac::hex(&h).into());
    }
    if let Some(c) = ap.acked {
        o.insert("acked".into(), id(c));
    }
    if let Some(c) = ap.latest {
        o.insert("latest".into(), id(c));
        o.insert("drift".into(), ap.drifts().into());
    }
    if let Some(c) = ap.wanted {
        o.insert("wanted".into(), id(c));
    }
    if let Some(a) = &ap.last_apply {
        let radios =
            a.result.radios.iter().map(
                |r| json!({ "band": band(r.radio), "mechanism": mechanism_name(r.mechanism) }),
            );
        let last = json!({
            "at": unix_ms(a.at),
            "sha256": mac::hex(&a.result.sha256),
            "ok": a.result.ok,
            "radios": radios.collect::<Vec<_>>(),
            "detail": a.result.detail,
        });
        o.insert("last".into(), last);
    }
    o
}

/// An action as the events show it.
/// What an action's detail reads as to a viewer who is not an admin, when
/// it is the admins' alone.
pub const DETAIL_HIDDEN: &str = "its details are the admins'";

/// An action's detail as a viewer reads it: a capture's (its filter, size
/// and outcome) is the admins' alone; who took which action, on whom, where
/// and when is every viewer's.
fn detail_for(action: &str, detail: &str, admin: bool) -> String {
    if admin || action != "capture" {
        detail.to_owned()
    } else {
        DETAIL_HIDDEN.to_owned()
    }
}

/// One action as an `admin`, or any other viewer, reads it.
pub fn action(a: &Action, admin: bool) -> Value {
    let mut o = json!({
        "at": unix_ms(a.at),
        "kind": "action",
        "action": a.action,
        "ok": a.ok,
        "detail": detail_for(a.action, &a.detail, admin),
    });
    if let Some(m) = a.mac {
        o["mac"] = mac::format(m).into();
    }
    if let Some(ap) = &a.ap {
        o["ap"] = ap.clone().into();
    }
    if let Some(user) = &a.user {
        o["user"] = user.clone().into();
    }
    o
}

/// Every wanted AP by name.
pub fn aps(state: &State, wanted: impl Fn(&str) -> bool) -> Value {
    aps_of(
        state,
        &experience::site(state, unix_ms(SystemTime::now())),
        wanted,
    )
}

/// Every wanted AP by name, with its experience as `site` has it.
fn aps_of(state: &State, site: &experience::Site, wanted: impl Fn(&str) -> bool) -> Value {
    let aps = state
        .aps()
        .filter(|(name, _)| wanted(name))
        .map(|(name, ap)| {
            let mut v = ap_view(ap);
            if let Some(e) = site.aps.get(name) {
                v["experience"] = experience::ap_json(e);
            }
            (name.to_owned(), v)
        });
    Value::Object(aps.collect())
}

/// Every client of a wanted AP by MAC.
pub fn clients(state: &State, wanted: impl Fn(&str) -> bool) -> Value {
    clients_of(
        state,
        &experience::site(state, unix_ms(SystemTime::now())),
        wanted,
    )
}

/// Every client of a wanted AP by MAC, with its experience as `site` has
/// it.
fn clients_of(state: &State, site: &experience::Site, wanted: impl Fn(&str) -> bool) -> Value {
    let clients = state.clients();
    let clients = clients.iter().filter(|c| wanted(&c.ap)).map(|c| {
        let mut v = client_view(state, c);
        if let Some(e) = site.clients.get(&c.station.mac) {
            v["experience"] = experience::json(e);
        }
        (mac::format(c.station.mac), v)
    });
    Value::Object(clients.collect())
}

/// The events of `ap`, or of every AP, oldest first; the operator's actions
/// among them (one carried out on no AP only in every AP's), as an `admin`
/// or any other viewer reads them.
pub fn events(state: &State, ap: Option<&str>, admin: bool) -> Vec<Value> {
    let mut out: Vec<(u64, Value)> = Vec::new();
    for (name, a) in state.aps().filter(|(n, _)| ap.is_none_or(|ap| ap == *n)) {
        let at = a
            .events
            .iter()
            .filter_map(|ev| Some((ev.at_ms, event(name, a, ev)?)));
        out.extend(at);
    }
    let actions = state
        .actions
        .iter()
        .filter(|a| ap.is_none_or(|ap| a.ap.as_deref() == Some(ap)));
    out.extend(actions.map(|a| (unix_ms(a.at), action(a, admin))));
    let changes = (state.services.events.iter())
        .filter(|e| ap.is_none_or(|ap| e.ap == ap))
        .map(|e| (e.at_ms, services::event_json(e)));
    out.extend(changes);
    // Stable: one AP's events keep the order they came in.
    out.sort_by_key(|(at, _)| *at);
    out.into_iter().map(|(_, v)| v).collect()
}

/// One event as the UI shows it, its BSS or radio named as the AP last
/// reported them; `None` for a kind this controller does not know.
pub fn event(ap_name: &str, ap: &Ap, ev: &Event) -> Option<Value> {
    let mut o = Map::new();
    o.insert("ap".into(), ap_name.into());
    o.insert("at".into(), ev.at_ms.into());
    let (kind, who) = match &ev.kind {
        EventKind::Assoc { mac, bss } => ("assoc", Ok((mac, *bss))),
        EventKind::Disassoc { mac, bss } => ("disassoc", Ok((mac, *bss))),
        EventKind::EapStart { mac, bss } => ("eap-start", Ok((mac, *bss))),
        EventKind::EapOk { mac, bss } => ("eap-ok", Ok((mac, *bss))),
        EventKind::EapFail { mac, bss } => ("eap-fail", Ok((mac, *bss))),
        EventKind::EapTimeout { mac, bss, server } => {
            o.insert("server".into(), (*server).into());
            ("eap-timeout", Ok((mac, *bss)))
        }
        EventKind::PskMismatch { mac, bss } => ("psk-mismatch", Ok((mac, *bss))),
        EventKind::RadioUp { phy } => ("radio-up", Err(phy)),
        EventKind::RadioDown { phy } => ("radio-down", Err(phy)),
        EventKind::FwCrash { phy } => ("fw-crash", Err(phy)),
        EventKind::GuardViolation(v) => {
            o.extend(violation(v));
            return Some(Value::Object(o));
        }
        EventKind::BtmQuery { mac, bss, reason } => {
            o.insert("reason".into(), (*reason).into());
            ("btm-query", Ok((mac, *bss)))
        }
        EventKind::BtmResponse {
            mac,
            bss,
            status,
            target,
        } => {
            o.insert("status".into(), (*status).into());
            if let Some(t) = target {
                o.insert("target".into(), mac::format(*t).into());
            }
            ("btm-response", Ok((mac, *bss)))
        }
        _ => return None,
    };
    o.insert("kind".into(), kind.into());
    match who {
        Ok((m, bss)) => {
            o.insert("mac".into(), mac::format(*m).into());
            // The BSS list changes only with the AP's config.
            if let Some(b) = ap.naming.bsss.get(usize::from(bss)) {
                o.insert("bss".into(), b.ifname.clone().into());
                o.insert("ssid".into(), b.ssid.clone().into());
                if let Some(b) = band_of(ap, &b.phy) {
                    o.insert("band".into(), b.into());
                }
            }
        }
        Err(phy) => {
            o.insert("phy".into(), phy.clone().into());
            if let Some(b) = band_of(ap, phy) {
                o.insert("band".into(), b.into());
            }
        }
    }
    Some(Value::Object(o))
}

/// Names and bands as the services' view shows them: a client's name as the
/// controller knows it, the band of the BSS a port is (or is the per-VLAN
/// interface of).
impl services::Look for State {
    fn name(&self, mac: &[u8; 6]) -> Option<String> {
        self.identity(mac).name().map(str::to_owned)
    }

    fn band(&self, ap: &str, port: &str) -> Option<&'static str> {
        let a = self.ap(ap)?;
        let bss = port.split('.').next()?;
        let b = a.naming.bsss.iter().find(|b| b.ifname == bss)?;
        band_of(a, &b.phy)
    }
}

/// The band of `ap`'s radio `phy`, as the AP last reported it.
fn band_of(ap: &Ap, phy: &str) -> Option<&'static str> {
    let (_, b) = ap.naming.bands.iter().find(|(p, _)| p == phy)?;
    Some(band(*b))
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

/// A client guard by the name the UI and the metrics give it.
pub fn guard_name(g: Guard) -> &'static str {
    match g {
        Guard::Arp => "arp",
        Guard::Dhcp => "dhcp",
        Guard::Ra => "ra",
        Guard::Source => "source",
        Guard::Tag => "tag",
    }
}

/// A violation's fields in an event.
fn violation(v: &Violation) -> Map<String, Value> {
    let mut o = Map::new();
    o.insert("kind".into(), "guard".into());
    o.insert("guard".into(), guard_name(v.guard).into());
    o.insert("mac".into(), mac::format(v.mac).into());
    o.insert("bss".into(), v.ifname.clone().into());
    o.insert("vlan".into(), v.vlan.into());
    if let Some(ip) = v.ip {
        o.insert("ip".into(), ip.to_string().into());
    }
    o.insert("detail".into(), v.detail.clone().into());
    o.insert("dropped".into(), v.dropped.into());
    o.insert("repeats".into(), v.repeats.into());
    o
}

pub fn band(b: Band) -> &'static str {
    match b {
        Band::B24 => "2.4",
        Band::B5 => "5",
        Band::B6 => "6",
    }
}

/// The scan of `radio` on `ap`: whether the AP is asked to scan, since when,
/// and for how long at most (`limit`, seconds); whether the AP says it does;
/// how many watch it; and why it stopped, once it has (`stopped`: `idle`,
/// `limit`, `link` or `ap`, the AP's own reason in `detail`).
pub fn spectrum(state: &State, ap: &str, radio: &str) -> Value {
    let mut o = json!({
        "key": format!("{ap}/{radio}"),
        "limit": state.spectrum.limit.as_secs(),
        "scanning": false,
        "running": false,
        "watchers": 0,
    });
    let Some(scan) = state.ap(ap).and_then(|a| a.scans.get(radio)) else {
        return o;
    };
    o["running"] = scan.running.into();
    o["watchers"] = scan.watchers().into();
    if let Some(since) = scan.since() {
        o["scanning"] = true.into();
        o["since"] = unix_ms(since).into();
    }
    if let Some(why) = scan.stopped {
        o["stopped"] = why.as_str().into();
    }
    if !scan.detail.is_empty() {
        o["detail"] = scan.detail.clone().into();
    }
    o
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
        o.insert("image".into(), h.image().into());
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
    let config = config_of(ap);
    if !config.is_empty() {
        o.insert("config".into(), Value::Object(config));
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
        o.insert("offload_held".into(), s.offload_held.into());
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
                "bssid": mac::format(b.bssid),
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
        "blocked": state.blocked.contains(&st.mac),
    });
    if let Some(b) = band {
        o["band"] = b.into();
    }
    let auth = snap.and_then(|s| {
        let i = s.auth.binary_search_by_key(&st.mac, |(m, _)| *m).ok()?;
        Some(&s.auth[i].1)
    });
    if let Some(a) = auth {
        let session = state.sessions.open_of(&st.mac);
        let authenticated = a.authorized || session.is_some_and(|s| s.authenticated);
        let cert = session.and_then(|s| state.sessions.session_cert(&st.mac, s));
        let identity = session
            .and_then(Session::eap_identity)
            .or_else(|| claimed(a));
        o["auth"] = auth_view(a, identity, authenticated, cert);
    }
    if let Value::Object(o) = &mut o {
        o.extend(state.identity(&st.mac).fields());
    }
    let bound = ap
        .into_iter()
        .flat_map(|a| &a.bindings)
        .filter(|b| b.mac == st.mac);
    let bound: Vec<Value> = bound
        .map(|b| match b.expires_ms {
            Some(ms) => json!({ "ip": b.ip.to_string(), "expires": ms }),
            None => json!({ "ip": b.ip.to_string() }),
        })
        .collect();
    if !bound.is_empty() {
        o["bound"] = bound.into();
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

/// The name of an EAP method, by its IANA type.
fn eap_name(t: u8) -> String {
    let known = match t {
        0 => "EAP",
        13 => "EAP-TLS",
        18 => "EAP-SIM",
        21 => "EAP-TTLS",
        23 => "EAP-AKA",
        25 => "PEAP",
        26 => "EAP-MSCHAPv2",
        43 => "EAP-FAST",
        50 => "EAP-AKA'",
        52 => "EAP-pwd",
        55 => "TEAP",
        _ => return format!("EAP (type {t})"),
    };
    known.into()
}

/// How a client authenticated, in words.
pub fn method(a: &StationAuth) -> String {
    match a.kind() {
        AuthKind::Eap => eap_name(a.eap_method),
        AuthKind::MacAuth => "MAC authentication".into(),
        AuthKind::Sae => "WPA3-Personal".into(),
        AuthKind::Other => "Open or other".into(),
    }
}

/// The EAP identity an AP names for a client, authenticated or claimed.
fn claimed(a: &StationAuth) -> Option<String> {
    (a.kind() == AuthKind::Eap && !a.identity.is_empty()).then(|| a.identity.clone())
}

/// A client's authentication: its `method`, its EAP `identity` (a fast
/// transition's carried over from the session it roamed in from), whether
/// its AP has authorized it in the session (`authenticated`; until then the
/// identity is only what the client claims), the certificate it signed in
/// with (`cert_cn`, `cert_expires` in milliseconds), whether its association
/// was a fast transition (`ft`), and the reauthentication period RADIUS set
/// (`reauth`, seconds).
fn auth_view(
    a: &StationAuth,
    identity: Option<String>,
    authenticated: bool,
    cert: Option<(String, u64)>,
) -> Value {
    let mut o = json!({
        "method": method(a),
        "ft": a.fast_transition(),
        "authenticated": authenticated,
    });
    if let Some(i) = identity {
        o["identity"] = i.into();
    }
    if let Some((cn, expires_s)) = cert.filter(|_| authenticated) {
        o["cert_cn"] = cn.into();
        o["cert_expires"] = (expires_s * 1000).into();
    }
    if a.reauth_s > 0 {
        o["reauth"] = a.reauth_s.into();
    }
    o
}

/// The most sessions of one client a history gives, the newest.
const HISTORY_SESSIONS: usize = 100;
/// The most timeline entries a history gives, the newest.
const HISTORY_ENTRIES: usize = 500;

/// Whether RADIUS's log is read: `off`, `up`, or `down` (its last read
/// failed, or none worked yet).
fn radius_log(state: &State) -> &'static str {
    match &state.radius {
        None => "off",
        Some(h) if h.up == Some(true) => "up",
        Some(_) => "down",
    }
}

/// A client's history (`/api/clients/{mac}/history`): how it authenticated
/// last (`identity`, with its VLAN and whether it is on now), its sessions
/// and its timeline, the newest first (`more`: the older entries left out),
/// and whether RADIUS's verdicts are read (`radius`); a capture's detail
/// only for an `admin`.
pub fn history(state: &State, mac: &[u8; 6], admin: bool) -> Value {
    let sessions: Vec<&Session> = state.sessions.of(mac).take(HISTORY_SESSIONS).collect();
    let timeline = &state.sessions.timeline;
    let entries: Vec<Value> = timeline
        .of(mac)
        .rev()
        .take(HISTORY_ENTRIES)
        .map(|e| entry(e, admin))
        .collect();
    let kept = timeline.of(mac).count();
    let mut o = json!({
        "sessions": sessions.iter().map(|s| session(state, s)).collect::<Vec<_>>(),
        "timeline": entries,
        "more": kept.saturating_sub(HISTORY_ENTRIES),
        "radius": radius_log(state),
    });
    let latest = sessions.iter().find_map(|s| Some((s, s.auth.as_ref()?)));
    if let Some((s, a)) = latest {
        let cert = state.sessions.session_cert(mac, s);
        let mut id = auth_view(a, s.eap_identity(), s.authenticated, cert);
        id["vlan"] = s.place.vlan.into();
        id["connected"] = s.end_ms.is_none().into();
        o["identity"] = id;
    }
    o
}

pub(crate) fn place(p: &Place) -> Map<String, Value> {
    let mut o = Map::new();
    o.insert("ap".into(), p.ap.clone().into());
    o.insert("bss".into(), p.bss.clone().into());
    o.insert("ssid".into(), p.ssid.clone().into());
    o.insert("vlan".into(), p.vlan.into());
    if let Some(b) = p.band {
        o.insert("band".into(), band(b).into());
    }
    o
}

/// Why a session ended: `why`, and who (`by`) or where to (`to`).
fn end(e: &End) -> Map<String, Value> {
    let (why, by, to) = match e {
        End::Left => ("left", None, None),
        End::Roamed { to } => ("roamed", None, Some(to)),
        End::Kicked { by } => ("kicked", by.as_ref(), None),
        End::Blocked { by } => ("blocked", by.as_ref(), None),
        End::EapFailed => ("eap-failed", None, None),
        End::EapTimedOut => ("eap-timeout", None, None),
        End::Inactive => ("inactive", None, None),
        End::Unobserved => ("unobserved", None, None),
    };
    let mut o = Map::new();
    o.insert("why".into(), why.into());
    if let Some(by) = by {
        o.insert("by".into(), by.clone().into());
    }
    if let Some(to) = to {
        o.insert("to".into(), to.clone().into());
    }
    o
}

/// One session: where, from when to when (`end` absent while it is open),
/// how and as whom it authenticated, its bytes each way as its AP counted
/// them (`rx_bytes` from the client), why it ended, and the AP it roamed in
/// from.
fn session(state: &State, s: &Session) -> Value {
    let mut o = place(&s.place);
    o.insert("id".into(), s.id.into());
    o.insert("start".into(), s.start_ms.into());
    if let Some(e) = s.end_ms {
        o.insert("end".into(), e.into());
    }
    if let Some(a) = &s.auth {
        let cert = state.sessions.session_cert(&s.mac, s);
        let auth = auth_view(a, s.eap_identity(), s.authenticated, cert);
        o.insert("auth".into(), auth);
    }
    o.insert("rx_bytes".into(), s.up_bytes.into());
    o.insert("tx_bytes".into(), s.down_bytes.into());
    if let Some(e) = &s.end {
        o.extend(end(e));
    }
    if let Some(from) = &s.from {
        o.insert("from".into(), from.clone().into());
    }
    Value::Object(o)
}

/// One timeline entry: its time (`at`), its `kind` and what it says (a
/// join's `authorized`: whether its AP authorized it in that session, until
/// when its `identity` is only claimed), as an `admin` or any other viewer
/// reads it.
fn entry(e: &Entry, admin: bool) -> Value {
    let mut o = Map::new();
    o.insert("at".into(), e.at_ms.into());
    let mut put = |k: &str, v: Value| {
        o.insert(k.into(), v);
    };
    let kind = match &e.what {
        What::Joined {
            session,
            place: p,
            from,
            auth,
        } => {
            for (k, v) in place(p) {
                put(&k, v);
            }
            put("session", (*session).into());
            if let Some(a) = auth {
                put("method", method(a).into());
                put("ft", a.fast_transition().into());
                put("authorized", a.authorized.into());
                if !a.identity.is_empty() {
                    put("identity", a.identity.clone().into());
                }
            }
            match from {
                None => "joined",
                Some(r) => {
                    put("from", r.ap.clone().into());
                    if let Some(b) = r.band {
                        put("from_band", band(b).into());
                    }
                    if let Some(gap) = r.gap_ms {
                        put("gap", gap.into());
                    }
                    if let Some(by) = &r.steered_by {
                        put("steered_by", by.clone().into());
                    }
                    "roamed"
                }
            }
        }
        What::Ended {
            session,
            ap,
            why,
            secs,
        } => {
            put("session", (*session).into());
            put("ap", ap.clone().into());
            put("secs", (*secs).into());
            for (k, v) in end(why) {
                put(&k, v);
            }
            "ended"
        }
        What::Eap { ap, step } => {
            put("ap", ap.clone().into());
            let step = match step {
                EapStep::Started => "started",
                EapStep::Succeeded { ms } => {
                    if let Some(ms) = ms {
                        put("ms", (*ms).into());
                    }
                    "succeeded"
                }
                EapStep::Failed => "failed",
                EapStep::TimedOut { server } => {
                    put("server", (*server).into());
                    "timeout"
                }
            };
            put("step", step.into());
            "eap"
        }
        What::PskMismatch { ap } => {
            put("ap", ap.clone().into());
            "psk-mismatch"
        }
        What::Radius {
            accept,
            user,
            node,
            nas,
            detail,
            cert_expires,
            cert_cn,
        } => {
            put("accept", (*accept).into());
            put("user", user.clone().into());
            put("node", node.clone().into());
            put("nas", nas.clone().into());
            put("detail", detail.clone().into());
            if let Some(s) = cert_expires {
                put("cert_expires", (s * 1000).into());
            }
            if let Some(cn) = cert_cn {
                put("cert_cn", cn.clone().into());
            }
            "radius"
        }
        What::Lease {
            ip,
            expires,
            renewed,
        } => {
            put("ip", ip.to_string().into());
            put("expires", (expires * 1000).into());
            put("renewed", (*renewed).into());
            "lease"
        }
        What::FirstTraffic { ap, conns } => {
            put("ap", ap.clone().into());
            put("conns", (*conns).into());
            "first-traffic"
        }
        What::Action {
            action,
            user,
            ap,
            ok,
            detail,
        } => {
            put("action", action.clone().into());
            if let Some(u) = user {
                put("user", u.clone().into());
            }
            if let Some(ap) = ap {
                put("ap", ap.clone().into());
            }
            put("ok", (*ok).into());
            put("detail", detail_for(action, detail, admin).into());
            "action"
        }
        What::Guard {
            ap,
            guard,
            detail,
            dropped,
            repeats,
        } => {
            put("ap", ap.clone().into());
            put("guard", guard_name(*guard).into());
            put("detail", detail.clone().into());
            put("dropped", (*dropped).into());
            put("repeats", (*repeats).into());
            "guard"
        }
        What::Service {
            ap,
            instance,
            service,
            change,
            by,
            misses,
            silent_ms,
        } => {
            put("ap", ap.clone().into());
            put("instance", instance.clone().into());
            put("label", services::instance_label(instance).into());
            put("service", service.clone().into());
            put("change", services::change_name(*change).into());
            if let Some(by) = by {
                put("by", mac::format(*by).into());
            }
            put("misses", (*misses).into());
            if let Some(ms) = silent_ms {
                put("silent_for", (*ms).into());
            }
            "service"
        }
    };
    o.insert("kind".into(), kind.into());
    Value::Object(o)
}

/// How far back the auth problems look.
pub const PROBLEMS_WINDOW_MS: u64 = 24 * 3600 * 1000;
/// The most clients the auth problems list.
const PROBLEMS_MAX: usize = 200;
/// A client's EAP timeout with no RADIUS verdict this close before it never
/// reached RADIUS.
const REACHED_MS: u64 = 60_000;

/// Whether `e` is a failure to get on: EAP rejected or timed out, a
/// passphrase mismatch, a RADIUS rejection.
fn failed(e: &Entry) -> bool {
    match &e.what {
        What::Eap { step, .. } => matches!(step, EapStep::Failed | EapStep::TimedOut { .. }),
        What::PskMismatch { .. } => true,
        What::Radius { accept, .. } => !accept,
        _ => false,
    }
}

/// The APs' side of a failure `e`, given the client's entries `recent`.
fn ap_side(e: &Entry, recent: &[&Entry]) -> Option<Value> {
    let mut side = json!({ "at": e.at_ms });
    match &e.what {
        What::Eap {
            ap,
            step: EapStep::TimedOut { server },
        } => {
            side["ap"] = ap.clone().into();
            side["kind"] = "eap-timeout".into();
            side["server"] = (*server).into();
            let verdict = |r: &&&Entry| {
                matches!(r.what, What::Radius { .. })
                    && r.at_ms <= e.at_ms
                    && e.at_ms - r.at_ms <= REACHED_MS
            };
            side["reached_radius"] = (*server || recent.iter().any(|r| verdict(&r))).into();
        }
        What::Eap { ap, .. } => {
            side["ap"] = ap.clone().into();
            side["kind"] = "eap-failed".into();
        }
        What::PskMismatch { ap } => {
            side["ap"] = ap.clone().into();
            side["kind"] = "psk-mismatch".into();
        }
        _ => return None,
    }
    Some(side)
}

/// The clients that failed to get on in the day before `now_ms`
/// (`/api/auth-problems`): for each, its last failure on the APs' side
/// (`ap_side`: EAP rejected or timed out, by the client or by RADIUS, and
/// whether a client that timed out reached RADIUS at all; a passphrase
/// mismatch), RADIUS's last rejection, its reason and the User-Name the
/// client claimed in it (`radius`: `claimed`, never who the client is), how
/// many failures there were, and whether it got on since (`connected_since`,
/// `connected`); the ones still failing first, the latest first.
pub fn auth_problems(state: &State, now_ms: u64) -> Value {
    let since = now_ms.saturating_sub(PROBLEMS_WINDOW_MS);
    let mut rows: Vec<(bool, u64, Value)> = Vec::new();
    for (mac, entries) in state.sessions.timeline.clients() {
        let recent: Vec<&Entry> = entries.iter().filter(|e| e.at_ms >= since).collect();
        let failures: Vec<&Entry> = recent.iter().copied().filter(|e| failed(e)).collect();
        let Some(last) = failures.last() else {
            continue;
        };
        let mut o = json!({
            "mac": mac::format(*mac),
            "attempts": failures.len(),
            "last": last.at_ms,
        });
        let who = state.identity(mac).fields();
        for k in ["name", "vendor"] {
            if let Some(v) = who.get(k) {
                o[k] = v.clone();
            }
        }
        let side = failures.iter().rev().find_map(|e| ap_side(e, &recent));
        if let Some(side) = side {
            o["ap_side"] = side;
        }
        let rejected = failures.iter().rev().find_map(|e| match &e.what {
            What::Radius {
                user, node, detail, ..
            } => Some(json!({ "at": e.at_ms, "claimed": user, "node": node, "detail": detail })),
            _ => None,
        });
        if let Some(r) = rejected {
            o["radius"] = r;
        }
        // On only once authorized: a client mid-EAP has not got on.
        let on = |id: u64| {
            state
                .sessions
                .of(mac)
                .any(|s| s.id == id && s.authenticated)
        };
        let joined = recent.iter().find(|e| {
            e.at_ms > last.at_ms && matches!(e.what, What::Joined { session, .. } if on(session))
        });
        if let Some(j) = joined {
            o["connected_since"] = j.at_ms.into();
        }
        let connected = state.sessions.open_of(mac).is_some_and(|s| s.authenticated);
        o["connected"] = connected.into();
        rows.push((joined.is_none() && !connected, last.at_ms, o));
    }
    rows.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
    rows.truncate(PROBLEMS_MAX);
    json!({
        "radius": radius_log(state),
        "since": since,
        "clients": rows.into_iter().map(|(_, _, o)| o).collect::<Vec<_>>(),
    })
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
