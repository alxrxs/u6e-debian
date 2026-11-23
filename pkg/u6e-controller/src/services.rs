//! What the APs' client guards read of mDNS (`AgentMsg::Services`): each AP's
//! table as its whole reads and changes build it, timed on the controller's
//! clock, and the site's view of it. A device is taken whole (its offers and
//! its queries too) from the AP whose Wi-Fi port hears it, else from the AP
//! that heard it last: every AP on a VLAN hears the same multicast, the one
//! a client is on first hand.
//!
//! The site view's offers are watched for what the UI and the timeline tell
//! of: a service gone (its goodbye, or its TTL run out) and back, a device
//! that stopped answering the queries for one ([`SILENT_AFTER`] missed in a
//! row) and that answers again; each change once, the newest [`EVENTS`]
//! kept. An offer first seen, or seen again after its AP's link came back,
//! is no change. `see` answers whether one device's queries for what
//! another offers are answered.
//!
//! Bounded as the APs bound their tables (`u6e_proto::msg::MDNS_*`): what
//! an AP sends past those is dropped. An AP's table goes with its session.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use serde_json::{Map, Value, json};
use u6e_proto::mac;
use u6e_proto::msg::{
    MDNS_DEVICES, MDNS_OFFERS, MDNS_QUERIES, MdnsDevice, MdnsKey, MdnsOffer, MdnsQuery,
    Services as Read,
};

pub use crate::timeline::ServiceChange as Change;

/// Misses in a row that make a device one that stopped answering.
pub const SILENT_AFTER: u16 = 3;
/// The service events kept.
pub const EVENTS: usize = 1000;
/// The service type whose TXT records group speakers (a stereo pair).
const AIRPLAY: &str = "_airplay._tcp.local";
const RAOP: &str = "_raop._tcp.local";

type OfferKey = ([u8; 6], String);
type QueryKey = ([u8; 6], String, u16);
/// Who offers a service type, and who asks for it.
type Parties = (BTreeSet<[u8; 6]>, BTreeSet<[u8; 6]>);

/// One AP's table, times in Unix milliseconds.
#[derive(Debug, Default, Clone)]
pub struct Table {
    pub devices: BTreeMap<[u8; 6], MdnsDevice>,
    pub offers: BTreeMap<OfferKey, MdnsOffer>,
    pub queries: BTreeMap<QueryKey, MdnsQuery>,
    pub packets: u64,
    pub malformed: u64,
    pub evicted: u64,
    pub limited: u64,
    pub at_ms: u64,
}

impl Table {
    /// The offers that live (no goodbye, TTL not run out) and miss every
    /// query in a row now.
    pub fn silent(&self, now_ms: u64) -> usize {
        let silent = |o: &&MdnsOffer| live(o, now_ms) && o.missed_in_row >= SILENT_AFTER;
        self.offers.values().filter(silent).count()
    }
}

/// Whether `o` lives at `now_ms`.
pub fn live(o: &MdnsOffer, now_ms: u64) -> bool {
    !o.goodbye && o.announced_ms + u64::from(o.ttl_s) * 1000 > now_ms
}

/// How an offer stands, as the site sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Gone,
    Answering,
    /// Missing every query since `since_ms`.
    Silent {
        since_ms: u64,
    },
}

pub fn change_name(c: Change) -> &'static str {
    match c {
        Change::Gone => "gone",
        Change::Back => "back",
        Change::Silent => "silent",
        Change::Answering => "answering",
    }
}

/// A change of an offer, as the site saw it: `by` the device whose query it
/// missed last, `misses` the misses in a row, `goodbye` whether it went by
/// its own goodbye, `silent_ms` how long it had missed every query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub at_ms: u64,
    pub ap: String,
    pub mac: [u8; 6],
    pub instance: String,
    pub service: String,
    pub change: Change,
    pub by: Option<[u8; 6]>,
    pub misses: u16,
    pub goodbye: bool,
    pub silent_ms: Option<u64>,
    /// Whether the AP heard the device on a Wi-Fi port: a client.
    pub wifi: bool,
}

#[derive(Debug, Default)]
pub struct Services {
    aps: BTreeMap<String, Table>,
    status: HashMap<OfferKey, Status>,
    pub events: VecDeque<Event>,
}

/// `t` of the AP's boot clock as Unix milliseconds, the AP's read at `now`
/// of that clock having come at `at_ms`.
fn unix(t: u64, now: u64, at_ms: u64) -> u64 {
    at_ms.saturating_sub(now.saturating_sub(t))
}

/// Moves what `s` holds onto the controller's clock.
fn retime(s: &mut Read, at_ms: u64) {
    let now = s.now_ms;
    let t = |v: &mut u64| *v = unix(*v, now, at_ms);
    let t_opt = |v: &mut Option<u64>| {
        if let Some(v) = v {
            *v = unix(*v, now, at_ms);
        }
    };
    for d in &mut s.devices {
        t(&mut d.first_ms);
        t(&mut d.last_ms);
    }
    for o in &mut s.offers {
        t(&mut o.announced_ms);
        t_opt(&mut o.answered_ms);
        t_opt(&mut o.missed_ms);
    }
    for q in &mut s.queries {
        t(&mut q.last_ms);
    }
}

impl Services {
    pub fn ap(&self, ap: &str) -> Option<&Table> {
        self.aps.get(ap)
    }

    pub fn aps(&self) -> impl Iterator<Item = (&str, &Table)> {
        self.aps.iter().map(|(n, t)| (n.as_str(), t))
    }

    /// Takes `ap`'s read `s`, which came at `at_ms`; the changes it made to
    /// the site's view.
    pub fn apply(&mut self, ap: &str, mut s: Read, at_ms: u64) -> Vec<Event> {
        retime(&mut s, at_ms);
        let table = self.aps.entry(ap.to_owned()).or_default();
        if s.full {
            *table = Table::default();
        }
        for k in s.gone {
            match k {
                MdnsKey::Device(mac) => {
                    table.devices.remove(&mac);
                }
                MdnsKey::Offer(mac, i) => {
                    table.offers.remove(&(mac, i));
                }
                MdnsKey::Query(mac, n, t) => {
                    table.queries.remove(&(mac, n, t));
                }
            }
        }
        for d in s.devices {
            if table.devices.len() < MDNS_DEVICES || table.devices.contains_key(&d.mac) {
                table.devices.insert(d.mac, d);
            }
        }
        for o in s.offers {
            let k = (o.mac, o.instance.clone());
            if table.offers.len() < MDNS_OFFERS || table.offers.contains_key(&k) {
                table.offers.insert(k, o);
            }
        }
        for q in s.queries {
            let k = (q.mac, q.name.clone(), q.qtype);
            if table.queries.len() < MDNS_QUERIES || table.queries.contains_key(&k) {
                table.queries.insert(k, q);
            }
        }
        (table.packets, table.malformed) = (s.packets, s.malformed);
        (table.evicted, table.limited) = (s.evicted, s.limited);
        table.at_ms = at_ms;
        self.watch(at_ms)
    }

    /// Forgets what `ap` said: its session ended.
    pub fn drop_ap(&mut self, ap: &str) {
        self.aps.remove(ap);
    }

    /// The AP each device is taken from: the one whose Wi-Fi port heard it
    /// last, else the one that heard it last.
    pub fn homes(&self) -> BTreeMap<[u8; 6], &str> {
        let mut best: BTreeMap<[u8; 6], (bool, u64, &str)> = BTreeMap::new();
        for (ap, t) in &self.aps {
            for d in t.devices.values() {
                let rank = (d.wifi, d.last_ms, ap.as_str());
                let e = best.entry(d.mac).or_insert(rank);
                if (rank.0, rank.1) > (e.0, e.1) {
                    *e = rank;
                }
            }
        }
        best.into_iter().map(|(m, (_, _, ap))| (m, ap)).collect()
    }

    /// The site's view: each device with its AP, and what that AP says it
    /// offers and asks.
    pub fn site(&self) -> Site<'_> {
        let mut site = Site::default();
        for (mac, ap) in self.homes() {
            let t = &self.aps[ap];
            site.devices.push((ap, &t.devices[&mac]));
            let offers = t.offers.range((mac, String::new())..);
            site.offers
                .extend(offers.take_while(|(k, _)| k.0 == mac).map(|(_, o)| (ap, o)));
            let queries = t.queries.range((mac, String::new(), 0)..);
            site.queries
                .extend(queries.take_while(|(k, _)| k.0 == mac).map(|(_, q)| q));
        }
        site
    }

    /// Looks at the site's offers at `now_ms`: what changed since the last
    /// look becomes an event.
    pub fn watch(&mut self, now_ms: u64) -> Vec<Event> {
        let site = self.site();
        let mut seen: HashMap<OfferKey, Status> = HashMap::new();
        let mut out = Vec::new();
        for (ap, o) in &site.offers {
            let key = (o.mac, o.instance.clone());
            let was = self.status.get(&key).copied();
            let now = if !live(o, now_ms) {
                Status::Gone
            } else if o.missed_in_row >= SILENT_AFTER {
                let since_ms = match was {
                    Some(Status::Silent { since_ms }) => since_ms,
                    _ => o.missed_ms.unwrap_or(now_ms),
                };
                Status::Silent { since_ms }
            } else {
                Status::Answering
            };
            let change = match (was, now) {
                (Some(Status::Answering | Status::Silent { .. }), Status::Gone) => {
                    Some(Change::Gone)
                }
                (Some(Status::Gone), Status::Answering | Status::Silent { .. }) => {
                    Some(Change::Back)
                }
                (Some(Status::Answering), Status::Silent { .. }) => Some(Change::Silent),
                (Some(Status::Silent { .. }), Status::Answering) => Some(Change::Answering),
                _ => None,
            };
            if let Some(change) = change {
                let wifi = site.device(o.mac).is_some_and(|d| d.wifi);
                let silent_ms = match (change, was) {
                    (Change::Answering, Some(Status::Silent { since_ms })) => {
                        Some(now_ms.saturating_sub(since_ms))
                    }
                    _ => None,
                };
                out.push(Event {
                    at_ms: now_ms,
                    ap: (*ap).to_owned(),
                    mac: o.mac,
                    instance: o.instance.clone(),
                    service: o.service.clone(),
                    change,
                    by: o.missed_by,
                    misses: o.missed_in_row,
                    goodbye: o.goodbye,
                    silent_ms,
                    wifi,
                });
            }
            seen.insert(key, now);
        }
        self.status = seen;
        for e in &out {
            self.events.push_back(e.clone());
        }
        while self.events.len() > EVENTS {
            self.events.pop_front();
        }
        out
    }
}

/// The site's view of the APs' tables: each device from its AP.
#[derive(Debug, Default)]
pub struct Site<'a> {
    pub devices: Vec<(&'a str, &'a MdnsDevice)>,
    pub offers: Vec<(&'a str, &'a MdnsOffer)>,
    pub queries: Vec<&'a MdnsQuery>,
}

impl Site<'_> {
    pub fn device(&self, mac: [u8; 6]) -> Option<&MdnsDevice> {
        self.devices
            .iter()
            .find(|(_, d)| d.mac == mac)
            .map(|(_, d)| *d)
    }
}

/// What `from`'s last query for one of `to`'s offers came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Answered,
    Missed,
    /// `from` listed it as a known answer: it holds it already.
    Known,
    /// Neither: it asked for a unicast answer, or the offer was not live.
    Unclear,
    NotAsked,
}

pub fn outcome_name(o: Outcome) -> &'static str {
    match o {
        Outcome::Answered => "answered",
        Outcome::Missed => "missed",
        Outcome::Known => "known",
        Outcome::Unclear => "unclear",
        Outcome::NotAsked => "not-asked",
    }
}

/// For each of `to`'s offers, `from`'s last query for its service type or
/// its instance and what came of it.
pub fn see<'a>(
    site: &Site<'a>,
    from: [u8; 6],
    to: [u8; 6],
) -> Vec<(&'a MdnsOffer, Option<&'a MdnsQuery>, Outcome)> {
    let mut out = Vec::new();
    for (_, o) in site.offers.iter().filter(|(_, o)| o.mac == to) {
        let asked = site
            .queries
            .iter()
            .filter(|q| q.mac == from)
            .filter(|q| {
                q.name.eq_ignore_ascii_case(&o.service) || q.name.eq_ignore_ascii_case(&o.instance)
            })
            .max_by_key(|q| q.last_ms)
            .copied();
        let outcome = match asked {
            None => Outcome::NotAsked,
            Some(q) if q.answered_by.contains(&to) => Outcome::Answered,
            Some(q) if q.missed_by.contains(&to) => Outcome::Missed,
            Some(q) if q.known.contains(&to) => Outcome::Known,
            Some(_) => Outcome::Unclear,
        };
        out.push((*o, asked, outcome));
    }
    out
}

/// What the UI is told of names and places.
pub trait Look {
    /// A client's name, as the controller knows it.
    fn name(&self, mac: &[u8; 6]) -> Option<String>;
    /// The band of `ap`'s port `port`, when it is a BSS's.
    fn band(&self, ap: &str, port: &str) -> Option<&'static str>;
}

/// The first label of an instance, as a person reads it.
pub fn instance_label(instance: &str) -> String {
    let mut out = String::new();
    let mut chars = instance.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.extend(chars.next()),
            '.' => break,
            _ => out.push(c),
        }
    }
    out
}

fn macs(list: &[[u8; 6]]) -> Value {
    list.iter().map(|m| Value::from(mac::format(*m))).collect()
}

fn offer_json(o: &MdnsOffer, now_ms: u64) -> Value {
    let status = if !live(o, now_ms) {
        "gone"
    } else if o.missed_in_row >= SILENT_AFTER {
        "silent"
    } else if o.answered_ms.is_some() || o.missed == 0 {
        "answering"
    } else {
        "missing"
    };
    let txt: Map<String, Value> = (o.txt.iter())
        .map(|(k, v)| (k.clone(), Value::from(v.as_str())))
        .collect();
    json!({
        "mac": mac::format(o.mac),
        "instance": o.instance,
        "label": instance_label(&o.instance),
        "service": o.service,
        "target": o.target,
        "port": o.port,
        "txt": txt,
        "ttl": o.ttl_s,
        "announced": o.announced_ms,
        "goodbye": o.goodbye,
        "status": status,
        "answered": o.answered,
        "missed": o.missed,
        "missed_in_row": o.missed_in_row,
        "answered_at": o.answered_ms,
        "missed_at": o.missed_ms,
        "missed_by": o.missed_by.map(mac::format),
    })
}

fn query_json(q: &MdnsQuery) -> Value {
    json!({
        "name": q.name,
        "qtype": q.qtype,
        "unicast": q.unicast,
        "count": q.count,
        "last": q.last_ms,
        "answered_by": macs(&q.answered_by),
        "missed_by": macs(&q.missed_by),
        "known": macs(&q.known),
        "unanswered": q.unanswered,
    })
}

/// The view `/api/services` serves: every device (of `ap`'s table alone,
/// when given; only `device` and those it relates to, when given) with its
/// offers and queries, the AirPlay groups (offers sharing a `gid`), and per
/// service type who offers it and who asks for it.
pub fn view(
    services: &Services,
    ap: Option<&str>,
    device: Option<[u8; 6]>,
    look: &dyn Look,
    now_ms: u64,
) -> Value {
    let site = match ap {
        None => services.site(),
        Some(ap) => {
            let Some(t) = services.ap(ap) else {
                return json!({ "aps": aps_json(services, now_ms), "devices": [], "groups": [], "services": [] });
            };
            Site {
                devices: t.devices.values().map(|d| (ap, d)).collect(),
                offers: t.offers.values().map(|o| (ap, o)).collect(),
                queries: t.queries.values().collect(),
            }
        }
    };
    // Per service type: who offers it, who asks for it.
    let mut by_type: BTreeMap<String, Parties> = BTreeMap::new();
    for (_, o) in &site.offers {
        by_type
            .entry(o.service.to_ascii_lowercase())
            .or_default()
            .0
            .insert(o.mac);
    }
    for q in &site.queries {
        if let Some(e) = by_type.get_mut(&q.name.to_ascii_lowercase()) {
            e.1.insert(q.mac);
        }
    }
    let related = |m: [u8; 6]| -> bool {
        let Some(d) = device else { return true };
        m == d
            || by_type.values().any(|(offer, ask)| {
                (offer.contains(&d) && ask.contains(&m)) || (ask.contains(&d) && offer.contains(&m))
            })
    };
    let devices: Vec<Value> = (site.devices.iter())
        .filter(|(_, d)| related(d.mac))
        .map(|(ap, d)| {
            let offers: Vec<Value> = (site.offers.iter())
                .filter(|(_, o)| o.mac == d.mac)
                .map(|(_, o)| offer_json(o, now_ms))
                .collect();
            let queries: Vec<Value> = (site.queries.iter())
                .filter(|q| q.mac == d.mac)
                .map(|q| query_json(q))
                .collect();
            let mut o = json!({
                "mac": mac::format(d.mac),
                "ap": ap,
                "port": d.port,
                "vlan": d.vlan,
                "wifi": d.wifi,
                "host": d.host,
                "addrs": d.addrs.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "first": d.first_ms,
                "last": d.last_ms,
                "queries_sent": d.queries,
                "responses_sent": d.responses,
                "offers": offers,
                "queries": queries,
            });
            if let Some(n) = look.name(&d.mac) {
                o["name"] = n.into();
            }
            if let Some(b) = look.band(ap, &d.port) {
                o["band"] = b.into();
            }
            o
        })
        .collect();
    let services_json: Vec<Value> = (by_type.iter())
        .filter(|(_, (offer, ask))| device.is_none_or(|d| offer.contains(&d) || ask.contains(&d)))
        .map(|(t, (offer, ask))| {
            json!({
                "service": t,
                "offered_by": offer.iter().map(|m| mac::format(*m)).collect::<Vec<_>>(),
                "asked_by": ask.iter().map(|m| mac::format(*m)).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({
        "aps": aps_json(services, now_ms),
        "devices": devices,
        "groups": groups(&site, device),
        "services": services_json,
        "targets": targets(&site),
    })
}

/// Each AP's table: its size and counts.
fn aps_json(services: &Services, now_ms: u64) -> Value {
    let aps: Map<String, Value> = services
        .aps()
        .map(|(n, t)| {
            let v = json!({
                "devices": t.devices.len(),
                "offers": t.offers.len(),
                "queries": t.queries.len(),
                "silent": t.silent(now_ms),
                "packets": t.packets,
                "malformed": t.malformed,
                "evicted": t.evicted,
                "limited": t.limited,
                "at": t.at_ms,
            });
            (n.to_owned(), v)
        })
        .collect();
    Value::Object(aps)
}

/// The AirPlay groups: offers of `_airplay._tcp` from two devices or more
/// sharing a `gid`, named by their `gpn`, the leader `igl=1`.
fn groups(site: &Site, device: Option<[u8; 6]>) -> Value {
    let mut by_gid: BTreeMap<&str, Vec<&MdnsOffer>> = BTreeMap::new();
    for (_, o) in &site.offers {
        let gid = o
            .txt
            .iter()
            .find(|(k, _)| k == "gid")
            .map(|(_, v)| v.as_str());
        if let Some(gid) = gid.filter(|g| !g.is_empty())
            && o.service.eq_ignore_ascii_case(AIRPLAY)
        {
            by_gid.entry(gid).or_default().push(o);
        }
    }
    let txt =
        |o: &MdnsOffer, key: &str| o.txt.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());
    let list: Vec<Value> = (by_gid.into_iter())
        .filter(|(_, members)| members.iter().map(|o| o.mac).collect::<BTreeSet<_>>().len() > 1)
        .filter(|(_, members)| device.is_none_or(|d| members.iter().any(|o| o.mac == d)))
        .map(|(gid, members)| {
            let name = members.iter().find_map(|o| txt(o, "gpn"));
            let members: Vec<Value> = (members.iter())
                .map(|o| {
                    json!({
                        "mac": mac::format(o.mac),
                        "instance": o.instance,
                        "label": instance_label(&o.instance),
                        "leader": txt(o, "igl").as_deref() == Some("1"),
                    })
                })
                .collect();
            json!({ "gid": gid, "name": name, "members": members })
        })
        .collect();
    Value::Array(list)
}

/// The devices offering AirPlay (video or audio).
fn targets(site: &Site) -> Value {
    let set: BTreeSet<[u8; 6]> = (site.offers.iter())
        .filter(|(_, o)| {
            o.service.eq_ignore_ascii_case(AIRPLAY) || o.service.eq_ignore_ascii_case(RAOP)
        })
        .map(|(_, o)| o.mac)
        .collect();
    set.into_iter()
        .map(|m| Value::from(mac::format(m)))
        .collect()
}

/// The view `/api/services/see` serves: for each of `to`'s offers, `from`'s
/// last query for it and what came of it.
pub fn see_view(services: &Services, from: [u8; 6], to: [u8; 6], now_ms: u64) -> Value {
    let site = services.site();
    let verdicts: Vec<Value> = see(&site, from, to)
        .into_iter()
        .map(|(o, q, outcome)| {
            json!({
                "offer": offer_json(o, now_ms),
                "query": q.map(query_json),
                "outcome": outcome_name(outcome),
            })
        })
        .collect();
    json!({
        "from": mac::format(from),
        "to": mac::format(to),
        "verdicts": verdicts,
    })
}

/// A service event as the UI shows it.
pub fn event_json(e: &Event) -> Value {
    json!({
        "kind": "service",
        "change": change_name(e.change),
        "ap": e.ap,
        "at": e.at_ms,
        "mac": mac::format(e.mac),
        "instance": e.instance,
        "label": instance_label(&e.instance),
        "service": e.service,
        "by": e.by.map(mac::format),
        "misses": e.misses,
        "goodbye": e.goodbye,
        "silent_for": e.silent_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHONE: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const LEFT: [u8; 6] = [2, 0, 0, 0, 0, 2];
    const RIGHT: [u8; 6] = [2, 0, 0, 0, 0, 3];
    /// The APs' boot clocks read 1 000 000 when the controller's reads
    /// T0.
    const T0: u64 = 1_800_000_000_000;
    const BOOT: u64 = 1_000_000;

    fn device(mac: [u8; 6], wifi: bool, last: u64) -> MdnsDevice {
        MdnsDevice {
            mac,
            port: if wifi { "wlan5.42" } else { "vlan42" }.into(),
            vlan: 42,
            wifi,
            host: String::new(),
            addrs: Vec::new(),
            first_ms: 0,
            last_ms: last,
            queries: 0,
            responses: 0,
        }
    }

    fn offer(mac: [u8; 6], label: &str, gid: &str, leader: bool) -> MdnsOffer {
        MdnsOffer {
            mac,
            instance: format!("{label}.{AIRPLAY}"),
            service: AIRPLAY.into(),
            target: format!("{label}.local"),
            port: 7000,
            txt: vec![
                ("gid".into(), gid.into()),
                ("igl".into(), if leader { "1" } else { "0" }.into()),
                ("gpn".into(), "Room".into()),
            ],
            ttl_s: 4500,
            announced_ms: BOOT,
            goodbye: false,
            answered: 1,
            missed: 0,
            missed_in_row: 0,
            answered_ms: Some(BOOT),
            missed_ms: None,
            missed_by: None,
        }
    }

    fn browse(mac: [u8; 6]) -> MdnsQuery {
        MdnsQuery {
            mac,
            name: AIRPLAY.into(),
            qtype: 12,
            unicast: false,
            count: 1,
            last_ms: BOOT,
            answered_by: vec![LEFT],
            missed_by: vec![RIGHT],
            known: vec![],
            unanswered: 0,
        }
    }

    fn full(devices: Vec<MdnsDevice>, offers: Vec<MdnsOffer>, queries: Vec<MdnsQuery>) -> Read {
        Read {
            full: true,
            now_ms: BOOT,
            devices,
            offers,
            queries,
            ..Read::default()
        }
    }

    fn pair_table() -> Read {
        full(
            vec![
                device(PHONE, true, BOOT),
                device(LEFT, true, BOOT),
                device(RIGHT, true, BOOT),
            ],
            vec![
                offer(LEFT, "Left", "G", true),
                offer(RIGHT, "Right", "G", false),
            ],
            vec![browse(PHONE)],
        )
    }

    #[test]
    fn reads_are_timed_on_the_controllers_clock_and_deltas_build_on_them() {
        let mut s = Services::default();
        assert!(s.apply("ap1", pair_table(), T0).is_empty());
        let t = s.ap("ap1").unwrap();
        assert_eq!(t.devices[&PHONE].last_ms, T0);
        assert_eq!(
            t.offers[&(LEFT, format!("Left.{AIRPLAY}"))].announced_ms,
            T0
        );
        // A delta 10 s later: the right is gone from the AP, the phone
        // asked again 2 s before the read.
        let mut q = browse(PHONE);
        q.last_ms = BOOT + 8000;
        let delta = Read {
            full: false,
            now_ms: BOOT + 10_000,
            queries: vec![q],
            gone: vec![MdnsKey::Offer(RIGHT, format!("Right.{AIRPLAY}"))],
            ..Read::default()
        };
        s.apply("ap1", delta, T0 + 10_000);
        let t = s.ap("ap1").unwrap();
        assert_eq!(t.offers.len(), 1);
        assert_eq!(t.queries[&(PHONE, AIRPLAY.into(), 12)].last_ms, T0 + 8000);
        // A full read replaces it all.
        s.apply("ap1", full(vec![], vec![], vec![]), T0 + 20_000);
        assert!(s.ap("ap1").unwrap().devices.is_empty());
    }

    #[test]
    fn a_device_is_taken_from_the_ap_whose_wifi_hears_it() {
        let mut s = Services::default();
        let mut on_ap1 = offer(LEFT, "Left", "G", true);
        on_ap1.missed_in_row = 5;
        s.apply(
            "ap1",
            full(vec![device(LEFT, false, BOOT + 500)], vec![on_ap1], vec![]),
            T0,
        );
        s.apply(
            "ap2",
            full(
                vec![device(LEFT, true, BOOT)],
                vec![offer(LEFT, "Left", "G", true)],
                vec![],
            ),
            T0,
        );
        let site = s.site();
        assert_eq!(
            site.devices,
            [("ap2", &s.ap("ap2").unwrap().devices[&LEFT])]
        );
        assert_eq!(site.offers[0].1.missed_in_row, 0);
    }

    #[test]
    fn each_change_of_an_offer_is_one_event() {
        let mut s = Services::default();
        s.apply("ap1", pair_table(), T0);
        // Both APs report the right missing three in a row: one event.
        let mut right = offer(RIGHT, "Right", "G", false);
        (right.missed, right.missed_in_row, right.missed_by) = (3, 3, Some(PHONE));
        right.missed_ms = Some(BOOT + 1000);
        let delta = |o: MdnsOffer| Read {
            now_ms: BOOT + 2000,
            offers: vec![o],
            ..Read::default()
        };
        let ev = s.apply("ap1", delta(right.clone()), T0 + 2000);
        assert_eq!(ev.len(), 1);
        assert_eq!(
            (ev[0].change, ev[0].by, ev[0].misses, ev[0].wifi),
            (Change::Silent, Some(PHONE), 3, true)
        );
        s.apply(
            "ap2",
            full(
                vec![device(RIGHT, false, BOOT)],
                vec![right.clone()],
                vec![],
            ),
            T0 + 2000,
        );
        assert!(s.apply("ap1", delta(right.clone()), T0 + 3000).is_empty());
        // It answers again a minute after its first miss.
        (right.missed_in_row, right.answered_ms) = (0, Some(BOOT + 61_000));
        let mut later = delta(right.clone());
        later.now_ms = BOOT + 62_000;
        let ev = s.apply("ap1", later, T0 + 62_000);
        assert_eq!(ev[0].change, Change::Answering);
        assert_eq!(ev[0].silent_ms, Some(61_000));
        // A goodbye, then back.
        right.goodbye = true;
        let ev = s.apply("ap1", delta(right.clone()), T0 + 63_000);
        assert_eq!((ev[0].change, ev[0].goodbye), (Change::Gone, true));
        right.goodbye = false;
        let ev = s.apply("ap1", delta(right.clone()), T0 + 64_000);
        assert_eq!(ev[0].change, Change::Back);
        // A TTL running out is seen by a look alone.
        let gone = s.watch(T0 + 4_600_000);
        assert_eq!(
            gone.iter().map(|e| e.change).collect::<Vec<_>>(),
            [Change::Gone, Change::Gone]
        );
        assert_eq!(s.events.len(), 6);
    }

    #[test]
    fn an_aps_session_ending_takes_its_table_without_events() {
        let mut s = Services::default();
        s.apply("ap1", pair_table(), T0);
        s.drop_ap("ap1");
        assert!(s.watch(T0 + 1000).is_empty());
        assert!(s.apply("ap1", pair_table(), T0 + 2000).is_empty());
    }

    #[test]
    fn what_one_device_sees_of_another() {
        let mut s = Services::default();
        let mut table = pair_table();
        let mut raop = browse(PHONE);
        (raop.name, raop.answered_by, raop.missed_by, raop.known) =
            (RAOP.into(), vec![], vec![], vec![RIGHT]);
        let mut raop_offer = offer(RIGHT, "Right", "", false);
        (raop_offer.instance, raop_offer.service) = (format!("Right.{RAOP}"), RAOP.into());
        table.offers.push(raop_offer);
        table.queries.push(raop);
        s.apply("ap1", table, T0);
        let site = s.site();
        let left: Vec<Outcome> = see(&site, PHONE, LEFT).iter().map(|v| v.2).collect();
        assert_eq!(left, [Outcome::Answered]);
        let mut right: Vec<(String, Outcome)> = see(&site, PHONE, RIGHT)
            .iter()
            .map(|v| (v.0.service.clone(), v.2))
            .collect();
        right.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            right,
            [
                (AIRPLAY.into(), Outcome::Missed),
                (RAOP.into(), Outcome::Known)
            ]
        );
        let none: Vec<Outcome> = see(&site, LEFT, RIGHT).iter().map(|v| v.2).collect();
        assert!(none.iter().all(|o| *o == Outcome::NotAsked));
    }

    struct Names;

    impl Look for Names {
        fn name(&self, mac: &[u8; 6]) -> Option<String> {
            (*mac == PHONE).then(|| "Phone".into())
        }

        fn band(&self, _: &str, port: &str) -> Option<&'static str> {
            port.starts_with("wlan5").then_some("5")
        }
    }

    #[test]
    fn the_view_names_groups_targets_and_relations() {
        let mut s = Services::default();
        let mut table = pair_table();
        table.devices.push(device([2, 0, 0, 0, 0, 9], false, BOOT));
        s.apply("ap1", table, T0);
        let v = view(&s, None, None, &Names, T0);
        assert_eq!(v["devices"].as_array().unwrap().len(), 4);
        let phone = &v["devices"][0];
        assert_eq!(
            (phone["name"].as_str(), phone["band"].as_str()),
            (Some("Phone"), Some("5"))
        );
        assert_eq!(phone["queries"][0]["missed_by"][0], "02:00:00:00:00:03");
        let group = &v["groups"][0];
        assert_eq!(
            (group["gid"].as_str(), group["name"].as_str()),
            (Some("G"), Some("Room"))
        );
        assert_eq!(group["members"][0]["leader"], true);
        assert_eq!(group["members"][0]["label"], "Left");
        assert_eq!(v["targets"].as_array().unwrap().len(), 2);
        assert_eq!(v["services"][0]["asked_by"][0], "02:00:00:00:00:01");
        assert_eq!(v["aps"]["ap1"]["devices"], 4);
        // One device: it and those it relates to, not the bystander.
        let v = view(&s, None, Some(RIGHT), &Names, T0);
        let macs: Vec<&str> = v["devices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["mac"].as_str().unwrap())
            .collect();
        assert_eq!(macs, ["02:00:00:00:00:01", "02:00:00:00:00:03"]);
        // One AP's own table; an AP without one shows nothing.
        assert_eq!(
            view(&s, Some("ap1"), None, &Names, T0)["devices"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
        assert!(
            view(&s, Some("ap2"), None, &Names, T0)["devices"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn an_ap_cannot_hold_more_than_the_caps() {
        let mut s = Services::default();
        let devices = (0..MDNS_DEVICES as u16 + 5)
            .map(|i| device([2, 9, 0, 0, (i >> 8) as u8, i as u8], true, BOOT))
            .collect();
        s.apply("ap1", full(devices, vec![], vec![]), T0);
        assert_eq!(s.ap("ap1").unwrap().devices.len(), MDNS_DEVICES);
    }

    #[test]
    fn an_instance_reads_as_its_first_label() {
        assert_eq!(
            instance_label("Living Room._airplay._tcp.local"),
            "Living Room"
        );
        assert_eq!(instance_label("a\\.b\\\\c._raop._tcp.local"), "a.b\\c");
    }
}
