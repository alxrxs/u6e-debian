//! The mDNS the replay's APs read, made up: an iPhone (`03`) browsing for
//! AirPlay, AirPlay audio and its companion link every ten seconds, and for
//! a sleep proxy nobody answers; a HomePod stereo pair (`0e` the left, the
//! group's leader, `0f` the right) whose right speaker stops answering
//! anything from second 20 to 100 of each cycle, and whose left one says
//! goodbye to its AirPlay audio from 105 to 115; a TV (`04`) offering
//! AirPlay and browsing for HomeKit, a printer (`07`), and a wired HomeKit
//! bridge both APs hear over their uplinks. Each AP hears everything on the
//! shared VLAN, its own clients on their BSS; it sends its whole table at a
//! session's start, then what changed.

use std::collections::BTreeMap;

use u6e_proto::msg::{MdnsDevice, MdnsKey, MdnsOffer, MdnsQuery, Services, Withdrawn};

use super::{BSSS, CYCLE, World};

pub const PHONE: u8 = 3;
const TV: u8 = 4;
const PRINTER: u8 = 7;
pub const LEFT: u8 = 14;
pub const RIGHT: u8 = 15;
/// The HomeKit bridge, wired.
const BRIDGE: [u8; 6] = [0x02, 0, 0, 0, 0, 0x30];
/// The pair's AirPlay group.
const GROUP: &str = "0e5c1f6a-77b2-4c39-9a0e-3d2f1b8c4e71";
/// The phone browses every this many seconds, the TV every three times as
/// long.
const EVERY: f64 = 10.0;
/// The part of each cycle the right speaker misses every query in, and the
/// left one's AirPlay audio is gone in.
const SILENT: (f64, f64) = (20.0, 100.0);
const AWAY: (f64, f64) = (105.0, 115.0);
const PTR: u16 = 12;

fn within(t: f64, (from, to): (f64, f64)) -> bool {
    (from..to).contains(&(t % CYCLE))
}

/// The times of the browses every `every` seconds up to `t`.
fn browses(t: f64, every: f64) -> impl Iterator<Item = f64> {
    (0..=(t / every) as u64).map(move |k| k as f64 * every)
}

/// What the right speaker did with the phone's browses up to `t`: answered,
/// missed, missed in a row, and when it last answered and missed.
struct Record {
    answered: u32,
    missed: u32,
    in_row: u16,
    answered_at: Option<f64>,
    missed_at: Option<f64>,
}

fn right(t: f64) -> Record {
    let mut r = Record {
        answered: 0,
        missed: 0,
        in_row: 0,
        answered_at: None,
        missed_at: None,
    };
    for b in browses(t, EVERY) {
        if within(b, SILENT) {
            (r.missed, r.in_row, r.missed_at) = (r.missed + 1, r.in_row + 1, Some(b + 1.0));
        } else {
            (r.answered, r.in_row, r.answered_at) = (r.answered + 1, 0, Some(b + 0.1));
        }
    }
    r
}

/// The table `ap` holds at `t` seconds since the start, its boot clock at
/// `boot_ms` then, its clients where `on` says (AP and BSS).
pub fn table(
    t: f64,
    boot_ms: u64,
    ap: usize,
    on: impl Fn(u8) -> Option<(usize, usize)>,
) -> Services {
    let ms = |s: f64| boot_ms.saturating_sub(((t - s).max(0.0) * 1000.0) as u64);
    let mac = World::mac;
    let mut devices = Vec::new();
    let mut device = |m: [u8; 6], at: Option<(usize, usize)>, host: &str, queries: u32| {
        let (port, vlan, wifi) = match at {
            Some((x, bss)) if x == ap => (BSSS[bss].0.to_owned(), BSSS[bss].3, true),
            _ => ("vlan10".to_owned(), 10, false),
        };
        devices.push(MdnsDevice {
            mac: m,
            port,
            vlan,
            wifi,
            host: host.into(),
            addrs: Vec::new(),
            first_ms: 0,
            last_ms: ms(t - 0.5),
            queries,
            responses: (t / EVERY) as u32,
        });
    };
    let phone_at = on(PHONE);
    let n = (t / EVERY) as u32 + 1;
    let last_browse = (t / EVERY).floor() * EVERY;
    let r = right(t);
    let silent = within(last_browse, SILENT);
    let away = within(t, AWAY);
    let mut offers = Vec::new();
    let mut queries = Vec::new();
    let offer = |m: [u8; 6],
                 instance: &str,
                 service: &str,
                 target: &str,
                 port: u16,
                 txt: &[(&str, &str)]| MdnsOffer {
        mac: m,
        instance: format!("{instance}.{service}"),
        service: service.into(),
        target: format!("{target}.local"),
        port,
        txt: txt
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect(),
        ttl_s: 4500,
        announced_ms: ms(last_browse + 0.1),
        withdrawn: None,
        answered: n,
        missed: 0,
        missed_in_row: 0,
        answered_ms: Some(ms(last_browse + 0.1)),
        missed_ms: None,
        missed_by: None,
    };
    let airplay = "_airplay._tcp.local";
    let raop = "_raop._tcp.local";
    let companion = "_companion-link._tcp.local";
    for (last, side, leader, raop_id) in [
        (LEFT, "L", "1", "5E2C3A1B9F04"),
        (RIGHT, "R", "0", "5E2C3A1B9F05"),
    ] {
        let Some(at) = on(last) else { continue };
        let host = format!("Living-Room-{side}");
        device(mac(last), Some(at), &format!("{host}.local"), 0);
        let txt = [
            ("model", "AudioAccessory5,1"),
            ("gid", GROUP),
            ("igl", leader),
            ("gpn", "Living Room"),
        ];
        let name = format!("Living Room {side}");
        let mut own = vec![
            offer(mac(last), &name, airplay, &host, 7000, &txt),
            offer(
                mac(last),
                &format!("{raop_id}@{name}"),
                raop,
                &host,
                7000,
                &txt[..1],
            ),
            offer(mac(last), &name, companion, &host, 49_152, &[]),
        ];
        if last == RIGHT {
            for o in &mut own {
                (o.answered, o.missed, o.missed_in_row) = (r.answered, r.missed, r.in_row);
                o.answered_ms = r.answered_at.map(ms);
                o.missed_ms = r.missed_at.map(ms);
                o.missed_by = r.missed_at.map(|_| mac(PHONE));
                o.announced_ms = ms(r.answered_at.unwrap_or(0.0));
            }
        }
        if last == LEFT && away {
            let gone = ms(t - t % CYCLE + AWAY.0);
            (own[1].withdrawn, own[1].announced_ms) = (Some(Withdrawn::Goodbye), gone);
        }
        offers.extend(own);
    }
    if let Some(at) = on(TV) {
        device(
            mac(TV),
            Some(at),
            "Living-Room-TV.local",
            (t / (3.0 * EVERY)) as u32 + 1,
        );
        let txt = [("model", "AppleTV14,1")];
        offers.push(offer(
            mac(TV),
            "Living Room TV",
            airplay,
            "Living-Room-TV",
            7000,
            &txt,
        ));
        offers.push(offer(
            mac(TV),
            "C8D0834F1A22@Living Room TV",
            raop,
            "Living-Room-TV",
            7000,
            &txt,
        ));
        queries.push(MdnsQuery {
            mac: mac(TV),
            name: "_hap._tcp.local".into(),
            qtype: PTR,
            unicast: false,
            count: (t / (3.0 * EVERY)) as u32 + 1,
            last_ms: ms((t / (3.0 * EVERY)).floor() * 3.0 * EVERY),
            answered_by: vec![BRIDGE],
            missed_by: Vec::new(),
            known: Vec::new(),
            unanswered: 0,
        });
    }
    if let Some(at) = on(PRINTER) {
        device(mac(PRINTER), Some(at), "Office-Printer.local", 0);
        offers.push(offer(
            mac(PRINTER),
            "Office Printer",
            "_ipp._tcp.local",
            "Office-Printer",
            631,
            &[],
        ));
        offers.push(offer(
            mac(PRINTER),
            "Office Printer",
            "_printer._tcp.local",
            "Office-Printer",
            515,
            &[],
        ));
    }
    device(BRIDGE, None, "Home-Bridge.local", 0);
    offers.push(offer(
        BRIDGE,
        "Home Bridge 5F2A",
        "_hap._tcp.local",
        "Home-Bridge",
        21_064,
        &[("md", "Home Bridge")],
    ));
    if let Some(at) = phone_at {
        device(mac(PHONE), Some(at), "iPhone.local", 4 * n);
        offers.push(offer(
            mac(PHONE),
            "iPhone",
            companion,
            "iPhone",
            49_153,
            &[],
        ));
        let on_air = |l: u8| on(l).map(|_| mac(l));
        let browse = |name: &str, answered: Vec<[u8; 6]>, missed: Vec<[u8; 6]>| MdnsQuery {
            mac: mac(PHONE),
            name: name.into(),
            qtype: PTR,
            unicast: false,
            count: n,
            last_ms: ms(last_browse),
            answered_by: answered,
            missed_by: missed,
            known: Vec::new(),
            unanswered: 0,
        };
        let (left, right_one, tv) = (on_air(LEFT), on_air(RIGHT), on_air(TV));
        let (heard, missed) = if silent {
            (None, right_one)
        } else {
            (right_one, None)
        };
        let left_audio = left.filter(|_| !away);
        queries.push(browse(
            airplay,
            [left, heard, tv].into_iter().flatten().collect(),
            missed.into_iter().collect(),
        ));
        queries.push(browse(
            raop,
            [left_audio, heard, tv].into_iter().flatten().collect(),
            missed.into_iter().collect(),
        ));
        queries.push(browse(
            companion,
            [left, heard].into_iter().flatten().collect(),
            missed.into_iter().collect(),
        ));
        queries.push(MdnsQuery {
            unanswered: n,
            ..browse("_sleep-proxy._udp.local", Vec::new(), Vec::new())
        });
    }
    Services {
        full: true,
        now_ms: boot_ms,
        devices,
        offers,
        queries,
        gone: Vec::new(),
        packets: u64::from(n) * 14,
        malformed: 0,
        evicted: 0,
        limited: 0,
    }
}

/// What an AP's agent sends of its table: whole at a session's start, then
/// the entries that changed and those gone.
#[derive(Default)]
pub struct Sent(Option<Services>);

impl Sent {
    pub fn next(&mut self, now: Services) -> Option<Services> {
        let Some(prev) = self.0.replace(now.clone()) else {
            return Some(now);
        };
        let devices = changed(&prev.devices, &now.devices, |d| MdnsKey::Device(d.mac));
        let offers = changed(&prev.offers, &now.offers, |o| {
            MdnsKey::Offer(o.mac, o.instance.clone())
        });
        let queries = changed(&prev.queries, &now.queries, |q| {
            MdnsKey::Query(q.mac, q.name.clone(), q.qtype)
        });
        let gone: Vec<MdnsKey> = [devices.1, offers.1, queries.1].concat();
        let delta = Services {
            full: false,
            devices: devices.0,
            offers: offers.0,
            queries: queries.0,
            gone,
            ..now
        };
        let empty = delta.devices.is_empty() && delta.offers.is_empty() && delta.queries.is_empty();
        (!empty || !delta.gone.is_empty()).then_some(delta)
    }
}

/// Of `now`, the entries not in `prev` as they are, and the keys of `prev`
/// that `now` has no more.
fn changed<T: Clone + PartialEq>(
    prev: &[T],
    now: &[T],
    key: impl Fn(&T) -> MdnsKey,
) -> (Vec<T>, Vec<MdnsKey>) {
    let before: BTreeMap<MdnsKey, &T> = prev.iter().map(|e| (key(e), e)).collect();
    let after: BTreeMap<MdnsKey, &T> = now.iter().map(|e| (key(e), e)).collect();
    let moved = now
        .iter()
        .filter(|e| before.get(&key(e)) != Some(e))
        .cloned()
        .collect();
    let gone = before
        .into_keys()
        .filter(|k| !after.contains_key(k))
        .collect();
    (moved, gone)
}
