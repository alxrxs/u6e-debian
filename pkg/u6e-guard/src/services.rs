//! What the guards read of the mDNS the bridges carry (`mdns`), as one
//! bounded table: the devices heard (by source MAC: the port and VLAN, the
//! host name and addresses their address records give), the services they
//! offer (from their PTR, SRV and TXT records; a TTL of 0 is a goodbye) and
//! the queries they send. Nothing of a message is kept but those names,
//! types, ports, addresses and TTLs and the few TXT keys `mdns` reads.
//!
//! Whether a device answers what it offers: a query (not a probe) opens a
//! one-second window per question name, which the copies of the same query
//! (IPv4 and IPv6) and other devices' queries for it join. Its known
//! answers and every response record's name heard within the second are
//! noted; when it closes, each live offer of that service type or instance
//! answered, was listed as known by an asker (so its owner rightly kept
//! quiet, RFC 6762 7.1), or missed. A window whose every question asked for
//! a unicast answer (QU) counts no miss: that answer may never reach the
//! host (between two clients of one BSS it never does).
//!
//! Messages are taken at most [`RATE`] a second, in bursts of [`BURST`]; the
//! rest are counted and dropped, so a client flooding mDNS costs the guards'
//! thread a bounded share of a core whatever it sends.
//!
//! Bounds: [`MDNS_DEVICES`], [`MDNS_OFFERS`] (at most [`PER_DEVICE`] a
//! device) and [`MDNS_QUERIES`] (as many a device), [`WINDOWS`] open
//! windows of at most [`WINDOW_KEYS`] names each, the least recently heard
//! entry evicted for a new one; devices unheard for [`IDLE_MS`] with no live
//! offer, offers dead (past their TTL, or said goodbye) and queries unsent
//! for as long are forgotten. Each change numbers a generation; a reader
//! gets the entries changed since its last and those forgotten since, from
//! a log of the last [`GONE`], or the whole table when it is further behind.

use std::collections::{HashMap, VecDeque};

use u6e_proto::msg::{
    MDNS_ADDRS, MDNS_DEVICES, MDNS_LISTED, MDNS_OFFERS, MDNS_QUERIES, MdnsDevice, MdnsKey,
    MdnsOffer, MdnsQuery, Services,
};

use crate::mdns::{self, Data, Kind, Message, Section};
use crate::ports::Port;

/// The most offers and queries one device holds.
pub const PER_DEVICE: usize = 32;
/// The windows open at once, the names each notes as answers and as known
/// (only its own name and the instances of its service type), and the
/// askers each records.
pub const WINDOWS: usize = 64;
pub const WINDOW_KEYS: usize = 32;
const ASKERS: usize = 4;
/// How long a window waits for answers: responders answer a shared record
/// within 20–120 ms, or 400–500 ms after a truncated query.
pub const WINDOW_MS: u64 = 1000;
/// How long a device, a dead offer or a query is kept unheard.
pub const IDLE_MS: u64 = 3600 * 1000;
/// The forgotten entries logged for readers.
pub const GONE: usize = 256;
/// The messages taken a second, and in a burst: an AP's VLANs carry about
/// one a second, a device waking a few dozen at once.
pub const RATE: u64 = 40;
pub const BURST: u64 = 200;

struct Device {
    wire: MdnsDevice,
    changed: u64,
}

struct Offer {
    wire: MdnsOffer,
    changed: u64,
    service: u64,
}

impl Offer {
    fn live(&self, now: u64) -> bool {
        !self.wire.goodbye && self.wire.announced_ms + u64::from(self.wire.ttl_s) * 1000 > now
    }

    /// When it was last heard of.
    fn active(&self) -> u64 {
        self.wire
            .announced_ms
            .max(self.wire.answered_ms.unwrap_or(0))
    }
}

struct Query {
    wire: MdnsQuery,
    changed: u64,
}

/// One question name's window.
struct Window {
    name: u64,
    deadline: u64,
    /// Every question that joined asked for a unicast answer.
    unicast: bool,
    /// Who asked, for which type, and whether they listed known answers.
    askers: Vec<([u8; 6], u16, bool)>,
    /// The names response records gave within the window (their owners and
    /// the instances PTR records point to), and those the askers listed as
    /// known.
    answered: Vec<u64>,
    known: Vec<u64>,
}

type OfferKey = ([u8; 6], u64);
type QueryKey = ([u8; 6], u64, u16);

#[derive(Default)]
pub struct Table {
    devices: HashMap<[u8; 6], Device>,
    offers: HashMap<OfferKey, Offer>,
    queries: HashMap<QueryKey, Query>,
    windows: Vec<Window>,
    generation: u64,
    gone: VecDeque<(u64, MdnsKey)>,
    /// A reader from a generation before this may have missed a forgotten
    /// entry the log no longer holds.
    floor: u64,
    packets: u64,
    malformed: u64,
    evicted: u64,
    limited: u64,
    /// The messages' allowance used and not yet given back, in thousandths
    /// of a message, and when it was last given back.
    spent: u64,
    spent_at: u64,
}

fn push_unique<T: PartialEq>(list: &mut Vec<T>, v: T, cap: usize) {
    if list.len() < cap && !list.contains(&v) {
        list.push(v);
    }
}

impl Table {
    fn bump(&mut self) -> u64 {
        self.generation += 1;
        self.generation
    }

    fn forget(&mut self, key: MdnsKey) {
        let g = self.bump();
        self.gone.push_back((g, key));
        if self.gone.len() > GONE
            && let Some((g, _)) = self.gone.pop_front()
        {
            self.floor = g;
        }
    }

    /// Takes one mDNS message `payload`, sent by `src` and read on `port`,
    /// at `now` (the boot clock, in milliseconds).
    pub fn take(&mut self, port: &Port, src: [u8; 6], payload: &[u8], now: u64) {
        self.close(now);
        self.packets += 1;
        let back = now.saturating_sub(self.spent_at) * RATE;
        (self.spent, self.spent_at) = (self.spent.saturating_sub(back), now);
        if self.spent + 1000 > BURST * 1000 {
            self.limited += 1;
            return;
        }
        self.spent += 1000;
        let Some(m) = mdns::parse(payload) else {
            self.malformed += 1;
            return;
        };
        if !m.complete {
            self.malformed += 1;
        }
        self.touch(port, src, m.response, now);
        if m.response {
            self.response(src, &m, payload, now);
        } else if !m.is_probe() {
            self.query(src, &m, payload, now);
        }
    }

    /// The device `src`, made if it is new, heard now.
    fn touch(&mut self, port: &Port, src: [u8; 6], response: bool, now: u64) {
        if !self.devices.contains_key(&src) && self.devices.len() >= MDNS_DEVICES {
            let oldest = self.devices.values().min_by_key(|d| d.wire.last_ms);
            if let Some(mac) = oldest.map(|d| d.wire.mac) {
                self.evicted += self.drop_device(mac);
            }
        }
        let g = self.bump();
        let d = self.devices.entry(src).or_insert_with(|| Device {
            wire: MdnsDevice {
                mac: src,
                port: String::new(),
                vlan: 0,
                wifi: false,
                host: String::new(),
                addrs: Vec::new(),
                first_ms: now,
                last_ms: now,
                queries: 0,
                responses: 0,
            },
            changed: g,
        });
        let w = &mut d.wire;
        if w.port != port.name {
            w.port.clone_from(&port.name);
        }
        (w.vlan, w.wifi, w.last_ms) = (port.vlan, port.wifi, now);
        if response {
            w.responses = w.responses.saturating_add(1);
        } else {
            w.queries = w.queries.saturating_add(1);
        }
        d.changed = g;
    }

    /// Forgets device `mac` and what it offers and asks; how many entries
    /// that was.
    fn drop_device(&mut self, mac: [u8; 6]) -> u64 {
        self.devices.remove(&mac);
        self.forget(MdnsKey::Device(mac));
        let offers: Vec<OfferKey> = self.offers.keys().filter(|k| k.0 == mac).copied().collect();
        let queries: Vec<QueryKey> = self
            .queries
            .keys()
            .filter(|k| k.0 == mac)
            .copied()
            .collect();
        let n = 1 + offers.len() + queries.len();
        offers.into_iter().for_each(|k| self.drop_offer(k));
        queries.into_iter().for_each(|k| self.drop_query(k));
        n as u64
    }

    fn drop_offer(&mut self, k: OfferKey) {
        if let Some(o) = self.offers.remove(&k) {
            self.forget(MdnsKey::Offer(k.0, o.wire.instance));
        }
    }

    fn drop_query(&mut self, k: QueryKey) {
        if let Some(q) = self.queries.remove(&k) {
            self.forget(MdnsKey::Query(k.0, q.wire.name, k.2));
        }
    }

    /// Makes room for one more of `src`'s offers: the least recently active
    /// of its own when it holds [`PER_DEVICE`], else of all at the cap.
    fn room_for_offer(&mut self, src: [u8; 6]) {
        let mine = self.offers.iter().filter(|(k, _)| k.0 == src).count();
        let victim = if mine >= PER_DEVICE {
            self.offers
                .iter()
                .filter(|(k, _)| k.0 == src)
                .min_by_key(|(_, o)| o.active())
        } else if self.offers.len() >= MDNS_OFFERS {
            self.offers.iter().min_by_key(|(_, o)| o.active())
        } else {
            None
        };
        if let Some(k) = victim.map(|(k, _)| *k) {
            self.drop_offer(k);
            self.evicted += 1;
        }
    }

    fn room_for_query(&mut self, src: [u8; 6]) {
        let mine = self.queries.keys().filter(|k| k.0 == src).count();
        let victim = if mine >= PER_DEVICE {
            self.queries
                .iter()
                .filter(|(k, _)| k.0 == src)
                .min_by_key(|(_, q)| q.wire.last_ms)
        } else if self.queries.len() >= MDNS_QUERIES {
            self.queries.iter().min_by_key(|(_, q)| q.wire.last_ms)
        } else {
            None
        };
        if let Some(k) = victim.map(|(k, _)| *k) {
            self.drop_query(k);
            self.evicted += 1;
        }
    }

    /// The offer of `src` for `name` of message `msg`, made if it is new;
    /// none when `name` is no instance.
    fn offer(
        &mut self,
        src: [u8; 6],
        name: &mdns::Name,
        msg: &[u8],
        now: u64,
    ) -> Option<&mut Offer> {
        let service = name.service_key()?;
        let key = (src, name.key);
        if !self.offers.contains_key(&key) {
            self.room_for_offer(src);
        }
        let g = self.bump();
        let o = self.offers.entry(key).or_insert_with(|| Offer {
            wire: MdnsOffer {
                mac: src,
                instance: name.text(msg),
                service: name.service_text(msg).unwrap_or_default(),
                target: String::new(),
                port: 0,
                txt: Vec::new(),
                ttl_s: 0,
                announced_ms: now,
                goodbye: false,
                answered: 0,
                missed: 0,
                missed_in_row: 0,
                answered_ms: None,
                missed_ms: None,
                missed_by: None,
            },
            changed: g,
            service,
        });
        o.changed = g;
        Some(o)
    }

    fn response(&mut self, src: [u8; 6], m: &Message, msg: &[u8], now: u64) {
        for r in &m.records {
            match &r.data {
                Data::Ptr(instance)
                    if r.name.kind == Kind::Service
                        && instance.service_key() == Some(r.name.key) =>
                {
                    if let Some(o) = self.offer(src, instance, msg, now) {
                        announce(&mut o.wire, r.ttl, now);
                    }
                }
                Data::Srv { port, target } => {
                    if let Some(o) = self.offer(src, &r.name, msg, now) {
                        announce(&mut o.wire, r.ttl, now);
                        o.wire.port = *port;
                        let target = target.text(msg);
                        if o.wire.target != target {
                            o.wire.target = target;
                        }
                    }
                }
                Data::Txt(txt) => {
                    if let Some(o) = self.offer(src, &r.name, msg, now)
                        && o.wire.txt != *txt
                    {
                        o.wire.txt.clone_from(txt);
                    }
                }
                Data::A(a) => self.address(src, &r.name, msg, (*a).into()),
                Data::Aaaa(a) => self.address(src, &r.name, msg, (*a).into()),
                _ => {}
            }
            // What answers each window: its own name, and an instance of
            // its service type.
            for w in &mut self.windows {
                if r.name.key == w.name {
                    push_unique(&mut w.answered, w.name, WINDOW_KEYS);
                    if let Data::Ptr(instance) = &r.data {
                        push_unique(&mut w.answered, instance.key, WINDOW_KEYS);
                    }
                } else if r.name.service_key() == Some(w.name) {
                    push_unique(&mut w.answered, r.name.key, WINDOW_KEYS);
                }
            }
        }
    }

    /// `src`'s address record of `host` (of message `msg`) for `ip`.
    fn address(&mut self, src: [u8; 6], host: &mdns::Name, msg: &[u8], ip: std::net::IpAddr) {
        if host.kind != Kind::Other || !host.local {
            return;
        }
        let g = self.bump();
        let Some(d) = self.devices.get_mut(&src) else {
            return;
        };
        let w = &mut d.wire;
        let text = host.text(msg);
        if w.host != text {
            w.host = text;
        }
        if w.addrs.first() != Some(&ip) {
            w.addrs.retain(|a| *a != ip);
            w.addrs.insert(0, ip);
            w.addrs.truncate(MDNS_ADDRS);
        }
        d.changed = g;
    }

    fn query(&mut self, src: [u8; 6], m: &Message, msg: &[u8], now: u64) {
        let answers: Vec<&mdns::Record> = (m.records.iter())
            .filter(|r| r.section == Section::Answer)
            .collect();
        for q in &m.questions {
            // The known answers for this name: the instances its PTR
            // records point to, or the name itself.
            let known: Vec<u64> = (answers.iter())
                .filter(|r| r.name.key == q.name.key)
                .map(|r| match &r.data {
                    Data::Ptr(instance) => instance.key,
                    _ => r.name.key,
                })
                .collect();
            let asked = self.window(src, q, &known, now);
            let key = (src, q.name.key, q.qtype);
            if !self.queries.contains_key(&key) {
                self.room_for_query(src);
            }
            let g = self.bump();
            let entry = self.queries.entry(key).or_insert_with(|| Query {
                wire: MdnsQuery {
                    mac: src,
                    name: q.name.text(msg),
                    qtype: q.qtype,
                    unicast: q.unicast,
                    count: 0,
                    last_ms: now,
                    answered_by: Vec::new(),
                    missed_by: Vec::new(),
                    known: Vec::new(),
                    unanswered: 0,
                },
                changed: g,
            });
            // The IPv6 copy of a query, or its repeat in the window, is
            // the same query.
            if !asked {
                entry.wire.count = entry.wire.count.saturating_add(1);
            }
            (entry.wire.unicast, entry.wire.last_ms) = (q.unicast, now);
            entry.changed = g;
        }
    }

    /// Opens the window of `q`'s name, or joins it, as `src` asking with
    /// `known` answers; whether `src` had asked it so in this window. With
    /// every window taken the query goes unwatched, counted as evicted.
    fn window(&mut self, src: [u8; 6], q: &mdns::Question, known: &[u64], now: u64) -> bool {
        let at = match self.windows.iter().position(|w| w.name == q.name.key) {
            Some(at) => at,
            None if self.windows.len() < WINDOWS => {
                self.windows.push(Window {
                    name: q.name.key,
                    deadline: now + WINDOW_MS,
                    unicast: true,
                    askers: Vec::new(),
                    answered: Vec::new(),
                    known: Vec::new(),
                });
                self.windows.len() - 1
            }
            None => {
                self.evicted += 1;
                return false;
            }
        };
        let w = &mut self.windows[at];
        w.unicast &= q.unicast;
        for k in known {
            push_unique(&mut w.known, *k, WINDOW_KEYS);
        }
        let asked = w
            .askers
            .iter()
            .any(|(mac, t, _)| *mac == src && *t == q.qtype);
        if !asked {
            push_unique(&mut w.askers, (src, q.qtype, !known.is_empty()), ASKERS);
        }
        asked
    }

    /// Closes the windows past their deadline at `now`.
    fn close(&mut self, now: u64) {
        while let Some(at) = self.windows.iter().position(|w| w.deadline <= now) {
            let w = self.windows.swap_remove(at);
            self.settle(&w, now);
        }
    }

    /// Counts what each live offer the window asked for did, and tells its
    /// askers.
    fn settle(&mut self, w: &Window, now: u64) {
        let (mut answered, mut missed, mut known) = (Vec::new(), Vec::new(), Vec::new());
        let g = self.bump();
        let asker = w.askers.first().map(|(mac, _, _)| *mac);
        let asked = self
            .offers
            .iter_mut()
            .filter(|(k, o)| (o.service == w.name || k.1 == w.name) && o.live(now));
        for ((mac, instance), o) in asked {
            if w.answered.contains(instance) {
                o.wire.answered = o.wire.answered.saturating_add(1);
                (o.wire.missed_in_row, o.wire.answered_ms) = (0, Some(now));
                push_unique(&mut answered, *mac, MDNS_LISTED);
            } else if w.known.contains(instance) {
                push_unique(&mut known, *mac, MDNS_LISTED);
                continue;
            } else if !w.unicast {
                o.wire.missed = o.wire.missed.saturating_add(1);
                o.wire.missed_in_row = o.wire.missed_in_row.saturating_add(1);
                (o.wire.missed_ms, o.wire.missed_by) = (Some(now), asker);
                push_unique(&mut missed, *mac, MDNS_LISTED);
            } else {
                continue;
            }
            o.changed = g;
        }
        for list in [&mut answered, &mut missed, &mut known] {
            list.sort_unstable();
        }
        let silent = !w.answered.contains(&w.name);
        for (mac, qtype, lists) in &w.askers {
            let Some(q) = self.queries.get_mut(&(*mac, w.name, *qtype)) else {
                continue;
            };
            q.wire.answered_by.clone_from(&answered);
            q.wire.missed_by.clone_from(&missed);
            q.wire.known.clone_from(&known);
            if silent && !lists && !w.unicast {
                q.wire.unanswered = q.wire.unanswered.saturating_add(1);
            }
            q.changed = g;
        }
    }

    /// Closes what is due and forgets what idled past [`IDLE_MS`] at `now`.
    pub fn expire(&mut self, now: u64) {
        self.close(now);
        let idle = |t: u64| now.saturating_sub(t) > IDLE_MS;
        let offers: Vec<OfferKey> = self
            .offers
            .iter()
            .filter(|(_, o)| !o.live(now) && idle(o.active()))
            .map(|(k, _)| *k)
            .collect();
        offers.into_iter().for_each(|k| self.drop_offer(k));
        let queries: Vec<QueryKey> = self
            .queries
            .iter()
            .filter(|(_, q)| idle(q.wire.last_ms))
            .map(|(k, _)| *k)
            .collect();
        queries.into_iter().for_each(|k| self.drop_query(k));
        let offering = |mac: [u8; 6]| self.offers.iter().any(|(k, o)| k.0 == mac && o.live(now));
        let devices: Vec<[u8; 6]> = self
            .devices
            .values()
            .filter(|d| idle(d.wire.last_ms) && !offering(d.wire.mac))
            .map(|d| d.wire.mac)
            .collect();
        for mac in devices {
            self.drop_device(mac);
        }
    }

    /// The generation reached and what changed after `since`, or the whole
    /// table without one or when the log of what was forgotten no longer
    /// reaches back to it.
    pub fn read(&mut self, since: Option<u64>, now: u64) -> (u64, Services) {
        self.expire(now);
        let after = since.filter(|s| *s >= self.floor && *s <= self.generation);
        let newer = |changed: u64| after.is_none_or(|s| changed > s);
        let mut devices: Vec<MdnsDevice> = (self.devices.values())
            .filter(|d| newer(d.changed))
            .map(|d| d.wire.clone())
            .collect();
        let mut offers: Vec<MdnsOffer> = (self.offers.values())
            .filter(|o| newer(o.changed))
            .map(|o| o.wire.clone())
            .collect();
        let mut queries: Vec<MdnsQuery> = (self.queries.values())
            .filter(|q| newer(q.changed))
            .map(|q| q.wire.clone())
            .collect();
        devices.sort_by_key(|d| d.mac);
        offers.sort_by(|a, b| (a.mac, &a.instance).cmp(&(b.mac, &b.instance)));
        queries.sort_by(|a, b| (a.mac, &a.name, a.qtype).cmp(&(b.mac, &b.name, b.qtype)));
        let gone = match after {
            Some(s) => self
                .gone
                .iter()
                .filter(|(g, _)| *g > s)
                .map(|(_, k)| k.clone())
                .collect(),
            None => Vec::new(),
        };
        let read = Services {
            full: after.is_none(),
            now_ms: now,
            devices,
            offers,
            queries,
            gone,
            packets: self.packets,
            malformed: self.malformed,
            evicted: self.evicted,
            limited: self.limited,
        };
        (self.generation, read)
    }
}

/// An offer announced or answered by a record of `ttl`, which lives until the
/// latest expiry its records give (a PTR's 75 minutes outlast its SRV's 2),
/// or withdrawn by one of TTL 0 (a goodbye).
fn announce(o: &mut MdnsOffer, ttl: u32, now: u64) {
    if ttl == 0 {
        (o.announced_ms, o.goodbye) = (now, true);
        return;
    }
    let held = match o.goodbye {
        true => now,
        false => o.announced_ms + u64::from(o.ttl_s) * 1000,
    };
    let until = held.max(now + u64::from(ttl) * 1000);
    o.ttl_s = u32::try_from((until - now) / 1000).unwrap_or(u32::MAX);
    (o.announced_ms, o.goodbye) = (now, false);
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::mdns::tests::{Builder, Rd, airplay_response, within};
    use crate::mdns::{A, PTR, SRV, TXT};

    const PHONE: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const LEFT: [u8; 6] = [2, 0, 0, 0, 0, 2];
    const RIGHT: [u8; 6] = [2, 0, 0, 0, 0, 3];
    const AIRPLAY: &str = "_airplay._tcp.local";

    fn wifi() -> Port {
        Port {
            ifindex: 10,
            name: "wlan5.42".into(),
            vlan: 42,
            wifi: true,
        }
    }

    fn browse(service: &str, unicast: bool, known: &[&str]) -> Vec<u8> {
        let mut b = Builder::new(false);
        b.question(service, PTR, unicast);
        for k in known {
            b.record(1, service, PTR, 4500, Rd::Ptr(&format!("{k}.{service}")));
        }
        b.bytes()
    }

    /// The pair, each announcing its AirPlay service at 0.
    fn pair() -> Table {
        let mut s = Table::default();
        s.take(
            &wifi(),
            LEFT,
            &airplay_response("Left", "Left", &["gid=G", "igl=1"]),
            0,
        );
        s.take(
            &wifi(),
            RIGHT,
            &airplay_response("Right", "Right", &["gid=G", "igl=0"]),
            0,
        );
        s
    }

    fn offer(r: &Services, mac: [u8; 6]) -> &MdnsOffer {
        r.offers.iter().find(|o| o.mac == mac).unwrap()
    }

    fn query(r: &Services, mac: [u8; 6]) -> &MdnsQuery {
        r.queries.iter().find(|q| q.mac == mac).unwrap()
    }

    #[test]
    fn offers_come_from_their_records() {
        let mut s = pair();
        let (_, r) = s.read(None, 10);
        assert!(r.full);
        assert_eq!(r.devices.len(), 2);
        let left = offer(&r, LEFT);
        assert_eq!(left.instance, "Left._airplay._tcp.local");
        assert_eq!(left.service, AIRPLAY);
        assert_eq!((left.target.as_str(), left.port), ("Left.local", 7000));
        assert_eq!(
            left.txt,
            [("gid".into(), "G".into()), ("igl".into(), "1".into())]
        );
        assert_eq!((left.ttl_s, left.goodbye), (4500, false));
        let d = r.devices.iter().find(|d| d.mac == LEFT).unwrap();
        assert_eq!(d.host, "Left.local");
        assert_eq!(d.addrs.len(), 2);
        assert_eq!(
            (d.port.as_str(), d.vlan, d.wifi, d.responses),
            ("wlan5.42", 42, true, 1)
        );
        // A goodbye withdraws it.
        let mut bye = Builder::new(true);
        bye.record(1, AIRPLAY, PTR, 0, Rd::Ptr("Left._airplay._tcp.local"));
        s.take(&wifi(), LEFT, &bye.bytes(), 20);
        let (_, r) = s.read(None, 30);
        assert!(offer(&r, LEFT).goodbye);
    }

    #[test]
    fn a_window_tells_who_answered_who_kept_quiet_and_who_missed() {
        let mut s = pair();
        // The phone browses, listing neither; only the left answers.
        s.take(&wifi(), PHONE, &browse(AIRPLAY, false, &[]), 100);
        s.take(&wifi(), LEFT, &airplay_response("Left", "Left", &[]), 180);
        let (_, r) = s.read(None, 1200);
        let q = query(&r, PHONE);
        assert_eq!(
            (q.count, q.answered_by.as_slice(), q.missed_by.as_slice()),
            (1, &[LEFT][..], &[RIGHT][..])
        );
        assert_eq!(q.unanswered, 0);
        let right = offer(&r, RIGHT);
        assert_eq!(
            (right.missed, right.missed_in_row, right.missed_by),
            (1, 1, Some(PHONE))
        );
        assert_eq!(
            (offer(&r, LEFT).answered, offer(&r, LEFT).answered_ms),
            (1, Some(1200))
        );
        // Two more misses in a row; then the right answers, which resets
        // the row.
        for t in [2000, 4000] {
            s.take(&wifi(), PHONE, &browse(AIRPLAY, false, &[]), t);
        }
        let (_, r) = s.read(None, 5100);
        assert_eq!(offer(&r, RIGHT).missed_in_row, 3);
        s.take(&wifi(), PHONE, &browse(AIRPLAY, false, &[]), 6000);
        s.take(
            &wifi(),
            RIGHT,
            &airplay_response("Right", "Right", &[]),
            6100,
        );
        let (_, r) = s.read(None, 7100);
        assert_eq!(
            (offer(&r, RIGHT).missed, offer(&r, RIGHT).missed_in_row),
            (3, 0)
        );
        assert_eq!(query(&r, PHONE).count, 4);
    }

    #[test]
    fn a_known_answer_is_no_miss_nor_is_a_unicast_question() {
        let mut s = pair();
        s.take(
            &wifi(),
            PHONE,
            &browse(AIRPLAY, false, &["Left", "Right"]),
            100,
        );
        let (_, r) = s.read(None, 1200);
        let q = query(&r, PHONE);
        assert_eq!(q.known, [LEFT, RIGHT]);
        assert!(q.missed_by.is_empty() && q.unanswered == 0);
        // Unicast: nothing heard is no miss, and nothing unanswered.
        s.take(&wifi(), PHONE, &browse(AIRPLAY, true, &[]), 2000);
        let (_, r) = s.read(None, 3100);
        assert_eq!(offer(&r, RIGHT).missed, 0);
        assert_eq!(query(&r, PHONE).unanswered, 0);
        // Asked from scratch and answered by nobody: unanswered.
        s.take(
            &wifi(),
            PHONE,
            &browse("_raop._tcp.local", false, &[]),
            4000,
        );
        let (_, r) = s.read(None, 5100);
        let raop = r
            .queries
            .iter()
            .find(|q| q.name == "_raop._tcp.local")
            .unwrap();
        assert_eq!(raop.unanswered, 1);
    }

    #[test]
    fn copies_and_probes_are_not_new_queries() {
        let mut s = pair();
        let q = browse(AIRPLAY, false, &[]);
        s.take(&wifi(), PHONE, &q, 100);
        s.take(&wifi(), PHONE, &q, 101);
        let mut probe = Builder::new(false);
        probe
            .question("Left._airplay._tcp.local", 255, true)
            .record(
                2,
                "Left._airplay._tcp.local",
                SRV,
                120,
                Rd::Srv(7000, "Left.local"),
            );
        s.take(&wifi(), LEFT, &probe.bytes(), 102);
        let (_, r) = s.read(None, 1200);
        assert_eq!(query(&r, PHONE).count, 1);
        assert!(r.queries.iter().all(|q| q.mac != LEFT));
        assert_eq!(
            r.devices.iter().find(|d| d.mac == PHONE).unwrap().queries,
            2
        );
    }

    #[test]
    fn a_dead_offer_is_not_missed_and_an_answer_for_it_counts() {
        let mut s = Table::default();
        let mut short = Builder::new(true);
        short.record(1, AIRPLAY, PTR, 2, Rd::Ptr("Left._airplay._tcp.local"));
        s.take(&wifi(), LEFT, &short.bytes(), 0);
        // Past its TTL by the time the window closes.
        s.take(&wifi(), PHONE, &browse(AIRPLAY, false, &[]), 1500);
        let (_, r) = s.read(None, 2600);
        assert_eq!(offer(&r, LEFT).missed, 0);
        // Another device answering for it (a sleep proxy) answers it.
        s.take(&wifi(), LEFT, &short.bytes(), 3000);
        s.take(&wifi(), PHONE, &browse(AIRPLAY, false, &[]), 3100);
        s.take(&wifi(), RIGHT, &short.bytes(), 3200);
        let (_, r) = s.read(None, 4200);
        assert_eq!(offer(&r, LEFT).answered, 1);
    }

    #[test]
    fn reads_carry_changes_and_what_went() {
        let mut s = pair();
        let (g, full) = s.read(None, 10);
        assert!(full.full && full.gone.is_empty());
        let (g2, none) = s.read(Some(g), 20);
        assert_eq!((g2, none.full), (g, false));
        assert!(none.devices.is_empty() && none.offers.is_empty() && none.queries.is_empty());
        s.take(&wifi(), PHONE, &browse(AIRPLAY, false, &[]), 100);
        let (g3, delta) = s.read(Some(g2), 1200);
        assert_eq!(
            delta.devices.iter().map(|d| d.mac).collect::<Vec<_>>(),
            [PHONE]
        );
        assert_eq!(delta.queries.len(), 1);
        // Both offers were settled: the right missed, the left too (it
        // did not answer).
        assert_eq!(delta.offers.len(), 2);
        // An hour later the phone and its query are forgotten; the pair's
        // offers live on (4500 s) and so do they.
        let later = 1200 + IDLE_MS + 1;
        let (_, gone) = s.read(Some(g3), later);
        assert_eq!(
            gone.gone,
            [
                MdnsKey::Query(PHONE, AIRPLAY.into(), PTR),
                MdnsKey::Device(PHONE)
            ]
        );
        // A reader from before another start, or too far behind, gets it all.
        let (_, behind) = s.read(Some(g3 + 1000), later);
        assert!(behind.full);
    }

    #[test]
    fn a_gone_log_that_overflowed_makes_the_next_read_whole() {
        let mut s = Table::default();
        let (g, _) = s.read(None, 0);
        for i in 0..=GONE {
            let q = browse(&format!("_s{i}._tcp.local"), true, &[]);
            s.take(&wifi(), PHONE, &q, i as u64 * 1000);
        }
        let (_, r) = s.read(Some(g), IDLE_MS + 400_000);
        assert!(r.full && r.queries.is_empty() && r.devices.is_empty());
    }

    #[test]
    fn the_table_stays_within_its_caps() {
        let mut s = Table::default();
        // Devices: the least recently heard goes, with what it held.
        for i in 0..=MDNS_DEVICES as u64 {
            let mac = [2, 1, 0, 0, (i >> 8) as u8, i as u8];
            let msg = airplay_response(&format!("D{i}"), &format!("d{i}"), &[]);
            s.take(&wifi(), mac, &msg, i);
        }
        let (_, r) = s.read(None, 1000);
        assert_eq!(
            (r.devices.len(), r.offers.len()),
            (MDNS_DEVICES, MDNS_DEVICES)
        );
        assert!(r.devices.iter().all(|d| d.mac != [2, 1, 0, 0, 0, 0]));
        assert_eq!(r.evicted, 2);
        // One device's offers and queries: 32 each.
        let mut s = Table::default();
        let mut b = Builder::new(true);
        for i in 0..PER_DEVICE + 5 {
            b.record(
                1,
                AIRPLAY,
                PTR,
                4500,
                Rd::Ptr(&format!("I{i}._airplay._tcp.local")),
            );
        }
        s.take(&wifi(), LEFT, &b.bytes(), 0);
        let mut q = Builder::new(false);
        for i in 0..PER_DEVICE + 5 {
            q.question(&format!("_s{i}._tcp.local"), PTR, false);
        }
        s.take(&wifi(), PHONE, &q.bytes(), 0);
        let (_, r) = s.read(None, 0);
        assert_eq!((r.offers.len(), r.queries.len()), (PER_DEVICE, PER_DEVICE));
        // Windows: the 65th name finds none open.
        let mut s = Table::default();
        for (i, mac) in [PHONE, LEFT, RIGHT].into_iter().enumerate() {
            let mut q = Builder::new(false);
            for n in (0..WINDOWS + 1).skip(i * 31).take(31) {
                q.question(&format!("n{n}.local"), A, false);
            }
            s.take(&wifi(), mac, &q.bytes(), 0);
        }
        assert_eq!((s.windows.len(), s.evicted), (WINDOWS, 1));
        assert_eq!(s.queries.len(), WINDOWS + 1);
        // Addresses: the newest four.
        let mut s = Table::default();
        let mut b = Builder::new(true);
        for i in 0..6 {
            b.record(1, "h.local", A, 120, Rd::A([192, 0, 2, i]));
        }
        b.record(1, "h.local", TXT, 120, Rd::Txt(&[]));
        s.take(&wifi(), LEFT, &b.bytes(), 0);
        let (_, r) = s.read(None, 0);
        let addrs: Vec<String> = r.devices[0].addrs.iter().map(|a| a.to_string()).collect();
        assert_eq!(addrs, ["192.0.2.5", "192.0.2.4", "192.0.2.3", "192.0.2.2"]);
    }

    /// The frames of a pcap file (Ethernet, microseconds) and their times.
    fn pcap(bytes: &[u8]) -> Vec<(u64, &[u8])> {
        let mut at = 24;
        let mut out = Vec::new();
        while at + 16 <= bytes.len() {
            let word = |o: usize| u32::from_le_bytes(bytes[at + o..at + o + 4].try_into().unwrap());
            let ms = u64::from(word(0)) * 1000 + u64::from(word(4)) / 1000;
            let len = word(8) as usize;
            out.push((ms, &bytes[at + 16..at + 16 + len]));
            at += 16 + len;
        }
        out
    }

    /// 56 s of mDNS on a 5 GHz BSS's per-VLAN port, both ways, every
    /// identifier rewritten to documentation values.
    const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/mdns.pcap");

    #[test]
    fn real_traffic_reads_whole() {
        let mut s = Table::default();
        let frames = pcap(FIXTURE);
        let start = frames[0].0;
        for (ms, f) in &frames {
            let (_, payload) = mdns::payload(f).unwrap();
            let src: [u8; 6] = f[6..12].try_into().unwrap();
            s.take(&wifi(), src, payload, ms - start);
            assert!(mdns::parse(payload).unwrap().complete);
        }
        let end = frames.last().unwrap().0 - start + WINDOW_MS;
        let (_, r) = s.read(None, end);
        assert_eq!((r.packets, r.malformed, r.evicted), (42, 0, 0));
        assert_eq!(r.devices.len(), 7);
        let services: std::collections::BTreeSet<&str> =
            r.offers.iter().map(|o| o.service.as_str()).collect();
        assert!(
            [
                "_companion-link._tcp.local",
                "_hap._tcp.local",
                "_raop._tcp.local",
                "_googlecast._tcp.local"
            ]
            .iter()
            .all(|s| services.contains(s)),
            "{services:?}"
        );
        // The HomeKit browse lists what it knows: their owners it has heard
        // are known, never missed.
        let hap = r
            .queries
            .iter()
            .find(|q| q.name == "_hap._tcp.local" && q.qtype == PTR)
            .unwrap();
        assert!(hap.missed_by.is_empty());
        // Each query and its IPv6 copy are one.
        assert!(r.queries.iter().all(|q| q.count <= 2), "{:?}", r.queries);
        // Reverse names give no offer; host names give addresses.
        assert!(r.offers.iter().all(|o| !o.instance.ends_with(".arpa")));
        assert!(
            r.devices
                .iter()
                .any(|d| !d.addrs.is_empty() && d.host.ends_with(".local"))
        );
    }

    #[test]
    fn taking_a_message_is_cheap() {
        let frames: Vec<(Vec<u8>, [u8; 6])> = pcap(FIXTURE)
            .iter()
            .map(|(_, f)| {
                (
                    mdns::payload(f).unwrap().1.to_vec(),
                    f[6..12].try_into().unwrap(),
                )
            })
            .collect();
        let each = cost(move |s, i| {
            let (payload, src) = &frames[i as usize % frames.len()];
            s.take(&wifi(), *src, payload, i * 1000);
        });
        eprintln!("services: {each:?} a message");
        assert!(each <= TARGET * DEBUG, "{each:?} a message");
    }

    #[test]
    fn a_flood_is_cut_to_the_rate() {
        let msg = browse(AIRPLAY, false, &[]);
        let mut s = Table::default();
        // A burst at once: the first BURST are taken.
        for _ in 0..BURST + 50 {
            s.take(&wifi(), PHONE, &msg, 1000);
        }
        assert_eq!((s.packets, s.limited), (BURST + 50, 50));
        // A second later RATE more are taken, no more.
        for _ in 0..RATE + 10 {
            s.take(&wifi(), PHONE, &msg, 2000);
        }
        assert_eq!(s.limited, 60);
        let (_, r) = s.read(None, 2000);
        assert_eq!(r.limited, 60);
    }

    /// The plan's cost of a message on the build host, a release build: 5 µs
    /// (the A53 is about 5 times slower). A hostile message may cost at most
    /// [`WORST`] times that; a debug build runs about [`DEBUG`] times slower.
    const TARGET: std::time::Duration = std::time::Duration::from_micros(5);
    const WORST: u32 = 4;
    const DEBUG: u32 = if cfg!(debug_assertions) { 30 } else { 1 };

    /// What `take` costs a message, the `i`th, a second apart so no limit
    /// holds one back: the best of 5 rounds of 1000, as other tests running
    /// at once make the slower ones slower.
    fn cost(mut take: impl FnMut(&mut Table, u64)) -> std::time::Duration {
        (0..5)
            .map(|round| {
                let mut s = Table::default();
                let started = std::time::Instant::now();
                for i in 0..1000 {
                    take(&mut s, round * 1000 + i);
                }
                started.elapsed() / 1000
            })
            .min()
            .unwrap_or_default()
    }

    /// A response of 92 PTR records whose owner and data each point at one
    /// name of 127 labels: 184 names of 127 labels to walk.
    pub fn long_names() -> Vec<u8> {
        let mut m = vec![0, 0, 0x84, 0, 0, 0, 0, 92, 0, 0, 0, 0];
        for _ in 0..127 {
            m.extend([1, b'a']);
        }
        m.push(0);
        m.extend([0, 12, 0, 1, 0, 0, 0, 120, 0, 2, 0xc0, 12]);
        for _ in 1..92 {
            m.extend([0xc0, 12, 0, 12, 0, 1, 0, 0, 0, 120, 0, 2, 0xc0, 12]);
        }
        m
    }

    /// A response whose first record's data holds a chain of 381 pointers,
    /// each to the one before, and 110 records named by its last: 110 walks
    /// of 382 steps.
    pub fn long_chain() -> Vec<u8> {
        let mut m = vec![0, 0, 0x84, 0, 0, 0, 0, 111, 0, 0, 0, 0];
        let rdlen = 3 + 2 * 381u16;
        m.extend([0, 0, 16, 0, 1, 0, 0, 0, 120]);
        m.extend(rdlen.to_be_bytes());
        let first = m.len();
        m.extend([1, b'x', 0]);
        let mut prev = first;
        for _ in 0..381 {
            let here = m.len();
            m.extend((0xc000 | prev as u16).to_be_bytes());
            prev = here;
        }
        for _ in 0..110 {
            m.extend((0xc000 | prev as u16).to_be_bytes());
            m.extend([0, 99, 0, 1, 0, 0, 0, 120, 0, 0]);
        }
        m
    }

    #[test]
    fn a_hostile_message_costs_a_few_times_a_real_one() {
        for (what, msg) in [("long names", long_names()), ("a long chain", long_chain())] {
            let each = within(std::time::Duration::from_secs(60), move || {
                cost(move |s, i| s.take(&wifi(), LEFT, &msg, i * 1000))
            });
            eprintln!("{what}: {each:?} a message");
            assert!(each <= TARGET * WORST * DEBUG, "{what}: {each:?} a message");
        }
    }
}
