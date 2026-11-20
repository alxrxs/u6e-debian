//! Each client's traffic over the last [`DAYS`] days: its volumes per hour,
//! from the byte counters its AP's snapshots carry (the radio's own count of
//! what it sent and received), and per day where they went, from the flows
//! the APs already report (the NSS connection manager's per-connection
//! bytes): no packet is looked at for it.
//!
//! A flows summary lists each client's largest connections; each one's bytes
//! since it was last listed go to its far end (address, protocol and port),
//! named by its reverse DNS when the controller has looked it up (the far
//! ends a page shows are, as those of the flows a page watches). A
//! connection first listed when it is older than the time since its AP's
//! previous summary had bytes before it was listed that the volumes counted
//! but no destination did: those stay "other", and only what it moves from
//! then on goes to its far end, so nothing counts twice. A counter that went
//! back is a new connection on the same addresses. "Other" is a day's
//! volume less what its destinations account for, never below nothing.
//!
//! Bounded: [`CLIENTS`] clients (the one heard of least recently dropped for
//! a new one), [`DAYS`] days, 24 hourly volumes a day, a day's
//! [`DESTS_KEPT`] largest destinations (the smallest dropped for a new one,
//! its bytes left to "other"), and [`CONNS`] connections' last counters
//! (forgotten after [`CONN_IDLE_MS`] unlisted, the oldest first beyond).
//! Kept in one file (`traffic_path`, 0600: it says where people go online),
//! written whole beside the old and renamed over it (`store::replace`)
//! every [`SAVE_EVERY`] when it changed and when the controller stops; a
//! file that does not decode is set aside as `<name>.corrupt-<ms>`.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs;
use std::io::{self, ErrorKind};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::time::interval;
use u6e_proto::mac;
use u6e_proto::msg::{Flows, Snapshot};

use crate::names;
use crate::sessions::unix_ms;
use crate::state::Shared;
use crate::store;

pub const DAYS: usize = 7;
pub const CLIENTS: usize = 512;
/// The destinations kept of a client's day, and those the UI shows.
pub const DESTS_KEPT: usize = 40;
pub const DESTS_SHOWN: usize = 20;
pub const CONNS: usize = 16_384;
pub const CONN_IDLE_MS: u64 = 15 * 60 * 1000;
pub const SAVE_EVERY: Duration = Duration::from_secs(300);
const HOUR_MS: u64 = 3600 * 1000;
const DAY_MS: u64 = 24 * HOUR_MS;
/// What a summary's interval is allowed to run over, the link's delays.
const SLACK_MS: u64 = 5000;
const MARK: &[u8; 4] = b"U6CT";
const FORMAT: u16 = 1;
/// The largest file read: the bounds keep it far below.
const FILE_MAX: u64 = 64 << 20;

/// Bytes a client sent (`up`) and received (`down`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bytes {
    pub up: u64,
    pub down: u64,
}

impl Bytes {
    fn add(&mut self, b: Bytes) {
        self.up = self.up.saturating_add(b.up);
        self.down = self.down.saturating_add(b.down);
    }

    fn total(self) -> u64 {
        self.up.saturating_add(self.down)
    }
}

/// A far end: its address, the IP protocol and its port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct End {
    pub ip: IpAddr,
    pub proto: u8,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dest {
    pub end: End,
    pub name: Option<String>,
    pub bytes: Bytes,
}

/// One UTC day of a client: its hourly volumes and its destinations.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Day {
    /// Days since the epoch.
    pub day: u64,
    pub hours: BTreeMap<u8, Bytes>,
    pub dests: Vec<Dest>,
}

impl Day {
    pub fn volume(&self) -> Bytes {
        let mut v = Bytes::default();
        self.hours.values().for_each(|b| v.add(*b));
        v
    }

    /// What its destinations do not account for.
    pub fn other(&self) -> Bytes {
        let (mut v, mut d) = (self.volume(), Bytes::default());
        self.dests.iter().for_each(|x| d.add(x.bytes));
        v.up = v.up.saturating_sub(d.up);
        v.down = v.down.saturating_sub(d.down);
        v
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Client {
    /// Oldest first.
    pub days: VecDeque<Day>,
    pub last_ms: u64,
}

/// One connection of one client on one AP.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ConnKey {
    ap: String,
    mac: [u8; 6],
    proto: u8,
    src: IpAddr,
    sport: u16,
    dst: IpAddr,
    dport: u16,
}

/// A connection's counters as last listed, and when.
struct Seen {
    bytes: Bytes,
    at_ms: u64,
}

#[derive(Default)]
pub struct Traffic {
    clients: HashMap<[u8; 6], Client>,
    conns: HashMap<ConnKey, Seen>,
    /// When each AP's previous summary came.
    flows_at: HashMap<String, u64>,
    pub dirty: bool,
}

/// What the file holds.
#[derive(Serialize, Deserialize)]
struct Saved {
    clients: Vec<([u8; 6], Client)>,
}

impl Traffic {
    /// The client `mac`'s day at `now_ms`, made (and the oldest client
    /// dropped beyond [`CLIENTS`], the days past [`DAYS`]) if it is new.
    fn day(&mut self, mac: [u8; 6], now_ms: u64) -> &mut Day {
        if !self.clients.contains_key(&mac) && self.clients.len() >= CLIENTS {
            let oldest = self.clients.iter().min_by_key(|(_, c)| c.last_ms);
            if let Some(m) = oldest.map(|(m, _)| *m) {
                self.clients.remove(&m);
            }
        }
        self.dirty = true;
        let c = self.clients.entry(mac).or_default();
        c.last_ms = c.last_ms.max(now_ms);
        let today = now_ms / DAY_MS;
        if c.days.back().is_none_or(|d| d.day < today) {
            c.days.push_back(Day {
                day: today,
                ..Day::default()
            });
        }
        while c.days.front().is_some_and(|d| d.day + DAYS as u64 <= today) {
            c.days.pop_front();
        }
        c.days
            .back_mut()
            .expect("today's day, just made if it was not")
    }

    /// Takes the station counters of a snapshot of an AP at `at`, its
    /// previous one at `then`: each station's bytes since then go to its
    /// client's hour.
    pub fn snapshot(&mut self, prev: &Snapshot, then: SystemTime, now: &Snapshot, at: SystemTime) {
        let at_ms = unix_ms(at);
        let gap_s = at.duration_since(then).map_or(0, |d| d.as_secs());
        for st in &now.stations {
            let bytes = match prev.stations.iter().find(|p| p.mac == st.mac) {
                Some(p) if st.rx_bytes >= p.rx_bytes && st.tx_bytes >= p.tx_bytes => Bytes {
                    up: st.rx_bytes - p.rx_bytes,
                    down: st.tx_bytes - p.tx_bytes,
                },
                // Counters that went back, or a station that associated
                // since the previous snapshot: all it counted is new.
                Some(_) => Bytes {
                    up: st.rx_bytes,
                    down: st.tx_bytes,
                },
                None if u64::from(st.connected_s) <= gap_s + SLACK_MS / 1000 => Bytes {
                    up: st.rx_bytes,
                    down: st.tx_bytes,
                },
                None => continue,
            };
            if bytes.total() == 0 {
                continue;
            }
            let hour = ((at_ms % DAY_MS) / HOUR_MS) as u8;
            self.day(st.mac, at_ms)
                .hours
                .entry(hour)
                .or_default()
                .add(bytes);
        }
    }

    /// Takes `ap`'s flows summary at `now_ms`, naming far ends by `name`.
    pub fn flows(
        &mut self,
        ap: &str,
        f: &Flows,
        now_ms: u64,
        name: impl Fn(&IpAddr) -> Option<String>,
    ) {
        let interval = self
            .flows_at
            .insert(ap.to_owned(), now_ms)
            .map(|t| now_ms.saturating_sub(t));
        for c in &f.clients {
            for fl in &c.top {
                let key = ConnKey {
                    ap: ap.to_owned(),
                    mac: c.mac,
                    proto: fl.proto,
                    src: fl.src,
                    sport: fl.sport,
                    dst: fl.dst,
                    dport: fl.dport,
                };
                let now = Bytes {
                    up: fl.tx_bytes,
                    down: fl.rx_bytes,
                };
                let new = match self.conns.get(&key) {
                    Some(s) if now.up >= s.bytes.up && now.down >= s.bytes.down => Bytes {
                        up: now.up - s.bytes.up,
                        down: now.down - s.bytes.down,
                    },
                    Some(_) => now,
                    None => match interval {
                        Some(i) if u64::from(fl.age_s) * 1000 <= i + SLACK_MS => now,
                        _ => Bytes::default(),
                    },
                };
                self.conns.insert(
                    key,
                    Seen {
                        bytes: now,
                        at_ms: now_ms,
                    },
                );
                if new.total() == 0 {
                    continue;
                }
                let ip = names::remote(fl);
                let port = if fl.client_is_src { fl.dport } else { fl.sport };
                let end = End {
                    ip,
                    proto: fl.proto,
                    port,
                };
                let named = name(&ip);
                add_dest(self.day(c.mac, now_ms), end, named, new);
            }
        }
        self.prune_conns(now_ms);
    }

    /// Forgets the connections unlisted for long, and the oldest beyond
    /// [`CONNS`].
    fn prune_conns(&mut self, now_ms: u64) {
        self.conns
            .retain(|_, s| now_ms.saturating_sub(s.at_ms) <= CONN_IDLE_MS);
        if self.conns.len() > CONNS {
            let mut ages: Vec<u64> = self.conns.values().map(|s| s.at_ms).collect();
            ages.sort_unstable();
            let cut = ages[self.conns.len() - CONNS];
            self.conns.retain(|_, s| s.at_ms >= cut);
        }
    }

    pub fn clients(&self) -> usize {
        self.clients.len()
    }

    pub fn of(&self, mac: &[u8; 6]) -> Option<&Client> {
        self.clients.get(mac)
    }

    /// The file's bytes.
    fn encode(&self) -> io::Result<Vec<u8>> {
        let saved = Saved {
            clients: self.clients.iter().map(|(m, c)| (*m, c.clone())).collect(),
        };
        let mut bytes = MARK.to_vec();
        bytes.extend_from_slice(&FORMAT.to_le_bytes());
        postcard::to_extend(&saved, bytes).map_err(io::Error::other)
    }

    /// What `path` holds; empty without the file. A file of another format,
    /// or that does not decode, is set aside (the name it was set aside
    /// under comes with the empty traffic); one that cannot be read at all
    /// is an error.
    pub fn load(path: &Path) -> io::Result<(Traffic, Option<String>)> {
        let mut bytes = Vec::new();
        match fs::File::open(path) {
            Ok(f) => {
                io::Read::read_to_end(&mut io::Read::take(f, FILE_MAX), &mut bytes)?;
            }
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok((Traffic::default(), None)),
            Err(e) => return Err(e),
        }
        let saved = match bytes.split_first_chunk::<6>() {
            Some((head, body)) if &head[..4] == MARK && head[4..] == FORMAT.to_le_bytes() => {
                postcard::from_bytes::<Saved>(body).ok()
            }
            _ => None,
        };
        let Some(saved) = saved else {
            let aside = store::set_aside(path)?;
            return Ok((Traffic::default(), Some(aside.display().to_string())));
        };
        let t = Traffic {
            clients: saved.clients.into_iter().collect(),
            ..Traffic::default()
        };
        Ok((t, None))
    }
}

/// Adds `bytes` to the far end `end` of `day`, naming it `named` when that
/// is known; a new one beyond [`DESTS_KEPT`] takes the place of the
/// smallest.
fn add_dest(day: &mut Day, end: End, named: Option<String>, bytes: Bytes) {
    if let Some(d) = day.dests.iter_mut().find(|d| d.end == end) {
        d.bytes.add(bytes);
        if named.is_some() {
            d.name = named;
        }
        return;
    }
    if day.dests.len() >= DESTS_KEPT {
        let smallest = day
            .dests
            .iter()
            .enumerate()
            .min_by_key(|(_, d)| d.bytes.total());
        if let Some(i) = smallest.map(|(i, _)| i) {
            day.dests.swap_remove(i);
        }
    }
    day.dests.push(Dest {
        end,
        name: named,
        bytes,
    });
}

/// Saves the traffic at `path` if it changed; a save that fails is tried
/// again at the next. Copied under the state's lock, written after.
pub async fn save(state: &Shared, path: &Path) {
    let bytes = {
        let mut s = state.write();
        if !s.traffic.dirty {
            return;
        }
        s.traffic.dirty = false;
        s.traffic.encode()
    };
    let path = path.to_owned();
    let written = tokio::task::spawn_blocking(move || store::replace(&path, &bytes?, 0o600))
        .await
        .map_err(|e| e.to_string())
        .and_then(|r| r.map_err(|e| e.to_string()));
    if let Err(e) = written {
        eprintln!("u6e-controller: the traffic could not be saved: {e}");
        state.write().traffic.dirty = true;
    }
}

/// Saves the traffic every [`SAVE_EVERY`], for the life of the process.
pub async fn keep(state: Shared, path: PathBuf) {
    let mut every = interval(SAVE_EVERY);
    loop {
        every.tick().await;
        save(&state, &path).await;
    }
}

/// What names a far end: its reverse DNS, as last looked up, and the
/// client whose own address it is.
pub trait Look {
    fn dns_name(&self, ip: &IpAddr) -> Option<String>;
    fn client_at(&self, ip: &IpAddr) -> Option<([u8; 6], Option<String>)>;
}

fn dest_json(end: End, name: Option<&str>, bytes: Bytes, look: &dyn Look) -> Value {
    let mut o = json!({
        "ip": end.ip.to_string(),
        "proto": end.proto,
        "port": end.port,
        "up": bytes.up,
        "down": bytes.down,
    });
    if let Some(n) = name.map(str::to_owned).or_else(|| look.dns_name(&end.ip)) {
        o["name"] = n.into();
    }
    if let Some((m, n)) = look.client_at(&end.ip) {
        o["client"] = mac::format(m).into();
        if let Some(n) = n {
            o["client_name"] = n.into();
        }
    }
    o
}

/// The far ends the view of `mac` shows: each day's largest and the
/// largest over the days.
pub fn shown(t: &Traffic, mac: &[u8; 6]) -> Vec<IpAddr> {
    let Some(c) = t.of(mac) else {
        return Vec::new();
    };
    let mut ips: Vec<IpAddr> = Vec::new();
    for d in &c.days {
        let mut dests: Vec<&Dest> = d.dests.iter().collect();
        dests.sort_by_key(|x| std::cmp::Reverse(x.bytes.total()));
        ips.extend(dests.iter().take(DESTS_SHOWN).map(|x| x.end.ip));
    }
    ips.sort_unstable();
    ips.dedup();
    ips
}

/// A far end over the days: its name, its bytes and each day's.
#[derive(Default)]
struct Over<'a> {
    name: Option<&'a str>,
    bytes: Bytes,
    days: Vec<(u64, u64)>,
}

/// The view `/api/clients/{mac}/traffic` serves: each day's hourly volumes
/// (Unix milliseconds of the hour), volume, "other" and largest
/// destinations, newest last, and the largest destinations over them all
/// with each day's bytes.
pub fn view(t: &Traffic, mac: &[u8; 6], look: &dyn Look) -> Value {
    let Some(c) = t.of(mac) else {
        return json!({ "days": [], "top": [] });
    };
    let days: Vec<Value> = (c.days.iter())
        .map(|d| {
            let mut dests: Vec<&Dest> = d.dests.iter().collect();
            dests.sort_by_key(|x| std::cmp::Reverse(x.bytes.total()));
            let hours: Vec<Value> = (d.hours.iter())
                .map(|(h, b)| json!([d.day * DAY_MS + u64::from(*h) * HOUR_MS, b.up, b.down]))
                .collect();
            let (v, o) = (d.volume(), d.other());
            json!({
                "day": d.day * DAY_MS,
                "up": v.up,
                "down": v.down,
                "other_up": o.up,
                "other_down": o.down,
                "hours": hours,
                "dests": dests.iter().take(DESTS_SHOWN)
                    .map(|x| dest_json(x.end, x.name.as_deref(), x.bytes, look))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();
    let mut all: BTreeMap<End, Over> = BTreeMap::new();
    for d in &c.days {
        for x in &d.dests {
            let e = all.entry(x.end).or_default();
            e.name = x.name.as_deref().or(e.name);
            e.bytes.add(x.bytes);
            e.days.push((d.day * DAY_MS, x.bytes.total()));
        }
    }
    let mut top: Vec<_> = all.into_iter().collect();
    top.sort_by_key(|(_, o)| std::cmp::Reverse(o.bytes.total()));
    let top: Vec<Value> = (top.into_iter().take(DESTS_SHOWN))
        .map(|(end, o)| {
            let mut v = dest_json(end, o.name, o.bytes, look);
            v["days"] = o.days.iter().map(|(d, b)| json!([d, b])).collect();
            v
        })
        .collect();
    json!({ "days": days, "top": top })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;
    use std::net::Ipv4Addr;
    use std::time::UNIX_EPOCH;
    use u6e_proto::msg::{ClientFlows, Flow, RateMode, Station};

    const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
    /// Midnight UTC, a day of the epoch.
    const T0: u64 = 20_000 * DAY_MS;

    fn far(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, last))
    }

    fn flow(last: u8, sport: u16, tx: u64, rx: u64, age_s: u32) -> Flow {
        Flow {
            proto: 6,
            src: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            sport,
            dst: far(last),
            dport: 443,
            tx_bytes: tx,
            rx_bytes: rx,
            tx_packets: 1,
            rx_packets: 1,
            offloaded: true,
            age_s,
            client_is_src: true,
        }
    }

    fn summary(flows: Vec<Flow>) -> Flows {
        Flows {
            seq: 1,
            complete: true,
            clients: vec![ClientFlows {
                mac: MAC,
                conns: flows.len() as u32,
                offloaded: 0,
                tx_bytes: 0,
                rx_bytes: 0,
                tx_packets: 0,
                rx_packets: 0,
                top: flows,
            }],
        }
    }

    fn named(ip: &IpAddr) -> Option<String> {
        (*ip == far(1)).then(|| "one.example.org".into())
    }

    fn dests(t: &Traffic) -> Vec<(u8, Bytes, Option<String>)> {
        let day = t.of(&MAC).unwrap().days.back().unwrap();
        let mut out: Vec<_> = (day.dests.iter())
            .map(|d| {
                let IpAddr::V4(v4) = d.end.ip else { panic!() };
                (v4.octets()[3], d.bytes, d.name.clone())
            })
            .collect();
        out.sort_by_key(|x| x.0);
        out
    }

    fn b(up: u64, down: u64) -> Bytes {
        Bytes { up, down }
    }

    #[test]
    fn a_connections_new_bytes_go_to_its_far_end_once() {
        let mut t = Traffic::default();
        // The first summary of an AP is only where its connections stand.
        t.flows(
            "ap1",
            &summary(vec![flow(1, 1000, 100, 1000, 5)]),
            T0,
            named,
        );
        assert!(t.of(&MAC).is_none());
        // A minute later: its bytes since, and a new connection's all.
        let next = vec![flow(1, 1000, 150, 3000, 65), flow(2, 1001, 10, 20, 30)];
        t.flows("ap1", &summary(next), T0 + 60_000, named);
        assert_eq!(
            dests(&t),
            [
                (1, b(50, 2000), Some("one.example.org".into())),
                (2, b(10, 20), None)
            ]
        );
        // A connection first listed older than the summaries' interval had
        // bytes nobody counted for it: only what it moves from now on.
        let next = vec![
            flow(1, 1000, 150, 3000, 125),
            flow(2, 1001, 10, 20, 90),
            flow(3, 1002, 7000, 9000, 600),
        ];
        t.flows("ap1", &summary(next), T0 + 120_000, named);
        let next = vec![flow(3, 1002, 7100, 9500, 660)];
        t.flows("ap1", &summary(next), T0 + 180_000, named);
        assert_eq!(dests(&t)[2], (3, b(100, 500), None));
        // Counters that went back: a new connection on the same addresses.
        t.flows(
            "ap1",
            &summary(vec![flow(3, 1002, 40, 60, 10)]),
            T0 + 240_000,
            named,
        );
        assert_eq!(dests(&t)[2], (3, b(140, 560), None));
        // The same connection on another AP (a roam) is its own.
        t.flows(
            "ap2",
            &summary(vec![flow(3, 1002, 40, 60, 10)]),
            T0 + 250_000,
            named,
        );
        t.flows(
            "ap2",
            &summary(vec![flow(3, 1002, 50, 70, 70)]),
            T0 + 310_000,
            named,
        );
        assert_eq!(dests(&t)[2], (3, b(150, 570), None));
    }

    fn station(rx: u64, tx: u64, connected_s: u32) -> Station {
        Station {
            mac: MAC,
            bss: 0,
            signal: -50,
            signal_avg: -50,
            rx_bytes: rx,
            tx_bytes: tx,
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
            tx_nss: 0,
            rx_nss: 0,
            tx_airtime_us: 0,
            rx_airtime_us: 0,
            inactive_ms: 0,
            connected_s,
            vlan: 0,
        }
    }

    fn snap(stations: Vec<Station>) -> Snapshot {
        Snapshot {
            seq: 1,
            uptime_s: 0,
            load_milli: 0,
            mem_avail_kb: 0,
            nss_load_pct: 0,
            temps: Vec::new(),
            radios: Vec::new(),
            bsss: Vec::new(),
            stations,
            config_sha256: None,
            clock_synced: true,
            power_limits: Vec::new(),
            auth: Vec::new(),
            offload_held: false,
        }
    }

    fn at(ms: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(ms)
    }

    #[test]
    fn volumes_come_from_the_station_counters_by_hour() {
        let mut t = Traffic::default();
        let s0 = snap(vec![station(1000, 5000, 600)]);
        let s1 = snap(vec![station(1500, 9000, 602)]);
        t.snapshot(&s0, at(T0 + 3_598_000), &s1, at(T0 + 3_600_000));
        // Counters that went back (a new association), in the next hour.
        let s2 = snap(vec![station(10, 20, 1)]);
        t.snapshot(&s1, at(T0 + 3_600_000), &s2, at(T0 + 3_602_000));
        let day = t.of(&MAC).unwrap().days.back().unwrap();
        assert_eq!(day.hours[&1], b(510, 4020));
        // A station that associated within the gap counts whole; one the
        // previous snapshot did not hold for longer is not counted.
        let mut t = Traffic::default();
        let empty = snap(vec![]);
        t.snapshot(
            &empty,
            at(T0),
            &snap(vec![station(30, 40, 1)]),
            at(T0 + 2000),
        );
        t.snapshot(
            &empty,
            at(T0),
            &snap(vec![station(3000, 4000, 900)]),
            at(T0 + 4000),
        );
        assert_eq!(t.of(&MAC).unwrap().days[0].volume(), b(30, 40));
    }

    #[test]
    fn other_is_what_the_destinations_leave_never_below_nothing() {
        let mut d = Day::default();
        d.hours.insert(3, b(100, 1000));
        add_dest(
            &mut d,
            End {
                ip: far(1),
                proto: 6,
                port: 443,
            },
            None,
            b(60, 1500),
        );
        assert_eq!(d.other(), b(40, 0));
    }

    #[test]
    fn days_destinations_and_clients_stay_bounded() {
        let mut t = Traffic::default();
        for day in 0..10 {
            t.day(MAC, T0 + day * DAY_MS);
        }
        let days: Vec<u64> = t.of(&MAC).unwrap().days.iter().map(|d| d.day).collect();
        assert_eq!(
            days,
            (T0 / DAY_MS + 3..T0 / DAY_MS + 10).collect::<Vec<_>>()
        );
        let mut d = Day::default();
        for i in 0..DESTS_KEPT as u64 + 5 {
            let end = End {
                ip: far(1),
                proto: 6,
                port: i as u16,
            };
            add_dest(&mut d, end, None, b(i + 100, 0));
        }
        assert_eq!(d.dests.len(), DESTS_KEPT);
        assert!(d.dests.iter().all(|x| x.bytes.up >= 105));
        for i in 0..CLIENTS as u64 + 3 {
            let m = [2, 1, 0, 0, (i >> 8) as u8, i as u8];
            t.day(m, T0 + 10 * DAY_MS + i);
        }
        assert_eq!(t.clients(), CLIENTS);
        assert!(t.of(&MAC).is_none());
        // The connections' counters: unlisted ones go, the oldest beyond
        // the cap.
        let flows: Vec<Flow> = (0..CONNS as u16 + 10)
            .map(|p| flow(1, p, 1, 1, 0))
            .collect();
        t.flows("ap1", &summary(flows), T0, named);
        assert_eq!(t.conns.len(), CONNS + 10);
        t.flows(
            "ap1",
            &summary(vec![flow(1, 1, 1, 1, 0)]),
            T0 + CONN_IDLE_MS + 1,
            named,
        );
        assert_eq!(t.conns.len(), 1);
    }

    #[test]
    fn it_is_saved_whole_and_a_corrupt_file_set_aside() {
        let dir = TestDir::new();
        let path = dir.path().join("traffic");
        let mut t = Traffic::default();
        t.flows("ap1", &summary(vec![flow(1, 1000, 0, 0, 0)]), T0, named);
        t.flows(
            "ap1",
            &summary(vec![flow(1, 1000, 10, 20, 60)]),
            T0 + 60_000,
            named,
        );
        store::replace(&path, &t.encode().unwrap(), 0o600).unwrap();
        let (back, aside) = Traffic::load(&path).unwrap();
        assert_eq!((back.clients, aside), (t.clients.clone(), None));
        fs::write(&path, b"U6CT\x01\x00garbage").unwrap();
        let (back, aside) = Traffic::load(&path).unwrap();
        assert!(back.clients.is_empty() && aside.unwrap().contains(".corrupt-"));
        assert!(
            Traffic::load(&dir.path().join("none"))
                .unwrap()
                .0
                .clients
                .is_empty()
        );
    }

    struct Lan;

    impl Look for Lan {
        fn dns_name(&self, ip: &IpAddr) -> Option<String> {
            (*ip == far(3)).then(|| "three.example.org".into())
        }

        fn client_at(&self, ip: &IpAddr) -> Option<([u8; 6], Option<String>)> {
            (*ip == far(2)).then(|| ([2, 0, 0, 0, 0, 9], Some("Speaker".into())))
        }
    }

    #[test]
    fn the_view_names_its_destinations() {
        let mut t = Traffic::default();
        t.flows("ap1", &summary(vec![]), T0, named);
        let next = vec![flow(1, 1000, 10, 2000, 30), flow(2, 1001, 500, 5, 30)];
        t.flows("ap1", &summary(next), T0 + 60_000, named);
        t.snapshot(
            &snap(vec![]),
            at(T0),
            &snap(vec![station(600, 3000, 1)]),
            at(T0 + 60_000),
        );
        let v = view(&t, &MAC, &Lan);
        let day = &v["days"][0];
        assert_eq!(
            (day["up"].as_u64(), day["down"].as_u64()),
            (Some(600), Some(3000))
        );
        assert_eq!(
            (day["other_up"].as_u64(), day["other_down"].as_u64()),
            (Some(90), Some(995))
        );
        assert_eq!(day["hours"][0][0].as_u64(), Some(T0));
        assert_eq!(day["dests"][0]["name"], "one.example.org");
        assert_eq!(v["top"][1]["client"], "02:00:00:00:00:09");
        assert_eq!(v["top"][1]["client_name"], "Speaker");
        assert_eq!(v["top"][0]["days"][0][1].as_u64(), Some(2010));
        assert_eq!(view(&t, &[2, 0, 0, 0, 0, 7], &Lan)["days"], json!([]));
    }
}
