//! A controller fed by two simulated APs, for working on the web UI without
//! hardware: the controller runs in this process, and `ap1` and `ap2` dial it
//! over the real link with the tests' throwaway keys. Each AP has three
//! radios; ten clients move about in a two-minute script that repeats (joins
//! and leaves, roams between the APs, an EAP failure, a 6 GHz radio going
//! down and up, one AP's link dropping for a while), their signals, rates,
//! traffic and connections drifting all the while.
//! The agents keep to the tick and flow cadence the controller sets, as real
//! ones do, and carry out its commands: a kicked client rejoins a few seconds
//! later, a blocked one stays away until it is unblocked, a steered one moves
//! to its target, and the thermostat (`02:00:00:00:00:06`) never answers a
//! kick, for the timeout. Each client's addresses have a DNS name, but one's.
//! The web listener adds what the sign-in proxy in front of a controller
//! would: a user, a member of the admin group unless `--viewer` is given.
//!
//!   cargo run -p u6e-controller --example replay [-- [<web address>] [--viewer]]
//!
//! The web address defaults to 127.0.0.1:8080.

mod flows;
#[path = "../../tests/common/keys.rs"]
mod keys;

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware;
use keys::{KEY_AP1, KEY_AP2, KEY_CONTROLLER};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{interval, sleep, sleep_until};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use u6e_controller::actions::{Access, GROUPS_HEADER, USER_HEADER};
use u6e_controller::agents::Timing;
use u6e_controller::config::Config;
use u6e_controller::http;
use u6e_controller::names::Resolve;
use u6e_proto::frame::{decode_frame, frame_body, write_frame};
use u6e_proto::msg::{
    AgentMsg, Band, Bss, CommandKind, CommandResult, CtlMsg, Event, EventKind, Flows, Hello, Radio,
    RateMode, Snapshot, Station, Temp,
};
use u6e_proto::tls::{self, Identity};
use u6e_proto::{PROTOCOL, delta, mac, version};

/// The script's length; it starts over after.
const CYCLE: f64 = 120.0;
const NOISE: [i8; 3] = [-92, -95, -96];
/// Airtime other networks and interference take on each band, in percent.
const FOREIGN_BUSY: [f64; 3] = [24.0, 5.0, 0.8];

/// One AP of the simulation: its radios and BSSs.
struct ApSim {
    name: &'static str,
    manifest: &'static str,
    kernel: &'static str,
    /// Uptime when the replay starts.
    booted_s: u32,
    /// Whether the image reports the radios' own temperatures.
    radio_temps: bool,
    radios: Vec<Radio>,
    events: Vec<Event>,
    /// Until when (seconds since the start) its link is down.
    away_until: f64,
}

/// (interface, SSID, radio index, VLAN), the same on both APs.
const BSSS: [(&str, &str, usize, u16); 4] = [
    ("wlan24", "ssid-b", 0, 20),
    ("wlan5", "ssid-a", 1, 10),
    ("wlan5c", "ssid-c", 1, 30),
    ("wlan6", "ssid-a", 2, 10),
];
/// The SSID that authenticates with EAP.
const EAP_SSID: &str = "ssid-a";

/// Each client's DNS name and the connections it usually keeps open, by the
/// last byte of its MAC (from 1); one has no name.
const PROFILES: [(Option<&str>, u32); 10] = [
    (Some("pixel-8.home.arpa"), 42),
    (Some("macbook-air.home.arpa"), 64),
    (Some("iphone-15.home.arpa"), 31),
    (Some("living-room-tv.home.arpa"), 18),
    (Some("galaxy-tab.home.arpa"), 26),
    (Some("thermostat.home.arpa"), 5),
    (Some("printer.home.arpa"), 7),
    (Some("workstation-with-a-rather-long-name.home.arpa"), 80),
    (Some("doorbell.home.arpa"), 9),
    (None, 22),
];
/// The reverse DNS of the clients' addresses (`flows`): their profiles' names.
struct Names;

impl Resolve for Names {
    fn reverse(&self, ip: IpAddr) -> Option<String> {
        let last = match ip {
            IpAddr::V4(v4) if v4.octets()[..3] == [192, 0, 2] => v4.octets()[3].checked_sub(10)?,
            IpAddr::V6(v6) if v6.segments()[..3] == [0x2001, 0xdb8, 0x10] => {
                u8::try_from(v6.segments()[7]).ok()?
            }
            _ => return None,
        };
        let (name, _) = PROFILES.get(usize::from(last).checked_sub(1)?)?;
        name.map(str::to_owned)
    }
}

/// The client that never answers a kick.
const SILENT: u8 = 6;
/// How long a kicked or unblocked client takes to come back, and a steered
/// one to move.
const REJOIN_S: f64 = 6.0;
const STEER_S: f64 = 3.0;

/// One simulated client: where it is, how it is heard, and its counters.
struct Client {
    last: u8,
    /// The newest PHY mode it speaks.
    phy: RateMode,
    nss: u8,
    /// Mean download while active, bit/s.
    traffic: f64,
    at: Option<(usize, usize)>,
    /// Its mean signal where it is.
    base: f64,
    phase: f64,
    since: f64,
    rx_bytes: f64,
    tx_bytes: f64,
    rx_packets: f64,
    tx_packets: f64,
    tx_retries: f64,
    tx_airtime_us: f64,
    rx_airtime_us: f64,
    idle_s: f64,
}

/// What the script does at a moment of its cycle.
#[derive(Clone, Copy)]
enum Act {
    Join(u8, usize, usize, f64),
    Leave(u8),
    EapFail(u8, usize, usize),
    RadioDown(usize, usize),
    RadioUp(usize, usize),
    /// The AP's link drops for so many seconds.
    LinkDown(usize, f64),
}

/// The script, by second of the cycle; clients by the last byte of their MAC,
/// APs and BSSs by index. A join of a client already somewhere is a roam.
const SCRIPT: [(f64, Act); 12] = [
    (20.0, Act::Join(3, 1, 1, -58.0)),
    (35.0, Act::Leave(7)),
    (50.0, Act::EapFail(10, 1, 1)),
    (53.0, Act::Join(10, 1, 1, -67.0)),
    (60.0, Act::RadioDown(1, 2)),
    (61.0, Act::Join(8, 1, 1, -61.0)),
    (75.0, Act::Join(7, 1, 0, -74.0)),
    (80.0, Act::RadioUp(1, 2)),
    (86.0, Act::Join(8, 1, 3, -56.0)),
    (95.0, Act::Join(3, 0, 1, -63.0)),
    (100.0, Act::LinkDown(1, 12.0)),
    (110.0, Act::Leave(10)),
];

struct World {
    start: Instant,
    /// Seconds since the start the counters are brought up to.
    t: f64,
    /// The cycle's start and the next step of its script.
    cycle: f64,
    step: usize,
    aps: [ApSim; 2],
    clients: Vec<Client>,
    /// The clients blocked, by MAC: they join nowhere.
    blocked: BTreeSet<[u8; 6]>,
    /// Where each client a block put off was, to go back to when unblocked.
    homes: BTreeMap<[u8; 6], (usize, usize)>,
    /// Joins the commands have set off, at seconds since the start.
    later: Vec<(f64, Act)>,
    rng: u64,
}

fn client(
    last: u8,
    phy: RateMode,
    nss: u8,
    traffic: f64,
    at: Option<(usize, usize, f64)>,
) -> Client {
    Client {
        last,
        phy,
        nss,
        traffic,
        at: at.map(|(a, b, _)| (a, b)),
        base: at.map_or(-60.0, |(.., s)| s),
        phase: f64::from(last) * 1.7,
        since: 0.0,
        rx_bytes: 0.0,
        tx_bytes: 0.0,
        rx_packets: 0.0,
        tx_packets: 0.0,
        tx_retries: 0.0,
        tx_airtime_us: 0.0,
        rx_airtime_us: 0.0,
        idle_s: 0.0,
    }
}

fn radios(channels: [(u16, u16); 3]) -> Vec<Radio> {
    let bands = [Band::B24, Band::B5, Band::B6];
    let power = [2000, 2300, 1900];
    (0..3)
        .map(|i| Radio {
            phy: format!("phy{i}"),
            band: bands[i],
            channel: channels[i].0,
            width_mhz: channels[i].1,
            txpower_mbm: power[i],
            noise_dbm: NOISE[i],
            active_ms: 0,
            busy_ms: 0,
            rx_ms: 0,
            tx_ms: 0,
            up: true,
        })
        .collect()
}

impl World {
    fn new() -> World {
        let ap = |name, manifest, kernel, booted_s, channels, radio_temps| ApSim {
            name,
            manifest,
            kernel,
            booted_s,
            radio_temps,
            radios: radios(channels),
            events: Vec::new(),
            away_until: 0.0,
        };
        let mut w = World {
            start: Instant::now(),
            t: 0.0,
            cycle: 0.0,
            step: 0,
            aps: [
                ap(
                    "ap1",
                    "image:     20261024-213000-5f0c2a1-9e1d3b7-ap1\nkernel:    5f0c2a1 kernel: thermal and spectral\nbackports: 9e1d3b7 ath11k: radio hwmon\ndebian-ap: 58e88f8 prep-rootfs: image identity\nhostapd:   2:2.10-21",
                    "6.12.57-u6e",
                    3 * 86_400 + 4_310,
                    [(6, 20), (36, 80), (37, 160)],
                    true,
                ),
                ap(
                    "ap2",
                    "image:     20261019-090500-c41d77e-2b80f15-ap2\nkernel:    c41d77e kernel: nss qdisc\nbackports: 2b80f15 ath11k: firmware 2.9\ndebian-ap: 33fe039 prep-rootfs: lone AP image\nhostapd:   2:2.10-21",
                    "6.12.52-u6e",
                    9 * 3_600 + 1_200,
                    [(1, 20), (149, 80), (69, 160)],
                    false,
                ),
            ],
            clients: vec![
                client(1, RateMode::He, 2, 60e6, Some((0, 1, -52.0))),
                client(2, RateMode::He, 2, 8e6, Some((0, 3, -58.0))),
                client(3, RateMode::He, 2, 3e6, Some((0, 1, -63.0))),
                client(4, RateMode::Vht, 2, 12e6, Some((1, 1, -60.0))),
                client(5, RateMode::He, 1, 18e6, Some((1, 2, -70.0))),
                client(6, RateMode::Ht, 1, 4e3, Some((0, 0, -71.0))),
                client(7, RateMode::Legacy, 1, 40e3, Some((1, 0, -74.0))),
                client(8, RateMode::He, 2, 90e6, Some((1, 3, -56.0))),
                client(9, RateMode::Ht, 1, 30e3, Some((0, 0, -66.0))),
                client(10, RateMode::He, 2, 2e6, None),
            ],
            blocked: BTreeSet::new(),
            homes: BTreeMap::new(),
            later: Vec::new(),
            rng: 0x9e37_79b9_7f4a_7c15,
        };
        for i in 0..w.clients.len() {
            if let Some((ap, bss)) = w.clients[i].at {
                w.announce_join(i, ap, bss);
            }
        }
        w
    }

    fn noise(&mut self) -> f64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        (self.rng % 10_000) as f64 / 10_000.0 - 0.5
    }

    fn event(&mut self, ap: usize, kind: EventKind) {
        let at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        self.aps[ap].events.push(Event { at_ms, kind });
    }

    fn mac(last: u8) -> [u8; 6] {
        [0x02, 0, 0, 0, 0, last]
    }

    fn announce_join(&mut self, i: usize, ap: usize, bss: usize) {
        let mac = World::mac(self.clients[i].last);
        let b = bss as u16;
        self.event(ap, EventKind::Assoc { mac, bss: b });
        if BSSS[bss].1 == EAP_SSID {
            self.event(ap, EventKind::EapOk { mac, bss: b });
        }
    }

    fn leave(&mut self, i: usize) {
        if let Some((ap, bss)) = self.clients[i].at.take() {
            let mac = World::mac(self.clients[i].last);
            let bss = bss as u16;
            self.event(ap, EventKind::Disassoc { mac, bss });
        }
    }

    fn act(&mut self, act: &Act) {
        let find = |w: &World, last: u8| w.clients.iter().position(|c| c.last == last);
        match *act {
            Act::Join(last, ap, bss, signal) => {
                let Some(i) = find(self, last) else { return };
                if self.blocked.contains(&World::mac(last)) {
                    return;
                }
                self.leave(i);
                let c = &mut self.clients[i];
                // A new association: the station's counters start over.
                *c = client(c.last, c.phy, c.nss, c.traffic, Some((ap, bss, signal)));
                c.since = self.t;
                self.announce_join(i, ap, bss);
            }
            Act::Leave(last) => {
                if let Some(i) = find(self, last) {
                    self.leave(i);
                }
            }
            Act::EapFail(last, ap, bss) => {
                let mac = World::mac(last);
                self.event(
                    ap,
                    EventKind::EapFail {
                        mac,
                        bss: bss as u16,
                    },
                );
            }
            Act::RadioDown(ap, radio) => {
                self.aps[ap].radios[radio].up = false;
                let phy = format!("phy{radio}");
                self.event(ap, EventKind::RadioDown { phy });
                let gone: Vec<_> = (0..self.clients.len())
                    .filter(|&i| {
                        self.clients[i]
                            .at
                            .is_some_and(|(a, b)| a == ap && BSSS[b].2 == radio)
                    })
                    .collect();
                for i in gone {
                    self.leave(i);
                }
            }
            Act::LinkDown(ap, secs) => {
                self.aps[ap].away_until = self.start.elapsed().as_secs_f64() + secs;
            }
            Act::RadioUp(ap, radio) => {
                self.aps[ap].radios[radio].up = true;
                let phy = format!("phy{radio}");
                self.event(ap, EventKind::RadioUp { phy });
            }
        }
    }

    /// Runs the script and the counters up to now.
    fn advance(&mut self) {
        let now = self.start.elapsed().as_secs_f64();
        while self.cycle + SCRIPT[self.step].0 <= now {
            let act = &SCRIPT[self.step].1;
            self.act(act);
            self.step += 1;
            if self.step == SCRIPT.len() {
                self.step = 0;
                self.cycle += CYCLE;
            }
        }
        let (due, later) = self.later.drain(..).partition(|(at, _)| *at <= now);
        self.later = later;
        for (_, act) in due {
            self.act(&act);
        }
        let dt = now - self.t;
        self.t = now;
        if dt <= 0.0 {
            return;
        }
        let mut airtime = [[(0.0, 0.0); 3]; 2];
        for i in 0..self.clients.len() {
            let wobble = self.noise();
            let burst = self.noise();
            let t = self.t;
            let c = &mut self.clients[i];
            let Some((ap, bss)) = c.at else { continue };
            let radio = BSSS[bss].2;
            let signal = c.base + 4.0 * (t / 9.0 + c.phase).sin() + 3.0 * wobble;
            // Bursts of traffic on a slow swell, quiet in between.
            let swell = ((t / 23.0 + c.phase).sin() + 1.0) / 2.0;
            let active = swell > 0.35 || burst > 0.3;
            let down = if active {
                c.traffic * (0.4 + swell + burst)
            } else {
                c.traffic * 0.002
            };
            let up = down * 0.12;
            let (tx_mbps, _, _) = rate(c.phy, c.nss, signal, radio, true);
            let (rx_mbps, _, _) = rate(c.phy, c.nss, signal, radio, false);
            let down_b = down / 8.0 * dt;
            let up_b = up / 8.0 * dt;
            c.tx_bytes += down_b;
            c.rx_bytes += up_b;
            c.tx_packets += down_b / 1200.0;
            c.rx_packets += up_b / 900.0;
            let snr = signal - f64::from(NOISE[radio]);
            let retry = (0.02 + (32.0 - snr) * 0.012).clamp(0.01, 0.35);
            c.tx_retries += down_b / 1200.0 * retry;
            let tx_us = down * dt / tx_mbps;
            let rx_us = up * dt / rx_mbps;
            c.tx_airtime_us += tx_us;
            c.rx_airtime_us += rx_us;
            c.idle_s = if active {
                0.05 + burst.abs() * 0.3
            } else {
                c.idle_s + dt
            };
            airtime[ap][radio].0 += tx_us / 1000.0;
            airtime[ap][radio].1 += rx_us / 1000.0;
        }
        for (ap, air) in airtime.iter().enumerate() {
            for (r, &(tx, rx)) in air.iter().enumerate() {
                let n = self.noise();
                let radio = &mut self.aps[ap].radios[r];
                if !radio.up {
                    continue;
                }
                let ms = dt * 1000.0;
                // Beacons and management on top of the clients' own airtime.
                let tx = tx + ms * 0.012;
                let rx = rx + ms * 0.02;
                let foreign = ms * (FOREIGN_BUSY[r] * (1.0 + n)) / 100.0;
                radio.active_ms += ms as u64;
                radio.tx_ms += tx as u64;
                radio.rx_ms += rx as u64;
                radio.busy_ms += (tx + rx + foreign).min(ms) as u64;
                radio.noise_dbm = NOISE[r] + (n * 2.4).round() as i8;
            }
        }
    }

    /// The flows of the AP's clients: each one's largest connections, or
    /// every one when `full`.
    fn flows(&mut self, ap: usize, seq: u64, full: bool) -> Flows {
        self.advance();
        let t = self.t;
        let clients = self
            .clients
            .iter()
            .filter(|c| c.at.is_some_and(|(x, _)| x == ap))
            .map(|c| {
                let traffic = flows::Traffic {
                    mac: World::mac(c.last),
                    last: c.last,
                    conns: PROFILES[usize::from(c.last) - 1].1,
                    down: c.tx_bytes,
                    up: c.rx_bytes,
                    connected_s: t - c.since,
                    t,
                };
                flows::client(&traffic, if full { usize::MAX } else { flows::TOP })
            })
            .collect();
        Flows {
            seq,
            complete: true,
            clients,
        }
    }

    /// Carries out a command on the AP as its hostapd would: its result, or
    /// `None` for one the AP never answers.
    fn command(&mut self, ap: usize, kind: &CommandKind) -> Option<(bool, String)> {
        self.advance();
        let mac = match kind {
            CommandKind::Kick { mac }
            | CommandKind::Block { mac }
            | CommandKind::Unblock { mac }
            | CommandKind::Steer { mac, .. } => *mac,
            // The list the AP's deny lists are made to hold: whoever is on
            // it and here goes.
            CommandKind::SyncBlocks { macs } => {
                self.blocked = macs.iter().copied().collect();
                let gone: Vec<usize> = (0..self.clients.len())
                    .filter(|&i| {
                        let c = &self.clients[i];
                        c.at.is_some_and(|(a, _)| a == ap)
                            && self.blocked.contains(&World::mac(c.last))
                    })
                    .collect();
                for i in gone {
                    self.leave(i);
                }
                return Some((true, "OK".into()));
            }
        };
        let i = self.clients.iter().position(|c| World::mac(c.last) == mac);
        let here = i.and_then(|i| {
            let at = self.clients[i].at.filter(|(a, _)| *a == ap)?;
            Some((i, at.1))
        });
        let ok = Some((true, "OK".to_owned()));
        match *kind {
            CommandKind::Block { .. } => {
                self.blocked.insert(mac);
                if let Some((i, bss)) = here {
                    self.homes.insert(mac, (ap, bss));
                    self.leave(i);
                }
                ok
            }
            CommandKind::Unblock { .. } => {
                // A client a block put off goes back to where it was.
                self.blocked.remove(&mac);
                if let (Some((a, b)), Some(i)) = (self.homes.remove(&mac), i) {
                    let c = &self.clients[i];
                    self.later
                        .push((self.t + REJOIN_S, Act::Join(c.last, a, b, c.base)));
                }
                ok
            }
            CommandKind::SyncBlocks { .. } => unreachable!("answered above"),
            _ if here.is_none() => Some((false, "not associated here".into())),
            CommandKind::Kick { .. } if mac[5] == SILENT => None,
            CommandKind::Kick { .. } => {
                let (i, bss) = here?;
                let c = &self.clients[i];
                let join = Act::Join(c.last, ap, bss, c.base);
                self.later.push((self.t + REJOIN_S, join));
                self.leave(i);
                ok
            }
            CommandKind::Steer { target_bssid, .. } => {
                let (i, _) = here?;
                // Only a BSS on a radio that is up is in the neighbor reports.
                let target = (0..self.aps.len()).find_map(|a| {
                    let b = (0..BSSS.len()).find(|&b| bssid(a, b) == target_bssid)?;
                    let up = self.t >= self.aps[a].away_until && self.aps[a].radios[BSSS[b].2].up;
                    up.then_some((a, b))
                });
                let Some((a, b)) = target else {
                    return Some((
                        false,
                        "unknown target BSS: not in the neighbor reports".into(),
                    ));
                };
                let c = &self.clients[i];
                let join = Act::Join(c.last, a, b, c.base + 3.0);
                self.later.push((self.t + STEER_S, join));
                ok
            }
        }
    }

    /// Whether the AP's link is down by the script.
    fn away(&mut self, ap: usize) -> bool {
        self.advance();
        self.t < self.aps[ap].away_until
    }

    fn snapshot(&mut self, ap: usize, seq: u64) -> Snapshot {
        self.advance();
        let t = self.t;
        let jitter = self.noise();
        let a = &self.aps[ap];
        let load: f64 = self
            .clients
            .iter()
            .filter(|c| c.at.is_some_and(|(x, _)| x == ap))
            .map(|c| c.traffic)
            .sum();
        let mut temps = vec![
            ("cpu-thermal", 51.0 + 2.0 * (t / 40.0).sin()),
            ("nss-top-thermal", 57.0 + 1.5 * (t / 55.0).sin()),
            ("gephy-thermal", 46.0 + (t / 70.0).sin()),
        ];
        if a.radio_temps {
            temps.extend([("phy0", 54.0), ("phy1", 63.5), ("phy2", 61.0)]);
        }
        let mut stations: Vec<Station> = self
            .clients
            .iter()
            .filter_map(|c| {
                let (x, bss) = c.at?;
                (x == ap).then(|| station(c, bss, t))
            })
            .collect();
        stations.sort_by_key(|s| s.mac);
        Snapshot {
            seq,
            uptime_s: a.booted_s + t as u32,
            load_milli: (120.0 + 90.0 * (t / 17.0).sin().abs() + 40.0 * jitter) as u32,
            mem_avail_kb: 212_000 - (t as u32 % 600) * 3,
            nss_load_pct: (2.0 + load / 12e6 + 2.0 * jitter).clamp(1.0, 60.0) as u8,
            temps: temps
                .into_iter()
                .map(|(zone, c)| Temp {
                    zone: zone.into(),
                    milli_c: (c * 1000.0 + 300.0 * jitter) as i32,
                })
                .collect(),
            radios: a.radios.clone(),
            bsss: BSSS
                .iter()
                .enumerate()
                .map(|(i, &(ifname, ssid, radio, vlan))| Bss {
                    ifname: ifname.into(),
                    bssid: bssid(ap, i),
                    ssid: ssid.into(),
                    phy: format!("phy{radio}"),
                    vlan,
                })
                .collect(),
            stations,
        }
    }
}

fn bssid(ap: usize, bss: usize) -> [u8; 6] {
    [0x02, 0, 0, 0x0a, ap as u8 + 1, bss as u8]
}

/// The rate a client is heard at: Mbit/s, MCS and mode, from its signal on
/// the radio's band and width; uplink a little slower than downlink.
fn rate(phy: RateMode, nss: u8, signal: f64, radio: usize, tx: bool) -> (f64, u8, RateMode) {
    const LEGACY: [f64; 8] = [6.0, 9.0, 12.0, 18.0, 24.0, 36.0, 48.0, 54.0];
    const HT20: [f64; 8] = [6.5, 13.0, 19.5, 26.0, 39.0, 52.0, 58.5, 65.0];
    const VHT80: [f64; 10] = [
        32.5, 65.0, 97.5, 130.0, 195.0, 260.0, 292.5, 325.0, 390.0, 433.3,
    ];
    const HE80: [f64; 12] = [
        36.0, 72.1, 108.1, 144.1, 216.2, 288.2, 324.3, 360.3, 432.4, 480.4, 540.4, 600.5,
    ];
    let width = [0.239, 1.0, 2.0][radio];
    let snr = signal - f64::from(NOISE[radio]) - if tx { 0.0 } else { 4.0 };
    let step = |n: usize| ((snr - 6.0) / 3.0).clamp(0.0, (n - 1) as f64) as usize;
    let streams = f64::from(nss);
    match phy {
        RateMode::Legacy => (LEGACY[step(8)], 0, RateMode::Legacy),
        RateMode::Ht => {
            let m = step(8);
            (
                HT20[m] * streams,
                (m + 8 * (usize::from(nss) - 1)) as u8,
                RateMode::Ht,
            )
        }
        RateMode::Vht => {
            let m = step(10);
            (VHT80[m] * streams, m as u8, RateMode::Vht)
        }
        RateMode::He => {
            let m = step(12);
            (HE80[m] * streams * width, m as u8, RateMode::He)
        }
    }
}

fn station(c: &Client, bss: usize, t: f64) -> Station {
    let radio = BSSS[bss].2;
    let signal = c.base + 4.0 * (t / 9.0 + c.phase).sin();
    let (tx, tx_mcs, tx_mode) = rate(c.phy, c.nss, signal, radio, true);
    let (rx, rx_mcs, rx_mode) = rate(c.phy, c.nss, signal, radio, false);
    let streams = |mode| match mode {
        RateMode::Vht | RateMode::He => c.nss,
        _ => 0,
    };
    Station {
        mac: World::mac(c.last),
        bss: bss as u16,
        signal: signal.round() as i8,
        signal_avg: c.base.round() as i8,
        rx_bytes: c.rx_bytes as u64,
        tx_bytes: c.tx_bytes as u64,
        rx_packets: c.rx_packets as u64,
        tx_packets: c.tx_packets as u64,
        tx_retries: c.tx_retries as u32,
        tx_failed: (c.tx_retries / 40.0) as u32,
        tx_rate_kbps: (tx * 1000.0) as u32,
        rx_rate_kbps: (rx * 1000.0) as u32,
        tx_mcs,
        rx_mcs,
        tx_mode,
        rx_mode,
        tx_nss: streams(tx_mode),
        rx_nss: streams(rx_mode),
        tx_airtime_us: c.tx_airtime_us as u64,
        rx_airtime_us: c.rx_airtime_us as u64,
        inactive_ms: (c.idle_s * 1000.0) as u32,
        connected_s: (t - c.since) as u32,
        vlan: BSSS[bss].3,
    }
}

async fn send<W: AsyncWrite + Unpin>(w: &mut W, msg: &AgentMsg) -> io::Result<()> {
    let mut out = Vec::new();
    write_frame(&mut out, msg)?;
    w.write_all(&out).await?;
    w.flush().await
}

/// One AP's agent for as long as the controller keeps it.
async fn agent(addr: SocketAddr, ap: usize, pem: &str, world: Arc<Mutex<World>>) -> io::Result<()> {
    let me = Identity::from_pem(pem).map_err(io::Error::other)?;
    let controller = Identity::from_pem(KEY_CONTROLLER).map_err(io::Error::other)?;
    let connector = TlsConnector::from(tls::client_config(&me, controller.public_key()));
    let tcp = TcpStream::connect(addr).await?;
    let name = ServerName::try_from("controller").map_err(io::Error::other)?;
    let link = connector.connect(name, tcp).await?;
    let (mut rd, mut wr) = tokio::io::split(link);
    wr.write_all(&version::frame(PROTOCOL)).await?;
    let (mut buf, mut chunk) = (Vec::new(), [0; 4096]);
    let theirs = loop {
        if let Some((body, n)) = frame_body(&buf)? {
            let v = version::decode(body);
            buf.drain(..n);
            break v;
        }
        let n = read(&mut rd, &mut chunk).await?;
        buf.extend_from_slice(&chunk[..n]);
    };
    if theirs != PROTOCOL {
        return Err(io::Error::other(format!(
            "controller speaks protocol {theirs}"
        )));
    }
    let hello = {
        let w = world.lock().unwrap_or_else(|e| e.into_inner());
        let a = &w.aps[ap];
        Hello {
            ap: a.name.into(),
            manifest: a.manifest.into(),
            kernel: a.kernel.into(),
            hostapd: "2:2.10-21".into(),
            agent: env!("CARGO_PKG_VERSION").into(),
        }
    };
    send(&mut wr, &AgentMsg::Hello(hello)).await?;

    let mut tick = Duration::from_secs(15);
    let mut next = tokio::time::Instant::now();
    let mut cadence = Duration::from_secs(60);
    let mut next_flows = next;
    let mut events = interval(Duration::from_millis(250));
    let (mut seq, mut last, mut want_key) = (0, None::<Snapshot>, true);
    let mut flows_seq = 0;
    let flows = |seq: &mut u64, full| {
        *seq += 1;
        let mut w = world.lock().unwrap_or_else(|e| e.into_inner());
        AgentMsg::Flows(w.flows(ap, *seq, full))
    };
    loop {
        // What came with the version frame too.
        while let Some((msg, used)) = decode_frame::<CtlMsg>(&buf)? {
            buf.drain(..used);
            match msg {
                CtlMsg::SetTick { secs } => {
                    tick = Duration::from_secs(secs.into());
                    next = tokio::time::Instant::now();
                }
                CtlMsg::WantKey => want_key = true,
                CtlMsg::Ping(n) => send(&mut wr, &AgentMsg::Pong(n)).await?,
                CtlMsg::FlowCadence { secs } => {
                    cadence = Duration::from_secs(secs.into());
                    next_flows = tokio::time::Instant::now();
                }
                CtlMsg::WantFlows { full } => send(&mut wr, &flows(&mut flows_seq, full)).await?,
                CtlMsg::Command(cmd) => {
                    let done = world
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .command(ap, &cmd.kind);
                    if let Some((ok, detail)) = done {
                        let r = CommandResult {
                            id: cmd.id,
                            ok,
                            detail,
                        };
                        send(&mut wr, &AgentMsg::Result(r)).await?;
                    }
                }
                _ => {}
            }
        }
        tokio::select! {
            () = sleep_until(next) => {
                if world.lock().unwrap_or_else(|e| e.into_inner()).away(ap) {
                    return Err(io::Error::other("link down by the script"));
                }
                seq += 1;
                let snap = world.lock().unwrap_or_else(|e| e.into_inner()).snapshot(ap, seq);
                let msg = match (&last, want_key) {
                    (Some(prev), false) => delta::diff(prev, &snap).map(AgentMsg::Delta),
                    _ => None,
                };
                send(&mut wr, &msg.unwrap_or_else(|| AgentMsg::Key(snap.clone()))).await?;
                (last, want_key) = (Some(snap), false);
                next += tick;
            }
            () = sleep_until(next_flows) => {
                send(&mut wr, &flows(&mut flows_seq, false)).await?;
                next_flows += cadence;
            }
            _ = events.tick() => {
                let due = {
                    let mut w = world.lock().unwrap_or_else(|e| e.into_inner());
                    w.advance();
                    std::mem::take(&mut w.aps[ap].events)
                };
                for ev in due {
                    send(&mut wr, &AgentMsg::Event(ev)).await?;
                }
            }
            n = read(&mut rd, &mut chunk) => buf.extend_from_slice(&chunk[..n?]),
        }
    }
}

async fn read<R: AsyncRead + Unpin>(r: &mut R, chunk: &mut [u8]) -> io::Result<usize> {
    match r.read(chunk).await? {
        0 => Err(io::ErrorKind::UnexpectedEof.into()),
        n => Ok(n),
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let admin = !args.iter().any(|a| a == "--viewer");
    let web = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .map_or("127.0.0.1:8080", String::as_str);
    let public = |pem| Identity::from_pem(pem).map(|i| mac::hex(&i.public_key()));
    // The actions' decisions, kept for the next replay like a controller's.
    let policy = std::env::temp_dir().join("u6e-replay-policy.json");
    // The controller's own web listener goes unused: the one below is its
    // router behind what the sign-in proxy adds.
    let config = format!(
        "listen_agents = \"127.0.0.1:0\"\nlisten_http = \"127.0.0.1:0\"\nlisten_metrics = \"127.0.0.1:0\"\n\
         public_origin = \"http://{web}\"\npolicy_path = \"{}\"\n\
         [aps.ap1]\npublic_key = \"{}\"\n[aps.ap2]\npublic_key = \"{}\"\n",
        policy.display(),
        public(KEY_AP1).map_err(io::Error::other)?,
        public(KEY_AP2).map_err(io::Error::other)?,
    );
    let config = Config::parse(&config).map_err(io::Error::other)?;
    let identity = Identity::from_pem(KEY_CONTROLLER).map_err(io::Error::other)?;
    let timing = Timing::default();
    let c = u6e_controller::start(&config, &identity, timing, Arc::new(Names)).await?;
    let user = HeaderValue::from_static(if admin { "operator" } else { "viewer" });
    let groups = HeaderValue::from_str(&config.admin_group).map_err(io::Error::other)?;
    let signed_in = move |mut req: Request| {
        let h = req.headers_mut();
        h.insert(USER_HEADER, user.clone());
        if admin {
            h.insert(GROUPS_HEADER, groups.clone());
        } else {
            h.remove(GROUPS_HEADER);
        }
        async move { req }
    };
    let web_router = http::router(c.state.clone(), Access::new(&config, timing.command))
        .layer(middleware::map_request(signed_in));
    let listener = tokio::net::TcpListener::bind(web).await?;
    eprintln!(
        "replay: the UI is on http://{}/, its user {}",
        listener.local_addr()?,
        if admin { "an admin" } else { "not an admin" }
    );
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, web_router).await {
            eprintln!("replay: web listener: {e}");
        }
    });
    let world = Arc::new(Mutex::new(World::new()));
    for (ap, pem) in [KEY_AP1, KEY_AP2].into_iter().enumerate() {
        let world = Arc::clone(&world);
        tokio::spawn(async move {
            // An AP that drops reconnects, as the real agent does.
            loop {
                while world.lock().unwrap_or_else(|e| e.into_inner()).away(ap) {
                    sleep(Duration::from_secs(1)).await;
                }
                if let Err(e) = agent(c.agents, ap, pem, Arc::clone(&world)).await {
                    eprintln!("replay: ap{}: {e}", ap + 1);
                }
                sleep(Duration::from_secs(1)).await;
            }
        });
    }
    std::future::pending().await
}
