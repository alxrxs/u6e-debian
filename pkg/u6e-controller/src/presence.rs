//! Presence events to Home Assistant (`[presence]`): for each device the
//! configuration lists, by MAC and a name of Home Assistant's kind, an event
//! `wifi_presence` when it joins the Wi-Fi and when it has left it.
//!
//! A device is home while it has an open session on any AP (`sessions`),
//! and away once its last session has been closed for `leave_after` (5
//! minutes unless set): a roam (one session closing as the next opens) and
//! a leave and join within that time announce nothing, and an AP whose link
//! is down keeps its sessions open until it is heard again or for an hour,
//! so an AP the controller cannot hear is not a house everyone left. The
//! state the sessions give at start is taken as already announced, so a
//! restart announces nothing.
//!
//! Each change is its device's one pending event: a newer change replaces
//! it, one that undoes it cancels it. [`supervise`] looks every second and
//! sends what is pending, one request at a time over HTTPS
//! (`fetch::post_json_tls`, the token read from its file at each request,
//! the CA bundle at each connection), backing off from 2 s to a minute
//! while Home Assistant fails, dropping an event not delivered within
//! [`STALE`] of its change, and stopping at a 401 or 403 until the token
//! file changes, so a refused token does not get the controller's address
//! banned. Nothing waits for any of it: Home Assistant away costs the
//! presence events and nothing else. Each event delivered or dropped is an
//! action `presence` on its device (its timeline).

use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use aws_lc_rs::digest;
use serde_json::{Value, json};
use tokio::time::interval;
use u6e_proto::mac;

use crate::fetch;
use crate::sessions::{Sessions, unix_ms};
use crate::state::{Action, Change, Shared};
use crate::timeline::Place;
use crate::view;

/// The event Home Assistant is sent.
pub const EVENT: &str = "wifi_presence";
/// An event not delivered this long after its change is dropped.
pub const STALE: Duration = Duration::from_secs(300);
/// The longest one request may take.
const REQUEST_WAIT: Duration = Duration::from_secs(10);
/// The waits after a failed request.
const BACKOFF_MIN: Duration = Duration::from_secs(2);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// The largest token file read.
const TOKEN_MAX: u64 = 4096;
/// The most devices listed.
pub const DEVICES_MAX: usize = 64;

/// `[presence]`, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Home Assistant's host and port (`https://host[:port]`).
    pub host: String,
    pub port: u16,
    /// The PEM bundle its certificate's chain is checked against.
    pub ca: PathBuf,
    /// The file of its long-lived access token.
    pub token: PathBuf,
    pub leave_after: Duration,
    /// The devices, each by MAC and name.
    pub devices: Vec<([u8; 6], String)>,
}

/// What Home Assistant was told of a device, and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Told {
    pub home: bool,
    pub at: SystemTime,
}

/// An event waiting to be delivered.
#[derive(Debug, Clone, PartialEq)]
pub struct Pending {
    pub home: bool,
    /// When the change came.
    pub at: SystemTime,
    pub body: Value,
    /// Why the last try failed.
    pub why: Option<String>,
    /// Told apart from a later one that replaced it.
    generation: u64,
}

/// One listed device.
#[derive(Debug, Clone, PartialEq)]
pub struct Device {
    pub mac: [u8; 6],
    pub name: String,
    /// Home or away as last decided, and since when; `None` before the
    /// first look.
    pub home: Option<bool>,
    pub since_ms: u64,
    /// Where it joined, or was last.
    pub place: Option<Place>,
    pub last_seen_ms: Option<u64>,
    /// Whether it had a session open at the last look, and when its last
    /// session ended while it has none.
    open: bool,
    gone_ms: Option<u64>,
    pub told: Option<Told>,
    pub pending: Option<Pending>,
}

/// Every listed device and how their events go.
#[derive(Debug)]
pub struct Presence {
    pub devices: Vec<Device>,
    leave_after_ms: u64,
    /// The first look announces nothing.
    looked: bool,
    next_generation: u64,
    /// Events by result, for the metrics.
    pub delivered: u64,
    pub dropped: u64,
    pub last_delivery: Option<SystemTime>,
    /// The hash of the token Home Assistant refused, while it is the file's.
    pub refused: Option<[u8; 32]>,
    backoff: Duration,
    next_try: Option<Instant>,
}

impl Presence {
    pub fn new(settings: &Settings) -> Self {
        let devices = settings.devices.iter().map(|(mac, name)| Device {
            mac: *mac,
            name: name.clone(),
            home: None,
            since_ms: 0,
            place: None,
            last_seen_ms: None,
            open: false,
            gone_ms: None,
            told: None,
            pending: None,
        });
        Presence {
            devices: devices.collect(),
            leave_after_ms: settings.leave_after.as_millis() as u64,
            looked: false,
            next_generation: 0,
            delivered: 0,
            dropped: 0,
            last_delivery: None,
            refused: None,
            backoff: BACKOFF_MIN,
            next_try: None,
        }
    }

    /// Looks at the sessions at `now_ms`; whether a device changed.
    pub fn tick(&mut self, now_ms: u64, sessions: &Sessions) -> bool {
        let first = !std::mem::replace(&mut self.looked, true);
        let mut changed = false;
        for d in &mut self.devices {
            let home = match sessions.open_of(&d.mac) {
                Some(s) => {
                    d.place = Some(s.place.clone());
                    d.last_seen_ms = Some(s.last_ms);
                    d.open = true;
                    d.gone_ms = None;
                    if d.home != Some(true) {
                        d.since_ms = s.start_ms;
                    }
                    true
                }
                None => {
                    // Its last session is looked up once, when it ends.
                    if std::mem::replace(&mut d.open, false) || first {
                        let last = sessions.of(&d.mac).next();
                        d.gone_ms = last.and_then(|s| s.end_ms);
                        if let Some(s) = last {
                            d.place = Some(s.place.clone());
                            d.last_seen_ms = Some(s.last_ms);
                        }
                    }
                    match d.gone_ms {
                        Some(gone) if now_ms.saturating_sub(gone) < self.leave_after_ms => {
                            // Not gone long enough: as it was.
                            d.home.unwrap_or(true)
                        }
                        Some(gone) => {
                            if d.home != Some(false) {
                                d.since_ms = gone;
                            }
                            false
                        }
                        None => false,
                    }
                }
            };
            if d.home == Some(home) {
                continue;
            }
            d.home = Some(home);
            changed = true;
            if first {
                d.told = Some(Told {
                    home,
                    at: SystemTime::now(),
                });
                continue;
            }
            if d.told.is_some_and(|t| t.home == home) {
                d.pending = None;
                continue;
            }
            self.next_generation += 1;
            d.pending = Some(Pending {
                home,
                at: SystemTime::now(),
                body: event(d, home),
                why: None,
                generation: self.next_generation,
            });
        }
        changed
    }

    /// The pending events to try now, each by its device and generation,
    /// and the events dropped as stale.
    fn due(&mut self, now: Instant) -> (Vec<Try>, Vec<Device>) {
        let mut dropped = Vec::new();
        for d in &mut self.devices {
            let stale = d
                .pending
                .as_ref()
                .is_some_and(|p| p.at.elapsed().unwrap_or_default() > STALE);
            if stale {
                dropped.push(d.clone());
                d.pending = None;
                // What Home Assistant holds is not known now.
                d.told = None;
                self.dropped += 1;
            }
        }
        if self.next_try.is_some_and(|t| now < t) {
            return (Vec::new(), dropped);
        }
        let tries = self.devices.iter().filter_map(|d| {
            let p = d.pending.as_ref()?;
            Some(Try {
                mac: d.mac,
                generation: p.generation,
                body: p.body.to_string(),
            })
        });
        (tries.collect(), dropped)
    }

    /// Takes what came of a try.
    fn tried(&mut self, t: &Try, outcome: &Outcome, now: Instant) -> Option<Device> {
        match outcome {
            Outcome::Delivered => {
                self.backoff = BACKOFF_MIN;
                self.next_try = None;
            }
            Outcome::Failed(_) | Outcome::Refused(_) => {
                self.next_try = Some(now + self.backoff);
                self.backoff = (self.backoff * 2).min(BACKOFF_MAX);
            }
        }
        let d = self.devices.iter_mut().find(|d| d.mac == t.mac)?;
        let p = d
            .pending
            .as_mut()
            .filter(|p| p.generation == t.generation)?;
        match outcome {
            Outcome::Delivered => {
                d.told = Some(Told {
                    home: p.home,
                    at: SystemTime::now(),
                });
                d.pending = None;
                self.delivered += 1;
                self.last_delivery = Some(SystemTime::now());
                Some(d.clone())
            }
            Outcome::Failed(why) | Outcome::Refused(why) => {
                p.why = Some(why.clone());
                None
            }
        }
    }
}

/// The event's data for `d` becoming `home`.
fn event(d: &Device, home: bool) -> Value {
    let p = d.place.as_ref();
    json!({
        "device": d.name,
        "mac": mac::format(d.mac),
        "state": if home { "home" } else { "not_home" },
        "ap": p.map(|p| p.ap.clone()),
        "band": p.and_then(|p| p.band).map(view::band),
        "ssid": p.map(|p| p.ssid.clone()),
        "last_seen": d.last_seen_ms.map(|ms| ms / 1000),
    })
}

/// One event to send.
#[derive(Debug)]
struct Try {
    mac: [u8; 6],
    generation: u64,
    body: String,
}

#[derive(Debug)]
enum Outcome {
    Delivered,
    /// Home Assistant refused the token (401, 403).
    Refused(String),
    Failed(String),
}

/// The token, trimmed, and its hash; why not.
fn token(path: &std::path::Path) -> Result<(String, [u8; 32]), String> {
    use std::io::Read;
    let mut text = String::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(TOKEN_MAX).read_to_string(&mut text))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let t = text.trim().to_owned();
    // SAFETY: zeros are valid UTF-8, and the text is not read after.
    u6e_proto::frame::zeroize(unsafe { text.as_mut_vec() });
    if t.is_empty() || t.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!("{}: no token", path.display()));
    }
    let hash = digest::digest(&digest::SHA256, t.as_bytes());
    let hash = hash.as_ref().try_into().expect("SHA-256 is 32 bytes");
    Ok((t, hash))
}

/// What one request came to.
async fn send(settings: &Settings, token: &str, body: &str) -> Outcome {
    let target = format!("/api/events/{EVENT}");
    let host = (settings.host.as_str(), settings.port);
    match fetch::post_json_tls(host, &target, &settings.ca, token, body, REQUEST_WAIT).await {
        Ok(s) if (200..300).contains(&s) => Outcome::Delivered,
        Ok(s @ (401 | 403)) => Outcome::Refused(format!("Home Assistant refused the token ({s})")),
        Ok(s) => Outcome::Failed(format!("Home Assistant answered {s}")),
        Err(e) => Outcome::Failed(e),
    }
}

/// Records an event delivered or dropped (`d` as it was with it pending)
/// as an action on its device.
fn record(state: &mut crate::state::State, d: &Device, ok: bool) {
    let home = d.pending.as_ref().map(|p| p.home);
    let home = home.or(d.told.map(|t| t.home)).unwrap_or(false);
    let word = if home { "home" } else { "not home" };
    let detail = if ok {
        format!("{word}: Home Assistant was told ({})", d.name)
    } else {
        let why = d.pending.as_ref().and_then(|p| p.why.clone());
        format!(
            "{word}: not delivered in {} min, dropped ({})",
            STALE.as_secs() / 60,
            why.unwrap_or_else(|| "not tried".into())
        )
    };
    state.record(Action {
        at: SystemTime::now(),
        user: None,
        action: "presence",
        mac: Some(d.mac),
        ap: d.place.as_ref().map(|p| p.ap.clone()),
        ok,
        detail,
    });
}

/// Looks at the devices every second and sends their events, for the life
/// of the process.
pub async fn supervise(state: Shared, settings: Settings) {
    let mut every = interval(Duration::from_secs(1));
    loop {
        every.tick().await;
        let tries = {
            let mut s = state.write();
            let s = &mut *s;
            let Some(p) = s.presence.as_mut() else { return };
            let changed = p.tick(unix_ms(SystemTime::now()), &s.sessions);
            let (tries, dropped) = p.due(Instant::now());
            for d in &dropped {
                record(s, d, false);
            }
            if changed || !dropped.is_empty() {
                s.notify(Change::Presence);
            }
            tries
        };
        if tries.is_empty() {
            continue;
        }
        let (token, hash) = match token(&settings.token) {
            Ok(t) => t,
            Err(why) => {
                fail_all(&state, &tries, &why);
                continue;
            }
        };
        let refused = state.read().presence.as_ref().and_then(|p| p.refused);
        if refused == Some(hash) {
            continue;
        }
        for t in &tries {
            let outcome = send(&settings, &token, &t.body).await;
            let mut s = state.write();
            let s = &mut *s;
            let Some(p) = s.presence.as_mut() else { return };
            // Each outage and each refusal is logged once, at its start.
            match &outcome {
                Outcome::Refused(why) => {
                    if p.refused.replace(hash).is_none() {
                        eprintln!(
                            "u6e-controller: presence: {why}; no event goes until the token changes"
                        );
                    }
                }
                Outcome::Failed(why) => {
                    if p.next_try.is_none() {
                        eprintln!("u6e-controller: presence: {why}; trying again");
                    }
                    p.refused = None;
                }
                Outcome::Delivered => p.refused = None,
            }
            let delivered = p.tried(t, &outcome, Instant::now());
            if let Some(d) = &delivered {
                record(s, d, true);
            }
            s.notify(Change::Presence);
            if !matches!(outcome, Outcome::Delivered) {
                break;
            }
        }
    }
}

/// Marks every try as failed for `why` (no request was made).
fn fail_all(state: &Shared, tries: &[Try], why: &str) {
    let mut s = state.write();
    let Some(p) = s.presence.as_mut() else { return };
    for t in tries {
        p.tried(t, &Outcome::Failed(why.to_owned()), Instant::now());
    }
}

/// The live view's presence: each device's state, where, and what Home
/// Assistant was told or is to be.
pub fn view(p: &Presence) -> Value {
    let devices: serde_json::Map<String, Value> = p
        .devices
        .iter()
        .map(|d| {
            let mut v = json!({
                "name": d.name,
                "state": match d.home {
                    Some(true) => "home",
                    Some(false) => "away",
                    None => "unknown",
                },
                "since": d.since_ms,
            });
            if let Some(pl) = &d.place {
                v["ap"] = pl.ap.clone().into();
                v["band"] = pl.band.map(view::band).into();
                v["ssid"] = pl.ssid.clone().into();
            }
            if let Some(ms) = d.last_seen_ms {
                v["last_seen"] = ms.into();
            }
            if let Some(t) = d.told {
                v["told"] = json!({ "home": t.home, "at": unix_ms(t.at) });
            }
            if let Some(pe) = &d.pending {
                v["pending"] = json!({ "home": pe.home, "at": unix_ms(pe.at), "why": pe.why });
            }
            (mac::format(d.mac), v)
        })
        .collect();
    json!({ "devices": devices, "refused": p.refused.is_some() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::pki_types::pem::PemObject;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio_rustls::rustls::{ServerConfig, crypto, version};
    use u6e_proto::msg::{Band, Bss, Event, EventKind};

    use crate::state::{Naming, State};
    use crate::testdir::TestDir;

    const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const T0: u64 = 1_800_000_000_000;
    const MIN: u64 = 60_000;
    /// The test certificates (tests/fixtures/tls): a CA, a server
    /// certificate for 127.0.0.1, one for another name, one of another CA.
    const TLS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls");

    fn naming() -> Naming {
        Naming {
            bsss: vec![Bss {
                ifname: "wlan5".into(),
                bssid: [2, 0, 0, 0, 0x10, 1],
                ssid: "ssid-a".into(),
                phy: "phy1".into(),
                vlan: 10,
            }],
            bands: vec![("phy1".into(), Band::B5)],
        }
    }

    fn ev(s: &mut Sessions, ap: &str, at: u64, assoc: bool) {
        let kind = if assoc {
            EventKind::Assoc { mac: MAC, bss: 0 }
        } else {
            EventKind::Disassoc { mac: MAC, bss: 0 }
        };
        s.event(ap, &naming(), &Event { at_ms: at, kind }, at);
    }

    fn settings(dir: &std::path::Path, port: u16) -> Settings {
        Settings {
            host: "127.0.0.1".into(),
            port,
            ca: format!("{TLS}/ca.pem").into(),
            token: dir.join("token"),
            leave_after: Duration::from_secs(300),
            devices: vec![(MAC, "phone_alice".into())],
        }
    }

    fn pending(p: &Presence) -> Option<(bool, Value)> {
        let d = &p.devices[0];
        d.pending.as_ref().map(|p| (p.home, p.body.clone()))
    }

    /// Delivers what is pending, as a request Home Assistant took would.
    fn deliver(p: &mut Presence) {
        let (tries, _) = p.due(Instant::now());
        for t in &tries {
            p.tried(t, &Outcome::Delivered, Instant::now());
        }
    }

    #[test]
    fn a_join_and_a_leave_are_announced_but_not_a_roam_or_a_short_gap() {
        let dir = TestDir::new();
        let mut p = Presence::new(&settings(dir.path(), 1));
        let mut s = Sessions::default();
        // The first look announces nothing: the device is away.
        assert!(p.tick(T0, &s));
        assert_eq!((p.devices[0].home, pending(&p)), (Some(false), None));
        ev(&mut s, "ap1", T0 + MIN, true);
        p.tick(T0 + MIN, &s);
        let (home, body) = pending(&p).unwrap();
        assert!(home);
        assert_eq!(
            body,
            json!({"device": "phone_alice", "mac": "02:00:00:00:00:01", "state": "home",
                   "ap": "ap1", "band": "5", "ssid": "ssid-a", "last_seen": (T0 + MIN) / 1000})
        );
        deliver(&mut p);
        assert_eq!(p.devices[0].told.map(|t| t.home), Some(true));
        // A roam to ap2, then a 4-minute gap: nothing.
        ev(&mut s, "ap2", T0 + 2 * MIN, true);
        ev(&mut s, "ap1", T0 + 2 * MIN + 2000, false);
        assert!(!p.tick(T0 + 3 * MIN, &s));
        ev(&mut s, "ap2", T0 + 3 * MIN, false);
        assert!(!p.tick(T0 + 7 * MIN - 1, &s));
        ev(&mut s, "ap1", T0 + 7 * MIN, true);
        assert!(!p.tick(T0 + 7 * MIN, &s));
        assert_eq!(pending(&p), None);
        // Gone 5 minutes: it left, last seen on ap1.
        ev(&mut s, "ap1", T0 + 8 * MIN, false);
        assert!(!p.tick(T0 + 13 * MIN - 1, &s));
        assert!(p.tick(T0 + 13 * MIN, &s));
        let (home, body) = pending(&p).unwrap();
        assert!(!home);
        assert_eq!(
            (&body["state"], &body["ap"]),
            (&json!("not_home"), &json!("ap1"))
        );
        assert_eq!(p.devices[0].since_ms, T0 + 8 * MIN);
    }

    #[test]
    fn a_restart_with_the_device_on_announces_nothing() {
        let dir = TestDir::new();
        let mut s = Sessions::default();
        ev(&mut s, "ap1", T0, true);
        let mut p = Presence::new(&settings(dir.path(), 1));
        assert!(p.tick(T0 + MIN, &s));
        assert_eq!((p.devices[0].home, pending(&p)), (Some(true), None));
        assert!(!p.tick(T0 + 2 * MIN, &s));
        // Gone within its leave time before the restart: home until then.
        ev(&mut s, "ap1", T0 + 3 * MIN, false);
        let mut p = Presence::new(&settings(dir.path(), 1));
        p.tick(T0 + 4 * MIN, &s);
        assert_eq!((p.devices[0].home, pending(&p)), (Some(true), None));
        p.tick(T0 + 8 * MIN, &s);
        assert_eq!(pending(&p).map(|p| p.0), Some(false));
    }

    #[test]
    fn an_ap_unheard_for_an_hour_is_a_leave_once_its_sessions_end() {
        let dir = TestDir::new();
        let mut p = Presence::new(&settings(dir.path(), 1));
        let mut s = Sessions::default();
        p.tick(T0, &s);
        ev(&mut s, "ap1", T0, true);
        p.tick(T0, &s);
        deliver(&mut p);
        // Its AP's link is down: the session stays open, the device home.
        s.tick(T0 + 30 * MIN, |_| false);
        assert!(!p.tick(T0 + 30 * MIN, &s));
        s.tick(T0 + 61 * MIN, |_| false);
        assert!(p.tick(T0 + 61 * MIN, &s));
        assert_eq!(pending(&p).map(|p| p.0), Some(false));
    }

    #[test]
    fn a_change_undone_before_it_was_delivered_is_not_sent() {
        let dir = TestDir::new();
        let mut p = Presence::new(&settings(dir.path(), 1));
        let mut s = Sessions::default();
        ev(&mut s, "ap1", T0, true);
        p.tick(T0, &s);
        ev(&mut s, "ap1", T0 + MIN, false);
        p.tick(T0 + 6 * MIN, &s);
        assert_eq!(pending(&p).map(|p| p.0), Some(false));
        ev(&mut s, "ap1", T0 + 7 * MIN, true);
        p.tick(T0 + 7 * MIN, &s);
        assert_eq!(pending(&p), None);
        // One left undelivered for 5 minutes is dropped, and then what
        // Home Assistant holds is not known.
        ev(&mut s, "ap1", T0 + 8 * MIN, false);
        p.tick(T0 + 13 * MIN, &s);
        p.devices[0].pending.as_mut().unwrap().at -= STALE + Duration::from_secs(1);
        let (tries, dropped) = p.due(Instant::now());
        assert!(tries.is_empty());
        assert_eq!(dropped.len(), 1);
        assert_eq!((p.dropped, p.devices[0].told), (1, None));
    }

    #[derive(Debug, Clone)]
    struct Request {
        head: String,
        body: String,
    }

    /// A Home Assistant on loopback serving `cert`, answering each request
    /// with the next of `answers` (the last one again once they run out);
    /// the requests it took.
    async fn fake_ha(cert: &str, answers: Vec<u16>) -> (SocketAddr, Arc<Mutex<Vec<Request>>>) {
        let certs = CertificateDer::pem_file_iter(format!("{TLS}/{cert}.pem"))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_file(format!("{TLS}/{cert}.key")).unwrap();
        let config =
            ServerConfig::builder_with_provider(Arc::new(crypto::aws_lc_rs::default_provider()))
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        tokio::spawn(async move {
            let mut answers = answers.into_iter().peekable();
            loop {
                let (sock, _) = listener.accept().await.unwrap();
                let Ok(mut tls) = acceptor.accept(sock).await else {
                    continue;
                };
                let mut got = Vec::new();
                let mut chunk = [0; 4096];
                let (head, body) = loop {
                    let n = tls.read(&mut chunk).await.unwrap();
                    got.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&got).into_owned();
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let len = head
                            .lines()
                            .find_map(|l| l.strip_prefix("Content-Length: "))
                            .map_or(0, |v| v.parse().unwrap());
                        if body.len() >= len {
                            break (head.to_owned(), body.to_owned());
                        }
                    }
                };
                log.lock().unwrap().push(Request { head, body });
                let status = if answers.len() > 1 {
                    answers.next().unwrap()
                } else {
                    *answers.peek().unwrap()
                };
                let reply = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                tls.write_all(reply.as_bytes()).await.unwrap();
                let _ = tls.shutdown().await;
            }
        });
        (addr, seen)
    }

    async fn post(cert: &str) -> Result<u16, String> {
        let (addr, _) = fake_ha(cert, vec![200]).await;
        let ca = std::path::PathBuf::from(format!("{TLS}/ca.pem"));
        let host = ("127.0.0.1", addr.port());
        fetch::post_json_tls(host, "/x", &ca, "tok", "{}", Duration::from_secs(5)).await
    }

    #[tokio::test]
    async fn only_a_server_the_bundle_vouches_for_by_its_name_is_sent_to() {
        assert_eq!(post("server").await, Ok(200));
        let e = post("other-name").await.unwrap_err();
        assert!(
            e.contains("certificate not valid for name \"127.0.0.1\""),
            "{e}"
        );
        let e = post("other-ca").await.unwrap_err();
        assert!(e.contains("UnknownIssuer"), "{e}");
        // A server that speaks no TLS.
        let plain = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = plain.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = plain.accept().await.unwrap();
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
        });
        let ca = std::path::PathBuf::from(format!("{TLS}/ca.pem"));
        let host = ("127.0.0.1", port);
        let e = fetch::post_json_tls(host, "/x", &ca, "tok", "{}", Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(e.starts_with("TLS: "), "{e}");
        // A bundle with nothing to trust.
        let dir = TestDir::new();
        std::fs::write(dir.path().join("empty.pem"), "").unwrap();
        let e = fetch::tls_client(&dir.path().join("empty.pem")).unwrap_err();
        assert!(e.ends_with("no certificate to trust"), "{e}");
    }

    /// A state with ap1 and the device listed, its presence sent to `port`
    /// with the token in `dir`.
    fn shared(dir: &std::path::Path, port: u16) -> (Shared, Settings) {
        let set = settings(dir, port);
        let state = State::new([("ap1".to_owned(), "ap1".to_owned())]).with_presence(&set);
        (Shared::new(state), set)
    }

    fn join(state: &Shared) {
        let now = unix_ms(SystemTime::now());
        let mut s = state.write();
        ev(&mut s.sessions, "ap1", now, true);
    }

    async fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
        let start = Instant::now();
        while !cond() {
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "timed out waiting for {what}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn an_event_is_posted_with_the_token_and_retried_until_taken() {
        let dir = TestDir::new();
        std::fs::write(dir.path().join("token"), "tok-1\n").unwrap();
        let (addr, seen) = fake_ha("server", vec![500, 200]).await;
        let (state, set) = shared(dir.path(), addr.port());
        tokio::spawn(supervise(state.clone(), set));
        wait_for("the first look", || {
            state.read().presence.as_ref().unwrap().devices[0]
                .home
                .is_some()
        })
        .await;
        join(&state);
        wait_for("the event delivered", || {
            state.read().presence.as_ref().unwrap().delivered == 1
        })
        .await;
        let reqs = seen.lock().unwrap().clone();
        assert_eq!(reqs.len(), 2, "one 500, then the retry");
        let head = &reqs[1].head;
        assert!(
            head.starts_with("POST /api/events/wifi_presence HTTP/1.1\r\n"),
            "{head}"
        );
        assert!(
            head.contains("\r\nAuthorization: Bearer tok-1\r\n"),
            "{head}"
        );
        assert!(head.contains("\r\nHost: 127.0.0.1\r\n"), "{head}");
        let body: Value = serde_json::from_str(&reqs[1].body).unwrap();
        assert_eq!(
            (&body["device"], &body["state"]),
            (&json!("phone_alice"), &json!("home"))
        );
        let s = state.read();
        let a = s.actions.back().unwrap();
        assert_eq!((a.action, a.ok, a.mac), ("presence", true, Some(MAC)));
        assert_eq!(a.detail, "home: Home Assistant was told (phone_alice)");
        let text = crate::metrics::render(&s);
        for line in [
            "wifi_presence_home{device=\"phone_alice\"} 1",
            "wifi_presence_events_total{result=\"delivered\"} 1",
            "wifi_presence_pending 0",
            "wifi_presence_refused 0",
        ] {
            assert!(text.lines().any(|l| l == line), "missing {line}");
        }
    }

    #[tokio::test]
    async fn a_refused_token_stops_the_events_until_it_changes() {
        let dir = TestDir::new();
        std::fs::write(dir.path().join("token"), "bad").unwrap();
        let (addr, seen) = fake_ha("server", vec![401, 200]).await;
        let (state, set) = shared(dir.path(), addr.port());
        tokio::spawn(supervise(state.clone(), set));
        wait_for("the first look", || {
            state.read().presence.as_ref().unwrap().devices[0]
                .home
                .is_some()
        })
        .await;
        join(&state);
        wait_for("the refusal", || {
            state.read().presence.as_ref().unwrap().refused.is_some()
        })
        .await;
        // Past its backoff, the same token is not tried again.
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert!(crate::metrics::render(&state.read()).contains("\nwifi_presence_refused 1\n"));
        std::fs::write(dir.path().join("token"), "good").unwrap();
        wait_for("the event delivered", || {
            state.read().presence.as_ref().unwrap().delivered == 1
        })
        .await;
        let reqs = seen.lock().unwrap().clone();
        assert_eq!(reqs.len(), 2);
        assert!(reqs[1].head.contains("Bearer good\r\n"));
        assert!(state.read().presence.as_ref().unwrap().refused.is_none());
    }
}
