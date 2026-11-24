//! A signed-in viewer's speed test of their own device, from the UI's "Test"
//! page, through the sign-in proxy as the UI is reached:
//!
//!   POST /api/speedtest               {}  → {"id", "secs", "max_bytes", "client"}
//!   GET  /api/speedtest/{id}/down     filler for the test's time or bytes
//!   POST /api/speedtest/{id}/up       a body of at most 8 MiB, two at a time
//!   POST /api/speedtest/{id}/done     {"down_bytes", "down_ms"} → the result
//!   GET  /api/speedtest               the user's own tests, newest first
//!
//! The download is timed by the browser, which says what it received and in
//! how long, its bytes held to what was sent and its time to no less than
//! the sending took (an engine may hand the page the body only once it is
//! all in); the upload by the controller, from the first body's request to
//! the last byte read. A body is read as it comes, counted frame by frame
//! and never held, at most [`IN_FLIGHT`] at once per test, while the
//! upload's time runs from the first and [`UP_SLACK`] after; a body past
//! that, or past the test's bytes, or of an ended test, is read no further.
//! The client is the associated client one of whose addresses (leased, or
//! seen in its flows) is the request's: the last `X-Forwarded-For` entry, which the sign-in proxy
//! sets and nothing else can, since only the proxy reaches the listener.
//! Its AP, band, SSID, signal and rates are taken at the start, and a move
//! during the test is noted; a device that is no Wi-Fi client of these APs
//! is tested all the same, unattributed.
//!
//! The test's id is random and its user's alone (another user's is not
//! found). Starting one and finishing it are JSON from the UI's own page;
//! each user has one test at a time and [`PER_HOUR`] an hour, and
//! [`AT_ONCE`] run across the site, so a test cannot be made to load the
//! controller. A test not finished [`Limits::abandon`] after it started is
//! abandoned. Its end is an action `speedtest` on its client.

use std::convert::Infallible;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::LazyLock;
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use axum::body::{Body, Bytes};
use axum::extract::{Path, State as Ext};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_core::Stream;
use serde::Deserialize;
use serde_json::{Value, json};
use u6e_proto::mac;

use super::{Measured, SpeedTests, Status, mbits};
use crate::actions::{Access, Via, Web, cross_site, user};
use crate::http::{error, json_response};
use crate::sessions::{self, unix_ms};
use crate::state::{Action, Shared, State};
use crate::view;

/// Each user's tests in an hour, and the tests running across the site.
pub const PER_HOUR: usize = 6;
pub const AT_ONCE: usize = 2;
/// The client tests kept, newest last, for a week at most.
pub const KEEP: usize = 500;
/// The largest upload body, and the bodies a test takes at once (the page
/// keeps two in flight).
pub const BODY_MAX: usize = 8 << 20;
pub const IN_FLIGHT: u8 = 2;
/// How long after the upload's time a body may still be read.
pub const UP_SLACK: Duration = Duration::from_secs(2);
/// A user's tests listed.
const LISTED: usize = 20;
/// The download's filler: random, so that nothing on the way compresses it,
/// and sent as slices of [`SLICE`].
static FILLER: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let mut b = vec![0; 1 << 20];
    SystemRandom::new()
        .fill(&mut b)
        .expect("the system's random source works");
    b
});
const SLICE: usize = 256 << 10;

/// What a client test takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Each direction's time and bytes.
    pub secs: u8,
    pub max_bytes: u64,
    /// How long after its start a test not finished is abandoned.
    pub abandon: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            secs: 10,
            max_bytes: 1_000_000_000,
            abandon: Duration::from_secs(60),
        }
    }
}

/// Where a tested client was: its AP, band, SSID, average signal and last
/// rates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct At {
    pub mac: [u8; 6],
    pub name: Option<String>,
    pub ap: String,
    pub band: Option<&'static str>,
    pub ssid: String,
    pub signal_dbm: i8,
    pub tx_kbps: u32,
    pub rx_kbps: u32,
}

impl At {
    fn json(&self) -> Value {
        json!({
            "mac": mac::format(self.mac),
            "name": self.name,
            "ap": self.ap,
            "band": self.band,
            "ssid": self.ssid,
            "signal": self.signal_dbm,
            "tx_mbps": f64::from(self.tx_kbps / 100) / 10.0,
            "rx_mbps": f64::from(self.rx_kbps / 100) / 10.0,
        })
    }
}

/// One client test.
#[derive(Debug, Clone, PartialEq)]
pub struct ClientTest {
    pub id: String,
    pub user: String,
    pub address: IpAddr,
    pub at: SystemTime,
    started: Instant,
    /// Its client at the start, and at the end when it moved meanwhile.
    pub client: Option<At>,
    pub moved: Option<At>,
    pub status: Status,
    /// The download asked for, and what was sent of it and in how long.
    down_asked: bool,
    sent: Option<Measured>,
    /// The upload: its bytes, its first request and the end of its last.
    up_bytes: u64,
    up_first: Option<Instant>,
    up_last: Option<Instant>,
    /// Its upload bodies being read now.
    up_in_flight: u8,
    /// The result: the browser's download, the controller's upload.
    pub down: Option<Measured>,
    pub up: Option<Measured>,
    pub detail: String,
    pub ended: Option<SystemTime>,
}

impl ClientTest {
    fn json(&self) -> Value {
        let mut v = json!({
            "id": self.id,
            "at": unix_ms(self.at),
            "address": self.address.to_string(),
            "status": self.status.name(),
            "client": self.client.as_ref().map(At::json),
        });
        if let Some(m) = &self.moved {
            v["moved"] = m.json();
        }
        if let Some(d) = &self.down {
            v["down"] = d.json();
        }
        if let Some(u) = &self.up {
            v["up"] = u.json();
        }
        if !self.detail.is_empty() {
            v["detail"] = self.detail.clone().into();
        }
        if let Some(t) = self.ended {
            v["ended"] = unix_ms(t).into();
        }
        v
    }
}

impl SpeedTests {
    fn client_test(&mut self, id: &str, user: &str) -> Option<&mut ClientTest> {
        self.clients
            .iter_mut()
            .find(|t| t.id == id && t.user == user)
    }

    /// Why `user` may not start a test at `now`.
    fn client_refusal(&self, user: &str, now: SystemTime) -> Option<String> {
        let running = || self.clients.iter().filter(|t| t.status == Status::Running);
        if running().any(|t| t.user == user) {
            return Some("a test of yours runs".into());
        }
        let hour = Duration::from_secs(3600);
        let mine: Vec<SystemTime> = self
            .clients
            .iter()
            .filter(|t| t.user == user && t.at + hour > now)
            .map(|t| t.at)
            .collect();
        if mine.len() >= PER_HOUR {
            let next = mine.iter().min().map_or(now, |&t| t + hour);
            let mins = next
                .duration_since(now)
                .unwrap_or_default()
                .as_secs()
                .div_ceil(60);
            return Some(format!(
                "{PER_HOUR} tests an hour are allowed: the next in {mins} min"
            ));
        }
        if running().count() >= AT_ONCE {
            return Some(format!(
                "{AT_ONCE} tests run already: try again in a minute"
            ));
        }
        None
    }

    /// Ends client test `id` with its result, or why it failed; the test as
    /// it ended, unless it had.
    fn end_client(&mut self, id: &str, why: Option<String>) -> Option<ClientTest> {
        let t = self
            .clients
            .iter_mut()
            .find(|t| t.id == id && t.status == Status::Running)?;
        t.status = if why.is_none() {
            Status::Done
        } else {
            Status::Failed
        };
        t.detail = why.unwrap_or_default();
        t.ended = Some(SystemTime::now());
        let t = t.clone();
        let result = if t.status == Status::Done {
            "ok"
        } else {
            "failed"
        };
        self.count("client", result);
        Some(t)
    }

    /// The running client tests past their time to finish.
    fn abandoned(&self) -> Vec<String> {
        let abandon = self.limits.client.abandon;
        let running = self.clients.iter().filter(|t| t.status == Status::Running);
        running
            .filter(|t| t.started.elapsed() > abandon)
            .map(|t| t.id.clone())
            .collect()
    }

    fn prune_clients(&mut self, now: SystemTime) {
        self.clients
            .retain(|t| t.status == Status::Running || t.at + super::KEEP >= now);
        while self.clients.len() > KEEP {
            let Some(at) = self
                .clients
                .iter()
                .position(|t| t.status != Status::Running)
            else {
                break;
            };
            self.clients.remove(at);
        }
    }
}

/// Where the associated client with the address `ip` is now; none when no
/// client, or more than one, holds it (an address two clients claim says
/// neither is the one asking).
fn client_at(state: &State, ip: IpAddr) -> Option<At> {
    let mut holders = state
        .clients()
        .into_iter()
        .filter(|c| state.identity(&c.station.mac).addresses.contains(&ip));
    let c = holders.next()?;
    if holders.next().is_some() {
        return None;
    }
    let ap = state.ap(&c.ap)?;
    let place = sessions::place(&c.ap, &ap.naming, c.station.bss, None);
    Some(At {
        mac: c.station.mac,
        name: state.identity(&c.station.mac).name().map(str::to_owned),
        ap: c.ap.clone(),
        band: place.and_then(|p| p.band).map(view::band),
        ssid: c.ssid.clone(),
        signal_dbm: c.station.signal_avg,
        tx_kbps: c.station.tx_rate_kbps,
        rx_kbps: c.station.rx_rate_kbps,
    })
}

/// The address the sign-in proxy says the request came from: the last
/// `X-Forwarded-For` entry (a client may send its own before it, which the
/// proxy keeps).
fn address(req: &HeaderMap) -> Option<IpAddr> {
    let last = req
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .next_back()?;
    let ip: IpAddr = last.trim().parse().ok()?;
    Some(ip.to_canonical())
}

/// Ends client test `id` and records it as an action on its client.
fn end(state: &mut State, id: &str, why: Option<String>) -> Option<ClientTest> {
    let t = state.speedtests.end_client(id, why)?;
    let detail = match (&t.down, &t.up) {
        (Some(d), Some(u)) if t.status == Status::Done => {
            let mut s = format!(
                "download {}, upload {} from {}",
                mbits(d),
                mbits(u),
                t.address
            );
            if let Some(c) = &t.client {
                let band = c.band.map(|b| format!(" on {b} GHz")).unwrap_or_default();
                s.push_str(&format!(
                    "{band} at {} dBm, rates {} and {} Mbit/s",
                    c.signal_dbm,
                    c.tx_kbps / 1000,
                    c.rx_kbps / 1000
                ));
            }
            if let Some(m) = &t.moved {
                s.push_str(&format!("; moved to {} during the test", m.ap));
            }
            s
        }
        _ => format!("{} (from {})", t.detail, t.address),
    };
    state.record(Action {
        at: SystemTime::now(),
        user: Some(t.user.clone()),
        action: "speedtest",
        mac: t.client.as_ref().map(|c| c.mac),
        ap: t.client.as_ref().map(|c| c.ap.clone()),
        ok: t.status == Status::Done,
        detail,
    });
    Some(t)
}

/// Abandons the client tests past their time to finish.
pub fn expire(state: &mut State) {
    for id in state.speedtests.abandoned() {
        end(state, &id, Some("not finished in time".into()));
    }
}

/// Who asks, as the sign-in proxy names them; or why they may not.
fn asker(req: &HeaderMap, access: &Access, via: Via) -> Result<String, &'static str> {
    if cross_site(req, &access.public_origin, via) {
        return Err("cross-site");
    }
    user(req).ok_or("not signed in")
}

fn too_many(why: &str) -> Response {
    let mut r = error(StatusCode::TOO_MANY_REQUESTS, why);
    r.headers_mut()
        .insert(header::RETRY_AFTER, header::HeaderValue::from_static("60"));
    r
}

/// `POST /api/speedtest`.
pub async fn start(Ext(web): Ext<Web>, req: HeaderMap) -> Response {
    let who = match asker(&req, &web.access, Via::Post) {
        Ok(u) => u,
        Err(why) => return error(StatusCode::FORBIDDEN, why),
    };
    let Some(address) = address(&req) else {
        return error(StatusCode::BAD_REQUEST, "no client address");
    };
    let mut id = [0; 16];
    if SystemRandom::new().fill(&mut id).is_err() {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "no random id");
    }
    let id = mac::hex(&id);
    let mut state = web.state.write();
    let now = SystemTime::now();
    if let Some(why) = state.speedtests.client_refusal(&who, now) {
        state.speedtests.count("client", "refused");
        return too_many(&why);
    }
    let client = client_at(&state, address);
    let limits = state.speedtests.limits.client;
    let test = ClientTest {
        id: id.clone(),
        user: who,
        address,
        at: now,
        started: Instant::now(),
        client: client.clone(),
        moved: None,
        status: Status::Running,
        down_asked: false,
        sent: None,
        up_bytes: 0,
        up_first: None,
        up_last: None,
        up_in_flight: 0,
        down: None,
        up: None,
        detail: String::new(),
        ended: None,
    };
    state.speedtests.clients.push_back(test);
    state.speedtests.prune_clients(now);
    json_response(&json!({
        "id": id,
        "secs": limits.secs,
        "max_bytes": limits.max_bytes,
        "body_max": BODY_MAX,
        "client": client.as_ref().map(At::json),
    }))
}

/// `GET /api/speedtest`: the user's own tests, newest first.
pub async fn list(Ext(web): Ext<Web>, req: HeaderMap) -> Response {
    let Some(who) = user(&req) else {
        return error(StatusCode::FORBIDDEN, "not signed in");
    };
    let state = web.state.read();
    let mine = state
        .speedtests
        .clients
        .iter()
        .rev()
        .filter(|t| t.user == who);
    let tests: Vec<Value> = mine.take(LISTED).map(ClientTest::json).collect();
    json_response(&json!({ "tests": tests, "per_hour": PER_HOUR }))
}

/// `GET /api/speedtest/{id}/down`: the download, once a test.
pub async fn down(Ext(web): Ext<Web>, Path(id): Path<String>, req: HeaderMap) -> Response {
    let Some(who) = user(&req) else {
        return error(StatusCode::FORBIDDEN, "not signed in");
    };
    let limits = {
        let mut state = web.state.write();
        let limits = state.speedtests.limits.client;
        let Some(t) = state.speedtests.client_test(&id, &who) else {
            return error(StatusCode::NOT_FOUND, "no such test");
        };
        if t.status != Status::Running || t.down_asked {
            return error(StatusCode::CONFLICT, "its download was taken");
        }
        t.down_asked = true;
        limits
    };
    let filler = Filler {
        state: web.state.clone(),
        id,
        user: who,
        sent: 0,
        max: limits.max_bytes,
        until: Instant::now() + Duration::from_secs(u64::from(limits.secs)),
        started: Instant::now(),
        done: false,
    };
    (
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        Body::from_stream(filler),
    )
        .into_response()
}

/// The download as it goes out: slices of the filler until its time or
/// bytes are up; what was sent is recorded at its end, or when the browser
/// goes away.
struct Filler {
    state: Shared,
    id: String,
    user: String,
    sent: u64,
    max: u64,
    until: Instant,
    started: Instant,
    done: bool,
}

impl Filler {
    fn record(&mut self) {
        if std::mem::replace(&mut self.done, true) {
            return;
        }
        let sent = Measured {
            bytes: self.sent,
            us: self.started.elapsed().as_micros() as u64,
        };
        let mut state = self.state.write();
        if let Some(t) = state.speedtests.client_test(&self.id, &self.user) {
            t.sent = Some(sent);
        }
    }
}

impl Stream for Filler {
    type Item = Result<Bytes, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done || self.sent >= self.max || Instant::now() >= self.until {
            self.record();
            return Poll::Ready(None);
        }
        let off = (self.sent as usize) % FILLER.len();
        let n = SLICE
            .min((self.max - self.sent) as usize)
            .min(FILLER.len() - off);
        self.sent += n as u64;
        Poll::Ready(Some(Ok(Bytes::from_static(&FILLER[off..off + n]))))
    }
}

impl Drop for Filler {
    fn drop(&mut self) {
        self.record();
    }
}

/// `POST /api/speedtest/{id}/up`: one body of the upload.
pub async fn up(
    Ext(web): Ext<Web>,
    Path(id): Path<String>,
    req: HeaderMap,
    body: Body,
) -> Response {
    let who = match asker(&req, &web.access, Via::Bytes) {
        Ok(u) => u,
        Err(why) => return error(StatusCode::FORBIDDEN, why),
    };
    let length = req
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok()?.parse().ok());
    if length.is_some_and(|n: usize| n > BODY_MAX) {
        return error(StatusCode::PAYLOAD_TOO_LARGE, "a body is 8 MiB at most");
    }
    let arrived = Instant::now();
    let until = {
        let mut state = web.state.write();
        let limits = state.speedtests.limits.client;
        let Some(t) = state.speedtests.client_test(&id, &who) else {
            return error(StatusCode::NOT_FOUND, "no such test");
        };
        if t.status != Status::Running {
            return error(StatusCode::CONFLICT, "the test is over");
        }
        if t.up_in_flight >= IN_FLIGHT {
            return error(
                StatusCode::TOO_MANY_REQUESTS,
                "two bodies are in flight already",
            );
        }
        let first = *t.up_first.get_or_insert(arrived);
        let window = Duration::from_secs(u64::from(limits.secs));
        if arrived > first + window || t.up_bytes >= limits.max_bytes {
            return error(StatusCode::CONFLICT, "the upload's time is up");
        }
        t.up_in_flight += 1;
        first + window + UP_SLACK
    };
    let flight = InFlight {
        state: web.state.clone(),
        id,
        user: who,
    };
    match tokio::time::timeout_at(until.into(), flight.read(body)).await {
        Ok(Ok(bytes)) => json_response(&json!({ "bytes": bytes })),
        Ok(Err((status, why))) => error(status, why),
        Err(_) => error(StatusCode::CONFLICT, "the upload's time is up"),
    }
}

/// An upload body being read: counted in its test's bodies in flight until
/// it is dropped, however its reading ends.
struct InFlight {
    state: Shared,
    id: String,
    user: String,
}

impl InFlight {
    /// Reads the body frame by frame into its test's count, nothing kept;
    /// the test's upload bytes once it ended, or why it was read no further.
    async fn read(&self, body: Body) -> Result<u64, (StatusCode, &'static str)> {
        let mut frames = body.into_data_stream();
        let mut read = 0;
        loop {
            let frame = std::future::poll_fn(|cx| Pin::new(&mut frames).poll_next(cx)).await;
            let Some(frame) = frame else {
                let mut state = self.state.write();
                let t = state.speedtests.client_test(&self.id, &self.user);
                return Ok(t.map_or(0, |t| t.up_bytes));
            };
            let bytes = frame.map_err(|_| (StatusCode::BAD_REQUEST, "the body broke off"))?;
            read += bytes.len();
            if read > BODY_MAX {
                return Err((StatusCode::PAYLOAD_TOO_LARGE, "a body is 8 MiB at most"));
            }
            let mut state = self.state.write();
            let max = state.speedtests.limits.client.max_bytes;
            let Some(t) = state.speedtests.client_test(&self.id, &self.user) else {
                return Err((StatusCode::NOT_FOUND, "no such test"));
            };
            if t.status != Status::Running {
                return Err((StatusCode::CONFLICT, "the test is over"));
            }
            t.up_bytes += bytes.len() as u64;
            t.up_last = Some(Instant::now());
            if t.up_bytes >= max {
                return Err((StatusCode::CONFLICT, "the upload's bytes are used up"));
            }
        }
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        let mut state = self.state.write();
        if let Some(t) = state.speedtests.client_test(&self.id, &self.user) {
            t.up_in_flight = t.up_in_flight.saturating_sub(1);
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DoneBody {
    down_bytes: u64,
    down_ms: u64,
}

/// `POST /api/speedtest/{id}/done`: the browser's download; the result.
pub async fn done(
    Ext(web): Ext<Web>,
    Path(id): Path<String>,
    req: HeaderMap,
    body: Bytes,
) -> Response {
    let who = match asker(&req, &web.access, Via::Post) {
        Ok(u) => u,
        Err(why) => return error(StatusCode::FORBIDDEN, why),
    };
    let Ok(b) = serde_json::from_slice::<DoneBody>(&body) else {
        return error(StatusCode::BAD_REQUEST, "not {\"down_bytes\", \"down_ms\"}");
    };
    let mut state = web.state.write();
    let now_at = {
        let Some(t) = state.speedtests.client_test(&id, &who) else {
            return error(StatusCode::NOT_FOUND, "no such test");
        };
        if t.status != Status::Running {
            return error(StatusCode::CONFLICT, "the test is over");
        }
        t.address
    };
    let moved = client_at(&state, now_at);
    let Some(t) = state.speedtests.client_test(&id, &who) else {
        return error(StatusCode::NOT_FOUND, "no such test");
    };
    let (sent, sent_us) = t.sent.map_or((0, 0), |s| (s.bytes, s.us));
    t.down = Some(Measured {
        bytes: b.down_bytes.min(sent),
        us: (b.down_ms.max(1) * 1000).max(sent_us),
    });
    let span = t.up_first.zip(t.up_last).map(|(a, z)| z - a);
    t.up = Some(Measured {
        bytes: t.up_bytes,
        us: span.map_or(0, |s| s.as_micros() as u64),
    });
    let place = |a: &At| (a.mac, a.ap.clone(), a.band);
    if t.client.as_ref().map(place) != moved.as_ref().map(place) {
        t.moved = moved;
    }
    let why = (sent == 0 || t.up_bytes == 0).then(|| "a direction carried nothing".to_owned());
    match end(&mut state, &id, why) {
        Some(t) => json_response(&t.json()),
        None => error(StatusCode::CONFLICT, "the test is over"),
    }
}

/// The last result on each AP and band, for the metrics.
pub fn last_by_place(tests: &SpeedTests) -> Vec<(&str, &'static str, &ClientTest)> {
    let mut out: Vec<(&str, &'static str, &ClientTest)> = Vec::new();
    let done = tests.clients.iter().filter(|t| t.status == Status::Done);
    for t in done {
        let Some(c) = &t.client else { continue };
        let Some(band) = c.band else { continue };
        out.retain(|(a, b, _)| !(*a == c.ap && *b == band));
        out.push((&c.ap, band, t));
    }
    out.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(xff: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in xff {
            h.append("x-forwarded-for", v.parse().unwrap());
        }
        h
    }

    #[test]
    fn the_address_is_the_proxys_last_entry() {
        let ip = |s: &str| Some(s.parse::<IpAddr>().unwrap());
        assert_eq!(address(&headers(&["192.0.2.10"])), ip("192.0.2.10"));
        assert_eq!(
            address(&headers(&["198.51.100.1, 192.0.2.10"])),
            ip("192.0.2.10")
        );
        assert_eq!(
            address(&headers(&["198.51.100.1", "2001:db8::5"])),
            ip("2001:db8::5")
        );
        // An IPv4 client the proxy names in IPv6's mapped form.
        assert_eq!(address(&headers(&["::ffff:192.0.2.10"])), ip("192.0.2.10"));
        assert_eq!(address(&headers(&[])), None);
        // A last entry that is no address is none, never the one before it.
        assert_eq!(address(&headers(&["192.0.2.10, junk"])), None);
    }

    fn test(user: &str, at: SystemTime, status: Status) -> ClientTest {
        ClientTest {
            id: format!("{user}{at:?}"),
            user: user.into(),
            address: "192.0.2.1".parse().unwrap(),
            at,
            started: Instant::now(),
            client: None,
            moved: None,
            status,
            down_asked: false,
            sent: None,
            up_bytes: 0,
            up_first: None,
            up_last: None,
            up_in_flight: 0,
            down: None,
            up: None,
            detail: String::new(),
            ended: None,
        }
    }

    #[test]
    fn each_user_has_six_tests_an_hour() {
        let now = SystemTime::now();
        let mut t = SpeedTests::default();
        for m in [70, 50, 40, 30, 20, 10] {
            let at = now - Duration::from_secs(m * 60);
            t.clients.push_back(test("alice", at, Status::Done));
        }
        // The one 70 minutes ago is past the hour: five in it.
        assert_eq!(t.client_refusal("alice", now), None);
        t.clients.push_back(test("alice", now, Status::Done));
        let why = t.client_refusal("alice", now).unwrap();
        assert_eq!(why, "6 tests an hour are allowed: the next in 10 min");
        assert_eq!(t.client_refusal("bob", now), None);
    }

    #[test]
    fn the_tests_kept_are_bounded() {
        let now = SystemTime::now();
        let mut t = SpeedTests::default();
        t.clients
            .push_back(test("run", now - super::super::KEEP * 2, Status::Running));
        t.clients
            .push_back(test("old", now - super::super::KEEP * 2, Status::Done));
        for i in 0..KEEP + 10 {
            t.clients
                .push_back(test(&format!("u{i}"), now, Status::Done));
        }
        t.prune_clients(now);
        assert_eq!(t.clients.len(), KEEP);
        assert_eq!(t.clients[0].user, "run");
        assert_eq!(t.clients[1].user, "u11");
    }

    #[test]
    fn the_metrics_take_the_last_test_of_each_ap_and_band() {
        let now = SystemTime::now();
        let at = |ap: &str, band| At {
            mac: [2, 0, 0, 0, 0, 1],
            name: None,
            ap: ap.into(),
            band: Some(band),
            ssid: "s".into(),
            signal_dbm: -50,
            tx_kbps: 0,
            rx_kbps: 0,
        };
        let mut t = SpeedTests::default();
        for (n, ap, band, status) in [
            (1, "ap1", "5", Status::Done),
            (2, "ap2", "5", Status::Done),
            (3, "ap1", "5", Status::Done),
            (4, "ap1", "6", Status::Failed),
        ] {
            let mut c = test(&format!("u{n}"), now, status);
            c.client = Some(at(ap, band));
            t.clients.push_back(c);
        }
        let last: Vec<(&str, &str, &str)> = last_by_place(&t)
            .into_iter()
            .map(|(a, b, c)| (a, b, c.user.as_str()))
            .collect();
        assert_eq!(last, [("ap1", "5", "u3"), ("ap2", "5", "u2")]);
    }
}
