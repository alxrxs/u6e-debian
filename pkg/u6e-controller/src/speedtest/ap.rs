//! An AP's speed test to the controller, `POST /api/aps/{ap}/speedtest` (an
//! admin's, from the UI's own page; answered 202 with the test's id once
//! the AP said it started): the controller sends the AP a `SpeedTest`
//! command, and its agent opens a connection of its own to the agent
//! listener, the link's TLS with its own key, whose first message names the
//! test (`agents`). On it the controller sends the download for its
//! [`Limits`]' time or bytes (10 s, 2 GiB), times the upload the agent sends
//! back, and takes the agent's report of the download and of its CPU
//! (`u6e_proto::speedtest`).
//!
//! One test at a time across the APs, and none while a rollout runs on any
//! of them, while the AP is held, not connected, or has a configuration or
//! a channel or power command on its way (`State::sendable`, which in turn
//! sends none of those to an AP under test). Only the AP the test was asked
//! of may open it, once, within 15 s; the whole test ends 30 s after it
//! opened. Its end is an action `speedtest` on the AP.

use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::sync::LazyLock;
use std::time::{Duration, Instant, SystemTime};

use axum::extract::{Path, State as Ext};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio::time::{sleep, timeout};
use tokio_rustls::server::TlsStream;
use u6e_proto::frame::decode_frame;
use u6e_proto::msg::{AgentMsg, CommandKind};
use u6e_proto::speedtest::{self, BYTES_MAX, CHUNK, Chunks};

use super::{ApResult, ApTest, Measured, SpeedTests, Status, mbits};
use crate::actions::{Via, Web, refusal, user};
use crate::agents::Counted;
use crate::http::{error, json_response};
use crate::state::{Action, Change, Shared, State, Waiter};

/// What an AP test takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Each direction's time and bytes, as asked of the AP.
    pub secs: u8,
    pub max_bytes: u64,
    /// How long the AP has to open the test's connection once it said it
    /// started.
    pub open: Duration,
    /// The longest a test may run once opened: both directions at their
    /// longest, the report and some.
    pub run: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            secs: speedtest::SECS_MAX,
            max_bytes: BYTES_MAX,
            open: Duration::from_secs(15),
            run: Duration::from_secs(30),
        }
    }
}

/// The longest one write or read of the test may wait.
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// How far past its time or size an upload may run before it is cut off.
const SLACK: Duration = Duration::from_secs(3);

/// A chunk of the download as it goes out: its header and its filler.
static CHUNK_OUT: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let mut c = speedtest::header(CHUNK).to_vec();
    c.resize(4 + CHUNK, 0);
    c
});

/// Why `ap` may not be tested now.
pub fn why_not(state: &State, ap: &str) -> Option<String> {
    if let Some(t) = state.speedtests.running_ap() {
        return Some(format!("a speed test of {} runs", t.ap));
    }
    if let Some(r) = state.rollouts.iter().find(|r| r.is_open()) {
        return Some(format!("{} is being rolled out to", r.ap));
    }
    state.sendable(ap).err()
}

impl SpeedTests {
    /// Records the test the command `id` asks of `ap`.
    fn begin_ap(&mut self, id: u64, ap: &str, user: Option<String>) {
        self.aps.push_back(ApTest {
            id,
            ap: ap.to_owned(),
            user,
            at: SystemTime::now(),
            status: Status::Running,
            opened: false,
            result: None,
            detail: String::new(),
            ended: None,
        });
        self.asked.insert(id, Instant::now());
        self.prune(SystemTime::now());
    }

    /// Takes the connection that opens test `id` from `ap`: refused unless
    /// it is that AP's running test, not opened yet, asked within its
    /// limits' time to open.
    pub fn open_ap(&mut self, id: u64, ap: &str) -> Result<(), &'static str> {
        let (asked, open) = (self.asked.get(&id).copied(), self.limits.ap.open);
        let t = self.ap_test_mut(id).filter(|t| t.ap == ap);
        let Some(t) = t.filter(|t| t.status == Status::Running) else {
            return Err("no such test runs on this AP");
        };
        if t.opened {
            return Err("the test is opened already");
        }
        if asked.is_none_or(|a| a.elapsed() > open) {
            return Err("opened too late");
        }
        t.opened = true;
        Ok(())
    }

    /// Ends test `id` with its result or why it failed; the test as it
    /// ended, unless it had.
    fn end_ap(&mut self, id: u64, result: Result<ApResult, String>) -> Option<ApTest> {
        self.asked.remove(&id);
        let t = self
            .ap_test_mut(id)
            .filter(|t| t.status == Status::Running)?;
        match result {
            Ok(r) => {
                t.status = Status::Done;
                t.result = Some(r);
            }
            Err(why) => {
                t.status = Status::Failed;
                t.detail = why;
            }
        }
        t.ended = Some(SystemTime::now());
        let t = t.clone();
        self.count(
            "ap",
            if t.status == Status::Done {
                "ok"
            } else {
                "failed"
            },
        );
        Some(t)
    }
}

/// Ends test `id` and records it as an action on its AP.
fn end(state: &Shared, id: u64, result: Result<ApResult, String>) {
    let mut state = state.write();
    let Some(t) = state.speedtests.end_ap(id, result) else {
        return;
    };
    let detail = match &t.result {
        Some(r) => format!(
            "download {}, upload {}; the AP's CPU {} % and {} %, the test's own {} % and {} % of a core",
            mbits(&r.down),
            mbits(&r.up),
            r.cpu_down.busy_permille / 10,
            r.cpu_up.busy_permille / 10,
            r.cpu_down.thread_permille / 10,
            r.cpu_up.thread_permille / 10,
        ),
        None => t.detail.clone(),
    };
    state.record(Action {
        at: SystemTime::now(),
        user: t.user.clone(),
        action: "speedtest",
        mac: None,
        ap: Some(t.ap.clone()),
        ok: t.status == Status::Done,
        detail,
    });
    state.notify(Change::SpeedTests);
}

/// `POST /api/aps/{ap}/speedtest`.
pub async fn start(Ext(web): Ext<Web>, Path(ap): Path<String>, req: HeaderMap) -> Response {
    if let Some(why) = refusal(&req, &web.access, Via::Post, &format!("speedtest {ap}")) {
        return error(StatusCode::FORBIDDEN, why);
    }
    let who = user(&req);
    let (tx, rx) = oneshot::channel();
    let id = {
        let mut state = web.state.write();
        if state.ap(&ap).is_none() {
            return error(StatusCode::NOT_FOUND, "no such AP");
        }
        let limits = state.speedtests.limits.ap;
        let kind = CommandKind::SpeedTest {
            secs: limits.secs,
            max_bytes: limits.max_bytes,
        };
        let refused = why_not(&state, &ap).map(|why| (why, StatusCode::CONFLICT));
        let id = match refused {
            Some(r) => Err(r),
            None => state
                .command(&ap, kind, Waiter::Reply(tx))
                .ok_or((format!("{ap} is not connected"), StatusCode::BAD_GATEWAY)),
        };
        match id {
            Ok(id) => {
                state.speedtests.begin_ap(id, &ap, who.clone());
                state.notify(Change::SpeedTests);
                id
            }
            Err((why, status)) => {
                state.speedtests.count("ap", "refused");
                state.record(Action {
                    at: SystemTime::now(),
                    user: who,
                    action: "speedtest",
                    mac: None,
                    ap: Some(ap),
                    ok: false,
                    detail: why.clone(),
                });
                return error(status, &why);
            }
        }
    };
    let (status, why) = match timeout(web.access.timeout, rx).await {
        Ok(Ok(r)) if r.ok => {
            tokio::spawn(unopened(web.state.clone(), id));
            let body = json!({ "id": id.to_string(), "detail": r.detail });
            return (StatusCode::ACCEPTED, json_response(&body)).into_response();
        }
        Ok(Ok(r)) => (StatusCode::CONFLICT, r.detail),
        Ok(Err(_)) => (StatusCode::BAD_GATEWAY, format!("{ap} went away")),
        Err(_) => {
            web.state.write().forget(id);
            let t = web.access.timeout;
            (
                StatusCode::GATEWAY_TIMEOUT,
                format!("no answer from {ap} in {t:?}"),
            )
        }
    };
    end(&web.state, id, Err(why.clone()));
    error(status, &why)
}

/// Ends test `id` as failed if its AP has not opened it in its limits'
/// time to open.
async fn unopened(state: Shared, id: u64) {
    let wait = state.read().speedtests.limits.ap.open;
    sleep(wait).await;
    let opened = state.read().speedtests.ap_test(id).is_none_or(|t| t.opened);
    if !opened {
        let why = format!("the AP did not open the test's connection in {wait:?}");
        end(&state, id, Err(why));
    }
}

/// Serves the connection that opens test `id` of `ap` from `peer`, `inbuf`
/// what came after its first message.
pub(crate) async fn serve(
    state: &Shared,
    ap: &str,
    peer: SocketAddr,
    id: u64,
    tls: &mut TlsStream<Counted>,
    inbuf: Vec<u8>,
) {
    let opened = {
        let mut state = state.write();
        let limits = state.speedtests.limits.ap;
        state.speedtests.open_ap(id, ap).map(|()| limits)
    };
    let limits = match opened {
        Ok(l) => l,
        Err(why) => {
            eprintln!("u6e-controller: {ap} ({peer}): speed test {id} refused: {why}");
            return;
        }
    };
    let result = match timeout(limits.run, run(tls, inbuf, id, limits)).await {
        Ok(Ok(r)) => Ok(r),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err(format!("not over in {:?}", limits.run)),
    };
    end(state, id, result);
}

/// The test on its connection: the download sent, the upload timed, the
/// agent's report taken.
async fn run(
    tls: &mut TlsStream<Counted>,
    mut inbuf: Vec<u8>,
    id: u64,
    limits: Limits,
) -> io::Result<ApResult> {
    let t0 = Instant::now();
    let secs = Duration::from_secs(u64::from(limits.secs));
    let mut sent = 0;
    while t0.elapsed() < secs && sent < limits.max_bytes {
        write(tls, &CHUNK_OUT).await?;
        sent += CHUNK as u64;
    }
    write(tls, &speedtest::header(0)).await?;
    timeout(IO_TIMEOUT, tls.flush())
        .await
        .map_err(|_| io::Error::new(ErrorKind::TimedOut, "the AP is not reading"))??;
    let mut up = Chunks::default();
    let mut first = None::<Instant>;
    let mut chunk = vec![0; CHUNK];
    loop {
        if !inbuf.is_empty() {
            let t = *first.get_or_insert_with(Instant::now);
            let used = up.take(&inbuf).map_err(invalid)?;
            inbuf.drain(..used);
            if up.bytes() > limits.max_bytes + CHUNK as u64 || t.elapsed() > secs + SLACK {
                return Err(invalid("the AP sent past the test's bounds"));
            }
        }
        if up.ended() {
            break;
        }
        let n = read(tls, &mut chunk, "the upload").await?;
        inbuf.extend_from_slice(&chunk[..n]);
    }
    let up = Measured {
        bytes: up.bytes(),
        us: first.map_or(0, |t| t.elapsed().as_micros() as u64),
    };
    let report = loop {
        if let Some((msg, _)) = decode_frame::<AgentMsg>(&inbuf)? {
            break msg;
        }
        let n = read(tls, &mut chunk, "its report").await?;
        inbuf.extend_from_slice(&chunk[..n]);
    };
    match report {
        AgentMsg::SpeedTestReport(r) if r.id == id => Ok(ApResult {
            down: Measured {
                bytes: r.down_bytes,
                us: r.down_us,
            },
            up,
            cpu_down: r.cpu_down,
            cpu_up: r.cpu_up,
        }),
        _ => Err(invalid("the AP's report is not this test's")),
    }
}

async fn write(tls: &mut TlsStream<Counted>, bytes: &[u8]) -> io::Result<()> {
    timeout(IO_TIMEOUT, tls.write_all(bytes))
        .await
        .map_err(|_| io::Error::new(ErrorKind::TimedOut, "the AP is not reading"))?
}

async fn read(tls: &mut TlsStream<Counted>, buf: &mut [u8], what: &str) -> io::Result<usize> {
    let n = timeout(IO_TIMEOUT, tls.read(buf))
        .await
        .map_err(|_| io::Error::new(ErrorKind::TimedOut, format!("no {what}")))??;
    if n == 0 {
        return Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            format!("the AP closed before {what}"),
        ));
    }
    Ok(n)
}

fn invalid(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::speedtest::{AP_KEEP, KEEP};

    #[test]
    fn the_tests_kept_are_bounded_and_a_running_one_is_never_dropped() {
        let mut t = SpeedTests::default();
        t.begin_ap(0, "ap1", None);
        for id in 1..=150 {
            t.begin_ap(id, "ap2", None);
            t.end_ap(id, Err("no".into()));
        }
        assert_eq!(t.aps.len(), AP_KEEP);
        assert_eq!(t.aps.front().map(|t| t.id), Some(0));
        assert_eq!(t.aps.get(1).map(|t| t.id), Some(52));
        // A week old, it goes at the next test; the running one stays.
        for old in t.aps.iter_mut().skip(1).take(10) {
            old.at -= KEEP + Duration::from_secs(1);
        }
        t.begin_ap(151, "ap2", None);
        assert_eq!(t.aps.len(), AP_KEEP - 9);
        assert_eq!(t.aps.front().map(|t| t.id), Some(0));
        assert!(t.end_ap(0, Err("no".into())).is_some());
        assert!(t.end_ap(0, Err("again".into())).is_none(), "ended once");
    }

    #[test]
    fn a_test_opens_once_from_its_own_ap_in_time() {
        let mut t = SpeedTests::default();
        t.begin_ap(1, "ap1", None);
        assert_eq!(t.open_ap(1, "ap2"), Err("no such test runs on this AP"));
        assert_eq!(t.open_ap(2, "ap1"), Err("no such test runs on this AP"));
        assert_eq!(t.open_ap(1, "ap1"), Ok(()));
        assert_eq!(t.open_ap(1, "ap1"), Err("the test is opened already"));
        t.limits.ap.open = Duration::ZERO;
        t.begin_ap(3, "ap1", None);
        std::thread::sleep(Duration::from_millis(1));
        assert_eq!(t.open_ap(3, "ap1"), Err("opened too late"));
    }
}
