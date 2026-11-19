//! The client captures admins ask for: one at a time on each AP, on the AP
//! the client is on, bounded as the AP bounds it (at most 600 s, 50 MB, a
//! snaplen of 65535, a filter of protocol, port and host). The AP streams
//! the pcapng file in chunks; each is written, in order and within the
//! capture's size, to `<id>.pcapng` (0600) in `captures_path`, then
//! acknowledged, which lets the AP send another. A capture the AP does not
//! end in its time and a minute is ended here as lost, and one whose AP's
//! link goes ends with it. The files are kept 24 hours and 250 MB in all,
//! the oldest going first; a restarted controller starts with none.
//!
//!   POST /api/clients/{mac}/capture  {"secs": 60, "max_mb": 10, "snaplen": 128,
//!                                     "filter": {"proto": "tcp", "port": 443, "host": null}}
//!   POST /api/captures/{id}/stop
//!   GET  /api/captures/{id}/file
//!
//! Admins only, the POSTs from the UI's own page (`actions::refusal`); the
//! start and the end of each are events naming who asked.

use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::IpAddr;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use axum::body::Bytes;
use axum::extract::{Path as UrlPath, State as Ext};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use u6e_proto::mac;
use u6e_proto::msg::{
    CaptureChunk, CaptureFilter, CaptureMechanism, CaptureRequest, CaptureState, CtlMsg,
    FilterProto,
};

use crate::actions::{Via, Web, is_admin, refusal, user};
use crate::http::{error, json_response};
use crate::sessions::unix_ms;
use crate::state::{Action, Shared, State};

/// How long a capture's file is kept, and how much of them in all.
pub const KEEP: Duration = Duration::from_secs(24 * 3600);
pub const TOTAL_MAX: u64 = 250_000_000;
/// The captures remembered, newest last.
const RECORDS_MAX: usize = 32;
/// Past its time, how long a capture may still take to end.
const LATE: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq)]
pub struct Capture {
    pub id: u64,
    pub ap: String,
    pub user: Option<String>,
    pub at: SystemTime,
    pub request: CaptureRequest,
    pub running: bool,
    pub mechanism: Option<CaptureMechanism>,
    /// The file's bytes written; the AP's count of packets and drops.
    pub written: u64,
    pub packets: u64,
    pub dropped: u64,
    pub reason: String,
    pub ended: Option<SystemTime>,
    /// Whether its file is kept.
    pub file: bool,
    next_seq: u64,
}

impl Capture {
    /// Whether it ended as a capture ends: asked to, its time or size up.
    pub fn ended_well(&self) -> bool {
        matches!(
            self.reason.as_str(),
            "stopped" | "its time is up" | "its size limit is reached"
        )
    }
}

/// The captures, and where their files are (none: captures are off).
#[derive(Default)]
pub struct Captures {
    pub dir: Option<PathBuf>,
    next_id: u64,
    pub list: VecDeque<Capture>,
}

/// The filter as the events and the UI say it.
pub fn describe(f: &CaptureFilter) -> String {
    let mut parts = Vec::new();
    if let Some(p) = f.proto {
        parts.push(proto_name(p).to_owned());
    }
    if let Some(p) = f.port {
        parts.push(format!("port {p}"));
    }
    if let Some(h) = f.host {
        parts.push(format!("host {h}"));
    }
    if parts.is_empty() {
        "none".into()
    } else {
        parts.join(" ")
    }
}

fn proto_name(p: FilterProto) -> &'static str {
    match p {
        FilterProto::Tcp => "tcp",
        FilterProto::Udp => "udp",
        FilterProto::Icmp => "icmp",
        FilterProto::Arp => "arp",
    }
}

pub fn mechanism_name(m: CaptureMechanism) -> &'static str {
    match m {
        CaptureMechanism::Mirror => "mirror",
        CaptureMechanism::OffOffload => "off offload",
    }
}

impl Captures {
    /// The captures of `dir`, made if it is not there; files a controller
    /// before this one left are removed.
    pub fn open(dir: &Path) -> io::Result<Self> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        for e in fs::read_dir(dir)?.flatten() {
            if e.file_name().to_string_lossy().ends_with(".pcapng") {
                fs::remove_file(e.path())?;
            }
        }
        Ok(Captures {
            dir: Some(dir.to_owned()),
            next_id: unix_ms(SystemTime::now()),
            list: VecDeque::new(),
        })
    }

    /// The file of capture `id`, while captures are on.
    pub fn path(&self, id: u64) -> Option<PathBuf> {
        Some(self.dir.as_ref()?.join(format!("{id}.pcapng")))
    }

    pub fn get(&self, id: u64) -> Option<&Capture> {
        self.list.iter().find(|c| c.id == id)
    }

    fn running(&mut self, ap: &str, id: u64) -> Option<&mut Capture> {
        self.list
            .iter_mut()
            .find(|c| c.ap == ap && c.id == id && c.running)
    }

    /// A new capture on `ap` of `request` (its id set here), its empty file
    /// made; refused while another runs there.
    pub fn start(
        &mut self,
        ap: &str,
        user: Option<String>,
        mut request: CaptureRequest,
    ) -> Result<CaptureRequest, String> {
        if self.list.iter().any(|c| c.ap == ap && c.running) {
            return Err(format!("a capture runs on {ap}"));
        }
        self.next_id += 1;
        request.id = self.next_id;
        let path = self
            .path(request.id)
            .ok_or("captures are off: the controller has no place for their files")?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("its file: {e}"))?;
        if self.list.len() == RECORDS_MAX
            && let Some(old) = self.list.pop_front()
            && let Some(p) = self.path(old.id)
        {
            let _ = fs::remove_file(p);
        }
        self.list.push_back(Capture {
            id: request.id,
            ap: ap.to_owned(),
            user,
            at: SystemTime::now(),
            request: request.clone(),
            running: true,
            mechanism: None,
            written: 0,
            packets: 0,
            dropped: 0,
            reason: "asked for".into(),
            ended: None,
            file: true,
            next_seq: 0,
        });
        Ok(request)
    }

    /// Where `c`, the next chunk of a capture running on `ap` within its
    /// size, is to be written; why it may not be.
    pub fn chunk(&mut self, ap: &str, c: &CaptureChunk) -> Result<PathBuf, String> {
        let path = self.path(c.id).ok_or("captures are off")?;
        let cap = self.running(ap, c.id).ok_or("no such capture runs there")?;
        if c.seq != cap.next_seq {
            return Err(format!(
                "chunk {} came where {} was due",
                c.seq, cap.next_seq
            ));
        }
        if cap.written + c.data.len() as u64 > u64::from(cap.request.max_bytes) {
            return Err("the AP sent more than its size".into());
        }
        cap.next_seq += 1;
        cap.written += c.data.len() as u64;
        Ok(path)
    }

    /// Takes in the AP's state of capture `id`; the capture, when it ended.
    pub fn report(&mut self, ap: &str, s: CaptureState) -> Option<Capture> {
        let cap = self.running(ap, s.id)?;
        cap.mechanism = s.mechanism.or(cap.mechanism);
        cap.packets = s.packets;
        cap.dropped = s.dropped;
        cap.reason = s.reason;
        if s.running {
            return None;
        }
        cap.running = false;
        cap.ended = Some(SystemTime::now());
        Some(cap.clone())
    }

    /// Ends capture `id` on `ap` for `why`, if it runs; the capture.
    pub fn end(&mut self, ap: &str, id: u64, why: &str) -> Option<Capture> {
        let cap = self.running(ap, id)?;
        cap.running = false;
        cap.reason = why.into();
        cap.ended = Some(SystemTime::now());
        Some(cap.clone())
    }

    /// The captures still running past their time and a minute, at `now`.
    pub fn overdue(&self, now: SystemTime) -> Vec<(String, u64)> {
        let late = |c: &Capture| {
            let due = c.at + Duration::from_secs(u64::from(c.request.secs)) + LATE;
            c.running && now > due
        };
        self.list
            .iter()
            .filter(|c| late(c))
            .map(|c| (c.ap.clone(), c.id))
            .collect()
    }

    /// The files no longer kept at `now`, their records marked so: past
    /// [`KEEP`], then the oldest ended ones beyond [`TOTAL_MAX`].
    pub fn expired(&mut self, now: SystemTime) -> Vec<PathBuf> {
        let mut gone = Vec::new();
        for c in self.list.iter_mut().filter(|c| c.file && !c.running) {
            let old = c
                .ended
                .is_some_and(|e| now.duration_since(e).unwrap_or_default() > KEEP);
            if old {
                c.file = false;
                gone.push(c.id);
            }
        }
        let mut total: u64 = self.list.iter().filter(|c| c.file).map(|c| c.written).sum();
        for c in self.list.iter_mut().filter(|c| c.file && !c.running) {
            if total <= TOTAL_MAX {
                break;
            }
            total -= c.written;
            c.file = false;
            gone.push(c.id);
        }
        gone.into_iter().filter_map(|id| self.path(id)).collect()
    }
}

/// What the event of a capture's start or end says.
pub fn summary(c: &Capture) -> String {
    let r = &c.request;
    if c.running {
        return format!(
            "{} s at most, {} MB, {} B a packet, filter {}",
            r.secs,
            r.max_bytes / 1_000_000,
            r.snaplen,
            describe(&r.filter)
        );
    }
    let how = c.mechanism.map_or("", |m| match m {
        CaptureMechanism::Mirror => "; mirrored by the NSS",
        CaptureMechanism::OffOffload => "; taken off the offload",
    });
    format!(
        "{}: {} B, {} packets, {} dropped{how}",
        c.reason, c.written, c.packets, c.dropped
    )
}

/// Records `c`'s start or end as an action of its user's.
pub fn record(state: &mut State, c: &Capture, ok: bool) {
    state.record(Action {
        at: SystemTime::now(),
        user: c.user.clone(),
        action: "capture",
        mac: Some(c.request.mac),
        ap: Some(c.ap.clone()),
        ok,
        detail: summary(c),
    });
}

/// The captures as the UI shows them, newest first.
pub fn view(state: &State) -> Value {
    let list = state.captures.list.iter().rev().map(|c| {
        let r = &c.request;
        json!({
            "id": c.id.to_string(),
            "ap": c.ap,
            "mac": mac::format(r.mac),
            "user": c.user,
            "at": unix_ms(c.at),
            "secs": r.secs,
            "max_bytes": r.max_bytes,
            "snaplen": r.snaplen,
            "filter": describe(&r.filter),
            "running": c.running,
            "mechanism": c.mechanism.map(mechanism_name),
            "bytes": c.written,
            "packets": c.packets,
            "dropped": c.dropped,
            "reason": c.reason,
            "ended": c.ended.map(unix_ms),
            "file": c.file && !c.running,
        })
    });
    Value::Array(list.collect())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FilterBody {
    proto: Option<String>,
    port: Option<u16>,
    host: Option<IpAddr>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartBody {
    secs: u16,
    max_mb: u32,
    snaplen: u16,
    filter: FilterBody,
}

/// The request a body asks for, checked as the AP checks it.
fn request(m: [u8; 6], b: StartBody) -> Result<CaptureRequest, &'static str> {
    let proto = match b.filter.proto.as_deref() {
        None => None,
        Some("tcp") => Some(FilterProto::Tcp),
        Some("udp") => Some(FilterProto::Udp),
        Some("icmp") => Some(FilterProto::Icmp),
        Some("arp") => Some(FilterProto::Arp),
        Some(_) => return Err("the protocol is tcp, udp, icmp or arp"),
    };
    let r = CaptureRequest {
        id: 0,
        mac: m,
        secs: b.secs,
        max_bytes: b.max_mb.saturating_mul(1_000_000),
        snaplen: b.snaplen,
        filter: CaptureFilter {
            proto,
            port: b.filter.port,
            host: b.filter.host,
        },
    };
    r.check()?;
    Ok(r)
}

/// `POST /api/clients/{mac}/capture`: 202 with the capture's id.
pub async fn start(
    Ext(web): Ext<Web>,
    UrlPath(m): UrlPath<String>,
    req: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(why) = refusal(&req, &web.access, Via::Post, &format!("capture {m}")) {
        return error(StatusCode::FORBIDDEN, why);
    }
    let Some(m) = mac::parse(&m).filter(|m| mac::is_station(*m)) else {
        return error(StatusCode::BAD_REQUEST, "not a station's MAC");
    };
    let Ok(b) = serde_json::from_slice::<StartBody>(&body) else {
        return error(
            StatusCode::BAD_REQUEST,
            "not {\"secs\", \"max_mb\", \"snaplen\", \"filter\": {\"proto\", \"port\", \"host\"}}",
        );
    };
    let r = match request(m, b) {
        Ok(r) => r,
        Err(why) => return error(StatusCode::BAD_REQUEST, why),
    };
    let who = user(&req);
    let mut state = web.state.write();
    let Some(ap) = state
        .clients()
        .into_iter()
        .find(|c| c.station.mac == m)
        .map(|c| c.ap)
    else {
        return error(StatusCode::NOT_FOUND, "not associated");
    };
    let started = state.captures.start(&ap, who, r);
    let count = |state: &mut State, result| {
        *state.action_counts.entry(("capture", result)).or_default() += 1;
    };
    let r = match started {
        Ok(r) => r,
        Err(why) => {
            count(&mut state, "failed");
            return error(StatusCode::CONFLICT, &why);
        }
    };
    if !state.tell(&ap, CtlMsg::CaptureStart(r.clone())) {
        let gone = state.captures.end(&ap, r.id, "the AP is not connected");
        if let Some(c) = gone {
            record(&mut state, &c, false);
        }
        count(&mut state, "failed");
        return error(StatusCode::BAD_GATEWAY, "the AP is not connected");
    }
    count(&mut state, "ok");
    if let Some(c) = state.captures.get(r.id).cloned() {
        record(&mut state, &c, true);
    }
    state.captures_changed();
    let body = json!({ "id": r.id.to_string(), "ap": ap });
    (StatusCode::ACCEPTED, json_response(&body)).into_response()
}

fn id_of(s: &str) -> Option<u64> {
    s.parse().ok()
}

/// `POST /api/captures/{id}/stop`: the AP is asked to stop; its end comes
/// as an event.
pub async fn stop(Ext(web): Ext<Web>, UrlPath(id): UrlPath<String>, req: HeaderMap) -> Response {
    if let Some(why) = refusal(&req, &web.access, Via::Post, &format!("stop capture {id}")) {
        return error(StatusCode::FORBIDDEN, why);
    }
    let mut state = web.state.write();
    let Some(c) = id_of(&id).and_then(|id| state.captures.get(id)).cloned() else {
        return error(StatusCode::NOT_FOUND, "no such capture");
    };
    if !c.running {
        return error(StatusCode::CONFLICT, "it ended");
    }
    let told = state.tell(&c.ap, CtlMsg::CaptureStop { id: c.id });
    state.record(Action {
        at: SystemTime::now(),
        user: user(&req),
        action: "capture",
        mac: Some(c.request.mac),
        ap: Some(c.ap.clone()),
        ok: told,
        detail: if told {
            "stop asked".into()
        } else {
            "stop asked: the AP is not connected".into()
        },
    });
    if !told {
        return error(StatusCode::BAD_GATEWAY, "the AP is not connected");
    }
    (StatusCode::ACCEPTED, json_response(&json!({ "ok": true }))).into_response()
}

/// `GET /api/captures/{id}/file`: the pcapng file, to an admin.
pub async fn file(Ext(web): Ext<Web>, UrlPath(id): UrlPath<String>, req: HeaderMap) -> Response {
    if !is_admin(&req, &web.access.admin_group) {
        return error(StatusCode::FORBIDDEN, "not an admin");
    }
    let found = {
        let state = web.state.read();
        id_of(&id).and_then(|id| {
            let c = state.captures.get(id).filter(|c| c.file && !c.running)?;
            Some((state.captures.path(id)?, c.clone()))
        })
    };
    let Some((path, c)) = found else {
        return error(StatusCode::NOT_FOUND, "no such file");
    };
    let read = tokio::task::spawn_blocking(move || fs::read(path)).await;
    let Ok(Ok(bytes)) = read else {
        return error(StatusCode::NOT_FOUND, "no such file");
    };
    let name = format!(
        "{}-{}-{}.pcapng",
        c.ap.replace(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-', "_"),
        mac::format(c.request.mac).replace(':', ""),
        unix_ms(c.at) / 1000
    );
    let headers = [
        (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
        (
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{name}\""),
        ),
        (header::CACHE_CONTROL, "no-store".to_owned()),
    ];
    (headers, bytes).into_response()
}

/// Writes the chunks a session took in, each then acknowledged; a capture
/// whose chunk cannot be written is ended and the AP told to stop it. The
/// messages for the AP, in order.
pub async fn write(state: &Shared, ap: &str, chunks: Vec<(PathBuf, CaptureChunk)>) -> Vec<CtlMsg> {
    let mut out = Vec::new();
    for (path, c) in chunks {
        let (id, seq) = (c.id, c.seq);
        let wrote = tokio::task::spawn_blocking(move || {
            let mut f = OpenOptions::new().append(true).open(&path)?;
            f.write_all(&c.data)
        })
        .await
        .unwrap_or_else(|e| Err(io::Error::other(e)));
        match wrote {
            Ok(()) => {
                state.write().captures_changed();
                out.push(CtlMsg::CaptureAck { id, seq });
            }
            Err(e) => {
                let mut s = state.write();
                if let Some(c) = s.captures.end(ap, id, &format!("its file: {e}")) {
                    record(&mut s, &c, false);
                    s.captures_changed();
                }
                out.push(CtlMsg::CaptureStop { id });
            }
        }
    }
    out
}

/// Ends the captures past their time and removes the files no longer kept.
pub fn supervise(state: &Shared, now: SystemTime) {
    let gone = {
        let mut s = state.write();
        let overdue = s.captures.overdue(now);
        let mut changed = !overdue.is_empty();
        for (ap, id) in overdue {
            if let Some(c) = s
                .captures
                .end(&ap, id, "lost: the AP did not end it in its time")
            {
                record(&mut s, &c, false);
                s.tell(&ap, CtlMsg::CaptureStop { id });
            }
        }
        let gone = s.captures.expired(now);
        changed |= !gone.is_empty();
        if changed {
            s.captures_changed();
        }
        gone
    };
    for p in gone {
        if let Err(e) = fs::remove_file(&p)
            && e.kind() != io::ErrorKind::NotFound
        {
            eprintln!("u6e-controller: {}: {e}", p.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;

    fn request(secs: u16) -> CaptureRequest {
        CaptureRequest {
            id: 0,
            mac: [2, 0, 0, 0, 0, 1],
            secs,
            max_bytes: 1_000_000,
            snaplen: 128,
            filter: CaptureFilter {
                proto: Some(FilterProto::Tcp),
                port: Some(443),
                host: None,
            },
        }
    }

    fn chunk(id: u64, seq: u64, len: usize) -> CaptureChunk {
        CaptureChunk {
            id,
            seq,
            data: vec![0; len],
        }
    }

    fn ended(id: u64, reason: &str) -> CaptureState {
        CaptureState {
            id,
            running: false,
            mechanism: Some(CaptureMechanism::OffOffload),
            bytes: 0,
            packets: 7,
            dropped: 1,
            reason: reason.into(),
        }
    }

    #[test]
    fn one_capture_an_ap_its_chunks_in_order_and_within_its_size() {
        let t = TestDir::new();
        fs::write(t.path().join("9.pcapng"), "left").unwrap();
        let mut c = Captures::open(t.path()).unwrap();
        assert!(
            !t.path().join("9.pcapng").exists(),
            "a restart starts with none"
        );
        let r = c.start("ap1", Some("alice".into()), request(60)).unwrap();
        assert!(c.start("ap1", None, request(60)).is_err());
        let other = c.start("ap2", None, request(60)).unwrap();
        assert_ne!(r.id, other.id);
        assert!(c.path(r.id).unwrap().exists());
        assert_eq!(
            c.chunk("ap1", &chunk(r.id, 0, 10)).unwrap(),
            c.path(r.id).unwrap()
        );
        assert!(c.chunk("ap1", &chunk(r.id, 2, 10)).is_err(), "out of order");
        assert!(c.chunk("ap2", &chunk(r.id, 1, 10)).is_err(), "another AP's");
        assert!(
            c.chunk("ap1", &chunk(r.id, 1, 1_000_000)).is_err(),
            "past its size"
        );
        c.chunk("ap1", &chunk(r.id, 1, 20)).unwrap();
        let mut running = ended(r.id, "started");
        running.running = true;
        assert!(c.report("ap1", running).is_none());
        let done = c.report("ap1", ended(r.id, "stopped")).unwrap();
        assert!(!done.running && done.ended_well());
        assert_eq!((done.written, done.packets, done.dropped), (30, 7, 1));
        assert_eq!(
            summary(&done),
            "stopped: 30 B, 7 packets, 1 dropped; taken off the offload"
        );
        assert!(
            c.start("ap1", None, request(60)).is_ok(),
            "the next may start"
        );
    }

    #[test]
    fn a_late_capture_is_lost_and_old_files_go() {
        let t = TestDir::new();
        let mut c = Captures::open(t.path()).unwrap();
        let r = c.start("ap1", None, request(10)).unwrap();
        let now = SystemTime::now();
        assert!(c.overdue(now).is_empty());
        let late = now + Duration::from_secs(10) + LATE + Duration::from_secs(1);
        assert_eq!(c.overdue(late), [("ap1".to_owned(), r.id)]);
        c.end("ap1", r.id, "lost").unwrap();
        assert!(c.expired(late).is_empty());
        let day = late + KEEP + Duration::from_secs(1);
        assert_eq!(c.expired(day), [c.path(r.id).unwrap()]);
        assert!(!c.get(r.id).unwrap().file);
        // Beyond the total, the oldest ended goes first.
        let mut c = Captures::open(t.path()).unwrap();
        let ids: Vec<u64> = (0..3)
            .map(|_| {
                let r = c.start("ap1", None, request(10)).unwrap();
                c.list.back_mut().unwrap().written = TOTAL_MAX / 2;
                c.end("ap1", r.id, "stopped");
                r.id
            })
            .collect();
        assert_eq!(c.expired(SystemTime::now()), [c.path(ids[0]).unwrap()]);
    }

    #[test]
    fn off_without_a_place_for_files() {
        let mut c = Captures::default();
        assert!(c.start("ap1", None, request(10)).is_err());
    }
}
