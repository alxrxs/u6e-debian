//! RADIUS's verdicts on the clients, read where the RADIUS servers already
//! ship their authentication log: a Loki (`[radius] loki`, `host:port`),
//! queried read-only for the log's stream (`[radius] selector`). The
//! controller never speaks to the RADIUS servers, and nothing waits on Loki:
//! a poller reads it every [`EVERY`] into the clients' timelines
//! (`sessions`), so without it only RADIUS's side of the story is missing.
//!
//! The log has a line per verdict, fields split by `|`:
//!
//!   time|ACCEPT or REJECT|User-Name|Calling-Station-Id|NAS name|NAS address|detail[|cert expiry]
//!
//! the detail being the method on an accept and the reason on a reject, the
//! last field (which older lines lack) the expiry of the client certificate
//! of an EAP-TLS login, as the certificate states it (ASN.1 UTCTime or
//! GeneralizedTime). Only lines whose Calling-Station-Id is a MAC are asked
//! for: the Wi-Fi's (and any other NAS's that names a MAC).
//!
//! Each poll reads from [`LAG`] before the newest line read so far (the
//! shipper's delay), the lines already taken skipped; the first goes on from
//! the newest line the clients' history holds, or back [`BACKFILL`] (the
//! history takes a line it holds already only once). A poll reads at most [`PAGES`] pages of [`PAGE`] lines, each
//! answer at most [`BODY_MAX`] bytes within [`TIMEOUT`]; what it could not
//! read is read at the next.

use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::{Duration, SystemTime};

use serde_json::Value;
use tokio::time::interval;
use u6e_proto::mac;

use crate::fetch;
use crate::state::Shared;

/// How often Loki is read.
pub const EVERY: Duration = Duration::from_secs(60);
/// How far behind the newest line read the next poll starts.
const LAG: Duration = Duration::from_secs(300);
/// How far back the first poll reads: as long as the timelines keep.
const BACKFILL: Duration = Duration::from_secs(7 * 24 * 3600);
const PAGE: usize = 1000;
const PAGES: usize = 10;
const TIMEOUT: Duration = Duration::from_secs(10);
const BODY_MAX: usize = 4 << 20;
/// The longest field kept of a line: User-Name's own limit.
const FIELD_MAX: usize = 253;

/// Where the log is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Loki's `host:port`.
    pub loki: String,
    /// The LogQL stream selector of the log, `{job="..."}`.
    pub selector: String,
}

/// How the reads of the log go, for the metrics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Health {
    /// Whether the last read worked (`None` before the first).
    pub up: Option<bool>,
    pub last_ok: Option<SystemTime>,
}

/// One verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// When Loki has it, in Unix milliseconds.
    pub at_ms: u64,
    /// The client, as its Calling-Station-Id.
    pub mac: [u8; 6],
    pub accept: bool,
    pub user: String,
    /// The RADIUS server that answered (the stream's `host`).
    pub node: String,
    /// The RADIUS client's name.
    pub nas: String,
    pub detail: String,
    /// The client certificate's expiry, Unix seconds.
    pub cert_expires: Option<u64>,
}

/// The verdict of one line of the log, which Loki has at `at_ms` from the
/// node `node`; `None` for a line that is not one.
pub fn parse(text: &str, at_ms: u64, node: &str) -> Option<Line> {
    let mut f = text.splitn(7, '|');
    let _time = f.next()?;
    let accept = match f.next()? {
        "ACCEPT" => true,
        "REJECT" => false,
        _ => return None,
    };
    let user = f.next()?;
    let mac = mac::parse(&f.next()?.replace('-', ":"))?;
    let nas = f.next()?;
    let _nas_address = f.next()?;
    let rest = f.next()?;
    // A line of the shape with the expiry ends in it, or in nothing.
    let (detail, cert_expires) = match rest.rsplit_once('|') {
        Some((d, "")) => (d, None),
        Some((d, e)) => match asn1_time(e) {
            Some(t) => (d, Some(t)),
            None => (rest, None),
        },
        None => (rest, None),
    };
    Some(Line {
        at_ms,
        mac,
        accept,
        user: field(user),
        node: field(node),
        nas: field(nas),
        detail: field(detail),
        cert_expires,
    })
}

/// A field as kept: one line, without control characters, within
/// [`FIELD_MAX`] bytes.
fn field(s: &str) -> String {
    let mut out: String = s.chars().filter(|c| !c.is_control()).collect();
    if out.len() > FIELD_MAX {
        let cut = (0..=FIELD_MAX).rev().find(|&i| out.is_char_boundary(i));
        out.truncate(cut.unwrap_or(0));
    }
    out
}

/// An X.509 time, `YYMMDDHHMMSSZ` (UTCTime, years 1950 to 2049) or
/// `YYYYMMDDHHMMSSZ` (GeneralizedTime), in Unix seconds.
pub fn asn1_time(s: &str) -> Option<u64> {
    let digits = s.strip_suffix('Z')?;
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n = |r: std::ops::Range<usize>| digits[r].parse::<u64>().ok();
    let (year, rest) = match digits.len() {
        12 => {
            let yy = n(0..2)?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, 2)
        }
        14 => (n(0..4)?, 4),
        _ => return None,
    };
    let (month, day) = (n(rest..rest + 2)?, n(rest + 2..rest + 4)?);
    let (h, m, sec) = (
        n(rest + 4..rest + 6)?,
        n(rest + 6..rest + 8)?,
        n(rest + 8..rest + 10)?,
    );
    let valid =
        (1..=12).contains(&month) && (1..=31).contains(&day) && h < 24 && m < 60 && sec < 61;
    if !valid || year < 1970 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + h * 3600 + m * 60 + sec)
}

/// Days from 1970-01-01 to the date (Howard Hinnant's algorithm), for
/// dates from 1970 on.
fn days_from_civil(y: u64, m: u64, d: u64) -> u64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The LogQL of the lines of `selector` whose Calling-Station-Id is a MAC.
fn query(selector: &str) -> String {
    let mac = "([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}";
    format!(r#"{selector} |~ "^[^|]*[|][A-Z]+[|][^|]*[|]{mac}[|]""#)
}

/// The lines of an answer of `query_range`, oldest first, each with its
/// time in nanoseconds; `None` for an answer that is not one.
fn lines(answer: &str) -> Option<Vec<(u64, Line)>> {
    let v: Value = serde_json::from_str(answer).ok()?;
    if v["status"] != "success" {
        return None;
    }
    let mut out = Vec::new();
    for stream in v["data"]["result"].as_array()? {
        let node = stream["stream"]["host"].as_str().unwrap_or_default();
        for pair in stream["values"].as_array()? {
            let ns: u64 = pair[0].as_str()?.parse().ok()?;
            let Some(text) = pair[1].as_str() else {
                continue;
            };
            if let Some(l) = parse(text, ns / 1_000_000, node) {
                out.push((ns, l));
            }
        }
    }
    out.sort_by_key(|(ns, _)| *ns);
    Some(out)
}

/// What the poller remembers between polls.
struct Cursor {
    /// Where the next poll starts, in nanoseconds since the epoch.
    from_ns: u64,
    /// The lines taken since `from_ns` less a lag, by time and hash.
    taken: HashSet<(u64, u64)>,
}

fn nanos(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

fn key(ns: u64, l: &Line) -> (u64, u64) {
    let mut h = DefaultHasher::new();
    (
        l.mac,
        l.accept,
        &l.user,
        &l.node,
        &l.nas,
        &l.detail,
        l.cert_expires,
    )
        .hash(&mut h);
    (ns, h.finish())
}

impl Cursor {
    /// A cursor at `now`, going on from `resume_ms` (the newest line the
    /// history holds), but never further back than [`BACKFILL`].
    fn new(now: SystemTime, resume_ms: Option<u64>) -> Self {
        let back = nanos(now).saturating_sub(BACKFILL.as_nanos() as u64);
        let resume = resume_ms.map_or(0, |ms| {
            (ms * 1_000_000).saturating_sub(LAG.as_nanos() as u64)
        });
        Cursor {
            from_ns: back.max(resume),
            taken: HashSet::new(),
        }
    }

    /// One poll at `now`: the lines not taken before, or why it failed.
    async fn poll(&mut self, s: &Settings, now: SystemTime) -> Result<Vec<Line>, String> {
        let q = fetch::query_value(&query(&s.selector));
        let end = nanos(now);
        let mut start = self.from_ns;
        let mut fresh = Vec::new();
        let mut newest = None;
        for _ in 0..PAGES {
            let target = format!(
                "/loki/api/v1/query_range?query={q}&start={start}&end={end}&limit={PAGE}&direction=forward"
            );
            let answer =
                fetch::get(&s.loki, &target, "application/json", BODY_MAX, TIMEOUT).await?;
            let page = lines(&answer).ok_or("Loki's answer is not a list of lines")?;
            let full = page.len() >= PAGE;
            for (ns, l) in page {
                newest = newest.max(Some(ns));
                start = start.max(ns);
                if self.taken.insert(key(ns, &l)) {
                    fresh.push(l);
                }
            }
            if !full {
                break;
            }
        }
        let lag = LAG.as_nanos() as u64;
        self.from_ns = newest.unwrap_or(end).saturating_sub(lag).max(self.from_ns);
        let from = self.from_ns;
        self.taken.retain(|(ns, _)| *ns >= from);
        Ok(fresh)
    }
}

/// Reads the log every [`EVERY`] for the life of the process, into the
/// state; a change of whether it can be read is logged once.
pub async fn supervise(state: Shared, settings: Settings) {
    let mut every = interval(EVERY);
    let resume = state.read().sessions.radius_newest();
    let mut cursor = Cursor::new(SystemTime::now(), resume);
    loop {
        every.tick().await;
        let now = SystemTime::now();
        let read = cursor.poll(&settings, now).await;
        let was = state.read().radius.as_ref().and_then(|h| h.up);
        if was != Some(read.is_ok()) {
            match &read {
                Ok(l) => eprintln!(
                    "u6e-controller: RADIUS log from {}: {} lines",
                    settings.loki,
                    l.len()
                ),
                Err(e) => eprintln!("u6e-controller: RADIUS log from {}: {e}", settings.loki),
            }
        }
        state.write().take_radius(read.map_err(|_| ()), now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    const MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x21];
    const OLD: &str =
        "2026-11-19 17:10:51|ACCEPT|user@example.org|02-00-00-00-00-21|ap1|192.0.2.17|eap";

    /// The log's lines as they are, without and with the expiry.
    #[test]
    fn both_shapes_of_line_parse() {
        let l = parse(OLD, 1_795_101_051_000, "radius1.example.org").unwrap();
        assert_eq!(
            l,
            Line {
                at_ms: 1_795_101_051_000,
                mac: MAC,
                accept: true,
                user: "user@example.org".into(),
                node: "radius1.example.org".into(),
                nas: "ap1".into(),
                detail: "eap".into(),
                cert_expires: None,
            }
        );
        let new = format!("{OLD}|271231235959Z");
        assert_eq!(
            parse(&new, 0, "").unwrap().cert_expires,
            Some(1_830_297_599)
        );
        let l = parse(&format!("{OLD}|"), 0, "").unwrap();
        assert_eq!((l.detail.as_str(), l.cert_expires), ("eap", None));
        let reject = "t|REJECT|02-00-00-00-00-21|02-00-00-00-00-21|ap1|192.0.2.16|\
                      No Auth-Type found: rejecting the user via Post-Auth-Type = Reject|";
        let l = parse(reject, 0, "").unwrap();
        assert!(!l.accept);
        assert_eq!(
            l.detail,
            "No Auth-Type found: rejecting the user via Post-Auth-Type = Reject"
        );
        // A reason with a | of its own keeps it, in either shape.
        let piped = "t|REJECT|u|02:00:00:00:00:21|ap1|192.0.2.16|bad | worse";
        assert_eq!(parse(piped, 0, "").unwrap().detail, "bad | worse");
        let piped = format!("{piped}|");
        assert_eq!(parse(&piped, 0, "").unwrap().detail, "bad | worse");
    }

    #[test]
    fn what_is_not_a_verdict_is_none() {
        for l in [
            "t|UNKNOWN|u|02-00-00-00-00-21|ap1|192.0.2.16|",
            "t|ACCEPT|u|192.0.2.99|vpn1|192.0.2.1|kcbridge",
            "t|ACCEPT|u",
            "",
        ] {
            assert_eq!(parse(l, 0, ""), None, "{l}");
        }
    }

    #[test]
    fn x509_times_read_in_both_forms() {
        assert_eq!(asn1_time("700101000000Z"), Some(0));
        assert_eq!(asn1_time("271231235959Z"), Some(1_830_297_599));
        assert_eq!(asn1_time("20271231235959Z"), Some(1_830_297_599));
        assert_eq!(asn1_time("20500101000000Z"), Some(2_524_608_000));
        assert_eq!(asn1_time("490101000000Z"), Some(2_493_072_000));
        for bad in [
            "",
            "Z",
            "271231235959",
            "271331235959Z",
            "2712312359Z",
            "27123123595aZ",
            "19691231235959Z",
        ] {
            assert_eq!(asn1_time(bad), None, "{bad}");
        }
    }

    /// Loki's answer: two streams, out of order, and a line that is no
    /// verdict.
    #[test]
    fn an_answer_gives_its_lines_in_time_order() {
        let answer = r#"{"status":"success","data":{"resultType":"streams","result":[
            {"stream":{"host":"r2"},"values":[["3000000","t|REJECT|u|02-00-00-00-00-21|ap1|192.0.2.16|no"]]},
            {"stream":{"host":"r1"},"values":[["1000000","t|ACCEPT|u|02-00-00-00-00-21|ap1|192.0.2.16|eap"],
                                              ["2000000","t|UNKNOWN|u|02-00-00-00-00-21|ap1|192.0.2.16|"]]}]}}"#;
        let got = lines(answer).unwrap();
        let summary: Vec<_> = got
            .iter()
            .map(|(ns, l)| (*ns, l.accept, l.node.as_str()))
            .collect();
        assert_eq!(summary, [(1_000_000, true, "r1"), (3_000_000, false, "r2")]);
        assert_eq!(got[0].1.at_ms, 1);
        assert_eq!(lines(r#"{"status":"error"}"#), None);
        assert_eq!(lines("<html>"), None);
    }

    /// A fake Loki answering each request with the next of `answers`,
    /// telling what it was asked.
    async fn loki(answers: Vec<String>) -> (String, mpsc::UnboundedReceiver<String>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            for body in answers {
                let (mut s, _) = l.accept().await.unwrap();
                let mut buf = vec![0; 8192];
                let n = s.read(&mut buf).await.unwrap();
                let _ = tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
                let head = "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n";
                s.write_all(format!("{head}{body}").as_bytes())
                    .await
                    .unwrap();
            }
        });
        (addr, rx)
    }

    fn answer(lines: &[(u64, &str)]) -> String {
        let values: Vec<Value> = lines
            .iter()
            .map(|(ns, l)| serde_json::json!([ns.to_string(), l]))
            .collect();
        let stream = serde_json::json!({"stream": {"host": "r1"}, "values": values});
        serde_json::json!({"status": "success", "data": {"result": [stream]}}).to_string()
    }

    fn settings(loki: String) -> Settings {
        Settings {
            loki,
            selector: r#"{job="radius"}"#.into(),
        }
    }

    /// The second poll overlaps the first by the lag and takes only what
    /// is new; the query asks for the selector's lines that name a MAC.
    #[tokio::test]
    async fn overlapping_polls_take_each_line_once() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let ns = nanos(now);
        let a = (ns - 60_000_000_000, OLD);
        let b = (
            ns - 1_000_000_000,
            "t|REJECT|u|02-00-00-00-00-21|ap1|192.0.2.16|no",
        );
        let with_expiry = format!("{OLD}|271231235959Z");
        let c = (ns + 30_000_000_000, with_expiry.as_str());
        let (addr, mut asked) = loki(vec![answer(&[a, b]), answer(&[a, b, c])]).await;
        let s = settings(addr);
        let mut cursor = Cursor::new(now, None);
        assert_eq!(cursor.poll(&s, now).await.unwrap().len(), 2);
        let req = asked.recv().await.unwrap();
        let q = "GET /loki/api/v1/query_range?query=%7Bjob%3D%22radius%22%7D%20%7C~%20%22%5E";
        assert!(req.starts_with(q), "{req}");
        let backfill = ns - BACKFILL.as_nanos() as u64;
        assert!(req.contains(&format!("&start={backfill}&")), "{req}");
        let second = cursor
            .poll(&s, now + Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].cert_expires, Some(1_830_297_599));
        let req = asked.recv().await.unwrap();
        let from = b.0 - LAG.as_nanos() as u64;
        assert!(req.contains(&format!("&start={from}&")), "{req}");
    }

    /// A restarted controller reads on from what its history holds, never
    /// further back than the backfill.
    #[test]
    fn a_cursor_goes_on_from_the_history() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let lag = LAG.as_nanos() as u64;
        let held = Cursor::new(now, Some(1_799_999_000_000));
        assert_eq!(held.from_ns, 1_799_999_000_000_000_000 - lag);
        let old = Cursor::new(now, Some(1_000));
        assert_eq!(old.from_ns, nanos(now) - BACKFILL.as_nanos() as u64);
    }

    /// A Loki that answers nonsense, or nothing, is an error in time, and
    /// the window it failed on is read again.
    #[tokio::test]
    async fn a_broken_loki_is_an_error_in_time() {
        let now = SystemTime::now();
        let (addr, _asked) = loki(vec!["<html>".into()]).await;
        let mut cursor = Cursor::new(now, None);
        let from = cursor.from_ns;
        assert!(cursor.poll(&settings(addr), now).await.is_err());
        assert_eq!(cursor.from_ns, from);
        let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = silent.local_addr().unwrap().to_string();
        let t = std::time::Instant::now();
        let wait = Duration::from_millis(300);
        let r = fetch::get(&addr, "/", "application/json", BODY_MAX, wait).await;
        assert!(r.is_err());
        assert!(t.elapsed() < Duration::from_secs(2));
    }
}
