//! RADIUS's verdicts on the clients, read where the RADIUS servers already
//! ship their authentication log: a Loki (`[radius] loki`, `host:port`),
//! queried read-only for the log's stream (`[radius] selector`). The
//! controller never speaks to the RADIUS servers, and nothing waits on Loki:
//! a poller reads it every [`EVERY`] into the clients' timelines
//! (`sessions`), so without it only RADIUS's side of the story is missing.
//!
//! The log has a line per verdict, nine fields split by `|`:
//!
//!   time|ACCEPT or REJECT|User-Name|Calling-Station-Id|NAS name|NAS address|detail|cert expiry|cert CN
//!
//! the detail being the method on an accept and the reason on a reject; the
//! last two the EAP-TLS client certificate's expiry, as the certificate
//! states it (ASN.1 UTCTime or GeneralizedTime), and its common name. What a
//! client chooses (User-Name, the reason that may quote it, the CN) is
//! escaped by FreeRADIUS's `%{escape:}`, every byte outside its safe set
//! written `=XX`, so no field holds a `|`; they are read back here. A line of
//! seven fields is one from before (unescaped, nothing after the detail); a
//! line of any other count, or whose expiry is neither empty nor a time, is
//! no verdict: it cannot be one the log wrote. Only lines whose
//! Calling-Station-Id is a MAC are asked for.
//!
//! A page goes on from the newest line Loki returned, a verdict or not, so
//! lines that are none (which an unauthenticated client can make) cannot
//! hold the reader in place; a full page of a single instant (the shipper
//! stamps whole seconds, and Loki pages by time alone) goes on a nanosecond
//! past it, the instant's rest unread, said in the journal. Each poll reads
//! from [`LAG`] before the newest line returned (the shipper's delay) once it
//! read to the end, and from where it stopped when it stopped at [`PAGES`]
//! pages of [`PAGE`] lines, so a flood cannot hold it in place either. The
//! first poll goes on from the newest line the clients' history holds, or
//! back [`BACKFILL`]. Every [`RESCAN_EVERY`] the last [`RESCAN`] are read
//! again, for lines stamped behind the cursor (the shipper stamps each with
//! its own local time, so on the autumn clock change the repeated hour's
//! lines land an hour early, and a shipper that was down sends its backlog
//! late). A line is handed over once: the lines delivered over the rescan's
//! window and the cursor's are remembered (at most [`TAKEN_MAX`]), and only
//! once the whole poll worked, so a poll that fails part way hands its lines
//! over at the next. Each answer is at most [`BODY_MAX`] bytes within
//! [`TIMEOUT`].
//!
//! Several Lokis that each receive the whole log (`[radius] loki`, a list)
//! are taken in turn: each page is asked of the one that answered last, and
//! of the next only when it fails, the change logged once. The cursor and
//! what was delivered are the lines', whichever Loki gave them, so a poll
//! read partly from each is the same poll. With `[radius] tls` every Loki
//! is read over mutual TLS (`mtls`), its failures counted.

use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::{Duration, SystemTime};

use serde_json::Value;
use tokio::time::interval;
use u6e_proto::{mac, text};

use crate::fetch;
use crate::mtls::{self, Endpoint, Failure};
use crate::state::Shared;

/// How often Loki is read.
pub const EVERY: Duration = Duration::from_secs(60);
/// How far behind the newest line read the next poll starts.
const LAG: Duration = Duration::from_secs(300);
/// How far back the first poll reads: as long as the timelines keep.
const BACKFILL: Duration = Duration::from_secs(7 * 24 * 3600);
/// How often, and how far back, the log is read again.
const RESCAN_EVERY: Duration = Duration::from_secs(3600);
const RESCAN: Duration = Duration::from_secs(2 * 3600);
const PAGE: usize = 1000;
const PAGES: usize = 10;
/// The most lines remembered as delivered.
const TAKEN_MAX: usize = 200_000;
const TIMEOUT: Duration = Duration::from_secs(10);
const BODY_MAX: usize = 4 << 20;
/// The longest field kept of a line: User-Name's own limit.
const FIELD_MAX: usize = 253;

/// Where the log is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Each Loki's `host:port`, in the order they are tried.
    pub loki: Vec<String>,
    /// The LogQL stream selector of the log, `{job="..."}`.
    pub selector: String,
    /// The certificate the Lokis are read with over mutual TLS.
    pub tls: Option<mtls::Files>,
}

/// How the reads of the log go, for the metrics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Health {
    /// Whether the last read worked (`None` before the first).
    pub up: Option<bool>,
    pub last_ok: Option<SystemTime>,
    /// When the newest verdict read happened, in Unix milliseconds.
    pub newest_ms: Option<u64>,
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
    /// The client certificate's expiry (Unix seconds) and common name.
    pub cert_expires: Option<u64>,
    pub cert_cn: Option<String>,
}

/// The verdict of one line of the log, which Loki has at `at_ms` from the
/// node `node`; `None` for a line that is not one.
pub fn parse(line: &str, at_ms: u64, node: &str) -> Option<Line> {
    let f: Vec<&str> = line.split('|').collect();
    let (escaped, cert_expires, cert_cn) = match f.len() {
        7 => (false, None, None),
        9 => {
            let expires = match f[7] {
                "" => None,
                t => Some(asn1_time(&unescape(t))?),
            };
            let cn = Some(field(&unescape(f[8]))).filter(|cn| !cn.is_empty());
            (true, expires, cn.filter(|_| expires.is_some()))
        }
        _ => return None,
    };
    let accept = match f[1] {
        "ACCEPT" => true,
        "REJECT" => false,
        _ => return None,
    };
    let read = |s: &str| {
        if escaped {
            field(&unescape(s))
        } else {
            field(s)
        }
    };
    Some(Line {
        at_ms,
        mac: mac::parse(&read(f[3]).replace('-', ":"))?,
        accept,
        user: read(f[2]),
        node: field(node),
        nas: field(f[4]),
        detail: read(f[6]),
        cert_expires,
        cert_cn,
    })
}

/// What `%{escape:}` wrote: every `=XX` a byte, as UTF-8.
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = b
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok());
        match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
            Some(byte) if b[i] == b'=' => {
                out.push(byte);
                i += 3;
            }
            _ => {
                out.push(b[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A field as kept: one line, without control or format characters, within
/// [`FIELD_MAX`] bytes.
fn field(s: &str) -> String {
    let mut out = text::clean(s);
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

/// One answer of `query_range`.
struct Page {
    /// How many lines Loki returned, verdicts or not, and the newest one's
    /// time in nanoseconds: what paging goes on from.
    returned: usize,
    newest: Option<u64>,
    /// The lines that are verdicts, oldest first, each with its time.
    verdicts: Vec<(u64, Line)>,
}

/// An answer of `query_range`; `None` for an answer that is not one.
fn lines(answer: &str) -> Option<Page> {
    let v: Value = serde_json::from_str(answer).ok()?;
    if v["status"] != "success" {
        return None;
    }
    let mut page = Page {
        returned: 0,
        newest: None,
        verdicts: Vec::new(),
    };
    for stream in v["data"]["result"].as_array()? {
        let node = stream["stream"]["host"].as_str().unwrap_or_default();
        for pair in stream["values"].as_array()? {
            let ns: u64 = pair[0].as_str()?.parse().ok()?;
            page.returned += 1;
            page.newest = page.newest.max(Some(ns));
            let Some(text) = pair[1].as_str() else {
                continue;
            };
            if let Some(l) = parse(text, ns / 1_000_000, node) {
                page.verdicts.push((ns, l));
            }
        }
    }
    page.verdicts.sort_by_key(|(ns, _)| *ns);
    Some(page)
}

/// What the poller remembers between polls.
struct Cursor {
    /// Where the next poll starts, in nanoseconds since the epoch.
    from_ns: u64,
    /// The lines delivered from `from_ns` on and over the last [`RESCAN`],
    /// by time and hash, at most [`TAKEN_MAX`]: what is never handed over
    /// twice.
    taken: HashSet<(u64, u64)>,
    /// When the last hours are read again next.
    rescan_at: SystemTime,
    /// The instants stepped past over the same span as `taken`: each
    /// held more lines than a page, whose rest Loki cannot be asked for.
    skipped: HashSet<u64>,
    /// How many instants were stepped past since the start.
    skips: u64,
    /// The Loki that answered last, which the next page is asked of first.
    at: usize,
    /// The failures of the reads since they were last counted.
    failures: Vec<Failure>,
}

/// What one read of a window found: whether it reached the window's end,
/// where reading goes on from, and the instants it stepped past, oldest
/// first, which the cursor never goes back to.
struct Read {
    reached: bool,
    next_ns: u64,
    stepped: Vec<u64>,
}

fn nanos(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

fn key(ns: u64, l: &Line) -> (u64, u64) {
    let mut h = DefaultHasher::new();
    let fields = (&l.user, &l.node, &l.nas, &l.detail, &l.cert_cn);
    (l.mac, l.accept, fields, l.cert_expires).hash(&mut h);
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
            rescan_at: now + RESCAN_EVERY,
            skipped: HashSet::new(),
            skips: 0,
            at: 0,
            failures: Vec::new(),
        }
    }

    /// One poll at `now`: the lines not delivered before, or why it failed.
    /// What it read is kept as delivered only when the whole poll worked, so
    /// a poll that fails part way hands its lines over at the next.
    async fn poll(&mut self, s: &Settings, now: SystemTime) -> Result<Vec<Line>, String> {
        let end = nanos(now);
        let (mut new, mut fresh) = (HashSet::new(), Vec::new());
        let read = self
            .read(s, self.from_ns, end, &mut new, &mut fresh)
            .await?;
        let mut stepped = read.stepped.clone();
        if now >= self.rescan_at {
            let back = end.saturating_sub(RESCAN.as_nanos() as u64);
            stepped.extend(self.read(s, back, end, &mut new, &mut fresh).await?.stepped);
            self.rescan_at = now + RESCAN_EVERY;
        }
        self.taken.extend(new);
        let stepped = stepped
            .into_iter()
            .filter(|&t| self.skipped.insert(t))
            .count();
        if stepped > 0 {
            self.skips += stepped as u64;
            eprintln!(
                "u6e-controller: RADIUS log: stepped past {stepped} instants of more than \
                 {PAGE} lines, whose rest Loki cannot page to ({} since start)",
                self.skips
            );
        }
        let lag = if read.reached {
            LAG.as_nanos() as u64
        } else {
            0
        };
        let past = read.stepped.last().map_or(0, |t| t + 1);
        let next = read.next_ns.saturating_sub(lag).max(past);
        self.from_ns = self.from_ns.max(next);
        self.prune(end);
        Ok(fresh)
    }

    /// Keeps what may be read again: from `from_ns` on, and the last
    /// [`RESCAN`]; at most [`TAKEN_MAX`], the oldest dropped first.
    fn prune(&mut self, end: u64) {
        let cutoff = self
            .from_ns
            .min(end.saturating_sub(RESCAN.as_nanos() as u64));
        self.taken.retain(|(ns, _)| *ns >= cutoff);
        self.skipped.retain(|ns| *ns >= cutoff);
        if let Some(excess) = self.taken.len().checked_sub(TAKEN_MAX).filter(|&n| n > 0) {
            let mut times: Vec<u64> = self.taken.iter().map(|(ns, _)| *ns).collect();
            let (_, &mut oldest_kept, _) = times.select_nth_unstable(excess);
            self.taken.retain(|(ns, _)| *ns >= oldest_kept);
        }
    }

    /// The lines from `start` to `end` neither delivered nor in `new`,
    /// into `fresh` (their keys into `new`), at most [`PAGES`] pages. A page
    /// goes on from the newest line returned, a verdict or not; a full page
    /// of one instant (Loki pages by time alone, so the rest of it cannot be
    /// asked for) goes on a nanosecond past it.
    async fn read(
        &mut self,
        s: &Settings,
        mut start: u64,
        end: u64,
        new: &mut HashSet<(u64, u64)>,
        fresh: &mut Vec<Line>,
    ) -> Result<Read, String> {
        let q = fetch::query_value(&query(&s.selector));
        let mut stepped = Vec::new();
        let mut newest = None;
        for _ in 0..PAGES {
            let target = format!(
                "/loki/api/v1/query_range?query={q}&start={start}&end={end}&limit={PAGE}&direction=forward"
            );
            let page = self.ask(s, &target).await?;
            for (ns, l) in page.verdicts {
                let k = key(ns, &l);
                if !self.taken.contains(&k) && new.insert(k) {
                    fresh.push(l);
                }
            }
            newest = newest.max(page.newest);
            if page.returned < PAGE {
                let next_ns = newest.unwrap_or(end).max(start);
                return Ok(Read {
                    reached: true,
                    next_ns,
                    stepped,
                });
            }
            match page.newest.filter(|&n| n > start) {
                Some(n) => start = n,
                None => {
                    stepped.push(start);
                    start += 1;
                }
            }
        }
        Ok(Read {
            reached: false,
            next_ns: start,
            stepped,
        })
    }

    /// The page `target` asks for: from the Loki that answered last, else
    /// from each next one in turn; why none gave it, otherwise.
    async fn ask(&mut self, s: &Settings, target: &str) -> Result<Page, String> {
        let mut why = Vec::new();
        for i in 0..s.loki.len() {
            let at = (self.at + i) % s.loki.len();
            let loki = &s.loki[at];
            let tls = s.tls.as_ref();
            let answer = mtls::get(tls, loki, target, "application/json", BODY_MAX, TIMEOUT).await;
            let page = match answer {
                Ok(a) => lines(&a).ok_or_else(|| "its answer is not a list of lines".to_owned()),
                Err(f) => {
                    let e = f.to_string();
                    self.failures.push(f);
                    Err(e)
                }
            };
            match page {
                Ok(page) => {
                    if at != self.at {
                        let why = why.join("; ");
                        eprintln!("u6e-controller: RADIUS log read from {loki} ({why})");
                        self.at = at;
                    }
                    return Ok(page);
                }
                Err(e) => why.push(format!("{loki}: {e}")),
            }
        }
        Err(why.join("; "))
    }
}

/// Reads the log every [`EVERY`] for the life of the process, into the
/// state; a change of whether it can be read is logged once, a failure of
/// mutual TLS counted.
pub async fn supervise(state: Shared, settings: Settings) {
    let mut every = interval(EVERY);
    let resume = state.read().sessions.radius_newest();
    let mut cursor = Cursor::new(SystemTime::now(), resume);
    let lokis = settings.loki.join(", ");
    loop {
        every.tick().await;
        let now = SystemTime::now();
        let read = cursor.poll(&settings, now).await;
        let mut st = state.write();
        for f in cursor.failures.drain(..) {
            st.tls_failures.count(Endpoint::Loki, &f);
        }
        let was = st.radius.as_ref().and_then(|h| h.up);
        if was != Some(read.is_ok()) {
            match &read {
                Ok(l) => eprintln!("u6e-controller: RADIUS log from {lokis}: {} lines", l.len()),
                Err(e) => eprintln!("u6e-controller: RADIUS log from {lokis}: {e}"),
            }
        }
        st.take_radius(read.map_err(|_| ()), now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use crate::mtls::Reason;
    use crate::mtls::testing::{acceptor, files};

    const MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x21];
    const OLD: &str =
        "2026-11-19 17:10:51|ACCEPT|user@example.org|02-00-00-00-00-21|ap1|192.0.2.17|eap";
    const NEW: &str = "2026-11-19 17:10:51|ACCEPT|user@example.org|02-00-00-00-00-21|ap1|\
                       192.0.2.17|eap|271231235959Z|host/pc1.example.org";

    /// The log's lines as they are: the old shape, and the new one with its
    /// certificate.
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
                cert_cn: None,
            }
        );
        let l = parse(NEW, 0, "").unwrap();
        assert_eq!(l.cert_expires, Some(1_830_297_599));
        assert_eq!(l.cert_cn.as_deref(), Some("host/pc1.example.org"));
        let reject = "t|REJECT|02-00-00-00-00-21|02-00-00-00-00-21|ap1|192.0.2.16|\
                      No Auth-Type found: rejecting the user via Post-Auth-Type =3D Reject||";
        let l = parse(reject, 0, "").unwrap();
        assert!(!l.accept);
        assert_eq!(
            l.detail,
            "No Auth-Type found: rejecting the user via Post-Auth-Type = Reject"
        );
        assert_eq!((l.cert_expires, l.cert_cn), (None, None));
    }

    /// FreeRADIUS escapes what a client chose, `|` included, so an identity
    /// holding pipes is one field and forges no other; a line of another
    /// count, or whose expiry is not a time, is no verdict.
    #[test]
    fn a_piped_identity_forges_nothing() {
        // What the log writes for User-Name `x|02-00-00-00-00-99|ap|ip|eap|
        // 491231235959Z|host/victim`.
        let escaped = "t|ACCEPT|x=7C02-00-00-00-00-99=7Cap=7Cip=7Ceap=7C491231235959Z=7Chost/victim|\
                       02-00-00-00-00-21|ap1|192.0.2.16|eap||";
        let l = parse(escaped, 0, "").unwrap();
        assert_eq!(l.mac, MAC);
        assert_eq!(
            l.user,
            "x|02-00-00-00-00-99|ap|ip|eap|491231235959Z|host/victim"
        );
        assert_eq!((l.cert_expires, l.cert_cn), (None, None));
        // The same identity in a log that did not escape it: refused.
        let raw = escaped.replace("=7C", "|");
        assert_eq!(parse(&raw, 0, ""), None);
        // An old line whose identity adds two fields: nine, but its
        // "expiry" is the NAS's address.
        let forged = "t|ACCEPT|x|02-00-00-00-00-99|ap9|02-00-00-00-00-21|ap1|192.0.2.16|eap";
        assert_eq!(parse(forged, 0, ""), None);
        // The expiry is escaped too (a client's certificate states it): read
        // back, and a pipe in it splits nothing.
        let expiry = "t|REJECT|u|02-00-00-00-00-21|ap1|192.0.2.16|bad|27123123=35959Z|cn";
        assert_eq!(
            parse(expiry, 0, "").unwrap().cert_expires,
            Some(1_830_297_599)
        );
        let piped = "t|REJECT|u|02-00-00-00-00-21|ap1|192.0.2.16|bad|27=7C1231235959Z|cn";
        assert_eq!(parse(piped, 0, ""), None);
        for count in [6, 8, 10] {
            let line = (0..count).map(|_| "eap").collect::<Vec<_>>().join("|");
            assert_eq!(parse(&line, 0, ""), None, "{count} fields");
        }
    }

    /// The lines FreeRADIUS 3.2.7 wrote through the role's linelog for a
    /// User-Name holding pipes, a certificate whose CN holds `|` and `=`, a
    /// reject whose reason and Calling-Station-Id hold `|`, and a plain
    /// login (recorded on loopback).
    #[test]
    fn freeradius_lines_read_as_written() {
        let log = [
            "2026-11-19 20:47:11|ACCEPT|x=7C02-00-00-00-00-99=7Cap=7Cip=7Ceap=7C491231235959Z=7C\
             host/victim|02-00-00-00-00-21|ap1|127.0.0.1|Accept||",
            "2026-11-19 20:47:11|ACCEPT|cert-user|02-00-00-00-00-22|ap1|127.0.0.1|Accept|\
             271231235959Z|host/a=7Cb=3Dc",
            "2026-11-19 20:47:11|REJECT|reject-me|02-00-00-00-00-23=7Cevil|ap1|127.0.0.1|\
             bad =7C worse =3D x||",
            "2026-11-19 20:47:12|ACCEPT|host/laptop1|02-00-00-00-00-24|ap1|127.0.0.1|Accept||",
        ];
        let got: Vec<Option<Line>> = log.iter().map(|l| parse(l, 0, "")).collect();
        let first = got[0].as_ref().unwrap();
        assert_eq!((first.mac, first.cert_expires), (MAC, None));
        let cert = got[1].as_ref().unwrap();
        assert_eq!(cert.cert_cn.as_deref(), Some("host/a|b=c"));
        assert_eq!(cert.cert_expires, Some(1_830_297_599));
        // A Calling-Station-Id that is no MAC is no Wi-Fi client's.
        assert_eq!(got[2], None);
        assert_eq!(got[3].as_ref().unwrap().user, "host/laptop1");
    }

    #[test]
    fn escapes_read_back_and_hidden_text_goes() {
        assert_eq!(unescape("a=7Cb=3Dc=C8=98"), "a|b=cȘ");
        // Not an escape: kept as it is.
        assert_eq!(unescape("x=Zy=4"), "x=Zy=4");
        let l = "t|ACCEPT|host/=E2=80=AEevil|02-00-00-00-00-21|ap1|192.0.2.16|eap||";
        assert_eq!(parse(l, 0, "").unwrap().user, "host/evil");
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
    /// verdict, which counts as returned.
    #[test]
    fn an_answer_gives_its_lines_in_time_order() {
        let answer = r#"{"status":"success","data":{"resultType":"streams","result":[
            {"stream":{"host":"r2"},"values":[["3000000","t|REJECT|u|02-00-00-00-00-21|ap1|192.0.2.16|no"]]},
            {"stream":{"host":"r1"},"values":[["1000000","t|ACCEPT|u|02-00-00-00-00-21|ap1|192.0.2.16|eap"],
                                              ["2000000","t|UNKNOWN|u|02-00-00-00-00-21|ap1|192.0.2.16|"]]}]}}"#;
        let page = lines(answer).unwrap();
        assert_eq!((page.returned, page.newest), (3, Some(3_000_000)));
        let summary: Vec<_> = page
            .verdicts
            .iter()
            .map(|(ns, l)| (*ns, l.accept, l.node.as_str()))
            .collect();
        assert_eq!(summary, [(1_000_000, true, "r1"), (3_000_000, false, "r2")]);
        assert_eq!(page.verdicts[0].1.at_ms, 1);
        assert!(lines(r#"{"status":"error"}"#).is_none());
        assert!(lines("<html>").is_none());
    }

    /// A fake Loki holding `log` (time in nanoseconds, text), answering each
    /// `query_range` as Loki does: its lines from `start` to `end`, oldest
    /// first, at most `limit`; every request is counted, and the requests
    /// numbered in `fail` (from 1) get an answer that is none.
    async fn loki_failing(
        log: Arc<Mutex<Vec<(u64, String)>>>,
        asked: Arc<Mutex<Vec<String>>>,
        fail: &'static [usize],
    ) -> String {
        loki_at("127.0.0.1", None, log, asked, fail).await
    }

    /// The same on `ip`, over mutual TLS with `tls`.
    async fn loki_at(
        ip: &str,
        tls: Option<TlsAcceptor>,
        log: Arc<Mutex<Vec<(u64, String)>>>,
        asked: Arc<Mutex<Vec<String>>>,
        fail: &'static [usize],
    ) -> String {
        let l = TcpListener::bind((ip, 0)).await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let (s, _) = l.accept().await.unwrap();
                match &tls {
                    Some(t) => {
                        if let Ok(s) = t.accept(s).await {
                            answer(s, &log, &asked, fail).await;
                        }
                    }
                    None => answer(s, &log, &asked, fail).await,
                }
            }
        });
        addr
    }

    async fn answer(
        mut s: impl AsyncRead + AsyncWrite + Unpin,
        log: &Mutex<Vec<(u64, String)>>,
        asked: &Mutex<Vec<String>>,
        fail: &[usize],
    ) {
        let mut buf = vec![0; 8192];
        let n = s.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]).into_owned();
        let param = |k: &str| -> u64 {
            let q = req
                .split_whitespace()
                .nth(1)
                .unwrap()
                .split_once('?')
                .unwrap()
                .1;
            let v = q
                .split('&')
                .find_map(|kv| kv.strip_prefix(k)?.strip_prefix('='));
            v.unwrap().parse().unwrap()
        };
        let (start, end, limit) = (param("start"), param("end"), param("limit"));
        asked.lock().unwrap().push(req.clone());
        let answer = if fail.contains(&asked.lock().unwrap().len()) {
            "HTTP/1.0 200 OK\r\n\r\n<html>".to_owned()
        } else {
            let values: Vec<Value> = log
                .lock()
                .unwrap()
                .iter()
                .filter(|(ns, _)| (start..=end).contains(ns))
                .take(limit as usize)
                .map(|(ns, l)| serde_json::json!([ns.to_string(), l]))
                .collect();
            let stream = serde_json::json!({"stream": {"host": "r1"}, "values": values});
            let body = serde_json::json!({"status": "success", "data": {"result": [stream]}});
            format!("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{body}")
        };
        let _ = s.write_all(answer.as_bytes()).await;
        let _ = s.shutdown().await;
    }

    async fn loki(log: Arc<Mutex<Vec<(u64, String)>>>, asked: Arc<Mutex<Vec<String>>>) -> String {
        loki_failing(log, asked, &[]).await
    }

    fn settings(loki: String) -> Settings {
        Settings {
            loki: vec![loki],
            selector: r#"{job="radius"}"#.into(),
            tls: None,
        }
    }

    fn verdict(n: u64) -> String {
        format!("t|ACCEPT|user{n}|02-00-00-00-00-21|ap1|192.0.2.16|eap||")
    }

    /// The second poll overlaps the first by the lag and takes only what
    /// is new; the query asks for the selector's lines that name a MAC.
    #[tokio::test]
    async fn overlapping_polls_take_each_line_once() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let ns = nanos(now);
        let log = Arc::new(Mutex::new(vec![
            (ns - 60_000_000_000, verdict(1)),
            (ns - 1_000_000_000, verdict(2)),
        ]));
        let asked = Arc::new(Mutex::new(Vec::new()));
        let s = settings(loki(Arc::clone(&log), Arc::clone(&asked)).await);
        let mut cursor = Cursor::new(now, None);
        assert_eq!(cursor.poll(&s, now).await.unwrap().len(), 2);
        let req = asked.lock().unwrap()[0].clone();
        let q = "GET /loki/api/v1/query_range?query=%7Bjob%3D%22radius%22%7D%20%7C~%20%22%5E";
        assert!(req.starts_with(q), "{req}");
        let backfill = ns - BACKFILL.as_nanos() as u64;
        assert!(req.contains(&format!("&start={backfill}&")), "{req}");
        log.lock().unwrap().push((ns + 30_000_000_000, verdict(3)));
        let second = cursor
            .poll(&s, now + Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(second.len(), 1);
        let req = asked.lock().unwrap().last().unwrap().clone();
        let from = ns - 1_000_000_000 - LAG.as_nanos() as u64;
        assert!(req.contains(&format!("&start={from}&")), "{req}");
    }

    /// More lines inside one lag window than a poll reads, 900 in each
    /// second as the shipper stamps them: each poll goes on where the last
    /// stopped, and every line is taken once.
    #[tokio::test]
    async fn a_flood_past_the_page_cap_is_read_through() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let ns = nanos(now);
        let flood: Vec<(u64, String)> = (0..25_000u64)
            .map(|i| (ns - 60_000_000_000 + i / 900 * 1_000_000_000, verdict(i)))
            .collect();
        let log = Arc::new(Mutex::new(flood));
        let s = settings(loki(log, Arc::new(Mutex::new(Vec::new()))).await);
        let mut cursor = Cursor::new(now, None);
        let mut taken = 0;
        let mut polls = 0;
        while polls < 6 {
            polls += 1;
            let n = cursor.poll(&s, now).await.unwrap().len();
            if n == 0 {
                break;
            }
            taken += n;
        }
        assert_eq!(taken, 25_000);
        assert!(polls <= 5, "{polls} polls");
    }

    /// Lines that match the query and are no verdict (a client can make
    /// them: this one's escaped fields are one too many) fill whole pages;
    /// the reader goes past them to the verdict after.
    #[tokio::test]
    async fn lines_that_are_no_verdict_cannot_hold_the_reader() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let ns = nanos(now);
        let junk = |i: u64| format!("t|REJECT|u{i}|02-00-00-00-00-21|ap1|192.0.2.16|bad|1|2|cn");
        let mut log: Vec<(u64, String)> = (0..1500u64)
            .map(|i| (ns - 120_000_000_000 + i / 600 * 1_000_000_000, junk(i)))
            .collect();
        log.push((ns - 1_000_000_000, verdict(7)));
        let s = settings(loki(Arc::new(Mutex::new(log)), Arc::new(Mutex::new(Vec::new()))).await);
        let mut cursor = Cursor::new(now, None);
        let got = cursor.poll(&s, now).await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].user, "user7");
    }

    /// More lines in one second (as the shipper stamps them) than a page
    /// holds: the reader steps past that instant, its rest unread, counts
    /// the step, reads on to the verdict after, and never steps there again.
    #[tokio::test]
    async fn a_full_page_of_one_instant_is_stepped_past() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let ns = nanos(now);
        let sec = ns - 120_000_000_000;
        let mut log: Vec<(u64, String)> = (0..1200u64).map(|i| (sec, verdict(i))).collect();
        log.push((ns - 1_000_000_000, verdict(99_999)));
        let s = settings(loki(Arc::new(Mutex::new(log)), Arc::new(Mutex::new(Vec::new()))).await);
        let mut cursor = Cursor::new(now, None);
        let mut got = 0;
        for i in 0..5 {
            got += cursor
                .poll(&s, now + Duration::from_secs(60 * i))
                .await
                .unwrap()
                .len();
        }
        // The first page of the instant, and the verdict after it.
        assert_eq!(got, 1001);
        assert_eq!(cursor.skips, 1);
        // The hourly re-read steps past it again, and neither counts it
        // nor hands anything over twice.
        let hour = now + RESCAN_EVERY;
        assert!(cursor.poll(&s, hour).await.unwrap().is_empty());
        assert_eq!(cursor.skips, 1);
    }

    /// A poll that fails part way keeps nothing as delivered: the next one
    /// hands its lines over.
    #[tokio::test]
    async fn a_poll_that_fails_part_way_hands_its_lines_over_at_the_next() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let ns = nanos(now);
        let log: Vec<(u64, String)> = (0..1500u64)
            .map(|i| (ns - 120_000_000_000 + i * 1_000_000, verdict(i)))
            .collect();
        let log = Arc::new(Mutex::new(log));
        let asked = Arc::new(Mutex::new(Vec::new()));
        let s = settings(loki_failing(log, asked, &[2]).await);
        let mut cursor = Cursor::new(now, None);
        assert!(cursor.poll(&s, now).await.is_err());
        let got = cursor.poll(&s, now).await.unwrap();
        assert_eq!(got.len(), 1500);
    }

    /// The hourly re-read hands over only what was not delivered before.
    #[tokio::test]
    async fn the_hourly_reread_hands_over_nothing_twice() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let ns = nanos(now);
        let log = Arc::new(Mutex::new(vec![(ns - 1_000_000_000, verdict(1))]));
        let s = settings(loki(Arc::clone(&log), Arc::new(Mutex::new(Vec::new()))).await);
        let mut cursor = Cursor::new(now, None);
        assert_eq!(cursor.poll(&s, now).await.unwrap().len(), 1);
        log.lock()
            .unwrap()
            .push((ns + 1_200_000_000_000, verdict(2)));
        let t = now + Duration::from_secs(1260);
        assert_eq!(cursor.poll(&s, t).await.unwrap().len(), 1);
        let hour = now + RESCAN_EVERY;
        assert!(cursor.poll(&s, hour).await.unwrap().is_empty());
    }

    /// A line stamped behind the cursor (sent late, or in the repeated hour
    /// of the autumn clock change) is read at the next hourly re-read.
    #[tokio::test]
    async fn a_line_stamped_behind_the_cursor_is_read_again_hourly() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let ns = nanos(now);
        let log = Arc::new(Mutex::new(vec![(ns - 1_000_000_000, verdict(1))]));
        let s = settings(loki(Arc::clone(&log), Arc::new(Mutex::new(Vec::new()))).await);
        let mut cursor = Cursor::new(now, None);
        assert_eq!(cursor.poll(&s, now).await.unwrap().len(), 1);
        // An hour early, after the cursor passed.
        let late = (ns - 3_600_000_000_000, verdict(2));
        log.lock().unwrap().push(late);
        log.lock().unwrap().sort();
        let later = now + Duration::from_secs(60);
        assert!(cursor.poll(&s, later).await.unwrap().is_empty());
        let hour = now + RESCAN_EVERY;
        let got = cursor.poll(&s, hour).await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].user, "user2");
    }

    /// A Loki that answers nonsense, or nothing, is an error in time, and
    /// the window it failed on is read again.
    #[tokio::test]
    async fn a_broken_loki_is_an_error_in_time() {
        let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = silent.local_addr().unwrap().to_string();
        let now = SystemTime::now();
        let mut cursor = Cursor::new(now, None);
        let from = cursor.from_ns;
        let t = std::time::Instant::now();
        let wait = Duration::from_millis(300);
        let r = fetch::get(&addr, "/", "application/json", BODY_MAX, wait).await;
        assert!(r.is_err());
        assert!(t.elapsed() < Duration::from_secs(2));
        let garbage = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = garbage.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut s, _) = garbage.accept().await.unwrap();
            let mut buf = [0; 4096];
            let _ = s.read(&mut buf).await;
            let _ = s.write_all(b"HTTP/1.0 200 OK\r\n\r\n<html>").await;
        });
        assert!(cursor.poll(&settings(addr), now).await.is_err());
        assert_eq!(cursor.from_ns, from);
    }

    fn lokis(loki: Vec<String>, tls: Option<mtls::Files>) -> Settings {
        Settings {
            loki,
            tls,
            ..settings(String::new())
        }
    }

    /// An address nothing listens on.
    async fn refusing() -> String {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().to_string()
    }

    fn reasons(c: &Cursor) -> Vec<Option<Reason>> {
        c.failures.iter().map(Failure::reason).collect()
    }

    /// A Loki that refuses hands the page to the next, which is asked
    /// first from then on.
    #[tokio::test]
    async fn a_failing_loki_hands_over_to_the_next_which_stays_first() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let log = Arc::new(Mutex::new(vec![(nanos(now) - 1_000_000_000, verdict(1))]));
        let asked = Arc::new(Mutex::new(Vec::new()));
        let good = loki(log, Arc::clone(&asked)).await;
        let s = lokis(vec![refusing().await, good], None);
        let mut cursor = Cursor::new(now, None);
        assert_eq!(cursor.poll(&s, now).await.unwrap().len(), 1);
        assert_eq!((cursor.at, reasons(&cursor)), (1, vec![None]));
        let later = now + Duration::from_secs(60);
        assert!(cursor.poll(&s, later).await.unwrap().is_empty());
        assert_eq!(
            cursor.failures.len(),
            1,
            "the refusing one is not asked first"
        );
        assert_eq!(asked.lock().unwrap().len(), 2);
    }

    /// A poll whose second page one Loki fails to give (an answer that is
    /// no list of lines) reads it from the other: the poll is one, each
    /// line delivered once.
    #[tokio::test]
    async fn a_poll_read_partly_from_each_loki_delivers_each_line_once() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let ns = nanos(now);
        let log: Vec<(u64, String)> = (0..1500u64)
            .map(|i| (ns - 120_000_000_000 + i * 1_000_000, verdict(i)))
            .collect();
        let log = Arc::new(Mutex::new(log));
        let (first, second) = (
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(Mutex::new(Vec::new())),
        );
        let a = loki_failing(Arc::clone(&log), Arc::clone(&first), &[2]).await;
        let b = loki(log, Arc::clone(&second)).await;
        let s = lokis(vec![a, b], None);
        let mut cursor = Cursor::new(now, None);
        let got = cursor.poll(&s, now).await.unwrap();
        let users: HashSet<&str> = got.iter().map(|l| l.user.as_str()).collect();
        assert_eq!((got.len(), users.len()), (1500, 1500));
        assert_eq!(
            (first.lock().unwrap().len(), second.lock().unwrap().len()),
            (2, 1)
        );
        assert!(cursor.poll(&s, now).await.unwrap().is_empty());
    }

    /// A Loki that takes the connection and never answers is given up
    /// after its timeout, and the page read from the next.
    #[tokio::test]
    async fn a_hanging_loki_is_given_up_in_time() {
        let now = SystemTime::now();
        let hung = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hung_at = hung.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = hung.accept().await {
                held.push(s);
            }
        });
        let log = Arc::new(Mutex::new(vec![(nanos(now) - 1_000_000_000, verdict(1))]));
        let good = loki(log, Arc::new(Mutex::new(Vec::new()))).await;
        let s = lokis(vec![hung_at, good], None);
        let mut cursor = Cursor::new(now, None);
        let t = std::time::Instant::now();
        assert_eq!(cursor.poll(&s, now).await.unwrap().len(), 1);
        assert!(t.elapsed() >= TIMEOUT && t.elapsed() < TIMEOUT + Duration::from_secs(5));
    }

    /// Over mutual TLS each Loki is verified by the address dialled and
    /// shown the controller's certificate; one of another name is refused
    /// and the next one read; the certificate missing fails every one, each
    /// failure kept for the count.
    #[tokio::test]
    async fn the_lokis_are_read_over_mutual_tls() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let log = Arc::new(Mutex::new(vec![(nanos(now) - 1_000_000_000, verdict(1))]));
        let me = ["controller.example.org"];
        let serve = |ip: &'static str, cert: &str| {
            let tls = Some(acceptor(cert, &me));
            loki_at(
                ip,
                tls,
                Arc::clone(&log),
                Arc::new(Mutex::new(Vec::new())),
                &[],
            )
        };
        let (one, two) = (
            serve("127.0.0.1", "server1").await,
            serve("127.0.0.2", "server2").await,
        );
        let misnamed = serve("127.0.0.1", "server2").await;
        let tls = Some(files("controller"));
        let mut cursor = Cursor::new(now, None);
        let s = lokis(vec![one.clone(), two.clone()], tls.clone());
        assert_eq!(cursor.poll(&s, now).await.unwrap().len(), 1);
        let mut cursor = Cursor::new(now, None);
        let s = lokis(vec![misnamed, two], tls);
        assert_eq!(cursor.poll(&s, now).await.unwrap().len(), 1);
        assert_eq!(reasons(&cursor), [Some(Reason::Handshake)]);
        let mut cursor = Cursor::new(now, None);
        let missing = mtls::Files {
            key: "/nonexistent/key.pem".into(),
            ..files("controller")
        };
        let s = lokis(vec![one, s.loki[1].clone()], Some(missing));
        let e = cursor.poll(&s, now).await.unwrap_err();
        assert!(e.contains("the monitoring certificate"), "{e}");
        let certificate = Some(Reason::Certificate);
        assert_eq!(reasons(&cursor), [certificate, certificate]);
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
}
