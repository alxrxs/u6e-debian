//! How the replay's clients sign in, and the RADIUS log that says so, which
//! a Loki of the replay's own serves the controller (`serve`). `ssid-a`
//! authenticates with EAP (EAP-TLS, each certificate's expiry in the log;
//! PEAP for two clients), `ssid-b` with a passphrase and RADIUS MAC
//! authentication, `ssid-c` with SAE. The log starts a week full, an
//! accept every few hours per client, and a device RADIUS does not know
//! (`00:00:5e:ef:10:0d`) refused all along.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::json;
use u6e_proto::msg::StationAuth;

use crate::{BSSS, World};

/// How each client of `ssid-a` signs in, by the last byte of its MAC: its
/// EAP identity, method and, for EAP-TLS, its certificate's days left.
const EAP: [(u8, &str, u8, Option<i64>); 7] = [
    (1, "host/pixel-8", 13, Some(410)),
    (2, "host/macbook-air", 13, Some(20)),
    (3, "iphone-15@example.org", 13, Some(180)),
    (4, "host/living-room-tv", 13, Some(700)),
    (5, "anonymous@example.org", 25, None),
    (8, "host/workstation", 13, Some(95)),
    (10, "bob@example.org", 25, None),
];
/// The device whose MAC RADIUS does not know.
pub const UNKNOWN: u8 = 13;
/// The most lines kept.
const KEPT: usize = 20_000;

/// How the client `last` on BSS `bss` authenticated; `ft` when it came by
/// fast transition.
pub fn auth(last: u8, bss: usize, ft: bool) -> StationAuth {
    let (akm, identity, eap_method) = match BSSS[bss].1 {
        "ssid-a" => {
            let (_, id, method, _) = EAP
                .iter()
                .find(|e| e.0 == last)
                .copied()
                .unwrap_or((0, "", 13, None));
            (0x000f_ac05, id, method)
        }
        "ssid-b" => (0x000f_ac02, "", 0),
        _ => (0x000f_ac08, "", 0),
    };
    StationAuth {
        akm,
        auth_alg: if ft {
            2
        } else if akm == 0x000f_ac08 {
            3
        } else {
            0
        },
        authorized: true,
        identity: identity.into(),
        eap_method,
        reauth_s: 0,
    }
}

/// An X.509 UTCTime, `YYMMDDHHMMSSZ`, of Unix seconds `s`.
fn utc_time(s: u64) -> String {
    let (days, rest) = (s / 86_400, s % 86_400);
    // Howard Hinnant's civil_from_days.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let (hh, mm, ss) = (rest / 3600, rest / 60 % 60, rest % 60);
    format!("{:02}{m:02}{d:02}{hh:02}{mm:02}{ss:02}Z", y % 100)
}

/// The RADIUS log: its lines by time (milliseconds), oldest first, and when
/// the replay started (the certificates' expiries count from it).
pub struct Log {
    lines: Vec<(u64, String)>,
    start_ms: u64,
}

impl Log {
    /// A log a week full before `now_ms`.
    pub fn new(now_ms: u64) -> Log {
        let mut log = Log {
            lines: Vec::new(),
            start_ms: now_ms,
        };
        for h in (6..7 * 24).rev().step_by(5) {
            let at = now_ms - h * 3_600_000;
            for (i, &(last, ..)) in EAP.iter().enumerate() {
                log.accept(at + i as u64 * 97_000, last, i % 2, "ssid-a");
            }
            for last in [6, 7, 9] {
                log.accept(at + u64::from(last) * 61_000, last, 1, "ssid-b");
            }
            if h % 24 < 5 {
                log.reject(
                    at + 600_000,
                    10,
                    1,
                    "Not authorized for Wi-Fi: group membership required",
                );
            }
        }
        for h in (0..24).rev().step_by(3) {
            let at = now_ms - h * 3_600_000 - 1_200_000;
            log.unknown(at, 1);
        }
        log
    }

    /// A line of the client `last` through AP `ap`: its verdict, User-Name,
    /// detail and certificate expiry.
    fn push(
        &mut self,
        at_ms: u64,
        last: u8,
        ap: usize,
        [verdict, user, detail, expiry]: [&str; 4],
    ) {
        let station = World::mac(last).map(|b| format!("{b:02X}")).join("-");
        // The time field is the log's own; the controller reads Loki's.
        let line = format!(
            "{}|{verdict}|{user}|{station}|ap{}|192.0.2.{}|{detail}|{expiry}",
            at_ms / 1000,
            ap + 1,
            16 + ap
        );
        let i = self.lines.partition_point(|(t, _)| *t <= at_ms);
        self.lines.insert(i, (at_ms, line));
        if self.lines.len() > KEPT {
            self.lines.remove(0);
        }
    }

    /// RADIUS accepted the client `last` on an `ssid` of AP `ap`.
    pub fn accept(&mut self, at_ms: u64, last: u8, ap: usize, ssid: &str) {
        if ssid == "ssid-b" {
            let user = World::mac(last).map(|b| format!("{b:02x}")).join("-");
            return self.push(at_ms, last, ap, ["ACCEPT", &user, "PAP", ""]);
        }
        let Some(&(_, user, _, days)) = EAP.iter().find(|e| e.0 == last) else {
            return;
        };
        let expiry = days.map_or_else(String::new, |d| {
            let s = (self.start_ms / 1000) as i64 + d * 86_400;
            utc_time(s.max(0) as u64)
        });
        self.push(at_ms, last, ap, ["ACCEPT", user, "eap", &expiry]);
    }

    /// RADIUS rejected the client `last`, for `why`.
    pub fn reject(&mut self, at_ms: u64, last: u8, ap: usize, why: &str) {
        let user = EAP.iter().find(|e| e.0 == last).map_or("", |e| e.1);
        self.push(at_ms, last, ap, ["REJECT", user, why, ""]);
    }

    /// The device RADIUS does not know tried MAC authentication.
    pub fn unknown(&mut self, at_ms: u64, ap: usize) {
        let user = World::mac(UNKNOWN).map(|b| format!("{b:02x}")).join("-");
        let why = "No Auth-Type found: rejecting the user via Post-Auth-Type = Reject";
        self.push(at_ms, UNKNOWN, ap, ["REJECT", &user, why, ""]);
    }

    /// Loki's answer to `query_range` from `start` to `end` (nanoseconds),
    /// at most `limit` lines, oldest first.
    fn answer(&self, start: u64, end: u64, limit: usize) -> String {
        let values: Vec<_> = self
            .lines
            .iter()
            .filter(|(ms, _)| (start..=end).contains(&(ms * 1_000_000)))
            .take(limit)
            .map(|(ms, l)| json!([(ms * 1_000_000).to_string(), l]))
            .collect();
        let stream = json!({"stream": {"host": "radius1.example.org"}, "values": values});
        json!({"status": "success", "data": {"resultType": "streams", "result": [stream]}})
            .to_string()
    }
}

/// The value of `key` in the query of the request line `request`.
fn param<'a>(request: &'a str, key: &str) -> Option<&'a str> {
    let query = request.split_whitespace().nth(1)?.split_once('?')?.1;
    query
        .split('&')
        .find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='))
}

/// The replay's Loki: every `query_range` gets the world's RADIUS log.
pub fn serve(world: Arc<Mutex<World>>) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            let mut ask = [0; 4096];
            let n = s.read(&mut ask).unwrap_or(0);
            let request = String::from_utf8_lossy(&ask[..n]).into_owned();
            let number = |k, default| {
                param(&request, k)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(default)
            };
            let body = world
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .radius
                .answer(
                    number("start", 0),
                    number("end", u64::MAX),
                    number("limit", 1000) as usize,
                );
            let answer = format!("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{body}");
            let _ = s.write_all(answer.as_bytes());
        }
    });
    Ok(addr)
}
