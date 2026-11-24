//! The speed tests: an admin's of an AP's throughput to the controller
//! (`ap`). Each is kept in RAM from its request to its end, the newest
//! [`AP_KEEP`] for a week at most, its result an action on its AP (the
//! events and the journal) and the AP's last result in the metrics; the
//! live view carries the newest [`SHOWN`].

pub mod ap;

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant, SystemTime};

use serde_json::{Value, json};
use u6e_proto::msg::CpuUse;
use u6e_proto::speedtest::bits_per_second;

use crate::sessions::unix_ms;

/// The AP tests kept, and for how long.
pub const AP_KEEP: usize = 100;
pub const KEEP: Duration = Duration::from_secs(7 * 24 * 3600);
/// The AP tests the live view carries, newest first.
pub const SHOWN: usize = 20;
/// The tests' kinds and results, as the metrics count them; every pair is
/// exported.
pub const KINDS: [&str; 1] = ["ap"];
pub const RESULTS: [&str; 3] = ["ok", "failed", "refused"];

/// Where a test is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Running,
    Done,
    Failed,
}

impl Status {
    pub fn name(self) -> &'static str {
        match self {
            Status::Running => "running",
            Status::Done => "done",
            Status::Failed => "failed",
        }
    }
}

/// One direction of a test as its receiver timed it: its filler bytes, and
/// the microseconds from their first byte to their end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Measured {
    pub bytes: u64,
    pub us: u64,
}

impl Measured {
    pub fn bits_per_second(&self) -> f64 {
        bits_per_second(self.bytes, self.us)
    }

    pub fn bytes_per_second(&self) -> f64 {
        self.bits_per_second() / 8.0
    }

    fn json(&self) -> Value {
        json!({
            "bits_per_second": self.bits_per_second().round(),
            "bytes": self.bytes,
            "ms": self.us / 1000,
        })
    }
}

/// What an AP test measured: the download as the agent received it, the
/// upload as the controller did, and the AP's CPU over each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApResult {
    pub down: Measured,
    pub up: Measured,
    pub cpu_down: CpuUse,
    pub cpu_up: CpuUse,
}

/// One AP test: the command `id` asked it of `ap`.
#[derive(Debug, Clone, PartialEq)]
pub struct ApTest {
    pub id: u64,
    pub ap: String,
    pub user: Option<String>,
    pub at: SystemTime,
    pub status: Status,
    /// Its own connection came.
    pub opened: bool,
    pub result: Option<ApResult>,
    /// Why it failed.
    pub detail: String,
    pub ended: Option<SystemTime>,
}

impl ApTest {
    fn json(&self) -> Value {
        let mut v = json!({
            "id": self.id.to_string(),
            "ap": self.ap,
            "user": self.user,
            "at": unix_ms(self.at),
            "status": self.status.name(),
        });
        if let Some(r) = &self.result {
            let cpu = |c: &CpuUse| {
                json!({
                    "busy": f64::from(c.busy_permille) / 10.0,
                    "thread": f64::from(c.thread_permille) / 10.0,
                })
            };
            v["down"] = r.down.json();
            v["up"] = r.up.json();
            v["cpu"] = json!({ "down": cpu(&r.cpu_down), "up": cpu(&r.cpu_up) });
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

/// Every test kept, and the counts of their ends.
#[derive(Debug, Default)]
pub struct SpeedTests {
    /// AP tests, newest last.
    pub aps: VecDeque<ApTest>,
    /// When each running AP test was asked, for its deadlines.
    asked: BTreeMap<u64, Instant>,
    /// Tests by kind and result.
    pub counts: BTreeMap<(&'static str, &'static str), u64>,
    /// What an AP test takes.
    pub limits: ap::Limits,
}

impl SpeedTests {
    pub fn count(&mut self, kind: &'static str, result: &'static str) {
        *self.counts.entry((kind, result)).or_default() += 1;
    }

    /// The AP test running, on any AP.
    pub fn running_ap(&self) -> Option<&ApTest> {
        self.aps.iter().find(|t| t.status == Status::Running)
    }

    /// Whether a test of `ap` runs.
    pub fn ap_running(&self, ap: &str) -> bool {
        self.running_ap().is_some_and(|t| t.ap == ap)
    }

    /// The AP test of the command `id`.
    pub fn ap_test(&self, id: u64) -> Option<&ApTest> {
        self.aps.iter().find(|t| t.id == id)
    }

    fn ap_test_mut(&mut self, id: u64) -> Option<&mut ApTest> {
        self.aps.iter_mut().find(|t| t.id == id)
    }

    /// Drops what is past keeping at `now`; a running test is never dropped.
    fn prune(&mut self, now: SystemTime) {
        self.aps
            .retain(|t| t.status == Status::Running || t.at + KEEP >= now);
        while self.aps.len() > AP_KEEP {
            let Some(at) = self.aps.iter().position(|t| t.status != Status::Running) else {
                break;
            };
            self.aps.remove(at);
        }
    }
}

/// The live view's tests: the newest [`SHOWN`] AP tests, newest first.
pub fn view(tests: &SpeedTests) -> Value {
    let aps: Vec<Value> = tests
        .aps
        .iter()
        .rev()
        .take(SHOWN)
        .map(ApTest::json)
        .collect();
    json!({ "aps": aps })
}

/// A rate as the events say it.
pub fn mbits(m: &Measured) -> String {
    let mbps = m.bits_per_second() / 1e6;
    if mbps >= 100.0 {
        format!("{mbps:.0} Mbit/s")
    } else {
        format!("{mbps:.1} Mbit/s")
    }
}
