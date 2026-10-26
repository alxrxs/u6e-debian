//! The operator's decisions that outlive the controller: the clients it
//! blocked, and the Wi-Fi configuration each AP last acknowledged, by its hash
//! and sequence number (never its text). `policy.json` is
//! `{"blocked": ["02:00:00:00:00:01", ...], "configs": {"ap1": {"sha256":
//! "<64 hex>", "seq": 1792929600000}}, "rollouts": [...], "next_rollout": 7}`.
//! An AP keeps its blocks in RAM only, so this file is what every AP is given
//! again when it connects. The recent image rollouts are kept too, with their
//! gate's verdict and result, so a restart neither loses one nor numbers a new
//! one as an old one: the gates of those not over go on, the runner's result,
//! which it sends until it is acknowledged, finds them, and a failed one's
//! time still raises its alert. So does the last result the runner sent for
//! a rollout this controller did not hold (`orphan`).
//!
//! A save writes the whole file beside the old one, syncs it, renames it over
//! the old one and syncs the directory: a crash at any point leaves either the
//! old file or the new one, never a part of either. [`Store`] makes it one
//! save at a time.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, MutexGuard};
use u6e_proto::mac;

/// The clients blocked, by MAC.
pub type Blocked = BTreeSet<[u8; 6]>;

/// A configuration as the deploy runner signed it: its hash and sequence
/// number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigId {
    pub sha256: [u8; 32],
    pub seq: u64,
}

/// Everything the file holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    pub blocked: Blocked,
    /// The configuration each AP last acknowledged, by AP.
    pub configs: BTreeMap<String, ConfigId>,
    /// The recent rollouts, oldest first.
    pub rollouts: Vec<SavedRollout>,
    /// The id the last rollout was given.
    pub next_rollout: u64,
    /// The last result for a rollout not held here: its id, outcome (as the
    /// metrics name it), what the runner said, and when it came.
    pub orphan: Option<(u64, String, String, SystemTime)>,
}

/// A rollout as it outlives the controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedRollout {
    pub id: u64,
    pub ap: String,
    pub image_id: String,
    pub previous: String,
    pub user: String,
    pub at: SystemTime,
    /// The runner said it took it on.
    pub started: bool,
    /// The radios up on the AP and the site's clients when it was asked.
    pub radios: usize,
    pub clients: usize,
    /// The gate's verdict, once it was given: healthy, and what was seen.
    pub gate: Option<(bool, String)>,
    /// How it ended, once it did: the outcome as the metrics name it, what
    /// the runner said, and when.
    pub result: Option<(String, String, SystemTime)>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    blocked: Vec<String>,
    // None until an AP acknowledged a configuration, as in a file from
    // before the controller relayed them.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    configs: BTreeMap<String, ConfigFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    rollouts: Vec<RolloutFile>,
    #[serde(default, skip_serializing_if = "is_zero")]
    next_rollout: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    orphan: Option<OrphanFile>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrphanFile {
    id: u64,
    outcome: String,
    detail: String,
    /// Milliseconds since the Unix epoch.
    at: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RolloutFile {
    id: u64,
    ap: String,
    image_id: String,
    previous: String,
    user: String,
    /// Milliseconds since the Unix epoch.
    at: u64,
    #[serde(default)]
    started: bool,
    radios: usize,
    clients: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gate: Option<GateFile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    result: Option<ResultFile>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultFile {
    outcome: String,
    detail: String,
    /// Milliseconds since the Unix epoch.
    at: u64,
}

fn millis(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn time(ms: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(ms)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GateFile {
    healthy: bool,
    detail: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    sha256: String,
    seq: u64,
}

/// The file, saved one save at a time.
#[derive(Clone)]
pub struct Store(Arc<Mutex<PathBuf>>);

impl Store {
    pub fn new(path: PathBuf) -> Self {
        Store(Arc::new(Mutex::new(path)))
    }

    /// The path, held until the guard is dropped: no other save starts
    /// meanwhile.
    pub async fn lock(&self) -> MutexGuard<'_, PathBuf> {
        self.0.lock().await
    }
}

/// Replaces the decisions at `path` with `policy`, off the runtime's threads.
pub async fn write(path: &Path, policy: Policy) -> io::Result<()> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || save(&path, &policy))
        .await
        .map_err(io::Error::other)?
}

/// The decisions saved at `path`; none when there is no file yet. A file that
/// does not parse is an error, never an empty policy: starting without its
/// blocks would let every blocked client back on.
pub fn load(path: &Path) -> io::Result<Policy> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Policy::default()),
        Err(e) => return Err(e),
    };
    let invalid = |what: String| io::Error::new(ErrorKind::InvalidData, what);
    let file: PolicyFile = serde_json::from_str(&text).map_err(|e| invalid(e.to_string()))?;
    let blocked = file
        .blocked
        .iter()
        .map(|m| mac::parse(m).ok_or_else(|| invalid(format!("blocked: {m:?} is not a MAC"))))
        .collect::<io::Result<_>>()?;
    let configs = file
        .configs
        .into_iter()
        .map(|(ap, c)| {
            let sha256 = mac::unhex(&c.sha256)
                .ok_or_else(|| invalid(format!("configs.{ap}.sha256 is not 64 hex digits")))?;
            Ok((ap, ConfigId { sha256, seq: c.seq }))
        })
        .collect::<io::Result<_>>()?;
    let rollouts = file.rollouts.into_iter().map(|r| SavedRollout {
        id: r.id,
        ap: r.ap,
        image_id: r.image_id,
        previous: r.previous,
        user: r.user,
        at: time(r.at),
        started: r.started,
        radios: r.radios,
        clients: r.clients,
        gate: r.gate.map(|g| (g.healthy, g.detail)),
        result: r.result.map(|e| (e.outcome, e.detail, time(e.at))),
    });
    Ok(Policy {
        blocked,
        configs,
        rollouts: rollouts.collect(),
        next_rollout: file.next_rollout,
        orphan: file.orphan.map(|o| (o.id, o.outcome, o.detail, time(o.at))),
    })
}

/// Replaces the decisions at `path` with `policy`.
pub fn save(path: &Path, policy: &Policy) -> io::Result<()> {
    let temp = write_temp(path, policy)?;
    fs::rename(&temp, path)?;
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty());
    File::open(dir.unwrap_or(Path::new(".")))?.sync_all()
}

/// The new file, whole and synced, beside the one it replaces. A temporary
/// file a crash left behind is overwritten.
fn write_temp(path: &Path, policy: &Policy) -> io::Result<PathBuf> {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    let temp = path.with_file_name(name);
    let configs = policy.configs.iter().map(|(ap, c)| {
        let file = ConfigFile {
            sha256: mac::hex(&c.sha256),
            seq: c.seq,
        };
        (ap.clone(), file)
    });
    let rollouts = policy.rollouts.iter().map(|r| RolloutFile {
        id: r.id,
        ap: r.ap.clone(),
        image_id: r.image_id.clone(),
        previous: r.previous.clone(),
        user: r.user.clone(),
        at: millis(r.at),
        started: r.started,
        radios: r.radios,
        clients: r.clients,
        gate: r
            .gate
            .clone()
            .map(|(healthy, detail)| GateFile { healthy, detail }),
        result: r.result.clone().map(|(outcome, detail, at)| ResultFile {
            outcome,
            detail,
            at: millis(at),
        }),
    });
    let file = PolicyFile {
        blocked: policy.blocked.iter().map(|m| mac::format(*m)).collect(),
        configs: configs.collect(),
        rollouts: rollouts.collect(),
        next_rollout: policy.next_rollout,
        orphan: policy
            .orphan
            .clone()
            .map(|(id, outcome, detail, at)| OrphanFile {
                id,
                outcome,
                detail,
                at: millis(at),
            }),
    };
    let mut body = serde_json::to_vec_pretty(&file).map_err(io::Error::other)?;
    body.push(b'\n');
    let mut f = File::create(&temp)?;
    f.write_all(&body)?;
    f.sync_all()?;
    Ok(temp)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory of the test's own, removed when it ends.
    struct Dir(PathBuf);

    impl Dir {
        fn new(name: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir = std::env::temp_dir()
                .join(format!("u6e-policy-{name}-{}-{nanos}", std::process::id()));
            fs::create_dir_all(&dir).unwrap();
            Dir(dir)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn blocked(lasts: &[u8]) -> Policy {
        Policy {
            blocked: lasts.iter().map(|&l| [2, 0, 0, 0, 0, l]).collect(),
            ..Policy::default()
        }
    }

    #[test]
    fn saved_then_loaded() {
        let dir = Dir::new("round-trip");
        let path = dir.0.join("policy.json");
        assert_eq!(load(&path).unwrap(), Policy::default());
        let mut p = blocked(&[2, 1]);
        let c = ConfigId {
            sha256: [0xab; 32],
            seq: 1_792_929_600_000,
        };
        p.configs.insert("ap1".into(), c);
        p.rollouts.push(SavedRollout {
            id: 7,
            ap: "ap1".into(),
            image_id: "20261025-120000-abc-def-ap1".into(),
            previous: "20261024-120000-abc-def-ap1".into(),
            user: "admin".into(),
            at: UNIX_EPOCH + Duration::from_millis(1_792_929_600_123),
            started: true,
            radios: 3,
            clients: 9,
            gate: Some((true, "back".into())),
            result: Some(("done".into(), "back".into(), time(1_792_929_700_000))),
        });
        p.next_rollout = 7;
        p.orphan = Some((5, "failed".into(), "gone".into(), time(1_792_929_800_000)));
        save(&path, &p).unwrap();
        assert_eq!(load(&path).unwrap(), p);
        let text = fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "blocked": ["02:00:00:00:00:01", "02:00:00:00:00:02"],
                "configs": {"ap1": {"sha256": "ab".repeat(32), "seq": 1_792_929_600_000u64}},
                "rollouts": [{
                    "id": 7,
                    "ap": "ap1",
                    "image_id": "20261025-120000-abc-def-ap1",
                    "previous": "20261024-120000-abc-def-ap1",
                    "user": "admin",
                    "at": 1_792_929_600_123u64,
                    "started": true,
                    "radios": 3,
                    "clients": 9,
                    "gate": {"healthy": true, "detail": "back"},
                    "result": {"outcome": "done", "detail": "back", "at": 1_792_929_700_000u64},
                }],
                "next_rollout": 7,
                "orphan": {"id": 5, "outcome": "failed", "detail": "gone", "at": 1_792_929_800_000u64},
            })
        );
        save(&path, &Policy::default()).unwrap();
        assert_eq!(load(&path).unwrap(), Policy::default());
    }

    /// A file written before the controller relayed configurations.
    #[test]
    fn a_file_with_blocks_only_loads() {
        let dir = Dir::new("blocks-only");
        let path = dir.0.join("policy.json");
        fs::write(&path, r#"{"blocked": ["02:00:00:00:00:01"]}"#).unwrap();
        assert_eq!(load(&path).unwrap(), blocked(&[1]));
    }

    /// A crash after the new file is written, before it is renamed: the old
    /// decisions stand, and the next save goes through.
    #[test]
    fn a_crash_before_the_rename_keeps_the_old_file() {
        let dir = Dir::new("crash");
        let path = dir.0.join("policy.json");
        save(&path, &blocked(&[1])).unwrap();
        let temp = write_temp(&path, &blocked(&[1, 2, 3])).unwrap();
        assert!(temp.exists());
        assert_eq!(load(&path).unwrap(), blocked(&[1]));
        save(&path, &blocked(&[4])).unwrap();
        assert_eq!(load(&path).unwrap(), blocked(&[4]));
        assert!(!temp.exists());
    }

    #[test]
    fn a_bad_file_is_an_error() {
        let dir = Dir::new("bad");
        let path = dir.0.join("policy.json");
        for bad in [
            "",
            "{}",
            r#"{"blocked": ["02:00:00:00:00"]}"#,
            r#"{"blocked": [], "other": 1}"#,
            r#"{"blocked": [], "configs": {"ap1": {"sha256": "ab", "seq": 1}}}"#,
            r#"{"blocked": [], "configs": {"ap1": {"seq": 1}}}"#,
        ] {
            fs::write(&path, bad).unwrap();
            let e = load(&path).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidData, "{bad}: {e}");
        }
    }
}
