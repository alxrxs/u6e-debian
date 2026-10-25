//! The operator's decisions that outlive the controller: the clients it
//! blocked. `policy.json` is `{"blocked": ["02:00:00:00:00:01", ...]}`. An AP
//! keeps its blocks in RAM only, so this file is what every AP is given again
//! when it connects.
//!
//! A save writes the whole file beside the old one, syncs it, renames it over
//! the old one and syncs the directory: a crash at any point leaves either the
//! old file or the new one, never a part of either.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use u6e_proto::mac;

/// The clients blocked, by MAC.
pub type Blocked = BTreeSet<[u8; 6]>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    blocked: Vec<String>,
}

/// The decisions saved at `path`; none when there is no file yet. A file that
/// does not parse is an error, never an empty policy: starting without its
/// blocks would let every blocked client back on.
pub fn load(path: &Path) -> io::Result<Blocked> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Blocked::new()),
        Err(e) => return Err(e),
    };
    let file: PolicyFile =
        serde_json::from_str(&text).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    file.blocked
        .iter()
        .map(|m| {
            mac::parse(m).ok_or_else(|| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    format!("blocked: {m:?} is not a MAC"),
                )
            })
        })
        .collect()
}

/// Replaces the decisions at `path` with `blocked`.
pub fn save(path: &Path, blocked: &Blocked) -> io::Result<()> {
    let temp = write_temp(path, blocked)?;
    fs::rename(&temp, path)?;
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty());
    File::open(dir.unwrap_or(Path::new(".")))?.sync_all()
}

/// The new file, whole and synced, beside the one it replaces. A temporary
/// file a crash left behind is overwritten.
fn write_temp(path: &Path, blocked: &Blocked) -> io::Result<PathBuf> {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    let temp = path.with_file_name(name);
    let file = PolicyFile {
        blocked: blocked.iter().map(|m| mac::format(*m)).collect(),
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
    use std::time::{SystemTime, UNIX_EPOCH};

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

    fn blocked(lasts: &[u8]) -> Blocked {
        lasts.iter().map(|&l| [2, 0, 0, 0, 0, l]).collect()
    }

    #[test]
    fn saved_then_loaded() {
        let dir = Dir::new("round-trip");
        let path = dir.0.join("policy.json");
        assert_eq!(load(&path).unwrap(), Blocked::new());
        save(&path, &blocked(&[2, 1])).unwrap();
        assert_eq!(load(&path).unwrap(), blocked(&[1, 2]));
        let text = fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"blocked": ["02:00:00:00:00:01", "02:00:00:00:00:02"]})
        );
        save(&path, &Blocked::new()).unwrap();
        assert_eq!(load(&path).unwrap(), Blocked::new());
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
        ] {
            fs::write(&path, bad).unwrap();
            let e = load(&path).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidData, "{bad}: {e}");
        }
    }
}
