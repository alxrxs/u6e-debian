//! A directory of a test's own, removed when it ends. It is under the
//! system's temporary directory, not the target directory: the controller's
//! local socket goes in it, and a socket's path must fit `sun_path` (108
//! bytes), which a deep target directory exceeds. Each is new: its name
//! counts within the process, since two tests may start in the same
//! nanosecond, and the time keeps a reused process ID's apart.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicU32 = AtomicU32::new(0);

pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(name: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("u6e-{name}-{}-{n}-{nanos}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
