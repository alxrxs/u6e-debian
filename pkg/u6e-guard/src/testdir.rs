//! A scratch directory for tests, removed when dropped, and the stand-in
//! for tc the tests run in it.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::{env, fs, process};

static NEXT: AtomicU32 = AtomicU32::new(0);

pub struct TestDir(PathBuf);

impl TestDir {
    pub fn new() -> Self {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = env::temp_dir().join(format!("u6e-guard-test-{}-{n}", process::id()));
        fs::create_dir_all(&dir).unwrap();
        TestDir(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The tests' tc (`testdata/tc`) in `dir`, printing `show` for a `show` or
/// `ls` and logging every other call to `dir/log`. Linked, never written:
/// an executable a test wrote could still be open for writing in a child
/// another test thread forked, and exec'ing it would fail (ETXTBSY).
pub fn fake_tc(dir: &Path, show: &str) -> PathBuf {
    let tc = dir.join("tc");
    if !tc.exists() {
        let fake = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/tc");
        std::os::unix::fs::symlink(fake, &tc).unwrap();
    }
    fs::write(dir.join("show"), show).unwrap();
    tc
}
