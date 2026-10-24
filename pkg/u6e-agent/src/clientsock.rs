//! The client end of a hostapd control socket: a datagram socket bound at a
//! path of its own in the agent's run directory. The path carries the process
//! id and a counter, as wpa_ctrl's do, so a second instance (`--print-snapshot`,
//! a test agent) never takes the resident agent's and deafens it. A path goes
//! with its socket, and those of processes that have died are swept at the
//! next bind.

use std::fs;
use std::io;
use std::ops::Deref;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU32, Ordering};

/// The agent's run directory (the unit's `RuntimeDirectory=`).
pub const RUN: &str = "/run/u6e-agent";

static NEXT: AtomicU32 = AtomicU32::new(0);

pub struct ClientSocket {
    sock: UnixDatagram,
    dir: PathBuf,
    what: String,
    path: PathBuf,
}

impl ClientSocket {
    /// A socket at `<dir>/<what>-<pid>-<n>`.
    pub fn bind(dir: &Path, what: &str) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        sweep(dir);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!("{what}-{}-{n}", process::id()));
        let sock = UnixDatagram::bind(&path)?;
        Ok(ClientSocket {
            sock,
            dir: dir.to_owned(),
            what: what.to_owned(),
            path,
        })
    }

    /// Whether answers can still reach the socket: they are sent to its
    /// path, and one removed from the directory leads nowhere.
    pub fn reachable(&self) -> bool {
        self.path.exists()
    }

    /// A new socket for the same purpose, in place of an unreachable one.
    pub fn rebind(&self) -> io::Result<Self> {
        Self::bind(&self.dir, &self.what)
    }
}

impl Deref for ClientSocket {
    type Target = UnixDatagram;

    fn deref(&self) -> &UnixDatagram {
        &self.sock
    }
}

impl Drop for ClientSocket {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Removes the sockets in `dir` whose process is gone.
fn sweep(dir: &Path) {
    for e in fs::read_dir(dir).into_iter().flatten().flatten() {
        let name = e.file_name();
        let pid = name
            .to_str()
            .and_then(|n| n.rsplit('-').nth(1))
            .and_then(|p| p.parse::<libc::pid_t>().ok());
        if pid.is_some_and(|p| p > 0 && !alive(p)) {
            let _ = fs::remove_file(e.path());
        }
    }
}

fn alive(pid: libc::pid_t) -> bool {
    // Signal 0 checks for the process without signalling it; EPERM means it
    // exists but is another user's.
    let found = unsafe { libc::kill(pid, 0) } == 0;
    found || io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;

    #[test]
    fn each_socket_has_its_own_path_and_takes_it_along() {
        let t = TestDir::new();
        let a = ClientSocket::bind(t.path(), "collect").unwrap();
        let b = ClientSocket::bind(t.path(), "collect").unwrap();
        assert_ne!(a.path, b.path);
        let (pa, pb) = (a.path.clone(), b.path.clone());
        drop(b);
        assert!(pa.exists() && !pb.exists());
    }

    #[test]
    fn the_sockets_of_dead_processes_are_swept() {
        let t = TestDir::new();
        // Above any pid_max: no such process.
        let dead = t.path().join("ev-wlan5-1-1073741823-0");
        // init's, this process's, and names without a pid.
        let others = [
            t.path().join("collect-1-0"),
            t.path().join(format!("ctrl-{}-999", process::id())),
            t.path().join("ctrl"),
            t.path().join("x-y-z"),
        ];
        for p in others.iter().chain([&dead]) {
            fs::write(p, "").unwrap();
        }
        let _s = ClientSocket::bind(t.path(), "collect").unwrap();
        assert!(!dead.exists());
        assert!(others.iter().all(|p| p.exists()));
    }
}
