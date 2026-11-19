//! The AP's rate-limit helper: it puts the agent's limits on the NSS
//! shaper (`plan`, `apply`), which the agent cannot (`tc` and nftables want
//! CAP_NET_ADMIN, ECM's deceleration is root's), and does nothing else, in a
//! sandbox that shows it only those (see prep-rootfs.sh for the units).
//!
//!   u6e-shaper serve
//!   u6e-shaper revert
//!
//! `serve` answers one request on the connection systemd passes as stdin
//! (`u6e_proto::shaper`), a member of the agent's group's only. A sync keeps
//! the state before it in a pending file until it is done; one that built a
//! tree is done only once the agent confirms it within 20 s (its link to the
//! controller still flows through the uplink), and is undone otherwise.
//! `revert`, the unit's last step whatever ended it, undoes a sync the helper
//! died in. The state lives in /run: a reboot clears it, and the NSS with it.

mod apply;
mod check;
mod host;
mod plan;

use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{env, process};

use serde::Serialize;
use serde::de::DeserializeOwned;
use u6e_proto::frame::{read_frame, write_frame};
use u6e_proto::local;
use u6e_proto::shaper::{CONFIRM_SECS, Reply, Request};

use apply::State;
use host::{Host, System};

/// The group whose members are served: the agent's.
const AGENT_GROUP: &str = "u6e-agent";
/// The helper's directory: its lock, its state and a sync's pending state.
const DIR: &str = "/run/u6e-shaper";
/// How long the agent may take to send its request.
const REQUEST_WAIT: Duration = Duration::from_secs(10);

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let dir = PathBuf::from(DIR);
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["serve"] => serve(&dir),
        ["revert"] => {
            let _lock = lock(&dir);
            revert_pending(&mut System::default(), &dir)
        }
        _ => {
            eprintln!("usage: u6e-shaper serve | revert");
            process::exit(2);
        }
    };
    if let Err(e) = result {
        eprintln!("u6e-shaper: {e}");
        process::exit(1);
    }
}

fn serve(dir: &Path) -> io::Result<()> {
    let gid = local::group_id(&fs::read_to_string("/etc/group")?, AGENT_GROUP)
        .ok_or_else(|| io::Error::other(format!("no group {AGENT_GROUP}")))?;
    // SAFETY: systemd passes the accepted connection as stdin, which nothing
    // else here uses.
    let mut conn = unsafe { UnixStream::from_raw_fd(0) };
    if !local::member(&conn, gid) {
        return Err(io::Error::other("a peer outside the agent's group"));
    }
    conn.set_read_timeout(Some(REQUEST_WAIT))?;
    let req: Request = read_frame(&mut conn)?;
    let _lock = lock(dir)?;
    handle(&mut System::default(), dir, &mut conn, req)
}

/// Answers `req` on `conn`, with the helper's lock held.
fn handle<H: Host>(h: &mut H, dir: &Path, conn: &mut UnixStream, req: Request) -> io::Result<()> {
    revert_pending(h, dir)?;
    let cur: State = load(&dir.join("state"))?.unwrap_or_default();
    match req {
        Request::Sync(spec) => {
            store(&dir.join("pending"), &cur)?;
            let synced = match apply::sync(h, &cur, &spec) {
                Ok(s) => s,
                Err(why) => {
                    remove(&dir.join("pending"))?;
                    return write_frame(conn, &Reply::Refused(why));
                }
            };
            store(&dir.join("state"), &synced.state)?;
            if !synced.built {
                remove(&dir.join("pending"))?;
            }
            let outcomes = synced.state.outcomes.clone();
            let reply = Reply::Synced {
                outcomes,
                confirm: synced.built,
            };
            write_frame(conn, &reply)?;
            if synced.built {
                conn.set_read_timeout(Some(Duration::from_secs(CONFIRM_SECS)))?;
                match read_frame::<_, Request>(conn) {
                    Ok(Request::Confirm) => {
                        remove(&dir.join("pending"))?;
                        write_frame(conn, &Reply::Done)?;
                    }
                    other => {
                        let why = other
                            .err()
                            .map_or_else(|| "no confirmation".into(), |e| e.to_string());
                        eprintln!("u6e-shaper: the sync was not confirmed ({why}): undoing it");
                        revert_pending(h, dir)?;
                    }
                }
            }
            Ok(())
        }
        Request::Counters => write_frame(conn, &Reply::Counters(apply::counters(h, &cur))),
        Request::Confirm => write_frame(conn, &Reply::Refused("nothing to confirm".into())),
    }
}

/// Puts back the state a sync left pending, if one did.
fn revert_pending<H: Host>(h: &mut H, dir: &Path) -> io::Result<()> {
    let Some(prev) = load::<State>(&dir.join("pending"))? else {
        return Ok(());
    };
    let back = apply::revert(h, &prev);
    store(&dir.join("state"), &back)?;
    remove(&dir.join("pending"))?;
    eprintln!("u6e-shaper: the shaping before the last sync is back");
    Ok(())
}

/// The helper's lock, held until dropped: one request at a time.
fn lock(dir: &Path) -> io::Result<File> {
    let f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(dir.join("lock"))?;
    // SAFETY: flock on a descriptor this function owns.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(f)
}

fn load<T: DeserializeOwned>(path: &Path) -> io::Result<Option<T>> {
    match fs::read(path) {
        Ok(b) => postcard::from_bytes(&b).map(Some).map_err(|e| {
            io::Error::new(ErrorKind::InvalidData, format!("{}: {e}", path.display()))
        }),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Replaces `path` with `value`, whole or not at all.
fn store<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let bytes = postcard::to_stdvec(value).map_err(io::Error::other)?;
    let temp = path.with_extension("new");
    fs::write(&temp, bytes)?;
    fs::rename(&temp, path)
}

fn remove(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::tests::Fake;
    use crate::check::tests::spec;
    use std::thread;
    use u6e_proto::shaper::Spec;

    struct Dir(PathBuf);

    impl Dir {
        fn new(name: &str) -> Self {
            let d = env::temp_dir().join(format!("u6e-shaper-{name}-{}", process::id()));
            let _ = fs::remove_dir_all(&d);
            fs::create_dir_all(&d).unwrap();
            Dir(d)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Runs one request through `handle` on a socket pair; `agent` is what
    /// the agent does with its end after sending it.
    fn exchange(
        h: &mut Fake,
        dir: &Path,
        req: Request,
        agent: impl FnOnce(&mut UnixStream) -> Vec<Reply> + Send + 'static,
    ) -> Vec<Reply> {
        let (mut ours, mut theirs) = UnixStream::pair().unwrap();
        let t = thread::spawn(move || agent(&mut theirs));
        handle(h, dir, &mut ours, req).unwrap();
        drop(ours);
        t.join().unwrap()
    }

    fn replies(conn: &mut UnixStream) -> Vec<Reply> {
        let mut out = Vec::new();
        while let Ok(r) = read_frame::<_, Reply>(conn) {
            out.push(r);
        }
        out
    }

    #[test]
    fn a_confirmed_sync_stays() {
        let d = Dir::new("confirm");
        let mut h = Fake::new();
        let got = exchange(&mut h, &d.0, Request::Sync(spec()), |c| {
            let first: Reply = read_frame(c).unwrap();
            write_frame(c, &Request::Confirm).unwrap();
            let mut all = vec![first];
            all.extend(replies(c));
            all
        });
        assert!(matches!(&got[0], Reply::Synced { confirm: true, .. }));
        assert_eq!(got[1], Reply::Done);
        assert!(h.roots.contains("lan"));
        assert!(!d.0.join("pending").exists());
        let state: State = load(&d.0.join("state")).unwrap().unwrap();
        assert_eq!(state.trees.len(), 3);
    }

    #[test]
    fn an_unconfirmed_sync_is_undone() {
        let d = Dir::new("unconfirmed");
        let mut h = Fake::new();
        // The agent hangs up without confirming.
        let got = exchange(&mut h, &d.0, Request::Sync(spec()), |c| {
            vec![read_frame(c).unwrap()]
        });
        assert!(matches!(&got[0], Reply::Synced { confirm: true, .. }));
        assert!(h.roots.is_empty() && h.classes.is_empty() && h.table.is_none());
        assert!(!d.0.join("pending").exists());
        let state: State = load(&d.0.join("state")).unwrap().unwrap();
        assert_eq!(state, apply::revert(&mut Fake::new(), &State::default()));
    }

    #[test]
    fn a_sync_that_built_nothing_needs_no_confirmation() {
        let d = Dir::new("nobuild");
        let mut h = Fake::new();
        let got = exchange(&mut h, &d.0, Request::Sync(Spec::default()), replies);
        assert_eq!(got.len(), 1);
        assert!(matches!(&got[0], Reply::Synced { confirm: false, .. }));
        assert!(!d.0.join("pending").exists());
    }

    #[test]
    fn a_sync_the_helper_died_in_is_undone_by_the_next_or_by_revert() {
        let d = Dir::new("died");
        let mut h = Fake::new();
        let before = apply::sync(&mut h, &State::default(), &Spec::default())
            .unwrap()
            .state;
        store(&d.0.join("pending"), &before).unwrap();
        // What the dead sync built.
        let dead = apply::sync(&mut h, &before, &spec()).unwrap().state;
        store(&d.0.join("state"), &dead).unwrap();
        assert!(!h.roots.is_empty());
        revert_pending(&mut h, &d.0).unwrap();
        assert!(h.roots.is_empty() && h.table.is_none());
        assert!(!d.0.join("pending").exists());
        // Nothing pending: nothing to do.
        h.log.clear();
        revert_pending(&mut h, &d.0).unwrap();
        assert!(h.log.is_empty());
    }

    #[test]
    fn counters_and_a_stray_confirm_are_answered() {
        let d = Dir::new("counters");
        let mut h = Fake::new();
        let state = apply::sync(&mut h, &State::default(), &spec())
            .unwrap()
            .state;
        store(&d.0.join("state"), &state).unwrap();
        let got = exchange(&mut h, &d.0, Request::Counters, replies);
        let [Reply::Counters(c)] = &got[..] else {
            panic!("{got:?}")
        };
        assert_eq!((c[0].down_bytes, c[0].up_bytes), (2468, 1234));
        let got = exchange(&mut h, &d.0, Request::Confirm, replies);
        assert!(matches!(&got[..], [Reply::Refused(_)]));
    }

    #[test]
    fn a_refused_spec_is_answered_and_nothing_is_pending() {
        let d = Dir::new("refused");
        let mut h = Fake::new();
        let mut s = spec();
        s.clients[0].mac = [0xff; 6];
        let got = exchange(&mut h, &d.0, Request::Sync(s), replies);
        assert!(matches!(&got[..], [Reply::Refused(_)]));
        assert!(!d.0.join("pending").exists() && h.log.is_empty());
    }
}
