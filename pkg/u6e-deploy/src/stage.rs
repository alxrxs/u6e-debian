//! The stage helper: the root end that stages a kept image on an AP for the
//! runner, which runs as its own user and may not. Staging needs what the
//! site's build host holds for it (the APs' root login, the stock firmware's
//! password), so the helper runs u6e-debian's own `boot/stage.sh` for it and
//! nothing else, from a tree root owns (`rollout.tree`: its `boot/`,
//! `site.conf` and `log/`), which it refuses to run unless no one but root
//! could have written it. A request names only an AP of the configuration
//! and the image to stage there, one of the kept images whose `MANIFEST`
//! names that AP (`<images>/<id>/`), checked here again whatever the runner
//! checked. systemd starts one helper for each connection to a socket only
//! root and the runner's group may open (`Accept=yes`) and hands it that
//! connection (`u6e-deploy --stage-helper`); the helper checks its peer too
//! and answers the connection's one request. So each request reads the
//! configuration and runs the binary as they are now, and no root process
//! outlives its request.
//!
//! `Check` answers whether an image could be staged, `Newest` names an AP's
//! newest kept image (by its name, which starts with its build time), and
//! `Stage` streams the command's output, a line at a time, and then how it
//! exited. One staging runs at a time, whoever asks: two APs rebooting at
//! once is what the runner's one rollout at a time exists to prevent, so the
//! root end holds to it too, by a lock on the kept images' directory held
//! for as long as the command runs (the site's own image deploys take the
//! same lock). A command once started runs to its end even if the runner
//! goes away: an AP left between two systems is worse than a staging nobody
//! watches.

use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, ErrorKind, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use u6e_proto::frame::{read_frame, write_frame};

use crate::config::Config;
use crate::frames;

/// The longest output line passed on; a longer one is cut.
const LINE_MAX: usize = 1000;
/// How long a caller may take to send its request.
const REQUEST_WAIT: Duration = Duration::from_secs(10);
/// Why a staging is refused while another runs.
pub const BUSY: &str = "another staging is under way";

/// What the runner asks of the helper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// Whether `image` is a kept image `ap` could be staged with.
    Check { ap: String, image: String },
    /// Stage `image` on `ap`.
    Stage { ap: String, image: String },
    /// The newest kept image of `ap`.
    Newest { ap: String },
}

/// What the helper answers, in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    /// The request may be carried out; the answer to `Check`.
    Ok,
    /// It may not, and why; nothing was run.
    Refused(String),
    /// A line of the command's output.
    Line(String),
    /// How the command exited: its status, -1 when a signal ended it.
    Exit(i32),
    /// The answer to `Newest`.
    Image(String),
}

/// Whether `image` could name a kept image: one path component of letters,
/// digits, `.`, `_` and `-`, not starting with a dot.
fn image_name(image: &str) -> bool {
    let ok = |c: char| c.is_ascii_alphanumeric() || "._-".contains(c);
    (1..=128).contains(&image.len()) && !image.starts_with('.') && image.chars().all(ok)
}

/// The AP an image's `MANIFEST` names: the first word of its `ap:` line.
fn manifest_ap(dir: &Path) -> Option<String> {
    let text = fs::read_to_string(dir.join("MANIFEST")).ok()?;
    let line = text.lines().find_map(|l| l.strip_prefix("ap:"))?;
    line.split_whitespace().next().map(str::to_owned)
}

/// Whether `image` names a kept image of `ap`: its directory, or why not.
pub fn kept(config: &Config, ap: &str, image: &str) -> Result<PathBuf, String> {
    if !config.aps.contains_key(ap) {
        return Err(format!("no AP {ap:.64} in the configuration"));
    }
    if !image_name(image) {
        return Err(format!("{image:.128} is not an image's name"));
    }
    let dir = config.rollout.images.join(image);
    match manifest_ap(&dir) {
        None => Err(format!("no image {image} is kept")),
        Some(of) if of == ap => Ok(dir),
        Some(of) => Err(format!("{image} is {of:.64}'s image, not {ap}'s")),
    }
}

/// The newest kept image of `ap`, by name.
pub fn newest(config: &Config, ap: &str) -> Result<String, String> {
    if !config.aps.contains_key(ap) {
        return Err(format!("no AP {ap:.64} in the configuration"));
    }
    let dir = &config.rollout.images;
    let entries = fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let names = entries.filter_map(|e| e.ok()?.file_name().into_string().ok());
    let mine = names.filter(|n| image_name(n) && manifest_ap(&dir.join(n)).as_deref() == Some(ap));
    mine.max()
        .ok_or_else(|| format!("no image of {ap} is kept"))
}

/// Why the staging tree could have been written by another than root (the
/// helper's own user): an entry of `boot/`, `boot/` itself, `site.conf` or
/// the tree owned by another, writable by its group or by anyone, or a
/// symbolic link; an ancestor of the tree owned by another, or writable by
/// others without the sticky bit. Root runs these files.
fn untrusted(tree: &Path) -> Option<String> {
    // SAFETY: geteuid has no preconditions.
    let me = unsafe { libc::geteuid() };
    let owned = |p: &Path, md: &fs::Metadata| -> Option<String> {
        if md.file_type().is_symlink() {
            return Some(format!("{} is a symbolic link", p.display()));
        }
        if md.uid() != me {
            return Some(format!("{} is not root's", p.display()));
        }
        (md.permissions().mode() & 0o022 != 0)
            .then(|| format!("{} is writable by others than root", p.display()))
    };
    let boot = tree.join("boot");
    let mut paths = vec![tree.to_owned(), boot.clone(), tree.join("site.conf")];
    match fs::read_dir(&boot) {
        Ok(entries) => paths.extend(entries.filter_map(|e| Some(e.ok()?.path()))),
        Err(e) => return Some(format!("{}: {e}", boot.display())),
    }
    for p in &paths {
        match fs::symlink_metadata(p) {
            Ok(md) => {
                if let Some(why) = owned(p, &md) {
                    return Some(why);
                }
            }
            Err(e) => return Some(format!("{}: {e}", p.display())),
        }
    }
    for dir in tree.ancestors().skip(1) {
        let md = match fs::metadata(dir) {
            Ok(md) => md,
            Err(e) => return Some(format!("{}: {e}", dir.display())),
        };
        let mode = md.permissions().mode();
        if (md.uid() != 0 && md.uid() != me) || (mode & 0o022 != 0 && mode & 0o1000 == 0) {
            return Some(format!(
                "{} could be written by others than root",
                dir.display()
            ));
        }
    }
    None
}

/// The kept images' directory, locked (`flock`) for one staging; None while
/// another staging holds it. The lock goes with the file.
pub fn lock(images: &Path) -> io::Result<Option<File>> {
    let dir = File::open(images)?;
    // SAFETY: flock on a descriptor `dir` owns and keeps open.
    if unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(Some(dir));
    }
    let e = io::Error::last_os_error();
    if e.kind() == ErrorKind::WouldBlock {
        Ok(None)
    } else {
        Err(e)
    }
}

/// Answers the one request of a connection.
pub fn serve(config: &Config, conn: &mut (impl io::Read + Write)) -> io::Result<()> {
    let req: Request = read_frame(conn)?;
    let (ap, image) = match &req {
        Request::Newest { ap } => {
            let reply = newest(config, ap).map_or_else(Reply::Refused, Reply::Image);
            return write_frame(conn, &reply);
        }
        Request::Check { ap, image } | Request::Stage { ap, image } => (ap, image),
    };
    // Checked before use: the names go into a path and the command line
    // (the configuration's AP names are plain).
    let dir = match kept(config, ap, image) {
        Ok(dir) => dir,
        Err(why) => return write_frame(conn, &Reply::Refused(why)),
    };
    if matches!(req, Request::Check { .. }) {
        return write_frame(conn, &Reply::Ok);
    }
    let tree = &config.rollout.tree;
    if let Some(why) = untrusted(tree) {
        return write_frame(conn, &Reply::Refused(format!("not staged from it: {why}")));
    }
    // Held until the command exits, whether or not the runner still listens.
    let Some(_staging) = lock(&config.rollout.images)? else {
        return write_frame(conn, &Reply::Refused(BUSY.into()));
    };
    let (reader, writer) = io::pipe()?;
    let script = tree.join("boot/stage.sh");
    let child = {
        let mut cmd = Command::new("/usr/bin/env");
        cmd.arg(format!("U6E_AP={ap}"))
            .arg(&script)
            .arg(&dir)
            .stdin(Stdio::null())
            .stdout(writer.try_clone()?)
            .stderr(writer);
        // The command's ends of the pipe close with `cmd`, so the reader
        // sees the end of the output once the command and its children exit.
        cmd.spawn()
    };
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            let why = format!("{}: {e}", script.display());
            return write_frame(conn, &Reply::Refused(why));
        }
    };
    let mut gone = write_frame(conn, &Reply::Ok).is_err();
    let mut out = BufReader::new(reader);
    let mut line = Vec::new();
    while out.read_until(b'\n', &mut line)? > 0 {
        let text = String::from_utf8_lossy(&line);
        let text: String = text.trim_end().chars().take(LINE_MAX).collect();
        // A runner that went away does not stop the staging.
        gone = gone || write_frame(conn, &Reply::Line(text)).is_err();
        line.clear();
    }
    let status = child.wait()?;
    let code = status.code().unwrap_or(-1);
    if !gone {
        write_frame(conn, &Reply::Exit(code))?;
    }
    Ok(())
}

/// Answers `conn`, if its peer is root or a process of group `gid` and asks
/// within [`REQUEST_WAIT`].
pub fn serve_peer(config: &Config, mut conn: UnixStream, gid: u32) -> io::Result<()> {
    conn.set_read_timeout(Some(REQUEST_WAIT))?;
    match peer(&conn)? {
        (uid, g) if crate::local::allowed(uid, g, gid) => serve(config, &mut conn),
        (uid, _) => Err(io::Error::other(format!("a caller of uid {uid} refused"))),
    }
}

/// The uid and gid of the process at the other end of `conn`.
pub fn peer(conn: &UnixStream) -> io::Result<(u32, u32)> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` and `len` are valid for the call, which writes at most
    // `len` bytes into `cred`.
    let r = unsafe {
        libc::getsockopt(
            conn.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &mut len,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((cred.uid, cred.gid))
}

/// The id of group `name` in an /etc/group.
pub fn group_id(etc_group: &str, name: &str) -> Option<u32> {
    etc_group.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next() == Some(name)).then(|| f.nth(1)?.parse().ok())?
    })
}

/// How a staging ended, as the runner sees it.
#[derive(Debug, PartialEq, Eq)]
pub enum Staged {
    Done,
    /// The helper would not run it: nothing was done to the AP.
    Refused(String),
    /// It ran and failed, or the helper could not be asked: the AP may be
    /// anywhere between its two systems.
    Failed(String),
}

/// The runner's end of the helper.
#[derive(Debug, Clone)]
pub struct Helper {
    pub socket: PathBuf,
}

/// How long a check or a lookup may take.
const ASK_WAIT: Duration = Duration::from_secs(30);

impl Helper {
    async fn ask(&self, req: &Request) -> io::Result<tokio::net::UnixStream> {
        let mut conn = tokio::net::UnixStream::connect(&self.socket).await?;
        frames::write(&mut conn, req).await?;
        Ok(conn)
    }

    /// The one reply to `req`, within [`ASK_WAIT`].
    async fn answer(&self, req: &Request) -> Result<Reply, String> {
        let reply = async { frames::read(&mut self.ask(req).await?).await };
        match tokio::time::timeout(ASK_WAIT, reply).await {
            Ok(Ok(r)) => Ok(r),
            Ok(Err(e)) => Err(format!("the stage helper: {e}")),
            Err(_) => Err(format!("the stage helper: no answer in {ASK_WAIT:?}")),
        }
    }

    /// Whether `image` could be staged on `ap`; why not.
    pub async fn check(&self, ap: &str, image: &str) -> Result<(), String> {
        let req = Request::Check {
            ap: ap.into(),
            image: image.into(),
        };
        match self.answer(&req).await? {
            Reply::Ok => Ok(()),
            Reply::Refused(why) => Err(why),
            other => Err(format!("the stage helper answered {other:?}")),
        }
    }

    /// The newest kept image of `ap`.
    pub async fn newest(&self, ap: &str) -> Result<String, String> {
        match self.answer(&Request::Newest { ap: ap.into() }).await? {
            Reply::Image(id) => Ok(id),
            Reply::Refused(why) => Err(why),
            other => Err(format!("the stage helper answered {other:?}")),
        }
    }

    /// Stages `image` on `ap`, each line of its output to `line`.
    pub async fn stage(&self, ap: &str, image: &str, mut line: impl FnMut(String)) -> Staged {
        let req = Request::Stage {
            ap: ap.into(),
            image: image.into(),
        };
        let mut conn = match self.ask(&req).await {
            Ok(c) => c,
            Err(e) => return Staged::Refused(format!("the stage helper: {e}")),
        };
        loop {
            match frames::read(&mut conn).await {
                Ok(Reply::Ok) => {}
                Ok(Reply::Refused(why)) => return Staged::Refused(why),
                Ok(Reply::Line(l)) => line(l),
                Ok(Reply::Exit(0)) => return Staged::Done,
                Ok(Reply::Exit(code)) => {
                    return Staged::Failed(format!("the staging exited with {code}"));
                }
                Ok(Reply::Image(_)) => {
                    return Staged::Failed("the stage helper answered out of turn".into());
                }
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                    return Staged::Failed("the stage helper ended before the staging".into());
                }
                Err(e) => return Staged::Failed(format!("the stage helper: {e}")),
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::Arc;
    use std::thread;

    use crate::config::tests::text;
    use crate::tests::TestDir;

    /// A staging tree in `dir` whose `boot/stage.sh` is `script`, root's
    /// (the test's own user's) and written by no other.
    pub fn tree(dir: &Path, script: &str) -> PathBuf {
        let tree = dir.join("tree");
        fs::create_dir_all(tree.join("boot")).unwrap();
        fs::create_dir_all(tree.join("log")).unwrap();
        fs::write(tree.join("site.conf"), "").unwrap();
        fs::write(tree.join("boot/stage.sh"), format!("#!/bin/sh\n{script}\n")).unwrap();
        for (p, mode) in [
            (dir.to_owned(), 0o755),
            (tree.clone(), 0o755),
            (tree.join("boot"), 0o755),
            (tree.join("site.conf"), 0o644),
            (tree.join("boot/stage.sh"), 0o755),
        ] {
            fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
        }
        tree
    }

    /// A kept image of `ap` in `images`.
    pub fn keep(images: &Path, id: &str, ap: &str) {
        fs::create_dir_all(images.join(id)).unwrap();
        let manifest = format!("ap:        {ap} (u6e-{ap}, 192.0.2.1/24)\nkernel:    x\n");
        fs::write(images.join(id).join("MANIFEST"), manifest).unwrap();
    }

    /// A configuration whose images are in `dir`, kept for ap1 (and ap2,
    /// `<id>` ending in `-ap2`), staged by `script`.
    pub fn config(dir: &Path, kept: &[&str], script: &str) -> Config {
        let mut c = Config::parse(&text("")).unwrap();
        c.rollout.images = dir.join("images");
        fs::create_dir_all(&c.rollout.images).unwrap();
        for id in kept {
            let ap = if id.ends_with("-ap2") { "ap2" } else { "ap1" };
            keep(&c.rollout.images, id, ap);
        }
        c.rollout.tree = tree(dir, script);
        c.rollout.helper = dir.join("stage.sock");
        c
    }

    /// The helper on its socket as systemd runs it, one per connection,
    /// serving root and the test's own group.
    pub fn listen(config: Config) {
        let listener = UnixListener::bind(&config.rollout.helper).unwrap();
        // SAFETY: getegid has no preconditions.
        let gid = unsafe { libc::getegid() };
        let config = Arc::new(config);
        thread::spawn(move || {
            for conn in listener.incoming() {
                let config = Arc::clone(&config);
                thread::spawn(move || serve_peer(&config, conn.unwrap(), gid));
            }
        });
    }

    fn ask(c: &Config, req: Request) -> Vec<Reply> {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        write_frame(&mut a, &req).unwrap();
        serve(c, &mut b).unwrap();
        drop(b);
        let mut out = Vec::new();
        while let Ok(r) = read_frame(&mut a) {
            out.push(r);
        }
        out
    }

    fn stage(image: &str) -> Request {
        Request::Stage {
            ap: "ap1".into(),
            image: image.into(),
        }
    }

    const IMG: &str = "20261025-120000-abc-def-ap1";

    #[test]
    fn only_a_kept_image_of_a_configured_ap_is_staged() {
        let t = TestDir::new();
        let c = config(t.path(), &[IMG, "20261025-x-ap2"], "echo $1");
        // An image named for ap1 whose MANIFEST names another AP.
        keep(&c.rollout.images, "20261025-y-big-ap1", "big-ap1");
        assert_eq!(kept(&c, "ap1", IMG), Ok(t.path().join("images").join(IMG)));
        for (ap, image, why) in [
            ("ap2", "20261025-x-ap2", "no AP ap2 in the configuration"),
            (
                "ap1",
                "20261025-x-ap2",
                "20261025-x-ap2 is ap2's image, not ap1's",
            ),
            (
                "ap1",
                "20261025-y-big-ap1",
                "20261025-y-big-ap1 is big-ap1's image, not ap1's",
            ),
            (
                "ap1",
                "../../etc-ap1",
                "../../etc-ap1 is not an image's name",
            ),
            ("ap1", ".hidden-ap1", ".hidden-ap1 is not an image's name"),
            ("ap1", "a b-ap1", "a b-ap1 is not an image's name"),
            ("ap1", "missing-ap1", "no image missing-ap1 is kept"),
        ] {
            assert_eq!(kept(&c, ap, image), Err(why.into()), "{ap} {image}");
            let req = Request::Stage {
                ap: ap.into(),
                image: image.into(),
            };
            assert_eq!(ask(&c, req), [Reply::Refused(why.into())]);
        }
        let req = Request::Check {
            ap: "ap1".into(),
            image: IMG.into(),
        };
        assert_eq!(ask(&c, req), [Reply::Ok]);
    }

    /// The newest of an AP's kept images, by name, which starts with the
    /// build time.
    #[test]
    fn the_newest_kept_image_of_an_ap() {
        let t = TestDir::new();
        let older = "20261024-120000-abc-def-ap1";
        let c = config(t.path(), &[older, IMG, "20261026-x-ap2"], "true");
        let newest = |ap: &str| ask(&c, Request::Newest { ap: ap.into() });
        assert_eq!(newest("ap1"), [Reply::Image(IMG.into())]);
        assert_eq!(
            newest("ap9"),
            [Reply::Refused("no AP ap9 in the configuration".into())]
        );
    }

    /// The command gets the AP and the image's directory, its output comes
    /// line by line, stderr too, and then its exit status.
    #[test]
    fn a_staging_streams_its_output_and_its_status() {
        let t = TestDir::new();
        let c = config(
            t.path(),
            &[IMG],
            "echo staging $1 on $U6E_AP; echo oops >&2; exit 3",
        );
        let dir = t.path().join("images").join(IMG);
        assert_eq!(
            ask(&c, stage(IMG)),
            [
                Reply::Ok,
                Reply::Line(format!("staging {} on ap1", dir.display())),
                Reply::Line("oops".into()),
                Reply::Exit(3),
            ]
        );
    }

    /// Root runs the tree's files, so it refuses one another could have
    /// written: group- or world-writable, a symbolic link, or another's.
    #[test]
    fn a_tree_others_could_write_is_not_run() {
        let t = TestDir::new();
        let c = config(t.path(), &[IMG], "echo ran > \"${1%/images/*}/ran\"");
        let script = c.rollout.tree.join("boot/stage.sh");
        let writable = |p: &Path, mode| fs::set_permissions(p, fs::Permissions::from_mode(mode));
        writable(&script, 0o775).unwrap();
        let why = format!(
            "not staged from it: {} is writable by others than root",
            script.display()
        );
        assert_eq!(ask(&c, stage(IMG)), [Reply::Refused(why)]);
        writable(&script, 0o755).unwrap();
        let lib = c.rollout.tree.join("boot/lib.sh");
        std::os::unix::fs::symlink("/etc/passwd", &lib).unwrap();
        let why = format!("not staged from it: {} is a symbolic link", lib.display());
        assert_eq!(ask(&c, stage(IMG)), [Reply::Refused(why)]);
        fs::remove_file(&lib).unwrap();
        writable(&c.rollout.tree.join("boot"), 0o777).unwrap();
        assert!(matches!(&ask(&c, stage(IMG))[..], [Reply::Refused(_)]));
        assert!(!t.path().join("ran").exists());
        writable(&c.rollout.tree.join("boot"), 0o755).unwrap();
        assert_eq!(ask(&c, stage(IMG)), [Reply::Ok, Reply::Exit(0)]);
        assert!(t.path().join("ran").exists());
    }

    /// While one staging runs, another is refused before anything runs; a
    /// check is still answered.
    #[test]
    fn one_staging_at_a_time() {
        let t = TestDir::new();
        let c = config(t.path(), &[IMG], "echo ran >> \"${1%/images/*}/ran\"");
        // Another helper's staging: a process of its own, as each helper is.
        // A lock taken in this one could outlive its drop in a child another
        // test forks meanwhile, which shares the open file until it execs.
        // --no-fork: the shell, and then sleep, hold the lock flock(1) took.
        let mut held = Command::new("flock")
            .arg("--no-fork")
            .arg(&c.rollout.images)
            .args(["-c", "echo locked; exec sleep 60"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut locked = String::new();
        BufReader::new(held.stdout.take().unwrap())
            .read_line(&mut locked)
            .unwrap();
        assert_eq!(locked, "locked\n");
        assert!(lock(&c.rollout.images).unwrap().is_none());
        assert_eq!(ask(&c, stage(IMG)), [Reply::Refused(BUSY.into())]);
        let check = Request::Check {
            ap: "ap1".into(),
            image: IMG.into(),
        };
        assert_eq!(ask(&c, check), [Reply::Ok]);
        assert!(!t.path().join("ran").exists());
        held.kill().unwrap();
        held.wait().unwrap();
        assert_eq!(ask(&c, stage(IMG)), [Reply::Ok, Reply::Exit(0)]);
        assert!(t.path().join("ran").exists());
    }

    #[test]
    fn the_runner_end() {
        let t = TestDir::new();
        let c = config(t.path(), &[IMG], "echo one; echo two");
        let helper = Helper {
            socket: c.rollout.helper.clone(),
        };
        listen(c);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            assert_eq!(helper.check("ap1", IMG).await, Ok(()));
            assert_eq!(
                helper.check("ap1", "x-ap1").await,
                Err("no image x-ap1 is kept".into())
            );
            assert_eq!(helper.newest("ap1").await, Ok(IMG.into()));
            let mut lines = Vec::new();
            assert_eq!(
                helper.stage("ap1", IMG, |l| lines.push(l)).await,
                Staged::Done
            );
            assert_eq!(lines, ["one", "two"]);
            let gone = Helper {
                socket: t.path().join("none"),
            };
            assert!(matches!(
                gone.stage("ap1", IMG, |_| {}).await,
                Staged::Refused(_)
            ));
        });
    }

    #[test]
    fn groups_by_name() {
        let etc = "root:x:0:\nu6e-deploy:x:997:\nother:x:12:a,b\n";
        assert_eq!(group_id(etc, "u6e-deploy"), Some(997));
        assert_eq!(group_id(etc, "u6e"), None);
    }
}
