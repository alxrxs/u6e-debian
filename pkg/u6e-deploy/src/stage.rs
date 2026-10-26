//! The stage helper: the root end that stages a kept image on an AP for the
//! runner, which runs as its own user and may not. Staging needs what the
//! site's build host holds for it (the APs' root login, the stock firmware's
//! password), so the helper runs u6e-debian's own `boot/stage.sh` for it and
//! nothing else, from a tree root owns (`rollout.tree`: its `boot/`,
//! `site.conf`, `log/` and what else the site keeps there, its `known_hosts`
//! say), which it refuses to run unless no one but root could have written
//! it. A request names only an AP of the configuration and the image to stage
//! there, one of the kept images whose `MANIFEST` names that AP
//! (`<images>/<id>/`), checked here again whatever the runner checked.
//! systemd starts one helper for each connection to a socket only root and
//! the runner's group may open (`Accept=yes`) and hands it that connection
//! (`u6e-deploy --stage-helper`); the helper checks its peer too. So each
//! connection reads the configuration and runs the binary as they are now,
//! and no root process outlives its connection.
//!
//! The kept images are another user's to write (the build user's), so root
//! never runs anything of theirs, nor anything from where they could write:
//! the files the image's `MANIFEST` lists are copied into a directory of
//! root's alone, each checked against the SHA-256 the `MANIFEST` gives it,
//! and `boot/stage.sh` runs with that copy as its argument and working
//! directory, and with Python kept from importing from it (`PYTHONSAFEPATH`,
//! `PYTHONNOUSERSITE`; the scripts call `python3 -I` too).
//!
//! `Check` answers whether an image could be staged, `Newest` names an AP's
//! newest kept image (by its name, which starts with its build time), and
//! `Stage` streams the command's output, a line at a time, and then how it
//! exited. One staging runs at a time, whoever asks: two APs rebooting at
//! once is what the runner's one rollout at a time exists to prevent, so the
//! root end holds to it too, by a lock on the kept images' directory, which
//! the site's own image deploys take too. A connection answers one request,
//! unless its first is `Hold`: the lock is then taken and held for the
//! connection's life, but no longer than [`HOLD_MAX`], and its stagings run
//! under it, so the runner keeps every other staging out through a
//! rollout's gate and its way back. A command once started runs to its end
//! even if the runner goes away (an AP left between two systems is worse
//! than a staging nobody watches), but no longer than [`STAGE_MAX`].

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::digest;
use serde::{Deserialize, Serialize};
use u6e_proto::frame::{read_frame, write_frame};
use u6e_proto::mac;

use crate::config::Config;
use crate::frames;

/// The longest output line passed on; a longer one is cut.
const LINE_MAX: usize = 1000;
/// How long a caller may take to send its request.
const REQUEST_WAIT: Duration = Duration::from_secs(10);
/// The longest a staging may take (`stage.sh` waits up to 400 s for stock
/// and 600 s for the image, around go8.sh's writes): the helper stops one
/// that runs longer, and the runner waits no longer for it.
pub const STAGE_MAX: Duration = Duration::from_secs(45 * 60);
/// The longest a connection holds the lock: a rollout's staging and its way
/// back, with a few minutes each to copy an image and to wait, its longest
/// gate and the linger past it. A rollout never needs it longer; the helper
/// then lets it go, and its unit must let a connection live past it.
pub const HOLD_MAX: Duration = Duration::from_secs(
    2 * (STAGE_MAX.as_secs() + 3 * 60)
        + crate::config::GATE_MAX.as_secs()
        + crate::rollout::LINGER.as_secs(),
);

/// How long a staging, and a hold, may last.
#[derive(Debug, Clone, Copy)]
pub struct Bounds {
    pub stage: Duration,
    pub hold: Duration,
}

/// The bounds a helper keeps to.
pub const BOUNDS: Bounds = Bounds {
    stage: STAGE_MAX,
    hold: HOLD_MAX,
};
/// Why a staging or a hold is refused while another holds the lock.
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
    /// Take the lock for the life of the connection, which then carries
    /// further requests.
    Hold,
}

/// What the helper answers, in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    /// The request may be carried out; the answer to `Check` and `Hold`.
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

/// The largest `MANIFEST` read.
const MANIFEST_MAX: u64 = 64 * 1024;
/// The most a staging copies of an image's files, all together: a real
/// image is under 100 MB, and the copy is in the helper's own `/tmp`.
pub const IMAGE_MAX: u64 = 256 * 1024 * 1024;

/// A kept image's directory, opened without following a link to it.
struct ImageDir(File);

impl ImageDir {
    fn open(dir: &Path) -> io::Result<ImageDir> {
        let flags = libc::O_DIRECTORY | libc::O_NOFOLLOW;
        let d = OpenOptions::new().read(true).custom_flags(flags).open(dir);
        d.map(ImageDir)
    }

    /// Its file `name` and its size: no link followed, never waiting on a
    /// FIFO or a device, and none but a regular file.
    fn file(&self, name: &str) -> io::Result<(File, u64)> {
        let c = CString::new(name).map_err(io::Error::other)?;
        let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
        // SAFETY: `c` is a valid C string, and the descriptor `self.0` holds
        // is open for as long as the call.
        let fd = unsafe { libc::openat(self.0.as_raw_fd(), c.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was just opened, and nothing else owns it.
        let f = unsafe { File::from_raw_fd(fd) };
        let md = f.metadata()?;
        if !md.is_file() {
            return Err(io::Error::other("not a regular file"));
        }
        Ok((f, md.len()))
    }

    /// Its `MANIFEST`, as long as it is not too long to be one.
    fn manifest(&self) -> io::Result<String> {
        let (f, len) = self.file("MANIFEST")?;
        if len > MANIFEST_MAX {
            return Err(io::Error::other("too long to be a MANIFEST"));
        }
        let mut text = String::new();
        f.take(MANIFEST_MAX).read_to_string(&mut text)?;
        Ok(text)
    }
}

/// The AP a `MANIFEST` names: the first word of its `ap:` line.
fn ap_of(manifest: &str) -> Option<String> {
    let line = manifest.lines().find_map(|l| l.strip_prefix("ap:"))?;
    line.split_whitespace().next().map(str::to_owned)
}

/// The AP the `MANIFEST` of the image in `dir` names.
fn manifest_ap(dir: &Path) -> Option<String> {
    ap_of(&ImageDir::open(dir).and_then(|d| d.manifest()).ok()?)
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
/// helper's own user): the tree, an entry of it or of its `boot/` owned by
/// another, writable by its group or by anyone, or a symbolic link; an
/// ancestor of the tree owned by another, or writable by others without the
/// sticky bit. Root runs and reads these files.
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
    let mut paths = vec![tree.to_owned(), tree.join("site.conf")];
    for dir in [tree.to_owned(), tree.join("boot")] {
        match fs::read_dir(&dir) {
            Ok(entries) => paths.extend(entries.filter_map(|e| Some(e.ok()?.path()))),
            Err(e) => return Some(format!("{}: {e}", dir.display())),
        }
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

/// The files an image's `MANIFEST` lists, by name, with their SHA-256: its
/// lines `<64 hex digits>  <path>`, the name the path's last part.
fn listed(manifest: &str) -> Result<Vec<(String, [u8; 32])>, String> {
    let mut files: Vec<(String, [u8; 32])> = Vec::new();
    for line in manifest.lines() {
        let Some((hex, path)) = line.split_once("  ") else {
            continue;
        };
        let Some(sha256) = mac::unhex(hex).filter(|_| !hex.bytes().any(|b| b.is_ascii_uppercase()))
        else {
            continue;
        };
        let name = path.rsplit('/').next().unwrap_or_default();
        if !image_name(name) || name == "MANIFEST" || files.iter().any(|(n, _)| n == name) {
            return Err(format!(
                "the MANIFEST lists {path:.128}, not a file to copy"
            ));
        }
        files.push((name.to_owned(), sha256));
    }
    Ok(files)
}

/// A copy of a kept image, in a directory of root's alone, removed with it.
struct Copy {
    /// The directory made for it; the image is `<top>/<id>`.
    top: PathBuf,
    dir: PathBuf,
}

impl Drop for Copy {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.top);
    }
}

/// Copies the image of `ap` in `dir` (its `MANIFEST`, which must still name
/// `ap`, and the files it lists, each checked against its SHA-256 as it is
/// copied, none but a regular file, no more than [`IMAGE_MAX`] in all) into
/// a new directory under `under`, root's alone.
fn copy_image(dir: &Path, ap: &str, under: &Path) -> Result<Copy, String> {
    static N: AtomicU32 = AtomicU32::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let n = N.fetch_add(1, Ordering::Relaxed);
    let top = under.join(format!("u6e-stage-{}-{nanos}-{n}", std::process::id()));
    let id = dir.file_name().unwrap_or_default();
    let copy = Copy {
        dir: top.join(id),
        top,
    };
    let made = fs::DirBuilder::new().mode(0o700).create(&copy.top);
    made.and_then(|()| fs::DirBuilder::new().mode(0o700).create(&copy.dir))
        .map_err(|e| format!("{}: {e}", copy.top.display()))?;
    let image = ImageDir::open(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let manifest = image.manifest().map_err(|e| format!("the MANIFEST: {e}"))?;
    // The MANIFEST read here is the one copied: it must name the AP still.
    if ap_of(&manifest).as_deref() != Some(ap) {
        return Err(format!("its MANIFEST no longer names {ap}"));
    }
    fs::write(copy.dir.join("MANIFEST"), &manifest).map_err(|e| e.to_string())?;
    let mut files = Vec::new();
    let mut total = 0;
    for (name, want) in listed(&manifest)? {
        let (src, len) = image.file(&name).map_err(|e| format!("{name}: {e}"))?;
        total += len;
        files.push((name, want, src));
    }
    if total > IMAGE_MAX {
        return Err(format!(
            "its files hold {total} B, more than the {IMAGE_MAX} B a staging copies"
        ));
    }
    let mut left = IMAGE_MAX;
    for (name, want, src) in files {
        // No more than the bound, though a file grows while it is copied.
        let mut src = src.take(left + 1);
        let mut dst = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(copy.dir.join(&name))
            .map_err(|e| format!("{name}: {e}"))?;
        let mut sha = digest::Context::new(&digest::SHA256);
        let mut buf = vec![0; 1 << 16];
        loop {
            let n = src.read(&mut buf).map_err(|e| format!("{name}: {e}"))?;
            if n == 0 {
                break;
            }
            left = left.checked_sub(n as u64).ok_or_else(|| {
                format!("its files hold more than the {IMAGE_MAX} B a staging copies")
            })?;
            sha.update(&buf[..n]);
            dst.write_all(&buf[..n])
                .map_err(|e| format!("{name}: {e}"))?;
        }
        if sha.finish().as_ref() != want {
            return Err(format!("{name} is not the file its MANIFEST lists"));
        }
    }
    Ok(copy)
}

/// A connection to the helper whose reads may be given a deadline.
pub trait Conn: io::Read + Write {
    fn wait(&mut self, deadline: Option<Duration>) -> io::Result<()>;
}

impl Conn for UnixStream {
    fn wait(&mut self, deadline: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(deadline)
    }
}

/// Answers a connection: its one request, or, when it holds the lock, each
/// it sends until it closes, or until it has held it for `bounds.hold`. A
/// staging is stopped past `bounds.stage`.
pub fn serve(config: &Config, conn: &mut impl Conn, bounds: Bounds) -> io::Result<()> {
    let bound = bounds.stage;
    let req: Request = read_frame(conn)?;
    if req != Request::Hold {
        return answer(config, conn, req, None, bound);
    }
    let Some(held) = lock(&config.rollout.images)? else {
        return write_frame(conn, &Reply::Refused(BUSY.into()));
    };
    write_frame(conn, &Reply::Ok)?;
    // The runner asks again when its rollout needs it, a gate's time later;
    // past the hold's bound the lock goes, and the runner hears the end.
    let until = std::time::Instant::now() + bounds.hold;
    loop {
        let left = until.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Ok(());
        }
        conn.wait(Some(left))?;
        let next: io::Result<Request> = read_frame(conn);
        match next {
            Ok(Request::Hold) => write_frame(conn, &Reply::Refused("held already".into()))?,
            Ok(req) => answer(config, conn, req, Some(&held), bound)?,
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Ok(());
            }
            Err(e) => return Err(e),
        }
    }
}

/// Answers `req`; a staging takes the lock unless the connection `held` it.
fn answer(
    config: &Config,
    conn: &mut impl Conn,
    req: Request,
    held: Option<&File>,
    bound: Duration,
) -> io::Result<()> {
    let (ap, image) = match &req {
        Request::Newest { ap } => {
            let reply = newest(config, ap).map_or_else(Reply::Refused, Reply::Image);
            return write_frame(conn, &reply);
        }
        Request::Check { ap, image } | Request::Stage { ap, image } => (ap, image),
        Request::Hold => return write_frame(conn, &Reply::Refused("not first".into())),
    };
    // Checked before use: the names go into a path and the command's
    // environment (the configuration's AP names are plain).
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
    let staging = match held {
        Some(_) => None,
        None => match lock(&config.rollout.images)? {
            Some(l) => Some(l),
            None => return write_frame(conn, &Reply::Refused(BUSY.into())),
        },
    };
    let copy = match copy_image(&dir, ap, &std::env::temp_dir()) {
        Ok(c) => c,
        Err(why) => return write_frame(conn, &Reply::Refused(format!("not copied: {why}"))),
    };
    let exit = stage(conn, &tree.join("boot/stage.sh"), ap, &copy.dir, bound)?;
    // Let go before the last word, so the staging asked for next is not
    // refused for a lock this one still held.
    drop(copy);
    drop(staging);
    match exit {
        Some(code) => write_frame(conn, &Reply::Exit(code)),
        None => Ok(()),
    }
}

/// Runs `script` for `ap` on the copied image `dir`, streaming its output,
/// and stops it, its whole process group, past `bound`; its exit status,
/// unless the runner went away.
fn stage(
    conn: &mut impl Conn,
    script: &Path,
    ap: &str,
    dir: &Path,
    bound: Duration,
) -> io::Result<Option<i32>> {
    let (reader, writer) = io::pipe()?;
    let child = {
        let mut cmd = Command::new(script);
        cmd.arg(dir)
            .current_dir(dir)
            .env("U6E_AP", ap)
            .env("PYTHONSAFEPATH", "1")
            .env("PYTHONNOUSERSITE", "1")
            .env_remove("PYTHONPATH")
            .env_remove("PYTHONHOME")
            .env_remove("PYTHONSTARTUP")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(writer.try_clone()?)
            .stderr(writer);
        // The command's ends of the pipe close with `cmd`, so the reader
        // sees the end of the output once the command and its children exit.
        // A script still open for writing somewhere (a child forked while it
        // was written, until it execs) is "busy" for a moment: tried again.
        let mut tries = 0;
        loop {
            match cmd.spawn() {
                Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) && tries < 20 => {
                    tries += 1;
                    thread::sleep(Duration::from_millis(50));
                }
                spawned => break spawned,
            }
        }
    };
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            let why = format!("{}: {e}", script.display());
            return write_frame(conn, &Reply::Refused(why)).map(|()| None);
        }
    };
    let ended = Arc::new((Mutex::new(false), Condvar::new()));
    let watch = {
        let ended = Arc::clone(&ended);
        let group = child.id() as libc::pid_t;
        thread::spawn(move || {
            let (lock, cv) = &*ended;
            let done = lock.lock().unwrap_or_else(|e| e.into_inner());
            let (done, _) = cv
                .wait_timeout_while(done, bound, |d| !*d)
                .unwrap_or_else(|e| e.into_inner());
            let stopped = !*done;
            if stopped {
                // SAFETY: a signal to the command's own process group.
                unsafe { libc::kill(-group, libc::SIGKILL) };
            }
            stopped
        })
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
    *ended.0.lock().unwrap_or_else(|e| e.into_inner()) = true;
    ended.1.notify_all();
    if watch.join().unwrap_or(false) && !gone {
        let why = format!("the staging ran past {bound:?} and was stopped");
        gone = write_frame(conn, &Reply::Line(why)).is_err();
    }
    Ok((!gone).then(|| status.code().unwrap_or(-1)))
}

/// Answers `conn`, if its peer is root or a process of group `gid` and asks
/// within `REQUEST_WAIT`.
pub fn serve_peer(config: &Config, mut conn: UnixStream, gid: u32) -> io::Result<()> {
    conn.set_read_timeout(Some(REQUEST_WAIT))?;
    match peer(&conn)? {
        (uid, g) if crate::local::allowed(uid, g, gid) => serve(config, &mut conn, BOUNDS),
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

/// How long a check, a lookup or a hold's answer may take.
const ASK_WAIT: Duration = Duration::from_secs(30);

impl Helper {
    async fn ask(&self, req: &Request) -> io::Result<tokio::net::UnixStream> {
        let mut conn = tokio::net::UnixStream::connect(&self.socket).await?;
        frames::write(&mut conn, req).await?;
        Ok(conn)
    }

    /// The one reply to `req`, within [`ASK_WAIT`], and the connection.
    async fn answer(&self, req: &Request) -> Result<(Reply, tokio::net::UnixStream), String> {
        let reply = async {
            let mut conn = self.ask(req).await?;
            Ok::<_, io::Error>((frames::read(&mut conn).await?, conn))
        };
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
        match self.answer(&req).await?.0 {
            Reply::Ok => Ok(()),
            Reply::Refused(why) => Err(why),
            other => Err(format!("the stage helper answered {other:?}")),
        }
    }

    /// The newest kept image of `ap`.
    pub async fn newest(&self, ap: &str) -> Result<String, String> {
        match self.answer(&Request::Newest { ap: ap.into() }).await?.0 {
            Reply::Image(id) => Ok(id),
            Reply::Refused(why) => Err(why),
            other => Err(format!("the stage helper answered {other:?}")),
        }
    }

    /// The lock on the kept images, held until the [`Hold`] is dropped;
    /// [`BUSY`] while another staging holds it.
    pub async fn hold(&self) -> Result<Hold, String> {
        match self.answer(&Request::Hold).await? {
            (Reply::Ok, conn) => Ok(Hold { conn }),
            (Reply::Refused(why), _) => Err(why),
            (other, _) => Err(format!("the stage helper answered {other:?}")),
        }
    }

    /// Stages `image` on `ap` under a lock of its own, each line of its
    /// output to `line`.
    pub async fn stage(&self, ap: &str, image: &str, line: impl FnMut(String)) -> Staged {
        let req = Request::Stage {
            ap: ap.into(),
            image: image.into(),
        };
        match self.ask(&req).await {
            Ok(mut conn) => staging(&mut conn, line).await.unwrap_or_else(|s| s),
            Err(e) => Staged::Refused(format!("the stage helper: {e}")),
        }
    }
}

/// The kept images' lock, held by a helper's connection for as long as this
/// lives; its stagings run under it.
pub struct Hold {
    conn: tokio::net::UnixStream,
}

/// A hold whose helper went away before it was asked: nothing was run.
#[derive(Debug, PartialEq, Eq)]
pub struct Lost(pub String);

impl Hold {
    /// Stages `image` on `ap` under the hold; [`Lost`] when the hold was
    /// gone before the staging began.
    pub async fn stage(
        &mut self,
        ap: &str,
        image: &str,
        line: impl FnMut(String),
    ) -> Result<Staged, Lost> {
        let req = Request::Stage {
            ap: ap.into(),
            image: image.into(),
        };
        if let Err(e) = frames::write(&mut self.conn, &req).await {
            return Err(Lost(format!("the stage helper: {e}")));
        }
        match staging(&mut self.conn, line).await {
            Ok(staged) => Ok(staged),
            Err(Staged::Failed(why)) => Err(Lost(why)),
            Err(other) => Ok(other),
        }
    }

    /// Returns once the helper lets the lock go (stopped, say), and why: an
    /// idle helper sends nothing while it holds it.
    pub async fn lost(&mut self) -> String {
        use tokio::io::AsyncReadExt;
        let mut byte = [0; 1];
        match self.conn.read(&mut byte).await {
            Ok(0) => "the stage helper ended".into(),
            Ok(_) => "the stage helper spoke out of turn".into(),
            Err(e) => format!("the stage helper: {e}"),
        }
    }

    /// Gives the lock up, and returns once the helper has: it closes the
    /// connection only after it let go, so a staging asked for next finds
    /// the lock free.
    pub async fn release(mut self) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let gone = async {
            self.conn.shutdown().await?;
            let mut rest = Vec::new();
            self.conn.read_to_end(&mut rest).await
        };
        let _ = tokio::time::timeout(ASK_WAIT, gone).await;
    }
}

/// How the staging on `conn` went, each line of its output to `line`;
/// `Err` when the helper ended before it began (a [`Staged::Failed`]).
async fn staging(
    conn: &mut tokio::net::UnixStream,
    mut line: impl FnMut(String),
) -> Result<Staged, Staged> {
    let mut began = false;
    loop {
        match frames::read(conn).await {
            Ok(Reply::Ok) => began = true,
            Ok(Reply::Refused(why)) => return Ok(Staged::Refused(why)),
            Ok(Reply::Line(l)) => line(l),
            Ok(Reply::Exit(0)) => return Ok(Staged::Done),
            Ok(Reply::Exit(code)) => {
                return Ok(Staged::Failed(format!("the staging exited with {code}")));
            }
            Ok(Reply::Image(_)) => {
                return Ok(Staged::Failed(
                    "the stage helper answered out of turn".into(),
                ));
            }
            Err(e) if !began => return Err(Staged::Failed(format!("the stage helper: {e}"))),
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                return Ok(Staged::Failed(
                    "the stage helper ended before the staging".into(),
                ));
            }
            Err(e) => return Ok(Staged::Failed(format!("the stage helper: {e}"))),
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

    /// A kept image of `ap` in `images`, as `prep-rootfs.sh` keeps one: its
    /// MANIFEST and the file it lists with its SHA-256.
    pub fn keep(images: &Path, id: &str, ap: &str) {
        keep_with(images, id, ap, &[("Image", b"kernel")]);
    }

    /// A kept image of `ap` in `images` holding `files`, each listed.
    pub fn keep_with(images: &Path, id: &str, ap: &str, files: &[(&str, &[u8])]) {
        let dir = images.join(id);
        fs::create_dir_all(&dir).unwrap();
        let mut manifest = format!("ap:        {ap} (u6e-{ap}, 192.0.2.1/24)\nkernel:    x\n");
        for (name, body) in files {
            fs::write(dir.join(name), body).unwrap();
            let sha = digest::digest(&digest::SHA256, body);
            manifest += &format!("{}  out/{name}\n", mac::hex(sha.as_ref()));
        }
        fs::write(dir.join("MANIFEST"), manifest).unwrap();
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
        ask_within(c, req, STAGE_MAX)
    }

    /// Waits for the lock to be free. A helper here is a thread, not a
    /// process of its own: a child another test thread forks shares its
    /// lock's open file until that child execs, so the lock can outlive its
    /// drop for that long, as it never does in a helper of its own.
    fn when_free(images: &Path) {
        for _ in 0..500 {
            if lock(images).unwrap().is_some() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("the lock was not freed");
    }

    fn ask_within(c: &Config, req: Request, bound: Duration) -> Vec<Reply> {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        write_frame(&mut a, &req).unwrap();
        let bounds = Bounds {
            stage: bound,
            hold: HOLD_MAX,
        };
        serve(c, &mut b, bounds).unwrap();
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

    /// The command gets the AP and a copy of the image (its directory, and
    /// its working directory), its output comes line by line, stderr too,
    /// and then its exit status.
    #[test]
    fn a_staging_streams_its_output_and_its_status() {
        let t = TestDir::new();
        let c = config(
            t.path(),
            &[IMG],
            "[ \"$PWD\" = \"$1\" ] && echo staging ${1##*/} on $U6E_AP; ls; \
             echo oops >&2; exit 3",
        );
        assert_eq!(
            ask(&c, stage(IMG)),
            [
                Reply::Ok,
                Reply::Line(format!("staging {IMG} on ap1")),
                Reply::Line("Image".into()),
                Reply::Line("MANIFEST".into()),
                Reply::Line("oops".into()),
                Reply::Exit(3),
            ]
        );
    }

    /// Root never runs nor imports what the build user could write: only
    /// the files the MANIFEST lists are copied, each as it lists it, and
    /// Python run in the copy imports nothing from it. A module planted in
    /// the image (listed or not) and a `sitecustomize` there have no effect.
    #[test]
    fn a_planted_module_in_an_image_is_never_run() {
        let t = TestDir::new();
        let planted = b"open('/dev/stderr', 'w').write('PLANTED ran\\n')\n";
        // What go8.sh runs in the image's directory, without -I.
        let c = config(
            t.path(),
            &[],
            "LC_ALL=C ls; python3 -c 'import hashlib; print(hashlib.__name__, \"from the stdlib\")'",
        );
        keep_with(
            &c.rollout.images,
            IMG,
            "ap1",
            &[("Image", b"kernel"), ("hashlib.py", planted)],
        );
        let dir = c.rollout.images.join(IMG);
        fs::write(dir.join("sitecustomize.py"), planted).unwrap();
        fs::write(dir.join("usercustomize.py"), planted).unwrap();
        let out = ask(&c, stage(IMG));
        assert!(!format!("{out:?}").contains("PLANTED"), "{out:?}");
        assert_eq!(
            out,
            [
                Reply::Ok,
                Reply::Line("Image".into()),
                Reply::Line("MANIFEST".into()),
                Reply::Line("hashlib.py".into()),
                Reply::Line("hashlib from the stdlib".into()),
                Reply::Exit(0),
            ]
        );
    }

    /// An image whose files are not what its MANIFEST lists, or are links,
    /// or whose MANIFEST lists a path out of the image, is not staged.
    #[test]
    fn an_image_unlike_its_manifest_is_not_staged() {
        let t = TestDir::new();
        let c = config(
            t.path(),
            &[IMG],
            &format!("echo ran > {}/ran", t.path().display()),
        );
        let dir = c.rollout.images.join(IMG);
        fs::write(dir.join("Image"), b"another kernel").unwrap();
        let why = "not copied: Image is not the file its MANIFEST lists";
        assert_eq!(ask(&c, stage(IMG)), [Reply::Refused(why.into())]);
        fs::remove_file(dir.join("Image")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", dir.join("Image")).unwrap();
        assert!(matches!(&ask(&c, stage(IMG))[..], [Reply::Refused(_)]));
        let manifest = fs::read_to_string(dir.join("MANIFEST")).unwrap();
        let sha = mac::hex(digest::digest(&digest::SHA256, b"x").as_ref());
        fs::write(
            dir.join("MANIFEST"),
            format!("{manifest}{sha}  out/../..\n"),
        )
        .unwrap();
        let why = "not copied: the MANIFEST lists out/../.., not a file to copy";
        assert_eq!(ask(&c, stage(IMG)), [Reply::Refused(why.into())]);
        assert!(!t.path().join("ran").exists());
    }

    /// The shape of the build user's directory is not trusted: an image
    /// directory or a MANIFEST that is a symbolic link is no kept image, a
    /// listed FIFO is refused at once (never read, so never waited on), and
    /// so are files too large together or a MANIFEST that no longer names
    /// the AP when it is copied.
    #[test]
    fn an_image_of_the_wrong_shape_is_not_copied() {
        let t = TestDir::new();
        let c = config(
            t.path(),
            &[IMG],
            &format!("echo ran > {}/ran", t.path().display()),
        );
        let images = &c.rollout.images;
        // A symbolic link to a kept image, and a kept image whose MANIFEST
        // is one.
        std::os::unix::fs::symlink(images.join(IMG), images.join("20261025-link-ap1")).unwrap();
        assert_eq!(
            kept(&c, "ap1", "20261025-link-ap1"),
            Err("no image 20261025-link-ap1 is kept".into())
        );
        keep(images, "20261025-m-ap1", "ap1");
        let m = images.join("20261025-m-ap1/MANIFEST");
        fs::rename(&m, images.join("20261025-m-ap1/real")).unwrap();
        std::os::unix::fs::symlink("real", &m).unwrap();
        assert_eq!(
            kept(&c, "ap1", "20261025-m-ap1"),
            Err("no image 20261025-m-ap1 is kept".into())
        );
        // A FIFO where its kernel should be.
        let dir = images.join(IMG);
        fs::remove_file(dir.join("Image")).unwrap();
        let fifo = CString::new(dir.join("Image").into_os_string().into_encoded_bytes()).unwrap();
        // SAFETY: a valid path, mode as for any file.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        let started = std::time::Instant::now();
        assert_eq!(
            ask(&c, stage(IMG)),
            [Reply::Refused(
                "not copied: Image: not a regular file".into()
            )]
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        // Files more than a staging copies, listed with any hash: refused
        // before a byte is read.
        fs::remove_file(dir.join("Image")).unwrap();
        File::create(dir.join("Image"))
            .unwrap()
            .set_len(IMAGE_MAX + 1)
            .unwrap();
        let why = format!(
            "not copied: its files hold {} B, more than the {IMAGE_MAX} B a staging copies",
            IMAGE_MAX + 1
        );
        assert_eq!(ask(&c, stage(IMG)), [Reply::Refused(why)]);
        // The MANIFEST, as copied, must name the AP asked for.
        let under = t.path().join("copies");
        fs::create_dir(&under).unwrap();
        keep(images, "20261025-n-ap1", "ap1");
        let other = copy_image(&images.join("20261025-n-ap1"), "ap2", &under);
        assert_eq!(other.err(), Some("its MANIFEST no longer names ap2".into()));
        assert!(copy_image(&images.join("20261025-n-ap1"), "ap1", &under).is_ok());
        assert!(!t.path().join("ran").exists());
    }

    /// A staging past its bound is stopped, its whole process group.
    #[test]
    fn a_staging_past_its_bound_is_stopped() {
        let t = TestDir::new();
        let c = config(t.path(), &[IMG], "echo started; sleep 30 & sleep 30");
        let started = std::time::Instant::now();
        let bound = Duration::from_millis(300);
        assert_eq!(
            ask_within(&c, stage(IMG), bound),
            [
                Reply::Ok,
                Reply::Line("started".into()),
                Reply::Line("the staging ran past 300ms and was stopped".into()),
                Reply::Exit(-1),
            ]
        );
        assert!(started.elapsed() < Duration::from_secs(10));
        // The lock went with it.
        assert!(lock(&c.rollout.images).unwrap().is_some());
    }

    /// A hold takes the lock for its connection's life: another staging is
    /// refused meanwhile, its own run under it, and its end frees it.
    #[test]
    fn a_hold_keeps_the_lock_for_its_stagings() {
        let t = TestDir::new();
        let c = config(t.path(), &[IMG], "echo staged ${1##*/}");
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let served = c.clone();
        let helper = thread::spawn(move || serve(&served, &mut b, BOUNDS));
        write_frame(&mut a, &Request::Hold).unwrap();
        assert_eq!(read_frame::<_, Reply>(&mut a).unwrap(), Reply::Ok);
        assert_eq!(ask(&c, stage(IMG)), [Reply::Refused(BUSY.into())]);
        assert_eq!(ask(&c, Request::Hold), [Reply::Refused(BUSY.into())]);
        write_frame(&mut a, &stage(IMG)).unwrap();
        for want in [
            Reply::Ok,
            Reply::Line(format!("staged {IMG}")),
            Reply::Exit(0),
        ] {
            assert_eq!(read_frame::<_, Reply>(&mut a).unwrap(), want);
        }
        assert_eq!(ask(&c, stage(IMG)), [Reply::Refused(BUSY.into())]);
        drop(a);
        helper.join().unwrap().unwrap();
        when_free(&c.rollout.images);
        assert_eq!(
            ask(&c, stage(IMG)),
            [
                Reply::Ok,
                Reply::Line(format!("staged {IMG}")),
                Reply::Exit(0)
            ]
        );
    }

    /// A rollout's longest hold, which the site's unit for the helper must
    /// let live (the README says so).
    #[test]
    fn a_hold_is_bounded_as_the_readme_says() {
        assert_eq!(HOLD_MAX, Duration::from_secs(2 * 3600 + 16 * 60));
    }

    /// A hold lasts no longer than its bound: the helper then lets the lock
    /// go and ends the connection, which the runner's end hears.
    #[test]
    fn a_hold_past_its_bound_lets_the_lock_go() {
        let t = TestDir::new();
        let c = config(t.path(), &[IMG], "true");
        let (a, mut b) = UnixStream::pair().unwrap();
        let served = c.clone();
        let bounds = Bounds {
            stage: STAGE_MAX,
            hold: Duration::from_millis(300),
        };
        let helper = thread::spawn(move || serve(&served, &mut b, bounds));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            a.set_nonblocking(true).unwrap();
            let mut conn = tokio::net::UnixStream::from_std(a).unwrap();
            frames::write(&mut conn, &Request::Hold).await.unwrap();
            assert_eq!(frames::read::<Reply>(&mut conn).await.unwrap(), Reply::Ok);
            let mut hold = Hold { conn };
            let started = std::time::Instant::now();
            assert_eq!(hold.lost().await, "the stage helper ended");
            assert!(started.elapsed() >= Duration::from_millis(250));
        });
        helper.join().unwrap().unwrap();
        when_free(&c.rollout.images);
    }

    /// Every Python the staging scripts run is isolated (`-I`): none imports
    /// from the directory it runs in.
    #[test]
    fn the_boot_scripts_run_python_isolated() {
        let boot = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../boot");
        let mut seen = 0;
        for entry in fs::read_dir(&boot).unwrap() {
            let path = entry.unwrap().path();
            let text = fs::read_to_string(&path).unwrap_or_default();
            for (n, line) in text.lines().enumerate() {
                for (i, _) in line.match_indices("python3 ") {
                    let after = &line[i + "python3 ".len()..];
                    seen += 1;
                    assert!(
                        after.starts_with("-I "),
                        "{}:{}: python3 without -I",
                        path.display(),
                        n + 1
                    );
                }
            }
        }
        assert!(seen >= 4, "{seen} python3 calls found");
    }

    /// Root runs the tree's files, so it refuses one another could have
    /// written: group- or world-writable, a symbolic link, or another's.
    #[test]
    fn a_tree_others_could_write_is_not_run() {
        let t = TestDir::new();
        let c = config(
            t.path(),
            &[IMG],
            &format!("echo ran > {}/ran", t.path().display()),
        );
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
        // The tree's own entries too: the known_hosts the site keeps there.
        let hosts = c.rollout.tree.join("known_hosts");
        fs::write(&hosts, "").unwrap();
        writable(&hosts, 0o666).unwrap();
        assert!(matches!(&ask(&c, stage(IMG))[..], [Reply::Refused(_)]));
        writable(&hosts, 0o644).unwrap();
        assert!(!t.path().join("ran").exists());
        assert_eq!(ask(&c, stage(IMG)), [Reply::Ok, Reply::Exit(0)]);
        assert!(t.path().join("ran").exists());
    }

    /// While one staging runs, another is refused before anything runs; a
    /// check is still answered.
    #[test]
    fn one_staging_at_a_time() {
        let t = TestDir::new();
        let c = config(
            t.path(),
            &[IMG],
            &format!("echo ran >> {}/ran", t.path().display()),
        );
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
        let images = c.rollout.images.clone();
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
            // A hold: a staging of its own under it, any other refused.
            when_free(&images);
            let mut hold = helper.hold().await.unwrap();
            assert_eq!(helper.hold().await.err(), Some(BUSY.into()));
            assert_eq!(
                helper.stage("ap1", IMG, |_| {}).await,
                Staged::Refused(BUSY.into())
            );
            let mut lines = Vec::new();
            let staged = hold.stage("ap1", IMG, |l| lines.push(l)).await;
            assert_eq!(staged, Ok(Staged::Done));
            assert_eq!(lines, ["one", "two"]);
            hold.release().await;
            when_free(&images);
        });
    }

    #[test]
    fn groups_by_name() {
        let etc = "root:x:0:\nu6e-deploy:x:997:\nother:x:12:a,b\n";
        assert_eq!(group_id(etc, "u6e-deploy"), Some(997));
        assert_eq!(group_id(etc, "u6e"), None);
    }
}
