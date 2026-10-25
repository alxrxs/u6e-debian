//! The stage helper: the root end that stages a kept image on an AP for the
//! runner, which runs as its own user and may not. Staging needs what the
//! site's build host holds for it (the APs' root login, the stock firmware's
//! password, the build tree), so the helper runs the site's command for it
//! (`rollout.command` in the configuration, which root owns) and nothing
//! else: a request names only an AP of the configuration and the image to
//! stage there, one of the kept images named for that AP (`<images>/<id>/`
//! with a `MANIFEST`, `<id>` ending in `-<ap>`), checked here again whatever
//! the runner checked. systemd starts the helper on the first connection to
//! a socket only root and the runner's group may open, and hands it that
//! socket (`u6e-deploy --stage-helper`); the helper checks each peer too, and
//! serves each connection, which carries one request, on a thread of its own.
//!
//! `Check` answers whether an image could be staged; `Stage` streams the
//! command's output, a line at a time, and then how it exited. A command
//! once started runs to its end even if the runner goes away: an AP left
//! between two systems is worse than a staging nobody watches.

use std::io::{self, BufRead, BufReader, ErrorKind, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;

use serde::{Deserialize, Serialize};
use u6e_proto::frame::{read_frame, write_frame};

use crate::config::Config;
use crate::frames;

/// The longest output line passed on; a longer one is cut.
const LINE_MAX: usize = 1000;

/// What the runner asks of the helper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// Whether `image` is a kept image `ap` could be staged with.
    Check { ap: String, image: String },
    /// Stage `image` on `ap`.
    Stage { ap: String, image: String },
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
}

/// Whether `image` names a kept image of `ap`: its directory, or why not.
pub fn kept(config: &Config, ap: &str, image: &str) -> Result<PathBuf, String> {
    if !config.aps.contains_key(ap) {
        return Err(format!("no AP {ap:.64} in the configuration"));
    }
    let ok = |c: char| c.is_ascii_alphanumeric() || "._-".contains(c);
    let named = image.len() <= 128 && !image.starts_with('.') && image.chars().all(ok);
    if !named || !image.ends_with(&format!("-{ap}")) {
        return Err(format!("{image:.128} is not an image's name for {ap}"));
    }
    let dir = config.rollout.images.join(image);
    if !dir.join("MANIFEST").is_file() {
        return Err(format!("no image {image} is kept"));
    }
    Ok(dir)
}

/// The command that stages the image in `dir` on `ap`.
fn argv(config: &Config, ap: &str, dir: &Path) -> Vec<String> {
    let dir = dir.display().to_string();
    let fill = |a: &String| a.replace("{ap}", ap).replace("{image}", &dir);
    config.rollout.command.iter().map(fill).collect()
}

/// Answers the one request of a connection.
pub fn serve(config: &Config, conn: &mut (impl io::Read + Write)) -> io::Result<()> {
    let req: Request = read_frame(conn)?;
    let (Request::Check { ap, image } | Request::Stage { ap, image }) = &req;
    // Checked before use: the names go into a path and the command line
    // (the configuration's AP names are plain).
    let dir = match kept(config, ap, image) {
        Ok(dir) => dir,
        Err(why) => return write_frame(conn, &Reply::Refused(why)),
    };
    if matches!(req, Request::Check { .. }) {
        return write_frame(conn, &Reply::Ok);
    }
    let argv = argv(config, ap, &dir);
    let (reader, writer) = io::pipe()?;
    let child = {
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..])
            .stdin(Stdio::null())
            .stdout(writer.try_clone()?)
            .stderr(writer);
        // The command's ends of the pipe close with `cmd`, so the reader
        // sees the end of the output once the command and its children exit.
        cmd.spawn()
    };
    let mut child = match child {
        Ok(c) => c,
        Err(e) => return write_frame(conn, &Reply::Refused(format!("{}: {e}", argv[0]))),
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

/// Serves the connections to `listener` for the life of the process, each
/// from root or a process of group `gid` alone.
pub fn run(config: Config, listener: UnixListener, gid: u32) -> io::Result<()> {
    let config = Arc::new(config);
    for conn in listener.incoming() {
        let mut conn = conn?;
        let config = Arc::clone(&config);
        thread::spawn(move || {
            let served = match peer(&conn) {
                Ok((uid, g)) if crate::local::allowed(uid, g, gid) => serve(&config, &mut conn),
                Ok((uid, _)) => Err(io::Error::other(format!("a caller of uid {uid} refused"))),
                Err(e) => Err(e),
            };
            if let Err(e) = served {
                eprintln!("u6e-deploy: stage helper: {e}");
            }
        });
    }
    Ok(())
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

impl Helper {
    async fn ask(&self, req: &Request) -> io::Result<tokio::net::UnixStream> {
        let mut conn = tokio::net::UnixStream::connect(&self.socket).await?;
        frames::write(&mut conn, req).await?;
        Ok(conn)
    }

    /// Whether `image` could be staged on `ap`; why not.
    pub async fn check(&self, ap: &str, image: &str) -> Result<(), String> {
        let req = Request::Check {
            ap: ap.into(),
            image: image.into(),
        };
        let reply = async { frames::read(&mut self.ask(&req).await?).await };
        match reply.await {
            Ok(Reply::Ok) => Ok(()),
            Ok(Reply::Refused(why)) => Err(why),
            Ok(other) => Err(format!("the stage helper answered {other:?}")),
            Err(e) => Err(format!("the stage helper: {e}")),
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
    use std::fs;

    use crate::config::tests::text;
    use crate::tests::TestDir;

    /// A configuration whose images are in `dir`, kept for `kept`, staged by
    /// `command`.
    pub fn config(dir: &Path, kept: &[&str], command: &str) -> Config {
        for id in kept {
            fs::create_dir_all(dir.join("images").join(id)).unwrap();
            fs::write(dir.join("images").join(id).join("MANIFEST"), "ap: ap1\n").unwrap();
        }
        let mut c = Config::parse(&text("")).unwrap();
        c.rollout.images = dir.join("images");
        c.rollout.command = vec![
            "/bin/sh".into(),
            "-c".into(),
            command.into(),
            "{ap}".into(),
            "{image}".into(),
        ];
        c.rollout.helper = dir.join("stage.sock");
        c
    }

    /// The helper on its socket, serving root and the test's own group.
    pub fn listen(config: Config) {
        let listener = UnixListener::bind(&config.rollout.helper).unwrap();
        // SAFETY: getegid has no preconditions.
        let gid = unsafe { libc::getegid() };
        thread::spawn(move || run(config, listener, gid));
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

    const IMG: &str = "20261025-120000-abc-def-ap1";

    #[test]
    fn only_a_kept_image_of_a_configured_ap_is_staged() {
        let t = TestDir::new();
        let c = config(t.path(), &[IMG, "20261025-x-ap2"], "echo $0 $1");
        assert_eq!(kept(&c, "ap1", IMG), Ok(t.path().join("images").join(IMG)));
        for (ap, image, why) in [
            ("ap2", "20261025-x-ap2", "no AP ap2 in the configuration"),
            (
                "ap1",
                "20261025-x-ap2",
                "20261025-x-ap2 is not an image's name for ap1",
            ),
            (
                "ap1",
                "../../etc-ap1",
                "../../etc-ap1 is not an image's name for ap1",
            ),
            (
                "ap1",
                ".hidden-ap1",
                ".hidden-ap1 is not an image's name for ap1",
            ),
            ("ap1", "a b-ap1", "a b-ap1 is not an image's name for ap1"),
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

    /// The command gets the AP and the image's directory, its output comes
    /// line by line, stderr too, and then its exit status.
    #[test]
    fn a_staging_streams_its_output_and_its_status() {
        let t = TestDir::new();
        let c = config(
            t.path(),
            &[IMG],
            "echo staging $1 on $0; echo oops >&2; exit 3",
        );
        let req = Request::Stage {
            ap: "ap1".into(),
            image: IMG.into(),
        };
        let dir = t.path().join("images").join(IMG);
        assert_eq!(
            ask(&c, req),
            [
                Reply::Ok,
                Reply::Line(format!("staging {} on ap1", dir.display())),
                Reply::Line("oops".into()),
                Reply::Exit(3),
            ]
        );
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
