//! The `git` command as the controller and the deploy runner run it on their
//! clones of the site's repository: from its arguments, never through a
//! shell; over SSH with the clone's own key, the server checked against a
//! known_hosts of its own (the two go together); each run bounded in time,
//! its whole process group killed past the bound, so a stalled connection
//! never holds the caller for good; and a failure's cause kept, ssh's
//! warnings (a key others may read, a host key that does not match) as well
//! as git's last word.

use std::fmt;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Where a clone fetches from and pushes to, and how it reaches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    pub url: String,
    /// The private key ssh offers; none for a path or HTTPS remote.
    pub ssh_key: Option<PathBuf>,
    /// The server's host key, the only one ssh accepts; required with a key.
    pub known_hosts: Option<PathBuf>,
}

/// Whether `p` may go into ssh's command line as it is: absolute, and made
/// of letters, digits, `/`, `.`, `_` and `-` alone.
pub fn plain_path(p: &Path) -> bool {
    let ok = |c: char| c.is_ascii_alphanumeric() || "/._-".contains(c);
    p.is_absolute() && p.to_str().is_some_and(|s| s.chars().all(ok))
}

/// Why the private key at `p` would not do: not a regular file, or one that
/// others than its owner may read or write (ssh refuses such a key).
pub fn check_key(p: &Path) -> Result<(), String> {
    let md = fs::metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
    if !md.is_file() {
        return Err(format!("{} is not a file", p.display()));
    }
    let mode = md.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "{} is mode {mode:o}: others than its owner (uid {}) may read it",
            p.display(),
            md.uid()
        ));
    }
    Ok(())
}

impl Remote {
    /// Why these settings would not do: a key without a known_hosts (or the
    /// other way round), or a path that is not plain.
    pub fn check(&self) -> Result<(), String> {
        match (&self.ssh_key, &self.known_hosts) {
            (None, None) => Ok(()),
            (Some(k), Some(h)) => [k, h].iter().find(|p| !plain_path(p)).map_or(Ok(()), |p| {
                Err(format!(
                    "{} is not an absolute path of letters, digits and /._-",
                    p.display()
                ))
            }),
            _ => Err("ssh_key and known_hosts go together".into()),
        }
    }
}

/// How a clone runs git: as whom its commits are, and how long a run may
/// take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Git {
    pub remote: Remote,
    pub name: String,
    pub email: String,
    pub timeout: Duration,
}

/// What a run of git printed, and whether it succeeded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Why git did not give what was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// It could not be started.
    Spawn(String),
    /// It ran past the bound and was killed.
    TimedOut(String),
    /// It failed: its cause.
    Failed(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn(e) | Self::Failed(e) => f.write_str(e),
            Self::TimedOut(what) => write!(f, "{what}: no end in time, stopped"),
        }
    }
}

impl std::error::Error for Error {}

/// The lines of ssh's and git's output that say why: ssh's warnings and
/// refusals, and the last line.
pub fn cause(stderr: &str) -> String {
    let telling = [
        "WARNING",
        "UNPROTECTED",
        "Permissions",
        "Permission denied",
        "verification failed",
    ];
    let mut lines: Vec<&str> = stderr
        .lines()
        .map(str::trim)
        .filter(|l| telling.iter().any(|t| l.contains(t)))
        .collect();
    if let Some(last) = stderr.lines().map(str::trim).rfind(|l| !l.is_empty())
        && !lines.contains(&last)
    {
        lines.push(last);
    }
    lines.join("; ")
}

fn read_all(mut r: impl Read + Send + 'static) -> thread::JoinHandle<String> {
    thread::spawn(move || {
        let mut out = Vec::new();
        let _ = r.read_to_end(&mut out);
        String::from_utf8_lossy(&out).into_owned()
    })
}

impl Git {
    fn command(&self, dir: &Path, args: &[&str]) -> Command {
        let mut cmd = Command::new("git");
        cmd.current_dir(dir)
            .args(["-c", &format!("user.name={}", self.name)])
            .args(["-c", &format!("user.email={}", self.email)])
            .args(args)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_HTTP_LOW_SPEED_LIMIT", "1000")
            .env("GIT_HTTP_LOW_SPEED_TIME", "30")
            .env("LC_ALL", "C");
        if let (Some(key), Some(hosts)) = (&self.remote.ssh_key, &self.remote.known_hosts) {
            // Plain paths alone (`Remote::check`): git hands this to a shell.
            let ssh = format!(
                "ssh -i {} -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=15 \
                 -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
                 -o StrictHostKeyChecking=yes -o UserKnownHostsFile={}",
                key.display(),
                hosts.display()
            );
            cmd.env("GIT_SSH_COMMAND", ssh);
        }
        cmd
    }

    /// Runs `git <args>` in `dir`, killed past the bound.
    pub fn run(&self, dir: &Path, args: &[&str]) -> Result<Output, Error> {
        let what = format!("git {}", args.first().copied().unwrap_or(""));
        let mut cmd = self.command(dir, args);
        cmd.process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .map_err(|e| Error::Spawn(format!("{what}: {e}")))?;
        let out = read_all(child.stdout.take().expect("piped"));
        let err = read_all(child.stderr.take().expect("piped"));
        let until = Instant::now() + self.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if Instant::now() < until => thread::sleep(Duration::from_millis(20)),
                Ok(None) => break None,
                Err(e) => return Err(Error::Spawn(format!("{what}: {e}"))),
            }
        };
        let Some(status) = status else {
            // SAFETY: a signal to the command's own process group.
            unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
            let _ = child.wait();
            return Err(Error::TimedOut(what));
        };
        let stdout = out.join().unwrap_or_default();
        let stderr = err.join().unwrap_or_default();
        Ok(Output {
            ok: status.success(),
            stdout,
            stderr,
        })
    }

    /// What `git <args>` in `dir` printed, or why it failed.
    pub fn ok(&self, dir: &Path, args: &[&str]) -> Result<String, Error> {
        let out = self.run(dir, args)?;
        if out.ok {
            return Ok(out.stdout);
        }
        let what = args.first().copied().unwrap_or("");
        Err(Error::Failed(format!("git {what}: {}", cause(&out.stderr))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("u6e-git-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn git(timeout: Duration) -> Git {
        Git {
            remote: Remote {
                url: String::new(),
                ssh_key: None,
                known_hosts: None,
            },
            name: "tester".into(),
            email: "tester@example.org".into(),
            timeout,
        }
    }

    #[test]
    fn a_run_past_its_bound_is_stopped() {
        let d = dir("bound");
        let g = git(Duration::from_millis(300));
        g.ok(&d, &["init", "--quiet"]).unwrap();
        // An alias that never ends, as a stalled fetch would not.
        let start = Instant::now();
        let r = g.run(&d, &["-c", "alias.hang=!sleep 30", "hang"]);
        assert_eq!(r, Err(Error::TimedOut("git -c".into())));
        assert!(start.elapsed() < Duration::from_secs(5));
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn a_failure_says_why() {
        let d = dir("cause");
        let e = git(Duration::from_secs(10))
            .ok(&d, &["rev-parse", "HEAD"])
            .unwrap_err();
        assert!(
            matches!(&e, Error::Failed(c) if c.starts_with("git rev-parse: fatal: not a git repository")),
            "{e}"
        );
        let stderr = "@@@@@@\nWARNING: UNPROTECTED PRIVATE KEY FILE!\nPermissions 0644 for 'k' are too open.\n\
                      Load key \"k\": bad permissions\nfatal: Could not read from remote repository.\n";
        assert_eq!(
            cause(stderr),
            "WARNING: UNPROTECTED PRIVATE KEY FILE!; Permissions 0644 for 'k' are too open.; \
             fatal: Could not read from remote repository."
        );
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn keys_and_paths_are_checked() {
        let d = dir("keys");
        let key = d.join("key");
        fs::write(&key, "k").unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(check_key(&key).unwrap_err().contains("mode 644"));
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(check_key(&key), Ok(()));
        assert!(check_key(&d).unwrap_err().contains("is not a file"));
        assert!(plain_path(Path::new("/etc/wifi-controller/git-key")));
        for bad in ["relative/key", "/a b/key", "/a;b", "/a$(x)", "/é"] {
            assert!(!plain_path(Path::new(bad)), "{bad}");
        }
        let remote = |k: Option<&str>, h: Option<&str>| Remote {
            url: "ssh://git@git.example.org/site.git".into(),
            ssh_key: k.map(PathBuf::from),
            known_hosts: h.map(PathBuf::from),
        };
        assert_eq!(remote(None, None).check(), Ok(()));
        assert_eq!(remote(Some("/k"), Some("/h")).check(), Ok(()));
        assert!(remote(Some("/k"), None).check().is_err());
        assert!(remote(None, Some("/h")).check().is_err());
        assert!(remote(Some("/k k"), Some("/h")).check().is_err());
        let _ = fs::remove_dir_all(d);
    }
}
