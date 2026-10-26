//! The controller's own clone of the repository that holds the site file,
//! through the `git` command: it reads the file as the remote branch has it,
//! and lands a change the repository's way, one commit by "wifi-controller"
//! fetched, rebased and pushed, never forced; a push the remote turns down
//! because the branch moved is rebased and pushed again, a rebase that
//! conflicts is given up. Every attempt starts from the remote branch, and
//! nothing of a failed one stays. Pushes go over SSH with the deploy key
//! (`ssh_key`), the host checked against `known_hosts`, or to a path.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Pushes turned down because the branch moved, each rebased and tried
/// again, before the change is given up.
pub const ATTEMPTS: usize = 3;
/// The commit's author and committer.
pub const NAME: &str = "wifi-controller";

/// The clone and how it reaches its remote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repo {
    pub remote: String,
    pub path: PathBuf,
    pub branch: String,
    /// The site file, relative to the repository's root.
    pub file: String,
    pub ssh_key: Option<PathBuf>,
    pub known_hosts: Option<PathBuf>,
    pub email: String,
}

/// Why the clone could not do what it was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A git command failed: what it was, and its last word.
    Git(String),
    /// The change itself was refused (by the edit).
    Edit(String),
    /// The branch changed the same lines meanwhile.
    Conflict,
    /// Every push was turned down: the branch kept moving.
    Rejected,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Git(e) => f.write_str(e),
            Self::Edit(e) => f.write_str(e),
            Self::Conflict => f.write_str("the branch changed the same lines meanwhile"),
            Self::Rejected => write!(
                f,
                "the push was turned down {ATTEMPTS} times: the branch kept moving"
            ),
        }
    }
}

impl std::error::Error for Error {}

/// A commit landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Landed {
    pub commit: String,
    /// Pushes turned down before it landed.
    pub rejected: usize,
}

/// What a git command printed, whether it succeeded or not.
struct Run {
    ok: bool,
    stdout: String,
    stderr: String,
}

/// The last line a command printed that says anything.
fn last_word(s: &str) -> &str {
    s.lines()
        .rfind(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim()
}

impl Repo {
    fn run(&self, dir: &Path, args: &[&str]) -> Result<Run, Error> {
        let mut cmd = Command::new("git");
        cmd.current_dir(dir)
            .args([
                "-c",
                &format!("user.name={NAME}"),
                "-c",
                &format!("user.email={}", self.email),
            ])
            .args(args)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("LC_ALL", "C");
        if let Some(key) = &self.ssh_key {
            let mut ssh = format!(
                "ssh -i {} -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=15",
                key.display()
            );
            if let Some(hosts) = &self.known_hosts {
                let hosts = hosts.display();
                ssh.push_str(&format!(
                    " -o StrictHostKeyChecking=yes -o UserKnownHostsFile={hosts}"
                ));
            }
            cmd.env("GIT_SSH_COMMAND", ssh);
        }
        let out = cmd
            .output()
            .map_err(|e| Error::Git(format!("git {}: {e}", args[0])))?;
        Ok(Run {
            ok: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    /// What a git command printed, or its last word as it failed.
    fn git(&self, dir: &Path, args: &[&str]) -> Result<String, Error> {
        let run = self.run(dir, args)?;
        if run.ok {
            return Ok(run.stdout);
        }
        Err(Error::Git(format!(
            "git {}: {}",
            args[0],
            last_word(&run.stderr)
        )))
    }

    fn here(&self, args: &[&str]) -> Result<String, Error> {
        self.git(&self.path, args)
    }

    fn origin(&self) -> String {
        format!("origin/{}", self.branch)
    }

    /// Clones the remote when there is no clone yet.
    fn ensure(&self) -> Result<(), Error> {
        if self.path.join(".git").is_dir() {
            return Ok(());
        }
        let parent = self.path.parent().unwrap_or(Path::new("."));
        let path = self.path.to_string_lossy();
        let args = [
            "clone",
            "--quiet",
            "--branch",
            &self.branch,
            &self.remote,
            &path,
        ];
        self.git(parent, &args).map(drop)
    }

    /// Brings the remote branch in.
    pub fn fetch(&self) -> Result<(), Error> {
        self.ensure()?;
        self.here(&["fetch", "--quiet", "origin", &self.branch])
            .map(drop)
    }

    /// The site file as the remote branch last fetched has it, and the
    /// commit it is of.
    pub fn read(&self) -> Result<(String, String), Error> {
        self.ensure()?;
        let rev = self.here(&["rev-parse", &self.origin()])?.trim().to_owned();
        let text = self.here(&["show", &format!("{rev}:{}", self.file)])?;
        Ok((rev, text))
    }

    /// Makes the clone the remote branch exactly, whatever it held.
    fn reset(&self) -> Result<(), Error> {
        let _ = self.here(&["rebase", "--abort"]);
        let origin = self.origin();
        self.here(&[
            "checkout",
            "--quiet",
            "--force",
            "-B",
            &self.branch,
            &origin,
        ])?;
        self.here(&["clean", "--quiet", "-fd"]).map(drop)
    }

    /// Lands one commit, of the site file as `edit` makes it from the
    /// remote's, with `message`; the commit landed.
    pub fn land(
        &self,
        edit: impl Fn(&str) -> Result<String, String>,
        message: &str,
    ) -> Result<Landed, Error> {
        let landed = self.try_land(edit, message);
        // Whatever happened, nothing of it stays in the clone.
        if let Err(e) = self.reset() {
            eprintln!("u6e-controller: rf: the clone could not be reset: {e}");
        }
        landed
    }

    fn try_land(
        &self,
        edit: impl Fn(&str) -> Result<String, String>,
        message: &str,
    ) -> Result<Landed, Error> {
        self.fetch()?;
        self.reset()?;
        let (_, text) = self.read()?;
        let next = edit(&text).map_err(Error::Edit)?;
        let file = self.path.join(&self.file);
        fs::write(&file, next).map_err(|e| Error::Git(format!("{}: {e}", file.display())))?;
        self.here(&["add", "--", &self.file])?;
        self.here(&["commit", "--quiet", "--no-verify", "-m", message])?;
        let target = format!("HEAD:refs/heads/{}", self.branch);
        for rejected in 0..ATTEMPTS {
            let push = self.run(&self.path, &["push", "--porcelain", "origin", &target])?;
            if push.ok {
                let commit = self.here(&["rev-parse", "HEAD"])?.trim().to_owned();
                return Ok(Landed { commit, rejected });
            }
            // The branch moved: before the push read it, `[rejected]`; while
            // it pushed, the remote's `failed to update ref`. Any other
            // refusal (a hook's) would meet the next try too.
            let refused = push.stdout.lines().find(|l| l.starts_with('!'));
            let moved =
                |l: &str| l.contains("\t[rejected]") || l.ends_with("(failed to update ref)");
            if !refused.is_some_and(moved) {
                let said = refused.unwrap_or_else(|| last_word(&push.stderr));
                return Err(Error::Git(format!("git push: {}", said.trim())));
            }
            self.fetch()?;
            if self.here(&["rebase", "--quiet", &self.origin()]).is_err() {
                return Err(Error::Conflict);
            }
        }
        Err(Error::Rejected)
    }
}
