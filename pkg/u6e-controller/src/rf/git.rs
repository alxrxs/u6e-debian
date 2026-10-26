//! The controller's own clone of the repository that holds the site file:
//! it reads the file as the remote branch has it, and lands a change as one
//! commit by "wifi-controller", pushed and never forced. Each attempt starts
//! from the remote branch as fetched then and makes the edit afresh on the
//! file there, which checks it again (`edit`), so a push the remote turns
//! down because the branch moved is followed by a new attempt on the new
//! branch, never by a rebase of the old edit: a rebase merges a commit that
//! is no longer right as readily as one that is. Nothing of a failed attempt
//! stays in the clone. Git runs through `u6e_git`: bounded in time, over SSH
//! with the deploy key and the server's own known_hosts.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use u6e_git::{Git, Remote};

/// Attempts of a change, each on the branch as it is then, before it is
/// given up while the branch keeps moving.
pub const ATTEMPTS: usize = 3;
/// The commit's author and committer.
pub const NAME: &str = "wifi-controller";
/// The longest one git command may run: a fetch or a push over a stalled
/// connection is stopped, and the planner's lock let go.
pub const GIT_TIMEOUT: Duration = Duration::from_secs(120);

/// The clone and how it reaches its remote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repo {
    pub remote: Remote,
    pub path: PathBuf,
    pub branch: String,
    /// The site file, relative to the repository's root.
    pub file: String,
    pub email: String,
}

/// Why the clone could not do what it was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A git command failed: what it was, and why.
    Git(String),
    /// The change itself was refused (by the edit).
    Edit(String),
    /// Every push was turned down: the branch kept moving.
    Rejected,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Git(e) | Self::Edit(e) => f.write_str(e),
            Self::Rejected => write!(
                f,
                "the push was turned down {ATTEMPTS} times: the branch kept moving"
            ),
        }
    }
}

impl std::error::Error for Error {}

impl From<u6e_git::Error> for Error {
    fn from(e: u6e_git::Error) -> Self {
        Error::Git(e.to_string())
    }
}

/// A commit landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Landed {
    pub commit: String,
    /// Pushes turned down before it landed.
    pub rejected: usize,
}

impl Repo {
    fn git(&self) -> Git {
        Git {
            remote: self.remote.clone(),
            name: NAME.into(),
            email: self.email.clone(),
            timeout: GIT_TIMEOUT,
        }
    }

    fn here(&self, args: &[&str]) -> Result<String, Error> {
        Ok(self.git().ok(&self.path, args)?)
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
        let url = &self.remote.url;
        let args = ["clone", "--quiet", "--branch", &self.branch, url, &path];
        self.git().ok(parent, &args)?;
        Ok(())
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

    /// Lands one commit of the site file as `edit` makes it from the
    /// remote's text, with `message`: each attempt fetches, edits the file as
    /// the branch has it then, and pushes.
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
        let target = format!("HEAD:refs/heads/{}", self.branch);
        for rejected in 0..ATTEMPTS {
            self.fetch()?;
            self.reset()?;
            let (_, text) = self.read()?;
            let next = edit(&text).map_err(Error::Edit)?;
            let file = self.path.join(&self.file);
            fs::write(&file, next).map_err(|e| Error::Git(format!("{}: {e}", file.display())))?;
            self.here(&["add", "--", &self.file])?;
            self.here(&["commit", "--quiet", "--no-verify", "-m", message])?;
            let push = self
                .git()
                .run(&self.path, &["push", "--porcelain", "origin", &target])?;
            if push.ok {
                let commit = self.here(&["rev-parse", "HEAD"])?.trim().to_owned();
                return Ok(Landed { commit, rejected });
            }
            // The branch moved: before the push read it, `[rejected]`; while
            // it pushed, the remote's `failed to update ref`. Any other
            // refusal (a hook's) would meet the next attempt too.
            let refused = push.stdout.lines().find(|l| l.starts_with('!'));
            let moved =
                |l: &str| l.contains("\t[rejected]") || l.ends_with("(failed to update ref)");
            if !refused.is_some_and(moved) {
                let why = refused.map_or_else(|| u6e_git::cause(&push.stderr), str::to_owned);
                return Err(Error::Git(format!("git push: {}", why.trim())));
            }
        }
        Err(Error::Rejected)
    }
}
