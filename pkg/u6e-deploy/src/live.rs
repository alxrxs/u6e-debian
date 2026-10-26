//! The site's live deploys the controller asks for (`DeploySite`): one at a
//! time, at least [`site::EVERY`] apart, the newest commit asked for taking
//! the place of one still waiting (which is told it was). Each is checked
//! (`site::check`) and then run by the stage helper, its progress and its end
//! told to the controller, and its last word told again at each session. The
//! commit deployed last is kept in the state directory, which a deploy's
//! check is made against; a person who deploys the site by hand tells the
//! runner too (`deployed`, a root caller's). A runner that stops during a
//! deploy says so at its next start: the deploy's own journal has its end.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tokio::task::spawn_blocking;
use tokio::time::sleep;
use u6e_proto::msg::{RunnerMsg, SiteDeployState};

use crate::runner::Runner;
use crate::site;
use crate::stage::Staged;

/// The state file of the site's deploys.
pub(crate) const FILE: &str = "site";
/// The least time between two progress lines told to the controller.
const LINE_EVERY: Duration = Duration::from_secs(1);

/// What outlives the runner: the commit deployed last, and the deploy under
/// way.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(crate) struct Record {
    pub deployed: Option<String>,
    pub running: Option<(u64, String)>,
}

#[derive(Default)]
struct State {
    /// The deploy asked for and not started yet.
    pending: Option<(u64, String)>,
    started: Option<Instant>,
    /// What was told of the latest deploy last.
    word: Option<RunnerMsg>,
    record: Record,
}

/// The site's deploys of one runner.
pub(crate) struct Live {
    state: Mutex<State>,
    wake: Notify,
}

fn short(rev: &str) -> &str {
    &rev[..rev.len().min(12)]
}

impl Live {
    /// The deploys with what the state directory kept; a deploy that was
    /// running when the runner stopped is told as such.
    pub(crate) fn new(mut record: Record) -> Live {
        let mut state = State::default();
        if let Some((id, rev)) = record.running.take() {
            state.word = Some(RunnerMsg::SiteDeploy {
                id,
                detail: format!(
                    "the runner stopped during the deploy of {}: the deploy's own journal has its end",
                    short(&rev)
                ),
                rev,
                state: SiteDeployState::Failed,
            });
        }
        state.record = record;
        Live {
            state: Mutex::new(state),
            wake: Notify::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// What is kept of the deploys now.
    pub(crate) fn record(&self) -> Record {
        self.lock().record.clone()
    }

    /// The last word on the latest deploy, for a new session.
    pub(crate) fn word(&self) -> Option<RunnerMsg> {
        self.lock().word.clone()
    }
}

/// Tells the controller where deploy `id` of `rev` is, and the journal.
fn tell(runner: &Runner, id: u64, rev: &str, state: SiteDeployState, detail: String) {
    eprintln!("u6e-deploy: site {}: {state:?}: {detail}", short(rev));
    let msg = RunnerMsg::SiteDeploy {
        id,
        rev: rev.to_owned(),
        state,
        detail,
    };
    runner.live.lock().word = Some(msg.clone());
    runner.tell(msg);
}

/// The controller asks for a deploy of `rev`.
pub(crate) fn ask(runner: &Runner, id: u64, rev: String) {
    if runner.config.site.is_none() {
        let why = "this runner deploys no site".to_owned();
        return tell(runner, id, &rev, SiteDeployState::Refused, why);
    }
    let older = runner.live.lock().pending.replace((id, rev.clone()));
    if let Some((old, old_rev)) = older {
        let why = format!("{} came after it", short(&rev));
        tell(runner, old, &old_rev, SiteDeployState::Refused, why);
    }
    runner.live.wake.notify_one();
}

/// A person deployed the site as commit `rev` (a root caller's word): the
/// commit the next deploy is checked against.
pub(crate) async fn deployed(runner: &Arc<Runner>, rev: String) -> Result<(), String> {
    let site = runner
        .config
        .site
        .clone()
        .ok_or("this runner deploys no site")?;
    let last = runner.live.record().deployed;
    let checked = rev.clone();
    spawn_blocking(move || site::deployed(&site, &checked, last.as_deref()))
        .await
        .map_err(|e| e.to_string())??;
    let record = {
        let mut state = runner.live.lock();
        state.record.deployed = Some(rev.clone());
        state.record.clone()
    };
    runner.keep(FILE, &record);
    eprintln!("u6e-deploy: site {}: deployed by hand", short(&rev));
    Ok(())
}

/// Runs the deploys asked for, for the life of the process.
pub(crate) async fn run(runner: Arc<Runner>) {
    loop {
        runner.live.wake.notified().await;
        loop {
            let Some((id, rev)) = runner.live.lock().pending.take() else {
                break;
            };
            deploy(&runner, id, rev).await;
        }
    }
}

async fn deploy(runner: &Arc<Runner>, id: u64, rev: String) {
    let Some(site) = runner.config.site.clone() else {
        return;
    };
    let last = runner.live.record().deployed;
    let checked = rev.clone();
    let check = spawn_blocking(move || site::check(&site, &checked, last.as_deref())).await;
    let base = match check.map_err(|e| e.to_string()).and_then(|c| c) {
        Ok(base) => base,
        Err(why) => return tell(runner, id, &rev, SiteDeployState::Refused, why),
    };
    // At least `EVERY` after the last one started; one asked for meanwhile
    // takes this one's place.
    let started = runner.live.lock().started;
    sleep(started.map_or(Duration::ZERO, |t| site::EVERY.saturating_sub(t.elapsed()))).await;
    if let Some((_, newer)) = runner.live.lock().pending.as_ref() {
        let why = format!("{} came after it", short(newer));
        return tell(runner, id, &rev, SiteDeployState::Refused, why);
    }
    let record = {
        let mut state = runner.live.lock();
        state.started = Some(Instant::now());
        state.record.running = Some((id, rev.clone()));
        state.record.clone()
    };
    runner.keep(FILE, &record);
    let what = format!("the change since {} checked: deploying", short(&base));
    tell(runner, id, &rev, SiteDeployState::Running, what);
    let mut last_line = String::new();
    let mut told = Instant::now();
    let staged = runner
        .helper
        .deploy_site(&rev, |line| {
            if told.elapsed() >= LINE_EVERY {
                told = Instant::now();
                tell(runner, id, &rev, SiteDeployState::Running, line.clone());
            }
            last_line = line;
        })
        .await;
    let record = {
        let mut state = runner.live.lock();
        state.record.running = None;
        if staged == Staged::Done {
            state.record.deployed = Some(rev.clone());
        }
        state.record.clone()
    };
    runner.keep(FILE, &record);
    let (state, detail) = match staged {
        Staged::Done => (SiteDeployState::Done, last_line),
        Staged::Refused(why) => (SiteDeployState::Refused, why),
        Staged::Failed(why) if last_line.is_empty() => (SiteDeployState::Failed, why),
        Staged::Failed(why) => (SiteDeployState::Failed, format!("{why}: {last_line}")),
    };
    tell(runner, id, &rev, state, detail);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A runner that stopped during a deploy says, at its next start, that
    /// it did, and keeps the commit deployed before it.
    #[test]
    fn a_deploy_the_runner_stopped_during_is_told_as_failed() {
        let rev = "0123456789abcdef0123456789abcdef01234567".to_owned();
        let live = Live::new(Record {
            deployed: Some("f".repeat(40)),
            running: Some((7, rev.clone())),
        });
        match live.word() {
            Some(RunnerMsg::SiteDeploy {
                id,
                rev: r,
                state,
                detail,
            }) => {
                assert_eq!((id, r, state), (7, rev, SiteDeployState::Failed));
                assert!(detail.starts_with("the runner stopped during the deploy of 0123456789ab"));
            }
            other => panic!("{other:?}"),
        }
        let record = live.record();
        assert_eq!(
            (record.deployed, record.running),
            (Some("f".repeat(40)), None)
        );
        assert!(Live::new(Record::default()).word().is_none());
    }
}
