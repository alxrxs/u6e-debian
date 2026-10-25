//! One rollout, from its checks to its result, each step kept (`Runner::
//! persist`) so that a restarted runner goes on where it was. A rollout the
//! controller asked for itself may only roll out the AP's newest kept image;
//! a local caller's may roll out any. Both images are checked with the stage
//! helper first, the new one and the one to roll back to, so a rollout that
//! could not be undone never starts. The new image is staged; then the AP
//! has the gate's time (`gate_secs`) to come back healthy as the controller
//! sees it (a verdict that came while staging counts). Healthy, the rollout
//! is done; unhealthy, out of time, or a staging that failed part way (the
//! AP may be left in its stock firmware), the previous image is staged
//! again: rolled back, or failed if that fails too. Each step is a line of
//! the rollout's log.
//!
//! The gate's time runs out only on a controller that could have said: one
//! the link reached all along, or that it reached again [`GRACE`] ago (a
//! verdict it gave while the runner could not hear it, it gives again). A
//! runner restarted during a staging cannot tell how the staging went, so
//! it gives the AP the gate's time from then; a staging still running in its
//! helper when the previous image is to be staged again is waited for.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tokio::time::{sleep, timeout};
use u6e_proto::msg::RolloutOutcome;

use crate::runner::{InFlight, Phase, Runner, unix_ms};
use crate::stage::{BUSY, Staged};

/// How long a re-dialled controller has to give its verdict again.
pub const GRACE: Duration = Duration::from_secs(60);
/// The longest a staging may take (`stage.sh` waits up to 400 s for stock
/// and 600 s for the image, around go8.sh's writes); the site's unit stops
/// the helper at the same bound.
pub const STAGE_MAX: Duration = Duration::from_secs(45 * 60);

pub(crate) async fn run(
    runner: Arc<Runner>,
    mut f: InFlight,
    mut gate: watch::Receiver<Option<(bool, String)>>,
) {
    let id = f.id;
    let log = |line: String| runner.log(id, line);
    loop {
        match f.phase.clone() {
            Phase::Checking => {
                if let Err(why) = check(&runner, &f).await {
                    return runner.finish(&f, RolloutOutcome::Refused, why).await;
                }
                log(format!(
                    "staging {} on {}, as {} asked",
                    f.image_id, f.ap, f.user
                ));
                f.phase = Phase::Staging;
                runner.persist(&f);
                f.phase = match stage(&runner, id, &f.ap, &f.image_id).await {
                    Staged::Done => gate_from_now(&runner),
                    Staged::Refused(why) => {
                        return runner.finish(&f, RolloutOutcome::Refused, why).await;
                    }
                    Staged::Failed(why) => Phase::RollingBack { why },
                };
            }
            // Restarted during the staging, which may have gone either way.
            Phase::Staging => f.phase = gate_from_now(&runner),
            Phase::Gate { deadline_ms } => {
                runner.persist(&f);
                let wait = Duration::from_millis(deadline_ms.saturating_sub(unix_ms()));
                log(format!(
                    "staged; waiting up to {wait:?} for the health gate"
                ));
                f.phase = match verdict(&runner, &mut gate, Instant::now() + wait).await {
                    Some((true, detail)) => {
                        return runner.finish(&f, RolloutOutcome::Done, detail).await;
                    }
                    Some((false, detail)) => Phase::RollingBack {
                        why: format!("unhealthy: {detail}"),
                    },
                    None => Phase::RollingBack {
                        why: format!("no healthy gate in {:?}", runner.config.gate),
                    },
                };
            }
            Phase::RollingBack { why } => {
                runner.persist(&f);
                log(format!("{why}: staging {} again", f.previous));
                let (outcome, detail) = match stage(&runner, id, &f.ap, &f.previous).await {
                    Staged::Done => (
                        RolloutOutcome::RolledBack,
                        format!("{why}; {} is staged again", f.previous),
                    ),
                    Staged::Refused(again) | Staged::Failed(again) => (
                        RolloutOutcome::Failed,
                        format!("{why}; staging {} again failed too: {again}", f.previous),
                    ),
                };
                return runner.finish(&f, outcome, detail).await;
            }
        }
    }
}

/// The gate from now, for the configured time.
fn gate_from_now(runner: &Runner) -> Phase {
    let gate_ms = u64::try_from(runner.config.gate.as_millis()).unwrap_or(u64::MAX);
    Phase::Gate {
        deadline_ms: unix_ms().saturating_add(gate_ms),
    }
}

/// Whether the rollout may start: the newest kept image, unless a local
/// caller asked, and both it and the way back kept for the AP.
async fn check(runner: &Runner, f: &InFlight) -> Result<(), String> {
    if !f.local {
        let newest = runner.helper.newest(&f.ap).await?;
        if newest != f.image_id {
            return Err(format!(
                "only {}'s newest kept image, {newest}, rolls out from the controller; \
                 another takes a local `u6e-deploy rollout`",
                f.ap
            ));
        }
    }
    for image in [&f.image_id, &f.previous] {
        runner.helper.check(&f.ap, image).await?;
    }
    Ok(())
}

/// Stages `image` on `ap` within [`STAGE_MAX`], its output in rollout
/// `id`'s log, after any staging still under way (one a restarted runner
/// left running) has ended.
async fn stage(runner: &Runner, id: u64, ap: &str, image: &str) -> Staged {
    let started = Instant::now();
    loop {
        let staging = runner.helper.stage(ap, image, |l| runner.log(id, l));
        let left = STAGE_MAX.saturating_sub(started.elapsed());
        match timeout(left, staging).await {
            Ok(Staged::Refused(why)) if why == BUSY && started.elapsed() < STAGE_MAX => {
                sleep(Duration::from_secs(10)).await;
            }
            Ok(staged) => return staged,
            Err(_) => return Staged::Failed(format!("the staging took longer than {STAGE_MAX:?}")),
        }
    }
}

/// The gate's verdict, or `None` once the time is up: at `deadline`, if the
/// link was up since before the wait began or for [`GRACE`], else as soon
/// as it has been.
async fn verdict(
    runner: &Runner,
    gate: &mut watch::Receiver<Option<(bool, String)>>,
    deadline: Instant,
) -> Option<(bool, String)> {
    let began = Instant::now();
    let left = deadline.saturating_duration_since(began);
    if let Ok(Ok(v)) = timeout(left, gate.wait_for(Option::is_some)).await {
        return v.clone();
    }
    loop {
        if let Some(v) = gate.borrow().clone() {
            return Some(v);
        }
        match runner.linked_at() {
            Some(t) if t <= began || t.elapsed() >= GRACE => return None,
            _ => sleep(Duration::from_secs(1)).await,
        }
    }
}
