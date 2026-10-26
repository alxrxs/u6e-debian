//! One rollout, from its checks to its result, each step kept (`Runner::
//! persist`) so that a restarted runner goes on where it was. A rollout the
//! controller asked for itself may only roll out the AP's newest kept image;
//! a local caller's may roll out any. Both images are checked with the stage
//! helper first, the new one and the one to roll back to, so a rollout that
//! could not be undone never starts. Then the kept images' lock is taken
//! (`stage::Hold`) and held to the end, through the staging, the gate and any
//! way back, so no other staging (the site's own deploy) takes another AP
//! down meanwhile; a rollout that finds it taken is refused. The new image
//! is staged; then the AP has the gate's time (`gate_secs`) to come back
//! healthy as the controller sees it (a verdict that came while staging
//! counts). Healthy, the rollout is done; unhealthy, out of time, or a
//! staging that failed part way (the AP may be left in its stock firmware),
//! the previous image is staged again: rolled back, or failed if that fails
//! too. Each step is a line of the rollout's log.
//!
//! The gate's time runs out only on a controller that could have said: one
//! the link reached all along, or that it reached again [`GRACE`] ago (a
//! verdict it gave while the runner could not hear it, it gives again), and
//! [`LINGER`] past its time in any case. A runner restarted during a staging
//! waits for that staging to end (its helper holds the lock until then) and
//! gives the AP the gate's time from there; one restarted during the gate,
//! or whose helper let the lock go meanwhile, takes it back within
//! [`RETAKE`] or fails the rollout, saying so: the gate never runs without
//! the lock. A staging the helper stopped past `STAGE_MAX` is waited out
//! before the way back is staged.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tokio::time::{sleep, timeout};
use u6e_proto::msg::RolloutOutcome;

use crate::runner::{InFlight, Phase, Runner, unix_ms};
use crate::stage::{BUSY, Hold, STAGE_MAX, Staged};

/// How long a re-dialled controller has to give its verdict again.
pub const GRACE: Duration = Duration::from_secs(60);
/// The longest the gate is waited for past its time, for a controller that
/// cannot be reached: then it has failed.
pub const LINGER: Duration = Duration::from_secs(10 * 60);
/// How often a held lock is asked for again.
const RETRY: Duration = Duration::from_secs(2);
/// Past the helper's own bound on a staging, which it answers for.
const STAGE_WAIT: Duration = Duration::from_secs(STAGE_MAX.as_secs() + 60);
/// How long a lock this rollout held is waited for when it must be taken
/// again (its helper, gone with a restarted runner, letting it go): any
/// longer, another holds it, and the rollout fails.
const RETAKE: Duration = Duration::from_secs(5);

pub(crate) async fn run(
    runner: Arc<Runner>,
    mut f: InFlight,
    mut gate: watch::Receiver<Option<(bool, String)>>,
) {
    let mut hold: Option<Hold> = None;
    let (outcome, detail) = steps(&runner, &mut f, &mut gate, &mut hold).await;
    // The lock goes before the result: the rollout its caller asks for
    // next finds it free.
    if let Some(h) = hold {
        h.release().await;
    }
    runner.finish(&f, outcome, detail).await;
}

/// The rollout's steps from where `f` is, to how it ended.
async fn steps(
    runner: &Runner,
    f: &mut InFlight,
    gate: &mut watch::Receiver<Option<(bool, String)>>,
    hold: &mut Option<Hold>,
) -> (RolloutOutcome, String) {
    let id = f.id;
    let log = |line: String| runner.log(id, line);
    loop {
        match f.phase.clone() {
            Phase::Checking => {
                if let Err(why) = check(runner, f).await {
                    return (RolloutOutcome::Refused, why);
                }
                *hold = match runner.helper.hold().await {
                    Ok(h) => Some(h),
                    Err(why) => {
                        let why = format!("the kept images are not free: {why}");
                        return (RolloutOutcome::Refused, why);
                    }
                };
                log(format!(
                    "staging {} on {}, as {} asked",
                    f.image_id, f.ap, f.user
                ));
                f.phase = Phase::Staging;
                runner.persist(f);
                f.phase = match stage(runner, hold, id, &f.ap, &f.image_id).await {
                    Staged::Done => gate_from_now(runner),
                    Staged::Refused(why) => {
                        return (RolloutOutcome::Refused, why);
                    }
                    Staged::Failed(why) => Phase::RollingBack { why },
                };
            }
            // Restarted during the staging, which its helper runs to its end
            // holding the lock: the gate's time starts once it is free.
            Phase::Staging => {
                log("restarted during the staging: waiting for it to end".into());
                f.phase = match held(runner, hold, STAGE_WAIT).await {
                    Ok(()) => gate_from_now(runner),
                    Err(why) => {
                        let why = format!("the staging did not end: {why}");
                        return (RolloutOutcome::Failed, why);
                    }
                };
            }
            Phase::Gate { deadline_ms } => {
                runner.persist(f);
                // Resumed: the lock again, or the rollout fails at once.
                if let Err(why) = held(runner, hold, RETAKE).await {
                    return (RolloutOutcome::Failed, lock_lost(f, &why));
                }
                let wait = Duration::from_millis(deadline_ms.saturating_sub(unix_ms()));
                log(format!(
                    "staged; waiting up to {wait:?} for the health gate"
                ));
                let deadline = Instant::now() + wait;
                // The lock is watched as the gate is: a helper that lets it go
                // (stopped by its unit, say) is told, and the lock taken again.
                let verdict = loop {
                    let Some(h) = hold.as_mut() else {
                        return (RolloutOutcome::Failed, lock_lost(f, "no hold"));
                    };
                    tokio::select! {
                        v = verdict(runner, gate, deadline) => break v,
                        why = h.lost() => {
                            log(format!("the kept images' lock went ({why}): taking it again"));
                            *hold = None;
                            if let Err(why) = held(runner, hold, RETAKE).await {
                                return (RolloutOutcome::Failed, lock_lost(f, &why));
                            }
                        }
                    }
                };
                f.phase = match verdict {
                    Some((true, detail)) => {
                        return (RolloutOutcome::Done, detail);
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
                runner.persist(f);
                log(format!("{why}: staging {} again", f.previous));
                let staged = match held(runner, hold, STAGE_WAIT).await {
                    Ok(()) => stage(runner, hold, id, &f.ap, &f.previous).await,
                    Err(again) => Staged::Failed(again),
                };
                let (outcome, detail) = match staged {
                    Staged::Done => (
                        RolloutOutcome::RolledBack,
                        format!("{why}; {} is staged again", f.previous),
                    ),
                    Staged::Refused(again) | Staged::Failed(again) => (
                        RolloutOutcome::Failed,
                        format!("{why}; staging {} again failed too: {again}", f.previous),
                    ),
                };
                return (outcome, detail);
            }
        }
    }
}

/// Why a rollout failed that lost its lock and could not take it back: the
/// AP is left as the staging left it.
fn lock_lost(f: &InFlight, why: &str) -> String {
    format!(
        "the kept images' lock could not be taken back ({why}); {} is left as the staging \
         of {} left it",
        f.ap, f.image_id
    )
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

/// Makes sure `hold` holds the lock, waiting `within` at most while another
/// has it: a staging a restarted runner left running, for as long as a
/// staging may take, or a helper of this rollout letting it go.
async fn held(runner: &Runner, hold: &mut Option<Hold>, within: Duration) -> Result<(), String> {
    if hold.is_some() {
        return Ok(());
    }
    let started = Instant::now();
    loop {
        match runner.helper.hold().await {
            Ok(h) => {
                *hold = Some(h);
                return Ok(());
            }
            Err(why) if why == BUSY && started.elapsed() < within => sleep(RETRY).await,
            Err(why) => return Err(why),
        }
    }
}

/// Stages `image` on `ap` under the hold, its output in rollout `id`'s log;
/// a hold lost before the staging began is taken again once.
async fn stage(runner: &Runner, hold: &mut Option<Hold>, id: u64, ap: &str, image: &str) -> Staged {
    for _ in 0..2 {
        if let Err(why) = held(runner, hold, STAGE_WAIT).await {
            return Staged::Failed(format!("the kept images' lock: {why}"));
        }
        let Some(h) = hold.as_mut() else {
            continue;
        };
        match timeout(STAGE_WAIT, h.stage(ap, image, |l| runner.log(id, l))).await {
            Ok(Ok(staged)) => return staged,
            Ok(Err(lost)) => {
                runner.log(
                    id,
                    format!("the stage helper went away ({}): again", lost.0),
                );
                *hold = None;
            }
            Err(_) => {
                *hold = None;
                return Staged::Failed(format!("the staging took longer than {STAGE_WAIT:?}"));
            }
        }
    }
    Staged::Failed("the stage helper went away twice".into())
}

/// The gate's verdict, or `None` once the time is up: at `deadline`, if the
/// link was up since before the wait began or for [`GRACE`], else as soon
/// as it has been, and [`LINGER`] past `deadline` in any case.
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
            _ if deadline.elapsed() >= LINGER => return None,
            _ => sleep(Duration::from_secs(1)).await,
        }
    }
}
