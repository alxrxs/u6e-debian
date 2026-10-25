//! One rollout, from its checks to its result. Both images are checked with
//! the stage helper first, the new one and the one to roll back to, so a
//! rollout that could not be undone never starts. The new image is staged;
//! then the AP has the gate's time (`gate_secs`) to come back healthy as the
//! controller sees it (a verdict that came while staging counts). Healthy,
//! the rollout is done; unhealthy, out of time, or a staging that failed
//! part way (the AP may be left in its stock firmware), the previous image is
//! staged again: rolled back, or failed if that fails too. Each step is a
//! line of the rollout's log.

use std::sync::Arc;

use tokio::sync::watch;
use tokio::time::timeout;
use u6e_proto::msg::{RolloutOutcome, RolloutRequest};

use crate::runner::Runner;
use crate::stage::Staged;

pub(crate) async fn run(
    runner: Arc<Runner>,
    req: RolloutRequest,
    mut gate: watch::Receiver<Option<(bool, String)>>,
) {
    let (id, ap) = (req.id, req.ap.as_str());
    let log = |line: String| runner.log(id, line);
    for image in [&req.image_id, &req.previous] {
        if let Err(why) = runner.helper.check(ap, image).await {
            return runner.finish(id, RolloutOutcome::Refused, why).await;
        }
    }
    log(format!(
        "staging {} on {ap}, as {} asked",
        req.image_id, req.user
    ));
    let why = match runner.helper.stage(ap, &req.image_id, log).await {
        Staged::Done => {
            let wait = runner.config.gate;
            log(format!(
                "staged; waiting up to {wait:?} for the health gate"
            ));
            let verdict = match timeout(wait, gate.wait_for(Option::is_some)).await {
                Ok(Ok(verdict)) => verdict.clone(),
                // The rollout ended under it: nothing to roll back.
                Ok(Err(_)) => return,
                Err(_) => None,
            };
            match verdict {
                Some((true, detail)) => {
                    return runner.finish(id, RolloutOutcome::Done, detail).await;
                }
                Some((false, detail)) => format!("unhealthy: {detail}"),
                None => format!("no healthy gate in {wait:?}"),
            }
        }
        Staged::Refused(why) => return runner.finish(id, RolloutOutcome::Refused, why).await,
        Staged::Failed(why) => why,
    };
    log(format!("{why}: staging {} again", req.previous));
    let (outcome, detail) = match runner.helper.stage(ap, &req.previous, log).await {
        Staged::Done => (
            RolloutOutcome::RolledBack,
            format!("{why}; {} is staged again", req.previous),
        ),
        Staged::Refused(again) | Staged::Failed(again) => (
            RolloutOutcome::Failed,
            format!("{why}; staging {} again failed too: {again}", req.previous),
        ),
    };
    runner.finish(id, outcome, detail).await;
}
