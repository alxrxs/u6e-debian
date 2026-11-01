//! The radios kept as the site file plans them: the controller's clone of
//! the site's repository (the one the planner commits to, fetched as the
//! planner fetches it and right after each of its pushes) says where each
//! radio should be, as the planner reads it, and a radio that runs
//! otherwise (back on its image's channel after a reboot, say, or a commit
//! just applied) is moved there live, by the agent's `ChannelSwitch` and
//! `TxPower`, which it checks against the radio and the regulatory domain.
//!
//! A radio is asked at most once per [`RETRY`], so one whose AP refuses
//! does not loop, and stays "not as planned" (the UI, the events and
//! `wifi_radio_not_as_planned_since_timestamp_seconds`, whose alert waits
//! 30 minutes) until it runs as planned. Nothing is asked of an AP being
//! rolled out to or sent a configuration, nor while the clone's last fetch
//! failed or is old, nor of an AP signed a configuration after the clone
//! was fetched (that configuration may state a newer plan than the clone);
//! a planned block that needs a radar check (DFS) is only reported, since a
//! live switch cannot run one: the next configuration push takes it there.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::oneshot;
use tokio::time::{interval_at, timeout};
use u6e_proto::msg::CommandKind;

use super::plan::{POWER_SLACK, Proposal};
use super::{Planner, channels, planned, unix_ms};
use crate::agents::Timing;
use crate::state::{Action, NotAsPlanned, Shared, Waiter};

/// The least time between two asks of one radio.
pub const RETRY: Duration = Duration::from_secs(5 * 60);
/// How often the clone is fetched for this, whatever else fetched it.
const REFRESH: Duration = Duration::from_secs(5 * 60);
/// The oldest the clone's last fetch may be to be acted on.
const FRESH: Duration = Duration::from_secs(10 * 60);

/// Keeps the radios as planned for the life of the process, looking every
/// `Timing::reconcile` and fetching every [`REFRESH`], each command's
/// result awaited `Timing::command`.
pub async fn supervise(state: Shared, planner: Arc<Planner>, timing: Timing) {
    let mut every = interval_at(
        tokio::time::Instant::now() + timing.reconcile,
        timing.reconcile,
    );
    let mut refreshed: Option<Instant> = None;
    loop {
        every.tick().await;
        if refreshed.is_none_or(|t| t.elapsed() >= REFRESH) {
            planner.refresh().await;
            refreshed = Some(Instant::now());
        }
        converge(&state, &planner, None, false, timing.command).await;
    }
}

/// The commands that bring `p`'s radio to what the site file plans.
fn commands(p: &Proposal) -> Vec<CommandKind> {
    let (Some(runs), want) = (p.runs, p.current) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if (runs.channel, runs.width) != (want.channel, want.width) {
        let centre =
            channels::block(p.band, want.channel, want.width).map(|b| channels::centre(&b));
        if let Some(center1) = centre {
            out.push(CommandKind::ChannelSwitch {
                radio: p.band,
                channel: want.channel,
                width_mhz: want.width,
                center1,
            });
        }
    }
    let power = p.planned_power.zip(runs.power);
    if let Some((want, _)) = power.filter(|(w, h)| (w - h).abs() >= POWER_SLACK)
        && let Ok(dbm) = i8::try_from(want)
    {
        out.push(CommandKind::TxPower { radio: p.band, dbm });
    }
    out
}

/// Brings the radios not as planned there (those of `only`, when given),
/// each at most once per [`RETRY`] unless `force`; what each asked radio
/// came to, by its key.
pub async fn converge(
    state: &Shared,
    planner: &Planner,
    only: Option<&[String]>,
    force: bool,
    wait: Duration,
) -> Vec<(String, Result<String, String>)> {
    let read = {
        let mut clone = planner.clone.lock().await;
        planner.read(&mut clone, false).await
    };
    let Ok(read) = read else {
        return Vec::new();
    };
    let fetched = read
        .fetched
        .filter(|t| read.error.is_none() && t.elapsed().is_ok_and(|e| e < FRESH));
    let Ok((plan, _)) = planned(&planner.settings, &state.read(), &read.text) else {
        return Vec::new();
    };
    let now = SystemTime::now();
    let mut asked = Vec::new();
    {
        let mut s = state.write();
        let off: Vec<&Proposal> = plan.radios.iter().filter(|p| p.pending).collect();
        s.not_as_planned
            .retain(|k, _| off.iter().any(|p| p.key() == *k));
        for p in off {
            let key = p.key();
            let detail = p.kept.clone().unwrap_or_default();
            let latest = s.ap(&p.ap).and_then(|a| a.latest);
            let free = s.sendable(&p.ap).is_ok();
            let entry = s.not_as_planned.entry(key.clone()).or_insert(NotAsPlanned {
                since: now,
                detail: detail.clone(),
                tried: None,
            });
            if entry.tried.is_none() {
                entry.detail = detail;
            }
            if only.is_some_and(|o| !o.contains(&key)) {
                continue;
            }
            if p.planned_dfs {
                entry.detail = format!(
                    "{}; its channel needs a radar check (DFS), which a live switch cannot \
                     run: the next configuration push takes it there",
                    p.kept.clone().unwrap_or_default()
                );
                continue;
            }
            let Some(fetched) = fetched else { continue };
            let newer = latest.is_some_and(|l| l.signed_ms > unix_ms(fetched));
            let recent = entry.tried.is_some_and(|t| t.elapsed() < RETRY);
            let kinds = commands(p);
            if newer || (recent && !force) || !free || kinds.is_empty() {
                continue;
            }
            entry.tried = Some(Instant::now());
            for kind in kinds {
                let (tx, rx) = oneshot::channel();
                if let Some(id) = s.command(&p.ap, kind, Waiter::Reply(tx)) {
                    asked.push((p.ap.clone(), key.clone(), id, rx));
                }
            }
        }
    }
    let mut out = Vec::new();
    for (ap, key, id, rx) in asked {
        let r = match timeout(wait, rx).await {
            Ok(Ok(r)) if r.ok => Ok(r.detail),
            Ok(Ok(r)) => Err(r.detail),
            _ => {
                state.write().forget(id);
                Err(format!("no answer from {ap} in {wait:?}"))
            }
        };
        let mut s = state.write();
        if let (Err(why), Some(e)) = (&r, s.not_as_planned.get_mut(&key)) {
            e.detail = format!("not moved as planned: {why}");
        }
        let (ok, detail) = match &r {
            Ok(d) => (true, format!("{key}: {d}")),
            Err(d) => (false, format!("{key}: {d}")),
        };
        s.record(Action {
            at: SystemTime::now(),
            user: None,
            action: "reconcile",
            mac: None,
            ap: Some(ap),
            ok,
            detail,
        });
        out.push((key, r));
    }
    out
}
