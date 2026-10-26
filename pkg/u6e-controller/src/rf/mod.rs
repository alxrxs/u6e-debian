//! The RF planner: it scores each radio's channel, width and power from what
//! the window measured (`history`, kept in RAM from the snapshots) within the
//! site file's constraints (`site`, `plan`), and proposes; nothing changes
//! until an admin applies a proposal. Applying it is a commit of the site
//! file to its repository by the controller (`git`, line-level `yaml` edits
//! of the affected keys only), after which the controller asks the deploy
//! runner to deploy that commit: the runner checks it is the branch's head
//! and changes only the site file's settings, and has the site's live deploy
//! render it, sign it and take it to the APs (a channel switch or a power
//! change, no reboot). The controller names a commit; it never supplies a
//! configuration.
//!
//! `GET /api/rf/plan` is the plan for anyone who may view, with its hash and
//! how the last site deploy goes; it reads the site file from the clone,
//! fetched at most once a minute. `POST /api/rf/apply`
//! (`{"plan": "<hash>", "radios": [{"key", "channel", "width", "center",
//! "power"}, …]}`) is gated as the other actions are (`actions::refusal`):
//! it applies exactly the proposals the admin confirmed, and only while they
//! are still the plan's (409 when the plan, any of them, or the site file
//! changed meanwhile, when a group is applied in part, or when the result
//! would put two APs on one spectrum), each attempt of the push re-checking
//! them on the branch as it is then. Each radio applied is an action in the
//! events and a journal line, the commit's id in it.

pub mod channels;
pub mod config;
pub mod git;
pub mod history;
pub mod plan;
pub mod site;
pub mod yaml;

use std::collections::BTreeMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::State as Ext;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::spawn_blocking;
use u6e_proto::msg::Band;

use crate::actions::{self, Via, Web};
use crate::http::{error, json_response};
use crate::state::{Action, Shared, State, site_deploy_name};
use crate::view;

use self::config::Settings;
use self::plan::{Inputs, Plan, Proposal};
use self::site::{Change, Setting, Site};

/// How long the site file read from the clone is taken as current.
const FETCH_EVERY: Duration = Duration::from_secs(60);
/// The most radios one apply names.
const MAX_RADIOS: usize = 16;

/// What the last apply did.
#[derive(Debug, Clone)]
struct Applied {
    at: SystemTime,
    user: Option<String>,
    radios: Vec<String>,
    ok: bool,
    commit: Option<String>,
    detail: String,
}

/// The clone's side: when it last fetched and what that said.
#[derive(Default)]
struct Checkout {
    fetched: Option<(Instant, SystemTime)>,
    error: Option<String>,
}

/// The planner the web listener serves.
pub struct Planner {
    settings: Settings,
    /// One fetch or apply at a time.
    clone: AsyncMutex<Checkout>,
    last: Mutex<Option<Applied>>,
}

/// The site file as read for a plan: its text, the commit it is of, and
/// whether the fetch before it failed.
struct Read {
    rev: String,
    text: String,
    fetched: Option<SystemTime>,
    error: Option<String>,
}

fn unix_ms(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

/// The plan of the site file `text` as the state is now.
fn planned(settings: &Settings, state: &State, text: &str) -> Result<(Plan, Site), String> {
    let site = site::read(text).map_err(|e| format!("{}: {e}", settings.repo.file))?;
    let live: BTreeMap<String, _> = state
        .aps()
        .map(|(n, a)| (n.to_owned(), a.snapshot.as_ref()))
        .collect();
    // The agents report no scans yet, so no AP hears others' networks.
    let neighbours = BTreeMap::new();
    let inputs = Inputs {
        site: &site,
        live: &live,
        history: &state.history,
        neighbours: &neighbours,
        rules: &settings.rules,
    };
    Ok((plan::plan(&inputs), site))
}

/// The plan's hash: of the commit it read and every proposal, so a plan
/// that changed in anything is told apart.
fn hash(plan: &Plan, rev: &str) -> String {
    let mut h = DefaultHasher::new();
    rev.hash(&mut h);
    for p in &plan.radios {
        (p.key(), p.current, p.proposed, p.group).hash(&mut h);
    }
    format!("{:016x}", h.finish())
}

impl Planner {
    pub fn new(settings: Settings) -> Planner {
        Planner {
            settings,
            clone: AsyncMutex::new(Checkout::default()),
            last: Mutex::new(None),
        }
    }

    /// Fetches unless that was done less than `FETCH_EVERY` ago (or `force`),
    /// then reads the site file; the clone's lock is held by the caller.
    async fn read(&self, clone: &mut Checkout, force: bool) -> Result<Read, String> {
        let fresh = clone
            .fetched
            .is_some_and(|(t, _)| t.elapsed() < FETCH_EVERY);
        if force || !fresh {
            let repo = self.settings.repo.clone();
            let fetched = spawn_blocking(move || repo.fetch())
                .await
                .map_err(|e| e.to_string())?;
            match fetched {
                Ok(()) => {
                    clone.fetched = Some((Instant::now(), SystemTime::now()));
                    clone.error = None;
                }
                Err(e) if force => return Err(e.to_string()),
                Err(e) => clone.error = Some(e.to_string()),
            }
        }
        let repo = self.settings.repo.clone();
        let (rev, text) = spawn_blocking(move || repo.read())
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        Ok(Read {
            rev,
            text,
            fetched: clone.fetched.map(|(_, t)| t),
            error: clone.error.clone(),
        })
    }

    fn last(&self) -> Option<Applied> {
        self.last
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

fn setting(s: &Setting) -> Value {
    let mut o = json!({ "channel": s.channel, "width": s.width });
    if let Some(p) = s.power {
        o["power"] = p.into();
    }
    o
}

/// A proposed setting as the UI confirms it: with its block's centre.
fn confirmable(band: Band, s: &Setting) -> Value {
    let mut o = setting(s);
    if let Some(b) = channels::block(band, s.channel, s.width) {
        o["center"] = channels::centre(&b).into();
    }
    o
}

fn proposal(p: &Proposal) -> Value {
    let mut o = json!({
        "key": p.key(),
        "ap": p.ap,
        "radio": p.radio,
        "band": view::band(p.band),
        "current": setting(&p.current),
        "proposed": confirmable(p.band, &p.proposed),
        "change": p.changes(),
        "measured": p.measured,
        "pending": p.pending,
        "snr_change": round1(p.snr_change),
        "reason": p.reason,
    });
    if let Some(r) = &p.runs {
        o["runs"] = setting(r);
    }
    if let Some(m) = &p.measure {
        o["busy"] = round1(m.busy).into();
        o["foreign"] = round1(m.foreign).into();
        o["noise"] = round1(m.noise).into();
        o["clients"] = round1(m.clients).into();
        o["hours"] = m.hours.into();
    }
    if let Some(b) = p.predicted_busy {
        o["predicted_busy"] = round1(b).into();
    }
    if let Some(s) = p.snr {
        o["snr"] = round1(s).into();
    }
    if let Some(k) = &p.kept {
        o["kept"] = k.clone().into();
    }
    if let Some(r) = &p.restart {
        o["restart"] = r.clone().into();
    }
    if let Some(g) = p.group {
        o["group"] = g.into();
    }
    o
}

fn applied(a: &Applied) -> Value {
    let mut o = json!({
        "at": unix_ms(a.at),
        "radios": a.radios,
        "ok": a.ok,
        "detail": a.detail,
    });
    if let Some(u) = &a.user {
        o["user"] = u.clone().into();
    }
    if let Some(c) = &a.commit {
        o["commit"] = c.clone().into();
    }
    o
}

/// How the last site deploy goes.
fn deploy(state: &State) -> Option<Value> {
    let d = state.site_deploy.as_ref()?;
    let mut o = json!({
        "id": d.id,
        "rev": d.rev,
        "state": site_deploy_name(d.state),
        "detail": d.detail,
        "asked": unix_ms(d.asked),
        "at": unix_ms(d.at),
        "runner": state.runner.is_up(),
    });
    if let Some(u) = &d.user {
        o["user"] = u.clone().into();
    }
    Some(o)
}

/// `GET /api/rf/plan`.
pub async fn get_plan(Ext(web): Ext<Web>) -> Response {
    let Some(planner) = &web.access.rf else {
        return json_response(&json!({ "configured": false }));
    };
    let read = {
        let mut clone = planner.clone.lock().await;
        planner.read(&mut clone, false).await
    };
    let read = match read {
        Ok(r) => r,
        Err(e) => {
            return error(
                StatusCode::BAD_GATEWAY,
                &format!("the site file could not be read: {e}"),
            );
        }
    };
    let state = web.state.read();
    let plan = match planned(&planner.settings, &state, &read.text) {
        Ok((p, _)) => p,
        Err(e) => return error(StatusCode::UNPROCESSABLE_ENTITY, &e),
    };
    let mut site = json!({ "rev": read.rev, "file": planner.settings.repo.file });
    if let Some(t) = read.fetched {
        site["fetched"] = unix_ms(t).into();
    }
    if let Some(e) = read.error {
        site["error"] = e.into();
    }
    let mut v = json!({
        "configured": true,
        "at": unix_ms(SystemTime::now()),
        "hash": hash(&plan, &read.rev),
        "window_hours": planner.settings.rules.window_hours,
        "notes": plan.notes,
        "site": site,
        "radios": plan.radios.iter().map(proposal).collect::<Vec<_>>(),
    });
    if let Some(a) = planner.last() {
        v["last"] = applied(&a);
    }
    if let Some(d) = deploy(&state) {
        v["deploy"] = d;
    }
    json_response(&v)
}

/// A proposal as the admin confirmed it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Confirmed {
    key: String,
    channel: u16,
    width: u16,
    center: u16,
    power: Option<i32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyBody {
    plan: String,
    radios: Vec<Confirmed>,
}

/// Whether `key` names a radio of one of this controller's APs.
fn known(state: &State, key: &str) -> bool {
    let Some((ap, radio)) = key.split_once('/') else {
        return false;
    };
    state.ap(ap).is_some() && ["radio24", "radio5", "radio6"].contains(&radio)
}

/// A setting in words.
fn what(s: &Setting) -> String {
    let p = s.power.map_or(String::new(), |p| format!(", {p} dBm"));
    format!("channel {} at {} MHz{p}", s.channel, s.width)
}

/// The commit message of `chosen`, applied by `user`.
fn message(chosen: &[&Proposal], user: &str) -> String {
    let subject = match chosen {
        [p] => format!(
            "wifi: the RF planner sets {}'s {} GHz radio to {}",
            p.ap,
            view::band(p.band),
            what(&p.proposed)
        ),
        _ => format!("wifi: the RF planner changes {} radios", chosen.len()),
    };
    let mut body = Vec::new();
    for p in chosen {
        let mut lines = vec![
            format!(
                "{} {} GHz: {} → {}",
                p.ap,
                view::band(p.band),
                what(&p.current),
                what(&p.proposed)
            ),
            format!("  {}", p.reason),
        ];
        if let (Some(m), Some(b)) = (&p.measure, p.predicted_busy) {
            lines.push(format!(
                "  predicted: busy {:.0} % → {:.0} %, weakest clients' SNR {:+.0} dB",
                m.busy, b, p.snr_change
            ));
        }
        body.push(lines.join("\n"));
    }
    format!(
        "{subject}\n\n{}\n\nApplied in the Wi-Fi controller by {user}.\n",
        body.join("\n\n")
    )
}

/// Why `confirmed` cannot be applied to the plan `plan` of `site`: a radio
/// whose proposal is not the one confirmed, a group applied in part, or a
/// result that puts two APs on one spectrum. The proposals otherwise.
fn check(plan: &Plan, site: &Site, confirmed: &[Confirmed]) -> Result<Vec<Proposal>, String> {
    let mut chosen = Vec::new();
    for c in confirmed {
        let p = plan
            .radios
            .iter()
            .find(|p| p.key() == c.key)
            .ok_or_else(|| format!("{} is not a radio of the plan", c.key))?;
        let centre = channels::block(p.band, p.proposed.channel, p.proposed.width)
            .map(|b| channels::centre(&b));
        let same = p.changes()
            && (p.proposed.channel, p.proposed.width, p.proposed.power)
                == (c.channel, c.width, c.power)
            && centre == Some(c.center);
        if !same {
            return Err(format!("{} no longer proposes what was confirmed", c.key));
        }
        chosen.push(p.clone());
    }
    for p in &chosen {
        let Some(g) = p.group else { continue };
        let left: Vec<String> = plan
            .radios
            .iter()
            .filter(|o| o.group == Some(g) && !chosen.iter().any(|c| c.key() == o.key()))
            .map(Proposal::key)
            .collect();
        if !left.is_empty() {
            return Err(format!(
                "{} goes with {}: apply them together",
                p.key(),
                left.join(", ")
            ));
        }
    }
    let settings: Vec<(String, Band, Setting)> = chosen
        .iter()
        .map(|p| (p.ap.clone(), p.band, p.proposed))
        .collect();
    if let Some(why) = plan::clash(site, &settings) {
        return Err(why);
    }
    Ok(chosen)
}

/// `POST /api/rf/apply`.
pub async fn apply(Ext(web): Ext<Web>, req: HeaderMap, body: Bytes) -> Response {
    if let Some(why) = actions::refusal(&req, &web.access, Via::Post, "rf apply") {
        return error(StatusCode::FORBIDDEN, why);
    }
    let Some(planner) = &web.access.rf else {
        return error(StatusCode::NOT_FOUND, "the RF planner is not configured");
    };
    let Ok(b) = serde_json::from_slice::<ApplyBody>(&body) else {
        return error(
            StatusCode::BAD_REQUEST,
            "not {\"plan\", \"radios\": [{\"key\", \"channel\", \"width\", \"center\", \"power\"}, …]}",
        );
    };
    if b.radios.is_empty() || b.radios.len() > MAX_RADIOS {
        return error(StatusCode::BAD_REQUEST, "radios must name 1 to 16 radios");
    }
    let user = actions::user(&req);
    {
        // Only names of this site's radios reach the events and the journal.
        let state = web.state.read();
        let mut seen = BTreeMap::new();
        for c in &b.radios {
            if !known(&state, &c.key) || seen.insert(c.key.clone(), ()).is_some() {
                drop(state);
                let detail = format!(
                    "refused: {:.64?} is not one radio of this site, once",
                    c.key
                );
                record(&web.state, &user, &[], false, &detail);
                return error(
                    StatusCode::BAD_REQUEST,
                    "a radio named is not one of this site's, once",
                );
            }
        }
    }
    let who = user.clone().unwrap_or_else(|| "(no user)".into());
    let keys: Vec<String> = b.radios.iter().map(|c| c.key.clone()).collect();
    // The lock is held from the fetch to the push: one apply at a time.
    let mut clone = planner.clone.lock().await;
    let outcome = async {
        let read = planner.read(&mut clone, true).await.map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("the site file could not be fetched: {e}"),
            )
        })?;
        let (plan, site) = planned(&planner.settings, &web.state.read(), &read.text)
            .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e))?;
        if hash(&plan, &read.rev) != b.plan {
            return Err((
                StatusCode::CONFLICT,
                "the plan changed: review it again".to_owned(),
            ));
        }
        let chosen = check(&plan, &site, &b.radios).map_err(|e| (StatusCode::CONFLICT, e))?;
        let refs: Vec<&Proposal> = chosen.iter().collect();
        let msg = message(&refs, &who);
        // Each attempt edits the branch as it is then: the confirmed
        // proposals must still be the plan's there, and fit the file.
        let (settings, state, confirmed) = (
            planner.settings.clone(),
            web.state.clone(),
            b.radios.clone(),
        );
        let edit = move |text: &str| {
            let (plan, site) = planned(&settings, &state.read(), text)?;
            let chosen = check(&plan, &site, &confirmed)
                .map_err(|e| format!("the site changed ({e}): review the plan again"))?;
            let changes: Vec<Change> = chosen
                .iter()
                .map(|p| Change {
                    ap: p.ap.clone(),
                    band: p.band,
                    from: p.current,
                    to: p.proposed,
                })
                .collect();
            site::edit(text, &changes).map_err(|e| e.to_string())
        };
        let repo = planner.settings.repo.clone();
        let landed = spawn_blocking(move || repo.land(edit, &msg))
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        match landed {
            Ok(l) => Ok((chosen, l)),
            Err(e @ git::Error::Edit(_)) => Err((StatusCode::CONFLICT, e.to_string())),
            Err(e @ git::Error::Rejected) => Err((StatusCode::SERVICE_UNAVAILABLE, e.to_string())),
            Err(e @ git::Error::Git(_)) => Err((StatusCode::BAD_GATEWAY, e.to_string())),
        }
    }
    .await;
    // The branch is as the push left it: the next plan need not fetch.
    if outcome.is_ok() {
        clone.fetched = Some((Instant::now(), SystemTime::now()));
    }
    drop(clone);
    let (status, body, last) = match outcome {
        Ok((chosen, landed)) => {
            let short = &landed.commit[..landed.commit.len().min(12)];
            for p in &chosen {
                let detail = format!(
                    "{}: {} → {}, commit {short}",
                    p.key(),
                    what(&p.current),
                    what(&p.proposed)
                );
                record(
                    &web.state,
                    &user,
                    std::slice::from_ref(&p.ap),
                    true,
                    &detail,
                );
            }
            // The site's live deploy takes the commit to the APs.
            let deploy = web.state.write().deploy_site(&landed.commit, user.clone());
            let radios: Vec<String> = chosen.iter().map(Proposal::key).collect();
            let detail = format!("committed {short} to {}", planner.settings.repo.branch);
            let body = json!({
                "ok": true,
                "commit": landed.commit,
                "radios": radios,
                "detail": detail,
                "deploy": deploy,
            });
            let last = Applied {
                at: SystemTime::now(),
                user: user.clone(),
                radios,
                ok: true,
                commit: Some(landed.commit),
                detail,
            };
            (StatusCode::OK, body, last)
        }
        Err((status, why)) => {
            let aps: Vec<String> = keys
                .iter()
                .filter_map(|k| Some(k.split_once('/')?.0.to_owned()))
                .collect();
            record(
                &web.state,
                &user,
                &aps,
                false,
                &format!("{}: {why}", keys.join(", ")),
            );
            let last = Applied {
                at: SystemTime::now(),
                user: user.clone(),
                radios: keys,
                ok: false,
                commit: None,
                detail: why.clone(),
            };
            (status, json!({ "ok": false, "error": why }), last)
        }
    };
    *planner.last.lock().unwrap_or_else(PoisonError::into_inner) = Some(last);
    (status, json_response(&body)).into_response()
}

/// Records an apply on `aps` (each once; on none when it named none of
/// them) as actions, for the events and the journal.
fn record(state: &Shared, user: &Option<String>, aps: &[String], ok: bool, detail: &str) {
    let mut aps: Vec<Option<String>> = aps.iter().cloned().map(Some).collect();
    aps.sort();
    aps.dedup();
    if aps.is_empty() {
        aps.push(None);
    }
    let mut state = state.write();
    for ap in aps {
        state.record(Action {
            at: SystemTime::now(),
            user: user.clone(),
            action: "rf-plan",
            mac: None,
            ap,
            ok,
            detail: detail.to_owned(),
        });
    }
}

/// The planner a configuration asks for, if any.
pub fn from(settings: Option<&Settings>) -> Option<Arc<Planner>> {
    settings.map(|s| Arc::new(Planner::new(s.clone())))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SITE: &str = include_str!("../../tests/fixtures/site.yml");

    fn proposal(ap: &str, from: u16, to: u16, group: Option<u32>) -> Proposal {
        let at = |channel| Setting {
            channel,
            width: 160,
            power: Some(18),
        };
        Proposal {
            ap: ap.into(),
            radio: "radio6".into(),
            band: Band::B6,
            current: at(from),
            proposed: at(to),
            runs: Some(at(from)),
            measure: None,
            predicted_busy: None,
            snr: None,
            snr_change: 0.0,
            measured: true,
            kept: None,
            pending: false,
            restart: None,
            group,
            reason: String::new(),
        }
    }

    fn confirmed(key: &str, channel: u16, center: u16) -> Confirmed {
        Confirmed {
            key: key.into(),
            channel,
            width: 160,
            center,
            power: Some(18),
        }
    }

    /// ap1 moves onto the block ap2 leaves: one group, applied together or
    /// not at all, and never as anything but what was confirmed.
    #[test]
    fn a_group_is_applied_whole_or_not_at_all() {
        let site = site::read(SITE).unwrap();
        let plan = Plan {
            radios: vec![
                proposal("ap1", 37, 69, Some(1)),
                proposal("ap2", 69, 5, Some(1)),
            ],
            notes: Vec::new(),
        };
        let one = [confirmed("ap1/radio6", 69, 79)];
        assert_eq!(
            check(&plan, &site, &one).unwrap_err(),
            "ap1/radio6 goes with ap2/radio6: apply them together"
        );
        let both = [one[0].clone(), confirmed("ap2/radio6", 5, 15)];
        let chosen = check(&plan, &site, &both).unwrap();
        assert_eq!(chosen.len(), 2);
        let off = [one[0].clone(), confirmed("ap2/radio6", 5, 47)];
        assert_eq!(
            check(&plan, &site, &off).unwrap_err(),
            "ap2/radio6 no longer proposes what was confirmed"
        );
        // Without the group, the result is still checked for shared spectrum.
        let ungrouped = Plan {
            radios: vec![proposal("ap1", 37, 69, None), proposal("ap2", 69, 5, None)],
            notes: Vec::new(),
        };
        assert_eq!(
            check(&ungrouped, &site, &one).unwrap_err(),
            "ap1's 6 GHz radio on channel 69 would share spectrum with ap2's on channel 69"
        );
    }
}
