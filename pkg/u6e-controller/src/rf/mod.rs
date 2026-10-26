//! The RF planner: it scores each radio's channel, width and power from what
//! the window measured (`history`, kept in RAM from the snapshots) within the
//! site file's constraints (`site`, `plan`), and proposes; nothing changes
//! until an admin applies a proposal. Applying it is a commit of the site
//! file to its repository by the controller (`git`, line-level `yaml` edits
//! of the affected keys only), which the deploy path then takes to the APs
//! like any other change of the file: rendered, signed by the deploy runner,
//! applied by the agent with a channel switch or a power change.
//!
//! `GET /api/rf/plan` is the plan for anyone who may view; it reads the site
//! file from the clone, fetched at most once a minute. `POST /api/rf/apply`
//! (`{"radios": ["<ap>/<radio>", …]}`) is gated as the other actions are
//! (`actions::refusal`): it fetches, plans again, and lands the chosen
//! radios' proposals as one commit, refused (409) when one no longer
//! proposes a change. Each radio applied is an action in the events and a
//! journal line, the commit's id in it.

pub mod channels;
pub mod config;
pub mod git;
pub mod history;
pub mod plan;
pub mod site;
pub mod yaml;

use std::collections::BTreeMap;
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

use crate::actions::{self, Via, Web};
use crate::http::{error, json_response};
use crate::state::{Action, State};
use crate::view;

use self::config::Settings;
use self::plan::{Plan, Proposal};
use self::site::{Change, Setting};

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

    /// The plan for the site file `text` and the state now.
    fn plan(&self, state: &State, text: &str) -> Result<Plan, String> {
        let site = site::read(text).map_err(|e| format!("{}: {e}", self.settings.repo.file))?;
        let live: BTreeMap<String, _> = state
            .aps()
            .map(|(n, a)| (n.to_owned(), a.snapshot.as_ref()))
            .collect();
        Ok(plan::plan(
            &site,
            &live,
            &state.history,
            &self.settings.rules,
        ))
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

fn proposal(p: &Proposal) -> Value {
    let mut o = json!({
        "key": p.key(),
        "ap": p.ap,
        "radio": p.radio,
        "band": view::band(p.band),
        "current": setting(&p.current),
        "proposed": setting(&p.proposed),
        "change": p.changes(),
        "measured": p.measured,
        "snr_change": round1(p.snr_change),
        "reason": p.reason,
    });
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
    let plan = planner.plan(&web.state.read(), &read.text);
    let plan = match plan {
        Ok(p) => p,
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
        "window_hours": planner.settings.rules.window_hours,
        "notes": plan.notes,
        "site": site,
        "radios": plan.radios.iter().map(proposal).collect::<Vec<_>>(),
    });
    if let Some(a) = planner.last() {
        v["last"] = applied(&a);
    }
    json_response(&v)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyBody {
    radios: Vec<String>,
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
            "not {\"radios\": [\"<ap>/<radio>\", …]}",
        );
    };
    if b.radios.is_empty() || b.radios.len() > MAX_RADIOS {
        return error(StatusCode::BAD_REQUEST, "radios must name 1 to 16 radios");
    }
    let user = actions::user(&req);
    let who = user.clone().unwrap_or_else(|| "(no user)".into());
    // The lock is held from the fetch to the push: one apply at a time.
    let mut clone = planner.clone.lock().await;
    let outcome = async {
        let read = planner.read(&mut clone, true).await.map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("the site file could not be fetched: {e}"),
            )
        })?;
        let plan = planner
            .plan(&web.state.read(), &read.text)
            .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e))?;
        let mut chosen = Vec::new();
        for key in &b.radios {
            match plan.radios.iter().find(|p| &p.key() == key) {
                Some(p) if p.changes() => chosen.push(p.clone()),
                Some(_) => {
                    return Err((
                        StatusCode::CONFLICT,
                        format!("{key} no longer proposes a change"),
                    ));
                }
                None => {
                    return Err((
                        StatusCode::CONFLICT,
                        format!("{key} is not a radio of the plan"),
                    ));
                }
            }
        }
        chosen.dedup_by(|a, b| a.key() == b.key());
        let changes: Vec<Change> = chosen
            .iter()
            .map(|p| Change {
                ap: p.ap.clone(),
                band: p.band,
                from: p.current,
                to: p.proposed,
            })
            .collect();
        let refs: Vec<&Proposal> = chosen.iter().collect();
        let msg = message(&refs, &who);
        let repo = planner.settings.repo.clone();
        let landed = spawn_blocking(move || {
            repo.land(
                |text| site::edit(text, &changes).map_err(|e| e.to_string()),
                &msg,
            )
        })
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        match landed {
            Ok(l) => Ok((chosen, l)),
            Err(e @ (git::Error::Edit(_) | git::Error::Conflict)) => {
                Err((StatusCode::CONFLICT, e.to_string()))
            }
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
    let record =
        |state: &mut State, radios: &[(String, Option<String>)], ok: bool, detail: &str| {
            for (key, ap) in radios {
                state.record(Action {
                    at: SystemTime::now(),
                    user: user.clone(),
                    action: "rf-plan",
                    mac: None,
                    ap: ap.clone(),
                    ok,
                    detail: format!("{key}: {detail}"),
                });
            }
        };
    let keys: Vec<(String, Option<String>)> = b
        .radios
        .iter()
        .map(|k| (k.clone(), k.split_once('/').map(|(ap, _)| ap.to_owned())))
        .collect();
    let (status, body, last) = match outcome {
        Ok((chosen, landed)) => {
            let short = &landed.commit[..landed.commit.len().min(12)];
            let mut state = web.state.write();
            for p in &chosen {
                let detail = format!(
                    "{} → {}, commit {short}",
                    what(&p.current),
                    what(&p.proposed)
                );
                record(&mut state, &[(p.key(), Some(p.ap.clone()))], true, &detail);
            }
            let radios: Vec<String> = chosen.iter().map(Proposal::key).collect();
            let detail = format!("committed {short} to {}", planner.settings.repo.branch);
            let body =
                json!({ "ok": true, "commit": landed.commit, "radios": radios, "detail": detail });
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
            record(&mut web.state.write(), &keys, false, &why);
            let last = Applied {
                at: SystemTime::now(),
                user: user.clone(),
                radios: b.radios.clone(),
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

/// The planner a configuration asks for, if any.
pub fn from(settings: Option<&Settings>) -> Option<Arc<Planner>> {
    settings.map(|s| Arc::new(Planner::new(s.clone())))
}
