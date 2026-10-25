//! The operator's actions on a client, `POST /api/clients/{mac}/kick`,
//! `/block`, `/unblock` and `/steer` (`{"target_bssid": "<mac>"}`, and
//! `"force": true` to have the client disassociated if it declines).
//!
//! A request acts only when it comes from the UI's own page and from an
//! admin, checked in that order ([`refusal`], which also gates the start of a
//! radio's spectrum scan over the WebSocket, since a scan costs airtime):
//! - its `Origin` is the one the UI is served at, and a POST says
//!   `Content-Type: application/json`, which no cross-site form can send
//!   without a preflight this listener never grants (403 `cross-site`);
//! - the sign-in proxy's groups header (`X-Auth-Request-Groups`, which the
//!   reverse proxy strips from what clients send) names the admin group (403
//!   `not an admin`).
//!
//! A kick or a steer goes to the AP the client is on. A block or an unblock
//! is saved in the policy first, so that what an AP is told is what a restart
//! tells it again, then sent to every connected AP; an AP that is away is
//! given the whole policy when it reconnects. Each AP's result is awaited for
//! `Timing::command` (504 past it), and each is an event and a journal line.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::Bytes;
use axum::extract::{FromRef, Path, State as Ext};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinSet;
use u6e_proto::mac;
use u6e_proto::msg::CommandKind;

use crate::config::Config;
use crate::http::{error, json_response};
use crate::policy;
use crate::state::{Action, Shared, Waiter, action_name};

/// The user the sign-in proxy names.
pub const USER_HEADER: &str = "x-forwarded-preferred-username";
/// The user's groups, comma-separated, as the sign-in proxy names them.
pub const GROUPS_HEADER: &str = "x-auth-request-groups";

/// What an action needs beside the state: who may take it, from where, and
/// where its decisions are kept.
#[derive(Clone)]
pub struct Access {
    pub public_origin: String,
    pub admin_group: String,
    /// The policy file; holding the lock is what makes one save at a time.
    policy: Arc<Mutex<PathBuf>>,
    /// How long an AP has to answer a command.
    pub timeout: Duration,
}

impl Access {
    pub fn new(config: &Config, timeout: Duration) -> Self {
        Access {
            public_origin: config.public_origin.clone(),
            admin_group: config.admin_group.clone(),
            policy: Arc::new(Mutex::new(config.policy_path.clone())),
            timeout,
        }
    }
}

/// The web listener's shared parts, each its handlers' `State`.
#[derive(Clone)]
pub struct Web {
    pub state: Shared,
    pub access: Access,
}

impl FromRef<Web> for Shared {
    fn from_ref(web: &Web) -> Shared {
        web.state.clone()
    }
}

impl FromRef<Web> for Access {
    fn from_ref(web: &Web) -> Access {
        web.access.clone()
    }
}

pub fn user(req: &HeaderMap) -> Option<String> {
    let v = req.get(USER_HEADER)?.to_str().ok()?;
    Some(v.to_owned())
}

/// Whether the groups header names `group`.
pub fn is_admin(req: &HeaderMap, group: &str) -> bool {
    let values = req.get_all(GROUPS_HEADER).iter();
    let groups = values
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','));
    groups.map(str::trim).any(|g| g == group)
}

/// How a request to act reaches the listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// A POST, whose body must say it is JSON.
    Post,
    /// A WebSocket's handshake: it has no body, and a browser always says
    /// which page opens one.
    WebSocket,
}

/// Whether the request could have come from another site's page.
fn cross_site(req: &HeaderMap, origin: &str, via: Via) -> bool {
    let kind = req.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok());
    let json = kind
        .and_then(|k| k.split(';').next())
        .is_some_and(|k| k.trim().eq_ignore_ascii_case("application/json"));
    let ours = req
        .get(header::ORIGIN)
        .is_some_and(|o| o.as_bytes() == origin.as_bytes());
    !(ours && (json || via == Via::WebSocket))
}

/// Why `req` may not act, if it may not, and logs the refusal of `what`.
pub fn refusal(req: &HeaderMap, access: &Access, via: Via, what: &str) -> Option<&'static str> {
    let why = if cross_site(req, &access.public_origin, via) {
        "cross-site"
    } else if !is_admin(req, &access.admin_group) {
        "not an admin"
    } else {
        return None;
    };
    // Quoted: the client spells what it asks for.
    eprintln!(
        "u6e-controller: {} {what:?} refused: {why}",
        user(req).as_deref().unwrap_or("(no user)")
    );
    Some(why)
}

/// `GET /api/me`: who the UI's user is, and whether they may act.
pub async fn me(Ext(access): Ext<Access>, req: HeaderMap) -> Response {
    let admin = is_admin(&req, &access.admin_group);
    json_response(&json!({ "user": user(&req), "admin": admin }))
}

pub async fn kick(web: Ext<Web>, Path(mac): Path<String>, req: HeaderMap) -> Response {
    act(&web, &req, "kick", &mac, |mac| {
        Ok(CommandKind::Kick { mac })
    })
    .await
}

pub async fn block(web: Ext<Web>, Path(mac): Path<String>, req: HeaderMap) -> Response {
    act(&web, &req, "block", &mac, |mac| {
        Ok(CommandKind::Block { mac })
    })
    .await
}

pub async fn unblock(web: Ext<Web>, Path(mac): Path<String>, req: HeaderMap) -> Response {
    act(&web, &req, "unblock", &mac, |mac| {
        Ok(CommandKind::Unblock { mac })
    })
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SteerBody {
    target_bssid: String,
    /// Disassociate the client if it declines; polite when left out.
    #[serde(default)]
    force: bool,
}

pub async fn steer(
    web: Ext<Web>,
    Path(mac): Path<String>,
    req: HeaderMap,
    body: Bytes,
) -> Response {
    act(&web, &req, "steer", &mac, |mac| {
        let b: SteerBody =
            serde_json::from_slice(&body).map_err(|_| "not {\"target_bssid\", \"force\"}")?;
        let target_bssid = mac::parse(&b.target_bssid).ok_or("target_bssid is not a MAC")?;
        Ok(CommandKind::Steer {
            mac,
            target_bssid,
            force: b.force,
        })
    })
    .await
}

/// Checks the request, then takes `action`, the command `kind` makes of the
/// client's MAC.
async fn act(
    Ext(web): &Ext<Web>,
    req: &HeaderMap,
    action: &str,
    mac: &str,
    kind: impl FnOnce([u8; 6]) -> Result<CommandKind, &'static str>,
) -> Response {
    if let Some(why) = refusal(req, &web.access, Via::Post, &format!("{action} {mac}")) {
        return error(StatusCode::FORBIDDEN, why);
    }
    let who = user(req);
    let Some(mac) = mac::parse(mac) else {
        return error(StatusCode::BAD_REQUEST, "not a MAC");
    };
    let kind = match kind(mac) {
        Ok(k) => k,
        Err(why) => return error(StatusCode::BAD_REQUEST, why),
    };
    let ctx = Ctx {
        state: &web.state,
        user: who,
        action: action_name(&kind),
        mac,
    };
    if matches!(
        kind,
        CommandKind::Block { .. } | CommandKind::Unblock { .. }
    ) {
        ctx.everywhere(&web.access, kind).await
    } else {
        ctx.where_it_is(&web.access, kind).await
    }
}

/// How a command sent to one AP ended.
enum Outcome {
    Done {
        ok: bool,
        detail: String,
    },
    /// No result in time.
    Timeout,
    /// The AP was not connected, or went away before it answered.
    Gone,
}

impl Outcome {
    fn ok(&self) -> bool {
        matches!(self, Outcome::Done { ok: true, .. })
    }

    fn detail(&self, timeout: Duration) -> String {
        match self {
            Outcome::Done { detail, .. } => detail.clone(),
            Outcome::Timeout => format!("no answer from the AP in {timeout:?}"),
            Outcome::Gone => "the AP is not connected".into(),
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Outcome::Done { .. } => StatusCode::OK,
            Outcome::Timeout => StatusCode::GATEWAY_TIMEOUT,
            Outcome::Gone => StatusCode::BAD_GATEWAY,
        }
    }
}

/// Sends `kind` to `ap` and waits for its result.
async fn send(state: &Shared, ap: &str, kind: CommandKind, timeout: Duration) -> Outcome {
    let (tx, rx) = oneshot::channel();
    let Some(id) = state.write().command(ap, kind, Waiter::Reply(tx)) else {
        return Outcome::Gone;
    };
    match tokio::time::timeout(timeout, rx).await {
        Ok(Ok(r)) => Outcome::Done {
            ok: r.ok,
            detail: r.detail,
        },
        // The session ended, and its commands with it.
        Ok(Err(_)) => Outcome::Gone,
        Err(_) => {
            state.write().forget(id);
            Outcome::Timeout
        }
    }
}

/// One action being taken.
struct Ctx<'a> {
    state: &'a Shared,
    user: Option<String>,
    action: &'static str,
    mac: [u8; 6],
}

impl Ctx<'_> {
    /// Records what came of the action on `ap`; its JSON for the answer.
    fn record(&self, ap: Option<&str>, ok: bool, detail: String) -> Value {
        let mut v = json!({ "ok": ok, "detail": detail });
        if let Some(ap) = ap {
            v["ap"] = ap.into();
        }
        self.state.write().record(Action {
            at: SystemTime::now(),
            user: self.user.clone(),
            action: self.action,
            mac: self.mac,
            ap: ap.map(str::to_owned),
            ok,
            detail,
        });
        v
    }

    fn count(&self, result: &'static str) {
        let mut state = self.state.write();
        *state
            .action_counts
            .entry((self.action, result))
            .or_default() += 1;
    }

    /// A kick or a steer, on the AP the client is on.
    async fn where_it_is(&self, access: &Access, kind: CommandKind) -> Response {
        let clients = self.state.read().clients();
        let Some(ap) = clients
            .into_iter()
            .find(|c| c.station.mac == self.mac)
            .map(|c| c.ap)
        else {
            self.record(None, false, "not associated".into());
            self.count("failed");
            return error(StatusCode::NOT_FOUND, "not associated");
        };
        let out = send(self.state, &ap, kind, access.timeout).await;
        let body = self.record(Some(&ap), out.ok(), out.detail(access.timeout));
        self.count(result(&[&out]));
        (out.status(), json_response(&body)).into_response()
    }

    /// A block or an unblock: saved, then sent to every connected AP.
    async fn everywhere(&self, access: &Access, kind: CommandKind) -> Response {
        let blocking = matches!(kind, CommandKind::Block { .. });
        let aps = match self.save(access, blocking).await {
            Ok(aps) => aps,
            Err(e) => {
                let detail = format!("the policy was not saved: {e}");
                self.record(None, false, detail.clone());
                self.count("failed");
                return error(StatusCode::INTERNAL_SERVER_ERROR, &detail);
            }
        };
        let mut sends = JoinSet::new();
        for ap in aps {
            let (state, kind, timeout) = (self.state.clone(), kind.clone(), access.timeout);
            sends.spawn(async move {
                let out = send(&state, &ap, kind, timeout).await;
                (ap, out)
            });
        }
        let mut outs = sends.join_all().await;
        outs.sort_by(|a, b| a.0.cmp(&b.0));
        let mut results = Vec::new();
        for (ap, out) in &outs {
            results.push(self.record(Some(ap), out.ok(), out.detail(access.timeout)));
        }
        if outs.is_empty() {
            results.push(self.record(None, true, "saved; no AP is connected".into()));
        }
        let all: Vec<&Outcome> = outs.iter().map(|(_, o)| o).collect();
        self.count(result(&all));
        let status = all.iter().map(|o| o.status()).max_by_key(|s| match *s {
            StatusCode::GATEWAY_TIMEOUT => 2,
            StatusCode::BAD_GATEWAY => 1,
            _ => 0,
        });
        let ok = all.iter().all(|o| o.ok());
        let body = json!({ "ok": ok, "results": results });
        (status.unwrap_or(StatusCode::OK), json_response(&body)).into_response()
    }

    /// Saves the client as blocked or not, one save at a time, and takes it
    /// into the state; the APs connected then, which are to be told.
    async fn save(&self, access: &Access, blocking: bool) -> std::io::Result<Vec<String>> {
        let path = access.policy.lock().await;
        let mut next = self.state.read().blocked.clone();
        let changed = if blocking {
            next.insert(self.mac)
        } else {
            next.remove(&self.mac)
        };
        if changed {
            let (path, next) = (path.clone(), next.clone());
            tokio::task::spawn_blocking(move || policy::save(&path, &next))
                .await
                .map_err(std::io::Error::other)??;
        }
        let mut state = self.state.write();
        state.blocked = next;
        Ok(state.connected())
    }
}

/// The metrics' result of an action that ended in `outs`.
fn result(outs: &[&Outcome]) -> &'static str {
    if outs.iter().any(|o| matches!(o, Outcome::Timeout)) {
        "timeout"
    } else if outs.iter().all(|o| o.ok()) {
        "ok"
    } else {
        "failed"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, HeaderValue::from_static(v));
        }
        h
    }

    const ORIGIN: &str = "https://wifi.example.org";

    #[test]
    fn only_json_from_the_uis_origin_is_same_site() {
        let ok = [
            ("content-type", "application/json"),
            ("origin", "https://wifi.example.org"),
        ];
        assert!(!cross_site(&headers(&ok), ORIGIN, Via::Post));
        let params = [
            ("content-type", "Application/JSON; charset=utf-8"),
            ("origin", "https://wifi.example.org"),
        ];
        assert!(!cross_site(&headers(&params), ORIGIN, Via::Post));
        // A WebSocket's handshake has no body; only its origin counts.
        let page = [("origin", "https://wifi.example.org")];
        assert!(!cross_site(&headers(&page), ORIGIN, Via::WebSocket));
        for bad in [
            &[][..],
            &[("origin", "https://elsewhere.example")],
            &[("origin", "http://wifi.example.org")],
            &[("origin", "null")],
        ] {
            assert!(cross_site(&headers(bad), ORIGIN, Via::WebSocket), "{bad:?}");
        }
        for bad in [
            &[("content-type", "application/json")][..],
            &[("origin", "https://wifi.example.org")],
            &[
                ("content-type", "text/plain"),
                ("origin", "https://wifi.example.org"),
            ],
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("origin", "https://wifi.example.org"),
            ],
            &[
                ("content-type", "application/json"),
                ("origin", "https://wifi.example.org.evil.example"),
            ],
            &[("content-type", "application/json"), ("origin", "null")],
        ] {
            assert!(cross_site(&headers(bad), ORIGIN, Via::Post), "{bad:?}");
        }
    }

    #[test]
    fn the_admin_group_is_one_of_the_listed_groups() {
        let g = |v: &'static str| headers(&[(GROUPS_HEADER, v)]);
        assert!(is_admin(&g("wifi-admins"), "wifi-admins"));
        assert!(is_admin(&g("staff, wifi-admins,other"), "wifi-admins"));
        assert!(!is_admin(&g("wifi-admins-old,staff"), "wifi-admins"));
        assert!(!is_admin(&g(""), "wifi-admins"));
        assert!(!is_admin(&headers(&[]), "wifi-admins"));
        // Only that header: another proxy's spelling is not read.
        let other = headers(&[("x-forwarded-groups", "wifi-admins")]);
        assert!(!is_admin(&other, "wifi-admins"));
    }
}
