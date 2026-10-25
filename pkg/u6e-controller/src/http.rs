//! The web listener (`listen_http`): the web UI, embedded in the binary, its
//! JSON API, the operator's actions (`actions`), and the WebSocket that keeps
//! the UI live.
//!
//! The UI's files are served under `/assets/<version>/`, the version a hash of
//! them all, so they can be cached for good and a new binary still reaches
//! every browser at once; the page itself is revalidated on each load. The
//! WebSocket's first message names the APs it watches (`{"subscribe":["ap1"]}`
//! or `{"subscribe":"*"}`, with `"flows":true` for their clients' flows too);
//! it then gets their state as one JSON `key`, a JSON merge `patch` of what
//! changed after each update, and their new `events`. While it is open each of
//! those APs reports every 2 s, and its flows every 10 s when asked for.
//!
//! `GET /api/flows?ap=&client=` is the latest flows, `GET /api/flows/full?ap=`
//! asks the AP for every connection it forwards and waits for the answer.
//!
//! The listener is reached only through the reverse proxy that signs users
//! in, which names the user in `X-Forwarded-Preferred-Username` and their
//! groups in `X-Auth-Request-Groups`.

use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::sync::LazyLock;
use std::time::Duration;

use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State as Ext};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::broadcast::error::RecvError;
use tokio::time::timeout;
use u6e_proto::mac;

use crate::actions::{self, Access, Web};
use crate::state::{Change, Shared, WatchGuard};
use crate::view;

/// How long a new WebSocket may take to say what it watches.
const SUBSCRIBE_TIMEOUT: Duration = Duration::from_secs(10);
/// A subscription is a list of AP names; nothing a client sends is larger.
const MAX_MESSAGE: usize = 4096;

const HTML: &str = "text/html; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";
const JS: &str = "text/javascript; charset=utf-8";
const SVG: &str = "image/svg+xml";

/// The page allows only its own files and its own WebSocket (and the
/// stylesheet's inline `data:` images).
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
                   connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// One embedded file of the UI.
struct Asset {
    path: &'static str,
    kind: &'static str,
    body: &'static [u8],
}

macro_rules! asset {
    ($path:literal, $kind:expr) => {
        Asset {
            path: $path,
            kind: $kind,
            body: include_bytes!(concat!("../ui/", $path)),
        }
    };
}

const FILES: [Asset; 10] = [
    asset!("app.js", JS),
    asset!("charts.js", JS),
    asset!("theme.js", JS),
    asset!("util.js", JS),
    asset!("views/client.js", JS),
    asset!("views/clients.js", JS),
    asset!("views/devices.js", JS),
    asset!("views/events.js", JS),
    asset!("style.css", CSS),
    asset!("icon.svg", SVG),
];

const INDEX: &str = include_str!("../ui/index.html");

/// The files with their entity tags, the version they make up, and the page
/// pointing at that version.
struct Ui {
    version: String,
    files: Vec<(&'static Asset, String)>,
    index: String,
    index_tag: String,
}

/// A strong entity tag of `body`: its hash, which is all a cache needs to
/// tell two versions apart.
fn tag(body: &[u8]) -> String {
    let mut h = DefaultHasher::new();
    h.write(body);
    format!("\"{:016x}\"", h.finish())
}

static UI: LazyLock<Ui> = LazyLock::new(|| {
    let files: Vec<_> = FILES.iter().map(|a| (a, tag(a.body))).collect();
    let all: String = files.iter().map(|(_, t)| t.as_str()).collect();
    let version = tag(all.as_bytes()).trim_matches('"')[..12].to_owned();
    let index = INDEX.replace("{{assets}}", &format!("/assets/{version}"));
    let index_tag = tag(index.as_bytes());
    Ui {
        version,
        files,
        index,
        index_tag,
    }
});

/// The web listener's routes.
pub fn router(state: Shared, access: Access) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/assets/{*path}", get(asset))
        .route("/api/aps", get(api_aps))
        .route("/api/clients", get(api_clients))
        .route("/api/events", get(api_events))
        .route("/api/flows", get(api_flows))
        .route("/api/flows/full", get(api_flows_full))
        .route("/api/me", get(actions::me))
        .route("/api/clients/{mac}/kick", post(actions::kick))
        .route("/api/clients/{mac}/block", post(actions::block))
        .route("/api/clients/{mac}/unblock", post(actions::unblock))
        .route("/api/clients/{mac}/steer", post(actions::steer))
        .route("/ws", get(ws))
        .with_state(Web { state, access })
}

/// `body` as `kind`, or 304 when the client holds `etag` already.
fn cached(
    req: &HeaderMap,
    kind: &'static str,
    body: &'static [u8],
    etag: &str,
    cache: &'static str,
) -> Response {
    let fresh = req
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim() == etag));
    let mut resp = if fresh {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        ([(header::CONTENT_TYPE, kind)], body).into_response()
    };
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    if let Ok(v) = HeaderValue::from_str(etag) {
        h.insert(header::ETAG, v);
    }
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    resp
}

async fn index(req: HeaderMap) -> Response {
    let ui = &*UI;
    let mut resp = cached(&req, HTML, ui.index.as_bytes(), &ui.index_tag, "no-cache");
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    resp
}

/// A file under the current version is cached for good; one named without a
/// version is revalidated, and a version other than the current one is gone.
async fn asset(Path(path): Path<String>, req: HeaderMap) -> Response {
    let ui = &*UI;
    let (name, cache) = match path.split_once('/') {
        Some((v, rest)) if v == ui.version => (rest, "public, max-age=31536000, immutable"),
        _ => (path.as_str(), "no-cache"),
    };
    match ui.files.iter().find(|(a, _)| a.path == name) {
        Some((a, etag)) => cached(&req, a.kind, a.body, etag, cache),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

pub(crate) fn json_response(v: &Value) -> Response {
    let headers = [
        (header::CONTENT_TYPE, "application/json"),
        (header::CACHE_CONTROL, "no-store"),
    ];
    (headers, v.to_string()).into_response()
}

async fn api_aps(Ext(state): Ext<Shared>) -> Response {
    json_response(&view::aps(&state.read(), |_| true))
}

async fn api_clients(Ext(state): Ext<Shared>) -> Response {
    json_response(&view::clients(&state.read(), |_| true))
}

#[derive(Deserialize)]
struct EventsQuery {
    ap: Option<String>,
}

async fn api_events(Ext(state): Ext<Shared>, Query(q): Query<EventsQuery>) -> Response {
    let events = view::events(&state.read(), q.ap.as_deref());
    json_response(&Value::Array(events))
}

#[derive(Deserialize)]
struct FlowsQuery {
    ap: Option<String>,
    client: Option<String>,
}

/// An API error: `{"error": why}`.
pub(crate) fn error(status: StatusCode, why: &str) -> Response {
    (status, json_response(&json!({ "error": why }))).into_response()
}

async fn api_flows(Ext(state): Ext<Shared>, Query(q): Query<FlowsQuery>) -> Response {
    let client = match q.client.as_deref().map(mac::parse) {
        None => None,
        Some(Some(m)) => Some(m),
        Some(None) => return error(StatusCode::BAD_REQUEST, "not a MAC"),
    };
    let wanted = |ap: &str| q.ap.as_deref().is_none_or(|a| a == ap);
    json_response(&view::flows(&state.read(), wanted, client))
}

#[derive(Deserialize)]
struct FullQuery {
    ap: String,
}

/// Every connection the AP forwards, from the agent's answer to a request:
/// in the shape of `/api/flows`, and never kept.
async fn api_flows_full(Ext(web): Ext<Web>, Query(q): Query<FullQuery>) -> Response {
    let Some(answer) = web.state.write().want_full(&q.ap) else {
        return error(StatusCode::NOT_FOUND, "not a connected AP");
    };
    match timeout(web.access.timeout, answer).await {
        Ok(Ok(flows)) => {
            let state = web.state.read();
            let one = view::flows_of(&state, &flows, std::time::SystemTime::now(), None);
            json_response(&json!({ q.ap: one }))
        }
        Ok(Err(_)) => error(StatusCode::BAD_GATEWAY, "the AP went away"),
        Err(_) => error(StatusCode::GATEWAY_TIMEOUT, "no answer from the AP"),
    }
}

/// Whether a browser's request comes from a page of this site: another site's
/// page could otherwise read the state with the user's sign-in.
fn same_origin(req: &HeaderMap) -> bool {
    let Some(origin) = req.get(header::ORIGIN) else {
        return true;
    };
    let host = req.get(header::HOST).and_then(|h| h.to_str().ok());
    let origin_host = origin
        .to_str()
        .ok()
        .and_then(|o| o.split_once("://"))
        .map(|(_, h)| h);
    host.is_some() && origin_host == host
}

async fn ws(Ext(state): Ext<Shared>, req: HeaderMap, upgrade: WebSocketUpgrade) -> Response {
    if !same_origin(&req) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let user = actions::user(&req);
    upgrade
        .max_message_size(MAX_MESSAGE)
        .on_upgrade(move |socket| live(socket, state, user))
}

#[derive(Deserialize)]
struct Subscribe {
    subscribe: Aps,
    /// The APs' clients' flows too.
    #[serde(default)]
    flows: bool,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Aps {
    Named(Vec<String>),
    /// `"*"`: every AP.
    All(String),
}

/// The configured APs the socket's first message asks for, and whether
/// their flows too.
async fn subscription(ws: &mut WebSocket, state: &Shared) -> Option<(Vec<String>, bool)> {
    let msg = timeout(SUBSCRIBE_TIMEOUT, ws.recv()).await.ok()??.ok()?;
    let Message::Text(text) = msg else {
        return None;
    };
    let sub: Subscribe = serde_json::from_str(&text).ok()?;
    let state = state.read();
    let names = state.aps().map(|(n, _)| n.to_owned());
    let aps = match sub.subscribe {
        Aps::All(all) if all == "*" => names.collect(),
        Aps::All(_) => return None,
        Aps::Named(wanted) => names.filter(|n| wanted.contains(n)).collect(),
    };
    Some((aps, sub.flows))
}

async fn send(ws: &mut WebSocket, msg: &Value) -> Result<(), axum::Error> {
    ws.send(Message::Text(msg.to_string().into())).await
}

/// Serves one WebSocket until either end closes it.
async fn live(mut ws: WebSocket, state: Shared, user: Option<String>) {
    let Some((names, flows)) = subscription(&mut ws, &state).await else {
        return;
    };
    let wanted = |ap: &str| names.iter().any(|n| n == ap);
    // Held until the socket ends: the watchers are what set the 2 s tick and
    // the 10 s flow cadence.
    let flow_watchers = names
        .iter()
        .filter(|_| flows)
        .filter_map(|n| state.watch_flows(n));
    let _watching: Vec<WatchGuard> = names
        .iter()
        .filter_map(|n| state.watch(n))
        .chain(flow_watchers)
        .collect();
    // Subscribed first, so nothing between the key and the first patch is lost.
    let mut changes = state.read().subscribe();
    let mut sent = view::view(&state.read(), wanted, flows);
    if send(&mut ws, &json!({ "key": sent, "user": user }))
        .await
        .is_err()
    {
        return;
    }
    loop {
        let change = tokio::select! {
            c = changes.recv() => c,
            m = ws.recv() => match m {
                // Nothing else a client says means anything yet.
                Some(Ok(_)) => continue,
                _ => return,
            },
        };
        let (relevant, out) = match change {
            Ok(Change::Event(ap, ev)) if wanted(&ap) => {
                let s = state.read();
                let ev = s.ap(&ap).and_then(|a| view::event(&ap, a, &ev));
                (true, ev.map(|e| json!({ "events": [e] })))
            }
            Ok(Change::Up(ap) | Change::Down(ap) | Change::Snapshot(ap)) => (wanted(&ap), None),
            Ok(Change::Flows(ap)) => (flows && wanted(&ap), None),
            Ok(Change::Names) => (true, None),
            Ok(Change::Action(a)) if a.ap.as_deref().is_none_or(wanted) => {
                (false, Some(json!({ "events": [view::action(&a)] })))
            }
            Ok(Change::Event(..) | Change::Action(_)) => (false, None),
            // Too slow to keep up: the state is whole again with the next
            // patch, the events missed are told of.
            Err(RecvError::Lagged(_)) => (true, Some(json!({ "lost": true }))),
            Err(RecvError::Closed) => return,
        };
        if let Some(msg) = out
            && send(&mut ws, &msg).await.is_err()
        {
            return;
        }
        if !relevant {
            continue;
        }
        let next = view::view(&state.read(), wanted, flows);
        if let Some(patch) = view::diff(&sent, &next) {
            if send(&mut ws, &json!({ "patch": patch })).await.is_err() {
                return;
            }
            sent = next;
        }
    }
}
