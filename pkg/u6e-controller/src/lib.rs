//! The Wi-Fi controller: the APs' agents dial in over the post-quantum,
//! key-pinned TLS of `u6e_proto::tls`, and their snapshots, flows and events
//! become a live state in RAM, served to Prometheus (`metrics`) and to the web
//! UI (`http`, which reads it through `view`). The UI's operators act on
//! clients through `actions`; what must outlive the process is in `policy`.
//! The radios' spectrum scans run while the UI watches them (`spectrum`).
//! The deploy runner dials the same listener with its own key (`runner`):
//! its signed Wi-Fi configurations are relayed to the APs, and the image
//! rollouts admins ask for go to it, each health-gated here.

pub mod actions;
pub mod agents;
pub mod config;
pub mod http;
pub mod metrics;
pub mod names;
pub mod policy;
pub mod runner;
pub mod spectrum;
pub mod state;
pub mod view;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use axum::Router;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use u6e_proto::tls::{self, AllowedKeys, Identity};

use crate::actions::Access;
use crate::agents::{Listener, Timing};
use crate::config::Config;
use crate::names::{Lookups, Resolve};
use crate::policy::Store;
use crate::state::{Shared, State};

/// A running controller: its state and the addresses it listens on.
pub struct Controller {
    pub state: Shared,
    pub agents: SocketAddr,
    pub http: SocketAddr,
    pub metrics: SocketAddr,
}

/// Loads the policy, binds the three listeners and serves them on the
/// current runtime; client names are looked up through `resolver`.
pub async fn start(
    config: &Config,
    identity: &Identity,
    timing: Timing,
    resolver: Arc<dyn Resolve>,
) -> io::Result<Controller> {
    let path = &config.policy_path;
    let saved = policy::load(path)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
    let mut state = State::new(config.hostnames.clone())
        .with_policy(saved)
        .with_spectrum(timing.spectrum);
    if config.runner.is_some() {
        state = state.with_runner();
    }
    let state = Shared::new(state);
    // The handshake admits the runner's key beside the APs'; which one a
    // connection holds says which it is (agents).
    let mut keys: HashMap<_, _> = config.aps.iter().map(|(n, k)| (*k, n.clone())).collect();
    keys.extend(config.runner.map(|k| (k, "(deploy runner)".to_owned())));
    let allowed: AllowedKeys = Arc::new(RwLock::new(keys));
    let bind = |addr| async move {
        TcpListener::bind(addr)
            .await
            .map_err(|e| io::Error::new(e.kind(), format!("listen on {addr}: {e}")))
    };
    let agents = bind(config.listen_agents).await?;
    let http = bind(config.listen_http).await?;
    let metrics = bind(config.listen_metrics).await?;
    let controller = Controller {
        state: state.clone(),
        agents: agents.local_addr()?,
        http: http.local_addr()?,
        metrics: metrics.local_addr()?,
    };
    let store = Store::new(config.policy_path.clone());
    let listener = Listener {
        acceptor: TlsAcceptor::from(tls::server_config(identity, Arc::clone(&allowed))),
        allowed,
        runner: config.runner,
        state: state.clone(),
        timing,
        lookups: Lookups::new(resolver),
        store: store.clone(),
    };
    tokio::spawn(agents::serve(agents, listener));
    tokio::spawn(runner::supervise(
        state.clone(),
        store.clone(),
        timing.start,
    ));
    let access = Access::new(config, timing.command, store);
    let web = http::router(state.clone(), access);
    tokio::spawn(serve_http("http", http, web));
    tokio::spawn(spectrum::supervise(state.clone()));
    tokio::spawn(serve_http("metrics", metrics, metrics::router(state)));
    Ok(controller)
}

async fn serve_http(what: &str, listener: TcpListener, router: Router) {
    // axum::serve retries failed accepts itself, so this returns only if the
    // listener is gone.
    if let Err(e) = axum::serve(listener, router).await {
        eprintln!("u6e-controller: {what} listener: {e}");
    }
}
