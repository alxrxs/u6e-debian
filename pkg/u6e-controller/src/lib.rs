//! The Wi-Fi controller: the APs' agents dial in over the post-quantum,
//! key-pinned TLS of `u6e_proto::tls`, and their snapshots, flows and events
//! become a live state in RAM, served to Prometheus (`metrics`) and to the web
//! UI (`http`, which reads it through `view`). The UI's operators act on
//! clients through `actions`; what must outlive the process is in `policy`.
//! The radios' spectrum scans run while the UI watches them (`spectrum`).

pub mod actions;
pub mod agents;
pub mod config;
pub mod http;
pub mod metrics;
pub mod names;
pub mod policy;
pub mod spectrum;
pub mod state;
pub mod view;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use axum::Router;
use tokio::net::TcpListener;
use u6e_proto::tls::{self, AllowedKeys, Identity};

use crate::actions::Access;
use crate::agents::Timing;
use crate::config::Config;
use crate::names::{Lookups, Resolve};
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
    let blocked = policy::load(path)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
    let state = State::new(config.aps.keys().cloned())
        .with_blocked(blocked)
        .with_spectrum(timing.spectrum);
    let state = Shared::new(state);
    let keys: HashMap<_, _> = config.aps.iter().map(|(n, k)| (*k, n.clone())).collect();
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
    let server = tls::server_config(identity, Arc::clone(&allowed));
    tokio::spawn(agents::serve(
        agents,
        server,
        allowed,
        state.clone(),
        timing,
        Lookups::new(resolver),
    ));
    let access = Access::new(config, timing.command);
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
