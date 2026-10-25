//! The Wi-Fi controller: the APs' agents dial in over the post-quantum,
//! key-pinned TLS of `u6e_proto::tls`, and their snapshots and events become
//! a live state in RAM, served to Prometheus (`metrics`) and to the web UI
//! (`http`, which reads it through `view`).

pub mod agents;
pub mod config;
pub mod http;
pub mod metrics;
pub mod state;
pub mod view;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use axum::Router;
use tokio::net::TcpListener;
use u6e_proto::tls::{self, AllowedKeys, Identity};

use crate::agents::Timing;
use crate::config::Config;
use crate::state::{Shared, State};

/// A running controller: its state and the addresses it listens on.
pub struct Controller {
    pub state: Shared,
    pub agents: SocketAddr,
    pub http: SocketAddr,
    pub metrics: SocketAddr,
}

/// Binds the three listeners and serves them on the current runtime.
pub async fn start(config: &Config, identity: &Identity, timing: Timing) -> io::Result<Controller> {
    let state = Shared::new(State::new(config.aps.keys().cloned()));
    let keys: HashMap<_, _> = config.aps.iter().map(|(n, k)| (*k, n.clone())).collect();
    let allowed: AllowedKeys = Arc::new(RwLock::new(keys));
    let agents = TcpListener::bind(config.listen_agents).await?;
    let http = TcpListener::bind(config.listen_http).await?;
    let metrics = TcpListener::bind(config.listen_metrics).await?;
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
    ));
    tokio::spawn(serve_http("http", http, http::router(state.clone())));
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
