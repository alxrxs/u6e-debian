//! The Wi-Fi controller: the APs' agents dial in over the post-quantum,
//! key-pinned TLS of `u6e_proto::tls`, and their snapshots, flows and events
//! become a live state in RAM, served to Prometheus (`metrics`) and to the web
//! UI (`http`, which reads it through `view`). The UI's operators act on
//! clients through `actions`, limit their rates and the SSIDs' on the APs'
//! NSS through `limits` and capture a client's traffic through `captures`;
//! what must outlive the process is in `policy`.
//! The radios' spectrum scans run while the UI watches them (`spectrum`).
//! The controller signs the live Wi-Fi configurations root's local command
//! hands it (`local`, `configs`) with a key of its own, which the APs pin,
//! and sends them; it keeps the images root's other local command adds
//! (`images`), stages them on the APs itself over SSH (`stage`) and rolls an
//! AP onto its newest one when an admin asks, health-gated and rolled back
//! when the AP does not come back healthy (`rollout`). The RF planner (`rf`)
//! proposes the radios' channels, widths and powers from their history, and
//! commits a proposal an admin applies to the site file. Clients are named
//! from the DHCP servers' leases, the reverse DNS of their addresses and
//! their MACs' vendors (`identity`, `leases`, `names`, `oui`). Each
//! client's sessions and timeline (`sessions`, `timeline`) come from all of
//! that and from RADIUS's verdicts, read from its log (`radius`). What the
//! APs read of mDNS shows which device offers which service and whether it
//! answers for it (`services`); the flows and the station counters each
//! client's volumes and where they went (`traffic`). An admin measures an
//! AP's throughput to the controller, and a signed-in viewer their own
//! device's through the UI (`speedtest`). The devices the configuration
//! lists are announced to Home Assistant as they join and leave the Wi-Fi
//! (`presence`). Admins set the VLAN RADIUS's MAC authentication puts a
//! device in, in the mapping every RADIUS server reads from OpenBao
//! (`macauth`). The metrics, RADIUS's log and the leases each speak mutual
//! TLS with the host's monitoring certificate when switched to it (`mtls`).

pub mod actions;
pub mod agents;
pub mod captures;
mod clean;
pub mod config;
pub mod configs;
pub mod experience;
mod fetch;
mod frames;
pub mod http;
pub mod identity;
pub mod images;
pub mod leases;
pub mod limits;
pub mod local;
pub mod macauth;
pub mod metrics;
pub mod mtls;
pub mod names;
pub mod oui;
pub mod policy;
pub mod presence;
pub mod radius;
pub mod rf;
pub mod roaming;
pub mod rollout;
pub mod script;
pub mod services;
pub mod sessions;
pub mod spectrum;
pub mod speedtest;
pub mod stage;
mod stall;
pub mod state;
mod store;
#[cfg(test)]
mod testdir;
pub mod timeline;
pub mod traffic;
pub mod view;

use std::collections::HashMap;
use std::fs::{self, Permissions};
use std::io;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime};

use axum::Router;
use tokio::net::{TcpListener, UnixListener};
use tokio::time::interval;
use tokio_rustls::TlsAcceptor;
use u6e_proto::frame::zeroize;
use u6e_proto::tls::{self, AllowedKeys, Identity};

use crate::actions::Access;
use crate::agents::{Listener, Timing};
use crate::captures::Captures;
use crate::config::Config;
use crate::configs::{SetAside, Signer};
use crate::images::Images;
use crate::local::Local;
use crate::names::{Lookups, Resolve};
use crate::policy::Store;
use crate::rollout::Engine;
use crate::sessions::Sessions;
use crate::stage::{Ssh, Stage, Target, Waits};
use crate::state::{Shared, State};
use crate::traffic::Traffic;

/// A running controller: its state, the addresses it listens on, and what
/// its web listener's actions take (for a listener of another's own).
pub struct Controller {
    pub state: Shared,
    pub agents: SocketAddr,
    pub http: SocketAddr,
    pub metrics: SocketAddr,
    pub access: Access,
}

/// The signer of `[configs]`, its key read from its file (and wiped there
/// after), with the files it set aside.
fn signer(config: &Config, identity: &Identity) -> io::Result<Option<(Signer, SetAside)>> {
    let Some(settings) = &config.configs else {
        return Ok(None);
    };
    let path = &settings.signing_key;
    let at = |e: String| io::Error::other(format!("{}: {e}", path.display()));
    let mut pem = fs::read_to_string(path).map_err(|e| at(e.to_string()))?;
    let key = configs::signing_key(&pem, identity);
    // SAFETY: zeros are valid UTF-8, and the PEM is not read after.
    zeroize(unsafe { pem.as_mut_vec() });
    let key = key.map_err(at)?;
    let hosts = config.hostnames.values().map(String::as_str);
    Signer::open(settings, key, hosts).map(Some)
}

/// Loads the policy, binds the listeners (and the local socket, when the
/// configuration signs configurations or rolls images out) and serves them
/// on the current runtime, going on with the rollouts the policy holds open;
/// client names are looked up through `resolver`, and images staged by
/// `stager`, or over SSH with the configuration's credentials without one.
pub async fn start(
    config: &Config,
    identity: &Identity,
    timing: Timing,
    resolver: Arc<dyn Resolve>,
    stager: Option<Arc<dyn Stage>>,
) -> io::Result<Controller> {
    let path = &config.policy_path;
    let saved = policy::load(path)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
    // ssh refuses a key others may read, and would say so only at the first
    // push or staging: the controller refuses to start with one instead.
    let rf_key = config
        .rf
        .as_ref()
        .and_then(|rf| rf.repo.remote.ssh_key.as_ref());
    let staging = config
        .rollouts
        .iter()
        .flat_map(|r| [&r.ssh.root_key, &r.ssh.stock_password]);
    for key in rf_key.into_iter().chain(staging) {
        u6e_git::check_key(key).map_err(io::Error::other)?;
    }
    let window = config
        .rf
        .as_ref()
        .map_or(rf::history::WINDOW, |rf| rf.rules.window_hours);
    if !config.guards.enforce.is_empty() && config.leases.exporters.is_empty() {
        eprintln!(
            "u6e-controller: [guards] enforce needs [leases]: the APs' client guards only report"
        );
    }
    let history = &config.history_path;
    let (sessions, aside) = Sessions::load(history)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", history.display())))?;
    if let Some(aside) = aside {
        eprintln!(
            "u6e-controller: {}: not a history this controller reads, set aside as {aside}",
            history.display()
        );
    }
    let traffic_path = &config.traffic_path;
    let (traffic, aside) = Traffic::load(traffic_path)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", traffic_path.display())))?;
    if let Some(aside) = aside {
        eprintln!(
            "u6e-controller: {}: not traffic this controller reads, set aside as {aside}",
            traffic_path.display()
        );
    }
    let mut state = State::new(config.hostnames.clone())
        .with_policy(saved)
        .with_sessions(sessions)
        .with_traffic(traffic)
        .with_sticky(config.sticky_dbm)
        .with_spectrum(timing.spectrum)
        .with_speedtests(timing.speedtest)
        .with_history(window)
        .with_leases(&config.leases.exporters)
        .with_tls(config.tls_endpoints())
        .with_guards(config.guards.clone())
        .with_site_limits(config.limits.clone())
        .with_captures(Captures::open(&config.captures_path).map_err(|e| {
            io::Error::new(e.kind(), format!("{}: {e}", config.captures_path.display()))
        })?);
    let mut set_aside = Vec::new();
    if let Some((s, aside)) = signer(config, identity)? {
        state = state.with_signer(s);
        set_aside = aside;
    }
    let images = match &config.rollouts {
        Some(r) => {
            let images = Images::open(&r.images)?;
            state = state.with_rollouts(images.index()?);
            Some(images)
        }
        None => None,
    };
    state.set_aside(set_aside);
    if config.radius.is_some() {
        state = state.with_radius();
    }
    if let Some(p) = &config.presence {
        state = state.with_presence(p);
    }
    if let Some(m) = &config.mac_auth {
        state = state.with_mac_auth(m, timing.mac_auth);
    }
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
    let addresses = (
        agents.local_addr()?,
        http.local_addr()?,
        metrics.local_addr()?,
    );
    let store = Store::new(config.policy_path.clone());
    let engine = config
        .rollouts
        .clone()
        .zip(images)
        .map(|(settings, images)| {
            let targets = config.addresses.iter().map(|(ap, address)| {
                let target = Target {
                    ap: ap.clone(),
                    hostname: config.hostnames[ap].clone(),
                    address: address.clone(),
                };
                (ap.clone(), target)
            });
            let (state, policy) = (state.clone(), store.clone());
            let ssh =
                || -> Arc<dyn Stage> { Arc::new(Ssh::new(settings.ssh.clone(), Waits::default())) };
            let stager = stager.unwrap_or_else(ssh);
            Engine::new(
                state,
                policy,
                settings,
                images,
                stager,
                targets.collect(),
                timing.resume,
            )
        });
    if config.configs.is_some() || engine.is_some() {
        let local = Local {
            state: state.clone(),
            policy: store.clone(),
            rollouts: engine.clone(),
            apply_wait: timing.apply + timing.ping * 2,
        };
        tokio::spawn(local::serve(local, bind_local(config)?));
    }
    let lookups = Lookups::new(resolver);
    let listener = Listener {
        acceptor: TlsAcceptor::from(tls::server_config(identity, Arc::clone(&allowed))),
        allowed,
        state: state.clone(),
        timing,
        lookups: lookups.clone(),
        store: store.clone(),
    };
    tokio::spawn(agents::serve(agents, listener));
    tokio::spawn(expire(state.clone(), timing));
    if !config.leases.exporters.is_empty() {
        tokio::spawn(leases::supervise(state.clone(), config.leases.clone()));
    }
    if let Some(settings) = &config.radius {
        tokio::spawn(radius::supervise(state.clone(), settings.clone()));
    }
    if let Some(settings) = &config.presence {
        tokio::spawn(presence::supervise(state.clone(), settings.clone()));
    }
    if let Some(settings) = &config.mac_auth {
        let read = timing.mac_auth.read;
        tokio::spawn(macauth::supervise(state.clone(), settings.clone(), read));
    }
    tokio::spawn(sessions::keep(state.clone(), history.clone()));
    tokio::spawn(traffic::keep(state.clone(), traffic_path.clone()));
    let mut access = Access::new(config, &timing, store, lookups);
    if let Some(e) = &engine {
        e.resume();
        access.rollouts = Some(e.clone());
    }
    if let Some(planner) = &access.rf {
        let live = rf::live::supervise(state.clone(), Arc::clone(planner), timing);
        tokio::spawn(live);
    }
    let controller = Controller {
        state: state.clone(),
        agents: addresses.0,
        http: addresses.1,
        metrics: addresses.2,
        access: access.clone(),
    };
    let web = http::router(state.clone(), access);
    let web_listener = stall::Listener::new(http, timing.ui_stall);
    tokio::spawn(async move {
        if let Err(e) = axum::serve(web_listener, web).await {
            eprintln!("u6e-controller: http listener: {e}");
        }
    });
    tokio::spawn(spectrum::supervise(state.clone()));
    let scraped = metrics::router(state.clone());
    match config
        .monitoring_tls
        .clone()
        .filter(|t| !t.metrics_clients.is_empty())
    {
        Some(tls) => {
            let listener = mtls::listen(metrics, tls, state)?;
            tokio::spawn(serve_http("metrics", listener, scraped));
        }
        None => {
            tokio::spawn(serve_http("metrics", metrics, scraped));
        }
    }
    Ok(controller)
}

/// The local socket, its owner's alone.
fn bind_local(config: &Config) -> io::Result<UnixListener> {
    let socket = &config.socket;
    match fs::remove_file(socket) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let listener = UnixListener::bind(socket)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", socket.display())))?;
    fs::set_permissions(socket, Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Gives up on the configurations the APs have not answered in
/// `Timing::apply`, ends the holds whose time is up, looks at the services
/// again and abandons the client speed tests not finished in time, for the
/// life of the process.
async fn expire(state_of: Shared, timing: Timing) {
    let mut every = interval(timing.ping);
    loop {
        every.tick().await;
        let mut state = state_of.write();
        state.expire_relays(Instant::now(), timing.apply);
        state.expire_holds();
        state.services_tick(SystemTime::now());
        speedtest::client::expire(&mut state);
        drop(state);
        captures::supervise(&state_of, SystemTime::now());
    }
}

async fn serve_http<L>(what: &str, listener: L, router: Router)
where
    L: axum::serve::Listener,
    L::Addr: std::fmt::Debug,
{
    // axum::serve retries failed accepts itself, so this returns only if the
    // listener is gone.
    if let Err(e) = axum::serve(listener, router).await {
        eprintln!("u6e-controller: {what} listener: {e}");
    }
}
