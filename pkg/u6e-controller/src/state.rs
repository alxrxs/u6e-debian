//! The live view of the APs: per AP what it runs, its latest snapshot rebuilt
//! from key frames and deltas, its clients' latest flows, and its recent
//! events. All of that is in RAM; an AP sends it all again when it
//! reconnects. Beside it are the operator's side: the clients blocked (kept
//! on disk by `policy`), the commands waiting for their results, the actions
//! taken, and the names of the clients' addresses; and the deploy runner's
//! (`runner`): the Wi-Fi configurations it signs, relayed to the APs and
//! known here by hash only (each AP's last acknowledged one kept on disk too),
//! and the image rollouts with their health gate.
//!
//! The state also sets each AP's tick and flow cadence. While a UI client
//! watches an AP it reports every 2 s, otherwise at the 15 s scrape interval;
//! while one watches its flows they come every 10 s (an AP stretches that
//! for a large connection table, up to the minute), otherwise every minute.
//! The session follows per-AP channels holding what the watchers want. The
//! scans of the APs' radios are kept here too, watched as `spectrum` says.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::{Notify, broadcast, mpsc, oneshot, watch};
use u6e_proto::delta::{self, Gap};
use u6e_proto::msg::{
    AgentMsg, Command, CommandKind, CommandResult, ConfigApplied, CtlMsg, Event, EventKind, Flows,
    Hello, Mechanism, RolloutOutcome, RolloutRequest, RolloutResult, RunnerCtlMsg, SignedConfig,
    Snapshot, Station,
};
use u6e_proto::{PROTOCOL, mac};

use crate::names::{self, Names};
use crate::policy::{Blocked, ConfigId, Policy};
use crate::spectrum::{self, Limits, Scan, Stopped};

/// Events kept per AP, newest last.
pub const EVENTS_CAP: usize = 1000;
/// Operator actions kept, newest last.
pub const ACTIONS_CAP: usize = 1000;
/// The tick of an AP someone is watching.
pub const TICK_WATCHED: u16 = 2;
/// The tick of an unwatched AP: the scrape interval, which is also the
/// agent's tick until it is told one.
pub const TICK_IDLE: u16 = 15;
/// The flow cadence of an AP whose flows someone is watching.
pub const FLOWS_WATCHED: u16 = 10;
/// The flow cadence otherwise, which is the agent's until it is told one.
pub const FLOWS_IDLE: u16 = 60;
/// The least time between two requests to an AP for its whole flow table:
/// each costs the AP a dump of every connection.
pub const FULL_INTERVAL: Duration = Duration::from_secs(10);
/// How long a client's addresses are remembered after its flows last showed
/// them, so that a client quiet for a while keeps its name.
const ADDRESSES_KEPT: Duration = Duration::from_secs(3600);
const CHANGES_CAP: usize = 256;
/// Messages queued for a session; a session that far behind is stalled.
const OUTBOX_CAP: usize = 64;
/// Rollouts kept, newest last.
pub const ROLLOUTS_CAP: usize = 20;
/// Lines of a rollout's log kept, newest last.
pub const ROLLOUT_LOG_CAP: usize = 400;
/// Longer than any rollout takes: staging, the gate, staging the previous
/// image again.
pub const ROLLOUT_STALE: Duration = Duration::from_secs(3 * 3600);

/// What changed, for the UI to fetch.
#[derive(Debug, Clone, PartialEq)]
pub enum Change {
    Up(String),
    Down(String),
    Snapshot(String),
    Event(String, Event),
    Flows(String),
    /// A client's name came or changed.
    Names,
    Action(Action),
    /// The scan of a radio (AP, radio) started, stopped or was joined.
    Spectrum(String, String),
    /// The runner's link, a configuration or a rollout changed.
    Deploy,
}

/// One action on one AP (or on none, when no AP was connected to carry a
/// block out), with what came of it: an operator's on a client (`mac`), or
/// one of the deploy runner's (`apply`, `repush`, `rollout`) or an admin's
/// (`upgrade`) on an AP.
#[derive(Debug, Clone, PartialEq)]
pub struct Action {
    pub at: SystemTime,
    /// The signed-in user, as the proxy named them, or who asked the runner.
    pub user: Option<String>,
    pub action: &'static str,
    pub mac: Option<[u8; 6]>,
    pub ap: Option<String>,
    pub ok: bool,
    pub detail: String,
}

/// What came of the last configuration relayed to an AP.
#[derive(Debug, Clone, PartialEq)]
pub struct Applied {
    pub at: SystemTime,
    pub result: ConfigApplied,
}

/// A configuration relayed to an AP and not answered yet: the runner's id of
/// its request, and when it went.
struct Relay {
    id: u64,
    config: ConfigId,
    since: Instant,
}

/// The deploy runner's link: at most one runner at a time, its key the one
/// the configuration names.
#[derive(Default)]
pub struct Runner {
    /// Whether the configuration admits a runner at all.
    pub configured: bool,
    /// What it said it runs, at its last connection.
    pub version: Option<String>,
    pub connected_since: Option<SystemTime>,
    session: Option<RunnerLive>,
}

impl Runner {
    pub fn is_up(&self) -> bool {
        self.session.is_some()
    }
}

/// The connection currently serving the runner; dropping `stop` ends it.
struct RunnerLive {
    id: u64,
    _stop: oneshot::Sender<()>,
    outbox: mpsc::Sender<RunnerCtlMsg>,
}

/// What a session gets when it takes over the runner's link.
pub struct RunnerRegistration {
    pub id: u64,
    /// What to send the runner: answers, re-pushes, rollouts, gates.
    pub outbox: mpsc::Receiver<RunnerCtlMsg>,
    /// Resolves when a newer connection of the runner takes over.
    pub stop: oneshot::Receiver<()>,
}

/// One image rollout, from its request to the runner's last word on it.
#[derive(Debug, Clone, PartialEq)]
pub struct Rollout {
    pub id: u64,
    pub ap: String,
    pub image_id: String,
    /// What the AP ran when it was asked, which a failed gate rolls back to.
    pub previous: String,
    pub user: String,
    pub at: SystemTime,
    /// The AP's sessions numbered past this one are the AP coming back.
    after: u64,
    /// The radios the AP had up and the clients it had when it was asked:
    /// the gate wants as many radios up, and some clients back if it had any.
    radios: usize,
    clients: usize,
    /// The gate's verdict, once it was sent: healthy, and what was seen.
    pub gate: Option<(bool, String)>,
    /// The runner's last word on it.
    pub result: Option<(RolloutOutcome, String)>,
    pub log: VecDeque<String>,
}

impl Rollout {
    pub fn is_open(&self) -> bool {
        self.result.is_none()
    }
}

/// The name of a mechanism, as the API and the events spell it.
pub fn mechanism_name(m: Mechanism) -> &'static str {
    match m {
        Mechanism::Unchanged => "unchanged",
        Mechanism::InPlace => "in place",
        Mechanism::ChannelSwitch => "channel switch",
        Mechanism::Power => "power",
        Mechanism::Restart => "restart",
    }
}

/// The name of a rollout's outcome, as the API and the metrics spell it.
pub fn outcome_name(o: RolloutOutcome) -> &'static str {
    match o {
        RolloutOutcome::Refused => "refused",
        RolloutOutcome::Done => "done",
        RolloutOutcome::RolledBack => "rolled_back",
        RolloutOutcome::Failed => "failed",
    }
}

/// An answer that a configuration was not applied, for the runner.
fn not_applied(sha256: [u8; 32], detail: String) -> ConfigApplied {
    ConfigApplied {
        sha256,
        ok: false,
        radios: Vec::new(),
        detail,
    }
}

/// A hash, short, for logs and events.
fn short(sha256: Option<[u8; 32]>) -> String {
    sha256.map_or_else(|| "none".into(), |h| mac::hex(&h[..6]))
}

/// The name of a command's kind, as the API and the metrics spell it.
pub fn action_name(kind: &CommandKind) -> &'static str {
    match kind {
        CommandKind::Kick { .. } => "kick",
        CommandKind::Block { .. } => "block",
        CommandKind::Unblock { .. } => "unblock",
        CommandKind::Steer { .. } => "steer",
        CommandKind::SyncBlocks { .. } => "sync",
    }
}

/// Who waits for a command's result.
pub enum Waiter {
    /// An operator's request.
    Reply(oneshot::Sender<CommandResult>),
    /// Nobody: the policy's blocks given to an AP that reconnected, whose
    /// failure is only logged.
    Resent,
}

struct Pending {
    ap: String,
    waiter: Waiter,
}

/// A client's addresses as its flows last showed them.
struct Addresses {
    ips: Vec<IpAddr>,
    at: SystemTime,
}

/// One configured AP.
pub struct Ap {
    /// What it last said it runs; kept while it is down.
    pub hello: Option<Hello>,
    /// The protocol its agent stated when it last dialed in.
    pub protocol: Option<u16>,
    /// The current snapshot, only while connected.
    pub snapshot: Option<Snapshot>,
    /// When `snapshot` was last brought up to date.
    pub snapshot_at: Option<SystemTime>,
    /// The snapshot before it in this session and when it came: the base
    /// the UI's rates are worked out from.
    pub previous: Option<(Snapshot, SystemTime)>,
    pub connected_since: Option<SystemTime>,
    /// When the agent last sent anything.
    pub last_seen: Option<SystemTime>,
    pub events: VecDeque<Event>,
    /// Firmware crashes per phy since the controller started.
    pub crashes: BTreeMap<String, u64>,
    /// Its clients' latest flows and when they came, only while connected.
    pub flows: Option<(Flows, SystemTime)>,
    rx_bytes: Arc<AtomicU64>,
    watchers: usize,
    tick: watch::Sender<u16>,
    flow_watchers: usize,
    cadence: watch::Sender<u16>,
    /// Requests for the whole table, answered by the next flows that hold it.
    full: Vec<oneshot::Sender<Flows>>,
    /// When the agent was last asked for it.
    full_asked: Option<Instant>,
    /// Its radios' scans, by radio, once one was watched.
    pub scans: BTreeMap<String, Scan>,
    /// The configuration it last acknowledged (kept in the policy), the one
    /// the runner sent it last, and what came of that.
    pub acked: Option<ConfigId>,
    pub wanted: Option<ConfigId>,
    pub last_apply: Option<Applied>,
    relay: Option<Relay>,
    /// It came back running another configuration than the one it
    /// acknowledged while the runner was away: ask the runner once it is back.
    repush_due: bool,
    pub(crate) session: Option<Live>,
}

/// The connection currently serving an AP; dropping `stop` ends it.
pub(crate) struct Live {
    id: u64,
    _stop: oneshot::Sender<()>,
    pub(crate) outbox: mpsc::Sender<CtlMsg>,
}

impl Ap {
    fn new() -> Self {
        Ap {
            hello: None,
            protocol: None,
            snapshot: None,
            snapshot_at: None,
            previous: None,
            connected_since: None,
            last_seen: None,
            events: VecDeque::new(),
            crashes: BTreeMap::new(),
            flows: None,
            rx_bytes: Arc::new(AtomicU64::new(0)),
            watchers: 0,
            tick: watch::Sender::new(TICK_IDLE),
            flow_watchers: 0,
            cadence: watch::Sender::new(FLOWS_IDLE),
            full: Vec::new(),
            full_asked: None,
            scans: BTreeMap::new(),
            acked: None,
            wanted: None,
            last_apply: None,
            relay: None,
            repush_due: false,
            session: None,
        }
    }

    /// The hash of the configuration it reports installed, while connected.
    pub fn installed(&self) -> Option<[u8; 32]> {
        self.snapshot.as_ref()?.config_sha256
    }

    /// Whether it runs another configuration than the one it acknowledged.
    pub fn drifts(&self) -> bool {
        let installed = self.snapshot.as_ref().map(|s| s.config_sha256);
        matches!((self.acked, installed), (Some(a), Some(i)) if i != Some(a.sha256))
    }

    pub fn is_up(&self) -> bool {
        self.session.is_some()
    }

    /// The protocol of its agent, when that is not this controller's and the
    /// agent is therefore turned away.
    pub fn mismatch(&self) -> Option<u16> {
        self.protocol.filter(|&p| p != PROTOCOL)
    }

    /// Bytes received from the agent on the wire, TLS included, over every
    /// connection since the controller started.
    pub fn rx_bytes(&self) -> u64 {
        self.rx_bytes.load(Ordering::Relaxed)
    }

    fn push_event(&mut self, ev: Event) {
        if self.events.len() == EVENTS_CAP {
            self.events.pop_front();
        }
        self.events.push_back(ev);
    }

    /// Makes `next` the current snapshot, the current one its predecessor.
    fn advance(&mut self, next: Snapshot, now: SystemTime) {
        let prev = self.snapshot.replace(next);
        self.previous = prev.zip(self.snapshot_at);
        self.snapshot_at = Some(now);
    }

    /// Forgets what only a live connection knows; the radios whose scans
    /// ended with it, which its agent stops as the link goes.
    fn reset_session(&mut self) -> Vec<String> {
        self.snapshot = None;
        self.snapshot_at = None;
        self.previous = None;
        self.connected_since = None;
        self.flows = None;
        self.full.clear();
        let scans = self.scans.iter_mut();
        let ended =
            scans.filter_map(|(radio, scan)| scan.end(Stopped::Link).then(|| radio.clone()));
        ended.collect()
    }

    /// The runner's request to sign again the configuration this AP last
    /// acknowledged, named as its configurations are (the AP's host name).
    fn repush(&self) -> Option<RunnerCtlMsg> {
        Some(RunnerCtlMsg::Repush {
            ap: self.hello.as_ref()?.ap.clone(),
            acked: Some(self.acked?.sha256),
            installed: self.installed(),
        })
    }

    /// One more watcher (`more`) or one fewer, of the AP or its flows.
    fn watched(&mut self, flows: bool, more: bool) {
        let (count, channel, watched, idle) = if flows {
            (
                &mut self.flow_watchers,
                &self.cadence,
                FLOWS_WATCHED,
                FLOWS_IDLE,
            )
        } else {
            (&mut self.watchers, &self.tick, TICK_WATCHED, TICK_IDLE)
        };
        if more {
            *count += 1;
            if *count == 1 {
                channel.send_replace(watched);
            }
        } else {
            *count -= 1;
            if *count == 0 {
                channel.send_replace(idle);
            }
        }
    }
}

/// Why a request for the whole flow table is not made.
#[derive(Debug, PartialEq, Eq)]
pub enum Full {
    /// No session serves the AP (or it is too far behind to take one).
    NotConnected,
    /// The AP was asked less than [`FULL_INTERVAL`] ago: this much is left.
    TooSoon(Duration),
}

/// Whether `f` lists every connection it counts, as an answer to a request
/// for the whole table does.
fn lists_everything(f: &Flows) -> bool {
    f.clients
        .iter()
        .all(|c| c.top.len() as u64 == u64::from(c.conns))
}

/// A client as the UI and the metrics see it: once, on the AP that heard it last.
#[derive(Debug, Clone, PartialEq)]
pub struct ClientView {
    pub ap: String,
    /// The BSS's interface name.
    pub bss: String,
    pub ssid: String,
    pub station: Station,
    /// When the AP last heard from the client.
    pub last_seen: SystemTime,
}

/// What a session gets when it takes over an AP.
pub struct Registration {
    pub id: u64,
    /// The tick the AP should report at.
    pub tick: watch::Receiver<u16>,
    /// The flow cadence the AP should keep.
    pub cadence: watch::Receiver<u16>,
    /// What else to send the agent: commands and requests for the flows.
    pub outbox: mpsc::Receiver<CtlMsg>,
    /// Resolves when a newer connection of the same AP takes over.
    pub stop: oneshot::Receiver<()>,
    /// The AP's received-bytes counter.
    pub rx_bytes: Arc<AtomicU64>,
}

/// The live state of every configured AP.
pub struct State {
    pub(crate) aps: BTreeMap<String, Ap>,
    next_id: u64,
    changes: broadcast::Sender<Change>,
    /// The clients blocked, as saved in the policy file.
    pub blocked: Blocked,
    next_command: u64,
    pending: HashMap<u64, Pending>,
    /// Operator actions, newest last.
    pub actions: VecDeque<Action>,
    /// Operator requests by action and result, for the metrics.
    pub action_counts: BTreeMap<(&'static str, &'static str), u64>,
    names: Names,
    addresses: HashMap<[u8; 6], Addresses>,
    /// When the scans stop.
    pub spectrum: Limits,
    /// Wakes `spectrum::supervise` when a scan's deadline may have moved.
    pub(crate) wake: Arc<Notify>,
    pub runner: Runner,
    /// The rollouts, newest last.
    pub rollouts: VecDeque<Rollout>,
    next_rollout: u64,
    /// Configurations relayed and rollouts ended, by result, for the metrics.
    pub apply_counts: BTreeMap<&'static str, u64>,
    pub rollout_counts: BTreeMap<&'static str, u64>,
    /// The policy changed since it was saved; the session that changed it
    /// saves it.
    policy_dirty: bool,
}

impl State {
    pub fn new(names: impl IntoIterator<Item = String>) -> Self {
        State {
            aps: names.into_iter().map(|n| (n, Ap::new())).collect(),
            next_id: 0,
            changes: broadcast::Sender::new(CHANGES_CAP),
            blocked: Blocked::new(),
            next_command: 0,
            pending: HashMap::new(),
            actions: VecDeque::new(),
            action_counts: BTreeMap::new(),
            names: Names::default(),
            addresses: HashMap::new(),
            spectrum: Limits::default(),
            wake: Arc::new(Notify::new()),
            runner: Runner::default(),
            rollouts: VecDeque::new(),
            next_rollout: 0,
            apply_counts: BTreeMap::new(),
            rollout_counts: BTreeMap::new(),
            policy_dirty: false,
        }
    }

    /// The state with a saved policy's blocks and acknowledged
    /// configurations (of the APs still configured).
    pub fn with_policy(mut self, policy: Policy) -> Self {
        for (name, config) in policy.configs {
            if let Some(ap) = self.aps.get_mut(&name) {
                ap.acked = Some(config);
            }
        }
        State {
            blocked: policy.blocked,
            ..self
        }
    }

    /// The state admitting a deploy runner.
    pub fn with_runner(mut self) -> Self {
        self.runner.configured = true;
        self
    }

    /// What the policy file is to hold now.
    pub fn policy(&self) -> Policy {
        let acked = self
            .aps
            .iter()
            .filter_map(|(n, a)| Some((n.clone(), a.acked?)));
        Policy {
            blocked: self.blocked.clone(),
            configs: acked.collect(),
        }
    }

    /// Whether the policy changed since this was last asked, which the asker
    /// then saves.
    pub fn take_dirty(&mut self) -> bool {
        std::mem::take(&mut self.policy_dirty)
    }

    /// The state with its scans stopped after `spectrum`.
    pub fn with_spectrum(self, spectrum: Limits) -> Self {
        State { spectrum, ..self }
    }

    /// Every configured AP by name, connected or not.
    pub fn aps(&self) -> impl Iterator<Item = (&str, &Ap)> {
        self.aps.iter().map(|(n, a)| (n.as_str(), a))
    }

    pub fn ap(&self, name: &str) -> Option<&Ap> {
        self.aps.get(name)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Change> {
        self.changes.subscribe()
    }

    pub fn watchers(&self, ap: &str) -> usize {
        self.aps.get(ap).map_or(0, |a| a.watchers)
    }

    pub fn flow_watchers(&self, ap: &str) -> usize {
        self.aps.get(ap).map_or(0, |a| a.flow_watchers)
    }

    pub(crate) fn notify(&self, change: Change) {
        // No receiver is not an error: nobody has the UI open.
        let _ = self.changes.send(change);
    }

    /// Hands the AP to a new connection, which said `hello`. A connection
    /// already serving it is told to stop.
    pub fn connect(&mut self, ap: &str, hello: Hello) -> Option<Registration> {
        let entry = self.aps.get_mut(ap)?;
        self.next_id += 1;
        let id = self.next_id;
        let (stop_tx, stop) = oneshot::channel();
        let (outbox_tx, outbox) = mpsc::channel(OUTBOX_CAP);
        entry.session = Some(Live {
            id,
            _stop: stop_tx,
            outbox: outbox_tx,
        });
        // Each connection numbers its snapshots from 1 again, so a delta must
        // never meet the previous connection's snapshot.
        let ended = entry.reset_session();
        let now = SystemTime::now();
        entry.connected_since = Some(now);
        entry.last_seen = Some(now);
        entry.hello = Some(hello);
        entry.protocol = Some(PROTOCOL);
        let reg = Registration {
            id,
            tick: entry.tick.subscribe(),
            cadence: entry.cadence.subscribe(),
            outbox,
            stop,
            rx_bytes: Arc::clone(&entry.rx_bytes),
        };
        // The previous connection's commands went with it.
        self.drop_pending(ap);
        self.scans_ended(ap, ended);
        self.notify(Change::Up(ap.to_owned()));
        Some(reg)
    }

    /// Records that the AP dialed in speaking `protocol`, not this
    /// controller's, and ends any session it held: it no longer runs what
    /// that session said. True when its protocol was another before, so that
    /// a change is told once and not at each redial.
    pub fn refuse(&mut self, ap: &str, protocol: u16) -> bool {
        let Some(entry) = self.aps.get_mut(ap) else {
            return false;
        };
        entry.last_seen = Some(SystemTime::now());
        // An image whose agent this controller turns away can never pass a
        // rollout's gate.
        let why = format!("its agent speaks protocol {protocol}, this controller {PROTOCOL}");
        self.gate_fails(ap, why);
        let Some(entry) = self.aps.get_mut(ap) else {
            return false;
        };
        if entry.protocol == Some(protocol) {
            return false;
        }
        entry.protocol = Some(protocol);
        entry.hello = None;
        entry.session = None;
        let ended = entry.reset_session();
        self.drop_pending(ap);
        self.scans_ended(ap, ended);
        self.notify(Change::Down(ap.to_owned()));
        true
    }

    /// Ends session `id`; a no-op when a newer connection has taken over.
    pub fn disconnect(&mut self, ap: &str, id: u64) {
        let Some(entry) = self.live(ap, id) else {
            return;
        };
        entry.session = None;
        let ended = entry.reset_session();
        self.drop_pending(ap);
        self.scans_ended(ap, ended);
        self.notify(Change::Down(ap.to_owned()));
    }

    /// Tells the watchers of the scans of `radios` on `ap` they ended.
    fn scans_ended(&self, ap: &str, radios: Vec<String>) {
        for radio in radios {
            self.notify(Change::Spectrum(ap.to_owned(), radio));
        }
    }

    /// Forgets the commands sent to `ap`: their waiters hear it went away.
    fn drop_pending(&mut self, ap: &str) {
        self.pending.retain(|_, p| p.ap != ap);
    }

    /// The AP, while session `id` is the one serving it.
    fn live(&mut self, ap: &str, id: u64) -> Option<&mut Ap> {
        self.aps
            .get_mut(ap)
            .filter(|a| a.session.as_ref().is_some_and(|s| s.id == id))
    }

    /// Takes in one message of session `id`. `Err(Gap)` means a delta did not
    /// fit the snapshot held, or a key frame was not valid; nothing was
    /// applied and the session asks for a key frame. Every snapshot held is
    /// therefore valid.
    pub fn apply(&mut self, ap: &str, id: u64, msg: AgentMsg) -> Result<(), Gap> {
        let Some(entry) = self.live(ap, id) else {
            return Ok(());
        };
        let now = SystemTime::now();
        entry.last_seen = Some(now);
        let change = match msg {
            AgentMsg::Hello(h) => {
                entry.hello = Some(h);
                None
            }
            AgentMsg::Key(s) => {
                // Deltas must be able to build on it.
                if !delta::valid(&s) {
                    return Err(Gap);
                }
                entry.advance(s, now);
                self.gate(ap);
                Some(Change::Snapshot(ap.to_owned()))
            }
            AgentMsg::Delta(d) => {
                let next = delta::apply(entry.snapshot.as_ref().ok_or(Gap)?, &d)?;
                entry.advance(next, now);
                self.gate(ap);
                Some(Change::Snapshot(ap.to_owned()))
            }
            AgentMsg::Event(ev) => {
                if let EventKind::FwCrash { phy } = &ev.kind {
                    *entry.crashes.entry(phy.clone()).or_default() += 1;
                }
                entry.push_event(ev.clone());
                Some(Change::Event(ap.to_owned(), ev))
            }
            AgentMsg::Flows(f) => {
                entry.full.retain(|w| !w.is_closed());
                // The whole table goes to those who asked for it; the UI's
                // view keeps to the summaries.
                if !entry.full.is_empty() && lists_everything(&f) {
                    for w in entry.full.drain(..) {
                        let _ = w.send(f.clone());
                    }
                    None
                } else {
                    entry.flows = Some((f, now));
                    self.learn_addresses(ap, now);
                    Some(Change::Flows(ap.to_owned()))
                }
            }
            AgentMsg::Result(r) => {
                self.result(ap, r);
                None
            }
            // Frames go to the watchers apart from the changes: they are
            // not part of the view.
            AgentMsg::Spectrum(f) => {
                if spectrum::RADIOS.contains(&f.radio.as_str()) {
                    let key = format!("{ap}/{}", f.radio);
                    entry
                        .scans
                        .entry(f.radio.clone())
                        .or_default()
                        .frame(&key, &f);
                }
                None
            }
            AgentMsg::SpectrumState {
                radio,
                running,
                reason,
            } => {
                if !spectrum::RADIOS.contains(&radio.as_str()) {
                    return Ok(());
                }
                let scan = entry.scans.entry(radio.clone()).or_default();
                scan.report(running, reason);
                Some(Change::Spectrum(ap.to_owned(), radio))
            }
            AgentMsg::ConfigApplied(c) => {
                self.applied(ap, c);
                None
            }
            // A Pong only proves the agent is alive.
            _ => None,
        };
        if let Some(c) = change {
            self.notify(c);
        }
        Ok(())
    }

    /// Hands a command's result to whoever waits for it. A result of another
    /// AP's command, or of one given up on, is dropped.
    fn result(&mut self, ap: &str, r: CommandResult) {
        if self.pending.get(&r.id).is_none_or(|p| p.ap != ap) {
            return;
        }
        let Some(Pending { waiter, .. }) = self.pending.remove(&r.id) else {
            return;
        };
        match waiter {
            Waiter::Reply(tx) => {
                let _ = tx.send(r);
            }
            Waiter::Resent if r.ok => {}
            Waiter::Resent => {
                eprintln!(
                    "u6e-controller: {ap}: the policy's blocks failed: {}",
                    r.detail
                );
            }
        }
    }

    /// Queues `kind` for the session serving `ap`, its result for `waiter`;
    /// the command's id, or `None` when no session serves the AP or it is
    /// too far behind to take one.
    pub fn command(&mut self, ap: &str, kind: CommandKind, waiter: Waiter) -> Option<u64> {
        let live = self.aps.get(ap)?.session.as_ref()?;
        let id = self.next_command + 1;
        let msg = CtlMsg::Command(Command { id, kind });
        live.outbox.try_send(msg).ok()?;
        self.next_command = id;
        let ap = ap.to_owned();
        self.pending.insert(id, Pending { ap, waiter });
        Some(id)
    }

    /// Forgets command `id`, whose waiter gave up on it.
    pub fn forget(&mut self, id: u64) {
        self.pending.remove(&id);
    }

    /// The command that makes a reconnected AP's blocks the policy's, for
    /// its session `id` to send: all of them at once, so that a client
    /// unblocked while the AP could not be told is let on there too.
    pub fn sync_blocks(&mut self, ap: &str, id: u64) -> Option<CtlMsg> {
        self.live(ap, id)?;
        self.next_command += 1;
        let macs = self.blocked.iter().copied().collect();
        let cmd = Command {
            id: self.next_command,
            kind: CommandKind::SyncBlocks { macs },
        };
        let pending = Pending {
            ap: ap.to_owned(),
            waiter: Waiter::Resent,
        };
        self.pending.insert(cmd.id, pending);
        Some(CtlMsg::Command(cmd))
    }

    /// The APs a session serves.
    pub fn connected(&self) -> Vec<String> {
        let up = self.aps.iter().filter(|(_, a)| a.is_up());
        up.map(|(n, _)| n.clone()).collect()
    }

    /// A request for the whole flow table of `ap`, answered by the agent's
    /// next table that lists every connection. A request while one is out
    /// waits for the same answer; otherwise the agent is asked, at most once
    /// per [`FULL_INTERVAL`].
    pub fn want_full(&mut self, ap: &str, now: Instant) -> Result<oneshot::Receiver<Flows>, Full> {
        let entry = self.aps.get_mut(ap).ok_or(Full::NotConnected)?;
        let live = entry.session.as_ref().ok_or(Full::NotConnected)?;
        entry.full.retain(|w| !w.is_closed());
        if entry.full.is_empty() {
            let since = entry.full_asked.map(|t| now.saturating_duration_since(t));
            let left = since.and_then(|s| FULL_INTERVAL.checked_sub(s));
            if let Some(left) = left.filter(|l| !l.is_zero()) {
                return Err(Full::TooSoon(left));
            }
            let ask = CtlMsg::WantFlows { full: true };
            live.outbox.try_send(ask).map_err(|_| Full::NotConnected)?;
            entry.full_asked = Some(now);
        }
        let (tx, rx) = oneshot::channel();
        entry.full.push(tx);
        Ok(rx)
    }

    /// Records an action, for the events and the journal.
    pub fn record(&mut self, action: Action) {
        let on = action.ap.as_deref().map(|ap| format!(" on {ap}"));
        let client = action.mac.map(|m| format!(" {}", mac::format(m)));
        eprintln!(
            "u6e-controller: {} {}{}{}: {}: {}",
            action.user.as_deref().unwrap_or("(no user)"),
            action.action,
            client.unwrap_or_default(),
            on.unwrap_or_default(),
            if action.ok { "ok" } else { "failed" },
            action.detail
        );
        if self.actions.len() == ACTIONS_CAP {
            self.actions.pop_front();
        }
        self.actions.push_back(action.clone());
        self.notify(Change::Action(action));
    }

    /// Records one of the runner's actions (or an admin's request of one) on
    /// `ap`.
    fn record_deploy(
        &mut self,
        action: &'static str,
        ap: &str,
        user: Option<String>,
        ok: bool,
        detail: String,
    ) {
        self.record(Action {
            at: SystemTime::now(),
            user,
            action,
            mac: None,
            ap: Some(ap.to_owned()),
            ok,
            detail,
        });
    }

    /// Hands the runner's link to a new connection, which said it runs
    /// `version`; a connection already serving it is told to stop. The
    /// re-pushes asked for while no runner was connected go first.
    pub fn runner_connect(&mut self, version: String) -> RunnerRegistration {
        self.next_id += 1;
        let id = self.next_id;
        let (stop_tx, stop) = oneshot::channel();
        let (outbox_tx, outbox) = mpsc::channel(OUTBOX_CAP);
        for ap in self.aps.values_mut().filter(|a| a.repush_due) {
            if let Some(msg) = ap.repush() {
                ap.repush_due = outbox_tx.try_send(msg).is_err();
            }
        }
        self.runner.session = Some(RunnerLive {
            id,
            _stop: stop_tx,
            outbox: outbox_tx,
        });
        self.runner.version = Some(version);
        self.runner.connected_since = Some(SystemTime::now());
        self.notify(Change::Deploy);
        RunnerRegistration { id, outbox, stop }
    }

    /// Ends the runner's session `id`; a no-op when a newer one took over.
    pub fn runner_disconnect(&mut self, id: u64) {
        if self.runner.session.as_ref().is_some_and(|s| s.id == id) {
            self.runner.session = None;
            self.runner.connected_since = None;
            self.notify(Change::Deploy);
        }
    }

    /// Queues `msg` for the runner; false when none is connected or it is too
    /// far behind.
    fn to_runner(&self, msg: RunnerCtlMsg) -> bool {
        let live = self.runner.session.as_ref();
        live.is_some_and(|s| s.outbox.try_send(msg).is_ok())
    }

    /// Relays `config`, the runner's request `id`, to the AP it is signed for:
    /// the one whose agent says it is `config.ap`. Only its hash and sequence
    /// stay here; the text goes to the AP's session and nowhere else. `Err`
    /// is the runner's answer when it cannot go, which is recorded.
    pub fn relay(&mut self, id: u64, config: SignedConfig) -> Result<(), ConfigApplied> {
        let ap = config.ap.clone();
        let sent = self.send_config(id, config);
        if let Err(answer) = &sent {
            *self.apply_counts.entry("failed").or_default() += 1;
            self.record_deploy("apply", &ap, None, false, answer.detail.clone());
        }
        sent
    }

    fn send_config(&mut self, id: u64, config: SignedConfig) -> Result<(), ConfigApplied> {
        let sha256 = config.sha256;
        let signed = ConfigId {
            sha256,
            seq: config.seq,
        };
        let found = self.aps.iter_mut().find(|(_, a)| {
            let hello = a.hello.as_ref();
            hello.is_some_and(|h| h.ap == config.ap)
        });
        let Some((name, entry)) = found else {
            let why = format!("no AP named {:.64} has connected", config.ap);
            return Err(not_applied(sha256, why));
        };
        let name = name.clone();
        let Some(live) = &entry.session else {
            return Err(not_applied(sha256, format!("{name} is not connected")));
        };
        if entry.relay.is_some() {
            let why = format!("a configuration for {name} is on its way already");
            return Err(not_applied(sha256, why));
        }
        if live.outbox.try_send(CtlMsg::ApplyConfig(config)).is_err() {
            return Err(not_applied(sha256, format!("{name} is not keeping up")));
        }
        entry.relay = Some(Relay {
            id,
            config: signed,
            since: Instant::now(),
        });
        entry.wanted = Some(signed);
        self.notify(Change::Deploy);
        Ok(())
    }

    /// The AP's answer to a configuration: the runner's, recorded, and when it
    /// applied, the one the AP acknowledged. An answer that comes after the
    /// relay was given up on still says what the AP runs.
    fn applied(&mut self, ap: &str, c: ConfigApplied) {
        let Some(entry) = self.aps.get_mut(ap) else {
            return;
        };
        let relay = entry.relay.take_if(|r| r.config.sha256 == c.sha256);
        let wanted = entry.wanted.filter(|w| w.sha256 == c.sha256);
        let config = relay.as_ref().map(|r| r.config).or(wanted);
        if c.ok
            && let Some(config) = config
            && entry.acked != Some(config)
        {
            entry.acked = Some(config);
            self.policy_dirty = true;
        }
        entry.last_apply = Some(Applied {
            at: SystemTime::now(),
            result: c.clone(),
        });
        let how: Vec<String> = c
            .radios
            .iter()
            .map(|r| {
                format!(
                    "{} {}",
                    crate::view::band(r.radio),
                    mechanism_name(r.mechanism)
                )
            })
            .collect();
        let detail = format!(
            "{} ({}): {}",
            short(Some(c.sha256)),
            how.join(", "),
            c.detail
        );
        let (ok, result) = (c.ok, if c.ok { "ok" } else { "failed" });
        if let Some(r) = relay {
            self.to_runner(RunnerCtlMsg::ConfigApplied {
                id: r.id,
                result: c,
            });
        }
        *self.apply_counts.entry(result).or_default() += 1;
        self.record_deploy("apply", ap, None, ok, detail);
        self.notify(Change::Deploy);
    }

    /// Gives up on the configurations relayed `wait` or longer ago: the
    /// runner hears no answer came. The AP may still apply one; its hash
    /// then says so.
    pub fn expire_relays(&mut self, now: Instant, wait: Duration) {
        let mut expired = Vec::new();
        for (name, a) in &mut self.aps {
            if let Some(r) = a
                .relay
                .take_if(|r| now.saturating_duration_since(r.since) >= wait)
            {
                expired.push((name.clone(), r));
            }
        }
        for (name, r) in expired {
            let why = format!("no answer from {name} in {wait:?}");
            let answer = not_applied(r.config.sha256, why.clone());
            self.to_runner(RunnerCtlMsg::ConfigApplied {
                id: r.id,
                result: answer,
            });
            *self.apply_counts.entry("timeout").or_default() += 1;
            self.record_deploy("apply", &name, None, false, why);
        }
    }

    /// At the first key frame of session `id`, and when a rollout of the AP
    /// ends: whether the AP runs the configuration it last acknowledged. If not, the runner is asked to
    /// sign that one again (now, or once it is connected), unless the AP's
    /// image was built after it was signed: then the image's own is the
    /// newer, and stands.
    pub fn check_installed(&mut self, ap: &str, id: u64) {
        let Some(entry) = self.live(ap, id) else {
            return;
        };
        if !entry.drifts() || entry.relay.is_some() {
            return;
        }
        let (Some(acked), Some(hello)) = (entry.acked, &entry.hello) else {
            return;
        };
        let installed = entry.installed();
        if hello.built_ms() >= acked.seq {
            entry.acked = None;
            self.policy_dirty = true;
            let detail = format!(
                "its image was built after the configuration it acknowledged ({}), so the \
                 image's own ({}) stands",
                short(Some(acked.sha256)),
                short(installed)
            );
            self.record_deploy("repush", ap, None, true, detail);
            return;
        }
        let msg = entry.repush();
        let sent = msg.is_some_and(|m| self.to_runner(m));
        let detail = format!(
            "runs {}, not the acknowledged {}: {}",
            short(installed),
            short(Some(acked.sha256)),
            if sent {
                "the runner is asked to sign it again"
            } else {
                "the runner is asked once it is connected"
            }
        );
        if let Some(entry) = self.aps.get_mut(ap) {
            entry.repush_due = !sent;
        }
        self.record_deploy("repush", ap, None, true, detail);
    }

    /// An admin's rollout of `image_id` to `ap`: refused here when it could
    /// not start (the runner then never hears of it), else queued for the
    /// runner, which may still refuse it.
    pub fn upgrade(&mut self, ap: &str, image_id: &str, user: &str) -> Result<u64, String> {
        if !self.runner.is_up() {
            return Err("the deploy runner is not connected".into());
        }
        let entry = self.aps.get(ap).ok_or_else(|| format!("no AP {ap}"))?;
        let Some(current) = entry
            .hello
            .as_ref()
            .map(Hello::image)
            .filter(|i| !i.is_empty())
        else {
            return Err(format!(
                "what {ap} runs is not known, so it could not be rolled back"
            ));
        };
        if current == image_id {
            return Err(format!("{ap} runs {image_id} already"));
        }
        self.close_stale(SystemTime::now());
        if let Some(r) = self.rollouts.iter().find(|r| r.is_open()) {
            return Err(format!(
                "the rollout of {} to {} is not over",
                r.image_id, r.ap
            ));
        }
        let id = self.start_rollout(ap, image_id, user)?;
        self.record_deploy(
            "upgrade",
            ap,
            Some(user.to_owned()),
            true,
            format!("{image_id} asked"),
        );
        Ok(id)
    }

    /// A rollout a local caller asked the runner for: queued as the runner's
    /// to judge, which refuses what the controller would have.
    pub fn rollout_ask(&mut self, ap: &str, image_id: &str, user: &str) {
        if self.aps.contains_key(ap) && self.start_rollout(ap, image_id, user).is_ok() {
            let detail = format!("{image_id} asked through the runner");
            self.record_deploy("upgrade", ap, Some(user.to_owned()), true, detail);
        } else {
            let detail = format!("{image_id} asked through the runner: no such AP, or no runner");
            self.record_deploy("upgrade", ap, Some(user.to_owned()), false, detail);
        }
    }

    /// Closes the rollouts the runner has not ended in [`ROLLOUT_STALE`]: a
    /// runner restarted meanwhile forgot them, and they would hold up every
    /// other.
    fn close_stale(&mut self, now: SystemTime) {
        let stale = |r: &Rollout| now.duration_since(r.at).is_ok_and(|d| d >= ROLLOUT_STALE);
        let ids: Vec<u64> = self
            .rollouts
            .iter()
            .filter(|r| r.is_open() && stale(r))
            .map(|r| r.id)
            .collect();
        for id in ids {
            let detail = format!("no result from the runner in {ROLLOUT_STALE:?}");
            self.rollout_result(RolloutResult {
                id,
                outcome: RolloutOutcome::Failed,
                detail,
            });
        }
    }

    /// Records a rollout and sends it to the runner; its id.
    fn start_rollout(&mut self, ap: &str, image_id: &str, user: &str) -> Result<u64, String> {
        let entry = &self.aps[ap];
        let previous = entry.hello.as_ref().map_or("", Hello::image).to_owned();
        let snap = entry.snapshot.as_ref();
        let radios = snap.map_or(0, |s| s.radios.iter().filter(|r| r.up).count());
        let clients = snap.map_or(0, |s| s.stations.len());
        let id = self.next_rollout + 1;
        let request = RolloutRequest {
            id,
            ap: ap.to_owned(),
            image_id: image_id.to_owned(),
            previous: previous.clone(),
            user: user.to_owned(),
        };
        if !self.to_runner(RunnerCtlMsg::Rollout(request)) {
            return Err("the deploy runner is not connected".into());
        }
        self.next_rollout = id;
        if self.rollouts.len() == ROLLOUTS_CAP {
            self.rollouts.pop_front();
        }
        self.rollouts.push_back(Rollout {
            id,
            ap: ap.to_owned(),
            image_id: image_id.to_owned(),
            previous,
            user: user.to_owned(),
            at: SystemTime::now(),
            after: self.next_id,
            radios,
            clients,
            gate: None,
            result: None,
            log: VecDeque::new(),
        });
        self.notify(Change::Deploy);
        Ok(id)
    }

    /// A line of rollout `id`'s log, from the runner.
    pub fn rollout_log(&mut self, id: u64, line: String) {
        let Some(r) = self.rollouts.iter_mut().find(|r| r.id == id) else {
            return;
        };
        if r.log.len() == ROLLOUT_LOG_CAP {
            r.log.pop_front();
        }
        r.log.push_back(line);
        self.notify(Change::Deploy);
    }

    /// The runner's last word on a rollout.
    pub fn rollout_result(&mut self, res: RolloutResult) {
        let Some(r) = self
            .rollouts
            .iter_mut()
            .find(|r| r.id == res.id && r.is_open())
        else {
            return;
        };
        r.result = Some((res.outcome, res.detail.clone()));
        let (ap, user, image) = (r.ap.clone(), r.user.clone(), r.image_id.clone());
        let outcome = outcome_name(res.outcome);
        *self.rollout_counts.entry(outcome).or_default() += 1;
        let ok = res.outcome == RolloutOutcome::Done;
        let detail = format!("{image}: {}: {}", outcome.replace('_', " "), res.detail);
        self.record_deploy("rollout", &ap, Some(user), ok, detail);
        self.notify(Change::Deploy);
        // The runner signs nothing for an AP under rollout, so an AP that
        // came back during it is checked again now that it is over.
        let session = self.aps.get(&ap).and_then(|a| a.session.as_ref());
        if let Some(id) = session.map(|s| s.id) {
            self.check_installed(&ap, id);
        }
    }

    /// The open rollout of `ap` whose gate has not spoken yet, if any.
    fn gating(&mut self, ap: &str) -> Option<&mut Rollout> {
        let r = self
            .rollouts
            .iter_mut()
            .rev()
            .find(|r| r.ap == ap && r.is_open())?;
        r.gate.is_none().then_some(r)
    }

    /// The health gate of the open rollout of `ap`, after a snapshot: healthy
    /// once a session newer than the request runs the image with as many
    /// radios up as before (at least one) and, if it had clients then, some
    /// again.
    fn gate(&mut self, ap: &str) {
        let Some(entry) = self.aps.get(ap) else {
            return;
        };
        let (Some(live), Some(hello), Some(snap)) = (&entry.session, &entry.hello, &entry.snapshot)
        else {
            return;
        };
        let (session, image) = (live.id, hello.image().to_owned());
        let up = snap.radios.iter().filter(|r| r.up).count();
        let all_up = snap.radios.iter().all(|r| r.up);
        let clients = snap.stations.len();
        let Some(r) = self.gating(ap) else {
            return;
        };
        if session <= r.after
            || image != r.image_id
            || !all_up
            || up < r.radios.max(1)
            || (r.clients > 0 && clients == 0)
        {
            return;
        }
        let detail = format!("back with {image}: {up} radios up, {clients} clients");
        r.gate = Some((true, detail.clone()));
        let id = r.id;
        self.to_runner(RunnerCtlMsg::RolloutGate {
            id,
            healthy: true,
            detail,
        });
        self.notify(Change::Deploy);
    }

    /// Fails the gate of the open rollout of `ap`, which cannot pass: `why`.
    fn gate_fails(&mut self, ap: &str, why: String) {
        let Some(r) = self.gating(ap) else {
            return;
        };
        r.gate = Some((false, why.clone()));
        let id = r.id;
        self.to_runner(RunnerCtlMsg::RolloutGate {
            id,
            healthy: false,
            detail: why,
        });
        self.notify(Change::Deploy);
    }

    /// Takes the addresses the flows of `ap` show its clients at.
    fn learn_addresses(&mut self, ap: &str, now: SystemTime) {
        let Some((flows, _)) = self.aps.get(ap).and_then(|a| a.flows.as_ref()) else {
            return;
        };
        let learnt: Vec<_> = flows
            .clients
            .iter()
            .map(|c| (c.mac, names::addresses(&c.top)))
            .filter(|(_, ips)| !ips.is_empty())
            .collect();
        for (mac, ips) in learnt {
            self.addresses.insert(mac, Addresses { ips, at: now });
        }
        let kept = |a: &Addresses| now.duration_since(a.at).is_ok_and(|d| d < ADDRESSES_KEPT);
        self.addresses.retain(|_, a| kept(a));
    }

    /// The addresses of the clients to look up now, marked as in flight.
    pub fn names_due(&mut self, now: Instant) -> Vec<IpAddr> {
        self.names.prune(now);
        let wanted = self.addresses.values().flat_map(|a| a.ips.iter().copied());
        self.names.due(wanted, now)
    }

    /// Takes the answer of a lookup of `ip`.
    pub fn named(&mut self, ip: IpAddr, name: Option<String>, now: Instant) {
        if self.names.answer(ip, name, now) {
            self.notify(Change::Names);
        }
    }

    /// The client's name: that of the first of its addresses that has one.
    pub fn name_of(&self, mac: &[u8; 6]) -> Option<&str> {
        let ips = &self.addresses.get(mac)?.ips;
        ips.iter().find_map(|ip| self.names.get(ip))
    }

    /// Every associated client, sorted by MAC. A MAC in two snapshots (a roam
    /// the old AP has not reported yet) is listed once, where it was heard
    /// last: the snapshot's time less the station's inactive time.
    pub fn clients(&self) -> Vec<ClientView> {
        let mut by_mac: BTreeMap<[u8; 6], ClientView> = BTreeMap::new();
        for (name, ap) in &self.aps {
            let (Some(snap), Some(at)) = (&ap.snapshot, ap.snapshot_at) else {
                continue;
            };
            for st in &snap.stations {
                let idle = Duration::from_millis(u64::from(st.inactive_ms));
                let seen = at.checked_sub(idle).unwrap_or(SystemTime::UNIX_EPOCH);
                if by_mac.get(&st.mac).is_some_and(|c| c.last_seen >= seen) {
                    continue;
                }
                // A valid snapshot has every station on a BSS of its list.
                let Some(bss) = snap.bsss.get(usize::from(st.bss)) else {
                    continue;
                };
                let view = ClientView {
                    ap: name.clone(),
                    bss: bss.ifname.clone(),
                    ssid: bss.ssid.clone(),
                    station: st.clone(),
                    last_seen: seen,
                };
                by_mac.insert(st.mac, view);
            }
        }
        by_mac.into_values().collect()
    }
}

/// The state as the sessions, the metrics and the UI share it.
#[derive(Clone)]
pub struct Shared(Arc<RwLock<State>>);

impl Shared {
    pub fn new(state: State) -> Self {
        Shared(Arc::new(RwLock::new(state)))
    }

    pub fn read(&self) -> RwLockReadGuard<'_, State> {
        self.0.read().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn write(&self) -> RwLockWriteGuard<'_, State> {
        self.0.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// Counts a watcher of `ap` until the guard is dropped; the first one
    /// moves the AP to the 2 s tick, the last one to leave moves it back.
    pub fn watch(&self, ap: &str) -> Option<WatchGuard> {
        self.watching(ap, false)
    }

    /// Counts a watcher of the flows of `ap` likewise: the first one moves
    /// the AP to the 10 s flow cadence, the last one back to the minute.
    pub fn watch_flows(&self, ap: &str) -> Option<WatchGuard> {
        self.watching(ap, true)
    }

    fn watching(&self, ap: &str, flows: bool) -> Option<WatchGuard> {
        let mut state = self.write();
        let entry = state.aps.get_mut(ap)?;
        entry.watched(flows, true);
        Some(WatchGuard {
            shared: self.clone(),
            ap: ap.to_owned(),
            flows,
        })
    }
}

/// One watcher of an AP or its flows; see [`Shared::watch`].
pub struct WatchGuard {
    shared: Shared,
    ap: String,
    flows: bool,
}

impl Drop for WatchGuard {
    fn drop(&mut self) {
        let mut state = self.shared.write();
        if let Some(entry) = state.aps.get_mut(&self.ap) {
            entry.watched(self.flows, false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use u6e_proto::msg::{Bss, FieldDelta, RateMode, SnapshotDelta};

    fn hello(ap: &str) -> Hello {
        Hello {
            ap: ap.into(),
            manifest: String::new(),
            kernel: String::new(),
            hostapd: String::new(),
            agent: String::new(),
        }
    }

    fn station(last: u8, bss: u16, inactive_ms: u32) -> Station {
        Station {
            mac: [2, 0, 0, 0, 0, last],
            bss,
            signal: -50,
            signal_avg: -50,
            rx_bytes: 0,
            tx_bytes: 0,
            rx_packets: 0,
            tx_packets: 0,
            tx_retries: 0,
            tx_failed: 0,
            tx_rate_kbps: 0,
            rx_rate_kbps: 0,
            tx_mcs: 0,
            rx_mcs: 0,
            tx_mode: RateMode::Legacy,
            rx_mode: RateMode::Legacy,
            tx_nss: 0,
            rx_nss: 0,
            tx_airtime_us: 0,
            rx_airtime_us: 0,
            inactive_ms,
            connected_s: 0,
            vlan: 0,
        }
    }

    fn snap(seq: u64, stations: Vec<Station>) -> Snapshot {
        Snapshot {
            seq,
            uptime_s: 0,
            load_milli: 0,
            mem_avail_kb: 0,
            nss_load_pct: 0,
            temps: Vec::new(),
            radios: Vec::new(),
            bsss: vec![Bss {
                ifname: "wlan0".into(),
                bssid: [2, 0, 0, 0, 1, 0],
                ssid: "Guest".into(),
                phy: "phy0".into(),
                vlan: 0,
            }],
            stations,
            config_sha256: None,
        }
    }

    fn delta(seq: u64, base: u64) -> SnapshotDelta {
        SnapshotDelta {
            seq,
            base,
            scalars: FieldDelta::default(),
            radios: Vec::new(),
            stations: Vec::new(),
            removed: Vec::new(),
            added: Vec::new(),
            bsss: None,
        }
    }

    fn state(names: &[&str]) -> State {
        State::new(names.iter().map(|n| n.to_string()))
    }

    #[test]
    fn delta_applies_only_to_its_base() {
        let mut s = state(&["ap1"]);
        let id = s.connect("ap1", hello("ap1")).unwrap().id;
        assert_eq!(s.apply("ap1", id, AgentMsg::Delta(delta(2, 1))), Err(Gap));
        assert_eq!(s.ap("ap1").unwrap().snapshot, None);
        s.apply("ap1", id, AgentMsg::Key(snap(1, Vec::new())))
            .unwrap();
        assert_eq!(s.apply("ap1", id, AgentMsg::Delta(delta(5, 4))), Err(Gap));
        assert_eq!(s.ap("ap1").unwrap().snapshot.as_ref().unwrap().seq, 1);
        s.apply("ap1", id, AgentMsg::Delta(delta(2, 1))).unwrap();
        assert_eq!(s.ap("ap1").unwrap().snapshot.as_ref().unwrap().seq, 2);
    }

    #[test]
    fn the_previous_snapshot_is_kept_for_the_session() {
        let mut s = state(&["ap1"]);
        let id = s.connect("ap1", hello("ap1")).unwrap().id;
        let seq = |s: &State| {
            let ap = s.ap("ap1").unwrap();
            let prev = ap.previous.as_ref().map(|(p, _)| p.seq);
            (ap.snapshot.as_ref().map(|s| s.seq), prev)
        };
        s.apply("ap1", id, AgentMsg::Key(snap(1, Vec::new())))
            .unwrap();
        assert_eq!(seq(&s), (Some(1), None));
        s.apply("ap1", id, AgentMsg::Delta(delta(2, 1))).unwrap();
        assert_eq!(seq(&s), (Some(2), Some(1)));
        s.apply("ap1", id, AgentMsg::Key(snap(3, Vec::new())))
            .unwrap();
        assert_eq!(seq(&s), (Some(3), Some(2)));
        let id = s.connect("ap1", hello("ap1")).unwrap().id;
        assert_eq!(seq(&s), (None, None));
        s.apply("ap1", id, AgentMsg::Key(snap(1, Vec::new())))
            .unwrap();
        assert_eq!(seq(&s), (Some(1), None));
    }

    #[test]
    fn reconnect_forgets_the_old_snapshot() {
        let mut s = state(&["ap1"]);
        let old = s.connect("ap1", hello("ap1")).unwrap();
        s.apply("ap1", old.id, AgentMsg::Key(snap(1, Vec::new())))
            .unwrap();
        let mut new = s.connect("ap1", hello("ap1")).unwrap();
        // The new connection's seq 2 is not the old connection's.
        assert_eq!(
            s.apply("ap1", new.id, AgentMsg::Delta(delta(2, 1))),
            Err(Gap)
        );
        // The old session is told to stop and can no longer write.
        let mut stop = old.stop;
        assert!(matches!(
            stop.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        assert!(matches!(
            new.stop.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        s.apply("ap1", old.id, AgentMsg::Key(snap(9, Vec::new())))
            .unwrap();
        s.disconnect("ap1", old.id);
        assert!(s.ap("ap1").unwrap().is_up());
        assert_eq!(s.ap("ap1").unwrap().snapshot, None);
        s.disconnect("ap1", new.id);
        assert!(!s.ap("ap1").unwrap().is_up());
        assert_eq!(s.ap("ap1").unwrap().hello, Some(hello("ap1")));
    }

    #[test]
    fn events_keep_the_newest_thousand_and_count_crashes() {
        let mut s = state(&["ap1"]);
        let id = s.connect("ap1", hello("ap1")).unwrap().id;
        for at_ms in 0..1005 {
            let kind = EventKind::FwCrash { phy: "phy1".into() };
            s.apply("ap1", id, AgentMsg::Event(Event { at_ms, kind }))
                .unwrap();
        }
        let ap = s.ap("ap1").unwrap();
        assert_eq!(ap.events.len(), EVENTS_CAP);
        assert_eq!(ap.events.front().unwrap().at_ms, 5);
        assert_eq!(ap.crashes["phy1"], 1005);
    }

    #[test]
    fn clients_dedup_by_last_heard() {
        let mut s = state(&["ap1", "ap2"]);
        let a = s.connect("ap1", hello("ap1")).unwrap().id;
        let b = s.connect("ap2", hello("ap2")).unwrap().id;
        // ap2 reports first, but the client went quiet there 10 s ago.
        let quiet = vec![station(1, 0, 10_000), station(2, 0, 0)];
        s.apply("ap2", b, AgentMsg::Key(snap(1, quiet))).unwrap();
        s.apply("ap1", a, AgentMsg::Key(snap(1, vec![station(1, 0, 0)])))
            .unwrap();
        let c = s.clients();
        let seen: Vec<_> = c
            .iter()
            .map(|c| (c.station.mac[5], c.ap.as_str()))
            .collect();
        assert_eq!(seen, [(1, "ap1"), (2, "ap2")]);
        assert_eq!((c[0].bss.as_str(), c[0].ssid.as_str()), ("wlan0", "Guest"));
    }

    #[test]
    fn invalid_key_frame_is_refused() {
        let mut s = state(&["ap1"]);
        let id = s.connect("ap1", hello("ap1")).unwrap().id;
        s.apply("ap1", id, AgentMsg::Key(snap(1, vec![station(1, 0, 0)])))
            .unwrap();
        let unsorted = vec![station(2, 0, 0), station(1, 0, 0)];
        let duplicate = vec![station(1, 0, 0), station(1, 0, 0)];
        let off_the_list = vec![station(1, 7, 0)];
        for stations in [unsorted, duplicate, off_the_list] {
            assert_eq!(
                s.apply("ap1", id, AgentMsg::Key(snap(2, stations))),
                Err(Gap)
            );
            assert_eq!(s.ap("ap1").unwrap().snapshot.as_ref().unwrap().seq, 1);
        }
    }

    #[test]
    fn changes_are_broadcast() {
        let mut s = state(&["ap1"]);
        let mut rx = s.subscribe();
        let id = s.connect("ap1", hello("ap1")).unwrap().id;
        s.apply("ap1", id, AgentMsg::Key(snap(1, Vec::new())))
            .unwrap();
        s.apply("ap1", id, AgentMsg::Pong(1)).unwrap();
        s.disconnect("ap1", id);
        let got: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        let ap1 = || "ap1".to_owned();
        assert_eq!(
            got,
            [
                Change::Up(ap1()),
                Change::Snapshot(ap1()),
                Change::Down(ap1())
            ]
        );
    }

    #[test]
    fn a_refused_protocol_is_told_once_per_change() {
        let mut s = state(&["ap1"]);
        let mut rx = s.subscribe();
        let reg = s.connect("ap1", hello("ap1")).unwrap();
        assert_eq!(s.ap("ap1").unwrap().mismatch(), None);
        assert!(s.refuse("ap1", 0));
        // An old agent redials: nothing new to tell.
        assert!(!s.refuse("ap1", 0));
        let mut stop = reg.stop;
        assert!(matches!(
            stop.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        let ap = s.ap("ap1").unwrap();
        assert!(!ap.is_up());
        assert_eq!((ap.mismatch(), &ap.hello), (Some(0), &None));
        assert!(s.refuse("ap1", PROTOCOL + 1));
        s.connect("ap1", hello("ap1")).unwrap();
        assert_eq!(s.ap("ap1").unwrap().mismatch(), None);
        assert!(s.refuse("ap1", PROTOCOL + 1));
        assert!(!s.refuse("ap9", 0));
        let got: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        let (up, down) = (Change::Up("ap1".into()), Change::Down("ap1".into()));
        assert_eq!(got, [up.clone(), down.clone(), down.clone(), up, down]);
    }

    #[test]
    fn watchers_drive_the_tick() {
        let shared = Shared::new(state(&["ap1"]));
        let mut tick = shared.write().connect("ap1", hello("ap1")).unwrap().tick;
        assert_eq!(*tick.borrow(), TICK_IDLE);
        let first = shared.watch("ap1").unwrap();
        assert!(tick.has_changed().unwrap());
        assert_eq!(*tick.borrow_and_update(), TICK_WATCHED);
        let second = shared.watch("ap1").unwrap();
        assert_eq!(shared.read().watchers("ap1"), 2);
        drop(first);
        assert!(!tick.has_changed().unwrap());
        drop(second);
        assert_eq!(*tick.borrow_and_update(), TICK_IDLE);
        assert_eq!(shared.read().watchers("ap1"), 0);
        assert!(shared.watch("ap9").is_none());
    }

    #[test]
    fn flow_watchers_drive_the_cadence_alone() {
        let shared = Shared::new(state(&["ap1"]));
        let reg = shared.write().connect("ap1", hello("ap1")).unwrap();
        let (mut cadence, mut tick) = (reg.cadence, reg.tick);
        assert_eq!(*cadence.borrow(), FLOWS_IDLE);
        let ap = shared.watch("ap1").unwrap();
        assert!(!cadence.has_changed().unwrap());
        let flows = shared.watch_flows("ap1").unwrap();
        assert_eq!(*cadence.borrow_and_update(), FLOWS_WATCHED);
        assert_eq!(*tick.borrow_and_update(), TICK_WATCHED);
        drop(flows);
        assert_eq!(*cadence.borrow_and_update(), FLOWS_IDLE);
        assert!(!tick.has_changed().unwrap());
        drop(ap);
        assert_eq!(*tick.borrow_and_update(), TICK_IDLE);
    }

    fn result(id: u64) -> AgentMsg {
        AgentMsg::Result(CommandResult {
            id,
            ok: true,
            detail: "OK".into(),
        })
    }

    #[test]
    fn a_result_reaches_its_own_waiter_only() {
        let mut s = state(&["ap1", "ap2"]);
        let mut one = s.connect("ap1", hello("ap1")).unwrap();
        let two = s.connect("ap2", hello("ap2")).unwrap().id;
        let mac = [2, 0, 0, 0, 0, 1];
        let (tx, mut rx) = oneshot::channel();
        let id = s
            .command("ap1", CommandKind::Kick { mac }, Waiter::Reply(tx))
            .unwrap();
        let sent = one.outbox.try_recv().unwrap();
        let kind = CommandKind::Kick { mac };
        assert_eq!(sent, CtlMsg::Command(Command { id, kind }));
        // Another AP cannot answer it.
        s.apply("ap2", two, result(id)).unwrap();
        assert!(rx.try_recv().is_err());
        s.apply("ap1", one.id, result(id)).unwrap();
        assert_eq!(rx.try_recv().unwrap().detail, "OK");
        // A command to an AP that goes away is answered by its going.
        let (tx, mut rx) = oneshot::channel();
        s.command("ap1", CommandKind::Kick { mac }, Waiter::Reply(tx))
            .unwrap();
        s.disconnect("ap1", one.id);
        assert!(matches!(
            rx.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        let (tx, _rx) = oneshot::channel();
        assert_eq!(
            s.command("ap1", CommandKind::Kick { mac }, Waiter::Reply(tx)),
            None
        );
    }

    #[test]
    fn the_sync_holds_the_policy_and_goes_to_the_session_only() {
        let mut s = state(&["ap1"]);
        let old = s.connect("ap1", hello("ap1")).unwrap().id;
        let new = s.connect("ap1", hello("ap1")).unwrap().id;
        s.blocked.insert([2, 0, 0, 0, 0, 2]);
        s.blocked.insert([2, 0, 0, 0, 0, 1]);
        assert_eq!(s.sync_blocks("ap1", old), None);
        let Some(CtlMsg::Command(c)) = s.sync_blocks("ap1", new) else {
            panic!("no sync");
        };
        let macs = vec![[2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2]];
        assert_eq!(c.kind, CommandKind::SyncBlocks { macs });
        // Its result is taken without a waiter.
        s.apply("ap1", new, result(c.id)).unwrap();
        assert!(s.pending.is_empty());
    }

    fn flows(seq: u64, conns: u32, listed: usize) -> Flows {
        let flow = u6e_proto::msg::Flow {
            proto: 6,
            src: "192.0.2.10".parse().unwrap(),
            sport: 1,
            dst: "198.51.100.1".parse().unwrap(),
            dport: 2,
            tx_bytes: 0,
            rx_bytes: 0,
            tx_packets: 0,
            rx_packets: 0,
            offloaded: false,
            age_s: 0,
            client_is_src: true,
        };
        Flows {
            seq,
            complete: true,
            clients: vec![u6e_proto::msg::ClientFlows {
                mac: [2, 0, 0, 0, 0, 1],
                conns,
                offloaded: 0,
                tx_bytes: 0,
                rx_bytes: 0,
                tx_packets: 0,
                rx_packets: 0,
                top: vec![flow; listed],
            }],
        }
    }

    #[test]
    fn a_full_table_answers_its_requests_and_is_not_kept() {
        let mut s = state(&["ap1"]);
        let mut reg = s.connect("ap1", hello("ap1")).unwrap();
        let seq = |s: &State| s.ap("ap1").unwrap().flows.as_ref().map(|(f, _)| f.seq);
        s.apply("ap1", reg.id, AgentMsg::Flows(flows(1, 9, 6)))
            .unwrap();
        let t0 = Instant::now();
        let mut first = s.want_full("ap1", t0).unwrap();
        let mut second = s.want_full("ap1", t0 + Duration::from_secs(1)).unwrap();
        // Asked once for both.
        assert_eq!(
            reg.outbox.try_recv().unwrap(),
            CtlMsg::WantFlows { full: true }
        );
        assert!(reg.outbox.try_recv().is_err());
        // A summary on the way meanwhile is not the answer.
        s.apply("ap1", reg.id, AgentMsg::Flows(flows(2, 9, 6)))
            .unwrap();
        assert_eq!(seq(&s), Some(2));
        assert!(first.try_recv().is_err());
        s.apply("ap1", reg.id, AgentMsg::Flows(flows(3, 9, 9)))
            .unwrap();
        assert_eq!(
            (
                first.try_recv().unwrap().seq,
                second.try_recv().unwrap().seq
            ),
            (3, 3)
        );
        assert_eq!(seq(&s), Some(2));
        // With nobody asking, a table that lists everything is a summary.
        s.apply("ap1", reg.id, AgentMsg::Flows(flows(4, 2, 2)))
            .unwrap();
        assert_eq!(seq(&s), Some(4));

        // The next ask waits out the interval from the last.
        let at = |secs| t0 + Duration::from_secs(secs);
        assert_eq!(
            s.want_full("ap1", at(4)).err(),
            Some(Full::TooSoon(Duration::from_secs(6)))
        );
        assert!(reg.outbox.try_recv().is_err());
        let _third = s.want_full("ap1", at(10)).unwrap();
        assert_eq!(
            reg.outbox.try_recv().unwrap(),
            CtlMsg::WantFlows { full: true }
        );
        assert_eq!(s.want_full("ap9", at(60)).err(), Some(Full::NotConnected));
    }
}
