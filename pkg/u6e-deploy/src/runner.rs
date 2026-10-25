//! The runner's state: what it signed, what waits for an answer, and the
//! rollout under way. It is the one party that originates Wi-Fi
//! configurations and image rollouts, and it holds the key the APs' images
//! pin for configurations, apart from its link key.
//!
//! A configuration is signed under a sequence number that is the signing
//! time in milliseconds (one past the last when the clock has not moved), so
//! it is newer than every image built before it and than every configuration
//! signed before it; the AP refuses any other (`config::replayed`). The last
//! one signed for each AP is kept, in memory only (it holds the site's
//! secrets), so that when the controller sees the AP come back running
//! another than the one it acknowledged, the same one is signed again under a
//! new sequence number (`Repush`): the old signature is a replay to the AP.
//!
//! Rollouts run one at a time (`rollout`), whoever asked: the controller
//! (an admin's Upgrade) or a local caller, whose ask goes through the
//! controller so that every rollout is gated and shown the same way.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::Ed25519KeyPair;
use tokio::sync::{mpsc, oneshot, watch};
use u6e_proto::config::{self, config_sha256};
use u6e_proto::mac;
use u6e_proto::msg::{
    Band, ConfigApplied, Mechanism, RadioConfig, RolloutOutcome, RolloutRequest, RolloutResult,
    RunnerCtlMsg, RunnerMsg,
};

use crate::config::Config;
use crate::local::Reply;
use crate::rollout;
use crate::stage::Helper;

/// Messages queued for the controller: a link down for long holds this
/// many, then drops log lines (never a result).
pub const OUTBOX_CAP: usize = 1024;

/// A configuration sent and not answered yet: whose the answer is.
enum Waiting {
    /// A local caller's.
    Local(oneshot::Sender<ConfigApplied>),
    /// A re-push of the AP of this host name, which only the journal hears.
    Repush(String),
}

/// The rollout under way.
pub(crate) struct Current {
    pub id: u64,
    pub ap: String,
    pub image_id: String,
    /// The controller's gate verdict, once it came: healthy, and what it saw.
    pub gate: watch::Sender<Option<(bool, String)>>,
    /// The local callers following it.
    pub followers: Vec<mpsc::Sender<Reply>>,
}

#[derive(Default)]
struct Inner {
    /// Whether a session with the controller is up.
    connected: bool,
    last_seq: u64,
    next_id: u64,
    /// The last configuration signed for each AP, by host name.
    last: HashMap<String, Vec<RadioConfig>>,
    applies: HashMap<u64, Waiting>,
    rollout: Option<Current>,
    /// Local callers waiting for the controller to hand their rollout of an
    /// AP back, by AP.
    asks: HashMap<String, Vec<mpsc::Sender<Reply>>>,
}

pub struct Runner {
    pub config: Config,
    key: Ed25519KeyPair,
    pub(crate) helper: Helper,
    inner: Mutex<Inner>,
    outbox: mpsc::Sender<RunnerMsg>,
}

/// The name of a band, as the runner's output spells it.
pub fn band(b: Band) -> &'static str {
    match b {
        Band::B24 => "2.4 GHz",
        Band::B5 => "5 GHz",
        Band::B6 => "6 GHz",
    }
}

/// The name of a mechanism, as the runner's output spells it.
pub fn mechanism(m: Mechanism) -> &'static str {
    match m {
        Mechanism::Unchanged => "unchanged",
        Mechanism::InPlace => "set in place",
        Mechanism::ChannelSwitch => "channel switch",
        Mechanism::Power => "power set",
        Mechanism::Restart => "restarted",
    }
}

fn unix_ms() -> u64 {
    let since = SystemTime::now().duration_since(UNIX_EPOCH);
    since.map_or(0, |d| d.as_millis() as u64)
}

impl Runner {
    /// The runner, and the queue of what it sends the controller, which the
    /// link drains.
    pub fn new(config: Config, key: Ed25519KeyPair) -> (Arc<Self>, mpsc::Receiver<RunnerMsg>) {
        let (outbox, rx) = mpsc::channel(OUTBOX_CAP);
        let helper = Helper {
            socket: config.rollout.helper.clone(),
        };
        let runner = Runner {
            config,
            key,
            helper,
            inner: Mutex::new(Inner::default()),
            outbox,
        };
        (Arc::new(runner), rx)
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn set_connected(&self, up: bool) {
        self.lock().connected = up;
    }

    pub fn is_connected(&self) -> bool {
        self.lock().connected
    }

    fn next_id(inner: &mut Inner) -> u64 {
        inner.next_id += 1;
        inner.next_id
    }

    /// Signs `radios` for the AP of `hostname` under the next sequence
    /// number, keeps them as its last, and sends them to the controller as
    /// request `id`, whose answer goes to `waiting`.
    fn send_signed(
        &self,
        inner: &mut Inner,
        hostname: &str,
        radios: Vec<RadioConfig>,
        waiting: Waiting,
    ) -> Result<(), String> {
        inner.last_seq = unix_ms().max(inner.last_seq + 1);
        let config = config::sign(&self.key, hostname, inner.last_seq, radios.clone());
        inner.last.insert(hostname.to_owned(), radios);
        let id = Runner::next_id(inner);
        let (sha256, seq) = (config.sha256, config.seq);
        inner.applies.insert(id, waiting);
        if self
            .outbox
            .try_send(RunnerMsg::ApplyConfig { id, config })
            .is_err()
        {
            inner.applies.remove(&id);
            return Err("the link to the controller is not keeping up".into());
        }
        let ap = self.config.ap_of(hostname).unwrap_or(hostname);
        eprintln!("u6e-deploy: {ap}: signed {} under {seq}", mac::hex(&sha256));
        Ok(())
    }

    /// A local caller's configuration for `ap`, signed and sent; the AP's
    /// answer comes on the receiver.
    pub fn apply(
        &self,
        ap: &str,
        radios: Vec<RadioConfig>,
    ) -> Result<oneshot::Receiver<ConfigApplied>, String> {
        let hostname = self
            .config
            .hostname(ap)
            .ok_or_else(|| format!("no AP {ap:.64} in the configuration"))?;
        let mut inner = self.lock();
        if !inner.connected {
            return Err("no link to the controller".into());
        }
        if inner.rollout.as_ref().is_some_and(|r| r.ap == ap) {
            return Err(format!("{ap} is being rolled out to"));
        }
        let (tx, rx) = oneshot::channel();
        self.send_signed(&mut inner, hostname, radios, Waiting::Local(tx))?;
        Ok(rx)
    }

    /// A local caller's rollout of `image_id` to `ap`, asked of the
    /// controller, which hands it back as its own; the caller hears it on
    /// `follower`.
    pub fn ask(
        &self,
        ap: &str,
        image_id: &str,
        user: String,
        follower: mpsc::Sender<Reply>,
    ) -> Result<(), String> {
        if self.config.hostname(ap).is_none() {
            return Err(format!("no AP {ap:.64} in the configuration"));
        }
        let mut inner = self.lock();
        if !inner.connected {
            return Err("no link to the controller".into());
        }
        let ask = RunnerMsg::RolloutAsk {
            ap: ap.into(),
            image_id: image_id.into(),
            user,
        };
        self.outbox
            .try_send(ask)
            .map_err(|_| "the link to the controller is not keeping up".to_owned())?;
        inner.asks.entry(ap.to_owned()).or_default().push(follower);
        Ok(())
    }

    /// Takes one message of the controller's; what to answer it with at once.
    pub fn handle(self: &Arc<Self>, msg: RunnerCtlMsg) -> Option<RunnerMsg> {
        match msg {
            RunnerCtlMsg::Ping(n) => return Some(RunnerMsg::Pong(n)),
            RunnerCtlMsg::ConfigApplied { id, result } => self.applied(id, result),
            RunnerCtlMsg::Repush {
                ap,
                acked,
                installed,
            } => self.repush(&ap, acked, installed),
            RunnerCtlMsg::Rollout(req) => self.start(req),
            RunnerCtlMsg::RolloutGate {
                id,
                healthy,
                detail,
            } => {
                if let Some(r) = self.lock().rollout.as_ref().filter(|r| r.id == id) {
                    r.gate.send_replace(Some((healthy, detail)));
                }
            }
            // A message of a newer protocol's would not have been decoded.
            _ => {}
        }
        None
    }

    fn applied(&self, id: u64, result: ConfigApplied) {
        match self.lock().applies.remove(&id) {
            Some(Waiting::Local(tx)) => {
                let _ = tx.send(result);
            }
            Some(Waiting::Repush(ap)) => {
                let how = if result.ok { "applied" } else { "not applied" };
                eprintln!(
                    "u6e-deploy: {ap}: the configuration signed again: {how}: {}",
                    result.detail
                );
            }
            None => {}
        }
    }

    /// The controller saw the AP of `hostname` come back running `installed`,
    /// not `acked`: the last configuration signed for it is signed again, if
    /// it is the acknowledged one.
    fn repush(&self, hostname: &str, acked: Option<[u8; 32]>, installed: Option<[u8; 32]>) {
        let mut inner = self.lock();
        let ap = self.config.ap_of(hostname).unwrap_or(hostname).to_owned();
        let skip = |why: String| eprintln!("u6e-deploy: {ap}: not signed again: {why}");
        let Some(radios) = inner.last.get(hostname) else {
            return skip("nothing was signed for it since this runner started".into());
        };
        let sha256 = config_sha256(radios);
        if acked != Some(sha256) {
            return skip(format!(
                "the last configuration signed for it ({}) is not the one it acknowledged",
                mac::hex(&sha256)
            ));
        }
        if installed == Some(sha256) {
            return skip("it runs it".into());
        }
        if inner.rollout.as_ref().is_some_and(|r| r.ap == ap) {
            return skip("it is being rolled out to".into());
        }
        let radios = radios.clone();
        eprintln!(
            "u6e-deploy: {ap}: runs {}, not the acknowledged {}: signing it again",
            installed.map_or_else(|| "none".into(), |h| mac::hex(&h)),
            mac::hex(&sha256),
        );
        let waiting = Waiting::Repush(hostname.to_owned());
        if let Err(why) = self.send_signed(&mut inner, hostname, radios, waiting) {
            skip(why);
        }
    }

    /// A rollout the controller hands over: refused when another runs or it
    /// could not be rolled back, else run.
    fn start(self: &Arc<Self>, req: RolloutRequest) {
        let mut inner = self.lock();
        let followers = inner.asks.remove(&req.ap).unwrap_or_default();
        let refusal = if let Some(r) = &inner.rollout {
            Some(format!(
                "the rollout of {} to {} is not over",
                r.image_id, r.ap
            ))
        } else if self.config.hostname(&req.ap).is_none() {
            Some(format!("no AP {:.64} in the configuration", req.ap))
        } else if req.previous.is_empty() {
            Some(format!(
                "what {} runs is not known, so it could not be rolled back",
                req.ap
            ))
        } else if req.image_id == req.previous {
            Some(format!("{} runs {} already", req.ap, req.image_id))
        } else {
            None
        };
        if let Some(why) = refusal {
            drop(inner);
            let msg = RunnerMsg::RolloutResult(RolloutResult {
                id: req.id,
                outcome: RolloutOutcome::Refused,
                detail: why.clone(),
            });
            eprintln!("u6e-deploy: {}: {} refused: {why}", req.ap, req.image_id);
            let _ = self.outbox.try_send(msg);
            for f in followers {
                let _ = f.try_send(Reply::Done {
                    ok: false,
                    detail: format!("refused: {why}"),
                });
            }
            return;
        }
        let (gate, gate_rx) = watch::channel(None);
        inner.rollout = Some(Current {
            id: req.id,
            ap: req.ap.clone(),
            image_id: req.image_id.clone(),
            gate,
            followers,
        });
        tokio::spawn(rollout::run(Arc::clone(self), req, gate_rx));
    }

    /// A line of the rollout under way's log: to the controller, its
    /// followers and the journal. One a lagging link or follower cannot
    /// take is dropped.
    pub(crate) fn log(&self, id: u64, line: String) {
        let inner = self.lock();
        let Some(r) = inner.rollout.as_ref().filter(|r| r.id == id) else {
            return;
        };
        eprintln!("u6e-deploy: {}: {line}", r.ap);
        for f in &r.followers {
            let _ = f.try_send(Reply::Line(line.clone()));
        }
        let _ = self.outbox.try_send(RunnerMsg::RolloutLog { id, line });
    }

    /// Ends the rollout under way: the controller and the followers hear how.
    pub(crate) async fn finish(&self, id: u64, outcome: RolloutOutcome, detail: String) {
        let current = self.lock().rollout.take_if(|r| r.id == id);
        let Some(r) = current else {
            return;
        };
        let word = match outcome {
            RolloutOutcome::Done => "done",
            RolloutOutcome::RolledBack => "rolled back",
            RolloutOutcome::Failed => "failed",
            RolloutOutcome::Refused => "refused",
        };
        eprintln!("u6e-deploy: {}: {}: {word}: {detail}", r.ap, r.image_id);
        let ok = outcome == RolloutOutcome::Done;
        for f in r.followers {
            let _ = f
                .send(Reply::Done {
                    ok,
                    detail: format!("{word}: {detail}"),
                })
                .await;
        }
        let result = RunnerMsg::RolloutResult(RolloutResult {
            id,
            outcome,
            detail,
        });
        // The last word is never dropped: it waits for the link.
        let _ = self.outbox.send(result).await;
    }
}
