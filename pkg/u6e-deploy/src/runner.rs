//! The runner's state: what it signed, what waits for an answer, and the
//! rollout under way. It is the one party that originates Wi-Fi
//! configurations and image rollouts, and it holds the key the APs' images
//! pin for configurations, apart from its link key.
//!
//! A configuration is signed under a sequence number that is the signing
//! time in milliseconds (one past the last when the clock has not moved), so
//! it is newer than every image built before it and than every configuration
//! signed before it; the AP refuses any other (`config::replayed`). The last
//! one each AP applied is kept, in memory only (it holds the site's secrets),
//! so that when the controller sees the AP come back running another than the
//! one it acknowledged, the same one is signed again under a new sequence
//! number (`Repush`): the old signature is a replay to the AP. One the AP
//! refused is not kept, so it never stands in for the one the AP still runs.
//!
//! Rollouts run one at a time (`rollout`), whoever asked: the controller
//! (an admin's Upgrade) or a local caller, whose ask goes through the
//! controller so that every rollout is gated and shown the same way. The
//! controller hands an ask back as a rollout of the same AP, image and user,
//! which is how its caller finds the rollout to follow.

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

/// A configuration sent and not answered yet: the AP's host name, the
/// radios (kept as its last once it applied them), and whose the answer is.
struct Pending {
    hostname: String,
    radios: Vec<RadioConfig>,
    waiting: Waiting,
}

enum Waiting {
    /// A local caller's.
    Local(oneshot::Sender<ConfigApplied>),
    /// A re-push's, which only the journal hears.
    Repush,
}

/// A local caller's rollout, until the controller hands it back.
struct Ask {
    ap: String,
    image_id: String,
    user: String,
    follower: mpsc::Sender<Reply>,
}

/// The rollout under way.
pub(crate) struct Current {
    pub id: u64,
    pub ap: String,
    pub image_id: String,
    /// The controller's gate verdict, once it came: healthy, and what it saw.
    pub gate: watch::Sender<Option<(bool, String)>>,
    /// The local caller following it, when one asked for it.
    pub follower: Option<mpsc::Sender<Reply>>,
}

#[derive(Default)]
struct Inner {
    /// Whether a session with the controller is up.
    connected: bool,
    last_seq: u64,
    next_id: u64,
    /// The last configuration each AP applied, by host name.
    last: HashMap<String, Vec<RadioConfig>>,
    applies: HashMap<u64, Pending>,
    rollout: Option<Current>,
    /// Local callers waiting for the controller to hand their rollout back,
    /// oldest first.
    asks: Vec<Ask>,
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
    /// number and sends them to the controller, the answer to `waiting`.
    fn send_signed(
        &self,
        inner: &mut Inner,
        hostname: &str,
        radios: Vec<RadioConfig>,
        waiting: Waiting,
    ) -> Result<(), String> {
        inner.last_seq = unix_ms().max(inner.last_seq + 1);
        let config = config::sign(&self.key, hostname, inner.last_seq, radios.clone());
        let id = Runner::next_id(inner);
        let (sha256, seq) = (config.sha256, config.seq);
        let pending = Pending {
            hostname: hostname.to_owned(),
            radios,
            waiting,
        };
        inner.applies.insert(id, pending);
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
            user: user.clone(),
        };
        self.outbox
            .try_send(ask)
            .map_err(|_| "the link to the controller is not keeping up".to_owned())?;
        // A caller that stopped waiting follows nothing.
        inner.asks.retain(|a| !a.follower.is_closed());
        inner.asks.push(Ask {
            ap: ap.into(),
            image_id: image_id.into(),
            user,
            follower,
        });
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
        let mut inner = self.lock();
        let Some(Pending {
            hostname,
            radios,
            waiting,
        }) = inner.applies.remove(&id)
        else {
            return;
        };
        if result.ok && result.sha256 == config_sha256(&radios) {
            inner.last.insert(hostname.clone(), radios);
        }
        match waiting {
            Waiting::Local(tx) => {
                let _ = tx.send(result);
            }
            Waiting::Repush => {
                let ap = self.config.ap_of(&hostname).unwrap_or(&hostname);
                let how = if result.ok { "applied" } else { "not applied" };
                eprintln!(
                    "u6e-deploy: {ap}: the configuration signed again: {how}: {}",
                    result.detail
                );
            }
        }
    }

    /// The controller saw the AP of `hostname` come back running `installed`,
    /// not `acked`: the last configuration it applied is signed again, if it
    /// is the acknowledged one.
    fn repush(&self, hostname: &str, acked: Option<[u8; 32]>, installed: Option<[u8; 32]>) {
        let mut inner = self.lock();
        let ap = self.config.ap_of(hostname).unwrap_or(hostname).to_owned();
        let skip = |why: String| eprintln!("u6e-deploy: {ap}: not signed again: {why}");
        let Some(radios) = inner.last.get(hostname) else {
            return skip("it applied nothing this runner signed since it started".into());
        };
        let sha256 = config_sha256(radios);
        if acked != Some(sha256) {
            return skip(format!(
                "the last configuration it applied ({}) is not the one it acknowledged",
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
        if let Err(why) = self.send_signed(&mut inner, hostname, radios, Waiting::Repush) {
            skip(why);
        }
    }

    /// A rollout the controller hands over: refused when another runs or it
    /// could not be rolled back, else run.
    fn start(self: &Arc<Self>, req: RolloutRequest) {
        let mut inner = self.lock();
        let asked = inner
            .asks
            .iter()
            .position(|a| (&a.ap, &a.image_id, &a.user) == (&req.ap, &req.image_id, &req.user));
        let follower = asked.map(|i| inner.asks.remove(i).follower);
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
            if let Some(f) = follower {
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
            follower,
        });
        tokio::spawn(rollout::run(Arc::clone(self), req, gate_rx));
    }

    /// A line of the rollout under way's log: to the controller, its
    /// follower and the journal. One a lagging link or follower cannot take
    /// is dropped.
    pub(crate) fn log(&self, id: u64, line: String) {
        let inner = self.lock();
        let Some(r) = inner.rollout.as_ref().filter(|r| r.id == id) else {
            return;
        };
        eprintln!("u6e-deploy: {}: {line}", r.ap);
        if let Some(f) = &r.follower {
            let _ = f.try_send(Reply::Line(line.clone()));
        }
        let _ = self.outbox.try_send(RunnerMsg::RolloutLog { id, line });
    }

    /// Ends the rollout under way: the controller hears how first, then the
    /// follower, who may ask for the next rollout at once; that ask must not
    /// reach the controller before this result.
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
        let done = Reply::Done {
            ok: outcome == RolloutOutcome::Done,
            detail: format!("{word}: {detail}"),
        };
        let result = RunnerMsg::RolloutResult(RolloutResult {
            id,
            outcome,
            detail,
        });
        // The last word is never dropped: it waits for the link.
        let _ = self.outbox.send(result).await;
        if let Some(f) = r.follower {
            let _ = f.send(done).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;

    use crate::config::tests::text;

    /// Two callers' asks for one AP: each follows the rollout the controller
    /// hands back for it, whichever comes first.
    #[test]
    fn each_caller_follows_the_rollout_it_asked_for() {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let (runner, mut sent) = Runner::new(Config::parse(&text("")).unwrap(), key);
        runner.set_connected(true);
        let (first, mut first_rx) = mpsc::channel(8);
        let (second, mut second_rx) = mpsc::channel(8);
        let user = || "root (local)".to_owned();
        runner.ask("ap1", "img-a-ap1", user(), first).unwrap();
        runner.ask("ap1", "img-b-ap1", user(), second).unwrap();
        assert!(matches!(sent.try_recv(), Ok(RunnerMsg::RolloutAsk { .. })));
        // The second comes back first, and is refused (nothing to roll back
        // to): only its caller hears it.
        runner.handle(RunnerCtlMsg::Rollout(RolloutRequest {
            id: 1,
            ap: "ap1".into(),
            image_id: "img-b-ap1".into(),
            previous: String::new(),
            user: user(),
        }));
        let refused = "refused: what ap1 runs is not known, so it could not be rolled back";
        assert!(
            matches!(second_rx.try_recv(), Ok(Reply::Done { ok: false, detail }) if detail == refused)
        );
        assert!(first_rx.try_recv().is_err());
        assert_eq!(runner.lock().asks.len(), 1);
        assert_eq!(runner.lock().asks[0].image_id, "img-a-ap1");
    }
}
