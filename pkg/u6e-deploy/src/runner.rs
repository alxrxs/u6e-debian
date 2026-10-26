//! The runner's state: what it signed, what waits for an answer, and the
//! rollout under way. It is the one party that originates Wi-Fi
//! configurations and image rollouts, and it holds the key the APs' images
//! pin for configurations, apart from its link key.
//!
//! A configuration is signed under a sequence number that is the signing
//! time in milliseconds (one past the last when the clock has not moved), so
//! it is newer than every image built before it and than every configuration
//! signed before it, and valid for ten minutes (`config::VALIDITY_MS`); the
//! AP refuses any other. The latest one signed for each AP is kept, in the
//! state directory (`store`, its own alone: it holds the site's secrets), and
//! told to the controller as each session starts (`RunnerMsg::Latest`): when
//! the controller sees an AP run another, that one is signed again under a
//! new sequence number (`Repush`), whatever the controller says the AP
//! acknowledged, so it can never have an older one signed again.
//!
//! Rollouts run one at a time (`rollout`), whoever asked: the controller
//! (an admin's Upgrade) or a local caller, whose ask goes through the
//! controller so that every rollout is gated and shown the same way. The
//! controller hands an ask back as a rollout of the same AP, image and user,
//! which is how its caller finds the rollout to follow; one the controller
//! asks for itself may only roll out the AP's newest kept image. The image
//! staged last on each AP is kept, by the runner's rollouts and by the
//! site's own image deploys, which tell it (`staged`, a root caller's), and a
//! failed gate rolls the AP back to it. The rollout under way is kept too, so
//! a restarted runner goes on with it, and told to the controller as taken
//! on, and each result is sent until the controller acknowledges it. A state
//! file the runner cannot read is set aside and told to the controller at
//! each session, until someone removes it.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::Ed25519KeyPair;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
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
use crate::store::{Store, Unreadable};

/// Messages queued for the controller: a link down for long holds this
/// many, then drops log lines (a result is kept on disk until acknowledged).
pub const OUTBOX_CAP: usize = 1024;

/// The files of the state directory.
const IMAGES: &str = "images";
const ROLLOUT: &str = "rollout";
const RESULTS: &str = "results";

fn latest_file(hostname: &str) -> String {
    format!("latest-{hostname}")
}

/// The latest configuration signed for an AP.
#[derive(Serialize, Deserialize)]
struct Latest {
    seq: u64,
    radios: Vec<RadioConfig>,
}

/// A configuration sent and not answered yet: whose answer it is.
enum Waiting {
    /// A local caller's.
    Local(oneshot::Sender<ConfigApplied>),
    /// A re-push's, which only the journal hears.
    Repush(String),
}

/// A local caller's rollout, until the controller hands it back.
struct Ask {
    ap: String,
    image_id: String,
    user: String,
    follower: mpsc::Sender<Reply>,
}

/// A rollout as it outlives the runner: what was asked, and where it got to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct InFlight {
    pub id: u64,
    pub ap: String,
    pub image_id: String,
    /// What a failed gate rolls the AP back to.
    pub previous: String,
    pub user: String,
    /// Asked for by a local caller, who may roll out any kept image.
    pub local: bool,
    pub phase: Phase,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Phase {
    /// Checking the images and taking the kept images' lock.
    Checking,
    Staging,
    /// Staged; the gate's verdict is awaited until `deadline_ms`.
    Gate {
        deadline_ms: u64,
    },
    /// Staging the previous image again, after `why`.
    RollingBack {
        why: String,
    },
}

/// The rollout under way.
pub(crate) struct Current {
    pub id: u64,
    pub ap: String,
    pub image_id: String,
    /// What a failed gate rolls the AP back to.
    pub previous: String,
    /// The controller's gate verdict, once it came: healthy, and what it saw.
    pub gate: watch::Sender<Option<(bool, String)>>,
    /// The local caller following it, when one asked for it.
    pub follower: Option<mpsc::Sender<Reply>>,
}

#[derive(Default)]
struct Inner {
    /// Since when a session with the controller is up.
    linked_at: Option<Instant>,
    last_seq: u64,
    next_id: u64,
    /// The latest configuration signed for each AP, by host name.
    latest: HashMap<String, Latest>,
    /// The image the runner staged on each AP, by AP.
    images: BTreeMap<String, String>,
    applies: HashMap<u64, Waiting>,
    rollout: Option<Current>,
    /// Results the controller has not acknowledged.
    unacked: Vec<RolloutResult>,
    /// Local callers waiting for the controller to hand their rollout back,
    /// oldest first.
    asks: Vec<Ask>,
    /// Why each state file this process set aside could not be read.
    set_aside: HashMap<String, String>,
}

/// What `name` of `store` holds; a file that cannot be read is set aside,
/// why noted in `notes`, and taken as empty.
fn load<T: DeserializeOwned>(
    store: &Store,
    name: &str,
    notes: &mut HashMap<String, String>,
) -> io::Result<Option<T>> {
    match store.load(name) {
        Ok(v) => Ok(v),
        Err(Unreadable::Io(e)) => Err(e),
        Err(Unreadable::Corrupt(why)) => {
            let aside = store.set_aside(name)?;
            eprintln!("u6e-deploy: {name}: not read ({why}): set aside as {aside}");
            notes.insert(aside, why);
            Ok(None)
        }
    }
}

pub struct Runner {
    pub config: Config,
    key: Ed25519KeyPair,
    pub(crate) helper: Helper,
    store: Store,
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

pub(crate) fn unix_ms() -> u64 {
    let since = SystemTime::now().duration_since(UNIX_EPOCH);
    since.map_or(0, |d| d.as_millis() as u64)
}

impl Runner {
    /// The runner with what its state directory keeps, the rollout it was
    /// running among it, and the queue of what it sends the controller,
    /// which the link drains.
    pub(crate) fn new(
        config: Config,
        key: Ed25519KeyPair,
    ) -> std::io::Result<(Arc<Self>, Option<InFlight>, mpsc::Receiver<RunnerMsg>)> {
        let store = Store::open(&config.state)?;
        let mut inner = Inner::default();
        let notes = &mut inner.set_aside;
        let mut latest = HashMap::new();
        for hostname in config.aps.values() {
            if let Some(l) = load::<Latest>(&store, &latest_file(hostname), notes)? {
                latest.insert(hostname.clone(), l);
            }
        }
        inner.images = load(&store, IMAGES, notes)?.unwrap_or_default();
        inner.unacked = load(&store, RESULTS, notes)?.unwrap_or_default();
        let resumed = load::<InFlight>(&store, ROLLOUT, notes)?;
        inner.last_seq = latest.values().map(|l| l.seq).max().unwrap_or(0);
        inner.latest = latest;
        let (outbox, rx) = mpsc::channel(OUTBOX_CAP);
        let helper = Helper {
            socket: config.rollout.helper.clone(),
        };
        let runner = Runner {
            config,
            key,
            helper,
            store,
            inner: Mutex::new(inner),
            outbox,
        };
        Ok((Arc::new(runner), resumed, rx))
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Keeps `v` as `name`; a failure is the journal's, as the state in
    /// memory stands.
    fn keep<T: Serialize>(&self, name: &str, v: &T) {
        if let Err(e) = self.store.save(name, v) {
            eprintln!("u6e-deploy: {}: not kept: {e}", self.config.state.display());
        }
    }

    /// What a new session with the controller says first, after its Hello:
    /// the latest configuration for each AP, the rollout under way, the
    /// results not yet acknowledged and the state files set aside.
    pub(crate) fn linked(&self) -> Vec<RunnerMsg> {
        let mut inner = self.lock();
        inner.linked_at = Some(Instant::now());
        let latest = inner.latest.iter().map(|(ap, l)| RunnerMsg::Latest {
            ap: ap.clone(),
            seq: l.seq,
            sha256: config_sha256(&l.radios),
        });
        let mut said: Vec<RunnerMsg> = latest.collect();
        if let Some(r) = &inner.rollout {
            said.push(RunnerMsg::RolloutStarted { id: r.id });
        }
        said.extend(inner.unacked.iter().cloned().map(RunnerMsg::RolloutResult));
        match self.store.set_aside_files() {
            Ok(files) => said.extend(files.into_iter().map(|(file, at_ms)| {
                let why = inner.set_aside.get(&file).cloned();
                RunnerMsg::StateDiscarded {
                    detail: why.unwrap_or_else(|| "set aside before the runner started".into()),
                    file,
                    at_ms,
                }
            })),
            Err(e) => eprintln!("u6e-deploy: {}: {e}", self.config.state.display()),
        }
        said
    }

    /// The kept images the runner needs, sorted: the one staged last on each
    /// AP (its way back), and both of a rollout under way.
    pub fn images(&self) -> Vec<String> {
        let inner = self.lock();
        let mut ids: Vec<String> = inner.images.values().cloned().collect();
        if let Some(r) = &inner.rollout {
            ids.extend([r.image_id.clone(), r.previous.clone()]);
        }
        ids.sort();
        ids.dedup();
        ids
    }

    /// The site's own deploy staged `image` on `ap` (a root caller's word,
    /// checked with the stage helper): the image a failed gate rolls the AP
    /// back to from now on.
    pub async fn staged(&self, ap: &str, image: &str) -> Result<(), String> {
        if self.config.hostname(ap).is_none() {
            return Err(format!("no AP {ap:.64} in the configuration"));
        }
        self.helper.check(ap, image).await?;
        let mut inner = self.lock();
        if inner.rollout.as_ref().is_some_and(|r| r.ap == ap) {
            return Err(format!("{ap} is being rolled out to"));
        }
        inner.images.insert(ap.to_owned(), image.to_owned());
        self.keep(IMAGES, &inner.images);
        eprintln!("u6e-deploy: {ap}: {image} staged by the site's deploy");
        Ok(())
    }

    /// The session ended: the configurations that waited for an answer have
    /// none, and their callers hear so.
    pub(crate) fn unlinked(&self) {
        let mut inner = self.lock();
        inner.linked_at = None;
        for (_, waiting) in inner.applies.drain() {
            if let Waiting::Local(tx) = waiting {
                let _ = tx.send(ConfigApplied {
                    sha256: [0; 32],
                    ok: false,
                    radios: Vec::new(),
                    detail: "the link to the controller went down before the AP answered".into(),
                });
            }
        }
    }

    /// Since when the link has been up.
    pub(crate) fn linked_at(&self) -> Option<Instant> {
        self.lock().linked_at
    }

    /// Whether request `id` still waits for an answer: one given up on is
    /// not sent.
    pub(crate) fn is_pending(&self, id: u64) -> bool {
        self.lock().applies.contains_key(&id)
    }

    /// Gives up on request `id`, whose caller stopped waiting.
    pub(crate) fn forget(&self, id: u64) {
        self.lock().applies.remove(&id);
    }

    fn next_id(inner: &mut Inner) -> u64 {
        inner.next_id += 1;
        inner.next_id
    }

    /// Signs `radios` for the AP of `hostname` under the next sequence
    /// number, keeps them as its latest, and sends them to the controller as
    /// request `id`, the answer to `waiting`.
    fn send_signed(
        &self,
        inner: &mut Inner,
        hostname: &str,
        radios: Vec<RadioConfig>,
        waiting: Waiting,
    ) -> Result<u64, String> {
        inner.last_seq = unix_ms().max(inner.last_seq + 1);
        let seq = inner.last_seq;
        let config = config::sign(&self.key, hostname, seq, radios.clone());
        let latest = Latest { seq, radios };
        self.keep(&latest_file(hostname), &latest);
        inner.latest.insert(hostname.to_owned(), latest);
        let id = Runner::next_id(inner);
        let sha256 = config.sha256;
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
        Ok(id)
    }

    /// A local caller's configuration for `ap`, signed and sent: its
    /// request's id, and the AP's answer on the receiver.
    pub fn apply(
        &self,
        ap: &str,
        radios: Vec<RadioConfig>,
    ) -> Result<(u64, oneshot::Receiver<ConfigApplied>), String> {
        let hostname = self
            .config
            .hostname(ap)
            .ok_or_else(|| format!("no AP {ap:.64} in the configuration"))?;
        let mut inner = self.lock();
        if inner.linked_at.is_none() {
            return Err("no link to the controller".into());
        }
        if inner.rollout.as_ref().is_some_and(|r| r.ap == ap) {
            return Err(format!("{ap} is being rolled out to"));
        }
        let (tx, rx) = oneshot::channel();
        let id = self.send_signed(&mut inner, hostname, radios, Waiting::Local(tx))?;
        Ok((id, rx))
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
        if inner.linked_at.is_none() {
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
            RunnerCtlMsg::Repush { ap, installed } => self.repush(&ap, installed),
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
            RunnerCtlMsg::RolloutAck { id } => {
                let mut inner = self.lock();
                inner.unacked.retain(|r| r.id != id);
                self.keep(RESULTS, &inner.unacked);
            }
            // A message of a newer protocol's would not have been decoded.
            _ => {}
        }
        None
    }

    fn applied(&self, id: u64, result: ConfigApplied) {
        let Some(waiting) = self.lock().applies.remove(&id) else {
            return;
        };
        match waiting {
            Waiting::Local(tx) => {
                let _ = tx.send(result);
            }
            Waiting::Repush(hostname) => {
                let ap = self.config.ap_of(&hostname).unwrap_or(&hostname);
                let how = if result.ok { "applied" } else { "not applied" };
                eprintln!(
                    "u6e-deploy: {ap}: the configuration signed again: {how}: {}",
                    result.detail
                );
            }
        }
    }

    /// The controller saw the AP of `hostname` run `installed`, not the
    /// latest configuration signed for it: that one is signed again.
    fn repush(&self, hostname: &str, installed: Option<[u8; 32]>) {
        let mut inner = self.lock();
        let ap = self.config.ap_of(hostname).unwrap_or(hostname).to_owned();
        let skip = |why: String| eprintln!("u6e-deploy: {ap}: not signed again: {why}");
        let Some(latest) = inner.latest.get(hostname) else {
            return skip("nothing was signed for it".into());
        };
        let sha256 = config_sha256(&latest.radios);
        if installed == Some(sha256) {
            return skip("it runs it".into());
        }
        if inner.rollout.as_ref().is_some_and(|r| r.ap == ap) {
            return skip("it is being rolled out to".into());
        }
        let radios = latest.radios.clone();
        eprintln!(
            "u6e-deploy: {ap}: runs {}, not the latest {}: signing it again",
            installed.map_or_else(|| "none".into(), |h| mac::hex(&h)),
            mac::hex(&sha256),
        );
        let waiting = Waiting::Repush(hostname.to_owned());
        if let Err(why) = self.send_signed(&mut inner, hostname, radios, waiting) {
            skip(why);
        }
    }

    /// A rollout the controller hands over: refused when another runs or it
    /// could not be rolled back, else run. Its way back is the image the
    /// runner staged on the AP, or, on an AP it has staged nothing on yet,
    /// the one the controller says it runs.
    fn start(self: &Arc<Self>, req: RolloutRequest) {
        let mut inner = self.lock();
        let asked = inner
            .asks
            .iter()
            .position(|a| (&a.ap, &a.image_id, &a.user) == (&req.ap, &req.image_id, &req.user));
        let follower = asked.map(|i| inner.asks.remove(i).follower);
        let previous = inner
            .images
            .get(&req.ap)
            .cloned()
            .unwrap_or(req.previous.clone());
        let refusal = if let Some(r) = &inner.rollout {
            Some(format!(
                "the rollout of {} to {} is not over",
                r.image_id, r.ap
            ))
        } else if self.config.hostname(&req.ap).is_none() {
            Some(format!("no AP {:.64} in the configuration", req.ap))
        } else if previous.is_empty() {
            Some(format!(
                "what {} runs is not known, so it could not be rolled back",
                req.ap
            ))
        } else if req.image_id == previous {
            Some(format!("{} runs {} already", req.ap, req.image_id))
        } else {
            None
        };
        if let Some(why) = refusal {
            drop(inner);
            self.refuse(req.id, &req.ap, &req.image_id, why, follower);
            return;
        }
        let flight = InFlight {
            id: req.id,
            ap: req.ap,
            image_id: req.image_id,
            previous,
            user: req.user,
            local: follower.is_some(),
            phase: Phase::Checking,
        };
        let gate = self.current(&mut inner, &flight, follower);
        // Kept before it is told as taken on: a runner restarted from here
        // still names it at its next session, and goes on with it.
        self.persist(&flight);
        let _ = self
            .outbox
            .try_send(RunnerMsg::RolloutStarted { id: flight.id });
        tokio::spawn(rollout::run(Arc::clone(self), flight, gate));
    }

    /// Goes on with the rollout the state directory kept, which a runner
    /// that stopped was running.
    pub(crate) fn resume(self: &Arc<Self>, flight: InFlight) {
        eprintln!(
            "u6e-deploy: {}: going on with the rollout of {} ({:?})",
            flight.ap, flight.image_id, flight.phase
        );
        let gate = self.current(&mut self.lock(), &flight, None);
        tokio::spawn(rollout::run(Arc::clone(self), flight, gate));
    }

    /// Makes `flight` the rollout under way; the receiver of its gate.
    fn current(
        &self,
        inner: &mut Inner,
        flight: &InFlight,
        follower: Option<mpsc::Sender<Reply>>,
    ) -> watch::Receiver<Option<(bool, String)>> {
        let (gate, gate_rx) = watch::channel(None);
        inner.rollout = Some(Current {
            id: flight.id,
            ap: flight.ap.clone(),
            image_id: flight.image_id.clone(),
            previous: flight.previous.clone(),
            gate,
            follower,
        });
        gate_rx
    }

    /// Refuses rollout `id`: nothing was staged.
    fn refuse(
        &self,
        id: u64,
        ap: &str,
        image_id: &str,
        why: String,
        follower: Option<mpsc::Sender<Reply>>,
    ) {
        eprintln!("u6e-deploy: {ap}: {image_id} refused: {why}");
        let result = RolloutResult {
            id,
            outcome: RolloutOutcome::Refused,
            detail: why.clone(),
        };
        self.record(result);
        if let Some(f) = follower {
            let _ = f.try_send(Reply::Done {
                ok: false,
                detail: format!("refused: {why}"),
            });
        }
    }

    /// Keeps `result` until the controller acknowledges it, and sends it.
    fn record(&self, result: RolloutResult) {
        let mut inner = self.lock();
        inner.unacked.push(result.clone());
        self.keep(RESULTS, &inner.unacked);
        let _ = self.outbox.try_send(RunnerMsg::RolloutResult(result));
    }

    /// Keeps where `flight` got to, for a runner that restarts.
    pub(crate) fn persist(&self, flight: &InFlight) {
        self.keep(ROLLOUT, flight);
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

    /// Ends the rollout under way: the image the AP runs is recorded, the
    /// result kept until the controller acknowledges it and sent, and then
    /// the follower hears how, who may ask for the next rollout at once; that
    /// ask must not reach the controller before this result.
    pub(crate) async fn finish(&self, flight: &InFlight, outcome: RolloutOutcome, detail: String) {
        let current = self.lock().rollout.take_if(|r| r.id == flight.id);
        let Some(r) = current else {
            return;
        };
        {
            let mut inner = self.lock();
            match outcome {
                RolloutOutcome::Done => {
                    inner
                        .images
                        .insert(flight.ap.clone(), flight.image_id.clone());
                }
                RolloutOutcome::RolledBack => {
                    inner
                        .images
                        .insert(flight.ap.clone(), flight.previous.clone());
                }
                // Where staging stopped, nothing is known.
                RolloutOutcome::Failed => {
                    inner.images.remove(&flight.ap);
                }
                // The controller's word alone, never the runner's.
                RolloutOutcome::Refused | RolloutOutcome::NotStarted => {}
            }
            self.keep(IMAGES, &inner.images);
        }
        if let Err(e) = self.store.remove(ROLLOUT) {
            eprintln!("u6e-deploy: {}: {e}", self.config.state.display());
        }
        let word = match outcome {
            RolloutOutcome::Done => "done",
            RolloutOutcome::RolledBack => "rolled back",
            RolloutOutcome::Failed => "failed",
            RolloutOutcome::Refused => "refused",
            RolloutOutcome::NotStarted => "not started",
        };
        eprintln!("u6e-deploy: {}: {}: {word}: {detail}", r.ap, r.image_id);
        let done = Reply::Done {
            ok: outcome == RolloutOutcome::Done,
            detail: format!("{word}: {detail}"),
        };
        self.record(RolloutResult {
            id: flight.id,
            outcome,
            detail,
        });
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
    use crate::tests::TestDir;

    fn runner(t: &TestDir) -> (Arc<Runner>, mpsc::Receiver<RunnerMsg>) {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let mut config = Config::parse(&text("")).unwrap();
        config.state = t.path().join("state");
        let (runner, _, sent) = Runner::new(config, key).unwrap();
        runner.linked();
        (runner, sent)
    }

    /// Two callers' asks for one AP: each follows the rollout the controller
    /// hands back for it, whichever comes first.
    #[test]
    fn each_caller_follows_the_rollout_it_asked_for() {
        let t = TestDir::new();
        let (runner, mut sent) = runner(&t);
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

    /// A rollout is kept before it is told to the controller as taken on: a
    /// runner restarted while it checks the images still holds it, names it
    /// at its next session and goes on with it.
    #[test]
    fn a_rollout_is_kept_before_it_is_told_as_taken_on() {
        let t = TestDir::new();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (runner, mut sent) = runner(&t);
            runner.handle(RunnerCtlMsg::Rollout(RolloutRequest {
                id: 9,
                ap: "ap1".into(),
                image_id: "img-b-ap1".into(),
                previous: "img-a-ap1".into(),
                user: "admin".into(),
            }));
            // Told, and kept, before the rollout's first step has run.
            assert!(matches!(
                sent.try_recv(),
                Ok(RunnerMsg::RolloutStarted { id: 9 })
            ));
            let kept: InFlight = runner.store.load(ROLLOUT).unwrap().unwrap();
            assert_eq!((kept.id, kept.phase), (9, Phase::Checking));
        });
        drop(rt);
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let mut config = Config::parse(&text("")).unwrap();
        config.state = t.path().join("state");
        let (_, resumed, _) = Runner::new(config, key).unwrap();
        assert_eq!(resumed.map(|f| (f.id, f.phase)), Some((9, Phase::Checking)));
    }

    /// A result is kept until the controller acknowledges it, across a
    /// restart, and said again at each new session.
    #[test]
    fn a_result_is_sent_until_acknowledged() {
        let t = TestDir::new();
        let (runner, _sent) = runner(&t);
        runner.handle(RunnerCtlMsg::Rollout(RolloutRequest {
            id: 4,
            ap: "ap1".into(),
            image_id: "img-b-ap1".into(),
            previous: String::new(),
            user: "admin".into(),
        }));
        drop(runner);
        let (again, _sent) = super::tests::runner(&t);
        let said = again.linked();
        assert!(
            matches!(&said[..], [RunnerMsg::RolloutResult(r)] if r.id == 4),
            "{said:?}"
        );
        again.handle(RunnerCtlMsg::RolloutAck { id: 4 });
        assert!(again.linked().is_empty());
        drop(again);
        let (third, _sent) = super::tests::runner(&t);
        assert!(third.linked().is_empty());
    }
}
