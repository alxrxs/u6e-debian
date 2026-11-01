//! Image rollouts, `[rollouts]`: the kept images (`images`), and the rollout
//! of an AP's newest one an admin asks for (`POST /api/aps/{ap}/upgrade`),
//! carried out here, one AP at a time.
//!
//! ```toml
//! [rollouts]
//! images = "/var/lib/wifi-controller/images"
//! gate_secs = 420                # 1 to 1800
//! keep = 3                       # the newest kept of each AP, at least
//! root_key = "/etc/wifi-controller/ap-root-key"
//! stock_user = "ubnt"
//! stock_password = "/etc/wifi-controller/ap-stock-password"
//! known_hosts = "/etc/wifi-controller/ap-known-hosts"
//! ```
//!
//! A rollout goes through its steps (`policy::Phase`), each kept in the
//! policy file before it is taken, so a restarted controller goes on where it
//! was: both images are checked against their MANIFESTs first, so one that
//! could not be undone never starts; the new one is staged (`stage`); then
//! the AP has `gate_secs` to pass the health gate (`State::gate`: back with
//! the image, its radios up, the site's clients back; a verdict that came
//! during the staging counts); healthy, it is done; unhealthy, out of time,
//! or a staging that failed part way, the image the AP ran before is staged
//! again: rolled back, or failed if that fails too. A controller restarted
//! during a staging stages again (the staging that died with it may have
//! left the AP anywhere between its two systems, rebooting even), the AP
//! given the gate's time to answer either first, and rolls back if it
//! answers neither; a rollback gives it that time too. Every end but done
//! raises the failure (`wifi_rollout_last_failure_timestamp_seconds`). One
//! restarted during the
//! gate gives the AP at least `Timing::resume` to come back to it, so a
//! restart never rolls a healthy AP back. The kept images are pruned after
//! each image added and each rollout: each AP keeps what it runs, what it
//! may run, both images of a rollout under way, and its newest `keep`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tokio::sync::{Mutex, OwnedMutexGuard};
use tokio::task::spawn_blocking;
use tokio::time::{sleep, timeout};

use crate::agents::save_policy;
use crate::configs::unix_ms;
use crate::images::{Adding, Images, Kept};
use crate::policy::{Phase, Store};
use crate::stage::{Credentials, Stage, Staged, Target};
use crate::state::{RolloutOutcome, Shared};

/// The longest gate.
pub const GATE_MAX: Duration = Duration::from_secs(30 * 60);
/// The longest a staging may take: `boot/stage.sh` waits up to 400 s for
/// stock and 600 s for the image, around the payloads' writes.
pub const STAGE_MAX: Duration = Duration::from_secs(45 * 60);
/// How often a gate's verdict is looked for.
const POLL: Duration = Duration::from_millis(250);
/// The waits between the tries of a policy save.
const SAVE_TRIES: [Duration; 3] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_secs(1),
];

/// The checked `[rollouts]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub images: PathBuf,
    /// How long after staging an image the AP has to pass the health gate.
    pub gate: Duration,
    /// The newest images of each AP kept however old.
    pub keep: usize,
    pub ssh: Credentials,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct File {
    #[serde(default = "default_images")]
    images: PathBuf,
    #[serde(default = "default_gate")]
    gate_secs: u64,
    #[serde(default = "default_keep")]
    keep: usize,
    root_key: PathBuf,
    #[serde(default = "default_user")]
    stock_user: String,
    stock_password: PathBuf,
    known_hosts: PathBuf,
}

fn default_images() -> PathBuf {
    "/var/lib/wifi-controller/images".into()
}

/// Seven minutes: an AP boots and brings its radios up in about two.
fn default_gate() -> u64 {
    420
}

fn default_keep() -> usize {
    3
}

fn default_user() -> String {
    "ubnt".into()
}

impl File {
    pub fn check(self) -> Result<Settings, String> {
        if !(1..=GATE_MAX.as_secs()).contains(&self.gate_secs) {
            return Err(format!(
                "rollouts: gate_secs is not from 1 to {}",
                GATE_MAX.as_secs()
            ));
        }
        if self.keep == 0 {
            return Err("rollouts: keep must be at least 1".into());
        }
        let paths = [
            &self.images,
            &self.root_key,
            &self.stock_password,
            &self.known_hosts,
        ];
        // They go into ssh's command line.
        if let Some(p) = paths.iter().find(|p| !u6e_git::plain_path(p)) {
            return Err(format!(
                "rollouts: {} is not an absolute path of letters, digits and /._-",
                p.display()
            ));
        }
        let user = |c: char| c.is_ascii_alphanumeric() || "._-".contains(c);
        if self.stock_user.is_empty()
            || self.stock_user.starts_with('-')
            || !self.stock_user.chars().all(user)
        {
            return Err("rollouts: stock_user is not a plain user name".into());
        }
        Ok(Settings {
            images: self.images,
            gate: Duration::from_secs(self.gate_secs),
            keep: self.keep,
            ssh: Credentials {
                root_key: self.root_key,
                stock_user: self.stock_user,
                stock_password: self.stock_password,
                known_hosts: self.known_hosts,
            },
        })
    }
}

/// What a log line calls `phase`.
fn phase_name(phase: &Phase) -> &'static str {
    match phase {
        Phase::Checking => "check",
        Phase::Staging => "staging",
        Phase::Gate { .. } => "health gate",
        Phase::RollingBack { .. } => "rollback",
    }
}

/// What a rollout's step leads to.
enum Next {
    Phase(Phase),
    End(RolloutOutcome, String),
}

/// The rollouts and the kept images, shared by the web's upgrades, the local
/// socket's image adds and the rollouts' own tasks.
#[derive(Clone)]
pub struct Engine(Arc<Inner>);

struct Inner {
    state: Shared,
    policy: Store,
    settings: Settings,
    images: Images,
    stager: Arc<dyn Stage>,
    /// Each AP as a staging reaches it.
    targets: BTreeMap<String, Target>,
    /// How long a gate resumed by a restarted controller waits at least.
    resume: Duration,
    /// One image added at a time.
    adding: Arc<Mutex<()>>,
}

impl Engine {
    pub fn new(
        state: Shared,
        policy: Store,
        settings: Settings,
        images: Images,
        stager: Arc<dyn Stage>,
        targets: BTreeMap<String, Target>,
        resume: Duration,
    ) -> Engine {
        Engine(Arc::new(Inner {
            state,
            policy,
            settings,
            images,
            stager,
            targets,
            resume,
            adding: Arc::new(Mutex::new(())),
        }))
    }

    /// Goes on with the rollouts the policy file holds open.
    pub fn resume(&self) {
        let open: Vec<u64> = {
            let state = self.0.state.read();
            let open = state.rollouts.iter().filter(|r| r.is_open());
            open.map(|r| r.id).collect()
        };
        for id in open {
            tokio::spawn(self.clone().run(id, true));
        }
    }

    /// An admin's rollout of `image_id` to `ap`: kept in the policy file
    /// before its first step is taken, or refused; its id.
    pub async fn upgrade(&self, ap: &str, image_id: &str, user: &str) -> Result<u64, String> {
        let id = self.0.state.write().upgrade(ap, image_id, user)?;
        if !self.save().await {
            let why = "the policy file could not be saved, so nothing was done";
            self.0
                .state
                .write()
                .rollout_end(id, RolloutOutcome::Refused, why.into());
            return Err(why.into());
        }
        tokio::spawn(self.clone().run(id, false));
        Ok(id)
    }

    /// Saves the policy file, if it changed, trying again a few times; it is
    /// what a restarted controller goes on from, so a step is taken only
    /// once it is saved. Whether it is.
    async fn save(&self) -> bool {
        let inner = &self.0;
        if !inner.state.write().take_dirty() {
            return true;
        }
        for backoff in SAVE_TRIES {
            if save_policy(inner.policy.clone(), inner.state.clone()).await {
                return true;
            }
            sleep(backoff).await;
        }
        inner.state.write().mark_dirty();
        false
    }

    fn log(&self, id: u64, line: String) {
        self.0.state.write().rollout_log(id, line);
    }

    /// Rollout `id`'s steps from where it is to its end; `resumed` by a
    /// restarted controller.
    async fn run(self, id: u64, mut resumed: bool) {
        loop {
            let Some(r) = self
                .0
                .state
                .read()
                .rollout(id)
                .filter(|r| r.is_open())
                .cloned()
            else {
                return;
            };
            let next = match r.phase.clone() {
                Phase::Checking => {
                    let new = self.verified(&r.ap, &r.image_id).await;
                    let back = self.verified(&r.ap, &r.previous).await;
                    match (new, back) {
                        (Ok(_), Ok(_)) => Next::Phase(Phase::Staging),
                        (Err(why), _) | (_, Err(why)) => Next::End(RolloutOutcome::Refused, why),
                    }
                }
                Phase::Staging => {
                    self.log(
                        id,
                        if resumed {
                            "the controller restarted during the staging: staging again, once \
                             the AP answers"
                                .into()
                        } else {
                            format!("staging {} on {}, as {} asked", r.image_id, r.ap, r.user)
                        },
                    );
                    // A staging the restart cut short may have left the AP
                    // rebooting: it has the gate's time to answer.
                    let wait = if resumed {
                        self.0.settings.gate
                    } else {
                        Duration::ZERO
                    };
                    match self.stage(id, &r.ap, &r.image_id, wait).await {
                        Staged::Done => {
                            let gate =
                                u64::try_from(self.0.settings.gate.as_millis()).unwrap_or(u64::MAX);
                            let deadline_ms = unix_ms().saturating_add(gate);
                            Next::Phase(Phase::Gate { deadline_ms })
                        }
                        Staged::Untouched(why) if !resumed => {
                            Next::End(RolloutOutcome::Refused, why)
                        }
                        Staged::Untouched(why) | Staged::Failed(why) => {
                            Next::Phase(Phase::RollingBack {
                                why: format!("the staging failed: {why}"),
                            })
                        }
                    }
                }
                Phase::Gate { deadline_ms } => {
                    let wait = Duration::from_millis(deadline_ms.saturating_sub(unix_ms()));
                    let wait = if resumed {
                        wait.max(self.0.resume)
                    } else {
                        wait
                    };
                    self.log(
                        id,
                        format!(
                            "staged; waiting up to {}s for the health gate",
                            wait.as_secs()
                        ),
                    );
                    match self.verdict(id, wait).await {
                        Some((true, detail)) => Next::End(RolloutOutcome::Done, detail),
                        Some((false, detail)) => Next::Phase(Phase::RollingBack {
                            why: format!("unhealthy: {detail}"),
                        }),
                        None => Next::Phase(Phase::RollingBack {
                            why: format!("no healthy gate in {:?}", self.0.settings.gate),
                        }),
                    }
                }
                Phase::RollingBack { why } => {
                    self.log(id, format!("{why}: staging {} again", r.previous));
                    // The AP may be rebooting from what went wrong.
                    let wait = self.0.settings.gate;
                    match self.stage(id, &r.ap, &r.previous, wait).await {
                        Staged::Done => Next::End(
                            RolloutOutcome::RolledBack,
                            format!("{why}; {} is staged again", r.previous),
                        ),
                        Staged::Untouched(again) | Staged::Failed(again) => Next::End(
                            RolloutOutcome::Failed,
                            format!("{why}; staging {} again failed too: {again}", r.previous),
                        ),
                    }
                }
            };
            resumed = false;
            match next {
                Next::Phase(phase) => {
                    let step = phase_name(&phase);
                    self.0.state.write().set_phase(id, phase);
                    if !self.save().await {
                        // Untaken, a step a restart would not know of.
                        self.0.state.write().set_phase(id, r.phase.clone());
                        let outcome = if r.phase == Phase::Checking {
                            RolloutOutcome::Refused
                        } else {
                            RolloutOutcome::Failed
                        };
                        let why = format!(
                            "the policy file could not be saved, so the {step} was not taken"
                        );
                        self.0.state.write().rollout_end(id, outcome, why);
                        self.save().await;
                        return;
                    }
                }
                Next::End(outcome, detail) => {
                    self.0.state.write().rollout_end(id, outcome, detail);
                    self.save().await;
                    self.prune().await;
                    return;
                }
            }
        }
    }

    /// Kept image `image` of `ap`, checked against its MANIFEST.
    async fn verified(&self, ap: &str, image: &str) -> Result<Kept, String> {
        let (images, ap, image) = (self.0.images.clone(), ap.to_owned(), image.to_owned());
        spawn_blocking(move || images.verified(&ap, &image))
            .await
            .map_err(|e| e.to_string())?
    }

    /// Stages `image` on `ap`, which has `wait` to answer first, its lines
    /// in rollout `id`'s log.
    async fn stage(&self, id: u64, ap: &str, image: &str, wait: Duration) -> Staged {
        let kept = match self.verified(ap, image).await {
            Ok(k) => k,
            Err(why) => return Staged::Untouched(why),
        };
        let Some(target) = self.0.targets.get(ap) else {
            return Staged::Untouched(format!("no address of {ap} is configured"));
        };
        let log = |line: String| self.log(id, line);
        let staging = self.0.stager.stage(target, &kept, wait, &log);
        match timeout(STAGE_MAX + wait, staging).await {
            Ok(staged) => staged,
            Err(_) => Staged::Failed(format!("the staging took longer than {STAGE_MAX:?}")),
        }
    }

    /// The gate's verdict on rollout `id`, or `None` once `wait` is up.
    async fn verdict(&self, id: u64, wait: Duration) -> Option<(bool, String)> {
        let state = &self.0.state;
        let gate = || state.read().rollout(id).and_then(|r| r.gate.clone());
        let looked = async {
            loop {
                if let Some(v) = gate() {
                    return v;
                }
                sleep(POLL).await;
            }
        };
        timeout(wait, looked).await.ok().or_else(gate)
    }

    /// Starts adding image `id` of `manifest`, which must name an AP of the
    /// configuration: `None` when it is kept already. The guard holds off
    /// every other add until it is dropped.
    pub async fn add(
        &self,
        id: &str,
        manifest: &str,
    ) -> Result<(Option<Adding>, OwnedMutexGuard<()>), String> {
        let held = Arc::clone(&self.0.adding).lock_owned().await;
        let aps: Vec<&str> = self.0.targets.keys().map(String::as_str).collect();
        let adding = self.0.images.add(id, manifest, &aps)?;
        Ok((adding, held))
    }

    /// Keeps the image `adding` brought, then prunes; what it says.
    pub async fn added(&self, adding: Adding) -> Result<String, String> {
        let (id, ap) = (adding.id.clone(), adding.ap.clone());
        spawn_blocking(move || adding.finish())
            .await
            .map_err(|e| e.to_string())??;
        let detail = format!("{id} kept for {ap}");
        self.0
            .state
            .write()
            .record_deploy("image", Some(&ap), None, true, detail.clone());
        self.prune().await;
        Ok(detail)
    }

    /// Removes the images nothing needs, and takes the store's index again.
    async fn prune(&self) {
        let needed = self.0.state.read().images_needed();
        let (images, keep) = (self.0.images.clone(), self.0.settings.keep);
        let pruned = spawn_blocking(move || {
            let removed = images.prune(&needed, keep)?;
            Ok::<_, std::io::Error>((removed, images.index()?))
        })
        .await;
        match pruned {
            Ok(Ok((removed, index))) => {
                let mut state = self.0.state.write();
                for id in removed {
                    state.record_deploy("image", None, None, true, format!("{id} pruned"));
                }
                state.set_kept(index);
            }
            Ok(Err(e)) => eprintln!("u6e-controller: the kept images: {e}"),
            Err(e) => eprintln!("u6e-controller: the kept images: {e}"),
        }
    }
}
