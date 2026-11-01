//! The controller's local socket (`socket`, 0600, its own user's): what
//! root's commands on the controller's host ask of it: applying a rendered
//! Wi-Fi configuration to an AP (`u6e-controller apply`), adding an image to
//! the kept ones (`u6e-controller image add`), and holding an AP while
//! something else reboots it, or releasing it (`u6e-controller hold`,
//! `release`; `State::hold`). Only
//! root and the controller's own user are served, by the peer's credentials:
//! whoever may ask holds the site's configuration anyway. A connection
//! carries one request, answered with a last word.

use std::fs;
use std::io;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::{sleep, timeout};
use u6e_proto::config::config_sha256;
use u6e_proto::mac;
use u6e_proto::msg::{ConfigApplied, RadioConfig};

use crate::agents::save_policy;
use crate::frames;
use crate::images::{self, MANIFEST_MAX, image_name};
use crate::policy::Store;
use crate::rollout::Engine;
use crate::state::{Shared, mechanism_name};
use crate::view::band;

/// What a local caller asks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// Sign these radios' configuration for the AP and have it applied.
    Apply {
        ap: String,
        radios: Vec<RadioConfig>,
    },
    /// Keep the image of this `MANIFEST` as `id`; its files follow, if the
    /// answer is [`Reply::Send`].
    AddImage { id: String, manifest: String },
    /// A part of the file being sent; an empty one ends it. The files come
    /// in their `MANIFEST`'s order.
    Chunk(Vec<u8>),
    /// Hold the AP, for this reason.
    Hold { ap: String, reason: String },
    /// End the AP's hold.
    Release { ap: String },
}

/// What the controller answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    /// The AP's answer to the configuration.
    Applied(ConfigApplied),
    /// The image's files may come.
    Send,
    /// The last word: whether it went through, and how.
    Done { ok: bool, detail: String },
}

/// The most of a file one chunk carries, well within a frame.
const CHUNK_MAX: usize = 512 * 1024;
/// How long a caller may take to send each frame of its request.
const REQUEST_WAIT: Duration = Duration::from_secs(60);

/// Whether a peer of `uid` may ask: root, or the controller's own user.
fn allowed(uid: u32, ours: u32) -> bool {
    uid == 0 || uid == ours
}

/// What the local socket serves with.
#[derive(Clone)]
pub struct Local {
    pub state: Shared,
    /// Where a hold is kept.
    pub policy: Store,
    pub rollouts: Option<Engine>,
    /// How long an apply waits for the AP: past the controller's own wait
    /// (`Timing::apply`), whose answer then comes first.
    pub apply_wait: Duration,
}

/// Serves local callers on `listener` for the life of the process.
pub async fn serve(local: Local, listener: UnixListener) {
    // SAFETY: geteuid has no preconditions.
    let ours = unsafe { libc::geteuid() };
    loop {
        match listener.accept().await {
            Ok((conn, _)) => {
                tokio::spawn(caller(local.clone(), conn, ours));
            }
            Err(e) => {
                eprintln!("u6e-controller: local socket: {e}");
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

fn done(ok: bool, detail: String) -> Reply {
    Reply::Done { ok, detail }
}

/// Serves one local caller, if it may ask.
async fn caller(local: Local, mut conn: UnixStream, ours: u32) {
    let Ok(cred) = conn.peer_cred() else {
        return;
    };
    if !allowed(cred.uid(), ours) {
        eprintln!(
            "u6e-controller: a local caller of uid {} refused",
            cred.uid()
        );
        return;
    }
    let req = match timeout(REQUEST_WAIT, frames::read(&mut conn)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return eprintln!("u6e-controller: a local caller: {e}"),
        Err(_) => return eprintln!("u6e-controller: a local caller sent no request"),
    };
    let reply = match req {
        Request::Apply { ap, radios } => {
            let asked = local.state.write().apply_config(&ap, radios);
            match asked {
                Err(why) => done(false, why),
                Ok(rx) => match timeout(local.apply_wait, rx).await {
                    Ok(Ok(c)) => Reply::Applied(c),
                    _ => done(false, format!("no answer from {ap}")),
                },
            }
        }
        Request::AddImage { id, manifest } => match &local.rollouts {
            None => done(
                false,
                "rollouts are off: the controller has no [rollouts]".into(),
            ),
            Some(engine) => add(engine, &mut conn, &id, &manifest).await,
        },
        Request::Chunk(_) => done(false, "a chunk of no image".into()),
        Request::Hold { ap, reason } => {
            let held = local.state.write().hold(&ap, &reason);
            kept(&local, held).await
        }
        Request::Release { ap } => {
            let released = local.state.write().release(&ap);
            kept(&local, released).await
        }
    };
    let _ = frames::write(&mut conn, &reply).await;
}

/// The answer to a hold or a release, once the policy file keeps it: a
/// hold a restart would forget holds nothing.
async fn kept(local: &Local, r: Result<String, String>) -> Reply {
    match r {
        Err(why) => done(false, why),
        Ok(detail) => {
            local.state.write().take_dirty();
            if save_policy(local.policy.clone(), local.state.clone()).await {
                done(true, detail)
            } else {
                local.state.write().mark_dirty();
                done(
                    false,
                    format!("{detail}, but the policy file was not saved"),
                )
            }
        }
    }
}

/// Takes image `id` of `manifest` from the caller, then keeps it.
async fn add(engine: &Engine, conn: &mut UnixStream, id: &str, manifest: &str) -> Reply {
    let (adding, _held) = match engine.add(id, manifest).await {
        Ok(a) => a,
        Err(why) => return done(false, why),
    };
    let Some(mut adding) = adding else {
        return done(true, format!("{id} is kept already"));
    };
    if frames::write(conn, &Reply::Send).await.is_err() {
        return done(false, "the caller went away".into());
    }
    loop {
        let chunk = match timeout(REQUEST_WAIT, frames::read(conn)).await {
            Ok(Ok(Request::Chunk(c))) => c,
            Ok(Ok(_)) => return done(false, "not a chunk of the image".into()),
            Ok(Err(e)) => return done(false, format!("the image did not come whole: {e}")),
            Err(_) => return done(false, "the image stopped coming".into()),
        };
        match adding.chunk(&chunk) {
            Ok(false) => {}
            Ok(true) => break,
            Err(why) => return done(false, why),
        }
    }
    match engine.added(adding).await {
        Ok(detail) => done(true, detail),
        Err(why) => done(false, why),
    }
}

async fn connect(socket: &Path) -> Result<UnixStream, String> {
    UnixStream::connect(socket)
        .await
        .map_err(|e| format!("{}: {e}", socket.display()))
}

/// Has the controller on `socket` apply `radios` to `ap`; what the AP did,
/// or why it did not take exactly these.
pub async fn apply(socket: &Path, ap: &str, radios: Vec<RadioConfig>) -> Result<String, String> {
    let sha256 = config_sha256(&radios);
    let req = Request::Apply {
        ap: ap.into(),
        radios,
    };
    let mut conn = connect(socket).await?;
    let reply = async {
        frames::write(&mut conn, &req).await?;
        frames::read(&mut conn).await
    };
    match reply.await.map_err(|e| format!("the controller: {e}"))? {
        Reply::Applied(c) if c.sha256 != sha256 => Err(format!(
            "{ap} answered for another configuration ({}, not {})",
            mac::hex(&c.sha256),
            mac::hex(&sha256)
        )),
        Reply::Applied(c) if !c.ok => Err(format!("{ap}: {}", c.detail)),
        Reply::Applied(c) => {
            let how: Vec<String> = c
                .radios
                .iter()
                .map(|r| format!("{} GHz {}", band(r.radio), mechanism_name(r.mechanism)))
                .collect();
            Ok(format!(
                "{ap}: {} ({}): {}",
                mac::hex(&sha256),
                how.join(", "),
                c.detail
            ))
        }
        Reply::Done { detail, .. } => Err(detail),
        Reply::Send => Err("the controller answered out of turn".into()),
    }
}

/// Has the controller on `socket` hold `ap` for `reason`, or release it
/// with `None`; what it said.
pub async fn hold(socket: &Path, ap: &str, reason: Option<&str>) -> Result<String, String> {
    let req = match reason {
        Some(reason) => Request::Hold {
            ap: ap.into(),
            reason: reason.into(),
        },
        None => Request::Release { ap: ap.into() },
    };
    let mut conn = connect(socket).await?;
    let reply = async {
        frames::write(&mut conn, &req).await?;
        frames::read(&mut conn).await
    };
    match reply.await.map_err(|e| format!("the controller: {e}"))? {
        Reply::Done { ok: true, detail } => Ok(detail),
        Reply::Done { detail, .. } => Err(detail),
        other => Err(format!("the controller answered {other:?}")),
    }
}

/// Has the controller on `socket` keep the image in `dir` (its `MANIFEST`
/// and the files it lists), under the directory's name; what it said.
pub async fn add_image(socket: &Path, dir: &Path) -> Result<String, String> {
    let id = dir
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| image_name(n))
        .ok_or_else(|| format!("{} is not named as a kept image", dir.display()))?;
    let manifest = fs::read(dir.join("MANIFEST")).map_err(|e| format!("MANIFEST: {e}"))?;
    if manifest.len() > MANIFEST_MAX {
        return Err("the MANIFEST is too long to be one".into());
    }
    let manifest = String::from_utf8(manifest).map_err(|_| "the MANIFEST is not text")?;
    let files = images::listed(&manifest)?;
    let mut conn = connect(socket).await?;
    let fail = |e: io::Error| format!("the controller: {e}");
    let req = Request::AddImage {
        id: id.into(),
        manifest,
    };
    frames::write(&mut conn, &req).await.map_err(fail)?;
    match frames::read(&mut conn).await.map_err(fail)? {
        Reply::Send => {}
        Reply::Done { ok: true, detail } => return Ok(detail),
        Reply::Done { detail, .. } => return Err(detail),
        Reply::Applied(_) => return Err("the controller answered out of turn".into()),
    }
    let mut buf = vec![0; CHUNK_MAX];
    'files: for (name, _) in &files {
        let mut f = fs::File::open(dir.join(name)).map_err(|e| format!("{name}: {e}"))?;
        loop {
            let n = io::Read::read(&mut f, &mut buf).map_err(|e| format!("{name}: {e}"))?;
            let chunk = Request::Chunk(buf[..n].to_vec());
            // A controller that refused a file says why before it closes.
            if frames::write(&mut conn, &chunk).await.is_err() {
                break 'files;
            }
            if n == 0 {
                break;
            }
        }
    }
    match frames::read(&mut conn).await.map_err(fail)? {
        Reply::Done { ok: true, detail } => Ok(detail),
        Reply::Done { detail, .. } => Err(detail),
        other => Err(format!("the controller answered {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_and_the_controllers_own_user_may_ask() {
        assert!(allowed(0, 997));
        assert!(allowed(997, 997));
        assert!(!allowed(1000, 997));
    }
}
