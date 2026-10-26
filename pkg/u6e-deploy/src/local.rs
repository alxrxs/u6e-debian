//! The runner's local socket: what its local callers (the site's
//! configuration play, an operator's shell, the site's image deploy) may
//! ask, which is exactly three things: apply a rendered Wi-Fi configuration
//! to an AP, roll a kept image out to one, and, root alone, record a kept
//! image the site's own deploy staged on one. Only root and processes of the
//! runner's group are served. A connection carries one request; the runner
//! answers with lines as the work goes and a last word.

use std::fs;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};
use u6e_proto::config::config_sha256;
use u6e_proto::mac;
use u6e_proto::msg::{ConfigApplied, RadioConfig};

use crate::frames;
use crate::runner::{Runner, band, mechanism};

/// What a local caller asks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// Sign these radios' configuration for the AP and have it applied.
    Apply {
        ap: String,
        radios: Vec<RadioConfig>,
    },
    /// Roll the kept image out to the AP, through the controller's gate.
    Rollout { ap: String, image_id: String },
    /// The site's deploy staged the kept image on the AP; root's alone.
    Staged { ap: String, image_id: String },
}

/// What the runner answers, in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    /// A line of a rollout's log.
    Line(String),
    /// The AP's answer to the configuration.
    Applied(ConfigApplied),
    /// The last word: whether it went through, and how.
    Done { ok: bool, detail: String },
}

/// Whether a peer of `uid` and `gid` may ask: root, or the runner's group.
pub fn allowed(uid: u32, gid: u32, ours: u32) -> bool {
    uid == 0 || gid == ours
}

async fn ask(socket: &Path, req: &Request) -> io::Result<UnixStream> {
    let mut conn = UnixStream::connect(socket).await?;
    frames::write(&mut conn, req).await?;
    Ok(conn)
}

/// Has the runner on `socket` apply `radios` to `ap`; what the AP did, or
/// why it did not take exactly these.
pub async fn apply(socket: &Path, ap: &str, radios: Vec<RadioConfig>) -> Result<String, String> {
    let sha256 = config_sha256(&radios);
    let req = Request::Apply {
        ap: ap.into(),
        radios,
    };
    let reply = async { frames::read(&mut ask(socket, &req).await?).await };
    let reply = reply
        .await
        .map_err(|e| format!("{}: {e}", socket.display()))?;
    match reply {
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
                .map(|r| format!("{} {}", band(r.radio), mechanism(r.mechanism)))
                .collect();
            Ok(format!(
                "{ap}: {} ({}): {}",
                mac::hex(&sha256),
                how.join(", "),
                c.detail
            ))
        }
        Reply::Done { detail, .. } => Err(detail),
        Reply::Line(l) => Err(format!("the runner answered a log line: {l}")),
    }
}

/// Has the runner on `socket` roll `image_id` out to `ap`, each line of the
/// rollout's log to `line`; how it ended.
pub async fn rollout(
    socket: &Path,
    ap: &str,
    image_id: &str,
    mut line: impl FnMut(&str),
) -> Result<String, String> {
    let req = Request::Rollout {
        ap: ap.into(),
        image_id: image_id.into(),
    };
    let mut conn = ask(socket, &req)
        .await
        .map_err(|e| format!("{}: {e}", socket.display()))?;
    loop {
        match frames::read(&mut conn).await {
            Ok(Reply::Line(l)) => line(&l),
            Ok(Reply::Done { ok: true, detail }) => return Ok(detail),
            Ok(Reply::Done { ok: false, detail }) => return Err(detail),
            Ok(Reply::Applied(_)) => return Err("the runner answered an apply".into()),
            Err(e) => return Err(format!("the runner: {e}")),
        }
    }
}

/// Has the runner on `socket` record that `image_id` was staged on `ap`.
pub async fn staged(socket: &Path, ap: &str, image_id: &str) -> Result<String, String> {
    let req = Request::Staged {
        ap: ap.into(),
        image_id: image_id.into(),
    };
    let reply = async { frames::read(&mut ask(socket, &req).await?).await };
    match reply.await {
        Ok(Reply::Done { ok: true, detail }) => Ok(detail),
        Ok(Reply::Done { ok: false, detail }) => Err(detail),
        Ok(other) => Err(format!("the runner answered {other:?}")),
        Err(e) => Err(format!("{}: {e}", socket.display())),
    }
}

/// How long an apply's caller waits: past the controller's own wait for the
/// AP (`Timing::apply`), whose answer then comes first.
const APPLY_WAIT: Duration = Duration::from_secs(330);
/// How long a rollout's caller waits for the controller to hand it back.
const ASK_WAIT: Duration = Duration::from_secs(30);

/// Serves local callers on `listener` for the life of the process.
pub async fn serve(runner: Arc<Runner>, listener: UnixListener) {
    // SAFETY: getegid has no preconditions.
    let ours = unsafe { libc::getegid() };
    loop {
        match listener.accept().await {
            Ok((conn, _)) => {
                tokio::spawn(caller(Arc::clone(&runner), conn, ours));
            }
            Err(e) => {
                eprintln!("u6e-deploy: local socket: {e}");
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Serves one local caller, if it may ask.
async fn caller(runner: Arc<Runner>, mut conn: UnixStream, ours: u32) {
    let Ok(cred) = conn.peer_cred() else {
        return;
    };
    if !allowed(cred.uid(), cred.gid(), ours) {
        eprintln!("u6e-deploy: a local caller of uid {} refused", cred.uid());
        return;
    }
    let req = match frames::read(&mut conn).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("u6e-deploy: a local caller: {e}");
            return;
        }
    };
    let done = |detail: String| Reply::Done { ok: false, detail };
    match req {
        Request::Apply { ap, radios } => {
            let reply = match runner.apply(&ap, radios) {
                Err(why) => done(why),
                Ok((id, rx)) => match timeout(APPLY_WAIT, rx).await {
                    Ok(Ok(c)) => Reply::Applied(c),
                    _ => {
                        runner.forget(id);
                        done(format!("no answer from the controller in {APPLY_WAIT:?}"))
                    }
                },
            };
            let _ = frames::write(&mut conn, &reply).await;
        }
        Request::Staged { ap, image_id } => {
            let reply = if cred.uid() != 0 {
                done("only root may say what was staged".into())
            } else {
                match runner.staged(&ap, &image_id).await {
                    Ok(()) => Reply::Done {
                        ok: true,
                        detail: format!("{ap} rolls back to {image_id}"),
                    },
                    Err(why) => done(why),
                }
            };
            let _ = frames::write(&mut conn, &reply).await;
        }
        Request::Rollout { ap, image_id } => {
            let (tx, mut rx) = mpsc::channel(256);
            let user = format!("{} (local)", user_name(cred.uid()));
            if let Err(why) = runner.ask(&ap, &image_id, user, tx) {
                let _ = frames::write(&mut conn, &done(why)).await;
                return;
            }
            let handed = done("the controller did not hand the rollout back".into());
            let mut next = timeout(ASK_WAIT, rx.recv()).await.unwrap_or(Some(handed));
            while let Some(reply) = next {
                let last = matches!(reply, Reply::Done { .. });
                if frames::write(&mut conn, &reply).await.is_err() || last {
                    return;
                }
                next = rx.recv().await;
            }
        }
    }
}

/// The name of user `uid`, as /etc/passwd has it.
fn user_name(uid: u32) -> String {
    let passwd = fs::read_to_string("/etc/passwd").unwrap_or_default();
    let name = passwd.lines().find_map(|l| {
        let mut f = l.split(':');
        let name = f.next()?;
        (f.nth(1)?.parse() == Ok(uid)).then(|| name.to_owned())
    });
    name.unwrap_or_else(|| format!("uid {uid}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_and_the_runners_group_may_ask() {
        assert!(allowed(0, 0, 997));
        assert!(allowed(0, 12, 997));
        assert!(allowed(1000, 997, 997));
        assert!(!allowed(1000, 1000, 997));
    }
}
