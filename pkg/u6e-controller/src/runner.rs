//! The deploy runner's session, on the agent listener: the connection whose
//! key is the runner's (`agents`), the only party that originates Wi-Fi
//! configurations and image rollouts.
//!
//! Its configurations, which it signed, are relayed to the AP they are signed
//! for as they are, and only their hash and sequence number stay here; their
//! text (passphrases, keys) goes from this session's buffer, wiped once
//! decoded, to the AP's session, which wipes its frame once sent. The AP's
//! answer goes back to the runner, as does the controller's own when the AP
//! cannot be asked or does not answer in `Timing::apply`. The runner tells its
//! latest configuration for each AP as the session starts; the state asks it
//! to sign that one again when an AP runs another (`Repush`), queues the
//! rollouts admins and the runner's local callers ask for, and sends each its
//! health gate; the runner's log lines and results of them end in the state's
//! rollouts. A result is acknowledged once the policy file holds it, and the
//! runner sends it until then; one for a rollout not held here is kept and
//! recorded as an orphan. A rollout the runner does not say it took on in
//! `Timing::start` is closed as not started (`supervise`). The state files
//! the runner set aside, which it tells at each session, are recorded.

use std::convert::Infallible;
use std::io::{self, ErrorKind};
use std::time::{Duration, SystemTime};

use tokio::io::AsyncReadExt;
use tokio::time::{Instant, interval_at, sleep, sleep_until};
use u6e_proto::PROTOCOL;
use u6e_proto::frame::{decode_frame, zeroize};
use u6e_proto::msg::{RunnerCtlMsg, RunnerHello, RunnerMsg};

use crate::agents::{Conn, Timing, save_policy};
use crate::policy::{ConfigId, Store};
use crate::state::{Discarded, Shared};

/// Closes the rollouts the runner did not take on in `wait`, for the life of
/// the process, whether or not a runner is connected.
pub(crate) async fn supervise(state: Shared, store: Store, wait: Duration) {
    loop {
        sleep((wait / 8).min(Duration::from_secs(15))).await;
        state.write().close_unstarted(SystemTime::now(), wait);
        if state.write().take_dirty() && !save_policy(store.clone(), state.clone()).await {
            state.write().mark_dirty();
        }
    }
}

/// Serves the runner's connection from its version frame to its end.
pub(crate) async fn serve(conn: Conn, state: Shared, timing: Timing, store: Store) {
    let peer = conn.peer;
    let mut s = Session {
        conn,
        state,
        timing,
        store,
        id: 0,
        pings: 0,
    };
    let r = match s.conn.versions().await {
        Ok(PROTOCOL) => s.run().await,
        Ok(theirs) => Err(io::Error::other(format!(
            "speaks protocol {theirs}, this controller {PROTOCOL}"
        ))),
        Err(e) => Err(e),
    };
    let Err(e) = r;
    eprintln!("u6e-controller: deploy runner ({peer}) down: {e}");
    s.state.write().runner_disconnect(s.id);
    s.conn.shutdown().await;
}

struct Session {
    conn: Conn,
    state: Shared,
    timing: Timing,
    /// The policy file, which holds the rollouts.
    store: Store,
    /// The state's id of this session, once it has said Hello.
    id: u64,
    pings: u64,
}

impl Session {
    /// Serves the session until it fails, goes silent or is replaced.
    async fn run(&mut self) -> io::Result<Infallible> {
        let hello = self.hello().await?;
        eprintln!(
            "u6e-controller: deploy runner up from {} ({})",
            self.conn.peer, hello.version
        );
        let mut reg = self.state.write().runner_connect(hello.version);
        self.id = reg.id;
        self.process().await?;

        let start = Instant::now() + self.timing.ping;
        let mut ping = interval_at(start, self.timing.ping);
        let mut chunk = [0; 4096];
        loop {
            let deadline = self.conn.deadline();
            tokio::select! {
                r = self.conn.tls.read(&mut chunk) => {
                    let n = r?;
                    let taken = self.conn.take(&chunk[..n]);
                    zeroize(&mut chunk[..n]);
                    taken?;
                    self.process().await?;
                }
                _ = ping.tick() => {
                    self.pings += 1;
                    self.conn.send(&RunnerCtlMsg::Ping(self.pings)).await?;
                    let expired = std::time::Instant::now();
                    self.state.write().expire_relays(expired, self.timing.apply);
                }
                // The state holds the sender while this session is the runner's.
                Some(msg) = reg.outbox.recv() => self.conn.send(&msg).await?,
                _ = &mut reg.stop => {
                    return Err(io::Error::other("replaced by a newer connection"));
                }
                () = sleep_until(deadline) => {
                    return Err(io::Error::new(ErrorKind::TimedOut, "runner silent"));
                }
            }
        }
    }

    /// Waits for the runner's first message, which must be its Hello.
    async fn hello(&mut self) -> io::Result<RunnerHello> {
        match self
            .conn
            .wait_frame(decode_frame::<RunnerMsg>, "Hello")
            .await?
        {
            RunnerMsg::Hello(h) => Ok(h),
            _ => Err(io::Error::new(ErrorKind::InvalidData, "no Hello first")),
        }
    }

    /// Takes every whole frame received so far, wiping each once decoded. A
    /// result is acknowledged only once the policy file holds it.
    async fn process(&mut self) -> io::Result<()> {
        let mut answers = Vec::new();
        let mut acks = Vec::new();
        while let Some((msg, n)) = decode_frame::<RunnerMsg>(&self.conn.inbuf)? {
            self.conn.consume(n);
            self.conn.last_rx = Instant::now();
            let mut state = self.state.write();
            match msg {
                RunnerMsg::ApplyConfig { id, config } => {
                    if let Err(result) = state.relay(id, config) {
                        answers.push(RunnerCtlMsg::ConfigApplied { id, result });
                    }
                }
                RunnerMsg::RolloutLog { id, line } => state.rollout_log(id, line),
                RunnerMsg::RolloutResult(r) => {
                    acks.push(RunnerCtlMsg::RolloutAck { id: r.id });
                    state.rollout_result(r);
                }
                RunnerMsg::Latest { ap, seq, sha256 } => {
                    state.latest(&ap, ConfigId { sha256, seq });
                }
                RunnerMsg::RolloutAsk { ap, image_id, user } => {
                    state.rollout_ask(&ap, &image_id, &user);
                }
                RunnerMsg::RolloutStarted { id } => state.rollout_started(id),
                RunnerMsg::StateDiscarded {
                    file,
                    detail,
                    at_ms,
                } => state.state_discarded(Discarded {
                    file,
                    detail,
                    at_ms,
                }),
                // A Pong only proves the runner is alive, a second Hello
                // says nothing new.
                _ => {}
            }
        }
        let dirty = self.state.write().take_dirty();
        if dirty && !save_policy(self.store.clone(), self.state.clone()).await {
            // Unacknowledged, the results come again at the next session.
            self.state.write().mark_dirty();
            acks.clear();
        }
        for msg in answers.iter().chain(&acks) {
            self.conn.send(msg).await?;
        }
        Ok(())
    }
}
