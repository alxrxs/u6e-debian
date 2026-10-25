//! The agent listener: one task per connection. The handshake admits only the
//! keys of configured APs and of the deploy runner; the key then says which
//! the peer is, so an AP's key never gets the runner's session (`runner`) and
//! the runner's never an AP's. Each end then states its protocol in the
//! version frame, and an agent of another protocol is turned away, recorded
//! in the state for the metrics and the UI. The session then takes the
//! agent's Hello, applies its key frames, deltas, events, flows and command
//! and configuration results to the state, pings it, sets its tick and flow
//! cadence from the AP's watchers, and passes on what the state queues for it
//! (commands, requests for flows, the runner's configurations). After the
//! first key frame of every connection it gives the AP the policy's blocks,
//! all of them, since the AP keeps them in RAM only, and checks that it runs
//! the configuration it last acknowledged.
//!
//! Received bytes collect in a buffer and are cut into frames only when whole,
//! so a read cancelled by another branch of the session's `select!` never
//! loses its place mid-frame.

use std::convert::Infallible;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, interval_at, sleep, sleep_until, timeout};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use u6e_proto::frame::{decode_frame, frame_body, write_frame, zeroize};
use u6e_proto::msg::{AgentMsg, CtlMsg, Hello};
use u6e_proto::tls::{self, AllowedKeys};
use u6e_proto::{PROTOCOL, version};

use crate::names::Lookups;
use crate::policy::{self, Store};
use crate::runner;
use crate::spectrum::Limits;
use crate::state::{FLOWS_WATCHED, Registration, Shared, TICK_WATCHED};

/// Longest a handshake, or a write to a stalled peer, may take.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// How often a session pings, how long it waits for any word from the peer
/// before dropping it (the agent keeps the same 60 s on its side), how long
/// an operator waits for a command's result and the runner for an AP's
/// answer to a configuration, and when scans stop.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    pub ping: Duration,
    pub silence: Duration,
    pub command: Duration,
    /// An apply that ends in a restart takes the better part of a minute,
    /// and its undo as long again.
    pub apply: Duration,
    pub spectrum: Limits,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            ping: Duration::from_secs(15),
            silence: Duration::from_secs(60),
            command: Duration::from_secs(5),
            apply: Duration::from_secs(300),
            spectrum: Limits::default(),
        }
    }
}

/// What every connection of the listener shares.
#[derive(Clone)]
pub struct Listener {
    pub acceptor: TlsAcceptor,
    /// The keys the handshake admits: every AP's, and the runner's.
    pub allowed: AllowedKeys,
    /// The runner's key: the connection holding it is the runner's, every
    /// other an AP's.
    pub runner: Option<[u8; 32]>,
    pub state: Shared,
    pub timing: Timing,
    pub lookups: Lookups,
    /// The policy file, saved when an AP's acknowledged configuration
    /// changes.
    pub store: Store,
}

/// Accepts agents and the runner for the life of the process.
pub async fn serve(listener: TcpListener, l: Listener) {
    loop {
        match listener.accept().await {
            Ok((sock, peer)) => {
                tokio::spawn(connection(l.clone(), sock, peer));
            }
            Err(e) => {
                // Out of descriptors, most likely: let sessions end first.
                eprintln!("u6e-controller: accept: {e}");
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Serves one connection from the handshake to its end.
async fn connection(l: Listener, sock: TcpStream, peer: SocketAddr) {
    // Each tick is one small record; Nagle would hold the answers back.
    let _ = sock.set_nodelay(true);
    let sock = Counted {
        sock,
        rx: Arc::new(AtomicU64::new(0)),
    };
    let tls = match timeout(IO_TIMEOUT, l.acceptor.accept(sock)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => {
            eprintln!("u6e-controller: {peer}: handshake refused: {e}");
            return;
        }
        Err(_) => {
            eprintln!("u6e-controller: {peer}: handshake timed out");
            return;
        }
    };
    let Some(key) = tls::peer_key(tls.get_ref().1) else {
        return;
    };
    let conn = Conn {
        tls,
        peer,
        inbuf: Vec::new(),
        last_rx: Instant::now(),
        silence: l.timing.silence,
    };
    if l.runner == Some(key) {
        runner::serve(conn, l.state, l.timing).await;
        return;
    }
    // The verifier admitted the key; None only if it left the map since.
    let Some(name) = l.allowed.read().ok().and_then(|m| m.get(&key).cloned()) else {
        eprintln!("u6e-controller: {peer}: key no longer enrolled");
        return;
    };
    let mut s = Session {
        conn,
        name,
        timing: l.timing,
        state: l.state,
        lookups: l.lookups,
        store: l.store,
        id: 0,
        awaiting_key: false,
        synced: false,
        pings: 0,
    };
    let r = match s.agree().await {
        Ok(true) => s.run().await,
        Ok(false) => {
            s.conn.shutdown().await;
            return;
        }
        Err(e) => Err(e),
    };
    let Err(e) = r;
    eprintln!("u6e-controller: {} ({peer}) down: {e}", s.name);
    s.state.write().disconnect(&s.name, s.id);
    s.conn.shutdown().await;
}

/// A connection after its handshake: the TLS stream, the decrypted bytes not
/// yet a whole frame, and when the peer was last heard.
pub(crate) struct Conn {
    pub(crate) tls: TlsStream<Counted>,
    pub(crate) peer: SocketAddr,
    pub(crate) inbuf: Vec<u8>,
    pub(crate) last_rx: Instant,
    silence: Duration,
}

impl Conn {
    /// When the peer, silent since it was last heard, is dropped.
    pub(crate) fn deadline(&self) -> Instant {
        self.last_rx + self.silence
    }

    /// Sends this controller's protocol and reads the peer's, before either
    /// end decodes a message.
    pub(crate) async fn versions(&mut self) -> io::Result<u16> {
        self.send_bytes(&version::frame(PROTOCOL)).await?;
        let read = |buf: &[u8]| Ok(frame_body(buf)?.map(|(b, n)| (version::decode(b), n)));
        self.wait_frame(read, "version frame").await
    }

    /// The next whole frame as `read` makes it out; `what` names it in the
    /// error of a peer that stays silent.
    pub(crate) async fn wait_frame<T>(
        &mut self,
        read: impl Fn(&[u8]) -> io::Result<Option<(T, usize)>>,
        what: &str,
    ) -> io::Result<T> {
        let mut chunk = [0; 4096];
        loop {
            if let Some((v, n)) = read(&self.inbuf)? {
                self.consume(n);
                self.last_rx = Instant::now();
                return Ok(v);
            }
            let n = tokio::time::timeout_at(self.deadline(), self.tls.read(&mut chunk))
                .await
                .map_err(|_| io::Error::new(ErrorKind::TimedOut, format!("no {what}")))??;
            self.take(&chunk[..n])?;
            zeroize(&mut chunk[..n]);
        }
    }

    pub(crate) fn take(&mut self, bytes: &[u8]) -> io::Result<()> {
        if bytes.is_empty() {
            return Err(ErrorKind::UnexpectedEof.into());
        }
        self.inbuf.extend_from_slice(bytes);
        Ok(())
    }

    /// Drops the first `used` bytes, which frames were made of, wiping them
    /// and what the move leaves behind: a runner's frames hold Wi-Fi secrets.
    pub(crate) fn consume(&mut self, used: usize) {
        let len = self.inbuf.len();
        zeroize(&mut self.inbuf[..used]);
        self.inbuf.drain(..used);
        self.inbuf.resize(len, 0);
        zeroize(&mut self.inbuf[len - used..]);
        self.inbuf.truncate(len - used);
    }

    pub(crate) async fn send(&mut self, msg: &impl Serialize) -> io::Result<()> {
        let mut out = Vec::new();
        write_frame(&mut out, msg)?;
        self.send_bytes(&out).await
    }

    /// Sends a message that holds secrets, its encoding wiped once sent.
    pub(crate) async fn send_secret(&mut self, msg: &impl Serialize) -> io::Result<()> {
        let mut out = Vec::new();
        write_frame(&mut out, msg)?;
        let r = self.send_bytes(&out).await;
        zeroize(&mut out);
        r
    }

    pub(crate) async fn send_bytes(&mut self, out: &[u8]) -> io::Result<()> {
        let write = async {
            self.tls.write_all(out).await?;
            self.tls.flush().await
        };
        timeout(IO_TIMEOUT, write)
            .await
            .map_err(|_| io::Error::new(ErrorKind::TimedOut, "peer not reading"))?
    }

    pub(crate) async fn shutdown(&mut self) {
        let _ = timeout(IO_TIMEOUT, self.tls.shutdown()).await;
    }
}

/// One agent's connection after the handshake.
struct Session {
    conn: Conn,
    /// The AP the key belongs to.
    name: String,
    timing: Timing,
    state: Shared,
    lookups: Lookups,
    store: Store,
    /// The state's id of this session, once it has said Hello.
    id: u64,
    /// A key frame was asked for and has not come yet.
    awaiting_key: bool,
    /// The policy's blocks were given to the AP, after its first key frame.
    synced: bool,
    pings: u64,
}

impl Session {
    /// Agrees on the protocol; false turns the agent away. The log tells of
    /// an AP's protocol when it changes, not at each redial of an old agent.
    async fn agree(&mut self) -> io::Result<bool> {
        let theirs = self.conn.versions().await?;
        if theirs == PROTOCOL {
            return Ok(true);
        }
        if self.state.write().refuse(&self.name, theirs) {
            eprintln!(
                "u6e-controller: {} ({}) speaks protocol {theirs}, this controller {PROTOCOL}: \
                 turned away until they match",
                self.name, self.conn.peer
            );
        }
        Ok(false)
    }

    /// Serves the session until it fails, goes silent or is replaced.
    async fn run(&mut self) -> io::Result<Infallible> {
        let hello = self.hello().await?;
        let agent = hello.agent.clone();
        let Some(mut reg) = self.state.write().connect(&self.name, hello) else {
            return Err(io::Error::other("not a configured AP"));
        };
        self.id = reg.id;
        self.count_into(&reg);
        eprintln!(
            "u6e-controller: {} up from {} (agent {agent})",
            self.name, self.conn.peer
        );
        if *reg.tick.borrow_and_update() == TICK_WATCHED {
            self.send(&CtlMsg::SetTick { secs: TICK_WATCHED }).await?;
        }
        if *reg.cadence.borrow_and_update() == FLOWS_WATCHED {
            let secs = FLOWS_WATCHED;
            self.send(&CtlMsg::FlowCadence { secs }).await?;
        }
        // Frames that came in the Hello's record.
        self.process().await?;

        let start = Instant::now() + self.timing.ping;
        let mut ping = interval_at(start, self.timing.ping);
        let mut chunk = [0; 4096];
        loop {
            let deadline = self.conn.deadline();
            tokio::select! {
                r = self.conn.tls.read(&mut chunk) => {
                    self.conn.take(&chunk[..r?])?;
                    self.process().await?;
                }
                _ = ping.tick() => {
                    self.pings += 1;
                    self.send(&CtlMsg::Ping(self.pings)).await?;
                }
                r = reg.tick.changed() => {
                    r.map_err(io::Error::other)?;
                    let secs = *reg.tick.borrow_and_update();
                    self.send(&CtlMsg::SetTick { secs }).await?;
                }
                r = reg.cadence.changed() => {
                    r.map_err(io::Error::other)?;
                    let secs = *reg.cadence.borrow_and_update();
                    self.send(&CtlMsg::FlowCadence { secs }).await?;
                }
                // The state holds the sender while this session is the AP's.
                Some(msg) = reg.outbox.recv() => self.send(&msg).await?,
                _ = &mut reg.stop => {
                    return Err(io::Error::other("replaced by a newer connection"));
                }
                () = sleep_until(deadline) => {
                    return Err(io::Error::new(ErrorKind::TimedOut, "agent silent"));
                }
            }
        }
    }

    /// Waits for the agent's first message, which must be its Hello.
    async fn hello(&mut self) -> io::Result<Hello> {
        match self
            .conn
            .wait_frame(decode_frame::<AgentMsg>, "Hello")
            .await?
        {
            AgentMsg::Hello(h) => Ok(h),
            _ => Err(io::Error::new(ErrorKind::InvalidData, "no Hello first")),
        }
    }

    /// Moves the connection's byte count to the AP's counter, which counts
    /// from here on.
    fn count_into(&mut self, reg: &Registration) {
        let sock = self.conn.tls.get_mut().0;
        reg.rx_bytes
            .fetch_add(sock.rx.load(Ordering::Relaxed), Ordering::Relaxed);
        sock.rx = Arc::clone(&reg.rx_bytes);
    }

    /// Applies every whole frame received so far; a delta that does not fit,
    /// or a key frame that is not valid, asks once for a key frame. The first
    /// key frame applied is followed by the policy's blocks and the check of
    /// the installed configuration, and flows by lookups of the names of the
    /// addresses they show. A change to the policy is saved.
    async fn process(&mut self) -> io::Result<()> {
        let mut used = 0;
        let mut want_key = false;
        let mut sync = None;
        let mut flows = false;
        while let Some((msg, n)) = decode_frame::<AgentMsg>(&self.conn.inbuf[used..])? {
            used += n;
            self.conn.last_rx = Instant::now();
            let key = matches!(msg, AgentMsg::Key(_));
            if key {
                self.awaiting_key = false;
            }
            flows |= matches!(msg, AgentMsg::Flows(_));
            let mut state = self.state.write();
            let gap = state.apply(&self.name, self.id, msg).is_err();
            if key && !gap && !self.synced {
                self.synced = true;
                sync = state.sync_blocks(&self.name, self.id);
                state.check_installed(&self.name, self.id);
            }
            drop(state);
            if gap && !self.awaiting_key {
                self.awaiting_key = true;
                want_key = true;
            }
        }
        self.conn.inbuf.drain(..used);
        if self.state.write().take_dirty() {
            tokio::spawn(save_policy(self.store.clone(), self.state.clone()));
        }
        if want_key {
            self.send(&CtlMsg::WantKey).await?;
        }
        if let Some(msg) = &sync {
            self.send(msg).await?;
        }
        if flows {
            self.look_up_names();
        }
        Ok(())
    }

    /// Looks up the names now due, each in a task of its own.
    fn look_up_names(&self) {
        let due = self.state.write().names_due(std::time::Instant::now());
        for ip in due {
            let (state, lookups) = (self.state.clone(), self.lookups.clone());
            tokio::spawn(async move {
                let name = lookups.reverse(ip).await;
                state.write().named(ip, name, std::time::Instant::now());
            });
        }
    }

    /// Sends `msg`; a configuration's frame is wiped once sent.
    async fn send(&mut self, msg: &CtlMsg) -> io::Result<()> {
        if matches!(msg, CtlMsg::ApplyConfig(_)) {
            self.conn.send_secret(msg).await
        } else {
            self.conn.send(msg).await
        }
    }
}

/// Saves the policy as the state holds it now, one save at a time.
async fn save_policy(store: Store, state: Shared) {
    let path = store.lock().await;
    let p = state.read().policy();
    if let Err(e) = policy::write(&path, p).await {
        eprintln!(
            "u6e-controller: {}: the policy was not saved: {e}",
            path.display()
        );
    }
}

/// A socket that counts what it receives, TLS records included: what the
/// link costs on the wire.
pub(crate) struct Counted {
    sock: TcpStream,
    rx: Arc<AtomicU64>,
}

impl AsyncRead for Counted {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.sock).poll_read(cx, buf);
        let n = buf.filled().len() - before;
        self.rx.fetch_add(n as u64, Ordering::Relaxed);
        r
    }
}

impl AsyncWrite for Counted {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.sock).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.sock).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.sock).poll_shutdown(cx)
    }
}
