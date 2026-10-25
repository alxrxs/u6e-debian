//! The agent's telemetry link: it dials the controller over the pinned-key TLS
//! of `u6e_proto::tls`, and each end states its protocol in the version frame;
//! a controller of another protocol is not spoken to. The agent then says who
//! it is, sends a snapshot every tick (a delta against the previous one, a
//! full key frame now and then) and the events as they happen. The controller
//! sets the tick, asks for key frames and pings; a silent or broken connection
//! is dropped and dialed again. The wait before a redial doubles from 1 s to
//! 30 s until a session is useful (the controller said something in it), so a
//! controller that takes each session and drops it is not redialed at once.
//!
//! One thread owns the connection and waits with `poll` for the socket, an
//! event or the next tick, so an event leaves at once without a polling loop.
//! Received bytes are decrypted into a buffer and cut into frames only when
//! whole, so no read can stop mid-frame. A second thread moves events into a
//! ring of the newest 256 whether or not the link is up.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::ops::RangeInclusive;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use std::{fs, mem, thread};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};
use u6e_proto::frame::{decode_frame, frame_body, write_frame};
use u6e_proto::msg::{AgentMsg, CommandResult, CtlMsg, Event, Hello, Snapshot};
use u6e_proto::tls::{self, Identity};
use u6e_proto::{PROTOCOL, delta, version};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest the handshake or the controller's version frame may take, or a
/// write wait for the socket.
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// The tick until the controller sets one: the estate's scrape interval.
const TICK_DEFAULT: Duration = Duration::from_secs(15);
const KEY_EVERY: Duration = Duration::from_secs(60);
/// An event this close to the next tick waits and rides in its record.
const COALESCE: Duration = Duration::from_millis(50);
/// The controller pings every 15 s; this long without a word is a dead session.
const SILENCE: Duration = Duration::from_secs(60);
const RING_CAP: usize = 256;

/// What the link needs to reach and recognise the controller.
pub struct Config {
    /// `host:port`, resolved at each connect.
    pub controller: String,
    pub identity: Identity,
    pub controller_key: [u8; 32],
    pub hello: Hello,
    /// How long the controller may say nothing before the session is taken
    /// for dead and dialed again.
    pub silence: Duration,
    /// The wait before a redial: the start after a useful session, doubled
    /// after each dial that brought none, up to the end.
    pub backoff: RangeInclusive<Duration>,
}

impl Config {
    pub fn new(
        controller: String,
        identity: Identity,
        controller_key: [u8; 32],
        hello: Hello,
    ) -> Self {
        Config {
            controller,
            identity,
            controller_key,
            hello,
            silence: SILENCE,
            backoff: BACKOFF_MIN..=BACKOFF_MAX,
        }
    }
}

/// Runs the link for the life of the process. `snapshot` is called with the
/// sequence number of each snapshot, only while connected.
pub fn run(cfg: Config, snapshot: impl FnMut(u64) -> Snapshot, events: Receiver<Event>) -> ! {
    let events = Arc::new(Mutex::new(Some(events)));
    run_with(cfg, snapshot, || Ring::relay(&events))
}

/// The link. `relay` starts the ring the events go through; it is tried again
/// before each connection until it works, and meanwhile the link carries the
/// snapshots alone. Nothing here may stop the agent: it has other duties.
fn run_with(
    cfg: Config,
    mut snapshot: impl FnMut(u64) -> Snapshot,
    mut relay: impl FnMut() -> io::Result<Arc<Ring>>,
) -> ! {
    let client = tls::client_config(&cfg.identity, cfg.controller_key);
    let mut ring = None;
    let mut backoff = *cfg.backoff.start();
    // A failure that repeats is logged once, not at every attempt.
    let (mut failed, mut relay_failed) = (String::new(), String::new());
    loop {
        if ring.is_none() {
            match relay() {
                Ok(r) => ring = Some(r),
                Err(e) if e.to_string() != relay_failed => {
                    relay_failed = e.to_string();
                    eprintln!("u6e-agent: link events: {e}; snapshots only until they start");
                }
                Err(_) => {}
            }
        }
        // A session the controller said nothing in counts as a failed dial.
        let failure = match connect(&cfg.controller, &client) {
            Ok(mut s) => {
                let Err(e) = s.serve(&cfg, ring.as_deref(), &mut snapshot);
                if s.heard {
                    eprintln!("u6e-agent: link to {} down: {e}", cfg.controller);
                    backoff = *cfg.backoff.start();
                    failed.clear();
                    None
                } else {
                    Some(format!(
                        "session ended before the controller said a word: {e}"
                    ))
                }
            }
            Err(e) => Some(e.to_string()),
        };
        if let Some(e) = failure.filter(|e| *e != failed) {
            eprintln!("u6e-agent: link to {}: {e}", cfg.controller);
            failed = e;
        }
        thread::sleep(backoff);
        backoff = (backoff * 2).min(*cfg.backoff.end());
    }
}

/// Events not yet sent, the newest [`RING_CAP`], and the pipe that wakes the
/// link when one arrives.
struct Ring {
    events: Mutex<VecDeque<Event>>,
    wake_rx: UnixStream,
    wake_tx: UnixStream,
}

impl Ring {
    /// Starts the thread that moves events from the receiver in `events`
    /// into the ring. It drains the channel during an outage too, so what an
    /// outage loses is the oldest events (the ring's choice), not the newest
    /// (a full channel's). The receiver stays in `events` until the thread
    /// runs, so a start that fails can be tried again.
    fn relay(events: &Arc<Mutex<Option<Receiver<Event>>>>) -> io::Result<Arc<Ring>> {
        let (wake_rx, wake_tx) = UnixStream::pair()?;
        wake_rx.set_nonblocking(true)?;
        wake_tx.set_nonblocking(true)?;
        let ring = Arc::new(Ring {
            events: Mutex::new(VecDeque::new()),
            wake_rx,
            wake_tx,
        });
        let (r, events) = (Arc::clone(&ring), Arc::clone(events));
        thread::Builder::new()
            .name("link-events".into())
            .spawn(move || {
                let rx = events.lock().unwrap_or_else(PoisonError::into_inner).take();
                rx.into_iter().flatten().for_each(|ev| r.push(ev));
            })?;
        Ok(ring)
    }

    fn lock(&self) -> MutexGuard<'_, VecDeque<Event>> {
        self.events.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn push(&self, ev: Event) {
        let mut q = self.lock();
        if q.len() == RING_CAP {
            q.pop_front();
        }
        q.push_back(ev);
        drop(q);
        // A full pipe already holds a wake-up.
        let _ = (&self.wake_tx).write(&[0]);
    }

    fn take(&self) -> VecDeque<Event> {
        mem::take(&mut *self.lock())
    }

    /// Empties the wake-up pipe; the caller then looks at the ring.
    fn clear_wake(&self) {
        let mut buf = [0; 64];
        while matches!((&self.wake_rx).read(&mut buf), Ok(n) if n > 0) {}
    }
}

/// Opens the TCP connection, completes the TLS handshake and agrees on the
/// protocol.
fn connect(controller: &str, client: &Arc<ClientConfig>) -> io::Result<Session> {
    let mut err = io::Error::new(ErrorKind::NotFound, "no address");
    let mut found = None;
    for addr in controller.to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(s) => {
                found = Some(s);
                break;
            }
            Err(e) => err = e,
        }
    }
    let mut sock = found.ok_or(err)?;
    sock.set_nodelay(true)?;
    sock.set_read_timeout(Some(IO_TIMEOUT))?;
    sock.set_write_timeout(Some(IO_TIMEOUT))?;
    // The verifier pins the key; the name only has to be well formed.
    let host = controller.rsplit_once(':').map_or(controller, |(h, _)| h);
    let name = ServerName::try_from(host.trim_matches(['[', ']']).to_owned())
        .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?;
    let mut conn = ClientConnection::new(Arc::clone(client), name).map_err(io::Error::other)?;
    while conn.is_handshaking() {
        conn.complete_io(&mut sock)?;
    }
    let mut s = Session::new(conn, sock);
    s.agree()?;
    Ok(s)
}

/// The tick the controller asked for, kept within 1 to 60 s.
fn clamp_tick(secs: u16) -> Duration {
    Duration::from_secs(u64::from(secs.clamp(1, 60)))
}

/// Whether this tick sends a key frame whatever the snapshot; otherwise it
/// does only when no delta can carry the change.
fn key_due(want_key: bool, since_key: Duration) -> bool {
    want_key || since_key >= KEY_EVERY
}

/// One connection: what has been sent and when the next tick is due.
struct Session {
    conn: ClientConnection,
    sock: TcpStream,
    /// Decrypted bytes not yet a whole frame.
    inbuf: Vec<u8>,
    tick: Duration,
    due: Instant,
    last_tick: Instant,
    last_key: Instant,
    last_rx: Instant,
    want_key: bool,
    /// The last snapshot sent: the base of the next delta.
    prev: Option<Snapshot>,
    seq: u64,
    /// The controller has sent a message: the session is a useful one.
    heard: bool,
}

impl Session {
    fn new(conn: ClientConnection, sock: TcpStream) -> Self {
        let now = Instant::now();
        Session {
            conn,
            sock,
            inbuf: Vec::new(),
            tick: TICK_DEFAULT,
            due: now,
            last_tick: now,
            last_key: now,
            last_rx: now,
            want_key: false,
            prev: None,
            seq: 0,
            heard: false,
        }
    }

    /// Sends this agent's protocol and reads the controller's, before either
    /// end decodes a message: a controller of another protocol, or of none
    /// (protocol 0, from before the version frame), is not spoken to.
    fn agree(&mut self) -> io::Result<()> {
        self.send(&version::frame(PROTOCOL))?;
        let theirs = self.version().map_err(|e| {
            io::Error::new(e.kind(), format!("no protocol from the controller: {e}"))
        })?;
        if theirs != PROTOCOL {
            let e = format!("the controller speaks protocol {theirs}, this agent {PROTOCOL}");
            return Err(io::Error::new(ErrorKind::InvalidData, e));
        }
        Ok(())
    }

    /// The protocol the controller's first frame states.
    fn version(&mut self) -> io::Result<u16> {
        loop {
            let closed = self.take_plaintext()?;
            if let Some((body, n)) = frame_body(&self.inbuf)? {
                let v = version::decode(body);
                self.inbuf.drain(..n);
                return Ok(v);
            }
            if closed {
                return Err(ErrorKind::UnexpectedEof.into());
            }
            self.read_records()?;
        }
    }

    /// Serves the connection until it fails; without a ring, the snapshots
    /// alone.
    fn serve(
        &mut self,
        cfg: &Config,
        ring: Option<&Ring>,
        snapshot: &mut impl FnMut(u64) -> Snapshot,
    ) -> io::Result<Infallible> {
        let mut out = Vec::new();
        write_frame(&mut out, &AgentMsg::Hello(cfg.hello.clone()))?;
        let mut up = false;
        loop {
            if let Some(r) = ring {
                r.clear_wake();
            }
            let now = Instant::now();
            let ticked = now >= self.due;
            if ticked {
                self.snapshot_into(&mut out, now, snapshot)?;
            }
            if ticked || self.due - now > COALESCE {
                for ev in ring.map(Ring::take).unwrap_or_default() {
                    write_frame(&mut out, &AgentMsg::Event(ev))?;
                }
            }
            if !out.is_empty() {
                self.send(&out)?;
                out.clear();
            }
            // On the first pass, what came with the version frame.
            self.process()?;
            if self.wait(ring, cfg.silence) {
                self.receive()?;
            }
            if self.heard && !up {
                up = true;
                eprintln!("u6e-agent: link to {} up", cfg.controller);
            }
            if self.last_rx.elapsed() >= cfg.silence {
                return Err(io::Error::new(ErrorKind::TimedOut, "controller silent"));
            }
        }
    }

    /// Appends this tick's snapshot, as a key frame or a delta, to `out`.
    fn snapshot_into(
        &mut self,
        out: &mut Vec<u8>,
        now: Instant,
        snapshot: &mut impl FnMut(u64) -> Snapshot,
    ) -> io::Result<()> {
        self.seq += 1;
        let next = snapshot(self.seq);
        let delta = self
            .prev
            .take()
            .filter(|_| !key_due(self.want_key, now - self.last_key))
            .and_then(|prev| delta::diff(&prev, &next));
        match delta {
            Some(d) => write_frame(out, &AgentMsg::Delta(d))?,
            None => {
                write_frame(out, &AgentMsg::Key(next.clone()))?;
                self.last_key = now;
                self.want_key = false;
            }
        }
        self.prev = Some(next);
        self.last_tick = now;
        self.due = now + self.tick;
        Ok(())
    }

    /// Waits for the socket (true), an event or the next deadline (false).
    fn wait(&self, ring: Option<&Ring>, silence: Duration) -> bool {
        let deadline = self.due.min(self.last_rx + silence);
        let left = deadline.saturating_duration_since(Instant::now());
        let ms = i32::try_from(left.as_micros().div_ceil(1000)).unwrap_or(i32::MAX);
        // poll skips a negative fd: without a ring, the socket alone.
        let wake = ring.map_or(-1, |r| r.wake_rx.as_raw_fd());
        let mut fds = [self.sock.as_raw_fd(), wake].map(|fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        });
        // SAFETY: `fds` is a valid array of two pollfds for the call.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, ms) };
        n > 0 && fds[0].revents != 0
    }

    /// Writes `buf` through TLS and waits until the socket took it; a buffer
    /// up to the record size limit goes out as one record.
    fn send(&mut self, mut buf: &[u8]) -> io::Result<()> {
        while !buf.is_empty() {
            let n = self.conn.writer().write(buf)?;
            buf = &buf[n..];
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        while self.conn.wants_write() {
            self.conn.write_tls(&mut self.sock)?;
        }
        Ok(())
    }

    /// Takes in what the readable socket holds and acts on every whole frame
    /// received so far, those that came with the controller's close too.
    fn receive(&mut self) -> io::Result<()> {
        self.read_records()?;
        let closed = self.take_plaintext()?;
        self.process()?;
        if closed {
            return Err(ErrorKind::UnexpectedEof.into());
        }
        Ok(())
    }

    /// Reads what the socket holds into the TLS session.
    fn read_records(&mut self) -> io::Result<()> {
        if self.conn.read_tls(&mut self.sock)? == 0 {
            return Err(ErrorKind::UnexpectedEof.into());
        }
        self.conn.process_new_packets().map_err(io::Error::other)?;
        // A key update asks for an answer.
        self.flush()
    }

    /// Moves the decrypted bytes to `inbuf`; true when the controller closed
    /// the session after them.
    fn take_plaintext(&mut self) -> io::Result<bool> {
        match self.conn.reader().read_to_end(&mut self.inbuf) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Acts on every whole frame in `inbuf`.
    fn process(&mut self) -> io::Result<()> {
        let mut used = 0;
        while let Some((msg, n)) = decode_frame::<CtlMsg>(&self.inbuf[used..])? {
            used += n;
            self.last_rx = Instant::now();
            self.heard = true;
            self.handle(msg)?;
        }
        self.inbuf.drain(..used);
        Ok(())
    }

    fn handle(&mut self, msg: CtlMsg) -> io::Result<()> {
        match msg {
            CtlMsg::SetTick { secs } => {
                self.tick = clamp_tick(secs);
                self.due = self.last_tick + self.tick;
            }
            CtlMsg::WantKey => {
                self.want_key = true;
                self.due = Instant::now();
            }
            CtlMsg::Ping(n) => {
                let mut out = Vec::new();
                write_frame(&mut out, &AgentMsg::Pong(n))?;
                self.send(&out)?;
            }
            // Every command is answered, so the controller never waits out
            // one this agent does not carry out.
            CtlMsg::Command(c) => {
                let result = CommandResult {
                    id: c.id,
                    ok: false,
                    detail: "not implemented".into(),
                };
                let mut out = Vec::new();
                write_frame(&mut out, &AgentMsg::Result(result))?;
                self.send(&out)?;
            }
            // This agent reads no flows, so it has none to send.
            CtlMsg::WantFlows { .. } | CtlMsg::FlowCadence { .. } => {}
            // A newer controller's messages mean nothing to this agent.
            _ => {}
        }
        Ok(())
    }
}

/// What this AP tells the controller about itself: its host name and kernel,
/// this agent's version, and the image identity `/etc/u6e-image` records.
pub fn local_hello() -> Hello {
    let read = |p| fs::read_to_string(p).unwrap_or_default().trim().to_owned();
    let image = read("/etc/u6e-image");
    Hello {
        ap: read("/proc/sys/kernel/hostname"),
        hostapd: hostapd_version(&image),
        manifest: image,
        kernel: read("/proc/sys/kernel/osrelease"),
        agent: env!("CARGO_PKG_VERSION").to_owned(),
    }
}

/// The `hostapd: <version>` line of an `/etc/u6e-image`.
fn hostapd_version(image: &str) -> String {
    image
        .lines()
        .find_map(|l| l.strip_prefix("hostapd:"))
        .map_or_else(String::new, |v| v.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::{SocketAddr, TcpListener};
    use std::sync::RwLock;
    use std::sync::mpsc::{self, SyncSender, sync_channel};

    use rustls::{ServerConfig, ServerConnection};
    use u6e_proto::msg::{Bss, Command, CommandKind, EventKind, RateMode, Station, Temp};
    use u6e_proto::version;

    // A throwaway Ed25519 key made for tests (the same as in u6e-proto's tls
    // tests); it protects nothing.
    const KEY_AGENT: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINI3m11iy47fpTD0dKK5Q2ViMRZef+/6f8mIN8n95xZz\n-----END PRIVATE KEY-----\n";

    /// How long a test waits for something that should happen, before failing.
    const WAIT: Duration = Duration::from_secs(20);
    /// How often a fake looks for a new connection: how late it may see one.
    const ACCEPT_POLL: Duration = Duration::from_millis(10);

    /// A new random Ed25519 key in PKCS#8 PEM. Each fake controller has its own:
    /// agents of finished tests keep dialing (the link never returns), and one
    /// that reaches a later test's port must fail that fake's handshake.
    fn random_pem() -> String {
        use std::hash::{BuildHasher, Hasher, RandomState};
        // The PKCS#8 header of an Ed25519 key, then a 32-byte seed: 48 bytes,
        // so the base64 below needs no padding.
        let mut der = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        for _ in 0..4 {
            der.extend(RandomState::new().build_hasher().finish().to_le_bytes());
        }
        const ABC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let b64: String = der
            .chunks(3)
            .flat_map(|c| {
                let n = c.iter().fold(0u32, |n, &b| n << 8 | u32::from(b));
                (0..4).map(move |i| ABC[(n >> (18 - 6 * i) & 63) as usize] as char)
            })
            .collect();
        format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n")
    }

    fn blank(seq: u64) -> Snapshot {
        Snapshot {
            seq,
            uptime_s: seq as u32,
            load_milli: 0,
            mem_avail_kb: 0,
            nss_load_pct: 0,
            temps: Vec::new(),
            radios: Vec::new(),
            bsss: Vec::new(),
            stations: Vec::new(),
        }
    }

    fn station() -> Station {
        Station {
            mac: [2, 0, 0, 0, 0, 8],
            bss: 0,
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
            inactive_ms: 0,
            connected_s: 0,
            vlan: 0,
        }
    }

    fn event(at_ms: u64) -> Event {
        Event {
            at_ms,
            kind: EventKind::RadioUp { phy: "phy0".into() },
        }
    }

    /// The controller end of the link.
    struct Fake {
        listener: TcpListener,
        server: Arc<ServerConfig>,
        pem: String,
        key: [u8; 32],
    }

    struct Peer {
        conn: ServerConnection,
        sock: TcpStream,
        buf: Vec<u8>,
    }

    impl Fake {
        fn bind(addr: &str, pem: String) -> io::Result<Self> {
            let listener = TcpListener::bind(addr)?;
            listener.set_nonblocking(true)?;
            let ap = Identity::from_pem(KEY_AGENT).unwrap();
            let ctl = Identity::from_pem(&pem).unwrap();
            let allowed = HashMap::from([(ap.public_key(), "ap1".to_owned())]);
            Ok(Fake {
                listener,
                server: tls::server_config(&ctl, Arc::new(RwLock::new(allowed))),
                key: ctl.public_key(),
                pem,
            })
        }

        fn new() -> Self {
            Self::bind("127.0.0.1:0", random_pem()).unwrap()
        }

        fn addr(&self) -> SocketAddr {
            self.listener.local_addr().unwrap()
        }

        /// The fake's successor on the same port and key, as after a restart.
        fn restart(self) -> Self {
            let (addr, pem) = (self.addr().to_string(), self.pem.clone());
            drop(self);
            let start = Instant::now();
            loop {
                match Self::bind(&addr, pem.clone()) {
                    Ok(f) => return f,
                    Err(e) if start.elapsed() < WAIT => {
                        eprintln!("rebind {addr}: {e}");
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("rebind {addr}: {e}"),
                }
            }
        }

        fn accept_tcp(&self) -> TcpStream {
            let start = Instant::now();
            loop {
                match self.listener.accept() {
                    Ok((sock, _)) => return sock,
                    Err(e) if e.kind() == ErrorKind::WouldBlock && start.elapsed() < WAIT => {
                        thread::sleep(ACCEPT_POLL);
                    }
                    Err(e) => panic!("no agent connected: {e}"),
                }
            }
        }

        /// The TLS session on `sock`, or `None` when the dialer was not an
        /// agent of this fake (one left over from another test).
        fn handshake(&self, mut sock: TcpStream) -> Option<Peer> {
            sock.set_nonblocking(false).unwrap();
            sock.set_read_timeout(Some(WAIT)).unwrap();
            let mut conn = ServerConnection::new(Arc::clone(&self.server)).unwrap();
            while conn.is_handshaking() {
                conn.complete_io(&mut sock).ok()?;
            }
            Some(Peer {
                conn,
                sock,
                buf: Vec::new(),
            })
        }

        /// The next session of an agent of this fake, TLS alone, and when its
        /// connection came.
        fn accept_tls(&self) -> (Peer, Instant) {
            loop {
                let sock = self.accept_tcp();
                let at = Instant::now();
                if let Some(p) = self.handshake(sock) {
                    return (p, at);
                }
            }
        }

        /// The next session, the protocols agreed.
        fn accept(&self) -> Peer {
            let (mut p, _) = self.accept_tls();
            assert_eq!(p.agree(PROTOCOL), PROTOCOL);
            p
        }
    }

    impl Peer {
        /// What `take` makes of the frames received once it makes something,
        /// or the error that ended the session.
        fn next<T>(&mut self, take: impl Fn(&[u8]) -> Option<(T, usize)>) -> io::Result<T> {
            loop {
                // rustls may hold decrypted data the socket no longer shows.
                let closed = match self.conn.reader().read_to_end(&mut self.buf) {
                    Ok(_) => true,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => false,
                    Err(e) => return Err(e),
                };
                if let Some((v, n)) = take(&self.buf) {
                    self.buf.drain(..n);
                    return Ok(v);
                }
                if closed || self.conn.read_tls(&mut self.sock)? == 0 {
                    return Err(ErrorKind::UnexpectedEof.into());
                }
                self.conn.process_new_packets().map_err(io::Error::other)?;
            }
        }

        fn recv(&mut self) -> AgentMsg {
            self.next(|b| decode_frame(b).unwrap())
                .expect("agent closed")
        }

        /// The body of the agent's next frame, undecoded.
        fn recv_body(&mut self) -> io::Result<Vec<u8>> {
            self.next(|b| frame_body(b).unwrap().map(|(body, n)| (body.to_vec(), n)))
        }

        /// Sends the version frame of `protocol`; the protocol the agent's states.
        fn agree(&mut self, protocol: u16) -> u16 {
            self.send_bytes(&version::frame(protocol));
            version::decode(&self.recv_body().expect("no version frame"))
        }

        /// Asserts that the agent closes the session without another frame.
        fn ends(&mut self) {
            match self.recv_body() {
                Err(e) => assert!(
                    matches!(
                        e.kind(),
                        ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset
                    ),
                    "{e}"
                ),
                Ok(body) => panic!("a frame of {} B, not the end", body.len()),
            }
        }

        fn send(&mut self, msg: CtlMsg) {
            let mut out = Vec::new();
            write_frame(&mut out, &msg).unwrap();
            self.send_bytes(&out);
        }

        fn send_bytes(&mut self, bytes: &[u8]) {
            self.conn.writer().write_all(bytes).unwrap();
            while self.conn.wants_write() {
                self.conn.write_tls(&mut self.sock).unwrap();
            }
        }

        fn expect_key(&mut self, seq: u64) {
            assert_eq!(self.recv(), AgentMsg::Key(blank(seq)));
        }

        fn expect_delta(&mut self, seq: u64) {
            match self.recv() {
                AgentMsg::Delta(d) => {
                    assert_eq!((d.seq, d.base), (seq, seq - 1));
                    assert_eq!(delta::apply(&blank(seq - 1), &d), Ok(blank(seq)));
                }
                other => panic!("expected delta {seq}, got {other:?}"),
            }
        }

        /// Hello, then the first key frame.
        fn start(&mut self) {
            assert!(matches!(self.recv(), AgentMsg::Hello(_)));
            self.expect_key(1);
        }
    }

    /// A link running in its own thread (it lives until the test process ends).
    struct Agent {
        events: SyncSender<Event>,
        /// Each snapshot taken: its seq and when.
        ticks: mpsc::Receiver<(u64, Instant)>,
        ring: Arc<Ring>,
    }

    impl Agent {
        fn spawn(fake: &Fake, snapshot: impl FnMut(u64) -> Snapshot + Send + 'static) -> Self {
            Self::spawn_with(fake, 0, |_| {}, snapshot)
        }

        /// An agent whose event relay fails to start the first
        /// `relay_failures` times, its configuration changed by `tweak`.
        fn spawn_with(
            fake: &Fake,
            relay_failures: u32,
            tweak: impl FnOnce(&mut Config),
            snapshot: impl FnMut(u64) -> Snapshot + Send + 'static,
        ) -> Self {
            let (events, rx) = sync_channel(256);
            let (tick_tx, ticks) = mpsc::channel();
            let ring = Ring::relay(&Arc::new(Mutex::new(Some(rx)))).unwrap();
            let mut cfg = Config::new(
                fake.addr().to_string(),
                Identity::from_pem(KEY_AGENT).unwrap(),
                fake.key,
                Hello {
                    ap: "ap1".into(),
                    manifest: "image: test".into(),
                    kernel: "6.12".into(),
                    hostapd: "2.11".into(),
                    agent: "1.0.0".into(),
                },
            );
            tweak(&mut cfg);
            let r = Arc::clone(&ring);
            let mut failures = relay_failures;
            let relay = move || match failures.checked_sub(1) {
                Some(left) => {
                    failures = left;
                    Err(io::Error::other("no threads left"))
                }
                None => Ok(Arc::clone(&r)),
            };
            let mut snapshot = snapshot;
            thread::spawn(move || {
                let snap = move |seq| {
                    let _ = tick_tx.send((seq, Instant::now()));
                    snapshot(seq)
                };
                run_with(cfg, snap, relay)
            });
            Agent {
                events,
                ticks,
                ring,
            }
        }

        /// When snapshot `seq` was taken.
        fn tick_at(&self, seq: u64) -> Instant {
            let (got, at) = self.ticks.recv_timeout(WAIT).expect("no snapshot");
            assert_eq!(got, seq);
            at
        }
    }

    fn secs(a: Instant, b: Instant) -> f64 {
        b.duration_since(a).as_secs_f64()
    }

    /// A backoff short enough for a test to watch it reach its cap.
    const QUICK: RangeInclusive<Duration> = Duration::from_millis(25)..=Duration::from_millis(300);
    /// What a dial may take beyond its backoff on a loaded host.
    const SLACK: f64 = 0.4;

    /// When each of the next `n` sessions was dialed, `serve` given each.
    fn dial_times(fake: &Fake, n: usize, mut serve: impl FnMut(usize, Peer)) -> Vec<Instant> {
        (0..n)
            .map(|i| {
                let (p, at) = fake.accept_tls();
                serve(i, p);
                at
            })
            .collect()
    }

    /// Asserts that the dials came at least the doubling backoff apart, and
    /// once it reached its cap, no further.
    fn assert_backs_off(at: &[Instant], backoff: &RangeInclusive<Duration>) {
        let gaps: Vec<f64> = at.windows(2).map(|w| secs(w[0], w[1])).collect();
        let mut wait = *backoff.start();
        for (i, &gap) in gaps.iter().enumerate() {
            let want = wait.as_secs_f64();
            // A connection is seen up to a poll late, the next one at once.
            let floor = want - ACCEPT_POLL.as_secs_f64();
            assert!(gap >= floor, "gap {i} below {want} s: {gaps:?}");
            if wait == *backoff.end() {
                assert!(gap < want + SLACK, "gap {i} past the cap: {gaps:?}");
            }
            wait = (wait * 2).min(*backoff.end());
        }
        assert_eq!(wait, *backoff.end(), "never reached the cap: {gaps:?}");
    }

    #[test]
    fn hello_then_key_then_deltas() {
        let fake = Fake::new();
        let _agent = Agent::spawn(&fake, blank);
        let mut p = fake.accept();
        match p.recv() {
            AgentMsg::Hello(h) => assert_eq!((h.ap.as_str(), h.hostapd.as_str()), ("ap1", "2.11")),
            other => panic!("expected hello, got {other:?}"),
        }
        p.expect_key(1);
        p.send(CtlMsg::SetTick { secs: 1 });
        p.expect_delta(2);
        p.expect_delta(3);
    }

    #[test]
    fn set_tick_changes_cadence() {
        let fake = Fake::new();
        let agent = Agent::spawn(&fake, blank);
        let mut p = fake.accept();
        p.start();
        let t1 = agent.tick_at(1);
        // The default tick is 15 s: nothing more for a while.
        thread::sleep(Duration::from_millis(1500));
        assert!(agent.ticks.try_recv().is_err());
        p.send(CtlMsg::SetTick { secs: 3 });
        let t2 = agent.tick_at(2);
        let t3 = agent.tick_at(3);
        for (a, b) in [(t1, t2), (t2, t3)] {
            assert!((2.95..4.5).contains(&secs(a, b)), "{}", secs(a, b));
        }
        p.expect_delta(2);
        p.expect_delta(3);
        // Zero is held at the 1 s minimum.
        p.send(CtlMsg::SetTick { secs: 0 });
        let t4 = agent.tick_at(4);
        let t5 = agent.tick_at(5);
        assert!((0.95..2.5).contains(&secs(t4, t5)), "{}", secs(t4, t5));
    }

    #[test]
    fn tick_is_clamped_to_a_minute() {
        assert_eq!(clamp_tick(0), Duration::from_secs(1));
        assert_eq!(clamp_tick(15), Duration::from_secs(15));
        assert_eq!(clamp_tick(u16::MAX), Duration::from_secs(60));
    }

    #[test]
    fn key_frame_every_minute_and_on_request() {
        let fresh = Duration::from_secs(1);
        assert!(!key_due(false, fresh));
        assert!(key_due(true, fresh));
        assert!(key_due(false, KEY_EVERY));
    }

    #[test]
    fn want_key_sends_key() {
        let fake = Fake::new();
        let _agent = Agent::spawn(&fake, blank);
        let mut p = fake.accept();
        p.start();
        // Well inside the 15 s default tick, so the key answers the request.
        p.send(CtlMsg::WantKey);
        p.expect_key(2);
        p.send(CtlMsg::SetTick { secs: 1 });
        p.expect_delta(3);
    }

    #[test]
    fn shape_change_sends_key() {
        let fake = Fake::new();
        let _agent = Agent::spawn(&fake, |seq| Snapshot {
            temps: (seq > 2)
                .then(|| Temp {
                    zone: "cpu".into(),
                    milli_c: 40_000,
                })
                .into_iter()
                .collect(),
            ..blank(seq)
        });
        let mut p = fake.accept();
        p.start();
        p.send(CtlMsg::SetTick { secs: 1 });
        p.expect_delta(2);
        assert!(matches!(p.recv(), AgentMsg::Key(s) if s.seq == 3 && s.temps.len() == 1));
    }

    /// A client listed by two BSSs at once: no delta can carry that, so each
    /// such tick is a key frame.
    #[test]
    fn a_snapshot_no_delta_can_carry_is_a_key_frame() {
        let fake = Fake::new();
        let _agent = Agent::spawn(&fake, |seq| {
            let mut s = blank(seq);
            s.bsss = vec![Bss {
                ifname: "wl0".into(),
                bssid: [2, 0, 0, 0, 0, 1],
                ssid: "net".into(),
                phy: "phy0".into(),
                vlan: 0,
            }];
            if seq == 2 {
                s.stations = vec![station(), station()];
            }
            s
        });
        let mut p = fake.accept();
        assert!(matches!(p.recv(), AgentMsg::Hello(_)));
        assert!(matches!(p.recv(), AgentMsg::Key(s) if s.seq == 1));
        p.send(CtlMsg::SetTick { secs: 1 });
        assert!(matches!(p.recv(), AgentMsg::Key(s) if s.seq == 2));
        assert!(matches!(p.recv(), AgentMsg::Key(s) if s.seq == 3));
        assert!(matches!(p.recv(), AgentMsg::Delta(d) if d.seq == 4));
    }

    #[test]
    fn ping_is_answered_and_events_leave_at_once() {
        let fake = Fake::new();
        let agent = Agent::spawn(&fake, blank);
        let mut p = fake.accept();
        p.start();
        p.send(CtlMsg::Ping(41));
        assert_eq!(p.recv(), AgentMsg::Pong(41));
        // The tick is 15 s: an event arriving now is not held for it.
        let sent = Instant::now();
        agent.events.send(event(5)).unwrap();
        assert_eq!(p.recv(), AgentMsg::Event(event(5)));
        assert!(sent.elapsed() < Duration::from_secs(3));
    }

    /// A command is refused with its id, and the flow requests are taken
    /// without an answer or an end to the session.
    #[test]
    fn a_command_is_answered_not_implemented() {
        let fake = Fake::new();
        let _agent = Agent::spawn(&fake, blank);
        let mut p = fake.accept();
        p.start();
        p.send(CtlMsg::WantFlows { full: true });
        p.send(CtlMsg::FlowCadence { secs: 10 });
        let mac = [0x02, 0, 0, 0, 0, 1];
        p.send(CtlMsg::Command(Command {
            id: 9,
            kind: CommandKind::Kick { mac },
        }));
        let refused = CommandResult {
            id: 9,
            ok: false,
            detail: "not implemented".into(),
        };
        assert_eq!(p.recv(), AgentMsg::Result(refused));
        p.send(CtlMsg::Ping(2));
        assert_eq!(p.recv(), AgentMsg::Pong(2));
    }

    #[test]
    fn event_near_a_tick_rides_with_it() {
        let fake = Fake::new();
        let agent = Agent::spawn(&fake, blank);
        let mut p = fake.accept();
        p.start();
        agent.tick_at(1);
        p.send(CtlMsg::SetTick { secs: 1 });
        let t2 = agent.tick_at(2);
        p.expect_delta(2);
        // 25 ms before tick 3: sent alone it would arrive before that tick.
        thread::sleep((t2 + Duration::from_millis(975)).saturating_duration_since(Instant::now()));
        agent.events.send(event(7)).unwrap();
        p.expect_delta(3);
        assert_eq!(p.recv(), AgentMsg::Event(event(7)));
    }

    #[test]
    fn reconnect_sends_key_frame() {
        let fake = Fake::new();
        let agent = Agent::spawn(&fake, blank);
        let mut p = fake.accept();
        p.start();
        agent.tick_at(1);
        p.send(CtlMsg::Ping(1));
        assert_eq!(p.recv(), AgentMsg::Pong(1));
        drop(p);
        let killed = Instant::now();
        let fake = fake.restart();
        let sock = fake.accept_tcp();
        // Backoff restarts at 1 s after a session the controller spoke in.
        assert!(
            killed.elapsed() < Duration::from_secs(5),
            "{:?}",
            killed.elapsed()
        );
        // Down, the link takes no snapshots and keeps the events for later.
        for n in 0..3 {
            agent.events.send(event(n)).unwrap();
        }
        assert!(agent.ticks.try_recv().is_err());
        let mut p = fake.handshake(sock).expect("the agent's handshake");
        assert_eq!(p.agree(PROTOCOL), PROTOCOL);
        p.start();
        for n in 0..3 {
            assert_eq!(p.recv(), AgentMsg::Event(event(n)));
        }
    }

    #[test]
    fn agent_memory_flat_while_controller_down() {
        // Down = a listener that never answers: the port stays this test's, so
        // no other test's fake can take it while the agent waits.
        let fake = Fake::new();
        let agent = Agent::spawn(&fake, blank);
        for n in 0..1000 {
            agent.events.send(event(n)).unwrap();
        }
        let start = Instant::now();
        while agent.ring.lock().back() != Some(&event(999)) {
            assert!(start.elapsed() < WAIT, "the ring never took the last event");
            thread::sleep(Duration::from_millis(10));
        }
        {
            let ring = agent.ring.lock();
            assert_eq!(ring.len(), RING_CAP);
            assert_eq!(ring.front(), Some(&event(744)));
            assert!(ring.capacity() < 2 * RING_CAP);
        }
        // No snapshot is taken (or kept) while down.
        assert!(agent.ticks.try_recv().is_err());

        let mut p = fake.accept();
        p.start();
        for n in 744..1000 {
            assert_eq!(p.recv(), AgentMsg::Event(event(n)));
        }
        p.send(CtlMsg::Ping(1));
        assert_eq!(p.recv(), AgentMsg::Pong(1));
    }

    #[test]
    fn a_silent_controller_is_dropped_and_dialed_again() {
        let fake = Fake::new();
        let _agent = Agent::spawn_with(&fake, 0, |c| c.silence = Duration::from_secs(1), blank);
        let mut p = fake.accept();
        p.start();
        let started = Instant::now();
        let mut again = fake.accept();
        // 1 s of silence, then the first backoff, 1 s.
        let gone = secs(started, Instant::now());
        assert!((0.9..4.0).contains(&gone), "{gone}");
        again.start();
    }

    #[test]
    fn a_controller_that_pings_keeps_the_session() {
        let fake = Fake::new();
        let _agent = Agent::spawn_with(&fake, 0, |c| c.silence = Duration::from_secs(1), blank);
        let mut p = fake.accept();
        p.start();
        for n in 0..10 {
            thread::sleep(Duration::from_millis(250));
            p.send(CtlMsg::Ping(n));
            assert_eq!(p.recv(), AgentMsg::Pong(n));
        }
        // Only another test's agent may have dialed in meanwhile.
        while let Ok((sock, _)) = fake.listener.accept() {
            assert!(fake.handshake(sock).is_none(), "the agent dialed again");
        }
    }

    /// The events need a thread and a socket pair; without them (resource
    /// exhaustion) the link carries the snapshots and tries again later.
    #[test]
    fn a_relay_that_fails_to_start_is_tried_again() {
        let fake = Fake::new();
        let agent = Agent::spawn_with(&fake, 1, |_| {}, blank);
        let mut p = fake.accept();
        p.start();
        agent.events.send(event(1)).unwrap();
        p.send(CtlMsg::Ping(7));
        assert_eq!(p.recv(), AgentMsg::Pong(7), "no ring, no events");
        drop(p);
        let mut p = fake.accept();
        p.start();
        assert_eq!(p.recv(), AgentMsg::Event(event(1)));
    }

    /// A controller that takes each session and drops it at once, or after
    /// its version frame, says nothing: each such dial backs off further.
    #[test]
    fn a_controller_that_drops_each_session_is_dialed_ever_more_slowly() {
        let fake = Fake::new();
        let _agent = Agent::spawn_with(&fake, 0, |c| c.backoff = QUICK, blank);
        let at = dial_times(&fake, 8, |i, mut p| {
            if i % 2 == 1 {
                assert_eq!(p.agree(PROTOCOL), PROTOCOL);
            }
        });
        assert_backs_off(&at, &QUICK);
    }

    #[test]
    fn a_useful_session_resets_the_backoff() {
        let backoff = Duration::from_millis(25)..=Duration::from_millis(1600);
        let fake = Fake::new();
        let _agent = Agent::spawn_with(&fake, 0, |c| c.backoff = backoff.clone(), blank);
        let at = dial_times(&fake, 8, |_, p| drop(p));
        assert_backs_off(&at, &backoff);
        let mut p = fake.accept();
        p.start();
        p.send(CtlMsg::Ping(1));
        assert_eq!(p.recv(), AgentMsg::Pong(1));
        drop(p);
        let ended = Instant::now();
        let (_p, next) = fake.accept_tls();
        // The 25 ms start, not the 1.6 s cap.
        let gap = secs(ended, next);
        assert!(gap < 0.8, "{gap}");
    }

    /// A newer controller, and one from before the version frame (whose first
    /// frame is a message): the agent sends them nothing past its version
    /// frame, and backs off as from a failed dial.
    #[test]
    fn a_controller_of_another_protocol_is_not_spoken_to() {
        let fake = Fake::new();
        let _agent = Agent::spawn_with(&fake, 0, |c| c.backoff = QUICK, blank);
        let at = dial_times(&fake, 7, |i, mut p| {
            if i % 2 == 0 {
                assert_eq!(p.agree(PROTOCOL + 1), PROTOCOL);
            } else {
                p.send(CtlMsg::SetTick { secs: 2 });
                let body = p.recv_body().expect("no version frame");
                assert_eq!(version::decode(&body), PROTOCOL);
            }
            p.ends();
        });
        assert_backs_off(&at, &QUICK);
    }

    /// A controller of protocol 1, from before flows and commands, would
    /// misread the messages this agent sends: its version frame turns it away.
    #[test]
    fn a_protocol_1_controller_is_not_spoken_to() {
        let fake = Fake::new();
        let _agent = Agent::spawn_with(&fake, 0, |c| c.backoff = QUICK, blank);
        let at = dial_times(&fake, 7, |_, mut p| {
            assert_eq!(p.agree(1), PROTOCOL);
            p.ends();
        });
        assert_backs_off(&at, &QUICK);
    }

    #[test]
    fn hello_reads_the_image_file() {
        let image = "image: u6e-2026.10\nhostapd: 2.11\nkernel: 6.12.0";
        assert_eq!(hostapd_version(image), "2.11");
        assert_eq!(hostapd_version(""), "");
        assert_eq!(hostapd_version("image: u6e-2026.10"), "");
    }
}
