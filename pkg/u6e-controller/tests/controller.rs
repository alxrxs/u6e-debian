//! The controller against fake agents on loopback. Each test starts its own
//! controller (in-process, or the binary when only its log can show the
//! result) on ports of its own, and speaks the link to it with u6e-proto
//! alone: a blocking rustls client, the framing and the messages.

use std::collections::{BTreeSet, HashMap};
use std::hash::{DefaultHasher, Hasher};
use std::io::{self, BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{fs, path::PathBuf};

use serde_json::{Value, json};
use tokio::runtime::{Builder, Runtime};
use tokio_rustls::rustls::ClientConnection;
use tokio_rustls::rustls::pki_types::ServerName;
use tungstenite::client::IntoClientRequest;
use tungstenite::{HandshakeError, Message};
use u6e_controller::agents::Timing;
use u6e_controller::config::Config;
use u6e_controller::names::Resolve;
use u6e_controller::state::{FLOWS_IDLE, FLOWS_WATCHED, TICK_IDLE, TICK_WATCHED};
use u6e_controller::{Controller, start};
use u6e_proto::PROTOCOL;
use u6e_proto::frame::{decode_frame, frame_body, write_frame};
use u6e_proto::msg::{
    AgentMsg, Band, Bss, ClientFlows, CommandKind, CommandResult, CtlMsg, Event, EventKind,
    FieldDelta, Flow, Flows, Hello, Radio, RateMode, Snapshot, SnapshotDelta, Station, Temp,
};
use u6e_proto::tls::{self, Identity};
use u6e_proto::{mac, version};

#[path = "common/keys.rs"]
mod keys;

use keys::{KEY_AP1, KEY_AP2, KEY_CONTROLLER};

// Throwaway, like the keys of `keys`: an AP that is not enrolled.
const KEY_STRANGER: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIIN98nA5U+8ay1kTe7TR4rEzYomCSC7d4p/BpYYuf1qw\n-----END PRIVATE KEY-----\n";

/// How long a test waits for something that should happen, before failing.
const WAIT: Duration = Duration::from_secs(20);

const MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];

fn identity(pem: &str) -> Identity {
    Identity::from_pem(pem).unwrap()
}

/// The origin the UI is served at, in the tests' configurations.
const ORIGIN: &str = "https://wifi.example.org";
/// The headers of the UI's own page asking for an action.
const SAME_SITE: &str = "Content-Type: application/json\r\nOrigin: https://wifi.example.org\r\n";
/// The headers the sign-in proxy sets for an admin.
const ADMIN: &str =
    "X-Auth-Request-Groups: staff,wifi-admins\r\nX-Forwarded-Preferred-Username: alice\r\n";

/// A configuration on loopback ports of the system's choosing, admitting
/// `ap1` and, with `ap2`, `ap2`, its policy in `dir`.
fn config_text(key: &str, ap2: bool, dir: &Path) -> String {
    let mut text = format!(
        "listen_agents = \"127.0.0.1:0\"\nlisten_http = \"127.0.0.1:0\"\n\
         listen_metrics = \"127.0.0.1:0\"\nkey = \"{key}\"\n\
         public_origin = \"{ORIGIN}\"\npolicy_path = \"{}\"\n\
         [aps.ap1]\npublic_key = \"{}\"\n",
        dir.join("policy.json").display(),
        mac::hex(&identity(KEY_AP1).public_key())
    );
    if ap2 {
        let k = mac::hex(&identity(KEY_AP2).public_key());
        text.push_str(&format!("[aps.ap2]\npublic_key = \"{k}\"\n"));
    }
    text
}

/// A resolver of the names it is given, which counts what it is asked.
#[derive(Default)]
struct FakeDns {
    names: Mutex<HashMap<IpAddr, String>>,
    asked: Mutex<Vec<IpAddr>>,
}

impl Resolve for FakeDns {
    fn reverse(&self, ip: IpAddr) -> Option<String> {
        self.asked.lock().unwrap().push(ip);
        self.names.lock().unwrap().get(&ip).cloned()
    }
}

/// A controller in this process, alive as long as the runtime, its policy
/// in a directory of its own unless it was given one.
struct Running {
    c: Controller,
    dns: Arc<FakeDns>,
    _rt: Runtime,
    _dir: Option<TempDir>,
}

fn controller(timing: Timing) -> Running {
    let dir = TempDir::new("controller");
    let mut r = controller_in(timing, &dir.0);
    r._dir = Some(dir);
    r
}

fn controller_in(timing: Timing, dir: &Path) -> Running {
    // Two workers are plenty, and a worker per core in every test of eight
    // test processes at once runs into the threads a cgroup allows.
    let rt = Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let config = Config::parse(&config_text("unused.pem", true, dir)).unwrap();
    let dns = Arc::new(FakeDns::default());
    let resolver: Arc<dyn Resolve> = dns.clone();
    let c = rt
        .block_on(start(&config, &identity(KEY_CONTROLLER), timing, resolver))
        .unwrap();
    Running {
        c,
        dns,
        _rt: rt,
        _dir: None,
    }
}

/// Polls `cond` until it holds.
fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let start = Instant::now();
    while !cond() {
        assert!(start.elapsed() < WAIT, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(10));
    }
}

/// The agent end of the link.
struct Agent {
    conn: ClientConnection,
    sock: TcpStream,
    buf: Vec<u8>,
    /// The blocks each sync the controller sent set, answered.
    syncs: Vec<Vec<[u8; 6]>>,
}

impl Agent {
    /// Dials and completes the client side of the handshake; a refusal by
    /// the controller shows at the first read.
    fn dial(addr: SocketAddr, pem: &str) -> io::Result<Agent> {
        let config = tls::client_config(&identity(pem), identity(KEY_CONTROLLER).public_key());
        let mut sock = TcpStream::connect(addr)?;
        sock.set_read_timeout(Some(WAIT))?;
        let name = ServerName::try_from("controller").unwrap();
        let mut conn = ClientConnection::new(config, name).map_err(io::Error::other)?;
        while conn.is_handshaking() {
            conn.complete_io(&mut sock)?;
        }
        Ok(Agent {
            conn,
            sock,
            buf: Vec::new(),
            syncs: Vec::new(),
        })
    }

    /// Dials as an agent of `protocol`: its version frame sent, and the
    /// protocol the controller's states.
    fn versioned(addr: SocketAddr, pem: &str, protocol: u16) -> (Agent, u16) {
        let mut a = Agent::dial(addr, pem).unwrap();
        a.send_bytes(&version::frame(protocol)).unwrap();
        let theirs = version::decode(&a.recv_body().unwrap());
        (a, theirs)
    }

    /// An enrolled AP of this protocol that has said Hello.
    fn hello(addr: SocketAddr, pem: &str, ap: &str) -> Agent {
        let (mut a, theirs) = Agent::versioned(addr, pem, PROTOCOL);
        assert_eq!(theirs, PROTOCOL);
        a.send(&AgentMsg::Hello(Hello {
            ap: ap.into(),
            manifest: "image: test".into(),
            kernel: "6.12".into(),
            hostapd: "2.11".into(),
            agent: "1.0.0".into(),
        }))
        .unwrap();
        a
    }

    fn send(&mut self, msg: &AgentMsg) -> io::Result<()> {
        let mut out = Vec::new();
        write_frame(&mut out, msg)?;
        self.send_bytes(&out)
    }

    fn send_bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.conn.writer().write_all(bytes)?;
        while self.conn.wants_write() {
            self.conn.write_tls(&mut self.sock)?;
        }
        Ok(())
    }

    /// What `take` makes of the frames received, once it makes something.
    fn next<T>(&mut self, take: impl Fn(&[u8]) -> io::Result<Option<(T, usize)>>) -> io::Result<T> {
        loop {
            // Ok: the controller closed, after what it sent with the close.
            let closed = match self.conn.reader().read_to_end(&mut self.buf) {
                Ok(_) => true,
                Err(e) if e.kind() == ErrorKind::WouldBlock => false,
                Err(e) => return Err(e),
            };
            if let Some((v, n)) = take(&self.buf)? {
                self.buf.drain(..n);
                return Ok(v);
            }
            if closed || self.conn.read_tls(&mut self.sock)? == 0 {
                return Err(ErrorKind::UnexpectedEof.into());
            }
            self.conn.process_new_packets().map_err(io::Error::other)?;
        }
    }

    /// The next message from the controller, pings included.
    fn recv(&mut self) -> io::Result<CtlMsg> {
        self.next(decode_frame)
    }

    /// The body of the next frame from the controller, undecoded.
    fn recv_body(&mut self) -> io::Result<Vec<u8>> {
        self.next(|buf| Ok(frame_body(buf)?.map(|(body, n)| (body.to_vec(), n))))
    }

    /// Asserts that the controller ends the session, and does not merely
    /// keep quiet.
    fn ends(&mut self) {
        match self.recv_body() {
            Err(e) => assert_eq!(e.kind(), ErrorKind::UnexpectedEof, "{e}"),
            Ok(body) => panic!("a frame of {} B, not the end", body.len()),
        }
    }

    /// The next message other than a ping or a sync of the blocks, which
    /// are answered (the sync's list kept in `syncs`).
    fn expect(&mut self) -> CtlMsg {
        let start = Instant::now();
        loop {
            // Answered pings would otherwise keep a missing message waited for.
            assert!(start.elapsed() < WAIT, "no message from the controller");
            match self.recv().unwrap() {
                CtlMsg::Ping(n) => self.send(&AgentMsg::Pong(n)).unwrap(),
                CtlMsg::Command(c) => match c.kind {
                    CommandKind::SyncBlocks { macs } => {
                        self.syncs.push(macs);
                        self.reply(c.id, true, "synced");
                    }
                    kind => return CtlMsg::Command(u6e_proto::msg::Command { id: c.id, kind }),
                },
                msg => return msg,
            }
        }
    }

    /// The blocks of the next sync of the blocks.
    fn expect_sync(&mut self) -> Vec<[u8; 6]> {
        if !self.syncs.is_empty() {
            return self.syncs.remove(0);
        }
        loop {
            match self.recv().unwrap() {
                CtlMsg::Ping(n) => self.send(&AgentMsg::Pong(n)).unwrap(),
                CtlMsg::Command(u6e_proto::msg::Command {
                    id,
                    kind: CommandKind::SyncBlocks { macs },
                }) => {
                    self.reply(id, true, "synced");
                    return macs;
                }
                other => panic!("{other:?} before the sync of the blocks"),
            }
        }
    }

    /// The next command, which must be `kind`; its id.
    fn expect_command(&mut self, kind: CommandKind) -> u64 {
        match self.expect() {
            CtlMsg::Command(c) if c.kind == kind => c.id,
            other => panic!("{other:?}, not {kind:?}"),
        }
    }

    fn reply(&mut self, id: u64, ok: bool, detail: &str) {
        let detail = detail.into();
        self.send(&AgentMsg::Result(CommandResult { id, ok, detail }))
            .unwrap();
    }
}

fn station(mac: [u8; 6], bss: u16, signal: i8) -> Station {
    Station {
        mac,
        bss,
        signal,
        signal_avg: signal,
        rx_bytes: 123_456,
        tx_bytes: 654_321,
        rx_packets: 100,
        tx_packets: 200,
        tx_retries: 3,
        tx_failed: 1,
        tx_rate_kbps: 72_200,
        rx_rate_kbps: 86_700,
        tx_mcs: 7,
        rx_mcs: 8,
        tx_mode: RateMode::Ht,
        rx_mode: RateMode::Ht,
        tx_nss: 0,
        rx_nss: 0,
        tx_airtime_us: 1000,
        rx_airtime_us: 2000,
        inactive_ms: 0,
        connected_s: 60,
        vlan: 42,
    }
}

fn bss(ifname: &str, ssid: &str) -> Bss {
    Bss {
        ifname: ifname.into(),
        bssid: [0x02, 0, 0, 0, 0x10, 0x01],
        ssid: ssid.into(),
        phy: "phy0".into(),
        vlan: 42,
    }
}

fn snapshot(seq: u64, bsss: Vec<Bss>, stations: Vec<Station>) -> Snapshot {
    Snapshot {
        seq,
        uptime_s: 3600,
        load_milli: 250,
        mem_avail_kb: 200_000,
        nss_load_pct: 37,
        temps: vec![Temp {
            zone: "cpu".into(),
            milli_c: 47_500,
        }],
        radios: vec![Radio {
            phy: "phy0".into(),
            band: Band::B5,
            channel: 36,
            width_mhz: 80,
            txpower_mbm: 2300,
            noise_dbm: -95,
            active_ms: 10_000,
            busy_ms: 2500,
            rx_ms: 1000,
            tx_ms: 500,
            up: true,
        }],
        bsss,
        stations,
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

/// The seq of the AP's snapshot, if it has one.
fn seq_of(r: &Running, ap: &str) -> Option<u64> {
    let state = r.c.state.read();
    state.ap(ap).unwrap().snapshot.as_ref().map(|s| s.seq)
}

/// The body of a GET over HTTP/1.1.
fn http_get(addr: SocketAddr, path: &str) -> String {
    let mut sock = TcpStream::connect(addr).unwrap();
    sock.set_read_timeout(Some(WAIT)).unwrap();
    write!(
        sock,
        "GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut resp = String::new();
    sock.read_to_string(&mut resp).unwrap();
    let (head, body) = resp.split_once("\r\n\r\n").unwrap();
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    body.to_owned()
}

#[test]
fn controller_drops_delta_without_base() {
    let r = controller(Timing::default());
    let mut a = Agent::hello(r.c.agents, KEY_AP1, "ap1");
    // No key frame yet: nothing to apply the delta to.
    a.send(&AgentMsg::Delta(delta(2, 1))).unwrap();
    assert_eq!(a.expect(), CtlMsg::WantKey);
    assert_eq!(seq_of(&r, "ap1"), None);
    assert!(r.c.state.read().ap("ap1").unwrap().is_up());

    a.send(&AgentMsg::Key(snapshot(1, Vec::new(), Vec::new())))
        .unwrap();
    // Deltas from a base the controller never saw: nothing applied, and one
    // request until the key frame comes.
    a.send(&AgentMsg::Delta(delta(4, 3))).unwrap();
    assert_eq!(a.expect(), CtlMsg::WantKey);
    a.send(&AgentMsg::Delta(delta(5, 4))).unwrap();
    a.send(&AgentMsg::Key(snapshot(6, Vec::new(), Vec::new())))
        .unwrap();
    wait_for("key frame 6", || seq_of(&r, "ap1") == Some(6));
    let _watching = r.c.state.watch("ap1").unwrap();
    assert_eq!(a.expect(), CtlMsg::SetTick { secs: TICK_WATCHED });

    // A delta on the key frame applies.
    a.send(&AgentMsg::Delta(delta(7, 6))).unwrap();
    wait_for("delta 7", || seq_of(&r, "ap1") == Some(7));

    // A key frame deltas could not build on is refused, and asked for again.
    let b = vec![bss("wlan0", "Guest")];
    let twice = vec![station(MAC, 0, -50), station(MAC, 0, -50)];
    a.send(&AgentMsg::Key(snapshot(8, b, twice))).unwrap();
    assert_eq!(a.expect(), CtlMsg::WantKey);
    assert_eq!(seq_of(&r, "ap1"), Some(7));
}

#[test]
fn roam_moves_client() {
    let r = controller(Timing::default());
    // From ap2 to ap1, against the order the APs are listed in.
    let mut from = Agent::hello(r.c.agents, KEY_AP2, "ap2");
    let mut to = Agent::hello(r.c.agents, KEY_AP1, "ap1");
    let on = |ap: &str, bss: &str| {
        let clients = r.c.state.read().clients();
        clients.len() == 1 && clients[0].ap == ap && clients[0].bss == bss
    };
    let s1 = snapshot(
        1,
        vec![bss("wlan5.42", "Guest")],
        vec![station(MAC, 0, -54)],
    );
    from.send(&AgentMsg::Key(s1)).unwrap();
    wait_for("the client on ap2", || on("ap2", "wlan5.42"));

    // ap2 still lists it (its next tick has not come), ap1 has it now.
    let s2 = snapshot(
        1,
        vec![bss("wlan2", "Guest"), bss("wlan6", "Guest")],
        vec![station(MAC, 1, -60)],
    );
    to.send(&AgentMsg::Key(s2)).unwrap();
    wait_for("the client on ap1", || on("ap1", "wlan6"));
    assert_eq!(seq_of(&r, "ap2"), Some(1));

    let body = http_get(r.c.metrics, "/metrics");
    let series: Vec<_> = body
        .lines()
        .filter(|l| l.starts_with("wifi_client_signal_dbm{"))
        .collect();
    assert_eq!(
        series,
        ["wifi_client_signal_dbm{ap=\"ap1\",ssid=\"Guest\",mac=\"02:00:00:00:00:01\"} -60"]
    );
}

/// A child process killed when the test ends, however it ends.
struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A directory of the test's own, removed when it ends.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("{name}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The controller binary, its log lines, and the addresses it reported.
struct Binary {
    _proc: Proc,
    log: Receiver<String>,
    agents: SocketAddr,
    http: SocketAddr,
    metrics: SocketAddr,
}

fn spawn_binary(dir: &TempDir) -> Binary {
    let key = dir.0.join("key.pem");
    fs::write(&key, KEY_CONTROLLER).unwrap();
    let config = dir.0.join("config.toml");
    fs::write(&config, config_text(key.to_str().unwrap(), false, &dir.0)).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_u6e-controller"))
        .arg("--config")
        .arg(&config)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let proc = Proc(child);
    let (tx, log) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let line = wait_line(&log, |l| l.contains("agents on "));
    let addr = |after: &str| -> SocketAddr {
        let rest = line.split_once(after).unwrap().1;
        rest.split(',').next().unwrap().parse().unwrap()
    };
    Binary {
        _proc: proc,
        log,
        agents: addr("agents on "),
        http: addr("http on "),
        metrics: addr("metrics on "),
    }
}

/// The first log line that matches.
fn wait_line(log: &Receiver<String>, matches: impl Fn(&str) -> bool) -> String {
    let start = Instant::now();
    loop {
        let left = WAIT.saturating_sub(start.elapsed());
        let line = log.recv_timeout(left).expect("no such log line");
        if matches(&line) {
            return line;
        }
    }
}

#[test]
fn unknown_ap_not_listed() {
    let dir = TempDir::new("unknown-ap");
    let b = spawn_binary(&dir);

    // TLS 1.3 completes the client's side first; the refusal shows at the read.
    let mut stranger = Agent::dial(b.agents, KEY_STRANGER).unwrap();
    let local = stranger.sock.local_addr().unwrap();
    let _ = stranger.send(&AgentMsg::Pong(0));
    assert!(stranger.recv().is_err());
    let refused = wait_line(&b.log, |l| {
        l.contains(&format!("{local}: handshake refused"))
    });
    let fp = tls::fingerprint(&identity(KEY_STRANGER).public_key());
    assert!(
        refused.contains(&format!("client key {fp} is not enrolled")),
        "{refused}"
    );

    let body = http_get(b.metrics, "/metrics");
    let up: Vec<_> = body
        .lines()
        .filter(|l| l.starts_with("wifi_ap_up"))
        .collect();
    assert_eq!(up, ["wifi_ap_up{ap=\"ap1\"} 0"]);

    // The enrolled AP is still served.
    let mut a = Agent::hello(b.agents, KEY_AP1, "ap1");
    a.send(&AgentMsg::Key(snapshot(1, Vec::new(), Vec::new())))
        .unwrap();
    wait_line(&b.log, |l| l.contains("ap1 up from"));
    wait_for("ap1 up in the metrics", || {
        http_get(b.metrics, "/metrics").contains("wifi_ap_up{ap=\"ap1\"} 1\n")
    });
}

#[test]
fn watchers_set_tick() {
    let r = controller(Timing::default());
    let mut a = Agent::hello(r.c.agents, KEY_AP1, "ap1");
    wait_for("ap1 up", || r.c.state.read().ap("ap1").unwrap().is_up());

    let watching = r.c.state.watch("ap1").unwrap();
    assert_eq!(a.expect(), CtlMsg::SetTick { secs: TICK_WATCHED });
    // A second watcher changes nothing; the last one to leave does.
    let second = r.c.state.watch("ap1").unwrap();
    drop(watching);
    // A gap's WantKey comes next, not a tick for the watcher still there.
    a.send(&AgentMsg::Delta(delta(2, 1))).unwrap();
    assert_eq!(a.expect(), CtlMsg::WantKey);
    drop(second);
    assert_eq!(a.expect(), CtlMsg::SetTick { secs: TICK_IDLE });
    assert_eq!(r.c.state.read().watchers("ap1"), 0);

    // An AP that connects while watched hears so right after its Hello.
    let _watching = r.c.state.watch("ap1").unwrap();
    assert_eq!(a.expect(), CtlMsg::SetTick { secs: TICK_WATCHED });
    let mut again = Agent::hello(r.c.agents, KEY_AP1, "ap1");
    assert_eq!(again.expect(), CtlMsg::SetTick { secs: TICK_WATCHED });
}

#[test]
fn second_connection_replaces_first() {
    let r = controller(Timing::default());
    let mut first = Agent::hello(r.c.agents, KEY_AP1, "ap1");
    first
        .send(&AgentMsg::Key(snapshot(1, Vec::new(), Vec::new())))
        .unwrap();
    wait_for("first key frame", || seq_of(&r, "ap1") == Some(1));
    assert!(first.expect_sync().is_empty());

    let mut second = Agent::hello(r.c.agents, KEY_AP1, "ap1");
    // The first connection is closed, whatever it still sends.
    loop {
        match first.recv() {
            Ok(CtlMsg::Ping(_)) => {}
            Ok(other) => panic!("unexpected {other:?}"),
            Err(_) => break,
        }
    }
    assert_eq!(seq_of(&r, "ap1"), None, "the old snapshot is gone");
    second
        .send(&AgentMsg::Key(snapshot(1, Vec::new(), Vec::new())))
        .unwrap();
    wait_for("second key frame", || seq_of(&r, "ap1") == Some(1));
    assert!(r.c.state.read().ap("ap1").unwrap().is_up());
}

#[test]
fn silent_agent_dropped() {
    let timing = Timing {
        ping: Duration::from_millis(200),
        silence: Duration::from_millis(1500),
        ..Timing::default()
    };
    let r = controller(timing);
    let up = |ap: &str| r.c.state.read().ap(ap).unwrap().is_up();

    // ap2 answers every ping; ap1 never says a word after its Hello.
    let mut talker = Agent::hello(r.c.agents, KEY_AP2, "ap2");
    let mut mute = Agent::hello(r.c.agents, KEY_AP1, "ap1");
    wait_for("both up", || up("ap1") && up("ap2"));
    let start = Instant::now();
    let mut pings = 0;
    while start.elapsed() < Duration::from_secs(3) {
        match talker.recv().unwrap() {
            CtlMsg::Ping(n) => {
                pings += 1;
                talker.send(&AgentMsg::Pong(n)).unwrap();
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(pings >= 10, "{pings} pings in 3 s");
    assert!(up("ap2"));
    assert!(!up("ap1"));
    // The mute agent's connection was closed after its pings went unanswered.
    while let Ok(msg) = mute.recv() {
        assert!(matches!(msg, CtlMsg::Ping(_)), "{msg:?}");
    }
}

#[test]
fn metrics_exposition() {
    let r = controller(Timing::default());
    let mut a = Agent::hello(r.c.agents, KEY_AP1, "ap1");
    let bsss = vec![bss("wlan5.42", "Guest"), bss("wlan6", "say \"hi\" \\o/")];
    a.send(&AgentMsg::Key(snapshot(
        1,
        bsss,
        vec![station(MAC, 0, -54)],
    )))
    .unwrap();
    let crash = EventKind::FwCrash { phy: "phy0".into() };
    a.send(&AgentMsg::Event(Event {
        at_ms: 5,
        kind: crash,
    }))
    .unwrap();
    wait_for("the crash", || {
        r.c.state.read().ap("ap1").unwrap().events.len() == 1
    });

    let body = http_get(r.c.metrics, "/metrics");
    for line in [
        "wifi_client_signal_dbm{ap=\"ap1\",ssid=\"Guest\",mac=\"02:00:00:00:00:01\"} -54",
        "wifi_client_rx_bytes_total{ap=\"ap1\",ssid=\"Guest\",mac=\"02:00:00:00:00:01\"} 123456",
        "wifi_client_tx_rate_bps{ap=\"ap1\",ssid=\"Guest\",mac=\"02:00:00:00:00:01\"} 72200000",
        "wifi_ap_up{ap=\"ap1\"} 1",
        "wifi_ap_up{ap=\"ap2\"} 0",
        "wifi_ap_uptime_seconds{ap=\"ap1\"} 3600",
        "wifi_ap_mem_available_bytes{ap=\"ap1\"} 204800000",
        "wifi_ap_nss_load_ratio{ap=\"ap1\"} 0.37",
        "wifi_temperature_celsius{ap=\"ap1\",zone=\"cpu\"} 47.5",
        "wifi_radio_up{ap=\"ap1\",phy=\"phy0\",band=\"5\"} 1",
        "wifi_radio_channel{ap=\"ap1\",phy=\"phy0\"} 36",
        "wifi_radio_txpower_dbm{ap=\"ap1\",phy=\"phy0\"} 23",
        "wifi_radio_noise_dbm{ap=\"ap1\",phy=\"phy0\"} -95",
        "wifi_radio_busy_seconds_total{ap=\"ap1\",phy=\"phy0\"} 2.5",
        "wifi_bss_stations{ap=\"ap1\",bss=\"wlan5.42\",ssid=\"Guest\"} 1",
        "wifi_bss_stations{ap=\"ap1\",bss=\"wlan6\",ssid=\"say \\\"hi\\\" \\\\o/\"} 0",
        "wifi_firmware_crashes_total{ap=\"ap1\",phy=\"phy0\"} 1",
    ] {
        assert!(body.lines().any(|l| l == line), "missing {line}\n{body}");
    }
    assert!(body.contains("\nwifi_agent_last_seen_timestamp_seconds{ap=\"ap1\"} 1"));
    for line in [
        format!("wifi_controller_protocol {PROTOCOL}"),
        format!("wifi_agent_protocol{{ap=\"ap1\"}} {PROTOCOL}"),
        "wifi_agent_compatible{ap=\"ap1\"} 1".to_owned(),
    ] {
        assert!(body.lines().any(|l| l == line), "missing {line}\n{body}");
    }
    // ap2 has never dialed in: no protocol to tell.
    assert!(!body.contains("wifi_agent_protocol{ap=\"ap2\"}"), "{body}");
    assert!(promtool_accepts(&body));

    // A client that leaves takes its series with it.
    a.send(&AgentMsg::Delta(SnapshotDelta {
        removed: vec![MAC],
        ..delta(2, 1)
    }))
    .unwrap();
    wait_for("delta 2", || seq_of(&r, "ap1") == Some(2));
    let body = http_get(r.c.metrics, "/metrics");
    assert!(!body.contains("02:00:00:00:00:01"), "{body}");
    assert!(body.contains("wifi_bss_stations{ap=\"ap1\",bss=\"wlan5.42\",ssid=\"Guest\"} 0\n"));
    assert!(promtool_accepts(&body));
}

/// Whether `promtool check metrics` passes the exposition, lint included;
/// true with a note when promtool is not installed.
fn promtool_accepts(body: &str) -> bool {
    let child = Command::new("promtool")
        .args(["check", "metrics"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            eprintln!("note: promtool not installed; the exposition check is skipped");
            return true;
        }
        Err(e) => panic!("promtool: {e}"),
    };
    child
        .stdin
        .take()
        .unwrap()
        .write_all(body.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    if !out.status.success() {
        eprintln!(
            "promtool: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    out.status.success()
}

#[test]
fn rx_bytes_are_counted() {
    let r = controller(Timing::default());
    let mut a = Agent::hello(r.c.agents, KEY_AP1, "ap1");
    a.send(&AgentMsg::Key(snapshot(1, Vec::new(), Vec::new())))
        .unwrap();
    wait_for("key frame", || seq_of(&r, "ap1") == Some(1));
    let at_key = r.c.state.read().ap("ap1").unwrap().rx_bytes();
    // The handshake alone is over a kilobyte (ML-KEM's share).
    assert!(at_key > 1000, "{at_key}");
    a.send(&AgentMsg::Pong(1)).unwrap();
    wait_for("the pong's bytes", || {
        r.c.state.read().ap("ap1").unwrap().rx_bytes() > at_key
    });
}

/// A GET over HTTP/1.1 with extra header lines: the status line and headers
/// (lowercased), and the body.
fn http_request(addr: SocketAddr, path: &str, headers: &str) -> (String, String) {
    let mut sock = TcpStream::connect(addr).unwrap();
    sock.set_read_timeout(Some(WAIT)).unwrap();
    write!(
        sock,
        "GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n{headers}\r\n"
    )
    .unwrap();
    let mut resp = String::new();
    sock.read_to_string(&mut resp).unwrap();
    let (head, body) = resp.split_once("\r\n\r\n").unwrap();
    (head.to_lowercase(), body.to_owned())
}

fn json_get(addr: SocketAddr, path: &str) -> Value {
    serde_json::from_str(&http_get(addr, path)).unwrap()
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(':'))
        .map(str::trim)
}

#[test]
fn api_aps_lists_connected() {
    let r = controller(Timing::default());
    let mut a = Agent::hello(r.c.agents, KEY_AP1, "ap1");
    let bsss = vec![bss("wlan5", "ssid-a")];
    a.send(&AgentMsg::Key(snapshot(
        1,
        bsss,
        vec![station(MAC, 0, -54)],
    )))
    .unwrap();
    wait_for("key frame", || seq_of(&r, "ap1") == Some(1));

    let aps = json_get(r.c.http, "/api/aps");
    let ap1 = &aps["ap1"];
    assert_eq!(ap1["up"], true);
    assert_eq!(ap1["image"], "test");
    assert_eq!(ap1["agent"], "1.0.0");
    assert_eq!(ap1["uptime"], 3600);
    assert_eq!(ap1["nss"], 37);
    assert_eq!(ap1["temps"]["cpu"], 47.5);
    let radio = &ap1["radios"]["phy0"];
    assert_eq!(radio["band"], "5");
    assert_eq!(
        (&radio["channel"], &radio["width"]),
        (&json!(36), &json!(80))
    );
    assert_eq!(radio["txpower"], 23.0);
    assert_eq!(radio["clients"], 1);
    assert_eq!(ap1["bsss"]["wlan5"]["ssid"], "ssid-a");
    // Known but never connected: only that it is down.
    assert_eq!(aps["ap2"], json!({"up": false}));

    let clients = json_get(r.c.http, "/api/clients");
    let c = &clients["02:00:00:00:00:01"];
    assert_eq!((&c["ap"], &c["ssid"]), (&json!("ap1"), &json!("ssid-a")));
    assert_eq!((&c["band"], &c["signal"]), (&json!("5"), &json!(-54)));
    assert_eq!(c["tx"], json!({"mbps": 72.2, "mode": "HT", "mcs": 7}));

    a.send(&AgentMsg::Event(Event {
        at_ms: 5,
        kind: EventKind::Assoc { mac: MAC, bss: 0 },
    }))
    .unwrap();
    wait_for("the event", || {
        r.c.state.read().ap("ap1").unwrap().events.len() == 1
    });
    let events = json_get(r.c.http, "/api/events?ap=ap1");
    let assoc = json!({"ap": "ap1", "at": 5, "kind": "assoc", "mac": "02:00:00:00:00:01",
        "bss": "wlan5", "ssid": "ssid-a", "band": "5"});
    assert_eq!(events, json!([assoc]));
    assert_eq!(json_get(r.c.http, "/api/events"), json!([assoc]));
    assert_eq!(json_get(r.c.http, "/api/events?ap=ap2"), json!([]));
}

#[test]
fn assets_served_with_cache_headers() {
    let r = controller(Timing::default());
    let (head, page) = http_request(r.c.http, "/", "");
    assert!(head.starts_with("http/1.1 200"), "{head}");
    assert_eq!(header(&head, "cache-control"), Some("no-cache"));
    assert!(header(&head, "content-security-policy").is_some());
    let page_tag = header(&head, "etag").unwrap().to_owned();
    let (head, _) = http_request(r.c.http, "/", &format!("If-None-Match: {page_tag}\r\n"));
    assert!(head.starts_with("http/1.1 304"), "{head}");

    // The page points at the files under their version.
    let at = page.find("/assets/").unwrap() + "/assets/".len();
    let version = page[at..].split('/').next().unwrap();
    assert_eq!(version.len(), 12, "{page}");
    let app = include_bytes!("../ui/app.js");
    let mut h = DefaultHasher::new();
    h.write(app);
    let tag = format!("\"{:016x}\"", h.finish());

    let path = format!("/assets/{version}/app.js");
    let (head, body) = http_request(r.c.http, &path, "");
    assert!(head.starts_with("http/1.1 200"), "{head}");
    assert_eq!(body.as_bytes(), app);
    assert_eq!(header(&head, "etag"), Some(tag.as_str()));
    assert_eq!(
        header(&head, "content-type"),
        Some("text/javascript; charset=utf-8")
    );
    assert_eq!(
        header(&head, "cache-control"),
        Some("public, max-age=31536000, immutable")
    );
    let (head, body) = http_request(r.c.http, &path, &format!("If-None-Match: {tag}\r\n"));
    assert!(head.starts_with("http/1.1 304"), "{head}");
    assert!(body.is_empty());

    // Without the version, the same file is revalidated each time.
    let (head, _) = http_request(r.c.http, "/assets/app.js", "");
    assert_eq!(header(&head, "etag"), Some(tag.as_str()));
    assert_eq!(header(&head, "cache-control"), Some("no-cache"));
    for missing in [
        "/assets/nope.js",
        "/assets/0123456789ab/app.js",
        "/assets/../Cargo.toml",
    ] {
        let (head, _) = http_request(r.c.http, missing, "");
        assert!(head.starts_with("http/1.1 404"), "{missing}: {head}");
    }
}

/// The quoted import specifiers of a module (`from './x.js'`).
fn imports(module: &str) -> Vec<String> {
    let after = module.split("from '").skip(1);
    after
        .map(|s| s.split('\'').next().unwrap().to_owned())
        .collect()
}

/// `spec` relative to the directory `dir` of the module importing it.
fn resolve(dir: &str, spec: &str) -> String {
    let mut parts: Vec<&str> = dir.split('/').collect();
    for p in spec.split('/') {
        match p {
            "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    parts.join("/")
}

/// Every file under `dir`, by its path from `root`.
fn files_under(root: &Path, dir: &Path, out: &mut BTreeSet<String>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files_under(root, &path, out);
        } else {
            let rel = path.strip_prefix(root).unwrap();
            out.insert(rel.to_str().unwrap().replace('\\', "/"));
        }
    }
}

/// Every file of the UI is served, reached as a browser reaches it: from the
/// page's links, then from each module's imports; and none is left out, so a
/// file added to `ui/` but not to the embedded list fails here.
#[test]
fn every_ui_file_is_served() {
    let r = controller(Timing::default());
    let (_, page) = http_request(r.c.http, "/", "");
    let links = page
        .split(['"', '\''])
        .filter(|s| s.starts_with("/assets/"));
    let mut todo: Vec<String> = links.map(str::to_owned).collect();
    assert!(!todo.is_empty(), "{page}");
    let mut served = BTreeSet::new();
    while let Some(path) = todo.pop() {
        if !served.insert(path.clone()) {
            continue;
        }
        let (head, body) = http_request(r.c.http, &path, "");
        assert!(head.starts_with("http/1.1 200"), "{path}: {head}");
        if path.ends_with(".js") {
            let dir = &path[..path.rfind('/').unwrap()];
            todo.extend(imports(&body).iter().map(|s| resolve(dir, s)));
        }
    }
    let version = page
        .split("/assets/")
        .nth(1)
        .unwrap()
        .split('/')
        .next()
        .unwrap();
    let prefix = format!("/assets/{version}/");
    let served: BTreeSet<String> = served
        .iter()
        .map(|p| p.strip_prefix(&prefix).unwrap_or(p).to_owned())
        .collect();
    let ui = Path::new(env!("CARGO_MANIFEST_DIR")).join("ui");
    let mut on_disk = BTreeSet::new();
    files_under(&ui, &ui, &mut on_disk);
    on_disk.remove("index.html");
    assert_eq!(served, on_disk);
}

/// A WebSocket client of the web listener.
struct Ui(tungstenite::WebSocket<TcpStream>);

impl Ui {
    fn open(addr: SocketAddr, headers: &[(&'static str, &str)]) -> Result<Ui, tungstenite::Error> {
        let sock = TcpStream::connect(addr).unwrap();
        sock.set_read_timeout(Some(WAIT)).unwrap();
        let mut req = format!("ws://{addr}/ws").into_client_request().unwrap();
        for (k, v) in headers {
            req.headers_mut().insert(*k, v.parse().unwrap());
        }
        match tungstenite::client(req, sock) {
            Ok((ws, _)) => Ok(Ui(ws)),
            Err(HandshakeError::Failure(e)) => Err(e),
            Err(HandshakeError::Interrupted(_)) => unreachable!("a blocking socket"),
        }
    }

    fn subscribe(addr: SocketAddr, aps: Value) -> Ui {
        let mut ui = Ui::open(addr, &[]).unwrap();
        ui.send(&json!({ "subscribe": aps }));
        ui
    }

    fn send(&mut self, v: &Value) {
        self.0.send(Message::text(v.to_string())).unwrap();
    }

    fn recv(&mut self) -> Value {
        loop {
            match self.0.read().unwrap() {
                Message::Text(t) => return serde_json::from_str(&t).unwrap(),
                Message::Ping(_) | Message::Pong(_) => {}
                other => panic!("unexpected {other:?}"),
            }
        }
    }
}

#[test]
fn ws_subscribe_counts_watcher() {
    let r = controller(Timing::default());
    let watchers = |ap: &str| r.c.state.read().watchers(ap);
    let mut one = Ui::subscribe(r.c.http, json!(["ap1", "ap9"]));
    assert_eq!(one.recv()["key"]["aps"], json!({"ap1": {"up": false}}));
    assert_eq!((watchers("ap1"), watchers("ap2")), (1, 0));
    let mut all = Ui::subscribe(r.c.http, json!("*"));
    assert_eq!(all.recv()["key"]["aps"].as_object().unwrap().len(), 2);
    assert_eq!((watchers("ap1"), watchers("ap2")), (2, 1));

    // The agent hears it is watched as soon as it connects.
    let mut a = Agent::hello(r.c.agents, KEY_AP1, "ap1");
    assert_eq!(a.expect(), CtlMsg::SetTick { secs: TICK_WATCHED });
    drop(one);
    wait_for("the first socket's watch to end", || watchers("ap1") == 1);
    drop(all);
    wait_for("every watch to end", || {
        watchers("ap1") + watchers("ap2") == 0
    });
    assert_eq!(a.expect(), CtlMsg::SetTick { secs: TICK_IDLE });

    // A socket that never says what it watches watches nothing.
    let _silent = Ui::open(r.c.http, &[]).unwrap();
    thread::sleep(Duration::from_millis(200));
    assert_eq!(watchers("ap1"), 0);
}

#[test]
fn ws_sends_only_what_changed() {
    let r = controller(Timing::default());
    let mut a = Agent::hello(r.c.agents, KEY_AP1, "ap1");
    let bsss = vec![bss("wlan5", "ssid-a")];
    a.send(&AgentMsg::Key(snapshot(
        1,
        bsss,
        vec![station(MAC, 0, -54)],
    )))
    .unwrap();
    wait_for("key frame", || seq_of(&r, "ap1") == Some(1));

    let user = [("x-forwarded-preferred-username", "alice")];
    let mut ui = Ui::open(r.c.http, &user).unwrap();
    ui.send(&json!({"subscribe": ["ap1"]}));
    let key = ui.recv();
    assert_eq!(key["user"], "alice");
    let client = &key["key"]["clients"]["02:00:00:00:00:01"];
    assert_eq!(client["signal"], -54);
    // One snapshot: nothing to work rates out from yet.
    assert!(client.get("down").is_none(), "{client}");

    let uptime_up = || FieldDelta {
        mask: 1,
        vals: vec![1],
    };
    a.send(&AgentMsg::Delta(SnapshotDelta {
        scalars: uptime_up(),
        ..delta(2, 1)
    }))
    .unwrap();
    let patch = ui.recv();
    let p = &patch["patch"];
    assert_eq!(p["aps"]["ap1"]["uptime"], 3601, "{patch}");
    // The second snapshot gives the counters a base: rates appear.
    assert_eq!(p["clients"]["02:00:00:00:00:01"]["down"], 0, "{patch}");
    // The radio's survey clock stood still: no utilization to tell.
    assert!(p["aps"]["ap1"].get("radios").is_none(), "{patch}");

    // The same update again sends nothing: what comes next is the next change.
    a.send(&AgentMsg::Delta(delta(3, 2))).unwrap();
    wait_for("delta 3", || seq_of(&r, "ap1") == Some(3));
    a.send(&AgentMsg::Delta(SnapshotDelta {
        scalars: uptime_up(),
        ..delta(4, 3)
    }))
    .unwrap();
    assert_eq!(
        ui.recv(),
        json!({"patch": {"aps": {"ap1": {"uptime": 3602}}}})
    );

    // Events come as they happen; a client leaving is a null where it was.
    a.send(&AgentMsg::Event(Event {
        at_ms: 9,
        kind: EventKind::Disassoc { mac: MAC, bss: 0 },
    }))
    .unwrap();
    let ev = ui.recv();
    assert_eq!(
        (&ev["events"][0]["kind"], &ev["events"][0]["ssid"]),
        (&json!("disassoc"), &json!("ssid-a")),
        "{ev}"
    );
    a.send(&AgentMsg::Delta(SnapshotDelta {
        removed: vec![MAC],
        ..delta(5, 4)
    }))
    .unwrap();
    let patch = ui.recv();
    assert_eq!(
        patch["patch"]["clients"],
        json!({"02:00:00:00:00:01": null})
    );

    // An AP going down takes its radios with it and says when it was seen.
    drop(a);
    let patch = ui.recv();
    let ap1 = &patch["patch"]["aps"]["ap1"];
    assert_eq!(ap1["up"], false, "{patch}");
    assert_eq!(ap1["radios"], Value::Null, "{patch}");
    assert!(ap1["seen"].is_u64(), "{patch}");
}

#[test]
fn ws_refuses_another_sites_page() {
    let r = controller(Timing::default());
    let refused = Ui::open(r.c.http, &[("origin", "https://elsewhere.example")]);
    match refused {
        Err(tungstenite::Error::Http(resp)) => assert_eq!(resp.status(), 403),
        other => panic!("{:?}", other.map(|_| ())),
    }
    let origin = format!("http://{}", r.c.http);
    let mut ok = Ui::open(r.c.http, &[("origin", &origin)]).unwrap();
    ok.send(&json!({"subscribe": "*"}));
    assert!(ok.recv()["key"].is_object());
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The first two frames of the agent deployed before the version frame
/// (58e88f8, protocol 0): its Hello and a key frame whose Station lacks the
/// rate modes of 828aeae, as that agent's own u6e-proto (`write_frame`)
/// encodes them.
const HELLO_V0: &str = "2100000000036170310b696d6167653a207465737404362e313204322e313105312e302e30";
const KEY_V0: &str = "640000000101901cfa01c09a0c25010363707598e605010470687930012450f823a1904ec413e807f403010105776c616e3002000000100105477565737404706879302a0102000000000100cacac0c407f1f72764c801030188b404aca5050708e807d00f003c2a";

/// What the log says of `ap` until it has been quiet for a while.
fn lines_of(log: &Receiver<String>, ap: &str) -> Vec<String> {
    let quiet = Duration::from_millis(500);
    std::iter::from_fn(|| log.recv_timeout(quiet).ok())
        .filter(|l| l.contains(ap))
        .collect()
}

#[test]
fn an_unversioned_agent_is_turned_away_once() {
    let dir = TempDir::new("unversioned");
    let b = spawn_binary(&dir);
    let opening = [unhex(HELLO_V0), unhex(KEY_V0)].concat();
    // An old agent redials after each session; every one is turned away.
    for _ in 0..5 {
        let mut a = Agent::dial(b.agents, KEY_AP1).unwrap();
        a.send_bytes(&opening).unwrap();
        // The controller's version frame, which such an agent fails to read.
        assert_eq!(version::decode(&a.recv_body().unwrap()), PROTOCOL);
        a.ends();
    }
    let lines = lines_of(&b.log, "ap1");
    assert_eq!(lines.len(), 1, "{lines:#?}");
    assert!(
        lines[0].contains(&format!("protocol 0, this controller {PROTOCOL}")),
        "{}",
        lines[0]
    );

    let body = http_get(b.metrics, "/metrics");
    for line in [
        "wifi_ap_up{ap=\"ap1\"} 0".to_owned(),
        "wifi_agent_protocol{ap=\"ap1\"} 0".to_owned(),
        "wifi_agent_compatible{ap=\"ap1\"} 0".to_owned(),
        format!("wifi_controller_protocol {PROTOCOL}"),
    ] {
        assert!(body.lines().any(|l| l == line), "missing {line}\n{body}");
    }
    assert!(promtool_accepts(&body));
    let ap1 = &json_get(b.http, "/api/aps")["ap1"];
    assert_eq!(ap1["up"], false);
    assert_eq!(ap1["mismatch"], json!({"ap": 0, "controller": PROTOCOL}));
}

/// An agent of protocol 1, from before flows and commands, would misread the
/// commands this controller sends: its version frame turns it away.
#[test]
fn a_protocol_1_agent_is_turned_away() {
    let r = controller(Timing::default());
    for _ in 0..3 {
        let (mut a, theirs) = Agent::versioned(r.c.agents, KEY_AP1, 1);
        assert_eq!(theirs, PROTOCOL);
        a.ends();
    }
    let ap1 = &json_get(r.c.http, "/api/aps")["ap1"];
    assert_eq!(ap1["up"], false);
    assert_eq!(ap1["mismatch"], json!({"ap": 1, "controller": PROTOCOL}));
    let body = http_get(r.c.metrics, "/metrics");
    for line in [
        "wifi_agent_protocol{ap=\"ap1\"} 1",
        "wifi_agent_compatible{ap=\"ap1\"} 0",
    ] {
        assert!(body.lines().any(|l| l == line), "missing {line}\n{body}");
    }
}

#[test]
fn an_agent_of_another_protocol_is_turned_away() {
    let r = controller(Timing::default());
    let up = |ap: &str| r.c.state.read().ap(ap).unwrap().is_up();
    let newer = PROTOCOL + 1;
    for _ in 0..3 {
        let (mut a, theirs) = Agent::versioned(r.c.agents, KEY_AP1, newer);
        assert_eq!(theirs, PROTOCOL);
        a.ends();
    }
    let ap1 = &json_get(r.c.http, "/api/aps")["ap1"];
    assert_eq!(ap1["up"], false);
    assert_eq!(
        ap1["mismatch"],
        json!({"ap": newer, "controller": PROTOCOL})
    );
    let body = http_get(r.c.metrics, "/metrics");
    for line in [
        format!("wifi_agent_protocol{{ap=\"ap1\"}} {newer}"),
        "wifi_agent_compatible{ap=\"ap1\"} 0".to_owned(),
    ] {
        assert!(body.lines().any(|l| l == line), "missing {line}\n{body}");
    }

    // Updated to this protocol, it is served again.
    let _a = Agent::hello(r.c.agents, KEY_AP1, "ap1");
    wait_for("ap1 up", || up("ap1"));
    let ap1 = &json_get(r.c.http, "/api/aps")["ap1"];
    assert!(ap1.get("mismatch").is_none(), "{ap1}");
    let body = http_get(r.c.metrics, "/metrics");
    assert!(
        body.contains("wifi_agent_compatible{ap=\"ap1\"} 1\n"),
        "{body}"
    );

    // An AP that comes back with another protocol ends the session it held.
    let mut old = Agent::hello(r.c.agents, KEY_AP2, "ap2");
    wait_for("ap2 up", || up("ap2"));
    let (mut a, _) = Agent::versioned(r.c.agents, KEY_AP2, newer);
    a.ends();
    assert!(!up("ap2"));
    while let Ok(msg) = old.recv() {
        assert!(matches!(msg, CtlMsg::Ping(_)), "{msg:?}");
    }
}

/// A request over HTTP/1.1: the status line and headers (lowercased), and
/// the body.
fn http_send(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &str,
    body: &str,
) -> (String, String) {
    let mut sock = TcpStream::connect(addr).unwrap();
    sock.set_read_timeout(Some(WAIT)).unwrap();
    write!(
        sock,
        "{method} {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n{headers}\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut resp = String::new();
    sock.read_to_string(&mut resp).unwrap();
    let (head, body) = resp.split_once("\r\n\r\n").unwrap();
    (head.to_lowercase(), body.to_owned())
}

/// The status and JSON body of an action.
fn post(addr: SocketAddr, path: &str, headers: &str, body: &str) -> (u16, Value) {
    let (head, body) = http_send(addr, "POST", path, headers, body);
    let status = head[9..12].parse().unwrap();
    (status, serde_json::from_str(&body).unwrap())
}

const CLIENT: &str = "/api/clients/02:00:00:00:00:01";

/// An AP of `name` up with `MAC` on its one BSS, its blocks synced (and
/// checked to be `blocked`).
fn ap_with_client(r: &Running, pem: &str, name: &str, blocked: &[[u8; 6]]) -> Agent {
    let mut a = Agent::hello(r.c.agents, pem, name);
    let s = snapshot(1, vec![bss("wlan5", "Guest")], vec![station(MAC, 0, -54)]);
    a.send(&AgentMsg::Key(s)).unwrap();
    assert_eq!(a.expect_sync(), blocked);
    a
}

/// The lines of the metrics that start with `prefix`.
fn metrics_of(r: &Running, prefix: &str) -> Vec<String> {
    let body = http_get(r.c.metrics, "/metrics");
    let lines = body.lines().filter(|l| l.starts_with(prefix));
    lines.map(str::to_owned).collect()
}

#[test]
fn actions_refuse_cross_site() {
    let r = controller(Timing::default());
    let mut a = ap_with_client(&r, KEY_AP1, "ap1", &[]);
    let kick = format!("{CLIENT}/kick");
    let origin = "Origin: https://wifi.example.org\r\n";
    let json = "Content-Type: application/json\r\n";
    for headers in [
        // A form or a plain-text body: what another site's page can send
        // without asking first.
        format!("{origin}Content-Type: text/plain\r\n"),
        format!("{origin}Content-Type: application/x-www-form-urlencoded\r\n"),
        origin.to_owned(),
        // Another site, or one that hides where it is.
        format!("{json}Origin: https://elsewhere.example\r\n"),
        format!("{json}Origin: null\r\n"),
        json.to_owned(),
    ] {
        let (status, body) = post(r.c.http, &kick, &format!("{headers}{ADMIN}"), "{}");
        assert_eq!(
            (status, body),
            (403, json!({"error": "cross-site"})),
            "{headers}"
        );
    }
    // Refused before the group is looked at.
    let (status, body) = post(r.c.http, &kick, "", "{}");
    assert_eq!((status, body), (403, json!({"error": "cross-site"})));

    // Nothing reached the AP: the next command is the one allowed.
    let t = thread::spawn(move || post(r.c.http, &kick, &format!("{SAME_SITE}{ADMIN}"), "{}"));
    let id = a.expect_command(CommandKind::Kick { mac: MAC });
    a.reply(id, true, "wlan5: OK");
    assert_eq!(t.join().unwrap().0, 200);
    assert_eq!(r.c.state.read().actions.len(), 1);
}

#[test]
fn actions_require_wifi_admins() {
    let r = controller(Timing::default());
    let mut a = ap_with_client(&r, KEY_AP1, "ap1", &[]);
    let kick = format!("{CLIENT}/kick");
    let user = "X-Forwarded-Preferred-Username: bob\r\n";
    for groups in [
        // No groups at all: the proxy sends no header.
        "",
        "X-Auth-Request-Groups: staff,wifi-admins-old\r\n",
        "X-Auth-Request-Groups: \r\n",
        // Another proxy's spelling is never read.
        "X-Forwarded-Groups: wifi-admins\r\n",
    ] {
        let (status, body) = post(r.c.http, &kick, &format!("{SAME_SITE}{user}{groups}"), "{}");
        assert_eq!(
            (status, body),
            (403, json!({"error": "not an admin"})),
            "{groups}"
        );
    }
    for path in ["block", "unblock", "steer"] {
        let p = format!("{CLIENT}/{path}");
        let (status, _) = post(
            r.c.http,
            &p,
            SAME_SITE,
            "{\"target_bssid\":\"02:00:00:00:10:02\"}",
        );
        assert_eq!(status, 403, "{path}");
    }
    assert!(r.c.state.read().blocked.is_empty());
    assert!(r.c.state.read().actions.is_empty());
    let me = |headers: &str| {
        let (_, body) = http_send(r.c.http, "GET", "/api/me", headers, "");
        serde_json::from_str::<Value>(&body).unwrap()
    };
    assert_eq!(me(user), json!({"user": "bob", "admin": false}));
    assert_eq!(me(ADMIN), json!({"user": "alice", "admin": true}));
    assert_eq!(me(""), json!({"user": null, "admin": false}));

    // An admin's kick reaches the AP the client is on, and is an event.
    let t = thread::spawn(move || post(r.c.http, &kick, &format!("{SAME_SITE}{ADMIN}"), "{}"));
    let id = a.expect_command(CommandKind::Kick { mac: MAC });
    a.reply(id, true, "wlan5: OK");
    let (status, body) = t.join().unwrap();
    assert_eq!(status, 200);
    assert_eq!(
        body,
        json!({"ap": "ap1", "ok": true, "detail": "wlan5: OK"})
    );
    let events = json_get(r.c.http, "/api/events?ap=ap1");
    let ev = events.as_array().unwrap().last().unwrap().clone();
    let at = ev["at"].clone();
    assert!(at.is_u64(), "{ev}");
    assert_eq!(
        ev,
        json!({"at": at, "kind": "action", "action": "kick", "user": "alice",
            "mac": "02:00:00:00:00:01", "ap": "ap1", "ok": true, "detail": "wlan5: OK"})
    );
    assert_eq!(
        metrics_of(&r, "wifi_actions_total{action=\"kick\""),
        [
            "wifi_actions_total{action=\"kick\",result=\"ok\"} 1",
            "wifi_actions_total{action=\"kick\",result=\"failed\"} 0",
            "wifi_actions_total{action=\"kick\",result=\"timeout\"} 0",
        ]
    );

    // A client on no AP is refused, and that is an event too.
    let (status, body) = post(
        r.c.http,
        "/api/clients/02:00:00:00:00:99/kick",
        &format!("{SAME_SITE}{ADMIN}"),
        "{}",
    );
    assert_eq!((status, body), (404, json!({"error": "not associated"})));
    let (status, _) = post(
        r.c.http,
        "/api/clients/nope/kick",
        &format!("{SAME_SITE}{ADMIN}"),
        "",
    );
    assert_eq!(status, 400);
}

/// Review focus 1: a client blocked, and another unblocked, while its AP is
/// away is blocked (and let on) when the AP comes back, by the one sync that
/// makes the AP's blocks the policy's.
#[test]
fn block_resent_on_reconnect() {
    let r = controller(Timing::default());
    let admin = format!("{SAME_SITE}{ADMIN}");
    let other = [0x02, 0, 0, 0, 0, 0x02];
    let mut a = ap_with_client(&r, KEY_AP1, "ap1", &[]);
    // Blocked while ap1 is up: sent to it at once.
    let t = {
        let admin = admin.clone();
        thread::spawn(move || post(r.c.http, "/api/clients/02:00:00:00:00:02/block", &admin, ""))
    };
    let id = a.expect_command(CommandKind::Block { mac: other });
    a.reply(id, true, "wlan5: OK; kick: not associated here");
    assert_eq!(t.join().unwrap().0, 200);
    drop(a);
    wait_for("ap1 down", || !r.c.state.read().ap("ap1").unwrap().is_up());

    // Blocked and unblocked while no AP is connected: saved all the same.
    let (status, body) = post(r.c.http, &format!("{CLIENT}/block"), &admin, "");
    assert_eq!(status, 200);
    assert_eq!(
        body,
        json!({"ok": true, "results": [{"ok": true, "detail": "saved; no AP is connected"}]})
    );
    let (status, _) = post(
        r.c.http,
        "/api/clients/02:00:00:00:00:02/unblock",
        &admin,
        "",
    );
    assert_eq!(status, 200);
    assert_eq!(
        metrics_of(&r, "wifi_blocked_clients"),
        ["wifi_blocked_clients 1"]
    );

    // Back: the AP's blocks are made exactly the policy's, which lets
    // `other` on there too; again on every connection.
    let a = ap_with_client(&r, KEY_AP1, "ap1", &[MAC]);
    drop(a);
    let _a = ap_with_client(&r, KEY_AP1, "ap1", &[MAC]);
    // ap2 dials in for the first time: the same.
    let _b = ap_with_client(&r, KEY_AP2, "ap2", &[MAC]);
}

/// The policy is saved before an AP hears of it, and is what the next
/// controller starts with.
#[test]
fn policy_survives_restart() {
    let dir = TempDir::new("restart");
    let admin = format!("{SAME_SITE}{ADMIN}");
    {
        let r = controller_in(Timing::default(), &dir.0);
        let (status, _) = post(r.c.http, &format!("{CLIENT}/block"), &admin, "");
        assert_eq!(status, 200);
        let text = fs::read_to_string(dir.0.join("policy.json")).unwrap();
        let saved: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(saved, json!({"blocked": ["02:00:00:00:00:01"]}));
    }
    let r = controller_in(Timing::default(), &dir.0);
    assert_eq!(r.c.state.read().blocked.len(), 1);
    let _a = ap_with_client(&r, KEY_AP1, "ap1", &[MAC]);

    // A policy file that does not parse stops the controller from starting
    // rather than letting every blocked client back on.
    drop(r);
    fs::write(dir.0.join("policy.json"), "{\"blocked\": [\"02:00\"]}").unwrap();
    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    let config = Config::parse(&config_text("unused.pem", true, &dir.0)).unwrap();
    let resolver: Arc<dyn Resolve> = Arc::new(FakeDns::default());
    let started = rt.block_on(start(
        &config,
        &identity(KEY_CONTROLLER),
        Timing::default(),
        resolver,
    ));
    let e = started.err().expect("started on a bad policy");
    assert!(e.to_string().contains("policy.json"), "{e}");
}

/// The clients blocked are listed whether an AP holds them or not, so one
/// kept off every AP can still be unblocked; an associated one says so too.
#[test]
fn blocked_clients_listed() {
    let r = controller(Timing::default());
    let mut a = ap_with_client(&r, KEY_AP1, "ap1", &[]);
    let mut ui = Ui::subscribe(r.c.http, json!("*"));
    let key = ui.recv();
    assert_eq!(key["key"]["blocked"], json!([]));
    assert_eq!(key["key"]["clients"]["02:00:00:00:00:01"]["blocked"], false);
    assert_eq!(a.expect(), CtlMsg::SetTick { secs: TICK_WATCHED });
    let mut block = |mac: [u8; 6]| {
        let (addr, path) = (r.c.http, format!("/api/clients/{}/block", mac::format(mac)));
        let t = thread::spawn(move || post(addr, &path, &format!("{SAME_SITE}{ADMIN}"), ""));
        let id = a.expect_command(CommandKind::Block { mac });
        a.reply(id, true, "OK");
        assert_eq!(t.join().unwrap().0, 200);
    };
    let blocked_patch = |ui: &mut Ui| loop {
        let m = ui.recv();
        if m["patch"].get("blocked").is_some() {
            return m["patch"].clone();
        }
    };

    // One no AP holds: listed, and nothing else changes.
    block([0x02, 0, 0, 0, 0, 0x09]);
    let patch = blocked_patch(&mut ui);
    assert_eq!(patch, json!({"blocked": ["02:00:00:00:00:09"]}));
    // One the AP still holds: listed, and its own entry says so.
    block(MAC);
    let patch = blocked_patch(&mut ui);
    let both = json!(["02:00:00:00:00:01", "02:00:00:00:00:09"]);
    assert_eq!(patch["blocked"], both);
    assert_eq!(patch["clients"]["02:00:00:00:00:01"]["blocked"], true);
    let clients = json_get(r.c.http, "/api/clients");
    assert_eq!(clients["02:00:00:00:00:01"]["blocked"], true);
}

#[test]
fn steer_routed_to_the_clients_ap() {
    let r = controller(Timing::default());
    let admin = format!("{SAME_SITE}{ADMIN}");
    // ap1 carries another client, ap2 the one steered.
    let mut one = Agent::hello(r.c.agents, KEY_AP1, "ap1");
    let other = [0x02, 0, 0, 0, 0, 0x02];
    let s = snapshot(1, vec![bss("wlan5", "Guest")], vec![station(other, 0, -50)]);
    one.send(&AgentMsg::Key(s)).unwrap();
    assert!(one.expect_sync().is_empty());
    let mut two = ap_with_client(&r, KEY_AP2, "ap2", &[]);

    let target = [0x02, 0, 0, 0, 0x10, 0x09];
    let body = "{\"target_bssid\": \"02:00:00:00:10:09\"}";
    let t = {
        let admin = admin.clone();
        thread::spawn(move || post(r.c.http, &format!("{CLIENT}/steer"), &admin, body))
    };
    let id = two.expect_command(CommandKind::Steer {
        mac: MAC,
        target_bssid: target,
    });
    two.reply(id, false, "unknown target");
    let (status, body) = t.join().unwrap();
    assert_eq!(status, 200);
    assert_eq!(
        body,
        json!({"ap": "ap2", "ok": false, "detail": "unknown target"})
    );
    assert_eq!(
        metrics_of(&r, "wifi_actions_total{action=\"steer\",result=\"failed\"}"),
        ["wifi_actions_total{action=\"steer\",result=\"failed\"} 1"]
    );

    // ap1 heard nothing of it: its next command is its own client's.
    let t = {
        let admin = admin.clone();
        thread::spawn(move || post(r.c.http, "/api/clients/02:00:00:00:00:02/kick", &admin, ""))
    };
    let id = one.expect_command(CommandKind::Kick { mac: other });
    one.reply(id, true, "wlan5: OK");
    assert_eq!(t.join().unwrap().0, 200);

    for bad in [
        "",
        "{}",
        "{\"target_bssid\": \"nope\"}",
        "{\"target_bssid\": \"02:00:00:00:10:09\", \"x\": 1}",
    ] {
        let (status, _) = post(r.c.http, &format!("{CLIENT}/steer"), &admin, bad);
        assert_eq!(status, 400, "{bad}");
    }
}

#[test]
fn an_unanswered_command_times_out() {
    let timing = Timing {
        command: Duration::from_millis(300),
        ..Timing::default()
    };
    let r = controller(timing);
    let mut a = ap_with_client(&r, KEY_AP1, "ap1", &[]);
    let admin = format!("{SAME_SITE}{ADMIN}");
    let t = thread::spawn(move || post(r.c.http, &format!("{CLIENT}/kick"), &admin, ""));
    let id = a.expect_command(CommandKind::Kick { mac: MAC });
    let (status, body) = t.join().unwrap();
    assert_eq!(status, 504);
    assert_eq!(
        body,
        json!({"ap": "ap1", "ok": false, "detail": "no answer from the AP in 300ms"})
    );
    // Too late: dropped, and the session goes on.
    a.reply(id, true, "wlan5: OK");
    let s = r.c.state.read();
    let last = s.actions.back().unwrap();
    assert_eq!((last.action, last.ok), ("kick", false));
    drop(s);
    assert_eq!(
        metrics_of(&r, "wifi_actions_total{action=\"kick\",result=\"timeout\"}"),
        ["wifi_actions_total{action=\"kick\",result=\"timeout\"} 1"]
    );
    a.send(&AgentMsg::Pong(0)).unwrap();
    assert!(r.c.state.read().ap("ap1").unwrap().is_up());
}

fn flow(src: &str, dst: &str, bytes: u64, offloaded: bool) -> Flow {
    Flow {
        proto: 6,
        src: src.parse().unwrap(),
        sport: 50_000,
        dst: dst.parse().unwrap(),
        dport: 443,
        tx_bytes: bytes,
        rx_bytes: bytes * 10,
        tx_packets: 10,
        rx_packets: 20,
        offloaded,
        age_s: 30,
        client_is_src: true,
    }
}

fn flows(seq: u64, top: Vec<Flow>, conns: u32) -> Flows {
    let sum = |f: fn(&Flow) -> u64| top.iter().map(f).sum();
    Flows {
        seq,
        complete: true,
        clients: vec![ClientFlows {
            mac: MAC,
            conns,
            offloaded: top.iter().filter(|f| f.offloaded).count() as u32,
            tx_bytes: sum(|f| f.tx_bytes),
            rx_bytes: sum(|f| f.rx_bytes),
            tx_packets: sum(|f| f.tx_packets),
            rx_packets: sum(|f| f.rx_packets),
            top,
        }],
    }
}

#[test]
fn flows_api_shape() {
    let r = controller(Timing::default());
    let mut a = ap_with_client(&r, KEY_AP1, "ap1", &[]);
    let top = vec![
        flow("192.0.2.10", "198.51.100.1", 1000, true),
        flow("2001:db8::10", "2001:db8:1::1", 10, false),
    ];
    a.send(&AgentMsg::Flows(flows(1, top, 9))).unwrap();
    wait_for("the flows", || {
        r.c.state.read().ap("ap1").unwrap().flows.is_some()
    });

    let got = json_get(r.c.http, "/api/flows");
    let at = got["ap1"]["at"].clone();
    assert!(at.is_u64(), "{got}");
    let client = json!({
        "conns": 9, "offloaded": 1, "tx_bytes": 1010, "rx_bytes": 10100,
        "tx_packets": 20, "rx_packets": 40,
        "top": [
            {"proto": 6, "src": "192.0.2.10", "sport": 50000, "dst": "198.51.100.1",
             "dport": 443, "tx_bytes": 1000, "rx_bytes": 10000, "tx_packets": 10,
             "rx_packets": 20, "offloaded": true, "age": 30, "client_is_src": true},
            {"proto": 6, "src": "2001:db8::10", "sport": 50000, "dst": "2001:db8:1::1",
             "dport": 443, "tx_bytes": 10, "rx_bytes": 100, "tx_packets": 10,
             "rx_packets": 20, "offloaded": false, "age": 30, "client_is_src": true},
        ],
    });
    let want = json!({"ap1": {"at": at, "seq": 1, "complete": true,
        "clients": {"02:00:00:00:00:01": client}}});
    assert_eq!(got, want);
    assert_eq!(
        json_get(r.c.http, "/api/flows?ap=ap1&client=02:00:00:00:00:01"),
        want
    );
    assert_eq!(
        json_get(r.c.http, "/api/flows?client=02:00:00:00:00:99")["ap1"]["clients"],
        json!({})
    );
    assert_eq!(json_get(r.c.http, "/api/flows?ap=ap2"), json!({}));
    let (head, _) = http_request(r.c.http, "/api/flows?client=nope", "");
    assert!(head.starts_with("http/1.1 400"), "{head}");
    let labels = "{ap=\"ap1\",ssid=\"Guest\",mac=\"02:00:00:00:00:01\"}";
    assert_eq!(
        metrics_of(&r, "wifi_client_conns{"),
        [format!("wifi_client_conns{labels} 9")]
    );
    assert_eq!(
        metrics_of(&r, "wifi_client_offloaded_conns{"),
        [format!("wifi_client_offloaded_conns{labels} 1")]
    );

    // The whole table answers its request only, and is not kept.
    let t = thread::spawn(move || http_send(r.c.http, "GET", "/api/flows/full?ap=ap1", "", ""));
    assert_eq!(a.expect(), CtlMsg::WantFlows { full: true });
    let every: Vec<Flow> = (1..=9)
        .map(|i| flow("192.0.2.10", &format!("198.51.100.{i}"), i, false))
        .collect();
    a.send(&AgentMsg::Flows(flows(2, every, 9))).unwrap();
    let (head, body) = t.join().unwrap();
    assert!(head.starts_with("http/1.1 200"), "{head}");
    let full: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(full["ap1"]["seq"], 2);
    assert_eq!(
        full["ap1"]["clients"]["02:00:00:00:00:01"]["top"]
            .as_array()
            .unwrap()
            .len(),
        9
    );
    assert_eq!(json_get(r.c.http, "/api/flows")["ap1"]["seq"], 1);
    let (head, _) = http_send(r.c.http, "GET", "/api/flows/full?ap=ap2", "", "");
    assert!(head.starts_with("http/1.1 404"), "{head}");
}

#[test]
fn a_full_table_is_asked_for_once_per_interval() {
    let timing = Timing {
        command: Duration::from_millis(300),
        ping: Duration::from_millis(200),
        ..Timing::default()
    };
    let r = controller(timing);
    let mut a = ap_with_client(&r, KEY_AP1, "ap1", &[]);
    // Two requests at once: one ask, unanswered, so both time out.
    let full = move || http_send(r.c.http, "GET", "/api/flows/full?ap=ap1", "", "");
    let (one, two) = (thread::spawn(full), thread::spawn(full));
    assert_eq!(a.expect(), CtlMsg::WantFlows { full: true });
    for t in [one, two] {
        let (head, _) = t.join().unwrap();
        assert!(head.starts_with("http/1.1 504"), "{head}");
    }
    // The AP was asked a moment ago: refused until the interval is out,
    // and the AP hears nothing; the next message it gets is its own ping.
    let (head, body) = full();
    assert!(head.starts_with("http/1.1 429"), "{head}");
    let wait: u64 = header(&head, "retry-after").unwrap().parse().unwrap();
    assert!((1..=10).contains(&wait), "{wait}");
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        json!({"error": "the AP was asked moments ago"})
    );
    a.send(&AgentMsg::Pong(0)).unwrap();
    assert!(matches!(a.recv().unwrap(), CtlMsg::Ping(_)));
}

#[test]
fn cadence_follows_watchers() {
    let r = controller(Timing::default());
    let mut a = ap_with_client(&r, KEY_AP1, "ap1", &[]);
    // Watching the APs alone sets the tick, not the flows' cadence.
    let mut plain = Ui::subscribe(r.c.http, json!(["ap1"]));
    assert!(plain.recv()["key"].get("flows").is_none());
    assert_eq!(a.expect(), CtlMsg::SetTick { secs: TICK_WATCHED });
    let mut ui = Ui::open(r.c.http, &[]).unwrap();
    ui.send(&json!({"subscribe": ["ap1"], "flows": true}));
    assert_eq!(ui.recv()["key"]["flows"], json!({}));
    assert_eq!(
        a.expect(),
        CtlMsg::FlowCadence {
            secs: FLOWS_WATCHED
        }
    );
    assert_eq!(r.c.state.read().flow_watchers("ap1"), 1);

    // Flows reach the watching socket.
    let top = vec![flow("192.0.2.10", "198.51.100.1", 5, true)];
    a.send(&AgentMsg::Flows(flows(1, top, 1))).unwrap();
    let patch = ui.recv();
    assert_eq!(patch["patch"]["flows"]["ap1"]["seq"], 1, "{patch}");

    // An AP that connects while watched hears it at once.
    drop(a);
    let mut a = Agent::hello(r.c.agents, KEY_AP1, "ap1");
    assert_eq!(a.expect(), CtlMsg::SetTick { secs: TICK_WATCHED });
    assert_eq!(
        a.expect(),
        CtlMsg::FlowCadence {
            secs: FLOWS_WATCHED
        }
    );
    drop(ui);
    assert_eq!(a.expect(), CtlMsg::FlowCadence { secs: FLOWS_IDLE });
    drop(plain);
    assert_eq!(a.expect(), CtlMsg::SetTick { secs: TICK_IDLE });
}

/// The page asks for the flows, and stops, on the socket it has open: the
/// AP's cadence follows, and the flows come and go in the patches.
#[test]
fn ws_flows_follow_the_page() {
    let r = controller(Timing::default());
    let mut a = ap_with_client(&r, KEY_AP1, "ap1", &[]);
    let mut ui = Ui::subscribe(r.c.http, json!(["ap1"]));
    assert!(ui.recv()["key"].get("flows").is_none());
    assert_eq!(a.expect(), CtlMsg::SetTick { secs: TICK_WATCHED });

    ui.send(&json!({"flows": true}));
    assert_eq!(ui.recv(), json!({"patch": {"flows": {}}}));
    assert_eq!(
        a.expect(),
        CtlMsg::FlowCadence {
            secs: FLOWS_WATCHED
        }
    );
    // Said again, or something else said, it changes nothing.
    ui.send(&json!({"flows": true}));
    ui.send(&json!({"what": 1}));
    assert_eq!(r.c.state.read().flow_watchers("ap1"), 1);

    ui.send(&json!({"flows": false}));
    assert_eq!(ui.recv(), json!({"patch": {"flows": null}}));
    assert_eq!(a.expect(), CtlMsg::FlowCadence { secs: FLOWS_IDLE });
    assert_eq!(r.c.state.read().flow_watchers("ap1"), 0);
    // The socket still watches the AP itself.
    assert_eq!(r.c.state.read().watchers("ap1"), 1);
}

/// A client whose only connection was opened from outside is named by its
/// own address, never by the end that opened it.
#[test]
fn a_flow_opened_from_outside_names_the_client() {
    let r = controller(Timing::default());
    let mut a = ap_with_client(&r, KEY_AP1, "ap1", &[]);
    let (client, opener) = (
        "192.0.2.20".parse().unwrap(),
        "198.51.100.9".parse().unwrap(),
    );
    let mut names = r.dns.names.lock().unwrap();
    names.insert(client, "printer.lan.example".into());
    names.insert(opener, "scanner.elsewhere.example".into());
    drop(names);
    let inbound = Flow {
        client_is_src: false,
        ..flow("198.51.100.9", "192.0.2.20", 5, true)
    };
    a.send(&AgentMsg::Flows(flows(1, vec![inbound], 1)))
        .unwrap();
    wait_for("the client's name", || {
        r.c.state.read().name_of(&MAC) == Some("printer.lan.example")
    });
    assert_eq!(*r.dns.asked.lock().unwrap(), [client]);
}

#[test]
fn names_resolved_from_the_flows_addresses() {
    let r = controller(Timing::default());
    let mut a = ap_with_client(&r, KEY_AP1, "ap1", &[]);
    let (v4, v6) = (
        "192.0.2.10".parse().unwrap(),
        "2001:db8::10".parse().unwrap(),
    );
    r.dns
        .names
        .lock()
        .unwrap()
        .insert(v6, "tablet.lan.example".into());
    let mut ui = Ui::subscribe(r.c.http, json!("*"));
    assert!(
        ui.recv()["key"]["clients"]["02:00:00:00:00:01"]
            .get("name")
            .is_none()
    );
    let top = vec![
        flow("192.0.2.10", "198.51.100.1", 1000, true),
        flow("192.0.2.10", "198.51.100.2", 100, true),
        flow("2001:db8::10", "2001:db8:1::1", 10, false),
    ];
    for seq in 1..=3 {
        a.send(&AgentMsg::Flows(flows(seq, top.clone(), 3)))
            .unwrap();
    }
    // The v4 address has no name; the v6 one's is the client's.
    loop {
        let msg = ui.recv();
        if let Some(name) = msg["patch"]["clients"]["02:00:00:00:00:01"].get("name") {
            assert_eq!(name, "tablet.lan.example");
            break;
        }
    }
    let c = &json_get(r.c.http, "/api/clients")["02:00:00:00:00:01"];
    assert_eq!(c["name"], "tablet.lan.example");
    let f = json_get(r.c.http, "/api/flows");
    assert_eq!(
        f["ap1"]["clients"]["02:00:00:00:00:01"]["name"],
        "tablet.lan.example"
    );
    // Each address once, however many flows showed it.
    wait_for("both lookups", || r.dns.asked.lock().unwrap().len() >= 2);
    let mut asked = r.dns.asked.lock().unwrap().clone();
    asked.sort();
    assert_eq!(asked, [v4, v6]);
}
