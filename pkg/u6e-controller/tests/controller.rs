//! The controller against fake agents on loopback. Each test starts its own
//! controller (in-process, or the binary when only its log can show the
//! result) on ports of its own, and speaks the link to it with u6e-proto
//! alone: a blocking rustls client, the framing and the messages.

use std::hash::{DefaultHasher, Hasher};
use std::io::{self, BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
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
use u6e_controller::state::{TICK_IDLE, TICK_WATCHED};
use u6e_controller::{Controller, start};
use u6e_proto::frame::{decode_frame, write_frame};
use u6e_proto::msg::{
    AgentMsg, Band, Bss, CtlMsg, Event, EventKind, FieldDelta, Hello, Radio, RateMode, Snapshot,
    SnapshotDelta, Station, Temp,
};
use u6e_proto::tls::{self, Identity};

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

fn hex(key: [u8; 32]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

/// A configuration on loopback ports of the system's choosing, admitting
/// `ap1` and, with `ap2`, `ap2`.
fn config_text(key: &str, ap2: bool) -> String {
    let mut text = format!(
        "listen_agents = \"127.0.0.1:0\"\nlisten_http = \"127.0.0.1:0\"\n\
         listen_metrics = \"127.0.0.1:0\"\nkey = \"{key}\"\n\
         [aps.ap1]\npublic_key = \"{}\"\n",
        hex(identity(KEY_AP1).public_key())
    );
    if ap2 {
        let k = hex(identity(KEY_AP2).public_key());
        text.push_str(&format!("[aps.ap2]\npublic_key = \"{k}\"\n"));
    }
    text
}

/// A controller in this process, alive as long as the runtime.
struct Running {
    c: Controller,
    _rt: Runtime,
}

fn controller(timing: Timing) -> Running {
    // Two workers are plenty, and a worker per core in every test of eight
    // test processes at once runs into the threads a cgroup allows.
    let rt = Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let config = Config::parse(&config_text("unused.pem", true)).unwrap();
    let c = rt
        .block_on(start(&config, &identity(KEY_CONTROLLER), timing))
        .unwrap();
    Running { c, _rt: rt }
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
        })
    }

    /// An enrolled AP that has said Hello.
    fn hello(addr: SocketAddr, pem: &str, ap: &str) -> Agent {
        let mut a = Agent::dial(addr, pem).unwrap();
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
        self.conn.writer().write_all(&out)?;
        while self.conn.wants_write() {
            self.conn.write_tls(&mut self.sock)?;
        }
        Ok(())
    }

    /// The next message from the controller, pings included.
    fn recv(&mut self) -> io::Result<CtlMsg> {
        loop {
            match self.conn.reader().read_to_end(&mut self.buf) {
                Ok(_) => return Err(ErrorKind::UnexpectedEof.into()),
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
            if let Some((msg, n)) = decode_frame(&self.buf)? {
                self.buf.drain(..n);
                return Ok(msg);
            }
            if self.conn.read_tls(&mut self.sock)? == 0 {
                return Err(ErrorKind::UnexpectedEof.into());
            }
            self.conn.process_new_packets().map_err(io::Error::other)?;
        }
    }

    /// The next message other than a ping, which is answered.
    fn expect(&mut self) -> CtlMsg {
        let start = Instant::now();
        loop {
            // Answered pings would otherwise keep a missing message waited for.
            assert!(start.elapsed() < WAIT, "no message from the controller");
            match self.recv().unwrap() {
                CtlMsg::Ping(n) => self.send(&AgentMsg::Pong(n)).unwrap(),
                msg => return msg,
            }
        }
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

/// The controller binary, its log lines, and the agents and metrics addresses
/// it reported.
fn spawn_binary(dir: &TempDir) -> (Proc, Receiver<String>, SocketAddr, SocketAddr) {
    let key = dir.0.join("key.pem");
    fs::write(&key, KEY_CONTROLLER).unwrap();
    let config = dir.0.join("config.toml");
    fs::write(&config, config_text(key.to_str().unwrap(), false)).unwrap();
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
    (proc, log, addr("agents on "), addr("metrics on "))
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
    let (_proc, log, agents, metrics) = spawn_binary(&dir);

    // TLS 1.3 completes the client's side first; the refusal shows at the read.
    let mut stranger = Agent::dial(agents, KEY_STRANGER).unwrap();
    let local = stranger.sock.local_addr().unwrap();
    let _ = stranger.send(&AgentMsg::Pong(0));
    assert!(stranger.recv().is_err());
    let refused = wait_line(&log, |l| l.contains(&format!("{local}: handshake refused")));
    let fp = tls::fingerprint(&identity(KEY_STRANGER).public_key());
    assert!(
        refused.contains(&format!("client key {fp} is not enrolled")),
        "{refused}"
    );

    let body = http_get(metrics, "/metrics");
    let up: Vec<_> = body
        .lines()
        .filter(|l| l.starts_with("wifi_ap_up"))
        .collect();
    assert_eq!(up, ["wifi_ap_up{ap=\"ap1\"} 0"]);

    // The enrolled AP is still served.
    let mut a = Agent::hello(agents, KEY_AP1, "ap1");
    a.send(&AgentMsg::Key(snapshot(1, Vec::new(), Vec::new())))
        .unwrap();
    wait_line(&log, |l| l.contains("ap1 up from"));
    wait_for("ap1 up in the metrics", || {
        http_get(metrics, "/metrics").contains("wifi_ap_up{ap=\"ap1\"} 1\n")
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
