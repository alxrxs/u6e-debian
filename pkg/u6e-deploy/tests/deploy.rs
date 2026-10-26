//! The runner against a controller in this process and fake APs, which
//! judge every configuration as the agent does (`config::verify`, then
//! `config::replayed` against the last one applied and the image's build
//! time, and `config::expired`; one with a radio marked `# refused` stands
//! for one the AP finds wrong), and a stage helper on a socket of the test's
//! own whose staging script logs what it is asked to stage. The controller
//! and the runner can each be restarted, their files kept.

use std::fs;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::KeyPair;
use tokio::runtime::{Builder, Runtime};
use tokio_rustls::rustls::ClientConnection;
use tokio_rustls::rustls::pki_types::ServerName;
use u6e_controller::agents::Timing;
use u6e_controller::names::Resolve;
use u6e_deploy::config::Config;
use u6e_deploy::{local, script, stage};
use u6e_proto::config::{self, config_sha256};
use u6e_proto::frame::{decode_frame, frame_body, write_frame};
use u6e_proto::msg::{
    AgentMsg, Band, Bss, CommandResult, ConfigApplied, CtlMsg, Hello, Mechanism, Radio,
    RadioApplied, RadioConfig, RateMode, SignedConfig, Snapshot, Station,
};
use u6e_proto::tls::{self, Identity};
use u6e_proto::{PROTOCOL, mac, version};

#[path = "../../u6e-controller/tests/common/keys.rs"]
mod keys;

use keys::{KEY_AP1, KEY_AP2, KEY_CONTROLLER};

// Throwaway keys made for these tests; they protect nothing. The runner's
// link key, and the key it signs configurations with.
const KEY_RUNNER: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINAqUTkY6FWIuFA8ryg9VCageTDEsBn8b3MW/ZMra3Ny\n-----END PRIVATE KEY-----\n";
const KEY_SIGNING: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAZae5VMrg9vRlxfW+DcRK5bRp5FRJ/vfTQn5f3VL1hf\n-----END PRIVATE KEY-----\n";

const WAIT: Duration = Duration::from_secs(20);
const SCRIPT: &str = include_str!("fixtures/u6e-wifi.sh");

fn identity(pem: &str) -> Identity {
    Identity::from_pem(pem).unwrap()
}

fn signing_public() -> [u8; 32] {
    let key = u6e_deploy::signing_key(KEY_SIGNING, &identity(KEY_RUNNER)).unwrap();
    key.public_key().as_ref().try_into().unwrap()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let start = Instant::now();
    while !cond() {
        assert!(start.elapsed() < WAIT, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(10));
    }
}

/// A directory of the test's own, removed when it ends.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("u6e-deploy-it-{name}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct NoNames;

impl Resolve for NoNames {
    fn reverse(&self, _: IpAddr) -> Option<String> {
        None
    }
}

/// The images kept for the tests, by AP.
const KEPT: [&str; 5] = [
    "img-1-ap1",
    "img-2-ap1",
    "img-slow-ap1",
    "img-bad-ap1",
    "img-1-ap2",
];

/// The staging script, `boot/stage.sh` of the site's root-owned tree: logs
/// the AP and the image, takes its time for a slow one and fails a bad one.
const STAGE: &str = "echo \"$U6E_AP ${1##*/}\" >> @SITE@/staged; \
                     echo staging $U6E_AP; \
                     case $1 in *slow*) sleep 1.5 ;; *bad*) exit 1 ;; esac; echo staged";

fn runtime() -> Runtime {
    Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

/// A controller, a runner and a stage helper, all in this process; the
/// controller and the runner each on a runtime of its own, which a restart
/// drops and makes anew, their files kept.
struct Site {
    dir: TempDir,
    controller: u6e_controller::Controller,
    controller_rt: Option<Runtime>,
    runner_rt: Option<Runtime>,
    socket: PathBuf,
    gate: Duration,
}

impl Site {
    fn new(name: &str, gate: Duration) -> Site {
        let dir = TempDir::new(name);
        let rt = runtime();
        let controller = start_controller(&rt, &dir.0, "127.0.0.1:0").unwrap();
        let mut site = Site {
            socket: dir.0.join("runner.sock"),
            dir,
            controller,
            controller_rt: Some(rt),
            runner_rt: None,
            gate,
        };
        fs::create_dir_all(site.dir.0.join("images")).unwrap();
        for id in KEPT {
            let ap = if id.ends_with("-ap2") { "ap2" } else { "ap1" };
            keep(&site.dir.0.join("images"), id, ap);
        }
        tree(&site.dir.0);
        let config = site.runner_config(&site.socket, gate);
        // The stage helper as systemd runs it: one per connection.
        let helper = std::os::unix::net::UnixListener::bind(&config.rollout.helper).unwrap();
        // SAFETY: getegid has no preconditions.
        let gid = unsafe { libc::getegid() };
        let served = Arc::new(config.clone());
        thread::spawn(move || {
            for conn in helper.incoming() {
                let served = Arc::clone(&served);
                thread::spawn(move || stage::serve_peer(&served, conn.unwrap(), gid));
            }
        });
        let rt = runtime();
        start_runner(&rt, config, KEY_RUNNER);
        site.runner_rt = Some(rt);
        site
    }

    /// The runner's configuration, its socket `socket` and its state in a
    /// directory beside it.
    fn runner_config(&self, socket: &Path, gate: Duration) -> Config {
        let text = format!(
            "controller = \"{}\"\ncontroller_key = \"{}\"\ntls_key = \"unused\"\n\
             signing_key = \"unused\"\nsocket = \"{}\"\nstate = \"{}\"\ngate_secs = {}\n\
             [aps.ap1]\nhostname = \"u6e-ap1\"\n[aps.ap2]\nhostname = \"u6e-ap2\"\n\
             [rollout]\nimages = \"{}\"\ntree = \"{}\"\n\
             helper = \"{}\"\ngroup = \"root\"\n",
            self.controller.agents,
            mac::hex(&identity(KEY_CONTROLLER).public_key()),
            socket.display(),
            socket.with_extension("state").display(),
            gate.as_secs(),
            self.dir.0.join("images").display(),
            self.dir.0.join("tree").display(),
            self.dir.0.join("stage.sock").display(),
        );
        Config::parse(&text).unwrap()
    }

    /// Another runner, of the link key `tls`, its socket `socket`.
    fn start_runner(&self, socket: &Path, tls: &str) -> Runtime {
        let rt = runtime();
        start_runner(&rt, self.runner_config(socket, self.gate), tls);
        rt
    }

    /// Stops the runner and starts it again, its state directory kept.
    fn restart_runner(&mut self) {
        if let Some(rt) = self.runner_rt.take() {
            rt.shutdown_background();
        }
        wait_for("the runner gone", || !self.runner_up());
        let rt = runtime();
        start_runner(&rt, self.runner_config(&self.socket, self.gate), KEY_RUNNER);
        self.runner_rt = Some(rt);
    }

    /// Stops the runner, to be started again later.
    fn stop_runner(&mut self) {
        if let Some(rt) = self.runner_rt.take() {
            rt.shutdown_background();
        }
        wait_for("the runner gone", || !self.runner_up());
    }

    /// Starts the runner stopped by [`Site::stop_runner`].
    fn start_runner_again(&mut self) {
        let rt = runtime();
        start_runner(&rt, self.runner_config(&self.socket, self.gate), KEY_RUNNER);
        self.runner_rt = Some(rt);
    }

    /// Stops the controller and starts it again on the same address, its
    /// policy file kept.
    fn restart_controller(&mut self) {
        let agents = self.controller.agents.to_string();
        if let Some(rt) = self.controller_rt.take() {
            rt.shutdown_background();
        }
        let rt = runtime();
        let start = Instant::now();
        // The old listener's port is free once its runtime has dropped it.
        self.controller = loop {
            match start_controller(&rt, &self.dir.0, &agents) {
                Ok(c) => break c,
                Err(e) => {
                    assert!(start.elapsed() < WAIT, "{e}");
                    thread::sleep(Duration::from_millis(50));
                }
            }
        };
        self.controller_rt = Some(rt);
    }

    /// What the staging script was asked, in order: `<ap> <image>` lines.
    fn staged(&self) -> Vec<String> {
        let text = fs::read_to_string(self.dir.0.join("staged")).unwrap_or_default();
        text.lines().map(str::to_owned).collect()
    }

    fn block_on<T>(&self, f: impl Future<Output = T>) -> T {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    fn runner_up(&self) -> bool {
        self.controller.state.read().runner.is_up()
    }

    /// The runner's state directory.
    fn state(&self) -> PathBuf {
        self.socket.with_extension("state")
    }
}

/// A controller on `rt` listening for agents at `agents`, its policy in
/// `dir`, admitting the two APs, each by its key and host name, and the
/// runner.
fn start_controller(
    rt: &Runtime,
    dir: &Path,
    agents: &str,
) -> io::Result<u6e_controller::Controller> {
    let hex = |pem| mac::hex(&identity(pem).public_key());
    let text = format!(
        "listen_agents = \"{agents}\"\nlisten_http = \"127.0.0.1:0\"\n\
         listen_metrics = \"127.0.0.1:0\"\nkey = \"unused.pem\"\n\
         public_origin = \"https://wifi.example.org\"\npolicy_path = \"{}\"\n\
         [runner]\npublic_key = \"{}\"\n\
         [aps.ap1]\npublic_key = \"{}\"\nhostname = \"u6e-ap1\"\n\
         [aps.ap2]\npublic_key = \"{}\"\nhostname = \"u6e-ap2\"\n",
        dir.join("policy.json").display(),
        hex(KEY_RUNNER),
        hex(KEY_AP1),
        hex(KEY_AP2),
    );
    let config = u6e_controller::config::Config::parse(&text).unwrap();
    rt.block_on(u6e_controller::start(
        &config,
        &identity(KEY_CONTROLLER),
        Timing::default(),
        Arc::new(NoNames),
    ))
}

/// A kept image of `ap`, as `prep-rootfs.sh` keeps one.
fn keep(images: &Path, id: &str, ap: &str) {
    fs::create_dir_all(images.join(id)).unwrap();
    let manifest = format!(
        "ap:        {ap} (u6e-{ap}, 192.0.2.1/24)
kernel:    x
"
    );
    fs::write(images.join(id).join("MANIFEST"), manifest).unwrap();
}

/// The root-owned staging tree in `dir`, its `boot/stage.sh` [`STAGE`]:
/// written by no one but its owner, or the stage helper would not run it.
fn tree(dir: &Path) {
    let tree = dir.join("tree");
    fs::create_dir_all(tree.join("boot")).unwrap();
    fs::create_dir_all(tree.join("log")).unwrap();
    fs::write(tree.join("site.conf"), "").unwrap();
    let script = STAGE.replace("@SITE@", &dir.display().to_string());
    fs::write(tree.join("boot/stage.sh"), format!("#!/bin/sh\n{script}\n")).unwrap();
    for (p, mode) in [
        (dir.to_owned(), 0o755),
        (tree.clone(), 0o755),
        (tree.join("boot"), 0o755),
        (tree.join("site.conf"), 0o644),
        (tree.join("boot/stage.sh"), 0o755),
    ] {
        fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
    }
}

fn start_runner(rt: &Runtime, config: Config, tls: &str) {
    let key = u6e_deploy::signing_key(KEY_SIGNING, &identity(tls)).unwrap();
    let started = rt.block_on(u6e_deploy::start(config, identity(tls), key));
    started.unwrap();
}

/// The AP end of the link, as the controller tests' agent.
struct Link {
    conn: ClientConnection,
    sock: TcpStream,
    buf: Vec<u8>,
}

impl Link {
    fn dial(addr: SocketAddr, pem: &str) -> Link {
        Link::speaking(addr, pem, PROTOCOL)
    }

    /// Dials as an agent of `protocol`.
    fn speaking(addr: SocketAddr, pem: &str, protocol: u16) -> Link {
        let config = tls::client_config(&identity(pem), identity(KEY_CONTROLLER).public_key());
        let mut sock = TcpStream::connect(addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let name = ServerName::try_from("controller").unwrap();
        let mut conn = ClientConnection::new(config, name).unwrap();
        while conn.is_handshaking() {
            match conn.complete_io(&mut sock) {
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => panic!("{e}"),
            }
        }
        let mut l = Link {
            conn,
            sock,
            buf: Vec::new(),
        };
        l.send_bytes(&version::frame(protocol)).unwrap();
        let start = Instant::now();
        loop {
            assert!(start.elapsed() < WAIT, "no version frame");
            if let Some((body, n)) = frame_body(&l.buf).unwrap() {
                assert_eq!(version::decode(body), PROTOCOL);
                l.buf.drain(..n);
                return l;
            }
            l.fill().unwrap();
        }
    }

    fn send_bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.conn.writer().write_all(bytes)?;
        while self.conn.wants_write() {
            self.conn.write_tls(&mut self.sock)?;
        }
        Ok(())
    }

    fn send(&mut self, msg: &AgentMsg) -> io::Result<()> {
        let mut out = Vec::new();
        write_frame(&mut out, msg)?;
        self.send_bytes(&out)
    }

    /// Reads what came; Ok(false) when nothing did in the read timeout.
    fn fill(&mut self) -> io::Result<bool> {
        match self.conn.reader().read_to_end(&mut self.buf) {
            Ok(_) => return Err(ErrorKind::UnexpectedEof.into()),
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
        match self.conn.read_tls(&mut self.sock) {
            Ok(0) => Err(ErrorKind::UnexpectedEof.into()),
            Ok(_) => {
                self.conn.process_new_packets().map_err(io::Error::other)?;
                let _ = self.conn.reader().read_to_end(&mut self.buf);
                Ok(true)
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// The next message, or None when none came in the read timeout.
    fn recv(&mut self) -> io::Result<Option<CtlMsg>> {
        loop {
            if let Some((msg, n)) = decode_frame::<CtlMsg>(&self.buf)? {
                self.buf.drain(..n);
                return Ok(Some(msg));
            }
            if !self.fill()? {
                return Ok(None);
            }
        }
    }
}

/// What a fake AP saw of the configurations it was sent.
#[derive(Default)]
struct Seen {
    received: Vec<SignedConfig>,
    applied: Vec<SignedConfig>,
    refused: Vec<String>,
}

/// An AP on a thread of its own, running `image` built at `built_ms`, which
/// reports the configuration it runs and applies the ones it is sent as the
/// agent judges them; dropped, it is gone (a reboot is a drop and a new one).
struct FakeAp {
    seen: Arc<Mutex<Seen>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for FakeAp {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn snapshot(seq: u64, installed: [u8; 32]) -> Snapshot {
    let station = Station {
        mac: [0x02, 0, 0, 0, 0, 0x01],
        bss: 0,
        signal: -50,
        signal_avg: -50,
        rx_bytes: 1,
        tx_bytes: 1,
        rx_packets: 1,
        tx_packets: 1,
        tx_retries: 0,
        tx_failed: 0,
        tx_rate_kbps: 1000,
        rx_rate_kbps: 1000,
        tx_mcs: 0,
        rx_mcs: 0,
        tx_mode: RateMode::He,
        rx_mode: RateMode::He,
        tx_nss: 1,
        rx_nss: 1,
        tx_airtime_us: 1,
        rx_airtime_us: 1,
        inactive_ms: 0,
        connected_s: 1,
        vlan: 42,
    };
    Snapshot {
        seq,
        uptime_s: 60,
        load_milli: 0,
        mem_avail_kb: 100_000,
        nss_load_pct: 0,
        temps: Vec::new(),
        radios: vec![Radio {
            phy: "phy0".into(),
            band: Band::B5,
            channel: 36,
            width_mhz: 80,
            txpower_mbm: 2300,
            noise_dbm: -95,
            active_ms: 0,
            busy_ms: 0,
            rx_ms: 0,
            tx_ms: 0,
            up: true,
        }],
        bsss: vec![Bss {
            ifname: "wlan5".into(),
            bssid: [0x02, 0, 0, 0, 0x10, 0x01],
            ssid: "example".into(),
            phy: "phy0".into(),
            vlan: 42,
        }],
        stations: vec![station],
        config_sha256: Some(installed),
        clock_synced: true,
    }
}

fn fake_ap(
    site: &Site,
    pem: &str,
    hostname: &str,
    image: &str,
    built_ms: u64,
    installed: [u8; 32],
) -> FakeAp {
    let mut link = Link::dial(site.controller.agents, pem);
    link.send(&AgentMsg::Hello(Hello {
        ap: hostname.into(),
        manifest: format!("image:     {image}\nbuilt_ms:  {built_ms}\n"),
        kernel: String::new(),
        hostapd: String::new(),
        agent: String::new(),
    }))
    .unwrap();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let (s, st, hostname) = (Arc::clone(&seen), Arc::clone(&stop), hostname.to_owned());
    let runner = signing_public();
    let thread = thread::spawn(move || {
        let (mut installed, mut last, mut tick) = (installed, 0, 1);
        link.send(&AgentMsg::Key(snapshot(tick, installed)))
            .unwrap();
        while !st.load(Ordering::Relaxed) {
            let msg = match link.recv() {
                Ok(Some(m)) => m,
                Ok(None) => continue,
                Err(_) => return,
            };
            let answer = match msg {
                CtlMsg::Ping(n) => AgentMsg::Pong(n),
                CtlMsg::Command(c) => AgentMsg::Result(CommandResult {
                    id: c.id,
                    ok: true,
                    detail: "ok".into(),
                }),
                CtlMsg::ApplyConfig(c) => {
                    let judged = config::verify(&runner, &hostname, &c).and_then(|()| {
                        if c.radios.iter().any(|r| r.text.contains("# refused")) {
                            return Err("a radio's file is wrong".into());
                        }
                        let replay = config::replayed(c.seq, last, "the last applied", built_ms);
                        replay
                            .or_else(|| config::expired(&c, Some(now_ms())))
                            .map_or(Ok(()), Err)
                    });
                    let mut seen = s.lock().unwrap();
                    seen.received.push(c.clone());
                    let (ok, detail) = match judged {
                        Ok(()) => {
                            (last, installed) = (c.seq, c.sha256);
                            seen.applied.push(c.clone());
                            (true, "set in place".to_owned())
                        }
                        Err(why) => {
                            seen.refused.push(why.clone());
                            (false, format!("refused: {why}"))
                        }
                    };
                    let radios = c.radios.iter().map(|r| RadioApplied {
                        radio: r.radio,
                        mechanism: Mechanism::InPlace,
                    });
                    link.send(&AgentMsg::ConfigApplied(ConfigApplied {
                        sha256: c.sha256,
                        ok,
                        radios: if ok { radios.collect() } else { Vec::new() },
                        detail,
                    }))
                    .unwrap();
                    tick += 1;
                    AgentMsg::Key(snapshot(tick, installed))
                }
                _ => continue,
            };
            if link.send(&answer).is_err() {
                return;
            }
        }
    });
    FakeAp {
        seen,
        stop,
        thread: Some(thread),
    }
}

/// The hash an image's own configuration is known by.
fn image_config(n: u8) -> [u8; 32] {
    config_sha256(&[RadioConfig {
        radio: Band::B5,
        text: format!("interface=wlan5\n# image {n}\n"),
        txpower_dbm: 23,
    }])
}

fn radios() -> Vec<RadioConfig> {
    script::radios(SCRIPT).unwrap()
}

/// The rollouts the controller counts as ended with `outcome`. A caller
/// hears the end once the result is on its way to the controller, which
/// takes it in on its own time: tests wait for the count.
fn ended(site: &Site, outcome: &str) -> Option<u64> {
    let state = site.controller.state.read();
    state.rollout_counts.get(outcome).copied()
}

fn up(site: &Site, ap: &str) -> bool {
    let state = site.controller.state.read();
    state.ap(ap).unwrap().snapshot.is_some()
}

/// The runner signs each configuration with its own key, under a sequence
/// number the AP has not seen and its image was not built after; after a
/// reboot onto the same image it signs its latest one again under a newer
/// one, and after a reboot onto an image built since, the old signature is a
/// replay the image refuses and nothing is signed again.
#[test]
fn configurations_are_signed_for_one_ap_and_never_replayed() {
    let site = Site::new("signed", Duration::from_secs(420));
    wait_for("the runner", || site.runner_up());
    let built = now_ms() - 60_000;
    let ap1 = fake_ap(
        &site,
        KEY_AP1,
        "u6e-ap1",
        "img-1-ap1",
        built,
        image_config(1),
    );
    wait_for("ap1", || up(&site, "ap1"));

    let done = site
        .block_on(local::apply(&site.socket, "ap1", radios()))
        .unwrap();
    assert!(
        done.contains("2.4 GHz set in place, 5 GHz set in place, 6 GHz set in place"),
        "{done}"
    );
    let first = ap1.seen.lock().unwrap().applied[0].clone();
    assert_eq!(first.sha256, config_sha256(&radios()));
    assert!(first.seq > built);
    // Signed by the signing key, not the link's.
    assert_eq!(config::verify(&signing_public(), "u6e-ap1", &first), Ok(()));
    let link = identity(KEY_RUNNER).public_key();
    assert!(config::verify(&link, "u6e-ap1", &first).is_err());
    // For this AP alone.
    assert_eq!(
        config::verify(&signing_public(), "u6e-ap2", &first),
        Err("for another AP (u6e-ap1)".into())
    );
    // Sent again, it is a replay.
    assert!(config::replayed(first.seq, first.seq, "the last applied", built).is_some());

    // A reboot onto the same image: back on the image's configuration, the
    // latest one is signed again, newer.
    drop(ap1);
    let ap1 = fake_ap(
        &site,
        KEY_AP1,
        "u6e-ap1",
        "img-1-ap1",
        built,
        image_config(1),
    );
    wait_for("the configuration again", || {
        !ap1.seen.lock().unwrap().applied.is_empty()
    });
    let again = ap1.seen.lock().unwrap().applied[0].clone();
    assert_eq!(again.sha256, first.sha256);
    assert!(again.seq > first.seq, "{} after {}", again.seq, first.seq);

    // A reboot onto an image built after it: the image's configuration is
    // the newer and stands; what was signed before is a replay to it.
    drop(ap1);
    let rebuilt = now_ms() + 1;
    thread::sleep(Duration::from_millis(5));
    let ap1 = fake_ap(
        &site,
        KEY_AP1,
        "u6e-ap1",
        "img-2-ap1",
        rebuilt,
        image_config(2),
    );
    wait_for("ap1 back", || up(&site, "ap1"));
    thread::sleep(Duration::from_millis(300));
    assert!(ap1.seen.lock().unwrap().received.is_empty());
    assert!(!site.controller.state.read().ap("ap1").unwrap().drifts());
    assert_eq!(
        config::replayed(again.seq, 0, "the last applied", rebuilt),
        Some(format!(
            "replayed: sequence {} is not past {rebuilt}, this image's build time",
            again.seq
        ))
    );

    // An AP that is not connected is not sent one.
    let e = site
        .block_on(local::apply(&site.socket, "ap2", radios()))
        .unwrap_err();
    assert_eq!(e, "ap2: ap2 is not connected");
    drop(ap1);
}

/// A runner holding an AP's key is never the runner: the controller gives
/// that key an AP's session, which the runner's Hello ends.
#[test]
fn a_runner_with_an_aps_key_is_not_the_runner() {
    let site = Site::new("roles", Duration::from_secs(420));
    wait_for("the runner", || site.runner_up());
    let impostor = site.dir.0.join("impostor.sock");
    let version = |s: &Site| s.controller.state.read().runner.connected_since;
    let before = version(&site);
    let _rt = site.start_runner(&impostor, KEY_AP2);
    thread::sleep(Duration::from_millis(1500));
    // Still the first runner's session, and no AP took ap2's place.
    assert_eq!(version(&site), before);
    assert!(!up(&site, "ap2"));
    let e = site
        .block_on(local::apply(&impostor, "ap1", radios()))
        .unwrap_err();
    assert_eq!(e, "no link to the controller");
}

/// A rollout a local caller asks for goes through the controller, which
/// gates it: the image is staged once, the AP comes back with it, done.
#[test]
fn a_rollout_that_passes_its_gate_is_done() {
    let site = Site::new("done", Duration::from_secs(420));
    wait_for("the runner", || site.runner_up());
    let ap1 = fake_ap(&site, KEY_AP1, "u6e-ap1", "img-1-ap1", 1, image_config(1));
    wait_for("ap1", || up(&site, "ap1"));
    let socket = site.socket.clone();
    let lines = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&lines);
    let asked = thread::spawn(move || {
        let rt = Builder::new_current_thread().enable_all().build().unwrap();
        let line = |l: &str| log.lock().unwrap().push(l.to_owned());
        rt.block_on(local::rollout(&socket, "ap1", "img-2-ap1", line))
    });
    wait_for("the staging", || site.staged().len() == 1);
    // The reboot into the new image.
    drop(ap1);
    let _ap1 = fake_ap(&site, KEY_AP1, "u6e-ap1", "img-2-ap1", 2, image_config(2));
    let done = asked.join().unwrap().unwrap();
    assert_eq!(
        done,
        "done: back with img-2-ap1: 1 radios up, 1 clients on the site"
    );
    assert_eq!(site.staged(), ["ap1 img-2-ap1"]);
    let lines = lines.lock().unwrap();
    assert_eq!(lines[0], "staging img-2-ap1 on ap1, as root (local) asked");
    assert!(lines.contains(&"staged".to_owned()), "{lines:?}");
    wait_for("the result counted", || ended(&site, "done") == Some(1));
    let state = site.controller.state.read();
    let r = state.rollouts.back().unwrap();
    assert_eq!(
        (r.image_id.as_str(), r.previous.as_str()),
        ("img-2-ap1", "img-1-ap1")
    );
}

/// An AP that does not come back healthy in the gate's time, or whose
/// staging fails, is rolled back to the image it ran.
#[test]
fn a_rollout_that_fails_its_gate_is_rolled_back() {
    let site = Site::new("rollback", Duration::from_secs(1));
    wait_for("the runner", || site.runner_up());
    let _ap1 = fake_ap(&site, KEY_AP1, "u6e-ap1", "img-1-ap1", 1, image_config(1));
    wait_for("ap1", || up(&site, "ap1"));
    let e = site
        .block_on(local::rollout(&site.socket, "ap1", "img-2-ap1", |_| {}))
        .unwrap_err();
    assert_eq!(
        e,
        "rolled back: no healthy gate in 1s; img-1-ap1 is staged again"
    );
    assert_eq!(site.staged(), ["ap1 img-2-ap1", "ap1 img-1-ap1"]);

    let e = site
        .block_on(local::rollout(&site.socket, "ap1", "img-bad-ap1", |_| {}))
        .unwrap_err();
    assert_eq!(
        e,
        "rolled back: the staging exited with 1; img-1-ap1 is staged again"
    );
    assert_eq!(site.staged()[2..], ["ap1 img-bad-ap1", "ap1 img-1-ap1"]);

    // An image that is not kept is refused before anything is staged.
    let e = site
        .block_on(local::rollout(&site.socket, "ap1", "img-9-ap1", |_| {}))
        .unwrap_err();
    assert_eq!(e, "refused: no image img-9-ap1 is kept");
    assert_eq!(site.staged().len(), 4);
    wait_for("the results counted", || {
        (ended(&site, "rolled_back"), ended(&site, "refused")) == (Some(2), Some(1))
    });
}

/// An AP that comes back during a rollout on another configuration than the
/// runner's latest for it is not signed one while the rollout runs, and gets
/// the latest one again once the rollout is over: here, rolled back to the
/// image it ran, which was built before that configuration was signed.
#[test]
fn an_ap_back_during_a_rollout_gets_its_configuration_after_it() {
    let site = Site::new("after", Duration::from_secs(1));
    wait_for("the runner", || site.runner_up());
    let built = now_ms() - 60_000;
    let ap1 = fake_ap(
        &site,
        KEY_AP1,
        "u6e-ap1",
        "img-1-ap1",
        built,
        image_config(1),
    );
    wait_for("ap1", || up(&site, "ap1"));
    site.block_on(local::apply(&site.socket, "ap1", radios()))
        .unwrap();
    let acked = ap1.seen.lock().unwrap().applied[0].sha256;

    let socket = site.socket.clone();
    let rollout = thread::spawn(move || {
        let rt = Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(local::rollout(&socket, "ap1", "img-slow-ap1", |_| {}))
    });
    wait_for("the slow staging", || site.staged().len() == 1);
    // The AP reboots onto its image while the staging still runs.
    drop(ap1);
    let ap1 = fake_ap(
        &site,
        KEY_AP1,
        "u6e-ap1",
        "img-1-ap1",
        built,
        image_config(1),
    );
    let e = rollout.join().unwrap().unwrap_err();
    assert!(e.starts_with("rolled back: no healthy gate"), "{e}");
    wait_for("the acknowledged configuration again", || {
        let seen = ap1.seen.lock().unwrap();
        seen.applied.iter().any(|c| c.sha256 == acked)
    });
}

/// One rollout at a time: another, of another AP, is refused while one runs.
#[test]
fn rollouts_run_one_at_a_time() {
    let site = Site::new("one", Duration::from_secs(1));
    wait_for("the runner", || site.runner_up());
    let _ap1 = fake_ap(&site, KEY_AP1, "u6e-ap1", "img-1-ap1", 1, image_config(1));
    let _ap2 = fake_ap(&site, KEY_AP2, "u6e-ap2", "img-1-ap2", 1, image_config(1));
    wait_for("the APs", || up(&site, "ap1") && up(&site, "ap2"));
    let socket = site.socket.clone();
    let slow = thread::spawn(move || {
        let rt = Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(local::rollout(&socket, "ap1", "img-slow-ap1", |_| {}))
    });
    wait_for("the slow staging", || site.staged().len() == 1);
    let e = site
        .block_on(local::rollout(&site.socket, "ap2", "img-1-ap2", |_| {}))
        .unwrap_err();
    assert_eq!(e, "refused: the rollout of img-slow-ap1 to ap1 is not over");
    let e = site
        .block_on(local::apply(&site.socket, "ap1", radios()))
        .unwrap_err();
    assert_eq!(e, "ap1 is being rolled out to");
    let e = slow.join().unwrap().unwrap_err();
    assert!(e.starts_with("rolled back: no healthy gate"), "{e}");
    assert_eq!(site.staged(), ["ap1 img-slow-ap1", "ap1 img-1-ap1"]);
}

/// The runner signs again only the latest configuration it signed for an
/// AP, whatever was acknowledged: an AP that refused the latest is offered
/// it again, never the older one it last applied (which a controller saying
/// the latest failed could otherwise have signed again).
#[test]
fn the_latest_is_signed_again_never_an_older_one() {
    let site = Site::new("latest", Duration::from_secs(420));
    wait_for("the runner", || site.runner_up());
    let built = now_ms() - 60_000;
    let image = || image_config(1);
    let ap1 = fake_ap(&site, KEY_AP1, "u6e-ap1", "img-1-ap1", built, image());
    wait_for("ap1", || up(&site, "ap1"));
    site.block_on(local::apply(&site.socket, "ap1", radios()))
        .unwrap();
    let mut wrong = radios();
    wrong[1].text.push_str("# refused\n");
    let e = site
        .block_on(local::apply(&site.socket, "ap1", wrong.clone()))
        .unwrap_err();
    assert_eq!(e, "ap1: refused: a radio's file is wrong");
    let refused = ap1.seen.lock().unwrap().received[1].seq;

    // A reboot onto its image: the latest, the one it refused, comes again.
    drop(ap1);
    let ap1 = fake_ap(&site, KEY_AP1, "u6e-ap1", "img-1-ap1", built, image());
    wait_for("the latest again", || {
        !ap1.seen.lock().unwrap().received.is_empty()
    });
    thread::sleep(Duration::from_millis(300));
    let seen = ap1.seen.lock().unwrap();
    assert_eq!(seen.received.len(), 1);
    assert_eq!(seen.received[0].sha256, config_sha256(&wrong));
    assert!(seen.received[0].seq > refused);
    assert!(seen.applied.is_empty());
}

/// The latest configuration outlives the runner, in its state directory
/// (its own alone): after a restart, an AP back on its image's
/// configuration is signed the latest again.
#[test]
fn a_restarted_runner_still_signs_its_latest_again() {
    let mut site = Site::new("restart-latest", Duration::from_secs(420));
    wait_for("the runner", || site.runner_up());
    let built = now_ms() - 60_000;
    let ap1 = fake_ap(
        &site,
        KEY_AP1,
        "u6e-ap1",
        "img-1-ap1",
        built,
        image_config(1),
    );
    wait_for("ap1", || up(&site, "ap1"));
    site.block_on(local::apply(&site.socket, "ap1", radios()))
        .unwrap();
    let first = ap1.seen.lock().unwrap().applied[0].clone();
    let kept = site.state().join("latest-u6e-ap1");
    let mode = fs::metadata(&kept).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    site.restart_runner();
    wait_for("the runner again", || site.runner_up());
    drop(ap1);
    let ap1 = fake_ap(
        &site,
        KEY_AP1,
        "u6e-ap1",
        "img-1-ap1",
        built,
        image_config(1),
    );
    wait_for("the latest again", || {
        !ap1.seen.lock().unwrap().applied.is_empty()
    });
    let again = ap1.seen.lock().unwrap().applied[0].clone();
    assert_eq!(again.sha256, first.sha256);
    assert!(again.seq > first.seq);
}

/// A rollout a local caller asks for, staged, and its follower thread.
fn roll_out(site: &Site, ap: &str, image: &str) -> JoinHandle<Result<String, String>> {
    let (socket, ap, image) = (site.socket.clone(), ap.to_owned(), image.to_owned());
    thread::spawn(move || {
        let rt = Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(local::rollout(&socket, &ap, &image, |_| {}))
    })
}

/// A runner restarted while it awaits a rollout's gate goes on with it: the
/// AP came back healthy meanwhile, so the rollout is done, nothing staged
/// again, and the rollout no longer kept.
#[test]
fn a_runner_restarted_during_the_gate_goes_on_with_the_rollout() {
    let mut site = Site::new("restart-gate", Duration::from_secs(30));
    wait_for("the runner", || site.runner_up());
    let ap1 = fake_ap(&site, KEY_AP1, "u6e-ap1", "img-1-ap1", 1, image_config(1));
    wait_for("ap1", || up(&site, "ap1"));
    let asked = roll_out(&site, "ap1", "img-2-ap1");
    wait_for("the staging", || site.staged().len() == 1);
    wait_for("the rollout kept", || site.state().join("rollout").exists());

    site.stop_runner();
    // The AP comes back with the image while the runner is away: the gate
    // is given, and the runner cannot hear it.
    drop(ap1);
    let _ap1 = fake_ap(&site, KEY_AP1, "u6e-ap1", "img-2-ap1", 2, image_config(2));
    wait_for("the gate", || {
        let state = site.controller.state.read();
        state.rollouts.back().unwrap().gate.is_some()
    });
    site.start_runner_again();
    wait_for("the result counted", || ended(&site, "done") == Some(1));
    assert_eq!(site.staged(), ["ap1 img-2-ap1"]);
    wait_for("the rollout no longer kept", || {
        !site.state().join("rollout").exists()
    });
    // Its caller's link went with the first runner.
    assert!(asked.join().unwrap().is_err());
}

/// A controller restarted while a rollout's gate is awaited goes on with
/// the rollout, kept in its policy file: the AP back healthy at the new
/// controller is done, and the new controller counts it.
#[test]
fn a_controller_restarted_during_the_gate_goes_on_with_the_rollout() {
    let mut site = Site::new("restart-controller", Duration::from_secs(30));
    wait_for("the runner", || site.runner_up());
    let ap1 = fake_ap(&site, KEY_AP1, "u6e-ap1", "img-1-ap1", 1, image_config(1));
    wait_for("ap1", || up(&site, "ap1"));
    let asked = roll_out(&site, "ap1", "img-2-ap1");
    wait_for("the staging", || site.staged().len() == 1);
    drop(ap1);

    site.restart_controller();
    wait_for("the runner back", || site.runner_up());
    let _ap1 = fake_ap(&site, KEY_AP1, "u6e-ap1", "img-2-ap1", 2, image_config(2));
    let done = asked.join().unwrap().unwrap();
    assert_eq!(
        done,
        "done: back with img-2-ap1: 1 radios up, 1 clients on the site"
    );
    wait_for("the result counted", || ended(&site, "done") == Some(1));
    assert_eq!(site.staged(), ["ap1 img-2-ap1"]);
}

/// An AP that comes back with an agent the controller turns away fails its
/// gate at once: the runner rolls it back without waiting out the gate.
#[test]
fn an_unhealthy_gate_is_rolled_back_at_once() {
    let site = Site::new("unhealthy", Duration::from_secs(60));
    wait_for("the runner", || site.runner_up());
    let ap1 = fake_ap(&site, KEY_AP1, "u6e-ap1", "img-1-ap1", 1, image_config(1));
    wait_for("ap1", || up(&site, "ap1"));
    let started = Instant::now();
    let asked = roll_out(&site, "ap1", "img-2-ap1");
    wait_for("the staging", || site.staged().len() == 1);
    drop(ap1);
    let _other = Link::speaking(site.controller.agents, KEY_AP1, PROTOCOL + 1);
    let e = asked.join().unwrap().unwrap_err();
    let unhealthy = format!(
        "rolled back: unhealthy: its agent speaks protocol {}, this controller {PROTOCOL}",
        PROTOCOL + 1
    );
    assert!(e.starts_with(&unhealthy), "{e}");
    assert!(started.elapsed() < Duration::from_secs(30));
    assert_eq!(site.staged(), ["ap1 img-2-ap1", "ap1 img-1-ap1"]);
}

/// The controller may roll out only an AP's newest kept image, and a failed
/// gate rolls the AP back to the image the runner staged on it, not to one
/// the controller names.
#[test]
fn the_controller_rolls_out_only_the_newest_image() {
    let site = Site::new("newest", Duration::from_secs(1));
    wait_for("the runner", || site.runner_up());
    let ap1 = fake_ap(&site, KEY_AP1, "u6e-ap1", "img-1-ap1", 1, image_config(1));
    wait_for("ap1", || up(&site, "ap1"));
    let upgrade = |image: &str| {
        let mut state = site.controller.state.write();
        state.upgrade("ap1", image, "admin").unwrap();
    };

    // An admin's upgrade to an image that is not the newest: refused.
    upgrade("img-2-ap1");
    wait_for("the refusal", || ended(&site, "refused") == Some(1));
    let refused = {
        let state = site.controller.state.read();
        state.rollouts.back().unwrap().result.clone().unwrap().1
    };
    assert!(
        refused.starts_with("only ap1's newest kept image, img-slow-ap1, rolls out"),
        "{refused}"
    );
    assert!(site.staged().is_empty());

    // A local caller may: the runner then knows the AP runs img-2.
    let asked = roll_out(&site, "ap1", "img-2-ap1");
    wait_for("the staging", || site.staged().len() == 1);
    drop(ap1);
    let ap1 = fake_ap(&site, KEY_AP1, "u6e-ap1", "img-2-ap1", 2, image_config(2));
    asked.join().unwrap().unwrap();

    // The AP said to run another (as a controller might lie): the newest
    // image fails its gate and goes back to what the runner staged.
    drop(ap1);
    let _ap1 = fake_ap(&site, KEY_AP1, "u6e-ap1", "img-bad-ap1", 3, image_config(3));
    wait_for("ap1", || up(&site, "ap1"));
    upgrade("img-slow-ap1");
    wait_for("the rollback", || ended(&site, "rolled_back") == Some(1));
    assert_eq!(
        site.staged(),
        ["ap1 img-2-ap1", "ap1 img-slow-ap1", "ap1 img-2-ap1"]
    );
}

/// An image the site's own deploy staged (`deploy.sh`, which tells the
/// runner as root) is the way back from then on: a failed gate after it
/// stages that one again, not the one the runner staged before.
#[test]
fn a_staging_of_the_sites_deploy_is_the_way_back() {
    let site = Site::new("deployed", Duration::from_secs(1));
    wait_for("the runner", || site.runner_up());
    let ap1 = fake_ap(&site, KEY_AP1, "u6e-ap1", "img-1-ap1", 1, image_config(1));
    wait_for("ap1", || up(&site, "ap1"));
    let asked = roll_out(&site, "ap1", "img-2-ap1");
    wait_for("the staging", || site.staged().len() == 1);
    drop(ap1);
    let ap1 = fake_ap(&site, KEY_AP1, "u6e-ap1", "img-2-ap1", 2, image_config(2));
    asked.join().unwrap().unwrap();

    // deploy.sh boots img-slow on it, and says so.
    drop(ap1);
    let _ap1 = fake_ap(
        &site,
        KEY_AP1,
        "u6e-ap1",
        "img-slow-ap1",
        3,
        image_config(3),
    );
    let told = site.block_on(local::staged(&site.socket, "ap1", "img-slow-ap1"));
    assert_eq!(told, Ok("ap1 rolls back to img-slow-ap1".into()));
    let unknown = site.block_on(local::staged(&site.socket, "ap1", "img-9-ap1"));
    assert_eq!(unknown, Err("no image img-9-ap1 is kept".into()));

    let e = site
        .block_on(local::rollout(&site.socket, "ap1", "img-bad-ap1", |_| {}))
        .unwrap_err();
    assert_eq!(
        e,
        "rolled back: the staging exited with 1; img-slow-ap1 is staged again"
    );
    assert_eq!(
        site.staged(),
        ["ap1 img-2-ap1", "ap1 img-bad-ap1", "ap1 img-slow-ap1"]
    );
}

/// The kept images' lock is held from a rollout's staging to its end, its
/// gate included, so the site's own deploy (which takes the same lock) and
/// any other staging wait it out; the rollout is started on the controller's
/// side, and the lock is free once it is over.
#[test]
fn a_rollout_holds_the_lock_through_its_gate() {
    let site = Site::new("held", Duration::from_secs(30));
    wait_for("the runner", || site.runner_up());
    let ap1 = fake_ap(&site, KEY_AP1, "u6e-ap1", "img-1-ap1", 1, image_config(1));
    wait_for("ap1", || up(&site, "ap1"));
    let images = site.dir.0.join("images");
    let asked = roll_out(&site, "ap1", "img-2-ap1");
    wait_for("the gate awaited", || {
        let state = site.controller.state.read();
        let r = state.rollouts.back();
        r.is_some_and(|r| r.started && r.log.iter().any(|l| l.starts_with("staged; waiting")))
    });
    // What deploy.sh does first: refused.
    assert!(stage::lock(&images).unwrap().is_none());
    drop(ap1);
    let _ap1 = fake_ap(&site, KEY_AP1, "u6e-ap1", "img-2-ap1", 2, image_config(2));
    asked.join().unwrap().unwrap();
    wait_for("the lock free", || stage::lock(&images).unwrap().is_some());
}

/// A runner restarted while its staging runs waits for the staging (which
/// its helper runs to its end, holding the lock) and gives the AP the whole
/// gate from there: the AP back after the staging passes it, and nothing is
/// staged again.
#[test]
fn a_runner_restarted_during_the_staging_waits_for_it() {
    let mut site = Site::new("restart-staging", Duration::from_secs(1));
    wait_for("the runner", || site.runner_up());
    let ap1 = fake_ap(&site, KEY_AP1, "u6e-ap1", "img-1-ap1", 1, image_config(1));
    wait_for("ap1", || up(&site, "ap1"));
    let asked = roll_out(&site, "ap1", "img-slow-ap1");
    wait_for("the staging", || site.staged().len() == 1);
    let staging = Instant::now();
    wait_for("the rollout kept", || site.state().join("rollout").exists());
    site.restart_runner();
    let gate = |site: &Site| {
        let state = site.controller.state.read();
        let r = state.rollouts.back().unwrap();
        r.log.iter().any(|l| l.starts_with("staged; waiting up to"))
    };
    // The staging takes 1.5 s; its gate waits for it.
    wait_for("the gate awaited", || gate(&site));
    assert!(
        staging.elapsed() >= Duration::from_millis(1400),
        "the gate began {:?} into a 1.5 s staging",
        staging.elapsed()
    );
    drop(ap1);
    let _ap1 = fake_ap(
        &site,
        KEY_AP1,
        "u6e-ap1",
        "img-slow-ap1",
        2,
        image_config(2),
    );
    wait_for("the result counted", || ended(&site, "done") == Some(1));
    assert_eq!(site.staged(), ["ap1 img-slow-ap1"]);
    let state = site.controller.state.read();
    let log = &state.rollouts.back().unwrap().log;
    assert!(
        log.contains(&"restarted during the staging: waiting for it to end".to_owned()),
        "{log:?}"
    );
    drop(state);
    assert!(asked.join().unwrap().is_err());
}

/// A state file the runner cannot read (another format, or garbage) is set
/// aside and the runner starts without it; the controller is told, at every
/// session, until someone removes it.
#[test]
fn an_unreadable_state_file_is_set_aside_and_told() {
    let mut site = Site::new("corrupt", Duration::from_secs(1));
    wait_for("the runner", || site.runner_up());
    site.stop_runner();
    fs::write(site.state().join("images"), b"not a state file").unwrap();
    site.start_runner_again();
    wait_for("told", || {
        let state = site.controller.state.read();
        state.runner.is_up() && state.runner.discarded.len() == 1
    });
    let aside: Vec<String> = fs::read_dir(site.state())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with("images.corrupt-"))
        .collect();
    assert_eq!(aside.len(), 1);
    {
        let state = site.controller.state.read();
        let d = &state.runner.discarded[0];
        assert_eq!(
            (d.file.as_str(), d.detail.as_str()),
            (aside[0].as_str(), "not of format 1")
        );
    }
    // Removed: the next runner tells nothing.
    fs::remove_file(site.state().join(&aside[0])).unwrap();
    site.restart_runner();
    wait_for("nothing told", || {
        let state = site.controller.state.read();
        state.runner.is_up() && state.runner.discarded.is_empty()
    });
}
