//! The agent's root helper, for what the agent may not do or see: the
//! installed Wi-Fi configuration, which is root's alone (it holds the
//! passphrases and keys). It tells the agent how each radio would take a
//! proposed configuration (the agent never reads the installed one), installs
//! one and renders it for the running hostapd and sets the radios' new
//! transmit powers (nl80211 wants CAP_NET_ADMIN for that), or restarts
//! u6e-wifi with it, putting the previous one back when the radios do not
//! come up again; it puts back the previous one when the agent asks; and it
//! publishes the hash of what is installed for the agent to report.
//!
//! It takes only configurations the deploy runner signed for this AP, newer
//! than the last it installed (the sequence number survives the agent, until
//! the next boot) and than the image's build time (`Hello::built_ms`, which
//! survives the boot), whatever the agent checked: a compromised controller
//! or agent cannot install one of its own, nor replay an old one. systemd starts one helper per
//! connection on a socket only the agent's group may open (`u6e-agent
//! --config-helper`; see prep-rootfs.sh for the units); a connection carries
//! one request and its reply, the configuration's bytes wiped after.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use u6e_proto::config::{self, config_sha256};
use u6e_proto::frame::{read_frame, write_frame, write_secret_frame};
use u6e_proto::msg::{Band, RadioConfig, SignedConfig};

use crate::neighbors::{self, Hostapd};
use crate::wificonf::{self, Class};

/// The helper's socket.
pub const SOCKET: &str = "/run/u6e-wifi-helper/sock";
/// How long the agent waits for an answer: a restart, then one more to put
/// the previous configuration back, each up to u6e-wifi's start timeout.
const ANSWER_WAIT: Duration = Duration::from_secs(600);
/// The most power a radio may be set to: no regulatory domain allows more.
const DBM_MAX: i8 = 36;
/// Where the configuration an install replaced is kept, in the
/// configuration directory.
const PREVIOUS: &str = "previous";

/// What the agent asks.
#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    /// How each radio would take `config`.
    Classify(SignedConfig),
    /// Install `config` in place of `expect` (the configuration it was
    /// classified against), then render it for the running hostapd and set
    /// the new powers or, with `restart`, restart u6e-wifi with it.
    Install {
        config: SignedConfig,
        expect: Option<[u8; 32]>,
        restart: bool,
    },
    /// Put back the configuration the last install replaced.
    Revert,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    /// The installed configuration's hash, and how each radio of the
    /// proposed one, in order, takes it.
    Classified {
        installed: Option<[u8; 32]>,
        radios: Vec<(Band, Class)>,
    },
    Done(String),
    Failed(String),
}

/// The agent's end: one connection per request.
#[derive(Debug, Clone)]
pub struct Client {
    pub socket: PathBuf,
    pub wait: Duration,
}

impl Client {
    pub fn new() -> Self {
        Client {
            socket: SOCKET.into(),
            wait: ANSWER_WAIT,
        }
    }

    /// The helper's answer; its refusal or failure is the error.
    pub fn ask(&self, req: &Request) -> Result<Reply, String> {
        let talk = || {
            let mut s = UnixStream::connect(&self.socket)?;
            s.set_read_timeout(Some(self.wait))?;
            write_secret_frame(&mut s, req)?;
            read_frame::<_, Reply>(&mut s)
        };
        match talk() {
            Ok(Reply::Failed(why)) => Err(why),
            Ok(r) => Ok(r),
            Err(e) => Err(format!("the config helper: {e}")),
        }
    }
}

/// The root end and what it works on.
pub struct Server {
    /// The installed configurations ([`wificonf::DIR`]).
    pub dir: PathBuf,
    /// Where the hash of the installed one is published ([`wificonf::STATE`]).
    pub state: PathBuf,
    /// hostapd's control sockets.
    pub hostapd: PathBuf,
    /// Renders the installed configuration into hostapd's files.
    pub render: Vec<String>,
    /// Restarts u6e-wifi, returning once it started (or failed to).
    pub restart: Vec<String>,
    pub iw: String,
    /// How long the radios may take to come up after a restart.
    pub up_wait: Duration,
    /// The deploy runner's public key, as the image pins it; without one,
    /// no configuration is taken.
    pub runner: Option<[u8; 32]>,
    /// This AP's name, which a configuration must be signed for.
    pub ap: String,
    /// The image's build time: no sequence number at or below it applies.
    pub floor: u64,
}

impl Server {
    /// The AP's helper.
    pub fn new(runner: Option<[u8; 32]>, ap: String, floor: u64) -> Self {
        Server {
            dir: wificonf::DIR.into(),
            state: wificonf::STATE.into(),
            hostapd: neighbors::HOSTAPD.into(),
            render: vec!["/usr/local/sbin/u6e-wifi".into(), "render".into()],
            restart: ["systemctl", "restart", "u6e-wifi.service"]
                .map(String::from)
                .to_vec(),
            iw: "iw".into(),
            up_wait: Duration::from_secs(30),
            runner,
            ap,
            floor,
        }
    }

    /// Answers the one request of a connection.
    pub fn serve(&self, conn: &mut (impl Read + Write)) -> io::Result<()> {
        let req: Request = read_frame(conn)?;
        let reply = self.handle(req).unwrap_or_else(Reply::Failed);
        write_frame(conn, &reply)
    }

    fn handle(&self, req: Request) -> Result<Reply, String> {
        match req {
            Request::Classify(config) => {
                self.check(&config)?;
                let _lock = self.lock()?;
                let old = self.installed(&config)?;
                let radios = old
                    .iter()
                    .zip(&config.radios)
                    .map(|(o, n)| Ok((n.radio, wificonf::class(o, n)?)))
                    .collect::<Result<_, String>>()?;
                Ok(Reply::Classified {
                    installed: Some(config_sha256(&old)),
                    radios,
                })
            }
            Request::Install {
                config,
                expect,
                restart,
            } => {
                self.check(&config)?;
                let _lock = self.lock()?;
                self.install(&config, expect, restart).map(Reply::Done)
            }
            Request::Revert => {
                let _lock = self.lock()?;
                self.revert().map(Reply::Done)
            }
        }
    }

    /// Whether `c` may be installed at all: signed by the runner for this
    /// AP, newer than the last installed, every radio once, each file one
    /// that passes.
    fn check(&self, c: &SignedConfig) -> Result<(), String> {
        let runner = self
            .runner
            .ok_or("no deploy runner key in this image: live configuration is off")?;
        config::verify(&runner, &self.ap, c)?;
        let last = wificonf::read_seq(&self.dir);
        if let Some(why) = wificonf::replayed(c.seq, last, "the last installed", self.floor) {
            return Err(why);
        }
        for r in &c.radios {
            let name = wificonf::iface(r.radio);
            wificonf::parse(r.radio, &r.text).map_err(|e| format!("{name}: {e}"))?;
            if !(0..=DBM_MAX).contains(&r.txpower_dbm) {
                return Err(format!("{name}: {} dBm is out of range", r.txpower_dbm));
            }
        }
        Ok(())
    }

    /// The installed configuration, which must have the radios of `c`.
    fn installed(&self, c: &SignedConfig) -> Result<Vec<RadioConfig>, String> {
        let old =
            wificonf::read(&self.dir).map_err(|e| format!("the installed configuration: {e}"))?;
        let bands = |rs: &[RadioConfig]| rs.iter().map(|r| r.radio).collect::<Vec<_>>();
        if old.is_empty() || bands(&c.radios) != bands(&old) {
            return Err("the radios must be those installed, in order".into());
        }
        Ok(old)
    }

    fn install(
        &self,
        c: &SignedConfig,
        expect: Option<[u8; 32]>,
        restart: bool,
    ) -> Result<String, String> {
        let old = self.installed(c)?;
        if Some(config_sha256(&old)) != expect {
            return Err("the installed configuration changed since it was classified".into());
        }
        let previous = self.dir.join(PREVIOUS);
        DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&previous)
            .and_then(|()| wificonf::stage(&previous, &old)?.commit())
            .map_err(|e| format!("keeping the previous configuration: {e}"))?;
        self.put(&c.radios)?;
        wificonf::write_seq(&self.dir, c.seq).map_err(|e| format!("the sequence number: {e}"))?;
        let Err(why) = self.take(&old, &c.radios, restart) else {
            let how = if restart { "restarted" } else { "rendered" };
            return Ok(format!("installed and {how}"));
        };
        self.put(&old)?;
        Err(match self.take(&c.radios, &old, restart) {
            Ok(()) => format!("{why}; the previous configuration is back"),
            Err(e) => format!("{why}; the previous configuration is back but did not start: {e}"),
        })
    }

    fn revert(&self) -> Result<String, String> {
        let previous = wificonf::read(&self.dir.join(PREVIOUS))
            .ok()
            .filter(|p| !p.is_empty())
            .ok_or("no previous configuration")?;
        let current =
            wificonf::read(&self.dir).map_err(|e| format!("the installed configuration: {e}"))?;
        self.put(&previous)?;
        self.take(&current, &previous, false)?;
        Ok("the previous configuration is back".into())
    }

    /// Has the radios take `new`, installed over `old`: rendered and its new
    /// powers set, or u6e-wifi restarted with it.
    fn take(&self, old: &[RadioConfig], new: &[RadioConfig], restart: bool) -> Result<(), String> {
        if restart {
            return self.restart_up(new);
        }
        run(&self.render.iter().map(String::as_str).collect::<Vec<_>>())?;
        for (o, n) in old.iter().zip(new) {
            if o.txpower_dbm != n.txpower_dbm {
                let mbm = (i32::from(n.txpower_dbm) * 100).to_string();
                let iface = wificonf::iface(n.radio);
                run(&[&self.iw, "dev", iface, "set", "txpower", "fixed", &mbm])?;
            }
        }
        Ok(())
    }

    /// Installs `radios` and publishes the hash of what is installed.
    fn put(&self, radios: &[RadioConfig]) -> Result<(), String> {
        let r = wificonf::stage(&self.dir, radios).and_then(wificonf::Staged::commit);
        self.publish();
        r.map_err(|e| format!("installing: {e}"))
    }

    /// Publishes the hash of the installed configuration for the agent.
    pub fn publish(&self) {
        let hash = wificonf::installed_hash(&self.dir);
        if let Err(e) = wificonf::write_hash(&self.state, hash) {
            eprintln!("u6e-agent: config helper: publishing the hash: {e}");
        }
    }

    /// Restarts u6e-wifi and waits until every radio of `radios` serves.
    fn restart_up(&self, radios: &[RadioConfig]) -> Result<(), String> {
        run(&self.restart.iter().map(String::as_str).collect::<Vec<_>>())?;
        let mut h = Hostapd::bind(&self.dir, "helper", &self.hostapd)
            .map_err(|e| format!("hostapd's control sockets: {e}"))?;
        let end = Instant::now() + self.up_wait;
        let mut down: Vec<&str> = radios.iter().map(|r| wificonf::iface(r.radio)).collect();
        loop {
            down.retain(|i| !neighbors::enabled(&h.request(i, "STATUS")));
            if down.is_empty() {
                return Ok(());
            }
            if Instant::now() >= end {
                return Err(format!("{} did not come up", down.join(", ")));
            }
            thread::sleep(Duration::from_millis(500));
        }
    }

    /// Held while one helper works, so that two never interleave.
    fn lock(&self) -> Result<File, String> {
        let take = || {
            let f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(self.dir.join(".lock"))?;
            // SAFETY: flock on a descriptor this function owns.
            if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(f)
        };
        take().map_err(|e: io::Error| format!("{}: {e}", self.dir.display()))
    }
}

/// Runs a command to its end; its failure says what it printed.
fn run(argv: &[&str]) -> Result<(), String> {
    let (cmd, args) = argv.split_first().ok_or("no command")?;
    let out = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("{cmd}: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let said = String::from_utf8_lossy(&out.stderr);
    let said = said.lines().last().unwrap_or_default();
    Err(format!(
        "{} failed ({}): {said}",
        argv.join(" "),
        out.status
    ))
}

/// Whether the peer of the connection on `fd` is root or of group `gid`.
pub fn peer_allowed(fd: &impl AsRawFd, gid: u32) -> bool {
    let mut cred = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` and `len` are valid for SO_PEERCRED to fill.
    let r = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &mut len,
        )
    };
    r == 0 && (cred.uid == 0 || cred.gid == gid)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixDatagram, UnixListener};
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};

    use crate::testdir::TestDir;
    use crate::wificonf::tests::{WLAN5, edit, fixture};

    /// The test runner's key and its public half; and another key.
    pub fn runner() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[1; 32]).unwrap()
    }

    pub fn runner_public() -> [u8; 32] {
        runner().public_key().as_ref().try_into().unwrap()
    }

    pub fn stranger() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[2; 32]).unwrap()
    }

    /// `radios` signed by the test runner for "ap1" under `seq`.
    pub fn signed(seq: u64, radios: Vec<RadioConfig>) -> SignedConfig {
        config::sign(&runner(), "ap1", seq, radios)
    }

    /// The fixture with wlan5's text `text` and power `dbm`.
    pub fn with5(text: &str, dbm: i8) -> Vec<RadioConfig> {
        let mut r = fixture();
        r[1].text = text.into();
        r[1].txpower_dbm = dbm;
        r
    }

    /// Fake hostapds over the three radios that serve unless a radio's
    /// installed configuration holds `dtim_period=7`.
    fn hostapds(ctrl: &Path, dir: &Path) {
        fs::create_dir_all(ctrl).unwrap();
        for band in wificonf::BANDS {
            let server = UnixDatagram::bind(ctrl.join(wificonf::iface(band))).unwrap();
            let conf = wificonf::path(dir, band);
            thread::spawn(move || {
                let mut buf = [0; 256];
                while let Ok((_, from)) = server.recv_from(&mut buf) {
                    let text = fs::read_to_string(&conf).unwrap_or_default();
                    let state = if text.contains("dtim_period=7") {
                        "DISABLED"
                    } else {
                        "ENABLED"
                    };
                    if let Some(p) = from.as_pathname() {
                        let _ = server.send_to(format!("state={state}\n").as_bytes(), p);
                    }
                }
            });
        }
    }

    /// A shell command that appends `what` and its arguments to `log`.
    pub fn logs(log: &Path, what: &str) -> Vec<String> {
        vec![
            "/bin/sh".into(),
            "-c".into(),
            format!("echo {what} \"$@\" >> {}", log.display()),
            "sh".into(),
        ]
    }

    /// An `iw` in `dir` that appends its arguments to `log`.
    pub fn iw(dir: &Path, log: &Path) -> String {
        let iw = dir.join("iw");
        fs::write(
            &iw,
            format!("#!/bin/sh\necho iw \"$@\" >> {}\n", log.display()),
        )
        .unwrap();
        fs::set_permissions(&iw, fs::Permissions::from_mode(0o755)).unwrap();
        iw.display().to_string()
    }

    /// A helper over a scratch tree holding the fixture, its commands
    /// logging what they ran.
    fn server(t: &TestDir) -> (Server, PathBuf) {
        let (dir, state, ctrl) = (
            t.path().join("wifi"),
            t.path().join("state"),
            t.path().join("hostapd"),
        );
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(&state).unwrap();
        wificonf::stage(&dir, &fixture()).unwrap().commit().unwrap();
        hostapds(&ctrl, &dir);
        let log = t.path().join("log");
        let s = Server {
            dir,
            state,
            hostapd: ctrl,
            render: logs(&log, "render"),
            restart: logs(&log, "restart"),
            iw: iw(t.path(), &log),
            up_wait: Duration::from_secs(2),
            runner: Some(runner_public()),
            ap: "ap1".into(),
            floor: 0,
        };
        (s, log)
    }

    /// The files of a directory, by name.
    fn names(dir: &Path) -> Vec<String> {
        let mut n: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        n.sort();
        n
    }

    struct Rig {
        t: TestDir,
        server: Server,
        log: PathBuf,
    }

    impl Rig {
        fn new() -> Self {
            let t = TestDir::new();
            let (server, log) = server(&t);
            Rig { t, server, log }
        }

        fn ask(&self, req: Request) -> Result<Reply, String> {
            let (mut a, mut b) = UnixStream::pair().unwrap();
            write_secret_frame(&mut a, &req).unwrap();
            self.server.serve(&mut b).unwrap();
            match read_frame(&mut a).unwrap() {
                Reply::Failed(why) => Err(why),
                r => Ok(r),
            }
        }

        fn install(&self, c: SignedConfig, restart: bool) -> Result<Reply, String> {
            let expect = Some(config_sha256(&self.installed()));
            self.ask(Request::Install {
                config: c,
                expect,
                restart,
            })
        }

        fn log(&self) -> String {
            fs::read_to_string(&self.log).unwrap_or_default()
        }

        fn installed(&self) -> Vec<RadioConfig> {
            wificonf::read(&self.server.dir).unwrap()
        }
    }

    fn done(s: &str) -> Result<Reply, String> {
        Ok(Reply::Done(s.into()))
    }

    #[test]
    fn a_proposed_configuration_is_classified_against_the_installed_one() {
        let r = Rig::new();
        let dtim = edit(WLAN5, "dtim_period=3", "dtim_period=1");
        let Ok(Reply::Classified { installed, radios }) =
            r.ask(Request::Classify(signed(1, with5(&dtim, 23))))
        else {
            panic!("no classification");
        };
        assert_eq!(installed, Some(config_sha256(&fixture())));
        let classes: Vec<_> = radios
            .iter()
            .map(|(b, c)| (*b, matches!(c, Class::InPlace(_))))
            .collect();
        assert_eq!(
            classes,
            [(Band::B24, false), (Band::B5, true), (Band::B6, false)]
        );
        assert_eq!(radios[0].1, Class::Unchanged);
        let Ok(Reply::Classified { radios, .. }) =
            r.ask(Request::Classify(signed(1, with5(WLAN5, 20))))
        else {
            panic!("no classification");
        };
        assert_eq!(radios[1].1, Class::Power);
        // Classifying installs nothing.
        assert_eq!((r.installed(), r.log()), (fixture(), String::new()));
    }

    /// The configuration files stay root's alone; the hash the agent reads is
    /// published for its group; the sequence number is kept.
    #[test]
    fn an_install_is_rendered_and_its_hash_published() {
        let r = Rig::new();
        let new = with5(&edit(WLAN5, "dtim_period=3", "dtim_period=1"), 23);
        assert_eq!(
            r.install(signed(5, new.clone()), false),
            done("installed and rendered")
        );
        assert_eq!(r.installed(), new);
        assert_eq!(r.log(), "render\n");
        assert_eq!(wificonf::read_seq(&r.server.dir), 5);
        assert_eq!(
            wificonf::read_hash(&r.server.state),
            Some(config_sha256(&new))
        );
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        for n in names(&r.server.dir) {
            let p = r.server.dir.join(&n);
            if p.is_file() {
                assert_eq!(mode(&p), 0o600, "{n}");
            }
        }
        assert_eq!(mode(&r.server.dir.join(PREVIOUS)), 0o700);
        for n in names(&r.server.dir.join(PREVIOUS)) {
            assert_eq!(mode(&r.server.dir.join(PREVIOUS).join(&n)), 0o600, "{n}");
        }
        assert_eq!(mode(&r.server.state.join(wificonf::HASH)), 0o640);
    }

    /// Only the radios whose power changed are set, through iw.
    #[test]
    fn a_power_change_is_set_with_iw() {
        let r = Rig::new();
        let new = with5(WLAN5, 20);
        assert_eq!(
            r.install(signed(1, new.clone()), false),
            done("installed and rendered")
        );
        assert_eq!(r.log(), "render\niw dev wlan5 set txpower fixed 2000\n");
        assert_eq!(r.installed(), new);
    }

    #[test]
    fn an_install_with_a_restart_waits_for_the_radios() {
        let r = Rig::new();
        let new = with5(&edit(WLAN5, "ssid=", "ssid=other"), 23);
        assert_eq!(
            r.install(signed(1, new.clone()), true),
            done("installed and restarted")
        );
        assert_eq!(r.installed(), new);
        assert_eq!(r.log(), "restart\n");
    }

    /// A configuration the radios do not come up with is replaced by the
    /// previous one, and u6e-wifi restarted again; the sequence number
    /// stays spent.
    #[test]
    fn a_restart_that_leaves_a_radio_down_puts_the_previous_configuration_back() {
        let r = Rig::new();
        let bad = with5(&edit(WLAN5, "dtim_period=3", "dtim_period=7"), 23);
        assert_eq!(
            r.install(signed(1, bad), true),
            Err("wlan5 did not come up; the previous configuration is back".into())
        );
        assert_eq!(r.installed(), fixture());
        assert_eq!(r.log(), "restart\nrestart\n");
        assert_eq!(wificonf::read_seq(&r.server.dir), 1);
        assert_eq!(
            wificonf::read_hash(&r.server.state),
            Some(config_sha256(&fixture()))
        );
    }

    #[test]
    fn a_failed_render_puts_the_previous_configuration_and_power_back() {
        let mut r = Rig::new();
        let marker = r.t.path().join("rendered-once");
        r.server.render = vec![
            "/bin/sh".into(),
            "-c".into(),
            format!(
                "[ -e {m} ] || {{ touch {m}; echo no address >&2; exit 1; }}",
                m = marker.display()
            ),
        ];
        let err = r.install(signed(1, with5(WLAN5, 20)), false).unwrap_err();
        assert!(
            err.ends_with(
                "failed (exit status: 1): no address; the previous configuration is back"
            ),
            "{err}"
        );
        assert_eq!(r.installed(), fixture());
        // The render failed before the power was set; going back sets it
        // to what it was.
        assert_eq!(r.log(), "iw dev wlan5 set txpower fixed 2300\n");
    }

    #[test]
    fn a_revert_puts_back_what_the_last_install_replaced() {
        let r = Rig::new();
        assert_eq!(
            r.ask(Request::Revert),
            Err("no previous configuration".into())
        );
        let new = with5(&edit(WLAN5, "dtim_period=3", "dtim_period=1"), 20);
        r.install(signed(1, new), false).unwrap();
        assert_eq!(
            r.ask(Request::Revert),
            done("the previous configuration is back")
        );
        assert_eq!(r.installed(), fixture());
        assert_eq!(
            wificonf::read_hash(&r.server.state),
            Some(config_sha256(&fixture()))
        );
        assert_eq!(
            r.log(),
            "render\niw dev wlan5 set txpower fixed 2000\nrender\niw dev wlan5 set txpower fixed 2300\n"
        );
    }

    /// What the runner did not sign for this AP, a replay, or anything the
    /// helper would not install, leaves everything as it was, whatever the
    /// agent checked.
    #[test]
    fn what_the_helper_would_not_install_leaves_everything_as_it_was() {
        let r = Rig::new();
        r.install(signed(10, fixture()), false).unwrap();
        let before = (r.installed(), r.log());
        let new = || with5(&edit(WLAN5, "dtim_period=3", "dtim_period=1"), 23);
        let forged = config::sign(&stranger(), "ap1", 11, new());
        let other_ap = config::sign(&runner(), "ap2", 11, new());
        let mut unsigned = signed(11, new());
        unsigned.signature.clear();
        let mut altered = signed(11, fixture());
        altered.radios[1].text = new()[1].text.clone();
        let bad_file = signed(
            11,
            with5(&edit(WLAN5, "ctrl_interface=", "ctrl_interface=/etc"), 23),
        );
        for (c, why) in [
            (forged, "not signed by the deploy runner"),
            (unsigned, "not signed by the deploy runner"),
            (other_ap, "for another AP (ap2)"),
            (altered, "the configuration does not match its SHA-256"),
            (
                signed(10, new()),
                "replayed: sequence 10 is not past 10, the last installed",
            ),
            (
                signed(3, new()),
                "replayed: sequence 3 is not past 10, the last installed",
            ),
            (bad_file, "wlan5: line 26: ctrl_interface is not allowed so"),
            (
                signed(11, fixture()[..2].to_vec()),
                "the radios must be those installed, in order",
            ),
            (
                signed(11, with5(WLAN5, 40)),
                "wlan5: 40 dBm is out of range",
            ),
        ] {
            assert_eq!(r.ask(Request::Classify(c.clone())), Err(why.into()));
            assert_eq!(r.install(c, false), Err(why.into()));
        }
        let mut stale = Request::Install {
            config: signed(11, new()),
            expect: Some([0; 32]),
            restart: false,
        };
        assert_eq!(
            r.ask(stale),
            Err("the installed configuration changed since it was classified".into())
        );
        stale = Request::Classify(signed(11, new()));
        let mut keyless = Rig::new();
        keyless.server.runner = None;
        assert_eq!(
            keyless.ask(stale),
            Err("no deploy runner key in this image: live configuration is off".into())
        );
        assert_eq!((r.installed(), r.log()), before);
        assert_eq!(wificonf::read_seq(&r.server.dir), 10);
    }

    /// A reboot forgets the last sequence number (it lives in /run), but not
    /// the image's build time: a configuration signed before the image was
    /// built is refused on it, before the first install and after a reboot.
    #[test]
    fn a_configuration_older_than_the_image_is_refused_across_a_reboot() {
        let mut r = Rig::new();
        r.server.floor = 1_000;
        let new = || with5(&edit(WLAN5, "dtim_period=3", "dtim_period=1"), 23);
        let why = "replayed: sequence 1000 is not past 1000, this image's build time";
        assert_eq!(r.install(signed(1_000, new()), false), Err(why.into()));
        assert!(r.install(signed(1_001, new()), false).is_ok());
        assert_eq!(wificonf::read_seq(&r.server.dir), 1_001);
        // The reboot: /run is gone, the image is the same.
        fs::remove_file(r.server.dir.join("seq")).unwrap();
        assert_eq!(wificonf::read_seq(&r.server.dir), 0);
        let why = "replayed: sequence 999 is not past 1000, this image's build time";
        assert_eq!(r.install(signed(999, fixture()), false), Err(why.into()));
        assert_eq!(r.installed(), new());
    }

    /// The agent's end, against a helper on a socket.
    #[test]
    fn the_client_carries_a_request_and_its_answer() {
        let r = Arc::new(Mutex::new(Rig::new()));
        let sock = r.lock().unwrap().t.path().join("sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let served = Arc::clone(&r);
        thread::spawn(move || {
            for conn in listener.incoming().flatten().take(1) {
                let mut conn = conn;
                // SAFETY: getegid has no preconditions.
                assert!(peer_allowed(&conn, unsafe { libc::getegid() }));
                served.lock().unwrap().server.serve(&mut conn).unwrap();
            }
        });
        let client = Client {
            socket: sock,
            wait: Duration::from_secs(5),
        };
        assert_eq!(
            client.ask(&Request::Revert),
            Err("no previous configuration".into())
        );
        let gone = Client {
            socket: r.lock().unwrap().t.path().join("none"),
            wait: Duration::from_secs(1),
        };
        assert!(
            gone.ask(&Request::Revert)
                .unwrap_err()
                .starts_with("the config helper: ")
        );
    }
}
