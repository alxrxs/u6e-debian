//! The guards' one thread: it waits with `poll` for a frame, a request of
//! the agent's or a signal to stop, and every few seconds looks at the ports
//! again and forgets what expired. The agent is served one request per
//! connection (`u6e_proto::guard`), a member of its group only, each with a
//! second to say what it wants. Enforcement follows every change that bears
//! on it (bindings, the VLANs enforced on, the ports, the rogue advertisers)
//! at once, its drop counts are read every [`DROPS_EVERY`] while it lasts,
//! and on the way out nothing is left dropping.

use std::collections::HashMap;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use u6e_proto::frame::{read_frame, write_frame};
use u6e_proto::guard::{Reply, Request};
use u6e_proto::local;
use u6e_proto::msg::{Binding, Guard, GuardConfig};

use crate::bindings::Clock;
use crate::capture::Capture;
use crate::enforce::{self, Enforcer};
use crate::frame;
use crate::ports::{self, Port};
use crate::rules::Guards;

/// Frames read at once before the socket is looked at again.
const BURST: usize = 256;
/// The longest a client may take to send its request or read the answer.
const CLIENT_WAIT: Duration = Duration::from_secs(1);
/// Bindings a seed or a mode may carry at most.
const MAX_BINDINGS: usize = 16_384;
/// How often the drop counts are read while enforcing: each read runs tc.
const DROPS_EVERY: Duration = Duration::from_secs(30);

pub struct Config {
    /// The agent's group: only its members are served.
    pub gid: u32,
    /// Where the interfaces are listed (`/sys/class/net`).
    pub net: PathBuf,
    pub tc: PathBuf,
    /// How often the ports are looked at again.
    pub rescan: Duration,
}

/// What bears on enforcement, to tell when it must change.
#[derive(PartialEq, Eq)]
struct Shape {
    generation: u64,
    enforce: Vec<u16>,
    ports: Vec<Port>,
    ra: Vec<[u8; 6]>,
}

struct Server<'a> {
    cfg: &'a Config,
    capture: Capture,
    guards: Guards,
    ports: Vec<Port>,
    by_index: HashMap<i32, Port>,
    enforcer: Enforcer,
    enforced: Option<Shape>,
    started_ms: u64,
    /// Each guard's drops, as last read.
    dropped: Vec<(Guard, u64)>,
    /// The last failure of each kind, logged once until it changes.
    failed: HashMap<&'static str, String>,
}

/// Serves `listener` until `stop` is readable.
pub fn run(cfg: &Config, listener: UnixListener, capture: Capture, stop: RawFd) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    let mut s = Server {
        cfg,
        capture,
        guards: Guards::default(),
        ports: Vec::new(),
        by_index: HashMap::new(),
        enforcer: Enforcer::new(cfg.tc.clone()),
        enforced: None,
        started_ms: Clock::now().wall_ms,
        dropped: Vec::new(),
        failed: HashMap::new(),
    };
    let mut next_scan = Instant::now();
    let mut next_drops = Instant::now();
    let mut buf = vec![0u8; 2048];
    loop {
        if Instant::now() >= next_scan {
            s.maintain();
            next_scan = Instant::now() + cfg.rescan;
        }
        if Instant::now() >= next_drops {
            s.read_drops();
            next_drops = Instant::now() + DROPS_EVERY;
        }
        let wait = next_scan.saturating_duration_since(Instant::now());
        let [frames, asked, stopped] = ready([s.capture.fd(), listener.as_raw_fd(), stop], wait);
        if stopped {
            // The unit's last step clears too, however it ended.
            return enforce::clear(&cfg.tc);
        }
        if frames {
            s.read_frames(&mut buf);
        }
        if asked {
            while let Ok((sock, _)) = listener.accept() {
                s.serve(sock);
            }
        }
        s.enforce();
    }
}

/// Which of `fds` are readable within `wait`.
fn ready(fds: [RawFd; 3], wait: Duration) -> [bool; 3] {
    let mut p = fds.map(|fd| libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    });
    let ms = i32::try_from(wait.as_millis()).unwrap_or(i32::MAX);
    // SAFETY: `p` is a valid array of pollfds of that length.
    let n = unsafe { libc::poll(p.as_mut_ptr(), p.len() as libc::nfds_t, ms) };
    p.map(|p| n > 0 && p.revents != 0)
}

impl Server<'_> {
    fn log_once(&mut self, what: &'static str, e: Option<String>) {
        match e {
            Some(e) if self.failed.get(what) != Some(&e) => {
                eprintln!("u6e-guard: {what}: {e}");
                self.failed.insert(what, e);
            }
            Some(_) => {}
            None => {
                self.failed.remove(what);
            }
        }
    }

    /// Looks at the ports again, the capture following them, and forgets
    /// what expired.
    fn maintain(&mut self) {
        match ports::scan(&self.cfg.net) {
            Ok(ports) if ports != self.ports => {
                let watched = self.capture.watch(&ports).err().map(|e| e.to_string());
                self.log_once("capture", watched);
                self.by_index = ports.iter().map(|p| (p.ifindex, p.clone())).collect();
                self.ports = ports;
            }
            Ok(_) => {}
            Err(e) => self.log_once("ports", Some(e.to_string())),
        }
        self.guards.expire(Clock::now());
    }

    fn read_drops(&mut self) {
        match self.enforcer.dropped() {
            Ok(d) if !d.is_empty() => self.dropped = d,
            Ok(_) => {}
            Err(e) => self.log_once("drop counts", Some(e.to_string())),
        }
    }

    fn read_frames(&mut self, buf: &mut [u8]) {
        for _ in 0..BURST {
            match self.capture.recv(buf) {
                Ok(Some(r)) => {
                    let Some(port) = self.by_index.get(&r.ifindex) else {
                        continue;
                    };
                    let f = match (r.tag, mac_at(buf)) {
                        (Some(vid), Some(src)) => Some(frame::Frame {
                            src,
                            what: frame::What::Tagged { vid },
                        }),
                        _ => frame::parse(&buf[..r.len]),
                    };
                    if let Some(f) = f {
                        self.guards.take(port, &f, Clock::now());
                    }
                }
                Ok(None) => return,
                Err(e) => {
                    self.log_once("capture", Some(e.to_string()));
                    return;
                }
            }
        }
    }

    /// Answers one connection's request, if it comes from the agent's group.
    fn serve(&mut self, mut sock: UnixStream) {
        if !local::member(&sock, self.cfg.gid) {
            return;
        }
        let setup = sock
            .set_nonblocking(false)
            .and_then(|()| sock.set_read_timeout(Some(CLIENT_WAIT)))
            .and_then(|()| sock.set_write_timeout(Some(CLIENT_WAIT)));
        if setup.is_err() {
            return;
        }
        let Ok(req) = read_frame::<_, Request>(&mut sock) else {
            return;
        };
        let reply = self.answer(req);
        let _ = write_frame(&mut sock, &reply);
    }

    fn answer(&mut self, req: Request) -> Reply {
        let now = Clock::now();
        match req {
            Request::Bindings => Reply::Bindings {
                started_ms: self.started_ms,
                generation: self.guards.bindings.generation,
                bindings: self.guards.bindings.list(now),
                dropped: self.dropped.clone(),
            },
            Request::Violations { after } => Reply::Violations {
                events: self.guards.after(after),
            },
            Request::Seed(leases) => match check(&leases) {
                Err(why) => Reply::Refused(why),
                Ok(()) => {
                    self.guards.bindings.seed(&leases, now);
                    Reply::Done
                }
            },
            Request::Mode(c) => match mode(&c) {
                Err(why) => Reply::Refused(why),
                Ok(()) => {
                    if c.enforce != self.guards.enforce {
                        match c.enforce.as_slice() {
                            [] => eprintln!("u6e-guard: reporting only"),
                            v => eprintln!("u6e-guard: enforcing on VLANs {v:?}"),
                        }
                    }
                    self.guards.enforce = c.enforce;
                    self.guards.dhcp_servers = c.dhcp_servers;
                    self.guards.dhcp_relays = c.dhcp_relays;
                    self.guards.bindings.statics(&c.statics, now);
                    Reply::Done
                }
            },
        }
    }

    /// Brings enforcement in line with what bears on it, if that changed.
    fn enforce(&mut self) {
        let shape = Shape {
            generation: self.guards.bindings.generation,
            enforce: self.guards.enforce.clone(),
            ports: self.ports.clone(),
            ra: self.guards.ra_offenders.keys().copied().collect(),
        };
        if self.enforced.as_ref() == Some(&shape) {
            return;
        }
        let bindings = self.guards.bindings.list(Clock::now());
        let synced = self
            .enforcer
            .sync(&shape.ports, &shape.enforce, &bindings, &shape.ra);
        let failed = synced.as_ref().err().map(|e| e.to_string());
        self.log_once("enforcement", failed);
        // A failure is tried again with the next change.
        self.enforced = synced.is_ok().then_some(shape);
    }
}

/// The source MAC of the frame in `buf`.
fn mac_at(buf: &[u8]) -> Option<[u8; 6]> {
    buf.get(6..12)?.try_into().ok()
}

fn check(bindings: &[Binding]) -> Result<(), String> {
    if bindings.len() > MAX_BINDINGS {
        return Err(format!("{} bindings, past {MAX_BINDINGS}", bindings.len()));
    }
    Ok(())
}

fn mode(c: &GuardConfig) -> Result<(), String> {
    if let Some(v) = c.enforce.iter().find(|v| !(1..=4094).contains(*v)) {
        return Err(format!("VLAN {v} is no VLAN"));
    }
    check(&c.statics)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixDatagram;
    use std::thread;
    use u6e_proto::msg::{EventKind, Guard};

    /// A stand-in for tc that shows nothing and does nothing.
    fn quiet_tc(dir: &TestDir) -> PathBuf {
        let tc = dir.path().join("tc");
        std::fs::write(&tc, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&tc, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        tc
    }

    /// A guard serving `dir/sock` with no ports, until `stop` is written to.
    fn start(dir: &TestDir, gid: u32) -> (UnixDatagram, thread::JoinHandle<io::Result<()>>) {
        let sock = dir.path().join("sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let net = dir.path().join("net");
        std::fs::create_dir_all(&net).unwrap();
        let (stop_tx, stop_rx) = UnixDatagram::pair().unwrap();
        let cfg = Config {
            gid,
            net,
            tc: quiet_tc(dir),
            rescan: Duration::from_millis(50),
        };
        let run = thread::spawn(move || {
            let capture = Capture::closed();
            run(&cfg, listener, capture, stop_rx.as_raw_fd())
        });
        (stop_tx, run)
    }

    fn ask(dir: &TestDir, req: &Request) -> io::Result<Reply> {
        let mut s = UnixStream::connect(dir.path().join("sock"))?;
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        write_frame(&mut s, req)?;
        read_frame(&mut s)
    }

    fn own_gid() -> u32 {
        // SAFETY: getgid cannot fail.
        unsafe { libc::getgid() }
    }

    #[test]
    fn the_agent_seeds_sets_the_mode_and_reads_back() {
        let dir = TestDir::new();
        let (stop, run) = start(&dir, own_gid());
        let leased = Binding {
            mac: [2, 0, 0, 0, 0, 1],
            ip: [192, 0, 2, 10].into(),
            expires_ms: Some(Clock::now().wall_ms + 600_000),
        };
        let fixed = Binding {
            mac: [2, 0, 0, 0, 0, 2],
            ip: [192, 0, 2, 20].into(),
            expires_ms: None,
        };
        assert_eq!(
            ask(&dir, &Request::Seed(vec![leased])).unwrap(),
            Reply::Done
        );
        let mode = GuardConfig {
            statics: vec![fixed],
            ..GuardConfig::default()
        };
        assert_eq!(ask(&dir, &Request::Mode(mode)).unwrap(), Reply::Done);
        let Reply::Bindings {
            generation,
            bindings,
            started_ms,
            ..
        } = ask(&dir, &Request::Bindings).unwrap()
        else {
            panic!()
        };
        assert_eq!((generation, bindings), (2, vec![leased, fixed]));
        assert!(started_ms > 0 && started_ms <= Clock::now().wall_ms);
        assert_eq!(
            ask(&dir, &Request::Violations { after: 0 }).unwrap(),
            Reply::Violations { events: vec![] }
        );
        // What no VLAN is, or too much, is refused.
        let bad = GuardConfig {
            enforce: vec![4095],
            ..GuardConfig::default()
        };
        assert_eq!(
            ask(&dir, &Request::Mode(bad)).unwrap(),
            Reply::Refused("VLAN 4095 is no VLAN".into())
        );
        let many = vec![leased; MAX_BINDINGS + 1];
        assert!(matches!(
            ask(&dir, &Request::Seed(many)).unwrap(),
            Reply::Refused(_)
        ));
        stop.send(b"x").unwrap();
        run.join().unwrap().unwrap();
    }

    #[test]
    fn only_the_agents_group_is_served() {
        let dir = TestDir::new();
        let (stop, run) = start(&dir, own_gid().wrapping_add(54_321));
        assert!(ask(&dir, &Request::Bindings).is_err());
        stop.send(b"x").unwrap();
        run.join().unwrap().unwrap();
    }

    #[test]
    fn a_violation_reads_as_an_event() {
        let mut g = Guards::default();
        let port = Port {
            ifindex: 1,
            name: "wlan5".into(),
            vlan: 42,
            wifi: true,
        };
        let f = frame::Frame {
            src: [2, 0, 0, 0, 0, 1],
            what: frame::What::Tagged { vid: 0 },
        };
        g.take(&port, &f, crate::rules::tests::now(5));
        let events = g.after(0);
        assert!(matches!(&events[0].1.kind, EventKind::GuardViolation(v) if v.guard == Guard::Tag));
    }
}
