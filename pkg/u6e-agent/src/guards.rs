//! The agent's side of the client guards (`u6e-guard`, a root helper on a
//! socket of the agent's group): each tick it reads their bindings, sent to
//! the controller whole when they changed and at the start of each session,
//! and the violations recorded since the last read, sent as events; it hands
//! them the mode and the seed of the leases the controller sends, and hands
//! them again to guards that restarted, which forget both. The violations
//! are read across sessions, so those of an outage leave once the link is
//! back (the newest of them: the guards keep 256). An image without the
//! guards, or guards that do not answer, cost a line in the log.

use std::io;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use u6e_proto::frame::{read_frame, write_frame};
use u6e_proto::guard::{Reply, Request};
use u6e_proto::msg::{AgentMsg, Binding, GuardConfig};

/// The longest a request may take: the guards answer from memory.
const WAIT: Duration = Duration::from_secs(2);

pub struct Guards {
    socket: PathBuf,
    /// The guards' start, as they last said it: another means they
    /// restarted.
    started: Option<u64>,
    /// The last violation read.
    after: u64,
    /// The bindings this session was sent last (the guards' start and
    /// generation).
    sent: Option<(u64, u64)>,
    config: Option<GuardConfig>,
    seed: Option<Vec<Binding>>,
    failed: String,
}

impl Guards {
    pub fn new(socket: PathBuf) -> Self {
        Guards {
            socket,
            started: None,
            after: 0,
            sent: None,
            config: None,
            seed: None,
            failed: String::new(),
        }
    }

    fn ask(&self, req: &Request) -> io::Result<Reply> {
        let mut sock = UnixStream::connect(&self.socket)?;
        sock.set_read_timeout(Some(WAIT))?;
        sock.set_write_timeout(Some(WAIT))?;
        write_frame(&mut sock, req)?;
        read_frame(&mut sock)
    }

    /// Logs a failure once, until another or a success.
    fn note(&mut self, failure: Option<String>) {
        match failure {
            Some(e) if e != self.failed => {
                eprintln!("u6e-agent: client guards: {e}");
                self.failed = e;
            }
            Some(_) => {}
            None => self.failed.clear(),
        }
    }

    /// Hands the guards `req`, which they answer with `Done`.
    fn tell(&mut self, req: Request) {
        let failure = match self.ask(&req) {
            Ok(Reply::Done) => None,
            Ok(Reply::Refused(why)) => Some(format!("refused: {why}")),
            Ok(other) => Some(format!("unexpected answer {other:?}")),
            Err(e) => Some(e.to_string()),
        };
        self.note(failure);
    }

    /// The mode the controller sent.
    pub fn configure(&mut self, config: GuardConfig) {
        self.config = Some(config.clone());
        self.tell(Request::Mode(config));
    }

    /// The leases the controller seeds.
    pub fn seed(&mut self, leases: Vec<Binding>) {
        self.seed = Some(leases.clone());
        self.tell(Request::Seed(leases));
    }

    /// A new session: it is sent the bindings at the next read.
    pub fn session(&mut self) {
        self.sent = None;
    }

    /// Appends to `out` the bindings, if this session has not had them as
    /// they are, and the violations since the last read.
    pub fn read_into(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        let (started, generation, bindings) = match self.ask(&Request::Bindings) {
            Ok(Reply::Bindings {
                started_ms,
                generation,
                bindings,
            }) => (started_ms, generation, bindings),
            Ok(other) => {
                self.note(Some(format!("unexpected answer {other:?}")));
                return Ok(());
            }
            Err(e) => {
                self.note(Some(e.to_string()));
                return Ok(());
            }
        };
        self.note(None);
        if self.started != Some(started) {
            // Restarted guards number their violations afresh, and hold
            // neither the mode nor the seed.
            self.started = Some(started);
            self.after = 0;
            if let Some(c) = self.config.clone() {
                self.tell(Request::Mode(c));
            }
            if let Some(s) = self.seed.clone() {
                self.tell(Request::Seed(s));
            }
        }
        if self.sent != Some((started, generation)) {
            write_frame(out, &AgentMsg::Bindings(bindings))?;
            self.sent = Some((started, generation));
        }
        if let Ok(Reply::Violations { events }) =
            self.ask(&Request::Violations { after: self.after })
        {
            for (n, ev) in events {
                self.after = n;
                write_frame(out, &AgentMsg::Event(ev))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    use u6e_proto::frame::decode_frame;
    use u6e_proto::msg::{Event, EventKind, Guard, Violation};

    use crate::testdir::TestDir;

    /// What the stand-in guards answer with.
    #[derive(Clone)]
    pub struct State {
        pub started_ms: u64,
        pub generation: u64,
        pub bindings: Vec<Binding>,
        pub violations: Vec<(u64, Event)>,
    }

    /// Stand-in guards on `dir/guard.sock`: they record what they are asked
    /// and answer from `state`.
    pub struct Fake {
        pub asked: Arc<Mutex<Vec<Request>>>,
        pub state: Arc<Mutex<State>>,
        pub socket: PathBuf,
    }

    impl Fake {
        pub fn start(dir: &TestDir) -> Self {
            let socket = dir.path().join("guard.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let asked = Arc::new(Mutex::new(Vec::new()));
            let state = Arc::new(Mutex::new(State {
                started_ms: 1,
                generation: 0,
                bindings: Vec::new(),
                violations: Vec::new(),
            }));
            let (a, s) = (Arc::clone(&asked), Arc::clone(&state));
            thread::spawn(move || {
                for mut sock in listener.incoming().flatten() {
                    let Ok(req) = read_frame::<_, Request>(&mut sock) else {
                        continue;
                    };
                    let State {
                        started_ms,
                        generation,
                        bindings,
                        violations,
                    } = s.lock().unwrap().clone();
                    let reply = match &req {
                        Request::Bindings => Reply::Bindings {
                            started_ms,
                            generation,
                            bindings,
                        },
                        Request::Violations { after } => Reply::Violations {
                            events: violations.into_iter().filter(|(n, _)| n > after).collect(),
                        },
                        _ => Reply::Done,
                    };
                    a.lock().unwrap().push(req);
                    let _ = write_frame(&mut sock, &reply);
                }
            });
            Fake {
                asked,
                state,
                socket,
            }
        }
    }

    pub fn violation(n: u64) -> (u64, Event) {
        let v = Violation {
            guard: Guard::Arp,
            mac: [2, 0, 0, 0, 0, 1],
            ifname: "wlan5".into(),
            vlan: 42,
            ip: None,
            detail: format!("violation {n}"),
            dropped: false,
            repeats: 0,
        };
        let at_ms = n;
        (
            n,
            Event {
                at_ms,
                kind: EventKind::GuardViolation(v),
            },
        )
    }

    fn sent(out: &[u8]) -> Vec<AgentMsg> {
        let mut msgs = Vec::new();
        let mut at = 0;
        while let Some((m, n)) = decode_frame::<AgentMsg>(&out[at..]).unwrap() {
            msgs.push(m);
            at += n;
        }
        msgs
    }

    #[test]
    fn bindings_go_once_per_change_and_violations_once() {
        let dir = TestDir::new();
        let fake = Fake::start(&dir);
        let mut g = Guards::new(fake.socket.clone());
        let b = Binding {
            mac: [2, 0, 0, 0, 0, 1],
            ip: [192, 0, 2, 10].into(),
            expires_ms: None,
        };
        fake.state.lock().unwrap().bindings = vec![b];
        fake.state.lock().unwrap().violations = vec![violation(1), violation(2)];
        let mut out = Vec::new();
        g.read_into(&mut out).unwrap();
        assert_eq!(
            sent(&out),
            [
                AgentMsg::Bindings(vec![b]),
                AgentMsg::Event(violation(1).1),
                AgentMsg::Event(violation(2).1)
            ]
        );
        out.clear();
        g.read_into(&mut out).unwrap();
        assert_eq!(sent(&out), []);
        // A new session is sent the bindings again; a change is sent.
        g.session();
        g.read_into(&mut out).unwrap();
        fake.state.lock().unwrap().generation = 1;
        g.read_into(&mut out).unwrap();
        assert_eq!(
            sent(&out),
            [AgentMsg::Bindings(vec![b]), AgentMsg::Bindings(vec![b])]
        );
    }

    #[test]
    fn restarted_guards_get_the_mode_and_seed_again() {
        let dir = TestDir::new();
        let fake = Fake::start(&dir);
        let mut g = Guards::new(fake.socket.clone());
        let mode = GuardConfig {
            enforce: vec![42],
            statics: vec![],
        };
        g.configure(mode.clone());
        g.seed(vec![]);
        let mut out = Vec::new();
        g.read_into(&mut out).unwrap();
        fake.state.lock().unwrap().violations = vec![violation(1)];
        g.read_into(&mut out).unwrap();
        // They restart: their numbering starts again.
        *fake.state.lock().unwrap() = State {
            started_ms: 2,
            generation: 0,
            bindings: vec![],
            violations: vec![violation(1)],
        };
        g.read_into(&mut out).unwrap();
        let asked = fake.asked.lock().unwrap().clone();
        let modes = asked
            .iter()
            .filter(|r| matches!(r, Request::Mode(_)))
            .count();
        let seeds = asked
            .iter()
            .filter(|r| matches!(r, Request::Seed(_)))
            .count();
        // Told when sent, then at the first read (the agent cannot tell
        // whether those were these guards) and after the restart.
        assert_eq!((modes, seeds), (3, 3));
        let events = sent(&out)
            .into_iter()
            .filter(|m| matches!(m, AgentMsg::Event(_)))
            .count();
        assert_eq!(events, 2);
    }

    #[test]
    fn no_guards_cost_nothing_but_a_log_line() {
        let dir = TestDir::new();
        let mut g = Guards::new(dir.path().join("absent.sock"));
        let mut out = Vec::new();
        g.read_into(&mut out).unwrap();
        g.configure(GuardConfig::default());
        assert!(out.is_empty());
        assert!(!g.failed.is_empty());
    }
}
