//! The agent's side of the client guards (`u6e-guard`, a helper on a socket
//! of the agent's group): each tick it reads their bindings and drop counts,
//! each sent to the controller when it changed and at the start of each
//! session, the violations recorded since the last read, sent as events,
//! and what they read of mDNS, whole at the start of each session (and
//! from guards that restarted) and then what changed; it hands them the
//! seed of the leases and the mode the controller sends, and hands them
//! both again (the seed first, so no enforcing mode
//! meets an empty table) to guards that restarted, which forget them. The
//! violations are read across sessions, so those of an outage leave once
//! the link is back (the newest of them: the guards keep 256), and the place
//! reached is kept in a file that outlives the agent (`cursor`), so a
//! restarted agent sends none twice. An image without the guards, or guards
//! that do not answer, cost a line in the log.

use std::fs;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use u6e_proto::frame::{read_frame, write_frame};
use u6e_proto::guard::{Reply, Request};
use u6e_proto::msg::{AgentMsg, Binding, Guard, GuardConfig, Services};

/// The longest a request may take: the guards answer from memory.
const WAIT: Duration = Duration::from_secs(2);
/// Where the place reached in the violations is kept: a directory of the
/// agent's that outlives it, until the AP reboots (prep-rootfs.sh).
pub const CURSOR: &str = "/run/u6e-agent-state/guards";

pub struct Guards {
    socket: PathBuf,
    cursor: PathBuf,
    /// The guards' start, as they last said it: another means they
    /// restarted.
    started: Option<u64>,
    /// The last violation read, of the guards started at `started`.
    after: u64,
    /// The bindings and the drop counts this session was sent last.
    sent: Option<(u64, u64)>,
    sent_drops: Option<Vec<(Guard, u64)>>,
    /// The guards' start and the generation of their mDNS table this
    /// session was sent last.
    services: Option<(u64, u64)>,
    config: Option<GuardConfig>,
    seed: Option<Vec<Binding>>,
    failed: String,
    /// The last failure of a read of the mDNS table, logged apart: the
    /// other reads working must not make it log again every tick.
    services_failed: String,
}

/// Logs `failure` once, until another or a success clears `slot`.
fn log_once(slot: &mut String, failure: Option<String>) {
    match failure {
        Some(e) if e != *slot => {
            eprintln!("u6e-agent: client guards: {e}");
            *slot = e;
        }
        Some(_) => {}
        None => slot.clear(),
    }
}

/// The guards' start and the last violation read, as `cursor` keeps them.
fn load(cursor: &PathBuf) -> Option<(u64, u64)> {
    let text = fs::read_to_string(cursor).ok()?;
    let (started, after) = text.trim().split_once(' ')?;
    Some((started.parse().ok()?, after.parse().ok()?))
}

impl Guards {
    pub fn new(socket: PathBuf, cursor: PathBuf) -> Self {
        let kept = load(&cursor);
        Guards {
            socket,
            cursor,
            started: kept.map(|(s, _)| s),
            after: kept.map_or(0, |(_, a)| a),
            sent: None,
            sent_drops: None,
            services: None,
            config: None,
            seed: None,
            failed: String::new(),
            services_failed: String::new(),
        }
    }

    /// Keeps the place reached, written whole or not at all.
    fn keep(&mut self) {
        let Some(started) = self.started else { return };
        let tmp = self.cursor.with_extension("tmp");
        let written = fs::write(&tmp, format!("{started} {}\n", self.after))
            .and_then(|()| fs::rename(&tmp, &self.cursor));
        let failure = written
            .err()
            .map(|e| format!("{}: {e}", self.cursor.display()));
        self.note(failure);
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
        log_once(&mut self.failed, failure);
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

    /// A new session: it is sent the bindings, the drop counts and the
    /// whole mDNS table at the next read.
    pub fn session(&mut self) {
        self.sent = None;
        self.sent_drops = None;
        self.services = None;
    }

    /// Appends to `out` the bindings and drop counts, if this session has
    /// not had them as they are, the violations since the last read and
    /// what changed of the mDNS table.
    pub fn read_into(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        let (started, generation, bindings, dropped) = match self.ask(&Request::Bindings) {
            Ok(Reply::Bindings {
                started_ms,
                generation,
                bindings,
                dropped,
            }) => (started_ms, generation, bindings, dropped),
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
            // neither the seed nor the mode.
            self.started = Some(started);
            self.after = 0;
            self.keep();
            if let Some(s) = self.seed.clone() {
                self.tell(Request::Seed(s));
            }
            if let Some(c) = self.config.clone() {
                self.tell(Request::Mode(c));
            }
        }
        if self.sent != Some((started, generation)) {
            write_frame(out, &AgentMsg::Bindings(bindings))?;
            self.sent = Some((started, generation));
        }
        if self.sent_drops.as_ref() != Some(&dropped) {
            write_frame(out, &AgentMsg::GuardDrops(dropped.clone()))?;
            self.sent_drops = Some(dropped);
        }
        if let Ok(Reply::Violations { events }) =
            self.ask(&Request::Violations { after: self.after })
            && !events.is_empty()
        {
            for (n, ev) in events {
                self.after = n;
                write_frame(out, &AgentMsg::Event(ev))?;
            }
            self.keep();
        }
        let since = self.services;
        let failure = match self.ask(&Request::Services { since }) {
            Ok(Reply::Services {
                started_ms,
                generation,
                services,
            }) => {
                if services.full || !unchanged(&services) {
                    write_frame(out, &AgentMsg::Services(services))?;
                }
                self.services = Some((started_ms, generation));
                None
            }
            Ok(other) => Some(format!("mDNS table: unexpected answer {other:?}")),
            Err(e) => Some(format!("mDNS table: {e}")),
        };
        log_once(&mut self.services_failed, failure);
        Ok(())
    }
}

/// Whether a read of the mDNS table holds no change.
fn unchanged(s: &Services) -> bool {
    s.devices.is_empty() && s.offers.is_empty() && s.queries.is_empty() && s.gone.is_empty()
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    use u6e_proto::frame::decode_frame;
    use u6e_proto::msg::{Event, EventKind, Violation};

    use crate::testdir::TestDir;

    /// What the stand-in guards answer with.
    #[derive(Clone)]
    pub struct State {
        pub started_ms: u64,
        pub generation: u64,
        pub bindings: Vec<Binding>,
        pub dropped: Vec<(Guard, u64)>,
        pub violations: Vec<(u64, Event)>,
        /// The mDNS table's generation and what it answers with: whole to
        /// a read without a place, else as it is; refused when `refuse`.
        pub services_generation: u64,
        pub services: Services,
        pub refuse: bool,
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
                dropped: Vec::new(),
                violations: Vec::new(),
                services_generation: 0,
                services: Services::default(),
                refuse: false,
            }));
            let (a, s) = (Arc::clone(&asked), Arc::clone(&state));
            thread::spawn(move || {
                for mut sock in listener.incoming().flatten() {
                    let Ok(req) = read_frame::<_, Request>(&mut sock) else {
                        continue;
                    };
                    let st = s.lock().unwrap().clone();
                    let reply = match &req {
                        Request::Bindings => Reply::Bindings {
                            started_ms: st.started_ms,
                            generation: st.generation,
                            bindings: st.bindings,
                            dropped: st.dropped,
                        },
                        Request::Violations { after } => Reply::Violations {
                            events: st
                                .violations
                                .into_iter()
                                .filter(|(n, _)| n > after)
                                .collect(),
                        },
                        Request::Services { .. } if st.refuse => Reply::Refused("busy".into()),
                        Request::Services { since } => Reply::Services {
                            started_ms: st.started_ms,
                            generation: st.services_generation,
                            services: Services {
                                full: since.is_none_or(|(s, _)| s != st.started_ms),
                                ..st.services
                            },
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

    pub fn sent(out: &[u8]) -> Vec<AgentMsg> {
        let mut msgs = Vec::new();
        let mut at = 0;
        while let Some((m, n)) = decode_frame::<AgentMsg>(&out[at..]).unwrap() {
            msgs.push(m);
            at += n;
        }
        msgs
    }

    fn guards(fake: &Fake, dir: &TestDir) -> Guards {
        Guards::new(fake.socket.clone(), dir.path().join("cursor"))
    }

    /// The messages of `out` but the mDNS table's.
    fn but_services(out: &[u8]) -> Vec<AgentMsg> {
        let all = sent(out).into_iter();
        all.filter(|m| !matches!(m, AgentMsg::Services(_)))
            .collect()
    }

    #[test]
    fn bindings_and_drops_go_once_per_change_and_violations_once() {
        let dir = TestDir::new();
        let fake = Fake::start(&dir);
        let mut g = guards(&fake, &dir);
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
            but_services(&out),
            [
                AgentMsg::Bindings(vec![b]),
                AgentMsg::GuardDrops(vec![]),
                AgentMsg::Event(violation(1).1),
                AgentMsg::Event(violation(2).1)
            ]
        );
        out.clear();
        g.read_into(&mut out).unwrap();
        assert_eq!(sent(&out), []);
        // A new session is sent both again; a change is sent.
        g.session();
        g.read_into(&mut out).unwrap();
        fake.state.lock().unwrap().generation = 1;
        fake.state.lock().unwrap().dropped = vec![(Guard::Arp, 3)];
        g.read_into(&mut out).unwrap();
        assert_eq!(
            but_services(&out),
            [
                AgentMsg::Bindings(vec![b]),
                AgentMsg::GuardDrops(vec![]),
                AgentMsg::Bindings(vec![b]),
                AgentMsg::GuardDrops(vec![(Guard::Arp, 3)]),
            ]
        );
    }

    #[test]
    fn a_restarted_agent_sends_no_violation_twice() {
        let dir = TestDir::new();
        let fake = Fake::start(&dir);
        fake.state.lock().unwrap().violations = vec![violation(1), violation(2)];
        let mut out = Vec::new();
        guards(&fake, &dir).read_into(&mut out).unwrap();
        // The agent restarts: the guards did not.
        out.clear();
        fake.state.lock().unwrap().violations.push(violation(3));
        guards(&fake, &dir).read_into(&mut out).unwrap();
        let events: Vec<_> = sent(&out)
            .into_iter()
            .filter(|m| matches!(m, AgentMsg::Event(_)))
            .collect();
        assert_eq!(events, [AgentMsg::Event(violation(3).1)]);
    }

    #[test]
    fn restarted_guards_get_the_seed_then_the_mode_again() {
        let dir = TestDir::new();
        let fake = Fake::start(&dir);
        let mut g = guards(&fake, &dir);
        let mode = GuardConfig {
            enforce: vec![42],
            ..GuardConfig::default()
        };
        g.configure(mode.clone());
        g.seed(vec![]);
        let mut out = Vec::new();
        g.read_into(&mut out).unwrap();
        fake.state.lock().unwrap().violations = vec![violation(1)];
        g.read_into(&mut out).unwrap();
        // They restart: their numbering starts again.
        fake.asked.lock().unwrap().clear();
        let mut st = fake.state.lock().unwrap().clone();
        st.started_ms = 2;
        *fake.state.lock().unwrap() = st;
        g.read_into(&mut out).unwrap();
        let asked = fake.asked.lock().unwrap().clone();
        let told: Vec<_> = asked
            .iter()
            .filter(|r| matches!(r, Request::Mode(_) | Request::Seed(_)))
            .collect();
        assert_eq!(told, [&Request::Seed(vec![]), &Request::Mode(mode)]);
        let events = sent(&out)
            .into_iter()
            .filter(|m| matches!(m, AgentMsg::Event(_)))
            .count();
        assert_eq!(events, 2);
    }

    #[test]
    fn the_mdns_table_goes_whole_then_its_changes() {
        use u6e_proto::msg::MdnsKey;
        let dir = TestDir::new();
        let fake = Fake::start(&dir);
        let mut g = guards(&fake, &dir);
        let services = |out: &[u8]| -> Vec<Services> {
            let all = sent(out).into_iter();
            all.filter_map(|m| match m {
                AgentMsg::Services(s) => Some(s),
                _ => None,
            })
            .collect()
        };
        let asked = |fake: &Fake| -> Vec<Option<(u64, u64)>> {
            let all = fake.asked.lock().unwrap().clone().into_iter();
            all.filter_map(|r| match r {
                Request::Services { since } => Some(since),
                _ => None,
            })
            .collect()
        };
        // The first read of a session asks with no place: the whole table,
        // empty or not.
        let mut out = Vec::new();
        g.read_into(&mut out).unwrap();
        assert_eq!(services(&out).len(), 1);
        assert!(services(&out)[0].full);
        // Then with the place reached; nothing changed sends nothing.
        fake.state.lock().unwrap().services_generation = 7;
        out.clear();
        g.read_into(&mut out).unwrap();
        g.read_into(&mut out).unwrap();
        assert_eq!(services(&out), []);
        // A change is sent.
        let gone = vec![MdnsKey::Device([2, 0, 0, 0, 0, 9])];
        fake.state.lock().unwrap().services.gone.clone_from(&gone);
        g.read_into(&mut out).unwrap();
        assert_eq!(services(&out)[0].gone, gone);
        assert!(!services(&out)[0].full);
        // A new session asks with no place again, and restarted guards
        // answer whole.
        g.session();
        g.read_into(&mut out).unwrap();
        fake.state.lock().unwrap().started_ms = 2;
        g.read_into(&mut out).unwrap();
        let fulls: Vec<bool> = services(&out).iter().map(|s| s.full).collect();
        assert_eq!(fulls, [false, true, true]);
        assert_eq!(
            asked(&fake),
            [
                None,
                Some((1, 0)),
                Some((1, 7)),
                Some((1, 7)),
                None,
                Some((1, 7))
            ]
        );
    }

    #[test]
    fn a_failed_read_of_the_mdns_table_is_logged_once() {
        let dir = TestDir::new();
        let fake = Fake::start(&dir);
        fake.state.lock().unwrap().refuse = true;
        let mut g = guards(&fake, &dir);
        let mut out = Vec::new();
        g.read_into(&mut out).unwrap();
        assert!(
            g.services_failed.contains("mDNS table"),
            "{:?}",
            g.services_failed
        );
        // The other reads working leave it as it was, so it logs no more.
        g.read_into(&mut out).unwrap();
        assert!(!g.services_failed.is_empty() && g.failed.is_empty());
        fake.state.lock().unwrap().refuse = false;
        g.read_into(&mut out).unwrap();
        assert!(g.services_failed.is_empty());
    }

    #[test]
    fn no_guards_cost_nothing_but_a_log_line() {
        let dir = TestDir::new();
        let mut g = Guards::new(dir.path().join("absent.sock"), dir.path().join("cursor"));
        let mut out = Vec::new();
        g.read_into(&mut out).unwrap();
        g.configure(GuardConfig::default());
        assert!(out.is_empty());
        assert!(!g.failed.is_empty());
    }
}
