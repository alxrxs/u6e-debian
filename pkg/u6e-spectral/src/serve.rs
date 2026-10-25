//! The helper's socket: the agent asks for a radio's scan with a line,
//! `start <radio>` or `stop <radio>`, and gets back length-prefixed
//! `AgentMsg` frames, the link's own encoding, which it forwards as they
//! are: a `SpectrumState` answering each request (and when a scan ends by
//! itself), and the scan's `Spectrum` frames, at most one per radio every
//! [`PERIOD`].
//!
//! Only a member of the agent's group is served, a client at most
//! [`BURST`] requests at once and one a second after, and a radio scans for
//! one client at a time; anything else is refused before any debugfs file is
//! touched. A scan stops when its client asks, disconnects or misbehaves,
//! when the radio's driver stops it, and when the helper ends. One thread,
//! one `poll`: nothing here blocks.

use std::io::{self, ErrorKind, Read, Write};
use std::mem;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use u6e_proto::frame::write_frame;
use u6e_proto::msg::AgentMsg;

use crate::hold::Hold;
use crate::radio::{self, Scan};
use crate::sample::Decoder;

/// One frame per radio per period: at most 10 a second.
pub const PERIOD: Duration = Duration::from_millis(100);
/// Requests a client may make at once; then one per [`REFILL`].
pub const BURST: u32 = 5;
const REFILL: Duration = Duration::from_secs(1);
/// The longest request line.
const LINE_MAX: usize = 32;
const CLIENTS_MAX: usize = 4;
/// What may wait to be sent to a client that reads slowly: about 50
/// frames. Past it, its frames are dropped rather than held.
const OUT_MAX: usize = 16 << 10;

pub struct Config {
    /// The radios' debugfs directories, [`radio::DEBUGFS`] on an AP.
    pub root: PathBuf,
    /// The agent's group: only its members are served.
    pub gid: u32,
    /// With no client for this long, the helper ends (socket activation
    /// starts it again).
    pub idle: Duration,
}

struct Client {
    sock: UnixStream,
    id: u64,
    line: Vec<u8>,
    out: Vec<u8>,
    tokens: u32,
    refilled: Instant,
    gone: bool,
}

struct Running {
    scan: Scan,
    owner: u64,
    decoder: Decoder,
    hold: Hold,
}

/// Serves `listener` until `stop` (a signalfd on an AP) is readable or the
/// helper has been idle for `cfg.idle`. Every scan is stopped on the way out.
pub fn run(listener: UnixListener, cfg: &Config, stop: RawFd) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    let mut s = Server {
        cfg,
        clients: Vec::new(),
        running: Vec::new(),
        next_id: 0,
    };
    let mut tick = Instant::now() + PERIOD;
    let mut idle_since = Instant::now();
    loop {
        let mut fds = vec![
            pollfd(stop, libc::POLLIN),
            pollfd(listener.as_raw_fd(), libc::POLLIN),
        ];
        for c in &s.clients {
            let out = if c.out.is_empty() { 0 } else { libc::POLLOUT };
            fds.push(pollfd(c.sock.as_raw_fd(), libc::POLLIN | out));
        }
        let now = Instant::now();
        let deadline = if s.running.is_empty() {
            idle_since + cfg.idle
        } else {
            tick
        };
        let ms = deadline
            .saturating_duration_since(now)
            .as_millis()
            .min(60_000) as i32;
        // SAFETY: `fds` is a valid array of pollfds for the call.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if fds[0].revents != 0 {
            return Ok(());
        }
        if fds[1].revents != 0 {
            s.accept(&listener);
        }
        for (c, fd) in s.clients.iter_mut().zip(&fds[2..]) {
            if fd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                c.receive();
            }
        }
        s.requests();
        if Instant::now() >= tick {
            s.tick();
            tick = (tick + PERIOD).max(Instant::now());
        }
        s.flush();
        s.reap();
        if !s.clients.is_empty() {
            idle_since = Instant::now();
        } else if idle_since.elapsed() >= cfg.idle {
            return Ok(());
        }
    }
}

fn pollfd(fd: RawFd, events: libc::c_short) -> libc::pollfd {
    libc::pollfd {
        fd,
        events,
        revents: 0,
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn state(radio: &str, running: bool, reason: impl Into<String>) -> AgentMsg {
    AgentMsg::SpectrumState {
        radio: radio.to_owned(),
        running,
        reason: reason.into(),
    }
}

struct Server<'a> {
    cfg: &'a Config,
    clients: Vec<Client>,
    running: Vec<Running>,
    next_id: u64,
}

impl Server<'_> {
    fn accept(&mut self, listener: &UnixListener) {
        while let Ok((sock, _)) = listener.accept() {
            let mut c = Client {
                sock,
                id: self.next_id,
                line: Vec::new(),
                out: Vec::new(),
                tokens: BURST,
                refilled: Instant::now(),
                gone: false,
            };
            self.next_id += 1;
            let refused = if !member(&c.sock, self.cfg.gid) {
                Some("refused: not in the agent's group")
            } else if self.clients.len() >= CLIENTS_MAX {
                Some("refused: too many clients")
            } else {
                None
            };
            if let Some(why) = refused {
                c.send(&state("", false, why));
                // Best effort: the client is not served either way.
                let _ = c.sock.write_all(&c.out);
                continue;
            }
            if c.sock.set_nonblocking(true).is_ok() {
                self.clients.push(c);
            }
        }
    }

    /// Carries out every whole request line of every client.
    fn requests(&mut self) {
        for i in 0..self.clients.len() {
            while let Some(end) = self.clients[i].line.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = self.clients[i].line.drain(..=end).collect();
                let reply = self.request(i, &line[..end]);
                self.clients[i].send(&reply);
            }
            if self.clients[i].line.len() > LINE_MAX {
                self.clients[i].gone = true;
            }
        }
    }

    fn request(&mut self, i: usize, line: &[u8]) -> AgentMsg {
        let c = &mut self.clients[i];
        if !c.take_token() {
            return state("", false, "refused: too many requests");
        }
        let id = c.id;
        let parsed = std::str::from_utf8(line)
            .ok()
            .and_then(|l| l.split_once(' '))
            .and_then(|(verb, name)| Some((verb, radio::radio(name)?)));
        let Some((verb, radio)) = parsed else {
            return state(
                "",
                false,
                "refused: not start or stop of radio24, radio5 or radio6",
            );
        };
        let at = self.running.iter().position(|r| r.scan.radio == radio);
        match (verb, at) {
            ("start", Some(at)) if self.running[at].owner == id => state(radio, true, "running"),
            ("start", Some(_)) => state(radio, false, "refused: another client scans it"),
            ("start", None) => match Scan::start(&self.cfg.root, radio) {
                Ok(scan) => {
                    self.running.push(Running {
                        scan,
                        owner: id,
                        decoder: Decoder::default(),
                        hold: Hold::default(),
                    });
                    state(radio, true, "started")
                }
                Err(e) => state(radio, false, format!("cannot start: {e}")),
            },
            ("stop", Some(at)) if self.running[at].owner == id => {
                drop(self.running.remove(at));
                state(radio, false, "stopped")
            }
            ("stop", _) => state(radio, false, "not running"),
            _ => state(
                "",
                false,
                "refused: not start or stop of radio24, radio5 or radio6",
            ),
        }
    }

    /// Reads every scan's relay file, sends each the frame of what came and
    /// triggers its next samples.
    fn tick(&mut self) {
        let at_ms = now_ms();
        let mut ended = Vec::new();
        for (i, r) in self.running.iter_mut().enumerate() {
            let hold = &mut r.hold;
            let read = r
                .decoder
                .read(&mut r.scan.relay, &mut |_| {}, &mut |s| hold.add(s));
            let why = match read.and_then(|_| r.scan.trigger()) {
                Err(e) => Some(format!("stopped: {e}")),
                Ok(()) => None,
            };
            let frame = r.hold.take(r.scan.radio, at_ms).map(AgentMsg::Spectrum);
            if let Some(c) = self.clients.iter_mut().find(|c| c.id == r.owner) {
                if let Some(f) = frame {
                    c.send(&f);
                }
                if let Some(why) = &why {
                    c.send(&state(r.scan.radio, false, why.clone()));
                }
            }
            if why.is_some() {
                ended.push(i);
            }
        }
        for i in ended.into_iter().rev() {
            self.running.remove(i);
        }
    }

    fn flush(&mut self) {
        for c in &mut self.clients {
            while !c.out.is_empty() {
                match c.sock.write(&c.out) {
                    Ok(n) => {
                        c.out.drain(..n);
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == ErrorKind::Interrupted => {}
                    Err(_) => {
                        c.gone = true;
                        break;
                    }
                }
            }
        }
    }

    /// Drops the clients that left, and with them their scans.
    fn reap(&mut self) {
        let gone: Vec<u64> = self
            .clients
            .iter()
            .filter(|c| c.gone)
            .map(|c| c.id)
            .collect();
        self.running.retain(|r| !gone.contains(&r.owner));
        self.clients.retain(|c| !c.gone);
    }
}

impl Client {
    /// Takes in what the socket holds, up to a few lines' worth: a client
    /// that sends more than a line without its end is dropped anyway.
    fn receive(&mut self) {
        let mut buf = [0; 256];
        match self.sock.read(&mut buf) {
            Ok(0) => self.gone = true,
            Ok(n) => self.line.extend_from_slice(&buf[..n]),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
            Err(_) => self.gone = true,
        }
    }

    fn send(&mut self, msg: &AgentMsg) {
        if self.out.len() < OUT_MAX {
            // Into a Vec: it cannot fail.
            let _ = write_frame(&mut self.out, msg);
        }
    }

    fn take_token(&mut self) -> bool {
        let refills = self.refilled.elapsed().as_secs() / REFILL.as_secs();
        if refills > 0 {
            self.tokens = (self.tokens + refills as u32).min(BURST);
            self.refilled += REFILL * refills as u32;
        }
        let ok = self.tokens > 0;
        self.tokens = self.tokens.saturating_sub(1);
        ok
    }
}

/// Whether the process at the other end of `sock` is a member of `gid`, as
/// its primary group or one of the others.
fn member(sock: &UnixStream, gid: u32) -> bool {
    let fd = sock.as_raw_fd();
    // SAFETY: a zeroed ucred is a valid one for getsockopt to fill.
    let mut cred: libc::ucred = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` and `len` describe a buffer of the size the call takes.
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &mut len,
        )
    };
    if r != 0 {
        return false;
    }
    if cred.gid == gid {
        return true;
    }
    let mut groups = [0 as libc::gid_t; 64];
    let mut len = mem::size_of_val(&groups) as libc::socklen_t;
    // SAFETY: `groups` and `len` describe a buffer of the size the call takes.
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERGROUPS,
            groups.as_mut_ptr().cast(),
            &mut len,
        )
    };
    let n = len as usize / mem::size_of::<libc::gid_t>();
    r == 0 && groups[..n.min(groups.len())].contains(&gid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::os::fd::IntoRawFd;
    use std::sync::mpsc::{self, Receiver};
    use std::thread;

    use u6e_proto::frame::{decode_frame, read_frame};
    use u6e_proto::msg::SpectrumFrame;

    use crate::radio::tests::{tree, writes};
    use crate::sample::tests::RECORDED;
    use crate::testdir::TestDir;

    const WAIT: Duration = Duration::from_secs(10);
    const REFUSED: &str = "refused: not start or stop of radio24, radio5 or radio6";

    /// A helper serving a debugfs tree of its own, in a thread.
    struct Helper {
        dir: TestDir,
        stop: UnixStream,
        done: Receiver<io::Result<()>>,
    }

    impl Helper {
        fn start(gid: u32, idle: Duration) -> Self {
            let dir = TestDir::new();
            tree(&dir.path().join("debugfs"));
            let listener = UnixListener::bind(dir.path().join("sock")).unwrap();
            let (stop_rx, stop) = UnixStream::pair().unwrap();
            let cfg = Config {
                root: dir.path().join("debugfs"),
                gid,
                idle,
            };
            let (tx, done) = mpsc::channel();
            thread::spawn(move || {
                // The fd is the thread's for the life of the helper.
                let r = run(listener, &cfg, stop_rx.into_raw_fd());
                let _ = tx.send(r);
            });
            Helper { dir, stop, done }
        }

        /// A helper serving this process's own group.
        fn new() -> Self {
            Self::start(own_gid(), WAIT)
        }

        fn connect(&self) -> UnixStream {
            let c = UnixStream::connect(self.dir.path().join("sock")).unwrap();
            c.set_read_timeout(Some(WAIT)).unwrap();
            c
        }

        fn writes(&self, radio: &str) -> String {
            writes(&self.dir.path().join("debugfs"), radio)
        }

        /// Waits until `radio`'s last write is `last`.
        fn wait_for(&self, radio: &str, last: &str) {
            let start = Instant::now();
            while self.writes(radio).lines().last() != Some(last) {
                assert!(start.elapsed() < WAIT, "{radio}: {:?}", self.writes(radio));
                thread::sleep(Duration::from_millis(10));
            }
        }

        /// Appends `bytes` to `radio`'s relay file, as the driver would.
        fn relay(&self, radio: &str, bytes: &[u8]) {
            let path = self.dir.path().join("debugfs").join(radio);
            OpenOptions::new()
                .append(true)
                .open(path.join("ath11k/spectral_scan0"))
                .unwrap()
                .write_all(bytes)
                .unwrap();
        }

        fn nothing_written(&self) {
            for r in radio::RADIOS {
                assert_eq!(self.writes(r), "", "{r}");
            }
        }
    }

    fn own_gid() -> u32 {
        // SAFETY: getgid cannot fail.
        unsafe { libc::getgid() }
    }

    fn ask(c: &mut UnixStream, line: &str) {
        c.write_all(format!("{line}\n").as_bytes()).unwrap();
    }

    fn recv(c: &mut UnixStream) -> AgentMsg {
        read_frame(c).unwrap()
    }

    fn expect_state(c: &mut UnixStream, radio: &str, running: bool, reason: &str) {
        match recv(c) {
            AgentMsg::SpectrumState {
                radio: r,
                running: on,
                reason: why,
            } => assert_eq!((r.as_str(), on, why.as_str()), (radio, running, reason)),
            other => panic!("expected a state, got {other:?}"),
        }
    }

    fn next_frame(c: &mut UnixStream) -> SpectrumFrame {
        match recv(c) {
            AgentMsg::Spectrum(f) => f,
            other => panic!("expected a frame, got {other:?}"),
        }
    }

    #[test]
    fn a_scan_streams_frames_and_stops_when_asked() {
        let h = Helper::new();
        let mut c = h.connect();
        ask(&mut c, "start radio5");
        expect_state(&mut c, "radio5", true, "started");
        h.relay("radio5", RECORDED);
        let f = next_frame(&mut c);
        assert_eq!(
            (f.radio.as_str(), f.center_mhz, f.bins.len()),
            ("radio5", 5775, 256)
        );
        ask(&mut c, "start radio5");
        expect_state(&mut c, "radio5", true, "running");
        ask(&mut c, "stop radio5");
        expect_state(&mut c, "radio5", false, "stopped");
        // Triggered at every tick, disabled at the end.
        let w = h.writes("radio5");
        assert!(w.starts_with("512\n8\nmanual\ntrigger\ntrigger\n"), "{w}");
        assert!(w.ends_with("trigger\ndisable\n"), "{w}");
        ask(&mut c, "stop radio5");
        expect_state(&mut c, "radio5", false, "not running");
    }

    /// Review focus 1 at the helper: when the client that asked goes, its
    /// scans stop at once.
    #[test]
    fn a_client_that_disconnects_stops_its_scans() {
        let h = Helper::new();
        let mut c = h.connect();
        ask(&mut c, "start radio5");
        expect_state(&mut c, "radio5", true, "started");
        ask(&mut c, "start radio24");
        expect_state(&mut c, "radio24", true, "started");
        let gone = Instant::now();
        drop(c);
        h.wait_for("radio5", "disable");
        h.wait_for("radio24", "disable");
        assert!(
            gone.elapsed() < Duration::from_secs(1),
            "{:?}",
            gone.elapsed()
        );
    }

    /// A sample every 5 ms for 2 s: folded into at most 10 frames a second,
    /// each within 600 B.
    #[test]
    fn frames_come_at_most_ten_a_second_each_within_600_bytes() {
        let h = Helper::new();
        let mut c = h.connect();
        ask(&mut c, "start radio6");
        expect_state(&mut c, "radio6", true, "started");
        c.set_read_timeout(Some(Duration::from_millis(5))).unwrap();
        let (start, mut fed) = (Instant::now(), Instant::now());
        let (mut buf, mut frames) = (Vec::new(), 0);
        while start.elapsed() < Duration::from_secs(2) {
            if fed.elapsed() >= Duration::from_millis(5) {
                h.relay("radio6", &RECORDED[..278]);
                fed = Instant::now();
            }
            let mut chunk = [0; 4096];
            if let Ok(n) = c.read(&mut chunk) {
                buf.extend_from_slice(&chunk[..n]);
            }
            while let Some((msg, n)) = decode_frame::<AgentMsg>(&buf).unwrap() {
                assert!(n <= 600, "{n} B");
                frames += usize::from(matches!(msg, AgentMsg::Spectrum(_)));
                buf.drain(..n);
            }
        }
        assert!((15..=21).contains(&frames), "{frames} frames in 2 s");
    }

    /// Review focus 5: no request but start or stop of a stable radio name
    /// is carried out, and none of the others touches a debugfs file.
    #[test]
    fn misuse_is_refused_without_a_write() {
        let h = Helper::new();
        let mut c = h.connect();
        for bad in [
            "start radio7",
            "start ../radio5",
            "start /sys/kernel/debug/ieee80211/radio5",
            "start radio5 now",
        ] {
            ask(&mut c, bad);
            expect_state(&mut c, "", false, REFUSED);
        }
        c.write_all(b"\xff\xfe radio5\n").unwrap();
        expect_state(&mut c, "", false, REFUSED);
        h.nothing_written();
        // A line longer than any request: the client is dropped (reset, as
        // it closes with the rest unread).
        c.write_all(&[b'x'; 300]).unwrap();
        assert!(matches!(c.read(&mut [0; 16]), Ok(0) | Err(_)));
        h.nothing_written();
    }

    #[test]
    fn a_client_not_in_the_agents_group_is_refused() {
        let h = Helper::start(own_gid() + 1, WAIT);
        let mut c = h.connect();
        expect_state(&mut c, "", false, "refused: not in the agent's group");
        // Its requests reach no one.
        let _ = c.write_all(b"start radio5\n");
        assert!(matches!(c.read(&mut [0; 16]), Ok(0) | Err(_)));
        h.nothing_written();
    }

    /// A flood of requests: the first [`BURST`] are carried out, the rest
    /// refused without a write.
    #[test]
    fn a_flood_of_requests_is_refused_past_the_burst() {
        let h = Helper::new();
        let mut c = h.connect();
        let flood: String = (0..40)
            .map(|i| {
                if i % 2 == 0 {
                    "start radio5\n"
                } else {
                    "stop radio5\n"
                }
            })
            .collect();
        c.write_all(flood.as_bytes()).unwrap();
        let mut refused = 0;
        for _ in 0..40 {
            if let AgentMsg::SpectrumState { reason, .. } = recv(&mut c) {
                refused += usize::from(reason == "refused: too many requests");
            }
        }
        assert_eq!(refused, 40 - BURST as usize);
        // Start, stop, start, stop, start.
        assert_eq!(h.writes("radio5").matches("manual").count(), 3);
    }

    #[test]
    fn a_radio_scans_for_one_client_at_a_time() {
        let h = Helper::new();
        let (mut a, mut b) = (h.connect(), h.connect());
        ask(&mut a, "start radio5");
        expect_state(&mut a, "radio5", true, "started");
        ask(&mut b, "start radio5");
        expect_state(&mut b, "radio5", false, "refused: another client scans it");
        ask(&mut b, "stop radio5");
        expect_state(&mut b, "radio5", false, "not running");
        ask(&mut b, "start radio6");
        expect_state(&mut b, "radio6", true, "started");
        assert_eq!(h.writes("radio5").matches("manual").count(), 1);
        assert!(!h.writes("radio5").contains("disable"));
    }

    /// The helper's end (SIGTERM on an AP) stops every scan on the way out.
    #[test]
    fn the_end_of_the_helper_stops_every_scan() {
        let mut h = Helper::new();
        let mut c = h.connect();
        ask(&mut c, "start radio24");
        expect_state(&mut c, "radio24", true, "started");
        h.stop.write_all(&[1]).unwrap();
        h.done.recv_timeout(WAIT).unwrap().unwrap();
        assert!(h.writes("radio24").ends_with("disable\n"));
        assert_eq!(c.read(&mut [0; 16]).unwrap(), 0);
    }

    #[test]
    fn an_idle_helper_ends() {
        let h = Helper::start(own_gid(), Duration::from_millis(200));
        let c = h.connect();
        thread::sleep(Duration::from_millis(400));
        assert!(h.done.try_recv().is_err(), "ended with a client");
        drop(c);
        h.done.recv_timeout(WAIT).unwrap().unwrap();
        h.nothing_written();
    }
}
