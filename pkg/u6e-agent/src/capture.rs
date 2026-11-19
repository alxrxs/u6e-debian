//! The client capture the controller asks for, which u6e-capture (a root
//! helper; the agent may open no packet socket) carries out. A capture is a
//! connection to the helper, one a session: shutting its writing side down
//! stops it, and the helper's last chunks and state still come; dropping
//! it ends the capture at once, as the session's end does. The agent
//! forwards the helper's frames under the controller's credit: while
//! [`CREDIT`] chunks wait for the controller's acknowledgement it reads
//! nothing more, and the helper, whose own bound is then reached, drops
//! packets rather than hold them. Every frame is checked first: a chunk of
//! this capture, next in order, within [`CHUNK_MAX`] and the capture's size;
//! a state of it. Past its time and a margin the capture is dropped.

use std::collections::VecDeque;
use std::io::{ErrorKind, Read};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use u6e_proto::capture::SOCKET;
use u6e_proto::frame::{decode_frame, write_frame};
use u6e_proto::msg::{AgentMsg, CHUNK_MAX, CaptureRequest, CaptureState};

/// The chunks the controller may leave unacknowledged.
pub const CREDIT: usize = 4;
/// Beyond the capture's own time: the helper's end and its last frames.
const MARGIN: Duration = Duration::from_secs(30);
/// What may wait of a frame not yet whole: a chunk's frame.
const INBUF_MAX: usize = CHUNK_MAX + 1024;

struct Capture {
    id: u64,
    max_bytes: u64,
    deadline: Instant,
    sock: UnixStream,
    inbuf: Vec<u8>,
    unacked: VecDeque<u64>,
    next_seq: u64,
    bytes: u64,
}

/// The capture running on behalf of one session, if any.
pub struct Captures {
    socket: PathBuf,
    cur: Option<Capture>,
}

fn ended(id: u64, reason: &str) -> AgentMsg {
    AgentMsg::Capture(CaptureState {
        id,
        running: false,
        mechanism: None,
        bytes: 0,
        packets: 0,
        dropped: 0,
        reason: reason.into(),
    })
}

impl Default for Captures {
    fn default() -> Self {
        Captures::new(Path::new(SOCKET))
    }
}

impl Captures {
    pub fn new(socket: &Path) -> Self {
        Captures {
            socket: socket.to_owned(),
            cur: None,
        }
    }

    /// Asks the helper for `req`'s capture; what the agent can tell at once
    /// (a request out of bounds, a capture running, no helper) is returned.
    pub fn start(&mut self, req: CaptureRequest) -> Option<AgentMsg> {
        if let Err(why) = req.check() {
            return Some(ended(req.id, &format!("refused: {why}")));
        }
        if self.cur.is_some() {
            return Some(ended(req.id, "refused: a capture runs on this AP"));
        }
        let ask = || {
            let mut sock = UnixStream::connect(&self.socket)?;
            write_frame(&mut sock, &req)?;
            sock.set_nonblocking(true)?;
            Ok::<_, std::io::Error>(sock)
        };
        match ask() {
            Ok(sock) => {
                self.cur = Some(Capture {
                    id: req.id,
                    max_bytes: u64::from(req.max_bytes),
                    deadline: Instant::now() + Duration::from_secs(u64::from(req.secs)) + MARGIN,
                    sock,
                    inbuf: Vec::new(),
                    unacked: VecDeque::new(),
                    next_seq: 0,
                    bytes: 0,
                });
                None
            }
            Err(e) => Some(ended(req.id, &format!("refused: no capture helper: {e}"))),
        }
    }

    /// Stops capture `id`: its last frames still come.
    pub fn stop(&mut self, id: u64) {
        if let Some(c) = self.cur.as_mut().filter(|c| c.id == id) {
            let _ = c.sock.shutdown(std::net::Shutdown::Write);
        }
    }

    /// The controller stored chunk `seq` of capture `id`, and those before.
    pub fn ack(&mut self, id: u64, seq: u64) {
        if let Some(c) = self.cur.as_mut().filter(|c| c.id == id) {
            c.unacked.retain(|s| *s > seq);
        }
    }

    /// The helper's connection, for `poll`, while there is credit to read.
    pub fn fd(&self) -> Option<RawFd> {
        let c = self.cur.as_ref()?;
        (c.unacked.len() < CREDIT).then(|| c.sock.as_raw_fd())
    }

    /// When the capture is dropped, whatever the helper does.
    pub fn deadline(&self) -> Option<Instant> {
        self.cur.as_ref().map(|c| c.deadline)
    }

    /// Appends to `out` what the helper sent that may go now; ends the
    /// capture when the helper says it ended, closes, misbehaves or keeps
    /// it past its time.
    pub fn read(&mut self, out: &mut Vec<u8>) {
        let Some(c) = self.cur.as_mut() else {
            return;
        };
        let end = if Instant::now() >= c.deadline {
            Some(Some("the capture outlasted its time".to_owned()))
        } else {
            c.read_into(out)
        };
        if let Some(why) = end {
            if let Some(why) = why {
                eprintln!("u6e-agent: capture {}: {why}", c.id);
                let _ = write_frame(out, &ended(c.id, &why));
            }
            self.cur = None;
        }
    }
}

impl Capture {
    /// Forwards whole frames while there is credit; `Some` when the capture
    /// is over, with why when the helper did not say.
    fn read_into(&mut self, out: &mut Vec<u8>) -> Option<Option<String>> {
        while self.unacked.len() < CREDIT {
            let mut used = 0;
            while let Some((msg, n)) = match decode_frame::<AgentMsg>(&self.inbuf[used..]) {
                Ok(m) => m,
                Err(e) => return Some(Some(format!("the helper sent no frame: {e}"))),
            } {
                used += n;
                match msg {
                    AgentMsg::CaptureChunk(ch)
                        if ch.id == self.id
                            && ch.seq == self.next_seq
                            && ch.data.len() <= CHUNK_MAX
                            && self.bytes + ch.data.len() as u64 <= self.max_bytes =>
                    {
                        self.bytes += ch.data.len() as u64;
                        self.unacked.push_back(ch.seq);
                        self.next_seq += 1;
                        let _ = write_frame(out, &AgentMsg::CaptureChunk(ch));
                    }
                    AgentMsg::Capture(s) if s.id == self.id => {
                        let over = !s.running;
                        let _ = write_frame(out, &AgentMsg::Capture(s));
                        if over {
                            return Some(None);
                        }
                    }
                    other => {
                        let what =
                            format!("the helper sent what is out of place: {:?}", kind(&other));
                        return Some(Some(what));
                    }
                }
                if self.unacked.len() >= CREDIT {
                    break;
                }
            }
            self.inbuf.drain(..used);
            if self.unacked.len() >= CREDIT {
                return None;
            }
            // What is left is part of one frame: past a chunk's, none.
            if self.inbuf.len() >= INBUF_MAX {
                return Some(Some("the helper sent a frame too large".into()));
            }
            let mut buf = [0u8; 16 << 10];
            let room = (INBUF_MAX - self.inbuf.len()).min(buf.len());
            match self.sock.read(&mut buf[..room]) {
                Ok(0) => return Some(Some("the capture helper ended without a word".into())),
                Ok(n) => self.inbuf.extend(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => return None,
                Err(e) => return Some(Some(format!("the capture helper: {e}"))),
            }
        }
        None
    }
}

/// A message's kind, for a log line that holds none of its data.
fn kind(m: &AgentMsg) -> &'static str {
    match m {
        AgentMsg::CaptureChunk(_) => "a chunk out of order or bounds",
        AgentMsg::Capture(_) => "another capture's state",
        _ => "another message",
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::testdir::TestDir;
    use std::io::Write;
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc::{Receiver, channel};
    use std::thread;
    use u6e_proto::frame::read_frame;
    use u6e_proto::msg::{CaptureChunk, CaptureFilter, CaptureMechanism};

    pub fn request(id: u64) -> CaptureRequest {
        CaptureRequest {
            id,
            mac: [2, 0, 0, 0, 0, 1],
            secs: 60,
            max_bytes: 1_000_000,
            snaplen: 128,
            filter: CaptureFilter::default(),
        }
    }

    pub fn chunk(id: u64, seq: u64, len: usize) -> AgentMsg {
        AgentMsg::CaptureChunk(CaptureChunk {
            id,
            seq,
            data: vec![seq as u8; len],
        })
    }

    pub fn started(id: u64, running: bool) -> AgentMsg {
        AgentMsg::Capture(CaptureState {
            id,
            running,
            mechanism: Some(CaptureMechanism::OffOffload),
            bytes: 0,
            packets: 0,
            dropped: 0,
            reason: if running { "started" } else { "stopped" }.into(),
        })
    }

    /// A helper that takes each capture's request, sends `first`, then, once
    /// the agent shuts its side down, `last`; it tells the test each request.
    pub fn helper(
        t: &TestDir,
        first: Vec<AgentMsg>,
        last: Vec<AgentMsg>,
    ) -> (PathBuf, Receiver<CaptureRequest>) {
        let path = t.path().join("capture.sock");
        let l = UnixListener::bind(&path).unwrap();
        let (tx, rx) = channel();
        thread::spawn(move || {
            for c in l.incoming() {
                let mut c = c.unwrap();
                let req: CaptureRequest = read_frame(&mut c).unwrap();
                let _ = tx.send(req);
                let (first, last) = (first.clone(), last.clone());
                thread::spawn(move || {
                    let mut out = Vec::new();
                    for m in &first {
                        write_frame(&mut out, m).unwrap();
                    }
                    let _ = c.write_all(&out);
                    let mut b = [0u8; 1];
                    let _ = c.read(&mut b);
                    let mut out = Vec::new();
                    for m in &last {
                        write_frame(&mut out, m).unwrap();
                    }
                    let _ = c.write_all(&out);
                });
            }
        });
        (path, rx)
    }

    /// The frames in `out`, taken out of it.
    fn frames(out: &mut Vec<u8>) -> Vec<AgentMsg> {
        let mut msgs = Vec::new();
        let mut at = 0;
        while let Some((m, n)) = decode_frame::<AgentMsg>(&out[at..]).unwrap() {
            msgs.push(m);
            at += n;
        }
        out.clear();
        msgs
    }

    /// Reads until `n` frames came or a second passed.
    fn read_n(c: &mut Captures, n: usize) -> Vec<AgentMsg> {
        let mut got = Vec::new();
        let until = Instant::now() + Duration::from_secs(1);
        while got.len() < n && Instant::now() < until {
            let mut out = Vec::new();
            c.read(&mut out);
            got.extend(frames(&mut out));
            thread::sleep(Duration::from_millis(5));
        }
        got
    }

    #[test]
    fn chunks_go_under_credit_and_a_stop_brings_the_tail() {
        let t = TestDir::new();
        let mut first = vec![started(1, true)];
        first.extend((0..6).map(|s| chunk(1, s, 100)));
        let (sock, rx) = helper(&t, first, vec![chunk(1, 6, 10), started(1, false)]);
        let mut c = Captures::new(&sock);
        assert!(c.start(request(1)).is_none());
        assert_eq!(rx.recv().unwrap(), request(1));
        let got = read_n(&mut c, 5);
        assert_eq!(got.len(), 5, "the state and four chunks");
        assert!(c.fd().is_none(), "no credit, no read");
        assert!(read_n(&mut c, 1).is_empty());
        c.ack(1, 1);
        assert!(c.fd().is_some());
        assert_eq!(read_n(&mut c, 2), [chunk(1, 4, 100), chunk(1, 5, 100)]);
        c.ack(1, 5);
        c.stop(1);
        assert_eq!(read_n(&mut c, 2), [chunk(1, 6, 10), started(1, false)]);
        assert!(c.deadline().is_none(), "over");
        // Another may start.
        assert!(c.start(request(2)).is_none());
    }

    #[test]
    fn a_misbehaving_or_silent_helper_ends_the_capture_with_why() {
        let t = TestDir::new();
        let (sock, _rx) = helper(&t, vec![started(1, true), chunk(1, 3, 10)], vec![]);
        let mut c = Captures::new(&sock);
        c.start(request(1));
        let got = read_n(&mut c, 2);
        let [_, AgentMsg::Capture(s)] = &got[..] else {
            panic!("{got:?}")
        };
        assert!(!s.running && s.reason.contains("out of place"), "{s:?}");
        assert!(c.deadline().is_none());

        let t = TestDir::new();
        let (sock, _rx) = helper(&t, vec![started(1, true)], vec![]);
        let mut c = Captures::new(&sock);
        c.start(request(1));
        let _ = read_n(&mut c, 1);
        c.stop(1);
        let got = read_n(&mut c, 1);
        assert!(
            matches!(&got[..], [AgentMsg::Capture(s)] if s.reason.contains("without a word")),
            "{got:?}"
        );

        // A chunk past its bound, a frame past any chunk's.
        for (len, why) in [(CHUNK_MAX + 1, "out of place"), (600_000, "too large")] {
            let t = TestDir::new();
            let (sock, _rx) = helper(&t, vec![chunk(1, 0, len)], vec![]);
            let mut c = Captures::new(&sock);
            c.start(request(1));
            let got = read_n(&mut c, 1);
            assert!(
                matches!(&got[..], [AgentMsg::Capture(s)] if s.reason.contains(why)),
                "{got:?}"
            );
        }
        // Past the capture's size.
        let t = TestDir::new();
        let (sock, _rx) = helper(
            &t,
            (0..13).map(|s| chunk(1, s, CHUNK_MAX)).collect(),
            vec![],
        );
        let mut c = Captures::new(&sock);
        c.start(request(1));
        let mut got = Vec::new();
        for s in 0..13 {
            got.extend(read_n(&mut c, 1));
            c.ack(1, s);
        }
        assert_eq!(got.len(), 13, "twelve chunks and the end");
        assert!(
            matches!(got.last(), Some(AgentMsg::Capture(s)) if s.reason.contains("out of place")),
            "{got:?}"
        );
    }

    #[test]
    fn one_capture_at_a_time_and_the_requests_are_checked() {
        let t = TestDir::new();
        let (sock, _rx) = helper(&t, vec![started(1, true)], vec![]);
        let mut c = Captures::new(&sock);
        let mut bad = request(1);
        bad.secs = 0;
        assert!(
            matches!(c.start(bad), Some(AgentMsg::Capture(s)) if s.reason.starts_with("refused"))
        );
        assert!(c.start(request(1)).is_none());
        let busy = c.start(request(2));
        assert!(
            matches!(busy, Some(AgentMsg::Capture(s)) if s.id == 2 && s.reason.contains("runs"))
        );
        let mut none = Captures::new(&t.path().join("none.sock"));
        assert!(
            matches!(none.start(request(3)), Some(AgentMsg::Capture(s)) if s.reason.contains("no capture helper"))
        );
    }
}
