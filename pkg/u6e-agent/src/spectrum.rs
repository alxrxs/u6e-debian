//! The radios' spectrum scans, which the controller starts and stops and
//! u6e-spectral (a root helper; the agent cannot run a scan) carries out.
//! Each scan is a connection of its own to the helper: the agent sends
//! `start <radio>` and forwards what comes back, the helper's
//! `SpectrumState` and its frames. Closing the connection is what stops the
//! scan, so none outlives the session it was asked in, the agent, or the
//! limit (10 minutes).
//!
//! Whatever the helper sends, the agent forwards at most [`FRAMES_PER_S`]
//! frames a second per radio, each within [`FRAME_MAX`], and holds at most
//! [`INBUF_MAX`] of a frame not yet whole.

use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use u6e_proto::frame::{decode_frame, write_frame};
use u6e_proto::msg::{AgentMsg, radio};

/// The helper's socket.
pub const SOCKET: &str = "/run/u6e-spectral/sock";
/// A scan's longest run; the controller may start another.
pub const LIMIT: Duration = Duration::from_secs(600);
pub const FRAMES_PER_S: u32 = 10;
/// The largest frame forwarded, its length prefix included.
pub const FRAME_MAX: usize = 600;
const INBUF_MAX: usize = 4 << 10;
/// Reads of one connection per call: a helper that sends without pause
/// cannot hold the link.
const READS_MAX: usize = 8;

/// The scans running on behalf of one session.
pub struct Spectrum {
    socket: PathBuf,
    limit: Duration,
    scans: Vec<Scan>,
}

struct Scan {
    radio: &'static str,
    sock: UnixStream,
    inbuf: Vec<u8>,
    started: Instant,
    /// The start of the second the frames are counted in, and its count.
    second: Instant,
    frames: u32,
}

/// Whether `msgs` say the scan is over.
fn ended(msgs: &[AgentMsg]) -> bool {
    msgs.iter()
        .any(|m| matches!(m, AgentMsg::SpectrumState { running: false, .. }))
}

fn state(radio: &str, running: bool, reason: impl Into<String>) -> AgentMsg {
    AgentMsg::SpectrumState {
        radio: radio.to_owned(),
        running,
        reason: reason.into(),
    }
}

impl Spectrum {
    pub fn new(socket: &Path, limit: Duration) -> Self {
        Spectrum {
            socket: socket.to_owned(),
            limit,
            scans: Vec::new(),
        }
    }

    /// Asks the helper to scan `name`. The helper's answer comes with
    /// [`Spectrum::read`]; what the agent can tell at once (a name that is no
    /// radio, a scan already running, no helper) is returned.
    pub fn start(&mut self, name: &str) -> Option<AgentMsg> {
        // A stable name, so the request line is one line.
        let Some(radio) = radio(name) else {
            return Some(state("", false, "refused: no such radio"));
        };
        if self.scans.iter().any(|s| s.radio == radio) {
            return Some(state(radio, true, "running"));
        }
        let ask = || {
            let mut sock = UnixStream::connect(&self.socket)?;
            sock.write_all(format!("start {radio}\n").as_bytes())?;
            sock.set_nonblocking(true)?;
            Ok::<_, std::io::Error>(sock)
        };
        match ask() {
            Ok(sock) => {
                let now = Instant::now();
                self.scans.push(Scan {
                    radio,
                    sock,
                    inbuf: Vec::new(),
                    started: now,
                    second: now,
                    frames: 0,
                });
                None
            }
            Err(e) => Some(state(radio, false, format!("no spectrum helper: {e}"))),
        }
    }

    /// Stops the scan of `name`: its connection goes, and with it the scan.
    pub fn stop(&mut self, name: &str) -> AgentMsg {
        let radio = radio(name).unwrap_or_default();
        match self.scans.iter().position(|s| s.radio == radio) {
            Some(i) => {
                self.scans.remove(i);
                state(radio, false, "stopped")
            }
            None => state(radio, false, "not running"),
        }
    }

    /// The helper's connections, for `poll`.
    pub fn fds(&self) -> impl Iterator<Item = RawFd> + '_ {
        self.scans.iter().map(|s| s.sock.as_raw_fd())
    }

    /// When the first scan reaches the limit.
    pub fn deadline(&self) -> Option<Instant> {
        self.scans.iter().map(|s| s.started + self.limit).min()
    }

    /// Appends to `out` what the helper sent for each scan, within the
    /// budget, and ends the scans that are over: past the limit, refused or
    /// ended by the helper, or whose helper sent what it may not.
    pub fn read(&mut self, out: &mut Vec<u8>) {
        let (now, limit) = (Instant::now(), self.limit);
        self.scans.retain_mut(|s| {
            let (msgs, ended) = s.take(now, limit);
            for m in &msgs {
                // Into a Vec: it cannot fail.
                let _ = write_frame(out, m);
            }
            !ended
        });
    }
}

impl Scan {
    /// What the helper sent since, as the messages to forward, and whether
    /// the scan is over.
    fn take(&mut self, now: Instant, limit: Duration) -> (Vec<AgentMsg>, bool) {
        let mut msgs = Vec::new();
        match self.receive(now, &mut msgs) {
            Err(why) => msgs.push(state(self.radio, false, why)),
            Ok(()) if !ended(&msgs) && now >= self.started + limit => {
                let why = format!("stopped after {} s, the limit", limit.as_secs());
                msgs.push(state(self.radio, false, why));
            }
            Ok(()) => {}
        }
        let over = ended(&msgs);
        (msgs, over)
    }

    /// Reads what the helper sent and moves its whole frames to `msgs`, as
    /// far as they may go, up to the helper's word that the scan ended; an
    /// error says why the scan is over.
    fn receive(&mut self, now: Instant, msgs: &mut Vec<AgentMsg>) -> Result<(), String> {
        let mut buf = [0; 2048];
        for _ in 0..READS_MAX {
            if ended(msgs) {
                break;
            }
            match self.sock.read(&mut buf) {
                Ok(0) => return Err("stopped: the spectrum helper ended the scan".into()),
                Ok(n) if self.inbuf.len() + n > INBUF_MAX => {
                    return Err("stopped: the spectrum helper sent no frame".into());
                }
                Ok(n) => self.inbuf.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(format!("stopped: the spectrum helper: {e}")),
            }
            self.cut(now, msgs)?;
        }
        Ok(())
    }

    fn cut(&mut self, now: Instant, msgs: &mut Vec<AgentMsg>) -> Result<(), String> {
        let mut used = 0;
        loop {
            let next = decode_frame::<AgentMsg>(&self.inbuf[used..])
                .map_err(|_| "stopped: the spectrum helper sent no frame".to_owned())?;
            let Some((msg, n)) = next else { break };
            used += n;
            match msg {
                AgentMsg::Spectrum(f) if f.radio == self.radio => {
                    if n <= FRAME_MAX && self.budget(now) {
                        msgs.push(AgentMsg::Spectrum(f));
                    }
                }
                // A request the helper refused names no radio: it is this
                // scan's.
                AgentMsg::SpectrumState {
                    radio,
                    running,
                    reason,
                } if radio == self.radio || radio.is_empty() => {
                    msgs.push(state(self.radio, running, reason));
                }
                _ => return Err("stopped: the spectrum helper sent another radio's".into()),
            }
        }
        self.inbuf.drain(..used);
        Ok(())
    }

    /// Whether one more frame fits this second's budget.
    fn budget(&mut self, now: Instant) -> bool {
        if now >= self.second + Duration::from_secs(1) {
            self.second = now;
            self.frames = 0;
        }
        self.frames += 1;
        self.frames <= FRAMES_PER_S
    }
}
