//! The AP's speed test to the controller, when a `SpeedTest` command asks
//! for one: a thread of its own dials the controller's agent listener again,
//! with the link's TLS client (the same pinned keys), opens the test with
//! `SpeedTestOpen` in place of a Hello, takes the controller's download,
//! sends its upload, and closes with its report (`u6e_proto::speedtest`).
//! The AP listens on nothing for it.
//!
//! One test at a time: the command is answered at once, started or refused.
//! Each direction is held to what `speedtest::bounds` allows whatever the
//! command asks, a download past them ends the test, and the whole of it
//! ends [`TEST_MAX`] after the command whatever the controller does (every
//! read and write of its socket is held to that one deadline, `deadline`),
//! so a
//! test costs at most a thread, a connection and two 64 KiB buffers for
//! that long. The AP's CPU is read from `/proc/stat` (all cores) and
//! `/proc/thread-self/stat` (the test's thread) around each direction.

use std::fs;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use u6e_proto::frame::{frame_body, write_frame};
use u6e_proto::msg::{AgentMsg, CommandResult, CpuUse, SpeedTestReport};
use u6e_proto::speedtest::{self, CHUNK, Chunks};
use u6e_proto::{PROTOCOL, version};

use crate::deadline::Deadline;

/// Where the CPU's counters are read.
pub const PROC: &str = "/proc";
/// The longest a whole test may take from its command: the handshake, both
/// directions at their longest ([`speedtest::SECS_MAX`] each) and some.
pub const TEST_MAX: Duration = Duration::from_secs(40);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How far past its time or size a download may run before it is cut off:
/// what the controller's socket held when its time was up.
const SLACK: Duration = Duration::from_secs(3);
/// The clock ticks of `/proc`'s CPU times (`USER_HZ`, fixed by the ABI).
const USER_HZ: u64 = 100;

/// What each direction of one test may take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
    pub secs: Duration,
    pub bytes: u64,
}

/// The tests the controller asks for, one at a time.
pub struct SpeedTests {
    controller: String,
    client: Arc<ClientConfig>,
    proc: PathBuf,
    running: Arc<AtomicBool>,
    /// How long a test may take from its command: [`TEST_MAX`].
    limit: Duration,
}

impl SpeedTests {
    /// Tests to `controller` (`host:port`, the link's) over `client`, the
    /// CPU read under `proc`.
    pub fn new(controller: String, client: Arc<ClientConfig>, proc: PathBuf) -> Self {
        SpeedTests {
            controller,
            client,
            proc,
            running: Arc::new(AtomicBool::new(false)),
            limit: TEST_MAX,
        }
    }

    /// Starts test `id` for `secs` and `max_bytes` each way, within the
    /// bounds; the command's answer.
    pub fn start(&self, id: u64, secs: u8, max_bytes: u64) -> CommandResult {
        let (secs, bytes) = speedtest::bounds(secs, max_bytes);
        let plan = Plan { secs, bytes };
        let answer = |ok, detail: String| CommandResult { id, ok, detail };
        if self.running.swap(true, Ordering::AcqRel) {
            return answer(false, "a speed test runs already".into());
        }
        let (controller, client, proc) = (
            self.controller.clone(),
            Arc::clone(&self.client),
            self.proc.clone(),
        );
        let running = Arc::clone(&self.running);
        let deadline = Instant::now() + self.limit;
        let spawned = thread::Builder::new()
            .name("speedtest".into())
            .spawn(move || {
                let r = run(&controller, client, &proc, id, plan, deadline);
                running.store(false, Ordering::Release);
                match r {
                    Ok(report) => eprintln!(
                        "u6e-agent: speed test {id}: download {:.0} Mbit/s",
                        speedtest::bits_per_second(report.down_bytes, report.down_us) / 1e6
                    ),
                    Err(e) => eprintln!("u6e-agent: speed test {id}: {e}"),
                }
            });
        match spawned {
            Ok(_) => answer(
                true,
                format!(
                    "started: {} s and {} MiB each way at most",
                    plan.secs.as_secs(),
                    plan.bytes >> 20
                ),
            ),
            Err(e) => {
                self.running.store(false, Ordering::Release);
                answer(false, format!("cannot start: {e}"))
            }
        }
    }
}

type Tls<'a> = StreamOwned<ClientConnection, Deadline<'a>>;

/// One test, from the dial to the report sent; the report.
fn run(
    controller: &str,
    client: Arc<ClientConfig>,
    proc: &Path,
    id: u64,
    plan: Plan,
    deadline: Instant,
) -> io::Result<SpeedTestReport> {
    let sock = dial(controller, deadline)?;
    // The verifier pins the key; the name only has to be well formed.
    let host = controller.rsplit_once(':').map_or(controller, |(h, _)| h);
    let name = ServerName::try_from(host.trim_matches(['[', ']']).to_owned())
        .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?;
    let conn = ClientConnection::new(client, name).map_err(io::Error::other)?;
    let mut tls = StreamOwned::new(conn, Deadline::new(&sock, deadline));
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    let mut open = version::frame(PROTOCOL).to_vec();
    write_frame(&mut open, &AgentMsg::SpeedTestOpen { id })?;
    tls.write_all(&open)?;
    tls.flush()?;
    let mut buf = vec![0; CHUNK];
    let early = versions(&mut tls, &mut buf)?;
    let (down_bytes, down_us, cpu_down) = download(&mut tls, &mut buf, early, proc, plan)?;
    let cpu_up = upload(&mut tls, &mut buf, proc, plan)?;
    let report = SpeedTestReport {
        id,
        down_bytes,
        down_us,
        cpu_down,
        cpu_up,
    };
    write_frame(&mut tls, &AgentMsg::SpeedTestReport(report.clone()))?;
    tls.conn.send_close_notify();
    tls.flush()?;
    Ok(report)
}

/// The TCP connection to the first of `controller`'s addresses that
/// answers by `deadline`.
fn dial(controller: &str, deadline: Instant) -> io::Result<TcpStream> {
    let mut err = io::Error::new(ErrorKind::NotFound, "no address");
    for addr in controller.to_socket_addrs()? {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(ErrorKind::TimedOut, "past the test's time"));
        }
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT.min(left)) {
            Ok(s) => return Ok(s),
            Err(e) => err = e,
        }
    }
    Err(err)
}

/// Reads into `buf`; an error when the controller closed.
fn read(tls: &mut Tls, buf: &mut [u8], what: &str) -> io::Result<usize> {
    match tls.read(buf)? {
        0 => Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            format!("the controller closed during {what}"),
        )),
        n => Ok(n),
    }
}

/// Reads the controller's version frame; the bytes that came after it.
fn versions(tls: &mut Tls, buf: &mut [u8]) -> io::Result<Vec<u8>> {
    let mut got = Vec::new();
    loop {
        if let Some((body, n)) = frame_body(&got)? {
            let theirs = version::decode(body);
            if theirs != PROTOCOL {
                let e = format!("the controller speaks protocol {theirs}, this agent {PROTOCOL}");
                return Err(io::Error::new(ErrorKind::InvalidData, e));
            }
            return Ok(got.split_off(n));
        }
        // A version frame is 10 bytes: more is the download's.
        let n = read(tls, buf, "the version frames")?;
        got.extend_from_slice(&buf[..n]);
    }
}

/// Takes the download, `early` its first bytes if they came with the
/// version frame; its bytes, its time from the first byte to its end, and
/// the CPU over it.
fn download(
    tls: &mut Tls,
    buf: &mut [u8],
    early: Vec<u8>,
    proc: &Path,
    plan: Plan,
) -> io::Result<(u64, u64, CpuUse)> {
    let mut down = Download {
        chunks: Chunks::default(),
        first: None,
        plan,
    };
    down.take(&early, proc)?;
    while !down.chunks.ended() {
        let n = read(tls, buf, "the download")?;
        down.take(&buf[..n], proc)?;
    }
    let (t0, cpu0) = down.first.expect("bytes came before the end");
    let us = t0.elapsed().as_micros() as u64;
    Ok((down.chunks.bytes(), us, cpu0.until(&Cpu::read(proc), us)))
}

/// A download as it comes: its chunks, when its first byte came with the
/// CPU then, and the bounds it must keep.
struct Download {
    chunks: Chunks,
    first: Option<(Instant, Cpu)>,
    plan: Plan,
}

impl Download {
    fn take(&mut self, bytes: &[u8], proc: &Path) -> io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let (t0, _) = *self
            .first
            .get_or_insert_with(|| (Instant::now(), Cpu::read(proc)));
        let used = self.chunks.take(bytes).map_err(invalid)?;
        if used < bytes.len() {
            return Err(invalid("the controller sent past the download's end"));
        }
        let plan = self.plan;
        if self.chunks.bytes() > plan.bytes.saturating_add(CHUNK as u64)
            || t0.elapsed() > plan.secs + SLACK
        {
            return Err(invalid("the controller sent past the test's bounds"));
        }
        Ok(())
    }
}

/// Sends the upload: chunks for the plan's time or bytes, then the end;
/// the CPU over it.
fn upload(tls: &mut Tls, buf: &mut [u8], proc: &Path, plan: Plan) -> io::Result<CpuUse> {
    buf.fill(0);
    let (t0, cpu0) = (Instant::now(), Cpu::read(proc));
    let mut sent = 0u64;
    while t0.elapsed() < plan.secs && sent < plan.bytes {
        let len = (plan.bytes - sent).min(CHUNK as u64) as usize;
        tls.write_all(&speedtest::header(len))?;
        tls.write_all(&buf[..len])?;
        sent += len as u64;
    }
    tls.write_all(&speedtest::header(0))?;
    tls.flush()?;
    let us = t0.elapsed().as_micros() as u64;
    Ok(cpu0.until(&Cpu::read(proc), us))
}

fn invalid(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, e)
}

/// The CPU time counters at one moment, in clock ticks: the AP's busy and
/// total over all cores, and the calling thread's; `None` for one that could
/// not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cpu {
    all: Option<(u64, u64)>,
    thread: Option<u64>,
}

impl Cpu {
    fn read(proc: &Path) -> Cpu {
        let text = |p: &str| fs::read_to_string(proc.join(p)).ok();
        Cpu {
            all: text("stat").as_deref().and_then(all_cores),
            thread: text("thread-self/stat").as_deref().and_then(thread_ticks),
        }
    }

    /// The use from this reading to `later`, `us` microseconds after.
    fn until(&self, later: &Cpu, us: u64) -> CpuUse {
        let permille = |part: u64, whole: u64| {
            u16::try_from(part.saturating_mul(1000) / whole.max(1)).unwrap_or(u16::MAX)
        };
        let busy = match (self.all, later.all) {
            (Some((b0, t0)), Some((b1, t1))) if t1 > t0 => {
                permille(b1.saturating_sub(b0), t1 - t0).min(1000)
            }
            _ => 0,
        };
        // A tick is 10 ms: ticks × 10 000 µs over the time, in thousandths.
        let thread = match (self.thread, later.thread) {
            (Some(a), Some(b)) => permille(b.saturating_sub(a) * (1_000_000 / USER_HZ), us),
            _ => 0,
        };
        CpuUse {
            busy_permille: busy,
            thread_permille: thread,
        }
    }
}

/// The busy ticks (all but idle and waiting for I/O) and the total of
/// `/proc/stat`'s `cpu` line: user, nice, system, idle, iowait, irq,
/// softirq, steal (guest time is counted in user already).
fn all_cores(stat: &str) -> Option<(u64, u64)> {
    let line = stat.lines().find(|l| l.starts_with("cpu "))?;
    let v: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .take(8)
        .map(|f| f.parse().ok())
        .collect::<Option<_>>()?;
    if v.len() < 5 {
        return None;
    }
    let total = v.iter().try_fold(0u64, |a, &x| a.checked_add(x))?;
    Some((total - v[3] - v[4], total))
}

/// A thread's user and system ticks: the 14th and 15th fields of its
/// `stat`, counted after its name, which may hold anything but ends at the
/// last `)`.
fn thread_ticks(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    let mut f = rest.split_whitespace().skip(11);
    let utime: u64 = f.next()?.parse().ok()?;
    let stime: u64 = f.next()?.parse().ok()?;
    utime.checked_add(stime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::TcpListener;
    use std::sync::RwLock;

    use rustls::{ServerConfig, ServerConnection};
    use u6e_proto::frame::decode_frame;
    use u6e_proto::tls::{self, Identity};

    use crate::testdir::TestDir;

    // Throwaway Ed25519 keys made for tests (u6e-proto's tls tests'); they
    // protect nothing.
    const KEY_AGENT: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINI3m11iy47fpTD0dKK5Q2ViMRZef+/6f8mIN8n95xZz\n-----END PRIVATE KEY-----\n";
    const KEY_CTL: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIIoSUDjXsAjqhope0CKaS38rhfHRd7Zp7+uYiC/ncyO7\n-----END PRIVATE KEY-----\n";

    const WAIT: Duration = Duration::from_secs(20);

    fn client() -> Arc<ClientConfig> {
        let me = Identity::from_pem(KEY_AGENT).unwrap();
        let ctl = Identity::from_pem(KEY_CTL).unwrap();
        tls::client_config(&me, ctl.public_key())
    }

    fn server() -> Arc<ServerConfig> {
        let me = Identity::from_pem(KEY_AGENT).unwrap();
        let ctl = Identity::from_pem(KEY_CTL).unwrap();
        let allowed = HashMap::from([(me.public_key(), "ap1".to_owned())]);
        tls::server_config(&ctl, Arc::new(RwLock::new(allowed)))
    }

    type Peer = StreamOwned<ServerConnection, TcpStream>;

    /// A controller's end of one test connection: accepted, its TLS done.
    fn accept(listener: &TcpListener) -> Peer {
        let (sock, _) = listener.accept().unwrap();
        sock.set_read_timeout(Some(WAIT)).unwrap();
        let mut p = StreamOwned::new(ServerConnection::new(server()).unwrap(), sock);
        while p.conn.is_handshaking() {
            p.conn.complete_io(&mut p.sock).unwrap();
        }
        p
    }

    /// Reads what `take` makes of the bytes once it makes something.
    fn next<T>(p: &mut Peer, got: &mut Vec<u8>, take: impl Fn(&[u8]) -> Option<(T, usize)>) -> T {
        let mut chunk = [0; 4096];
        loop {
            if let Some((v, n)) = take(got) {
                got.drain(..n);
                return v;
            }
            let n = p.read(&mut chunk).unwrap();
            assert!(n > 0, "the agent closed");
            got.extend_from_slice(&chunk[..n]);
        }
    }

    /// The agent's version frame and open, after sending ours.
    fn opened(p: &mut Peer, got: &mut Vec<u8>) -> u64 {
        p.write_all(&version::frame(PROTOCOL)).unwrap();
        p.flush().unwrap();
        let v = next(p, got, |b| {
            frame_body(b).unwrap().map(|(b, n)| (version::decode(b), n))
        });
        assert_eq!(v, PROTOCOL);
        match next(p, got, |b| decode_frame::<AgentMsg>(b).unwrap()) {
            AgentMsg::SpeedTestOpen { id } => id,
            m => panic!("{m:?} for an open"),
        }
    }

    fn send_chunks(p: &mut Peer, lens: &[usize]) {
        let zeros = vec![0; CHUNK];
        for &len in lens {
            p.write_all(&speedtest::header(len)).unwrap();
            p.write_all(&zeros[..len]).unwrap();
        }
        p.flush().unwrap();
    }

    /// Reads the agent's upload to its end; its filler bytes.
    fn take_upload(p: &mut Peer, got: &mut Vec<u8>) -> u64 {
        let mut up = Chunks::default();
        let used = up.take(got).unwrap();
        got.drain(..used);
        let mut chunk = vec![0; CHUNK];
        while !up.ended() {
            let n = p.read(&mut chunk).unwrap();
            assert!(n > 0, "the agent closed during its upload");
            let used = up.take(&chunk[..n]).unwrap();
            got.extend_from_slice(&chunk[used..n]);
        }
        up.bytes()
    }

    fn listen() -> (TcpListener, String) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        (l, addr)
    }

    fn plan(ms: u64, bytes: u64) -> Plan {
        Plan {
            secs: Duration::from_millis(ms),
            bytes,
        }
    }

    #[test]
    fn both_directions_are_measured_and_reported() {
        let (l, addr) = listen();
        let ctl = thread::spawn(move || {
            let mut p = accept(&l);
            let mut got = Vec::new();
            let id = opened(&mut p, &mut got);
            send_chunks(&mut p, &[CHUNK, CHUNK, 100, 0]);
            let up = take_upload(&mut p, &mut got);
            let report = next(&mut p, &mut got, |b| decode_frame::<AgentMsg>(b).unwrap());
            (id, up, report)
        });
        let deadline = Instant::now() + WAIT;
        let r = run(
            &addr,
            client(),
            Path::new("/proc"),
            7,
            plan(60_000, 3 * CHUNK as u64 + 5),
            deadline,
        )
        .unwrap();
        let (id, up, report) = ctl.join().unwrap();
        assert_eq!(id, 7);
        // The plan's bytes, a short last chunk included, well within its time.
        assert_eq!(up, 3 * CHUNK as u64 + 5);
        assert_eq!(r.down_bytes, 2 * CHUNK as u64 + 100);
        assert!(r.down_us > 0 && r.down_us < WAIT.as_micros() as u64);
        assert_eq!(report, AgentMsg::SpeedTestReport(r.clone()));
        assert!(r.cpu_up.busy_permille <= 1000);
    }

    #[test]
    fn the_upload_ends_at_its_time() {
        let (l, addr) = listen();
        let ctl = thread::spawn(move || {
            let mut p = accept(&l);
            let mut got = Vec::new();
            opened(&mut p, &mut got);
            send_chunks(&mut p, &[0]);
            let at = Instant::now();
            let up = take_upload(&mut p, &mut got);
            let took = at.elapsed();
            next(&mut p, &mut got, |b| decode_frame::<AgentMsg>(b).unwrap());
            (up, took)
        });
        let deadline = Instant::now() + WAIT;
        run(
            &addr,
            client(),
            Path::new("/proc"),
            1,
            plan(300, u64::MAX),
            deadline,
        )
        .unwrap();
        let (up, took) = ctl.join().unwrap();
        assert!(up > 0);
        assert!(
            took >= Duration::from_millis(300) && took < Duration::from_secs(5),
            "{took:?}"
        );
    }

    #[test]
    fn a_download_past_its_bounds_ends_the_test() {
        let (l, addr) = listen();
        let ctl = thread::spawn(move || {
            let mut p = accept(&l);
            let mut got = Vec::new();
            opened(&mut p, &mut got);
            // Three chunks where the plan takes one: never ended.
            let zeros = vec![0; CHUNK];
            for _ in 0..3 {
                if p.write_all(&speedtest::header(CHUNK)).is_err() || p.write_all(&zeros).is_err() {
                    break;
                }
            }
            let _ = p.flush();
            thread::sleep(Duration::from_millis(200));
        });
        let deadline = Instant::now() + WAIT;
        let e = run(
            &addr,
            client(),
            Path::new("/proc"),
            1,
            plan(60_000, 1),
            deadline,
        )
        .unwrap_err();
        assert!(e.to_string().contains("past the test's bounds"), "{e}");
        ctl.join().unwrap();
    }

    #[test]
    fn a_stalled_controller_is_left_at_the_deadline() {
        let (l, addr) = listen();
        let ctl = thread::spawn(move || {
            let mut p = accept(&l);
            let mut got = Vec::new();
            opened(&mut p, &mut got);
            // The download never comes.
            thread::sleep(Duration::from_millis(1500));
        });
        let start = Instant::now();
        let deadline = start + Duration::from_millis(700);
        let e = run(
            &addr,
            client(),
            Path::new("/proc"),
            1,
            plan(60_000, 1 << 20),
            deadline,
        )
        .unwrap_err();
        assert!(
            matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
            "{e}"
        );
        assert!(
            start.elapsed() < Duration::from_millis(1400),
            "{:?}",
            start.elapsed()
        );
        ctl.join().unwrap();
    }

    #[test]
    fn a_controller_that_closes_early_ends_the_test_with_why() {
        let (l, addr) = listen();
        let ctl = thread::spawn(move || {
            let mut p = accept(&l);
            let mut got = Vec::new();
            opened(&mut p, &mut got);
            send_chunks(&mut p, &[CHUNK]);
            p.conn.send_close_notify();
            p.flush().unwrap();
        });
        let deadline = Instant::now() + WAIT;
        let e = run(
            &addr,
            client(),
            Path::new("/proc"),
            1,
            plan(60_000, 1 << 20),
            deadline,
        )
        .unwrap_err();
        assert!(e.to_string().contains("closed during the download"), "{e}");
        ctl.join().unwrap();
    }

    #[test]
    fn a_controller_of_another_protocol_is_not_tested_against() {
        let (l, addr) = listen();
        let ctl = thread::spawn(move || {
            let mut p = accept(&l);
            p.write_all(&version::frame(PROTOCOL + 1)).unwrap();
            p.flush().unwrap();
            thread::sleep(Duration::from_millis(200));
        });
        let deadline = Instant::now() + WAIT;
        let e = run(
            &addr,
            client(),
            Path::new("/proc"),
            1,
            plan(1000, 1),
            deadline,
        )
        .unwrap_err();
        assert!(e.to_string().contains("speaks protocol"), "{e}");
        ctl.join().unwrap();
    }

    /// A controller that answers with its version frame a byte every
    /// 300 ms, each byte its own TCP segment: every read is short, and the
    /// test ends at its deadline all the same.
    fn trickler(l: TcpListener) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut p = accept(&l);
            let mut got = Vec::new();
            let v = next(&mut p, &mut got, |b| {
                frame_body(b).unwrap().map(|(b, n)| (version::decode(b), n))
            });
            assert_eq!(v, PROTOCOL);
            p.conn
                .writer()
                .write_all(&version::frame(PROTOCOL))
                .unwrap();
            let mut record = Vec::new();
            while p.conn.wants_write() {
                p.conn.write_tls(&mut record).unwrap();
            }
            p.sock.set_nodelay(true).unwrap();
            for b in record {
                if p.sock.write_all(&[b]).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(300));
            }
        })
    }

    #[test]
    fn a_trickling_controller_is_left_at_the_deadline() {
        let (l, addr) = listen();
        let ctl = trickler(l);
        let start = Instant::now();
        let deadline = start + Duration::from_millis(700);
        let e = run(
            &addr,
            client(),
            Path::new("/proc"),
            1,
            plan(60_000, 1 << 20),
            deadline,
        )
        .unwrap_err();
        assert!(
            matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
            "{e}"
        );
        let took = start.elapsed();
        assert!(took < Duration::from_millis(1200), "{took:?}");
        ctl.join().unwrap();
    }

    /// A test is given [`TEST_MAX`] from its command, which holds both
    /// directions at their longest and little more, and is held to it.
    #[test]
    fn a_test_ends_at_its_limit_from_the_command() {
        let (l, addr) = listen();
        let mut tests = SpeedTests::new(addr, client(), "/proc".into());
        assert_eq!(tests.limit, TEST_MAX);
        let both = Duration::from_secs(2 * u64::from(speedtest::SECS_MAX));
        assert!(TEST_MAX >= both && TEST_MAX <= both + Duration::from_secs(20));
        tests.limit = Duration::from_millis(700);
        let ctl = trickler(l);
        let start = Instant::now();
        assert!(tests.start(1, 10, 1 << 20).ok);
        while tests.running.load(Ordering::Acquire) {
            assert!(
                start.elapsed() < Duration::from_millis(1200),
                "past its limit"
            );
            thread::sleep(Duration::from_millis(10));
        }
        ctl.join().unwrap();
    }

    #[test]
    fn one_test_at_a_time() {
        let (l, addr) = listen();
        let tests = SpeedTests::new(addr, client(), "/proc".into());
        let first = tests.start(1, 1, 1);
        assert!(first.ok, "{}", first.detail);
        assert_eq!(first.detail, "started: 1 s and 0 MiB each way at most");
        let second = tests.start(2, 1, 1);
        assert_eq!((second.id, second.ok), (2, false));
        assert_eq!(second.detail, "a speed test runs already");
        // The first ends (its controller goes away) and the next may start.
        drop(accept(&l));
        let start = Instant::now();
        while tests.running.load(Ordering::Acquire) {
            assert!(start.elapsed() < WAIT, "the first test never ended");
            thread::sleep(Duration::from_millis(10));
        }
        assert!(tests.start(3, 1, 1).ok);
    }

    #[test]
    fn cpu_counters_are_read_from_proc() {
        let d = TestDir::new();
        fs::create_dir(d.path().join("thread-self")).unwrap();
        let write = |p: &str, s: &str| fs::write(d.path().join(p), s).unwrap();
        write(
            "stat",
            "cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 1 2 3 4 5 6 7 8\n",
        );
        write(
            "thread-self/stat",
            "42 (speed) test) S 1 1 1 0 -1 0 0 0 0 0 20 5 0 0 20 0 1 0\n",
        );
        let a = Cpu::read(d.path());
        assert_eq!(
            a,
            Cpu {
                all: Some((150, 1000)),
                thread: Some(25)
            }
        );
        write("stat", "cpu  400 0 150 1300 150 0 0 0 0 0\n");
        write(
            "thread-self/stat",
            "42 (speed) test) S 1 1 1 0 -1 0 0 0 0 0 220 5 0 0 20 0 1 0\n",
        );
        // Of 1000 more ticks 400 busy; the thread 200 ticks (2 s) in 4 s.
        let u = a.until(&Cpu::read(d.path()), 4_000_000);
        assert_eq!(
            u,
            CpuUse {
                busy_permille: 400,
                thread_permille: 500
            }
        );
    }

    #[test]
    fn unreadable_or_hostile_cpu_counters_count_as_none() {
        for stat in [
            "",
            "cpu",
            "cpu 1 2",
            "cpu x 1 2 3 4",
            "cpu 18446744073709551615 1 0 0 0",
        ] {
            assert_eq!(all_cores(stat), None, "{stat:?}");
        }
        for stat in ["", "1 (x", "1 (x) S 1", "1 (x) S 1 1 1 0 -1 0 0 0 0 0 y 1"] {
            assert_eq!(thread_ticks(stat), None, "{stat:?}");
        }
        let none = Cpu {
            all: None,
            thread: None,
        };
        assert_eq!(none.until(&none, 1), CpuUse::default());
        // A counter that went back, or no time, is no use, not a wrap.
        let a = Cpu {
            all: Some((10, 100)),
            thread: Some(10),
        };
        let b = Cpu {
            all: Some((5, 90)),
            thread: Some(5),
        };
        assert_eq!(a.until(&b, 0), CpuUse::default());
    }
}
