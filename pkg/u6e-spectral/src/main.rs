//! The AP's spectrum helper: it runs a radio's spectral scan for the agent,
//! which cannot (the scan's debugfs and relay files are root's), decodes the
//! samples into dBm per bin and hands the agent at most 10 frames a second
//! per radio. It does that and nothing else, as root without capabilities in
//! a sandbox that shows it only those files (see prep-rootfs.sh for the
//! units).
//!
//!   u6e-spectral serve
//!   u6e-spectral record <radio> <seconds>
//!   u6e-spectral disable-all
//!
//! `serve` serves the socket systemd listens on for it (the protocol is in
//! `serve.rs`) and ends after 10 s without a client. `record` scans one
//! radio for at most 10 s, writes the raw samples to stdout (the tests'
//! fixtures) and on stderr what they held and cost. `disable-all` stops every
//! radio's scan: the unit's last step, however the helper ended.

mod hold;
mod radio;
mod sample;
mod serve;
#[cfg(test)]
mod testdir;

use std::fs;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{env, mem, process, ptr};

use u6e_proto::frame::write_frame;
use u6e_proto::msg::AgentMsg;

/// The group whose members are served: the agent's.
const AGENT_GROUP: &str = "u6e-agent";
/// The longest `record`.
const RECORD_MAX: Duration = Duration::from_secs(10);
const IDLE: Duration = Duration::from_secs(10);

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args[..] {
        ["serve"] => serve(),
        ["record", radio, secs] => match (radio::radio(radio), secs.parse()) {
            (Some(r), Ok(s)) if (1..=RECORD_MAX.as_secs()).contains(&s) => {
                record(r, Duration::from_secs(s))
            }
            _ => usage(),
        },
        ["disable-all"] => radio::disable_all(Path::new(radio::DEBUGFS)),
        _ => usage(),
    };
    if let Err(e) = result {
        eprintln!("u6e-spectral: {e}");
        process::exit(1);
    }
}

fn usage() -> ! {
    eprintln!("usage: u6e-spectral serve | record <radio24|radio5|radio6> <1-10 s> | disable-all");
    process::exit(2);
}

fn serve() -> io::Result<()> {
    let stop = signals()?;
    let gid = group_id(&fs::read_to_string("/etc/group")?, AGENT_GROUP)
        .ok_or_else(|| io::Error::other(format!("no group {AGENT_GROUP}")))?;
    let cfg = serve::Config {
        root: radio::DEBUGFS.into(),
        gid,
        idle: IDLE,
    };
    serve::run(listener()?, &cfg, stop.as_raw_fd())
}

/// The one socket systemd passes (`LISTEN_FDS`, from fd 3).
fn listener() -> io::Result<UnixListener> {
    let ours = env::var("LISTEN_PID").ok() == Some(process::id().to_string());
    if !ours || env::var("LISTEN_FDS").ok().as_deref() != Some("1") {
        return Err(io::Error::other("not started by its socket unit"));
    }
    // SAFETY: systemd passed fd 3, a listening socket, to this process alone.
    Ok(unsafe { UnixListener::from_raw_fd(3) })
}

/// The id of group `name` in an /etc/group.
fn group_id(etc_group: &str, name: &str) -> Option<u32> {
    etc_group.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next() == Some(name)).then(|| f.nth(1)?.parse().ok())?
    })
}

/// A descriptor readable once SIGTERM, SIGINT or SIGHUP arrives; they no
/// longer end the process, so the scans are stopped on the way out.
fn signals() -> io::Result<OwnedFd> {
    // SAFETY: a zeroed sigset_t is valid for sigemptyset to initialise, and
    // the calls are given valid pointers.
    unsafe {
        let mut set: libc::sigset_t = mem::zeroed();
        libc::sigemptyset(&mut set);
        for s in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            libc::sigaddset(&mut set, s);
        }
        if libc::pthread_sigmask(libc::SIG_BLOCK, &set, ptr::null_mut()) != 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = libc::signalfd(-1, &set, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

/// Waits up to `wait` for `fd`; true when it became readable.
fn readable(fd: RawFd, wait: Duration) -> bool {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `p` is a valid pollfd for the call.
    unsafe { libc::poll(&mut p, 1, wait.as_millis() as i32) > 0 }
}

/// The CPU time this process has used, the kernel's on its behalf included.
fn cpu() -> Duration {
    // SAFETY: a zeroed rusage is a valid one for getrusage to fill.
    let mut u: libc::rusage = unsafe { mem::zeroed() };
    // SAFETY: `u` is a valid rusage for the call.
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut u) };
    let d = |t: libc::timeval| {
        Duration::from_secs(t.tv_sec as u64) + Duration::from_micros(t.tv_usec as u64)
    };
    d(u.ru_utime) + d(u.ru_stime)
}

/// Scans `radio` for `secs` as `serve` would, the raw samples to stdout.
fn record(radio: &'static str, secs: Duration) -> io::Result<()> {
    let stop = signals()?;
    let root = Path::new(radio::DEBUGFS);
    let mut scan = radio::Scan::start(root, radio)?;
    let (used, start) = (cpu(), Instant::now());
    let (mut decoder, mut hold) = (sample::Decoder::default(), hold::Hold::default());
    let mut out = io::stdout().lock();
    let (mut raw, mut frames, mut frame_max) = (0usize, 0u32, 0usize);
    let mut seen = Seen::default();
    let mut last = None;
    while start.elapsed() < secs && !readable(stop.as_raw_fd(), serve::PERIOD) {
        let mut put = |b: &[u8]| {
            raw += b.len();
            // A closed stdout ends nothing but the fixture.
            let _ = out.write_all(b);
        };
        decoder.read(&mut scan.relay, &mut put, &mut |s| {
            seen.add(s);
            hold.add(s);
        })?;
        let at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        if let Some(f) = hold.take(radio, at_ms) {
            let mut buf = Vec::new();
            write_frame(&mut buf, &AgentMsg::Spectrum(f.clone()))?;
            frames += 1;
            frame_max = frame_max.max(buf.len());
            last = Some(f);
        }
        scan.trigger()?;
    }
    let (used, wall) = (cpu() - used, start.elapsed());
    drop(scan);
    decoder.finish();
    eprintln!(
        "{radio}: {:.1} s, {} samples ({raw} B), skipped {:?}, {frames} frames (largest {frame_max} B framed); \
         {:.1} ms CPU ({:.2} % of a core); spectral_scan_ctl now reads {:?}",
        wall.as_secs_f64(),
        decoder.samples,
        decoder.skipped,
        used.as_secs_f64() * 1e3,
        100.0 * used.as_secs_f64() / wall.as_secs_f64(),
        radio::mode(&root.join(radio).join("ath11k"))?,
    );
    eprintln!("{seen:?}");
    if let Some(f) = last {
        let mut b = f.bins.clone();
        b.sort_unstable();
        eprintln!(
            "last frame: {} bins from {} MHz x10 by {} kHz, noise {} dBm, dBm min {} median {} max {}",
            f.bins.len(),
            f.first_mhz_x10,
            f.step_khz,
            f.noise_dbm,
            b[0],
            b[b.len() / 2],
            b[b.len() - 1],
        );
    }
    Ok(())
}

/// The ranges of a recording's header fields, to check its samples by.
#[derive(Debug, Default)]
struct Seen {
    widths: Vec<u16>,
    freq1: Vec<u16>,
    bins: Vec<usize>,
    rssi: Option<(i16, i16)>,
    noise: Option<(i32, i32)>,
    max_exp: u8,
}

impl Seen {
    fn add(&mut self, s: &sample::Sample) {
        fn put<T: PartialEq>(v: &mut Vec<T>, x: T) {
            if !v.contains(&x) {
                v.push(x);
            }
        }
        put(&mut self.widths, s.width_mhz);
        put(&mut self.freq1, s.freq1);
        put(&mut self.bins, s.bins.len());
        let span = |r: Option<(i32, i32)>, x: i32| r.map_or((x, x), |(a, b)| (a.min(x), b.max(x)));
        let rssi = span(self.rssi.map(|(a, b)| (a.into(), b.into())), s.rssi.into());
        self.rssi = Some((rssi.0 as i16, rssi.1 as i16));
        self.noise = Some(span(self.noise, s.noise));
        self.max_exp = self.max_exp.max(s.max_exp);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_group_is_found_by_name() {
        let etc = "root:x:0:\nu6e-agentx:x:5:\nu6e-agent:x:988:\n";
        assert_eq!(group_id(etc, "u6e-agent"), Some(988));
        assert_eq!(group_id(etc, "u6e"), None);
        assert_eq!(group_id("u6e-agent:x:\n", "u6e-agent"), None);
    }
}
