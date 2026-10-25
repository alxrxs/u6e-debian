//! The AP's resident agent: the neighbor report exchange between APs, the
//! management network check and the state line for the syslog collector. One
//! process, which starts no other; it runs as its own user, with no
//! capabilities (see prep-rootfs.sh for the unit).
//!
//!   u6e-agent --listen <address> --port <port> --gateway <address> [--arm]
//!             [--peer <address>]...
//!             [--controller <host:port> --key <path> --controller-key <hex>
//!              [--runner-key <hex>]]
//!   u6e-agent --print-snapshot
//!   u6e-agent --print-flows [--full]
//!   u6e-agent --config-helper [--runner-key <hex>]
//!   u6e-agent --publish-config-hash
//!
//! With the three controller options it also streams telemetry to the
//! controller, carries out its commands and forwards the spectrum scans it
//! asks for, which u6e-spectral runs; with the deploy runner's public key
//! too, it applies the Wi-Fi configurations the runner signs and the
//! controller relays (see `link`, `command`, `spectrum` and `apply`).
//! `--print-flows` prints the flows the link would send now, and what
//! reading them cost. `--config-helper` is the root helper that classifies
//! and installs those configurations for the agent, one request on the
//! connection systemd passes it as stdin (see `helper`), and
//! `--publish-config-hash` publishes the hash of the installed one, as the
//! helper does after each install, for u6e-wifi to run at boot.

mod apply;
mod clientsock;
mod collect;
mod command;
mod ecm;
mod events;
mod helper;
mod kmsg;
mod link;
mod neighbors;
mod netcheck;
mod nl80211;
mod passed;
mod rates;
mod regdomain;
mod spectrum;
mod stats;
#[cfg(test)]
mod testdir;
mod wificonf;

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use std::{env, mem, process, thread};

use u6e_proto::frame::write_frame;
use u6e_proto::mac;
use u6e_proto::msg::AgentMsg;
use u6e_proto::tls::Identity;

/// The state line: first 2 minutes after start, then every 5.
const STATS_FIRST: Duration = Duration::from_secs(120);
const STATS_EVERY: Duration = Duration::from_secs(300);

/// Where and as whom the telemetry link connects, and whose configurations
/// it applies.
struct LinkArgs {
    controller: String,
    key: String,
    controller_key: [u8; 32],
    runner_key: Option<[u8; 32]>,
}

struct Args {
    listen: IpAddr,
    port: u16,
    gateway: Ipv4Addr,
    arm: bool,
    peers: Vec<IpAddr>,
    link: Option<LinkArgs>,
}

fn args() -> Option<Args> {
    let (mut listen, mut port, mut gateway, mut arm, mut peers) =
        (None, None, None, false, Vec::new());
    let (mut controller, mut key, mut controller_key) = (None, None, None);
    let mut runner_key = None;
    let mut a = env::args().skip(1);
    while let Some(k) = a.next() {
        match k.as_str() {
            "--listen" => listen = Some(a.next()?.parse().ok()?),
            "--port" => port = Some(a.next()?.parse().ok()?),
            "--gateway" => gateway = Some(a.next()?.parse().ok()?),
            "--arm" => arm = true,
            "--peer" => peers.push(a.next()?.parse().ok()?),
            "--controller" => controller = Some(a.next()?),
            "--key" => key = Some(a.next()?),
            "--controller-key" => controller_key = Some(mac::unhex(&a.next()?)?),
            "--runner-key" => runner_key = Some(mac::unhex(&a.next()?)?),
            _ => return None,
        }
    }
    let link = match (controller, key, controller_key) {
        (Some(controller), Some(key), Some(controller_key)) => Some(LinkArgs {
            controller,
            key,
            controller_key,
            runner_key,
        }),
        (None, None, None) if runner_key.is_none() => None,
        _ => return None,
    };
    Some(Args {
        listen: listen?,
        port: port?,
        gateway: gateway?,
        arm,
        peers,
        link,
    })
}

/// Starts the telemetry link and the events thread that feeds it. The
/// agent's other duties do not depend on either, so a failure here is
/// logged and they carry on. Commands steer to `targets` and hold their
/// blocks in `blocks`.
fn start_link(
    l: LinkArgs,
    collector: &Arc<Mutex<collect::Collector>>,
    targets: &Arc<Mutex<Vec<neighbors::Target>>>,
    blocks: &Arc<command::Blocks>,
) {
    let identity = fs::read_to_string(&l.key)
        .map_err(|e| e.to_string())
        .and_then(|pem| Identity::from_pem(&pem).map_err(|e| e.to_string()));
    let identity = match identity {
        Ok(i) => i,
        Err(e) => {
            eprintln!("u6e-agent: {}: {e}; no link to the controller", l.key);
            return;
        }
    };
    let (run, ctrl) = (clientsock::run_dir(), Path::new(neighbors::HOSTAPD));
    let commands = command::Commands::open(&run, ctrl, Arc::clone(targets), Arc::clone(blocks));
    let hello = link::local_hello();
    let worker = neighbors::Hostapd::bind(&run, "apply", ctrl).and_then(|h| {
        let mut a = apply::Apply::new(
            h,
            helper::Client::new(),
            Box::new(apply::NlPhy::default()),
            Arc::clone(targets),
            l.runner_key,
            hello.ap.clone(),
            hello.built_ms(),
        );
        apply::Worker::new(move |c, last: Option<&_>| a.run(c, last))
    });
    let (mut commands, worker) = match (commands, worker) {
        (Ok(c), Ok(w)) => (c, w),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!(
                "u6e-agent: hostapd control socket for commands: {e}; no link to the controller"
            );
            return;
        }
    };
    let (tx, rx) = sync_channel(256);
    if let Err(e) = events::Events::spawn(tx) {
        eprintln!("u6e-agent: events: {e}; the link carries snapshots only");
    }
    let cfg = link::Config::new(l.controller, identity, l.controller_key, hello);
    let (collector, flows) = (Arc::clone(collector), Arc::clone(collector));
    spawn_or_log("link", move || {
        link::run(
            cfg,
            move |seq| lock(&collector).snapshot(seq),
            move |seq, stations, full| lock(&flows).flows(seq, stations, full),
            move |c, last| commands.run(c, last),
            worker,
            rx,
        )
    });
}

/// The root helper: one request on the connection systemd passes as stdin,
/// answered there, from a member of the agent's group only. It takes
/// configurations the runner of `--runner-key` signed for this AP alone.
fn config_helper() -> ! {
    let runner = match env::args().skip(2).collect::<Vec<_>>().as_slice() {
        [] => None,
        [k, hex] if k == "--runner-key" => mac::unhex(hex).map(Some).unwrap_or_else(|| {
            eprintln!("u6e-agent: --runner-key: not 64 hex digits");
            process::exit(2);
        }),
        _ => {
            eprintln!("usage: u6e-agent --config-helper [--runner-key <hex>]");
            process::exit(2);
        }
    };
    let gid = fs::read_to_string("/etc/group")
        .ok()
        .and_then(|g| group_id(&g, "u6e-agent"));
    let Some(gid) = gid else {
        eprintln!("u6e-agent: no group u6e-agent");
        process::exit(1);
    };
    // SAFETY: systemd passes the accepted connection as stdin, which nothing
    // else here uses.
    let mut conn = unsafe { UnixStream::from_raw_fd(0) };
    if !helper::peer_allowed(&conn, gid) {
        eprintln!("u6e-agent: config helper: a peer outside the agent's group");
        process::exit(1);
    }
    let hello = link::local_hello();
    let floor = hello.built_ms();
    let server = helper::Server::new(runner, hello.ap, floor);
    if let Err(e) = server.serve(&mut conn) {
        eprintln!("u6e-agent: config helper: {e}");
        process::exit(1);
    }
    process::exit(0);
}

/// The id of group `name` in an /etc/group.
fn group_id(etc_group: &str, name: &str) -> Option<u32> {
    etc_group.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next() == Some(name)).then(|| f.nth(1)?.parse().ok())?
    })
}

/// Starts a thread for a duty the 802.11k exchange and the network check do
/// not depend on; if it cannot start (no threads left), that is logged and
/// they carry on.
fn spawn_or_log(name: &str, f: impl FnOnce() + Send + 'static) {
    if let Err(e) = thread::Builder::new().name(name.into()).spawn(f) {
        eprintln!("u6e-agent: {name}: {e}; carrying on without it");
    }
}

/// The CPU time this process has used, the kernel's on its behalf included
/// (the kernel splits the two by sampling, so only their sum is exact).
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

/// Prints the flows of this AP's stations as the link would send them, and
/// on stderr what the read of ECM's table cost.
fn print_flows(nss_load: Option<fs::File>, full: bool) {
    let mut c = collect::Collector::new(nss_load);
    let stations: Vec<_> = c.snapshot(0).stations.iter().map(|s| s.mac).collect();
    drop(c);
    let (used, start) = (cpu(), Instant::now());
    let table = ecm::read(&Path::new("/").join(ecm::DEVICE), ecm::CAP).unwrap_or_else(|e| {
        eprintln!("u6e-agent: ECM connection table: {e}");
        process::exit(1);
    });
    let flows = table.flows(1, &stations, full);
    let (used, wall) = (cpu() - used, start.elapsed());
    let mut frame = Vec::new();
    // Into a Vec: it cannot fail.
    let _ = write_frame(&mut frame, &AgentMsg::Flows(flows.clone()));
    println!("{flows:#?}");
    eprintln!(
        "{} connections (complete: {}, {} without slow path counts), {} of {} stations with some: {:.1} ms CPU, {:.1} ms wall, {} B framed",
        table.conns.len(),
        table.complete,
        table.without_slow_path,
        flows.clients.len(),
        stations.len(),
        used.as_secs_f64() * 1e3,
        wall.as_secs_f64() * 1e3,
        frame.len(),
    );
}

fn main() {
    if env::args().nth(1).as_deref() == Some("--config-helper") {
        config_helper();
    }
    if env::args().nth(1).as_deref() == Some("--publish-config-hash") {
        helper::Server::new(None, String::new(), 0).publish();
        return;
    }
    let nss_load = passed::take(collect::NSS_LOAD_NAME);
    if env::args().nth(1).as_deref() == Some("--print-flows") {
        print_flows(nss_load, env::args().nth(2).as_deref() == Some("--full"));
        return;
    }
    if env::args().nth(1).as_deref() == Some("--print-snapshot") {
        let mut c = collect::Collector::new(nss_load);
        println!("{:#?}", c.snapshot(0));
        let ok = c.has_nl80211();
        // Its client sockets go with it; exit would skip that.
        drop(c);
        if !ok {
            process::exit(1);
        }
        return;
    }
    let Some(a) = args() else {
        eprintln!(
            "usage: u6e-agent --listen <address> --port <port> --gateway <address> [--arm] [--peer <address>]... [--controller <host:port> --key <path> --controller-key <hex> [--runner-key <hex>]]"
        );
        process::exit(2);
    };
    let mut h = neighbors::Hostapd::open().unwrap_or_else(|e| {
        eprintln!("u6e-agent: hostapd control socket: {e}");
        process::exit(1);
    });
    let collector = Arc::new(Mutex::new(collect::Collector::new(nss_load)));
    let peers: Vec<SocketAddr> = a
        .peers
        .iter()
        .map(|&ip| SocketAddr::new(ip, a.port))
        .collect();

    let own = Arc::new(Mutex::new(String::new()));
    let targets = Arc::new(Mutex::new(Vec::new()));
    let blocks = Arc::new(command::Blocks::default());
    let served = Arc::clone(&own);
    let listen = SocketAddr::new(a.listen, a.port);
    thread::spawn(move || neighbors::serve(listen, served));
    let (gateway, arm) = (a.gateway, a.arm);
    thread::spawn(move || netcheck::run(gateway, arm));
    if let Some(l) = a.link {
        start_link(l, &collector, &targets, &blocks);
    }

    let stations = Arc::new(Mutex::new(Vec::new()));
    let counted = Arc::clone(&stations);
    spawn_or_log("state line", move || {
        state_lines(&collector, &counted, STATS_FIRST, STATS_EVERY, |l| {
            println!("{l}");
        })
    });
    loop {
        let counts = neighbors::round(&mut h, &own, &targets, &peers);
        *lock(&stations) = counts;
        command::reassert(&mut h, &blocks, Path::new(neighbors::HOSTAPD));
        thread::sleep(Duration::from_secs(neighbors::ROUND_SECS));
    }
}

/// Prints the state line, on a thread of its own: a snapshot can wait on the
/// collector (the link's, or a slow kernel), and the 802.11k rounds must not.
/// `stations` holds the latest round's stations per BSS.
fn state_lines(
    collector: &Mutex<collect::Collector>,
    stations: &Mutex<Vec<(String, u32)>>,
    first: Duration,
    every: Duration,
    mut emit: impl FnMut(String),
) -> ! {
    thread::sleep(first);
    loop {
        let line = {
            let mut c = lock(collector);
            let snap = c.snapshot(0);
            stats::line(&snap, c.fw_crashes(), &lock(stations))
        };
        emit(line);
        thread::sleep(every);
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_state_line_counts_the_latest_round() {
        let t = testdir::TestDir::new();
        let paths = collect::Paths {
            root: t.path().join("root"),
            hostapd: t.path().join("hostapd"),
            kmsg: t.path().join("kmsg"),
            run: t.path().join("run"),
            wifi: t.path().join("wifi"),
        };
        let collector = Arc::new(Mutex::new(collect::Collector::with_paths(paths)));
        let stations = Arc::new(Mutex::new(vec![("wlan5".to_owned(), 3)]));
        let (tx, rx) = std::sync::mpsc::channel();
        let (c, s) = (Arc::clone(&collector), Arc::clone(&stations));
        let every = Duration::from_millis(20);
        thread::spawn(move || {
            state_lines(&c, &s, Duration::ZERO, every, |l| {
                // The thread outlives the test.
                let _ = tx.send(l);
            })
        });
        let wait = Duration::from_secs(5);
        assert!(rx.recv_timeout(wait).unwrap().contains("clients: wlan5=3 "));
        *stations.lock().unwrap() = vec![("wlan5".to_owned(), 4)];
        while !rx.recv_timeout(wait).unwrap().contains("clients: wlan5=4 ") {}
    }
}
