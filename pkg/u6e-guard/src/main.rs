//! The AP's client guards: ARP inspection, rogue-DHCP guard, RA guard, IP
//! source guard and a ban on VLAN-tagged frames, on every Wi-Fi port
//! (`rules`). They bind each client's MAC to the addresses the site's DHCP
//! server acknowledges, or the controller seeds from the servers' leases, or
//! the site makes static (`bindings`), read the frames that bear on them as
//! they reach the host (`capture`), and report each violation to the agent,
//! which forwards it; on the VLANs the controller says to enforce on, they
//! drop with `tc` (`enforce`) only frames they report, each reported as
//! dropped, never the client. Their own user, with CAP_NET_RAW and CAP_NET_ADMIN alone (`tc`
//! inherits them), in a sandbox (see prep-rootfs.sh).
//!
//!   u6e-guard serve
//!   u6e-guard clear
//!
//! `serve` serves the agent on the socket systemd passes (the protocol is
//! `u6e_proto::guard`) until stopped. `clear` removes the guards' qdiscs and
//! actions, and fails when tc cannot: the unit's first and last step, so
//! nothing drops while the guards are not running.

mod bindings;
mod capture;
mod dhcp;
mod enforce;
mod frame;
#[cfg(test)]
mod live;
mod ports;
mod rules;
mod serve;
#[cfg(test)]
mod testdir;

use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{env, process};

use u6e_proto::local;

/// The group whose members are served: the agent's.
const AGENT_GROUP: &str = "u6e-agent";
const NET: &str = "/sys/class/net";
const TC: &str = "/usr/sbin/tc";
/// How often the ports are looked at again: a new per-VLAN interface of a
/// client is watched within this.
const RESCAN: Duration = Duration::from_secs(2);

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["serve"] => serve(),
        ["clear"] => enforce::clear(Path::new(TC)),
        _ => {
            eprintln!("usage: u6e-guard serve | clear");
            process::exit(2);
        }
    };
    if let Err(e) = result {
        eprintln!("u6e-guard: {e}");
        process::exit(1);
    }
}

fn serve() -> io::Result<()> {
    let stop = local::signals()?;
    let gid = local::group_id(&fs::read_to_string("/etc/group")?, AGENT_GROUP)
        .ok_or_else(|| io::Error::other(format!("no group {AGENT_GROUP}")))?;
    let cfg = serve::Config {
        gid,
        net: PathBuf::from(NET),
        tc: PathBuf::from(TC),
        rescan: RESCAN,
    };
    // What a guard that ended without its last step left behind.
    enforce::clear(&cfg.tc)?;
    let capture = capture::Capture::open()?;
    eprintln!("u6e-guard: reporting only until the controller says otherwise");
    serve::run(&cfg, local::listener()?, capture, stop.as_raw_fd())
}
