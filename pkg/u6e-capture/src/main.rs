//! The AP's capture helper: it captures one client's traffic for the agent,
//! which may neither open a packet socket nor take a client's flows from
//! the NSS offload, and does nothing else, in a sandbox that shows it only
//! what that needs (see prep-rootfs.sh for the units).
//!
//!   u6e-capture serve
//!   u6e-capture restore
//!
//! `serve` runs the capture asked for on the connection systemd passes as
//! stdin (`u6e_proto::capture`), a member of the agent's group's only, one
//! at a time on the AP (`serve`). `restore`, the unit's last step however
//! the helper ended, gives the flows back to the offload unless a live
//! capture holds them (`offload`). The unit's runtime limit is the
//! backstop of the capture's own deadline.

mod filter;
#[cfg(test)]
mod live;
mod offload;
mod pcapng;
mod serve;
mod sock;
#[cfg(test)]
mod testdir;

use std::ffi::CStr;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::{env, process};

use u6e_proto::local;

use offload::Paths;

/// The group whose members are served: the agent's.
const AGENT_GROUP: &str = "u6e-agent";

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let paths = Paths { root: "/".into() };
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["serve"] => serve(paths),
        ["restore"] => restore(&paths),
        _ => {
            eprintln!("usage: u6e-capture serve | restore");
            process::exit(2);
        }
    };
    if let Err(e) = result {
        eprintln!("u6e-capture: {e}");
        process::exit(1);
    }
}

fn serve(paths: Paths) -> io::Result<()> {
    let stop = local::signals()?;
    let gid = local::group_id(&fs::read_to_string("/etc/group")?, AGENT_GROUP)
        .ok_or_else(|| io::Error::other(format!("no group {AGENT_GROUP}")))?;
    // SAFETY: systemd passes the accepted connection as stdin, which nothing
    // else here uses.
    let conn = unsafe { UnixStream::from_raw_fd(0) };
    if !local::member(&conn, gid) {
        return Err(io::Error::other("a peer outside the agent's group"));
    }
    let cfg = serve::Config {
        paths,
        host: host_name(),
        netdevs: serve::netdevs,
    };
    serve::run(&cfg, conn, stop.as_raw_fd())
}

/// Gives the flows back, unless a live capture holds them.
fn restore(paths: &Paths) -> io::Result<()> {
    let Some(_lock) = serve::try_lock(paths)? else {
        return Ok(());
    };
    match offload::restore_from(paths) {
        Ok(true) => eprintln!("u6e-capture: the offload is back"),
        Ok(false) => {}
        Err(e) => return Err(io::Error::other(format!("the offload is not back: {e}"))),
    }
    Ok(())
}

fn host_name() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is valid for the length passed; the name ends with NUL.
    if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len() - 1) } != 0 {
        return "this AP".into();
    }
    CStr::from_bytes_until_nul(&buf)
        .map_or_else(|_| "this AP".into(), |c| c.to_string_lossy().into_owned())
}
