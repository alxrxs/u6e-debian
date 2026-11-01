//! What the AP's root helpers (`u6e-spectral`, `u6e-guard`) share about the
//! sockets they serve the agent on: the listening socket systemd passes,
//! the agent's group, the check that a client is in it, and the signals
//! that end them gracefully.

use std::env;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixListener;
use std::process;
use std::ptr;

/// The one socket systemd passes (`LISTEN_FDS`, from fd 3).
pub fn listener() -> io::Result<UnixListener> {
    let ours = env::var("LISTEN_PID").ok() == Some(process::id().to_string());
    if !ours || env::var("LISTEN_FDS").ok().as_deref() != Some("1") {
        return Err(io::Error::other("not started by its socket unit"));
    }
    // SAFETY: systemd passed fd 3, a listening socket, to this process alone.
    Ok(unsafe { UnixListener::from_raw_fd(3) })
}

/// The id of group `name` in an /etc/group.
pub fn group_id(etc_group: &str, name: &str) -> Option<u32> {
    etc_group.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next() == Some(name)).then(|| f.nth(1)?.parse().ok())?
    })
}

/// Whether the process at the other end of `sock` is a member of `gid`, as
/// its primary group or one of the others.
pub fn member(sock: &impl AsRawFd, gid: u32) -> bool {
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

/// A descriptor readable once SIGTERM, SIGINT or SIGHUP arrives; they no
/// longer end the process, so it can tidy up on the way out.
pub fn signals() -> io::Result<OwnedFd> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn the_group_is_found_by_name() {
        let etc = "root:x:0:\nu6e-agentx:x:5:\nu6e-agent:x:988:\n";
        assert_eq!(group_id(etc, "u6e-agent"), Some(988));
        assert_eq!(group_id(etc, "u6e"), None);
        assert_eq!(group_id("u6e-agent:x:\n", "u6e-agent"), None);
    }

    #[test]
    fn a_peer_is_a_member_of_its_own_group_only() {
        let (a, _b) = UnixStream::pair().unwrap();
        // SAFETY: getgid cannot fail.
        let gid = unsafe { libc::getgid() };
        assert!(member(&a, gid));
        assert!(!member(&a, gid.wrapping_add(54_321)));
    }
}
