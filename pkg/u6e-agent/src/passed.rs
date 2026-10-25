//! Files the service manager opened for the agent (the unit's `OpenFile=`),
//! passed by name as sd_listen_fds(3) describes: a file the agent's own user
//! may not open, such as a root-only debugfs file, is opened by systemd and
//! handed over, so the agent needs no privilege to read it.

use std::env;
use std::fs::File;
use std::os::fd::FromRawFd;
use std::process;

/// The first passed descriptor; the rest follow in LISTEN_FDNAMES order.
const FIRST: i32 = 3;

/// The file passed as `name`, if this process was given one. Call it once
/// per name: the file owns the descriptor.
pub fn take(name: &str) -> Option<File> {
    let fd = fd_of(|k| env::var(k).ok(), process::id(), name)?;
    // SAFETY: a descriptor the service manager passed to this process, which
    // nothing else owns; one that is not open fails here.
    unsafe {
        if libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
            return None;
        }
        Some(File::from_raw_fd(fd))
    }
}

/// The descriptor of `name` by the LISTEN_* variables, which hold only for
/// the process LISTEN_PID names (not for one it starts).
fn fd_of(var: impl Fn(&str) -> Option<String>, pid: u32, name: &str) -> Option<i32> {
    if var("LISTEN_PID")?.parse::<u32>().ok()? != pid {
        return None;
    }
    let count: usize = var("LISTEN_FDS")?.parse().ok()?;
    let i = var("LISTEN_FDNAMES")?.split(':').position(|n| n == name)?;
    (i < count).then(|| FIRST + i as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars<'a>(pid: &'a str, fds: &'a str, names: &'a str) -> impl Fn(&str) -> Option<String> {
        move |k| match k {
            "LISTEN_PID" => Some(pid.into()),
            "LISTEN_FDS" => Some(fds.into()),
            "LISTEN_FDNAMES" => Some(names.into()),
            _ => None,
        }
    }

    #[test]
    fn a_passed_file_is_found_by_its_name() {
        assert_eq!(
            fd_of(vars("7", "2", "kmsg:nss-load"), 7, "nss-load"),
            Some(4)
        );
        assert_eq!(fd_of(vars("7", "2", "kmsg:nss-load"), 7, "kmsg"), Some(3));
        assert_eq!(fd_of(vars("7", "2", "kmsg:nss-load"), 7, "other"), None);
    }

    #[test]
    fn files_passed_to_another_process_or_beyond_the_count_are_not() {
        assert_eq!(fd_of(vars("8", "1", "nss-load"), 7, "nss-load"), None);
        assert_eq!(fd_of(vars("7", "1", "kmsg:nss-load"), 7, "nss-load"), None);
        assert_eq!(fd_of(|_| None, 7, "nss-load"), None);
    }
}
