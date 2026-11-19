//! The packet sockets a capture reads: on every interface (the Wi-Fi ports,
//! by the program's interface test) or bound to one (the mirror netdev),
//! both directions, each packet with the kernel's receive time, its
//! original length and the interface and direction it was seen in.

use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const ETH_P_ALL: u16 = 0x0003;
const SOL_PACKET: libc::c_int = 263;
const PACKET_AUXDATA: libc::c_int = 8;
const PACKET_STATISTICS: libc::c_int = 6;
/// What the socket is to hold for the helper, its kernel overhead in: a
/// burst while it writes. A plain SO_RCVBUF is capped at twice
/// net.core.rmem_max (about 416 KiB), less than an AP image's default of
/// 1 MiB, so the helper forces it with CAP_NET_ADMIN where the socket holds
/// less, and reads back what it got ([`PacketSocket::rcvbuf`]).
const RCVBUF: usize = 2 << 20;

/// A packet read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Received {
    /// The bytes read into the buffer: the packet cut at the snaplen.
    pub len: usize,
    /// Its length before it was cut.
    pub orig_len: u32,
    pub ifindex: i32,
    pub outgoing: bool,
    /// The kernel's receive time, in nanoseconds since the Unix epoch.
    pub ts_ns: u64,
}

pub struct PacketSocket {
    fd: OwnedFd,
    rcvbuf: usize,
}

impl PacketSocket {
    /// A socket on `ifindex`, or on every interface; it keeps nothing until
    /// [`PacketSocket::filter`].
    pub fn open(ifindex: Option<i32>) -> io::Result<Self> {
        // SAFETY: plain socket creation; the descriptor is owned at once.
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                i32::from(ETH_P_ALL.to_be()),
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a fresh descriptor this process owns.
        let mut s = PacketSocket {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            rcvbuf: 0,
        };
        s.option(libc::SOL_SOCKET, libc::SO_TIMESTAMPNS, &1i32)?;
        s.option(SOL_PACKET, PACKET_AUXDATA, &1i32)?;
        if s.read_option(libc::SOL_SOCKET, libc::SO_RCVBUF)? < RCVBUF {
            // The kernel doubles what it is asked. Without CAP_NET_ADMIN the
            // socket keeps the default rather than shrink to the cap.
            let half = (RCVBUF / 2) as libc::c_int;
            let _ = s.option(libc::SOL_SOCKET, libc::SO_RCVBUFFORCE, &half);
        }
        s.rcvbuf = s.read_option(libc::SOL_SOCKET, libc::SO_RCVBUF)?;
        s.filter(&[libc::sock_filter {
            code: u6e_proto::bpf::RET,
            jt: 0,
            jf: 0,
            k: 0,
        }])?;
        if let Some(i) = ifindex {
            // SAFETY: a zeroed sockaddr_ll is valid, filled in below.
            let mut sa: libc::sockaddr_ll = unsafe { mem::zeroed() };
            sa.sll_family = libc::AF_PACKET as u16;
            sa.sll_protocol = ETH_P_ALL.to_be();
            sa.sll_ifindex = i;
            // SAFETY: `sa` is a valid sockaddr_ll of the size passed.
            let r = unsafe {
                libc::bind(
                    s.fd.as_raw_fd(),
                    (&raw const sa).cast(),
                    mem::size_of::<libc::sockaddr_ll>() as u32,
                )
            };
            if r != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        // What arrived before the filter was in place passed none.
        let mut buf = [0; 64];
        while s.recv(&mut buf)?.is_some() {}
        Ok(s)
    }

    fn option<T>(&self, level: libc::c_int, name: libc::c_int, value: &T) -> io::Result<()> {
        // SAFETY: `value` is a valid T of the size passed.
        let r = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                level,
                name,
                (value as *const T).cast(),
                mem::size_of::<T>() as libc::socklen_t,
            )
        };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn read_option(&self, level: libc::c_int, name: libc::c_int) -> io::Result<usize> {
        let mut v: libc::c_int = 0;
        let mut len = mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `v` is a valid int of the length passed.
        let r = unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                level,
                name,
                (&raw mut v).cast(),
                &raw mut len,
            )
        };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(usize::try_from(v).unwrap_or(0))
    }

    /// The bytes the kernel holds for the socket, its own overhead in.
    pub fn rcvbuf(&self) -> usize {
        self.rcvbuf
    }

    /// Keeps what `prog` passes from now on.
    pub fn filter(&self, prog: &[libc::sock_filter]) -> io::Result<()> {
        let fprog = libc::sock_fprog {
            len: u16::try_from(prog.len()).map_err(io::Error::other)?,
            filter: prog.as_ptr().cast_mut(),
        };
        self.option(libc::SOL_SOCKET, libc::SO_ATTACH_FILTER, &fprog)
    }

    /// The next packet into `buf`, if one is waiting.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<Option<Received>> {
        // SAFETY: zeroed sockaddr_ll and msghdr are valid for recvmsg to fill.
        let mut from: libc::sockaddr_ll = unsafe { mem::zeroed() };
        let mut control = [0u64; 16];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        // SAFETY: as above.
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = (&raw mut from).cast();
        msg.msg_namelen = mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = mem::size_of_val(&control) as _;
        // SAFETY: every buffer msg points at is valid for its stated length.
        let n = unsafe { libc::recvmsg(self.fd.as_raw_fd(), &raw mut msg, 0) };
        if n < 0 {
            let e = io::Error::last_os_error();
            return match e.kind() {
                io::ErrorKind::WouldBlock => Ok(None),
                _ => Err(e),
            };
        }
        let len = (n as usize).min(buf.len());
        let (mut orig_len, mut ts_ns) = (len as u32, 0);
        // SAFETY: the kernel filled `msg` and its control buffer; the CMSG
        // macros walk only within them.
        unsafe {
            let mut c = libc::CMSG_FIRSTHDR(&raw const msg);
            while !c.is_null() {
                let data = libc::CMSG_DATA(c);
                match ((*c).cmsg_level, (*c).cmsg_type) {
                    (SOL_PACKET, PACKET_AUXDATA) => {
                        let aux: libc::tpacket_auxdata = std::ptr::read_unaligned(data.cast());
                        orig_len = aux.tp_len;
                    }
                    (libc::SOL_SOCKET, libc::SCM_TIMESTAMPNS) => {
                        let t: libc::timespec = std::ptr::read_unaligned(data.cast());
                        ts_ns = t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64;
                    }
                    _ => {}
                }
                c = libc::CMSG_NXTHDR(&raw const msg, c);
            }
        }
        Ok(Some(Received {
            len,
            orig_len,
            ifindex: from.sll_ifindex,
            outgoing: from.sll_pkttype == libc::PACKET_OUTGOING,
            ts_ns,
        }))
    }

    /// The packets the kernel dropped for want of room since the last call.
    pub fn drops(&self) -> u64 {
        let mut st = libc::tpacket_stats {
            tp_packets: 0,
            tp_drops: 0,
        };
        let mut len = mem::size_of::<libc::tpacket_stats>() as libc::socklen_t;
        // SAFETY: `st` and `len` describe a buffer of the size the call takes.
        let r = unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                SOL_PACKET,
                PACKET_STATISTICS,
                (&raw mut st).cast(),
                &mut len,
            )
        };
        if r == 0 { u64::from(st.tp_drops) } else { 0 }
    }

    pub fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With the helper's capabilities the socket holds what it is to, more
    /// than the rmem_max cap; without them it says so and passes.
    #[test]
    fn the_socket_holds_what_the_kernel_granted() {
        let s = match PacketSocket::open(None) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                return eprintln!("skipped: no packet socket ({e})");
            }
            Err(e) => panic!("{e}"),
        };
        assert_eq!(
            s.rcvbuf(),
            s.read_option(libc::SOL_SOCKET, libc::SO_RCVBUF).unwrap()
        );
        assert!(s.rcvbuf() >= RCVBUF, "{} B", s.rcvbuf());
    }
}
