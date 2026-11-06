//! The frames the guards read: one packet socket on every interface,
//! receiving only (outgoing frames are not even copied), behind a classic
//! BPF program that lets through just the frames of interest. ARP, DHCP and
//! router advertisements never ride the NSS fast path, so they always reach
//! the host; a client's connections reach it only until the connection is
//! offloaded, which is when its first packets are seen. The socket taps the
//! ports before the bridge, and before any `tc` filter that drops a frame.
//!
//! From a Wi-Fi port it takes every VLAN-tagged frame (its tag in the data,
//! or taken off by the kernel before the tap, which the socket's auxiliary
//! data then holds), ARP, IPv4 TCP SYNs outside fragments and UDP datagrams
//! and fragments (DHCP whole, the rest their headers), DHCPv6 from the
//! servers' port, router advertisements, ICMPv6 whose type `tc` cannot
//! read (type 0, or cut short) and IPv6 behind extension headers (whole: an
//! advertisement may hide there); from an uplink port, DHCP servers'
//! answers. The program names the ports' interface indices, so it is made
//! again when they change.

use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use crate::ports::Port;

const ETH_P_ALL: u16 = 0x0003;
const SOL_PACKET: libc::c_int = 263;
const PACKET_IGNORE_OUTGOING: libc::c_int = 23;
const PACKET_AUXDATA: libc::c_int = 8;
const TP_STATUS_VLAN_VALID: u32 = 1 << 4;

/// What a frame of interest keeps: the headers alone, or a DHCP message or
/// router advertisement whole.
const SHORT: u32 = 96;
const WHOLE: u32 = 1600;

// Classic BPF (linux/filter.h).
const LD: u16 = 0x00;
const LDX: u16 = 0x01;
const ALU: u16 = 0x04;
const JMP: u16 = 0x05;
const RET: u16 = 0x06;
const H: u16 = 0x08;
const B: u16 = 0x10;
const ABS: u16 = 0x20;
const IND: u16 = 0x40;
const LEN: u16 = 0x80;
const MSH: u16 = 0xa0;
const AND: u16 = 0x50;
const JEQ: u16 = 0x10;
const JGE: u16 = 0x30;
const JSET: u16 = 0x40;
/// The interface a frame came in on, and whether the kernel took a VLAN tag
/// off it, as absolute loads (SKF_AD_IFINDEX, SKF_AD_VLAN_TAG_PRESENT).
const IFINDEX: u32 = 0xffff_f000 + 8;
const VLAN_TAG_PRESENT: u32 = 0xffff_f000 + 48;

/// One instruction, its jump (if any) to a label, or a label.
enum Ins {
    Op(u16, u32),
    Jump(u16, u32, &'static str),
    Label(&'static str),
}

use Ins::{Jump, Label, Op};

/// Resolves the labels of `prog` into relative jumps.
fn assemble(prog: &[Ins]) -> Vec<libc::sock_filter> {
    let mut at = std::collections::HashMap::new();
    let mut n = 0;
    for i in prog {
        match i {
            Label(l) => {
                at.insert(*l, n);
            }
            _ => n += 1,
        }
    }
    let mut out = Vec::with_capacity(n);
    for i in prog {
        let (code, k, jt) = match i {
            Label(_) => continue,
            Op(code, k) => (*code, *k, 0),
            Jump(code, k, label) => {
                let off = at[label] - out.len() - 1;
                (*code, *k, u8::try_from(off).expect("a jump within 255"))
            }
        };
        out.push(libc::sock_filter { code, jt, jf: 0, k });
    }
    out
}

/// The ports a program names at most, so its first jumps stay within the
/// 255 instructions a classic BPF jump can skip; an AP has a few dozen.
pub const MAX_PORTS: usize = 160;

/// The program for `ports` (the first [`MAX_PORTS`] of them).
pub fn program(ports: &[Port]) -> Vec<libc::sock_filter> {
    let mut p = vec![Op(LD | ABS, IFINDEX)];
    for port in ports.iter().take(MAX_PORTS) {
        let to = if port.wifi { "wifi" } else { "uplink" };
        p.push(Jump(JMP | JEQ, port.ifindex as u32, to));
    }
    p.extend([
        Op(RET, 0),
        Label("wifi"),
        Op(LD | ABS, VLAN_TAG_PRESENT),
        Jump(JMP | JEQ, 1, "short"),
        Op(LD | H | ABS, 12),
        Jump(JMP | JEQ, 0x8100, "short"),
        Jump(JMP | JEQ, 0x88a8, "short"),
        Jump(JMP | JEQ, 0x0806, "short"),
        Jump(JMP | JEQ, 0x0800, "wifi4"),
        Jump(JMP | JEQ, 0x86dd, "wifi6"),
        Op(RET, 0),
        Label("wifi4"),
        Op(LDX | B | MSH, 14),
        Op(LD | B | ABS, 23),
        Jump(JMP | JEQ, 6, "tcp"),
        Jump(JMP | JEQ, 17, "udp"),
        Op(RET, 0),
        // No fragment's flags, any fragment of a datagram (more fragments,
        // or an offset).
        Label("tcp"),
        Op(LD | H | ABS, 20),
        Jump(JMP | JSET, 0x3fff, "drop"),
        Op(LD | B | IND, 14 + 13),
        Op(ALU | AND, 0x12),
        Jump(JMP | JEQ, 0x02, "short"),
        Op(RET, 0),
        Label("udp"),
        Op(LD | H | ABS, 20),
        Jump(JMP | JSET, 0x3fff, "short"),
        Op(LD | H | IND, 14),
        Jump(JMP | JEQ, 67, "whole"),
        Jump(JMP | JEQ, 68, "whole"),
        Op(RET, SHORT),
        Label("wifi6"),
        Op(LD | B | ABS, 20),
        Jump(JMP | JEQ, 58, "icmp6"),
        Jump(JMP | JEQ, 17, "udp6"),
        // Hop-by-hop, routing, fragment, destination options.
        Jump(JMP | JEQ, 0, "whole"),
        Jump(JMP | JEQ, 43, "whole"),
        Jump(JMP | JEQ, 44, "whole"),
        Jump(JMP | JEQ, 60, "whole"),
        Op(RET, 0),
        // Shorter than its 8-byte header, of type 0, or an advertisement.
        Label("icmp6"),
        Op(LD | LEN, 0),
        Jump(JMP | JGE, 14 + 40 + 8, "icmp6_type"),
        Op(RET, SHORT),
        Label("icmp6_type"),
        Op(LD | B | ABS, 54),
        Jump(JMP | JEQ, 134, "whole"),
        Jump(JMP | JEQ, 0, "short"),
        Op(RET, 0),
        Label("udp6"),
        Op(LD | H | ABS, 54),
        Jump(JMP | JEQ, 547, "short"),
        Op(RET, 0),
        Label("uplink"),
        Op(LD | H | ABS, 12),
        Jump(JMP | JEQ, 0x0800, "uplink4"),
        Op(RET, 0),
        Label("uplink4"),
        Op(LD | B | ABS, 23),
        Jump(JMP | JEQ, 17, "uplink_udp"),
        Op(RET, 0),
        Label("uplink_udp"),
        Op(LD | H | ABS, 20),
        Jump(JMP | JSET, 0x1fff, "drop"),
        Op(LDX | B | MSH, 14),
        Op(LD | H | IND, 14),
        Jump(JMP | JEQ, 67, "whole"),
        Op(RET, 0),
        Label("short"),
        Op(RET, SHORT),
        Label("whole"),
        Op(RET, WHOLE),
        Label("drop"),
        Op(RET, 0),
    ]);
    assemble(&p)
}

/// A frame read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Received {
    pub len: usize,
    pub ifindex: i32,
    /// The VLAN of the tag the kernel took off the frame, if it did.
    pub tag: Option<u16>,
}

/// The packet socket.
pub struct Capture {
    fd: OwnedFd,
}

impl Capture {
    /// A socket on every interface that keeps nothing until [`Capture::watch`].
    pub fn open() -> io::Result<Self> {
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
        let c = Capture {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        };
        c.option(SOL_PACKET, PACKET_IGNORE_OUTGOING, &1i32)?;
        c.option(SOL_PACKET, PACKET_AUXDATA, &1i32)?;
        c.attach(&[libc::sock_filter {
            code: RET,
            jt: 0,
            jf: 0,
            k: 0,
        }])?;
        // What arrived before the filter was in place passed none.
        let mut buf = [0; 64];
        while c.recv(&mut buf)?.is_some() {}
        Ok(c)
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

    fn attach(&self, prog: &[libc::sock_filter]) -> io::Result<()> {
        let fprog = libc::sock_fprog {
            len: u16::try_from(prog.len()).map_err(io::Error::other)?,
            filter: prog.as_ptr().cast_mut(),
        };
        self.option(libc::SOL_SOCKET, libc::SO_ATTACH_FILTER, &fprog)
    }

    /// Keeps the frames of interest of `ports` from now on.
    pub fn watch(&self, ports: &[Port]) -> io::Result<()> {
        self.attach(&program(ports))
    }

    /// The next frame into `buf`, if one is waiting: its length, the
    /// interface it came in on, and the VLAN tag the kernel took off it.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<Option<Received>> {
        // SAFETY: zeroed sockaddr_ll and msghdr are valid for recvmsg to fill.
        let mut from: libc::sockaddr_ll = unsafe { mem::zeroed() };
        let mut control = [0u64; 8];
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
        let mut tag = None;
        // SAFETY: the kernel filled `msg` and its control buffer; the
        // CMSG macros walk only within them.
        unsafe {
            let mut c = libc::CMSG_FIRSTHDR(&raw const msg);
            while !c.is_null() {
                if (*c).cmsg_level == SOL_PACKET && (*c).cmsg_type == PACKET_AUXDATA {
                    let aux: libc::tpacket_auxdata =
                        std::ptr::read_unaligned(libc::CMSG_DATA(c).cast());
                    if aux.tp_status & TP_STATUS_VLAN_VALID != 0 {
                        tag = Some(aux.tp_vlan_tci & 0x0fff);
                    }
                }
                c = libc::CMSG_NXTHDR(&raw const msg, c);
            }
        }
        Ok(Some(Received {
            len: n as usize,
            ifindex: from.sll_ifindex,
            tag,
        }))
    }

    pub fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// A capture that never has a frame, for tests that need none.
    #[cfg(test)]
    pub fn closed() -> Self {
        let s = std::os::unix::net::UnixDatagram::unbound().unwrap();
        s.set_nonblocking(true).unwrap();
        Capture { fd: s.into() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::tests::*;

    /// Runs `prog` on `pkt` arriving on `ifindex`, as the kernel does: what
    /// it keeps of the frame (0: drops it).
    fn run(prog: &[libc::sock_filter], pkt: &[u8], ifindex: u32) -> u32 {
        run_tagged(prog, pkt, ifindex, false)
    }

    /// The same, `tagged` saying whether the kernel took a tag off the frame.
    fn run_tagged(prog: &[libc::sock_filter], pkt: &[u8], ifindex: u32, tagged: bool) -> u32 {
        let (mut a, mut x, mut pc) = (0u32, 0u32, 0usize);
        let load = |at: usize, n: usize| -> Option<u32> {
            Some(
                pkt.get(at..at + n)?
                    .iter()
                    .fold(0, |v, b| v << 8 | u32::from(*b)),
            )
        };
        loop {
            let i = prog[pc];
            pc += 1;
            let size = match i.code & 0x18 {
                H => 2,
                B => 1,
                _ => 4,
            };
            match i.code & 0x07 {
                LD if i.k == IFINDEX => a = ifindex,
                LD if i.k == VLAN_TAG_PRESENT => a = u32::from(tagged),
                LD if i.code & 0xe0 == LEN => a = pkt.len() as u32,
                LD => {
                    let at = if i.code & 0xe0 == IND { x + i.k } else { i.k };
                    let Some(v) = load(at as usize, size) else {
                        return 0;
                    };
                    a = v;
                }
                LDX => {
                    let Some(v) = load(i.k as usize, 1) else {
                        return 0;
                    };
                    x = (v & 0x0f) * 4;
                }
                ALU => a &= i.k,
                JMP => {
                    let hit = match i.code & 0xf0 {
                        JEQ => a == i.k,
                        JGE => a >= i.k,
                        JSET => a & i.k != 0,
                        c => panic!("jump {c:#x}"),
                    };
                    pc += usize::from(if hit { i.jt } else { i.jf });
                }
                RET => return i.k,
                c => panic!("class {c:#x}"),
            }
        }
    }

    fn ports() -> Vec<Port> {
        let port = |ifindex, wifi| Port {
            ifindex,
            name: format!("if{ifindex}"),
            vlan: 42,
            wifi,
        };
        vec![port(10, true), port(21, true), port(7, false)]
    }

    #[test]
    fn the_program_keeps_the_frames_of_interest() {
        let prog = program(&ports());
        let dhcp = crate::dhcp::tests::message(2, 5, [192, 0, 2, 10], Some(60));
        let ack = ipv4_frame(CLIENT, [192, 0, 2, 1], 17, &udp(67, 68, &dhcp));
        let ra = ipv6_frame(CLIENT, 58, &ra_body(0, &[]));
        let ns = ipv6_frame(CLIENT, 58, &[135, 0, 0, 0, 0, 0, 0, 0]);
        let cases = [
            (arp_frame(CLIENT, CLIENT, [192, 0, 2, 10], 1), [SHORT, 0]),
            (
                ipv4_frame(CLIENT, [192, 0, 2, 10], 6, &tcp(0x02)),
                [SHORT, 0],
            ),
            (ipv4_frame(CLIENT, [192, 0, 2, 10], 6, &tcp(0x12)), [0, 0]),
            (ipv4_frame(CLIENT, [192, 0, 2, 10], 6, &tcp(0x18)), [0, 0]),
            (
                ipv4_frame(CLIENT, [192, 0, 2, 10], 17, &udp(5000, 53, &[])),
                [SHORT, 0],
            ),
            (
                ipv4_frame(CLIENT, [192, 0, 2, 10], 1, &[8, 0, 0, 0]),
                [0, 0],
            ),
            (ack, [WHOLE, WHOLE]),
            (ra, [WHOLE, 0]),
            (ns, [0, 0]),
            (ipv6_frame(CLIENT, 17, &udp(547, 546, &[7])), [SHORT, 0]),
            (ipv6_frame(CLIENT, 17, &udp(546, 547, &[1])), [0, 0]),
        ];
        for (i, (pkt, [wifi, uplink])) in cases.iter().enumerate() {
            assert_eq!(run(&prog, pkt, 21), *wifi, "case {i} on a Wi-Fi port");
            assert_eq!(run(&prog, pkt, 7), *uplink, "case {i} on the uplink");
            assert_eq!(run(&prog, pkt, 99), 0, "case {i} elsewhere");
        }
        // Tagged, in the data or taken off: whatever it carries.
        let mut tagged = arp_frame(CLIENT, CLIENT, [0; 4], 1);
        tagged.splice(12..12, [0x81, 0, 0, 0]);
        assert_eq!(
            (run(&prog, &tagged, 21), run(&prog, &tagged, 7)),
            (SHORT, 0)
        );
        let ns = ipv6_frame(CLIENT, 58, &[135, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(run_tagged(&prog, &ns, 21, true), SHORT);
        // Behind an extension header, whole.
        let (nh, payload) = crate::frame::tests::behind(&[(0, 0)], 58, &ra_body(0, &[]));
        assert_eq!(run(&prog, &ipv6_frame(CLIENT, nh, &payload), 21), WHOLE);
        // Any fragment of a datagram, its headers; no TCP fragment.
        let mut fragment = ipv4_frame(CLIENT, [192, 0, 2, 10], 17, &udp(5000, 53, &[]));
        fragment[20] = 0x01;
        assert_eq!(run(&prog, &fragment, 10), SHORT);
        let mut first = ipv4_frame(CLIENT, [192, 0, 2, 10], 6, &tcp(0x02));
        first[20] = 0x20;
        assert_eq!(run(&prog, &first, 10), 0);
        // ICMPv6 whose type tc cannot read: cut short, or of type 0.
        assert_eq!(run(&prog, &ipv6_frame(CLIENT, 58, &[134, 0]), 10), SHORT);
        assert_eq!(run(&prog, &ipv6_frame(CLIENT, 58, &[]), 10), SHORT);
        assert_eq!(run(&prog, &ipv6_frame(CLIENT, 58, &[0; 8]), 10), SHORT);
        // A header shorter than the program reads: dropped, as the kernel does.
        assert_eq!(
            run(&prog, &arp_frame(CLIENT, CLIENT, [0; 4], 1)[..13], 10),
            0
        );
    }

    #[test]
    fn many_ports_still_fit_the_jumps() {
        let many: Vec<Port> = (0..MAX_PORTS as i32 + 40)
            .map(|i| Port {
                ifindex: i,
                name: format!("p{i}"),
                vlan: 42,
                wifi: i % 2 == 0,
            })
            .collect();
        let prog = program(&many);
        let arp = arp_frame(CLIENT, CLIENT, [0; 4], 1);
        assert_eq!(run(&prog, &arp, 0), SHORT);
        assert_eq!(run(&prog, &arp, MAX_PORTS as u32 + 2), 0, "past the cap");
    }
}
