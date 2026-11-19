//! The capture's classic BPF programs, built from the request's closed
//! filter: the kernel keeps what they pass, cut at the snaplen, and copies
//! nothing else to the helper.
//!
//! On the Wi-Fi ports a frame is kept once: as it comes in from the client
//! (its source) or as it goes out to it (its destination). A frame between
//! two clients of the AP is seen coming in on one port and going out on the
//! other, and is kept on whichever side the client is. On the mirror netdev
//! every copy is the client's; a copy is a frame when the client's address
//! is where a frame has its addresses, else an IP packet.
//!
//! The filter: a protocol (ICMP is ICMP and ICMPv6), a port (either end's,
//! of TCP or UDP; a fragment past the first has none), a host (either
//! end's address; with ARP, the sender's or the target's protocol address).
//! IPv6 is read at its fixed header: a packet behind extension headers has
//! no protocol or port the filter can see.

use std::net::IpAddr;

use u6e_proto::bpf::{
    ABS, ALU, AND, B, H, IFINDEX, IND, Ins, JEQ, JGE, JMP, JSET, LD, LDX, MSH, PACKET_OUTGOING,
    PKTTYPE, RET, W, assemble,
};
use u6e_proto::msg::{CaptureFilter, FilterProto};

use Ins::{Jump, Label, Op};

/// A label, and the part of the program it is in (one filter body per
/// header offset).
type L = (&'static str, u32);

/// The most ports a program names, so its first jumps stay within the 255
/// instructions a jump can skip.
pub const MAX_PORTS: usize = 128;

fn goto(to: L) -> Ins<L> {
    // A jump that is always taken: A >= 0.
    Jump(JMP | JGE, 0, to)
}

fn word(b: &[u8]) -> u32 {
    u32::from_be_bytes(b.try_into().unwrap())
}

fn half(b: &[u8]) -> u32 {
    u32::from(u16::from_be_bytes(b.try_into().unwrap()))
}

/// Jumps to `to` when the 6 bytes at `at` are `mac`; falls through when not.
fn mac_at(p: &mut Vec<Ins<L>>, at: u32, mac: [u8; 6], to: L, part: u32) {
    let next = ("mac_hi", part * 1000 + at);
    let miss = ("mac_miss", part * 1000 + at);
    p.extend([
        Op(LD | W | ABS, at),
        Jump(JMP | JEQ, word(&mac[..4]), next),
        goto(miss),
        Label(next),
        Op(LD | H | ABS, at + 4),
        Jump(JMP | JEQ, half(&mac[4..]), to),
        Label(miss),
    ]);
}

/// Jumps to `to` when the 4 words at `at` are `ip`.
fn v6_at(p: &mut Vec<Ins<L>>, at: u32, ip: [u8; 16], to: L, part: u32) {
    let miss = ("v6_miss", part * 1000 + at);
    for i in 0..4 {
        let w = word(&ip[i * 4..i * 4 + 4]);
        let next = ("v6_next", part * 1000 + at + i as u32);
        p.extend([
            Op(LD | W | ABS, at + 4 * i as u32),
            Jump(JMP | JEQ, w, if i == 3 { to } else { next }),
            goto(miss),
        ]);
        if i < 3 {
            p.push(Label(next));
        }
    }
    p.push(Label(miss));
}

/// The filter on an IPv4 packet at `b`, then `keep`.
fn v4(p: &mut Vec<Ins<L>>, f: &CaptureFilter, b: u32, keep: L) {
    let proto = match f.proto {
        Some(FilterProto::Tcp) => Some(6),
        Some(FilterProto::Udp) => Some(17),
        Some(FilterProto::Icmp) => Some(1),
        Some(FilterProto::Arp) => return p.push(Op(RET, 0)),
        None => None,
    };
    let host = match f.host {
        Some(IpAddr::V4(ip)) => Some(u32::from(ip)),
        Some(IpAddr::V6(_)) => return p.push(Op(RET, 0)),
        None => None,
    };
    if proto.is_some() || f.port.is_some() {
        p.push(Op(LD | B | ABS, b + 9));
        match proto {
            Some(n) => p.push(Jump(JMP | JEQ, n, ("v4_proto", b))),
            None => p.extend([
                Jump(JMP | JEQ, 6, ("v4_proto", b)),
                Jump(JMP | JEQ, 17, ("v4_proto", b)),
            ]),
        }
        p.extend([Op(RET, 0), Label(("v4_proto", b))]);
    }
    if let Some(ip) = host {
        p.extend([
            Op(LD | W | ABS, b + 12),
            Jump(JMP | JEQ, ip, ("v4_host", b)),
            Op(LD | W | ABS, b + 16),
            Jump(JMP | JEQ, ip, ("v4_host", b)),
            Op(RET, 0),
            Label(("v4_host", b)),
        ]);
    }
    if let Some(port) = f.port {
        p.extend([
            Op(LD | H | ABS, b + 6),
            Jump(JMP | JSET, 0x1fff, ("v4_drop", b)),
            Op(LDX | B | MSH, b),
            Op(LD | H | IND, b),
            Jump(JMP | JEQ, u32::from(port), keep),
            Op(LD | H | IND, b + 2),
            Jump(JMP | JEQ, u32::from(port), keep),
            Label(("v4_drop", b)),
            Op(RET, 0),
        ]);
    } else {
        p.push(goto(keep));
    }
}

/// The filter on an IPv6 packet at `b`, then `keep`.
fn v6(p: &mut Vec<Ins<L>>, f: &CaptureFilter, b: u32, keep: L) {
    let proto = match f.proto {
        Some(FilterProto::Tcp) => Some(6),
        Some(FilterProto::Udp) => Some(17),
        Some(FilterProto::Icmp) => Some(58),
        Some(FilterProto::Arp) => return p.push(Op(RET, 0)),
        None => None,
    };
    let host = match f.host {
        Some(IpAddr::V6(ip)) => Some(ip.octets()),
        Some(IpAddr::V4(_)) => return p.push(Op(RET, 0)),
        None => None,
    };
    if proto.is_some() || f.port.is_some() {
        p.push(Op(LD | B | ABS, b + 6));
        match proto {
            Some(n) => p.push(Jump(JMP | JEQ, n, ("v6_proto", b))),
            None => p.extend([
                Jump(JMP | JEQ, 6, ("v6_proto", b)),
                Jump(JMP | JEQ, 17, ("v6_proto", b)),
            ]),
        }
        p.extend([Op(RET, 0), Label(("v6_proto", b))]);
    }
    if let Some(ip) = host {
        v6_at(p, b + 8, ip, ("v6_host", b), 1);
        v6_at(p, b + 24, ip, ("v6_host", b), 2);
        p.extend([Op(RET, 0), Label(("v6_host", b))]);
    }
    if let Some(port) = f.port {
        p.extend([
            Op(LD | H | ABS, b + 40),
            Jump(JMP | JEQ, u32::from(port), keep),
            Op(LD | H | ABS, b + 42),
            Jump(JMP | JEQ, u32::from(port), keep),
            Op(RET, 0),
        ]);
    } else {
        p.push(goto(keep));
    }
}

/// The filter on an Ethernet frame (`l2`) or an IP packet: what it keeps
/// goes to `keep`.
fn body(p: &mut Vec<Ins<L>>, f: &CaptureFilter, l2: bool, keep: L) {
    if *f == CaptureFilter::default() {
        return p.push(goto(keep));
    }
    let b = if l2 { 14 } else { 0 };
    if l2 {
        p.extend([
            Op(LD | H | ABS, 12),
            Jump(JMP | JEQ, 0x0800, ("v4", b)),
            Jump(JMP | JEQ, 0x86dd, ("v6", b)),
            Jump(JMP | JEQ, 0x0806, ("arp", b)),
            Op(RET, 0),
        ]);
    } else {
        p.extend([
            Op(LD | B | ABS, 0),
            Op(ALU | AND, 0xf0),
            Jump(JMP | JEQ, 0x40, ("v4", b)),
            Jump(JMP | JEQ, 0x60, ("v6", b)),
            Op(RET, 0),
        ]);
    }
    p.push(Label(("v4", b)));
    v4(p, f, b, keep);
    p.push(Label(("v6", b)));
    v6(p, f, b, keep);
    if l2 {
        p.push(Label(("arp", b)));
        match (f.proto, f.port, f.host) {
            (Some(FilterProto::Arp) | None, None, None) => p.push(goto(keep)),
            (Some(FilterProto::Arp) | None, None, Some(IpAddr::V4(ip))) => p.extend([
                Op(LD | W | ABS, b + 14),
                Jump(JMP | JEQ, u32::from(ip), keep),
                Op(LD | W | ABS, b + 24),
                Jump(JMP | JEQ, u32::from(ip), keep),
                Op(RET, 0),
            ]),
            _ => p.push(Op(RET, 0)),
        }
    }
}

/// The program for the Wi-Fi ports `ports` (their indices): the client
/// `mac`'s frames, once each, that `f` keeps, cut at `snaplen`; refused
/// past [`MAX_PORTS`] ports, whose jumps would not reach.
pub fn ports(
    ports: &[u32],
    mac: [u8; 6],
    f: &CaptureFilter,
    snaplen: u16,
) -> Result<Vec<libc::sock_filter>, String> {
    if ports.len() > MAX_PORTS {
        return Err(format!(
            "{} Wi-Fi ports, more than a capture can read ({MAX_PORTS})",
            ports.len()
        ));
    }
    let mut p = vec![Op(LD | ABS, IFINDEX)];
    for i in ports {
        p.push(Jump(JMP | JEQ, *i, ("port", 0)));
    }
    p.extend([
        Op(RET, 0),
        Label(("port", 0)),
        Op(LD | ABS, PKTTYPE),
        Jump(JMP | JEQ, PACKET_OUTGOING, ("out", 0)),
    ]);
    mac_at(&mut p, 6, mac, ("filter", 14), 1);
    p.extend([Op(RET, 0), Label(("out", 0))]);
    mac_at(&mut p, 0, mac, ("filter", 14), 2);
    p.extend([Op(RET, 0), Label(("filter", 14))]);
    body(&mut p, f, true, ("keep", 0));
    p.extend([Label(("keep", 0)), Op(RET, u32::from(snaplen))]);
    Ok(assemble(&p))
}

/// The program for the mirror netdev: the copies `f` keeps, frames or IP
/// packets, cut at `snaplen`.
pub fn mirror(mac: [u8; 6], f: &CaptureFilter, snaplen: u16) -> Vec<libc::sock_filter> {
    let mut p = Vec::new();
    mac_at(&mut p, 0, mac, ("l2", 0), 1);
    mac_at(&mut p, 6, mac, ("l2", 0), 2);
    body(&mut p, f, false, ("keep", 0));
    p.push(Label(("l2", 0)));
    body(&mut p, f, true, ("keep", 0));
    p.extend([Label(("keep", 0)), Op(RET, u32::from(snaplen))]);
    assemble(&p)
}

/// Whether a mirror's copy is a frame: the client's address where a
/// frame's destination or source is.
pub fn is_frame(data: &[u8], mac: [u8; 6]) -> bool {
    data.get(..6) == Some(&mac[..]) || data.get(6..12) == Some(&mac[..])
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use u6e_proto::bpf::{Meta, run};

    pub const CLIENT: [u8; 6] = [0x64, 0, 0, 0, 0, 1];
    pub const OTHER: [u8; 6] = [2, 0, 0, 0, 0, 2];

    pub fn eth(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend(dst);
        f.extend(src);
        f.extend(ethertype.to_be_bytes());
        f.extend(payload);
        f
    }

    pub fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], l4: &[u8]) -> Vec<u8> {
        let mut h = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, proto, 0, 0];
        h[2..4].copy_from_slice(&((20 + l4.len()) as u16).to_be_bytes());
        h.extend(src);
        h.extend(dst);
        h.extend(l4);
        h
    }

    pub fn ipv6(nh: u8, src: Ipv6Addr, dst: Ipv6Addr, l4: &[u8]) -> Vec<u8> {
        let mut h = vec![0x60, 0, 0, 0];
        h.extend((l4.len() as u16).to_be_bytes());
        h.extend([nh, 64]);
        h.extend(src.octets());
        h.extend(dst.octets());
        h.extend(l4);
        h
    }

    pub fn ports_l4(sport: u16, dport: u16) -> Vec<u8> {
        let mut l4 = sport.to_be_bytes().to_vec();
        l4.extend(dport.to_be_bytes());
        l4.extend([0; 16]);
        l4
    }

    fn arp(spa: [u8; 4], tpa: [u8; 4]) -> Vec<u8> {
        let mut a = vec![0, 1, 8, 0, 6, 4, 0, 1];
        a.extend(CLIENT);
        a.extend(spa);
        a.extend([0; 6]);
        a.extend(tpa);
        a
    }

    const A: [u8; 4] = [192, 0, 2, 10];
    const B: [u8; 4] = [198, 51, 100, 7];

    fn v6a() -> Ipv6Addr {
        "2001:db8::10".parse().unwrap()
    }

    fn filter(
        proto: Option<FilterProto>,
        port: Option<u16>,
        host: Option<IpAddr>,
    ) -> CaptureFilter {
        CaptureFilter { proto, port, host }
    }

    fn incoming(ifindex: u32) -> Meta {
        Meta {
            ifindex,
            tagged: false,
            pkttype: 0,
        }
    }

    fn outgoing(ifindex: u32) -> Meta {
        Meta {
            ifindex,
            tagged: false,
            pkttype: PACKET_OUTGOING,
        }
    }

    #[test]
    fn a_frame_is_kept_once_on_the_clients_side() {
        let prog = ports(&[10, 11], CLIENT, &CaptureFilter::default(), 128).unwrap();
        let up = eth(OTHER, CLIENT, 0x0800, &ipv4(6, A, B, &ports_l4(5000, 443)));
        let down = eth(CLIENT, OTHER, 0x0800, &ipv4(6, B, A, &ports_l4(443, 5000)));
        assert_eq!(run(&prog, &up, incoming(10)), 128);
        assert_eq!(run(&prog, &down, outgoing(11)), 128);
        // The same frames the other way round: the other client's side.
        assert_eq!(run(&prog, &up, outgoing(11)), 0);
        assert_eq!(run(&prog, &down, incoming(10)), 0);
        // Not a Wi-Fi port; another client.
        assert_eq!(run(&prog, &up, incoming(30)), 0);
        let other = eth(OTHER, [2, 0, 0, 0, 0, 3], 0x0800, &ipv4(6, A, B, &[]));
        assert_eq!(run(&prog, &other, incoming(10)), 0);
        // A MAC that matches in its first four bytes only.
        let near = eth(OTHER, [0x64, 0, 0, 0, 9, 9], 0x0806, &arp(A, B));
        assert_eq!(run(&prog, &near, incoming(10)), 0);
    }

    #[test]
    fn a_program_names_at_most_max_ports_and_reaches_the_last() {
        let all: Vec<u32> = (1..=MAX_PORTS as u32).collect();
        let prog = ports(&all, CLIENT, &CaptureFilter::default(), 128).unwrap();
        let up = eth(OTHER, CLIENT, 0x0800, &ipv4(6, A, B, &ports_l4(5000, 443)));
        assert_eq!(run(&prog, &up, incoming(MAX_PORTS as u32)), 128);
        let more: Vec<u32> = (1..=MAX_PORTS as u32 + 1).collect();
        let e = ports(&more, CLIENT, &CaptureFilter::default(), 128).unwrap_err();
        assert!(e.starts_with("129 Wi-Fi ports"), "{e}");
    }

    #[test]
    fn each_field_of_the_filter_keeps_what_it_says() {
        let tcp4 = eth(OTHER, CLIENT, 0x0800, &ipv4(6, A, B, &ports_l4(5000, 443)));
        let udp4 = eth(OTHER, CLIENT, 0x0800, &ipv4(17, A, B, &ports_l4(5353, 53)));
        let icmp4 = eth(OTHER, CLIENT, 0x0800, &ipv4(1, A, B, &[8, 0, 0, 0]));
        let tcp6 = eth(
            OTHER,
            CLIENT,
            0x86dd,
            &ipv6(6, v6a(), Ipv6Addr::LOCALHOST, &ports_l4(5000, 443)),
        );
        let icmp6 = eth(
            OTHER,
            CLIENT,
            0x86dd,
            &ipv6(58, v6a(), Ipv6Addr::LOCALHOST, &[128, 0, 0, 0]),
        );
        let arp_f = eth([0xff; 6], CLIENT, 0x0806, &arp(A, B));
        let all = [&tcp4, &udp4, &icmp4, &tcp6, &icmp6, &arp_f];
        let v4a = Some(IpAddr::V4(Ipv4Addr::from(A)));
        let v4b = Some(IpAddr::V4(Ipv4Addr::from(B)));
        let cases: [(CaptureFilter, [bool; 6]); 11] = [
            (CaptureFilter::default(), [true; 6]),
            (
                filter(Some(FilterProto::Tcp), None, None),
                [true, false, false, true, false, false],
            ),
            (
                filter(Some(FilterProto::Udp), None, None),
                [false, true, false, false, false, false],
            ),
            (
                filter(Some(FilterProto::Icmp), None, None),
                [false, false, true, false, true, false],
            ),
            (
                filter(Some(FilterProto::Arp), None, None),
                [false, false, false, false, false, true],
            ),
            (
                filter(None, Some(443), None),
                [true, false, false, true, false, false],
            ),
            (
                filter(Some(FilterProto::Udp), Some(53), None),
                [false, true, false, false, false, false],
            ),
            (
                filter(None, None, v4b),
                [true, true, true, false, false, true],
            ),
            (
                filter(Some(FilterProto::Arp), None, v4a),
                [false, false, false, false, false, true],
            ),
            (
                filter(None, None, Some(IpAddr::V6(v6a()))),
                [false, false, false, true, true, false],
            ),
            (filter(Some(FilterProto::Tcp), Some(80), v4a), [false; 6]),
        ];
        for (i, (f, want)) in cases.iter().enumerate() {
            let prog = ports(&[10], CLIENT, f, 96).unwrap();
            for (j, pkt) in all.iter().enumerate() {
                let kept = run(&prog, pkt, incoming(10));
                assert_eq!(kept == 96, want[j], "filter {i} ({f:?}), packet {j}");
                assert!(kept == 0 || kept == 96);
            }
        }
    }

    #[test]
    fn a_later_fragment_has_no_port() {
        let mut frag = ipv4(17, A, B, &ports_l4(5353, 53));
        frag[6] = 0x00;
        frag[7] = 0x10;
        let pkt = eth(OTHER, CLIENT, 0x0800, &frag);
        let prog = ports(&[10], CLIENT, &filter(None, Some(53), None), 64).unwrap();
        assert_eq!(run(&prog, &pkt, incoming(10)), 0);
        // The first fragment carries them.
        let mut first = ipv4(17, A, B, &ports_l4(5353, 53));
        first[6] = 0x20;
        assert_eq!(
            run(&prog, &eth(OTHER, CLIENT, 0x0800, &first), incoming(10)),
            64
        );
        // A header with options: the ports are past it.
        let mut opts = ipv4(17, A, B, &[]);
        opts[0] = 0x46;
        opts.extend([0, 0, 0, 0]);
        opts.extend(ports_l4(5353, 53));
        assert_eq!(
            run(&prog, &eth(OTHER, CLIENT, 0x0800, &opts), incoming(10)),
            64
        );
    }

    #[test]
    fn the_mirror_keeps_frames_and_packets_alike() {
        let f = filter(Some(FilterProto::Tcp), Some(443), None);
        let prog = mirror(CLIENT, &f, 200);
        let packet = ipv4(6, A, B, &ports_l4(5000, 443));
        let frame_up = eth(OTHER, CLIENT, 0x0800, &packet);
        let frame_down = eth(CLIENT, OTHER, 0x0800, &ipv4(6, B, A, &ports_l4(443, 5000)));
        let any = Meta::default();
        assert_eq!(run(&prog, &frame_up, any), 200);
        assert_eq!(run(&prog, &frame_down, any), 200);
        assert_eq!(run(&prog, &packet, any), 200);
        let v6 = ipv6(6, v6a(), Ipv6Addr::LOCALHOST, &ports_l4(443, 1));
        assert_eq!(run(&prog, &v6, any), 200);
        let udp = ipv4(17, A, B, &ports_l4(5000, 443));
        assert_eq!(run(&prog, &udp, any), 0);
        assert!(is_frame(&frame_up, CLIENT) && is_frame(&frame_down, CLIENT));
        assert!(!is_frame(&packet, CLIENT));
        // With no filter, all of it.
        let all = mirror(CLIENT, &CaptureFilter::default(), 64);
        assert_eq!(run(&all, &udp, any), 64);
    }
}
