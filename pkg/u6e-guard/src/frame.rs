//! The frames the guards look at, read from their Ethernet bytes as the
//! kernel's flow dissector reads them for tc's flower, so that what the
//! rules name is what the filters can drop: ARP, DHCP and DHCPv6 messages
//! from the server ports, router advertisements (behind IPv6 extension
//! headers too), ICMPv6 whose type flower cannot read, a client's IPv4 TCP
//! SYN or UDP datagram, and VLAN-tagged frames, whatever they carry.
//! Everything else reads as nothing.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::dhcp::{self, Message};

const ETH_ARP: u16 = 0x0806;
const ETH_IPV4: u16 = 0x0800;
const ETH_IPV6: u16 = 0x86dd;
const ETH_8021Q: u16 = 0x8100;
const ETH_8021AD: u16 = 0x88a8;
/// IPv6 extension headers: hop-by-hop, routing, fragment, destination.
pub const HOP_BY_HOP: u8 = 0;
pub const ROUTING: u8 = 43;
pub const FRAGMENT: u8 = 44;
pub const DESTINATION: u8 = 60;
/// The extension headers flower reads an upper-layer header behind (the
/// dissector's MAX_FLOW_DISSECT_HDRS): behind one more it still reads the
/// ports, as it does after each header it walks, but no ICMPv6 type, which
/// it reads only on a walk's next step; behind two more not even the
/// protocol.
pub const EXT_MAX: usize = 15;
const TCP: u8 = 6;
const UDP: u8 = 17;
pub const ICMPV6: u8 = 58;
const ROUTER_ADVERTISEMENT: u8 = 134;

/// A frame of interest, with the MAC that sent it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub src: [u8; 6],
    pub what: What,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum What {
    /// The sender's hardware and protocol addresses; both zero for an ARP
    /// packet flower cannot read (not an Ethernet and IPv4 request or
    /// reply, or cut short).
    Arp {
        sha: [u8; 6],
        spa: Ipv4Addr,
    },
    /// A DHCP message from the server port to the client's (`server`) or
    /// the other way; `None` when it is malformed.
    Dhcp {
        src: Ipv4Addr,
        server: bool,
        msg: Option<Message>,
    },
    /// A DHCPv6 message from the servers' port to the clients', of this
    /// type (`None`: cut short).
    Dhcp6Server {
        src: Ipv6Addr,
        kind: Option<u8>,
    },
    Ra(Ra),
    /// ICMPv6 whose type flower cannot read, which may be a router
    /// advertisement.
    Hidden(Hidden),
    /// A TCP SYN without ACK, or a UDP datagram (any fragment of one).
    Conn {
        src: Ipv4Addr,
    },
    /// A frame carrying a VLAN tag, of this VLAN (0: priority only).
    Tagged {
        vid: u16,
    },
}

/// Why flower cannot read an IPv6 packet's ICMPv6 type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hidden {
    /// A first fragment of ICMPv6 or of further extension headers: flower
    /// reads nothing past a fragment header.
    Fragment,
    /// Behind more than [`EXT_MAX`] extension headers.
    Deep,
    /// An extension header or the ICMPv6 header cut short, or ICMPv6 of type
    /// 0, which flower cannot tell from an unread one.
    Cut,
}

/// A router advertisement: what makes a host take its sender as a router.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ra {
    /// As a default router, in seconds (0: not one).
    pub lifetime: u16,
    /// Prefix information: each prefix, its length and its L and A flags.
    pub prefixes: Vec<(Ipv6Addr, u8, u8)>,
    /// Route information: each route's prefix and length.
    pub routes: Vec<(Ipv6Addr, u8)>,
    /// Whether it names DNS servers or search domains (RDNSS, DNSSL).
    pub dns: bool,
    /// The extension headers before it: each one's type and length field.
    pub ext: Vec<(u8, u8)>,
    /// Whether it is cut short or an option's length is wrong.
    pub malformed: bool,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn mac_at(b: &[u8], at: usize) -> Option<[u8; 6]> {
    b.get(at..at + 6)?.try_into().ok()
}

fn v4_at(b: &[u8], at: usize) -> Option<Ipv4Addr> {
    let o: [u8; 4] = b.get(at..at + 4)?.try_into().ok()?;
    Some(o.into())
}

fn v6_at(b: &[u8], at: usize) -> Option<Ipv6Addr> {
    let o: [u8; 16] = b.get(at..at + 16)?.try_into().ok()?;
    Some(o.into())
}

fn is_ext(nh: u8) -> bool {
    matches!(nh, HOP_BY_HOP | ROUTING | FRAGMENT | DESTINATION)
}

/// The frame in `b`, an Ethernet frame as the packet socket gives it.
pub fn parse(b: &[u8]) -> Option<Frame> {
    let src = mac_at(b, 6)?;
    let body = b.get(14..)?;
    let what = match u16_at(b, 12)? {
        ETH_8021Q | ETH_8021AD => What::Tagged {
            vid: u16_at(b, 14)? & 0x0fff,
        },
        ETH_ARP => arp(body),
        ETH_IPV4 => ipv4(body)?,
        ETH_IPV6 => ipv6(body)?,
        _ => return None,
    };
    Some(Frame { src, what })
}

fn arp(b: &[u8]) -> What {
    let read = || {
        let eth_ipv4 = u16_at(b, 0)? == 1 && u16_at(b, 2)? == ETH_IPV4 && b.get(4..6)? == [6, 4];
        // Requests and replies; the target's addresses must be there too.
        let op = matches!(u16_at(b, 6)?, 1 | 2) && b.len() >= 28;
        (eth_ipv4 && op).then(|| (mac_at(b, 8), v4_at(b, 14)))
    };
    match read() {
        Some((Some(sha), Some(spa))) => What::Arp { sha, spa },
        _ => What::Arp {
            sha: [0; 6],
            spa: Ipv4Addr::UNSPECIFIED,
        },
    }
}

/// flower keys IPv4 on the EtherType and reads no version.
fn ipv4(b: &[u8]) -> Option<What> {
    let header = b.get(..20)?;
    let ihl = usize::from(header[0] & 0x0f) * 4;
    if ihl < 20 {
        return None;
    }
    let src = v4_at(header, 12)?;
    // More fragments, or an offset: flower reads no ports or flags of any
    // fragment.
    let fragment = u16_at(header, 6)? & 0x3fff != 0;
    let l4 = b.get(ihl..).unwrap_or_default();
    match header[9] {
        TCP if !fragment => {
            // Flags only from a whole header: SYN without ACK opens a
            // connection.
            let whole = l4.len() >= 20 && l4[12] >> 4 >= 5;
            (whole && l4[13] & 0x12 == 0x02).then_some(What::Conn { src })
        }
        UDP if fragment => Some(What::Conn { src }),
        UDP => {
            let msg = || dhcp::parse(l4.get(8..).unwrap_or_default());
            Some(match (u16_at(l4, 0), u16_at(l4, 2)) {
                (Some(67), Some(68)) => What::Dhcp {
                    src,
                    server: true,
                    msg: msg(),
                },
                (Some(68), Some(67)) => What::Dhcp {
                    src,
                    server: false,
                    msg: msg(),
                },
                _ => What::Conn { src },
            })
        }
        _ => None,
    }
}

fn ipv6(b: &[u8]) -> Option<What> {
    let src = v6_at(b, 8)?;
    let (mut nh, mut at, mut ext) = (*b.get(6)?, 40, Vec::new());
    while is_ext(nh) {
        if ext.len() > EXT_MAX {
            return Some(What::Hidden(Hidden::Deep));
        }
        if nh == FRAGMENT {
            let Some(h) = b.get(at..at + 8) else {
                return Some(What::Hidden(Hidden::Cut));
            };
            // A later fragment holds no header of what it carries.
            if u16::from_be_bytes([h[2], h[3]]) & 0xfff8 != 0 {
                return None;
            }
            ext.push((FRAGMENT, 0));
            return first_fragment(h[0], b.get(at + 8..).unwrap_or_default(), ext);
        }
        let (Some(&next), Some(&len)) = (b.get(at), b.get(at + 1)) else {
            return Some(What::Hidden(Hidden::Cut));
        };
        ext.push((nh, len));
        at += 8 * (usize::from(len) + 1);
        nh = next;
    }
    let deep = ext.len() > EXT_MAX;
    let l4 = b.get(at..).unwrap_or_default();
    match nh {
        // flower reads the type from a whole 8-byte header.
        ICMPV6 if deep => Some(What::Hidden(Hidden::Deep)),
        ICMPV6 if l4.len() < 8 || l4[0] == 0 => Some(What::Hidden(Hidden::Cut)),
        ICMPV6 if l4[0] == ROUTER_ADVERTISEMENT => Some(What::Ra(Ra { ext, ..ra(l4) })),
        UDP if (u16_at(l4, 0), u16_at(l4, 2)) == (Some(547), Some(546)) => {
            Some(What::Dhcp6Server {
                src,
                kind: l4.get(8).copied(),
            })
        }
        _ => None,
    }
}

/// A first fragment whose fragment header names `next`, `rest` after it.
fn first_fragment(next: u8, rest: &[u8], ext: Vec<(u8, u8)>) -> Option<What> {
    let ra = next == ICMPV6 && rest.len() >= 8 && rest[0] == ROUTER_ADVERTISEMENT;
    if ra {
        return Some(What::Ra(Ra {
            ext,
            ..self::ra(rest)
        }));
    }
    (next == ICMPV6 || is_ext(next)).then_some(What::Hidden(Hidden::Fragment))
}

/// A router advertisement's lifetime and options (RFC 4861 4.2, RFC 4191),
/// from `b`, at least its first 8 bytes.
fn ra(b: &[u8]) -> Ra {
    let mut ra = Ra {
        lifetime: u16_at(b, 6).unwrap_or_default(),
        malformed: b.len() < 16,
        ..Ra::default()
    };
    let mut opts = b.get(16..).unwrap_or_default();
    while !opts.is_empty() {
        let len = opts.get(1).map_or(0, |l| usize::from(*l) * 8);
        if len == 0 || len > opts.len() {
            ra.malformed = true;
            break;
        }
        let opt = &opts[..len];
        match opt[0] {
            3 if len == 32 => {
                let prefix = v6_at(opt, 16).unwrap_or(Ipv6Addr::UNSPECIFIED);
                ra.prefixes.push((prefix, opt[2], opt[3] & 0xc0));
            }
            24 => {
                // The prefix is cut to the option's length; the rest is zero.
                let mut p = [0u8; 16];
                let have = (len - 8).min(16);
                p[..have].copy_from_slice(&opt[8..8 + have]);
                ra.routes.push((p.into(), opt[2]));
            }
            25 | 31 => ra.dns = true,
            _ => {}
        }
        opts = &opts[len..];
    }
    ra
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub const CLIENT: [u8; 6] = [2, 0, 0, 0, 0, 1];

    fn ether(src: [u8; 6], kind: u16, body: &[u8]) -> Vec<u8> {
        let mut f = vec![0xff; 6];
        f.extend(src);
        f.extend(kind.to_be_bytes());
        f.extend(body);
        f
    }

    /// An ARP frame from `src` whose sender is `sha` at `spa`.
    pub fn arp_frame(src: [u8; 6], sha: [u8; 6], spa: [u8; 4], op: u16) -> Vec<u8> {
        let mut a = vec![0, 1, 8, 0, 6, 4];
        a.extend(op.to_be_bytes());
        a.extend(sha);
        a.extend(spa);
        a.extend([0; 6]);
        a.extend([192, 0, 2, 1]);
        ether(src, ETH_ARP, &a)
    }

    /// An IPv4 packet from `src` of protocol `proto` with `l4` after the header.
    pub fn ipv4_frame(mac: [u8; 6], src: [u8; 4], proto: u8, l4: &[u8]) -> Vec<u8> {
        let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, proto, 0, 0];
        ip.extend(src);
        ip.extend([198, 51, 100, 1]);
        ip.extend(l4);
        ether(mac, ETH_IPV4, &ip)
    }

    pub fn tcp(flags: u8) -> Vec<u8> {
        let mut t = vec![0xc3, 0x50, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, flags];
        t.extend([0; 6]);
        t
    }

    pub fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut u = sport.to_be_bytes().to_vec();
        u.extend(dport.to_be_bytes());
        u.extend([0; 4]);
        u.extend(payload);
        u
    }

    /// An IPv6 packet from `src` with next header `nh` and `l4`.
    pub fn ipv6_frame(mac: [u8; 6], nh: u8, l4: &[u8]) -> Vec<u8> {
        let mut ip = vec![0x60, 0, 0, 0];
        ip.extend((l4.len() as u16).to_be_bytes());
        ip.extend([nh, 255]);
        ip.extend("fe80::1".parse::<Ipv6Addr>().unwrap().octets());
        ip.extend("ff02::1".parse::<Ipv6Addr>().unwrap().octets());
        ip.extend(l4);
        ether(mac, ETH_IPV6, &ip)
    }

    /// A router advertisement with `lifetime` and the options `opts`.
    pub fn ra_body(lifetime: u16, opts: &[Vec<u8>]) -> Vec<u8> {
        let mut r = vec![ROUTER_ADVERTISEMENT, 0, 0, 0, 64, 0];
        r.extend(lifetime.to_be_bytes());
        r.extend([0; 8]);
        for o in opts {
            r.extend(o);
        }
        r
    }

    pub fn pio(prefix: &str, len: u8, flags: u8) -> Vec<u8> {
        let mut o = vec![
            3, 4, len, flags, 0, 0, 0x0e, 0x10, 0, 0, 0x0e, 0x10, 0, 0, 0, 0,
        ];
        o.extend(prefix.parse::<Ipv6Addr>().unwrap().octets());
        o
    }

    pub fn rio(prefix: &str, len: u8) -> Vec<u8> {
        let mut o = vec![24, 2, len, 0, 0, 0, 0x07, 0x08];
        o.extend(&prefix.parse::<Ipv6Addr>().unwrap().octets()[..8]);
        o
    }

    #[test]
    fn arp_is_read() {
        let f = parse(&arp_frame(CLIENT, CLIENT, [192, 0, 2, 10], 2)).unwrap();
        assert_eq!(
            f,
            Frame {
                src: CLIENT,
                what: What::Arp {
                    sha: CLIENT,
                    spa: Ipv4Addr::new(192, 0, 2, 10)
                }
            }
        );
        let mut bad = arp_frame(CLIENT, CLIENT, [192, 0, 2, 10], 2);
        // What flower cannot read, it reads as zeros: another address
        // length, an opcode other than a request's or a reply's, a cut.
        let unread = What::Arp {
            sha: [0; 6],
            spa: Ipv4Addr::UNSPECIFIED,
        };
        bad[18] = 4;
        assert_eq!(parse(&bad).unwrap().what, unread);
        let rarp = arp_frame(CLIENT, CLIENT, [192, 0, 2, 10], 3);
        assert_eq!(parse(&rarp).unwrap().what, unread);
        let cut = arp_frame(CLIENT, CLIENT, [192, 0, 2, 10], 2);
        assert_eq!(parse(&cut[..14 + 27]).unwrap().what, unread);
    }

    #[test]
    fn a_connection_opens_with_a_syn_or_a_datagram() {
        let src = Ipv4Addr::new(192, 0, 2, 10);
        let conn = Some(What::Conn { src });
        let what = |f: Vec<u8>| parse(&f).map(|f| f.what);
        assert_eq!(
            what(ipv4_frame(CLIENT, src.octets(), TCP, &tcp(0x02))),
            conn
        );
        // SYN-ACK, ACK: not a connection's first packet.
        assert_eq!(
            what(ipv4_frame(CLIENT, src.octets(), TCP, &tcp(0x12))),
            None
        );
        assert_eq!(
            what(ipv4_frame(CLIENT, src.octets(), TCP, &tcp(0x10))),
            None
        );
        assert_eq!(
            what(ipv4_frame(CLIENT, src.octets(), UDP, &udp(50000, 53, &[]))),
            conn
        );
        // Any UDP fragment, as flower knows its protocol; no TCP fragment,
        // as it reads no flags of one.
        let mut later = ipv4_frame(CLIENT, src.octets(), UDP, &udp(50000, 53, &[]));
        later[20] = 0x01;
        assert_eq!(what(later), conn, "a later UDP fragment");
        let mut first = ipv4_frame(CLIENT, src.octets(), TCP, &tcp(0x02));
        first[20] = 0x20;
        assert_eq!(what(first), None, "a first TCP fragment");
        // A TCP header cut short, or saying it is shorter than 20 bytes.
        let syn = ipv4_frame(CLIENT, src.octets(), TCP, &tcp(0x02));
        assert_eq!(what(syn[..syn.len() - 1].to_vec()), None);
        let mut short = syn.clone();
        short[34 + 12] = 0x40;
        assert_eq!(what(short), None);
        // UDP whose ports are cut off: flower still knows it is UDP.
        assert_eq!(what(ipv4_frame(CLIENT, src.octets(), UDP, &[0xc3])), conn);
        assert_eq!(what(ipv4_frame(CLIENT, src.octets(), 1, &[8, 0])), None);
    }

    #[test]
    fn dhcp_is_told_from_its_ports() {
        let ack = dhcp::tests::message(2, 5, [192, 0, 2, 10], Some(3600));
        let f = parse(&ipv4_frame(CLIENT, [192, 0, 2, 1], UDP, &udp(67, 68, &ack))).unwrap();
        let What::Dhcp {
            server,
            msg: Some(msg),
            ..
        } = f.what
        else {
            panic!("{f:?}")
        };
        assert!(server);
        assert_eq!(
            (msg.kind, msg.yiaddr),
            (Some(5), Ipv4Addr::new(192, 0, 2, 10))
        );
        let req = dhcp::tests::message(1, 3, [0; 4], None);
        let f = parse(&ipv4_frame(CLIENT, [0; 4], UDP, &udp(68, 67, &req))).unwrap();
        assert!(matches!(
            f.what,
            What::Dhcp {
                server: false,
                msg: Some(_),
                ..
            }
        ));
        // Exactly the ports the filters match: anything on the server port
        // to the client's is a server message, malformed or not; other
        // traffic on those ports is a datagram like any.
        let what = |f: Vec<u8>| parse(&f).unwrap().what;
        let src = Ipv4Addr::new(192, 0, 2, 66);
        assert_eq!(
            what(ipv4_frame(CLIENT, src.octets(), UDP, &udp(67, 68, &[1, 2]))),
            What::Dhcp {
                src,
                server: true,
                msg: None
            }
        );
        assert_eq!(
            what(ipv4_frame(CLIENT, src.octets(), UDP, &udp(67, 67, &ack))),
            What::Conn { src }
        );
        let v6 = udp(547, 546, &[7, 0, 0, 1]);
        assert!(matches!(
            what(ipv6_frame(CLIENT, UDP, &v6)),
            What::Dhcp6Server { kind: Some(7), .. }
        ));
        // flower sees through extension headers.
        let (nh, behind_hbh) = behind(&[(HOP_BY_HOP, 0)], UDP, &v6);
        assert!(matches!(
            what(ipv6_frame(CLIENT, nh, &behind_hbh)),
            What::Dhcp6Server { kind: Some(7), .. }
        ));
        assert!(matches!(
            what(ipv6_frame(CLIENT, UDP, &udp(547, 546, &[]))),
            What::Dhcp6Server { kind: None, .. }
        ));
        assert_eq!(parse(&ipv6_frame(CLIENT, UDP, &udp(547, 547, &[7]))), None);
    }

    #[test]
    fn router_advertisements_are_read_with_their_options() {
        let body = ra_body(
            1800,
            &[
                pio("2001:db8:1::", 64, 0xc0),
                vec![1, 1, 2, 0, 0, 0, 0, 1],
                vec![
                    25, 3, 0, 0, 0, 0, 0x0e, 0x10, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0x53,
                ],
                rio("fd00:1:2:3::", 64),
            ],
        );
        let f = parse(&ipv6_frame(CLIENT, ICMPV6, &body)).unwrap();
        assert_eq!(
            f.what,
            What::Ra(Ra {
                lifetime: 1800,
                prefixes: vec![("2001:db8:1::".parse().unwrap(), 64, 0xc0)],
                routes: vec![("fd00:1:2:3::".parse().unwrap(), 64)],
                dns: true,
                ext: vec![],
                malformed: false,
            })
        );
        // An option claiming more than the packet holds, or a body cut
        // short: malformed, its lifetime still read, as the filters read it.
        let mut bad = ra_body(1800, &[vec![3, 9, 0, 0]]);
        bad.extend([0; 4]);
        let ra = |b: &[u8]| match parse(&ipv6_frame(CLIENT, ICMPV6, b)).unwrap().what {
            What::Ra(ra) => ra,
            w => panic!("{w:?}"),
        };
        assert_eq!((ra(&bad).lifetime, ra(&bad).malformed), (1800, true));
        assert!(ra(&ra_body(0, &[])[..8]).malformed);
        // Other ICMPv6 messages are not read; one flower cannot read the
        // type of is hidden.
        let ns = [135, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(parse(&ipv6_frame(CLIENT, ICMPV6, &ns)), None);
        let hidden = |b: &[u8]| parse(&ipv6_frame(CLIENT, ICMPV6, b)).unwrap().what;
        assert_eq!(hidden(&ns[..7]), What::Hidden(Hidden::Cut));
        assert_eq!(hidden(&[0; 8]), What::Hidden(Hidden::Cut));
    }

    /// `l4` behind the extension headers `ext` (each a type and length
    /// field; a fragment header is the first fragment's).
    pub fn behind(ext: &[(u8, u8)], last: u8, l4: &[u8]) -> (u8, Vec<u8>) {
        let mut out = Vec::new();
        let types: Vec<u8> = ext.iter().map(|(t, _)| *t).skip(1).chain([last]).collect();
        for ((_, len), next) in ext.iter().zip(types) {
            let size = if ext[0].0 == FRAGMENT {
                8
            } else {
                8 * (usize::from(*len) + 1)
            };
            let mut h = vec![0u8; size];
            h[0] = next;
            h[1] = *len;
            out.extend(h);
        }
        out.extend(l4);
        (ext.first().map_or(last, |(t, _)| *t), out)
    }

    #[test]
    fn a_router_advertisement_behind_extension_headers_is_one() {
        let body = ra_body(0, &[]);
        for ext in [
            vec![(HOP_BY_HOP, 0)],
            vec![(DESTINATION, 2), (HOP_BY_HOP, 0)],
            vec![(FRAGMENT, 0)],
        ] {
            let (nh, payload) = behind(&ext, ICMPV6, &body);
            let f = parse(&ipv6_frame(CLIENT, nh, &payload)).unwrap();
            let What::Ra(ra) = f.what else {
                panic!("{f:?}")
            };
            assert_eq!(ra.ext.len(), ext.len(), "{ext:?}");
        }
        // A later fragment carries no header to read.
        let (nh, mut payload) = behind(&[(FRAGMENT, 0)], ICMPV6, &body);
        payload[3] = 0x08;
        assert_eq!(parse(&ipv6_frame(CLIENT, nh, &payload)), None);
    }

    #[test]
    fn icmpv6_flower_cannot_read_the_type_of_is_hidden() {
        let what = |ext: &[(u8, u8)], last, l4: &[u8]| {
            let (nh, payload) = behind(ext, last, l4);
            parse(&ipv6_frame(CLIENT, nh, &payload)).map(|f| f.what)
        };
        let ra = ra_body(1800, &[]);
        let echo = [128, 0, 0, 0, 0, 1, 0, 1];
        // First fragments: of ICMPv6 that is no advertisement, or of more
        // extension headers; a first fragment of anything else is nothing.
        let first = [(FRAGMENT, 0)];
        let hidden = Some(What::Hidden(Hidden::Fragment));
        assert_eq!(what(&first, ICMPV6, &echo), hidden);
        assert_eq!(
            what(&first, DESTINATION, &[ICMPV6, 0, 0, 0, 0, 0, 0, 0]),
            hidden
        );
        assert_eq!(what(&first, UDP, &udp(547, 546, &[7])), None);
        assert!(matches!(what(&first, ICMPV6, &ra), Some(What::Ra(_))));
        // Its depth: read behind 15 extension headers, its type unread
        // behind 16 (ports still read), its protocol behind 17.
        let dest = |n| vec![(DESTINATION, 0); n];
        assert!(matches!(
            what(&dest(EXT_MAX), ICMPV6, &ra),
            Some(What::Ra(_))
        ));
        let deep = Some(What::Hidden(Hidden::Deep));
        assert_eq!(what(&dest(EXT_MAX + 1), ICMPV6, &ra), deep);
        assert_eq!(what(&dest(EXT_MAX + 2), ICMPV6, &ra), deep);
        assert_eq!(what(&dest(EXT_MAX + 2), UDP, &udp(1, 2, &[])), deep);
        assert!(matches!(
            what(&dest(EXT_MAX + 1), UDP, &udp(547, 546, &[7])),
            Some(What::Dhcp6Server { .. })
        ));
        // An extension header cut short.
        let (nh, payload) = behind(&[(DESTINATION, 0)], DESTINATION, &[]);
        let cut = parse(&ipv6_frame(CLIENT, nh, &payload)).map(|f| f.what);
        assert_eq!(cut, Some(What::Hidden(Hidden::Cut)));
    }

    #[test]
    fn a_tagged_frame_is_read_as_one_whatever_it_carries() {
        let mut f = arp_frame(CLIENT, CLIENT, [192, 0, 2, 10], 1);
        let tag = [0x81, 0x00, 0x20, 0x2a];
        f.splice(12..12, tag);
        assert_eq!(parse(&f).unwrap().what, What::Tagged { vid: 42 });
        f[12..14].copy_from_slice(&[0x88, 0xa8]);
        f[14..16].copy_from_slice(&[0, 0]);
        assert_eq!(parse(&f).unwrap().what, What::Tagged { vid: 0 });
    }
}
