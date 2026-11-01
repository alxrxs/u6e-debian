//! The frames the guards look at, read from their Ethernet bytes: ARP, DHCP
//! and DHCPv6 messages, router advertisements, and the first packet of a
//! client's IPv4 connection (a TCP SYN or a UDP datagram). Everything else,
//! and anything too short or malformed, reads as nothing.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::dhcp::{self, Message};

const ETH_ARP: u16 = 0x0806;
const ETH_IPV4: u16 = 0x0800;
const ETH_IPV6: u16 = 0x86dd;
const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMPV6: u8 = 58;
const ROUTER_ADVERTISEMENT: u8 = 134;

/// A frame of interest, with the MAC that sent it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub src: [u8; 6],
    pub what: What,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum What {
    Arp {
        /// The sender's hardware and protocol addresses.
        sha: [u8; 6],
        spa: Ipv4Addr,
    },
    /// A DHCP message, from either end.
    Dhcp {
        src: Ipv4Addr,
        server: bool,
        msg: Message,
    },
    /// A DHCPv6 message from the servers' port, of this type.
    Dhcp6Server {
        src: Ipv6Addr,
        kind: u8,
    },
    Ra(Ra),
    /// The first packet of a connection, or any datagram.
    Conn {
        src: Ipv4Addr,
    },
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

/// The frame in `b`, an Ethernet frame as the packet socket gives it.
pub fn parse(b: &[u8]) -> Option<Frame> {
    let src = mac_at(b, 6)?;
    let what = match u16_at(b, 12)? {
        ETH_ARP => arp(&b[14..])?,
        ETH_IPV4 => ipv4(&b[14..])?,
        ETH_IPV6 => ipv6(&b[14..])?,
        _ => return None,
    };
    Some(Frame { src, what })
}

fn arp(b: &[u8]) -> Option<What> {
    // Ethernet and IPv4 only.
    if u16_at(b, 0)? != 1 || u16_at(b, 2)? != ETH_IPV4 || b.get(4..6)? != [6, 4] {
        return None;
    }
    Some(What::Arp {
        sha: mac_at(b, 8)?,
        spa: v4_at(b, 14)?,
    })
}

fn ipv4(b: &[u8]) -> Option<What> {
    let ihl = usize::from(b.first()? & 0x0f) * 4;
    // A fragment past the first carries no header of its own.
    if b.first()? >> 4 != 4 || ihl < 20 || u16_at(b, 6)? & 0x1fff != 0 {
        return None;
    }
    let src = v4_at(b, 12)?;
    let l4 = b.get(ihl..)?;
    match *b.get(9)? {
        TCP => {
            let flags = *l4.get(13)?;
            // SYN without ACK: a connection being opened.
            (flags & 0x12 == 0x02).then_some(What::Conn { src })
        }
        UDP => {
            let (sport, dport) = (u16_at(l4, 0)?, u16_at(l4, 2)?);
            if matches!((sport, dport), (67 | 68, 67 | 68)) {
                let msg = dhcp::parse(l4.get(8..)?)?;
                return Some(What::Dhcp {
                    src,
                    server: sport == 67,
                    msg,
                });
            }
            Some(What::Conn { src })
        }
        _ => None,
    }
}

fn ipv6(b: &[u8]) -> Option<What> {
    if b.first()? >> 4 != 6 {
        return None;
    }
    let src = v6_at(b, 8)?;
    let l4 = b.get(40..)?;
    match *b.get(6)? {
        ICMPV6 if *l4.first()? == ROUTER_ADVERTISEMENT => Some(What::Ra(ra(l4)?)),
        UDP if u16_at(l4, 0)? == 547 => Some(What::Dhcp6Server {
            src,
            kind: *l4.get(8)?,
        }),
        _ => None,
    }
}

/// A router advertisement's lifetime and options (RFC 4861 4.2, RFC 4191).
fn ra(b: &[u8]) -> Option<Ra> {
    let mut ra = Ra {
        lifetime: u16_at(b, 6)?,
        ..Ra::default()
    };
    let mut opts = b.get(16..)?;
    while opts.len() >= 2 {
        let len = usize::from(opts[1]) * 8;
        if len == 0 || len > opts.len() {
            return None;
        }
        let opt = &opts[..len];
        match opt[0] {
            3 if len == 32 => ra.prefixes.push((v6_at(opt, 16)?, opt[2], opt[3] & 0xc0)),
            24 => {
                // The prefix is cut to the option's length; the rest is zero.
                let mut p = [0u8; 16];
                let have = (len - 8).min(16);
                p[..have].copy_from_slice(&opt[8..8 + have]);
                ra.routes.push((p.into(), opt[2]));
            }
            _ => {}
        }
        opts = &opts[len..];
    }
    Some(ra)
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
        bad[18] = 4;
        assert_eq!(parse(&bad), None);
        assert_eq!(parse(&bad[..20]), None);
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
        let mut later = ipv4_frame(CLIENT, src.octets(), UDP, &udp(50000, 53, &[]));
        later[20] = 0x01;
        assert_eq!(what(later), None, "a later fragment");
        assert_eq!(what(ipv4_frame(CLIENT, src.octets(), 1, &[8, 0])), None);
    }

    #[test]
    fn dhcp_is_told_from_its_ports() {
        let ack = dhcp::tests::message(2, 5, [192, 0, 2, 10], Some(3600));
        let f = parse(&ipv4_frame(CLIENT, [192, 0, 2, 1], UDP, &udp(67, 68, &ack))).unwrap();
        let What::Dhcp { server, msg, .. } = f.what else {
            panic!("{f:?}")
        };
        assert!(server);
        assert_eq!(
            (msg.kind, msg.yiaddr),
            (Some(5), Ipv4Addr::new(192, 0, 2, 10))
        );
        let req = dhcp::tests::message(1, 3, [0; 4], None);
        let f = parse(&ipv4_frame(CLIENT, [0; 4], UDP, &udp(68, 67, &req))).unwrap();
        assert!(matches!(f.what, What::Dhcp { server: false, .. }));
        let v6 = udp(547, 546, &[7, 0, 0, 1]);
        let f = parse(&ipv6_frame(CLIENT, UDP, &v6)).unwrap();
        assert!(matches!(f.what, What::Dhcp6Server { kind: 7, .. }));
    }

    #[test]
    fn router_advertisements_are_read_with_their_options() {
        let body = ra_body(
            1800,
            &[
                pio("2001:db8:1::", 64, 0xc0),
                vec![1, 1, 2, 0, 0, 0, 0, 1],
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
            })
        );
        // An option claiming more than the packet holds: not a valid RA.
        let mut bad = ra_body(0, &[vec![3, 9, 0, 0]]);
        bad.extend([0; 4]);
        assert_eq!(parse(&ipv6_frame(CLIENT, ICMPV6, &bad)), None);
        // Other ICMPv6 messages are not read.
        assert_eq!(parse(&ipv6_frame(CLIENT, ICMPV6, &[135, 0, 0, 0])), None);
    }
}
