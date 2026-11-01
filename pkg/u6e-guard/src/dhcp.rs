//! The parts of a DHCP message (RFC 2131) the guards use: who it is for,
//! the address it assigns, its type and the lease's length.

use std::net::Ipv4Addr;

/// The fixed fields before the options, and the magic cookie.
const OPTIONS: usize = 240;
const COOKIE: [u8; 4] = [99, 130, 83, 99];

pub const ACK: u8 = 5;
pub const DECLINE: u8 = 4;
pub const RELEASE: u8 = 7;

/// A DHCP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// 1 from a client, 2 from a server.
    pub op: u8,
    pub chaddr: [u8; 6],
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    /// Option 53, the message's type.
    pub kind: Option<u8>,
    /// Option 51, the lease's length in seconds.
    pub lease_s: Option<u32>,
}

/// The message in `b`, a UDP payload; only Ethernet clients.
pub fn parse(b: &[u8]) -> Option<Message> {
    if b.get(1..3)? != [1, 6] || b.get(236..OPTIONS)? != COOKIE {
        return None;
    }
    let addr = |at: usize| -> Option<Ipv4Addr> {
        let o: [u8; 4] = b.get(at..at + 4)?.try_into().ok()?;
        Some(o.into())
    };
    let mut msg = Message {
        op: b[0],
        chaddr: b.get(28..34)?.try_into().ok()?,
        ciaddr: addr(12)?,
        yiaddr: addr(16)?,
        kind: None,
        lease_s: None,
    };
    let mut opts = &b[OPTIONS..];
    while let Some((&code, rest)) = opts.split_first() {
        match code {
            0 => {
                opts = rest;
                continue;
            }
            255 => break,
            _ => {}
        }
        let (&len, rest) = rest.split_first()?;
        let value = rest.get(..usize::from(len))?;
        match (code, value) {
            (53, &[k]) => msg.kind = Some(k),
            (51, &[a, b, c, d]) => msg.lease_s = Some(u32::from_be_bytes([a, b, c, d])),
            _ => {}
        }
        opts = &rest[usize::from(len)..];
    }
    Some(msg)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A message of `op` and `kind` assigning `yiaddr` to 02:00:00:00:00:01.
    pub fn message(op: u8, kind: u8, yiaddr: [u8; 4], lease_s: Option<u32>) -> Vec<u8> {
        let mut m = vec![0u8; OPTIONS];
        m[0] = op;
        m[1] = 1;
        m[2] = 6;
        m[16..20].copy_from_slice(&yiaddr);
        m[28..34].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        m[236..240].copy_from_slice(&COOKIE);
        m.extend([0, 53, 1, kind]);
        if let Some(s) = lease_s {
            m.extend([51, 4]);
            m.extend(s.to_be_bytes());
        }
        m.push(255);
        m
    }

    #[test]
    fn a_message_is_read_with_its_options() {
        let m = parse(&message(2, ACK, [192, 0, 2, 10], Some(86_400))).unwrap();
        assert_eq!(
            m,
            Message {
                op: 2,
                chaddr: [2, 0, 0, 0, 0, 1],
                ciaddr: Ipv4Addr::UNSPECIFIED,
                yiaddr: Ipv4Addr::new(192, 0, 2, 10),
                kind: Some(ACK),
                lease_s: Some(86_400),
            }
        );
    }

    #[test]
    fn malformed_messages_are_refused() {
        let good = message(2, ACK, [192, 0, 2, 10], Some(60));
        let mut cookie = good.clone();
        cookie[239] = 0;
        assert_eq!(parse(&cookie), None);
        let mut token_ring = good.clone();
        token_ring[1] = 6;
        assert_eq!(parse(&token_ring), None);
        // An option running past the end.
        let mut cut = good[..OPTIONS].to_vec();
        cut.extend([51, 4, 0]);
        assert_eq!(parse(&cut), None);
        assert_eq!(parse(&good[..100]), None);
    }
}
