//! The capture's file, pcapng (draft-ietf-opsawg-pcapng): a section header
//! saying where it was taken, an interface description for each interface
//! and link type as it is first seen (nanosecond timestamps), and an
//! enhanced packet block per packet, its direction in its flags. Every block
//! is written whole, little endian, so the file can be cut into chunks
//! anywhere between blocks.

const SHB: u32 = 0x0A0D_0D0A;
const IDB: u32 = 1;
const EPB: u32 = 6;
const BYTE_ORDER: u32 = 0x1A2B_3C4D;
const OPT_END: u16 = 0;
const OPT_COMMENT: u16 = 1;
const SHB_USERAPPL: u16 = 4;
const IF_NAME: u16 = 2;
const IF_TSRESOL: u16 = 9;
const EPB_FLAGS: u16 = 2;

/// The link types a capture has: frames from a port, and IP packets with no
/// link header (as a mirror may copy them).
pub const ETHERNET: u16 = 1;
pub const RAW: u16 = 101;

/// Which way a packet went, from the AP's side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

fn option(out: &mut Vec<u8>, code: u16, value: &[u8]) {
    out.extend(code.to_le_bytes());
    out.extend((value.len() as u16).to_le_bytes());
    out.extend(value);
    out.resize(out.len().next_multiple_of(4), 0);
}

/// A block of `kind` with `body` (options included, already padded).
fn block(kind: u32, body: &[u8]) -> Vec<u8> {
    let len = (12 + body.len()) as u32;
    let mut out = Vec::with_capacity(len as usize);
    out.extend(kind.to_le_bytes());
    out.extend(len.to_le_bytes());
    out.extend(body);
    out.extend(len.to_le_bytes());
    out
}

/// The section header: `comment` says where and what was captured.
pub fn section(comment: &str) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(BYTE_ORDER.to_le_bytes());
    b.extend(1u16.to_le_bytes());
    b.extend(0u16.to_le_bytes());
    b.extend((-1i64).to_le_bytes());
    option(&mut b, SHB_USERAPPL, b"u6e-capture");
    option(&mut b, OPT_COMMENT, comment.as_bytes());
    option(&mut b, OPT_END, &[]);
    block(SHB, &b)
}

/// An interface `name` of `linktype`, packets cut at `snaplen`.
pub fn interface(name: &str, linktype: u16, snaplen: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(linktype.to_le_bytes());
    b.extend(0u16.to_le_bytes());
    b.extend(snaplen.to_le_bytes());
    option(&mut b, IF_NAME, name.as_bytes());
    option(&mut b, IF_TSRESOL, &[9]);
    option(&mut b, OPT_END, &[]);
    block(IDB, &b)
}

/// A packet of interface `id` at `ts_ns` (since the Unix epoch): `data` as
/// captured, `orig_len` as it was, and its direction when it is known.
pub fn packet(id: u32, ts_ns: u64, data: &[u8], orig_len: u32, dir: Option<Direction>) -> Vec<u8> {
    let mut b = Vec::with_capacity(32 + data.len());
    b.extend(id.to_le_bytes());
    b.extend(((ts_ns >> 32) as u32).to_le_bytes());
    b.extend((ts_ns as u32).to_le_bytes());
    b.extend((data.len() as u32).to_le_bytes());
    b.extend(orig_len.to_le_bytes());
    b.extend(data);
    b.resize(b.len().next_multiple_of(4), 0);
    if let Some(d) = dir {
        let flags: u32 = match d {
            Direction::Inbound => 1,
            Direction::Outbound => 2,
        };
        option(&mut b, EPB_FLAGS, &flags.to_le_bytes());
    }
    option(&mut b, OPT_END, &[]);
    block(EPB, &b)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A block read back: its type and its body.
    pub fn blocks(mut b: &[u8]) -> Vec<(u32, Vec<u8>)> {
        let mut out = Vec::new();
        while !b.is_empty() {
            let kind = u32::from_le_bytes(b[0..4].try_into().unwrap());
            let len = u32::from_le_bytes(b[4..8].try_into().unwrap()) as usize;
            assert_eq!(len % 4, 0, "a block is padded");
            let trailer = u32::from_le_bytes(b[len - 4..len].try_into().unwrap()) as usize;
            assert_eq!(len, trailer, "a block ends with its length");
            out.push((kind, b[8..len - 4].to_vec()));
            b = &b[len..];
        }
        out
    }

    /// The options of a block body after its `fixed` bytes.
    fn options(body: &[u8], fixed: usize) -> Vec<(u16, Vec<u8>)> {
        let mut o = &body[fixed..];
        let mut out = Vec::new();
        loop {
            let code = u16::from_le_bytes([o[0], o[1]]);
            let len = u16::from_le_bytes([o[2], o[3]]) as usize;
            if code == OPT_END {
                return out;
            }
            out.push((code, o[4..4 + len].to_vec()));
            o = &o[4 + len.next_multiple_of(4)..];
        }
    }

    #[test]
    fn blocks_read_back_as_written() {
        let mut file = section("ap1: client 02:00:00:00:00:01");
        file.extend(interface("wlan5.42", ETHERNET, 128));
        let data = [7u8; 61];
        file.extend(packet(
            0,
            1_792_929_600_123_456_789,
            &data,
            1500,
            Some(Direction::Outbound),
        ));
        file.extend(packet(0, 1, &data[..4], 4, None));
        let b = blocks(&file);
        assert_eq!(
            b.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            [SHB, IDB, EPB, EPB]
        );
        assert!(options(&b[3].1, 24).is_empty(), "no direction, no flags");
        let shb = options(&b[0].1, 16);
        assert_eq!(
            shb[1],
            (OPT_COMMENT, b"ap1: client 02:00:00:00:00:01".to_vec())
        );
        assert_eq!(u16::from_le_bytes([b[1].1[0], b[1].1[1]]), ETHERNET);
        assert_eq!(options(&b[1].1, 8)[0], (IF_NAME, b"wlan5.42".to_vec()));
        let epb = &b[2].1;
        let ts = u64::from(u32::from_le_bytes(epb[4..8].try_into().unwrap())) << 32
            | u64::from(u32::from_le_bytes(epb[8..12].try_into().unwrap()));
        assert_eq!(ts, 1_792_929_600_123_456_789);
        assert_eq!(&epb[12..20], [61, 0, 0, 0, 0xdc, 0x05, 0, 0]);
        assert_eq!(&epb[20..81], &data);
        assert_eq!(options(epb, 84), [(EPB_FLAGS, 2u32.to_le_bytes().to_vec())]);
    }
}
