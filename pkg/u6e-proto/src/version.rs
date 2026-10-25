//! The version frame: the first frame each end of the link sends, stating the
//! protocol its messages follow.
//!
//! postcard does not describe what it encodes, so a message of one layout read
//! as another fails, or worse, decodes as something else. The version frame is
//! therefore frozen, never changed by any protocol: the four bytes `u6ep` and
//! the protocol as a u16, little endian, in the usual length-prefixed framing.
//! Each end reads the other's before it decodes a message, and only two ends
//! of the same protocol go on. The agents from before this frame open with
//! their Hello; any first frame not of this form is theirs, protocol 0.

/// The protocol of the messages of [`crate::msg`] and their delta coding;
/// bumped with every change an end built before it could not decode.
pub const PROTOCOL: u16 = 1;

/// The protocol of a peer whose first frame is no version frame: the link as
/// it was before there was one.
pub const UNVERSIONED: u16 = 0;

const MAGIC: [u8; 4] = *b"u6ep";

/// The version frame stating `protocol`, length prefix included.
pub fn frame(protocol: u16) -> [u8; 10] {
    let mut f = [0; 10];
    f[..4].copy_from_slice(&6u32.to_le_bytes());
    f[4..8].copy_from_slice(&MAGIC);
    f[8..].copy_from_slice(&protocol.to_le_bytes());
    f
}

/// The protocol a peer's first frame body states; [`UNVERSIONED`] for a body
/// that is not a version frame.
pub fn decode(body: &[u8]) -> u16 {
    match body.split_first_chunk::<4>() {
        Some((magic, &[lo, hi])) if *magic == MAGIC => u16::from_le_bytes([lo, hi]),
        _ => UNVERSIONED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{decode_frame, frame_body};
    use crate::msg::{AgentMsg, CtlMsg};

    #[test]
    fn the_frame_is_frozen() {
        // Every version past and future reads exactly these bytes.
        assert_eq!(frame(0x0102), *b"\x06\0\0\0u6ep\x02\x01");
    }

    #[test]
    fn frames_state_their_protocol() {
        for p in [0, 1, PROTOCOL, PROTOCOL + 1, u16::MAX] {
            let f = frame(p);
            let (body, n) = frame_body(&f).unwrap().unwrap();
            assert_eq!((decode(body), n), (p, f.len()));
        }
    }

    /// The first frame of an agent from before the version frame: its Hello,
    /// as the 58e88f8 agent wrote it.
    const HELLO_V0: &str =
        "2100000000036170310b696d6167653a207465737404362e313204322e313105312e302e30";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn anything_else_is_unversioned() {
        let hello = unhex(HELLO_V0);
        let (body, _) = frame_body(&hello).unwrap().unwrap();
        assert_eq!(decode(body), UNVERSIONED);
        for body in [
            &b""[..],
            b"u6ep",
            b"u6ep\x01",
            b"u6ep\x01\0\0",
            b"u6eq\x01\0",
        ] {
            assert_eq!(decode(body), UNVERSIONED, "{body:?}");
        }
    }

    /// An end from before the version frame reads it as a message it does
    /// not know and ends the session, rather than mistaking it for one.
    #[test]
    fn an_unversioned_end_refuses_the_frame() {
        let f = frame(PROTOCOL);
        assert!(decode_frame::<CtlMsg>(&f).is_err());
        assert!(decode_frame::<AgentMsg>(&f).is_err());
    }
}
