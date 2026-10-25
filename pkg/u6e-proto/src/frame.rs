//! Length-prefixed frames: a u32 little-endian length, then the postcard
//! encoding of one message. A frame read is wiped once decoded, and one that
//! holds secrets (a Wi-Fi configuration) can be written the same way.

use std::io::{self, ErrorKind, Read, Write};

use serde::Serialize;
use serde::de::DeserializeOwned;

/// The largest frame either side accepts or sends.
pub const MAX_FRAME: u32 = 1 << 20;

/// Writes one frame.
pub fn write_frame<W: Write>(w: &mut W, msg: &impl Serialize) -> io::Result<()> {
    // One write, so a frame is never split across TLS records by its prefix.
    w.write_all(&encode(msg)?)
}

/// Writes one frame that holds secrets, its encoding wiped once written.
pub fn write_secret_frame<W: Write>(w: &mut W, msg: &impl Serialize) -> io::Result<()> {
    let mut buf = encode(msg)?;
    let r = w.write_all(&buf);
    zeroize(&mut buf);
    r
}

/// A frame of `msg`, length prefix included; what was encoded of one too
/// large is wiped.
fn encode(msg: &impl Serialize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0; 4];
    postcard::to_io(msg, &mut buf).map_err(invalid)?;
    let len = u32::try_from(buf.len() - 4)
        .ok()
        .filter(|&n| n <= MAX_FRAME);
    let Some(len) = len else {
        zeroize(&mut buf);
        return Err(io::Error::new(ErrorKind::InvalidInput, "frame too large"));
    };
    buf[..4].copy_from_slice(&len.to_le_bytes());
    Ok(buf)
}

/// Reads one frame; a length above [`MAX_FRAME`] is refused before anything is
/// allocated for it.
pub fn read_frame<R: Read, T: DeserializeOwned>(r: &mut R) -> io::Result<T> {
    let mut body = read_body(r)?;
    let msg = postcard::from_bytes(&body).map_err(invalid);
    zeroize(&mut body);
    msg
}

fn read_body<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut len = [0; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len);
    if len > MAX_FRAME {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("frame of {len} B exceeds {MAX_FRAME}"),
        ));
    }
    let mut body = vec![0; len as usize];
    r.read_exact(&mut body)?;
    Ok(body)
}

/// Overwrites `buf` with zeros in a way the compiler keeps, for memory that
/// held secrets and is about to be freed or reused.
pub fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, aligned reference to one byte.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Decodes the first frame of `buf` and returns it with the bytes it took, or
/// `None` while `buf` holds only part of one. For a reader that accumulates
/// bytes from a stream that can time out, where [`read_frame`] would lose its
/// place mid-frame.
pub fn decode_frame<T: DeserializeOwned>(buf: &[u8]) -> io::Result<Option<(T, usize)>> {
    let Some((body, end)) = frame_body(buf)? else {
        return Ok(None);
    };
    Ok(Some((postcard::from_bytes(body).map_err(invalid)?, end)))
}

/// The body of the first frame of `buf`, undecoded, with the bytes the frame
/// took; `None` while `buf` holds only part of it. A length above
/// [`MAX_FRAME`] is refused without waiting for the body.
pub fn frame_body(buf: &[u8]) -> io::Result<Option<(&[u8], usize)>> {
    let Some(prefix) = buf.first_chunk::<4>() else {
        return Ok(None);
    };
    let len = u32::from_le_bytes(*prefix);
    if len > MAX_FRAME {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("frame of {len} B exceeds {MAX_FRAME}"),
        ));
    }
    let end = 4 + len as usize;
    Ok(buf.get(4..end).map(|body| (body, end)))
}

fn invalid(e: postcard::Error) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::{AgentMsg, CtlMsg};

    /// A frame with secrets goes out as any other; only the copy left
    /// behind differs, and zeroize leaves nothing of it.
    #[test]
    fn a_secret_frame_is_an_ordinary_frame() {
        let (mut plain, mut secret) = (Vec::new(), Vec::new());
        write_frame(&mut plain, &AgentMsg::Pong(7)).unwrap();
        write_secret_frame(&mut secret, &AgentMsg::Pong(7)).unwrap();
        assert_eq!(plain, secret);
        zeroize(&mut secret);
        assert!(secret.iter().all(|&b| b == 0));
    }

    #[test]
    fn frames_roundtrip_back_to_back() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &AgentMsg::Pong(7)).unwrap();
        write_frame(&mut buf, &AgentMsg::Pong(8)).unwrap();
        let mut r = buf.as_slice();
        assert_eq!(
            read_frame::<_, AgentMsg>(&mut r).unwrap(),
            AgentMsg::Pong(7)
        );
        assert_eq!(
            read_frame::<_, AgentMsg>(&mut r).unwrap(),
            AgentMsg::Pong(8)
        );
        assert_eq!(
            read_frame::<_, AgentMsg>(&mut r).unwrap_err().kind(),
            ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn ctl_messages_roundtrip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &CtlMsg::SetTick { secs: 2 }).unwrap();
        assert_eq!(
            read_frame::<_, CtlMsg>(&mut buf.as_slice()).unwrap(),
            CtlMsg::SetTick { secs: 2 }
        );
    }

    #[test]
    fn oversized_frame_rejected() {
        let buf = (MAX_FRAME + 1).to_le_bytes();
        let e = read_frame::<_, AgentMsg>(&mut buf.as_slice()).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn oversized_frame_not_written() {
        let hello = AgentMsg::Hello(crate::msg::Hello {
            ap: String::new(),
            manifest: "x".repeat(MAX_FRAME as usize),
            kernel: String::new(),
            hostapd: String::new(),
            agent: String::new(),
        });
        let mut buf = Vec::new();
        let e = write_frame(&mut buf, &hello).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput);
        assert!(buf.is_empty());
    }

    #[test]
    fn garbage_body_is_invalid_data() {
        let mut buf = 2u32.to_le_bytes().to_vec();
        buf.extend([0xff, 0xff]);
        let e = read_frame::<_, AgentMsg>(&mut buf.as_slice()).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn decode_frame_waits_for_the_whole_frame() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &AgentMsg::Pong(7)).unwrap();
        write_frame(&mut buf, &AgentMsg::Pong(8)).unwrap();
        let first = 4 + u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
        for cut in 0..first {
            assert!(decode_frame::<AgentMsg>(&buf[..cut]).unwrap().is_none());
        }
        let (msg, n) = decode_frame::<AgentMsg>(&buf).unwrap().unwrap();
        assert_eq!((msg, n), (AgentMsg::Pong(7), first));
        let (msg, n2) = decode_frame::<AgentMsg>(&buf[n..]).unwrap().unwrap();
        assert_eq!((msg, n + n2), (AgentMsg::Pong(8), buf.len()));
    }

    #[test]
    fn decode_frame_refuses_oversize_before_the_body() {
        let buf = (MAX_FRAME + 1).to_le_bytes();
        let e = decode_frame::<AgentMsg>(&buf).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn decode_frame_garbage_is_invalid_data() {
        let mut buf = 2u32.to_le_bytes().to_vec();
        buf.extend([0xff, 0xff]);
        let e = decode_frame::<AgentMsg>(&buf).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidData);
    }
}
