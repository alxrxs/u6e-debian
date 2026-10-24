//! Length-prefixed frames: a u32 little-endian length, then the postcard
//! encoding of one message.

use std::io::{self, ErrorKind, Read, Write};

use serde::Serialize;
use serde::de::DeserializeOwned;

/// The largest frame either side accepts or sends.
pub const MAX_FRAME: u32 = 1 << 20;

/// Writes one frame.
pub fn write_frame<W: Write>(w: &mut W, msg: &impl Serialize) -> io::Result<()> {
    // One write, so a frame is never split across TLS records by its prefix.
    let mut buf = vec![0; 4];
    postcard::to_io(msg, &mut buf).map_err(invalid)?;
    let len = u32::try_from(buf.len() - 4)
        .ok()
        .filter(|&n| n <= MAX_FRAME);
    let len = len.ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "frame too large"))?;
    buf[..4].copy_from_slice(&len.to_le_bytes());
    w.write_all(&buf)
}

/// Reads one frame; a length above [`MAX_FRAME`] is refused before anything is
/// allocated for it.
pub fn read_frame<R: Read, T: DeserializeOwned>(r: &mut R) -> io::Result<T> {
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
    postcard::from_bytes(&body).map_err(invalid)
}

fn invalid(e: postcard::Error) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::{AgentMsg, CtlMsg};

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
    fn garbage_body_is_invalid_data() {
        let mut buf = 2u32.to_le_bytes().to_vec();
        buf.extend([0xff, 0xff]);
        let e = read_frame::<_, AgentMsg>(&mut buf.as_slice()).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidData);
    }
}
