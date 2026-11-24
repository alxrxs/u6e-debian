//! A speed test's own connection, which the agent opens to the controller's
//! agent listener when a [`CommandKind::SpeedTest`] asks for one: after the
//! version frames and the agent's [`AgentMsg::SpeedTestOpen`], the download
//! (chunks from the controller), then the upload (chunks from the agent),
//! then the agent's [`AgentMsg::SpeedTestReport`]. A chunk is its length, a
//! u32 little endian, and that many filler bytes, at most [`CHUNK`]; an
//! empty chunk ends its direction. Each direction is timed by its receiver,
//! from its first byte to its end, and [`Chunks`] reads them for both ends.
//!
//! [`CommandKind::SpeedTest`]: crate::msg::CommandKind::SpeedTest
//! [`AgentMsg::SpeedTestOpen`]: crate::msg::AgentMsg::SpeedTestOpen
//! [`AgentMsg::SpeedTestReport`]: crate::msg::AgentMsg::SpeedTestReport

use std::fmt;
use std::time::Duration;

/// The longest each direction runs, whatever the command asks.
pub const SECS_MAX: u8 = 10;
/// The most each direction carries, whatever the command asks: a 2.5 GbE
/// port's line rate would need more in 10 s, so a direction may end on it
/// before its time, which its rate takes into account.
pub const BYTES_MAX: u64 = 2 << 30;
/// The largest chunk.
pub const CHUNK: usize = 64 << 10;

/// The time and the bytes each direction of a test asked for `secs` and
/// `max_bytes` runs: held to [`SECS_MAX`] and [`BYTES_MAX`], at least a
/// second and a chunk.
pub fn bounds(secs: u8, max_bytes: u64) -> (Duration, u64) {
    let secs = secs.clamp(1, SECS_MAX);
    let bytes = max_bytes.clamp(CHUNK as u64, BYTES_MAX);
    (Duration::from_secs(u64::from(secs)), bytes)
}

/// The header of a chunk of `len` bytes; `header(0)` ends a direction.
pub fn header(len: usize) -> [u8; 4] {
    debug_assert!(len <= CHUNK);
    (len as u32).to_le_bytes()
}

/// A chunk's length above [`CHUNK`]: the peer is no speed test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooLong(pub u32);

impl fmt::Display for TooLong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a chunk of {} B is longer than {CHUNK}", self.0)
    }
}

impl std::error::Error for TooLong {}

/// One direction's chunks, read as their bytes come and counted, not kept.
#[derive(Debug, Default)]
pub struct Chunks {
    head: [u8; 4],
    /// The bytes of the next header read so far.
    have: usize,
    /// The bytes of the current chunk still to come.
    left: usize,
    bytes: u64,
    ended: bool,
}

impl Chunks {
    /// Takes the next bytes of the stream; how many of them belong to this
    /// direction: all of them, or, once its end chunk is among them, those
    /// up to its end, the rest being what follows it.
    pub fn take(&mut self, mut buf: &[u8]) -> Result<usize, TooLong> {
        let total = buf.len();
        while !buf.is_empty() && !self.ended {
            if self.left > 0 {
                let n = self.left.min(buf.len());
                self.left -= n;
                self.bytes += n as u64;
                buf = &buf[n..];
                continue;
            }
            let n = (4 - self.have).min(buf.len());
            self.head[self.have..self.have + n].copy_from_slice(&buf[..n]);
            self.have += n;
            buf = &buf[n..];
            if self.have == 4 {
                self.have = 0;
                let len = u32::from_le_bytes(self.head);
                if len as usize > CHUNK {
                    return Err(TooLong(len));
                }
                self.left = len as usize;
                self.ended = len == 0;
            }
        }
        Ok(total - buf.len())
    }

    /// Whether its end chunk came.
    pub fn ended(&self) -> bool {
        self.ended
    }

    /// The filler bytes read, headers left out.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// A rate in bits per second from `bytes` over `us` microseconds; 0 for no
/// time.
pub fn bits_per_second(bytes: u64, us: u64) -> f64 {
    if us == 0 {
        return 0.0;
    }
    bytes as f64 * 8.0 * 1e6 / us as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A direction of `chunks` of the given lengths, ended, then `after`.
    fn stream(chunks: &[usize], after: &[u8]) -> Vec<u8> {
        let mut s = Vec::new();
        for &len in chunks {
            s.extend(header(len));
            s.extend(std::iter::repeat_n(0xa5, len));
        }
        s.extend(header(0));
        s.extend(after);
        s
    }

    #[test]
    fn every_split_reads_the_same() {
        let s = stream(&[5, CHUNK, 1], b"next");
        let data = (5 + CHUNK + 1) as u64;
        let end = s.len() - 4;
        for cut in [0, 1, 3, 4, 5, 8, 9, 100, end - 1, end, s.len()] {
            let mut c = Chunks::default();
            let mut used = c.take(&s[..cut]).unwrap();
            assert_eq!(used, cut.min(end), "cut {cut}");
            if !c.ended() {
                used += c.take(&s[cut..]).unwrap();
            }
            assert!(c.ended(), "cut {cut}");
            assert_eq!((c.bytes(), used), (data, end), "cut {cut}");
            assert_eq!(&s[used..], b"next");
        }
    }

    #[test]
    fn a_byte_at_a_time_reads_the_same() {
        let s = stream(&[3, 7], b"");
        let mut c = Chunks::default();
        for b in &s {
            assert_eq!(c.take(std::slice::from_ref(b)).unwrap(), 1);
        }
        assert!(c.ended());
        assert_eq!(c.bytes(), 10);
        assert_eq!(c.take(b"more").unwrap(), 0);
    }

    #[test]
    fn a_chunk_longer_than_the_cap_is_refused() {
        let mut c = Chunks::default();
        let mut s = ((CHUNK + 1) as u32).to_le_bytes().to_vec();
        s.extend([0; 8]);
        assert_eq!(c.take(&s), Err(TooLong(CHUNK as u32 + 1)));
        let mut c = Chunks::default();
        assert_eq!(c.take(&u32::MAX.to_le_bytes()), Err(TooLong(u32::MAX)));
    }

    #[test]
    fn the_bounds_hold_whatever_is_asked() {
        assert_eq!(bounds(60, u64::MAX), (Duration::from_secs(10), BYTES_MAX));
        assert_eq!(bounds(0, 0), (Duration::from_secs(1), CHUNK as u64));
        assert_eq!(bounds(4, 1 << 20), (Duration::from_secs(4), 1 << 20));
    }

    #[test]
    fn rates_are_bits_per_second() {
        assert_eq!(bits_per_second(125_000_000, 1_000_000), 1e9);
        assert_eq!(bits_per_second(1, 0), 0.0);
    }
}
