//! A socket whose reads and writes end at one deadline: each system call is
//! given only the time left, and none starts once it is past. A socket
//! timeout alone bounds each call, so a peer that trickles a byte at a time
//! could hold a loop of them (a TLS handshake, a record read whole) for as
//! long as it likes.

use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

pub struct Deadline<'a> {
    sock: &'a TcpStream,
    at: Instant,
}

impl<'a> Deadline<'a> {
    pub fn new(sock: &'a TcpStream, at: Instant) -> Self {
        Deadline { sock, at }
    }

    /// The time left; an error once there is none.
    fn left(&self) -> io::Result<Duration> {
        let left = self.at.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(ErrorKind::TimedOut, "past its deadline"));
        }
        Ok(left)
    }
}

impl Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.sock.set_read_timeout(Some(self.left()?))?;
        (&mut &*self.sock).read(buf)
    }
}

impl Write for Deadline<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sock.set_write_timeout(Some(self.left()?))?;
        (&mut &*self.sock).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (b, _) = l.accept().unwrap();
        (a, b)
    }

    /// A peer that sends a byte every 100 ms keeps each read short, and the
    /// reads end at the deadline all the same.
    #[test]
    fn a_trickle_does_not_outlast_the_deadline() {
        let (a, mut b) = pair();
        let feeder = thread::spawn(move || {
            for _ in 0..30 {
                if b.write_all(&[1]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
        });
        let start = Instant::now();
        let mut d = Deadline::new(&a, start + Duration::from_millis(500));
        let mut got = [0; 64];
        let e = d.read_exact(&mut got).unwrap_err();
        assert!(
            matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock),
            "{e}"
        );
        let took = start.elapsed();
        assert!(took < Duration::from_millis(800), "{took:?}");
        drop(a);
        feeder.join().unwrap();
    }

    /// A peer that never reads: the writes end at the deadline once its
    /// buffers are full.
    #[test]
    fn a_peer_that_reads_nothing_does_not_outlast_the_deadline() {
        let (a, _b) = pair();
        let start = Instant::now();
        let mut d = Deadline::new(&a, start + Duration::from_millis(500));
        let chunk = vec![0; 1 << 16];
        let e = loop {
            if let Err(e) = d.write_all(&chunk) {
                break e;
            }
            assert!(start.elapsed() < Duration::from_secs(5), "never stopped");
        };
        assert!(
            matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock),
            "{e}"
        );
        assert!(start.elapsed() < Duration::from_millis(800));
    }
}
