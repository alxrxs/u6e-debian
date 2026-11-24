//! The web listener's connections, each ended once a write to it has made
//! no progress for its stall time: a page that stops reading (a speed
//! test's download nobody takes, a WebSocket whose browser went) cannot hold
//! the controller's buffers and its task for good. A connection that is
//! read keeps going however long it lasts.

use std::future::Future;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Sleep, sleep};

/// A listener whose connections end at a write stalled for `stall`.
pub struct Listener {
    inner: TcpListener,
    stall: Duration,
}

impl Listener {
    pub fn new(inner: TcpListener, stall: Duration) -> Self {
        Listener { inner, stall }
    }
}

impl axum::serve::Listener for Listener {
    type Io = Watched;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Watched, SocketAddr) {
        loop {
            match self.inner.accept().await {
                Ok((io, addr)) => {
                    let io = Watched {
                        io,
                        stall: self.stall,
                        timer: None,
                    };
                    return (io, addr);
                }
                // Out of descriptors, most likely: let connections end first.
                Err(e) => {
                    eprintln!("u6e-controller: http accept: {e}");
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

/// One connection, with the timer of its write that is waiting.
pub struct Watched {
    io: TcpStream,
    stall: Duration,
    timer: Option<Pin<Box<Sleep>>>,
}

impl Watched {
    /// What a write's `poll` came to: progress clears the timer, a wait
    /// starts it or polls it, and its end fails the write.
    fn watch<T>(&mut self, cx: &mut Context<'_>, poll: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        if poll.is_ready() {
            self.timer = None;
            return poll;
        }
        let stall = self.stall;
        let timer = self.timer.get_or_insert_with(|| Box::pin(sleep(stall)));
        match timer.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                ErrorKind::TimedOut,
                "the peer has read nothing for too long",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncRead for Watched {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Watched {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.io).poll_write(cx, buf);
        self.watch(cx, poll)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let poll = Pin::new(&mut self.io).poll_flush(cx);
        self.watch(cx, poll)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
