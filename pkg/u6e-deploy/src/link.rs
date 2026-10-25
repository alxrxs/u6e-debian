//! The runner's link to the controller: outbound only, TLS 1.3 with the
//! X25519MLKEM768 key exchange, the controller pinned by its key and the
//! runner admitted by its own (`u6e_proto::tls`). Each session opens with the
//! version frames, and only a controller of this protocol is spoken to; the
//! runner then says Hello, sends what is queued for the controller and takes
//! what the controller sends. A session silent for a minute is dropped (the
//! controller pings every 15 s), and the link redials after 1 s, doubling to
//! 30 s while sessions end before the controller says anything.
//!
//! Frames are wiped once decoded or sent: a configuration's carry secrets.

use std::io::{self, ErrorKind};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep, sleep_until, timeout};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use u6e_proto::frame::{decode_frame, frame_body, write_frame, zeroize};
use u6e_proto::msg::{RunnerCtlMsg, RunnerHello, RunnerMsg};
use u6e_proto::tls::{self, Identity};
use u6e_proto::{PROTOCOL, version};

use crate::runner::Runner;

/// Longest a connection, a handshake or a write may take.
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// The controller pings every 15 s.
const SILENCE: Duration = Duration::from_secs(60);
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Keeps the link up for the life of the process, sending what `outbox`
/// holds.
pub async fn run(runner: Arc<Runner>, identity: Identity, mut outbox: mpsc::Receiver<RunnerMsg>) {
    let config = tls::client_config(&identity, runner.config.controller_key);
    let connector = TlsConnector::from(config);
    let mut backoff = BACKOFF_MIN;
    // A message taken from the queue whose write failed goes first next time.
    let mut unsent = None;
    loop {
        let mut s = Session {
            runner: &runner,
            buf: Vec::new(),
            heard: false,
        };
        let e = s.run(&connector, &mut outbox, &mut unsent).await;
        runner.set_connected(false);
        eprintln!(
            "u6e-deploy: the controller {}: {e}",
            runner.config.controller
        );
        backoff = if s.heard {
            BACKOFF_MIN
        } else {
            (backoff * 2).min(BACKOFF_MAX)
        };
        sleep(backoff).await;
    }
}

struct Session<'a> {
    runner: &'a Arc<Runner>,
    /// Received bytes not yet a whole frame.
    buf: Vec<u8>,
    /// The controller said something this session.
    heard: bool,
}

impl Session<'_> {
    async fn run(
        &mut self,
        connector: &TlsConnector,
        outbox: &mut mpsc::Receiver<RunnerMsg>,
        unsent: &mut Option<RunnerMsg>,
    ) -> io::Error {
        match self.serve(connector, outbox, unsent).await {
            Ok(never) => match never {},
            Err(e) => e,
        }
    }

    async fn serve(
        &mut self,
        connector: &TlsConnector,
        outbox: &mut mpsc::Receiver<RunnerMsg>,
        unsent: &mut Option<RunnerMsg>,
    ) -> io::Result<std::convert::Infallible> {
        let addr = &self.runner.config.controller;
        let host = addr.rsplit_once(':').map_or(addr.as_str(), |(h, _)| h);
        let name = ServerName::try_from(host.trim_matches(['[', ']']).to_owned())
            .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?;
        let sock = timeout(IO_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| io::Error::new(ErrorKind::TimedOut, "connect timed out"))??;
        sock.set_nodelay(true)?;
        let mut tls = timeout(IO_TIMEOUT, connector.connect(name, sock))
            .await
            .map_err(|_| io::Error::new(ErrorKind::TimedOut, "handshake timed out"))??;

        send(&mut tls, &version::frame(PROTOCOL)).await?;
        let theirs = self.version(&mut tls).await?;
        if theirs != PROTOCOL {
            let why = format!("speaks protocol {theirs}, this runner {PROTOCOL}");
            return Err(io::Error::new(ErrorKind::InvalidData, why));
        }
        self.heard = true;
        let hello = RunnerHello {
            version: env!("CARGO_PKG_VERSION").to_owned(),
        };
        write(&mut tls, &RunnerMsg::Hello(hello)).await?;
        eprintln!(
            "u6e-deploy: linked to the controller {}",
            self.runner.config.controller
        );
        self.runner.set_connected(true);
        if let Some(msg) = unsent.take() {
            write_or_keep(&mut tls, msg, unsent).await?;
        }
        let mut last_rx = Instant::now();
        let mut chunk = [0; 4096];
        loop {
            tokio::select! {
                r = tls.read(&mut chunk) => {
                    let n = r?;
                    if n == 0 {
                        return Err(ErrorKind::UnexpectedEof.into());
                    }
                    self.buf.extend_from_slice(&chunk[..n]);
                    zeroize(&mut chunk[..n]);
                    last_rx = Instant::now();
                    while let Some((msg, used)) = decode_frame::<RunnerCtlMsg>(&self.buf)? {
                        consume(&mut self.buf, used);
                        if let Some(answer) = self.runner.handle(msg) {
                            write(&mut tls, &answer).await?;
                        }
                    }
                }
                msg = outbox.recv() => {
                    let msg = msg.ok_or_else(|| io::Error::other("the runner is gone"))?;
                    write_or_keep(&mut tls, msg, unsent).await?;
                }
                () = sleep_until(last_rx + SILENCE) => {
                    return Err(io::Error::new(ErrorKind::TimedOut, "the controller is silent"));
                }
            }
        }
    }

    /// The protocol the controller's version frame states.
    async fn version(&mut self, tls: &mut TlsStream<TcpStream>) -> io::Result<u16> {
        let mut chunk = [0; 64];
        loop {
            if let Some((body, used)) = frame_body(&self.buf)? {
                let theirs = version::decode(body);
                self.buf.drain(..used);
                return Ok(theirs);
            }
            let n = timeout(SILENCE, tls.read(&mut chunk))
                .await
                .map_err(|_| io::Error::new(ErrorKind::TimedOut, "no version frame"))??;
            if n == 0 {
                return Err(ErrorKind::UnexpectedEof.into());
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

/// Drops the first `used` bytes of `buf`, wiping them and what the move
/// leaves behind.
fn consume(buf: &mut Vec<u8>, used: usize) {
    let len = buf.len();
    zeroize(&mut buf[..used]);
    buf.drain(..used);
    buf.resize(len, 0);
    zeroize(&mut buf[len - used..]);
    buf.truncate(len - used);
}

async fn send(tls: &mut TlsStream<TcpStream>, bytes: &[u8]) -> io::Result<()> {
    let w = async {
        tls.write_all(bytes).await?;
        tls.flush().await
    };
    timeout(IO_TIMEOUT, w)
        .await
        .map_err(|_| io::Error::new(ErrorKind::TimedOut, "the controller is not reading"))?
}

/// Sends `msg`, its encoding wiped once sent.
async fn write(tls: &mut TlsStream<TcpStream>, msg: &RunnerMsg) -> io::Result<()> {
    let mut out = Vec::new();
    write_frame(&mut out, msg)?;
    let r = send(tls, &out).await;
    zeroize(&mut out);
    r
}

/// Sends `msg`; kept in `unsent` for the next session when it could not be.
async fn write_or_keep(
    tls: &mut TlsStream<TcpStream>,
    msg: RunnerMsg,
    unsent: &mut Option<RunnerMsg>,
) -> io::Result<()> {
    let r = write(tls, &msg).await;
    if r.is_err() {
        *unsent = Some(msg);
    }
    r
}
