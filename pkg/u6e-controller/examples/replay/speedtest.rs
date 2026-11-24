//! The replay's speed tests: an AP asked for one opens a connection of its
//! own to the controller, as its agent does, and paces both directions to
//! what an AP of its kind reaches on a gigabit uplink, its CPU made up.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, sleep};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use u6e_proto::frame::{frame_body, write_frame};
use u6e_proto::msg::{AgentMsg, CpuUse, SpeedTestReport};
use u6e_proto::speedtest::{self, CHUNK, Chunks};
use u6e_proto::tls::{self, Identity};
use u6e_proto::{PROTOCOL, version};

use crate::keys::KEY_CONTROLLER;

/// Each AP's pace, bit/s: download, upload.
const PACE: [(f64, f64); 2] = [(941e6, 612e6), (702e6, 488e6)];
/// Its CPU over each direction, in thousandths: all cores, the test's own.
const CPU: [((u16, u16), (u16, u16)); 2] = [((612, 941), (705, 978)), ((655, 967), (730, 990))];

/// Waits until `bytes` at `bps` have had their time since `t0`.
async fn pace(t0: Instant, bytes: u64, bps: f64) {
    let due = t0 + Duration::from_secs_f64(bytes as f64 * 8.0 / bps);
    if due > Instant::now() {
        sleep(due - Instant::now()).await;
    }
}

/// The test `id` of AP `ap`, its key `pem`, to the controller's agent
/// listener at `addr`.
pub async fn run(addr: SocketAddr, pem: &str, ap: usize, id: u64, secs: u8) -> io::Result<()> {
    let me = Identity::from_pem(pem).map_err(io::Error::other)?;
    let controller = Identity::from_pem(KEY_CONTROLLER).map_err(io::Error::other)?;
    let connector = TlsConnector::from(tls::client_config(&me, controller.public_key()));
    let tcp = TcpStream::connect(addr).await?;
    let name = ServerName::try_from("controller").map_err(io::Error::other)?;
    let mut tls = connector.connect(name, tcp).await?;
    let mut open = version::frame(PROTOCOL).to_vec();
    write_frame(&mut open, &AgentMsg::SpeedTestOpen { id })?;
    tls.write_all(&open).await?;
    let (down_bps, up_bps) = PACE[ap];
    let mut buf = vec![0; CHUNK];
    let mut got = Vec::new();
    while frame_body(&got)?.is_none() {
        let n = tls.read(&mut buf).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        got.extend_from_slice(&buf[..n]);
    }
    let (_, used) = frame_body(&got)?.expect("a whole frame");
    let mut down = Chunks::default();
    down.take(&got[used..]).map_err(io::Error::other)?;
    let t0 = Instant::now();
    while !down.ended() {
        pace(t0, down.bytes(), down_bps).await;
        let n = tls.read(&mut buf).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        down.take(&buf[..n]).map_err(io::Error::other)?;
    }
    let down_us = t0.elapsed().as_micros() as u64;
    buf.fill(0);
    let t1 = Instant::now();
    let mut sent = 0u64;
    while t1.elapsed() < Duration::from_secs(u64::from(secs)) {
        tls.write_all(&speedtest::header(CHUNK)).await?;
        tls.write_all(&buf).await?;
        sent += CHUNK as u64;
        pace(t1, sent, up_bps).await;
    }
    tls.write_all(&speedtest::header(0)).await?;
    let ((busy_d, thread_d), (busy_u, thread_u)) = CPU[ap];
    let report = SpeedTestReport {
        id,
        down_bytes: down.bytes(),
        down_us,
        cpu_down: CpuUse {
            busy_permille: busy_d,
            thread_permille: thread_d,
        },
        cpu_up: CpuUse {
            busy_permille: busy_u,
            thread_permille: thread_u,
        },
    };
    let mut out = Vec::new();
    write_frame(&mut out, &AgentMsg::SpeedTestReport(report))?;
    tls.write_all(&out).await?;
    tls.shutdown().await
}
