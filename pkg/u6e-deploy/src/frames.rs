//! u6e-proto's framing over tokio's streams, for the local socket and the
//! stage helper's: one frame read whole, then decoded and wiped as
//! `frame::read_frame` does; one written from an encoding wiped once sent.
//! Their frames can hold a Wi-Fi configuration's secrets.

use std::io::{self, ErrorKind};

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use u6e_proto::frame::{MAX_FRAME, read_frame, write_frame, zeroize};

pub async fn read<T: DeserializeOwned>(r: &mut (impl AsyncRead + Unpin)) -> io::Result<T> {
    let mut frame = vec![0; 4];
    r.read_exact(&mut frame).await?;
    let len = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]);
    if len > MAX_FRAME {
        let why = format!("frame of {len} B exceeds {MAX_FRAME}");
        return Err(io::Error::new(ErrorKind::InvalidData, why));
    }
    frame.resize(4 + len as usize, 0);
    let read = r.read_exact(&mut frame[4..]).await;
    let msg = read.and_then(|_| read_frame(&mut frame.as_slice()));
    zeroize(&mut frame);
    msg
}

pub async fn write<T: Serialize>(w: &mut (impl AsyncWrite + Unpin), msg: &T) -> io::Result<()> {
    let mut out = Vec::new();
    write_frame(&mut out, msg)?;
    let r = async {
        w.write_all(&out).await?;
        w.flush().await
    }
    .await;
    zeroize(&mut out);
    r
}
