//! The replay's Home Assistant: an HTTPS server with the tests' certificate
//! (`tests/fixtures/tls`, whose CA the controller's `[presence]` trusts),
//! which takes every `wifi_presence` event, says so, and answers 200; or,
//! failing, answers every one 503, as a Home Assistant restarting does.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::{ServerConfig, crypto, version};

/// The test certificates.
pub const TLS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls");

/// Serves until the process ends, `failing` or not; its address.
pub async fn serve(failing: bool) -> io::Result<SocketAddr> {
    let certs = CertificateDer::pem_file_iter(format!("{TLS}/server.pem"))
        .map_err(io::Error::other)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
    let key =
        PrivateKeyDer::from_pem_file(format!("{TLS}/server.key")).map_err(io::Error::other)?;
    let config =
        ServerConfig::builder_with_provider(Arc::new(crypto::aws_lc_rs::default_provider()))
            .with_protocol_versions(&[&version::TLS13])
            .map_err(io::Error::other)?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(io::Error::other)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(sock).await else {
                    return;
                };
                let mut got = Vec::new();
                let mut chunk = [0; 4096];
                // Read until the body of its length has come.
                loop {
                    let Ok(n) = tls.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    got.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&got);
                    let Some((head, body)) = text.split_once("\r\n\r\n") else {
                        continue;
                    };
                    let len = head
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    if body.len() >= len {
                        let path = head.split_whitespace().nth(1).unwrap_or("");
                        let took = if failing { "refused" } else { "took" };
                        eprintln!("replay: Home Assistant {took} {path}: {body}");
                        break;
                    }
                }
                let answer: &[u8] = if failing {
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                } else {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
                };
                let _ = tls.write_all(answer).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    Ok(addr)
}
