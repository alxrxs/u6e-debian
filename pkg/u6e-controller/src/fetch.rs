//! One plain HTTP/1.0 GET, the way the controller reads what the estate
//! already publishes (the DHCP nodes' node exporters, the RADIUS log's
//! store): no chunking, the body ends with the connection, an answer past
//! its cap or its time refused. Plain HTTP on the estate's own network: what
//! is read is published there already, and nothing is sent but the request.
//!
//! And one HTTPS POST of JSON with a bearer token (Home Assistant's events,
//! `presence`): TLS 1.3 by rustls on aws-lc-rs, the server's name and chain
//! verified against a PEM bundle of trust anchors read at each connection,
//! so a bundle that changes counts from the next request on, with no
//! restart.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, crypto, version};
use u6e_proto::frame::zeroize;

/// The most of an HTTPS answer read: only its status line is wanted.
const ANSWER_MAX: u64 = 64 << 10;

/// The body `address` (`host:port`) answers `target` (a path and query)
/// with, of at most `max` bytes, within `wait`, connecting included; why
/// not, otherwise.
pub async fn get(
    address: &str,
    target: &str,
    accept: &str,
    max: usize,
    wait: Duration,
) -> Result<String, String> {
    timeout(wait, fetch(address, target, accept, max))
        .await
        .map_err(|_| format!("no answer in {} s", wait.as_secs()))?
}

async fn fetch(address: &str, target: &str, accept: &str, max: usize) -> Result<String, String> {
    let host = address.rsplit_once(':').map_or(address, |(h, _)| h);
    let mut sock = TcpStream::connect(address)
        .await
        .map_err(|e| e.to_string())?;
    let ask = format!("GET {target} HTTP/1.0\r\nHost: {host}\r\nAccept: {accept}\r\n\r\n");
    sock.write_all(ask.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut body = Vec::new();
    let read = (&mut sock)
        .take(max as u64 + 1)
        .read_to_end(&mut body)
        .await;
    read.map_err(|e| e.to_string())?;
    if body.len() > max {
        return Err(format!("the answer is over {} MiB", max >> 20));
    }
    let text = String::from_utf8(body).map_err(|_| "the answer is not UTF-8".to_owned())?;
    let (head, body) = text.split_once("\r\n\r\n").ok_or("no end of the headers")?;
    let mut lines = head.lines();
    let status = lines.next().unwrap_or_default();
    if status.split_whitespace().nth(1) != Some("200") {
        return Err(format!("answered {status:?}"));
    }
    let encoded = lines.any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") || l.starts_with("content-encoding:")
    });
    if encoded {
        return Err("the body is encoded".into());
    }
    Ok(body.to_owned())
}

/// A TLS 1.3 client that trusts the certificates of the PEM bundle `ca` as
/// anchors, on aws-lc-rs (which verifies every curve the estate's CAs use);
/// none of them parsable is an error.
pub fn tls_client(ca: &Path) -> Result<Arc<ClientConfig>, String> {
    let at = |e: &dyn std::fmt::Display| format!("{}: {e}", ca.display());
    let certs: Vec<CertificateDer> = CertificateDer::pem_file_iter(ca)
        .map_err(|e| at(&e))?
        .collect::<Result<_, _>>()
        .map_err(|e| at(&e))?;
    let mut roots = RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(at(&"no certificate to trust"));
    }
    let provider = Arc::new(crypto::aws_lc_rs::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&version::TLS13])
        .map_err(|e| at(&e))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// The status `host`:`port` answers a POST of the JSON `body` to `target`
/// with, sent with the bearer `token` over TLS that `ca` verifies, within
/// `wait`, connecting included; why not, otherwise (never the token).
pub async fn post_json_tls(
    (host, port): (&str, u16),
    target: &str,
    ca: &Path,
    token: &str,
    body: &str,
    wait: Duration,
) -> Result<u16, String> {
    let config = tls_client(ca)?;
    let ask = async {
        let name = ServerName::try_from(host.to_owned()).map_err(|e| e.to_string())?;
        let sock = TcpStream::connect((host, port))
            .await
            .map_err(|e| e.to_string())?;
        let mut tls = TlsConnector::from(config)
            .connect(name, sock)
            .await
            .map_err(|e| format!("TLS: {e}"))?;
        let head = format!(
            "POST {target} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut out = head.into_bytes();
        out.extend_from_slice(body.as_bytes());
        let sent = tls.write_all(&out).await;
        zeroize(&mut out);
        sent.map_err(|e| e.to_string())?;
        let mut answer = Vec::new();
        let read = (&mut tls).take(ANSWER_MAX).read_to_end(&mut answer).await;
        // A server that ends without its close_notify still said what it said.
        if answer.is_empty() {
            read.map_err(|e| e.to_string())?;
        }
        let line = answer.split(|&b| b == b'\n').next().unwrap_or_default();
        let line = String::from_utf8_lossy(line);
        line.split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(|| "no HTTP answer".to_owned())
    };
    timeout(wait, ask)
        .await
        .map_err(|_| format!("no answer in {} s", wait.as_secs()))?
}

/// `s` as a URL's query value: every byte but the unreserved ones
/// percent-encoded (RFC 3986).
pub fn query_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_values_are_percent_encoded() {
        assert_eq!(
            query_value(r#"{job="x"} |~ "a|b""#),
            "%7Bjob%3D%22x%22%7D%20%7C~%20%22a%7Cb%22"
        );
        assert_eq!(query_value("a-Z_0.9~"), "a-Z_0.9~");
    }
}
