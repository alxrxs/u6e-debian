//! One plain HTTP/1.0 GET, the way the controller reads what the estate
//! already publishes (the DHCP nodes' node exporters, the RADIUS log's
//! store): no chunking, the body ends with the connection, an answer past
//! its cap or its time refused. Plain HTTP on the estate's own network: what
//! is read is published there already, and nothing is sent but the request.
//! The same GET over TLS by a configuration of the caller's ([`get_tls`])
//! reads them over mutual TLS once they require it (`mtls`), a failure of
//! TLS itself told apart from any other.
//!
//! And one HTTPS request ([`request_tls`]) carrying a secret in one header
//! and, for a write, a JSON body: Home Assistant's events (`presence`, a
//! bearer token) and OpenBao's KV (`macauth`, its token). TLS 1.3 by
//! rustls on aws-lc-rs, the server's name and chain verified against a PEM
//! bundle of trust anchors read at each connection, so a bundle that
//! changes counts from the next request on, with no restart. HTTP/1.0 too,
//! so the answer is never chunked; the request, secret included, is wiped
//! once sent. The secret is read from its file at each request
//! ([`read_token`]) and wiped when dropped.

use std::fmt;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{self, ClientConfig, RootCertStore, crypto, version};
use u6e_proto::frame::zeroize;

/// The most of an HTTPS answer's status line and headers read.
const HEAD_MAX: usize = 16 << 10;
/// The largest token file read.
const TOKEN_MAX: u64 = 4096;

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

/// The certificates of the PEM bundle `ca` as trust anchors; none of them
/// parsable is an error.
pub fn roots(ca: &Path) -> Result<RootCertStore, String> {
    let at = |e: &dyn fmt::Display| format!("{}: {e}", ca.display());
    let certs: Vec<CertificateDer> = CertificateDer::pem_file_iter(ca)
        .map_err(|e| at(&e))?
        .collect::<Result<_, _>>()
        .map_err(|e| at(&e))?;
    let mut roots = RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(at(&"no certificate to trust"));
    }
    Ok(roots)
}

/// A TLS 1.3 client that trusts the certificates of the PEM bundle `ca` as
/// anchors, on aws-lc-rs (which verifies every curve the estate's CAs use).
pub fn tls_client(ca: &Path) -> Result<Arc<ClientConfig>, String> {
    let roots = roots(ca)?;
    let provider = Arc::new(crypto::aws_lc_rs::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&version::TLS13])
        .map_err(|e| format!("{}: {e}", ca.display()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Why a request over TLS failed: TLS itself (the peer's certificate or
/// ours refused, or a peer that speaks no TLS), or anything else
/// (connecting, the time, the HTTP answer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failed {
    Tls(String),
    Other(String),
}

impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tls(e) => write!(f, "TLS: {e}"),
            Self::Other(e) => f.write_str(e),
        }
    }
}

/// An I/O error of a TLS stream: TLS's own when rustls raised it.
fn failed(e: io::Error) -> Failed {
    match e.get_ref() {
        Some(inner) if inner.is::<rustls::Error>() => Failed::Tls(e.to_string()),
        _ => Failed::Other(e.to_string()),
    }
}

/// An answer to [`request_tls`]: its status and its body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub status: u16,
    pub body: String,
}

/// `method` `target` at `host`:`port` over TLS that `ca` verifies, with the
/// header `auth` (its name and any scheme, then the secret) and, given one,
/// the JSON `body`; the answer, its body at most `max` bytes, within `wait`,
/// connecting included; why not, otherwise (never the secret).
pub async fn request_tls(
    (host, port): (&str, u16),
    (method, target): (&str, &str),
    ca: &Path,
    (header, secret): (&str, &str),
    body: Option<&str>,
    max: usize,
    wait: Duration,
) -> Result<Answer, String> {
    let config = tls_client(ca)?;
    let json = body.map_or_else(String::new, |b| {
        format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            b.len()
        )
    });
    let head =
        format!("{method} {target} HTTP/1.0\r\nHost: {host}\r\n{header}{secret}\r\n{json}\r\n");
    let mut request = head.into_bytes();
    request.extend_from_slice(body.unwrap_or_default().as_bytes());
    timeout(wait, exchange_tls((host, port), config, request, max))
        .await
        .map_err(|_| format!("no answer in {} s", wait.as_secs()))?
        .map_err(|e| e.to_string())
}

/// The body `host`:`port` answers a GET of `target` with over TLS by
/// `config` (the host's name verified), of at most `max` bytes, within
/// `wait`, connecting included; why not, otherwise.
pub async fn get_tls(
    (host, port): (&str, u16),
    config: Arc<ClientConfig>,
    target: &str,
    accept: &str,
    max: usize,
    wait: Duration,
) -> Result<String, Failed> {
    let authority = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let ask = format!("GET {target} HTTP/1.0\r\nHost: {authority}\r\nAccept: {accept}\r\n\r\n");
    let answer = timeout(
        wait,
        exchange_tls((host, port), config, ask.into_bytes(), max),
    )
    .await
    .map_err(|_| Failed::Other(format!("no answer in {} s", wait.as_secs())))??;
    if answer.status != 200 {
        return Err(Failed::Other(format!("answered {}", answer.status)));
    }
    Ok(answer.body)
}

/// The answer to `request` (wiped once sent) from `host`:`port` over TLS by
/// `config`, whose name it verifies, its body at most `max` bytes.
async fn exchange_tls(
    (host, port): (&str, u16),
    config: Arc<ClientConfig>,
    mut request: Vec<u8>,
    max: usize,
) -> Result<Answer, Failed> {
    let other = |e: &dyn fmt::Display| Failed::Other(e.to_string());
    let name = ServerName::try_from(host.to_owned()).map_err(|e| other(&e))?;
    let sock = TcpStream::connect((host, port))
        .await
        .map_err(|e| other(&e))?;
    let mut tls = TlsConnector::from(config)
        .connect(name, sock)
        .await
        .map_err(failed)?;
    let sent = tls.write_all(&request).await;
    zeroize(&mut request);
    sent.map_err(failed)?;
    let mut answer = Vec::new();
    let cap = (HEAD_MAX + max + 4) as u64;
    let read = (&mut tls).take(cap).read_to_end(&mut answer).await;
    // A server that ends without its close_notify still said what it said;
    // one that refused our certificate (TLS 1.3 tells the client after its
    // side of the handshake) says so here.
    if answer.is_empty() {
        read.map_err(failed)?;
    }
    parse_answer(&answer, max).map_err(Failed::Other)
}

/// The status and the body of an HTTP/1.0 answer, its body at most `max`
/// bytes and neither chunked nor compressed.
fn parse_answer(answer: &[u8], max: usize) -> Result<Answer, String> {
    let end = answer
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .filter(|&e| e <= HEAD_MAX)
        .ok_or("no end of the headers")?;
    let head = String::from_utf8_lossy(&answer[..end]);
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or("no HTTP answer")?;
    let encoded = lines.any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") || l.starts_with("content-encoding:")
    });
    if encoded {
        return Err("the body is encoded".into());
    }
    let body = &answer[end + 4..];
    if body.len() > max {
        return Err(format!("the answer is over {} KiB", max >> 10));
    }
    let body = String::from_utf8(body.to_vec()).map_err(|_| "the answer is not UTF-8")?;
    Ok(Answer { status, body })
}

/// The status `host`:`port` answers a POST of the JSON `body` to `target`
/// with, sent with the bearer `token` over TLS that `ca` verifies, within
/// `wait`, connecting included; why not, otherwise (never the token).
pub async fn post_json_tls(
    host: (&str, u16),
    target: &str,
    ca: &Path,
    token: &str,
    body: &str,
    wait: Duration,
) -> Result<u16, String> {
    let auth = ("Authorization: Bearer ", token);
    let post = ("POST", target);
    let answer = request_tls(host, post, ca, auth, Some(body), 64 << 10, wait).await?;
    Ok(answer.status)
}

/// A secret read from its file, wiped when dropped.
pub struct Token(pub String);

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: zeros are valid UTF-8, and the string is not read after.
        zeroize(unsafe { self.0.as_mut_vec() });
    }
}

/// The token in the file `path`, trimmed, and its hash; why not.
pub fn read_token(path: &Path) -> Result<(Token, [u8; 32]), String> {
    use std::io::Read;
    let mut text = Token(String::new());
    std::fs::File::open(path)
        .and_then(|f| f.take(TOKEN_MAX).read_to_string(&mut text.0))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let t = Token(text.0.trim().to_owned());
    if t.0.is_empty() || t.0.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!("{}: no token", path.display()));
    }
    let hash = digest::digest(&digest::SHA256, t.0.as_bytes());
    let hash = hash.as_ref().try_into().expect("SHA-256 is 32 bytes");
    Ok((t, hash))
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
    fn an_answer_is_its_status_and_its_whole_body_or_refused() {
        let ok = parse_answer(b"HTTP/1.0 200 OK\r\nContent-Type: a/b\r\n\r\n{\"x\":1}", 64);
        let ok = ok.unwrap();
        assert_eq!((ok.status, ok.body.as_str()), (200, "{\"x\":1}"));
        let not_found = parse_answer(b"HTTP/1.1 404 Not Found\r\n\r\n", 64).unwrap();
        assert_eq!((not_found.status, not_found.body.as_str()), (404, ""));
        for (bad, why) in [
            (
                &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab"[..],
                "encoded",
            ),
            (
                b"HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\n\r\nxx",
                "encoded",
            ),
            (b"HTTP/1.0 200 OK\r\n\r\n12345", "over"),
            (b"HTTP/1.0 200 OK\r\n", "no end of the headers"),
            (b"garbage\r\n\r\n", "no HTTP answer"),
            (b"HTTP/1.0 200 OK\r\n\r\n\xff\xfe", "not UTF-8"),
        ] {
            let e = parse_answer(bad, 4).unwrap_err();
            assert!(e.contains(why), "{e}");
        }
        let long = [
            &b"HTTP/1.0 200 OK\r\nX: "[..],
            &[b'a'; HEAD_MAX],
            b"\r\n\r\n",
        ]
        .concat();
        assert!(parse_answer(&long, 4).is_err(), "headers past their cap");
    }

    #[test]
    fn a_token_is_one_word_from_its_file() {
        let dir = crate::testdir::TestDir::new();
        let p = dir.path().join("token");
        std::fs::write(&p, "  s.abc123\n").unwrap();
        assert_eq!(read_token(&p).unwrap().0.0, "s.abc123");
        for bad in ["", "\n", "two words", "a\u{7}b"] {
            std::fs::write(&p, bad).unwrap();
            assert!(read_token(&p).is_err(), "{bad:?}");
        }
        assert!(read_token(&dir.path().join("none")).is_err());
    }

    #[test]
    fn query_values_are_percent_encoded() {
        assert_eq!(
            query_value(r#"{job="x"} |~ "a|b""#),
            "%7Bjob%3D%22x%22%7D%20%7C~%20%22a%7Cb%22"
        );
        assert_eq!(query_value("a-Z_0.9~"), "a-Z_0.9~");
    }
}
