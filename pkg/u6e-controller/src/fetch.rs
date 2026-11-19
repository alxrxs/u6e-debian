//! One plain HTTP/1.0 GET, the way the controller reads what the estate
//! already publishes (the DHCP nodes' node exporters, the RADIUS log's
//! store): no chunking, the body ends with the connection, an answer past
//! its cap or its time refused. Plain HTTP on the estate's own network: what
//! is read is published there already, and nothing is sent but the request.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

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
