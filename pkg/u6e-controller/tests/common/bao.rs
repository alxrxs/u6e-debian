//! A stand-in for OpenBao, for the tests and the replay: KV-v2's read and
//! check-and-set write of the secrets under `/v1/secret/data/`, over TLS
//! with the tests' certificate (`tests/fixtures/tls`, for 127.0.0.1), each
//! request's token checked and every request kept; it answers 503 while
//! `down`, makes the next `races` writes find that another writer came
//! first, and closes the connection unanswered on the next `lost_writes`
//! writes (not taken) and `lost_answers` (taken).

use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::{ServerConfig, crypto, version};

/// The test certificates.
pub const TLS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls");

/// One secret: its versions' data, the newest last.
#[derive(Debug, Default)]
pub struct Secret {
    pub versions: Vec<Value>,
}

/// What the stand-in holds and was asked.
#[derive(Debug, Default)]
pub struct Store {
    pub token: String,
    pub secrets: BTreeMap<String, Secret>,
    /// Each request: its method and path, and its JSON body.
    pub requests: Vec<(String, Option<Value>)>,
    pub down: bool,
    pub races: u32,
    pub lost_writes: u32,
    pub lost_answers: u32,
}

/// Serves `store` until the process ends; its address.
pub async fn serve(store: Arc<Mutex<Store>>) -> io::Result<SocketAddr> {
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
            let (acceptor, store) = (acceptor.clone(), Arc::clone(&store));
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(sock).await else {
                    return;
                };
                let Some((head, body)) = request(&mut tls).await else {
                    return;
                };
                let Some((status, answer)) = answer(&mut store.lock().unwrap(), &head, &body)
                else {
                    return;
                };
                let body = answer.to_string();
                let out = format!(
                    "HTTP/1.0 {status} X\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(out.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    Ok(addr)
}

/// A request's head and body, once its body of the length it says has come.
async fn request<S: AsyncReadExt + Unpin>(tls: &mut S) -> Option<(String, String)> {
    let mut got = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        let n = tls.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
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
            return Some((head.to_owned(), body.to_owned()));
        }
    }
}

/// KV-v2's answer to one request; none when it is lost.
fn answer(store: &mut Store, head: &str, body: &str) -> Option<(u16, Value)> {
    let mut words = head.split_whitespace();
    let (method, path) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
    store
        .requests
        .push((format!("{method} {path}"), serde_json::from_str(body).ok()));
    let post = method == "POST";
    if post && store.lost_writes > 0 {
        store.lost_writes -= 1;
        return None;
    }
    let answer = kv(store, head, body);
    if post && store.lost_answers > 0 {
        store.lost_answers -= 1;
        return None;
    }
    Some(answer)
}

/// KV-v2's answer to one request, taken.
fn kv(store: &mut Store, head: &str, body: &str) -> (u16, Value) {
    let mut words = head.split_whitespace();
    let (method, path) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
    let json: Option<Value> = serde_json::from_str(body).ok();
    let errors = |e: &str| json!({ "errors": [e] });
    if store.down {
        return (503, errors("Vault is sealed"));
    }
    let token = head.lines().find_map(|l| l.strip_prefix("X-Vault-Token: "));
    if token != Some(store.token.as_str()) {
        return (403, errors("permission denied"));
    }
    let Some(name) = path.strip_prefix("/v1/secret/data/") else {
        return (404, json!({ "errors": [] }));
    };
    let secret = store.secrets.entry(name.to_owned()).or_default();
    match method {
        "GET" => match secret.versions.last() {
            None => (404, json!({ "errors": [] })),
            Some(data) => {
                let version = secret.versions.len();
                let metadata = json!({ "version": version, "destroyed": false });
                (
                    200,
                    json!({ "data": { "data": data, "metadata": metadata } }),
                )
            }
        },
        "POST" => {
            let Some(json) = json else {
                return (400, errors("invalid JSON"));
            };
            if store.races > 0 {
                store.races -= 1;
                let last = secret.versions.last().cloned().unwrap_or_else(|| json!({}));
                secret.versions.push(last);
            }
            let cas = json["options"]["cas"].as_u64();
            if cas.is_some_and(|c| c != secret.versions.len() as u64) {
                let e = "check-and-set parameter did not match the current version";
                return (400, errors(e));
            }
            secret.versions.push(json["data"].clone());
            (200, json!({ "data": { "version": secret.versions.len() } }))
        }
        _ => (405, errors("unsupported operation")),
    }
}
