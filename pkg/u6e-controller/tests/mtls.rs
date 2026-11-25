//! `/metrics` over mutual TLS end to end: a controller in this process
//! serving it with the test certificates (`fixtures/mtls`) to the scraper it
//! admits, refusing every other client in the handshake while its UI keeps
//! answering, serving a renewed certificate from the next connection on, and
//! failing only the connections made while its key is missing.

use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use tokio::runtime::{Builder, Runtime};
use tokio_rustls::rustls::crypto::aws_lc_rs::default_provider;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use u6e_controller::agents::Timing;
use u6e_controller::config::Config;
use u6e_controller::mtls::Files;
use u6e_controller::names::Resolve;
use u6e_controller::{Controller, start};
use u6e_proto::tls::Identity;

// The tests' keys, only the controller's used here.
#[allow(dead_code)]
#[path = "common/keys.rs"]
mod keys;
#[path = "common/tempdir.rs"]
mod tempdir;

use keys::KEY_CONTROLLER;
use tempdir::TempDir;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/mtls");
/// The name the controller's certificate carries.
const NAME: &str = "controller.example.org";
const WAIT: Duration = Duration::from_secs(20);

struct NoNames;

impl Resolve for NoNames {
    fn reverse(&self, _: std::net::IpAddr) -> Option<String> {
        None
    }

    fn forward(&self, _: &str) -> Vec<std::net::IpAddr> {
        Vec::new()
    }
}

/// A controller with its files in `dir`, presenting `dir`'s cert.pem and
/// key.pem and admitting the test scraper to its metrics.
fn controller(dir: &Path) -> (Controller, Runtime) {
    let d = dir.display();
    let text = format!(
        "listen_agents = \"127.0.0.1:0\"\nlisten_http = \"127.0.0.1:0\"\n\
         listen_metrics = \"127.0.0.1:0\"\npublic_origin = \"https://wifi.example.org\"\n\
         policy_path = \"{d}/policy.json\"\nhistory_path = \"{d}/history\"\n\
         traffic_path = \"{d}/traffic\"\ncaptures_path = \"{d}/captures\"\n\
         [monitoring_tls]\ncert = \"{d}/cert.pem\"\nkey = \"{d}/key.pem\"\n\
         ca = \"{FIXTURES}/chain.pem\"\nmetrics_clients = [\"status1.example.org\"]\n"
    );
    let config = Config::parse(&text).unwrap();
    let rt = Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let identity = Identity::from_pem(KEY_CONTROLLER).unwrap();
    let c = rt
        .block_on(start(
            &config,
            &identity,
            Timing::default(),
            Arc::new(NoNames),
            None,
        ))
        .unwrap();
    (c, rt)
}

/// Puts the fixture `name`'s chain and key in `dir` as new files, the way
/// a renewal replaces them.
fn install(dir: &Path, name: &str) {
    for (from, to) in [("pem", "cert.pem"), ("key", "key.pem")] {
        let new = dir.join(format!("{to}.new"));
        fs::copy(format!("{FIXTURES}/{name}.{from}"), &new).unwrap();
        fs::rename(&new, dir.join(to)).unwrap();
    }
}

fn leaf(name: &str) -> Vec<u8> {
    let mut certs = CertificateDer::pem_file_iter(format!("{FIXTURES}/{name}.pem")).unwrap();
    certs.next().unwrap().unwrap().to_vec()
}

fn client(name: &str) -> Arc<ClientConfig> {
    Files {
        cert: format!("{FIXTURES}/{name}.pem").into(),
        key: format!("{FIXTURES}/{name}.key").into(),
        ca: format!("{FIXTURES}/chain.pem").into(),
    }
    .client()
    .unwrap()
}

/// A client that trusts the test CA and has no certificate of its own.
fn without_certificate() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for ca in CertificateDer::pem_file_iter(format!("{FIXTURES}/chain.pem")).unwrap() {
        roots.add(ca.unwrap()).unwrap();
    }
    let config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(config)
}

/// `/metrics` as `config` scrapes it, with the leaf the controller served;
/// why not.
fn scrape(addr: SocketAddr, config: Arc<ClientConfig>) -> Result<(String, Vec<u8>), String> {
    let name = ServerName::try_from(NAME).unwrap();
    let conn = ClientConnection::new(config, name).map_err(|e| e.to_string())?;
    let sock = TcpStream::connect(addr).map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(WAIT)).unwrap();
    let mut tls = StreamOwned::new(conn, sock);
    let ask = "GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    tls.write_all(ask.as_bytes()).map_err(|e| e.to_string())?;
    let mut answer = String::new();
    match tls.read_to_string(&mut answer) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof && !answer.is_empty() => {}
        Err(e) => return Err(e.to_string()),
    }
    let served = tls.conn.peer_certificates().unwrap()[0].to_vec();
    let (head, body) = answer.split_once("\r\n\r\n").ok_or("no answer")?;
    if !head.starts_with("HTTP/1.1 200") {
        return Err(head.to_owned());
    }
    Ok((body.to_owned(), served))
}

/// The UI's index answers, over plain HTTP as ever.
fn ui_answers(addr: SocketAddr) -> bool {
    let mut sock = TcpStream::connect(addr).unwrap();
    sock.set_read_timeout(Some(WAIT)).unwrap();
    write!(
        sock,
        "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut answer = String::new();
    sock.read_to_string(&mut answer).unwrap();
    answer.starts_with("HTTP/1.1 200")
}

/// The failures the admitted scraper reads, once the count of `reason`
/// reaches `n`.
fn failures_reach(addr: SocketAddr, reason: &str, n: u64) -> String {
    let sample = format!(
        "wifi_monitoring_tls_failures_total{{endpoint=\"metrics\",reason=\"{reason}\"}} {n}"
    );
    let until = Instant::now() + WAIT;
    loop {
        let body = scrape(addr, client("scraper")).unwrap().0;
        if body.lines().any(|l| l == sample) || Instant::now() > until {
            return body;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn metrics_are_served_to_the_admitted_scraper_alone() {
    let dir = TempDir::new("mtls-admitted");
    install(&dir.0, "controller");
    let (c, _rt) = controller(&dir.0);
    let (body, served) = scrape(c.metrics, client("scraper")).unwrap();
    assert_eq!(served, leaf("controller"));
    for zero in ["certificate", "handshake"] {
        let sample = format!(
            "wifi_monitoring_tls_failures_total{{endpoint=\"metrics\",reason=\"{zero}\"}} 0"
        );
        assert!(body.lines().any(|l| l == sample), "{sample}");
    }
    // Another name, another CA, no certificate at all.
    for refused in ["stranger", "foreign"] {
        assert!(scrape(c.metrics, client(refused)).is_err(), "{refused}");
    }
    assert!(scrape(c.metrics, without_certificate()).is_err());
    // Plain HTTP gets no answer of HTTP.
    let mut plain = TcpStream::connect(c.metrics).unwrap();
    plain.set_read_timeout(Some(WAIT)).unwrap();
    write!(
        plain,
        "GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut answer = Vec::new();
    let _ = plain.read_to_end(&mut answer);
    assert!(!answer.starts_with(b"HTTP"), "{answer:?}");
    assert!(ui_answers(c.http));
    let body = failures_reach(c.metrics, "handshake", 4);
    let handshake =
        "wifi_monitoring_tls_failures_total{endpoint=\"metrics\",reason=\"handshake\"} 4";
    assert!(body.lines().any(|l| l == handshake), "{body}");
}

#[test]
fn a_renewal_is_served_at_the_next_connection_and_a_missing_key_fails_only_while_missing() {
    let dir = TempDir::new("mtls-renewal");
    install(&dir.0, "controller");
    let (c, _rt) = controller(&dir.0);
    assert_eq!(
        scrape(c.metrics, client("scraper")).unwrap().1,
        leaf("controller")
    );
    install(&dir.0, "controller-renewed");
    let renewed = leaf("controller-renewed");
    assert_eq!(scrape(c.metrics, client("scraper")).unwrap().1, renewed);
    fs::remove_file(dir.0.join("key.pem")).unwrap();
    assert!(scrape(c.metrics, client("scraper")).is_err());
    assert!(ui_answers(c.http), "the UI is served throughout");
    install(&dir.0, "controller-renewed");
    let body = failures_reach(c.metrics, "certificate", 1);
    let certificate =
        "wifi_monitoring_tls_failures_total{endpoint=\"metrics\",reason=\"certificate\"} 1";
    assert!(body.lines().any(|l| l == certificate), "{body}");
    assert_eq!(scrape(c.metrics, client("scraper")).unwrap().1, renewed);
}
