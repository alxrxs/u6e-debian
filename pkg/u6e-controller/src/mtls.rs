//! Mutual TLS 1.3 with the host's monitoring certificate
//! (`[monitoring_tls]`): the chain it presents (leaf first), its key, and
//! the CA bundle every peer is verified against. The controller serves
//! `/metrics` over it to the scrapers it names, when it names any, and
//! [`get`] reads an endpoint over it. The files are read at every
//! connection, so a renewed
//! certificate (new files) counts from the next one with no restart, and a
//! missing, unreadable or mismatched one fails that connection alone:
//! counted and logged, never served or read in plain HTTP instead. rustls
//! on aws-lc-rs, which verifies the P-521 chains a site's CA may sign with;
//! TLS 1.3 only, the hybrid post-quantum key exchange preferred.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::client::danger::HandshakeSignatureValid;
use tokio_rustls::rustls::client::verify_server_name;
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::crypto::aws_lc_rs::{default_provider, kx_group};
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use tokio_rustls::rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use tokio_rustls::rustls::server::{
    NoServerSessionStorage, ParsedCertificate, WebPkiClientVerifier,
};
use tokio_rustls::rustls::version::TLS13;
use tokio_rustls::rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, Error, ServerConfig,
    SignatureScheme,
};
use tokio_rustls::server::TlsStream;

use crate::fetch::{self, Failed};
use crate::state::Shared;

/// The longest a scraper's handshake may take.
const HANDSHAKE_WAIT: Duration = Duration::from_secs(10);
/// Handshaken connections waiting for the HTTP server to take them.
const QUEUE: usize = 16;

/// The host's certificate, as files read at each connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Files {
    /// The chain presented, leaf first (PEM).
    pub cert: PathBuf,
    /// Its private key (PKCS#8, SEC1 or PKCS#1 PEM).
    pub key: PathBuf,
    /// The CA bundle a peer's certificate must chain to (PEM).
    pub ca: PathBuf,
}

/// `[monitoring_tls]`: the files, and the DNS names a scraper's certificate
/// must carry one of; `/metrics` is served over mutual TLS only when some
/// are listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub files: Files,
    pub metrics_clients: Vec<String>,
}

/// An endpoint that speaks mutual TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Endpoint {
    /// `/metrics`, served.
    Metrics,
    /// RADIUS's log, read from Loki.
    Loki,
    /// The DHCP nodes' leases, read from their exporters.
    Leases,
}

impl Endpoint {
    pub fn name(self) -> &'static str {
        match self {
            Self::Metrics => "metrics",
            Self::Loki => "loki",
            Self::Leases => "leases",
        }
    }
}

/// Why a connection over mutual TLS was not made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reason {
    /// The host's own files could not be read or used.
    Certificate,
    /// The handshake failed or was refused, by either side.
    Handshake,
}

impl Reason {
    pub const ALL: [Reason; 2] = [Reason::Certificate, Reason::Handshake];

    pub fn name(self) -> &'static str {
        match self {
            Self::Certificate => "certificate",
            Self::Handshake => "handshake",
        }
    }
}

/// Why a read over mutual TLS (or plain HTTP) failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    Certificate(String),
    Handshake(String),
    /// Anything else: connecting, the time, the HTTP answer.
    Other(String),
}

impl Failure {
    pub fn reason(&self) -> Option<Reason> {
        match self {
            Self::Certificate(_) => Some(Reason::Certificate),
            Self::Handshake(_) => Some(Reason::Handshake),
            Self::Other(_) => None,
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Certificate(e) => write!(f, "the monitoring certificate: {e}"),
            Self::Handshake(e) => write!(f, "TLS: {e}"),
            Self::Other(e) => f.write_str(e),
        }
    }
}

impl From<Failed> for Failure {
    fn from(f: Failed) -> Self {
        match f {
            Failed::Tls(e) => Self::Handshake(e),
            Failed::Other(e) => Self::Other(e),
        }
    }
}

/// The connections not made, per endpoint switched to mutual TLS and why,
/// for the metrics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Failures {
    pub on: BTreeSet<Endpoint>,
    pub counts: BTreeMap<(Endpoint, Reason), u64>,
}

impl Failures {
    pub fn new(on: impl IntoIterator<Item = Endpoint>) -> Self {
        Failures {
            on: on.into_iter().collect(),
            counts: BTreeMap::new(),
        }
    }

    /// Counts `failure` of `endpoint`, if it is one of TLS.
    pub fn count(&mut self, endpoint: Endpoint, failure: &Failure) {
        if let Some(r) = failure.reason() {
            *self.counts.entry((endpoint, r)).or_default() += 1;
        }
    }
}

/// aws-lc-rs, offering X25519MLKEM768 first and the classical groups after
/// it for a peer without it.
fn provider() -> Arc<CryptoProvider> {
    let mut groups = vec![kx_group::X25519MLKEM768];
    groups.extend(
        default_provider()
            .kx_groups
            .into_iter()
            .filter(|g| g.name() != kx_group::X25519MLKEM768.name()),
    );
    Arc::new(CryptoProvider {
        kx_groups: groups,
        ..default_provider()
    })
}

impl Files {
    /// The chain and key as they are now in their files.
    fn certified(&self) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
        let at = |p: &PathBuf, e: &dyn fmt::Display| format!("{}: {e}", p.display());
        let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&self.cert)
            .map_err(|e| at(&self.cert, &e))?
            .collect::<Result<_, _>>()
            .map_err(|e| at(&self.cert, &e))?;
        if chain.is_empty() {
            return Err(at(&self.cert, &"no certificate"));
        }
        let key = PrivateKeyDer::from_pem_file(&self.key).map_err(|e| at(&self.key, &e))?;
        Ok((chain, key))
    }

    /// A server presenting the certificate and admitting only a client
    /// whose certificate chains to the bundle and names one of `clients`.
    pub fn server(&self, clients: &[String]) -> Result<Arc<ServerConfig>, String> {
        let (chain, key) = self.certified()?;
        let roots = Arc::new(fetch::roots(&self.ca)?);
        let provider = provider();
        let inner = WebPkiClientVerifier::builder_with_provider(roots, Arc::clone(&provider))
            .build()
            .map_err(|e| e.to_string())?;
        let names = clients
            .iter()
            .map(|c| ServerName::try_from(c.clone()).map_err(|e| format!("{c:?}: {e}")))
            .collect::<Result<_, _>>()?;
        let verifier = Arc::new(Admitted { inner, names });
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&TLS13])
            .map_err(|e| e.to_string())?
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key)
            .map_err(|e| format!("{}: {e}", self.key.display()))?;
        // A resumed session would skip the client's certificate.
        config.session_storage = Arc::new(NoServerSessionStorage {});
        Ok(Arc::new(config))
    }

    /// A client presenting the certificate and trusting only a server whose
    /// certificate chains to the bundle (its name is the one dialled).
    pub fn client(&self) -> Result<Arc<ClientConfig>, String> {
        let (chain, key) = self.certified()?;
        let roots = fetch::roots(&self.ca)?;
        let config = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&TLS13])
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_client_auth_cert(chain, key)
            .map_err(|e| format!("{}: {e}", self.key.display()))?;
        Ok(Arc::new(config))
    }
}

/// The body `address` (`host:port`) answers a GET of `target` with, of at
/// most `max` bytes, within `wait`: over mutual TLS with `tls`, else plain
/// HTTP; why not, otherwise.
pub async fn get(
    tls: Option<&Files>,
    address: &str,
    target: &str,
    accept: &str,
    max: usize,
    wait: Duration,
) -> Result<String, Failure> {
    let Some(files) = tls else {
        return fetch::get(address, target, accept, max, wait)
            .await
            .map_err(Failure::Other);
    };
    let config = files.client().map_err(Failure::Certificate)?;
    let (host, port) = address
        .rsplit_once(':')
        .and_then(|(h, p)| Some((h, p.parse().ok()?)))
        .ok_or_else(|| Failure::Other(format!("{address:?} is not host:port")))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    Ok(fetch::get_tls((host, port), config, target, accept, max, wait).await?)
}

/// The verifier of the bundle, then the names: a certificate that chains
/// but names no admitted client is refused in the handshake.
#[derive(Debug)]
struct Admitted {
    inner: Arc<dyn ClientCertVerifier>,
    names: Vec<ServerName<'static>>,
}

impl ClientCertVerifier for Admitted {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        self.inner
            .verify_client_cert(end_entity, intermediates, now)?;
        let cert = ParsedCertificate::try_from(end_entity)?;
        if self
            .names
            .iter()
            .any(|n| verify_server_name(&cert, n).is_ok())
        {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(Error::InvalidCertificate(CertificateError::NotValidForName))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// The metrics listener's connections over mutual TLS: each accepted
/// connection is handshaken in a task of its own, so a slow or refused one
/// holds up no other, and only an admitted scraper's reaches the HTTP
/// server.
pub struct Listener {
    ready: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
}

/// Serves `tcp` over mutual TLS as `settings` say, each failure counted in
/// `state` and logged with its peer.
pub fn listen(tcp: TcpListener, settings: Settings, state: Shared) -> io::Result<Listener> {
    let local = tcp.local_addr()?;
    let (tx, ready) = mpsc::channel(QUEUE);
    tokio::spawn(accept(tcp, Arc::new(settings), state, tx));
    Ok(Listener { ready, local })
}

async fn accept(
    tcp: TcpListener,
    settings: Arc<Settings>,
    state: Shared,
    tx: mpsc::Sender<(TlsStream<TcpStream>, SocketAddr)>,
) {
    loop {
        let (sock, peer) = match tcp.accept().await {
            Ok(c) => c,
            // Out of descriptors, most likely: let connections end first.
            Err(e) => {
                eprintln!("u6e-controller: metrics accept: {e}");
                sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let (settings, state, tx) = (Arc::clone(&settings), state.clone(), tx.clone());
        tokio::spawn(async move {
            match handshake(&settings, sock).await {
                Ok(tls) => {
                    let _ = tx.send((tls, peer)).await;
                }
                Err(f) => {
                    eprintln!("u6e-controller: metrics to {peer}: {f}");
                    state.write().tls_failures.count(Endpoint::Metrics, &f);
                }
            }
        });
    }
}

async fn handshake(settings: &Settings, sock: TcpStream) -> Result<TlsStream<TcpStream>, Failure> {
    let config = settings
        .files
        .server(&settings.metrics_clients)
        .map_err(Failure::Certificate)?;
    match timeout(HANDSHAKE_WAIT, TlsAcceptor::from(config).accept(sock)).await {
        Ok(Ok(tls)) => Ok(tls),
        Ok(Err(e)) => Err(Failure::Handshake(e.to_string())),
        Err(_) => Err(Failure::Handshake(format!(
            "not finished in {} s",
            HANDSHAKE_WAIT.as_secs()
        ))),
    }
}

impl axum::serve::Listener for Listener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.ready.recv().await {
            Some(c) => c,
            // The accept loop never ends while the listener lives.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

/// The test certificates (`tests/fixtures/mtls`, made by its `make.sh`: a
/// P-521 root and issuing CA signing with SHA-512, P-384 leaves) and a TLS
/// server of them, for these tests and the readers'.
#[cfg(test)]
pub(crate) mod testing {
    use std::sync::Mutex;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    pub const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/mtls");

    /// The fixture `name`'s chain and key, with the test CA bundle.
    pub fn files(name: &str) -> Files {
        Files {
            cert: format!("{DIR}/{name}.pem").into(),
            key: format!("{DIR}/{name}.key").into(),
            ca: format!("{DIR}/chain.pem").into(),
        }
    }

    /// A TLS acceptor presenting the fixture `name`, admitting `clients`.
    pub fn acceptor(name: &str, clients: &[&str]) -> TlsAcceptor {
        let clients: Vec<String> = clients.iter().map(|c| (*c).to_owned()).collect();
        TlsAcceptor::from(files(name).server(&clients).unwrap())
    }

    /// The handshakes a test server saw: each client's leaf, or why it
    /// refused the client.
    pub type Seen = Arc<Mutex<Vec<Result<Vec<u8>, String>>>>;

    /// A server on `ip` presenting the fixture `name`, admitting the
    /// `clients`, answering each request with `answer`.
    pub async fn server(
        ip: &str,
        name: &str,
        clients: &[&str],
        answer: &'static str,
    ) -> (String, Seen) {
        let acceptor = acceptor(name, clients);
        let l = TcpListener::bind((ip, 0)).await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let seen: Seen = Arc::default();
        let saw = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let (sock, _) = l.accept().await.unwrap();
                let mut tls = match acceptor.accept(sock).await {
                    Ok(t) => t,
                    Err(e) => {
                        saw.lock().unwrap().push(Err(e.to_string()));
                        continue;
                    }
                };
                let leaf = tls.get_ref().1.peer_certificates().unwrap()[0].to_vec();
                saw.lock().unwrap().push(Ok(leaf));
                let mut buf = [0; 4096];
                let _ = tls.read(&mut buf).await;
                let reply = format!("HTTP/1.0 200 OK\r\n\r\n{answer}");
                let _ = tls.write_all(reply.as_bytes()).await;
                let _ = tls.shutdown().await;
            }
        });
        (addr, seen)
    }

    /// The leaf (the first certificate) of the fixture `name`.
    pub fn leaf(name: &str) -> Vec<u8> {
        let mut certs = CertificateDer::pem_file_iter(format!("{DIR}/{name}.pem")).unwrap();
        certs.next().unwrap().unwrap().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::NamedGroup;

    use super::testing::{files, leaf, server};
    use super::*;
    use crate::testdir::TestDir;

    const WAIT: Duration = Duration::from_secs(5);

    async fn ask(tls: &Files, address: &str) -> Result<String, Failure> {
        get(Some(tls), address, "/x", "text/plain", 1 << 20, WAIT).await
    }

    /// A chain of a site's shape (P-521 CAs signing SHA-512, a P-384 leaf)
    /// verified both ways, by address and by name, over the hybrid key
    /// exchange.
    #[tokio::test]
    async fn a_sites_chain_is_verified_both_ways() {
        let me = files("controller");
        let (addr, seen) = server("127.0.0.1", "server1", &["controller.example.org"], "hi").await;
        assert_eq!(ask(&me, &addr).await, Ok("hi".into()));
        assert_eq!(seen.lock().unwrap()[0], Ok(leaf("controller")));
        let port = addr.rsplit_once(':').unwrap().1;
        assert_eq!(
            ask(&me, &format!("localhost:{port}")).await,
            Ok("hi".into())
        );
        let sock = TcpStream::connect(&addr).await.unwrap();
        let name = ServerName::try_from("127.0.0.1").unwrap();
        let tls = TlsConnector::from(me.client().unwrap())
            .connect(name, sock)
            .await
            .unwrap();
        let group = tls.get_ref().1.negotiated_key_exchange_group().unwrap();
        assert_eq!(group.name(), NamedGroup::X25519MLKEM768);
    }

    /// The server admits a certificate of the bundle's that names an
    /// admitted client, and refuses in the handshake one naming another,
    /// one of another CA and a client with none.
    #[tokio::test]
    async fn a_client_is_admitted_by_its_name_alone() {
        let (addr, seen) = server("127.0.0.1", "server1", &["status1.example.org"], "hi").await;
        assert_eq!(ask(&files("scraper"), &addr).await, Ok("hi".into()));
        for refused in ["stranger", "controller", "foreign"] {
            assert!(ask(&files(refused), &addr).await.is_err(), "{refused}");
        }
        let bare = fetch::tls_client(&files("scraper").ca).unwrap();
        let port = addr.rsplit_once(':').unwrap().1.parse().unwrap();
        let r = fetch::get_tls(("127.0.0.1", port), bare, "/", "*/*", 64, WAIT).await;
        assert!(r.is_err());
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen[0], Ok(leaf("scraper")));
        let why: Vec<String> = seen[1..].iter().map(|s| s.clone().unwrap_err()).collect();
        assert!(why[0].contains("NotValidForName"), "{why:?}");
        assert!(why[1].contains("NotValidForName"), "{why:?}");
        assert!(why[2].contains("UnknownIssuer"), "{why:?}");
        assert!(why[3].contains("no certificates"), "{why:?}");
    }

    /// The client trusts only a server the bundle vouches for by the name
    /// it dialled, and never speaks plain HTTP to one that does not speak
    /// TLS.
    #[tokio::test]
    async fn a_server_is_trusted_by_the_bundle_and_the_name_dialled() {
        let me = files("controller");
        let (other_name, _) = server("127.0.0.1", "server2", &["controller.example.org"], "").await;
        let e = ask(&me, &other_name).await.unwrap_err();
        assert!(
            matches!(&e, Failure::Handshake(w) if w.contains("not valid for name")),
            "{e}"
        );
        let (other_ca, _) = server("127.0.0.1", "foreign", &["controller.example.org"], "").await;
        let e = ask(&me, &other_ca).await.unwrap_err();
        assert!(
            matches!(&e, Failure::Handshake(w) if w.contains("UnknownIssuer")),
            "{e}"
        );
        let plain = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = plain.local_addr().unwrap().to_string();
        let heard = tokio::spawn(async move {
            let (mut s, _) = plain.accept().await.unwrap();
            let mut first = [0; 1];
            s.read_exact(&mut first).await.unwrap();
            let _ = s.write_all(b"HTTP/1.0 400 Bad Request\r\n\r\n").await;
            first[0]
        });
        assert!(matches!(ask(&me, &addr).await, Err(Failure::Handshake(_))));
        // A TLS handshake record, never a request.
        assert_eq!(heard.await.unwrap(), 0x16);
    }

    /// The files are read at each connection: a renewal (new files, a new
    /// key) is presented at the next one, and a missing or mismatched key
    /// fails that connection alone.
    #[tokio::test]
    async fn the_files_are_read_at_each_connection() {
        let dir = TestDir::new();
        let put = |name: &str| {
            for ext in ["pem", "key"] {
                let new = dir.path().join(format!("new.{ext}"));
                fs::copy(format!("{}/{name}.{ext}", testing::DIR), &new).unwrap();
                fs::rename(&new, dir.path().join(format!("cert.{ext}"))).unwrap();
            }
        };
        let me = Files {
            cert: dir.path().join("cert.pem"),
            key: dir.path().join("cert.key"),
            ca: files("controller").ca,
        };
        let (addr, seen) = server("127.0.0.1", "server1", &["controller.example.org"], "hi").await;
        put("controller");
        assert_eq!(ask(&me, &addr).await, Ok("hi".into()));
        put("controller-renewed");
        assert_eq!(ask(&me, &addr).await, Ok("hi".into()));
        let seen = seen.lock().unwrap().clone();
        assert_eq!(
            seen,
            [Ok(leaf("controller")), Ok(leaf("controller-renewed"))]
        );
        // The renewal's key under the certificate before it.
        fs::copy(files("controller").cert, &me.cert).unwrap();
        let e = ask(&me, &addr).await.unwrap_err();
        assert!(
            matches!(&e, Failure::Certificate(w) if w.contains("cert.key")),
            "{e}"
        );
        assert!(me.server(&["x.example.org".into()]).is_err());
        fs::remove_file(&me.key).unwrap();
        assert!(matches!(
            ask(&me, &addr).await,
            Err(Failure::Certificate(_))
        ));
        let no_ca = Files {
            ca: dir.path().join("none.pem"),
            ..files("controller")
        };
        assert!(matches!(
            ask(&no_ca, &addr).await,
            Err(Failure::Certificate(_))
        ));
    }

    #[test]
    fn failures_are_counted_by_endpoint_and_reason() {
        let mut f = Failures::new([Endpoint::Loki]);
        f.count(Endpoint::Loki, &Failure::Certificate("x".into()));
        f.count(Endpoint::Loki, &Failure::Handshake("x".into()));
        f.count(Endpoint::Loki, &Failure::Handshake("x".into()));
        f.count(Endpoint::Loki, &Failure::Other("refused".into()));
        let counts: Vec<_> = f.counts.into_iter().collect();
        assert_eq!(
            counts,
            [
                ((Endpoint::Loki, Reason::Certificate), 1),
                ((Endpoint::Loki, Reason::Handshake), 2)
            ]
        );
    }
}
