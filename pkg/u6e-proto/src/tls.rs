//! TLS 1.3 for the access point link: the one key exchange is the hybrid
//! X25519MLKEM768, and each end authenticates the other by an Ed25519 raw
//! public key (RFC 7250) it already knows. There are no certificates, no CA
//! and no clock to be wrong about; trust is the pinned key and nothing else.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};

use aws_lc_rs::digest;
use rustls::client::AlwaysResolvesClientRawPublicKeys;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::aws_lc_rs::{default_provider, kx_group};
use rustls::crypto::{
    CryptoProvider, SupportedKxGroup, WebPkiSupportedAlgorithms,
    verify_tls13_signature_with_raw_key,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::AlwaysResolvesServerRawPublicKeys;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::CertifiedKey;
use rustls::version::TLS13;
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, Error, ServerConfig, ServerConnection,
    SignatureScheme,
};

/// Public key to AP name, shared with the controller so enrolment changes
/// take effect on the next handshake without rebuilding the config.
pub type AllowedKeys = Arc<RwLock<HashMap<[u8; 32], String>>>;

/// DER prefix of an Ed25519 SubjectPublicKeyInfo; the 32 key bytes follow.
const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Why an identity could not be loaded.
#[derive(Debug)]
pub enum TlsError {
    /// The input is not a PEM private key.
    BadPem,
    /// The key is valid but not Ed25519.
    NotEd25519,
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadPem => f.write_str("not a PEM private key"),
            Self::NotEd25519 => f.write_str("private key is not Ed25519"),
        }
    }
}

impl std::error::Error for TlsError {}

/// This end's Ed25519 key pair, presented as a raw public key.
pub struct Identity {
    certified: Arc<CertifiedKey>,
    public: [u8; 32],
}

impl Identity {
    /// Load the PKCS#8 PEM that `openssl genpkey -algorithm ed25519` writes.
    pub fn from_pem(pem: &str) -> Result<Self, TlsError> {
        let der = PrivateKeyDer::from_pem_slice(pem.as_bytes()).map_err(|_| TlsError::BadPem)?;
        let key = default_provider()
            .key_provider
            .load_private_key(der)
            .map_err(|_| TlsError::NotEd25519)?;
        let spki = key.public_key().ok_or(TlsError::NotEd25519)?;
        let public = ed25519_key(spki.as_ref()).ok_or(TlsError::NotEd25519)?;
        let certified = Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(spki.as_ref().to_vec())],
            key,
        ));
        Ok(Self { certified, public })
    }

    /// The 32-byte public key peers pin.
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }
}

/// The 32 key bytes of an Ed25519 SubjectPublicKeyInfo, or `None` for anything else.
fn ed25519_key(spki: &[u8]) -> Option<[u8; 32]> {
    spki.strip_prefix(&SPKI_PREFIX)?.try_into().ok()
}

/// The first 8 bytes of the key's SHA-256, hex: a short stable name for logs.
pub fn fingerprint(key: &[u8; 32]) -> String {
    digest::digest(&digest::SHA256, key).as_ref()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn provider_with(group: &'static dyn SupportedKxGroup) -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider {
        kx_groups: vec![group],
        ..default_provider()
    })
}

/// Pins one server key.
#[derive(Debug)]
struct PinnedServer {
    key: [u8; 32],
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedServer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        match ed25519_key(end_entity.as_ref()) {
            Some(k) if k == self.key => Ok(ServerCertVerified::assertion()),
            _ => Err(Error::General("server key is not the pinned key".into())),
        }
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 is not used".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature_with_raw_key(message, &cert.as_ref().into(), dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// Admits only keys currently in the shared map.
#[derive(Debug)]
struct KnownClients {
    allowed: AllowedKeys,
    algs: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for KnownClients {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        let known = ed25519_key(end_entity.as_ref())
            .is_some_and(|k| self.allowed.read().is_ok_and(|m| m.contains_key(&k)));
        if known {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(Error::General("client key is not enrolled".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 is not used".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature_with_raw_key(message, &cert.as_ref().into(), dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

fn client_with(
    me: &Identity,
    server: [u8; 32],
    provider: Arc<CryptoProvider>,
) -> Arc<ClientConfig> {
    let verifier = PinnedServer {
        key: server,
        algs: provider.signature_verification_algorithms,
    };
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .expect("the provider supports TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(
            me.certified.clone(),
        )));
    Arc::new(config)
}

/// The agent side: connects only to the server holding the `server` key.
pub fn client_config(me: &Identity, server: [u8; 32]) -> Arc<ClientConfig> {
    client_with(me, server, provider_with(kx_group::X25519MLKEM768))
}

/// The controller side: every client must present a key found in `allowed`.
pub fn server_config(me: &Identity, allowed: AllowedKeys) -> Arc<ServerConfig> {
    let provider = provider_with(kx_group::X25519MLKEM768);
    let verifier = KnownClients {
        allowed,
        algs: provider.signature_verification_algorithms,
    };
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .expect("the provider supports TLS 1.3")
        .with_client_cert_verifier(Arc::new(verifier))
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(
            me.certified.clone(),
        )));
    Arc::new(config)
}

/// The enrolled name of the peer whose handshake `conn` completed.
pub fn peer_name(
    conn: &ServerConnection,
    allowed: &RwLock<HashMap<[u8; 32], String>>,
) -> Option<String> {
    let key = ed25519_key(conn.peer_certificates()?.first()?.as_ref())?;
    allowed.read().ok()?.get(&key).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    use rustls::{ClientConnection, ServerConnection};

    // Throwaway Ed25519 keys made for these tests; they protect nothing.
    const KEY_A: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINI3m11iy47fpTD0dKK5Q2ViMRZef+/6f8mIN8n95xZz\n-----END PRIVATE KEY-----\n";
    const KEY_B: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIIoSUDjXsAjqhope0CKaS38rhfHRd7Zp7+uYiC/ncyO7\n-----END PRIVATE KEY-----\n";
    const KEY_C: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINXgz9Oy+9OgZmnmI1vLcuGryYpyy5ILTVbfDkDkP08I\n-----END PRIVATE KEY-----\n";

    fn allowed(keys: &[([u8; 32], &str)]) -> Arc<RwLock<HashMap<[u8; 32], String>>> {
        let map = keys.iter().map(|(k, n)| (*k, n.to_string())).collect();
        Arc::new(RwLock::new(map))
    }

    /// Shuttle handshake bytes between the two ends until both settle or one
    /// errors; the first error is returned with the side that raised it.
    fn pump(
        client: &mut ClientConnection,
        server: &mut ServerConnection,
    ) -> Result<(), (&'static str, rustls::Error)> {
        for _ in 0..16 {
            let mut buf = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut buf).unwrap();
            }
            server.read_tls(&mut buf.as_slice()).unwrap();
            server.process_new_packets().map_err(|e| ("server", e))?;

            let mut buf = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut buf).unwrap();
            }
            client.read_tls(&mut buf.as_slice()).unwrap();
            client.process_new_packets().map_err(|e| ("client", e))?;
        }
        Ok(())
    }

    fn connect(
        client: Arc<rustls::ClientConfig>,
        server: Arc<rustls::ServerConfig>,
    ) -> (ClientConnection, ServerConnection) {
        let name = ServerName::try_from("controller").unwrap();
        (
            ClientConnection::new(client, name).unwrap(),
            ServerConnection::new(server).unwrap(),
        )
    }

    #[test]
    fn handshake_with_pinned_keys() {
        let ap = Identity::from_pem(KEY_A).unwrap();
        let ctl = Identity::from_pem(KEY_B).unwrap();
        let map = allowed(&[(ap.public_key(), "ap1")]);
        let (mut c, mut s) = connect(
            client_config(&ap, ctl.public_key()),
            server_config(&ctl, map.clone()),
        );
        pump(&mut c, &mut s).unwrap();
        assert!(!c.is_handshaking() && !s.is_handshaking());
        assert_eq!(c.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3));
        assert_eq!(
            c.negotiated_key_exchange_group().unwrap().name(),
            rustls::NamedGroup::X25519MLKEM768
        );
        assert_eq!(peer_name(&s, &map).as_deref(), Some("ap1"));
    }

    #[test]
    fn unknown_key_refused() {
        let stranger = Identity::from_pem(KEY_C).unwrap();
        let ap = Identity::from_pem(KEY_A).unwrap();
        let ctl = Identity::from_pem(KEY_B).unwrap();
        let map = allowed(&[(ap.public_key(), "ap1")]);
        let (mut c, mut s) = connect(
            client_config(&stranger, ctl.public_key()),
            server_config(&ctl, map.clone()),
        );
        c.writer().write_all(b"hello").unwrap();
        let (side, err) = pump(&mut c, &mut s).unwrap_err();
        assert!(err.to_string().contains("not enrolled"), "{err}");
        assert_eq!(side, "server");
        assert!(s.reader().read(&mut [0u8; 8]).is_err());
        assert_eq!(peer_name(&s, &map), None);
    }

    #[test]
    fn wrong_server_key_refused() {
        let ap = Identity::from_pem(KEY_A).unwrap();
        let ctl = Identity::from_pem(KEY_B).unwrap();
        let other = Identity::from_pem(KEY_C).unwrap();
        let map = allowed(&[(ap.public_key(), "ap1")]);
        let (mut c, mut s) = connect(
            client_config(&ap, other.public_key()),
            server_config(&ctl, map),
        );
        let (side, err) = pump(&mut c, &mut s).unwrap_err();
        assert!(err.to_string().contains("not the pinned key"), "{err}");
        assert_eq!(side, "client");
    }

    #[test]
    fn x25519_only_client_refused() {
        let ap = Identity::from_pem(KEY_A).unwrap();
        let ctl = Identity::from_pem(KEY_B).unwrap();
        let map = allowed(&[(ap.public_key(), "ap1")]);
        let classical = client_with(&ap, ctl.public_key(), provider_with(kx_group::X25519));
        let (mut c, mut s) = connect(classical, server_config(&ctl, map));
        let (side, err) = pump(&mut c, &mut s).unwrap_err();
        assert_eq!(side, "server", "{err}");
    }
}
