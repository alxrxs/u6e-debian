//! The deploy runner: the one party that originates the APs' Wi-Fi
//! configurations and image rollouts. It keeps an outbound link to the
//! controller (`link`), which admits it by its own key and relays what it
//! sends; it signs every configuration with a key of its own, which the APs'
//! images pin, so neither the controller nor anyone who takes it over can
//! make an AP run a configuration of their own (`runner`). Local callers ask
//! it on its socket for exactly two things, an apply and a rollout (`local`);
//! the controller hands it the rollouts admins ask for and gates each.
//! Rollouts run one at a time (`rollout`), each staged by a root helper that
//! runs u6e-debian's `boot/stage.sh` from a tree only root writes, and
//! nothing else (`stage`), and an AP that does not come back healthy is
//! rolled back to the image the runner staged on it. What outlives the
//! runner, its latest configuration per AP, the image it staged on each and
//! the rollout under way, is in its state directory (`store`).
//! Configurations come as `boot/wifi-up.sh --print` renders them (`script`).

pub mod config;
mod frames;
pub mod link;
pub mod local;
mod rollout;
pub mod runner;
pub mod script;
pub mod stage;
mod store;

use std::fs::{self, Permissions};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use tokio::net::UnixListener;
use tokio_rustls::rustls::pki_types::PrivateKeyDer;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use u6e_proto::tls::Identity;

use crate::config::Config;
use crate::runner::Runner;

/// The signing key of a PKCS#8 PEM (`openssl genpkey -algorithm ed25519`),
/// which must not be the link's `identity`: a key that signs configurations
/// signs nothing else.
pub fn signing_key(pem: &str, identity: &Identity) -> Result<Ed25519KeyPair, String> {
    let der = match PrivateKeyDer::from_pem_slice(pem.as_bytes()) {
        Ok(PrivateKeyDer::Pkcs8(der)) => der,
        _ => return Err("not a PKCS#8 PEM private key".into()),
    };
    let key = Ed25519KeyPair::from_pkcs8_maybe_unchecked(der.secret_pkcs8_der())
        .map_err(|_| "not an Ed25519 private key")?;
    if key.public_key().as_ref() == identity.public_key() {
        return Err("the signing key is the link's key: it must be one of its own".into());
    }
    Ok(key)
}

/// Starts the runner on the current runtime: its local socket (open to its
/// owner and group, the caller checked by its credentials) and its link to
/// the controller.
pub async fn start(
    config: Config,
    identity: Identity,
    key: Ed25519KeyPair,
) -> io::Result<Arc<Runner>> {
    let socket = config.socket.clone();
    match fs::remove_file(&socket) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let listener = UnixListener::bind(&socket)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", socket.display())))?;
    fs::set_permissions(&socket, Permissions::from_mode(0o660))?;
    let (runner, resumed, outbox) = Runner::new(config, key)?;
    tokio::spawn(link::run(Arc::clone(&runner), identity, outbox));
    tokio::spawn(local::serve(Arc::clone(&runner), listener));
    if let Some(flight) = resumed {
        runner.resume(flight);
    }
    Ok(runner)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::{fs, process};

    /// A directory of the test's own, removed when it ends.
    pub struct TestDir(PathBuf);

    impl TestDir {
        pub fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!("u6e-deploy-{}-{n}", process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            TestDir(dir)
        }

        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
