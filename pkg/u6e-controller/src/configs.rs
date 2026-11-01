//! The signing of live Wi-Fi configurations, `[configs]`: the controller
//! signs every configuration it sends an AP with a key of its own, not its
//! link's, whose public half the AP's image pins (`site.conf`'s
//! `CONFIG_KEY`), so the link's key, which every handshake uses, signs no
//! configuration.
//!
//! ```toml
//! [configs]
//! signing_key = "/etc/wifi-controller/signing-key.pem"   # PKCS#8 PEM
//! state = "/var/lib/wifi-controller/configs"
//! ```
//!
//! A configuration is signed under a sequence number that is the signing
//! time in milliseconds (one past the last when the clock has not moved), so
//! it is newer than every image built before it and than every configuration
//! signed before it, and valid for ten minutes (`config::VALIDITY_MS`); the
//! AP refuses any other. The latest one signed for each AP is kept in
//! `state` (`store`, files 0600: they hold the site's secrets), so that an
//! AP found running another, a reboot having put it back on its image's, say,
//! is signed that one again under a new sequence number, and never an older
//! one, across restarts of the controller too.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use tokio_rustls::rustls::pki_types::PrivateKeyDer;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use u6e_proto::config;
use u6e_proto::msg::{RadioConfig, SignedConfig};
use u6e_proto::tls::Identity;

use crate::policy::ConfigId;
use crate::store::{Store, Unreadable};

/// The checked `[configs]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub signing_key: PathBuf,
    /// Where the latest configuration of each AP is kept.
    pub state: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct File {
    #[serde(default = "default_key")]
    signing_key: PathBuf,
    #[serde(default = "default_state")]
    state: PathBuf,
}

fn default_key() -> PathBuf {
    "/etc/wifi-controller/signing-key.pem".into()
}

fn default_state() -> PathBuf {
    "/var/lib/wifi-controller/configs".into()
}

impl File {
    pub fn check(self) -> Result<Settings, String> {
        if !self.signing_key.is_absolute() || !self.state.is_absolute() {
            return Err("configs: signing_key and state must be absolute paths".into());
        }
        Ok(Settings {
            signing_key: self.signing_key,
            state: self.state,
        })
    }
}

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

pub(crate) fn unix_ms() -> u64 {
    let since = SystemTime::now().duration_since(UNIX_EPOCH);
    since.map_or(0, |d| d.as_millis() as u64)
}

/// The latest configuration signed for an AP.
#[derive(Serialize, Deserialize)]
struct Latest {
    seq: u64,
    radios: Vec<RadioConfig>,
}

impl Latest {
    fn id(&self) -> ConfigId {
        ConfigId {
            sha256: config::config_sha256(&self.radios),
            seq: self.seq,
        }
    }
}

/// The files set aside as they were opened, each with why.
pub type SetAside = Vec<(String, String)>;

fn file_of(hostname: &str) -> String {
    format!("latest-{hostname}")
}

/// The signer: the key, and the latest configuration signed for each AP, by
/// its host name, as `state` keeps them.
pub struct Signer {
    key: Ed25519KeyPair,
    store: Store,
    last_seq: u64,
    latest: HashMap<String, Latest>,
}

impl Signer {
    /// The signer of `key`, with what `state` keeps for the APs of
    /// `hostnames`; a file it cannot read is set aside, and named with why.
    pub fn open<'a>(
        settings: &Settings,
        key: Ed25519KeyPair,
        hostnames: impl IntoIterator<Item = &'a str>,
    ) -> io::Result<(Signer, SetAside)> {
        let store = Store::open(&settings.state)?;
        let (mut latest, mut aside) = (HashMap::new(), Vec::new());
        for hostname in hostnames {
            let name = file_of(hostname);
            match store.load::<Latest>(&name) {
                Ok(Some(l)) => {
                    latest.insert(hostname.to_owned(), l);
                }
                Ok(None) => {}
                Err(Unreadable::Io(e)) => return Err(e),
                Err(Unreadable::Corrupt(why)) => aside.push((store.set_aside(&name)?, why)),
            }
        }
        let last_seq = latest.values().map(|l| l.seq).max().unwrap_or(0);
        let signer = Signer {
            key,
            store,
            last_seq,
            latest,
        };
        Ok((signer, aside))
    }

    /// The files of `state` set aside, and when, oldest first.
    pub fn set_aside(&self) -> io::Result<Vec<(String, u64)>> {
        self.store.set_aside_files()
    }

    pub fn public_key(&self) -> [u8; 32] {
        let mut k = [0; 32];
        k.copy_from_slice(self.key.public_key().as_ref());
        k
    }

    /// The latest configuration signed for the AP of `hostname`.
    pub fn latest(&self, hostname: &str) -> Option<ConfigId> {
        self.latest.get(hostname).map(Latest::id)
    }

    /// `radios`, signed for the AP of `hostname` under the next sequence
    /// number, and kept as its latest.
    pub fn sign(&mut self, hostname: &str, radios: Vec<RadioConfig>) -> SignedConfig {
        self.last_seq = unix_ms().max(self.last_seq + 1);
        let seq = self.last_seq;
        let signed = config::sign(&self.key, hostname, seq, radios.clone());
        let latest = Latest { seq, radios };
        if let Err(e) = self.store.save(&file_of(hostname), &latest) {
            eprintln!("u6e-controller: {hostname}: the latest configuration was not kept: {e}");
        }
        self.latest.insert(hostname.to_owned(), latest);
        signed
    }

    /// The latest configuration of the AP of `hostname`, signed again under
    /// a new sequence number: the old one is a replay to the AP.
    pub fn resign(&mut self, hostname: &str) -> Option<SignedConfig> {
        let radios = self.latest.get(hostname)?.radios.clone();
        Some(self.sign(hostname, radios))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use aws_lc_rs::rand::SystemRandom;
    use u6e_proto::msg::Band;

    use crate::testdir::TestDir;

    const LINK: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJPDgdl1UiKSdc5PGYk7cHQW0aDdKybWtzrCcHWZvr1H\n-----END PRIVATE KEY-----\n";

    fn key() -> Ed25519KeyPair {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn radios(dtim: u8) -> Vec<RadioConfig> {
        vec![RadioConfig {
            radio: Band::B5,
            text: format!("interface=wlan5\ndtim_period={dtim}\n"),
            txpower_dbm: 23,
        }]
    }

    #[test]
    fn the_signing_key_is_not_the_links() {
        let link = Identity::from_pem(LINK).unwrap();
        assert_eq!(
            signing_key(LINK, &link).err().as_deref(),
            Some("the signing key is the link's key: it must be one of its own")
        );
        assert!(signing_key("not a key", &link).is_err());
    }

    /// Each one is newer than the last, the latest is kept (0600) across a
    /// restart, and signing it again makes a newer one of the same radios.
    #[test]
    fn signed_newer_each_time_and_kept() {
        let t = TestDir::new();
        let settings = Settings {
            signing_key: "/unused".into(),
            state: t.path().join("configs"),
        };
        let k = key();
        let public = k.public_key().as_ref().to_vec();
        let (mut s, aside) = Signer::open(&settings, k, ["ap1"]).unwrap();
        assert!(aside.is_empty());
        let a = s.sign("ap1", radios(1));
        let b = s.sign("ap1", radios(2));
        assert!(b.seq > a.seq && a.seq + 10 * 60 * 1000 == a.not_after);
        let pk: [u8; 32] = public.try_into().unwrap();
        assert_eq!(config::verify(&pk, "ap1", &b), Ok(()));
        let mode = fs::metadata(t.path().join("configs/latest-ap1"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        drop(s);
        let (mut s, _) = Signer::open(&settings, key(), ["ap1", "ap2"]).unwrap();
        assert_eq!(s.latest("ap1").map(|l| l.seq), Some(b.seq));
        assert_eq!(s.latest("ap2"), None);
        let c = s.resign("ap1").unwrap();
        assert!(c.seq > b.seq);
        assert_eq!(c.sha256, b.sha256);
        assert!(s.resign("ap2").is_none());
    }

    /// A latest file that cannot be read is set aside and named, and the
    /// signer goes on without it.
    #[test]
    fn an_unreadable_latest_is_set_aside() {
        let t = TestDir::new();
        let settings = Settings {
            signing_key: "/unused".into(),
            state: t.path().join("configs"),
        };
        fs::create_dir_all(&settings.state).unwrap();
        fs::write(settings.state.join("latest-ap1"), b"garbage").unwrap();
        let (s, aside) = Signer::open(&settings, key(), ["ap1"]).unwrap();
        assert_eq!(s.latest("ap1"), None);
        assert_eq!(aside.len(), 1);
        assert!(aside[0].0.starts_with("latest-ap1.corrupt-"), "{aside:?}");
        assert_eq!(s.set_aside().unwrap().len(), 1);
    }
}
