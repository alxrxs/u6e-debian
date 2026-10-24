//! The controller's configuration file: where it listens, its key, and the APs
//! it admits, each by the Ed25519 public key it pins.
//!
//! ```toml
//! listen_agents = "[::]:8443"
//! listen_http = "[::]:8080"
//! listen_metrics = "[::]:9810"
//! key = "/etc/wifi-controller/key.pem"
//!
//! [aps.ap1]
//! public_key = "<64 lowercase hex digits>"
//! ```

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

/// The parsed, checked configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub listen_agents: SocketAddr,
    pub listen_http: SocketAddr,
    pub listen_metrics: SocketAddr,
    /// The controller's Ed25519 private key (PKCS#8 PEM).
    pub key: PathBuf,
    /// AP name to its public key.
    pub aps: BTreeMap<String, [u8; 32]>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default = "default_agents")]
    listen_agents: SocketAddr,
    #[serde(default = "default_http")]
    listen_http: SocketAddr,
    #[serde(default = "default_metrics")]
    listen_metrics: SocketAddr,
    #[serde(default = "default_key")]
    key: PathBuf,
    #[serde(default)]
    aps: BTreeMap<String, ApFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApFile {
    public_key: String,
}

fn default_agents() -> SocketAddr {
    "[::]:8443".parse().expect("valid address")
}

fn default_http() -> SocketAddr {
    "[::]:8080".parse().expect("valid address")
}

fn default_metrics() -> SocketAddr {
    "[::]:9810".parse().expect("valid address")
}

fn default_key() -> PathBuf {
    "/etc/wifi-controller/key.pem".into()
}

/// Why a configuration was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    Syntax(String),
    /// The AP's `public_key` is not 64 lowercase hex digits.
    BadKey(String),
    /// Two APs share a key, so a connection could not be told apart.
    SharedKey(String, String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(e) => f.write_str(e.trim_end()),
            Self::BadKey(ap) => write!(f, "aps.{ap}.public_key is not 64 lowercase hex digits"),
            Self::SharedKey(a, b) => write!(f, "aps.{a} and aps.{b} have the same public_key"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let file: File = toml::from_str(text).map_err(|e| ConfigError::Syntax(e.to_string()))?;
        let mut aps = BTreeMap::new();
        let mut owner = HashMap::new();
        for (name, ap) in file.aps {
            let key = parse_key(&ap.public_key).ok_or_else(|| ConfigError::BadKey(name.clone()))?;
            if let Some(first) = owner.insert(key, name.clone()) {
                return Err(ConfigError::SharedKey(first, name));
            }
            aps.insert(name, key);
        }
        Ok(Config {
            listen_agents: file.listen_agents,
            listen_http: file.listen_http,
            listen_metrics: file.listen_metrics,
            key: file.key,
            aps,
        })
    }
}

/// The 32 bytes of 64 lowercase hex digits: one spelling per key, so a key
/// written twice in different case is still caught as shared.
fn parse_key(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut key = [0; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY1: &str = "0101010101010101010101010101010101010101010101010101010101010101";
    const KEY2: &str = "abababababababababababababababababababababababababababababababab";

    #[test]
    fn defaults_and_aps() {
        let c = Config::parse(&format!(
            "[aps.ap1]\npublic_key = \"{KEY1}\"\n[aps.ap2]\npublic_key = \"{KEY2}\"\n"
        ))
        .unwrap();
        assert_eq!(c.listen_agents, "[::]:8443".parse().unwrap());
        assert_eq!(c.listen_http, "[::]:8080".parse().unwrap());
        assert_eq!(c.listen_metrics, "[::]:9810".parse().unwrap());
        assert_eq!(c.key, PathBuf::from("/etc/wifi-controller/key.pem"));
        assert_eq!(c.aps["ap1"], [1; 32]);
        assert_eq!(c.aps["ap2"], [0xab; 32]);
    }

    #[test]
    fn listeners_and_key_are_set() {
        let c = Config::parse(
            "listen_agents = \"192.0.2.1:1\"\nlisten_http = \"192.0.2.1:2\"\n\
             listen_metrics = \"[2001:db8::1]:3\"\nkey = \"/k.pem\"\n",
        )
        .unwrap();
        assert_eq!(c.listen_agents, "192.0.2.1:1".parse().unwrap());
        assert_eq!(c.listen_http, "192.0.2.1:2".parse().unwrap());
        assert_eq!(c.listen_metrics, "[2001:db8::1]:3".parse().unwrap());
        assert_eq!(c.key, PathBuf::from("/k.pem"));
        assert!(c.aps.is_empty());
    }

    #[test]
    fn bad_keys_refused() {
        let upper = KEY2.to_uppercase();
        for bad in [
            &KEY1[1..],
            "zz",
            upper.as_str(),
            &format!("+{}", &KEY1[1..]),
        ] {
            let text = format!("[aps.ap1]\npublic_key = \"{bad}\"\n");
            assert_eq!(
                Config::parse(&text),
                Err(ConfigError::BadKey("ap1".into())),
                "{bad}"
            );
        }
    }

    #[test]
    fn shared_key_refused() {
        let text =
            format!("[aps.ap1]\npublic_key = \"{KEY1}\"\n[aps.ap2]\npublic_key = \"{KEY1}\"\n");
        assert_eq!(
            Config::parse(&text),
            Err(ConfigError::SharedKey("ap1".into(), "ap2".into()))
        );
    }

    #[test]
    fn unknown_keys_refused() {
        for text in [
            "listen = \"[::]:1\"\n",
            "[aps.ap1]\npublic_key = \"\"\nname = \"x\"\n",
        ] {
            assert!(
                matches!(Config::parse(text), Err(ConfigError::Syntax(_))),
                "{text}"
            );
        }
    }
}
