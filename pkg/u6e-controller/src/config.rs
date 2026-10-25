//! The controller's configuration file: where it listens, its key, the APs it
//! admits, each by the Ed25519 public key it pins and the host name its agent
//! must name itself by (the AP's name unless set), the deploy runner it
//! admits on the same listener by its own key (without one, configurations
//! and rollouts are off), and what the operator actions need: the origin the
//! UI is served at (required), the group allowed to act, and where the
//! decisions are kept.
//!
//! ```toml
//! listen_agents = "[::]:8443"
//! listen_http = "[::]:8080"
//! listen_metrics = "[::]:9810"
//! key = "/etc/wifi-controller/key.pem"
//! public_origin = "https://wifi.example.org"
//! admin_group = "wifi-admins"
//! policy_path = "/var/lib/wifi-controller/policy.json"
//!
//! [aps.ap1]
//! public_key = "<64 lowercase hex digits>"
//! hostname = "u6e-ap1"
//!
//! [runner]
//! public_key = "<64 lowercase hex digits>"
//! ```

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;
use u6e_proto::mac;

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
    /// AP name to the host name its agent names itself by in its Hello, and
    /// configurations are signed for: the key decides which AP a session
    /// is, and an agent naming another host is turned away.
    pub hostnames: BTreeMap<String, String>,
    /// The deploy runner's public key (its link's, not the one it signs
    /// configurations with, which only the APs check).
    pub runner: Option<[u8; 32]>,
    /// The scheme, host and port the browser reaches the UI at: the only
    /// `Origin` an action is taken from.
    pub public_origin: String,
    /// The group, as the sign-in proxy names it, whose members may act.
    pub admin_group: String,
    /// The operator's decisions (the blocked clients), kept across restarts.
    pub policy_path: PathBuf,
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
    runner: Option<KeyFile>,
    public_origin: String,
    #[serde(default = "default_admin_group")]
    admin_group: String,
    #[serde(default = "default_policy")]
    policy_path: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApFile {
    public_key: String,
    hostname: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
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

fn default_admin_group() -> String {
    "wifi-admins".into()
}

fn default_policy() -> PathBuf {
    "/var/lib/wifi-controller/policy.json".into()
}

/// Why a configuration was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    Syntax(String),
    /// The AP's `public_key` is not 64 lowercase hex digits.
    BadKey(String),
    /// Two APs share a key, so a connection could not be told apart.
    SharedKey(String, String),
    /// An AP's `hostname` is empty or longer than 64 bytes.
    BadHostname(String),
    /// Two APs share a host name, so a configuration could not be routed.
    SharedHostname(String, String),
    /// The runner's `public_key` is not 64 lowercase hex digits.
    BadRunnerKey,
    /// The runner's key is an AP's: that AP could act as the runner.
    RunnerIsAp(String),
    /// `public_origin` is not spelled as a browser's `Origin` header is.
    BadOrigin,
    /// `admin_group` is empty, which no group header could match.
    NoAdminGroup,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(e) => f.write_str(e.trim_end()),
            Self::BadKey(ap) => write!(f, "aps.{ap}.public_key is not 64 lowercase hex digits"),
            Self::SharedKey(a, b) => write!(f, "aps.{a} and aps.{b} have the same public_key"),
            Self::BadHostname(ap) => write!(f, "aps.{ap}.hostname is empty or too long"),
            Self::SharedHostname(a, b) => write!(f, "aps.{a} and aps.{b} have the same hostname"),
            Self::BadRunnerKey => f.write_str("runner.public_key is not 64 lowercase hex digits"),
            Self::RunnerIsAp(ap) => write!(f, "runner.public_key is aps.{ap}'s"),
            Self::BadOrigin => f.write_str(
                "public_origin is not scheme://host[:port] (no path, no trailing slash)",
            ),
            Self::NoAdminGroup => f.write_str("admin_group is empty"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let file: File = toml::from_str(text).map_err(|e| ConfigError::Syntax(e.to_string()))?;
        let mut aps = BTreeMap::new();
        let mut hostnames = BTreeMap::new();
        let mut owner = HashMap::new();
        let mut host_owner = HashMap::new();
        for (name, ap) in file.aps {
            let key = parse_key(&ap.public_key).ok_or_else(|| ConfigError::BadKey(name.clone()))?;
            if let Some(first) = owner.insert(key, name.clone()) {
                return Err(ConfigError::SharedKey(first, name));
            }
            let hostname = ap.hostname.unwrap_or_else(|| name.clone());
            if hostname.is_empty() || hostname.len() > 64 {
                return Err(ConfigError::BadHostname(name));
            }
            if let Some(first) = host_owner.insert(hostname.clone(), name.clone()) {
                return Err(ConfigError::SharedHostname(first, name));
            }
            hostnames.insert(name.clone(), hostname);
            aps.insert(name, key);
        }
        let runner = match file.runner {
            Some(r) => Some(parse_key(&r.public_key).ok_or(ConfigError::BadRunnerKey)?),
            None => None,
        };
        if let Some(ap) = runner.and_then(|k| owner.remove(&k)) {
            return Err(ConfigError::RunnerIsAp(ap));
        }
        if !is_origin(&file.public_origin) {
            return Err(ConfigError::BadOrigin);
        }
        if file.admin_group.trim().is_empty() {
            return Err(ConfigError::NoAdminGroup);
        }
        Ok(Config {
            listen_agents: file.listen_agents,
            listen_http: file.listen_http,
            listen_metrics: file.listen_metrics,
            key: file.key,
            aps,
            hostnames,
            runner,
            public_origin: file.public_origin,
            admin_group: file.admin_group,
            policy_path: file.policy_path,
        })
    }
}

/// Whether `s` is spelled as a browser sends `Origin`: an http(s) scheme and
/// a host, with nothing after it but a port, so that comparing the header with
/// it byte for byte is the whole check.
fn is_origin(s: &str) -> bool {
    let Some((scheme, rest)) = s.split_once("://") else {
        return false;
    };
    let host = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || "-.:[]".contains(c);
    matches!(scheme, "http" | "https") && !rest.is_empty() && rest.chars().all(host)
}

/// The 32 bytes of 64 lowercase hex digits: one spelling per key, so a key
/// written twice in different case is still caught as shared.
fn parse_key(hex: &str) -> Option<[u8; 32]> {
    if hex.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    mac::unhex(hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY1: &str = "0101010101010101010101010101010101010101010101010101010101010101";
    const KEY2: &str = "abababababababababababababababababababababababababababababababab";
    const ORIGIN: &str = "public_origin = \"https://wifi.example.org\"\n";

    #[test]
    fn defaults_and_aps() {
        let c = Config::parse(&format!(
            "{ORIGIN}[aps.ap1]\npublic_key = \"{KEY1}\"\n[aps.ap2]\npublic_key = \"{KEY2}\"\n"
        ))
        .unwrap();
        assert_eq!(c.listen_agents, "[::]:8443".parse().unwrap());
        assert_eq!(c.listen_http, "[::]:8080".parse().unwrap());
        assert_eq!(c.listen_metrics, "[::]:9810".parse().unwrap());
        assert_eq!(c.key, PathBuf::from("/etc/wifi-controller/key.pem"));
        assert_eq!(c.aps["ap1"], [1; 32]);
        assert_eq!(c.aps["ap2"], [0xab; 32]);
        // Without a hostname, an AP's agent names itself by the AP's name.
        assert_eq!(c.hostnames["ap1"], "ap1");
        assert_eq!(c.runner, None);
        assert_eq!(c.public_origin, "https://wifi.example.org");
        assert_eq!(c.admin_group, "wifi-admins");
        assert_eq!(
            c.policy_path,
            PathBuf::from("/var/lib/wifi-controller/policy.json")
        );
    }

    #[test]
    fn listeners_and_key_are_set() {
        let c = Config::parse(
            "listen_agents = \"192.0.2.1:1\"\nlisten_http = \"192.0.2.1:2\"\n\
             listen_metrics = \"[2001:db8::1]:3\"\nkey = \"/k.pem\"\n\
             public_origin = \"http://[2001:db8::1]:8080\"\nadmin_group = \"ops\"\n\
             policy_path = \"/p.json\"\n",
        )
        .unwrap();
        assert_eq!(c.listen_agents, "192.0.2.1:1".parse().unwrap());
        assert_eq!(c.listen_http, "192.0.2.1:2".parse().unwrap());
        assert_eq!(c.listen_metrics, "[2001:db8::1]:3".parse().unwrap());
        assert_eq!(c.key, PathBuf::from("/k.pem"));
        assert!(c.aps.is_empty());
        assert_eq!(c.public_origin, "http://[2001:db8::1]:8080");
        assert_eq!(c.admin_group, "ops");
        assert_eq!(c.policy_path, PathBuf::from("/p.json"));
    }

    #[test]
    fn the_origin_is_required_and_spelled_as_browsers_send_it() {
        assert!(matches!(Config::parse(""), Err(ConfigError::Syntax(_))));
        for bad in [
            "wifi.example.org",
            "https://wifi.example.org/",
            "https://wifi.example.org/ui",
            "https://Wifi.example.org",
            "ftp://wifi.example.org",
            "https://",
        ] {
            let text = format!("public_origin = \"{bad}\"\n");
            assert_eq!(Config::parse(&text), Err(ConfigError::BadOrigin), "{bad}");
        }
        let text = format!("{ORIGIN}admin_group = \" \"\n");
        assert_eq!(Config::parse(&text), Err(ConfigError::NoAdminGroup));
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
            let text = format!("{ORIGIN}[aps.ap1]\npublic_key = \"{bad}\"\n");
            assert_eq!(
                Config::parse(&text),
                Err(ConfigError::BadKey("ap1".into())),
                "{bad}"
            );
        }
    }

    #[test]
    fn shared_key_refused() {
        let text = format!(
            "{ORIGIN}[aps.ap1]\npublic_key = \"{KEY1}\"\n[aps.ap2]\npublic_key = \"{KEY1}\"\n"
        );
        assert_eq!(
            Config::parse(&text),
            Err(ConfigError::SharedKey("ap1".into(), "ap2".into()))
        );
    }

    /// The runner is admitted by a key of its own, never an AP's: the
    /// listener tells the two roles apart by the key alone.
    #[test]
    fn each_ap_has_a_host_name_of_its_own() {
        let ap = |name: &str, key: &str, host: &str| {
            format!("[aps.{name}]\npublic_key = \"{key}\"\nhostname = \"{host}\"\n")
        };
        let two = |h1: &str, h2: &str| {
            Config::parse(&format!(
                "{ORIGIN}{}{}",
                ap("ap1", KEY1, h1),
                ap("ap2", KEY2, h2)
            ))
        };
        let c = two("u6e-ap1", "u6e-ap2").unwrap();
        assert_eq!(c.hostnames["ap1"], "u6e-ap1");
        assert_eq!(c.hostnames["ap2"], "u6e-ap2");
        assert_eq!(
            two("u6e-ap1", "u6e-ap1"),
            Err(ConfigError::SharedHostname("ap1".into(), "ap2".into()))
        );
        assert_eq!(
            two("", "u6e-ap2"),
            Err(ConfigError::BadHostname("ap1".into()))
        );
    }

    #[test]
    fn the_runner_has_a_key_of_its_own() {
        let ap = format!("{ORIGIN}[aps.ap1]\npublic_key = \"{KEY1}\"\n");
        let c = Config::parse(&format!("{ap}[runner]\npublic_key = \"{KEY2}\"\n")).unwrap();
        assert_eq!(c.runner, Some([0xab; 32]));
        assert_eq!(
            Config::parse(&format!("{ap}[runner]\npublic_key = \"{KEY1}\"\n")),
            Err(ConfigError::RunnerIsAp("ap1".into()))
        );
        assert_eq!(
            Config::parse(&format!("{ap}[runner]\npublic_key = \"{}\"\n", &KEY2[1..])),
            Err(ConfigError::BadRunnerKey)
        );
    }

    #[test]
    fn unknown_keys_refused() {
        for text in [
            "listen = \"[::]:1\"\n",
            "[aps.ap1]\npublic_key = \"\"\nname = \"x\"\n",
        ] {
            let text = format!("{ORIGIN}{text}");
            assert!(
                matches!(Config::parse(&text), Err(ConfigError::Syntax(_))),
                "{text}"
            );
        }
    }
}
