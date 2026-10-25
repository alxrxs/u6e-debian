//! The runner's configuration file, which its root stage helper reads too:
//! the controller it dials and the key it pins there, its own two keys (the
//! link's, and the one it signs configurations with, which the APs' images
//! pin), its local socket and state directory, the health gate's time, the
//! APs, and how a kept image is staged on one.
//!
//! ```toml
//! controller = "controller.example.net:8443"
//! controller_key = "<64 lowercase hex digits>"
//! tls_key = "/run/credentials/u6e-deploy.service/tls-key.pem"
//! signing_key = "/run/credentials/u6e-deploy.service/signing-key.pem"
//! socket = "/run/u6e-deploy/sock"
//! state = "/var/lib/u6e-deploy"
//! gate_secs = 420
//!
//! # Each AP by the name the site, its images and the controller give it,
//! # with the host name its configurations are signed for.
//! [aps.ap1]
//! hostname = "u6e-ap1"
//!
//! [rollout]
//! # The kept images, each a directory <images>/<id>/ with a MANIFEST.
//! images = "/srv/u6e-debian/images"
//! # The root-owned tree whose boot/stage.sh stages one (with its boot/,
//! # site.conf and log/, as in a u6e-debian checkout).
//! tree = "/usr/local/lib/u6e-deploy"
//! # The stage helper's socket, and the group whose processes it serves.
//! helper = "/run/u6e-deploy-stage.sock"
//! group = "u6e-deploy"
//! ```

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use u6e_proto::mac;

/// The parsed, checked configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The controller's `host:port`.
    pub controller: String,
    pub controller_key: [u8; 32],
    /// The runner's link key (PKCS#8 PEM), which the controller pins.
    pub tls_key: PathBuf,
    /// The key it signs configurations with (PKCS#8 PEM), which the APs'
    /// images pin: another than the link's.
    pub signing_key: PathBuf,
    /// Where local callers ask for applies and rollouts.
    pub socket: PathBuf,
    /// Where what outlives the runner is kept (`store`).
    pub state: PathBuf,
    /// How long after staging an image the AP has to pass the health gate.
    pub gate: Duration,
    /// AP name to the host name its configurations are signed for.
    pub aps: BTreeMap<String, String>,
    pub rollout: Rollout,
}

/// How kept images are staged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rollout {
    pub images: PathBuf,
    /// The root-owned tree whose `boot/stage.sh` stages an image.
    pub tree: PathBuf,
    pub helper: PathBuf,
    pub group: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    controller: String,
    controller_key: String,
    tls_key: PathBuf,
    signing_key: PathBuf,
    socket: PathBuf,
    state: PathBuf,
    #[serde(default = "default_gate")]
    gate_secs: u64,
    aps: BTreeMap<String, ApFile>,
    rollout: RolloutFile,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApFile {
    hostname: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RolloutFile {
    images: PathBuf,
    tree: PathBuf,
    helper: PathBuf,
    group: String,
}

/// Seven minutes: an AP boots and brings its radios up in about two.
fn default_gate() -> u64 {
    420
}

/// Why a configuration was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    Syntax(String),
    /// `controller_key` is not 64 lowercase hex digits.
    BadKey,
    /// `controller` is not `host:port`.
    BadController,
    /// An AP's name or host name is not a plain lowercase name.
    BadName(String),
    NoAps,
    /// `rollout.tree` is not an absolute path.
    BadTree,
    NoGate,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(e) => f.write_str(e.trim_end()),
            Self::BadKey => f.write_str("controller_key is not 64 lowercase hex digits"),
            Self::BadController => f.write_str("controller is not host:port"),
            Self::BadName(ap) => write!(
                f,
                "aps.{ap}: the AP's name and hostname must be lowercase letters, digits and -"
            ),
            Self::NoAps => f.write_str("no aps"),
            Self::BadTree => f.write_str("rollout.tree is not an absolute path"),
            Self::NoGate => f.write_str("gate_secs is 0"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Whether `s` is a plain name: what an AP's names may be, so that they can
/// go into an image's name and a command's arguments as they are.
pub fn plain(s: &str) -> bool {
    let ok = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
    (1..=63).contains(&s.len()) && !s.starts_with('-') && s.chars().all(ok)
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let file: File = toml::from_str(text).map_err(|e| ConfigError::Syntax(e.to_string()))?;
        let controller_key = Some(&file.controller_key)
            .filter(|k| !k.bytes().any(|b| b.is_ascii_uppercase()))
            .and_then(|k| mac::unhex(k))
            .ok_or(ConfigError::BadKey)?;
        let port = file
            .controller
            .rsplit_once(':')
            .map(|(h, p)| (h, p.parse::<u16>()));
        if !matches!(port, Some((h, Ok(_))) if !h.is_empty()) {
            return Err(ConfigError::BadController);
        }
        if file.aps.is_empty() {
            return Err(ConfigError::NoAps);
        }
        let mut aps = BTreeMap::new();
        for (name, ap) in file.aps {
            if !plain(&name) || !plain(&ap.hostname) {
                return Err(ConfigError::BadName(name));
            }
            aps.insert(name, ap.hostname);
        }
        if !file.rollout.tree.is_absolute() {
            return Err(ConfigError::BadTree);
        }
        if file.gate_secs == 0 {
            return Err(ConfigError::NoGate);
        }
        let r = file.rollout;
        Ok(Config {
            controller: file.controller,
            controller_key,
            tls_key: file.tls_key,
            signing_key: file.signing_key,
            socket: file.socket,
            state: file.state,
            gate: Duration::from_secs(file.gate_secs),
            aps,
            rollout: Rollout {
                images: r.images,
                tree: r.tree,
                helper: r.helper,
                group: r.group,
            },
        })
    }

    /// The AP named `ap`'s host name, which its configurations are signed for.
    pub fn hostname(&self, ap: &str) -> Option<&str> {
        self.aps.get(ap).map(String::as_str)
    }

    /// The AP whose host name is `hostname`.
    pub fn ap_of(&self, hostname: &str) -> Option<&str> {
        let mut aps = self.aps.iter();
        aps.find(|(_, h)| *h == hostname).map(|(n, _)| n.as_str())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const KEY: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    /// A whole configuration, `extra` appended at the top level.
    pub fn text(extra: &str) -> String {
        format!(
            "controller = \"controller.example.net:8443\"\ncontroller_key = \"{KEY}\"\n\
             tls_key = \"/k/tls.pem\"\nsigning_key = \"/k/sign.pem\"\nsocket = \"/run/d/sock\"\n\
             state = \"/var/lib/d\"\n\
             {extra}\
             [aps.ap1]\nhostname = \"u6e-ap1\"\n\
             [rollout]\nimages = \"/srv/images\"\ntree = \"/usr/local/lib/d\"\n\
             helper = \"/run/stage.sock\"\ngroup = \"u6e-deploy\"\n"
        )
    }

    #[test]
    fn a_whole_configuration() {
        let c = Config::parse(&text("")).unwrap();
        assert_eq!(c.controller, "controller.example.net:8443");
        assert_eq!(c.controller_key, [1; 32]);
        assert_eq!(c.gate, Duration::from_secs(420));
        assert_eq!(c.hostname("ap1"), Some("u6e-ap1"));
        assert_eq!(c.ap_of("u6e-ap1"), Some("ap1"));
        assert_eq!((c.hostname("ap2"), c.ap_of("ap1")), (None, None));
        assert_eq!(c.rollout.tree, PathBuf::from("/usr/local/lib/d"));
        assert_eq!(c.state, PathBuf::from("/var/lib/d"));
        assert_eq!(c.rollout.group, "u6e-deploy");
        let c = Config::parse(&text("gate_secs = 60\n")).unwrap();
        assert_eq!(c.gate, Duration::from_secs(60));
    }

    #[test]
    fn what_is_refused() {
        let bad = |t: &str| Config::parse(t).unwrap_err();
        assert!(matches!(bad(&text("other = 1\n")), ConfigError::Syntax(_)));
        assert_eq!(bad(&text("gate_secs = 0\n")), ConfigError::NoGate);
        let t = text("");
        assert_eq!(bad(&t.replace(KEY, &"AB".repeat(32))), ConfigError::BadKey);
        assert_eq!(bad(&t.replace(KEY, "ab")), ConfigError::BadKey);
        assert_eq!(bad(&t.replace(":8443", "")), ConfigError::BadController);
        assert_eq!(
            bad(&t.replace("u6e-ap1", "U6E/ap1")),
            ConfigError::BadName("ap1".into())
        );
        assert_eq!(
            bad(&t.replace("[aps.ap1]", "[aps.\"../x\"]")),
            ConfigError::BadName("../x".into())
        );
        assert_eq!(
            bad(&t.replace("/usr/local/lib/d", "lib/d")),
            ConfigError::BadTree
        );
        let none = t.replace("[aps.ap1]\nhostname = \"u6e-ap1\"\n", "[aps]\n");
        assert_eq!(bad(&none), ConfigError::NoAps);
    }

    #[test]
    fn plain_names() {
        for ok in ["ap1", "u6e-ap1", "a"] {
            assert!(plain(ok), "{ok}");
        }
        for bad in ["", "-ap", "Ap1", "a_b", "a.b", "a/b", "ä", &"a".repeat(64)] {
            assert!(!plain(bad), "{bad}");
        }
    }
}
