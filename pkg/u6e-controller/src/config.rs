//! The controller's configuration file: where it listens, its key, the APs it
//! admits, each by the Ed25519 public key it pins, the host name its agent
//! must name itself by (the AP's name unless set) and the address its SSH
//! answers on (which rollouts stage it through), and what the operator
//! actions need: the origin the UI is served at (required), the group allowed
//! to act, and where the decisions are kept; the local socket root's commands
//! reach it on (`local`); in `[configs]`, the signing of live Wi-Fi
//! configurations (`configs`), and in `[rollouts]`, the kept images and their
//! rollouts (`rollout`), each off without its section; in `[rf]`, the RF
//! planner's (`rf::config`), without which it is off; in `[leases]`, the
//! DHCP nodes' node exporters the clients' leases are read from (`leases`),
//! none without it; and, in `[guards]`, the VLANs the APs' client guards
//! enforce on and the clients with a static address, the guards only
//! reporting without it.
//!
//! ```toml
//! listen_agents = "[::]:8443"
//! listen_http = "[::]:8080"
//! listen_metrics = "[::]:9810"
//! key = "/etc/wifi-controller/key.pem"
//! public_origin = "https://wifi.example.org"
//! admin_group = "wifi-admins"
//! policy_path = "/var/lib/wifi-controller/policy.json"
//! socket = "/run/wifi-controller/sock"
//!
//! [aps.ap1]
//! public_key = "<64 lowercase hex digits>"
//! hostname = "u6e-ap1"
//! address = "192.0.2.16"
//!
//! [configs]
//! signing_key = "/etc/wifi-controller/signing-key.pem"
//!
//! [rollouts]
//! root_key = "/etc/wifi-controller/ap-root-key"
//! stock_password = "/etc/wifi-controller/ap-stock-password"
//! known_hosts = "/etc/wifi-controller/ap-known-hosts"
//!
//! [leases]
//! exporters = ["dhcp1.example.org:9100", "[2001:db8::53]:9100"]
//!
//! [guards]
//! enforce = [42]
//! static = [{ mac = "02:00:00:00:00:01", ip = "192.0.2.5" }]
//! ```

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use serde::Deserialize;
use u6e_proto::mac;
use u6e_proto::msg::{Binding, GuardConfig};

use crate::{configs, rf, rollout};

/// The parsed, checked configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub listen_agents: SocketAddr,
    pub listen_http: SocketAddr,
    pub listen_metrics: SocketAddr,
    /// The controller's Ed25519 private key (PKCS#8 PEM), its link's.
    pub key: PathBuf,
    /// AP name to its public key.
    pub aps: BTreeMap<String, [u8; 32]>,
    /// AP name to the host name its agent names itself by in its Hello, and
    /// configurations are signed for: the key decides which AP a session
    /// is, and an agent naming another host is turned away.
    pub hostnames: BTreeMap<String, String>,
    /// AP name to the address (an IP address or a DNS name) both of its
    /// systems answer SSH on.
    pub addresses: BTreeMap<String, String>,
    /// The scheme, host and port the browser reaches the UI at: the only
    /// `Origin` an action is taken from.
    pub public_origin: String,
    /// The group, as the sign-in proxy names it, whose members may act.
    pub admin_group: String,
    /// The operator's decisions (the blocked clients), kept across restarts.
    pub policy_path: PathBuf,
    /// Where root's local commands reach the controller.
    pub socket: PathBuf,
    /// The signing of live configurations, if it is on.
    pub configs: Option<configs::Settings>,
    /// The kept images and their rollouts, if they are on.
    pub rollouts: Option<rollout::Settings>,
    /// The RF planner's settings, if it is on.
    pub rf: Option<rf::config::Settings>,
    /// The node exporters (`host:port`) that publish the DHCP leases.
    pub leases: Vec<String>,
    /// How the APs' client guards run.
    pub guards: GuardConfig,
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
    public_origin: String,
    #[serde(default = "default_admin_group")]
    admin_group: String,
    #[serde(default = "default_policy")]
    policy_path: PathBuf,
    #[serde(default = "default_socket")]
    socket: PathBuf,
    configs: Option<configs::File>,
    rollouts: Option<rollout::File>,
    rf: Option<rf::config::File>,
    leases: Option<LeasesFile>,
    guards: Option<GuardsFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GuardsFile {
    #[serde(default)]
    enforce: Vec<u16>,
    #[serde(default, rename = "static")]
    statics: Vec<StaticFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticFile {
    mac: String,
    ip: Ipv4Addr,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LeasesFile {
    exporters: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApFile {
    public_key: String,
    hostname: Option<String>,
    address: Option<String>,
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

fn default_socket() -> PathBuf {
    "/run/wifi-controller/sock".into()
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
    /// An AP's `address` is not an address or a name: it goes into ssh's
    /// command line.
    BadAddress(String),
    /// `[rollouts]` is set, and an AP has no `address` to stage it through.
    NoAddress(String),
    /// `public_origin` is not spelled as a browser's `Origin` header is.
    BadOrigin,
    /// `admin_group` is empty, which no group header could match.
    NoAdminGroup,
    /// `[configs]` or `[rollouts]` is not one: why.
    Section(String),
    /// `[rf]` is not a planner's configuration: why.
    Rf(String),
    /// A `[leases]` exporter is not `host:port`.
    BadExporter(String),
    /// `[guards]` names no VLAN, or no client's MAC: which.
    Guards(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(e) => f.write_str(e.trim_end()),
            Self::BadKey(ap) => write!(f, "aps.{ap}.public_key is not 64 lowercase hex digits"),
            Self::SharedKey(a, b) => write!(f, "aps.{a} and aps.{b} have the same public_key"),
            Self::BadHostname(ap) => write!(f, "aps.{ap}.hostname is empty or too long"),
            Self::SharedHostname(a, b) => write!(f, "aps.{a} and aps.{b} have the same hostname"),
            Self::BadAddress(ap) => write!(f, "aps.{ap}.address is not an address or a name"),
            Self::NoAddress(ap) => write!(f, "aps.{ap} has no address, which rollouts need"),
            Self::BadOrigin => f.write_str(
                "public_origin is not scheme://host[:port] (no path, no trailing slash)",
            ),
            Self::NoAdminGroup => f.write_str("admin_group is empty"),
            Self::Section(e) | Self::Rf(e) => f.write_str(e),
            Self::BadExporter(e) => write!(f, "leases.exporters: {e:?} is not host:port"),
            Self::Guards(e) => write!(f, "guards: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let file: File = toml::from_str(text).map_err(|e| ConfigError::Syntax(e.to_string()))?;
        let mut aps = BTreeMap::new();
        let mut hostnames = BTreeMap::new();
        let mut addresses = BTreeMap::new();
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
            match ap.address {
                Some(a) if is_address(&a) => {
                    addresses.insert(name.clone(), a);
                }
                Some(_) => return Err(ConfigError::BadAddress(name)),
                None if file.rollouts.is_some() => return Err(ConfigError::NoAddress(name)),
                None => {}
            }
            hostnames.insert(name.clone(), hostname);
            aps.insert(name, key);
        }
        if !is_origin(&file.public_origin) {
            return Err(ConfigError::BadOrigin);
        }
        if file.admin_group.trim().is_empty() {
            return Err(ConfigError::NoAdminGroup);
        }
        let configs = file.configs.map(configs::File::check).transpose();
        let rollouts = file.rollouts.map(rollout::File::check).transpose();
        let rf = file
            .rf
            .map(rf::config::File::check)
            .transpose()
            .map_err(ConfigError::Rf)?;
        let leases = file.leases.map_or_else(Vec::new, |l| l.exporters);
        if let Some(bad) = leases.iter().find(|e| !is_exporter(e)) {
            return Err(ConfigError::BadExporter(bad.clone()));
        }
        let guards = file
            .guards
            .map_or_else(|| Ok(GuardConfig::default()), guards)?;
        Ok(Config {
            listen_agents: file.listen_agents,
            listen_http: file.listen_http,
            listen_metrics: file.listen_metrics,
            key: file.key,
            aps,
            hostnames,
            addresses,
            public_origin: file.public_origin,
            admin_group: file.admin_group,
            policy_path: file.policy_path,
            socket: file.socket,
            configs: configs.map_err(ConfigError::Section)?,
            rollouts: rollouts.map_err(ConfigError::Section)?,
            rf,
            leases,
            guards,
        })
    }
}

/// The guards' section, checked: real VLANs, each once, and unicast MACs.
fn guards(file: GuardsFile) -> Result<GuardConfig, ConfigError> {
    let mut enforce = file.enforce;
    if let Some(v) = enforce.iter().find(|v| !(1..=4094).contains(*v)) {
        return Err(ConfigError::Guards(format!("enforce: {v} is no VLAN")));
    }
    enforce.sort_unstable();
    enforce.dedup();
    let statics = file.statics.into_iter().map(|s| {
        let mac = mac::parse(&s.mac).filter(|m| m[0] & 1 == 0);
        let mac = mac.ok_or_else(|| {
            ConfigError::Guards(format!("static: {:?} is no client's MAC", s.mac))
        })?;
        Ok(Binding {
            mac,
            ip: s.ip,
            expires_ms: None,
        })
    });
    Ok(GuardConfig {
        enforce,
        statics: statics.collect::<Result<_, _>>()?,
    })
}

/// Whether `s` is `host:port`: a name or IPv4 address, or an IPv6 one in
/// brackets, and a port.
fn is_exporter(s: &str) -> bool {
    let Some((host, port)) = s.rsplit_once(':') else {
        return false;
    };
    let host = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(v6) => v6.parse::<std::net::Ipv6Addr>().is_ok(),
        None => !host.contains(':') && is_address(host),
    };
    host && port.parse::<u16>().is_ok_and(|p| p > 0)
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

/// Whether `s` may go into ssh's command line as the host it dials: an IP
/// address or a DNS name, nothing an option could start with.
fn is_address(s: &str) -> bool {
    let ok = |c: char| c.is_ascii_alphanumeric() || ".:-".contains(c);
    (1..=253).contains(&s.len()) && !s.starts_with('-') && s.chars().all(ok)
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
    use std::time::Duration;

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
        assert!(c.addresses.is_empty());
        assert_eq!((&c.configs, &c.rollouts, &c.rf), (&None, &None, &None));
        assert_eq!(c.public_origin, "https://wifi.example.org");
        assert_eq!(c.admin_group, "wifi-admins");
        assert_eq!(
            c.policy_path,
            PathBuf::from("/var/lib/wifi-controller/policy.json")
        );
        assert_eq!(c.socket, PathBuf::from("/run/wifi-controller/sock"));
    }

    #[test]
    fn listeners_and_key_are_set() {
        let c = Config::parse(
            "listen_agents = \"192.0.2.1:1\"\nlisten_http = \"192.0.2.1:2\"\n\
             listen_metrics = \"[2001:db8::1]:3\"\nkey = \"/k.pem\"\n\
             public_origin = \"http://[2001:db8::1]:8080\"\nadmin_group = \"ops\"\n\
             policy_path = \"/p.json\"\nsocket = \"/s.sock\"\n",
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
        assert_eq!(c.socket, PathBuf::from("/s.sock"));
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

    /// Signing and rollouts each come on with their section; rollouts need
    /// every AP's address, which goes into ssh's command line as it is.
    #[test]
    fn configs_and_rollouts_are_configured_in_their_own_sections() {
        let ap = |address: &str| format!("{ORIGIN}[aps.ap1]\npublic_key = \"{KEY1}\"\n{address}");
        let rollouts = "[rollouts]\nroot_key = \"/k\"\nstock_password = \"/p\"\n\
                        known_hosts = \"/h\"\ngate_secs = 60\n";
        let c = Config::parse(&format!(
            "{}[configs]\nsigning_key = \"/s.pem\"\n{rollouts}",
            ap("address = \"192.0.2.16\"\n")
        ))
        .unwrap();
        assert_eq!(c.addresses["ap1"], "192.0.2.16");
        let configs = c.configs.unwrap();
        assert_eq!(configs.signing_key, PathBuf::from("/s.pem"));
        assert_eq!(
            configs.state,
            PathBuf::from("/var/lib/wifi-controller/configs")
        );
        let r = c.rollouts.unwrap();
        assert_eq!(r.gate, Duration::from_secs(60));
        assert_eq!(r.images, PathBuf::from("/var/lib/wifi-controller/images"));
        assert_eq!((r.keep, r.ssh.stock_user.as_str()), (3, "ubnt"));
        assert_eq!(
            Config::parse(&format!("{}{rollouts}", ap(""))),
            Err(ConfigError::NoAddress("ap1".into()))
        );
        for bad in ["-oProxyCommand=x", "a b", ""] {
            let text = ap(&format!("address = \"{bad}\"\n"));
            assert_eq!(
                Config::parse(&text),
                Err(ConfigError::BadAddress("ap1".into())),
                "{bad}"
            );
        }
        let bad = format!(
            "{}{}",
            ap("address = \"ap1.example.net\"\n"),
            rollouts.replace("60", "0")
        );
        assert!(matches!(Config::parse(&bad), Err(ConfigError::Section(_))));
    }

    /// `[rf]` turns the planner on, and its errors are the configuration's.
    #[test]
    fn the_rf_planner_is_configured_in_its_own_section() {
        let rf = "[rf]\nremote = \"/srv/site.git\"\nrepo = \"/var/lib/site\"\nfile = \"wifi/site.yml\"\n\
                  [rf.channels.KR]\n\"6\" = [{ channels = \"1-93\" }]\n";
        let c = Config::parse(&format!("{ORIGIN}{rf}")).unwrap();
        let s = c.rf.unwrap();
        assert_eq!(
            (s.repo.file.as_str(), s.repo.branch.as_str()),
            ("wifi/site.yml", "main")
        );
        assert_eq!(s.rules.countries["KR"][2][0].hi, 93);
        let bad = format!("{ORIGIN}{}", rf.replace("1-93", "1-0"));
        assert!(matches!(Config::parse(&bad), Err(ConfigError::Rf(_))));
    }

    #[test]
    fn the_lease_exporters_are_host_and_port() {
        let leases =
            |list: &str| Config::parse(&format!("{ORIGIN}[leases]\nexporters = [{list}]\n"));
        let c = leases("\"dhcp1.example.org:9100\", \"192.0.2.53:9100\", \"[2001:db8::53]:9100\"")
            .unwrap();
        assert_eq!(c.leases.len(), 3);
        assert!(Config::parse(ORIGIN).unwrap().leases.is_empty());
        for bad in [
            "dhcp1.example.org",
            "2001:db8::53:9100",
            "x:0",
            "-o:1",
            "[x]:9100",
            "a b:9100",
        ] {
            assert_eq!(
                leases(&format!("\"{bad}\"")),
                Err(ConfigError::BadExporter(bad.into())),
                "{bad}"
            );
        }
    }

    #[test]
    fn the_guards_report_only_unless_told_where_to_enforce() {
        assert_eq!(
            Config::parse(ORIGIN).unwrap().guards,
            GuardConfig::default()
        );
        let text = format!(
            "{ORIGIN}[guards]\nenforce = [43, 42, 43]\n\
             static = [{{ mac = \"02:00:00:00:00:01\", ip = \"192.0.2.5\" }}]\n"
        );
        let g = Config::parse(&text).unwrap().guards;
        assert_eq!(g.enforce, [42, 43]);
        assert_eq!(
            g.statics,
            [Binding {
                mac: [2, 0, 0, 0, 0, 1],
                ip: Ipv4Addr::new(192, 0, 2, 5),
                expires_ms: None
            }]
        );
        for bad in [
            "enforce = [0]",
            "enforce = [4095]",
            "static = [{ mac = \"x\", ip = \"192.0.2.5\" }]",
            "static = [{ mac = \"01:00:5e:00:00:01\", ip = \"192.0.2.5\" }]",
        ] {
            let text = format!("{ORIGIN}[guards]\n{bad}\n");
            assert!(
                matches!(Config::parse(&text), Err(ConfigError::Guards(_))),
                "{bad}"
            );
        }
        let v6 = format!(
            "{ORIGIN}[guards]\nstatic = [{{ mac = \"02:00:00:00:00:01\", ip = \"2001:db8::5\" }}]\n"
        );
        assert!(matches!(Config::parse(&v6), Err(ConfigError::Syntax(_))));
    }

    #[test]
    fn unknown_keys_refused() {
        for text in [
            "listen = \"[::]:1\"\n",
            "[aps.ap1]\npublic_key = \"\"\nname = \"x\"\n",
            "[runner]\npublic_key = \"\"\n",
        ] {
            let text = format!("{ORIGIN}{text}");
            assert!(
                matches!(Config::parse(&text), Err(ConfigError::Syntax(_))),
                "{text}"
            );
        }
    }
}
