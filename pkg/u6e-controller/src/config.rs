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
//! over mutual TLS with `tls = true`, none without it; in `[radius]`, the
//! Lokis the RADIUS servers' log is read from (`radius`, one, or several
//! taken in turn when one fails), over mutual TLS with `tls = true`,
//! RADIUS's side of the clients' timelines missing without it; in
//! `[monitoring_tls]`, the host's monitoring certificate those two present
//! (`mtls`): the chain (leaf first), its key and the CA bundle every peer
//! is verified against, and the DNS names of the scrapers `/metrics` is
//! then served to over mutual TLS alone (`metrics_clients`, plain HTTP
//! while none is listed); where the clients' sessions and timelines are
//! kept (`history_path`, `sessions`), and their traffic (`traffic_path`,
//! `traffic`); the signal below which a client another AP heard better is
//! sticky (`sticky_dbm`,
//! `roaming`, −72 dBm unless set); where the client captures' files are kept
//! (`captures_path`, `captures`); in `[limits]`, the site's per-SSID rate
//! limits, which an
//! admin's limit of the same SSID overrides (`limits`); and, in `[guards]`,
//! the VLANs the APs' client guards
//! enforce on (only with `[leases]`: without the seed of the leases a client
//! that roamed in is unknown to its new AP), the clients with a static
//! address, and the site's DHCP servers and relays, whose acknowledgements
//! alone bind addresses; the guards only report without it; and, in
//! `[presence]`, the devices whose joining and leaving the Wi-Fi go to Home
//! Assistant as events (`presence`): its `https://` address, the CA bundle
//! its certificate chains to (the system's unless set), the file of its
//! long-lived token, the minutes unseen that make a leave
//! (`leave_after_secs`, 300 unless set, 60 to 3600) and the devices, each
//! by MAC and a name of lower case letters, digits and `_`; none without it;
//! and, in `[mac_auth]`, RADIUS's MAC authentication mapping admins edit
//! (`macauth`): OpenBao's `https://` address, its CA bundle (the system's
//! unless set), the file of the token it is read and written with, the
//! KV-v2 mount (`secret` unless set) and path, the VLANs an admin may put a
//! device in, the SSIDs whose clients MAC authentication places, the most
//! entries the mapping may hold (`entries_max`, 512 unless set); the
//! mapping is not shown or edited without it; and, in `[ui]`, the web UI's
//! branding (`theme`): the name shown before "Wi-Fi" (`brand`) and the
//! directory of the operator's theme served at `/theme/` (`theme`), the
//! built-in look without it.
//!
//! ```toml
//! listen_agents = "[::]:8443"
//! listen_http = "[::]:8080"
//! listen_metrics = "[::]:9810"
//! key = "/etc/wifi-controller/key.pem"
//! public_origin = "https://wifi.example.org"
//! admin_group = "wifi-admins"
//! policy_path = "/var/lib/wifi-controller/policy.json"
//! history_path = "/var/lib/wifi-controller/history"
//! traffic_path = "/var/lib/wifi-controller/traffic"
//! sticky_dbm = -72
//! captures_path = "/var/lib/wifi-controller/captures"
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
//! tls = true
//!
//! [radius]
//! loki = ["logs1.example.org:3100", "logs2.example.org:3100"]
//! selector = '{job="radius-auth"}'
//! tls = true
//!
//! [monitoring_tls]
//! cert = "/etc/ssl/monitoring/fullchain.pem"
//! key = "/etc/ssl/monitoring/key.pem"
//! ca = "/etc/ssl/monitoring/chain.pem"
//! metrics_clients = ["prometheus1.example.org", "prometheus2.example.org"]
//!
//! [limits]
//! ssids = [{ ssid = "guest", down_kbit = 50000, up_kbit = 10000 }]
//!
//! [guards]
//! enforce = [42]
//! static = [{ mac = "02:00:00:00:00:01", ip = "192.0.2.5" }]
//! dhcp_servers = ["192.0.2.53"]
//! dhcp_relays = ["192.0.2.2", "198.51.100.2"]
//!
//! [presence]
//! url = "https://ha.example.org"
//! token = "/etc/wifi-controller/ha-token"
//! devices = [{ mac = "02:00:00:00:00:01", name = "phone_alice" }]
//!
//! [mac_auth]
//! url = "https://bao.example.org"
//! token = "/run/bao-approle/wifi-controller/token"
//! path = "mac-auth"
//! vlans = [42, 43]
//! ssids = ["iot"]
//!
//! [ui]
//! brand = "Example Org"
//! theme = "/etc/wifi-controller/theme"
//! ```

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use serde::Deserialize;
use u6e_proto::mac;
use u6e_proto::msg::{Binding, GuardConfig, Limit, LimitTarget, Rate, check_limits};

use crate::{configs, leases, macauth, mtls, presence, radius, rf, roaming, rollout, theme};

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
    /// The clients' sessions and timelines.
    pub history_path: PathBuf,
    /// The clients' volumes and destinations.
    pub traffic_path: PathBuf,
    /// The signal below which a client is sticky (`roaming`).
    pub sticky_dbm: i8,
    /// The client captures' files.
    pub captures_path: PathBuf,
    /// The site's rate limits, per SSID.
    pub limits: BTreeMap<String, Rate>,
    /// Where root's local commands reach the controller.
    pub socket: PathBuf,
    /// The signing of live configurations, if it is on.
    pub configs: Option<configs::Settings>,
    /// The kept images and their rollouts, if they are on.
    pub rollouts: Option<rollout::Settings>,
    /// The RF planner's settings, if it is on.
    pub rf: Option<rf::config::Settings>,
    /// The node exporters that publish the DHCP leases.
    pub leases: leases::Settings,
    /// Where RADIUS's log is read, if it is.
    pub radius: Option<radius::Settings>,
    /// How the APs' client guards run.
    pub guards: GuardConfig,
    /// The presence events to Home Assistant, if they are on.
    pub presence: Option<presence::Settings>,
    /// RADIUS's MAC authentication mapping, if admins edit it.
    pub mac_auth: Option<macauth::Settings>,
    /// The host's monitoring certificate, if anything speaks mutual TLS.
    pub monitoring_tls: Option<mtls::Settings>,
    pub ui: theme::Settings,
}

impl Config {
    /// The endpoints switched to mutual TLS.
    pub fn tls_endpoints(&self) -> Vec<mtls::Endpoint> {
        let metrics = self
            .monitoring_tls
            .as_ref()
            .is_some_and(|t| !t.metrics_clients.is_empty());
        let loki = self.radius.as_ref().is_some_and(|r| r.tls.is_some());
        let leases = self.leases.tls.is_some();
        [
            (metrics, mtls::Endpoint::Metrics),
            (loki, mtls::Endpoint::Loki),
            (leases, mtls::Endpoint::Leases),
        ]
        .into_iter()
        .filter_map(|(on, e)| on.then_some(e))
        .collect()
    }
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
    #[serde(default = "default_history")]
    history_path: PathBuf,
    #[serde(default = "default_traffic")]
    traffic_path: PathBuf,
    #[serde(default = "default_sticky")]
    sticky_dbm: i8,
    #[serde(default = "default_captures")]
    captures_path: PathBuf,
    #[serde(default = "default_socket")]
    socket: PathBuf,
    configs: Option<configs::File>,
    rollouts: Option<rollout::File>,
    rf: Option<rf::config::File>,
    leases: Option<LeasesFile>,
    radius: Option<RadiusFile>,
    guards: Option<GuardsFile>,
    limits: Option<LimitsFile>,
    presence: Option<PresenceFile>,
    mac_auth: Option<MacAuthFile>,
    monitoring_tls: Option<MonitoringTlsFile>,
    ui: Option<theme::File>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MonitoringTlsFile {
    cert: PathBuf,
    key: PathBuf,
    ca: PathBuf,
    #[serde(default)]
    metrics_clients: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MacAuthFile {
    url: String,
    #[serde(default = "default_ca")]
    ca: PathBuf,
    token: PathBuf,
    #[serde(default = "default_mount")]
    mount: String,
    path: String,
    vlans: Vec<u16>,
    ssids: Vec<String>,
    #[serde(default = "default_entries_max")]
    entries_max: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PresenceFile {
    url: String,
    #[serde(default = "default_ca")]
    ca: PathBuf,
    token: PathBuf,
    #[serde(default = "default_leave_after")]
    leave_after_secs: u64,
    devices: Vec<PresenceDeviceFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PresenceDeviceFile {
    mac: String,
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsFile {
    #[serde(default)]
    ssids: Vec<SsidLimitFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SsidLimitFile {
    ssid: String,
    down_kbit: Option<u32>,
    up_kbit: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RadiusFile {
    loki: Addresses,
    selector: String,
    #[serde(default)]
    tls: bool,
}

/// One `host:port`, or several.
#[derive(Deserialize)]
#[serde(untagged)]
enum Addresses {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GuardsFile {
    #[serde(default)]
    enforce: Vec<u16>,
    #[serde(default, rename = "static")]
    statics: Vec<StaticFile>,
    #[serde(default)]
    dhcp_servers: Vec<Ipv4Addr>,
    #[serde(default)]
    dhcp_relays: Vec<Ipv4Addr>,
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
    #[serde(default)]
    tls: bool,
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

fn default_history() -> PathBuf {
    "/var/lib/wifi-controller/history".into()
}

fn default_traffic() -> PathBuf {
    "/var/lib/wifi-controller/traffic".into()
}

fn default_sticky() -> i8 {
    roaming::STICKY_DBM
}

fn default_captures() -> PathBuf {
    "/var/lib/wifi-controller/captures".into()
}

fn default_socket() -> PathBuf {
    "/run/wifi-controller/sock".into()
}

fn default_ca() -> PathBuf {
    "/etc/ssl/certs/ca-certificates.crt".into()
}

fn default_leave_after() -> u64 {
    300
}

fn default_mount() -> String {
    "secret".into()
}

fn default_entries_max() -> usize {
    macauth::ENTRIES_MAX
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
    /// `[radius]`'s Loki is not `host:port`, or its selector no LogQL
    /// stream selector: which.
    Radius(String),
    /// `[guards]` names no VLAN, or no client's MAC: which.
    Guards(String),
    /// A `[limits]` SSID is named twice, or its rate is out of range.
    Limits(String),
    /// `sticky_dbm` is outside −90 to −50 dBm.
    BadSticky,
    /// `[presence]` is not one: why.
    Presence(String),
    /// `[mac_auth]` is not one: why.
    MacAuth(String),
    /// `[monitoring_tls]` is not one, or a `tls = true` has none: why.
    MonitoringTls(String),
    /// `[ui]` is not one: why.
    Ui(String),
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
            Self::Section(e) | Self::Rf(e) | Self::Ui(e) => f.write_str(e),
            Self::BadExporter(e) => write!(f, "leases.exporters: {e:?} is not host:port"),
            Self::Radius(e) => write!(f, "radius: {e}"),
            Self::Guards(e) => write!(f, "guards: {e}"),
            Self::Limits(e) => write!(f, "limits: {e}"),
            Self::BadSticky => f.write_str("sticky_dbm is not between -90 and -50"),
            Self::Presence(e) => write!(f, "presence: {e}"),
            Self::MacAuth(e) => write!(f, "mac_auth: {e}"),
            Self::MonitoringTls(e) => write!(f, "monitoring_tls: {e}"),
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
        let monitoring_tls = file
            .monitoring_tls
            .map(monitoring_tls_settings)
            .transpose()?;
        // A path switched to mutual TLS presents the host's certificate.
        let tls = |on: bool, what: &str| match (on, &monitoring_tls) {
            (false, _) => Ok(None),
            (true, Some(t)) => Ok(Some(t.files.clone())),
            (true, None) => Err(ConfigError::MonitoringTls(format!(
                "{what}.tls needs [monitoring_tls]"
            ))),
        };
        let leases = match file.leases {
            Some(l) => leases::Settings {
                tls: tls(l.tls, "leases")?,
                exporters: l.exporters,
            },
            None => leases::Settings::default(),
        };
        if let Some(bad) = leases.exporters.iter().find(|e| !is_host_port(e)) {
            return Err(ConfigError::BadExporter(bad.clone()));
        }
        let radius = file
            .radius
            .map(|r| {
                let files = tls(r.tls, "radius")?;
                radius_settings(r, files)
            })
            .transpose()?;
        let guards = file
            .guards
            .map_or_else(|| Ok(GuardConfig::default()), guards)?;
        let limits = file.limits.map_or_else(|| Ok(BTreeMap::new()), limits)?;
        if !(-90..=-50).contains(&file.sticky_dbm) {
            return Err(ConfigError::BadSticky);
        }
        let presence = file.presence.map(presence_settings).transpose()?;
        let mac_auth = file.mac_auth.map(mac_auth_settings).transpose()?;
        let ui = file
            .ui
            .map_or_else(|| Ok(theme::Settings::default()), theme::File::check)
            .map_err(ConfigError::Ui)?;
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
            history_path: file.history_path,
            traffic_path: file.traffic_path,
            sticky_dbm: file.sticky_dbm,
            captures_path: file.captures_path,
            limits,
            socket: file.socket,
            configs: configs.map_err(ConfigError::Section)?,
            rollouts: rollouts.map_err(ConfigError::Section)?,
            rf,
            leases,
            radius,
            guards,
            presence,
            mac_auth,
            monitoring_tls,
            ui,
        })
    }
}

/// The monitoring certificate's section, checked: 0 to 16 scrapers, each
/// a DNS name (what their certificates carry), each once.
fn monitoring_tls_settings(file: MonitoringTlsFile) -> Result<mtls::Settings, ConfigError> {
    let bad = |e: String| ConfigError::MonitoringTls(e);
    let clients = file.metrics_clients;
    if clients.len() > 16 {
        return Err(bad("metrics_clients: at most 16 are listed".into()));
    }
    for (i, c) in clients.iter().enumerate() {
        let name = c.parse::<std::net::IpAddr>().is_err() && is_address(c) && !c.contains(':');
        if !name || clients[..i].contains(c) {
            return Err(bad(format!(
                "metrics_clients: {c:?} is not a DNS name, or is listed twice"
            )));
        }
    }
    Ok(mtls::Settings {
        files: mtls::Files {
            cert: file.cert,
            key: file.key,
            ca: file.ca,
        },
        metrics_clients: clients,
    })
}

/// The presence section, checked: an `https://host[:port]` with nothing
/// after it, a leave of 1 to 60 minutes, and 1 to 64 devices, each a
/// station's MAC and a name Home Assistant takes as it is, each once.
fn presence_settings(file: PresenceFile) -> Result<presence::Settings, ConfigError> {
    let bad = |e: String| ConfigError::Presence(e);
    let (host, port) = https_host_port(&file.url).map_err(bad)?;
    if !(60..=3600).contains(&file.leave_after_secs) {
        return Err(bad("leave_after_secs is not between 60 and 3600".into()));
    }
    if file.devices.is_empty() || file.devices.len() > presence::DEVICES_MAX {
        return Err(bad(format!(
            "devices: 1 to {} are listed",
            presence::DEVICES_MAX
        )));
    }
    let mut devices: Vec<([u8; 6], String)> = Vec::new();
    for d in file.devices {
        let mac = mac::parse(&d.mac).filter(|m| mac::is_station(*m));
        let mac = mac.ok_or_else(|| bad(format!("devices: {:?} is no station's MAC", d.mac)))?;
        let named = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_';
        if d.name.is_empty() || d.name.len() > 64 || !d.name.chars().all(named) {
            return Err(bad(format!(
                "devices: {:?} is not a name of a-z, 0-9 and _",
                d.name
            )));
        }
        if devices.iter().any(|(m, n)| *m == mac || *n == d.name) {
            return Err(bad(format!(
                "devices: {} or {:?} is listed twice",
                d.mac, d.name
            )));
        }
        devices.push((mac, d.name));
    }
    Ok(presence::Settings {
        host,
        port,
        ca: file.ca,
        token: file.token,
        leave_after: std::time::Duration::from_secs(file.leave_after_secs),
        devices,
    })
}

/// The host and port of an `https://host[:port]` with nothing after it.
fn https_host_port(url: &str) -> Result<(String, u16), String> {
    let bad = || format!("url: {url:?} is not https://host[:port]");
    let hostport = url.strip_prefix("https://").ok_or_else(bad)?;
    let (host, port) = if is_host_port(hostport) {
        let (h, p) = hostport.rsplit_once(':').expect("host:port");
        (h, p.parse().expect("a port"))
    } else {
        (hostport, 443)
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let ok_host =
        host.parse::<std::net::IpAddr>().is_ok() || (!host.contains(':') && is_address(host));
    if !ok_host {
        return Err(bad());
    }
    Ok((host.to_owned(), port))
}

/// The MAC authentication mapping's section, checked: OpenBao's
/// `https://host[:port]`, a KV-v2 mount and path of plain segments, 1 to 64
/// VLANs (1-4094) an admin may choose, the MAC-authenticated SSIDs, and an
/// entry cap of 1 to 4096.
fn mac_auth_settings(file: MacAuthFile) -> Result<macauth::Settings, ConfigError> {
    let bad = |e: String| ConfigError::MacAuth(e);
    let (host, port) = https_host_port(&file.url).map_err(bad)?;
    let plain = |p: &str| {
        !p.is_empty()
            && p.split('/').all(|s| {
                !s.is_empty()
                    && s != "."
                    && s != ".."
                    && s.chars()
                        .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
            })
    };
    if !plain(&file.mount) || !plain(&file.path) {
        return Err(bad("mount and path are not plain path segments".into()));
    }
    if file.vlans.is_empty() || file.vlans.len() > 64 {
        return Err(bad("vlans: 1 to 64 are listed".into()));
    }
    if file.vlans.iter().any(|v| !(1..=4094).contains(v)) {
        return Err(bad("vlans: each is 1 to 4094".into()));
    }
    if file.ssids.is_empty() || file.ssids.iter().any(|s| s.is_empty() || s.len() > 32) {
        return Err(bad("ssids: at least one, each 1 to 32 bytes".into()));
    }
    if !(1..=4096).contains(&file.entries_max) {
        return Err(bad("entries_max is not between 1 and 4096".into()));
    }
    let mut vlans = file.vlans;
    vlans.sort_unstable();
    vlans.dedup();
    Ok(macauth::Settings {
        host,
        port,
        ca: file.ca,
        token: file.token,
        mount: file.mount,
        path: file.path,
        vlans,
        ssids: file.ssids,
        entries_max: file.entries_max,
    })
}

/// The RADIUS log's section, checked: 1 to 8 `host:port`, each once, and a
/// stream selector (in braces, on one line: it goes into the query as it
/// is); read over mutual TLS with `tls`.
fn radius_settings(
    file: RadiusFile,
    tls: Option<mtls::Files>,
) -> Result<radius::Settings, ConfigError> {
    let loki = match file.loki {
        Addresses::One(a) => vec![a],
        Addresses::Many(a) => a,
    };
    if loki.is_empty() || loki.len() > 8 {
        return Err(ConfigError::Radius("loki: 1 to 8 are listed".into()));
    }
    for (i, a) in loki.iter().enumerate() {
        if !is_host_port(a) || loki[..i].contains(a) {
            let e = format!("loki: {a:?} is not host:port, or is listed twice");
            return Err(ConfigError::Radius(e));
        }
    }
    let s = &file.selector;
    if !(s.starts_with('{') && s.ends_with('}') && !s.chars().any(char::is_control)) {
        return Err(ConfigError::Radius(format!(
            "selector: {s:?} is no stream selector"
        )));
    }
    Ok(radius::Settings {
        loki,
        selector: file.selector,
        tls,
    })
}

/// The limits' section, checked: each SSID once, each rate as an AP takes
/// it.
fn limits(file: LimitsFile) -> Result<BTreeMap<String, Rate>, ConfigError> {
    let mut out = BTreeMap::new();
    for s in file.ssids {
        let rate = Rate {
            down_kbit: s.down_kbit,
            up_kbit: s.up_kbit,
        };
        let set = [Limit {
            target: LimitTarget::Ssid(s.ssid.clone()),
            rate,
        }];
        check_limits(&set).map_err(|e| ConfigError::Limits(format!("{:?}: {e}", s.ssid)))?;
        if out.insert(s.ssid.clone(), rate).is_some() {
            return Err(ConfigError::Limits(format!("{:?} is named twice", s.ssid)));
        }
    }
    let all: Vec<Limit> = out
        .iter()
        .map(|(s, r)| Limit {
            target: LimitTarget::Ssid(s.clone()),
            rate: *r,
        })
        .collect();
    check_limits(&all).map_err(ConfigError::Limits)?;
    Ok(out)
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
        dhcp_servers: file.dhcp_servers,
        dhcp_relays: file.dhcp_relays,
    })
}

/// Whether `s` is `host:port`: a name or IPv4 address, or an IPv6 one in
/// brackets, and a port.
fn is_host_port(s: &str) -> bool {
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
        assert_eq!(c.leases.exporters.len(), 3);
        assert_eq!(c.leases.tls, None);
        let none = Config::parse(ORIGIN).unwrap();
        assert_eq!(none.leases, leases::Settings::default());
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
    fn the_traffic_is_kept_where_it_says() {
        let c = Config::parse(ORIGIN).unwrap();
        assert_eq!(
            c.traffic_path,
            PathBuf::from("/var/lib/wifi-controller/traffic")
        );
        let c = Config::parse(&format!("{ORIGIN}traffic_path = \"/t\"\n")).unwrap();
        assert_eq!(c.traffic_path, PathBuf::from("/t"));
    }

    #[test]
    fn presence_goes_to_an_https_home_assistant_for_named_devices() {
        assert_eq!(Config::parse(ORIGIN).unwrap().presence, None);
        let with = |url: &str, rest: &str| {
            Config::parse(&format!(
                "{ORIGIN}[presence]\nurl = \"{url}\"\ntoken = \"/t\"\n{rest}\n"
            ))
        };
        let one = "devices = [{ mac = \"02:00:00:00:00:01\", name = \"phone_alice\" }]";
        let p = with("https://ha.example.org", one)
            .unwrap()
            .presence
            .unwrap();
        assert_eq!(
            p,
            presence::Settings {
                host: "ha.example.org".into(),
                port: 443,
                ca: "/etc/ssl/certs/ca-certificates.crt".into(),
                token: "/t".into(),
                leave_after: Duration::from_secs(300),
                devices: vec![([2, 0, 0, 0, 0, 1], "phone_alice".into())],
            }
        );
        let p = with(
            "https://[2001:db8::8]:8123",
            &format!("leave_after_secs = 60\nca = \"/c\"\n{one}"),
        );
        let p = p.unwrap().presence.unwrap();
        assert_eq!(
            (p.host.as_str(), p.port, p.leave_after.as_secs()),
            ("2001:db8::8", 8123, 60)
        );
        assert_eq!(p.ca, PathBuf::from("/c"));
        let refused =
            |url: &str, rest: &str| matches!(with(url, rest), Err(ConfigError::Presence(_)));
        for url in [
            "http://ha.example.org",
            "https://ha.example.org/api",
            "https://",
            "https://-x",
        ] {
            assert!(refused(url, one), "{url}");
        }
        assert!(refused(
            "https://ha.example.org",
            &format!("leave_after_secs = 59\n{one}")
        ));
        assert!(refused(
            "https://ha.example.org",
            &format!("leave_after_secs = 3601\n{one}")
        ));
        assert!(refused("https://ha.example.org", "devices = []"));
        for d in [
            r#"{ mac = "03:00:00:00:00:01", name = "x" }"#,
            r#"{ mac = "02:00:00:00:00:01", name = "Phone Alice" }"#,
            r#"{ mac = "02:00:00:00:00:01", name = "" }"#,
            r#"{ mac = "02:00:00:00:00:01", name = "a" }, { mac = "02:00:00:00:00:01", name = "b" }"#,
            r#"{ mac = "02:00:00:00:00:01", name = "a" }, { mac = "02:00:00:00:00:02", name = "a" }"#,
        ] {
            assert!(
                refused("https://ha.example.org", &format!("devices = [{d}]")),
                "{d}"
            );
        }
        let many: Vec<String> = (0..65)
            .map(|i| format!("{{ mac = \"02:00:00:00:01:{i:02x}\", name = \"d{i}\" }}"))
            .collect();
        assert!(refused(
            "https://ha.example.org",
            &format!("devices = [{}]", many.join(", "))
        ));
        assert!(matches!(
            with("https://ha.example.org", &format!("port = 1\n{one}")),
            Err(ConfigError::Syntax(_))
        ));
    }

    #[test]
    fn the_mac_auth_mapping_is_one_kv_secret_and_the_vlans_admins_may_choose() {
        assert_eq!(Config::parse(ORIGIN).unwrap().mac_auth, None);
        let with = |rest: &str| {
            Config::parse(&format!(
                "{ORIGIN}[mac_auth]\nurl = \"https://bao.example.org\"\ntoken = \"/t\"\n{rest}\n"
            ))
        };
        let base = "path = \"mac-auth\"\nvlans = [43, 42, 43]\nssids = [\"iot\"]";
        let m = with(base).unwrap().mac_auth.unwrap();
        assert_eq!(
            m,
            macauth::Settings {
                host: "bao.example.org".into(),
                port: 443,
                ca: "/etc/ssl/certs/ca-certificates.crt".into(),
                token: "/t".into(),
                mount: "secret".into(),
                path: "mac-auth".into(),
                vlans: vec![42, 43],
                ssids: vec!["iot".into()],
                entries_max: 512,
            }
        );
        let refused = |rest: &str| matches!(with(rest), Err(ConfigError::MacAuth(_)));
        for bad in [
            "path = \"../x\"\nvlans = [42]\nssids = [\"iot\"]",
            "path = \"a//b\"\nvlans = [42]\nssids = [\"iot\"]",
            "path = \"m\"\nmount = \"\"\nvlans = [42]\nssids = [\"iot\"]",
            "path = \"m\"\nvlans = []\nssids = [\"iot\"]",
            "path = \"m\"\nvlans = [0]\nssids = [\"iot\"]",
            "path = \"m\"\nvlans = [4095]\nssids = [\"iot\"]",
            "path = \"m\"\nvlans = [42]\nssids = []",
            "path = \"m\"\nvlans = [42]\nssids = [\"\"]",
            "path = \"m\"\nvlans = [42]\nssids = [\"iot\"]\nentries_max = 0",
            "path = \"m\"\nvlans = [42]\nssids = [\"iot\"]\nentries_max = 4097",
        ] {
            assert!(refused(bad), "{bad}");
        }
        let plain = Config::parse(&format!(
            "{ORIGIN}[mac_auth]\nurl = \"http://bao.example.org\"\ntoken = \"/t\"\n{base}\n"
        ));
        assert!(matches!(plain, Err(ConfigError::MacAuth(_))));
        assert!(matches!(with("path = \"m\""), Err(ConfigError::Syntax(_))));
    }

    #[test]
    fn the_sticky_threshold_defaults_and_is_bounded() {
        assert_eq!(Config::parse(ORIGIN).unwrap().sticky_dbm, -72);
        let set = |v: i32| Config::parse(&format!("{ORIGIN}sticky_dbm = {v}\n"));
        assert_eq!(set(-80).unwrap().sticky_dbm, -80);
        assert_eq!(set(-90).unwrap().sticky_dbm, -90);
        assert_eq!(set(-50).unwrap().sticky_dbm, -50);
        assert_eq!(set(-91), Err(ConfigError::BadSticky));
        assert_eq!(set(-49), Err(ConfigError::BadSticky));
        assert!(matches!(set(-200), Err(ConfigError::Syntax(_))));
    }

    #[test]
    fn the_radius_log_is_read_from_a_loki_by_its_selector() {
        let c = Config::parse(ORIGIN).unwrap();
        assert_eq!(c.radius, None);
        assert_eq!(
            c.history_path,
            PathBuf::from("/var/lib/wifi-controller/history")
        );
        let radius = |loki: &str, selector: &str| {
            let section = format!("[radius]\nloki = \"{loki}\"\nselector = '{selector}'\n");
            Config::parse(&format!("{ORIGIN}history_path = \"/h\"\n{section}"))
        };
        let c = radius("logs.example.org:3100", r#"{job="radius-auth"}"#).unwrap();
        assert_eq!(
            c.radius,
            Some(radius::Settings {
                loki: vec!["logs.example.org:3100".into()],
                selector: r#"{job="radius-auth"}"#.into(),
                tls: None,
            })
        );
        assert_eq!(c.history_path, PathBuf::from("/h"));
        // Several, taken in turn.
        let several = "[radius]\nloki = [\"logs1.example.org:3100\", \"[2001:db8::3]:3100\"]\n\
                       selector = '{job=\"x\"}'\n";
        let c = Config::parse(&format!("{ORIGIN}{several}")).unwrap();
        let loki = c.radius.unwrap().loki;
        assert_eq!(loki, ["logs1.example.org:3100", "[2001:db8::3]:3100"]);
        for list in ["[]", "[\"a:1\", \"a:1\"]", "[\"a:1\", \"b\"]"] {
            let text = format!("{ORIGIN}[radius]\nloki = {list}\nselector = '{{job=\"x\"}}'\n");
            assert!(
                matches!(Config::parse(&text), Err(ConfigError::Radius(_))),
                "{list}"
            );
        }
        for (loki, selector) in [
            ("logs.example.org", r#"{job="x"}"#),
            ("logs.example.org:3100", r#"job="x""#),
            ("logs.example.org:3100", "{job=\"x\"}\t|= \"y\""),
        ] {
            assert!(
                matches!(radius(loki, selector), Err(ConfigError::Radius(_))),
                "{loki} {selector}"
            );
        }
    }

    #[test]
    fn each_monitoring_endpoint_is_switched_to_mutual_tls_on_its_own() {
        const TLS: &str =
            "[monitoring_tls]\ncert = \"/c.pem\"\nkey = \"/k.pem\"\nca = \"/ca.pem\"\n";
        const LEASES: &str = "[leases]\nexporters = [\"dhcp1.example.org:9100\"]\n";
        const RADIUS: &str =
            "[radius]\nloki = \"logs1.example.org:3100\"\nselector = '{job=\"x\"}'\n";
        let files = mtls::Files {
            cert: "/c.pem".into(),
            key: "/k.pem".into(),
            ca: "/ca.pem".into(),
        };
        let parse = |s: String| Config::parse(&format!("{ORIGIN}{s}"));
        // The section alone switches nothing.
        let c = parse(format!("{TLS}{LEASES}{RADIUS}")).unwrap();
        let t = c.monitoring_tls.clone().unwrap();
        assert_eq!((t.files, t.metrics_clients.len()), (files.clone(), 0));
        assert_eq!(c.tls_endpoints(), []);
        assert_eq!((c.leases.tls, c.radius.unwrap().tls), (None, None));
        // Each switch, alone.
        let clients = "metrics_clients = [\"status1.example.org\", \"status2.example.org\"]\n";
        let c = parse(format!("{TLS}{clients}{LEASES}{RADIUS}")).unwrap();
        assert_eq!(c.tls_endpoints(), [mtls::Endpoint::Metrics]);
        let c = parse(format!("{TLS}{LEASES}tls = true\n{RADIUS}")).unwrap();
        assert_eq!(c.tls_endpoints(), [mtls::Endpoint::Leases]);
        assert_eq!(c.leases.tls, Some(files.clone()));
        let c = parse(format!("{TLS}{LEASES}{RADIUS}tls = true\n")).unwrap();
        assert_eq!(c.tls_endpoints(), [mtls::Endpoint::Loki]);
        assert_eq!(c.radius.unwrap().tls, Some(files));
        // A switch with no certificate to present.
        for s in [
            format!("{LEASES}tls = true\n"),
            format!("{RADIUS}tls = true\n"),
        ] {
            assert!(
                matches!(parse(s.clone()), Err(ConfigError::MonitoringTls(_))),
                "{s}"
            );
        }
        // Scrapers are DNS names, each once; the files are required.
        for bad in [
            "[\"192.0.2.1\"]",
            "[\"2001:db8::1\"]",
            "[\"a b\"]",
            "[\"-x.example.org\"]",
            "[\"a.example.org\", \"a.example.org\"]",
        ] {
            let text = format!("{TLS}metrics_clients = {bad}\n");
            assert!(
                matches!(parse(text), Err(ConfigError::MonitoringTls(_))),
                "{bad}"
            );
        }
        let seventeen: Vec<String> = (0..17).map(|i| format!("\"s{i}.example.org\"")).collect();
        let text = format!("{TLS}metrics_clients = [{}]\n", seventeen.join(", "));
        assert!(matches!(parse(text), Err(ConfigError::MonitoringTls(_))));
        let no_ca = "[monitoring_tls]\ncert = \"/c.pem\"\nkey = \"/k.pem\"\n";
        assert!(matches!(parse(no_ca.into()), Err(ConfigError::Syntax(_))));
    }

    #[test]
    fn the_sites_limits_are_per_ssid_each_once_in_range() {
        let none = Config::parse(ORIGIN).unwrap();
        assert!(none.limits.is_empty());
        assert_eq!(
            none.captures_path,
            PathBuf::from("/var/lib/wifi-controller/captures")
        );
        let text = format!(
            "{ORIGIN}[limits]\nssids = [{{ ssid = \"Guest\", down_kbit = 50000 }}, \
             {{ ssid = \"IoT\", up_kbit = 1000 }}]\n"
        );
        let l = Config::parse(&text).unwrap().limits;
        let rate = |down, up| Rate {
            down_kbit: down,
            up_kbit: up,
        };
        assert_eq!(
            l,
            BTreeMap::from([
                ("Guest".to_owned(), rate(Some(50_000), None)),
                ("IoT".to_owned(), rate(None, Some(1_000))),
            ])
        );
        for bad in [
            "ssids = [{ ssid = \"Guest\" }]",
            "ssids = [{ ssid = \"Guest\", down_kbit = 10 }]",
            "ssids = [{ ssid = \"\", down_kbit = 1000 }]",
            "ssids = [{ ssid = \"G\", down_kbit = 1000 }, { ssid = \"G\", up_kbit = 1000 }]",
            "ssids = [{ ssid = \"G\", down_kbit = 1000, other = 1 }]",
        ] {
            let text = format!("{ORIGIN}[limits]\n{bad}\n");
            assert!(Config::parse(&text).is_err(), "{bad}");
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
