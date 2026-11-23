//! The messages of the agent-to-controller link, and the state they carry. postcard encodes them
//! without a schema, so every change to their layout (a field, a variant, an
//! order) bumps [`crate::PROTOCOL`].

use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

/// Everything the agent sends.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AgentMsg {
    /// First message of a connection.
    Hello(Hello),
    /// A complete snapshot; the base of the deltas that follow.
    Key(Snapshot),
    /// The change since the snapshot numbered `base`.
    Delta(SnapshotDelta),
    Event(Event),
    /// Answer to [`CtlMsg::Ping`], echoing its value.
    Pong(u64),
    /// The connections of the AP's clients, at the cadence
    /// [`CtlMsg::FlowCadence`] sets or on [`CtlMsg::WantFlows`].
    Flows(Flows),
    /// The outcome of a [`CtlMsg::Command`].
    Result(CommandResult),
    /// One spectrum of a radio scanning since [`CtlMsg::SpectrumStart`].
    Spectrum(SpectrumFrame),
    /// Whether a radio's spectrum scan runs, and why it started or ended: the
    /// answer to [`CtlMsg::SpectrumStart`] and [`CtlMsg::SpectrumStop`], and
    /// what the agent sends when it ends a scan itself.
    SpectrumState {
        radio: String,
        running: bool,
        reason: String,
    },
    /// The outcome of a [`CtlMsg::ApplyConfig`].
    ConfigApplied(ConfigApplied),
    /// The bindings the AP's client guards hold, whole, whenever they change
    /// (at most every tick) and at the start of each session.
    Bindings(Vec<Binding>),
    /// The frames each guard's filters dropped since the guards started,
    /// whenever that changes and at the start of each session.
    GuardDrops(Vec<(Guard, u64)>),
    /// How each limit of the last [`CommandKind::SyncLimits`] stands on this
    /// AP, whenever one changes and at the start of each session.
    Limits(Vec<LimitState>),
    /// The next part of a capture's pcapng file, acknowledged by a
    /// [`CtlMsg::CaptureAck`] of its `seq`.
    CaptureChunk(CaptureChunk),
    /// Whether a capture runs, how it takes the client's flows and what it
    /// has written: the answer to [`CtlMsg::CaptureStart`], and its end,
    /// however it ended.
    Capture(CaptureState),
    /// What the client guards read of mDNS: whole at the start of each
    /// session and after the guards restarted, then what changed, at most
    /// every tick.
    Services(Services),
}

/// Everything the controller sends.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CtlMsg {
    /// Seconds between snapshots.
    SetTick {
        secs: u16,
    },
    /// Send a complete snapshot next (after a gap in the deltas).
    WantKey,
    Ping(u64),
    /// Send the flows next: every connection (up to the agent's cap) when
    /// `full`, else each client's summary and top flows.
    WantFlows {
        full: bool,
    },
    /// Seconds between flow summaries.
    FlowCadence {
        secs: u16,
    },
    /// An operator action, answered by an [`AgentMsg::Result`] of its id.
    Command(Command),
    /// Scan the spectrum of the radio of this stable name (`radio24`,
    /// `radio5`, `radio6`) on its own channel and stream it, until
    /// [`CtlMsg::SpectrumStop`], the end of the session or the agent's limit.
    SpectrumStart {
        radio: String,
    },
    SpectrumStop {
        radio: String,
    },
    /// Install this configuration and apply it the least disruptive way
    /// [`Mechanism`] names; answered by an [`AgentMsg::ConfigApplied`] of the
    /// same `sha256`. Signed with the controller's configuration key, which
    /// the AP's image pins, apart from the key of the link.
    ApplyConfig(SignedConfig),
    /// How the client guards run: the VLANs they enforce on and the static
    /// clients; sent after each session's first key frame and when it
    /// changes. Without it they only report.
    Guards(GuardConfig),
    /// Every client's leased addresses, as the DHCP servers hold them, which
    /// replace the ones seeded before: a client whose DHCP exchange this AP
    /// did not see (it roamed in, or the AP restarted) is bound all the same.
    SeedBindings(Vec<Binding>),
    /// Capture a client's traffic and stream it, until
    /// [`CtlMsg::CaptureStop`], the request's own limits or the end of the
    /// session.
    CaptureStart(CaptureRequest),
    CaptureStop {
        id: u64,
    },
    /// The chunk `seq` of capture `id` is stored: the agent may send another.
    CaptureAck {
        id: u64,
        seq: u64,
    },
}

/// What the AP is running, sent once per connection. `manifest` is the
/// image's `/etc/u6e-image`: `key: value` lines, among them `image:` and
/// `built_ms:`.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hello {
    pub ap: String,
    pub manifest: String,
    pub kernel: String,
    pub hostapd: String,
    pub agent: String,
}

impl Hello {
    /// The image's name: where its build keeps it, and what a rollout names.
    pub fn image(&self) -> &str {
        self.manifest_line("image")
    }

    /// The image's build time in milliseconds since the Unix epoch; 0 for an
    /// image from before the manifest said. No configuration the controller
    /// signed before it (its sequence number is its signing time) applies on
    /// the image.
    pub fn built_ms(&self) -> u64 {
        self.manifest_line("built_ms").parse().unwrap_or(0)
    }

    /// The value of the manifest's `<key>:` line; empty without one.
    fn manifest_line(&self, key: &str) -> &str {
        let line = self
            .manifest
            .lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix(':'));
        line.unwrap_or_default().trim()
    }
}

/// The state of the AP at one tick.
///
/// `stations` is sorted by MAC, each MAC once, as [`crate::delta::valid`]
/// requires; a snapshot that is not goes out as a key frame.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub seq: u64,
    pub uptime_s: u32,
    pub load_milli: u32,
    pub mem_avail_kb: u32,
    pub nss_load_pct: u8,
    pub temps: Vec<Temp>,
    pub radios: Vec<Radio>,
    pub bsss: Vec<Bss>,
    pub stations: Vec<Station>,
    /// The hash ([`crate::config::config_sha256`]) of the configuration
    /// installed for the radios; `None` while it cannot be read.
    pub config_sha256: Option<[u8; 32]>,
    /// Whether the AP's clock is synchronized, which a signed configuration
    /// needs before it applies.
    pub clock_synced: bool,
    /// The power each radio's channels allow, by its own regulatory rules
    /// (a self-managed radio's own, else the kernel's): runs of a band's
    /// enabled channels of one limit. They change so rarely that a key frame
    /// carries a change.
    pub power_limits: Vec<PowerLimit>,
    /// How the stations authenticated, by MAC, sorted, each one a station's:
    /// a station hostapd could not be asked about yet has none.
    pub auth: Vec<([u8; 6], StationAuth)>,
    /// Whether a capture holds a client's flows off the NSS offload: its
    /// restore not done. A capture holds them at most 10 minutes; longer is
    /// a restore that failed.
    pub offload_held: bool,
}

/// The longest identity carried: RADIUS's User-Name is at most 253 bytes.
pub const IDENTITY_MAX: usize = 253;

/// How a client authenticated, as hostapd holds it for its association:
/// what it associated with, and, over 802.1X, the identity it gave and the
/// EAP method it used. The VLAN RADIUS gave it is its [`Station::vlan`].
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StationAuth {
    /// The AKM suite it associated with, as its selector (OUI and type:
    /// 00-0f-ac:1 is 0x000f_ac01); 0 for none.
    pub akm: u32,
    /// The 802.11 authentication algorithm of the association: 0 open
    /// system, 2 fast BSS transition (802.11r), 3 SAE.
    pub auth_alg: u16,
    /// Whether hostapd authorized it: its keys are in place and its traffic
    /// passes.
    pub authorized: bool,
    /// The identity it gave EAP, which hostapd relays to RADIUS as its
    /// User-Name, at most [`IDENTITY_MAX`] bytes; empty without 802.1X.
    pub identity: String,
    /// The EAP method it last used, by its IANA type (13 TLS, 21 TTLS, 25
    /// PEAP, 26 MSCHAPv2); 0 without one.
    pub eap_method: u8,
    /// The reauthentication period RADIUS set (Session-Timeout with
    /// Termination-Action RADIUS-Request), in seconds; 0 without one.
    pub reauth_s: u32,
}

/// How a client authenticates, by its AKM suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKind {
    /// 802.1X: EAP, checked by RADIUS.
    Eap,
    /// A passphrase (WPA-PSK), which u6e-wifi always pairs with RADIUS MAC
    /// authentication (its `psk-mab` networks): RADIUS admitted the MAC.
    MacAuth,
    /// WPA3-Personal.
    Sae,
    /// Anything else: an open network, OWE, FILS.
    Other,
}

/// The OUI of the IEEE 802.11 AKM suites.
const IEEE80211: u32 = 0x000f_ac00;

impl StationAuth {
    pub fn kind(&self) -> AuthKind {
        if self.akm & !0xff != IEEE80211 {
            return AuthKind::Other;
        }
        match self.akm & 0xff {
            // 802.1X, FT over 802.1X, their SHA-256 and Suite B forms.
            1 | 3 | 5 | 11 | 12 | 13 => AuthKind::Eap,
            // PSK, FT-PSK, PSK-SHA256.
            2 | 4 | 6 => AuthKind::MacAuth,
            // SAE, FT-SAE, and their extended-key forms.
            8 | 9 | 24 | 25 => AuthKind::Sae,
            _ => AuthKind::Other,
        }
    }

    /// Whether the association was a fast BSS transition (802.11r): a roam
    /// that carried its keys over, with no new authentication.
    pub fn fast_transition(&self) -> bool {
        self.auth_alg == 2
    }
}

/// The most a radio transmits with `first..=last` of `band` as its primary
/// channel: that channel's limit, the one the driver holds a fixed power to
/// whatever the width.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowerLimit {
    pub band: Band,
    pub first: u16,
    pub last: u16,
    pub dbm: i8,
}

/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Temp {
    pub zone: String,
    pub milli_c: i32,
}

/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Band {
    B24,
    B5,
    B6,
}

/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Radio {
    pub phy: String,
    pub band: Band,
    pub channel: u16,
    pub width_mhz: u16,
    pub txpower_mbm: i32,
    pub noise_dbm: i8,
    pub active_ms: u64,
    pub busy_ms: u64,
    pub rx_ms: u64,
    pub tx_ms: u64,
    pub up: bool,
    /// The most it transmits on its channel now: its [`PowerLimit`], or the
    /// power it sends where that is less than the power asked of it (the
    /// radio holds itself lower, as a 6 GHz one does by its power spectral
    /// density); 0 while not known.
    pub max_txpower_dbm: i8,
}

/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bss {
    pub ifname: String,
    pub bssid: [u8; 6],
    pub ssid: String,
    pub phy: String,
    pub vlan: u16,
}

/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Station {
    pub mac: [u8; 6],
    /// Index into [`Snapshot::bsss`].
    pub bss: u16,
    pub signal: i8,
    pub signal_avg: i8,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub tx_retries: u32,
    pub tx_failed: u32,
    pub tx_rate_kbps: u32,
    pub rx_rate_kbps: u32,
    /// The MCS index of the last rate, meaningless when its mode is
    /// [`RateMode::Legacy`]; an HT index (0–31) counts the streams in.
    pub tx_mcs: u8,
    pub rx_mcs: u8,
    pub tx_mode: RateMode,
    pub rx_mode: RateMode,
    /// Spatial streams of a VHT or HE rate; 0 when the rate does not say.
    pub tx_nss: u8,
    pub rx_nss: u8,
    pub tx_airtime_us: u64,
    pub rx_airtime_us: u64,
    pub inactive_ms: u32,
    pub connected_s: u32,
    pub vlan: u16,
}

/// The PHY mode a rate was sent in, which says what its MCS index means.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RateMode {
    /// 802.11a/b/g: no MCS.
    Legacy,
    Ht,
    Vht,
    He,
}

/// The difference between two snapshots, applied with [`crate::delta::apply`].
///
/// In every mask, bit *i* stands for the *i*-th field of the record in
/// declaration order, the field that identifies the record (a station's MAC, a
/// radio's phy) left out; `vals` holds the differences of the set bits, lowest
/// bit first. The scalar bits are the four numbers of [`Snapshot`], then one per
/// temperature.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SnapshotDelta {
    pub seq: u64,
    /// The `seq` of the snapshot this is a difference from.
    pub base: u64,
    pub scalars: FieldDelta,
    pub radios: Vec<RecDelta>,
    pub stations: Vec<RecDelta>,
    pub removed: Vec<[u8; 6]>,
    pub added: Vec<Station>,
    /// The complete list when it changed.
    pub bsss: Option<Vec<Bss>>,
    /// The stations' authentications that are new or changed, by MAC; a
    /// station's leaves with it.
    pub auth: Vec<([u8; 6], StationAuth)>,
}

/// Changed fields of a record that has no index.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldDelta {
    pub mask: u32,
    pub vals: Vec<i64>,
}

/// Changed fields of the record at `idx` of the base snapshot's list.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecDelta {
    pub idx: u16,
    pub mask: u32,
    pub vals: Vec<i64>,
}

/// Something that happened between two ticks.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub at_ms: u64,
    pub kind: EventKind,
}

/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum EventKind {
    Assoc {
        mac: [u8; 6],
        bss: u16,
    },
    Disassoc {
        mac: [u8; 6],
        bss: u16,
    },
    /// hostapd started EAP with a client that associated.
    EapStart {
        mac: [u8; 6],
        bss: u16,
    },
    EapOk {
        mac: [u8; 6],
        bss: u16,
    },
    /// RADIUS (or hostapd's own EAP server) rejected the client.
    EapFail {
        mac: [u8; 6],
        bss: u16,
    },
    /// EAP gave up: the client stopped answering, or, with `server`, the
    /// RADIUS server did.
    EapTimeout {
        mac: [u8; 6],
        bss: u16,
        server: bool,
    },
    /// A client's 4-way handshake failed as a wrong passphrase makes it fail.
    PskMismatch {
        mac: [u8; 6],
        bss: u16,
    },
    RadioUp {
        phy: String,
    },
    RadioDown {
        phy: String,
    },
    FwCrash {
        phy: String,
    },
    /// A client broke one of the client guards' rules.
    GuardViolation(Violation),
}

/// An address the client guards admit for a MAC: one its DHCP server
/// acknowledged, one the controller seeded from the leases, or a static one.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Binding {
    pub mac: [u8; 6],
    pub ip: Ipv4Addr,
    /// When it expires, Unix milliseconds; never, for a static one.
    pub expires_ms: Option<u64>,
}

/// The client guards.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Guard {
    /// ARP inspection: no client's ARP claims an address bound to another
    /// client, nor, when either holds an address, names another sender.
    Arp,
    /// Rogue DHCP: no client sends from a DHCP or DHCPv6 server port to a
    /// client port, and no other than the site's server binds an address.
    Dhcp,
    /// RA guard: no client advertises a default route, DNS servers, or a
    /// prefix or route that is not unique local, nor sends ICMPv6 the
    /// filters cannot read the type of.
    Ra,
    /// IP source guard: a client's new connections come from no address
    /// bound to another client.
    Source,
    /// No client sends a VLAN-tagged frame.
    Tag,
}

/// A client breaking a guard's rule, at most once a minute per client and
/// guard, the repeats in between counted.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Violation {
    pub guard: Guard,
    /// The frame's source MAC.
    pub mac: [u8; 6],
    /// The interface it came in on and that interface's VLAN.
    pub ifname: String,
    pub vlan: u16,
    /// The address it claimed or offered, when there is one.
    pub ip: Option<IpAddr>,
    pub detail: String,
    /// Whether the guard enforces on that VLAN, so the frame was dropped.
    pub dropped: bool,
    /// Violations of the same client and guard since the last one reported.
    pub repeats: u32,
}

/// How the client guards run.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardConfig {
    /// The VLANs whose offending frames are dropped; on the others the
    /// guards only report.
    pub enforce: Vec<u16>,
    /// The clients with a static address, bound for good.
    pub statics: Vec<Binding>,
    /// The site's DHCP servers (the server identifiers of their answers)
    /// and the relays that bring their answers onto the VLANs: only their
    /// acknowledgements bind addresses. Empty, none is learnt.
    pub dhcp_servers: Vec<Ipv4Addr>,
    pub dhcp_relays: Vec<Ipv4Addr>,
}

/// The connections the AP forwards, per client, as the NSS connection
/// manager tracks them.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flows {
    pub seq: u64,
    /// False when the agent's cap on connections cut the table short.
    pub complete: bool,
    pub clients: Vec<ClientFlows>,
}

/// One client's connections: totals over all of them, and the largest.
///
/// Bytes and packets are counted from the client's point of view: `tx` is
/// what it sent, `rx` what it received.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientFlows {
    pub mac: [u8; 6],
    pub conns: u32,
    /// Connections the NSS hardware forwards past the CPU, or forwarded most
    /// of the packets of before they ended.
    pub offloaded: u32,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
    /// The client's connections with the most bytes, most first.
    pub top: Vec<Flow>,
}

/// One connection of a client; `src` is the end that opened it.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flow {
    /// The IP protocol number (6 TCP, 17 UDP, ...).
    pub proto: u8,
    pub src: IpAddr,
    pub sport: u16,
    pub dst: IpAddr,
    pub dport: u16,
    /// From the client's point of view, as in [`ClientFlows`].
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub offloaded: bool,
    pub age_s: u32,
    /// The client is `src`, the end that opened it; else it is `dst`.
    pub client_is_src: bool,
}

/// An operator action for the agent to carry out.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Command {
    /// Chosen by the controller; echoed in the [`CommandResult`].
    pub id: u64,
    pub kind: CommandKind,
}

/// The closed set of actions. None carries free-form text, and the set is
/// exhaustive, so a new action is a compile error at every end that must
/// carry it out. None changes the radios' installed configuration: only a
/// signed [`CtlMsg::ApplyConfig`] does, so its hash always says what was
/// installed; a channel switch or a power set moves the radio as it runs, and
/// the snapshot says where it is.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommandKind {
    /// Deauthenticate the client from the BSS it is on.
    Kick {
        mac: [u8; 6],
    },
    /// Refuse the client on every BSS of the AP, and kick it.
    Block {
        mac: [u8; 6],
    },
    Unblock {
        mac: [u8; 6],
    },
    /// Ask the client to move to the BSS `target_bssid` (802.11v BSS
    /// transition management). A client may decline and stay; with `force`,
    /// the request says its disassociation is imminent, and one that
    /// declines is disassociated about 10 s later.
    Steer {
        mac: [u8; 6],
        target_bssid: [u8; 6],
        force: bool,
    },
    /// Make the AP's blocks exactly `macs`, on every BSS: what the controller
    /// sends after the first key frame of each connection, so that a client
    /// unblocked while the AP could not be told is let on there too.
    SyncBlocks {
        macs: Vec<[u8; 6]>,
    },
    /// Move the radio of `radio` to primary `channel` of a `width_mhz` block
    /// centred on channel `center1`, by a channel switch announcement the
    /// clients follow; refused when the radio, the regulatory domain or a
    /// radar check (CAC) the target needs would not allow it.
    ChannelSwitch {
        radio: Band,
        channel: u16,
        width_mhz: u16,
        center1: u16,
    },
    /// Set the transmit power of the radio of `radio`; refused above what
    /// its channels allow.
    TxPower {
        radio: Band,
        dbm: i8,
    },
    /// Make the AP's rate limits exactly `limits` ([`check_limits`]): what
    /// the controller sends on every change and after the first key frame of
    /// each connection. The AP keeps them while the controller is away.
    SyncLimits {
        limits: Vec<Limit>,
    },
}

/// What came of a [`Command`].
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandResult {
    pub id: u64,
    pub ok: bool,
    /// hostapd's answer, or why the command was refused.
    pub detail: String,
}

/// The slowest and the fastest a limit may be, in kbit/s.
pub const RATE_MIN_KBIT: u32 = 64;
pub const RATE_MAX_KBIT: u32 = 2_000_000;
/// The most client limits, and SSID limits, an AP is given.
pub const CLIENT_LIMITS_MAX: usize = 64;
pub const SSID_LIMITS_MAX: usize = 16;
/// The longest SSID.
pub const SSID_MAX: usize = 32;

/// What a limit applies to: one client, or the clients of an SSID together
/// (on each radio of it apart: the AP shapes each radio's netdev on its own).
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LimitTarget {
    Client([u8; 6]),
    Ssid(String),
}

/// The most a target may receive (`down`) and send (`up`), in kbit/s; a
/// direction without one is not limited.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Rate {
    pub down_kbit: Option<u32>,
    pub up_kbit: Option<u32>,
}

impl Rate {
    /// At least one direction, each within [`RATE_MIN_KBIT`] and
    /// [`RATE_MAX_KBIT`].
    pub fn valid(&self) -> bool {
        let ok = |r: Option<u32>| r.is_none_or(|k| (RATE_MIN_KBIT..=RATE_MAX_KBIT).contains(&k));
        (self.down_kbit.is_some() || self.up_kbit.is_some())
            && ok(self.down_kbit)
            && ok(self.up_kbit)
    }
}

/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limit {
    pub target: LimitTarget,
    pub rate: Rate,
}

/// Why `limits` cannot be a sync's: a target twice, a client's address that
/// is no station's, an SSID empty or too long, a rate out of range, or more
/// than [`CLIENT_LIMITS_MAX`] clients or [`SSID_LIMITS_MAX`] SSIDs.
pub fn check_limits(limits: &[Limit]) -> Result<(), String> {
    let mut seen = std::collections::BTreeSet::new();
    let (mut clients, mut ssids) = (0, 0);
    for l in limits {
        match &l.target {
            LimitTarget::Client(m) if !crate::mac::is_station(*m) => {
                return Err(format!(
                    "{} is not a station's address",
                    crate::mac::format(*m)
                ));
            }
            LimitTarget::Client(_) => clients += 1,
            LimitTarget::Ssid(s) if s.is_empty() || s.len() > SSID_MAX => {
                return Err("an SSID is 1 to 32 bytes".into());
            }
            LimitTarget::Ssid(_) => ssids += 1,
        }
        if !l.rate.valid() {
            return Err(format!(
                "a limit is at least one direction of {RATE_MIN_KBIT} to {RATE_MAX_KBIT} kbit/s"
            ));
        }
        if !seen.insert(&l.target) {
            return Err("a target is limited twice".into());
        }
    }
    if clients > CLIENT_LIMITS_MAX || ssids > SSID_LIMITS_MAX {
        return Err(format!(
            "at most {CLIENT_LIMITS_MAX} clients and {SSID_LIMITS_MAX} SSIDs are limited"
        ));
    }
    Ok(())
}

/// How a limit stands on an AP.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LimitStatus {
    /// Its NSS shaper classes are in place.
    Enforced,
    /// Nothing to shape here: the client is not on this AP, or the SSID has
    /// no radio on it.
    Waiting,
    /// The shaper could not put it in place; the detail says why.
    Refused,
    /// In place, but its classes counted nothing while the client's own
    /// counters show traffic in a limited direction: the NSS does not shape
    /// it.
    NotEnforced,
}

/// A limit's state on an AP, with the bytes its NSS classes passed since
/// they were made, summed per direction.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LimitState {
    pub target: LimitTarget,
    pub status: LimitStatus,
    pub detail: String,
    pub down_bytes: u64,
    pub up_bytes: u64,
}

/// The longest capture, in seconds, and its size bounds, in bytes of pcapng.
pub const CAPTURE_SECS_MAX: u16 = 600;
pub const CAPTURE_BYTES_MIN: u32 = 1_000_000;
pub const CAPTURE_BYTES_MAX: u32 = 50_000_000;
/// The shortest snaplen: an Ethernet, IPv6 and TCP header with options.
pub const SNAPLEN_MIN: u16 = 64;
/// The most pcapng bytes a chunk carries: whole blocks, about 64 KiB, and
/// one packet of the longest snaplen whatever.
pub const CHUNK_MAX: usize = 80 << 10;

/// A protocol a capture's filter keeps; ICMP is ICMP and ICMPv6.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilterProto {
    Tcp,
    Udp,
    Icmp,
    Arp,
}

/// What of a client's traffic a capture keeps: every field set must match.
/// A port is either end's (of TCP or UDP, either without a protocol); a
/// host is either end's address (with ARP, the sender's or the target's).
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CaptureFilter {
    pub proto: Option<FilterProto>,
    pub port: Option<u16>,
    pub host: Option<IpAddr>,
}

/// A capture of the client `mac`'s traffic: at most `secs` seconds and
/// `max_bytes` of pcapng, each packet cut at `snaplen` bytes.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureRequest {
    /// Chosen by the controller; every chunk and state of it carries it.
    pub id: u64,
    pub mac: [u8; 6],
    pub secs: u16,
    pub max_bytes: u32,
    pub snaplen: u16,
    pub filter: CaptureFilter,
}

impl CaptureRequest {
    /// Why the request cannot be carried out as it is, if it cannot.
    pub fn check(&self) -> Result<(), &'static str> {
        let f = &self.filter;
        if !crate::mac::is_station(self.mac) {
            return Err("not a station's address");
        }
        if !(1..=CAPTURE_SECS_MAX).contains(&self.secs) {
            return Err("a capture lasts 1 to 600 s");
        }
        if !(CAPTURE_BYTES_MIN..=CAPTURE_BYTES_MAX).contains(&self.max_bytes) {
            return Err("a capture is 1 to 50 MB");
        }
        if self.snaplen < SNAPLEN_MIN {
            return Err("the snaplen is 64 to 65535 bytes");
        }
        if f.port == Some(0) {
            return Err("port 0 is no port");
        }
        match f.proto {
            Some(FilterProto::Arp | FilterProto::Icmp) if f.port.is_some() => {
                Err("a port goes with TCP or UDP")
            }
            Some(FilterProto::Arp) if matches!(f.host, Some(IpAddr::V6(_))) => {
                Err("ARP carries IPv4 addresses only")
            }
            _ => Ok(()),
        }
    }
}

/// A part of a capture's file; `seq` counts from 0.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureChunk {
    pub id: u64,
    pub seq: u64,
    pub data: Vec<u8>,
}

/// How a capture sees a client's flows.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureMechanism {
    /// They stay offloaded, and the NSS copies each of their packets to the
    /// host.
    Mirror,
    /// They are taken off the offload for the capture: the client's, and no
    /// other client's, go back to the AP's CPU at its start and stay there
    /// until it ends.
    OffOffload,
}

/// A capture's state: `bytes` of pcapng written, `packets` in them,
/// `dropped` packets the AP could not keep up with.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureState {
    pub id: u64,
    pub running: bool,
    /// `None` when it was refused before it took the flows.
    pub mechanism: Option<CaptureMechanism>,
    pub bytes: u64,
    pub packets: u64,
    pub dropped: u64,
    /// Why it started, was refused or ended.
    pub reason: String,
}

/// The most devices, offers and queries an AP's mDNS table holds
/// (`u6e-guard`), which the controller holds of each AP too.
pub const MDNS_DEVICES: usize = 96;
pub const MDNS_OFFERS: usize = 256;
pub const MDNS_QUERIES: usize = 256;
/// The most devices each of a query's lists names (the rest counted), and
/// the most addresses kept of a device.
pub const MDNS_LISTED: usize = 16;
pub const MDNS_ADDRS: usize = 4;

/// What the AP's client guards read of the mDNS its bridges carry: the
/// devices heard, the services they offer and the queries they send, each
/// whole as it stands. `full` replaces what the controller holds of the AP;
/// otherwise these are the entries that changed, and those `gone`, since the
/// last. Times are milliseconds of the AP's boot clock and `now_ms` is the
/// read's, so the controller times them on its own clock.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Services {
    pub full: bool,
    pub now_ms: u64,
    pub devices: Vec<MdnsDevice>,
    pub offers: Vec<MdnsOffer>,
    pub queries: Vec<MdnsQuery>,
    pub gone: Vec<MdnsKey>,
    /// Since the guards started: the mDNS messages read, those that did not
    /// read whole, the entries dropped for room, and the messages dropped
    /// past the guards' rate.
    pub packets: u64,
    pub malformed: u64,
    pub evicted: u64,
    pub limited: u64,
}

/// A device heard sending mDNS, by its source MAC.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MdnsDevice {
    pub mac: [u8; 6],
    /// The bridge port it was last heard on and that port's VLAN; `wifi`
    /// when the port is a BSS or a client's per-VLAN interface, else it came
    /// over the uplink.
    pub port: String,
    pub vlan: u16,
    pub wifi: bool,
    /// The host name its address records name, and the addresses they give
    /// (the newest [`MDNS_ADDRS`]).
    pub host: String,
    pub addrs: Vec<IpAddr>,
    pub first_ms: u64,
    pub last_ms: u64,
    /// The queries and the responses it sent, each copy (IPv4, IPv6) one.
    pub queries: u32,
    pub responses: u32,
}

/// A service instance a device advertises.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MdnsOffer {
    pub mac: [u8; 6],
    /// The instance (`Living Room._airplay._tcp.local`), its service type
    /// (`_airplay._tcp.local`), the host and port its SRV record names and
    /// the TXT keys `model`, `md`, `gid`, `igl`, `gpn` and `tsid` it
    /// carries.
    pub instance: String,
    pub service: String,
    pub target: String,
    pub port: u16,
    pub txt: Vec<(String, String)>,
    /// When it was first heard.
    pub first_ms: u64,
    /// How long it lives from when its records last came, the latest expiry
    /// any of them gave; past that and not withdrawn it is unconfirmed.
    pub ttl_s: u32,
    pub announced_ms: u64,
    /// Withdrawn: by its goodbye, or, once unconfirmed, by a query for it
    /// it did not answer.
    pub withdrawn: Option<Withdrawn>,
    /// The queries for it it answered within a second and those it missed
    /// (neither answered nor listed as known by the asker), the misses since
    /// its last answer, when it last answered and last missed, and who
    /// sent the query it missed last.
    pub answered: u32,
    pub missed: u32,
    pub missed_in_row: u16,
    pub answered_ms: Option<u64>,
    pub missed_ms: Option<u64>,
    pub missed_by: Option<[u8; 6]>,
}

/// The queries one device sends for one name and type.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MdnsQuery {
    pub mac: [u8; 6],
    pub name: String,
    pub qtype: u16,
    /// Its last asked for a unicast answer (the QU bit), which may never
    /// reach the host: no miss is counted against such a query.
    pub unicast: bool,
    pub count: u32,
    pub last_ms: u64,
    /// Of its last query: the devices whose offers answered it, those whose
    /// live offers did not, and those whose offers it listed as known
    /// answers, at most [`MDNS_LISTED`] each, and how many more there were.
    pub answered_by: Vec<[u8; 6]>,
    pub missed_by: Vec<[u8; 6]>,
    pub known: Vec<[u8; 6]>,
    pub unlisted: u16,
    /// Its queries that listed no known answer and that nothing answered.
    pub unanswered: u32,
}

/// How an offer was withdrawn.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Withdrawn {
    /// A record of it with TTL 0 (RFC 6762 10.1).
    Goodbye,
    /// It did not answer a query for it after its TTL ran out.
    Unanswered,
}

/// What names an entry of [`Services`].
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MdnsKey {
    Device([u8; 6]),
    Offer([u8; 6], String),
    Query([u8; 6], String, u16),
}

/// The radios' stable names, as their wiphys are named on the AP: the only
/// radios a spectrum scan may be asked of.
pub const RADIOS: [&str; 3] = ["radio24", "radio5", "radio6"];

/// `name` as the one of [`RADIOS`] it is; nothing else names a radio.
pub fn radio(name: &str) -> Option<&'static str> {
    RADIOS.iter().copied().find(|r| *r == name)
}

/// One spectrum of a radio's own channel: the power in each FFT bin, the
/// highest over the samples since the frame before.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpectrumFrame {
    pub radio: String,
    /// Milliseconds since the Unix epoch, as [`Event::at_ms`].
    pub at_ms: u64,
    /// The scanned segment: its centre and width.
    pub center_mhz: u16,
    pub width_mhz: u16,
    /// The centre of the first bin, in tenths of a MHz.
    pub first_mhz_x10: u32,
    /// From one bin's centre to the next, rounded to the kHz; exactly
    /// `width_mhz` / `bins.len()`.
    pub step_khz: u32,
    /// dBm per bin, lowest frequency first.
    pub bins: Vec<i8>,
    /// The noise floor the samples report.
    pub noise_dbm: i8,
}

/// One radio's configuration: the hostapd file u6e-wifi starts the radio's
/// hostapd interface from, and the transmit power it sets. Opaque to the
/// controller, which never stores or shows it: the text holds passphrases
/// and keys, so it is not in this type's `Debug` either.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RadioConfig {
    pub radio: Band,
    pub text: String,
    pub txpower_dbm: i8,
}

impl std::fmt::Debug for RadioConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RadioConfig")
            .field("radio", &self.radio)
            .field("text", &format_args!("<{} bytes>", self.text.len()))
            .field("txpower_dbm", &self.txpower_dbm)
            .finish()
    }
}

/// The text is wiped before its memory goes back to the allocator.
impl Drop for RadioConfig {
    fn drop(&mut self) {
        // SAFETY: zeros are valid UTF-8, and nothing reads the text after.
        crate::frame::zeroize(unsafe { self.text.as_mut_vec() });
    }
}

/// A whole configuration of one AP, as the controller signed it: Ed25519
/// over [`crate::config::payload`] (the protocol, `ap`, `seq`, `not_after`
/// and `sha256`), by the configuration key the AP's image pins. `seq` grows
/// with every configuration signed for the AP and `not_after` ends its
/// validity soon after, so an old one cannot be replayed.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedConfig {
    /// The AP it is for, by its host name.
    pub ap: String,
    /// The signing time, in milliseconds since the Unix epoch.
    pub seq: u64,
    /// The last moment, in the same milliseconds, at which it may apply.
    pub not_after: u64,
    /// [`crate::config::config_sha256`] of `radios`.
    pub sha256: [u8; 32],
    /// Every radio of the AP, once each, in band order.
    pub radios: Vec<RadioConfig>,
    /// 64 bytes.
    pub signature: Vec<u8>,
}

/// What came of a [`CtlMsg::ApplyConfig`].
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigApplied {
    pub sha256: [u8; 32],
    pub ok: bool,
    /// What each radio went through, in the request's order; empty when the
    /// request was refused before anything was installed.
    pub radios: Vec<RadioApplied>,
    /// Why it was refused or failed, or what each step answered.
    pub detail: String,
}

/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RadioApplied {
    pub radio: Band,
    pub mechanism: Mechanism,
}

/// How a radio took a new configuration, least disruptive first.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mechanism {
    /// Nothing changed on the radio: its configuration is the same but for
    /// comments.
    Unchanged,
    /// The changed BSS settings were set in the running hostapd, each one a
    /// setting hostapd reads at every use: no client noticed.
    InPlace,
    /// Its channel or width changed by a channel switch announcement, which
    /// the clients followed.
    ChannelSwitch,
    /// Only its transmit power changed, set through nl80211.
    Power,
    /// u6e-wifi restarted, after asking every client to move to another AP.
    Restart,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(manifest: &str) -> Hello {
        Hello {
            ap: "ap1".into(),
            manifest: manifest.into(),
            kernel: String::new(),
            hostapd: String::new(),
            agent: String::new(),
        }
    }

    /// The AKM suites u6e-wifi configures (ent: WPA-EAP-SHA256 and FT-EAP;
    /// psk-mab: WPA-PSK; sae: SAE and FT-SAE) and a few it does not.
    #[test]
    fn the_akm_suite_says_how_a_client_authenticates() {
        let kind = |akm| {
            let a = StationAuth {
                akm,
                auth_alg: 0,
                authorized: true,
                identity: String::new(),
                eap_method: 0,
                reauth_s: 0,
            };
            a.kind()
        };
        for (akm, want) in [
            (0x000f_ac05, AuthKind::Eap),
            (0x000f_ac03, AuthKind::Eap),
            (0x000f_ac01, AuthKind::Eap),
            (0x000f_ac02, AuthKind::MacAuth),
            (0x000f_ac08, AuthKind::Sae),
            (0x000f_ac09, AuthKind::Sae),
            (0x000f_ac12, AuthKind::Other),
            (0x0050_f201, AuthKind::Other),
            (0, AuthKind::Other),
        ] {
            assert_eq!(kind(akm), want, "{akm:08x}");
        }
    }

    fn limit(target: LimitTarget, down: Option<u32>, up: Option<u32>) -> Limit {
        Limit {
            target,
            rate: Rate {
                down_kbit: down,
                up_kbit: up,
            },
        }
    }

    #[test]
    fn limits_are_checked_whole() {
        let client = |last| LimitTarget::Client([2, 0, 0, 0, 0, last]);
        let ssid = |s: &str| LimitTarget::Ssid(s.into());
        let good = vec![
            limit(client(1), Some(64), None),
            limit(client(2), None, Some(2_000_000)),
            limit(ssid("guest"), Some(10_000), Some(1_000)),
        ];
        assert_eq!(check_limits(&good), Ok(()));
        let bad = [
            vec![limit(client(1), None, None)],
            vec![limit(client(1), Some(63), None)],
            vec![limit(client(1), None, Some(2_000_001))],
            vec![limit(client(1), Some(0), Some(100))],
            vec![limit(
                LimitTarget::Client([1, 0, 0, 0, 0, 1]),
                Some(100),
                None,
            )],
            vec![limit(LimitTarget::Client([0; 6]), Some(100), None)],
            vec![limit(ssid(""), Some(100), None)],
            vec![limit(ssid(&"x".repeat(33)), Some(100), None)],
            vec![
                limit(client(1), Some(100), None),
                limit(client(1), None, Some(100)),
            ],
            (0..=CLIENT_LIMITS_MAX as u8)
                .map(|l| limit(client(l + 1), Some(100), None))
                .collect(),
            (0..=SSID_LIMITS_MAX)
                .map(|l| limit(ssid(&format!("s{l}")), Some(100), None))
                .collect(),
        ];
        for (i, b) in bad.iter().enumerate() {
            assert!(check_limits(b).is_err(), "case {i}");
        }
    }

    fn request(filter: CaptureFilter) -> CaptureRequest {
        CaptureRequest {
            id: 1,
            mac: [2, 0, 0, 0, 0, 1],
            secs: 60,
            max_bytes: 10_000_000,
            snaplen: 128,
            filter,
        }
    }

    #[test]
    fn a_capture_request_is_checked_field_by_field() {
        let v4 = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        let v6 = Some("2001:db8::1".parse().unwrap());
        let ok = |proto, port, host| CaptureFilter { proto, port, host };
        for f in [
            CaptureFilter::default(),
            ok(Some(FilterProto::Tcp), Some(443), v6),
            ok(None, Some(53), v4),
            ok(Some(FilterProto::Icmp), None, v6),
            ok(Some(FilterProto::Arp), None, v4),
        ] {
            assert_eq!(request(f).check(), Ok(()), "{f:?}");
        }
        for f in [
            ok(Some(FilterProto::Arp), Some(53), None),
            ok(Some(FilterProto::Icmp), Some(53), None),
            ok(Some(FilterProto::Arp), None, v6),
            ok(None, Some(0), None),
        ] {
            assert!(request(f).check().is_err(), "{f:?}");
        }
        let base = request(CaptureFilter::default());
        let bad = [
            CaptureRequest {
                mac: [0xff; 6],
                ..base.clone()
            },
            CaptureRequest {
                mac: [0x01, 0, 0x5e, 0, 0, 1],
                ..base.clone()
            },
            CaptureRequest {
                secs: 0,
                ..base.clone()
            },
            CaptureRequest {
                secs: CAPTURE_SECS_MAX + 1,
                ..base.clone()
            },
            CaptureRequest {
                max_bytes: CAPTURE_BYTES_MIN - 1,
                ..base.clone()
            },
            CaptureRequest {
                max_bytes: CAPTURE_BYTES_MAX + 1,
                ..base.clone()
            },
            CaptureRequest {
                snaplen: SNAPLEN_MIN - 1,
                ..base.clone()
            },
        ];
        for b in bad {
            assert!(b.check().is_err(), "{b:?}");
        }
        let edges = CaptureRequest {
            secs: CAPTURE_SECS_MAX,
            max_bytes: CAPTURE_BYTES_MAX,
            snaplen: u16::MAX,
            ..base
        };
        assert_eq!(edges.check(), Ok(()));
    }

    #[test]
    fn the_manifest_names_the_image_and_its_build_time() {
        let h = hello(
            "image:     20261025-120000-abc-def-ap1\nbuilt_ms:  1792929600000\nkernel:    x\n",
        );
        assert_eq!(h.image(), "20261025-120000-abc-def-ap1");
        assert_eq!(h.built_ms(), 1_792_929_600_000);
        // From before the build time was written; and nonsense.
        let old = hello("image: old\nkernel: x\n");
        assert_eq!((old.image(), old.built_ms()), ("old", 0));
        let bad = hello("images: x\nbuilt_ms: soon\n");
        assert_eq!((bad.image(), bad.built_ms()), ("", 0));
    }
}
