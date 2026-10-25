//! The messages of the agent-to-controller link and of the deploy runner's
//! link to the controller, and the state they carry. postcard encodes them
//! without a schema, so every change to their layout (a field, a variant, an
//! order) bumps [`crate::PROTOCOL`].

use std::net::IpAddr;

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
    /// same `sha256`. Signed by the deploy runner, the only party that
    /// originates one: the controller relays it unread and cannot forge it.
    ApplyConfig(SignedConfig),
}

/// What the AP is running, sent once per connection.
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
}

/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Temp {
    pub zone: String,
    pub milli_c: i32,
}

/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    Assoc { mac: [u8; 6], bss: u16 },
    Disassoc { mac: [u8; 6], bss: u16 },
    EapOk { mac: [u8; 6], bss: u16 },
    EapFail { mac: [u8; 6], bss: u16 },
    RadioUp { phy: String },
    RadioDown { phy: String },
    FwCrash { phy: String },
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
    /// Connections the NSS hardware forwards, past the CPU.
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
/// carry it out. None changes the radios' configuration: only a signed
/// [`CtlMsg::ApplyConfig`] does, so its hash always says what runs.
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
    /// transition management).
    Steer {
        mac: [u8; 6],
        target_bssid: [u8; 6],
    },
    /// Make the AP's blocks exactly `macs`, on every BSS: what the controller
    /// sends after the first key frame of each connection, so that a client
    /// unblocked while the AP could not be told is let on there too.
    SyncBlocks {
        macs: Vec<[u8; 6]>,
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

/// A whole configuration of one AP, as the deploy runner signed it: Ed25519
/// over [`crate::config::payload`] (the protocol, `ap`, `seq` and `sha256`),
/// by the key the AP's image pins. `seq` grows with every configuration the
/// runner signs for the AP, so an old one cannot be replayed.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedConfig {
    /// The AP it is for, by its host name.
    pub ap: String,
    pub seq: u64,
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

/// Everything the deploy runner (`wifi-deploy`) sends the controller. The
/// runner is the only party that originates configuration or images.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RunnerMsg {
    /// First message of a connection.
    Hello(RunnerHello),
    /// Answer to [`RunnerCtlMsg::Ping`], echoing its value.
    Pong(u64),
    /// Apply a rendered and signed configuration to the AP it names; the
    /// controller relays it unchanged and answers with a
    /// [`RunnerCtlMsg::ConfigApplied`] of the same id.
    ApplyConfig { id: u64, config: SignedConfig },
    /// One line of a rollout's log, as it runs.
    RolloutLog { id: u64, line: String },
    /// How a rollout ended: the last word on it.
    RolloutResult(RolloutResult),
}

/// Everything the controller sends the deploy runner.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RunnerCtlMsg {
    Ping(u64),
    /// The agent's answer to a [`RunnerMsg::ApplyConfig`], or the
    /// controller's own when the AP could not be asked.
    ConfigApplied {
        id: u64,
        result: ConfigApplied,
    },
    /// The AP reconnected with an installed configuration other than the
    /// one it last acknowledged (`acked`): sign the runner's last
    /// configuration for it again, under a new sequence number (the old one
    /// is a replay to the AP), and send it.
    Repush {
        ap: String,
        acked: Option<[u8; 32]>,
        installed: Option<[u8; 32]>,
    },
    /// Roll an image out to an AP, as an admin asked; the runner may refuse.
    Rollout(RolloutRequest),
    /// A rollout's health gate: whether the AP came back as the gate
    /// requires, in its time. Unhealthy, the runner rolls the AP back.
    RolloutGate {
        id: u64,
        healthy: bool,
        detail: String,
    },
}

/// What the runner is, sent once per connection.
///
/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerHello {
    pub version: String,
}

/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutRequest {
    /// Chosen by the controller; the runner's log and result carry it.
    pub id: u64,
    pub ap: String,
    /// The kept build to stage, as the image names itself.
    pub image_id: String,
    /// The admin who asked, for the runner's audit.
    pub user: String,
}

/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutResult {
    pub id: u64,
    pub outcome: RolloutOutcome,
    pub detail: String,
}

/// On the wire: a change to it bumps [`crate::PROTOCOL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RolloutOutcome {
    /// Not started: another rollout runs, the image is unknown, ...
    Refused,
    /// The AP runs the image and passed the health gate.
    Done,
    /// The AP failed the health gate and runs its previous image again.
    RolledBack,
    /// Neither the image nor the way back could be staged.
    Failed,
}
