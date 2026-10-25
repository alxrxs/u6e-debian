//! The messages of the agent-to-controller link and the state they carry.
//! postcard encodes them without a schema, so every change to their layout
//! (a field, a variant, an order) bumps [`crate::PROTOCOL`].

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
/// carry it out.
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
