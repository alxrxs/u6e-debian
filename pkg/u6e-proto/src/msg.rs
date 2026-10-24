//! The messages of the agent-to-controller link and the state they carry.

use serde::{Deserialize, Serialize};

/// Everything the agent sends.
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
}

/// Everything the controller sends.
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
}

/// What the AP is running, sent once per connection.
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Temp {
    pub zone: String,
    pub milli_c: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Band {
    B24,
    B5,
    B6,
}

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bss {
    pub ifname: String,
    pub bssid: [u8; 6],
    pub ssid: String,
    pub phy: String,
    pub vlan: u16,
}

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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldDelta {
    pub mask: u32,
    pub vals: Vec<i64>,
}

/// Changed fields of the record at `idx` of the base snapshot's list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecDelta {
    pub idx: u16,
    pub mask: u32,
    pub vals: Vec<i64>,
}

/// Something that happened between two ticks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub at_ms: u64,
    pub kind: EventKind,
}

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
