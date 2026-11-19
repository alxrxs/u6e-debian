//! The AP's own socket between the agent and its rate-limit helper
//! (`u6e-shaper`), which only the agent's group may open: one request per
//! connection, in the framing of `frame`, answered once; a sync that built
//! the uplink's shaper tree then waits for the agent's [`Request::Confirm`]
//! on the same connection, and is undone without it. Both ends ship in one
//! image, so this is no part of [`crate::PROTOCOL`].

use serde::{Deserialize, Serialize};

use crate::msg::{LimitTarget, Rate};

/// Where the helper listens.
pub const SOCKET: &str = "/run/u6e-shaper/sock";

/// A network interface, by its name and its index: a netdev made again (a
/// radio's restart) has a new index, and so needs its tree again.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Netdev {
    pub name: String,
    pub ifindex: u32,
}

/// An SSID as this AP carries it: its own limit (none in either direction
/// when only its clients are limited), its BSSs' netdevs, where download is
/// shaped, and its ports (those netdevs and their per-VLAN netdevs), where
/// its clients' packets come in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsidSpec {
    pub ssid: String,
    pub rate: Rate,
    pub vaps: Vec<Netdev>,
    pub ports: Vec<Netdev>,
}

/// A client limit, on the SSID `ssid` (an index into [`Spec::ssids`]) the
/// client is on now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSpec {
    pub mac: [u8; 6],
    pub rate: Rate,
    pub ssid: usize,
}

/// Everything the AP shapes: exactly this, after a sync.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spec {
    pub ssids: Vec<SsidSpec>,
    pub clients: Vec<ClientSpec>,
    /// The client VLANs' netdevs, where download packets come in from the
    /// uplink.
    pub vlans: Vec<Netdev>,
}

/// What the agent asks, a closed set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// Make the shaping `Spec`'s.
    Sync(Spec),
    /// The same while the agent has no controller to confirm with: a limit
    /// that needs the uplink's tree built (which could cut the agent's
    /// link) is refused for now, so nothing is to be confirmed.
    SyncAway(Spec),
    /// Keep the sync just made: the uplink still carries the agent's link.
    Confirm,
    /// The bytes each limit's classes passed.
    Counters,
}

/// How one limit came out, and the bytes its NSS classes passed, per
/// direction, since they were made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    pub target: LimitTarget,
    pub ok: bool,
    pub detail: String,
    pub down_bytes: u64,
    pub up_bytes: u64,
}

/// The answer to a [`Request`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    /// Each limit's outcome; with `confirm`, the sync built the uplink's
    /// tree and is undone unless confirmed within [`CONFIRM_SECS`].
    Synced {
        outcomes: Vec<Outcome>,
        confirm: bool,
    },
    Counters(Vec<Outcome>),
    Done,
    Refused(String),
}

/// How long a sync that built the uplink's tree waits for its
/// [`Request::Confirm`].
pub const CONFIRM_SECS: u64 = 20;
