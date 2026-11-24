//! The replay's roaming: what each client says it supports, the speakers
//! that stick to the far AP when theirs reboots, and the client that
//! declines every request to move.

use u6e_proto::msg::{RateMode, StationCaps};

use crate::services;

/// The kitchen speaker, a client of its own beside the HomePod pair.
pub const KITCHEN: u8 = 16;
/// The speakers that, once their AP reboots, stay on the other one until it
/// asks them back late in the cycle.
pub const STICKY: [u8; 3] = [services::LEFT, services::RIGHT, KITCHEN];
/// How much weaker the far AP hears a client than its own.
pub const FAR_DB: f64 = 18.0;
/// The client that declines every request to move (no suitable candidate).
pub const DECLINER: u8 = 9;
pub const DECLINED: u8 = 7;
/// A client's query for candidates: its signal is low.
pub const LOW_SIGNAL: u8 = 16;

/// What a client of `phy` and `nss` streams says it supports: the top MCS
/// of its mode, HE at 160 MHz, VHT at 80, HT at 20.
pub fn caps(phy: RateMode, nss: u8) -> StationCaps {
    let (mcs, width_mhz) = match phy {
        RateMode::He => (11, 160),
        RateMode::Vht => (9, 80),
        RateMode::Ht => (7, 20),
        RateMode::Legacy => (0, 20),
    };
    StationCaps {
        mode: phy,
        nss,
        mcs,
        width_mhz,
    }
}
