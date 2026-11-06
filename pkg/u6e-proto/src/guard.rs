//! The AP's own socket between the agent and its client guards
//! (`u6e-guard`), which only the agent's group may open: one request per
//! connection, answered once, in the framing of `frame`. Both ends ship in
//! one image, so this is no part of [`crate::PROTOCOL`].

use serde::{Deserialize, Serialize};

use crate::msg::{Binding, Event, Guard, GuardConfig};

/// Where the guards listen.
pub const SOCKET: &str = "/run/u6e-guard/sock";

/// What the agent asks, a closed set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// The bindings held now.
    Bindings,
    /// The violations recorded after the one numbered `after`.
    Violations { after: u64 },
    /// Every client's leased addresses, replacing those seeded before.
    Seed(Vec<Binding>),
    /// How to run.
    Mode(GuardConfig),
}

/// The answer to a [`Request`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    /// `started_ms` tells a guard that restarted (and so forgot its mode and
    /// seed) from one that did not; `generation` grows with each change;
    /// `dropped` counts the frames each guard's filters dropped since then.
    Bindings {
        started_ms: u64,
        generation: u64,
        bindings: Vec<Binding>,
        dropped: Vec<(Guard, u64)>,
    },
    /// Each [`crate::msg::EventKind::GuardViolation`] with its number, the
    /// oldest first; a gap in the numbers is what a full record dropped.
    Violations {
        events: Vec<(u64, Event)>,
    },
    Done,
    Refused(String),
}
