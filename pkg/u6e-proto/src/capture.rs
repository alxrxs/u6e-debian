//! The AP's own socket between the agent and its capture helper
//! (`u6e-capture`), which only the agent's group may open: the agent sends
//! one [`crate::msg::CaptureRequest`] frame and reads back the
//! [`crate::msg::AgentMsg::Capture`] and
//! [`crate::msg::AgentMsg::CaptureChunk`] frames it forwards. Shutting its
//! writing side down stops the capture (its last frames still come);
//! closing the connection ends it at once. Both ends ship in one image, so
//! this is no part of [`crate::PROTOCOL`].

/// Where the helper listens.
pub const SOCKET: &str = "/run/u6e-capture/sock";

/// What a capture changed, written before it changes anything and removed
/// once it is put back: while it exists the NSS offload is held back.
pub const RESTORE: &str = "/run/u6e-capture/restore";

/// ECM's switches that stop it accelerating new IPv4 and IPv6 connections.
pub const ECM_STOP: [&str; 2] = [
    "/proc/sys/net/ecm/front_end_ipv4_stop",
    "/proc/sys/net/ecm/front_end_ipv6_stop",
];
