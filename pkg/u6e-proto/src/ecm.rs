//! ECM's control files, as the AP's helpers write them and the agent reads
//! them. The deceleration handlers drop a write's last byte, a newline.

/// The switches that stop ECM accelerating new IPv4 and IPv6 connections.
pub const STOP: [&str; 2] = [
    "/proc/sys/net/ecm/front_end_ipv4_stop",
    "/proc/sys/net/ecm/front_end_ipv6_stop",
];

/// A write of a MAC decelerates that client's connections, of an
/// interface's name that interface's: ECM accelerates them again from their
/// next packets, as it then classifies them.
pub const DEFUNCT_BY_MAC: &str = "/proc/sys/net/ecm/defunct_by_mac";
pub const DEFUNCT_BY_IFACE: &str = "/proc/sys/net/ecm/defunct_by_iface";
