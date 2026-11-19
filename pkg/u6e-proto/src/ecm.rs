//! ECM's control files, as the AP's helpers write them and the agent reads
//! them, and the mark that keeps a connection off the NSS. The deceleration
//! handlers drop a write's last byte, a newline.

/// A write of a MAC decelerates that client's connections, of an
/// interface's name that interface's: ECM accelerates them again from their
/// next packets, as it then classifies them.
pub const DEFUNCT_BY_MAC: &str = "/proc/sys/net/ecm/defunct_by_mac";
pub const DEFUNCT_BY_IFACE: &str = "/proc/sys/net/ecm/defunct_by_iface";

/// A packet whose skb mark is this keeps its connection on the CPU while
/// its packets carry it (ECM_CLASSIFIER_DSCP_NO_ACCEL_MARK, the image's ECM
/// patch 904): one client's traffic reaches the host, and no other's.
pub const NO_ACCEL_MARK: u32 = 0x7536_0000;
