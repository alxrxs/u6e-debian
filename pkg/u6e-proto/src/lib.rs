//! Wire protocol shared by the access point agent and the controller: the
//! messages, the delta coding that keeps a 2 s snapshot of 20 clients near
//! 400 B, the length-prefixed framing both ends speak over the TLS link, and
//! (feature `tls`) the post-quantum, key-pinned TLS configuration of that link.

pub mod delta;
pub mod frame;
pub mod msg;
#[cfg(feature = "tls")]
pub mod tls;
