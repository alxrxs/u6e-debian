//! Wire protocol shared by the access point agent, the controller and the
//! deploy runner: the messages, the delta coding that keeps a 2 s snapshot of
//! 20 clients near 400 B, the length-prefixed framing every end speaks over
//! its TLS link, the MAC and hex text they read and write, (feature `digest`)
//! the hash a Wi-Fi configuration is known by and the deploy runner's
//! signature over it, and (feature `tls`, which includes `digest`) the
//! post-quantum, key-pinned TLS configuration of the links.
//! Each end opens with the frozen version frame of `version`, so ends of
//! different protocols tell so before either decodes a message.

#[cfg(feature = "digest")]
pub mod config;
pub mod delta;
pub mod frame;
#[cfg(test)]
mod golden;
pub mod mac;
pub mod msg;
#[cfg(feature = "tls")]
pub mod tls;
pub mod version;

pub use version::PROTOCOL;
