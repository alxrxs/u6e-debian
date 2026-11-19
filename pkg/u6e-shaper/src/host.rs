//! What the shaper does to the AP, behind one trait the tests fake: `tc` and
//! `nft` run by argument vector (never a shell), sysctl writes (ECM's
//! deceleration, `u6e_proto::ecm`), and the AP's netdevs as sysfs lists them.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use u6e_proto::nft::{self, complaint};
use u6e_proto::shaper::Netdev;

pub trait Host {
    /// Runs `tc` with `args`: what it printed, or the first line of its
    /// complaint.
    fn tc(&mut self, args: &[String]) -> Result<String, String>;
    /// Runs the nftables script `script` as one transaction.
    fn nft(&mut self, script: &str) -> Result<(), String>;
    /// Writes `value` to the sysctl file `path`.
    fn sysctl(&mut self, path: &str, value: &str) -> Result<(), String>;
    /// The AP's netdevs now.
    fn netdevs(&mut self) -> Vec<Netdev>;
}

/// The AP.
pub struct System {
    pub tc: PathBuf,
    pub nft: PathBuf,
    pub net: PathBuf,
}

impl Default for System {
    fn default() -> Self {
        System {
            tc: "/usr/sbin/tc".into(),
            nft: "/usr/sbin/nft".into(),
            net: "/sys/class/net".into(),
        }
    }
}

impl Host for System {
    fn tc(&mut self, args: &[String]) -> Result<String, String> {
        let out = Command::new(&self.tc)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("tc: {e}"))?;
        if !out.status.success() {
            return Err(complaint(&out));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn nft(&mut self, script: &str) -> Result<(), String> {
        nft::run(&self.nft, script)
    }

    fn sysctl(&mut self, path: &str, value: &str) -> Result<(), String> {
        fs::write(path, value).map_err(|e| format!("{path}: {e}"))
    }

    fn netdevs(&mut self) -> Vec<Netdev> {
        let Ok(dir) = fs::read_dir(&self.net) else {
            return Vec::new();
        };
        let mut out: Vec<Netdev> = dir
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                let index = fs::read_to_string(e.path().join("ifindex")).ok()?;
                let ifindex = index.trim().parse().ok()?;
                Some(Netdev { name, ifindex })
            })
            .collect();
        out.sort();
        out
    }
}
