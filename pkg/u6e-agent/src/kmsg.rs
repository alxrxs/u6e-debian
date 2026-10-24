//! The kernel log, read through /dev/kmsg without blocking: the Wi-Fi
//! firmware crash records, and the phy each one belongs to.

use std::fs::{self, File};
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

const O_NONBLOCK: i32 = 0o4000;
const CRASH: &str = "firmware crashed";

pub struct Kmsg {
    file: Option<File>,
    buf: Vec<u8>,
}

impl Kmsg {
    /// Opens the log at its oldest record, or past the newest with `new_only`.
    /// An unreadable log reads as empty.
    pub fn open(path: &Path, new_only: bool) -> Self {
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_NONBLOCK)
            .open(path)
            .ok()
            .and_then(|mut f| {
                if new_only {
                    f.seek(SeekFrom::End(0)).ok()?;
                }
                Some(f)
            });
        Kmsg {
            file,
            buf: vec![0; 8192],
        }
    }

    /// The messages logged since the last call. A record is "<prefix>;<message>"
    /// and continuation lines (the device properties) start with a space.
    pub fn drain(&mut self) -> Vec<String> {
        let Some(file) = &mut self.file else {
            return Vec::new();
        };
        let mut out = Vec::new();
        loop {
            match file.read(&mut self.buf) {
                Ok(0) => break,
                Ok(n) => out.extend(
                    String::from_utf8_lossy(&self.buf[..n])
                        .lines()
                        .filter(|l| !l.starts_with(' '))
                        .map(|l| l.split_once(';').map_or(l, |(_, m)| m).to_owned()),
                ),
                // A record overwritten while we read it.
                Err(e) if e.kind() == ErrorKind::BrokenPipe => continue,
                Err(_) => break,
            }
        }
        out
    }
}

/// Whether a message reports a firmware crash.
pub fn is_fw_crash(msg: &str) -> bool {
    msg.contains(CRASH)
}

/// The phy of the device a crash message names ("ath11k_pci 0000:01:00.0:
/// firmware crashed: ..."): the one whose sysfs `device` link ends in it.
pub fn crashed_phy(sys: &Path, msg: &str) -> Option<String> {
    let dev = msg
        .split_once(&format!(": {CRASH}"))?
        .0
        .split_whitespace()
        .next_back()?;
    fs::read_dir(sys.join("class/ieee80211"))
        .ok()?
        .flatten()
        .find(|e| {
            fs::read_link(e.path().join("device"))
                .is_ok_and(|l| l.file_name().is_some_and(|n| n == dev))
        })
        .map(|e| e.file_name().to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;
    use std::io::Write;
    use std::os::unix::fs::symlink;

    const PCI: &str = "4,812,5550000,-;ath11k_pci 0000:01:00.0: firmware crashed: MHI_CB_EE_RDDM\n SUBSYSTEM=pci\n DEVICE=+pci:0000:01:00.0\n";
    const AHB: &str = "4,813,5560000,-;ath11k c000000.wifi: firmware crashed: MHI_CB_EE_RDDM\n";

    fn sys(t: &TestDir) -> std::path::PathBuf {
        for (phy, dev) in [("phy0", "c000000.wifi"), ("phy1", "0000:01:00.0")] {
            let d = t.path().join("class/ieee80211").join(phy);
            fs::create_dir_all(&d).unwrap();
            symlink(format!("../../../{dev}"), d.join("device")).unwrap();
        }
        t.path().to_owned()
    }

    #[test]
    fn crashes_map_to_the_phy_of_their_device() {
        let t = TestDir::new();
        let sys = sys(&t);
        let msg = PCI.split_once(';').unwrap().1.lines().next().unwrap();
        assert_eq!(crashed_phy(&sys, msg).as_deref(), Some("phy1"));
        assert_eq!(
            crashed_phy(&sys, AHB.split_once(';').unwrap().1).as_deref(),
            Some("phy0")
        );
        assert_eq!(
            crashed_phy(&sys, "ath11k_pci 0000:09:00.0: firmware crashed"),
            None
        );
        assert!(is_fw_crash(msg) && !is_fw_crash("ath11k_pci 0000:01:00.0: recovered"));
    }

    #[test]
    fn reads_the_backlog_or_only_what_follows() {
        let t = TestDir::new();
        let log = t.path().join("kmsg");
        fs::write(&log, format!("{PCI}6,814,5570000,-;unrelated\n")).unwrap();
        let mut all = Kmsg::open(&log, false);
        let mut new = Kmsg::open(&log, true);
        let msgs = all.drain();
        assert_eq!(msgs.len(), 2);
        assert!(is_fw_crash(&msgs[0]) && msgs[1] == "unrelated");
        assert!(new.drain().is_empty());

        fs::OpenOptions::new()
            .append(true)
            .open(&log)
            .unwrap()
            .write_all(AHB.as_bytes())
            .unwrap();
        assert_eq!(new.drain().len(), 1);
        assert_eq!(all.drain().len(), 1);
        assert!(
            Kmsg::open(&t.path().join("absent"), true)
                .drain()
                .is_empty()
        );
    }
}
