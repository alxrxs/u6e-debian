//! The kernel log, read through /dev/kmsg without blocking: the Wi-Fi
//! firmware crash records, and the phy each one belongs to.

use std::fs::{self, File};
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const O_NONBLOCK: i32 = 0o4000;
/// ath11k's report of a PCI radio's crash.
const CRASH: &str = "firmware crashed";
/// remoteproc's report of a remote processor's crash, which for the SoC's
/// own radio is its firmware's.
const RPROC_CRASH: &str = "crash detected in ";

pub struct Kmsg {
    path: PathBuf,
    new_only: bool,
    file: Option<File>,
    buf: Vec<u8>,
}

impl Kmsg {
    /// Opens the log at its oldest record, or past the newest with `new_only`.
    /// An unreadable log reads as empty and is opened again at the next
    /// `drain`.
    pub fn open(path: &Path, new_only: bool) -> Self {
        let mut k = Kmsg {
            path: path.to_owned(),
            new_only,
            file: None,
            buf: vec![0; 8192],
        };
        k.file = k.try_open();
        k
    }

    fn try_open(&self) -> Option<File> {
        let mut f = fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_NONBLOCK)
            .open(&self.path)
            .ok()?;
        if self.new_only {
            f.seek(SeekFrom::End(0)).ok()?;
        }
        Some(f)
    }

    /// The messages logged since the last call. A record is "<prefix>;<message>"
    /// and continuation lines (the device properties) start with a space.
    pub fn drain(&mut self) -> Vec<String> {
        if self.file.is_none() {
            self.file = self.try_open();
        }
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
    msg.contains(CRASH) || msg.contains(RPROC_CRASH)
}

/// The phy whose firmware a crash message is about: for a PCI radio, the
/// one whose `device` is the device the message names ("ath11k_pci
/// 0000:01:00.0: firmware crashed: ..."); for the SoC's radio, the one whose
/// remote processor is the one that crashed or runs under it ("remoteproc
/// remoteproc0: crash detected in cd00000.remoteproc: ...").
pub fn crashed_phy(sys: &Path, msg: &str) -> Option<String> {
    if let Some((head, _)) = msg.split_once(&format!(": {CRASH}")) {
        let dev = head.split_whitespace().next_back()?;
        return phy_where(sys, |device| {
            fs::read_link(device).is_ok_and(|l| l.file_name().is_some_and(|n| n == dev))
        });
    }
    let name = msg.split_once(RPROC_CRASH)?.1.split(':').next()?;
    let crashed = remoteprocs(sys).find(|(n, _)| n == name)?.1;
    phy_where(sys, |device| {
        let Ok(handle) = fs::read(device.join("of_node/qcom,rproc")) else {
            return false;
        };
        remoteprocs(sys).any(|(_, d)| {
            d.starts_with(&crashed)
                && fs::read(d.join("of_node/phandle")).is_ok_and(|h| h == handle)
        })
    })
}

/// The first phy whose `device` link `matches`.
fn phy_where(sys: &Path, matches: impl Fn(&Path) -> bool) -> Option<String> {
    fs::read_dir(sys.join("class/ieee80211"))
        .ok()?
        .flatten()
        .find(|e| matches(&e.path().join("device")))
        .map(|e| e.file_name().to_string_lossy().into_owned())
}

/// Every remote processor as (name, real path of its device).
fn remoteprocs(sys: &Path) -> impl Iterator<Item = (String, PathBuf)> {
    fs::read_dir(sys.join("class/remoteproc"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = fs::read_to_string(e.path().join("name")).ok()?;
            let device = fs::canonicalize(e.path().join("device")).ok()?;
            Some((name.trim().to_owned(), device))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;
    use std::io::Write;
    use std::os::unix::fs::symlink;

    const PCI: &str = "4,812,5550000,-;ath11k_pci 0000:01:00.0: firmware crashed: MHI_CB_EE_RDDM\n SUBSYSTEM=pci\n DEVICE=+pci:0000:01:00.0\n";
    const SOC: &str = "3,813,5560000,-;remoteproc remoteproc0: crash detected in cd00000.remoteproc: type fatal error\n";

    fn sys(t: &TestDir) -> std::path::PathBuf {
        for (phy, dev) in [("phy0", "c000000.wifi"), ("phy1", "0000:01:00.0")] {
            let d = t.path().join("class/ieee80211").join(phy);
            fs::create_dir_all(&d).unwrap();
            symlink(format!("../../../{dev}"), d.join("device")).unwrap();
        }
        t.path().to_owned()
    }

    #[test]
    fn a_pci_radio_crash_maps_to_the_phy_of_its_device() {
        let t = TestDir::new();
        let sys = sys(&t);
        let msg = PCI.split_once(';').unwrap().1.lines().next().unwrap();
        assert_eq!(crashed_phy(&sys, msg).as_deref(), Some("phy1"));
        assert_eq!(
            crashed_phy(&sys, "ath11k_pci 0000:09:00.0: firmware crashed"),
            None
        );
        assert!(is_fw_crash(msg) && !is_fw_crash("ath11k_pci 0000:01:00.0: recovered"));
    }

    /// The SoC's own radio runs its firmware on a remote processor, in a
    /// user PD under the root PD: remoteproc reports the crash, by name.
    #[test]
    fn a_remote_processor_crash_maps_to_the_radio_it_runs() {
        let t = TestDir::new();
        let sys = t.path();
        let soc = sys.join("devices/soc");
        let (wifi, root) = (soc.join("c000000.wifi"), soc.join("cd00000.remoteproc"));
        let user = root.join("pd-1");
        for d in [wifi.join("of_node"), user.join("of_node")] {
            fs::create_dir_all(d).unwrap();
        }
        fs::write(wifi.join("of_node/qcom,rproc"), [0, 0, 0, 0x29]).unwrap();
        fs::write(user.join("of_node/phandle"), [0, 0, 0, 0x29]).unwrap();
        let phy = sys.join("class/ieee80211/phy0");
        fs::create_dir_all(&phy).unwrap();
        symlink("../../../devices/soc/c000000.wifi", phy.join("device")).unwrap();
        for (n, name, dev) in [(0, "cd00000.remoteproc", ""), (1, "pd-1", "/pd-1")] {
            let r = sys.join(format!("class/remoteproc/remoteproc{n}"));
            fs::create_dir_all(&r).unwrap();
            fs::write(r.join("name"), format!("{name}\n")).unwrap();
            symlink(
                format!("../../../devices/soc/cd00000.remoteproc{dev}"),
                r.join("device"),
            )
            .unwrap();
        }
        let root_pd =
            "remoteproc remoteproc0: crash detected in cd00000.remoteproc: type fatal error";
        let user_pd = "remoteproc remoteproc1: crash detected in pd-1: type fatal error";
        for msg in [root_pd, user_pd] {
            assert!(is_fw_crash(msg), "{msg}");
            assert_eq!(crashed_phy(sys, msg).as_deref(), Some("phy0"), "{msg}");
        }
        assert!(!is_fw_crash(
            "remoteproc remoteproc0: handling crash #1 in cd00000.remoteproc"
        ));
        let other = "remoteproc remoteproc2: crash detected in modem: type watchdog";
        assert_eq!(crashed_phy(sys, other), None);
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
            .write_all(SOC.as_bytes())
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
