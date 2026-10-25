//! A radio's spectral scan, through the debugfs files ath11k gives it under
//! the radio's stable wiphy name (`ieee80211/<radio>/ath11k/`): the FFT
//! size (`spectral_bins`), the samples per trigger (`spectral_count`), the
//! mode and trigger (`spectral_scan_ctl`) and the relay file the samples come
//! through (`spectral_scan0`). These are the only files the helper writes,
//! and only with the values here.
//!
//! The scan runs on the radio's own channel while it serves clients. ath11k's
//! `background` mode samples without end, about 2300 samples a second on a
//! busy 5 GHz radio, which costs the kernel a third of a core; `manual` mode
//! is the same scan, [`COUNT`] samples per trigger, so the helper triggers it
//! once per frame and the rate is its choice.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// The stable names are the only radios; a request naming anything else (a
/// path among them) is no request.
pub use u6e_proto::msg::{RADIOS, radio};

/// Where the radios' debugfs directories are.
pub const DEBUGFS: &str = "/sys/kernel/debug/ieee80211";

/// The FFT size: 512 points, of which the in-band 256 are reported, 285 B
/// a frame on the wire.
pub const FFT_BINS: u32 = 512;
/// Samples per trigger, one trigger per frame: 64 samples a second.
pub const COUNT: u32 = 8;

/// A radio whose scan runs: disabled when dropped.
pub struct Scan {
    pub radio: &'static str,
    ctl: File,
    pub relay: File,
}

impl Scan {
    /// Configures the scan of `radio` under `root` and triggers its first
    /// samples. Samples left in the relay file from before are read away
    /// first, so the first frame is of now.
    pub fn start(root: &Path, radio: &'static str) -> io::Result<Self> {
        let dir = root.join(radio).join("ath11k");
        let mut relay = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open(dir.join("spectral_scan0"))?;
        drain(&mut relay)?;
        let ctl = open(&dir, "spectral_scan_ctl")?;
        write(&mut open(&dir, "spectral_bins")?, &FFT_BINS.to_string())?;
        write(&mut open(&dir, "spectral_count")?, &COUNT.to_string())?;
        let mut scan = Scan { radio, ctl, relay };
        write(&mut scan.ctl, "manual")?;
        scan.trigger()?;
        Ok(scan)
    }

    /// The next [`COUNT`] samples. The driver refuses it once it has stopped
    /// the scan itself (it does when the radio's interface goes down).
    pub fn trigger(&mut self) -> io::Result<()> {
        write(&mut self.ctl, "trigger")
    }
}

impl Drop for Scan {
    fn drop(&mut self) {
        if let Err(e) = write(&mut self.ctl, "disable") {
            eprintln!("u6e-spectral: {}: disable: {e}", self.radio);
        }
    }
}

/// Disables the scan of every radio under `root` that is not disabled: the
/// unit's last step, whatever ended the helper.
pub fn disable_all(root: &Path) -> io::Result<()> {
    let mut result = Ok(());
    for r in RADIOS {
        let dir = root.join(r).join("ath11k");
        let done = match mode(&dir) {
            Ok(m) if m == "disable" => Ok(()),
            Ok(_) => open(&dir, "spectral_scan_ctl").and_then(|mut f| write(&mut f, "disable")),
            // A radio that is not there scans nothing.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        };
        if let Err(e) = done {
            eprintln!("u6e-spectral: {r}: disable: {e}");
            result = Err(e);
        }
    }
    result
}

/// The mode `spectral_scan_ctl` reads.
pub fn mode(dir: &Path) -> io::Result<String> {
    let mut s = String::new();
    File::open(dir.join("spectral_scan_ctl"))?.read_to_string(&mut s)?;
    // A test's control file is the log of what was written to it.
    Ok(s.lines().last().unwrap_or_default().to_owned())
}

/// A control file, for writing. Appending changes nothing on debugfs, and
/// leaves a test's file the log of every write.
fn open(dir: &Path, file: &str) -> io::Result<File> {
    OpenOptions::new()
        .append(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dir.join(file))
}

/// One write of `value` and a newline, as `echo` does.
fn write(f: &mut File, value: &str) -> io::Result<()> {
    f.write_all(format!("{value}\n").as_bytes())
}

/// Reads away what the relay file holds; it ends, as a disabled scan writes
/// nothing more.
fn drain(relay: &mut File) -> io::Result<()> {
    let mut buf = vec![0; 64 << 10];
    for _ in 0..64 {
        match relay.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::fs;

    const FILES: [&str; 4] = [
        "spectral_bins",
        "spectral_count",
        "spectral_scan_ctl",
        "spectral_scan0",
    ];

    /// A debugfs tree of the three radios, every file empty.
    pub fn tree(root: &Path) {
        for r in RADIOS {
            let dir = root.join(r).join("ath11k");
            fs::create_dir_all(&dir).unwrap();
            for f in FILES {
                fs::write(dir.join(f), "").unwrap();
            }
        }
    }

    /// Everything written to `radio`'s control files: the FFT size and
    /// count, then the modes and triggers in order.
    pub fn writes(root: &Path, radio: &str) -> String {
        let dir = root.join(radio).join("ath11k");
        FILES[..3]
            .iter()
            .map(|f| fs::read_to_string(dir.join(f)).unwrap())
            .collect()
    }

    #[test]
    fn only_the_stable_names_are_radios() {
        assert_eq!(radio("radio5"), Some("radio5"));
        for bad in [
            "",
            "radio",
            "radio7",
            "../radio5",
            "radio5/",
            "radio5\nstart radio6",
            "phy0",
            "RADIO5",
        ] {
            assert_eq!(radio(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_scan_is_configured_triggered_and_disabled_when_dropped() {
        let t = crate::testdir::TestDir::new();
        tree(t.path());
        let relay = t.path().join("radio5/ath11k/spectral_scan0");
        fs::write(&relay, [1; 100]).unwrap();
        let mut scan = Scan::start(t.path(), "radio5").unwrap();
        assert_eq!(writes(t.path(), "radio5"), "512\n8\nmanual\ntrigger\n");
        // What was there before the scan is read away.
        assert_eq!(scan.relay.read(&mut [0; 10]).unwrap(), 0);
        scan.trigger().unwrap();
        drop(scan);
        assert_eq!(
            writes(t.path(), "radio5"),
            "512\n8\nmanual\ntrigger\ntrigger\ndisable\n"
        );
        assert_eq!(writes(t.path(), "radio24"), "");
    }

    #[test]
    fn a_missing_radio_is_an_error_and_nothing_is_written() {
        let t = crate::testdir::TestDir::new();
        tree(t.path());
        fs::remove_file(t.path().join("radio6/ath11k/spectral_scan0")).unwrap();
        assert!(Scan::start(t.path(), "radio6").is_err());
        assert_eq!(writes(t.path(), "radio6"), "");
    }

    #[test]
    fn disable_all_writes_only_where_a_scan_runs() {
        let t = crate::testdir::TestDir::new();
        tree(t.path());
        fs::remove_dir_all(t.path().join("radio24")).unwrap();
        let ctl = |r: &str| t.path().join(r).join("ath11k/spectral_scan_ctl");
        fs::write(ctl("radio5"), "manual\ntrigger\n").unwrap();
        fs::write(ctl("radio6"), "disable\n").unwrap();
        disable_all(t.path()).unwrap();
        assert_eq!(writes(t.path(), "radio5"), "manual\ntrigger\ndisable\n");
        assert_eq!(writes(t.path(), "radio6"), "disable\n");
    }
}
