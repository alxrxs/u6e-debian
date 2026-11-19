//! How a capture takes a client's flows from the NSS offload, and how it
//! gives them back.
//!
//! With `u6e-pcc` loaded (the image's `U6E_PCC=1`) and its mirror netdev up,
//! the client's TCP and UDP connections are accelerated again with an NSS
//! mirror rule: they stay offloaded and the NSS copies each packet, cut at
//! the snaplen, to the mirror netdev. Otherwise the capture takes them off
//! the offload: ECM stops accelerating new connections (both address
//! families) and the client's connections are decelerated, so all of its
//! traffic reaches the host's Wi-Fi ports, where the capture reads it; every
//! other client's new connections stay on the CPU until it ends.
//!
//! Before it changes anything, a capture writes what it is about to change
//! as it is (the restore file); a restore writes those values back, in that
//! order, and removes the file only once all of them are back. Whatever
//! ends the helper, its unit's last step restores (`u6e-capture restore`),
//! and the next capture restores a file left behind before it takes
//! anything. A restore writes only the files it knows.

use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;

use u6e_proto::capture::RESTORE;
use u6e_proto::ecm::{DEFUNCT_BY_MAC, STOP};
use u6e_proto::mac;
use u6e_proto::msg::CaptureMechanism;

/// `u6e-pcc`'s files: its target client and its snaplen.
pub const PCC_TARGET: &str = "/sys/kernel/debug/u6e-pcc/target";
pub const PCC_SNAPLEN: &str = "/sys/kernel/debug/u6e-pcc/snaplen";
/// The NSS mirror netdev `u6e-nss` creates for `u6e-pcc`.
pub const MIRROR: &str = "mirror.0";

/// The files a restore may write.
const RESTORABLE: [&str; 4] = [PCC_TARGET, PCC_SNAPLEN, STOP[0], STOP[1]];

/// Where the files are: `/` on an AP, a scratch tree in the tests.
#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
}

impl Paths {
    pub fn at(&self, path: &str) -> PathBuf {
        self.root.join(&path[1..])
    }

    fn read(&self, path: &str) -> Result<String, String> {
        let v = fs::read_to_string(self.at(path)).map_err(|e| format!("{path}: {e}"))?;
        Ok(v.trim().to_owned())
    }

    fn write(&self, path: &str, value: &str) -> Result<(), String> {
        fs::write(self.at(path), format!("{value}\n")).map_err(|e| format!("{path}: {e}"))
    }
}

/// How a capture on this AP takes the flows: by the mirror where the image
/// loads `u6e-pcc` and its netdev exists (`mirror` says whether it does).
pub fn mechanism(paths: &Paths, mirror: bool) -> CaptureMechanism {
    if mirror && paths.at(PCC_TARGET).exists() {
        CaptureMechanism::Mirror
    } else {
        CaptureMechanism::OffOffload
    }
}

/// Takes the client `mac`'s flows by `how`, the restore file written first;
/// on a failure part way, what was changed is put back.
pub fn take(
    paths: &Paths,
    how: CaptureMechanism,
    mac: [u8; 6],
    snaplen: u16,
) -> Result<(), String> {
    let (saved, steps): (Vec<&str>, Vec<(&str, String)>) = match how {
        CaptureMechanism::Mirror => (
            vec![PCC_TARGET, PCC_SNAPLEN],
            vec![
                (PCC_SNAPLEN, snaplen.to_string()),
                (PCC_TARGET, mac::format(mac)),
            ],
        ),
        CaptureMechanism::OffOffload => (
            STOP.to_vec(),
            vec![
                (STOP[0], "1".into()),
                (STOP[1], "1".into()),
                (DEFUNCT_BY_MAC, mac::format(mac)),
            ],
        ),
    };
    let mut file = String::new();
    for p in saved {
        let v = paths.read(p)?;
        if p == PCC_TARGET && v != "none" {
            return Err(format!("the mirror already follows {v}"));
        }
        file += &format!("{p} {v}\n");
    }
    let restore = paths.at(RESTORE);
    let temp = restore.with_extension("new");
    fs::write(&temp, &file)
        .and_then(|()| fs::rename(&temp, &restore))
        .map_err(|e| format!("{RESTORE}: {e}"))?;
    for (p, v) in steps {
        if let Err(e) = paths.write(p, &v) {
            if let Err(r) = restore_from(paths) {
                return Err(format!("{e}; and putting back: {r}"));
            }
            return Err(e);
        }
    }
    Ok(())
}

/// Puts back what the restore file holds, if there is one; whether there
/// was. The file stays until every value is back.
pub fn restore_from(paths: &Paths) -> Result<bool, String> {
    let file = paths.at(RESTORE);
    let text = match fs::read_to_string(&file) {
        Ok(t) => t,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(format!("{RESTORE}: {e}")),
    };
    let mut failed = Vec::new();
    for line in text.lines() {
        let Some((p, v)) = line.split_once(' ') else {
            continue;
        };
        let Some(p) = RESTORABLE.iter().find(|r| **r == p) else {
            failed.push(format!("{p}: not a file a capture changes"));
            continue;
        };
        if let Err(e) = paths.write(p, v) {
            failed.push(e);
        }
    }
    if !failed.is_empty() {
        return Err(failed.join("; "));
    }
    fs::remove_file(&file).map_err(|e| format!("{RESTORE}: {e}"))?;
    Ok(true)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::testdir::TestDir;

    /// The AP's files as a capture finds them: ECM running, `u6e-pcc`
    /// loaded or not.
    pub fn ap(t: &TestDir, pcc: bool) -> Paths {
        let p = Paths {
            root: t.path().into(),
        };
        for f in [STOP[0], STOP[1], DEFUNCT_BY_MAC, RESTORE] {
            fs::create_dir_all(p.at(f).parent().unwrap()).unwrap();
        }
        fs::write(p.at(STOP[0]), "0\n").unwrap();
        fs::write(p.at(STOP[1]), "0\n").unwrap();
        fs::write(p.at(DEFUNCT_BY_MAC), "").unwrap();
        if pcc {
            fs::create_dir_all(p.at(PCC_TARGET).parent().unwrap()).unwrap();
            fs::write(p.at(PCC_TARGET), "none\n").unwrap();
            fs::write(p.at(PCC_SNAPLEN), "128\n").unwrap();
        }
        p
    }

    pub fn read(p: &Paths, f: &str) -> String {
        fs::read_to_string(p.at(f)).unwrap()
    }

    /// Whether the restore file exists.
    pub fn pending(p: &Paths) -> bool {
        p.at(RESTORE).exists()
    }

    const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];

    #[test]
    fn off_the_offload_and_back() {
        let t = TestDir::new();
        let p = ap(&t, false);
        assert_eq!(mechanism(&p, true), CaptureMechanism::OffOffload);
        take(&p, CaptureMechanism::OffOffload, MAC, 128).unwrap();
        assert_eq!(
            (read(&p, STOP[0]), read(&p, STOP[1])),
            ("1\n".into(), "1\n".into())
        );
        assert_eq!(read(&p, DEFUNCT_BY_MAC), "02:00:00:00:00:01\n");
        assert!(pending(&p));
        assert_eq!(restore_from(&p), Ok(true));
        assert_eq!(
            (read(&p, STOP[0]), read(&p, STOP[1])),
            ("0\n".into(), "0\n".into())
        );
        assert!(!pending(&p));
        // Twice is harmless.
        assert_eq!(restore_from(&p), Ok(false));
    }

    #[test]
    fn the_mirror_and_back() {
        let t = TestDir::new();
        let p = ap(&t, true);
        assert_eq!(mechanism(&p, true), CaptureMechanism::Mirror);
        assert_eq!(mechanism(&p, false), CaptureMechanism::OffOffload);
        take(&p, CaptureMechanism::Mirror, MAC, 300).unwrap();
        assert_eq!(
            (read(&p, PCC_SNAPLEN), read(&p, PCC_TARGET)),
            ("300\n".into(), "02:00:00:00:00:01\n".into())
        );
        // ECM is left alone.
        assert_eq!(read(&p, STOP[0]), "0\n");
        assert_eq!(restore_from(&p), Ok(true));
        assert_eq!(
            (read(&p, PCC_TARGET), read(&p, PCC_SNAPLEN)),
            ("none\n".into(), "128\n".into())
        );
        // A mirror that follows a client already is not taken from it.
        fs::write(p.at(PCC_TARGET), "02:00:00:00:00:09\n").unwrap();
        assert!(take(&p, CaptureMechanism::Mirror, MAC, 300).is_err());
        assert!(!pending(&p));
    }

    #[test]
    fn a_failed_step_puts_back_what_it_changed() {
        let t = TestDir::new();
        let p = ap(&t, false);
        // The deceleration file is gone: its write fails after the stops.
        fs::remove_file(p.at(DEFUNCT_BY_MAC)).unwrap();
        fs::create_dir(p.at(DEFUNCT_BY_MAC)).unwrap();
        assert!(take(&p, CaptureMechanism::OffOffload, MAC, 128).is_err());
        assert_eq!(
            (read(&p, STOP[0]), read(&p, STOP[1])),
            ("0\n".into(), "0\n".into())
        );
        assert!(!pending(&p));
    }

    #[test]
    fn a_restore_writes_only_what_a_capture_changes_and_keeps_its_file_until_done() {
        let t = TestDir::new();
        let p = ap(&t, false);
        fs::write(p.at(RESTORE), format!("/etc/passwd x\n{} 0\n", STOP[0])).unwrap();
        fs::write(p.at(STOP[0]), "1\n").unwrap();
        assert!(restore_from(&p).is_err());
        assert_eq!(read(&p, STOP[0]), "0\n", "the rest is put back");
        assert!(pending(&p), "the file stays: the alert keeps it seen");
    }
}
