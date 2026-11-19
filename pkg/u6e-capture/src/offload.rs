//! How a capture takes a client's flows from the NSS offload, and how it
//! gives them back.
//!
//! With `u6e-pcc` loaded (the image's `U6E_PCC=1`) and its mirror netdev up,
//! the client's TCP and UDP connections are accelerated again with an NSS
//! mirror rule: they stay offloaded and the NSS copies each packet, cut at
//! the snaplen, to the mirror netdev. Otherwise the capture takes the
//! client's flows, and no other client's, off the offload: a nftables table
//! marks its frames both ways ([`NO_ACCEL_MARK`], which the image's ECM
//! keeps off the NSS) and its connections are decelerated, so all of its
//! traffic reaches the host's Wi-Fi ports, where the capture reads it.
//!
//! Before it changes anything, a capture writes what it is about to change
//! (the restore file); a restore puts those back, in that order, and removes
//! the file only once all of them are. Whatever ends the helper, its unit's
//! last step restores (`u6e-capture restore`), and the next capture restores
//! a file left behind before it takes anything. A restore changes only what
//! a capture changes.

use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;

use u6e_proto::capture::RESTORE;
use u6e_proto::ecm::{DEFUNCT_BY_MAC, NO_ACCEL_MARK};
use u6e_proto::msg::CaptureMechanism;
use u6e_proto::netdev::{vlan, wifi_port};
use u6e_proto::{mac, nft};

/// `u6e-pcc`'s files: its target client and its snaplen.
pub const PCC_TARGET: &str = "/sys/kernel/debug/u6e-pcc/target";
pub const PCC_SNAPLEN: &str = "/sys/kernel/debug/u6e-pcc/snaplen";
/// The NSS mirror netdev `u6e-nss` creates for `u6e-pcc`.
pub const MIRROR: &str = "mirror.0";
/// The table that marks the client's frames.
pub const TABLE: &str = "netdev u6e-capture";

/// The files a restore may write; a `client` line is the marks.
const RESTORABLE: [&str; 2] = [PCC_TARGET, PCC_SNAPLEN];
const CLIENT: &str = "client";

/// Where the files are (`/` on an AP, a scratch tree in the tests) and the
/// `nft` the marks are made with.
#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
    pub nft: PathBuf,
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

    fn nft(&self, script: &str) -> Result<(), String> {
        nft::run(&self.nft, script)
    }
}

/// The netdevs the client's frames are marked on: the Wi-Fi ports, which
/// its frames come in by, and the client VLANs', which frames to it do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Devs {
    pub ports: Vec<String>,
    pub vlans: Vec<String>,
}

impl Devs {
    /// Those among `names`.
    pub fn of<'a>(names: impl IntoIterator<Item = &'a str>) -> Devs {
        let mut d = Devs::default();
        for n in names {
            if wifi_port(n) {
                d.ports.push(n.into());
            } else if vlan(n) {
                d.vlans.push(n.into());
            }
        }
        d.ports.sort();
        d.vlans.sort();
        d
    }
}

/// The script that marks the client `mac`'s frames on `devs`.
pub fn marks(mac: [u8; 6], devs: &Devs) -> String {
    let m = mac::format(mac);
    let chain = |name: &str, devs: &[String], rule: String| {
        if devs.is_empty() {
            return String::new();
        }
        format!(
            "\tchain {name} {{\n\t\ttype filter hook ingress devices = {{ {} }} priority 0; policy accept;\n\t\t{rule}\n\t}}\n",
            nft::devices(devs)
        )
    };
    let body = chain(
        "up",
        &devs.ports,
        format!("ether saddr {m} meta mark set {NO_ACCEL_MARK:#x}"),
    ) + &chain(
        "down",
        &devs.vlans,
        format!("ether daddr {m} meta mark set {NO_ACCEL_MARK:#x}"),
    );
    nft::replace(TABLE, &body)
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

/// Takes the client `mac`'s flows by `how` (off the offload, its frames
/// marked on `devs`), the restore file written first; on a failure part
/// way, what was changed is put back.
pub fn take(
    paths: &Paths,
    how: CaptureMechanism,
    mac: [u8; 6],
    snaplen: u16,
    devs: &Devs,
) -> Result<(), String> {
    let m = mac::format(mac);
    let (file, steps): (String, Vec<Step>) = match how {
        CaptureMechanism::Mirror => {
            let mut file = String::new();
            for p in [PCC_TARGET, PCC_SNAPLEN] {
                let v = paths.read(p)?;
                if p == PCC_TARGET && v != "none" {
                    return Err(format!("the mirror already follows {v}"));
                }
                file += &format!("{p} {v}\n");
            }
            let steps = vec![
                Step::Write(PCC_SNAPLEN, snaplen.to_string()),
                Step::Write(PCC_TARGET, m),
            ];
            (file, steps)
        }
        CaptureMechanism::OffOffload => {
            if devs.ports.is_empty() {
                return Err("the client is on no Wi-Fi port".into());
            }
            let steps = vec![
                Step::Nft(marks(mac, devs)),
                Step::Write(DEFUNCT_BY_MAC, m.clone()),
            ];
            (format!("{CLIENT} {m}\n"), steps)
        }
    };
    let restore = paths.at(RESTORE);
    let temp = restore.with_extension("new");
    fs::write(&temp, &file)
        .and_then(|()| fs::rename(&temp, &restore))
        .map_err(|e| format!("{RESTORE}: {e}"))?;
    for step in steps {
        let done = match step {
            Step::Write(p, v) => paths.write(p, &v),
            Step::Nft(s) => paths.nft(&s),
        };
        if let Err(e) = done {
            if let Err(r) = restore_from(paths) {
                return Err(format!("{e}; and putting back: {r}"));
            }
            return Err(e);
        }
    }
    Ok(())
}

enum Step {
    Write(&'static str, String),
    Nft(String),
}

/// Marks the client `mac`'s frames on `devs` now, as the client's ports
/// change during a capture off the offload.
pub fn follow(paths: &Paths, mac: [u8; 6], devs: &Devs) -> Result<(), String> {
    paths.nft(&marks(mac, devs))
}

/// Puts back what the restore file holds, if there is one; whether there
/// was. The file stays until everything is back.
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
        if p == CLIENT {
            let Some(m) = mac::parse(v) else {
                failed.push(format!("{v}: not a client's MAC"));
                continue;
            };
            // The marks go first, so the client's connections, decelerated
            // once more, are accelerated again as any other's.
            failed.extend(paths.nft(&nft::replace(TABLE, "")).err());
            failed.extend(paths.write(DEFUNCT_BY_MAC, &mac::format(m)).err());
            continue;
        }
        let Some(p) = RESTORABLE.iter().find(|r| **r == p) else {
            failed.push(format!("{p}: not a file a capture changes"));
            continue;
        };
        failed.extend(paths.write(p, v).err());
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
    use std::os::unix::fs::PermissionsExt;

    /// ECM's switches that stop it accelerating any new connection, which
    /// a capture must leave alone.
    pub const STOP: [&str; 2] = [
        "/proc/sys/net/ecm/front_end_ipv4_stop",
        "/proc/sys/net/ecm/front_end_ipv6_stop",
    ];

    /// The AP's files as a capture finds them: ECM running, `u6e-pcc`
    /// loaded or not, and an `nft` that logs each script it is given
    /// (`nft.log`) and fails while `nft.fail` exists.
    pub fn ap(t: &TestDir, pcc: bool) -> Paths {
        let nft = t.path().join("nft");
        fs::write(
            &nft,
            "#!/bin/sh\nd=$(dirname \"$0\")\n[ -e \"$d/nft.fail\" ] && { echo 'Error: no' >&2; exit 1; }\ncat >> \"$d/nft.log\"\n",
        )
        .unwrap();
        fs::set_permissions(&nft, fs::Permissions::from_mode(0o755)).unwrap();
        let p = Paths {
            root: t.path().into(),
            nft,
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

    /// The scripts the fake `nft` was given, and forgets them.
    pub fn nft_log(p: &Paths) -> String {
        let log = p.root.join("nft.log");
        let s = fs::read_to_string(&log).unwrap_or_default();
        let _ = fs::remove_file(log);
        s
    }

    /// Whether the restore file exists.
    pub fn pending(p: &Paths) -> bool {
        p.at(RESTORE).exists()
    }

    const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];

    fn devs() -> Devs {
        Devs::of(["lan", "wlan5", "wlan6.42", "vlan42", "mirror.0"])
    }

    #[test]
    fn the_marks_name_the_client_on_its_ports_and_its_vlans() {
        assert_eq!(
            devs(),
            Devs {
                ports: vec!["wlan5".into(), "wlan6.42".into()],
                vlans: vec!["vlan42".into()],
            }
        );
        assert_eq!(
            marks(MAC, &devs()),
            "table netdev u6e-capture\ndelete table netdev u6e-capture\ntable netdev u6e-capture {\n\
             \tchain up {\n\t\ttype filter hook ingress devices = { \"wlan5\", \"wlan6.42\" } priority 0; policy accept;\n\
             \t\tether saddr 02:00:00:00:00:01 meta mark set 0x75360000\n\t}\n\
             \tchain down {\n\t\ttype filter hook ingress devices = { \"vlan42\" } priority 0; policy accept;\n\
             \t\tether daddr 02:00:00:00:00:01 meta mark set 0x75360000\n\t}\n}\n"
        );
        // No VLAN netdev: frames to the client are not marked, from it are.
        let d = Devs::of(["wlan5"]);
        assert!(!marks(MAC, &d).contains("chain down") && marks(MAC, &d).contains("chain up"));
    }

    #[test]
    fn off_the_offload_takes_only_the_client_and_gives_it_back() {
        let t = TestDir::new();
        let p = ap(&t, false);
        assert_eq!(mechanism(&p, true), CaptureMechanism::OffOffload);
        take(&p, CaptureMechanism::OffOffload, MAC, 128, &devs()).unwrap();
        // ECM goes on accelerating every other client's connections.
        assert_eq!(
            (read(&p, STOP[0]), read(&p, STOP[1])),
            ("0\n".into(), "0\n".into())
        );
        assert_eq!(nft_log(&p), marks(MAC, &devs()));
        assert_eq!(read(&p, DEFUNCT_BY_MAC), "02:00:00:00:00:01\n");
        assert!(pending(&p));
        fs::write(p.at(DEFUNCT_BY_MAC), "").unwrap();
        assert_eq!(restore_from(&p), Ok(true));
        assert_eq!(nft_log(&p), nft::replace(TABLE, ""));
        assert_eq!(read(&p, DEFUNCT_BY_MAC), "02:00:00:00:00:01\n");
        assert!(!pending(&p));
        // Twice is harmless.
        assert_eq!(restore_from(&p), Ok(false));
        // A client on no Wi-Fi port is not taken.
        assert!(take(&p, CaptureMechanism::OffOffload, MAC, 128, &Devs::default()).is_err());
        assert!(!pending(&p) && nft_log(&p).is_empty());
    }

    #[test]
    fn the_mirror_and_back() {
        let t = TestDir::new();
        let p = ap(&t, true);
        assert_eq!(mechanism(&p, true), CaptureMechanism::Mirror);
        assert_eq!(mechanism(&p, false), CaptureMechanism::OffOffload);
        take(&p, CaptureMechanism::Mirror, MAC, 300, &devs()).unwrap();
        assert_eq!(
            (read(&p, PCC_SNAPLEN), read(&p, PCC_TARGET)),
            ("300\n".into(), "02:00:00:00:00:01\n".into())
        );
        // ECM and the marks are left alone.
        assert_eq!(read(&p, STOP[0]), "0\n");
        assert!(nft_log(&p).is_empty());
        assert_eq!(restore_from(&p), Ok(true));
        assert_eq!(
            (read(&p, PCC_TARGET), read(&p, PCC_SNAPLEN)),
            ("none\n".into(), "128\n".into())
        );
        // A mirror that follows a client already is not taken from it.
        fs::write(p.at(PCC_TARGET), "02:00:00:00:00:09\n").unwrap();
        assert!(take(&p, CaptureMechanism::Mirror, MAC, 300, &devs()).is_err());
        assert!(!pending(&p));
    }

    #[test]
    fn a_failed_step_puts_back_what_it_changed() {
        let t = TestDir::new();
        let p = ap(&t, false);
        // The deceleration file is gone: its write fails after the marks.
        fs::remove_file(p.at(DEFUNCT_BY_MAC)).unwrap();
        fs::create_dir(p.at(DEFUNCT_BY_MAC)).unwrap();
        assert!(take(&p, CaptureMechanism::OffOffload, MAC, 128, &devs()).is_err());
        assert_eq!(
            nft_log(&p),
            marks(MAC, &devs()) + &nft::replace(TABLE, ""),
            "the marks are made, then removed"
        );
        // The deceleration that would have followed fails too: the file
        // stays, the alert keeps it seen.
        assert!(pending(&p));
        fs::remove_dir(p.at(DEFUNCT_BY_MAC)).unwrap();
        fs::write(p.at(DEFUNCT_BY_MAC), "").unwrap();
        assert_eq!(restore_from(&p), Ok(true));

        // nft refuses the marks: nothing else is changed.
        fs::write(t.path().join("nft.fail"), "").unwrap();
        let e = take(&p, CaptureMechanism::OffOffload, MAC, 128, &devs()).unwrap_err();
        assert!(e.starts_with("Error: no"), "{e}");
        assert_eq!(read(&p, DEFUNCT_BY_MAC), "02:00:00:00:00:01\n");
        assert!(pending(&p), "nft cannot remove the table either");
        fs::remove_file(t.path().join("nft.fail")).unwrap();
        assert_eq!(restore_from(&p), Ok(true));
        assert!(!pending(&p));
    }

    #[test]
    fn a_restore_changes_only_what_a_capture_changes_and_keeps_its_file_until_done() {
        let t = TestDir::new();
        let p = ap(&t, true);
        fs::write(
            p.at(RESTORE),
            format!("/etc/passwd x\nclient nonsense\n{PCC_TARGET} none\n"),
        )
        .unwrap();
        fs::write(p.at(PCC_TARGET), "02:00:00:00:00:01\n").unwrap();
        assert!(restore_from(&p).is_err());
        assert_eq!(read(&p, PCC_TARGET), "none\n", "the rest is put back");
        assert!(nft_log(&p).is_empty());
        assert!(pending(&p), "the file stays: the alert keeps it seen");
    }
}
