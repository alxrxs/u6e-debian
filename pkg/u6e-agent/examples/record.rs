//! Records what the collectors parse, as test fixtures: the raw nl80211
//! replies (interfaces, the stations of every AP interface, the survey of
//! every radio) and each hostapd's STATUS text, into one directory.
//!
//!   record <directory>
//!
//! Run it on an AP; anything that identifies the site is replaced before the
//! files are committed.

#![allow(dead_code)]

#[path = "../src/nl80211.rs"]
mod nl80211;

use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::time::Duration;
use std::{env, fs, process};

const HOSTAPD: &str = "/run/hostapd";

fn status(iface: &str, client: &Path) -> String {
    let _ = fs::remove_file(client);
    let Ok(sock) = UnixDatagram::bind(client) else {
        return String::new();
    };
    let _ = sock.set_read_timeout(Some(Duration::from_secs(1)));
    let _ = sock.send_to(b"STATUS", format!("{HOSTAPD}/{iface}"));
    let mut buf = vec![0; 65536];
    let n = sock.recv(&mut buf).unwrap_or(0);
    let _ = fs::remove_file(client);
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

fn run(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    let mut nl = nl80211::Nl80211::open()?;
    let raw = nl.dump_interfaces()?.to_vec();
    fs::write(dir.join("interfaces.bin"), &raw)?;
    let mut radios = Vec::new();
    for i in nl80211::parse_interfaces(&raw) {
        if i.kind != nl80211::IFTYPE_AP && i.kind != nl80211::IFTYPE_AP_VLAN {
            continue;
        }
        let stations = nl.dump_stations(i.ifindex)?;
        fs::write(dir.join(format!("station-{}.bin", i.name)), stations)?;
        if i.kind == nl80211::IFTYPE_AP {
            let text = status(&i.name, &dir.join("status.sock"));
            fs::write(dir.join(format!("status-{}.txt", i.name)), text)?;
            if !radios.contains(&i.wiphy) {
                radios.push(i.wiphy);
                let survey = nl.dump_survey(i.ifindex)?;
                fs::write(dir.join(format!("survey-{}.bin", i.phy())), survey)?;
            }
        }
    }
    Ok(())
}

fn main() {
    let Some(dir) = env::args().nth(1) else {
        eprintln!("usage: record <directory>");
        process::exit(2);
    };
    if let Err(e) = run(Path::new(&dir)) {
        eprintln!("record: {e}");
        process::exit(1);
    }
}
