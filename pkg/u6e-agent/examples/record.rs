//! Records what the collectors parse, as test fixtures: the raw nl80211
//! replies (interfaces, the stations of every AP interface, the survey of
//! every radio), each hostapd's STATUS text and a part of ECM's connection
//! dump, into one directory.
//!
//!   record <directory>
//!
//! Run it on an AP. What identifies the site is replaced as it is written:
//! every MAC by 02:00:00:00:00:NN, every IP address by one of 192.0.2.0/24
//! or 2001:db8::/64 and every SSID by ssid-a, ssid-b, ... in the order first
//! seen, and the regulatory country by 00.

#![allow(dead_code)]

#[path = "../src/nl80211.rs"]
mod nl80211;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::time::Duration;
use std::{env, fs, process};

use u6e_proto::mac;

const HOSTAPD: &str = "/run/hostapd";
const ECM: &str = "/dev/ecm_state";
/// The connections of the ECM fixture: the newest, and the newest one the
/// hardware does not forward.
const ECM_CONNS: usize = 12;
const ATTR_MAC: u16 = 6;
const ATTR_SSID: u16 = 52;
const NLA_TYPE_MASK: u16 = 0x3fff;

/// The stand-ins handed out so far, so one MAC or SSID keeps its stand-in
/// across the files.
#[derive(Default)]
struct Scrub {
    macs: Vec<Vec<u8>>,
    ssids: Vec<Vec<u8>>,
    ips: Vec<Vec<u8>>,
}

impl Scrub {
    fn mac(&mut self, m: &[u8]) -> [u8; 6] {
        [2, 0, 0, 0, 0, index(&mut self.macs, m) as u8 + 1]
    }

    /// A documentation address of the same family; the unspecified one
    /// stays.
    fn ip(&mut self, a: IpAddr) -> IpAddr {
        if a.is_unspecified() {
            return a;
        }
        let octets = match a {
            IpAddr::V4(v) => v.octets().to_vec(),
            IpAddr::V6(v) => v.octets().to_vec(),
        };
        let n = u8::try_from(index(&mut self.ips, &octets) + 1).expect("at most 255 addresses");
        match a {
            IpAddr::V4(_) => Ipv4Addr::new(192, 0, 2, n).into(),
            IpAddr::V6(_) => Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, n.into()).into(),
        }
    }

    /// An ECM dump with every MAC and IP address replaced, written as ECM
    /// writes them; the zero MAC stays.
    fn ecm(&mut self, text: &str) -> String {
        let mut out = String::new();
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                out += &format!("{line}\n");
                continue;
            };
            let value = if let Some(m) = mac::parse(value).filter(|m| *m != [0; 6]) {
                mac::format(self.mac(&m))
            } else if let Ok(a) = value.parse::<IpAddr>() {
                match self.ip(a) {
                    IpAddr::V4(v) => v.to_string(),
                    IpAddr::V6(v) => v.segments().map(|g| format!("{g:04x}")).join(":"),
                }
            } else {
                value.to_owned()
            };
            out += &format!("{key}={value}\n");
        }
        out
    }

    fn ssid(&mut self, s: &[u8]) -> Vec<u8> {
        format!("ssid-{}", (b'a' + index(&mut self.ssids, s) as u8) as char).into_bytes()
    }

    /// A dump with the MAC and SSID of each record replaced, every other
    /// byte as the kernel sent it.
    fn dump(&mut self, mut raw: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(len) = raw.first_chunk().map(|l| u32::from_ne_bytes(*l) as usize) {
            if len < 20 || len > raw.len() {
                break;
            }
            let m = &raw[..len];
            let mut body = m[16..20].to_vec();
            let mut attrs = &m[20..];
            while attrs.len() >= 4 {
                let alen = usize::from(u16::from_ne_bytes([attrs[0], attrs[1]]));
                if alen < 4 || alen > attrs.len() {
                    break;
                }
                let ty = u16::from_ne_bytes([attrs[2], attrs[3]]);
                let data = &attrs[4..alen];
                let data = match ty & NLA_TYPE_MASK {
                    ATTR_MAC => self.mac(data).to_vec(),
                    ATTR_SSID => self.ssid(data),
                    _ => data.to_vec(),
                };
                body.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
                body.extend_from_slice(&ty.to_ne_bytes());
                body.extend_from_slice(&data);
                body.resize(body.len().next_multiple_of(4), 0);
                attrs = &attrs[alen.next_multiple_of(4).min(attrs.len())..];
            }
            out.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
            out.extend_from_slice(&m[4..16]);
            out.extend_from_slice(&body);
            raw = &raw[len.next_multiple_of(4).min(raw.len())..];
        }
        out
    }

    /// A STATUS text with its BSSIDs, SSIDs and country replaced.
    fn status(&mut self, text: &str) -> String {
        let mut out = String::new();
        for line in text.lines() {
            let (key, value) = line.split_once('=').unwrap_or((line, ""));
            let value = if key.starts_with("bssid[") {
                let m = mac::parse(value).unwrap_or_default();
                mac::format(self.mac(&m))
            } else if key.starts_with("ssid[") {
                String::from_utf8_lossy(&self.ssid(value.as_bytes())).into_owned()
            } else if key == "country_code" {
                "00".to_owned()
            } else {
                value.to_owned()
            };
            out += &if line.contains('=') {
                format!("{key}={value}\n")
            } else {
                format!("{line}\n")
            };
        }
        out
    }
}

/// The position of `v` in `seen`, added at the end if new.
fn index(seen: &mut Vec<Vec<u8>>, v: &[u8]) -> usize {
    seen.iter().position(|s| s == v).unwrap_or_else(|| {
        seen.push(v.to_vec());
        seen.len() - 1
    })
}

/// The connections of an ECM dump the fixture keeps, whole: the first
/// [`ECM_CONNS`] (ECM lists the newest first) and the first the hardware
/// does not forward.
fn ecm_part(dump: &str) -> String {
    let serial = |l: &str| {
        l.strip_prefix("conns.conn.")?
            .split_once('.')
            .map(|(s, _)| s.to_owned())
    };
    let mut records: Vec<Vec<&str>> = Vec::new();
    for line in dump.lines() {
        let same = records.last().and_then(|r| serial(r[0])) == serial(line);
        match records.last_mut() {
            Some(r) if same => r.push(line),
            _ => records.push(vec![line]),
        }
    }
    let forwarded = |r: &Vec<&str>| r.iter().any(|l| l.ends_with(".accel_mode=2"));
    let slow = records.iter().position(|r| !forwarded(r));
    let mut out = String::new();
    for (i, r) in records.iter().enumerate() {
        if i < ECM_CONNS || Some(i) == slow {
            for l in r {
                out += l;
                out.push('\n');
            }
        }
    }
    out
}

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
    let mut scrub = Scrub::default();
    let mut nl = nl80211::Nl80211::open()?;
    let raw = nl.dump_interfaces()?.to_vec();
    fs::write(dir.join("interfaces.bin"), scrub.dump(&raw))?;
    let mut radios = Vec::new();
    for i in nl80211::parse_interfaces(&raw) {
        if i.kind != nl80211::IFTYPE_AP && i.kind != nl80211::IFTYPE_AP_VLAN {
            continue;
        }
        let stations = scrub.dump(nl.dump_stations(i.ifindex)?);
        fs::write(dir.join(format!("station-{}.bin", i.name)), stations)?;
        if i.kind == nl80211::IFTYPE_AP {
            let text = scrub.status(&status(&i.name, &dir.join("status.sock")));
            fs::write(dir.join(format!("status-{}.txt", i.name)), text)?;
            if !radios.contains(&i.wiphy) {
                radios.push(i.wiphy);
                let survey = nl.dump_survey(i.ifindex)?;
                fs::write(dir.join(format!("survey-wiphy{}.bin", i.wiphy)), survey)?;
            }
        }
    }
    let dump = fs::read_to_string(ECM)?;
    fs::write(dir.join("ecm-state.txt"), scrub.ecm(&ecm_part(&dump)))?;
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
