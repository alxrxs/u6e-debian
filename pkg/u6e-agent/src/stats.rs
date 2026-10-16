//! One line of the AP's state for the syslog collector: load, free memory, the
//! Wi-Fi firmware crashes so far, the stations of each BSS and the thermal
//! zones.

use std::fs;
use std::io::{ErrorKind, Read};
use std::os::unix::fs::OpenOptionsExt;

const O_NONBLOCK: i32 = 0o4000;

fn first_field(path: &str) -> String {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| Some(s.split_whitespace().next()?.to_owned()))
        .unwrap_or_default()
}

fn mem_available_kb() -> String {
    fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|m| {
            let l = m.lines().find(|l| l.starts_with("MemAvailable:"))?;
            Some(l.split_whitespace().nth(1)?.to_owned())
        })
        .unwrap_or_default()
}

/// The kernel log records (one per read of /dev/kmsg) that report a crash.
fn fw_crashes() -> usize {
    let Ok(mut kmsg) = fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK)
        .open("/dev/kmsg")
    else {
        return 0;
    };
    let (mut buf, mut n) = (vec![0; 8192], 0);
    loop {
        match kmsg.read(&mut buf) {
            Ok(0) => break,
            Ok(len) => n += usize::from(buf[..len].windows(17).any(|w| w == b"firmware crashed")),
            // A record overwritten while we read it.
            Err(e) if e.kind() == ErrorKind::BrokenPipe => continue,
            Err(_) => break,
        }
    }
    n
}

fn temps() -> String {
    let mut zones: Vec<_> = fs::read_dir("/sys/class/thermal")
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("thermal_zone"))
        })
        .collect();
    zones.sort();
    zones
        .iter()
        .map(|z| {
            let millic: i64 = first_field(&z.join("temp").to_string_lossy())
                .parse()
                .unwrap_or(0);
            format!(
                "{}={} ",
                first_field(&z.join("type").to_string_lossy()),
                millic / 1000
            )
        })
        .collect()
}

pub fn line(stations: &[(String, u32)]) -> String {
    let mut stations = stations.to_vec();
    stations.sort();
    let clients: String = stations.iter().map(|(i, n)| format!("{i}={n} ")).collect();
    format!(
        "load={} memavail_kb={} fw_crashes={} clients: {clients}temps: {}",
        first_field("/proc/loadavg"),
        mem_available_kb(),
        fw_crashes(),
        temps().trim_end()
    )
}
