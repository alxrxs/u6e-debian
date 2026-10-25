//! One line of the AP's state for the syslog collector: load, free memory, the
//! Wi-Fi firmware crashes so far, the stations of each BSS and the thermal
//! zones.

use u6e_proto::msg::Snapshot;

pub fn line(snap: &Snapshot, fw_crashes: u64, stations: &[(String, u32)]) -> String {
    let mut stations = stations.to_vec();
    stations.sort();
    let clients: String = stations.iter().map(|(i, n)| format!("{i}={n} ")).collect();
    let temps: Vec<String> = snap
        .temps
        .iter()
        .map(|t| format!("{}={}", t.zone, t.milli_c / 1000))
        .collect();
    format!(
        "load={}.{:02} memavail_kb={} fw_crashes={fw_crashes} clients: {clients}temps: {}",
        snap.load_milli / 1000,
        snap.load_milli % 1000 / 10,
        snap.mem_avail_kb,
        temps.join(" ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use u6e_proto::msg::Temp;

    #[test]
    fn keeps_the_line_format() {
        let snap = Snapshot {
            seq: 0,
            uptime_s: 0,
            load_milli: 1230,
            mem_avail_kb: 812345,
            nss_load_pct: 0,
            temps: vec![
                Temp {
                    zone: "cpu-thermal".into(),
                    milli_c: 61000,
                },
                Temp {
                    zone: "phy1".into(),
                    milli_c: 55500,
                },
            ],
            radios: vec![],
            bsss: vec![],
            stations: vec![],
            config_sha256: None,
        };
        let stations = [("wlan5".to_string(), 3), ("wlan24".to_string(), 0)];
        assert_eq!(
            line(&snap, 2, &stations),
            "load=1.23 memavail_kb=812345 fw_crashes=2 clients: wlan24=0 wlan5=3 temps: cpu-thermal=61 phy1=55"
        );
    }
}
