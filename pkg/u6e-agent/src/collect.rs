//! The AP's state as a `Snapshot`: nl80211 for the interfaces, stations and
//! survey, hostapd for whether a radio is up, sysfs and procfs for the rest.
//! A source that is missing or odd reads as zeros and empty lists; collecting
//! never fails.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use u6e_proto::msg::{Band, Bss, Radio, Snapshot, Station, Temp};

use crate::kmsg::{self, Kmsg};
use crate::neighbors::{self, Hostapd};
use crate::nl80211::{self, Iface, Nl80211, Survey, Watch};

/// Where the collectors and the events thread look, so tests can point them
/// at a scratch tree.
#[derive(Debug, Clone)]
pub struct Paths {
    /// The prefix of /sys, /proc and the debugfs under it.
    pub root: PathBuf,
    pub hostapd: PathBuf,
    pub kmsg: PathBuf,
    /// Where this agent binds its client sockets.
    pub run: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Paths {
            root: "/".into(),
            hostapd: crate::neighbors::HOSTAPD.into(),
            kmsg: "/dev/kmsg".into(),
            run: crate::clientsock::RUN.into(),
        }
    }
}

impl Paths {
    pub fn sys(&self) -> PathBuf {
        self.root.join("sys")
    }
}

/// The BSSs, by interface name: the AP interfaces, one per hostapd control
/// socket, sorted. `Snapshot::bsss` and the BSS index of every event follow
/// this order, so the two need no shared state.
pub fn bss_order(hostapd: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(hostapd)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_socket()))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// A source that may not be there yet, or may break: opened again at every
/// snapshot until it opens, dropped when it fails so the next snapshot opens
/// it afresh. A failure is logged once, and its end once a use succeeds.
struct Source<T> {
    name: &'static str,
    inner: Option<T>,
    reported: bool,
    /// It failed in use, so opening it again proves nothing until a use
    /// succeeds.
    failed_in_use: bool,
}

impl<T> Source<T> {
    fn new(name: &'static str) -> Self {
        Source {
            name,
            inner: None,
            reported: false,
            failed_in_use: false,
        }
    }

    fn get(&mut self, open: impl FnOnce() -> io::Result<T>) -> Option<&mut T> {
        if self.inner.is_none() {
            match open() {
                Ok(v) => {
                    self.inner = Some(v);
                    if !self.failed_in_use {
                        self.ok();
                    }
                }
                Err(e) => self.report(&e),
            }
        }
        self.inner.as_mut()
    }

    /// The source failed in use: it is opened again next time.
    fn fail(&mut self, e: &io::Error) {
        self.inner = None;
        self.failed_in_use = true;
        self.report(e);
    }

    /// A use of the source succeeded.
    fn ok(&mut self) {
        self.failed_in_use = false;
        if self.reported {
            eprintln!("u6e-agent: {} is available again", self.name);
            self.reported = false;
        }
    }

    fn report(&mut self, e: &io::Error) {
        if !self.reported {
            eprintln!("u6e-agent: {}: {e}", self.name);
            self.reported = true;
        }
    }
}

/// How long the interface list stands without a notification; the transmit
/// power, which nothing announces, is at most this old.
const IFACES_FOR: Duration = Duration::from_secs(60);

/// The interfaces as of their last dump. A dump costs a firmware round trip
/// per AP interface under the RTNL lock (for the transmit power), so it is
/// repeated only when nl80211 announces a change, the hostapd sockets
/// change, or [`IFACES_FOR`] has passed.
#[derive(Default)]
struct Ifaces {
    list: Vec<Iface>,
    /// The BSS order the list was read for.
    order: Vec<String>,
    read_at: Option<Instant>,
}

impl Ifaces {
    fn stale(&self, order: &[String], reconfigured: bool, now: Instant) -> bool {
        reconfigured
            || self.order != order
            || self
                .read_at
                .is_none_or(|t| now.duration_since(t) >= IFACES_FOR)
    }

    fn store(&mut self, list: Vec<Iface>, order: Vec<String>, now: Instant) {
        *self = Ifaces {
            list,
            order,
            read_at: Some(now),
        };
    }
}

/// Collects the state; whatever cannot be read yet reads as empty, so the
/// agent's other duties never depend on the collectors.
pub struct Collector {
    nl: Source<Nl80211>,
    watch: Source<Watch>,
    ifaces: Ifaces,
    hostapd: Source<Hostapd>,
    kmsg: Kmsg,
    paths: Paths,
    crashes: u64,
    /// Whether each BSS's radio was up at the last answer.
    up: HashMap<String, bool>,
}

impl Collector {
    pub fn new() -> Self {
        Self::with_paths(Paths::default())
    }

    pub fn with_paths(paths: Paths) -> Self {
        let mut kmsg = Kmsg::open(&paths.kmsg, false);
        let crashes = kmsg.drain().iter().filter(|m| kmsg::is_fw_crash(m)).count() as u64;
        Collector {
            nl: Source::new("nl80211"),
            watch: Source::new("nl80211 notifications"),
            ifaces: Ifaces::default(),
            hostapd: Source::new("hostapd control socket"),
            kmsg,
            paths,
            crashes,
            up: HashMap::new(),
        }
    }

    /// The Wi-Fi firmware crashes in the kernel log, as of the last snapshot.
    pub fn fw_crashes(&self) -> u64 {
        self.crashes
    }

    /// Whether nl80211 is open (after a snapshot).
    pub fn has_nl80211(&self) -> bool {
        self.nl.inner.is_some()
    }

    /// Opens nl80211 if need be and reads the interfaces again if they are
    /// stale.
    fn refresh_ifaces(&mut self, order: &[String]) {
        let Some(nl) = self.nl.get(Nl80211::open) else {
            return;
        };
        // Notifications are read before the dump, so one that follows it
        // brings the next.
        let watch = self.watch.get(|| nl.watch());
        let reconfigured = watch.is_some_and(|w| w.reconfigured());
        let now = Instant::now();
        if !self.ifaces.stale(order, reconfigured, now) {
            return;
        }
        match nl.interfaces() {
            Ok(list) => {
                self.ifaces.store(list, order.to_vec(), now);
                self.nl.ok();
            }
            // A socket that fails a dump (the family registered again under
            // a new id, say) is opened afresh, its watch too.
            Err(e) => {
                self.ifaces = Ifaces::default();
                self.nl.fail(&e);
                self.watch.inner = None;
            }
        }
    }

    pub fn snapshot(&mut self, seq: u64) -> Snapshot {
        let sys = self.paths.sys();
        self.crashes += self
            .kmsg
            .drain()
            .iter()
            .filter(|m| kmsg::is_fw_crash(m))
            .count() as u64;
        let order = bss_order(&self.paths.hostapd);
        self.refresh_ifaces(&order);
        let mut nl = self.nl.inner.as_mut();
        let ifaces = &self.ifaces.list;
        let bsss = bsss(&sys, &order, ifaces);
        let per_iface: Vec<_> = ifaces
            .iter()
            .filter(|i| i.kind == nl80211::IFTYPE_AP || i.kind == nl80211::IFTYPE_AP_VLAN)
            .map(|i| {
                let stas = nl.as_mut().and_then(|nl| nl.stations(i.ifindex).ok());
                (i.name.as_str(), stas.unwrap_or_default())
            })
            .collect();
        let stations = stations(&sys, &order, per_iface);
        let (run, dir) = (&self.paths.run, &self.paths.hostapd);
        let mut hostapd = self.hostapd.get(|| Hostapd::bind(run, "collect", dir));
        let radios = radios(
            &bsss,
            ifaces,
            |i| {
                let survey = nl.as_mut().and_then(|nl| nl.survey(i.ifindex).ok());
                survey.unwrap_or_default()
            },
            |bss| {
                let answer = hostapd.as_mut().map_or_else(
                    || Err(io::ErrorKind::NotFound.into()),
                    |h| h.try_request(bss, "STATUS"),
                );
                let up = radio_up(answer, self.up.get(bss).copied());
                self.up.insert(bss.to_owned(), up);
                up
            },
        );
        self.up.retain(|bss, _| order.contains(bss));
        let root = &self.paths.root;
        Snapshot {
            seq,
            uptime_s: first_field(&root.join("proc/uptime")).map_or(0, |v| v as u32),
            load_milli: first_field(&root.join("proc/loadavg"))
                .map_or(0, |v| (v * 1000.0).round() as u32),
            mem_avail_kb: mem_available_kb(&root.join("proc/meminfo")),
            nss_load_pct: nss_load_pct(
                &root.join("sys/kernel/debug/qca-nss-drv/stats/cpu_load_ubi"),
            ),
            temps: temps(&sys, &radios),
            radios,
            bsss,
            stations,
        }
    }
}

/// Whether a radio serves, from its hostapd's answer to STATUS. A hostapd
/// too busy to answer in time keeps the radio as it last was, rather than
/// flapping it down for a tick.
fn radio_up(status: io::Result<String>, last: Option<bool>) -> bool {
    match status {
        Ok(s) => neighbors::enabled(&s),
        Err(e) if e.kind() == io::ErrorKind::TimedOut => last.unwrap_or(false),
        Err(_) => false,
    }
}

fn first_field(path: &Path) -> Option<f64> {
    fs::read_to_string(path)
        .ok()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn mem_available_kb(path: &Path) -> u32 {
    fs::read_to_string(path)
        .ok()
        .and_then(|m| {
            let l = m.lines().find(|l| l.starts_with("MemAvailable:"))?;
            l.split_whitespace().nth(1)?.parse().ok()
        })
        .unwrap_or(0)
}

/// The average of the per-core "Avg" figures; the file lists, per core, a
/// "Min Avg Max" header and a line of percentages.
fn nss_load_pct(path: &Path) -> u8 {
    let text = fs::read_to_string(path).unwrap_or_default();
    let mut lines = text.lines();
    let mut avgs = Vec::new();
    while let Some(l) = lines.next() {
        if l.contains("Avg") {
            let avg = lines.next().and_then(|v| v.split_whitespace().nth(1));
            avgs.extend(avg.and_then(|a| a.trim_end_matches('%').parse::<u32>().ok()));
        }
    }
    let n = avgs.len() as u32;
    if n == 0 {
        0
    } else {
        (avgs.iter().sum::<u32>() as f64 / f64::from(n)).round() as u8
    }
}

/// Every thermal zone by its type, and a radio's own sensor as the zone named
/// after its phy, where the driver exposes one.
fn temps(sys: &Path, radios: &[Radio]) -> Vec<Temp> {
    let milli_c = |p: PathBuf| fs::read_to_string(p).ok()?.trim().parse().ok();
    let mut zones: Vec<_> = fs::read_dir(sys.join("class/thermal"))
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
    let mut out: Vec<Temp> = zones
        .iter()
        .map(|z| Temp {
            zone: fs::read_to_string(z.join("type"))
                .unwrap_or_default()
                .trim()
                .to_owned(),
            milli_c: milli_c(z.join("temp")).unwrap_or(0),
        })
        .collect();
    for r in radios {
        let dev = sys.join("class/ieee80211").join(&r.phy).join("device");
        let mut hwmons: Vec<_> = fs::read_dir(dev)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("hwmon"))
            .map(|e| e.path())
            .collect();
        hwmons.sort();
        let sensor = hwmons.iter().find_map(|h| milli_c(h.join("temp1_input")));
        out.extend(sensor.map(|milli_c| Temp {
            zone: r.phy.clone(),
            milli_c,
        }));
    }
    out
}

/// The number N of the bridge `brN` an interface is enslaved to; 0 for none.
fn vlan_of(sys: &Path, ifname: &str) -> u16 {
    fs::read_link(sys.join("class/net").join(ifname).join("master"))
        .ok()
        .and_then(|m| m.file_name()?.to_str()?.strip_prefix("br")?.parse().ok())
        .unwrap_or(0)
}

/// One BSS per name in `order`; an interface nl80211 does not list (hostapd
/// not yet through starting it) keeps its place, empty, so indices hold.
fn bsss(sys: &Path, order: &[String], ifaces: &[Iface]) -> Vec<Bss> {
    order
        .iter()
        .map(|name| {
            let iface = ifaces
                .iter()
                .find(|i| i.name == *name && i.kind == nl80211::IFTYPE_AP);
            Bss {
                ifname: name.clone(),
                bssid: iface.map_or([0; 6], |i| i.mac),
                ssid: iface.map_or_else(String::new, |i| i.ssid.clone()),
                phy: iface.map_or_else(String::new, Iface::phy),
                vlan: vlan_of(sys, name),
            }
        })
        .collect()
}

/// The stations of all interfaces, sorted by MAC, each once. A dynamic
/// VLAN's stations sit on an AP_VLAN interface `<bss>.<vlan>`, whose BSS is
/// the part before the dot; one that belongs to no BSS is dropped.
fn stations(sys: &Path, order: &[String], per_iface: Vec<(&str, Vec<Station>)>) -> Vec<Station> {
    let mut out = Vec::new();
    for (ifname, stas) in per_iface {
        let parent = ifname.split('.').next().unwrap_or(ifname);
        let Some(bss) = order.iter().position(|n| n == parent) else {
            continue;
        };
        let vlan = vlan_of(sys, ifname);
        out.extend(stas.into_iter().map(|s| Station {
            bss: bss as u16,
            vlan,
            ..s
        }));
    }
    // A client roaming between BSSs is listed by both until the old entry
    // ages out; the newest association is the one it is on.
    out.sort_by_key(|s| (s.mac, s.connected_s));
    out.dedup_by_key(|s| s.mac);
    out
}

fn band(freq_mhz: u32) -> Band {
    match freq_mhz {
        ..3000 => Band::B24,
        3000..5925 => Band::B5,
        _ => Band::B6,
    }
}

fn channel(freq_mhz: u32) -> u16 {
    let (f, base) = match band(freq_mhz) {
        Band::B24 if freq_mhz == 2484 => return 14,
        Band::B24 => (freq_mhz, 2407),
        Band::B5 => (freq_mhz, 5000),
        Band::B6 if freq_mhz == 5935 => return 2,
        Band::B6 => (freq_mhz, 5950),
    };
    (f.saturating_sub(base) / 5) as u16
}

/// One radio per phy that has a BSS, by phy name. Its channel, width and power
/// are its first BSS's that is on a channel (hostapd brings them up one by
/// one); the survey of the channel in use gives the noise and the times, and
/// that BSS's hostapd says whether it is up.
fn radios(
    bsss: &[Bss],
    ifaces: &[Iface],
    mut survey: impl FnMut(&Iface) -> Vec<Survey>,
    mut enabled: impl FnMut(&str) -> bool,
) -> Vec<Radio> {
    let on_channel = |b: &Bss| ifaces.iter().any(|i| i.name == b.ifname && i.freq_mhz != 0);
    let mut firsts: BTreeMap<&str, &Bss> = BTreeMap::new();
    for b in bsss.iter().filter(|b| !b.phy.is_empty()) {
        let first = firsts.entry(&b.phy).or_insert(b);
        if !on_channel(first) && on_channel(b) {
            *first = b;
        }
    }
    firsts
        .into_iter()
        .filter_map(|(phy, bss)| {
            let iface = ifaces.iter().find(|i| i.name == bss.ifname)?;
            let s = survey(iface)
                .into_iter()
                .find(|s| s.in_use)
                .unwrap_or_default();
            Some(Radio {
                phy: phy.to_owned(),
                band: band(iface.freq_mhz),
                channel: channel(iface.freq_mhz),
                width_mhz: iface.width_mhz,
                txpower_mbm: iface.txpower_mbm,
                noise_dbm: s.noise_dbm,
                active_ms: s.active_ms,
                busy_ms: s.busy_ms,
                rx_ms: s.rx_ms,
                tx_ms: s.tx_ms,
                up: enabled(&bss.ifname),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixDatagram;

    const INTERFACES: &[u8] = include_bytes!("../tests/fixtures/interfaces.bin");
    const STATIONS: &[u8] = include_bytes!("../tests/fixtures/station-wlan5.42.bin");
    const SURVEYS: [&[u8]; 3] = [
        include_bytes!("../tests/fixtures/survey-phy0.bin"),
        include_bytes!("../tests/fixtures/survey-phy1.bin"),
        include_bytes!("../tests/fixtures/survey-phy2.bin"),
    ];
    const STATUS: &str = include_str!("../tests/fixtures/status-wlan5.txt");

    const ORDER: [&str; 7] = [
        "wlan24", "wlan24-1", "wlan5", "wlan5-1", "wlan5-2", "wlan6", "wlan6-1",
    ];

    fn order() -> Vec<String> {
        ORDER.iter().map(|s| s.to_string()).collect()
    }

    /// A /sys with every interface of the fixture enslaved to br42, but the
    /// dynamic VLAN 43 ones.
    fn sys(t: &TestDir) -> PathBuf {
        let sys = t.path().join("sys");
        for i in nl80211::parse_interfaces(INTERFACES) {
            let dir = sys.join("class/net").join(&i.name);
            fs::create_dir_all(&dir).unwrap();
            let bridge = if i.name.ends_with(".43") {
                "br43"
            } else {
                "br42"
            };
            symlink(
                format!("../../../../virtual/net/{bridge}"),
                dir.join("master"),
            )
            .unwrap();
        }
        fs::create_dir_all(sys.join("class/net/eth0")).unwrap();
        sys
    }

    #[test]
    fn bss_order_is_the_sorted_hostapd_sockets() {
        let t = TestDir::new();
        let _socks: Vec<_> = ["wlan5-1", "wlan24", "wlan5"]
            .iter()
            .map(|n| UnixDatagram::bind(t.path().join(n)).unwrap())
            .collect();
        fs::write(t.path().join("not-a-socket"), "").unwrap();
        assert_eq!(bss_order(t.path()), ["wlan24", "wlan5", "wlan5-1"]);
        assert!(bss_order(&t.path().join("absent")).is_empty());
    }

    #[test]
    fn a_bss_carries_its_interface_and_bridge() {
        let t = TestDir::new();
        let all = bsss(&sys(&t), &order(), &nl80211::parse_interfaces(INTERFACES));
        assert_eq!(all.len(), 7);
        let b = &all[2];
        assert_eq!(
            (
                b.ifname.as_str(),
                b.bssid,
                b.ssid.as_str(),
                b.phy.as_str(),
                b.vlan
            ),
            ("wlan5", [2, 0, 0, 0, 0, 5], "ssid-a", "phy1", 42)
        );
        assert_eq!(
            (all[0].ssid.as_str(), all[0].phy.as_str()),
            ("ssid-b", "phy0")
        );
        assert_eq!(
            (all[6].ssid.as_str(), all[6].phy.as_str()),
            ("ssid-c", "phy2")
        );
    }

    #[test]
    fn a_bss_hostapd_has_but_nl80211_lacks_keeps_its_index() {
        let t = TestDir::new();
        let mut names = order();
        names.insert(0, "wlan0".into());
        let all = bsss(&sys(&t), &names, &nl80211::parse_interfaces(INTERFACES));
        assert_eq!(
            (all[0].ifname.as_str(), all[0].phy.as_str(), all[0].bssid),
            ("wlan0", "", [0; 6])
        );
        assert_eq!(all[3].ifname, "wlan5");
    }

    /// A client roaming between two BSSs of the AP is listed by both until
    /// the old entry ages out: it belongs to the newer association.
    #[test]
    fn a_station_listed_twice_belongs_to_its_newest_association() {
        let t = TestDir::new();
        let sys = sys(&t);
        let mut old = nl80211::parse_stations(STATIONS);
        old.truncate(1);
        old[0].connected_s = 600;
        let mut new = old.clone();
        new[0].connected_s = 2;
        let all = stations(&sys, &order(), vec![("wlan24", old), ("wlan6", new)]);
        assert_eq!(all.len(), 1);
        assert_eq!((all[0].bss, all[0].connected_s), (5, 2));
    }

    #[test]
    fn stations_are_sorted_and_belong_to_their_parent_bss() {
        let t = TestDir::new();
        let sys = sys(&t);
        let mut reversed = nl80211::parse_stations(STATIONS);
        reversed.reverse();
        let stray = nl80211::parse_stations(STATIONS);
        let all = stations(
            &sys,
            &order(),
            vec![
                ("wlan5.43", reversed),
                ("wlan9.42", stray),
                ("wlan5.42", nl80211::parse_stations(STATIONS)),
            ],
        );
        let macs: Vec<u8> = all.iter().map(|s| s.mac[5]).collect();
        assert_eq!(macs, [8, 9, 10]);
        assert!(all.iter().all(|s| s.bss == 2), "wlan5 is the third BSS");
        assert!(
            all.iter().all(|s| s.vlan == 43),
            "the first copy of each MAC is kept"
        );
        let again = stations(
            &sys,
            &order(),
            vec![("wlan5.42", nl80211::parse_stations(STATIONS))],
        );
        assert!(again.iter().all(|s| s.vlan == 42));
        assert_eq!((again[0].signal, again[0].tx_rate_kbps), (-54, 72_200));
    }

    #[test]
    fn radios_come_from_the_first_bss_of_each_phy() {
        let t = TestDir::new();
        let ifaces = nl80211::parse_interfaces(INTERFACES);
        let all_bsss = bsss(&sys(&t), &order(), &ifaces);
        let survey = |i: &Iface| nl80211::parse_survey(SURVEYS[i.wiphy as usize]);
        let mut asked = Vec::new();
        let enabled = |bss: &str| {
            asked.push(bss.to_owned());
            bss == "wlan5"
        };
        let all = radios(&all_bsss, &ifaces, survey, enabled);
        assert_eq!(asked, ["wlan24", "wlan5", "wlan6"]);
        let phys: Vec<_> = all.iter().map(|r| r.phy.as_str()).collect();
        assert_eq!(phys, ["phy0", "phy1", "phy2"]);
        assert_eq!(
            all[1],
            Radio {
                phy: "phy1".into(),
                band: Band::B5,
                channel: 149,
                width_mhz: 80,
                txpower_mbm: 2300,
                noise_dbm: -109,
                active_ms: 73_173_292,
                busy_ms: 5_242_301,
                rx_ms: 358_101,
                tx_ms: 3_555_556,
                up: true,
            }
        );
        assert_eq!(
            (all[0].band, all[0].channel, all[0].width_mhz, all[0].up),
            (Band::B24, 13, 20, false)
        );
        assert_eq!(
            (
                all[2].band,
                all[2].channel,
                all[2].width_mhz,
                all[2].noise_dbm
            ),
            (Band::B6, 85, 160, -108)
        );
    }

    #[test]
    fn a_radio_is_up_by_its_status_and_a_silent_one_keeps_its_last() {
        let timeout = || Err(io::ErrorKind::TimedOut.into());
        assert!(radio_up(Ok(STATUS.to_owned()), None));
        assert!(!radio_up(Ok("state=DISABLED\n".into()), Some(true)));
        assert!(radio_up(timeout(), Some(true)));
        assert!(!radio_up(timeout(), None));
        let refused = Err(io::ErrorKind::ConnectionRefused.into());
        assert!(!radio_up(refused, Some(true)));
    }

    /// hostapd brings a radio's BSSs up one by one: until the first is on its
    /// channel, the radio's channel comes from one that is.
    #[test]
    fn a_radio_takes_its_channel_from_a_bss_that_has_one() {
        let t = TestDir::new();
        let mut ifaces = nl80211::parse_interfaces(INTERFACES);
        ifaces
            .iter_mut()
            .filter(|i| i.name == "wlan5")
            .for_each(|i| i.freq_mhz = 0);
        let all_bsss = bsss(&sys(&t), &order(), &ifaces);
        let all = radios(&all_bsss, &ifaces, |_| Vec::new(), |_| true);
        assert_eq!(
            (all[1].phy.as_str(), all[1].band, all[1].channel),
            ("phy1", Band::B5, 149)
        );
    }

    #[test]
    fn a_radio_without_a_survey_reads_as_zeros() {
        let t = TestDir::new();
        let ifaces = nl80211::parse_interfaces(INTERFACES);
        let all_bsss = bsss(&sys(&t), &order(), &ifaces);
        let all = radios(&all_bsss, &ifaces, |_| Vec::new(), |_| false);
        assert_eq!(all.len(), 3);
        assert!(
            all.iter()
                .all(|r| r.noise_dbm == 0 && r.active_ms == 0 && !r.up)
        );
        assert!(radios(&[], &ifaces, |_| Vec::new(), |_| true).is_empty());
    }

    #[test]
    fn a_source_that_fails_is_opened_again_and_reported_once() {
        let mut s = Source::new("test");
        assert!(s.get(|| Err(io::Error::other("absent"))).is_none());
        assert!(s.reported);
        let mut opens = 0;
        let mut open = || {
            opens += 1;
            Ok(opens)
        };
        assert_eq!(s.get(&mut open).copied(), Some(1));
        assert!(!s.reported, "it opened: it is back");
        assert_eq!(s.get(&mut open).copied(), Some(1));
        s.fail(&io::Error::other("broken"));
        assert!(s.reported);
        assert_eq!(s.get(&mut open).copied(), Some(2));
        // Opening is not working: still reported until a use succeeds, so
        // a source that keeps failing is not logged at every tick.
        s.fail(&io::Error::other("broken"));
        assert_eq!(s.get(&mut open).copied(), Some(3));
        assert!(s.reported);
        s.ok();
        assert!(!s.reported);
    }

    #[test]
    fn interfaces_are_read_again_on_a_change_or_after_a_minute() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let mut cache = Ifaces::default();
        assert!(cache.stale(&order(), false, t0));
        cache.store(nl80211::parse_interfaces(INTERFACES), order(), t0);
        assert!(!cache.stale(&order(), false, t0 + s(59)));
        assert!(cache.stale(&order(), true, t0 + s(1)));
        assert!(cache.stale(&order()[1..], false, t0 + s(1)));
        assert!(cache.stale(&order(), false, t0 + s(60)));
    }

    #[test]
    fn channels_follow_the_band() {
        assert_eq!((channel(2412), channel(2472), channel(2484)), (1, 13, 14));
        assert_eq!((channel(5180), channel(5745)), (36, 149));
        assert_eq!((channel(5955), channel(6375)), (1, 85));
        // 6 GHz channel 2 sits below channel 1.
        assert_eq!((band(5935), channel(5935)), (Band::B6, 2));
        assert_eq!(
            (band(2484), band(5180), band(5925), band(7115)),
            (Band::B24, Band::B5, Band::B6, Band::B6)
        );
    }

    fn radio(phy: &str) -> Radio {
        Radio {
            phy: phy.into(),
            band: Band::B5,
            channel: 36,
            width_mhz: 80,
            txpower_mbm: 0,
            noise_dbm: 0,
            active_ms: 0,
            busy_ms: 0,
            rx_ms: 0,
            tx_ms: 0,
            up: true,
        }
    }

    #[test]
    fn temperatures_without_hwmon_are_just_the_zones() {
        let t = TestDir::new();
        for (z, name, milli) in [
            (0, "cpu-thermal", "61000"),
            (1, "top-glue-thermal", "58000"),
        ] {
            let dir = t.path().join(format!("class/thermal/thermal_zone{z}"));
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("type"), format!("{name}\n")).unwrap();
            fs::write(dir.join("temp"), format!("{milli}\n")).unwrap();
        }
        fs::create_dir_all(t.path().join("class/ieee80211/phy1/device")).unwrap();
        let zones = |all: Vec<Temp>| {
            all.into_iter()
                .map(|t| (t.zone, t.milli_c))
                .collect::<Vec<_>>()
        };
        let radios = [radio("phy1"), radio("phy7")];
        assert_eq!(
            zones(temps(t.path(), &radios)),
            [
                ("cpu-thermal".to_owned(), 61_000),
                ("top-glue-thermal".to_owned(), 58_000)
            ]
        );

        let hwmon = t.path().join("class/ieee80211/phy1/device/hwmon3");
        fs::create_dir_all(&hwmon).unwrap();
        fs::write(hwmon.join("temp1_input"), "47500\n").unwrap();
        assert_eq!(
            zones(temps(t.path(), &radios)).last(),
            Some(&("phy1".to_owned(), 47_500))
        );
        assert!(temps(&t.path().join("absent"), &radios).is_empty());
    }

    #[test]
    fn nss_load_averages_the_cores() {
        let t = TestDir::new();
        let file = t.path().join("cpu_load_ubi");
        fs::write(&file, "CPU Utilization:\nNote: Averaged over 1 second\n\nCore 0:\nMin\tAvg\tMax\n 1%\t 10%\t 30%\n\nCore 1:\nMin\tAvg\tMax\n 1%\t 21%\t 30%\n").unwrap();
        assert_eq!(nss_load_pct(&file), 16);
        fs::write(&file, "CPU Utilization:\nNote: Averaged over 1 second\n\nCore 0:\nMin\tAvg\tMax\n 1%\t 1%\t 1%\n").unwrap();
        assert_eq!(nss_load_pct(&file), 1);
        assert_eq!(nss_load_pct(&t.path().join("absent")), 0);
    }

    #[test]
    fn procfs_values_read_and_default_to_zero() {
        let t = TestDir::new();
        fs::write(t.path().join("loadavg"), "0.57 0.40 0.30 1/200 999\n").unwrap();
        fs::write(t.path().join("uptime"), "73173.46 140000.00\n").unwrap();
        fs::write(
            t.path().join("meminfo"),
            "MemTotal: 2000 kB\nMemAvailable:    812345 kB\n",
        )
        .unwrap();
        assert_eq!(first_field(&t.path().join("loadavg")), Some(0.57));
        assert_eq!(
            first_field(&t.path().join("uptime")).map(|v| v as u32),
            Some(73_173)
        );
        assert_eq!(mem_available_kb(&t.path().join("meminfo")), 812_345);
        assert_eq!(first_field(&t.path().join("absent")), None);
        assert_eq!(mem_available_kb(&t.path().join("absent")), 0);
    }

    #[test]
    fn a_collector_without_its_sources_still_reports_and_picks_them_up() {
        let t = TestDir::new();
        let run = t.path().join("run");
        fs::create_dir_all(&run).unwrap();
        let paths = Paths {
            root: t.path().join("root"),
            hostapd: t.path().join("hostapd"),
            kmsg: t.path().join("kmsg"),
            run,
        };
        let mut c = Collector::with_paths(paths.clone());
        let snap = c.snapshot(7);
        assert_eq!(snap.seq, 7);
        assert!(snap.bsss.is_empty() && snap.stations.is_empty() && snap.temps.is_empty());
        assert_eq!(
            (snap.uptime_s, snap.load_milli, snap.nss_load_pct),
            (0, 0, 0)
        );
        assert_eq!(c.fw_crashes(), 0);

        fs::create_dir_all(&paths.hostapd).unwrap();
        let _sock = UnixDatagram::bind(paths.hostapd.join("wlan5")).unwrap();
        fs::write(
            &paths.kmsg,
            "4,1,1,-;ath11k_pci 0000:01:00.0: firmware crashed: x\n",
        )
        .unwrap();
        let snap = c.snapshot(8);
        assert_eq!(snap.bsss.len(), 1);
        assert_eq!(snap.bsss[0].ifname, "wlan5");
        assert_eq!(c.fw_crashes(), 1);
    }
}
