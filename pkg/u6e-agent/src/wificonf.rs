//! The radios' configurations as u6e-wifi keeps them, in [`DIR`] (root's
//! alone: they hold passphrases and keys): per radio, its hostapd file (its
//! interface section, then its further BSSs, the BSSIDs still the
//! placeholders u6e-wifi's `render` fills in from the radio's address) and
//! its transmit power. Here: checking a configuration (the root helper
//! installs only what passes, and one that could make root write or read
//! outside hostapd's own run directories fails), telling how a radio can take
//! a new one, which only the helper does since only it reads what is
//! installed, and installing it file by file atomically. The hash of what is
//! installed, which says nothing secret, is the one thing the agent reads,
//! from [`STATE`].

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use u6e_proto::config::config_sha256;
use u6e_proto::frame::zeroize;
use u6e_proto::mac;
use u6e_proto::msg::{Band, RadioConfig};

use crate::regdomain::Target;

/// The installed configurations: root's alone.
pub const DIR: &str = "/run/u6e-wifi";
/// The config helper's socket and the installed configuration's hash
/// ([`HASH`]): root's, set-group-ID to the agent's group, which reads them.
pub const STATE: &str = "/run/u6e-wifi-helper";
pub const HASH: &str = "sha256";
/// The last sequence number installed, in [`DIR`].
const SEQ: &str = "seq";
/// hostapd's control sockets and the group they belong to, as every
/// configuration must say.
const CTRL_INTERFACE: &str = "/run/hostapd";
const CTRL_GROUP: &str = "u6e-agent";
/// The only directory a configuration may name files in: u6e-wifi's.
const FILES: &str = "/run/hostapd-u6e/";
/// Where systemd-timesyncd marks the clock synchronized: until it is, the
/// clock may still be at the image's build date (the AP has no RTC).
const SYNCHRONIZED: &str = "/run/systemd/timesync/synchronized";
const TEXT_MAX: usize = 64 << 10;

/// BSS settings hostapd reads from its configuration at each use, so a `SET`
/// takes effect with no other step than rebuilding the beacon: bss_load.c
/// rereads the period and the averaging at every update, beacon.c the DTIM
/// period and the FILS Discovery intervals at every beacon build,
/// ieee802_11.c `rnr` and `max_listen_interval` per frame, and sta_info.c
/// and drv_callbacks.c the inactivity and low-ACK settings per station
/// (hostapd 2.13~git20261001). hostapd's RELOAD and RELOAD_CONFIG are no
/// way to change them: both deauthenticate every station, or re-key the
/// group without telling the stations (see apply.rs).
const IN_PLACE: [&str; 9] = [
    "bss_load_update_period",
    "chan_util_avg_period",
    "dtim_period",
    "fils_discovery_max_interval",
    "fils_discovery_min_interval",
    "rnr",
    "max_listen_interval",
    "ap_max_inactivity",
    "disassoc_low_ack",
];

/// Radio settings that say where the radio operates: a change of them alone
/// is a channel switch.
const CHANNEL: [&str; 7] = [
    "channel",
    "op_class",
    "ht_capab",
    "vht_oper_chwidth",
    "vht_oper_centr_freq_seg0_idx",
    "he_oper_chwidth",
    "he_oper_centr_freq_seg0_idx",
];

/// The interface a radio's first BSS is, which names its files.
pub fn iface(band: Band) -> &'static str {
    match band {
        Band::B24 => "wlan24",
        Band::B5 => "wlan5",
        Band::B6 => "wlan6",
    }
}

pub fn path(dir: &Path, band: Band) -> PathBuf {
    dir.join(format!("{}.conf", iface(band)))
}

fn power_path(dir: &Path, band: Band) -> PathBuf {
    dir.join(format!("{}.txpower", iface(band)))
}

/// Every radio's band, in the order the configurations are listed.
pub const BANDS: [Band; 3] = [Band::B24, Band::B5, Band::B6];

/// One BSS's lines: the first BSS's are the radio's too. They are wiped when
/// dropped, and never shown.
pub struct Section {
    pub iface: String,
    pub lines: Vec<(String, String)>,
}

impl Section {
    /// Every value of `key`, in order.
    fn values(&self) -> BTreeMap<&str, Vec<&str>> {
        let mut m: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for (k, v) in &self.lines {
            m.entry(k).or_default().push(v);
        }
        m
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.lines
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

impl Drop for Section {
    fn drop(&mut self) {
        for (k, v) in &mut self.lines {
            // SAFETY: zeros are valid UTF-8, and nothing reads them after.
            unsafe {
                zeroize(k.as_mut_vec());
                zeroize(v.as_mut_vec());
            }
        }
    }
}

/// A radio's configuration, checked: its BSSs, the radio's own first.
pub struct Conf {
    pub bsss: Vec<Section>,
}

/// Checks `text` as the configuration of the radio of `band` and splits it
/// into its BSSs. An error names the line and the setting, never a value.
pub fn parse(band: Band, text: &str) -> Result<Conf, String> {
    if text.len() > TEXT_MAX {
        return Err(format!("larger than {} KiB", TEXT_MAX >> 10));
    }
    let own = iface(band);
    let mut bsss: Vec<Section> = Vec::new();
    for (n, line) in text.split('\n').enumerate() {
        let at = |why: String| format!("line {}: {why}", n + 1);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| at("not key=value".into()))?;
        if k.is_empty() || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(at("not a setting".into()));
        }
        if v.contains(['\0', '\r']) {
            return Err(at(format!("{k} has a control character")));
        }
        match (k, bsss.last()) {
            ("interface", None) if v == own => {}
            ("interface", _) => return Err(at(format!("the interface must be {own}, first"))),
            (_, None) => return Err(at(format!("interface={own} must come first"))),
            ("bss", Some(_)) => {
                let want = format!("{own}-{}", bsss.len());
                if v != want {
                    return Err(at(format!("the next BSS must be {want}")));
                }
            }
            _ => {}
        }
        if k == "interface" || k == "bss" {
            bsss.push(Section {
                iface: v.to_owned(),
                lines: Vec::new(),
            });
            continue;
        }
        let bss = bsss.last_mut().expect("an interface or a BSS came first");
        if !allowed(&bss.iface, k, v) {
            return Err(at(format!("{k} is not allowed so")));
        }
        bss.lines.push((k.to_owned(), v.to_owned()));
    }
    if bsss.is_empty() {
        return Err(format!("no interface={own}"));
    }
    Ok(Conf { bsss })
}

/// What keeps a configuration from making root (hostapd, u6e-wifi's render)
/// touch anything but hostapd's own files: the control sockets and their
/// group are fixed, a VLAN file is its BSS's, a bridge is a client VLAN's,
/// and any other path lies in [`FILES`].
fn allowed(bss: &str, k: &str, v: &str) -> bool {
    match k {
        "ctrl_interface" => v == CTRL_INTERFACE,
        "ctrl_interface_group" => v == CTRL_GROUP,
        "vlan_file" => v == format!("{FILES}{bss}.vlan"),
        "bridge" => v.strip_prefix("br").is_some_and(digits),
        "bssid" => placeholder(v) || mac::parse(v).is_some(),
        // Names a database hostapd writes, in a form of its own.
        "eap_sim_db" => false,
        _ if v.starts_with('/') => v.starts_with(FILES) && !v.split('/').any(|c| c == ".."),
        _ => true,
    }
}

fn digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// u6e-wifi's BSSID placeholders: `@LA<n>@`, `@MB<n>@`.
fn placeholder(v: &str) -> bool {
    let inner = v.strip_prefix('@').and_then(|v| v.strip_suffix('@'));
    inner
        .and_then(|i| i.strip_prefix("LA").or_else(|| i.strip_prefix("MB")))
        .is_some_and(digits)
}

/// A setting to change in a running BSS, and the value it had: only ever
/// one of [`IN_PLACE`], none secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Set {
    pub iface: String,
    pub key: String,
    pub value: String,
    pub old: String,
}

/// How a radio's hostapd file changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Unchanged,
    /// Settings hostapd applies by `SET`, in place.
    InPlace(Vec<Set>),
    /// Only where the radio operates changed.
    Channel(Target),
    /// Anything else, and why.
    Restart(String),
}

/// What it takes the radio of `band` to go from `old` to `new`; a restart's
/// reason names the radio or the BSS it is about.
pub fn classify(band: Band, old: &Conf, new: &Conf) -> Change {
    let radio = iface(band);
    let names = |c: &Conf| c.bsss.iter().map(|b| b.iface.clone()).collect::<Vec<_>>();
    if names(old) != names(new) {
        return Change::Restart(format!("{radio}: the BSSs changed"));
    }
    let (mut sets, mut channel) = (Vec::new(), false);
    for (i, (o, n)) in old.bsss.iter().zip(&new.bsss).enumerate() {
        let (ov, nv) = (o.values(), n.values());
        let keys = ov.keys().chain(nv.keys()).collect::<BTreeSet<_>>();
        for &key in keys {
            let (a, b) = (ov.get(key), nv.get(key));
            if a == b {
                continue;
            }
            match (a.map(Vec::as_slice), b.map(Vec::as_slice)) {
                (Some([old]), Some([value])) if IN_PLACE.contains(&key) => sets.push(Set {
                    iface: n.iface.clone(),
                    key: key.to_owned(),
                    value: (*value).to_owned(),
                    old: (*old).to_owned(),
                }),
                _ if i == 0 && CHANNEL.contains(&key) && ht_unchanged(key, a, b) => channel = true,
                _ => return Change::Restart(format!("{}: {key} changed", n.iface)),
            }
        }
    }
    match (channel, sets.is_empty()) {
        (false, true) => Change::Unchanged,
        (false, false) => Change::InPlace(sets),
        (true, true) => target(band, &new.bsss[0]).map_or_else(
            || Change::Restart(format!("{radio}: the new channel cannot be told")),
            Change::Channel,
        ),
        (true, false) => {
            Change::Restart(format!("{radio}: the channel and other settings changed"))
        }
    }
}

/// The helper's verdict on one radio, for the agent, which sees only the
/// proposed configuration: what it takes, and what it may tell of the
/// installed one (the in-place settings' old values, whether the channel
/// moves), none of it secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Class {
    Unchanged,
    InPlace(Vec<Set>),
    /// Only the channel or width changed: to the proposed file's.
    Channel,
    /// Only the transmit power changed.
    Power,
    Restart {
        reason: String,
        moved: bool,
    },
}

/// What it takes the radio to go from `old` to `new`; `new` must be one
/// [`parse`] passes.
pub fn class(old: &RadioConfig, new: &RadioConfig) -> Result<Class, String> {
    let name = iface(new.radio);
    let new_conf = parse(new.radio, &new.text).map_err(|e| format!("{name}: {e}"))?;
    let Ok(old_conf) = parse(old.radio, &old.text) else {
        let reason = format!("{name}: the installed configuration does not pass");
        return Ok(Class::Restart {
            reason,
            moved: true,
        });
    };
    let moved = target(new.radio, &old_conf.bsss[0]) != target(new.radio, &new_conf.bsss[0]);
    let power = old.txpower_dbm != new.txpower_dbm;
    Ok(match classify(new.radio, &old_conf, &new_conf) {
        Change::Unchanged if power => Class::Power,
        Change::Unchanged => Class::Unchanged,
        Change::Restart(reason) => Class::Restart { reason, moved },
        _ if power => Class::Restart {
            reason: format!("{name}: the power and other settings changed"),
            moved,
        },
        Change::InPlace(sets) => Class::InPlace(sets),
        Change::Channel(_) => Class::Channel,
    })
}

/// Whether an `ht_capab` change is one of the 40 MHz secondary channel
/// alone; any other key passes.
fn ht_unchanged(key: &str, a: Option<&Vec<&str>>, b: Option<&Vec<&str>>) -> bool {
    let rest =
        |v: Option<&Vec<&str>>| v.map(|v| v.join("").replace("[HT40+]", "").replace("[HT40-]", ""));
    key != "ht_capab" || rest(a) == rest(b)
}

/// Where a radio's configuration puts it: its primary channel, its width
/// and the centre of that width, as hostapd reads them.
pub fn target(band: Band, radio: &Section) -> Option<Target> {
    let num = |k| radio.get(k).and_then(|v| v.parse::<u16>().ok());
    let channel = num("channel").filter(|&c| c != 0)?;
    let ht = radio.get("ht_capab").unwrap_or_default();
    let ht40 = if ht.contains("[HT40+]") {
        Some(channel + 2)
    } else if ht.contains("[HT40-]") {
        channel.checked_sub(2)
    } else {
        None
    };
    let chwidth = num("he_oper_chwidth").or_else(|| num("vht_oper_chwidth"));
    let seg0 = num("he_oper_centr_freq_seg0_idx").or_else(|| num("vht_oper_centr_freq_seg0_idx"));
    let (width_mhz, center_channel) = match (band, chwidth.unwrap_or(0)) {
        (Band::B24, _) | (Band::B5, 0) => match ht40 {
            Some(c) => (40, c),
            None => (20, channel),
        },
        (Band::B5, 1) => (80, seg0?),
        (Band::B5, 2) => (160, seg0?),
        (Band::B6, w) => {
            let width = match radio.get("op_class") {
                Some("131") => 20,
                Some("132") => 40,
                Some("133") => 80,
                Some("134") => 160,
                _ => [20, 80, 160].get(usize::from(w)).copied()?,
            };
            (width, if width == 20 { channel } else { seg0? })
        }
        _ => return None,
    };
    Some(Target {
        channel,
        width_mhz,
        center_channel,
    })
}

/// The installed configurations, in band order; a radio without one is
/// left out.
pub fn read(dir: &Path) -> io::Result<Vec<RadioConfig>> {
    let mut out = Vec::new();
    for radio in BANDS {
        let text = match fs::read_to_string(path(dir, radio)) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let power = fs::read_to_string(power_path(dir, radio))?;
        let txpower_dbm = power.trim().parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: no transmit power", iface(radio)),
            )
        })?;
        out.push(RadioConfig {
            radio,
            text,
            txpower_dbm,
        });
    }
    Ok(out)
}

/// The hash of the installed configuration; `None` when there is none or it
/// cannot be read.
pub fn installed_hash(dir: &Path) -> Option<[u8; 32]> {
    read(dir)
        .ok()
        .filter(|r| !r.is_empty())
        .map(|r| config_sha256(&r))
}

/// The last sequence number installed; 0 before any since boot.
pub fn read_seq(dir: &Path) -> u64 {
    fs::read_to_string(dir.join(SEQ))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// The time in milliseconds since the Unix epoch, which a signed
/// configuration's validity is judged by; `None` while the clock is not
/// synchronized.
pub fn now_ms() -> Option<u64> {
    if !Path::new(SYNCHRONIZED).exists() {
        return None;
    }
    let since = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    u64::try_from(since.as_millis()).ok()
}

pub fn write_seq(dir: &Path, seq: u64) -> io::Result<()> {
    replace(dir, SEQ, format!("{seq}\n").as_bytes(), 0o600)
}

/// Publishes `hash` in `state` for the agent to read.
pub fn write_hash(state: &Path, hash: Option<[u8; 32]>) -> io::Result<()> {
    let text = hash.map_or_else(String::new, |h| mac::hex(&h) + "\n");
    replace(state, HASH, text.as_bytes(), 0o640)
}

/// The hash the helper published.
pub fn read_hash(state: &Path) -> Option<[u8; 32]> {
    mac::unhex(fs::read_to_string(state.join(HASH)).ok()?.trim())
}

/// Writes `name` in `dir` whole: beside, synced, renamed over.
fn replace(dir: &Path, name: &str, data: &[u8], mode: u32) -> io::Result<()> {
    let new = dir.join(format!(".{name}.new"));
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&new)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&new, dir.join(name))
}

/// A configuration written beside the installed one and synced, waiting to
/// replace it; dropped uncommitted, it goes.
pub struct Staged {
    dir: PathBuf,
    files: Vec<(PathBuf, PathBuf)>,
}

/// Writes each radio's files beside its installed ones, root's alone, and
/// syncs them; nothing installed changes until [`Staged::commit`].
pub fn stage(dir: &Path, radios: &[RadioConfig]) -> io::Result<Staged> {
    let mut staged = Staged {
        dir: dir.to_owned(),
        files: Vec::new(),
    };
    for r in radios {
        let power = format!("{}\n", r.txpower_dbm);
        for (to, data) in [
            (path(dir, r.radio), r.text.as_bytes()),
            (power_path(dir, r.radio), power.as_bytes()),
        ] {
            let name = to.file_name().unwrap_or_default().to_string_lossy();
            let new = dir.join(format!(".{name}.new"));
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&new)?;
            staged.files.push((new, to));
            f.write_all(data)?;
            f.sync_all()?;
        }
    }
    Ok(staged)
}

impl Staged {
    /// Renames each staged file over the installed one, then syncs the
    /// directory: each file is the old one or the new one, whole, whenever
    /// the AP stops.
    pub fn commit(mut self) -> io::Result<()> {
        for (new, to) in &self.files {
            fs::rename(new, to)?;
        }
        self.files.clear();
        File::open(&self.dir)?.sync_all()
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        for (new, _) in &self.files {
            let _ = fs::remove_file(new);
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    use crate::testdir::TestDir;

    /// What `boot/wifi-up.sh --print` makes of site.conf.example (the
    /// secrets replaced by test values), each radio's configuration as
    /// u6e-wifi installs it, at powers every channel of the tests' radios
    /// allows (`regdomain::tests`).
    pub const WLAN24: &str = include_str!("../tests/fixtures/wifi/wlan24.conf");
    pub const WLAN5: &str = include_str!("../tests/fixtures/wifi/wlan5.conf");
    pub const WLAN6: &str = include_str!("../tests/fixtures/wifi/wlan6.conf");

    pub fn fixture() -> Vec<RadioConfig> {
        [
            (Band::B24, WLAN24, 20),
            (Band::B5, WLAN5, 23),
            (Band::B6, WLAN6, 23),
        ]
        .into_iter()
        .map(|(radio, text, txpower_dbm)| RadioConfig {
            radio,
            text: text.into(),
            txpower_dbm,
        })
        .collect()
    }

    /// `text` with its first line that starts with `from` replaced by `to`.
    pub fn edit(text: &str, from: &str, to: &str) -> String {
        let mut done = false;
        text.split('\n')
            .map(|l| {
                if !done && l.starts_with(from) {
                    done = true;
                    to.to_owned()
                } else {
                    l.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn conf(band: Band, text: &str) -> Conf {
        parse(band, text).unwrap()
    }

    #[test]
    fn the_rendered_configurations_pass_and_split_into_their_bsss() {
        let five = conf(Band::B5, WLAN5);
        let names: Vec<&str> = five.bsss.iter().map(|b| b.iface.as_str()).collect();
        assert_eq!(names, ["wlan5", "wlan5-1", "wlan5-2"]);
        assert_eq!(five.bsss[0].get("channel"), Some("149"));
        assert_eq!(five.bsss[1].get("bssid"), Some("@LA1@"));
        let six = conf(Band::B6, WLAN6);
        assert_eq!(six.bsss.len(), 2);
        assert_eq!(six.bsss[1].get("bssid"), Some("@MB1@"));
        assert_eq!(conf(Band::B24, WLAN24).bsss.len(), 2);
    }

    #[test]
    fn a_configuration_that_could_reach_beyond_hostapd_is_refused() {
        let refused = |from: &str, to: &str| {
            let text = edit(WLAN5, from, to);
            assert_ne!(text, WLAN5, "{from} is in the fixture");
            parse(Band::B5, &text).err().unwrap()
        };
        assert_eq!(
            refused("ctrl_interface=", "ctrl_interface=/etc/systemd/system"),
            "line 26: ctrl_interface is not allowed so"
        );
        assert!(
            refused("ctrl_interface_group=", "ctrl_interface_group=root").contains("not allowed")
        );
        assert!(
            refused("vlan_file=", "vlan_file=/run/hostapd-u6e/../../etc/x.vlan")
                .contains("not allowed")
        );
        assert!(
            refused("vlan_file=", "vlan_file=/run/hostapd-u6e/wlan6.vlan").contains("not allowed")
        );
        assert!(
            refused("auth_server_ca_cert=", "auth_server_ca_cert=/etc/shadow")
                .contains("not allowed")
        );
        assert!(
            refused(
                "auth_server_ca_cert=",
                "auth_server_ca_cert=/run/hostapd-u6e/../../etc/shadow"
            )
            .contains("not allowed")
        );
        assert!(refused("bridge=", "bridge=lan").contains("not allowed"));
        assert!(refused("bssid=", "bssid=@LA1;reboot@").contains("not allowed"));
        assert!(refused("ssid=", "eap_sim_db=unix:/tmp/sim").contains("not allowed"));
        assert_eq!(
            refused("interface=", "interface=wlan6"),
            "line 1: the interface must be wlan5, first"
        );
        assert!(refused("bss=wlan5-1", "bss=wlan5-2").contains("the next BSS must be wlan5-1"));
        assert!(refused("ssid=", "ssid x").contains("not key=value"));
        assert!(refused("ssid=", " ssid=x").contains("not a setting"));
        assert!(refused("ssid=", "ssid=a\rb").contains("ssid has a control character"));
        assert!(
            parse(Band::B5, "ssid=x\n")
                .err()
                .is_some_and(|e| e == "line 1: interface=wlan5 must come first")
        );
        assert!(
            parse(Band::B5, "# only\n")
                .err()
                .is_some_and(|e| e == "no interface=wlan5")
        );
        let huge = format!("interface=wlan5\n{}", "#".repeat(TEXT_MAX));
        assert!(
            parse(Band::B5, &huge)
                .err()
                .is_some_and(|e| e == "larger than 64 KiB")
        );
        // A value with a slash that is no path, and a path in hostapd's own
        // directory, pass.
        assert!(parse(Band::B5, &edit(WLAN5, "ssid=", "ssid=home/guest")).is_ok());
        assert!(
            parse(
                Band::B5,
                &edit(
                    WLAN5,
                    "auth_server_ca_cert=",
                    "auth_server_ca_cert=/run/hostapd-u6e/radsec/other.pem"
                )
            )
            .is_ok()
        );
    }

    /// A refusal says which line and setting, never the value: the value
    /// may be a passphrase, and the refusal goes to the controller.
    #[test]
    fn a_refusal_never_quotes_a_value() {
        for (from, to) in [
            ("sae_password=", "sae_password=/secret-pass"),
            ("sae_password=", "sae_password=secret\rpass"),
            ("sae_password=", "secret pass"),
            ("sae_password=", "secret-pass=x"),
        ] {
            let e = parse(Band::B5, &edit(WLAN5, from, to)).err().unwrap();
            assert!(!e.contains("secret"), "{e}");
        }
    }

    fn classify5(new: &str) -> Change {
        classify(Band::B5, &conf(Band::B5, WLAN5), &conf(Band::B5, new))
    }

    #[test]
    fn the_same_configuration_or_a_comment_is_unchanged() {
        assert_eq!(classify5(WLAN5), Change::Unchanged);
        let comment = format!("{WLAN5}# a note\n");
        assert_eq!(classify5(&comment), Change::Unchanged);
    }

    /// Changes of BSS settings hostapd rereads at each use are set in place,
    /// on the BSS they changed on.
    #[test]
    fn bss_settings_hostapd_rereads_are_set_in_place() {
        let text = WLAN5.replacen("bss_load_update_period=50", "bss_load_update_period=60", 2);
        let text = edit(&text, "dtim_period=3", "dtim_period=1");
        let Change::InPlace(sets) = classify5(&text) else {
            panic!("{:?}", classify5(&text));
        };
        let got: Vec<(&str, &str, &str, &str)> = sets
            .iter()
            .map(|s| {
                (
                    s.iface.as_str(),
                    s.key.as_str(),
                    s.value.as_str(),
                    s.old.as_str(),
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                ("wlan5", "bss_load_update_period", "60", "50"),
                ("wlan5", "dtim_period", "1", "3"),
                ("wlan5-1", "bss_load_update_period", "60", "50"),
            ]
        );
    }

    #[test]
    fn a_channel_change_alone_is_a_channel_switch() {
        let text = edit(WLAN5, "channel=149", "channel=36");
        let text = edit(
            &text,
            "vht_oper_centr_freq_seg0_idx=",
            "vht_oper_centr_freq_seg0_idx=42",
        );
        let text = edit(
            &text,
            "he_oper_centr_freq_seg0_idx=",
            "he_oper_centr_freq_seg0_idx=42",
        );
        assert_eq!(
            classify5(&text),
            Change::Channel(Target {
                channel: 36,
                width_mhz: 80,
                center_channel: 42
            })
        );
        let six = edit(WLAN6, "channel=", "channel=33");
        assert_eq!(
            classify(Band::B6, &conf(Band::B6, WLAN6), &conf(Band::B6, &six)),
            Change::Channel(Target {
                channel: 33,
                width_mhz: 160,
                center_channel: 47
            })
        );
        let ht40 = edit(
            WLAN24,
            "ht_capab=",
            "ht_capab=[HT40-][LDPC][SHORT-GI-20][SHORT-GI-40][TX-STBC][RX-STBC1]",
        );
        assert_eq!(
            classify(Band::B24, &conf(Band::B24, WLAN24), &conf(Band::B24, &ht40)),
            Change::Channel(Target {
                channel: 13,
                width_mhz: 40,
                center_channel: 11
            })
        );
    }

    #[test]
    fn anything_else_restarts_and_says_why() {
        let restart = |text: &str| match classify5(text) {
            Change::Restart(why) => why,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            restart(&edit(WLAN5, "ssid=", "ssid=other")),
            "wlan5: ssid changed"
        );
        assert_eq!(
            restart(&WLAN5.replacen("sae_groups=19 20 21", "sae_groups=19", 1)),
            "wlan5-2: sae_groups changed"
        );
        assert_eq!(
            restart(&edit(WLAN5, "he_bss_color=", "he_bss_color=5")),
            "wlan5: he_bss_color changed"
        );
        // Added or removed, a setting hostapd rereads still needs a restart:
        // no SET takes one back to hostapd's default.
        assert_eq!(
            restart(&edit(WLAN5, "dtim_period=3", "#")),
            "wlan5: dtim_period changed"
        );
        let cut = WLAN5.split("\nbss=wlan5-2").next().unwrap();
        assert_eq!(restart(cut), "wlan5: the BSSs changed");
        let both = edit(WLAN5, "channel=149", "channel=153");
        let both = edit(&both, "dtim_period=3", "dtim_period=1");
        assert_eq!(
            restart(&both),
            "wlan5: the channel and other settings changed"
        );
        let caps = edit(WLAN5, "ht_capab=", "ht_capab=[HT40+][LDPC]");
        assert_eq!(restart(&caps), "wlan5: ht_capab changed");
        assert_eq!(
            restart(&edit(WLAN5, "channel=149", "channel=0")),
            "wlan5: the new channel cannot be told"
        );
    }

    /// The helper's verdict adds the power: alone, it is set; with anything
    /// else, the radio restarts.
    #[test]
    fn a_power_change_alone_is_set_and_with_more_restarts() {
        let old = &fixture()[1];
        let with = |text: &str, txpower_dbm| RadioConfig {
            radio: Band::B5,
            text: text.into(),
            txpower_dbm,
        };
        assert_eq!(class(old, &with(WLAN5, 23)), Ok(Class::Unchanged));
        assert_eq!(class(old, &with(WLAN5, 20)), Ok(Class::Power));
        let dtim = edit(WLAN5, "dtim_period=3", "dtim_period=1");
        assert!(matches!(
            class(old, &with(&dtim, 23)),
            Ok(Class::InPlace(_))
        ));
        assert_eq!(
            class(old, &with(&dtim, 20)),
            Ok(Class::Restart {
                reason: "wlan5: the power and other settings changed".into(),
                moved: false
            })
        );
        let moved = edit(WLAN5, "channel=149", "channel=153");
        assert_eq!(class(old, &with(&moved, 23)), Ok(Class::Channel));
        let both = edit(&moved, "ssid=", "ssid=other");
        assert_eq!(
            class(old, &with(&both, 23)),
            Ok(Class::Restart {
                reason: "wlan5: ssid changed".into(),
                moved: true
            })
        );
        let bad = edit(WLAN5, "bridge=", "bridge=lan");
        assert_eq!(
            class(old, &with(&bad, 23)),
            Err("wlan5: line 47: bridge is not allowed so".into())
        );
    }

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o7777
    }

    /// Every installed file is root's alone: they hold the secrets.
    #[test]
    fn the_installed_set_is_root_only_read_in_band_order_and_hashed() {
        let t = TestDir::new();
        assert_eq!(installed_hash(t.path()), None);
        let all = fixture();
        stage(t.path(), &all).unwrap().commit().unwrap();
        assert_eq!(read(t.path()).unwrap(), all);
        assert_eq!(installed_hash(t.path()), Some(config_sha256(&all)));
        let names: Vec<String> = fs::read_dir(t.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 6, "nothing staged is left: {names:?}");
        for n in names {
            assert_eq!(mode(&t.path().join(&n)), 0o600, "{n}");
        }
    }

    /// The AP losing power (or the helper dying) between the write and the
    /// rename leaves the installed configuration as it was, whole.
    #[test]
    fn a_stage_never_committed_leaves_the_installed_configuration() {
        let t = TestDir::new();
        let old = fixture();
        stage(t.path(), &old).unwrap().commit().unwrap();
        let mut new = old.clone();
        new[1].text = edit(WLAN5, "dtim_period=3", "dtim_period=1");
        new[1].txpower_dbm = 20;
        let staged = stage(t.path(), &new).unwrap();
        // As a crash leaves it: the new files written and synced beside.
        std::mem::forget(staged);
        assert_eq!(read(t.path()).unwrap(), old);
        assert!(t.path().join(".wlan5.conf.new").exists());
        assert!(t.path().join(".wlan5.txpower.new").exists());
        // The next install writes over what the crash left.
        stage(t.path(), &new).unwrap().commit().unwrap();
        assert_eq!(read(t.path()).unwrap(), new);
        // Staged and dropped, it goes and the installed one stays.
        drop(stage(t.path(), &old).unwrap());
        assert_eq!(read(t.path()).unwrap(), new);
        assert!(!t.path().join(".wlan5.conf.new").exists());
    }

    /// The sequence number and the published hash, and who may read them.
    #[test]
    fn the_sequence_and_the_published_hash_are_kept() {
        let t = TestDir::new();
        assert_eq!(read_seq(t.path()), 0);
        write_seq(t.path(), 41).unwrap();
        assert_eq!(read_seq(t.path()), 41);
        assert_eq!(mode(&t.path().join(SEQ)), 0o600);
        assert_eq!(read_hash(t.path()), None);
        write_hash(t.path(), Some([0xab; 32])).unwrap();
        assert_eq!(read_hash(t.path()), Some([0xab; 32]));
        assert_eq!(mode(&t.path().join(HASH)), 0o640);
        write_hash(t.path(), None).unwrap();
        assert_eq!(read_hash(t.path()), None);
    }
}
