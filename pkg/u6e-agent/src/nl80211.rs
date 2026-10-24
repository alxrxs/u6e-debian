//! A minimal nl80211 client: generic netlink over one socket, enough to dump
//! the interfaces, the stations of an interface and the survey of a radio,
//! and a second socket that notices when the interfaces change. Dumps come
//! back as the kernel's raw bytes and the `parse_*` functions are pure over
//! them, so recorded replies test the parsing without an AP.

use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use u6e_proto::msg::{RateMode, Station};

const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLA_TYPE_MASK: u16 = 0x3fff;
const SOL_NETLINK: libc::c_int = 270;
const NETLINK_ADD_MEMBERSHIP: libc::c_int = 1;

const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const CTRL_ATTR_MCAST_GROUPS: u16 = 7;
const CTRL_ATTR_MCAST_GRP_NAME: u16 = 1;
const CTRL_ATTR_MCAST_GRP_ID: u16 = 2;
/// The multicast groups that announce new, removed and reconfigured
/// interfaces, APs starting and stopping, and channel switches.
const WATCHED_GROUPS: [&str; 2] = ["config", "mlme"];

const CMD_NEW_WIPHY: u8 = 3;
const CMD_DEL_WIPHY: u8 = 4;
const CMD_GET_INTERFACE: u8 = 5;
const CMD_SET_INTERFACE: u8 = 6;
const CMD_NEW_INTERFACE: u8 = 7;
const CMD_DEL_INTERFACE: u8 = 8;
const CMD_START_AP: u8 = 15;
const CMD_STOP_AP: u8 = 16;
const CMD_GET_STATION: u8 = 17;
#[cfg(test)]
const CMD_NEW_STATION: u8 = 19;
#[cfg(test)]
const CMD_DEL_STATION: u8 = 20;
const CMD_GET_SURVEY: u8 = 50;
const CMD_CH_SWITCH_NOTIFY: u8 = 88;

const ATTR_WIPHY: u16 = 1;
const ATTR_IFINDEX: u16 = 3;
const ATTR_IFNAME: u16 = 4;
const ATTR_IFTYPE: u16 = 5;
const ATTR_MAC: u16 = 6;
const ATTR_STA_INFO: u16 = 21;
const ATTR_WIPHY_FREQ: u16 = 38;
const ATTR_SSID: u16 = 52;
const ATTR_SURVEY_INFO: u16 = 84;
const ATTR_WIPHY_TX_POWER_LEVEL: u16 = 98;
const ATTR_CHANNEL_WIDTH: u16 = 159;

pub const IFTYPE_AP: u32 = 3;
pub const IFTYPE_AP_VLAN: u32 = 4;

const STA_INACTIVE_TIME: u16 = 1;
const STA_RX_BYTES: u16 = 2;
const STA_TX_BYTES: u16 = 3;
const STA_SIGNAL: u16 = 7;
const STA_TX_BITRATE: u16 = 8;
const STA_RX_PACKETS: u16 = 9;
const STA_TX_PACKETS: u16 = 10;
const STA_TX_RETRIES: u16 = 11;
const STA_TX_FAILED: u16 = 12;
const STA_SIGNAL_AVG: u16 = 13;
const STA_RX_BITRATE: u16 = 14;
const STA_CONNECTED_TIME: u16 = 16;
const STA_RX_BYTES64: u16 = 23;
const STA_TX_BYTES64: u16 = 24;
const STA_RX_DURATION: u16 = 32;
const STA_TX_DURATION: u16 = 39;

const RATE_BITRATE: u16 = 1;
const RATE_MCS: u16 = 2;
const RATE_BITRATE32: u16 = 5;
const RATE_VHT_MCS: u16 = 6;
const RATE_VHT_NSS: u16 = 7;
const RATE_HE_MCS: u16 = 13;
const RATE_HE_NSS: u16 = 14;

const SURVEY_FREQUENCY: u16 = 1;
const SURVEY_NOISE: u16 = 2;
const SURVEY_IN_USE: u16 = 3;
const SURVEY_TIME: u16 = 4;
const SURVEY_TIME_BUSY: u16 = 5;
const SURVEY_TIME_RX: u16 = 7;
const SURVEY_TIME_TX: u16 = 8;

/// One interface of a wiphy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Iface {
    pub ifindex: u32,
    pub name: String,
    pub wiphy: u32,
    pub kind: u32,
    pub mac: [u8; 6],
    pub ssid: String,
    pub freq_mhz: u32,
    pub width_mhz: u16,
    pub txpower_mbm: i32,
}

impl Iface {
    /// The wiphy's name in sysfs.
    pub fn phy(&self) -> String {
        format!("phy{}", self.wiphy)
    }
}

/// One channel of a survey dump; the one in use carries the busy times.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Survey {
    pub freq_mhz: u32,
    pub noise_dbm: i8,
    pub in_use: bool,
    pub active_ms: u64,
    pub busy_ms: u64,
    pub rx_ms: u64,
    pub tx_ms: u64,
}

pub struct Nl80211 {
    fd: OwnedFd,
    family: u16,
    seq: u32,
    /// The receive buffer and the answer, kept across requests: allocating
    /// and zeroing 64 KiB per request cost more than the dumps themselves.
    buf: Vec<u8>,
    out: Vec<u8>,
    /// The ids of [`WATCHED_GROUPS`].
    groups: Vec<u32>,
}

impl Nl80211 {
    /// Opens the socket and resolves the nl80211 family id, once.
    pub fn open() -> io::Result<Self> {
        let fd = netlink_socket()?;
        let timeout = libc::timeval {
            tv_sec: 2,
            tv_usec: 0,
        };
        let set = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const timeout).cast(),
                mem::size_of_val(&timeout) as u32,
            )
        };
        if set < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut nl = Self::with_fd(fd, GENL_ID_CTRL);
        let mut name = Vec::new();
        put_attr(&mut name, CTRL_ATTR_FAMILY_NAME, b"nl80211\0");
        let reply = nl.transact(GENL_ID_CTRL, 0, CTRL_CMD_GETFAMILY, &name)?;
        let family = parse_family_id(reply)
            .ok_or_else(|| io::Error::other("no nl80211 family in the reply"))?;
        nl.groups = parse_groups(reply, &WATCHED_GROUPS);
        nl.family = family;
        Ok(nl)
    }

    /// A socket that receives the notifications of [`WATCHED_GROUPS`].
    pub fn watch(&self) -> io::Result<Watch> {
        if self.groups.len() != WATCHED_GROUPS.len() {
            return Err(io::Error::other("nl80211 lacks a notification group"));
        }
        let fd = netlink_socket()?;
        for g in &self.groups {
            let joined = unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    SOL_NETLINK,
                    NETLINK_ADD_MEMBERSHIP,
                    (&raw const *g).cast(),
                    mem::size_of_val(g) as u32,
                )
            };
            if joined < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Watch::with_fd(fd, self.family))
    }

    fn with_fd(fd: OwnedFd, family: u16) -> Self {
        Nl80211 {
            fd,
            family,
            seq: 0,
            buf: vec![0; 65536],
            out: Vec::new(),
            groups: Vec::new(),
        }
    }

    /// The raw replies to `GET_INTERFACE`: every interface of every wiphy.
    pub fn dump_interfaces(&mut self) -> io::Result<&[u8]> {
        self.dump(CMD_GET_INTERFACE, &[])
    }

    /// The raw replies to `GET_STATION` of one interface.
    pub fn dump_stations(&mut self, ifindex: u32) -> io::Result<&[u8]> {
        self.dump(CMD_GET_STATION, &ifindex_attr(ifindex))
    }

    /// The raw replies to `GET_SURVEY` of the wiphy of an interface.
    pub fn dump_survey(&mut self, ifindex: u32) -> io::Result<&[u8]> {
        self.dump(CMD_GET_SURVEY, &ifindex_attr(ifindex))
    }

    pub fn interfaces(&mut self) -> io::Result<Vec<Iface>> {
        Ok(parse_interfaces(self.dump_interfaces()?))
    }

    pub fn stations(&mut self, ifindex: u32) -> io::Result<Vec<Station>> {
        Ok(parse_stations(self.dump_stations(ifindex)?))
    }

    pub fn survey(&mut self, ifindex: u32) -> io::Result<Vec<Survey>> {
        Ok(parse_survey(self.dump_survey(ifindex)?))
    }

    fn dump(&mut self, cmd: u8, attrs: &[u8]) -> io::Result<&[u8]> {
        self.transact(self.family, NLM_F_DUMP, cmd, attrs)
    }

    /// Sends one request and returns the data messages of the answer, back
    /// to back: until the end of the dump, or the one reply of a plain
    /// request.
    fn transact(&mut self, family: u16, flags: u16, cmd: u8, attrs: &[u8]) -> io::Result<&[u8]> {
        self.seq = self.seq.wrapping_add(1);
        let msg = request(family, NLM_F_REQUEST | flags, self.seq, cmd, attrs);
        let sent = unsafe { libc::send(self.fd.as_raw_fd(), msg.as_ptr().cast(), msg.len(), 0) };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        self.out.clear();
        loop {
            let (buf, out) = (&mut self.buf, &mut self.out);
            let n =
                unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            for (ty, seq, m) in messages(&buf[..n as usize]) {
                if seq != self.seq {
                    continue;
                }
                match ty {
                    // A dump that failed part-way says so here; what came
                    // before is not the whole list.
                    NLMSG_DONE => match m.get(16..20).map_or(0, i32_of) {
                        e if e < 0 => return Err(io::Error::from_raw_os_error(-e)),
                        _ => return Ok(&self.out),
                    },
                    NLMSG_ERROR => match m.get(16..20).map(i32_of) {
                        Some(0) => {}
                        Some(e) => return Err(io::Error::from_raw_os_error(-e)),
                        None => return Err(io::ErrorKind::InvalidData.into()),
                    },
                    _ => out.extend_from_slice(m),
                }
            }
            if flags & NLM_F_DUMP != NLM_F_DUMP && !out.is_empty() {
                return Ok(&self.out);
            }
        }
    }
}

/// nl80211's notifications, read without blocking: whether anything that
/// changes what an interface dump says happened since the last look.
pub struct Watch {
    fd: OwnedFd,
    family: u16,
}

impl Watch {
    fn with_fd(fd: OwnedFd, family: u16) -> Self {
        Watch { fd, family }
    }

    /// Reads every pending notification. Lost ones (a full socket buffer)
    /// count as a change too.
    pub fn reconfigured(&mut self) -> bool {
        // Each notification is one datagram; its header is all that counts,
        // and the rest of a longer one is dropped by the read.
        let mut head = [0u8; 20];
        let mut changed = false;
        loop {
            let n = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    head.as_mut_ptr().cast(),
                    head.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                match e.kind() {
                    io::ErrorKind::WouldBlock => return changed,
                    io::ErrorKind::Interrupted => continue,
                    _ => return true,
                }
            }
            let ours = n as usize == head.len() && u16_of(&head[4..6]) == self.family;
            changed |= ours
                && matches!(
                    head[16],
                    CMD_NEW_WIPHY
                        | CMD_DEL_WIPHY
                        | CMD_SET_INTERFACE
                        | CMD_NEW_INTERFACE
                        | CMD_DEL_INTERFACE
                        | CMD_START_AP
                        | CMD_STOP_AP
                        | CMD_CH_SWITCH_NOTIFY
                );
        }
    }
}

/// A bound generic netlink socket.
fn netlink_socket() -> io::Result<OwnedFd> {
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_GENERIC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    let bound = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&raw const addr).cast(),
            mem::size_of_val(&addr) as u32,
        )
    };
    if bound < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

fn ifindex_attr(ifindex: u32) -> Vec<u8> {
    let mut a = Vec::new();
    put_attr(&mut a, ATTR_IFINDEX, &ifindex.to_ne_bytes());
    a
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn put_attr(buf: &mut Vec<u8>, ty: u16, data: &[u8]) {
    buf.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
    buf.extend_from_slice(&ty.to_ne_bytes());
    buf.extend_from_slice(data);
    buf.resize(align4(buf.len()), 0);
}

/// A netlink message with a generic netlink header (version 1) and attributes.
fn request(family: u16, flags: u16, seq: u32, cmd: u8, attrs: &[u8]) -> Vec<u8> {
    let len = 16 + 4 + attrs.len();
    let mut m = Vec::with_capacity(len);
    m.extend_from_slice(&(len as u32).to_ne_bytes());
    m.extend_from_slice(&family.to_ne_bytes());
    m.extend_from_slice(&flags.to_ne_bytes());
    m.extend_from_slice(&seq.to_ne_bytes());
    m.extend_from_slice(&0u32.to_ne_bytes());
    m.extend_from_slice(&[cmd, 1, 0, 0]);
    m.extend_from_slice(attrs);
    m
}

/// The messages of a buffer as (type, sequence number, whole message).
fn messages(mut buf: &[u8]) -> Vec<(u16, u32, &[u8])> {
    let mut out = Vec::new();
    while buf.len() >= 16 {
        let len = u32_of(&buf[..4]) as usize;
        if len < 16 || len > buf.len() {
            break;
        }
        out.push((u16_of(&buf[4..6]), u32_of(&buf[8..12]), &buf[..len]));
        buf = &buf[align4(len).min(buf.len())..];
    }
    out
}

/// The attributes of a payload as (type without flags, data).
fn attrs(mut buf: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while buf.len() >= 4 {
        let len = usize::from(u16_of(&buf[..2]));
        if len < 4 || len > buf.len() {
            break;
        }
        out.push((u16_of(&buf[2..4]) & NLA_TYPE_MASK, &buf[4..len]));
        buf = &buf[align4(len).min(buf.len())..];
    }
    out
}

/// The attributes of every data message of a reply, one list per message;
/// the generic netlink header (4 bytes) follows the netlink header.
fn records(raw: &[u8]) -> impl Iterator<Item = Vec<(u16, &[u8])>> {
    messages(raw)
        .into_iter()
        .filter(|(ty, ..)| *ty != NLMSG_DONE && *ty != NLMSG_ERROR)
        .map(|(.., m)| attrs(m.get(20..).unwrap_or_default()))
}

fn u16_of(d: &[u8]) -> u16 {
    d.try_into().map(u16::from_ne_bytes).unwrap_or(0)
}

fn u32_of(d: &[u8]) -> u32 {
    d.try_into().map(u32::from_ne_bytes).unwrap_or(0)
}

fn i32_of(d: &[u8]) -> i32 {
    u32_of(d) as i32
}

fn u64_of(d: &[u8]) -> u64 {
    d.try_into().map(u64::from_ne_bytes).unwrap_or(0)
}

fn mac_of(d: &[u8]) -> [u8; 6] {
    d.try_into().unwrap_or_default()
}

fn str_of(d: &[u8]) -> String {
    String::from_utf8_lossy(d.split(|&b| b == 0).next().unwrap_or_default()).into_owned()
}

/// The family id in the reply to `CTRL_CMD_GETFAMILY`.
pub fn parse_family_id(raw: &[u8]) -> Option<u16> {
    records(raw)
        .flatten()
        .find(|(ty, _)| *ty == CTRL_ATTR_FAMILY_ID)
        .map(|(_, d)| u16_of(d))
}

/// The ids of the multicast groups `names` in the reply to
/// `CTRL_CMD_GETFAMILY`, in the order found; a missing group is left out.
fn parse_groups(raw: &[u8], names: &[&str]) -> Vec<u32> {
    let mut ids = Vec::new();
    for (_, groups) in records(raw)
        .flatten()
        .filter(|(ty, _)| *ty == CTRL_ATTR_MCAST_GROUPS)
    {
        for (_, group) in attrs(groups) {
            let (mut name, mut id) = (String::new(), None);
            for (ty, d) in attrs(group) {
                match ty {
                    CTRL_ATTR_MCAST_GRP_NAME => name = str_of(d),
                    CTRL_ATTR_MCAST_GRP_ID => id = Some(u32_of(d)),
                    _ => {}
                }
            }
            ids.extend(id.filter(|_| names.contains(&name.as_str())));
        }
    }
    ids
}

fn width_mhz(w: u32) -> u16 {
    match w {
        0 | 1 => 20,
        2 => 40,
        3 => 80,
        4 | 5 => 160,
        6 => 5,
        7 => 10,
        13 => 320,
        _ => 0,
    }
}

pub fn parse_interfaces(raw: &[u8]) -> Vec<Iface> {
    records(raw)
        .map(|a| {
            let mut i = Iface {
                ifindex: 0,
                name: String::new(),
                wiphy: 0,
                kind: 0,
                mac: [0; 6],
                ssid: String::new(),
                freq_mhz: 0,
                width_mhz: 0,
                txpower_mbm: 0,
            };
            for (ty, d) in a {
                match ty {
                    ATTR_IFINDEX => i.ifindex = u32_of(d),
                    ATTR_IFNAME => i.name = str_of(d),
                    ATTR_WIPHY => i.wiphy = u32_of(d),
                    ATTR_IFTYPE => i.kind = u32_of(d),
                    ATTR_MAC => i.mac = mac_of(d),
                    ATTR_SSID => i.ssid = String::from_utf8_lossy(d).into_owned(),
                    ATTR_WIPHY_FREQ => i.freq_mhz = u32_of(d),
                    ATTR_CHANNEL_WIDTH => i.width_mhz = width_mhz(u32_of(d)),
                    ATTR_WIPHY_TX_POWER_LEVEL => i.txpower_mbm = i32_of(d),
                    _ => {}
                }
            }
            i
        })
        .collect()
}

/// One direction's last rate, from a rate nested attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rate {
    kbps: u32,
    /// Which MCS attribute was present; none is a legacy rate. ath11k sends
    /// no EHT rates.
    mode: RateMode,
    mcs: u8,
    /// Only VHT and HE rates carry a stream count.
    nss: u8,
}

fn rate(d: &[u8]) -> Rate {
    let mut r = Rate {
        kbps: 0,
        mode: RateMode::Legacy,
        mcs: 0,
        nss: 0,
    };
    for (ty, d) in attrs(d) {
        let byte = d.first().copied().unwrap_or(0);
        match ty {
            RATE_BITRATE if r.kbps == 0 => r.kbps = u32::from(u16_of(d)) * 100,
            RATE_BITRATE32 => r.kbps = u32_of(d).saturating_mul(100),
            RATE_MCS => (r.mode, r.mcs) = (RateMode::Ht, byte),
            RATE_VHT_MCS => (r.mode, r.mcs) = (RateMode::Vht, byte),
            RATE_HE_MCS => (r.mode, r.mcs) = (RateMode::He, byte),
            RATE_VHT_NSS | RATE_HE_NSS => r.nss = byte,
            _ => {}
        }
    }
    r
}

/// The stations of one interface; `bss` and `vlan` are left for the caller,
/// who knows what the interface belongs to.
pub fn parse_stations(raw: &[u8]) -> Vec<Station> {
    let mut out = Vec::new();
    for a in records(raw) {
        let mut s = Station {
            mac: [0; 6],
            bss: 0,
            signal: 0,
            signal_avg: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            rx_packets: 0,
            tx_packets: 0,
            tx_retries: 0,
            tx_failed: 0,
            tx_rate_kbps: 0,
            rx_rate_kbps: 0,
            tx_mcs: 0,
            rx_mcs: 0,
            tx_mode: RateMode::Legacy,
            rx_mode: RateMode::Legacy,
            tx_nss: 0,
            rx_nss: 0,
            tx_airtime_us: 0,
            rx_airtime_us: 0,
            inactive_ms: 0,
            connected_s: 0,
            vlan: 0,
        };
        for (ty, d) in a {
            match ty {
                ATTR_MAC => s.mac = mac_of(d),
                ATTR_STA_INFO => sta_info(&mut s, d),
                _ => {}
            }
        }
        out.push(s);
    }
    out
}

fn sta_info(s: &mut Station, info: &[u8]) {
    let (mut rx32, mut tx32) = (0, 0);
    let mut has64 = (false, false);
    for (ty, d) in attrs(info) {
        match ty {
            STA_INACTIVE_TIME => s.inactive_ms = u32_of(d),
            STA_RX_BYTES => rx32 = u64::from(u32_of(d)),
            STA_TX_BYTES => tx32 = u64::from(u32_of(d)),
            STA_RX_BYTES64 => (s.rx_bytes, has64.0) = (u64_of(d), true),
            STA_TX_BYTES64 => (s.tx_bytes, has64.1) = (u64_of(d), true),
            STA_SIGNAL => s.signal = d.first().map_or(0, |&b| b as i8),
            STA_SIGNAL_AVG => s.signal_avg = d.first().map_or(0, |&b| b as i8),
            STA_RX_PACKETS => s.rx_packets = u64::from(u32_of(d)),
            STA_TX_PACKETS => s.tx_packets = u64::from(u32_of(d)),
            STA_TX_RETRIES => s.tx_retries = u32_of(d),
            STA_TX_FAILED => s.tx_failed = u32_of(d),
            STA_TX_BITRATE => {
                let r = rate(d);
                (s.tx_rate_kbps, s.tx_mode, s.tx_mcs, s.tx_nss) = (r.kbps, r.mode, r.mcs, r.nss);
            }
            STA_RX_BITRATE => {
                let r = rate(d);
                (s.rx_rate_kbps, s.rx_mode, s.rx_mcs, s.rx_nss) = (r.kbps, r.mode, r.mcs, r.nss);
            }
            STA_CONNECTED_TIME => s.connected_s = u32_of(d),
            STA_RX_DURATION => s.rx_airtime_us = u64_of(d),
            STA_TX_DURATION => s.tx_airtime_us = u64_of(d),
            _ => {}
        }
    }
    if !has64.0 {
        s.rx_bytes = rx32;
    }
    if !has64.1 {
        s.tx_bytes = tx32;
    }
}

pub fn parse_survey(raw: &[u8]) -> Vec<Survey> {
    records(raw)
        .filter_map(|a| {
            let (_, info) = a.into_iter().find(|(ty, _)| *ty == ATTR_SURVEY_INFO)?;
            let mut s = Survey::default();
            for (ty, d) in attrs(info) {
                match ty {
                    SURVEY_FREQUENCY => s.freq_mhz = u32_of(d),
                    SURVEY_NOISE => s.noise_dbm = d.first().map_or(0, |&b| b as i8),
                    SURVEY_IN_USE => s.in_use = true,
                    SURVEY_TIME => s.active_ms = u64_of(d),
                    SURVEY_TIME_BUSY => s.busy_ms = u64_of(d),
                    SURVEY_TIME_RX => s.rx_ms = u64_of(d),
                    SURVEY_TIME_TX => s.tx_ms = u64_of(d),
                    _ => {}
                }
            }
            Some(s)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTERFACES: &[u8] = include_bytes!("../tests/fixtures/interfaces.bin");
    const STATIONS: &[u8] = include_bytes!("../tests/fixtures/station-wlan5.42.bin");
    const NO_STATIONS: &[u8] = include_bytes!("../tests/fixtures/station-wlan5.bin");
    const SURVEY_24: &[u8] = include_bytes!("../tests/fixtures/survey-phy0.bin");
    const SURVEY_5: &[u8] = include_bytes!("../tests/fixtures/survey-phy1.bin");
    const SURVEY_6: &[u8] = include_bytes!("../tests/fixtures/survey-phy2.bin");

    fn iface<'a>(all: &'a [Iface], name: &str) -> &'a Iface {
        all.iter().find(|i| i.name == name).unwrap()
    }

    #[test]
    fn parses_the_interfaces_of_all_radios() {
        let all = parse_interfaces(INTERFACES);
        assert_eq!(all.len(), 15);
        let wlan5 = iface(&all, "wlan5");
        assert_eq!(
            (
                wlan5.ifindex,
                wlan5.wiphy,
                wlan5.kind,
                wlan5.mac,
                wlan5.ssid.as_str()
            ),
            (9, 1, IFTYPE_AP, [2, 0, 0, 0, 0, 5], "ssid-a")
        );
        assert_eq!(
            (
                wlan5.freq_mhz,
                wlan5.width_mhz,
                wlan5.txpower_mbm,
                wlan5.phy().as_str()
            ),
            (5745, 80, 2300, "phy1")
        );
        let vlan = iface(&all, "wlan5.42");
        assert_eq!((vlan.kind, vlan.ssid.as_str()), (IFTYPE_AP_VLAN, ""));
        let six = iface(&all, "wlan6");
        assert_eq!(
            (six.freq_mhz, six.width_mhz, six.txpower_mbm),
            (6375, 160, 1900)
        );
        let two = iface(&all, "wlan24");
        assert_eq!(
            (two.freq_mhz, two.width_mhz, two.ssid.as_str()),
            (2472, 20, "ssid-b")
        );
    }

    #[test]
    fn parses_the_stations_of_a_dynamic_vlan() {
        let all = parse_stations(STATIONS);
        assert_eq!(all.len(), 3);
        let s = &all[0];
        assert_eq!(s.mac, [2, 0, 0, 0, 0, 8]);
        assert_eq!((s.signal, s.signal_avg), (-54, -55));
        assert_eq!(
            (s.tx_rate_kbps, s.tx_mode, s.tx_mcs, s.tx_nss),
            (72_200, RateMode::Ht, 7, 0)
        );
        assert_eq!(
            (s.rx_rate_kbps, s.rx_mode, s.rx_mcs, s.rx_nss),
            (72_200, RateMode::Ht, 7, 0)
        );
        assert_eq!((s.tx_retries, s.tx_failed), (1, 2));
        assert_eq!((s.rx_bytes, s.tx_bytes), (21_367_714, 47_912_043));
        assert_eq!((s.rx_packets, s.tx_packets), (149_286, 324_102));
        assert_eq!(
            (s.tx_airtime_us, s.inactive_ms, s.connected_s),
            (41_381_687, 48, 8754)
        );
        let vht = &all[2];
        assert_eq!((vht.signal, vht.tx_rate_kbps), (-83, 300_000));
        assert_eq!((vht.tx_mode, vht.tx_mcs, vht.tx_nss), (RateMode::Vht, 7, 2));
        assert_eq!(
            (vht.rx_rate_kbps, vht.rx_mode, vht.rx_mcs, vht.rx_nss),
            (130_000, RateMode::Vht, 3, 1)
        );
        assert!(parse_stations(NO_STATIONS).is_empty());
    }

    #[test]
    fn finds_the_channel_in_use_in_a_survey() {
        let in_use = |raw| parse_survey(raw).into_iter().find(|s| s.in_use).unwrap();
        assert_eq!(parse_survey(SURVEY_5).len(), 25);
        assert_eq!(
            in_use(SURVEY_5),
            Survey {
                freq_mhz: 5745,
                noise_dbm: -109,
                in_use: true,
                active_ms: 73_173_292,
                busy_ms: 5_242_301,
                rx_ms: 358_101,
                tx_ms: 3_555_556,
            }
        );
        assert_eq!(
            (in_use(SURVEY_24).freq_mhz, in_use(SURVEY_24).noise_dbm),
            (2472, -104)
        );
        assert_eq!(
            (in_use(SURVEY_6).freq_mhz, in_use(SURVEY_6).tx_ms),
            (6375, 768_401)
        );
    }

    #[test]
    fn reads_the_family_id_from_a_reply() {
        let mut attrs = Vec::new();
        put_attr(&mut attrs, CTRL_ATTR_FAMILY_NAME, b"nl80211\0");
        put_attr(&mut attrs, CTRL_ATTR_FAMILY_ID, &27u16.to_ne_bytes());
        let reply = request(GENL_ID_CTRL, 0, 1, 1, &attrs);
        assert_eq!(parse_family_id(&reply), Some(27));
        assert_eq!(parse_family_id(&[]), None);
    }

    /// A client whose kernel is the other end of a socket pair: the test
    /// queues the kernel's datagrams on the returned end.
    fn fake_kernel() -> (Nl80211, OwnedFd) {
        let mut sv = [0; 2];
        let r = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, sv.as_mut_ptr()) };
        assert_eq!(r, 0);
        let (ours, kernel) = unsafe { (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(sv[1])) };
        (Nl80211::with_fd(ours, 28), kernel)
    }

    fn queue(kernel: &OwnedFd, datagram: &[u8]) {
        let sent = unsafe {
            libc::send(
                kernel.as_raw_fd(),
                datagram.as_ptr().cast(),
                datagram.len(),
                0,
            )
        };
        assert_eq!(sent as usize, datagram.len());
    }

    /// A station record of the dump with sequence number `seq`.
    fn station_msg(seq: u32, last: u8) -> Vec<u8> {
        let mut mac = Vec::new();
        put_attr(&mut mac, ATTR_MAC, &[2, 0, 0, 0, 0, last]);
        request(28, 2, seq, CMD_GET_STATION, &mac)
    }

    /// The end of a dump: NLMSG_DONE with the dump's status.
    fn done(seq: u32, status: i32) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&20u32.to_ne_bytes());
        m.extend_from_slice(&NLMSG_DONE.to_ne_bytes());
        m.extend_from_slice(&2u16.to_ne_bytes());
        m.extend_from_slice(&seq.to_ne_bytes());
        m.extend_from_slice(&0u32.to_ne_bytes());
        m.extend_from_slice(&status.to_ne_bytes());
        m
    }

    #[test]
    fn a_dump_is_joined_across_reads_and_skips_other_requests() {
        let (mut nl, kernel) = fake_kernel();
        // A late answer to an earlier request, then the dump in two reads.
        queue(&kernel, &station_msg(0, 9));
        queue(&kernel, &station_msg(1, 1));
        queue(&kernel, &[station_msg(1, 2), done(1, 0)].concat());
        let macs: Vec<u8> = nl.stations(9).unwrap().iter().map(|s| s.mac[5]).collect();
        assert_eq!(macs, [1, 2]);
    }

    #[test]
    fn a_dump_that_ends_in_an_error_is_not_a_complete_answer() {
        let (mut nl, kernel) = fake_kernel();
        queue(
            &kernel,
            &[station_msg(1, 1), done(1, -libc::ENODEV)].concat(),
        );
        let e = nl.stations(9).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ENODEV));
    }

    #[test]
    fn an_error_reply_is_an_error() {
        let (mut nl, kernel) = fake_kernel();
        let mut err = request(NLMSG_ERROR, 0, 1, 0, &[]);
        err.truncate(16);
        err.extend_from_slice(&(-libc::EPERM).to_ne_bytes());
        err[..4].copy_from_slice(&20u32.to_ne_bytes());
        queue(&kernel, &err);
        assert_eq!(
            nl.stations(9).unwrap_err().raw_os_error(),
            Some(libc::EPERM)
        );
    }

    #[test]
    fn reads_the_multicast_groups_from_a_reply() {
        let group = |name: &[u8], id: u32| {
            let mut g = Vec::new();
            put_attr(&mut g, CTRL_ATTR_MCAST_GRP_NAME, name);
            put_attr(&mut g, CTRL_ATTR_MCAST_GRP_ID, &id.to_ne_bytes());
            g
        };
        let mut groups = Vec::new();
        put_attr(&mut groups, 1, &group(b"config\0", 5));
        put_attr(&mut groups, 2, &group(b"scan\0", 6));
        put_attr(&mut groups, 3, &group(b"mlme\0", 8));
        let mut attrs = Vec::new();
        put_attr(&mut attrs, CTRL_ATTR_FAMILY_ID, &27u16.to_ne_bytes());
        put_attr(&mut attrs, CTRL_ATTR_MCAST_GROUPS, &groups);
        let reply = request(GENL_ID_CTRL, 0, 1, 1, &attrs);
        assert_eq!(parse_groups(&reply, &["config", "mlme"]), [5, 8]);
        assert!(parse_groups(&[], &["config"]).is_empty());
    }

    /// A notification of `cmd` as the kernel multicasts it.
    fn notification(cmd: u8) -> Vec<u8> {
        request(28, 0, 0, cmd, &ifindex_attr(9))
    }

    #[test]
    fn a_watch_sees_what_changes_an_interface_and_nothing_else() {
        let (nl, kernel) = fake_kernel();
        let mut w = Watch::with_fd(nl.fd, nl.family);
        assert!(!w.reconfigured());
        queue(&kernel, &notification(CMD_NEW_STATION));
        queue(&kernel, &notification(CMD_DEL_STATION));
        assert!(!w.reconfigured());
        for cmd in [
            CMD_NEW_INTERFACE,
            CMD_DEL_INTERFACE,
            CMD_SET_INTERFACE,
            CMD_NEW_WIPHY,
            CMD_DEL_WIPHY,
            CMD_START_AP,
            CMD_STOP_AP,
            CMD_CH_SWITCH_NOTIFY,
        ] {
            queue(&kernel, &notification(CMD_NEW_STATION));
            queue(&kernel, &notification(cmd));
            queue(&kernel, &notification(CMD_DEL_STATION));
            assert!(w.reconfigured(), "{cmd}");
            // Read once: the backlog is gone.
            assert!(!w.reconfigured(), "{cmd}");
        }
        // A larger notification is cut to its header, and still counts.
        let mut attrs = ifindex_attr(9);
        put_attr(&mut attrs, ATTR_SSID, &[0; 4000]);
        queue(&kernel, &request(28, 0, 0, CMD_CH_SWITCH_NOTIFY, &attrs));
        assert!(w.reconfigured());
    }

    #[test]
    fn a_rate_says_its_mode() {
        let mut he = Vec::new();
        put_attr(&mut he, RATE_BITRATE32, &12_010u32.to_ne_bytes());
        put_attr(&mut he, RATE_HE_MCS, &[11]);
        put_attr(&mut he, RATE_HE_NSS, &[2]);
        assert_eq!(
            rate(&he),
            Rate {
                kbps: 1_201_000,
                mode: RateMode::He,
                mcs: 11,
                nss: 2,
            }
        );
        let mut legacy = Vec::new();
        put_attr(&mut legacy, RATE_BITRATE, &60u16.to_ne_bytes());
        assert_eq!(
            rate(&legacy),
            Rate {
                kbps: 6000,
                mode: RateMode::Legacy,
                mcs: 0,
                nss: 0,
            }
        );
    }

    #[test]
    fn a_huge_rate_saturates() {
        let mut a = Vec::new();
        put_attr(&mut a, RATE_BITRATE32, &u32::MAX.to_ne_bytes());
        assert_eq!(rate(&a).kbps, u32::MAX);
    }

    #[test]
    fn damaged_replies_parse_to_what_is_intact() {
        assert!(parse_interfaces(&[]).is_empty());
        assert!(parse_interfaces(&[1, 2, 3]).is_empty());
        let cut = &STATIONS[..STATIONS.len() - 10];
        assert_eq!(parse_stations(cut).len(), 2);
        let mut bad_len = STATIONS.to_vec();
        bad_len[..4].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(parse_stations(&bad_len).is_empty());
    }
}
