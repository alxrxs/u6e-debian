//! The DHCP servers' leases, read where they already publish them: each
//! DHCP node's node_exporter (`[leases] exporters`), whose textfile carries
//! one `kea_lease_expiry_timestamp_seconds{family,ip,mac,hostname,device,
//! subnet_id}` sample per active lease, its value the lease's expiry. The
//! controller never speaks to the DHCP servers themselves.
//!
//! Every [`EVERY`] each exporter is read over plain HTTP/1.0 (no chunking,
//! the body ends with the connection) and its leases replace the ones it
//! gave last; one that does not answer keeps its last ones until they
//! expire. A client's addresses are the union over the exporters, each
//! address with its newest expiry, and its host name and device those of
//! its lease that expires last.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{interval, timeout};
use u6e_proto::mac;

use crate::names;
use crate::state::Shared;

/// The family that carries the leases.
pub const FAMILY: &str = "kea_lease_expiry_timestamp_seconds";
/// How often the exporters are read.
pub const EVERY: Duration = Duration::from_secs(60);
/// The longest a read of one exporter may take, connecting included.
const TIMEOUT: Duration = Duration::from_secs(10);
/// The largest exposition taken: a node's whole exporter is a few hundred kB.
const BODY_MAX: usize = 16 << 20;
/// The longest device description kept: the DHCP server's free text.
const DEVICE_MAX: usize = 128;

/// One active lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub mac: [u8; 6],
    pub ip: IpAddr,
    /// The host name the client asked for, if it is one.
    pub hostname: Option<String>,
    /// The device the DHCP server knows the MAC as.
    pub device: Option<String>,
    /// When it expires, in Unix seconds.
    pub expires: u64,
}

/// The leases in an exposition: the samples of [`FAMILY`] that name a MAC
/// and an address, every other line ignored.
pub fn parse(text: &str) -> Vec<Lease> {
    text.lines().filter_map(lease).collect()
}

fn lease(line: &str) -> Option<Lease> {
    let rest = line.strip_prefix(FAMILY)?.strip_prefix('{')?;
    let (labels, value) = labels(rest)?;
    let expires = value.split_whitespace().next()?.parse::<f64>().ok()?;
    if !(expires.is_finite() && expires > 0.0) {
        return None;
    }
    let get = |k: &str| labels.get(k).map(String::as_str);
    let hostname = get("hostname").and_then(names::clean);
    let device = get("device").map(tidy).filter(|d| !d.is_empty());
    Some(Lease {
        mac: mac::parse(get("mac")?)?,
        ip: get("ip")?.parse().ok()?,
        hostname,
        device,
        expires: expires as u64,
    })
}

/// The labels of a sample up to its closing brace, and what follows it.
fn labels(mut s: &str) -> Option<(HashMap<&str, String>, &str)> {
    let mut out = HashMap::new();
    loop {
        s = s.trim_start_matches(',');
        if let Some(rest) = s.strip_prefix('}') {
            return Some((out, rest));
        }
        let (name, rest) = s.split_once("=\"")?;
        let mut value = String::new();
        let mut chars = rest.char_indices();
        let end = loop {
            match chars.next()? {
                (i, '"') => break i,
                (_, '\\') => match chars.next()?.1 {
                    'n' => value.push('\n'),
                    c => value.push(c),
                },
                (_, c) => value.push(c),
            }
        };
        out.insert(name, value);
        s = &rest[end + 1..];
    }
}

/// `s` on one line, without control characters, at most [`DEVICE_MAX`] long.
fn tidy(s: &str) -> String {
    let words = s.split(|c: char| c.is_whitespace() || c.is_control());
    let mut out = words
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if out.len() > DEVICE_MAX {
        let cut = (0..=DEVICE_MAX).rev().find(|&i| out.is_char_boundary(i));
        out.truncate(cut.unwrap_or(0));
    }
    out
}

/// What the leases say of one client.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Leased {
    /// Its addresses with when each lease expires (Unix seconds), the one
    /// expiring last first.
    pub addresses: Vec<(IpAddr, u64)>,
    pub hostname: Option<String>,
    pub device: Option<String>,
}

impl Leased {
    /// When its last lease expires.
    pub fn expires(&self) -> Option<u64> {
        self.addresses.first().map(|&(_, e)| e)
    }

    /// The same, without the leases expired by `now` (Unix seconds); `None`
    /// when none is left.
    pub fn at(&self, now: u64) -> Option<Leased> {
        let addresses: Vec<_> = self
            .addresses
            .iter()
            .filter(|(_, e)| *e > now)
            .copied()
            .collect();
        (!addresses.is_empty()).then(|| Leased {
            addresses,
            ..self.clone()
        })
    }
}

/// How one exporter's last read went.
#[derive(Debug, Clone, Default)]
pub struct Exporter {
    /// Its leases as it last gave them.
    pub leases: Vec<Lease>,
    /// Whether the last read worked (`None` before the first), and when
    /// one last did.
    pub up: Option<bool>,
    pub last_ok: Option<SystemTime>,
}

/// The leases of every exporter, and their union by client.
#[derive(Debug, Default)]
pub struct Leases {
    pub exporters: BTreeMap<String, Exporter>,
    by_mac: HashMap<[u8; 6], Leased>,
}

impl Leases {
    /// The exporters `names`, none read yet.
    pub fn new(names: &[String]) -> Self {
        let exporters = names.iter().map(|n| (n.clone(), Exporter::default()));
        Leases {
            exporters: exporters.collect(),
            by_mac: HashMap::new(),
        }
    }

    /// Takes a read of `exporter`: its leases, or why there are none this
    /// time. True when the union changed.
    pub fn take(
        &mut self,
        exporter: &str,
        read: Result<Vec<Lease>, String>,
        now: SystemTime,
    ) -> bool {
        let Some(e) = self.exporters.get_mut(exporter) else {
            return false;
        };
        match read {
            Ok(leases) => {
                e.leases = leases;
                e.up = Some(true);
                e.last_ok = Some(now);
            }
            Err(_) => e.up = Some(false),
        }
        let union = union(self.exporters.values().flat_map(|e| &e.leases));
        let changed = union != self.by_mac;
        self.by_mac = union;
        changed
    }

    /// What the leases say of `mac` at `now`.
    pub fn of(&self, mac: &[u8; 6], now: SystemTime) -> Option<Leased> {
        self.by_mac.get(mac)?.at(unix(now))
    }

    /// Every client with a lease at `now`, by MAC.
    pub fn all(&self, now: SystemTime) -> impl Iterator<Item = ([u8; 6], Leased)> + '_ {
        let now = unix(now);
        self.by_mac
            .iter()
            .filter_map(move |(m, l)| Some((*m, l.at(now)?)))
    }
}

fn unix(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// The leases by client: each address once, with its newest expiry; the
/// host name and device of the lease that expires last.
fn union<'a>(leases: impl Iterator<Item = &'a Lease>) -> HashMap<[u8; 6], Leased> {
    let mut newest: HashMap<([u8; 6], IpAddr), &Lease> = HashMap::new();
    for l in leases {
        let e = newest.entry((l.mac, l.ip)).or_insert(l);
        if l.expires > e.expires {
            *e = l;
        }
    }
    let mut by_mac: HashMap<[u8; 6], Vec<&Lease>> = HashMap::new();
    for l in newest.into_values() {
        by_mac.entry(l.mac).or_default().push(l);
    }
    let leased = by_mac.into_iter().map(|(m, mut ls)| {
        ls.sort_by(|a, b| b.expires.cmp(&a.expires).then(a.ip.cmp(&b.ip)));
        let named = |f: fn(&Lease) -> &Option<String>| ls.iter().find_map(|l| f(l).clone());
        let leased = Leased {
            addresses: ls.iter().map(|l| (l.ip, l.expires)).collect(),
            hostname: named(|l| &l.hostname),
            device: named(|l| &l.device),
        };
        (m, leased)
    });
    leased.collect()
}

/// Reads every exporter each [`EVERY`] for the life of the process, one
/// task per read so a slow exporter holds up no other; a change of an
/// exporter's state is logged once.
pub async fn supervise(state: Shared, exporters: Vec<String>) {
    let mut every = interval(EVERY);
    loop {
        every.tick().await;
        for exporter in &exporters {
            let (state, exporter) = (state.clone(), exporter.clone());
            tokio::spawn(async move {
                let read = read(&exporter).await.map(|text| parse(&text));
                let was = state
                    .read()
                    .leases
                    .exporters
                    .get(&exporter)
                    .and_then(|e| e.up);
                if was != Some(read.is_ok()) {
                    match &read {
                        Err(e) => eprintln!("u6e-controller: leases from {exporter}: {e}"),
                        Ok(l) => {
                            eprintln!("u6e-controller: leases from {exporter}: {} active", l.len())
                        }
                    }
                }
                state
                    .write()
                    .take_leases(&exporter, read, SystemTime::now());
            });
        }
    }
}

/// The exposition of the exporter at `address` (`host:port`).
pub async fn read(address: &str) -> Result<String, String> {
    timeout(TIMEOUT, fetch(address))
        .await
        .map_err(|_| "no answer in 10 s".to_owned())?
}

async fn fetch(address: &str) -> Result<String, String> {
    let host = address.rsplit_once(':').map_or(address, |(h, _)| h);
    let mut sock = TcpStream::connect(address)
        .await
        .map_err(|e| e.to_string())?;
    let ask = format!("GET /metrics HTTP/1.0\r\nHost: {host}\r\nAccept: text/plain\r\n\r\n");
    sock.write_all(ask.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut body = Vec::new();
    let read = (&mut sock)
        .take(BODY_MAX as u64 + 1)
        .read_to_end(&mut body)
        .await;
    read.map_err(|e| e.to_string())?;
    if body.len() > BODY_MAX {
        return Err("the exposition is over 16 MiB".into());
    }
    let text = String::from_utf8(body).map_err(|_| "the answer is not UTF-8".to_owned())?;
    let (head, body) = text.split_once("\r\n\r\n").ok_or("no end of the headers")?;
    let mut lines = head.lines();
    let status = lines.next().unwrap_or_default();
    if status.split_whitespace().nth(1) != Some("200") {
        return Err(format!("answered {status:?}"));
    }
    let encoded = lines.any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") || l.starts_with("content-encoding:")
    });
    if encoded {
        return Err("the body is encoded".into());
    }
    Ok(body.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exporter's own spelling: labels sorted by name, the value in
    /// exponent form, a host name with its root dot.
    const EXPOSITION: &str = r#"# HELP kea_lease_expiry_timestamp_seconds When an active lease expires, with its device.
# TYPE kea_lease_expiry_timestamp_seconds gauge
kea_lease_expiry_timestamp_seconds{device="",family="ipv4",hostname="tablet",ip="192.0.2.55",mac="02:00:00:00:00:01",subnet_id="1"} 1.793572772e+09
kea_lease_expiry_timestamp_seconds{device="Kitchen \"esp\"\nsensor",family="ipv4",hostname="laptop.",ip="192.0.2.132",mac="02:00:00:00:00:02",subnet_id="1"} 1.793585123e+09
kea_lease_expiry_timestamp_seconds{device="",family="ipv6",hostname="<b>x</b>",ip="2001:db8::2",mac="02:00:00:00:00:02",subnet_id="7"} 1.7935e+09
kea_lease_expiry_timestamp_seconds{device="",family="ipv4",hostname="",ip="not-an-ip",mac="02:00:00:00:00:03",subnet_id="1"} 1.79e+09
kea_subnet_addresses{family="ipv4",kind="assigned",subnet="192.0.2.0/24",subnet_id="1"} 28
"#;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn mac(last: u8) -> [u8; 6] {
        [2, 0, 0, 0, 0, last]
    }

    #[test]
    fn the_leases_are_read_from_the_exporters_text() {
        let leases = parse(EXPOSITION);
        assert_eq!(leases.len(), 3);
        assert_eq!(
            leases[0],
            Lease {
                mac: mac(1),
                ip: ip("192.0.2.55"),
                hostname: Some("tablet".into()),
                device: None,
                expires: 1_793_572_772,
            }
        );
        assert_eq!(leases[1].hostname.as_deref(), Some("laptop"));
        assert_eq!(leases[1].device.as_deref(), Some("Kitchen \"esp\" sensor"));
        // A host name that is not one is dropped, the lease kept.
        assert_eq!(
            (leases[2].ip, &leases[2].hostname),
            (ip("2001:db8::2"), &None)
        );
        assert!(
            parse("kea_lease_expiry_timestamp_seconds{mac=\"02:00:00:00:00:01\"} 1").is_empty()
        );
        assert!(
            parse("kea_lease_expiry_timestamp_seconds{ip=\"192.0.2.1\",mac=\"x\"} 1").is_empty()
        );
        assert!(
            parse(
                "kea_lease_expiry_timestamp_seconds{ip=\"192.0.2.1\",mac=\"02:00:00:00:00:01\"} NaN"
            )
            .is_empty()
        );
        assert!(
            parse("kea_lease_expiry_timestamp_seconds{ip=\"192.0.2.1\",mac=\"02:00:00:00:00:01")
                .is_empty()
        );
    }

    #[test]
    fn devices_are_one_short_line() {
        assert_eq!(tidy(" a\tb \n c "), "a b c");
        assert_eq!(tidy(&"é".repeat(100)).len(), 128);
    }

    fn lease(last: u8, ip_: &str, host: Option<&str>, expires: u64) -> Lease {
        Lease {
            mac: mac(last),
            ip: ip(ip_),
            hostname: host.map(str::to_owned),
            device: None,
            expires,
        }
    }

    #[test]
    fn the_union_keeps_the_newest_expiry_of_each_address() {
        let t = UNIX_EPOCH + Duration::from_secs(1000);
        let mut l = Leases::new(&["a:9100".into(), "b:9100".into()]);
        let a = vec![
            lease(1, "192.0.2.1", Some("old"), 2000),
            lease(2, "192.0.2.2", None, 3000),
        ];
        assert!(l.take("a:9100", Ok(a), t));
        let b = vec![
            lease(1, "192.0.2.1", Some("new"), 2500),
            lease(1, "2001:db8::1", None, 2200),
        ];
        assert!(l.take("b:9100", Ok(b), t));
        let one = l.of(&mac(1), t).unwrap();
        assert_eq!(
            one.addresses,
            [(ip("192.0.2.1"), 2500), (ip("2001:db8::1"), 2200)]
        );
        assert_eq!(
            (one.hostname.as_deref(), one.expires()),
            (Some("new"), Some(2500))
        );
        // A failed read keeps the exporter's last leases, until they expire.
        assert!(!l.take("a:9100", Err("refused".into()), t));
        assert_eq!(
            (l.exporters["a:9100"].up, l.exporters["b:9100"].up),
            (Some(false), Some(true))
        );
        assert!(l.of(&mac(2), t).is_some());
        let later = UNIX_EPOCH + Duration::from_secs(2300);
        assert_eq!(
            l.of(&mac(1), later).unwrap().addresses,
            [(ip("192.0.2.1"), 2500)]
        );
        assert_eq!(l.all(later).count(), 2);
        assert_eq!(l.of(&mac(1), UNIX_EPOCH + Duration::from_secs(2500)), None);
        // Unknown exporters are not taken.
        assert!(!l.take("c:9100", Ok(vec![lease(9, "192.0.2.9", None, 9000)]), t));
    }

    #[tokio::test]
    async fn an_exporter_is_read_over_http() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let serve = |answer: &'static str| {
            let listener = &listener;
            async move {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut ask = [0; 1024];
                let n = s.read(&mut ask).await.unwrap();
                assert!(ask[..n].starts_with(b"GET /metrics HTTP/1.0\r\n"));
                s.write_all(answer.as_bytes()).await.unwrap();
            }
        };
        let ok = format!("HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n{EXPOSITION}");
        let (text, ()) = tokio::join!(read(&addr), serve(Box::leak(ok.into_boxed_str())));
        assert_eq!(parse(&text.unwrap()).len(), 3);
        let (r, ()) = tokio::join!(read(&addr), serve("HTTP/1.0 503 Busy\r\n\r\n"));
        assert!(r.unwrap_err().contains("503"));
        let gz = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\nxx";
        let (r, ()) = tokio::join!(read(&addr), serve(gz));
        assert_eq!(r.unwrap_err(), "the body is encoded");
        drop(listener);
        assert!(read(&addr).await.is_err());
    }
}
