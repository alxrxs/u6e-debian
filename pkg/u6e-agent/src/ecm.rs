//! The connections the AP forwards, as the NSS connection manager (ECM)
//! tracks them, summarized per client. ECM's state device dumps its
//! connection database as `conns.conn.<serial>.<field>=<value>` lines, one
//! connection per read; the bytes and packets are those ECM counts, the NSS
//! hardware's included, so no packet is looked at on the CPU. The image asks
//! for the brief record (output mask 4097, nss/patches/qca-nss-ecm/902):
//! addresses, ports, nodes, protocol, totals, `age` and the front end's
//! `accel_mode`, 13 lines where the full record has 175. A connection is
//! offloaded when that mode is ECM's ACCEL, 2: the NSS hardware forwards it.
//! A full record (mask 1, where the mode is in the front end's block, e.g.
//! `nss_v4.ported.accel_mode`) parses too, without its age.
//!
//! Each open of the device starts a new dump, which walks ECM's list by
//! reference, so a connection added or removed meanwhile is either whole in
//! it or absent. The parse streams through a fixed buffer into a table of at
//! most the cap's connections and stops reading there; a record that misses
//! a field it uses (cut short, unreadable) is dropped whole. Either way the
//! table says it is incomplete, and no connection counts from part of its
//! record.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, ErrorKind, Read};
use std::net::IpAddr;
use std::ops::ControlFlow;
use std::path::Path;
use std::str::FromStr;

use u6e_proto::mac;
use u6e_proto::msg::{ClientFlows, Flow, Flows};

/// ECM's state device, under the collectors' root. ECM registers it with a
/// dynamic major and no uevent, so the image creates it (prep-rootfs.sh).
pub const DEVICE: &str = "dev/ecm_state";
/// The most connections one dump is read for, a full table's included.
pub const CAP: usize = 4096;
/// The connections a summary lists per client: with 6, a summary of 17
/// busy clients is 2.7 KB, under 300 B/s at the fastest cadence.
pub const TOP: usize = 6;
/// ECM's `accel_mode` of a connection the hardware forwards
/// (ECM_FRONT_END_ACCELERATION_MODE_ACCEL).
const ACCEL: i32 = 2;
/// ECM's own message buffer: one connection fits in one read.
const BUF: usize = 32 * 1024;

/// One connection; "from" is the end that opened it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conn {
    pub proto: u8,
    pub src: IpAddr,
    pub sport: u16,
    pub src_mac: [u8; 6],
    pub dst: IpAddr,
    pub dport: u16,
    pub dst_mac: [u8; 6],
    /// What the opening end sent, and what the other end sent.
    pub from_bytes: u64,
    pub to_bytes: u64,
    pub from_packets: u64,
    pub to_packets: u64,
    pub offloaded: bool,
    /// Seconds since ECM added it; 0 from a full record, which has none.
    pub age_s: u32,
}

/// The connections of one dump.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct EcmTable {
    pub conns: Vec<Conn>,
    /// False when the dump held more than the cap, broke off, or had a
    /// record it could not read.
    pub complete: bool,
}

/// Reads a dump from the device at `path`, at most `cap` connections of it.
pub fn read(path: &Path, cap: usize) -> io::Result<EcmTable> {
    Ok(parse(File::open(path)?, cap))
}

/// The table in the dump `r`. A record missing a field, and a read error,
/// which ends the dump as a cut, leave out what they spoil and mark the
/// table incomplete.
pub fn parse(r: impl Read, cap: usize) -> EcmTable {
    let mut t = EcmTable {
        conns: Vec::new(),
        complete: true,
    };
    let mut cur: Option<Pending> = None;
    let end = lines(r, |line| {
        let Some((serial, field, value)) = split(line) else {
            return ControlFlow::Continue(());
        };
        if cur.as_ref().is_none_or(|p| p.serial != serial) {
            if let Some(p) = cur.take() {
                t.add(p);
            }
            if t.conns.len() >= cap {
                return ControlFlow::Break(());
            }
            cur = Some(Pending::new(serial));
        }
        if let Some(p) = cur.as_mut() {
            p.set(field, value);
        }
        ControlFlow::Continue(())
    });
    match (end, cur) {
        (Ok(End::Whole), Some(p)) => t.add(p),
        (Ok(End::Whole), None) => {}
        _ => t.complete = false,
    }
    t
}

/// How a dump ended.
enum End {
    /// At the end of a line.
    Whole,
    /// Mid-line: the last record is cut short.
    Cut,
    /// The caller stopped it.
    Capped,
}

/// Calls `each` with every line of `r`, read through a fixed buffer; a line
/// longer than the buffer cannot be one ECM writes, and is skipped.
fn lines(mut r: impl Read, mut each: impl FnMut(&[u8]) -> ControlFlow<()>) -> io::Result<End> {
    let mut buf = vec![0; BUF];
    let (mut len, mut skipping) = (0, false);
    loop {
        let n = match r.read(&mut buf[len..]) {
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if n == 0 {
            return Ok(if len == 0 && !skipping {
                End::Whole
            } else {
                End::Cut
            });
        }
        let end = len + n;
        let mut start = 0;
        while let Some(i) = buf[start..end].iter().position(|&c| c == b'\n') {
            let line = &buf[start..start + i];
            start += i + 1;
            if !std::mem::take(&mut skipping) && each(line).is_break() {
                return Ok(End::Capped);
            }
        }
        if start == 0 && end == buf.len() {
            skipping = true;
            len = 0;
        } else {
            buf.copy_within(start..end, 0);
            len = end - start;
        }
    }
}

/// A connection's serial, and the field and value of one of its lines.
fn split(line: &[u8]) -> Option<(u32, &[u8], &[u8])> {
    let rest = line.strip_prefix(b"conns.conn.")?;
    let dot = rest.iter().position(|&c| c == b'.')?;
    let (serial, rest) = (&rest[..dot], &rest[dot + 1..]);
    let eq = rest.iter().position(|&c| c == b'=')?;
    Some((value(serial)?, &rest[..eq], &rest[eq + 1..]))
}

/// A value as ECM writes it in text; only those of the fields the parse
/// keeps are ever decoded.
fn value<T: FromStr>(v: &[u8]) -> Option<T> {
    std::str::from_utf8(v).ok()?.parse().ok()
}

/// The fields of the connection being read, as they come.
#[derive(Default)]
struct Pending {
    serial: u32,
    proto: Option<u8>,
    src: Option<IpAddr>,
    sport: Option<u16>,
    src_mac: Option<[u8; 6]>,
    dst: Option<IpAddr>,
    dport: Option<u16>,
    dst_mac: Option<[u8; 6]>,
    from_bytes: Option<u64>,
    to_bytes: Option<u64>,
    from_packets: Option<u64>,
    to_packets: Option<u64>,
    accel_mode: Option<i32>,
    age: Option<u32>,
}

impl Pending {
    fn new(serial: u32) -> Self {
        Pending {
            serial,
            ..Pending::default()
        }
    }

    fn set(&mut self, field: &[u8], v: &[u8]) {
        let mac = |v| mac::parse(std::str::from_utf8(v).ok()?);
        match field {
            b"protocol" => self.proto = value(v),
            b"sip_address" => self.src = value(v),
            b"sport" => self.sport = value(v),
            b"snode_address" => self.src_mac = mac(v),
            b"dip_address" => self.dst = value(v),
            b"dport" => self.dport = value(v),
            b"dnode_address" => self.dst_mac = mac(v),
            b"age" => self.age = value(v),
            b"adv_stats.from_data_total" => self.from_bytes = value(v),
            b"adv_stats.to_data_total" => self.to_bytes = value(v),
            b"adv_stats.from_packet_total" => self.from_packets = value(v),
            b"adv_stats.to_packet_total" => self.to_packets = value(v),
            // A full record has it in the front end's block (`nss_v4.ported`,
            // `nss_v6.non_ported`, ...).
            f if f == b"accel_mode" || f.ends_with(b".accel_mode") => {
                self.accel_mode = value(v);
            }
            _ => {}
        }
    }

    fn finish(self) -> Option<Conn> {
        Some(Conn {
            proto: self.proto?,
            src: self.src?,
            sport: self.sport?,
            src_mac: self.src_mac?,
            dst: self.dst?,
            dport: self.dport?,
            dst_mac: self.dst_mac?,
            from_bytes: self.from_bytes?,
            to_bytes: self.to_bytes?,
            from_packets: self.from_packets?,
            to_packets: self.to_packets?,
            offloaded: self.accel_mode? == ACCEL,
            age_s: self.age.unwrap_or(0),
        })
    }
}

impl EcmTable {
    /// The connection `p` read, or, when it misses a field, the mark that
    /// one is left out.
    fn add(&mut self, p: Pending) {
        match p.finish() {
            Some(c) => self.conns.push(c),
            None => self.complete = false,
        }
    }

    /// Each station's connections, by MAC: totals over all of them and its
    /// largest [`TOP`] by bytes, or every one when `full`. A connection
    /// between two stations counts for both; one of no station is left out,
    /// and so is a station without connections.
    pub fn flows(&self, seq: u64, stations: &[[u8; 6]], full: bool) -> Flows {
        let stations: BTreeSet<[u8; 6]> = stations.iter().copied().collect();
        let mut per: BTreeMap<[u8; 6], Vec<Flow>> = BTreeMap::new();
        for c in &self.conns {
            if stations.contains(&c.src_mac) {
                per.entry(c.src_mac).or_default().push(flow(c, true));
            }
            // A connection a station has with itself counts once.
            if c.dst_mac != c.src_mac && stations.contains(&c.dst_mac) {
                per.entry(c.dst_mac).or_default().push(flow(c, false));
            }
        }
        let clients = per
            .into_iter()
            .map(|(mac, mut top)| {
                let sum = |f: fn(&Flow) -> u64| top.iter().map(f).sum();
                let summary = ClientFlows {
                    mac,
                    conns: top.len() as u32,
                    offloaded: top.iter().filter(|f| f.offloaded).count() as u32,
                    tx_bytes: sum(|f| f.tx_bytes),
                    rx_bytes: sum(|f| f.rx_bytes),
                    tx_packets: sum(|f| f.tx_packets),
                    rx_packets: sum(|f| f.rx_packets),
                    top: Vec::new(),
                };
                // Stable: equal ones keep the dump's order, newest first.
                top.sort_by_key(|f| Reverse(f.tx_bytes + f.rx_bytes));
                if !full {
                    top.truncate(TOP);
                }
                ClientFlows { top, ..summary }
            })
            .collect();
        Flows {
            seq,
            complete: self.complete,
            clients,
        }
    }
}

/// `c` as the station at its opening end (`opened`) or at the other sees it.
fn flow(c: &Conn, opened: bool) -> Flow {
    let (tx_bytes, rx_bytes, tx_packets, rx_packets) = if opened {
        (c.from_bytes, c.to_bytes, c.from_packets, c.to_packets)
    } else {
        (c.to_bytes, c.from_bytes, c.to_packets, c.from_packets)
    };
    Flow {
        proto: c.proto,
        src: c.src,
        sport: c.sport,
        dst: c.dst,
        dport: c.dport,
        tx_bytes,
        rx_bytes,
        tx_packets,
        rx_packets,
        offloaded: c.offloaded,
        age_s: c.age_s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Recorded on an AP, in full records (mask 1): its 12 newest
    /// connections and the newest the hardware does not forward. Its
    /// stations are 02:00:00:00:00:08 to :18; :19 is the gateway, :1b and :1c
    /// wired hosts.
    const FIXTURE: &str = include_str!("../tests/fixtures/ecm-state.txt");

    const fn m(n: u8) -> [u8; 6] {
        [2, 0, 0, 0, 0, n]
    }

    fn stations() -> Vec<[u8; 6]> {
        (0x08..=0x18).map(m).collect()
    }

    fn v4(n: u8) -> IpAddr {
        Ipv4Addr::new(192, 0, 2, n).into()
    }

    /// A connection's brief record, as the image's ECM writes it.
    fn record(serial: u32, from: [u8; 6], to: [u8; 6], bytes: [u64; 2]) -> String {
        let p = format!("conns.conn.{serial}");
        [
            "sip_address=192.0.2.1".into(),
            format!("sport={}", 1000 + serial % 60000),
            format!("snode_address={}", mac::format(from)),
            "dip_address=192.0.2.2".into(),
            "dport=443".into(),
            format!("dnode_address={}", mac::format(to)),
            "protocol=6".into(),
            format!("adv_stats.from_data_total={}", bytes[0]),
            format!("adv_stats.to_data_total={}", bytes[1]),
            "adv_stats.from_packet_total=3".into(),
            "adv_stats.to_packet_total=4".into(),
            "age=10".into(),
            "accel_mode=2".into(),
        ]
        .iter()
        .map(|l| format!("{p}.{l}\n"))
        .collect()
    }

    /// Hands out its bytes `chunk` at a time, then fails if `fail`.
    struct Trickle<'a> {
        data: &'a [u8],
        chunk: usize,
        fail: bool,
    }

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.data.is_empty() && self.fail {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            let n = self.chunk.min(buf.len()).min(self.data.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            Ok(n)
        }
    }

    #[test]
    fn the_fixture_parses_exactly() {
        let t = parse(FIXTURE.as_bytes(), CAP);
        assert!(t.complete);
        assert_eq!(t.conns.len(), 13);
        assert_eq!(
            t.conns[0],
            Conn {
                proto: 17,
                src: v4(1),
                sport: 38031,
                src_mac: m(0x08),
                dst: v4(2),
                dport: 9930,
                dst_mac: m(0x19),
                from_bytes: 100,
                to_bytes: 473,
                from_packets: 1,
                to_packets: 1,
                offloaded: true,
                age_s: 0,
            }
        );
        // ECM writes every IPv6 group in full.
        assert_eq!(t.conns[2].src, "2001:db8::5".parse::<IpAddr>().unwrap());
        assert_eq!(
            t.conns[12],
            Conn {
                proto: 6,
                src: v4(13),
                sport: 33318,
                src_mac: m(0x1c),
                dst: v4(12),
                dport: 9000,
                dst_mac: m(0x16),
                from_bytes: 540,
                to_bytes: 0,
                from_packets: 9,
                to_packets: 0,
                offloaded: false,
                age_s: 0,
            }
        );
        assert_eq!(t.conns.iter().filter(|c| c.offloaded).count(), 12);
    }

    /// Any split of the reads gives the same table.
    #[test]
    fn a_brief_record_parses_exactly() {
        let t = parse(record(7, m(1), m(9), [100, 900]).as_bytes(), CAP);
        assert!(t.complete);
        assert_eq!(
            t.conns,
            [Conn {
                proto: 6,
                src: v4(1),
                sport: 1007,
                src_mac: m(1),
                dst: v4(2),
                dport: 443,
                dst_mac: m(9),
                from_bytes: 100,
                to_bytes: 900,
                from_packets: 3,
                to_packets: 4,
                offloaded: true,
                age_s: 10,
            }]
        );
    }

    #[test]
    fn the_parse_does_not_depend_on_how_the_reads_split() {
        let whole = parse(FIXTURE.as_bytes(), CAP);
        for chunk in [1, 7, 4096, BUF - 1] {
            let r = Trickle {
                data: FIXTURE.as_bytes(),
                chunk,
                fail: false,
            };
            assert_eq!(parse(r, CAP), whole, "chunk {chunk}");
        }
    }

    #[test]
    fn each_station_gets_its_totals_and_largest_connections() {
        let f = parse(FIXTURE.as_bytes(), CAP).flows(7, &stations(), false);
        assert_eq!((f.seq, f.complete), (7, true));
        let macs: Vec<_> = f.clients.iter().map(|c| c.mac).collect();
        assert_eq!(macs, [m(0x08), m(0x0e), m(0x0f), m(0x16)]);
        let v6 = |n: u16| IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, n]);
        // :0f is the far end of an mDNS connection a wired host opened, so it
        // sent none of its bytes.
        assert_eq!(
            f.clients[2],
            ClientFlows {
                mac: m(0x0f),
                conns: 3,
                offloaded: 3,
                tx_bytes: 15531,
                rx_bytes: 24563,
                tx_packets: 26,
                rx_packets: 32,
                top: vec![
                    Flow {
                        proto: 17,
                        src: v6(5),
                        sport: 64798,
                        dst: v6(7),
                        dport: 443,
                        tx_bytes: 11132,
                        rx_bytes: 21498,
                        tx_packets: 21,
                        rx_packets: 26,
                        offloaded: true,
                        age_s: 0,
                    },
                    Flow {
                        proto: 17,
                        src: v6(5),
                        sport: 61126,
                        dst: v6(6),
                        dport: 443,
                        tx_bytes: 4399,
                        rx_bytes: 2784,
                        tx_packets: 5,
                        rx_packets: 5,
                        offloaded: true,
                        age_s: 0,
                    },
                    Flow {
                        proto: 17,
                        src: v4(3),
                        sport: 41670,
                        dst: v4(4),
                        dport: 5353,
                        tx_bytes: 0,
                        rx_bytes: 281,
                        tx_packets: 0,
                        rx_packets: 1,
                        offloaded: true,
                        age_s: 0,
                    },
                ],
            }
        );
        let c = &f.clients[1];
        assert_eq!(
            (c.conns, c.offloaded, c.tx_bytes, c.rx_bytes),
            (5, 5, 5720, 6851)
        );
        // By bytes; the two of 248 B in the dump's order.
        let ports: Vec<_> = c.top.iter().map(|f| f.sport).collect();
        assert_eq!(ports, [47394, 20764, 51135, 8719, 20422]);
        let c = &f.clients[3];
        assert_eq!(
            (c.conns, c.offloaded, c.tx_bytes, c.rx_bytes, c.rx_packets),
            (2, 1, 87, 882, 10)
        );
        assert!(!c.top[0].offloaded);
    }

    #[test]
    fn non_station_flows_are_ignored() {
        let t = parse(FIXTURE.as_bytes(), CAP);
        let f = t.flows(1, &[m(0x08)], false);
        assert_eq!(f.clients.len(), 1);
        assert_eq!((f.clients[0].conns, f.clients[0].tx_bytes), (3, 300));
        assert!(t.flows(1, &[], false).clients.is_empty());
        // A station that is not this AP's is not one of its clients.
        assert!(t.flows(1, &[m(0x30)], false).clients.is_empty());
    }

    #[test]
    fn a_flow_between_two_stations_counts_for_both() {
        let dump = record(5, m(1), m(2), [100, 900]) + &record(6, m(3), m(3), [5, 5]);
        let f = parse(dump.as_bytes(), CAP).flows(1, &[m(1), m(2), m(3)], false);
        let view: Vec<_> = f
            .clients
            .iter()
            .map(|c| (c.mac, c.conns, c.tx_bytes, c.rx_bytes, c.tx_packets))
            .collect();
        assert_eq!(
            view,
            [
                (m(1), 1, 100, 900, 3),
                (m(2), 1, 900, 100, 4),
                // With itself: once.
                (m(3), 1, 5, 5, 3),
            ]
        );
        assert_eq!(f.clients[0].top[0].src, f.clients[1].top[0].src);
    }

    #[test]
    fn a_summary_lists_the_largest_six_and_a_full_table_every_one() {
        let dump: String = (0..10)
            .map(|i| record(i, m(1), m(9), [i.into(), 0]))
            .collect();
        let t = parse(dump.as_bytes(), CAP);
        let f = t.flows(1, &[m(1)], false);
        let sent: Vec<_> = f.clients[0].top.iter().map(|f| f.tx_bytes).collect();
        assert_eq!(sent, [9, 8, 7, 6, 5, 4]);
        assert_eq!((f.clients[0].conns, f.clients[0].tx_bytes), (10, 45));
        assert_eq!(t.flows(1, &[m(1)], true).clients[0].top.len(), 10);
    }

    /// A table larger than the cap: the first `cap` connections, marked
    /// incomplete, and the dump read no further than it takes to see that.
    #[test]
    fn ecm_overflow_capped() {
        let dump: String = (0..5000).map(|i| record(i, m(1), m(9), [1, 1])).collect();
        let mut r = Trickle {
            data: dump.as_bytes(),
            chunk: BUF,
            fail: false,
        };
        let t = parse(&mut r, CAP);
        assert_eq!((t.conns.len(), t.complete), (CAP, false));
        // 904 of the 5000 records are left, less what one read took.
        assert!(r.data.len() > dump.len() / 6, "read on past the cap");
        let f = t.flows(1, &[m(1)], true);
        assert_eq!((f.complete, f.clients[0].conns), (false, CAP as u32));
        // Exactly the cap is a whole table.
        let exact: String = (0..4).map(|i| record(i, m(1), m(9), [1, 1])).collect();
        let t = parse(exact.as_bytes(), 4);
        assert_eq!((t.conns.len(), t.complete), (4, true));
    }

    /// A record cut short (the dump ended or failed mid-record) or garbled is
    /// left out whole, and the table says it is incomplete.
    #[test]
    fn ecm_truncated_record() {
        let whole = parse(FIXTURE.as_bytes(), CAP);
        let accel = FIXTURE
            .find("conns.conn.1195.nss_v4.ported.accel_mode")
            .unwrap();
        // Before the field the record needs last, and mid-line in it.
        for cut in [accel, accel + 20] {
            let t = parse(&FIXTURE.as_bytes()[..cut], CAP);
            assert_eq!(t.conns, whole.conns[..12], "cut at {cut}");
            assert!(!t.complete);
        }
        let r = Trickle {
            data: &FIXTURE.as_bytes()[..accel + 20],
            chunk: 4096,
            fail: true,
        };
        let t = parse(r, CAP);
        assert_eq!((t.conns.len(), t.complete), (12, false));
        let garbled = FIXTURE.replacen("sport=38031", "sport=38031x", 1);
        let t = parse(garbled.as_bytes(), CAP);
        assert_eq!(t.conns, whole.conns[1..]);
        assert!(!t.complete);
        let f = t.flows(1, &stations(), false);
        let c = f.clients.iter().find(|c| c.mac == m(0x08)).unwrap();
        assert_eq!((c.conns, c.tx_bytes), (2, 200));
    }

    #[test]
    fn a_line_longer_than_the_buffer_is_skipped() {
        let long = format!("conns.conn.5.x={}\n", "y".repeat(3 * BUF));
        let dump = record(5, m(1), m(9), [1, 2]).replacen('\n', &format!("\n{long}"), 1);
        let t = parse(dump.as_bytes(), CAP);
        assert_eq!((t.conns.len(), t.complete), (1, true));
    }
}
