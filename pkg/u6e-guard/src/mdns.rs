//! mDNS messages (RFC 6762, DNS-SD RFC 6763), read from the frames the
//! guards' socket takes: the header, each question's name, type and QU bit,
//! each record's name, type and TTL, and of the records' data only what the
//! services table uses (PTR and SRV names, the SRV port, A and AAAA
//! addresses, the TXT keys of [`TXT_KEYS`]); every other byte is read past
//! and dropped with the frame.
//!
//! Hostile input stays bounded: every read is checked against the end of
//! the payload; a compression pointer must point strictly before the part of
//! the name it continues, so decompression always ends, and a name is at
//! most 255 bytes on the wire; a message yields at most [`QUESTIONS`]
//! questions and [`RECORDS`] records, and its names take at most [`STEPS`]
//! labels and pointers in all, so no message costs more than a few times a
//! real one. A name is read as a key and its kind alone; its text is made
//! only for the names the table keeps, at most [`TEXT_MAX`] bytes. A message
//! cut short, or malformed or over its steps past its header, yields what
//! read whole before the fault, marked incomplete.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use u6e_proto::text;

pub const PORT: u16 = 5353;
/// The most questions and records read of one message.
pub const QUESTIONS: usize = 64;
pub const RECORDS: usize = 128;
/// The longest name on the wire, length bytes and root included (RFC 1035).
const NAME_MAX: usize = 255;
/// The labels and pointers all the names of one message may take: a
/// response of 128 compressed records takes some 1200.
pub const STEPS: usize = 2048;
/// The longest text kept of a name, in bytes; a longer one ends in `…`.
pub const TEXT_MAX: usize = 160;
/// The TXT keys kept, each value at most [`TXT_VALUE_MAX`] bytes: the
/// model, and an AirPlay group's id, leader flag and name and the timing
/// group (`tsid`) its members share.
pub const TXT_KEYS: [&str; 6] = ["model", "md", "gid", "igl", "gpn", "tsid"];
pub const TXT_VALUE_MAX: usize = 64;

pub const PTR: u16 = 12;
pub const SRV: u16 = 33;
pub const TXT: u16 = 16;
pub const A: u16 = 1;
pub const AAAA: u16 = 28;

/// The top bit of a question's class asks for a unicast answer (QU); of a
/// record's, that it replaces what the cache holds (cache flush).
const TOP_BIT: u16 = 0x8000;

/// What a name is to DNS-SD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A service type: `_name._tcp.local` or `_name._udp.local`.
    Service,
    /// A service instance: one label before a service type.
    Instance,
    Other,
}

/// A name as the table compares it: a hash of its labels in lower case,
/// its kind, of an instance its service type's hash, and where it starts in
/// its message, to read its text from when it is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Name {
    pub at: usize,
    pub key: u64,
    pub kind: Kind,
    pub service: Option<u64>,
    /// Its last label is `local`.
    pub local: bool,
}

impl Name {
    /// Its labels joined by dots (a dot or backslash inside a label escaped
    /// with a backslash, control and format characters dropped).
    pub fn text(&self, msg: &[u8]) -> String {
        text_of(msg, self.at, 0)
    }

    /// The service type of an instance, as `text` reads it.
    pub fn service_text(&self, msg: &[u8]) -> Option<String> {
        self.service.map(|_| text_of(msg, self.at, 1))
    }

    pub fn service_key(&self) -> Option<u64> {
        self.service
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: Name,
    pub qtype: u16,
    pub unicast: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Answer,
    Authority,
    Additional,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Data {
    Ptr(Name),
    Srv {
        port: u16,
        target: Name,
    },
    Txt(Vec<(String, String)>),
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    /// A type the table does not use, or data of the wrong length.
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: Name,
    pub rtype: u16,
    pub ttl: u32,
    pub section: Section,
    pub data: Data,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub response: bool,
    pub questions: Vec<Question>,
    pub records: Vec<Record>,
    /// Whether every question and record its header counts read whole.
    pub complete: bool,
}

impl Message {
    /// A query with records in its authority section probes for the
    /// uniqueness of the names they claim (RFC 6762 8.1): it asks nobody.
    pub fn is_probe(&self) -> bool {
        !self.response && self.records.iter().any(|r| r.section == Section::Authority)
    }
}

/// The UDP payload of `frame` (Ethernet) and its sender's address, when it
/// is UDP to or from the mDNS port: IPv4 (a first fragment as far as it
/// goes, no later one) or IPv6 with UDP right after its header.
pub fn payload(frame: &[u8]) -> Option<(IpAddr, &[u8])> {
    let ip = frame.get(14..)?;
    let (src, l4) = match u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]) {
        0x0800 => {
            let ihl = usize::from(*ip.first()? & 0x0f) * 4;
            let offset = u16::from_be_bytes([*ip.get(6)?, *ip.get(7)?]) & 0x1fff;
            if ihl < 20 || *ip.get(9)? != 17 || offset != 0 {
                return None;
            }
            let src: [u8; 4] = ip.get(12..16)?.try_into().ok()?;
            (IpAddr::from(src), ip.get(ihl..)?)
        }
        0x86dd => {
            if *ip.get(6)? != 17 {
                return None;
            }
            let src: [u8; 16] = ip.get(8..24)?.try_into().ok()?;
            (IpAddr::from(src), ip.get(40..)?)
        }
        _ => return None,
    };
    let sport = u16::from_be_bytes([*l4.first()?, *l4.get(1)?]);
    let dport = u16::from_be_bytes([*l4.get(2)?, *l4.get(3)?]);
    if sport != PORT && dport != PORT {
        return None;
    }
    // A first fragment holds less than its length says.
    let len = usize::from(u16::from_be_bytes([*l4.get(4)?, *l4.get(5)?]));
    let end = if (8..=l4.len()).contains(&len) {
        len
    } else {
        l4.len()
    };
    Some((src, l4.get(8..end)?))
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// FNV-1a over a name's labels, each in lower case and after its length.
struct Hasher(u64);

impl Hasher {
    fn new() -> Self {
        Hasher(0xcbf2_9ce4_8422_2325)
    }

    fn label(&mut self, label: &[u8]) {
        let len = [label.len() as u8];
        for b in len.iter().chain(label) {
            self.0 = (self.0 ^ u64::from(b.to_ascii_lowercase())).wrapping_mul(0x0100_0000_01b3);
        }
    }
}

/// Walks the name at `at` in `msg`, label by label to `label`, taking a
/// step of `steps` for each label and each pointer; where the bytes after
/// it start, or `None` for a name that does not read: past the end, a label
/// type other than a plain one or a pointer, a pointer to itself or to
/// anything not strictly before the part it continues, longer than
/// [`NAME_MAX`], or out of steps.
fn walk<'a>(
    msg: &'a [u8],
    at: usize,
    steps: &mut usize,
    mut label: impl FnMut(&'a [u8]),
) -> Option<usize> {
    let (mut pos, mut limit, mut after, mut wire) = (at, at, None, 1);
    loop {
        let len = *msg.get(pos)?;
        if len != 0 {
            *steps = steps.checked_sub(1)?;
        }
        match len & 0xc0 {
            0x00 if len == 0 => return Some(after.unwrap_or(pos + 1)),
            0x00 => {
                let l = msg.get(pos + 1..pos + 1 + usize::from(len))?;
                wire += 1 + l.len();
                if wire > NAME_MAX {
                    return None;
                }
                label(l);
                pos += 1 + l.len();
            }
            0xc0 => {
                let ptr = usize::from(u16_at(msg, pos)? & 0x3fff);
                after.get_or_insert(pos + 2);
                // Strictly backwards: the walk ends.
                if ptr >= limit {
                    return None;
                }
                (pos, limit) = (ptr, ptr);
            }
            _ => return None,
        }
    }
}

/// The name at `at` in `msg` and where the bytes after it start, the steps
/// it takes off `steps`; `None` for one that does not read (`walk`).
pub fn name(msg: &[u8], at: usize, steps: &mut usize) -> Option<(Name, usize)> {
    let mut all = Hasher::new();
    let mut first: [&[u8]; 4] = [&[]; 4];
    let (mut n, mut last): (usize, &[u8]) = (0, &[]);
    let after = walk(msg, at, steps, |l| {
        all.label(l);
        if let Some(f) = first.get_mut(n) {
            *f = l;
        }
        (n, last) = (n + 1, l);
    })?;
    let kind = kind_of(&first[..n.min(4)], n);
    let name = Name {
        at,
        key: all.0,
        kind,
        // An instance has four labels, its type the last three.
        service: (kind == Kind::Instance).then(|| {
            let mut rest = Hasher::new();
            first[1..].iter().for_each(|l| rest.label(l));
            rest.0
        }),
        local: last.eq_ignore_ascii_case(b"local"),
    };
    Some((name, after))
}

/// The text of the name at `at` in `msg` (one that read), from its label
/// `from`, at most [`TEXT_MAX`] bytes.
fn text_of(msg: &[u8], at: usize, from: usize) -> String {
    let mut text = String::new();
    let mut i = 0;
    let mut unlimited = usize::MAX;
    walk(msg, at, &mut unlimited, |label| {
        if i >= from {
            if i > from {
                text.push('.');
            }
            for c in text::clean(&String::from_utf8_lossy(label)).chars() {
                if c == '.' || c == '\\' {
                    text.push('\\');
                }
                text.push(c);
            }
        }
        i += 1;
    });
    if text.len() > TEXT_MAX {
        let mut end = TEXT_MAX - '…'.len_utf8();
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push('…');
    }
    text
}

/// The kind of a name of `n` labels, the first four `labels`.
fn kind_of(labels: &[&[u8]], n: usize) -> Kind {
    // The name that lists the service types reads as an instance of one.
    let meta = labels
        .first()
        .is_some_and(|l| l.eq_ignore_ascii_case(b"_services"));
    if n == 3 && is_service(labels) {
        Kind::Service
    } else if n == 4 && is_service(&labels[1..]) && !meta {
        Kind::Instance
    } else {
        Kind::Other
    }
}

/// Whether `labels` are a DNS-SD service type, `_name._tcp.local` or
/// `_name._udp.local`.
fn is_service(labels: &[&[u8]]) -> bool {
    let is = |l: &[u8], s: &str| l.eq_ignore_ascii_case(s.as_bytes());
    match labels {
        [svc, proto, local] => {
            svc.len() > 1
                && svc[0] == b'_'
                && (is(proto, "_tcp") || is(proto, "_udp"))
                && is(local, "local")
        }
        _ => false,
    }
}

/// The message in `payload`; `None` when not even its header reads.
pub fn parse(payload: &[u8]) -> Option<Message> {
    let flags = u16_at(payload, 2)?;
    let count = |at| usize::from(u16_at(payload, at).unwrap_or_default());
    let (qd, an, ns, ar) = (count(4), count(6), count(8), count(10));
    let mut m = Message {
        response: flags & 0x8000 != 0,
        questions: Vec::new(),
        records: Vec::new(),
        complete: payload.len() >= 12,
    };
    let (mut at, mut steps) = (12, STEPS);
    for _ in 0..qd {
        if m.questions.len() == QUESTIONS {
            m.complete = false;
            return Some(m);
        }
        let Some((q, next)) = question(payload, at, &mut steps) else {
            m.complete = false;
            return Some(m);
        };
        m.questions.push(q);
        at = next;
    }
    let sections = [
        (Section::Answer, an),
        (Section::Authority, ns),
        (Section::Additional, ar),
    ];
    for (section, n) in sections {
        for _ in 0..n {
            if m.records.len() == RECORDS {
                m.complete = false;
                return Some(m);
            }
            let Some((r, next)) = record(payload, at, section, &mut steps) else {
                m.complete = false;
                return Some(m);
            };
            m.records.push(r);
            at = next;
        }
    }
    Some(m)
}

fn question(msg: &[u8], at: usize, steps: &mut usize) -> Option<(Question, usize)> {
    let (qname, at) = name(msg, at, steps)?;
    let qtype = u16_at(msg, at)?;
    let class = u16_at(msg, at + 2)?;
    let q = Question {
        name: qname,
        qtype,
        unicast: class & TOP_BIT != 0,
    };
    Some((q, at + 4))
}

fn record(msg: &[u8], at: usize, section: Section, steps: &mut usize) -> Option<(Record, usize)> {
    let (owner, at) = name(msg, at, steps)?;
    let rtype = u16_at(msg, at)?;
    let ttl = u32_at(msg, at + 4)?;
    let len = usize::from(u16_at(msg, at + 8)?);
    let start = at + 10;
    let end = start + len;
    let rdata = msg.get(start..end)?;
    // A name in the data may point back into the message, but must end
    // within the data.
    let mut name_in = |at| name(msg, at, steps).filter(|(_, after)| *after <= end);
    let data = match (rtype, len) {
        (PTR, _) => name_in(start).map_or(Data::Other, |(n, _)| Data::Ptr(n)),
        (SRV, 7..) => name_in(start + 6).map_or(Data::Other, |(target, _)| Data::Srv {
            port: u16_at(rdata, 4).unwrap_or_default(),
            target,
        }),
        (TXT, _) => Data::Txt(txt(rdata)),
        (A, 4) => Data::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
        (AAAA, 16) => {
            let o: [u8; 16] = rdata.try_into().ok()?;
            Data::Aaaa(o.into())
        }
        _ => Data::Other,
    };
    let r = Record {
        name: owner,
        rtype,
        ttl,
        section,
        data,
    };
    Some((r, end))
}

/// The keys of [`TXT_KEYS`] in a TXT record's strings, each only as it
/// first comes (RFC 6763 6.4), with its value when that is short and reads
/// as text.
fn txt(mut rdata: &[u8]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    while let Some((&len, rest)) = rdata.split_first() {
        let Some(s) = rest.get(..usize::from(len)) else {
            break;
        };
        rdata = &rest[usize::from(len)..];
        let (k, v) = match s.iter().position(|&b| b == b'=') {
            Some(i) => (&s[..i], &s[i + 1..]),
            None => (s, &[][..]),
        };
        let Some(key) = TXT_KEYS
            .iter()
            .find(|t| k.eq_ignore_ascii_case(t.as_bytes()))
        else {
            continue;
        };
        if seen.contains(key) {
            continue;
        }
        seen.push(key);
        if v.len() > TXT_VALUE_MAX {
            continue;
        }
        if let Ok(v) = std::str::from_utf8(v) {
            out.push(((*key).to_owned(), text::clean(v)));
        }
    }
    out
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Writes mDNS messages, compressing each name against the suffixes
    /// written before it, as responders do.
    #[derive(Default)]
    pub struct Builder {
        pub out: Vec<u8>,
        suffixes: HashMap<Vec<String>, u16>,
        counts: [u16; 4],
        pub compress: bool,
    }

    /// A record's data, for [`Builder::record`].
    pub enum Rd<'a> {
        Ptr(&'a str),
        Srv(u16, &'a str),
        Txt(&'a [&'a str]),
        A([u8; 4]),
        Aaaa(Ipv6Addr),
        Raw(&'a [u8]),
    }

    fn labels(name: &str) -> Vec<String> {
        // Splits on dots not escaped by a backslash.
        let mut out = vec![String::new()];
        let mut chars = name.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => out.last_mut().unwrap().extend(chars.next()),
                '.' => out.push(String::new()),
                _ => out.last_mut().unwrap().push(c),
            }
        }
        out
    }

    impl Builder {
        pub fn new(response: bool) -> Self {
            let mut b = Builder {
                compress: true,
                ..Builder::default()
            };
            let flags: u16 = if response { 0x8400 } else { 0 };
            b.out.extend([0, 0]);
            b.out.extend(flags.to_be_bytes());
            b.out.extend([0; 8]);
            b
        }

        pub fn name(&mut self, name: &str) {
            let labels = labels(name);
            for i in 0..labels.len() {
                if self.compress
                    && let Some(&at) = self.suffixes.get(&labels[i..])
                {
                    self.out.extend((0xc000 | at).to_be_bytes());
                    return;
                }
                if let Ok(at) = u16::try_from(self.out.len())
                    && at < 0x4000
                {
                    self.suffixes.insert(labels[i..].to_vec(), at);
                }
                self.out.push(labels[i].len() as u8);
                self.out.extend(labels[i].as_bytes());
            }
            self.out.push(0);
        }

        fn count(&mut self, i: usize) {
            self.counts[i] += 1;
            let at = 4 + 2 * i;
            self.out[at..at + 2].copy_from_slice(&self.counts[i].to_be_bytes());
        }

        pub fn question(&mut self, name: &str, qtype: u16, unicast: bool) -> &mut Self {
            self.name(name);
            self.out.extend(qtype.to_be_bytes());
            self.out
                .extend((1 | if unicast { TOP_BIT } else { 0 }).to_be_bytes());
            self.count(0);
            self
        }

        /// A record in section `section` (1 answer, 2 authority, 3
        /// additional).
        pub fn record(
            &mut self,
            section: usize,
            name: &str,
            rtype: u16,
            ttl: u32,
            rd: Rd,
        ) -> &mut Self {
            self.name(name);
            self.out.extend(rtype.to_be_bytes());
            self.out.extend((1 | TOP_BIT).to_be_bytes());
            self.out.extend(ttl.to_be_bytes());
            let len_at = self.out.len();
            self.out.extend([0, 0]);
            match rd {
                Rd::Ptr(n) => self.name(n),
                Rd::Srv(port, target) => {
                    self.out.extend([0, 0, 0, 0]);
                    self.out.extend(port.to_be_bytes());
                    self.name(target);
                }
                Rd::Txt(strings) => {
                    for s in strings {
                        self.out.push(s.len() as u8);
                        self.out.extend(s.as_bytes());
                    }
                }
                Rd::A(a) => self.out.extend(a),
                Rd::Aaaa(a) => self.out.extend(a.octets()),
                Rd::Raw(r) => self.out.extend(r),
            }
            let len = (self.out.len() - len_at - 2) as u16;
            self.out[len_at..len_at + 2].copy_from_slice(&len.to_be_bytes());
            self.count(section);
            self
        }

        pub fn bytes(&self) -> Vec<u8> {
            self.out.clone()
        }
    }

    /// A HomePod's response to a browse for AirPlay: its PTR, SRV, TXT and
    /// addresses, as its answers and additional records.
    pub fn airplay_response(instance: &str, host: &str, txt: &[&str]) -> Vec<u8> {
        let mut b = Builder::new(true);
        let full = format!("{instance}._airplay._tcp.local");
        let host = format!("{host}.local");
        b.record(1, "_airplay._tcp.local", PTR, 4500, Rd::Ptr(&full))
            .record(3, &full, SRV, 120, Rd::Srv(7000, &host))
            .record(3, &full, TXT, 4500, Rd::Txt(txt))
            .record(3, &host, A, 120, Rd::A([192, 0, 2, 20]))
            .record(3, &host, AAAA, 120, Rd::Aaaa("fe80::20".parse().unwrap()));
        b.bytes()
    }

    #[test]
    fn a_response_reads_whole() {
        let msg = airplay_response(
            "Living Room",
            "Living-Room",
            &[
                "model=AudioAccessory5,1",
                "gid=1234",
                "pk=abcdef",
                "igl=1",
                "gpn=Room",
            ],
        );
        let m = parse(&msg).unwrap();
        assert!(m.response && m.complete && m.questions.is_empty());
        assert_eq!(m.records.len(), 5);
        let ptr = &m.records[0];
        assert_eq!(ptr.name.text(&msg), "_airplay._tcp.local");
        assert_eq!(ptr.name.kind, Kind::Service);
        assert_eq!(ptr.section, Section::Answer);
        let Data::Ptr(instance) = &ptr.data else {
            panic!()
        };
        assert_eq!(instance.text(&msg), "Living Room._airplay._tcp.local");
        assert_eq!(instance.kind, Kind::Instance);
        assert_eq!(
            instance.service_text(&msg).as_deref(),
            Some("_airplay._tcp.local")
        );
        assert_eq!(instance.service_key(), Some(ptr.name.key));
        let Data::Srv { port, target } = &m.records[1].data else {
            panic!()
        };
        assert_eq!(
            (*port, target.text(&msg).as_str()),
            (7000, "Living-Room.local")
        );
        assert_eq!(m.records[1].name.key, instance.key);
        assert_eq!(
            m.records[2].data,
            Data::Txt(vec![
                ("model".into(), "AudioAccessory5,1".into()),
                ("gid".into(), "1234".into()),
                ("igl".into(), "1".into()),
                ("gpn".into(), "Room".into()),
            ])
        );
        assert_eq!(m.records[3].data, Data::A(Ipv4Addr::new(192, 0, 2, 20)));
        assert_eq!(m.records[4].ttl, 120);
        assert!(!m.is_probe());
    }

    #[test]
    fn names_compare_without_case_and_read_their_escapes() {
        let mut b = Builder::new(false);
        b.question("_AirPlay._TCP.Local", PTR, true)
            .question("_airplay._tcp.local", PTR, false)
            .question("a\\.b\\\\c._raop._udp.local", SRV, false)
            .question("_services._dns-sd._udp.local", PTR, false)
            .question("10.2.0.192.in-addr.arpa", PTR, false);
        let msg = b.bytes();
        let m = parse(&msg).unwrap();
        let q = &m.questions;
        assert_eq!(q[0].name.key, q[1].name.key);
        assert_ne!(q[0].name.text(&msg), q[1].name.text(&msg));
        assert!(q[0].unicast && !q[1].unicast);
        assert_eq!(q[2].name.text(&msg), "a\\.b\\\\c._raop._udp.local");
        assert_eq!(q[2].name.kind, Kind::Instance);
        assert_eq!(
            q[2].name.service_text(&msg).as_deref(),
            Some("_raop._udp.local")
        );
        assert_eq!(q[3].name.kind, Kind::Other);
        assert_eq!(q[4].name.kind, Kind::Other);
    }

    #[test]
    fn txt_keeps_its_first_short_allowed_keys() {
        let long = format!("gpn={}", "x".repeat(TXT_VALUE_MAX + 1));
        let rd: Vec<u8> = [
            "MODEL=One",
            "model=Two",
            "md",
            &long,
            "gid=\u{202e}evil",
            "deviceid=02:00:00:00:00:01",
        ]
        .iter()
        .flat_map(|s| {
            let mut v = vec![s.len() as u8];
            v.extend(s.as_bytes());
            v
        })
        .chain([5, b'i', b'g', b'l'])
        .collect();
        assert_eq!(
            txt(&rd),
            [
                ("model".into(), "One".into()),
                ("md".into(), String::new()),
                ("gid".into(), "evil".into()),
            ]
        );
        // A first copy too long to keep still wins over a later one.
        let twice: Vec<u8> = [long.as_str(), "gpn=Room"]
            .iter()
            .flat_map(|s| {
                let mut v = vec![s.len() as u8];
                v.extend(s.as_bytes());
                v
            })
            .collect();
        assert_eq!(txt(&twice), []);
        assert_eq!(
            txt(&[0, 0, 3, b'i', b'g', b'l']),
            [("igl".into(), String::new())]
        );
    }

    #[test]
    fn a_probe_asks_nobody() {
        let mut b = Builder::new(false);
        b.question("Living-Room.local", 255, true).record(
            2,
            "Living-Room.local",
            A,
            120,
            Rd::A([192, 0, 2, 9]),
        );
        let m = parse(&b.bytes()).unwrap();
        assert!(m.is_probe());
    }

    #[test]
    fn the_payload_is_taken_from_either_ip() {
        use crate::frame::tests::{CLIENT, ipv4_frame, ipv6_frame, udp};
        let msg = airplay_response("A", "a", &[]);
        let v4 = ipv4_frame(CLIENT, [192, 0, 2, 10], 17, &udp(PORT, PORT, &msg));
        assert_eq!(payload(&v4), Some(([192, 0, 2, 10].into(), &msg[..])));
        let v6 = ipv6_frame(CLIENT, 17, &udp(PORT, PORT, &msg));
        assert_eq!(payload(&v6).map(|(_, p)| p), Some(&msg[..]));
        // A legacy query's answer comes from 5353 to the asker's port.
        let legacy = ipv4_frame(CLIENT, [192, 0, 2, 10], 17, &udp(PORT, 40_000, &msg));
        assert!(payload(&legacy).is_some());
        for (sport, dport) in [(53, 40_000), (5354, 5355)] {
            let other = ipv4_frame(CLIENT, [192, 0, 2, 10], 17, &udp(sport, dport, &msg));
            assert_eq!(payload(&other), None);
        }
        // A later fragment holds no UDP header; a first one, what it holds.
        let mut later = v4.clone();
        later[14 + 7] = 0x10;
        assert_eq!(payload(&later), None);
        let mut first = v4.clone();
        first[14 + 6] = 0x20;
        first.truncate(14 + 20 + 8 + 30);
        assert_eq!(payload(&first).map(|(_, p)| p.len()), Some(30));
        // TCP, and IPv6 behind an extension header, are not looked into.
        assert_eq!(
            payload(&ipv4_frame(
                CLIENT,
                [192, 0, 2, 10],
                6,
                &udp(PORT, PORT, &msg)
            )),
            None
        );
        assert_eq!(
            payload(&ipv6_frame(CLIENT, 0, &udp(PORT, PORT, &msg))),
            None
        );
        assert_eq!(payload(&v4[..20]), None);
    }

    /// The name at `at` of `msg`, with a whole message's steps.
    fn name_at(msg: &[u8], at: usize) -> Option<(Name, usize)> {
        name(msg, at, &mut STEPS.to_owned())
    }

    /// A message with one question at 12 whose name is `name` (wire bytes).
    fn with_name(name: &[u8]) -> Vec<u8> {
        let mut m = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend(name);
        m.extend([0, 12, 0, 1]);
        m
    }

    /// Runs `f` on a thread of its own, failing the test past `limit`
    /// rather than hanging it.
    pub fn within<T: Send + 'static>(
        limit: std::time::Duration,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(limit).expect("did not end in time")
    }

    #[test]
    fn hostile_names_are_refused_in_time() {
        within(
            std::time::Duration::from_secs(10),
            hostile_names_are_refused,
        );
    }

    fn hostile_names_are_refused() {
        // A pointer to itself, to after itself, back into its own name, a
        // label type that is neither, a label past the end.
        for name in [
            &[0xc0, 12][..],
            &[0xc0, 14, 1, b'a', 0],
            &[1, b'a', 0xc0, 12],
            &[0x40, 1, 0],
            &[0x80, 1, 0],
            &[5, b'a', b'b'],
            &[1, b'a'],
            &[0xc0],
        ] {
            let m = parse(&with_name(name)).unwrap();
            assert!(!m.complete && m.questions.is_empty(), "{name:?}");
        }
        // Two names pointing at each other, the second one read.
        let mut m = vec![0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0];
        m.extend([
            1, b'a', 0xc0, 18, 0, 12, 0, 1, 1, b'b', 0xc0, 12, 0, 12, 0, 1,
        ]);
        let read = parse(&m).unwrap();
        assert!(!read.complete && read.questions.is_empty());
        // A pointer into the header reads what is there, and ends.
        assert!(name_at(&with_name(&[0xc0, 2]), 12).is_some());
        // 63-byte labels up to 255 bytes on the wire read; one more does not.
        let label = |n: usize| {
            let mut l = vec![n as u8];
            l.extend(std::iter::repeat_n(b'x', n));
            l
        };
        let mut fits: Vec<u8> = (0..3).flat_map(|_| label(63)).collect();
        fits.extend(label(61));
        fits.push(0);
        assert_eq!(fits.len(), 255);
        let msg = with_name(&fits);
        let (n, after) = name_at(&msg, 12).unwrap();
        assert_eq!(after, 12 + 255);
        // Its text is cut short, at a character.
        let text = n.text(&msg);
        assert!(text.len() <= TEXT_MAX && text.ends_with('…'), "{text}");
        let mut over: Vec<u8> = (0..3).flat_map(|_| label(63)).collect();
        over.extend(label(62));
        over.push(0);
        assert_eq!(name_at(&with_name(&over), 12), None);
        assert_eq!(name_at(&with_name(&label(64)), 12), None);
        // A pointer chain backwards through many names reads, and each
        // jump is strictly backwards.
        let mut chain = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, b'z', 0];
        for i in 0..100usize {
            let prev = if i == 0 { 12 } else { 15 + 4 * (i - 1) };
            chain.extend([1, b'y', 0xc0 | (prev >> 8) as u8, prev as u8]);
        }
        let (n, _) = name_at(&chain, chain.len() - 4).unwrap();
        assert!(n.text(&chain).starts_with("y.y.y"));
        // So does a run of pointers each to the one before: the walk takes
        // at most a jump per two bytes of the message.
        let mut run = vec![0; 12];
        run.push(0);
        for i in 0..700usize {
            let prev = 12 + if i == 0 { 0 } else { 1 + 2 * (i - 1) };
            run.extend([0xc0 | (prev >> 8) as u8, prev as u8]);
        }
        let (n, after) = name_at(&run, run.len() - 2).unwrap();
        assert_eq!((n.text(&run).as_str(), after), ("", run.len()));
    }

    #[test]
    fn records_cut_short_or_lying_stop_the_read() {
        let msg = airplay_response("A", "a", &["model=M"]);
        // Every cut reads at most what precedes it, and never panics.
        let whole = parse(&msg).unwrap().records.len();
        for n in 0..msg.len() {
            match parse(&msg[..n]) {
                None => assert!(n < 4),
                Some(m) => assert!(!m.complete && m.records.len() < whole, "cut at {n}"),
            }
        }
        // An SRV too short to hold a target, an A of three bytes and a PTR
        // whose name runs past its data are read past.
        let mut b = Builder::new(true);
        b.record(1, "x.local", SRV, 1, Rd::Raw(&[0, 0, 0, 0, 0x1b]))
            .record(1, "_s._tcp.local", A, 1, Rd::Raw(&[1, 2, 3]))
            .record(1, "y.local", PTR, 1, Rd::Raw(&[3, b'a', b'b', b'c', 0]));
        let mut bytes = b.bytes();
        let m = parse(&bytes).unwrap();
        assert!(m.complete && matches!(m.records[2].data, Data::Ptr(_)));
        let len_at = bytes.len() - 7;
        assert_eq!(bytes[len_at..len_at + 2], [0, 5]);
        bytes[len_at + 1] = 3;
        let m = parse(&bytes).unwrap();
        assert!(m.records.iter().all(|r| r.data == Data::Other), "{m:?}");
        // An rdlength past the end stops the read.
        bytes[len_at + 1] = 6;
        assert!(!parse(&bytes).unwrap().complete);
        let mut lying = Builder::new(true);
        lying.record(1, "a.local", A, 1, Rd::A([192, 0, 2, 1]));
        let mut lying = lying.bytes();
        lying[7] = 200;
        let m = parse(&lying).unwrap();
        assert!(!m.complete);
        assert_eq!(m.records.len(), 1);
    }

    #[test]
    fn a_messages_names_take_at_most_its_steps() {
        use crate::services::tests::{long_chain, long_names};
        // 184 names of 127 labels: 8 read whole, then the steps run out.
        let m = parse(&long_names()).unwrap();
        assert!(!m.complete);
        assert_eq!(m.records.len(), STEPS / (2 * 127));
        // 110 walks of 382 steps: 2 read.
        let m = parse(&long_chain()).unwrap();
        assert!(!m.complete);
        assert_eq!(m.records.len(), 1 + (STEPS - 1) / 382);
        // A real response of 128 records fits.
        let mut b = Builder::new(true);
        for i in 0..RECORDS {
            let instance = format!("Speaker {i}._airplay._tcp.local");
            b.record(1, "_airplay._tcp.local", PTR, 4500, Rd::Ptr(&instance));
        }
        let m = parse(&b.bytes()).unwrap();
        assert!(m.complete && m.records.len() == RECORDS);
    }

    #[test]
    fn a_message_yields_its_caps_at_most() {
        let mut b = Builder::new(false);
        for i in 0..QUESTIONS + 3 {
            b.question(&format!("q{i}.local"), PTR, false);
        }
        let m = parse(&b.bytes()).unwrap();
        assert_eq!((m.questions.len(), m.complete), (QUESTIONS, false));
        let mut b = Builder::new(true);
        for i in 0..RECORDS + 3 {
            b.record(1, &format!("r{i}.local"), A, 1, Rd::A([192, 0, 2, 1]));
        }
        let m = parse(&b.bytes()).unwrap();
        assert_eq!((m.records.len(), m.complete), (RECORDS, false));
    }

    /// A small deterministic generator: the tests read the same bytes on
    /// every run.
    pub struct Rng(pub u64);

    impl Rng {
        pub fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        pub fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }

        pub fn fill(&mut self, buf: &mut [u8]) {
            for chunk in buf.chunks_mut(8) {
                let r = self.next().to_le_bytes();
                chunk.copy_from_slice(&r[..chunk.len()]);
            }
        }
    }

    /// Every parse of `payload` stays within its bounds.
    fn bounded(payload: &[u8]) {
        if let Some(m) = parse(payload) {
            assert!(m.questions.len() <= QUESTIONS && m.records.len() <= RECORDS);
            let names = m
                .questions
                .iter()
                .map(|q| &q.name)
                .chain(m.records.iter().map(|r| &r.name));
            for n in names {
                assert!(n.text(payload).len() <= TEXT_MAX);
            }
        }
    }

    #[test]
    fn random_bytes_parse_within_bounds() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut buf = vec![0u8; 1600];
        for _ in 0..200_000 {
            let len = rng.below(buf.len());
            rng.fill(&mut buf[..len]);
            // Counts that are plausible reach the records more often.
            if len > 12 && rng.below(2) == 0 {
                buf[4..12].copy_from_slice(&[0, 2, 0, 4, 0, 1, 0, 3]);
            }
            bounded(&buf[..len]);
        }
    }

    #[test]
    fn every_cut_and_bit_flip_of_real_messages_parses_within_bounds() {
        let mut query = Builder::new(false);
        query
            .question("_airplay._tcp.local", PTR, false)
            .question("_raop._tcp.local", PTR, true)
            .record(
                1,
                "_airplay._tcp.local",
                PTR,
                4500,
                Rd::Ptr("Left._airplay._tcp.local"),
            );
        let messages = [
            airplay_response("Left", "Left", &["model=M", "gid=G", "igl=1", "gpn=Room"]),
            query.bytes(),
        ];
        for msg in &messages {
            for n in 0..=msg.len() {
                bounded(&msg[..n]);
            }
            let mut flipped = msg.clone();
            for bit in 0..msg.len() * 8 {
                flipped[bit / 8] ^= 1 << (bit % 8);
                bounded(&flipped);
                flipped[bit / 8] ^= 1 << (bit % 8);
            }
        }
    }
}
