//! The guards against a real kernel, in a network namespace of the test's
//! own: a veth pair stands for a Wi-Fi port (`w0`) and its client (`c0`),
//! `w0` a port of the bridge `br42` whose other port (`w1`) leads to a
//! listener (`o1`), which sees what the bridge forwards. The client sends
//! frames; reporting, every frame passes and the offending ones are
//! reported; enforcing, exactly those are reported again and dropped before
//! the bridge, their drops counted, while a client the guards know nothing
//! of passes, as does what a client sends from another's address without
//! opening a connection (ICMP, a SYN-ACK, a DHCP renewal). Tagged frames are
//! the reviewer's VID-0 probe; fragments and extension headers his RA-shape
//! probe's, at the depths flower stops reading at. It needs CAP_SYS_ADMIN
//! and CAP_NET_ADMIN; without them it says so and passes.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use u6e_proto::msg::{Binding, EventKind, Guard, Violation};

use crate::bindings::Clock;

use crate::capture::Capture;
use crate::dhcp;
use crate::enforce::{self, Enforcer};
use crate::frame::{self, tests::*};
use crate::ports::Port;
use crate::rules::Guards;
use crate::rules::tests::{RELAY, SERVER, answer, guards, now};

const ROGUE: [u8; 6] = [2, 0, 0, 0, 0, 0x66];
/// A client the guards know nothing of.
const STRANGER: [u8; 6] = [2, 0, 0, 0, 0, 0x77];

fn ip(args: &str) {
    let ok = Command::new("ip")
        .args(args.split(' '))
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "ip {args}");
}

/// The index of `name` in this namespace (sysfs shows the one it was
/// mounted in).
fn ifindex(name: &str) -> i32 {
    let out = Command::new("ip")
        .args(["-o", "link", "show", name])
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    text.split(':').next().unwrap().trim().parse().unwrap()
}

/// A raw socket on `name`, to send from or read what reaches it.
fn raw(name: &str) -> OwnedFd {
    // SAFETY: plain socket creation; the descriptor is owned at once.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            i32::from(0x0003u16.to_be()),
        )
    };
    assert!(fd >= 0, "{}", io::Error::last_os_error());
    // SAFETY: a fresh descriptor this test owns.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: a zeroed sockaddr_ll is valid, filled in below.
    let mut sa: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sa.sll_family = libc::AF_PACKET as u16;
    sa.sll_protocol = 0x0003u16.to_be();
    sa.sll_ifindex = ifindex(name);
    // SAFETY: `sa` is a valid sockaddr_ll of the size passed.
    let r = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&raw const sa).cast(),
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    };
    assert_eq!(r, 0, "{}", io::Error::last_os_error());
    fd
}

fn send(fd: &OwnedFd, frame: &[u8]) {
    // SAFETY: `frame` is valid for its length.
    let n = unsafe { libc::send(fd.as_raw_fd(), frame.as_ptr().cast(), frame.len(), 0) };
    assert_eq!(n, frame.len() as isize, "{}", io::Error::last_os_error());
}

/// Whether `got` is `sent`, a tag in the data taken off on the way.
fn same(sent: &[u8], got: &[u8]) -> bool {
    let untagged = || [&sent[..12], &sent[16..]].concat();
    sent == got || (matches!(sent[12..14], [0x81, 0] | [0x88, 0xa8]) && untagged() == got)
}

/// Which of `sent` reached `fd` within a moment.
fn received(fd: &OwnedFd, sent: &[Vec<u8>]) -> Vec<Vec<u8>> {
    thread::sleep(Duration::from_millis(200));
    let mut out = Vec::new();
    let mut buf = [0u8; 2048];
    loop {
        let mut from: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_ll>() as u32;
        // SAFETY: `buf` and `from` are valid for the sizes passed.
        let n = unsafe {
            libc::recvfrom(
                fd.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
                (&raw mut from).cast(),
                &mut len,
            )
        };
        if n < 0 {
            return out;
        }
        let f = &buf[..n as usize];
        let ours = sent.iter().find(|s| same(s, f));
        if let (true, Some(s)) = (from.sll_pkttype != libc::PACKET_OUTGOING, ours) {
            out.push(s.clone());
        }
    }
}

/// Runs `test` in a new network namespace on a thread of its own; false
/// when this process may not make one.
fn in_netns(test: impl FnOnce() + Send + 'static) -> bool {
    let made = thread::spawn(move || {
        // SAFETY: unshare affects this thread alone, which holds nothing else.
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            return false;
        }
        test();
        true
    });
    made.join().expect("the test passed")
}

fn violations(g: &Guards) -> Vec<Violation> {
    let all = g.record.iter().map(|(_, e)| match &e.kind {
        EventKind::GuardViolation(v) => v.clone(),
        k => panic!("{k:?}"),
    });
    all.collect()
}

/// `frame` tagged for VLAN 0, as the reviewer's probe sends it.
fn vid0(frame: Vec<u8>) -> Vec<u8> {
    let mut f = frame;
    f.splice(12..12, [0x81, 0, 0, 0]);
    f
}

/// The site's acknowledgement of `ip` for ROGUE, as the uplink brings it.
fn take_ack(g: &mut Guards, ip: [u8; 4]) {
    let up = Port {
        ifindex: 99,
        name: "vlan42".into(),
        vlan: 42,
        wifi: false,
    };
    let mut ack = answer(dhcp::ACK, RELAY, SERVER);
    // The message starts after 42 bytes of headers: its yiaddr at 16, its
    // chaddr at 28.
    ack[42 + 16..42 + 20].copy_from_slice(&ip);
    ack[42 + 28..42 + 34].copy_from_slice(&ROGUE);
    g.take(&up, &frame::parse(&ack).unwrap(), now(62_000));
}

#[test]
fn the_guards_read_and_drop_on_a_real_kernel() {
    let ran = in_netns(|| {
        // No address autoconfiguration chatter on the links.
        for c in ["all", "default"] {
            std::fs::write(format!("/proc/sys/net/ipv6/conf/{c}/disable_ipv6"), "1").unwrap();
        }
        ip("link add w0 type veth peer name c0");
        ip("link add w1 type veth peer name o1");
        ip("link add br42 type bridge");
        for l in ["w0", "c0", "w1", "o1", "br42"] {
            ip(&format!("link set {l} up"));
        }
        ip("link set w0 master br42");
        ip("link set w1 master br42");
        let port = Port {
            ifindex: ifindex("w0"),
            name: "w0".into(),
            vlan: 42,
            wifi: true,
        };
        let ports = [port.clone()];
        let capture = Capture::open().unwrap();
        capture.watch(&ports).unwrap();
        let (client, out) = (raw("c0"), raw("o1"));
        let read = |g: &mut Guards, at: Clock| {
            let deadline = Instant::now() + Duration::from_millis(300);
            let mut buf = [0u8; 2048];
            while Instant::now() < deadline {
                match capture.recv(&mut buf).unwrap() {
                    Some(r) if r.ifindex == port.ifindex => {
                        let f = match r.tag {
                            Some(vid) => Some(frame::Frame {
                                src: buf[6..12].try_into().unwrap(),
                                what: frame::What::Tagged { vid },
                            }),
                            None => frame::parse(&buf[..r.len]),
                        };
                        if let Some(f) = f {
                            g.take(&port, &f, at);
                        }
                    }
                    Some(_) => {}
                    None => thread::sleep(Duration::from_millis(10)),
                }
            }
        };
        let mut g = guards(&[]);
        let bound = [192, 0, 2, 10];
        g.bindings.statics(
            &[Binding {
                mac: CLIENT,
                ip: bound.into(),
                expires_ms: None,
            }],
            now(0),
        );
        let offer = dhcp::tests::message(2, 2, [192, 0, 2, 50], Some(60));
        let renew = dhcp::tests::message(1, 3, [0; 4], None);
        let rdnss = vec![
            25, 3, 0, 0, 0, 0, 0, 1, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53,
        ];
        let (hbh, behind_hbh) = behind(&[(0, 0)], 58, &ra_body(0, &[]));
        let mac = |last| [2, 0, 0, 0, 0, last];
        let v6 = |last, ext: &[(u8, u8)], next, l4: &[u8]| {
            let (nh, payload) = behind(ext, next, l4);
            ipv6_frame(mac(last), nh, &payload)
        };
        let ra_1800 = ra_body(1800, &[]);
        let (first, dest) = ([(frame::FRAGMENT, 0)], frame::DESTINATION);
        let deep = |n| vec![(dest, 0); n];
        let mut more_fragments = v6(0x59, &first, 58, &ra_1800);
        more_fragments[14 + 40 + 3] = 1;
        let mut later_udp = ipv4_frame(mac(0x57), bound, 17, &udp(50_000, 53, &[]));
        later_udp[14 + 7] = 1;
        let good = vec![
            arp_frame(CLIENT, CLIENT, bound, 1),
            ipv4_frame(CLIENT, bound, 6, &tcp(0x02)),
            // A client the guards know nothing of: a static address, or a
            // lease from before the seed reached the AP; and its renewal.
            arp_frame(STRANGER, STRANGER, [192, 0, 2, 77], 1),
            ipv4_frame(STRANGER, [192, 0, 2, 77], 6, &tcp(0x02)),
            ipv4_frame(STRANGER, [192, 0, 2, 77], 17, &udp(68, 67, &renew)),
            // A Thread border router.
            ipv6_frame(CLIENT, 58, &ra_body(0, &[rio("fdba:97ab:f6e9:1::", 64)])),
            // From another's address, opening no connection.
            ipv4_frame(ROGUE, bound, 1, &[8, 0, 0, 0, 0, 1, 0, 1]),
            ipv4_frame(ROGUE, bound, 6, &tcp(0x12)),
            ipv4_frame(ROGUE, bound, 17, &udp(68, 67, &renew)),
            // DHCPv6 server ports where flower reads no ports: in a first
            // fragment.
            v6(0x60, &first, 17, &udp(547, 546, &[7, 0, 0, 1])),
        ];
        let bad = vec![
            arp_frame(ROGUE, ROGUE, bound, 2),
            ipv4_frame(ROGUE, bound, 6, &tcp(0x02)),
            ipv4_frame(ROGUE, [192, 0, 2, 66], 17, &udp(67, 68, &offer)),
            ipv6_frame(ROGUE, 58, &ra_body(1800, &[])),
            ipv6_frame([2, 0, 0, 0, 0, 0x55], hbh, &behind_hbh),
            vid0(arp_frame(
                [2, 0, 0, 0, 0, 0x44],
                [2, 0, 0, 0, 0, 0x44],
                [192, 0, 2, 99],
                2,
            )),
            vid0(ipv4_frame(
                [2, 0, 0, 0, 0, 0x45],
                [192, 0, 2, 66],
                6,
                &tcp(0x02),
            )),
            // Advertisements flower reads no type of: an atomic fragment, a
            // first fragment, behind 16 and 17 extension headers, a first
            // fragment of a destination header; ICMPv6 cut short.
            v6(0x58, &first, 58, &ra_1800),
            more_fragments,
            v6(0x5a, &deep(16), 58, &ra_1800),
            v6(0x5b, &deep(17), 58, &ra_1800),
            v6(0x5c, &first, dest, &[58, 0, 1, 4, 0, 0, 0, 0]),
            v6(0x5f, &[], 58, &[134, 0, 0, 0]),
            // A malformed DHCP server message; a DHCPv6 one behind an
            // extension header, and behind 16, where flower still reads
            // ports.
            ipv4_frame(mac(0x5d), [192, 0, 2, 66], 17, &udp(67, 68, &[2, 1, 6])),
            v6(0x5e, &[(0, 0)], 17, &udp(547, 546, &[7, 0, 0, 1])),
            v6(0x61, &deep(16), 17, &udp(547, 546, &[7, 0, 0, 1])),
            // ARP the filters cannot read, from a MAC that holds an address.
            arp_frame(CLIENT, CLIENT, bound, 3),
            // A later fragment of a datagram from another's address.
            later_udp,
        ];
        let all: Vec<Vec<u8>> = good.iter().chain(&bad).cloned().collect();
        let reported = |g: &Guards| {
            let mut v: Vec<_> = violations(g)
                .iter()
                .map(|v| (v.guard, v.mac, v.dropped))
                .collect();
            v.sort();
            v
        };
        let mut want = vec![
            (Guard::Arp, ROGUE, false),
            (Guard::Source, ROGUE, false),
            (Guard::Dhcp, ROGUE, false),
            (Guard::Ra, ROGUE, false),
            (Guard::Ra, [2, 0, 0, 0, 0, 0x55], false),
            (Guard::Tag, [2, 0, 0, 0, 0, 0x44], false),
            (Guard::Tag, [2, 0, 0, 0, 0, 0x45], false),
            (Guard::Ra, mac(0x58), false),
            (Guard::Ra, mac(0x59), false),
            (Guard::Ra, mac(0x5a), false),
            (Guard::Ra, mac(0x5b), false),
            (Guard::Ra, mac(0x5c), false),
            (Guard::Ra, mac(0x5f), false),
            (Guard::Dhcp, mac(0x5d), false),
            (Guard::Dhcp, mac(0x5e), false),
            (Guard::Dhcp, mac(0x61), false),
            (Guard::Arp, CLIENT, false),
            (Guard::Source, mac(0x57), false),
        ];
        want.sort();

        // Reporting only: every frame forwarded, the offending ones reported.
        for f in &all {
            send(&client, f);
        }
        read(&mut g, now(1));
        assert_eq!(received(&out, &all).len(), all.len());
        assert_eq!(reported(&g), want);

        // Enforcing: the same frames reported, and those dropped; the rest
        // forwarded.
        g.enforce = vec![42];
        let tc = Path::new("/usr/sbin/tc");
        enforce::clear(tc).unwrap();
        let mut e = Enforcer::new(tc.into());
        let sync = |g: &Guards, e: &mut Enforcer| {
            let ra: Vec<_> = g.ra_offenders.keys().copied().collect();
            e.sync(&ports, &g.enforce, &g.bindings.list(now(0)), &ra)
                .unwrap();
        };
        sync(&g, &mut e);
        for f in &all {
            send(&client, f);
        }
        assert_eq!(
            received(&out, &all),
            good,
            "only the good frames are forwarded"
        );
        g.record.clear();
        read(&mut g, now(61_000));
        let dropping: Vec<_> = want.iter().map(|(gd, m, _)| (*gd, *m, true)).collect();
        assert_eq!(reported(&g), dropping);
        let dropped = e.dropped().unwrap();
        let count = |guard| {
            let found = dropped.iter().find(|(g, _)| *g == guard);
            found.map_or(0, |(_, n)| *n)
        };
        assert_eq!(
            [
                Guard::Arp,
                Guard::Dhcp,
                Guard::Ra,
                Guard::Source,
                Guard::Tag
            ]
            .map(count),
            [2, 4, 8, 2, 2]
        );

        // A rogue advertisement shaped like a border router's passes once,
        // reported; its sender's next is dropped.
        let quiet = ipv6_frame([2, 0, 0, 0, 0, 0x56], 58, &ra_body(0, &[rdnss]));
        send(&client, &quiet);
        read(&mut g, now(62_000));
        assert_eq!(received(&out, std::slice::from_ref(&quiet)).len(), 1);
        sync(&g, &mut e);
        send(&client, &quiet);
        assert!(received(&out, std::slice::from_ref(&quiet)).is_empty());
        read(&mut g, now(62_000));
        // Within the hour, even its border-router-shaped one is dropped,
        // and reported so.
        let shaped = ipv6_frame(mac(0x56), 58, &ra_body(0, &[rio("fdba:97ab:f6e9:1::", 64)]));
        g.record.clear();
        send(&client, &shaped);
        read(&mut g, now(130_000));
        assert!(received(&out, std::slice::from_ref(&shaped)).is_empty());
        assert_eq!(reported(&g), [(Guard::Ra, mac(0x56), true)]);

        // A binding added drops a claim of its address at once.
        let late = [192, 0, 2, 88];
        let claim = arp_frame(STRANGER, STRANGER, late, 2);
        send(&client, &claim);
        assert_eq!(received(&out, std::slice::from_ref(&claim)).len(), 1);
        take_ack(&mut g, late);
        sync(&g, &mut e);
        send(&client, &claim);
        assert!(received(&out, std::slice::from_ref(&claim)).is_empty());

        // Back to reporting: nothing drops; clear leaves nothing behind.
        e.sync(&ports, &[], &[], &[]).unwrap();
        for f in &bad {
            send(&client, f);
        }
        assert_eq!(received(&out, &bad).len(), bad.len());
        enforce::clear(tc).unwrap();
        let actions = Command::new("tc")
            .args(["actions", "ls", "action", "gact"])
            .output()
            .unwrap();
        let left = String::from_utf8(actions.stdout).unwrap();
        assert!(!left.contains("index 640"), "{left}");
    });
    if !ran {
        eprintln!("note: no network namespace allowed; the live test is skipped");
    }
}
