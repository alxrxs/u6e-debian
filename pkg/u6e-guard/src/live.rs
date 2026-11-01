//! The guards against a real kernel, in a network namespace of the test's
//! own: a veth pair stands for a Wi-Fi port (`w0`) and its client (`c0`),
//! `w0` a port of the bridge `br42` whose other port (`w1`) leads to a
//! listener (`o1`), which sees what the bridge forwards. The client sends
//! frames; the packet socket must read what the rules look at, and
//! enforcing, `tc` must drop exactly the offending frames before the bridge.
//! It needs CAP_SYS_ADMIN and CAP_NET_ADMIN; without them it says so and
//! passes.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use u6e_proto::msg::{Binding, EventKind, Guard, Violation};

use crate::capture::Capture;
use crate::dhcp;
use crate::enforce::Enforcer;
use crate::frame::{self, tests::*};
use crate::ports::Port;
use crate::rules::Guards;

const ROGUE: [u8; 6] = [2, 0, 0, 0, 0, 0x66];

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
        if from.sll_pkttype != libc::PACKET_OUTGOING && sent.iter().any(|s| s == f) {
            out.push(f.to_vec());
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
        let mut g = Guards::default();
        let read = |g: &mut Guards, now_ms: u64| {
            let deadline = Instant::now() + Duration::from_millis(300);
            let mut buf = [0u8; 2048];
            while Instant::now() < deadline {
                match capture.recv(&mut buf).unwrap() {
                    Some((n, i)) if i == port.ifindex => {
                        if let Some(f) = frame::parse(&buf[..n]) {
                            g.take(&port, &f, now_ms);
                        }
                    }
                    Some(_) => {}
                    None => thread::sleep(Duration::from_millis(10)),
                }
            }
        };
        let bound = [192, 0, 2, 10];
        g.bindings.statics(
            &[Binding {
                mac: CLIENT,
                ip: bound.into(),
                expires_ms: None,
            }],
            0,
        );
        let offer = dhcp::tests::message(2, 2, [192, 0, 2, 50], Some(60));
        let good = [
            arp_frame(CLIENT, CLIENT, bound, 1),
            ipv4_frame(CLIENT, bound, 6, &tcp(0x02)),
            // A Thread border router's advertisement.
            ipv6_frame(CLIENT, 58, &ra_body(0, &[rio("fdba:97ab:f6e9:1::", 64)])),
        ];
        let bad = [
            arp_frame(ROGUE, ROGUE, bound, 2),
            ipv4_frame(ROGUE, [192, 0, 2, 66], 17, &udp(67, 68, &offer)),
            ipv6_frame(ROGUE, 58, &ra_body(1800, &[])),
            ipv4_frame(ROGUE, bound, 6, &tcp(0x02)),
        ];
        // Reporting only: every frame is read, and forwarded.
        for f in good.iter().chain(&bad) {
            send(&client, f);
        }
        let all: Vec<Vec<u8>> = good.iter().chain(&bad).cloned().collect();
        read(&mut g, 1);
        let seen: Vec<_> = violations(&g)
            .iter()
            .map(|v| (v.guard, v.mac, v.dropped))
            .collect();
        let reported = |dropped| {
            [Guard::Arp, Guard::Dhcp, Guard::Ra, Guard::Source].map(|guard| (guard, ROGUE, dropped))
        };
        assert_eq!(seen, reported(false));
        assert_eq!(received(&out, &all).len(), all.len());

        // Enforcing: the offending frames stop at the port; the rest pass.
        g.enforce = vec![42];
        let mut e = Enforcer::new(Path::new("/usr/sbin/tc").into());
        let bindings = g.bindings.list(0);
        let ra: Vec<_> = g.ra_offenders.keys().copied().collect();
        e.sync(&ports, &g.enforce, &bindings, &ra).unwrap();
        for f in good.iter().chain(&bad) {
            send(&client, f);
        }
        assert_eq!(
            received(&out, &all),
            good.to_vec(),
            "only the good frames are forwarded"
        );
        // The tap still reads the dropped ones, a minute on reported again.
        g.record.clear();
        read(&mut g, 61_000);
        let seen: Vec<_> = violations(&g)
            .iter()
            .map(|v| (v.guard, v.mac, v.dropped))
            .collect();
        assert_eq!(seen, reported(true));
        // Back to reporting: nothing drops.
        e.sync(&ports, &[], &bindings, &ra).unwrap();
        for f in &bad {
            send(&client, f);
        }
        assert_eq!(received(&out, &bad).len(), bad.len());
        let left = Command::new("tc")
            .args(["qdisc", "show", "dev", "w0", "ingress"])
            .output()
            .unwrap();
        assert!(
            String::from_utf8(left.stdout).unwrap().trim().is_empty(),
            "no qdisc left"
        );
    });
    if !ran {
        eprintln!("note: no network namespace allowed; the live test is skipped");
    }
}
