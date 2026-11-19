//! A capture against a real kernel and nftables, in a network namespace of
//! the test's own: veth pairs stand for two Wi-Fi ports, a BSS's (`wlan5`)
//! and a per-VLAN one (`wlan6.42`), their peers for the clients, and a
//! client VLAN's netdev (`vlan42`); the ECM files are a scratch tree's. The
//! client's frames both ways are captured once each and another client's
//! not, and only the client's are marked off the offload; the flows are
//! taken and given back however the capture ends: stopped, its time up, the
//! agent gone. It needs CAP_SYS_ADMIN and CAP_NET_ADMIN, and nft; without
//! them it says so and passes.

use std::io::{self, Read};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use u6e_proto::ecm::{DEFUNCT_BY_MAC, NO_ACCEL_MARK};
use u6e_proto::frame::{decode_frame, write_frame};
use u6e_proto::msg::{AgentMsg, CaptureFilter, CaptureMechanism, CaptureRequest};

use crate::filter::tests::{CLIENT, OTHER, eth, ipv4, ports_l4};
use crate::offload::tests::{STOP, ap, pending, read};
use crate::offload::{Paths, TABLE};
use crate::pcapng::tests::blocks;
use crate::serve::{self, Config};
use crate::testdir::TestDir;

fn ip(args: &str) {
    let ok = Command::new("ip")
        .args(args.split(' '))
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "ip {args}");
}

fn ifindex(name: &str) -> i32 {
    serve::netdevs()
        .into_iter()
        .find(|(n, _)| n == name)
        .map(|(_, i)| i as i32)
        .unwrap()
}

/// Sends `frame` out of `name`.
fn send(name: &str, frame: &[u8]) {
    Sender::new().send(ifindex(name), frame);
}

/// A packet socket to send frames with: one for many frames, as closing
/// one waits out a grace period.
struct Sender(OwnedFd);

impl Sender {
    fn new() -> Self {
        // SAFETY: plain socket creation; the descriptor is owned at once.
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) };
        assert!(fd >= 0, "{}", io::Error::last_os_error());
        // SAFETY: a fresh descriptor this test owns.
        Sender(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Sends `frame` out of the interface of index `idx`.
    fn send(&self, idx: i32, frame: &[u8]) {
        // SAFETY: a zeroed sockaddr_ll is valid, filled in below.
        let mut sa: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sa.sll_family = libc::AF_PACKET as u16;
        sa.sll_ifindex = idx;
        sa.sll_halen = 6;
        // SAFETY: the buffer and the address are valid for the lengths given.
        let n = unsafe {
            libc::sendto(
                self.0.as_raw_fd(),
                frame.as_ptr().cast(),
                frame.len(),
                0,
                (&raw const sa).cast(),
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        assert_eq!(n, frame.len() as isize, "{}", io::Error::last_os_error());
    }
}

/// Runs `test` in a network namespace of its own with the two ports; false
/// when one cannot be made.
fn in_netns(test: impl FnOnce() + Send + 'static) -> bool {
    let made = thread::spawn(move || {
        // SAFETY: unshare affects this thread alone, which holds nothing else.
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            return false;
        }
        ip("link add wlan5 type veth peer name c5");
        ip("link add wlan6.42 type veth peer name c6");
        ip("link add vlan42 type veth peer name u42");
        for d in ["wlan5", "c5", "wlan6.42", "c6", "vlan42", "u42"] {
            ip(&format!("link set {d} up"));
        }
        test();
        true
    });
    made.join().expect("the test passed")
}

fn request(secs: u16) -> CaptureRequest {
    CaptureRequest {
        id: 7,
        mac: CLIENT,
        secs,
        max_bytes: 1_000_000,
        snaplen: 96,
        filter: CaptureFilter::default(),
    }
}

/// `t`'s scratch AP, its marks made by the host's nft.
fn scratch_ap(t: &TestDir) -> Paths {
    Paths {
        nft: "/usr/sbin/nft".into(),
        ..ap(t, false)
    }
}

fn nft(script: &str) -> Result<(), String> {
    u6e_proto::nft::run(std::path::Path::new("/usr/sbin/nft"), script)
}

/// How many frames carrying the no-offload mark came in by `wlan5`, by
/// `wlan6.42` and by `vlan42`, as the counters `count_marks` adds count them.
fn marked() -> (u64, u64, u64) {
    let out = Command::new("nft")
        .args(["list", "table", "netdev", "count"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let n: Vec<u64> = text
        .split("packets ")
        .skip(1)
        .map(|s| s.split(' ').next().unwrap().parse().unwrap())
        .collect();
    (n[0], n[1], n[2])
}

fn count_marks() {
    let rule = format!("meta mark {NO_ACCEL_MARK:#x} counter");
    let chain = |name: &str, dev: &str| {
        format!(
            "\tchain {name} {{ type filter hook ingress device \"{dev}\" priority 10; {rule}; }}\n"
        )
    };
    let body = chain("w", "wlan5") + &chain("x", "wlan6.42") + &chain("v", "vlan42");
    nft(&u6e_proto::nft::replace("netdev count", &body)).unwrap();
}

/// Starts a capture of `req` on the scratch AP `paths`; the agent's end of it.
fn start(paths: &Paths, req: &CaptureRequest) -> (UnixStream, thread::JoinHandle<io::Result<()>>) {
    let (mut agent, helper) = UnixStream::pair().unwrap();
    write_frame(&mut agent, req).unwrap();
    let cfg = Config {
        paths: paths.clone(),
        host: "ap1".into(),
        netdevs: serve::netdevs,
    };
    let (_never, stop) = UnixStream::pair().unwrap();
    let h = thread::spawn(move || {
        let r = serve::run(&cfg, helper, stop.as_raw_fd());
        drop(_never);
        r
    });
    (agent, h)
}

/// Every frame the agent reads until the helper closes.
fn read_all(agent: &mut UnixStream) -> Vec<AgentMsg> {
    let mut buf = Vec::new();
    let _ = agent.read_to_end(&mut buf);
    let mut out = Vec::new();
    let mut at = 0;
    while let Some((m, n)) = decode_frame::<AgentMsg>(&buf[at..]).unwrap() {
        out.push(m);
        at += n;
    }
    out
}

fn first(agent: &mut UnixStream) -> AgentMsg {
    let mut len = [0u8; 4];
    agent.read_exact(&mut len).unwrap();
    let mut body = vec![0; u32::from_le_bytes(len) as usize];
    agent.read_exact(&mut body).unwrap();
    let mut frame = len.to_vec();
    frame.extend(body);
    decode_frame::<AgentMsg>(&frame).unwrap().unwrap().0
}

/// The file the chunks make, and the final state.
fn file(msgs: &[AgentMsg]) -> (Vec<u8>, &u6e_proto::msg::CaptureState) {
    let mut f = Vec::new();
    let mut seq = 0;
    for m in msgs {
        if let AgentMsg::CaptureChunk(c) = m {
            assert_eq!((c.id, c.seq), (7, seq));
            seq += 1;
            f.extend(&c.data);
        }
    }
    let Some(AgentMsg::Capture(end)) = msgs.last() else {
        panic!("no final state: {msgs:?}");
    };
    (f, end)
}

#[test]
fn a_clients_frames_both_ways_are_captured_once_and_only_its_flows_leave_the_offload() {
    let ran = in_netns(|| {
        let t = TestDir::new();
        let p = scratch_ap(&t);
        count_marks();
        let (mut agent, h) = start(&p, &request(60));
        let AgentMsg::Capture(s) = first(&mut agent) else {
            panic!()
        };
        assert!(
            s.running && s.mechanism == Some(CaptureMechanism::OffOffload),
            "{s:?}"
        );
        // ECM goes on accelerating every other client's connections; the
        // client's are decelerated.
        assert_eq!(
            (read(&p, STOP[0]), read(&p, STOP[1])),
            ("0\n".into(), "0\n".into())
        );
        assert_eq!(
            read(&p, DEFUNCT_BY_MAC),
            format!("{}\n", u6e_proto::mac::format(CLIENT))
        );
        let up = eth(
            OTHER,
            CLIENT,
            0x0800,
            &ipv4(6, [192, 0, 2, 10], [198, 51, 100, 7], &ports_l4(5000, 443)),
        );
        let down = eth(
            CLIENT,
            OTHER,
            0x0800,
            &ipv4(6, [198, 51, 100, 7], [192, 0, 2, 10], &ports_l4(443, 5000)),
        );
        let stranger = eth(
            OTHER,
            [2, 0, 0, 0, 0, 3],
            0x0800,
            &ipv4(6, [192, 0, 2, 11], [198, 51, 100, 7], &[]),
        );
        send("c5", &up);
        send("c5", &stranger);
        send("wlan5", &down);
        send("c6", &up);
        // The client's frames are marked on their way in, from it on its
        // ports, to it from another client's port and on its VLAN's netdev;
        // the stranger's are not.
        send("c6", &down);
        send("u42", &down);
        send("u42", &stranger);
        thread::sleep(Duration::from_millis(300));
        assert_eq!(marked(), (1, 2, 1));
        agent.shutdown(Shutdown::Write).unwrap();
        let msgs = read_all(&mut agent);
        h.join().unwrap().unwrap();
        let (f, end) = file(&msgs);
        assert!(!end.running && end.reason == "stopped", "{end:?}");
        assert_eq!((end.packets, end.bytes), (3, f.len() as u64));
        let kinds: Vec<u32> = blocks(&f).iter().map(|(k, _)| *k).collect();
        // The header, wlan5's description and its two packets, then
        // wlan6.42's description and its packet.
        assert_eq!(kinds, [0x0A0D_0D0A, 1, 6, 6, 1, 6]);
        // The marks are gone and nothing more is marked.
        assert!(nft(&format!("list table {TABLE}")).is_err());
        send("c5", &up);
        thread::sleep(Duration::from_millis(100));
        assert_eq!(marked(), (1, 2, 1));
        assert!(!pending(&p));
        // tcpdump reads it as written, when the host has it.
        let pcap = t.path().join("c.pcapng");
        std::fs::write(&pcap, &f).unwrap();
        if let Ok(out) = Command::new("tcpdump")
            .args(["-nn", "-r"])
            .arg(&pcap)
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            assert_eq!(text.lines().count(), 3, "{text}");
        }
    });
    if !ran {
        eprintln!("skipped: no network namespace of its own");
    }
}

#[test]
fn a_capture_ends_at_its_time_or_when_the_agent_goes_and_gives_the_flows_back() {
    let ran = in_netns(|| {
        let t = TestDir::new();
        let p = scratch_ap(&t);
        let at = Instant::now();
        let (mut agent, h) = start(&p, &request(1));
        let msgs = read_all(&mut agent);
        h.join().unwrap().unwrap();
        let (_, end) = file(&msgs);
        assert_eq!(end.reason, "its time is up");
        assert!(at.elapsed() < Duration::from_secs(3));
        assert!(nft(&format!("list table {TABLE}")).is_err());

        let (mut agent, h) = start(&p, &request(60));
        let _ = first(&mut agent);
        assert!(nft(&format!("list table {TABLE}")).is_ok());
        drop(agent);
        assert!(h.join().unwrap().is_err(), "nobody took the last frames");
        assert!(nft(&format!("list table {TABLE}")).is_err());
        assert!(!pending(&p));
    });
    if !ran {
        eprintln!("skipped: no network namespace of its own");
    }
}

#[test]
fn no_block_is_written_past_the_size_limit() {
    let ran = in_netns(|| {
        let t = TestDir::new();
        let p = scratch_ap(&t);
        let mut req = request(60);
        req.snaplen = 1500;
        let (mut agent, h) = start(&p, &req);
        let _ = first(&mut agent);
        // The agent takes what comes as it comes.
        let reader = thread::spawn(move || read_all(&mut agent));
        let big = eth(
            OTHER,
            CLIENT,
            0x0800,
            &ipv4(17, [192, 0, 2, 10], [198, 51, 100, 7], &[0; 1300]),
        );
        // A burst past what the socket holds is dropped and counted: frames
        // go a few at a time until the capture ends.
        let (sender, c5) = (Sender::new(), ifindex("c5"));
        let until = Instant::now() + Duration::from_secs(30);
        while !h.is_finished() && Instant::now() < until {
            for _ in 0..20 {
                sender.send(c5, &big);
            }
            thread::sleep(Duration::from_millis(2));
        }
        let msgs = reader.join().unwrap();
        h.join().unwrap().unwrap();
        let (f, end) = file(&msgs);
        assert_eq!(end.reason, "its size limit is reached");
        assert!(
            f.len() as u64 == end.bytes && end.bytes <= 1_000_000,
            "{end:?}"
        );
        assert!(
            end.bytes > 1_000_000 - 1500,
            "it stops at the first block past it"
        );
        assert!(msgs.iter().all(|m| match m {
            AgentMsg::CaptureChunk(c) => c.data.len() <= u6e_proto::msg::CHUNK_MAX,
            _ => true,
        }));
        assert_eq!(blocks(&f).len() as u64, end.packets + 2);
        assert!(!pending(&p));
    });
    if !ran {
        eprintln!("skipped: no network namespace of its own");
    }
}

#[test]
fn one_capture_at_a_time_and_a_bad_request_takes_nothing() {
    let ran = in_netns(|| {
        let t = TestDir::new();
        let p = scratch_ap(&t);
        let (mut a, ha) = start(&p, &request(60));
        let _ = first(&mut a);
        let (mut b, hb) = start(&p, &request(60));
        let msgs = read_all(&mut b);
        hb.join().unwrap().unwrap();
        let [AgentMsg::Capture(s)] = &msgs[..] else {
            panic!("{msgs:?}")
        };
        assert!(!s.running && s.mechanism.is_none() && s.reason.contains("another capture"));
        a.shutdown(Shutdown::Write).unwrap();
        let _ = read_all(&mut a);
        ha.join().unwrap().unwrap();

        let mut bad = request(60);
        bad.snaplen = 10;
        let (mut c, hc) = start(&p, &bad);
        let msgs = read_all(&mut c);
        hc.join().unwrap().unwrap();
        assert!(matches!(&msgs[..], [AgentMsg::Capture(s)] if s.reason.starts_with("refused")));
        assert!(nft(&format!("list table {TABLE}")).is_err() && !pending(&p));
    });
    if !ran {
        eprintln!("skipped: no network namespace of its own");
    }
}
