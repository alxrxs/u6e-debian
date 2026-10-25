//! The wire format pinned: an instance of every message and every variant,
//! each field set (numbers too large for the next smaller type, each u8 above
//! 127 so that a widening to a varint shows), encoded and compared with
//! `golden/protocol-<PROTOCOL>.txt`. Bytes that differ while PROTOCOL did not
//! fail the test, as does a variant with no instance.
//!
//! After a change to the messages, bump [`PROTOCOL`] and write the new golden:
//!
//!   U6E_GOLDEN=write cargo test -p u6e-proto golden
//!
//! The write refuses to replace the golden of a protocol with other bytes.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::{env, fs};

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::PROTOCOL;
use crate::mac::hex;
use crate::msg::{
    AgentMsg, Band, Bss, ClientFlows, Command, CommandKind, CommandResult, CtlMsg, Event,
    EventKind, FieldDelta, Flow, Flows, Hello, Radio, RateMode, RecDelta, Snapshot, SnapshotDelta,
    Station, Temp,
};

const HOW: &str = "bump u6e_proto::PROTOCOL (pkg/u6e-proto/src/version.rs) and write the \
                   golden: U6E_GOLDEN=write cargo test -p u6e-proto golden";

/// Asserts that `values` hold every variant of `T`: their indices run from 0
/// with none left out, and the next index is no variant at all.
fn assert_every_variant<T: Serialize + DeserializeOwned>(what: &str, values: &[T]) {
    // Every enum here has fewer than 128 variants: the index is one byte.
    let seen: BTreeSet<u8> = values
        .iter()
        .map(|v| postcard::to_stdvec(v).unwrap()[0])
        .collect();
    let n = u8::try_from(seen.len()).unwrap();
    assert!(
        seen.iter().copied().eq(0..n),
        "{what}: a variant has no instance in `samples`, which holds {seen:?}"
    );
    assert_eq!(
        postcard::from_bytes::<T>(&[n]).err(),
        Some(postcard::Error::SerdeDeCustom),
        "{what}: variant {n} has no instance in `samples`"
    );
}

fn station(last: u8, mode: RateMode) -> Station {
    Station {
        mac: [0x02, 0, 0, 0, 0, last],
        bss: 300,
        signal: -54,
        signal_avg: -57,
        rx_bytes: 1 << 33,
        tx_bytes: (1 << 34) + 1,
        rx_packets: (1 << 35) + 2,
        tx_packets: (1 << 36) + 3,
        tx_retries: 70_001,
        tx_failed: 70_002,
        tx_rate_kbps: 1_201_000,
        rx_rate_kbps: 864_700,
        tx_mcs: 200,
        rx_mcs: 201,
        tx_mode: mode,
        rx_mode: RateMode::Vht,
        tx_nss: 202,
        rx_nss: 203,
        tx_airtime_us: (1 << 37) + 4,
        rx_airtime_us: (1 << 38) + 5,
        inactive_ms: 70_003,
        connected_s: 70_004,
        vlan: 4094,
    }
}

fn bss(ifname: &str, phy: &str) -> Bss {
    Bss {
        ifname: ifname.into(),
        bssid: [0x02, 0, 0, 0, 0x10, 0x01],
        ssid: "ssid-a".into(),
        phy: phy.into(),
        vlan: 300,
    }
}

fn radio(phy: &str, band: Band) -> Radio {
    Radio {
        phy: phy.into(),
        band,
        channel: 300,
        width_mhz: 320,
        txpower_mbm: -70_000,
        noise_dbm: -95,
        active_ms: 1 << 33,
        busy_ms: (1 << 33) + 1,
        rx_ms: (1 << 33) + 2,
        tx_ms: (1 << 33) + 3,
        up: true,
    }
}

/// Messages, each with its name in the golden.
type Named<T> = Vec<(&'static str, T)>;

/// One of every message, by name.
fn samples() -> (Named<AgentMsg>, Named<CtlMsg>) {
    let snapshot = Snapshot {
        seq: 1 << 40,
        uptime_s: 70_005,
        load_milli: 70_006,
        mem_avail_kb: 70_007,
        nss_load_pct: 204,
        temps: vec![Temp {
            zone: "cpu".into(),
            milli_c: -70_008,
        }],
        radios: vec![
            radio("phy0", Band::B24),
            radio("phy1", Band::B5),
            radio("phy2", Band::B6),
        ],
        bsss: vec![bss("wlan0", "phy0"), bss("wlan1", "phy1")],
        stations: [RateMode::Legacy, RateMode::Ht, RateMode::Vht, RateMode::He]
            .into_iter()
            .zip(1..)
            .map(|(m, last)| station(last, m))
            .collect(),
    };
    let rec = |idx| RecDelta {
        idx,
        mask: 0x8000_0001,
        vals: vec![i64::MIN, -1, 1, i64::MAX],
    };
    let delta = SnapshotDelta {
        seq: (1 << 40) + 1,
        base: 1 << 40,
        scalars: FieldDelta {
            mask: 0x8000_0003,
            vals: vec![-70_000, 70_000],
        },
        radios: vec![rec(300)],
        stations: vec![rec(301)],
        removed: vec![[0x02, 0, 0, 0, 0, 9]],
        added: vec![station(10, RateMode::He)],
        bsss: Some(vec![bss("wlan2", "phy2")]),
    };
    let mac = [0x02, 0, 0, 0, 0, 1];
    let phy = || "phy1".to_owned();
    let events = [
        ("Assoc", EventKind::Assoc { mac, bss: 300 }),
        ("Disassoc", EventKind::Disassoc { mac, bss: 300 }),
        ("EapOk", EventKind::EapOk { mac, bss: 300 }),
        ("EapFail", EventKind::EapFail { mac, bss: 300 }),
        ("RadioUp", EventKind::RadioUp { phy: phy() }),
        ("RadioDown", EventKind::RadioDown { phy: phy() }),
        ("FwCrash", EventKind::FwCrash { phy: phy() }),
    ];
    let mut agent = vec![
        (
            "Hello",
            AgentMsg::Hello(Hello {
                ap: "ap1".into(),
                manifest: "image: test\nhostapd: 2.11".into(),
                kernel: "6.12.57".into(),
                hostapd: "2.11".into(),
                agent: "1.0.0".into(),
            }),
        ),
        ("Key", AgentMsg::Key(snapshot)),
        ("Delta", AgentMsg::Delta(delta)),
        ("Pong", AgentMsg::Pong(1 << 50)),
    ];
    for (name, kind) in events {
        let at_ms = 1 << 41;
        agent.push((name, AgentMsg::Event(Event { at_ms, kind })));
    }
    agent.push(("Flows", AgentMsg::Flows(flows())));
    agent.push((
        "Result",
        AgentMsg::Result(CommandResult {
            id: 1 << 42,
            ok: true,
            detail: "OK".into(),
        }),
    ));
    let mut ctl = vec![
        ("SetTick", CtlMsg::SetTick { secs: 300 }),
        ("WantKey", CtlMsg::WantKey),
        ("Ping", CtlMsg::Ping(1 << 50)),
        ("WantFlows", CtlMsg::WantFlows { full: true }),
        ("FlowCadence", CtlMsg::FlowCadence { secs: 300 }),
    ];
    let target_bssid = [0x02, 0, 0, 0, 0x20, 0x01];
    let commands = [
        ("Kick", CommandKind::Kick { mac }),
        ("Block", CommandKind::Block { mac }),
        ("Unblock", CommandKind::Unblock { mac }),
        ("Steer", CommandKind::Steer { mac, target_bssid }),
    ];
    for (name, kind) in commands {
        ctl.push((name, CtlMsg::Command(Command { id: 1 << 42, kind })));
    }
    (agent, ctl)
}

/// A client's flows, one of each address family.
fn flows() -> Flows {
    let flow = |src: IpAddr, dst: IpAddr| Flow {
        proto: 200,
        src,
        sport: 60_001,
        dst,
        dport: 60_002,
        tx_bytes: 1 << 33,
        rx_bytes: (1 << 34) + 1,
        tx_packets: (1 << 35) + 2,
        rx_packets: (1 << 36) + 3,
        offloaded: true,
        age_s: 70_009,
    };
    let v4 = |last| IpAddr::V4(Ipv4Addr::new(192, 0, 2, last));
    let v6 = |last| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last));
    Flows {
        seq: (1 << 40) + 2,
        complete: true,
        clients: vec![ClientFlows {
            mac: [0x02, 0, 0, 0, 0, 1],
            conns: 70_010,
            offloaded: 70_011,
            tx_bytes: (1 << 37) + 4,
            rx_bytes: (1 << 38) + 5,
            tx_packets: (1 << 39) + 6,
            rx_packets: (1 << 40) + 7,
            top: vec![flow(v4(10), v4(200)), flow(v6(0x10), v6(0x200))],
        }],
    }
}

/// The golden text: one `<name> <hex>` line per message.
fn render() -> String {
    let (agent, ctl) = samples();
    let agent = agent.iter().map(|(n, m)| (n, postcard::to_stdvec(m)));
    let ctl = ctl.iter().map(|(n, m)| (n, postcard::to_stdvec(m)));
    agent
        .chain(ctl)
        .map(|(n, b)| format!("{n} {}\n", hex(&b.unwrap())))
        .collect()
}

fn path(protocol: u16) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("golden/protocol-{protocol}.txt"))
}

#[test]
fn every_variant_has_an_instance() {
    let (agent, ctl) = samples();
    let agent: Vec<AgentMsg> = agent.into_iter().map(|(_, m)| m).collect();
    let ctl: Vec<CtlMsg> = ctl.into_iter().map(|(_, m)| m).collect();
    let mut events = Vec::new();
    let (mut bands, mut modes, mut addrs) = (Vec::new(), Vec::new(), Vec::new());
    for m in &agent {
        match m {
            AgentMsg::Event(e) => events.push(e.kind.clone()),
            AgentMsg::Key(s) => {
                bands.extend(s.radios.iter().map(|r| r.band));
                modes.extend(s.stations.iter().map(|st| st.tx_mode));
            }
            AgentMsg::Flows(f) => {
                let flows = f.clients.iter().flat_map(|c| &c.top);
                addrs.extend(flows.flat_map(|f| [f.src, f.dst]));
            }
            _ => {}
        }
    }
    let commands: Vec<CommandKind> = ctl
        .iter()
        .filter_map(|m| match m {
            CtlMsg::Command(c) => Some(c.kind.clone()),
            _ => None,
        })
        .collect();
    assert_every_variant("AgentMsg", &agent);
    assert_every_variant("CtlMsg", &ctl);
    assert_every_variant("EventKind", &events);
    assert_every_variant("Band", &bands);
    assert_every_variant("RateMode", &modes);
    assert_every_variant("IpAddr", &addrs);
    assert_every_variant("CommandKind", &commands);
}

#[test]
fn golden_matches_the_wire_format() {
    let now = render();
    let golden = fs::read_to_string(path(PROTOCOL)).ok();
    if env::var_os("U6E_GOLDEN").is_some_and(|v| v == "write") {
        assert!(
            golden.as_ref().is_none_or(|g| *g == now),
            "protocol {PROTOCOL} already has a golden with other bytes: bump \
             u6e_proto::PROTOCOL first"
        );
        fs::write(path(PROTOCOL), &now).unwrap();
        return;
    }
    let Some(golden) = golden else {
        panic!(
            "no golden for protocol {PROTOCOL}: write it with U6E_GOLDEN=write cargo test -p u6e-proto golden"
        );
    };
    let changed: Vec<&str> = now
        .lines()
        .filter(|l| !golden.lines().any(|g| g == *l))
        .map(|l| l.split(' ').next().unwrap_or(l))
        .collect();
    assert!(
        now == golden,
        "the wire format changed (messages {changed:?}): {HOW}"
    );
}
