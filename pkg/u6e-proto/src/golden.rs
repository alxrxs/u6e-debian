//! The wire format pinned: an instance of every message and every variant,
//! each field set (numbers too large for the next smaller type, each u8 above
//! 127 so that a widening to a varint shows), encoded and compared with
//! `golden/protocol-<PROTOCOL>.txt`, with the hash of a sample configuration
//! and the bytes the deploy runner signs for it, which every end computes.
//! Bytes that differ while PROTOCOL did not fail the test, as does a variant
//! with no instance.
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
use crate::config::{config_sha256, payload};
use crate::mac::hex;
use crate::msg::{
    AgentMsg, Band, Bss, ClientFlows, Command, CommandKind, CommandResult, ConfigApplied, CtlMsg,
    Event, EventKind, FieldDelta, Flow, Flows, Hello, Mechanism, Radio, RadioApplied, RadioConfig,
    RateMode, RecDelta, RolloutOutcome, RolloutRequest, RolloutResult, RunnerCtlMsg, RunnerHello,
    RunnerMsg, SignedConfig, Snapshot, SnapshotDelta, SpectrumFrame, Station, Temp,
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

/// One of every message of each end, by name.
struct Samples {
    agent: Named<AgentMsg>,
    ctl: Named<CtlMsg>,
    runner: Named<RunnerMsg>,
    runner_ctl: Named<RunnerCtlMsg>,
}

/// A configuration of every radio, each text past 127 bytes so that its
/// length takes two bytes of varint, each power negative.
fn radio_configs() -> Vec<RadioConfig> {
    [Band::B24, Band::B5, Band::B6]
        .into_iter()
        .map(|radio| RadioConfig {
            radio,
            text: format!("interface=wlan0\n{}\n", "#".repeat(130)),
            txpower_dbm: -100,
        })
        .collect()
}

/// A signed configuration, its signature a fixed stand-in (the golden pins
/// the layout; `config` tests the signing).
fn signed_config() -> SignedConfig {
    SignedConfig {
        ap: "ap1".into(),
        seq: (1 << 42) + 2,
        sha256: [0x82; 32],
        radios: radio_configs(),
        signature: (0..64).map(|i| 0x80 + i).collect(),
    }
}

fn config_applied() -> ConfigApplied {
    let mechanisms = [
        Mechanism::Unchanged,
        Mechanism::InPlace,
        Mechanism::ChannelSwitch,
        Mechanism::Power,
        Mechanism::Restart,
    ];
    ConfigApplied {
        sha256: [0x80; 32],
        ok: true,
        radios: mechanisms
            .into_iter()
            .map(|mechanism| RadioApplied {
                radio: Band::B6,
                mechanism,
            })
            .collect(),
        detail: "wlan6: OK".into(),
    }
}

fn samples() -> Samples {
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
        config_sha256: Some([0x81; 32]),
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
    agent.push((
        "Spectrum",
        AgentMsg::Spectrum(SpectrumFrame {
            radio: "radio5".into(),
            at_ms: 1 << 41,
            center_mhz: 60_003,
            width_mhz: 320,
            first_mhz_x10: 70_012,
            step_khz: 70_013,
            bins: vec![-128, -95, 0, 127],
            noise_dbm: -96,
        }),
    ));
    agent.push((
        "SpectrumState",
        AgentMsg::SpectrumState {
            radio: "radio5".into(),
            running: true,
            reason: "started".into(),
        },
    ));
    agent.push(("ConfigApplied", AgentMsg::ConfigApplied(config_applied())));
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
        (
            "Steer",
            CommandKind::Steer {
                mac,
                target_bssid,
                force: true,
            },
        ),
        (
            "SyncBlocks",
            CommandKind::SyncBlocks {
                macs: vec![mac, target_bssid],
            },
        ),
    ];
    for (name, kind) in commands {
        ctl.push((name, CtlMsg::Command(Command { id: 1 << 42, kind })));
    }
    let radio = || "radio5".to_owned();
    ctl.push(("SpectrumStart", CtlMsg::SpectrumStart { radio: radio() }));
    ctl.push(("SpectrumStop", CtlMsg::SpectrumStop { radio: radio() }));
    ctl.push(("ApplyConfig", CtlMsg::ApplyConfig(signed_config())));
    let id = (1 << 42) + 1;
    let rollout = |outcome| {
        RunnerMsg::RolloutResult(RolloutResult {
            id,
            outcome,
            detail: "staged".into(),
        })
    };
    let runner = vec![
        (
            "RunnerHello",
            RunnerMsg::Hello(RunnerHello {
                version: "1.0.0".into(),
            }),
        ),
        ("RunnerPong", RunnerMsg::Pong(1 << 50)),
        (
            "RunnerApplyConfig",
            RunnerMsg::ApplyConfig {
                id,
                config: signed_config(),
            },
        ),
        (
            "RolloutLog",
            RunnerMsg::RolloutLog {
                id,
                line: "staging".into(),
            },
        ),
        ("RolloutRefused", rollout(RolloutOutcome::Refused)),
        ("RolloutDone", rollout(RolloutOutcome::Done)),
        ("RolloutRolledBack", rollout(RolloutOutcome::RolledBack)),
        ("RolloutFailed", rollout(RolloutOutcome::Failed)),
    ];
    let runner_ctl = vec![
        ("RunnerPing", RunnerCtlMsg::Ping(1 << 50)),
        (
            "RunnerConfigApplied",
            RunnerCtlMsg::ConfigApplied {
                id,
                result: config_applied(),
            },
        ),
        (
            "Repush",
            RunnerCtlMsg::Repush {
                ap: "ap1".into(),
                acked: Some([0x83; 32]),
                installed: None,
            },
        ),
        (
            "Rollout",
            RunnerCtlMsg::Rollout(RolloutRequest {
                id,
                ap: "ap1".into(),
                image_id: "u6e-ap1-20261025".into(),
                user: "admin".into(),
            }),
        ),
        (
            "RolloutGate",
            RunnerCtlMsg::RolloutGate {
                id,
                healthy: true,
                detail: "radios up".into(),
            },
        ),
    ];
    Samples {
        agent,
        ctl,
        runner,
        runner_ctl,
    }
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
        client_is_src: true,
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

/// The golden text: one `<name> <hex>` line per message, then the hash of
/// the sample configuration and the bytes the runner signs for it, which
/// every end must compute alike too.
fn render() -> String {
    fn lines<T: Serialize>(named: &Named<T>) -> impl Iterator<Item = String> + '_ {
        named
            .iter()
            .map(|(n, m)| format!("{n} {}\n", hex(&postcard::to_stdvec(m).unwrap())))
    }
    let s = samples();
    let sha256 = config_sha256(&radio_configs());
    let hash = format!("ConfigSha256 {}\n", hex(&sha256));
    let signed = payload(PROTOCOL, "ap1", (1 << 42) + 2, &sha256);
    let signed = format!("SignedPayload {}\n", hex(&signed));
    lines(&s.agent)
        .chain(lines(&s.ctl))
        .chain(lines(&s.runner))
        .chain(lines(&s.runner_ctl))
        .chain([hash, signed])
        .collect()
}

fn path(protocol: u16) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("golden/protocol-{protocol}.txt"))
}

#[test]
fn every_variant_has_an_instance() {
    fn values<T>(named: Named<T>) -> Vec<T> {
        named.into_iter().map(|(_, m)| m).collect()
    }
    let s = samples();
    let (agent, ctl) = (values(s.agent), values(s.ctl));
    let (runner, runner_ctl) = (values(s.runner), values(s.runner_ctl));
    let mut events = Vec::new();
    let (mut bands, mut modes, mut addrs) = (Vec::new(), Vec::new(), Vec::new());
    let (mut mechanisms, mut outcomes) = (Vec::new(), Vec::new());
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
            AgentMsg::ConfigApplied(c) => mechanisms.extend(c.radios.iter().map(|r| r.mechanism)),
            _ => {}
        }
    }
    for m in &runner {
        if let RunnerMsg::RolloutResult(r) = m {
            outcomes.push(r.outcome);
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
    assert_every_variant("RunnerMsg", &runner);
    assert_every_variant("RunnerCtlMsg", &runner_ctl);
    assert_every_variant("Mechanism", &mechanisms);
    assert_every_variant("RolloutOutcome", &outcomes);
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
