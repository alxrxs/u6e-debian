//! `/metrics` in the Prometheus text exposition format, rendered from the live
//! state at each scrape. Client series exist only for associated clients, so
//! their number follows the clients on the air, not every MAC ever seen; the
//! connection counts only for those of an AP that has sent its flows. The
//! spectrum series are per radio that scans, of every AP with a snapshot.
//! The configurations' series exist only when the controller signs them,
//! the rollouts' only when it rolls images out; the configurations sent and
//! the rollouts ended are counted by result, every result always exported,
//! and the last rollout that failed is timed from the rollouts the policy
//! file keeps, so that its alert outlives a restart. The sessions refused for
//! naming another AP are counted per AP, and a radio not as the site file
//! plans it is timed from when it was found so. The lease exporters' series
//! exist only when the leases are read. The client guards' violations are
//! counted per AP, guard and VLAN from the first of each, repeats included
//! (a sleep proxy's reports apart, per AP alone: `sleep_proxy`), and the
//! frames their filters dropped per AP and guard as the AP counts them. Per identity (an EAP identity, or the MAC of a MAC-authenticated
//! client), the only label of its series, so their number is bounded by
//! the identities the sessions keep (`sessions::IDENTITIES_MAX`): its ended
//! sessions and its bytes (those of its open sessions counted in), its
//! clients on now; per client certificate, by its common name (the
//! certificates the sessions keep, as many), its expiry; the RADIUS log's
//! reads and its newest verdict exist only when it is read. The rate limits
//! are counted per connected AP by how they stand there, every state always
//! exported, and an AP whose offload a capture holds back says so. What an
//! AP's client guards read of mDNS is counted per AP alone (its devices,
//! offers, offers not answering, messages read, unreadable, evicted and
//! dropped past the guards' rate), never per device or service, and the
//! clients whose traffic is kept are counted. The roams are counted per AP
//! roamed to and kind, every kind always exported, failed roams, sticky
//! time and the clients sticky now per AP, steering per AP and answer, every
//! answer always exported, and the moves after it per AP. The experience
//! score is per AP with clients, with each part's mean, and per client for
//! at most [`EXPERIENCE_CLIENTS`] associated clients that have a name (the
//! DHCP server's device, a lease's host name or a DNS name; the first by
//! name), labelled by MAC and name: one series per named device, not per
//! MAC ever seen. The speed tests are counted by kind and result, every pair
//! always exported, each AP's last one gives its rate and CPU per
//! direction, and the clients' last one on each AP and band its rates.
//! The presence events exist only when they go to Home Assistant: per
//! listed device (at most `presence::DEVICES_MAX`) its state, and counted
//! by result. The MAC authentication mapping's exist only when admins edit
//! it: whether its last read worked and when one last did, its entries and
//! version, and the changes by result, every result always exported. The
//! connections over mutual TLS not made are counted per endpoint switched
//! to it and why, every pair always exported.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::State as Ext;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use u6e_proto::PROTOCOL;
use u6e_proto::mac;
use u6e_proto::msg::{LimitStatus, Radio, Snapshot, Station};

use crate::experience::{self, PARTS};
use crate::limits::status_name;
use crate::mtls;
use crate::roaming::{Answer, Kind};
use crate::services::Table;
use crate::sessions::Totals;
use crate::sessions::unix_ms;
use crate::spectrum::{RADIOS, Scan};
use crate::speedtest;
use crate::state::{Ap, OUTCOMES, Shared, State, is_failure};
use crate::view::{band, guard_name};

/// The operator's actions and their results, every pair always exported.
const ACTIONS: [&str; 8] = [
    "kick",
    "block",
    "unblock",
    "steer",
    "limit",
    "unlimit",
    "ssid-limit",
    "capture",
];
const RESULTS: [&str; 3] = ["ok", "failed", "timeout"];
/// The states a limit has on an AP, every one always exported.
const LIMIT_STATUSES: [LimitStatus; 4] = [
    LimitStatus::Enforced,
    LimitStatus::Waiting,
    LimitStatus::Refused,
    LimitStatus::NotEnforced,
];

/// The most clients with an experience series of their own.
pub const EXPERIENCE_CLIENTS: usize = 64;

const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// The metrics listener's routes.
pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/metrics", get(scrape))
        .with_state(state)
}

async fn scrape(Ext(state): Ext<Shared>) -> impl IntoResponse {
    let body = render(&state.read());
    ([(header::CONTENT_TYPE, CONTENT_TYPE)], body)
}

/// The exposition being written: families one after another, each sample
/// under the family started last.
#[derive(Default)]
struct Text {
    out: String,
    name: &'static str,
}

impl Text {
    fn family(&mut self, name: &'static str, kind: &str, help: &str) {
        self.name = name;
        let _ = writeln!(self.out, "# HELP {name} {help}\n# TYPE {name} {kind}");
    }

    fn sample(&mut self, labels: &[(&str, &str)], value: f64) {
        self.out.push_str(self.name);
        for (i, (k, v)) in labels.iter().enumerate() {
            let sep = if i == 0 { '{' } else { ',' };
            let _ = write!(self.out, "{sep}{k}=\"{}\"", escape(v));
        }
        if !labels.is_empty() {
            self.out.push('}');
        }
        // f64's Display never uses an exponent and drops a zero fraction.
        let _ = writeln!(self.out, " {value}");
    }
}

/// A label value as the exposition format quotes it.
fn escape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

fn unix_seconds(t: SystemTime) -> f64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

const GAUGE: &str = "gauge";
const COUNTER: &str = "counter";

type RadioValue = fn(&Radio) -> f64;

const RADIO_GAUGES: [(&str, &str, RadioValue); 4] = [
    ("wifi_radio_channel", "The radio's primary channel.", |r| {
        f64::from(r.channel)
    }),
    (
        "wifi_radio_width_mhz",
        "The radio's channel width in MHz.",
        |r| f64::from(r.width_mhz),
    ),
    (
        "wifi_radio_txpower_dbm",
        "The radio's transmit power in dBm.",
        |r| f64::from(r.txpower_mbm) / 100.0,
    ),
    (
        "wifi_radio_noise_dbm",
        "The noise floor on the radio's channel in dBm.",
        |r| f64::from(r.noise_dbm),
    ),
];

const RADIO_COUNTERS: [(&str, &str, RadioValue); 4] = [
    (
        "wifi_radio_active_seconds_total",
        "Time the radio was on its channel.",
        |r| r.active_ms as f64 / 1000.0,
    ),
    (
        "wifi_radio_busy_seconds_total",
        "Time the radio sensed its channel busy.",
        |r| r.busy_ms as f64 / 1000.0,
    ),
    (
        "wifi_radio_rx_seconds_total",
        "Time the radio spent receiving.",
        |r| r.rx_ms as f64 / 1000.0,
    ),
    (
        "wifi_radio_tx_seconds_total",
        "Time the radio spent transmitting.",
        |r| r.tx_ms as f64 / 1000.0,
    ),
];

type StationValue = fn(&Station) -> f64;

const CLIENT_FAMILIES: [(&str, &str, &str, StationValue); 5] = [
    (
        "wifi_client_signal_dbm",
        GAUGE,
        "The client's signal at the AP in dBm.",
        |st| f64::from(st.signal),
    ),
    (
        "wifi_client_rx_bytes_total",
        COUNTER,
        "Bytes the AP received from the client.",
        |st| st.rx_bytes as f64,
    ),
    (
        "wifi_client_tx_bytes_total",
        COUNTER,
        "Bytes the AP sent to the client.",
        |st| st.tx_bytes as f64,
    ),
    (
        "wifi_client_tx_retries_total",
        COUNTER,
        "Frames the AP retransmitted to the client.",
        |st| f64::from(st.tx_retries),
    ),
    (
        "wifi_client_tx_rate_bps",
        GAUGE,
        "The AP's last transmit rate to the client in bit/s.",
        |st| f64::from(st.tx_rate_kbps) * 1000.0,
    ),
];

/// A radio's scan, if it was ever watched.
type ScanValue = fn(Option<&Scan>) -> f64;

const SPECTRUM_FAMILIES: [(&str, &str, &str, ScanValue); 2] = [
    (
        "wifi_spectrum_scans_running",
        GAUGE,
        "Whether the radio's spectrum scan runs, as the AP says.",
        |s| f64::from(u8::from(s.is_some_and(|s| s.running))),
    ),
    (
        "wifi_spectrum_frames_total",
        COUNTER,
        "Spectrum frames received from the radio.",
        |s| s.map_or(0, |s| s.frames_total) as f64,
    ),
];

/// The whole exposition for `state`.
pub fn render(state: &State) -> String {
    let mut m = Text::default();
    let aps: Vec<(&str, &Ap)> = state.aps().collect();
    let snaps: Vec<(&str, &Snapshot)> = aps
        .iter()
        .filter_map(|&(n, a)| Some((n, a.snapshot.as_ref()?)))
        .collect();

    m.family("wifi_ap_up", GAUGE, "Whether the AP's agent is connected.");
    for &(ap, a) in &aps {
        m.sample(&[("ap", ap)], f64::from(u8::from(a.is_up())));
    }
    m.family(
        "wifi_controller_protocol",
        GAUGE,
        "The link protocol this controller speaks.",
    );
    m.sample(&[], f64::from(PROTOCOL));
    m.family(
        "wifi_agent_protocol",
        GAUGE,
        "The link protocol the AP's agent stated when it last dialed in.",
    );
    for &(ap, a) in &aps {
        if let Some(p) = a.protocol {
            m.sample(&[("ap", ap)], f64::from(p));
        }
    }
    m.family(
        "wifi_agent_compatible",
        GAUGE,
        "Whether the AP's agent speaks this controller's protocol; one that does not is turned away.",
    );
    for &(ap, a) in &aps {
        if a.protocol.is_some() {
            m.sample(&[("ap", ap)], f64::from(u8::from(a.mismatch().is_none())));
        }
    }
    m.family(
        "wifi_agent_identity_refused_total",
        COUNTER,
        "Sessions of the AP's key turned away because the agent named itself by another host name than the AP's.",
    );
    for &(ap, a) in &aps {
        m.sample(&[("ap", ap)], a.identity_refused as f64);
    }
    m.family(
        "wifi_agent_last_seen_timestamp_seconds",
        GAUGE,
        "When the AP's agent last sent anything.",
    );
    for &(ap, a) in &aps {
        if let Some(t) = a.last_seen {
            m.sample(&[("ap", ap)], unix_seconds(t));
        }
    }
    m.family(
        "wifi_agent_received_bytes_total",
        COUNTER,
        "Bytes received from the AP's agent on the wire, TLS included.",
    );
    for &(ap, a) in &aps {
        m.sample(&[("ap", ap)], a.rx_bytes() as f64);
    }
    m.family(
        "wifi_firmware_crashes_total",
        COUNTER,
        "Firmware crashes of the AP's radios.",
    );
    for &(ap, a) in &aps {
        let radios = a.snapshot.iter().flat_map(|s| &s.radios);
        let phys: BTreeSet<&str> = radios
            .map(|r| r.phy.as_str())
            .chain(a.crashes.keys().map(String::as_str))
            .collect();
        for phy in phys {
            let n = a.crashes.get(phy).copied().unwrap_or(0);
            m.sample(&[("ap", ap), ("phy", phy)], n as f64);
        }
    }

    m.family("wifi_ap_uptime_seconds", GAUGE, "Time since the AP booted.");
    for &(ap, s) in &snaps {
        m.sample(&[("ap", ap)], f64::from(s.uptime_s));
    }
    m.family(
        "wifi_ap_mem_available_bytes",
        GAUGE,
        "Memory available on the AP.",
    );
    for &(ap, s) in &snaps {
        m.sample(&[("ap", ap)], f64::from(s.mem_avail_kb) * 1024.0);
    }
    m.family(
        "wifi_offload_held",
        GAUGE,
        "1 while a capture holds a client's flows off the AP's NSS offload (its restore not done).",
    );
    for &(ap, s) in &snaps {
        m.sample(&[("ap", ap)], f64::from(u8::from(s.offload_held)));
    }
    m.family(
        "wifi_ap_nss_load_ratio",
        GAUGE,
        "Load of the AP's network processor, 0 to 1.",
    );
    for &(ap, s) in &snaps {
        m.sample(&[("ap", ap)], f64::from(s.nss_load_pct) / 100.0);
    }
    m.family(
        "wifi_temperature_celsius",
        GAUGE,
        "Temperature of each sensor on the AP.",
    );
    for &(ap, s) in &snaps {
        for t in &s.temps {
            m.sample(
                &[("ap", ap), ("zone", &t.zone)],
                f64::from(t.milli_c) / 1000.0,
            );
        }
    }

    m.family(
        "wifi_radio_up",
        GAUGE,
        "Whether the radio is up; band in GHz.",
    );
    for &(ap, s) in &snaps {
        for r in &s.radios {
            let labels = [("ap", ap), ("phy", r.phy.as_str()), ("band", band(r.band))];
            m.sample(&labels, f64::from(u8::from(r.up)));
        }
    }
    for (families, kind) in [(&RADIO_GAUGES, GAUGE), (&RADIO_COUNTERS, COUNTER)] {
        for &(name, help, value) in families {
            m.family(name, kind, help);
            for &(ap, s) in &snaps {
                for r in &s.radios {
                    m.sample(&[("ap", ap), ("phy", &r.phy)], value(r));
                }
            }
        }
    }

    for (name, kind, help, value) in SPECTRUM_FAMILIES {
        m.family(name, kind, help);
        for &(ap, a) in &aps {
            // The radios that scan, of the snapshot or that have scanned.
            let radios = a.snapshot.iter().flat_map(|s| &s.radios);
            let radios: BTreeSet<&str> = radios
                .map(|r| r.phy.as_str())
                .filter(|r| RADIOS.contains(r))
                .chain(a.scans.keys().map(String::as_str))
                .collect();
            for radio in radios {
                m.sample(&[("ap", ap), ("radio", radio)], value(a.scans.get(radio)));
            }
        }
    }

    m.family(
        "wifi_bss_stations",
        GAUGE,
        "Stations associated with the BSS.",
    );
    for &(ap, s) in &snaps {
        for (i, b) in s.bsss.iter().enumerate() {
            let n = s
                .stations
                .iter()
                .filter(|st| usize::from(st.bss) == i)
                .count();
            let labels = [
                ("ap", ap),
                ("bss", b.ifname.as_str()),
                ("ssid", b.ssid.as_str()),
            ];
            m.sample(&labels, n as f64);
        }
    }

    let clients = state.clients();
    for (name, kind, help, value) in CLIENT_FAMILIES {
        m.family(name, kind, help);
        for c in &clients {
            let mac = mac::format(c.station.mac);
            let labels = [
                ("ap", c.ap.as_str()),
                ("ssid", c.ssid.as_str()),
                ("mac", mac.as_str()),
            ];
            m.sample(&labels, value(&c.station));
        }
    }
    let conns = [
        (
            "wifi_client_conns",
            "Connections of the client the AP forwards.",
            false,
        ),
        (
            "wifi_client_offloaded_conns",
            "Connections of the client the AP's network processor forwards, past its CPU.",
            true,
        ),
    ];
    for (name, help, offloaded) in conns {
        m.family(name, GAUGE, help);
        for c in &clients {
            let Some((flows, _)) = state.ap(&c.ap).and_then(|a| a.flows.as_ref()) else {
                continue;
            };
            let of = flows.clients.iter().find(|f| f.mac == c.station.mac);
            let n = of.map_or(0, |f| if offloaded { f.offloaded } else { f.conns });
            let mac = mac::format(c.station.mac);
            let labels = [
                ("ap", c.ap.as_str()),
                ("ssid", c.ssid.as_str()),
                ("mac", mac.as_str()),
            ];
            m.sample(&labels, f64::from(n));
        }
    }

    configs(&mut m, state, &aps);
    rollouts(&mut m, state);
    not_as_planned(&mut m, state);
    leases(&mut m, state);
    guards(&mut m, &aps);
    services(&mut m, state);
    roaming(&mut m, state, &aps);
    experience(&mut m, state);
    speedtests(&mut m, state);
    if let Some(p) = &state.presence {
        presence(&mut m, p);
    }
    if let Some(a) = &state.mac_auth {
        mac_auth(&mut m, a);
    }
    m.family(
        "wifi_traffic_clients",
        GAUGE,
        "Clients whose volumes and destinations the controller keeps.",
    );
    m.sample(&[], state.traffic.clients() as f64);
    identities(&mut m, state);
    radius_log(&mut m, state);
    tls_failures(&mut m, &state.tls_failures);
    m.family(
        "wifi_blocked_clients",
        GAUGE,
        "Clients the operator blocked on every AP.",
    );
    m.sample(&[], state.blocked.len() as f64);
    m.family(
        "wifi_limits",
        GAUGE,
        "Rate limits on each connected AP, by how they stand there.",
    );
    for (name, ap) in state.aps().filter(|(_, a)| a.is_up()) {
        for status in LIMIT_STATUSES {
            let n = ap
                .limit_states
                .iter()
                .filter(|s| s.status == status)
                .count();
            m.sample(&[("ap", name), ("status", status_name(status))], n as f64);
        }
    }
    m.family(
        "wifi_actions_total",
        COUNTER,
        "Operator actions on clients, by result (timeout: an AP did not answer in time).",
    );
    for action in ACTIONS {
        for result in RESULTS {
            let n = state.action_counts.get(&(action, result)).copied();
            m.sample(
                &[("action", action), ("result", result)],
                n.unwrap_or(0) as f64,
            );
        }
    }
    m.out
}

/// The speed tests: counted by kind and result, every pair exported; each
/// AP's last result, from the tests kept.
fn speedtests(m: &mut Text, state: &State) {
    let tests = &state.speedtests;
    m.family(
        "wifi_speedtests_total",
        COUNTER,
        "Speed tests by kind and result (refused: one could not start).",
    );
    for kind in speedtest::KINDS {
        for result in speedtest::RESULTS {
            let n = tests.counts.get(&(kind, result)).copied().unwrap_or(0);
            m.sample(&[("kind", kind), ("result", result)], n as f64);
        }
    }
    let mut last: BTreeMap<&str, &speedtest::ApTest> = BTreeMap::new();
    for t in tests.aps.iter().filter(|t| t.result.is_some()) {
        last.insert(&t.ap, t);
    }
    let results = || {
        last.iter()
            .filter_map(|(ap, t)| Some((*ap, t, t.result.as_ref()?)))
    };
    m.family(
        "wifi_ap_speedtest_bytes_per_second",
        GAUGE,
        "The AP's last speed test to the controller, each direction as its receiver timed it.",
    );
    for (ap, _, r) in results() {
        for (dir, d) in [("down", &r.down), ("up", &r.up)] {
            m.sample(
                &[("ap", ap), ("direction", dir)],
                d.bytes_per_second().round(),
            );
        }
    }
    m.family(
        "wifi_ap_speedtest_cpu_busy_ratio",
        GAUGE,
        "The AP's CPU busy over all its cores during each direction of its last speed test.",
    );
    for (ap, _, r) in results() {
        for (dir, c) in [("down", &r.cpu_down), ("up", &r.cpu_up)] {
            m.sample(
                &[("ap", ap), ("direction", dir)],
                f64::from(c.busy_permille) / 1000.0,
            );
        }
    }
    m.family(
        "wifi_ap_speedtest_timestamp_seconds",
        GAUGE,
        "When the AP's last speed test was asked.",
    );
    for (ap, t, _) in results() {
        m.sample(&[("ap", ap)], unix_seconds(t.at));
    }
    let clients = speedtest::client::last_by_place(tests);
    m.family(
        "wifi_client_speedtest_bytes_per_second",
        GAUGE,
        "The last client speed test on the AP and band: the download as the browser timed it, the upload as the controller did.",
    );
    for (ap, band, t) in &clients {
        for (dir, d) in [("down", &t.down), ("up", &t.up)] {
            if let Some(d) = d {
                let labels = [("ap", *ap), ("band", *band), ("direction", dir)];
                m.sample(&labels, d.bytes_per_second().round());
            }
        }
    }
    m.family(
        "wifi_client_speedtest_timestamp_seconds",
        GAUGE,
        "When the last client speed test on the AP and band started.",
    );
    for (ap, band, t) in &clients {
        m.sample(&[("ap", *ap), ("band", *band)], unix_seconds(t.at));
    }
}

/// The presence events, when they go to Home Assistant: each listed
/// device's state, the events by result (every result exported), those
/// waiting, whether Home Assistant refused the token, and the last delivery.
fn presence(m: &mut Text, p: &crate::presence::Presence) {
    m.family(
        "wifi_presence_home",
        GAUGE,
        "Whether the listed device is on the Wi-Fi (1) or has left it (0), by its Home Assistant name.",
    );
    for d in &p.devices {
        if let Some(home) = d.home {
            m.sample(&[("device", d.name.as_str())], f64::from(u8::from(home)));
        }
    }
    m.family(
        "wifi_presence_events_total",
        COUNTER,
        "Presence events: delivered to Home Assistant, or dropped undelivered after 5 minutes.",
    );
    m.sample(&[("result", "delivered")], p.delivered as f64);
    m.sample(&[("result", "dropped")], p.dropped as f64);
    m.family(
        "wifi_presence_pending",
        GAUGE,
        "Presence events waiting to be delivered.",
    );
    let pending = p.devices.iter().filter(|d| d.pending.is_some()).count();
    m.sample(&[], pending as f64);
    m.family(
        "wifi_presence_refused",
        GAUGE,
        "Whether Home Assistant refused the token the controller holds (no event goes until it changes).",
    );
    m.sample(&[], f64::from(u8::from(p.refused.is_some())));
    m.family(
        "wifi_presence_last_delivery_timestamp_seconds",
        GAUGE,
        "When Home Assistant last took a presence event.",
    );
    if let Some(t) = p.last_delivery {
        m.sample(&[], unix_seconds(t));
    }
}

/// RADIUS's MAC authentication mapping, when admins edit it: how reading it
/// goes, what it holds, and the changes by result.
fn mac_auth(m: &mut Text, a: &crate::macauth::MacAuth) {
    m.family(
        "wifi_mac_auth_read_up",
        GAUGE,
        "Whether the controller's last read of the MAC authentication mapping in OpenBao worked.",
    );
    m.sample(
        &[],
        f64::from(u8::from(a.error.is_none() && a.read_at.is_some())),
    );
    m.family(
        "wifi_mac_auth_last_read_timestamp_seconds",
        GAUGE,
        "When a read of the MAC authentication mapping last worked.",
    );
    if let Some(t) = a.read_at {
        m.sample(&[], unix_seconds(t));
    }
    if let Some(map) = &a.mapping {
        m.family(
            "wifi_mac_auth_entries",
            GAUGE,
            "The entries of the MAC authentication mapping as last read.",
        );
        m.sample(&[], map.entries.len() as f64);
        m.family(
            "wifi_mac_auth_version",
            GAUGE,
            "The KV version of the MAC authentication mapping as last read or written.",
        );
        m.sample(&[], map.version as f64);
    }
    m.family(
        "wifi_mac_auth_changes_total",
        COUNTER,
        "Admins' changes of the MAC authentication mapping, by result.",
    );
    for (result, n) in &a.changes {
        m.sample(&[("result", result)], *n as f64);
    }
}

/// The lease exporters, when the leases are read: whether each answered its
/// last read and when one last worked, and the clients with a lease.
fn leases(m: &mut Text, state: &State) {
    let exporters = &state.leases.exporters;
    if exporters.is_empty() {
        return;
    }
    m.family(
        "wifi_leases_exporter_up",
        GAUGE,
        "Whether the DHCP node's exporter answered the controller's last read of its leases.",
    );
    for (name, e) in exporters {
        m.sample(
            &[("exporter", name)],
            f64::from(u8::from(e.up == Some(true))),
        );
    }
    m.family(
        "wifi_leases_exporter_last_success_timestamp_seconds",
        GAUGE,
        "When the controller last read the DHCP node's leases.",
    );
    for (name, e) in exporters {
        if let Some(t) = e.last_ok {
            m.sample(&[("exporter", name)], unix_seconds(t));
        }
    }
    m.family(
        "wifi_leases_active",
        GAUGE,
        "Clients with an active lease, over every DHCP node.",
    );
    m.sample(&[], state.leases.all(SystemTime::now()).count() as f64);
}

/// The client guards: each AP's bindings while connected, its violations,
/// and the reports that were a sleep proxy's.
fn guards(m: &mut Text, aps: &[(&str, &Ap)]) {
    m.family(
        "wifi_guard_bindings",
        GAUGE,
        "Addresses the AP's client guards bind to its clients' MACs.",
    );
    for &(ap, a) in aps {
        if a.is_up() {
            m.sample(&[("ap", ap)], a.bindings.len() as f64);
        }
    }
    m.family(
        "wifi_guard_dropped_total",
        COUNTER,
        "Frames the AP's client guards dropped while enforcing, by guard, since they started.",
    );
    for &(ap, a) in aps {
        for (guard, n) in &a.guard_drops {
            m.sample(&[("ap", ap), ("guard", guard_name(*guard))], *n as f64);
        }
    }
    m.family(
        "wifi_guard_violations_total",
        COUNTER,
        "Frames of the AP's clients that broke a client guard's rule (arp, dhcp, ra, source), by VLAN.",
    );
    for &(ap, a) in aps {
        for ((guard, vlan), n) in &a.violations {
            let vlan = vlan.to_string();
            let labels = [
                ("ap", ap),
                ("guard", guard_name(*guard)),
                ("vlan", vlan.as_str()),
            ];
            m.sample(&labels, *n as f64);
        }
    }
    m.family(
        "wifi_guard_sleep_proxy_total",
        COUNTER,
        "Reports of the AP's client guards (arp, source) that were a sleep proxy answering for a sleeping device, not violations.",
    );
    for &(ap, a) in aps {
        m.sample(&[("ap", ap)], a.sleep_proxied as f64);
    }
}

/// What each AP's client guards read of mDNS.
fn services(m: &mut Text, state: &State) {
    let now = unix_ms(SystemTime::now());
    let tables: Vec<(&str, &Table)> = state.services.aps().collect();
    let mut per_ap = |name, kind, help, of: &dyn Fn(&Table) -> usize| {
        m.family(name, kind, help);
        for &(ap, t) in &tables {
            m.sample(&[("ap", ap)], of(t) as f64);
        }
    };
    per_ap(
        "wifi_mdns_devices",
        GAUGE,
        "Devices the AP's client guards heard send mDNS.",
        &|t| t.devices.len(),
    );
    per_ap(
        "wifi_mdns_offers",
        GAUGE,
        "Services those devices offer over mDNS.",
        &|t| t.offers.len(),
    );
    per_ap(
        "wifi_mdns_offers_silent",
        GAUGE,
        "Live mDNS services whose device missed the last three queries for them or more.",
        &|t| t.silent(now),
    );
    per_ap(
        "wifi_mdns_packets_total",
        COUNTER,
        "mDNS messages the AP's client guards read, since they started.",
        &|t| t.packets as usize,
    );
    per_ap(
        "wifi_mdns_malformed_total",
        COUNTER,
        "mDNS messages that did not read whole, since the guards started.",
        &|t| t.malformed as usize,
    );
    per_ap(
        "wifi_mdns_evicted_total",
        COUNTER,
        "mDNS table entries dropped for room, since the guards started.",
        &|t| t.evicted as usize,
    );
    per_ap(
        "wifi_mdns_limited_total",
        COUNTER,
        "mDNS messages dropped past the guards' rate (a flood), since they started.",
        &|t| t.limited as usize,
    );
}

/// A per-AP figure, by the AP's name.
type ApValue<'a> = &'a dyn Fn(&str) -> f64;

/// The roams, failed roams, sticky time and steering, per configured AP.
fn roaming(m: &mut Text, state: &State, aps: &[(&str, &Ap)]) {
    let r = &state.roaming;
    let c = &r.counts;
    let kinds = Kind::ALL.map(Some).into_iter().chain([None]);
    m.family(
        "wifi_roams_total",
        COUNTER,
        "Roams into the AP, by how the client authenticated there (unknown: it never was authorized).",
    );
    for &(ap, _) in aps {
        for kind in kinds.clone() {
            let n = c.roams.get(&(ap.to_owned(), kind)).copied().unwrap_or(0);
            let name = kind.map_or("unknown", Kind::name);
            m.sample(&[("ap", ap), ("kind", name)], n as f64);
        }
    }
    let now = unix_ms(SystemTime::now());
    let sticky = r.sticky(now);
    let per_ap: [(&str, &str, &str, ApValue); 4] = [
        (
            "wifi_roam_failures_total",
            COUNTER,
            "Failed roams to the AP: a sign-in that failed there, or a session that ended within 30 s.",
            &|ap| c.failures.get(ap).copied().unwrap_or(0) as f64,
        ),
        (
            "wifi_sticky_seconds_total",
            COUNTER,
            "Time clients spent sticky on the AP: below the threshold while another AP heard them 8 dB better.",
            &|ap| c.sticky_ms.get(ap).copied().unwrap_or(0) as f64 / 1000.0,
        ),
        (
            "wifi_clients_sticky",
            GAUGE,
            "Clients sticky on the AP now.",
            &|ap| sticky.iter().filter(|(_, s)| s.ap == ap).count() as f64,
        ),
        (
            "wifi_steering_moved_total",
            COUNTER,
            "Steering requests of the AP a client moved within 10 s of.",
            &|ap| c.moved.get(ap).copied().unwrap_or(0) as f64,
        ),
    ];
    for (name, kind, help, value) in per_ap {
        m.family(name, kind, help);
        for &(ap, _) in aps {
            m.sample(&[("ap", ap)], value(ap));
        }
    }
    m.family(
        "wifi_steering_total",
        COUNTER,
        "Steering requests of the AP (an admin's, its answer to a query, its own), by the client's answer.",
    );
    for &(ap, _) in aps {
        for a in Answer::ALL {
            let n = c.answers.get(&(ap.to_owned(), a)).copied().unwrap_or(0);
            m.sample(&[("ap", ap), ("answer", a.name())], n as f64);
        }
    }
}

/// The experience score per AP with clients and its parts, and per named
/// client, at most [`EXPERIENCE_CLIENTS`].
fn experience(m: &mut Text, state: &State) {
    let site = experience::site(state, unix_ms(SystemTime::now()));
    m.family(
        "wifi_ap_experience",
        GAUGE,
        "The mean Wi-Fi experience score (0 to 100) of the AP's clients.",
    );
    for (ap, e) in &site.aps {
        if let Some(s) = e.score {
            m.sample(&[("ap", ap)], f64::from(s));
        }
    }
    m.family(
        "wifi_ap_experience_part",
        GAUGE,
        "The mean of each part (0 to 100) of the experience score of the AP's clients.",
    );
    for (ap, e) in &site.aps {
        for (part, v) in PARTS.iter().zip(e.parts) {
            if let Some(v) = v {
                m.sample(&[("ap", ap), ("part", part)], v);
            }
        }
    }
    let named = named(&site.clients, |mac| {
        state.identity(mac).name().map(str::to_owned)
    });
    m.family(
        "wifi_client_experience",
        GAUGE,
        "The Wi-Fi experience score (0 to 100) of an associated client that has a name.",
    );
    for (name, mac, score) in named {
        let mac = mac::format(mac);
        m.sample(&[("mac", &mac), ("name", &name)], f64::from(score));
    }
}

/// The clients of `clients` with a score that have a name (`name`), by
/// name, at most [`EXPERIENCE_CLIENTS`]: name, MAC and score.
fn named(
    clients: &BTreeMap<[u8; 6], experience::Experience>,
    name: impl Fn(&[u8; 6]) -> Option<String>,
) -> Vec<(String, [u8; 6], u8)> {
    let mut named: Vec<_> = clients
        .iter()
        .filter_map(|(mac, e)| Some((name(mac)?, *mac, e.score?)))
        .collect();
    named.sort();
    named.truncate(EXPERIENCE_CLIENTS);
    named
}

/// Each identity's sessions, bytes, clients and client certificate.
fn identities(m: &mut Text, state: &State) {
    let ids = state.sessions.identities();
    type Value = fn(&Totals, usize) -> f64;
    let families: [(&str, &str, &str, Value); 4] = [
        (
            "wifi_identity_sessions_total",
            COUNTER,
            "Sessions of the identity's clients that ended (a roam begins a new one).",
            |t, _| t.sessions as f64,
        ),
        (
            "wifi_identity_rx_bytes_total",
            COUNTER,
            "Bytes the APs received from the identity's clients.",
            |t, _| t.up_bytes as f64,
        ),
        (
            "wifi_identity_tx_bytes_total",
            COUNTER,
            "Bytes the APs sent to the identity's clients.",
            |t, _| t.down_bytes as f64,
        ),
        (
            "wifi_identity_clients",
            GAUGE,
            "The identity's clients associated now.",
            |_, on| on as f64,
        ),
    ];
    for (name, kind, help, value) in families {
        m.family(name, kind, help);
        for (id, (t, on)) in &ids {
            m.sample(&[("identity", id)], value(t, *on));
        }
    }
    m.family(
        "wifi_client_cert_expiry_timestamp_seconds",
        GAUGE,
        "When an EAP-TLS client certificate RADIUS accepted expires, by its common name.",
    );
    for (cn, c) in state.sessions.certs() {
        m.sample(&[("cn", cn)], c.expires_s as f64);
    }
}

/// The reads of RADIUS's log, when it is read.
fn radius_log(m: &mut Text, state: &State) {
    let Some(h) = &state.radius else {
        return;
    };
    m.family(
        "wifi_radius_log_up",
        GAUGE,
        "Whether the controller's last read of RADIUS's log worked.",
    );
    m.sample(&[], f64::from(u8::from(h.up == Some(true))));
    m.family(
        "wifi_radius_log_last_success_timestamp_seconds",
        GAUGE,
        "When the controller last read RADIUS's log.",
    );
    if let Some(t) = h.last_ok {
        m.sample(&[], unix_seconds(t));
    }
    m.family(
        "wifi_radius_last_verdict_timestamp_seconds",
        GAUGE,
        "When the newest verdict read from RADIUS's log happened; absent before any.",
    );
    if let Some(ms) = h.newest_ms {
        m.sample(&[], ms as f64 / 1000.0);
    }
}

/// The connections over mutual TLS not made, when any endpoint speaks it.
fn tls_failures(m: &mut Text, f: &mtls::Failures) {
    if f.on.is_empty() {
        return;
    }
    m.family(
        "wifi_monitoring_tls_failures_total",
        COUNTER,
        "Connections over mutual TLS not made, by endpoint and why: the host's certificate \
         could not be read or used, or the handshake failed or was refused.",
    );
    for &e in &f.on {
        for r in mtls::Reason::ALL {
            let n = f.counts.get(&(e, r)).copied().unwrap_or(0);
            m.sample(&[("endpoint", e.name()), ("reason", r.name())], n as f64);
        }
    }
}

/// The APs' configurations, when the controller signs them.
fn configs(m: &mut Text, state: &State, aps: &[(&str, &Ap)]) {
    let Some(signer) = &state.signer else {
        return;
    };
    m.family(
        "wifi_config_drift",
        GAUGE,
        "Whether the connected AP runs another Wi-Fi configuration than the latest one signed for it.",
    );
    for &(ap, a) in aps {
        if a.latest.is_some() && a.snapshot.is_some() {
            m.sample(&[("ap", ap)], f64::from(u8::from(a.drifts())));
        }
    }
    m.family(
        "wifi_config_applies_total",
        COUNTER,
        "Configurations sent to the APs, by result (timeout: the AP did not answer in time).",
    );
    for result in RESULTS {
        let n = state.apply_counts.get(result).copied();
        m.sample(&[("result", result)], n.unwrap_or(0) as f64);
    }
    m.family(
        "wifi_config_state_discarded_files",
        GAUGE,
        "Files of signed configurations the controller could not read and set aside.",
    );
    let aside = signer.set_aside().map_or(0, |f| f.len());
    m.sample(&[], aside as f64);
}

/// The radios that run otherwise than the site file plans (`rf::live`),
/// since when, for the alert that waits on them.
fn not_as_planned(m: &mut Text, state: &State) {
    if state.not_as_planned.is_empty() {
        return;
    }
    m.family(
        "wifi_radio_not_as_planned_since_timestamp_seconds",
        GAUGE,
        "Since when the radio runs otherwise than the site file plans.",
    );
    for (key, n) in &state.not_as_planned {
        if let Some((ap, radio)) = key.split_once('/') {
            m.sample(&[("ap", ap), ("radio", radio)], unix_seconds(n.since));
        }
    }
}

/// The rollouts, when the controller rolls images out.
fn rollouts(m: &mut Text, state: &State) {
    let Some(kept) = &state.kept else {
        return;
    };
    m.family(
        "wifi_images_kept",
        GAUGE,
        "Images the controller keeps for the AP, which it can roll out or back to.",
    );
    for (ap, ids) in kept {
        m.sample(&[("ap", ap)], ids.len() as f64);
    }
    m.family(
        "wifi_rollouts_total",
        COUNTER,
        "Image rollouts ended, by outcome.",
    );
    for (_, outcome) in OUTCOMES {
        let n = state.rollout_counts.get(outcome).copied();
        m.sample(&[("outcome", outcome)], n.unwrap_or(0) as f64);
    }
    // From the rollouts the policy file keeps, so a restart loses no alert.
    let failed = state.rollouts.iter().filter_map(|r| {
        let (outcome, _) = r.result.as_ref()?;
        is_failure(*outcome).then_some(r.ended?)
    });
    if let Some(last) = failed.max() {
        m.family(
            "wifi_rollout_last_failure_timestamp_seconds",
            GAUGE,
            "When the last image rollout that did not end done (refused, rolled back or failed) ended.",
        );
        m.sample(&[], unix_seconds(last));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Of 65 named clients 64 have a series, the first by name; an unnamed
    /// one, or one without a score, has none.
    #[test]
    fn the_named_clients_series_are_bounded() {
        let scored = experience::Experience {
            score: Some(80),
            ..Default::default()
        };
        let mut clients = BTreeMap::new();
        for i in 0..=EXPERIENCE_CLIENTS as u8 + 1 {
            clients.insert([2, 0, 0, 0, 0, i], scored.clone());
        }
        clients.insert([2, 0, 0, 0, 1, 0], experience::Experience::default());
        let name = |m: &[u8; 6]| (m[5] != 0 || m[4] == 1).then(|| format!("device {:03}", m[5]));
        let got = named(&clients, name);
        assert_eq!(got.len(), EXPERIENCE_CLIENTS);
        assert_eq!(got[0], ("device 001".to_owned(), [2, 0, 0, 0, 0, 1], 80));
        assert_eq!(got.last().unwrap().0, "device 064");
    }

    #[test]
    fn label_values_are_escaped() {
        assert_eq!(escape(r#"a"b\c"#), r#"a\"b\\c"#);
        assert_eq!(escape("two\nlines"), "two\\nlines");
        assert_eq!(escape("Café ☕"), "Café ☕");
    }

    #[test]
    fn samples_format_their_values() {
        let mut m = Text::default();
        m.family("x", GAUGE, "An x.");
        m.sample(&[], -54.0);
        m.sample(&[("a", "1"), ("b", "\"")], 0.25);
        assert_eq!(
            m.out,
            "# HELP x An x.\n# TYPE x gauge\nx -54\nx{a=\"1\",b=\"\\\"\"} 0.25\n"
        );
    }
}
