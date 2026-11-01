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
//! counted per AP, guard and VLAN from the first of each, repeats included.

use std::collections::BTreeSet;
use std::fmt::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::State as Ext;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use u6e_proto::PROTOCOL;
use u6e_proto::mac;
use u6e_proto::msg::{Radio, Snapshot, Station};

use crate::spectrum::{RADIOS, Scan};
use crate::state::{Ap, OUTCOMES, Shared, State, is_failure};
use crate::view::{band, guard_name};

/// The operator's actions and their results, every pair always exported.
const ACTIONS: [&str; 4] = ["kick", "block", "unblock", "steer"];
const RESULTS: [&str; 3] = ["ok", "failed", "timeout"];

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
    m.family(
        "wifi_blocked_clients",
        GAUGE,
        "Clients the operator blocked on every AP.",
    );
    m.sample(&[], state.blocked.len() as f64);
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

/// The client guards: each AP's bindings while connected, and its
/// violations.
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
