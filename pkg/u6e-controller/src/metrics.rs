//! `/metrics` in the Prometheus text exposition format, rendered from the live
//! state at each scrape. Client series exist only for associated clients, so
//! their number follows the clients on the air, not every MAC ever seen; the
//! connection counts only for those of an AP that has sent its flows. The
//! spectrum series are per radio that scans, of every AP with a snapshot.

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
use crate::state::{Ap, Shared, State};
use crate::view::band;

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
