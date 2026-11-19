//! What an agent sends that a person reads (its image's manifest, SSIDs,
//! interface and radio names, identities, guards' details, hostapd's
//! answers), cleaned of control and Unicode format characters
//! (`u6e_proto::text`) before it reaches the state, so no AP, and no client
//! through one, can reorder or hide text in the UI.

use u6e_proto::msg::{AgentMsg, Bss, EventKind, Hello, Snapshot, StationAuth};
use u6e_proto::text::{clean_in_place as clean, clean_lines};

/// Cleans every string of `msg` a person reads.
pub fn agent_msg(msg: &mut AgentMsg) {
    match msg {
        AgentMsg::Hello(h) => hello(h),
        AgentMsg::Key(s) => snapshot(s),
        AgentMsg::Delta(d) => {
            d.bsss.iter_mut().flatten().for_each(bss);
            d.auth.iter_mut().for_each(|(_, a)| auth(a));
        }
        AgentMsg::Event(e) => match &mut e.kind {
            EventKind::RadioUp { phy }
            | EventKind::RadioDown { phy }
            | EventKind::FwCrash { phy } => clean(phy),
            EventKind::GuardViolation(v) => {
                clean(&mut v.ifname);
                clean(&mut v.detail);
            }
            _ => {}
        },
        AgentMsg::Result(r) => clean(&mut r.detail),
        AgentMsg::Spectrum(f) => clean(&mut f.radio),
        AgentMsg::SpectrumState { radio, reason, .. } => {
            clean(radio);
            clean(reason);
        }
        AgentMsg::ConfigApplied(c) => clean(&mut c.detail),
        _ => {}
    }
}

/// Cleans what an agent says it runs.
pub fn hello(h: &mut Hello) {
    for s in [&mut h.ap, &mut h.kernel, &mut h.hostapd, &mut h.agent] {
        clean(s);
    }
    clean_lines(&mut h.manifest);
}

fn snapshot(s: &mut Snapshot) {
    s.temps.iter_mut().for_each(|t| clean(&mut t.zone));
    s.radios.iter_mut().for_each(|r| clean(&mut r.phy));
    s.bsss.iter_mut().for_each(bss);
    s.auth.iter_mut().for_each(|(_, a)| auth(a));
}

fn bss(b: &mut Bss) {
    clean(&mut b.ifname);
    clean(&mut b.ssid);
    clean(&mut b.phy);
}

fn auth(a: &mut StationAuth) {
    clean(&mut a.identity);
}

#[cfg(test)]
mod tests {
    use super::*;
    use u6e_proto::msg::{Event, Guard, Violation};

    #[test]
    fn what_a_person_reads_is_cleaned() {
        let mut hello = AgentMsg::Hello(Hello {
            ap: "ap1\u{202e}".into(),
            manifest: "image: x\u{200b}\nkernel: y".into(),
            kernel: "6.12".into(),
            hostapd: "2.11".into(),
            agent: "1.0".into(),
        });
        agent_msg(&mut hello);
        let AgentMsg::Hello(h) = hello else { panic!() };
        assert_eq!(
            (h.ap.as_str(), h.manifest.as_str()),
            ("ap1", "image: x\nkernel: y")
        );
        let v = Violation {
            guard: Guard::Arp,
            mac: [2, 0, 0, 0, 0, 1],
            ifname: "wlan5".into(),
            vlan: 10,
            ip: None,
            detail: "claims\u{2066} an\u{feff} address".into(),
            dropped: false,
            repeats: 0,
        };
        let mut ev = AgentMsg::Event(Event {
            at_ms: 0,
            kind: EventKind::GuardViolation(v),
        });
        agent_msg(&mut ev);
        let AgentMsg::Event(Event {
            kind: EventKind::GuardViolation(v),
            ..
        }) = ev
        else {
            panic!()
        };
        assert_eq!(v.detail, "claims an address");
    }
}
