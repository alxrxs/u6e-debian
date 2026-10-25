//! The live view of the APs: per AP what it runs, its latest snapshot rebuilt
//! from key frames and deltas, and its recent events. Everything is in RAM; an
//! AP sends it all again when it reconnects.
//!
//! The state also sets each AP's tick. While a UI client watches an AP it
//! reports every 2 s, otherwise at the 15 s scrape interval: the session
//! follows a per-AP channel holding the tick the watchers want.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, SystemTime};

use tokio::sync::{broadcast, oneshot, watch};
use u6e_proto::PROTOCOL;
use u6e_proto::delta::{self, Gap};
use u6e_proto::msg::{AgentMsg, Event, EventKind, Hello, Snapshot, Station};

/// Events kept per AP, newest last.
pub const EVENTS_CAP: usize = 1000;
/// The tick of an AP someone is watching.
pub const TICK_WATCHED: u16 = 2;
/// The tick of an unwatched AP: the scrape interval, which is also the
/// agent's tick until it is told one.
pub const TICK_IDLE: u16 = 15;
const CHANGES_CAP: usize = 256;

/// What changed, for the UI to fetch.
#[derive(Debug, Clone, PartialEq)]
pub enum Change {
    Up(String),
    Down(String),
    Snapshot(String),
    Event(String, Event),
}

/// One configured AP.
pub struct Ap {
    /// What it last said it runs; kept while it is down.
    pub hello: Option<Hello>,
    /// The protocol its agent stated when it last dialed in.
    pub protocol: Option<u16>,
    /// The current snapshot, only while connected.
    pub snapshot: Option<Snapshot>,
    /// When `snapshot` was last brought up to date.
    pub snapshot_at: Option<SystemTime>,
    /// The snapshot before it in this session and when it came: the base
    /// the UI's rates are worked out from.
    pub previous: Option<(Snapshot, SystemTime)>,
    pub connected_since: Option<SystemTime>,
    /// When the agent last sent anything.
    pub last_seen: Option<SystemTime>,
    pub events: VecDeque<Event>,
    /// Firmware crashes per phy since the controller started.
    pub crashes: BTreeMap<String, u64>,
    rx_bytes: Arc<AtomicU64>,
    watchers: usize,
    tick: watch::Sender<u16>,
    session: Option<Live>,
}

/// The connection currently serving an AP; dropping `stop` ends it.
struct Live {
    id: u64,
    _stop: oneshot::Sender<()>,
}

impl Ap {
    fn new() -> Self {
        Ap {
            hello: None,
            protocol: None,
            snapshot: None,
            snapshot_at: None,
            previous: None,
            connected_since: None,
            last_seen: None,
            events: VecDeque::new(),
            crashes: BTreeMap::new(),
            rx_bytes: Arc::new(AtomicU64::new(0)),
            watchers: 0,
            tick: watch::Sender::new(TICK_IDLE),
            session: None,
        }
    }

    pub fn is_up(&self) -> bool {
        self.session.is_some()
    }

    /// The protocol of its agent, when that is not this controller's and the
    /// agent is therefore turned away.
    pub fn mismatch(&self) -> Option<u16> {
        self.protocol.filter(|&p| p != PROTOCOL)
    }

    /// Bytes received from the agent on the wire, TLS included, over every
    /// connection since the controller started.
    pub fn rx_bytes(&self) -> u64 {
        self.rx_bytes.load(Ordering::Relaxed)
    }

    fn push_event(&mut self, ev: Event) {
        if self.events.len() == EVENTS_CAP {
            self.events.pop_front();
        }
        self.events.push_back(ev);
    }

    /// Makes `next` the current snapshot, the current one its predecessor.
    fn advance(&mut self, next: Snapshot, now: SystemTime) {
        let prev = self.snapshot.replace(next);
        self.previous = prev.zip(self.snapshot_at);
        self.snapshot_at = Some(now);
    }

    /// Forgets what only a live connection knows.
    fn reset_session(&mut self) {
        self.snapshot = None;
        self.snapshot_at = None;
        self.previous = None;
        self.connected_since = None;
    }
}

/// A client as the UI and the metrics see it: once, on the AP that heard it last.
#[derive(Debug, Clone, PartialEq)]
pub struct ClientView {
    pub ap: String,
    /// The BSS's interface name.
    pub bss: String,
    pub ssid: String,
    pub station: Station,
    /// When the AP last heard from the client.
    pub last_seen: SystemTime,
}

/// What a session gets when it takes over an AP.
pub struct Registration {
    pub id: u64,
    /// The tick the AP should report at.
    pub tick: watch::Receiver<u16>,
    /// Resolves when a newer connection of the same AP takes over.
    pub stop: oneshot::Receiver<()>,
    /// The AP's received-bytes counter.
    pub rx_bytes: Arc<AtomicU64>,
}

/// The live state of every configured AP.
pub struct State {
    aps: BTreeMap<String, Ap>,
    next_id: u64,
    changes: broadcast::Sender<Change>,
}

impl State {
    pub fn new(names: impl IntoIterator<Item = String>) -> Self {
        State {
            aps: names.into_iter().map(|n| (n, Ap::new())).collect(),
            next_id: 0,
            changes: broadcast::Sender::new(CHANGES_CAP),
        }
    }

    /// Every configured AP by name, connected or not.
    pub fn aps(&self) -> impl Iterator<Item = (&str, &Ap)> {
        self.aps.iter().map(|(n, a)| (n.as_str(), a))
    }

    pub fn ap(&self, name: &str) -> Option<&Ap> {
        self.aps.get(name)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Change> {
        self.changes.subscribe()
    }

    pub fn watchers(&self, ap: &str) -> usize {
        self.aps.get(ap).map_or(0, |a| a.watchers)
    }

    fn notify(&self, change: Change) {
        // No receiver is not an error: nobody has the UI open.
        let _ = self.changes.send(change);
    }

    /// Hands the AP to a new connection, which said `hello`. A connection
    /// already serving it is told to stop.
    pub fn connect(&mut self, ap: &str, hello: Hello) -> Option<Registration> {
        let entry = self.aps.get_mut(ap)?;
        self.next_id += 1;
        let id = self.next_id;
        let (stop_tx, stop) = oneshot::channel();
        entry.session = Some(Live { id, _stop: stop_tx });
        // Each connection numbers its snapshots from 1 again, so a delta must
        // never meet the previous connection's snapshot.
        entry.reset_session();
        let now = SystemTime::now();
        entry.connected_since = Some(now);
        entry.last_seen = Some(now);
        entry.hello = Some(hello);
        entry.protocol = Some(PROTOCOL);
        let reg = Registration {
            id,
            tick: entry.tick.subscribe(),
            stop,
            rx_bytes: Arc::clone(&entry.rx_bytes),
        };
        self.notify(Change::Up(ap.to_owned()));
        Some(reg)
    }

    /// Records that the AP dialed in speaking `protocol`, not this
    /// controller's, and ends any session it held: it no longer runs what
    /// that session said. True when its protocol was another before, so that
    /// a change is told once and not at each redial.
    pub fn refuse(&mut self, ap: &str, protocol: u16) -> bool {
        let Some(entry) = self.aps.get_mut(ap) else {
            return false;
        };
        entry.last_seen = Some(SystemTime::now());
        if entry.protocol == Some(protocol) {
            return false;
        }
        entry.protocol = Some(protocol);
        entry.hello = None;
        entry.session = None;
        entry.reset_session();
        self.notify(Change::Down(ap.to_owned()));
        true
    }

    /// Ends session `id`; a no-op when a newer connection has taken over.
    pub fn disconnect(&mut self, ap: &str, id: u64) {
        let Some(entry) = self.live(ap, id) else {
            return;
        };
        entry.session = None;
        entry.reset_session();
        self.notify(Change::Down(ap.to_owned()));
    }

    /// The AP, while session `id` is the one serving it.
    fn live(&mut self, ap: &str, id: u64) -> Option<&mut Ap> {
        self.aps
            .get_mut(ap)
            .filter(|a| a.session.as_ref().is_some_and(|s| s.id == id))
    }

    /// Takes in one message of session `id`. `Err(Gap)` means a delta did not
    /// fit the snapshot held, or a key frame was not valid; nothing was
    /// applied and the session asks for a key frame. Every snapshot held is
    /// therefore valid.
    pub fn apply(&mut self, ap: &str, id: u64, msg: AgentMsg) -> Result<(), Gap> {
        let Some(entry) = self.live(ap, id) else {
            return Ok(());
        };
        let now = SystemTime::now();
        entry.last_seen = Some(now);
        let change = match msg {
            AgentMsg::Hello(h) => {
                entry.hello = Some(h);
                None
            }
            AgentMsg::Key(s) => {
                // Deltas must be able to build on it.
                if !delta::valid(&s) {
                    return Err(Gap);
                }
                entry.advance(s, now);
                Some(Change::Snapshot(ap.to_owned()))
            }
            AgentMsg::Delta(d) => {
                let next = delta::apply(entry.snapshot.as_ref().ok_or(Gap)?, &d)?;
                entry.advance(next, now);
                Some(Change::Snapshot(ap.to_owned()))
            }
            AgentMsg::Event(ev) => {
                if let EventKind::FwCrash { phy } = &ev.kind {
                    *entry.crashes.entry(phy.clone()).or_default() += 1;
                }
                entry.push_event(ev.clone());
                Some(Change::Event(ap.to_owned(), ev))
            }
            // A Pong only proves the agent is alive.
            _ => None,
        };
        if let Some(c) = change {
            self.notify(c);
        }
        Ok(())
    }

    /// Every associated client, sorted by MAC. A MAC in two snapshots (a roam
    /// the old AP has not reported yet) is listed once, where it was heard
    /// last: the snapshot's time less the station's inactive time.
    pub fn clients(&self) -> Vec<ClientView> {
        let mut by_mac: BTreeMap<[u8; 6], ClientView> = BTreeMap::new();
        for (name, ap) in &self.aps {
            let (Some(snap), Some(at)) = (&ap.snapshot, ap.snapshot_at) else {
                continue;
            };
            for st in &snap.stations {
                let idle = Duration::from_millis(u64::from(st.inactive_ms));
                let seen = at.checked_sub(idle).unwrap_or(SystemTime::UNIX_EPOCH);
                if by_mac.get(&st.mac).is_some_and(|c| c.last_seen >= seen) {
                    continue;
                }
                // A valid snapshot has every station on a BSS of its list.
                let Some(bss) = snap.bsss.get(usize::from(st.bss)) else {
                    continue;
                };
                let view = ClientView {
                    ap: name.clone(),
                    bss: bss.ifname.clone(),
                    ssid: bss.ssid.clone(),
                    station: st.clone(),
                    last_seen: seen,
                };
                by_mac.insert(st.mac, view);
            }
        }
        by_mac.into_values().collect()
    }
}

/// The state as the sessions, the metrics and the UI share it.
#[derive(Clone)]
pub struct Shared(Arc<RwLock<State>>);

impl Shared {
    pub fn new(state: State) -> Self {
        Shared(Arc::new(RwLock::new(state)))
    }

    pub fn read(&self) -> RwLockReadGuard<'_, State> {
        self.0.read().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn write(&self) -> RwLockWriteGuard<'_, State> {
        self.0.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// Counts a watcher of `ap` until the guard is dropped; the first one
    /// moves the AP to the 2 s tick, the last one to leave moves it back.
    pub fn watch(&self, ap: &str) -> Option<WatchGuard> {
        let mut state = self.write();
        let entry = state.aps.get_mut(ap)?;
        entry.watchers += 1;
        if entry.watchers == 1 {
            entry.tick.send_replace(TICK_WATCHED);
        }
        Some(WatchGuard {
            shared: self.clone(),
            ap: ap.to_owned(),
        })
    }
}

/// One watcher of an AP; see [`Shared::watch`].
pub struct WatchGuard {
    shared: Shared,
    ap: String,
}

impl Drop for WatchGuard {
    fn drop(&mut self) {
        let mut state = self.shared.write();
        if let Some(entry) = state.aps.get_mut(&self.ap) {
            entry.watchers -= 1;
            if entry.watchers == 0 {
                entry.tick.send_replace(TICK_IDLE);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use u6e_proto::msg::{Bss, FieldDelta, RateMode, SnapshotDelta};

    fn hello(ap: &str) -> Hello {
        Hello {
            ap: ap.into(),
            manifest: String::new(),
            kernel: String::new(),
            hostapd: String::new(),
            agent: String::new(),
        }
    }

    fn station(last: u8, bss: u16, inactive_ms: u32) -> Station {
        Station {
            mac: [2, 0, 0, 0, 0, last],
            bss,
            signal: -50,
            signal_avg: -50,
            rx_bytes: 0,
            tx_bytes: 0,
            rx_packets: 0,
            tx_packets: 0,
            tx_retries: 0,
            tx_failed: 0,
            tx_rate_kbps: 0,
            rx_rate_kbps: 0,
            tx_mcs: 0,
            rx_mcs: 0,
            tx_mode: RateMode::Legacy,
            rx_mode: RateMode::Legacy,
            tx_nss: 0,
            rx_nss: 0,
            tx_airtime_us: 0,
            rx_airtime_us: 0,
            inactive_ms,
            connected_s: 0,
            vlan: 0,
        }
    }

    fn snap(seq: u64, stations: Vec<Station>) -> Snapshot {
        Snapshot {
            seq,
            uptime_s: 0,
            load_milli: 0,
            mem_avail_kb: 0,
            nss_load_pct: 0,
            temps: Vec::new(),
            radios: Vec::new(),
            bsss: vec![Bss {
                ifname: "wlan0".into(),
                bssid: [2, 0, 0, 0, 1, 0],
                ssid: "Guest".into(),
                phy: "phy0".into(),
                vlan: 0,
            }],
            stations,
        }
    }

    fn delta(seq: u64, base: u64) -> SnapshotDelta {
        SnapshotDelta {
            seq,
            base,
            scalars: FieldDelta::default(),
            radios: Vec::new(),
            stations: Vec::new(),
            removed: Vec::new(),
            added: Vec::new(),
            bsss: None,
        }
    }

    fn state(names: &[&str]) -> State {
        State::new(names.iter().map(|n| n.to_string()))
    }

    #[test]
    fn delta_applies_only_to_its_base() {
        let mut s = state(&["ap1"]);
        let id = s.connect("ap1", hello("ap1")).unwrap().id;
        assert_eq!(s.apply("ap1", id, AgentMsg::Delta(delta(2, 1))), Err(Gap));
        assert_eq!(s.ap("ap1").unwrap().snapshot, None);
        s.apply("ap1", id, AgentMsg::Key(snap(1, Vec::new())))
            .unwrap();
        assert_eq!(s.apply("ap1", id, AgentMsg::Delta(delta(5, 4))), Err(Gap));
        assert_eq!(s.ap("ap1").unwrap().snapshot.as_ref().unwrap().seq, 1);
        s.apply("ap1", id, AgentMsg::Delta(delta(2, 1))).unwrap();
        assert_eq!(s.ap("ap1").unwrap().snapshot.as_ref().unwrap().seq, 2);
    }

    #[test]
    fn the_previous_snapshot_is_kept_for_the_session() {
        let mut s = state(&["ap1"]);
        let id = s.connect("ap1", hello("ap1")).unwrap().id;
        let seq = |s: &State| {
            let ap = s.ap("ap1").unwrap();
            let prev = ap.previous.as_ref().map(|(p, _)| p.seq);
            (ap.snapshot.as_ref().map(|s| s.seq), prev)
        };
        s.apply("ap1", id, AgentMsg::Key(snap(1, Vec::new())))
            .unwrap();
        assert_eq!(seq(&s), (Some(1), None));
        s.apply("ap1", id, AgentMsg::Delta(delta(2, 1))).unwrap();
        assert_eq!(seq(&s), (Some(2), Some(1)));
        s.apply("ap1", id, AgentMsg::Key(snap(3, Vec::new())))
            .unwrap();
        assert_eq!(seq(&s), (Some(3), Some(2)));
        let id = s.connect("ap1", hello("ap1")).unwrap().id;
        assert_eq!(seq(&s), (None, None));
        s.apply("ap1", id, AgentMsg::Key(snap(1, Vec::new())))
            .unwrap();
        assert_eq!(seq(&s), (Some(1), None));
    }

    #[test]
    fn reconnect_forgets_the_old_snapshot() {
        let mut s = state(&["ap1"]);
        let old = s.connect("ap1", hello("ap1")).unwrap();
        s.apply("ap1", old.id, AgentMsg::Key(snap(1, Vec::new())))
            .unwrap();
        let mut new = s.connect("ap1", hello("ap1")).unwrap();
        // The new connection's seq 2 is not the old connection's.
        assert_eq!(
            s.apply("ap1", new.id, AgentMsg::Delta(delta(2, 1))),
            Err(Gap)
        );
        // The old session is told to stop and can no longer write.
        let mut stop = old.stop;
        assert!(matches!(
            stop.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        assert!(matches!(
            new.stop.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        s.apply("ap1", old.id, AgentMsg::Key(snap(9, Vec::new())))
            .unwrap();
        s.disconnect("ap1", old.id);
        assert!(s.ap("ap1").unwrap().is_up());
        assert_eq!(s.ap("ap1").unwrap().snapshot, None);
        s.disconnect("ap1", new.id);
        assert!(!s.ap("ap1").unwrap().is_up());
        assert_eq!(s.ap("ap1").unwrap().hello, Some(hello("ap1")));
    }

    #[test]
    fn events_keep_the_newest_thousand_and_count_crashes() {
        let mut s = state(&["ap1"]);
        let id = s.connect("ap1", hello("ap1")).unwrap().id;
        for at_ms in 0..1005 {
            let kind = EventKind::FwCrash { phy: "phy1".into() };
            s.apply("ap1", id, AgentMsg::Event(Event { at_ms, kind }))
                .unwrap();
        }
        let ap = s.ap("ap1").unwrap();
        assert_eq!(ap.events.len(), EVENTS_CAP);
        assert_eq!(ap.events.front().unwrap().at_ms, 5);
        assert_eq!(ap.crashes["phy1"], 1005);
    }

    #[test]
    fn clients_dedup_by_last_heard() {
        let mut s = state(&["ap1", "ap2"]);
        let a = s.connect("ap1", hello("ap1")).unwrap().id;
        let b = s.connect("ap2", hello("ap2")).unwrap().id;
        // ap2 reports first, but the client went quiet there 10 s ago.
        let quiet = vec![station(1, 0, 10_000), station(2, 0, 0)];
        s.apply("ap2", b, AgentMsg::Key(snap(1, quiet))).unwrap();
        s.apply("ap1", a, AgentMsg::Key(snap(1, vec![station(1, 0, 0)])))
            .unwrap();
        let c = s.clients();
        let seen: Vec<_> = c
            .iter()
            .map(|c| (c.station.mac[5], c.ap.as_str()))
            .collect();
        assert_eq!(seen, [(1, "ap1"), (2, "ap2")]);
        assert_eq!((c[0].bss.as_str(), c[0].ssid.as_str()), ("wlan0", "Guest"));
    }

    #[test]
    fn invalid_key_frame_is_refused() {
        let mut s = state(&["ap1"]);
        let id = s.connect("ap1", hello("ap1")).unwrap().id;
        s.apply("ap1", id, AgentMsg::Key(snap(1, vec![station(1, 0, 0)])))
            .unwrap();
        let unsorted = vec![station(2, 0, 0), station(1, 0, 0)];
        let duplicate = vec![station(1, 0, 0), station(1, 0, 0)];
        let off_the_list = vec![station(1, 7, 0)];
        for stations in [unsorted, duplicate, off_the_list] {
            assert_eq!(
                s.apply("ap1", id, AgentMsg::Key(snap(2, stations))),
                Err(Gap)
            );
            assert_eq!(s.ap("ap1").unwrap().snapshot.as_ref().unwrap().seq, 1);
        }
    }

    #[test]
    fn changes_are_broadcast() {
        let mut s = state(&["ap1"]);
        let mut rx = s.subscribe();
        let id = s.connect("ap1", hello("ap1")).unwrap().id;
        s.apply("ap1", id, AgentMsg::Key(snap(1, Vec::new())))
            .unwrap();
        s.apply("ap1", id, AgentMsg::Pong(1)).unwrap();
        s.disconnect("ap1", id);
        let got: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        let ap1 = || "ap1".to_owned();
        assert_eq!(
            got,
            [
                Change::Up(ap1()),
                Change::Snapshot(ap1()),
                Change::Down(ap1())
            ]
        );
    }

    #[test]
    fn a_refused_protocol_is_told_once_per_change() {
        let mut s = state(&["ap1"]);
        let mut rx = s.subscribe();
        let reg = s.connect("ap1", hello("ap1")).unwrap();
        assert_eq!(s.ap("ap1").unwrap().mismatch(), None);
        assert!(s.refuse("ap1", 0));
        // An old agent redials: nothing new to tell.
        assert!(!s.refuse("ap1", 0));
        let mut stop = reg.stop;
        assert!(matches!(
            stop.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        let ap = s.ap("ap1").unwrap();
        assert!(!ap.is_up());
        assert_eq!((ap.mismatch(), &ap.hello), (Some(0), &None));
        assert!(s.refuse("ap1", PROTOCOL + 1));
        s.connect("ap1", hello("ap1")).unwrap();
        assert_eq!(s.ap("ap1").unwrap().mismatch(), None);
        assert!(s.refuse("ap1", PROTOCOL + 1));
        assert!(!s.refuse("ap9", 0));
        let got: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        let (up, down) = (Change::Up("ap1".into()), Change::Down("ap1".into()));
        assert_eq!(got, [up.clone(), down.clone(), down.clone(), up, down]);
    }

    #[test]
    fn watchers_drive_the_tick() {
        let shared = Shared::new(state(&["ap1"]));
        let mut tick = shared.write().connect("ap1", hello("ap1")).unwrap().tick;
        assert_eq!(*tick.borrow(), TICK_IDLE);
        let first = shared.watch("ap1").unwrap();
        assert!(tick.has_changed().unwrap());
        assert_eq!(*tick.borrow_and_update(), TICK_WATCHED);
        let second = shared.watch("ap1").unwrap();
        assert_eq!(shared.read().watchers("ap1"), 2);
        drop(first);
        assert!(!tick.has_changed().unwrap());
        drop(second);
        assert_eq!(*tick.borrow_and_update(), TICK_IDLE);
        assert_eq!(shared.read().watchers("ap1"), 0);
        assert!(shared.watch("ap9").is_none());
    }
}
