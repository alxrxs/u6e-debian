//! The clients' sessions, one per association with a BSS, and their
//! timeline (`timeline`), built from what the controller already hears: the
//! agents' events (associations, disassociations, EAP's steps) and
//! snapshots (who is associated, how each authenticated, their bytes), the
//! flows (first traffic), the leases (grants and renewals, seen at the next
//! read of the leases), RADIUS's verdicts (`radius`), the operators' actions,
//! the client guards' reports and the changes of the services a client
//! offers over mDNS (`services`).
//!
//! A session ends with a reason. An association with another BSS while one
//! is open, or within [`ROAM_WINDOW_MS`] of one ending elsewhere, is a roam,
//! and the new session's `Joined` says where from (and whether it was a fast
//! transition, once its AP says how it authenticated). A disassociation is a
//! kick or a block when an operator's came within [`CAUSE_WINDOW_MS`], EAP's
//! failure or timeout when one did, inactivity when the client had been
//! silent past [`INACTIVE_MS`], and otherwise the client leaving. A session
//! whose client was gone when its AP was heard again (its link, or the
//! controller, was away) ends unobserved at the time it was last heard, as
//! does one of an AP not heard for an hour.
//!
//! A session's identity (an EAP identity, or the MAC of a MAC-authenticated
//! client) counts only once its AP authorized it in that session: until
//! then it is only what the client claims. What is kept is bounded: the
//! sessions of the last 30 days, at most [`SESSIONS_MAX`]; the timeline's own
//! bounds; the totals of the [`IDENTITIES_MAX`] identities seen last within
//! 30 days, and as many client certificates, each by its common name (never
//! by the User-Name, which the client chooses), with its last expiry. It is all saved in one file (`history_path`, 0600:
//! it names people), whole through `store::replace`, every
//! [`SAVE_EVERY`] when it changed and when the controller stops; a file that
//! does not decode is set aside as `<name>.corrupt-<ms>` and the controller
//! starts without it.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{self, ErrorKind};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::time::interval;
use u6e_proto::mac;
use u6e_proto::msg::{AuthKind, Band, Event, EventKind, Flows, Snapshot, StationAuth};

use crate::leases::Leases;
use crate::radius::Line;
use crate::state::{Action, Naming, Shared};
use crate::store;
use crate::timeline::{EapStep, End, Entry, Place, Roam, Timeline, What};

const DAY_MS: u64 = 24 * 3600 * 1000;
/// How long ended sessions are kept, and how many at most.
pub const SESSIONS_KEEP_MS: u64 = 30 * DAY_MS;
pub const SESSIONS_MAX: usize = 10_000;
/// An association elsewhere this soon after a session ended makes the end a
/// roam.
pub const ROAM_WINDOW_MS: u64 = 10_000;
/// An operator's action, or EAP's failure, this soon before a
/// disassociation is its cause.
pub const CAUSE_WINDOW_MS: u64 = 30_000;
/// A client silent this long when it went had been dropped as inactive.
pub const INACTIVE_MS: u32 = 60_000;
/// How long before its session began a certificate's accept may come (EAP
/// runs before the association is reported).
const CERT_BEFORE_MS: u64 = 120_000;
/// An open session of an AP not heard for this long ends unobserved.
const UNHEARD_MS: u64 = 3600 * 1000;
/// A station that began this much later than its open session did is a
/// new association the events did not tell of (AP-STA-CONNECTED comes after
/// EAP, which may take this long).
const REASSOCIATED_MS: u64 = 60_000;
/// An AP's event time this far from the controller's clock is the AP's
/// unsynchronized clock (it boots at its image's build time): the event is
/// timed when it arrives.
const SKEW_MS: u64 = 5 * 60 * 1000;
/// The identities whose totals and certificate expiry are kept.
pub const IDENTITIES_MAX: usize = 256;
const IDENTITY_KEEP_MS: u64 = 30 * DAY_MS;
/// The clients whose recent causes are kept, at most.
const RECENT_MAX: usize = 4096;
/// How often the history is saved, when it changed.
pub const SAVE_EVERY: Duration = Duration::from_secs(300);
/// What the file starts with, and the format of what follows, raised with
/// every change to it.
const MARK: &[u8; 4] = b"U6CH";
const FORMAT: u16 = 2;
/// The largest file read: the bounds keep it far below.
const FILE_MAX: u64 = 256 << 20;

/// One association of a client with a BSS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub id: u64,
    pub mac: [u8; 6],
    pub place: Place,
    pub start_ms: u64,
    /// When it ended; `None` while it is open.
    pub end_ms: Option<u64>,
    /// When its client was last heard.
    pub last_ms: u64,
    /// How it authenticated, once its AP said, and whether its AP has
    /// authorized it in this session.
    pub auth: Option<StationAuth>,
    pub authenticated: bool,
    /// Bytes from the client and to it, as its AP counted them.
    pub up_bytes: u64,
    pub down_bytes: u64,
    pub end: Option<End>,
    /// The AP it roamed in from.
    pub from: Option<String>,
    /// The sign-in of the session it roamed in from, which a fast
    /// transition carries over.
    prior: Option<Prior>,
    /// Whether its first traffic was seen.
    traffic: bool,
    /// How long its client had been silent when last heard of.
    inactive_ms: u32,
}

/// The sign-in a session roamed in from ran: when its EAP ran, and the
/// identity it authenticated as.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Prior {
    signed_in_ms: u64,
    identity: Option<String>,
}

impl Session {
    /// Whether it began by a fast transition, carrying over the sign-in of
    /// the session it roamed in from.
    fn carried_over(&self) -> Option<&Prior> {
        let ft = self.auth.as_ref().is_some_and(StationAuth::fast_transition);
        self.prior.as_ref().filter(|_| ft)
    }

    /// When its sign-in ran: when it began, or, for a fast transition, when
    /// the session it roamed in from signed in.
    pub fn signed_in_ms(&self) -> u64 {
        self.carried_over()
            .map_or(self.start_ms, |p| p.signed_in_ms)
    }

    /// Its EAP identity, authenticated or only claimed: its AP's word, or,
    /// for a fast transition its AP names none for, the identity of the
    /// session it roamed in from.
    pub fn eap_identity(&self) -> Option<String> {
        let a = self.auth.as_ref().filter(|a| a.kind() == AuthKind::Eap)?;
        let carried = || self.carried_over()?.identity.clone();
        Some(a.identity.clone())
            .filter(|i| !i.is_empty())
            .or_else(carried)
    }

    /// Who it authenticated as, once its AP authorized it: its EAP
    /// identity, or its MAC when RADIUS admitted the MAC.
    pub fn identity(&self) -> Option<String> {
        let a = self.auth.as_ref().filter(|_| self.authenticated)?;
        match a.kind() {
            AuthKind::Eap => self.eap_identity(),
            AuthKind::MacAuth => Some(mac::format(self.mac)),
            _ => None,
        }
    }
}

/// An identity's sessions and bytes over the sessions that ended, and when
/// it was last seen.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totals {
    pub sessions: u64,
    pub up_bytes: u64,
    pub down_bytes: u64,
    pub seen_ms: u64,
}

/// A client certificate, by its common name: when it expires (Unix
/// seconds), as RADIUS last accepted it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cert {
    pub expires_s: u64,
    pub seen_ms: u64,
}

/// What lately happened to a client that explains how a session of it ends.
#[derive(Debug, Default)]
struct Recent {
    /// The AP whose EAP with it started last, and when.
    eap_start: Option<(String, u64)>,
    /// EAP's last failure or timeout, and when.
    failure: Option<(End, u64)>,
    /// The last operator's action that worked on it, by whom, and when.
    action: Option<(&'static str, Option<String>, u64)>,
}

impl Recent {
    fn newest(&self) -> u64 {
        let times = [
            self.eap_start.as_ref().map(|e| e.1),
            self.failure.as_ref().map(|f| f.1),
            self.action.as_ref().map(|a| a.2),
        ];
        times.into_iter().flatten().max().unwrap_or(0)
    }
}

/// What the file holds: the history, copied while the state is locked and
/// encoded after.
#[derive(Serialize, Deserialize)]
pub struct Saved {
    next_id: u64,
    open: Vec<Session>,
    closed: Vec<Session>,
    timeline: Vec<([u8; 6], Vec<Entry>)>,
    totals: Vec<(String, Totals)>,
    certs: Vec<(String, Cert)>,
}

/// The sessions, the timeline and the identities' totals.
#[derive(Debug, Default)]
pub struct Sessions {
    open: HashMap<[u8; 6], Session>,
    /// Ended sessions, the newest last.
    closed: VecDeque<Session>,
    pub timeline: Timeline,
    totals: BTreeMap<String, Totals>,
    certs: BTreeMap<String, Cert>,
    recent: HashMap<[u8; 6], Recent>,
    /// The leases at the last read, by client and address: their expiry.
    /// `None` until the first read, which only sets the baseline.
    leases: Option<HashMap<([u8; 6], IpAddr), u64>>,
    next_id: u64,
    dirty: bool,
}

/// Milliseconds since the epoch.
pub fn unix_ms(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Where a station of BSS `bss` of the AP is, as its `naming` says.
fn place(ap: &str, naming: &Naming, bss: u16, vlan: Option<u16>) -> Option<Place> {
    let b = naming.bsss.get(usize::from(bss))?;
    let band = naming
        .bands
        .iter()
        .find(|(p, _)| *p == b.phy)
        .map(|(_, b)| *b);
    Some(Place {
        ap: ap.to_owned(),
        bss: b.ifname.clone(),
        ssid: b.ssid.clone(),
        band,
        vlan: vlan.unwrap_or(b.vlan),
    })
}

impl Sessions {
    /// Whether anything changed since this was last asked.
    pub fn take_dirty(&mut self) -> bool {
        std::mem::take(&mut self.dirty)
    }

    fn push(&mut self, mac: [u8; 6], at_ms: u64, what: What) {
        self.timeline.push(mac, Entry { at_ms, what });
        self.dirty = true;
    }

    fn recent(&mut self, mac: [u8; 6]) -> &mut Recent {
        if self.recent.len() >= RECENT_MAX && !self.recent.contains_key(&mac) {
            let oldest = self.recent.iter().min_by_key(|(_, r)| r.newest());
            if let Some(m) = oldest.map(|(m, _)| *m) {
                self.recent.remove(&m);
            }
        }
        self.recent.entry(mac).or_default()
    }

    /// What ended `session`, its end seen at `seen`: what came within
    /// [`CAUSE_WINDOW_MS`] before, and in the session (a kick of an earlier
    /// one is not its). A session found gone from a snapshot was last heard
    /// before its cause came, so the window runs to when that was seen.
    fn cause(&self, mac: &[u8; 6], seen: u64, session: &Session) -> End {
        let fresh = |t: u64| t >= session.start_ms && t <= seen && seen - t <= CAUSE_WINDOW_MS;
        let r = self.recent.get(mac);
        match r.and_then(|r| r.action.clone()).filter(|a| fresh(a.2)) {
            Some(("kick", by, _)) => return End::Kicked { by },
            Some(("block", by, _)) => return End::Blocked { by },
            _ => {}
        }
        if let Some((end, _)) = r.and_then(|r| r.failure.clone()).filter(|f| fresh(f.1)) {
            return end;
        }
        if session.inactive_ms >= INACTIVE_MS {
            return End::Inactive;
        }
        End::Left
    }

    /// Takes an event of `ap` heard at `now_ms`.
    pub fn event(&mut self, ap: &str, naming: &Naming, ev: &Event, now_ms: u64) {
        let at = if ev.at_ms.abs_diff(now_ms) > SKEW_MS {
            now_ms
        } else {
            ev.at_ms
        };
        let eap = |step| What::Eap {
            ap: ap.to_owned(),
            step,
        };
        match &ev.kind {
            EventKind::Assoc { mac, bss } => {
                if let Some(p) = place(ap, naming, *bss, None) {
                    self.join(*mac, p, at, at);
                }
            }
            EventKind::Disassoc { mac, bss } => {
                let here = |s: &Session| {
                    s.place.ap == ap
                        && naming.bsss.get(usize::from(*bss)).map(|b| &b.ifname)
                            == Some(&s.place.bss)
                };
                if let Some(s) = self.open.get(mac).filter(|s| here(s)) {
                    let why = self.cause(mac, at, s);
                    self.close(*mac, at, why);
                }
            }
            EventKind::EapStart { mac, .. } => {
                self.recent(*mac).eap_start = Some((ap.to_owned(), at));
                self.push(*mac, at, eap(EapStep::Started));
            }
            EventKind::EapOk { mac, .. } => {
                let started = self.recent.get(mac).and_then(|r| r.eap_start.clone());
                let ms = started
                    .filter(|(a, t)| a == ap && *t <= at)
                    .map(|(_, t)| at - t);
                self.push(*mac, at, eap(EapStep::Succeeded { ms }));
            }
            EventKind::EapFail { mac, .. } => {
                self.recent(*mac).failure = Some((End::EapFailed, at));
                self.late_cause(*mac, ap, at, End::EapFailed);
                self.push(*mac, at, eap(EapStep::Failed));
            }
            EventKind::EapTimeout { mac, server, .. } => {
                self.recent(*mac).failure = Some((End::EapTimedOut, at));
                self.late_cause(*mac, ap, at, End::EapTimedOut);
                let step = EapStep::TimedOut { server: *server };
                self.push(*mac, at, eap(step));
            }
            EventKind::PskMismatch { mac, .. } => {
                let what = What::PskMismatch { ap: ap.to_owned() };
                self.push(*mac, at, what);
            }
            EventKind::GuardViolation(v) => {
                let what = What::Guard {
                    ap: ap.to_owned(),
                    guard: v.guard,
                    detail: v.detail.clone(),
                    dropped: v.dropped,
                    repeats: v.repeats,
                };
                self.push(v.mac, at, what);
            }
            _ => {}
        }
    }

    /// A failure of `mac` on `ap` at `at` heard after its session there was
    /// found gone (the AP's snapshot came first): the session that ended
    /// there within [`CAUSE_WINDOW_MS`] before, as having left or gone
    /// quiet, ended by it, its `Ended` entry too.
    fn late_cause(&mut self, mac: [u8; 6], ap: &str, at: u64, why: End) {
        if self.open.get(&mac).is_some_and(|s| s.place.ap == ap) {
            return;
        }
        let ended = self
            .closed
            .iter_mut()
            .rev()
            .take_while(|s| s.end_ms.is_some_and(|e| e + CAUSE_WINDOW_MS >= at))
            .find(|s| s.mac == mac)
            .filter(|s| s.place.ap == ap && s.end_ms.is_some_and(|e| e <= at))
            .filter(|s| matches!(s.end, Some(End::Left | End::Inactive)));
        let Some(s) = ended else {
            return;
        };
        s.end = Some(why.clone());
        let id = s.id;
        let pick = |w: &What| matches!(w, What::Ended { session, .. } if *session == id);
        self.timeline.edit(&mac, pick, |w| {
            if let What::Ended { why: was, .. } = w {
                *was = why;
            }
            true
        });
        self.dirty = true;
    }

    /// The client `mac` associated at `place`, beginning at `began` (heard
    /// of at `at`): a new session, unless its open one is this very
    /// association. A roam ends the session it leaves without an `Ended`
    /// entry: the new `Joined` says where it came from.
    fn join(&mut self, mac: [u8; 6], place: Place, began: u64, at: u64) {
        let steered = self.recent.get(&mac).and_then(|r| r.action.clone());
        let steered_by = steered
            .filter(|a| a.0 == "steer" && a.2 <= at && at - a.2 <= CAUSE_WINDOW_MS)
            .and_then(|a| a.1);
        let mut from = None;
        let mut prior = None;
        let carry = |s: &Session| Prior {
            signed_in_ms: s.signed_in_ms(),
            identity: s.identity(),
        };
        if let Some(open) = self.open.get(&mac) {
            let same = open.place.ap == place.ap && open.place.bss == place.bss;
            if same && began <= open.start_ms + REASSOCIATED_MS {
                return;
            }
            if same {
                self.close(mac, began, End::Left);
            } else {
                prior = Some(carry(open));
                from = Some(Roam {
                    ap: open.place.ap.clone(),
                    band: open.place.band,
                    gap_ms: None,
                    steered_by: steered_by.clone(),
                });
                self.close_roamed(mac, began, &place.ap);
            }
        } else if let Some((id, ap, band, end)) = self.just_left(&mac, &place, began) {
            from = Some(Roam {
                ap,
                band,
                gap_ms: (began > end).then(|| began - end),
                steered_by,
            });
            if let Some(s) = self.closed.iter_mut().rev().find(|s| s.id == id) {
                prior = Some(carry(s));
                s.end = Some(End::Roamed {
                    to: place.ap.clone(),
                });
            }
            let ended = |w: &What| matches!(w, What::Ended { session, .. } if *session == id);
            self.timeline.edit(&mac, ended, |_| false);
        }
        self.next_id += 1;
        let session = Session {
            id: self.next_id,
            mac,
            place: place.clone(),
            start_ms: began,
            end_ms: None,
            last_ms: at,
            auth: None,
            authenticated: false,
            up_bytes: 0,
            down_bytes: 0,
            end: None,
            from: from.as_ref().map(|r| r.ap.clone()),
            prior,
            traffic: false,
            inactive_ms: 0,
        };
        self.open.insert(mac, session);
        let what = What::Joined {
            session: self.next_id,
            place,
            from,
            auth: None,
        };
        self.push(mac, began, what);
    }

    /// The session of `mac` that ended elsewhere than `place` within
    /// [`ROAM_WINDOW_MS`] of `began`, by the client leaving or going quiet:
    /// its id, AP, band and end. It may end after `began`: the new AP heard
    /// the client first (a fast transition), and its old AP's word of the
    /// end reached the controller first.
    fn just_left(
        &self,
        mac: &[u8; 6],
        place: &Place,
        began: u64,
    ) -> Option<(u64, String, Option<Band>, u64)> {
        let recent = self
            .closed
            .iter()
            .rev()
            .take_while(|s| s.end_ms.is_some_and(|e| e + ROAM_WINDOW_MS >= began))
            .find(|s| s.mac == *mac)?;
        let end = recent.end_ms?;
        let elsewhere = recent.place.ap != place.ap || recent.place.bss != place.bss;
        let left = matches!(recent.end, Some(End::Left | End::Inactive));
        let roam = (recent.id, recent.place.ap.clone(), recent.place.band, end);
        (elsewhere && left && end <= began + ROAM_WINDOW_MS).then_some(roam)
    }

    /// Ends the open session of `mac` at `at` for `why`, with its
    /// `Ended` entry.
    fn close(&mut self, mac: [u8; 6], at: u64, why: End) {
        let Some(s) = self.end(mac, at, why.clone()) else {
            return;
        };
        let what = What::Ended {
            session: s.id,
            ap: s.place.ap.clone(),
            why,
            secs: s.end_ms.unwrap_or(at).saturating_sub(s.start_ms) / 1000,
        };
        self.push(mac, at, what);
    }

    /// Ends the open session of `mac` at `at` by a roam to `to`.
    fn close_roamed(&mut self, mac: [u8; 6], at: u64, to: &str) {
        let to = to.to_owned();
        self.end(mac, at, End::Roamed { to });
    }

    /// Moves the open session of `mac` to the ended ones, counted in its
    /// identity's totals; the session.
    fn end(&mut self, mac: [u8; 6], at: u64, why: End) -> Option<&Session> {
        let mut s = self.open.remove(&mac)?;
        s.end_ms = Some(at.max(s.start_ms));
        s.end = Some(why);
        if let Some(id) = s.identity() {
            let t = self.totals.entry(id).or_default();
            t.sessions += 1;
            t.up_bytes += s.up_bytes;
            t.down_bytes += s.down_bytes;
            t.seen_ms = t.seen_ms.max(at);
            self.cap_identities();
        }
        self.closed.push_back(s);
        if self.closed.len() > SESSIONS_MAX {
            self.closed.pop_front();
        }
        self.dirty = true;
        self.closed.back()
    }

    /// Takes a snapshot of `ap` received at `at_ms`; `fresh` when it is the
    /// first of a session of the AP's link, after which a client missing
    /// went unobserved.
    pub fn snapshot(
        &mut self,
        ap: &str,
        snap: &Snapshot,
        naming: &Naming,
        at_ms: u64,
        fresh: bool,
    ) {
        let mut present = HashSet::new();
        for st in &snap.stations {
            let Some(p) = place(ap, naming, st.bss, Some(st.vlan)) else {
                continue;
            };
            let began = at_ms.saturating_sub(u64::from(st.connected_s) * 1000);
            let heard = at_ms.saturating_sub(u64::from(st.inactive_ms));
            // An AP that still lists an association older than the one the
            // client roamed to has not dropped it yet.
            if self
                .open
                .get(&st.mac)
                .is_some_and(|s| s.place.ap != ap && began < s.start_ms)
            {
                continue;
            }
            present.insert(st.mac);
            // Associated again while the AP's link was away: the old
            // session ended unseen.
            if fresh
                && let Some(s) = self.open.get(&st.mac)
                && s.place.ap == ap
                && began > s.start_ms + REASSOCIATED_MS
            {
                let at = s.last_ms;
                self.close(st.mac, at, End::Unobserved);
            }
            self.join(st.mac, p, began, heard);
            let auth = snap
                .auth
                .binary_search_by_key(&st.mac, |(m, _)| *m)
                .ok()
                .map(|i| &snap.auth[i].1);
            let Some(s) = self.open.get_mut(&st.mac) else {
                continue;
            };
            s.last_ms = s.last_ms.max(heard);
            s.up_bytes = st.rx_bytes;
            s.down_bytes = st.tx_bytes;
            s.inactive_ms = st.inactive_ms;
            let vlan_moved = s.place.vlan != st.vlan;
            s.place.vlan = st.vlan;
            let learnt = auth.filter(|a| s.auth.as_ref() != Some(a)).cloned();
            if learnt.is_none() && !vlan_moved {
                continue;
            }
            if let Some(a) = &learnt {
                s.authenticated |= a.authorized;
                s.auth = Some(a.clone());
            }
            // The timeline says who the session is: authorized once its AP
            // authorized it in the session, the identity a fast transition
            // carried over.
            let learnt = learnt.map(|mut a| {
                a.authorized = s.authenticated;
                if a.kind() == AuthKind::Eap {
                    a.identity = s.eap_identity().unwrap_or_default();
                }
                a
            });
            let (id, vlan) = (s.id, st.vlan);
            let joined = |w: &What| matches!(w, What::Joined { session, .. } if *session == id);
            self.timeline.edit(&st.mac, joined, |w| {
                if let What::Joined { place, auth, .. } = w {
                    place.vlan = vlan;
                    if learnt.is_some() {
                        *auth = learnt;
                    }
                }
                true
            });
            self.dirty = true;
        }
        let gone: Vec<[u8; 6]> = self
            .open
            .values()
            .filter(|s| s.place.ap == ap && !present.contains(&s.mac))
            .map(|s| s.mac)
            .collect();
        for mac in gone {
            let s = &self.open[&mac];
            let at = s.last_ms;
            let why = if fresh {
                End::Unobserved
            } else {
                self.cause(&mac, at_ms, s)
            };
            self.close(mac, at, why);
        }
    }

    /// Takes flows of `ap` received at `at_ms`: the first connections of a
    /// session.
    pub fn flows(&mut self, ap: &str, flows: &Flows, at_ms: u64) {
        for c in flows.clients.iter().filter(|c| c.conns > 0) {
            let Some(s) = self.open.get_mut(&c.mac) else {
                continue;
            };
            if s.place.ap != ap || s.traffic {
                continue;
            }
            s.traffic = true;
            let what = What::FirstTraffic {
                ap: ap.to_owned(),
                conns: c.conns,
            };
            self.push(c.mac, at_ms, what);
        }
    }

    /// Takes an operator's action.
    pub fn action(&mut self, a: &Action) {
        let Some(mac) = a.mac else { return };
        let at = unix_ms(a.at);
        if a.ok {
            self.recent(mac).action = Some((a.action, a.user.clone(), at));
        }
        let what = What::Action {
            action: a.action.to_owned(),
            user: a.user.clone(),
            ap: a.ap.clone(),
            ok: a.ok,
            detail: a.detail.clone(),
        };
        self.push(mac, at, what);
    }

    /// Takes a change of a service a client offers.
    pub fn service(&mut self, e: &crate::services::Event) {
        let what = What::Service {
            ap: e.ap.clone(),
            instance: e.instance.clone(),
            service: e.service.clone(),
            change: e.change,
            by: e.by,
            misses: e.misses,
            silent_ms: e.silent_ms,
        };
        self.push(e.mac, e.at_ms, what);
    }

    /// Takes a read of the leases at `now_ms`: a lease new since the last
    /// read, or with a later expiry, is granted or renewed then, for the
    /// clients the Wi-Fi knows. The first read only sets what is known.
    pub fn leases(&mut self, leases: &Leases, now_ms: u64) {
        let now = UNIX_EPOCH + Duration::from_millis(now_ms);
        let current: HashMap<([u8; 6], IpAddr), u64> = leases
            .all(now)
            .flat_map(|(m, l)| l.addresses.into_iter().map(move |(ip, e)| ((m, ip), e)))
            .collect();
        let Some(before) = self.leases.replace(current.clone()) else {
            return;
        };
        let mut news: Vec<_> = current
            .iter()
            .filter_map(|(&(m, ip), &expires)| match before.get(&(m, ip)) {
                None => Some((m, ip, expires, false)),
                Some(&was) if expires > was => Some((m, ip, expires, true)),
                Some(_) => None,
            })
            .filter(|(m, ..)| self.open.contains_key(m) || self.timeline.knows(m))
            .collect();
        news.sort();
        for (m, ip, expires, renewed) in news {
            let what = What::Lease {
                ip,
                expires,
                renewed,
            };
            self.push(m, now_ms, what);
        }
    }

    /// Takes RADIUS's verdicts: each into its client's timeline, once
    /// however often it is read, and an accepted certificate's expiry by its
    /// common name.
    pub fn radius(&mut self, lines: &[Line]) {
        for l in lines {
            if l.accept
                && let (Some(expires_s), Some(cn)) = (l.cert_expires, &l.cert_cn)
            {
                let c = self.certs.entry(cn.clone()).or_insert(Cert {
                    expires_s,
                    seen_ms: 0,
                });
                if l.at_ms >= c.seen_ms {
                    *c = Cert {
                        expires_s,
                        seen_ms: l.at_ms,
                    };
                }
                self.cap_identities();
            }
            let what = What::Radius {
                accept: l.accept,
                user: l.user.clone(),
                node: l.node.clone(),
                nas: l.nas.clone(),
                detail: l.detail.clone(),
                cert_expires: l.cert_expires,
                cert_cn: l.cert_cn.clone(),
            };
            let entry = Entry {
                at_ms: l.at_ms,
                what,
            };
            if !self.timeline.holds(&l.mac, &entry) {
                self.timeline.push(l.mac, entry);
                self.dirty = true;
            }
        }
    }

    /// When the newest of RADIUS's verdicts kept happened: where reading
    /// its log goes on from.
    pub fn radius_newest(&self) -> Option<u64> {
        self.timeline.newest(|w| matches!(w, What::Radius { .. }))
    }

    /// Keeps the identities seen last, [`IDENTITIES_MAX`] of each kind.
    fn cap_identities(&mut self) {
        while self.totals.len() > IDENTITIES_MAX {
            let oldest = self.totals.iter().min_by_key(|(_, t)| t.seen_ms);
            let Some(id) = oldest.map(|(i, _)| i.clone()) else {
                break;
            };
            self.totals.remove(&id);
        }
        while self.certs.len() > IDENTITIES_MAX {
            let oldest = self.certs.iter().min_by_key(|(_, c)| c.seen_ms);
            let Some(id) = oldest.map(|(i, _)| i.clone()) else {
                break;
            };
            self.certs.remove(&id);
        }
    }

    /// Drops what is past its keeping at `now_ms`, and ends the open
    /// sessions of APs not heard for an hour (`up` says which APs are).
    pub fn tick(&mut self, now_ms: u64, up: impl Fn(&str) -> bool) {
        let unheard: Vec<[u8; 6]> = self
            .open
            .values()
            .filter(|s| !up(&s.place.ap) && s.last_ms + UNHEARD_MS < now_ms)
            .map(|s| s.mac)
            .collect();
        for mac in unheard {
            let at = self.open[&mac].last_ms;
            self.close(mac, at, End::Unobserved);
        }
        let before = (self.closed.len(), self.timeline.total());
        let cutoff = now_ms.saturating_sub(SESSIONS_KEEP_MS);
        while self
            .closed
            .front()
            .is_some_and(|s| s.end_ms.unwrap_or(0) < cutoff)
        {
            self.closed.pop_front();
        }
        self.timeline.prune(now_ms);
        let cutoff = now_ms.saturating_sub(IDENTITY_KEEP_MS);
        let open: HashSet<String> = self.open.values().filter_map(Session::identity).collect();
        self.totals
            .retain(|id, t| t.seen_ms >= cutoff || open.contains(id));
        self.certs.retain(|_, c| c.seen_ms >= cutoff);
        self.recent
            .retain(|_, r| r.newest() + CAUSE_WINDOW_MS.max(ROAM_WINDOW_MS) >= now_ms);
        self.dirty |= before != (self.closed.len(), self.timeline.total());
    }

    /// The open session of `mac`.
    pub fn open_of(&self, mac: &[u8; 6]) -> Option<&Session> {
        self.open.get(mac)
    }

    /// The sessions of `mac`, the newest first, the open one first of all.
    pub fn of(&self, mac: &[u8; 6]) -> impl Iterator<Item = &Session> {
        let closed = self.closed.iter().rev().filter(move |s| s.mac == *mac);
        self.open.get(mac).into_iter().chain(closed)
    }

    /// Every open session.
    pub fn all_open(&self) -> impl Iterator<Item = &Session> {
        self.open.values()
    }

    /// Every client certificate RADIUS accepted, by common name.
    pub fn certs(&self) -> &BTreeMap<String, Cert> {
        &self.certs
    }

    /// The certificate `session` of `mac` signed in with, once its AP
    /// authorized it: the newest EAP-TLS accept of the client from shortly
    /// before its sign-in ran (EAP comes first; a fast transition's ran in
    /// the session it roamed in from) to its end; its common name and expiry
    /// (Unix seconds).
    pub fn session_cert(&self, mac: &[u8; 6], session: &Session) -> Option<(String, u64)> {
        if !session.authenticated {
            return None;
        }
        let from = session.signed_in_ms().saturating_sub(CERT_BEFORE_MS);
        let to = session.end_ms.unwrap_or(u64::MAX);
        let accepts = self.timeline.of(mac).rev();
        accepts
            .filter(|e| (from..=to).contains(&e.at_ms))
            .find_map(|e| match &e.what {
                What::Radius {
                    accept: true,
                    cert_expires: Some(s),
                    cert_cn: Some(cn),
                    ..
                } => Some((cn.clone(), *s)),
                _ => None,
            })
    }

    /// Every identity's totals with its open sessions counted in, and how
    /// many clients it has on now.
    pub fn identities(&self) -> BTreeMap<String, (Totals, usize)> {
        let mut out: BTreeMap<String, (Totals, usize)> = self
            .totals
            .iter()
            .map(|(i, t)| (i.clone(), (*t, 0)))
            .collect();
        for s in self.open.values() {
            let Some(id) = s.identity() else { continue };
            if !out.contains_key(&id) && out.len() >= IDENTITIES_MAX {
                continue;
            }
            let (t, on) = out.entry(id).or_default();
            t.up_bytes += s.up_bytes;
            t.down_bytes += s.down_bytes;
            *on += 1;
        }
        out
    }

    /// What the file is to hold.
    pub fn saved(&self) -> Saved {
        Saved {
            next_id: self.next_id,
            open: self.open.values().cloned().collect(),
            closed: self.closed.iter().cloned().collect(),
            timeline: self.timeline.saved(),
            totals: self.totals.iter().map(|(i, t)| (i.clone(), *t)).collect(),
            certs: self.certs.iter().map(|(i, c)| (i.clone(), *c)).collect(),
        }
    }

    /// The file's bytes.
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        self.saved().encode()
    }

    /// What `path` holds; empty without the file. A file of another format,
    /// or that does not decode, is set aside (the name it was set aside
    /// under comes with the empty history); one that cannot be read at all
    /// is an error.
    pub fn load(path: &Path) -> io::Result<(Sessions, Option<String>)> {
        let mut bytes = Vec::new();
        match fs::File::open(path) {
            Ok(f) => {
                io::Read::read_to_end(&mut io::Read::take(f, FILE_MAX), &mut bytes)?;
            }
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok((Sessions::default(), None)),
            Err(e) => return Err(e),
        }
        let saved = match bytes.split_first_chunk::<6>() {
            Some((head, body)) if &head[..4] == MARK && head[4..] == FORMAT.to_le_bytes() => {
                postcard::from_bytes::<Saved>(body).ok()
            }
            _ => None,
        };
        let Some(saved) = saved else {
            let aside = store::set_aside(path)?;
            return Ok((Sessions::default(), Some(aside.display().to_string())));
        };
        let s = Sessions {
            open: saved.open.into_iter().map(|s| (s.mac, s)).collect(),
            closed: saved.closed.into(),
            timeline: Timeline::from_saved(saved.timeline),
            totals: saved.totals.into_iter().collect(),
            certs: saved.certs.into_iter().collect(),
            next_id: saved.next_id,
            ..Sessions::default()
        };
        Ok((s, None))
    }
}

impl Saved {
    /// The file's bytes.
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut bytes = MARK.to_vec();
        bytes.extend_from_slice(&FORMAT.to_le_bytes());
        postcard::to_extend(self, bytes).map_err(io::Error::other)
    }
}

/// Saves the history at `path` if it changed, after dropping what is past
/// its keeping; a save that fails is tried again at the next. The history is
/// copied under the state's lock and encoded and written after, so the
/// state is not held while megabytes are encoded.
pub async fn save(state: &Shared, path: &Path) {
    let saved = {
        let mut s = state.write();
        s.sessions_tick(SystemTime::now());
        if !s.sessions.take_dirty() {
            return;
        }
        s.sessions.saved()
    };
    let path = path.to_owned();
    let written = tokio::task::spawn_blocking(move || {
        let bytes = saved.encode()?;
        store::replace(&path, &bytes, 0o600)
    })
    .await
    .map_err(|e| e.to_string())
    .and_then(|r| r.map_err(|e| e.to_string()));
    if let Err(e) = written {
        eprintln!("u6e-controller: the client history could not be saved: {e}");
        state.write().sessions.dirty = true;
    }
}

/// Saves the history every [`SAVE_EVERY`], for the life of the process.
pub async fn keep(state: Shared, path: PathBuf) {
    let mut every = interval(SAVE_EVERY);
    loop {
        every.tick().await;
        save(&state, &path).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;
    use u6e_proto::msg::{Bss, ClientFlows, Guard, RateMode, Station, Violation};

    const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const T0: u64 = 1_800_000_000_000;

    /// An AP of one 5 GHz BSS (`wlan5`) and one 6 GHz BSS (`wlan6`).
    fn naming() -> Naming {
        let bss = |ifname: &str, phy: &str| Bss {
            ifname: ifname.into(),
            bssid: [2, 0, 0, 0, 0x10, 1],
            ssid: "ssid-a".into(),
            phy: phy.into(),
            vlan: 10,
        };
        Naming {
            bsss: vec![bss("wlan5", "phy1"), bss("wlan6", "phy2")],
            bands: vec![("phy1".into(), Band::B5), ("phy2".into(), Band::B6)],
        }
    }

    fn ev(at_ms: u64, kind: EventKind) -> Event {
        Event { at_ms, kind }
    }

    fn assoc(s: &mut Sessions, ap: &str, bss: u16, at: u64) {
        let e = ev(at, EventKind::Assoc { mac: MAC, bss });
        s.event(ap, &naming(), &e, at);
    }

    fn disassoc(s: &mut Sessions, ap: &str, bss: u16, at: u64) {
        let e = ev(at, EventKind::Disassoc { mac: MAC, bss });
        s.event(ap, &naming(), &e, at);
    }

    fn eap(identity: &str, auth_alg: u16) -> StationAuth {
        StationAuth {
            akm: 0x000f_ac03,
            auth_alg,
            authorized: true,
            identity: identity.into(),
            eap_method: 13,
            reauth_s: 0,
        }
    }

    fn station(bss: u16, connected_s: u32, inactive_ms: u32) -> Station {
        Station {
            mac: MAC,
            bss,
            signal: -50,
            signal_avg: -50,
            rx_bytes: 1000,
            tx_bytes: 9000,
            rx_packets: 10,
            tx_packets: 20,
            tx_retries: 0,
            tx_failed: 0,
            tx_rate_kbps: 0,
            rx_rate_kbps: 0,
            tx_mcs: 0,
            rx_mcs: 0,
            tx_mode: RateMode::He,
            rx_mode: RateMode::He,
            tx_nss: 2,
            rx_nss: 2,
            tx_airtime_us: 0,
            rx_airtime_us: 0,
            inactive_ms,
            connected_s,
            vlan: 42,
        }
    }

    fn snap(stations: Vec<Station>, auth: Option<StationAuth>) -> Snapshot {
        let auth = auth.into_iter().map(|a| (MAC, a)).collect();
        Snapshot {
            seq: 1,
            uptime_s: 0,
            load_milli: 0,
            mem_avail_kb: 0,
            nss_load_pct: 0,
            temps: Vec::new(),
            radios: Vec::new(),
            bsss: naming().bsss,
            stations,
            config_sha256: None,
            clock_synced: true,
            power_limits: Vec::new(),
            auth,
            caps: Vec::new(),
            offload_held: false,
        }
    }

    /// The kinds of the client's entries, in order.
    fn kinds(s: &Sessions) -> Vec<&'static str> {
        let kind = |w: &What| match w {
            What::Joined { from: None, .. } => "joined",
            What::Joined { from: Some(_), .. } => "roamed",
            What::Ended { .. } => "ended",
            What::Eap { .. } => "eap",
            What::PskMismatch { .. } => "psk",
            What::Radius { .. } => "radius",
            What::Lease { .. } => "lease",
            What::FirstTraffic { .. } => "traffic",
            What::Action { .. } => "action",
            What::Guard { .. } => "guard",
            What::Service { .. } => "service",
        };
        s.timeline.of(&MAC).map(|e| kind(&e.what)).collect()
    }

    fn ends(s: &Sessions) -> Vec<Option<End>> {
        s.of(&MAC).map(|x| x.end.clone()).collect()
    }

    /// A client joins, roams by FT to the other AP (which hears it before
    /// the first lets it go) and leaves: two sessions, the first ended by
    /// the roam, and one timeline that tells it once.
    #[test]
    fn a_join_an_ft_roam_and_a_leave() {
        let mut s = Sessions::default();
        assoc(&mut s, "ap1", 0, T0);
        let st = station(0, 4, 100);
        s.snapshot(
            "ap1",
            &snap(vec![st], Some(eap("host/pc1", 0))),
            &naming(),
            T0 + 5000,
            false,
        );
        assoc(&mut s, "ap2", 1, T0 + 60_000);
        let st = station(1, 1, 100);
        s.snapshot(
            "ap2",
            &snap(vec![st], Some(eap("host/pc1", 2))),
            &naming(),
            T0 + 61_000,
            false,
        );
        disassoc(&mut s, "ap1", 0, T0 + 61_500);
        disassoc(&mut s, "ap2", 1, T0 + 120_000);
        assert_eq!(kinds(&s), ["joined", "roamed", "ended"]);
        assert_eq!(
            ends(&s),
            [Some(End::Left), Some(End::Roamed { to: "ap2".into() })]
        );
        let roam = s.timeline.of(&MAC).nth(1).unwrap();
        let What::Joined {
            place, from, auth, ..
        } = &roam.what
        else {
            panic!("{roam:?}")
        };
        assert_eq!(
            (place.ap.as_str(), place.band, place.vlan),
            ("ap2", Some(Band::B6), 42)
        );
        let from = from.as_ref().unwrap();
        assert_eq!(
            (from.ap.as_str(), from.band, from.gap_ms),
            ("ap1", Some(Band::B5), None)
        );
        assert!(auth.as_ref().unwrap().fast_transition());
        let ended = s.timeline.of(&MAC).last().unwrap();
        assert!(
            matches!(
                &ended.what,
                What::Ended {
                    secs: 60,
                    why: End::Left,
                    ..
                }
            ),
            "{ended:?}"
        );
        let ids = s.identities();
        let (t, on) = ids["host/pc1"];
        assert_eq!(
            (t.sessions, t.up_bytes, t.down_bytes, on),
            (2, 2000, 18_000, 0)
        );
    }

    /// A client that leaves one AP and joins the other within the window
    /// roamed; its gap is the time between.
    #[test]
    fn leaving_then_joining_elsewhere_soon_after_is_a_roam() {
        let mut s = Sessions::default();
        assoc(&mut s, "ap1", 0, T0);
        disassoc(&mut s, "ap1", 0, T0 + 30_000);
        assoc(&mut s, "ap2", 0, T0 + 33_000);
        assert_eq!(kinds(&s), ["joined", "roamed"]);
        assert_eq!(ends(&s)[1], Some(End::Roamed { to: "ap2".into() }));
        let What::Joined { from, .. } = &s.timeline.of(&MAC).last().unwrap().what else {
            panic!()
        };
        assert_eq!(from.as_ref().unwrap().gap_ms, Some(3000));
        // The old AP's word of a fast transition can come first, timed after
        // the new association: a roam without a gap.
        disassoc(&mut s, "ap2", 0, T0 + 36_000);
        assoc(&mut s, "ap1", 1, T0 + 35_500);
        let What::Joined { from, .. } = &s.timeline.of(&MAC).last().unwrap().what else {
            panic!()
        };
        assert_eq!(from.as_ref().unwrap().gap_ms, None);
        assert_eq!(kinds(&s), ["joined", "roamed", "roamed"]);
        disassoc(&mut s, "ap1", 1, T0 + 37_000);
        // Too late, or on the same BSS, it is a new connection.
        assoc(&mut s, "ap1", 0, T0 + 51_000);
        disassoc(&mut s, "ap1", 0, T0 + 52_000);
        assoc(&mut s, "ap1", 0, T0 + 53_000);
        assert_eq!(
            kinds(&s),
            [
                "joined", "roamed", "roamed", "ended", "joined", "ended", "joined"
            ]
        );
    }

    fn act(s: &mut Sessions, action: &'static str, at_ms: u64) {
        s.action(&Action {
            at: UNIX_EPOCH + Duration::from_millis(at_ms),
            user: Some("admin".into()),
            action,
            mac: Some(MAC),
            ap: Some("ap1".into()),
            ok: true,
            detail: String::new(),
        });
    }

    /// What came just before a disassociation is its cause: an operator's
    /// kick or block, EAP failing, or silence; a steer followed makes the
    /// roam its.
    #[test]
    fn a_disassociation_is_put_down_to_what_came_before() {
        let mut s = Sessions::default();
        let mut t = T0;
        let mut cycle = |s: &mut Sessions, before: &dyn Fn(&mut Sessions, u64)| {
            assoc(s, "ap1", 0, t);
            before(s, t + 1000);
            disassoc(s, "ap1", 0, t + 2000);
            t += 100_000;
            s.of(&MAC).next().unwrap().end.clone()
        };
        assert_eq!(
            cycle(&mut s, &|s, at| act(s, "kick", at)),
            Some(End::Kicked {
                by: Some("admin".into())
            })
        );
        assert_eq!(
            cycle(&mut s, &|s, at| act(s, "block", at)),
            Some(End::Blocked {
                by: Some("admin".into())
            })
        );
        let fail = |s: &mut Sessions, at| {
            s.event(
                "ap1",
                &naming(),
                &ev(at, EventKind::EapFail { mac: MAC, bss: 0 }),
                at,
            )
        };
        assert_eq!(cycle(&mut s, &fail), Some(End::EapFailed));
        let quiet = |s: &mut Sessions, at| {
            s.snapshot(
                "ap1",
                &snap(vec![station(0, 1, 70_000)], None),
                &naming(),
                at,
                false,
            )
        };
        assert_eq!(cycle(&mut s, &quiet), Some(End::Inactive));
        assert_eq!(cycle(&mut s, &|_, _| {}), Some(End::Left));
        // A kick long before is no cause.
        act(&mut s, "kick", t);
        assoc(&mut s, "ap1", 0, t + CAUSE_WINDOW_MS + 10_000);
        disassoc(&mut s, "ap1", 0, t + CAUSE_WINDOW_MS + 11_000);
        assert_eq!(ends(&s)[0], Some(End::Left));
        let t = t + 200_000;
        assoc(&mut s, "ap1", 0, t);
        act(&mut s, "steer", t + 1000);
        assoc(&mut s, "ap2", 1, t + 3000);
        let What::Joined { from, .. } = &s.timeline.of(&MAC).last().unwrap().what else {
            panic!()
        };
        assert_eq!(from.as_ref().unwrap().steered_by.as_deref(), Some("admin"));
    }

    /// EAP's steps go into the timeline, its success timed from its start;
    /// an AP whose clock is off is timed by the controller's.
    #[test]
    fn eap_steps_and_their_times() {
        let mut s = Sessions::default();
        let n = naming();
        s.event(
            "ap1",
            &n,
            &ev(T0, EventKind::EapStart { mac: MAC, bss: 0 }),
            T0,
        );
        s.event(
            "ap1",
            &n,
            &ev(T0 + 1500, EventKind::EapOk { mac: MAC, bss: 0 }),
            T0 + 1500,
        );
        let timeout = EventKind::EapTimeout {
            mac: MAC,
            bss: 0,
            server: true,
        };
        s.event("ap1", &n, &ev(1_000, timeout), T0 + 9000);
        let steps: Vec<(u64, EapStep)> = s
            .timeline
            .of(&MAC)
            .filter_map(|e| match &e.what {
                What::Eap { step, .. } => Some((e.at_ms, *step)),
                _ => None,
            })
            .collect();
        assert_eq!(
            steps,
            [
                (T0, EapStep::Started),
                (T0 + 1500, EapStep::Succeeded { ms: Some(1500) }),
                (T0 + 9000, EapStep::TimedOut { server: true })
            ]
        );
    }

    /// The first snapshot of a link's session reconciles: a client gone in
    /// the meantime ended unobserved, one that associated again began a
    /// new session, one still there goes on.
    #[test]
    fn an_ap_heard_again_reconciles_its_sessions() {
        let mut s = Sessions::default();
        assoc(&mut s, "ap1", 0, T0);
        s.snapshot(
            "ap1",
            &snap(vec![station(0, 10, 0)], None),
            &naming(),
            T0 + 10_000,
            false,
        );
        // Still there an hour later, the same association.
        let later = T0 + 3_600_000;
        s.snapshot(
            "ap1",
            &snap(vec![station(0, 3610, 0)], None),
            &naming(),
            later,
            true,
        );
        assert_eq!(s.of(&MAC).count(), 1);
        // Associated anew while the link was away.
        let again = later + 3_600_000;
        s.snapshot(
            "ap1",
            &snap(vec![station(0, 30, 0)], None),
            &naming(),
            again,
            true,
        );
        assert_eq!(ends(&s), [None, Some(End::Unobserved)]);
        // Gone while it was away.
        s.snapshot(
            "ap1",
            &snap(Vec::new(), None),
            &naming(),
            again + 600_000,
            true,
        );
        assert_eq!(ends(&s)[0], Some(End::Unobserved));
        let first = s.of(&MAC).next().unwrap();
        assert_eq!(first.end_ms, Some(again));
    }

    /// An AP not heard for an hour ends its sessions unobserved; what is
    /// past its keeping goes.
    #[test]
    fn the_tick_ends_what_no_ap_reports_and_drops_the_old() {
        let mut s = Sessions::default();
        assoc(&mut s, "ap1", 0, T0);
        s.tick(T0 + 1000, |_| false);
        assert!(s.open_of(&MAC).is_some());
        s.tick(T0 + UNHEARD_MS + 1, |_| true);
        assert!(s.open_of(&MAC).is_some(), "its AP is up");
        s.tick(T0 + UNHEARD_MS + 1, |_| false);
        assert_eq!(ends(&s), [Some(End::Unobserved)]);
        s.tick(T0 + SESSIONS_KEEP_MS + 1, |_| true);
        assert_eq!(s.of(&MAC).count(), 0);
        assert_eq!(s.timeline.total(), 0);
    }

    fn leases_of(entries: &[([u8; 6], &str, u64)]) -> Leases {
        let mut l = Leases::new(&["dhcp1:9100".into()]);
        let list = entries
            .iter()
            .map(|(mac, ip, expires)| crate::leases::Lease {
                mac: *mac,
                ip: ip.parse().unwrap(),
                hostname: None,
                device: None,
                expires: *expires,
            })
            .collect();
        l.take("dhcp1:9100", Ok(list), UNIX_EPOCH);
        l
    }

    /// The first read of the leases only sets what is known; a lease new
    /// since, or renewed, goes into the timeline of a client the Wi-Fi
    /// knows, and of no other.
    #[test]
    fn leases_granted_and_renewed() {
        let mut s = Sessions::default();
        let other = [2, 0, 0, 0, 0, 9];
        let now = T0 / 1000;
        s.leases(&leases_of(&[(MAC, "192.0.2.10", now + 600)]), T0);
        assert_eq!(s.timeline.total(), 0);
        assoc(&mut s, "ap1", 0, T0 + 1000);
        let read = [
            (MAC, "192.0.2.10", now + 1800),
            (MAC, "192.0.2.11", now + 1800),
            (other, "192.0.2.12", now + 1800),
        ];
        s.leases(&leases_of(&read), T0 + 60_000);
        s.leases(&leases_of(&read), T0 + 120_000);
        let leases: Vec<(String, bool)> = s
            .timeline
            .of(&MAC)
            .filter_map(|e| match &e.what {
                What::Lease { ip, renewed, .. } => Some((ip.to_string(), *renewed)),
                _ => None,
            })
            .collect();
        assert_eq!(
            leases,
            [("192.0.2.10".into(), true), ("192.0.2.11".into(), false)]
        );
        assert!(!s.timeline.knows(&other));
    }

    fn line(at_ms: u64, accept: bool, cert_expires: Option<u64>) -> Line {
        Line {
            at_ms,
            mac: MAC,
            accept,
            user: "host/pc1".into(),
            node: "radius1".into(),
            nas: "ap1".into(),
            detail: if accept { "eap" } else { "no" }.into(),
            cert_cn: cert_expires.map(|_| "host/pc1".into()),
            cert_expires,
        }
    }

    fn cert(s: &Sessions, cn: &str) -> Option<u64> {
        s.certs().get(cn).map(|c| c.expires_s)
    }

    /// RADIUS's verdicts go into the timeline in time order; an accepted
    /// certificate's expiry is kept by its common name, the newest accept's
    /// winning.
    #[test]
    fn radius_verdicts_and_certificates() {
        let mut s = Sessions::default();
        assoc(&mut s, "ap1", 0, T0 + 5000);
        s.radius(&[
            line(T0 + 4000, true, Some(1_900_000_000)),
            line(T0 + 1000, false, None),
        ]);
        assert_eq!(kinds(&s), ["radius", "radius", "joined"]);
        assert_eq!(cert(&s, "host/pc1"), Some(1_900_000_000));
        // A line read again is taken once.
        s.radius(&[line(T0 + 1000, false, None)]);
        assert_eq!(kinds(&s), ["radius", "radius", "joined"]);
        assert_eq!(s.radius_newest(), Some(T0 + 4000));
        // An older line read late does not replace the newer certificate.
        s.radius(&[line(T0 + 2000, true, Some(1_800_000_000))]);
        assert_eq!(cert(&s, "host/pc1"), Some(1_900_000_000));
        s.radius(&[line(T0 + 9000, true, Some(1_950_000_000))]);
        assert_eq!(cert(&s, "host/pc1"), Some(1_950_000_000));
    }

    /// A client whose certificate is its own signs in as `host/victim`: the
    /// certificate is kept by its common name, never the victim's name, and
    /// the victim's own certificate stays as it was.
    #[test]
    fn a_certificate_counts_for_its_common_name_only() {
        let mut s = Sessions::default();
        s.radius(&[line(T0, true, Some(1_900_000_000))]);
        let forged = Line {
            user: "host/pc1".into(),
            cert_cn: Some("host/attacker".into()),
            ..line(T0 + 1000, true, Some(1_700_000_000))
        };
        s.radius(&[forged]);
        assert_eq!(cert(&s, "host/pc1"), Some(1_900_000_000));
        assert_eq!(cert(&s, "host/attacker"), Some(1_700_000_000));
        // A line without a common name keeps no certificate.
        let anonymous = Line {
            cert_cn: None,
            ..line(T0 + 2000, true, Some(1_600_000_000))
        };
        s.radius(&[anonymous]);
        assert_eq!(s.certs().len(), 2);
    }

    /// A session begun by a fast transition ran no EAP of its own: 10
    /// minutes after the client signed in, it shows the certificate of the
    /// session that ran EAP, through a second roam too, and the identity
    /// that session authenticated as when its AP names none.
    #[test]
    fn a_fast_transition_carries_the_sign_in_over() {
        let mut s = Sessions::default();
        assoc(&mut s, "ap1", 0, T0);
        let signed_in = snap(vec![station(0, 4, 100)], Some(eap("host/pc1", 0)));
        s.snapshot("ap1", &signed_in, &naming(), T0 + 5000, false);
        s.radius(&[line(T0 - 1000, true, Some(1_900_000_000))]);
        let cert = Some(("host/pc1".to_owned(), 1_900_000_000));
        assert_eq!(s.session_cert(&MAC, s.open_of(&MAC).unwrap()), cert);
        let later = T0 + 600_000;
        assoc(&mut s, "ap2", 1, later);
        let ft = snap(vec![station(1, 1, 100)], Some(eap("", 2)));
        s.snapshot("ap2", &ft, &naming(), later + 1000, false);
        disassoc(&mut s, "ap1", 0, later + 1500);
        let open = s.open_of(&MAC).unwrap();
        assert_eq!(open.signed_in_ms(), T0);
        assert_eq!(open.identity().as_deref(), Some("host/pc1"));
        assert_eq!(s.session_cert(&MAC, open), cert);
        let joined = s.timeline.of(&MAC).rev().find_map(|e| match &e.what {
            What::Joined { auth: Some(a), .. } => Some(a.clone()),
            _ => None,
        });
        assert_eq!(joined.unwrap().identity, "host/pc1");
        // Roamed on, out of the first AP's window altogether.
        let again = later + 600_000;
        assoc(&mut s, "ap1", 0, again);
        let ft = snap(vec![station(0, 1, 100)], Some(eap("", 2)));
        s.snapshot("ap1", &ft, &naming(), again + 1000, false);
        let open = s.open_of(&MAC).unwrap();
        assert_eq!(s.session_cert(&MAC, open), cert);
        assert_eq!(s.identities()["host/pc1"].1, 1);
        // A session that ran EAP again does not carry the old sign-in.
        disassoc(&mut s, "ap1", 0, again + 2000);
        assoc(&mut s, "ap2", 1, again + 3000);
        let full = snap(vec![station(1, 1, 100)], Some(eap("host/pc1", 0)));
        s.snapshot("ap2", &full, &naming(), again + 4000, false);
        let open = s.open_of(&MAC).unwrap();
        assert_eq!(open.signed_in_ms(), open.start_ms);
        assert_eq!(s.session_cert(&MAC, open), None);
    }

    /// The timeline's join says whether its AP authorized the session, and
    /// keeps saying so while a reauthentication runs.
    #[test]
    fn a_join_says_whether_it_was_authorized() {
        let mut s = Sessions::default();
        assoc(&mut s, "ap1", 0, T0);
        let authorized = |s: &Sessions| {
            s.timeline.of(&MAC).find_map(|e| match &e.what {
                What::Joined { auth: Some(a), .. } => Some(a.authorized),
                _ => None,
            })
        };
        let claiming = StationAuth {
            authorized: false,
            ..eap("host/claimed", 0)
        };
        let st = vec![station(0, 1, 0)];
        s.snapshot(
            "ap1",
            &snap(st.clone(), Some(claiming.clone())),
            &naming(),
            T0 + 1000,
            false,
        );
        assert_eq!(authorized(&s), Some(false));
        s.snapshot(
            "ap1",
            &snap(st.clone(), Some(eap("host/claimed", 0))),
            &naming(),
            T0 + 2000,
            false,
        );
        assert_eq!(authorized(&s), Some(true));
        s.snapshot(
            "ap1",
            &snap(st, Some(claiming)),
            &naming(),
            T0 + 3000,
            false,
        );
        assert_eq!(authorized(&s), Some(true));
    }

    /// A client its AP has not authorized only claims its identity: it
    /// counts for no identity, and shows no certificate, until it is.
    #[test]
    fn a_claimed_identity_counts_only_once_authorized() {
        let mut s = Sessions::default();
        assoc(&mut s, "ap1", 0, T0);
        let claimed = StationAuth {
            authorized: false,
            ..eap("host/claimed", 0)
        };
        s.snapshot(
            "ap1",
            &snap(vec![station(0, 1, 0)], Some(claimed)),
            &naming(),
            T0 + 1000,
            false,
        );
        let cert_line = Line {
            cert_cn: Some("host/claimed".into()),
            ..line(T0 + 500, true, Some(1_900_000_000))
        };
        s.radius(&[cert_line]);
        let open = s.open_of(&MAC).unwrap();
        assert_eq!(open.identity(), None);
        assert_eq!(s.session_cert(&MAC, open), None);
        assert!(s.identities().is_empty());
        disassoc(&mut s, "ap1", 0, T0 + 2000);
        assert!(
            s.identities().is_empty(),
            "an unauthenticated session counts for nobody"
        );
        // Authorized, it counts, and shows the certificate it signed in with.
        assoc(&mut s, "ap1", 0, T0 + 60_000);
        s.snapshot(
            "ap1",
            &snap(vec![station(0, 1, 0)], Some(eap("host/pc1", 0))),
            &naming(),
            T0 + 61_000,
            false,
        );
        s.radius(&[line(T0 + 59_000, true, Some(1_900_000_000))]);
        let open = s.open_of(&MAC).unwrap();
        assert_eq!(open.identity().as_deref(), Some("host/pc1"));
        assert_eq!(
            s.session_cert(&MAC, open),
            Some(("host/pc1".into(), 1_900_000_000))
        );
        assert_eq!(s.identities()["host/pc1"].1, 1);
    }

    /// A client that gave up in EAP is found gone from a snapshot, the
    /// timeout coming after it was last heard: the timeout ended it.
    #[test]
    fn a_timeout_after_the_client_was_last_heard_ends_its_session() {
        let mut s = Sessions::default();
        s.snapshot(
            "ap1",
            &snap(vec![station(0, 1, 0)], None),
            &naming(),
            T0,
            false,
        );
        let timeout = EventKind::EapTimeout {
            mac: MAC,
            bss: 0,
            server: false,
        };
        s.event("ap1", &naming(), &ev(T0 + 5000, timeout), T0 + 5000);
        s.snapshot("ap1", &snap(Vec::new(), None), &naming(), T0 + 6000, false);
        assert_eq!(ends(&s), [Some(End::EapTimedOut)]);
    }

    /// The snapshot that no longer lists a client that gave up in EAP comes
    /// before the timeout: the timeout still ended its session, in the
    /// timeline too; one heard too late, or after the client left another
    /// AP, ends nothing.
    #[test]
    fn a_timeout_heard_after_the_session_was_found_gone_ends_it() {
        let mut s = Sessions::default();
        s.snapshot(
            "ap1",
            &snap(vec![station(0, 1, 0)], None),
            &naming(),
            T0,
            false,
        );
        s.snapshot("ap1", &snap(Vec::new(), None), &naming(), T0 + 6000, false);
        assert_eq!(ends(&s), [Some(End::Left)]);
        let timeout = |at| {
            let kind = EventKind::EapTimeout {
                mac: MAC,
                bss: 0,
                server: false,
            };
            ev(at, kind)
        };
        s.event("ap1", &naming(), &timeout(T0 + 7000), T0 + 7000);
        assert_eq!(ends(&s), [Some(End::EapTimedOut)]);
        let why = s.timeline.of(&MAC).find_map(|e| match &e.what {
            What::Ended { why, .. } => Some(why.clone()),
            _ => None,
        });
        assert_eq!(why, Some(End::EapTimedOut));
        // Left another AP, and a timeout heard long after: both left.
        assoc(&mut s, "ap2", 1, T0 + 100_000);
        disassoc(&mut s, "ap2", 1, T0 + 101_000);
        s.event("ap1", &naming(), &timeout(T0 + 102_000), T0 + 102_000);
        assoc(&mut s, "ap1", 0, T0 + 200_000);
        disassoc(&mut s, "ap1", 0, T0 + 201_000);
        let late = T0 + 201_000 + CAUSE_WINDOW_MS + 1;
        s.event("ap1", &naming(), &timeout(late), late);
        let newest_first = [Some(End::Left), Some(End::Left), Some(End::EapTimedOut)];
        assert_eq!(ends(&s), newest_first);
    }

    /// An operator's kick of an earlier session is no cause of this one's
    /// end, however close in time.
    #[test]
    fn a_cause_must_come_within_the_session() {
        let mut s = Sessions::default();
        assoc(&mut s, "ap1", 0, T0);
        act(&mut s, "kick", T0 + 1000);
        disassoc(&mut s, "ap1", 0, T0 + 1500);
        assoc(&mut s, "ap1", 0, T0 + 5000);
        disassoc(&mut s, "ap1", 0, T0 + 9000);
        assert_eq!(
            ends(&s),
            [
                Some(End::Left),
                Some(End::Kicked {
                    by: Some("admin".into())
                })
            ]
        );
    }

    /// First traffic and the guards' reports, once each.
    #[test]
    fn first_traffic_and_guard_reports() {
        let mut s = Sessions::default();
        assoc(&mut s, "ap1", 0, T0);
        let flows = |conns| Flows {
            seq: 1,
            complete: true,
            clients: vec![ClientFlows {
                mac: MAC,
                conns,
                offloaded: 0,
                tx_bytes: 0,
                rx_bytes: 0,
                tx_packets: 0,
                rx_packets: 0,
                top: Vec::new(),
            }],
        };
        s.flows("ap1", &flows(0), T0 + 10_000);
        s.flows("ap2", &flows(3), T0 + 20_000);
        s.flows("ap1", &flows(3), T0 + 30_000);
        s.flows("ap1", &flows(5), T0 + 40_000);
        let v = Violation {
            guard: Guard::Arp,
            mac: MAC,
            ifname: "wlan5".into(),
            vlan: 10,
            ip: None,
            detail: "x".into(),
            dropped: false,
            repeats: 2,
        };
        let e = ev(T0 + 50_000, EventKind::GuardViolation(v));
        s.event("ap1", &naming(), &e, T0 + 50_000);
        assert_eq!(kinds(&s), ["joined", "traffic", "guard"]);
    }

    /// Saved and loaded alike; a file that is no history is set aside.
    #[test]
    fn the_history_is_saved_and_a_bad_file_set_aside() {
        let t = TestDir::new();
        let path = t.path().join("history");
        let (s, aside) = Sessions::load(&path).unwrap();
        assert_eq!((s.timeline.total(), aside), (0, None));
        let mut s = Sessions::default();
        assoc(&mut s, "ap1", 0, T0);
        disassoc(&mut s, "ap1", 0, T0 + 60_000);
        assoc(&mut s, "ap1", 1, T0 + 120_000);
        s.radius(&[line(T0, true, Some(1_900_000_000))]);
        store::replace(&path, &s.encode().unwrap(), 0o600).unwrap();
        let (back, aside) = Sessions::load(&path).unwrap();
        assert_eq!(aside, None);
        assert_eq!(back.encode().unwrap(), s.encode().unwrap());
        assert_eq!(back.of(&MAC).count(), 2);
        fs::write(&path, b"U6CH\x09\x00garbage").unwrap();
        let (empty, aside) = Sessions::load(&path).unwrap();
        assert_eq!(empty.timeline.total(), 0);
        let aside = aside.unwrap();
        assert!(aside.contains("history.corrupt-"), "{aside}");
        assert!(!path.exists());
    }

    /// 200 000 events over 5 000 clients across two APs and their
    /// snapshots keep every bound, in little time.
    #[test]
    fn stress_keeps_every_bound() {
        let started = std::time::Instant::now();
        let mut s = Sessions::default();
        let n = naming();
        let mut rng = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = |m: u64| {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng % m
        };
        for i in 0..200_000u64 {
            let c = next(5000) as u16;
            let mac = [2, 0, 0, 1, (c >> 8) as u8, c as u8];
            let ap = if next(2) == 0 { "ap1" } else { "ap2" };
            let bss = next(2) as u16;
            let at = T0 + i * 1000;
            let kind = match next(6) {
                0 | 1 => EventKind::Assoc { mac, bss },
                2 => EventKind::Disassoc { mac, bss },
                3 => EventKind::EapStart { mac, bss },
                4 => EventKind::EapFail { mac, bss },
                _ => EventKind::PskMismatch { mac, bss },
            };
            s.event(ap, &n, &ev(at, kind), at);
            if i % 5000 == 0 {
                s.radius(&[Line {
                    mac,
                    user: format!("user{c}"),
                    ..line(at, true, Some(1_900_000_000))
                }]);
                s.tick(at, |_| true);
            }
        }
        let end = T0 + 200_000 * 1000;
        s.tick(end, |_| true);
        assert!(s.timeline.total() <= crate::timeline::TOTAL);
        assert!(s.closed.len() <= SESSIONS_MAX);
        assert!(s.totals.len() <= IDENTITIES_MAX && s.certs.len() <= IDENTITIES_MAX);
        assert!(s.recent.len() <= RECENT_MAX);
        assert!(s.open.len() <= 5000);
        let bytes = s.encode().unwrap().len();
        assert!(bytes < 32 << 20, "{bytes} B");
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "{:?}",
            started.elapsed()
        );
    }
}
