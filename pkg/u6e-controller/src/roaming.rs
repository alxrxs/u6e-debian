//! Roaming analytics, from what the sessions decide and what the agents
//! already send: every roam with its kind, how long the client was between
//! APs, where it went from and to, its signal on either side, the steer it
//! followed and whether it failed; each client's readings on each AP and
//! band and its sticky time; and the steering the APs did, each request with
//! the client's answer and what it did next. The README ("Roaming analytics")
//! defines each figure.
//!
//! No AP can say how it hears a client associated elsewhere (no probe
//! request reaches hostapd on these radios), so another AP's view of a
//! client is its last reading of it in the session its current one replaced
//! (the session it roamed from, or one that ended unobserved, or as its
//! AP's radio on the band went down, before it joined here), taken for as
//! long as it can still hold: [`VIEW_MS`] at most, that AP's radio on the
//! band up at the same power, and the client not moved since (its signal
//! within [`MOVED_DB`] of its first on its current AP). A reading of an
//! unrelated earlier session says nothing of where the client is now.
//!
//! All of it is in RAM and bounded ([`ROAMS_MAX`], [`STEERS_MAX`],
//! [`CLIENTS_MAX`], [`KEEP_MS`]); the history of its counts is Prometheus'.

use std::collections::{BTreeMap, HashMap, VecDeque};

use serde_json::{Map, Value, json};
use u6e_proto::mac;
use u6e_proto::msg::{AuthKind, Band, Event, EventKind, Snapshot, StationAuth};

use crate::sessions::{self, Roamed, Session, Sessions, unix_ms};
use crate::state::{Action, Naming};
use crate::timeline::{End, Place};

/// How long roams and steering records are kept, and how many at most.
pub const KEEP_MS: u64 = 7 * 24 * 3600 * 1000;
pub const ROAMS_MAX: usize = 2000;
pub const STEERS_MAX: usize = 1000;
/// The clients whose readings are kept, the least recently heard dropped.
pub const CLIENTS_MAX: usize = 512;
/// The sticky threshold unless the configuration sets another.
pub const STICKY_DBM: i8 = -72;
/// How much stronger another AP's view must be for a client to be sticky.
pub const BETTER_DB: i16 = 8;
/// The oldest reading that stands for another AP's view, and how far the
/// client's signal may drift on its current AP before the view is dropped.
pub const VIEW_MS: u64 = 24 * 3600 * 1000;
pub const MOVED_DB: i16 = 6;
/// The longest step between two readings counted as sticky.
pub const STEP_MS: u64 = 30_000;
/// A roam whose session ends this soon failed.
pub const FAILED_MS: u64 = 30_000;
/// A client that roams this soon after a steer followed it, and how much
/// earlier it may have, as two APs' clocks and reports have it.
pub const MOVE_MS: u64 = 10_000;
const SLACK_MS: u64 = 1000;
/// How soon a client's answer follows a query's request, and an admin's
/// steer the answer to it (the admin's result comes after the answer).
const ANSWER_MS: u64 = 5_000;
const ADMIN_MS: u64 = 10_000;
/// An EAP start this near a new association is that association's.
const EAP_NEAR_MS: u64 = 60_000;
/// The same power, within a dB (mBm).
const SAME_POWER_MBM: i32 = 100;
/// The roams and steering records `/api/roaming` shows of the site.
pub const ROAMS_SHOWN: usize = 200;
pub const STEERS_SHOWN: usize = 100;
/// Sticky time is kept in 5-minute buckets over the last day.
const BUCKET_MS: u64 = 300_000;
const DAY_MS: u64 = 24 * 3600 * 1000;
const HOUR_MS: u64 = 3600 * 1000;

/// How a client authenticated on the AP it roamed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// 802.11r: its keys carried over, no new authentication.
    Ft,
    /// 802.1X with an EAP exchange at the new AP: a full re-authentication.
    Eap,
    /// 802.1X without one: a reassociation on keys it holds (PMKSA caching).
    Cached,
    /// A passphrase (with RADIUS MAC authentication).
    Psk,
    Sae,
    Open,
}

impl Kind {
    pub const ALL: [Kind; 6] = [
        Kind::Ft,
        Kind::Eap,
        Kind::Cached,
        Kind::Psk,
        Kind::Sae,
        Kind::Open,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Kind::Ft => "ft",
            Kind::Eap => "eap",
            Kind::Cached => "cached",
            Kind::Psk => "psk",
            Kind::Sae => "sae",
            Kind::Open => "open",
        }
    }

    fn of(a: &StationAuth, eap: bool) -> Kind {
        if a.fast_transition() {
            return Kind::Ft;
        }
        match a.kind() {
            AuthKind::Eap if eap => Kind::Eap,
            AuthKind::Eap => Kind::Cached,
            AuthKind::MacAuth => Kind::Psk,
            AuthKind::Sae => Kind::Sae,
            AuthKind::Other => Kind::Open,
        }
    }
}

/// Why a roam failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// At the AP it tried: RADIUS rejected it, EAP timed out, or its
    /// passphrase did not match.
    EapFailed,
    EapTimedOut,
    Passphrase,
    /// It got on and its session ended within [`FAILED_MS`].
    Dropped,
}

impl Failure {
    pub fn name(self) -> &'static str {
        match self {
            Failure::EapFailed => "eap-failed",
            Failure::EapTimedOut => "eap-timeout",
            Failure::Passphrase => "passphrase",
            Failure::Dropped => "dropped",
        }
    }
}

/// Who asked a client to move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// An admin's steer, by whom.
    Admin(Option<String>),
    /// The AP, answering the client's own query for candidates.
    Query,
    /// The AP of its own accord (before a restart, say): an answer to no
    /// request the controller knows of.
    Ap,
}

/// A roam, or a failed attempt at one (`session` 0).
#[derive(Debug, Clone, PartialEq)]
pub struct Roam {
    pub mac: [u8; 6],
    /// When the new AP authorized the client, or the attempt failed.
    pub at_ms: u64,
    pub from: Place,
    pub to: Place,
    /// How long the client was between the APs, at most (from the last
    /// frame the old AP's snapshots heard) and at least (from the old AP's
    /// word that it was gone, when that came first); `None` for an attempt.
    pub gap_ms: Option<u64>,
    pub gap_min_ms: u64,
    /// Its signal on the old AP last and on the new one first.
    pub before: Option<i8>,
    pub after: Option<i8>,
    /// `None` until the new AP authorized it.
    pub kind: Option<Kind>,
    /// The steering record it followed.
    pub steer: Option<u64>,
    pub failure: Option<Failure>,
    /// The session it began (0 for an attempt) and the one it left.
    session: u64,
    from_session: u64,
    settled: bool,
}

/// A steering request and what came of it.
#[derive(Debug, Clone, PartialEq)]
pub struct Steer {
    pub id: u64,
    pub at_ms: u64,
    pub ap: String,
    pub mac: [u8; 6],
    pub origin: Origin,
    /// The reason the client's query gave.
    pub reason: Option<u8>,
    /// The client's answer: its status (0 accepts) and the BSS it named.
    pub status: Option<u8>,
    pub target: Option<[u8; 6]>,
    pub answered_ms: Option<u64>,
    /// `None` until it moved or [`MOVE_MS`] passed.
    pub outcome: Option<Outcome>,
}

impl Steer {
    /// When the client answered, else when it was asked.
    fn time(&self) -> u64 {
        self.answered_ms.unwrap_or(self.at_ms)
    }

    pub fn answer(&self) -> Answer {
        match self.status {
            Some(0) => Answer::Accepted,
            Some(_) => Answer::Rejected,
            None => Answer::None,
        }
    }
}

/// What a client did after a steering request.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Moved { to: Place, after_ms: u64 },
    Stayed,
    Left,
}

/// A client's answer to a steering request, as counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Answer {
    Accepted,
    Rejected,
    None,
}

impl Answer {
    pub const ALL: [Answer; 3] = [Answer::Accepted, Answer::Rejected, Answer::None];

    pub fn name(self) -> &'static str {
        match self {
            Answer::Accepted => "accepted",
            Answer::Rejected => "rejected",
            Answer::None => "none",
        }
    }
}

/// Another AP's view of a client: its last reading there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct View {
    pub ap: String,
    pub signal: i8,
    pub at_ms: u64,
}

/// A client sticky now: where, how weak, since when, and the view it is
/// measured against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StickyNow {
    pub ap: String,
    pub band: Band,
    pub signal: i8,
    pub since_ms: u64,
    pub view: View,
}

/// What `roaming` says of one client.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Facts {
    /// Over the last day: its roams, those that failed, its sticky time.
    pub roams: usize,
    pub failed: usize,
    pub sticky_ms: u64,
    /// Over the last hour: its share of time sticky and its failed roams.
    pub sticky_share: f64,
    pub failed_hour: u32,
    pub sticky: Option<StickyNow>,
    /// Its current AP's best other view of it, while one holds.
    pub view: Option<View>,
}

/// An AP's reading of a client on one band: its average signal, when, and
/// the radio's power then.
#[derive(Debug, Clone, PartialEq)]
struct Reading {
    ap: String,
    band: Band,
    signal: i8,
    at_ms: u64,
    power_mbm: i32,
    session: u64,
}

#[derive(Debug, Default)]
struct Client {
    readings: Vec<Reading>,
    /// The session its last reading belongs to, the session that one
    /// replaced (whose readings alone are other APs' views of it), its first
    /// signal in it, and its last reading's AP, band, signal and time.
    session: u64,
    replaced: Option<u64>,
    arrived: i8,
    at: Option<(String, Band, i8, u64)>,
    sticky_since: Option<u64>,
    view: Option<View>,
    /// Sticky milliseconds by 5-minute bucket, oldest first.
    buckets: VecDeque<(u64, u64)>,
    eap_start: Option<(String, u64)>,
    /// A roam into its current session still to learn its kind or its
    /// signal after.
    open_roam: bool,
}

impl Client {
    fn newest(&self) -> u64 {
        let readings = self.readings.iter().map(|r| r.at_ms);
        let rest = [
            self.eap_start.as_ref().map(|e| e.1),
            self.at.as_ref().map(|a| a.3),
        ];
        readings
            .chain(rest.into_iter().flatten())
            .max()
            .unwrap_or(0)
    }

    fn reading(&self, ap: &str, band: Option<Band>) -> Option<&Reading> {
        self.readings
            .iter()
            .find(|r| r.ap == ap && Some(r.band) == band)
    }

    /// Takes its reading `now` in its open session `now.session`, which
    /// replaced `replaced`: whether another AP's view of it holds and it is
    /// sticky, the sticky step this reading ends (counted in its buckets),
    /// and the reading kept as its AP's view of it on the band.
    fn read(
        &mut self,
        now: Reading,
        replaced: Option<u64>,
        sticky_dbm: i8,
        radio: RadioOf,
    ) -> Option<u64> {
        if self.session != now.session {
            self.session = now.session;
            self.replaced = replaced;
            self.arrived = now.signal;
            self.at = None;
            self.sticky_since = None;
        }
        let still = (i16::from(now.signal) - i16::from(self.arrived)).abs() <= MOVED_DB;
        let holds = |r: &&Reading| {
            r.ap != now.ap
                && Some(r.session) == self.replaced
                && r.band == now.band
                && now.at_ms.saturating_sub(r.at_ms) <= VIEW_MS
                && radio(&r.ap, r.band)
                    .is_some_and(|(up, p)| up && (p - r.power_mbm).abs() <= SAME_POWER_MBM)
        };
        let best = still.then(|| self.readings.iter().filter(holds).max_by_key(|r| r.signal));
        self.view = best.flatten().map(|r| View {
            ap: r.ap.clone(),
            signal: r.signal,
            at_ms: r.at_ms,
        });
        let better = |v: &View| i16::from(v.signal) >= i16::from(now.signal) + BETTER_DB;
        let sticky = now.signal < sticky_dbm && self.view.as_ref().is_some_and(better);
        let step = self
            .at
            .as_ref()
            .filter(|_| sticky)
            .map(|a| now.at_ms.saturating_sub(a.3).min(STEP_MS));
        if let Some(ms) = step.filter(|&ms| ms > 0) {
            let bucket = now.at_ms / BUCKET_MS;
            match self.buckets.back_mut() {
                Some((b, total)) if *b == bucket => *total += ms,
                _ => self.buckets.push_back((bucket, ms)),
            }
        }
        self.sticky_since = sticky.then(|| self.sticky_since.unwrap_or(now.at_ms));
        self.at = Some((now.ap.clone(), now.band, now.signal, now.at_ms));
        match self
            .readings
            .iter_mut()
            .find(|r| r.ap == now.ap && r.band == now.band)
        {
            Some(r) => *r = now,
            None => self.readings.push(now),
        }
        step
    }

    fn sticky_in(&self, from_ms: u64) -> u64 {
        let b = self
            .buckets
            .iter()
            .filter(|(b, _)| b * BUCKET_MS + BUCKET_MS > from_ms);
        b.map(|(_, ms)| ms).sum()
    }
}

/// What the metrics count, since the controller started.
#[derive(Debug, Default)]
pub struct Counts {
    /// Roams by the AP roamed to and their kind (`None`: never authorized).
    pub roams: BTreeMap<(String, Option<Kind>), u64>,
    /// Failed roams by the AP tried.
    pub failures: BTreeMap<String, u64>,
    /// Sticky milliseconds by the AP a client stuck to.
    pub sticky_ms: BTreeMap<String, u64>,
    /// Steering requests by AP and answer, and those a client moved after.
    pub answers: BTreeMap<(String, Answer), u64>,
    pub moved: BTreeMap<String, u64>,
}

#[derive(Debug)]
pub struct Roaming {
    sticky_dbm: i8,
    clients: HashMap<[u8; 6], Client>,
    /// When each AP's radio on a band last went down.
    downs: HashMap<(String, Band), u64>,
    roams: VecDeque<Roam>,
    steers: VecDeque<Steer>,
    next_steer: u64,
    pub counts: Counts,
}

impl Default for Roaming {
    fn default() -> Self {
        Roaming::new(STICKY_DBM)
    }
}

/// The radio of an AP on a band, as its snapshot has it: whether it is up,
/// and its power (mBm).
pub type RadioOf<'a> = &'a dyn Fn(&str, Band) -> Option<(bool, i32)>;

impl Roaming {
    pub fn new(sticky_dbm: i8) -> Self {
        Roaming {
            sticky_dbm,
            clients: HashMap::new(),
            downs: HashMap::new(),
            roams: VecDeque::new(),
            steers: VecDeque::new(),
            next_steer: 0,
            counts: Counts::default(),
        }
    }

    pub fn sticky_dbm(&self) -> i8 {
        self.sticky_dbm
    }

    /// The roams kept, oldest first.
    pub fn roams(&self) -> impl DoubleEndedIterator<Item = &Roam> {
        self.roams.iter()
    }

    /// The steering records kept, oldest first.
    pub fn steers(&self) -> impl DoubleEndedIterator<Item = &Steer> {
        self.steers.iter()
    }

    pub fn steer(&self, id: u64) -> Option<&Steer> {
        self.steers.iter().find(|s| s.id == id)
    }

    /// The entry of `mac`, made when there is none, the least recently
    /// heard client dropped past [`CLIENTS_MAX`].
    fn client(&mut self, mac: [u8; 6]) -> &mut Client {
        if !self.clients.contains_key(&mac) && self.clients.len() >= CLIENTS_MAX {
            let oldest = self.clients.iter().min_by_key(|(_, c)| c.newest());
            if let Some(m) = oldest.map(|(m, _)| *m) {
                self.clients.remove(&m);
            }
        }
        self.clients.entry(mac).or_default()
    }

    fn push_roam(&mut self, r: Roam) {
        self.roams.push_back(r);
        if self.roams.len() > ROAMS_MAX {
            self.roams.pop_front();
        }
    }

    fn push_steer(&mut self, mut s: Steer) {
        self.next_steer += 1;
        s.id = self.next_steer;
        self.steers.push_back(s);
        if self.steers.len() > STEERS_MAX {
            self.steers.pop_front();
        }
    }

    /// Takes a roam the sessions decided.
    pub fn roamed(&mut self, r: Roamed) {
        let c = self.client(r.mac);
        let before = c
            .reading(&r.from.ap, r.from.band)
            .filter(|x| x.at_ms >= r.from_start_ms)
            .map(|x| x.signal);
        c.open_roam = true;
        let gap = r.began.saturating_sub(r.heard_ms);
        let gap_min = r.gone_ms.map_or(0, |g| r.began.saturating_sub(g)).min(gap);
        let followed = self
            .steers
            .iter_mut()
            .rev()
            .find(|s| s.mac == r.mac && s.outcome.is_none() && followed(s.time(), r.began));
        let steer = followed.map(|s| {
            s.outcome = Some(Outcome::Moved {
                to: r.to.clone(),
                after_ms: r.began.saturating_sub(s.time()),
            });
            s.id
        });
        if let Some(s) = steer.and_then(|id| self.steers.iter().find(|s| s.id == id)) {
            decided(&mut self.counts, s);
        }
        self.push_roam(Roam {
            mac: r.mac,
            at_ms: r.began,
            from: r.from,
            to: r.to,
            gap_ms: Some(gap),
            gap_min_ms: gap_min,
            before,
            after: None,
            kind: None,
            steer,
            failure: None,
            session: r.session,
            from_session: r.from_session,
            settled: false,
        });
    }

    /// The session the open session `s` of `mac` replaced: the one it
    /// roamed from, else the client's one before if that ended unobserved,
    /// or by the client leaving within the roam window of its AP's radio on
    /// the band going down, and before `s` began.
    fn replaced(&self, mac: &[u8; 6], s: &Session, sessions: &Sessions) -> Option<u64> {
        if let Some(r) = self.roams.iter().rev().find(|r| r.session == s.id) {
            return Some(r.from_session);
        }
        let before = sessions.of(mac).find(|p| p.id != s.id)?;
        let end = before.end_ms.filter(|&e| e <= s.start_ms)?;
        let radio_went = || {
            let band = before.place.band?;
            let down = self.downs.get(&(before.place.ap.clone(), band))?;
            Some(down.abs_diff(end) <= sessions::ROAM_WINDOW_MS)
        };
        let gone = match before.end {
            Some(End::Unobserved) => true,
            Some(End::Left | End::Inactive) => radio_went().unwrap_or(false),
            _ => false,
        };
        gone.then_some(before.id)
    }

    /// Takes an event of `ap` that happened at `at` (`sessions::event_ms`).
    pub fn event(&mut self, ap: &str, naming: &Naming, ev: &Event, at: u64, sessions: &Sessions) {
        let failed = match &ev.kind {
            EventKind::EapStart { mac, .. } => {
                self.client(*mac).eap_start = Some((ap.to_owned(), at));
                None
            }
            EventKind::EapFail { mac, bss } => Some((*mac, *bss, Failure::EapFailed)),
            EventKind::EapTimeout { mac, bss, .. } => Some((*mac, *bss, Failure::EapTimedOut)),
            EventKind::PskMismatch { mac, bss } => Some((*mac, *bss, Failure::Passphrase)),
            EventKind::RadioDown { phy } => {
                let band = naming.bands.iter().find(|(p, _)| p == phy);
                if let Some((_, band)) = band {
                    self.downs.insert((ap.to_owned(), *band), at);
                }
                None
            }
            EventKind::BtmQuery { mac, reason, .. } => {
                self.push_steer(Steer {
                    id: 0,
                    at_ms: at,
                    ap: ap.to_owned(),
                    mac: *mac,
                    origin: Origin::Query,
                    reason: Some(*reason),
                    status: None,
                    target: None,
                    answered_ms: None,
                    outcome: None,
                });
                None
            }
            EventKind::BtmResponse {
                mac,
                status,
                target,
                ..
            } => {
                self.answered(ap, *mac, *status, *target, at);
                None
            }
            _ => None,
        };
        if let Some(failed) = failed {
            self.failed(failed, ap, naming, at, sessions);
        }
    }

    /// A client's answer to a steering request: the request it answers (a
    /// query's within [`ANSWER_MS`], an admin's steer), or one of the AP's
    /// own.
    fn answered(&mut self, ap: &str, mac: [u8; 6], status: u8, target: Option<[u8; 6]>, at: u64) {
        let open = self.steers.iter_mut().rev().find(|s| {
            s.mac == mac
                && s.ap == ap
                && s.answered_ms.is_none()
                && match s.origin {
                    Origin::Query => s.at_ms <= at && at - s.at_ms <= ANSWER_MS,
                    Origin::Admin(_) => s.at_ms.abs_diff(at) <= ADMIN_MS,
                    Origin::Ap => false,
                }
        });
        match open {
            Some(s) => {
                s.status = Some(status);
                s.target = target;
                s.answered_ms = Some(at);
            }
            None => self.push_steer(Steer {
                id: 0,
                at_ms: at,
                ap: ap.to_owned(),
                mac,
                origin: Origin::Ap,
                reason: None,
                status: Some(status),
                target,
                answered_ms: Some(at),
                outcome: None,
            }),
        }
    }

    /// An admin's steer: the answer it drew, when that came first (the agent
    /// waits for it before it answers), or a request of its own when the AP
    /// sent it: the steer worked, or failed as the client declined (the
    /// agent's word for a request sent and refused; one it never sent says
    /// why it was not).
    pub fn action(&mut self, a: &Action) {
        let (Some(mac), Some(ap)) = (a.mac, a.ap.as_deref()) else {
            return;
        };
        if a.action != "steer" {
            return;
        }
        let at = unix_ms(a.at);
        let by = Origin::Admin(a.user.clone());
        let answer = self.steers.iter_mut().rev().find(|s| {
            s.mac == mac && s.ap == ap && s.origin == Origin::Ap && s.at_ms.abs_diff(at) <= ADMIN_MS
        });
        if let Some(s) = answer {
            s.origin = by;
        } else if a.ok || a.detail.contains("declined") {
            self.push_steer(Steer {
                id: 0,
                at_ms: at,
                ap: ap.to_owned(),
                mac,
                origin: by,
                reason: None,
                status: None,
                target: None,
                answered_ms: None,
                outcome: None,
            });
        }
    }

    /// An authentication of `mac` that failed at `ap`'s BSS `bss` for
    /// `why`: a failed roam when the client is on another BSS, or left one
    /// within the roam window; once per client and BSS within
    /// [`FAILED_MS`].
    fn failed(
        &mut self,
        (mac, bss, why): ([u8; 6], u16, Failure),
        ap: &str,
        naming: &Naming,
        at: u64,
        sessions: &Sessions,
    ) {
        let Some(to) = sessions::place(ap, naming, bss, None) else {
            return;
        };
        let here = |p: &Place| p.ap == to.ap && p.bss == to.bss;
        let from = match sessions.open_of(&mac) {
            Some(s) if here(&s.place) => return,
            Some(s) => s.place.clone(),
            None => {
                let last = sessions.of(&mac).next();
                let left = last.filter(|s| {
                    !here(&s.place)
                        && matches!(s.end, Some(End::Left | End::Inactive))
                        && s.end_ms
                            .is_some_and(|e| e <= at && at - e <= sessions::ROAM_WINDOW_MS)
                });
                match left {
                    Some(s) => s.place.clone(),
                    None => return,
                }
            }
        };
        let again = self
            .roams
            .iter()
            .rev()
            .take_while(|r| r.at_ms + FAILED_MS >= at);
        if again
            .filter(|r| r.mac == mac && r.session == 0)
            .any(|r| here(&r.to))
        {
            return;
        }
        let before = self
            .clients
            .get(&mac)
            .and_then(|c| c.reading(&from.ap, from.band));
        let before = before.map(|r| r.signal);
        *self.counts.failures.entry(to.ap.clone()).or_default() += 1;
        self.push_roam(Roam {
            mac,
            at_ms: at,
            from,
            to,
            gap_ms: None,
            gap_min_ms: 0,
            before,
            after: None,
            kind: None,
            steer: None,
            failure: Some(why),
            session: 0,
            from_session: 0,
            settled: true,
        });
    }

    /// Takes a snapshot of `ap` received at `at_ms`: each station whose open
    /// session is this association is read (its signal on this AP and band),
    /// completes the roam into its session, and adds to its sticky time.
    pub fn snapshot(
        &mut self,
        ap: &str,
        snap: &Snapshot,
        at_ms: u64,
        sessions: &Sessions,
        radio: RadioOf,
    ) {
        let sticky_dbm = self.sticky_dbm;
        for st in &snap.stations {
            let Some(s) = sessions.open_of(&st.mac) else {
                continue;
            };
            let here = snap.bsss.get(usize::from(st.bss));
            if s.place.ap != ap || here.is_none_or(|b| b.ifname != s.place.bss) {
                continue;
            }
            let Some(band) = s.place.band else {
                continue;
            };
            let signal = if st.signal_avg != 0 {
                st.signal_avg
            } else {
                st.signal
            };
            if self.client(st.mac).open_roam {
                let auth = snap.auth.binary_search_by_key(&st.mac, |(m, _)| *m);
                let auth = auth.ok().map(|i| &snap.auth[i].1);
                self.complete(st.mac, s.id, signal, auth);
            }
            let now = Reading {
                ap: ap.to_owned(),
                band,
                signal,
                at_ms,
                power_mbm: radio(ap, band).map_or(0, |(_, p)| p),
                session: s.id,
            };
            let replaced = self.replaced(&st.mac, s, sessions);
            if let Some(ms) = self.client(st.mac).read(now, replaced, sticky_dbm, radio) {
                *self.counts.sticky_ms.entry(ap.to_owned()).or_default() += ms;
            }
        }
    }

    /// Completes the roam into `session` of `mac`: its signal after, and,
    /// once the new AP authorized the client, its kind (EAP when an EAP
    /// exchange at that AP came near the roam).
    fn complete(&mut self, mac: [u8; 6], session: u64, signal: i8, auth: Option<&StationAuth>) {
        let eap = self.clients.get(&mac).and_then(|c| c.eap_start.clone());
        let open = match self.roams.iter_mut().rev().find(|r| r.session == session) {
            Some(r) => {
                r.after.get_or_insert(signal);
                if let Some(a) = auth.filter(|a| a.authorized && r.kind.is_none()) {
                    let near = eap.filter(|(at_ap, t)| {
                        *at_ap == r.to.ap && t.abs_diff(r.at_ms) <= EAP_NEAR_MS
                    });
                    r.kind = Some(Kind::of(a, near.is_some()));
                }
                r.kind.is_none()
            }
            None => false,
        };
        self.client(mac).open_roam = open;
    }

    /// Settles at `now_ms` what waited for its window: a roam's failure (its
    /// session ended within [`FAILED_MS`]) and its count, a steer's outcome,
    /// and drops what is past its keeping.
    pub fn settle(&mut self, now_ms: u64, sessions: &Sessions) {
        for r in self.roams.iter_mut().filter(|r| !r.settled) {
            let open = sessions.open_of(&r.mac).filter(|s| s.id == r.session);
            if open.is_some() {
                if now_ms < r.at_ms + FAILED_MS {
                    continue;
                }
            } else {
                let ended = sessions.of(&r.mac).find(|s| s.id == r.session);
                let soon = ended.filter(|s| {
                    s.end_ms
                        .is_some_and(|e| e.saturating_sub(r.at_ms) <= FAILED_MS)
                });
                r.failure = match soon.and_then(|s| s.end.as_ref()) {
                    Some(End::Left | End::Inactive) => Some(Failure::Dropped),
                    Some(End::EapFailed) => Some(Failure::EapFailed),
                    Some(End::EapTimedOut) => Some(Failure::EapTimedOut),
                    _ => None,
                };
            }
            r.settled = true;
            *self
                .counts
                .roams
                .entry((r.to.ap.clone(), r.kind))
                .or_default() += 1;
            if r.failure.is_some() {
                *self.counts.failures.entry(r.to.ap.clone()).or_default() += 1;
            }
        }
        // A client whose new association came before its answer to the
        // request was reported (two APs, two links) moved all the same.
        let late = self
            .steers
            .iter_mut()
            .filter(|s| s.outcome.is_none() && s.time() + MOVE_MS + SLACK_MS < now_ms);
        for s in late {
            let open = sessions.open_of(&s.mac);
            s.outcome = Some(match open {
                Some(o) if followed(s.time(), o.start_ms) => {
                    let roam = self.roams.iter_mut().rev().find(|r| r.session == o.id);
                    if let Some(r) = roam.filter(|r| r.steer.is_none()) {
                        r.steer = Some(s.id);
                    }
                    Outcome::Moved {
                        to: o.place.clone(),
                        after_ms: o.start_ms.saturating_sub(s.time()),
                    }
                }
                Some(_) => Outcome::Stayed,
                None => Outcome::Left,
            });
            decided(&mut self.counts, s);
        }
        let cutoff = now_ms.saturating_sub(KEEP_MS);
        while self.roams.front().is_some_and(|r| r.at_ms < cutoff) {
            self.roams.pop_front();
        }
        while self.steers.front().is_some_and(|s| s.at_ms < cutoff) {
            self.steers.pop_front();
        }
        let views = now_ms.saturating_sub(VIEW_MS);
        let day = (now_ms.saturating_sub(DAY_MS)) / BUCKET_MS;
        self.clients.retain(|_, c| {
            c.readings.retain(|r| r.at_ms >= views);
            while c.buckets.front().is_some_and(|(b, _)| *b < day) {
                c.buckets.pop_front();
            }
            c.newest() >= views || !c.buckets.is_empty()
        });
    }

    /// What `roaming` says of `mac` at `now_ms`.
    pub fn facts(&self, mac: &[u8; 6], now_ms: u64) -> Facts {
        let day = now_ms.saturating_sub(DAY_MS);
        let hour = now_ms.saturating_sub(HOUR_MS);
        let mine = || {
            self.roams
                .iter()
                .rev()
                .take_while(move |r| r.at_ms >= day)
                .filter(|r| r.mac == *mac)
        };
        let c = self.clients.get(mac);
        // Sticky now only while its last reading is fresh.
        let fresh = c
            .and_then(|c| c.at.as_ref())
            .filter(|a| a.3 + 2 * STEP_MS >= now_ms);
        let sticky = fresh.zip(c).and_then(|((ap, band, signal, _), c)| {
            Some(StickyNow {
                ap: ap.clone(),
                band: *band,
                signal: *signal,
                since_ms: c.sticky_since?,
                view: c.view.clone()?,
            })
        });
        Facts {
            roams: mine().filter(|r| r.session != 0).count(),
            failed: mine().filter(|r| r.failure.is_some()).count(),
            sticky_ms: c.map_or(0, |c| c.sticky_in(day)),
            sticky_share: c.map_or(0.0, |c| {
                (c.sticky_in(hour) as f64 / HOUR_MS as f64).min(1.0)
            }),
            failed_hour: mine()
                .filter(|r| r.at_ms >= hour && r.failure.is_some())
                .count() as u32,
            sticky,
            view: fresh.and(c).and_then(|c| c.view.clone()),
        }
    }

    /// The clients sticky now.
    pub fn sticky(&self, now_ms: u64) -> Vec<([u8; 6], StickyNow)> {
        let mut out: Vec<_> = self
            .clients
            .keys()
            .filter_map(|m| Some((*m, self.facts(m, now_ms).sticky?)))
            .collect();
        out.sort_by_key(|(m, s)| (s.since_ms, *m));
        out
    }
}

impl Roaming {
    /// What `/api/roaming` serves at `now_ms`, of `client` alone when given:
    /// the thresholds (`settings`); per AP (`aps`) the roams into it over
    /// the last day by kind and those that failed, the clients sticky on it
    /// now, and its steering records kept by who asked, by answer and by
    /// what the client did; the roams, newest first (`roams`, the site's
    /// newest [`ROAMS_SHOWN`]), the clients sticky now (`sticky`) and the
    /// steering records, newest first (`steering`, the site's newest
    /// [`STEERS_SHOWN`]); for a client, what `facts` says of it too. Each
    /// client is named by `name` when it has one.
    pub fn view(
        &self,
        client: Option<[u8; 6]>,
        now_ms: u64,
        name: impl Fn(&[u8; 6]) -> Option<String>,
    ) -> Value {
        let mine = |m: &[u8; 6]| client.is_none_or(|c| c == *m);
        let who = |m: &[u8; 6]| {
            let mut o = Map::new();
            o.insert("mac".into(), mac::format(*m).into());
            if let Some(n) = name(m) {
                o.insert("name".into(), n.into());
            }
            o
        };
        let shown = |n| if client.is_some() { usize::MAX } else { n };
        let roams: Vec<Value> = (self.roams.iter().rev())
            .filter(|r| mine(&r.mac))
            .take(shown(ROAMS_SHOWN))
            .map(|r| self.roam_json(r, who(&r.mac)))
            .collect();
        let sticky_now = self.sticky(now_ms);
        let sticky: Vec<Value> = (sticky_now.iter())
            .filter(|(m, _)| mine(m))
            .map(|(m, s)| {
                let mut o = who(m);
                o.extend(sticky_json(s));
                Value::Object(o)
            })
            .collect();
        let steering: Vec<Value> = (self.steers.iter().rev())
            .filter(|s| mine(&s.mac))
            .take(shown(STEERS_SHOWN))
            .map(|s| {
                let mut o = who(&s.mac);
                o.extend(steer_json(s));
                Value::Object(o)
            })
            .collect();
        let mut v = json!({
            "settings": {
                "sticky_dbm": self.sticky_dbm,
                "better_db": BETTER_DB,
                "moved_db": MOVED_DB,
                "view_ms": VIEW_MS,
                "move_ms": MOVE_MS,
                "failed_ms": FAILED_MS,
            },
            "roams": roams,
            "sticky": sticky,
            "steering": steering,
        });
        match client {
            Some(m) => {
                let f = self.facts(&m, now_ms);
                v["client"] = json!({
                    "roams": f.roams,
                    "failed": f.failed,
                    "sticky_ms": f.sticky_ms,
                    "sticky_share": (f.sticky_share * 1000.0).round() / 1000.0,
                    "failed_hour": f.failed_hour,
                    "view": f.view.as_ref().map(view_json),
                });
            }
            None => v["aps"] = self.aps_json(&sticky_now, now_ms),
        }
        v
    }

    /// Each AP's summary, as [`Roaming::view`] says.
    fn aps_json(&self, sticky: &[([u8; 6], StickyNow)], now_ms: u64) -> Value {
        let day = now_ms.saturating_sub(DAY_MS);
        let mut aps: BTreeMap<&str, Value> = BTreeMap::new();
        let blank = || {
            json!({
                "roams": 0, "kinds": {}, "failed": 0, "sticky": 0,
                "steering": { "asked": {}, "answers": {}, "rejected": {}, "outcomes": {} },
            })
        };
        let add = |v: &mut Value, path: &[&str]| {
            let mut at = v;
            for p in path {
                at = &mut at[*p];
            }
            *at = (at.as_u64().unwrap_or(0) + 1).into();
        };
        for r in self.roams.iter().rev().take_while(|r| r.at_ms >= day) {
            let a = aps.entry(&r.to.ap).or_insert_with(blank);
            if r.session != 0 {
                add(a, &["roams"]);
                add(a, &["kinds", r.kind.map_or("unknown", Kind::name)]);
            }
            if r.failure.is_some() {
                add(a, &["failed"]);
            }
        }
        for (_, s) in sticky {
            add(aps.entry(&s.ap).or_insert_with(blank), &["sticky"]);
        }
        for s in &self.steers {
            let a = &mut aps.entry(&s.ap).or_insert_with(blank)["steering"];
            add(a, &["asked", origin_name(&s.origin)]);
            add(a, &["answers", s.answer().name()]);
            if let Some(code) = s.status.filter(|&c| c != 0) {
                add(a, &["rejected", &code.to_string()]);
            }
            let outcome = match &s.outcome {
                Some(Outcome::Moved { .. }) => "moved",
                Some(Outcome::Stayed) => "stayed",
                Some(Outcome::Left) => "left",
                None => "pending",
            };
            add(a, &["outcomes", outcome]);
        }
        let aps = aps.into_iter().map(|(k, v)| (k.to_owned(), v));
        Value::Object(aps.collect())
    }

    fn roam_json(&self, r: &Roam, mut o: Map<String, Value>) -> Value {
        o.insert("at".into(), r.at_ms.into());
        o.insert("from".into(), Value::Object(crate::view::place(&r.from)));
        o.insert("to".into(), Value::Object(crate::view::place(&r.to)));
        let mut put = |k: &str, v: Option<Value>| {
            if let Some(v) = v {
                o.insert(k.into(), v);
            }
        };
        put("gap_ms", r.gap_ms.map(Into::into));
        put("gap_min_ms", r.gap_ms.map(|_| r.gap_min_ms.into()));
        put("before", r.before.map(Into::into));
        put("after", r.after.map(Into::into));
        put("kind", r.kind.map(|k| k.name().into()));
        put("failure", r.failure.map(|f| f.name().into()));
        let steer = r.steer.and_then(|id| self.steer(id));
        put(
            "steered",
            steer.map(|s| Value::Object(origin_json(&s.origin))),
        );
        Value::Object(o)
    }
}

fn origin_name(o: &Origin) -> &'static str {
    match o {
        Origin::Admin(_) => "admin",
        Origin::Query => "query",
        Origin::Ap => "ap",
    }
}

/// Who asked: `origin`, and the admin's name (`by`).
fn origin_json(o: &Origin) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("origin".into(), origin_name(o).into());
    if let Origin::Admin(Some(by)) = o {
        m.insert("by".into(), by.clone().into());
    }
    m
}

fn view_json(v: &View) -> Value {
    json!({ "ap": v.ap, "signal": v.signal, "at": v.at_ms })
}

fn sticky_json(s: &StickyNow) -> Map<String, Value> {
    let v = json!({
        "ap": s.ap,
        "band": crate::view::band(s.band),
        "signal": s.signal,
        "since": s.since_ms,
        "view": view_json(&s.view),
    });
    match v {
        Value::Object(o) => o,
        _ => Map::new(),
    }
}

fn steer_json(s: &Steer) -> Map<String, Value> {
    let mut o = origin_json(&s.origin);
    o.insert("at".into(), s.at_ms.into());
    o.insert("ap".into(), s.ap.clone().into());
    let mut put = |k: &str, v: Option<Value>| {
        if let Some(v) = v {
            o.insert(k.into(), v);
        }
    };
    put("reason", s.reason.map(Into::into));
    put("status", s.status.map(Into::into));
    put("target", s.target.map(|t| mac::format(t).into()));
    put("answered", s.answered_ms.map(Into::into));
    let outcome = s.outcome.as_ref().map(|o| match o {
        Outcome::Moved { to, after_ms } => {
            json!({ "moved": crate::view::place(to), "after_ms": after_ms })
        }
        Outcome::Stayed => "stayed".into(),
        Outcome::Left => "left".into(),
    });
    put("outcome", outcome);
    o
}

/// Whether a client that began a session at `began` followed a steering
/// request of `asked`: within [`MOVE_MS`] after it, [`SLACK_MS`] either way.
fn followed(asked: u64, began: u64) -> bool {
    (asked.saturating_sub(SLACK_MS)..=asked + MOVE_MS + SLACK_MS).contains(&began)
}

/// Counts a steer whose outcome is settled.
fn decided(counts: &mut Counts, s: &Steer) {
    *counts
        .answers
        .entry((s.ap.clone(), s.answer()))
        .or_default() += 1;
    if matches!(s.outcome, Some(Outcome::Moved { .. })) {
        *counts.moved.entry(s.ap.clone()).or_default() += 1;
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use u6e_proto::msg::{Bss, RateMode, Station};

    use super::*;

    const T0: u64 = 1_800_000_000_000;
    const S: u64 = 1000;

    fn mac(last: u8) -> [u8; 6] {
        [2, 0, 0, 0, 0, last]
    }

    /// Each AP: 5 GHz `wlan5` (0), 6 GHz `wlan6` (1), 2.4 GHz `wlan24` (2),
    /// one SSID.
    fn naming() -> Naming {
        let bss = |ifname: &str, phy: &str| Bss {
            ifname: ifname.into(),
            bssid: [2, 0, 0, 0, 0x10, 1],
            ssid: "ssid-a".into(),
            phy: phy.into(),
            vlan: 10,
        };
        Naming {
            bsss: vec![
                bss("wlan5", "phy1"),
                bss("wlan6", "phy2"),
                bss("wlan24", "phy0"),
            ],
            bands: vec![
                ("phy1".into(), Band::B5),
                ("phy2".into(), Band::B6),
                ("phy0".into(), Band::B24),
            ],
        }
    }

    /// How a station authenticated: its AKM suite and algorithm.
    const FT: (u32, u16) = (0x000f_ac03, 2);
    const EAP: (u32, u16) = (0x000f_ac03, 0);
    const PSK: (u32, u16) = (0x000f_ac02, 0);

    /// A station a snapshot lists: the last byte of its MAC, its BSS, its
    /// signal, its connected seconds and how it authenticated.
    struct Sta(u8, u16, i8, u32, Option<(u32, u16)>);

    fn station(s: &Sta) -> Station {
        Station {
            mac: mac(s.0),
            bss: s.1,
            signal: s.2,
            signal_avg: s.2,
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
            tx_mode: RateMode::He,
            rx_mode: RateMode::He,
            tx_nss: 2,
            rx_nss: 2,
            tx_airtime_us: 0,
            rx_airtime_us: 0,
            inactive_ms: 100,
            connected_s: s.3,
            vlan: 10,
        }
    }

    /// Both APs' sessions and roaming, fed as the state feeds them; every
    /// radio up at 23 dBm unless a test sets otherwise.
    struct Site {
        s: Sessions,
        r: Roaming,
        radios: HashMap<(String, Band), (bool, i32)>,
    }

    impl Site {
        fn new() -> Self {
            let mut radios = HashMap::new();
            for ap in ["ap1", "ap2"] {
                for band in [Band::B24, Band::B5, Band::B6] {
                    radios.insert((ap.to_owned(), band), (true, 2300));
                }
            }
            Site {
                s: Sessions::default(),
                r: Roaming::default(),
                radios,
            }
        }

        fn event(&mut self, ap: &str, at: u64, kind: EventKind) {
            let ev = Event { at_ms: at, kind };
            self.s.event(ap, &naming(), &ev, at);
            for x in self.s.take_roams() {
                self.r.roamed(x);
            }
            self.r.event(ap, &naming(), &ev, at, &self.s);
        }

        fn snap(&mut self, ap: &str, at: u64, stations: &[Sta]) {
            self.snap_of(ap, at, stations, false);
        }

        /// The first snapshot of the AP's link after it was away.
        fn back(&mut self, ap: &str, at: u64, stations: &[Sta]) {
            self.snap_of(ap, at, stations, true);
        }

        fn snap_of(&mut self, ap: &str, at: u64, stations: &[Sta], fresh: bool) {
            let mut list: Vec<&Sta> = stations.iter().collect();
            list.sort_by_key(|s| s.0);
            let auth = list
                .iter()
                .filter_map(|s| {
                    let (akm, auth_alg) = s.4?;
                    let a = StationAuth {
                        akm,
                        auth_alg,
                        authorized: true,
                        identity: String::new(),
                        eap_method: 13,
                        reauth_s: 0,
                    };
                    Some((mac(s.0), a))
                })
                .collect();
            let snap = Snapshot {
                seq: 1,
                uptime_s: 0,
                load_milli: 0,
                mem_avail_kb: 0,
                nss_load_pct: 0,
                temps: Vec::new(),
                radios: Vec::new(),
                bsss: naming().bsss,
                stations: list.into_iter().map(station).collect(),
                config_sha256: None,
                clock_synced: true,
                power_limits: Vec::new(),
                auth,
                caps: Vec::new(),
                offload_held: false,
            };
            self.s.snapshot(ap, &snap, &naming(), at, fresh);
            for x in self.s.take_roams() {
                self.r.roamed(x);
            }
            let radios = &self.radios;
            let radio = |a: &str, b| radios.get(&(a.to_owned(), b)).copied();
            self.r.snapshot(ap, &snap, at, &self.s, &radio);
            self.r.settle(at, &self.s);
        }

        /// The newest roam of `last`.
        fn roam(&self, last: u8) -> &Roam {
            self.r.roams().rev().find(|r| r.mac == mac(last)).unwrap()
        }

        fn steer(&self, last: u8) -> &Steer {
            self.r.steers().rev().find(|s| s.mac == mac(last)).unwrap()
        }

        fn act(&mut self, last: u8, at: u64, ok: bool) {
            self.r.action(&Action {
                at: UNIX_EPOCH + Duration::from_millis(at),
                user: Some("admin".into()),
                action: "steer",
                mac: Some(mac(last)),
                ap: Some("ap1".into()),
                ok,
                detail: String::new(),
            });
        }
    }

    fn assoc(last: u8, bss: u16) -> EventKind {
        EventKind::Assoc {
            mac: mac(last),
            bss,
        }
    }

    fn disassoc(last: u8, bss: u16) -> EventKind {
        EventKind::Disassoc {
            mac: mac(last),
            bss,
        }
    }

    /// A client on `ap1`'s 5 GHz BSS heard at `signal` at T0 and two
    /// seconds later (last heard 100 ms before each).
    fn on_ap1(site: &mut Site, last: u8, signal: i8) {
        site.snap("ap1", T0, &[Sta(last, 0, signal, 60, Some(EAP))]);
        site.snap("ap1", T0 + 2 * S, &[Sta(last, 0, signal, 62, Some(EAP))]);
    }

    /// The new AP heard the client first: its gap is at most the time since
    /// the old AP's snapshots last heard it; the old AP's pruning of it
    /// afterwards, and its stale listing, change nothing.
    #[test]
    fn an_ft_roam_is_timed_by_what_the_old_ap_last_heard() {
        let mut site = Site::new();
        on_ap1(&mut site, 1, -70);
        site.event("ap2", T0 + 3 * S, assoc(1, 0));
        site.snap("ap1", T0 + 3500, &[Sta(1, 0, -40, 63, Some(EAP))]);
        site.snap("ap2", T0 + 4 * S, &[Sta(1, 0, -50, 1, Some(FT))]);
        site.event("ap1", T0 + 6 * S, disassoc(1, 0));
        let r = site.roam(1).clone();
        assert_eq!((r.from.ap.as_str(), r.to.ap.as_str()), ("ap1", "ap2"));
        assert_eq!((r.from.band, r.to.band), (Some(Band::B5), Some(Band::B5)));
        assert_eq!((r.gap_ms, r.gap_min_ms), (Some(1100), 0));
        assert_eq!(
            (r.before, r.after, r.kind),
            (Some(-70), Some(-50), Some(Kind::Ft))
        );
        site.snap("ap2", T0 + 40 * S, &[Sta(1, 0, -50, 37, Some(FT))]);
        assert_eq!(site.r.roams().count(), 1);
        assert_eq!(site.roam(1).failure, None);
        let key = ("ap2".to_owned(), Some(Kind::Ft));
        assert_eq!(site.r.counts.roams.get(&key), Some(&1));
        assert!(site.r.counts.failures.is_empty());
    }

    /// A client that left one AP and joined another: the old AP's word that
    /// it was gone bounds the gap from below; EAP at the new AP makes the
    /// roam a full one, its absence a cached one, a passphrase a PSK one.
    #[test]
    fn a_roam_after_leaving_is_bounded_both_ways_and_named_by_its_sign_in() {
        let mut site = Site::new();
        for (last, eap, how, kind) in [
            (1, true, EAP, Kind::Eap),
            (2, false, EAP, Kind::Cached),
            (3, false, PSK, Kind::Psk),
        ] {
            on_ap1(&mut site, last, -71);
            site.event("ap1", T0 + 2500, disassoc(last, 0));
            if eap {
                let start = EventKind::EapStart {
                    mac: mac(last),
                    bss: 0,
                };
                site.event("ap2", T0 + 2600, start);
            }
            site.event("ap2", T0 + 3200, assoc(last, 0));
            site.snap("ap2", T0 + 4 * S, &[Sta(last, 0, -55, 1, Some(how))]);
            let r = site.roam(last);
            assert_eq!((r.gap_ms, r.gap_min_ms), (Some(1300), 700), "{last}");
            assert_eq!(r.kind, Some(kind), "{last}");
        }
    }

    /// A move to another band of the same AP is a roam too.
    #[test]
    fn a_band_change_on_one_ap_is_a_roam() {
        let mut site = Site::new();
        on_ap1(&mut site, 1, -60);
        site.event("ap1", T0 + 3 * S, assoc(1, 1));
        let r = site.roam(1);
        assert_eq!((r.from.ap.as_str(), r.to.ap.as_str()), ("ap1", "ap1"));
        assert_eq!((r.from.band, r.to.band), (Some(Band::B5), Some(Band::B6)));
    }

    /// A roam whose session ends within 30 s failed, once; one that holds
    /// did not.
    #[test]
    fn a_roam_that_drops_at_once_failed() {
        let mut site = Site::new();
        on_ap1(&mut site, 1, -70);
        site.event("ap2", T0 + 3 * S, assoc(1, 0));
        site.snap("ap2", T0 + 4 * S, &[Sta(1, 0, -60, 1, Some(FT))]);
        site.event("ap2", T0 + 8 * S, disassoc(1, 0));
        site.snap("ap2", T0 + 40 * S, &[]);
        assert_eq!(site.roam(1).failure, Some(Failure::Dropped));
        assert_eq!(site.r.counts.failures.get("ap2"), Some(&1));
        site.snap("ap2", T0 + 80 * S, &[]);
        assert_eq!(site.r.counts.failures.get("ap2"), Some(&1));
        let f = site.r.facts(&mac(1), T0 + 80 * S);
        assert_eq!((f.roams, f.failed, f.failed_hour), (1, 1, 1));
    }

    /// A sign-in that fails on another AP or band while the client is on
    /// one is a failed roam, once per BSS within 30 s; one on its own BSS,
    /// or of a client on none, is not.
    #[test]
    fn a_failed_sign_in_elsewhere_is_a_failed_roam() {
        let mut site = Site::new();
        on_ap1(&mut site, 1, -70);
        let fail = |bss| EventKind::EapFail { mac: mac(1), bss };
        site.event("ap2", T0 + 5 * S, fail(0));
        site.event("ap2", T0 + 6 * S, fail(0));
        let wrong = EventKind::PskMismatch {
            mac: mac(1),
            bss: 2,
        };
        site.event("ap2", T0 + 7 * S, wrong);
        site.event("ap1", T0 + 8 * S, fail(0));
        site.event(
            "ap2",
            T0 + 9 * S,
            EventKind::EapFail {
                mac: mac(9),
                bss: 0,
            },
        );
        let failed: Vec<(&str, Option<Band>, Option<Failure>)> = site
            .r
            .roams()
            .map(|r| (r.to.ap.as_str(), r.to.band, r.failure))
            .collect();
        assert_eq!(
            failed,
            [
                ("ap2", Some(Band::B5), Some(Failure::EapFailed)),
                ("ap2", Some(Band::B24), Some(Failure::Passphrase)),
            ]
        );
        let first = site.r.roams().next().unwrap();
        assert_eq!(
            (first.from.ap.as_str(), first.gap_ms, first.before),
            ("ap1", None, Some(-70))
        );
        assert_eq!(site.r.counts.failures.get("ap2"), Some(&2));
    }

    /// The speakers of an AP that rebooted: on the far AP at −78 dBm, sticky
    /// once the near AP is back (its last reading, from before, 33 dB
    /// stronger), each step counted and capped at 30 s, until the speaker
    /// moves.
    #[test]
    fn a_speaker_stuck_on_the_far_ap_after_a_reboot_is_sticky() {
        let mut site = Site::new();
        site.snap("ap1", T0, &[Sta(1, 0, -45, 600, Some(EAP))]);
        site.snap("ap1", T0 + 15 * S, &[Sta(1, 0, -45, 615, Some(EAP))]);
        // ap1 reboots: its radios are gone and the speaker joins ap2.
        for band in [Band::B24, Band::B5, Band::B6] {
            site.radios.remove(&("ap1".to_owned(), band));
        }
        let at = |s| T0 + s * S;
        site.snap("ap2", at(120), &[Sta(1, 0, -78, 5, Some(EAP))]);
        site.snap("ap2", at(135), &[Sta(1, 0, -78, 20, Some(EAP))]);
        assert_eq!(site.r.facts(&mac(1), at(135)).sticky, None);
        site.radios
            .insert(("ap1".to_owned(), Band::B5), (true, 2300));
        site.snap("ap2", at(150), &[Sta(1, 0, -77, 35, Some(EAP))]);
        site.snap("ap2", at(165), &[Sta(1, 0, -79, 50, Some(EAP))]);
        let f = site.r.facts(&mac(1), at(165));
        assert_eq!(f.sticky_ms, 30 * S);
        let now = f.sticky.unwrap();
        assert_eq!(
            (now.ap.as_str(), now.band, now.signal, now.since_ms),
            ("ap2", Band::B5, -79, at(150))
        );
        assert_eq!(
            (now.view.ap.as_str(), now.view.signal, now.view.at_ms),
            ("ap1", -45, at(15))
        );
        // ap1 listing it a moment longer changes ap1's reading in nothing.
        site.snap("ap1", at(166), &[Sta(1, 0, -30, 666, Some(EAP))]);
        site.snap("ap2", at(265), &[Sta(1, 0, -78, 150, Some(EAP))]);
        assert_eq!(site.r.facts(&mac(1), at(265)).sticky_ms, 60 * S);
        assert_eq!(
            site.r.facts(&mac(1), at(265)).sticky.unwrap().view.signal,
            -45
        );
        // Moved: 8 dB from where it began on ap2.
        site.snap("ap2", at(280), &[Sta(1, 0, -86, 165, Some(EAP))]);
        let f = site.r.facts(&mac(1), at(280));
        assert_eq!((f.sticky, f.view, f.sticky_ms), (None, None, 60 * S));
        assert_eq!(site.r.counts.sticky_ms.get("ap2"), Some(&(60 * S)));
        // Hours on, the day still counts it, the last hour does not.
        let later = site.r.facts(&mac(1), at(280) + 2 * 3600 * S);
        assert_eq!((later.sticky_ms, later.sticky_share), (60 * S, 0.0));
        assert!((site.r.facts(&mac(1), at(280)).sticky_share - 60.0 / 3600.0).abs() < 1e-9);
    }

    /// A laptop read at -45 dBm on ap1 that left, and woke three hours later
    /// on ap2 at -78: ap1's reading is of a session its new one did not
    /// replace, so it is no view of where the laptop is.
    #[test]
    fn a_reading_of_an_unrelated_session_is_no_view() {
        let mut site = Site::new();
        site.snap("ap1", T0, &[Sta(1, 0, -45, 600, Some(EAP))]);
        site.event("ap1", T0 + 10 * S, disassoc(1, 0));
        let later = T0 + 3 * 3600 * S;
        site.snap("ap2", later, &[Sta(1, 0, -78, 5, Some(EAP))]);
        site.snap("ap2", later + 15 * S, &[Sta(1, 0, -78, 20, Some(EAP))]);
        site.snap("ap2", later + 30 * S, &[Sta(1, 0, -78, 35, Some(EAP))]);
        let f = site.r.facts(&mac(1), later + 30 * S);
        assert_eq!((f.sticky, f.view, f.sticky_ms), (None, None, 0));
    }

    /// A client the APs lost track of, not one that left: its session ended
    /// unobserved (its AP's link came back without it), or as its AP's radio
    /// on the band went down; the session it joins after replaced it.
    #[test]
    fn a_session_lost_with_its_ap_or_radio_was_replaced() {
        let stuck = |site: &mut Site, at: u64| {
            site.snap("ap2", at, &[Sta(1, 0, -78, 5, Some(EAP))]);
            site.snap("ap2", at + 15 * S, &[Sta(1, 0, -78, 20, Some(EAP))]);
            site.snap("ap2", at + 30 * S, &[Sta(1, 0, -78, 35, Some(EAP))]);
            site.r.facts(&mac(1), at + 30 * S).sticky_ms
        };
        let mut site = Site::new();
        site.snap("ap1", T0, &[Sta(1, 0, -45, 600, Some(EAP))]);
        site.back("ap1", T0 + 100 * S, &[]);
        assert_eq!(stuck(&mut site, T0 + 200 * S), 30 * S, "unobserved");

        let mut site = Site::new();
        site.snap("ap1", T0, &[Sta(1, 0, -45, 600, Some(EAP))]);
        let down = EventKind::RadioDown { phy: "phy1".into() };
        site.event("ap1", T0 + 10 * S, down);
        site.event("ap1", T0 + 10_500, disassoc(1, 0));
        assert_eq!(stuck(&mut site, T0 + 60 * S), 30 * S, "radio down");
    }

    /// The view of the other AP holds only while it can: not once that AP's
    /// radio runs at another power, not for another band, not for a client
    /// above the threshold or one the other AP heard less than 8 dB better.
    #[test]
    fn another_aps_view_holds_only_while_it_can() {
        let sticky = |setup: &dyn Fn(&mut Site), near: i8, far: i8, bss: u16| {
            let mut site = Site::new();
            site.snap("ap1", T0, &[Sta(1, 0, near, 600, Some(EAP))]);
            setup(&mut site);
            site.snap("ap2", T0 + 60 * S, &[Sta(1, bss, far, 5, Some(EAP))]);
            site.snap("ap2", T0 + 75 * S, &[Sta(1, bss, far, 20, Some(EAP))]);
            site.r.facts(&mac(1), T0 + 75 * S).sticky_ms
        };
        let none = |_: &mut Site| {};
        assert_eq!(sticky(&none, -45, -78, 0), 15 * S);
        let lower = |s: &mut Site| {
            s.radios.insert(("ap1".to_owned(), Band::B5), (true, 2000));
        };
        assert_eq!(sticky(&lower, -45, -78, 0), 0, "another power");
        let down = |s: &mut Site| {
            s.radios.insert(("ap1".to_owned(), Band::B5), (false, 2300));
        };
        assert_eq!(sticky(&down, -45, -78, 0), 0, "radio down");
        assert_eq!(sticky(&none, -45, -78, 1), 0, "another band");
        assert_eq!(sticky(&none, -45, -70, 0), 0, "above the threshold");
        assert_eq!(sticky(&none, -71, -78, 0), 0, "7 dB better only");
        assert_eq!(sticky(&none, -70, -78, 0), 15 * S, "8 dB better");
        // A view older than a day is no view.
        let mut site = Site::new();
        site.snap("ap1", T0, &[Sta(1, 0, -45, 600, Some(EAP))]);
        let day = 24 * 3600 * S;
        site.snap("ap2", T0 + day, &[Sta(1, 0, -78, 5, Some(EAP))]);
        site.snap("ap2", T0 + day + 15 * S, &[Sta(1, 0, -78, 20, Some(EAP))]);
        assert_eq!(site.r.facts(&mac(1), T0 + day + 15 * S).sticky_ms, 0);
    }

    /// An admin's steer: the client's answer came first (the agent waits for
    /// it before it answers the controller), the roam right after.
    #[test]
    fn an_admin_steer_answered_and_followed() {
        let mut site = Site::new();
        on_ap1(&mut site, 1, -70);
        let target = [2, 0, 0, 0, 0x20, 1];
        let answer = EventKind::BtmResponse {
            mac: mac(1),
            bss: 0,
            status: 0,
            target: Some(target),
        };
        site.event("ap1", T0 + 3 * S, answer);
        site.event("ap2", T0 + 3800, assoc(1, 0));
        site.act(1, T0 + 4500, true);
        let s = site.steer(1).clone();
        assert_eq!(s.origin, Origin::Admin(Some("admin".into())));
        assert_eq!((s.status, s.target), (Some(0), Some(target)));
        let Some(Outcome::Moved { to, after_ms }) = &s.outcome else {
            panic!("{s:?}")
        };
        assert_eq!((to.ap.as_str(), *after_ms), ("ap2", 800));
        assert_eq!(site.roam(1).steer, Some(s.id));
        assert_eq!(site.r.steers().count(), 1);
        let key = ("ap1".to_owned(), Answer::Accepted);
        assert_eq!(site.r.counts.answers.get(&key), Some(&1));
        assert_eq!(site.r.counts.moved.get("ap1"), Some(&1));
    }

    /// A client's query answered by its AP and the request rejected, then
    /// the client staying; the AP's own request; an admin's steer the client
    /// never answered; and one that never reached it.
    #[test]
    fn steering_records_say_who_asked_and_what_the_client_did() {
        let mut site = Site::new();
        on_ap1(&mut site, 1, -70);
        on_ap1(&mut site, 2, -70);
        on_ap1(&mut site, 3, -70);
        on_ap1(&mut site, 4, -70);
        let query = EventKind::BtmQuery {
            mac: mac(1),
            bss: 0,
            reason: 16,
        };
        let answer = |last, status| EventKind::BtmResponse {
            mac: mac(last),
            bss: 0,
            status,
            target: None,
        };
        site.event("ap1", T0 + 3 * S, query);
        site.event("ap1", T0 + 3050, answer(1, 7));
        site.event("ap1", T0 + 3 * S, answer(2, 0));
        site.act(3, T0 + 3 * S, true);
        site.act(4, T0 + 3 * S, false);
        let all = [
            Sta(1, 0, -70, 80, None),
            Sta(2, 0, -70, 80, None),
            Sta(3, 0, -70, 80, None),
        ];
        site.snap("ap1", T0 + 20 * S, &all);
        let s = site.steer(1);
        assert_eq!(
            (s.origin.clone(), s.reason, s.status),
            (Origin::Query, Some(16), Some(7))
        );
        assert_eq!(s.outcome, Some(Outcome::Stayed));
        assert_eq!(site.steer(2).origin, Origin::Ap);
        let s = site.steer(3);
        assert_eq!(
            (s.origin.clone(), s.status),
            (Origin::Admin(Some("admin".into())), None)
        );
        assert_eq!(site.r.steers().filter(|s| s.mac == mac(4)).count(), 0);
        let count = |a| site.r.counts.answers.get(&("ap1".to_owned(), a)).copied();
        assert_eq!(
            (
                count(Answer::Accepted),
                count(Answer::Rejected),
                count(Answer::None)
            ),
            (Some(1), Some(1), Some(1))
        );
        assert_eq!(site.r.counts.moved.get("ap1"), None);
    }

    /// An admin's steer the client declined, its result here before the
    /// client's answer: one request, the admin's, answered.
    #[test]
    fn a_declined_steer_is_the_admins_whichever_word_comes_first() {
        let mut site = Site::new();
        on_ap1(&mut site, 1, -70);
        site.r.action(&Action {
            at: UNIX_EPOCH + Duration::from_millis(T0 + 3 * S),
            user: Some("admin".into()),
            action: "steer",
            mac: Some(mac(1)),
            ap: Some("ap1".into()),
            ok: false,
            detail: "wlan5: declined: no suitable candidates".into(),
        });
        let answer = EventKind::BtmResponse {
            mac: mac(1),
            bss: 0,
            status: 7,
            target: None,
        };
        site.event("ap1", T0 + 3200, answer);
        assert_eq!(site.r.steers().count(), 1);
        let s = site.steer(1);
        assert_eq!(
            (s.origin.clone(), s.status),
            (Origin::Admin(Some("admin".into())), Some(7))
        );
    }

    /// The new AP's word of the association came before the old AP's of
    /// the client's answer, and two APs' clocks put the answer a little
    /// after the roam: the client moved, and the roam followed the steer.
    #[test]
    fn a_move_reported_before_the_answer_is_a_move() {
        let mut site = Site::new();
        on_ap1(&mut site, 1, -70);
        site.event("ap2", T0 + 3 * S, assoc(1, 0));
        let answer = EventKind::BtmResponse {
            mac: mac(1),
            bss: 0,
            status: 0,
            target: Some([2, 0, 0, 0, 0x20, 1]),
        };
        site.event("ap1", T0 + 3400, answer);
        site.snap("ap2", T0 + 20 * S, &[Sta(1, 0, -60, 17, Some(FT))]);
        let s = site.steer(1).clone();
        let Some(Outcome::Moved { to, after_ms }) = &s.outcome else {
            panic!("{s:?}")
        };
        assert_eq!((to.ap.as_str(), *after_ms), ("ap2", 0));
        assert_eq!(site.roam(1).steer, Some(s.id));
        assert_eq!(site.r.counts.moved.get("ap1"), Some(&1));
        // One that stays where it was asked to leave stayed.
        on_ap1(&mut site, 2, -70);
        let answer = EventKind::BtmResponse {
            mac: mac(2),
            bss: 0,
            status: 0,
            target: None,
        };
        site.event("ap1", T0 + 3 * S, answer);
        site.snap("ap1", T0 + 20 * S, &[Sta(2, 0, -70, 80, Some(EAP))]);
        assert_eq!(site.steer(2).outcome, Some(Outcome::Stayed));
    }

    /// Kept: the newest roams, the last week, and the clients heard last.
    #[test]
    fn what_is_kept_is_bounded() {
        let mut r = Roaming::default();
        let place = Place {
            ap: "ap1".into(),
            bss: "wlan5".into(),
            ssid: "ssid-a".into(),
            band: Some(Band::B5),
            vlan: 10,
        };
        for i in 0..=ROAMS_MAX as u64 {
            r.push_roam(Roam {
                mac: mac(1),
                at_ms: T0 + i,
                from: place.clone(),
                to: place.clone(),
                gap_ms: None,
                gap_min_ms: 0,
                before: None,
                after: None,
                kind: None,
                steer: None,
                failure: None,
                session: 0,
                from_session: 0,
                settled: true,
            });
        }
        assert_eq!(r.roams().count(), ROAMS_MAX);
        assert_eq!(r.roams().next().unwrap().at_ms, T0 + 1);
        r.settle(T0 + KEEP_MS + 1000, &Sessions::default());
        assert_eq!(r.roams().count(), ROAMS_MAX - 1000 + 1);
        for i in 0..=CLIENTS_MAX as u64 {
            let m = [2, 0, 0, 0, (i >> 8) as u8, i as u8];
            r.client(m).eap_start = Some(("ap1".into(), T0 + i));
        }
        assert_eq!(r.clients.len(), CLIENTS_MAX);
        assert!(!r.clients.contains_key(&[2, 0, 0, 0, 0, 0]));
        r.settle(T0 + KEEP_MS, &Sessions::default());
        assert!(r.clients.is_empty());
    }
}
