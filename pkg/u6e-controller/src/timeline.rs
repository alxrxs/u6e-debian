//! Each client's history as one ordered list: what it went through on the
//! Wi-Fi (associations and roams, EAP's steps, a passphrase that did not
//! match, disconnects), what RADIUS answered for it, its DHCP leases being
//! granted and renewed, its first traffic, the operators' actions on it and
//! the client guards' reports. Every entry is whole on its own (where, who,
//! how long), so it reads the same once the session it belongs to is gone.
//!
//! Bounded: a client's entries are kept for [`KEEP`], at most [`PER_CLIENT`]
//! of them, and [`TOTAL`] over every client, the oldest going first.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use u6e_proto::msg::{Band, Guard, StationAuth};

/// How long a client's entries are kept.
pub const KEEP_MS: u64 = 7 * 24 * 3600 * 1000;
/// The most entries kept of one client: a client roaming every few minutes
/// for a week stays within it.
pub const PER_CLIENT: usize = 2000;
/// The most entries kept over every client.
pub const TOTAL: usize = 100_000;

/// One thing that happened to a client, in milliseconds since the epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub at_ms: u64,
    pub what: What,
}

/// Where a client was associated: the AP, the BSS's interface and SSID, its
/// radio's band and the client's VLAN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Place {
    pub ap: String,
    pub bss: String,
    pub ssid: String,
    pub band: Option<Band>,
    pub vlan: u16,
}

/// Where a roam came from: the AP and band left, and how long the client
/// was on neither (`None` when the new association came first).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roam {
    pub ap: String,
    pub band: Option<Band>,
    pub gap_ms: Option<u64>,
    /// The operator whose steer it followed.
    pub steered_by: Option<String>,
}

/// Why a session ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum End {
    /// It disassociated, or went out of range.
    Left,
    /// It associated elsewhere.
    Roamed {
        to: String,
    },
    /// An operator kicked or blocked it.
    Kicked {
        by: Option<String>,
    },
    Blocked {
        by: Option<String>,
    },
    /// Its EAP failed or timed out.
    EapFailed,
    EapTimedOut,
    /// It had been silent past the AP's inactivity limit.
    Inactive,
    /// It was gone when its AP was heard again: the AP's link, or the
    /// controller, was away when it ended.
    Unobserved,
}

/// A step of EAP on an AP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EapStep {
    Started,
    /// It succeeded, `ms` after it started (when the start was seen).
    Succeeded {
        ms: Option<u64>,
    },
    /// RADIUS rejected the client.
    Failed,
    /// The client stopped answering, or (`server`) RADIUS did.
    TimedOut {
        server: bool,
    },
}

/// What happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum What {
    /// It associated, beginning session `session`, roaming in when `from`
    /// says where from; `auth` once its AP said how it authenticated.
    Joined {
        session: u64,
        place: Place,
        from: Option<Roam>,
        auth: Option<StationAuth>,
    },
    /// Session `session` ended after `secs`, not by a roam (a roam is the
    /// next session's `Joined`).
    Ended {
        session: u64,
        ap: String,
        why: End,
        secs: u64,
    },
    Eap {
        ap: String,
        step: EapStep,
    },
    /// Its 4-way handshake failed as a wrong passphrase makes it fail.
    PskMismatch {
        ap: String,
    },
    /// RADIUS's verdict, as its log has it: the User-Name, the node that
    /// answered, the NAS (the RADIUS client's name), the detail (the method
    /// on an accept, the reason on a reject) and the client certificate's
    /// expiry (Unix seconds).
    Radius {
        accept: bool,
        user: String,
        node: String,
        nas: String,
        detail: String,
        cert_expires: Option<u64>,
    },
    /// A DHCP server leased it `ip` until `expires` (Unix seconds): newly,
    /// or `renewed`.
    Lease {
        ip: IpAddr,
        expires: u64,
        renewed: bool,
    },
    /// Its first connections of the session, as its AP's flows counted them.
    FirstTraffic {
        ap: String,
        conns: u32,
    },
    /// An operator's action on it.
    Action {
        action: String,
        user: Option<String>,
        ap: Option<String>,
        ok: bool,
        detail: String,
    },
    /// A client guard's report of it.
    Guard {
        ap: String,
        guard: Guard,
        detail: String,
        dropped: bool,
        repeats: u32,
    },
}

/// Every client's entries, each client's sorted by time.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Timeline {
    clients: HashMap<[u8; 6], VecDeque<Entry>>,
    total: usize,
}

impl Timeline {
    /// The entries kept, as saved.
    pub fn from_saved(saved: Vec<([u8; 6], Vec<Entry>)>) -> Self {
        let mut t = Timeline::default();
        for (mac, entries) in saved {
            t.total += entries.len();
            t.clients.insert(mac, entries.into());
        }
        t
    }

    /// The entries as saved, by client.
    pub fn saved(&self) -> Vec<([u8; 6], Vec<Entry>)> {
        let all = self.clients.iter();
        all.map(|(m, e)| (*m, e.iter().cloned().collect()))
            .collect()
    }

    /// Adds `entry` of `mac` in its place by time (after the entries of the
    /// same time), dropping the client's oldest past [`PER_CLIENT`], and the
    /// oldest of all when the total runs well past [`TOTAL`].
    pub fn push(&mut self, mac: [u8; 6], entry: Entry) {
        let list = self.clients.entry(mac).or_default();
        let at = list.partition_point(|e| e.at_ms <= entry.at_ms);
        list.insert(at, entry);
        self.total += 1;
        if list.len() > PER_CLIENT {
            list.pop_front();
            self.total -= 1;
        }
        if self.total > TOTAL + TOTAL / 10 {
            self.cap();
        }
    }

    /// Changes, or drops (`edit` returning false), the newest entry of `mac`
    /// that `pick` picks; whether there was one.
    pub fn edit(
        &mut self,
        mac: &[u8; 6],
        pick: impl Fn(&What) -> bool,
        edit: impl FnOnce(&mut What) -> bool,
    ) -> bool {
        let Some(list) = self.clients.get_mut(mac) else {
            return false;
        };
        let Some(i) = list.iter().rposition(|e| pick(&e.what)) else {
            return false;
        };
        if !edit(&mut list[i].what) {
            list.remove(i);
            self.total -= 1;
        }
        true
    }

    /// The entries of `mac`, oldest first.
    pub fn of(&self, mac: &[u8; 6]) -> impl DoubleEndedIterator<Item = &Entry> {
        self.clients.get(mac).into_iter().flatten()
    }

    /// Whether `mac` holds an entry equal to `entry`.
    pub fn holds(&self, mac: &[u8; 6], entry: &Entry) -> bool {
        let Some(list) = self.clients.get(mac) else {
            return false;
        };
        let from = list.partition_point(|e| e.at_ms < entry.at_ms);
        let same_time = list.range(from..).take_while(|e| e.at_ms == entry.at_ms);
        same_time.into_iter().any(|e| e == entry)
    }

    /// When the newest entry `pick` picks happened, over every client.
    pub fn newest(&self, pick: impl Fn(&What) -> bool) -> Option<u64> {
        let all = self
            .clients
            .values()
            .flat_map(|l| l.iter().rev().find(|e| pick(&e.what)));
        all.map(|e| e.at_ms).max()
    }

    /// Whether anything of `mac` is kept.
    pub fn knows(&self, mac: &[u8; 6]) -> bool {
        self.clients.contains_key(mac)
    }

    /// Every client with entries, and its entries.
    pub fn clients(&self) -> impl Iterator<Item = (&[u8; 6], &VecDeque<Entry>)> {
        self.clients.iter()
    }

    /// Entries kept over every client.
    pub fn total(&self) -> usize {
        self.total
    }

    /// Drops what is older than [`KEEP_MS`] before `now_ms`, and the oldest
    /// entries over [`TOTAL`].
    pub fn prune(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(KEEP_MS);
        let mut dropped = 0;
        self.clients.retain(|_, list| {
            let old = list.partition_point(|e| e.at_ms < cutoff);
            list.drain(..old);
            dropped += old;
            !list.is_empty()
        });
        self.total -= dropped;
        self.cap();
    }

    /// Drops the oldest entries over every client until [`TOTAL`] are left.
    fn cap(&mut self) {
        let Some(excess) = self.total.checked_sub(TOTAL).filter(|&n| n > 0) else {
            return;
        };
        let mut times: Vec<u64> = self
            .clients
            .values()
            .flat_map(|l| l.iter().map(|e| e.at_ms))
            .collect();
        let (_, &mut cutoff, _) = times.select_nth_unstable(excess - 1);
        // Entries older than the cutoff go, then as many of its time as are
        // still to go.
        let mut left = excess;
        for list in self.clients.values_mut() {
            let old = list.partition_point(|e| e.at_ms < cutoff);
            list.drain(..old);
            left -= old;
        }
        for list in self.clients.values_mut() {
            while left > 0 && list.front().is_some_and(|e| e.at_ms == cutoff) {
                list.pop_front();
                left -= 1;
            }
        }
        self.clients.retain(|_, l| !l.is_empty());
        self.total = TOTAL;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease(at_ms: u64) -> Entry {
        Entry {
            at_ms,
            what: What::Lease {
                ip: "192.0.2.10".parse().unwrap(),
                expires: at_ms / 1000 + 3600,
                renewed: false,
            },
        }
    }

    fn mac(n: u16) -> [u8; 6] {
        [2, 0, 0, 0, (n >> 8) as u8, n as u8]
    }

    #[test]
    fn entries_keep_their_order_by_time() {
        let mut t = Timeline::default();
        for at in [30, 10, 20, 20, 40] {
            t.push(mac(1), lease(at));
        }
        let times: Vec<u64> = t.of(&mac(1)).map(|e| e.at_ms).collect();
        assert_eq!(times, [10, 20, 20, 30, 40]);
        assert_eq!(t.total(), 5);
    }

    #[test]
    fn a_client_keeps_its_newest_entries() {
        let mut t = Timeline::default();
        for at in 0..PER_CLIENT as u64 + 10 {
            t.push(mac(1), lease(at));
        }
        assert_eq!(t.total(), PER_CLIENT);
        assert_eq!(t.of(&mac(1)).next().unwrap().at_ms, 10);
    }

    #[test]
    fn a_week_is_kept_and_the_oldest_of_all_go_past_the_total() {
        let mut t = Timeline::default();
        let now = KEEP_MS + 1_000_000;
        t.push(mac(1), lease(now - KEEP_MS - 1));
        t.push(mac(1), lease(now - KEEP_MS));
        t.prune(now);
        assert_eq!(t.total(), 1);
        // 120 clients of 1000 entries each, every client's times interleaved.
        let mut t = Timeline::default();
        for i in 0..1000u64 {
            for c in 0..120 {
                t.push(mac(c), lease(now - 1000 + i));
            }
            assert!(t.total() <= TOTAL + TOTAL / 10);
        }
        t.prune(now);
        assert_eq!(t.total(), TOTAL);
        let counted: usize = t.clients().map(|(_, l)| l.len()).sum();
        assert_eq!(counted, TOTAL);
        let oldest = t.clients().map(|(_, l)| l[0].at_ms).min().unwrap();
        assert!(oldest >= now - 1000 + 166, "{oldest}");
    }

    #[test]
    fn the_newest_picked_entry_is_edited_or_dropped() {
        let mut t = Timeline::default();
        t.push(mac(1), lease(1));
        t.push(mac(1), lease(2));
        let renew = |w: &mut What| {
            if let What::Lease { renewed, .. } = w {
                *renewed = true;
            }
            true
        };
        assert!(t.edit(&mac(1), |w| matches!(w, What::Lease { .. }), renew));
        let renewed: Vec<bool> = t
            .of(&mac(1))
            .map(|e| matches!(e.what, What::Lease { renewed: true, .. }))
            .collect();
        assert_eq!(renewed, [false, true]);
        assert!(t.edit(&mac(1), |_| true, |_| false));
        assert_eq!(t.total(), 1);
        assert!(!t.edit(&mac(9), |_| true, |_| false));
    }

    #[test]
    fn saved_and_restored_alike() {
        let mut t = Timeline::default();
        t.push(mac(1), lease(1));
        t.push(mac(2), lease(2));
        let back = Timeline::from_saved(t.saved());
        assert_eq!(back, t);
    }
}
