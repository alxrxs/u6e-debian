//! The bindings: which IPv4 addresses each MAC may use. An address is bound
//! by a DHCP acknowledgement seen on the AP (until its lease ends, or the
//! client releases or declines it), by the controller's seed of the DHCP
//! servers' leases (each seed replacing the one before), or statically.
//! The table counts its changes, so a reader can tell when to look again.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use u6e_proto::msg::Binding;

/// What binds one address to one MAC; it holds while any part does.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Held {
    /// Until when an acknowledgement seen here, and the seed, bind it (Unix ms).
    learned: Option<u64>,
    seeded: Option<u64>,
    fixed: bool,
}

impl Held {
    /// Until when it holds; `None` for good, so it compares as `Some(MAX)`.
    fn until(&self) -> Option<u64> {
        (!self.fixed).then(|| self.learned.max(self.seeded).unwrap_or(0))
    }

    fn holds(&self, now_ms: u64) -> bool {
        self.until().is_none_or(|u| u > now_ms)
    }

    fn empty(&self) -> bool {
        *self == Held::default()
    }
}

#[derive(Debug, Default)]
pub struct Bindings {
    held: BTreeMap<([u8; 6], Ipv4Addr), Held>,
    /// Counts the changes to the table.
    pub generation: u64,
}

impl Bindings {
    /// Applies `change` and counts it if the bindings in force changed.
    fn change(
        &mut self,
        now_ms: u64,
        change: impl FnOnce(&mut BTreeMap<([u8; 6], Ipv4Addr), Held>),
    ) {
        let before = self.list(now_ms);
        change(&mut self.held);
        self.held.retain(|_, h| !h.empty());
        if self.list(now_ms) != before {
            self.generation += 1;
        }
    }

    /// An acknowledgement of `ip` for `mac` until `until_ms`.
    pub fn learn(&mut self, mac: [u8; 6], ip: Ipv4Addr, until_ms: u64, now_ms: u64) {
        self.change(now_ms, |held| {
            let h = held.entry((mac, ip)).or_default();
            h.learned = h.learned.max(Some(until_ms));
        });
    }

    /// The client gave `ip` back: neither the seed nor what was seen here
    /// binds it any longer.
    pub fn release(&mut self, mac: [u8; 6], ip: Ipv4Addr, now_ms: u64) {
        self.change(now_ms, |held| {
            if let Some(h) = held.get_mut(&(mac, ip)) {
                h.learned = None;
                h.seeded = None;
            }
        });
    }

    /// The leases the controller seeds, in place of the last seed.
    pub fn seed(&mut self, leases: &[Binding], now_ms: u64) {
        self.change(now_ms, |held| {
            held.values_mut().for_each(|h| h.seeded = None);
            for b in leases {
                let h = held.entry((b.mac, b.ip)).or_default();
                h.seeded = h.seeded.max(Some(b.expires_ms.unwrap_or(u64::MAX)));
            }
        });
    }

    /// The static bindings, in place of the ones before.
    pub fn statics(&mut self, fixed: &[Binding], now_ms: u64) {
        self.change(now_ms, |held| {
            held.values_mut().for_each(|h| h.fixed = false);
            for b in fixed {
                held.entry((b.mac, b.ip)).or_default().fixed = true;
            }
        });
    }

    /// Forgets what expired by `now_ms`.
    pub fn expire(&mut self, now_ms: u64) {
        let before = self.held.len();
        self.held.retain(|_, h| h.holds(now_ms));
        if self.held.len() != before {
            self.generation += 1;
        }
    }

    pub fn bound(&self, mac: [u8; 6], ip: Ipv4Addr, now_ms: u64) -> bool {
        self.held.get(&(mac, ip)).is_some_and(|h| h.holds(now_ms))
    }

    /// Another MAC `ip` is bound to, if any.
    pub fn owner(&self, ip: Ipv4Addr, not: [u8; 6], now_ms: u64) -> Option<[u8; 6]> {
        let mut held = self.held.iter();
        held.find(|((m, i), h)| *i == ip && *m != not && h.holds(now_ms))
            .map(|((m, _), _)| *m)
    }

    /// The bindings in force, by MAC and address.
    pub fn list(&self, now_ms: u64) -> Vec<Binding> {
        let held = self.held.iter().filter(|(_, h)| h.holds(now_ms));
        held.map(|((mac, ip), h)| Binding {
            mac: *mac,
            ip: *ip,
            expires_ms: h.until(),
        })
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const B: [u8; 6] = [2, 0, 0, 0, 0, 2];

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, last)
    }

    fn binding(mac: [u8; 6], last: u8, expires_ms: Option<u64>) -> Binding {
        Binding {
            mac,
            ip: ip(last),
            expires_ms,
        }
    }

    #[test]
    fn an_acknowledged_lease_binds_until_it_ends_or_is_released() {
        let mut t = Bindings::default();
        t.learn(A, ip(10), 2000, 1000);
        assert_eq!(t.generation, 1);
        assert!(t.bound(A, ip(10), 1999) && !t.bound(A, ip(10), 2000));
        assert!(!t.bound(B, ip(10), 1000));
        assert_eq!(t.owner(ip(10), B, 1000), Some(A));
        assert_eq!(t.owner(ip(10), A, 1000), None);
        // A renewal moves the end; an older acknowledgement does not.
        t.learn(A, ip(10), 3000, 1500);
        t.learn(A, ip(10), 2500, 1500);
        assert_eq!(t.list(1500), [binding(A, 10, Some(3000))]);
        assert_eq!(t.generation, 2);
        t.release(A, ip(10), 1600);
        assert_eq!((t.list(1600), t.generation), (vec![], 3));
    }

    #[test]
    fn seeds_replace_each_other_and_statics_hold_for_good() {
        let mut t = Bindings::default();
        t.learn(A, ip(10), 5000, 1000);
        t.seed(
            &[binding(A, 10, Some(9000)), binding(B, 11, Some(9000))],
            1000,
        );
        assert_eq!(
            t.list(1000),
            [binding(A, 10, Some(9000)), binding(B, 11, Some(9000))]
        );
        // The next seed no longer has B's lease: it goes; A keeps what was
        // seen here.
        t.seed(&[], 1000);
        assert_eq!(t.list(1000), [binding(A, 10, Some(5000))]);
        t.statics(&[binding(B, 20, None)], 1000);
        assert!(t.bound(B, ip(20), u64::MAX - 1));
        t.expire(6000);
        assert_eq!(t.list(6000), [binding(B, 20, None)]);
        // Released, a static address stays bound.
        t.release(B, ip(20), 6000);
        assert!(t.bound(B, ip(20), 6000));
        t.statics(&[], 6000);
        assert_eq!(t.list(6000), []);
    }

    #[test]
    fn only_changes_count() {
        let mut t = Bindings::default();
        t.seed(&[binding(A, 10, Some(9000))], 1000);
        t.seed(&[binding(A, 10, Some(9000))], 1000);
        t.release(B, ip(1), 1000);
        t.expire(1000);
        assert_eq!(t.generation, 1);
    }
}
