//! The bindings: which IPv4 addresses each MAC holds. An address is bound by
//! a DHCP acknowledgement of the site's server seen on the AP (for the
//! lease's length, counted on the boot clock: the AP has no RTC, and its
//! wall clock jumps when it is first synchronized), by the controller's seed
//! of the DHCP servers' leases (until their expiry, on the wall clock the
//! controller stated them in; each seed replaces the one before), or
//! statically. A client's release or decline unbinds what was learnt or
//! seeded. The table counts its changes, so a reader can tell when to look
//! again.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use u6e_proto::msg::Binding;

/// Now, on both clocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Clock {
    /// Unix milliseconds.
    pub wall_ms: u64,
    /// Milliseconds since boot, suspended time included.
    pub boot_ms: u64,
}

impl Clock {
    pub fn now() -> Self {
        let wall_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        // SAFETY: a zeroed timespec is a valid one for clock_gettime to fill.
        let mut t: libc::timespec = unsafe { std::mem::zeroed() };
        // SAFETY: `t` is a valid timespec.
        unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut t) };
        let boot_ms = t.tv_sec as u64 * 1000 + t.tv_nsec as u64 / 1_000_000;
        Clock { wall_ms, boot_ms }
    }
}

/// What binds one address to one MAC; it holds while any part does.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Held {
    /// Until when an acknowledgement seen here binds it (boot clock).
    learned: Option<u64>,
    /// Until when the seed binds it (wall clock).
    seeded: Option<u64>,
    fixed: bool,
}

impl Held {
    fn holds(&self, now: Clock) -> bool {
        self.fixed
            || self.learned.is_some_and(|u| u > now.boot_ms)
            || self.seeded.is_some_and(|u| u > now.wall_ms)
    }

    /// Until when it holds, on the wall clock; `None` for good.
    fn until(&self, now: Clock) -> Option<u64> {
        if self.fixed {
            return None;
        }
        let learned = self
            .learned
            .map(|u| now.wall_ms + u.saturating_sub(now.boot_ms));
        Some(learned.max(self.seeded).unwrap_or(0))
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

type Table = BTreeMap<([u8; 6], Ipv4Addr), Held>;

impl Bindings {
    /// Applies `change` and counts it if the bindings in force changed.
    fn change(&mut self, now: Clock, change: impl FnOnce(&mut Table)) {
        let before = self.list(now);
        change(&mut self.held);
        self.held.retain(|_, h| !h.empty());
        if self.list(now) != before {
            self.generation += 1;
        }
    }

    /// An acknowledgement of `ip` for `mac`, for `lease_ms`.
    pub fn learn(&mut self, mac: [u8; 6], ip: Ipv4Addr, lease_ms: u64, now: Clock) {
        self.change(now, |held| {
            let h = held.entry((mac, ip)).or_default();
            h.learned = h.learned.max(Some(now.boot_ms.saturating_add(lease_ms)));
        });
    }

    /// The client gave `ip` back: neither the seed nor what was seen here
    /// binds it any longer.
    pub fn release(&mut self, mac: [u8; 6], ip: Ipv4Addr, now: Clock) {
        self.change(now, |held| {
            if let Some(h) = held.get_mut(&(mac, ip)) {
                h.learned = None;
                h.seeded = None;
            }
        });
    }

    /// The leases the controller seeds, in place of the last seed.
    pub fn seed(&mut self, leases: &[Binding], now: Clock) {
        self.change(now, |held| {
            held.values_mut().for_each(|h| h.seeded = None);
            for b in leases {
                let h = held.entry((b.mac, b.ip)).or_default();
                h.seeded = h.seeded.max(Some(b.expires_ms.unwrap_or(u64::MAX)));
            }
        });
    }

    /// The static bindings, in place of the ones before.
    pub fn statics(&mut self, fixed: &[Binding], now: Clock) {
        self.change(now, |held| {
            held.values_mut().for_each(|h| h.fixed = false);
            for b in fixed {
                held.entry((b.mac, b.ip)).or_default().fixed = true;
            }
        });
    }

    /// Forgets what expired by `now`.
    pub fn expire(&mut self, now: Clock) {
        let before = self.held.len();
        self.held.retain(|_, h| h.holds(now));
        if self.held.len() != before {
            self.generation += 1;
        }
    }

    pub fn bound(&self, mac: [u8; 6], ip: Ipv4Addr, now: Clock) -> bool {
        self.held.get(&(mac, ip)).is_some_and(|h| h.holds(now))
    }

    /// Whether `mac` holds any address.
    pub fn holds_any(&self, mac: [u8; 6], now: Clock) -> bool {
        let mine = self
            .held
            .range((mac, Ipv4Addr::UNSPECIFIED)..=(mac, Ipv4Addr::BROADCAST));
        mine.into_iter().any(|(_, h)| h.holds(now))
    }

    /// Another MAC `ip` is bound to, when it is not bound to `not` too: an
    /// address two MACs hold is either's.
    pub fn owner(&self, ip: Ipv4Addr, not: [u8; 6], now: Clock) -> Option<[u8; 6]> {
        if self.bound(not, ip, now) {
            return None;
        }
        let mut held = self.held.iter();
        held.find(|((_, i), h)| *i == ip && h.holds(now))
            .map(|((m, _), _)| *m)
    }

    /// The bindings in force, by MAC and address.
    pub fn list(&self, now: Clock) -> Vec<Binding> {
        let held = self.held.iter().filter(|(_, h)| h.holds(now));
        held.map(|((mac, ip), h)| Binding {
            mac: *mac,
            ip: *ip,
            expires_ms: h.until(now),
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

    /// A clock whose wall time is `wall` and boot time `boot`.
    fn at(wall_ms: u64, boot_ms: u64) -> Clock {
        Clock { wall_ms, boot_ms }
    }

    #[test]
    fn an_acknowledged_lease_binds_until_it_ends_or_is_released() {
        let mut t = Bindings::default();
        t.learn(A, ip(10), 1000, at(1000, 1000));
        assert_eq!(t.generation, 1);
        assert!(t.bound(A, ip(10), at(1999, 1999)) && !t.bound(A, ip(10), at(2000, 2000)));
        assert!(!t.bound(B, ip(10), at(1000, 1000)));
        assert_eq!(t.owner(ip(10), B, at(1000, 1000)), Some(A));
        assert_eq!(t.owner(ip(10), A, at(1000, 1000)), None);
        // A renewal moves the end; an older acknowledgement does not.
        t.learn(A, ip(10), 1500, at(1500, 1500));
        t.learn(A, ip(10), 1000, at(1500, 1500));
        assert_eq!(t.list(at(1500, 1500)), [binding(A, 10, Some(3000))]);
        assert_eq!(t.generation, 2);
        t.release(A, ip(10), at(1600, 1600));
        assert_eq!((t.list(at(1600, 1600)), t.generation), (vec![], 3));
    }

    #[test]
    fn a_learnt_lease_outlives_the_first_clock_synchronization() {
        let mut t = Bindings::default();
        // Booted at the image's build date, a day before the true time.
        t.learn(A, ip(10), 3_600_000, at(5_000, 5_000));
        let synced = at(86_400_000 + 6_000, 6_000);
        assert!(t.bound(A, ip(10), synced));
        assert_eq!(
            t.list(synced),
            [binding(A, 10, Some(86_400_000 + 3_605_000))]
        );
        t.expire(synced);
        assert_eq!(t.list(synced).len(), 1);
        assert!(!t.bound(A, ip(10), at(90_000_000, 3_605_000)));
    }

    #[test]
    fn seeds_replace_each_other_and_statics_hold_for_good() {
        let now = at(1000, 1000);
        let mut t = Bindings::default();
        t.learn(A, ip(10), 4000, now);
        t.seed(
            &[binding(A, 10, Some(9000)), binding(B, 11, Some(9000))],
            now,
        );
        assert_eq!(
            t.list(now),
            [binding(A, 10, Some(9000)), binding(B, 11, Some(9000))]
        );
        assert!(t.holds_any(B, now) && !t.holds_any([2, 0, 0, 0, 0, 3], now));
        // The next seed no longer has B's lease: it goes; A keeps what was
        // seen here.
        t.seed(&[], now);
        assert_eq!(t.list(now), [binding(A, 10, Some(5000))]);
        t.statics(&[binding(B, 20, None)], now);
        assert!(t.bound(B, ip(20), at(u64::MAX - 1, u64::MAX - 1)));
        t.expire(at(6000, 6000));
        assert_eq!(t.list(at(6000, 6000)), [binding(B, 20, None)]);
        // Released, a static address stays bound.
        t.release(B, ip(20), at(6000, 6000));
        assert!(t.bound(B, ip(20), at(6000, 6000)));
        t.statics(&[], at(6000, 6000));
        assert_eq!(t.list(at(6000, 6000)), []);
    }

    #[test]
    fn an_address_two_macs_hold_is_either_ones() {
        let now = at(1000, 1000);
        let mut t = Bindings::default();
        t.seed(
            &[binding(A, 10, Some(9000)), binding(B, 10, Some(9000))],
            now,
        );
        assert_eq!(t.owner(ip(10), A, now), None);
        assert_eq!(t.owner(ip(10), B, now), None);
        assert!(t.owner(ip(10), [2, 0, 0, 0, 0, 3], now).is_some());
    }

    #[test]
    fn only_changes_count() {
        let now = at(1000, 1000);
        let mut t = Bindings::default();
        t.seed(&[binding(A, 10, Some(9000))], now);
        t.seed(&[binding(A, 10, Some(9000))], now);
        t.release(B, ip(1), now);
        t.expire(now);
        assert_eq!(t.generation, 1);
    }
}
