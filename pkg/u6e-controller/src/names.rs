//! Client names: the reverse DNS of the addresses a client's flows show it
//! at, through the system resolver, so a client is named by whatever its
//! address is registered under (a DHCP server's PTR, typically) with no data
//! source of the controller's own.
//!
//! Each address is looked up at most once at a time. A name found is kept for
//! [`FOUND_TTL`], the lack of one for [`MISSING_TTL`]; past that the next flows
//! that show the address look it up again, and the old name is shown until
//! the answer comes.

use std::collections::{BTreeMap, HashMap};
use std::ffi::CStr;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;
use u6e_proto::msg::Flow;

pub const FOUND_TTL: Duration = Duration::from_secs(600);
pub const MISSING_TTL: Duration = Duration::from_secs(120);
/// Lookups at once: a resolver that does not answer holds each for seconds.
const LOOKUPS: usize = 8;
/// The longest a DNS name is.
const NAME_MAX: usize = 253;

/// A reverse lookup; it blocks, and is run off the async workers.
pub trait Resolve: Send + Sync + 'static {
    fn reverse(&self, ip: IpAddr) -> Option<String>;
}

/// The C library's resolver (`getnameinfo`): `/etc/hosts`, then the DNS
/// servers of `/etc/resolv.conf`.
pub struct System;

impl Resolve for System {
    fn reverse(&self, ip: IpAddr) -> Option<String> {
        // SAFETY: both are plain C structs, valid when zeroed.
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let len = match ip {
            IpAddr::V4(v4) => {
                let sa = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: 0,
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(v4.octets()),
                    },
                    // SAFETY: as above.
                    ..unsafe { std::mem::zeroed() }
                };
                // SAFETY: sockaddr_storage is larger than any sockaddr.
                unsafe { std::ptr::write((&raw mut storage).cast(), sa) };
                size_of::<libc::sockaddr_in>()
            }
            IpAddr::V6(v6) => {
                let sa = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_addr: libc::in6_addr {
                        s6_addr: v6.octets(),
                    },
                    // SAFETY: as above.
                    ..unsafe { std::mem::zeroed() }
                };
                // SAFETY: as above.
                unsafe { std::ptr::write((&raw mut storage).cast(), sa) };
                size_of::<libc::sockaddr_in6>()
            }
        };
        let mut host = [0 as libc::c_char; 1025];
        // SAFETY: the address is `len` initialized bytes, the buffer's length
        // is passed with it, and NI_NAMEREQD makes a missing name an error
        // rather than the address spelled out.
        let r = unsafe {
            libc::getnameinfo(
                (&raw const storage).cast(),
                len as libc::socklen_t,
                host.as_mut_ptr(),
                host.len() as libc::socklen_t,
                std::ptr::null_mut(),
                0,
                libc::NI_NAMEREQD,
            )
        };
        if r != 0 {
            return None;
        }
        // SAFETY: getnameinfo wrote a terminated string into the buffer.
        let name = unsafe { CStr::from_ptr(host.as_ptr()) };
        clean(name.to_str().ok()?)
    }
}

/// `name` without its root dot, if it is a host name. A client may register
/// whatever it likes, so nothing else is shown.
fn clean(name: &str) -> Option<String> {
    let name = name.strip_suffix('.').unwrap_or(name);
    let ok = |c: char| c.is_ascii_alphanumeric() || "-_.".contains(c);
    (!name.is_empty() && name.len() <= NAME_MAX && name.chars().all(ok)).then(|| name.to_owned())
}

/// What is known of one address.
struct Entry {
    /// The name last found; kept while a newer lookup is out.
    name: Option<String>,
    /// When the answer is stale.
    until: Instant,
    pending: bool,
}

/// The names of the addresses seen.
#[derive(Default)]
pub struct Names {
    entries: HashMap<IpAddr, Entry>,
}

impl Names {
    /// The addresses of `wanted` to look up now, marked as in flight: those
    /// never looked up and those whose answer is stale, unless a lookup is
    /// out already.
    pub fn due(&mut self, wanted: impl IntoIterator<Item = IpAddr>, now: Instant) -> Vec<IpAddr> {
        let mut out = Vec::new();
        for ip in wanted {
            let e = self.entries.entry(ip).or_insert(Entry {
                name: None,
                until: now,
                pending: false,
            });
            if !e.pending && e.until <= now {
                e.pending = true;
                out.push(ip);
            }
        }
        out
    }

    /// Takes the answer of a lookup of `ip`; true when its name changed.
    pub fn answer(&mut self, ip: IpAddr, name: Option<String>, now: Instant) -> bool {
        let ttl = if name.is_some() {
            FOUND_TTL
        } else {
            MISSING_TTL
        };
        let e = self.entries.entry(ip).or_insert(Entry {
            name: None,
            until: now,
            pending: true,
        });
        e.pending = false;
        e.until = now + ttl;
        let changed = e.name != name;
        e.name = name;
        changed
    }

    pub fn get(&self, ip: &IpAddr) -> Option<&str> {
        self.entries.get(ip)?.name.as_deref()
    }

    /// Forgets the addresses no flow has shown for a while.
    pub fn prune(&mut self, now: Instant) {
        self.entries
            .retain(|_, e| e.pending || e.until + FOUND_TTL > now);
    }
}

/// Runs lookups, a few at a time, through one resolver.
#[derive(Clone)]
pub struct Lookups {
    pub resolver: Arc<dyn Resolve>,
    permits: Arc<Semaphore>,
}

impl Lookups {
    pub fn new(resolver: Arc<dyn Resolve>) -> Self {
        Lookups {
            resolver,
            permits: Arc::new(Semaphore::new(LOOKUPS)),
        }
    }

    /// The name of `ip`, looked up on a blocking thread when a permit is free.
    pub async fn reverse(&self, ip: IpAddr) -> Option<String> {
        let _permit = self.permits.acquire().await.ok()?;
        let resolver = Arc::clone(&self.resolver);
        tokio::task::spawn_blocking(move || resolver.reverse(ip))
            .await
            .ok()
            .flatten()
    }
}

/// A client's own addresses as its flows show them (the end each flow says
/// is the client's), the one in most flows first.
pub fn addresses(flows: &[Flow]) -> Vec<IpAddr> {
    let mut seen: BTreeMap<IpAddr, usize> = BTreeMap::new();
    for f in flows {
        let own = if f.client_is_src { f.src } else { f.dst };
        *seen.entry(own).or_default() += 1;
    }
    let mut by_use: Vec<_> = seen.into_iter().collect();
    // Stable: equal counts keep the lowest address first.
    by_use.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    by_use.into_iter().map(|(ip, _)| ip).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn flow(src: &str, dst: &str, client_is_src: bool) -> Flow {
        Flow {
            proto: 6,
            src: ip(src),
            sport: 50000,
            dst: ip(dst),
            dport: 443,
            tx_bytes: 0,
            rx_bytes: 0,
            tx_packets: 0,
            rx_packets: 0,
            offloaded: false,
            age_s: 0,
            client_is_src,
        }
    }

    #[test]
    fn a_clients_addresses_are_its_own_ends() {
        let flows = [
            flow("192.0.2.10", "198.51.100.1", true),
            flow("2001:db8::10", "2001:db8:1::1", true),
            flow("192.0.2.10", "198.51.100.2", true),
            // Opened from outside: the client is the far end, never the opener.
            flow("198.51.100.3", "2001:db8::20", false),
            flow("198.51.100.3", "2001:db8::20", false),
            flow("198.51.100.3", "2001:db8::20", false),
        ];
        assert_eq!(
            addresses(&flows),
            [ip("2001:db8::20"), ip("192.0.2.10"), ip("2001:db8::10")]
        );
        assert_eq!(addresses(&[]), Vec::<IpAddr>::new());
    }

    #[test]
    fn lookups_are_one_at_a_time_and_cached() {
        let mut n = Names::default();
        let t0 = Instant::now();
        let (a, b) = (ip("192.0.2.1"), ip("192.0.2.2"));
        assert_eq!(n.due([a, b], t0), [a, b]);
        // In flight: not asked again.
        assert!(n.due([a, b], t0).is_empty());
        assert!(n.answer(a, Some("host-a.example".into()), t0));
        assert!(!n.answer(b, None, t0));
        assert_eq!((n.get(&a), n.get(&b)), (Some("host-a.example"), None));
        // The missing name is asked again after two minutes, the found one
        // after ten, and stays shown meanwhile.
        let later = |s| t0 + Duration::from_secs(s);
        assert!(n.due([a, b], later(119)).is_empty());
        assert_eq!(n.due([a, b], later(120)), [b]);
        assert!(n.due([a, b], later(599)).is_empty());
        assert_eq!(n.due([a, b], later(600)), [a]);
        assert_eq!(n.get(&a), Some("host-a.example"));
        assert!(!n.answer(a, Some("host-a.example".into()), later(600)));
        assert!(n.answer(a, Some("renamed.example".into()), later(600)));
        // Not seen for a while: forgotten, unless a lookup is out (b's
        // since 120 s, c's).
        let c = ip("192.0.2.3");
        assert_eq!(n.due([c], later(1500)), [c]);
        n.prune(later(2400));
        assert_eq!(n.get(&a), None);
        let mut kept: Vec<_> = n.entries.keys().copied().collect();
        kept.sort();
        assert_eq!(kept, [b, c]);
    }

    #[test]
    fn only_host_names_are_kept() {
        assert_eq!(clean("tab.lan.example."), Some("tab.lan.example".into()));
        assert_eq!(clean("esp_32-kitchen"), Some("esp_32-kitchen".into()));
        for bad in ["", ".", "a b", "<b>x</b>", "x\n", "é.example"] {
            assert_eq!(clean(bad), None, "{bad:?}");
        }
        assert_eq!(clean(&"a".repeat(254)), None);
    }

    #[test]
    fn the_system_resolver_reads_the_hosts_file() {
        // Every system names its loopback address in /etc/hosts.
        let name = System.reverse(ip("127.0.0.1"));
        assert!(name.is_some_and(|n| !n.is_empty()));
    }
}
