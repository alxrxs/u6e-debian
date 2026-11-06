//! A MAC's vendor, from the IEEE registry as Wireshark compiles it (the
//! vendored `oui/manuf.tsv`), compacted into the binary at build time
//! (`build.rs`): the organization its address block was assigned to, the
//! narrowest of the MA-S (36-bit), MA-M (28-bit) and MA-L (24-bit) blocks it
//! falls in. A locally administered address, which phones and laptops make
//! up per network to stay private, has no vendor; nor has one in a block the
//! registry split up and has not assigned.

const MA_L: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/oui/ma-l.bin"));
const MA_M: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/oui/ma-m.bin"));
const MA_S: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/oui/ma-s.bin"));
const NAMES: &str = include_str!(concat!(env!("OUT_DIR"), "/oui/names.bin"));
const ENDS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/oui/ends.bin"));

/// What a MAC says of who made it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vendor {
    /// A locally administered address: made up, not assigned.
    Private,
    /// The organization the block is assigned to.
    Assigned(&'static str),
}

/// The vendor of `mac`, when the registry names one. Blocks whose assignee
/// asked to stay unnamed ("Private") name none.
pub fn vendor(mac: &[u8; 6]) -> Option<Vendor> {
    if mac[0] & 0x02 != 0 {
        return Some(Vendor::Private);
    }
    let bits = mac.iter().fold(0u64, |a, &b| a << 8 | u64::from(b));
    let index = [(MA_S, 12), (MA_M, 20), (MA_L, 24)]
        .into_iter()
        .find_map(|(table, shift)| find(table, bits >> shift))?;
    Some(name(index))
        .filter(|n| *n != "Private")
        .map(Vendor::Assigned)
}

/// The name index of `prefix` in a table of sorted entries.
fn find(table: &[u8], prefix: u64) -> Option<usize> {
    let entry = |i: usize| {
        let bytes = table[i * 8..i * 8 + 8].try_into().expect("8 bytes");
        u64::from_le_bytes(bytes)
    };
    let (mut lo, mut hi) = (0, table.len() / 8);
    while lo < hi {
        let mid = (lo + hi) / 2;
        let e = entry(mid);
        match (e >> 16).cmp(&prefix) {
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
            std::cmp::Ordering::Equal => return Some((e & 0xffff) as usize),
        }
    }
    None
}

fn end(i: usize) -> usize {
    let bytes = ENDS[i * 4..i * 4 + 4].try_into().expect("4 bytes");
    u32::from_le_bytes(bytes) as usize
}

fn name(i: usize) -> &'static str {
    let start = if i == 0 { 0 } else { end(i - 1) };
    &NAMES[start..end(i)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_narrowest_block_names_the_vendor() {
        // MA-L.
        assert_eq!(
            vendor(&[0x00, 0x00, 0x0c, 0x12, 0x34, 0x56]),
            Some(Vendor::Assigned("Cisco Systems, Inc"))
        );
        // MA-S, inside an MA-L block the registry itself holds.
        assert_eq!(
            vendor(&[0x8c, 0x1f, 0x64, 0xaf, 0xa0, 0x01]),
            Some(Vendor::Assigned("Data Electronic Devices, Inc"))
        );
        // Outside every MA-S block of it: not assigned.
        assert_eq!(vendor(&[0x8c, 0x1f, 0x64, 0xff, 0xf0, 0x01]), None);
        // MA-M.
        assert_eq!(
            vendor(&[0xc8, 0x5c, 0xe2, 0x70, 0x00, 0x01]),
            Some(Vendor::Assigned("Synergy Systems And Solutions"))
        );
    }

    #[test]
    fn made_up_and_unnamed_addresses_have_no_vendor() {
        assert_eq!(vendor(&[0x02, 0, 0, 0, 0, 1]), Some(Vendor::Private));
        assert_eq!(vendor(&[0xa2, 0xad, 0x51, 0, 0, 1]), Some(Vendor::Private));
        // An MA-M block assigned as "Private".
        assert_eq!(vendor(&[0x74, 0x1a, 0xe0, 0x90, 0x00, 0x01]), None);
    }

    #[test]
    fn every_entry_names_a_name() {
        let names = ENDS.len() / 4;
        for table in [MA_L, MA_M, MA_S] {
            assert_eq!(table.len() % 8, 0);
            assert!(table.len() / 8 > 1000);
            let mut last = None;
            for chunk in table.chunks(8) {
                let e = u64::from_le_bytes(chunk.try_into().unwrap());
                assert!(((e & 0xffff) as usize) < names);
                assert!(last < Some(e >> 16), "sorted, once each");
                last = Some(e >> 16);
            }
        }
        assert!((0..names).all(|i| !name(i).is_empty()));
    }
}
