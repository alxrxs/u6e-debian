//! The MAC vendor table (`src/oui.rs`): the vendored `oui/manuf.tsv` (see
//! `oui/update.py`), compacted into `OUT_DIR/oui/`: per listing (MA-L, MA-M,
//! MA-S: 6, 7 and 9 hex digits) its prefixes, sorted, each with the index of
//! its organization's name (8 bytes, little endian: prefix << 16 | index),
//! and the names once each (`names.bin`, the end of each in `ends.bin`).
//! Nothing is downloaded and nothing written outside `OUT_DIR`.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// The digits of each listing's prefixes, and its output.
const LISTINGS: [(usize, &str); 3] = [(6, "ma-l.bin"), (7, "ma-m.bin"), (9, "ma-s.bin")];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=oui/manuf.tsv");
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("set by cargo"));
    let out = PathBuf::from(env::var("OUT_DIR").expect("set by cargo")).join("oui");
    fs::create_dir_all(&out).unwrap_or_else(|e| panic!("{}: {e}", out.display()));
    let source = manifest.join("oui/manuf.tsv");
    let text = fs::read_to_string(&source).unwrap_or_else(|e| panic!("{}: {e}", source.display()));
    let mut names = Names::default();
    let mut tables: HashMap<usize, Vec<u64>> = HashMap::new();
    for (n, line) in text
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.starts_with('#'))
    {
        let (prefix, name) = line
            .split_once('\t')
            .unwrap_or_else(|| panic!("manuf.tsv:{}: no tab", n + 1));
        let bits = u64::from_str_radix(prefix, 16)
            .ok()
            .filter(|_| LISTINGS.iter().any(|(d, _)| *d == prefix.len()))
            .unwrap_or_else(|| panic!("manuf.tsv:{}: {prefix:?} is no prefix", n + 1));
        let entry = bits << 16 | u64::from(names.index(name));
        tables.entry(prefix.len()).or_default().push(entry);
    }
    for (digits, output) in LISTINGS {
        let mut entries = tables.remove(&digits).unwrap_or_default();
        entries.sort_unstable();
        entries.dedup_by_key(|e| *e >> 16);
        let bytes: Vec<u8> = entries.iter().flat_map(|e| e.to_le_bytes()).collect();
        write(&out.join(output), &bytes);
    }
    write(&out.join("names.bin"), names.text.as_bytes());
    let ends: Vec<u8> = names.ends.iter().flat_map(|e| e.to_le_bytes()).collect();
    write(&out.join("ends.bin"), &ends);
}

fn write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
}

/// The organizations' names, each once: the text, and where each one ends.
#[derive(Default)]
struct Names {
    text: String,
    ends: Vec<u32>,
    seen: HashMap<String, u16>,
}

impl Names {
    fn index(&mut self, name: &str) -> u16 {
        if let Some(&i) = self.seen.get(name) {
            return i;
        }
        let i = u16::try_from(self.ends.len()).expect("fewer than 65536 organizations");
        self.text.push_str(name);
        self.ends
            .push(u32::try_from(self.text.len()).expect("names under 4 GiB"));
        self.seen.insert(name.to_owned(), i);
        i
    }
}
