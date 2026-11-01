//! The MAC vendor table (`src/oui.rs`): the IEEE registry's three public
//! listings, MA-L (24-bit prefixes), MA-M (28-bit) and MA-S (36-bit), fetched
//! from the Internet Archive's copy of each at a fixed date (the registry's
//! own files change every day), checked against the sha256 pinned here,
//! kept in the workspace's `dl/ieee/`, and compacted into `OUT_DIR/oui/`:
//! per listing its prefixes, sorted, each with the index of its
//! organization's name (8 bytes, little endian: prefix << 16 | index), and
//! the names once each (`names.bin`, the end of each in `ends.bin`).

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The listings: file, the archived copy, its sha256, and the digits a
/// prefix has.
const LISTINGS: [(&str, &str, &str, usize); 3] = [
    (
        "oui.csv",
        "https://web.archive.org/web/20260925150909id_/https://standards-oui.ieee.org/oui/oui.csv",
        "7eb144b4917bf1da2e1af1df1e5a49e74b6f18fe57e03922e1df4de4fc2d30f8",
        6,
    ),
    (
        "mam.csv",
        "https://web.archive.org/web/20241216143244id_/https://standards-oui.ieee.org/oui28/mam.csv",
        "7347a1ff9eb9803fefca6c8c3a2945933cc2b36c849839064e009eeb3b36e00c",
        7,
    ),
    (
        "oui36.csv",
        "https://web.archive.org/web/20260317202402id_/https://standards-oui.ieee.org/oui36/oui36.csv",
        "1a22d0ad2a6f0193f259bfe6889d60774a90e18c5ae3701cd7e54bd154298c27",
        9,
    ),
];

/// The outputs, one per listing, in the order of `LISTINGS`.
const OUTPUTS: [&str; 3] = ["ma-l.bin", "ma-m.bin", "ma-s.bin"];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("set by cargo"));
    let cache = manifest.join("../../dl/ieee");
    let out = PathBuf::from(env::var("OUT_DIR").expect("set by cargo")).join("oui");
    fs::create_dir_all(&cache).unwrap_or_else(|e| panic!("{}: {e}", cache.display()));
    fs::create_dir_all(&out).unwrap_or_else(|e| panic!("{}: {e}", out.display()));
    let mut names = Names::default();
    for ((file, url, sha256, digits), output) in LISTINGS.iter().zip(OUTPUTS) {
        let path = cache.join(file);
        fetch(&path, url, sha256);
        let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{file}: {e}"));
        let mut entries = Vec::new();
        for (n, row) in records(&text).into_iter().enumerate().skip(1) {
            let [_, assignment, organization, ..] = row.as_slice() else {
                panic!("{file}: record {n} has too few fields");
            };
            let prefix = u64::from_str_radix(assignment, 16)
                .ok()
                .filter(|_| assignment.len() == *digits)
                .unwrap_or_else(|| panic!("{file}: record {n}: {assignment:?} is no prefix"));
            entries.push(prefix << 16 | u64::from(names.index(organization)));
        }
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

/// Makes `path` the file at `url` whose sha256 is `sha256`, downloading it
/// unless it is there already.
fn fetch(path: &Path, url: &str, sha256: &str) {
    if digest(path).as_deref() == Some(sha256) {
        return;
    }
    let part = path.with_extension("part");
    let ok = Command::new("curl")
        .args(["-fsSL", "--retry", "3", "-o"])
        .arg(&part)
        .arg(url)
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "{url}: the download failed (curl)");
    let got = digest(&part);
    assert!(
        got.as_deref() == Some(sha256),
        "{url}: sha256 {got:?}, pinned {sha256}"
    );
    fs::rename(&part, path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
}

/// The sha256 of the file at `path`, by coreutils' sha256sum.
fn digest(path: &Path) -> Option<String> {
    if !path.exists() {
        return None;
    }
    let out = Command::new("sha256sum").arg(path).output().ok()?;
    let text = String::from_utf8(out.stdout).ok()?;
    out.status
        .success()
        .then(|| text.split_whitespace().next().map(str::to_owned))?
}

/// The organizations' names, each once: the text, and where each one ends.
#[derive(Default)]
struct Names {
    text: String,
    ends: Vec<u32>,
    seen: HashMap<String, u16>,
}

impl Names {
    /// The index of `name`, tidied to one line of printable text.
    fn index(&mut self, name: &str) -> u16 {
        let words: Vec<&str> = name
            .split(|c: char| c.is_whitespace() || c.is_control())
            .collect();
        let name = words
            .into_iter()
            .filter(|w| !w.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        if let Some(&i) = self.seen.get(&name) {
            return i;
        }
        let i = u16::try_from(self.ends.len()).expect("fewer than 65536 organizations");
        self.text.push_str(&name);
        self.ends
            .push(u32::try_from(self.text.len()).expect("names under 4 GiB"));
        self.seen.insert(name, i);
        i
    }
}

/// The records of a CSV text (RFC 4180: quoted fields may hold commas,
/// line breaks and doubled quotes).
fn records(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') if chars.peek() == Some(&'"') => {
                chars.next();
                field.push('"');
            }
            (true, '"') => quoted = false,
            (true, c) => field.push(c),
            (false, '"') => quoted = true,
            (false, ',') => row.push(std::mem::take(&mut field)),
            (false, '\r') => {}
            (false, '\n') => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            (false, c) => field.push(c),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}
