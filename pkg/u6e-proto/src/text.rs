//! Text an AP reports that a person reads: an identity a client typed, an
//! SSID, a guard's detail. Control characters and Unicode format characters
//! (general category Cf: the bidirectional overrides and isolates, zero-width
//! spaces and joiners, the byte order mark, the tag characters) are dropped,
//! so no string can reorder or hide what is shown around it. A byte count in
//! such text is written as the UI writes one (`bytes`).

/// The Unicode format characters (general category Cf), as ranges.
const FORMAT: [(u32, u32); 21] = [
    (0x00AD, 0x00AD),
    (0x0600, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
];

/// Whether `c` is a Unicode format character.
pub fn is_format(c: char) -> bool {
    let c = u32::from(c);
    FORMAT.iter().any(|&(lo, hi)| (lo..=hi).contains(&c))
}

/// `s` without control and format characters.
pub fn clean(s: &str) -> String {
    s.chars()
        .filter(|&c| !c.is_control() && !is_format(c))
        .collect()
}

/// `s` cleaned in place, its line breaks kept (an image's manifest).
pub fn clean_lines(s: &mut String) {
    if s.chars()
        .any(|c| (c.is_control() && c != '\n') || is_format(c))
    {
        *s = s
            .chars()
            .filter(|&c| c == '\n' || !(c.is_control() || is_format(c)))
            .collect();
    }
}

/// `s` cleaned in place.
pub fn clean_in_place(s: &mut String) {
    if s.chars().any(|c| c.is_control() || is_format(c)) {
        *s = clean(s);
    }
}

/// `n` bytes as the UI writes them: SI units, one decimal under 10 of
/// one past bytes (`3.1 MB`, `218 kB`, `30 B`).
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];
    let (mut v, mut i) = (n as f64, 0);
    while v >= 1000.0 && i < UNITS.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    if i > 0 && v < 10.0 {
        format!("{v:.1} {}", UNITS[i])
    } else {
        format!("{} {}", v.round(), UNITS[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_read_as_the_ui_writes_them() {
        assert_eq!(bytes(30), "30 B");
        assert_eq!(bytes(218_034), "218 kB");
        assert_eq!(bytes(3_145_728), "3.1 MB");
        assert_eq!(bytes(250_000_000), "250 MB");
        assert_eq!(bytes(1_000), "1.0 kB");
    }

    #[test]
    fn controls_and_format_characters_go() {
        // A right-to-left override, a zero-width joiner and space, a BOM, a
        // tag character, a bell and a newline.
        let s = "host/\u{202E}evil\u{200D}\u{200B}\u{FEFF}\u{E0041}pc\u{7}\n1";
        assert_eq!(clean(s), "host/evilpc1");
        let mut m = "image: x\u{2066}\nkernel: y\u{1b}".to_owned();
        clean_lines(&mut m);
        assert_eq!(m, "image: x\nkernel: y");
        // Letters of every script stay.
        assert_eq!(clean("Ștefan-ﺭ-日本-é"), "Ștefan-ﺭ-日本-é");
    }
}
