//! MAC addresses and the hex they are written in, parsed and formatted one
//! way for the agent and the controller alike.
//!
//! Parsing is strict: exactly the digits asked for, no sign, no padding, no
//! trailing text, so that what parses can be written into a command line (a
//! hostapd request, a log) without carrying anything else along.

/// The address of six colon-separated pairs of hex digits, in either case.
pub fn parse(s: &str) -> Option<[u8; 6]> {
    let mut out = [0; 6];
    let mut parts = s.split(':');
    for b in &mut out {
        *b = byte(parts.next()?.as_bytes())?;
    }
    parts.next().is_none().then_some(out)
}

/// The address as six lowercase pairs of hex digits joined by colons.
pub fn format(m: [u8; 6]) -> String {
    m.map(|b| format!("{b:02x}")).join(":")
}

/// The bytes as lowercase hex digits, two per byte.
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The `N` bytes of exactly `2 * N` hex digits, in either case.
pub fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let s = s.as_bytes();
    if s.len() != 2 * N {
        return None;
    }
    let mut out = [0; N];
    for (b, pair) in out.iter_mut().zip(s.chunks_exact(2)) {
        *b = byte(pair)?;
    }
    Some(out)
}

/// The byte of two hex digits; `u8::from_str_radix` would also take a sign.
fn byte(pair: &[u8]) -> Option<u8> {
    let digit = |c: u8| char::from(c).to_digit(16);
    match *pair {
        [hi, lo] => u8::try_from((digit(hi)? << 4) | digit(lo)?).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [0x02, 0, 0, 0xab, 0, 0x2f];

    #[test]
    fn parses_and_formats() {
        assert_eq!(parse("02:00:00:ab:00:2f"), Some(MAC));
        assert_eq!(format(MAC), "02:00:00:ab:00:2f");
        // Uppercase is read, and written back in the one spelling.
        assert_eq!(
            parse("02:00:00:AB:00:2F").map(format).unwrap(),
            "02:00:00:ab:00:2f"
        );
    }

    #[test]
    fn refuses_anything_more_or_less() {
        for s in [
            "",
            "02:00:00:00:00:01 ;X",
            "02:00:00:00:00:01 ;REMOVE_NEIGHBOR 02:00:00:00:00:02",
            "02:00:00:00:00:01\n",
            " 02:00:00:00:00:01",
            "02:00:00:00:00",
            "02:00:00:00:00:01:02",
            "02:00:00:00:00:",
            "2:00:00:00:00:01",
            "002:00:00:00:00:01",
            "+2:00:00:00:00:01",
            "02:00:00:00:00:0g",
            "02-00-00-00-00-01",
            "020000000001",
            "02:00:00:00:00:0١",
        ] {
            assert_eq!(parse(s), None, "{s:?}");
        }
    }

    #[test]
    fn hex_round_trips() {
        let key: [u8; 32] = unhex(&"00ff".repeat(16)).unwrap();
        assert_eq!((key[0], key[1], key[31]), (0x00, 0xff, 0xff));
        assert_eq!(hex(&key), "00ff".repeat(16));
        assert_eq!(unhex::<32>(&"00FF".repeat(16)), Some(key));
    }

    #[test]
    fn unhex_takes_exactly_its_digits() {
        let hex = "00ff".repeat(16);
        assert_eq!(unhex::<32>(&hex[2..]), None);
        assert_eq!(unhex::<32>(&format!("{hex}00")), None);
        assert_eq!(unhex::<32>(&format!("{}zz", &hex[2..])), None);
        assert_eq!(unhex::<32>(&format!("+f{}", &hex[2..])), None);
        assert_eq!(unhex::<32>(&format!("-f{}", &hex[2..])), None);
        assert_eq!(unhex::<0>(""), Some([]));
    }
}
