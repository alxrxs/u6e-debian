//! The radios' configurations in a u6e-wifi script, as `boot/wifi-up.sh
//! --print` renders it for an AP: its `install_confs` writes each radio's
//! hostapd file from a here-document (`cat > /run/u6e-wifi/wlanB.conf
//! <<'EOF'`) and its transmit power (`echo N > /run/u6e-wifi/wlanB.txpower`),
//! which is what an AP installs at boot, so a configuration read here is the
//! one the AP would run from an image built from the same site. The files
//! hold the site's secrets: nothing here quotes a line of them.

use u6e_proto::msg::{Band, RadioConfig};

const DIR: &str = "/run/u6e-wifi/wlan";

fn band(name: &str) -> Option<Band> {
    match name {
        "24" => Some(Band::B24),
        "5" => Some(Band::B5),
        "6" => Some(Band::B6),
        _ => None,
    }
}

/// Every radio's configuration in `script`, in band order.
pub fn radios(script: &str) -> Result<Vec<RadioConfig>, String> {
    let mut lines = script.lines().enumerate();
    lines
        .find(|(_, l)| *l == "install_confs() {")
        .ok_or("no install_confs in the script: not boot/wifi-up.sh --print")?;
    let mut texts: Vec<(Band, String)> = Vec::new();
    let mut powers: Vec<(Band, i8)> = Vec::new();
    loop {
        let Some((n, line)) = lines.next() else {
            return Err("install_confs does not end".into());
        };
        if line == "}" {
            break;
        }
        if let Some(rest) = line.strip_prefix(&format!("cat > {DIR}")) {
            let b = rest
                .strip_suffix(".conf <<'EOF'")
                .and_then(band)
                .ok_or_else(|| format!("line {}: not a radio's file", n + 1))?;
            if texts.iter().any(|(x, _)| *x == b) {
                return Err(format!("line {}: a radio's file twice", n + 1));
            }
            let mut text = String::new();
            loop {
                match lines.next() {
                    Some((_, "EOF")) => break,
                    Some((_, l)) => {
                        text.push_str(l);
                        text.push('\n');
                    }
                    None => return Err(format!("line {}: the file does not end", n + 1)),
                }
            }
            texts.push((b, text));
        } else if line.contains(".txpower") {
            for echo in line.split(';') {
                let power = echo
                    .trim()
                    .strip_prefix("echo ")
                    .and_then(|e| e.split_once(&format!(" > {DIR}")))
                    .and_then(|(dbm, file)| {
                        Some((dbm.parse().ok()?, band(file.strip_suffix(".txpower")?)?))
                    });
                let (dbm, b) =
                    power.ok_or_else(|| format!("line {}: not a radio's power", n + 1))?;
                powers.push((b, dbm));
            }
        } else {
            return Err(format!("line {}: unexpected in install_confs", n + 1));
        }
    }
    let mut out = Vec::new();
    for b in [Band::B24, Band::B5, Band::B6] {
        let text = texts
            .iter()
            .position(|(x, _)| *x == b)
            .map(|i| texts.swap_remove(i).1);
        let power = powers.iter().find(|(x, _)| *x == b).map(|(_, p)| *p);
        match (text, power) {
            (Some(text), Some(txpower_dbm)) => out.push(RadioConfig {
                radio: b,
                text,
                txpower_dbm,
            }),
            (None, None) => {}
            _ => {
                return Err(format!(
                    "{b:?}: a file without a power, or a power without a file"
                ));
            }
        }
    }
    if out.is_empty() {
        return Err("install_confs installs no radio".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `boot/wifi-up.sh --print` for site.conf.example, its secrets test
    /// values.
    const SCRIPT: &str = include_str!("../tests/fixtures/u6e-wifi.sh");

    #[test]
    fn the_radios_of_a_rendered_script() {
        let radios = radios(SCRIPT).unwrap();
        let bands: Vec<_> = radios.iter().map(|r| (r.radio, r.txpower_dbm)).collect();
        assert_eq!(bands, [(Band::B24, 20), (Band::B5, 23), (Band::B6, 23)]);
        for (r, iface) in radios.iter().zip(["wlan24", "wlan5", "wlan6"]) {
            assert!(
                r.text.starts_with(&format!("interface={iface}\n")),
                "{iface}"
            );
            assert!(r.text.ends_with('\n') && !r.text.contains("EOF"), "{iface}");
        }
        // Exactly the lines of the here-document, as cat writes them.
        let start = SCRIPT.find("wlan5.conf <<'EOF'\n").unwrap() + 19;
        let len = SCRIPT[start..].find("EOF\n").unwrap();
        assert_eq!(radios[1].text, SCRIPT[start..start + len]);
    }

    #[test]
    fn what_is_not_a_rendered_script() {
        let err = |s: &str| radios(s).unwrap_err();
        assert!(err("#!/bin/sh\n").contains("no install_confs"));
        let head = "install_confs() {\n";
        let conf =
            "cat > /run/u6e-wifi/wlan5.conf <<'EOF'\ninterface=wlan5\nwpa_passphrase=hidden\nEOF\n";
        let power = "echo 23 > /run/u6e-wifi/wlan5.txpower\n";
        assert!(radios(&format!("{head}{conf}{power}}}\n")).is_ok());
        for (bad, why) in [
            (format!("{head}{conf}{power}"), "does not end"),
            (format!("{head}{conf}}}\n"), "a file without a power"),
            (format!("{head}{power}}}\n"), "a file without a power"),
            (
                format!("{head}{conf}{conf}{power}}}\n"),
                "a radio's file twice",
            ),
            (
                format!("{head}cat > /run/u6e-wifi/wlan7.conf <<'EOF'\nEOF\n}}\n"),
                "not a radio's file",
            ),
            (
                format!("{head}echo x > /run/u6e-wifi/wlan5.txpower\n}}\n"),
                "not a radio's power",
            ),
            (format!("{head}rm -rf /\n}}\n"), "unexpected"),
            (format!("{head}}}\n"), "installs no radio"),
            (
                format!("{head}cat > /run/u6e-wifi/wlan5.conf <<'EOF'\nwpa_passphrase=hidden\n"),
                "does not end",
            ),
        ] {
            let e = err(&bad);
            assert!(e.contains(why), "{e}, not {why}");
            assert!(!e.contains("hidden"), "{e}");
        }
    }
}
