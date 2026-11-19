//! nftables as the AP's root helpers drive it: a script run by `nft -f -`,
//! one transaction, never through a shell, and the device lists of their
//! netdev chains.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

/// Runs the nftables script `script` with the `nft` at `nft`: the first
/// line of its complaint when it fails.
pub fn run(nft: &Path, script: &str) -> Result<(), String> {
    let mut child = Command::new(nft)
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("nft: {e}"))?;
    let wrote = child
        .stdin
        .take()
        .map(|mut s| s.write_all(script.as_bytes()));
    let out = child.wait_with_output().map_err(|e| format!("nft: {e}"))?;
    if let Some(Err(e)) = wrote {
        return Err(format!("nft: {e}"));
    }
    if !out.status.success() {
        return Err(complaint(&out));
    }
    Ok(())
}

/// The first line of what a failed command printed, or how it ended.
pub fn complaint(out: &std::process::Output) -> String {
    let text = String::from_utf8_lossy(&out.stderr);
    let first = text.lines().find(|l| !l.trim().is_empty());
    first.map_or_else(|| out.status.to_string(), |l| l.trim().to_owned())
}

/// `devs` as a chain's `devices = { … }` lists them; each a name
/// `crate::netdev` accepts, safe there as it is.
pub fn devices(devs: &[String]) -> String {
    let quoted: Vec<String> = devs.iter().map(|d| format!("\"{d}\"")).collect();
    quoted.join(", ")
}

/// The script that replaces the table `table` (`<family> <name>`) with
/// `body` (its chains), or removes it when `body` is empty, whether it
/// existed or not.
pub fn replace(table: &str, body: &str) -> String {
    let mut s = format!("table {table}\ndelete table {table}\n");
    if !body.is_empty() {
        s += &format!("table {table} {{\n{body}}}\n");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_table_is_replaced_or_removed_whether_it_existed_or_not() {
        assert_eq!(
            replace("netdev t", ""),
            "table netdev t\ndelete table netdev t\n"
        );
        assert_eq!(
            replace("netdev t", "\tchain c {\n\t}\n"),
            "table netdev t\ndelete table netdev t\ntable netdev t {\n\tchain c {\n\t}\n}\n"
        );
        assert_eq!(
            devices(&["wlan5".into(), "wlan6.42".into()]),
            "\"wlan5\", \"wlan6.42\""
        );
    }

    #[test]
    fn a_failure_says_why() {
        let e = run(Path::new("/nonexistent/nft"), "").unwrap_err();
        assert!(e.starts_with("nft: "), "{e}");
    }
}
