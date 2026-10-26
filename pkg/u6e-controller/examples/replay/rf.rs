//! The RF planner's side of the replay: the repository it commits the site
//! file to, a bare one made afresh in the temporary directory from the tests'
//! site file at each start, and the radios' last day, made up so that the
//! plan has hours to score from its first moment. Over that day the 5 GHz
//! band was busy with other networks, most in the evening, and ap1's 5 GHz
//! radio spent the night on 165-177, a far quieter block, before it moved to
//! 36-48; the 2.4 GHz radios share channel 6, as the site file has them.

use std::f64::consts::PI;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use u6e_controller::state::Shared;

use crate::World;

const SITE: &str = include_str!("../../tests/fixtures/site.yml");
/// Where the site file is in its repository.
pub const FILE: &str = "wifi/site.yml";
/// Each made-up hour is this many intervals of this long: the most the
/// history takes as one.
const INTERVALS: u32 = 6;
const INTERVAL: Duration = Duration::from_secs(600);

fn git(dir: &Path, args: &[&str]) -> io::Result<()> {
    let out = Command::new("git")
        .current_dir(dir)
        .args([
            "-c",
            "user.name=replay",
            "-c",
            "user.email=replay@example.org",
        ])
        .args(args)
        .output()?;
    if out.status.success() {
        return Ok(());
    }
    let said = String::from_utf8_lossy(&out.stderr);
    Err(io::Error::other(format!(
        "git {}: {}",
        args[0],
        said.trim()
    )))
}

/// The site repository, made afresh: the bare remote and the path of the
/// planner's clone of it (left for the planner to make).
pub fn repository() -> io::Result<(PathBuf, PathBuf)> {
    let root = std::env::temp_dir().join("u6e-replay-site");
    if root.exists() {
        fs::remove_dir_all(&root)?;
    }
    let seed = root.join("seed");
    fs::create_dir_all(seed.join("wifi"))?;
    fs::write(seed.join(FILE), SITE)?;
    git(
        &root,
        &[
            "init",
            "--quiet",
            "--bare",
            "--initial-branch=main",
            "site.git",
        ],
    )?;
    git(&seed, &["init", "--quiet", "--initial-branch=main"])?;
    git(&seed, &["add", "--", FILE])?;
    git(&seed, &["commit", "--quiet", "-m", "wifi: the site"])?;
    git(
        &seed,
        &[
            "push",
            "--quiet",
            &root.join("site.git").display().to_string(),
            "main",
        ],
    )?;
    Ok((root.join("site.git"), root.join("clone")))
}

/// The share of the air other networks took `hours_ago` on radio `r` of
/// `ap`, and whether that radio was on 165-177 then.
fn foreign(ap: usize, r: usize, hours_ago: u32) -> (f64, bool) {
    // The evening (6 to 9 hours ago) is the busiest.
    let evening = 1.0 + 0.6 * (f64::from(hours_ago) * PI / 12.0 - PI / 4.0).sin();
    match (ap, r) {
        (0, 1) if hours_ago >= 16 => (3.0, true),
        (_, 0) => (22.0 * evening, false),
        (_, 1) => (24.0 * evening, false),
        _ => (1.0, false),
    }
}

/// Fills the state's history with the last day of both APs.
pub fn seed(state: &Shared, world: &mut World) {
    let now = SystemTime::now();
    for hours_ago in 1..24u32 {
        for (ap, name) in ["ap1", "ap2"].into_iter().enumerate() {
            let mut prev = world.snapshot(ap, 1);
            let mut next = prev.clone();
            for (i, (p, n)) in prev.radios.iter_mut().zip(&mut next.radios).enumerate() {
                let (share, night) = foreign(ap, i, hours_ago);
                if night {
                    (p.channel, n.channel) = (165, 165);
                }
                let ms = INTERVAL.as_millis() as u64;
                let own = ms / 20;
                (p.active_ms, p.busy_ms, p.tx_ms, p.rx_ms) = (0, 0, 0, 0);
                n.active_ms = ms;
                n.tx_ms = own;
                n.busy_ms = own + (ms as f64 * share / 100.0) as u64;
            }
            let end = now - Duration::from_secs(u64::from(hours_ago) * 3600);
            let mut s = state.write();
            for k in 0..INTERVALS {
                let at = end - INTERVAL * k;
                s.history.observe(name, &prev, at - INTERVAL, &next, at);
            }
        }
    }
}
