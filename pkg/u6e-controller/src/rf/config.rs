//! The RF planner's part of the controller's configuration, `[rf]`: the
//! clone of the repository holding the site file and how to push to it, the
//! window it plans over, and the channels it may choose, per country (the
//! regulatory domain's, narrowed to what the site's clients can use; their
//! power limits are each radio's own, as its AP reports them); without
//! `[rf]` the planner is off.
//!
//! ```toml
//! [rf]
//! remote = "ssh://git@git.example.org/team/site.git"
//! repo = "/var/lib/wifi-controller/site"
//! branch = "main"
//! file = "wifi/site.yml"
//! ssh_key = "/etc/wifi-controller/git-key"
//! known_hosts = "/etc/wifi-controller/git-known-hosts"
//! author_email = "wifi-controller@example.org"
//! window_hours = 24
//! dfs = false
//! client_dbm = 15
//! widths = { "24" = [20], "5" = [20, 40, 80], "6" = [20, 40, 80, 160] }
//!
//! [rf.channels.ZZ]
//! "24" = [{ channels = "1-13" }]
//! "5" = [{ channels = "36-48" }, { channels = "52-64", dfs = true }]
//! "6" = [{ channels = "1-93" }]
//! ```
//!
//! A range holds every channel of its band from its first to its last;
//! `dfs = true` marks those the planner leaves alone unless `dfs` allows them
//! (a move onto one then takes the next configuration push, which runs the
//! radar check a live switch cannot).
//! `ssh_key` and `known_hosts` go together, as plain absolute paths (letters,
//! digits and `/._-`), and the key must be its owner's alone (checked at
//! start). `client_dbm` is the power a client is taken to send at, from which
//! what clients hear of an AP is estimated.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Deserialize;
use u6e_git::Remote;

use super::channels::{self, BANDS, WIDTHS};
use super::git::Repo;
use super::plan::{Allowed, Rules};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct File {
    remote: String,
    repo: PathBuf,
    #[serde(default = "default_branch")]
    branch: String,
    #[serde(default = "default_file")]
    file: String,
    ssh_key: Option<PathBuf>,
    known_hosts: Option<PathBuf>,
    #[serde(default = "default_email")]
    author_email: String,
    #[serde(default = "default_window")]
    window_hours: u64,
    #[serde(default)]
    dfs: bool,
    #[serde(default = "default_client")]
    client_dbm: i32,
    #[serde(default)]
    widths: BTreeMap<String, Vec<u16>>,
    channels: BTreeMap<String, BTreeMap<String, Vec<RangeFile>>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RangeFile {
    channels: String,
    #[serde(default)]
    dfs: bool,
}

fn default_branch() -> String {
    "main".into()
}

fn default_file() -> String {
    "site.yml".into()
}

fn default_email() -> String {
    "wifi-controller@localhost".into()
}

fn default_window() -> u64 {
    24
}

fn default_client() -> i32 {
    15
}

/// The longest window: a week of hours.
const MAX_WINDOW: u64 = 168;

/// The planner's checked configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub repo: Repo,
    pub rules: Rules,
}

/// The default widths per band: 2.4 GHz at 20 MHz only, its 40 MHz channels
/// overlapping every other one.
fn default_widths(band: usize) -> Vec<u16> {
    match band {
        0 => vec![20],
        1 => vec![20, 40, 80],
        _ => WIDTHS.to_vec(),
    }
}

fn band_index(key: &str) -> Result<usize, String> {
    let band = channels::from_site_key(key)
        .ok_or_else(|| format!("rf: no band {key:?} (\"24\", \"5\" or \"6\")"))?;
    Ok(BANDS.iter().position(|b| *b == band).expect("a band"))
}

fn range(band: usize, r: &RangeFile) -> Result<Allowed, String> {
    let bad = || {
        format!(
            "rf: channels {:?} is not <first>-<last> or <channel>",
            r.channels
        )
    };
    let (lo, hi) = match r.channels.split_once('-') {
        Some((a, b)) => (
            a.trim().parse().map_err(|_| bad())?,
            b.trim().parse().map_err(|_| bad())?,
        ),
        None => {
            let c = r.channels.trim().parse().map_err(|_| bad())?;
            (c, c)
        }
    };
    let b = BANDS[band];
    if lo > hi || !(lo..=hi).any(|c| channels::exists(b, c)) {
        return Err(format!("rf: {:?} holds no channel of its band", r.channels));
    }
    Ok(Allowed { lo, hi, dfs: r.dfs })
}

impl File {
    pub fn check(self) -> Result<Settings, String> {
        if !(1..=MAX_WINDOW).contains(&self.window_hours) {
            return Err(format!("rf: window_hours is not 1 to {MAX_WINDOW}"));
        }
        if self.author_email.trim().is_empty() || self.remote.trim().is_empty() {
            return Err("rf: remote and author_email may not be empty".into());
        }
        if !(0..=30).contains(&self.client_dbm) {
            return Err("rf: client_dbm is not 0 to 30".into());
        }
        let remote = Remote {
            url: self.remote,
            ssh_key: self.ssh_key,
            known_hosts: self.known_hosts,
        };
        remote.check().map_err(|e| format!("rf: {e}"))?;
        let mut widths: [Vec<u16>; 3] = [0, 1, 2].map(default_widths);
        for (key, list) in &self.widths {
            let i = band_index(key)?;
            if list.is_empty()
                || list
                    .iter()
                    .any(|w| !WIDTHS.contains(w) || (i == 0 && *w != 20))
            {
                return Err(format!(
                    "rf: widths.{key:?} must list widths of 20, 40, 80 or 160 (2.4 GHz: 20)"
                ));
            }
            widths[i] = list.clone();
        }
        let mut countries = BTreeMap::new();
        for (country, bands) in &self.channels {
            let mut table: [Vec<Allowed>; 3] = Default::default();
            for (key, ranges) in bands {
                let i = band_index(key)?;
                table[i] = ranges
                    .iter()
                    .map(|r| range(i, r))
                    .collect::<Result<_, _>>()?;
            }
            countries.insert(country.clone(), table);
        }
        Ok(Settings {
            repo: Repo {
                remote,
                path: self.repo,
                branch: self.branch,
                file: self.file,
                email: self.author_email,
            },
            rules: Rules {
                window_hours: self.window_hours,
                dfs: self.dfs,
                client_dbm: self.client_dbm,
                widths,
                countries,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Settings, String> {
        toml::from_str::<File>(text)
            .map_err(|e| e.to_string())?
            .check()
    }

    const MIN: &str = "remote = \"/srv/site.git\"\nrepo = \"/var/lib/site\"\n[channels.ZZ]\n";

    #[test]
    fn defaults_and_tables() {
        let s = parse(&format!(
            "{MIN}\"24\" = [{{ channels = \"1-13\" }}]\n\
             \"5\" = [{{ channels = \"36-48\" }}, {{ channels = \"52\", dfs = true }}]\n"
        ))
        .unwrap();
        assert_eq!(s.repo.branch, "main");
        assert_eq!(s.repo.file, "site.yml");
        assert_eq!(s.rules.window_hours, 24);
        assert!(!s.rules.dfs);
        assert_eq!(s.rules.widths[0], [20]);
        assert_eq!(s.rules.widths[2], [20, 40, 80, 160]);
        let zz = &s.rules.countries["ZZ"];
        assert_eq!(
            zz[0],
            [Allowed {
                lo: 1,
                hi: 13,
                dfs: false
            }]
        );
        assert_eq!(
            zz[1][1],
            Allowed {
                lo: 52,
                hi: 52,
                dfs: true
            }
        );
        assert!(zz[2].is_empty());
    }

    #[test]
    fn bad_tables_refused() {
        for bad in [
            "\"7\" = []\n",
            "\"5\" = [{ channels = \"48-36\" }]\n",
            "\"5\" = [{ channels = \"1-13\" }]\n",
            "\"5\" = [{ channels = \"x\" }]\n",
            "\"5\" = [{ channels = \"36\", other = 1 }]\n",
            "\"5\" = [{ channels = \"36\", max_dbm = 23 }]\n",
        ] {
            assert!(parse(&format!("{MIN}{bad}")).is_err(), "{bad}");
        }
        let widths = "remote = \"r\"\nrepo = \"p\"\nwidths = { \"24\" = [40] }\n[channels]\n";
        assert!(parse(widths).is_err());
        let window = "remote = \"r\"\nrepo = \"p\"\nwindow_hours = 0\n[channels]\n";
        assert!(parse(window).is_err());
    }
}
