//! The site's live deploys: the controller names a commit of the site's
//! repository it just pushed (the RF planner's), and the runner deploys it
//! only after checking, in a clone of its own, that the commit is the head
//! of the site's branch and that, of what the deploy reads (the site file
//! and `reads`), what changed since the commit it last deployed is plain
//! settings of the site file alone: the keys the planner writes (a radio's
//! channel and width, a power), with numbers or the few words those keys
//! take, nothing a template could make into another command. Changes to the
//! rest of the repository, which the deploy never reads, do not matter. So
//! the controller can have deployed only what is on the branch, and nothing
//! but radio settings, and never supplies a configuration. A commit whose
//! change is more is refused, for a person to deploy.
//!
//! The deploy itself is the stage helper's (`stage`): it runs the site's own
//! command, as root, with the commit.

use std::path::Path;
use std::time::Duration;

use u6e_git::Git;

use crate::config::Site;

/// The least time between two deploys started.
pub const EVERY: Duration = Duration::from_secs(60);
/// The longest one git command may run.
const GIT_TIMEOUT: Duration = Duration::from_secs(120);
/// The most lines of a change looked at.
const CHANGE_MAX: usize = 400;

/// Whether `rev` names a commit as the controller must: 40 lowercase hex
/// digits.
pub fn is_rev(rev: &str) -> bool {
    rev.len() == 40
        && rev
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn git(site: &Site) -> Git {
    Git {
        remote: site.remote.clone(),
        name: "u6e-deploy".into(),
        email: "u6e-deploy@localhost".into(),
        timeout: GIT_TIMEOUT,
    }
}

/// Brings the site's branch into the runner's clone, made when missing.
fn fetch(site: &Site) -> Result<(), String> {
    let g = git(site);
    if !site.clone.join("HEAD").is_file() {
        let parent = site.clone.parent().unwrap_or(Path::new("/"));
        let path = site.clone.to_string_lossy();
        g.ok(parent, &["init", "--quiet", "--bare", &path])
            .map_err(|e| e.to_string())?;
    }
    let refspec = format!("+refs/heads/{0}:refs/remotes/origin/{0}", site.branch);
    g.ok(
        &site.clone,
        &["fetch", "--quiet", &site.remote.url, &refspec],
    )
    .map(drop)
    .map_err(|e| e.to_string())
}

fn head(site: &Site) -> Result<String, String> {
    let g = git(site);
    let at = format!("refs/remotes/origin/{}", site.branch);
    Ok(g.ok(&site.clone, &["rev-parse", &at])
        .map_err(|e| e.to_string())?
        .trim()
        .to_owned())
}

/// Whether `a` is `b` or an ancestor of it.
fn ancestor(site: &Site, a: &str, b: &str) -> Result<bool, String> {
    let out = git(site)
        .run(&site.clone, &["merge-base", "--is-ancestor", a, b])
        .map_err(|e| e.to_string())?;
    Ok(out.ok)
}

/// The keys of the site file the RF planner writes, and those a radio of an
/// AP's own copies from the fleet's.
const KEYS: [&str; 13] = [
    "radios",
    "txpower",
    "24",
    "5",
    "6",
    "hw_mode",
    "channel",
    "op_class",
    "ht_capab",
    "vht_oper_chwidth",
    "vht_oper_centr_freq_seg0_idx",
    "he_oper_chwidth",
    "he_oper_centr_freq_seg0_idx",
];

/// Whether a value is one those keys take: none (a mapping follows), a
/// number, `a` or `g`, an HT capability list, or a mapping of bands to
/// numbers on one line.
fn plain_value(v: &str) -> bool {
    let number = |s: &str| {
        !s.is_empty()
            && s.trim_start_matches('-')
                .bytes()
                .all(|b| b.is_ascii_digit())
    };
    let ht = |s: &str| {
        s.strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .is_some_and(|s| {
                s.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b"[]+-".contains(&b))
            })
    };
    let flow = |s: &str| {
        s.strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .is_some_and(|inner| {
                inner.split(',').all(|item| {
                    item.split_once(':').is_some_and(|(k, n)| {
                        ["\"24\"", "\"5\"", "\"6\""].contains(&k.trim()) && number(n.trim())
                    })
                })
            })
    };
    v.is_empty() || number(v) || v == "a" || v == "g" || ht(v) || flow(v)
}

/// Whether one line a change adds or takes away is a plain setting: blank,
/// a comment, or one of [`KEYS`] with a plain value (and a comment, which
/// nothing renders).
pub fn plain_line(line: &str) -> bool {
    let body = line.trim();
    if body.is_empty() || body.starts_with('#') {
        return true;
    }
    let body = match body.find(" #") {
        Some(i) => body[..i].trim_end(),
        None => body,
    };
    let Some((key, value)) = body.split_once(':') else {
        return false;
    };
    let key = key.trim().trim_matches('"');
    KEYS.contains(&key) && plain_value(value.trim())
}

/// Whether the deploy reads `path` besides the site file: one of
/// `site.reads`, or under one that names a directory.
fn read_by_deploy(site: &Site, path: &str) -> bool {
    site.reads.iter().any(|r| match r.strip_suffix('/') {
        Some(dir) => path.strip_prefix(dir).is_some_and(|p| p.starts_with('/')),
        None => path == r,
    })
}

/// Checks commit `rev` for a deploy in the runner's clone, fetched first:
/// the head of the site's branch, and of what the deploy reads, what changed
/// since `last` (the commit deployed last, when the branch holds it; `rev`'s
/// parent otherwise) plain settings of the site file alone. The commit
/// checked against.
pub fn check(site: &Site, rev: &str, last: Option<&str>) -> Result<String, String> {
    if !is_rev(rev) {
        return Err("not a commit's full name".into());
    }
    fetch(site)?;
    let head = head(site)?;
    if head != rev {
        return Err(format!(
            "{} is not the head of {} ({})",
            &rev[..12],
            site.branch,
            &head[..head.len().min(12)]
        ));
    }
    let base = match last {
        Some(l) if ancestor(site, l, rev)? => l.to_owned(),
        _ => format!("{rev}^"),
    };
    let g = git(site);
    let files = g
        .ok(&site.clone, &["diff", "--name-only", &base, rev])
        .map_err(|e| e.to_string())?;
    let others: Vec<&str> = files
        .lines()
        .filter(|f| *f != site.file && read_by_deploy(site, f))
        .collect();
    if !others.is_empty() {
        return Err(format!(
            "the change since {} touches {}, which the deploy reads, besides {}: a person deploys that",
            &base[..base.len().min(12)],
            others.join(", "),
            site.file
        ));
    }
    let diff = g
        .ok(&site.clone, &["diff", "-U0", &base, rev, "--", &site.file])
        .map_err(|e| e.to_string())?;
    let lines: Vec<&str> = diff
        .lines()
        .filter(|l| {
            (l.starts_with('+') || l.starts_with('-'))
                && !l.starts_with("+++")
                && !l.starts_with("---")
        })
        .collect();
    if lines.len() > CHANGE_MAX {
        return Err(format!(
            "the change is {} lines: a person deploys that",
            lines.len()
        ));
    }
    if let Some(l) = lines.iter().find(|l| !plain_line(&l[1..])) {
        return Err(format!(
            "the change is more than radio settings ({:.80?}): a person deploys that",
            &l[1..]
        ));
    }
    Ok(base)
}

/// Checks that `rev`, which a person deployed, is on the site's branch and
/// not older than `last`.
pub fn deployed(site: &Site, rev: &str, last: Option<&str>) -> Result<(), String> {
    if !is_rev(rev) {
        return Err("not a commit's full name".into());
    }
    fetch(site)?;
    let head = head(site)?;
    if !ancestor(site, rev, &head)? {
        return Err(format!("{} is not on {}", &rev[..12], site.branch));
    }
    if let Some(l) = last.filter(|l| ancestor(site, l, rev).map(|a| !a).unwrap_or(true)) {
        return Err(format!(
            "{} is not newer than {}, deployed already",
            &rev[..12],
            &l[..l.len().min(12)]
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;

    use u6e_git::Remote;

    use crate::tests::TestDir;

    const SITE: &str = "u6e:\n  wifi:\n    txpower: {\"24\": 20, \"5\": 23}\n  aps:\n    ap1:\n      \
                        radios:\n        \"5\":\n          channel: 36\n          ht_capab: \"[HT40+]\"\n";

    /// A bare remote with the site file and a README on main, a working
    /// clone that commits to it, and the runner's site settings.
    pub struct Repo {
        pub dir: PathBuf,
        pub site: Site,
    }

    fn sh(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .current_dir(dir)
            .args([
                "-c",
                "user.name=someone",
                "-c",
                "user.email=someone@example.org",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    impl Repo {
        pub fn new(dir: &Path) -> Repo {
            sh(
                dir,
                &[
                    "init",
                    "--quiet",
                    "--bare",
                    "--initial-branch=main",
                    "remote.git",
                ],
            );
            sh(dir, &["clone", "--quiet", "remote.git", "work"]);
            let work = dir.join("work");
            fs::create_dir_all(work.join("wifi/templates")).unwrap();
            fs::write(work.join("wifi/site.yml"), SITE).unwrap();
            fs::write(work.join("wifi/templates/site.conf.j2"), "{{ site }}\n").unwrap();
            fs::write(work.join("wifi-other.yml"), "other\n").unwrap();
            fs::write(work.join("README.md"), "the site\n").unwrap();
            sh(
                &work,
                &[
                    "add",
                    "--",
                    "wifi/site.yml",
                    "wifi/templates/site.conf.j2",
                    "wifi-other.yml",
                    "README.md",
                ],
            );
            sh(&work, &["commit", "--quiet", "-m", "the site"]);
            sh(&work, &["push", "--quiet", "origin", "HEAD:main"]);
            let site = Site {
                remote: Remote {
                    url: dir.join("remote.git").display().to_string(),
                    ssh_key: None,
                    known_hosts: None,
                },
                clone: dir.join("runner-clone"),
                branch: "main".into(),
                file: "wifi/site.yml".into(),
                reads: vec!["wifi/".into(), "lib/deploy.yml".into()],
                command: dir.join("deploy"),
            };
            Repo {
                dir: dir.into(),
                site,
            }
        }

        /// Commits `text` as `path` and pushes it; the commit.
        pub fn commit(&self, path: &str, from: &str, to: &str) -> String {
            let work = self.dir.join("work");
            let file = work.join(path);
            let text = fs::read_to_string(&file).unwrap().replace(from, to);
            fs::write(&file, text).unwrap();
            sh(&work, &["commit", "--quiet", "-am", "a change"]);
            sh(&work, &["push", "--quiet", "origin", "HEAD:main"]);
            sh(&work, &["rev-parse", "HEAD"]).trim().to_owned()
        }
    }

    #[test]
    fn a_plain_change_of_the_site_file_at_the_head_is_taken() {
        let t = TestDir::new();
        let r = Repo::new(t.path());
        let first = r.commit("wifi/site.yml", "channel: 36", "channel: 44");
        assert_eq!(check(&r.site, &first, None), Ok(format!("{first}^")));
        let second = r.commit("wifi/site.yml", "\"5\": 23}", "\"5\": 20}");
        // Since the one deployed last.
        assert_eq!(check(&r.site, &second, Some(&first)), Ok(first.clone()));
        let why = check(&r.site, &first, Some(&first)).unwrap_err();
        assert!(why.contains("is not the head of main"), "{why}");
    }

    /// The rest of the repository moves on between two deploys: what the
    /// deploy never reads blocks none.
    #[test]
    fn an_unrelated_commit_between_two_deploys_is_taken() {
        let t = TestDir::new();
        let r = Repo::new(t.path());
        let first = r.commit("wifi/site.yml", "channel: 36", "channel: 44");
        r.commit("README.md", "the site", "the site, changed");
        // Not under wifi/, though its name starts so.
        r.commit("wifi-other.yml", "other", "other, changed");
        let second = r.commit("wifi/site.yml", "channel: 44", "channel: 48");
        assert_eq!(check(&r.site, &second, Some(&first)), Ok(first));
    }

    #[test]
    fn more_than_radio_settings_is_refused() {
        let t = TestDir::new();
        let r = Repo::new(t.path());
        let base = r.commit("wifi/site.yml", "channel: 36", "channel: 44");
        let injected = r.commit("wifi/site.yml", "channel: 44", "channel: \"44$(id)\"");
        let why = check(&r.site, &injected, Some(&base)).unwrap_err();
        assert!(why.contains("more than radio settings"), "{why}");
        // What the deploy reads changed since the last deploy: refused, even
        // when the commit itself is plain.
        r.commit(
            "wifi/templates/site.conf.j2",
            "{{ site }}",
            "{{ site | x }}",
        );
        let plain = r.commit("wifi/site.yml", "channel: \"44$(id)\"", "channel: 48");
        let why = check(&r.site, &plain, Some(&base)).unwrap_err();
        assert!(
            why.contains("touches wifi/templates/site.conf.j2, which the deploy reads"),
            "{why}"
        );
        assert!(
            check(&r.site, "HEAD", None)
                .unwrap_err()
                .contains("not a commit")
        );
    }

    #[test]
    fn plain_lines() {
        for ok in [
            "          channel: 149",
            "          channel: 149  # planner: fixed",
            "        \"24\":",
            "      txpower: {\"24\": 20, \"5\": 23}",
            "          ht_capab: \"[HT40-][SHORT-GI-40]\"",
            "          hw_mode: g",
            "        # A comment says why.",
            "",
        ] {
            assert!(plain_line(ok), "{ok}");
        }
        for bad in [
            "          channel: \"1; reboot\"",
            "          ctrl_interface: /tmp",
            "          ssid: x",
            "      txpower: {\"24\": x}",
            "          ht_capab: \"[HT40+]$(x)\"",
            "    passphrase: {path: secret/x, field: y}",
        ] {
            assert!(!plain_line(bad), "{bad}");
        }
    }

    #[test]
    fn a_commit_a_person_deployed_must_be_on_the_branch_and_newer() {
        let t = TestDir::new();
        let r = Repo::new(t.path());
        let first = r.commit("wifi/site.yml", "channel: 36", "channel: 44");
        let second = r.commit("README.md", "the site", "the site, changed");
        assert_eq!(deployed(&r.site, &second, Some(&first)), Ok(()));
        let why = deployed(&r.site, &first, Some(&second)).unwrap_err();
        assert!(why.contains("is not newer than"), "{why}");
        let elsewhere = "0123456789abcdef0123456789abcdef01234567";
        assert!(deployed(&r.site, elsewhere, None).is_err());
    }
}
