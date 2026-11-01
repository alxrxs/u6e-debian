//! The RF planner end to end: its commits landed in a scratch repository (a
//! bare remote, the controller's clone and another clone that pushes
//! meanwhile), and its API on a controller in this process whose APs' state
//! is fed in directly.

use std::cell::Cell;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use tokio::runtime::{Builder, Runtime};
use u6e_controller::agents::Timing;
use u6e_controller::config::Config;
use u6e_controller::names::Resolve;
use u6e_controller::rf::git::{self, Repo};
use u6e_controller::rf::site::{self, Change, Setting};
use u6e_controller::{Controller, start};
use u6e_git::Remote;
use u6e_proto::mac;
use u6e_proto::msg::{AgentMsg, Band, Bss, Hello, Radio, RateMode, Snapshot, Station};
use u6e_proto::tls::Identity;

#[path = "common/keys.rs"]
mod keys;

use keys::{KEY_AP1, KEY_AP2, KEY_CONTROLLER};

const SITE: &str = include_str!("fixtures/site.yml");
const FILE: &str = "wifi/site.yml";
const WAIT: Duration = Duration::from_secs(20);

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("{name}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// What `git` prints in `dir`, which must succeed.
fn git_in(dir: &Path, args: &[&str]) -> String {
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
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// A bare remote holding the fixture as `wifi/site.yml` on `main`, and
/// another clone of it, as another editor of the site has.
struct Scratch {
    dir: TempDir,
}

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = TempDir::new(name);
        git_in(
            &dir.0,
            &[
                "init",
                "--quiet",
                "--bare",
                "--initial-branch=main",
                "remote.git",
            ],
        );
        git_in(&dir.0, &["clone", "--quiet", "remote.git", "other"]);
        let other = dir.0.join("other");
        fs::create_dir_all(other.join("wifi")).unwrap();
        fs::write(other.join(FILE), SITE).unwrap();
        fs::write(other.join("README.md"), "The site.\n").unwrap();
        git_in(&other, &["add", "--", FILE, "README.md"]);
        git_in(&other, &["commit", "--quiet", "-m", "the site"]);
        git_in(&other, &["push", "--quiet", "origin", "HEAD:main"]);
        Scratch { dir }
    }

    fn remote(&self) -> PathBuf {
        self.dir.0.join("remote.git")
    }

    fn other(&self) -> PathBuf {
        self.dir.0.join("other")
    }

    /// The controller's clone, not made yet: the first use clones.
    fn repo(&self) -> Repo {
        Repo {
            remote: Remote {
                url: self.remote().display().to_string(),
                ssh_key: None,
                known_hosts: None,
            },
            path: self.dir.0.join("clone"),
            branch: "main".into(),
            file: FILE.into(),
            email: "wifi-controller@example.org".into(),
        }
    }

    /// The other clone commits `text` as `path` and pushes it.
    fn push_other(&self, path: &str, text: &str) {
        let other = self.other();
        git_in(&other, &["pull", "--quiet", "--rebase", "origin", "main"]);
        fs::write(other.join(path), text).unwrap();
        git_in(&other, &["commit", "--quiet", "-am", "meanwhile"]);
        git_in(&other, &["push", "--quiet", "origin", "HEAD:main"]);
    }

    /// Has the other clone push `text` as `path` from inside the next push
    /// of the clone at `clone`: after the remote told that push where main
    /// was, before it moves main.
    fn push_other_during_push(&self, clone: &Path, path: &str, text: &str) {
        let staged = self.dir.0.join("meanwhile");
        fs::write(&staged, text).unwrap();
        let hook = clone.join(".git/hooks/pre-push");
        let script = format!(
            "#!/bin/sh\n[ -e \"$0.done\" ] && exit 0\ntouch \"$0.done\"\nunset $(git rev-parse --local-env-vars)\n\
             cd '{}' && cp '{}' '{path}' && \
             git -c user.name=someone -c user.email=someone@example.org commit -qam meanwhile && \
             git push -q origin HEAD:main\n",
            self.other().display(),
            staged.display()
        );
        fs::write(&hook, script).unwrap();
        Command::new("chmod").arg("+x").arg(&hook).status().unwrap();
    }

    /// `path` as the remote's main has it.
    fn on_main(&self, path: &str) -> String {
        git_in(&self.remote(), &["show", &format!("main:{path}")])
    }

    /// The subjects on the remote's main, newest first.
    fn log(&self) -> Vec<String> {
        let log = git_in(&self.remote(), &["log", "--format=%s", "main"]);
        log.lines().map(str::to_owned).collect()
    }
}

/// ap2's 2.4 GHz radio off channel 6, onto 1.
fn move_ap2() -> Change {
    let at = |channel| Setting {
        channel,
        width: 20,
        power: Some(20),
    };
    Change {
        ap: "ap2".into(),
        band: Band::B24,
        from: at(6),
        to: at(1),
    }
}

fn edit(text: &str) -> Result<String, String> {
    site::edit(text, &[move_ap2()]).map_err(|e| e.to_string())
}

#[test]
fn a_change_lands_as_one_commit_by_the_controller() {
    let s = Scratch::new("rf-land");
    let repo = s.repo();
    let landed = repo
        .land(edit, "wifi: one change\n\nApplied by alice.\n")
        .unwrap();
    assert_eq!(landed.rejected, 0);
    assert_eq!(
        git_in(&s.remote(), &["rev-parse", "main"]).trim(),
        landed.commit
    );
    let who = git_in(
        &s.remote(),
        &["log", "-1", "--format=%an <%ae>|%cn|%B", "main"],
    );
    assert!(
        who.starts_with(
            "wifi-controller <wifi-controller@example.org>|wifi-controller|wifi: one change"
        ),
        "{who}"
    );
    assert!(who.contains("Applied by alice."));
    // The file on main is the edit, comments and all; nothing else moved.
    assert_eq!(s.on_main(FILE), edit(SITE).unwrap());
    let changed = git_in(&s.remote(), &["diff", "--name-only", "main~1", "main"]);
    assert_eq!(changed.trim(), FILE);
    // The clone is the remote's branch again, with nothing left over.
    assert_eq!(git_in(&repo.path, &["status", "--porcelain"]), "");
    let (rev, text) = repo.read().unwrap();
    assert_eq!((rev, text), (landed.commit.clone(), s.on_main(FILE)));
}

/// Someone else lands a commit after the controller fetched, before it
/// pushes: the change is made again on the new branch, which keeps theirs.
#[test]
fn a_push_turned_down_because_the_branch_moved_is_made_again_and_lands() {
    let s = Scratch::new("rf-moved");
    let repo = s.repo();
    let once = Cell::new(true);
    let landed = repo
        .land(
            |text| {
                if once.replace(false) {
                    s.push_other("README.md", "The site, meanwhile.\n");
                }
                edit(text)
            },
            "wifi: one change\n",
        )
        .unwrap();
    assert_eq!(landed.rejected, 1);
    assert_eq!(s.log(), ["wifi: one change", "meanwhile", "the site"]);
    assert_eq!(s.on_main("README.md"), "The site, meanwhile.\n");
    assert_eq!(s.on_main(FILE), edit(SITE).unwrap());
}

/// The other clone lands its commit while the controller's push is under
/// way, which git reports as `failed to update ref`: made again too.
#[test]
fn a_push_racing_another_is_made_again_and_lands() {
    let s = Scratch::new("rf-race");
    let repo = s.repo();
    repo.fetch().unwrap();
    s.push_other_during_push(&repo.path, "README.md", "The site, meanwhile.\n");
    let landed = repo.land(edit, "wifi: one change\n").unwrap();
    assert_eq!(landed.rejected, 1);
    assert_eq!(s.log(), ["wifi: one change", "meanwhile", "the site"]);
    assert_eq!(s.on_main(FILE), edit(SITE).unwrap());
}

/// Meanwhile the radio is changed another way: the edit made again on the
/// new branch finds the file no longer as planned, and nothing lands.
#[test]
fn a_change_made_meanwhile_is_never_overwritten() {
    let s = Scratch::new("rf-conflict");
    let repo = s.repo();
    let theirs = edit(SITE)
        .unwrap()
        .replace("          channel: 1\n", "          channel: 11\n");
    let once = Cell::new(true);
    let landed = repo.land(
        |text| {
            if once.replace(false) {
                s.push_other(FILE, &theirs);
            }
            edit(text)
        },
        "wifi: one change\n",
    );
    assert!(
        matches!(&landed, Err(git::Error::Edit(e)) if e.contains("no longer as planned")),
        "{landed:?}"
    );
    assert_eq!(s.on_main(FILE), theirs);
    assert_eq!(git_in(&repo.path, &["status", "--porcelain"]), "");
    assert_eq!(
        git_in(&repo.path, &["rev-parse", "HEAD"]),
        git_in(&s.remote(), &["rev-parse", "main"])
    );
}

#[test]
fn a_push_the_remote_refuses_is_not_tried_again() {
    let s = Scratch::new("rf-refused");
    let hook = s.remote().join("hooks/pre-receive");
    fs::write(&hook, "#!/bin/sh\necho 'main is protected' >&2\nexit 1\n").unwrap();
    Command::new("chmod").arg("+x").arg(&hook).status().unwrap();
    let repo = s.repo();
    let landed = repo.land(edit, "wifi: one change\n");
    match landed {
        Err(git::Error::Git(e)) => assert!(e.contains("remote rejected"), "{e}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(s.log(), ["the site"]);
    assert_eq!(git_in(&repo.path, &["status", "--porcelain"]), "");
}

#[test]
fn an_edit_refused_lands_nothing() {
    let s = Scratch::new("rf-stale");
    let repo = s.repo();
    let mut stale = move_ap2();
    stale.from.channel = 11;
    let landed = repo.land(
        |t| site::edit(t, &[stale.clone()]).map_err(|e| e.to_string()),
        "x\n",
    );
    assert!(
        matches!(landed, Err(git::Error::Edit(ref e)) if e.contains("no longer as planned")),
        "{landed:?}"
    );
    assert_eq!(s.log(), ["the site"]);
}

// The API, on a controller in this process.

const ORIGIN: &str = "https://wifi.example.org";
const SAME_SITE: &str = "Content-Type: application/json\r\nOrigin: https://wifi.example.org\r\n";
const ADMIN: &str =
    "X-Auth-Request-Groups: wifi-admins\r\nX-Forwarded-Preferred-Username: alice\r\n";

struct NoNames;

impl Resolve for NoNames {
    fn reverse(&self, _: std::net::IpAddr) -> Option<String> {
        None
    }
}

struct Running {
    c: Controller,
    _rt: Runtime,
}

fn public(pem: &str) -> String {
    mac::hex(&Identity::from_pem(pem).unwrap().public_key())
}

/// A controller of ap1 and ap2, with the planner on `scratch` if given.
fn controller(dir: &Path, scratch: Option<&Scratch>) -> Running {
    let mut text = format!(
        "listen_agents = \"127.0.0.1:0\"\nlisten_http = \"127.0.0.1:0\"\nlisten_metrics = \"127.0.0.1:0\"\n\
         public_origin = \"{ORIGIN}\"\npolicy_path = \"{}\"\n\
         [aps.ap1]\npublic_key = \"{}\"\n[aps.ap2]\npublic_key = \"{}\"\n",
        dir.join("policy.json").display(),
        public(KEY_AP1),
        public(KEY_AP2),
    );
    if let Some(s) = scratch {
        text.push_str(&format!(
            "[rf]\nremote = \"{}\"\nrepo = \"{}\"\nfile = \"{FILE}\"\nauthor_email = \"wifi-controller@example.org\"\n\
             [rf.channels.ZZ]\n\"24\" = [{{ channels = \"1-13\", max_dbm = 23 }}]\n\
             \"5\" = [{{ channels = \"36-48\", max_dbm = 23 }}, {{ channels = \"149-177\", max_dbm = 23 }}]\n\
             \"6\" = [{{ channels = \"1-93\", max_dbm = 24 }}]\n",
            s.remote().display(),
            s.repo().path.display(),
        ));
    }
    let config = Config::parse(&text).unwrap();
    let rt = Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let identity = Identity::from_pem(KEY_CONTROLLER).unwrap();
    let c = rt
        .block_on(start(
            &config,
            &identity,
            Timing::default(),
            Arc::new(NoNames),
            None,
        ))
        .unwrap();
    Running { c, _rt: rt }
}

fn station(mac: [u8; 6], bss: u16, signal: i8) -> Station {
    Station {
        mac,
        bss,
        signal,
        signal_avg: signal,
        rx_bytes: 0,
        tx_bytes: 0,
        rx_packets: 0,
        tx_packets: 0,
        tx_retries: 0,
        tx_failed: 0,
        tx_rate_kbps: 0,
        rx_rate_kbps: 0,
        tx_mcs: 0,
        rx_mcs: 0,
        tx_mode: RateMode::He,
        rx_mode: RateMode::He,
        tx_nss: 2,
        rx_nss: 2,
        tx_airtime_us: 0,
        rx_airtime_us: 0,
        inactive_ms: 0,
        connected_s: 60,
        vlan: 101,
    }
}

/// A snapshot of an AP on the fixture's channels and powers, its counters
/// at `secs`, with one client on its 2.4 GHz radio when `client`.
fn snapshot(seq: u64, channels: [(u16, u16); 3], secs: u64, client: bool) -> Snapshot {
    let bands = [
        (Band::B24, "radio24", 2000),
        (Band::B5, "radio5", 2300),
        (Band::B6, "radio6", 1800),
    ];
    let radios = bands
        .iter()
        .zip(channels)
        .map(|((band, phy, mbm), (channel, width))| Radio {
            phy: (*phy).into(),
            band: *band,
            channel,
            width_mhz: width,
            txpower_mbm: *mbm,
            noise_dbm: -95,
            active_ms: secs * 1000,
            busy_ms: secs * 300,
            rx_ms: 0,
            tx_ms: secs * 100,
            up: true,
        })
        .collect();
    let bsss = bands
        .iter()
        .enumerate()
        .map(|(i, (_, phy, _))| Bss {
            ifname: format!("wlan{i}"),
            bssid: [2, 0, 0, 0, 1, i as u8],
            ssid: "ssid-a".into(),
            phy: (*phy).into(),
            vlan: 101,
        })
        .collect();
    let stations = if client {
        vec![station([2, 0, 0, 0, 0, 1], 0, -60)]
    } else {
        Vec::new()
    };
    Snapshot {
        seq,
        uptime_s: 3600,
        load_milli: 0,
        mem_avail_kb: 0,
        nss_load_pct: 0,
        temps: Vec::new(),
        radios,
        bsss,
        stations,
        config_sha256: None,
        clock_synced: true,
    }
}

/// Connects `ap` and gives it two snapshots a moment apart: an interval in
/// its history.
fn feed(r: &Running, ap: &str, channels: [(u16, u16); 3], client: bool) {
    let hello = Hello {
        ap: ap.into(),
        manifest: "image: test".into(),
        kernel: String::new(),
        hostapd: String::new(),
        agent: String::new(),
    };
    let id = r.c.state.write().connect(ap, hello).unwrap().id;
    r.c.state
        .write()
        .apply(ap, id, AgentMsg::Key(snapshot(1, channels, 0, client)))
        .unwrap();
    thread::sleep(Duration::from_millis(20));
    r.c.state
        .write()
        .apply(ap, id, AgentMsg::Key(snapshot(2, channels, 60, client)))
        .unwrap();
}

fn feed_both(r: &Running) {
    feed(r, "ap1", [(6, 20), (36, 80), (37, 160)], true);
    feed(r, "ap2", [(6, 20), (149, 80), (69, 160)], false);
}

fn http(addr: SocketAddr, method: &str, path: &str, headers: &str, body: &str) -> (u16, Value) {
    let mut sock = TcpStream::connect(addr).unwrap();
    sock.set_read_timeout(Some(WAIT)).unwrap();
    write!(
        sock,
        "{method} {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n{headers}Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut resp = String::new();
    sock.read_to_string(&mut resp).unwrap();
    let (head, body) = resp.split_once("\r\n\r\n").unwrap();
    (
        head[9..12].parse().unwrap(),
        serde_json::from_str(body).unwrap(),
    )
}

fn plan(r: &Running) -> Value {
    let (status, v) = http(r.c.http, "GET", "/api/rf/plan", "", "");
    assert_eq!(status, 200, "{v}");
    v
}

fn radio<'a>(plan: &'a Value, key: &str) -> &'a Value {
    let radios = plan["radios"].as_array().unwrap();
    radios
        .iter()
        .find(|r| r["key"] == key)
        .unwrap_or_else(|| panic!("no {key} in {plan}"))
}

/// The body that confirms the proposals of `keys` as `plan` shows them.
fn confirm(plan: &Value, keys: &[&str]) -> String {
    let radios: Vec<Value> = keys
        .iter()
        .map(|k| {
            let mut c = radio(plan, k)["proposed"].clone();
            c["key"] = (*k).into();
            c
        })
        .collect();
    json!({ "plan": plan["hash"], "radios": radios }).to_string()
}

fn apply(r: &Running, headers: &str, body: &str) -> (u16, Value) {
    http(r.c.http, "POST", "/api/rf/apply", headers, body)
}

fn events(r: &Running, query: &str) -> Vec<Value> {
    let (_, events) = http(r.c.http, "GET", &format!("/api/events{query}"), "", "");
    events.as_array().unwrap().clone()
}

#[test]
fn the_plan_is_for_anyone_and_says_what_it_rests_on() {
    let s = Scratch::new("rf-plan");
    let r = controller(&s.dir.0, Some(&s));
    feed_both(&r);
    let p = plan(&r);
    assert_eq!(p["configured"], true);
    assert_eq!(p["window_hours"], 24);
    assert_eq!(p["site"]["file"], FILE);
    assert_eq!(
        p["site"]["rev"],
        git_in(&s.remote(), &["rev-parse", "main"]).trim()
    );
    assert_eq!(p["hash"].as_str().map(str::len), Some(16));
    assert!(
        p["notes"][0]
            .as_str()
            .unwrap()
            .contains("No AP reports scans")
    );
    assert_eq!(p["radios"].as_array().unwrap().len(), 6);
    // ap1 has the client, so ap2 leaves the 2.4 GHz channel they share.
    let ap2 = radio(&p, "ap2/radio24");
    assert_eq!(ap2["change"], true, "{ap2}");
    assert_eq!(
        ap2["current"],
        json!({"channel": 6, "width": 20, "power": 20})
    );
    assert_eq!(
        ap2["proposed"],
        json!({"channel": 1, "width": 20, "power": 20, "center": 1})
    );
    assert_eq!(ap2["runs"], json!({"channel": 6, "width": 20, "power": 20}));
    assert_eq!(
        (ap2["measured"].as_bool(), ap2["pending"].as_bool()),
        (Some(false), Some(false))
    );
    assert_eq!(ap2["busy"], 30.0);
    let ap1 = radio(&p, "ap1/radio24");
    assert_eq!(ap1["change"], false);
    // Heard at 36 dB from -59 dBm, sending at 15 dBm: it hears the AP's 20
    // at 41.
    assert_eq!(
        (ap1["snr"].as_f64(), ap1["clients"].as_f64()),
        (Some(41.0), Some(1.0))
    );
    assert_eq!(
        radio(&p, "ap2/radio5")["kept"],
        "the site file keeps its channel (planner: fixed)"
    );
}

#[test]
fn applying_a_plan_needs_an_admin_on_the_uis_page_and_what_was_confirmed() {
    let s = Scratch::new("rf-gate");
    let r = controller(&s.dir.0, Some(&s));
    feed_both(&r);
    let p = plan(&r);
    let body = confirm(&p, &["ap2/radio24"]);
    assert_eq!(
        apply(&r, ADMIN, &body),
        (403, json!({"error": "cross-site"}))
    );
    let viewer = "X-Forwarded-Preferred-Username: bob\r\n";
    assert_eq!(apply(&r, &format!("{SAME_SITE}{viewer}"), &body).0, 403);
    let admin = format!("{SAME_SITE}{ADMIN}");
    assert_eq!(apply(&r, &admin, "{\"radios\": []}").0, 400);
    let none = json!({"plan": p["hash"], "radios": []}).to_string();
    assert_eq!(apply(&r, &admin, &none).0, 400);
    // Another setting than the one proposed is not what the plan proposes.
    let mut other: Value = serde_json::from_str(&body).unwrap();
    other["radios"][0]["channel"] = 11.into();
    other["radios"][0]["center"] = 11.into();
    let (status, v) = apply(&r, &admin, &other.to_string());
    assert_eq!(
        (status, v["error"].as_str()),
        (
            409,
            Some("ap2/radio24 no longer proposes what was confirmed")
        )
    );
    // A radio that proposes no change.
    let mut same: Value = serde_json::from_str(&body).unwrap();
    same["radios"][0] =
        json!({"key": "ap1/radio5", "channel": 36, "width": 80, "center": 42, "power": 23});
    assert_eq!(apply(&r, &admin, &same.to_string()).0, 409);
    // A plan that changed since it was shown.
    let mut stale: Value = serde_json::from_str(&body).unwrap();
    stale["plan"] = "0000000000000000".into();
    let (status, v) = apply(&r, &admin, &stale.to_string());
    assert_eq!(
        (status, v["error"].as_str()),
        (409, Some("the plan changed: review it again"))
    );
    assert_eq!(s.log(), ["the site"]);
}

/// A name that is not of a radio of the site is refused before it is
/// logged, once, escaped, and on no AP.
#[test]
fn a_radio_not_of_the_site_is_refused_before_it_is_logged() {
    let s = Scratch::new("rf-names");
    let r = controller(&s.dir.0, Some(&s));
    feed_both(&r);
    let p = plan(&r);
    let admin = format!("{SAME_SITE}{ADMIN}");
    let odd = json!({"plan": p["hash"], "radios": [
        {"key": "ap9/radio5\nforged line", "channel": 1, "width": 20, "center": 1, "power": 1}
    ]});
    assert_eq!(apply(&r, &admin, &odd.to_string()).0, 400);
    let twice = json!({"plan": p["hash"], "radios": [
        {"key": "ap2/radio24", "channel": 1, "width": 20, "center": 1, "power": 20},
        {"key": "ap2/radio24", "channel": 1, "width": 20, "center": 1, "power": 20}
    ]});
    assert_eq!(apply(&r, &admin, &twice.to_string()).0, 400);
    let refused: Vec<Value> = events(&r, "")
        .into_iter()
        .filter(|e| e["action"] == "rf-plan")
        .collect();
    assert_eq!(refused.len(), 2);
    assert!(
        refused
            .iter()
            .all(|e| e.get("ap").is_none() && e["ok"] == false)
    );
    let detail = refused[0]["detail"].as_str().unwrap();
    assert!(
        !detail.contains('\n') && detail.contains("ap9/radio5\\nforged line"),
        "{detail}"
    );
}

#[test]
fn an_applied_plan_is_a_commit_an_event_and_then_pending() {
    let s = Scratch::new("rf-apply");
    let r = controller(&s.dir.0, Some(&s));
    feed_both(&r);
    let p = plan(&r);
    let (status, v) = apply(
        &r,
        &format!("{SAME_SITE}{ADMIN}"),
        &confirm(&p, &["ap2/radio24"]),
    );
    assert_eq!(status, 200, "{v}");
    let commit = v["commit"].as_str().unwrap();
    assert_eq!(git_in(&s.remote(), &["rev-parse", "main"]).trim(), commit);
    let msg = git_in(&s.remote(), &["log", "-1", "--format=%an|%B", "main"]);
    assert!(
        msg.starts_with(
            "wifi-controller|wifi: the RF planner sets ap2's 2.4 GHz radio to channel 1 at 20 MHz, 20 dBm"
        ),
        "{msg}"
    );
    assert!(
        msg.contains("Applied in the Wi-Fi controller by alice."),
        "{msg}"
    );
    let site = s.on_main(FILE);
    assert!(
        site.contains("        \"24\":\n          hw_mode: g\n          channel: 1\n"),
        "{site}"
    );
    // The event, on the AP and without a client.
    let ev = events(&r, "?ap=ap2")
        .into_iter()
        .find(|e| e["action"] == "rf-plan")
        .unwrap();
    assert_eq!(
        (ev["ok"].as_bool(), ev["user"].as_str(), ev.get("mac")),
        (Some(true), Some("alice"), None)
    );
    assert!(
        ev["detail"].as_str().unwrap().contains(&commit[..12]),
        "{ev}"
    );
    let p = plan(&r);
    assert_eq!(p["last"]["commit"], commit);
    // Until the deploy takes it to ap2, ap2 runs other than the file.
    let after = radio(&p, "ap2/radio24");
    assert_eq!(
        (after["change"].as_bool(), after["pending"].as_bool()),
        (Some(false), Some(true))
    );
    assert_eq!(
        after["kept"],
        "waiting for the deploy: it runs channel 6 at 20 MHz, the site file says channel 1 at 20 MHz"
    );
    // What it shows measured is of the channel it still runs.
    assert_eq!(after["busy"], 30.0, "{after}");
}

/// While the controller lands the plan, someone keeps ap2 in the site file
/// (`planner: fixed`) and moves ap1 onto the channel planned for ap2: made
/// again on that branch, the confirmed proposal is no longer the plan's,
/// and nothing lands.
#[test]
fn a_site_that_changed_while_the_plan_was_landing_is_reviewed_again() {
    let s = Scratch::new("rf-replan");
    let r = controller(&s.dir.0, Some(&s));
    feed_both(&r);
    let p = plan(&r);
    let theirs = SITE.replace("    ap2:\n", "    ap2:  # planner: fixed\n");
    s.push_other_during_push(&s.repo().path, FILE, &theirs);
    let (status, v) = apply(
        &r,
        &format!("{SAME_SITE}{ADMIN}"),
        &confirm(&p, &["ap2/radio24"]),
    );
    assert_eq!(status, 409, "{v}");
    assert_eq!(
        v["error"],
        "the site changed (ap2/radio24 no longer proposes what was confirmed): review the plan again"
    );
    assert_eq!(s.log(), ["meanwhile", "the site"]);
    assert_eq!(s.on_main(FILE), theirs);
}

#[test]
fn without_rf_the_planner_is_off() {
    let dir = TempDir::new("rf-off");
    let r = controller(&dir.0, None);
    let (status, v) = http(r.c.http, "GET", "/api/rf/plan", "", "");
    assert_eq!((status, v), (200, json!({"configured": false})));
    let body = json!({"plan": "x", "radios": [
        {"key": "ap1/radio5", "channel": 36, "width": 80, "center": 42, "power": 23}
    ]});
    let (status, _) = apply(&r, &format!("{SAME_SITE}{ADMIN}"), &body.to_string());
    assert_eq!(status, 404);
}
