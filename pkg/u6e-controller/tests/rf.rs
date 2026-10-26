//! The RF planner end to end: its commits landed in a scratch repository (a
//! bare remote, the controller's clone and another clone that pushes
//! meanwhile), and its API on a controller in this process whose APs' state
//! is fed in directly.

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;
use tokio::runtime::{Builder, Runtime};
use u6e_controller::agents::Timing;
use u6e_controller::config::Config;
use u6e_controller::names::Resolve;
use u6e_controller::rf::git::{self, Repo};
use u6e_controller::rf::site::{self, Change, Setting};
use u6e_controller::{Controller, start};
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
            remote: self.remote().display().to_string(),
            path: self.dir.0.join("clone"),
            branch: "main".into(),
            file: FILE.into(),
            ssh_key: None,
            known_hosts: None,
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

    /// `path` as the remote's main has it.
    fn on_main(&self, path: &str) -> String {
        git_in(&self.remote(), &["show", &format!("main:{path}")])
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

#[test]
fn a_push_turned_down_because_the_branch_moved_is_rebased_and_lands() {
    let s = Scratch::new("rf-moved");
    let repo = s.repo();
    // Someone else lands a commit after the controller fetched, before it
    // pushes: its first push is turned down.
    let landed = repo
        .land(
            |text| {
                s.push_other("README.md", "The site, meanwhile.\n");
                edit(text)
            },
            "wifi: one change\n",
        )
        .unwrap();
    assert_eq!(landed.rejected, 1);
    let log = git_in(&s.remote(), &["log", "--format=%s", "main"]);
    assert_eq!(
        log.lines().collect::<Vec<_>>(),
        ["wifi: one change", "meanwhile", "the site"]
    );
    assert_eq!(s.on_main("README.md"), "The site, meanwhile.\n");
    assert_eq!(s.on_main(FILE), edit(SITE).unwrap());
}

#[test]
fn a_push_racing_another_is_rebased_and_lands() {
    let s = Scratch::new("rf-race");
    let repo = s.repo();
    repo.fetch().unwrap();
    // The other clone lands its commit while the controller's push is under
    // way: after the remote told it where main was, before it moved main.
    let hook = repo.path.join(".git/hooks/pre-push");
    let other = s.other();
    let script = format!(
        "#!/bin/sh\n[ -e \"$0.done\" ] && exit 0\ntouch \"$0.done\"\nunset $(git rev-parse --local-env-vars)\n\
         cd '{}' && echo 'The site, meanwhile.' > README.md && \
         git -c user.name=someone -c user.email=someone@example.org commit -qam meanwhile && \
         git push -q origin HEAD:main\n",
        other.display()
    );
    fs::write(&hook, script).unwrap();
    Command::new("chmod").arg("+x").arg(&hook).status().unwrap();
    let landed = repo.land(edit, "wifi: one change\n").unwrap();
    assert_eq!(landed.rejected, 1);
    let log = git_in(&s.remote(), &["log", "--format=%s", "main"]);
    assert_eq!(
        log.lines().collect::<Vec<_>>(),
        ["wifi: one change", "meanwhile", "the site"]
    );
    assert_eq!(s.on_main(FILE), edit(SITE).unwrap());
}

#[test]
fn a_rebase_that_conflicts_gives_up_and_leaves_nothing() {
    let s = Scratch::new("rf-conflict");
    let repo = s.repo();
    // Meanwhile the same line of the site file is changed another way.
    let theirs = edit(SITE)
        .unwrap()
        .replace("          channel: 1\n", "          channel: 11\n");
    let landed = repo.land(
        |text| {
            s.push_other(FILE, &theirs);
            edit(text)
        },
        "wifi: one change\n",
    );
    assert_eq!(landed, Err(git::Error::Conflict));
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
    assert_eq!(
        git_in(&s.remote(), &["log", "--format=%s", "main"]).trim(),
        "the site"
    );
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
    assert_eq!(
        git_in(&s.remote(), &["rev-list", "--count", "main"]).trim(),
        "1"
    );
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
             [rf.channels.KR]\n\"24\" = [{{ channels = \"1-13\", max_dbm = 23 }}]\n\
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
        vlan: 42,
    }
}

/// A snapshot of an AP on the fixture's channels, its counters at `secs`,
/// with one client on its 2.4 GHz radio when `client`.
fn snapshot(seq: u64, channels: [(u16, u16); 3], secs: u64, client: bool) -> Snapshot {
    let bands = [
        (Band::B24, "radio24"),
        (Band::B5, "radio5"),
        (Band::B6, "radio6"),
    ];
    let radios = bands
        .iter()
        .zip(channels)
        .map(|((band, phy), (channel, width))| Radio {
            phy: (*phy).into(),
            band: *band,
            channel,
            width_mhz: width,
            txpower_mbm: 2000,
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
        .map(|(i, (_, phy))| Bss {
            ifname: format!("wlan{i}"),
            bssid: [2, 0, 0, 0, 1, i as u8],
            ssid: "ssid-a".into(),
            phy: (*phy).into(),
            vlan: 42,
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

fn apply(r: &Running, headers: &str, body: &str) -> (u16, Value) {
    http(r.c.http, "POST", "/api/rf/apply", headers, body)
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
        serde_json::json!({"channel": 6, "width": 20, "power": 20})
    );
    assert_eq!(ap2["measured"], false);
    assert_eq!(ap2["busy"], 30.0);
    let ap1 = radio(&p, "ap1/radio24");
    assert_eq!(ap1["change"], false);
    assert_eq!(
        (ap1["snr"].as_f64(), ap1["clients"].as_f64()),
        (Some(36.0), Some(1.0))
    );
    assert_eq!(
        radio(&p, "ap2/radio5")["kept"],
        "the site file keeps its channel (planner: fixed)"
    );
}

#[test]
fn applying_a_plan_needs_an_admin_on_the_uis_page_and_a_change() {
    let s = Scratch::new("rf-gate");
    let r = controller(&s.dir.0, Some(&s));
    feed_both(&r);
    let body = r#"{"radios": ["ap2/radio24"]}"#;
    assert_eq!(
        apply(&r, ADMIN, body),
        (403, serde_json::json!({"error": "cross-site"}))
    );
    let viewer = "X-Forwarded-Preferred-Username: bob\r\n";
    assert_eq!(apply(&r, &format!("{SAME_SITE}{viewer}"), body).0, 403);
    let admin = format!("{SAME_SITE}{ADMIN}");
    assert_eq!(apply(&r, &admin, "{\"radio\": []}").0, 400);
    assert_eq!(apply(&r, &admin, r#"{"radios": []}"#).0, 400);
    let (status, v) = apply(&r, &admin, r#"{"radios": ["ap1/radio5"]}"#);
    assert_eq!(
        (status, v["error"].as_str()),
        (409, Some("ap1/radio5 no longer proposes a change"))
    );
    let (status, _) = apply(&r, &admin, r#"{"radios": ["ap9/radio5"]}"#);
    assert_eq!(status, 409);
    // Nothing reached the remote.
    assert_eq!(
        git_in(&s.remote(), &["rev-list", "--count", "main"]).trim(),
        "1"
    );
}

#[test]
fn an_applied_plan_is_a_commit_an_event_and_then_out_of_step_until_deployed() {
    let s = Scratch::new("rf-apply");
    let r = controller(&s.dir.0, Some(&s));
    feed_both(&r);
    let proposed = radio(&plan(&r), "ap2/radio24")["proposed"].clone();
    let (status, v) = apply(
        &r,
        &format!("{SAME_SITE}{ADMIN}"),
        r#"{"radios": ["ap2/radio24"]}"#,
    );
    assert_eq!(status, 200, "{v}");
    let commit = v["commit"].as_str().unwrap();
    assert_eq!(git_in(&s.remote(), &["rev-parse", "main"]).trim(), commit);
    let msg = git_in(&s.remote(), &["log", "-1", "--format=%an|%B", "main"]);
    let channel = proposed["channel"].as_u64().unwrap();
    assert!(msg.starts_with(&format!("wifi-controller|wifi: the RF planner sets ap2's 2.4 GHz radio to channel {channel} at 20 MHz, 20 dBm")), "{msg}");
    assert!(
        msg.contains("Applied in the Wi-Fi controller by alice."),
        "{msg}"
    );
    let site = s.on_main(FILE);
    assert!(
        site.contains(&format!(
            "        \"24\":\n          hw_mode: g\n          channel: {channel}\n"
        )),
        "{site}"
    );
    // The event, on the AP and without a client.
    let (_, events) = http(r.c.http, "GET", "/api/events?ap=ap2", "", "");
    let ev = events
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["action"] == "rf-plan")
        .unwrap()
        .clone();
    assert_eq!(
        (ev["ok"].as_bool(), ev["user"].as_str(), ev.get("mac")),
        (Some(true), Some("alice"), None)
    );
    assert!(
        ev["detail"].as_str().unwrap().contains(&commit[..12]),
        "{ev}"
    );
    // Until the deploy path takes it to ap2, ap2 runs other than the file.
    let p = plan(&r);
    assert_eq!(p["last"]["commit"], commit);
    let after = radio(&p, "ap2/radio24");
    assert_eq!(after["change"], false);
    assert!(
        after["kept"]
            .as_str()
            .unwrap()
            .contains("has not reached it yet"),
        "{after}"
    );
    // What it shows measured is of the channel it still runs.
    assert_eq!(after["busy"], 30.0, "{after}");
}

#[test]
fn without_rf_the_planner_is_off() {
    let dir = TempDir::new("rf-off");
    let r = controller(&dir.0, None);
    let (status, v) = http(r.c.http, "GET", "/api/rf/plan", "", "");
    assert_eq!((status, v), (200, serde_json::json!({"configured": false})));
    let (status, _) = apply(
        &r,
        &format!("{SAME_SITE}{ADMIN}"),
        r#"{"radios": ["ap1/radio5"]}"#,
    );
    assert_eq!(status, 404);
}
