//! The MAC → VLAN mapping RADIUS's MAC authentication puts devices in
//! (`[mac_auth]`): an OpenBao KV-v2 secret,
//! `{"vlans": {<group>: {"id": <VLAN>, "devices": [{"mac", "description"}]}}}`,
//! which every RADIUS server reads on its own and authenticates from, so the
//! controller is never in the authentication path: it reads the mapping, and
//! an admin's change is one write of it.
//!
//! [`supervise`] reads it every minute with the token in its file (re-read
//! at each request), keeping the last mapping read when a read fails. An
//! admin sets, moves or removes one device's entry (`POST
//! /api/clients/{mac}/vlan`, [`change`]): `{"vlan": n | null, "description",
//! "expect": n | null}`, `expect` being the VLAN the admin saw, so a change
//! made meanwhile by someone else is refused rather than undone. The
//! controller reads the mapping afresh, edits that one entry in the tree it
//! read (everything else in it kept as it is), and writes it with
//! check-and-set on the version read, reading and editing again when
//! another writer came first, three times at most; one change at a time.
//! The VLAN must be one of `vlans`, the mapping hold at most `entries_max`
//! entries; the MAC is written as RADIUS keys it, `aa-bb-cc-dd-ee-ff`. A
//! mapping holding anything RADIUS refuses (which makes it keep its last
//! good one) takes no change until it is fixed in OpenBao. A write whose
//! answer is lost is settled by reading the mapping again. The description
//! is the admin's or the client's name, without control or format
//! characters, 64 at most. Each change is an action `vlan` on the client,
//! with the admin's name.
//!
//! A device moved onto a VLAN while it is on one of the MAC-authenticated
//! `ssids` is then kicked once, 90 s after the write (by when every
//! RADIUS server has taken it), so it joins again into its new VLAN; a newer
//! change replaces a pending kick. The VLAN it comes back on within two
//! minutes is recorded, which says whether RADIUS had the change. A removal
//! kicks nothing: the device stays on until it leaves, and cannot join
//! again.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use axum::body::Bytes;
use axum::extract::{Path, State as Ext};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};
use tokio::sync::Mutex;
use tokio::time::{interval, sleep};
use u6e_proto::mac;
use u6e_proto::msg::CommandKind;

use crate::actions::{self, Ctx, Via, Web};
use crate::fetch;
use crate::http::{error, json_response};
use crate::sessions::unix_ms;
use crate::state::{Action, Change, Shared, State};

/// The most entries the controller lets the mapping hold, unless set.
pub const ENTRIES_MAX: usize = 512;
/// The longest one request may take, and the largest answer read.
const REQUEST_WAIT: Duration = Duration::from_secs(10);
const ANSWER_MAX: usize = 1 << 20;
/// The writes one change may take, each after another writer came first.
const WRITE_TRIES: usize = 3;
/// The longest description an admin may give.
pub const DESCRIPTION_MAX: usize = 64;

/// Whether `c` is a format character (Unicode's Cf): invisible, it can
/// reorder or hide what a description says.
fn is_format(c: char) -> bool {
    matches!(c as u32,
        0xad | 0x600..=0x605 | 0x61c | 0x6dd | 0x70f | 0x890..=0x891 | 0x8e2 | 0x180e
        | 0x200b..=0x200f | 0x202a..=0x202e | 0x2060..=0x2064 | 0x2066..=0x206f | 0xfeff
        | 0xfff9..=0xfffb | 0x110bd | 0x110cd | 0x13430..=0x1343f | 0x1bca0..=0x1bca3
        | 0x1d173..=0x1d17a | 0xe0001 | 0xe0020..=0xe007f)
}

/// An admin's description without its format characters; why it is
/// refused.
pub fn description(d: &str) -> Result<String, &'static str> {
    let d: String = d.trim().chars().filter(|c| !is_format(*c)).collect();
    if d.chars().count() > DESCRIPTION_MAX || d.chars().any(char::is_control) {
        return Err("the description is over 64 characters or holds a control character");
    }
    Ok(d)
}

/// A client's name as a description: without control or format characters,
/// 64 at most.
pub fn name_description(name: &str) -> String {
    let d: String = name
        .chars()
        .filter(|c| !is_format(*c) && !c.is_control())
        .collect();
    d.trim().chars().take(DESCRIPTION_MAX).collect()
}

/// `[mac_auth]`, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// OpenBao's host and port (`https://host[:port]`).
    pub host: String,
    pub port: u16,
    /// The PEM bundle its certificate's chain is checked against.
    pub ca: PathBuf,
    /// The file of the token the controller reads and writes with.
    pub token: PathBuf,
    /// The KV-v2 mount and the secret's path in it.
    pub mount: String,
    pub path: String,
    /// The VLANs an admin may put a device in.
    pub vlans: Vec<u16>,
    /// The SSIDs whose clients MAC authentication places.
    pub ssids: Vec<String>,
    pub entries_max: usize,
}

/// How long the mapping's reads and kicks wait (`Timing::mac_auth`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Waits {
    /// Between two reads.
    pub read: Duration,
    /// From a write to the kick: a minute between each RADIUS server's
    /// reads, and margin.
    pub settle: Duration,
    /// For a kicked device to come back, for its VLAN to be recorded.
    pub back: Duration,
}

impl Default for Waits {
    fn default() -> Self {
        Waits {
            read: Duration::from_secs(60),
            settle: Duration::from_secs(90),
            back: Duration::from_secs(120),
        }
    }
}

/// One device's entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub vlan: u16,
    /// The group of the mapping it is in.
    pub group: String,
    pub description: String,
}

/// The mapping as read: the tree, its KV version, its entries by MAC, and
/// what of it RADIUS refuses (the mapping whole: it keeps its last good
/// one), which blocks every change until it is fixed in OpenBao.
#[derive(Debug, Clone, PartialEq)]
pub struct Mapping {
    pub version: u64,
    tree: Value,
    pub entries: BTreeMap<[u8; 6], Entry>,
    pub unread: Vec<String>,
}

/// A device kicked, or about to be, to join again into a new VLAN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Follow {
    pub from: Option<u16>,
    pub to: u16,
    pub user: Option<String>,
    /// When it is kicked, then when it was.
    pub kick_at: SystemTime,
    pub kicked: bool,
    generation: u64,
}

/// The mapping as the controller knows it.
#[derive(Debug)]
pub struct MacAuth {
    pub settings: Settings,
    pub waits: Waits,
    pub mapping: Option<Mapping>,
    /// When a read last worked, and why the last one did not.
    pub read_at: Option<SystemTime>,
    pub error: Option<String>,
    pub follows: BTreeMap<[u8; 6], Follow>,
    /// Changes by result: ok, unchanged, conflict, refused, failed.
    pub changes: BTreeMap<&'static str, u64>,
    generation: u64,
    /// One change at a time.
    writing: Arc<Mutex<()>>,
}

impl MacAuth {
    pub fn new(settings: &Settings, waits: Waits) -> Self {
        MacAuth {
            settings: settings.clone(),
            waits,
            mapping: None,
            read_at: None,
            error: None,
            follows: BTreeMap::new(),
            changes: RESULTS.iter().map(|r| (*r, 0)).collect(),
            generation: 0,
            writing: Arc::new(Mutex::new(())),
        }
    }
}

/// Every result a change is counted under.
pub const RESULTS: [&str; 5] = ["ok", "unchanged", "conflict", "refused", "failed"];

/// The MAC as RADIUS keys it: `aa-bb-cc-dd-ee-ff`.
pub fn key(m: [u8; 6]) -> String {
    m.map(|b| format!("{b:02x}")).join("-")
}

/// A MAC in any spelling RADIUS's rewrite accepts: twelve hex digits, bare
/// or in pairs joined by one of `:` or `-`, in either case.
pub fn parse_key(s: &str) -> Option<[u8; 6]> {
    let s = s.trim();
    let digits = match s.len() {
        12 => s.to_owned(),
        17 => {
            let sep = s.as_bytes()[2];
            let pairs: Vec<&str> = s.split(char::from(sep)).collect();
            if !matches!(sep, b':' | b'-') || pairs.len() != 6 || pairs.iter().any(|p| p.len() != 2)
            {
                return None;
            }
            pairs.concat()
        }
        _ => return None,
    };
    mac::unhex(&digits)
}

impl Mapping {
    /// The mapping KV version `version` holds (`data`, `None` while there
    /// is no secret), `vlans` being the site's; refused only when it has a
    /// `vlans` that is no object, which the controller could not edit
    /// without losing what it holds.
    pub fn from_kv(data: Option<Value>, version: u64, vlans: &[u16]) -> Result<Self, String> {
        let tree = data.unwrap_or_else(|| json!({}));
        if !tree.is_object() {
            return Err("the mapping is not a JSON object".into());
        }
        let mut entries = BTreeMap::new();
        let mut unread = Vec::new();
        match tree.get("vlans") {
            None if version == 0 => {}
            None => unread.push("the mapping has no vlans; RADIUS refuses it".into()),
            Some(Value::Object(groups)) => {
                for (group, g) in groups {
                    read_group(group, g, vlans, &mut entries, &mut unread);
                }
            }
            Some(_) => return Err("the mapping's vlans is not an object".into()),
        }
        Ok(Mapping {
            version,
            tree,
            entries,
            unread,
        })
    }

    /// The group `vlan` is, empty or not.
    pub fn group(&self, vlan: u16) -> Option<&str> {
        let groups = self.tree.get("vlans")?.as_object()?;
        let id = |g: &Value| g.get("id").and_then(Value::as_u64);
        let mut named = groups
            .iter()
            .filter(|(_, g)| id(g) == Some(u64::from(vlan)));
        named.next().map(|(n, _)| n.as_str())
    }

    /// The tree with `m`'s entry set to `to` (a VLAN and a description) or
    /// removed, everything else as it was; why not.
    pub fn edit(&self, m: [u8; 6], to: Option<(u16, &str)>, max: usize) -> Result<Value, String> {
        let mut tree = self.tree.clone();
        let root = tree.as_object_mut().expect("checked in from_kv");
        let groups = root
            .entry("vlans")
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .expect("checked in from_kv");
        for g in groups.values_mut() {
            if let Some(Value::Array(devices)) = g.get_mut("devices") {
                devices.retain(|d| {
                    d.get("mac").and_then(Value::as_str).and_then(parse_key) != Some(m)
                });
            }
        }
        let Some((vlan, description)) = to else {
            return Ok(tree);
        };
        if !self.entries.contains_key(&m) && self.entries.len() >= max {
            return Err(format!(
                "the mapping holds {} entries, the most it may",
                self.entries.len()
            ));
        }
        let name = groups
            .iter()
            .find(|(_, g)| g.get("id").and_then(Value::as_u64) == Some(u64::from(vlan)))
            .map(|(n, _)| n.clone());
        let name = match name {
            Some(n) => n,
            None => {
                let n = format!("vlan-{vlan}");
                if groups.contains_key(&n) {
                    return Err(format!("the mapping's group {n} is not VLAN {vlan}"));
                }
                groups.insert(n.clone(), json!({ "id": vlan, "devices": [] }));
                n
            }
        };
        let group = groups.get_mut(&name).expect("found or made");
        let devices = group
            .as_object_mut()
            .ok_or_else(|| format!("the mapping's group {name} is not an object"))?
            .entry("devices")
            .or_insert_with(|| Value::Array(Vec::new()));
        if devices.is_null() {
            *devices = Value::Array(Vec::new());
        }
        let devices = devices
            .as_array_mut()
            .ok_or_else(|| format!("the mapping's group {name}'s devices is not a list"))?;
        devices.push(json!({ "mac": key(m), "description": description }));
        Ok(tree)
    }
}

/// The entries of one group, and what of it RADIUS refuses.
fn read_group(
    group: &str,
    g: &Value,
    vlans: &[u16],
    entries: &mut BTreeMap<[u8; 6], Entry>,
    unread: &mut Vec<String>,
) {
    let vlan = g.get("id").and_then(Value::as_u64);
    let Some(vlan) = vlan.filter(|v| (1..=4094).contains(v)) else {
        unread.push(format!("group {group}: no VLAN 1-4094"));
        return;
    };
    // Its devices are still read: they show where they were meant to go.
    if !vlans.contains(&(vlan as u16)) {
        unread.push(format!(
            "group {group}: VLAN {vlan} is not one of the site's"
        ));
    }
    let devices = match g.get("devices") {
        None | Some(Value::Null) => return,
        Some(Value::Array(d)) => d,
        Some(_) => {
            unread.push(format!("group {group}: devices is not a list"));
            return;
        }
    };
    for d in devices {
        let raw = d.get("mac").and_then(Value::as_str);
        let Some(m) = raw.and_then(parse_key).filter(|m| mac::is_station(*m)) else {
            unread.push(format!(
                "group {group}: {} is no station's MAC",
                raw.unwrap_or("(none)")
            ));
            continue;
        };
        if let Some(first) = entries.get(&m) {
            unread.push(format!(
                "{} is in groups {} and {group}",
                mac::format(m),
                first.group
            ));
            continue;
        }
        let description = d
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let entry = Entry {
            vlan: vlan as u16,
            group: group.to_owned(),
            description: description.to_owned(),
        };
        entries.insert(m, entry);
    }
}

/// Why a read or a write did not work.
#[derive(Debug, PartialEq, Eq)]
enum Failure {
    /// Another writer came first.
    Conflict,
    /// No answer: OpenBao may have taken the write or not.
    Lost(String),
    Other(String),
}

/// The secret's KV path, under `kind` (`data`, `metadata`).
fn target(s: &Settings, kind: &str) -> String {
    format!("/v1/{}/{kind}/{}", s.mount, s.path)
}

/// The mapping and its version now; why not.
async fn read(s: &Settings) -> Result<Mapping, String> {
    let (token, _) = fetch::read_token(&s.token)?;
    let auth = ("X-Vault-Token: ", token.0.as_str());
    let host = (s.host.as_str(), s.port);
    let get = ("GET", target(s, "data"));
    let get = (get.0, get.1.as_str());
    let a = fetch::request_tls(host, get, &s.ca, auth, None, ANSWER_MAX, REQUEST_WAIT).await?;
    match a.status {
        200 => {}
        404 => return Mapping::from_kv(None, 0, &s.vlans),
        n => return Err(bao_error(n, &a.body)),
    }
    let v: Value = serde_json::from_str(&a.body).map_err(|_| "OpenBao's answer is not JSON")?;
    let version = v["data"]["metadata"]["version"].as_u64();
    let version = version.ok_or("OpenBao's answer is not a KV-v2 secret")?;
    Mapping::from_kv(Some(v["data"]["data"].clone()), version, &s.vlans)
}

/// Writes `tree` over version `cas`; the version written.
async fn write(s: &Settings, tree: &Value, cas: u64) -> Result<u64, Failure> {
    let (token, _) = fetch::read_token(&s.token).map_err(Failure::Other)?;
    let auth = ("X-Vault-Token: ", token.0.as_str());
    let host = (s.host.as_str(), s.port);
    let path = target(s, "data");
    let body = json!({ "options": { "cas": cas }, "data": tree }).to_string();
    let post = ("POST", path.as_str());
    let a = fetch::request_tls(
        host,
        post,
        &s.ca,
        auth,
        Some(&body),
        ANSWER_MAX,
        REQUEST_WAIT,
    )
    .await
    .map_err(Failure::Lost)?;
    if a.status == 400 && a.body.contains("check-and-set") {
        return Err(Failure::Conflict);
    }
    if a.status != 200 {
        return Err(Failure::Other(bao_error(a.status, &a.body)));
    }
    let v: Value = serde_json::from_str(&a.body).unwrap_or_default();
    v["data"]["version"]
        .as_u64()
        .ok_or_else(|| Failure::Other("OpenBao's answer names no version".into()))
}

/// What OpenBao answered, with its errors (which never hold the token).
fn bao_error(status: u16, body: &str) -> String {
    let v: Value = serde_json::from_str(body).unwrap_or_default();
    let errors: Vec<&str> = v["errors"]
        .as_array()
        .map(|e| e.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if errors.is_empty() {
        format!("OpenBao answered {status}")
    } else {
        format!("OpenBao answered {status}: {}", errors.join("; "))
    }
}

/// Reads the mapping every `every` (a minute), for the life of the process.
pub async fn supervise(state: Shared, settings: Settings, every: Duration) {
    let mut every = interval(every);
    loop {
        every.tick().await;
        let read = read(&settings).await;
        let mut s = state.write();
        let Some(m) = s.mac_auth.as_mut() else { return };
        match read {
            Ok(mapping) => {
                if m.error.is_some() {
                    eprintln!("u6e-controller: mac_auth: the mapping is read again");
                }
                m.mapping = Some(mapping);
                m.read_at = Some(SystemTime::now());
                m.error = None;
            }
            Err(why) => {
                if m.error.as_deref() != Some(why.as_str()) {
                    eprintln!("u6e-controller: mac_auth: the mapping is not read: {why}");
                }
                m.error = Some(why);
            }
        }
        s.notify(Change::MacAuth);
    }
}

/// The view: the mapping as last read and how reading it goes, the VLANs
/// an admin may choose (with their groups), the MAC-authenticated SSIDs and
/// the devices about to be kicked.
pub fn view(m: &MacAuth) -> Value {
    let entries: Map<String, Value> = m
        .mapping
        .iter()
        .flat_map(|map| &map.entries)
        .map(|(mac, e)| {
            let v = json!({ "vlan": e.vlan, "group": e.group, "description": e.description });
            (mac::format(*mac), v)
        })
        .collect();
    let group = |vlan: u16| m.mapping.as_ref().and_then(|map| map.group(vlan));
    let vlans: Vec<Value> = m
        .settings
        .vlans
        .iter()
        .map(|v| json!({ "id": v, "group": group(*v) }))
        .collect();
    let follows: Map<String, Value> = m
        .follows
        .iter()
        .map(|(mac, f)| {
            let v = json!({ "from": f.from, "to": f.to, "user": f.user,
                            "kick_at": unix_ms(f.kick_at), "kicked": f.kicked });
            (mac::format(*mac), v)
        })
        .collect();
    json!({
        "version": m.mapping.as_ref().map(|map| map.version),
        "read_at": m.read_at.map(unix_ms),
        "error": m.error,
        "entries": entries,
        "unread": m.mapping.as_ref().map(|map| map.unread.clone()).unwrap_or_default(),
        "vlans": vlans,
        "ssids": m.settings.ssids,
        "max": m.settings.entries_max,
        "settle_secs": m.waits.settle.as_secs(),
        "follows": follows,
    })
}

/// `GET /api/mac-auth`: the view, for any signed-in user.
pub async fn get(Ext(state): Ext<Shared>) -> Response {
    match &state.read().mac_auth {
        Some(m) => json_response(&view(m)),
        None => error(StatusCode::NOT_FOUND, "the controller has no [mac_auth]"),
    }
}

/// What an admin asks: the device's VLAN (none removes its entry), its
/// description, and the VLAN they saw it in.
struct Ask {
    vlan: Option<u16>,
    description: Option<String>,
    expect: Option<u16>,
}

/// The body, with `vlan` and `expect` each present, a number or null.
fn ask(body: &[u8]) -> Result<Ask, &'static str> {
    const SHAPE: &str = "not {\"vlan\": n | null, \"expect\": n | null, \"description\"}";
    let v: Value = serde_json::from_slice(body).map_err(|_| SHAPE)?;
    let o = v.as_object().ok_or(SHAPE)?;
    if o.keys()
        .any(|k| !matches!(k.as_str(), "vlan" | "expect" | "description"))
    {
        return Err(SHAPE);
    }
    let vlan_of = |k: &str| -> Result<Option<u16>, &'static str> {
        match o.get(k) {
            Some(Value::Null) => Ok(None),
            Some(n) => n
                .as_u64()
                .and_then(|n| u16::try_from(n).ok())
                .map(Some)
                .ok_or(SHAPE),
            None => Err(SHAPE),
        }
    };
    let description = match o.get("description") {
        None | Some(Value::Null) => None,
        Some(Value::String(d)) => Some(d.trim().to_owned()),
        Some(_) => return Err(SHAPE),
    };
    Ok(Ask {
        vlan: vlan_of("vlan")?,
        description,
        expect: vlan_of("expect")?,
    })
}

/// How a change came out, for its answer and its count.
enum Done {
    /// The mapping written, at its new version, and the VLAN the device
    /// had.
    Written {
        mapping: Mapping,
        from: Option<u16>,
    },
    Unchanged,
    Conflict(String),
    /// The mapping holds what RADIUS refuses: nothing written.
    Refused(String),
    Failed(String),
}

/// `POST /api/clients/{mac}/vlan`: an admin's change of one entry.
pub async fn change(
    Ext(web): Ext<Web>,
    Path(m): Path<String>,
    req: HeaderMap,
    body: Bytes,
) -> Response {
    let what = format!("vlan {m}");
    if let Some(why) = actions::refusal(&req, &web.access, Via::Post, &what) {
        return error(StatusCode::FORBIDDEN, why);
    }
    let Some((settings, writing)) = web
        .state
        .read()
        .mac_auth
        .as_ref()
        .map(|a| (a.settings.clone(), Arc::clone(&a.writing)))
    else {
        return error(StatusCode::NOT_FOUND, "the controller has no [mac_auth]");
    };
    let refuse = |why: &str| {
        count(&web.state, "refused");
        error(StatusCode::BAD_REQUEST, why)
    };
    let Some(m) = mac::parse(&m).filter(|m| mac::is_station(*m)) else {
        return refuse("not a station's MAC");
    };
    let a = match ask(&body) {
        Ok(a) => a,
        Err(why) => return refuse(why),
    };
    if let Some(v) = a.vlan
        && !settings.vlans.contains(&v)
    {
        return refuse("not a VLAN the site lets a device be put in");
    }
    let a = match a.description.as_deref().map(description).transpose() {
        Ok(d) => Ask {
            description: d,
            ..a
        },
        Err(why) => return refuse(why),
    };
    let user = actions::user(&req);
    let name = web.state.read().identity(&m).name().map(name_description);
    let _one = writing.lock().await;
    let done = write_one(&settings, m, &a, name.as_deref()).await;
    finish(&web, m, &a, user, done)
}

/// Reads, edits and writes, again after another writer came first.
async fn write_one(s: &Settings, m: [u8; 6], a: &Ask, name: Option<&str>) -> Done {
    for _ in 0..WRITE_TRIES {
        let mapping = match read(s).await {
            Ok(map) => map,
            Err(why) => return Done::Failed(why),
        };
        if !mapping.unread.is_empty() {
            let why = mapping.unread.join("; ");
            return Done::Refused(format!("RADIUS refuses the mapping as it is ({why})"));
        }
        let now = mapping.entries.get(&m);
        let from = now.map(|e| e.vlan);
        if from != a.expect {
            let is = from.map_or_else(|| "no entry".into(), |v| format!("VLAN {v}"));
            return Done::Conflict(format!("changed meanwhile: it has {is} now"));
        }
        let description = a
            .description
            .clone()
            .or_else(|| now.map(|e| e.description.clone()))
            .or_else(|| name.map(str::to_owned))
            .unwrap_or_default();
        let unchanged = match (now, a.vlan) {
            (None, None) => true,
            (Some(e), Some(v)) => e.vlan == v && e.description == description,
            _ => false,
        };
        if unchanged {
            return Done::Unchanged;
        }
        let tree = match mapping.edit(m, a.vlan.map(|v| (v, description.as_str())), s.entries_max) {
            Ok(t) => t,
            Err(why) => return Done::Failed(why),
        };
        match write(s, &tree, mapping.version).await {
            Ok(version) => {
                let mapping =
                    Mapping::from_kv(Some(tree), version, &s.vlans).expect("edited from one");
                return Done::Written { mapping, from };
            }
            Err(Failure::Conflict) => continue,
            Err(Failure::Lost(why)) => {
                let to = a.vlan.map(|v| (v, description.as_str()));
                return settle(s, m, mapping.version, to, from, why).await;
            }
            Err(Failure::Other(why)) => return Done::Failed(why),
        }
    }
    Done::Failed(format!("{WRITE_TRIES} writes, each after another writer's"))
}

/// A write over version `cas` whose answer was lost, settled by reading
/// the mapping again: written when a newer version has `m`'s entry as the
/// change made it (`to`), not when the version is still `cas`.
async fn settle(
    s: &Settings,
    m: [u8; 6],
    cas: u64,
    to: Option<(u16, &str)>,
    from: Option<u16>,
    why: String,
) -> Done {
    let mapping = match read(s).await {
        Ok(map) => map,
        Err(again) => {
            return Done::Failed(format!(
                "{why}; whether it was written is not known: {again}"
            ));
        }
    };
    let now = mapping
        .entries
        .get(&m)
        .map(|e| (e.vlan, e.description.as_str()));
    if mapping.version > cas && now == to {
        return Done::Written { mapping, from };
    }
    if mapping.version == cas {
        return Done::Failed(format!("{why}; not written"));
    }
    Done::Failed(format!(
        "{why}; another writer changed the mapping meanwhile, not to this"
    ))
}

fn count(state: &Shared, result: &'static str) {
    if let Some(m) = state.write().mac_auth.as_mut() {
        *m.changes.entry(result).or_default() += 1;
    }
}

/// A VLAN, or none, as a timeline says it.
fn vlan_text(v: Option<u16>) -> String {
    v.map_or_else(|| "no entry".into(), |v| format!("VLAN {v}"))
}

/// Records and answers how a change came out, and follows a written move.
fn finish(web: &Web, m: [u8; 6], a: &Ask, user: Option<String>, done: Done) -> Response {
    let (status, result, ok, detail) = match &done {
        Done::Written { mapping, from } => {
            let to = vlan_text(a.vlan);
            let detail = format!(
                "{} → {to} (mapping version {})",
                vlan_text(*from),
                mapping.version
            );
            (StatusCode::OK, "ok", true, detail)
        }
        Done::Unchanged => (StatusCode::OK, "unchanged", true, "unchanged".into()),
        Done::Conflict(why) => (StatusCode::CONFLICT, "conflict", false, why.clone()),
        Done::Refused(why) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "refused",
            false,
            why.clone(),
        ),
        Done::Failed(why) => (StatusCode::BAD_GATEWAY, "failed", false, why.clone()),
    };
    count(&web.state, result);
    if !matches!(done, Done::Unchanged) {
        web.state.write().record(Action {
            at: SystemTime::now(),
            user: user.clone(),
            action: "vlan",
            mac: Some(m),
            ap: None,
            ok,
            detail: detail.clone(),
        });
    }
    let mut answer = json!({ "ok": ok, "result": result, "detail": detail });
    if let Done::Written { mapping, from } = done {
        // What was written is the mapping now: the page sees it at once.
        if let Some(ma) = web.state.write().mac_auth.as_mut() {
            ma.mapping = Some(mapping);
        }
        answer["kick"] = follow(web, m, from, a.vlan, user).into();
        web.state.read().notify(Change::MacAuth);
    }
    (status, json_response(&answer)).into_response()
}

/// Whether the client is on a MAC-authenticated SSID.
fn on_mab(state: &State, ssids: &[String], m: [u8; 6]) -> bool {
    let c = state.clients().into_iter().find(|c| c.station.mac == m);
    c.is_some_and(|c| ssids.contains(&c.ssid))
}

/// Starts following a move onto `to`, replacing a pending one; what the
/// page is told of the kick.
fn follow(
    web: &Web,
    m: [u8; 6],
    from: Option<u16>,
    to: Option<u16>,
    user: Option<String>,
) -> String {
    let mut s = web.state.write();
    let ssids = s
        .mac_auth
        .as_ref()
        .map(|a| a.settings.ssids.clone())
        .unwrap_or_default();
    let on = on_mab(&s, &ssids, m);
    let Some(ma) = s.mac_auth.as_mut() else {
        return String::new();
    };
    ma.follows.remove(&m);
    let Some(to) = to else {
        return "none: a removed device stays on until it leaves, and cannot join again".into();
    };
    if !on {
        return "none: it is on no MAC-authenticated SSID; it joins the new VLAN when it next does"
            .into();
    }
    ma.generation += 1;
    let waits = ma.waits;
    let f = Follow {
        from,
        to,
        user,
        kick_at: SystemTime::now() + waits.settle,
        kicked: false,
        generation: ma.generation,
    };
    let generation = f.generation;
    ma.follows.insert(m, f);
    s.notify(Change::MacAuth);
    drop(s);
    tokio::spawn(kick_and_watch(web.clone(), m, generation, waits));
    format!(
        "once, in {} s, to join again on VLAN {to}",
        waits.settle.as_secs()
    )
}

/// The follow of `m` if it is still `generation`'s.
fn current(state: &State, m: [u8; 6], generation: u64) -> Option<Follow> {
    let f = state.mac_auth.as_ref()?.follows.get(&m)?;
    (f.generation == generation).then(|| f.clone())
}

/// Ends the follow of `m` (if still `generation`'s), recording `detail`.
fn end(
    state: &Shared,
    m: [u8; 6],
    generation: u64,
    f: &Follow,
    ap: Option<String>,
    ok: bool,
    detail: String,
) {
    let mut s = state.write();
    if current(&s, m, generation).is_none() {
        return;
    }
    if let Some(ma) = s.mac_auth.as_mut() {
        ma.follows.remove(&m);
    }
    s.record(Action {
        at: SystemTime::now(),
        user: f.user.clone(),
        action: "vlan",
        mac: Some(m),
        ap,
        ok,
        detail,
    });
    s.notify(Change::MacAuth);
}

/// After the settle time, kicks the device if it is still on a
/// MAC-authenticated SSID, and records the VLAN it comes back on.
async fn kick_and_watch(web: Web, m: [u8; 6], generation: u64, waits: Waits) {
    sleep(waits.settle).await;
    let (f, on) = {
        let s = web.state.read();
        let Some(f) = current(&s, m, generation) else {
            return;
        };
        let ssids = s
            .mac_auth
            .as_ref()
            .map(|a| a.settings.ssids.clone())
            .unwrap_or_default();
        (f, on_mab(&s, &ssids, m))
    };
    let to = f.to;
    if !on {
        let detail = format!("not kicked: it left first; it joins VLAN {to} when it comes back");
        end(&web.state, m, generation, &f, None, true, detail);
        return;
    }
    if let Some(ma) = web.state.write().mac_auth.as_mut()
        && let Some(cur) = ma.follows.get_mut(&m)
    {
        cur.kicked = true;
        cur.kick_at = SystemTime::now();
    }
    let ctx = Ctx {
        state: &web.state,
        user: f.user.clone(),
        action: "kick",
        mac: Some(m),
        about: format!("to join again on VLAN {to}"),
    };
    let kicked = Instant::now();
    let answer = ctx
        .where_it_is(&web.access, CommandKind::Kick { mac: m })
        .await;
    if !answer.status().is_success() {
        end(
            &web.state,
            m,
            generation,
            &f,
            None,
            false,
            format!("the kick to VLAN {to} failed"),
        );
        return;
    }
    let mut every = interval(Duration::from_secs(1));
    while kicked.elapsed() < waits.back {
        every.tick().await;
        let back = {
            let s = web.state.read();
            if current(&s, m, generation).is_none() {
                return;
            }
            let c = s.clients().into_iter().find(|c| c.station.mac == m);
            // A new association: younger than the kick.
            c.filter(|c| u64::from(c.station.connected_s) < kicked.elapsed().as_secs())
                .map(|c| (c.ap, c.station.vlan))
        };
        let Some((ap, vlan)) = back else { continue };
        let (ok, detail) = if vlan == to {
            (true, format!("back on VLAN {vlan}"))
        } else {
            (
                false,
                format!("back on VLAN {vlan}, not {to}: RADIUS had not taken the change"),
            )
        };
        end(&web.state, m, generation, &f, Some(ap), ok, detail);
        return;
    }
    let back = waits.back.as_secs();
    let detail = format!("not back within {back} s; it joins VLAN {to} when it comes back");
    end(&web.state, m, generation, &f, None, true, detail);
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const B: [u8; 6] = [2, 0, 0, 0, 0, 2];
    const C: [u8; 6] = [2, 0, 0, 0, 0, 3];
    /// The site's VLANs.
    const SITE: &[u16] = &[42, 43, 44, 45, 46, 47];

    /// A mapping as a site keeps it: two groups, and keys and fields the
    /// controller does not know, which it must keep.
    fn site() -> Mapping {
        let tree = json!({
            "vlans": {
                "common": {"id": 42, "devices": [
                    {"mac": "02-00-00-00-00-01", "description": "laptop", "note": "x"},
                ], "colour": "blue"},
                "iot": {"id": 43, "devices": [
                    {"mac": "02:00:00:00:00:02", "description": "plug"},
                ]},
            },
            "owner": "netops",
        });
        Mapping::from_kv(Some(tree), 7, SITE).unwrap()
    }

    #[test]
    fn a_mac_is_read_in_every_spelling_radius_takes_and_written_as_it_keys_it() {
        for s in [
            "02:00:00:00:00:01",
            "02-00-00-00-00-01",
            "020000000001",
            " 02:00:00:00:00:01 ",
        ] {
            assert_eq!(parse_key(s), Some(A), "{s}");
        }
        let upper = Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x0f]);
        assert_eq!(parse_key("AA:BB:CC:DD:EE:0F"), upper);
        for bad in [
            "02:00-00:00:00:01",
            "02.00.00.00.00.01",
            "0200000000",
            "02:00:00:00:00:0g",
            "",
            "x",
        ] {
            assert_eq!(parse_key(bad), None, "{bad}");
        }
        assert_eq!(
            key([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x0f]),
            "aa-bb-cc-dd-ee-0f"
        );
    }

    #[test]
    fn the_entries_are_read_and_what_is_none_is_said() {
        let m = site();
        assert_eq!(m.version, 7);
        let laptop = Entry {
            vlan: 42,
            group: "common".into(),
            description: "laptop".into(),
        };
        assert_eq!(m.entries[&A], laptop);
        assert_eq!(m.entries[&B].vlan, 43);
        assert!(m.unread.is_empty());
        let odd = json!({"vlans": {
            "bad": {"id": 0, "devices": [{"mac": "020000000009"}]},
            "big": {"id": "43", "devices": []},
            "x": {"id": 44, "devices": [
                {"mac": "nope"}, {"mac": "01:00:5e:00:00:01"}, {"mac": "020000000001"},
            ]},
            "y": {"id": 45, "devices": [{"mac": "02-00-00-00-00-01"}]},
            "z": {"id": 46, "devices": "many"},
            "empty": {"id": 47, "devices": null},
        }});
        let m = Mapping::from_kv(Some(odd), 1, SITE).unwrap();
        assert_eq!(m.entries.keys().copied().collect::<Vec<_>>(), vec![A]);
        assert_eq!(m.unread.len(), 6, "{:?}", m.unread);
        assert!(m.unread.iter().any(|u| u.contains("in groups x and y")));
        // No secret yet: no entry. A tree it could not edit: refused.
        assert!(Mapping::from_kv(None, 0, SITE).unwrap().entries.is_empty());
        assert!(Mapping::from_kv(Some(json!({"vlans": []})), 1, SITE).is_err());
        assert!(Mapping::from_kv(Some(json!([1])), 1, SITE).is_err());
    }

    #[test]
    fn what_radius_refuses_is_said_and_its_entries_still_read() {
        // A group on a VLAN that is not the site's: RADIUS refuses the
        // mapping, and its devices show where they were meant to go.
        let m = Mapping::from_kv(Some(site().tree), 7, &[42]).unwrap();
        assert_eq!(
            m.unread,
            vec!["group iot: VLAN 43 is not one of the site's".to_owned()]
        );
        assert_eq!(m.entries[&B].vlan, 43);
        // A secret with no vlans: refused by RADIUS; none yet: nothing to say.
        let m = Mapping::from_kv(Some(json!({"owner": "netops"})), 3, SITE).unwrap();
        assert_eq!(
            m.unread,
            vec!["the mapping has no vlans; RADIUS refuses it".to_owned()]
        );
        assert!(Mapping::from_kv(None, 0, SITE).unwrap().unread.is_empty());
    }

    #[test]
    fn a_description_has_no_control_or_format_character() {
        // An admin's: format characters dropped, a control character or
        // over 64 refused.
        assert_eq!(description(" tv\u{200b}\u{202e} ").as_deref(), Ok("tv"));
        assert_eq!(
            description(&"\u{feff}x".repeat(64)).map(|d| d.len()),
            Ok(64)
        );
        assert!(description("a\nb").is_err());
        assert!(description("a\u{85}b").is_err());
        assert!(description(&"x".repeat(65)).is_err());
        // A client's name: cleaned and cut alike, never refused.
        assert_eq!(name_description("Ana\u{202e}'s\tphone\n"), "Ana'sphone");
        assert_eq!(name_description(&"é".repeat(80)).chars().count(), 64);
    }

    #[test]
    fn an_edit_changes_that_one_entry_and_keeps_the_rest_of_the_tree() {
        let m = site();
        // Moved: out of common (written in another spelling), into iot.
        let t = m.edit(A, Some((43, "laptop")), 512).unwrap();
        assert_eq!(t["owner"], "netops");
        assert_eq!(t["vlans"]["common"]["colour"], "blue");
        assert_eq!(t["vlans"]["common"]["devices"], json!([]));
        assert_eq!(
            t["vlans"]["iot"]["devices"],
            json!([{"mac": "02:00:00:00:00:02", "description": "plug"},
                   {"mac": "02-00-00-00-00-01", "description": "laptop"}])
        );
        let moved = Mapping::from_kv(Some(t), 8, SITE).unwrap();
        assert_eq!(moved.entries[&A].vlan, 43);
        assert_eq!(moved.entries[&B], m.entries[&B]);
        // Added onto a VLAN no group has yet: a group of its own.
        let t = m.edit(C, Some((44, "tv")), 512).unwrap();
        let tv = json!({"id": 44, "devices": [{"mac": "02-00-00-00-00-03", "description": "tv"}]});
        assert_eq!(t["vlans"]["vlan-44"], tv);
        // Removed, the other group as it was.
        let t = m.edit(B, None, 512).unwrap();
        assert_eq!(t["vlans"]["iot"]["devices"], json!([]));
        assert_eq!(t["vlans"]["common"], site().tree["vlans"]["common"]);
        // The cap holds for a new entry, never for one there already.
        let e = m.edit(C, Some((42, "")), 2).unwrap_err();
        assert!(e.contains("holds 2 entries"), "{e}");
        assert!(m.edit(A, Some((43, "")), 2).is_ok());
        // No secret yet: the tree is made.
        let empty = Mapping::from_kv(None, 0, SITE).unwrap();
        let t = empty.edit(A, Some((42, "laptop")), 512).unwrap();
        let made = json!({"vlans": {"vlan-42": {"id": 42, "devices": [
            {"mac": "02-00-00-00-00-01", "description": "laptop"},
        ]}}});
        assert_eq!(t, made);
    }

    #[test]
    fn a_change_names_its_vlan_and_the_one_it_saw() {
        let a = ask(br#"{"vlan": 43, "expect": 42, "description": " tv "}"#).unwrap();
        let got = (a.vlan, a.expect, a.description.as_deref());
        assert_eq!(got, (Some(43), Some(42), Some("tv")));
        let a = ask(br#"{"vlan": null, "expect": null}"#).unwrap();
        assert_eq!((a.vlan, a.expect, a.description), (None, None, None));
        for bad in [
            &br#"{"vlan": 43}"#[..],
            br#"{"expect": 42}"#,
            br#"{"vlan": "43", "expect": null}"#,
            br#"{"vlan": 70000, "expect": null}"#,
            br#"{"vlan": -1, "expect": null}"#,
            br#"{"vlan": 43, "expect": null, "description": 5}"#,
            br#"{"vlan": 43, "expect": null, "group": "iot"}"#,
            b"[]",
            b"nope",
        ] {
            assert!(ask(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }
}
