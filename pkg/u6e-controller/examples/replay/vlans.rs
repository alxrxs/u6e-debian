//! The replay's OpenBao (the tests' stand-in, `tests/common/bao.rs`),
//! holding RADIUS's MAC authentication mapping of the clients that join
//! `ssid-b`, the MAC-authenticated SSID, on its two VLANs: a client joining
//! it is put on the VLAN its entry names, as RADIUS would put it, so an
//! admin's move shows when the kicked client joins again. The thermostat
//! never answers a kick, so its move waits for its next join.

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use u6e_proto::mac;

use crate::World;
use crate::bao::Store;

/// The SSID MAC authentication places clients on.
pub const SSID: &str = "ssid-b";
/// The VLANs an admin may put a device in.
pub const VLANS: [u16; 2] = [20, 21];
/// The token the controller reads and writes with.
pub const TOKEN: &str = "replay-bao-token";

/// The mapping: the printer and the kitchen speaker on 20, the thermostat
/// and the doorbell on 21.
pub fn store() -> Arc<Mutex<Store>> {
    let entry = |last: u8, description: &str| {
        let m = mac::format(World::mac(last)).replace(':', "-");
        json!({ "mac": m, "description": description })
    };
    let mapping = json!({ "vlans": {
        "devices": { "id": 20, "devices": [
            entry(7, "Office printer"),
            entry(crate::roaming::KITCHEN, "Kitchen speaker"),
        ]},
        "iot": { "id": 21, "devices": [
            entry(6, "Bedroom thermostat"),
            entry(9, "Doorbell"),
        ]},
    }});
    let mut store = Store {
        token: TOKEN.into(),
        ..Store::default()
    };
    store
        .secrets
        .entry("mac-auth".into())
        .or_default()
        .versions
        .push(mapping);
    Arc::new(Mutex::new(store))
}

/// The VLAN the mapping now puts `m` on, if it has an entry.
pub fn vlan_of(store: &Mutex<Store>, m: [u8; 6]) -> Option<u16> {
    let store = store.lock().unwrap_or_else(|e| e.into_inner());
    let mapping = store.secrets.get("mac-auth")?.versions.last()?;
    let key = mac::format(m).replace(':', "-");
    let groups = mapping.get("vlans")?.as_object()?;
    groups.values().find_map(|g| {
        let devices = g.get("devices")?.as_array()?;
        let listed = devices
            .iter()
            .any(|d| d.get("mac").and_then(Value::as_str) == Some(key.as_str()));
        listed.then(|| g.get("id")?.as_u64()?.try_into().ok())?
    })
}
