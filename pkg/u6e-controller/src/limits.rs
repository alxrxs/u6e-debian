//! The rate limits: an admin's per client and per SSID, kept in the policy
//! file, over the site file's per-SSID limits (`[limits]`), which an admin's
//! limit of the same SSID overrides and its clearing gives back. The
//! effective set goes whole to every AP (`SyncLimits`) on each change and
//! after each session's first key frame, since an agent restarted with its
//! AP keeps none; each AP says how each limit stands there, which the view
//! shows.
//!
//!   POST /api/clients/{mac}/limit  {"down_kbit": n|null, "up_kbit": n|null}
//!   POST /api/ssids/limit          {"ssid": "...", "down_kbit": ..., "up_kbit": ...}
//!
//! Rates are kbit/s; a direction without one is not limited, and neither a
//! client's limit gone or an SSID's admin limit gone. Admins only, from the
//! UI's own page (`actions::refusal`).

use std::collections::BTreeMap;

use axum::body::Bytes;
use axum::extract::{Path, State as Ext};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde::Deserialize;
use serde_json::{Value, json};
use u6e_proto::mac;
use u6e_proto::msg::{
    CommandKind, Limit, LimitState, LimitStatus, LimitTarget, Rate, SSID_MAX, check_limits,
};

use crate::actions::{Ctx, Via, Web, refusal, user};
use crate::http::error;
use crate::state::State;

/// An admin's limits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RateLimits {
    pub clients: BTreeMap<[u8; 6], Rate>,
    pub ssids: BTreeMap<String, Rate>,
}

impl RateLimits {
    /// What the APs are given: the site file's SSID limits with an admin's
    /// of the same SSID over them, and the clients'.
    pub fn effective(&self, site: &BTreeMap<String, Rate>) -> Vec<Limit> {
        let mut ssids = site.clone();
        ssids.extend(self.ssids.iter().map(|(s, r)| (s.clone(), *r)));
        let ssids = ssids.into_iter().map(|(s, rate)| Limit {
            target: LimitTarget::Ssid(s),
            rate,
        });
        let clients = self.clients.iter().map(|(m, rate)| Limit {
            target: LimitTarget::Client(*m),
            rate: *rate,
        });
        ssids.chain(clients).collect()
    }
}

/// The command that makes an AP's limits the effective set.
pub fn sync(state: &State) -> CommandKind {
    CommandKind::SyncLimits {
        limits: state.limits.effective(&state.site_limits),
    }
}

/// A rate as JSON, kbit/s per direction.
fn rate(r: &Rate) -> Value {
    json!({ "down_kbit": r.down_kbit, "up_kbit": r.up_kbit })
}

pub fn status_name(s: LimitStatus) -> &'static str {
    match s {
        LimitStatus::Enforced => "enforced",
        LimitStatus::Waiting => "waiting",
        LimitStatus::Refused => "refused",
        LimitStatus::NotEnforced => "not enforced",
    }
}

/// A limit's target as the view keys it: a client's MAC, or `ssid:` and
/// the SSID.
pub fn target_key(t: &LimitTarget) -> String {
    match t {
        LimitTarget::Client(m) => mac::format(*m),
        LimitTarget::Ssid(s) => format!("ssid:{s}"),
    }
}

fn state_json(s: &LimitState) -> Value {
    json!({
        "status": status_name(s.status),
        "detail": s.detail,
        "down_bytes": s.down_bytes,
        "up_bytes": s.up_bytes,
    })
}

/// The limits as the UI shows them: the site file's per SSID, an admin's
/// per SSID and per client, and how each stands on each connected AP.
pub fn view(state: &State) -> Value {
    let site: serde_json::Map<String, Value> = state
        .site_limits
        .iter()
        .map(|(s, r)| (s.clone(), rate(r)))
        .collect();
    let ssids: serde_json::Map<String, Value> = state
        .limits
        .ssids
        .iter()
        .map(|(s, r)| (s.clone(), rate(r)))
        .collect();
    let clients: serde_json::Map<String, Value> = state
        .limits
        .clients
        .iter()
        .map(|(m, r)| (mac::format(*m), rate(r)))
        .collect();
    let states = state.aps().filter(|(_, a)| a.is_up()).map(|(name, a)| {
        let per: serde_json::Map<String, Value> = a
            .limit_states
            .iter()
            .map(|s| (target_key(&s.target), state_json(s)))
            .collect();
        (name.to_owned(), Value::Object(per))
    });
    json!({
        "site": site,
        "ssids": ssids,
        "clients": clients,
        "states": Value::Object(states.collect()),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RateBody {
    down_kbit: Option<u32>,
    up_kbit: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SsidBody {
    ssid: String,
    down_kbit: Option<u32>,
    up_kbit: Option<u32>,
}

/// The rate of a request; `None` for none at all (a limit cleared).
fn parsed(down: Option<u32>, up: Option<u32>) -> Result<Option<Rate>, &'static str> {
    let r = Rate {
        down_kbit: down,
        up_kbit: up,
    };
    if r == Rate::default() {
        return Ok(None);
    }
    if !r.valid() {
        return Err("a rate is 64 to 2000000 kbit/s");
    }
    Ok(Some(r))
}

/// Describes a rate for the events: "download 20 Mbit/s, upload none".
pub fn said(r: Option<Rate>) -> String {
    let one = |k: Option<u32>| {
        k.map_or_else(
            || "none".to_owned(),
            |k| {
                if k % 1000 == 0 {
                    format!("{} Mbit/s", k / 1000)
                } else {
                    format!("{k} kbit/s")
                }
            },
        )
    };
    match r {
        None => "no limit".into(),
        Some(r) => format!("download {}, upload {}", one(r.down_kbit), one(r.up_kbit)),
    }
}

/// `POST /api/clients/{mac}/limit`.
pub async fn set_client(
    Ext(web): Ext<Web>,
    Path(m): Path<String>,
    req: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(why) = refusal(&req, &web.access, Via::Post, &format!("limit {m}")) {
        return error(StatusCode::FORBIDDEN, why);
    }
    let Some(m) = mac::parse(&m).filter(|m| mac::is_station(*m)) else {
        return error(StatusCode::BAD_REQUEST, "not a station's MAC");
    };
    let Ok(b) = serde_json::from_slice::<RateBody>(&body) else {
        return error(StatusCode::BAD_REQUEST, "not {\"down_kbit\", \"up_kbit\"}");
    };
    let r = match parsed(b.down_kbit, b.up_kbit) {
        Ok(r) => r,
        Err(why) => return error(StatusCode::BAD_REQUEST, why),
    };
    let ctx = Ctx {
        state: &web.state,
        user: user(&req),
        action: if r.is_some() { "limit" } else { "unlimit" },
        mac: Some(m),
        about: said(r),
    };
    ctx.everywhere(&web.access, sync, |p| {
        let before = p.limits.clone();
        match r {
            Some(r) => p.limits.clients.insert(m, r),
            None => p.limits.clients.remove(&m),
        };
        changed(&before, p, &web.state)
    })
    .await
}

/// `POST /api/ssids/limit`.
pub async fn set_ssid(Ext(web): Ext<Web>, req: HeaderMap, body: Bytes) -> Response {
    if let Some(why) = refusal(&req, &web.access, Via::Post, "ssid limit") {
        return error(StatusCode::FORBIDDEN, why);
    }
    let Ok(b) = serde_json::from_slice::<SsidBody>(&body) else {
        return error(
            StatusCode::BAD_REQUEST,
            "not {\"ssid\", \"down_kbit\", \"up_kbit\"}",
        );
    };
    if b.ssid.is_empty() || b.ssid.len() > SSID_MAX {
        return error(StatusCode::BAD_REQUEST, "an SSID is 1 to 32 bytes");
    }
    let r = match parsed(b.down_kbit, b.up_kbit) {
        Ok(r) => r,
        Err(why) => return error(StatusCode::BAD_REQUEST, why),
    };
    let ssid = b.ssid;
    let ctx = Ctx {
        state: &web.state,
        user: user(&req),
        action: "ssid-limit",
        mac: None,
        about: format!("{ssid:?}: {}", said(r)),
    };
    ctx.everywhere(&web.access, sync, |p| {
        let before = p.limits.clone();
        match r {
            Some(r) => p.limits.ssids.insert(ssid.clone(), r),
            None => p.limits.ssids.remove(&ssid),
        };
        changed(&before, p, &web.state)
    })
    .await
}

/// Whether the limits changed, refused (an error) when the set it makes
/// is more than an AP takes.
fn changed(
    before: &RateLimits,
    p: &crate::policy::Policy,
    state: &crate::state::Shared,
) -> Result<bool, String> {
    let set = p.limits.effective(&state.read().site_limits);
    check_limits(&set)?;
    Ok(p.limits != *before)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(down: Option<u32>, up: Option<u32>) -> Rate {
        Rate {
            down_kbit: down,
            up_kbit: up,
        }
    }

    #[test]
    fn an_admins_ssid_limit_overrides_the_site_files() {
        let site = BTreeMap::from([
            ("guest".to_owned(), r(Some(50_000), None)),
            ("iot".to_owned(), r(None, Some(1_000))),
        ]);
        let mut l = RateLimits::default();
        l.ssids.insert("guest".into(), r(Some(10_000), Some(2_000)));
        l.clients.insert([2, 0, 0, 0, 0, 1], r(Some(5_000), None));
        let e = l.effective(&site);
        assert_eq!(
            e,
            vec![
                Limit {
                    target: LimitTarget::Ssid("guest".into()),
                    rate: r(Some(10_000), Some(2_000))
                },
                Limit {
                    target: LimitTarget::Ssid("iot".into()),
                    rate: r(None, Some(1_000))
                },
                Limit {
                    target: LimitTarget::Client([2, 0, 0, 0, 0, 1]),
                    rate: r(Some(5_000), None)
                },
            ]
        );
        // Cleared: the site file's again.
        l.ssids.clear();
        assert_eq!(l.effective(&site)[0].rate, r(Some(50_000), None));
    }

    #[test]
    fn rates_are_read_and_said() {
        assert_eq!(parsed(None, None), Ok(None));
        assert_eq!(parsed(Some(64), None), Ok(Some(r(Some(64), None))));
        assert!(parsed(Some(63), None).is_err() && parsed(None, Some(2_000_001)).is_err());
        assert_eq!(
            said(Some(r(Some(20_000), None))),
            "download 20 Mbit/s, upload none"
        );
        assert_eq!(
            said(Some(r(None, Some(1_500)))),
            "download none, upload 1500 kbit/s"
        );
        assert_eq!(said(None), "no limit");
    }
}
