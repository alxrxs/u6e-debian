//! Who a client is, from all the controller knows of it: the device the DHCP
//! server knows its MAC as, the host name it asked its lease for, the
//! reverse DNS of its addresses, the vendor of its MAC, its addresses (the
//! leased ones first, then those only its flows show, such as IPv6 ones it
//! made up itself) and when its lease runs out. It is named by the first of
//! the device, the host name and the DNS name it has; the UI shows its MAC
//! when it has none.

use std::net::IpAddr;

use serde_json::{Map, Value};

use crate::oui::Vendor;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Identity {
    pub device: Option<String>,
    pub hostname: Option<String>,
    pub dns: Option<String>,
    pub vendor: Option<Vendor>,
    pub addresses: Vec<IpAddr>,
    /// When its last lease expires, in Unix seconds.
    pub lease_expires: Option<u64>,
}

impl Identity {
    /// The name it goes by.
    pub fn name(&self) -> Option<&str> {
        let names = [&self.device, &self.hostname, &self.dns];
        names.into_iter().find_map(Option::as_deref)
    }

    /// The fields of a client's view: `name` and each source of it,
    /// `vendor` ("Private address" for a locally administered MAC),
    /// `addresses` and `lease_expires` (Unix milliseconds), each only when
    /// known.
    pub fn fields(&self) -> Map<String, Value> {
        let mut o = Map::new();
        let mut put = |k: &str, v: Option<Value>| {
            if let Some(v) = v {
                o.insert(k.into(), v);
            }
        };
        put("name", self.name().map(Into::into));
        put("device", self.device.clone().map(Into::into));
        put("hostname", self.hostname.clone().map(Into::into));
        put("dns", self.dns.clone().map(Into::into));
        put(
            "vendor",
            self.vendor.map(|v| match v {
                Vendor::Private => "Private address".into(),
                Vendor::Assigned(name) => name.into(),
            }),
        );
        let addresses: Vec<Value> = self
            .addresses
            .iter()
            .map(|a| a.to_string().into())
            .collect();
        put(
            "addresses",
            (!addresses.is_empty()).then_some(addresses.into()),
        );
        put(
            "lease_expires",
            self.lease_expires.map(|s| (s * 1000).into()),
        );
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_device_names_it_then_the_host_name_then_dns() {
        let mut i = Identity {
            dns: Some("tab.example.org".into()),
            ..Identity::default()
        };
        assert_eq!(i.name(), Some("tab.example.org"));
        i.hostname = Some("tablet".into());
        assert_eq!(i.name(), Some("tablet"));
        i.device = Some("Kitchen tablet".into());
        assert_eq!(i.name(), Some("Kitchen tablet"));
        assert_eq!(Identity::default().name(), None);
    }

    #[test]
    fn its_fields_are_only_what_is_known() {
        assert_eq!(Value::Object(Identity::default().fields()), json!({}));
        let i = Identity {
            hostname: Some("tablet".into()),
            vendor: Some(Vendor::Private),
            addresses: vec!["192.0.2.5".parse().unwrap(), "2001:db8::5".parse().unwrap()],
            lease_expires: Some(1_800_000_000),
            ..Identity::default()
        };
        assert_eq!(
            Value::Object(i.fields()),
            json!({
                "name": "tablet",
                "hostname": "tablet",
                "vendor": "Private address",
                "addresses": ["192.0.2.5", "2001:db8::5"],
                "lease_expires": 1_800_000_000_000u64,
            })
        );
    }
}
