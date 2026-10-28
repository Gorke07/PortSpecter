use crate::{HostObservation, parse_mac};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize)]
pub struct IdentityClaim {
    pub field: String,
    pub value: String,
    pub sources: Vec<String>,
}

/// Retain conflicting observations; never merge different hosts solely by name or MAC.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DeviceIdentity {
    pub claims: Vec<IdentityClaim>,
    pub conflicts: BTreeSet<String>,
}

impl DeviceIdentity {
    fn add(&mut self, field: &str, value: Option<&str>, source: &str) {
        let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
            return;
        };
        let value = if field == "mac" {
            let Some(mac) = parse_mac(value).filter(|m| *m != [0; 6] && m[0] & 1 == 0) else {
                return;
            };
            mac.iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(":")
        } else {
            value
                .chars()
                .filter(|c| !c.is_control())
                .take(512)
                .collect()
        };
        if let Some(claim) = self
            .claims
            .iter_mut()
            .find(|c| c.field == field && c.value.eq_ignore_ascii_case(&value))
        {
            if !claim.sources.iter().any(|s| s == source) {
                claim.sources.push(source.into());
            }
        } else {
            if self.claims.iter().any(|c| c.field == field) {
                self.conflicts.insert(field.into());
            }
            self.claims.push(IdentityClaim {
                field: field.into(),
                value,
                sources: vec![source.into()],
            });
        }
    }
    pub fn preferred(&self, field: &str) -> Option<&str> {
        self.claims
            .iter()
            .find(|c| c.field == field)
            .map(|c| c.value.as_str())
    }
}

impl HostObservation {
    pub fn identity(&self) -> DeviceIdentity {
        let mut identity = DeviceIdentity::default();
        identity.add(
            "hostname",
            self.hostname.as_deref(),
            self.hostname_info
                .as_ref()
                .map(|n| n.source.as_str())
                .unwrap_or("DNS / saved name"),
        );
        if let Some(mac) = &self.mac {
            identity.add("mac", Some(&mac.address), &mac.source);
            identity.add("vendor", mac.vendor.as_deref(), "MAC prefix database");
        }
        for c in &self.cameras {
            identity.add("device-name", c.name.as_deref(), &c.protocol);
            identity.add("mac", c.mac.as_deref(), &c.protocol);
            identity.add("device-model", c.model.as_deref(), &c.protocol);
            identity.add("device-serial", c.serial.as_deref(), &c.protocol);
            identity.add("device-firmware", c.firmware.as_deref(), &c.protocol);
        }
        for ad in &self.advertisements {
            // Service instance names are not DNS hostnames or physical device names.
            identity.add("service-hostname", ad.hostname.as_deref(), &ad.protocol);
            identity.add(
                if ad.service_type.is_some() {
                    "service-instance"
                } else {
                    "device-name"
                },
                ad.name.as_deref(),
                &ad.protocol,
            );
            identity.add("mac", ad.mac.as_deref(), &ad.protocol);
            identity.add("device-model", ad.model.as_deref(), &ad.protocol);
            identity.add("device-serial", ad.serial.as_deref(), &ad.protocol);
            identity.add("manufacturer", ad.manufacturer.as_deref(), &ad.protocol);
        }
        for port in &self.ports {
            if let Some(service) = &port.service {
                let source = format!("{} / port {}", service.name, port.port);
                if service.verified
                    && let Some(product) = &service.product
                {
                    let software = format!(
                        "{}{}",
                        product,
                        service
                            .version
                            .as_ref()
                            .map(|v| format!(" {v}"))
                            .unwrap_or_default()
                    );
                    identity.add("service-product", Some(&software), &source);
                }
                if let Some(tls) = &service.tls {
                    identity.add(
                        "tls-subject",
                        Some(&tls.subject),
                        &format!("{source} / {}", tls.validation),
                    );
                }
            }
        }
        // Multiple hosted services and DNS-SD names are expected, not identity conflicts.
        identity.conflicts.remove("service-instance");
        identity.conflicts.remove("service-hostname");
        identity.conflicts.remove("service-product");
        identity.conflicts.remove("tls-subject");
        identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalizes_macs_keeps_sources_and_exposes_conflicts() {
        let mut id = DeviceIdentity::default();
        id.add("mac", Some("00-11-22-33-44-55"), "ARP");
        id.add("mac", Some("00:11:22:33:44:55"), "SADP");
        assert_eq!(id.claims.len(), 1);
        assert_eq!(id.claims[0].sources.len(), 2);
        id.add("mac", Some("00:11:22:33:44:66"), "Dahua");
        assert!(id.conflicts.contains("mac"));
        assert_eq!(id.preferred("mac"), Some("00:11:22:33:44:55"));
        id.add("mac", Some("ff:ff:ff:ff:ff:ff"), "invalid");
        assert_eq!(id.claims.len(), 2);
    }
    #[test]
    fn legacy_service_records_remain_readable_without_claiming_verification() {
        let value: crate::ServiceObservation =
            serde_json::from_str(r#"{"name":"SSH?","evidence":"hint","tls":null}"#).unwrap();
        assert!(!value.verified);
        assert!(value.product.is_none());
    }
}
