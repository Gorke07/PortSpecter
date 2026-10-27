use crate::HostObservation;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Protocol-reported metadata. Advertised ports are not confirmed open ports.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeviceAdvertisement {
    pub protocol: String,
    pub identity: String,
    pub name: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub mac: Option<String>,
    pub device_type: Option<String>,
    pub service_type: Option<String>,
    pub port: Option<u16>,
    pub transport: Option<String>,
    pub hostname: Option<String>,
    pub endpoints: Vec<String>,
    pub properties: BTreeMap<String, String>,
    pub interface: String,
    pub observed_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PortObservation, PortState};
    #[test]
    fn types_require_evidence_and_support_multiple_roles() {
        let mut host = HostObservation {
            ip: "192.0.2.1".parse().unwrap(),
            blocks: vec![0],
            hostname: None,
            hostname_info: None,
            discovery: None,
            cameras: vec![],
            advertisements: vec![],
            shares: None,
            mac: None,
            ports: vec![PortObservation {
                port: 445,
                state: PortState::Open,
                elapsed_ms: 1,
                observed_at: Utc::now(),
                error: None,
                service: None,
            }],
            completed: 1,
            total: 1,
        };
        assert!(host.device_kinds().contains_key(&DeviceKind::Unknown));
        host.ports.clear();
        host.advertisements.push(DeviceAdvertisement {
            protocol: "DNS-SD".into(),
            service_type: Some("_ipp._tcp.local.".into()),
            port: Some(8631),
            ..Default::default()
        });
        assert!(host.device_kinds().contains_key(&DeviceKind::Printer));
        assert_eq!(host.open_count(), 0);
        assert!(host.responding());
        host.advertisements.push(DeviceAdvertisement {
            protocol: "DNS-SD".into(),
            service_type: Some("_smb._tcp.local.".into()),
            ..Default::default()
        });
        assert_eq!(host.device_kinds().len(), 2);
        host.advertisements = vec![DeviceAdvertisement {
            protocol: "Dahua".into(),
            device_type: Some("HCVR".into()),
            ..Default::default()
        }];
        assert!(host.device_kinds().contains_key(&DeviceKind::Recorder));
        assert!(!host.device_kinds().contains_key(&DeviceKind::Camera));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DeviceKind {
    Camera,
    Recorder,
    Printer,
    Router,
    Switch,
    FileServer,
    Media,
    Computer,
    Unknown,
}
impl DeviceKind {
    pub const ALL: [Self; 9] = [
        Self::Camera,
        Self::Recorder,
        Self::Printer,
        Self::Router,
        Self::Switch,
        Self::FileServer,
        Self::Media,
        Self::Computer,
        Self::Unknown,
    ];
    pub fn key(self) -> &'static str {
        match self {
            Self::Camera => "kind-camera",
            Self::Recorder => "kind-recorder",
            Self::Printer => "kind-printer",
            Self::Router => "kind-router",
            Self::Switch => "kind-switch",
            Self::FileServer => "kind-fileserver",
            Self::Media => "kind-media",
            Self::Computer => "kind-computer",
            Self::Unknown => "kind-unknown",
        }
    }
}

impl HostObservation {
    /// Multiple roles can coexist on one IP. Never classify from port numbers or vendor alone.
    pub fn device_kinds(&self) -> BTreeMap<DeviceKind, Vec<String>> {
        let mut result: BTreeMap<DeviceKind, Vec<String>> = BTreeMap::new();
        for camera in &self.cameras {
            let model = camera.model.as_deref().unwrap_or("").to_ascii_uppercase();
            let kind = if model.starts_with("NVR")
                || model.starts_with("DVR")
                || model.starts_with("DS-76")
                || model.starts_with("DS-77")
                || model.starts_with("DS-96")
            {
                DeviceKind::Recorder
            } else {
                DeviceKind::Camera
            };
            result.entry(kind).or_default().push(format!(
                "{}: {}",
                camera.protocol,
                camera.model.as_deref().unwrap_or("video discovery")
            ));
        }
        for ad in &self.advertisements {
            let declared = ad.device_type.as_deref().unwrap_or("");
            let value = declared.to_ascii_lowercase();
            let service = ad
                .service_type
                .as_deref()
                .unwrap_or("")
                .to_ascii_lowercase();
            let kind = if ad.protocol == "Dahua" {
                if matches!(value.as_str(), "nvr" | "dvr" | "xvr" | "hcvr") {
                    Some(DeviceKind::Recorder)
                } else if matches!(value.as_str(), "ipc" | "camera" | "sd") {
                    Some(DeviceKind::Camera)
                } else if value == "switch" {
                    Some(DeviceKind::Switch)
                } else if value == "router" {
                    Some(DeviceKind::Router)
                } else {
                    None
                }
            } else if service == "_workstation._tcp.local." {
                Some(DeviceKind::Computer)
            } else if value.contains(":device:internetgatewaydevice:")
                || value.contains(":device:wangatewaydevice:")
            {
                Some(DeviceKind::Router)
            } else if value.contains(":device:printer:")
                || matches!(
                    service.as_str(),
                    "_ipp._tcp.local."
                        | "_ipps._tcp.local."
                        | "_printer._tcp.local."
                        | "_pdl-datastream._tcp.local."
                )
            {
                Some(DeviceKind::Printer)
            } else if value.contains(":device:mediarenderer:")
                || value.contains(":device:mediaserver:")
                || matches!(
                    service.as_str(),
                    "_airplay._tcp.local." | "_raop._tcp.local." | "_googlecast._tcp.local."
                )
            {
                Some(DeviceKind::Media)
            } else if matches!(
                service.as_str(),
                "_smb._tcp.local." | "_afpovertcp._tcp.local." | "_nfs._tcp.local."
            ) {
                Some(DeviceKind::FileServer)
            } else {
                None
            };
            if let Some(kind) = kind {
                result.entry(kind).or_default().push(format!(
                    "{}: {}",
                    ad.protocol,
                    if declared.is_empty() {
                        service.as_str()
                    } else {
                        declared
                    }
                ));
            }
        }
        if self.shares.as_ref().is_some_and(|s| !s.shares.is_empty()) {
            result
                .entry(DeviceKind::FileServer)
                .or_default()
                .push("SMB: disk shares".into());
        }
        if result.is_empty() {
            result.insert(DeviceKind::Unknown, vec![]);
        }
        result
    }
}
