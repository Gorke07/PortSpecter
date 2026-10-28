mod device;
mod identity;
pub use identity::*;
mod export;
mod plan;
mod vendor;
pub use device::*;

pub use export::*;
pub use plan::*;
pub use vendor::*;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionStatus {
    Running,
    Pausing,
    Paused,
    Completed,
    Cancelled,
    Failed,
    Interrupted,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
    TimedOut,
    Unreachable,
    LocalError,
    Filtered,
    OpenFiltered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortObservation {
    pub port: u16,
    pub state: PortState,
    pub elapsed_ms: u64,
    pub observed_at: DateTime<Utc>,
    pub error: Option<String>,
    pub service: Option<ServiceObservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServiceObservation {
    pub name: String,
    pub evidence: String,
    pub tls: Option<TlsObservation>,
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub product: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub detection: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsObservation {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub sha256: String,
    pub validation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacObservation {
    pub address: String,
    pub interface: String,
    pub source: String,
    pub neighbor_state: String,
    pub observed_at: DateTime<Utc>,
    pub vendor: Option<String>,
    pub locally_administered: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostObservation {
    pub ip: IpAddr,
    pub blocks: Vec<usize>,
    pub hostname: Option<String>,
    #[serde(default)]
    pub hostname_info: Option<NameObservation>,
    #[serde(default)]
    pub discovery: Option<DiscoveryObservation>,
    #[serde(default)]
    pub cameras: Vec<CameraObservation>,
    #[serde(default)]
    pub advertisements: Vec<DeviceAdvertisement>,
    #[serde(default)]
    pub shares: Option<ShareDiscovery>,
    pub mac: Option<MacObservation>,
    pub ports: Vec<PortObservation>,
    pub completed: usize,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CameraObservation {
    pub protocol: String,
    pub endpoint_id: String,
    pub name: Option<String>,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub firmware: Option<String>,
    pub mac: Option<String>,
    pub activated: Option<bool>,
    pub endpoints: Vec<String>,
    pub scopes: Vec<String>,
    pub interface: String,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ShareStatus {
    Complete,
    AccessDenied,
    Unavailable,
    TimedOut,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkShare {
    pub name: String,
    pub comment: String,
    pub hidden: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareDiscovery {
    pub status: ShareStatus,
    pub shares: Vec<NetworkShare>,
    pub source: String,
    pub detail: Option<String>,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameObservation {
    pub name: String,
    pub source: String,
    pub observed_at: DateTime<Utc>,
}

impl HostObservation {
    pub fn responding(&self) -> bool {
        !self.cameras.is_empty()
            || !self.advertisements.is_empty()
            || self.hostname_info.as_ref().is_some_and(|name| {
                matches!(
                    name.source.as_str(),
                    "mdns" | "llmnr" | "netbios_node_status"
                )
            })
            || self
                .discovery
                .as_ref()
                .is_some_and(|result| result.state == DiscoveryState::Reachable)
            || self
                .ports
                .iter()
                .any(|p| matches!(p.state, PortState::Open | PortState::Closed))
    }
    pub fn open_count(&self) -> usize {
        self.ports
            .iter()
            .filter(|p| p.state == PortState::Open)
            .count()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSession {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub status: SessionStatus,
    pub plan: ScanPlan,
    pub hosts: Vec<HostObservation>,
    pub completed: usize,
    pub total: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanMethod {
    #[default]
    TcpConnect,
    Udp,
    TcpSyn,
}
impl ScanMethod {
    pub fn protocol(self) -> &'static str {
        if self == Self::Udp { "udp" } else { "tcp" }
    }
}
impl std::fmt::Display for ScanMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TcpConnect => "TCP connect",
            Self::Udp => "UDP",
            Self::TcpSyn => "TCP SYN",
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSettings {
    #[serde(default)]
    pub method: ScanMethod,
    #[serde(default)]
    pub icmp_discovery: bool,
    #[serde(default = "enabled")]
    pub resolve_names: bool,
    #[serde(default = "enabled")]
    pub local_names: bool,
    #[serde(default)]
    pub onvif_discovery: bool,
    #[serde(default)]
    pub sadp_discovery: bool,
    #[serde(default)]
    pub dahua_discovery: bool,
    #[serde(default)]
    pub dnssd_discovery: bool,
    #[serde(default)]
    pub ssdp_discovery: bool,
    #[serde(default = "enabled")]
    pub smb_shares: bool,
    #[serde(default = "default_worker_threads")]
    pub worker_threads: usize,
    pub concurrency: usize,
    pub per_host: usize,
    pub rate_per_second: u32,
    pub timeout_ms: u64,
    pub retries: u8,
    pub inspect_services: bool,
    pub source_ip: Option<IpAddr>,
}

pub fn default_worker_threads() -> usize {
    std::thread::available_parallelism()
        .map_or(4, usize::from)
        .clamp(1, 256)
}
pub fn enabled() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryState {
    Reachable,
    NoReply,
    Unavailable,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryObservation {
    pub state: DiscoveryState,
    pub elapsed_ms: Option<u64>,
    pub observed_at: DateTime<Utc>,
    pub error: Option<String>,
}

impl Default for ScanSettings {
    fn default() -> Self {
        Self {
            method: ScanMethod::default(),
            icmp_discovery: true,
            resolve_names: true,
            local_names: true,
            onvif_discovery: false,
            sadp_discovery: false,
            dahua_discovery: false,
            dnssd_discovery: false,
            ssdp_discovery: false,
            smb_shares: true,
            worker_threads: default_worker_threads(),
            concurrency: 256,
            per_host: 8,
            rate_per_second: 200,
            timeout_ms: 1500,
            retries: 1,
            inspect_services: true,
            source_ip: None,
        }
    }
}

impl ScanSettings {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            (1..=256).contains(&self.worker_threads),
            "Worker threads must be 1–256"
        );
        anyhow::ensure!(
            (1..=4096).contains(&self.concurrency),
            "Concurrency must be 1–4096"
        );
        anyhow::ensure!(
            (1..=64).contains(&self.per_host),
            "Per-host concurrency must be 1–64"
        );
        anyhow::ensure!(
            (1..=10_000).contains(&self.rate_per_second),
            "Rate must be 1–10000"
        );
        anyhow::ensure!(
            (100..=30_000).contains(&self.timeout_ms),
            "Timeout must be 100–30000 ms"
        );
        anyhow::ensure!(self.retries <= 3, "Retries must be 0–3");
        Ok(())
    }
}

#[cfg(test)]
mod settings_tests {
    use super::*;
    #[test]
    fn old_profiles_get_thread_default_and_invalid_counts_are_rejected() {
        let mut json = serde_json::to_value(ScanSettings::default()).unwrap();
        json.as_object_mut().unwrap().remove("worker_threads");
        let mut settings: ScanSettings = serde_json::from_value(json).unwrap();
        assert_eq!(settings.worker_threads, default_worker_threads());
        for count in [0, 257, usize::MAX] {
            settings.worker_threads = count;
            assert!(settings.validate().is_err());
        }
        for count in [1, 4, 64, 128, 256] {
            settings.worker_threads = count;
            assert!(settings.validate().is_ok());
        }
    }
}
