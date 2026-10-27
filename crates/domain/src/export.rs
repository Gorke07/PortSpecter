use crate::*;
use anyhow::Result;
use serde::Serialize;
use std::{collections::BTreeMap, net::IpAddr, path::Path};

pub fn export_json(path: &Path, session: &ScanSession) -> Result<()> {
    #[derive(Serialize)]
    struct Export<'a> {
        schema_version: u32,
        session: &'a ScanSession,
    }
    let file = std::fs::File::create(path)?;
    serde_json::to_writer_pretty(
        file,
        &Export {
            schema_version: 4,
            session,
        },
    )?;
    Ok(())
}
fn csv_safe(value: &str) -> String {
    if value
        .trim_start()
        .starts_with(['=', '+', '-', '@', '\t', '\r'])
    {
        format!("'{value}")
    } else {
        value.into()
    }
}
pub fn export_csv(path: &Path, session: &ScanSession) -> Result<()> {
    let mut out = csv::Writer::from_path(path)?;
    out.write_record([
        "session_id",
        "session_status",
        "camera_discovery_json",
        "device_advertisements_json",
        "smb_shares_json",
        "ip",
        "hostname",
        "hostname_source",
        "icmp_state",
        "icmp_ms",
        "target_groups",
        "vlan_labels",
        "mac",
        "vendor",
        "port",
        "protocol",
        "scan_method",
        "state",
        "service",
        "evidence",
        "observed_at",
    ])?;
    for host in &session.hosts {
        let names = host
            .blocks
            .iter()
            .filter_map(|i| session.plan.blocks.get(*i))
            .map(|b| b.name.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        let vlans = host
            .blocks
            .iter()
            .filter_map(|i| session.plan.blocks.get(*i)?.vlan_id)
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(";");
        for port in host
            .ports
            .iter()
            .map(Some)
            .chain(host.ports.is_empty().then_some(None))
        {
            let record = vec![
                session.id.to_string(),
                format!("{:?}", session.status),
                serde_json::to_string(&host.cameras)?,
                serde_json::to_string(&host.advertisements)?,
                serde_json::to_string(&host.shares)?,
                host.ip.to_string(),
                host.hostname.clone().unwrap_or_default(),
                host.hostname_info
                    .as_ref()
                    .map(|name| name.source.clone())
                    .unwrap_or_default(),
                host.discovery
                    .as_ref()
                    .map(|value| format!("{:?}", value.state))
                    .unwrap_or_default(),
                host.discovery
                    .as_ref()
                    .and_then(|value| value.elapsed_ms)
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
                names.clone(),
                vlans.clone(),
                host.mac
                    .as_ref()
                    .map(|m| m.address.clone())
                    .unwrap_or_default(),
                host.mac
                    .as_ref()
                    .and_then(|m| m.vendor.clone())
                    .unwrap_or_default(),
                port.map(|p| p.port.to_string()).unwrap_or_default(),
                session.plan.settings.method.protocol().into(),
                session.plan.settings.method.to_string(),
                port.map(|p| format!("{:?}", p.state)).unwrap_or_default(),
                port.and_then(|p| p.service.as_ref())
                    .map(|s| s.name.clone())
                    .unwrap_or_default(),
                port.and_then(|p| p.service.as_ref())
                    .map(|s| s.evidence.clone())
                    .unwrap_or_default(),
                port.map(|p| p.observed_at)
                    .or_else(|| host.advertisements.first().map(|a| a.observed_at))
                    .or_else(|| host.cameras.first().map(|c| c.observed_at))
                    .unwrap_or(session.started_at)
                    .to_rfc3339(),
            ];
            out.write_record(record.iter().map(|s| csv_safe(s)))?;
        }
    }
    out.flush()?;
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct PortChange {
    pub protocol: String,
    pub ip: IpAddr,
    pub port: u16,
    pub change: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct DeviceChange {
    pub ip: IpAddr,
    pub change: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct Comparison {
    pub before: String,
    pub after: String,
    pub warnings: Vec<String>,
    pub devices: Vec<DeviceChange>,
    pub ports: Vec<PortChange>,
}
pub fn compare(before: &ScanSession, after: &ScanSession) -> Comparison {
    let mut result = Comparison {
        before: before.started_at.to_rfc3339(),
        after: after.started_at.to_rfc3339(),
        warnings: Vec::new(),
        devices: Vec::new(),
        ports: Vec::new(),
    };
    if before.plan.settings.method != after.plan.settings.method {
        result.warnings.push("compare-method".into());
        return result;
    }
    if before.plan.settings.source_ip != after.plan.settings.source_ip {
        result.warnings.push("compare-source".into());
        return result;
    }
    if before.status != SessionStatus::Completed || after.status != SessionStatus::Completed {
        result.warnings.push("compare-partial".into());
    }
    let old: BTreeMap<_, _> = before.hosts.iter().map(|host| (host.ip, host)).collect();
    let new: BTreeMap<_, _> = after.hosts.iter().map(|host| (host.ip, host)).collect();
    if old.keys().ne(new.keys()) || before.plan.ports != after.plan.ports {
        result.warnings.push("compare-scope".into());
    }
    let discovery_matches =
        before.plan.settings.icmp_discovery == after.plan.settings.icmp_discovery;
    if !discovery_matches {
        result.warnings.push("compare-discovery".into());
    }
    for (ip, host) in new {
        let Some(previous) = old.get(&ip) else {
            continue;
        };
        if discovery_matches
            && previous.completed == previous.total
            && host.completed == host.total
            && before.plan.ports == after.plan.ports
        {
            let change = match (previous.responding(), host.responding()) {
                (false, true) => Some("device-appeared"),
                (true, false) => Some("device-unobserved"),
                _ => None,
            };
            if let Some(change) = change {
                result.devices.push(DeviceChange {
                    ip,
                    change: change.into(),
                });
            }
        }
        let ports: BTreeMap<_, _> = previous
            .ports
            .iter()
            .map(|port| (port.port, port.state))
            .collect();
        for port in &host.ports {
            let Some(previous) = ports.get(&port.port) else {
                continue;
            };
            let change = match (*previous, port.state) {
                (PortState::Open, PortState::Closed) => Some("closed"),
                (
                    PortState::Open,
                    PortState::TimedOut
                    | PortState::Unreachable
                    | PortState::Filtered
                    | PortState::OpenFiltered,
                ) => Some("no_longer_observed"),
                (state, PortState::Open)
                    if state != PortState::Open && state != PortState::LocalError =>
                {
                    Some("opened")
                }
                _ => None,
            };
            if let Some(change) = change {
                result.ports.push(PortChange {
                    protocol: after.plan.settings.method.protocol().into(),
                    ip,
                    port: port.port,
                    change: change.into(),
                });
            }
        }
    }
    result
}
pub fn compare_sessions(before: &ScanSession, after: &ScanSession) -> Vec<PortChange> {
    let old: BTreeMap<_, _> = before
        .hosts
        .iter()
        .flat_map(|h| h.ports.iter().map(move |p| ((h.ip, p.port), p.state)))
        .collect();
    let mut changes = Vec::new();
    if before.plan.settings.method != after.plan.settings.method
        || before.plan.settings.source_ip != after.plan.settings.source_ip
    {
        return changes;
    }
    for host in &after.hosts {
        for p in &host.ports {
            if let Some(previous) = old.get(&(host.ip, p.port)) {
                let change = match (*previous, p.state) {
                    (PortState::Closed, PortState::Open) => Some("opened"),
                    (PortState::Open, PortState::Closed) => Some("closed"),
                    (
                        PortState::Open,
                        PortState::TimedOut
                        | PortState::Unreachable
                        | PortState::Filtered
                        | PortState::OpenFiltered,
                    ) => Some("no_longer_observed"),
                    _ => None,
                };
                if let Some(change) = change {
                    changes.push(PortChange {
                        protocol: after.plan.settings.method.protocol().into(),
                        ip: host.ip,
                        port: p.port,
                        change: change.into(),
                    });
                }
            }
        }
    }
    changes
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discovery_only_device_is_exported_without_a_fabricated_port() {
        let mut session = session("192.0.2.1", None);
        session.hosts[0].advertisements.push(DeviceAdvertisement {
            protocol: "DNS-SD".into(),
            identity: "fixture".into(),
            port: Some(8631),
            ..Default::default()
        });
        let path = std::env::temp_dir().join(format!(
            "portspecter-discovery-{}.csv",
            uuid::Uuid::new_v4()
        ));
        export_csv(&path, &session).unwrap();
        let mut reader = csv::Reader::from_path(&path).unwrap();
        let headers = reader.headers().unwrap().clone();
        let row = reader.records().next().unwrap().unwrap();
        let index = |key: &str| headers.iter().position(|h| h == key).unwrap();
        assert_eq!(&row[index("port")], "");
        assert_eq!(&row[index("state")], "");
        assert!(row[index("device_advertisements_json")].contains("8631"));
        drop(reader);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn udp_export_and_comparison_preserve_protocol() {
        let before = session("192.0.2.1", Some(PortState::Open));
        let mut after = before.clone();
        after.plan.settings.method = ScanMethod::Udp;
        let comparison = compare(&before, &after);
        assert!(comparison.ports.is_empty());
        assert!(comparison.warnings.contains(&"compare-method".into()));
        assert!(compare_sessions(&before, &after).is_empty());
        let path =
            std::env::temp_dir().join(format!("portspecter-udp-{}.csv", uuid::Uuid::new_v4()));
        export_csv(&path, &after).unwrap();
        let mut reader = csv::Reader::from_path(&path).unwrap();
        let protocol = reader
            .headers()
            .unwrap()
            .iter()
            .position(|h| h == "protocol")
            .unwrap();
        let record = reader.records().next().unwrap().unwrap();
        assert_eq!(&record[protocol], "udp");
        drop(reader);
        std::fs::remove_file(path).unwrap();
    }
    fn session(ip: &str, state: Option<PortState>) -> ScanSession {
        let ip: IpAddr = ip.parse().unwrap();
        let plan = merge_targets(
            parse_blocks(&ip.to_string()).unwrap(),
            vec![vec![ip]],
            &[],
            vec![80],
            ScanSettings::default(),
        )
        .unwrap();
        let ports = state
            .map(|state| PortObservation {
                port: 80,
                state,
                elapsed_ms: 1,
                observed_at: chrono::Utc::now(),
                error: None,
                service: None,
            })
            .into_iter()
            .collect::<Vec<_>>();
        ScanSession {
            id: uuid::Uuid::new_v4(),
            started_at: chrono::Utc::now(),
            finished_at: None,
            status: SessionStatus::Completed,
            plan,
            hosts: vec![HostObservation {
                ip,
                blocks: vec![0],
                hostname: None,
                hostname_info: None,
                cameras: Vec::new(),
                advertisements: Vec::new(),
                shares: None,
                discovery: None,
                mac: None,
                completed: ports.len(),
                total: 1,
                ports,
            }],
            completed: usize::from(state.is_some()),
            total: 1,
        }
    }
    #[test]
    fn comparison_does_not_invent_changes_for_untested_or_out_of_scope_targets() {
        let before = session("192.0.2.1", Some(PortState::Open));
        let after = session("192.0.2.1", None);
        let result = compare(&before, &after);
        assert!(result.devices.is_empty() && result.ports.is_empty());
        let after = session("192.0.2.2", Some(PortState::Open));
        let result = compare(&before, &after);
        assert!(result.devices.is_empty() && result.ports.is_empty());
        assert!(result.warnings.contains(&"compare-scope".into()));
    }
    #[test]
    fn comparison_distinguishes_closed_from_missing_reply() {
        let before = session("192.0.2.1", Some(PortState::Open));
        let closed = compare(&before, &session("192.0.2.1", Some(PortState::Closed)));
        assert_eq!(closed.ports[0].change, "closed");
        assert!(closed.devices.is_empty());
        let missing = compare(&before, &session("192.0.2.1", Some(PortState::TimedOut)));
        assert_eq!(missing.ports[0].change, "no_longer_observed");
        assert_eq!(missing.devices[0].change, "device-unobserved");
    }
    #[test]
    fn formula_escape() {
        assert_eq!(csv_safe("=SUM(1)"), "'=SUM(1)");
        assert_eq!(csv_safe(" Acme"), " Acme");
        assert_eq!(csv_safe("  +cmd"), "'  +cmd");
    }
}
