use crate::{RouteInfo, echo, route_to};
use portspecter_domain::DiscoveryState;
use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Default)]
pub struct Samples {
    pub sent: usize,
    pub received: usize,
    pub unavailable: usize,
    pub min_ms: Option<u64>,
    pub average_ms: Option<f64>,
    pub max_ms: Option<u64>,
    pub jitter_ms: Option<f64>,
}
impl Samples {
    pub fn from_samples(values: &[Option<u64>], unavailable: usize) -> Self {
        let times: Vec<_> = values.iter().filter_map(|v| *v).collect();
        // Jitter only uses adjacent successful probes, never bridges a lost sample.
        let differences: Vec<_> = values
            .windows(2)
            .filter_map(|p| Some(p[0]?.abs_diff(p[1]?) as f64))
            .collect();
        Self {
            sent: values.len(),
            received: times.len(),
            unavailable,
            min_ms: times.iter().min().copied(),
            max_ms: times.iter().max().copied(),
            average_ms: (!times.is_empty())
                .then(|| times.iter().map(|t| *t as f64).sum::<f64>() / times.len() as f64),
            jitter_ms: (!differences.is_empty())
                .then(|| differences.iter().sum::<f64>() / differences.len() as f64),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HealthReport {
    pub target: SocketAddr,
    pub dns_name: String,
    pub measured_at: chrono::DateTime<chrono::Utc>,
    pub route: Result<RouteInfo, String>,
    pub dhcp: String,
    pub dns: Result<(Vec<IpAddr>, u128), String>,
    pub gateway: Option<Samples>,
    pub target_ping: Samples,
    pub tcp: Result<u128, String>,
}

async fn sample(ip: IpAddr, source: Option<IpAddr>) -> Samples {
    let mut values = Vec::new();
    let mut unavailable = 0;
    let mut received = 0;
    for _ in 0..5 {
        let result = echo(ip, source, Duration::from_millis(800)).await;
        unavailable += usize::from(result.state == DiscoveryState::Unavailable);
        received += usize::from(result.state == DiscoveryState::Reachable);
        values.push(if result.state == DiscoveryState::Reachable {
            result.elapsed_ms
        } else {
            None
        });
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    let mut result = Samples::from_samples(&values, unavailable);
    result.received = received;
    result
}

/// Reads DHCP configuration/lease information; does not renew leases or claim server reachability.
async fn dhcp_configuration(source: Option<IpAddr>) -> String {
    let Some(source) = source else {
        return "No source interface found".into();
    };
    let interface = netdev::get_interfaces().into_iter().find(|i| {
        i.ipv4.iter().any(|n| IpAddr::V4(n.addr()) == source)
            || i.ipv6.iter().any(|n| IpAddr::V6(n.addr()) == source)
    });
    let Some(interface) = interface else {
        return "Source interface unavailable".into();
    };
    if let Some(enabled) = interface.dhcp_v4_enabled {
        return if enabled {
            "DHCPv4 enabled (OS configuration; lease renewal not tested)"
        } else {
            "DHCPv4 disabled / static configuration"
        }
        .into();
    }
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut c = tokio::process::Command::new("ipconfig");
        c.args(["getpacket", &interface.name]);
        c
    };
    #[cfg(not(any(windows, target_os = "macos")))]
    let mut command = {
        let mut c = tokio::process::Command::new("nmcli");
        c.args([
            "-t",
            "-f",
            "DHCP4.OPTION",
            "device",
            "show",
            &interface.name,
        ]);
        c
    };
    #[cfg(not(windows))]
    {
        command.kill_on_drop(true);
        match tokio::time::timeout(Duration::from_secs(2), command.output()).await {
            Ok(Ok(output)) if output.status.success() && !output.stdout.is_empty() => {
                let raw = String::from_utf8_lossy(&output.stdout);
                let details = raw
                    .lines()
                    .filter(|line| {
                        line.contains("server_identifier")
                            || line.contains("lease_time")
                            || line.contains("ip_address")
                    })
                    .take(6)
                    .collect::<Vec<_>>()
                    .join("\n");
                if details.is_empty() {
                    "DHCP lease information unavailable; interface may be static or managed elsewhere".into()
                } else {
                    format!(
                        "OS DHCP lease information (renewal not tested):\n{}",
                        details.chars().take(1200).collect::<String>()
                    )
                }
            }
            _ => "DHCP information unavailable (static configuration or OS helper unavailable)"
                .into(),
        }
    }
    #[cfg(windows)]
    {
        "DHCP configuration unavailable".into()
    }
}

pub fn valid_dns_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.parse::<IpAddr>().is_err()
        && name.trim_end_matches('.').split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

pub async fn run(target: SocketAddr, dns_name: String) -> HealthReport {
    let route = tokio::task::spawn_blocking(move || route_to(target.ip(), None))
        .await
        .map_err(|e| e.to_string())
        .and_then(|r| r.map_err(|e| e.to_string()));
    let source = route.as_ref().ok().map(|r| r.source);
    let gateway = route.as_ref().ok().and_then(|r| r.next_hop);
    let dns = async {
        if !valid_dns_name(&dns_name) {
            return Err("Enter a DNS hostname, not an IP or URL".into());
        }
        let start = Instant::now();
        match tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::lookup_host((dns_name.as_str(), 443)),
        )
        .await
        {
            Ok(Ok(addresses)) => {
                let ips = addresses
                    .map(|a| a.ip())
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .take(16)
                    .collect::<Vec<_>>();
                if ips.is_empty() {
                    Err("Resolver returned no addresses".into())
                } else {
                    Ok((ips, start.elapsed().as_millis()))
                }
            }
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("DNS resolution timed out".into()),
        }
    };
    let tcp = async {
        let start = Instant::now();
        match tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::TcpStream::connect(target),
        )
        .await
        {
            Ok(Ok(_)) => Ok(start.elapsed().as_millis()),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("TCP connection timed out".into()),
        }
    };
    let (dns, tcp, dhcp, target_ping, gateway) = tokio::join!(
        dns,
        tcp,
        dhcp_configuration(source),
        sample(target.ip(), source),
        async {
            if let Some(ip) = gateway {
                Some(sample(ip, source).await)
            } else {
                None
            }
        }
    );
    HealthReport {
        target,
        dns_name,
        measured_at: chrono::Utc::now(),
        route,
        dhcp,
        dns,
        gateway,
        target_ping,
        tcp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn loopback_health_checks_use_real_connections_without_external_targets() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            listener.accept().await.unwrap();
        });
        let report = tokio::time::timeout(Duration::from_secs(15), run(target, "localhost".into()))
            .await
            .unwrap();
        assert!(report.tcp.is_ok());
        assert!(report.dns.is_ok());
        assert_eq!(report.target_ping.sent, 5);
        assert_eq!(report.target_ping.received, 5);
        accept.await.unwrap();
    }
    #[test]
    fn metrics_distinguish_missing_and_unavailable_and_do_not_bridge_loss() {
        let s = Samples::from_samples(&[Some(10), Some(14), None, Some(30), Some(32)], 1);
        assert_eq!(s.sent, 5);
        assert_eq!(s.received, 4);
        assert_eq!(s.unavailable, 1);
        assert_eq!(s.average_ms, Some(21.5));
        assert_eq!(s.jitter_ms, Some(3.0));
        assert!(Samples::from_samples(&[None; 5], 5).average_ms.is_none());
    }
    #[test]
    fn validates_dns_input() {
        assert!(valid_dns_name("example.com"));
        assert!(!valid_dns_name("1.1.1.1"));
        assert!(!valid_dns_name("https://example.com"));
        assert!(!valid_dns_name("example.com\r\n"));
    }
}
