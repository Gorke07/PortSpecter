use crate::ScanSettings;
use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub const MAX_HOSTS: usize = 65_536;
pub const MAX_PROBES: usize = 10_000_000;
pub const DEFAULT_UDP_PORTS: &str = "53,123,137,161,5353";
pub const EXTENDED_UDP_PORTS: &str = "53,123,137,161,500,514,1900,4500,5353,5355,11211";

pub const DEFAULT_PORTS: &str = "21,22,53,80,135,139,443,445,3389,5900,8080";
pub const EXTENDED_PORTS: &str = "21,22,25,53,80,110,135,139,143,389,443,445,465,587,636,993,995,1433,1521,2049,2375,3000,3306,3389,5432,5900,6379,8000,8080,8443,9000,9090,9200,27017";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetBlock {
    pub target: String,
    pub name: String,
    pub vlan_id: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedHost {
    pub ip: IpAddr,
    pub blocks: Vec<usize>,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPlan {
    pub blocks: Vec<TargetBlock>,
    pub hosts: Vec<PlannedHost>,
    pub ports: Vec<u16>,
    pub settings: ScanSettings,
}

pub fn parse_ports(input: &str) -> Result<Vec<u16>> {
    let mut ports = BTreeSet::new();
    for token in input
        .split([',', ';', ' ', '\n'])
        .filter(|s| !s.trim().is_empty())
    {
        if let Some((a, b)) = token.split_once('-') {
            let a: u16 = a.trim().parse().context("Invalid port range")?;
            let b: u16 = b.trim().parse().context("Invalid port range")?;
            ensure!(a > 0 && a <= b, "Invalid port range: {token}");
            ports.extend(a..=b);
        } else {
            let port: u16 = token.trim().parse().context("Invalid port")?;
            ensure!(port > 0, "Port zero is not supported");
            ports.insert(port);
        }
    }
    ensure!(!ports.is_empty(), "Enter at least one TCP port");
    Ok(ports.into_iter().collect())
}

/// Lines use target | optional name | optional VLAN. Comma/semicolon-separated bare targets are accepted.
pub fn parse_blocks(input: &str) -> Result<Vec<TargetBlock>> {
    let mut blocks = Vec::new();
    for line in input.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        for item in line.split([';', ',']) {
            let parts: Vec<_> = item.split('|').map(str::trim).collect();
            ensure!(
                parts.len() <= 3 && !parts[0].is_empty(),
                "Invalid target: {item}"
            );
            let vlan_id = parts
                .get(2)
                .filter(|s| !s.is_empty())
                .map(|s| s.parse::<u16>())
                .transpose()
                .context("Invalid VLAN ID")?;
            ensure!(
                vlan_id.is_none_or(|v| (1..=4094).contains(&v)),
                "VLAN ID must be 1–4094"
            );
            blocks.push(TargetBlock {
                target: parts[0].into(),
                name: parts
                    .get(1)
                    .filter(|s| !s.is_empty())
                    .unwrap_or(&parts[0])
                    .to_string(),
                vlan_id,
            });
        }
    }
    ensure!(!blocks.is_empty(), "Enter at least one target");
    ensure!(
        blocks.len() <= 4096,
        "At most 4096 target blocks per session"
    );
    Ok(blocks)
}

pub fn import_targets(path: &std::path::Path) -> Result<String> {
    ensure!(
        std::fs::metadata(path)?.len() <= 2_000_000,
        "Target file is too large (2 MB maximum)"
    );
    if path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("csv"))
    {
        let mut reader = csv::Reader::from_path(path)?;
        let headers = reader.headers()?.clone();
        let target = headers
            .iter()
            .position(|h| h == "target")
            .context("CSV needs a target column")?;
        let name = headers.iter().position(|h| h == "name");
        let vlan = headers.iter().position(|h| h == "vlan_id");
        let mut lines = Vec::new();
        for (i, record) in reader.records().enumerate() {
            let record = record.with_context(|| format!("Invalid CSV row {}", i + 2))?;
            let t = record.get(target).unwrap_or("");
            let n = name.and_then(|n| record.get(n)).unwrap_or("");
            let v = vlan.and_then(|n| record.get(n)).unwrap_or("");
            ensure!(
                ![t, n, v]
                    .iter()
                    .any(|s| s.contains(['|', '\n', '\r', ',', ';'])),
                "Invalid delimiter at CSV row {}",
                i + 2
            );
            let line = format!("{t}|{n}|{v}");
            parse_blocks(&line).with_context(|| format!("Invalid CSV row {}", i + 2))?;
            lines.push(line);
        }
        let result = lines.join("\n");
        parse_blocks(&result)?;
        Ok(result)
    } else {
        let value = std::fs::read_to_string(path)?;
        parse_blocks(&value)?;
        Ok(value)
    }
}

/// Returns None only for a hostname which must be resolved asynchronously by the core.
pub fn expand_literal(input: &str) -> Result<Option<Vec<IpAddr>>> {
    let input = input.trim();
    if let Ok(ip) = input.parse::<IpAddr>() {
        return Ok(Some(vec![ip]));
    }
    if input.contains('/') {
        let net: IpNet = input.parse().context("Invalid CIDR")?;
        let host_bits = match net {
            IpNet::V4(v) => 32 - v.prefix_len(),
            IpNet::V6(v) => 128 - v.prefix_len(),
        };
        ensure!(
            host_bits <= 16,
            "Subnet too large; split it into blocks of at most 65536 addresses"
        );
        return Ok(Some(net.hosts().collect()));
    }
    if let Some((a, b)) = input.split_once('-')
        && let Ok(a) = a.trim().parse::<IpAddr>()
    {
        let b = b.trim();
        let b = if let Ok(ip) = b.parse::<IpAddr>() {
            ip
        } else if let IpAddr::V4(start) = a {
            ensure!(
                !b.is_empty() && b.bytes().all(|c| c.is_ascii_digit()),
                "Invalid IP range end: {b}; use a full IP or final IPv4 octet (e.g. 192.168.2.1-255)"
            );
            let end: u8 = b
                .parse()
                .context("Final IPv4 octet must be between 0 and 255")?;
            let [first, second, third, _] = start.octets();
            IpAddr::V4(Ipv4Addr::new(first, second, third, end))
        } else {
            bail!("IPv6 ranges require two full addresses");
        };
        let (start, end, is_v4) = match (a, b) {
            (IpAddr::V4(a), IpAddr::V4(b)) => (u32::from(a) as u128, u32::from(b) as u128, true),
            (IpAddr::V6(a), IpAddr::V6(b)) => (u128::from(a), u128::from(b), false),
            _ => bail!("Address range families do not match"),
        };
        ensure!(
            end >= start && end - start < MAX_HOSTS as u128,
            "Invalid or oversized IP range"
        );
        return Ok(Some(
            (start..=end)
                .map(|v| {
                    if is_v4 {
                        IpAddr::V4(Ipv4Addr::from(v as u32))
                    } else {
                        IpAddr::V6(Ipv6Addr::from(v))
                    }
                })
                .collect(),
        ));
    }
    if let Some((start, _)) = input.split_once('-') {
        ensure!(
            !start.contains('.') || !start.chars().all(|c| c.is_ascii_digit() || c == '.'),
            "Invalid IP range start: {start}"
        );
    }
    ensure!(
        !input.contains([':', '%', ' ', '\t'])
            && input
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'),
        "Invalid target: {input}"
    );
    ensure!(
        !input.chars().all(|c| c.is_ascii_digit() || c == '.'),
        "Invalid IP address: {input}"
    );
    Ok(None)
}

pub fn merge_targets(
    blocks: Vec<TargetBlock>,
    expanded: Vec<Vec<IpAddr>>,
    exclusions: &[IpNet],
    ports: Vec<u16>,
    settings: ScanSettings,
) -> Result<ScanPlan> {
    settings.validate()?;
    ensure!(blocks.len() == expanded.len(), "Target expansion mismatch");
    let mut hosts: BTreeMap<IpAddr, PlannedHost> = BTreeMap::new();
    for (index, addresses) in expanded.into_iter().enumerate() {
        for ip in addresses {
            if exclusions.iter().any(|n| n.contains(&ip)) {
                continue;
            }
            ensure!(
                !ip.is_unspecified() && !ip.is_multicast() && ip != IpAddr::V4(Ipv4Addr::BROADCAST),
                "Unsupported target address: {ip}"
            );
            ensure!(
                !matches!(ip, IpAddr::V6(v) if v.is_unicast_link_local()),
                "Scoped IPv6 link-local targets are not supported in this build"
            );
            if let Some(source) = settings.source_ip {
                ensure!(
                    source.is_ipv4() == ip.is_ipv4(),
                    "Source and target address families must match"
                );
            }
            let hostname = blocks[index]
                .target
                .parse::<IpAddr>()
                .err()
                .filter(|_| {
                    !blocks[index].target.contains('/') && !blocks[index].target.contains('-')
                })
                .map(|_| blocks[index].target.clone());
            let entry = hosts.entry(ip).or_insert(PlannedHost {
                ip,
                blocks: Vec::new(),
                hostname,
            });
            if !entry.blocks.contains(&index) {
                entry.blocks.push(index);
            }
            ensure!(
                hosts.len() <= MAX_HOSTS,
                "Too many unique addresses (65536 maximum)"
            );
        }
    }
    ensure!(!hosts.is_empty(), "No targets remain after exclusions");
    ensure!(!ports.is_empty() && !ports.contains(&0), "Invalid ports");
    ensure!(
        hosts
            .len()
            .checked_mul(ports.len())
            .is_some_and(|n| n <= MAX_PROBES),
        "Plan exceeds 10 million TCP probes; split the session"
    );
    // Interleave blocks, preserving one unique host per address.
    let mut buckets: Vec<std::collections::VecDeque<PlannedHost>> =
        vec![Default::default(); blocks.len()];
    for host in hosts.into_values() {
        buckets[host.blocks[0]].push_back(host);
    }
    let mut ordered = Vec::new();
    loop {
        let before = ordered.len();
        for bucket in &mut buckets {
            if let Some(host) = bucket.pop_front() {
                ordered.push(host);
            }
        }
        if before == ordered.len() {
            break;
        }
    }
    Ok(ScanPlan {
        blocks,
        hosts: ordered,
        ports,
        settings,
    })
}

pub fn parse_exclusions(input: &str) -> Result<Vec<IpNet>> {
    input
        .split([',', ';', '\n', ' '])
        .filter(|s| !s.trim().is_empty())
        .map(|s| {
            if let Ok(ip) = s.parse::<IpAddr>() {
                Ok(IpNet::from(ip))
            } else {
                s.parse().context("Invalid exclusion; use IP or CIDR")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn port_validation() {
        assert_eq!(parse_ports("22,80-82,22").unwrap(), vec![22, 80, 81, 82]);
        for v in ["0", "80-22", "65536", ""] {
            assert!(parse_ports(v).is_err());
        }
    }
    #[test]
    fn cidr_edges() {
        assert_eq!(expand_literal("192.0.2.0/31").unwrap().unwrap().len(), 2);
        assert_eq!(expand_literal("192.0.2.1/32").unwrap().unwrap().len(), 1);
        assert_eq!(expand_literal("192.0.2.0/24").unwrap().unwrap().len(), 254);
        assert!(expand_literal("::/0").is_err());
    }
    #[test]
    fn ipv4_short_range_includes_both_ends() {
        let short = expand_literal("192.168.2.1-255").unwrap().unwrap();
        let full = expand_literal("192.168.2.1-192.168.2.255")
            .unwrap()
            .unwrap();
        assert_eq!(short, full);
        assert_eq!(short.len(), 255);
        assert_eq!(short.first(), Some(&"192.168.2.1".parse().unwrap()));
        assert_eq!(short.last(), Some(&"192.168.2.255".parse().unwrap()));
        assert_eq!(
            expand_literal("192.168.2.255-255").unwrap().unwrap().len(),
            1
        );
        assert_eq!(
            expand_literal("192.168.2.0-255").unwrap().unwrap().len(),
            256
        );
    }
    #[test]
    fn invalid_short_ranges_do_not_fall_through_to_dns() {
        for target in [
            "192.168.2.1-256",
            "192.168.2.200-100",
            "192.168.2.1-",
            "192.168.2.1-foo",
            "192.168.2.1-1.5",
            "999.168.2.1-255",
            "192.168.2.1-255-256",
        ] {
            assert!(
                expand_literal(target).is_err(),
                "Accepted invalid range: {target}"
            );
        }
        assert!(expand_literal("nas-01.local").unwrap().is_none());
        assert_eq!(
            expand_literal("2001:db8::1-2001:db8::3")
                .unwrap()
                .unwrap()
                .len(),
            3
        );
    }
    #[test]
    fn cidr_with_host_bits_expands_the_network() {
        let addresses = expand_literal("192.168.2.1/24").unwrap().unwrap();
        assert_eq!(
            addresses,
            expand_literal("192.168.2.0/24").unwrap().unwrap()
        );
        assert_eq!(addresses.len(), 254);
        assert_eq!(addresses.first(), Some(&"192.168.2.1".parse().unwrap()));
        assert_eq!(addresses.last(), Some(&"192.168.2.254".parse().unwrap()));
    }
    #[test]
    fn merge_and_exclude() {
        let blocks = parse_blocks("192.0.2.0/30|One|10\n192.0.2.1|Two|20").unwrap();
        let expanded = blocks
            .iter()
            .map(|b| expand_literal(&b.target).unwrap().unwrap())
            .collect();
        let plan = merge_targets(
            blocks,
            expanded,
            &parse_exclusions("192.0.2.2").unwrap(),
            vec![80],
            ScanSettings::default(),
        )
        .unwrap();
        assert_eq!(plan.hosts.len(), 1);
        assert_eq!(plan.hosts[0].blocks, vec![0, 1]);
    }
    #[test]
    fn invalid_addresses() {
        for s in ["999.2.3.4", "192.0.2.1/99", "1.2.3.4-1.2.3.1"] {
            assert!(expand_literal(s).is_err());
        }
    }
    #[test]
    fn vlan_validation() {
        assert!(parse_blocks("192.0.2.1|A|4095").is_err());
        assert_eq!(parse_blocks("192.0.2.1|A|10").unwrap()[0].vlan_id, Some(10));
    }
}
