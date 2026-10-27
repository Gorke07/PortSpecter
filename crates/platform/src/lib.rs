use anyhow::Result;
use chrono::Utc;
use portspecter_domain::{MacObservation, VendorDatabase, parse_mac};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::IpAddr};

mod ping;
mod route;
pub mod shares;
pub mod syn;
pub use ping::echo;
pub use route::{RouteInfo, route_to};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub index: u32,
    pub name: String,
    pub addresses: Vec<IpAddr>,
    pub networks: Vec<String>,
    pub mac: Option<String>,
}

pub fn interfaces() -> Vec<InterfaceInfo> {
    netdev::get_interfaces()
        .into_iter()
        .filter(|i| !i.ipv4.is_empty() || !i.ipv6.is_empty())
        .map(|i| InterfaceInfo {
            index: i.index,
            name: i.friendly_name.clone().unwrap_or(i.name),
            addresses: i
                .ipv4
                .iter()
                .map(|n| IpAddr::V4(n.addr()))
                .chain(i.ipv6.iter().map(|n| IpAddr::V6(n.addr())))
                .collect(),
            networks: i
                .ipv4
                .iter()
                .map(|n| n.trunc().to_string())
                .chain(i.ipv6.iter().map(|n| n.trunc().to_string()))
                .collect(),
            mac: i.mac_addr.map(|m| m.to_string()),
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct Neighbor {
    pub ip: IpAddr,
    pub mac: [u8; 6],
    pub interface: String,
    pub state: String,
    pub source: String,
}

/// Neighbor entries describe link-layer observations, not verified physical device identities.
pub fn mac_snapshot(vendors: &VendorDatabase) -> Result<HashMap<IpAddr, MacObservation>> {
    let adapters = interfaces();
    let mut result = HashMap::new();
    for n in neighbors()? {
        if n.mac == [0; 6] || n.mac == [255; 6] || n.mac[0] & 1 != 0 {
            continue;
        }
        // Never use a gateway MAC as the destination MAC; require the exact neighbor IP.
        let address = n
            .mac
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":");
        result.insert(
            n.ip,
            MacObservation {
                address,
                interface: n.interface,
                source: n.source,
                neighbor_state: n.state,
                observed_at: Utc::now(),
                vendor: vendors.lookup(&n.mac).map(str::to_owned),
                locally_administered: n.mac[0] & 2 != 0,
            },
        );
    }
    for adapter in adapters {
        if let Some(mac) = adapter.mac.and_then(|v| parse_mac(&v)) {
            if mac == [0; 6] || mac[0] & 1 != 0 {
                continue;
            }
            for ip in adapter.addresses {
                result.insert(
                    ip,
                    MacObservation {
                        address: mac
                            .iter()
                            .map(|b| format!("{b:02X}"))
                            .collect::<Vec<_>>()
                            .join(":"),
                        interface: adapter.name.clone(),
                        source: "local_interface".into(),
                        neighbor_state: "local".into(),
                        observed_at: Utc::now(),
                        vendor: vendors.lookup(&mac).map(str::to_owned),
                        locally_administered: mac[0] & 2 != 0,
                    },
                );
            }
        }
    }
    Ok(result)
}

#[cfg(windows)]
fn neighbors() -> Result<Vec<Neighbor>> {
    use windows::Win32::{
        NetworkManagement::IpHelper::{FreeMibTable, GetIpNetTable2, MIB_IPNET_TABLE2},
        Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC},
    };
    let mut table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
    // SAFETY: the OS allocates this table; it is read only until FreeMibTable below.
    let status = unsafe { GetIpNetTable2(AF_UNSPEC, &mut table) };
    if status.0 == 1168 {
        return Ok(Vec::new());
    }
    anyhow::ensure!(status.0 == 0, "GetIpNetTable2 failed: {}", status.0);
    if table.is_null() {
        return Ok(Vec::new());
    }
    let adapters = interfaces();
    let mut out = Vec::new();
    // SAFETY: the flexible array contains NumEntries initialized rows, as documented by IP Helper.
    unsafe {
        let rows =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        for row in rows {
            if row.PhysicalAddressLength != 6 || matches!(row.State.0, 0 | 1) {
                continue;
            }
            let ip = if row.Address.si_family == AF_INET {
                IpAddr::V4(std::net::Ipv4Addr::from(
                    row.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
                ))
            } else if row.Address.si_family == AF_INET6 {
                IpAddr::V6(std::net::Ipv6Addr::from(row.Address.Ipv6.sin6_addr.u.Byte))
            } else {
                continue;
            };
            let mut mac = [0; 6];
            mac.copy_from_slice(&row.PhysicalAddress[..6]);
            let state = match row.State.0 {
                2 => "probe",
                3 => "delay",
                4 => "stale",
                5 => "reachable",
                6 => "permanent",
                _ => "unknown",
            };
            out.push(Neighbor {
                ip,
                mac,
                interface: adapters
                    .iter()
                    .find(|i| i.index == row.InterfaceIndex)
                    .map(|i| i.name.clone())
                    .unwrap_or_else(|| row.InterfaceIndex.to_string()),
                state: state.into(),
                source: "windows_neighbor_table".into(),
            });
        }
        FreeMibTable(table.cast());
    }
    Ok(out)
}

#[cfg(target_os = "linux")]
fn neighbors() -> Result<Vec<Neighbor>> {
    // iproute2 is present in the supported Ubuntu baseline. Arguments are fixed, no shell is used.
    let output = std::process::Command::new("ip")
        .args(["-j", "neigh", "show"])
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "Could not read Linux neighbor table"
    );
    let entries: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)?;
    Ok(entries
        .iter()
        .filter_map(|e| {
            let states = e.get("state").map(|s| s.to_string()).unwrap_or_default();
            if states.contains("FAILED") || states.contains("INCOMPLETE") {
                return None;
            }
            Some(Neighbor {
                ip: e.get("dst")?.as_str()?.parse().ok()?,
                mac: parse_mac(e.get("lladdr")?.as_str()?)?,
                interface: e.get("dev")?.as_str()?.into(),
                state: states,
                source: "linux_neighbor_table".into(),
            })
        })
        .collect())
}

#[cfg(target_os = "macos")]
fn neighbors() -> Result<Vec<Neighbor>> {
    let mut out = Vec::new();
    for (command, args) in [
        ("/usr/sbin/arp", vec!["-an"]),
        ("/usr/sbin/ndp", vec!["-an"]),
    ] {
        let output = std::process::Command::new(command)
            .args(args)
            .env("LC_ALL", "C")
            .output()?;
        anyhow::ensure!(
            output.status.success(),
            "Could not read macOS neighbor table"
        );
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let words: Vec<_> = line.split_whitespace().collect();
            let ip = words.iter().find_map(|w| {
                w.trim_matches(['(', ')'])
                    .split('%')
                    .next()?
                    .parse::<IpAddr>()
                    .ok()
            });
            let mac = words.iter().find_map(|w| parse_mac(w));
            if let (Some(ip), Some(mac)) = (ip, mac) {
                let interface = words
                    .windows(2)
                    .find(|p| p[0] == "on")
                    .map(|p| p[1])
                    .or_else(|| words.get(2).copied())
                    .unwrap_or("unknown");
                out.push(Neighbor {
                    ip,
                    mac,
                    interface: interface.into(),
                    state: "cached".into(),
                    source: "macos_neighbor_table".into(),
                });
            }
        }
    }
    Ok(out)
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn neighbors() -> Result<Vec<Neighbor>> {
    anyhow::bail!("Neighbor lookup is unsupported on this platform")
}
