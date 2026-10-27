use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Current local routing information, not historical scan evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteInfo {
    pub interface: String,
    pub source: IpAddr,
    pub next_hop: Option<IpAddr>,
    pub on_link: bool,
}

#[cfg(windows)]
pub fn route_to(destination: IpAddr, source: Option<IpAddr>) -> Result<RouteInfo> {
    use windows::Win32::{
        NetworkManagement::IpHelper::{GetBestRoute2, MIB_IPFORWARD_ROW2},
        Networking::WinSock::*,
    };
    fn sockaddr(ip: IpAddr) -> SOCKADDR_INET {
        match ip {
            IpAddr::V4(ip) => SOCKADDR_INET {
                Ipv4: SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_addr: u32::from_ne_bytes(ip.octets()),
                        },
                    },
                    ..Default::default()
                },
            },
            IpAddr::V6(ip) => SOCKADDR_INET {
                Ipv6: SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_addr: IN6_ADDR {
                        u: IN6_ADDR_0 { Byte: ip.octets() },
                    },
                    ..Default::default()
                },
            },
        }
    }
    fn address(value: &SOCKADDR_INET) -> Result<IpAddr> {
        // SAFETY: the family and corresponding initialized union member are supplied by IP Helper.
        unsafe {
            match value.si_family {
                AF_INET => Ok(IpAddr::V4(std::net::Ipv4Addr::from(
                    value.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
                ))),
                AF_INET6 => Ok(IpAddr::V6(std::net::Ipv6Addr::from(
                    value.Ipv6.sin6_addr.u.Byte,
                ))),
                _ => anyhow::bail!("Unsupported route address family"),
            }
        }
    }
    let destination = sockaddr(destination);
    let source = source.map(sockaddr);
    let mut best = MIB_IPFORWARD_ROW2::default();
    let mut best_source = SOCKADDR_INET::default();
    // SAFETY: input addresses and writable outputs remain valid throughout this synchronous API call.
    let status = unsafe {
        GetBestRoute2(
            None,
            0,
            source.as_ref().map(std::ptr::from_ref),
            &destination,
            0,
            &mut best,
            &mut best_source,
        )
    };
    anyhow::ensure!(status.0 == 0, "Windows route lookup failed: {}", status.0);
    let next = address(&best.NextHop)?;
    Ok(RouteInfo {
        interface: super::interfaces()
            .into_iter()
            .find(|i| i.index == best.InterfaceIndex)
            .map(|i| i.name)
            .unwrap_or_else(|| best.InterfaceIndex.to_string()),
        source: address(&best_source)?,
        next_hop: (!next.is_unspecified()).then_some(next),
        on_link: next.is_unspecified(),
    })
}

#[cfg(target_os = "linux")]
pub fn route_to(destination: IpAddr, source: Option<IpAddr>) -> Result<RouteInfo> {
    let mut command = std::process::Command::new("ip");
    command
        .args(["-j", "route", "get"])
        .arg(destination.to_string());
    if let Some(source) = source {
        command.arg("from").arg(source.to_string());
    }
    let output = command.output()?;
    anyhow::ensure!(output.status.success(), "Linux route lookup failed");
    let entries: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)?;
    let route = entries
        .first()
        .ok_or_else(|| anyhow::anyhow!("No route found"))?;
    let source = route
        .get("prefsrc")
        .or_else(|| route.get("src"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Route has no source address"))?
        .parse()?;
    let next_hop = route
        .get("gateway")
        .and_then(|v| v.as_str())
        .map(str::parse)
        .transpose()?;
    Ok(RouteInfo {
        interface: route
            .get("dev")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .into(),
        source,
        next_hop,
        on_link: next_hop.is_none(),
    })
}

#[cfg(target_os = "macos")]
pub fn route_to(destination: IpAddr, source: Option<IpAddr>) -> Result<RouteInfo> {
    anyhow::ensure!(
        source.is_none(),
        "Source-specific route diagnostics are unavailable on macOS"
    );
    let output = std::process::Command::new("/sbin/route")
        .args(["-n", "get"])
        .arg(destination.to_string())
        .env("LC_ALL", "C")
        .output()?;
    anyhow::ensure!(output.status.success(), "macOS route lookup failed");
    let value = String::from_utf8_lossy(&output.stdout);
    let field = |name: &str| {
        value
            .lines()
            .find_map(|line| line.trim().strip_prefix(name).map(str::trim))
    };
    let interface = field("interface:").ok_or_else(|| anyhow::anyhow!("Route has no interface"))?;
    let next_hop = field("gateway:").and_then(|s| s.parse::<IpAddr>().ok());
    let source = super::interfaces()
        .into_iter()
        .find(|i| i.name == interface)
        .and_then(|i| {
            i.addresses
                .into_iter()
                .find(|ip| ip.is_ipv4() == destination.is_ipv4())
        })
        .ok_or_else(|| anyhow::anyhow!("Route source address unavailable"))?;
    Ok(RouteInfo {
        interface: interface.into(),
        source,
        next_hop,
        on_link: next_hop.is_none(),
    })
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn route_to(_: IpAddr, _: Option<IpAddr>) -> Result<RouteInfo> {
    anyhow::bail!("Route diagnostics are unsupported")
}
