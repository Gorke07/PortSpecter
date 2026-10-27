use portspecter_domain::{DiscoveryObservation, DiscoveryState};
use std::{net::IpAddr, time::Duration};

fn observation(
    state: DiscoveryState,
    elapsed_ms: Option<u64>,
    error: Option<String>,
) -> DiscoveryObservation {
    DiscoveryObservation {
        state,
        elapsed_ms,
        error,
        observed_at: chrono::Utc::now(),
    }
}

/// Echo failures never mark a host offline: filtering or unavailable OS facilities are possible.
pub async fn echo(ip: IpAddr, source: Option<IpAddr>, timeout: Duration) -> DiscoveryObservation {
    match tokio::time::timeout(
        timeout + Duration::from_millis(250),
        platform_echo(ip, source, timeout),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => observation(DiscoveryState::Unavailable, None, Some(error.to_string())),
        Err(_) => observation(DiscoveryState::NoReply, None, None),
    }
}

#[cfg(windows)]
async fn platform_echo(
    ip: IpAddr,
    source: Option<IpAddr>,
    timeout: Duration,
) -> anyhow::Result<DiscoveryObservation> {
    use std::sync::{Arc, OnceLock};
    static SLOTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    let permit = SLOTS
        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(32)))
        .clone()
        .acquire_owned()
        .await?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        native_echo(ip, source, timeout)
    })
    .await?
}

#[cfg(windows)]
fn native_echo(
    ip: IpAddr,
    source: Option<IpAddr>,
    timeout: Duration,
) -> anyhow::Result<DiscoveryObservation> {
    use windows::Win32::{
        Foundation::HANDLE, NetworkManagement::IpHelper::*, Networking::WinSock::*,
    };
    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                let _ = IcmpCloseHandle(self.0);
            }
        }
    }
    let data = b"PortSpecter";
    // u64 storage guarantees alignment for the OS reply structures and has ample trailing space.
    let mut reply = [0u64; 128];
    let timeout = timeout.as_millis().clamp(1, u32::MAX as u128) as u32;
    let (count, status, elapsed) = unsafe {
        match ip {
            IpAddr::V4(ip) => {
                let handle = Handle(IcmpCreateFile()?);
                let source = match source {
                    Some(IpAddr::V4(ip)) => u32::from_ne_bytes(ip.octets()),
                    None => 0,
                    _ => anyhow::bail!("ICMP source address family mismatch"),
                };
                let count = IcmpSendEcho2Ex(
                    handle.0,
                    None,
                    None,
                    None,
                    source,
                    u32::from_ne_bytes(ip.octets()),
                    data.as_ptr().cast(),
                    data.len() as u16,
                    None,
                    reply.as_mut_ptr().cast(),
                    std::mem::size_of_val(&reply) as u32,
                    timeout,
                );
                let result = &*reply.as_ptr().cast::<ICMP_ECHO_REPLY>();
                (count, result.Status, result.RoundTripTime)
            }
            IpAddr::V6(ip) => {
                let handle = Handle(Icmp6CreateFile()?);
                let address = |ip: std::net::Ipv6Addr| {
                    let mut address = SOCKADDR_IN6 {
                        sin6_family: AF_INET6,
                        ..Default::default()
                    };
                    address.sin6_addr.u.Byte = ip.octets();
                    address
                };
                let source = match source {
                    Some(IpAddr::V6(ip)) => ip,
                    None => std::net::Ipv6Addr::UNSPECIFIED,
                    _ => anyhow::bail!("ICMP source address family mismatch"),
                };
                let count = Icmp6SendEcho2(
                    handle.0,
                    None,
                    None,
                    None,
                    &address(source),
                    &address(ip),
                    data.as_ptr().cast(),
                    data.len() as u16,
                    None,
                    reply.as_mut_ptr().cast(),
                    std::mem::size_of_val(&reply) as u32,
                    timeout,
                );
                let result = &*reply.as_ptr().cast::<ICMPV6_ECHO_REPLY_LH>();
                (count, result.Status, result.RoundTripTime)
            }
        }
    };
    Ok(if count > 0 && status == 0 {
        observation(DiscoveryState::Reachable, Some(elapsed as u64), None)
    } else {
        observation(DiscoveryState::NoReply, None, None)
    })
}

#[cfg(not(windows))]
async fn platform_echo(
    ip: IpAddr,
    source: Option<IpAddr>,
    timeout: Duration,
) -> anyhow::Result<DiscoveryObservation> {
    let executable = if cfg!(target_os = "macos") && ip.is_ipv6() {
        "ping6"
    } else {
        "ping"
    };
    let mut command = tokio::process::Command::new(executable);
    command
        .env("LC_ALL", "C")
        .args(["-n", "-c", "1"])
        .kill_on_drop(true);
    #[cfg(target_os = "linux")]
    {
        command.arg(if ip.is_ipv4() { "-4" } else { "-6" });
        command.args(["-W", &timeout.as_secs().max(1).to_string()]);
        if let Some(source) = source {
            command.args(["-I", &source.to_string()]);
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = timeout;
        if let Some(source) = source {
            command.args(["-S", &source.to_string()]);
        }
    }
    let output = command.arg(ip.to_string()).output().await?;
    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        let elapsed = text
            .split("time=")
            .nth(1)
            .and_then(|part| part.split_whitespace().next())
            .and_then(|part| part.parse::<f64>().ok())
            .map(|ms| ms.ceil() as u64);
        Ok(observation(DiscoveryState::Reachable, elapsed, None))
    } else if output.status.code() == Some(1)
        || (cfg!(target_os = "macos")
            && output.status.code() == Some(2)
            && output.stderr.is_empty())
    {
        Ok(observation(DiscoveryState::NoReply, None, None))
    } else {
        Ok(observation(
            DiscoveryState::Unavailable,
            None,
            Some(
                String::from_utf8_lossy(&output.stderr)
                    .chars()
                    .take(250)
                    .collect(),
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn local_echo_is_real_and_bounded() {
        for ip in ["127.0.0.1", "::1"] {
            let result = echo(ip.parse().unwrap(), None, Duration::from_secs(1)).await;
            assert_eq!(
                result.state,
                DiscoveryState::Reachable,
                "{ip}: {:?}",
                result.error
            );
        }
    }
}
