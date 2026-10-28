use anyhow::{Result, bail};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::Command,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceAction {
    Web,
    SecureWeb,
    Ssh,
    Rdp,
    Shares,
}

pub fn destination(action: DeviceAction, ip: IpAddr, port: u16) -> Result<String> {
    if port == 0 {
        bail!("Port must be between 1 and 65535")
    }
    let authority = SocketAddr::new(ip, port);
    Ok(match action {
        DeviceAction::Web => format!("http://{authority}/"),
        DeviceAction::SecureWeb => format!("https://{authority}/"),
        DeviceAction::Ssh => format!("ssh://{authority}"),
        DeviceAction::Rdp => format!("rdp://full%20address=s:{authority}"),
        DeviceAction::Shares => {
            if cfg!(windows) {
                match ip {
                    IpAddr::V4(_) => format!("\\\\{ip}\\"),
                    IpAddr::V6(ip) => format!(
                        "\\\\{}.ipv6-literal.net\\",
                        ip.to_string().replace(':', "-")
                    ),
                }
            } else {
                format!(
                    "smb://{}/",
                    if ip.is_ipv6() {
                        format!("[{ip}]")
                    } else {
                        ip.to_string()
                    }
                )
            }
        }
    })
}

/// Only typed addresses/ports are accepted. No discovered strings become shell commands.
pub fn open(action: DeviceAction, ip: IpAddr, port: u16) -> Result<()> {
    let target = destination(action, ip, port)?;
    #[cfg(windows)]
    let mut command = match action {
        DeviceAction::Ssh => {
            let mut c = Command::new("wt.exe");
            c.args(["ssh", "-p", &port.to_string(), &ip.to_string()]);
            c
        }
        DeviceAction::Rdp => {
            let mut c = Command::new("mstsc.exe");
            c.arg(format!("/v:{}", SocketAddr::new(ip, port)))
                .arg("/prompt");
            c
        }
        DeviceAction::Shares => {
            let mut c = Command::new("explorer.exe");
            c.arg(target);
            c
        }
        _ => {
            let mut c = Command::new("rundll32.exe");
            c.arg("url.dll,FileProtocolHandler").arg(target);
            c
        }
    };
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut c = Command::new("open");
        c.arg(target);
        c
    };
    #[cfg(not(any(windows, target_os = "macos")))]
    let mut command = if action == DeviceAction::Rdp {
        let mut c = Command::new("xfreerdp");
        c.arg(format!("/v:{}", SocketAddr::new(ip, port)));
        c
    } else {
        let mut c = Command::new("xdg-open");
        c.arg(target);
        c
    };
    let mut child = command.spawn()?;
    // Reap without blocking the UI or terminating an interactive client.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

pub fn magic_packet(address: &str) -> Result<[u8; 102]> {
    let mac = portspecter_domain::parse_mac(address)
        .ok_or_else(|| anyhow::anyhow!("Invalid MAC address"))?;
    if mac == [0; 6] || mac[0] & 1 != 0 {
        bail!("Wake-on-LAN requires a unicast MAC address")
    }
    let mut packet = [255; 102];
    for chunk in packet[6..].as_chunks_mut::<6>().0 {
        chunk.copy_from_slice(&mac);
    }
    Ok(packet)
}

pub async fn wake(address: &str, destination: Ipv4Addr) -> Result<()> {
    if destination.is_unspecified() || destination.is_multicast() {
        bail!("Enter a unicast or broadcast IPv4 destination")
    }
    let packet = magic_packet(address)?;
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    socket.set_broadcast(true)?;
    socket.send_to(&packet, (destination, 9)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn destinations_preserve_ipv6_ports_and_reject_zero() {
        assert_eq!(
            destination(DeviceAction::SecureWeb, "::1".parse().unwrap(), 8443).unwrap(),
            "https://[::1]:8443/"
        );
        assert!(destination(DeviceAction::Web, "127.0.0.1".parse().unwrap(), 0).is_err());
    }
    #[test]
    fn magic_packet_is_exact_and_rejects_invalid_addresses() {
        let packet = magic_packet("00:11:22:33:44:55").unwrap();
        assert_eq!(&packet[..6], &[255; 6]);
        assert!(
            packet[6..]
                .as_chunks::<6>()
                .0
                .iter()
                .all(|c| *c == [0, 17, 34, 51, 68, 85])
        );
        assert!(magic_packet("ff:ff:ff:ff:ff:ff").is_err());
        assert!(magic_packet("not a mac").is_err());
    }
}
