use portspecter_domain::PortState;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::net::UdpSocket;

fn payload(port: u16) -> Vec<u8> {
    match port {
        53 => {
            let id = uuid::Uuid::new_v4();
            let mut data = vec![
                id.as_bytes()[0],
                id.as_bytes()[1],
                1,
                0,
                0,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
            ];
            // A bounded DNS query for the reserved .invalid name; no recursive workload.
            data[2] = 0;
            data.extend_from_slice(b"\x07invalid\x00\x00\x01\x00\x01");
            data
        }
        123 => {
            let mut data = vec![0; 48];
            data[0] = 0x23;
            data
        }
        _ => Vec::new(),
    }
}

/// A connected socket accepts datagrams only from the target tuple. Silence is
/// ambiguous: a UDP service can discard an unrecognized payload without replying.
pub async fn scan(
    ip: IpAddr,
    port: u16,
    source: Option<IpAddr>,
    timeout: Duration,
) -> (PortState, Option<String>) {
    let operation = async {
        let source = source.unwrap_or_else(|| {
            if ip.is_ipv4() {
                "0.0.0.0".parse().unwrap()
            } else {
                "::".parse().unwrap()
            }
        });
        let socket = UdpSocket::bind(SocketAddr::new(source, 0)).await?;
        socket.connect(SocketAddr::new(ip, port)).await?;
        socket.send(&payload(port)).await?;
        let mut response = [0; 4096];
        socket.recv(&mut response).await?;
        Ok::<_, std::io::Error>(())
    };
    match tokio::time::timeout(timeout, operation).await {
        Ok(Ok(())) => (PortState::Open, None),
        Err(_) => (
            PortState::OpenFiltered,
            Some("No UDP response; open or filtered".into()),
        ),
        Ok(Err(error)) => {
            use std::io::ErrorKind;
            let state = match error.kind() {
                ErrorKind::ConnectionRefused => PortState::Closed,
                // Winsock reports a received ICMP port-unreachable as WSAECONNRESET.
                ErrorKind::ConnectionReset
                    if cfg!(windows) && error.raw_os_error() == Some(10054) =>
                {
                    PortState::Closed
                }
                ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable => {
                    PortState::Unreachable
                }
                ErrorKind::TimedOut => PortState::OpenFiltered,
                _ => PortState::LocalError,
            };
            (state, Some(error.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn reply_and_silent_listener_are_distinct() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut data = [0; 512];
            let (_, peer) = socket.recv_from(&mut data).await.unwrap();
            socket.send_to(b"response", peer).await.unwrap();
            socket
        });
        assert_eq!(
            scan(address.ip(), address.port(), None, Duration::from_secs(1))
                .await
                .0,
            PortState::Open
        );
        let _silent = server.await.unwrap();
        assert_eq!(
            scan(
                address.ip(),
                address.port(),
                None,
                Duration::from_millis(50)
            )
            .await
            .0,
            PortState::OpenFiltered
        );
    }
}
