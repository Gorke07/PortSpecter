//! RFC 6762 legacy-unicast mDNS replies and RFC 4795 TCP reverse lookups.
use std::{
    net::{IpAddr, SocketAddr, SocketAddrV6},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, UdpSocket},
};

fn reverse(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => {
            let b = ip.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", b[3], b[2], b[1], b[0])
        }
        IpAddr::V6(ip) => {
            let digits = format!("{:032x}", u128::from(ip));
            format!(
                "{}.ip6.arpa",
                digits
                    .chars()
                    .rev()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()
                    .join(".")
            )
        }
    }
}
fn request(name: &str, id: u16) -> Vec<u8> {
    let mut bytes = vec![(id >> 8) as u8, id as u8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.extend_from_slice(&[0, 0, 12, 0, 1]);
    bytes
}
fn word(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}
fn name(bytes: &[u8], cursor: &mut usize) -> Option<String> {
    let mut pos = *cursor;
    let mut end = None;
    let mut labels = Vec::new();
    let mut length = 0;
    for _ in 0..128 {
        let size = *bytes.get(pos)?;
        pos += 1;
        if size == 0 {
            *cursor = end.unwrap_or(pos);
            return Some(labels.join("."));
        }
        if size & 0xc0 == 0xc0 {
            let next = *bytes.get(pos)?;
            pos += 1;
            end.get_or_insert(pos);
            pos = ((size as usize & 0x3f) << 8) | next as usize;
            continue;
        }
        if size > 63 {
            return None;
        }
        let label = std::str::from_utf8(bytes.get(pos..pos + size as usize)?).ok()?;
        if label
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '.')
        {
            return None;
        }
        length += label.len() + 1;
        if length > 254 {
            return None;
        }
        labels.push(label.to_owned());
        pos += size as usize;
    }
    None
}
fn response(bytes: &[u8], id: u16, owner: &str) -> Option<String> {
    if word(bytes, 0)? != id {
        return None;
    }
    let flags = word(bytes, 2)?;
    if flags & 0x8000 == 0 || flags & 0x780f != 0 || flags & 0x0200 != 0 {
        return None;
    }
    let questions = word(bytes, 4)?;
    let answers = word(bytes, 6)?;
    if questions > 8 || answers > 64 {
        return None;
    }
    let mut cursor = 12;
    for _ in 0..questions {
        name(bytes, &mut cursor)?;
        bytes.get(cursor..cursor + 4)?;
        cursor += 4;
    }
    for _ in 0..answers {
        let record = name(bytes, &mut cursor)?;
        let kind = word(bytes, cursor)?;
        let class = word(bytes, cursor + 2)? & 0x7fff;
        let length = word(bytes, cursor + 8)? as usize;
        cursor += 10;
        let end = cursor.checked_add(length)?;
        bytes.get(cursor..end)?;
        if kind == 12 && class == 1 && record.eq_ignore_ascii_case(owner) {
            let hostname = name(bytes, &mut cursor)?;
            if cursor != end || hostname.is_empty() || hostname.parse::<IpAddr>().is_ok() {
                return None;
            }
            return Some(hostname);
        }
        cursor = end;
    }
    None
}
fn transaction() -> u16 {
    let id = uuid::Uuid::new_v4();
    u16::from_be_bytes([id.as_bytes()[0], id.as_bytes()[1]])
}

/// Call only for a target confirmed on-link. Replies must originate from that target.
pub async fn mdns_name(
    ip: IpAddr,
    source: IpAddr,
    index: u32,
    timeout: Duration,
) -> Option<String> {
    tokio::time::timeout(timeout, async move {
        let bind = match source {
            IpAddr::V4(_) => SocketAddr::new(source, 0),
            IpAddr::V6(ip) => SocketAddr::V6(SocketAddrV6::new(ip, 0, 0, index)),
        };
        let socket = std::net::UdpSocket::bind(bind).ok()?;
        socket.set_nonblocking(true).ok()?;
        let options = socket2::SockRef::from(&socket);
        let destination = match source {
            IpAddr::V4(source) => {
                options.set_multicast_if_v4(&source).ok()?;
                options.set_multicast_ttl_v4(255).ok()?;
                "224.0.0.251:5353".parse().ok()?
            }
            IpAddr::V6(_) => {
                options.set_multicast_if_v6(index).ok()?;
                options.set_multicast_hops_v6(255).ok()?;
                SocketAddr::V6(SocketAddrV6::new("ff02::fb".parse().ok()?, 5353, 0, index))
            }
        };
        let socket = UdpSocket::from_std(socket).ok()?;
        mdns_query(socket, ip, destination).await
    })
    .await
    .ok()
    .flatten()
}

async fn mdns_query(socket: UdpSocket, ip: IpAddr, destination: SocketAddr) -> Option<String> {
    let id = transaction();
    let owner = reverse(ip);
    socket
        .send_to(&request(&owner, id), destination)
        .await
        .ok()?;
    let mut bytes = [0u8; 9000];
    loop {
        let (length, peer) = socket.recv_from(&mut bytes).await.ok()?;
        if peer.ip() == ip
            && peer.port() == destination.port()
            && let Some(name) = response(&bytes[..length], id, &owner)
        {
            return Some(name);
        }
    }
}

/// LLMNR unicast PTR uses TCP, with hop limit one; unicast UDP is forbidden by RFC 4795.
pub async fn llmnr_name(ip: IpAddr, source: IpAddr, timeout: Duration) -> Option<String> {
    llmnr_at(ip, source, 5355, timeout).await
}
async fn llmnr_at(ip: IpAddr, source: IpAddr, port: u16, timeout: Duration) -> Option<String> {
    tokio::time::timeout(timeout, async move {
        let socket = if ip.is_ipv4() {
            TcpSocket::new_v4().ok()?
        } else {
            TcpSocket::new_v6().ok()?
        };
        socket.bind(SocketAddr::new(source, 0)).ok()?;
        let options = socket2::SockRef::from(&socket);
        if ip.is_ipv4() {
            options.set_ttl_v4(1).ok()?;
        } else {
            options.set_unicast_hops_v6(1).ok()?;
        }
        let mut stream = socket.connect(SocketAddr::new(ip, port)).await.ok()?;
        let id = transaction();
        let owner = reverse(ip);
        let bytes = request(&owner, id);
        stream
            .write_all(&(bytes.len() as u16).to_be_bytes())
            .await
            .ok()?;
        stream.write_all(&bytes).await.ok()?;
        let length = stream.read_u16().await.ok()? as usize;
        if !(12..=9000).contains(&length) {
            return None;
        }
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).await.ok()?;
        response(&bytes, id, &owner)
    })
    .await
    .ok()
    .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn answer(mut query: Vec<u8>) -> Vec<u8> {
        query[2] = 0x80;
        query[7] = 1;
        query.extend_from_slice(&[
            0xc0, 12, 0, 12, 0, 1, 0, 0, 0, 10, 0, 12, 4, b'h', b'o', b's', b't', 5, b'l', b'o',
            b'c', b'a', b'l', 0,
        ]);
        query
    }
    #[tokio::test]
    async fn mdns_socket_rejects_wrong_transaction_before_valid_answer() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut bytes = [0; 512];
            let (length, peer) = server.recv_from(&mut bytes).await.unwrap();
            let valid = answer(bytes[..length].to_vec());
            let mut invalid = valid.clone();
            invalid[0] ^= 1;
            server.send_to(&invalid, peer).await.unwrap();
            server.send_to(&valid, peer).await.unwrap();
        });
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            mdns_query(client, address.ip(), address),
        )
        .await
        .unwrap();
        assert_eq!(result.as_deref(), Some("host.local"));
        task.await.unwrap();
    }
    #[tokio::test]
    async fn llmnr_reads_length_framed_tcp_reply() {
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = server.accept().await.unwrap();
            let length = socket.read_u16().await.unwrap() as usize;
            let mut bytes = vec![0; length];
            socket.read_exact(&mut bytes).await.unwrap();
            let valid = answer(bytes);
            socket
                .write_all(&(valid.len() as u16).to_be_bytes())
                .await
                .unwrap();
            socket.write_all(&valid).await.unwrap();
        });
        assert_eq!(
            llmnr_at(
                address.ip(),
                address.ip(),
                address.port(),
                Duration::from_secs(1)
            )
            .await
            .as_deref(),
            Some("host.local")
        );
        task.await.unwrap();
    }
    #[test]
    fn ptr_is_bound_to_transaction_and_owner_and_rejects_truncation() {
        let owner = reverse("192.0.2.3".parse().unwrap());
        let mut bytes = request(&owner, 42);
        bytes[2] = 0x84;
        bytes[7] = 1;
        bytes.extend_from_slice(&[
            0xc0, 12, 0, 12, 0, 1, 0, 0, 0, 10, 0, 12, 4, b'h', b'o', b's', b't', 5, b'l', b'o',
            b'c', b'a', b'l', 0,
        ]);
        assert_eq!(response(&bytes, 42, &owner).as_deref(), Some("host.local"));
        assert!(response(&bytes, 43, &owner).is_none());
        assert!(response(&bytes, 42, "other").is_none());
        for n in 0..bytes.len() {
            assert!(response(&bytes[..n], 42, &owner).is_none());
        }
    }
    #[test]
    fn compression_cycles_are_bounded() {
        assert!(name(&[0xc0, 0], &mut 0).is_none());
    }
    #[test]
    fn ipv6_reverse_has_all_nibbles() {
        let text = reverse("::1".parse().unwrap());
        assert!(text.starts_with("1.0.0."));
        assert_eq!(text.split('.').count(), 34);
    }
}
