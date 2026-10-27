//! RFC 1002 unicast node-status queries. No credentials, broadcasts or name registration.
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::net::UdpSocket;

fn request(id: u16) -> Vec<u8> {
    let mut bytes = vec![(id >> 8) as u8, id as u8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 32];
    let mut name = [0u8; 16];
    name[0] = b'*';
    for byte in name {
        bytes.push(b'A' + (byte >> 4));
        bytes.push(b'A' + (byte & 15));
    }
    bytes.extend_from_slice(&[0, 0, 0x21, 0, 1]);
    bytes
}
fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}
fn skip_name(bytes: &[u8], cursor: &mut usize) -> Option<()> {
    for _ in 0..128 {
        let length = *bytes.get(*cursor)?;
        *cursor += 1;
        if length == 0 {
            return Some(());
        }
        if length & 0xc0 == 0xc0 {
            let low = *bytes.get(*cursor)?;
            *cursor += 1;
            let pointer = ((length as usize & 0x3f) << 8) | low as usize;
            return (pointer < bytes.len()).then_some(());
        }
        if length > 63 {
            return None;
        }
        bytes.get(*cursor..*cursor + length as usize)?;
        *cursor += length as usize;
    }
    None
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeStatus {
    pub mac: Option<[u8; 6]>,
    pub hostname: Option<String>,
}
fn response_status(bytes: &[u8], id: u16) -> Option<NodeStatus> {
    if u16_at(bytes, 0)? != id {
        return None;
    }
    let flags = u16_at(bytes, 2)?;
    if flags & 0x8000 == 0 || flags & 0x7800 != 0 || flags & 0x020f != 0 {
        return None;
    }
    let questions = u16_at(bytes, 4)?;
    let answers = u16_at(bytes, 6)?;
    if questions > 8 || answers == 0 || answers > 32 {
        return None;
    }
    let mut cursor = 12;
    for _ in 0..questions {
        skip_name(bytes, &mut cursor)?;
        bytes.get(cursor..cursor + 4)?;
        cursor += 4;
    }
    for _ in 0..answers {
        skip_name(bytes, &mut cursor)?;
        let kind = u16_at(bytes, cursor)?;
        let class = u16_at(bytes, cursor + 2)?;
        let length = u16_at(bytes, cursor + 8)? as usize;
        cursor += 10;
        let data = bytes.get(cursor..cursor + length)?;
        cursor += length;
        if kind != 0x21 || class != 1 {
            continue;
        }
        let names = *data.first()? as usize;
        let statistics = 1 + names * 18;
        // The node-status statistics field is 46 bytes; its first six are UNIT_ID.
        data.get(statistics..statistics + 46)?;
        let mac: [u8; 6] = data.get(statistics..statistics + 6)?.try_into().ok()?;
        let mac = (mac != [0; 6] && mac != [255; 6] && mac[0] & 1 == 0).then_some(mac);
        let mut candidates = Vec::new();
        for record in data.get(1..statistics)?.as_chunks::<18>().0 {
            let suffix = record[15];
            let flags = u16::from_be_bytes([record[16], record[17]]);
            // Unique, active, non-conflicting workstation or server names only.
            if ![0, 0x20].contains(&suffix)
                || flags & 0x8000 != 0
                || flags & 0x0400 == 0
                || flags & 0x1800 != 0
            {
                continue;
            }
            if let Ok(name) = std::str::from_utf8(&record[..15]) {
                let name = name.trim_end_matches([' ', '\0']);
                if !name.is_empty() && !name.chars().any(|c| c.is_control() || c.is_whitespace()) {
                    candidates.push((suffix, name.to_owned()));
                }
            }
        }
        candidates.sort_by_key(|(suffix, _)| *suffix);
        return Some(NodeStatus {
            mac,
            hostname: candidates.into_iter().next().map(|(_, name)| name),
        });
    }
    None
}

pub async fn query_mac(
    ip: IpAddr,
    source: Option<IpAddr>,
    timeout: Duration,
) -> std::io::Result<Option<[u8; 6]>> {
    Ok(query_node_status(ip, source, timeout)
        .await?
        .and_then(|status| status.mac))
}
pub async fn query_node_status(
    ip: IpAddr,
    source: Option<IpAddr>,
    timeout: Duration,
) -> std::io::Result<Option<NodeStatus>> {
    if !ip.is_ipv4() {
        return Ok(None);
    }
    query(SocketAddr::new(ip, 137), source, timeout).await
}
async fn query(
    destination: SocketAddr,
    source: Option<IpAddr>,
    timeout: Duration,
) -> std::io::Result<Option<NodeStatus>> {
    let transaction = uuid::Uuid::new_v4();
    let id = u16::from_be_bytes([transaction.as_bytes()[0], transaction.as_bytes()[1]]);
    let socket = UdpSocket::bind(SocketAddr::new(
        source.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
        0,
    ))
    .await?;
    // A connected UDP socket rejects datagrams from other IP/port pairs.
    socket.connect(destination).await?;
    socket.send(&request(id)).await?;
    let deadline = tokio::time::Instant::now() + timeout;
    let mut bytes = [0u8; 8192];
    loop {
        match tokio::time::timeout_at(deadline, socket.recv(&mut bytes)).await {
            Ok(Ok(length)) => {
                if let Some(status) = response_status(&bytes[..length], id) {
                    return Ok(Some(status));
                }
            }
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                return Ok(None);
            }
            Ok(Err(error)) => return Err(error),
            Err(_) => return Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn response_mac(bytes: &[u8], id: u16) -> Option<[u8; 6]> {
        response_status(bytes, id).and_then(|status| status.mac)
    }
    #[test]
    fn hostname_survives_missing_mac_and_rejects_group_name() {
        let bytes = reply(42, [0; 6]);
        assert_eq!(
            response_status(&bytes, 42).unwrap().hostname.as_deref(),
            Some("TEST-PC")
        );
        let mut bytes = bytes;
        bytes[79] |= 0x80;
        assert!(response_status(&bytes, 42).unwrap().hostname.is_none());
    }
    fn reply(id: u16, mac: [u8; 6]) -> Vec<u8> {
        let mut bytes = request(id);
        bytes[2] = 0x84;
        bytes[7] = 1;
        let mut data = vec![1];
        data.extend_from_slice(b"TEST-PC        ");
        data.extend_from_slice(&[0, 4, 0]);
        let mut statistics = [0; 46];
        statistics[..6].copy_from_slice(&mac);
        data.extend_from_slice(&statistics);
        bytes.extend_from_slice(&[0xc0, 0x0c, 0, 0x21, 0, 1, 0, 0, 0, 0]);
        bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
        bytes.extend(data);
        bytes
    }
    #[test]
    fn extracts_valid_unit_id_and_rejects_truncation() {
        let bytes = reply(42, [0, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(
            response_mac(&bytes, 42),
            Some([0, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
        for length in 0..bytes.len() {
            assert_eq!(response_mac(&bytes[..length], 42), None, "length {length}");
        }
        assert_eq!(response_mac(&bytes, 43), None);
    }
    #[test]
    fn does_not_invent_mac_from_zero_multicast_or_error() {
        for mac in [[0; 6], [255; 6], [1, 2, 3, 4, 5, 6]] {
            assert_eq!(response_mac(&reply(9, mac), 9), None);
        }
        let mut bytes = reply(9, [0, 1, 2, 3, 4, 5]);
        bytes[3] = 3;
        assert_eq!(response_mac(&bytes, 9), None);
        let mut bytes = reply(9, [0, 1, 2, 3, 4, 5]);
        bytes[2] = 0;
        assert_eq!(response_mac(&bytes, 9), None);
    }
    #[tokio::test]
    async fn unicast_query_accepts_only_matching_response() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut bytes = [0; 512];
            let (n, peer) = server.recv_from(&mut bytes).await.unwrap();
            assert_eq!(n, 50);
            let id = u16_at(&bytes, 0).unwrap();
            server
                .send_to(&reply(id.wrapping_add(1), [0, 1, 2, 3, 4, 5]), peer)
                .await
                .unwrap();
            server
                .send_to(&reply(id, [0, 0x11, 0x22, 0x33, 0x44, 0x55]), peer)
                .await
                .unwrap();
        });
        assert_eq!(
            query(address, None, Duration::from_secs(1))
                .await
                .unwrap()
                .and_then(|status| status.mac),
            Some([0, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
        task.await.unwrap();
    }
}
