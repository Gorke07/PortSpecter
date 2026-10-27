//! Read-only IPv4 multicast discovery. Advertised URLs are data, never fetched automatically.
use chrono::Utc;
use portspecter_domain::{CameraObservation, parse_mac};
use roxmltree::{Document, Node, ParsingOptions};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::HashSet,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::net::UdpSocket;

const SOAP: &str = "http://www.w3.org/2003/05/soap-envelope";
const WSA: &str = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
const WSD: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery";
const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);

fn text(node: Node<'_, '_>, name: &str) -> Option<String> {
    node.children()
        .find(|n| n.is_element() && n.tag_name().name() == name)
        .and_then(|n| n.text())
        .map(clean)
        .filter(|s| !s.is_empty())
}
fn clean(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(2048)
        .collect::<String>()
        .trim()
        .to_owned()
}
fn document(bytes: &[u8]) -> Option<Document<'_>> {
    if bytes.len() > 60_000 {
        return None;
    }
    Document::parse_with_options(
        std::str::from_utf8(bytes).ok()?.trim_end_matches('\0'),
        ParsingOptions {
            allow_dtd: false,
            nodes_limit: 2048,
            ..Default::default()
        },
    )
    .ok()
}
fn blank(protocol: &str, interface: &str) -> CameraObservation {
    CameraObservation {
        protocol: protocol.into(),
        endpoint_id: String::new(),
        name: None,
        model: None,
        serial: None,
        firmware: None,
        mac: None,
        activated: None,
        endpoints: vec![],
        scopes: vec![],
        interface: interface.into(),
        observed_at: Utc::now(),
    }
}

pub fn parse_onvif(
    bytes: &[u8],
    request_id: &str,
    peer: IpAddr,
    interface: &str,
) -> Vec<CameraObservation> {
    let Some(doc) = document(bytes) else {
        return vec![];
    };
    let root = doc.root_element();
    if !root.has_tag_name((SOAP, "Envelope")) {
        return vec![];
    }
    let Some(header) = root.children().find(|n| n.has_tag_name((SOAP, "Header"))) else {
        return vec![];
    };
    if !header
        .children()
        .any(|n| n.has_tag_name((WSA, "RelatesTo")) && n.text() == Some(request_id))
    {
        return vec![];
    }
    let Some(body) = root.children().find(|n| n.has_tag_name((SOAP, "Body"))) else {
        return vec![];
    };
    let mut records = vec![];
    for node in body
        .descendants()
        .filter(|n| n.has_tag_name((WSD, "ProbeMatch")))
        .take(16)
    {
        let scopes: Vec<String> = text(node, "Scopes")
            .unwrap_or_default()
            .split_whitespace()
            .take(32)
            .map(str::to_owned)
            .collect();
        let onvif_type = node
            .children()
            .find(|n| n.has_tag_name((WSD, "Types")))
            .is_some_and(|n| {
                n.text().unwrap_or("").split_whitespace().any(|q| {
                    let (prefix, local) = q.split_once(':').unwrap_or(("", q));
                    let ns = n.lookup_namespace_uri((!prefix.is_empty()).then_some(prefix));
                    matches!(local, "NetworkVideoTransmitter" | "Device")
                        && matches!(
                            ns,
                            Some(
                                "http://www.onvif.org/ver10/network/wsdl"
                                    | "http://www.onvif.org/ver10/device/wsdl"
                            )
                        )
                })
            });
        if !onvif_type
            && !scopes
                .iter()
                .any(|s| s.starts_with("onvif://www.onvif.org/"))
        {
            continue;
        }
        let mut item = blank("ONVIF", interface);
        item.endpoint_id = node
            .children()
            .find(|n| n.has_tag_name((WSA, "EndpointReference")))
            .and_then(|n| text(n, "Address"))
            .unwrap_or_default();
        if item.endpoint_id.is_empty() {
            continue;
        }
        item.endpoints = text(node, "XAddrs")
            .unwrap_or_default()
            .split_whitespace()
            .take(16)
            .filter_map(|s| {
                let url = url::Url::parse(s).ok()?;
                // Do not accept credentials or endpoints pointing at a different device.
                (matches!(url.scheme(), "http" | "https")
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url
                        .host_str()?
                        .trim_matches(['[', ']'])
                        .parse::<IpAddr>()
                        .ok()
                        == Some(peer))
                .then(|| url.to_string())
            })
            .collect();
        for scope in &scopes {
            for (prefix, field) in [
                ("onvif://www.onvif.org/name/", &mut item.name),
                ("onvif://www.onvif.org/hardware/", &mut item.model),
            ] {
                if let Some(value) = scope.strip_prefix(prefix) {
                    *field = Some(clean(
                        &percent_encoding::percent_decode_str(value).decode_utf8_lossy(),
                    ));
                }
            }
        }
        item.scopes = scopes;
        records.push(item);
    }
    records
}

pub fn parse_sadp(bytes: &[u8], peer: IpAddr, interface: &str) -> Option<CameraObservation> {
    let doc = document(bytes)?;
    let node = doc.root_element();
    if node.tag_name().name() != "ProbeMatch"
        || text(node, "Types")?.to_lowercase() != "inquiry"
        || text(node, "IPv4Address")?.parse::<IpAddr>().ok()? != peer
    {
        return None;
    }
    let mut item = blank("SADP", interface);
    item.serial = text(node, "DeviceSN");
    item.endpoint_id = item.serial.clone()?;
    item.model = text(node, "DeviceDescription");
    item.firmware = text(node, "SoftwareVersion");
    item.activated = text(node, "Activated").and_then(|v| match v.as_str() {
        "true" | "1" => Some(true),
        "false" | "0" => Some(false),
        _ => None,
    });
    item.mac = text(node, "MAC")
        .and_then(|s| parse_mac(&s))
        .filter(|m| *m != [0; 6] && m[0] & 1 == 0)
        .map(|m| {
            m.iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(":")
        });
    if let Some(port) = text(node, "HttpPort")
        .and_then(|p| p.parse::<u16>().ok())
        .filter(|p| *p != 0)
    {
        item.endpoints.push(format!("http://{peer}:{port}/"));
    }
    Some(item)
}

fn socket(source: Ipv4Addr, sadp: bool) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    if sadp {
        socket.set_reuse_address(true)?;
    }
    socket.bind(
        &SocketAddr::from((
            if sadp { Ipv4Addr::UNSPECIFIED } else { source },
            if sadp { 37020 } else { 0 },
        ))
        .into(),
    )?;
    socket.set_multicast_if_v4(&source)?;
    socket.set_multicast_ttl_v4(1)?;
    socket.set_multicast_loop_v4(false)?;
    if sadp {
        socket.join_multicast_v4(&GROUP, &source)?;
    }
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

pub async fn discover(
    source: Ipv4Addr,
    sadp: bool,
    targets: &HashSet<IpAddr>,
) -> io::Result<Vec<(IpAddr, CameraObservation)>> {
    let socket = socket(source, sadp)?;
    let id = format!("uuid:{}", uuid::Uuid::new_v4());
    let request = if sadp {
        format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?><Probe><Uuid>{}</Uuid><Types>inquiry</Types></Probe>",
            id.trim_start_matches("uuid:")
        )
    } else {
        format!(
            "<s:Envelope xmlns:s=\"{SOAP}\" xmlns:a=\"{WSA}\" xmlns:d=\"{WSD}\" xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\"><s:Header><a:MessageID>{id}</a:MessageID><a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To><a:Action>{WSD}/Probe</a:Action></s:Header><s:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></s:Body></s:Envelope>"
        )
    };
    let destination = SocketAddr::from((GROUP, if sadp { 37020 } else { 3702 }));
    exchange(socket, source, sadp, targets, destination, id, request).await
}

async fn exchange(
    socket: UdpSocket,
    source: Ipv4Addr,
    sadp: bool,
    targets: &HashSet<IpAddr>,
    destination: SocketAddr,
    id: String,
    request: String,
) -> io::Result<Vec<(IpAddr, CameraObservation)>> {
    socket.send_to(request.as_bytes(), destination).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut retry = tokio::time::interval(Duration::from_millis(800));
    retry.tick().await;
    let mut sends = 1;
    let mut bytes = vec![0; 65_536];
    let mut results = vec![];
    let mut seen = HashSet::new();
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            _ = retry.tick(), if sends < 3 => { socket.send_to(request.as_bytes(),destination).await?; sends+=1; },
            response = socket.recv_from(&mut bytes) => {
                let (n,peer) = response?;
                if !targets.contains(&peer.ip()) || (sadp && peer.port()!=37020) {continue;}
                let values = if sadp {parse_sadp(&bytes[..n],peer.ip(),&source.to_string()).into_iter().collect()}
                    else {parse_onvif(&bytes[..n],&id,peer.ip(),&source.to_string())};
                for value in values {
                    if seen.insert((peer.ip(),value.endpoint_id.clone())) { results.push((peer.ip(),value)); }
                }
                if results.len()>=4096 {break;}
            }
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn udp_discovery_correlates_deduplicates_and_limits_target_scope() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let task = tokio::spawn(async move {
            let mut bytes = [0; 4096];
            let (_, peer) = server.recv_from(&mut bytes).await.unwrap();
            let xml = format!(
                r#"<s:Envelope xmlns:s="{SOAP}" xmlns:a="{WSA}" xmlns:d="{WSD}"><s:Header><a:RelatesTo>uuid:fixture</a:RelatesTo></s:Header><s:Body><d:ProbeMatches><d:ProbeMatch><a:EndpointReference><a:Address>camera1</a:Address></a:EndpointReference><d:Scopes>onvif://www.onvif.org/name/Test</d:Scopes><d:XAddrs>http://127.0.0.1/onvif/device_service</d:XAddrs></d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>"#
            );
            server
                .send_to(xml.replace("uuid:fixture", "uuid:wrong").as_bytes(), peer)
                .await
                .unwrap();
            server.send_to(xml.as_bytes(), peer).await.unwrap();
            server.send_to(xml.as_bytes(), peer).await.unwrap();
            tokio::time::sleep(Duration::from_secs(4)).await;
        });
        let targets = HashSet::from([destination.ip()]);
        let values = exchange(
            client,
            Ipv4Addr::LOCALHOST,
            false,
            &targets,
            destination,
            "uuid:fixture".into(),
            "fixture probe".into(),
        )
        .await
        .unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].1.name.as_deref(), Some("Test"));
        task.abort();
    }
    #[test]
    fn sadp_validates_sender_and_preserves_hidden_device_identity() {
        let xml = br#"<ProbeMatch><Types>inquiry</Types><IPv4Address>192.0.2.1</IPv4Address><DeviceSN>SN123</DeviceSN><DeviceDescription>Camera</DeviceDescription><MAC>00-11-22-33-44-55</MAC><Activated>false</Activated><HttpPort>80</HttpPort></ProbeMatch>"#;
        let ip = "192.0.2.1".parse().unwrap();
        let value = parse_sadp(xml, ip, "fixture").unwrap();
        assert_eq!(value.mac.as_deref(), Some("00:11:22:33:44:55"));
        assert_eq!(value.activated, Some(false));
        assert!(parse_sadp(xml, "192.0.2.2".parse().unwrap(), "").is_none());
        assert!(
            parse_sadp(
                b"<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///x'>]><ProbeMatch>&e;</ProbeMatch>",
                ip,
                ""
            )
            .is_none()
        );
    }
    #[test]
    fn onvif_correlates_probe_and_rejects_foreign_endpoints() {
        let xml = format!(
            r#"<s:Envelope xmlns:s="{SOAP}" xmlns:a="{WSA}" xmlns:d="{WSD}"><s:Header><a:RelatesTo>uuid:test</a:RelatesTo></s:Header><s:Body><d:ProbeMatches><d:ProbeMatch><a:EndpointReference><a:Address>urn:uuid:camera</a:Address></a:EndpointReference><d:Scopes>onvif://www.onvif.org/name/Front%20Door onvif://www.onvif.org/hardware/IPC</d:Scopes><d:XAddrs>http://192.0.2.1/onvif/device_service http://192.0.2.2/other http://user:pass@192.0.2.1/</d:XAddrs></d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>"#
        );
        let ip = "192.0.2.1".parse().unwrap();
        let values = parse_onvif(xml.as_bytes(), "uuid:test", ip, "fixture");
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].name.as_deref(), Some("Front Door"));
        assert_eq!(values[0].endpoints.len(), 1);
        assert!(parse_onvif(xml.as_bytes(), "uuid:other", ip, "").is_empty());
        assert!(parse_onvif(b"not xml", "uuid:test", ip, "").is_empty());
    }
}
