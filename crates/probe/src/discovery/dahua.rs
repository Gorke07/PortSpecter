use super::*;
use portspecter_domain::parse_mac;
use serde_json::{Value, json};

fn frame(value: &Value) -> Vec<u8> {
    let body = serde_json::to_vec(value).expect("JSON value");
    let mut bytes = vec![0; 32];
    bytes[..4].copy_from_slice(&32u32.to_le_bytes());
    bytes[4..8].copy_from_slice(b"DHIP");
    bytes[16..20].copy_from_slice(&(body.len() as u32).to_le_bytes());
    bytes[24..28].copy_from_slice(&(body.len() as u32).to_le_bytes());
    bytes.extend(body);
    bytes
}
fn parse(bytes: &[u8], peer: SocketAddr, source: Ipv4Addr) -> Option<DeviceAdvertisement> {
    if peer.port() != 37810
        || bytes.len() < 32
        || bytes.len() > 60_000
        || bytes.get(..4)? != 32u32.to_le_bytes()
        || bytes.get(4..8)? != b"DHIP"
    {
        return None;
    }
    let word =
        |at| -> Option<u32> { Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?)) };
    let length = word(16)? as usize;
    if length != word(24)? as usize
        || word(20)? != 0
        || word(28)? != 0
        || length + 32 > bytes.len()
        || bytes[length + 32..].iter().any(|b| *b != 0)
    {
        return None;
    }
    let value: Value = serde_json::from_slice(&bytes[32..32 + length]).ok()?;
    if !matches!(
        value.get("method")?.as_str()?,
        "client.notifyDevInfo" | "DHDiscover.search"
    ) {
        return None;
    }
    let info = value.pointer("/params/deviceInfo")?;
    let address = info
        .pointer("/IPv4Address/IPAddress")
        .and_then(Value::as_str)?;
    if address.parse::<IpAddr>().ok() != Some(peer.ip()) {
        return None;
    }
    let field = |key: &str| {
        info.get(key)
            .and_then(Value::as_str)
            .map(clean)
            .filter(|s| !s.is_empty())
    };
    let serial = field("SerialNo");
    let raw_mac =
        field("Mac").or_else(|| value.get("mac").and_then(Value::as_str).map(str::to_owned));
    let mac = raw_mac
        .and_then(|v| parse_mac(&v))
        .filter(|v| *v != [0; 6] && v[0] & 1 == 0)
        .map(|v| {
            v.iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(":")
        });
    let identity = serial.clone().or(mac.clone())?;
    let mut record = blank("Dahua", identity, source);
    record.serial = serial;
    record.mac = mac;
    record.name = field("MachineName").or_else(|| field("Name"));
    record.model = field("DeviceType");
    record.device_type = field("DeviceClass");
    record.manufacturer = field("Manufacturer").or_else(|| field("Vendor"));
    for key in [
        "Version",
        "SoftwareVersion",
        "Init",
        "HttpPort",
        "HttpsPort",
        "Port",
        "VideoInputChannels",
        "RemoteVideoInputChannels",
    ] {
        if let Some(value) = info
            .get(key)
            .filter(|v| v.is_string() || v.is_number() || v.is_boolean())
        {
            record.properties.insert(
                key.into(),
                clean(value.as_str().unwrap_or(&value.to_string())),
            );
        }
    }
    if let Some(port) = info
        .get("HttpPort")
        .and_then(Value::as_u64)
        .filter(|p| *p > 0 && *p <= 65535)
    {
        record
            .endpoints
            .push(format!("http://{}:{port}/", peer.ip()));
    }
    Some(record)
}
pub(super) async fn discover(
    source: Ipv4Addr,
    targets: &HashSet<IpAddr>,
) -> io::Result<Vec<(IpAddr, DeviceAdvertisement)>> {
    let socket = socket(source, 1)?;
    let request = frame(&json!({"method":"DHDiscover.search","params":{"mac":"","uni":1}}));
    collect(
        &socket,
        SocketAddr::from(([239, 255, 255, 251], 37810)),
        &request,
        targets,
        |bytes, peer| parse(bytes, peer, source),
    )
    .await
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dhip_length_identity_and_sender_validation() {
        let value = json!({"method":"client.notifyDevInfo","mac":"00:11:22:33:44:55","params":{"deviceInfo":{"IPv4Address":{"IPAddress":"192.0.2.8"},"DeviceClass":"NVR","DeviceType":"NVR-Test","SerialNo":"fixture","HttpPort":80}}});
        let bytes = frame(&value);
        let peer = "192.0.2.8:37810".parse().unwrap();
        let result = parse(&bytes, peer, Ipv4Addr::LOCALHOST).unwrap();
        assert_eq!(result.device_type.as_deref(), Some("NVR"));
        assert_eq!(result.mac.as_deref(), Some("00:11:22:33:44:55"));
        assert!(parse(&bytes[..bytes.len() - 1], peer, Ipv4Addr::LOCALHOST).is_none());
        assert!(
            parse(
                &bytes,
                "192.0.2.9:37810".parse().unwrap(),
                Ipv4Addr::LOCALHOST
            )
            .is_none()
        );
        let mut invalid = bytes;
        invalid[24] = 0;
        assert!(parse(&invalid, peer, Ipv4Addr::LOCALHOST).is_none());
    }
}
