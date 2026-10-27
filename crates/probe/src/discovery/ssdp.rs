use super::*;
use roxmltree::{Document, ParsingOptions};

fn parse(bytes: &[u8], peer: SocketAddr, source: Ipv4Addr) -> Option<DeviceAdvertisement> {
    if bytes.len() > 16_384 {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.split("\r\n");
    let status = lines.next()?;
    if status.split_whitespace().take(2).collect::<Vec<_>>() != ["HTTP/1.1", "200"] {
        return None;
    }
    let mut headers = BTreeMap::new();
    for line in lines.take(64) {
        if line.is_empty() {
            break;
        }
        let (key, value) = line.split_once(':')?;
        if headers
            .insert(key.to_ascii_lowercase(), value.trim())
            .is_some()
        {
            return None;
        }
    }
    let location = same_host_url(headers.get("location")?, peer.ip())?;
    let usn = clean(headers.get("usn")?);
    let st = clean(headers.get("st")?);
    if !usn.starts_with("uuid:") || st.is_empty() {
        return None;
    }
    let mut result = blank("SSDP", usn.split("::").next()?.to_ascii_lowercase(), source);
    result.device_type = st.contains(":device:").then(|| st.clone());
    result.service_type = Some(st);
    result.endpoints.push(location.to_string());
    result.properties.insert("USN".into(), usn);
    if let Some(server) = headers.get("server") {
        result.properties.insert("SERVER".into(), clean(server));
    }
    result
        .properties
        .insert("description".into(), "pending".into());
    Some(result)
}

fn description(bytes: &[u8], record: &mut DeviceAdvertisement) -> Option<()> {
    if bytes.len() > 131_072 {
        return None;
    }
    let doc = Document::parse_with_options(
        std::str::from_utf8(bytes).ok()?,
        ParsingOptions {
            allow_dtd: false,
            nodes_limit: 4096,
            ..Default::default()
        },
    )
    .ok()?;
    let root = doc.root_element();
    if root.tag_name().name() != "root" {
        return None;
    }
    let expected = record.properties.get("USN")?.split("::").next()?;
    // A root description can contain embedded devices: select exactly the advertised UDN.
    let node = doc
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "device")
        .find(|n| {
            n.children().any(|c| {
                c.is_element()
                    && c.tag_name().name() == "UDN"
                    && c.text()
                        .is_some_and(|s| s.trim().eq_ignore_ascii_case(expected))
            })
        })?;
    let field = |key: &str| {
        node.children()
            .find(|n| n.is_element() && n.tag_name().name() == key)
            .and_then(|n| n.text())
            .map(clean)
            .filter(|s| !s.is_empty())
    };
    record.name = field("friendlyName");
    record.model = field("modelName");
    record.manufacturer = field("manufacturer");
    record.serial = field("serialNumber");
    record.device_type = field("deviceType");
    record
        .properties
        .insert("description".into(), "received".into());
    Some(())
}
async fn fetch(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, String> {
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?;
    if response.content_length().is_some_and(|n| n > 131_072) {
        return Err("description too large".into());
    }
    let mut bytes = vec![];
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        if bytes.len() + chunk.len() > 131_072 {
            return Err("description too large".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
pub(super) async fn discover(
    source: Ipv4Addr,
    targets: &HashSet<IpAddr>,
) -> io::Result<Vec<(IpAddr, DeviceAdvertisement)>> {
    let socket = socket(source, 1)?;
    let request=b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";
    let mut records = collect(
        &socket,
        SocketAddr::from(([239, 255, 255, 250], 1900)),
        request,
        targets,
        |b, p| parse(b, p, source),
    )
    .await?;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .local_address(IpAddr::V4(source))
        .timeout(Duration::from_secs(2))
        .connect_timeout(Duration::from_secs(1))
        .build()
        .map_err(io::Error::other)?;
    let mut jobs = tokio::task::JoinSet::new();
    let urls: Vec<_> = records
        .iter()
        .flat_map(|(_, r)| r.endpoints.iter().cloned())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut downloaded = BTreeMap::new();
    // Bound follow-up reads independently from the number of SSDP advertisements.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    'fetches: for batch in urls.iter().take(32).collect::<Vec<_>>().chunks(4) {
        for url in batch {
            let url = (*url).clone();
            let client = client.clone();
            jobs.spawn(async move {
                let result = fetch(&client, &url).await;
                (url, result)
            });
        }
        while !jobs.is_empty() {
            let result = tokio::select! {biased;_=tokio::time::sleep_until(deadline)=>{jobs.abort_all();break 'fetches;},v=jobs.join_next()=>v};
            if let Some(Ok((url, result))) = result {
                downloaded.insert(url, result);
            }
        }
    }
    for (_, record) in &mut records {
        let status = match downloaded.get(&record.endpoints[0]) {
            Some(Ok(bytes)) => {
                if description(bytes, record).is_some() {
                    continue;
                } else {
                    "invalid description or mismatched UDN".into()
                }
            }
            Some(Err(error)) => clean(error),
            None => "description fetch limit reached".into(),
        };
        record.properties.insert("description".into(), status);
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn udp_search_ignores_out_of_scope_and_merges_duplicate_udn() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let task = tokio::spawn(async move {
            let mut bytes = [0; 2048];
            let (_, peer) = server.recv_from(&mut bytes).await.unwrap();
            let response=b"HTTP/1.1 200 OK\r\nUSN: uuid:fixture::upnp:rootdevice\r\nST: upnp:rootdevice\r\nLOCATION: http://127.0.0.1/device.xml\r\n\r\n";
            server.send_to(response, peer).await.unwrap();
            server.send_to(response, peer).await.unwrap();
            // Wrong LOCATION cannot trigger a follow-up HTTP request.
            server.send_to(b"HTTP/1.1 200 OK\r\nUSN: uuid:foreign\r\nST: upnp:rootdevice\r\nLOCATION: http://192.0.2.1/private\r\n\r\n",peer).await.unwrap();
            tokio::time::sleep(Duration::from_secs(4)).await;
        });
        let result = collect(
            &client,
            destination,
            b"fixture search",
            &HashSet::from([destination.ip()]),
            |b, p| parse(b, p, Ipv4Addr::LOCALHOST),
        )
        .await
        .unwrap();
        task.abort();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].1.identity, "uuid:fixture");
    }
    #[test]
    fn headers_and_description_reject_foreign_urls_and_entities() {
        let response=b"HTTP/1.1 200 OK\r\nUSN: uuid:test::upnp:rootdevice\r\nST: upnp:rootdevice\r\nLOCATION: http://192.0.2.1/device.xml\r\n\r\n";
        let mut record = parse(
            response,
            "192.0.2.1:1900".parse().unwrap(),
            Ipv4Addr::LOCALHOST,
        )
        .unwrap();
        assert!(
            parse(
                response,
                "192.0.2.2:1900".parse().unwrap(),
                Ipv4Addr::LOCALHOST
            )
            .is_none()
        );
        assert!(
            same_host_url("http://user:pw@192.0.2.1/a", "192.0.2.1".parse().unwrap()).is_none()
        );
        let xml=b"<root><device><UDN>uuid:test</UDN><friendlyName>Living room</friendlyName><manufacturer>Fixture</manufacturer><deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType></device></root>";
        description(xml, &mut record).unwrap();
        assert_eq!(record.name.as_deref(), Some("Living room"));
        assert!(
            description(
                b"<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///x'>]><root>&e;</root>",
                &mut record
            )
            .is_none()
        );
        assert!(
            description(
                b"<root><device><UDN>uuid:other</UDN></device></root>",
                &mut record
            )
            .is_none()
        );
    }
    #[tokio::test]
    async fn http_description_does_not_follow_redirects_and_caps_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            for response in [
                "HTTP/1.1 302 Found\r\nLocation: http://192.0.2.1/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                "HTTP/1.1 200 OK\r\nContent-Length: 9999999\r\nConnection: close\r\n\r\n",
            ] {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut b = [0; 2048];
                let n = s.read(&mut b).await.unwrap();
                assert!(n > 0);
                s.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(1))
            .build()
            .unwrap();
        assert!(
            fetch(&client, &format!("http://{address}/"))
                .await
                .unwrap()
                .is_empty()
        );
        assert!(fetch(&client, &format!("http://{address}/")).await.is_err());
        task.await.unwrap();
    }
}
