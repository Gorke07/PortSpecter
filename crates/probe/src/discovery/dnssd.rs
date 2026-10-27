use super::*;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{DNSClass, Name, RData, Record, RecordType},
};
use std::collections::{HashMap, VecDeque};

const ENUMERATION: &str = "_services._dns-sd._udp.local.";
const TYPES: [&str; 15] = [
    ENUMERATION,
    "_workstation._tcp.local.",
    "_nfs._tcp.local.",
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_ipp._tcp.local.",
    "_ipps._tcp.local.",
    "_printer._tcp.local.",
    "_pdl-datastream._tcp.local.",
    "_smb._tcp.local.",
    "_afpovertcp._tcp.local.",
    "_ssh._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_googlecast._tcp.local.",
];
fn normalize(name: &Name) -> String {
    name.to_ascii().to_ascii_lowercase()
}
fn service_type(name: &Name) -> bool {
    let parts: Vec<_> = name.iter().collect();
    parts.len() == 3
        && parts[0].starts_with(b"_")
        && matches!(parts[1], b"_tcp" | b"_udp")
        && parts[2].eq_ignore_ascii_case(b"local")
}
#[derive(Clone)]
struct Pending {
    peer: Option<IpAddr>,
    query: Query,
}
fn decode(bytes: &[u8], id: u16, query: &Query) -> Option<Vec<Record>> {
    if bytes.len() > 60_000 || bytes.len() < 12 {
        return None;
    }
    let count = (4..12)
        .step_by(2)
        .map(|i| u16::from_be_bytes([bytes[i], bytes[i + 1]]) as usize)
        .sum::<usize>();
    if count > 256 {
        return None;
    }
    let msg = Message::from_vec(bytes).ok()?;
    if msg.metadata.id != id
        || msg.metadata.message_type != MessageType::Response
        || msg.metadata.op_code != OpCode::Query
        || msg.metadata.response_code != ResponseCode::NoError
        || msg.metadata.truncation
        || !msg
            .queries
            .iter()
            .any(|q| q.name() == query.name() && q.query_type() == query.query_type())
    {
        return None;
    }
    Some(
        msg.answers
            .into_iter()
            .chain(msg.additionals)
            .filter(|r| r.ttl > 0 && r.dns_class == DNSClass::IN)
            .collect(),
    )
}

fn assemble(peer: IpAddr, records: &[Record], source: Ipv4Addr) -> Vec<DeviceAdvertisement> {
    let mut result = BTreeMap::new();
    for record in records {
        let RData::PTR(ptr) = &record.data else {
            continue;
        };
        if !service_type(&record.name)
            || !record.name.zone_of(&ptr.0)
            || ptr.0.num_labels() != record.name.num_labels() + 1
        {
            continue;
        }
        let Some(srv) = records.iter().find_map(|r| {
            if r.name == ptr.0 {
                if let RData::SRV(s) = &r.data {
                    Some(s)
                } else {
                    None
                }
            } else {
                None
            }
        }) else {
            continue;
        };
        if srv.port == 0
            || !records.iter().any(|r| {
                r.name == srv.target
                    && match &r.data {
                        RData::A(a) => IpAddr::V4(a.0) == peer,
                        RData::AAAA(a) => IpAddr::V6(a.0) == peer,
                        _ => false,
                    }
            })
        {
            continue;
        }
        let mut ad = blank("DNS-SD", normalize(&ptr.0), source);
        ad.name = ptr
            .0
            .iter()
            .next()
            .map(|b| clean(&String::from_utf8_lossy(b)));
        ad.service_type = Some(normalize(&record.name));
        ad.port = Some(srv.port);
        ad.transport = Some(
            if normalize(&record.name).contains("._udp.") {
                "udp"
            } else {
                "tcp"
            }
            .into(),
        );
        ad.hostname = Some(srv.target.to_utf8());
        for r in records.iter().filter(|r| r.name == ptr.0) {
            if let RData::TXT(txt) = &r.data {
                for entry in txt.txt_data.iter().take(24) {
                    let value = clean(&String::from_utf8_lossy(entry));
                    let (key, value) = value.split_once('=').unwrap_or((&value, ""));
                    if key.is_empty() {
                        continue;
                    }
                    // TXT strings are untrusted metadata, never credentials or instructions.
                    ad.properties.insert(format!("TXT: {key}"), value.into());
                }
            }
        }
        ad.model = ad
            .properties
            .get("TXT: ty")
            .or_else(|| ad.properties.get("TXT: model"))
            .cloned();
        result.insert(ad.identity.clone(), ad);
    }
    result.into_values().collect()
}

pub(super) async fn discover(
    source: Ipv4Addr,
    targets: &HashSet<IpAddr>,
) -> io::Result<Vec<(IpAddr, DeviceAdvertisement)>> {
    let socket = socket(source, 255)?;
    let destination = SocketAddr::from(([224, 0, 0, 251], 5353));
    exchange(
        &socket,
        source,
        targets,
        destination,
        Duration::from_secs(4),
    )
    .await
}
async fn exchange(
    socket: &UdpSocket,
    source: Ipv4Addr,
    targets: &HashSet<IpAddr>,
    destination: SocketAddr,
    duration: Duration,
) -> io::Result<Vec<(IpAddr, DeviceAdvertisement)>> {
    let mut pending: HashMap<u16, Pending> = HashMap::new();
    let mut queued = HashSet::new();
    let mut queue = VecDeque::new();
    for service in TYPES {
        queue.push_back(Pending {
            peer: None,
            query: Query::query(
                Name::from_ascii(service).expect("service name"),
                RecordType::PTR,
            ),
        });
    }
    let mut records: HashMap<IpAddr, Vec<Record>> = HashMap::new();
    let mut bytes = vec![0; 65_536];
    let mut total_records = 0;
    let deadline = tokio::time::Instant::now() + duration;
    let mut tick = tokio::time::interval(Duration::from_millis(20));
    let mut next_id = u16::from_be_bytes(uuid::Uuid::new_v4().as_bytes()[..2].try_into().unwrap());
    loop {
        tokio::select! {
            biased;
            _=tokio::time::sleep_until(deadline)=>break,
            _=tick.tick(),if !queue.is_empty() && pending.len()<192=>{
                let request=queue.pop_front().unwrap();
                let key=(request.peer,normalize(request.query.name()),request.query.query_type());
                if !queued.insert(key) {continue;}
                next_id=next_id.wrapping_add(1);
                let mut message=Message::new(next_id,MessageType::Query,OpCode::Query);message.queries.push(request.query.clone());
                let packet=message.to_vec().map_err(io::Error::other)?;
                socket.send_to(&packet,request.peer.map(|ip|SocketAddr::new(ip,destination.port())).unwrap_or(destination)).await?;
                pending.insert(next_id,request);
            },
            response=socket.recv_from(&mut bytes)=>{
                let (n,peer)=response?;
                if peer.port()!=destination.port() || !targets.contains(&peer.ip()) || n<12 {continue;}
                let id=u16::from_be_bytes([bytes[0],bytes[1]]);
                let Some(request)=pending.get(&id) else{continue;};
                if request.peer.is_some_and(|ip|ip!=peer.ip()){continue;}
                let Some(incoming)=decode(&bytes[..n],id,&request.query) else {continue;};
                let entries=records.entry(peer.ip()).or_default();
                for record in incoming {
                    if entries.len()>=256 || total_records>=4096 {break;}
                    if !entries.iter().any(|r|r.name==record.name && r.data==record.data) {entries.push(record);total_records+=1;}
                }
                // Resolve discovered service types, instance SRV/TXT records and target addresses.
                // Work is peer-bound and globally capped; no enumeration escapes the scan scope.
                for record in entries.iter() {
                    let mut followups=vec![];
                    match &record.data {
                        RData::PTR(ptr) if normalize(&record.name)==ENUMERATION && service_type(&ptr.0)=>followups.push((ptr.0.clone(),RecordType::PTR)),
                        RData::PTR(ptr) if service_type(&record.name) && record.name.zone_of(&ptr.0)=>{
                            followups.push((ptr.0.clone(),RecordType::SRV));followups.push((ptr.0.clone(),RecordType::TXT));
                        },
                        RData::SRV(srv) if srv.target.to_ascii().to_ascii_lowercase().ends_with(".local.")=>followups.push((srv.target.clone(),RecordType::A)),
                        _=>{}
                    }
                    for (name,kind) in followups {
                        let key=(Some(peer.ip()),normalize(&name),kind);
                        if queue.len()<192 && !queued.contains(&key) && !queue.iter().any(|p|p.peer==Some(peer.ip()) && p.query.name()==&name && p.query.query_type()==kind) {
                            queue.push_back(Pending{peer:Some(peer.ip()),query:Query::query(name,kind)});
                        }
                    }
                }
            }
        }
    }
    let mut result = vec![];
    for (ip, records) in records {
        result.extend(assemble(ip, &records, source).into_iter().map(|r| (ip, r)));
    }
    result.sort_by(|a, b| (a.0, &a.1.identity).cmp(&(b.0, &b.1.identity)));
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, PTR, SRV, TXT};
    #[tokio::test]
    async fn udp_browsing_resolves_split_records_and_new_service_types() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = server.local_addr().unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let task = tokio::spawn(async move {
            let service = Name::from_ascii("_fixture._tcp.local.").unwrap();
            let instance = Name::from_ascii("Test._fixture._tcp.local.").unwrap();
            let host = Name::from_ascii("fixture.local.").unwrap();
            let mut bytes = [0; 4096];
            loop {
                let (n, peer) = server.recv_from(&mut bytes).await.unwrap();
                let request = Message::from_vec(&bytes[..n]).unwrap();
                let q = &request.queries[0];
                let data = match (normalize(q.name()).as_str(), q.query_type()) {
                    (ENUMERATION, RecordType::PTR) => RData::PTR(PTR(service.clone())),
                    ("_fixture._tcp.local.", RecordType::PTR) => RData::PTR(PTR(instance.clone())),
                    ("test._fixture._tcp.local.", RecordType::SRV) => {
                        RData::SRV(SRV::new(0, 0, 4242, host.clone()))
                    }
                    ("test._fixture._tcp.local.", RecordType::TXT) => {
                        RData::TXT(TXT::new(vec!["model=Fixture".into()]))
                    }
                    ("fixture.local.", RecordType::A) => RData::A(A(Ipv4Addr::LOCALHOST)),
                    _ => continue,
                };
                let mut response = Message::response(request.metadata.id, OpCode::Query);
                response.queries.push(q.clone());
                response
                    .answers
                    .push(Record::from_rdata(q.name().clone(), 120, data));
                server
                    .send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        let results = exchange(
            &socket,
            Ipv4Addr::LOCALHOST,
            &HashSet::from([destination.ip()]),
            destination,
            Duration::from_millis(1200),
        )
        .await
        .unwrap();
        task.abort();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1.port, Some(4242));
        assert_eq!(results[0].1.model.as_deref(), Some("Fixture"));
    }
    #[test]
    fn links_ptr_srv_txt_and_address_without_inventing_open_port() {
        let service = Name::from_ascii("_ipp._tcp.local.").unwrap();
        let instance =
            Name::from_labels([b"Office Printer".as_slice(), b"_ipp", b"_tcp", b"local"]).unwrap();
        let host = Name::from_ascii("printer.local.").unwrap();
        let records = vec![
            Record::from_rdata(service.clone(), 120, RData::PTR(PTR(instance.clone()))),
            Record::from_rdata(
                instance.clone(),
                120,
                RData::SRV(SRV::new(0, 0, 8631, host.clone())),
            ),
            Record::from_rdata(host, 120, RData::A(A(Ipv4Addr::new(192, 0, 2, 1)))),
            Record::from_rdata(
                instance,
                120,
                RData::TXT(TXT::new(vec!["ty=Fixture printer".into()])),
            ),
        ];
        let ip = "192.0.2.1".parse().unwrap();
        let output = assemble(ip, &records, Ipv4Addr::LOCALHOST);
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].port, Some(8631));
        assert_eq!(output[0].model.as_deref(), Some("Fixture printer"));
        assert_eq!(output[0].name.as_deref(), Some("Office Printer"));
        assert!(assemble("192.0.2.2".parse().unwrap(), &records, Ipv4Addr::LOCALHOST).is_empty());
        let query = Query::query(service, RecordType::PTR);
        let mut msg = Message::response(42, OpCode::Query);
        msg.queries.push(query.clone());
        msg.answers = records;
        let bytes = msg.to_vec().unwrap();
        assert!(decode(&bytes, 42, &query).is_some());
        assert!(decode(&bytes, 43, &query).is_none());
        assert!(decode(&bytes[..15], 42, &query).is_none());
    }
}
