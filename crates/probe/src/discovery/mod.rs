//! Bounded, read-only local device advertisements; no advertised port is marked open.
mod dahua;
mod dnssd;
mod ssdp;
use chrono::Utc;
use portspecter_domain::DeviceAdvertisement;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::{BTreeMap, HashSet},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::net::UdpSocket;

#[derive(Debug, Clone, Copy)]
pub enum ProtocolKind {
    Dahua,
    DnsSd,
    Ssdp,
}
impl ProtocolKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Dahua => "Dahua",
            Self::DnsSd => "DNS-SD",
            Self::Ssdp => "SSDP",
        }
    }
}
pub(crate) fn clean(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(1024)
        .collect::<String>()
        .trim()
        .to_owned()
}
fn blank(protocol: &str, identity: String, source: Ipv4Addr) -> DeviceAdvertisement {
    DeviceAdvertisement {
        protocol: protocol.into(),
        identity,
        interface: source.to_string(),
        observed_at: Utc::now(),
        ..Default::default()
    }
}
pub(crate) fn socket(source: Ipv4Addr, ttl: u32) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.bind(&SocketAddr::from((source, 0)).into())?;
    socket.set_multicast_if_v4(&source)?;
    socket.set_multicast_ttl_v4(ttl)?;
    socket.set_multicast_loop_v4(false)?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}
pub async fn discover(
    source: Ipv4Addr,
    kind: ProtocolKind,
    targets: &HashSet<IpAddr>,
) -> io::Result<Vec<(IpAddr, DeviceAdvertisement)>> {
    match kind {
        ProtocolKind::Dahua => dahua::discover(source, targets).await,
        ProtocolKind::DnsSd => dnssd::discover(source, targets).await,
        ProtocolKind::Ssdp => ssdp::discover(source, targets).await,
    }
}
async fn collect<F>(
    socket: &UdpSocket,
    destination: SocketAddr,
    request: &[u8],
    targets: &HashSet<IpAddr>,
    mut parse: F,
) -> io::Result<Vec<(IpAddr, DeviceAdvertisement)>>
where
    F: FnMut(&[u8], SocketAddr) -> Option<DeviceAdvertisement>,
{
    socket.send_to(request, destination).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut retry = tokio::time::interval(Duration::from_millis(1000));
    retry.tick().await;
    let mut sends = 1;
    let mut bytes = vec![0; 65_536];
    let mut records = BTreeMap::new();
    loop {
        tokio::select! {
            biased;
            _=tokio::time::sleep_until(deadline)=>break,
            _=retry.tick(),if sends<2=>{socket.send_to(request,destination).await?;sends+=1;},
            response=socket.recv_from(&mut bytes)=>{
                let (n,peer)=response?;
                if !targets.contains(&peer.ip()){continue;}
                if let Some(record)=parse(&bytes[..n],peer) {records.insert((peer.ip(),record.identity.clone()),record);}
                if records.len()>=4096 {break;}
            }
        }
    }
    Ok(records.into_iter().map(|((ip, _), r)| (ip, r)).collect())
}

/// No hostname resolution, credentials, fragments, redirects or foreign-IP URL fetches.
fn same_host_url(value: &str, peer: IpAddr) -> Option<url::Url> {
    let url = url::Url::parse(value).ok()?;
    (matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && url
            .host_str()?
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .ok()
            == Some(peer))
    .then_some(url)
}
