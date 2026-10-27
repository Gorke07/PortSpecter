use anyhow::{Context, Result};
use chrono::Utc;
use portspecter_domain::*;
use portspecter_storage::Storage;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    net::TcpSocket,
    sync::{Mutex, Semaphore, mpsc},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub enum ScanEvent {
    NetworkChanged,
    Advertisements {
        id: Uuid,
        ip: IpAddr,
        values: Vec<DeviceAdvertisement>,
    },
    Cameras {
        id: Uuid,
        ip: IpAddr,
        values: Vec<CameraObservation>,
    },
    Shares {
        id: Uuid,
        ip: IpAddr,
        value: ShareDiscovery,
    },
    Started(Box<ScanSession>),
    Observations {
        id: Uuid,
        values: Vec<(IpAddr, PortObservation)>,
        completed: usize,
    },
    Discovery {
        id: Uuid,
        ip: IpAddr,
        value: DiscoveryObservation,
    },
    Name {
        id: Uuid,
        ip: IpAddr,
        value: NameObservation,
    },
    Macs {
        id: Uuid,
        values: Vec<(IpAddr, MacObservation)>,
    },
    Status {
        id: Uuid,
        status: SessionStatus,
    },
    Finished {
        id: Uuid,
        status: SessionStatus,
        completed: usize,
    },
    Log(String),
    Error(String),
}

#[derive(Clone)]
pub struct ScanControl {
    pub cancel: CancellationToken,
    paused: Arc<AtomicBool>,
    blocks: Arc<Vec<AtomicU8>>,
}
impl ScanControl {
    pub fn new(blocks: usize) -> Self {
        Self {
            cancel: CancellationToken::new(),
            paused: Arc::new(AtomicBool::new(false)),
            blocks: Arc::new((0..blocks).map(|_| AtomicU8::new(0)).collect()),
        }
    }
    pub fn pause(&self, value: bool) {
        self.paused.store(value, Ordering::SeqCst);
    }
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }
    pub fn pause_block(&self, index: usize, value: bool) {
        if let Some(b) = self.blocks.get(index) {
            b.store(if value { 1 } else { 0 }, Ordering::SeqCst);
        }
    }
    pub fn cancel_block(&self, index: usize) {
        if let Some(b) = self.blocks.get(index) {
            b.store(2, Ordering::SeqCst);
        }
    }
    pub fn block_state(&self, index: usize) -> u8 {
        self.blocks
            .get(index)
            .map(|b| b.load(Ordering::SeqCst))
            .unwrap_or(2)
    }
    fn eligible(&self, blocks: &[usize]) -> bool {
        blocks.iter().any(|i| self.block_state(*i) == 0)
    }
    fn abandoned(&self, blocks: &[usize]) -> bool {
        blocks.iter().all(|i| self.block_state(*i) == 2)
    }
    async fn ready(&self, blocks: &[usize]) -> bool {
        loop {
            if self.cancel.is_cancelled() || self.abandoned(blocks) {
                return false;
            }
            if !self.is_paused() && self.eligible(blocks) {
                return true;
            }
            tokio::select! {_=self.cancel.cancelled()=>return false,_=tokio::time::sleep(Duration::from_millis(20))=>{}}
        }
    }
}

pub async fn prepare(
    targets: &str,
    ports: &str,
    exclusions: &str,
    settings: ScanSettings,
) -> Result<ScanPlan> {
    settings.validate()?;
    let blocks = parse_blocks(targets)?;
    let ports = parse_ports(ports)?;
    let exclusions = parse_exclusions(exclusions)?;
    let mut expanded = Vec::new();
    let mut expansion_count = 0usize;
    let mut dns_names = HashMap::new();
    for block in &blocks {
        let ips = if let Some(ips) = expand_literal(&block.target)? {
            ips
        } else {
            let resolved = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::lookup_host((block.target.as_str(), 0)),
            )
            .await
            .context("DNS resolution timed out")??;
            let ips: Vec<_> = resolved.map(|s| s.ip()).collect();
            anyhow::ensure!(
                !ips.is_empty(),
                "DNS returned no addresses for {}",
                block.target
            );
            for ip in &ips {
                dns_names.insert(*ip, block.target.clone());
            }
            ips
        };
        expansion_count = expansion_count.saturating_add(ips.len());
        anyhow::ensure!(
            expansion_count <= MAX_HOSTS * 4,
            "Combined target expansion is too large; simplify overlapping target blocks"
        );
        expanded.push(ips);
    }
    let mut plan = merge_targets(blocks, expanded, &exclusions, ports, settings)?;
    for h in &mut plan.hosts {
        if let Some(name) = dns_names.get(&h.ip) {
            h.hostname = Some(name.clone());
        }
    }
    Ok(plan)
}

#[derive(Clone)]
struct RateLimiter {
    next: Arc<Mutex<tokio::time::Instant>>,
    spacing: Duration,
}
impl RateLimiter {
    fn new(rate: u32) -> Self {
        Self {
            next: Arc::new(Mutex::new(tokio::time::Instant::now())),
            spacing: Duration::from_secs_f64(1.0 / rate as f64),
        }
    }
    async fn wait(&self, cancel: &CancellationToken) -> bool {
        let mut next =
            tokio::select! {_=cancel.cancelled()=>return false,lock=self.next.lock()=>lock};
        let due = (*next).max(tokio::time::Instant::now());
        *next = due + self.spacing;
        drop(next);
        tokio::select! {_ = cancel.cancelled()=>false,_=tokio::time::sleep_until(due)=>true}
    }
    async fn wait_for(&self, control: &ScanControl, blocks: &[usize]) -> bool {
        loop {
            if !control.ready(blocks).await || !self.wait(&control.cancel).await {
                return false;
            }
            if !control.is_paused() && control.eligible(blocks) {
                return true;
            }
        }
    }
}

fn classify(error: &std::io::Error) -> PortState {
    use std::io::ErrorKind::*;
    match error.kind() {
        ConnectionRefused => PortState::Closed,
        TimedOut => PortState::TimedOut,
        NetworkUnreachable | HostUnreachable => PortState::Unreachable,
        _ => PortState::LocalError,
    }
}

#[derive(Clone)]
struct ProbeContext {
    settings: ScanSettings,
    control: ScanControl,
    limiter: RateLimiter,
    service_slots: Arc<Semaphore>,
    mac_attempted: Arc<std::sync::Mutex<HashSet<IpAddr>>>,
    vendors: Arc<VendorDatabase>,
    names_attempted: Arc<std::sync::Mutex<HashSet<IpAddr>>>,
    dns_slots: Arc<Semaphore>,
    syn: Option<portspecter_platform::syn::SynScanner>,
}

struct ProbeOutput {
    observation: PortObservation,
    mac: Option<MacObservation>,
    name: Option<NameObservation>,
    discovery: Option<DiscoveryObservation>,
    shares: Option<ShareDiscovery>,
}

async fn probe(
    host: PlannedHost,
    port: u16,
    context: ProbeContext,
    discover: bool,
) -> Option<ProbeOutput> {
    let PlannedHost {
        ip,
        blocks,
        hostname,
    } = host;
    let ProbeContext {
        settings,
        control,
        limiter,
        service_slots,
        mac_attempted,
        vendors,
        names_attempted,
        dns_slots,
        syn,
    } = context;
    let mut observation = None;
    for attempt in 0..=settings.retries {
        if control.cancel.is_cancelled() || control.abandoned(&blocks) {
            return None;
        }
        if !limiter.wait_for(&control, &blocks).await {
            return None;
        }
        if control.cancel.is_cancelled() || control.abandoned(&blocks) {
            return None;
        }
        let start = Instant::now();
        let timeout = Duration::from_millis(settings.timeout_ms);
        let operation = async {
            if settings.method == ScanMethod::Udp {
                return portspecter_probe::udp::scan(ip, port, settings.source_ip, timeout).await;
            }
            if settings.method == ScanMethod::TcpSyn {
                return match syn
                    .as_ref()
                    .expect("SYN context initialized")
                    .scan(ip, port, settings.source_ip, timeout)
                    .await
                {
                    Ok(state) => (state, None),
                    Err(error) => (PortState::LocalError, Some(format!("{error:#}"))),
                };
            }
            let connection = async {
                let socket = if ip.is_ipv4() {
                    TcpSocket::new_v4()?
                } else {
                    TcpSocket::new_v6()?
                };
                if let Some(source) = settings.source_ip {
                    socket.bind(SocketAddr::new(source, 0))?;
                }
                socket.connect(SocketAddr::new(ip, port)).await
            };
            match tokio::time::timeout(timeout, connection).await {
                Ok(Ok(stream)) => {
                    drop(stream);
                    (PortState::Open, None)
                }
                Ok(Err(error)) => (classify(&error), Some(error.to_string())),
                Err(_) => (PortState::TimedOut, Some("Connection timed out".into())),
            }
        };
        let (state, error) =
            tokio::select! { _=control.cancel.cancelled()=>return None, result=operation=>result };
        observation = Some(PortObservation {
            port,
            state,
            elapsed_ms: start.elapsed().as_millis() as u64,
            observed_at: Utc::now(),
            error,
            service: None,
        });
        if !matches!(
            state,
            PortState::TimedOut | PortState::OpenFiltered | PortState::Filtered
        ) || attempt == settings.retries
            || control.is_paused()
        {
            break;
        }
    }
    let mut observation = observation?;
    let discovery = if discover
        && settings.icmp_discovery
        && !control.is_paused()
        && !control.abandoned(&blocks)
        && limiter.wait_for(&control, &blocks).await
    {
        tokio::select! {_=control.cancel.cancelled()=>None,result=portspecter_platform::echo(ip,settings.source_ip,Duration::from_millis(settings.timeout_ms))=>Some(result)}
    } else {
        None
    };
    if settings.method == ScanMethod::TcpConnect
        && observation.state == PortState::Open
        && settings.inspect_services
        && !control.is_paused()
    {
        let permit = tokio::select! {_=control.cancel.cancelled()=>return None,p=service_slots.acquire()=>p.ok()?};
        if !limiter.wait_for(&control, &blocks).await {
            return None;
        }
        let service = tokio::select! {_=control.cancel.cancelled()=>return Some(ProbeOutput{observation,mac:None,name:None,discovery,shares:None}),s=portspecter_probe::inspect(ip,port,hostname.clone(),settings.source_ip)=>s};
        observation.service = Some(service);
        drop(permit);
    }
    let mut mac = None;
    let mut name = None;
    if (matches!(observation.state, PortState::Open | PortState::Closed)
        || (discover && settings.resolve_names && settings.local_names)
        || discovery
            .as_ref()
            .is_some_and(|value| value.state == DiscoveryState::Reachable))
        && !control.is_paused()
        && !control.abandoned(&blocks)
        && !control.cancel.is_cancelled()
    {
        let first = names_attempted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(ip);
        let need_name = first && settings.resolve_names && hostname.is_none();
        let need_mac = first
            && ip.is_ipv4()
            && !ip.is_loopback()
            && mac_attempted
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(ip);
        let timeout = Duration::from_millis(settings.timeout_ms.min(1500));
        if need_name && limiter.wait_for(&control, &blocks).await {
            let result = tokio::select! {
                _ = control.cancel.cancelled() => None,
                result = portspecter_probe::reverse_name(ip, dns_slots, timeout) => result,
            };
            name = result.map(|name| NameObservation {
                name,
                source: "reverse_dns".into(),
                observed_at: Utc::now(),
            });
        }
        if ip.is_ipv4()
            && !ip.is_loopback()
            && (need_mac || (need_name && name.is_none()))
            && !control.cancel.is_cancelled()
        {
            let permit = tokio::select! {
                _ = control.cancel.cancelled() => return Some(ProbeOutput {observation, mac, name, discovery, shares:None}),
                permit = service_slots.acquire() => permit.ok()?,
            };
            if limiter.wait_for(&control, &blocks).await {
                let response = tokio::select! {
                    _ = control.cancel.cancelled() => None,
                    response = portspecter_probe::query_node_status(ip, settings.source_ip, timeout) => response.ok().flatten(),
                };
                if let Some(status) = response {
                    if need_name && name.is_none() {
                        name = status.hostname.map(|name| NameObservation {
                            name,
                            source: "netbios_node_status".into(),
                            observed_at: Utc::now(),
                        });
                    }
                    if let Some(address) = status.mac.filter(|_| need_mac) {
                        mac = Some(MacObservation {
                            address: address
                                .iter()
                                .map(|b| format!("{b:02X}"))
                                .collect::<Vec<_>>()
                                .join(":"),
                            interface: "UDP 137".into(),
                            source: "netbios_node_status".into(),
                            neighbor_state: "reported_by_target".into(),
                            observed_at: Utc::now(),
                            vendor: vendors.lookup(&address).map(str::to_owned),
                            locally_administered: address[0] & 2 != 0,
                        });
                    }
                }
            }
            drop(permit);
        }
        if need_name
            && name.is_none()
            && settings.local_names
            && !ip.is_loopback()
            && !control.cancel.is_cancelled()
        {
            let _permit = tokio::select! {_=control.cancel.cancelled()=>return Some(ProbeOutput{observation,mac,name,discovery,shares:None}),permit=service_slots.acquire()=>permit.ok()?};
            let source = settings.source_ip;
            let link = tokio::task::spawn_blocking(move || {
                let route = portspecter_platform::route_to(ip, source).ok()?;
                if !route.on_link {
                    return None;
                }
                let index = portspecter_platform::interfaces()
                    .iter()
                    .find(|interface| interface.addresses.contains(&route.source))
                    .map(|interface| interface.index)?;
                Some((route.source, index))
            })
            .await
            .ok()
            .flatten();
            if let Some((source, index)) = link {
                for protocol in ["mdns", "llmnr"] {
                    if !limiter.wait_for(&control, &blocks).await {
                        break;
                    }
                    let timeout = Duration::from_millis(settings.timeout_ms.min(750));
                    let query = async {
                        if protocol == "mdns" {
                            portspecter_probe::mdns_name(ip, source, index, timeout).await
                        } else {
                            portspecter_probe::llmnr_name(ip, source, timeout).await
                        }
                    };
                    let result =
                        tokio::select! {_=control.cancel.cancelled()=>None,result=query=>result};
                    if let Some(value) = result {
                        name = Some(NameObservation {
                            name: value,
                            source: protocol.into(),
                            observed_at: Utc::now(),
                        });
                        break;
                    }
                }
            }
        }
    }
    let shares = if settings.smb_shares
        && settings.method == ScanMethod::TcpConnect
        && port == 445
        && observation.state == PortState::Open
    {
        if !control.ready(&blocks).await {
            return None;
        }
        let _permit = tokio::select! { _=control.cancel.cancelled()=>return None, p=service_slots.acquire()=>p.ok()? };
        if !limiter.wait_for(&control, &blocks).await {
            return None;
        }
        if settings.source_ip.is_some() {
            Some(ShareDiscovery {
                status: ShareStatus::Unavailable,
                shares: vec![],
                source: "SMB".into(),
                detail: Some(
                    "SMB enumeration uses OS routing; clear the explicit source IP to enable it"
                        .into(),
                ),
                observed_at: Utc::now(),
            })
        } else {
            tokio::select! {_=control.cancel.cancelled()=>None,v=portspecter_platform::shares::enumerate(ip)=>Some(v)}
        }
    } else {
        None
    };
    Some(ProbeOutput {
        shares,
        observation,
        mac,
        name,
        discovery,
    })
}

/// A bounded scheduler. At most `concurrency` futures and one small DB batch are live.
pub async fn run(
    plan: ScanPlan,
    control: ScanControl,
    storage: Storage,
    vendors: Arc<VendorDatabase>,
    events: mpsc::Sender<ScanEvent>,
) {
    if let Err(e) = run_inner(plan, control, storage, vendors, &events).await {
        let _ = events.send(ScanEvent::Error(format!("{e:#}"))).await;
    }
}

async fn run_inner(
    plan: ScanPlan,
    control: ScanControl,
    storage: Storage,
    vendors: Arc<VendorDatabase>,
    events: &mpsc::Sender<ScanEvent>,
) -> Result<()> {
    let syn = if plan.settings.method == ScanMethod::TcpSyn {
        anyhow::ensure!(
            plan.hosts.iter().all(|h| h.ip.is_ipv4()),
            "Native SYN currently supports IPv4; select TCP connect for IPv6"
        );
        let scanner = portspecter_platform::syn::SynScanner::new()?;
        if let Some(host) = plan.hosts.first() {
            scanner.preflight(host.ip, plan.settings.source_ip).await?;
        }
        Some(scanner)
    } else {
        None
    };
    let id = Uuid::new_v4();
    let total = plan.hosts.len() * plan.ports.len();
    let session = ScanSession {
        id,
        started_at: Utc::now(),
        finished_at: None,
        status: SessionStatus::Running,
        plan: plan.clone(),
        hosts: plan
            .hosts
            .iter()
            .map(|h| HostObservation {
                ip: h.ip,
                blocks: h.blocks.clone(),
                hostname: h.hostname.clone(),
                hostname_info: None,
                cameras: Vec::new(),
                advertisements: Vec::new(),
                shares: None,
                discovery: None,
                mac: None,
                ports: Vec::new(),
                completed: 0,
                total: plan.ports.len(),
            })
            .collect(),
        completed: 0,
        total,
    };
    storage.begin(&session).await?;
    if events
        .send(ScanEvent::Started(Box::new(session)))
        .await
        .is_err()
    {
        return Ok(());
    }
    discover_cameras(&plan, &control, &storage, id, events).await?;
    let limiter = RateLimiter::new(plan.settings.rate_per_second);
    let service_slots = Arc::new(Semaphore::new(16));
    let cached = match update_macs(&storage, id, &plan, &vendors, events).await {
        Ok(addresses) => addresses,
        Err(error) => {
            let _ = events.try_send(ScanEvent::Log(format!("MAC lookup: {error}")));
            HashSet::new()
        }
    };
    let context = ProbeContext {
        settings: plan.settings.clone(),
        control: control.clone(),
        limiter,
        service_slots,
        mac_attempted: Arc::new(std::sync::Mutex::new(cached)),
        names_attempted: Arc::new(std::sync::Mutex::new(HashSet::new())),
        dns_slots: Arc::new(Semaphore::new(8)),
        syn,
        vendors: vendors.clone(),
    };
    let mut waiting: VecDeque<usize> = (0..plan.hosts.len()).collect();
    let mut next = vec![0usize; plan.hosts.len()];
    let mut inflight = vec![0usize; plan.hosts.len()];
    let mut futures = tokio::task::JoinSet::new();
    let mut completed = 0usize;
    let mut batch = Vec::new();
    let mut last_flush = Instant::now();
    let mut last_mac = Instant::now();
    let mut representatives = HashMap::new();
    for host in &plan.hosts {
        for block in &host.blocks {
            representatives.entry(*block).or_insert(host.ip);
        }
    }
    let mut watched: Vec<_> = representatives.into_iter().collect();
    watched.sort_by_key(|(block, _)| *block);
    let watched: Vec<_> = watched.into_iter().take(32).map(|(_, ip)| ip).collect();
    let mut network = network_snapshot(watched.clone(), plan.settings.source_ip).await;
    let mut reported = SessionStatus::Running;
    let mut storage_error = None;
    loop {
        if control.cancel.is_cancelled() {
            break;
        }
        if !control.is_paused() {
            let rounds = waiting.len();
            for _ in 0..rounds {
                if futures.len() >= plan.settings.concurrency {
                    break;
                }
                let Some(index) = waiting.pop_front() else {
                    break;
                };
                let host = &plan.hosts[index];
                if control.abandoned(&host.blocks) {
                    next[index] = plan.ports.len();
                    continue;
                }
                if next[index] < plan.ports.len() {
                    if control.eligible(&host.blocks) && inflight[index] < plan.settings.per_host {
                        let ip = host.ip;
                        let port = plan.ports[next[index]];
                        next[index] += 1;
                        inflight[index] += 1;
                        let future = probe(host.clone(), port, context.clone(), next[index] == 1);
                        futures.spawn(async move { (index, ip, future.await) });
                    }
                    if next[index] < plan.ports.len() {
                        waiting.push_back(index);
                    }
                }
            }
        }
        let status = if control.is_paused() {
            SessionStatus::Paused
        } else {
            SessionStatus::Running
        };
        if reported != status {
            reported = status.clone();
            if events.send(ScanEvent::Status { id, status }).await.is_err() {
                control.cancel.cancel();
                break;
            }
        }
        if futures.is_empty() && waiting.is_empty() {
            break;
        }
        tokio::select! {
            _=control.cancel.cancelled()=>break,
            value=futures.join_next(),if !futures.is_empty()=>{
                if let Some(Err(error)) = &value { storage_error=Some(anyhow::anyhow!("Scan worker failed: {error}")); break; }
                if let Some(Ok((index,ip,output)))=value {
                    inflight[index]=inflight[index].saturating_sub(1);
                    if let Some(output)=output {
                        completed+=1;batch.push((ip,output.observation));
                        if let Some(value)=output.shares {
                            if let Err(error)=storage.save_shares(id,ip,&value).await {storage_error=Some(error);break;}
                            let _=events.send(ScanEvent::Shares{id,ip,value}).await;
                        }
                        if let Some(value)=output.discovery {
                            if let Err(error)=storage.save_discovery(id,ip,&value).await {storage_error=Some(error);break;}
                            let _=events.send(ScanEvent::Discovery{id,ip,value}).await;
                        }
                        if let Some(value)=output.name {
                            if let Err(error)=storage.save_name(id,ip,&value).await {storage_error=Some(error);break;}
                            let _=events.send(ScanEvent::Name{id,ip,value}).await;
                        }
                        if let Some(mac)=output.mac {
                            let values=vec![(ip,mac)];
                            if let Err(error)=storage.save_macs(id,&values).await {storage_error=Some(error);break;}
                            let _=events.send(ScanEvent::Macs{id,values}).await;
                        }
                    }
                }
            },
            _=tokio::time::sleep(Duration::from_millis(10))=>{},
        }
        if !batch.is_empty()
            && (batch.len() >= 256 || last_flush.elapsed() >= Duration::from_millis(100))
        {
            if let Err(e) = flush(&storage, id, &mut batch, completed, events).await {
                storage_error = Some(e);
                break;
            }
            last_flush = Instant::now();
        }
        if last_mac.elapsed() >= Duration::from_secs(5) {
            let current = network_snapshot(watched.clone(), plan.settings.source_ip).await;
            if current != network {
                network = current;
                if let Some(syn) = &context.syn {
                    syn.invalidate_routes();
                }
                control.pause(true);
                let _ = events.send(ScanEvent::NetworkChanged).await;
            }
            if let Err(e) = update_macs(&storage, id, &plan, &vendors, events).await {
                let _ = events.try_send(ScanEvent::Log(format!("MAC lookup: {e}")));
            }
            last_mac = Instant::now();
        }
    }
    // Drop cancels all in-flight async sockets. Completed observations are flushed before terminal status.
    drop(futures);
    if storage_error.is_none()
        && let Err(e) = flush(&storage, id, &mut batch, completed, events).await
    {
        storage_error = Some(e);
    }
    let _ = update_macs(&storage, id, &plan, &vendors, events).await;
    let status = if storage_error.is_some() {
        SessionStatus::Failed
    } else if control.cancel.is_cancelled() || completed < total {
        SessionStatus::Cancelled
    } else {
        SessionStatus::Completed
    };
    if let Some(e) = storage_error {
        let _ = events
            .send(ScanEvent::Error(format!(
                "Storage failed; scan stopped: {e:#}"
            )))
            .await;
    }
    storage.finish(id, status.clone(), completed).await?;
    let _ = events
        .send(ScanEvent::Finished {
            id,
            status,
            completed,
        })
        .await;
    Ok(())
}

/// One bounded discovery window per relevant local IPv4 interface, never one per host.
async fn discover_cameras(
    plan: &ScanPlan,
    control: &ScanControl,
    storage: &Storage,
    id: Uuid,
    events: &mpsc::Sender<ScanEvent>,
) -> Result<()> {
    if !plan.settings.onvif_discovery
        && !plan.settings.sadp_discovery
        && !plan.settings.dahua_discovery
        && !plan.settings.dnssd_discovery
        && !plan.settings.ssdp_discovery
    {
        return Ok(());
    }
    let targets: Arc<HashSet<IpAddr>> = Arc::new(
        plan.hosts
            .iter()
            .filter(|h| !control.abandoned(&h.blocks))
            .map(|h| h.ip)
            .collect(),
    );
    let mut sources = HashSet::new();
    for interface in portspecter_platform::interfaces() {
        if !interface
            .networks
            .iter()
            .filter_map(|n| n.parse::<ipnet::IpNet>().ok())
            .any(|n| targets.iter().any(|ip| n.contains(ip)))
        {
            continue;
        }
        for source in interface.addresses {
            if source.is_loopback() || plan.settings.source_ip.is_some_and(|v| v != source) {
                continue;
            }
            if let IpAddr::V4(v) = source {
                sources.insert(v);
            }
        }
    }
    let _ = events
        .send(ScanEvent::Log(format!(
            "Device discovery: {} local IPv4 interfaces; ONVIF={}, SADP={}, Dahua={}, DNS-SD={}, SSDP={}",
            sources.len(),
            plan.settings.onvif_discovery,
            plan.settings.sadp_discovery,
            plan.settings.dahua_discovery,
            plan.settings.dnssd_discovery,
            plan.settings.ssdp_discovery
        )))
        .await;
    // A batch of at most 8 interfaces avoids unbounded sockets on large virtualized hosts.
    let mut sources: Vec<_> = sources.into_iter().collect();
    sources.sort();
    let blocks: Vec<_> = (0..plan.blocks.len()).collect();
    let mut merged: HashMap<IpAddr, Vec<CameraObservation>> = HashMap::new();
    let mut advertisements: HashMap<IpAddr, Vec<DeviceAdvertisement>> = HashMap::new();
    enum Found {
        Cameras(Vec<(IpAddr, CameraObservation)>),
        Advertisements(Vec<(IpAddr, DeviceAdvertisement)>),
    }
    let host_map: HashMap<_, _> = plan.hosts.iter().map(|h| (h.ip, h)).collect();
    for batch in sources.chunks(8) {
        if !control.ready(&blocks).await {
            break;
        }
        let mut jobs = tokio::task::JoinSet::new();
        for source in batch {
            for (label, enabled) in [
                ("ONVIF", plan.settings.onvif_discovery),
                ("SADP", plan.settings.sadp_discovery),
                ("Dahua", plan.settings.dahua_discovery),
                ("DNS-SD", plan.settings.dnssd_discovery),
                ("SSDP", plan.settings.ssdp_discovery),
            ] {
                if !enabled {
                    continue;
                }
                let targets = targets.clone();
                let source = *source;
                jobs.spawn(async move {
                    let result = match label {
                        "ONVIF" | "SADP" => {
                            portspecter_probe::cameras::discover(source, label == "SADP", &targets)
                                .await
                                .map(Found::Cameras)
                        }
                        _ => {
                            use portspecter_probe::discovery::ProtocolKind;
                            let kind = match label {
                                "Dahua" => ProtocolKind::Dahua,
                                "DNS-SD" => ProtocolKind::DnsSd,
                                _ => ProtocolKind::Ssdp,
                            };
                            portspecter_probe::discovery::discover(source, kind, &targets)
                                .await
                                .map(Found::Advertisements)
                        }
                    };
                    (source, label, result)
                });
            }
        }
        while !jobs.is_empty() {
            let value =
                tokio::select! {_=control.cancel.cancelled()=>return Ok(()),v=jobs.join_next()=>v};
            if let Some(Err(error)) = &value {
                let _ = events
                    .send(ScanEvent::Log(format!(
                        "Device discovery worker failed: {error}"
                    )))
                    .await;
            }
            if let Some(Ok((source, label, result))) = value {
                match result {
                    Ok(Found::Cameras(values)) => {
                        for (ip, value) in values {
                            let Some(host) = host_map.get(&ip) else {
                                continue;
                            };
                            if control.abandoned(&host.blocks) {
                                continue;
                            }
                            let entries = merged.entry(ip).or_default();
                            if !entries.iter().any(|v| {
                                v.protocol == value.protocol && v.endpoint_id == value.endpoint_id
                            }) {
                                entries.push(value);
                            }
                        }
                    }
                    Ok(Found::Advertisements(values)) => {
                        for (ip, value) in values {
                            let Some(host) = host_map.get(&ip) else {
                                continue;
                            };
                            if control.abandoned(&host.blocks) {
                                continue;
                            }
                            let entries = advertisements.entry(ip).or_default();
                            if entries.len() < 128
                                && !entries.iter().any(|v| {
                                    v.protocol == value.protocol && v.identity == value.identity
                                })
                            {
                                entries.push(value);
                            }
                        }
                    }
                    Err(error) => {
                        let _ = events
                            .send(ScanEvent::Log(format!(
                                "{} discovery on {source}: {error}",
                                label
                            )))
                            .await;
                    }
                }
            }
        }
    }
    for (ip, mut values) in advertisements {
        values.sort_by(|a, b| (&a.protocol, &a.identity).cmp(&(&b.protocol, &b.identity)));
        storage.save_advertisements(id, ip, &values).await?;
        let _ = events
            .send(ScanEvent::Advertisements { id, ip, values })
            .await;
    }
    for (ip, values) in merged {
        storage.save_cameras(id, ip, &values).await?;
        let _ = events.send(ScanEvent::Cameras { id, ip, values }).await;
    }
    Ok(())
}

async fn network_snapshot(targets: Vec<IpAddr>, source: Option<IpAddr>) -> Vec<String> {
    tokio::task::spawn_blocking(move || {
        let mut result: Vec<String> = portspecter_platform::interfaces()
            .into_iter()
            .map(|interface| format!("{}:{:?}", interface.index, interface.addresses))
            .collect();
        result.sort();
        result.extend(targets.into_iter().map(|ip| {
            match portspecter_platform::route_to(ip, source) {
                Ok(route) => format!(
                    "{ip}:{:?}:{:?}:{}",
                    route.source, route.next_hop, route.interface
                ),
                Err(_) => format!("{ip}:unavailable"),
            }
        }));
        result
    })
    .await
    .unwrap_or_default()
}

async fn flush(
    storage: &Storage,
    id: Uuid,
    batch: &mut Vec<(IpAddr, PortObservation)>,
    completed: usize,
    events: &mpsc::Sender<ScanEvent>,
) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    storage.write_batch(id, batch, completed).await?;
    events
        .send(ScanEvent::Observations {
            id,
            values: std::mem::take(batch),
            completed,
        })
        .await
        .map_err(|_| anyhow::anyhow!("UI channel disconnected"))?;
    Ok(())
}

async fn update_macs(
    storage: &Storage,
    id: Uuid,
    plan: &ScanPlan,
    vendors: &Arc<VendorDatabase>,
    events: &mpsc::Sender<ScanEvent>,
) -> Result<HashSet<IpAddr>> {
    let vendors = vendors.clone();
    let snapshot =
        tokio::task::spawn_blocking(move || portspecter_platform::mac_snapshot(&vendors)).await??;
    let values: Vec<_> = plan
        .hosts
        .iter()
        .filter_map(|h| snapshot.get(&h.ip).map(|m| (h.ip, m.clone())))
        .collect();
    let addresses = values.iter().map(|(ip, _)| *ip).collect();
    if !values.is_empty() {
        storage.save_macs(id, &values).await?;
        let _ = events.send(ScanEvent::Macs { id, values }).await;
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn pause_blocks_reserved_work_and_cancel_unblocks_it() {
        let control = ScanControl::new(1);
        control.pause(true);
        let limiter = RateLimiter::new(1000);
        assert!(
            tokio::time::timeout(Duration::from_millis(30), limiter.wait_for(&control, &[0]))
                .await
                .is_err()
        );
        control.cancel.cancel();
        assert!(
            !tokio::time::timeout(Duration::from_millis(100), limiter.wait_for(&control, &[0]))
                .await
                .unwrap()
        );
    }
    #[tokio::test]
    async fn real_loopback_and_persistence() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let db = Storage::memory().await.unwrap();
        let settings = ScanSettings {
            inspect_services: false,
            retries: 0,
            ..Default::default()
        };
        let plan = prepare("127.0.0.1", &port.to_string(), "", settings)
            .await
            .unwrap();
        let (tx, mut rx) = mpsc::channel(32);
        let db_copy = db.clone();
        let task = tokio::spawn(run(
            plan,
            ScanControl::new(1),
            db_copy,
            Arc::new(VendorDatabase::default()),
            tx,
        ));
        let mut found = false;
        let mut finished = false;
        while let Some(event) = rx.recv().await {
            match event {
                ScanEvent::Observations { values, .. } => {
                    found = values.iter().any(|(_, p)| p.state == PortState::Open);
                }
                ScanEvent::Finished { status, .. } => {
                    assert_eq!(status, SessionStatus::Completed);
                    finished = true;
                }
                ScanEvent::Error(e) => panic!("{e}"),
                _ => {}
            }
        }
        task.await.unwrap();
        assert!(found && finished);
        assert_eq!(db.list().await.unwrap().len(), 1);
        drop(listener);
    }
    #[tokio::test]
    async fn cancel_paused_session() {
        let db = Storage::memory().await.unwrap();
        let plan = prepare("127.0.0.1", "1-100", "", ScanSettings::default())
            .await
            .unwrap();
        let control = ScanControl::new(1);
        control.pause(true);
        let (tx, mut rx) = mpsc::channel(32);
        let stop = control.clone();
        let task = tokio::spawn(run(
            plan,
            control,
            db,
            Arc::new(VendorDatabase::default()),
            tx,
        ));
        loop {
            if let Some(ScanEvent::Status {
                status: SessionStatus::Paused,
                ..
            }) = rx.recv().await
            {
                break;
            }
        }
        stop.cancel.cancel();
        let mut finished = false;
        while let Some(event) = rx.recv().await {
            if let ScanEvent::Finished {
                status, completed, ..
            } = event
            {
                assert_eq!(status, SessionStatus::Cancelled);
                assert_eq!(completed, 0);
                finished = true;
            }
        }
        task.await.unwrap();
        assert!(finished);
    }
    #[tokio::test]
    async fn udp_session_persists_method_and_response_without_tcp_inspection() {
        let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let mut bytes = [0; 512];
            let (_, peer) = listener.recv_from(&mut bytes).await.unwrap();
            listener.send_to(b"udp fixture", peer).await.unwrap();
        });
        let settings = ScanSettings {
            method: ScanMethod::Udp,
            icmp_discovery: false,
            resolve_names: false,
            retries: 0,
            ..Default::default()
        };
        let plan = prepare("127.0.0.1", &address.port().to_string(), "", settings)
            .await
            .unwrap();
        let db = Storage::memory().await.unwrap();
        let (tx, mut rx) = mpsc::channel(32);
        let storage = db.clone();
        let task = tokio::spawn(run(
            plan,
            ScanControl::new(1),
            storage,
            Arc::new(VendorDatabase::default()),
            tx,
        ));
        let mut id = None;
        while let Some(event) = rx.recv().await {
            match event {
                ScanEvent::Started(session) => id = Some(session.id),
                ScanEvent::Finished { status, .. } => assert_eq!(status, SessionStatus::Completed),
                ScanEvent::Error(error) => panic!("{error}"),
                _ => {}
            }
        }
        task.await.unwrap();
        responder.await.unwrap();
        let saved = db.load(&id.unwrap().to_string()).await.unwrap();
        assert_eq!(saved.plan.settings.method, ScanMethod::Udp);
        assert_eq!(saved.hosts[0].ports[0].state, PortState::Open);
        assert!(saved.hosts[0].ports[0].service.is_none());
        assert_eq!(saved.completed, 1);
    }

    #[tokio::test]
    async fn cancelled_subnet_does_not_block_another_subnet() {
        let db = Storage::memory().await.unwrap();
        let settings = ScanSettings {
            inspect_services: false,
            retries: 0,
            ..Default::default()
        };
        let plan = prepare("127.0.0.1|One|10\n127.0.0.2|Two|20", "1", "", settings)
            .await
            .unwrap();
        let control = ScanControl::new(2);
        control.cancel_block(0);
        let (tx, mut rx) = mpsc::channel(32);
        let task = tokio::spawn(run(
            plan,
            control,
            db,
            Arc::new(VendorDatabase::default()),
            tx,
        ));
        let mut addresses = Vec::new();
        let mut terminal = None;
        while let Some(event) = rx.recv().await {
            match event {
                ScanEvent::Observations { values, .. } => {
                    addresses.extend(values.into_iter().map(|(ip, _)| ip))
                }
                ScanEvent::Finished {
                    status, completed, ..
                } => terminal = Some((status, completed)),
                ScanEvent::Error(e) => panic!("{e}"),
                _ => {}
            }
        }
        task.await.unwrap();
        assert_eq!(addresses, vec!["127.0.0.2".parse::<IpAddr>().unwrap()]);
        assert_eq!(terminal, Some((SessionStatus::Cancelled, 1)));
    }
}
