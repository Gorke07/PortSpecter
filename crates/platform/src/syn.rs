//! Native IPv4 SYN engine. One capture/injection thread per source interface;
//! no external scanner, no TCP-connect fallback, and no completed handshake.
use anyhow::{Context, Result, bail, ensure};
use portspecter_domain::PortState;
use std::{
    collections::HashMap,
    ffi::{CStr, CString, c_char, c_int, c_long, c_void},
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};
use tokio::sync::oneshot;

#[repr(C)]
struct Device {
    next: *mut Device,
    name: *mut c_char,
    description: *mut c_char,
    addresses: *mut Address,
    flags: u32,
}
#[repr(C)]
struct Address {
    next: *mut Address,
    addr: *mut u8,
    netmask: *mut u8,
    broadcast: *mut u8,
    destination: *mut u8,
}
#[repr(C)]
struct Header {
    seconds: c_long,
    micros: c_long,
    captured: u32,
    original: u32,
}
#[repr(C)]
struct Filter {
    len: u32,
    instructions: *mut c_void,
}
type Handle = *mut c_void;
struct Api {
    find: unsafe extern "C" fn(*mut *mut Device, *mut c_char) -> c_int,
    free: unsafe extern "C" fn(*mut Device),
    open: unsafe extern "C" fn(*const c_char, c_int, c_int, c_int, *mut c_char) -> Handle,
    close: unsafe extern "C" fn(Handle),
    nonblock: unsafe extern "C" fn(Handle, c_int, *mut c_char) -> c_int,
    datalink: unsafe extern "C" fn(Handle) -> c_int,
    next: unsafe extern "C" fn(Handle, *mut *const Header, *mut *const u8) -> c_int,
    send: unsafe extern "C" fn(Handle, *const u8, c_int) -> c_int,
    error: unsafe extern "C" fn(Handle) -> *const c_char,
    compile: unsafe extern "C" fn(Handle, *mut Filter, *const c_char, c_int, u32) -> c_int,
    setfilter: unsafe extern "C" fn(Handle, *mut Filter) -> c_int,
    freecode: unsafe extern "C" fn(*mut Filter),
    _library: libloading::Library,
}
impl Api {
    fn load() -> Result<Arc<Self>> {
        // SAFETY: load only the system capture library; function signatures are
        // the stable libpcap C ABI. The library outlives every copied function.
        unsafe {
            #[cfg(windows)]
            let library = {
                let root = std::env::var_os("SystemRoot").context("SystemRoot unavailable")?;
                let path = std::path::PathBuf::from(root).join("System32/Npcap/wpcap.dll");
                libloading::os::windows::Library::load_with_flags(path, 0x100 | 0x1000)
                    .context("SYN requires Npcap installed from npcap.com; capture access may require Administrator")?.into()
            };
            #[cfg(target_os = "linux")]
            let library = libloading::Library::new("libpcap.so.1")
                .or_else(|_| libloading::Library::new("libpcap.so.0.8"))
                .context("SYN requires libpcap and raw packet capture/injection permissions")?;
            #[cfg(target_os = "macos")]
            let library = libloading::Library::new("/usr/lib/libpcap.A.dylib")
                .context("SYN requires system libpcap and access to /dev/bpf devices")?;
            let library: libloading::Library = library;
            macro_rules! symbol {
                ($name:literal) => {
                    *library.get(concat!($name, "\0").as_bytes())?
                };
            }
            Ok(Arc::new(Self {
                find: symbol!("pcap_findalldevs"),
                free: symbol!("pcap_freealldevs"),
                open: symbol!("pcap_open_live"),
                close: symbol!("pcap_close"),
                nonblock: symbol!("pcap_setnonblock"),
                datalink: symbol!("pcap_datalink"),
                next: symbol!("pcap_next_ex"),
                send: symbol!("pcap_sendpacket"),
                error: symbol!("pcap_geterr"),
                compile: symbol!("pcap_compile"),
                setfilter: symbol!("pcap_setfilter"),
                freecode: symbol!("pcap_freecode"),
                _library: library,
            }))
        }
    }
    fn device(&self, source: Ipv4Addr) -> Result<CString> {
        let mut devices = std::ptr::null_mut();
        let mut error = [0; 256];
        // SAFETY: libpcap owns this linked list until freealldevs; only read it
        // during that lifetime. IPv4 sockaddr has its address at byte offset 4.
        unsafe {
            ensure!(
                (self.find)(&mut devices, error.as_mut_ptr()) == 0,
                "{}",
                CStr::from_ptr(error.as_ptr()).to_string_lossy()
            );
            let mut found = None;
            let mut current = devices;
            while !current.is_null() {
                let device = &*current;
                let mut matches = source.is_loopback() && device.flags & 1 != 0;
                let mut address = device.addresses;
                while !address.is_null() {
                    let raw = (*address).addr;
                    if !raw.is_null() {
                        #[cfg(target_os = "macos")]
                        let family = *raw.add(1) as u16;
                        #[cfg(not(target_os = "macos"))]
                        let family = u16::from_ne_bytes([*raw, *raw.add(1)]);
                        if family == 2
                            && std::slice::from_raw_parts(raw.add(4), 4) == source.octets()
                        {
                            matches = true;
                        }
                    }
                    address = (*address).next;
                }
                if matches && !device.name.is_null() {
                    found = Some(CStr::from_ptr(device.name).to_owned());
                    break;
                }
                current = device.next;
            }
            (self.free)(devices);
            found.context("No capture adapter for selected IPv4 source; this VPN/interface may not support raw injection")
        }
    }
}
struct Capture {
    api: Arc<Api>,
    handle: Handle,
    link: c_int,
}
// SAFETY: the handle is moved into one worker thread and is never used concurrently.
unsafe impl Send for Capture {}
impl Drop for Capture {
    fn drop(&mut self) {
        unsafe {
            (self.api.close)(self.handle);
        }
    }
}
impl Capture {
    fn open(api: Arc<Api>, source: Ipv4Addr) -> Result<Self> {
        let device = api.device(source)?;
        let mut error = [0; 256];
        // SAFETY: valid C strings/buffers, and Capture owns the successful handle.
        unsafe {
            let handle = (api.open)(device.as_ptr(), 65535, 0, 1, error.as_mut_ptr());
            ensure!(
                !handle.is_null(),
                "Capture access denied/unavailable: {}",
                CStr::from_ptr(error.as_ptr()).to_string_lossy()
            );
            let capture = Self {
                link: (api.datalink)(handle),
                handle,
                api,
            };
            ensure!(
                matches!(capture.link, 0 | 1 | 12 | 108),
                "Unsupported raw link type {}; use TCP connect on this interface",
                capture.link
            );
            ensure!(
                (capture.api.nonblock)(handle, 1, error.as_mut_ptr()) == 0,
                "Cannot enable nonblocking capture"
            );
            let filter_text = CString::new(format!(
                "arp or (ip and dst host {source} and (tcp or icmp))"
            ))?;
            let mut filter = Filter {
                len: 0,
                instructions: std::ptr::null_mut(),
            };
            ensure!(
                (capture.api.compile)(handle, &mut filter, filter_text.as_ptr(), 1, u32::MAX) == 0,
                "Cannot compile SYN capture filter"
            );
            let installed = (capture.api.setfilter)(handle, &mut filter);
            (capture.api.freecode)(&mut filter);
            ensure!(installed == 0, "Cannot install SYN capture filter");
            Ok(capture)
        }
    }
    fn send(&self, bytes: &[u8]) -> Result<()> {
        unsafe {
            ensure!(
                (self.api.send)(self.handle, bytes.as_ptr(), bytes.len() as c_int) == 0,
                "Raw packet injection failed: {}",
                CStr::from_ptr((self.api.error)(self.handle)).to_string_lossy()
            );
        }
        Ok(())
    }
    fn next(&self) -> Result<Option<Vec<u8>>> {
        let mut header = std::ptr::null();
        let mut data = std::ptr::null();
        // SAFETY: next_ex exposes caplen initialized bytes until the next call.
        unsafe {
            match (self.api.next)(self.handle, &mut header, &mut data) {
                1 if !header.is_null() && !data.is_null() => {
                    let length = (*header).captured as usize;
                    ensure!(length <= 65535, "Invalid capture length");
                    Ok(Some(std::slice::from_raw_parts(data, length).to_vec()))
                }
                0 => Ok(None),
                _ => bail!(
                    "Capture stopped: {}",
                    CStr::from_ptr((self.api.error)(self.handle)).to_string_lossy()
                ),
            }
        }
    }
}

type Reply = oneshot::Sender<Result<PortState>>;
struct Request {
    target: Ipv4Addr,
    hop: Ipv4Addr,
    port: u16,
    timeout: Duration,
    reply: Reply,
}
struct Pending {
    request: Request,
    sequence: u32,
    deadline: Instant,
    sent: bool,
    _reservation: socket2::Socket,
}
#[derive(Clone)]
pub struct SynScanner {
    inner: Arc<Scanner>,
}
struct Scanner {
    api: Arc<Api>,
    workers: Mutex<HashMap<Ipv4Addr, mpsc::SyncSender<Request>>>,
    routes: Mutex<HashMap<(Ipv4Addr, Option<IpAddr>), crate::RouteInfo>>,
}
impl SynScanner {
    pub fn invalidate_routes(&self) {
        self.inner
            .routes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.inner
            .workers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
    pub fn new() -> Result<Self> {
        Ok(Self {
            inner: Arc::new(Scanner {
                api: Api::load()?,
                workers: Mutex::new(HashMap::new()),
                routes: Mutex::new(HashMap::new()),
            }),
        })
    }
    fn sender(
        &self,
        target: Ipv4Addr,
        selected: Option<IpAddr>,
    ) -> Result<(mpsc::SyncSender<Request>, Ipv4Addr)> {
        let route = {
            let mut routes = self.inner.routes.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(route) = routes.get(&(target, selected)) {
                route.clone()
            } else {
                let route = crate::route_to(target.into(), selected)?;
                routes.insert((target, selected), route.clone());
                route
            }
        };
        let IpAddr::V4(source) = route.source else {
            bail!("SYN currently requires IPv4");
        };
        let IpAddr::V4(hop) = route.next_hop.unwrap_or(target.into()) else {
            bail!("SYN requires an IPv4 next hop");
        };
        let mut workers = self.inner.workers.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(sender) = workers.get(&source) {
            return Ok((sender.clone(), hop));
        }
        let capture = Capture::open(self.inner.api.clone(), source)?;
        let mac = netdev::get_interfaces()
            .into_iter()
            .find(|i| i.ipv4.iter().any(|n| n.addr() == source))
            .and_then(|i| i.mac_addr)
            .map(|m| m.octets());
        ensure!(
            capture.link != 1 || mac.is_some(),
            "Ethernet source MAC unavailable"
        );
        let (sender, receiver) = mpsc::sync_channel(4096);
        std::thread::Builder::new()
            .name("portspecter-syn".into())
            .spawn(move || worker(capture, source, mac.unwrap_or([0; 6]), receiver))?;
        workers.insert(source, sender.clone());
        Ok((sender, hop))
    }
    pub async fn preflight(&self, ip: IpAddr, source: Option<IpAddr>) -> Result<()> {
        let IpAddr::V4(ip) = ip else {
            bail!("Native SYN currently supports IPv4; use TCP connect for IPv6");
        };
        let scanner = self.clone();
        tokio::task::spawn_blocking(move || scanner.sender(ip, source)).await??;
        Ok(())
    }
    pub async fn scan(
        &self,
        ip: IpAddr,
        port: u16,
        source: Option<IpAddr>,
        timeout: Duration,
    ) -> Result<PortState> {
        let IpAddr::V4(ip) = ip else {
            bail!("Native SYN currently supports IPv4");
        };
        let scanner = self.clone();
        let (sender, hop) =
            tokio::task::spawn_blocking(move || scanner.sender(ip, source)).await??;
        let (reply, receive) = oneshot::channel();
        sender
            .try_send(Request {
                target: ip,
                hop,
                port,
                timeout,
                reply,
            })
            .context("SYN worker unavailable or queue full")?;
        receive.await.context("SYN capture worker stopped")?
    }
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|b| u16::from_be_bytes([b[0], *b.get(1).unwrap_or(&0)]) as u32)
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
fn tcp(
    source: Ipv4Addr,
    target: Ipv4Addr,
    local: u16,
    remote: u16,
    sequence: u32,
    ack: u32,
    flags: u8,
) -> Vec<u8> {
    let mut packet = vec![0; 40];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&40u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&target.octets());
    let sum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet[20..22].copy_from_slice(&local.to_be_bytes());
    packet[22..24].copy_from_slice(&remote.to_be_bytes());
    packet[24..28].copy_from_slice(&sequence.to_be_bytes());
    packet[28..32].copy_from_slice(&ack.to_be_bytes());
    packet[32] = 0x50;
    packet[33] = flags;
    packet[34..36].copy_from_slice(&64240u16.to_be_bytes());
    let mut pseudo = packet[12..20].to_vec();
    pseudo.extend_from_slice(&[0, 6, 0, 20]);
    pseudo.extend_from_slice(&packet[20..]);
    let sum = checksum(&pseudo);
    packet[36..38].copy_from_slice(&sum.to_be_bytes());
    packet
}
fn frame(link: c_int, source: [u8; 6], destination: [u8; 6], packet: &[u8]) -> Vec<u8> {
    let mut bytes = match link {
        1 => {
            let mut b = destination.to_vec();
            b.extend_from_slice(&source);
            b.extend_from_slice(&[8, 0]);
            b
        }
        0 => 2u32.to_ne_bytes().to_vec(),
        108 => 2u32.to_be_bytes().to_vec(),
        _ => Vec::new(),
    };
    bytes.extend_from_slice(packet);
    bytes
}
fn arp(source: Ipv4Addr, mac: [u8; 6], hop: Ipv4Addr) -> Vec<u8> {
    let mut bytes = vec![255; 6];
    bytes.extend_from_slice(&mac);
    bytes.extend_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 1]);
    bytes.extend_from_slice(&mac);
    bytes.extend_from_slice(&source.octets());
    bytes.extend_from_slice(&[0; 6]);
    bytes.extend_from_slice(&hop.octets());
    bytes
}
fn ipv4(bytes: &[u8], link: c_int) -> Option<&[u8]> {
    let offset = match link {
        1 => {
            let mut offset = 14;
            let mut kind = word(bytes, 12)?;
            for _ in 0..2 {
                if kind == 0x8100 || kind == 0x88a8 {
                    kind = word(bytes, offset + 2)?;
                    offset += 4;
                }
            }
            if kind != 0x800 {
                return None;
            }
            offset
        }
        0 | 108 => 4,
        12 => 0,
        _ => return None,
    };
    let packet = bytes.get(offset..)?;
    if packet.len() < 20
        || packet[0] >> 4 != 4
        || packet[0] & 15 < 5
        || word(packet, 6)? & 0x3fff != 0
    {
        return None;
    }
    packet.get(..word(packet, 2)? as usize)
}
fn word(bytes: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes(bytes.get(i..i + 2)?.try_into().ok()?))
}
fn dword(bytes: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.get(i..i + 4)?.try_into().ok()?))
}
fn reply(
    packet: &[u8],
    source: Ipv4Addr,
    pending: &HashMap<u16, Pending>,
) -> Option<(u16, PortState, u32)> {
    if packet.get(16..20)? != source.octets() {
        return None;
    }
    let offset = ((packet[0] & 15) as usize) * 4;
    let data = packet.get(offset..)?;
    if packet[9] == 6 {
        if data.len() < 20 || data[12] >> 4 < 5 || (data[12] >> 4) as usize * 4 > data.len() {
            return None;
        }
        let local = word(data, 2)?;
        let job = pending.get(&local)?;
        if !job.sent
            || packet.get(12..16)? != job.request.target.octets()
            || word(data, 0)? != job.request.port
            || dword(data, 8)? != job.sequence.wrapping_add(1)
        {
            return None;
        }
        if data[13] & 0x14 == 0x14 {
            return Some((local, PortState::Closed, 0));
        }
        if data[13] & 0x17 == 0x12 {
            return Some((local, PortState::Open, dword(data, 4)?.wrapping_add(1)));
        }
    } else if packet[9] == 1 && data.first() == Some(&3) {
        let quoted = data.get(8..)?;
        if quoted.len() < 28
            || quoted[0] >> 4 != 4
            || quoted[0] & 15 < 5
            || quoted[9] != 6
            || quoted.get(12..16)? != source.octets()
        {
            return None;
        }
        let inner = quoted.get((quoted[0] as usize & 15) * 4..)?;
        let local = word(inner, 0)?;
        let job = pending.get(&local)?;
        if job.sent
            && quoted.get(16..20)? == job.request.target.octets()
            && word(inner, 2)? == job.request.port
            && dword(inner, 4)? == job.sequence
        {
            return Some((local, PortState::Filtered, 0));
        }
    }
    None
}

fn worker(capture: Capture, source: Ipv4Addr, mac: [u8; 6], receiver: mpsc::Receiver<Request>) {
    let mut pending: HashMap<u16, Pending> = HashMap::new();
    let mut neighbors: HashMap<Ipv4Addr, ([u8; 6], Instant)> = HashMap::new();
    let mut arp_sent: HashMap<Ipv4Addr, Instant> = HashMap::new();
    loop {
        for _ in 0..256 {
            let request = match receiver.try_recv() {
                Ok(r) => r,
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return,
            };
            if request.reply.is_closed() {
                continue;
            }
            let reservation = (|| -> Result<_> {
                let socket = socket2::Socket::new(
                    socket2::Domain::IPV4,
                    socket2::Type::STREAM,
                    Some(socket2::Protocol::TCP),
                )?;
                socket.bind(&std::net::SocketAddr::new(source.into(), 0).into())?;
                let port = socket
                    .local_addr()?
                    .as_socket()
                    .context("Missing bound TCP port")?
                    .port();
                Ok((socket, port))
            })();
            match reservation {
                Ok((socket, port)) => {
                    let sequence = u32::from_be_bytes(
                        uuid::Uuid::new_v4().as_bytes()[..4].try_into().unwrap(),
                    );
                    let deadline = Instant::now() + request.timeout;
                    pending.insert(
                        port,
                        Pending {
                            request,
                            sequence,
                            deadline,
                            sent: false,
                            _reservation: socket,
                        },
                    );
                }
                Err(error) => {
                    let _ = request.reply.send(Err(error));
                }
            }
        }
        let mut done = Vec::new();
        for (&port, job) in &mut pending {
            if job.request.reply.is_closed() {
                done.push((port, None));
                continue;
            }
            if Instant::now() >= job.deadline {
                done.push((
                    port,
                    Some(if job.sent {
                        Ok(PortState::Filtered)
                    } else {
                        Err(anyhow::anyhow!(
                            "Next-hop MAC unresolved; no SYN packet was sent"
                        ))
                    }),
                ));
                continue;
            }
            if job.sent {
                continue;
            }
            let destination = neighbors
                .get(&job.request.hop)
                .filter(|(_, time)| time.elapsed() < Duration::from_secs(30))
                .map(|(mac, _)| *mac);
            if capture.link != 1 || source.is_loopback() || destination.is_some() {
                let packet = frame(
                    capture.link,
                    mac,
                    destination.unwrap_or([0; 6]),
                    &tcp(
                        source,
                        job.request.target,
                        port,
                        job.request.port,
                        job.sequence,
                        0,
                        2,
                    ),
                );
                match capture.send(&packet) {
                    Ok(()) => {
                        job.sent = true;
                        job.deadline = Instant::now() + job.request.timeout;
                    }
                    Err(e) => done.push((port, Some(Err(e)))),
                }
            } else if arp_sent
                .get(&job.request.hop)
                .is_none_or(|time| time.elapsed() >= Duration::from_secs(1))
            {
                match capture.send(&arp(source, mac, job.request.hop)) {
                    Ok(()) => {
                        arp_sent.insert(job.request.hop, Instant::now());
                    }
                    Err(e) => done.push((port, Some(Err(e)))),
                }
            }
        }
        for (port, result) in done {
            if let Some(job) = pending.remove(&port)
                && let Some(result) = result
            {
                let _ = job.request.reply.send(result);
            }
        }
        for _ in 0..2048 {
            let bytes = match capture.next() {
                Ok(Some(b)) => b,
                Ok(None) => break,
                Err(e) => {
                    for (_, job) in pending.drain() {
                        let _ = job.request.reply.send(Err(anyhow::anyhow!(e.to_string())));
                    }
                    return;
                }
            };
            if capture.link == 1
                && bytes.len() >= 42
                && bytes[12..22] == [8, 6, 0, 1, 8, 0, 6, 4, 0, 2]
                && bytes[32..38] == mac
                && bytes[38..42] == source.octets()
            {
                let hop = Ipv4Addr::new(bytes[28], bytes[29], bytes[30], bytes[31]);
                let neighbor: [u8; 6] = bytes[22..28].try_into().unwrap();
                if arp_sent.contains_key(&hop)
                    && neighbor[0] & 1 == 0
                    && neighbor != [0; 6]
                    && bytes[6..12] == neighbor
                {
                    neighbors.insert(hop, (neighbor, Instant::now()));
                }
            }
            if let Some(packet) = ipv4(&bytes, capture.link)
                && let Some((port, state, ack)) = reply(packet, source, &pending)
                && let Some(job) = pending.remove(&port)
            {
                if state == PortState::Open {
                    let destination = neighbors
                        .get(&job.request.hop)
                        .map(|(mac, _)| *mac)
                        .unwrap_or([0; 6]);
                    let reset = frame(
                        capture.link,
                        mac,
                        destination,
                        &tcp(
                            source,
                            job.request.target,
                            port,
                            job.request.port,
                            job.sequence.wrapping_add(1),
                            ack,
                            0x14,
                        ),
                    );
                    let _ = capture.send(&reset);
                }
                let _ = job.request.reply.send(Ok(state));
            }
        }
        neighbors.retain(|_, (_, time)| time.elapsed() < Duration::from_secs(30));
        arp_sent.retain(|_, time| time.elapsed() < Duration::from_secs(30));
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "Requires installed Npcap/libpcap and capture/injection permissions"]
    async fn native_loopback_open_closed_without_completing_handshake() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let scanner = SynScanner::new().unwrap();
        scanner.preflight(address.ip(), None).await.unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            scanner.scan(address.ip(), address.port(), None, Duration::from_secs(1)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result, PortState::Open);
        assert!(
            tokio::time::timeout(Duration::from_millis(150), listener.accept())
                .await
                .is_err()
        );
        drop(listener);
        assert_eq!(
            scanner
                .scan(address.ip(), address.port(), None, Duration::from_secs(1))
                .await
                .unwrap(),
            PortState::Closed
        );
    }
    #[test]
    fn syn_checksums_reply_correlation_and_truncation() {
        let source = Ipv4Addr::LOCALHOST;
        let target = Ipv4Addr::new(192, 0, 2, 1);
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        let (sender, _) = oneshot::channel();
        let request = Request {
            target,
            hop: target,
            port: 443,
            timeout: Duration::from_secs(1),
            reply: sender,
        };
        let mut jobs = HashMap::new();
        jobs.insert(
            50000,
            Pending {
                request,
                sequence: 42,
                deadline: Instant::now(),
                sent: true,
                _reservation: socket,
            },
        );
        let syn = tcp(source, target, 50000, 443, 42, 0, 2);
        assert_eq!(checksum(&syn[..20]), 0);
        let mut pseudo = syn[12..20].to_vec();
        pseudo.extend_from_slice(&[0, 6, 0, 20]);
        pseudo.extend_from_slice(&syn[20..]);
        assert_eq!(checksum(&pseudo), 0);
        let valid = tcp(target, source, 443, 50000, 90, 43, 0x12);
        assert_eq!(
            reply(&valid, source, &jobs),
            Some((50000, PortState::Open, 91))
        );
        assert!(
            reply(
                &tcp(target, source, 443, 50000, 90, 44, 0x12),
                source,
                &jobs
            )
            .is_none()
        );
        assert!(
            reply(
                &tcp(target, source, 444, 50000, 90, 43, 0x12),
                source,
                &jobs
            )
            .is_none()
        );
        assert_eq!(
            reply(
                &tcp(target, source, 443, 50000, 90, 43, 0x14),
                source,
                &jobs
            ),
            Some((50000, PortState::Closed, 0))
        );
        for link in [0, 1, 12, 108] {
            let encoded = frame(link, [2; 6], [4; 6], &valid);
            assert_eq!(ipv4(&encoded, link), Some(valid.as_slice()));
            for length in 0..encoded.len() {
                assert!(ipv4(&encoded[..length], link).is_none());
            }
        }
        for length in 0..valid.len() {
            assert!(reply(&valid[..length], source, &jobs).is_none());
        }
    }
    #[test]
    fn icmp_error_must_quote_our_tuple_and_sequence() {
        let source = Ipv4Addr::LOCALHOST;
        let target = Ipv4Addr::new(192, 0, 2, 1);
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        let (sender, _) = oneshot::channel();
        let request = Request {
            target,
            hop: target,
            port: 80,
            timeout: Duration::from_secs(1),
            reply: sender,
        };
        let jobs = HashMap::from([(
            50000,
            Pending {
                request,
                sequence: 42,
                deadline: Instant::now(),
                sent: true,
                _reservation: socket,
            },
        )]);
        let mut packet = vec![0; 28];
        packet[0] = 0x45;
        packet[9] = 1;
        packet[16..20].copy_from_slice(&source.octets());
        packet[20] = 3;
        packet[21] = 13;
        packet.extend_from_slice(&tcp(source, target, 50000, 80, 42, 0, 2)[..28]);
        assert_eq!(
            reply(&packet, source, &jobs),
            Some((50000, PortState::Filtered, 0))
        );
        *packet.last_mut().unwrap() ^= 1;
        assert!(reply(&packet, source, &jobs).is_none());
    }
}
