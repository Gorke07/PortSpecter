use crate::{
    backend::{self, Command, Event},
    locale::{Language, Locale},
    style,
};
use iced::widget::rule::horizontal as horizontal_rule;
use iced::widget::{
    self, Column, Row, button, checkbox, column, container, pick_list, progress_bar, row,
    scrollable, slider, space, text, text_editor, text_input,
};
use iced::{Alignment, Color, Element, Length, Subscription, Task, Theme};
use portspecter_core::{ScanControl, ScanEvent};
use portspecter_domain::*;
use portspecter_storage::{SavedProfile, SessionSummary};
use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    path::PathBuf,
    time::Duration,
};
use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Scan,
    Devices,
    History,
    Profiles,
    Settings,
    Queue,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectorTab {
    Overview,
    Ports,
    Discovery,
    Shares,
}
#[derive(Debug, Clone)]
pub enum Message {
    #[cfg(windows)]
    WindowOpened(iced::window::Id),
    WindowDrag,
    WindowMinimize,
    WindowMaximize,
    WindowMaximized(bool),
    WindowClose,
    WindowResize(iced::window::Direction),
    #[cfg(target_os = "macos")]
    WindowPointer(iced::mouse::Event),
    Tick,
    Keyboard(iced::keyboard::Event),
    Screenshot(iced::window::Screenshot),
    Resize(iced::Size),
    Page(Page),
    Target(text_editor::Action),
    AddSubnet(String),
    ResetFilters,
    Ports(String),
    Method(ScanMethod),
    KnownPorts(bool),
    ExtendedPorts(bool),
    Exclusions(String),
    Search(String),
    Timeout(String),
    Concurrency(String),
    WorkerThreads(String),
    ThreadSlide(u16),
    ThreadCommit,
    PerHost(String),
    Retries(String),
    SaveDefaults,
    ResetDefaults,
    ToggleNetwork,
    Rate(String),
    Source(String),
    Services(bool),
    IcmpDiscovery(bool),
    ResolveNames(bool),
    LocalNames(bool),
    Onvif(bool),
    Sadp(bool),
    Dahua(bool),
    DnsSd(bool),
    Ssdp(bool),
    DeviceKind(Option<DeviceKind>),
    SmbShares(bool),
    OnlyResponding(bool),
    Advanced,
    Start,
    Pause,
    Stop,
    BlockPause(usize),
    BlockStop(usize),
    Select(IpAddr),
    CloseDetail,
    ToggleScanControls,
    InfoTab(InspectorTab),
    ExpandDiscovery(String),
    DetailAllPorts(bool),
    ExpandPort(u16),
    Copy(String),
    OnlyOpen(bool),
    Subnet(Option<usize>),
    SortOpen(bool),
    Scrolled(f32),
    Export(bool),
    Import,
    Language(Language),
    Light(bool),
    ClearError,
    Activity,
    ClearLog,
    Load(String),
    Delete(String),
    CompareSelect(String),
    CloseComparison,
    QueueCurrent,
    QueueProfile(usize),
    RunQueue,
    PauseQueue,
    RemoveQueued(usize),
    NotifyFinished(bool),
    ClearNotice,
    ProfileName(String),
    SaveProfile,
    ApplyProfile(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KindChoice {
    kind: Option<DeviceKind>,
    label: String,
}
impl std::fmt::Display for KindChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.label)
    }
}

pub struct App {
    locale: Locale,
    light: bool,
    page: Page,
    width: f32,
    window_maximized: bool,
    #[cfg(target_os = "macos")]
    resizing: Option<iced::window::Direction>,
    closing: bool,
    shutdown_requested: bool,
    shutdown_complete: bool,
    tx: mpsc::Sender<Command>,
    rx: mpsc::Receiver<Event>,
    ready: bool,
    data_path: PathBuf,
    vendor_count: usize,
    interfaces: Vec<portspecter_platform::InterfaceInfo>,
    targets: text_editor::Content,
    ports: String,
    method: ScanMethod,
    known_ports: bool,
    extended_ports: bool,
    exclusions: String,
    timeout: String,
    concurrency: String,
    worker_threads: String,
    logical_cpus: usize,
    per_host: String,
    retries: String,
    settings_network_open: bool,
    defaults_saved: bool,
    compare_base: Option<String>,
    comparison: Option<Comparison>,
    queue: VecDeque<SavedProfile>,
    queue_current: Option<SavedProfile>,
    queue_running: bool,
    notify_finished: bool,
    request_attention: bool,
    notice: Option<String>,
    rate: String,
    source: String,
    services: bool,
    icmp_discovery: bool,
    resolve_names: bool,
    local_names: bool,
    onvif_discovery: bool,
    sadp_discovery: bool,
    dahua_discovery: bool,
    dnssd_discovery: bool,
    ssdp_discovery: bool,
    smb_shares: bool,
    only_responding: bool,
    advanced: bool,
    preparing: bool,
    control: Option<ScanControl>,
    session: Option<ScanSession>,
    host_indices: HashMap<IpAddr, usize>,
    routes: HashMap<IpAddr, portspecter_platform::RouteInfo>,
    search: String,
    only_open: bool,
    subnet: Option<usize>,
    device_kind: Option<DeviceKind>,
    sort_open: bool,
    selected: Option<IpAddr>,
    scan_controls_expanded: bool,
    info_tab: InspectorTab,
    expanded_discovery: Option<String>,
    detail_all_ports: bool,
    expanded_port: Option<u16>,
    detail_open: bool,
    scroll_y: f32,
    history: Vec<SessionSummary>,
    profiles: Vec<SavedProfile>,
    profile_name: String,
    delete_confirm: Option<String>,
    error: Option<String>,
    logs: VecDeque<String>,
    activity: bool,
    capture_path: Option<PathBuf>,
    capture_ticks: u8,
}

impl App {
    pub fn new() -> Self {
        let (tx, rx) = backend::launch();
        Self::with_backend(tx, rx)
    }
    fn with_backend(tx: mpsc::Sender<Command>, rx: mpsc::Receiver<Event>) -> Self {
        Self {
            locale: Locale::new(Language::system()),
            light: false,
            page: if std::env::args().any(|arg| arg == "--settings") {
                Page::Settings
            } else {
                Page::Scan
            },
            width: 1440.,
            window_maximized: false,
            #[cfg(target_os = "macos")]
            resizing: None,
            closing: false,
            shutdown_requested: false,
            shutdown_complete: false,
            tx,
            rx,
            ready: false,
            data_path: PathBuf::new(),
            vendor_count: 0,
            interfaces: Vec::new(),
            targets: text_editor::Content::with_text("127.0.0.1 | Localhost"),
            ports: String::new(),
            method: ScanMethod::default(),
            known_ports: true,
            extended_ports: false,
            exclusions: String::new(),
            timeout: "1500".into(),
            concurrency: "256".into(),
            worker_threads: default_worker_threads().to_string(),
            logical_cpus: std::thread::available_parallelism().map_or(4, usize::from),
            per_host: "8".into(),
            retries: "1".into(),
            settings_network_open: false,
            defaults_saved: false,
            compare_base: None,
            comparison: None,
            queue: VecDeque::new(),
            queue_current: None,
            queue_running: false,
            notify_finished: true,
            request_attention: false,
            notice: None,
            rate: "200".into(),
            source: String::new(),
            services: true,
            icmp_discovery: true,
            resolve_names: true,
            local_names: true,
            onvif_discovery: false,
            sadp_discovery: false,
            dahua_discovery: false,
            dnssd_discovery: false,
            ssdp_discovery: false,
            smb_shares: true,
            only_responding: false,
            advanced: false,
            preparing: false,
            control: None,
            session: None,
            host_indices: HashMap::new(),
            routes: HashMap::new(),
            search: String::new(),
            only_open: true,
            subnet: None,
            device_kind: None,
            sort_open: false,
            selected: None,
            scan_controls_expanded: true,
            info_tab: InspectorTab::Overview,
            expanded_discovery: None,
            detail_all_ports: false,
            expanded_port: None,
            detail_open: false,
            scroll_y: 0.,
            history: Vec::new(),
            profiles: Vec::new(),
            profile_name: String::new(),
            delete_confirm: None,
            error: None,
            logs: VecDeque::new(),
            activity: false,
            capture_path: std::env::args()
                .skip_while(|a| a != "--capture")
                .nth(1)
                .map(PathBuf::from),
            capture_ticks: 0,
        }
    }
    fn t(&self, key: &str) -> String {
        self.locale.text(key)
    }
    fn active(&self) -> bool {
        self.control.is_some()
    }
    fn begin_shutdown(&mut self) {
        if !self.shutdown_requested {
            self.shutdown_requested = true;
            if !self.ready || self.tx.try_send(Command::Shutdown).is_err() {
                self.shutdown_complete = true;
            }
        }
    }
    fn save_queue(&mut self) {
        self.send(Command::SaveQueue(
            self.queue_current
                .iter()
                .chain(self.queue.iter())
                .cloned()
                .collect(),
        ));
    }
    fn enqueue(&mut self, profile: SavedProfile) {
        if self.queue.len() + usize::from(self.queue_current.is_some()) >= 100 {
            self.error = Some(self.t("queue-limit"));
            return;
        }
        self.queue.push_back(profile);
        self.save_queue();
        self.notice = Some(self.t("queue-added"));
    }
    fn queue_failed(&mut self) {
        self.queue_running = false;
        if let Some(profile) = self.queue_current.take() {
            self.queue.push_front(profile);
            self.save_queue();
        }
    }
    fn queued_start(&mut self) {
        let Some(profile) = self.queue.pop_front() else {
            self.queue_running = false;
            return;
        };
        self.queue_current = Some(profile.clone());
        self.save_queue();
        self.targets = text_editor::Content::with_text(&profile.targets);
        self.apply_profile_ports(&profile);
        self.exclusions = profile.exclusions.clone();
        self.worker_threads = profile.settings.worker_threads.to_string();
        self.timeout = profile.settings.timeout_ms.to_string();
        self.concurrency = profile.settings.concurrency.to_string();
        self.per_host = profile.settings.per_host.to_string();
        self.rate = profile.settings.rate_per_second.to_string();
        self.retries = profile.settings.retries.to_string();
        self.services = profile.settings.inspect_services;
        self.icmp_discovery = profile.settings.icmp_discovery;
        self.resolve_names = profile.settings.resolve_names;
        self.local_names = profile.settings.local_names;
        self.onvif_discovery = profile.settings.onvif_discovery;
        self.sadp_discovery = profile.settings.sadp_discovery;
        self.dahua_discovery = profile.settings.dahua_discovery;
        self.dnssd_discovery = profile.settings.dnssd_discovery;
        self.ssdp_discovery = profile.settings.ssdp_discovery;
        self.smb_shares = profile.settings.smb_shares;
        self.method = profile.settings.method;
        self.source = profile
            .settings
            .source_ip
            .map(|ip| ip.to_string())
            .unwrap_or_default();
        let _ = self.update(Message::Start);
        if !self.preparing {
            self.queue_failed();
        }
    }
    fn apply_profile_ports(&mut self, profile: &SavedProfile) {
        self.method = profile.settings.method;
        let (basic, extended) = self.preset_ports();
        let preset = profile.ports == basic || profile.ports == extended;
        self.known_ports = profile.known_ports.unwrap_or(preset) && preset;
        self.extended_ports = self.known_ports && profile.ports == extended;
        self.ports = if self.known_ports {
            String::new()
        } else {
            profile.ports.clone()
        };
    }
    fn preset_ports(&self) -> (&'static str, &'static str) {
        if self.method == ScanMethod::Udp {
            (DEFAULT_UDP_PORTS, EXTENDED_UDP_PORTS)
        } else {
            (DEFAULT_PORTS, EXTENDED_PORTS)
        }
    }
    fn selected_ports(&self) -> &str {
        if self.known_ports && self.extended_ports {
            self.preset_ports().1
        } else if self.known_ports {
            self.preset_ports().0
        } else {
            &self.ports
        }
    }
    fn send(&mut self, command: Command) {
        let is_preparing = matches!(&command, Command::Prepare { .. });
        let is_starting = matches!(&command, Command::Start(..));
        if let Err(e) = self.tx.try_send(command) {
            if is_preparing {
                self.preparing = false;
            }
            if is_starting {
                self.control = None;
            }
            self.error = Some(format!("{}: {e}", self.t("backend-offline")));
        }
    }
    fn log(&mut self, value: String) {
        self.logs.push_front(format!(
            "{}  {value}",
            chrono::Local::now().format("%H:%M:%S")
        ));
        self.logs.truncate(100);
    }
    fn settings(&self) -> anyhow::Result<ScanSettings> {
        let result = ScanSettings {
            method: self.method,
            worker_threads: self.worker_threads.trim().parse()?,
            per_host: self.per_host.trim().parse()?,
            retries: self.retries.trim().parse()?,
            timeout_ms: self.timeout.trim().parse()?,
            concurrency: self.concurrency.trim().parse()?,
            rate_per_second: self.rate.trim().parse()?,
            source_ip: if self.source.trim().is_empty() {
                None
            } else {
                Some(self.source.trim().parse()?)
            },
            inspect_services: self.services,
            icmp_discovery: self.icmp_discovery,
            resolve_names: self.resolve_names,
            local_names: self.local_names,
            onvif_discovery: self.onvif_discovery,
            sadp_discovery: self.sadp_discovery,
            dahua_discovery: self.dahua_discovery,
            dnssd_discovery: self.dnssd_discovery,
            ssdp_discovery: self.ssdp_discovery,
            smb_shares: self.smb_shares,
        };
        result.validate()?;
        Ok(result)
    }
    fn set_session(&mut self, session: ScanSession) {
        self.routes.clear();
        self.host_indices = session
            .hosts
            .iter()
            .enumerate()
            .map(|(i, h)| (h.ip, i))
            .collect();
        self.session = Some(session);
        self.scan_controls_expanded = false;
        self.selected = None;
        self.detail_open = false;
        self.subnet = None;
        self.device_kind = None;
        self.scroll_y = 0.;
        self.page = Page::Scan;
    }
    fn handle(&mut self, event: Event) {
        match event {
            Event::Route {
                session_id,
                ip,
                result,
            } => {
                if self.session.as_ref().is_some_and(|s| s.id == session_id) {
                    match result {
                        Ok(route) => {
                            self.routes.insert(ip, route);
                        }
                        Err(error) => self.log(format!("{}: {error}", self.t("route-current"))),
                    }
                }
            }
            Event::Ready {
                path,
                vendors,
                interfaces,
                history,
                profiles,
                language,
                light,
                worker_threads,
                scan_defaults,
                queue,
                notify_finished,
            } => {
                self.ready = true;
                self.queue = queue.into();
                self.notify_finished = notify_finished;
                self.light = light;
                self.worker_threads = worker_threads.to_string();
                if let Some(settings) = scan_defaults {
                    self.timeout = settings.timeout_ms.to_string();
                    self.concurrency = settings.concurrency.to_string();
                    self.rate = settings.rate_per_second.to_string();
                    self.per_host = settings.per_host.to_string();
                    self.retries = settings.retries.to_string();
                    self.services = settings.inspect_services;
                    self.icmp_discovery = settings.icmp_discovery;
                    self.resolve_names = settings.resolve_names;
                    self.local_names = settings.local_names;
                    self.onvif_discovery = settings.onvif_discovery;
                    self.sadp_discovery = settings.sadp_discovery;
                    self.dahua_discovery = settings.dahua_discovery;
                    self.dnssd_discovery = settings.dnssd_discovery;
                    self.ssdp_discovery = settings.ssdp_discovery;
                    self.smb_shares = settings.smb_shares;
                    self.method = settings.method;
                    self.source = settings
                        .source_ip
                        .map(|ip| ip.to_string())
                        .unwrap_or_default();
                }
                self.data_path = path;
                self.vendor_count = vendors;
                self.interfaces = interfaces;
                self.history = history;
                self.profiles = profiles;
                if let Some(language) = language {
                    self.locale = Locale::new(if language == "tr" {
                        Language::Turkish
                    } else {
                        Language::English
                    });
                }
                self.log(self.t("ready"));
                if let Some(id) = std::env::args().skip_while(|arg| arg != "--session").nth(1) {
                    self.send(Command::Load(id));
                }
            }
            Event::Plan(result) => {
                if !self.preparing {
                    return;
                }
                self.preparing = false;
                match result {
                    Ok(plan) => {
                        let control = ScanControl::new(plan.blocks.len());
                        self.control = Some(control.clone());
                        self.send(Command::Start(plan, control));
                    }
                    Err(error) => {
                        self.queue_failed();
                        self.error = Some(format!("{}: {error}", self.t("validation-error")))
                    }
                }
            }
            Event::Scan(event) => match event {
                ScanEvent::NetworkChanged => {
                    self.error = Some(self.t("network-changed"));
                    self.log(self.t("network-changed"));
                }
                ScanEvent::Started(session) => {
                    let page = self.page;
                    self.set_session(*session);
                    if self.queue_running {
                        self.page = page;
                    }
                    self.log(self.t("running"));
                }
                ScanEvent::Observations {
                    id,
                    values,
                    completed,
                } => {
                    if let Some(session) = self.session.as_mut().filter(|s| s.id == id) {
                        session.completed = completed;
                        for (ip, p) in values {
                            if let Some(index) = self.host_indices.get(&ip) {
                                let host = &mut session.hosts[*index];
                                host.completed += 1;
                                host.ports.push(p);
                            }
                        }
                    }
                }
                ScanEvent::Macs { id, values } => {
                    if let Some(session) = self.session.as_mut().filter(|s| s.id == id) {
                        for (ip, mac) in values {
                            if let Some(index) = self.host_indices.get(&ip) {
                                session.hosts[*index].mac = Some(mac);
                            }
                        }
                    }
                }
                ScanEvent::Advertisements { id, ip, values } => {
                    if let Some(session) = self.session.as_mut().filter(|s| s.id == id)
                        && let Some(index) = self.host_indices.get(&ip)
                    {
                        session.hosts[*index].advertisements = values;
                    }
                }
                ScanEvent::Cameras { id, ip, values } => {
                    if let Some(session) = self.session.as_mut().filter(|s| s.id == id)
                        && let Some(index) = self.host_indices.get(&ip)
                    {
                        session.hosts[*index].cameras = values;
                    }
                }
                ScanEvent::Shares { id, ip, value } => {
                    if let Some(session) = self.session.as_mut().filter(|s| s.id == id)
                        && let Some(index) = self.host_indices.get(&ip)
                    {
                        session.hosts[*index].shares = Some(value);
                    }
                }
                ScanEvent::Discovery { id, ip, value } => {
                    if let Some(session) = self.session.as_mut().filter(|s| s.id == id)
                        && let Some(index) = self.host_indices.get(&ip)
                    {
                        session.hosts[*index].discovery = Some(value);
                    }
                }
                ScanEvent::Name { id, ip, value } => {
                    if let Some(session) = self.session.as_mut().filter(|s| s.id == id)
                        && let Some(index) = self.host_indices.get(&ip)
                    {
                        session.hosts[*index].hostname = Some(value.name.clone());
                        session.hosts[*index].hostname_info = Some(value);
                    }
                }
                ScanEvent::Status { id, status } => {
                    if let Some(session) = self.session.as_mut().filter(|s| s.id == id) {
                        session.status = status;
                    }
                }
                ScanEvent::Finished {
                    id,
                    status,
                    completed,
                } => {
                    let successful = status == SessionStatus::Completed;
                    if let Some(session) = self.session.as_mut().filter(|s| s.id == id) {
                        session.completed = completed;
                        session.status = status;
                        session.finished_at = Some(chrono::Utc::now());
                    }
                    self.control = None;
                    self.log(self.status_label());
                    if self.notify_finished {
                        self.notice = Some(format!("{}: {}", self.t("scan"), self.status_label()));
                        self.request_attention = true;
                    }
                    if self.queue_current.take().is_some() {
                        self.save_queue();
                    }
                    if !successful {
                        self.queue_running = false;
                    }
                    self.send(Command::History);
                }
                ScanEvent::Log(value) => self.log(value),
                ScanEvent::Error(value) => {
                    self.queue_failed();
                    self.error = Some(value.clone());
                    self.log(value);
                    self.control = None;
                }
            },
            Event::History(history) => self.history = history,
            Event::Loaded(session) => {
                self.set_session(*session);
                if let Some(ip) = std::env::args()
                    .skip_while(|arg| arg != "--device")
                    .nth(1)
                    .and_then(|value| value.parse::<IpAddr>().ok())
                    && self.host_indices.contains_key(&ip)
                {
                    let _ = self.update(Message::Select(ip));
                }
            }
            Event::Imported(value) => {
                self.targets = text_editor::Content::with_text(&value);
            }
            Event::Profiles(profiles) => {
                self.profiles = profiles;
                self.log(self.t("save-profile"));
            }
            Event::Notice(value) => self.log(value),
            Event::ShutdownComplete => self.shutdown_complete = true,
            Event::Compared(result) => {
                self.comparison = Some(result);
                self.compare_base = None;
                self.page = Page::History;
            }
            Event::DefaultsSaved => {
                self.defaults_saved = true;
                self.log(self.t("defaults-saved"));
            }
            Event::Failure(value) => {
                self.queue_failed();
                self.error = Some(value.clone());
                self.log(value);
                self.preparing = false;
            }
        }
    }
    pub fn update(&mut self, message: Message) -> Task<Message> {
        if matches!(
            &message,
            Message::Timeout(_)
                | Message::Concurrency(_)
                | Message::PerHost(_)
                | Message::Retries(_)
                | Message::Rate(_)
                | Message::Source(_)
                | Message::Services(_)
                | Message::ThreadSlide(_)
                | Message::WorkerThreads(_)
                | Message::ApplyProfile(_)
        ) {
            self.defaults_saved = false;
        }
        match message {
            Message::QueueCurrent => match self.settings() {
                Ok(settings) => {
                    let profile = SavedProfile {
                        name: self.t("queue-current"),
                        targets: self.targets.text(),
                        ports: self.selected_ports().to_owned(),
                        known_ports: Some(self.known_ports),
                        exclusions: self.exclusions.clone(),
                        settings,
                    };
                    self.enqueue(profile);
                }
                Err(error) => self.error = Some(error.to_string()),
            },
            Message::QueueProfile(index) => {
                if let Some(profile) = self.profiles.get(index).cloned() {
                    self.enqueue(profile);
                }
            }
            Message::RunQueue => {
                if !self.closing {
                    self.queue_running = true;
                }
            }
            Message::PauseQueue => self.queue_running = false,
            Message::RemoveQueued(index) => {
                self.queue.remove(index);
                self.save_queue();
            }
            Message::NotifyFinished(value) => {
                self.notify_finished = value;
                self.send(Command::NotifyFinished(value));
            }
            Message::ClearNotice => self.notice = None,
            Message::CompareSelect(id) => {
                if let Some(base) = self.compare_base.take() {
                    if base != id {
                        self.send(Command::Compare(base, id));
                    }
                } else {
                    self.compare_base = Some(id);
                    self.comparison = None;
                }
            }
            Message::CloseComparison => {
                self.comparison = None;
                self.compare_base = None;
            }
            Message::WindowDrag => return iced::window::oldest().and_then(iced::window::drag),
            #[cfg(windows)]
            Message::WindowOpened(id) => {
                return iced::window::run(id, crate::windows_icon::set_taskbar_icon).discard();
            }
            Message::WindowMinimize => {
                return iced::window::oldest().and_then(|id| iced::window::minimize(id, true));
            }
            Message::WindowMaximize => {
                return iced::window::oldest().and_then(|id| {
                    iced::window::toggle_maximize(id)
                        .chain(iced::window::is_maximized(id).map(Message::WindowMaximized))
                });
            }
            Message::WindowMaximized(value) => self.window_maximized = value,
            Message::WindowResize(direction) => {
                #[cfg(target_os = "macos")]
                {
                    self.resizing = Some(direction);
                }
                #[cfg(not(target_os = "macos"))]
                return iced::window::oldest()
                    .and_then(move |id| iced::window::drag_resize(id, direction));
            }
            #[cfg(target_os = "macos")]
            Message::WindowPointer(event) => match event {
                iced::mouse::Event::ButtonReleased(iced::mouse::Button::Left)
                | iced::mouse::Event::CursorLeft => self.resizing = None,
                iced::mouse::Event::CursorMoved { position } => {
                    if let Some(direction) = self.resizing {
                        // Winit does not implement drag_resize_window on macOS.
                        // Keep the origin fixed and resize from the right/bottom grips.
                        return iced::window::oldest().and_then(move |id| {
                            iced::window::size(id).then(move |mut size| {
                                use iced::window::Direction;
                                if matches!(direction, Direction::East | Direction::SouthEast) {
                                    size.width = (position.x + 2.).max(1024.);
                                }
                                if matches!(direction, Direction::South | Direction::SouthEast) {
                                    size.height = (position.y + 2.).max(700.);
                                }
                                iced::window::resize(id, size)
                            })
                        });
                    }
                }
                _ => {}
            },
            Message::WindowClose => {
                self.closing = true;
                self.preparing = false;
                self.queue_running = false;
                if let Some(control) = &self.control {
                    control.cancel.cancel();
                } else {
                    self.begin_shutdown();
                }
            }
            Message::Keyboard(iced::keyboard::Event::KeyPressed {
                key: iced::keyboard::Key::Named(key),
                ..
            }) => {
                use iced::keyboard::key::Named;
                match key {
                    Named::F5 => return self.update(Message::Start),
                    Named::F8 => return self.update(Message::Pause),
                    Named::F9 => return self.update(Message::Stop),
                    Named::F12 => {
                        self.capture_path =
                            Some(PathBuf::from("artifacts/portspecter-current.png"));
                        return iced::window::oldest()
                            .and_then(iced::window::screenshot)
                            .map(Message::Screenshot);
                    }
                    _ => {}
                }
            }
            Message::Keyboard(_) => {}
            Message::Tick => {
                for _ in 0..256 {
                    match self.rx.try_recv() {
                        Ok(event) => self.handle(event),
                        Err(_) => break,
                    }
                }
                if self.closing && self.control.is_none() {
                    self.begin_shutdown();
                    if self.shutdown_complete {
                        return iced::window::oldest().and_then(iced::window::close);
                    }
                }
                if self.ready
                    && self.queue_running
                    && !self.active()
                    && !self.preparing
                    && !self.closing
                {
                    self.queued_start();
                }
                if self.request_attention && !self.closing {
                    self.request_attention = false;
                    return iced::window::oldest().and_then(|id| {
                        iced::window::request_user_attention(
                            id,
                            Some(iced::window::UserAttention::Informational),
                        )
                    });
                }
                if self.ready && self.capture_path.is_some() {
                    self.capture_ticks = self.capture_ticks.saturating_add(1);
                    if self.capture_ticks == 10 {
                        return iced::window::oldest()
                            .and_then(iced::window::screenshot)
                            .map(Message::Screenshot);
                    }
                }
            }
            Message::Screenshot(screenshot) => {
                if let Some(path) = self.capture_path.take() {
                    if let Some(parent) = path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    if let Err(error) = image::save_buffer(
                        &path,
                        &screenshot.rgba,
                        screenshot.size.width,
                        screenshot.size.height,
                        image::ColorType::Rgba8,
                    ) {
                        self.error = Some(error.to_string());
                    }
                }
            }
            Message::Resize(size) => {
                self.width = size.width;
                return iced::window::oldest()
                    .and_then(iced::window::is_maximized)
                    .map(Message::WindowMaximized);
            }
            Message::Page(page) => {
                self.page = page;
                if page == Page::History {
                    self.send(Command::History);
                }
            }
            Message::Target(action) => {
                if !self.active() && !self.preparing {
                    self.targets.perform(action);
                }
            }
            Message::Ports(v) => {
                if !self.active() && !self.preparing && !self.known_ports {
                    self.ports = v;
                }
            }
            Message::Method(method) => {
                if !self.active() && !self.preparing {
                    self.method = method;
                }
            }
            Message::ExtendedPorts(value) => {
                if !self.active() && !self.preparing && self.known_ports {
                    self.extended_ports = value;
                }
            }
            Message::KnownPorts(value) => {
                if !self.active() && !self.preparing {
                    self.known_ports = value;
                }
            }
            Message::Exclusions(v) => {
                if !self.active() {
                    self.exclusions = v;
                }
            }
            Message::AddSubnet(subnet) => {
                if !self.active() && !self.preparing {
                    let existing = self.targets.text();
                    let duplicate = existing.lines().any(|line| {
                        line.split('|')
                            .next()
                            .is_some_and(|target| target.trim() == subnet)
                    });
                    if !duplicate {
                        self.targets = text_editor::Content::with_text(&format!(
                            "{}{}{}",
                            existing.trim_end(),
                            if existing.trim().is_empty() { "" } else { "\n" },
                            subnet
                        ));
                    }
                }
            }
            Message::ResetFilters => {
                self.search.clear();
                self.subnet = None;
                self.device_kind = None;
                self.only_open = false;
                self.only_responding = false;
                self.scroll_y = 0.;
            }
            Message::Search(v) => {
                self.search = v;
                self.scroll_y = 0.;
            }
            Message::Timeout(v) => {
                self.timeout = v;
            }
            Message::Concurrency(v) => {
                self.concurrency = v;
            }
            Message::ToggleNetwork => self.settings_network_open = !self.settings_network_open,
            Message::PerHost(value) => self.per_host = value,
            Message::Retries(value) => self.retries = value,
            Message::SaveDefaults => match self.settings() {
                Ok(settings) => self.send(Command::ScanDefaults(settings)),
                Err(error) => self.error = Some(format!("{}: {error}", self.t("validation-error"))),
            },
            Message::ResetDefaults => {
                self.defaults_saved = false;
                let settings = ScanSettings::default();
                self.worker_threads = settings.worker_threads.to_string();
                self.timeout = settings.timeout_ms.to_string();
                self.concurrency = settings.concurrency.to_string();
                self.rate = settings.rate_per_second.to_string();
                self.per_host = settings.per_host.to_string();
                self.retries = settings.retries.to_string();
                self.services = settings.inspect_services;
                self.icmp_discovery = settings.icmp_discovery;
                self.resolve_names = settings.resolve_names;
                self.local_names = settings.local_names;
                self.onvif_discovery = settings.onvif_discovery;
                self.sadp_discovery = settings.sadp_discovery;
                self.dahua_discovery = settings.dahua_discovery;
                self.dnssd_discovery = settings.dnssd_discovery;
                self.ssdp_discovery = settings.ssdp_discovery;
                self.smb_shares = settings.smb_shares;
                self.method = settings.method;
                self.source.clear();
            }
            Message::ThreadSlide(value) => self.worker_threads = value.clamp(1, 256).to_string(),
            Message::ThreadCommit => {
                if let Ok(count) = self.worker_threads.parse::<usize>() {
                    self.send(Command::WorkerThreads(count));
                }
            }
            Message::WorkerThreads(value) => {
                if let Ok(count) = value.trim().parse::<usize>()
                    && (1..=256).contains(&count)
                {
                    self.send(Command::WorkerThreads(count));
                }
                self.worker_threads = value;
            }
            Message::Rate(v) => {
                self.rate = v;
            }
            Message::Source(v) => {
                self.source = v;
            }
            Message::IcmpDiscovery(v) => self.icmp_discovery = v,
            Message::ResolveNames(v) => self.resolve_names = v,
            Message::LocalNames(v) => self.local_names = v,
            Message::Onvif(v) => self.onvif_discovery = v,
            Message::Sadp(v) => self.sadp_discovery = v,
            Message::Dahua(v) => self.dahua_discovery = v,
            Message::DnsSd(v) => self.dnssd_discovery = v,
            Message::Ssdp(v) => self.ssdp_discovery = v,
            Message::DeviceKind(v) => {
                self.device_kind = v;
                self.scroll_y = 0.;
            }
            Message::SmbShares(v) => self.smb_shares = v,
            Message::OnlyResponding(v) => {
                self.only_responding = v;
                if v {
                    self.only_open = false;
                }
                self.scroll_y = 0.;
            }
            Message::Services(v) => {
                self.services = v;
            }
            Message::Advanced => self.advanced = !self.advanced,
            Message::Start => {
                if !self.closing && !self.active() && self.ready && !self.preparing {
                    match self.settings() {
                        Ok(settings) => {
                            self.error = None;
                            self.preparing = true;
                            self.send(Command::Prepare {
                                targets: self.targets.text(),
                                ports: self.selected_ports().to_owned(),
                                exclusions: self.exclusions.clone(),
                                settings,
                            });
                        }
                        Err(e) => self.error = Some(format!("{}: {e}", self.t("validation-error"))),
                    }
                }
            }
            Message::Pause => {
                if let Some(control) = &self.control {
                    control.pause(!control.is_paused());
                }
            }
            Message::Stop => {
                if let Some(control) = &self.control {
                    control.cancel.cancel();
                }
            }
            Message::BlockPause(index) => {
                if let Some(control) = &self.control
                    && control.block_state(index) != 2
                {
                    control.pause_block(index, control.block_state(index) == 0);
                }
            }
            Message::BlockStop(index) => {
                if let Some(control) = &self.control {
                    control.cancel_block(index);
                    self.log(self.t("subnet-cancelled"));
                }
            }
            Message::DetailAllPorts(value) => self.detail_all_ports = value,
            Message::ExpandPort(port) => {
                self.expanded_port = if self.expanded_port == Some(port) {
                    None
                } else {
                    Some(port)
                }
            }
            Message::Select(ip) => {
                if self.selected != Some(ip) {
                    self.info_tab = InspectorTab::Overview;
                    self.expanded_discovery = None;
                    self.detail_all_ports = false;
                    self.expanded_port = None;
                }
                self.selected = Some(ip);
                self.detail_open = true;
                if let Some(session) = &self.session {
                    self.send(Command::InspectRoute {
                        session_id: session.id,
                        ip,
                        source: session.plan.settings.source_ip,
                    });
                }
                return iced::widget::operation::snap_to(
                    "device-detail",
                    scrollable::RelativeOffset::START,
                );
            }
            Message::CloseDetail => self.detail_open = false,
            Message::ToggleScanControls => {
                self.scan_controls_expanded = !self.scan_controls_expanded;
            }
            Message::InfoTab(value) => {
                self.info_tab = value;
                return iced::widget::operation::snap_to(
                    "device-detail",
                    scrollable::RelativeOffset::START,
                );
            }
            Message::ExpandDiscovery(key) => {
                self.expanded_discovery = if self.expanded_discovery.as_ref() == Some(&key) {
                    None
                } else {
                    Some(key)
                };
            }
            Message::Copy(value) => return iced::clipboard::write(value),
            Message::OnlyOpen(value) => {
                self.only_open = value;
                self.scroll_y = 0.;
            }
            Message::Subnet(value) => {
                self.subnet = value;
                self.scroll_y = 0.;
            }
            Message::SortOpen(value) => {
                self.sort_open = value;
                self.scroll_y = 0.;
            }
            Message::Scrolled(y) => self.scroll_y = y,
            Message::Export(json) => {
                if let Some(session) = &self.session {
                    self.send(Command::Export {
                        id: session.id.to_string(),
                        json,
                    });
                }
            }
            Message::Import => {
                if !self.active() && !self.preparing {
                    self.send(Command::Import);
                }
            }
            Message::Language(language) => {
                self.locale = Locale::new(language);
                self.send(Command::Language(language.code().into()));
            }
            Message::Light(value) => {
                self.light = value;
                self.send(Command::Theme(value));
            }
            Message::ClearError => self.error = None,
            Message::Activity => self.activity = !self.activity,
            Message::ClearLog => self.logs.clear(),
            Message::Load(id) => {
                if !self.active() {
                    self.send(Command::Load(id));
                }
            }
            Message::Delete(id) => {
                if !self.active() {
                    if self.delete_confirm.as_ref() == Some(&id) {
                        self.delete_confirm = None;
                        self.send(Command::Delete(id));
                    } else {
                        self.delete_confirm = Some(id);
                    }
                }
            }
            Message::ProfileName(value) => self.profile_name = value,
            Message::SaveProfile => {
                if !self.profile_name.trim().is_empty() {
                    match self.settings() {
                        Ok(settings) => self.send(Command::SaveProfile(SavedProfile {
                            name: self.profile_name.trim().into(),
                            targets: self.targets.text(),
                            ports: self.selected_ports().to_owned(),
                            known_ports: Some(self.known_ports),
                            exclusions: self.exclusions.clone(),
                            settings,
                        })),
                        Err(e) => self.error = Some(e.to_string()),
                    }
                }
            }
            Message::ApplyProfile(index) => {
                if !self.active()
                    && !self.preparing
                    && let Some(profile) = self.profiles.get(index).cloned()
                {
                    self.targets = text_editor::Content::with_text(&profile.targets);
                    self.apply_profile_ports(&profile);
                    self.exclusions = profile.exclusions;
                    self.timeout = profile.settings.timeout_ms.to_string();
                    self.concurrency = profile.settings.concurrency.to_string();
                    self.worker_threads = profile.settings.worker_threads.to_string();
                    self.per_host = profile.settings.per_host.to_string();
                    self.retries = profile.settings.retries.to_string();
                    self.rate = profile.settings.rate_per_second.to_string();
                    self.source = profile
                        .settings
                        .source_ip
                        .map(|i| i.to_string())
                        .unwrap_or_default();
                    self.services = profile.settings.inspect_services;
                    self.icmp_discovery = profile.settings.icmp_discovery;
                    self.resolve_names = profile.settings.resolve_names;
                    self.local_names = profile.settings.local_names;
                    self.onvif_discovery = profile.settings.onvif_discovery;
                    self.sadp_discovery = profile.settings.sadp_discovery;
                    self.dahua_discovery = profile.settings.dahua_discovery;
                    self.dnssd_discovery = profile.settings.dnssd_discovery;
                    self.ssdp_discovery = profile.settings.ssdp_discovery;
                    self.smb_shares = profile.settings.smb_shares;
                    self.method = profile.settings.method;
                    self.page = Page::Scan;
                }
            }
        }
        Task::none()
    }
    pub fn subscription(&self) -> Subscription<Message> {
        Subscription::batch([
            #[cfg(windows)]
            iced::window::open_events().map(Message::WindowOpened),
            iced::window::close_requests().map(|_| Message::WindowClose),
            iced::time::every(Duration::from_millis(100)).map(|_| Message::Tick),
            iced::window::resize_events().map(|(_, size)| Message::Resize(size)),
            iced::event::listen_with(|event, _, _| match event {
                iced::Event::Keyboard(key) => Some(Message::Keyboard(key)),
                #[cfg(target_os = "macos")]
                iced::Event::Mouse(event) => Some(Message::WindowPointer(event)),
                _ => None,
            }),
        ])
    }
    pub fn theme(&self) -> Theme {
        style::theme(self.light)
    }
    fn status_label(&self) -> String {
        self.t(match self.session.as_ref().map(|s| &s.status) {
            Some(SessionStatus::Running) => "running",
            Some(SessionStatus::Pausing) => "pausing",
            Some(SessionStatus::Paused) => "paused",
            Some(SessionStatus::Completed) => "completed",
            Some(SessionStatus::Cancelled) => "cancelled",
            Some(SessionStatus::Failed) => "failed",
            Some(SessionStatus::Interrupted) => "interrupted",
            None => {
                if self.ready {
                    "ready"
                } else {
                    "db-loading"
                }
            }
        })
    }
    fn label(&self, key: &str) -> widget::Text<'static> {
        text(self.t(key)).size(11).color(if self.light {
            Color::from_rgb8(80, 95, 105)
        } else {
            style::MUTED
        })
    }
    fn action<'a>(&self, key: &str, message: Message) -> widget::Button<'a, Message> {
        button(text(self.t(key)).size(12))
            .on_press(message)
            .padding([8, 12])
            .style(style::secondary)
    }
    pub fn view(&self) -> Element<'_, Message> {
        let sidebar = self.sidebar();
        let content: Element<_> = match self.page {
            Page::Scan | Page::Devices => self.scan_page(),
            Page::History => self.history_page(),
            Page::Profiles => self.profiles_page(),
            Page::Settings => self.settings_page(),
            Page::Queue => self.queue_page(),
        };
        let mut body = column![content].spacing(8).height(Length::Fill);
        if let Some(error) = &self.error {
            body = body.push(
                container(
                    row![
                        text(error).size(12).color(style::RED).width(Length::Fill),
                        self.action("clear", Message::ClearError)
                    ]
                    .spacing(12)
                    .align_y(Alignment::Center),
                )
                .padding(12)
                .style(style::subtle),
            );
        }
        if let Some(notice) = &self.notice {
            body = body.push(
                container(
                    row![
                        text(notice).size(12).width(Length::Fill),
                        self.action("clear", Message::ClearNotice)
                    ]
                    .align_y(Alignment::Center),
                )
                .padding(10)
                .style(style::selected),
            );
        }
        let status = row![
            text(
                self.session
                    .as_ref()
                    .map(|s| s.plan.settings.method)
                    .unwrap_or(self.method)
                    .to_string()
            )
            .size(11)
            .font(style::MONO),
            text("/ ").size(11).color(style::MUTED),
            text(self.status_label()).size(11),
            space::horizontal(),
            text("PortSpecter 0.1.0 · Community")
                .size(11)
                .color(style::MUTED)
        ]
        .spacing(8)
        .align_y(Alignment::Center);
        let workspace = container(
            row![
                sidebar,
                container(column![body, horizontal_rule(1), status].spacing(10))
                    .padding([16, 12])
                    .width(Length::Fill)
            ]
            .height(Length::Fill),
        );
        let inner = column![
            self.title_bar(),
            horizontal_rule(1),
            workspace.height(Length::Fill)
        ]
        .height(Length::Fill);
        if self.window_maximized {
            return inner.into();
        }
        use iced::window::Direction;
        let edge = |direction, width, height| {
            widget::mouse_area(space().width(width).height(height))
                .on_press(Message::WindowResize(direction))
                .interaction(match direction {
                    Direction::North | Direction::South => {
                        iced::mouse::Interaction::ResizingVertically
                    }
                    Direction::East | Direction::West => {
                        iced::mouse::Interaction::ResizingHorizontally
                    }
                    Direction::NorthWest | Direction::SouthEast => {
                        iced::mouse::Interaction::ResizingDiagonallyDown
                    }
                    _ => iced::mouse::Interaction::ResizingDiagonallyUp,
                })
        };
        #[cfg(target_os = "macos")]
        return column![
            row![
                inner,
                edge(Direction::East, Length::Fixed(6.), Length::Fill)
            ]
            .height(Length::Fill),
            row![
                edge(Direction::South, Length::Fill, Length::Fixed(6.)),
                edge(Direction::SouthEast, Length::Fixed(16.), Length::Fixed(6.))
            ]
        ]
        .height(Length::Fill)
        .into();
        #[cfg(not(target_os = "macos"))]
        column![
            row![
                edge(Direction::NorthWest, Length::Fixed(12.), Length::Fixed(2.)),
                edge(Direction::North, Length::Fill, Length::Fixed(2.)),
                edge(Direction::NorthEast, Length::Fixed(12.), Length::Fixed(2.))
            ],
            row![
                edge(Direction::West, Length::Fixed(2.), Length::Fill),
                inner,
                edge(Direction::East, Length::Fixed(2.), Length::Fill)
            ]
            .height(Length::Fill),
            row![
                edge(Direction::SouthWest, Length::Fixed(12.), Length::Fixed(2.)),
                edge(Direction::South, Length::Fill, Length::Fixed(2.)),
                edge(Direction::SouthEast, Length::Fixed(12.), Length::Fixed(2.))
            ]
        ]
        .height(Length::Fill)
        .into()
    }
    fn title_bar(&self) -> Element<'_, Message> {
        let drag = widget::mouse_area(
            container(
                row![
                    text("PortSpecter").size(12),
                    text(self.t(if self.closing {
                        "window-closing"
                    } else {
                        "local-first"
                    }))
                    .size(9)
                    .color(style::MUTED),
                ]
                .spacing(16)
                .align_y(Alignment::Center),
            )
            .padding([0, 14])
            .height(36)
            .align_y(Alignment::Center)
            .width(Length::Fill),
        )
        .on_press(Message::WindowDrag)
        .on_double_click(Message::WindowMaximize);
        let control = |glyph: &'static str, label: &str, message, close| -> Element<'_, Message> {
            widget::tooltip(
                button(text(glyph).font(style::MONO).size(17).center())
                    .width(46)
                    .height(36)
                    .padding(0)
                    .style(move |theme, status| style::window_control(theme, status, close))
                    .on_press(message),
                container(text(self.t(label)).size(12))
                    .padding(7)
                    .style(style::surface),
                widget::tooltip::Position::Bottom,
            )
            .into()
        };
        container(
            row![
                drag,
                control("−", "window-minimize", Message::WindowMinimize, false),
                control(
                    if self.window_maximized { "❐" } else { "□" },
                    if self.window_maximized {
                        "window-restore"
                    } else {
                        "window-maximize"
                    },
                    Message::WindowMaximize,
                    false
                ),
                control("×", "window-close", Message::WindowClose, true)
            ]
            .align_y(Alignment::Center),
        )
        .style(style::sidebar)
        .into()
    }
    fn sidebar(&self) -> Element<'_, Message> {
        let mut nav = column![
            text("PortSpecter").size(23),
            text("NETWORK WORKSPACE")
                .size(9)
                .font(style::MONO)
                .color(style::ACCENT),
            space::vertical().height(28),
            self.label("workspace")
        ]
        .spacing(9);
        for (page, key, mark) in [
            (Page::Scan, "scan", "◉"),
            (Page::Devices, "devices", "▦"),
            (Page::History, "history", "◷"),
            (Page::Queue, "queue", "+"),
            (Page::Profiles, "profiles", "≡"),
        ] {
            let selected = self.page == page;
            nav = nav.push(
                button(row![text(mark).width(22).size(17), text(self.t(key)).size(13)].spacing(8))
                    .on_press(Message::Page(page))
                    .width(Length::Fill)
                    .padding([10, 12])
                    .style(if selected {
                        button::primary
                    } else {
                        button::text
                    }),
            );
        }
        nav = nav.push(space::vertical().height(Length::Fill));
        if let Some(adapter) = self
            .interfaces
            .iter()
            .find(|i| i.addresses.iter().any(|a| a.is_ipv4() && !a.is_loopback()))
        {
            nav = nav
                .push(horizontal_rule(1))
                .push(text(&adapter.name).size(12))
                .push(
                    text(
                        adapter
                            .addresses
                            .iter()
                            .find(|a| a.is_ipv4())
                            .map(ToString::to_string)
                            .unwrap_or_default(),
                    )
                    .size(11)
                    .font(style::MONO)
                    .color(style::MUTED),
                );
        }
        nav = nav
            .push(self.action("settings", Message::Page(Page::Settings)))
            .push(
                text("LOCAL · OFFLINE READY")
                    .size(9)
                    .font(style::MONO)
                    .color(style::MUTED),
            );
        container(nav)
            .padding([20, 12])
            .width(190)
            .height(Length::Fill)
            .style(style::sidebar)
            .into()
    }
    fn header(&self, title: &str, subtitle: &str) -> Element<'static, Message> {
        column![
            text(self.t(title)).size(25),
            text(self.t(subtitle)).size(12).color(style::MUTED)
        ]
        .spacing(6)
        .into()
    }
    fn scan_page(&self) -> Element<'_, Message> {
        let compact = self.session.is_some() && !self.scan_controls_expanded;
        let title = if self.page == Page::Devices {
            "devices"
        } else {
            "scan"
        };
        let heading: Element<'_, Message> = if compact {
            text(self.t(title)).size(22).into()
        } else {
            self.header(title, "subtitle")
        };
        let mut page = column![heading].spacing(12).height(Length::Fill);
        if self.page == Page::Scan {
            page = page.push(if compact {
                self.compact_controls()
            } else {
                self.controls()
            });
        }
        if self.session.is_some() {
            page = page.push(self.telemetry()).push(self.scope_tabs());
        }
        page = page.push(self.workspace());
        if self.activity {
            page = page.push(self.activity_panel());
        }
        page.into()
    }
    fn compact_controls(&self) -> Element<'_, Message> {
        let session = self
            .session
            .as_ref()
            .expect("compact controls require a session");
        let targets = session
            .plan
            .blocks
            .iter()
            .map(|block| block.target.to_string())
            .collect::<Vec<_>>();
        let target = if targets.len() > 1 {
            format!("{} (+{})", targets[0], targets.len() - 1)
        } else {
            targets.first().cloned().unwrap_or_default()
        };
        let summary = column![
            text(target)
                .size(13)
                .font(style::MONO)
                .wrapping(text::Wrapping::WordOrGlyph),
            text(format!(
                "{} / {}: {}",
                session.plan.settings.method,
                self.t("ports"),
                session.plan.ports.len()
            ))
            .size(11)
            .color(style::MUTED)
        ]
        .spacing(4)
        .width(Length::Fill);
        let mut controls = row![
            summary,
            self.action(
                if self.active() {
                    "scan-show-settings"
                } else {
                    "scan-edit-settings"
                },
                Message::ToggleScanControls,
            )
        ]
        .spacing(10)
        .align_y(Alignment::Center);
        if let Some(control) = &self.control {
            controls = controls
                .push(self.action(
                    if control.is_paused() {
                        "resume"
                    } else {
                        "pause"
                    },
                    Message::Pause,
                ))
                .push(
                    button(text(self.t("stop")).size(12))
                        .on_press(Message::Stop)
                        .padding([8, 12])
                        .style(button::danger),
                );
        }
        container(controls)
            .padding([10, 16])
            .width(Length::Fill)
            .style(style::surface)
            .into()
    }
    fn controls(&self) -> Element<'_, Message> {
        let locked = self.active() || self.preparing;
        let mut target_editor = text_editor(&self.targets)
            .height(64)
            .size(13)
            .font(style::MONO);
        if !locked {
            target_editor = target_editor.on_action(Message::Target);
        }
        let mut right = column![
            self.label("scan-method"),
            pick_list(
                [ScanMethod::TcpConnect, ScanMethod::Udp, ScanMethod::TcpSyn],
                Some(self.method),
                Message::Method
            )
            .text_size(13),
            self.label("ports"),
            checkbox(self.known_ports)
                .label(self.t(if self.method == ScanMethod::Udp {
                    "known-udp-ports"
                } else {
                    "known-ports"
                }))
                .text_size(13)
                .on_toggle_maybe(if locked {
                    None
                } else {
                    Some(Message::KnownPorts)
                }),
        ]
        .spacing(8)
        .width(Length::FillPortion(2));
        if self.known_ports {
            right = right.push(
                checkbox(self.extended_ports)
                    .label(self.t(if self.method == ScanMethod::Udp {
                        "extended-udp-ports"
                    } else {
                        "extended-ports"
                    }))
                    .text_size(13)
                    .on_toggle_maybe(if locked {
                        None
                    } else {
                        Some(Message::ExtendedPorts)
                    }),
            );
            right = right.push(
                text(self.t(if self.method == ScanMethod::Udp {
                    "udp-help"
                } else if self.extended_ports {
                    "extended-ports-help"
                } else {
                    "known-ports-help"
                }))
                .size(11)
                .color(style::MUTED),
            );
        } else {
            right = right.push(
                text_input(&self.t("custom-ports-placeholder"), &self.ports)
                    .size(13)
                    .padding(10)
                    .on_input_maybe(if locked { None } else { Some(Message::Ports) }),
            );
        }
        if self.method == ScanMethod::TcpSyn {
            right = right.push(text(self.t("syn-help")).size(11).color(style::MUTED));
        }
        if self.method == ScanMethod::Udp && !self.known_ports {
            right = right.push(text(self.t("udp-help")).size(11).color(style::MUTED));
        }
        let mut actions = row![].spacing(8);
        if self.session.is_some() {
            actions =
                actions.push(self.action("scan-collapse-settings", Message::ToggleScanControls));
        }
        if let Some(control) = &self.control {
            actions = actions
                .push(self.action(
                    if control.is_paused() {
                        "resume"
                    } else {
                        "pause"
                    },
                    Message::Pause,
                ))
                .push(
                    button(text(self.t("stop")).size(12))
                        .on_press(Message::Stop)
                        .padding([8, 12])
                        .style(button::danger),
                );
        } else {
            actions = actions.push(
                button(text(self.t(if self.preparing { "starting" } else { "start" })).size(12))
                    .on_press_maybe(if self.ready && !self.preparing {
                        Some(Message::Start)
                    } else {
                        None
                    })
                    .padding([10, 14]),
            );
        }
        let networks: Vec<String> = self
            .interfaces
            .iter()
            .flat_map(|interface| interface.networks.iter())
            .filter(|network| {
                network
                    .split('/')
                    .next()
                    .and_then(|ip| ip.parse::<IpAddr>().ok())
                    .is_some_and(|ip| ip.is_ipv4() && !ip.is_loopback())
            })
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut target_tools = row![self.label("targets").width(Length::Fill)]
            .spacing(8)
            .align_y(Alignment::Center);
        if !locked && !networks.is_empty() {
            target_tools = target_tools.push(
                pick_list(networks, None::<String>, Message::AddSubnet)
                    .placeholder(self.t("add-local-subnet"))
                    .text_size(11),
            );
        }
        let footer = row![
            text(format!(
                "{} thread  /  {} {}  /  {} ms",
                self.worker_threads,
                self.rate,
                self.t("attempts-second"),
                self.timeout
            ))
            .font(style::MONO)
            .size(11)
            .color(style::MUTED)
            .width(Length::Fill),
            self.action("advanced", Message::Advanced),
            self.action("import", Message::Import)
                .on_press_maybe(if locked { None } else { Some(Message::Import) }),
            self.action("queue-add", Message::QueueCurrent),
            actions
        ]
        .spacing(10)
        .align_y(Alignment::Center);
        let mut contents = column![
            row![
                column![
                    target_tools,
                    target_editor,
                    text(self.t("targets-help")).size(10).color(style::MUTED)
                ]
                .spacing(7)
                .width(Length::FillPortion(3)),
                right
            ]
            .spacing(20)
        ]
        .spacing(14);
        if self.advanced {
            let field =
                |key: &str, value: &str, handler: fn(String) -> Message| -> Element<'_, Message> {
                    column![
                        self.label(key),
                        text_input("", value)
                            .padding(8)
                            .size(12)
                            .on_input_maybe(if locked { None } else { Some(handler) })
                    ]
                    .spacing(5)
                    .into()
                };
            contents = contents.push(horizontal_rule(1)).push(
                row![
                    field("timeout", &self.timeout, Message::Timeout),
                    field("concurrency", &self.concurrency, Message::Concurrency),
                    field("rate", &self.rate, Message::Rate),
                    column![
                        self.label("source"),
                        text_input(&self.t("auto-route"), &self.source)
                            .padding(8)
                            .size(12)
                            .on_input_maybe(if locked { None } else { Some(Message::Source) })
                    ]
                ]
                .spacing(12),
            );
            contents = contents.push(
                row![
                    column![
                        self.label("exclusions"),
                        text_input("192.168.1.1; 10.0.0.0/30", &self.exclusions)
                            .padding(8)
                            .size(12)
                            .on_input_maybe(if locked {
                                None
                            } else {
                                Some(Message::Exclusions)
                            })
                    ]
                    .spacing(5)
                    .width(Length::Fill),
                    checkbox(self.services && self.method == ScanMethod::TcpConnect)
                        .label(self.t("services"))
                        .on_toggle_maybe(if locked || self.method != ScanMethod::TcpConnect {
                            None
                        } else {
                            Some(Message::Services)
                        })
                        .text_size(12)
                ]
                .spacing(20)
                .align_y(Alignment::Center),
            );
        }
        contents = contents.push(horizontal_rule(1)).push(footer);
        container(contents).padding(16).style(style::surface).into()
    }
    fn telemetry(&self) -> Element<'_, Message> {
        let s = self.session.as_ref().expect("session");
        let responding = s.hosts.iter().filter(|h| h.open_count() > 0).count();
        let open: usize = s.hosts.iter().map(|h| h.open_count()).sum();
        let percentage = if s.total == 0 {
            0.
        } else {
            s.completed as f32 / s.total as f32
        };
        let elapsed = (s.finished_at.unwrap_or_else(chrono::Utc::now) - s.started_at)
            .num_seconds()
            .max(0);
        column![
            row![
                text(self.status_label()).size(12).color(style::ACCENT),
                text(format!(
                    "{responding} {}  ·  {open} {}",
                    self.t("active-devices"),
                    self.t("open-ports").to_lowercase()
                ))
                .size(12),
                space::horizontal(),
                text(format!(
                    "{} / {} · {:.0}% · {:02}:{:02}",
                    s.completed,
                    s.total,
                    percentage * 100.,
                    elapsed / 60,
                    elapsed % 60
                ))
                .font(style::MONO)
                .size(12)
            ]
            .spacing(14)
            .align_y(Alignment::Center),
            progress_bar(0.0..=1.0, percentage).girth(3)
        ]
        .spacing(10)
        .into()
    }
    fn scope_tabs(&self) -> Element<'_, Message> {
        let mut tabs = row![
            button(text(self.t("all-subnets")).size(11))
                .on_press(Message::Subnet(None))
                .padding([5, 9])
                .style(if self.subnet.is_none() {
                    button::primary
                } else {
                    style::secondary
                })
        ]
        .spacing(6);
        if let Some(s) = &self.session {
            for (i, block) in s.plan.blocks.iter().enumerate() {
                let complete: usize = s
                    .hosts
                    .iter()
                    .filter(|h| h.blocks.contains(&i))
                    .map(|h| h.completed)
                    .sum();
                let total: usize = s
                    .hosts
                    .iter()
                    .filter(|h| h.blocks.contains(&i))
                    .map(|h| h.total)
                    .sum();
                let vlan = block
                    .vlan_id
                    .map(|v| format!(" · V{v}"))
                    .unwrap_or_default();
                tabs = tabs.push(
                    button(text(format!("{}{vlan}  {complete}/{total}", block.name)).size(11))
                        .on_press(Message::Subnet(Some(i)))
                        .padding([5, 9])
                        .style(if self.subnet == Some(i) {
                            button::primary
                        } else {
                            style::secondary
                        }),
                );
            }
        }
        scrollable(tabs)
            .direction(scrollable::Direction::Horizontal(
                scrollable::Scrollbar::new(),
            ))
            .into()
    }
    fn workspace(&self) -> Element<'_, Message> {
        if self.session.is_none() {
            return container(
                column![
                    text(self.t("scan-ready-title")).size(21),
                    text(self.t("scan-ready-note"))
                        .size(13)
                        .color(style::MUTED)
                        .width(480),
                    container(
                        column![
                            self.label("scan-format-title"),
                            text("192.168.2.1/24     192.168.2.1-255\n10.0.20.0/24 | Office | 20")
                                .font(style::MONO)
                                .size(12),
                        ]
                        .spacing(10)
                    )
                    .padding(16)
                    .style(style::surface)
                ]
                .spacing(16)
                .align_x(Alignment::Center),
            )
            .center(Length::Fill)
            .style(style::subtle)
            .into();
        }
        if self.width < 1200. && self.detail_open && self.selected.is_some() {
            return self.inspector();
        }
        let table = self.results_table();
        if self.width >= 1200. && self.detail_open && self.selected.is_some() {
            row![container(table).width(Length::Fill), self.inspector()]
                .spacing(14)
                .height(Length::Fill)
                .into()
        } else {
            table
        }
    }
    fn filtered_hosts(&self) -> Vec<&HostObservation> {
        let Some(session) = &self.session else {
            return Vec::new();
        };
        let query = self.search.to_lowercase();
        let mut hosts: Vec<_> = session
            .hosts
            .iter()
            .filter(|h| {
                if self.only_responding && !h.responding() {
                    return false;
                }
                if self.only_open && h.open_count() == 0 {
                    return false;
                }
                if self.subnet.is_some_and(|i| !h.blocks.contains(&i)) {
                    return false;
                }
                if self
                    .device_kind
                    .is_some_and(|kind| !h.device_kinds().contains_key(&kind))
                {
                    return false;
                }
                if query.is_empty() {
                    return true;
                }
                h.ip.to_string().contains(&query)
                    || h.hostname
                        .as_ref()
                        .is_some_and(|n| n.to_lowercase().contains(&query))
                    || h.mac.as_ref().is_some_and(|m| {
                        m.address.to_lowercase().contains(&query)
                            || m.vendor
                                .as_ref()
                                .is_some_and(|v| v.to_lowercase().contains(&query))
                    })
                    || h.cameras.iter().any(|c| {
                        [
                            &c.protocol,
                            &c.endpoint_id,
                            c.name.as_deref().unwrap_or(""),
                            c.model.as_deref().unwrap_or(""),
                            c.mac.as_deref().unwrap_or(""),
                        ]
                        .iter()
                        .any(|v| v.to_lowercase().contains(&query))
                    })
                    || h.advertisements.iter().any(|ad| {
                        [
                            Some(ad.protocol.as_str()),
                            Some(ad.identity.as_str()),
                            ad.name.as_deref(),
                            ad.model.as_deref(),
                            ad.manufacturer.as_deref(),
                            ad.service_type.as_deref(),
                            ad.mac.as_deref(),
                            ad.hostname.as_deref(),
                        ]
                        .into_iter()
                        .flatten()
                        .any(|v| v.to_lowercase().contains(&query))
                    })
                    || h.shares.as_ref().is_some_and(|v| {
                        v.shares
                            .iter()
                            .any(|s| s.name.to_lowercase().contains(&query))
                    })
                    || h.ports.iter().any(|p| {
                        p.port.to_string().contains(&query)
                            || p.service
                                .as_ref()
                                .is_some_and(|s| s.name.to_lowercase().contains(&query))
                    })
            })
            .collect();
        if self.sort_open {
            hosts.sort_by_key(|h| (std::cmp::Reverse(h.open_count()), h.ip));
        } else {
            hosts.sort_by_key(|h| h.ip);
        }
        hosts
    }
    fn results_table(&self) -> Element<'_, Message> {
        let hosts = self.filtered_hosts();
        let count = hosts.len();
        let search = text_input(&self.t("search"), &self.search)
            .size(12)
            .padding(9)
            .on_input(Message::Search);
        let toolbar = row![
            search,
            self.action("export-csv", Message::Export(false)),
            self.action("export-json", Message::Export(true))
        ]
        .spacing(8)
        .align_y(Alignment::Center);
        let choices: Vec<_> = std::iter::once(None)
            .chain(DeviceKind::ALL.into_iter().map(Some))
            .map(|kind| KindChoice {
                kind,
                label: self.t(kind.map_or("kind-all", DeviceKind::key)),
            })
            .collect();
        let selected_kind = choices.iter().find(|v| v.kind == self.device_kind).cloned();
        let filters = row![
            pick_list(choices, selected_kind, |v: KindChoice| Message::DeviceKind(
                v.kind
            ))
            .text_size(11)
            .width(155),
            checkbox(self.only_responding)
                .label(self.t("only-responding"))
                .text_size(11)
                .on_toggle(Message::OnlyResponding),
            checkbox(self.only_open)
                .label(self.t("only-open"))
                .on_toggle(Message::OnlyOpen)
                .text_size(11),
            space::horizontal(),
            button(
                text(self.t(if self.sort_open {
                    "sort-ip"
                } else {
                    "sort-open"
                }))
                .size(11)
            )
            .style(button::text)
            .on_press(Message::SortOpen(!self.sort_open)),
            text(format!(
                "{count} / {}",
                self.session
                    .as_ref()
                    .map_or(0, |session| session.hosts.len())
            ))
            .size(11)
            .font(style::MONO)
        ]
        .spacing(8)
        .align_y(Alignment::Center);
        let header = row![
            self.label("device-column").width(170),
            self.label("mac").width(150),
            self.label("vendor").width(Length::Fill),
            self.label("open-ports").width(140),
            self.label("state").width(94)
        ]
        .spacing(8)
        .padding([8, 12]);
        let row_height = 46.;
        let start = ((self.scroll_y / row_height) as usize)
            .saturating_sub(3)
            .min(count.saturating_sub(1));
        let end = (start + 32).min(count);
        let mut rows = Column::new().spacing(0);
        if start > 0 {
            rows = rows.push(space::vertical().height(start as f32 * row_height));
        }
        for host in &hosts[start..end] {
            rows = rows.push(self.device_row(host));
        }
        if end < count {
            rows = rows.push(space::vertical().height((count - end) as f32 * row_height));
        }
        if hosts.is_empty() {
            rows = rows.push(
                container(
                    column![
                        text(self.t("no-results")).size(16),
                        text(self.t("no-results-hint")).size(12).color(style::MUTED),
                        button(text(self.t("show-all-results")).size(12))
                            .style(style::secondary)
                            .padding([8, 12])
                            .on_press(Message::ResetFilters)
                    ]
                    .spacing(12),
                )
                .padding(24),
            );
        }
        let body = scrollable(rows)
            .height(Length::Fill)
            .on_scroll(|v| Message::Scrolled(v.absolute_offset().y));
        let mut result = column![
            toolbar,
            filters,
            horizontal_rule(1),
            header,
            horizontal_rule(1),
            body
        ]
        .spacing(8)
        .height(Length::Fill);
        if let (Some(index), Some(control)) = (self.subnet, &self.control) {
            result = result.push(
                row![
                    self.action(
                        if control.block_state(index) == 1 {
                            "resume-subnet"
                        } else {
                            "pause-subnet"
                        },
                        Message::BlockPause(index)
                    ),
                    self.action("cancel-subnet", Message::BlockStop(index))
                ]
                .spacing(8),
            );
        }
        result = result.push(
            button(
                text(format!(
                    "{} {}",
                    if self.activity { "−" } else { "+" },
                    self.t("activity")
                ))
                .size(11),
            )
            .style(button::text)
            .on_press(Message::Activity),
        );
        container(result)
            .padding(12)
            .style(style::subtle)
            .height(Length::Fill)
            .into()
    }
    fn device_row<'a>(&'a self, host: &'a HostObservation) -> Element<'a, Message> {
        let ip = column![
            text(host.ip.to_string()).font(style::MONO).size(12),
            text({
                let name = host
                    .hostname
                    .as_deref()
                    .or_else(|| {
                        host.cameras
                            .iter()
                            .find_map(|c| c.name.as_deref().or(c.model.as_deref()))
                    })
                    .or_else(|| {
                        host.advertisements
                            .iter()
                            .find_map(|a| a.name.as_deref().or(a.model.as_deref()))
                    })
                    .unwrap_or("—");
                let short: String = name.chars().take(23).collect();
                if name.chars().count() > 23 {
                    format!("{short}…")
                } else {
                    short
                }
            })
            .size(10)
            .color(style::MUTED)
        ]
        .spacing(2)
        .width(170);
        let mac = host
            .mac
            .as_ref()
            .map(|m| m.address.clone())
            .or_else(|| host.cameras.iter().find_map(|c| c.mac.clone()))
            .or_else(|| host.advertisements.iter().find_map(|a| a.mac.clone()))
            .unwrap_or_else(|| {
                self.t(if self.routes.get(&host.ip).is_some_and(|r| !r.on_link) {
                    "mac-routed-short"
                } else {
                    "mac-missing-short"
                })
            });
        let vendor = host
            .mac
            .as_ref()
            .and_then(|m| m.vendor.as_deref())
            .or_else(|| {
                host.advertisements
                    .iter()
                    .find_map(|a| a.manufacturer.as_deref())
            })
            .unwrap_or("—");
        let status = if host.open_count() == 0
            && host
                .discovery
                .as_ref()
                .is_some_and(|r| r.state == DiscoveryState::Reachable)
        {
            "icmp-only"
        } else if host.responding() {
            "responding"
        } else if host.completed == 0 {
            "pending"
        } else if host.ports.iter().all(|p| p.state == PortState::Unreachable) {
            "unreachable"
        } else if host.ports.iter().all(|p| p.state == PortState::LocalError) {
            "local-error"
        } else {
            "no-response"
        };
        let content = row![
            ip,
            text(mac).font(style::MONO).size(11).width(150),
            column![
                text(vendor.chars().take(21).collect::<String>()).size(11),
                text(
                    host.device_kinds()
                        .keys()
                        .map(|kind| self.t(kind.key()))
                        .collect::<Vec<_>>()
                        .join(" / ")
                )
                .size(10)
                .color(style::MUTED)
            ]
            .spacing(2)
            .width(Length::Fill),
            iced::widget::tooltip(
                text({
                    let ports: Vec<_> = host
                        .ports
                        .iter()
                        .filter(|port| port.state == PortState::Open)
                        .map(|port| port.port)
                        .collect::<std::collections::BTreeSet<_>>()
                        .into_iter()
                        .collect();
                    if ports.is_empty() {
                        String::from("\u{2014}")
                    } else {
                        format!(
                            "{}{}",
                            ports
                                .iter()
                                .take(3)
                                .map(u16::to_string)
                                .collect::<Vec<_>>()
                                .join(" / "),
                            if ports.len() > 3 {
                                format!(" +{}", ports.len() - 3)
                            } else {
                                String::new()
                            }
                        )
                    }
                })
                .font(style::MONO)
                .size(11)
                .color(if host.open_count() > 0 {
                    style::ACCENT
                } else {
                    style::MUTED
                })
                .width(140),
                container(
                    text(
                        host.ports
                            .iter()
                            .filter(|port| port.state == PortState::Open)
                            .map(|port| port.port)
                            .collect::<std::collections::BTreeSet<_>>()
                            .into_iter()
                            .map(|port| port.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                    .size(12)
                )
                .padding(8)
                .style(style::surface),
                iced::widget::tooltip::Position::Top,
            ),
            text(self.t(status)).size(10).width(94)
        ]
        .spacing(8)
        .align_y(Alignment::Center);
        let selected = self.selected == Some(host.ip);
        button(
            container(content)
                .style(move |theme| {
                    if selected {
                        style::selected(theme)
                    } else {
                        container::Style::default()
                    }
                })
                .padding([5, 10])
                .height(46),
        )
        .on_press(Message::Select(host.ip))
        .padding(0)
        .width(Length::Fill)
        .style(button::text)
        .into()
    }
    fn inspector(&self) -> Element<'_, Message> {
        let host = self.selected.and_then(|ip| {
            self.session
                .as_ref()?
                .hosts
                .get(*self.host_indices.get(&ip)?)
        });
        let Some(host) = host else {
            return container(text(self.t("select-device")).size(13))
                .padding(18)
                .into();
        };
        let muted = self.theme().extended_palette().background.weak.text;
        let open = host.open_count();
        let closed = host
            .ports
            .iter()
            .filter(|port| port.state == PortState::Closed)
            .count();
        let other = host.ports.len().saturating_sub(open + closed);
        let ip = host.ip.to_string();
        let display_name = host
            .hostname
            .clone()
            .or_else(|| {
                host.cameras
                    .iter()
                    .find_map(|c| c.name.clone().or(c.model.clone()))
            })
            .or_else(|| {
                host.advertisements
                    .iter()
                    .find_map(|a| a.name.clone().or(a.model.clone()))
            });
        let mut heading = column![
            row![
                self.label("inspector").width(Length::Fill),
                button(text(self.t("close-detail")).size(11))
                    .style(button::text)
                    .on_press(Message::CloseDetail)
            ]
            .align_y(Alignment::Center),
            text(display_name.clone().unwrap_or_else(|| ip.clone()))
                .size(21)
                .wrapping(text::Wrapping::WordOrGlyph),
        ]
        .spacing(8);
        if display_name.is_some() {
            heading = heading.push(text(ip.clone()).font(style::MONO).size(13).color(muted));
        }
        heading = heading.push(
            row![
                container(text(format!("{open} {}", self.t("detail-open"))).size(12))
                    .padding([5, 8])
                    .style(style::selected),
                text(format!(
                    "{} / {} {}",
                    host.completed,
                    host.total,
                    self.t("detail-checked")
                ))
                .size(11)
                .color(muted)
            ]
            .spacing(10)
            .align_y(Alignment::Center),
        );
        let mut actions = row![self.action("copy-ip", Message::Copy(ip))].spacing(6);
        if let Some(name) = &display_name {
            actions = actions.push(self.action("copy-name", Message::Copy(name.clone())));
        }
        let mut tabs = row![].spacing(4);
        for (tab, label) in [
            (InspectorTab::Overview, "detail-overview"),
            (InspectorTab::Ports, "port-tab"),
            (InspectorTab::Discovery, "detail-discovery"),
            (InspectorTab::Shares, "detail-shares"),
        ] {
            tabs = tabs.push(
                button(text(self.t(label)).size(12))
                    .padding([9, 5])
                    .width(Length::Fill)
                    .style(if self.info_tab == tab {
                        button::primary
                    } else {
                        style::secondary
                    })
                    .on_press(Message::InfoTab(tab)),
            );
        }
        let mut body = column![].spacing(12).width(Length::Fill);
        let field = |key: &str, value: String| -> Element<'_, Message> {
            column![
                self.label(key),
                text(value).size(12).wrapping(text::Wrapping::WordOrGlyph)
            ]
            .spacing(5)
            .into()
        };
        if self.info_tab == InspectorTab::Overview {
            let kinds = host.device_kinds();
            let mut types = column![
                self.label("device-kind"),
                text(
                    kinds
                        .keys()
                        .map(|k| self.t(k.key()))
                        .collect::<Vec<_>>()
                        .join(" / ")
                )
                .size(14)
            ]
            .spacing(6);
            for evidence in kinds.values().flatten() {
                types = types.push(text(evidence.clone()).size(11).color(muted));
            }

            body = body.push(
                container(types)
                    .padding(12)
                    .width(Length::Fill)
                    .style(style::subtle),
            );
            if let Some(discovery) = &host.discovery {
                let status = match discovery.state {
                    DiscoveryState::Reachable => format!(
                        "{}{}",
                        self.t("icmp-only"),
                        discovery
                            .elapsed_ms
                            .map(|ms| format!(" / {ms} ms"))
                            .unwrap_or_default()
                    ),
                    DiscoveryState::NoReply => self.t("icmp-no-reply"),
                    DiscoveryState::Unavailable => format!(
                        "{}: {}",
                        self.t("icmp-unavailable"),
                        discovery.error.as_deref().unwrap_or("")
                    ),
                };
                body = body.push(
                    container(field("icmp-result", status))
                        .padding(12)
                        .width(Length::Fill)
                        .style(style::subtle),
                );
            }
            let mut identity = column![field(
                "hostname",
                host.hostname
                    .clone()
                    .or_else(|| host
                        .advertisements
                        .iter()
                        .find_map(|ad| ad.hostname.clone()))
                    .or_else(|| display_name.clone())
                    .unwrap_or_else(|| self.t("unknown-name"))
            )]
            .spacing(12);
            if let Some(name) = &host.hostname_info {
                identity = identity.push(field(
                    "name-source",
                    self.t(if name.source == "reverse_dns" {
                        "source-dns"
                    } else if name.source == "mdns" {
                        "source-mdns"
                    } else if name.source == "llmnr" {
                        "source-llmnr"
                    } else {
                        "source-netbios"
                    }),
                ));
            } else if host.hostname.is_none() {
                let source = host
                    .advertisements
                    .iter()
                    .find(|ad| ad.hostname.is_some())
                    .map(|ad| ad.protocol.clone())
                    .or_else(|| {
                        host.cameras
                            .iter()
                            .find(|camera| camera.name.is_some() || camera.model.is_some())
                            .map(|camera| camera.protocol.clone())
                    })
                    .or_else(|| {
                        host.advertisements
                            .iter()
                            .find(|ad| ad.name.is_some() || ad.model.is_some())
                            .map(|ad| ad.protocol.clone())
                    });
                if let Some(source) = source {
                    identity = identity.push(field("name-source", source));
                }
            }
            if let Some(mac) = &host.mac {
                identity = identity
                    .push(field("mac", mac.address.clone()))
                    .push(self.action("copy-mac", Message::Copy(mac.address.clone())));
                identity = identity.push(field(
                    "vendor",
                    if mac.locally_administered {
                        self.t("local-mac")
                    } else {
                        mac.vendor
                            .clone()
                            .unwrap_or_else(|| self.t("unknown-vendor"))
                    },
                ));
                let source = match mac.source.as_str() {
                    "local_interface" => "source-interface",
                    "netbios_node_status" => "source-netbios",
                    _ => "source-neighbor",
                };
                identity = identity
                    .push(field("mac-source", self.t(source)))
                    .push(field("interface", mac.interface.clone()))
                    .push(field("mac-state", mac.neighbor_state.clone()))
                    .push(field(
                        "observed",
                        mac.observed_at
                            .with_timezone(&chrono::Local)
                            .format("%Y-%m-%d %H:%M:%S")
                            .to_string(),
                    ));
            } else if let Some(camera) = host.cameras.iter().find(|c| c.mac.is_some()) {
                identity = identity
                    .push(field("mac", camera.mac.clone().unwrap_or_default()))
                    .push(self.action(
                        "copy-mac",
                        Message::Copy(camera.mac.clone().unwrap_or_default()),
                    ))
                    .push(field("mac-source", camera.protocol.clone()));
            } else if let Some(ad) = host.advertisements.iter().find(|a| a.mac.is_some()) {
                identity = identity
                    .push(field("mac", ad.mac.clone().unwrap_or_default()))
                    .push(self.action(
                        "copy-mac",
                        Message::Copy(ad.mac.clone().unwrap_or_default()),
                    ))
                    .push(field("mac-source", ad.protocol.clone()));
            } else {
                identity = identity
                    .push(self.label("mac"))
                    .push(text(self.t("no-mac")).size(12).color(muted));
            }
            body = body.push(
                container(identity)
                    .padding(12)
                    .width(Length::Fill)
                    .style(style::subtle),
            );
            let mut route_block = column![self.label("route-current")].spacing(10);
            if let Some(route) = self.routes.get(&host.ip) {
                route_block = route_block
                    .push(
                        text(self.t(if route.on_link {
                            "route-local"
                        } else {
                            "route-remote"
                        }))
                        .size(13),
                    )
                    .push(field("source", route.source.to_string()))
                    .push(field(
                        "next-hop",
                        route
                            .next_hop
                            .map(|ip| ip.to_string())
                            .unwrap_or_else(|| self.t("route-on-link")),
                    ))
                    .push(field("interface", route.interface.clone()));
                if !route.on_link
                    && host.mac.is_none()
                    && !host.cameras.iter().any(|c| c.mac.is_some())
                    && !host.advertisements.iter().any(|a| a.mac.is_some())
                {
                    route_block =
                        route_block.push(text(self.t("mac-routed-help")).size(11).color(muted));
                }
            } else {
                route_block =
                    route_block.push(text(self.t("route-not-loaded")).size(12).color(muted));
            }
            body = body.push(
                container(route_block)
                    .padding(12)
                    .width(Length::Fill)
                    .style(style::subtle),
            );
            if let Some(session) = &self.session {
                let mut scope = column![self.label("scope")].spacing(8);
                for index in &host.blocks {
                    if let Some(block) = session.plan.blocks.get(*index) {
                        scope = scope.push(text(block.name.clone()).size(13)).push(
                            text(format!(
                                "{}{}",
                                block.target,
                                block
                                    .vlan_id
                                    .map(|v| format!(" / VLAN {v}"))
                                    .unwrap_or_default()
                            ))
                            .font(style::MONO)
                            .size(11),
                        );
                    }
                }
                body = body.push(
                    container(scope)
                        .padding(12)
                        .width(Length::Fill)
                        .style(style::subtle),
                );
            }
        } else if self.info_tab == InspectorTab::Discovery {
            body = body.push(
                text(format!(
                    "{} {}",
                    host.advertisements.len() + host.cameras.len(),
                    self.t("detail-discovery-count")
                ))
                .size(12)
                .color(muted),
            );
            if host.advertisements.is_empty() && host.cameras.is_empty() {
                body = body.push(text(self.t("detail-discovery-empty")).size(13));
            }
            for ad in &host.advertisements {
                let key = format!("ad:{}:{}", ad.protocol, ad.identity);
                let expanded = self.expanded_discovery.as_ref() == Some(&key);
                let mut card = column![
                    button(
                        row![
                            text(ad.protocol.clone()).size(14).width(Length::Fill),
                            text(self.t(if expanded {
                                "detail-collapse"
                            } else {
                                "detail-expand"
                            }))
                            .size(11)
                        ]
                        .spacing(8)
                    )
                    .width(Length::Fill)
                    .padding(0)
                    .style(button::text)
                    .on_press(Message::ExpandDiscovery(key)),
                    text(
                        ad.name
                            .clone()
                            .or(ad.model.clone())
                            .or(ad.service_type.clone())
                            .unwrap_or_else(|| ad.identity.clone())
                    )
                    .size(12)
                    .wrapping(text::Wrapping::WordOrGlyph)
                ]
                .spacing(10);
                if expanded {
                    for (key, value) in [
                        ("hostname", ad.name.as_ref()),
                        ("vendor", ad.manufacturer.as_ref()),
                        ("device-model", ad.model.as_ref()),
                        ("device-serial", ad.serial.as_ref()),
                        ("mac", ad.mac.as_ref()),
                        ("declared-device-type", ad.device_type.as_ref()),
                        ("advertised-service", ad.service_type.as_ref()),
                        ("service-hostname", ad.hostname.as_ref()),
                    ] {
                        if let Some(value) = value {
                            card = card.push(field(key, value.clone()));
                        }
                    }
                    if let Some(port) = ad.port {
                        card = card
                            .push(field(
                                "advertised-port",
                                format!("{port}/{}", ad.transport.as_deref().unwrap_or("?")),
                            ))
                            .push(text(self.t("advertised-port-help")).size(11).color(muted));
                    }
                    for endpoint in &ad.endpoints {
                        card = card
                            .push(field("device-endpoint", endpoint.clone()))
                            .push(self.action("copy-endpoint", Message::Copy(endpoint.clone())));
                    }
                    for (key, value) in &ad.properties {
                        card = card.push(
                            text(format!("{key}: {value}"))
                                .size(11)
                                .color(muted)
                                .wrapping(text::Wrapping::WordOrGlyph),
                        );
                    }
                    card = card
                        .push(field("device-id", ad.identity.clone()))
                        .push(field("interface", ad.interface.clone()));
                }
                body = body.push(
                    container(card)
                        .padding(12)
                        .width(Length::Fill)
                        .style(style::subtle),
                );
            }
            for camera in &host.cameras {
                let key = format!("camera:{}:{}", camera.protocol, camera.endpoint_id);
                let expanded = self.expanded_discovery.as_ref() == Some(&key);
                let mut card = column![
                    button(
                        row![
                            text(camera.protocol.clone()).size(14).width(Length::Fill),
                            text(self.t(if expanded {
                                "detail-collapse"
                            } else {
                                "detail-expand"
                            }))
                            .size(11)
                        ]
                        .spacing(8)
                    )
                    .width(Length::Fill)
                    .padding(0)
                    .style(button::text)
                    .on_press(Message::ExpandDiscovery(key)),
                    text(
                        camera
                            .name
                            .clone()
                            .or(camera.model.clone())
                            .unwrap_or_else(|| self.t("camera-device"))
                    )
                    .size(12)
                    .wrapping(text::Wrapping::WordOrGlyph)
                ]
                .spacing(10);
                if expanded {
                    for (key, value) in [
                        ("hostname", camera.name.as_ref()),
                        ("device-model", camera.model.as_ref()),
                        ("device-serial", camera.serial.as_ref()),
                        ("device-firmware", camera.firmware.as_ref()),
                        ("mac", camera.mac.as_ref()),
                    ] {
                        if let Some(value) = value {
                            card = card.push(field(key, value.clone()));
                        }
                    }
                    if let Some(active) = camera.activated {
                        card = card.push(field(
                            "device-activation",
                            self.t(if active {
                                "device-activated"
                            } else {
                                "device-inactive"
                            }),
                        ));
                    }
                    for endpoint in &camera.endpoints {
                        card = card
                            .push(field("device-endpoint", endpoint.clone()))
                            .push(self.action("copy-endpoint", Message::Copy(endpoint.clone())));
                    }
                    card = card
                        .push(field("device-id", camera.endpoint_id.clone()))
                        .push(field("interface", camera.interface.clone()));
                    for scope in &camera.scopes {
                        card = card.push(field("scope", scope.clone()));
                    }
                    if camera.protocol == "ONVIF" {
                        card = card.push(text(self.t("onvif-auth-note")).size(11).color(muted));
                    }
                }
                body = body.push(
                    container(card)
                        .padding(12)
                        .width(Length::Fill)
                        .style(style::subtle),
                );
            }
        } else if self.info_tab == InspectorTab::Shares {
            let mut shares = column![text(self.t("shared-folders")).size(15)].spacing(10);
            if let Some(result) = &host.shares {
                let status = match result.status {
                    ShareStatus::Complete => {
                        if result.shares.is_empty() {
                            "shares-empty"
                        } else {
                            "shares-complete"
                        }
                    }
                    ShareStatus::AccessDenied => "shares-denied",
                    ShareStatus::Unavailable => "shares-unavailable",
                    ShareStatus::TimedOut => "shares-timeout",
                    ShareStatus::Failed => "shares-failed",
                };
                shares = shares.push(text(self.t(status)).size(12));
                for share in &result.shares {
                    let path = if cfg!(windows) {
                        format!("\\\\{}\\{}", host.ip, share.name)
                    } else {
                        format!("smb://{}/{}", host.ip, share.name)
                    };
                    let mut entry = column![
                        row![
                            text(share.name.clone()).size(13).width(Length::Fill),
                            text(self.t(if share.hidden {
                                "share-hidden"
                            } else {
                                "share-visible"
                            }))
                            .size(11)
                            .color(muted)
                        ]
                        .spacing(8),
                        text(path.clone())
                            .font(style::MONO)
                            .size(11)
                            .wrapping(text::Wrapping::WordOrGlyph)
                    ]
                    .spacing(5);
                    if !share.comment.is_empty() {
                        entry = entry.push(text(share.comment.clone()).size(11).color(muted));
                    }
                    entry = entry.push(self.action("copy-share-path", Message::Copy(path)));
                    shares = shares.push(
                        container(entry)
                            .padding(10)
                            .width(Length::Fill)
                            .style(style::subtle),
                    );
                }
                shares = shares.push(text(result.source.clone()).size(10).color(muted));
                if let Some(detail) = &result.detail {
                    shares = shares.push(text(detail.clone()).size(11).color(muted));
                }
            } else {
                shares = shares.push(text(self.t("shares-not-scanned")).size(12).color(muted));
            }
            shares = shares.push(text(self.t("shares-access-note")).size(11).color(muted));
            body = body.push(
                container(shares)
                    .padding(12)
                    .width(Length::Fill)
                    .style(style::subtle),
            );
        } else {
            body = body.push(
                row![
                    text(format!(
                        "{closed} {} / {other} {}",
                        self.t("detail-closed"),
                        self.t("detail-other")
                    ))
                    .size(11)
                    .color(muted)
                    .width(Length::Fill),
                    checkbox(self.detail_all_ports)
                        .label(self.t("all-ports"))
                        .text_size(11)
                        .on_toggle(Message::DetailAllPorts)
                ]
                .spacing(8)
                .align_y(Alignment::Center),
            );
            let mut ports: Vec<_> = host
                .ports
                .iter()
                .filter(|port| self.detail_all_ports || port.state == PortState::Open)
                .collect();
            ports.sort_by_key(|port| (port.state != PortState::Open, port.port));
            let count = ports.len();
            if ports.is_empty() {
                body = body.push(
                    container(
                        text(self.t(if host.completed == 0 {
                            "no-ports"
                        } else {
                            "no-open-ports"
                        }))
                        .size(13)
                        .color(muted),
                    )
                    .padding(12)
                    .style(style::subtle),
                );
            }
            if open > 0 {
                body = body.push(
                    self.action(
                        "copy-ports",
                        Message::Copy(
                            host.ports
                                .iter()
                                .filter(|port| port.state == PortState::Open)
                                .map(|port| port.port)
                                .collect::<std::collections::BTreeSet<_>>()
                                .into_iter()
                                .map(|port| port.to_string())
                                .collect::<Vec<_>>()
                                .join(","),
                        ),
                    ),
                );
            }
            for port in ports.into_iter().take(100) {
                let expanded = self.expanded_port == Some(port.port);
                let state = match port.state {
                    PortState::Open => "open",
                    PortState::Closed => "closed",
                    PortState::TimedOut => "timeout-state",
                    PortState::Unreachable => "unreachable",
                    PortState::LocalError => "local-error",
                    PortState::Filtered => "filtered",
                    PortState::OpenFiltered => "open-filtered",
                };
                let name = port
                    .service
                    .as_ref()
                    .map(|service| service.name.clone())
                    .filter(|name| !name.is_empty())
                    .unwrap_or_else(|| {
                        if port.state == PortState::Open
                            && self
                                .session
                                .as_ref()
                                .is_none_or(|s| s.plan.settings.method != ScanMethod::Udp)
                        {
                            portspecter_probe::port_hint(port.port).into()
                        } else {
                            String::new()
                        }
                    });
                let head = button(
                    column![
                        row![
                            text(format!(
                                "{}/{}",
                                port.port,
                                self.session
                                    .as_ref()
                                    .map(|s| s.plan.settings.method.protocol())
                                    .unwrap_or("tcp")
                            ))
                            .font(style::MONO)
                            .size(15)
                            .width(Length::Fill),
                            text(self.t(state))
                                .size(11)
                                .color(if port.state == PortState::Open {
                                    style::GREEN
                                } else {
                                    muted
                                }),
                            text(if expanded { "-" } else { "+" }).size(14)
                        ]
                        .spacing(8)
                        .align_y(Alignment::Center),
                        row![
                            text(name).size(12).width(Length::Fill),
                            text(format!("{} ms", port.elapsed_ms))
                                .font(style::MONO)
                                .size(11)
                                .color(muted)
                        ]
                    ]
                    .spacing(7),
                )
                .padding(10)
                .width(Length::Fill)
                .style(style::secondary)
                .on_press(Message::ExpandPort(port.port));
                let mut card = column![head].spacing(10);
                if expanded {
                    let mut details = column![field(
                        "observed",
                        port.observed_at
                            .with_timezone(&chrono::Local)
                            .format("%Y-%m-%d %H:%M:%S")
                            .to_string()
                    )]
                    .spacing(10);
                    if let Some(service) = &port.service {
                        if !service.evidence.is_empty() {
                            details = details.push(self.label("evidence")).push(
                                text(service.evidence.chars().take(1600).collect::<String>())
                                    .font(style::MONO)
                                    .size(11),
                            );
                        }
                        if let Some(tls) = &service.tls {
                            details =
                                details
                                    .push(horizontal_rule(1))
                                    .push(self.label("tls-certificate"))
                                    .push(field("tls-subject", tls.subject.clone()))
                                    .push(field("tls-issuer", tls.issuer.clone()))
                                    .push(field(
                                        "tls-validity",
                                        format!("{} / {}", tls.not_before, tls.not_after),
                                    ))
                                    .push(field("tls-validation", tls.validation.clone()))
                                    .push(field("tls-fingerprint", tls.sha256.clone()))
                                    .push(self.action(
                                        "copy-fingerprint",
                                        Message::Copy(tls.sha256.clone()),
                                    ));
                        }
                    }
                    if let Some(error) = &port.error {
                        details =
                            details.push(field("detail-error", error.chars().take(400).collect()));
                    }
                    card = card.push(container(details).padding(10));
                }
                body = body.push(container(card).width(Length::Fill).style(style::subtle));
            }
            if count > 100 {
                body = body.push(
                    text(format!("100 / {count} / {}", self.t("export-json")))
                        .size(11)
                        .color(muted),
                );
            }
            body = body.push(text(self.t("port-hint")).size(10).color(muted));
        }
        container(
            column![
                heading,
                actions,
                tabs,
                horizontal_rule(1),
                scrollable(
                    container(body)
                        .width(Length::Fill)
                        .padding(iced::Padding::default().right(12))
                )
                .id("device-detail")
                .height(Length::Fill)
            ]
            .spacing(12),
        )
        .padding(16)
        .width(if self.width < 1200. {
            Length::Fill
        } else {
            Length::Fixed(360.)
        })
        .height(Length::Fill)
        .style(style::surface)
        .into()
    }
    fn activity_panel(&self) -> Element<'_, Message> {
        let mut logs = column![
            row![
                self.label("activity"),
                space::horizontal(),
                self.action("clear", Message::ClearLog)
            ]
            .align_y(Alignment::Center)
        ]
        .spacing(8);
        for log in self.logs.iter().take(20) {
            logs = logs.push(text(log).size(11).font(style::MONO).color(style::MUTED));
        }
        container(scrollable(logs))
            .height(140)
            .padding(12)
            .style(style::subtle)
            .into()
    }
    fn history_page(&self) -> Element<'_, Message> {
        if let Some(comparison) = &self.comparison {
            let mut details = column![
                self.action("back-history", Message::CloseComparison),
                text(format!("{} → {}", comparison.before, comparison.after))
                    .font(style::MONO)
                    .size(12)
            ]
            .spacing(12);
            for warning in &comparison.warnings {
                details = details.push(text(self.t(warning)).size(13).color(style::AMBER));
            }
            if comparison.devices.is_empty() && comparison.ports.is_empty() {
                details = details.push(text(self.t("compare-empty")).size(16));
            }
            for change in &comparison.devices {
                details = details.push(
                    container(
                        row![
                            text(change.ip.to_string()).font(style::MONO).width(180),
                            text(self.t(&change.change))
                        ]
                        .spacing(16),
                    )
                    .padding(12)
                    .style(style::surface),
                );
            }
            for change in &comparison.ports {
                details = details.push(
                    container(
                        row![
                            text(change.ip.to_string()).font(style::MONO).width(180),
                            text(format!("{}/{}", change.port, change.protocol))
                                .font(style::MONO)
                                .width(100),
                            text(self.t(match change.change.as_str() {
                                "opened" => "port-new-open",
                                "closed" => "port-now-closed",
                                _ => "port-unobserved",
                            }))
                        ]
                        .spacing(16),
                    )
                    .padding(12)
                    .style(style::surface),
                );
            }
            return column![
                self.header("compare-title", "compare-help"),
                scrollable(details).height(Length::Fill)
            ]
            .spacing(20)
            .height(Length::Fill)
            .into();
        }
        let mut items = column![].spacing(10);
        if self.compare_base.is_some() {
            items = items.push(row![
                text(self.t("compare-second")).width(Length::Fill),
                self.action("clear", Message::CloseComparison)
            ]);
        }
        if self.history.is_empty() {
            items = items.push(text(self.t("history-empty")).size(14).color(style::MUTED));
        }
        for session in &self.history {
            let label = format!(
                "{} · {} {}",
                session.started_at.chars().take(19).collect::<String>(),
                session.hosts,
                self.t("hosts")
            );
            let mut actions = Row::new().spacing(8);
            actions = actions.push(self.action(
                if self.compare_base.as_ref() == Some(&session.id) {
                    "compare-selected"
                } else {
                    "compare-select"
                },
                Message::CompareSelect(session.id.clone()),
            ));
            actions = actions.push(
                button(text(self.t("load")).size(12))
                    .padding([8, 12])
                    .on_press_maybe(if self.active() {
                        None
                    } else {
                        Some(Message::Load(session.id.clone()))
                    }),
            );
            actions = actions.push(
                button(
                    text(
                        self.t(if self.delete_confirm.as_ref() == Some(&session.id) {
                            "delete-confirm"
                        } else {
                            "delete"
                        }),
                    )
                    .size(12),
                )
                .style(button::danger)
                .padding([8, 12])
                .on_press_maybe(if self.active() {
                    None
                } else {
                    Some(Message::Delete(session.id.clone()))
                }),
            );
            items = items.push(
                container(
                    row![
                        column![
                            text(label).size(14),
                            text(format!(
                                "{} · {}/{} · {}",
                                session.status,
                                session.completed,
                                session.total,
                                &session.id[..8]
                            ))
                            .size(11)
                            .font(style::MONO)
                            .color(style::MUTED)
                        ]
                        .spacing(6)
                        .width(Length::Fill),
                        actions
                    ]
                    .spacing(12)
                    .align_y(Alignment::Center),
                )
                .padding(16)
                .style(style::surface),
            );
        }
        column![
            self.header("history", "history-help"),
            scrollable(items).height(Length::Fill)
        ]
        .spacing(24)
        .height(Length::Fill)
        .into()
    }
    fn queue_page(&self) -> Element<'_, Message> {
        let mut items = column![
            self.header("queue", "queue-help"),
            row![
                self.action("queue-run", Message::RunQueue),
                self.action("queue-pause", Message::PauseQueue),
                text(format!("{} {}", self.queue.len(), self.t("queue-waiting")))
            ]
            .spacing(10)
        ]
        .spacing(16);
        if let Some(current) = &self.queue_current {
            items = items.push(
                container(text(format!("{}: {}", self.t("running"), current.name)).size(14))
                    .padding(14)
                    .style(style::selected),
            );
        }
        if self.queue.is_empty() {
            items = items.push(text(self.t("queue-empty")).size(14));
        }
        for (index, profile) in self.queue.iter().enumerate() {
            items = items.push(
                container(
                    row![
                        column![
                            text(format!("{}. {}", index + 1, profile.name)).size(16),
                            text(
                                profile
                                    .targets
                                    .lines()
                                    .take(2)
                                    .collect::<Vec<_>>()
                                    .join(" / ")
                            )
                            .font(style::MONO)
                            .size(12),
                            text(profile.ports.clone()).size(11)
                        ]
                        .spacing(7)
                        .width(Length::Fill),
                        self.action("queue-remove", Message::RemoveQueued(index))
                    ]
                    .spacing(12)
                    .align_y(Alignment::Center),
                )
                .padding(14)
                .style(style::surface),
            );
        }
        scrollable(items).height(Length::Fill).into()
    }
    fn profiles_page(&self) -> Element<'_, Message> {
        let mut items = column![
            self.header("profiles", "profiles-empty"),
            row![
                text_input(&self.t("profile-name"), &self.profile_name)
                    .on_input(Message::ProfileName)
                    .padding(10),
                self.action("save-profile", Message::SaveProfile)
            ]
            .spacing(10)
        ]
        .spacing(20);
        for (i, profile) in self.profiles.iter().enumerate() {
            items = items.push(
                container(
                    row![
                        column![
                            text(format!("{} / {}", profile.name, profile.settings.method))
                                .size(16),
                            text(
                                profile
                                    .targets
                                    .lines()
                                    .take(3)
                                    .collect::<Vec<_>>()
                                    .join(" · ")
                            )
                            .size(12)
                            .font(style::MONO),
                            text(
                                if profile.known_ports != Some(false)
                                    && profile.ports == EXTENDED_PORTS
                                {
                                    self.t("extended-ports")
                                } else if profile.known_ports != Some(false)
                                    && profile.ports == DEFAULT_PORTS
                                {
                                    self.t("known-ports")
                                } else {
                                    profile.ports.clone()
                                }
                            )
                            .size(11)
                            .color(style::MUTED)
                        ]
                        .spacing(8)
                        .width(Length::Fill),
                        self.action("queue-add", Message::QueueProfile(i)),
                        button(text(self.t("apply")))
                            .on_press_maybe(if self.active() {
                                None
                            } else {
                                Some(Message::ApplyProfile(i))
                            })
                            .padding([8, 12])
                    ]
                    .spacing(16)
                    .align_y(Alignment::Center),
                )
                .padding(16)
                .style(style::surface),
            );
        }
        scrollable(items).height(Length::Fill).into()
    }
    fn settings_page(&self) -> Element<'_, Message> {
        let threads = self
            .worker_threads
            .parse::<u16>()
            .unwrap_or(1)
            .clamp(1, 256);
        let cpus = self.logical_cpus;
        let muted = self.theme().extended_palette().background.weak.text;
        let mut presets = row![].spacing(8);
        for count in [cpus.clamp(1, 256), 32, 64, 128, 256]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
        {
            presets = presets.push(
                button(text(count.to_string()).font(style::MONO).size(13))
                    .padding([8, 14])
                    .style(if usize::from(threads) == count {
                        button::primary
                    } else {
                        style::secondary
                    })
                    .on_press(Message::WorkerThreads(count.to_string())),
            );
        }
        let performance = container(
            column![
                row![
                    text(self.t("settings-performance"))
                        .size(17)
                        .width(Length::Fill),
                    text(format!("{cpus} CPU"))
                        .font(style::MONO)
                        .size(11)
                        .color(muted)
                ]
                .align_y(Alignment::Center),
                row![
                    self.label("worker-threads").width(Length::Fill),
                    text(threads.to_string()).font(style::MONO).size(23)
                ]
                .align_y(Alignment::Center),
                slider(1..=256, threads, Message::ThreadSlide)
                    .step(1u16)
                    .on_release(Message::ThreadCommit),
                presets,
                text(self.t("threads-compact-note")).size(11).color(muted),
            ]
            .spacing(10),
        )
        .padding(18)
        .width(Length::Fill)
        .style(style::surface);
        let appearance = container(
            column![
                text(self.t("settings-appearance")).size(17),
                row![
                    column![
                        self.label("language"),
                        pick_list(
                            [Language::Turkish, Language::English],
                            Some(self.locale.language),
                            Message::Language
                        )
                        .width(Length::Fill)
                    ]
                    .spacing(8)
                    .width(Length::Fill),
                    column![
                        self.label("theme"),
                        row![
                            button(text(self.t("dark")).size(12))
                                .padding([9, 12])
                                .style(if !self.light {
                                    button::primary
                                } else {
                                    style::secondary
                                })
                                .on_press(Message::Light(false)),
                            button(text(self.t("light")).size(12))
                                .padding([9, 12])
                                .style(if self.light {
                                    button::primary
                                } else {
                                    style::secondary
                                })
                                .on_press(Message::Light(true))
                        ]
                        .spacing(6)
                    ]
                    .spacing(8)
                ]
                .spacing(16),
            ]
            .spacing(14),
        )
        .padding(18)
        .width(Length::Fill)
        .style(style::surface);
        let top: Element<'_, Message> = if self.width >= 1150. {
            row![
                container(performance).width(Length::FillPortion(3)),
                container(appearance).width(Length::FillPortion(2))
            ]
            .spacing(20)
            .into()
        } else {
            column![performance, appearance].spacing(20).into()
        };
        let field = |key: &str,
                     hint: &str,
                     value: &str,
                     handler: fn(String) -> Message|
         -> Element<'_, Message> {
            column![
                self.label(key),
                text_input(hint, value)
                    .on_input(handler)
                    .padding(9)
                    .size(13)
            ]
            .spacing(6)
            .width(Length::Fill)
            .into()
        };
        let controls = container(
            column![
                row![
                    text(self.t("scan-limits")).size(17).width(Length::Fill),
                    text(self.t("next-scan-only")).size(11).color(muted)
                ]
                .align_y(Alignment::Center),
                row![
                    field(
                        "concurrency",
                        "1-4096",
                        &self.concurrency,
                        Message::Concurrency
                    ),
                    field("per-host-limit", "1-64", &self.per_host, Message::PerHost),
                    field("rate", "1-10000", &self.rate, Message::Rate)
                ]
                .spacing(16),
                row![
                    field("timeout", "100-30000 ms", &self.timeout, Message::Timeout),
                    field("retry-count", "0-3", &self.retries, Message::Retries),
                    field(
                        "source",
                        &self.t("auto-route"),
                        &self.source,
                        Message::Source
                    )
                ]
                .spacing(16),
                checkbox(self.notify_finished)
                    .label(self.t("notify-finished"))
                    .on_toggle(Message::NotifyFinished),
                checkbox(self.icmp_discovery)
                    .label(self.t("icmp-discovery"))
                    .on_toggle(Message::IcmpDiscovery),
                checkbox(self.resolve_names)
                    .label(self.t("resolve-names"))
                    .on_toggle(Message::ResolveNames),
                checkbox(self.local_names)
                    .label(self.t("local-names"))
                    .on_toggle(Message::LocalNames),
                text(self.t("local-names-help")).size(11).color(muted),
                horizontal_rule(1),
                self.label("device-protocols"),
                row![
                    checkbox(self.onvif_discovery)
                        .label("ONVIF")
                        .on_toggle(Message::Onvif),
                    checkbox(self.sadp_discovery)
                        .label("Hikvision SADP")
                        .on_toggle(Message::Sadp),
                ]
                .spacing(24),
                row![
                    checkbox(self.dahua_discovery)
                        .label("Dahua")
                        .on_toggle(Message::Dahua),
                    checkbox(self.dnssd_discovery)
                        .label("DNS-SD / Bonjour")
                        .on_toggle(Message::DnsSd),
                    checkbox(self.ssdp_discovery)
                        .label("SSDP / UPnP")
                        .on_toggle(Message::Ssdp),
                ]
                .spacing(24),
                text(self.t("extended-discovery-help"))
                    .size(11)
                    .color(muted),
                text(self.t("camera-discovery-help")).size(11).color(muted),
                checkbox(self.smb_shares)
                    .label(self.t("smb-shares-setting"))
                    .on_toggle(Message::SmbShares),
                text(self.t("smb-shares-help")).size(11).color(muted),
                horizontal_rule(1),
                checkbox(self.services && self.method == ScanMethod::TcpConnect)
                    .label(self.t("services"))
                    .on_toggle_maybe(if self.method == ScanMethod::TcpConnect {
                        Some(Message::Services)
                    } else {
                        None
                    }),
                text(self.t("scan-limits-note")).size(12).color(muted),
                horizontal_rule(1),
                row![
                    text(self.t(if self.defaults_saved {
                        "defaults-saved"
                    } else {
                        "defaults-save-note"
                    }))
                    .size(12)
                    .color(muted)
                    .width(Length::Fill),
                    button(text(self.t("reset-defaults")).size(12))
                        .padding([8, 12])
                        .style(style::secondary)
                        .on_press(Message::ResetDefaults),
                    button(text(self.t("save-defaults")).size(12))
                        .padding([8, 12])
                        .on_press(Message::SaveDefaults)
                ]
                .spacing(10)
                .align_y(Alignment::Center),
            ]
            .spacing(14),
        )
        .padding(18)
        .width(Length::Fill)
        .style(style::surface);
        let storage = container(
            column![
                row![
                    text(self.t("settings-storage"))
                        .size(17)
                        .width(Length::Fill),
                    text(format!("{} MACLookup", self.vendor_count))
                        .font(style::MONO)
                        .size(12)
                        .color(muted)
                ],
                text(self.data_path.display().to_string())
                    .font(style::MONO)
                    .size(11),
            ]
            .spacing(10),
        )
        .padding(18)
        .width(Length::Fill)
        .style(style::surface);
        let mut network = column![
            row![
                text(self.t("settings-network"))
                    .size(17)
                    .width(Length::Fill),
                text(self.interfaces.len().to_string())
                    .font(style::MONO)
                    .size(16)
            ],
            text(self.t("scope-note")).size(13).color(muted),
        ]
        .spacing(10);
        network = network.push(
            button(
                text(self.t(if self.settings_network_open {
                    "hide-interfaces"
                } else {
                    "show-interfaces"
                }))
                .size(12),
            )
            .padding([7, 10])
            .style(style::secondary)
            .on_press(Message::ToggleNetwork),
        );
        if self.settings_network_open && self.interfaces.is_empty() {
            network = network.push(text(self.t("settings-no-interfaces")).size(13));
        }
        for interface in self
            .interfaces
            .iter()
            .filter(|_| self.settings_network_open)
        {
            network = network.push(horizontal_rule(1)).push(
                column![
                    text(&interface.name).size(15),
                    text(
                        interface
                            .addresses
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(" · ")
                    )
                    .font(style::MONO)
                    .size(12),
                    text(format!("MAC  {}", interface.mac.as_deref().unwrap_or("—")))
                        .font(style::MONO)
                        .size(11)
                        .color(muted)
                ]
                .spacing(8),
            );
        }
        let network = container(network)
            .padding(18)
            .width(Length::Fill)
            .style(style::surface);
        scrollable(
            column![
                self.header("settings", "settings-subtitle"),
                top,
                controls,
                storage,
                network
            ]
            .spacing(20)
            .padding(iced::Padding::default().bottom(24)),
        )
        .height(Length::Fill)
        .into()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn inspector_tabs_and_expansion_reset_for_a_new_device() {
        let (mut app, _) = isolated_app();
        assert_eq!(app.info_tab, InspectorTab::Overview);
        for tab in [
            InspectorTab::Ports,
            InspectorTab::Discovery,
            InspectorTab::Shares,
        ] {
            let _ = app.update(Message::InfoTab(tab));
            assert_eq!(app.info_tab, tab);
        }
        let key = "ad:DNS-SD:printer".to_owned();
        let _ = app.update(Message::ExpandDiscovery(key.clone()));
        assert_eq!(app.expanded_discovery.as_ref(), Some(&key));
        let _ = app.update(Message::ExpandDiscovery(key.clone()));
        assert!(app.expanded_discovery.is_none());
        let _ = app.update(Message::ExpandDiscovery(key));
        let _ = app.update(Message::Select("192.0.2.11".parse().unwrap()));
        assert_eq!(app.info_tab, InspectorTab::Overview);
        assert!(app.expanded_discovery.is_none());
    }
    #[tokio::test]
    async fn device_kind_filter_combines_with_open_filter_and_resets() {
        let (mut app, _commands) = isolated_app();
        let plan = portspecter_core::prepare("192.0.2.1-2", "80", "", ScanSettings::default())
            .await
            .unwrap();
        let hosts = plan
            .hosts
            .iter()
            .enumerate()
            .map(|(i, h)| HostObservation {
                ip: h.ip,
                blocks: h.blocks.clone(),
                hostname: None,
                hostname_info: None,
                discovery: None,
                cameras: vec![],
                shares: None,
                mac: None,
                ports: vec![],
                completed: 0,
                total: 1,
                advertisements: vec![if i == 0 {
                    DeviceAdvertisement {
                        protocol: "DNS-SD".into(),
                        service_type: Some("_ipp._tcp.local.".into()),
                        ..Default::default()
                    }
                } else {
                    DeviceAdvertisement {
                        protocol: "Dahua".into(),
                        device_type: Some("NVR".into()),
                        ..Default::default()
                    }
                }],
            })
            .collect();
        app.set_session(ScanSession {
            id: uuid::Uuid::new_v4(),
            started_at: chrono::Utc::now(),
            finished_at: None,
            status: SessionStatus::Completed,
            plan,
            hosts,
            completed: 0,
            total: 2,
        });
        assert!(app.filtered_hosts().is_empty());
        assert!(!app.scan_controls_expanded);
        let _ = app.update(Message::ToggleScanControls);
        assert!(app.scan_controls_expanded);
        let _ = app.update(Message::ToggleScanControls);
        assert!(!app.scan_controls_expanded);
        let _ = app.update(Message::OnlyOpen(false));
        let _ = app.update(Message::DeviceKind(Some(DeviceKind::Printer)));
        assert_eq!(app.filtered_hosts().len(), 1);
        assert_eq!(app.filtered_hosts()[0].ip.to_string(), "192.0.2.1");
        let _ = app.update(Message::DeviceKind(Some(DeviceKind::Recorder)));
        assert_eq!(app.filtered_hosts()[0].ip.to_string(), "192.0.2.2");
        let _ = app.update(Message::ResetFilters);
        assert_eq!(app.filtered_hosts().len(), 2);
        assert!(app.device_kind.is_none());
    }
    #[test]
    fn discovery_options_round_trip_through_scan_settings() {
        let (mut app, _commands) = isolated_app();
        let _ = app.update(Message::Onvif(true));
        let _ = app.update(Message::Sadp(true));
        let _ = app.update(Message::Dahua(true));
        let _ = app.update(Message::DnsSd(true));
        let _ = app.update(Message::Ssdp(true));
        let _ = app.update(Message::SmbShares(false));
        let settings = app.settings().unwrap();
        assert!(settings.onvif_discovery && settings.sadp_discovery);
        assert!(!settings.smb_shares);
        let json = serde_json::to_string(&settings).unwrap();
        let saved: ScanSettings = serde_json::from_str(&json).unwrap();
        assert!(saved.onvif_discovery && saved.sadp_discovery);
        assert!(saved.dahua_discovery && saved.dnssd_discovery && saved.ssdp_discovery);
        assert!(!saved.smb_shares);
    }
    use super::*;
    #[test]
    fn scan_defaults_validate_before_saving_and_reset_without_starting_scan() {
        let (mut app, mut commands) = isolated_app();
        let _ = app.update(Message::PerHost("16".into()));
        let _ = app.update(Message::Retries("2".into()));
        let _ = app.update(Message::SaveDefaults);
        let Command::ScanDefaults(settings) = commands.try_recv().unwrap() else {
            panic!("Expected saved settings")
        };
        assert_eq!(settings.per_host, 16);
        assert_eq!(settings.retries, 2);
        let _ = app.update(Message::Retries("4".into()));
        let _ = app.update(Message::SaveDefaults);
        assert!(app.error.is_some());
        assert!(commands.try_recv().is_err());
        let _ = app.update(Message::ResetDefaults);
        assert_eq!(app.settings().unwrap().retries, 1);
        assert_eq!(app.settings().unwrap().per_host, 8);
        assert!(commands.try_recv().is_err());
    }
    fn isolated_app() -> (App, mpsc::Receiver<Command>) {
        let (tx, commands) = mpsc::channel(8);
        let (_events, rx) = mpsc::channel(8);
        let mut app = App::with_backend(tx, rx);
        app.ready = true;
        (app, commands)
    }
    #[test]
    fn queue_preserves_snapshot_and_waits_for_explicit_run() {
        let (mut app, mut commands) = isolated_app();
        let _ = app.update(Message::QueueCurrent);
        let Command::SaveQueue(saved) = commands.try_recv().unwrap() else {
            panic!("queue must persist")
        };
        assert_eq!(saved.len(), 1);
        assert!(!app.queue_running);
        assert!(!app.preparing);
        app.timeout = "9999".into();
        let _ = app.update(Message::RunQueue);
        let _ = app.update(Message::Tick);
        assert!(matches!(commands.try_recv(), Ok(Command::SaveQueue(_))));
        let Command::Prepare { settings, .. } = commands.try_recv().unwrap() else {
            panic!("queue must prepare first scan")
        };
        assert_eq!(settings.timeout_ms, 1500);
        assert!(app.preparing);
        assert!(app.queue_current.is_some());
        app.handle(Event::Plan(Err("Invalid target".into())));
        assert!(!app.queue_running);
        assert_eq!(app.queue.len(), 1);
        assert!(app.queue_current.is_none());
    }
    #[test]
    fn close_cancels_active_scan_and_stops_queue_without_immediate_exit() {
        let (mut app, _commands) = isolated_app();
        let control = ScanControl::new(1);
        app.control = Some(control.clone());
        app.queue_running = true;
        let _ = app.update(Message::WindowClose);
        assert!(control.cancel.is_cancelled());
        assert!(app.closing);
        assert!(!app.queue_running);
        assert!(app.control.is_some());
    }
    #[test]
    fn adding_subnet_preserves_targets_deduplicates_and_never_starts_scan() {
        let (mut app, mut commands) = isolated_app();
        let original = app.targets.text();
        let _ = app.update(Message::AddSubnet("192.168.2.0/24".into()));
        assert!(app.targets.text().starts_with(&original));
        let once = app.targets.text();
        let _ = app.update(Message::AddSubnet("192.168.2.0/24".into()));
        assert_eq!(app.targets.text(), once);
        app.preparing = true;
        let _ = app.update(Message::AddSubnet("10.0.0.0/24".into()));
        assert_eq!(app.targets.text(), once);
        assert!(commands.try_recv().is_err());
    }
    #[tokio::test]
    async fn one_start_validates_and_dispatches_scan_without_second_action() {
        let (mut app, mut commands) = isolated_app();
        assert!(app.only_open);
        let _ = app.update(Message::Start);
        assert!(app.preparing);
        let _ = app.update(Message::Start);
        let Command::Prepare {
            targets,
            ports,
            exclusions,
            settings,
        } = commands.try_recv().unwrap()
        else {
            panic!("Expected target validation")
        };
        assert!(commands.try_recv().is_err());
        let plan = portspecter_core::prepare(&targets, &ports, &exclusions, settings)
            .await
            .unwrap();
        app.handle(Event::Plan(Ok(plan)));
        assert!(!app.preparing);
        assert!(app.active());
        let Command::Start(plan, _) = commands.try_recv().unwrap() else {
            panic!("A valid plan must start immediately")
        };
        assert_eq!(plan.hosts[0].ip, "127.0.0.1".parse::<IpAddr>().unwrap());
        let _ = app.update(Message::Start);
        assert!(commands.try_recv().is_err());
    }
    #[tokio::test]
    async fn close_during_preparation_never_starts_scan_and_waits_for_shutdown() {
        let (mut app, mut commands) = isolated_app();
        let _ = app.update(Message::Start);
        let Command::Prepare {
            targets,
            ports,
            exclusions,
            settings,
        } = commands.try_recv().unwrap()
        else {
            panic!("Expected preparation");
        };
        let _ = app.update(Message::WindowClose);
        assert!(matches!(commands.try_recv(), Ok(Command::Shutdown)));
        assert!(!app.shutdown_complete);
        let plan = portspecter_core::prepare(&targets, &ports, &exclusions, settings)
            .await
            .unwrap();
        app.handle(Event::Plan(Ok(plan)));
        assert!(app.control.is_none());
        assert!(commands.try_recv().is_err());
        app.handle(Event::ShutdownComplete);
        assert!(app.shutdown_complete);
    }
    #[test]
    fn thread_setting_is_saved_and_used_by_next_scan() {
        let (mut app, mut commands) = isolated_app();
        let _ = app.update(Message::WorkerThreads("8".into()));
        assert!(matches!(commands.try_recv(), Ok(Command::WorkerThreads(8))));
        assert_eq!(app.settings().unwrap().worker_threads, 8);
        let _ = app.update(Message::WorkerThreads("0".into()));
        assert!(commands.try_recv().is_err());
        assert!(app.settings().is_err());
    }
    #[tokio::test]
    async fn invalid_custom_ports_keep_input_and_do_not_start() {
        let (mut app, mut commands) = isolated_app();
        app.known_ports = false;
        let targets = app.targets.text();
        let _ = app.update(Message::Start);
        let Command::Prepare {
            targets: input,
            ports,
            exclusions,
            settings,
        } = commands.try_recv().unwrap()
        else {
            panic!("Expected validation")
        };
        let error = portspecter_core::prepare(&input, &ports, &exclusions, settings)
            .await
            .unwrap_err();
        app.handle(Event::Plan(Err(error.to_string())));
        assert!(!app.active() && !app.preparing);
        assert!(app.error.is_some());
        assert_eq!(app.targets.text(), targets);
        assert!(commands.try_recv().is_err());
    }
    #[tokio::test]
    async fn port_presets_reduce_subnet_work_and_preserve_old_profiles() {
        let (mut app, _) = isolated_app();
        let quick = portspecter_core::prepare(
            "192.168.2.1/24",
            app.selected_ports(),
            "",
            app.settings().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(quick.hosts.len() * quick.ports.len(), 2794);
        app.ports = "12345".into();
        let _ = app.update(Message::ExtendedPorts(true));
        let extended = portspecter_core::prepare(
            "192.168.2.1/24",
            app.selected_ports(),
            "",
            app.settings().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(extended.hosts.len() * extended.ports.len(), 8636);
        assert!(quick.ports.iter().all(|port| extended.ports.contains(port)));
        let _ = app.update(Message::KnownPorts(false));
        assert_eq!(app.selected_ports(), "12345");
        let mut old = SavedProfile {
            name: "Legacy".into(),
            targets: "127.0.0.1".into(),
            ports: EXTENDED_PORTS.into(),
            known_ports: Some(true),
            exclusions: String::new(),
            settings: ScanSettings::default(),
        };
        app.apply_profile_ports(&old);
        assert!(app.known_ports && app.extended_ports);
        assert_eq!(app.selected_ports(), EXTENDED_PORTS);
        old.known_ports = None;
        app.apply_profile_ports(&old);
        assert_eq!(app.selected_ports(), EXTENDED_PORTS);
        old.known_ports = Some(false);
        app.apply_profile_ports(&old);
        assert!(!app.known_ports);
        assert_eq!(app.selected_ports(), EXTENDED_PORTS);
        let _ = app.update(Message::KnownPorts(true));
        app.preparing = true;
        let _ = app.update(Message::ExtendedPorts(true));
        assert!(!app.extended_ports);
    }
    #[test]
    fn protocol_changes_presets_and_profile_retains_udp_mode() {
        let (mut app, _) = isolated_app();
        let _ = app.update(Message::Method(ScanMethod::Udp));
        assert_eq!(app.selected_ports(), DEFAULT_UDP_PORTS);
        let _ = app.update(Message::ExtendedPorts(true));
        assert_eq!(app.selected_ports(), EXTENDED_UDP_PORTS);
        let profile = SavedProfile {
            name: "UDP".into(),
            targets: "127.0.0.1".into(),
            ports: app.selected_ports().into(),
            known_ports: Some(true),
            exclusions: String::new(),
            settings: app.settings().unwrap(),
        };
        let _ = app.update(Message::Method(ScanMethod::TcpSyn));
        assert_eq!(app.selected_ports(), EXTENDED_PORTS);
        app.apply_profile_ports(&profile);
        assert_eq!(app.method, ScanMethod::Udp);
        assert!(app.extended_ports);
        assert_eq!(app.selected_ports(), EXTENDED_UDP_PORTS);
    }
}
