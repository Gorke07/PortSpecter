use portspecter_core::{ScanControl, ScanEvent};
use portspecter_domain::*;
use portspecter_storage::{SavedProfile, SessionSummary, Storage};
use std::{path::PathBuf, sync::Arc};
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub enum Event {
    Health(u64, Box<portspecter_platform::health::HealthReport>),
    Ready {
        path: PathBuf,
        vendors: usize,
        interfaces: Vec<portspecter_platform::InterfaceInfo>,
        history: Vec<SessionSummary>,
        profiles: Vec<SavedProfile>,
        language: Option<String>,
        light: bool,
        worker_threads: usize,
        scan_defaults: Option<ScanSettings>,
        queue: Vec<SavedProfile>,
        notify_finished: bool,
    },
    Plan(Result<ScanPlan, String>),
    Scan(ScanEvent),
    History(Vec<SessionSummary>),
    Loaded(Box<ScanSession>),
    Imported(String),
    Profiles(Vec<SavedProfile>),
    Notice(String),
    DefaultsSaved,
    ShutdownComplete,
    Compared(Comparison),
    Failure(String),
    Route {
        session_id: uuid::Uuid,
        ip: std::net::IpAddr,
        result: Result<portspecter_platform::RouteInfo, String>,
    },
}
pub enum Command {
    Health(u64, std::net::SocketAddr, String),
    CancelHealth,
    Prepare {
        targets: String,
        ports: String,
        exclusions: String,
        settings: ScanSettings,
    },
    Start(ScanPlan, ScanControl),
    History,
    Load(String),
    Delete(String),
    Import,
    Export {
        id: String,
        json: bool,
    },
    SaveProfile(SavedProfile),
    Language(String),
    Theme(bool),
    WorkerThreads(usize),
    ScanDefaults(ScanSettings),
    Compare(String, String),
    SaveQueue(Vec<SavedProfile>),
    NotifyFinished(bool),
    Shutdown,
    InspectRoute {
        session_id: uuid::Uuid,
        ip: std::net::IpAddr,
        source: Option<std::net::IpAddr>,
    },
}

pub fn launch() -> (mpsc::Sender<Command>, mpsc::Receiver<Event>) {
    let (commands, mut receiver) = mpsc::channel(32);
    let (events, output) = mpsc::channel(512);
    std::thread::Builder::new()
        .name("portspecter-backend".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .build()
            {
                Ok(r) => r,
                Err(e) => {
                    let _ = events.blocking_send(Event::Failure(e.to_string()));
                    return;
                }
            };
            runtime.block_on(async move {
                let result = async {
                    let paths = directories::ProjectDirs::from("app", "PortSpecter", "PortSpecter")
                        .ok_or_else(|| anyhow::anyhow!("No application data directory"))?;
                    let data_dir = std::env::var_os("PORTSPECTER_DATA_DIR")
                        .map(PathBuf::from)
                        .unwrap_or_else(|| paths.data_local_dir().to_path_buf());
                    let path = data_dir.join("portspecter.db");
                    std::fs::create_dir_all(&data_dir)?;
                    let workspace_lock = std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .truncate(false)
                        .open(path.with_extension("lock"))?;
                    workspace_lock.try_lock().map_err(|_| {
                        anyhow::anyhow!(
                            "This local workspace is already open in another PortSpecter window"
                        )
                    })?;
                    let storage = Storage::open(&path).await?;
                    let vendors = Arc::new(VendorDatabase::from_json(include_bytes!(
                        "../../../assets/data/mac-vendors.json"
                    ))?);
                    events
                        .send(Event::Ready {
                            path,
                            vendors: vendors.len(),
                            interfaces: portspecter_platform::interfaces(),
                            history: storage.list().await?,
                            profiles: storage.profiles().await?,
                            language: storage.setting("language").await?,
                            light: storage.setting("theme").await?.as_deref() == Some("light"),
                            queue: storage
                                .setting("scan_queue")
                                .await?
                                .and_then(|value| {
                                    serde_json::from_str::<Vec<SavedProfile>>(&value).ok()
                                })
                                .unwrap_or_default()
                                .into_iter()
                                .take(100)
                                .collect(),
                            notify_finished: storage.setting("notify_finished").await?.as_deref()
                                != Some("false"),
                            scan_defaults: storage
                                .setting("scan_defaults")
                                .await?
                                .and_then(|value| serde_json::from_str::<ScanSettings>(&value).ok())
                                .filter(|settings| settings.validate().is_ok()),
                            worker_threads: storage
                                .setting("worker_threads")
                                .await?
                                .and_then(|v| v.parse().ok())
                                .filter(|v| (1..=256).contains(v))
                                .unwrap_or_else(default_worker_threads),
                        })
                        .await
                        .ok();
                    let mut active: Option<(tokio::task::JoinHandle<()>, ScanControl)> = None;
                    let mut health_task: Option<tokio::task::JoinHandle<()>> = None;
                    while let Some(command) = receiver.recv().await {
                        let response: anyhow::Result<()> = async {
                            match command {
                                Command::Health(id, target, dns) => {
                                    if let Some(task) = health_task.take() {
                                        task.abort();
                                    }
                                    let events = events.clone();
                                    health_task = Some(tokio::spawn(async move {
                                        let report =
                                            portspecter_platform::health::run(target, dns).await;
                                        let _ =
                                            events.send(Event::Health(id, Box::new(report))).await;
                                    }));
                                }
                                Command::CancelHealth => {
                                    if let Some(task) = health_task.take() {
                                        task.abort();
                                    }
                                }
                                Command::InspectRoute {
                                    session_id,
                                    ip,
                                    source,
                                } => {
                                    let result = tokio::task::spawn_blocking(move || {
                                        portspecter_platform::route_to(ip, source)
                                    })
                                    .await?
                                    .map_err(|e| e.to_string());
                                    let _ = events
                                        .send(Event::Route {
                                            session_id,
                                            ip,
                                            result,
                                        })
                                        .await;
                                }
                                Command::Prepare {
                                    targets,
                                    ports,
                                    exclusions,
                                    settings,
                                } => {
                                    let plan = portspecter_core::prepare(
                                        &targets,
                                        &ports,
                                        &exclusions,
                                        settings,
                                    )
                                    .await
                                    .map_err(|e| format!("{e:#}"));
                                    let _ = events.send(Event::Plan(plan)).await;
                                }
                                Command::Start(plan, control) => {
                                    if let Some((task, _)) = active.as_mut()
                                        && !task.is_finished()
                                    {
                                        anyhow::ensure!(
                                            tokio::time::timeout(
                                                std::time::Duration::from_secs(3),
                                                task
                                            )
                                            .await
                                            .is_ok(),
                                            "A scan is already running"
                                        );
                                    }
                                    anyhow::ensure!(
                                        active.as_ref().is_none_or(|(h, _)| h.is_finished()),
                                        "A scan is already running"
                                    );
                                    let (tx, mut rx) = mpsc::channel(128);
                                    let forward = events.clone();
                                    tokio::spawn(async move {
                                        while let Some(event) = rx.recv().await {
                                            if forward.send(Event::Scan(event)).await.is_err() {
                                                break;
                                            }
                                        }
                                    });
                                    plan.settings.validate()?;
                                    let scan_control = control.clone();
                                    let scan_storage = storage.clone();
                                    let scan_vendors = vendors.clone();
                                    let task = tokio::task::spawn_blocking(move || {
                                        match tokio::runtime::Builder::new_multi_thread()
                                            .worker_threads(plan.settings.worker_threads)
                                            .thread_name("portspecter-scan")
                                            .enable_all()
                                            .build()
                                        {
                                            Ok(runtime) => {
                                                runtime.block_on(portspecter_core::run(
                                                    plan,
                                                    scan_control,
                                                    scan_storage,
                                                    scan_vendors,
                                                    tx,
                                                ));
                                                runtime.shutdown_timeout(
                                                    std::time::Duration::from_secs(2),
                                                );
                                            }
                                            Err(error) => {
                                                let _ = tx.blocking_send(ScanEvent::Error(
                                                    error.to_string(),
                                                ));
                                            }
                                        }
                                    });
                                    active = Some((task, control));
                                }
                                Command::History => {
                                    let _ =
                                        events.send(Event::History(storage.list().await?)).await;
                                }
                                Command::Shutdown => {
                                    if let Some(task) = health_task.take() {
                                        task.abort();
                                    }
                                    if let Some((task, control)) = active.take() {
                                        control.cancel.cancel();
                                        let _ = task.await;
                                    }
                                    let _ = events.send(Event::ShutdownComplete).await;
                                }
                                Command::Compare(a, b) => {
                                    let a = storage.load(&a).await?;
                                    let b = storage.load(&b).await?;
                                    let (before, after) = if a.started_at <= b.started_at {
                                        (&a, &b)
                                    } else {
                                        (&b, &a)
                                    };
                                    let _ =
                                        events.send(Event::Compared(compare(before, after))).await;
                                }
                                Command::SaveQueue(queue) => {
                                    anyhow::ensure!(queue.len() <= 100, "Queue limit is 100 scans");
                                    storage
                                        .set_setting("scan_queue", &serde_json::to_string(&queue)?)
                                        .await?;
                                }
                                Command::NotifyFinished(value) => {
                                    storage
                                        .set_setting(
                                            "notify_finished",
                                            if value { "true" } else { "false" },
                                        )
                                        .await?
                                }
                                Command::WorkerThreads(value) => {
                                    anyhow::ensure!(
                                        (1..=256).contains(&value),
                                        "Worker threads must be 1–256"
                                    );
                                    storage
                                        .set_setting("worker_threads", &value.to_string())
                                        .await?;
                                }
                                Command::ScanDefaults(settings) => {
                                    settings.validate()?;
                                    storage
                                        .set_setting(
                                            "scan_defaults",
                                            &serde_json::to_string(&settings)?,
                                        )
                                        .await?;
                                    storage
                                        .set_setting(
                                            "worker_threads",
                                            &settings.worker_threads.to_string(),
                                        )
                                        .await?;
                                    let _ = events.send(Event::DefaultsSaved).await;
                                }
                                Command::Load(id) => {
                                    let _ = events
                                        .send(Event::Loaded(Box::new(storage.load(&id).await?)))
                                        .await;
                                }
                                Command::Delete(id) => {
                                    anyhow::ensure!(
                                        active.as_ref().is_none_or(|(h, _)| h.is_finished()),
                                        "Stop the scan before deleting history"
                                    );
                                    storage.delete(&id).await?;
                                    let _ =
                                        events.send(Event::History(storage.list().await?)).await;
                                }
                                Command::Import => {
                                    let path = tokio::task::spawn_blocking(|| {
                                        rfd::FileDialog::new()
                                            .add_filter("Targets", &["txt", "csv"])
                                            .pick_file()
                                    })
                                    .await?;
                                    if let Some(path) = path {
                                        let value = tokio::task::spawn_blocking(move || {
                                            import_targets(&path)
                                        })
                                        .await??;
                                        let _ = events.send(Event::Imported(value)).await;
                                    }
                                }
                                Command::Export { id, json } => {
                                    let session = storage.load(&id).await?;
                                    let path = tokio::task::spawn_blocking(move || {
                                        rfd::FileDialog::new()
                                            .set_file_name(if json {
                                                "portspecter.json"
                                            } else {
                                                "portspecter.csv"
                                            })
                                            .save_file()
                                    })
                                    .await?;
                                    if let Some(path) = path {
                                        let label = path.display().to_string();
                                        tokio::task::spawn_blocking(move || {
                                            if json {
                                                export_json(&path, &session)
                                            } else {
                                                export_csv(&path, &session)
                                            }
                                        })
                                        .await??;
                                        let _ = events
                                            .send(Event::Notice(format!("Export: {label}")))
                                            .await;
                                    }
                                }
                                Command::SaveProfile(profile) => {
                                    storage.save_profile(&profile).await?;
                                    let _ = events
                                        .send(Event::Profiles(storage.profiles().await?))
                                        .await;
                                }
                                Command::Language(language) => {
                                    storage.set_setting("language", &language).await?;
                                }
                                Command::Theme(light) => {
                                    storage
                                        .set_setting("theme", if light { "light" } else { "dark" })
                                        .await?;
                                }
                            }
                            Ok(())
                        }
                        .await;
                        if let Err(e) = response {
                            let _ = events.send(Event::Failure(format!("{e:#}"))).await;
                        }
                    }
                    if let Some(task) = health_task.take() {
                        task.abort();
                    }
                    if let Some((task, control)) = active {
                        control.cancel.cancel();
                        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), task).await;
                    }
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                if let Err(e) = result {
                    let _ = events.send(Event::Failure(format!("{e:#}"))).await;
                }
            });
        })
        .expect("backend thread");
    (commands, output)
}
