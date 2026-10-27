//! Offline /16 planning plus a bounded loopback-only TCP benchmark. No LAN targets are scanned.
use portspecter_core::{ScanControl, ScanEvent, prepare, run};
use portspecter_domain::*;
use portspecter_storage::Storage;
use std::{sync::Arc, time::Instant};

fn main() -> anyhow::Result<()> {
    let workers = std::env::args()
        .nth(1)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(4);
    anyhow::ensure!((1..=256).contains(&workers), "workers must be 1..256");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let settings=ScanSettings{worker_threads:workers,concurrency:512,per_host:64,rate_per_second:10000,timeout_ms:100,retries:0,inspect_services:false,icmp_discovery:false,resolve_names:false,local_names:false,..Default::default()};
        let planning=Instant::now();
        let large=prepare("10.32.0.0/16","22,80,443","",settings.clone()).await?;
        let planning_ms=planning.elapsed().as_millis();let planned_hosts=large.hosts.len();drop(large);
        let path=std::path::PathBuf::from("artifacts").join(format!("benchmark-{}.db",uuid::Uuid::new_v4()));
        let storage=Storage::open(&path).await?;
        let plan=prepare("127.0.0.1","10000-12047","",settings).await?;
        let total=plan.hosts.len()*plan.ports.len();
        let control=ScanControl::new(plan.blocks.len());
        let (sender,mut receiver)=tokio::sync::mpsc::channel(128);
        let writer=storage.clone();let start=Instant::now();
        let task=tokio::spawn(run(plan,control,writer,Arc::new(VendorDatabase::default()),sender));
        let mut terminal=None;
        while let Some(event)=receiver.recv().await {
            match event {
                ScanEvent::Finished{id,status,completed}=>terminal=Some((id,status,completed)),
                ScanEvent::Error(error)=>anyhow::bail!(error),
                _=>{}
            }
        }
        task.await?;
        let duration=start.elapsed();
        let (id,status,completed)=terminal.ok_or_else(||anyhow::anyhow!("missing terminal event"))?;
        anyhow::ensure!(status==SessionStatus::Completed && completed==total,"incomplete benchmark");
        let restored=storage.load(&id.to_string()).await?;
        anyhow::ensure!(restored.hosts.iter().map(|host|host.ports.len()).sum::<usize>()==total,"persisted count mismatch");
        println!("{}",serde_json::json!({"workers":workers,"planned_hosts":planned_hosts,"planning_ms":planning_ms,"probes":total,"elapsed_ms":duration.as_millis(),"probes_per_second":total as f64/duration.as_secs_f64(),"persisted":completed,"database":path}));
        Ok(())
    })
}
