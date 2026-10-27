use anyhow::Result;
use portspecter_domain::*;
use serde::{Deserialize, Serialize};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use std::{net::IpAddr, path::Path, time::Duration};

#[derive(Clone)]
pub struct Storage {
    pool: SqlitePool,
}
#[derive(Debug, Clone)]
pub struct SessionSummary {
    pub id: String,
    pub started_at: String,
    pub status: String,
    pub hosts: i64,
    pub completed: i64,
    pub total: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedProfile {
    pub name: String,
    pub targets: String,
    pub ports: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_ports: Option<bool>,
    pub exclusions: String,
    pub settings: ScanSettings,
}

impl Storage {
    pub async fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(2)
            .connect_with(options)
            .await?;
        Self::initialize(pool).await
    }
    pub async fn memory() -> Result<Self> {
        Self::initialize(
            SqlitePoolOptions::new()
                .max_connections(1)
                .connect("sqlite::memory:")
                .await?,
        )
        .await
    }
    async fn initialize(pool: SqlitePool) -> Result<Self> {
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(
            version <= 5,
            "Database was created by a newer PortSpecter version; no changes were made"
        );
        if version == 0 {
            let mut transaction = pool.begin().await?;
            sqlx::raw_sql(include_str!("../migrations/0001_initial.sql"))
                .execute(&mut *transaction)
                .await?;
            transaction.commit().await?;
        }
        if version < 2 {
            let mut transaction = pool.begin().await?;
            sqlx::raw_sql(include_str!("../migrations/0002_host_names.sql"))
                .execute(&mut *transaction)
                .await?;
            transaction.commit().await?;
        }
        if version < 3 {
            let mut transaction = pool.begin().await?;
            sqlx::raw_sql(include_str!("../migrations/0003_discovery.sql"))
                .execute(&mut *transaction)
                .await?;
            transaction.commit().await?;
        }
        if version < 4 {
            let mut transaction = pool.begin().await?;
            sqlx::raw_sql(include_str!("../migrations/0004_device_services.sql"))
                .execute(&mut *transaction)
                .await?;
            transaction.commit().await?;
        }
        if version < 5 {
            let mut transaction = pool.begin().await?;
            sqlx::raw_sql(include_str!("../migrations/0005_advertisements.sql"))
                .execute(&mut *transaction)
                .await?;
            transaction.commit().await?;
        }
        sqlx::query("UPDATE sessions SET status='Interrupted' WHERE status IN ('Running','Paused','Pausing')").execute(&pool).await?;
        Ok(Self { pool })
    }
    pub async fn begin(&self, session: &ScanSession) -> Result<()> {
        sqlx::query("INSERT INTO sessions(id,started_at,status,plan,total) VALUES(?,?,?,?,?)")
            .bind(session.id.to_string())
            .bind(session.started_at.to_rfc3339())
            .bind("Running")
            .bind(serde_json::to_string(&session.plan)?)
            .bind(session.total as i64)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn save_advertisements(
        &self,
        id: uuid::Uuid,
        ip: IpAddr,
        values: &[DeviceAdvertisement],
    ) -> Result<()> {
        sqlx::query("INSERT INTO device_services(session_id,ip,advertisements) VALUES(?,?,?) ON CONFLICT(session_id,ip) DO UPDATE SET advertisements=excluded.advertisements")
            .bind(id.to_string()).bind(ip.to_string()).bind(serde_json::to_string(values)?).execute(&self.pool).await?;
        Ok(())
    }
    pub async fn save_cameras(
        &self,
        id: uuid::Uuid,
        ip: IpAddr,
        value: &[CameraObservation],
    ) -> Result<()> {
        sqlx::query("INSERT INTO device_services(session_id,ip,cameras) VALUES(?,?,?) ON CONFLICT(session_id,ip) DO UPDATE SET cameras=excluded.cameras")
            .bind(id.to_string()).bind(ip.to_string()).bind(serde_json::to_string(value)?).execute(&self.pool).await?;
        Ok(())
    }
    pub async fn save_shares(
        &self,
        id: uuid::Uuid,
        ip: IpAddr,
        value: &ShareDiscovery,
    ) -> Result<()> {
        sqlx::query("INSERT INTO device_services(session_id,ip,shares) VALUES(?,?,?) ON CONFLICT(session_id,ip) DO UPDATE SET shares=excluded.shares")
            .bind(id.to_string()).bind(ip.to_string()).bind(serde_json::to_string(value)?).execute(&self.pool).await?;
        Ok(())
    }
    pub async fn save_name(
        &self,
        id: uuid::Uuid,
        ip: IpAddr,
        name: &NameObservation,
    ) -> Result<()> {
        sqlx::query("INSERT OR REPLACE INTO host_names VALUES(?,?,?)")
            .bind(id.to_string())
            .bind(ip.to_string())
            .bind(serde_json::to_string(name)?)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn save_discovery(
        &self,
        id: uuid::Uuid,
        ip: IpAddr,
        value: &DiscoveryObservation,
    ) -> Result<()> {
        sqlx::query("INSERT OR REPLACE INTO discovery VALUES(?,?,?)")
            .bind(id.to_string())
            .bind(ip.to_string())
            .bind(serde_json::to_string(value)?)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn write_batch(
        &self,
        id: uuid::Uuid,
        values: &[(IpAddr, PortObservation)],
        completed: usize,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        for (ip, observation) in values {
            sqlx::query("INSERT OR REPLACE INTO observations VALUES(?,?,?,?)")
                .bind(id.to_string())
                .bind(ip.to_string())
                .bind(observation.port as i64)
                .bind(serde_json::to_string(observation)?)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("UPDATE sessions SET completed=? WHERE id=?")
            .bind(completed as i64)
            .bind(id.to_string())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn save_macs(&self, id: uuid::Uuid, macs: &[(IpAddr, MacObservation)]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        for (ip, mac) in macs {
            sqlx::query("INSERT OR REPLACE INTO macs VALUES(?,?,?)")
                .bind(id.to_string())
                .bind(ip.to_string())
                .bind(serde_json::to_string(mac)?)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }
    pub async fn finish(
        &self,
        id: uuid::Uuid,
        status: SessionStatus,
        completed: usize,
    ) -> Result<()> {
        sqlx::query("UPDATE sessions SET status=?,finished_at=?,completed=? WHERE id=?")
            .bind(format!("{status:?}"))
            .bind(chrono::Utc::now().to_rfc3339())
            .bind(completed as i64)
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn list(&self) -> Result<Vec<SessionSummary>> {
        Ok(sqlx::query("SELECT id,started_at,status,completed,total, json_array_length(json_extract(plan,'$.hosts')) AS hosts FROM sessions ORDER BY started_at DESC LIMIT 100").fetch_all(&self.pool).await?.into_iter().map(|r|SessionSummary{id:r.get("id"),started_at:r.get("started_at"),status:r.get("status"),hosts:r.get("hosts"),completed:r.get("completed"),total:r.get("total")}).collect())
    }
    pub async fn load(&self, id: &str) -> Result<ScanSession> {
        let row = sqlx::query("SELECT * FROM sessions WHERE id=?")
            .bind(id)
            .fetch_one(&self.pool)
            .await?;
        let plan: ScanPlan = serde_json::from_str(row.get("plan"))?;
        let mut hosts: std::collections::BTreeMap<IpAddr, HostObservation> = plan
            .hosts
            .iter()
            .map(|h| {
                (
                    h.ip,
                    HostObservation {
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
                    },
                )
            })
            .collect();
        let mut offset = 0i64;
        loop {
            let rows=sqlx::query("SELECT ip,payload FROM observations WHERE session_id=? ORDER BY ip,port LIMIT 1000 OFFSET ?").bind(id).bind(offset).fetch_all(&self.pool).await?;
            if rows.is_empty() {
                break;
            }
            offset += rows.len() as i64;
            for row in rows {
                let ip: IpAddr = row.get::<&str, _>("ip").parse()?;
                let p: PortObservation = serde_json::from_str(row.get("payload"))?;
                if let Some(host) = hosts.get_mut(&ip) {
                    host.completed += 1;
                    host.ports.push(p);
                }
            }
        }
        for row in sqlx::query("SELECT ip,payload FROM macs WHERE session_id=?")
            .bind(id)
            .fetch_all(&self.pool)
            .await?
        {
            let ip: IpAddr = row.get::<&str, _>("ip").parse()?;
            if let Some(host) = hosts.get_mut(&ip) {
                host.mac = Some(serde_json::from_str(row.get("payload"))?);
            }
        }
        for row in sqlx::query("SELECT ip,payload FROM host_names WHERE session_id=?")
            .bind(id)
            .fetch_all(&self.pool)
            .await?
        {
            let ip: IpAddr = row.get::<&str, _>("ip").parse()?;
            if let Some(host) = hosts.get_mut(&ip) {
                let name: NameObservation = serde_json::from_str(row.get("payload"))?;
                host.hostname = Some(name.name.clone());
                host.hostname_info = Some(name);
            }
        }
        for row in sqlx::query("SELECT ip,payload FROM discovery WHERE session_id=?")
            .bind(id)
            .fetch_all(&self.pool)
            .await?
        {
            let ip: IpAddr = row.get::<&str, _>("ip").parse()?;
            if let Some(host) = hosts.get_mut(&ip) {
                host.discovery = Some(serde_json::from_str(row.get("payload"))?);
            }
        }
        for row in sqlx::query(
            "SELECT ip,cameras,shares,advertisements FROM device_services WHERE session_id=?",
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await?
        {
            let ip: IpAddr = row.get::<&str, _>("ip").parse()?;
            if let Some(host) = hosts.get_mut(&ip) {
                host.cameras = serde_json::from_str(row.get("cameras"))?;
                host.advertisements = serde_json::from_str(row.get("advertisements"))?;
                host.shares = row
                    .get::<Option<&str>, _>("shares")
                    .map(serde_json::from_str)
                    .transpose()?;
            }
        }
        let status: String = row.get("status");
        Ok(ScanSession {
            id: id.parse()?,
            started_at: row.get::<&str, _>("started_at").parse()?,
            finished_at: row
                .get::<Option<&str>, _>("finished_at")
                .map(str::parse)
                .transpose()?,
            status: serde_json::from_value(serde_json::Value::String(status))?,
            plan,
            hosts: hosts.into_values().collect(),
            completed: row.get::<i64, _>("completed") as usize,
            total: row.get::<i64, _>("total") as usize,
        })
    }
    pub async fn delete(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM sessions WHERE id=?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn save_profile(&self, p: &SavedProfile) -> Result<()> {
        sqlx::query("INSERT OR REPLACE INTO profiles VALUES(?,?)")
            .bind(&p.name)
            .bind(serde_json::to_string(p)?)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn profiles(&self) -> Result<Vec<SavedProfile>> {
        sqlx::query("SELECT payload FROM profiles ORDER BY name")
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(|r| Ok(serde_json::from_str(r.get("payload"))?))
            .collect()
    }
    pub async fn setting(&self, key: &str) -> Result<Option<String>> {
        Ok(sqlx::query("SELECT value FROM settings WHERE key=?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?
            .map(|r| r.get("value")))
    }
    pub async fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        sqlx::query("INSERT OR REPLACE INTO settings VALUES(?,?)")
            .bind(key)
            .bind(value)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn version_one_migrates_without_losing_settings() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::raw_sql(include_str!("../migrations/0001_initial.sql"))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO settings VALUES('language','tr')")
            .execute(&pool)
            .await
            .unwrap();
        let db = Storage::initialize(pool).await.unwrap();
        assert_eq!(db.setting("language").await.unwrap().as_deref(), Some("tr"));
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(version, 5);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM host_names")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }
    #[tokio::test]
    async fn durable_observations_and_profiles() {
        let db = Storage::memory().await.unwrap();
        let plan = merge_targets(
            parse_blocks("127.0.0.1").unwrap(),
            vec![vec!["127.0.0.1".parse().unwrap()]],
            &[],
            vec![22],
            ScanSettings::default(),
        )
        .unwrap();
        let session = ScanSession {
            id: uuid::Uuid::new_v4(),
            started_at: chrono::Utc::now(),
            finished_at: None,
            status: SessionStatus::Running,
            plan,
            hosts: vec![],
            completed: 0,
            total: 1,
        };
        db.begin(&session).await.unwrap();
        db.write_batch(
            session.id,
            &[(
                "127.0.0.1".parse().unwrap(),
                PortObservation {
                    port: 22,
                    state: PortState::Closed,
                    elapsed_ms: 1,
                    observed_at: chrono::Utc::now(),
                    error: None,
                    service: None,
                },
            )],
            1,
        )
        .await
        .unwrap();
        db.finish(session.id, SessionStatus::Completed, 1)
            .await
            .unwrap();
        db.save_name(
            session.id,
            "127.0.0.1".parse().unwrap(),
            &NameObservation {
                name: "test-device".into(),
                source: "netbios_node_status".into(),
                observed_at: chrono::Utc::now(),
            },
        )
        .await
        .unwrap();
        let ip = "127.0.0.1".parse().unwrap();
        db.save_shares(
            session.id,
            ip,
            &ShareDiscovery {
                status: ShareStatus::Complete,
                shares: vec![NetworkShare {
                    name: "Secret$".into(),
                    comment: "Fixture".into(),
                    hidden: true,
                }],
                source: "fixture".into(),
                detail: None,
                observed_at: chrono::Utc::now(),
            },
        )
        .await
        .unwrap();
        let camera = CameraObservation {
            protocol: "SADP".into(),
            endpoint_id: "SN123".into(),
            name: None,
            model: Some("IPC".into()),
            serial: Some("SN123".into()),
            firmware: None,
            mac: None,
            activated: Some(false),
            endpoints: vec![],
            scopes: vec![],
            interface: "fixture".into(),
            observed_at: chrono::Utc::now(),
        };
        db.save_cameras(session.id, ip, &[camera]).await.unwrap();
        db.save_advertisements(
            session.id,
            ip,
            &[DeviceAdvertisement {
                protocol: "DNS-SD".into(),
                identity: "Printer._ipp._tcp.local.".into(),
                service_type: Some("_ipp._tcp.local.".into()),
                port: Some(8631),
                ..Default::default()
            }],
        )
        .await
        .unwrap();
        let restored = db.load(&session.id.to_string()).await.unwrap();
        assert_eq!(restored.hosts[0].advertisements[0].port, Some(8631));
        assert!(
            restored.hosts[0]
                .device_kinds()
                .contains_key(&DeviceKind::Printer)
        );
        assert_eq!(
            restored.hosts[0].cameras[0].serial.as_deref(),
            Some("SN123")
        );
        assert!(restored.hosts[0].shares.as_ref().unwrap().shares[0].hidden);
        assert_eq!(
            restored.hosts[0].shares.as_ref().unwrap().shares[0].name,
            "Secret$"
        );
        assert_eq!(restored.hosts[0].hostname.as_deref(), Some("test-device"));
        assert_eq!(
            restored.hosts[0].hostname_info.as_ref().unwrap().source,
            "netbios_node_status"
        );
        assert_eq!(restored.hosts[0].ports[0].state, PortState::Closed);
        assert_eq!(restored.status, SessionStatus::Completed);
        assert_eq!(db.list().await.unwrap().len(), 1);
        db.delete(&session.id.to_string()).await.unwrap();
        assert!(db.list().await.unwrap().is_empty());
    }
}
