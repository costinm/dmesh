use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use tokio::sync::mpsc;
use tracing::{debug, error, info};

const INIT_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS frames (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    protocol TEXT NOT NULL,
    payload_hash INTEGER NOT NULL,
    src_device TEXT NOT NULL,
    target_device TEXT,
    seq INTEGER,
    msg_type TEXT,
    payload BLOB NOT NULL,
    rssi INTEGER,
    timestamp INTEGER NOT NULL,
    sent INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_frames_timestamp ON frames(timestamp);
CREATE INDEX IF NOT EXISTS idx_frames_payload_hash ON frames(payload_hash);
CREATE INDEX IF NOT EXISTS idx_frames_src_device ON frames(src_device);
CREATE INDEX IF NOT EXISTS idx_frames_sent ON frames(sent);

CREATE TABLE IF NOT EXISTS nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL UNIQUE,
    last_seen INTEGER NOT NULL,
    rssi INTEGER,
    metadata TEXT
);
"#;

/// Default maximum age in hours for stored frames (24 hours).
pub const DEFAULT_MAX_AGE_HOURS: u64 = 24;
/// Default maximum number of stored frames (10000).
pub const DEFAULT_MAX_MESSAGES: u64 = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreConfig {
    /// Maximum age of frames in hours (default: 24).
    pub max_age_hours: u64,
    /// Maximum number of frames to retain (default: 10000).
    pub max_messages: u64,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            max_age_hours: DEFAULT_MAX_AGE_HOURS,
            max_messages: DEFAULT_MAX_MESSAGES,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FrameRecord {
    pub protocol: String,
    pub payload_hash: u32,
    pub src_device: String,
    pub target_device: Option<String>,
    pub seq: Option<u16>,
    pub msg_type: Option<String>,
    pub payload: Vec<u8>,
    pub rssi: Option<i32>,
    pub timestamp: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NodeRecord {
    pub device_id: String,
    pub last_seen: i64,
    pub rssi: Option<i32>,
    pub metadata: Option<String>,
}

pub struct Store {
    pool: SqlitePool,
    nan_active: bool,
    config: StoreConfig,
}

impl Store {
    pub async fn new(db_path: &str) -> Result<Self> {
        Self::with_config(db_path, StoreConfig::default()).await
    }

    pub async fn with_config(db_path: &str, config: StoreConfig) -> Result<Self> {
        if db_path != ":memory:" {
            let parent = std::path::Path::new(db_path)
                .parent()
                .ok_or_else(|| anyhow::anyhow!("no parent dir for {}", db_path))?;
            std::fs::create_dir_all(parent)?;
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .open(db_path);
        }
        let pool = SqlitePool::connect(db_path).await?;
        sqlx::query(INIT_SQL).execute(&pool).await?;
        info!(
            "dmesh-store initialized at {} (max_age={}h, max_msgs={})",
            db_path, config.max_age_hours, config.max_messages
        );
        Ok(Self {
            pool,
            nan_active: false,
            config,
        })
    }

    pub async fn insert_frame(&self, frame: &FrameRecord) -> Result<i64> {
        let now = Utc::now().timestamp_millis();
        let existing = sqlx::query_scalar::<_, i64>(
            "SELECT id FROM frames WHERE payload_hash = ? AND src_device = ? AND (seq = ? OR seq IS NULL) LIMIT 1"
        )
        .bind(frame.payload_hash as i64)
        .bind(&frame.src_device)
        .bind(frame.seq.map(|s| s as i64))
        .fetch_optional(&self.pool)
        .await?;

        if existing.is_some() {
            debug!(
                "frame deduplicated: hash={:08x} src={}",
                frame.payload_hash, frame.src_device
            );
            return Ok(existing.unwrap_or(0));
        }

        let id = sqlx::query_scalar::<_, i64>(
            "INSERT INTO frames (protocol, payload_hash, src_device, target_device, seq, msg_type, payload, rssi, timestamp, sent, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
             RETURNING id"
        )
        .bind(&frame.protocol)
        .bind(frame.payload_hash as i64)
        .bind(&frame.src_device)
        .bind(&frame.target_device)
        .bind(frame.seq.map(|s| s as i64))
        .bind(&frame.msg_type)
        .bind(&frame.payload)
        .bind(frame.rssi)
        .bind(frame.timestamp)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        debug!("frame inserted: id={} hash={:08x}", id, frame.payload_hash);
        Ok(id)
    }

    pub async fn query_pending(&self, limit: usize) -> Result<Vec<FrameRecord>> {
        let rows = sqlx::query(
            "SELECT protocol, payload_hash, src_device, target_device, seq, msg_type, payload, rssi, timestamp
             FROM frames WHERE sent = 0 ORDER BY created_at ASC LIMIT ?"
        )
        .bind(limit as i64)
        .map(|row: sqlx::sqlite::SqliteRow| FrameRecord {
            protocol: row.get(0),
            payload_hash: row.get(1),
            src_device: row.get(2),
            target_device: row.get(3),
            seq: row.get(4),
            msg_type: row.get(5),
            payload: row.get(6),
            rssi: row.get(7),
            timestamp: row.get(8),
        })
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    pub async fn mark_sent(&self, frame_id: i64) -> Result<()> {
        sqlx::query("UPDATE frames SET sent = 1 WHERE id = ?")
            .bind(frame_id)
            .execute(&self.pool)
            .await?;
        debug!("frame marked sent: id={}", frame_id);
        Ok(())
    }

    pub async fn update_node(&self, node: &NodeRecord) -> Result<()> {
        let now = Utc::now().timestamp_millis();
        let existing = sqlx::query_scalar::<_, i64>("SELECT id FROM nodes WHERE device_id = ?")
            .bind(&node.device_id)
            .fetch_optional(&self.pool)
            .await?;

        if existing.is_some() {
            sqlx::query(
                "UPDATE nodes SET last_seen = ?, rssi = ?, metadata = ? WHERE device_id = ?",
            )
            .bind(now)
            .bind(node.rssi)
            .bind(&node.metadata)
            .bind(&node.device_id)
            .execute(&self.pool)
            .await?;
        } else {
            sqlx::query(
                "INSERT INTO nodes (device_id, last_seen, rssi, metadata) VALUES (?, ?, ?, ?)",
            )
            .bind(&node.device_id)
            .bind(now)
            .bind(node.rssi)
            .bind(&node.metadata)
            .execute(&self.pool)
            .await?;
        }

        debug!("node updated: id={}", node.device_id);
        Ok(())
    }

    pub fn set_nan_active(&mut self, active: bool) {
        if self.nan_active != active {
            info!("NAN mode changed: active={}", active);
            self.nan_active = active;
        }
    }

    pub fn is_nan_active(&self) -> bool {
        self.nan_active
    }

    /// Remove expired frames (older than max_age_hours) and excess frames (beyond max_messages).
    /// Returns (removed_expired, removed_excess) counts.
    pub async fn cleanup_expired(&self) -> Result<(u64, u64)> {
        let now = Utc::now().timestamp_millis();
        let cutoff = now - (self.config.max_age_hours as i64) * 3_600_000;

        // Remove expired frames
        let expired_result = sqlx::query("DELETE FROM frames WHERE created_at < ?")
            .bind(cutoff)
            .execute(&self.pool)
            .await?;
        let removed_expired = expired_result.rows_affected();
        if removed_expired > 0 {
            debug!(
                "removed {} expired frames (older than {}h)",
                removed_expired, self.config.max_age_hours
            );
        }

        // Remove excess frames beyond max_messages (keep newest)
        let excess_count: i64 = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM frames")
            .fetch_one(&self.pool)
            .await?;
        let excess = excess_count.saturating_sub(self.config.max_messages as i64);
        if excess > 0 {
            let removed = sqlx::query(
                "DELETE FROM frames WHERE id NOT IN (
                    SELECT id FROM frames ORDER BY created_at DESC LIMIT ?
                )",
            )
            .bind(self.config.max_messages as i64)
            .execute(&self.pool)
            .await?;
            let removed_excess = removed.rows_affected();
            debug!(
                "removed {} excess frames (max {})",
                removed_excess, self.config.max_messages
            );
            Ok((removed_expired, removed_excess))
        } else {
            Ok((removed_expired, 0))
        }
    }
}

pub trait PlatformAdapter {
    fn power_state(&self) -> PowerState;
    fn inject_frame(&self, frame: FrameRecord);
    fn set_nan_active(&self, active: bool);
    fn pending_outbound(&self) -> Vec<FrameRecord>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PowerState {
    Battery,
    Charging(ChargingSource),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChargingSource {
    Usb,
    Ac,
    Other,
}

pub struct StoreService {
    store: Store,
    tx: mpsc::UnboundedSender<StoreCommand>,
    rx: mpsc::UnboundedReceiver<StoreCommand>,
    cleanup_interval_secs: u64,
}

#[derive(Debug)]
pub enum StoreCommand {
    InsertFrame(FrameRecord),
    UpdateNode(NodeRecord),
    SetNanActive(bool),
    QueryPending(usize),
    MarkSent(i64),
    CleanupExpired,
}

impl StoreService {
    pub async fn new(db_path: &str) -> Result<Self> {
        Self::with_config(db_path, StoreConfig::default()).await
    }

    pub async fn with_config(db_path: &str, config: StoreConfig) -> Result<Self> {
        let store = Store::with_config(db_path, config).await?;
        let (tx, rx) = mpsc::unbounded_channel();
        Ok(Self {
            store,
            tx,
            rx,
            cleanup_interval_secs: 300,
        })
    }

    pub async fn run(mut self) {
        info!("dmesh-store service started");
        let mut cleanup_interval =
            tokio::time::interval(tokio::time::Duration::from_secs(self.cleanup_interval_secs));
        loop {
            tokio::select! {
                _ = cleanup_interval.tick() => {
                    if let Err(e) = self.store.cleanup_expired().await {
                        error!("cleanup failed: {}", e);
                    }
                }
                cmd = self.rx.recv() => {
                    let cmd = match cmd {
                        Some(c) => c,
                        None => break,
                    };
                    match cmd {
                        StoreCommand::InsertFrame(frame) => {
                            if let Err(e) = self.store.insert_frame(&frame).await {
                                error!("failed to insert frame: {}", e);
                            }
                        }
                        StoreCommand::UpdateNode(node) => {
                            if let Err(e) = self.store.update_node(&node).await {
                                error!("failed to update node: {}", e);
                            }
                        }
                        StoreCommand::SetNanActive(active) => {
                            self.store.set_nan_active(active);
                        }
                        StoreCommand::QueryPending(limit) => {
                            let _ = self.store.query_pending(limit).await;
                        }
                        StoreCommand::MarkSent(id) => {
                            if let Err(e) = self.store.mark_sent(id).await {
                                error!("failed to mark sent: {}", e);
                            }
                        }
                        StoreCommand::CleanupExpired => {
                            if let Err(e) = self.store.cleanup_expired().await {
                                error!("cleanup failed: {}", e);
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn sender(&self) -> mpsc::UnboundedSender<StoreCommand> {
        self.tx.clone()
    }
}

pub fn fnv1a32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c_9dc5_u32, |acc, byte| {
        acc.wrapping_mul(16777619) ^ *byte as u32
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a32_consistent() {
        let hash = fnv1a32(b"test payload");
        assert_eq!(hash, 0x3792_093b);
    }

    #[tokio::test]
    async fn store_insert_and_query() {
        let store = Store::new(":memory:").await.unwrap();
        let frame = FrameRecord {
            protocol: "dmesh_nan_followup".to_string(),
            payload_hash: fnv1a32(b"hello"),
            src_device: "010203040506".to_string(),
            target_device: Some("0708090a0b0c".to_string()),
            seq: Some(1),
            msg_type: Some("hello".to_string()),
            payload: b"hello".to_vec(),
            rssi: Some(-50),
            timestamp: Utc::now().timestamp_millis(),
        };
        let id = store.insert_frame(&frame).await.unwrap();
        assert!(id > 0);

        let pending = store.query_pending(10).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].src_device, "010203040506");
    }

    #[tokio::test]
    async fn store_deduplication() {
        let store = Store::new(":memory:").await.unwrap();
        let frame = FrameRecord {
            protocol: "dmesh_nan_followup".to_string(),
            payload_hash: fnv1a32(b"hello"),
            src_device: "010203040506".to_string(),
            target_device: None,
            seq: Some(1),
            msg_type: None,
            payload: b"hello".to_vec(),
            rssi: None,
            timestamp: Utc::now().timestamp_millis(),
        };
        let id1 = store.insert_frame(&frame).await.unwrap();
        let id2 = store.insert_frame(&frame).await.unwrap();
        assert_eq!(id1, id2);

        let pending = store.query_pending(10).await.unwrap();
        assert_eq!(pending.len(), 1);
    }

    #[tokio::test]
    async fn store_cleanup_expired() {
        let config = StoreConfig {
            max_age_hours: 24,
            max_messages: 5,
        };
        let store = Store::with_config(":memory:", config).await.unwrap();

        for i in 0..8 {
            let frame = FrameRecord {
                protocol: "dmesh_nan_followup".to_string(),
                payload_hash: fnv1a32(&format!("msg{}", i).as_bytes()),
                src_device: "010203040506".to_string(),
                target_device: None,
                seq: Some(i as u16),
                msg_type: None,
                payload: format!("msg{}", i).into_bytes(),
                rssi: None,
                timestamp: Utc::now().timestamp_millis(),
            };
            store.insert_frame(&frame).await.unwrap();
        }

        let before = store.query_pending(100).await.unwrap();
        assert_eq!(before.len(), 8);

        let (expired, excess) = store.cleanup_expired().await.unwrap();
        assert_eq!(expired, 0);
        assert_eq!(excess, 3);

        let after = store.query_pending(100).await.unwrap();
        assert_eq!(after.len(), 5);
    }
}
