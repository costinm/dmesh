//! Append-only operator audit, shared JSONL schema with flash-device.py.
use std::{cell::RefCell, fs::OpenOptions, io::Write, path::{Path, PathBuf}, time::{Duration, SystemTime, UNIX_EPOCH}};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

thread_local! { static ACTIVE: RefCell<Option<Value>> = const { RefCell::new(None) }; }

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

pub(crate) fn path() -> PathBuf {
    if let Some(path) = std::env::var_os("DMESH_FLASH_AUDIT_LOG") { return path.into(); }
    let root = std::env::var_os("XDG_STATE_HOME").map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/state"));
    root.join("dmesh/flash.jsonl")
}

fn append(path: &Path, record: &Value) -> std::io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let mut bytes = serde_json::to_vec(record)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    // Closing the descriptor releases the lock, also on an error/unwind.
    file.write_all(&bytes)?;
    file.sync_data()
}

fn emit(record: &Value) {
    if let Err(error) = append(&path(), record) {
        eprintln!("flash_log error={error} path={}", path().display());
    }
}

pub(crate) struct Attempt;

pub(crate) fn begin(device: &str, target: &str, dry_run: bool, artifact: Option<&str>, completion_scope: &str) -> Option<Attempt> {
    ACTIVE.with(|active| {
        let mut active = active.borrow_mut();
        if active.is_some() { return None; }
        let timestamp = now_ms();
        let record = json!({"schema":1, "attempt_id":format!("{}-{timestamp}",std::process::id()),
            "event":"started", "timestamp_unix_ms":timestamp, "device":device,
            "target":target, "dry_run":dry_run, "artifact":artifact, "completion_scope":completion_scope,
            "method":null, "bytes":null, "transfer_ms":null, "transfer_success":null});
        emit(&record);
        *active = Some(record);
        Some(Attempt)
    })
}

pub(crate) fn image(method: &str, artifact: Option<&Path>, bytes: &[u8]) {
    ACTIVE.with(|active| {
        if let Some(record) = active.borrow_mut().as_mut() {
            record["method"] = json!(method);
            if let Some(path) = artifact { record["artifact"] = json!(path); }
            record["bytes"] = json!(bytes.len());
            record["sha256"] = json!(crate::client::hex_encode(&Sha256::digest(bytes)));
            let mut snapshot = record.clone();
            snapshot["event"] = json!("image_selected");
            snapshot["timestamp_unix_ms"] = json!(now_ms());
            if snapshot["attempt_id"].is_string() { emit(&snapshot); }
        }
    });
}

pub(crate) fn transfer(elapsed: Duration, success: bool) {
    ACTIVE.with(|active| {
        if let Some(record) = active.borrow_mut().as_mut() {
            record["transfer_ms"] = json!(elapsed.as_secs_f64() * 1000.0);
            record["transfer_success"] = json!(success);
            let mbps = record["bytes"].as_u64().filter(|_| success && !elapsed.is_zero())
                .map(|n| n as f64 * 8.0 / elapsed.as_secs_f64() / 1_000_000.0);
            record["mbps"] = json!(mbps);
        }
    });
}

impl Attempt {
    pub(crate) fn finish(self, result: &Result<(), String>) {
        end(result.as_ref().err().map(String::as_str));
    }
}

fn end(error: Option<&str>) {
    ACTIVE.with(|active| {
        if let Some(mut record) = active.borrow_mut().take() {
            let timestamp = now_ms();
            record["elapsed_ms"] = json!(timestamp.saturating_sub(record["timestamp_unix_ms"].as_u64().unwrap_or(timestamp)));
            record["timestamp_unix_ms"] = json!(timestamp);
            record["event"] = json!("finished");
            record["success"] = json!(error.is_none());
            record["error"] = json!(error);
            emit(&record);
        }
    });
}

impl Drop for Attempt {
    fn drop(&mut self) { end(Some("attempt interrupted before completion")); }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn appends_parseable_records_and_preserves_prior_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/flash.jsonl");
        append(&path, &json!({"method":"quic_udp", "success":true})).unwrap();
        append(&path, &json!({"method":"espflash", "success":false})).unwrap();
        let records: Vec<Value> = std::fs::read_to_string(path).unwrap().lines()
            .map(|line| serde_json::from_str(line).unwrap()).collect();
        assert_eq!(records.len(),2);
        assert_eq!(records[1]["method"],"espflash");
    }

    #[test]
    fn failed_transfer_has_no_completed_speed() {
        ACTIVE.with(|active| *active.borrow_mut() = Some(json!({"dry_run":true})));
        image("quic_udp", Some(Path::new("main.bin")), b"test image");
        transfer(Duration::from_secs(1), false);
        let record = ACTIVE.with(|active| active.borrow_mut().take().unwrap());
        assert_eq!(record["bytes"],10);
        assert_eq!(record["sha256"].as_str().unwrap().len(),64);
        assert_eq!(record["transfer_success"],false);
        assert!(record["mbps"].is_null());
    }

    #[test]
    fn concurrent_appenders_do_not_interleave_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flash.jsonl");
        std::thread::scope(|scope| {
            for worker in 0..4 {
                let path = &path;
                scope.spawn(move || for sequence in 0..25 {
                    append(path,&json!({"worker":worker,"sequence":sequence})).unwrap();
                });
            }
        });
        let content = std::fs::read_to_string(path).unwrap();
        assert_eq!(content.lines().count(),100);
        for line in content.lines() { serde_json::from_str::<Value>(line).unwrap(); }
    }
}
