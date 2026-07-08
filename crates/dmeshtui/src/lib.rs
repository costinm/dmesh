use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MeshEventKind {
    Info,
    Inbound,
    Outbound,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeshEvent {
    pub kind: MeshEventKind,
    pub text: String,
    pub timestamp_ms: u128,
}

impl MeshEvent {
    pub fn new(kind: MeshEventKind, text: impl Into<String>) -> Self {
        Self {
            kind,
            text: text.into(),
            timestamp_ms: now_ms(),
        }
    }
}

#[derive(Debug)]
pub struct UiModel {
    pub title: String,
    pub input: String,
    pub events: Vec<MeshEvent>,
}

impl UiModel {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            input: String::new(),
            events: vec![MeshEvent::new(
                MeshEventKind::Info,
                "dmeshtui ready. Type a mesh method or /quit.",
            )],
        }
    }

    pub fn push(&mut self, kind: MeshEventKind, text: impl Into<String>) {
        self.events.push(MeshEvent::new(kind, text));
        if self.events.len() > 512 {
            let extra = self.events.len() - 512;
            self.events.drain(0..extra);
        }
    }

    pub fn submit_current<C: MeshClient + ?Sized>(&mut self, client: &mut C) {
        let line = self.input.trim().to_owned();
        if line.is_empty() {
            return;
        }
        self.push(MeshEventKind::Outbound, line.clone());
        self.input.clear();
        match client.send_command(&line) {
            Ok(reply) if reply.is_empty() => {}
            Ok(reply) => self.push(MeshEventKind::Inbound, reply),
            Err(err) => self.push(MeshEventKind::Error, err.to_string()),
        }
    }
}

pub trait MeshClient {
    fn send_command(&mut self, line: &str) -> anyhow::Result<String>;
    fn poll(&mut self) -> anyhow::Result<Vec<String>> {
        Ok(Vec::new())
    }
}

#[derive(Default)]
pub struct MemoryMeshClient {
    sent: Vec<String>,
}

impl MemoryMeshClient {
    pub fn sent(&self) -> &[String] {
        &self.sent
    }
}

impl MeshClient for MemoryMeshClient {
    fn send_command(&mut self, line: &str) -> anyhow::Result<String> {
        self.sent.push(line.to_owned());
        Ok(format!("queued locally: {line}"))
    }
}

#[cfg(feature = "terminal")]
pub mod local;

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default()
}
