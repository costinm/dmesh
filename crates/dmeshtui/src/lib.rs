use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    User,
    Assistant,
    System,
}

#[derive(Debug, Clone)]
pub struct Message {
    pub role: Role,
    pub content: String,
    pub raw_response: Option<String>,
    pub timestamp_ms: u128,
}

#[derive(Debug, Clone)]
pub struct Conversation {
    pub service: String,
    pub messages: Vec<Message>,
    pub created_ms: u128,
}

impl Conversation {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            messages: Vec::new(),
            created_ms: now_ms(),
        }
    }

    pub fn push(&mut self, role: Role, content: impl Into<String>) {
        self.messages.push(Message {
            role,
            content: content.into(),
            raw_response: None,
            timestamp_ms: now_ms(),
        });
    }

    pub fn push_response(&mut self, content: impl Into<String>, raw: impl Into<String>) {
        self.messages.push(Message {
            role: Role::Assistant,
            content: content.into(),
            raw_response: Some(raw.into()),
            timestamp_ms: now_ms(),
        });
    }
}

#[derive(Debug)]
pub struct UiModel {
    pub title: String,
    pub input: String,
    pub conversation: Conversation,
    pub conversations: VecDeque<Conversation>,
    pub max_messages: usize,
    pub active_service: String,
    pub show_palette: bool,
    pub scroll_offset: usize,
}

impl UiModel {
    pub fn new(title: impl Into<String>) -> Self {
        let mut conv = Conversation::new("local");
        conv.push(
            Role::System,
            "dmeshtui ready. Ctrl-P=commands, Ctrl-Tab=switch service, /help for keys.",
        );
        Self {
            title: title.into(),
            input: String::new(),
            conversation: conv,
            conversations: VecDeque::new(),
            max_messages: 512,
            active_service: "local".to_string(),
            show_palette: false,
            scroll_offset: 0,
        }
    }

    pub fn push_system(&mut self, content: impl Into<String>) {
        self.conversation.push(Role::System, content);
        self.scroll_offset = 0;
        self.trim_conversation();
    }

    pub fn push_user(&mut self, content: impl Into<String>) {
        self.conversation.push(Role::User, content);
        self.scroll_offset = 0;
        self.trim_conversation();
    }

    pub fn push_response(&mut self, content: impl Into<String>, raw: impl Into<String>) {
        self.conversation.push_response(content, raw);
        self.scroll_offset = 0;
        self.trim_conversation();
    }

    pub fn push_error(&mut self, content: impl Into<String>) {
        let text = content.into();
        self.conversation
            .push(Role::Assistant, format!("error: {}", text));
        self.scroll_offset = 0;
        self.trim_conversation();
    }

    fn trim_conversation(&mut self) {
        let total: usize = self
            .conversations
            .iter()
            .map(|c| c.messages.len())
            .sum::<usize>()
            + self.conversation.messages.len();
        if total > self.max_messages {
            let excess = total - self.max_messages;
            self.trim_old(excess);
        }
    }

    fn trim_old(&mut self, mut excess: usize) {
        while excess > 0 && !self.conversations.is_empty() {
            let front = &mut self.conversations[0];
            let remove = excess.min(front.messages.len());
            front.messages.drain(0..remove);
            excess -= remove;
            if front.messages.is_empty() {
                self.conversations.pop_front();
            }
        }
        if excess > 0 {
            self.conversation.messages.drain(0..excess);
        }
    }

    pub fn cycle_service(&mut self, services: &[commands::ServiceInfo]) {
        if services.is_empty() {
            return;
        }
        let idx = services
            .iter()
            .position(|s| s.name == self.active_service)
            .map(|i| (i + 1) % services.len())
            .unwrap_or(0);
        self.active_service = services[idx].name.clone();
    }

    pub fn submit_current<C: MeshClient + ?Sized>(&mut self, client: &mut C) {
        let line = self.input.trim().to_owned();
        if line.is_empty() {
            return;
        }
        self.handle_command(&line, client);
    }

    pub fn handle_command<C: MeshClient + ?Sized>(&mut self, line: &str, client: &mut C) {
        if line == "/help" || line == "help" {
            self.push_system(HELP_TEXT);
            self.input.clear();
            return;
        }
        if line == "/quit" {
            std::process::exit(0);
        }
        if line == "/sessions" {
            let count = self.conversations.len();
            self.push_system(format!("{} saved conversations in memory", count));
            self.input.clear();
            return;
        }
        if line == "/save" {
            self.save_conversation();
            self.input.clear();
            return;
        }

        self.push_user(line);
        self.input.clear();

        match client.send_command(line) {
            Ok(reply) if reply.is_empty() => {}
            Ok(reply) => {
                let formatted = format_response(&reply);
                self.push_response(formatted, reply);
            }
            Err(err) => self.push_error(err.to_string()),
        }
    }

    fn save_conversation(&mut self) {
        let dir = std::path::Path::new(".dmeshtui/sessions");
        if let Err(e) = std::fs::create_dir_all(dir) {
            self.push_error(format!("Failed to create sessions dir: {}", e));
            return;
        }
        let ts = self
            .conversation
            .created_ms
            .to_string();
        let path = dir.join(format!("{}.jsonl", ts));
        let mut out = String::new();
        for msg in &self.conversation.messages {
            let role = match msg.role {
                Role::User => "user",
                Role::Assistant => "assistant",
                Role::System => "system",
            };
            let entry = serde_json::json!({
                "role": role,
                "content": &msg.content,
                "timestamp_ms": msg.timestamp_ms,
            });
            if let Ok(line) = serde_json::to_string(&entry) {
                out.push_str(&line);
                out.push('\n');
            }
        }
        match std::fs::write(&path, &out) {
            Ok(_) => self.push_system(format!("Saved to {}", path.display())),
            Err(e) => self.push_error(format!("Save failed: {}", e)),
        }
    }
}

fn format_response(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
        return render::render_json_flat(&val);
    }
    trimmed.to_string()
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

pub const HELP_TEXT: &str = "DMesh TUI Help
Enter        - Send command
Up/Down      - Scroll message history
Ctrl-P       - Command palette (fuzzy search)
Ctrl-N       - Cycle active service
Tab          - Cycle active service
Esc          - Close palette
/help        - Show this help
/save        - Save current conversation
/sessions    - List saved conversations
/quit        - Exit
Ctrl-Q       - Exit";

pub mod browser;
pub mod commands;
pub mod render;

#[cfg(feature = "terminal")]
pub mod local;

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default()
}
