use std::collections::BTreeMap;

use anyhow::{anyhow, Result};

pub mod protocol;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandRequest {
    pub method: u16,
    pub name: String,
    pub args: BTreeMap<u16, String>,
    pub positionals: Vec<String>,
    pub payload: Vec<u8>,
    pub is_binary: bool,
}

impl CommandRequest {
    pub fn new(name: impl Into<String>) -> Self {
        let name_str = name.into();
        let method = crate::commands::protocol::command_id(&name_str).unwrap_or(0);
        Self {
            method,
            name: name_str,
            args: BTreeMap::new(),
            positionals: Vec::new(),
            payload: Vec::new(),
            is_binary: false,
        }
    }

    pub fn new_binary(method: u16) -> Self {
        let name = crate::commands::protocol::command_name(method)
            .unwrap_or("unknown")
            .to_string();
        Self {
            method,
            name,
            args: BTreeMap::new(),
            positionals: Vec::new(),
            payload: Vec::new(),
            is_binary: true,
        }
    }

    #[allow(dead_code)]
    pub fn arg_pair(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let key_str = key.into();
        if let Some(tag) = crate::commands::protocol::arg_tag(&key_str) {
            self.args.insert(tag, value.into());
        }
        self
    }

    #[allow(dead_code)]
    pub fn arg_pair_by_tag(mut self, tag: u16, value: impl Into<String>) -> Self {
        self.args.insert(tag, value.into());
        self
    }

    pub fn arg(&self, key: &str) -> Option<&str> {
        let tag = crate::commands::protocol::arg_tag(key)?;
        self.arg_by_tag(tag)
    }

    pub fn arg_by_tag(&self, tag: u16) -> Option<&str> {
        self.args.get(&tag).map(String::as_str)
    }

    pub fn positional(&self, index: usize) -> Option<&str> {
        self.positionals.get(index).map(String::as_str)
    }

    pub fn arg_i32(&self, key: &str) -> Result<Option<i32>> {
        self.arg(key)
            .map(|value| {
                value
                    .parse::<i32>()
                    .map_err(|err| anyhow!("invalid {key}={value}: {err}"))
            })
            .transpose()
    }

    #[allow(dead_code)]
    pub fn arg_i32_by_tag(&self, tag: u16) -> Result<Option<i32>> {
        self.arg_by_tag(tag)
            .map(|value| {
                value
                    .parse::<i32>()
                    .map_err(|err| anyhow!("invalid tag {tag}={value}: {err}"))
            })
            .transpose()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandResponse {
    pub status: CommandStatus,
    pub message: String,
    pub payload: Vec<u8>,
}

impl CommandResponse {
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            status: CommandStatus::Ok,
            message: message.into(),
            payload: Vec::new(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            status: CommandStatus::Error,
            message: message.into(),
            payload: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandStatus {
    Ok,
    Error,
}

pub trait CommandHandler {
    fn name(&self) -> &'static str;
    fn method_id(&self) -> u16 {
        crate::commands::protocol::command_id(self.name()).unwrap_or(0)
    }
    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse>;
}

pub struct CommandRegistry {
    handlers: Vec<Box<dyn CommandHandler>>,
}

impl CommandRegistry {
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    pub fn register<H>(&mut self, handler: H)
    where
        H: CommandHandler + 'static,
    {
        self.handlers.push(Box::new(handler));
    }

    pub fn dispatch(&mut self, request: &CommandRequest) -> CommandResponse {
        match self
            .handlers
            .iter_mut()
            .find(|handler| handler.method_id() == request.method)
        {
            Some(handler) => handler
                .handle(request)
                .unwrap_or_else(|err| CommandResponse::error(err.to_string())),
            None => CommandResponse::error(format!("unknown command id: {}", request.method)),
        }
    }
}
