use std::thread;
use std::time::Duration;

use anyhow::Result;
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

/// Register the runtime reset command. This is a firmware reset, not a
/// modem-line operation; bootloader/recovery selection remains esptool-owned.
pub fn register_commands(registry: &mut CommandRegistry) {
    registry.register(ResetCommand);
}

struct ResetCommand;

impl CommandHandler for ResetCommand {
    fn name(&self) -> &'static str {
        "reset"
    }

    fn handle(&mut self, _request: &CommandRequest) -> Result<CommandResponse> {
        thread::spawn(|| {
            thread::sleep(Duration::from_millis(100));
            unsafe { sys::esp_restart() };
        });
        Ok(CommandResponse::ok("reset scheduled"))
    }
}
