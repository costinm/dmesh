use anyhow::Result;

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
        if dmesh_fw_transport::task_esp::schedule_restart_ms(100) {
            Ok(CommandResponse::ok("reset scheduled"))
        } else {
            Ok(CommandResponse::error("reset scheduler unavailable"))
        }
    }
}
