use anyhow::{anyhow, Result};
use esp_idf_sys as sys;

use crate::commands::protocol::quote_text_value;
use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

use super::settings::SharedSettings;

struct NvsCommand {
    name: &'static str,
    settings: SharedSettings,
}

impl NvsCommand {
    fn new(name: &'static str, settings: SharedSettings) -> Self {
        Self { name, settings }
    }
}

pub fn register_commands(registry: &mut CommandRegistry, settings: SharedSettings) {
    registry.register(NvsCommand::new("nvs", settings.clone()));
    registry.register(NvsCommand::new("namespace", settings.clone()));
    registry.register(NvsCommand::new("set", settings.clone()));
    registry.register(NvsCommand::new("get", settings.clone()));
    registry.register(NvsCommand::new("list", settings));
}

impl CommandHandler for NvsCommand {
    fn name(&self) -> &'static str {
        self.name
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        match self.name {
            "nvs" => self.handle_grouped(request),
            "list" if request.arg("stats").is_some() => nvs_stats(),
            "namespace" => self.namespace(),
            "set" => self.set_values(request, 0),
            "get" => self.get_value(request, 0),
            "list" => self.list_values(),
            _ => Ok(CommandResponse::error("invalid nvs command")),
        }
    }
}

impl NvsCommand {
    fn handle_grouped(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        match request
            .positional(0)
            .or_else(|| request.arg("op"))
            .or_else(|| request.arg("cmd"))
            .unwrap_or("list")
        {
            "ns" | "namespace" => self.namespace(),
            "set" => self.set_values(request, 1),
            "get" => self.get_value(request, 1),
            "list" => {
                if request.arg("stats").is_some() {
                    nvs_stats()
                } else {
                    self.list_values()
                }
            }
            other => Err(anyhow!("unknown nvs subcommand: {other}")),
        }
    }

    fn namespace(&self) -> Result<CommandResponse> {
        let settings = self.settings.borrow();
        Ok(CommandResponse::ok(format!(
            "namespace {}",
            settings.namespace()
        )))
    }

    fn set_values(
        &mut self,
        request: &CommandRequest,
        positional_skip: usize,
    ) -> Result<CommandResponse> {
        let mut pairs = Vec::new();
        if let (Some(key), Some(value)) = (request.arg("key"), request.arg("value")) {
            pairs.push((key, value));
        } else if let (Some(key), Some(value)) = (
            request.positional(positional_skip),
            request.positional(positional_skip + 1),
        ) {
            pairs.push((key, value));
        }
        for (&tag, value) in &request.args {
            if let Some(key_str) = nvs_key(tag) {
                pairs.push((key_str, value.as_str()));
            }
        }
        if pairs.is_empty() {
            return Err(anyhow!("set requires KEY VALUE or key=KEY value=VALUE"));
        }

        let mut settings = self.settings.borrow_mut();
        let mut changed = Vec::new();
        for (key, value) in pairs {
            settings.set_str(key, value)?;
            log::info!("setting set: key={} value={}", key, value);
            changed.push(key.to_string());
        }
        Ok(CommandResponse::ok(format!("set {}", changed.join(","))))
    }

    fn get_value(
        &self,
        request: &CommandRequest,
        positional_skip: usize,
    ) -> Result<CommandResponse> {
        let key = request
            .positional(positional_skip)
            .or_else(|| request.arg("key"))
            .ok_or_else(|| anyhow!("get requires KEY"))?;
        let value = self.settings.borrow().get_str(key)?.unwrap_or_default();
        Ok(CommandResponse::ok(format!(
            "{key}={}",
            quote_text_value(&value)
        )))
    }

    fn list_values(&self) -> Result<CommandResponse> {
        let settings = self.settings.borrow();
        let mut values = Vec::new();
        for key in settings.known_keys() {
            if let Some(value) = settings.get_str(key)? {
                values.push(format!("{key}={}", quote_text_value(&value)));
            }
        }
        Ok(CommandResponse::ok(values.join(" ")))
    }
}

fn nvs_stats() -> Result<CommandResponse> {
    // Current 4 MB ESP32 partition table gives NVS 0x6000 bytes (24 KiB).
    // On the paired TLORA test unit this reports 756 total entries, with
    // 228 used and 402 available after companion/LoRa settings are saved.
    let mut stats = sys::nvs_stats_t {
        used_entries: 0,
        free_entries: 0,
        available_entries: 0,
        total_entries: 0,
        namespace_count: 0,
    };
    let ret = unsafe { sys::nvs_get_stats(core::ptr::null(), &mut stats) };
    if ret != sys::ESP_OK {
        return Err(anyhow!("nvs_get_stats failed ret=0x{ret:x}"));
    }
    Ok(CommandResponse::ok(format!(
        "nvs used_entries={} free_entries={} available_entries={} total_entries={} namespaces={}",
        stats.used_entries,
        stats.free_entries,
        stats.available_entries,
        stats.total_entries,
        stats.namespace_count
    )))
}

fn nvs_key(tag: u16) -> Option<&'static str> {
    Some(match tag {
        42 => "mode",
        150 => "wifi.mode",
        151 => "power.profile",
        152 => "nan.backend",
        153 => "nan.boot",
        154 => "nan.role",
        155 => "nan.service",
        156 => "nan.channel",
        157 => "nan.wake_ms",
        158 => "nan.active_ms",
        159 => "nan.light_sleep",
        160 => "nan.early_ms",
        161 => "nan.dw_tu",
        162 => "nan.dw_off_tu",
        163 => "battery.divider",
        164 => "battery.mult",
        165 => "ble.peer",
        166 => "identity.node",
        167 => "identity.meshtastic",
        301 => "lora.enabled",
        380 => "nan.sync_source",
        381 => "nan.ap_owner",
        382 => "nan.ap_loss_ms",
        383 => "nan.ap_recovery_ms",
        384 => "nan.ap_recovery_listen_ms",
        385 => "nan.ap_slot_tu",
        386 => "nan.ap_beacon_tu",
        387 => "uart.hb_every",
        _ => return None,
    })
}
