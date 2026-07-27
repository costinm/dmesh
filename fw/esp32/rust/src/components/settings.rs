use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use anyhow::{anyhow, Result};
use esp_idf_svc::nvs::{EspDefaultNvs, EspDefaultNvsPartition};

pub type SharedSettings = Rc<RefCell<Settings>>;

const NAMESPACE: &str = "dmesh";
const STRING_BUF_LEN: usize = 128;

pub fn open_shared() -> SharedSettings {
    Rc::new(RefCell::new(Settings::open()))
}

pub struct Settings {
    nvs: Option<EspDefaultNvs>,
    cache: BTreeMap<String, String>,
    known_keys: Vec<&'static str>,
}

impl Settings {
    pub fn open() -> Self {
        let nvs = EspDefaultNvsPartition::take()
            .and_then(|partition| EspDefaultNvs::new(partition, NAMESPACE, true))
            .map_err(|err| {
                log::warn!("NVS unavailable for settings, using volatile cache: {err}");
                err
            })
            .ok();

        Self {
            nvs,
            cache: BTreeMap::new(),
            known_keys: vec![
                "battery.enabled",
                "battery.pin",
                "battery.divider",
                "battery.mult",
                "battery.ctrl",
                "battery.ctl_lvl",
                "battery.ref_mv",
                "battery.min_mv",
                "battery.max_mv",
                "ble.comp",
                "ble.comp.ble",
                "ble.comp.adv_period_ms",
                "ble.comp.adv_window_ms",
                "ble.comp.active_ms",
                "ble.comp.ble_scan",
                "ble.comp.channel",
                "ble.comp.nan",
                "ble.comp.ps",
                "ble.comp.raw",
                "ble.comp.serial",
                "ble.comp.wifi",
                "ble.fixed_pin",
                "bc.active_ms",
                "bc.wake_ms",
                "bc.win_ms",
                "bc.phase_ms",
                "ble.peer",
                "button.enabled",
                "button.gpio",
                "i2c.port",
                "i2c.sda",
                "i2c.scl",
                "i2c.freq",
                "identity.meshtastic",
                "identity.meshcore",
                "identity.node",
                "identity.pubkey",
                "identity.raw",
                "log.depth",
                "local_msg.depth",
                "lora.chip",
                "lora.freq",
                "lora.beacon",
                "lora.enabled",
                "lora.bw",
                "lora.channel_hash",
                "lora.crc",
                "lora.hop_limit",
                "lora.preamble",
                "lora.portnum",
                "lora.spi_host",
                "lora.sck",
                "lora.miso",
                "lora.mosi",
                "lora.cs",
                "lora.rst",
                "lora.dio0",
                "lora.busy",
                "lora.pwrpin",
                "lora.pwrlvl",
                "lora.dio2rf",
                "lora.tcxo_mv",
                "lora.pa_duty",
                "lora.pa_hp",
                "lora.pa_dev",
                "lora.pa_lut",
                "lora.rx_timeout",
                "lora.sx_sync",
                "lora.sf",
                "lora.cr",
                "lora.sync_word",
                "lora.mode",
                "lora.tx_power",
                "msg.depth",
                "mode",
                "wifi.mode",
                "wifi.ssid",
                "cm.adv_ms",
                "cm.win_ms",
                "cm.boot_ms",
                "cm.active_ms",
                "cm.pending_ms",
                "cm.pending_adv_ms",
                "cm.wake_ms",
                "cm.lora",
                "nan.active_ms",
                "nan.ap_beacon_tu",
                "nan.ap_loss_ms",
                "nan.ap_owner",
                "nan.ap_recovery_listen_ms",
                "nan.ap_recovery_ms",
                "nan.ap_slot_tu",
                "nan.backend",
                "nan.boot",
                "nan.channel",
                "nan.dw_off_tu",
                "nan.dw_tu",
                "nan.enabled",
                "nan.light_sleep",
                "nan.role",
                "nan.service",
                "nan.sync_source",
                "nan.early_ms",
                "nan.wake_ms",
                "power.profile",
                "uart.active_ms",
                "uart.hb_every",
            ],
        }
    }

    pub fn namespace(&self) -> &'static str {
        NAMESPACE
    }

    pub fn known_keys(&self) -> &[&'static str] {
        &self.known_keys
    }

    pub fn get_str(&self, key: &str) -> Result<Option<String>> {
        if let Some(value) = self.cache.get(key) {
            return Ok(Some(value.clone()));
        }

        if let Some(nvs) = &self.nvs {
            let mut buf = [0_u8; STRING_BUF_LEN];
            if let Some(value) = nvs.get_str(storage_key(key), &mut buf)? {
                return Ok(Some(value.to_string()));
            }
        }

        Ok(None)
    }

    pub fn set_str(&mut self, key: &str, value: &str) -> Result<()> {
        validate_key(storage_key(key))?;
        validate_value(value)?;
        let heartbeat_every = if key == "uart.hb_every" {
            let every = parse_i32(value)?;
            if every < 0 {
                return Err(anyhow!("uart.hb_every must be zero or positive"));
            }
            Some(every as u32)
        } else {
            None
        };
        if let Some(nvs) = &mut self.nvs {
            nvs.set_str(storage_key(key), value)?;
        }
        self.cache.insert(key.to_string(), value.to_string());
        if let Some(every) = heartbeat_every {
            super::serial::set_heartbeat_every(every);
        }
        super::telemetry::record_log(format!(
            "ev=nvs.set key={} value={}",
            key,
            crate::commands::protocol::quote_text_value(value)
        ));
        Ok(())
    }

    pub fn get_i32(&self, key: &str, default: i32) -> Result<i32> {
        match self.get_str(key)? {
            Some(value) => parse_i32(&value),
            None => Ok(default),
        }
    }

    pub fn set_i32(&mut self, key: &str, value: i32) -> Result<()> {
        self.set_str(key, &value.to_string())
    }

    pub fn get_bool(&self, key: &str, default: bool) -> Result<bool> {
        match self.get_str(key)? {
            Some(value) => parse_bool(&value),
            None => Ok(default),
        }
    }

    pub fn set_bool(&mut self, key: &str, value: bool) -> Result<()> {
        self.set_str(key, if value { "true" } else { "false" })
    }
}

/// ESP-IDF NVS keys are limited to 15 bytes. Keep public settings descriptive
/// and map only the overlong Wi-Fi fallback keys at the persistence boundary.
fn storage_key(key: &str) -> &str {
    match key {
        "nan.ap_beacon_tu" => "nap_beacon",
        "nan.ap_recovery_ms" => "nap_recover",
        "nan.ap_recovery_listen_ms" => "nap_listen",
        _ => key,
    }
}

pub fn parse_i32(value: &str) -> Result<i32> {
    if let Some(hex) = value.strip_prefix("0x") {
        i32::from_str_radix(hex, 16).map_err(|err| anyhow!("invalid hex integer {value}: {err}"))
    } else {
        value
            .parse::<i32>()
            .map_err(|err| anyhow!("invalid integer {value}: {err}"))
    }
}

pub fn parse_bool(value: &str) -> Result<bool> {
    match value {
        "1" | "true" | "on" | "yes" => Ok(true),
        "0" | "false" | "off" | "no" => Ok(false),
        _ => Err(anyhow!("invalid boolean {value}")),
    }
}

fn validate_key(key: &str) -> Result<()> {
    if key.is_empty() || key.len() > 15 {
        return Err(anyhow!("NVS key must be 1..15 bytes"));
    }
    if !key
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'_')
    {
        return Err(anyhow!("NVS key contains unsupported characters"));
    }
    Ok(())
}

fn validate_value(value: &str) -> Result<()> {
    if value.len() >= STRING_BUF_LEN {
        return Err(anyhow!("setting value is too long"));
    }
    Ok(())
}
