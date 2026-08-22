use anyhow::{anyhow, bail, Result};
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

pub fn register_commands(registry: &mut CommandRegistry) {
    registry.register(GpioCommand);
}

struct GpioCommand;

impl CommandHandler for GpioCommand {
    fn name(&self) -> &'static str {
        "gpio"
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        let pin = request
            .arg_i32("pin")?
            .ok_or_else(|| anyhow!("gpio requires pin=N"))?;
        validate_pin(pin)?;
        let mode = request.arg("mode").unwrap_or("output");
        let open_drain = request
            .arg("open_drain")
            .map(super::settings::parse_bool)
            .transpose()?
            .unwrap_or(false);
        let gpio_mode = match (mode, open_drain) {
            ("input", false) => sys::gpio_mode_t_GPIO_MODE_INPUT,
            ("input", true) => sys::gpio_mode_t_GPIO_MODE_INPUT,
            ("output", false) => sys::gpio_mode_t_GPIO_MODE_INPUT_OUTPUT,
            ("output", true) => sys::gpio_mode_t_GPIO_MODE_INPUT_OUTPUT_OD,
            ("disabled", _) | ("disable", _) => sys::gpio_mode_t_GPIO_MODE_DISABLE,
            _ => bail!("unsupported gpio mode {mode}"),
        };

        unsafe {
            esp_ok(sys::gpio_reset_pin(pin))?;
            esp_ok(sys::gpio_set_direction(pin, gpio_mode))?;
        }

        match request.arg("pull").unwrap_or("none") {
            "none" => unsafe {
                esp_ok(sys::gpio_pullup_dis(pin))?;
                esp_ok(sys::gpio_pulldown_dis(pin))?;
            },
            "up" | "pullup" => unsafe {
                esp_ok(sys::gpio_pullup_en(pin))?;
                esp_ok(sys::gpio_pulldown_dis(pin))?;
            },
            "down" | "pulldown" => unsafe {
                esp_ok(sys::gpio_pullup_dis(pin))?;
                esp_ok(sys::gpio_pulldown_en(pin))?;
            },
            pull => bail!("unsupported gpio pull {pull}"),
        }

        if let Some(level) = request.arg_i32("level")? {
            if matches!(mode, "output") {
                unsafe {
                    esp_ok(sys::gpio_set_level(pin, if level == 0 { 0 } else { 1 }))?;
                }
            }
        }
        let level = unsafe { sys::gpio_get_level(pin) };
        log::info!("gpio command: pin={pin} mode={mode} level={level}");
        Ok(CommandResponse::ok(format!(
            "gpio pin={pin} mode={mode} level={level} open_drain={open_drain}"
        )))
    }
}

fn validate_pin(pin: i32) -> Result<()> {
    if pin < 0 || pin > max_gpio_pin() {
        bail!("invalid ESP32 GPIO pin {pin}");
    }
    #[cfg(target_feature = "esp32s3ops")]
    if pin == 22 || pin == 23 || pin == 24 || pin == 25 {
        bail!("GPIO{pin} is not exposed on ESP32-S3");
    }
    #[cfg(not(target_feature = "esp32s3ops"))]
    if (34..=39).contains(&pin) {
        log::warn!("GPIO{pin} is input-only on classic ESP32");
    }
    Ok(())
}

fn max_gpio_pin() -> i32 {
    #[cfg(target_feature = "esp32s3ops")]
    {
        48
    }
    #[cfg(not(target_feature = "esp32s3ops"))]
    {
        39
    }
}

fn esp_ok(ret: sys::esp_err_t) -> Result<()> {
    if ret == sys::ESP_OK {
        Ok(())
    } else {
        bail!("esp_err=0x{ret:x}")
    }
}
