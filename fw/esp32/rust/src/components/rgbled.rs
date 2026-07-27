use anyhow::{anyhow, bail, Result};
use libc::{c_int, c_uchar};

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

unsafe extern "C" {
    fn dmesh_ws2812_write(gpio: c_uchar, red: c_uchar, green: c_uchar, blue: c_uchar) -> c_int;
}

// RGB Led is present on some dev boards and uses a lot of current - this code
// is meant to turn it off, not to use it. BLE/NAN and android notifications
// are used to communicate in STA - not LEDs.
pub fn register_commands(registry: &mut CommandRegistry) {
    registry.register(RgbLedCommand);
}

struct RgbLedCommand;

impl CommandHandler for RgbLedCommand {
    fn name(&self) -> &'static str {
        "rgbled"
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        let pin = request
            .arg_i32("pin")?
            .ok_or_else(|| anyhow!("rgbled requires pin=N"))?;
        validate_pin(pin)?;

        let off = request
            .arg("off")
            .or_else(|| request.arg("disable"))
            .map(super::settings::parse_bool)
            .transpose()?
            .unwrap_or(false);
        let (red, green, blue) = if off {
            (0, 0, 0)
        } else {
            (
                color_arg(request, "r")?,
                color_arg(request, "g")?,
                color_arg(request, "b")?,
            )
        };

        let ret = unsafe {
            dmesh_ws2812_write(
                pin as c_uchar,
                red as c_uchar,
                green as c_uchar,
                blue as c_uchar,
            )
        };
        if ret != 0 {
            bail!("ws2812 write failed esp_err=0x{ret:x} pin={pin}");
        }
        Ok(CommandResponse::ok(format!(
            "rgbled pin={pin} r={red} g={green} b={blue} off={}",
            red == 0 && green == 0 && blue == 0
        )))
    }
}

fn color_arg(request: &CommandRequest, name: &str) -> Result<u8> {
    let value = request.arg_i32(name)?.unwrap_or(0);
    if !(0..=255).contains(&value) {
        bail!("rgbled {name} must be 0..255");
    }
    Ok(value as u8)
}

fn validate_pin(pin: i32) -> Result<()> {
    if pin < 0 || pin > max_gpio_pin() {
        bail!("invalid ESP32 GPIO pin {pin}");
    }
    #[cfg(target_feature = "esp32s3ops")]
    if pin == 22 || pin == 23 || pin == 24 || pin == 25 || (26..=37).contains(&pin) {
        bail!("GPIO{pin} is not a safe diagnostic pin on ESP32-S3");
    }
    #[cfg(not(target_feature = "esp32s3ops"))]
    if (34..=39).contains(&pin) {
        bail!("GPIO{pin} is input-only on classic ESP32");
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
