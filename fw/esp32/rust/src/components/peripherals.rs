//! Built-in peripheral module.
//!
//! This is deliberately separate from the optional flash-mapped DMOD modules
//! (for example `lora`).  Peripheral control is needed by Main during boot,
//! sleep and telemetry, so it remains in the Main image for now.  The module
//! owns the high-level command surface; the individual components retain the
//! SDK-backed low-level operations and the boot-critical button runtime.
//!
//! Keeping this registration boundary independent means new I2C/GPIO/ADC
//! functionality can be added here without changing `main.rs` or the command
//! loop.  A future external module can use the same operations through a
//! versioned host-service ABI; it must use a separate DMOD slot from `lora`.

use super::settings::SharedSettings;
use crate::commands::CommandRegistry;

/// The optional flash-mapped LoRa module owns the first aligned module slot.
/// This built-in peripheral module is not stored there (or in the data
/// partition), which prevents accidental slot sharing.
pub const DMOD_SLOT_LORA: u32 = 0;
pub const DMOD_SLOT_PERIPHERALS: u32 = 1;

pub fn register_commands(registry: &mut CommandRegistry, settings: SharedSettings) {
    super::battery::register_commands(registry, settings.clone());
    super::button::register_commands(registry, settings.clone());
    super::gpio::register_commands(registry);
    super::i2c::register_commands(registry, settings.clone());
    super::rgbled::register_commands(registry);
}

/// Main-owned boot initialization for the button peripheral.  It is exposed
/// through this module so callers do not need to know the component layout.
pub fn initialize_button(settings: &SharedSettings) -> anyhow::Result<()> {
    super::button::initialize(settings)
}

pub fn button_start_runtime_interrupts() -> anyhow::Result<()> {
    super::button::start_runtime_interrupts()
}

pub fn take_console_wakes() -> u32 {
    super::button::take_console_wakes()
}

pub fn take_long_presses() -> u32 {
    super::button::take_long_presses()
}

pub fn take_sync_requests() -> u32 {
    super::button::take_sync_requests()
}
