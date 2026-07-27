pub mod battery;
pub mod ble_bt;
pub mod button;
pub mod frames;
pub mod gpio;
pub mod i2c;
pub mod l3dmesh;
pub mod lora;
pub mod mode;
pub mod nan;
pub mod nvs;
pub mod power;
pub mod rgbled;
pub mod serial;
pub mod settings;
pub mod sleep;
pub mod telemetry;
pub mod test;
pub mod wake;
pub mod wifi;

use crate::commands::CommandRegistry;

use settings::SharedSettings;

pub fn register_commands(registry: &mut CommandRegistry, settings: SharedSettings) {
    battery::register_commands(registry, settings.clone());
    button::register_commands(registry, settings.clone());
    gpio::register_commands(registry);
    i2c::register_commands(registry, settings.clone());
    lora::register_commands(registry, settings.clone());
    mode::register_commands(registry, settings.clone());
    ble_bt::register_commands(registry, settings.clone());
    nan::register_commands(registry, settings.clone());
    power::register_commands(registry, settings.clone());
    rgbled::register_commands(registry);
    sleep::register_commands(registry, settings.clone());
    test::register_commands(registry);
    telemetry::register_commands(registry, settings.clone());
    nvs::register_commands(registry, settings);
    wifi::register_commands(registry);
}
