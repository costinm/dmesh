# mod_lora

Position-independent, `no_std` LoRa module. The SX127x/SX126x radio drivers,
LoRa packet policy, and the chip's FSK mode are module-owned. Main supplies the
ESP-IDF SPI/GPIO/IRQ host table in `include/dmesh_lora_abi.h` and retains the
legacy implementation as a disabled fallback.

The first hardware target is `lora3` (SX127x), followed by `lora4` (SX1262).
