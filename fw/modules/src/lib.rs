//! Optional ESP flash-module control, exposed as tagged-CBOR components.
//!
//! The schema/dispatch registration is transport-independent: a caller uses
//! a normal tagged-CBOR QUIC stream or a direct tagged record. Only this crate's
//! small C ABI bridge is ESP-specific. Images that do not link the native
//! module loader simply do not call [`register_tagged_handlers`].

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::vec;
use alloc::vec::Vec;
use dmesh_server::{
    cbor::{Decoder, Encoder},
    services,
    tagged::{self, Name, Record},
};

/// Module-loader control/status component.
pub const MODULE_COMPONENT: u64 = 1000;
/// Flash-mapped hello module service.
pub const HELLO_COMPONENT: u64 = 1001;
/// Flash-mapped LoRa module service.
pub const LORA_COMPONENT: u64 = 1002;
/// Flash-mapped hardware module service.
pub const HARDWARE_COMPONENT: u64 = 1003;

pub const MODULE_STATUS: u64 = 1;
pub const MODULE_INIT: u64 = 2;
pub const MODULE_STOP: u64 = 3;
pub const MODULE_RUN: u64 = 4;

extern "C" {
    fn dmesh_module_loader_init();
    fn dmesh_module_loader_is_initialized() -> bool;
    fn dmesh_module_loader_refresh_header() -> bool;
    fn dmesh_module_loader_prepare_flash(timeout_ms: u32) -> bool;
    fn dmesh_module_loader_header_valid() -> bool;
    fn dmesh_module_loader_last_result() -> i32;
    fn dmesh_module_start_service(
        service_tag: u16,
        offset: u32,
        size: u32,
        payload: *const u8,
        payload_len: usize,
        args: *const u8,
        args_len: usize,
    ) -> i32;
    fn dmesh_module_lora_configure(config: *const LoraConfig) -> i32;
    fn dmesh_module_lora_command(
        args: *const u8, args_len: usize, payload: *const u8, payload_len: usize,
    ) -> i32;
    fn dmesh_module_lora_running() -> bool;
}

/// Versioned projection of `dmesh_lora_config_v1`.  Keep this in the
/// tagged-CBOR adapter rather than in a bearer so UART, NOW and QUIC streams
/// select identical board wiring and radio parameters.
#[repr(C)]
#[derive(Clone, Copy)]
struct LoraConfig {
    abi_version: u32,
    size: u32,
    chip: u32,
    frequency_hz: u32,
    bandwidth_hz: u32,
    spreading_factor: u32,
    spi_host: i32,
    sync_word: u8,
    tx_power: u8,
    reset_pin: i8,
    cs_pin: i8,
    irq_pin: i8,
    busy_pin: i8,
    sck_pin: i8,
    miso_pin: i8,
    mosi_pin: i8,
    board_power_pin: i32,
    board_power_level: i32,
    sx1262_dio2_rf_switch: i32,
    sx1262_tcxo_mv: i32,
    sx1262_pa_duty: i32,
    sx1262_pa_hp: i32,
    sx1262_pa_device: i32,
    sx1262_pa_lut: i32,
    sx1262_sync_word: i32,
    sx1262_rx_timeout_ms: i32,
    coding_rate: i32,
    preamble: i32,
    crc: i32,
    cad_rx: i32,
    cad_interval_ms: u32,
    cad_rx_ms: u32,
}

const _: () = assert!(core::mem::size_of::<LoraConfig>() == 104);

impl Default for LoraConfig {
    fn default() -> Self {
        Self {
            abi_version: 2, size: 104, chip: 1, frequency_hz: 913_125_000,
            bandwidth_hz: 250_000, spreading_factor: 10, spi_host: 2,
            sync_word: 0x2b, tx_power: 17, reset_pin: 14, cs_pin: 18,
            irq_pin: 26, busy_pin: -1, sck_pin: 5, miso_pin: 19, mosi_pin: 27,
            board_power_pin: -1, board_power_level: 1, sx1262_dio2_rf_switch: 0,
            sx1262_tcxo_mv: 0, sx1262_pa_duty: 4, sx1262_pa_hp: 7,
            sx1262_pa_device: 0, sx1262_pa_lut: 1, sx1262_sync_word: 0x24b4,
            sx1262_rx_timeout_ms: 0, coding_rate: 5, preamble: 16, crc: 1,
            cad_rx: 0, cad_interval_ms: 2_000, cad_rx_ms: 1_000,
        }
    }
}

// The C loader calls these bearer-neutral callbacks from a module task.  The
// former Main implementation queued them through its legacy string-command
// registry.  That registry is intentionally no longer linked: tagged-CBOR
// handlers are the public surface.  Keep the ABI here, beside the loader
// handler, and fail unsupported asynchronous operations explicitly instead
// of silently routing them through a Main-only command path.  Settings and
// event delivery will be wired to their common dmesh-server counterparts when
// their tagged-CBOR request/response schema is added.
#[no_mangle]
pub unsafe extern "C" fn dmesh_module_get_setting(
    _key: *const u8,
    _key_len: usize,
    _value: *mut u8,
    _value_capacity: usize,
    value_len: *mut usize,
) -> i32 {
    if !value_len.is_null() {
        *value_len = 0;
    }
    -2 // absent
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_module_set_setting(
    _key: *const u8,
    _key_len: usize,
    _value: *const u8,
    _value_len: usize,
) -> i32 {
    -2 // not yet supported by the common settings service
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_module_emit_event(
    _event_id: u16,
    _value_type: u8,
    _flags: u8,
    _payload: *const u8,
    _payload_len: usize,
) -> i32 {
    -2 // not yet supported by the common events service
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_module_call_service(
    _service_tag: u16,
    _payload: *const u8,
    _payload_len: usize,
    _response: *mut u8,
    _response_capacity: usize,
    response_len: *mut usize,
    _timeout_ms: u32,
) -> i32 {
    if !response_len.is_null() {
        *response_len = 0;
    }
    -2 // no legacy Main command dispatcher
}

/// Register the module components with `dmesh-server` before a connection is
/// accepted. This does not initialize, map, or execute a module.
pub fn register_tagged_handlers() {
    assert!(services::register_tagged_component(
        MODULE_COMPONENT,
        handle_module
    ));
    assert!(services::register_tagged_component(
        HELLO_COMPONENT,
        handle_hello
    ));
    assert!(services::register_tagged_component(
        LORA_COMPONENT,
        handle_lora
    ));
    assert!(services::register_tagged_component(
        HARDWARE_COMPONENT,
        handle_hardware
    ));
}

fn response(record: Record<'_>, ok: bool, value: i64) -> Option<Vec<u8>> {
    let mut result = [0u8; 24];
    let mut encoder = Encoder::new(&mut result);
    encoder.map(2)?;
    encoder.uint(1)?;
    encoder.boolean(ok)?;
    encoder.uint(2)?;
    // Native loader status is an `i32`; retain failures as their compact
    // absolute diagnostic code because this minimal shared CBOR encoder has
    // no signed-integer writer.
    encoder.uint(value.unsigned_abs() as u64)?;
    let used = encoder.len();
    drop(encoder);
    let mut response = vec![0; 64];
    let response_used = tagged::encode_numeric_response(
        match record.component? {
            Name::Tag(tag) => tag,
            _ => return None,
        },
        match record.method? {
            Name::Tag(tag) => tag,
            _ => return None,
        },
        record.id.unwrap_or(0),
        &result[..used],
        &mut response,
    )?;
    response.truncate(response_used);
    Some(response)
}

fn handle_module(record: Record<'_>) -> Option<Vec<u8>> {
    let component = match record.component? {
        Name::Tag(tag) if tag == MODULE_COMPONENT => tag,
        _ => return None,
    };
    let method = match record.method? {
        Name::Tag(tag) => tag,
        _ => return None,
    };
    let result = unsafe {
        match (component, method) {
            (MODULE_COMPONENT, MODULE_STATUS) => {
                dmesh_module_loader_refresh_header();
                return response(
                    record,
                    dmesh_module_loader_header_valid(),
                    dmesh_module_loader_last_result() as i64,
                );
            }
            (MODULE_COMPONENT, MODULE_INIT) => {
                dmesh_module_loader_init();
                0
            }
            (MODULE_COMPONENT, MODULE_STOP) => i32::from(!dmesh_module_loader_prepare_flash(1_500)),
            _ => return None,
        }
    };
    response(record, result == 0, result as i64)
}

fn handle_hello(record: Record<'_>) -> Option<Vec<u8>> {
    run_service(record, HELLO_COMPONENT, 46)
}
fn handle_lora(record: Record<'_>) -> Option<Vec<u8>> {
    if !matches!(record.component, Some(Name::Tag(LORA_COMPONENT)))
        || !matches!(record.method, Some(Name::Tag(MODULE_RUN)))
    {
        return None;
    }
    let (args, config) = lora_request(record)?;
    // Initializing the loader only discovers the flash partition and prepares
    // host callbacks. It does not map a DMOD, allocate the module arena, or
    // create a task; those remain scoped to this active request.
    unsafe {
        if !dmesh_module_loader_is_initialized() {
            dmesh_module_loader_init();
        }
    }
    let configured = unsafe { dmesh_module_lora_configure(&config) };
    if configured != 0 {
        return response(record, false, i64::from(configured));
    }
    let payload = record.data.unwrap_or_default();
    let result = unsafe {
        if dmesh_module_lora_running() {
            dmesh_module_lora_command(args.as_ptr(), args.len(), payload.as_ptr(), payload.len())
        } else {
            dmesh_module_start_service(
                43,
                0,
                0,
                payload.as_ptr(),
                payload.len(),
                args.as_ptr(),
                args.len(),
            )
        }
    };
    response(record, result == 0, i64::from(result))
}
fn handle_hardware(record: Record<'_>) -> Option<Vec<u8>> {
    run_service(record, HARDWARE_COMPONENT, 45)
}

fn run_service(record: Record<'_>, component: u64, service_tag: u16) -> Option<Vec<u8>> {
    if !matches!(record.component, Some(Name::Tag(tag)) if tag == component)
        || !matches!(record.method, Some(Name::Tag(MODULE_RUN)))
    {
        return None;
    }
    let payload = record.data.unwrap_or_default();
    let offset = u32::from(service_tag - 43) * 0x10000;
    let result = unsafe {
        dmesh_module_start_service(
            service_tag,
            offset,
            0,
            payload.as_ptr(),
            payload.len(),
            core::ptr::null(),
            0,
        )
    };
    response(record, result == 0, i64::from(result))
}

/// Decode the old Main LoRa command surface without reintroducing its
/// string-command dispatcher. `params` is `[operation]`; `data` remains the
/// opaque TX payload.  Optional numeric fields carry the full board/radio
/// configuration, so an SX1262 board does not inherit SX127x wiring.
///
/// Field IDs follow the C ABI after the header: 1=chip, 2=freq, 3=bw,
/// 4=sf, 5=spi_host, 6=sync_word, 7=tx_power, 8..14=reset/cs/irq/busy/
/// sck/miso/mosi, 15..28=board/SX1262/LoRa tuning, 29..30=CAD settings.
fn lora_request(record: Record<'_>) -> Option<(&[u8], LoraConfig)> {
    let params = record.params?;
    let mut decoder = Decoder::new(params);
    let (major, count) = decoder.head()?;
    if major != 4 || count == 0 || count == u64::MAX {
        return None;
    }
    let args = decoder.text_ref()?;
    if args.is_empty() || args.len() > 16 || !valid_lora_operation(args) {
        return None;
    }
    for _ in 1..count {
        decoder.skip()?;
    }
    if !decoder.is_finished() {
        return None;
    }
    let mut config = LoraConfig::default();
    if let Some(fields) = record.fields {
        let mut fields = Decoder::new(fields);
        let (major, count) = fields.head()?;
        if major != 5 || count == u64::MAX {
            return None;
        }
        for _ in 0..count {
            let key = fields.uint()?;
            let value = fields.int()?;
            apply_lora_field(&mut config, key, value)?;
        }
        if !fields.is_finished() {
            return None;
        }
    }
    Some((args, config))
}

fn valid_lora_operation(value: &[u8]) -> bool {
    matches!(value, b"probe" | b"probe127" | b"probe126" | b"rx" | b"tx" | b"stop" | b"reconfigure" | b"fsk" | b"stats")
}

fn apply_lora_field(config: &mut LoraConfig, key: u64, value: i64) -> Option<()> {
    let value32 = i32::try_from(value).ok()?;
    match key {
        1 => config.chip = u32::try_from(value).ok()?,
        2 => config.frequency_hz = u32::try_from(value).ok()?,
        3 => config.bandwidth_hz = u32::try_from(value).ok()?,
        4 => config.spreading_factor = u32::try_from(value).ok()?,
        5 => config.spi_host = value32,
        6 => config.sync_word = u8::try_from(value).ok()?,
        7 => config.tx_power = u8::try_from(value).ok()?,
        8 => config.reset_pin = i8::try_from(value).ok()?,
        9 => config.cs_pin = i8::try_from(value).ok()?,
        10 => config.irq_pin = i8::try_from(value).ok()?,
        11 => config.busy_pin = i8::try_from(value).ok()?,
        12 => config.sck_pin = i8::try_from(value).ok()?,
        13 => config.miso_pin = i8::try_from(value).ok()?,
        14 => config.mosi_pin = i8::try_from(value).ok()?,
        15 => config.board_power_pin = value32,
        16 => config.board_power_level = value32,
        17 => config.sx1262_dio2_rf_switch = value32,
        18 => config.sx1262_tcxo_mv = value32,
        19 => config.sx1262_pa_duty = value32,
        20 => config.sx1262_pa_hp = value32,
        21 => config.sx1262_pa_device = value32,
        22 => config.sx1262_pa_lut = value32,
        23 => config.sx1262_sync_word = value32,
        24 => config.sx1262_rx_timeout_ms = value32,
        25 => config.coding_rate = value32,
        26 => config.preamble = value32,
        27 => config.crc = value32,
        28 => config.cad_rx = value32,
        29 => config.cad_interval_ms = u32::try_from(value).ok()?,
        30 => config.cad_rx_ms = u32::try_from(value).ok()?,
        _ => return None,
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lora_request_keeps_tx_data_separate_from_operation() {
        // params=["tx"], fields={1:2, 2:915000000, 8:12, 11:13}
        let params = [0x81, 0x62, b't', b'x'];
        let fields = [0xa4, 1, 2, 2, 0x1a, 0x36, 0x89, 0xca, 0xc0,
            8, 12, 11, 13];
        let record = Record {
            component: Some(Name::Tag(LORA_COMPONENT)),
            method: Some(Name::Tag(MODULE_RUN)), id: Some(7),
            params: Some(&params), fields: Some(&fields), result: None,
            error: None, to: None, data: Some(b"opaque packet"),
        };
        let (operation, config) = lora_request(record).unwrap();
        assert_eq!(operation, b"tx");
        assert_eq!(config.chip, 2);
        assert_eq!(config.frequency_hz, 915_000_000);
        assert_eq!(config.reset_pin, 12);
        assert_eq!(config.busy_pin, 13);
    }

    #[test]
    fn lora_request_rejects_unknown_operation() {
        let params = [0x81, 0x67, b'r', b'e', b'b', b'o', b'o', b't', b'!'];
        let record = Record { params: Some(&params), ..Record::default() };
        assert!(lora_request(record).is_none());
    }
}
