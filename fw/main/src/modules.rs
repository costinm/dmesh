//! Flash-module control as tagged-CBOR components: the DMesh side of the esp-xip-modules runtime.
//!
//! The runtime and the loader are the `espmod-host` crate (esp-xip-modules repository); what a module answers to (its
//! operation names, its events) is the module's own crate (`esp-mod-lora`, `esp-mod-hw`). This file only turns a tagged
//! record into a module request and a module event into a DMesh call, and that is the only CBOR here. It knows no module's
//! configuration: a `lora` record's numeric fields are passed to the LoRa module as they are (`modules/mod_lora/API.md`).
//! The slot table below is the one `tools/mkmod.py --slots` reads and the installer (`dmesh_fw_transport::flash`, same
//! order) writes.
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use dmesh_server::{
    cbor::{Decoder, Encoder},
    tagged::{self, Name, Record},
};
use esp_mod_hw::method_from_name as hw_method;
use esp_mod_lora::{command::op_from_name, espmod::{decode_packet, EV_PACKET}};
use espmod_host::{self as em, slot, Features, Slot};

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

/// The value type of a CBOR event value (espmod ABI `VALUE_CBOR`).
const VALUE_CBOR: u8 = 5;
/// Component numbers of the modules: their slot tags.
const LORA_MODULE: i32 = 43;
const HW_MODULE: i32 = 45;
/// Field id of the packet bytes in a LoRa request map (`modules/mod_lora/API.md`).
const FIELD_DATA: u64 = 31;
/// Longest operation name accepted from a record.
const MAX_OPERATION: usize = 16;

/// Slots of the `data` partition, one 64 KiB flash MMU page each, in the order of `dmesh_fw_transport::flash`; the tag is
/// the component number of the module (`LORA_MODULE`, `HW_MODULE`).
static SLOTS: [Slot; 4] = [
    slot!("lora", 43, 0x00000, 0x10000),
    slot!("flash", 44, 0x10000, 0x10000),
    slot!("hw", 45, 0x20000, 0x10000),
    slot!("hello", 46, 0x30000, 0x10000),
];

static READY: AtomicBool = AtomicBool::new(false);

/// A module emitted an event: a LoRa packet goes to the transport, the rest is dropped.
fn on_event(module: &str, id: u16, value_type: u8, value: &[u8]) -> i32 {
    if module != "lora" || id != EV_PACKET || value_type != VALUE_CBOR {
        return 0;
    }
    match decode_packet(value) {
        Some((rssi, snr, packet)) => i32::from(dmesh_fw_transport::main_runtime::forward_lora_packet(packet, rssi, snr)),
        None => -1,
    }
}

/// Start the host and the loader once (NVS is initialised by Main before any module request). DMesh installs its own
/// images and has its own Wi-Fi: no console, no network calls.
fn ensure_loader() -> i32 {
    if READY.load(Ordering::Acquire) {
        return 0;
    }
    let rc = em::init(&SLOTS, "data\0", Features::default(), Some(on_event));
    if rc == 0 {
        READY.store(true, Ordering::Release);
    }
    rc
}

/// Stop the module in `slot` (the slot numbers of `dmesh_fw_transport::flash`) and wait until it has returned;
/// an installer calls this before it erases the slot. True when nothing is running there any more.
pub fn stop_slot(slot: u8) -> bool {
    !READY.load(Ordering::Acquire) || em::stop(slot as usize, 3000) == 0
}

/// Register the module components with `dmesh-server` before a connection is accepted. This does not initialize,
/// map, or execute a module.
pub fn register_tagged_handlers() {
    use dmesh_server::registry::{register, register_all, Method, SyncFn};
    assert!(register_all(
        &[
            Method::new(MODULE_COMPONENT, "module", MODULE_STATUS, "status"),
            Method::new(MODULE_COMPONENT, "module", MODULE_INIT, "init"),
            Method::new(MODULE_COMPONENT, "module", MODULE_STOP, "stop"),
        ],
        SyncFn(handle_module),
    ));
    assert!(register(Method::new(HELLO_COMPONENT, "hello", MODULE_RUN, "run"), SyncFn(handle_hello)));
    assert!(register(Method::new(LORA_COMPONENT, "lora", MODULE_RUN, "run"), SyncFn(handle_lora)));
    assert!(register(Method::new(HARDWARE_COMPONENT, "hardware", MODULE_RUN, "run"), SyncFn(handle_hardware)));
}

fn response(record: Record<'_>, ok: bool, value: i64) -> Option<Vec<u8>> {
    let mut result = [0u8; 24];
    let mut encoder = Encoder::new(&mut result);
    encoder.map(2)?;
    encoder.uint(1)?;
    encoder.boolean(ok)?;
    encoder.uint(2)?;
    // The loader status is an `i32`; keep failures as their absolute diagnostic code because this minimal shared
    // CBOR encoder has no signed-integer writer.
    encoder.uint(value.unsigned_abs())?;
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
    let (Name::Tag(MODULE_COMPONENT), Name::Tag(method)) = (record.component?, record.method?) else { return None };
    let result = match method {
        MODULE_STATUS => {
            // Value: installed slots as a bit mask, running slots in the next byte.
            let ready = READY.load(Ordering::Acquire);
            let mut mask = 0i64;
            if ready {
                for slot in 0..em::slot_count() {
                    let st = em::status(slot);
                    mask |= i64::from(st.installed) << slot;
                    mask |= i64::from(st.running) << (8 + slot);
                }
            }
            return response(record, ready, mask);
        }
        MODULE_INIT => ensure_loader(),
        // Ask every running module to return before the caller erases or replaces a slot.
        MODULE_STOP => i32::from(READY.load(Ordering::Acquire) && !em::stop_all(1_500)),
        _ => return None,
    };
    response(record, result == 0, i64::from(result))
}

fn handle_hello(record: Record<'_>) -> Option<Vec<u8>> {
    if !matches!(record.component, Some(Name::Tag(HELLO_COMPONENT))) || !matches!(record.method, Some(Name::Tag(MODULE_RUN))) {
        return None;
    }
    // hello is a one-shot module: it runs when started, with the record's data as its start request
    let init = ensure_loader();
    let result = match (init, em::find("hello")) {
        (0, Some(slot)) => em::start(slot, record.data.unwrap_or_default()),
        (0, None) => -7, // ERR_NOTFOUND
        (rc, _) => rc,
    };
    response(record, result == 0, i64::from(result))
}

fn handle_hardware(record: Record<'_>) -> Option<Vec<u8>> {
    module_request(record, HARDWARE_COMPONENT, "hw", HW_MODULE, hw_method, false)
}

fn handle_lora(record: Record<'_>) -> Option<Vec<u8>> {
    module_request(record, LORA_COMPONENT, "lora", LORA_MODULE, |name| op_from_name(name).map(i32::from), true)
}

/// A tagged `run` record as one request to a module: `params` is `[operation]`, `fields` the numeric-id map of
/// settings, `data` (if `with_data`) the opaque packet. The module is started idle first when it is not running.
fn module_request(record: Record<'_>, component: u64, module: &str, module_component: i32,
                  method_of: impl Fn(&[u8]) -> Option<i32>, with_data: bool) -> Option<Vec<u8>> {
    if !matches!(record.component, Some(Name::Tag(tag)) if tag == component) || !matches!(record.method, Some(Name::Tag(MODULE_RUN))) {
        return None;
    }
    let (method, request) = module_call(record, method_of, with_data)?;
    let init = ensure_loader();
    let result = if init != 0 {
        init
    } else {
        let mut answer = [0u8; 32];
        // `idle`: mod_lora's start request that brings it up without asking it to do anything (mod_hw ignores it)
        match em::call(module, b"idle", module_component, method, &request, &mut answer) {
            Ok(len) => module_result(&answer[..len]),
            Err(rc) => rc,
        }
    };
    response(record, result == 0, i64::from(result))
}

/// What the module answered: `{1: result}`, or `{9: error}` (hw), or nothing.
fn module_result(answer: &[u8]) -> i32 {
    let mut d = Decoder::new(answer);
    let Some((5, count)) = d.head() else { return 0 };
    for _ in 0..count {
        let Some(key) = d.uint() else { return -1 };
        let Some(value) = d.int() else { return -1 };
        if key == 1 || key == 9 {
            return i32::try_from(value).unwrap_or(-1);
        }
    }
    0
}

/// The method number and request map for a record: `(method, {<field id>: integer ..., 31: data})`.
///
/// `params` is `[operation]`, `fields` the numeric-id map of board and radio settings and `data` the opaque packet. The ids
/// are the module's own (its `API.md`); the module validates them, this keeps the shape and maps the operation name to the
/// method number.
fn module_call(record: Record<'_>, method_of: impl Fn(&[u8]) -> Option<i32>, with_data: bool) -> Option<(i32, Vec<u8>)> {
    let mut params = Decoder::new(record.params?);
    let (major, count) = params.head()?;
    if major != 4 || count == 0 || count == u64::MAX {
        return None;
    }
    let operation = params.text_ref()?;
    if operation.is_empty() || operation.len() > MAX_OPERATION {
        return None;
    }
    let method = method_of(operation)?;
    for _ in 1..count {
        params.skip()?;
    }
    if !params.is_finished() {
        return None;
    }
    let mut pairs: Vec<(u64, i64)> = Vec::new();
    if let Some(fields) = record.fields {
        let mut fields = Decoder::new(fields);
        let (major, count) = fields.head()?;
        if major != 5 || count > 64 {
            return None;
        }
        for _ in 0..count {
            let key = fields.uint()?;
            if key == FIELD_DATA {
                return None;
            }
            pairs.push((key, fields.int()?));
        }
        if !fields.is_finished() {
            return None;
        }
    }
    let data = record.data.filter(|data| with_data && !data.is_empty());
    if data.is_some_and(|data| data.len() > 255) {
        return None;
    }
    let mut out = vec![0u8; 16 + pairs.len() * 12 + data.map_or(0, |d| d.len() + 4)];
    let mut encoder = Encoder::new(&mut out);
    encoder.map((pairs.len() + usize::from(data.is_some())) as u64)?;
    for (key, value) in pairs {
        encoder.uint(key)?;
        encoder.int(value)?;
    }
    if let Some(data) = data {
        encoder.uint(FIELD_DATA)?;
        encoder.bytes(data)?;
    }
    let used = encoder.len();
    drop(encoder);
    out.truncate(used);
    Some((method, out))
}
