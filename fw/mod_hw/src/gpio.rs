use crate::{cbor, emit_cbor, get_setting_i32, HwHost, ModuleContext};

pub const OP_BUTTON: u64 = 3;
const GPIO0: i32 = 0;
const EVENT_BUTTON: u16 = 1;
const EVENT_SHORT: u16 = 101;
const EVENT_LONG: u16 = 102;
const EVENT_DOUBLE: u16 = 103;
const LONG_MS: u64 = 2_500;
const DOUBLE_MS: u64 = 500;

unsafe fn event(ctx: &ModuleContext, id: u16, pin: i32, held_ms: u64) -> i32 {
    let mut bytes = [0u8; 32];
    let Some(mut out) = cbor::Encoder::array(&mut bytes, 3) else { return -1 };
    let _ = out.u64(pin.max(0) as u64);
    let _ = out.u64(held_ms);
    let _ = out.u64(0);
    let length = out.len();
    drop(out);
    emit_cbor(ctx, id, &bytes[..length])
}

unsafe fn button(ctx: &ModuleContext, hw: &HwHost, request: &mut cbor::Reader<'_>) -> i32 {
    let pin = request.next_u64().unwrap_or(get_setting_i32(ctx, b"button.gpio", GPIO0) as u64) as i32;
    let enabled = request.next_u64().map(|v| v != 0).unwrap_or(true);
    if !enabled { return 0; }
    let (Some(config), Some(register), Some(wait), Some(now), Some(stop)) =
        (hw.gpio_config, hw.irq_register, hw.event_wait, hw.now_ms, hw.should_stop) else { return -2 };
    if config(hw.user, pin, 0, 1, 1) != 0 { return -3; }
    if register(hw.user, pin, 3, EVENT_BUTTON) != 0 { return -4; }
    let mut pressed_at = 0u64;
    let mut last_release = 0u64;
    loop {
        if stop(hw.user) != 0 { break; }
        let mut event_id = 0u16;
        let mut value = 0i32;
        if wait(hw.user, 50, &mut event_id, &mut value) != 0 || event_id != EVENT_BUTTON { continue; }
        let time = now(hw.user);
        if value == 0 { pressed_at = time; continue; }
        if pressed_at == 0 { continue; }
        let held = time.saturating_sub(pressed_at);
        let id = if held >= LONG_MS { EVENT_LONG }
                 else if time.saturating_sub(last_release) <= DOUBLE_MS { EVENT_DOUBLE }
                 else { EVENT_SHORT };
        let _ = event(ctx, id, pin, held);
        last_release = time;
        pressed_at = 0;
    }
    let _ = hw.irq_unregister.map(|f| f(hw.user, pin));
    0
}

pub unsafe fn run(ctx: &ModuleContext, hw: &HwHost, payload: &[u8]) -> i32 {
    let Some(mut request) = cbor::Reader::array(payload) else { return -10 };
    let Some(op) = request.next_u64() else { return -11 };
    if op != OP_BUTTON { return -12; }
    let result = button(ctx, hw, &mut request);
    if result == 0 && !request.done() { return -13; }
    result
}
