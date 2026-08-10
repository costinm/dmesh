use crate::{cbor, emit_cbor, get_setting_i32, get_setting_scaled, HwHost, ModuleContext};

pub const OP_BATTERY: u64 = 1;
pub const OP_PROBE: u64 = 2;
pub const EVENT_SAMPLE: u16 = 110;
pub const EVENT_BATTERY: u16 = 111;
const ADC_UNKNOWN: u64 = 255;
#[cfg(target_arch = "riscv32")]
const DEFAULT_PIN: i32 = 0; // ESP32-C6 ADC1 GPIO0..GPIO6
#[cfg(not(target_arch = "riscv32"))]
const DEFAULT_PIN: i32 = 35; // classic ESP32 battery ADC convention

unsafe fn gpio_level(hw: &HwHost, pin: i32, level: i32) -> i32 {
    let Some(config) = hw.gpio_config else { return -2 };
    let Some(write) = hw.gpio_write else { return -2 };
    let result = config(hw.user, pin, 1, 0, level);
    if result == 0 { write(hw.user, pin, level) } else { result }
}

unsafe fn sample(ctx: &ModuleContext, hw: &HwHost, pin: i32, ref_mv: u32,
                 event_id: u16, divider_x100: u32, min_mv: u32, max_mv: u32) -> i32 {
    if hw.adc_read.is_none() && hw.adc_read_ex.is_none() {
        return -2;
    }
    let mut raw = 0i32;
    let mut mv = 0u32;
    let mut unit = 0i32;
    let mut channel = 0i32;
    let result = if let Some(read_ex) = hw.adc_read_ex {
        read_ex(hw.user, pin, ref_mv, &mut raw, &mut mv, &mut unit, &mut channel)
    } else if let Some(read) = hw.adc_read {
        read(hw.user, pin, ref_mv, &mut raw, &mut mv)
    } else {
        return -2;
    };
    if result != 0 { return result; }
    let battery_mv = (mv as u64).saturating_mul(divider_x100 as u64) / 100;
    let level = if divider_x100 == 0 || max_mv <= min_mv || battery_mv < min_mv.saturating_sub(200) as u64 {
        ADC_UNKNOWN
    } else {
        battery_mv.saturating_sub(min_mv as u64).saturating_mul(100)
            / (max_mv - min_mv) as u64
    }.min(100);
    let mut encoded = [0u8; 96];
    let Some(mut out) = cbor::Encoder::array(&mut encoded, 8) else { return -3 };
    let _ = out.u64(pin.max(0) as u64);
    let _ = out.u64(raw.max(0) as u64);
    let _ = out.u64(mv as u64);
    let _ = out.u64(battery_mv);
    let _ = out.u64(level);
    let _ = out.u64(ref_mv as u64);
    let _ = out.u64(unit.max(0) as u64);
    let _ = out.u64(channel.max(0) as u64);
    let length = out.len();
    drop(out);
    emit_cbor(ctx, event_id, &encoded[..length])
}

unsafe fn battery(ctx: &ModuleContext, hw: &HwHost, request: &mut cbor::Reader<'_>) -> i32 {
    let pin = request.next_u64().unwrap_or(get_setting_i32(ctx, b"battery.pin", DEFAULT_PIN) as u64) as i32;
    let ref_mv = request.next_u64().unwrap_or(get_setting_i32(ctx, b"battery.ref_mv", 3300) as u64) as u32;
    let divider = request.next_u64().unwrap_or_else(|| {
        let compact = get_setting_i32(ctx, b"battery.divider_x100", -1);
        if compact >= 0 { compact as u64 } else { get_setting_scaled(ctx, b"battery.divider", 220).max(0) as u64 }
    }) as u32;
    let min_mv = request.next_u64().unwrap_or(get_setting_i32(ctx, b"battery.min_mv", 3300) as u64) as u32;
    let max_mv = request.next_u64().unwrap_or(get_setting_i32(ctx, b"battery.max_mv", 4200) as u64) as u32;
    let ctrl_pin = request.next_u64().map(|v| v as i32).unwrap_or(get_setting_i32(ctx, b"battery.ctrl", -1));
    let ctrl_level = request.next_u64().map(|v| (v != 0) as i32).unwrap_or(get_setting_i32(ctx, b"battery.ctl_lvl", 1));
    let enabled = request.next_u64().map(|v| v != 0).unwrap_or(true);
    if !enabled || pin < 0 { return 0; }
    if max_mv <= min_mv { return -4; }
    if ctrl_pin >= 0 {
        if gpio_level(hw, ctrl_pin, ctrl_level) != 0 { return -5; }
        if let Some(sleep) = hw.sleep_ms { let _ = sleep(hw.user, 10); }
    }
    let result = sample(ctx, hw, pin, ref_mv, EVENT_BATTERY, divider, min_mv, max_mv);
    if ctrl_pin >= 0 {
        let _ = gpio_level(hw, ctrl_pin, if ctrl_level == 0 { 1 } else { 0 });
    }
    result
}

unsafe fn probe(ctx: &ModuleContext, hw: &HwHost, request: &mut cbor::Reader<'_>) -> i32 {
    let samples = request.next_u64().unwrap_or(1);
    let interval_ms = request.next_u64().unwrap_or(1000).min(60_000) as u32;
    let ref_mv = request.next_u64().unwrap_or(3300).max(1) as u32;
    let mut pins = [34i32, 35, 36, 39];
    let mut pin_count = 4usize;
    if request.remaining() != 0 {
        pin_count = request.remaining().min(pins.len());
        for pin in pins.iter_mut().take(pin_count) {
            *pin = request.next_u64().unwrap_or(0) as i32;
        }
    }
    let mut sample_index = 0u64;
    loop {
        for pin in pins.iter().take(pin_count) {
            let result = sample(ctx, hw, *pin, ref_mv, EVENT_SAMPLE, 0, 0, 0);
            if result != 0 { return result; }
        }
        sample_index += 1;
        if samples != 0 && sample_index >= samples { break; }
        if let Some(stop) = hw.should_stop {
            if stop(hw.user) != 0 { break; }
        }
        if let Some(sleep) = hw.sleep_ms { let _ = sleep(hw.user, interval_ms); }
    }
    0
}

pub unsafe fn run(ctx: &ModuleContext, hw: &HwHost, payload: &[u8]) -> i32 {
    let Some(mut request) = cbor::Reader::array(payload) else { return -10 };
    let Some(op) = request.next_u64() else { return -11 };
    let result = match op {
        OP_BATTERY => battery(ctx, hw, &mut request),
        OP_PROBE => probe(ctx, hw, &mut request),
        _ => -12,
    };
    if result == 0 && !request.done() { return -13; }
    result
}
