# Hardware Module API

Status: experimental V3. Service tag `45`, slot `2`, one 64-KiB slot.

`hw.dmod` is a replaceable, `no_std` peripheral service. Main supplies the
host ABI; the module owns peripheral policy and emits compact telemetry. Main
does not need to understand the event payloads.

The C ABI declaration is [dmesh_hw_abi.h](../modules/include/dmesh_hw_abi.h).
This document is the source contract for generating numeric schemas later.
Names are documentation only; firmware requests and events use integer tuples.

## Module request

The module entry payload is a definite-length CBOR array of unsigned integers.
The first item is `operation`; the remaining items depend on that operation.
No text keys or text values are required.

### Operation IDs

| ID | Name | Purpose |
|---:|---|---|
| 1 | `battery` | Read the configured battery ADC and emit one event |
| 2 | `adc_probe` | Sample one or more ADC pins |
| 3 | `button` | Run the GPIO button interrupt task |

### Battery request

```text
[1, pin, ref_mv, divider_x100, min_mv, max_mv,
   control_pin, control_level, enabled]
```

All fields after `1` are optional and default to the corresponding settings:

| Position | Field | Default |
|---:|---|---:|
| 1 | ADC GPIO | `battery.pin`, 35 |
| 2 | ADC reference in mV | `battery.ref_mv`, 3300 |
| 3 | Battery divider ×100 | `battery.divider_x100`, or `battery.divider` parsed as decimal |
| 4 | Empty voltage in mV | `battery.min_mv`, 3300 |
| 5 | Full voltage in mV | `battery.max_mv`, 4200 |
| 6 | ADC control GPIO | `battery.ctrl`, -1 disabled |
| 7 | Control active level | `battery.ctl_lvl`, 1 |
| 8 | Enabled | 1 |

When a control GPIO is present, the module configures it as an output, sets
the active level, waits 10 ms, samples, then sets the inactive level.

### ADC probe request

```text
[2, sample_count, interval_ms, ref_mv, pin0, pin1, ...]
```

`sample_count=0` means continuous until the module task is stopped. The count
is bounded by the host/task lifetime; `interval_ms` is clamped to 0..60000.
The loader permits independent service tasks to run concurrently. The radio
service (tag 43) and hardware service (tag 45) have separate runtime state;
flash preparation stops all active services before erasing their slots.
If no pins are supplied, the default list is `[34, 35, 36, 39]`.

### Button request

```text
[3, gpio, enabled]
```

Defaults are `button.gpio=0` and `enabled=1`. The module registers both-edge
interrupts, classifies releases as short, long (at least 2500 ms), or double
(within 500 ms), and exits when the host stop callback is asserted.

## Event ABI

Events use the common module event callback with `value_type=5`:

```text
ModuleEvent(event_id, value_type=5, flags, cbor_tuple)
```

The payload is a CBOR tuple of unsigned integers. `value_type=5` means Main
must forward the bytes unchanged; it must not format or reinterpret fields.

### Event IDs and tuples

| ID | Name | Tuple |
|---:|---|---|
| 110 | `adc.sample` | `[pin, raw, adc_mv, 0, 255, ref_mv, unit, channel]` |
| 111 | `battery.sample` | `[pin, raw, adc_mv, battery_mv, level, ref_mv, unit, channel]` |
| 101 | `button.short` | `[pin, held_ms, 0]` |
| 102 | `button.long` | `[pin, held_ms, 0]` |
| 103 | `button.double` | `[pin, held_ms, 0]` |

For `adc.sample`, battery voltage is zero and level is `255` (unknown).
`level=255` is reserved for unknown; otherwise battery level is 0..100.
`unit` is 1-based (`1=ADC1`); `channel` is the ESP ADC channel number.

## Host ABI

The host table provides generic GPIO, ADC, I2C, SPI, RGB LED, IRQ, event
wait, stop, sleep, and monotonic-time callbacks. `adc_read` is the original
raw/mV operation. `adc_read_ex` is additive and returns ADC unit/channel
metadata. Modules must check `size` before using additive fields.

Callbacks return zero on success or an ESP error/result code. The host owns
SDK objects and synchronization; modules must not link ESP-IDF or block on
unbounded operations.

## Ownership and storage

- Main owns the ABI implementation and command/service dispatch. The
  device-facing identity is the numeric service tag; names are controller and
  schema data only.
- `hw.dmod` owns battery, ADC probe, button, and peripheral policy.
- Recovery owns only the flash transport and named module-slot writing.
- LoRa and hardware modules use fixed 64-KiB-aligned slots: physical offset is
  `(service_tag - 43) * 0x10000`.
- Event IDs 1..127 are reserved for core hardware events; 128..255 are
  available for future peripheral modules.
- Operation IDs 1..63 are reserved for this module; 64..255 are future work.
