# Stage2 boot API

This file owns the wire and retained-state contract for `fw/boot`. The C
implementation must remain a small encoder/decoder of these primitives; the
meaning and compatibility rules live here.

## UART transport

UART carries PPP/HDLC frames: `0x7e` delimits a packet and `0x7d` escapes the
following byte with XOR `0x20`. There is no DMB1 packet and no plaintext
selector. Stage2 emits `boot.identity` when `recovery:uart_boot` is enabled
and accepts the definite CBOR selector `{0:60010,6:[partition]}`. Partition
`1` selects Main and partition `2` selects Recovery.

The selector window is 1000 ms after reset. ROM text is not a stage2 protocol;
the managed lmesh forward may classify and suppress it.

## Boot identity event

Events use `{7:event_id,6:[values...]}`. `boot.identity` is event `60000` and
its tuple is:

```text
[role, partition, reset_reason, rtc_handoff, main_failures,
 recovery_failures, recent_resets, rtc_tick, mac_bytes]
```

Stage2 has role `3`, partition `0`. The event is diagnostic and must not select
a partition by itself.

## Selection state

The retained RTC layout starts at `DMESH_RTC_CUSTOM_OFFSET` (`+12` bytes from
the RTC retain base). The health event is at custom `+4` (`+16` overall), and
the partition handoff is at custom `+5` (`+17` overall). These offsets are
part of the ABI and are defined in `boot_health_rtc.h`.

The RTC handoff byte is authoritative: `0` normal selection, `1` Recovery,
`2` Main. Main writes Recovery before requesting an update. Recovery writes
Main only after a verified Main transfer. NVS is not used for this handoff;
Recovery transport settings supplied over PPP are runtime-only.

Rapid-reset history is only a crash-loop fallback. There is no NVS request
marker that can trap a healthy board in Recovery.

Stage2 emits event `60004` (`boot.recovery_failed`) when UART boot is enabled.
Its tuple is `[role, partition, recovery_failures, main_failures]`. A known-
healthy Main falls back to Main after this event; a Main crash loop remains on
the Recovery path and eventually enters the terminal UART-repair halt.
