# FSK Rendezvous And Discovery Plan

## Goal

Add a higher-throughput, shorter-range radio path between raw Wi-Fi action
frames and Meshtastic LoRa. ESP firmware remains a battery-first modem behind
host or Android `lmesh`; it does not make autonomous routing decisions.

The normal low-power profile remains unchanged: raw-NAN Wi-Fi duty windows and
Meshtastic MEDIUM_FAST receive. FSK is used only when a powered host or Android
control plane asks for a bounded discovery or transfer session over FSK.


## Initial US915 Test Profile

| Field | Value |
| --- | --- |
| Modulation | 2-FSK NRZ, no Gaussian shaping |
| Bit rate | 100 kbps |
| Deviation | 25 kHz |
| Receive bandwidth | 250 kHz requested (SX126x selects 234.3 kHz) |
| Preamble | 16 bytes |
| Integrity | CCITT CRC; whitening disabled for SX127x/SX126x wire compatibility |
| Network filter | 16-bit `network_id` hardware sync word |
| Payload limit | 128 bytes |
| Slot | 80 ms |
| Sweep | 50 slots, approximately four seconds |

The channel map is 500 kHz spaced: 22 channels from 902.250 through 912.750
MHz, four from 913.750 through 915.250 MHz, and 24 from 916.250 through
927.750 MHz. This is an engineering test profile only. Check regional rules
and measured occupied bandwidth before any deployment. Current Meshtastic
Medium Fast (913.125 MHz) and MeshCore (910.525 MHz) are coexistence references
to avoid during shared testing, not guarantees that adjacent channels are free.

## Firmware Operations

`radio` is the low-level compact-CBOR command. It persists profile parameters
under `fsk.*`, but no FSK receive loop is enabled at boot.

```text
radio status=true
radio op=sweep target=8e074170 sequence=1
radio op=listen ms=4200
radio op=send channel=7 data=hex:444d5346
```

Every operation first stops background LoRa RX, configures the same radio as
GFSK, completes the bounded operation, puts the radio to sleep, and restores
background LoRa RX. This keeps FSK from changing the normal CAD/sleep behavior.

The initial `DMSF` sync packet is 16 bytes:

```text
magic[4] = "DMSF" | version | type=FSK_SYNC | network_id:u16-be |
sequence:u32-be | target_last4:u32-be
```

`target_last4` is the final four bytes of the target Wi-Fi MAC in network byte
order; `ffffffff` is broadcast. The sender emits this same packet once in each
channel slot of one sweep.

## Rendezvous Protocol

The deterministic listener channel is:

```text
(network_id ^ hop_seed) % 50
```

A battery node that has coarse time wakes near its chosen rendezvous window,
stays on that one channel for one sweep plus guard, and does not scan all 50
channels. The initial lab test uses a 60-second host-triggered cadence. Product
policy can move to five or fifteen minutes; a node that has no time source may
listen for two or three intervals.

Next implementation step after PHY interoperability is a targeted exchange:

1. Host emits one FSK_SYNC sweep with one target MAC.
2. Target sends `FSK_CONFIRM` in its deterministic response slot in the next
   superframe.
3. Host sends an FSK ping in the following slot; target returns FSK pong with
   uptime and received RSSI.
4. A successful exchange can hold a bounded active transfer window for larger
   action-frame or FSK payloads.

Broadcast response suppression is deliberate for the first version to avoid
collisions. Discovery reliability is measured over long tests; loss is
acceptable, crashes and stuck radios are not.

## Meshtastic And Routing Policy

MEDIUM_FAST remains the long-range compatibility receiver. A powered host may
send a DMesh availability announcement every hour and on explicit discovery.
It uses the normal Meshtastic packet header and minimal `Data` envelope with
private port 256; the payload is DMesh CBOR, not a new protobuf payload. This
currently requires a clear/no-PSK lab channel; Meshtastic channel encryption is
not implemented by firmware.

Telemetry and position frames may provide coarse Unix time, but Mesh Beacon and
NodeInfo have no reliable on-air timestamp. They are not a phase-lock source.

Host/Android route policy is: cellular/internet first, nearby raw-NAN/action
frames next, scheduled direct FSK after that, then normal Meshtastic text as
the long-range fallback. Firmware reports link state and counters; it does not
select paths or forward traffic autonomously.

## Validation

1. Verify SX127x <-> SX126x `radio op=send` / `listen` on one fixed channel.
2. Verify SX127x <-> SX126x 50-slot sweep reaches a listener dwelling at the
   rendezvous channel.
3. Repeat both directions for at least 100 attempts; retain packet-loss and
   RSSI results.
4. Verify normal LoRa background receive resumes after every success, timeout,
   and malformed packet.
5. Run the power matrix again to ensure a bounded FSK operation does not leave
   the SX126x BUSY, TCXO, DIO2 RF switch, or radio rail active.

### Lab status: 2026-07-26

The fixed-channel profile was validated in both directions between `lora1`
(classic ESP32/SX127x) and `lora4` (Heltec V3 ESP32-S3/SX1262). The validation
also found and fixed two SX127x packet-engine bugs: FSK must not write the
LoRa-only FIFO-pointer register at `0x0d` (it is `RegRxConfig` in the FSK
bank), and the FSK FIFO start/RX trigger settings must be explicitly configured
after a LoRa session rather than inherited from reset state.

Final validation later on 2026-07-26 removed the earlier `lora2` transmit
restriction. The fixed-channel FSK matrix passed `lora1 -> lora2`,
`lora2 -> lora1`, `lora1 -> lora4`, and `lora4 -> lora1`; `lora2` is therefore
valid as both the metered FSK sender and receiver. This proves the bounded
fixed-channel modem operation only. The 50-slot sweep, 100-attempt loss/RSSI
run, post-operation LoRa restoration, and FSK power matrix above remain open.

# Others 
## BLE L2CAP and CoC 

For inspiration, CoC:
- each PDU is sent on a different channel - size based on allowed time, with SAR
- L2CAP handles fragmentation - PDU len is 27 for 4.0, 251 for 4.2+ (262 incl crc/header)
- CoC uses connection credit flow, like H2/SSH/Quic
- 37 data channels, 3 'announcement channels'
- very strict timing requirements.
- no Wifi-like beacons - not using the announcements as beacons/time sync

We can reuse a simplified SAR, without the layers (since streams/messages are the
only abstraction we want), but we can add beacons like NAN.

## Z-Wave

- 3 frequncies: 
Channel IndexFrequencyModulationData RatePrimary FunctionChannel
1908.42 MHz2-FSK9.6 kbps / 40 kbps Legacy mesh traffic & discoveryChannel
2908.40 MHz2-FSK40 kbps Mid-rate mesh trafficChannel 
3916.00 MHz2-GFSK100 kbps - high speed

- 1 sec wake up, listen on one channel
- low power - so no need for hoping.

## Wi-SUN

- 802.15.4g
- 128 + 64 + 42 channels, 
- could be directly supported instead of the custom protocol
- but would likely require the extra overhead of MAC/IP headers
