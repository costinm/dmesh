# mod_rawwifi

Status: initial implementation. The portable NAN core and EFI-like host-table
ABI are present; radio backends and ESP loader integration are incremental.

`mod_rawwifi` is a replaceable `no_std` Wi-Fi MAC and minimal IPv6/UDP module.
It is intended for mesh links where QUIC provides end-to-end encryption,
acknowledgement, duplicate suppression, and peer privacy. The module does not
implement WPA, DHCP, DNS, TCP, a general IP stack, or a second reliable
transport.

The existing Main-owned raw-NAN and ESP-IDF STA/AP-STA implementation remains
unchanged. It retains its current enable/disable controls and may continue to
combine promiscuous raw NAN with ESP-IDF networking. `mod_rawwifi` is a
separate, explicitly selected radio owner for experiments that use ESP-IDF
only to initialize the PHY/radio. It may run only while Main's STA, AP,
AP-STA, ESP-NOW, and raw-NAN modes are all stopped; it never shares an active
Wi-Fi interface with Main.

The initial targets are classic ESP32 and Espressif RISC-V Wi-Fi devices,
starting with ESP32-C3/C6. Xtensa uses the established fixed-VMA module window;
RISC-V uses the relocation-free PIC module path. ESP32-S3 support follows once
the common host primitives have been proven on those two architecture lanes.

## Intended radio modes

The first implementation has one mode:

- `nan`: a shared NAN-derived open medium using cluster discovery, the NAN
  cluster BSSID, NAN multicast service discovery, and directed or multicast
  frames;
- `open_ap` and `open_sta` are deferred until NAN discovery, cluster filtering,
  and custom data frames are proven on host and ESP.

There is no WPA supplicant or authenticator. Open System authentication is
the two-frame 802.11 state transition expected by normal Linux and Android
clients; it does not verify credentials or provide encryption.

The data path intentionally has no software retransmission or MAC duplicate
cache. Hardware automatic ACK generation remains enabled for standards-
compatible unicast, but TX is submitted as one attempt and ACK results are not
reported as delivery. Received duplicates are passed upward. QUIC owns
end-to-end loss recovery and duplicate suppression.

## Minimal IPv6/UDP surface

The module constructs and parses only:

```text
802.11 data | LLC/SNAP | IPv6 | UDP | opaque DMesh/QUIC bytes
```

The default multicast destination is the existing DMesh group
`ff02::5227`, UDP port `5227`, mapped to `33:33:00:00:52:27`. The source is a
persisted link-local IPv6 address. No global address, router advertisement,
SLAAC prefix, or DHCP lease is required.

The module validates IPv6 and UDP lengths and the mandatory UDP checksum. It
accepts unicast UDP addressed to the local link-local address and DMesh UDP
multicast. Minimal ICMPv6 Neighbor Solicitation/Advertisement support permits
Linux or Android to resolve the link-local address. It does not implement a
general ICMPv6 or IP forwarding stack.

UDP payloads are opaque. Received datagrams are emitted through the module
event/service bridge with source link-local address, source port, RSSI, and
payload bytes. Main or another service owns QUIC and may forward the payload
over NAN, LoRa, FSK, or another bearer. `mod_rawwifi` must not parse QUIC
DCIDs, retransmit QUIC packets, or suppress duplicates.

## Host boundary

Main owns SDK initialization, DMA/interrupt safety, module lifetime, and the
bounded RX queue. The module owns MAC policy and frame construction. SDK
objects and DMA pointers never cross the ABI. The required versioned host
primitives are:

- exclusive raw-radio acquire/release and bounded shutdown;
- channel set/get, local MAC, TSF/monotonic time, and random bytes;
- configure/enable/disable an RX filter slot with A1 and A3 address/mask
  fields and return the filter-match bitmap in RX metadata;
- wait for one bounded RX frame into a module-owned buffer, returning length,
  RSSI, channel, timestamp, flags, and match bitmap;
- submit one raw 802.11 frame with a selected rate and hardware-auto-ACK flag,
  with software retry count fixed to zero;
- structured event emission, settings get/set, stop check, bounded sleep, and
  transient allocation from the existing module arena.

The hardware exposes paired A1/A3 filters per virtual RX interface. Classic
ESP32 and the principal S3/C3/C5/C6/C61 families expose four slots; ESP32-C2
exposes three. The first NAN experiment uses A3-only filtering after cluster
selection so beacons, multicast discovery, and directed follow-ups from the
same cluster all remain visible.

Radio acquisition fails cleanly if Main's ESP-IDF STA/AP/raw-NAN owner is
active. Stopping the module removes its filters, drains the host RX queue,
disables its interrupt path, releases the radio, and permits Main to restore
the existing ESP-IDF mode without rebooting.

## Testable protocol core

The module deliberately carries its own NAN implementation. It may copy and
adapt parsing, frame construction, cluster selection, and timing logic from
Main, but does not call back into Main's NAN component. This duplication keeps
the existing path stable while the module develops a smaller, independently
testable implementation.

Organize the crate as a pure `no_std` protocol core plus platform adapters:

- the core owns 802.11 frame codecs, NAN attributes/state, open AP/STA state,
  LLC/SNAP, IPv6, ICMPv6 Neighbor Discovery, UDP, and deterministic timers;
- the ESP adapter implements radio I/O through the module host table;
- an `lmesh` Linux adapter drives `mac80211_hwsim` or a supported physical
  monitor/injection interface without changing the core protocol code;
- host tests use `std` only in the adapter/test harness, never in the module
  library.

An attached Linux Wi-Fi card can be used for capture and, where its driver
supports monitor-mode injection, on-air tests. Deterministic authentication,
association, retry/loss, and malformed-frame tests should use
`mac80211_hwsim`; hardware-card tests remain capability-gated because many
drivers cannot inject arbitrary management/data frames or expose RX filter
metadata.

## lmesh integration

`lmesh` consumes the `mod_rawwifi` library directly as another radio backend;
it does not load a DMOD image on Linux. The embedded DMOD binary and Linux
backend share the same codecs, state machines, settings model, and golden
tests.

The Linux adapter exclusively acquires a configured Wi-Fi phy/interface,
places it in the required monitor/raw mode, selects the channel, and feeds RX
frames and metadata into the core. Core transmit actions are injected by the
adapter. Received UDP datagrams enter the normal lmesh packet/service router;
outgoing lmesh payloads are passed to the core as opaque UDP/QUIC bytes.

The adapter requires `CAP_NET_ADMIN` for interface/channel ownership and
`CAP_NET_RAW` for capture/injection. It refuses startup while the interface is
managed by wpa_supplicant, NetworkManager, hostapd, or another lmesh backend,
unless that owner explicitly hands it over. On stop it removes any interface
it created and restores the recorded type, channel, and link state where the
driver supports restoration.

Physical-card support is capability-reported rather than assumed. lmesh
status distinguishes monitor RX, management injection, data injection,
channel control, RX filtering, and automatic-ACK support. Unsupported
operations return a precise capability error; `mac80211_hwsim` remains the
complete deterministic backend.

## Android and Linux interoperability

The preferred direct-IP experiments are:

1. Android creates an open local AP and the ESP module joins as `open_sta`.
2. ESP runs `open_ap` and Android joins as a STA.
3. Linux performs either role using its normal Wi-Fi control plane.

The current Android SDK and device policy must be tested: public/local-only
hotspot APIs have varied in whether applications can request an explicitly
open network. If either Wi-Fi direction works reliably, BLE CoC is not needed
for that link. BLE remains an independent Main capability and is not an
initial `mod_rawwifi` acceptance requirement; simultaneous BLE/radio
coexistence is a later hardware test.

See [the implementation plan](../../docs/plans/mod-rawwifi.md) for ABI,
milestones, and acceptance criteria.
