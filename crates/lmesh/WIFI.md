# lmesh Wi-Fi defaults and tuning notes

This file records the direct nl80211 settings that are known to start an open
local DMesh AP on the current Linux USB Wi-Fi cards. The defaults are optimized
for a stable first mesh control channel, not yet for maximum distance, maximum
rate, or minimum power.

## Current open AP defaults

`wifi.ap.start_open` currently starts `hostapd_exact_ht20`:

| Setting | Current value |
|---|---|
| Interface mode | `NL80211_IFTYPE_AP` |
| SSID | `Direct-XXXXXXXX-Dmesh-local` by default, or caller supplied |
| Channel | 6 |
| Frequency | 2437 MHz |
| Channel type | HT20 |
| Width | 20 MHz |
| Auth | Open system, no password |
| Beacon interval | 100 TU |
| DTIM period | 1 |
| Capability | `0x0401` |
| Basic rates | `02 04 0b 16` (1, 2, 5.5, 11 Mbps) |
| Hidden SSID | disabled |
| Group cipher attr | WEP40 (`00-0f-ac:1`), matching hostapd's open-AP nl80211 call |
| WPA/RSN attrs | not sent |
| Probe response attr | not sent for the selected profile |
| Extra IEs | extended capabilities `7f 08 04 00 00 00 00 00 00 40` |
| Socket lifetime | `NL80211_ATTR_SOCKET_OWNER`; lmesh keeps the owner socket alive |

`wifi.ap.start_open` also registers AP SME management frame delivery for auth,
assoc, reassoc, disassoc, deauth, probe request, and selected action-frame
categories. lmesh records received frames as `wifi.ap.mgmt` with parsed source,
destination, BSSID, subtype, fixed fields, IEs, raw frame hex, and
`rx_signal_dbm` when the driver reports it.

## Raw Wi-Fi defaults

Raw NAN SDF is the low-rate, synchronized poor-man NDP transport: it handles
beacon/discovery-window timing, directed follow-ups, and bounded datagrams.
The custom raw-action transport is its unassociated bulk supplement during the
same active window; the SDF payload length does not constrain custom raw-action
payloads. Monitor mode remains reserved for explicit debug or raw 802.11
data-frame experiments.

| Setting | Current value |
|---|---|
| Default channel | 6 |
| Multicast destination | `33:33:00:00:52:27` (`ff02::5227`) |
| Peer raw destination | `rx:<peer-mac>` flips bit 0 of the first MAC octet |
| Body marker | `7f 18 fe 34 ff ff ff ff 04` |
| Custom raw-action payload MTU | 1200 bytes on ESP firmware; host accepts up to 1400 bytes |
| Default raw ping payload | `dmesh.ping type=status source=lmesh nonce=...` |
| Default raw ping TX | `tx_variant=dont_wait_ack` nl80211 vendor action frame |
| Default raw ping RX | `rx_variant=nl80211` vendor action-frame match |
| Monitor TX variants | `monitor`, `monitor_active`, `multicast_data`, `multicast_data_active`, `sta_multicast_llc`, `sta_multicast_llc_active` |
| nl80211 TX variants | `standard`, `roc`, `dont_wait_ack`, `dont_wait_no_duration`, `dont_wait_minimal`, `dont_wait_no_cck`, `no_cck`, `no_freq`, `pyroute2` |
| Normal data EtherType | `0x88b5` with the same DMesh marker after the Ethernet header |

Custom raw-action TX uses `DONT_WAIT_FOR_ACK` by default for long-distance
work. Multicast and ToDS data frame injection currently require
explicit AF_PACKET monitor TX variants, so the no-ack behavior is implied by
multicast addressing rather than an nl80211 TX flag.

The action-frame marker uses the Espressif OUI `18:fe:34` and ESP-NOW type
`0x04` only as a stable custom wire marker; it does not invoke ESP-NOW or
inherit its 250-byte maximum. The four marker bytes are fixed to
`ff:ff:ff:ff`. lmesh also registers matches for
the shared DMesh multicast MAC, the interface MAC, and the interface raw-receive
MAC so we can re-enable destination-oriented filtering after the basic path is
proven.

Monitor-mode receive should not be treated as guaranteed hardware address
filtering. Most drivers expose monitor RX as channel-visible 802.11 frames,
with driver-specific filtering behavior. lmesh therefore filters monitor RX
before parsing or recording to only:

1. the interface's real MAC address;
2. the interface's raw receive MAC, produced by flipping bit 0 of the first
   real-MAC octet;
3. the shared DMesh IPv6 multicast MAC `33:33:00:00:52:27`.

For normal AP/STA data paths, the kernel and firmware should be allowed to use
the ordinary interface receive filter. Monitor mode is the raw 802.11 fallback
and debug path, and lmesh should not create monitor interfaces unless a caller
explicitly requests a monitor RX/TX or management-capture method.

`wifi.data.listen` is the normal-interface test hook for that path. It opens an
AF_PACKET socket on the AP/STA netdev and requests packet multicast membership
for the real MAC, raw receive MAC, and shared multicast MAC. Frames delivered by
the kernel data path are recorded as `wifi.data.rx`. `wifi.data.send` emits the
same payload shape as an Ethernet frame on an associated AP/STA interface.

For the synthetic unassociated-station experiment, use
`wifi.raw.send tx_variant=sta_multicast_llc destination=<ap-bssid>`. That
injects a STA-to-AP ToDS 802.11 data frame whose LLC/SNAP payload maps to the
DMesh Ethernet frame. If the AP driver accepts a station created with
`wifi.ap.station.add`, that frame should appear on the AP normal netdev and be
visible to `wifi.data.listen`. If it only appears on monitor, the driver is
dropping it before netdev delivery.

Observed on the current mt76 USB setup:

1. Without a station table entry, a `sta_multicast_llc` frame is visible on the
   AP monitor interface but is not delivered as `wifi.data.rx`.
2. With a synthetic `wifi.ap.station.add` entry that sets authorized,
   authenticated, and associated station flags, the same frame increments AP
   station RX counters and is delivered on the normal AP netdev as
   `wifi.data.rx`.

## Tunable surface

The current host cards advertise these useful nl80211 capabilities:

| Tuning area | Driver support observed | lmesh status |
|---|---|---|
| 2.4 GHz channel | channels 1-11 usable, 12-14 no-IR/disabled depending on card | AP/raw fixed to channel 6 by default; raw calls accept `channel` |
| Channel width | HT20/HT40, MCS 0-7 | AP fixed to HT20 |
| Per-vif TX power | supported | not exposed |
| Retry limits | short 7, long 4 currently reported | not exposed |
| Coverage class | currently 0 | not exposed |
| Bitrate mask | `set_tx_bitrate_mask` supported | not exposed |
| Multicast rate | `set_mcast_rate` supported | not exposed |
| No-ack map | `set_noack_map` supported | not exposed |
| Channel switch | supported | not exposed |
| Station table | `new_station`, station dump, full AP/GO client state transitions | minimal add and dump exposed |
| AP management RX | auth/assoc/reassoc/disassoc/deauth/probe/action supported | recorded as `wifi.ap.mgmt` |
| Multi-channel concurrency | valid combinations allow only `#channels <= 1` | keep AP, STA, raw, NAN-like control on channel 6 |

Initial profile ideas:

| Profile | Likely settings |
|---|---|
| `range` | 2.4 GHz, 20 MHz, low basic/MCS rates, maximum allowed TX power, no-ack raw multicast/action frames, larger coverage class |
| `rate` | 5/6 GHz when available, wider channels, higher basic/HT/VHT/HE rates, lower retry cost, AP/STA data path preferred |
| `low_power` | lower per-vif TX power, short listen windows, AP disabled when not needed, raw control only |

## Pending experiments

1. Verify direct `wifi.sta.join_open iface=wlan2` can associate to the lmesh AP
   on `wlan0`.
2. Confirm `wifi.ap.mgmt` records auth and assoc request frames with RSSI.
3. Send raw frames from an unassociated STA and check whether the AP monitor or
   AP SME path receives them.
4. If unassociated raw frames fail, add the STA MAC with
   `wifi.ap.station.add` and retry raw TX/RX.
5. Add lmesh APIs for the supported tuning surface above once the useful driver
   calls are proven on the current cards.
