# Main NAN inventory and migration map

This is the migration record for replacing `fw/esp32/rust/src/components/nan.rs`
with the shared `dmesh-mod-rawwifi::nan` core. The current Main implementation
remains authoritative at runtime while the module path is proven. The goal is
to preserve the tested NAN wire format and debugging evidence, not to copy
Main's ESP-IDF/FreeRTOS ownership into a `no_std` crate.

## What belongs in the shared `no_std` core

These operations are pure byte parsing, deterministic frame construction, or
bounded state transitions. They can be used unchanged by Main, the ESP DMOD,
and the Linux/lmesh adapter:

- Address/layout constants: `FRAME_DST`, `FRAME_SRC`, `FRAME_BSSID`,
  `FRAME_DATA`, `NAN_ACTION_START`, `NAN_BSSID`, `NAN_DISCOVERY_MAC`,
  `SVC_ID`, and the DMESH/NAN service flags.
- Frame recognition and fields: `is_nan_bssid`, `is_nan_sdf`,
  `is_nan_followup`, `beacon_tsf_us`, `beacon_interval_tu`,
  `is_direct_dmesh_ssid`, `raw_service_descriptor_payload`,
  `dmesh_service_descriptor_kind`, and `classify`.
- Service/follow-up codecs: `raw_service_descriptor_payload`,
  `parse_dmesh_nan_followup`, `is_dmesh_nan_service_info`,
  `wake_request_for_service`, `active_ack_for_service`,
  `dmesh_nan_followup_frame`, `nan_followup_frame`, `nan_service_info`,
  `nan_service_info_with_wake`, `nan_service_extension`, and `fnv1a32`.
- Cluster policy: `ClusterBeaconDecision`, `cluster_beacon_decision`,
  `accept_nan_cluster`, `store_nan_cluster_bssid_bytes`,
  `configured_filter_bssid`, `nan_cluster_bssid`, `matches_filter`, and the
  shared `NanState` transition/timeout behavior.
- Timing math: `sync_to_next_discovery_window`,
  `sync_to_observed_discovery_window`, `wait_us_until_tsf_phase`,
  `estimated_tsf_us`, `beacon_age_ms`, and `nan_beacon_matching_since` once
  their clock access is passed as a scalar instead of read from ESP globals.
- Bounded packet representations: `RawNanCommandInfo`, `DmeshNanFollowup`,
  `NanIncomingCommand`, `RawNanOutgoing`, and receipt records, after replacing
  `Vec`/`String` with fixed-capacity buffers or caller-owned slices.

The first extraction already supplies shared implementations for the NAN
address tests, beacon TSF/interval parsing, SDF recognition, service
descriptor parsing, follow-up parsing, service-info validation, wake flags,
FNV-1a, and cluster state.

## Main/ESP adapter responsibilities

These functions must stay outside the portable core because they access
ESP-IDF, FreeRTOS, Main settings, Main services, or the firmware's radio
ownership policy:

- Runtime lifecycle and command registration: `register_commands`,
  `start_raw_window`, `stop_nan`, `transport`, `poll_rx`, `take_command`,
  `forward_packet`, `forward_or_queue_packet`, `queue_response_payload_to`,
  `queue_raw_broadcast`, `drain_raw_queue`,
  `drain_publish_on_discovery_window`, and `raw_tx_active`.
- Main integration and policy: `configured_discovery_role`,
  `set_discovery_role`, `set_solicited_publish_attributes`,
  `queue_solicited_publish`, `apply_dw_control`,
  `command_targets_this_device_cbor`, `target_matches_local`,
  `local_mac_matches`, `parse_uart_wake_target`, and all calls into
  `mode`, `wake`, `serial`, `ble_bt`, `lora`, `wifi`, `telemetry`, and the
  command registry.
- ESP queue/task/interrupt plumbing: `nan_command_queue`,
  `nan_outgoing_queue`, `nan_publish_queue`, `ensure_rx_queue`,
  `enqueue_raw_command`, `enqueue_outgoing_raw`, `drain_outgoing_raw`,
  `task_delay`, `duration_to_ticks`, `now_us`, `raw_tx`, and
  `clear_pending_nan_transmissions`.
- ESP hardware and ownership: `start_raw_sniffer`,
  `reconcile_hardware_bssid_filter`, `configured_hardware_filter_bssid`,
  `station_mac`, `raw_tx`, `esp_ok`, and the `esp_wifi_*`/GPIO/queue calls
  reached from these functions.
- Main transport/task types: `NanBackend`, `NanCommandPeer`,
  `NanDiscoveryRole`, `NanCommand`, `NanTransport`, and `RawNanRxFrame`.
  The module receives equivalent host-table capabilities but does not link
  their implementations.

## Diagnostics worth preserving

The following are useful evidence and should become structured counters/events
instead of formatted strings:

- RX/TX/drop counters: `raw_response_rx_count`, `raw_command_rx_count`,
  `raw_response_tx_count`, `raw_queue_len`, `raw_work_pending`,
  `raw_command_pending_count`, `raw_response_pending_count`, plus the
  `NAN_RX_*`, `NAN_RAW_*`, `NAN_DMESH_*`, and hardware-filter counters.
- Beacon evidence: `last_nan_sync_beacon`, `nan_beacon_snapshot`,
  `nan_beacon_age_ms`, `last_ap_sync_beacon`, `ap_beacon_age_ms`,
  `nan_cluster_reselects`, `render_beacon_history`, `beacon_stats`,
  `reset_beacon_stats`, and `nan_beacon_matching_since`.
- Packet evidence: `record_service_receipt`, `render_service_history`,
  `record_followup_receipt`, `render_followup_history`,
  `record_raw_response`, `render_raw_response_history`, `raw_payload`,
  `raw_command_info`, and `rx_timing_fields`.
- Formatting/configuration helpers such as `encode_hex`, `parse_bytes`,
  `parse_mac`, `format_mac`, `parse_filter_mode`, and `filter_name` may stay
  in Main's text command adapter; the module should expose typed values.

## Frame construction and scheduling split

The pure constructors should move first and be covered by golden fixtures:

- `nan_sync_beacon_frame`, `nan_sync_beacon_frame_for`,
  `nan_availability_attribute`, `nan_publish_attributes`,
  `nan_device_capability_attribute`, `nan_publish_frame*`,
  `nan_service_info*`, and `dmesh_nan_followup_frame`.

Their callers remain Main/ESP scheduling code until the module can acquire the
radio exclusively. In particular, `sync_to_*`, `wait_for_beacon_or_timeout`,
`wait_for_discovery_beacon_at_phase`, `drain_publish_on_discovery_window`,
and `drain_outgoing_raw` must be rewritten around the module's bounded
`RawWifiIo` callbacks rather than copied with blocking ESP calls.

## Full function inventory

For auditability, every current function is accounted for below.

| Group | Functions |
|---|---|
| Configuration/queues | `configured_discovery_role`, `nan_command_queue`, `nan_outgoing_queue`, `nan_publish_queue`, `clear_pending_nan_transmissions`, `set_discovery_role`, `solicited_publish_attributes`, `set_solicited_publish_attributes`, `queue_solicited_publish`, `followup_history`, `service_history`, `raw_response_history` |
| Public runtime | `take_command`, `poll_rx`, `register_commands`, `transport`, `forward_packet`, `forward_or_queue_packet`, `raw_followup_frame`, `start_raw_window`, `stop_nan`, `queue_response_payload_to`, `queue_raw_broadcast`, `drain_raw_queue`, `raw_work_pending`, `raw_command_pending_count`, `raw_response_pending_count`, `drain_publish_on_discovery_window`, `raw_response_rx_count`, `raw_command_rx_count`, `raw_response_tx_count`, `raw_queue_len`, `raw_tx_active` |
| Diagnostics | `record_service_receipt`, `render_service_history`, `record_followup_receipt`, `render_followup_history`, `record_raw_response`, `render_raw_response_history`, `last_nan_sync_beacon`, `nan_beacon_snapshot`, `nan_cluster_reselects`, `render_beacon_history`, `beacon_stats_source_name`, `beacon_stats_bssid`, `store_beacon_stats_bssid`, `reset_beacon_stats`, `record_beacon_stats`, `beacon_stats`, `nan_beacon_matching_since`, `last_ap_sync_beacon`, `nan_beacon_age_ms`, `ap_beacon_age_ms`, `raw_payload`, `rx_timing_fields`, `stats`, `filter_name` |
| Parsing | `raw_command_info`, `dmesh_service_descriptor_kind`, `is_nan_followup`, `raw_service_descriptor_payload`, `parse_dmesh_nan_followup`, `is_dmesh_nan_service_info`, `wake_request_for_service`, `active_ack_for_service`, `is_nan_bssid`, `beacon_tsf_us`, `beacon_interval_tu`, `is_direct_dmesh_ssid`, `is_nan_sdf`, `matches_filter` |
| Cluster/filter | `store_nan_cluster_bssid`, `cluster_beacon_decision`, `accept_nan_cluster`, `store_nan_cluster_bssid_bytes`, `configured_filter_bssid`, `nan_cluster_bssid`, `configured_hardware_filter_bssid`, `reconcile_hardware_bssid_filter` |
| Timing | `sync_to_next_discovery_window`, `sync_to_observed_discovery_window`, `wait_for_beacon_or_timeout`, `wait_for_discovery_beacon_at_phase`, `wait_us_until_tsf_phase`, `estimated_tsf_us`, `beacon_age_ms`, `store_last_beacon_local_us`, `store_last_beacon_tsf_us`, `last_beacon_local_us`, `last_beacon_tsf_us`, `load_u64`, `store_u64` |
| Frame construction | `dmesh_nan_followup_frame`, `nan_sync_beacon_frame`, `nan_sync_beacon_frame_for`, `nan_availability_attribute`, `nan_publish_attributes`, `nan_device_capability_attribute`, `nan_publish_frame`, `nan_publish_frame_with_requestor`, `nan_publish_frame_with_uart_wake`, `nan_publish_frame_from_template`, `nan_publish_frame_for`, `nan_publish_frame_for_requestor`, `nan_publish_frame_for_requestor_with_wake`, `nan_service_extension`, `nan_service_info`, `nan_service_info_with_wake`, `nan_followup_frame` |
| Queue/dispatch internals | `enqueue_raw_command`, `command_targets_this_device_cbor`, `enqueue_outgoing_raw`, `add_dw_control`, `apply_dw_control`, `drain_outgoing_raw`, `checked_service_name` |
| ESP/platform | `wait_for_beacon_or_timeout`, `start_raw_sniffer`, `ensure_rx_queue`, `task_delay`, `duration_to_ticks`, `now_us`, `raw_tx`, `station_mac`, `local_target_suffixes`, `target_matches_local`, `local_mac_matches`, `is_broadcast_target`, `parse_uart_wake_target`, `mac_suffix4_hex`, `esp_ok` |
| Small utilities | `fnv1a32`, `encode_hex`, `parse_bytes`, `parse_mac`, `format_mac` |

## Replacement order

1. Keep Main's runtime path and replace its pure parser/codec bodies with
   calls into `dmesh-mod-rawwifi::nan` (currently started for address, beacon,
   SDF, and timing helpers).
2. Move typed service descriptors, DMesh follow-ups, wake flags, and frame
   constructors; add golden tests using captured Main/Android frames.
3. Move cluster selection, filter transitions, beacon timing, and bounded
   diagnostics into shared state objects.
4. Add ESP host-table adapters for RX queue, A3 programming, TX, clock, and
   event emission. Main retains ownership and only supplies primitives.
5. Switch lmesh to the same shared state (the host `wifi.rawwifi.ping`
   command now does this) and verify host↔lora1 before replacing Main's full
   NAN runtime.
