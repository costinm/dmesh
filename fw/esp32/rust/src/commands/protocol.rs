use anyhow::{anyhow, bail, Result};
use minicbor::{data::Type, Decoder, Encoder};
use std::net::IpAddr;

use super::CommandRequest;

/// Common compact-CBOR field identifiers. These match `mesh::cbor` but are
/// intentionally duplicated: firmware does not link the host crate.
pub const CBOR_METHOD: u16 = 0;
pub const CBOR_PAYLOAD: u16 = 6;
pub const CBOR_STATUS: u16 = 4;
pub const CBOR_ERROR: u16 = 5;
/// Maximum compact-CBOR body accepted on a firmware transport. Keep this
/// below 4 KiB so a corrupted stream can be recovered with the 4,000-byte
/// resynchronization marker without treating the marker as a valid packet.
pub const CBOR_MAX_RECORD: usize = 4_000;

fn cbor_major_type(byte: u8) -> &'static str {
    match byte >> 5 {
        0 => "unsigned",
        1 => "negative",
        2 => "bytes",
        3 => "text",
        4 => "array",
        5 => "map",
        6 => "tag",
        _ => "simple/float",
    }
}

fn cbor_first_byte_error(input: &[u8], expected: &str) -> anyhow::Error {
    match input.first().copied() {
        Some(byte) => anyhow!(
            "CBOR first_byte=0x{byte:02x} major_type={} expected {expected}",
            cbor_major_type(byte),
        ),
        None => anyhow!("CBOR first_byte=none expected {expected}"),
    }
}

fn decode_text_bytes(value: &str) -> Result<Vec<u8>> {
    let value = value.strip_prefix("hex:").unwrap_or(value);
    if value.len() % 2 != 0 {
        bail!("hex payload must have even length");
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| anyhow!("invalid hex payload at byte {index}"))
        })
        .collect()
}

fn network_address_bytes(tag: u16, value: &str) -> Option<Vec<u8>> {
    if !matches!(tag, 246 | 247 | 255 | 256 | 407) {
        return None;
    }
    value.parse::<IpAddr>().ok().map(|address| match address {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    })
}

fn network_address_text(tag: u16, bytes: &[u8]) -> Option<String> {
    if !matches!(tag, 246 | 247 | 255 | 256 | 407) {
        return None;
    }
    let address = match bytes.len() {
        4 => IpAddr::V4(std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])),
        16 => IpAddr::V6(std::net::Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?)),
        _ => return None,
    };
    Some(address.to_string())
}

/// Firmware-local command identifiers. These are two-byte CBOR values and are
/// documented in `crates/lmesh/ESP_FIRMWARE_API.md`.
pub fn command_id(name: &str) -> Option<u16> {
    Some(match name {
        "status" => 33,
        "xstatus" => 34,
        "stats" => 35,
        "logs" => 36,
        "messages" => 37,
        "local_messages" => 38,
        "test" => 39,
        "wifi" => 40,
        "nan" => 41,
        "ble" => 42,
        "lora" => 43,
        "lorasend" => 44,
        "loralisten" => 45,
        "loradump" => 46,
        "loraprobe" => 47,
        "sleep" => 48,
        "mode" => 49,
        // Convenience aliases for the runtime-only infra radio override.
        // They deliberately share the mode handler so no NVS state changes.
        "active" | "idle" => 49,
        "power" => 50,
        "battery" => 51,
        "adcprobe" => 52,
        "namespace" => 53,
        "set" => 54,
        "get" => 55,
        "list" => 56,
        "rgbled" => 57,
        "gpio" => 58,
        "i2cconfig" => 59,
        "i2cprobe" => 60,
        "i2cdetect" => 61,
        "i2cget" => 62,
        "i2cset" => 63,
        "i2cdump" => 64,
        "button" => 65,
        "nvs" => 66,
        "radio" => 67,
        "recovery" => 68,
        "reset" | "rst" => 69,
        "module" => 70,
        "hello" => 71,
        "hw" => 72,
        _ => return None,
    })
}

pub fn command_name(id: u16) -> Option<&'static str> {
    Some(match id {
        33 => "status",
        34 => "xstatus",
        35 => "stats",
        36 => "logs",
        37 => "messages",
        38 => "local_messages",
        39 => "test",
        40 => "wifi",
        41 => "nan",
        42 => "ble",
        43 => "lora",
        44 => "lorasend",
        45 => "loralisten",
        46 => "loradump",
        47 => "loraprobe",
        48 => "sleep",
        49 => "mode",
        50 => "power",
        51 => "battery",
        52 => "adcprobe",
        53 => "namespace",
        54 => "set",
        55 => "get",
        56 => "list",
        57 => "rgbled",
        58 => "gpio",
        59 => "i2cconfig",
        60 => "i2cprobe",
        61 => "i2cdetect",
        62 => "i2cget",
        63 => "i2cset",
        64 => "i2cdump",
        65 => "button",
        66 => "nvs",
        67 => "radio",
        68 => "recovery",
        69 => "reset",
        70 => "module",
        71 => "hello",
        72 => "hw",
        _ => return None,
    })
}

pub fn arg_tag(name: &str) -> Option<u16> {
    Some(match name {
        "message" => 32,
        "status" => 33,
        "stats" => 34,
        "reset" => 35,
        "enabled" | "enable" => 36,
        "rx" => 37,
        "tx" => 38,
        "data" | "payload" => 39,
        "text" => 40,
        // Raw NAN data-frame injection. Keep this distinct from `data`,
        // which is the generic binary command payload on text transports.
        "frame" => 333,
        "hw_filter" => 334,
        "timeout" => 41,
        "mode" => 42,
        "preset" => 43,
        "freq" => 44,
        "bw" => 45,
        "sf" => 46,
        "cr" => 47,
        "sync_word" => 48,
        "preamble" => 49,
        "crc" => 50,
        "board" => 51,
        "chip" => 52,
        "sck" => 53,
        "miso" => 54,
        "mosi" => 55,
        "cs" => 56,
        "rst" => 57,
        "dio0" => 58,
        "busy" => 59,
        "spi_host" => 60,
        "cad" => 61,
        "cad_rx" => 62,
        "cad_tx" => 63,
        "cad_interval_ms" => 64,
        "cad_rx_ms" => 65,
        "cad_tx_tries" => 66,
        "gpio" => 67,
        "level" => 68,
        "pin" => 69,
        "divider" => 70,
        "ctrl" => 71,
        "ctl_lvl" | "ctrl_level" => 72,
        "ref_mv" => 73,
        "min_mv" => 74,
        "max_mv" => 75,
        "sda" => 76,
        "scl" => 77,
        "save" => 78,
        "wake_ms" => 79,
        "active_ms" => 80,
        "early_ms" | "nan_early_ms" | "wake_early_ms" => 81,
        "dw_tu" => 82,
        "dw_off_tu" | "offset_tu" => 83,
        "channel" => 84,
        "light_sleep" | "light" => 85,
        "profile" => 86,
        "op" => 87,
        "args" => 408,
        "name" => 409,
        "raw_response_history" => 410,
        "key" => 88,
        "value" => 89,
        "mult" | "multiplier" => 90,
        "pins" => 91,
        "adv_ms" | "adv_min_ms" | "adv_max_ms" => 92,
        "filter_uuid16" => 93,
        "filter" => 94,
        "filter_addr" => 95,
        "pairing_recovery" | "recovery" => 96,
        "companion" => 97,
        "peer" => 98,
        "pairing" => 99,
        "reset_pairing" | "clear_pairing" => 100,
        "cancel" => 101,
        "start" => 102,
        "stop" => 103,
        "advertise" => 104,
        "bonds" | "paired" => 105,
        "scan_stop" => 106,
        "scan" => 107,
        "coc" => 350,
        "psm" => 351,
        "identity" => 352,
        "keep_active" => 353,
        "bonding" => 354,
        "link_profile" => 355,
        "sleepy" => 356,
        "battery" => 357,
        "pairable" => 108,
        "raw_adv" => 109,
        "announce" => 110,
        "snr" => 111,
        "send" | "gatt" => 112,
        "event" => 113,
        "get" => 114,
        "sniff" => 115,
        "slots" => 116,
        "min_us" | "min_ms" => 117,
        "channel_active" => 118,
        "hop" => 119,
        "wake_only" => 120,
        "network_id" => 340,
        "hop_seed" => 341,
        "bitrate" => 342,
        "deviation" => 343,
        "rx_bw" => 344,
        "slot_ms" => 345,
        "target" => 346,
        "sequence" => 347,
        "rendezvous_scan_ms" => 348,
        "rendezvous_adv_ms" => 349,
        "wifi.mode" => 150,
        "power.profile" => 151,
        "nan.backend" => 152,
        "nan.boot" => 153,
        "nan.role" => 154,
        "nan.service" => 155,
        "nan.channel" => 156,
        "nan.wake_ms" => 157,
        "nan.active_ms" => 158,
        "nan.light_sleep" => 159,
        "nan.early_ms" => 160,
        "nan.dw_tu" => 161,
        "nan.dw_off_tu" => 162,
        "nan.sync_source" => 380,
        "nan.ap_loss_ms" => 382,
        "nan.ap_recovery_ms" => 383,
        "nan.ap_recovery_listen_ms" => 384,
        "nan.ap_slot_tu" => 385,
        "nan.ap_beacon_tu" => 386,
        "nan.dw_stride" => 392,
        "sync_timeout_ms" => 393,
        "beacon_dump" => 388,
        "sync_beacon" => 389,
        "service_dump" => 390,
        "action_dump" => 391,
        "action_history" => 394,
        "publish_dump" => 395,
        "subscribe_dump" => 396,
        // Non-persistent raw-NAN interoperability probe.  This controls
        // whether an otherwise bare unsolicited Publish carries the optional
        // Service Descriptor Extension Attribute.
        "sdea" => 397,
        "availability_map" => 398,
        "sdea_update" => 399,
        "service_history" => 400,
        "beacon_history" => 401,
        "beacon_stats" => 404,
        "response_history" => 405,
        // Flash-control resource selectors.  `module` identifies the DMOD
        // name requested from the negotiated resource server; `gateway` is
        // the static IPv4 route used by Main's STA maintenance session.
        "module" => 406,
        "gateway" => 407,
        // Targeted DW-gated rendezvous SDFs. These are firmware-private
        // fields shared with lmesh's `nan uart_wake`/`ble_wake` helpers.
        "uart_wake" => 402,
        "ble_wake" => 403,
        "uart.hb_every" => 387,
        "battery.divider" => 163,
        "battery.mult" => 164,
        "ble.peer" => 165,
        "identity.node" => 166,
        "identity.meshtastic" => 167,
        "lora.enabled" => 301,

        "ack" => 121,
        "active" => 122,
        "adv" => 123,
        "after_seq" => 124,
        "ap" => 125,
        "ap_bssid" => 126,
        "ap_psk" => 127,
        "ap_ssid" => 128,
        "apply" => 129,
        "backend" => 130,
        "bytes" => 2,
        "beacon_ms" => 131,
        "ble" => 132,
        "ble_scan" => 133,
        "bssid" => 134,
        "bssid_filter" => 135,
        "cad_timeout" | "timeout_ms" => 136,
        "clear" => 137,
        "cnt" => 138,
        "confirm_ms" => 139,
        "confirm_timeout_ms" => 140,
        "conn_wake_ms" => 141,
        "count" => 142,
        "ctrl_pin" => 143,
        "cycle" => 144,
        "d" => 145,
        "data_ds" => 146,
        "depth" => 147,
        "destination" => 148,
        "direction" => 149,
        "disable" => 150,
        "discover" => 151,
        "discovery" => 152,
        "ds" => 153,
        "dst" => 154,
        "dump" => 155,
        "enable_level" => 156,
        "enable_pin" => 157,
        "enqueue" => 158,
        "extend_ms" => 159,
        "extend_on_rx" => 160,
        "fixed_pin" => 161,
        "format" => 162,
        "forward" => 163,
        "hash" => 164,
        "hop_limit" => 165,
        "if" => 166,
        "iface" => 167,
        "infra" => 168,
        "instance" => 169,
        "interval_ms" => 170,
        "join_psk" => 171,
        "join_ssid" => 172,
        "local_only" => 173,
        "locks" => 174,
        "lora" => 175,
        "lora_listen" => 176,
        "lora_sleep" => 177,
        "lora_sleep_listen" => 178,
        "max_bytes" => 179,
        "max_mhz" => 180,
        "min_mhz" => 181,
        "monitor" => 182,
        "ms" => 183,
        "mtu" => 184,
        "netif_probe" => 185,
        "netif_stats" => 186,
        "off" => 187,
        "open_drain" => 188,
        "passkey" => 189,
        "ping" => 190,
        "port" => 191,
        "portnum" => 192,
        "probe" => 193,
        "ps" => 194,
        "psk" => 195,
        "publish" => 196,
        "pull" => 197,
        "queue" => 198,
        "quiet" => 199,
        "r" => 200,
        "radio_wake" => 201,
        "raw" => 202,
        "raw_action" => 203,
        "raw_bssid" => 204,
        "raw_data" => 205,
        "raw_filter" => 206,
        "raw_monitor" => 207,
        "raw_nan" => 208,
        "raw_payload" => 209,
        "raw_stats" => 210,
        // Keep diagnostic-only fields outside the established network
        // address range; 272 is reserved for this diagnostic selector.
        "object_action_stats" => 272,
        "raw_stop" => 211,
        "raw_tx" => 212,
        "raw_wifi" => 213,
        "register" => 214,
        "repeat" => 215,
        "request_ms" => 216,
        "restore" => 217,
        "rssi" => 218,
        "role" => 219,
        "seq" => 220,
        "serial" => 221,
        "service" => 222,
        "sleep" => 223,
        "source_mac" => 224,
        "src" => 225,
        "ssid" => 226,
        "sta_psk" => 227,
        "sta_ssid" => 228,
        "sync" => 229,
        "sys_seq" => 230,
        "time" => 231,
        "to" => 331,
        "from" => 332,
        "to_ap" => 232,
        "tods" => 233,
        "transport" => 234,
        "uart_off" => 235,
        "uart_probe_ms" => 236,
        "uart_probe_reset" => 237,
        "uart_status" => 238,
        "uart_uninstall" => 239,
        "wake_interval_ms" => 240,
        "wifi" => 241,
        "wifi_wake" => 242,
        "window_ms" => 243,
        "request" => 244,
        "reboot" => 245,
        "server" => 246,
        "ip" => 247,
        "url" => 248,
        "flags" => 249,
        "password" => 250,
        "offset" => 251,
        "length" => 252,
        "verify" => 253,
        "size" => 254,
        "gw" => 255,
        "mask" => 256,
        // Flash-control mode is a typed boolean in the compact CBOR payload.
        // Keep it outside the legacy 0..256 argument range so this field can
        // be added without renumbering existing firmware arguments.
        "dry_run" => 257,
        "bench_stats" => 258,
        "bench_stream_send" => 259,
        "bench_send" => 260,
        "bench_reset" => 261,
        "delay_us" => 262,
        "udp_hello" => 263,
        "udp_hello_status" => 264,
        "udp_dry_run" => 265,
        "udp_dry_run_status" => 266,
        "udp_status_probe" => 267,
        "udp_status_probe_status" => 268,
        "udp_status_server" => 269,
        "udp_status_server_status" => 270,
        "verify_sha" => 271,
        // UDP object-transfer mode: receive/verify only when false, or
        // commit the received image when true.  This is deliberately a
        // typed command field so the managed flash helper and the text
        // command path use the same wire representation.
        "write_flash" => 273,
        // Stream-transport session selector. Keep this typed field stable so
        // remote two-connection diagnostics can select a local CID without
        // falling back to positional text arguments.
        "cid" => 274,
        _ => return None,
    })
}

/// Encode a flat compact-CBOR command. USB/TTY adds its length/type envelope;
/// BLE, LoRa, NAN, raw Wi-Fi, and UDP carry these bytes directly.
pub fn encode_binary(request: &CommandRequest) -> Vec<u8> {
    let mut out = Vec::new();
    let mut encoder = Encoder::new(&mut out);

    let has_status = request.args.contains_key(&CBOR_STATUS);
    let has_error = request.args.contains_key(&CBOR_ERROR);
    let payload_fields = request
        .args
        .iter()
        .filter(|(&k, _)| k != CBOR_STATUS && k != CBOR_ERROR)
        .count()
        + request
            .binary_args
            .keys()
            .filter(|&&k| {
                k != CBOR_STATUS && k != CBOR_ERROR && !request.args.contains_key(&k)
            })
            .count()
        + usize::from(!request.payload.is_empty());

    let entries =
        1 + usize::from(has_status) + usize::from(has_error) + usize::from(payload_fields > 0);

    encoder.map(entries as u64).expect("Vec CBOR encode");
    encoder.u16(CBOR_METHOD).expect("Vec CBOR encode");
    encoder.u16(request.method).expect("Vec CBOR encode");

    if let Some(status_val) = request.args.get(&CBOR_STATUS) {
        encoder.u16(CBOR_STATUS).expect("Vec CBOR encode");
        encoder.str(status_val).expect("Vec CBOR encode");
    }
    if let Some(err_val) = request.args.get(&CBOR_ERROR) {
        encoder.u16(CBOR_ERROR).expect("Vec CBOR encode");
        encoder.str(err_val).expect("Vec CBOR encode");
    }

    if payload_fields > 0 {
        encoder.u16(CBOR_PAYLOAD).expect("Vec CBOR encode");
        encoder.map(payload_fields as u64).expect("Vec CBOR encode");
        for (&tag, value) in &request.args {
            if tag != CBOR_STATUS && tag != CBOR_ERROR {
                encoder.u16(tag).expect("Vec CBOR encode");
                if let Some(bytes) = request.binary_args.get(&tag) {
                    encoder.bytes(bytes).expect("Vec CBOR encode");
                } else {
                    encoder.str(value).expect("Vec CBOR encode");
                }
            }
        }
        for (&tag, bytes) in &request.binary_args {
            if tag != CBOR_STATUS && tag != CBOR_ERROR && !request.args.contains_key(&tag) {
                encoder.u16(tag).expect("Vec CBOR encode");
                encoder.bytes(bytes).expect("Vec CBOR encode");
            }
        }
        if !request.payload.is_empty() {
            encoder.u16(39).expect("Vec CBOR encode");
            encoder.bytes(&request.payload).expect("Vec CBOR encode");
        }
    }
    out
}

pub fn decode_binary(input: &[u8]) -> Result<CommandRequest> {
    if input.len() > CBOR_MAX_RECORD {
        bail!("CBOR command exceeds {CBOR_MAX_RECORD} bytes");
    }
    if input.first().map(|byte| byte >> 5) != Some(5) {
        return Err(cbor_first_byte_error(input, "map").context("invalid CBOR command"));
    }
    let mut decoder = Decoder::new(input);
    let count = decoder.map().map_err(|error| {
        anyhow!(
            "CBOR first_byte=0x{:02x} major_type={} expected map: {error}",
            input[0],
            cbor_major_type(input[0]),
        )
    })?;
    let mut method_id = 0;
    let mut method_name = None;
    let mut args = std::collections::BTreeMap::new();
    let mut binary_args = std::collections::BTreeMap::new();
    let mut payload = Vec::new();
    let mut entries = 0u64;
    loop {
        if let Some(count) = count {
            if entries >= count {
                break;
            }
        } else if decoder.datatype()? == Type::Break {
            decoder.skip()?;
            break;
        }
        entries += 1;
        let numeric_key = match decoder.datatype()? {
            Type::U8 | Type::U16 | Type::U32 => decoder.u16()?,
            kind => bail!("unsupported CBOR command key {kind:?}"),
        };
        match numeric_key {
            CBOR_METHOD => {
                method_id = match decoder.datatype()? {
                    Type::U8 | Type::U16 | Type::U32 => decoder.u16()?,
                    Type::String => {
                        let name = decoder.str()?;
                        let method = command_id(name)
                            .ok_or_else(|| anyhow!("unknown CBOR command name: {name}"))?;
                        method_name = Some(name.to_owned());
                        method
                    }
                    kind => bail!("unsupported CBOR method value {kind:?}"),
                };
            }
            CBOR_STATUS => {
                args.insert(CBOR_STATUS, decoder.str()?.to_owned());
            }
            CBOR_ERROR => {
                args.insert(CBOR_ERROR, decoder.str()?.to_owned());
            }
            CBOR_PAYLOAD => {
                let payload_count = decoder.map()?;
                let mut payload_entries = 0u64;
                loop {
                    if let Some(payload_count) = payload_count {
                        if payload_entries >= payload_count {
                            break;
                        }
                    } else if decoder.datatype()? == Type::Break {
                        decoder.skip()?;
                        break;
                    }
                    payload_entries += 1;
                    let tag = match decoder.datatype()? {
                        Type::U8 | Type::U16 | Type::U32 => decoder.u16()?,
                        Type::String => {
                            let key = decoder.str()?;
                            if key == "data" {
                                39
                            } else {
                                arg_tag(key)
                                    .ok_or_else(|| anyhow!("unknown payload key string: {key}"))?
                            }
                        }
                        kind => bail!("unsupported CBOR payload key {kind:?}"),
                    };
                    if tag == 39 {
                        match decoder.datatype()? {
                            Type::Bytes => payload.extend_from_slice(decoder.bytes()?),
                            // Text transports encode `data=...` as a string
                            // inside the payload map. Accept the documented
                            // hex form as well as native CBOR byte strings.
                            Type::String => payload.extend(decode_text_bytes(decoder.str()?)?),
                            kind => bail!("unexpected payload data type {kind:?}; expected bytes or hex string"),
                        }
                    } else {
                        let value = match decoder.datatype()? {
                            Type::String => decoder.str()?.to_owned(),
                            Type::Bool => decoder.bool()?.to_string(),
                            Type::Bytes => {
                                let bytes = decoder.bytes()?.to_vec();
                                if let Some(value) = network_address_text(tag, &bytes) {
                                    // Keep the printable view for existing
                                    // handlers while retaining the canonical
                                    // bytes for the next encode.
                                    args.insert(tag, value);
                                }
                                binary_args.insert(tag, bytes);
                                continue;
                            }
                            kind => bail!("unsupported payload value type {kind:?}"),
                        };
                        if let Some(bytes) = network_address_bytes(tag, &value) {
                            // Preserve the text spelling for handlers and
                            // diagnostics, but make every re-encoded packet
                            // use the canonical network-order byte string.
                            binary_args.insert(tag, bytes);
                        }
                        args.insert(tag, value);
                    }
                }
            }
            key => bail!("unsupported reserved CBOR command field {key}"),
        }
    }
    if decoder.position() != input.len() {
        bail!("trailing CBOR command data");
    }
    let mut request = CommandRequest::new_binary(method_id);
    if let Some(method_name) = method_name {
        request.name = method_name;
    }
    request.args = args;
    request.binary_args = binary_args;
    request.payload = payload;
    Ok(request)
}

pub fn escape_value(value: &str) -> String {
    quote_text_value(value)
}

pub fn quote_text_value(value: &str) -> String {
    if is_bare_text_value(value) {
        return value.to_string();
    }
    let mut out = String::new();
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

fn is_bare_text_value(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\'' | b'\\' | b'='))
}

#[cfg(test)]
mod tests {
    use minicbor::Encoder;

    use super::{arg_tag, command_id, decode_binary};

    #[test]
    fn active_and_idle_aliases_keep_their_cbor_method_name() {
        for name in ["active", "idle"] {
            let mut bytes = Vec::new();
            Encoder::new(&mut bytes)
                .map(1)
                .unwrap()
                .u16(0)
                .unwrap()
                .str(name)
                .unwrap();
            let request = decode_binary(&bytes).unwrap();
            assert_eq!(request.method, command_id("mode").unwrap());
            assert_eq!(request.name, name);
        }
    }

    #[test]
    fn sdea_probe_has_a_stable_cbor_tag() {
        assert_eq!(arg_tag("sdea"), Some(397));
    }

    #[test]
    fn service_history_has_a_stable_cbor_tag() {
        assert_eq!(arg_tag("service_history"), Some(400));
    }

    #[test]
    fn beacon_history_has_a_stable_cbor_tag() {
        assert_eq!(arg_tag("beacon_history"), Some(401));
    }

    #[test]
    fn beacon_stats_has_a_stable_cbor_tag() {
        assert_eq!(arg_tag("beacon_stats"), Some(404));
    }

    #[test]
    fn role_has_a_stable_cbor_tag() {
        assert_eq!(arg_tag("role"), Some(219));
    }

    #[test]
    fn transport_cid_has_a_stable_cbor_tag() {
        assert_eq!(arg_tag("cid"), Some(274));
    }

    #[test]
    fn nan_transport_request_decodes_cid_selector() {
        let mut bytes = Vec::new();
        Encoder::new(&mut bytes)
            .map(2)
            .unwrap()
            .u16(0)
            .unwrap()
            .str("nan")
            .unwrap()
            .u16(6)
            .unwrap()
            .map(4)
            .unwrap()
            .str("transport")
            .unwrap()
            .str("request")
            .unwrap()
            .str("peer")
            .unwrap()
            .str("840d8e074170")
            .unwrap()
            .str("cid")
            .unwrap()
            .str("1281")
            .unwrap()
            .str("service")
            .unwrap()
            .str("metrics")
            .unwrap();
        let request = decode_binary(&bytes).unwrap();
        assert_eq!(request.arg("transport"), Some("request"));
        assert_eq!(request.arg("peer"), Some("840d8e074170"));
        assert_eq!(request.arg("cid"), Some("1281"));
        assert_eq!(request.arg("service"), Some("metrics"));
    }

    #[test]
    fn dry_run_is_a_typed_boolean_payload_field() {
        assert_eq!(arg_tag("dry_run"), Some(257));
        let mut bytes = Vec::new();
        Encoder::new(&mut bytes)
            .map(2).unwrap()
            .u16(0).unwrap().str("recovery").unwrap()
            .u16(6).unwrap()
            .map(1).unwrap().str("dry_run").unwrap().bool(true).unwrap();
        let request = decode_binary(&bytes).unwrap();
        assert_eq!(request.arg("dry_run"), Some("true"));
    }

    #[test]
    fn text_payload_data_is_decoded_as_hex_bytes() {
        let mut bytes = Vec::new();
        Encoder::new(&mut bytes)
            .map(2).unwrap()
            .u16(0).unwrap().str("lorasend").unwrap()
            .u16(6).unwrap()
            .map(1).unwrap().str("data").unwrap().str("hex:00ff10").unwrap();
        let request = decode_binary(&bytes).unwrap();
        assert_eq!(request.payload, vec![0x00, 0xff, 0x10]);
    }

    #[test]
    fn indefinite_command_and_payload_maps_are_stream_decoded() {
        // {0: "mode", 6: {80: "1000"}} using indefinite maps.
        let bytes = vec![
            0xbf, 0x00, 0x64, b'm', b'o', b'd', b'e', 0x06, 0xbf, 0x18, 0x50, 0x64, b'1',
            b'0', b'0', b'0', 0xff, 0xff,
        ];
        let request = decode_binary(&bytes).unwrap();
        assert_eq!(request.name, "mode");
        assert_eq!(request.args.get(&80).map(String::as_str), Some("1000"));
    }

    #[test]
    fn network_addresses_use_byte_strings_and_accept_ipv6() {
        let mut bytes = Vec::new();
        Encoder::new(&mut bytes)
            .map(2)
            .unwrap()
            .u16(0)
            .unwrap()
            .str("wifi")
            .unwrap()
            .u16(6)
            .unwrap()
            .map(2)
            .unwrap()
            .u16(247)
            .unwrap()
            .str("10.78.0.200")
            .unwrap()
            .u16(255)
            .unwrap()
            .bytes(&[0x20, 0x01, 0xdb, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
            .unwrap();
        let request = decode_binary(&bytes).unwrap();
        assert_eq!(request.arg("ip"), Some("10.78.0.200"));
        assert_eq!(request.arg_bytes("ip"), Some(&[10, 78, 0, 200][..]));
        assert_eq!(request.arg_bytes("gw"), Some(&[0x20, 0x01, 0xdb, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1][..]));
        let encoded = encode_binary(&request);
        assert!(encoded
            .windows(7)
            .any(|window| window == [0x18, 0xf7, 0x44, 10, 78, 0, 200]));
    }
}
