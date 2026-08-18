//! Shared host-side UART command dispatcher and backend.
//!
//! The standalone binary and the main `lmesh` service use this mapping. The
//! transport around it may be JSONL over a mesh socket or the main service's
//! framed mesh protocol.

pub mod client;
pub mod device;
pub mod l2;
mod schema;
mod service;

use serde_json::{Value, json};
pub use service::UartService;

fn string_arg(request: &Value, name: &str) -> Option<String> {
    request.get(name).and_then(Value::as_str).map(str::to_owned)
}

/// Dispatch one UART JSON request and return the stable response envelope.
pub fn handle_request(uart: &UartService, request: Value) -> Value {
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let result = match method {
        "usb.serial.list" => {
            Ok(uart.usb_serial_list(request.get("handshake").and_then(Value::as_bool)))
        }
        "usb.serial.handshake" => Ok(uart.usb_serial_handshake(
            string_arg(&request, "port"),
            string_arg(&request, "profile"),
            request.get("timeout_sec").and_then(Value::as_f64),
            request
                .get("baud")
                .and_then(Value::as_u64)
                .map(|value| value as u32),
        )),
        "usb.serial.boot" => Ok(uart.usb_serial_boot(
            string_arg(&request, "port"),
            string_arg(&request, "command"),
            request.get("timeout_sec").and_then(Value::as_f64),
            request.get("reset").and_then(Value::as_bool),
        )),
        "usb.serial.forward.start"
        | "usb.serial.connect"
        | "usb.serial.forward.stop"
        | "usb.serial.disconnect"
        | "usb.serial.forward.list"
        | "usb.serial.forward.flush" => {
            Err("legacy UART byte forwarding is retired; use the QUIC-lite client".into())
        }
        "usb.serial.rst" | "usb.serial.reset" => {
            Ok(uart.serial_modem_reset(string_arg(&request, "port")))
        }
        "usb.serial.dtr" => Ok(uart.serial_modem_dtr(
            string_arg(&request, "port"),
            request.get("asserted").and_then(Value::as_bool),
            request.get("pulse_ms").and_then(Value::as_u64),
        )),
        "esp.serial.command" => Ok(uart.esp_serial_command_with_options(
            string_arg(&request, "adapter"),
            string_arg(&request, "port"),
            string_arg(&request, "command").unwrap_or_default(),
            request.get("timeout_sec").and_then(Value::as_f64),
            request
                .get("force_direct")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        )),
        "status" => Ok(json!({"service": "lmesh-uart", "uart": uart.status()})),
        _ => Err(format!("unsupported lmesh-uart method {method:?}")),
    };
    match result {
        Ok(data) => json!({"success": true, "data": data}),
        Err(error) => json!({"success": false, "error": error}),
    }
}
