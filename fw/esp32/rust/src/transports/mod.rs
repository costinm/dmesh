use anyhow::Result;

use crate::commands::protocol::{decode_binary, encode_binary};
use crate::commands::{CommandRegistry, CommandRequest, CommandResponse, CommandStatus};

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandFormat {
    Text,
    Binary,
}

#[allow(dead_code)]
pub trait CommandTransport {
    fn name(&self) -> &'static str;
    fn format(&self) -> CommandFormat;
    fn send_response(&mut self, response: &[u8]) -> Result<()>;
}

#[allow(dead_code)]
pub struct LoggingCommandTransport {
    name: &'static str,
    format: CommandFormat,
    responses: u32,
}

impl LoggingCommandTransport {
    #[allow(dead_code)]
    pub fn new(name: &'static str, format: CommandFormat) -> Self {
        Self {
            name,
            format,
            responses: 0,
        }
    }
}

impl CommandTransport for LoggingCommandTransport {
    fn name(&self) -> &'static str {
        self.name
    }

    fn format(&self) -> CommandFormat {
        self.format
    }

    fn send_response(&mut self, response: &[u8]) -> Result<()> {
        self.responses = self.responses.saturating_add(1);
        log::info!(
            "command response: transport={} format={:?} len={} total={}",
            self.name,
            self.format,
            response.len(),
            self.responses
        );
        Ok(())
    }
}

/// Dispatch a compact-CBOR command. UART callers pass the mesh packet body
/// (`00 cb 00 00` followed by CBOR); radio callers pass CBOR directly.
pub fn dispatch_binary_packet(registry: &mut CommandRegistry, packet: &[u8]) -> Vec<u8> {
    let is_framed = packet.starts_with(&[0, 0xcb, 0, 0]);
    let cbor_bytes = if is_framed { &packet[4..] } else { packet };
    // The transport envelope can carry more than command CBOR.  UART also
    // has a fixed DMB1 bootstrap packet, and recovery/ROM paths may leave
    // text or other binary bytes in the stream.  CBOR's top three bits are
    // its major type; command packets must begin with a map
    // (0xa0..0xbf, including indefinite 0xbf).  Do not manufacture an
    // "invalid CBOR" response for a
    // packet that was never claiming to be CBOR in the first place.
    if !is_cbor_map_marker(cbor_bytes) {
        log::debug!(
            "ignoring non-command packet: {}",
            packet_first_byte_summary(cbor_bytes)
        );
        return Vec::new();
    }
    match decode_binary(cbor_bytes) {
        Ok(request) => {
            let response = registry.dispatch(&request);
            let mut response_bytes = encode_response_as_binary(request.method, &response);
            if is_framed {
                response_bytes = wrap_stream_frame(&response_bytes);
            }
            response_bytes
        }
        Err(err) => {
            let mut request = CommandRequest::new_binary(0);
            request.args.insert(5, err.to_string()); // CBOR_ERROR is 5
            let mut response_bytes = encode_binary(&request);
            if is_framed {
                response_bytes = wrap_stream_frame(&response_bytes);
            }
            response_bytes
        }
    }
}

fn is_cbor_map_marker(packet: &[u8]) -> bool {
    packet
        .first()
        .map(|byte| *byte >> 5 == 5)
        .unwrap_or(false)
}

fn packet_first_byte_summary(packet: &[u8]) -> String {
    let Some(&byte) = packet.first() else {
        return "first_byte=none type=empty".to_string();
    };
    let kind = match byte >> 5 {
        0 => "unsigned",
        1 => "negative",
        2 => "bytes",
        3 => "text",
        4 => "array",
        5 => "map",
        6 => "tag",
        _ => "simple/float",
    };
    format!("first_byte=0x{byte:02x} major_type={kind}")
}

/// Dispatch a compact-CBOR command for the BLE CoC rendezvous transport.
///
/// The current CoC service deliberately uses a single 256-byte SDU per
/// request and response.  Keep the response as a complete CBOR map: cutting
/// the ordinary response byte stream would turn an otherwise useful status
/// reply into malformed CBOR.  Larger component responses therefore become a
/// small, explicit partial response; callers can request a narrower command
/// or use a packet transport with a larger framing budget.
pub fn dispatch_coc_packet(registry: &mut CommandRegistry, packet: &[u8]) -> Vec<u8> {
    const COC_MAX_RESPONSE: usize = 256;

    let response = dispatch_binary_packet(registry, packet);
    if response.len() <= COC_MAX_RESPONSE {
        return response;
    }

    let method = decode_binary(packet)
        .map(|request| request.method)
        .unwrap_or(0);
    let mut partial = CommandRequest::new_binary(method);
    partial.args.insert(4, "partial".to_string()); // CBOR_STATUS is 4
    partial.args.insert(
        32,
        format!("CoC response exceeds {COC_MAX_RESPONSE} bytes; request a compact status"),
    );
    let response = encode_binary(&partial);
    debug_assert!(response.len() <= COC_MAX_RESPONSE);
    response
}

/// Dispatch one compact-CBOR UART packet. UART's HDLC/PPP codec is below this
/// layer; lmesh adds the generic mesh stream envelope on the UDS side.
/// Valid command maps return a complete stream record. Non-CBOR packets are
/// ignored without fabricating a CBOR error response.
pub fn dispatch_uart_packet(registry: &mut CommandRegistry, packet: &[u8]) -> Vec<u8> {
    let response = dispatch_binary_packet(registry, packet);
    if response.is_empty() {
        Vec::new()
    } else {
        wrap_stream_frame(&response)
    }
}

fn wrap_stream_frame(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 8);
    let len = data.len() + 4;
    out.extend_from_slice(&(len as u32).to_be_bytes());
    out.extend_from_slice(&[0, 0xcb, 0, 0]);
    out.extend_from_slice(data);
    out
}

fn encode_response_as_binary(method: u16, response: &CommandResponse) -> Vec<u8> {
    let mut request = CommandRequest::new_binary(method);
    match response.status {
        CommandStatus::Ok => {
            request.args.insert(4, "ok".to_string()); // CBOR_STATUS is 4
            if !response.message.is_empty() {
                request.args.insert(32, response.message.clone()); // tag 32 for message
            }
        }
        CommandStatus::Error => {
            request.args.insert(5, response.message.clone()); // CBOR_ERROR is 5
        }
    }
    request.payload = response.payload.clone();
    encode_binary(&request)
}

#[cfg(test)]
mod tests {
    use super::{is_cbor_map_marker, packet_first_byte_summary};

    #[test]
    fn classifies_cbor_major_types_before_command_decode() {
        assert!(is_cbor_map_marker(&[0xa2]));
        assert!(is_cbor_map_marker(&[0xb7]));
        assert!(is_cbor_map_marker(&[0xbf]));
        assert!(!is_cbor_map_marker(b"status\n"));
        assert!(!is_cbor_map_marker(b"DMB1"));
        assert!(!is_cbor_map_marker(&[0x82]));
        assert_eq!(packet_first_byte_summary(&[0x82]), "first_byte=0x82 major_type=array");
    }
}

/// Encode a diagnostic notification using the same binary stream as command
/// responses. The diagnostic text is payload data, never UART text output.
pub fn encode_log_notification(line: &str) -> Vec<u8> {
    wrap_stream_frame(&encode_log_packet(line))
}

/// Encode a diagnostic notification for a packet transport. Unlike UART, radio
/// transports already carry packet boundaries and must not receive stream metadata.
pub fn encode_log_packet(line: &str) -> Vec<u8> {
    let mut event = CommandRequest::new_binary(0);
    event.args.insert(4, "event".to_string());
    event.args.insert(32, line.to_string());
    encode_binary(&event)
}

#[cfg(test)]
mod tests {
    use super::{
        dispatch_uart_packet, encode_log_notification, encode_log_packet, wrap_stream_frame,
    };
    use crate::commands::CommandRegistry;

    #[test]
    fn stream_frame_uses_u32_network_length() {
        let frame = wrap_stream_frame(&[1, 2, 3]);
        assert_eq!(&frame[..4], &(7_u32).to_be_bytes());
        assert_eq!(&frame[4..8], &[0, 0xcb, 0, 0]);
        assert_eq!(&frame[8..], &[1, 2, 3]);
    }

    #[test]
    fn malformed_uart_record_still_gets_a_stream_frame() {
        let mut registry = CommandRegistry::new();
        let frame = dispatch_uart_packet(&mut registry, &[0x01]);
        assert_eq!(&frame[4..8], &[0, 0xcb, 0, 0]);
    }

    #[test]
    fn radio_log_notification_is_cbor_without_uart_metadata() {
        let packet = encode_log_packet("event type=test");
        let framed = encode_log_notification("event type=test");
        assert_ne!(packet.get(..4), Some(&[0, 0xcb, 0, 0][..]));
        assert_eq!(&framed[4..8], &[0, 0xcb, 0, 0]);
        assert_eq!(&framed[8..], packet.as_slice());
    }
}
