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

/// Dispatch one compact-CBOR UART packet. UART's HDLC/PPP codec is below this
/// layer; lmesh adds the generic mesh stream envelope on the UDS side.
/// UART always returns a complete stream record, including malformed input
/// errors.
pub fn dispatch_uart_packet(registry: &mut CommandRegistry, packet: &[u8]) -> Vec<u8> {
    wrap_stream_frame(&dispatch_binary_packet(registry, packet))
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
