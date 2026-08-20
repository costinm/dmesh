//! Bearer-neutral direct-command dispatch.
//!
//! A complete raw record may arrive through UART PPP, raw UDP6, or an action
//! bearer. This module decodes it once and invokes a registered handler; it
//! deliberately owns no socket, radio, response queue, or persistent profile.

use crate::recovery::{decode_recovery_command, RecoveryCommand};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawDispatchError {
    Decode,
    Rejected,
}

/// Decode a schema-defined raw Recovery command and deliver it to the caller
/// registered for this device role. The handler is where a firmware profile,
/// NVS write, or Main-only power policy may be applied; the wire parser stays
/// identical on host, Recovery, and Main.
pub fn dispatch_recovery_command<'a, F>(
    packet: &'a [u8],
    handler: F,
) -> Result<(), RawDispatchError>
where
    F: FnOnce(RecoveryCommand<'a>) -> Result<(), RawDispatchError>,
{
    handler(decode_recovery_command(packet).ok_or(RawDispatchError::Decode)?)
}

#[cfg(test)]
mod tests {
    use super::{RawDispatchError, dispatch_recovery_command};

    #[test]
    fn decoded_command_is_delivered_without_a_bearer_dependency() {
        let packet = [0xa2, 0x00, 0x18, 0x44, 0x06, 0xa0];
        let mut called = false;
        assert_eq!(
            dispatch_recovery_command(&packet, |_| {
                called = true;
                Ok(())
            }),
            Ok(())
        );
        assert!(called);
        assert_eq!(
            dispatch_recovery_command(&[0xff], |_| Ok(())),
            Err(RawDispatchError::Decode)
        );
    }
}
