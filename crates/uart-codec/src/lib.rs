#![no_std]

//! Runtime-neutral UART framing shared by host forwarding and ESP32 firmware.

extern crate alloc;

/// Low-level codec API. It is public only so the Wi-Fi backend can reuse the
/// implementation; it is not part of the service command API.
#[doc(hidden)]
pub mod codec;
