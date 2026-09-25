#![no_std]

//! Runtime-neutral UART framing shared by host forwarding and ESP32 firmware.

extern crate alloc;
#[cfg(feature = "host")]
extern crate std;

/// Low-level codec API. It is public only so the Wi-Fi backend can reuse the
/// implementation; it is not part of the service command API.
#[doc(hidden)]
pub mod codec;

/// Linux UART device and frame I/O. Firmware builds keep only the codec.
#[cfg(all(feature = "host", target_os = "linux"))]
pub mod host;
