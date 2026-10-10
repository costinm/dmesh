//! Flashing through the `esp_wifi_loader` C component (library mode), next to the older
//! object-transfer path, which is left in place for now.
//!
//! The component owns the protocol (docs/protocol.md in the esp-wifi-loader repository):
//! signed header, key pin, rollback check, per-block hashes, and the writes. Main only
//! accepts TCP connections on whatever network it is on and hands each socket over. It can
//! install a signed loader or Stage2 image; a zero-length Main manifest makes the component
//! reboot the device into the loader (for a Main upgrade), from inside the call.

use std::net::TcpListener;
use std::os::fd::IntoRawFd;
use std::time::Duration;

extern "C" {
    fn esp_wifi_loader_init() -> i32;
    fn esp_wifi_loader_serve(fd: i32) -> i32;
}

/// Same port as the loader's upload port and announce group.
pub const PORT: u16 = 5227;

fn say(msg: &'static [u8]) {
    // Callers pass NUL-terminated literals.
    unsafe { esp_idf_sys::esp_rom_printf(msg.as_ptr().cast()) };
}

fn serve_forever() {
    if unsafe { esp_wifi_loader_init() } != 0 {
        say(b"DMESH main: loader flash unavailable\n\0");
        return;
    }
    // The network may not exist yet; the socket does not need it.
    let listener = loop {
        match TcpListener::bind(("::", PORT)) {
            Ok(l) => break l,
            Err(_) => std::thread::sleep(Duration::from_secs(2)),
        }
    };
    say(b"DMESH main: loader flash listening on 5227\n\0");
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
        let fd = stream.into_raw_fd();
        // A finished install in the loader build restarts the chip; here it returns.
        unsafe {
            esp_wifi_loader_serve(fd);
            esp_idf_sys::close(fd);
        }
    }
}

/// Start the listener thread. The upload buffers are static in the component; the stack
/// carries the signature check and the flash driver calls.
pub fn start() {
    let _ = std::thread::Builder::new()
        .name("loader-flash".into())
        .stack_size(12 * 1024)
        .spawn(serve_forever);
}
