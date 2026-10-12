//! Installing loader, Stage2 and module images over TCP with the esp-wifi-loader protocol. The `esp-wifi-loader` crate (the loader repository, docs/protocol.md)
//! does the protocol: signature, pinned key, versions, block hashes, head-block-last commit, the state
//! log shared with the loader. This file only supplies the pieces that belong to this firmware: the
//! flash destinations (`dmesh_fw_transport::flash`), the state sectors, and the accept loop.
//!
//! A signed zero-length Main package asks Main to restart into the loader, which can then replace Main.
//! There is no unsigned restart request and no trust on first use here (see `require_pinned_key`).

use std::io;
use std::net::TcpStream;
use std::os::fd::FromRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use esp_wifi_loader::device::{Device, Outcome, Platform, Sink};
use esp_wifi_loader::state::{FlashOps, SECTOR, SIZE};
use esp_wifi_loader::wire::{self, target, Reject};

struct FlashSink(dmesh_fw_transport::flash::EspPartitionSink);
static UPLOAD_ACTIVE: AtomicBool = AtomicBool::new(false);

impl Sink for FlashSink {
    fn begin(&mut self, len: u32) -> Result<(), ()> {
        self.0.begin(len)
    }
    fn write_block(&mut self, index: u32, bytes: &[u8]) -> Result<(), ()> {
        self.0.write_block(index, bytes)
    }
    fn finish(&mut self) -> Result<(), ()> {
        self.0.finish()
    }
}

struct Main;

impl Platform for Main {
    type Sink = FlashSink;

    fn cpu(&self) -> u8 {
        dmesh_fw_transport::flash::local_cpu()
    }

    fn open(&mut self, tgt: u8, name: &[u8], image_size: u32, dry: bool) -> Result<FlashSink, Reject> {
        if !matches!(tgt, target::LOADER | target::STAGE2 | target::MODULE) {
            return Err(wire::WRONG_TARGET);
        }
        // The slot's code may be executing: it has to have returned before the first block is erased.
        #[cfg(feature = "modules")]
        if tgt == target::MODULE && !dry {
            let stopped = dmesh_fw_transport::flash::module_slot(name).map_or(true, crate::modules::stop_slot);
            if !stopped {
                return Err(wire::FLASH);
            }
        }
        let sink = dmesh_fw_transport::flash::open_loader_sink(tgt, name, dry).map_err(|_| wire::WRONG_TARGET)?;
        if image_size as usize > sink.capacity() {
            return Err(wire::BAD_LENGTH);
        }
        Ok(FlashSink(sink))
    }

    /// The loader key in the Stage2 region (fixed offset, same on every chip): the only key that may sign the loader and Stage2.
    fn trusted_key(&self) -> Option<[u8; wire::PUBKEY_SIZE]> {
        let mut slot = [0u8; wire::TRUST_SIZE];
        let ok = unsafe {
            esp_idf_sys::esp_flash_read(core::ptr::null_mut(), slot.as_mut_ptr().cast(), wire::TRUST_OFFSET, slot.len() as u32)
        } == esp_idf_sys::ESP_OK;
        ok.then(|| wire::parse_trust_slot(&slot)).flatten()
    }

    /// The module slots of the `data` partition (names and locations: dmesh_fw_transport::flash).
    fn module_slot(&self, name: &[u8]) -> Option<u8> {
        dmesh_fw_transport::flash::module_slot(name)
    }
}

/// The last 8 KiB of the loader partition: the state log shared with Stage2 and the loader.
struct StateSectors {
    partition: *const esp_idf_sys::esp_partition_t,
    base: usize,
}

// The partition table entry lives for the whole run.
unsafe impl Send for StateSectors {}

impl StateSectors {
    fn open() -> Option<Self> {
        let partition = unsafe {
            esp_idf_sys::esp_partition_find_first(
                esp_idf_sys::esp_partition_type_t_ESP_PARTITION_TYPE_APP,
                esp_idf_sys::esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_APP_FACTORY,
                core::ptr::null(),
            )
        };
        if partition.is_null() {
            return None;
        }
        let size = unsafe { (*partition).size } as usize;
        Some(StateSectors { partition, base: size.checked_sub(SIZE as usize)? })
    }
}

impl FlashOps for StateSectors {
    fn read(&mut self, off: u32, buf: &mut [u8]) -> bool {
        unsafe { esp_idf_sys::esp_partition_read(self.partition, self.base + off as usize, buf.as_mut_ptr().cast(), buf.len()) == esp_idf_sys::ESP_OK }
    }
    fn write(&mut self, off: u32, data: &[u8]) -> bool {
        unsafe { esp_idf_sys::esp_partition_write(self.partition, self.base + off as usize, data.as_ptr().cast(), data.len()) == esp_idf_sys::ESP_OK }
    }
    fn erase(&mut self, sector_off: u32) -> bool {
        unsafe { esp_idf_sys::esp_partition_erase_range(self.partition, self.base + sector_off as usize, SECTOR as usize) == esp_idf_sys::ESP_OK }
    }
}

fn say(msg: &'static [u8]) {
    // Callers pass NUL-terminated literals.
    unsafe { esp_idf_sys::esp_rom_printf(msg.as_ptr().cast()) };
}

fn serve_connection(mut stream: TcpStream) {
    // Some lwIP configurations copy the listener's nonblocking flag to the
    // accepted socket. The upload protocol currently uses synchronous I/O.
    if stream.set_nonblocking(false).is_err() {
        return;
    }
    let Some(state) = StateSectors::open() else {
        say(b"DMESH main: loader flash unavailable (no loader partition)\n\0");
        return;
    };
    // No trust on first use on this network: the Stage2 trust slot, or a key the loader already pinned,
    // must exist, otherwise every upload is refused.
    let mut device = Device::new(Main, state).require_pinned_key();
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let outcome = device.serve(&mut stream);
    // Let the reply drain before the connection (or the chip) goes away.
    let _ = io::Write::flush(&mut stream);
    let _ = stream.shutdown(std::net::Shutdown::Write);
    std::thread::sleep(Duration::from_millis(200));
    if let Outcome::RequestLoader = outcome {
        dmesh_fw_transport::rtc::arm_recovery();
        unsafe { esp_idf_sys::esp_restart() };
    }
}

/// The shared lwIP transport calls this only when a connection is accepted.
/// The loader protocol owns the stream, while the listener remains available.
fn accept_upload(fd: i32) {
    if UPLOAD_ACTIVE.swap(true, Ordering::AcqRel) {
        unsafe { esp_idf_sys::lwip_close(fd) };
        return;
    }
    let stream = unsafe { TcpStream::from_raw_fd(fd) };
    if std::thread::Builder::new()
        .name("loader-upload".into())
        .stack_size(24 * 1024)
        .spawn(move || {
            serve_connection(stream);
            UPLOAD_ACTIVE.store(false, Ordering::Release);
        })
        .is_err()
    {
        UPLOAD_ACTIVE.store(false, Ordering::Release);
        say(b"DMESH main: loader upload thread unavailable\n\0");
    }
}

/// Register the loader wire protocol as a TCP stream handler. Socket readiness
/// and accepting belong to the shared lwIP transport task.
pub fn start() {
    if StateSectors::open().is_none() {
        say(b"DMESH main: loader flash unavailable (no loader partition)\n\0");
    } else if dmesh_fw_transport::lwip_io_esp::listen_tcp(wire::PORT, 1, accept_upload).is_none() {
        say(b"DMESH main: loader flash listener unavailable\n\0");
    }
}
