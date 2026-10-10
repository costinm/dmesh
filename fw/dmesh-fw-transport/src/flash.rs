//! Flash destinations for the esp-wifi-loader protocol (docs/protocol.md in that repository), which Main
//! serves with the `esp-wifi-loader` crate (`fw/main/src/loader_flash.rs`). This module owns only the
//! durable partition writes: target 2 is the loader partition without its trailing 8 KiB state log,
//! target 3 the Stage2 region, target 4 a module slot in the `data` partition.

const STAGE2_REGION_BYTES: usize = 0x7000;
/// The write unit and erase granularity of the sink.
const BLOCK_SIZE: usize = 4096;
/// All region-erase drivers in the configured ESP-IDF support 64 KiB blocks.
/// Whole-chip erase must never be used for an image/partition update.
const ERASE_BLOCK_BYTES: usize = 64 * 1024;
/// The state log at the end of the loader partition belongs to Stage2 and the loader.
const STATE_LOG_BYTES: usize = 8192;

/// Module slots in the `data` partition: name, offset, size. The position is the slot number the state log
/// keeps the module's minimum version under.
const MODULE_SLOTS: [(&[u8], usize, usize); 4] = [
    (b"lora", 0x00000, 0x20000),
    (b"flash", 0x10000, 0x10000),
    (b"hw", 0x20000, 0x10000),
    (b"hello", 0x30000, 0x10000),
];

/// The slot number of a module name.
pub fn module_slot(name: &[u8]) -> Option<u8> {
    MODULE_SLOTS.iter().position(|(n, ..)| *n == name).map(|i| i as u8)
}

pub const fn local_cpu() -> u8 {
    #[cfg(target_arch = "riscv32")]
    {
        13
    }
    #[cfg(all(not(target_arch = "riscv32"), target_feature = "esp32s3ops"))]
    {
        9
    }
    #[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
    {
        0
    }
}

/// Synchronous ESP-IDF partition (or raw flash region) sink: erases 64 KiB blocks on demand and writes one
/// block at a time, so a write is durable before the next block is accepted.
pub struct EspPartitionSink {
    partition: *const esp_idf_sys::esp_partition_t,
    address: usize,
    capacity: usize,
    dry_run: bool,
    planned: usize,
    erased: usize,
}

/// Open the destination for a package target (2 loader, 3 Stage2, 4 module by name).
pub fn open_loader_sink(target: u8, name: &[u8], dry_run: bool) -> Result<EspPartitionSink, ()> {
    match target {
        2 => {
            let app = esp_idf_sys::esp_partition_type_t_ESP_PARTITION_TYPE_APP;
            // The loader table names the factory app `loader`; older tables `recovery_app`.
            let mut sink = [b"loader\0".as_slice(), b"recovery_app\0", b"recovery\0"]
                .into_iter()
                .find_map(|label| EspPartitionSink::new_partition(app, label, 0, None, dry_run).ok())
                .ok_or(())?;
            sink.capacity = sink.capacity.checked_sub(STATE_LOG_BYTES).ok_or(())?;
            Ok(sink)
        }
        3 => {
            // The classic ESP32's bootloader starts at 0x1000, the others' at 0.
            let boot = if local_cpu() == 0 { 0x1000 } else { 0 };
            EspPartitionSink::new_raw(boot, STAGE2_REGION_BYTES - boot, dry_run)
        }
        4 => {
            let (_, offset, size) = *MODULE_SLOTS.iter().find(|(n, ..)| *n == name).ok_or(())?;
            let data = esp_idf_sys::esp_partition_type_t_ESP_PARTITION_TYPE_DATA;
            EspPartitionSink::new_partition(data, b"data\0", offset, Some(size), dry_run)
        }
        _ => Err(()),
    }
}

/// Plan one sector-aligned erase without crossing a hardware block boundary. A leading partial block
/// aligns the following calls for large-block erase; a final partial block never erases beyond the extent.
fn next_erase_chunk_len(address: usize, remaining: usize) -> Option<usize> {
    if address % BLOCK_SIZE != 0 || remaining % BLOCK_SIZE != 0 {
        return None;
    }
    address.checked_add(remaining)?;
    Some(remaining.min(ERASE_BLOCK_BYTES - address % ERASE_BLOCK_BYTES))
}

impl EspPartitionSink {
    /// Bytes this destination can take.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    fn new_partition(
        kind: esp_idf_sys::esp_partition_type_t,
        label: &[u8],
        offset: usize,
        capacity: Option<usize>,
        dry_run: bool,
    ) -> Result<Self, ()> {
        if label.last() != Some(&0) {
            return Err(());
        }
        let partition = unsafe {
            esp_idf_sys::esp_partition_find_first(
                kind,
                esp_idf_sys::esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_ANY,
                label.as_ptr().cast(),
            )
        };
        if partition.is_null() {
            return Err(());
        }
        let partition_size = unsafe { (*partition).size as usize };
        let capacity = capacity.unwrap_or_else(|| partition_size.saturating_sub(offset));
        if capacity == 0 || offset.checked_add(capacity).is_none_or(|end| end > partition_size) {
            return Err(());
        }
        Ok(Self { partition, address: offset, capacity, dry_run, planned: 0, erased: 0 })
    }

    fn new_raw(address: usize, capacity: usize, dry_run: bool) -> Result<Self, ()> {
        if capacity == 0
            || address % BLOCK_SIZE != 0
            || address.checked_add(capacity).is_none_or(|end| end > STAGE2_REGION_BYTES)
        {
            return Err(());
        }
        Ok(Self { partition: core::ptr::null(), address, capacity, dry_run, planned: 0, erased: 0 })
    }

    fn erase_next(&mut self, count: usize) -> Result<(), ()> {
        let offset = self.address.checked_add(self.erased).ok_or(())?;
        let result = unsafe {
            if self.partition.is_null() {
                esp_idf_sys::esp_flash_erase_region(core::ptr::null_mut(), offset as u32, count as u32)
            } else {
                esp_idf_sys::esp_partition_erase_range(self.partition, offset, count)
            }
        };
        if result != esp_idf_sys::ESP_OK {
            return Err(());
        }
        self.erased = self.erased.checked_add(count).ok_or(())?;
        Ok(())
    }

    /// Reserve the extent of an image of `len` bytes (erasing happens block by block on write).
    pub fn begin(&mut self, len: u32) -> Result<(), ()> {
        let image_len = len as usize;
        let erase_len = image_len.checked_add(BLOCK_SIZE - 1).ok_or(())? / BLOCK_SIZE * BLOCK_SIZE;
        if image_len == 0 || erase_len > self.capacity {
            return Err(());
        }
        if !self.dry_run {
            self.planned = erase_len;
            self.erased = 0;
        }
        Ok(())
    }

    pub fn write_block(&mut self, index: u32, bytes: &[u8]) -> Result<(), ()> {
        if self.dry_run {
            return Ok(());
        }
        let relative = (index as usize).checked_mul(BLOCK_SIZE).ok_or(())?;
        let end = relative.checked_add(bytes.len()).ok_or(())?;
        if end > self.planned {
            return Err(());
        }
        while self.erased < end {
            let base = if self.partition.is_null() { 0 } else { unsafe { (*self.partition).address as usize } };
            let address = base.checked_add(self.address).and_then(|b| b.checked_add(self.erased)).ok_or(())?;
            let count = next_erase_chunk_len(address, self.planned - self.erased).ok_or(())?;
            self.erase_next(count)?;
        }
        let offset = self.address.checked_add(relative).ok_or(())?;
        let result = unsafe {
            if self.partition.is_null() {
                esp_idf_sys::esp_flash_write(core::ptr::null_mut(), bytes.as_ptr().cast(), offset as u32, bytes.len() as u32)
            } else {
                esp_idf_sys::esp_partition_write(self.partition, offset, bytes.as_ptr().cast(), bytes.len())
            }
        };
        (result == esp_idf_sys::ESP_OK).then_some(()).ok_or(())
    }

    pub fn finish(&mut self) -> Result<(), ()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erases_cover_only_the_requested_extent() {
        for base in [0, 4096, 60 * 1024, 64 * 1024] {
            for length in [0, 4096, 64 * 1024, 68 * 1024, 460 * 4096] {
                let mut erased = 0;
                while erased < length {
                    let n = next_erase_chunk_len(base + erased, length - erased).unwrap();
                    assert!(n > 0 && n <= ERASE_BLOCK_BYTES && n % BLOCK_SIZE == 0);
                    erased += n;
                }
                assert_eq!(erased, length);
            }
        }
        assert!(next_erase_chunk_len(100, 4096).is_none());
    }

    #[test]
    fn module_slots_have_stable_numbers() {
        assert_eq!(module_slot(b"lora"), Some(0));
        assert_eq!(module_slot(b"hello"), Some(3));
        assert_eq!(module_slot(b"nosuch"), None);
    }
}
