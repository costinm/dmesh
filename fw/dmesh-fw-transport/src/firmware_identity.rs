//! Running-image identity exposed through the common tagged stream service.

use alloc::vec::Vec;

fn elf_sha256_hex() -> Option<[u8; 64]> {
    let description = unsafe { esp_idf_sys::esp_app_get_description().as_ref()? };
    let mut output = [0u8; 64];
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (index, byte) in description.app_elf_sha256.iter().copied().enumerate() {
        output[index * 2] = HEX[usize::from(byte >> 4)];
        output[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    }
    Some(output)
}

pub(crate) fn receive_tagged_identity(record: dmesh_server::tagged::Record<'_>) -> Option<Vec<u8>> {
    let identity = elf_sha256_hex()?;
    dmesh_server::services::encode_firmware_identity_response(record, &identity)
}
