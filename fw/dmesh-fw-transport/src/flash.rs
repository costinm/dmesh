//! Firmware-update application state during the `QuicNode` cutover.
//!
//! The former implementation reached through dmesh-server into a private
//! packet dispatcher. Flashing will be reattached as an ordinary tagged
//! stream handler; radio adapters must not own transfer or QUIC state.

struct EspFlashAdapter;

impl dmesh_server::verified_object::FlashPlatform for EspFlashAdapter {
    fn start(
        &mut self,
        _request: dmesh_server::verified_object::FlashRequest<'_>,
    ) -> Result<(), dmesh_server::verified_object::FlashStartError> {
        // Partition writing is intentionally unavailable until the new node
        // can open the signed-object download stream. Do not revive the old
        // packet dispatcher merely to start a transfer.
        Err(dmesh_server::verified_object::FlashStartError::Unsupported)
    }
}

/// ESP binding for the common dmesh-server flash handler.
pub fn receive_tagged_flash(
    record: dmesh_server::tagged::Record<'_>,
) -> Option<alloc::vec::Vec<u8>> {
    dmesh_server::verified_object::handle_flash_record(record, &mut EspFlashAdapter)
}

/// No transfer is active until the tagged flash handler is installed.
pub fn transfer_active() -> bool {
    false
}

/// Durable completion is produced by the future tagged flash handler.
pub fn take_durable_flash_completion() -> bool {
    false
}
