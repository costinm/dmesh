// IMPORTANT: This is the shared no-std ESP firmware layer. If code can be
// host-tested or reused without ESP/FreeRTOS ownership, it belongs in
// `quic-lite` (transport mechanics) or `dmesh-server` (service behavior),
// not here.

//! ESP-IDF hardware crypto adapters shared by Main and Recovery.

/// ESP-IDF's mbedTLS alternate uses the ESP SHA hardware. Object admission,
/// record framing, and verification policy remain host-testable in
/// `dmesh-server`; this is only the target-specific hash implementation.
pub fn sha256_native(bytes: &[u8]) -> Option<[u8; 32]> {
    let mut digest = [0u8; 32];
    let result =
        unsafe { esp_idf_sys::mbedtls_sha256(bytes.as_ptr(), bytes.len(), digest.as_mut_ptr(), 0) };
    (result == 0).then_some(digest)
}
