// IMPORTANT: This is the shared no-std ESP firmware layer. If code can be
// host-tested or reused without ESP/FreeRTOS ownership, it belongs in
// `quic-lite` (transport mechanics) or `dmesh-server` (service behavior),
// not here.

//! ESP-IDF hardware crypto adapters shared by Main and Recovery.

use core::ffi::c_void;

/// A compressed SEC1 P-256 public key.
pub const P256_PUBLIC_KEY_LEN: usize = 33;
/// Raw P-256 private scalar stored only in binary NVS.
pub const P256_PRIVATE_KEY_LEN: usize = 32;
/// Fixed-width P1363 ECDSA signature (`r || s`).
pub const P256_SIGNATURE_LEN: usize = 64;

/// ESP-IDF's mbedTLS alternate uses the ESP SHA hardware. Object admission,
/// record framing, and verification policy remain host-testable in
/// `dmesh-server`; this is only the target-specific hash implementation.
pub fn sha256_native(bytes: &[u8]) -> Option<[u8; 32]> {
    let mut digest = [0u8; 32];
    let result =
        unsafe { esp_idf_sys::mbedtls_sha256(bytes.as_ptr(), bytes.len(), digest.as_mut_ptr(), 0) };
    (result == 0).then_some(digest)
}

/// Derive a compressed SEC1 public key with ESP-IDF's P-256 implementation.
/// The scalar never leaves the firmware identity adapter.
pub fn p256_public_key(private: &[u8; P256_PRIVATE_KEY_LEN]) -> Option<[u8; P256_PUBLIC_KEY_LEN]> {
    let mut group = core::mem::MaybeUninit::<esp_idf_sys::mbedtls_ecp_group>::zeroed();
    let mut scalar = core::mem::MaybeUninit::<esp_idf_sys::mbedtls_mpi>::zeroed();
    let mut point = core::mem::MaybeUninit::<esp_idf_sys::mbedtls_ecp_point>::zeroed();
    unsafe {
        let group = group.as_mut_ptr();
        let scalar = scalar.as_mut_ptr();
        let point = point.as_mut_ptr();
        esp_idf_sys::mbedtls_ecp_group_init(group);
        esp_idf_sys::mbedtls_mpi_init(scalar);
        esp_idf_sys::mbedtls_ecp_point_init(point);
        let result = (|| {
            (esp_idf_sys::mbedtls_ecp_group_load(
                group,
                esp_idf_sys::mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP256R1,
            ) == 0)
                .then_some(())?;
            (esp_idf_sys::mbedtls_mpi_read_binary(scalar, private.as_ptr(), private.len()) == 0)
                .then_some(())?;
            (esp_idf_sys::mbedtls_ecp_check_privkey(group, scalar) == 0).then_some(())?;
            (esp_idf_sys::mbedtls_ecp_mul(
                group,
                point,
                scalar,
                &(*group).G,
                Some(esp_rng),
                core::ptr::null_mut(),
            ) == 0)
                .then_some(())?;
            // Some ESP-IDF mbedTLS configurations omit the optional
            // compressed-point writer. The SEC1 compressed form is still
            // unambiguous for P-256: `0x02|0x03 || X`, selected by Y's low
            // bit. Keep this conversion here, beside the platform ECP call,
            // rather than adding an ESP-specific wire encoding.
            let mut public = [0u8; P256_PUBLIC_KEY_LEN];
            public[0] = if esp_idf_sys::mbedtls_mpi_get_bit(&(*point).Y, 0) == 0 {
                0x02
            } else {
                0x03
            };
            (esp_idf_sys::mbedtls_mpi_write_binary(
                &(*point).X,
                public[1..].as_mut_ptr(),
                P256_PRIVATE_KEY_LEN,
            ) == 0)
                .then_some(public)
        })();
        esp_idf_sys::mbedtls_ecp_point_free(point);
        esp_idf_sys::mbedtls_mpi_free(scalar);
        esp_idf_sys::mbedtls_ecp_group_free(group);
        result
    }
}

/// Generate a valid P-256 scalar using the ESP hardware RNG.
pub fn generate_p256_private() -> Option<[u8; P256_PRIVATE_KEY_LEN]> {
    for _ in 0..16 {
        let mut private = [0u8; P256_PRIVATE_KEY_LEN];
        unsafe { esp_idf_sys::esp_fill_random(private.as_mut_ptr().cast(), private.len()) };
        if p256_public_key(&private).is_some() {
            return Some(private);
        }
    }
    None
}

/// Sign canonical announce bytes with the ESP-IDF P-256 implementation.
/// mbedTLS receives SHA-256 bytes and returns `r` and `s`, which are encoded
/// directly as the common fixed-width P1363 wire signature.
pub fn p256_sign(
    private: &[u8; P256_PRIVATE_KEY_LEN],
    message: &[u8],
) -> Option<[u8; P256_SIGNATURE_LEN]> {
    let digest = sha256_native(message)?;
    let mut group = core::mem::MaybeUninit::<esp_idf_sys::mbedtls_ecp_group>::zeroed();
    let mut scalar = core::mem::MaybeUninit::<esp_idf_sys::mbedtls_mpi>::zeroed();
    let mut r = core::mem::MaybeUninit::<esp_idf_sys::mbedtls_mpi>::zeroed();
    let mut s = core::mem::MaybeUninit::<esp_idf_sys::mbedtls_mpi>::zeroed();
    unsafe {
        let group = group.as_mut_ptr();
        let scalar = scalar.as_mut_ptr();
        let r = r.as_mut_ptr();
        let s = s.as_mut_ptr();
        esp_idf_sys::mbedtls_ecp_group_init(group);
        esp_idf_sys::mbedtls_mpi_init(scalar);
        esp_idf_sys::mbedtls_mpi_init(r);
        esp_idf_sys::mbedtls_mpi_init(s);
        let result = (|| {
            (esp_idf_sys::mbedtls_ecp_group_load(
                group,
                esp_idf_sys::mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP256R1,
            ) == 0)
                .then_some(())?;
            (esp_idf_sys::mbedtls_mpi_read_binary(scalar, private.as_ptr(), private.len()) == 0)
                .then_some(())?;
            (esp_idf_sys::mbedtls_ecp_check_privkey(group, scalar) == 0).then_some(())?;
            (esp_idf_sys::mbedtls_ecdsa_sign(
                group,
                r,
                s,
                scalar,
                digest.as_ptr(),
                digest.len(),
                Some(esp_rng),
                core::ptr::null_mut(),
            ) == 0)
                .then_some(())?;
            let mut signature = [0u8; P256_SIGNATURE_LEN];
            (esp_idf_sys::mbedtls_mpi_write_binary(r, signature[..32].as_mut_ptr(), 32) == 0
                && esp_idf_sys::mbedtls_mpi_write_binary(s, signature[32..].as_mut_ptr(), 32) == 0)
                .then_some(signature)
        })();
        esp_idf_sys::mbedtls_mpi_free(s);
        esp_idf_sys::mbedtls_mpi_free(r);
        esp_idf_sys::mbedtls_mpi_free(scalar);
        esp_idf_sys::mbedtls_ecp_group_free(group);
        result
    }
}

unsafe extern "C" fn esp_rng(_: *mut c_void, output: *mut u8, len: usize) -> i32 {
    if output.is_null() {
        return -1;
    }
    unsafe { esp_idf_sys::esp_fill_random(output.cast(), len) };
    0
}
