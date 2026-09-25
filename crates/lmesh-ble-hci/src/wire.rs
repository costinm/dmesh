//! Compact BLE discovery record.
//!
//! Legacy advertising has 31 bytes total, so it carries the complete virtual
//! IPv6 identity but not a public key or signature. A subsequent CoC-directed
//! discovery exchange returns the ordinary signed DMesh identity.

use anyhow::{Result, bail};

pub const DMESH_BLE_SERVICE_UUID16: u16 = 0x1820;
const VERSION: u8 = 1;
const FLAG_CONFIGURED: u8 = 1;
const VALUE_LEN: usize = 18;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Advertisement {
    pub vip6: [u8; 16],
    pub configured: bool,
}

impl Advertisement {
    pub const fn new(vip6: [u8; 16]) -> Self {
        Self {
            configured: !mesh_id_is_zero(&vip6),
            vip6,
        }
    }

    /// Value passed to Android's `addServiceData(0x1820, value)`.
    pub fn encode_value(self) -> [u8; VALUE_LEN] {
        let mut value = [0u8; VALUE_LEN];
        value[0] = VERSION;
        value[1] = if self.configured { FLAG_CONFIGURED } else { 0 };
        value[2..].copy_from_slice(&self.vip6);
        value
    }

    pub fn decode_value(value: &[u8]) -> Result<Self> {
        if value.len() != VALUE_LEN || value[0] != VERSION {
            bail!("unsupported DMesh BLE discovery value");
        }
        let mut vip6 = [0u8; 16];
        vip6.copy_from_slice(&value[2..]);
        Ok(Self {
            vip6,
            configured: value[1] & FLAG_CONFIGURED != 0,
        })
    }

    /// Complete legacy AD structure used by raw HCI. Its 22 bytes leave room
    /// for the standard flags and 16-bit service UUID list under the 31-byte
    /// legacy advertising limit.
    pub fn encode_service_data_ad(self) -> [u8; 22] {
        let mut ad = [0u8; 22];
        ad[0] = 21; // type + UUID + value
        ad[1] = 0x16; // Service Data - 16-bit UUID
        ad[2..4].copy_from_slice(&DMESH_BLE_SERVICE_UUID16.to_le_bytes());
        ad[4..].copy_from_slice(&self.encode_value());
        ad
    }
}

/// Treat the fixed ULA prefix byte separately from the 40-bit owner/mesh ID.
/// DMesh derives those five bytes from the owner root CA. An all-zero mesh ID
/// means the device is not provisioned yet; the ULA prefix and subnet do not
/// establish ownership.
const fn mesh_id_is_zero(vip6: &[u8; 16]) -> bool {
    let mut index = 1;
    while index < 6 {
        if vip6[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_vip6_fits_legacy_service_data() {
        let mut vip6 = [0u8; 16];
        vip6[0] = 0xfc;
        vip6[8..].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let advertisement = Advertisement::new(vip6);
        assert!(!advertisement.configured);
        assert_eq!(
            Advertisement::decode_value(&advertisement.encode_value()).unwrap(),
            advertisement
        );
        assert_eq!(advertisement.encode_service_data_ad().len(), 22);
    }

    #[test]
    fn nonzero_owner_mesh_prefix_marks_configured_device() {
        let mut vip6 = [0u8; 16];
        vip6[0] = 0xfc;
        vip6[1] = 7;
        assert!(Advertisement::new(vip6).configured);
    }
}
