//! IPv6 address helpers shared by the ESP transport adapters.

/// Convert a Wi-Fi MAC into its RFC 4291 modified-EUI-64 link-local address.
pub const fn link_local_from_mac(mac: [u8; 6]) -> [u8; 16] {
    [
        0xfe,
        0x80,
        0,
        0,
        0,
        0,
        0,
        0,
        mac[0] ^ 0x02,
        mac[1],
        mac[2],
        0xff,
        0xfe,
        mac[3],
        mac[4],
        mac[5],
    ]
}

#[cfg(test)]
mod tests {
    use super::link_local_from_mac;

    #[test]
    fn link_local_uses_modified_eui64() {
        assert_eq!(
            link_local_from_mac([0x02, 0, 0, 0, 0, 1]),
            [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xfe, 0, 0, 1],
        );
    }
}
