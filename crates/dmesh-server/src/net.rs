//! No-std address parsing shared by host and firmware bearer adapters.

/// Parse a dotted IPv4 address into the in-memory network-byte layout used by
/// lwIP address fields. Socket ownership remains outside `dmesh-server`.
pub fn parse_ipv4(bytes: &[u8]) -> Option<u32> {
    let mut octets = [0u8; 4];
    let mut part = 0usize;
    let mut number = 0u16;
    let mut digits = 0usize;
    for byte in bytes.iter().copied().chain(core::iter::once(b'.')) {
        if byte == b'.' {
            if digits == 0 || part >= octets.len() || number > u16::from(u8::MAX) {
                return None;
            }
            octets[part] = number as u8;
            part += 1;
            number = 0;
            digits = 0;
        } else if byte.is_ascii_digit() && digits < 3 {
            number = number
                .checked_mul(10)?
                .checked_add(u16::from(byte - b'0'))?;
            digits += 1;
        } else {
            return None;
        }
    }
    (part == 4).then(|| u32::from_ne_bytes(octets))
}

#[cfg(test)]
mod tests {
    use super::parse_ipv4;

    #[test]
    fn parses_only_complete_dotted_quad() {
        assert_eq!(
            parse_ipv4(b"10.78.0.1").map(u32::to_ne_bytes),
            Some([10, 78, 0, 1])
        );
        assert_eq!(parse_ipv4(b"10.78.0"), None);
        assert_eq!(parse_ipv4(b"10.78..1"), None);
        assert_eq!(parse_ipv4(b"10.78.0.256"), None);
    }
}
