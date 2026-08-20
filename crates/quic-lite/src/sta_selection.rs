//! Host-testable STA candidate policy shared by ESP firmware variants.
//!
//! This module deliberately does not perform a scan or call a Wi-Fi driver.
//! The ESP adapter supplies observed beacon/scan records; this policy decides
//! whether an association attempt is worthwhile.  A configured SSID is a
//! preference, not a command to attach to an unusable AP.

/// Minimal observation needed for association choice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaCandidate<'a> {
    pub ssid: &'a [u8],
    pub bssid: [u8; 6],
    pub rssi_dbm: i8,
    pub channel: u8,
}

/// A selected AP and its link-local server identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaSelection<'a> {
    pub candidate: StaCandidate<'a>,
    pub preferred: bool,
    pub server_link_local: [u8; 16],
}

/// True for the open DMesh AP naming family.  `lmesh-wifi` currently emits
/// names such as `Direct-CAB879CC-Dmesh-local`; discovery input is an
/// 802.11 SSID, so compare its ASCII branding case-insensitively and accept
/// the optional deployment suffix after `-dmesh`.
///
/// It intentionally accepts the variable identifier between the fixed
/// `DIRECT-` prefix and the `-dmesh` marker.
pub const fn is_dmesh_direct_ssid(ssid: &[u8]) -> bool {
    const PREFIX: &[u8] = b"DIRECT-";
    const MARKER: &[u8] = b"-dmesh";
    if ssid.len() <= PREFIX.len() + MARKER.len() || !starts_with_ascii_ignore_case(ssid, PREFIX) {
        return false;
    }
    let mut index = PREFIX.len();
    while index + MARKER.len() <= ssid.len() {
        if marker_at_ascii_ignore_case(ssid, index, MARKER) {
            return true;
        }
        index += 1;
    }
    false
}

/// Pick an eligible DMesh AP.  The preferred SSID wins only when it meets the
/// same RSSI floor as a fallback; otherwise the strongest eligible fallback
/// provides a fast, low-power recovery path.
pub fn select_sta_candidate<'a>(
    candidates: &'a [StaCandidate<'a>],
    preferred_ssid: &[u8],
    minimum_rssi_dbm: i8,
) -> Option<StaSelection<'a>> {
    let mut strongest = None;
    for candidate in candidates {
        if !is_dmesh_direct_ssid(candidate.ssid) || candidate.rssi_dbm < minimum_rssi_dbm {
            continue;
        }
        if candidate.ssid == preferred_ssid {
            return Some(StaSelection {
                candidate: *candidate,
                preferred: true,
                server_link_local: crate::raw_udp6::link_local_from_mac(candidate.bssid),
            });
        }
        if strongest.is_none_or(|current: StaCandidate<'a>| candidate.rssi_dbm > current.rssi_dbm) {
            strongest = Some(*candidate);
        }
    }
    strongest.map(|candidate| StaSelection {
        candidate,
        preferred: false,
        server_link_local: crate::raw_udp6::link_local_from_mac(candidate.bssid),
    })
}

const fn marker_at_ascii_ignore_case(value: &[u8], offset: usize, marker: &[u8]) -> bool {
    if offset + marker.len() > value.len() {
        return false;
    }
    let mut index = 0;
    while index < marker.len() {
        if ascii_lower(value[offset + index]) != ascii_lower(marker[index]) {
            return false;
        }
        index += 1;
    }
    true
}

const fn starts_with_ascii_ignore_case(value: &[u8], prefix: &[u8]) -> bool {
    if prefix.len() > value.len() {
        return false;
    }
    let mut index = 0;
    while index < prefix.len() {
        if ascii_lower(value[index]) != ascii_lower(prefix[index]) {
            return false;
        }
        index += 1;
    }
    true
}

const fn ascii_lower(value: u8) -> u8 {
    if value >= b'A' && value <= b'Z' {
        value + (b'a' - b'A')
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preferred_is_only_used_above_floor() {
        let candidates = [
            StaCandidate {
                ssid: b"DIRECT-weak-dmesh",
                bssid: [0, 1, 2, 3, 4, 5],
                rssi_dbm: -80,
                channel: 6,
            },
            StaCandidate {
                ssid: b"DIRECT-fast-dmesh",
                bssid: [0, 0xc0, 0xca, 0xb8, 0x79, 0xcc],
                rssi_dbm: -50,
                channel: 6,
            },
        ];
        let selected = select_sta_candidate(&candidates, b"DIRECT-weak-dmesh", -70).unwrap();
        assert!(!selected.preferred);
        assert_eq!(selected.candidate.ssid, b"DIRECT-fast-dmesh");
        assert_eq!(
            selected.server_link_local,
            [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 2, 0xc0, 0xca, 0xff, 0xfe, 0xb8, 0x79, 0xcc]
        );
    }

    #[test]
    fn preferred_wins_when_usable() {
        let candidates = [
            StaCandidate {
                ssid: b"DIRECT-other-dmesh",
                bssid: [1; 6],
                rssi_dbm: -30,
                channel: 6,
            },
            StaCandidate {
                ssid: b"DIRECT-preferred-dmesh",
                bssid: [2; 6],
                rssi_dbm: -60,
                channel: 6,
            },
        ];
        assert!(
            select_sta_candidate(&candidates, b"DIRECT-preferred-dmesh", -70)
                .unwrap()
                .preferred
        );
    }

    #[test]
    fn accepts_live_lmesh_wifi_direct_ssid_shape() {
        assert!(is_dmesh_direct_ssid(b"Direct-CAB879CC-Dmesh-local"));
        assert!(is_dmesh_direct_ssid(b"DIRECT-CAB879CC-dmesh"));
        assert!(!is_dmesh_direct_ssid(b"Direct-CAB879CC-local"));
    }
}
