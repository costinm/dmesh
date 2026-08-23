//! Small, portable Wi-Fi Direct discovery primitives.
//!
//! This is deliberately the *passive* half of P2P: a DMesh node advertises
//! capability by carrying a P2P vendor IE in its probe response.  It does not
//! send probe, GAS, Service Discovery, GO-negotiation, or WPS traffic on its
//! own. Those are controller-triggered Phase-2 operations.

/// IEEE 802.11 vendor-specific information element.
pub const VENDOR_IE: u8 = 221;
/// Wi-Fi Alliance OUI and Wi-Fi Direct OUI type.
pub const P2P_OUI_TYPE: [u8; 4] = [0x50, 0x6f, 0x9a, 0x09];
/// Public action category and Wi-Fi Direct public-action code.
pub const PUBLIC_ACTION_CATEGORY: u8 = 0x04;
pub const P2P_PUBLIC_ACTION: u8 = 0x09;
/// P2P Capability attribute id.  Its two bytes advertise group/client roles;
/// DMesh uses zero until the controller starts GO negotiation.
pub const ATTR_CAPABILITY: u8 = 0x02;
/// P2P Device ID and Listen Channel attribute identifiers.
pub const ATTR_DEVICE_ID: u8 = 0x03;
pub const ATTR_LISTEN_CHANNEL: u8 = 0x06;
/// P2P Device Info attribute identifier.
pub const ATTR_DEVICE_INFO: u8 = 0x0d;
/// Service Discovery device-capability bit.
pub const DEVICE_CAPABILITY_SERVICE_DISCOVERY: u8 = 1;
/// Generic 2.4 GHz operating class used for the channel-6-first discovery
/// profile. The active controller owns future use of channels 1 and 11.
pub const OPERATING_CLASS_2GHZ: u8 = 81;
/// IEEE public-action code for GAS Initial Request.
pub const GAS_INITIAL_REQUEST: u8 = 10;
/// IEEE public-action code for GAS Initial Response.
pub const GAS_INITIAL_RESPONSE: u8 = 11;
const ANQP_VENDOR_SPECIFIC: u16 = 0xdddd;
const P2P_SERVICE_PROTOCOL_BONJOUR: u8 = 1;
const P2P_SERVICE_SUCCESS: u8 = 0;
const DNS_SD_TXT_TYPE: [u8; 3] = [0, 16, 1];

/// Passive host/ESP P2P SD advertisement. It proves that the peer can take
/// part in DMesh P2P discovery, but intentionally carries no transport
/// configuration or credential. The Android Group Owner publishes the
/// actionable STA SSID/passphrase after a group is formed.
pub const DMESH_SERVICE_PRESENCE_PREFIX: &[u8] = b"dmesh=";

/// Encode the host/ESP P2P SD TXT marker with a stable local identifier.
/// MAC addresses are used at this discovery layer because they are already
/// the P2P device address; signed long-term identities remain control-plane
/// work. The output is `dmesh=<12 lower-case hex digits>` for a six-byte MAC.
pub fn encode_dmesh_service_presence_txt(
    out: &mut [u8],
    device_id: &[u8],
) -> Result<usize, P2pError> {
    let required = DMESH_SERVICE_PRESENCE_PREFIX.len() + device_id.len() * 2;
    let dst = out.get_mut(..required).ok_or(P2pError::OutputTooSmall)?;
    dst[..DMESH_SERVICE_PRESENCE_PREFIX.len()].copy_from_slice(DMESH_SERVICE_PRESENCE_PREFIX);
    for (index, byte) in device_id.iter().enumerate() {
        let at = DMESH_SERVICE_PRESENCE_PREFIX.len() + index * 2;
        dst[at] = b"0123456789abcdef"[(byte >> 4) as usize];
        dst[at + 1] = b"0123456789abcdef"[(byte & 0x0f) as usize];
    }
    Ok(required)
}

/// P2P Service Discovery query for DNS-SD instance `dmesh`, type
/// `_dmesh._tcp`, and TXT records. It is shared by active host/ESP
/// controllers and by the ESP passive responder's bounded reconstruction of
/// Android's request; it is not adapter-specific wire data.
pub const DMESH_DNS_SD_QUERY: [u8; 32] = [
    0xdd, 0xdd, 0x1c, 0, 0x50, 0x6f, 0x9a, 0x09, 5, 0, 0x14, 0, 1, 2, 5, b'd', b'm', b'e', b's',
    b'h', 6, b'_', b'd', b'm', b'e', b's', b'h', 0xc0, 0x0c, 0, 0x10, 1,
];

/// Return the dialog token from a complete P2P Service Discovery GAS Initial
/// Request. The outer 802.11 management header is deliberately left to the
/// radio owner; this only validates the public-action prefix.
pub fn gas_initial_request_dialog_token(frame: &[u8]) -> Option<u8> {
    let body = frame.get(crate::FRAME_DATA..)?;
    (body.first().copied() == Some(4) && body.get(1).copied() == Some(GAS_INITIAL_REQUEST))
        .then(|| body.get(2).copied())
        .flatten()
}

/// Encode the common GAS Initial Request body for the DMesh DNS-SD service.
/// Adapters prepend the 802.11 management header and own TX timing/channel.
pub fn encode_dmesh_dns_sd_gas_initial_request(
    out: &mut [u8],
    dialog_token: u8,
) -> Result<usize, P2pError> {
    const ACTION_HEADER: usize = 9;
    let required = ACTION_HEADER + DMESH_DNS_SD_QUERY.len();
    let dst = out.get_mut(..required).ok_or(P2pError::OutputTooSmall)?;
    dst[..ACTION_HEADER].copy_from_slice(&[
        PUBLIC_ACTION_CATEGORY,
        GAS_INITIAL_REQUEST,
        dialog_token,
        108,
        2,
        0,
        0,
        0,
        0,
    ]);
    dst[7..9].copy_from_slice(&(DMESH_DNS_SD_QUERY.len() as u16).to_le_bytes());
    dst[ACTION_HEADER..].copy_from_slice(&DMESH_DNS_SD_QUERY);
    Ok(required)
}

/// Encode a standards-shaped successful GAS Initial Response with an empty
/// query-response payload.
///
/// This is useful for proving the P2P peer/SD request-response exchange
/// before a responder has registered a particular DNS-SD service. It must not
/// be reported as a DMesh service result: no ANQP vendor-specific or DNS-SD
/// TLV is included here.
pub fn encode_empty_gas_initial_response(
    out: &mut [u8],
    dialog_token: u8,
) -> Result<usize, P2pError> {
    // Public Action, GAS Initial Response, dialog token, success, no comeback
    // delay, Advertisement Protocol (ANQP), empty Query Response.
    const RESPONSE: [u8; 13] = [4, GAS_INITIAL_RESPONSE, 0, 0, 0, 0, 0, 108, 2, 0, 0, 0, 0];
    let dst = out
        .get_mut(..RESPONSE.len())
        .ok_or(P2pError::OutputTooSmall)?;
    dst.copy_from_slice(&RESPONSE);
    dst[2] = dialog_token;
    Ok(RESPONSE.len())
}

/// Encode a successful P2P DNS-SD/GAS response for the `dmesh._dmesh._tcp`
/// TXT query emitted by Android's `WifiP2pDnsSdServiceRequest`.
///
/// `txt` is one complete DNS-SD TXT item such as `dmesh=7419f817de65`. Host/ESP use the
/// small presence marker; Android, once it is Group Owner, publishes its
/// credential-bearing `cbor=<hex>` record through the platform DNS-SD API.
pub fn encode_dmesh_dns_sd_gas_initial_response(
    out: &mut [u8],
    request: &[u8],
    txt: &[u8],
) -> Result<usize, P2pError> {
    if txt.is_empty() || txt.len() > u8::MAX as usize {
        return Err(P2pError::Malformed);
    }
    let body = request
        .get(crate::FRAME_DATA..)
        .ok_or(P2pError::Malformed)?;
    if body.len() < 9
        || body[0] != PUBLIC_ACTION_CATEGORY
        || body[1] != GAS_INITIAL_REQUEST
        || body[3] != 108
        || body[4] != 2
        || body[5] != 0
        || body[6] != 0
    {
        return Err(P2pError::Malformed);
    }
    let query_len = usize::from(u16::from_le_bytes([body[7], body[8]]));
    let query = body.get(9..9 + query_len).ok_or(P2pError::Malformed)?;
    if query.len() < 10 || u16::from_le_bytes([query[0], query[1]]) != ANQP_VENDOR_SPECIFIC {
        return Err(P2pError::Malformed);
    }
    let vendor_len = usize::from(u16::from_le_bytes([query[2], query[3]]));
    let vendor = query.get(4..4 + vendor_len).ok_or(P2pError::Malformed)?;
    if vendor.len() < 8 || vendor[..4] != P2P_OUI_TYPE {
        return Err(P2pError::Malformed);
    }
    let service = vendor.get(6..).ok_or(P2pError::Malformed)?;
    if service.len() < 5 {
        return Err(P2pError::Malformed);
    }
    let service_len = usize::from(u16::from_le_bytes([service[0], service[1]]));
    let service = service.get(2..2 + service_len).ok_or(P2pError::Malformed)?;
    // A request TLV is `protocol, transaction, query`; the response adds a
    // status byte after the transaction. Do not consume a nonexistent status
    // byte here or the echoed DNS-SD query stops being byte-for-byte identical.
    if service.len() < 2 || service[0] != P2P_SERVICE_PROTOCOL_BONJOUR {
        return Err(P2pError::Malformed);
    }
    let transaction = service[1];
    let dns_query = &service[2..];
    if dns_query.len() < DNS_SD_TXT_TYPE.len()
        || dns_query[dns_query.len() - DNS_SD_TXT_TYPE.len()..] != DNS_SD_TXT_TYPE
        || !dns_query
            .windows(b"dmesh".len())
            .any(|part| part == b"dmesh")
    {
        return Err(P2pError::Malformed);
    }
    let txt_len = txt.len();
    let service_response_len = 3 + dns_query.len() + 1 + txt_len;
    let vendor_response_len = 4 + 2 + 2 + service_response_len;
    let query_response_len = 4 + vendor_response_len;
    let required = 13 + query_response_len;
    if out.len() < required || query_response_len > u16::MAX as usize {
        return Err(P2pError::OutputTooSmall);
    }
    let mut at = 0;
    out[at..at + 7].copy_from_slice(&[4, GAS_INITIAL_RESPONSE, body[2], 0, 0, 0, 0]);
    at += 7;
    out[at..at + 4].copy_from_slice(&[108, 2, 0, 0]);
    at += 4;
    out[at..at + 2].copy_from_slice(&(query_response_len as u16).to_le_bytes());
    at += 2;
    out[at..at + 2].copy_from_slice(&ANQP_VENDOR_SPECIFIC.to_le_bytes());
    at += 2;
    out[at..at + 2].copy_from_slice(&(vendor_response_len as u16).to_le_bytes());
    at += 2;
    out[at..at + 4].copy_from_slice(&P2P_OUI_TYPE);
    at += 4;
    out[at..at + 2].copy_from_slice(&1u16.to_le_bytes());
    at += 2;
    out[at..at + 2].copy_from_slice(&(service_response_len as u16).to_le_bytes());
    at += 2;
    out[at..at + 3].copy_from_slice(&[
        P2P_SERVICE_PROTOCOL_BONJOUR,
        transaction,
        P2P_SERVICE_SUCCESS,
    ]);
    at += 3;
    out[at..at + dns_query.len()].copy_from_slice(dns_query);
    at += dns_query.len();
    out[at] = txt_len as u8;
    at += 1;
    out[at..at + txt.len()].copy_from_slice(txt);
    at += txt.len();
    debug_assert_eq!(at, required);
    Ok(at)
}

/// Recognize the bounded `dmesh._dmesh._tcp` DNS-SD TXT request handled by
/// the passive responder. This is intentionally parser-only, so radio
/// callbacks can reject unrelated GAS/ANQP traffic without constructing a
/// response or retaining driver-owned bytes.
pub fn is_dmesh_dns_sd_request(request: &[u8]) -> bool {
    let Some(body) = request.get(crate::FRAME_DATA..) else {
        return false;
    };
    if body.len() < 9
        || body[0] != PUBLIC_ACTION_CATEGORY
        || body[1] != GAS_INITIAL_REQUEST
        || body[3..7] != [108, 2, 0, 0]
    {
        return false;
    }
    let query_len = usize::from(u16::from_le_bytes([body[7], body[8]]));
    let Some(query) = body.get(9..9 + query_len) else {
        return false;
    };
    if query.len() < 10 || u16::from_le_bytes([query[0], query[1]]) != ANQP_VENDOR_SPECIFIC {
        return false;
    }
    let vendor_len = usize::from(u16::from_le_bytes([query[2], query[3]]));
    let Some(vendor) = query.get(4..4 + vendor_len) else {
        return false;
    };
    if vendor.len() < 10 || vendor[..4] != P2P_OUI_TYPE {
        return false;
    }
    let service = &vendor[6..];
    let service_len = usize::from(u16::from_le_bytes([service[0], service[1]]));
    let Some(service) = service.get(2..2 + service_len) else {
        return false;
    };
    if service.len() < 2 || service[0] != P2P_SERVICE_PROTOCOL_BONJOUR {
        return false;
    }
    let dns_query = &service[2..];
    dns_query.len() >= DNS_SD_TXT_TYPE.len()
        && dns_query[dns_query.len() - DNS_SD_TXT_TYPE.len()..] == DNS_SD_TXT_TYPE
        && dns_query
            .windows(b"dmesh".len())
            .any(|part| part == b"dmesh")
}

/// Minimal P2P capability marker for passive DMesh discovery.
///
/// It is suitable for beacon and probe-response insertion while a node is
/// idle on one of the configured social channels.  It intentionally says
/// nothing about group ownership, Service Discovery, WPS, or credentials:
/// those are emitted only by the Phase-2 controller-triggered exchange.
pub const PASSIVE_DISCOVERY_IE: [u8; 11] = [
    VENDOR_IE,
    9,
    P2P_OUI_TYPE[0],
    P2P_OUI_TYPE[1],
    P2P_OUI_TYPE[2],
    P2P_OUI_TYPE[3],
    ATTR_CAPABILITY,
    2,
    0,
    0,
    0,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P2pError {
    OutputTooSmall,
    Malformed,
}

/// A borrowed P2P vendor IE discovered in a probe response or beacon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P2pAdvertisement<'a> {
    /// P2P attributes, excluding the WFA OUI/type.
    pub attributes: &'a [u8],
}

/// Encode a minimal P2P vendor IE. `attributes` must be a complete sequence
/// of P2P attributes; this function does not invent Device Info, channel list,
/// or WPS data before an active controller request needs them.
pub fn encode_advertisement(out: &mut [u8], attributes: &[u8]) -> Result<usize, P2pError> {
    let body_len = P2P_OUI_TYPE.len() + attributes.len();
    if body_len > u8::MAX as usize || out.len() < body_len + 2 {
        return Err(P2pError::OutputTooSmall);
    }
    out[0] = VENDOR_IE;
    out[1] = body_len as u8;
    out[2..6].copy_from_slice(&P2P_OUI_TYPE);
    out[6..6 + attributes.len()].copy_from_slice(attributes);
    Ok(body_len + 2)
}

/// Encode the directed probe-response P2P IE used by a host/ESP passive
/// listener. It identifies a real device address, advertises P2P Service
/// Discovery capability, and pins the listen channel to the active channel.
///
/// This is not a GO declaration and contains neither WPS nor credentials.
/// GAS/P2P SD replies are deliberately a separate, controller-triggered
/// operation so this constant-time response never changes radio state.
pub fn encode_discovery_advertisement(
    out: &mut [u8],
    device_addr: [u8; 6],
    channel: u8,
) -> Result<usize, P2pError> {
    // P2P Capability (5), Listen Channel (8), Device Info (29), plus the
    // vendor IE header/OUI type (6).
    const USED: usize = 48;
    if out.len() < USED || channel == 0 {
        return Err(P2pError::OutputTooSmall);
    }
    out[0] = VENDOR_IE;
    out[1] = (USED - 2) as u8;
    out[2..6].copy_from_slice(&P2P_OUI_TYPE);
    let mut at = 6;
    let mut attr = |id: u8, value: &[u8]| {
        out[at] = id;
        out[at + 1..at + 3].copy_from_slice(&(value.len() as u16).to_le_bytes());
        at += 3;
        out[at..at + value.len()].copy_from_slice(value);
        at += value.len();
    };
    attr(ATTR_CAPABILITY, &[DEVICE_CAPABILITY_SERVICE_DISCOVERY, 0]);
    attr(
        ATTR_LISTEN_CHANNEL,
        &[b'X', b'X', 0x04, OPERATING_CLASS_2GHZ, channel],
    );
    // Device address, WPS config methods, primary device type, no secondary
    // types, then a WPS Device Name attribute. The values identify a generic
    // computer-class device; connection/WPS policy is intentionally absent.
    let mut device_info = [0u8; 26];
    device_info[..6].copy_from_slice(&device_addr);
    device_info[8..16].copy_from_slice(&[0, 1, 0, 0x50, 0xf2, 4, 0, 1]);
    device_info[17..21].copy_from_slice(&[0x10, 0x11, 0, 5]);
    device_info[21..].copy_from_slice(b"dmesh");
    attr(ATTR_DEVICE_INFO, &device_info);
    debug_assert_eq!(at, USED);
    Ok(USED)
}

/// Return the first complete P2P vendor IE in an information-element list.
/// Invalid/truncated IEs are rejected rather than skipped: adapters must not
/// accidentally accept a partial driver frame as a P2P advertisement.
pub fn parse_advertisement(ies: &[u8]) -> Result<Option<P2pAdvertisement<'_>>, P2pError> {
    let mut offset = 0usize;
    while offset < ies.len() {
        if offset + 2 > ies.len() {
            return Err(P2pError::Malformed);
        }
        let id = ies[offset];
        let len = ies[offset + 1] as usize;
        let start = offset + 2;
        let end = start.checked_add(len).ok_or(P2pError::Malformed)?;
        if end > ies.len() {
            return Err(P2pError::Malformed);
        }
        if id == VENDOR_IE && ies.get(start..start + 4) == Some(&P2P_OUI_TYPE) {
            return Ok(Some(P2pAdvertisement {
                attributes: &ies[start + 4..end],
            }));
        }
        offset = end;
    }
    Ok(None)
}

/// Detect a Wi-Fi Direct public action before Phase 2 parses its subtype,
/// transaction token, and attributes.
pub const fn is_public_action(body: &[u8]) -> bool {
    body.len() >= 6
        && body[0] == PUBLIC_ACTION_CATEGORY
        && body[1] == P2P_PUBLIC_ACTION
        && body[2] == P2P_OUI_TYPE[0]
        && body[3] == P2P_OUI_TYPE[1]
        && body[4] == P2P_OUI_TYPE[2]
        && body[5] == P2P_OUI_TYPE[3]
}

/// Detect GAS initial service-discovery requests. The detailed ANQP/P2P SD
/// payload parser is intentionally introduced with the active SD responder;
/// Phase 1 still records the token and complete body without accepting a
/// malformed request as a DMesh command.
pub const fn is_gas_initial_request(body: &[u8]) -> bool {
    body.len() >= 3 && body[0] == PUBLIC_ACTION_CATEGORY && body[1] == GAS_INITIAL_REQUEST
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertisement_round_trip_and_truncation() {
        let attributes = [ATTR_CAPABILITY, 2, 0, 0, 0];
        let mut wire = [0; 16];
        let used = encode_advertisement(&mut wire, &attributes).unwrap();
        assert_eq!(
            parse_advertisement(&wire[..used])
                .unwrap()
                .unwrap()
                .attributes,
            attributes
        );
        assert_eq!(parse_advertisement(&[]), Ok(None));
        for end in 1..used {
            assert!(parse_advertisement(&wire[..end]).is_err());
        }
    }

    #[test]
    fn passive_discovery_marker_is_a_complete_p2p_ie() {
        let advertisement = parse_advertisement(&PASSIVE_DISCOVERY_IE).unwrap().unwrap();
        assert_eq!(advertisement.attributes, [ATTR_CAPABILITY, 2, 0, 0, 0]);
    }

    #[test]
    fn directed_discovery_advertisement_has_device_and_channel_attributes() {
        let mut wire = [0; 64];
        let used = encode_discovery_advertisement(&mut wire, [1, 2, 3, 4, 5, 6], 6).unwrap();
        let advertisement = parse_advertisement(&wire[..used]).unwrap().unwrap();
        assert_eq!(
            advertisement.attributes[0..5],
            [ATTR_CAPABILITY, 2, 0, 1, 0]
        );
        assert_eq!(
            advertisement.attributes[5..13],
            [ATTR_LISTEN_CHANNEL, 5, 0, b'X', b'X', 4, 81, 6]
        );
        assert_eq!(advertisement.attributes[13], ATTR_DEVICE_INFO);
    }

    #[test]
    fn recognizes_p2p_public_action() {
        assert!(is_public_action(&[0x04, 0x09, 0x50, 0x6f, 0x9a, 0x09]));
        assert!(!is_public_action(&[0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13]));
    }

    #[test]
    fn empty_gas_response_preserves_the_request_dialog_token() {
        let mut response = [0u8; 16];
        let used = encode_empty_gas_initial_response(&mut response, 0x6c).unwrap();
        assert_eq!(
            &response[..used],
            &[
                4,
                GAS_INITIAL_RESPONSE,
                0x6c,
                0,
                0,
                0,
                0,
                108,
                2,
                0,
                0,
                0,
                0
            ]
        );
        assert_eq!(
            gas_initial_request_dialog_token(&[0; crate::FRAME_DATA]),
            None
        );
    }

    #[test]
    fn dmesh_dns_sd_response_echoes_query_and_presence_marker() {
        // Android's WifiP2pDnsSdServiceRequest for dmesh._dmesh._tcp / TXT.
        let mut request = [0u8; crate::FRAME_DATA + 41];
        assert_eq!(
            encode_dmesh_dns_sd_gas_initial_request(&mut request[crate::FRAME_DATA..], 0x6c,)
                .unwrap(),
            41
        );
        let mut response = [0u8; 160];
        let mut presence = [0u8; 18];
        let presence_len =
            encode_dmesh_service_presence_txt(&mut presence, &[0x74, 0x19, 0xf8, 0x17, 0xde, 0x65])
                .unwrap();
        assert!(is_dmesh_dns_sd_request(&request));
        let used = encode_dmesh_dns_sd_gas_initial_response(
            &mut response,
            &request,
            &presence[..presence_len],
        )
        .unwrap();
        assert_eq!(&response[..3], &[4, GAS_INITIAL_RESPONSE, 0x6c]);
        assert!(response[..used].windows(5).any(|part| part == b"dmesh"));
        assert!(
            response[..used]
                .windows(presence_len)
                .any(|part| part == &presence[..presence_len])
        );
        for end in crate::FRAME_DATA..request.len() {
            assert!(!is_dmesh_dns_sd_request(&request[..end]));
            assert_eq!(
                encode_dmesh_dns_sd_gas_initial_response(
                    &mut response,
                    &request[..end],
                    &presence[..presence_len],
                ),
                Err(P2pError::Malformed),
            );
        }
    }
}
