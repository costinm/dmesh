//! Bearer-neutral stream services used by UDP, NAN, fake links, and devices.
//!
//! This module deliberately has no socket or bearer code. A bearer decodes a
//! stream packet and passes the complete request to the shared tagged
//! dispatcher. Bearers do not select application handlers.

use alloc::vec::Vec;

const MAX_EVENT_RESPONSE_BYTES: usize = 1200;
/// A retained binary event must fit in one bounded direct-record response.
/// This is also a memory boundary: a count-limited history without a payload
/// limit would still allow one producer to retain an arbitrary allocation.
pub const MAX_BINARY_EVENT_PAYLOAD_BYTES: usize = 1024;

/// Current Main identity and infrastructure-link state exposed by the
/// generic `status` stream method. Address values are presentation-ready text
/// so controllers can display them without knowing firmware byte order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceStatus<'a> {
    pub uptime_secs: u64,
    pub sta_enabled: bool,
    pub sta_associated: bool,
    pub sta_bssid: &'a [u8],
    pub sta_ipv4: &'a [u8],
}

/// Encode a correlated compact Main status response, including current STA
/// enablement, association, BSSID, and IPv4 state.
pub fn encode_device_status_response(id: u64, status: DeviceStatus<'_>) -> Option<Vec<u8>> {
    if !status.sta_bssid.is_ascii() || !status.sta_ipv4.is_ascii() {
        return None;
    }
    let mut result = [0u8; 224];
    let mut encoder = crate::cbor::Encoder::new(&mut result);
    encoder.map(7)?;
    encoder.text_value(b"status")?;
    encoder.text_value(b"ok")?;
    encoder.text_value(b"role")?;
    encoder.text_value(b"main")?;
    encoder.text_value(b"uptime_secs")?;
    encoder.uint(status.uptime_secs)?;
    encoder.text_value(b"sta_enabled")?;
    encoder.boolean(status.sta_enabled)?;
    encoder.text_value(b"sta_associated")?;
    encoder.boolean(status.sta_associated)?;
    encoder.text_value(b"sta_bssid")?;
    encoder.text_value(status.sta_bssid)?;
    encoder.text_value(b"sta_ipv4")?;
    encoder.text_value(status.sta_ipv4)?;
    let result_len = encoder.len();
    drop(encoder);

    let mut response = [0u8; 288];
    let response_len = crate::tagged::encode_numeric_response(
        DIAGNOSTIC_COMPONENT,
        DIAGNOSTIC_STATUS_METHOD,
        id,
        &result[..result_len],
        &mut response,
    )?;
    Some(Vec::from(&response[..response_len]))
}

struct IncompleteRecord<K> {
    key: K,
    bytes: Vec<u8>,
}

/// Reassembles ordered application records split across transport chunks.
/// Both the per-record and aggregate retained-byte limits are supplied by
/// the owner so firmware can follow its runtime association limits.
pub struct OrderedRecordAssembler<K> {
    incomplete: Vec<IncompleteRecord<K>>,
    buffered_bytes: usize,
}

impl<K> OrderedRecordAssembler<K> {
    pub const fn new() -> Self {
        Self {
            incomplete: Vec::new(),
            buffered_bytes: 0,
        }
    }

    pub const fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }
}

impl<K: Eq> OrderedRecordAssembler<K> {
    /// Accept one in-order chunk. A short acceptance of zero means the owner
    /// must withhold receive credit until retained capacity becomes available.
    /// A complete record is returned only when its FIN has been observed.
    pub fn push(
        &mut self,
        key: K,
        offset: u64,
        fin: bool,
        chunk: &[u8],
        max_record_bytes: usize,
        max_total_bytes: usize,
    ) -> (usize, Option<(K, Vec<u8>)>) {
        let existing = self.incomplete.iter().position(|record| record.key == key);
        let index = if let Some(index) = existing {
            index
        } else {
            if offset != 0
                || chunk.len() > max_record_bytes
                || chunk.len() > max_total_bytes.saturating_sub(self.buffered_bytes)
                || self.incomplete.try_reserve(1).is_err()
            {
                return (0, None);
            }
            self.incomplete.push(IncompleteRecord {
                key,
                bytes: Vec::new(),
            });
            self.incomplete.len() - 1
        };

        let record = &mut self.incomplete[index];
        if offset != record.bytes.len() as u64
            || chunk.len() > max_record_bytes.saturating_sub(record.bytes.len())
            || chunk.len() > max_total_bytes.saturating_sub(self.buffered_bytes)
            || record.bytes.try_reserve(chunk.len()).is_err()
        {
            return (0, None);
        }
        record.bytes.extend_from_slice(chunk);
        self.buffered_bytes += chunk.len();
        let accepted = chunk.len();
        if !fin {
            return (accepted, None);
        }

        let record = self.incomplete.swap_remove(index);
        self.buffered_bytes -= record.bytes.len();
        (accepted, Some((record.key, record.bytes)))
    }
}

impl<K: Eq> Default for OrderedRecordAssembler<K> {
    fn default() -> Self {
        Self::new()
    }
}

/// Common read-only connection diagnostics. These are application handlers,
/// not QUIC service numbers; every request uses the normal tagged envelope.
pub const DIAGNOSTIC_COMPONENT: u64 = 9;
pub const DIAGNOSTIC_STATUS_METHOD: u64 = 1;
pub const DIAGNOSTIC_SERVICES_METHOD: u64 = 2;
/// Main-only boot-control component. It is stream-only; Recovery deliberately
/// does not register it.
pub const BOOT_COMPONENT: u64 = 11;
pub const BOOT_RECOVERY_METHOD: u64 = 1;
/// Read-only identity of the currently executing firmware image.
pub const FIRMWARE_COMPONENT: u64 = 12;
pub const FIRMWARE_IDENTITY_METHOD: u64 = 1;
/// Runtime reset component (the state snapshot is `telemetry.runtime`).
pub const RUNTIME_SNAPSHOT_COMPONENT: u64 = 101;
pub const RUNTIME_RESET_METHOD: u64 = 2;
/// BLE adapter component shared by the ESP firmware adapter and host
/// services that expose the same catalog surface.
pub const BLE_COMPONENT: u64 = 104;
pub const BLE_START_METHOD: u64 = 80;
pub const BLE_STOP_METHOD: u64 = 81;
pub const BLE_SCAN_METHOD: u64 = 82;
pub const BLE_STATUS_METHOD: u64 = 83;
pub const BLE_SCAN_STOP_METHOD: u64 = 84;
pub const BLE_CONNECT_METHOD: u64 = 85;
pub const BLE_COC_SEND_METHOD: u64 = 86;
/// Loadable-firmware-module control component.
pub const MODULE_COMPONENT: u64 = 1000;

/// Encode the one running-image identity string supplied by a firmware
/// platform. The portable service owns validation and the tagged response;
/// ESP-IDF only supplies its ELF SHA-256 bytes.
pub fn encode_firmware_identity_response(
    record: crate::tagged::Record<'_>,
    identity: &[u8],
) -> Option<Vec<u8>> {
    if record.component != Some(crate::tagged::Name::Tag(FIRMWARE_COMPONENT))
        || record.method != Some(crate::tagged::Name::Tag(FIRMWARE_IDENTITY_METHOD))
        || record.to.is_some()
        || record.params.is_some()
        || record.data.is_some()
        || record.fields.is_some()
        || record.result.is_some()
        || record.error.is_some()
        || identity.is_empty()
        || identity.len() > 128
        || !identity.is_ascii()
    {
        return None;
    }
    let id = record.id?;
    let mut response = alloc::vec![0; identity.len().checked_add(64)?];
    let used = crate::tagged::encode_numeric_data_response(
        FIRMWARE_COMPONENT,
        FIRMWARE_IDENTITY_METHOD,
        id,
        identity,
        true,
        &mut response,
    )?;
    response.truncate(used);
    Some(response)
}
/// Encode the registered tagged handlers as
/// `[[component, method, "name"], ...]`. The registry is the only source:
/// a method that is not registered is not reported.
///
/// Compatibility stream selectors are intentionally excluded: they are
/// framing for object transfer and connection migration, not application
/// handler identities.
pub fn encode_tagged_service_catalog() -> Vec<u8> {
    crate::registry::REGISTRY.encode_service_catalog()
}

/// Association identity for handlers that bind follow-on streams or state to
/// a peer. Kept under its historical name; the type lives with the registry.
pub use crate::registry::CallContext as TaggedRequestContext;

#[cfg(test)]
mod record_assembler_tests {
    use super::OrderedRecordAssembler;

    #[test]
    fn request_body_and_fin_may_arrive_in_separate_chunks() {
        let mut assembler = OrderedRecordAssembler::new();
        assert_eq!(
            assembler.push(7, 0, false, b"request body", 128, 256),
            (12, None)
        );
        let (accepted, complete) = assembler.push(7, 12, true, b"", 128, 256);
        assert_eq!(accepted, 0);
        assert_eq!(complete, Some((7, b"request body".to_vec())));
        assert_eq!(assembler.buffered_bytes(), 0);
    }

    #[test]
    fn interleaved_records_keep_independent_offsets_and_contents() {
        let mut assembler = OrderedRecordAssembler::new();
        assert_eq!(assembler.push(1, 0, false, b"ab", 16, 16), (2, None));
        assert_eq!(assembler.push(2, 0, false, b"x", 16, 16), (1, None));
        assert_eq!(
            assembler.push(1, 2, true, b"cd", 16, 16),
            (2, Some((1, b"abcd".to_vec())))
        );
        assert_eq!(
            assembler.push(2, 1, true, b"y", 16, 16),
            (1, Some((2, b"xy".to_vec())))
        );
        assert_eq!(assembler.buffered_bytes(), 0);
    }

    #[test]
    fn byte_limits_withhold_the_chunk_without_corrupting_prior_data() {
        let mut assembler = OrderedRecordAssembler::new();
        assert_eq!(assembler.push(1, 0, false, b"ab", 4, 3), (2, None));
        assert_eq!(assembler.push(2, 0, false, b"xy", 4, 3), (0, None));
        assert_eq!(assembler.buffered_bytes(), 2);
        assert_eq!(
            assembler.push(1, 2, true, b"", 4, 3),
            (0, Some((1, b"ab".to_vec())))
        );
        assert_eq!(
            assembler.push(2, 0, true, b"xy", 4, 3),
            (2, Some((2, b"xy".to_vec())))
        );
        assert_eq!(assembler.buffered_bytes(), 0);
    }
}

#[cfg(test)]
mod device_status_tests {
    #[test]
    fn correlated_status_contains_current_sta_state_and_addresses() {
        let response = super::encode_device_status_response(
            93,
            super::DeviceStatus {
                uptime_secs: 17,
                sta_enabled: true,
                sta_associated: true,
                sta_bssid: b"1c:b7:2c:77:1b:f8",
                sta_ipv4: b"192.0.2.44",
            },
        )
        .unwrap();
        let envelope = crate::tagged::decode(&response).unwrap();
        assert_eq!(envelope.component, Some(crate::tagged::Name::Tag(9)));
        assert_eq!(envelope.method, Some(crate::tagged::Name::Tag(1)));
        assert_eq!(envelope.id, Some(93));

        let mut result = crate::cbor::Decoder::new(envelope.result.unwrap());
        assert_eq!(result.head(), Some((5, 7)));
        assert_eq!(result.text_ref(), Some(b"status".as_slice()));
        assert_eq!(result.text_ref(), Some(b"ok".as_slice()));
        assert_eq!(result.text_ref(), Some(b"role".as_slice()));
        assert_eq!(result.text_ref(), Some(b"main".as_slice()));
        assert_eq!(result.text_ref(), Some(b"uptime_secs".as_slice()));
        assert_eq!(result.uint(), Some(17));
        assert_eq!(result.text_ref(), Some(b"sta_enabled".as_slice()));
        assert_eq!(result.boolean(), Some(true));
        assert_eq!(result.text_ref(), Some(b"sta_associated".as_slice()));
        assert_eq!(result.boolean(), Some(true));
        assert_eq!(result.text_ref(), Some(b"sta_bssid".as_slice()));
        assert_eq!(result.text_ref(), Some(b"1c:b7:2c:77:1b:f8".as_slice()));
        assert_eq!(result.text_ref(), Some(b"sta_ipv4".as_slice()));
        assert_eq!(result.text_ref(), Some(b"192.0.2.44".as_slice()));
        assert!(result.is_finished());
    }
}

/// Encode a compact `recovery` success response whose payload is a numeric
/// counter map. UART, UDP logging, and host tests share this schema; bearer
/// framing is deliberately outside this function.
pub fn encode_numeric_result(values: &[(u64, u64)]) -> Option<Vec<u8>> {
    if values.len() > u8::MAX as usize {
        return None;
    }
    let mut inner = [0u8; 1024];
    let mut encoder = crate::cbor::Encoder::new(&mut inner);
    encoder.map(values.len() as u64)?;
    for (key, value) in values {
        encoder.uint(*key)?;
        encoder.uint(*value)?;
    }
    let encoded_len = encoder.len();
    drop(encoder);
    let mut response = Vec::with_capacity(16 + encoded_len);
    response.extend_from_slice(&[0xa3, 0x00, 0x18, 0x44, 0x04, 0x62, b'o', b'k', 0x06]);
    response.extend_from_slice(&inner[..encoded_len]);
    Some(response)
}

/// Encode the bounded diagnostic/status envelope used by the direct-CBOR
/// exception plane. Firmware adapters share this rather than growing a
/// second CBOR schema for bootstrap failures.
pub fn encode_status_text(message: &[u8]) -> Option<Vec<u8>> {
    if message.len() >= 256 {
        return None;
    }
    let mut response = Vec::with_capacity(16 + message.len());
    response.extend_from_slice(&[
        0xa3, 0x00, 0x18, 0x44, 0x04, 0x62, b'o', b'k', 0x06, 0xa1, 0x18, 0x20,
    ]);
    if message.len() < 24 {
        response.push(0x60 + message.len() as u8);
    } else {
        response.extend_from_slice(&[0x78, message.len() as u8]);
    }
    response.extend_from_slice(message);
    Some(response)
}

/// Decode the text form of the bounded direct status record. This is useful
/// on connectionless bearers during discovery: the record is intentionally
/// not a QUIC-lite datagram and must be recognized before a bearer attempts
/// transport dispatch.
pub fn decode_status_text(record: &[u8]) -> Option<&[u8]> {
    let mut decoder = crate::cbor::Decoder::new(record);
    (decoder.head()? == (5, 3)).then_some(())?;
    (decoder.uint()? == 0).then_some(())?;
    (decoder.uint()? == 68).then_some(())?;
    (decoder.uint()? == 4).then_some(())?;
    (decoder.text_ref()? == b"ok").then_some(())?;
    (decoder.uint()? == 6).then_some(())?;
    (decoder.head()? == (5, 1)).then_some(())?;
    (decoder.uint()? == 32).then_some(())?;
    let message = decoder.text_ref()?;
    decoder.is_finished().then_some(message)
}

/// Encode one named numeric diagnostic without converting the value to text.
/// The direct-record envelope remains compatible with ordinary status text,
/// but its payload is `{name: uint}` so consumers retain a CBOR integer.
pub fn encode_status_numeric(name: &[u8], value: u64) -> Option<Vec<u8>> {
    if name.is_empty() || name.len() > 96 || !name.is_ascii() {
        return None;
    }
    // Three outer fields, a one-entry payload map, a 96-byte name, and a u64
    // fit in this fixed scratch allocation. Truncate after canonical encoding.
    let mut response = Vec::with_capacity(128);
    response.resize(128, 0);
    let mut encoder = crate::cbor::Encoder::new(&mut response);
    encoder.map(3)?;
    encoder.uint(0)?;
    encoder.uint(68)?;
    encoder.uint(4)?;
    encoder.text_value(b"ok")?;
    encoder.uint(6)?;
    encoder.map(1)?;
    encoder.text_value(name)?;
    encoder.uint(value)?;
    let len = encoder.len();
    response.truncate(len);
    Some(response)
}

/// Encode a small named numeric status map as one direct diagnostic record.
/// Related values from one physical boundary stay together rather than being
/// interleaved with another producer's direct records.
pub fn encode_status_numbers(entries: &[(&[u8], u64)]) -> Option<Vec<u8>> {
    if entries.is_empty()
        || entries.len() > 8
        || entries
            .iter()
            .any(|(name, _)| name.is_empty() || name.len() > 96 || !name.is_ascii())
    {
        return None;
    }
    let mut response = Vec::with_capacity(256);
    response.resize(256, 0);
    let mut encoder = crate::cbor::Encoder::new(&mut response);
    encoder.map(3)?;
    encoder.uint(0)?;
    encoder.uint(68)?;
    encoder.uint(4)?;
    encoder.text_value(b"ok")?;
    encoder.uint(6)?;
    encoder.map(entries.len() as u64)?;
    for (name, value) in entries {
        encoder.text_value(name)?;
        encoder.uint(*value)?;
    }
    let len = encoder.len();
    response.truncate(len);
    Some(response)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventRecord {
    pub sequence: u64,
    pub kind: u8,
    pub stream_id: u64,
    pub packet_number: u64,
    pub value: u64,
}

/// One application-owned binary event retained outside the transport core.
/// The numeric envelope is shared by firmware and host clients; payload bytes
/// remain opaque to dmesh-server and QUIC-lite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BinaryEventRecord<'a> {
    pub sequence: u64,
    pub event_id: u16,
    pub value_type: u8,
    pub flags: u8,
    pub payload: &'a [u8],
}

fn cbor_head_len(value: u64) -> usize {
    if value < 24 {
        1
    } else if value <= u8::MAX as u64 {
        2
    } else if value <= u32::MAX as u64 {
        5
    } else {
        9
    }
}

fn binary_event_len(event: BinaryEventRecord<'_>) -> usize {
    // [sequence, event_id, value_type, flags, payload]
    cbor_head_len(5)
        .saturating_add(cbor_head_len(event.sequence))
        .saturating_add(cbor_head_len(u64::from(event.event_id)))
        .saturating_add(cbor_head_len(u64::from(event.value_type)))
        .saturating_add(cbor_head_len(u64::from(event.flags)))
        .saturating_add(cbor_head_len(event.payload.len() as u64))
        .saturating_add(event.payload.len())
}

/// Encode canonical CBOR `[next_sequence, [[seq,id,type,flags,payload],...]]`
/// without splitting an event. `max_bytes` bounds one bearer response; callers
/// continue with `since=<sequence>` when the retained history is longer.
pub fn encode_binary_events(
    next_sequence: u64,
    records: &[BinaryEventRecord<'_>],
    max_bytes: usize,
) -> Option<Vec<u8>> {
    let header = cbor_head_len(2).saturating_add(cbor_head_len(next_sequence));
    let mut count = 0usize;
    let mut events_len = 0usize;
    for record in records {
        let event_len = binary_event_len(*record);
        let next = header
            .saturating_add(cbor_head_len((count + 1) as u64))
            .saturating_add(events_len)
            .saturating_add(event_len);
        if next > max_bytes {
            break;
        }
        events_len = events_len.saturating_add(event_len);
        count += 1;
    }
    if header.saturating_add(cbor_head_len(count as u64)) > max_bytes {
        return None;
    }
    let mut output = Vec::with_capacity(max_bytes);
    output.resize(max_bytes, 0);
    let mut encoder = crate::cbor::Encoder::new(&mut output);
    encoder.array(2)?;
    encoder.uint(next_sequence)?;
    encoder.array(count as u64)?;
    for record in records.iter().take(count) {
        encoder.array(5)?;
        encoder.uint(record.sequence)?;
        encoder.uint(u64::from(record.event_id))?;
        encoder.uint(u64::from(record.value_type))?;
        encoder.uint(u64::from(record.flags))?;
        encoder.bytes_value(record.payload)?;
    }
    let len = encoder.len();
    output.truncate(len);
    Some(output)
}

/// Bounded, bearer-neutral event history for diagnostics and test control.
#[derive(Clone, Debug)]
pub struct EventRing {
    entries: Vec<EventRecord>,
    next_sequence: u64,
    capacity: usize,
}

impl EventRing {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
            next_sequence: 0,
            capacity,
        }
    }
    pub fn capacity(&self) -> usize {
        self.capacity
    }
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn records(&self) -> &[EventRecord] {
        &self.entries
    }
    pub fn push(&mut self, kind: u8, stream_id: u64, packet_number: u64, value: u64) {
        if self.capacity == 0 {
            return;
        }
        let record = EventRecord {
            sequence: self.next_sequence,
            kind,
            stream_id,
            packet_number,
            value,
        };
        self.next_sequence = self.next_sequence.saturating_add(1);
        if self.entries.len() == self.capacity {
            self.entries.remove(0);
        }
        self.entries.push(record);
    }
    pub fn since(&self, sequence: u64) -> impl Iterator<Item = &EventRecord> {
        self.entries
            .iter()
            .filter(move |record| record.sequence >= sequence)
    }
}
