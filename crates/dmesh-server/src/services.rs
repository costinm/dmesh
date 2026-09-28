//! Bearer-neutral stream services used by UDP, NAN, fake links, and devices.
//!
//! This module deliberately has no socket or bearer code. A bearer decodes a
//! stream packet and passes the complete request to the shared tagged
//! dispatcher. Bearers do not select application handlers.

use alloc::format;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

const MAX_EVENT_RESPONSE_BYTES: usize = 1200;
/// A retained binary event must fit in one bounded direct-record response.
/// This is also a memory boundary: a count-limited history without a payload
/// limit would still allow one producer to retain an arbitrary allocation.
pub const MAX_BINARY_EVENT_PAYLOAD_BYTES: usize = 1024;
pub const LOG_WATCH_MAX_RECORDS: usize = 64;

/// Common read-only connection diagnostics. These are application handlers,
/// not QUIC service numbers; every request uses the normal tagged envelope.
pub const DIAGNOSTIC_COMPONENT: u64 = 9;
pub const DIAGNOSTIC_STATUS_METHOD: u64 = 1;
pub const DIAGNOSTIC_SERVICES_METHOD: u64 = 2;
pub const DIAGNOSTIC_METRICS_METHOD: u64 = 3;
pub const DIAGNOSTIC_EVENTS_METHOD: u64 = 4;
pub const DIAGNOSTIC_LOG_WATCH_METHOD: u64 = 5;
/// Main-only boot-control component. It is stream-only; Recovery deliberately
/// does not register it.
pub const BOOT_COMPONENT: u64 = 11;
pub const BOOT_RECOVERY_METHOD: u64 = 1;
/// Read-only identity of the currently executing firmware image.
pub const FIRMWARE_COMPONENT: u64 = 12;
pub const FIRMWARE_IDENTITY_METHOD: u64 = 1;

const BUILTIN_TAGGED_SERVICES: &[(u64, u64, &[u8])] = &[
    (DIAGNOSTIC_COMPONENT, DIAGNOSTIC_STATUS_METHOD, b"status"),
    (
        DIAGNOSTIC_COMPONENT,
        DIAGNOSTIC_SERVICES_METHOD,
        b"services",
    ),
    (DIAGNOSTIC_COMPONENT, DIAGNOSTIC_METRICS_METHOD, b"metrics"),
    (DIAGNOSTIC_COMPONENT, DIAGNOSTIC_EVENTS_METHOD, b"events"),
    (
        DIAGNOSTIC_COMPONENT,
        DIAGNOSTIC_LOG_WATCH_METHOD,
        b"log-watch",
    ),
    (
        crate::probe::PROBE_COMPONENT,
        crate::probe::PROBE_RUN,
        b"probe",
    ),
    (
        crate::verified_object::OBJECT_COMPONENT,
        crate::verified_object::OBJECT_GET_METHOD,
        b"object.get",
    ),
    (
        crate::verified_object::OBJECT_COMPONENT,
        crate::verified_object::OBJECT_FLASH_METHOD,
        b"object.flash",
    ),
    (BOOT_COMPONENT, BOOT_RECOVERY_METHOD, b"boot.recovery"),
    (
        FIRMWARE_COMPONENT,
        FIRMWARE_IDENTITY_METHOD,
        b"firmware.identity",
    ),
];

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
/// Encode the built-in tagged QUIC handler catalog as
/// `[[component, method, "service"], ...]`.
///
/// Compatibility stream selectors are intentionally excluded: they are
/// framing for object transfer and connection migration, not application
/// handler identities.
pub fn encode_tagged_service_catalog() -> Vec<u8> {
    let mut output = alloc::vec![0; 192];
    let mut encoder = crate::cbor::Encoder::new(&mut output);
    encoder
        .array(BUILTIN_TAGGED_SERVICES.len() as u64)
        .expect("fixed service catalog capacity");
    for (component, method, name) in BUILTIN_TAGGED_SERVICES {
        encoder.array(3).expect("fixed service catalog capacity");
        encoder
            .uint(*component)
            .expect("fixed service catalog capacity");
        encoder
            .uint(*method)
            .expect("fixed service catalog capacity");
        encoder
            .text_value(name)
            .expect("fixed service catalog capacity");
    }
    let used = encoder.len();
    output.truncate(used);
    output
}

/// Platform extension for tagged-CBOR requests carried directly in an
/// application stream. Component IDs remain `u64` inside the envelope, so
/// board modules can use the 1000+ range without colliding with legacy
/// one-byte stream-service selectors. Handlers are registered per component
/// by an application (Main, Recovery, or a host server); the bearer runtime
/// remains unaware of them.
pub type TaggedComponentHandler = fn(crate::tagged::Record<'_>) -> Option<Vec<u8>>;

const TAGGED_COMPONENT_CAPACITY: usize = 16;
// Each slot is published handler-first, component-second. A reader that sees
// the component with Acquire ordering therefore sees the matching function.
// Components use small numeric IDs today (1000+) and fit `usize` on every
// ESP target; the decoded `u64` is checked before the cast.
static TAGGED_COMPONENT_IDS: [AtomicUsize; TAGGED_COMPONENT_CAPACITY] =
    [const { AtomicUsize::new(0) }; TAGGED_COMPONENT_CAPACITY];
static TAGGED_COMPONENT_HANDLERS: [AtomicUsize; TAGGED_COMPONENT_CAPACITY] =
    [const { AtomicUsize::new(0) }; TAGGED_COMPONENT_CAPACITY];

/// Register one tagged-CBOR component. It is called at application startup,
/// before transports accept traffic; duplicate component IDs are rejected.
/// The fixed table bounds the handler surface without heap allocations.
pub fn register_tagged_component(component: u64, handler: TaggedComponentHandler) -> bool {
    let Ok(component) = usize::try_from(component) else {
        return false;
    };
    if component == 0 {
        return false;
    }
    for index in 0..TAGGED_COMPONENT_CAPACITY {
        let existing = TAGGED_COMPONENT_IDS[index].load(Ordering::Acquire);
        if existing == component {
            return false;
        }
        if existing == 0
            && TAGGED_COMPONENT_IDS[index]
                .compare_exchange(0, usize::MAX, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            TAGGED_COMPONENT_HANDLERS[index].store(handler as usize, Ordering::Release);
            TAGGED_COMPONENT_IDS[index].store(component, Ordering::Release);
            return true;
        }
    }
    false
}

/// Dispatch a complete tagged-CBOR stream request.
///
/// A stream is an HTTP-like request channel, not a handler identity: each
/// stream may carry any component and multiple streams may concurrently call
/// the same component.
pub fn dispatch_tagged_stream(data: &[u8]) -> Option<Vec<u8>> {
    dispatch_tagged_record(crate::tagged::decode(data)?)
}

/// Dispatch an already-decoded tagged record from a canonical stream handler.
/// This registry is deliberately not a direct-message allowlist: connectionless
/// ingress must apply its explicit policy before invoking any operation.
pub fn dispatch_tagged_record(record: crate::tagged::Record<'_>) -> Option<Vec<u8>> {
    let crate::tagged::Name::Tag(component) = record.component? else {
        return None;
    };
    let component = usize::try_from(component).ok()?;
    for index in 0..TAGGED_COMPONENT_CAPACITY {
        if TAGGED_COMPONENT_IDS[index].load(Ordering::Acquire) == component {
            let handler = TAGGED_COMPONENT_HANDLERS[index].load(Ordering::Acquire);
            let handler: TaggedComponentHandler =
                (handler != 0).then(|| unsafe { core::mem::transmute(handler) })?;
            return handler(record);
        }
    }
    None
}

/// Decode `{1: since?, 2: records?}` without allowing unknown or duplicate
/// fields. An omitted fields map is the same as an empty map.
fn diagnostic_fields(fields: Option<&[u8]>) -> Option<(Option<u64>, Option<u64>)> {
    let Some(fields) = fields else {
        return Some((None, None));
    };
    let mut decoder = crate::cbor::Decoder::new(fields);
    let (major, count) = decoder.head()?;
    if major != 5 || count == u64::MAX {
        return None;
    }
    let mut since = None;
    let mut records = None;
    for _ in 0..count {
        match decoder.uint()? {
            1 if since.is_none() => since = Some(decoder.uint()?),
            2 if records.is_none() => records = Some(decoder.uint()?),
            _ => return None,
        }
    }
    decoder.is_finished().then_some((since, records))
}

/// Bounded subscription request shared by every server adapter. The request
/// is deliberately small and opaque to QUIC-lite: adapters decide only how
/// to schedule the resulting stream records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogWatchRequest {
    pub records: usize,
}

pub fn decode_log_watch_request(data: &[u8]) -> Result<LogWatchRequest, &'static str> {
    let records = match data {
        [] => 1,
        [records] => usize::from(*records),
        _ => return Err("log-watch request must contain at most one record count"),
    };
    if !(1..=LOG_WATCH_MAX_RECORDS).contains(&records) {
        return Err("log-watch record count out of range");
    }
    Ok(LogWatchRequest { records })
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
