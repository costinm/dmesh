//! Signed announcement streams, with optional retained receiver metadata.
use crate::{
    discovery_nodes::{self as wire, Observation, Options, Origin},
    inventory::Device,
};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};

/// Build the response header and live/retained byte source for `discovery.nodes`.
///
/// Transport stream adapters wrap [`NodesSource`] in their response body type.
pub fn open_stream(
    engine: Arc<crate::Engine>,
    id: u64,
    options: Options,
    live_scopes_only: bool,
) -> Option<(Vec<u8>, NodesSource)> {
    let mut header = vec![0; 64];
    let n = wire::header(id, &mut header)?;
    header.truncate(n);
    Some((
        header,
        NodesSource::new(engine, options, live_scopes_only),
    ))
}

/// A snapshot using the same wire; useful to synchronous local adapters. Network
/// endpoints use stream_response to include live updates for the requested window.
pub fn response(devices: &[Device], id: u64, live_scopes_only: bool) -> Option<Vec<u8>> {
    let mut out = vec![0; 64];
    let n = wire::header(id, &mut out)?;
    out.truncate(n);
    for (_, _, row) in records(devices, live_scopes_only, true) {
        out.extend(row);
    }
    out.extend(wire::END);
    Some(out)
}

fn records(
    devices: &[Device],
    live_scopes_only: bool,
    retained: bool,
) -> Vec<(String, (i64, u32), Vec<u8>)> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let mut rows = Vec::new();
    for device in devices {
        let Some(record) = device.record.as_deref() else {
            continue;
        };
        for (bearer, facts) in &device.observations {
            if live_scopes_only
                && bearer == crate::BEARER_UDP
                && device
                    .udp_sender
                    .is_some_and(|p| !crate::interfaces::has_live_scope(&p))
            {
                continue;
            }
            let mut row = Observation::new(record, bearer);
            // Only an actual six-byte colon-separated radio address is a MAC.
            let mac: Option<Vec<u8>> = facts
                .last_peer
                .split(':')
                .map(|b| {
                    if b.len() == 2 {
                        u8::from_str_radix(b, 16).ok()
                    } else {
                        None
                    }
                })
                .collect();
            row.peer = mac.and_then(|m| m.try_into().ok());
            row.rssi_dbm = facts.last_rssi_dbm;
            row.channel = facts.last_channel;
            row.last_seen_ms = (facts.last_seen_ms>0).then(||u64::try_from(facts.last_seen_ms).ok()).flatten();
            row.age_ms = row.last_seen_ms.map(|t| now.saturating_sub(t));
            row.retained = retained;
            if let Some(via) = device.crawled_via.get(bearer) {
                row.origin = Origin::Crawled;
                row.via = Some(via);
            }
            let mut out = vec![0; record.len() + 256];
            if let Some(n) = row.encode(&mut out) {
                out.truncate(n);
                rows.push((
                    format!("{}:{bearer}", device.id),
                    (facts.last_seen_ms, facts.packets),
                    out,
                ));
            }
        }
    }
    rows
}

/// Incremental byte producer for `discovery.nodes`, emitting retained rows
/// (when requested), polling live updates until `options.duration_ms` elapses,
/// and terminating with [`wire::END`].
pub struct NodesSource {
    engine: Arc<crate::Engine>,
    until: Instant,
    next_poll: Instant,
    scopes: bool,
    seen: BTreeMap<String, (i64, u32)>,
    ready: std::collections::VecDeque<Vec<u8>>,
    current: Vec<u8>,
    position: usize,
    ended: bool,
    closing: bool,
}
impl NodesSource {
    pub fn new(engine: Arc<crate::Engine>, options: Options, scopes: bool) -> Self {
        let now = Instant::now();
        let mut source = Self {
            engine,
            until: now + Duration::from_millis(options.duration_ms as u64),
            next_poll: now,
            scopes,
            seen: BTreeMap::new(),
            ready: Default::default(),
            current: Vec::new(),
            position: 0,
            ended: false,
            closing: false,
        };
        for (key, stamp, row) in records(&source.engine.devices(), scopes, true) {
            source.seen.insert(key, stamp);
            if options.retained {
                source.ready.push_back(row);
            }
        }
        source
    }
    fn prepare(&mut self) -> bool {
        if self.position < self.current.len() {
            return true;
        }
        self.current = Vec::new();
        self.position = 0;
        if let Some(row) = self.ready.pop_front() {
            self.current = row;
            return true;
        }
        if self.ended {
            return false;
        }
        let now = Instant::now();
        if self.closing {
            self.current = wire::END.to_vec();
            self.ended = true;
            return true;
        }
        self.closing = now >= self.until;
        if !self.closing && now < self.next_poll {
            return false;
        }
        self.next_poll = now + Duration::from_millis(50);
        for (key, stamp, row) in records(&self.engine.devices(), self.scopes, false) {
            if self.seen.insert(key, stamp) != Some(stamp) {
                self.ready.push_back(row);
            }
        }
        if let Some(row) = self.ready.pop_front() {
            self.current = row;
            true
        } else if self.closing {
            self.current = wire::END.to_vec();
            self.ended = true;
            true
        } else {
            false
        }
    }

    /// Borrow the next ready bytes without advancing `position`.
    ///
    /// Returns:
    /// - `Some(slice)` with `!slice.is_empty()` when bytes are ready to send;
    /// - `None` when either waiting for new observations (`!is_done()`) or
    ///   completely finished (`is_done()`).
    pub fn peek_chunk(&mut self) -> Option<&[u8]> {
        if !self.prepare() {
            return None;
        }
        Some(&self.current[self.position..])
    }

    /// Advance past `accepted` bytes from [`Self::peek_chunk`].
    ///
    /// Returns `false` if `accepted` exceeds the remaining bytes of the
    /// current record.
    pub fn consume(&mut self, accepted: usize) -> bool {
        let remaining = self.current.len().saturating_sub(self.position);
        if accepted > remaining {
            return false;
        }
        self.position += accepted;
        true
    }

    /// Whether the final [`wire::END`] sentinel has been completely consumed.
    pub fn is_done(&self) -> bool {
        self.ended && self.position >= self.current.len()
    }

    /// Fill `out` and return `(count, done)`. `(0, false)` means no bytes are
    /// available yet; `done` means the final [`wire::END`] byte was included.
    pub fn read(&mut self, out: &mut [u8]) -> (usize, bool) {
        if !self.prepare() {
            return (0, self.ended);
        }
        let n = out.len().min(self.current.len() - self.position);
        out[..n].copy_from_slice(&self.current[self.position..self.position + n]);
        self.position += n;
        (n, self.ended && self.position == self.current.len())
    }
}

/// Write a `discovery.nodes` response stream (header, retained/live rows, and
/// [`wire::END`]) directly to an asynchronous writer and close its write half.
#[cfg(feature = "tokio")]
pub async fn serve_stream<S>(
    engine: Arc<crate::Engine>,
    id: u64,
    options: Options,
    live_scopes_only: bool,
    stream: &mut S,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin + ?Sized,
{
    use tokio::io::AsyncWriteExt;
    let Some((header, mut source)) = open_stream(engine, id, options, live_scopes_only) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "failed to encode discovery.nodes header",
        ));
    };
    stream.write_all(&header).await?;
    while !source.is_done() {
        if let Some(chunk) = source.peek_chunk() {
            let n = chunk.len();
            stream.write_all(chunk).await?;
            source.consume(n);
        } else {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    stream.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Carrier, Engine, NoFacts, P256Identity, UnsignedIdentity, announce,
        discovery::DiscoveryPacketKind,
    };
    use mesh_api::cbor::Decoder;
    fn engine() -> Arc<Engine> {
        Arc::new(Engine::new(
            Arc::new(UnsignedIdentity::from_seed(b"observer")),
            Arc::new(NoFacts),
        ))
    }
    fn signed() -> Vec<u8> {
        Engine::new(Arc::new(P256Identity::generate()), Arc::new(NoFacts))
            .announce_wire()
            .unwrap()
    }
    fn items(bytes: &[u8]) -> Vec<Observation<'_>> {
        let mut d = Decoder::new(bytes);
        let mut rows = Vec::new();
        while !d.is_finished() {
            let at = d.position();
            d.skip().unwrap();
            let item = &bytes[at..d.position()];
            if item == wire::END {
                assert!(d.is_finished());
                break;
            }
            rows.push(Observation::decode(item).unwrap());
        }
        rows
    }
    fn drain(source: &mut NodesSource) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut small = [0; 13];
        loop {
            let (n, done) = source.read(&mut small);
            bytes.extend_from_slice(&small[..n]);
            if done {
                break;
            }
            assert!(n > 0, "test deadline must have elapsed");
        }
        bytes
    }
    #[test]
    fn retained_rows_preserve_original_signed_bytes_per_bearer_and_complete() {
        let engine = engine();
        let signed = signed();
        engine.on_datagram(
            &Carrier::radio(
                "nan",
                "02:02:02:02:02:02",
                DiscoveryPacketKind::ActivePublish,
            ),
            &signed,
        );
        engine.on_datagram(
            &Carrier::udp("[fe80::1%3]:3339", "[fe80::1%3]:3339".parse().unwrap()),
            &signed,
        );
        let response = response(&engine.devices(), 42, false).unwrap();
        let mut d = Decoder::new(&response);
        d.skip().unwrap();
        assert!(wire::is_header(
            mesh_api::envelope::decode(&response[..d.position()]).unwrap()
        ));
        let rows = items(&response[d.position()..]);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].record, signed);
        assert_eq!(rows[1].record, signed);
        assert!(rows.iter().all(|r| r.retained
            && r.origin == Origin::Direct
            && r.last_seen_ms.is_some()
            && r.age_ms.is_some()));
        assert!(
            rows.iter()
                .any(|r| r.bearer == "nan" && r.peer == Some([2; 6]))
        );
        assert!(
            rows.iter()
                .any(|r| r.bearer == crate::BEARER_UDP && r.peer.is_none())
        );
        assert!(announce::verify_identity(
            announce::decode_announce(rows[0].record).unwrap()
        ));
    }
    #[test]
    fn live_stream_does_not_replay_old_rows_and_closing_collects_updates() {
        let engine = engine();
        let first = signed();
        let fresh = signed();
        let carrier = Carrier::radio(
            "nan",
            "02:02:02:02:02:02",
            DiscoveryPacketKind::ActivePublish,
        );
        engine.on_datagram(&carrier, &first);
        let mut source = NodesSource::new(
            engine.clone(),
            Options {
                duration_ms: 5000,
                retained: false,
                active: false,
            },
            false,
        );
        engine.on_datagram(&carrier, &fresh);
        source.until = Instant::now();
        let bytes = drain(&mut source);
        let rows = items(&bytes);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].record, fresh);
        assert!(!rows[0].retained);
    }
    #[test]
    fn crawl_provenance_is_unsigned_and_cannot_replace_a_direct_observation() {
        let engine = engine();
        let raw = signed();
        let observer = [9; 8];
        let mut row = Observation::new(&raw, "nan");
        row.peer = Some([2; 6]);
        row.rssi_dbm = Some(-80);
        assert!(engine.observe_crawled(&observer, &row));
        let data = response(&engine.devices(), 1, false).unwrap();
        let mut d = Decoder::new(&data);
        d.skip().unwrap();
        let rows = items(&data[d.position()..]);
        assert_eq!(rows[0].origin, Origin::Crawled);
        assert_eq!(rows[0].via, Some(&observer[..]));
        engine.on_datagram(
            &Carrier::radio(
                "nan",
                "02:02:02:02:02:02",
                DiscoveryPacketKind::ActivePublish,
            ),
            &raw,
        );
        assert!(!engine.observe_crawled(&observer, &row));
        assert!(engine.devices()[0].crawled_via.is_empty());
    }
    #[test]
    fn compact_unsigned_sightings_do_not_discard_the_last_verified_signature() {
        let engine = engine();
        let raw = signed();
        let carrier = Carrier::radio(
            "nan",
            "02:02:02:02:02:02",
            DiscoveryPacketKind::ActivePublish,
        );
        engine.on_datagram(&carrier, &raw);
        let mut hint = announce::decode_announce(&raw).unwrap();
        hint.public_key_len = 0;
        hint.signature_len = 0;
        hint.uptime_secs += 1;
        let mut encoded = [0; 512];
        let n = announce::encode(hint, &mut encoded).unwrap();
        engine.on_datagram(&carrier, &encoded[..n]);
        let devices = engine.devices();
        assert!(devices[0].authenticated);
        assert_eq!(devices[0].record.as_deref(), Some(raw.as_slice()));
    }

    #[test]
    fn crawling_an_expired_record_does_not_refresh_its_last_seen_time() {
        let engine=engine();let raw=signed();let mut row=Observation::new(&raw,"nan");
        row.age_ms=Some(3_601_000);
        assert!(engine.observe_crawled(&[9;8],&row));
        assert!(engine.devices().is_empty());
    }

    #[test]
    fn transport_refusal_keeps_the_same_record_and_byte_position() {
        let engine = engine();
        let raw = signed();
        engine.on_datagram(
            &Carrier::radio(
                "nan",
                "02:02:02:02:02:02",
                DiscoveryPacketKind::ActivePublish,
            ),
            &raw,
        );
        let mut source = NodesSource::new(
            engine,
            Options {
                duration_ms: 0,
                ..Options::default()
            },
            false,
        );
        let first_ptr = source.peek_chunk().unwrap().as_ptr() as usize;
        assert_eq!(source.position, 0);
        assert_eq!(source.current.as_ptr() as usize, first_ptr);
        let bytes = drain(&mut source);
        assert_eq!(items(&bytes).len(), 1);
        assert!(source.is_done());
    }
}
