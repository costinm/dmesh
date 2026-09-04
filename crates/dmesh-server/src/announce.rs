//! Small, bearer-neutral device presence records.
//!
//! An announce is a direct tagged-CBOR record, so exactly the same bytes can
//! travel in UART, a NAN Service Info field, a NOW action, or an IPv6 UDP
//! datagram. The tagged envelope has no separate public-key slot: the current
//! optional P-256 key and signature are fields of this CBOR body. This is a
//! temporary layout; a later signed envelope may carry the key/signature
//! outside the announce body. Platform key storage and signing implementations
//! remain outside this bearer-neutral module.

use crate::{
    cbor::{Decoder, Encoder},
    tagged::{Name, Record, decode},
};
use sha2::{Digest, Sha256};

/// Tagged component reserved for one-way presence records.
pub const ANNOUNCE_COMPONENT: u64 = 6;
pub const ANNOUNCE_DISCOVERY: u64 = 2;
/// Local request/response for bounded observation caches, not a broadcast.
pub const ANNOUNCE_OBSERVED: u64 = 3;
/// Local request/response for bounded DMesh NAN Follow-up receipts.
pub const ANNOUNCE_FOLLOWUPS_OBSERVED: u64 = 4;
/// Local request/response for the unified per-peer discovery observation
/// list. Unlike [`ANNOUNCE_OBSERVED`], entries may be provisional radio peers
/// without a decoded DMesh announce identity.
pub const ANNOUNCE_DEVICES_OBSERVED: u64 = 9;
/// Transition markers use the same presence schema so every bearer can carry
/// timing evidence without inventing a UART-only event format.
pub const ANNOUNCE_TRANSITION_BEGIN: u64 = 5;
pub const ANNOUNCE_SLEEP_PENDING: u64 = 6;
pub const ANNOUNCE_TRANSITION_COMPLETE: u64 = 7;
pub const ANNOUNCE_WAKE: u64 = 8;

const FIELD_DEVICE_ID: u64 = 1;
const FIELD_UPTIME_SECS: u64 = 2;
/// Optional producer class for discovery-driven control-plane selection.
/// `0` deliberately means legacy/unknown so existing records remain valid.
pub const FIELD_DEVICE_CLASS: u64 = 7;
/// Optional supported probe-feature bit set.  The values are shared with
/// `probe::PROBE_CAP_*`; absence means the control plane must use a local
/// descriptor override or decline capability-dependent rows.
pub const FIELD_PROBE_CAPABILITIES: u64 = 8;
pub const DEVICE_CLASS_UNKNOWN: u8 = 0;
pub const DEVICE_CLASS_ESP: u8 = 1;
pub const DEVICE_CLASS_HOST: u8 = 2;
pub const DEVICE_CLASS_ANDROID: u8 = 3;
/// Optional compressed SEC1 P-256 public key in the announce CBOR body. This
/// is not an envelope key. It is retained temporarily for signed announces;
/// the intended compact form is a VIP/identity-hint-only announce, with the
/// public key retrieved in a directed Follow-up when the receiver lacks it.
pub const FIELD_PUBLIC_KEY: u64 = 5;
/// Optional fixed-width raw signature over [`signing_bytes`].
pub const FIELD_SIGNATURE: u64 = 6;
/// Optional short human-facing display name. It is not an identity claim;
/// certificates will later supply a verified FQDN.
pub const FIELD_DEVICE_NAME: u64 = 9;
/// Optional current STA network name. This is discovery routing metadata, not
/// an identity or trust assertion. It lets two peers explicitly select their
/// common UDP6 bearer instead of guessing from a NAN observation.
pub const FIELD_NETWORK_NAME: u64 = 10;
/// Optional IPv6 link-local endpoint for the active STA bearer.  This is
/// routing metadata only; a scoped interface is still required by the local
/// sender when it uses the address.
pub const FIELD_STA_LINK_LOCAL_V6: u64 = 11;
/// Current Wi-Fi channel for the announcing radio. This is routing metadata:
/// a receiver uses it to decide whether channel-bound NAN/NOW is relevant,
/// while a shared STA/AP network still selects UDP6.
pub const FIELD_WIFI_CHANNEL: u64 = 13;
/// UDP/QUIC listener port for the advertised IPv6 endpoint. The source
/// address and scope come from the received multicast datagram; this field
/// distinguishes co-located services such as lmesh (3337) and lmesh-wifi
/// (3336) without inventing a second host identity.
pub const FIELD_UDP_PORT: u64 = 14;
/// IPv6 link-local address paired with [`FIELD_UDP_PORT`]. The receiver keeps
/// its own interface scope as ingress metadata; it is never serialized.
pub const FIELD_UDP_LINK_LOCAL_V6: u64 = 15;
/// Optional DNS suffix paired with the compact device label. The two fields
/// avoid bloating NAN Service Info while still allowing an FQDN identity.
pub const FIELD_DEVICE_DOMAIN: u64 = 16;
const MAX_DEVICE_ID: usize = 16;
pub const MAX_PUBLIC_KEY: usize = 128;
pub const SIGNATURE_LEN: usize = 64;
pub const MAX_DEVICE_NAME: usize = 8;
pub const MAX_DEVICE_DOMAIN: usize = 16;
pub const MAX_NETWORK_NAME: usize = 32;

/// Number of SHA-256 prefix bytes used as the compact cross-bearer identity
/// hint.
///
/// NAN announcements carry `SHA-256(public_key)[..IDENTITY_HINT_LEN]`. VIP6
/// copies exactly those same bytes into its low 64 bits; neither uses a digest
/// suffix. This invariant lets a NAN receipt correlate with a UDP announce
/// without exposing an implementation-specific device ID to users.
pub const IDENTITY_HINT_LEN: usize = 8;

/// Compact SHA-256 prefix shared verbatim by NAN observations and the low 64
/// bits of the virtual IPv6 address. This is the future always-present
/// identity material when public keys move out of broadcasts and into directed
/// Follow-up key retrieval.
pub fn identity_hint(public_key: &[u8]) -> Option<[u8; IDENTITY_HINT_LEN]> {
    if public_key.is_empty() {
        return None;
    }
    let digest = Sha256::digest(public_key);
    let mut hint = [0u8; IDENTITY_HINT_LEN];
    hint.copy_from_slice(&digest[..IDENTITY_HINT_LEN]);
    Some(hint)
}

/// Reconstruct a VIP6 from the compact NAN identity hint.
pub fn virtual_ip6_from_identity_hint(hint: &[u8]) -> Option<[u8; 16]> {
    if hint.len() != IDENTITY_HINT_LEN {
        return None;
    }
    let mut address = [0u8; 16];
    address[0] = 0xfc;
    address[8..].copy_from_slice(hint);
    Some(address)
}

/// Stable virtual IPv6 address for a public-key mesh identity.
///
/// The `fc00::/8` prefix identifies the DMesh virtual-address space; its low
/// 64 bits are the shared compact SHA-256 identity hint.
/// It is an overlay identity, not a claimed LAN address, and is therefore
/// absent for unsigned discovery observations.
pub fn virtual_ip6(public_key: &[u8]) -> Option<[u8; 16]> {
    virtual_ip6_from_identity_hint(&identity_hint(public_key)?)
}

/// Bounded presence information common to every radio bearer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Announce {
    /// Presence/lifecycle event. `BOOT` and `DISCOVERY` mean the producer is
    /// present; the transition values bracket ESP sleep/wake work. It is not
    /// a bearer or discovery-method selector. ESP, Linux, and Android all
    /// populate it. Example: an ESP emits `BOOT` after reset and
    /// `SLEEP_PENDING` before planned sleep.
    pub kind: u64,
    /// Stable compact SHA-256 prefix of `public_key`, also carried by short
    /// NAN/NOW observations and used in the virtual IPv6 address. It is not a
    /// second identity key. Long-term, this is the broadcast identity and a
    /// receiver fetches an unknown public key through a directed Follow-up.
    /// Example: the same eight bytes correlate a NAN receipt and UDP6 record.
    pub device_id: [u8; MAX_DEVICE_ID],
    pub device_id_len: u8,
    /// ESP uses its running timer; Linux/Android use their announce/runtime
    /// clock. Receivers treat it as producer-relative only. Example: a lower
    /// value after a prior observation indicates an ESP reboot.
    pub uptime_secs: u32,
    /// ESP and Linux populate their producer class/capabilities; Android may
    /// leave both at the backwards-compatible unknown/zero values. Example:
    /// `DEVICE_CLASS_ESP` rules out an Android-only probe row.
    pub device_class: u8,
    /// Shared `probe::PROBE_CAP_*` capability set, or zero for legacy peers.
    /// Example: `PROBE_CAP_NOW` permits an ESP-NOW probe to be scheduled.
    pub probe_capabilities: u16,
    /// Compressed SEC1 P-256 public key, encoded once as CBOR field 5 inside
    /// this announce—not separately in the tagged envelope. The signature
    /// covers a transient canonical CBOR form containing this field and
    /// omitting only the signature itself. This layout may change to a normal
    /// signed envelope with key/signature outside the announce body. Future
    /// size reduction: omit both key and broadcast signature; retain the
    /// identity hint and fetch an unknown key through a directed Follow-up.
    /// Example: a Linux receiver verifies a current broadcast with this SEC1
    /// point before caching it.
    pub public_key: [u8; MAX_PUBLIC_KEY],
    pub public_key_len: u8,
    /// P1363 ECDSA P-256 signature over [`signing_bytes`]. Current ESP,
    /// Linux, and Android populate it with their local private key. Example:
    /// its matching public key validates a received UDP6 announce.
    pub signature: [u8; SIGNATURE_LEN],
    pub signature_len: u8,
    /// ESP populates the catalog provisioned label; Linux uses a compact
    /// hostname; Android currently leaves it absent. Example: `e6` combines
    /// with `test.webinf.info` as display name `e6.test.webinf.info`.
    pub device_name: [u8; MAX_DEVICE_NAME],
    pub device_name_len: u8,
    /// ESP loads its provisioned suffix; Linux and Android populate it from
    /// `DMESH_DISCOVERY_DOMAIN` when set. Example: `test.webinf.info` pairs
    /// with the provisioned ESP label `e6`.
    pub device_domain: [u8; MAX_DEVICE_DOMAIN],
    pub device_domain_len: u8,
    /// Current associated Wi-Fi SSID, when the platform can obtain it. It is
    /// routing metadata only, never an identity or trust assertion. Example:
    /// peers both on `lab-wifi` may select their common UDP6 bearer.
    pub network_name: [u8; MAX_NETWORK_NAME],
    pub network_name_len: u8,
    /// ESP reports the current radio channel; Linux and Android currently omit
    /// it because their announced UDP link is interface-scoped instead.
    /// Example: a NOW receiver can determine whether channel 6 is usable.
    pub wifi_channel: u8,
    /// ESP reports the active STA endpoint; Android reports the multicast
    /// interface endpoint. Linux currently uses `udp_link_local_v6` instead.
    /// Example: an ESP STA peer provides `fe80::...` for a directed reply.
    pub sta_link_local_v6: [u8; 16],
    pub sta_link_local_v6_present: bool,
    /// Linux and Android advertise their UDP listener and interface endpoint;
    /// ESP currently omits this until its UDP control listener is exposed.
    /// Example: port 3336 distinguishes `lmesh-wifi` from another local
    /// service sharing the same link-local address.
    pub udp_port: u16,
    /// IPv6 link-local address paired with `udp_port`; the receiver retains
    /// its ingress interface scope. Example: Android advertises its Wi-Fi
    /// address without serializing Android's interface name.
    pub udp_link_local_v6: [u8; 16],
    pub udp_link_local_v6_present: bool,
}

/// Typed entry in a local announce-observation cache.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedAnnounce<'a> {
    pub device_id: &'a [u8],
    pub source_mac: [u8; 6],
    pub source_ip: &'a [u8],
    pub uptime_secs: u32,
    pub kind: u8,
    pub last_seen_ms: u32,
}

/// Small fixed diagnostic view of a received directed NAN Follow-up. Payload
/// bytes remain in the local bounded cache; the response carries a hash/size
/// so ten receipts fit in the common 1100-byte transport MTU.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedFollowup {
    pub source: [u8; 6],
    pub target: [u8; 6],
    pub msg_type: u8,
    pub seq: u16,
    pub payload_len: u16,
    pub payload_hash: u32,
    pub last_seen_ms: u32,
}

/// Compact, bearer-neutral device-list observation. `device_id` is empty when
/// the adapter has only a provisional radio peer. `peer` remains local
/// adapter state for correlation/reply routing; it is intentionally not
/// encoded in the presentation response because platform peer handles are
/// not interchangeable DMesh identities.  `available_fields` is accompanied
/// on the wire by its explicit complement, so a compact firmware response
/// has the same "unavailable, not zero" meaning as Android/Linux JSON.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedDevice<'a> {
    pub device_id: &'a [u8],
    pub peer: [u8; 6],
    pub bssid: Option<[u8; 6]>,
    /// Receiver-side channel at which the adapter captured the observation.
    /// It is omitted when the adapter cannot report one.
    pub channel: Option<u8>,
    pub available_fields: u32,
    pub first_seen_ms: u32,
    pub last_seen_ms: u32,
    pub packets: u32,
    pub active_publish_rx: u32,
    pub active_subscribe_rx: u32,
    pub followup_rx: u32,
    pub last_kind: u8,
    pub last_payload_len: u16,
    pub last_payload_hash: u32,
}

impl Announce {
    pub const fn discovery(
        device_id: [u8; MAX_DEVICE_ID],
        device_id_len: u8,
        uptime_secs: u32,
    ) -> Self {
        Self {
            kind: ANNOUNCE_DISCOVERY,
            device_id,
            device_id_len,
            uptime_secs,
            device_class: DEVICE_CLASS_UNKNOWN,
            probe_capabilities: 0,
            public_key: [0; MAX_PUBLIC_KEY],
            public_key_len: 0,
            signature: [0; SIGNATURE_LEN],
            signature_len: 0,
            device_name: [0; MAX_DEVICE_NAME],
            device_name_len: 0,
            device_domain: [0; MAX_DEVICE_DOMAIN],
            device_domain_len: 0,
            network_name: [0; MAX_NETWORK_NAME],
            network_name_len: 0,
            wifi_channel: 0,
            sta_link_local_v6: [0; 16],
            sta_link_local_v6_present: false,
            udp_port: 0,
            udp_link_local_v6: [0; 16],
            udp_link_local_v6_present: false,
        }
    }

    pub fn device_id(&self) -> &[u8] {
        &self.device_id[..usize::from(self.device_id_len).min(MAX_DEVICE_ID)]
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key[..usize::from(self.public_key_len).min(MAX_PUBLIC_KEY)]
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature[..usize::from(self.signature_len).min(SIGNATURE_LEN)]
    }

    pub fn device_name(&self) -> Option<&str> {
        core::str::from_utf8(
            &self.device_name[..usize::from(self.device_name_len).min(MAX_DEVICE_NAME)],
        )
        .ok()
        .filter(|name| !name.is_empty())
    }

    pub fn device_domain(&self) -> Option<&str> {
        core::str::from_utf8(
            &self.device_domain[..usize::from(self.device_domain_len).min(MAX_DEVICE_DOMAIN)],
        )
        .ok()
        .filter(|domain| !domain.is_empty())
    }

    pub fn network_name(&self) -> Option<&str> {
        core::str::from_utf8(
            &self.network_name[..usize::from(self.network_name_len).min(MAX_NETWORK_NAME)],
        )
        .ok()
        .filter(|name| !name.is_empty())
    }

    pub fn sta_link_local_v6(&self) -> Option<[u8; 16]> {
        self.sta_link_local_v6_present
            .then_some(self.sta_link_local_v6)
    }

    pub fn set_sta_link_local_v6(&mut self, address: [u8; 16]) {
        self.sta_link_local_v6 = address;
        self.sta_link_local_v6_present = true;
    }

    /// Advertise a normal UDP/QUIC listener. The port is meaningful only
    /// together with a received UDP6 source address and network name.
    pub fn set_udp_port(&mut self, port: u16) {
        self.udp_port = port;
    }

    /// Set the IPv6 address paired with [`Self::udp_port`]. It deliberately
    /// excludes a scope/interface: scope is chosen by each receiver.
    pub fn set_udp_link_local_v6(&mut self, address: [u8; 16]) {
        self.udp_link_local_v6 = address;
        self.udp_link_local_v6_present = true;
    }

    pub fn udp_link_local_v6(&self) -> Option<[u8; 16]> {
        self.udp_link_local_v6_present
            .then_some(self.udp_link_local_v6)
    }

    pub fn has_identity(&self) -> bool {
        !self.public_key().is_empty() && !self.signature().is_empty()
    }

    /// Attach optional discovery-only selection metadata.  It is not a trust
    /// assertion: signed hosts still require their existing key/signature and
    /// unsigned records remain hints until the control exchange succeeds.
    pub fn set_probe_descriptor(&mut self, device_class: u8, probe_capabilities: u16) {
        self.device_class = device_class;
        self.probe_capabilities = probe_capabilities;
    }

    /// Attach a host/Android public key before calculating its signature.
    pub fn set_public_key(&mut self, public_key: &[u8]) -> bool {
        if public_key.is_empty() || public_key.len() > MAX_PUBLIC_KEY {
            return false;
        }
        self.public_key.fill(0);
        self.public_key[..public_key.len()].copy_from_slice(public_key);
        self.public_key_len = public_key.len() as u8;
        true
    }

    pub fn set_signature(&mut self, signature: &[u8]) -> bool {
        if signature.len() != SIGNATURE_LEN {
            return false;
        }
        self.signature.copy_from_slice(signature);
        self.signature_len = SIGNATURE_LEN as u8;
        true
    }

    /// Set bounded UI metadata. It must never be used for authorization or
    /// peer identity.
    pub fn set_device_name(&mut self, name: &str) -> bool {
        if name.is_empty() || name.len() > MAX_DEVICE_NAME {
            return false;
        }
        self.device_name.fill(0);
        self.device_name[..name.len()].copy_from_slice(name.as_bytes());
        self.device_name_len = name.len() as u8;
        true
    }

    /// Set the bounded suffix paired with [`Self::device_name`]. It is display
    /// metadata carried in the same signed announce, not an authorization
    /// domain.
    pub fn set_device_domain(&mut self, domain: &str) -> bool {
        if domain.is_empty() || domain.len() > MAX_DEVICE_DOMAIN {
            return false;
        }
        self.device_domain.fill(0);
        self.device_domain[..domain.len()].copy_from_slice(domain.as_bytes());
        self.device_domain_len = domain.len() as u8;
        true
    }

    /// Set current local-link routing metadata. This may be omitted whenever
    /// the platform cannot establish a STA attachment or reveal its SSID.
    pub fn set_network_name(&mut self, name: &str) -> bool {
        if name.is_empty() || name.len() > MAX_NETWORK_NAME {
            return false;
        }
        self.network_name.fill(0);
        self.network_name[..name.len()].copy_from_slice(name.as_bytes());
        self.network_name_len = name.len() as u8;
        true
    }

    /// Set the current Wi-Fi channel. Zero clears an unavailable channel.
    pub fn set_wifi_channel(&mut self, channel: u8) -> bool {
        if channel != 0 && !(1..=13).contains(&channel) {
            return false;
        }
        self.wifi_channel = channel;
        true
    }
}

/// Encode one unsolicited announce into the common direct-record envelope.
///
/// The same signed record is used by every bearer. For a selected-neighbor
/// reply use [`encode_discovery_response`] so the requester can correlate it
/// without inventing a ping or boot-identity record.
pub fn encode(announce: Announce, out: &mut [u8]) -> Option<usize> {
    encode_inner(announce, true, None, out)
}

/// Encode an empty directed-discovery request.
///
/// The physical bearer selects the peer; the CBOR envelope deliberately has
/// no `to` field because the same bytes also travel in UART and NAN follow-up
/// paths. A valid response is a signed [`ANNOUNCE_DISCOVERY`] record with this
/// request ID, encoded by [`encode_discovery_response`].
pub fn encode_discovery_request(id: u64, out: &mut [u8]) -> Option<usize> {
    let mut e = Encoder::new(out);
    e.map(4)?;
    e.uint(1)?;
    e.uint(ANNOUNCE_COMPONENT)?;
    e.uint(2)?;
    e.uint(ANNOUNCE_DISCOVERY)?;
    e.uint(3)?;
    e.uint(id)?;
    e.uint(5)?;
    e.map(0)?;
    Some(e.len())
}

/// True only for a canonical directed-discovery request.
pub fn discovery_request_id(packet: &[u8]) -> Option<u64> {
    let record = decode(packet)?;
    if record.to.is_some()
        || record.component != Some(Name::Tag(ANNOUNCE_COMPONENT))
        || record.method != Some(Name::Tag(ANNOUNCE_DISCOVERY))
    {
        return None;
    }
    let id = record.id?;
    let mut fields = Decoder::new(record.fields?);
    if !matches!(fields.head(), Some((5, 0))) || !fields.is_finished() {
        return None;
    }
    Some(id)
}

/// Encode a correlated signed response to [`encode_discovery_request`].
///
/// Only the discovery announce kind can be used as a directed reply. This
/// keeps unsolicited and directed discovery one record type rather than
/// preserving a parallel boot/ping identity protocol.
pub fn encode_discovery_response(announce: Announce, id: u64, out: &mut [u8]) -> Option<usize> {
    if announce.kind != ANNOUNCE_DISCOVERY {
        return None;
    }
    encode_inner(announce, true, Some(id), out)
}

/// Transient canonical CBOR bytes signed by an identified announce. They
/// include the public-key field but omit the signature field itself; only
/// [`encode`] emits the final key-plus-signature wire record.
pub fn signing_bytes(announce: Announce, out: &mut [u8]) -> Option<usize> {
    if announce.public_key_len == 0 {
        None
    } else {
        encode_inner(announce, false, None, out)
    }
}

fn encode_inner(
    announce: Announce,
    include_signature: bool,
    id: Option<u64>,
    out: &mut [u8],
) -> Option<usize> {
    let device_id = announce.device_id();
    if device_id.is_empty() {
        return None;
    }
    let has_key = !announce.public_key().is_empty();
    let supplied_signature = !announce.signature().is_empty();
    let has_name = announce.device_name().is_some();
    let has_domain = announce.device_domain().is_some();
    let has_network_name = announce.network_name().is_some();
    let has_wifi_channel = announce.wifi_channel != 0;
    let has_sta_link_local_v6 = announce.sta_link_local_v6_present;
    let has_udp_port = announce.udp_port != 0;
    let has_udp_link_local_v6 = announce.udp_link_local_v6_present;
    // A port is an override, not a prerequisite for advertising a UDP path.
    // The receiver knows the default service port for the announced device
    // class; requiring it here made every default-port ESP path invisible.
    if has_udp_port && !has_udp_link_local_v6 {
        return None;
    }
    // Canonical signing bytes deliberately omit field 6 even after a
    // signature has been attached. Only the full wire form requires key and
    // signature to appear together; otherwise verification of a decoded
    // signed announce can never reconstruct the signed bytes.
    if (include_signature && supplied_signature != has_key)
        || (!include_signature && supplied_signature && !has_key)
    {
        return None;
    }
    let has_signature = include_signature && supplied_signature;
    let mut e = Encoder::new(out);
    e.map(if id.is_some() { 4 } else { 3 })?;
    e.uint(1)?;
    e.uint(ANNOUNCE_COMPONENT)?;
    e.uint(2)?;
    e.uint(announce.kind)?;
    if let Some(id) = id {
        e.uint(3)?;
        e.uint(id)?;
    }
    e.uint(5)?;
    let has_descriptor =
        announce.device_class != DEVICE_CLASS_UNKNOWN || announce.probe_capabilities != 0;
    e.map(
        2 + u64::from(has_key)
            + u64::from(has_signature)
            + 2 * u64::from(has_descriptor)
            + u64::from(has_name)
            + u64::from(has_domain)
            + u64::from(has_network_name)
            + u64::from(has_wifi_channel)
            + u64::from(has_sta_link_local_v6)
            + u64::from(has_udp_port)
            + u64::from(has_udp_link_local_v6),
    )?;
    e.uint(FIELD_DEVICE_ID)?;
    e.bytes_value(device_id)?;
    e.uint(FIELD_UPTIME_SECS)?;
    e.uint(u64::from(announce.uptime_secs))?;
    if has_descriptor {
        e.uint(FIELD_DEVICE_CLASS)?;
        e.uint(u64::from(announce.device_class))?;
        e.uint(FIELD_PROBE_CAPABILITIES)?;
        e.uint(u64::from(announce.probe_capabilities))?;
    }
    if has_key {
        e.uint(FIELD_PUBLIC_KEY)?;
        e.bytes_value(announce.public_key())?;
    }
    if has_signature {
        e.uint(FIELD_SIGNATURE)?;
        e.bytes_value(announce.signature())?;
    }
    if has_name {
        e.uint(FIELD_DEVICE_NAME)?;
        e.bytes_value(announce.device_name().expect("checked above").as_bytes())?;
    }
    if has_domain {
        e.uint(FIELD_DEVICE_DOMAIN)?;
        e.bytes_value(announce.device_domain().expect("checked above").as_bytes())?;
    }
    if has_network_name {
        e.uint(FIELD_NETWORK_NAME)?;
        e.bytes_value(announce.network_name().expect("checked above").as_bytes())?;
    }
    if has_wifi_channel {
        e.uint(FIELD_WIFI_CHANNEL)?;
        e.uint(u64::from(announce.wifi_channel))?;
    }
    if has_sta_link_local_v6 {
        e.uint(FIELD_STA_LINK_LOCAL_V6)?;
        e.bytes_value(&announce.sta_link_local_v6)?;
    }
    if has_udp_port {
        e.uint(FIELD_UDP_PORT)?;
        e.uint(u64::from(announce.udp_port))?;
    }
    if has_udp_link_local_v6 {
        e.uint(FIELD_UDP_LINK_LOCAL_V6)?;
        e.bytes_value(&announce.udp_link_local_v6)?;
    }
    Some(e.len())
}

/// Decode a local announce. Directed records are not presence broadcasts.
pub fn decode_announce(packet: &[u8]) -> Option<Announce> {
    let record = decode(packet)?;
    (record.to.is_none())
        .then(|| decode_record(record))
        .flatten()
}

/// True only for the canonical empty observation-list request.
pub fn is_observed_request(packet: &[u8]) -> bool {
    is_empty_observation_request(packet, ANNOUNCE_OBSERVED)
}

/// True only for the canonical empty Follow-up receipt-list request.
pub fn is_followups_observed_request(packet: &[u8]) -> bool {
    is_empty_observation_request(packet, ANNOUNCE_FOLLOWUPS_OBSERVED)
}

/// True only for the canonical unified device-observation request.
pub fn is_devices_observed_request(packet: &[u8]) -> bool {
    is_empty_observation_request(packet, ANNOUNCE_DEVICES_OBSERVED)
}

fn is_empty_observation_request(packet: &[u8], method: u64) -> bool {
    let Some(record) = decode(packet) else {
        return false;
    };
    if record.to.is_some()
        || record.component != Some(Name::Tag(ANNOUNCE_COMPONENT))
        || record.method != Some(Name::Tag(method))
    {
        return false;
    }
    let Some(fields) = record.fields else {
        return false;
    };
    let mut fields = Decoder::new(fields);
    matches!(fields.head(), Some((5, 0))) && fields.is_finished()
}

/// Encode the empty, bearer-neutral observation-list request.
pub fn encode_observed_request(out: &mut [u8]) -> Option<usize> {
    encode_empty_observation_request(ANNOUNCE_OBSERVED, out)
}

/// Encode the empty, bearer-neutral Follow-up receipt request.
pub fn encode_followups_observed_request(out: &mut [u8]) -> Option<usize> {
    encode_empty_observation_request(ANNOUNCE_FOLLOWUPS_OBSERVED, out)
}

/// Encode the empty request for the common `discovery.nodes` observation facts.
pub fn encode_devices_observed_request(out: &mut [u8]) -> Option<usize> {
    encode_empty_observation_request(ANNOUNCE_DEVICES_OBSERVED, out)
}

fn encode_empty_observation_request(method: u64, out: &mut [u8]) -> Option<usize> {
    let mut e = Encoder::new(out);
    e.map(3)?;
    e.uint(1)?;
    e.uint(ANNOUNCE_COMPONENT)?;
    e.uint(2)?;
    e.uint(method)?;
    e.uint(5)?;
    e.map(0)?;
    Some(e.len())
}

/// Encode typed cache entries without allocating a per-bearer response.
pub fn encode_observed_response(entries: &[ObservedAnnounce<'_>], out: &mut [u8]) -> Option<usize> {
    let mut e = Encoder::new(out);
    e.map(3)?;
    e.uint(1)?;
    e.uint(ANNOUNCE_COMPONENT)?;
    e.uint(2)?;
    e.uint(ANNOUNCE_OBSERVED)?;
    e.uint(5)?;
    e.map(1)?;
    e.uint(1)?;
    e.array(entries.len() as u64)?;
    for entry in entries {
        e.map(6)?;
        e.uint(1)?;
        e.bytes_value(entry.device_id)?;
        e.uint(2)?;
        e.bytes_value(&entry.source_mac)?;
        e.uint(3)?;
        e.bytes_value(entry.source_ip)?;
        e.uint(4)?;
        e.uint(u64::from(entry.uptime_secs))?;
        e.uint(7)?;
        e.uint(u64::from(entry.kind))?;
        e.uint(8)?;
        e.uint(u64::from(entry.last_seen_ms))?;
    }
    Some(e.len())
}

/// Encode bounded Follow-up receipt metadata without exposing Wi-Fi buffers
/// or overflowing the common control MTU.
pub fn encode_followups_observed_response(
    entries: &[ObservedFollowup],
    out: &mut [u8],
) -> Option<usize> {
    let mut e = Encoder::new(out);
    e.map(3)?;
    e.uint(1)?;
    e.uint(ANNOUNCE_COMPONENT)?;
    e.uint(2)?;
    e.uint(ANNOUNCE_FOLLOWUPS_OBSERVED)?;
    e.uint(5)?;
    e.map(1)?;
    e.uint(1)?;
    e.array(entries.len() as u64)?;
    for entry in entries {
        e.map(7)?;
        e.uint(1)?;
        e.bytes_value(&entry.source)?;
        e.uint(2)?;
        e.bytes_value(&entry.target)?;
        e.uint(3)?;
        e.uint(u64::from(entry.msg_type))?;
        e.uint(4)?;
        e.uint(u64::from(entry.seq))?;
        e.uint(5)?;
        e.uint(u64::from(entry.payload_len))?;
        e.uint(6)?;
        e.uint(u64::from(entry.payload_hash))?;
        e.uint(7)?;
        e.uint(u64::from(entry.last_seen_ms))?;
    }
    Some(e.len())
}

/// Encode bounded receiver observations without retaining or returning raw
/// radio frames. Optional BSSID is omitted when unavailable; its corresponding
/// bit is clear in `available_fields`.
pub fn encode_devices_observed_response(
    entries: &[ObservedDevice<'_>],
    out: &mut [u8],
) -> Option<usize> {
    let mut e = Encoder::new(out);
    e.map(3)?;
    e.uint(1)?;
    e.uint(ANNOUNCE_COMPONENT)?;
    e.uint(2)?;
    e.uint(ANNOUNCE_DEVICES_OBSERVED)?;
    e.uint(5)?;
    e.map(1)?;
    e.uint(1)?;
    e.array(entries.len() as u64)?;
    for entry in entries {
        e.map(12 + u64::from(entry.bssid.is_some()) + u64::from(entry.channel.is_some()))?;
        e.uint(1)?;
        e.bytes_value(entry.device_id)?;
        if let Some(bssid) = entry.bssid {
            e.uint(3)?;
            e.bytes_value(&bssid)?;
        }
        if let Some(channel) = entry.channel {
            e.uint(15)?;
            e.uint(u64::from(channel))?;
        }
        e.uint(4)?;
        e.uint(u64::from(entry.available_fields))?;
        e.uint(5)?;
        e.uint(u64::from(entry.first_seen_ms))?;
        e.uint(6)?;
        e.uint(u64::from(entry.last_seen_ms))?;
        e.uint(7)?;
        e.uint(u64::from(entry.packets))?;
        e.uint(8)?;
        e.uint(u64::from(entry.active_publish_rx))?;
        e.uint(9)?;
        e.uint(u64::from(entry.active_subscribe_rx))?;
        e.uint(10)?;
        e.uint(u64::from(entry.followup_rx))?;
        e.uint(11)?;
        e.uint(u64::from(entry.last_kind))?;
        e.uint(12)?;
        e.uint(u64::from(entry.last_payload_len))?;
        e.uint(13)?;
        e.uint(u64::from(entry.last_payload_hash))?;
        // Keep this explicit rather than requiring a UI to know which bit
        // definitions a particular firmware image supports.  The native
        // peer itself remains deliberately absent.
        e.uint(14)?;
        e.uint(u64::from(
            crate::discovery::OBSERVATION_ALL_FIELDS & !entry.available_fields,
        ))?;
    }
    Some(e.len())
}

pub fn decode_record(record: Record<'_>) -> Option<Announce> {
    if record.component != Some(Name::Tag(ANNOUNCE_COMPONENT)) {
        return None;
    }
    let kind = match record.method? {
        Name::Tag(
            value @ (ANNOUNCE_DISCOVERY
            | ANNOUNCE_TRANSITION_BEGIN
            | ANNOUNCE_SLEEP_PENDING
            | ANNOUNCE_TRANSITION_COMPLETE
            | ANNOUNCE_WAKE),
        ) => value,
        _ => return None,
    };
    let mut d = Decoder::new(record.fields?);
    let (major, count) = d.head()?;
    if major != 5 || count == u64::MAX {
        return None;
    }
    let mut announce = Announce {
        kind,
        device_id: [0; MAX_DEVICE_ID],
        device_id_len: 0,
        uptime_secs: 0,
        device_class: DEVICE_CLASS_UNKNOWN,
        probe_capabilities: 0,
        public_key: [0; MAX_PUBLIC_KEY],
        public_key_len: 0,
        signature: [0; SIGNATURE_LEN],
        signature_len: 0,
        device_name: [0; MAX_DEVICE_NAME],
        device_name_len: 0,
        device_domain: [0; MAX_DEVICE_DOMAIN],
        device_domain_len: 0,
        network_name: [0; MAX_NETWORK_NAME],
        network_name_len: 0,
        wifi_channel: 0,
        sta_link_local_v6: [0; 16],
        sta_link_local_v6_present: false,
        udp_port: 0,
        udp_link_local_v6: [0; 16],
        udp_link_local_v6_present: false,
    };
    for _ in 0..count {
        match d.uint()? {
            FIELD_DEVICE_ID => {
                let id = d.bytes_ref()?;
                if id.is_empty() || id.len() > MAX_DEVICE_ID {
                    return None;
                }
                announce.device_id[..id.len()].copy_from_slice(id);
                announce.device_id_len = id.len() as u8;
            }
            FIELD_UPTIME_SECS => announce.uptime_secs = u32::try_from(d.uint()?).ok()?,
            FIELD_DEVICE_CLASS => announce.device_class = u8::try_from(d.uint()?).ok()?,
            FIELD_PROBE_CAPABILITIES => {
                announce.probe_capabilities = u16::try_from(d.uint()?).ok()?
            }
            FIELD_PUBLIC_KEY => {
                let key = d.bytes_ref()?;
                if key.is_empty() || key.len() > MAX_PUBLIC_KEY || !announce.public_key().is_empty()
                {
                    return None;
                }
                announce.public_key[..key.len()].copy_from_slice(key);
                announce.public_key_len = key.len() as u8;
            }
            FIELD_SIGNATURE => {
                let signature = d.bytes_ref()?;
                if signature.len() != SIGNATURE_LEN || !announce.signature().is_empty() {
                    return None;
                }
                announce.signature.copy_from_slice(signature);
                announce.signature_len = SIGNATURE_LEN as u8;
            }
            FIELD_DEVICE_NAME => {
                let name = d.bytes_ref()?;
                if name.is_empty()
                    || name.len() > MAX_DEVICE_NAME
                    || core::str::from_utf8(name).is_err()
                    || announce.device_name().is_some()
                {
                    return None;
                }
                announce.device_name[..name.len()].copy_from_slice(name);
                announce.device_name_len = name.len() as u8;
            }
            FIELD_DEVICE_DOMAIN => {
                let domain = d.bytes_ref()?;
                if domain.is_empty()
                    || domain.len() > MAX_DEVICE_DOMAIN
                    || core::str::from_utf8(domain).is_err()
                    || announce.device_domain().is_some()
                {
                    return None;
                }
                announce.device_domain[..domain.len()].copy_from_slice(domain);
                announce.device_domain_len = domain.len() as u8;
            }
            FIELD_NETWORK_NAME => {
                let name = d.bytes_ref()?;
                if name.is_empty()
                    || name.len() > MAX_NETWORK_NAME
                    || core::str::from_utf8(name).is_err()
                    || announce.network_name().is_some()
                {
                    return None;
                }
                announce.network_name[..name.len()].copy_from_slice(name);
                announce.network_name_len = name.len() as u8;
            }
            FIELD_WIFI_CHANNEL => {
                if announce.wifi_channel != 0 {
                    return None;
                }
                let channel = u8::try_from(d.uint()?).ok()?;
                if !(1..=13).contains(&channel) {
                    return None;
                }
                announce.wifi_channel = channel;
            }
            FIELD_STA_LINK_LOCAL_V6 => {
                let address: [u8; 16] = d.bytes_ref()?.try_into().ok()?;
                if announce.sta_link_local_v6_present {
                    return None;
                }
                announce.set_sta_link_local_v6(address);
            }
            FIELD_UDP_PORT => {
                if announce.udp_port != 0 {
                    return None;
                }
                let port = u16::try_from(d.uint()?).ok()?;
                if port == 0 {
                    return None;
                }
                announce.set_udp_port(port);
            }
            FIELD_UDP_LINK_LOCAL_V6 => {
                if announce.udp_link_local_v6_present {
                    return None;
                }
                let address: [u8; 16] = d.bytes_ref()?.try_into().ok()?;
                announce.set_udp_link_local_v6(address);
            }
            _ => d.skip()?,
        }
    }
    (announce.device_id_len != 0
        && (announce.public_key_len == 0) == (announce.signature_len == 0)
        && (announce.udp_port == 0 || announce.udp_link_local_v6_present)
        && d.is_finished())
    .then_some(announce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn announce_round_trips_as_one_direct_record() {
        let mut id = [0; MAX_DEVICE_ID];
        id[..6].copy_from_slice(b"e6-c6!");
        let mut announce = Announce::discovery(id, 6, 900);
        announce.set_probe_descriptor(DEVICE_CLASS_ESP, 0x1f);
        assert!(announce.set_device_name("lora-3"));
        assert!(announce.set_device_domain("test.webinf.info"));
        assert!(announce.set_network_name("mesh-test"));
        assert!(announce.set_wifi_channel(6));
        announce.set_udp_port(3336);
        announce.set_udp_link_local_v6("fe80::1234".parse::<Ipv6Addr>().unwrap().octets());
        let mut wire = [0; 128];
        let used = encode(announce, &mut wire).unwrap();
        assert_eq!(decode_announce(&wire[..used]), Some(announce));
    }

    #[test]
    fn directed_discovery_reuses_the_signed_announce_record() {
        let mut request = [0u8; 32];
        let request_len = encode_discovery_request(71, &mut request).unwrap();
        assert_eq!(discovery_request_id(&request[..request_len]), Some(71));
        assert!(decode_announce(&request[..request_len]).is_none());

        let mut id = [0; MAX_DEVICE_ID];
        id[..6].copy_from_slice(b"e6-c6!");
        let mut announce = Announce::discovery(id, 6, 900);
        assert!(announce.set_public_key(&[0x02; 33]));
        assert!(announce.set_signature(&[0xa5; SIGNATURE_LEN]));
        let mut response = [0u8; 256];
        let response_len = encode_discovery_response(announce, 71, &mut response).unwrap();
        let record = decode(&response[..response_len]).unwrap();
        assert_eq!(record.id, Some(71));
        assert_eq!(decode_announce(&response[..response_len]), Some(announce));
    }

    #[test]
    fn observed_request_is_separate_from_broadcast_presence() {
        let mut request = [0; 32];
        let used = encode_observed_request(&mut request).unwrap();
        assert!(is_observed_request(&request[..used]));
        assert!(decode_announce(&request[..used]).is_none());

        let entries = [ObservedAnnounce {
            device_id: b"e6-c6!",
            source_mac: [1, 2, 3, 4, 5, 6],
            source_ip: &[0; 16],
            uptime_secs: 20,
            kind: ANNOUNCE_DISCOVERY as u8,
            last_seen_ms: 500,
        }];
        let mut response = [0; 192];
        assert!(encode_observed_response(&entries, &mut response).is_some());
    }

    #[test]
    fn followup_observation_request_and_ten_entries_fit_control_mtu() {
        let mut request = [0; 32];
        let used = encode_followups_observed_request(&mut request).unwrap();
        assert!(is_followups_observed_request(&request[..used]));
        assert!(decode_announce(&request[..used]).is_none());

        let entry = ObservedFollowup {
            source: [1, 2, 3, 4, 5, 6],
            target: [6, 5, 4, 3, 2, 1],
            msg_type: 7,
            seq: 21,
            payload_len: 231,
            payload_hash: 0x1234_5678,
            last_seen_ms: 1_000,
        };
        let entries = [entry; 10];
        let mut response = [0; 1_100];
        assert!(encode_followups_observed_response(&entries, &mut response).is_some());
    }

    #[test]
    fn device_observation_request_and_ten_entries_fit_control_mtu() {
        let mut request = [0; 32];
        let used = encode_devices_observed_request(&mut request).unwrap();
        assert!(is_devices_observed_request(&request[..used]));
        let entry = ObservedDevice {
            device_id: &[],
            peer: [1, 2, 3, 4, 5, 6],
            bssid: Some([0x50, 0x6f, 0x9a, 1, 2, 3]),
            channel: Some(6),
            available_fields: crate::discovery::OBSERVATION_PEER
                | crate::discovery::OBSERVATION_BSSID
                | crate::discovery::OBSERVATION_CHANNEL
                | crate::discovery::OBSERVATION_PAYLOAD_FINGERPRINT,
            first_seen_ms: 1,
            last_seen_ms: 2,
            packets: 3,
            active_publish_rx: 4,
            active_subscribe_rx: 5,
            followup_rx: 6,
            last_kind: 2,
            last_payload_len: 231,
            last_payload_hash: 0x1234_5678,
        };
        let entries = [entry; 10];
        let mut response = [0; 1_100];
        assert!(encode_devices_observed_response(&entries, &mut response).is_some());
    }

    #[test]
    fn maximum_signed_host_announce_fits_host_scratch() {
        let mut id = [0; MAX_DEVICE_ID];
        id[..6].copy_from_slice(b"host01");
        let mut announce = Announce::discovery(id, 6, 1);
        assert!(announce.set_public_key(&[0x5a; MAX_PUBLIC_KEY]));
        assert!(announce.set_signature(&[0xa5; SIGNATURE_LEN]));
        let mut signing = [0; 384];
        assert!(signing_bytes(announce, &mut signing).is_some());
        let mut encoded = [0; 384];
        assert!(encode(announce, &mut encoded).is_some());
    }

    #[test]
    fn signed_compressed_p256_announce_fits_nan_service_info() {
        let mut id = [0; MAX_DEVICE_ID];
        id[..IDENTITY_HINT_LEN].copy_from_slice(&[1; IDENTITY_HINT_LEN]);
        let mut announce = Announce::discovery(id, IDENTITY_HINT_LEN as u8, 1);
        assert!(announce.set_public_key(&[0x02; 33]));
        assert!(announce.set_signature(&[0xa5; SIGNATURE_LEN]));
        assert!(announce.set_device_name("esp-main"));
        announce.set_wifi_channel(6);
        announce
            .set_udp_link_local_v6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0xff, 0xfe, 0, 0, 1]);
        announce.set_udp_port(3336);
        let mut encoded = [0; 255];
        let used = encode(announce, &mut encoded).expect("signed ESP announce encodes");
        assert!(used <= encoded.len());
        let decoded = decode_announce(&encoded[..used]).expect("same common record decodes");
        assert_eq!(decoded.public_key(), announce.public_key());
        assert_eq!(decoded.signature(), announce.signature());
    }

    #[test]
    fn public_key_virtual_ip6_is_stable_and_in_fc00_prefix() {
        let key = b"a public key is the virtual identity input";
        let address = virtual_ip6(key).unwrap();
        assert_eq!(address[0], 0xfc);
        assert_eq!(&address[8..], &identity_hint(key).unwrap());
        assert_eq!(Some(address), virtual_ip6_from_identity_hint(&address[8..]));
        assert_eq!(Some(address), virtual_ip6(key));
        assert_eq!(virtual_ip6(&[]), None);
        assert_eq!(identity_hint(&[]), None);
    }
}
