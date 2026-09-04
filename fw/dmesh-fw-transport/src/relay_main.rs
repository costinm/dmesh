//! Main-only DCID forwarding state.
//!
//! This module owns no radio queue. It holds the bounded desired-state
//! registry and asks its caller to submit a rewritten opaque datagram through
//! an already selected local bearer.

use alloc::boxed::Box;
use core::cell::UnsafeCell;

use dmesh_server::{
    cbor::Encoder,
    relay::{Handler, ObservedRule, PairRequest, ReconcileError, RelayState, Request},
};

const RULE_CAPACITY: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NextHop {
    Now(crate::wifi_espnow_esp::EspNowPeer),
    Udp6 {
        link: crate::shared_ingress_esp::IngressLink,
        peer: crate::wifi_raw_udp6_esp::RawUdp6Peer,
    },
}

struct RelayStorage {
    state: UnsafeCell<Option<Box<RelayState<NextHop, RULE_CAPACITY>>>>,
    next_hops: UnsafeCell<[Option<(u64, NextHop)>; RULE_CAPACITY]>,
    // A normal QUIC stream is decoded by the shared connection before it
    // dispatches a tagged component.  Pairing must bind its reverse rule to
    // that exact ingress bearer, so the serialized Main worker publishes the
    // bearer only for the duration of that synchronous dispatch.
    stream_ingress: UnsafeCell<Option<NextHop>>,
    // A stream handler runs while the shared dispatcher is mutably servicing
    // its packet. Snapshot the association immediately before dispatch and
    // publish it only for that synchronous callback; re-entering the
    // dispatcher from `relay.list` would create a second mutable owner.
    connection_status: UnsafeCell<Option<dmesh_server::transport::ActiveConnectionStatus>>,
    last_close_at: UnsafeCell<Option<u64>>,
}

// All access is serialized by Main's existing shared ingress worker. This
// wrapper prevents accidental references to mutable statics while documenting
// that single-owner invariant at the storage boundary.
unsafe impl Sync for RelayStorage {}

static STORAGE: RelayStorage = RelayStorage {
    state: UnsafeCell::new(None),
    next_hops: UnsafeCell::new([None; RULE_CAPACITY]),
    stream_ingress: UnsafeCell::new(None),
    connection_status: UnsafeCell::new(None),
    last_close_at: UnsafeCell::new(None),
};

/// Run one shared connection turn with the physical bearer that delivered
/// its QUIC packet.  The raw dispatcher invokes registered tagged handlers
/// synchronously, and the Main ingress worker is the sole owner, so this
/// scoped slot cannot leak between connections or bearers.
pub(crate) fn with_stream_ingress<T>(ingress: NextHop, action: impl FnOnce() -> T) -> T {
    unsafe {
        let slot = &mut *STORAGE.stream_ingress.get();
        let previous = slot.replace(ingress);
        let result = action();
        *slot = previous;
        result
    }
}

fn stream_ingress() -> Option<NextHop> {
    unsafe { *STORAGE.stream_ingress.get() }
}

/// Run one registered stream handler with an immutable snapshot of the
/// association that delivered the stream. This keeps `relay.list` diagnostic
/// data in the shared QUIC owner without recursively borrowing it.
pub(crate) fn with_connection_status<T>(
    status: Option<dmesh_server::transport::ActiveConnectionStatus>,
    last_close_at: Option<u64>,
    action: impl FnOnce() -> T,
) -> T {
    unsafe {
        let status_slot = &mut *STORAGE.connection_status.get();
        let close_slot = &mut *STORAGE.last_close_at.get();
        let previous_status = *status_slot;
        let previous_close = *close_slot;
        *status_slot = status;
        *close_slot = last_close_at;
        let result = action();
        *status_slot = previous_status;
        *close_slot = previous_close;
        result
    }
}

fn connection_status() -> Option<dmesh_server::transport::ActiveConnectionStatus> {
    unsafe { *STORAGE.connection_status.get() }
}

fn last_connection_close_at() -> Option<u64> {
    unsafe { *STORAGE.last_close_at.get() }
}

fn state() -> &'static mut RelayState<NextHop, RULE_CAPACITY> {
    unsafe {
        let state = &mut *STORAGE.state.get();
        if state.is_none() {
            *state = Some(Box::new(RelayState::new()));
        }
        state.as_deref_mut().expect("relay state initialized")
    }
}

/// Bind an already-ready local bearer path to the opaque handle carried by a
/// desired relay rule. Transport activation stays outside packet ingress.
pub(crate) fn bind_next_hop(handle: u64, next_hop: NextHop) -> bool {
    if handle == 0 {
        return false;
    }
    unsafe {
        let next_hops = &mut *STORAGE.next_hops.get();
        if let Some(slot) = next_hops
            .iter_mut()
            .find(|slot| slot.is_some_and(|(existing, _)| existing == handle))
        {
            *slot = Some((handle, next_hop));
            return true;
        }
        let Some(slot) = next_hops.iter_mut().find(|slot| slot.is_none()) else {
            return false;
        };
        *slot = Some((handle, next_hop));
        true
    }
}

fn resolve_next_hop(handle: u64) -> Option<NextHop> {
    unsafe {
        (&*STORAGE.next_hops.get())
            .iter()
            .flatten()
            .find_map(|(existing, next_hop)| (*existing == handle).then_some(*next_hop))
    }
}

/// Release only route bindings no active forwarding entry references. This is
/// important for UDP6 because each control connection can carry a fresh
/// ingress token; retaining removed tokens would consume the same small table
/// as live relay mappings.
fn prune_next_hops() {
    unsafe {
        let next_hops = &mut *STORAGE.next_hops.get();
        for entry in next_hops.iter_mut() {
            if entry.is_some_and(|(handle, _)| !state().uses_next_hop(handle)) {
                *entry = None;
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApplyError {
    Reconcile(ReconcileError),
}

struct MainHandler;

impl Handler for MainHandler {
    type Error = ApplyError;

    fn reconcile(&mut self, desired: Request) -> Result<ObservedRule, Self::Error> {
        // relay.apply is the activation handler: resolve its portable NOW
        // handle into the platform peer table before the shared reconciler
        // installs the DCID rule. This keeps address lookup out of packet
        // forwarding and makes an idempotent apply sufficient to converge.
        if let Some(rule) = desired.rule {
            let handle = rule.route.next_hop;
            if resolve_next_hop(handle).is_none() {
                if let Some(mac) = dmesh_server::relay::now_next_hop_mac(handle) {
                    let _ = bind_next_hop(
                        handle,
                        NextHop::Now(crate::wifi_espnow_esp::EspNowPeer { mac }),
                    );
                }
            }
        }
        state()
            .reconcile(desired, resolve_next_hop)
            .map_err(ApplyError::Reconcile)
    }
}

impl MainHandler {
    fn reconcile_pair(
        &mut self,
        desired: PairRequest,
        ingress: NextHop,
    ) -> Result<(ObservedRule, ObservedRule), ApplyError> {
        let reverse_handle = desired
            .reverse
            .rule
            .map(|rule| rule.route.next_hop)
            .ok_or(ApplyError::Reconcile(ReconcileError::UnknownNextHop))?;
        // A paired reverse rule is always bound to the bearer which carried
        // the authenticated control stream. UDP6 uses an opaque controller
        // token; directed NOW uses the host's unicast source-MAC handle. Do
        // not infer either route from the requested forward next hop.
        let reverse_matches_ingress = match ingress {
            NextHop::Udp6 { .. } => {
                dmesh_server::relay::udp6_next_hop_token(reverse_handle).is_some()
            }
            NextHop::Now(peer) => {
                dmesh_server::relay::now_next_hop_mac(reverse_handle) == Some(peer.mac)
            }
        };
        if !reverse_matches_ingress || !bind_next_hop(reverse_handle, ingress) {
            return Err(ApplyError::Reconcile(ReconcileError::UnknownNextHop));
        }
        // The normal per-rule handler resolves and binds the forward NOW peer.
        if let Some(rule) = desired.forward.rule {
            let handle = rule.route.next_hop;
            if resolve_next_hop(handle).is_none() {
                if let Some(mac) = dmesh_server::relay::now_next_hop_mac(handle) {
                    let _ = bind_next_hop(
                        handle,
                        NextHop::Now(crate::wifi_espnow_esp::EspNowPeer { mac }),
                    );
                }
            }
        }
        state()
            .reconcile_pair(desired, resolve_next_hop)
            .map_err(ApplyError::Reconcile)
    }

    fn remove_pair(
        &mut self,
        dcid: quic_lite::ConnectionId,
        revision: u64,
    ) -> Result<bool, ApplyError> {
        let removed = state()
            .remove_pair(dcid, revision)
            .map_err(ApplyError::Reconcile)?;
        if removed {
            prune_next_hops();
        }
        Ok(removed)
    }
}

/// Encode the resolved, device-local route for `relay.list`.  The forwarding
/// table itself stores only an opaque handle; resolving it here is what makes
/// a UDP entry useful to a controller without exposing a token or pointer.
/// Field 1 is the transport ID, field 2 is the MAC/IPv6 address bytes, and
/// field 3 (UDP6 only) is the port.
fn encode_next_hop(encoder: &mut Encoder<'_>, next_hop: NextHop) -> Option<()> {
    match next_hop {
        NextHop::Now(peer) => {
            encoder.map(2)?;
            encoder.uint(1)?;
            encoder.uint(dmesh_server::transport_path::TransportId::NOW.0 as u64)?;
            encoder.uint(2)?;
            encoder.bytes_value(&peer.mac)
        }
        NextHop::Udp6 { link: _, peer } => {
            encoder.map(3)?;
            encoder.uint(1)?;
            encoder.uint(dmesh_server::transport_path::TransportId::UDP6.0 as u64)?;
            encoder.uint(2)?;
            encoder.bytes_value(&peer.ip)?;
            encoder.uint(3)?;
            encoder.uint(u64::from(peer.port))
        }
    }
}

/// Encode one opaque association path only at the ESP adapter boundary.
/// QUIC-lite owns the path selection and sees only its `PathId`; the response
/// projects a transport ID and the adapter's six-byte peer fact for operator
/// diagnostics.
fn encode_connection_path(encoder: &mut Encoder<'_>, path: quic_lite::PathId) -> Option<()> {
    encoder.map(2)?;
    encoder.uint(1)?;
    encoder.uint(crate::core_runtime::connection_path_transport(path) as u64)?;
    encoder.uint(2)?;
    encoder.bytes_value(&crate::core_runtime::connection_path_peer(path))
}

fn encode_stream_direction(
    encoder: &mut Encoder<'_>,
    stats: quic_lite::StreamDirectionStats,
) -> Option<()> {
    encoder.map(2)?;
    encoder.uint(1)?;
    encoder.uint(stats.active)?;
    encoder.uint(2)?;
    encoder.uint(stats.total)
}

/// Encode the active shared QUIC association. Field 1 is this endpoint's
/// receive CID, field 2 the peer's receive CID, field 3 has locally/peer
/// initiated stream counts, field 4 is active transport/path, field 5 lists
/// every path that has carried a valid packet, field 6 is the last accepted
/// CLOSE timestamp (if any), and field 7 has packet counters. No bearer
/// adapter maintains a competing copy of this state.
fn encode_connection_status(
    encoder: &mut Encoder<'_>,
    status: dmesh_server::transport::ActiveConnectionStatus,
) -> Option<()> {
    // Base keys 1, 2, 3, 5, and 7 are always present; active path and close
    // time are optional. Keep this cardinality exact: an under-declared CBOR
    // map would make the enclosing tagged response unparsable.
    let fields =
        5 + u64::from(status.active_path.is_some()) + u64::from(status.last_close_at.is_some());
    encoder.map(fields)?;
    encoder.uint(1)?;
    encoder.uint(status.receive_cid.value())?;
    encoder.uint(2)?;
    encoder.uint(status.peer_cid.value())?;
    encoder.uint(3)?;
    encoder.map(2)?;
    encoder.uint(1)?;
    encode_stream_direction(encoder, status.streams.locally_initiated)?;
    encoder.uint(2)?;
    encode_stream_direction(encoder, status.streams.peer_initiated)?;
    if let Some(path) = status.active_path {
        encoder.uint(4)?;
        encode_connection_path(encoder, path)?;
    }
    encoder.uint(5)?;
    let known = status.known_paths.into_iter().flatten().count();
    encoder.array(known as u64)?;
    for path in status.known_paths.into_iter().flatten() {
        encode_connection_path(encoder, path)?;
    }
    if let Some(last_close_at) = status.last_close_at {
        encoder.uint(6)?;
        encoder.uint(last_close_at)?;
    }
    encoder.uint(7)?;
    encoder.map(6)?;
    encoder.uint(1)?;
    encoder.uint(status.transport.received_datagrams)?;
    encoder.uint(2)?;
    encoder.uint(status.transport.sent_datagrams)?;
    encoder.uint(3)?;
    encoder.uint(status.transport.stream_datagrams)?;
    encoder.uint(4)?;
    encoder.uint(status.transport.sent_stream_datagrams)?;
    encoder.uint(5)?;
    encoder.uint(status.transport.retransmitted_datagrams)?;
    encoder.uint(6)?;
    encoder.uint(status.transport.duplicate_datagrams)
}

/// Encode the bounded active-mapping snapshot. The compact result is
/// `{1: active, 2: capacity, 3: rules, 4: connections, 5: last_close_at}`.
/// Each forwarding rule
/// includes the active association receive CID as field 5 when the table is
/// being read through one. The connection list reports association-owned CID,
/// stream, transport, path, and close facts independently of forwarding.
fn encode_relay_list(out: &mut [u8]) -> Option<usize> {
    let relay = state();
    let active = relay.active_len();
    let connection = connection_status();
    let last_close_at = last_connection_close_at();
    let mut encoder = Encoder::new(out);
    encoder.map(5)?;
    encoder.uint(1)?;
    encoder.uint(active as u64)?;
    encoder.uint(2)?;
    encoder.uint(RULE_CAPACITY as u64)?;
    encoder.uint(3)?;
    encoder.array(active as u64)?;
    let mut complete = Some(());
    relay.visit_active(|dcid, handle, destination, revision| {
        let Some(next_hop) = resolve_next_hop(handle) else {
            complete = None;
            return;
        };
        complete = complete.and_then(|()| {
            let has_destination = matches!(
                destination,
                quic_lite::ForwardDestination::Connection(_)
            );
            encoder.map(3 + u64::from(has_destination) + u64::from(connection.is_some()))?;
            encoder.uint(1)?;
            encoder.uint(dcid.value())?;
            encoder.uint(2)?;
            encode_next_hop(&mut encoder, next_hop)?;
            if let quic_lite::ForwardDestination::Connection(dcid) = destination {
                encoder.uint(3)?;
                encoder.uint(dcid.value())?;
            }
            encoder.uint(4)?;
            encoder.uint(revision)?;
            if let Some(connection) = connection {
                encoder.uint(5)?;
                encoder.uint(connection.receive_cid.value())?;
            }
            Some(())
        });
    });
    complete?;
    encoder.uint(4)?;
    encoder.array(u64::from(connection.is_some()))?;
    if let Some(connection) = connection {
        encode_connection_status(&mut encoder, connection)?;
    }
    encoder.uint(5)?;
    // `0` is the explicit “no accepted CLOSE yet” value; timestamps are
    // monotonic microseconds and are never otherwise zero for a live Main.
    encoder.uint(last_close_at.unwrap_or(0))?;
    Some(encoder.len())
}

/// Apply relay desired state from a normal, authenticated QUIC stream. There
/// is deliberately no sentinel-CID relay-administration binding.
pub(crate) fn receive_tagged_relay(
    record: dmesh_server::tagged::Record<'_>,
) -> Option<alloc::vec::Vec<u8>> {
    let id = record.id?;
    // `relay.list` may contain every one of the bounded rule slots, including
    // full IPv6 addresses. Keep this on the existing transport-MTU budget;
    // the relay still owns no dynamic inventory or queue.
    let mut result = [0u8; crate::TRANSPORT_MTU];
    let (method, result_len) = if dmesh_server::relay::decode_list_record(record).is_some() {
        (
            dmesh_server::relay::RELAY_LIST,
            encode_relay_list(&mut result)?,
        )
    } else if let Some((dcid, revision)) = dmesh_server::relay::decode_remove_record(record) {
        let removed = MainHandler.remove_pair(dcid, revision).ok()?;
        let mut encoder = Encoder::new(&mut result);
        encoder.boolean(removed)?;
        (dmesh_server::relay::RELAY_REMOVE, encoder.len())
    } else if let Some(request) = dmesh_server::relay::decode_pair_record(record) {
        let (forward, reverse) = MainHandler
            .reconcile_pair(request, stream_ingress()?)
            .ok()?;
        let used = dmesh_server::relay::encode_observed_pair(forward, reverse, &mut result)?;
        (dmesh_server::relay::RELAY_APPLY_PAIR, used)
    } else if let Some(request) = dmesh_server::relay::decode_record(record) {
        let observed = MainHandler.reconcile(request).ok()?;
        let used = dmesh_server::relay::encode_observed_rule(observed, &mut result)?;
        (dmesh_server::relay::RELAY_APPLY, used)
    } else {
        return None;
    };
    let mut response = [0u8; crate::TRANSPORT_MTU];
    let used = dmesh_server::tagged::encode_numeric_response(
        dmesh_server::relay::RELAY_COMPONENT,
        method,
        id,
        &result[..result_len],
        &mut response,
    )?;
    Some(alloc::vec::Vec::from(&response[..used]))
}

/// Attempt opaque forwarding. `false` means no local forwarding rule matched;
/// the existing endpoint/direct dispatcher remains responsible for the packet.
///
/// A matched rule is consumed even when its immediate bearer submission fails.
/// Falling through in that case would let the relay's own QUIC service answer
/// an endpoint packet, poisoning the client's learned server CID and turning
/// a radio TX failure into a false local bootstrap success.
pub(crate) fn forward<F>(packet: &[u8], output: &mut [u8], mut submit: F) -> bool
where
    F: FnMut(NextHop, &[u8]) -> bool,
{
    let relay = state();
    let outcome = quic_lite::dispatch_datagram(relay.registry(), packet, output);
    let Ok(quic_lite::DcidDatagram::Forward {
        received_dcid,
        rule,
        used,
    }) = outcome
    else {
        return false;
    };
    // relay.open is the narrowly-scoped exception to opaque forwarding.
    // The client owns its receive CID; the relay owns both aliases.  For
    // the initial OPEN only, replace the client CID carried in the body
    // with the paired reverse alias.  The server then addresses ACKs to
    // that alias, and the normal reverse rule restores the client CID on
    // the UDP path.  If this is not a valid OPEN, preserve the generic
    // opaque rewrite already produced by dispatch_datagram.
    let used = if matches!(rule.destination, quic_lite::ForwardDestination::Bootstrap) {
        relay
            .relay_open_return_dcid(received_dcid)
            .and_then(|reverse_dcid| {
                quic_lite::rewrite_relay_open(packet, None, reverse_dcid, output).ok()
            })
            .unwrap_or(used)
    } else {
        used
    };
    crate::commands::send_stat(b"relay forward dcid=", received_dcid.value());
    let next_hop = rule.next_hop;
    crate::commands::send_stat(
        b"relay forward submit=",
        u64::from(submit(next_hop, &output[..used])),
    );
    true
}
