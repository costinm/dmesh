//! Main-only DCID forwarding state.
//!
//! This module owns no radio queue. It holds the bounded desired-state
//! registry and asks its caller to submit a rewritten opaque datagram through
//! an already selected local bearer.

use alloc::boxed::Box;
use core::cell::UnsafeCell;

use dmesh_server::relay::{
    DirectOutcome, Handler, ObservedRule, PairRequest, ReconcileError, RelayState, Request,
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
    dedup: UnsafeCell<dmesh_server::relay::TerminatingDirectDedup<8, { crate::TRANSPORT_MTU }>>,
    // A normal QUIC stream is decoded by the shared raw service before it
    // dispatches a tagged component.  Pairing must bind its reverse rule to
    // that exact ingress bearer, so the serialized Main worker publishes the
    // bearer only for the duration of that synchronous dispatch.
    stream_ingress: UnsafeCell<Option<NextHop>>,
}

// All access is serialized by Main's existing shared ingress worker. This
// wrapper prevents accidental references to mutable statics while documenting
// that single-owner invariant at the storage boundary.
unsafe impl Sync for RelayStorage {}

static STORAGE: RelayStorage = RelayStorage {
    state: UnsafeCell::new(None),
    next_hops: UnsafeCell::new([None; RULE_CAPACITY]),
    dedup: UnsafeCell::new(dmesh_server::relay::TerminatingDirectDedup::new()),
    stream_ingress: UnsafeCell::new(None),
};

/// Run one shared raw-service turn with the physical bearer that delivered
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
            NextHop::Udp6 { .. } => dmesh_server::relay::udp6_next_hop_token(reverse_handle)
                .is_some(),
            NextHop::Now(peer) => dmesh_server::relay::now_next_hop_mac(reverse_handle)
                == Some(peer.mac),
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
}

/// Apply relay desired state from a normal, authenticated QUIC stream.  This
/// is intentionally the same reconciliation as the DCID-zero diagnostic
/// binding below; only packet framing and direct-message dedup differ.
pub(crate) fn receive_tagged_relay(
    record: dmesh_server::tagged::Record<'_>,
) -> Option<alloc::vec::Vec<u8>> {
    let id = record.id?;
    let mut result = [0u8; 64];
    let (method, result_len) = if let Some(request) = dmesh_server::relay::decode_pair_record(record)
    {
        let (forward, reverse) = MainHandler.reconcile_pair(request, stream_ingress()?).ok()?;
        let used = dmesh_server::relay::encode_observed_pair(forward, reverse, &mut result)?;
        (dmesh_server::relay::RELAY_APPLY_PAIR, used)
    } else if let Some(request) = dmesh_server::relay::decode_record(record) {
        let observed = MainHandler.reconcile(request).ok()?;
        let used = dmesh_server::relay::encode_observed_rule(observed, &mut result)?;
        (dmesh_server::relay::RELAY_APPLY, used)
    } else {
        return None;
    };
    let mut response = [0u8; 128];
    let used = dmesh_server::tagged::encode_numeric_response(
        dmesh_server::relay::RELAY_COMPONENT,
        method,
        id,
        &result[..result_len],
        &mut response,
    )?;
    Some(alloc::vec::Vec::from(&response[..used]))
}

/// Apply one direct relay desired-state record. The caller owns terminal
/// request deduplication and response packet-number policy.
pub(crate) fn apply_direct(
    packet: &[u8],
    response: &mut [u8],
    ingress: Option<NextHop>,
) -> DirectOutcome {
    let Ok((header, payload)) = quic_lite::decode_direct_packet(packet) else {
        return DirectOutcome::NotHandled;
    };
    // A QUIC-lite bootstrap OPEN deliberately also has DCID zero and a
    // four-byte packet number.  It is therefore syntactically a `direct`
    // packet at this layer, even though its payload is a QUIC frame rather
    // than tagged-CBOR.  Do not let direct-control dedup claim that OPEN:
    // normal raw-service dispatch must see it and produce OPEN_ACK.
    //
    // Decode once before mutating dedup state.  In particular, an arbitrary
    // future DCID-zero control family must not consume a relay request ID or
    // turn a later valid relay request into a replay/conflict.
    let Some(record) = dmesh_server::tagged::decode(payload) else {
        return DirectOutcome::NotHandled;
    };
    let Some(id) = record.id else {
        return DirectOutcome::NotHandled;
    };
    let is_pair = dmesh_server::relay::decode_pair_record(record).is_some();
    let is_apply = dmesh_server::relay::decode_record(record).is_some();
    if !is_pair && !is_apply {
        return DirectOutcome::NotHandled;
    }
    let dedup = unsafe { &mut *STORAGE.dedup.get() };
    match dedup.check(header.packet_number, payload, response) {
        dmesh_server::relay::TerminatingDirectDedupResult::Replay(used) => {
            return DirectOutcome::Response(used);
        }
        dmesh_server::relay::TerminatingDirectDedupResult::Conflict => {
            return DirectOutcome::Handled;
        }
        dmesh_server::relay::TerminatingDirectDedupResult::New => {}
    }
    let mut result = [0u8; 64];
    let (method, result_len) = if is_pair {
        let Some(request) = dmesh_server::relay::decode_pair_request(payload) else {
            return DirectOutcome::Handled;
        };
        let Some(ingress) = ingress else {
            return DirectOutcome::Handled;
        };
        let Ok((forward, reverse)) = MainHandler.reconcile_pair(request, ingress) else {
            return DirectOutcome::Handled;
        };
        let Some(used) = dmesh_server::relay::encode_observed_pair(forward, reverse, &mut result)
        else {
            return DirectOutcome::Handled;
        };
        (dmesh_server::relay::RELAY_APPLY_PAIR, used)
    } else if is_apply {
        let Some(request) = dmesh_server::relay::decode_request(payload) else {
            return DirectOutcome::Handled;
        };
        let Ok(observed) = MainHandler.reconcile(request) else {
            return DirectOutcome::Handled;
        };
        let Some(used) = dmesh_server::relay::encode_observed_rule(observed, &mut result) else {
            return DirectOutcome::Handled;
        };
        (dmesh_server::relay::RELAY_APPLY, used)
    } else {
        return DirectOutcome::NotHandled;
    };
    let mut cbor = [0u8; 128];
    let Some(cbor_len) = dmesh_server::tagged::encode_numeric_response(
        dmesh_server::relay::RELAY_COMPONENT,
        method,
        id,
        &result[..result_len],
        &mut cbor,
    ) else {
        return DirectOutcome::Handled;
    };
    match quic_lite::encode_direct_packet(header.packet_number, &cbor[..cbor_len], response) {
        Ok(used) => {
            let _ = dedup.store(header.packet_number, payload, &response[..used]);
            DirectOutcome::Response(used)
        }
        Err(_) => DirectOutcome::Handled,
    }
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
    let Ok(quic_lite::DcidDatagram::Forward { rule, used }) = outcome else {
        return false;
    };
    if let Ok((header, _)) = quic_lite::ShortHeader::decode(packet) {
        // relay.open is the narrowly-scoped exception to opaque forwarding.
        // The client owns its receive CID; the relay owns both aliases.  For
        // the initial OPEN only, replace the client CID carried in the body
        // with the paired reverse alias.  The server then addresses ACKs to
        // that alias, and the normal reverse rule restores the client CID on
        // the UDP path.  If this is not a valid OPEN, preserve the generic
        // opaque rewrite already produced by dispatch_datagram.
        let used = if rule.outbound_dcid.value() == 0 {
            relay
                .relay_open_return_dcid(header.dcid)
                .and_then(|reverse_dcid| {
                    quic_lite::rewrite_relay_open(packet, rule.outbound_dcid, reverse_dcid, output)
                        .ok()
                })
                .unwrap_or(used)
        } else {
            used
        };
        crate::commands::send_stat(b"relay forward dcid=", header.dcid.value());
        let next_hop = rule.next_hop;
        crate::commands::send_stat(
            b"relay forward submit=",
            u64::from(submit(next_hop, &output[..used])),
        );
        return true;
    }
    let next_hop = rule.next_hop;
    crate::commands::send_stat(
        b"relay forward submit=",
        u64::from(submit(next_hop, &output[..used])),
    );
    true
}
