//! Firmware QUIC owner and ESP packet-bearer registration.
//!
//! UART receives its pool and ingress handle only through `BearerContext`.
//! QUIC output returns through the registered `PacketEgress` implementation;
//! neither direction calls private node packet APIs.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use quic_lite::{
    BearerContext, BearerInfo, BearerName, EgressSubmission, OwnedPacket, PacketBearer,
    PacketEgress, PacketMeta, PacketSubmitError, PeerL2Address, QuicNodeEgressError, QuicStream,
    nostd::NoStdRuntime,
    packet_pool::{PacketPool, PoolBufferLease},
};

const PACKETS: usize = 8;
const SLOT_SIZE: usize = quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE;

pub(crate) type FirmwarePool = PacketPool<PACKETS, SLOT_SIZE>;
pub(crate) type FirmwarePacket = OwnedPacket<PoolBufferLease<'static, PACKETS, SLOT_SIZE>>;
// Every local association owns one receive CID in the node's shared DCID
// registry. Firmware does not currently reserve additional entries for relay
// forwarding, but a zero-entry registry would reject the first association.
type FirmwareRuntime = NoStdRuntime<FirmwarePool>;

static POOL: FirmwarePool = FirmwarePool::new();
static UART_READY: AtomicBool = AtomicBool::new(false);
static INGRESS_PROGRESS_REPORTED: AtomicBool = AtomicBool::new(false);
static INGRESS_ERROR_REPORTED: AtomicBool = AtomicBool::new(false);
static mut UART_CONTEXT: core::mem::MaybeUninit<BearerContext<FirmwarePool>> =
    core::mem::MaybeUninit::uninit();
static READY: AtomicBool = AtomicBool::new(false);
// The node contains association and stream state. Keeping it in a static
// `MaybeUninit` reserves the complete value in `.bss`, which does not fit
// classic ESP32 internal DRAM. Allocate it once after ESP-IDF has
// initialized the heap; the leaked box remains the device-wide owner.
static mut RUNTIME: *mut FirmwareRuntime = core::ptr::null_mut();
// The stream position is unchanged when the UART bearer retains an ACK or
// another packet. Keep the application response until send completion wakes
// the node owner, then retry the same bytes without a second packet copy.
static mut PENDING_RESPONSE: Option<(QuicStream, Vec<u8>, usize)> = None;

struct UartBearer;

impl PacketEgress<<FirmwarePool as quic_lite::PacketPool>::Buffer> for UartBearer {
    fn submit(
        &mut self,
        peer: PeerL2Address,
        submission: EgressSubmission<<FirmwarePool as quic_lite::PacketPool>::Buffer>,
    ) -> Result<(), PacketSubmitError<<FirmwarePool as quic_lite::PacketPool>::Buffer>> {
        // The physical bearer retains this pool lease until every framed byte
        // has been accepted by the UART driver. Do not copy into the legacy
        // raw-packet queue or report completion at queue admission: completion
        // is the edge that returns the node-owned packet to its pool and lets
        // QUIC submit the next pending packet.
        crate::uart_esp::EspUartBearer.submit(peer, submission)
    }
}

impl PacketBearer<FirmwarePool> for UartBearer {
    type AttachError = ();

    fn info(&self) -> BearerInfo {
        BearerInfo {
            name: BearerName::new("uart0").expect("static bearer name is valid"),
            max_packet_size: quic_lite::DEFAULT_MAX_PACKET_SIZE,
            prefix_required: quic_lite::PACKET_PREFIX_RESERVE,
            suffix_required: quic_lite::PACKET_SUFFIX_RESERVE,
            requires_packet_encryption: false,
            secure_link: true,
            nominal_bitrate_bps: 115_200,
            local_mac: None,
        }
    }

    fn attach(&mut self, context: BearerContext<FirmwarePool>) -> Result<(), Self::AttachError> {
        unsafe {
            core::ptr::addr_of_mut!(UART_CONTEXT).write(core::mem::MaybeUninit::new(context));
        }
        UART_READY.store(true, Ordering::Release);
        Ok(())
    }
}

unsafe fn runtime() -> &'static mut FirmwareRuntime {
    if !READY.load(Ordering::Acquire) {
        let embedded = quic_lite::AssociationLimits::embedded();
        let mut value = FirmwareRuntime::try_new_boxed(
            crate::main_runtime::stateless_reset_key(),
            &POOL,
            embedded.connection,
        )
        .expect("firmware QUIC runtime allocation succeeds");
        value
            .set_limits(quic_lite::NodeLimits::embedded())
            .expect("firmware QUIC node limits are valid");
        value
            .set_default_association_limits(embedded)
            .expect("firmware QUIC association limits are valid");
        value
            .add_bearer(UartBearer)
            .expect("static UART bearer registration succeeds");
        core::ptr::addr_of_mut!(RUNTIME).write(Box::into_raw(value));
        READY.store(true, Ordering::Release);
    }
    &mut **core::ptr::addr_of_mut!(RUNTIME)
}

/// Pool assigned to UART by its registered bearer context.
pub(crate) fn uart_pool() -> &'static FirmwarePool {
    unsafe {
        let _ = runtime();
    }
    assert!(UART_READY.load(Ordering::Acquire));
    unsafe { (&*core::ptr::addr_of!(UART_CONTEXT).cast::<BearerContext<FirmwarePool>>()).pool() }
}

/// Transfer one UART-decoded packet through its bearer context.
///
/// The physical UART task stops here. QUIC parsing and application dispatch
/// run on the firmware owner task after the bearer's wake callback fires, so
/// neither the node nor handler working set is placed on the UART task stack.
pub(crate) fn receive_uart(packet: FirmwarePacket) {
    let context = {
        unsafe {
            let _ = runtime();
        }
        assert!(UART_READY.load(Ordering::Acquire));
        unsafe {
            (&*core::ptr::addr_of!(UART_CONTEXT).cast::<BearerContext<FirmwarePool>>()).clone()
        }
    };
    let meta = PacketMeta {
        bearer: context.bearer(),
        peer_l2_address: PeerL2Address::new(1).expect("UART peer handle is nonzero"),
        received_at_us: unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 },
    };

    context.enqueue_packet(meta, packet);
}

/// Advance queued bearer ingress and dispatch complete request streams.
///
/// Main calls this only from its single event owner. It is intentionally not
/// public API: physical bearers enqueue through `BearerContext` and merely
/// wake that owner.
pub(crate) fn progress() {
    let runtime = unsafe { runtime() };
    if let Some((mut stream, response, offset)) = unsafe { PENDING_RESPONSE.take() } {
        match write_response(runtime, &mut stream, &response, offset) {
            Ok(next) if next < response.len() => {
                unsafe { PENDING_RESPONSE = Some((stream, response, next)) };
                return;
            }
            Err(error) if error.is_retryable() => {
                unsafe { PENDING_RESPONSE = Some((stream, response, offset)) };
                return;
            }
            _ => {}
        }
    }
    let mut received_response = None;
    match runtime.progress_with_stream(|stream, offset, fin, bytes| {
        if offset == 0 && fin {
            if let Some(response) = dmesh_server::services::dispatch_tagged_stream(bytes) {
                received_response = Some((stream, response));
            }
        }
        Ok(bytes.len())
    }) {
        Ok(true) => {
            if !INGRESS_PROGRESS_REPORTED.swap(true, Ordering::AcqRel) {
                let _ = crate::uart_esp::send_debug_text(b"DMESH uart: quic ingress processed");
            }
        }
        Ok(false) => {}
        Err(error) => {
            if !INGRESS_ERROR_REPORTED.swap(true, Ordering::AcqRel) {
                let detail = match error {
                    QuicNodeEgressError::Association(_) => b"association".as_slice(),
                    QuicNodeEgressError::Transport(quic_lite::Error::BufferTooSmall) => {
                        b"buffer-too-small"
                    }
                    QuicNodeEgressError::Transport(quic_lite::Error::Truncated) => b"truncated",
                    QuicNodeEgressError::Transport(quic_lite::Error::Invalid) => b"invalid",
                    QuicNodeEgressError::Transport(quic_lite::Error::Blocked) => b"blocked",
                    QuicNodeEgressError::Transport(quic_lite::Error::InvalidVarint) => {
                        b"invalid-varint"
                    }
                    QuicNodeEgressError::Transport(quic_lite::Error::FlowControl) => {
                        b"flow-control"
                    }
                    QuicNodeEgressError::Transport(quic_lite::Error::StreamLimit) => {
                        b"stream-limit"
                    }
                    QuicNodeEgressError::Transport(quic_lite::Error::PacketNumberExhausted) => {
                        b"packet-number-exhausted"
                    }
                    QuicNodeEgressError::Transport(quic_lite::Error::WrongConnectionId) => {
                        b"wrong-connection-id"
                    }
                    QuicNodeEgressError::Transport(quic_lite::Error::PeerRestarted) => {
                        b"peer-restarted"
                    }
                    QuicNodeEgressError::Transport(quic_lite::Error::BootstrapInvalid) => {
                        b"bootstrap-invalid"
                    }
                    QuicNodeEgressError::Transport(quic_lite::Error::HistoryFull) => {
                        b"history-full"
                    }
                    QuicNodeEgressError::Transport(quic_lite::Error::RetransmissionTooLarge) => {
                        b"retransmission-too-large"
                    }
                    QuicNodeEgressError::PoolUnavailable => b"pool-unavailable",
                    QuicNodeEgressError::InvalidPoolLayout => b"invalid-pool-layout",
                    QuicNodeEgressError::MissingEgressAddress => b"missing-egress-address",
                    QuicNodeEgressError::MissingBearer => b"missing-bearer",
                    QuicNodeEgressError::BearerBusy => b"bearer-busy",
                    QuicNodeEgressError::StreamEventsFull => b"stream-events-full",
                    QuicNodeEgressError::AssociationTimedOut => b"association-timeout",
                    QuicNodeEgressError::RelayUnavailable => b"relay-unavailable",
                };
                let _ = crate::uart_esp::send_debug_text(detail);
            }
        }
    }
    if let Some((mut stream, response)) = received_response {
        match write_response(runtime, &mut stream, &response, 0) {
            Ok(next) if next < response.len() => {
                unsafe { PENDING_RESPONSE = Some((stream, response, next)) };
                return;
            }
            Err(error) if error.is_retryable() => {
                unsafe { PENDING_RESPONSE = Some((stream, response, 0)) };
                return;
            }
            _ => {}
        }
    }
    while let Some(mut chunk) = runtime.next_stream_chunk() {
        if chunk.offset == 0 && chunk.fin {
            if let Some(response) = dmesh_server::services::dispatch_tagged_stream(&chunk.bytes) {
                match write_response(runtime, &mut chunk.stream, &response, 0) {
                    Ok(next) if next < response.len() => {
                        unsafe { PENDING_RESPONSE = Some((chunk.stream, response, next)) };
                        break;
                    }
                    Err(error) if error.is_retryable() => {
                        unsafe { PENDING_RESPONSE = Some((chunk.stream, response, 0)) };
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
}

fn write_response(
    runtime: &mut FirmwareRuntime,
    stream: &mut QuicStream,
    response: &[u8],
    offset: usize,
) -> Result<usize, QuicNodeEgressError> {
    let accepted = runtime.write_stream_and_finish(stream, &response[offset..])?;
    Ok(offset.saturating_add(accepted))
}
