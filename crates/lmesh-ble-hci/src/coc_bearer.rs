//! QUIC-lite bearer over one encrypted Linux BLE CoC packet channel.

use std::sync::Arc;

use quic_lite::{
    BearerContext, BearerInfo, BearerName, EgressSubmission, PacketBearer, PacketEgress,
    PacketMeta, PacketPool, PacketSendOutcome, PacketSubmitError, PeerL2Address,
};

use crate::coc::{COC_PACKET_MAX, CocChannel, DEFAULT_COC_PSM};

/// One connected BLE CoC exposed as an opaque packet bearer.
///
/// This implementation currently owns one channel. It may evolve into one
/// multi-peer CoC bearer with dynamically added and removed channels, each
/// represented by a distinct `PeerL2Address`, consistent with UDP, ESP-NOW,
/// multi-port UART, and Android's Java-owned BLE bearer.
pub struct CocBearer {
    channel: Arc<CocChannel>,
    info: BearerInfo,
}

impl CocBearer {
    /// Connect a CoC to `address` (a BLE address from a scan) on `psm`,
    /// default 128. The link must negotiate encryption; BlueZ's agent owns user
    /// consent and bond persistence. The bearer adds no cryptography of its own
    /// and carries no credentials; the device decides what a peer may do.
    pub fn connect(address: &str, psm: Option<u16>) -> anyhow::Result<Self> {
        Ok(Self::new(CocChannel::connect(
            address,
            psm.unwrap_or(DEFAULT_COC_PSM),
        )?))
    }

    pub(crate) fn channel(&self) -> Arc<CocChannel> {
        self.channel.clone()
    }

    fn new(channel: CocChannel) -> Self {
        Self {
            channel: Arc::new(channel),
            info: BearerInfo {
                name: BearerName::new("ble-coc").expect("static bearer name is valid"),
                max_packet_size: COC_PACKET_MAX,
                prefix_required: 0,
                suffix_required: 0,
                requires_packet_encryption: false,
                // connect() refuses a link that did not negotiate encryption.
                secure_link: true,
                nominal_bitrate_bps: 1_000_000,
                local_mac: None,
            },
        }
    }
}

impl<B: AsRef<[u8]>> PacketEgress<B> for CocBearer {
    fn submit(
        &mut self,
        _peer: PeerL2Address,
        submission: EgressSubmission<B>,
    ) -> Result<(), PacketSubmitError<B>> {
        let outcome = self.channel.write_packet(submission.packet().bytes());
        submission.complete(
            if outcome.is_ok() {
                PacketSendOutcome::Sent
            } else {
                PacketSendOutcome::Failed
            },
            0,
        );
        Ok(())
    }
}

impl<P> PacketBearer<P> for CocBearer
where
    P: PacketPool + Sync + 'static,
    P::Buffer: Send,
{
    type AttachError = std::io::Error;

    fn info(&self) -> BearerInfo {
        self.info
    }

    fn attach(&mut self, context: BearerContext<P>) -> Result<(), Self::AttachError> {
        let channel = self.channel.clone();
        std::thread::Builder::new()
            .name("lmesh-ble-coc".to_owned())
            .spawn(move || {
                let peer = PeerL2Address::new(1).expect("one is a valid CoC peer");
                loop {
                    let packet = context.pool().build_packet(0, 0, |output| {
                        channel.read_packet(output)
                    });
                    match packet {
                        Ok(packet) => context.enqueue_packet(
                            PacketMeta {
                                bearer: context.bearer(),
                                peer_l2_address: peer,
                                received_at_us: 0,
                            },
                            packet,
                        ),
                        Err(quic_lite::PacketBuildError::Serialize(_)) => break,
                        Err(_) => std::thread::yield_now(),
                    }
                }
            })?;
        Ok(())
    }
}
