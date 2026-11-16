//! Encrypted Linux BLE CoC packet link over [`mesh_api::link::PacketLink`].

use std::sync::Arc;

use mesh_api::link::{
    LinkInfo, LinkIngress, LinkMeta, LinkName, LinkTxOutcome, PacketLink, PeerL2Address,
};
use mesh_api::pool::{PacketPool, PoolPacket};

use crate::coc::{COC_PACKET_MAX, CocChannel, DEFAULT_COC_PSM};

/// One connected BLE CoC exposed as an opaque [`PacketLink`].
///
/// This implementation currently owns one channel. It may evolve into one
/// multi-peer CoC link with dynamically added and removed channels, each
/// represented by a distinct [`PeerL2Address`].
pub struct CocBearer {
    channel: Arc<CocChannel>,
    info: LinkInfo,
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
            info: LinkInfo {
                name: LinkName::new("ble-coc").expect("static link name is valid"),
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

    /// Spawn the blocking BLE CoC reader thread using `pool` and `ingress`.
    pub fn attach<Pool>(&mut self, pool: Pool, ingress: Arc<dyn LinkIngress<Pool::Packet>>)
    where
        Pool: PacketPool + Send + Sync + 'static,
    {
        let channel = self.channel.clone();
        std::thread::Builder::new()
            .name("lmesh-ble-coc".to_owned())
            .spawn(move || {
                let peer = PeerL2Address::new(1).expect("one is a valid CoC peer");
                let mut buf = [0u8; COC_PACKET_MAX];
                loop {
                    let n = match channel.read_packet(&mut buf) {
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    if let Ok(mut packet) = pool.alloc()
                        && packet.append(&buf[..n]).is_ok()
                    {
                        ingress.on_packet(
                            LinkMeta {
                                peer,
                                received_at_us: 0,
                                rssi_dbm: None,
                            },
                            packet,
                        );
                    }
                }
            })
            .expect("spawn ble coc reader thread");
    }
}

impl<P: PoolPacket> PacketLink<P> for CocBearer {
    fn info(&self) -> &LinkInfo {
        &self.info
    }

    fn send_packet(&mut self, _peer: PeerL2Address, packet: P) -> Result<LinkTxOutcome, P> {
        match self.channel.write_packet(packet.bytes()) {
            Ok(()) => Ok(LinkTxOutcome::Sent),
            Err(_) => Ok(LinkTxOutcome::Failed),
        }
    }
}
