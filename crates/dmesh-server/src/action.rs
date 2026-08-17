//! Socket-free QUIC-lite object server for ESP-NOW/vendor-action datagrams.
//!
//! This module deliberately knows nothing about nl80211, channels, NAN, or
//! raw-frame injection. `lmesh-wifi` provides those privileged operations and
//! passes each complete action payload plus its source MAC to [`ActionServer`].
//! The returned payloads are sent back over that same action bearer.

use crate::protocol::{ObjectRecordStream, decode_get};
use crate::{ObjectServer, ServerConfig};
use anyhow::{Result, anyhow, bail};
use quic_lite::mux::StreamMux;
use quic_lite::{
    ConnectionId, ConnectionLimits, DEFAULT_MAX_DATAGRAM_SIZE, Role, SERVICE_OBJECT, ShortHeader,
};
use std::collections::HashMap;

const MTU: usize = DEFAULT_MAX_DATAGRAM_SIZE;
const OBJECT_STREAM: u64 = 3;
const MAX_CONNECTIONS: usize = 64;
const OBJECT_CHUNK: usize = MTU - 64;

struct Connection {
    peer: [u8; 6],
    mux: StreamMux<8, 512>,
    transfer: Option<ObjectRecordStream>,
}

/// Host object service bound to complete action-frame payloads.
///
/// There is one QUIC-lite connection table across action paths. The caller may
/// retain this value inside `lmesh-wifi`; it does not open a socket or thread.
pub struct ActionServer {
    objects: ObjectServer,
    connections: HashMap<u64, Connection>,
    next_cid: u64,
    object_chunk: usize,
}

impl ActionServer {
    pub fn new(config: ServerConfig) -> Self {
        Self {
            objects: ObjectServer::new(config),
            connections: HashMap::new(),
            next_cid: 0x5000,
            object_chunk: OBJECT_CHUNK,
        }
    }

    pub fn with_object_chunk(config: ServerConfig, object_chunk: usize) -> Result<Self> {
        if !(1..=OBJECT_CHUNK).contains(&object_chunk) {
            bail!("action object chunk must be in 1..={OBJECT_CHUNK}");
        }
        let mut server = Self::new(config);
        server.object_chunk = object_chunk;
        Ok(server)
    }

    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Process one complete action payload and return zero or more payloads
    /// to send to `peer`. Invalid/unroutable data returns an error rather than
    /// creating an implicit connection.
    pub fn receive(&mut self, peer: [u8; 6], packet: &[u8]) -> Result<Vec<Vec<u8>>> {
        if packet.len() > MTU {
            bail!("action packet exceeds common MTU");
        }
        let (header, _) =
            ShortHeader::decode(packet).map_err(|error| anyhow!("action header: {error:?}"))?;
        if header.dcid.value() == 0 {
            return self.accept_open(peer, packet);
        }
        let connection = self
            .connections
            .get_mut(&header.dcid.value())
            .ok_or_else(|| anyhow!("unknown action DCID"))?;
        if connection.peer != peer {
            bail!("action peer does not own DCID");
        }
        let request = connection
            .mux
            .receive_request(packet)
            .map_err(|error| anyhow!("action transport input: {error:?}"))?;
        if let Some(request) = request {
            let Some((&service, body)) = request.data.split_first() else {
                bail!("empty action stream service");
            };
            if service != SERVICE_OBJECT {
                bail!("action service is not object");
            }
            if connection.transfer.is_some() {
                bail!("action object transfer already active");
            }
            let get = decode_get(body).ok_or_else(|| anyhow!("invalid action object GET"))?;
            let records = self.objects.response_records(get)?;
            connection
                .mux
                .complete_request(request.stream_id, request.data.len())
                .map_err(|error| anyhow!("action request accounting: {error:?}"))?;
            connection.transfer = Some(ObjectRecordStream::new(records));
        }
        Self::drain(connection, self.object_chunk)
    }

    fn accept_open(&mut self, peer: [u8; 6], packet: &[u8]) -> Result<Vec<Vec<u8>>> {
        let (_, open) = quic_lite::decode_bootstrap_open_packet_with_limits(packet)
            .map_err(|error| anyhow!("invalid action bootstrap: {error:?}"))?;
        if self.connections.len() >= MAX_CONNECTIONS {
            bail!("action connection capacity");
        }
        let client_cid = open.client_receive_cid;
        let server_cid = self.allocate_cid(client_cid)?;
        let mut mux = StreamMux::new_with_history_capacity(
            Role::Server,
            ConnectionLimits::default(),
            MTU as u64,
            16,
            8,
            256 * 1024,
            512,
        );
        mux.install_connection_ids(server_cid, client_cid)
            .map_err(|error| anyhow!("action bootstrap CIDs: {error:?}"))?;
        mux.endpoint
            .set_initial_peer_budget(
                open.max_data,
                open.max_stream_data,
                open.max_in_flight_packets,
            )
            .map_err(|error| anyhow!("action bootstrap credit: {error:?}"))?;
        let mut ack = [0u8; MTU];
        let used = quic_lite::encode_bootstrap_open_ack_packet_with_limits(
            client_cid,
            server_cid,
            0,
            ConnectionLimits::default(),
            &mut ack,
        )
        .map_err(|error| anyhow!("action bootstrap ACK: {error:?}"))?;
        self.connections.insert(
            server_cid.value(),
            Connection {
                peer,
                mux,
                transfer: None,
            },
        );
        Ok(vec![ack[..used].to_vec()])
    }

    fn allocate_cid(&mut self, avoid: ConnectionId) -> Result<ConnectionId> {
        for _ in 0..1024 {
            let value = self.next_cid;
            self.next_cid = self.next_cid.saturating_add(1);
            if let Some(cid) = ConnectionId::new(value)
                && cid != avoid
                && !self.connections.contains_key(&cid.value())
            {
                return Ok(cid);
            }
        }
        bail!("action CID exhausted")
    }

    fn drain(connection: &mut Connection, object_chunk: usize) -> Result<Vec<Vec<u8>>> {
        let mut output = Vec::new();
        let mut control = [0u8; MTU];
        if let Some(used) = connection
            .mux
            .endpoint
            .poll_transmit(&mut control)
            .map_err(|error| anyhow!("action control output: {error:?}"))?
        {
            output.push(control[..used].to_vec());
        }
        let mut packet = [0u8; MTU];
        while let Some(transfer) = connection.transfer.as_mut() {
            if connection.mux.endpoint.history_len() >= connection.mux.endpoint.history_capacity() {
                break;
            }
            let mut bytes = [0u8; OBJECT_CHUNK];
            let Some(chunk) = transfer.copy_next(&mut bytes[..object_chunk]) else {
                connection.transfer = None;
                break;
            };
            let peer = connection
                .mux
                .endpoint
                .peer_connection_id()
                .ok_or_else(|| anyhow!("action missing peer CID"))?;
            connection
                .mux
                .endpoint
                .open_send_stream(OBJECT_STREAM, quic_lite::INITIAL_MAX_STREAM_DATA)
                .ok();
            let (used, _) = match connection.mux.endpoint.encode_stream_packet(
                peer,
                OBJECT_STREAM,
                chunk.offset,
                chunk.fin,
                &bytes[..chunk.len],
                &mut packet,
            ) {
                Ok(value) => value,
                Err(quic_lite::Error::FlowControl | quic_lite::Error::Invalid) => break,
                Err(error) => return Err(anyhow!("action object packet: {error:?}")),
            };
            if !transfer.advance(chunk) {
                bail!("action object stream advancement failed");
            }
            output.push(packet[..used].to_vec());
            if transfer.is_complete() {
                connection.transfer = None;
                break;
            }
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_server_bootstraps_by_dcid_and_binds_the_peer_mac() {
        let directory = tempfile::tempdir().unwrap();
        let mut server = ActionServer::new(ServerConfig {
            artifact_root: directory.path().to_owned(),
            ..ServerConfig::default()
        });
        let client = ConnectionId::new(17).unwrap();
        let mut open = [0u8; MTU];
        let used = quic_lite::encode_bootstrap_open_packet_with_limits(
            client,
            0,
            ConnectionLimits::default(),
            &mut open,
        )
        .unwrap();
        let peer = [1, 2, 3, 4, 5, 6];
        let response = server.receive(peer, &open[..used]).unwrap();
        assert_eq!(server.connection_count(), 1);
        assert_eq!(response.len(), 1);
        let (_, ack) =
            quic_lite::decode_bootstrap_open_ack_packet_with_limits(&response[0], client).unwrap();
        assert_ne!(ack.server_receive_cid, client);
        assert!(server.receive([6, 5, 4, 3, 2, 1], &response[0]).is_err());
    }

    #[test]
    fn action_server_rejects_non_object_application_services() {
        let directory = tempfile::tempdir().unwrap();
        let mut server = ActionServer::new(ServerConfig {
            artifact_root: directory.path().to_owned(),
            ..ServerConfig::default()
        });
        let client = ConnectionId::new(17).unwrap();
        let mut open = [0u8; MTU];
        let used = quic_lite::encode_bootstrap_open_packet_with_limits(
            client,
            0,
            ConnectionLimits::default(),
            &mut open,
        )
        .unwrap();
        let peer = [1, 2, 3, 4, 5, 6];
        let response = server.receive(peer, &open[..used]).unwrap();
        let (_, ack) =
            quic_lite::decode_bootstrap_open_ack_packet_with_limits(&response[0], client).unwrap();
        let mut endpoint = quic_lite::EndpointState::<8, 8>::new(
            Role::Client,
            ConnectionLimits::default(),
            MTU as u64,
        );
        endpoint
            .install_connection_ids(client, ack.server_receive_cid)
            .unwrap();
        endpoint
            .set_initial_peer_budget(ack.max_data, ack.max_stream_data, 8)
            .unwrap();
        endpoint.continue_packet_numbers_from(1).unwrap();
        endpoint
            .open_send_stream(4, quic_lite::INITIAL_MAX_STREAM_DATA)
            .unwrap();
        let mut packet = [0u8; MTU];
        let (used, _) = endpoint
            .encode_stream_packet(ack.server_receive_cid, 4, 0, true, &[0xff], &mut packet)
            .unwrap();
        assert!(server.receive(peer, &packet[..used]).is_err());
    }
}
