//! Deterministic local datagram bearer for conformance and fault testing.
//! It transports opaque datagrams; stream operations are built by the caller.

use std::collections::VecDeque;
use std::vec;
use std::vec::Vec;

use crate::mux::StreamMux;
use crate::{
    ConnectionId, ConnectionLimits, DatagramBearer, Error, Role, SERVICE_ECHO, SERVICE_EVENTS,
    SERVICE_IPERF, SERVICE_METRICS, SERVICE_STREAM,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamOperation {
    Echo,
    Iperf,
    Metrics,
    Events,
    Registry,
}

impl StreamOperation {
    fn service(self) -> u8 {
        match self {
            Self::Echo => SERVICE_ECHO,
            Self::Iperf => SERVICE_IPERF,
            Self::Metrics => SERVICE_METRICS,
            Self::Events => SERVICE_EVENTS,
            Self::Registry => SERVICE_STREAM,
        }
    }

    fn body(self) -> &'static [u8] {
        match self {
            Self::Echo | Self::Metrics | Self::Registry => b"",
            Self::Iperf => b"\0\0\0\0\0\0\0\x20payload",
            Self::Events => b"since=0",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationResult {
    pub stream_id: u64,
    pub operation: StreamOperation,
    pub response: Vec<u8>,
}

/// Errors returned by the bearer-neutral operation harness.  Transport
/// failures are kept separate from adapter failures so a NAN/UDP/remote test
/// runner can preserve its native I/O error type and still use the same
/// operation script.
#[derive(Debug)]
pub enum OperationHarnessError<C, S> {
    ClientBearer(C),
    ServerBearer(S),
    Transport(Error),
}

/// Drive stream operations through the same mux/handler path used by a
/// bearer adapter. A NAN or remote-device runner can replace this fake link
/// while retaining the operation list and response assertions.
pub fn run_stream_operations(
    operations: &[StreamOperation],
    faults: FaultConfig,
) -> Result<Vec<OperationResult>, Error> {
    let mut c2s = FakeDatagramLink::new(faults);
    let mut s2c = FakeDatagramLink::new(faults);
    run_stream_operations_with_bearers(operations, &mut c2s, &mut s2c, faults.latency_ticks.max(1))
}

/// Run the operation script over caller-supplied datagram bearers. This is
/// the seam used by NAN, device, and remote test runners: they replace only
/// the two bearer values while retaining the same stream IDs, handlers,
/// event polling, and response assertions.
pub fn run_stream_operations_with_bearers<C2S, S2C>(
    operations: &[StreamOperation],
    c2s: &mut C2S,
    s2c: &mut S2C,
    tick: u64,
) -> Result<Vec<OperationResult>, Error>
where
    C2S: DatagramBearer<Error = Error>,
    S2C: DatagramBearer<Error = Error>,
{
    run_stream_operations_with_external_bearers(
        operations,
        c2s,
        s2c,
        tick,
        ConnectionId::new(0x501).ok_or(Error::Invalid)?,
        ConnectionId::new(0x502).ok_or(Error::Invalid)?,
    )
    .map_err(|error| match error {
        OperationHarnessError::ClientBearer(error) | OperationHarnessError::ServerBearer(error) => {
            error
        }
        OperationHarnessError::Transport(error) => error,
    })
}

/// Run the same operation script with explicitly selected directional CIDs.
/// Remote and multi-connection conformance harnesses use this entry point to
/// prove that two simultaneous sessions cannot cross-deliver stream responses.
pub fn run_stream_operations_with_bearers_and_cids<C2S, S2C>(
    operations: &[StreamOperation],
    c2s: &mut C2S,
    s2c: &mut S2C,
    tick: u64,
    client_cid: ConnectionId,
    server_cid: ConnectionId,
) -> Result<Vec<OperationResult>, Error>
where
    C2S: DatagramBearer<Error = Error>,
    S2C: DatagramBearer<Error = Error>,
{
    run_stream_operations_with_external_bearers(operations, c2s, s2c, tick, client_cid, server_cid)
        .map_err(|error| match error {
            OperationHarnessError::ClientBearer(error)
            | OperationHarnessError::ServerBearer(error) => error,
            OperationHarnessError::Transport(error) => error,
        })
}

/// Generic operation runner for adapters whose native client/server errors
/// differ from the core transport error (for example NAN uses `anyhow::Error`
/// while a remote test bridge may use a command/RPC error).  The operation
/// sequence and response assertions remain identical across bearers.
pub fn run_stream_operations_with_external_bearers<C2S, S2C>(
    operations: &[StreamOperation],
    c2s: &mut C2S,
    s2c: &mut S2C,
    tick: u64,
    client_cid: ConnectionId,
    server_cid: ConnectionId,
) -> Result<Vec<OperationResult>, OperationHarnessError<C2S::Error, S2C::Error>>
where
    C2S: DatagramBearer,
    S2C: DatagramBearer,
{
    let mut client = StreamMux::<8, 8>::new(
        Role::Client,
        ConnectionLimits::default(),
        1200,
        32,
        8,
        16 * 1024,
    );
    let mut server = StreamMux::<8, 8>::new(
        Role::Server,
        ConnectionLimits::default(),
        1200,
        32,
        8,
        16 * 1024,
    );
    client
        .install_connection_ids(client_cid, server_cid)
        .map_err(OperationHarnessError::Transport)?;
    server
        .install_connection_ids(server_cid, client_cid)
        .map_err(OperationHarnessError::Transport)?;
    let mut results = Vec::new();
    let mut now = 0;
    let tick = tick.max(1);
    for (index, operation) in operations.iter().copied().enumerate() {
        let stream_id = 4 + index as u64 * 4;
        client
            .endpoint
            .open_send_stream(stream_id, crate::INITIAL_MAX_STREAM_DATA)
            .map_err(OperationHarnessError::Transport)?;
        let mut request = Vec::from([operation.service()]);
        request.extend_from_slice(operation.body());
        let mut packet = vec![0u8; 1400];
        let (used, _) = client
            .endpoint
            .encode_stream_packet(server_cid, stream_id, 0, true, &request, &mut packet)
            .map_err(OperationHarnessError::Transport)?;
        c2s.send_datagram(now, &packet[..used])
            .map_err(OperationHarnessError::ClientBearer)?;
        let mut incoming = vec![0u8; 1400];
        let mut response = None;
        for attempt in 0..16 {
            if let Some(length) = c2s
                .receive_datagram(now, &mut incoming)
                .map_err(OperationHarnessError::ClientBearer)?
            {
                if let Some(candidate) = server
                    .receive_datagram(&incoming[..length])
                    .map_err(OperationHarnessError::Transport)?
                {
                    if candidate.stream_id == stream_id {
                        response = Some(candidate);
                        break;
                    }
                }
            }
            if attempt == 15 {
                break;
            }
            now = now.saturating_add(tick);
            c2s.send_datagram(now, &packet[..used])
                .map_err(OperationHarnessError::ClientBearer)?;
        }
        let response = response.ok_or(OperationHarnessError::Transport(Error::Invalid))?;
        let mut response_packet = vec![0u8; 1400];
        let (response_len, _) = server
            .encode_response(
                1 + index as u64 * 4,
                &response.data,
                true,
                &mut response_packet,
            )
            .map_err(OperationHarnessError::Transport)?;
        s2c.send_datagram(now, &response_packet[..response_len])
            .map_err(OperationHarnessError::ServerBearer)?;
        let mut outgoing = vec![0u8; 1400];
        let mut result = None;
        for attempt in 0..16 {
            if let Some(length) = s2c
                .receive_datagram(now, &mut outgoing)
                .map_err(OperationHarnessError::ServerBearer)?
            {
                if let crate::TransportPacket::Stream { frame, .. } = client
                    .endpoint
                    .receive_datagram(&outgoing[..length])
                    .map_err(OperationHarnessError::Transport)?
                {
                    if frame.id == 1 + index as u64 * 4 {
                        result = Some(frame.data.to_vec());
                        break;
                    }
                }
            }
            if attempt == 15 {
                break;
            }
            now = now.saturating_add(tick);
            s2c.send_datagram(now, &response_packet[..response_len])
                .map_err(OperationHarnessError::ServerBearer)?;
        }
        let response_bytes = result.ok_or(OperationHarnessError::Transport(Error::Invalid))?;
        results.push(OperationResult {
            stream_id,
            operation,
            response: response_bytes,
        });
    }
    Ok(results)
}

#[derive(Clone, Copy, Debug)]
pub struct FaultConfig {
    pub latency_ticks: u64,
    pub drop_every: Option<u64>,
    pub duplicate: bool,
    pub reorder: bool,
    pub mtu: usize,
}

impl Default for FaultConfig {
    fn default() -> Self {
        Self {
            latency_ticks: 0,
            drop_every: None,
            duplicate: false,
            reorder: false,
            mtu: usize::MAX,
        }
    }
}

#[derive(Debug)]
struct QueuedDatagram {
    ready_at: u64,
    ordinal: u64,
    bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct FakeDatagramLink {
    config: FaultConfig,
    queue: VecDeque<QueuedDatagram>,
    sent: u64,
    dropped: u64,
}

impl FakeDatagramLink {
    pub fn new(config: FaultConfig) -> Self {
        Self {
            config,
            queue: VecDeque::new(),
            sent: 0,
            dropped: 0,
        }
    }

    pub fn sent(&self) -> u64 {
        self.sent
    }
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    pub fn send(&mut self, now: u64, payload: &[u8]) {
        self.sent = self.sent.saturating_add(1);
        let ordinal = self.sent;
        if self
            .config
            .drop_every
            .is_some_and(|n| n != 0 && ordinal % n == 0)
        {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        let mut bytes = payload.to_vec();
        bytes.truncate(self.config.mtu);
        let ready_at = now.saturating_add(self.config.latency_ticks);
        self.queue.push_back(QueuedDatagram {
            ready_at,
            ordinal,
            bytes: bytes.clone(),
        });
        if self.config.duplicate {
            self.queue.push_back(QueuedDatagram {
                ready_at,
                ordinal,
                bytes,
            });
        }
    }

    pub fn poll(&mut self, now: u64) -> Vec<Vec<u8>> {
        let mut ready = Vec::new();
        let mut pending = VecDeque::new();
        while let Some(datagram) = self.queue.pop_front() {
            if datagram.ready_at <= now {
                ready.push(datagram);
            } else {
                pending.push_back(datagram);
            }
        }
        self.queue = pending;
        if self.config.reorder {
            ready.sort_by_key(|entry| core::cmp::Reverse(entry.ordinal));
        }
        ready.into_iter().map(|entry| entry.bytes).collect()
    }

    fn poll_one(&mut self, now: u64) -> Option<Vec<u8>> {
        let mut selected = None;
        for (index, datagram) in self.queue.iter().enumerate() {
            if datagram.ready_at > now {
                continue;
            }
            if selected.is_none()
                || self.config.reorder
                    && datagram.ordinal
                        > self
                            .queue
                            .get(selected.unwrap())
                            .map(|value| value.ordinal)
                            .unwrap_or(0)
            {
                selected = Some(index);
            }
            if !self.config.reorder {
                break;
            }
        }
        selected.and_then(|index| self.queue.remove(index).map(|datagram| datagram.bytes))
    }
}

impl crate::DatagramBearer for FakeDatagramLink {
    type Error = crate::Error;

    fn send_datagram(&mut self, now: u64, payload: &[u8]) -> Result<(), Self::Error> {
        self.send(now, payload);
        Ok(())
    }

    fn receive_datagram(&mut self, now: u64, out: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        let Some(payload) = self.poll_one(now) else {
            return Ok(None);
        };
        if payload.len() > out.len() {
            return Err(crate::Error::BufferTooSmall);
        }
        out[..payload.len()].copy_from_slice(&payload);
        Ok(Some(payload.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::String;
    use std::vec;

    #[test]
    fn operation_runner_drives_shared_stream_handlers() {
        let results = run_stream_operations(
            &[
                StreamOperation::Echo,
                StreamOperation::Iperf,
                StreamOperation::Metrics,
                StreamOperation::Events,
                StreamOperation::Registry,
            ],
            FaultConfig {
                latency_ticks: 2,
                mtu: 1200,
                ..FaultConfig::default()
            },
        )
        .unwrap_or_else(|error| panic!("operation failed: {error:?}"));
        assert_eq!(results.len(), 5);
        assert!(String::from_utf8_lossy(&results[0].response).contains("service=2"));
        assert_eq!(results[1].response.len(), 49);
        assert_eq!(results[1].response[0], 1);
        assert_eq!(u64::from_be_bytes(results[1].response[1..9].try_into().unwrap()), 32);
        assert_eq!(u64::from_be_bytes(results[1].response[9..17].try_into().unwrap()), 7);
        assert!(String::from_utf8_lossy(&results[2].response).contains("metrics_version=1"));
        assert!(String::from_utf8_lossy(&results[3].response).contains("events_version="));
        assert!(String::from_utf8_lossy(&results[4].response).contains("echo"));
    }

    #[test]
    fn operation_runner_retries_stream_operations_under_faults() {
        let results = run_stream_operations(
            &[StreamOperation::Metrics, StreamOperation::Events],
            FaultConfig {
                latency_ticks: 3,
                drop_every: Some(2),
                duplicate: true,
                reorder: true,
                mtu: 1200,
            },
        )
        .unwrap();
        assert_eq!(results.len(), 2);
        assert!(String::from_utf8_lossy(&results[0].response).contains("metrics_version=1"));
        assert!(String::from_utf8_lossy(&results[1].response).contains("events_version="));
    }

    #[test]
    fn operation_runner_accepts_replacement_bearers() {
        struct CountingBearer {
            inner: FakeDatagramLink,
            sends: usize,
            receives: usize,
        }

        impl DatagramBearer for CountingBearer {
            type Error = Error;

            fn send_datagram(&mut self, now: u64, payload: &[u8]) -> Result<(), Self::Error> {
                self.sends += 1;
                self.inner.send_datagram(now, payload)
            }

            fn receive_datagram(
                &mut self,
                now: u64,
                out: &mut [u8],
            ) -> Result<Option<usize>, Self::Error> {
                self.receives += 1;
                self.inner.receive_datagram(now, out)
            }
        }

        let mut c2s = CountingBearer {
            inner: FakeDatagramLink::new(FaultConfig {
                latency_ticks: 1,
                ..FaultConfig::default()
            }),
            sends: 0,
            receives: 0,
        };
        let mut s2c = CountingBearer {
            inner: FakeDatagramLink::new(FaultConfig {
                latency_ticks: 1,
                ..FaultConfig::default()
            }),
            sends: 0,
            receives: 0,
        };
        let result = run_stream_operations_with_bearers(
            &[StreamOperation::Metrics, StreamOperation::Events],
            &mut c2s,
            &mut s2c,
            1,
        )
        .unwrap();
        assert_eq!(result.len(), 2);
        assert!(c2s.sends > 0 && c2s.receives > 0);
        assert!(s2c.sends > 0 && s2c.receives > 0);
    }

    #[test]
    fn operation_runner_accepts_native_errors_from_external_bearers() {
        #[derive(Debug)]
        struct ForeignError;

        struct ForeignBearer {
            inner: FakeDatagramLink,
        }

        impl DatagramBearer for ForeignBearer {
            type Error = ForeignError;

            fn send_datagram(&mut self, now: u64, payload: &[u8]) -> Result<(), Self::Error> {
                self.inner
                    .send_datagram(now, payload)
                    .map_err(|_| ForeignError)
            }

            fn receive_datagram(
                &mut self,
                now: u64,
                out: &mut [u8],
            ) -> Result<Option<usize>, Self::Error> {
                self.inner
                    .receive_datagram(now, out)
                    .map_err(|_| ForeignError)
            }
        }

        let mut c2s = ForeignBearer {
            inner: FakeDatagramLink::new(FaultConfig {
                latency_ticks: 1,
                ..FaultConfig::default()
            }),
        };
        let mut s2c = ForeignBearer {
            inner: FakeDatagramLink::new(FaultConfig {
                latency_ticks: 1,
                ..FaultConfig::default()
            }),
        };
        let result = run_stream_operations_with_external_bearers(
            &[StreamOperation::Metrics, StreamOperation::Events],
            &mut c2s,
            &mut s2c,
            1,
            ConnectionId::new(0x811).unwrap(),
            ConnectionId::new(0x822).unwrap(),
        )
        .unwrap();
        assert_eq!(result.len(), 2);
        assert!(String::from_utf8_lossy(&result[0].response).contains("metrics_version=1"));
        assert!(String::from_utf8_lossy(&result[1].response).contains("events_version="));
    }

    #[test]
    fn operation_runner_isolates_two_connections_with_multiple_streams() {
        let operations = [
            StreamOperation::Echo,
            StreamOperation::Metrics,
            StreamOperation::Events,
            StreamOperation::Iperf,
            StreamOperation::Registry,
        ];
        let faults = FaultConfig {
            latency_ticks: 4,
            drop_every: Some(3),
            duplicate: true,
            reorder: true,
            mtu: 1200,
        };
        let mut first_c2s = FakeDatagramLink::new(faults);
        let mut first_s2c = FakeDatagramLink::new(faults);
        let first = run_stream_operations_with_bearers_and_cids(
            &operations,
            &mut first_c2s,
            &mut first_s2c,
            1,
            ConnectionId::new(0x601).unwrap(),
            ConnectionId::new(0x602).unwrap(),
        )
        .unwrap();
        let mut second_c2s = FakeDatagramLink::new(faults);
        let mut second_s2c = FakeDatagramLink::new(faults);
        let second = run_stream_operations_with_bearers_and_cids(
            &operations,
            &mut second_c2s,
            &mut second_s2c,
            1,
            ConnectionId::new(0x701).unwrap(),
            ConnectionId::new(0x702).unwrap(),
        )
        .unwrap();
        assert_eq!(first.len(), operations.len());
        assert_eq!(second.len(), operations.len());
        for result in first {
            let text = String::from_utf8_lossy(&result.response);
            if result.operation == StreamOperation::Metrics {
                assert!(text.contains("connection_dcid=1538"));
            }
        }
        for result in second {
            let text = String::from_utf8_lossy(&result.response);
            if result.operation == StreamOperation::Metrics {
                assert!(text.contains("connection_dcid=1794"));
            }
        }
    }

    #[test]
    fn injects_latency_loss_duplication_reordering_and_mtu() {
        let mut link = FakeDatagramLink::new(FaultConfig {
            latency_ticks: 5,
            drop_every: Some(3),
            duplicate: true,
            reorder: true,
            mtu: 3,
        });
        link.send(0, b"one");
        link.send(0, b"two");
        link.send(0, b"three");
        assert!(link.poll(4).is_empty());
        let packets = link.poll(5);
        assert_eq!(
            packets,
            vec![
                b"two".to_vec(),
                b"two".to_vec(),
                b"one".to_vec(),
                b"one".to_vec()
            ]
        );
        assert_eq!(link.dropped(), 1);
    }

    #[test]
    fn bearer_contract_preserves_datagram_boundaries() {
        let mut link = FakeDatagramLink::new(FaultConfig {
            latency_ticks: 2,
            duplicate: true,
            ..FaultConfig::default()
        });
        crate::DatagramBearer::send_datagram(&mut link, 0, b"first").unwrap();
        let mut out = [0u8; 16];
        assert!(
            crate::DatagramBearer::receive_datagram(&mut link, 1, &mut out)
                .unwrap()
                .is_none()
        );
        let used = crate::DatagramBearer::receive_datagram(&mut link, 2, &mut out)
            .unwrap()
            .unwrap();
        assert_eq!(&out[..used], b"first");
        let duplicate = crate::DatagramBearer::receive_datagram(&mut link, 2, &mut out)
            .unwrap()
            .unwrap();
        assert_eq!(&out[..duplicate], b"first");
    }
}
