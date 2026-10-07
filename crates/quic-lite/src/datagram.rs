//! RFC 9221 opaque, pool-backed DATAGRAMs. No application routing lives here.
use crate::bearer::OwnedPacket;
use crate::{Error, Frame, QuicAssociation, QuicNodeEgressError};
use core::ops::Range;

/// Admission/scheduling priority, never a delivery guarantee.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatagramPriority {
    /// Spare capacity only; reliable connection credit is an advisory signal.
    Low,
    /// Immediate admission, still subject to congestion, pacing and pool limits.
    High,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{vec, vec::Vec};

    #[test]
    fn both_wire_types_roundtrip_empty_and_binary_payloads_and_truncation() {
        for data in [&b""[..], &b"opaque\0\xff"[..], &vec![0x5a; 1024][..]] {
            for length in [false, true] {
                let mut output = vec![0; data.len() + 16];
                let frame = Frame::Datagram { data, length };
                let used = frame.encode(&mut output).unwrap();
                assert_eq!(crate::decode_frame(&output[..used]), Ok((frame, used)));
            }
        }
        assert!(crate::decode_frame(&[0x31]).is_err());
        assert!(crate::decode_frame(&[0x31, 5, 1, 2]).is_err());
        assert_eq!(
            crate::decode_frame(&[0x30, 0x31, 0]),
            Ok((
                Frame::Datagram {
                    data: &[0x31, 0],
                    length: false
                },
                3
            ))
        );
    }

    #[test]
    fn negotiation_preserves_legacy_profiles_and_roundtrips_extensions() {
        for reset in [false, true] {
            for request in [false, true] {
                for size in [0, 1100, 65535, (1 << 62) - 1] {
                    let limits = crate::ConnectionLimits {
                        max_datagram_frame_size: size,
                        ..crate::ConnectionLimits::default()
                    };
                    let token = reset.then_some(crate::StatelessResetToken([7; 16]));
                    let request = request.then_some(crate::ReceiveWindowRequest {
                        max_data: 1024,
                        max_stream_data: 256,
                    });
                    let mut output = [0; 128];
                    let used =
                        crate::encode_bootstrap_profile(0, limits, 8, token, request, &mut output)
                            .unwrap();
                    let (decoded, packets, decoded_token, decoded_request) =
                        crate::decode_bootstrap_profile(&output[..used], 0).unwrap_or_else(
                            |error| {
                                panic!(
                                    "reset={reset} request={request:?} size={size} error={error:?}"
                                )
                            },
                        );
                    assert_eq!(decoded.max_datagram_frame_size, size);
                    assert_eq!(
                        (packets, decoded_token, decoded_request),
                        (8, token, request)
                    );
                    assert_eq!(output[1] & 4 != 0, size != 0);
                    // Server replies carry the same unidirectional capability.
                    let used =
                        crate::encode_bootstrap_profile(1, limits, 8, token, None, &mut output)
                            .unwrap();
                    assert_eq!(
                        crate::decode_bootstrap_profile(&output[..used], 1)
                            .unwrap()
                            .0
                            .max_datagram_frame_size,
                        size
                    );
                }
            }
        }
        // Profile 4: ordinary values followed by repeated 0x20 parameters.
        assert!(
            crate::decode_bootstrap_profile(&[0, 4, 9, 1, 1, 1, 0x20, 1, 1, 0x20, 1, 1], 0)
                .is_err()
        );
        assert!(crate::decode_bootstrap_profile(&[0, 4, 6, 1, 1, 1, 0x20, 8, 1], 0).is_err());
    }
}

/// Refused admission returns the original, unmodified payload lease.
#[derive(Debug)]
pub struct DatagramSendError<B> {
    /// Admission reason; no payload bytes or range have changed.
    pub reason: QuicNodeEgressError,
    /// Original payload lease, available for retry or another bearer.
    pub packet: OwnedPacket<B>,
}

/// One received opaque payload with exclusive packet ownership.
/// Dropping it returns storage to the pool; retaining it uses no stream credit.
pub struct ReceivedDatagram<B> {
    /// Local association that authenticated/admitted the packet.
    pub association: QuicAssociation,
    /// Original bearer/peer and receive timestamp, not application metadata.
    pub meta: crate::PacketMeta,
    /// Payload range only, with available prefix/suffix storage preserved.
    /// May be reframed and passed directly to a bearer by the handler.
    pub packet: OwnedPacket<B>,
}

pub(crate) fn payloads(bytes: &[u8], frames_at: usize) -> impl Iterator<Item = &[u8]> {
    let mut tail = &bytes[frames_at..];
    core::iter::from_fn(move || {
        while !tail.is_empty() {
            let (frame, used) = crate::decode_frame(tail).ok()?;
            tail = &tail[used..];
            if let Frame::Datagram { data, .. } = frame {
                return Some(data);
            }
        }
        None
    })
}

impl<const P: usize> crate::EndpointState<P> {
    pub(crate) fn set_peer_datagram_limit(&mut self, size: u64) {
        self.peer_max_datagram_frame_size = size;
    }

    /// Validate all admission before touching the caller's payload bytes.
    pub(crate) fn datagram_send_layout(
        &self,
        path_id: usize,
        payload: Range<usize>,
        storage_len: usize,
        prefix: usize,
        suffix: usize,
        mtu: usize,
        priority: DatagramPriority,
    ) -> Result<(Range<usize>, [u8; 16], usize), Error> {
        if self.is_closed() {
            return Err(Error::Invalid);
        }
        let path = self.paths.get(path_id).ok_or(Error::PathLimit)?;
        if self.peer_max_datagram_frame_size == 0 {
            return Err(Error::DatagramUnsupported);
        }
        let frame_len = 1 + payload.len(); // 0x30: extends to packet end.
        if frame_len as u64 > self.peer_max_datagram_frame_size {
            return Err(Error::DatagramTooLarge);
        }
        let mut header = [0; 16];
        let mut len = crate::ShortHeader {
            flags: crate::FLAG_FIXED,
            dcid: self
                .peer_connection_id_on_path(path_id)
                .ok_or(Error::WrongConnectionId)?,
            packet_number: self.next_packet_number,
            packet_number_len: self.next_packet_number_len(),
        }
        .encode(&mut header)?;
        header[len] = 0x30;
        len += 1;
        let start = payload
            .start
            .checked_sub(len)
            .ok_or(Error::BufferTooSmall)?;
        let tag = self.datagram_tag_len();
        let end = payload.end.checked_add(tag).ok_or(Error::BufferTooSmall)?;
        let size = end - start;
        if size > mtu || size as u64 > path.congestion.max_packet_size {
            return Err(Error::DatagramTooLarge);
        }
        if start < prefix || end.checked_add(suffix).is_none_or(|end| end > storage_len) {
            return Err(Error::BufferTooSmall);
        }
        if priority == DatagramPriority::Low
            && self.send.max_data.saturating_sub(self.send.sent_data)
                <= path.congestion.max_packet_size
        {
            return Err(Error::Blocked);
        }
        self.next_packet_number
            .checked_add(1)
            .ok_or(Error::PacketNumberExhausted)?;
        if self.in_flight_packet_count() >= self.peer_max_in_flight_packets
            || !path.congestion.can_send(size as u64)
        {
            return Err(Error::Blocked);
        }
        if !self
            .sent_packets
            .iter()
            .take(self.transmission_limit)
            .any(Option::is_none)
        {
            return Err(Error::HistoryFull);
        }
        if path.next_send_order == u64::MAX {
            return Err(Error::PacketNumberExhausted);
        }
        Ok((start..end, header, len))
    }

    pub(crate) fn datagram_tag_len(&self) -> usize {
        #[cfg(feature = "packet-protection")]
        if self.protection.is_some() {
            return crate::crypto::AEAD_TAG_LEN;
        }
        0
    }

    /// Retain transmission metadata only: no payload, repair range or stream.
    pub(crate) fn commit_datagram_transmission(
        &mut self,
        path_id: usize,
        size: usize,
    ) -> Result<(), Error> {
        let slot = self
            .sent_packets
            .iter()
            .take(self.transmission_limit)
            .position(Option::is_none)
            .ok_or(Error::HistoryFull)?;
        let path = &mut self.paths[path_id];
        let window_limited = path
            .congestion
            .bytes_in_flight
            .saturating_add(size as u64)
            .saturating_add(path.congestion.max_packet_size)
            > path.congestion.congestion_window;
        if !path.try_reserve_pacing(size as u64, path.send_clock) {
            return Err(Error::Blocked);
        }
        let send_order = path.assign_send_order()?;
        if !path.congestion.on_packet_sent(size as u64) {
            return Err(Error::Blocked);
        }
        let packet_number = self.next_packet_number;
        self.next_packet_number += 1;
        self.sent_packets[slot] = Some(crate::SentPacket {
            packet_number,
            path_id,
            send_order,
            bytes: size as u64,
            stream_id: 0,
            offset: 0,
            data_len: 0,
            fin: false,
            priority_stream: false,
            path_probe: false,
            probe_idle_exempt: false,
            send_buffer_slot: None,
            probe_token: None,
            path_status: None,
            rtt_eligible: true,
            logical_packet_number: packet_number,
            duplication_charge: 0,
            duplication_budget_committed: false,
            sent_at: path.send_clock,
            accepted: true,
            window_limited,
            lost: false,
            inferred_lost: false,
            data_delivered: true,
        });
        let now = self.paths[path_id].send_clock;
        self.record_congestion_packet(path_id, packet_number, now, size, false, false);
        self.stats.sent_packets += 1;
        Ok(())
    }
}
