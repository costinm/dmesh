//! Bearer-neutral bounded raw-datagram service primitives.
//!
//! The historical module name reflects its first consumer.  New bearers use
//! this API instead: it describes a QUIC-lite service over complete packets,
//! not a benchmark protocol or a particular radio.

pub use crate::raw_iperf::{
    RAW_ACTION_IPERF_DEFAULT_TIMEOUT_MS as RAW_ACTION_DEFAULT_TIMEOUT_MS,
    RAW_ACTION_IPERF_MAX_TIMEOUT_MS as RAW_ACTION_MAX_TIMEOUT_MS,
    RawAssociationProfile as RawAssociation, RawCheckClient, RawIngressPath as IngressPath,
    RawIperfClient as RawClient, RawIperfDispatcher as RawServiceDispatcher,
    RawIperfServer as RawService, RawObjectClient, RawServiceCounters, receive_error_code,
};

/// Result of driving a bounded service egress burst.
///
/// The connection keeps retransmission history; this only centralizes the
/// adapter contract shared by raw UDP6, action frames, and UART: never send
/// more than the caller's credit and stop at the first local submission
/// failure. It deliberately stores no packets or peers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EgressPumpResult {
    pub sent: usize,
    pub invalid_length: bool,
    pub submit_failed: bool,
}

/// Submit an optional immediate response and then poll up to the remaining
/// packet credit. A credit of one therefore still polls once when ingress
/// produced no immediate response, which is required for delayed ACK/PTO
/// progress on packet-at-a-time bearers.
pub fn pump_egress<const N: usize, P, T>(
    response: &mut [u8; N],
    packet_credit: usize,
    immediate: Option<usize>,
    mut poll: P,
    mut submit: T,
) -> EgressPumpResult
where
    P: FnMut(&mut [u8; N]) -> Option<usize>,
    T: FnMut(&[u8]) -> bool,
{
    let mut result = EgressPumpResult::default();
    let mut remaining = packet_credit;
    macro_rules! submit_one {
        ($used:expr) => {{
            let used = $used;
            if used > response.len() {
                result.invalid_length = true;
                false
            } else if !submit(&response[..used]) {
                result.submit_failed = true;
                false
            } else {
                result.sent += 1;
                remaining = remaining.saturating_sub(1);
                true
            }
        }};
    }
    if let Some(used) = immediate {
        if !submit_one!(used) {
            return result;
        }
    }
    while remaining != 0 {
        let Some(used) = poll(response) else {
            break;
        };
        if !submit_one!(used) {
            break;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::pump_egress;

    #[test]
    fn one_credit_polls_when_ingress_has_no_response() {
        let mut response = [0; 8];
        let mut polls = 0;
        let mut sent = 0;
        let result = pump_egress(
            &mut response,
            1,
            None,
            |out| {
                polls += 1;
                out[..2].copy_from_slice(b"ok");
                (polls == 1).then_some(2)
            },
            |packet| {
                sent += 1;
                packet == b"ok"
            },
        );
        assert_eq!(polls, 1);
        assert_eq!(sent, 1);
        assert_eq!(result.sent, 1);
    }

    #[test]
    fn immediate_response_consumes_credit() {
        let mut response = [0; 8];
        response[..2].copy_from_slice(b"ok");
        let mut polled = false;
        let result = pump_egress(
            &mut response,
            1,
            Some(2),
            |_| {
                polled = true;
                None
            },
            |packet| packet == b"ok",
        );
        assert_eq!(result.sent, 1);
        assert!(!polled);
    }
}
