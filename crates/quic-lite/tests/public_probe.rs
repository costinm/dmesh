#![deny(deprecated)]

//! External coverage for the transport-neutral probe workload.
//!
//! The probe is intentionally public because the same ordered-byte workload is
//! run over QUIC, TCP, HTTP, or SSH. Keeping this test outside the crate proves
//! it needs no QUIC packet or connection internals.

use quic_lite::probe::{ProbeError, ProbeReceiver, ProbeRun, ProbeSender};

#[test]
fn sender_and_receiver_exchange_multiple_flow_controlled_chunks() {
    let mut sender = ProbeSender::new(11, 21, 8).unwrap();
    let mut receiver = ProbeReceiver::new(2);
    let mut scratch = [0u8; 16];

    assert!(sender.prepare(0, &mut scratch).is_none());
    assert_eq!(sender.bytes_sent(), 0);
    while !sender.is_complete() {
        let chunk = sender.prepare(8, &mut scratch).unwrap();
        assert_eq!(chunk.stream_id, 11);
        assert_eq!(chunk.offset, sender.bytes_sent());
        assert_eq!(
            receiver.receive(chunk.offset, chunk.fin, &scratch[..chunk.len]),
            Ok(chunk.len)
        );
        sender.commit(chunk).unwrap();
    }

    assert!(receiver.is_complete());
    assert_eq!(receiver.bytes(), 21);
    assert_eq!(receiver.callback_errors(), &[0; 6]);
}

#[test]
fn prepared_range_is_unchanged_until_transport_accepts_it() {
    let mut sender = ProbeSender::new(3, 12, 8).unwrap();
    let mut scratch = [0u8; 8];
    let first = sender.prepare(8, &mut scratch).unwrap();
    assert_eq!(sender.prepare(8, &mut scratch), Some(first));
    assert_eq!(sender.bytes_sent(), 0);

    sender.commit(first).unwrap();
    assert_eq!(sender.commit(first), Err(ProbeError::UnexpectedRange));
    assert_eq!(sender.bytes_sent(), 8);
}

#[test]
fn run_routes_normal_and_optional_priority_streams() {
    let mut run = ProbeRun::<4>::new(0, 2, true, true);
    let first_stream = 7;

    for stream in [7, 11, 15, 19] {
        let complete = run
            .receive(first_stream, stream, 0, true, &[0, 0, 0, 0])
            .unwrap()
            .0;
        assert_eq!(complete, stream == 19);
    }
    assert!(run.is_complete());
    assert_eq!(run.normal_bytes(), 8);
    assert_eq!(run.high_bytes(), 4);
    assert_eq!(run.low_bytes(), 4);
    assert_eq!(run.bytes(), 16);
    assert_eq!(run.callback_errors(), [0; 6]);
    assert_eq!(
        run.receive(first_stream, 23, 0, true, &[0, 0, 0, 0]),
        Err(ProbeError::UnexpectedStream)
    );
}

#[test]
fn invalid_payload_is_reported_without_advancing_receiver() {
    let mut receiver = ProbeReceiver::new(1);
    assert_eq!(
        receiver.receive(0, true, &[0, 0, 0, 1]),
        Err(ProbeError::InvalidPayload)
    );
    assert_eq!(receiver.bytes(), 0);
    assert!(!receiver.is_complete());
    assert_eq!(receiver.callback_errors()[5], 1);
}

#[test]
fn invalid_probe_configuration_is_rejected() {
    assert!(ProbeSender::new(3, 0, 8).is_none());
    assert!(ProbeSender::new(3, 8, 3).is_none());
}
