//! Opt-in diagnostics using the real private wire decoder, not a second codec.

use crate::{Frame, ShortHeader, decode_frame};
use std::collections::{BTreeMap, BTreeSet};
use std::vec::Vec;

#[derive(Default)]
struct Direction {
    expected: u32,
    dcid: Option<u64>,
    packets: usize,
    bytes: usize,
    stream_bytes: usize,
    repeated_bytes: usize,
    sent: BTreeMap<u32, (u64, bool)>,
    acknowledged: BTreeSet<u32>,
    ack_elapsed: Vec<u64>,
    streams: BTreeMap<u64, Vec<(u64, u64)>>,
}

fn insert_range(ranges: &mut Vec<(u64, u64)>, start: u64, len: usize) -> usize {
    let end = start + len as u64;
    let overlap: u64 = ranges
        .iter()
        .map(|&(a, b)| end.min(b).saturating_sub(start.max(a)))
        .sum();
    ranges.push((start, end));
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for &(a, b) in ranges.iter() {
        if let Some(last) = merged.last_mut().filter(|last| last.1 >= a) {
            last.1 = last.1.max(b);
        } else {
            merged.push((a, b));
        }
    }
    *ranges = merged;
    overlap as usize
}

#[test]
fn capture_range_union_counts_partial_retransmissions() {
    let mut ranges = Vec::new();
    assert_eq!(insert_range(&mut ranges, 100, 100), 0);
    assert_eq!(insert_range(&mut ranges, 150, 100), 50);
    assert_eq!(insert_range(&mut ranges, 0, 300), 150);
    assert_eq!(insert_range(&mut ranges, 120, 20), 20);
    assert_eq!(ranges, [(0, 300)]);
}

#[test]
#[ignore = "set QUIC_ANALYZE_PCAP to a QUIC-lite cooked-v2 capture"]
fn analyze_stream_capture() {
    let path = std::env::var("QUIC_ANALYZE_PCAP").expect("QUIC_ANALYZE_PCAP");
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(&bytes[..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
    let word = |p: usize| u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
    assert_eq!(word(20), 276, "Linux cooked-v2 capture required");
    let mut directions: [Direction; 2] = core::array::from_fn(|_| Direction::default());
    let mut cursor = 24;
    let mut base = None;
    let mut end = 0;
    let mut accepted_submissions = 0;
    let mut blocked_submissions = 0;
    let mut unresolved_submissions = 0;
    let mut legacy_submissions = 0;
    while cursor < bytes.len() {
        let time = u64::from(word(cursor)) * 1_000_000 + u64::from(word(cursor + 4));
        let len = word(cursor + 8) as usize;
        let packet = &bytes[cursor + 16..cursor + 16 + len];
        cursor += 16 + len;
        let time = time - *base.get_or_insert(time);
        end = time;
        assert!(packet.len() >= 20);
        let direction = match packet[10] {
            4 => 1, // host submission
            0 => 0, // host receipt
            other => panic!("packet type {other}"),
        };
        if direction == 1 {
            if packet[11] == 1 {
                match packet[12] {
                    1 => accepted_submissions += 1,
                    2 => blocked_submissions += 1,
                    _ => unresolved_submissions += 1,
                }
                if packet[12] != 1 {
                    std::println!("SUBMISSION time_us={time} outcome={} bytes={}", packet[12], packet.len() - 20);
                    continue; // Busy/unresolved attempts are not transmitted packets.
                }
            } else {
                legacy_submissions += 1;
            }
        }
        let payload = &packet[20..];
        if payload.first().is_none_or(|flags| flags & 0x80 != 0) {
            continue; // Initial has a distinct packet-number space.
        }
        let (header, mut p) =
            ShortHeader::decode_with_expected(payload, directions[direction].expected).unwrap();
        let state = &mut directions[direction];
        assert_eq!(
            *state.dcid.get_or_insert(header.dcid.value()),
            header.dcid.value(),
            "analyzer requires a single-circuit, single-association capture"
        );
        state.expected = state.expected.max(header.packet_number + 1);
        state.packets += 1;
        state.bytes += payload.len();
        std::println!("PACKET,{time},{direction},{},{}", header.packet_number, payload.len());
        let mut frame_offset = p;
        let mut ack_eliciting = false;
        while frame_offset < payload.len() {
            let (frame, used) = decode_frame(&payload[frame_offset..]).unwrap();
            ack_eliciting |= !matches!(
                frame,
                Frame::Ack { .. } | Frame::AckRanges { .. } | Frame::Padding | Frame::Close { .. }
            );
            frame_offset += used;
        }
        state
            .sent
            .insert(header.packet_number, (time, ack_eliciting));
        while p < payload.len() {
            let (frame, used) = decode_frame(&payload[p..]).unwrap();
            p += used;
            let mut acknowledge = |largest: u32, delay: u64, ranges: &[(u32, u32)]| {
                let other = &mut directions[1 - direction];
                let mut new = 0;
                for &(start, stop) in ranges {
                    for (&pn, &(sent_at, ack_eliciting)) in other.sent.range(start..=stop) {
                        if other.acknowledged.insert(pn) {
                            if ack_eliciting {
                                other.ack_elapsed.push(time.saturating_sub(sent_at));
                            }
                            new += 1;
                        }
                    }
                }
                let elapsed = other
                    .sent
                    .get(&largest)
                    .map(|(sent_at, _)| time.saturating_sub(*sent_at));
                std::println!(
                    "ACK,{time},{direction},{},{largest},{delay},{new},{elapsed:?},{ranges:?}",
                    header.packet_number
                );
            };
            match frame {
                Frame::Stream(stream) => {
                    let state = &mut directions[direction];
                    let overlap = insert_range(
                        state.streams.entry(stream.id).or_default(),
                        stream.offset,
                        stream.data.len(),
                    );
                    state.stream_bytes += stream.data.len();
                    state.repeated_bytes += overlap;
                    std::println!(
                        "STREAM,{time},{direction},{},{},{},{},{},{overlap}",
                        header.packet_number,
                        stream.id,
                        stream.offset,
                        stream.data.len(),
                        stream.fin
                    );
                    // Opt-in bounded preview for diagnosing application envelopes.
                    // Keep pacing records unchanged and avoid dumping full bodies.
                    if std::env::var_os("QUIC_ANALYZE_STREAM_PREFIX").is_some()
                        && stream.offset == 0
                    {
                        let prefix: std::string::String = stream.data.iter().take(96)
                            .map(|byte| std::format!("{byte:02x}"))
                            .collect();
                        std::println!("STREAM_PREFIX,{time},{direction},{},{prefix}", stream.id);
                    }
                }
                Frame::Ack { largest, delay } => acknowledge(largest, delay, &[(largest, largest)]),
                Frame::AckRanges {
                    largest,
                    delay,
                    ranges,
                } => {
                    let spans: Vec<_> = (0..ranges.len())
                        .map(|i| {
                            let range = ranges.get(i).unwrap();
                            (range.start, range.end)
                        })
                        .collect();
                    acknowledge(largest, delay, &spans);
                }
                Frame::MaxStreamData { id, max } => {
                    std::println!(
                        "CREDIT,{time},{direction},{},{id},{max}",
                        header.packet_number
                    );
                }
                Frame::MaxData(max) => {
                    std::println!(
                        "CONNECTION_CREDIT,{time},{direction},{},{max}",
                        header.packet_number
                    );
                }
                _ => {}
            }
        }
    }
    std::println!("CAPTURE accepted_submissions={accepted_submissions} blocked_submissions={blocked_submissions} unresolved_submissions={unresolved_submissions} legacy_submissions={legacy_submissions}");
    for (direction, mut state) in directions.into_iter().enumerate() {
        state.ack_elapsed.sort_unstable();
        let percentile = |p: usize| {
            state
                .ack_elapsed
                .get(state.ack_elapsed.len().saturating_sub(1) * p / 100)
        };
        let unacked_ack_eliciting = state
            .sent
            .iter()
            .filter(|(pn, (_, ack_eliciting))| *ack_eliciting && !state.acknowledged.contains(pn))
            .count();
        std::println!(
            "SUMMARY direction={direction} duration_us={end} packets={} wire_bytes={} stream_bytes={} repeated_bytes={} ack_eliciting_p50_us={:?} ack_eliciting_p95_us={:?} ack_eliciting_max_us={:?} unacked_all={} unacked_ack_eliciting={unacked_ack_eliciting}",
            state.packets,
            state.bytes,
            state.stream_bytes,
            state.repeated_bytes,
            percentile(50),
            percentile(95),
            state.ack_elapsed.last(),
            state.sent.len() - state.acknowledged.len()
        );
    }
}
