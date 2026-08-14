//! Bounded fragmentation for bearers whose service envelope is smaller than a
//! transport datagram. The fragment layer preserves datagram boundaries; it
//! does not acknowledge, retransmit, or interpret transport packets.

use alloc::vec::Vec;

use crate::Error;

#[derive(Debug)]
struct Assembly {
    key: u64,
    sequence: u16,
    total: u8,
    parts: Vec<Option<Vec<u8>>>,
    bytes: usize,
}

/// Bounded reassembly state. `S` is the maximum number of incomplete packets
/// retained simultaneously; completed packet IDs are retained in a small
/// deduplication window.
pub struct FragmentReassembler<const S: usize = 4> {
    entries: Vec<Assembly>,
    completed: Vec<(u64, u16)>,
    max_datagram: usize,
    completed_capacity: usize,
}

impl<const S: usize> FragmentReassembler<S> {
    pub fn new(max_datagram: usize, completed_capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(S),
            completed: Vec::with_capacity(completed_capacity),
            max_datagram,
            completed_capacity,
        }
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.completed.clear();
    }

    pub fn push(
        &mut self,
        key: u64,
        sequence: u16,
        index: u8,
        total: u8,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, Error> {
        if total == 0 || index >= total || total > 64 || payload.is_empty() {
            return Err(Error::Invalid);
        }
        if self
            .completed
            .iter()
            .any(|(known_key, known_sequence)| *known_key == key && *known_sequence == sequence)
        {
            return Ok(None);
        }
        let position = if let Some(position) = self
            .entries
            .iter()
            .position(|entry| entry.key == key && entry.sequence == sequence)
        {
            position
        } else {
            if self.entries.len() >= S {
                self.entries.remove(0);
            }
            self.entries.push(Assembly {
                key,
                sequence,
                total,
                parts: (0..usize::from(total)).map(|_| None).collect(),
                bytes: 0,
            });
            self.entries.len() - 1
        };
        let entry = &mut self.entries[position];
        if entry.total != total {
            return Err(Error::Invalid);
        }
        let slot = &mut entry.parts[usize::from(index)];
        if let Some(existing) = slot {
            if existing.as_slice() != payload {
                return Err(Error::Invalid);
            }
            return Ok(None);
        }
        entry.bytes = entry.bytes.saturating_add(payload.len());
        if entry.bytes > self.max_datagram {
            self.entries.remove(position);
            return Err(Error::FlowControl);
        }
        *slot = Some(payload.to_vec());
        if !entry.parts.iter().all(Option::is_some) {
            return Ok(None);
        }
        let mut result = Vec::with_capacity(entry.bytes);
        for part in &entry.parts {
            result.extend_from_slice(part.as_deref().unwrap_or_default());
        }
        self.entries.remove(position);
        if self.completed.len() >= self.completed_capacity {
            if !self.completed.is_empty() {
                self.completed.remove(0);
            }
        }
        self.completed.push((key, sequence));
        Ok(Some(result))
    }
}

pub fn fragment_datagram(payload: &[u8], chunk: usize) -> Result<Vec<Vec<u8>>, Error> {
    if payload.is_empty() || chunk == 0 {
        return Err(Error::Invalid);
    }
    let total = payload.len().div_ceil(chunk);
    if total > 64 {
        return Err(Error::FlowControl);
    }
    Ok(payload.chunks(chunk).map(|part| part.to_vec()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reassembles_reordered_duplicate_fragments_once() {
        let mut reassembler = FragmentReassembler::<2>::new(64, 4);
        let parts = [b"abc".as_slice(), b"def", b"ghi"];
        assert!(reassembler.push(7, 3, 2, 3, parts[2]).unwrap().is_none());
        assert!(reassembler.push(7, 3, 0, 3, parts[0]).unwrap().is_none());
        assert!(reassembler.push(7, 3, 0, 3, parts[0]).unwrap().is_none());
        assert_eq!(
            reassembler.push(7, 3, 1, 3, parts[1]).unwrap(),
            Some(b"abcdefghi".to_vec())
        );
        assert!(reassembler.push(7, 3, 0, 3, parts[0]).unwrap().is_none());
    }

    #[test]
    fn rejects_conflicting_duplicate_and_bounds_memory() {
        let mut reassembler = FragmentReassembler::<1>::new(5, 1);
        assert!(reassembler.push(1, 1, 0, 2, b"ab").unwrap().is_none());
        assert_eq!(
            reassembler.push(1, 1, 0, 2, b"zz").unwrap_err(),
            Error::Invalid
        );
        assert_eq!(
            reassembler.push(1, 1, 1, 2, b"1234").unwrap_err(),
            Error::FlowControl
        );
    }

    #[test]
    fn fragmenter_rejects_empty_and_limits_fragment_count() {
        assert_eq!(fragment_datagram(&[], 4).unwrap_err(), Error::Invalid);
        assert_eq!(fragment_datagram(&[1, 2, 3, 4, 5], 2).unwrap().len(), 3);
        assert_eq!(fragment_datagram(&[1], 0).unwrap_err(), Error::Invalid);
    }
}
