//! Fixed-capacity mapping between bearer-native addresses and peer L2 handles.
//!
//! This is transport- and runtime-independent. A UDP adapter may use
//! `SocketAddr`, Wi-Fi may use a MAC address, and another bearer may use a small
//! driver token. The table assigns only the opaque [`PeerL2Address`] exposed to
//! QUIC; it does not select associations or routes.

use core::array;

use crate::PeerL2Address;

/// Failure to allocate another bearer-native peer address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PeerL2TableFull;

struct PeerEntry<Address> {
    generation: u32,
    address: Option<Address>,
}

/// Fixed-capacity mapping from bearer-native addresses to opaque peer handles.
///
/// `Address` is private driver state such as a UDP socket address, Wi-Fi MAC,
/// BLE connection token, or UART endpoint. QUIC retains only the returned
/// [`PeerL2Address`]. Removing an entry advances its generation, so a delayed
/// packet or association holding the old handle cannot address a later peer
/// which reuses the same slot.
pub(crate) struct PeerL2Table<Address, const PEERS: usize> {
    peers: [PeerEntry<Address>; PEERS],
}

impl<Address: Eq, const PEERS: usize> PeerL2Table<Address, PEERS> {
    /// Create an empty peer table.
    pub(crate) fn new() -> Self {
        assert!(PEERS <= u32::MAX as usize);
        Self {
            peers: array::from_fn(|_| PeerEntry {
                generation: 1,
                address: None,
            }),
        }
    }

    /// Return the stable handle for `peer`, allocating one unused slot when
    /// this is the first observation of that bearer-native address.
    pub(crate) fn get_or_insert(
        &mut self,
        peer: Address,
    ) -> Result<PeerL2Address, PeerL2TableFull> {
        if let Some(slot) = self
            .peers
            .iter()
            .position(|candidate| candidate.address.as_ref() == Some(&peer))
        {
            return Ok(self.handle(slot));
        }
        let slot = self
            .peers
            .iter()
            .position(|entry| entry.address.is_none() && entry.generation != 0)
            .ok_or(PeerL2TableFull)?;
        self.peers[slot].address = Some(peer);
        Ok(self.handle(slot))
    }

    /// Resolve a current opaque handle to the bearer's native address.
    pub(crate) fn peer(&self, handle: PeerL2Address) -> Option<&Address> {
        let (slot, generation) = Self::decode(handle)?;
        let entry = self.peers.get(slot)?;
        (entry.generation == generation)
            .then_some(entry.address.as_ref())
            .flatten()
    }

    /// Return the current opaque handle for a bearer-native address.
    pub(crate) fn address(&self, peer: &Address) -> Option<PeerL2Address> {
        self.peers
            .iter()
            .position(|candidate| candidate.address.as_ref() == Some(peer))
            .map(|slot| self.handle(slot))
    }

    /// Remove exactly the peer named by `handle` and invalidate every copy of
    /// that handle before the slot may be reused.
    pub(crate) fn remove(&mut self, handle: PeerL2Address) -> Option<Address> {
        let (slot, generation) = Self::decode(handle)?;
        let entry = self.peers.get_mut(slot)?;
        if entry.generation != generation {
            return None;
        }
        let address = entry.address.take()?;
        // Generation zero permanently retires an exhausted slot. Wrapping to
        // one would eventually make a very old retained handle valid again.
        entry.generation = entry.generation.checked_add(1).unwrap_or(0);
        Some(address)
    }

    fn handle(&self, slot: usize) -> PeerL2Address {
        let slot = u32::try_from(slot).expect("peer table exceeds handle slot range");
        let value = (u64::from(self.peers[slot as usize].generation) << 32)
            | u64::from(slot.saturating_add(1));
        PeerL2Address::new(value).expect("peer table handles are nonzero")
    }

    fn decode(handle: PeerL2Address) -> Option<(usize, u32)> {
        let generation = u32::try_from(handle.value() >> 32).ok()?;
        let encoded_slot = handle.value() as u32;
        let slot = usize::try_from(encoded_slot.checked_sub(1)?).ok()?;
        (generation != 0).then_some((slot, generation))
    }
}

impl<Address: Eq, const PEERS: usize> Default for PeerL2Table<Address, PEERS> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_native_address_keeps_one_stable_handle() {
        let mut peers = PeerL2Table::<[u8; 6], 2>::new();
        let first = peers.get_or_insert([1; 6]).unwrap();
        let repeated = peers.get_or_insert([1; 6]).unwrap();

        assert_eq!(first, repeated);
        assert_eq!(peers.peer(first), Some(&[1; 6]));
        assert_eq!(peers.address(&[1; 6]), Some(first));
    }

    #[test]
    fn full_table_rejects_a_new_peer_without_changing_existing_entries() {
        let mut peers = PeerL2Table::<u32, 2>::new();
        let first = peers.get_or_insert(10).unwrap();
        let second = peers.get_or_insert(20).unwrap();

        assert_eq!(peers.get_or_insert(30), Err(PeerL2TableFull));
        assert_eq!(peers.peer(first), Some(&10));
        assert_eq!(peers.peer(second), Some(&20));
        assert_eq!(peers.address(&30), None);
    }

    #[test]
    fn reused_slot_rejects_its_stale_handle() {
        let mut peers = PeerL2Table::<u8, 1>::new();
        let stale = peers.get_or_insert(7).unwrap();
        assert_eq!(peers.remove(stale), Some(7));

        let current = peers.get_or_insert(9).unwrap();
        assert_ne!(stale, current);
        assert_eq!(peers.peer(stale), None);
        assert_eq!(peers.remove(stale), None);
        assert_eq!(peers.peer(current), Some(&9));
    }
}
