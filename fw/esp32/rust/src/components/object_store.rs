//! Main-linked NAN object receiver boundary.
//!
//! The flash writer remains platform-specific; this service owns only the
//! bounded envelope/session parsing and can therefore be exercised without
//! IP. A future flash sink can be attached to the same protocol receiver.

use quic_lite::{decode_envelope, ConnectionId, PeerKey};

#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub frames: u32,
    pub bytes: u32,
    pub rejected: u32,
}

pub struct NanObjectService {
    active: bool,
    stats: Stats,
}

impl NanObjectService {
    pub const fn new() -> Self {
        Self {
            active: false,
            stats: Stats {
                frames: 0,
                bytes: 0,
                rejected: 0,
            },
        }
    }
    pub fn start(&mut self) {
        self.active = true;
    }
    pub fn stop(&mut self) {
        self.active = false;
    }
    pub fn active(&self) -> bool {
        self.active
    }
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Validate the common data/action envelope and return its `(MAC, DCID)`
    /// connection key. The caller then dispatches the payload to the bounded
    /// object receiver and platform flash sink.
    pub fn observe(&mut self, frame: &[u8]) -> Option<(PeerKey, u8, usize)> {
        if !self.active {
            return None;
        }
        match decode_envelope(frame) {
            Ok((key, kind, payload)) => {
                self.stats.frames = self.stats.frames.saturating_add(1);
                self.stats.bytes = self.stats.bytes.saturating_add(payload.len() as u32);
                Some((key, kind, payload.len()))
            }
            Err(_) => {
                self.stats.rejected = self.stats.rejected.saturating_add(1);
                None
            }
        }
    }

    pub fn connection_key(mac: [u8; 6], dcid: u64) -> Option<PeerKey> {
        Some(PeerKey {
            wifi_mac: mac,
            dcid: ConnectionId::new(dcid)?,
        })
    }
}
