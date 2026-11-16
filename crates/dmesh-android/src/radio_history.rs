//! A short in-memory history of radio events: NAN follow-ups and Wi-Fi Aware lifecycle callbacks.
//!
//! The history is not persisted and not a frame store; it is the retained history behind the
//! follow-up/event listing commands and the NAN session state derived from the lifecycle events.
//! The ring holds a fixed number of entries (`capacity`), oldest first.

use std::collections::VecDeque;

/// One observed radio event.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RadioEvent {
    pub protocol: String,
    pub payload_hash: u32,
    pub source: String,
    pub target: Option<String>,
    pub seq: Option<u16>,
    /// Event or message type (`aware.on_attached`, `hello`, ...).
    pub event: Option<String>,
    pub payload: Vec<u8>,
    /// Unix milliseconds.
    pub timestamp_ms: i64,
}

/// Whether an event name is a Wi-Fi Aware session/publish/subscribe lifecycle transition.
pub fn is_aware_lifecycle(event: Option<&str>) -> bool {
    matches!(
        event,
        Some(
            "attached"
                | "aware.on_attached"
                | "aware.on_session_terminated"
                | "aware.on_attach_failed"
                | "aware.session_close"
                | "aware.on_publish_started"
                | "aware.on_publish_terminated"
                | "aware.publish_close"
                | "aware.on_subscribe_started"
                | "aware.on_subscribe_terminated"
                | "aware.subscribe_close"
        )
    )
}

/// A fixed-capacity ring of [`RadioEvent`]s.
#[derive(Debug)]
pub struct RadioHistory {
    entries: VecDeque<RadioEvent>,
    capacity: usize,
}

impl RadioHistory {
    pub const fn new(capacity: usize) -> Self {
        Self { entries: VecDeque::new(), capacity }
    }

    /// Append, dropping the oldest entry when full.
    pub fn push(&mut self, event: RadioEvent) {
        if self.entries.len() >= self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back(event);
    }

    /// Append, but never evict a lifecycle event to make room for a routine one: those describe
    /// the state of the local Aware session, and routine discovery callbacks can be far more
    /// frequent. A routine event arriving when the ring holds only lifecycle events is dropped; a
    /// lifecycle event always gets in (the oldest entry makes room).
    pub fn push_keeping_lifecycle(&mut self, event: RadioEvent) {
        if self.entries.len() >= self.capacity {
            match self
                .entries
                .iter()
                .position(|entry| !is_aware_lifecycle(entry.event.as_deref()))
            {
                Some(index) => {
                    self.entries.remove(index);
                }
                None if is_aware_lifecycle(event.event.as_deref()) => {
                    self.entries.pop_front();
                }
                None => return,
            }
        }
        self.entries.push_back(event);
    }

    /// Oldest first; `.rev()` for newest first.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &RadioEvent> {
        self.entries.iter()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(name: &str) -> RadioEvent {
        RadioEvent { event: Some(name.to_owned()), ..Default::default() }
    }

    fn names(history: &RadioHistory) -> Vec<&str> {
        history.iter().filter_map(|entry| entry.event.as_deref()).collect()
    }

    #[test]
    fn a_full_ring_drops_its_oldest_entry() {
        let mut history = RadioHistory::new(2);
        for name in ["a", "b", "c"] {
            history.push(event(name));
        }
        assert_eq!(names(&history), ["b", "c"]);
    }

    #[test]
    fn routine_events_never_evict_a_lifecycle_transition() {
        let mut history = RadioHistory::new(2);
        history.push_keeping_lifecycle(event("aware.on_attached"));
        history.push_keeping_lifecycle(event("discovered"));
        history.push_keeping_lifecycle(event("discovered-2"));
        assert_eq!(names(&history), ["aware.on_attached", "discovered-2"]);
        // Only lifecycle events left: a routine one is dropped, a lifecycle one replaces the oldest.
        history.push_keeping_lifecycle(event("aware.on_publish_started"));
        assert_eq!(names(&history), ["aware.on_attached", "aware.on_publish_started"]);
        history.push_keeping_lifecycle(event("routine"));
        assert_eq!(names(&history), ["aware.on_attached", "aware.on_publish_started"]);
        history.push_keeping_lifecycle(event("aware.session_close"));
        assert_eq!(names(&history), ["aware.on_publish_started", "aware.session_close"]);
    }
}
