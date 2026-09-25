//! Bearer-neutral planning for waking a sleepy device through NAN observers.
//!
//! Platforms discover observers and execute the resulting tagged request;
//! this module owns target matching, de-duplication, and fallback policy.

use alloc::{string::String, vec::Vec};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NanObservation<'a, O> {
    pub observer: O,
    pub observer_ready: bool,
    pub node: Option<&'a str>,
    pub peer_mac: Option<[u8; 6]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NanWakeAttempt<O> {
    pub observer: O,
    pub target_mac: [u8; 6],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NanWakePlan<O> {
    pub attempts: Vec<NanWakeAttempt<O>>,
    /// Signed identity learned from an observer, used to correlate the target
    /// after it becomes directly reachable.
    pub observed_node: Option<String>,
}

/// Select every independently reachable observer which can wake the target.
///
/// An observer-specific sighting wins for that observer. If the catalog has a
/// target MAC, every other ready observer is also tried: local queue admission
/// is not proof that one observer's NAN SDF reached the sleepy peer.
pub fn plan_nan_wake<'a, O: Copy + Eq>(
    target_node: Option<&str>,
    target_mac: Option<[u8; 6]>,
    observations: impl IntoIterator<Item = NanObservation<'a, O>>,
) -> NanWakePlan<O> {
    let observations = observations.into_iter().collect::<Vec<_>>();
    let mut attempts = Vec::new();
    let mut observed_node = None;

    for observation in &observations {
        let matches = target_mac.is_some_and(|mac| observation.peer_mac == Some(mac))
            || target_node.is_some_and(|node| {
                observation
                    .node
                    .is_some_and(|seen| seen.eq_ignore_ascii_case(node))
            });
        if !matches {
            continue;
        }
        let Some(mac) = observation.peer_mac else {
            continue;
        };
        if let Some(node) = observation.node.filter(|node| !node.is_empty()) {
            observed_node = Some(String::from(node));
        }
        if !attempts
            .iter()
            .any(|attempt: &NanWakeAttempt<O>| attempt.observer == observation.observer)
        {
            attempts.push(NanWakeAttempt {
                observer: observation.observer,
                target_mac: mac,
            });
        }
    }

    if let Some(mac) = target_mac {
        for observation in observations {
            if observation.observer_ready
                && !attempts
                    .iter()
                    .any(|attempt| attempt.observer == observation.observer)
            {
                attempts.push(NanWakeAttempt {
                    observer: observation.observer,
                    target_mac: mac,
                });
            }
        }
    }

    NanWakePlan {
        attempts,
        observed_node,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sightings_select_the_reported_mac_and_catalog_mac_fans_out() {
        let observations = [
            NanObservation {
                observer: 1,
                observer_ready: true,
                node: Some("AABB"),
                peer_mac: Some([1, 2, 3, 4, 5, 6]),
            },
            NanObservation {
                observer: 2,
                observer_ready: true,
                node: None,
                peer_mac: None,
            },
        ];
        let plan = plan_nan_wake(Some("aabb"), Some([1, 2, 3, 4, 5, 6]), observations);
        assert_eq!(plan.observed_node.as_deref(), Some("AABB"));
        assert_eq!(plan.attempts.len(), 2);
        assert_eq!(plan.attempts[0].observer, 1);
        assert_eq!(plan.attempts[1].observer, 2);
    }

    #[test]
    fn unknown_target_has_no_wake_plan() {
        let plan = plan_nan_wake(
            Some("missing"),
            None,
            [NanObservation {
                observer: 1,
                observer_ready: true,
                node: Some("other"),
                peer_mac: Some([1; 6]),
            }],
        );
        assert!(plan.attempts.is_empty());
    }
}
