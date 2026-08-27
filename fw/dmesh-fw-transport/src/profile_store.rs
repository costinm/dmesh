//! Serialized desired-transport publication for the Main radio owner.
//!
//! Bearer ingress updates one complete fixed-size [`TransportProfile`] while
//! holding this short lock, then advances its generation. The Main task copies
//! the profile only after dequeuing that generation. This module intentionally
//! owns desired configuration only; applied radio state belongs to
//! `main_runtime::MainRadioState`.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

static mut TRANSPORT_PROFILE: crate::TransportProfile = crate::TransportProfile::new();
static TRANSPORT_PROFILE_LOCK: AtomicBool = AtomicBool::new(false);
static GENERATION: AtomicU32 = AtomicU32::new(0);

/// Mutate one complete desired profile. Called by copied command ingress, not
/// by a Wi-Fi callback. The lock is held only while copying bounded fields;
/// no driver call or CBOR parsing happens while it is held.
pub(crate) fn with_profile<R>(operation: impl FnOnce(&mut crate::TransportProfile) -> R) -> R {
    while TRANSPORT_PROFILE_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    let result = operation(unsafe { &mut *core::ptr::addr_of_mut!(TRANSPORT_PROFILE) });
    TRANSPORT_PROFILE_LOCK.store(false, Ordering::Release);
    result
}

/// Return a coherent profile copy for a Main event effect. Credentials never
/// leave this module except in that owner-task copy, and are never projected
/// into the runtime snapshot.
pub(crate) fn snapshot() -> crate::TransportProfile {
    with_profile(|profile| *profile)
}

/// Advance the generation after an accepted profile change, then return it.
/// The release operation makes the complete locked profile visible before the
/// Main queue event that carries this generation.
pub(crate) fn advance_generation() -> u32 {
    GENERATION.fetch_add(1, Ordering::Release).saturating_add(1)
}

/// Return the latest committed desired-profile generation.
pub(crate) fn generation() -> u32 {
    GENERATION.load(Ordering::Acquire)
}
