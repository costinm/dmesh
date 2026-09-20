use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::firmware_profile::TransportProfile;
use crate::main_runtime_state::RadioLifecycle;

pub trait TransportStateObserver: Sync {
    fn transport_requested(
        &self,
        requested: &TransportProfile,
        current: RadioLifecycle,
        generation: u32,
    ) {
        let _ = (requested, current, generation);
    }
    fn transport_applied(
        &self,
        requested: &TransportProfile,
        current: RadioLifecycle,
        generation: u32,
    ) {
        let _ = (requested, current, generation);
    }
}

struct ObserverSlot {
    value: UnsafeCell<Option<&'static dyn TransportStateObserver>>,
    ready: AtomicBool,
}

impl ObserverSlot {
    const fn new() -> Self {
        Self {
            value: UnsafeCell::new(None),
            ready: AtomicBool::new(false),
        }
    }

    fn set(&self, observer: &'static dyn TransportStateObserver) -> bool {
        if self.ready.load(Ordering::Acquire) {
            return false;
        }
        unsafe { *self.value.get() = Some(observer) };
        self.ready.store(true, Ordering::Release);
        true
    }

    fn get(&self) -> Option<&'static dyn TransportStateObserver> {
        if self.ready.load(Ordering::Acquire) {
            unsafe { *self.value.get() }
        } else {
            None
        }
    }
}

unsafe impl Sync for ObserverSlot {}

static OBSERVERS: [ObserverSlot; 4] = [
    ObserverSlot::new(),
    ObserverSlot::new(),
    ObserverSlot::new(),
    ObserverSlot::new(),
];

pub fn register_transport_state_observer(
    observer: &'static dyn TransportStateObserver,
) -> bool {
    for slot in OBSERVERS.iter() {
        if slot.set(observer) {
            return true;
        }
    }
    false
}

pub fn notify_transport_requested(
    requested: &TransportProfile,
    current: RadioLifecycle,
    generation: u32,
) {
    for slot in OBSERVERS.iter() {
        if let Some(observer) = slot.get() {
            observer.transport_requested(requested, current, generation);
        }
    }
}

pub fn notify_transport_applied(
    requested: &TransportProfile,
    current: RadioLifecycle,
    generation: u32,
) {
    for slot in OBSERVERS.iter() {
        if let Some(observer) = slot.get() {
            observer.transport_applied(requested, current, generation);
        }
    }
}
