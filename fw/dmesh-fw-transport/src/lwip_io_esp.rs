//! One lwIP readiness task for firmware TCP listeners and UDP/TCP sockets.
//!
//! Callbacks run on the poll task. They may accept, drain a short receive
//! batch, or wake an owner, but application handlers run elsewhere.

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU16, AtomicUsize, Ordering};

const SLOTS: usize = 12;
const POLL_STACK: u32 = 6 * 1024;
type Ready = fn(Registration, i32, i16);
type Accept = fn(i32);

struct Entry {
    used: AtomicBool,
    generation: AtomicUsize,
    fd: AtomicI32,
    events: AtomicI32,
    tick_ms: AtomicI32,
    ready: AtomicUsize,
    port: AtomicU16,
    backlog: AtomicI32,
    accept: AtomicUsize,
}

impl Entry {
    const fn new() -> Self {
        Self {
            used: AtomicBool::new(false),
            generation: AtomicUsize::new(0),
            fd: AtomicI32::new(-1),
            events: AtomicI32::new(0),
            tick_ms: AtomicI32::new(0),
            ready: AtomicUsize::new(0),
            port: AtomicU16::new(0),
            backlog: AtomicI32::new(0),
            accept: AtomicUsize::new(0),
        }
    }
}

static ENTRIES: [Entry; SLOTS] = [const { Entry::new() }; SLOTS];
// 0: stopped, 1: starting, 2: running.
static TASK_STATE: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy)]
pub struct Registration {
    index: usize,
    generation: usize,
}

fn start_task() -> bool {
    match TASK_STATE.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => {
            let mut task = core::ptr::null_mut();
            let created = unsafe {
                esp_idf_sys::xTaskCreatePinnedToCore(
                    Some(poll_task),
                    b"dmesh_lwip\0".as_ptr().cast(),
                    POLL_STACK,
                    core::ptr::null_mut(),
                    4,
                    &mut task,
                    esp_idf_sys::CONFIG_FREERTOS_NO_AFFINITY as _,
                )
            } == 1;
            TASK_STATE.store(if created { 2 } else { 0 }, Ordering::Release);
            created
        }
        Err(_) => {
            while TASK_STATE.load(Ordering::Acquire) == 1 {
                core::hint::spin_loop();
            }
            TASK_STATE.load(Ordering::Acquire) == 2
        }
    }
}

fn reserve(ready: Ready) -> Option<Registration> {
    if !start_task() {
        return None;
    }
    for (index, entry) in ENTRIES.iter().enumerate() {
        if entry
            .used
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let generation = entry.generation.fetch_add(1, Ordering::AcqRel) + 1;
            entry.ready.store(ready as usize, Ordering::Release);
            return Some(Registration { index, generation });
        }
    }
    None
}

/// Add a socket already owned by an adapter. `ready` only observes readiness;
/// the adapter retains the descriptor and must call `clear` before closing it.
pub fn register_socket(fd: i32, events: i16, ready: Ready) -> Option<Registration> {
    let registration = reserve(ready)?;
    update(registration, fd, events, 0);
    Some(registration)
}

/// Replace the descriptor and requested events for an existing registration.
/// A positive tick wakes the callback even without socket readiness.
pub fn update(registration: Registration, fd: i32, events: i16, tick_ms: i32) {
    let entry = &ENTRIES[registration.index];
    if entry.generation.load(Ordering::Acquire) != registration.generation {
        return;
    }
    entry.fd.store(-1, Ordering::Release);
    entry.events.store(events as i32, Ordering::Relaxed);
    entry.tick_ms.store(tick_ms, Ordering::Relaxed);
    entry.fd.store(fd, Ordering::Release);
}

pub fn clear(registration: Registration) {
    update(registration, -1, 0, 0);
    let entry = &ENTRIES[registration.index];
    if entry.generation.load(Ordering::Acquire) == registration.generation {
        entry.ready.store(0, Ordering::Release);
        entry.port.store(0, Ordering::Relaxed);
        entry.accept.store(0, Ordering::Relaxed);
        entry.backlog.store(0, Ordering::Relaxed);
        entry.generation.fetch_add(1, Ordering::AcqRel);
        entry.used.store(false, Ordering::Release);
    }
}

/// Hide a level-triggered socket until its owner has consumed the event and
/// publishes its next requested events.
pub fn suspend(registration: Registration) {
    let entry = &ENTRIES[registration.index];
    if entry.generation.load(Ordering::Acquire) == registration.generation {
        entry.fd.store(-1, Ordering::Release);
    }
}

/// Register a TCP port before the network interface exists. This task binds
/// it when lwIP is ready and accepts connections without an application stack.
/// The handler owns each accepted descriptor and must close it on rejection.
pub fn listen_tcp(port: u16, backlog: i32, accept: Accept) -> Option<Registration> {
    let registration = reserve(listener_ready)?;
    let entry = &ENTRIES[registration.index];
    entry.accept.store(accept as usize, Ordering::Relaxed);
    entry.backlog.store(backlog, Ordering::Relaxed);
    entry.port.store(port, Ordering::Release);
    Some(registration)
}

fn bind_listener(entry: &Entry) {
    if entry.port.load(Ordering::Acquire) == 0 || entry.fd.load(Ordering::Acquire) >= 0 {
        return;
    }
    if unsafe { esp_idf_sys::esp_netif_next_unsafe(core::ptr::null_mut()) }.is_null() {
        return;
    }
    let fd = unsafe {
        esp_idf_sys::lwip_socket(esp_idf_sys::AF_INET6 as _, esp_idf_sys::SOCK_STREAM as _, 0)
    };
    if fd < 0 {
        return;
    }
    let mut address = esp_idf_sys::sockaddr_in6::default();
    address.sin6_len = core::mem::size_of_val(&address) as u8;
    address.sin6_family = esp_idf_sys::AF_INET6 as u8;
    address.sin6_port = entry.port.load(Ordering::Acquire).to_be();
    let bound = unsafe {
        esp_idf_sys::lwip_bind(
            fd,
            (&address as *const esp_idf_sys::sockaddr_in6).cast(),
            core::mem::size_of_val(&address) as _,
        )
    };
    let nonblocking = unsafe {
        esp_idf_sys::lwip_fcntl(fd, esp_idf_sys::F_SETFL as _, esp_idf_sys::O_NONBLOCK as _)
    } == 0;
    let listening = bound == 0
        && nonblocking
        && unsafe { esp_idf_sys::lwip_listen(fd, entry.backlog.load(Ordering::Relaxed)) } == 0;
    if listening {
        entry
            .events
            .store(esp_idf_sys::POLLIN as i32, Ordering::Relaxed);
        entry.fd.store(fd, Ordering::Release);
        unsafe {
            esp_idf_sys::esp_rom_printf(
                b"DMESH lwIP: TCP listening on %u\n\0".as_ptr().cast(),
                entry.port.load(Ordering::Relaxed) as u32,
            )
        };
    } else {
        unsafe { esp_idf_sys::lwip_close(fd) };
    }
}

fn listener_ready(registration: Registration, fd: i32, events: i16) {
    if events & esp_idf_sys::POLLIN as i16 == 0 {
        return;
    }
    let accept = ENTRIES[registration.index].accept.load(Ordering::Acquire);
    if accept == 0 {
        return;
    }
    let accept: Accept = unsafe { core::mem::transmute(accept) };
    for _ in 0..4 {
        let client =
            unsafe { esp_idf_sys::lwip_accept(fd, core::ptr::null_mut(), core::ptr::null_mut()) };
        if client < 0 {
            break;
        }
        accept(client);
    }
}

unsafe extern "C" fn poll_task(_: *mut c_void) {
    // Main registers listeners before Wi-Fi creates a netif.
    while unsafe { esp_idf_sys::esp_netif_next_unsafe(core::ptr::null_mut()) }.is_null() {
        unsafe { esp_idf_sys::vTaskDelay(100) };
    }
    unsafe { esp_idf_sys::lwip_socket_thread_init() };
    let mut last_tick = [0u64; SLOTS];
    loop {
        let mut fds = [esp_idf_sys::pollfd {
            fd: -1,
            events: 0,
            revents: 0,
        }; SLOTS];
        let mut generations = [0usize; SLOTS];
        let mut timeout = 1000;
        for index in 0..SLOTS {
            let entry = &ENTRIES[index];
            if !entry.used.load(Ordering::Acquire) {
                continue;
            }
            bind_listener(entry);
            generations[index] = entry.generation.load(Ordering::Acquire);
            fds[index].fd = entry.fd.load(Ordering::Acquire);
            fds[index].events = entry.events.load(Ordering::Relaxed) as i16;
            let tick = entry.tick_ms.load(Ordering::Relaxed);
            if fds[index].fd >= 0 && tick > 0 {
                timeout = timeout.min(tick);
            }
        }
        unsafe { esp_idf_sys::lwip_poll(fds.as_mut_ptr(), SLOTS as _, timeout) };
        let now = unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 / 1000 };
        for index in 0..SLOTS {
            let entry = &ENTRIES[index];
            let fd = fds[index].fd;
            if fd < 0
                || generations[index] != entry.generation.load(Ordering::Acquire)
                || entry.fd.load(Ordering::Acquire) != fd
            {
                continue;
            }
            let tick = entry.tick_ms.load(Ordering::Relaxed);
            let expired = tick > 0 && now.saturating_sub(last_tick[index]) >= tick as u64;
            if fds[index].revents == 0 && !expired {
                continue;
            }
            if expired {
                last_tick[index] = now;
            }
            let ready = entry.ready.load(Ordering::Acquire);
            if ready != 0 {
                let ready: Ready = unsafe { core::mem::transmute(ready) };
                ready(
                    Registration {
                        index,
                        generation: generations[index],
                    },
                    fd,
                    fds[index].revents,
                );
            }
        }
    }
}
