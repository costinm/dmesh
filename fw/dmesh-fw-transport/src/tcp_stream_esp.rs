//! TCP framing adapter: normal CBOR header/body/FIN and the shared registry.
//! Socket readiness task never dispatches a handler: all service state stays
//! on Main's serialized owner. No private probe or flash implementation.
use alloc::{boxed::Box, vec::Vec};
use core::{
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering},
};
use dmesh_server::stream::{ResponseReader, ServerStream};

const PORT: u16 = 3341;
const CLIENTS: usize = 2; // One upload + one download for the same duplex probe.
const IO: usize = 1024;
unsafe extern "C" {
    fn __errno() -> *mut i32;
}
static FDS: [AtomicI32; CLIENTS + 1] = [const { AtomicI32::new(-1) }; CLIENTS + 1];
static EVENTS: [AtomicI32; CLIENTS + 1] = [const { AtomicI32::new(0) }; CLIENTS + 1];
static TASK: AtomicUsize = AtomicUsize::new(0);
static WAITING: AtomicBool = AtomicBool::new(false);
static mut STATE: Option<State> = None;
static mut START_ATTEMPTED: bool = false;

struct State {
    listener: i32,
    clients: Vec<Box<Client>>,
}
struct Client {
    fd: i32,
    request: Option<ServerStream>,
    response: Option<ResponseReader>,
    input: [u8; IO],
    input_start: usize,
    input_end: usize,
    input_fin: bool,
    output: [u8; IO],
    output_start: usize,
    output_end: usize,
    output_fin: bool,
    offset: u64,
    last_ms: u64,
    body_waiting: bool,
    sent: u64,
    started_ms: u64,
    last_error: i32,
    report_ms: u64,
    turns: u64,
    send_blocked: u64,
}
fn now_ms() -> u64 {
    unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 / 1000 }
}
fn nonblocking(fd: i32) -> bool {
    unsafe {
        esp_idf_sys::lwip_fcntl(
            fd,
            esp_idf_sys::F_SETFL as i32,
            esp_idf_sys::O_NONBLOCK as i32,
        ) == 0
    }
}
fn would_block() -> bool {
    let e = unsafe { *__errno() };
    e == esp_idf_sys::EAGAIN as i32 || e == esp_idf_sys::EWOULDBLOCK as i32
}
fn notify_poller() {
    let task = TASK.load(Ordering::Acquire);
    if task != 0 {
        unsafe {
            esp_idf_sys::xTaskGenericNotify(
                task as _,
                0,
                1,
                esp_idf_sys::eNotifyAction_eSetBits,
                core::ptr::null_mut(),
            );
        }
    }
}
unsafe extern "C" fn poll_task(_: *mut c_void) {
    unsafe { esp_idf_sys::lwip_socket_thread_init() };
    loop {
        let mut fds = [esp_idf_sys::pollfd {
            fd: -1,
            events: 0,
            revents: 0,
        }; CLIENTS + 1];
        for (i, fd) in fds.iter_mut().enumerate() {
            fd.events = EVENTS[i].load(Ordering::Acquire) as i16;
            fd.fd = FDS[i].load(Ordering::Acquire);
        }
        let waiting = WAITING.load(Ordering::Acquire);
        let active_client = fds[1..].iter().any(|fd| fd.fd >= 0);
        let ready = unsafe {
            esp_idf_sys::lwip_poll(
                fds.as_mut_ptr(),
                fds.len() as u32,
                if waiting { 10 } else { 1000 },
            )
        };
        // A blocked socket may produce no readiness at all. Still service
        // client idle expiry on the one-second poll timeout.
        if ready != 0 || waiting || active_client {
            crate::main_runtime::request_quic_ingress();
            // Do not spin on readable/writable sockets while the owner is busy.
            unsafe {
                esp_idf_sys::xTaskGenericNotifyWait(0, 0, u32::MAX, core::ptr::null_mut(), 100)
            };
        }
    }
}
fn start() -> Option<State> {
    unsafe { esp_idf_sys::lwip_socket_thread_init() };
    let fd = unsafe {
        esp_idf_sys::lwip_socket(esp_idf_sys::AF_INET6 as _, esp_idf_sys::SOCK_STREAM as _, 0)
    };
    if fd < 0 {
        return None;
    }
    let mut address = esp_idf_sys::sockaddr_in6::default();
    address.sin6_len = core::mem::size_of_val(&address) as u8;
    address.sin6_family = esp_idf_sys::AF_INET6 as u8;
    address.sin6_port = PORT.to_be();
    let bound = unsafe {
        esp_idf_sys::lwip_bind(
            fd,
            (&address as *const esp_idf_sys::sockaddr_in6).cast(),
            core::mem::size_of_val(&address) as _,
        )
    };
    if bound != 0 || !nonblocking(fd) || unsafe { esp_idf_sys::lwip_listen(fd, CLIENTS as _) } != 0
    {
        unsafe { esp_idf_sys::lwip_close(fd) };
        return None;
    }
    FDS[0].store(fd, Ordering::Release);
    EVENTS[0].store(esp_idf_sys::POLLIN as _, Ordering::Release);
    let mut task = core::ptr::null_mut();
    let created = unsafe {
        esp_idf_sys::xTaskCreatePinnedToCore(
            Some(poll_task),
            b"dmesh_tcp\0".as_ptr().cast(),
            3072,
            core::ptr::null_mut(),
            4,
            &mut task,
            esp_idf_sys::CONFIG_FREERTOS_NO_AFFINITY as _,
        )
    } == 1;
    if !created {
        FDS[0].store(-1, Ordering::Release);
        unsafe { esp_idf_sys::lwip_close(fd) };
        return None;
    }
    TASK.store(task as usize, Ordering::Release);
    Some(State {
        listener: fd,
        clients: Vec::new(),
    })
}
impl Client {
    fn new(fd: i32) -> Self {
        Self {
            fd,
            request: Some(ServerStream::new(
                dmesh_server::registry::CallContext::default(),
            )),
            response: None,
            input: [0; IO],
            input_start: 0,
            input_end: 0,
            input_fin: false,
            output: [0; IO],
            output_start: 0,
            output_end: 0,
            output_fin: false,
            offset: 0,
            last_ms: now_ms(),
            body_waiting: false,
            sent: 0,
            started_ms: now_ms(),
            last_error: 0,
            report_ms: now_ms(),
            turns: 0,
            send_blocked: 0,
        }
    }
    fn step(&mut self) -> bool {
        self.turns += 1;
        let now = now_ms();
        if now.saturating_sub(self.report_ms) >= 5_000 {
            self.report_ms = now;
            use dmesh_server::cbor::FieldValue::{Signed as I, Unsigned as U};
            let memory = crate::shared_ingress_esp::memory_stats();
            crate::log_history::push_event(
                dmesh_server::log_watch::LEVEL_INFO,
                "tcp",
                "tcp.stream_progress",
                &[
                    (1, U(self.offset)),
                    (2, U(self.sent)),
                    (3, U(self.turns)),
                    (4, U(self.send_blocked)),
                    (5, I(self.last_error as i64)),
                    (6, U(memory.free_internal_bytes as u64)),
                    (7, U(memory.min_free_internal_bytes as u64)),
                    (8, U(memory.largest_internal_block_bytes as u64)),
                    (9, U(now.saturating_sub(self.last_ms))),
                ],
            );
        }
        if now_ms().saturating_sub(self.last_ms) > 120_000 {
            return false;
        }
        // Finite service burst keeps QUIC, other handlers and the opposite
        // duplex direction runnable; TCP buffers provide socket backpressure.
        for _ in 0..32 {
            if self.response.is_none() {
                if self.input_start == self.input_end && !self.input_fin {
                    let n = unsafe {
                        esp_idf_sys::lwip_recv(
                            self.fd,
                            self.input.as_mut_ptr().cast(),
                            IO,
                            esp_idf_sys::MSG_DONTWAIT as _,
                        )
                    };
                    if n < 0 {
                        if would_block() {
                            break;
                        }
                        return false;
                    }
                    self.input_start = 0;
                    self.input_end = n as usize;
                    self.input_fin = n == 0;
                    if n > 0 {
                        self.last_ms = now_ms();
                    }
                }
                let request = self.request.as_mut().expect("live request");
                let pushed = request.push(
                    &dmesh_server::registry::REGISTRY,
                    self.offset,
                    self.input_fin,
                    &self.input[self.input_start..self.input_end],
                );
                self.input_start += pushed.accepted;
                self.offset += pushed.accepted as u64;
                if let Some(response) = pushed.response.or_else(|| request.poll()) {
                    self.response = Some(response.into_reader());
                } else if pushed.accepted == 0 || self.input_fin {
                    break;
                }
            }
            if let Some(response) = self.response.as_mut() {
                if self.output_start == self.output_end && !self.output_fin {
                    let (count, done) = response.read(&mut self.output);
                    self.output_start = 0;
                    self.output_end = count;
                    self.output_fin = done;
                    self.body_waiting = count == 0 && !done;
                    if self.body_waiting {
                        break;
                    }
                }
                if self.output_start < self.output_end {
                    let n = unsafe {
                        esp_idf_sys::lwip_send(
                            self.fd,
                            self.output[self.output_start..self.output_end]
                                .as_ptr()
                                .cast(),
                            self.output_end - self.output_start,
                            esp_idf_sys::MSG_DONTWAIT as _,
                        )
                    };
                    if n < 0 {
                        self.last_error = unsafe { *__errno() };
                        if would_block() {
                            self.send_blocked += 1;
                            break;
                        }
                        return false;
                    }
                    if n == 0 {
                        break;
                    }
                    self.output_start += n as usize;
                    self.sent += n as u64;
                    self.last_ms = now_ms();
                }
                if self.output_start == self.output_end && self.output_fin {
                    if unsafe { esp_idf_sys::lwip_shutdown(self.fd, esp_idf_sys::SHUT_WR as _) }
                        != 0
                    {
                        return false;
                    }
                    response.finish_response();
                    return false;
                }
            }
        }
        true
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        use dmesh_server::cbor::FieldValue::{Signed as I, Unsigned as U};
        crate::log_history::push_event(
            dmesh_server::log_watch::LEVEL_INFO,
            "tcp",
            "tcp.stream_finished",
            &[
                (1, U(self.offset)),
                (2, U(self.sent)),
                (3, U(now_ms().saturating_sub(self.started_ms))),
                (4, I(self.last_error as i64)),
                (5, U(self.output_fin as u64)),
            ],
        );
        if let Some(request) = self.request.take() {
            request.abort();
        }
        unsafe { esp_idf_sys::lwip_close(self.fd) };
    }
}
pub(crate) fn progress() {
    // Only Main's existing event owner accesses STATE or invokes handlers.
    let state = unsafe {
        if !START_ATTEMPTED {
            START_ATTEMPTED = true;
            STATE = start();
            if STATE.is_none() {
                crate::uart_esp::send_debug_text(b"TCP listener start failed");
            }
        }
        &mut *core::ptr::addr_of_mut!(STATE)
    };
    let Some(state) = state else {
        return;
    };
    while state.clients.len() < CLIENTS {
        let fd = unsafe {
            esp_idf_sys::lwip_accept(state.listener, core::ptr::null_mut(), core::ptr::null_mut())
        };
        if fd < 0 {
            break;
        }
        if !nonblocking(fd) {
            unsafe { esp_idf_sys::lwip_close(fd) };
            continue;
        }
        state.clients.push(Box::new(Client::new(fd)));
    }
    state.clients.retain_mut(|client| client.step());
    let mut waiting = false;
    for i in 0..CLIENTS {
        let (fd, flags) = if let Some(client) = state.clients.get(i) {
            if client.body_waiting {
                waiting = true;
                (client.fd, 0)
            } else if client.response.is_some() {
                (client.fd, esp_idf_sys::POLLOUT as i32)
            } else if client.input_fin || client.input_start < client.input_end {
                waiting = true;
                (client.fd, 0)
            } else {
                (client.fd, esp_idf_sys::POLLIN as i32)
            }
        } else {
            (-1, 0)
        };
        EVENTS[i + 1].store(flags, Ordering::Release);
        FDS[i + 1].store(fd, Ordering::Release);
    }
    WAITING.store(waiting, Ordering::Release);
    notify_poller();
}
