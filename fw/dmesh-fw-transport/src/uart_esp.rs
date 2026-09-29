// IMPORTANT: This is shared no-std ESP firmware code. It owns ESP USB/UART
// queues and the nonblocking FreeRTOS L2 task shared by Recovery and Main.
// PPP marker semantics and classification are shared server/bearer policy.

// TODO: copy uart_codec codec into this file - making escaping/framing integral and done closer to the driver.
// TODO: evaluate using interrupts for send and receive
// TODO: remove owned buffers - use the Quic pool buffer for everything. On receive - get a pool after the packet delim.

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicUsize, Ordering};

use dmesh_server::firmware_profile::{UART_DEFAULT, UART_OFF};
use quic_lite::{
    EgressSubmission, PacketEgress, PacketSendOutcome, PacketSubmitError, PeerL2Address,
};
use uart_codec::encode_packet;
use uart_codec::pool::{PooledDecoder, PooledFrame};

/// UART is an L2 bearer and therefore uses the transport MTU rather than a
/// separate 512-byte diagnostic limit. PPP escaping is framing overhead, not
/// an additional fragmentation layer.
pub const UART_MAX_PACKET: usize = crate::TRANSPORT_MTU + 1;

// The image's physical UART rate is intentionally a build-time choice:
// switching it at runtime would strand a direct UART client before it could
// receive an acknowledgement. C6 selects USB-JTAG only when a host is
// physically attached at boot; otherwise it uses the board's UART0 bridge.
include!(concat!(env!("OUT_DIR"), "/physical_uart_baud.rs"));

// UART egress sends complete MTU records..
#[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
const UART_EGRESS_MAX_CAPACITY: usize = 4;
#[cfg(target_arch = "riscv32")]
const UART_EGRESS_MAX_CAPACITY: usize = 2;
#[cfg(target_feature = "esp32s3ops")]
const UART_EGRESS_MAX_CAPACITY: usize = 8;
#[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
pub(crate) const UART_L2_STACK_BYTES: u32 = 8 * 1024;
#[cfg(any(target_arch = "riscv32", target_feature = "esp32s3ops"))]
pub(crate) const UART_L2_STACK_BYTES: u32 = 8 * 1024;

// USB-JTAG is a packetized USB transport on C6, not a 115200 UART. One PPP
// frame can grow to roughly twice the transport MTU through escaping. Reserve
// two frames per direction, matching the C6's device-wide UART flight cap.
#[cfg(target_arch = "riscv32")]
const USB_JTAG_BUFFER_SIZE: u32 = (2 * (2 * UART_MAX_PACKET + 2)) as u32;
// ESP-IDF owns this queue as part of the UART driver.  The shared L2 task is
// its sole consumer on classic/S3; polling `uart_read_bytes` beside the event
// queue loses RX wakeups on some classic bridge/driver combinations.
static UART_RX_EVENT_QUEUE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

#[cfg(target_arch = "riscv32")]
static C6_USB_JTAG_SELECTED: AtomicBool = AtomicBool::new(false);

static UART_RX_EVENT_COUNT: AtomicU32 = AtomicU32::new(0);
static UART_RX_BYTE_COUNT: AtomicU32 = AtomicU32::new(0);
static UART_RX_BYTES_REPORTED: AtomicBool = AtomicBool::new(false);
static UART_RX_PACKET_REPORTED: AtomicBool = AtomicBool::new(false);
/// Optional firmware-owner wake hook. The L2 task has no dependency on Main,
/// Recovery, commands, or a particular executor; an owner can install this
/// one-shot notification so its dispatcher need not wait for a housekeeping
/// timeout after an ingress queue transition.
static INGRESS_NOTIFY: AtomicUsize = AtomicUsize::new(0);
/// Optional task-context notification after the physical writer dequeues one
/// complete record.  It does not carry a packet: the shared QUIC-lite owner
/// retains its own ledger and consults the real egress queue capacity when it
/// receives this writable transition.
static EGRESS_NOTIFY: AtomicUsize = AtomicUsize::new(0);
static UART_EGRESS_QUEUE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static UART_EGRESS_QUEUED: AtomicUsize = AtomicUsize::new(0);
/// Actual queue depth selected at startup. Keeping it atomic allows the
/// shared worker to use the same capacity feedback without a UART lock.
static UART_EGRESS_CAPACITY: AtomicUsize = AtomicUsize::new(0);

// Solely owned by the UART writer task.  This is deliberately a short driver
// write chunk, not a packet or an escaped-frame buffer.
static mut UART_TX_SCRATCH: [u8; 64] = [0; 64];

// The sole writer task receives legacy raw/text records here. Keeping the
// scratch record out of the FreeRTOS stack prevents a packet-sized stack
// reservation. Pool-backed QUIC packets never pass through this record.
static mut UART_TX_CURRENT: core::mem::MaybeUninit<QueuedUartPayload> =
    core::mem::MaybeUninit::uninit();

type UartPoolSubmission = EgressSubmission<crate::shared_ingress_esp::SharedPacketLease>;

// The bearer accepts only one pool lease at a time. The FreeRTOS queue carries
// a wake record, never the packet or its ownership-bearing Rust value.
static UART_POOL_SUBMISSION_STATE: AtomicUsize = AtomicUsize::new(0);
static mut UART_POOL_SUBMISSION: core::mem::MaybeUninit<UartPoolSubmission> =
    core::mem::MaybeUninit::uninit();
static UART_APB_LOCK: AtomicPtr<esp_idf_sys::esp_pm_lock> = AtomicPtr::new(core::ptr::null_mut());
static UART_APB_LOCK_HELD: AtomicBool = AtomicBool::new(false);
static UART_NO_LIGHT_SLEEP_LOCK: AtomicPtr<esp_idf_sys::esp_pm_lock> =
    AtomicPtr::new(core::ptr::null_mut());
static UART_NO_LIGHT_SLEEP_LOCK_HELD: AtomicBool = AtomicBool::new(false);
static UART_ACTIVE_UNTIL_MS: AtomicU32 = AtomicU32::new(0);
static UART_ALWAYS_ON: AtomicBool = AtomicBool::new(false);
static UART_ACTIVE_WINDOW_MS: AtomicU32 = AtomicU32::new(4_000);
static UART_DEBUG_ENABLED: AtomicBool = AtomicBool::new(true);
pub const COMMAND_GRACE_TICKS: u32 = 8000;

/// Convert the compact transport.start selector to a physical baud rate.
/// Zero is the product-default spelling for 115200; `UART_OFF` has no baud.
/// USB-JTAG builds never call this mapping because their bearer is packetized,
/// not serial.
pub const fn baud_from_selector(selector: u8) -> Option<i32> {
    match selector {
        UART_DEFAULT | 1 => Some(115_200),
        2 => Some(9_600),
        3 => Some(19_200),
        4 => Some(38_400),
        5 => Some(57_600),
        6 => Some(230_400),
        7 => Some(460_800),
        UART_OFF => None,
        _ => None,
    }
}

/// Whether this profile explicitly disables a real UART bearer. USB-JTAG is
/// intentionally not governed by this predicate so hardware debug remains
/// usable when a radio-only profile asks to turn UART off.
pub const fn uart_is_off(selector: u8) -> bool {
    selector == UART_OFF
}

/// Whether this boot selected the packetized native USB-JTAG endpoint rather
/// than a power-gated physical UART.
pub fn packetized_debug_selected() -> bool {
    #[cfg(target_arch = "riscv32")]
    {
        return C6_USB_JTAG_SELECTED.load(Ordering::Acquire);
    }
    #[cfg(not(target_arch = "riscv32"))]
    {
        false
    }
}

/// Install and configure the physical console bearer. This is deliberately
/// the sole ESP UART0/USB-JTAG setup path used by both Main and Recovery.
/// Callers provide only higher-layer dispatch policy; they must never create
/// a competing UART driver, reader, writer, or RX event queue.
pub unsafe fn install_l2_driver(baud_selector: u8) -> bool {
    #[cfg(target_arch = "riscv32")]
    {
        if c6_usb_host_connected() {
            let mut config = esp_idf_sys::usb_serial_jtag_driver_config_t {
                tx_buffer_size: USB_JTAG_BUFFER_SIZE,
                rx_buffer_size: USB_JTAG_BUFFER_SIZE,
            };
            let result = esp_idf_sys::usb_serial_jtag_driver_install(&mut config);
            let installed =
                result == esp_idf_sys::ESP_OK || result == esp_idf_sys::ESP_ERR_INVALID_STATE;
            C6_USB_JTAG_SELECTED.store(installed, Ordering::Release);
            return installed;
        }
        C6_USB_JTAG_SELECTED.store(false, Ordering::Release);
        return install_uart0_driver(baud_selector);
    }

    #[cfg(not(target_arch = "riscv32"))]
    {
        install_uart0_driver(baud_selector)
    }
}

unsafe fn install_uart0_driver(baud_selector: u8) -> bool {
    const UART0: esp_idf_sys::uart_port_t = esp_idf_sys::uart_port_t_UART_NUM_0;
    let mut config = esp_idf_sys::uart_config_t::default();
    let Some(baud) = baud_from_selector(baud_selector) else {
        return false;
    };
    config.baud_rate = baud;
    config.data_bits = esp_idf_sys::uart_word_length_t_UART_DATA_8_BITS;
    config.parity = esp_idf_sys::uart_parity_t_UART_PARITY_DISABLE;
    config.stop_bits = esp_idf_sys::uart_stop_bits_t_UART_STOP_BITS_1;
    config.flow_ctrl = esp_idf_sys::uart_hw_flowcontrol_t_UART_HW_FLOWCTRL_DISABLE;
    config.__bindgen_anon_1.source_clk = uart_source_clk();
    if esp_idf_sys::uart_param_config(UART0, &config) != esp_idf_sys::ESP_OK {
        return false;
    }

    let mut event_queue: esp_idf_sys::QueueHandle_t = core::ptr::null_mut();
    let mut result = esp_idf_sys::uart_driver_install(UART0, 2_048, 0, 16, &mut event_queue, 0);
    if result == esp_idf_sys::ESP_ERR_INVALID_STATE {
        let _ = esp_idf_sys::uart_driver_delete(UART0);
        event_queue = core::ptr::null_mut();
        result = esp_idf_sys::uart_driver_install(UART0, 2_048, 0, 16, &mut event_queue, 0);
    }
    if result != esp_idf_sys::ESP_OK || event_queue.is_null() {
        return false;
    }
    UART_RX_EVENT_QUEUE.store(event_queue.cast(), Ordering::Release);
    let (tx_pin, rx_pin) = uart0_pins();
    let _ = esp_idf_sys::_uart_set_pin6(UART0, tx_pin, rx_pin, -1, -1, -1, -1);
    let _ = esp_idf_sys::uart_disable_tx_intr(UART0);
    let _ = esp_idf_sys::uart_set_rx_full_threshold(UART0, 64);
    let _ = esp_idf_sys::uart_set_rx_timeout(UART0, 10);
    esp_idf_sys::uart_set_always_rx_timeout(UART0, true);
    let _ = esp_idf_sys::uart_enable_rx_intr(UART0);
    let _ = esp_idf_sys::uart_set_wakeup_threshold(UART0, 3);
    let _ = esp_idf_sys::esp_sleep_enable_uart_wakeup(UART0 as i32);
    true
}

/// Allocate the bounded bearer queues and start their sole UART/USB owner.
/// It is idempotent at queue level; callers still invoke it exactly once
/// during their firmware startup sequence.
pub unsafe fn start_l2_task() -> bool {
    init_uart_egress_queue() && start_task(UART_L2_STACK_BYTES, 5, 0)
}

/// Start the common UART/USB pool, handlers and L2 task after
/// `install_l2_driver`. Both marked QUIC-lite datagrams and unmarked opaque
/// QUIC packets are admitted to the common pool. The UART adapter does not
/// decode the transport packet.
pub unsafe fn start_shared_l2() -> bool {
    start_l2_task()
}

#[cfg(target_feature = "esp32s3ops")]
fn uart0_pins() -> (i32, i32) {
    // The S3 external bridge's console is UART0 GPIO43/44. Retain these pins
    // through light sleep; this is physical-bearer ownership, not Main policy.
    unsafe {
        let _ = esp_idf_sys::gpio_sleep_sel_dis(43);
        let _ = esp_idf_sys::gpio_sleep_sel_dis(44);
    }
    (43, 44)
}

#[cfg(all(not(target_feature = "esp32s3ops"), not(target_arch = "riscv32")))]
fn uart0_pins() -> (i32, i32) {
    (1, 3)
}

#[cfg(target_arch = "riscv32")]
fn uart0_pins() -> (i32, i32) {
    // ESP32-C6 DevKit boards route their external USB-UART bridge to UART0
    // on GPIO16/17. Native USB-JTAG boards select their packetized endpoint
    // before this function is reached.
    (16, 17)
}

#[cfg(target_arch = "riscv32")]
unsafe fn c6_usb_host_connected() -> bool {
    // ESP-IDF intentionally initializes this monitor to `true` until several
    // scheduler ticks have proven that no USB SOF packets arrive. Main used
    // to query it during that optimistic startup interval and therefore
    // selected an unattached USB-JTAG endpoint on external-UART boards.
    esp_idf_sys::vTaskDelay(8);
    esp_idf_sys::usb_serial_jtag_is_connected()
}

#[cfg(any(target_feature = "esp32s3ops", target_arch = "riscv32"))]
fn uart_source_clk() -> esp_idf_sys::uart_sclk_t {
    esp_idf_sys::soc_periph_uart_clk_src_legacy_t_UART_SCLK_XTAL
}

#[cfg(all(not(target_feature = "esp32s3ops"), not(target_arch = "riscv32")))]
fn uart_source_clk() -> esp_idf_sys::uart_sclk_t {
    esp_idf_sys::soc_periph_uart_clk_src_legacy_t_UART_SCLK_APB
}

#[cfg(any(target_feature = "esp32s3ops", target_arch = "riscv32"))]
const UART_REQUIRES_APB_LOCK: bool = false;
#[cfg(all(not(target_feature = "esp32s3ops"), not(target_arch = "riscv32")))]
const UART_REQUIRES_APB_LOCK: bool = true;

// The classic UART0 source is APB. An active console must retain the APB
// frequency lock or a PM frequency reduction changes its physical baud rate
// after boot, leaving host-to-device RX silently undecodable. The lock is
// created only for an explicitly active UART window and released on expiry;
// it is not permanent UART allocation.
const UART_PM_LOCKS_ENABLED: bool = true;

/// Configure the bounded interactive-console interval. Settings ownership is
/// intentionally above this adapter; the policy only receives validated ms.
pub fn configure_active_window(window_ms: u32) {
    UART_ACTIVE_WINDOW_MS.store(window_ms, Ordering::Release);
}

pub fn activate_window() {
    if !UART_DEBUG_ENABLED.load(Ordering::Acquire) {
        return;
    }
    let window_ms = UART_ACTIVE_WINDOW_MS.load(Ordering::Acquire);
    if window_ms == 0 {
        UART_ACTIVE_UNTIL_MS.store(0, Ordering::Release);
        release_power_locks();
        return;
    }
    UART_ACTIVE_UNTIL_MS.store(now_ms().wrapping_add(window_ms), Ordering::Release);
    let _ = ensure_power_locks();
}

pub fn activate_window_for(window_ms: u32) {
    UART_DEBUG_ENABLED.store(true, Ordering::Release);
    let until = now_ms().wrapping_add(window_ms.max(1));
    let current = UART_ACTIVE_UNTIL_MS.load(Ordering::Acquire);
    if current == 0 || time_after_or_equal(until, current) {
        UART_ACTIVE_UNTIL_MS.store(until, Ordering::Release);
    }
    let _ = ensure_power_locks();
}

pub fn poll_active_window() {
    if UART_ALWAYS_ON.load(Ordering::Acquire) {
        return;
    }
    let deadline = UART_ACTIVE_UNTIL_MS.load(Ordering::Acquire);
    if deadline != 0 && time_after_or_equal(now_ms(), deadline) {
        UART_ACTIVE_UNTIL_MS.store(0, Ordering::Release);
        release_power_locks();
    }
}

pub fn is_active() -> bool {
    UART_DEBUG_ENABLED.load(Ordering::Acquire)
        && (UART_ALWAYS_ON.load(Ordering::Acquire) || active_window_open())
}

pub fn interactive_active() -> bool {
    UART_DEBUG_ENABLED.load(Ordering::Acquire)
        && !UART_ALWAYS_ON.load(Ordering::Acquire)
        && active_window_open()
}

pub fn set_always_on(enabled: bool) {
    UART_ALWAYS_ON.store(enabled, Ordering::Release);
    if enabled {
        UART_DEBUG_ENABLED.store(true, Ordering::Release);
        let _ = ensure_power_locks();
    } else {
        UART_ACTIVE_UNTIL_MS.store(0, Ordering::Release);
        release_power_locks();
    }
}

pub fn set_debug_enabled(enabled: bool) {
    UART_DEBUG_ENABLED.store(enabled, Ordering::Release);
    if enabled {
        activate_window();
    } else {
        UART_ACTIVE_UNTIL_MS.store(0, Ordering::Release);
        release_power_locks();
    }
}

pub fn suspend_for_light_sleep() {
    // A physical UART may remain installed across explicit light sleep: the
    // host only needs it again after the timer wake.  Its APB and
    // NO_LIGHT_SLEEP PM locks, however, would make `esp_light_sleep_start()`
    // reject that explicit boundary immediately.  This helper is therefore
    // intentionally stronger than an ordinary interactive-window expiry;
    // its caller must pair it with `rearm_after_wake()` before admitting more
    // UART work.
    release_power_locks();
}

/// Re-arm the physical UART receive wake after a light-sleep return.
///
/// ESP-IDF can leave the receive interrupt disabled after a GPIO wake even
/// though the driver and the shared L2 task remain installed.  This belongs
/// with that driver owner, not with a Main command or battery-policy module.
pub fn rearm_after_wake() {
    let physical_uart = {
        #[cfg(target_arch = "riscv32")]
        {
            !C6_USB_JTAG_SELECTED.load(Ordering::Acquire)
        }
        #[cfg(not(target_arch = "riscv32"))]
        {
            true
        }
    };
    if physical_uart {
        unsafe {
            let _ = esp_idf_sys::uart_set_wakeup_threshold(esp_idf_sys::uart_port_t_UART_NUM_0, 3);
            let _ = esp_idf_sys::uart_enable_rx_intr(esp_idf_sys::uart_port_t_UART_NUM_0);
        }
    }
    if UART_DEBUG_ENABLED.load(Ordering::Acquire) {
        activate_window();
    }
}

fn ensure_power_locks() -> bool {
    if !UART_PM_LOCKS_ENABLED {
        return true;
    }
    ensure_apb_lock() && ensure_no_light_sleep_lock()
}

fn active_window_open() -> bool {
    let deadline = UART_ACTIVE_UNTIL_MS.load(Ordering::Acquire);
    deadline != 0 && !time_after_or_equal(now_ms(), deadline)
}

fn ensure_apb_lock() -> bool {
    if !UART_REQUIRES_APB_LOCK {
        UART_APB_LOCK_HELD.store(true, Ordering::Release);
        return true;
    }
    unsafe {
        let mut lock = UART_APB_LOCK.load(Ordering::Acquire);
        if lock.is_null() {
            let mut created = core::ptr::null_mut();
            if esp_idf_sys::esp_pm_lock_create(
                esp_idf_sys::esp_pm_lock_type_t_ESP_PM_APB_FREQ_MAX,
                0,
                b"dmesh_uart_apb\0".as_ptr().cast(),
                &mut created,
            ) != esp_idf_sys::ESP_OK
                || created.is_null()
            {
                return false;
            }
            match UART_APB_LOCK.compare_exchange(
                core::ptr::null_mut(),
                created,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => lock = created,
                Err(existing) => {
                    let _ = esp_idf_sys::esp_pm_lock_delete(created);
                    lock = existing;
                }
            }
        }
        if !UART_APB_LOCK_HELD.swap(true, Ordering::AcqRel)
            && esp_idf_sys::esp_pm_lock_acquire(lock) != esp_idf_sys::ESP_OK
        {
            UART_APB_LOCK_HELD.store(false, Ordering::Release);
            return false;
        }
    }
    true
}

fn ensure_no_light_sleep_lock() -> bool {
    unsafe {
        let mut lock = UART_NO_LIGHT_SLEEP_LOCK.load(Ordering::Acquire);
        if lock.is_null() {
            let mut created = core::ptr::null_mut();
            if esp_idf_sys::esp_pm_lock_create(
                esp_idf_sys::esp_pm_lock_type_t_ESP_PM_NO_LIGHT_SLEEP,
                0,
                b"dmesh_uart_no_ls\0".as_ptr().cast(),
                &mut created,
            ) != esp_idf_sys::ESP_OK
                || created.is_null()
            {
                return false;
            }
            match UART_NO_LIGHT_SLEEP_LOCK.compare_exchange(
                core::ptr::null_mut(),
                created,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => lock = created,
                Err(existing) => {
                    let _ = esp_idf_sys::esp_pm_lock_delete(created);
                    lock = existing;
                }
            }
        }
        if !UART_NO_LIGHT_SLEEP_LOCK_HELD.swap(true, Ordering::AcqRel)
            && esp_idf_sys::esp_pm_lock_acquire(lock) != esp_idf_sys::ESP_OK
        {
            UART_NO_LIGHT_SLEEP_LOCK_HELD.store(false, Ordering::Release);
            return false;
        }
    }
    true
}

fn release_power_locks() {
    if UART_NO_LIGHT_SLEEP_LOCK_HELD.swap(false, Ordering::AcqRel) {
        let lock = UART_NO_LIGHT_SLEEP_LOCK.load(Ordering::Acquire);
        if !lock.is_null() {
            unsafe {
                let _ = esp_idf_sys::esp_pm_lock_release(lock);
            }
        }
    }
    if !UART_APB_LOCK_HELD.swap(false, Ordering::AcqRel) || !UART_REQUIRES_APB_LOCK {
        return;
    }
    let lock = UART_APB_LOCK.load(Ordering::Acquire);
    if !lock.is_null() {
        unsafe {
            let _ = esp_idf_sys::esp_pm_lock_release(lock);
        }
    }
}

fn now_ms() -> u32 {
    unsafe { (esp_idf_sys::esp_timer_get_time().max(0) as u64 / 1_000) as u32 }
}

fn time_after_or_equal(now: u32, deadline: u32) -> bool {
    now.wrapping_sub(deadline) < i32::MAX as u32
}

/// One raw record waiting for the dedicated serial task. It is deliberately
/// *not* an escaped PPP frame: for transport output `bytes` contains only the
/// opaque QUIC packet, and uart-codec adds the marker plus PPP escaping while
/// USB accepts bytes. Thus PPP costs no 2x-MTU buffer, even when every payload
/// byte needs escaping.
#[repr(C)]
struct QueuedUartPayload {
    /// `UART_EGRESS_PPP` is an opaque QUIC packet; `UART_EGRESS_TEXT` is raw
    /// ASCII diagnostic text (the writer appends CRLF). Both have one writer.
    kind: u8,
    len: u16,
    bytes: [u8; UART_MAX_PACKET],
}

// Classic retains static task backing, but egress records are allocated only
// while UART is enabled and can be sized from measured headroom. Keep the
// classic UART receive and transmit tasks separate, as in the proven original
// Main/Recovery implementation: RX waits indefinitely for the driver's event
// queue at priority 6 while TX waits independently for framed egress at
// priority 5.  That avoids polling the console event queue while a large PPP
// write is pending.
#[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
const UART_CLASSIC_TASK_STACK_WORDS: usize = (UART_L2_STACK_BYTES as usize) / 2;
#[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
static mut UART_RX_TASK_CONTROL: core::mem::MaybeUninit<esp_idf_sys::StaticTask_t> =
    core::mem::MaybeUninit::uninit();
#[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
static mut UART_RX_TASK_STACK: [esp_idf_sys::StackType_t; UART_CLASSIC_TASK_STACK_WORDS] =
    [0; UART_CLASSIC_TASK_STACK_WORDS];
#[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
static UART_RX_TASK_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
#[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
static mut UART_TX_TASK_CONTROL: core::mem::MaybeUninit<esp_idf_sys::StaticTask_t> =
    core::mem::MaybeUninit::uninit();
#[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
static mut UART_TX_TASK_STACK: [esp_idf_sys::StackType_t; UART_CLASSIC_TASK_STACK_WORDS] =
    [0; UART_CLASSIC_TASK_STACK_WORDS];
#[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
static UART_TX_TASK_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

const UART_EGRESS_PPP: u8 = 1;
const UART_EGRESS_TEXT: u8 = 2;
/// ESP UART adapter for the common bearer API. It retains exactly one pool
/// lease while the dedicated physical writer performs PPP framing and returns
/// that lease only after the final framed byte has been accepted.
pub struct EspUartBearer;

impl PacketEgress<crate::shared_ingress_esp::SharedPacketLease> for EspUartBearer {
    fn submit(
        &mut self,
        _peer_l2_address: PeerL2Address,
        submission: UartPoolSubmission,
    ) -> Result<(), PacketSubmitError<crate::shared_ingress_esp::SharedPacketLease>> {
        if !physical_bearer_active()
            || UART_POOL_SUBMISSION_STATE
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Err(PacketSubmitError::WouldBlock(submission));
        }
        unsafe {
            core::ptr::addr_of_mut!(UART_POOL_SUBMISSION)
                .write(core::mem::MaybeUninit::new(submission))
        };
        // State 1 reserves the slot while it is initialized. Publish state 2
        // only after the ownership-bearing value is complete, so the writer
        // can never observe an uninitialized submission.
        UART_POOL_SUBMISSION_STATE.store(2, Ordering::Release);
        #[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
        notify_classic_tx_task();
        Ok(())
    }
}

#[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
fn notify_classic_tx_task() {
    let task = UART_TX_TASK_HANDLE.load(Ordering::Acquire);
    if !task.is_null() {
        unsafe {
            let _ = esp_idf_sys::xTaskGenericNotify(
                task.cast(),
                0,
                1,
                esp_idf_sys::eNotifyAction_eSetBits,
                core::ptr::null_mut(),
            );
        }
    }
}

pub unsafe fn init_transport_ingress_queue() -> bool {
    // Kept as an idempotent compatibility entry point for Recovery/Main
    // bootstrap. UART transport ingress is now the shared packet-pool queue.
    true
}

pub unsafe fn init_uart_egress_queue() -> bool {
    if !UART_EGRESS_QUEUE.load(Ordering::Acquire).is_null() {
        return true;
    }
    let capacity = select_egress_capacity();
    let queue = esp_idf_sys::xQueueGenericCreate(
        capacity as _,
        core::mem::size_of::<QueuedUartPayload>() as _,
        0,
    );
    if queue.is_null() {
        return false;
    }
    match UART_EGRESS_QUEUE.compare_exchange(
        core::ptr::null_mut(),
        queue.cast(),
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => {
            UART_EGRESS_CAPACITY.store(capacity, Ordering::Release);
            true
        }
        Err(_) => true,
    }
}

/// Select a small UART flight from the actual internal heap before Wi-Fi
/// owns its dynamic buffers. Four records cost roughly 5 KiB plus FreeRTOS
/// metadata, so only choose it with a deliberately conservative 72 KiB
/// headroom. A constrained classic board still has a functional one-record
/// queue because the shared worker is woken by each dequeue edge.
fn select_egress_capacity() -> usize {
    #[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
    {
        let caps = esp_idf_sys::MALLOC_CAP_INTERNAL | esp_idf_sys::MALLOC_CAP_8BIT;
        let free = unsafe { esp_idf_sys::heap_caps_get_free_size(caps) as usize };
        if free >= 72 * 1024 {
            4
        } else if free >= 48 * 1024 {
            2
        } else {
            1
        }
    }
    #[cfg(any(target_arch = "riscv32", target_feature = "esp32s3ops"))]
    {
        UART_EGRESS_MAX_CAPACITY
    }
}

/// Immediate egress capacity suitable for `quic_lite::PathCapacity`. This is
/// local L2 feedback, not stream credit: the transport remains responsible
/// for end-to-end ACK, retransmission, and flow control.
pub(crate) fn transport_egress_capacity() -> (usize, usize) {
    (
        UART_EGRESS_QUEUED.load(Ordering::Acquire),
        UART_EGRESS_CAPACITY.load(Ordering::Acquire),
    )
}

fn enqueue_uart_payload(kind: u8, payload: &[u8]) -> bool {
    if payload.is_empty() || payload.len() > UART_MAX_PACKET {
        return false;
    }
    if !matches!(kind, UART_EGRESS_PPP | UART_EGRESS_TEXT) {
        return false;
    }
    let queue = UART_EGRESS_QUEUE.load(Ordering::Acquire);
    if queue.is_null() {
        return false;
    }
    let mut queued = QueuedUartPayload {
        kind,
        len: payload.len() as u16,
        bytes: [0; UART_MAX_PACKET],
    };
    queued.bytes[..payload.len()].copy_from_slice(payload);
    // Increment before waking the serial task through xQueueGenericSend: the
    // receiver has higher scheduling priority and may dequeue immediately.
    // A failed send rolls the provisional count back below.
    UART_EGRESS_QUEUED.fetch_add(1, Ordering::AcqRel);
    let accepted = unsafe {
        esp_idf_sys::xQueueGenericSend(
            queue.cast(),
            (&queued as *const QueuedUartPayload).cast(),
            0,
            0,
        ) == 1
    };
    if !accepted {
        UART_EGRESS_QUEUED.fetch_sub(1, Ordering::AcqRel);
    } else {
        #[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
        notify_classic_tx_task();
    }
    accepted
}

fn dequeue_uart_payload(out: &mut QueuedUartPayload) -> bool {
    dequeue_uart_payload_wait(out, 0)
}

fn dequeue_uart_payload_wait(out: &mut QueuedUartPayload, ticks_to_wait: u32) -> bool {
    let queue = UART_EGRESS_QUEUE.load(Ordering::Acquire);
    if queue.is_null()
        || unsafe {
            esp_idf_sys::xQueueReceive(
                queue.cast(),
                (out as *mut QueuedUartPayload).cast(),
                ticks_to_wait,
            )
        } != 1
    {
        return false;
    }
    UART_EGRESS_QUEUED.fetch_sub(1, Ordering::AcqRel);
    let len = usize::from(out.len);
    matches!(out.kind, UART_EGRESS_PPP | UART_EGRESS_TEXT) && len != 0 && len <= UART_MAX_PACKET
}

fn dequeue_uart_current(ticks_to_wait: u32) -> bool {
    unsafe {
        UART_TX_CURRENT.write(QueuedUartPayload {
            kind: UART_EGRESS_PPP,
            len: 0,
            bytes: [0; UART_MAX_PACKET],
        });
        dequeue_uart_payload_wait(UART_TX_CURRENT.assume_init_mut(), ticks_to_wait)
    }
}

fn write_uart_current() {
    unsafe { write_queued_payload(UART_TX_CURRENT.assume_init_ref()) }
}

/// Install or clear a task-context notification callback for newly accepted
/// UART ingress. The callback must be nonblocking and safe from the dedicated
/// FreeRTOS UART task; it is not an interrupt callback.
pub fn set_ingress_notify(callback: Option<fn()>) {
    let callback = callback.map_or(0, |callback| callback as usize);
    INGRESS_NOTIFY.store(callback, Ordering::Release);
}

/// Install or clear the task-context notification for newly available UART
/// egress capacity. The dedicated UART writer calls it after dequeuing a
/// record, never from an interrupt, so its recipient may safely enqueue a
/// typed shared-worker event without allocating or touching the UART driver.
pub fn set_egress_notify(callback: Option<fn()>) {
    let callback = callback.map_or(0, |callback| callback as usize);
    EGRESS_NOTIFY.store(callback, Ordering::Release);
}

fn notify_ingress() {
    let callback = INGRESS_NOTIFY.load(Ordering::Acquire);
    if callback != 0 {
        // Function pointers are stored only by `set_ingress_notify` above.
        // A function pointer is non-null and fits in usize on supported ESP
        // targets; no callback owns or aliases UART queue memory.
        let callback: fn() = unsafe { core::mem::transmute(callback) };
        callback();
    }
}

fn notify_egress_ready() {
    let callback = EGRESS_NOTIFY.load(Ordering::Acquire);
    if callback != 0 {
        // The writer has already dequeued the record, so the callback observes
        // one available queue slot. It is only a wake edge; packet production
        // remains serialized on shared_ingress_esp.
        let callback: fn() = unsafe { core::mem::transmute(callback) };
        callback();
    }
}

/// Queue one raw ASCII diagnostic line for the sole physical UART writer.
///
/// This is deliberately not a service or a command response. It is the
/// troubleshooting exception shared with boot/crash text: usable when PPP or
/// QUIC-lite itself is suspect, bounded and lossy, and never written directly
/// by a Wi-Fi, transport, or application task. The ASCII/no-flag rule keeps a
/// diagnostic line from accidentally opening or corrupting a PPP frame.
pub fn send_debug_text(text: &[u8]) -> bool {
    if text.is_empty()
        || text.len().saturating_add(2) > UART_MAX_PACKET
        || !text.is_ascii()
        || text.iter().any(|byte| matches!(*byte, 0x7d | 0x7e))
    {
        return false;
    }
    enqueue_uart_payload(UART_EGRESS_TEXT, text)
}

/// C/ESP-IDF log bridge. It only queues an already-formatted diagnostic line;
/// the dedicated UART writer remains the sole physical UART0 owner.
#[no_mangle]
pub unsafe extern "C" fn dmesh_uart_log_line(bytes: *const u8, len: usize) -> i32 {
    if bytes.is_null() || len == 0 || len > 255 {
        return -1;
    }
    let line = core::slice::from_raw_parts(bytes, len);
    i32::from(send_debug_text(line))
}

#[cfg(target_arch = "riscv32")]
fn write_usb(bytes: &[u8]) -> i32 {
    unsafe {
        if C6_USB_JTAG_SELECTED.load(Ordering::Acquire) {
            // The queue owner never waits for USB. A partial write remains at
            // the head of the task-local frame until it is complete.
            esp_idf_sys::usb_serial_jtag_write_bytes(bytes.as_ptr().cast(), bytes.len(), 0)
        } else {
            esp_idf_sys::uart_write_bytes(
                esp_idf_sys::uart_port_t_UART_NUM_0,
                bytes.as_ptr().cast(),
                bytes.len(),
            ) as i32
        }
    }
}

/// Emit one queued raw record without constructing an escaped frame. This
/// runs only in the sole physical writer task, so the borrowed payload stays
/// valid until the final byte has been accepted by the driver.
fn write_queued_payload(queued: &QueuedUartPayload) {
    let len = usize::from(queued.len);
    if len == 0 || len > UART_MAX_PACKET {
        return;
    }
    match queued.kind {
        UART_EGRESS_PPP => {
            let Ok(mut encoder) = encode_packet(&queued.bytes[..len]) else {
                return;
            };
            while !encoder.is_finished() {
                let produced = unsafe { encoder.write(&mut UART_TX_SCRATCH) };
                write_all(&unsafe { &UART_TX_SCRATCH[..produced] });
            }
        }
        UART_EGRESS_TEXT => {
            write_all(&queued.bytes[..len]);
            write_all(b"\r\n");
        }
        _ => {}
    }
}

fn write_pool_submission_if_ready() -> bool {
    if UART_POOL_SUBMISSION_STATE
        .compare_exchange(2, 3, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false;
    }
    let submission = unsafe {
        core::ptr::addr_of!(UART_POOL_SUBMISSION)
            .read()
            .assume_init()
    };
    let result = write_transport_bytes(submission.packet().bytes());
    UART_POOL_SUBMISSION_STATE.store(0, Ordering::Release);
    submission.complete(
        if result {
            PacketSendOutcome::Sent
        } else {
            PacketSendOutcome::Failed
        },
        0,
    );
    notify_egress_ready();
    true
}

fn write_transport_bytes(packet: &[u8]) -> bool {
    let Ok(mut encoder) = encode_packet(packet) else {
        return false;
    };
    while !encoder.is_finished() {
        let produced = unsafe { encoder.write(&mut UART_TX_SCRATCH) };
        write_all(unsafe { &UART_TX_SCRATCH[..produced] });
    }
    true
}

fn write_all(bytes: &[u8]) {
    let mut offset = 0usize;
    while offset < bytes.len() {
        let written = write_usb(&bytes[offset..]);
        if written <= 0 {
            unsafe { esp_idf_sys::vTaskDelay(1) };
            continue;
        }
        offset = offset.saturating_add(written as usize).min(bytes.len());
    }
}
#[cfg(not(target_arch = "riscv32"))]
fn write_usb(bytes: &[u8]) -> i32 {
    unsafe {
        esp_idf_sys::uart_write_bytes(
            esp_idf_sys::uart_port_t_UART_NUM_0,
            bytes.as_ptr().cast(),
            bytes.len(),
        ) as i32
    }
}

#[cfg(target_arch = "riscv32")]
fn read_usb(bytes: &mut [u8], ticks_to_wait: u32) -> i32 {
    unsafe {
        if C6_USB_JTAG_SELECTED.load(Ordering::Acquire) {
            esp_idf_sys::usb_serial_jtag_read_bytes(
                bytes.as_mut_ptr().cast(),
                bytes.len() as u32,
                ticks_to_wait,
            )
        } else {
            esp_idf_sys::uart_read_bytes(
                esp_idf_sys::uart_port_t_UART_NUM_0,
                bytes.as_mut_ptr().cast(),
                bytes.len() as u32,
                ticks_to_wait,
            )
        }
    }
}
#[cfg(not(target_arch = "riscv32"))]
fn read_usb(bytes: &mut [u8], ticks_to_wait: u32) -> i32 {
    unsafe {
        esp_idf_sys::uart_read_bytes(
            esp_idf_sys::uart_port_t_UART_NUM_0,
            bytes.as_mut_ptr().cast(),
            bytes.len() as u32,
            ticks_to_wait,
        )
    }
}

pub unsafe extern "C" fn task_entry(_argument: *mut c_void) {
    command_task();
}

#[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
unsafe extern "C" fn classic_rx_task_entry(argument: *mut c_void) {
    classic_rx_task(argument.cast());
}

#[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
unsafe extern "C" fn classic_tx_task_entry(_argument: *mut c_void) {
    classic_tx_task();
}

/// Start the dedicated physical UART L2 task after the platform has installed
/// its UART or USB-JTAG driver and all three queues are ready. The
/// task is the only reader and writer of that driver; callers interact only
/// through opaque direct-record or QUIC-lite packet queues.
pub unsafe fn start_task(stack_bytes: u32, priority: u32, core: i32) -> bool {
    #[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
    {
        if !UART_RX_TASK_HANDLE.load(Ordering::Acquire).is_null()
            && !UART_TX_TASK_HANDLE.load(Ordering::Acquire).is_null()
        {
            return true;
        }
        if stack_bytes as usize != UART_L2_STACK_BYTES as usize {
            return false;
        }
        let event_queue = UART_RX_EVENT_QUEUE.load(Ordering::Acquire);
        let egress_queue = UART_EGRESS_QUEUE.load(Ordering::Acquire);
        if event_queue.is_null() || egress_queue.is_null() {
            return false;
        }
        let rx_task = esp_idf_sys::xTaskCreateStaticPinnedToCore(
            Some(classic_rx_task_entry),
            b"dmesh_uart_rx\0".as_ptr().cast(),
            UART_CLASSIC_TASK_STACK_WORDS as u32,
            event_queue.cast(),
            priority.saturating_add(1),
            core::ptr::addr_of_mut!(UART_RX_TASK_STACK).cast(),
            core::ptr::addr_of_mut!(UART_RX_TASK_CONTROL).cast(),
            core,
        );
        if rx_task.is_null() {
            return false;
        }
        if UART_RX_TASK_HANDLE
            .compare_exchange(
                core::ptr::null_mut(),
                rx_task.cast(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            esp_idf_sys::vTaskDelete(rx_task);
            return false;
        }
        let tx_task = esp_idf_sys::xTaskCreateStaticPinnedToCore(
            Some(classic_tx_task_entry),
            b"dmesh_uart_tx\0".as_ptr().cast(),
            UART_CLASSIC_TASK_STACK_WORDS as u32,
            egress_queue.cast(),
            priority,
            core::ptr::addr_of_mut!(UART_TX_TASK_STACK).cast(),
            core::ptr::addr_of_mut!(UART_TX_TASK_CONTROL).cast(),
            core,
        );
        if tx_task.is_null() {
            UART_RX_TASK_HANDLE.store(core::ptr::null_mut(), Ordering::Release);
            esp_idf_sys::vTaskDelete(rx_task);
            return false;
        }
        if UART_TX_TASK_HANDLE
            .compare_exchange(
                core::ptr::null_mut(),
                tx_task.cast(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            esp_idf_sys::vTaskDelete(tx_task);
            UART_RX_TASK_HANDLE.store(core::ptr::null_mut(), Ordering::Release);
            esp_idf_sys::vTaskDelete(rx_task);
            return false;
        }
        return true;
    }

    #[cfg(any(target_arch = "riscv32", target_feature = "esp32s3ops"))]
    {
        let mut task = core::ptr::null_mut();
        esp_idf_sys::xTaskCreatePinnedToCore(
            Some(task_entry),
            b"dmesh_uart_l2\0".as_ptr().cast(),
            stack_bytes,
            core::ptr::null_mut(),
            priority,
            &mut task,
            core,
        ) == 1
            && !task.is_null()
    }
}

/// Restore the original classic ESP32 event-driven receive ownership.  The
/// UART driver is the source of truth for RX readiness: this task does not
/// poll its ring after an empty event or share the queue with transmit.
#[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
fn classic_rx_task(event_queue: *mut esp_idf_sys::QueueDefinition) {
    let mut decoder = PooledDecoder::new(crate::quic_node_esp::uart_pool());
    let mut bytes = [0u8; 256];
    loop {
        let mut event = esp_idf_sys::uart_event_t::default();
        let received = unsafe {
            esp_idf_sys::xQueueReceive(
                event_queue.cast(),
                (&mut event as *mut esp_idf_sys::uart_event_t).cast(),
                esp_idf_sys::TickType_t::MAX,
            )
        };
        if received != 1 {
            continue;
        }
        UART_RX_EVENT_COUNT.fetch_add(1, Ordering::Relaxed);
        match event.type_ {
            kind if kind == esp_idf_sys::uart_event_type_t_UART_DATA => {
                drain_uart_driver(&mut decoder, &mut bytes);
            }
            kind if kind == esp_idf_sys::uart_event_type_t_UART_FIFO_OVF
                || kind == esp_idf_sys::uart_event_type_t_UART_BUFFER_FULL =>
            {
                unsafe {
                    let _ = esp_idf_sys::uart_flush_input(esp_idf_sys::uart_port_t_UART_NUM_0);
                    let _ = esp_idf_sys::xQueueGenericReset(event_queue.cast(), 0);
                }
                decoder = PooledDecoder::new(crate::quic_node_esp::uart_pool());
            }
            _ => {}
        }
    }
}

/// The matching classic ESP32 writer. Pool-backed QUIC submissions wake it
/// directly; local diagnostic text remains in the auxiliary queue.
#[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
fn classic_tx_task() {
    loop {
        let _ = write_pool_submission_if_ready();
        while dequeue_uart_current(0) {
            notify_egress_ready();
            write_uart_current();
        }
        unsafe {
            let _ = esp_idf_sys::xTaskGenericNotifyWait(
                0,
                0,
                u32::MAX,
                core::ptr::null_mut(),
                esp_idf_sys::TickType_t::MAX,
            );
        }
    }
}

/// Dedicated nonblocking UART L2 task. It owns only PPP decode and fixed-size
/// ingress queues; QUIC-lite dispatch happens above it.
fn command_task() {
    let mut decoder = PooledDecoder::new(crate::quic_node_esp::uart_pool());
    let mut bytes = [0u8; 256];
    // This record is emitted only after the physical driver, codec pool,
    // no-std QUIC runtime, registered bearer, egress queue, and sole UART task
    // are all live. A reset-time host watch can therefore distinguish a
    // functioning UART transport from earlier ROM/ESP-IDF console text.
    let _ = send_debug_text(b"DMESH uart: writer ready");
    crate::commands::send_response(b"DMESH uart: quic ready");
    loop {
        // C6/S3 own a cooperative UART task, so a published pool lease is its
        // own wake condition. Do not copy a packet-sized dummy record through
        // the legacy queue merely to signal this task.
        let wrote_pool_submission = write_pool_submission_if_ready();
        let has_pending = dequeue_uart_current(0);
        if has_pending {
            notify_egress_ready();
            write_uart_current();
        }
        #[cfg(target_arch = "riscv32")]
        {
            if C6_USB_JTAG_SELECTED.load(Ordering::Acquire) {
                // USB-JTAG has no ESP-IDF UART event queue. Its nonblocking
                // driver read is the corresponding one-owner primitive.
                let count = read_usb(&mut bytes, 0);
                if count > 0 {
                    UART_RX_BYTE_COUNT.fetch_add(count as u32, Ordering::Relaxed);
                    consume_uart_bytes(&mut decoder, &bytes[..count as usize]);
                    continue;
                }
            }
        }

        let use_uart_events = {
            #[cfg(target_arch = "riscv32")]
            {
                !C6_USB_JTAG_SELECTED.load(Ordering::Acquire)
            }
            #[cfg(not(target_arch = "riscv32"))]
            {
                true
            }
        };
        if use_uart_events {
            let event_queue = UART_RX_EVENT_QUEUE.load(Ordering::Acquire);
            if !event_queue.is_null() {
                let mut event = esp_idf_sys::uart_event_t::default();
                let received = unsafe {
                    esp_idf_sys::xQueueReceive(
                        event_queue.cast(),
                        (&mut event as *mut esp_idf_sys::uart_event_t).cast(),
                        0,
                    )
                };
                if received == 1 {
                    UART_RX_EVENT_COUNT.fetch_add(1, Ordering::Relaxed);
                    match event.type_ {
                        kind if kind == esp_idf_sys::uart_event_type_t_UART_DATA => {
                            drain_uart_driver(&mut decoder, &mut bytes);
                            continue;
                        }
                        kind if kind == esp_idf_sys::uart_event_type_t_UART_FIFO_OVF
                            || kind == esp_idf_sys::uart_event_type_t_UART_BUFFER_FULL =>
                        {
                            unsafe {
                                let _ = esp_idf_sys::uart_flush_input(
                                    esp_idf_sys::uart_port_t_UART_NUM_0,
                                );
                                let _ = esp_idf_sys::xQueueGenericReset(event_queue.cast(), 0);
                            }
                            decoder = PooledDecoder::new(crate::quic_node_esp::uart_pool());
                        }
                        _ => {}
                    }
                }
                // Some classic ESP-IDF UART0 console handoffs retain bytes
                // in the driver ring without publishing a UART_DATA event.
                // The L2 task remains the sole reader; make one zero-wait
                // drain after the bounded event wait so that condition cannot
                // strand an otherwise complete PPP record.
                drain_uart_driver(&mut decoder, &mut bytes);
            }
        }

        // A pending egress frame must not turn an idle receive into a full
        // RTOS-tick wait. Yield after an empty poll so the UART task remains
        // cooperative while a partial write is retried.
        unsafe {
            esp_idf_sys::vTaskDelay(if has_pending || wrote_pool_submission {
                0
            } else {
                1
            });
        }
    }
}

fn drain_uart_driver(
    decoder: &mut PooledDecoder<crate::quic_node_esp::FirmwarePool>,
    bytes: &mut [u8; 256],
) {
    loop {
        let count = read_usb(bytes, 0);
        if count <= 0 {
            break;
        }
        UART_RX_BYTE_COUNT.fetch_add(count as u32, Ordering::Relaxed);
        if !UART_RX_BYTES_REPORTED.swap(true, Ordering::AcqRel) {
            let _ = send_debug_text(b"DMESH uart: first physical rx bytes");
        }
        consume_uart_bytes(decoder, &bytes[..count as usize]);
    }
}

fn consume_uart_bytes(
    decoder: &mut PooledDecoder<crate::quic_node_esp::FirmwarePool>,
    bytes: &[u8],
) {
    if !physical_receive_enabled() {
        // Keep the ESP-IDF driver owner installed, but discard bytes while
        // UART is explicitly disabled by policy. An expired interactive
        // window is not disabled: receiving bytes reopens that window so a
        // host can attach to an otherwise idle UART port.
        return;
    }
    activate_window();
    decoder.push(
        bytes,
        quic_lite::PACKET_PREFIX_RESERVE,
        |frame| match frame {
            PooledFrame::Packet(packet) => {
                activate_window();
                if !UART_RX_PACKET_REPORTED.swap(true, Ordering::AcqRel) {
                    let _ = send_debug_text(b"DMESH uart: first pooled packet rx");
                }
                crate::quic_node_esp::receive_uart(packet);
                notify_ingress();
            }
            PooledFrame::PoolUnavailable => {
                let _ = send_debug_text(b"DMESH uart: packet pool unavailable");
            }
            PooledFrame::Log(_) => {}
        },
    );
}

fn physical_bearer_active() -> bool {
    #[cfg(target_arch = "riscv32")]
    if C6_USB_JTAG_SELECTED.load(Ordering::Acquire) {
        return true;
    }
    is_active()
}

fn physical_receive_enabled() -> bool {
    #[cfg(target_arch = "riscv32")]
    if C6_USB_JTAG_SELECTED.load(Ordering::Acquire) {
        return true;
    }
    UART_DEBUG_ENABLED.load(Ordering::Acquire)
}
