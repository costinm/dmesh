// IMPORTANT: This is shared no-std ESP firmware code. It owns ESP USB/UART
// queues and the nonblocking FreeRTOS L2 task shared by Recovery and Main.
// PPP marker semantics and classification are shared server/bearer policy.

// TODO: copy uart_codec codec into this file - making escaping/framing integral and done closer to the driver.
// TODO: evaluate using interrupts for send and receive
// Normal QUIC ingress/egress already uses the shared packet pool. The
// remaining sideband decoder scratch is limited to rare UART control records.

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicUsize, Ordering};

use dmesh_server::firmware_profile::{UART_DEFAULT, UART_OFF};
use quic_lite::packet_pool::PacketLeaseQueue;
use quic_lite::{
    EgressSubmission, PacketEgress, PacketSendOutcome, PacketSubmitError, PacketWriter,
    PeerL2Address,
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

// Only one rare baud-handshake ACK can be queued outside QUIC at a time.
// Queue entries are leases and metadata only; no MTU-sized UART array exists.
const UART_CONTROL_QUEUE_CAPACITY: usize = 1;
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
static UART_RX_PACKET_COUNT: AtomicU32 = AtomicU32::new(0);
static UART_RX_WAKE_COUNT: AtomicU32 = AtomicU32::new(0);
static UART_RX_OVERRUN_COUNT: AtomicU32 = AtomicU32::new(0);

/// Private driver diagnostics; monotonic counters, not application completion.
/// The final item is the rare pool-backed sideband-control queue depth.
pub(crate) fn receive_diagnostics() -> [u32; 7] {
    [
        UART_RX_BYTE_COUNT.load(Ordering::Relaxed),
        UART_RX_EVENT_COUNT.load(Ordering::Relaxed),
        UART_RX_PACKET_COUNT.load(Ordering::Relaxed),
        UART_RX_WAKE_COUNT.load(Ordering::Relaxed),
        UART_RX_OVERRUN_COUNT.load(Ordering::Relaxed),
        UART_POOL_SUBMISSION_STATE.load(Ordering::Acquire) as u32,
        UART_EGRESS_QUEUED.load(Ordering::Acquire) as u32,
    ]
}

/// Read-only task-context observation of bytes already in the driver's RX
/// ring. This does not consume bytes or create a second UART reader.
pub(crate) fn buffered_receive_bytes() -> Option<u32> {
    #[cfg(target_arch = "riscv32")]
    if C6_USB_JTAG_SELECTED.load(Ordering::Acquire) {
        return None;
    }
    let mut bytes = 0usize;
    let result = unsafe {
        esp_idf_sys::uart_get_buffered_data_len(esp_idf_sys::uart_port_t_UART_NUM_0, &mut bytes)
    };
    (result == esp_idf_sys::ESP_OK).then_some(bytes.min(u32::MAX as usize) as u32)
}
/// Optional firmware-owner wake hook. The L2 task has no dependency on Main,
/// Recovery, commands, or a particular executor; an owner can install this
/// one-shot notification so its dispatcher need not wait for a housekeeping
/// timeout after an ingress queue transition.
static INGRESS_NOTIFY: AtomicUsize = AtomicUsize::new(0);
/// Optional task-context notification after the single QUIC pool submission
/// slot is released. It carries no packet; the shared owner retries its own
/// retained stream state after this writable edge.
static EGRESS_NOTIFY: AtomicUsize = AtomicUsize::new(0);
static UART_EGRESS_QUEUED: AtomicUsize = AtomicUsize::new(0);

type UartPoolSubmission = EgressSubmission<crate::shared_ingress_esp::SharedPacketLease>;
type UartControlPacket = quic_lite::OwnedPacket<crate::shared_ingress_esp::SharedPacketLease>;
static UART_CONTROL_TX: PacketLeaseQueue<
    u8,
    crate::shared_ingress_esp::SharedPacketLease,
    UART_CONTROL_QUEUE_CAPACITY,
> = PacketLeaseQueue::new();

// The bearer accepts only one pool lease at a time. Task notification carries
// only a wake edge; the ownership-bearing QUIC submission stays in this slot.
static UART_POOL_SUBMISSION_STATE: AtomicUsize = AtomicUsize::new(0);
/// Set only after QUIC receives `WouldBlock` because the single physical TX
/// slot is occupied. The writer reports readiness only for this edge, rather
/// than publishing one ready event for every successful packet completion.
static UART_SEND_BLOCKED: AtomicBool = AtomicBool::new(false);
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
        9 => Some(921_600),
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
    let Some(baud) = baud_from_selector(baud_selector) else {
        return false;
    };
    install_l2_driver_baud(baud)
}

/// Install with a reviewed physical rate; native USB-JTAG ignores the rate.
pub unsafe fn install_l2_driver_baud(baud: i32) -> bool {
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
        return install_uart0_driver(baud);
    }

    #[cfg(not(target_arch = "riscv32"))]
    {
        install_uart0_driver(baud)
    }
}

unsafe fn install_uart0_driver(baud: i32) -> bool {
    const UART0: esp_idf_sys::uart_port_t = esp_idf_sys::uart_port_t_UART_NUM_0;
    let mut config = esp_idf_sys::uart_config_t::default();
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

// Keep the driver installed without a UART-owned power lock. Main's PM
// configuration keeps the awake CPU at >=80 MHz, so classic ESP32's APB
// remains at 80 MHz without a frequency lock. ESP-IDF's APB_MAX lock also
// vetoes automatic light sleep: reacquiring it on packet RX after Main's
// one-time grace release prevented NAN-only devices from sleeping again.
// UART reception during discovery windows and the framed wake train remain
// unchanged; UART is not an independent reason to keep the CPU awake.
const UART_PM_LOCKS_ENABLED: bool = false;

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
    #[cfg(not(target_arch = "riscv32"))]
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
        // Always-on means the driver/bearer remains enabled, not that it
        // owns a permanent PM lock. NAN-only Main may enter light sleep and
        // receive again when the CPU wakes for its discovery window.
        #[cfg(not(target_arch = "riscv32"))]
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
    // UART remains installed, but does not veto NAN-only CPU idle sleep.
    // Classic UART0 still needs the APB frequency constraint to preserve baud;
    // that is not a NO_LIGHT_SLEEP constraint. Active personalities disable
    // automatic light sleep in Main's power policy instead.
    ensure_apb_lock()
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

// Physical Xtensa UARTs retain static task backing; egress records are sized
// from measured headroom. Keep the receive and transmit tasks separate, as in
// the proven original
// Main/Recovery implementation: RX waits indefinitely for the driver's event
// queue at priority 6 while TX waits independently for framed egress at
// priority 5.  That avoids polling the console event queue while a large PPP
// write is pending. S3 must use the same blocking path: polling every tick
// prevents the minimum three-tick idle opportunity needed for light sleep.
#[cfg(not(target_arch = "riscv32"))]
const UART_CLASSIC_TASK_STACK_WORDS: usize = (UART_L2_STACK_BYTES as usize) / 2;
#[cfg(not(target_arch = "riscv32"))]
static mut UART_RX_TASK_CONTROL: core::mem::MaybeUninit<esp_idf_sys::StaticTask_t> =
    core::mem::MaybeUninit::uninit();
#[cfg(not(target_arch = "riscv32"))]
static mut UART_RX_TASK_STACK: [esp_idf_sys::StackType_t; UART_CLASSIC_TASK_STACK_WORDS] =
    [0; UART_CLASSIC_TASK_STACK_WORDS];
#[cfg(not(target_arch = "riscv32"))]
static UART_RX_TASK_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
#[cfg(not(target_arch = "riscv32"))]
static mut UART_TX_TASK_CONTROL: core::mem::MaybeUninit<esp_idf_sys::StaticTask_t> =
    core::mem::MaybeUninit::uninit();
#[cfg(not(target_arch = "riscv32"))]
static mut UART_TX_TASK_STACK: [esp_idf_sys::StackType_t; UART_CLASSIC_TASK_STACK_WORDS] =
    [0; UART_CLASSIC_TASK_STACK_WORDS];
static UART_TX_TASK_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static UART_PENDING_BAUD: AtomicU32 = AtomicU32::new(0);

/// Serialize a volatile physical-rate change through the sole writer.
/// Native USB-JTAG is unaffected. The transport response finishes first.
pub(crate) fn request_baud_change(baud: u32) {
    if physical_uart_selected() {
        UART_PENDING_BAUD.store(baud, Ordering::Release);
        notify_classic_tx_task();
    }
}

const UART_EGRESS_LOG: u8 = 3;
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
        if !physical_bearer_active() {
            return Err(PacketSubmitError::WouldBlock(submission));
        }
        if UART_POOL_SUBMISSION_STATE
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            UART_SEND_BLOCKED.store(true, Ordering::Release);
            // Close the race where the writer completed after the failed CAS
            // but before the blocked flag was published. If completion runs
            // later, its normal readiness callback consumes the same latch.
            if UART_POOL_SUBMISSION_STATE.load(Ordering::Acquire) == 0 {
                notify_egress_ready();
            }
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
        notify_classic_tx_task();
        Ok(())
    }
}

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
    // Queue metadata is static; packet storage is leased from the one dynamic
    // QUIC pool only when a rare sideband control record is actually queued.
    true
}

fn enqueue_uart_control(payload: &[u8]) -> bool {
    if payload.is_empty() || payload.len() > UART_MAX_PACKET {
        return false;
    }
    let Some(mut writer) = crate::quic_node_esp::acquire_log_writer() else {
        return false;
    };
    if payload.len() > writer.payload_mut().len() {
        return false;
    }
    writer.payload_mut()[..payload.len()].copy_from_slice(payload);
    let Some(packet) = writer.commit(payload.len()) else {
        return false;
    };
    UART_EGRESS_QUEUED.fetch_add(1, Ordering::AcqRel);
    match UART_CONTROL_TX.try_push(UART_EGRESS_LOG, packet) {
        Ok(()) => {
            notify_classic_tx_task();
            true
        }
        Err((_kind, _packet)) => {
            UART_EGRESS_QUEUED.fetch_sub(1, Ordering::AcqRel);
            false
        }
    }
}

/// Install or clear a task-context notification callback for newly accepted
/// UART ingress. The callback must be nonblocking and safe from the dedicated
/// FreeRTOS UART task; it is not an interrupt callback.
pub fn set_ingress_notify(callback: Option<fn()>) {
    let callback = callback.map_or(0, |callback| callback as usize);
    INGRESS_NOTIFY.store(callback, Ordering::Release);
}

/// Install or clear the task-context notification for a QUIC bearer slot
/// released after physical transmission. The callback never runs in an ISR.
pub fn set_egress_notify(callback: Option<fn()>) {
    let callback = callback.map_or(0, |callback| callback as usize);
    EGRESS_NOTIFY.store(callback, Ordering::Release);
}

/// Consume the one-shot QUIC readiness edge recorded after an egress submit
/// returned `WouldBlock`. Successful packet completion alone is not a new
/// readiness event; its independent completion notification still wakes the
/// QUIC owner to release the packet lease.
pub(crate) fn take_send_blocked() -> bool {
    UART_SEND_BLOCKED.swap(false, Ordering::AcqRel)
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
        // The matching QUIC submission has completed and its physical bearer
        // slot is free. Packet production remains serialized on shared_ingress_esp.
        let callback: fn() = unsafe { core::mem::transmute(callback) };
        callback();
    }
}

/// Record one diagnostic in the QUIC log history. Hardware ROM and panic output
/// bypass this function and remain visible after a crash.
pub fn send_debug_text(text: &[u8]) -> bool {
    if text.is_empty() || text.len().saturating_add(2) > UART_MAX_PACKET || !text.is_ascii() {
        return false;
    }
    crate::log_history::push(text)
}

/// C/ESP-IDF log bridge. Normal records go to retained `log.watch` history;
/// the physical UART remains available for boot and crash diagnostics only.
#[no_mangle]
pub unsafe extern "C" fn dmesh_uart_log_line(bytes: *const u8, len: usize) -> i32 {
    if bytes.is_null() || len == 0 || len > 255 {
        return -1;
    }
    let line = core::slice::from_raw_parts(bytes, len);
    crate::log_history::push(line);
    len as i32
}

#[cfg(target_arch = "riscv32")]
fn write_usb(bytes: &[u8]) -> i32 {
    unsafe {
        if C6_USB_JTAG_SELECTED.load(Ordering::Acquire) {
            // Only the dedicated TX task waits for driver space. RX and the
            // QUIC owner remain independent; no tick-based retry polling.
            esp_idf_sys::usb_serial_jtag_write_bytes(
                bytes.as_ptr().cast(),
                bytes.len(),
                esp_idf_sys::TickType_t::MAX,
            )
        } else {
            esp_idf_sys::uart_write_bytes(
                esp_idf_sys::uart_port_t_UART_NUM_0,
                bytes.as_ptr().cast(),
                bytes.len(),
            ) as i32
        }
    }
}

/// Emit one rare sideband baud ACK from a dynamic QUIC pool lease. The lease
/// remains alive until the codec and physical driver have consumed it.
fn write_control_packet(packet: &UartControlPacket) {
    let bytes = packet.bytes();
    let Ok(mut encoder) = uart_codec::codec::Encoder::new(bytes, UART_MAX_PACKET) else {
        return;
    };
    if !write_encoded_chunks(&mut encoder) {
        return;
    }
    // The ACK must leave at the old rate; this sole writer switches only
    // after the last encoded byte has drained.
    if let Some(handshake) = uart_codec::BaudHandshake::decode(bytes) {
        if handshake.acknowledged && physical_uart_selected() {
            unsafe {
                if esp_idf_sys::uart_wait_tx_done(esp_idf_sys::uart_port_t_UART_NUM_0, 100) == 0 {
                    let _ = esp_idf_sys::uart_set_baudrate(
                        esp_idf_sys::uart_port_t_UART_NUM_0,
                        handshake.baud,
                    );
                }
            }
        }
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
    if !result {
        let _ = send_debug_text(b"DMESH UART packet transmit failed");
    }
    notify_egress_ready();
    true
}

fn write_transport_bytes(packet: &[u8]) -> bool {
    let Ok(mut encoder) = encode_packet(packet) else {
        return false;
    };
    write_encoded_chunks(&mut encoder)
}

/// Encode PPP framing in transient chunks borrowed from the QUIC packet pool.
/// The returned chunk lease is held only while the UART driver consumes it.
fn write_encoded_chunks(encoder: &mut uart_codec::codec::Encoder<'_>) -> bool {
    while !encoder.is_finished() {
        let Some(mut chunk) = crate::quic_node_esp::acquire_uart_tx_writer() else {
            return false;
        };
        let output = chunk.payload_mut();
        let produced = encoder.write(output);
        if produced == 0 {
            return false;
        }
        write_all(&output[..produced]);
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

#[cfg(not(target_arch = "riscv32"))]
unsafe extern "C" fn classic_rx_task_entry(argument: *mut c_void) {
    classic_rx_task(argument.cast());
}

unsafe extern "C" fn classic_tx_task_entry(_argument: *mut c_void) {
    classic_tx_task();
}

/// Start the dedicated physical UART L2 task after the platform has installed
/// its UART or USB-JTAG driver. The task is the only reader and writer of the
/// driver; packet bytes stay in the common pool until physical transmission.
pub unsafe fn start_task(stack_bytes: u32, priority: u32, core: i32) -> bool {
    #[cfg(not(target_arch = "riscv32"))]
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
        if event_queue.is_null() {
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
            core::ptr::null_mut(),
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

    #[cfg(target_arch = "riscv32")]
    {
        if !UART_TX_TASK_HANDLE.load(Ordering::Acquire).is_null() {
            return true;
        }
        let mut tx_task = core::ptr::null_mut();
        if esp_idf_sys::xTaskCreatePinnedToCore(
            Some(classic_tx_task_entry),
            b"dmesh_usb_tx\0".as_ptr().cast(),
            stack_bytes,
            core::ptr::null_mut(),
            priority,
            &mut tx_task,
            core,
        ) != 1
            || tx_task.is_null()
        {
            return false;
        }
        UART_TX_TASK_HANDLE.store(tx_task.cast(), Ordering::Release);
        let mut task = core::ptr::null_mut();
        let started = esp_idf_sys::xTaskCreatePinnedToCore(
            Some(task_entry),
            b"dmesh_uart_l2\0".as_ptr().cast(),
            stack_bytes,
            core::ptr::null_mut(),
            priority,
            &mut task,
            core,
        ) == 1
            && !task.is_null();
        if !started {
            UART_TX_TASK_HANDLE.store(core::ptr::null_mut(), Ordering::Release);
            esp_idf_sys::vTaskDelete(tx_task);
        }
        started
    }
}

/// Physical Xtensa UART event-driven receive ownership. The
/// UART driver is the source of truth for RX readiness: this task does not
/// poll its ring after an empty event or share the queue with transmit.
#[cfg(not(target_arch = "riscv32"))]
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
                UART_RX_OVERRUN_COUNT.fetch_add(1, Ordering::Relaxed);
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

/// The matching physical UART writer. Pool-backed QUIC submissions wake it
/// directly; rare sideband control records use dynamic pool leases.
fn classic_tx_task() {
    loop {
        let _ = write_pool_submission_if_ready();
        while let Some((kind, packet)) = UART_CONTROL_TX.try_pop() {
            UART_EGRESS_QUEUED.fetch_sub(1, Ordering::AcqRel);
            if kind == UART_EGRESS_LOG {
                write_control_packet(&packet);
            }
        }
        let baud = UART_PENDING_BAUD.swap(0, Ordering::AcqRel);
        if baud != 0 && physical_uart_selected() {
            unsafe {
                if esp_idf_sys::uart_wait_tx_done(esp_idf_sys::uart_port_t_UART_NUM_0, 100) == 0 {
                    let _ =
                        esp_idf_sys::uart_set_baudrate(esp_idf_sys::uart_port_t_UART_NUM_0, baud);
                }
            }
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
    // no-std QUIC runtime, registered bearer, shared packet pool, and sole UART task
    // are all live. A reset-time host watch can therefore distinguish a
    // functioning UART transport from earlier ROM/ESP-IDF console text.
    let _ = send_debug_text(b"DMESH uart: writer ready");
    crate::commands::send_response(b"DMESH uart: quic ready");
    loop {
        // TX has its own notification-driven task. Block RX on the USB
        // driver's arrival event instead of sampling once per 10 ms tick.
        #[cfg(target_arch = "riscv32")]
        {
            if C6_USB_JTAG_SELECTED.load(Ordering::Acquire) {
                // USB-JTAG has no UART event queue; the driver blocks until
                // bytes arrive. Each decoded batch wakes the QUIC owner.
                let count = read_usb(&mut bytes, esp_idf_sys::TickType_t::MAX);
                if count > 0 {
                    UART_RX_BYTE_COUNT.fetch_add(count as u32, Ordering::Relaxed);
                    consume_uart_bytes(&mut decoder, &bytes[..count as usize]);
                    // Let the owner return/admit leases between driver batches
                    // without waiting for the scheduler's time-slice tick.
                    unsafe { esp_idf_sys::vTaskDelay(0) };
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
                            UART_RX_OVERRUN_COUNT.fetch_add(1, Ordering::Relaxed);
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

        // Physical UART fallback (or disconnected USB) has no blocking read
        // above. Avoid spinning when it has no event; TX remains independent.
        unsafe {
            esp_idf_sys::vTaskDelay(1);
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
                UART_RX_PACKET_COUNT.fetch_add(1, Ordering::Relaxed);
                activate_window();
                crate::quic_node_esp::receive_uart(packet);
                notify_ingress();
            }
            PooledFrame::Wake => {
                UART_RX_WAKE_COUNT.fetch_add(1, Ordering::Relaxed);
                activate_window_for(60_000);
                let _ = send_debug_text(b"DMESH uart: wake request");
                crate::main_runtime::request_uart_wake();
            }
            PooledFrame::PoolUnavailable => {
                // A log for every discarded frame competes with QUIC on USB.
                // Keep the first diagnostic; telemetry.memory counts all drops.
                if crate::shared_ingress_esp::record_pool_drop() {
                    let _ = send_debug_text(b"DMESH uart: packet pool unavailable");
                }
                crate::quic_node_esp::note_packet_pool_pressure();
            }
            PooledFrame::Log(record) => {
                if physical_uart_selected() {
                    if let Some(mut handshake) = uart_codec::BaudHandshake::decode(&record) {
                        if !handshake.acknowledged {
                            handshake.acknowledged = true;
                            if let Some(ack) = handshake.record() {
                                let _ = enqueue_uart_control(&ack);
                            }
                        }
                    }
                }
            }
        },
    );
}

fn physical_uart_selected() -> bool {
    #[cfg(target_arch = "riscv32")]
    {
        !C6_USB_JTAG_SELECTED.load(Ordering::Acquire)
    }
    #[cfg(not(target_arch = "riscv32"))]
    {
        true
    }
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
