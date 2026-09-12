//! Main policy and state ownership.
//!
//! This module owns Main's identity and boot policy. Shared connection and
//! bearer adapters remain below it; Recovery never constructs this type.

extern "C" {
    fn nvs_flash_init() -> i32;
    fn nvs_open(namespace: *const i8, mode: i32, handle: *mut u32) -> i32;
    fn nvs_get_str(handle: u32, key: *const i8, value: *mut u8, length: *mut usize) -> i32;
    fn nvs_set_str(handle: u32, key: *const i8, value: *const i8) -> i32;
    fn nvs_get_blob(
        handle: u32,
        key: *const i8,
        value: *mut core::ffi::c_void,
        length: *mut usize,
    ) -> i32;
    fn nvs_set_blob(
        handle: u32,
        key: *const i8,
        value: *const core::ffi::c_void,
        length: usize,
    ) -> i32;
    fn nvs_commit(handle: u32) -> i32;
    fn nvs_close(handle: u32);
}

const NVS_READONLY: i32 = 0;
const NVS_READWRITE: i32 = 1;
const SETTINGS_KEYS: [&[u8]; 6] = [
    b"mode",
    b"name",
    b"domain",
    b"sta_ssid",
    b"sta_server_ll",
    b"sta_server_port",
];
// Private settings are write-only. `id_p256` is created internally and stored
// as a binary NVS blob; it is never a settings transport value.
const SECRET_SETTING_KEYS: [&[u8]; 1] = [b"sta"];
const IDENTITY_NVS_KEY: &[u8] = b"id_p256\0";
const CONTROL_PLANE_NVS_KEY: &[u8] = b"cp\0";
const SHARED_SECRET_NVS_KEY: &[u8] = b"key\0";

fn settings_key(key: &[u8]) -> Option<&'static [u8]> {
    SETTINGS_KEYS.iter().copied().find(|known| *known == key)
}

pub(crate) fn secret_setting_keys() -> &'static [&'static [u8]] {
    &SECRET_SETTING_KEYS
}

/// Report whether a reviewed `sec` key exists without reading its value.
/// Secret contents must never cross the live control response path.
pub(crate) fn secret_setting_exists(key: &[u8]) -> bool {
    if !SECRET_SETTING_KEYS.contains(&key) {
        return false;
    }
    let _ = unsafe { nvs_flash_init() };
    let mut handle = 0_u32;
    if unsafe { nvs_open(b"sec\0".as_ptr().cast(), NVS_READONLY, &mut handle) } != 0 {
        return false;
    }
    let mut length = 0usize;
    let mut nul_key = [0u8; 20];
    nul_key[..key.len()].copy_from_slice(key);
    let result = unsafe {
        nvs_get_str(
            handle,
            nul_key.as_ptr().cast(),
            core::ptr::null_mut(),
            &mut length,
        ) == 0
    };
    unsafe { nvs_close(handle) };
    result && length > 1
}

/// Persist a reviewed `sec` value without exposing it through a response.
/// This is first-use provisioning only; callers must never log the supplied
/// bytes or return them through `settings.get`/`settings.list`.
pub(crate) fn write_secret_setting(key: &[u8], value: &[u8]) -> bool {
    if !SECRET_SETTING_KEYS.contains(&key) || !(8..=63).contains(&value.len()) || value.contains(&0)
    {
        return false;
    }
    let _ = unsafe { nvs_flash_init() };
    let mut handle = 0_u32;
    if unsafe { nvs_open(b"sec\0".as_ptr().cast(), NVS_READWRITE, &mut handle) } != 0 {
        return false;
    }
    let mut nul_key = [0u8; 20];
    nul_key[..key.len()].copy_from_slice(key);
    let mut nul_value = [0u8; 64];
    nul_value[..value.len()].copy_from_slice(value);
    let result = unsafe {
        nvs_set_str(handle, nul_key.as_ptr().cast(), nul_value.as_ptr().cast()) == 0
            && nvs_commit(handle) == 0
    };
    unsafe { nvs_close(handle) };
    result
}

/// Load the firmware's persistent P-256 identity, or generate it on first
/// Main startup. The scalar is an exact 32-byte binary NVS blob: it must never
/// pass through a text/base64 settings API or an announce response. A failed
/// commit returns no identity rather than creating a misleading volatile one.
fn load_or_create_identity_private_key() -> Option<[u8; crate::crypto_esp::P256_PRIVATE_KEY_LEN]> {
    let _ = unsafe { nvs_flash_init() };
    let mut handle = 0_u32;
    if unsafe { nvs_open(b"sec\0".as_ptr().cast(), NVS_READWRITE, &mut handle) } != 0 {
        return None;
    }
    let mut private = [0u8; crate::crypto_esp::P256_PRIVATE_KEY_LEN];
    let mut length = private.len();
    let existing = unsafe {
        nvs_get_blob(
            handle,
            IDENTITY_NVS_KEY.as_ptr().cast(),
            private.as_mut_ptr().cast(),
            &mut length,
        ) == 0
    };
    if existing && length == private.len() && crate::crypto_esp::p256_public_key(&private).is_some()
    {
        unsafe { nvs_close(handle) };
        return Some(private);
    }
    private = crate::crypto_esp::generate_p256_private()?;
    let stored = unsafe {
        nvs_set_blob(
            handle,
            IDENTITY_NVS_KEY.as_ptr().cast(),
            private.as_ptr().cast(),
            private.len(),
        ) == 0
            && nvs_commit(handle) == 0
    };
    unsafe { nvs_close(handle) };
    stored.then_some(private)
}

/// Read one reviewed, non-secret `dmesh` NVS string into caller-owned storage.
pub(crate) fn read_setting(key: &[u8], output: &mut [u8]) -> Option<usize> {
    let key = settings_key(key)?;
    let _ = unsafe { nvs_flash_init() };
    let mut handle = 0_u32;
    if unsafe { nvs_open(b"dmesh\0".as_ptr().cast(), NVS_READONLY, &mut handle) } != 0 {
        return None;
    }
    let mut nul_key = [0u8; 20];
    nul_key[..key.len()].copy_from_slice(key);
    let length = nvs_string(handle, &nul_key[..key.len() + 1], output);
    unsafe { nvs_close(handle) };
    length
}

/// Persist one reviewed, non-secret NVS setting.
pub(crate) fn write_setting(key: &[u8], value: &[u8]) -> bool {
    let Some(key) = settings_key(key) else {
        return false;
    };
    if value.is_empty() || value.len() > 63 {
        return false;
    }
    let valid = match key {
        b"mode" => matches!(value, b"active" | b"sleepy" | b"sleepy-soft"),
        b"name" => {
            value.len() <= dmesh_server::announce::MAX_DEVICE_NAME
                && core::str::from_utf8(value).is_ok()
        }
        b"domain" => {
            value.len() <= dmesh_server::announce::MAX_DEVICE_DOMAIN
                && core::str::from_utf8(value).is_ok()
        }
        b"sta_ssid" => dmesh_server::firmware_profile::valid_ssid(value),
        b"sta_server_ll" => value.starts_with(b"fe80:") && !value.contains(&b'%'),
        b"sta_server_port" => parse_port(value).is_some(),
        _ => false,
    };
    if !valid {
        return false;
    }
    let _ = unsafe { nvs_flash_init() };
    let mut handle = 0_u32;
    if unsafe { nvs_open(b"dmesh\0".as_ptr().cast(), NVS_READWRITE, &mut handle) } != 0 {
        return false;
    }
    let mut nul_key = [0u8; 20];
    nul_key[..key.len()].copy_from_slice(key);
    let mut nul_value = [0u8; 64];
    nul_value[..value.len()].copy_from_slice(value);
    let result = unsafe {
        nvs_set_str(handle, nul_key.as_ptr().cast(), nul_value.as_ptr().cast()) == 0
            && nvs_commit(handle) == 0
    };
    unsafe { nvs_close(handle) };
    if result {
        // The signed discovery record embeds name, domain, and STA facts.
        // A successful stream `settings.set` must be visible to the next
        // directed or unsolicited announce, not only after a radio change.
        invalidate_discovery_cache();
    }
    result
}

/// Store reviewed binary security material without sending it through a text
/// or base64 settings path. `cp` is public control-plane material; `sec:key`
/// is the catalog shared secret and is never readable over control.
pub(crate) fn write_binary_setting(key: &[u8], value: &[u8]) -> bool {
    let (namespace, nvs_key, secret) = match key {
        b"cp" => (b"dmesh\0".as_slice(), CONTROL_PLANE_NVS_KEY, false),
        b"sec:key" => (b"sec\0".as_slice(), SHARED_SECRET_NVS_KEY, true),
        _ => return false,
    };
    if value.is_empty() || value.len() > dmesh_server::announce::MAX_PUBLIC_KEY {
        return false;
    }
    let _ = secret; // Documents the read/redaction boundary above.
    let _ = unsafe { nvs_flash_init() };
    let mut handle = 0_u32;
    if unsafe { nvs_open(namespace.as_ptr().cast(), NVS_READWRITE, &mut handle) } != 0 {
        return false;
    }
    let result = unsafe {
        nvs_set_blob(
            handle,
            nvs_key.as_ptr().cast(),
            value.as_ptr().cast(),
            value.len(),
        ) == 0
            && nvs_commit(handle) == 0
    };
    unsafe { nvs_close(handle) };
    result
}

/// Derive the quic-lite stateless-reset branch from Main's provisioned device
/// secret. The raw `sec:key` material remains in NVS: callers receive only a
/// derived, bearer-neutral key and must never log or serialize it. This is the
/// DMesh PSP-style key-schedule boundary; future packet-protection branches
/// use different labels in quic-lite.
pub(crate) fn stateless_reset_key() -> Option<quic_lite::StatelessResetKey> {
    let _ = unsafe { nvs_flash_init() };
    let mut handle = 0_u32;
    if unsafe { nvs_open(b"sec\0".as_ptr().cast(), NVS_READONLY, &mut handle) } != 0 {
        return None;
    }
    // `sec:key` is provisioned as bounded binary material. Keep the raw value
    // on this stack only long enough to derive the reset branch.
    let mut secret = [0u8; dmesh_server::announce::MAX_PUBLIC_KEY];
    let mut length = secret.len();
    let loaded = unsafe {
        nvs_get_blob(
            handle,
            SHARED_SECRET_NVS_KEY.as_ptr().cast(),
            secret.as_mut_ptr().cast(),
            &mut length,
        ) == 0
    };
    unsafe { nvs_close(handle) };
    if !loaded || length > secret.len() {
        return None;
    }
    let key = quic_lite::StatelessResetKey::from_device_secret(&secret[..length]).ok();
    secret.fill(0);
    key
}

pub(crate) fn setting_keys() -> &'static [&'static [u8]] {
    &SETTINGS_KEYS
}

/// Read one NUL-terminated NVS string into a fixed buffer.  NVS does not
/// promise whether the reported length includes the terminator, so normalize
/// on the first NUL rather than relying on a version-specific ABI detail.
fn nvs_string(handle: u32, key: &[u8], output: &mut [u8]) -> Option<usize> {
    let mut length = output.len();
    let result = unsafe {
        nvs_get_str(
            handle,
            key.as_ptr().cast(),
            output.as_mut_ptr(),
            &mut length,
        )
    };
    if result != 0 {
        return None;
    }
    Some(
        output
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(length.min(output.len())),
    )
}

fn parse_port(value: &[u8]) -> Option<u16> {
    let mut port = 0u16;
    for byte in value {
        if !byte.is_ascii_digit() {
            return None;
        }
        port = port.checked_mul(10)?.checked_add(u16::from(*byte - b'0'))?;
    }
    (port != 0).then_some(port)
}

/// Load the persisted, private STA profile into Main's desired profile.  The
/// reader is deliberately all-or-nothing: a partially written credential or
/// endpoint must leave Main in its ordinary NAN/NOW boot personality instead
/// of associating to a guessed network.  Link-local text has no host scope in
/// firmware, so it is retained only as a validated future UDP endpoint input;
/// the Wi-Fi adapter never derives an address from a BSSID.
pub(crate) fn apply_sta_profile_from_nvs(profile: &mut crate::TransportProfile) -> bool {
    let _ = unsafe { nvs_flash_init() };
    let mut handle = 0_u32;
    if unsafe { nvs_open(b"dmesh\0".as_ptr().cast(), NVS_READONLY, &mut handle) } != 0 {
        return false;
    }
    let mut ssid = [0u8; 33];
    let mut server_ll = [0u8; 40];
    let mut server_port = [0u8; 6];
    let result = (|| {
        let ssid_len = nvs_string(handle, b"sta_ssid\0", &mut ssid)?;
        let server_len = nvs_string(handle, b"sta_server_ll\0", &mut server_ll);
        let port_len = nvs_string(handle, b"sta_server_port\0", &mut server_port);
        if !dmesh_server::firmware_profile::valid_ssid(&ssid[..ssid_len]) {
            return None;
        }
        // Main discovers its UDP6 peer through multicast/NAN when no server
        // endpoint is provisioned. If one is present, retain the former
        // all-or-nothing endpoint validation for Recovery compatibility.
        match (server_len, port_len) {
            (None, None) => {}
            (Some(server_len), Some(port_len))
                if server_ll[..server_len].starts_with(b"fe80:")
                    && !server_ll[..server_len].contains(&b'%')
                    && parse_port(&server_port[..port_len]).is_some() => {}
            _ => return None,
        }
        let mut psk = [0u8; 64];
        let mut secret_handle = 0_u32;
        if unsafe { nvs_open(b"sec\0".as_ptr().cast(), NVS_READONLY, &mut secret_handle) } != 0 {
            return None;
        }
        let psk_len = nvs_string(secret_handle, b"sta\0", &mut psk);
        unsafe { nvs_close(secret_handle) };
        let Some(psk_len) = psk_len else {
            return None;
        };
        if !(8..=63).contains(&psk_len) {
            return None;
        }
        profile.ssid[..ssid_len].copy_from_slice(&ssid[..ssid_len]);
        profile.ssid_len = ssid_len;
        profile.sta_passphrase[..psk_len].copy_from_slice(&psk[..psk_len]);
        profile.sta_passphrase_len = psk_len;
        profile.requested_transport = Some(dmesh_server::control::TransportKind::Sta);
        // A provisioned STA remains a NAN participant on its associated
        // channel. `now=2` keeps the pre-existing STA NOW power policy while
        // DW1 supplies discovery receive/respond windows.
        profile.now = 2;
        profile.nan_dw_interval = 1;
        profile.ap = 0;
        profile.run_requested = true;
        Some(())
    })()
    .is_some();
    unsafe { nvs_close(handle) };
    result
}

/// Complete Main-only boot power policy read from the product NVS namespace.
/// It is read exactly once before the radio owner starts: `sleepy-soft` is a
/// sleepy radio policy with physical light sleep suppressed for diagnostics.
/// Recovery never constructs this value, so its image does not need this NVS
/// schema or the mode strings.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct BootPowerPolicy {
    pub(crate) sleepy: bool,
    pub(crate) soft_sleep: bool,
}

/// Read the complete product boot policy once. The later PHY startup may
/// initialize NVS again, so this bounded read does not couple policy to Wi-Fi
/// setup or introduce a background NVS task.
pub(crate) fn boot_power_policy_from_nvs() -> BootPowerPolicy {
    let _ = unsafe { nvs_flash_init() };
    let mut handle = 0_u32;
    if unsafe { nvs_open(b"dmesh\0".as_ptr().cast(), 0, &mut handle) } != 0 {
        return BootPowerPolicy::default();
    }
    let mut value = [0u8; 16];
    let mut length = value.len();
    let result = unsafe {
        nvs_get_str(
            handle,
            b"mode\0".as_ptr().cast(),
            value.as_mut_ptr(),
            &mut length,
        )
    };
    unsafe { nvs_close(handle) };
    if result != 0 {
        return BootPowerPolicy::default();
    }
    // ESP-IDF versions differ on whether this length includes the NUL.  Use
    // the first NUL when present so the policy does not depend on that ABI.
    let end = value
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(length.min(value.len()));
    // Soft mode is still a sleepy radio profile; it only suppresses physical
    // light sleep later so the canary can retain USB diagnostics.
    match value.get(..end) {
        Some(b"sleepy") => BootPowerPolicy {
            sleepy: true,
            soft_sleep: false,
        },
        Some(b"sleepy-soft") => BootPowerPolicy {
            sleepy: true,
            soft_sleep: true,
        },
        _ => BootPowerPolicy::default(),
    }
}

/// Publish boot diagnostics over NOW after Main's unassociated radio is live.
/// Called once during Main boot; it deliberately uses the same wire records
/// as UART and UDP6, rather than creating a NOW-only discovery schema.
/// Emit one received LoRa/FSK packet through every currently-live public
/// bearer.  The record is deliberately connectionless: it contains the RF
/// measurements and opaque packet but does not feed back into the local
/// tagged dispatcher or create a new radio task.
pub fn forward_lora_packet(payload: &[u8], rssi: i16, snr: i8) -> bool {
    // LoRa payload fan-out used a connectionless application side channel on
    // UART, NOW, and UDP6. Do not bypass a QUIC stream: a future stream event
    // subscriber owns delivery and backpressure. Keep this ABI hook inert
    // while module callers migrate to that stream service.
    let _ = (payload, rssi, snr);
    false
}

pub(crate) fn send_startup_records_on_now(boot_message: &[u8], role: u8, partition: u8) {
    let _ = boot_message;
    send_announce_on_now(
        dmesh_server::announce::ANNOUNCE_DISCOVERY,
        0,
        role,
        partition,
    );
}

/// Emit Main's initial discovery record on UART and arm it for later NAN SD.
/// Called once after the common UART ingress task starts and before Main's
/// initial NAN+NOW epoch, so serial diagnostics establish boot identity even
/// if radio initialization later fails.
pub(crate) fn send_startup_discovery_uart(role: u8, partition: u8) {
    if let Some((record, used)) = announce_record(
        dmesh_server::announce::ANNOUNCE_DISCOVERY,
        0,
        role,
        partition,
    ) {
        let _ = crate::commands::send_record(&record[..used]);
        // Boot runs before the initial NAN epoch selects channel 6, so retain
        // the record for that later start. STA transitions gate publication
        // below once their actual channel is known.
        let _ = crate::wifi_nan_dw_capture_esp::configure_active_publish(true, &record[..used]);
    }
}

/// Active Main devices refresh their passive presence every five minutes.
///
/// The same five-minute cadence is used by Android and host adapters. The
/// actual work runs on the existing DW one-shot deadline, never in a polling
/// loop.
const ACTIVE_DISCOVERY_INTERVAL_MS: u64 = 5 * 60 * 1_000;

/// Check the active passive-discovery cadence after a queued owner event.
/// Called by the Main coordinator after every profile/callback/one-shot
/// deadline wake. In the normal NAN+NOW epoch the NAN DW deadline reaches
/// this method about once per DW; it returns without sending until the
/// five-minute policy deadline is due. The resulting record refreshes NAN
/// Publish Service Info and broadcasts the same record on NOW (and UDP6 when
/// associated), so all currently available passive bearers agree on identity.
pub(crate) fn send_discovery_announce(uptime_secs: u64, now_active: bool, sta_active: bool) {
    send_transition_announce(
        dmesh_server::announce::ANNOUNCE_DISCOVERY,
        uptime_secs,
        now_active,
        sta_active,
    );
}

/// Send one Main transition marker over every currently live bearer. Called
/// only at explicit transition boundaries or the bounded discovery cadence;
/// it does not run from a Wi-Fi callback or every NAN discovery window.
pub(crate) fn send_transition_announce(
    kind: u64,
    uptime_secs: u64,
    now_active: bool,
    sta_active: bool,
) {
    if let Some((record, used)) = announce_record(kind, uptime_secs, 0, 0) {
        let _ = crate::commands::send_record(&record[..used]);
        let _ = crate::wifi_nan_dw_capture_esp::configure_active_publish(
            crate::wifi_nan_dw_capture_esp::active_on_nan_channel(),
            &record[..used],
        );
        if now_active {
            let _ = crate::wifi_espnow_esp::broadcast_record(&record[..used]);
        }
        if sta_active {
            let _ = crate::wifi_raw_udp6_esp::broadcast_announce(&record[..used]);
        }
    }
}

/// Announce a completed STA startup on multicast UDP6. Called after the raw
/// UDP6 bearer starts, once per STA epoch; unassociated Main never calls it.
pub(crate) fn send_sta_discovery_announce() {
    if let Some((record, used)) =
        announce_record(dmesh_server::announce::ANNOUNCE_DISCOVERY, 0, 0, 0)
    {
        let _ = crate::wifi_raw_udp6_esp::broadcast_announce(&record[..used]);
    }
}

/// Whether a requested profile is the narrow DW8 sleepy personality. This is
/// evaluated only by Main after a queued profile or radio deadline event; it
/// is never inferred by a Wi-Fi callback or from an association side effect.
pub(crate) fn is_sleepy_profile(profile: &crate::TransportProfile) -> bool {
    profile.requested_transport == Some(dmesh_server::control::TransportKind::Nan)
        && profile.nan_dw_interval == 8
        && profile.now == 2
        && profile.ap == 0
}

/// Apply a single explicit sleep boundary after Main has completed the radio
/// effects of an event. It runs at most once per eligible deadline: on return,
/// the grace window prevents an immediate repeat and leaves NAN reachable for
/// the next accepted transport request.
pub(crate) fn maybe_enter_sleep(
    role: u8,
    profile: &crate::TransportProfile,
    nan_now_started: &mut bool,
    wifi_started: bool,
    soft_sleep: bool,
    now_ms: u64,
    sleepy_awake_until_ms: &mut u64,
) -> bool {
    if role != 1
        || !is_sleepy_profile(profile)
        || !*nan_now_started
        || wifi_started
        || now_ms < *sleepy_awake_until_ms
    {
        return false;
    }

    send_transition_announce(
        dmesh_server::announce::ANNOUNCE_SLEEP_PENDING,
        now_ms / 1_000,
        profile.now != 2,
        false,
    );
    if soft_sleep {
        // Soft mode proves the same state boundary while retaining the radio
        // and USB-JTAG for diagnostic wake/control injection.
        send_transition_announce(
            dmesh_server::announce::ANNOUNCE_WAKE,
            now_ms / 1_000,
            true,
            false,
        );
        *sleepy_awake_until_ms = now_ms.saturating_add(5_000);
        return true;
    }

    // Keep the control UART alive through the DW8 command window.  Turning it
    // off during the profile transition races the command response and leaves
    // no way to inspect the armed boundary.  The physical sleep entry below
    // owns the final shutdown instead.
    crate::commands::send_response(b"sleep DW8: entering explicit light sleep");
    // UART is not a light-sleep precondition. Retain it across DW8 so the
    // device remains observable and we do not churn the physical serial
    // driver on every wake cycle.
    crate::wifi_esp::stop_sta();
    // Classic ESP32 retains a Wi-Fi PM lock after `esp_wifi_stop()`. Release
    // the initialized driver before the explicit timer sleep; `init_nan_now`
    // recreates it after wake. Without this, `esp_light_sleep_start()` returns
    // immediately and the device remains at its active current.
    crate::wifi_esp::deinit_for_light_sleep();
    crate::wifi_nan_dw_capture_esp::prepare_light_sleep_resume();
    let (bssid, anchor_us, _) = crate::wifi_nan_dw_capture_esp::sync_diagnostics();
    // Without a NAN timing anchor, use the prescribed 30-second acquisition
    // backoff instead of repeatedly missing a discovery window; synchronized
    // Main sleeps exactly one DW8 interval.
    let duration_us = if bssid != [0; 6] && anchor_us != 0 {
        4_194_304
    } else {
        30_000_000
    };
    let _entered_sleep = crate::power_esp::enter_timer_light_sleep(duration_us);

    let after_wake = crate::profile_store::snapshot();
    if !is_sleepy_profile(&after_wake) {
        crate::core_runtime::apply_uart_profile(!crate::uart_esp::uart_is_off(after_wake.uart));
    }
    crate::core_runtime::prepare_espnow_association(&after_wake);
    *nan_now_started =
        crate::wifi_esp::init_nan_now(&after_wake, crate::core_runtime::receive_main_espnow);
    if *nan_now_started {
        crate::wifi_espnow_esp::set_poll_handler(Some(crate::core_runtime::poll_espnow));
    }
    // A completed explicit sleep is not a new control session.  Keeping the
    // former five-second command window here made every DW8 cycle spend more
    // time awake than asleep, even when no peer had requested a wake.  The
    // radio has already restored its saved NAN anchor, so its next owner
    // deadline is the selected discovery window.  A targeted active
    // Subscribe received in that window still replaces the profile; an idle
    // device immediately returns to low duty operation.
    *sleepy_awake_until_ms = 0;
    send_transition_announce(
        dmesh_server::announce::ANNOUNCE_WAKE,
        (unsafe { esp_idf_sys::esp_timer_get_time() }.max(0) as u64) / 1_000_000,
        *nan_now_started && after_wake.now != 2,
        false,
    );
    true
}

/// Service exactly the adapter deadlines named by a queued timer event.
/// Called only after Main's one-shot ESP timer fires; this is not a busy loop
/// or packet poll. Wi-Fi callbacks record bounded state and return, while this
/// owner task performs the selected follow-up driver operation that may block.
pub(crate) fn service_radio_deadline(services: u8) {
    if services & DEADLINE_NAN_CAPTURE != 0 {
        crate::wifi_nan_dw_capture_esp::service_deadline();
    }
    if services & DEADLINE_ROC != 0 {
        crate::wifi_nonpromisc_probe_esp::service_deadline();
    }
    if services & DEADLINE_CONNECTION != 0 {
        crate::core_runtime::schedule_connection_timer();
    }
}

/// Emit one active passive-discovery record when the five-minute cadence is
/// due. Called only from the single Main event owner after a queued wake; it
/// does not create a task, poll a driver, or make a separate periodic wake.
pub(crate) fn maybe_send_periodic_discovery(
    now_ms: u64,
    nan_active: bool,
    now_active: bool,
    sta_active: bool,
    last_discovery_announce_ms: &mut u64,
) -> bool {
    let due = (nan_active || sta_active)
        && now_ms.saturating_sub(*last_discovery_announce_ms) >= ACTIVE_DISCOVERY_INTERVAL_MS;
    if due {
        send_discovery_announce(now_ms / 1_000, now_active, sta_active);
        *last_discovery_announce_ms = now_ms;
    }
    due
}

/// True when the requested transport epoch is associated STA. Called by Main
/// while applying a queued profile; it is a pure profile classification and
/// never claims that ESP-IDF association has completed.
pub(crate) fn wants_sta(profile: &crate::TransportProfile) -> bool {
    matches!(
        profile.requested_transport,
        Some(dmesh_server::control::TransportKind::Sta)
    )
}

fn wants_nan(profile: &crate::TransportProfile) -> bool {
    matches!(
        profile.requested_transport,
        Some(dmesh_server::control::TransportKind::Nan)
    )
}

fn wants_sta_extensions(profile: &crate::TransportProfile) -> bool {
    // `now=2` is the only explicit NOW-off spelling.  The out-of-box active
    // Main profile uses `now=0`, which means the default private NOW action
    // path remains available even when a host has no NAN cluster.
    profile.now != 2 || profile.nan_dw_interval != 0
}

/// NAN is the fixed channel-6 discovery bearer. A STA on another channel may
/// still use its co-channel NOW action bearer and its ordinary UDP6 network,
/// but it must not open a NAN DW or advertise NAN service information there.
/// An SSID-only STA profile deliberately leaves `sta_channel` at zero so the
/// scan selects the AP. Once associated, the driver-reported channel is the
/// authority; using the profile field here silently disabled NAN even for a
/// channel-6 AP.
fn effective_sta_nan_dw_interval(profile: &crate::TransportProfile) -> u8 {
    let channel = crate::wifi_esp::current_channel()
        .map(|(primary, _)| primary)
        .unwrap_or(profile.sta_channel);
    (channel == 6)
        .then_some(profile.nan_dw_interval)
        .unwrap_or(0)
}

/// Project a committed request onto the bounded, credential-free state model.
/// Called when Main dequeues a profile generation, before adapter work starts.
pub(crate) fn requested_mode(
    profile: &crate::TransportProfile,
) -> dmesh_server::main_runtime_state::RequestedMode {
    use dmesh_server::main_runtime_state::RequestedMode;
    if wants_sta(profile) {
        return match (profile.ap != 0, wants_sta_extensions(profile)) {
            (false, false) => RequestedMode::Sta,
            (false, true) => RequestedMode::StaNanNow,
            (true, false) => RequestedMode::StaAp,
            (true, true) => RequestedMode::StaApNanNow,
        };
    }
    if wants_nan(profile) {
        RequestedMode::NanNow
    } else {
        RequestedMode::Stopped
    }
}

/// Project confirmed adapter state after a Main effect turn. Called only after
/// driver calls have completed; it cannot report a requested STA as live.
pub(crate) fn applied_lifecycle(
    profile: &crate::TransportProfile,
    wifi_started: bool,
    nan_now_started: bool,
    sta_associated: bool,
) -> dmesh_server::main_runtime_state::RadioLifecycle {
    use dmesh_server::main_runtime_state::RadioLifecycle;
    if wifi_started {
        if !sta_associated {
            return RadioLifecycle::Starting;
        }
        return match (profile.ap != 0, nan_now_started) {
            (false, false) => RadioLifecycle::Sta,
            (false, true) => RadioLifecycle::StaNanNow,
            (true, false) => RadioLifecycle::StaAp,
            (true, true) => RadioLifecycle::StaApNanNow,
        };
    }
    if nan_now_started {
        RadioLifecycle::NanNow
    } else {
        RadioLifecycle::Stopped
    }
}

/// Copy the last power-service completion into Main's bounded status model.
/// Called by the Main event owner immediately after it applies boot/profile
/// power policy or returns from explicit timer light sleep. ESP-IDF callbacks
/// only update the power-service atomics; they never mutate the runtime state
/// or publish a partly-updated snapshot.
pub(crate) fn record_power_completion(
    runtime_state: &mut dmesh_server::main_runtime_state::MainRuntimeState,
) {
    let power = crate::power_esp::status();
    let _ = runtime_state.reduce(dmesh_server::main_runtime_state::MainEvent::PowerApplied {
        cpu_mhz: power.cpu_mhz,
        min_mhz: power.min_mhz,
        max_mhz: power.max_mhz,
        automatic_light_sleep: power.automatic_light_sleep,
        configured: power.configured,
        light_sleep_attempts: power.light_sleep_attempts,
        light_sleep_entries: power.light_sleep_entries,
        light_sleep_skipped: power.light_sleep_skipped,
        last_sleep_requested_us: power.last_sleep_requested_us,
        last_sleep_duration_us: power.last_sleep_duration_us,
    });
}

/// Replace the unassociated NAN/NOW epoch for a newly committed generation.
/// Called by Main on a profile event or a retry deadline; it is a no-op for an
/// already-applied generation and never runs from a Wi-Fi callback.
pub(crate) fn apply_nan_epoch(
    profile: &crate::TransportProfile,
    generation: u32,
    wifi_started: bool,
    nan_now_started: &mut bool,
    applied_nan_start_generation: &mut u32,
) {
    if !wants_nan(profile) || wifi_started || *applied_nan_start_generation == generation {
        return;
    }
    if *nan_now_started {
        crate::wifi_esp::stop_sta_extensions();
        crate::wifi_esp::stop_sta();
        crate::wifi_esp::restart_sta_driver_runtime();
    }
    crate::core_runtime::prepare_espnow_association(profile);
    *nan_now_started =
        crate::wifi_esp::init_nan_now(profile, crate::core_runtime::receive_main_espnow);
    if *nan_now_started {
        crate::wifi_espnow_esp::set_poll_handler(Some(crate::core_runtime::poll_espnow));
    }
    *applied_nan_start_generation = generation;
}

/// Apply Main's real-UART selector after a profile change. Called by the Main
/// event owner; ESP32-C6 USB-JTAG stays available inside the shared adapter.
pub(crate) fn apply_uart_profile(
    role: u8,
    profile: &crate::TransportProfile,
    applied_uart: &mut Option<u8>,
) {
    if role != 1 || *applied_uart == Some(profile.uart) {
        return;
    }
    crate::core_runtime::apply_uart_profile(!crate::uart_esp::uart_is_off(profile.uart));
    *applied_uart = Some(profile.uart);
}

/// Reconcile the STA-held NAN/NOW extension after one Main effect turn. It is
/// called on event turns, but performs start/stop/interval work only when the
/// cached adapter state differs from the committed profile.
pub(crate) fn apply_sta_nan_extensions(
    profile: &crate::TransportProfile,
    wifi_started: bool,
    sta_extensions_enabled: &mut bool,
    applied_nan_dw_interval: &mut Option<u8>,
) {
    if !wifi_started {
        return;
    }
    if wants_sta_extensions(profile) != *sta_extensions_enabled {
        if wants_sta_extensions(profile) {
            let nan_dw_interval = effective_sta_nan_dw_interval(profile);
            let enabled = crate::wifi_esp::start_sta_extensions(
                crate::core_runtime::receive_main_espnow,
                nan_dw_interval,
                profile.now,
            );
            if enabled {
                crate::wifi_espnow_esp::set_poll_handler(Some(crate::core_runtime::poll_espnow));
            }
            *sta_extensions_enabled = enabled;
            *applied_nan_dw_interval = enabled.then_some(nan_dw_interval);
            crate::commands::send_response(if enabled {
                if profile.nan_dw_interval != 0 && nan_dw_interval == 0 {
                    b"wifi STA off-channel: NAN disabled, NOW/UDP6 enabled"
                } else {
                    b"wifi NAN/NOW coexistence enabled"
                }
            } else {
                b"wifi NAN/NOW coexistence failed"
            });
        } else {
            crate::wifi_esp::stop_sta_extensions();
            *sta_extensions_enabled = false;
            *applied_nan_dw_interval = None;
            crate::commands::send_response(b"wifi STA/NAN/NOW DW capture disabled");
        }
    }
    let nan_dw_interval = effective_sta_nan_dw_interval(profile);
    if *sta_extensions_enabled && *applied_nan_dw_interval != Some(nan_dw_interval) {
        if crate::wifi_esp::set_nan_dw_interval(nan_dw_interval) {
            *applied_nan_dw_interval = Some(nan_dw_interval);
            crate::commands::send_response(b"wifi STA/NAN/NOW DW interval updated");
        } else {
            crate::commands::send_response(b"wifi STA/NAN/NOW DW interval rejected");
        }
    }
}

/// Clear cached STA application fields after a driver teardown. Called exactly
/// on each STA replacement/stop path so a fresh driver cannot inherit a stale
/// successful-application marker from the previous radio epoch.
pub(crate) fn reset_sta_applied_state(
    applied_raw_tx_rate: &mut Option<u8>,
    applied_sta_driver_tx: &mut Option<bool>,
    applied_sta_bssid_check_disabled: &mut Option<bool>,
    applied_sta_ampdu_enabled: &mut Option<bool>,
    applied_sta_11b_rates_disabled: &mut Option<bool>,
    applied_sta_raw_rx_enabled: &mut Option<bool>,
    applied_ack_frequency: &mut Option<u8>,
    applied_ack_delay_ms: &mut Option<u8>,
    applied_tx_burst_packets: &mut Option<u8>,
) {
    *applied_raw_tx_rate = None;
    *applied_sta_driver_tx = None;
    *applied_sta_bssid_check_disabled = None;
    *applied_sta_ampdu_enabled = None;
    *applied_sta_11b_rates_disabled = None;
    *applied_sta_raw_rx_enabled = None;
    *applied_ack_frequency = None;
    *applied_ack_delay_ms = None;
    *applied_tx_burst_packets = None;
}

/// Start the AP-side raw UDP6 bearer for an already-applied NAN/AP epoch.
///
/// Called after a queued profile event or a retry deadline, but has no effect
/// once the adapter reports that its one bearer is started.  It performs no
/// discovery scan and never runs from a Wi-Fi callback.
fn start_nan_ap_raw_bearer_if_needed(profile: &crate::TransportProfile, state: &MainRadioState) {
    if wants_sta(profile)
        || profile.ap != 1
        || !state.nan_now_started
        || crate::wifi_raw_udp6_esp::started()
    {
        return;
    }
    if crate::wifi_esp::start_raw_udp6_ap(
        crate::core_runtime::receive_main_raw_udp6,
        crate::core_runtime::receive_udp6_connectionless,
    ) {
        crate::wifi_raw_udp6_esp::set_poll_handler(Some(crate::core_runtime::poll_raw_udp6));
        crate::commands::send_response(b"raw udp6 AP bearer started");
    } else {
        crate::commands::send_response(b"raw udp6 AP bearer failed");
    }
}

/// Replace the current unassociated or older STA epoch with the requested STA
/// epoch. Called only for a queued profile generation that requests STA, or a
/// deadline retry of that incomplete generation; it does not run on idle.
fn start_sta_epoch(profile: &crate::TransportProfile, generation: u32, state: &mut MainRadioState) {
    if state.nan_now_started {
        crate::wifi_esp::stop_sta_extensions();
        crate::wifi_esp::stop_sta();
        // Stopping a path does not discard the bearer-neutral QUIC
        // connection. A valid packet on the replacement path adopts that
        // path while retaining DCIDs, streams, and handler state.
        crate::wifi_esp::restart_sta_driver_runtime();
        state.nan_now_started = false;
    }
    state.sta_associated = false;
    if state.wifi_started {
        if state.sta_extensions_enabled {
            crate::wifi_esp::stop_sta_extensions();
            state.sta_extensions_enabled = false;
            state.applied_nan_dw_interval = None;
        }
        crate::wifi_raw_udp6_esp::stop();
        // Wi-Fi owns the complete driver/callback replacement.
        crate::wifi_esp::replace_sta(profile);
    } else {
        crate::wifi_esp::init_sta(profile);
    }
    state.applied_sta_start_generation = generation;
    state.applied_raw_tx_rate = Some(profile.raw_tx_rate);
    crate::wifi_raw_udp6_esp::set_sta_driver_tx(profile.sta_driver_tx);
    state.applied_sta_driver_tx = Some(profile.sta_driver_tx);
    state.applied_sta_bssid_check_disabled = Some(profile.sta_bssid_check_disabled);
    state.applied_sta_ampdu_enabled = Some(profile.sta_ampdu_enabled);
    state.applied_sta_11b_rates_disabled = Some(profile.sta_11b_rates_disabled);
    state.applied_ack_frequency = Some(profile.ack_frequency);
    state.applied_ack_delay_ms = Some(profile.ack_delay_ms);
    state.applied_tx_burst_packets = Some(profile.tx_burst_packets);
    crate::commands::send_response(if profile.sta_driver_tx {
        b"raw udp6 STA driver tx enabled"
    } else {
        b"raw udp6 STA raw tx enabled"
    });
    if profile.sta_raw_rx_enabled {
        // ESP-IDF connects asynchronously.  The STA completion event will
        // run `apply_sta_live_settings`, which prepares and starts raw UDP6
        // only after the AP/channel identity exists.
        state.applied_sta_raw_rx_enabled = None;
    } else {
        crate::commands::send_response(b"wifi STA esp-netif RX enabled");
        state.applied_sta_raw_rx_enabled = Some(false);
    }
    state.wifi_started = true;
}

/// Tear down an associated epoch and restore the requested unassociated NAN
/// personality. Called only when a queued profile explicitly leaves STA; it
/// returns after the replacement is complete so the caller can publish the
/// one transition-complete marker without falling through to STA settings.
fn stop_sta_epoch_for_nan(
    profile: &crate::TransportProfile,
    generation: u32,
    now_ms: u64,
    state: &mut MainRadioState,
) {
    if state.sta_extensions_enabled {
        crate::wifi_esp::stop_sta_extensions();
        state.sta_extensions_enabled = false;
        state.applied_nan_dw_interval = None;
    }
    crate::wifi_raw_udp6_esp::stop();
    crate::wifi_esp::stop_sta();
    state.wifi_started = false;
    state.sta_associated = false;
    reset_sta_applied_state(
        &mut state.applied_raw_tx_rate,
        &mut state.applied_sta_driver_tx,
        &mut state.applied_sta_bssid_check_disabled,
        &mut state.applied_sta_ampdu_enabled,
        &mut state.applied_sta_11b_rates_disabled,
        &mut state.applied_sta_raw_rx_enabled,
        &mut state.applied_ack_frequency,
        &mut state.applied_ack_delay_ms,
        &mut state.applied_tx_burst_packets,
    );
    crate::commands::send_response(b"transport STA stopped");
    crate::core_runtime::prepare_espnow_association(profile);
    state.nan_now_started =
        crate::wifi_esp::init_nan_now(profile, crate::core_runtime::receive_main_espnow);
    if state.nan_now_started {
        crate::wifi_espnow_esp::set_poll_handler(Some(crate::core_runtime::poll_espnow));
        // This replacement consumed the generation, so a deadline does not
        // immediately replace its new NAN/DW epoch a second time.
        state.applied_nan_start_generation = generation;
    }
    send_transition_announce(
        dmesh_server::announce::ANNOUNCE_TRANSITION_COMPLETE,
        now_ms / 1_000,
        state.nan_now_started,
        state.wifi_started,
    );
}

/// Apply the raw transmit-rate setting that ESP-IDF permits after association.
/// Called once per Main event only while an STA epoch is live; a failed driver
/// call deliberately leaves the cached value unchanged so a later explicit
/// deadline/profile event can retry without an idle-rate poll.
fn apply_sta_raw_tx_rate(profile: &crate::TransportProfile, state: &mut MainRadioState) {
    if !state.wifi_started || state.applied_raw_tx_rate == Some(profile.raw_tx_rate) {
        return;
    }
    if crate::wifi_esp::configure_raw_tx_rate(profile.raw_tx_rate) {
        state.applied_raw_tx_rate = Some(profile.raw_tx_rate);
        crate::commands::send_response(b"raw udp6 tx rate updated");
    } else {
        crate::commands::send_response(b"raw udp6 tx rate failed");
    }
}

/// Restart the current STA driver for one setting that ESP-IDF applies only
/// before association. Called only by `apply_sta_live_settings` after an
/// explicit profile change; the caller retries the requested STA generation
/// on its next queued event rather than continuing through stale state.
fn restart_sta_for_preassociation_setting(state: &mut MainRadioState, driver_only: bool) {
    if state.sta_extensions_enabled {
        crate::wifi_esp::stop_sta_extensions();
        state.sta_extensions_enabled = false;
        state.applied_nan_dw_interval = None;
    }
    crate::wifi_raw_udp6_esp::stop();
    if driver_only {
        crate::wifi_esp::restart_sta_driver_runtime();
    } else {
        crate::wifi_esp::restart_sta_runtime();
    }
    state.wifi_started = false;
    reset_sta_applied_state(
        &mut state.applied_raw_tx_rate,
        &mut state.applied_sta_driver_tx,
        &mut state.applied_sta_bssid_check_disabled,
        &mut state.applied_sta_ampdu_enabled,
        &mut state.applied_sta_11b_rates_disabled,
        &mut state.applied_sta_raw_rx_enabled,
        &mut state.applied_ack_frequency,
        &mut state.applied_ack_delay_ms,
        &mut state.applied_tx_burst_packets,
    );
}

/// Apply live STA bearer settings for one explicit Main event.
///
/// It returns `true` when a pre-association setting required a driver restart;
/// the event owner must then stop processing this turn and wait for the next
/// event to create the new STA epoch. No callback calls this method, and it
/// has no effect while Main is in its NAN-only personality.
fn apply_sta_live_settings(profile: &crate::TransportProfile, state: &mut MainRadioState) -> bool {
    if !state.wifi_started || !state.sta_associated {
        return false;
    }
    if state.applied_sta_driver_tx != Some(profile.sta_driver_tx) {
        crate::wifi_raw_udp6_esp::set_sta_driver_tx(profile.sta_driver_tx);
        state.applied_sta_driver_tx = Some(profile.sta_driver_tx);
        crate::commands::send_response(if profile.sta_driver_tx {
            b"raw udp6 STA driver tx enabled"
        } else {
            b"raw udp6 STA raw tx enabled"
        });
    }
    if state.applied_sta_raw_rx_enabled != Some(profile.sta_raw_rx_enabled) {
        crate::wifi_raw_udp6_esp::stop();
        if profile.sta_raw_rx_enabled {
            crate::core_runtime::prepare_raw_association(profile);
            if crate::wifi_esp::start_raw_udp6(
                crate::core_runtime::receive_main_raw_udp6,
                crate::core_runtime::receive_udp6_connectionless,
            ) {
                crate::wifi_raw_udp6_esp::set_poll_handler(Some(
                    crate::core_runtime::poll_raw_udp6,
                ));
                crate::commands::send_response(b"raw udp6 STA RX enabled");
                // The associated bearer is now actually live, so emit the
                // once-per-STA-epoch multicast boot record here rather than
                // at the earlier asynchronous connect request.
                send_sta_discovery_announce();
                state.applied_sta_raw_rx_enabled = Some(true);
            } else {
                crate::commands::send_response(b"raw udp6 STA RX failed");
                state.applied_sta_raw_rx_enabled = None;
            }
        } else {
            crate::commands::send_response(b"wifi STA esp-netif RX enabled");
            state.applied_sta_raw_rx_enabled = Some(false);
        }
    }
    if state.applied_sta_ampdu_enabled != Some(profile.sta_ampdu_enabled)
        || state.applied_sta_11b_rates_disabled != Some(profile.sta_11b_rates_disabled)
    {
        // AMPDU/basic-rate policy must precede STA association.
        restart_sta_for_preassociation_setting(state, true);
        return true;
    }
    if state.applied_sta_bssid_check_disabled != Some(profile.sta_bssid_check_disabled) {
        // This setting needs the full STA restart to restore raw NDP on C6.
        restart_sta_for_preassociation_setting(state, false);
        return true;
    }
    if state.applied_ack_frequency != Some(profile.ack_frequency)
        || state.applied_ack_delay_ms != Some(profile.ack_delay_ms)
        || state.applied_tx_burst_packets != Some(profile.tx_burst_packets)
    {
        crate::core_runtime::replace_raw_association(profile);
        state.applied_ack_frequency = Some(profile.ack_frequency);
        state.applied_ack_delay_ms = Some(profile.ack_delay_ms);
        state.applied_tx_burst_packets = Some(profile.tx_burst_packets);
        crate::commands::send_response(b"connection association defaults updated");
    }
    apply_sta_nan_extensions(
        profile,
        state.wifi_started,
        &mut state.sta_extensions_enabled,
        &mut state.applied_nan_dw_interval,
    );
    false
}

fn send_announce_on_now(kind: u64, uptime_secs: u64, role: u8, partition: u8) {
    if let Some((record, used)) = announce_record(kind, uptime_secs, role, partition) {
        let _ = crate::wifi_espnow_esp::broadcast_record(&record[..used]);
    }
}

const DISCOVERY_CACHE_EMPTY: u8 = 0;
const DISCOVERY_CACHE_BUILDING: u8 = 1;
const DISCOVERY_CACHE_READY: u8 = 2;

/// One signed discovery record, keyed by the transport fields it contains.
/// A changed association/channel/link-local set invalidates the cache and
/// causes exactly one replacement signature; repeated peer requests reuse it.
struct CachedDiscoveryRecord {
    bytes: core::cell::UnsafeCell<[u8; dmesh_rawnan::NAN_ACTIVE_PUBLISH_MAX_LEN]>,
    key: core::cell::UnsafeCell<[u8; 40]>,
    len: AtomicUsize,
}

// The try-lock serializes the only unsafe cache access. Packet ingress never
// waits for it: a simultaneous request is simply coalesced into the cached
// publication/retry policy.
unsafe impl Sync for CachedDiscoveryRecord {}

static DISCOVERY_CACHE_STATE: AtomicU8 = AtomicU8::new(DISCOVERY_CACHE_EMPTY);
static DISCOVERY_CACHE_LOCK: AtomicBool = AtomicBool::new(false);
/// Monotonic semantic revision for fields that participate in a signed
/// discovery record.  It is part of the cache key so a write racing a packet
/// turn cannot leave a stale name/domain record reusable.
static DISCOVERY_CACHE_REVISION: AtomicU32 = AtomicU32::new(0);
static DISCOVERY_CACHE: CachedDiscoveryRecord = CachedDiscoveryRecord {
    bytes: core::cell::UnsafeCell::new([0; dmesh_rawnan::NAN_ACTIVE_PUBLISH_MAX_LEN]),
    key: core::cell::UnsafeCell::new([0; 40]),
    len: AtomicUsize::new(0),
};

/// Invalidate a cached signed discovery record after a normal stream setting
/// mutation.  This is intentionally independent of UART/NOW/UDP: persistence
/// changes discovery facts, while every bearer obtains the refreshed record
/// from the common cache on its next send.
pub(crate) fn invalidate_discovery_cache() {
    DISCOVERY_CACHE_REVISION.fetch_add(1, Ordering::AcqRel);
    DISCOVERY_CACHE_STATE.store(DISCOVERY_CACHE_EMPTY, Ordering::Release);
}

fn discovery_transport_key() -> Option<[u8; 40]> {
    let mac = crate::wifi_esp::interface_mac(crate::wifi_esp::RadioInterface::Sta)
        .or_else(|| crate::wifi_esp::interface_mac(crate::wifi_esp::RadioInterface::Ap))?;
    let mut key = [0u8; 40];
    key[..6].copy_from_slice(&mac);
    if let Some((channel, _)) = crate::wifi_esp::current_channel() {
        key[7] = channel;
    }
    if crate::wifi_esp::sta_associated() {
        key[6] = 1;
        let mut ssid = [0u8; dmesh_server::announce::MAX_NETWORK_NAME];
        if let Some(used) = read_setting(b"sta_ssid", &mut ssid) {
            let used = used.min(key.len() - 8);
            key[8..8 + used].copy_from_slice(&ssid[..used]);
        }
    }
    let revision = DISCOVERY_CACHE_REVISION
        .load(Ordering::Acquire)
        .to_be_bytes();
    key[36..40].copy_from_slice(&revision);
    Some(key)
}

fn cached_discovery_record(
    role: u8,
    partition: u8,
) -> Option<([u8; dmesh_rawnan::NAN_ACTIVE_PUBLISH_MAX_LEN], usize)> {
    let key = discovery_transport_key()?;
    if DISCOVERY_CACHE_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        // Never spin the packet ingress worker behind an expensive signer.
        return None;
    }
    let result = (|| {
        if DISCOVERY_CACHE_STATE.load(Ordering::Acquire) == DISCOVERY_CACHE_READY
            // Safe under the try-lock above; the cache key is immutable while
            // READY and is replaced together with the signed record.
            && unsafe { *DISCOVERY_CACHE.key.get() } == key
        {
            let used = DISCOVERY_CACHE.len.load(Ordering::Acquire);
            if used == 0 || used > dmesh_rawnan::NAN_ACTIVE_PUBLISH_MAX_LEN {
                return None;
            }
            let mut record = [0; dmesh_rawnan::NAN_ACTIVE_PUBLISH_MAX_LEN];
            // Safe under the try-lock above.
            unsafe {
                let cached = &*DISCOVERY_CACHE.bytes.get();
                record[..used].copy_from_slice(&cached[..used]);
            }
            return Some((record, used));
        }
        DISCOVERY_CACHE_STATE.store(DISCOVERY_CACHE_BUILDING, Ordering::Release);
        let built = build_announce_record(
            dmesh_server::announce::ANNOUNCE_DISCOVERY,
            0,
            role,
            partition,
        );
        match built {
            Some((record, used)) => {
                unsafe {
                    let cached = &mut *DISCOVERY_CACHE.bytes.get();
                    cached[..used].copy_from_slice(&record[..used]);
                    *DISCOVERY_CACHE.key.get() = key;
                }
                DISCOVERY_CACHE.len.store(used, Ordering::Relaxed);
                DISCOVERY_CACHE_STATE.store(DISCOVERY_CACHE_READY, Ordering::Release);
                Some((record, used))
            }
            None => {
                DISCOVERY_CACHE_STATE.store(DISCOVERY_CACHE_EMPTY, Ordering::Release);
                None
            }
        }
    })();
    DISCOVERY_CACHE_LOCK.store(false, Ordering::Release);
    result
}

fn announce_record(
    kind: u64,
    uptime_secs: u64,
    role: u8,
    partition: u8,
) -> Option<([u8; dmesh_rawnan::NAN_ACTIVE_PUBLISH_MAX_LEN], usize)> {
    if kind == dmesh_server::announce::ANNOUNCE_DISCOVERY {
        cached_discovery_record(role, partition)
    } else {
        build_announce_record(kind, uptime_secs, role, partition)
    }
}

fn build_announce_record(
    kind: u64,
    uptime_secs: u64,
    role: u8,
    partition: u8,
) -> Option<([u8; dmesh_rawnan::NAN_ACTIVE_PUBLISH_MAX_LEN], usize)> {
    build_announce_record_with_capabilities(
        kind,
        uptime_secs,
        role,
        partition,
        dmesh_server::probe::PROBE_CAP_NAN
            | dmesh_server::probe::PROBE_CAP_NOW
            | dmesh_server::probe::PROBE_CAP_STA
            | dmesh_server::probe::PROBE_CAP_AP
            | dmesh_server::probe::PROBE_CAP_UDP6,
    )
}

/// Signed Recovery presence for the ordinary STA/UDP6 update server.  This
/// deliberately advertises neither NAN, NOW nor AP capabilities.
pub(crate) fn recovery_discovery_record(
    uptime_secs: u64,
) -> Option<([u8; dmesh_rawnan::NAN_ACTIVE_PUBLISH_MAX_LEN], usize)> {
    build_announce_record_with_capabilities(
        dmesh_server::announce::ANNOUNCE_DISCOVERY,
        uptime_secs,
        0,
        0,
        dmesh_server::probe::PROBE_CAP_STA | dmesh_server::probe::PROBE_CAP_UDP6,
    )
}

fn build_announce_record_with_capabilities(
    kind: u64,
    uptime_secs: u64,
    _role: u8,
    _partition: u8,
    capabilities: u16,
) -> Option<([u8; dmesh_rawnan::NAN_ACTIVE_PUBLISH_MAX_LEN], usize)> {
    let mac = crate::wifi_esp::interface_mac(crate::wifi_esp::RadioInterface::Sta)
        .or_else(|| crate::wifi_esp::interface_mac(crate::wifi_esp::RadioInterface::Ap))?;
    let private = load_or_create_identity_private_key()?;
    let public_key = crate::crypto_esp::p256_public_key(&private)?;
    let identity_hint = dmesh_server::announce::identity_hint(&public_key)?;
    let mut id = [0; 16];
    id[..identity_hint.len()].copy_from_slice(&identity_hint);
    let uptime_secs = u32::try_from(uptime_secs).unwrap_or(u32::MAX);
    let mut announce =
        dmesh_server::announce::Announce::discovery(id, identity_hint.len() as u8, uptime_secs);
    announce.kind = kind;
    let mut announce = announce;
    if !announce.set_public_key(&public_key) {
        return None;
    }
    announce.set_probe_descriptor(dmesh_server::announce::DEVICE_CLASS_ESP, capabilities);
    let mut name = [0u8; dmesh_server::announce::MAX_DEVICE_NAME];
    if let Some(used) = read_setting(b"name", &mut name) {
        if let Ok(name) = core::str::from_utf8(&name[..used]) {
            let _ = announce.set_device_name(name);
        }
    }
    let mut domain = [0u8; dmesh_server::announce::MAX_DEVICE_DOMAIN];
    if let Some(used) = read_setting(b"domain", &mut domain) {
        if let Ok(domain) = core::str::from_utf8(&domain[..used]) {
            let _ = announce.set_device_domain(domain);
        }
    }
    // The station profile is the active SSID while associated. Do not expose
    // a stale provisioned value while running only NAN/NOW or AP.
    if crate::wifi_esp::sta_associated() {
        let mut ssid = [0u8; dmesh_server::announce::MAX_NETWORK_NAME];
        if let Some(used) = read_setting(b"sta_ssid", &mut ssid) {
            if let Ok(ssid) = core::str::from_utf8(&ssid[..used]) {
                let _ = announce.set_network_name(ssid);
            }
        }
    }
    if let Some((channel, _)) = crate::wifi_esp::current_channel() {
        let _ = announce.set_wifi_channel(channel);
    }
    // ESP raw UDP6 uses the deterministic EUI-64 link-local address for its
    // active STA netif. AP endpoints are found by multicast rather than being
    // repeated in the announce.
    if crate::wifi_esp::sta_associated() {
        let address = quic_lite::raw_udp6::link_local_from_mac(mac);
        announce.set_sta_link_local_v6(address);
        // Raw UDP6 is a normal QUIC bearer on Main, not merely an observation
        // source. Advertise the same path facts which the receive adapter
        // actually accepts so Linux/Android can select it without a private
        // board-specific port fallback.
        announce.set_udp_link_local_v6(address);
        announce.set_udp_port(crate::wifi_raw_udp6_esp::RAW_UDP6_PORT);
    }
    let mut signing = [0; dmesh_rawnan::NAN_ACTIVE_PUBLISH_MAX_LEN];
    let signing_len = dmesh_server::announce::signing_bytes(announce, &mut signing)?;
    let signature = crate::crypto_esp::p256_sign(&private, &signing[..signing_len])?;
    if !announce.set_signature(&signature) {
        return None;
    }
    let mut record = [0; dmesh_rawnan::NAN_ACTIVE_PUBLISH_MAX_LEN];
    let used = dmesh_server::announce::encode(announce, &mut record)?;
    Some((record, used))
}

/// Apply the complete radio side of one accepted Main event.
/// Called only by Main's queue owner after a profile or adapter completion;
/// callbacks cannot invoke it. `true` means a radio epoch stopped or a live
/// setting is deferred, so the caller must publish and await another event.
fn apply_radio_transition(
    role: u8,
    profile: &crate::TransportProfile,
    generation: u32,
    now_ms: u64,
    state: &mut MainRadioState,
    transition_pending: bool,
) -> bool {
    if transition_pending && !(state.wifi_started && !wants_sta(profile)) {
        send_transition_announce(
            dmesh_server::announce::ANNOUNCE_TRANSITION_BEGIN,
            now_ms / 1_000,
            state.nan_now_started,
            state.wifi_started,
        );
        state.transition_announced_generation = generation;
    }
    // A DW8 profile retains the control UART through the physical sleep call.
    // Apply the profile like every other transport configuration.
    apply_uart_profile(role, profile, &mut state.applied_uart);
    // ESP-IDF has completed an association attempt without a connection.
    // Restore the normal unassociated radio personality once, then leave the
    // next scan/STA attempt to the discovery cadence below.
    if wants_sta(profile) && state.sta_retry_pending && state.wifi_started && !state.sta_associated
    {
        // The fallback announce below is the status-changing announce for
        // this failed attempt.  Start the five-minute retry interval from it.
        state.last_discovery_announce_ms = now_ms;
        stop_sta_epoch_for_nan(profile, generation, now_ms, state);
        return true;
    }
    apply_nan_epoch(
        profile,
        generation,
        state.wifi_started,
        &mut state.nan_now_started,
        &mut state.applied_nan_start_generation,
    );
    start_nan_ap_raw_bearer_if_needed(profile, state);
    if wants_sta(profile)
        && (!state.sta_retry_pending || state.sta_retry_due)
        && (!state.wifi_started || state.applied_sta_start_generation != generation)
    {
        start_sta_epoch(profile, generation, state);
        state.sta_retry_pending = false;
        state.sta_retry_due = false;
    }
    if state.wifi_started && !wants_sta(profile) {
        stop_sta_epoch_for_nan(profile, generation, now_ms, state);
        return true;
    }
    apply_sta_raw_tx_rate(profile, state);
    if transition_pending {
        send_transition_announce(
            dmesh_server::announce::ANNOUNCE_TRANSITION_COMPLETE,
            now_ms / 1_000,
            state.nan_now_started,
            state.wifi_started,
        );
    }
    apply_sta_live_settings(profile, state)
}

/// Admit and execute a sleepy boundary after its radio effects have settled.
/// Called once at the tail of a Main-owner event only for a DW8 profile. It
/// records physical sleep/wake effects in the portable reducer and returns
/// whether the caller must yield to the queue before another effect.
fn apply_sleep_boundary(
    role: u8,
    profile: &crate::TransportProfile,
    generation: u32,
    now_ms: u64,
    soft_sleep: bool,
    state: &mut MainRadioState,
    runtime_state: &mut dmesh_server::main_runtime_state::MainRuntimeState,
) -> bool {
    use dmesh_server::main_runtime_state::{MainEffect, MainEvent, SleepBlockers};
    if !is_sleepy_profile(profile) {
        return false;
    }
    let mut blockers = SleepBlockers::NONE;
    if role != 1 || state.wifi_started || !state.nan_now_started {
        blockers = SleepBlockers(blockers.0 | SleepBlockers::RADIO_TRANSITION.0);
    }
    if now_ms < state.sleepy_awake_until_ms {
        blockers = SleepBlockers(blockers.0 | SleepBlockers::NAN_DEADLINE.0);
    }
    if !blockers.is_empty() {
        if blockers.0 & SleepBlockers::RADIO_TRANSITION.0 != 0 {
            crate::commands::send_response(b"sleep DW8 blocked: radio transition");
        } else {
            crate::commands::send_response(b"sleep DW8 blocked: command window");
        }
    }
    let effect = runtime_state.reduce(MainEvent::SleepDeadline {
        generation,
        blockers,
    });
    if !matches!(effect, MainEffect::EnterLightSleep { generation: effect_generation } if effect_generation == generation)
    {
        return false;
    }
    if !maybe_enter_sleep(
        role,
        profile,
        &mut state.nan_now_started,
        state.wifi_started,
        soft_sleep,
        now_ms,
        &mut state.sleepy_awake_until_ms,
    ) {
        return false;
    }
    let _ = runtime_state.reduce(MainEvent::SleepEntered { generation });
    let _ = runtime_state.reduce(MainEvent::Wake {
        generation,
        cause: 1,
    });
    record_power_completion(runtime_state);
    publish_snapshot(runtime_state.snapshot());
    true
}

/// All mutable radio-application bookkeeping belongs to this one Main task.
///
/// Wi-Fi and UART callbacks only copy ingress data and enqueue an event.  They
/// never borrow this structure or call a driver transition themselves.  The
/// fields are deliberately grouped here instead of remaining as independent
/// locals in the coordinator: a profile replacement must either advance this
/// whole applied epoch, or leave it retryable on the next explicit event.
pub(crate) struct MainRadioState {
    pub nan_now_started: bool,
    pub wifi_started: bool,
    /// ESP-IDF-confirmed STA association. `wifi_started` means only that the
    /// driver epoch exists; Main keeps the portable lifecycle at `Starting`
    /// until the STA callback queues this completion.
    pub sta_associated: bool,
    /// A disconnected STA returns to NAN/NOW.  It may only begin a new
    /// scan/association at the next discovery cadence, never from a driver
    /// callback or a general timer turn.
    pub sta_retry_pending: bool,
    pub sta_retry_due: bool,
    pub applied_raw_tx_rate: Option<u8>,
    pub applied_sta_driver_tx: Option<bool>,
    pub applied_sta_bssid_check_disabled: Option<bool>,
    pub applied_sta_ampdu_enabled: Option<bool>,
    pub applied_sta_11b_rates_disabled: Option<bool>,
    pub applied_sta_raw_rx_enabled: Option<bool>,
    pub applied_ack_frequency: Option<u8>,
    pub applied_ack_delay_ms: Option<u8>,
    pub applied_tx_burst_packets: Option<u8>,
    pub applied_sta_start_generation: u32,
    pub transition_announced_generation: u32,
    pub applied_nan_start_generation: u32,
    pub sta_extensions_enabled: bool,
    pub applied_nan_dw_interval: Option<u8>,
    pub applied_uart: Option<u8>,
    pub last_discovery_announce_ms: u64,
    pub sleepy_awake_until_ms: u64,
}

/// Serialized work accepted by the Main coordinator. Profile changes are
/// enqueued by copied bearer ingress; deadline events are emitted by the
/// coordinator's timer path. Neither variant carries credentials or a driver
/// buffer across a task boundary.
#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) enum MainRuntimeEvent {
    /// A one-shot timer expired. `services` identifies exactly which adapter
    /// deadlines were due when Main armed the timer; it is not a periodic
    /// general-purpose tick or permission to scan every radio service.
    Deadline {
        services: u8,
    },
    /// An ESP-IDF adapter completed asynchronous driver ownership.  The
    /// callback only enqueues the affected service mask; Main performs any
    /// resulting radio work after it receives this event.
    AdapterComplete {
        services: u8,
    },
    ProfileChanged {
        generation: u32,
    },
}

const DEADLINE_NAN_CAPTURE: u8 = 1 << 0;
const DEADLINE_ROC: u8 = 1 << 1;
/// A server-side connection PTO. Main only queues the typed event; the
/// shared packet worker owns the service ledger and performs the egress turn.
const DEADLINE_CONNECTION: u8 = 1 << 5;
/// A raw NOW packet changed the server ledger and Main must recompute its
/// next one-shot deadline.  This is intentionally a wake-only marker: the
/// packet worker already sent any immediate response, so treating it as a
/// due PTO would submit a second action back-to-back.
const DEADLINE_RECHECK: u8 = 1 << 6;
/// This bit wakes the owner solely to evaluate an admitted sleepy boundary.
/// It never calls a radio adapter by itself.
const DEADLINE_SLEEP_POLICY: u8 = 1 << 3;
/// STA lifecycle is a callback event, not a timer service. The bit wakes the
/// event owner so it can apply the associated raw bearer after ESP-IDF's
/// connected/disconnected completion.
const DEADLINE_STA_LIFECYCLE: u8 = 1 << 4;

/// Main owns this queue and timer for its entire lifetime. Bearer workers may
/// append a copyable event, but only the Main task receives and acts on it.
static EVENT_QUEUE: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(core::ptr::null_mut());
/// Durable service work posted by ESP-IDF callbacks and the one-shot timer.
///
/// The queue is deliberately small because it transfers only wake markers,
/// not packets. A marker can be dropped while the queue is full, but a NOW
/// transaction must still receive its retry/PTO deadline. Producers OR their
/// service bits here before attempting the non-blocking queue send; the owner
/// atomically drains them after every wake. Queue pressure therefore coalesces
/// wake markers but cannot lose the service itself.
static PENDING_DEADLINE_SERVICES: AtomicU8 = AtomicU8::new(0);
/// Count coalesced queue markers for diagnostics. Their work remains in
/// `PENDING_DEADLINE_SERVICES`, so this records congestion rather than loss.
static EVENT_QUEUE_DROPS: AtomicU32 = AtomicU32::new(0);

/// Send a zero-work wake marker after a producer has persisted service bits.
/// This runs only in timer/adapter callback context and may not block. If the
/// queue is full, its existing entry wakes Main, which drains the bitset.
fn enqueue_service_marker(queue: *mut core::ffi::c_void) {
    let event = MainRuntimeEvent::AdapterComplete { services: 0 };
    if unsafe {
        esp_idf_sys::xQueueGenericSend(
            queue.cast(),
            (&event as *const MainRuntimeEvent).cast(),
            0,
            0,
        )
    } != 1
    {
        EVENT_QUEUE_DROPS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Create Main's bounded event channel. Called once before UART/radio bring-up;
/// Recovery never reaches this code. The owner waits on the queue with the
/// nearest adapter deadline as its FreeRTOS timeout, so there is no separate
/// timer callback that can be delayed behind a full producer queue.
pub(crate) fn initialize_event_queue() -> bool {
    let queue = unsafe {
        esp_idf_sys::xQueueGenericCreate(8, core::mem::size_of::<MainRuntimeEvent>() as _, 0)
    };
    if queue.is_null()
        || EVENT_QUEUE
            .compare_exchange(
                core::ptr::null_mut(),
                queue.cast(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
    {
        return false;
    }
    true
}

/// Queue a fully committed profile generation. Called by bearer ingress after
/// it releases the profile lock; never from a Wi-Fi driver callback.
pub(crate) fn enqueue_profile_change(generation: u32) {
    let queue = EVENT_QUEUE.load(Ordering::Acquire);
    if queue.is_null() {
        return;
    }
    let event = MainRuntimeEvent::ProfileChanged { generation };
    if unsafe {
        esp_idf_sys::xQueueGenericSend(
            queue.cast(),
            (&event as *const MainRuntimeEvent).cast(),
            0,
            0,
        )
    } != 1
    {
        EVENT_QUEUE_DROPS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Copy one adapter completion into Main's bounded event queue. Registered
/// callbacks call this after they release their own driver/static-resource
/// ownership; it never calls Wi-Fi, takes the profile lock, or allocates.
pub(crate) fn enqueue_adapter_completion(services: u8) {
    if services == 0 {
        return;
    }
    let queue = EVENT_QUEUE.load(Ordering::Acquire);
    if queue.is_null() {
        return;
    }
    // Driver callbacks must not block. Persist their required owner-side work
    // before the best-effort marker, so a full queue loses no transition.
    PENDING_DEADLINE_SERVICES.fetch_or(services, Ordering::AcqRel);
    enqueue_service_marker(queue);
}

/// Wake Main after ingress starts or advances a connection-owned deadline.
/// Adapters never poll: this durable bit makes the owner compute and sleep
/// until the next exact transport deadline.
pub(crate) fn request_deadline_recheck() {
    enqueue_adapter_completion(DEADLINE_RECHECK);
}

/// Wake the Main owner after the shared connection worker changed NOW
/// retransmission state. Called once per accepted NOW datagram, not from a
/// Wi-Fi callback and never as a periodic tick. The next owner turn merely
/// recalculates the exact server PTO before blocking again.
pub(crate) fn request_connection_deadline_recheck() {
    enqueue_adapter_completion(DEADLINE_RECHECK);
}

/// ROC completion bridge registered at Main boot. It is called by ESP-IDF's
/// Wi-Fi task only after that adapter has released its static request slot.
/// The selected NAN service can therefore resume a deferred acquisition on
/// the owner task without waiting for an unrelated timer deadline.
fn receive_roc_completion() {
    enqueue_adapter_completion(DEADLINE_NAN_CAPTURE);
}

/// STA lifecycle bridge registered at Main boot. ESP-IDF has already updated
/// its association atomics before this runs; Main reads that bounded observed
/// state on the queued owner turn and never treats `esp_wifi_connect` as a
/// completed association.
fn receive_sta_lifecycle(_associated: bool, _reason: u8) {
    enqueue_adapter_completion(DEADLINE_STA_LIFECYCLE);
}

/// Compute the nearest actual adapter or sleepy-policy deadline, preserving
/// every source that is due at that instant. The caller passes this exact
/// duration to `xQueueReceive`, which blocks the sole Main owner until either
/// a producer event or the deadline occurs. This deliberately has no periodic
/// fallback: with no service active the queue wait is unbounded.
fn next_deadline(sleep_deadline_ms: Option<u64>) -> Option<(u8, u32)> {
    let nan_delay = crate::wifi_nan_dw_capture_esp::next_service_delay_ms();
    let roc_delay = crate::wifi_nonpromisc_probe_esp::next_service_delay_ms();
    let connection_delay = crate::core_runtime::connection_delay_ms();
    let now_ms = (unsafe { esp_idf_sys::esp_timer_get_time() }.max(0) as u64) / 1_000;
    let sleep_delay = sleep_deadline_ms
        .map(|deadline| deadline.saturating_sub(now_ms).min(u64::from(u32::MAX)) as u32);
    let Some(delay_ms) = nan_delay
        .into_iter()
        .chain(roc_delay)
        .chain(connection_delay)
        .chain(sleep_delay)
        .min()
    else {
        return None;
    };
    let mut services = 0;
    if nan_delay == Some(delay_ms) {
        services |= DEADLINE_NAN_CAPTURE;
    }
    if roc_delay == Some(delay_ms) {
        services |= DEADLINE_ROC;
    }
    if connection_delay == Some(delay_ms) {
        services |= DEADLINE_CONNECTION;
    }
    if sleep_delay == Some(delay_ms) {
        services |= DEADLINE_SLEEP_POLICY;
    }
    Some((services, delay_ms.max(1)))
}

/// Wait once for a producer event or the scheduled radio deadline. The
/// FreeRTOS receive blocks, so this is not a CPU polling loop.
fn wait_for_event(last_generation: u32, sleep_deadline_ms: Option<u64>) -> MainRuntimeEvent {
    let deadline = next_deadline(sleep_deadline_ms);
    // Producer-before-receive: handle durable work immediately without a
    // polling pass. Inactive Main still blocks below with no timer armed.
    let pending = PENDING_DEADLINE_SERVICES.swap(0, Ordering::AcqRel);
    if pending != 0 {
        return MainRuntimeEvent::AdapterComplete { services: pending };
    }
    let queue = EVENT_QUEUE.load(Ordering::Acquire);
    let mut event = MainRuntimeEvent::Deadline { services: 0 };
    // ESP-IDF configures the FreeRTOS tick rate; round up so a 25 ms NOW
    // delayed-ACK/PTO deadline never fires early. This is a one-shot block,
    // not a service tick: the next wait recalculates only after real work.
    let wait_ticks = deadline
        .map(|(_, delay_ms)| {
            (u64::from(delay_ms) * u64::from(esp_idf_sys::configTICK_RATE_HZ))
                .div_ceil(1_000)
                .max(1)
                .min(u64::from(esp_idf_sys::TickType_t::MAX)) as esp_idf_sys::TickType_t
        })
        .unwrap_or(esp_idf_sys::TickType_t::MAX);
    if !queue.is_null()
        && unsafe {
            esp_idf_sys::xQueueReceive(
                queue.cast(),
                (&mut event as *mut MainRuntimeEvent).cast(),
                wait_ticks,
            )
        } == 1
    {
        // Merge a producer racing with the blocking receive. Profile changes
        // retain ordering: their adapter work stays pending for the next turn.
        let pending = PENDING_DEADLINE_SERVICES.swap(0, Ordering::AcqRel);
        return match event {
            MainRuntimeEvent::Deadline { services } => MainRuntimeEvent::Deadline {
                services: services | pending,
            },
            MainRuntimeEvent::AdapterComplete { services } => MainRuntimeEvent::AdapterComplete {
                services: services | pending,
            },
            MainRuntimeEvent::ProfileChanged { generation } => {
                if pending != 0 {
                    PENDING_DEADLINE_SERVICES.fetch_or(pending, Ordering::AcqRel);
                }
                MainRuntimeEvent::ProfileChanged { generation }
            }
        };
    }
    if let Some((services, _)) = deadline {
        // The bounded receive elapsed. Service only the adapters which chose
        // this deadline; no idle radio reconciliation is permitted here.
        return MainRuntimeEvent::Deadline { services };
    }
    let generation = crate::profile_store::generation();
    if generation != last_generation {
        MainRuntimeEvent::ProfileChanged { generation }
    } else {
        MainRuntimeEvent::Deadline { services: 0 }
    }
}

/// Drain the event-producer overflow counter after one Main event turn.
pub(crate) fn take_event_queue_drops() -> u32 {
    EVENT_QUEUE_DROPS.swap(0, Ordering::AcqRel)
}

/// Apply a tagged `transport.start` request received through a QUIC/UDP6
/// stream. Called by the fixed shared handler registry on the bearer worker;
/// it commits one complete desired profile and enqueues its generation, but
/// never calls Wi-Fi or waits for the Main owner. UART and NAN use equivalent
/// packet adapters until their Main-only ingress code is moved here as well.
pub(crate) fn receive_tagged_control(
    record: dmesh_server::tagged::Record<'_>,
) -> Option<alloc::vec::Vec<u8>> {
    if record.to.is_some() {
        return None;
    }
    // A settings inventory is bounded by the reviewed NVS key/value limits.
    // Keep its correlated result on the requesting stream rather than
    // emitting one status record per key on a bearer-specific side channel.
    let mut response = [0u8; 640];
    let mut response_len = 0usize;
    let mut changed_transport = false;
    let accepted = crate::profile_store::with_profile(|params| {
        let Some(result) = crate::commands::apply_control_record_decoded(record, params) else {
            return false;
        };
        match result {
            Ok(result) => {
                // Both start and stop change the immutable desired radio
                // profile. A repeated declarative request has `changed=false`
                // and deliberately leaves the current epoch alone.
                changed_transport = result.changed;
                response_len = encode_tagged_control_response(record, &mut response).unwrap_or(0);
            }
            Err(error) => {
                response_len =
                    crate::commands::encode_control_error_decoded(record, error, &mut response)
                        .unwrap_or(0);
            }
        }
        true
    });
    if !accepted {
        return None;
    }
    crate::state::direct_record_accepted();
    if changed_transport {
        let generation = crate::profile_store::advance_generation();
        enqueue_profile_change(generation);
    }
    (response_len != 0).then(|| alloc::vec::Vec::from(&response[..response_len]))
}

/// Encode the complete, bounded result of a control-stream operation.
///
/// Settings reads need data, not merely an acknowledgement.  The result uses
/// text keys so the schema/HTTP adapter and CLI can render it without a
/// UART/NOW-specific decoder.  Secret values are represented only by the
/// fixed redacted marker.  All other control methods retain their shared empty
/// success response.
fn encode_tagged_control_response(
    record: dmesh_server::tagged::Record<'_>,
    out: &mut [u8],
) -> Option<usize> {
    use dmesh_server::{cbor::Encoder, control, tagged};

    let id = record.id?;
    let request = control::decode_record(record)?;
    let method = match request {
        control::Request::SettingsGet { .. } => control::SETTINGS_GET,
        control::Request::SettingsSet { .. } => control::SETTINGS_SET,
        control::Request::SettingsList => control::SETTINGS_LIST,
        control::Request::TransportSet { .. } => control::TRANSPORT_SET,
    };
    let mut result = [0u8; 512];
    let mut encoder = Encoder::new(&mut result);
    match request {
        control::Request::SettingsGet { key } => {
            let mut value = [0u8; 64];
            let used = read_setting(key, &mut value)?;
            encoder.map(2)?;
            encoder.text_value(b"key")?;
            encoder.text_value(key)?;
            encoder.text_value(b"value")?;
            encoder.text_value(&value[..used])?;
        }
        control::Request::SettingsList => {
            let mut value = [0u8; 64];
            let public_count = setting_keys()
                .iter()
                .filter(|key| read_setting(key, &mut value).is_some())
                .count();
            let secret_count = secret_setting_keys()
                .iter()
                .filter(|key| secret_setting_exists(key))
                .count();
            encoder.map(1)?;
            encoder.text_value(b"entries")?;
            encoder.array((public_count + secret_count) as u64)?;
            for key in setting_keys() {
                let Some(used) = read_setting(key, &mut value) else {
                    continue;
                };
                encoder.map(2)?;
                encoder.text_value(b"key")?;
                encoder.text_value(key)?;
                encoder.text_value(b"value")?;
                encoder.text_value(&value[..used])?;
            }
            for key in secret_setting_keys() {
                if !secret_setting_exists(key) {
                    continue;
                }
                let mut label = [0u8; 24];
                label[..4].copy_from_slice(b"sec:");
                label[4..4 + key.len()].copy_from_slice(key);
                encoder.map(2)?;
                encoder.text_value(b"key")?;
                encoder.text_value(&label[..4 + key.len()])?;
                // Keep a secret's key name useful for diagnostics without
                // exposing any secret value.
                encoder.text_value(b"value")?;
                encoder.text_value(b"<redacted>")?;
            }
        }
        _ => encoder.map(0)?,
    }
    let used = encoder.len();
    drop(encoder);
    tagged::encode_numeric_response(control::CONTROL_COMPONENT, method, id, &result[..used], out)
}

/// Serve the bounded `discovery.nodes` inventory on a correlated QUIC stream.
/// Every bearer which carries QUIC reaches this handler through the shared
/// tagged registry. Compact direct records remain a diagnostic form; they do
/// not define a separate UART or radio-specific discovery API.
///
/// The inventory contains receiver-local observation facts only.  It neither
/// starts a scan nor touches a radio callback, so serving it on a stream does
/// not add a new wakeup or packet queue on ESP Main.
pub(crate) fn receive_tagged_discovery_nodes(
    record: dmesh_server::tagged::Record<'_>,
) -> Option<alloc::vec::Vec<u8>> {
    let id = record.id?;
    if record.to.is_some()
        || record.component
            != Some(dmesh_server::tagged::Name::Tag(
                dmesh_server::announce::ANNOUNCE_COMPONENT,
            ))
        || record.method
            != Some(dmesh_server::tagged::Name::Tag(
                dmesh_server::announce::ANNOUNCE_DEVICES_OBSERVED,
            ))
    {
        return None;
    }

    let mut snapshots = [None; crate::wifi_nan_dw_capture_esp::NAN_DEVICE_OBSERVATION_CAPACITY];
    crate::wifi_nan_dw_capture_esp::nan_device_observations(&mut snapshots);
    let mut entries = [dmesh_server::announce::ObservedDevice {
        device_id: &[],
        peer: [0; 6],
        bssid: None,
        channel: None,
        available_fields: 0,
        first_seen_ms: 0,
        last_seen_ms: 0,
        packets: 0,
        active_publish_rx: 0,
        active_subscribe_rx: 0,
        followup_rx: 0,
        last_kind: 0,
        last_payload_len: 0,
        last_payload_hash: 0,
    }; crate::wifi_nan_dw_capture_esp::NAN_DEVICE_OBSERVATION_CAPACITY];
    let mut count = 0;
    for snapshot in snapshots.iter().flatten() {
        entries[count] = dmesh_server::announce::ObservedDevice {
            device_id: &[],
            peer: snapshot.peer,
            bssid: (snapshot.bssid != [0; 6]).then_some(snapshot.bssid),
            channel: (1..=13)
                .contains(&snapshot.last_channel)
                .then_some(snapshot.last_channel),
            available_fields: dmesh_server::discovery::OBSERVATION_PEER
                | u32::from(snapshot.bssid != [0; 6]) * dmesh_server::discovery::OBSERVATION_BSSID
                | u32::from((1..=13).contains(&snapshot.last_channel))
                    * dmesh_server::discovery::OBSERVATION_CHANNEL
                | dmesh_server::discovery::OBSERVATION_PAYLOAD_FINGERPRINT,
            first_seen_ms: snapshot.first_seen_ms,
            last_seen_ms: snapshot.last_seen_ms,
            packets: snapshot.packets,
            active_publish_rx: snapshot.active_publish_rx,
            active_subscribe_rx: snapshot.active_subscribe_rx,
            followup_rx: snapshot.followup_rx,
            last_kind: snapshot.last_kind,
            last_payload_len: snapshot.last_payload_len,
            last_payload_hash: snapshot.last_payload_hash,
        };
        count += 1;
    }

    // Reuse the canonical compact discovery encoding and promote its result
    // body from the direct envelope into the correlated stream envelope.
    let mut direct = [0u8; crate::TRANSPORT_MTU];
    let direct_len =
        dmesh_server::announce::encode_devices_observed_response(&entries[..count], &mut direct)?;
    let result = dmesh_server::tagged::decode(&direct[..direct_len])?.fields?;
    let mut response = [0u8; crate::TRANSPORT_MTU];
    let response_len = dmesh_server::tagged::encode_numeric_response(
        dmesh_server::announce::ANNOUNCE_COMPONENT,
        dmesh_server::announce::ANNOUNCE_DEVICES_OBSERVED,
        id,
        result,
        &mut response,
    )?;
    Some(alloc::vec::Vec::from(&response[..response_len]))
}

/// Canonical discovery component handler. A directed active-discovery request
/// is a regular tagged operation first; its connectionless form only supplies
/// a small body to this same handler.
pub(crate) fn receive_tagged_discovery(
    record: dmesh_server::tagged::Record<'_>,
) -> Option<alloc::vec::Vec<u8>> {
    if record.component
        == Some(dmesh_server::tagged::Name::Tag(
            dmesh_server::announce::ANNOUNCE_COMPONENT,
        ))
        && record.method
            == Some(dmesh_server::tagged::Name::Tag(
                dmesh_server::announce::ANNOUNCE_DISCOVERY,
            ))
    {
        return tagged_discovery_response(record);
    }
    receive_tagged_discovery_nodes(record)
}

fn tagged_discovery_response(
    record: dmesh_server::tagged::Record<'_>,
) -> Option<alloc::vec::Vec<u8>> {
    if record.to.is_some() {
        return None;
    }
    let id = record.id?;
    // Reject an unsolicited signed announce that happens to share the method
    // tag: only the bounded directed-request form may invoke this handler.
    let mut request = [0u8; 96];
    let used = dmesh_server::announce::encode_discovery_request(id, &mut request)?;
    if dmesh_server::tagged::decode(&request[..used])?.fields != record.fields {
        return None;
    }
    let (announce, announce_len) =
        announce_record(dmesh_server::announce::ANNOUNCE_DISCOVERY, 0, 0, 0)?;
    let announce = dmesh_server::announce::decode_announce(&announce[..announce_len])?;
    let mut response = [0u8; dmesh_rawnan::NAN_ACTIVE_PUBLISH_MAX_LEN];
    let used = dmesh_server::announce::encode_discovery_response(announce, id, &mut response)?;
    Some(alloc::vec::Vec::from(&response[..used]))
}

/// Consume a copied NAN Service Discovery payload. The Wi-Fi callback has
/// already released its driver buffer before this worker runs. An accepted
/// `transport.set` therefore commits one profile and queues Main work; it
/// never performs Wi-Fi teardown/restart from the capture callback.
pub(crate) fn receive_nan_service_info(peer: [u8; 6], packet: &[u8]) {
    if let Some(announce) = dmesh_server::announce::decode_announce(packet) {
        crate::wifi_raw_udp6_esp::record_connectionless_announce(announce, peer);
        return;
    }
    // NAN carries the same direct allowlist as every other bearer. The
    // bearer-specific closure only selects the Follow-up return path.
    if receive_direct_request(packet, |response| {
        // This callback is itself the accepted NAN Service Info ingress. A
        // common control response belongs to that source peer even if a
        // later repeated Android Subscribe raced the one-slot marker. Clear
        // the marker when it still matches, but never fall back to NOW for a
        // NAN request merely because that advisory marker was overwritten.
        if let Some((instance, requestor_instance)) =
            crate::wifi_nan_dw_capture_esp::take_active_subscribe(peer)
        {
            let _ = crate::wifi_nan_dw_capture_esp::send_followup_response(
                peer,
                instance,
                requestor_instance,
                response,
            );
        }
    }) {
        return;
    }
    crate::commands::send_stat(
        b"nan direct rejected peer=",
        u64::from_le_bytes([peer[0], peer[1], peer[2], peer[3], peer[4], peer[5], 0, 0]),
    );
}

/// Apply the one bootstrap-safe mutable direct record and emit at most one
/// copied response through the caller-selected bearer. Discovery itself uses
/// the signed `announce.discovery` request/reply record; every other handler
/// remains on a normal QUIC stream.
pub(crate) fn receive_direct_transport_set_record<F>(packet: &[u8], send_response: F) -> bool
where
    F: FnOnce(&[u8]),
{
    if dmesh_server::direct::classify(packet)
        != Some(dmesh_server::direct::DirectMessageKind::TransportSet)
    {
        return false;
    }
    let Some(record) = dmesh_server::tagged::decode(packet) else {
        return false;
    };
    // Direct is only a short request/response transport form.  It invokes
    // this exact canonical tagged handler used by a normal QUIC stream;
    // QUIC-lite provides the framing/correlation around its payload.
    let Some(response) = receive_tagged_control(record) else {
        return false;
    };
    crate::state::direct_record_accepted();
    send_response(&response);
    true
}

/// Dispatch the complete shared direct-request allowlist without knowledge of
/// its bearer. Presence records are consumed by discovery observation; the
/// only request forms here are directed discovery and `transport.set`.
pub(crate) fn receive_direct_request<F>(packet: &[u8], send_response: F) -> bool
where
    F: FnOnce(&[u8]),
{
    match dmesh_server::direct::classify(packet) {
        Some(dmesh_server::direct::DirectMessageKind::DiscoveryRequest) => {
            let Some(record) = dmesh_server::tagged::decode(packet) else {
                return false;
            };
            let Some(response) = receive_tagged_discovery(record) else {
                return false;
            };
            crate::state::direct_record_accepted();
            send_response(&response);
            true
        }
        Some(dmesh_server::direct::DirectMessageKind::TransportSet) => {
            receive_direct_transport_set_record(packet, send_response)
        }
        _ => false,
    }
}

/// Stream projection of the bounded telemetry snapshot.
fn encode_telemetry_response_record(
    record: dmesh_server::tagged::Record<'_>,
    out: &mut [u8],
) -> Option<usize> {
    use dmesh_server::telemetry as t;

    let (method, id) = t::decode_request_record(record)?;
    let snapshot = crate::wifi_radio_control_esp::snapshot();
    let counters = snapshot.counters;
    let mut result = [0u8; t::TELEMETRY_RESPONSE_MAX_BYTES];
    let used = match method {
        t::NAN_STATUS_METHOD => t::encode_nan_status(
            t::NanStatus {
                active: snapshot.nan_dw_interval.map(|_| true),
                cluster_id: snapshot.comparator_bssid.as_ref().map(|value| &value[..]),
                sync_id: None,
                publishing: None,
                publish_pending: None,
            },
            &mut result,
        )?,
        t::NOW_METRICS_METHOD => {
            let (last_roc_body_prefix, last_roc_body_len) =
                crate::wifi_espnow_esp::last_roc_action_body();
            let (
                rx_invalid_drops,
                rx_busy_drops,
                rx_shared_ingress_drops,
                last_registered_body_prefix,
                last_registered_body_len,
            ) = crate::wifi_espnow_esp::receive_drop_diagnostics();
            t::encode_metrics(
                &[
                    t::Metric {
                        id: t::now_metric::TX_ATTEMPTED,
                        value: u64::from(counters.tx_attempted),
                    },
                    t::Metric {
                        id: t::now_metric::TX_ACCEPTED,
                        value: u64::from(counters.tx_driver_accepted),
                    },
                    t::Metric {
                        id: t::now_metric::TX_FAILED,
                        value: u64::from(counters.tx_driver_failed),
                    },
                    t::Metric {
                        id: t::now_metric::RX_DISPATCHED,
                        value: u64::from(counters.rx_driver_dispatch),
                    },
                    t::Metric {
                        id: t::now_metric::RX_ACCEPTED,
                        value: u64::from(counters.rx_parser_accepted),
                    },
                    t::Metric {
                        id: t::now_metric::RX_REJECTED,
                        value: u64::from(counters.rx_parser_rejected),
                    },
                    t::Metric {
                        id: t::now_metric::RX_SELF_ECHO,
                        value: u64::from(counters.rx_self_echo),
                    },
                    t::Metric {
                        id: t::now_metric::RX_DROPPED,
                        value: u64::from(counters.rx_dropped),
                    },
                    t::Metric {
                        id: t::now_metric::REGISTERED_ACTIONS,
                        value: u64::from(counters.registered_now_actions),
                    },
                    t::Metric {
                        id: t::now_metric::REGISTERED_DROPS,
                        value: u64::from(counters.registered_action_drops),
                    },
                    t::Metric {
                        id: t::now_metric::LAST_ROC_BODY_PREFIX,
                        value: u64::from(last_roc_body_prefix),
                    },
                    t::Metric {
                        id: t::now_metric::LAST_ROC_BODY_LEN,
                        value: u64::from(last_roc_body_len),
                    },
                    t::Metric {
                        id: t::now_metric::RX_INVALID_DROPS,
                        value: u64::from(rx_invalid_drops),
                    },
                    t::Metric {
                        id: t::now_metric::RX_BUSY_DROPS,
                        value: u64::from(rx_busy_drops),
                    },
                    t::Metric {
                        id: t::now_metric::RX_SHARED_INGRESS_DROPS,
                        value: u64::from(rx_shared_ingress_drops),
                    },
                    t::Metric {
                        id: t::now_metric::LAST_REGISTERED_BODY_PREFIX,
                        value: u64::from(last_registered_body_prefix),
                    },
                    t::Metric {
                        id: t::now_metric::LAST_REGISTERED_BODY_LEN,
                        value: u64::from(last_registered_body_len),
                    },
                ],
                &mut result,
            )?
        }
        t::NAN_METRICS_METHOD => t::encode_metrics(
            &[
                t::Metric {
                    id: t::nan_metric::BEACONS,
                    value: u64::from(counters.nan_beacons),
                },
                t::Metric {
                    id: t::nan_metric::SDFS,
                    value: u64::from(counters.nan_sdfs),
                },
                t::Metric {
                    id: t::nan_metric::FOLLOWUPS_RX,
                    value: u64::from(counters.nan_followups),
                },
                t::Metric {
                    id: t::nan_metric::FOLLOWUPS_QUEUED,
                    value: u64::from(counters.nan_followup_queued),
                },
                t::Metric {
                    id: t::nan_metric::FOLLOWUPS_SENT,
                    value: u64::from(counters.nan_followup_sent),
                },
                t::Metric {
                    id: t::nan_metric::FOLLOWUPS_DROPPED,
                    value: u64::from(counters.nan_followup_dropped),
                },
                t::Metric {
                    id: t::nan_metric::SERVICE_INFO_MATCHED,
                    value: u64::from(counters.nan_service_info_matched),
                },
                t::Metric {
                    id: t::nan_metric::SERVICE_INFO_ENQUEUED,
                    value: u64::from(counters.nan_service_info_enqueued),
                },
                t::Metric {
                    id: t::nan_metric::SERVICE_INFO_DROPPED,
                    value: u64::from(counters.nan_service_info_dropped),
                },
                t::Metric {
                    id: t::nan_metric::SERVICE_INFO_DISPATCHED,
                    value: u64::from(counters.nan_service_info_dispatched),
                },
                t::Metric {
                    id: t::nan_metric::ACTIVE_PUBLISH_ATTEMPTED,
                    value: u64::from(counters.nan_active_publish_attempted),
                },
                t::Metric {
                    id: t::nan_metric::ACTIVE_PUBLISH_SENT,
                    value: u64::from(counters.nan_active_publish_sent),
                },
                t::Metric {
                    id: t::nan_metric::ACTIVE_PUBLISH_DROPPED,
                    value: u64::from(counters.nan_active_publish_dropped),
                },
            ],
            &mut result,
        )?,
        t::UDP6_METRICS_METHOD => t::encode_metrics(
            &[
                t::Metric {
                    id: t::udp6_metric::RX_FRAMES,
                    value: u64::from(counters.udp6_rx_frames),
                },
                t::Metric {
                    id: t::udp6_metric::RX_QUEUE_DROPS,
                    value: u64::from(counters.udp6_rx_queue_drops),
                },
                t::Metric {
                    id: t::udp6_metric::RX_INVALID,
                    value: u64::from(counters.udp6_rx_invalid),
                },
                t::Metric {
                    id: t::udp6_metric::UDP_DELIVERED,
                    value: u64::from(counters.udp6_udp_delivered),
                },
                t::Metric {
                    id: t::udp6_metric::NDP_ADVERTISEMENTS,
                    value: u64::from(counters.udp6_ndp_advertisements),
                },
                t::Metric {
                    id: t::udp6_metric::TX_FAILURES,
                    value: u64::from(counters.udp6_tx_failures),
                },
                t::Metric {
                    id: t::udp6_metric::RAW_TX_COMPLETIONS,
                    value: u64::from(counters.udp6_raw_tx_completions),
                },
                t::Metric {
                    id: t::udp6_metric::RAW_TX_COMPLETION_FAILURES,
                    value: u64::from(counters.udp6_raw_tx_completion_failures),
                },
            ],
            &mut result,
        )?,
        t::WIFI_LINK_METRICS_METHOD => {
            t::encode_wifi_link_metrics(snapshot.link_metrics(), &mut result)?
        }
        _ => return None,
    };
    dmesh_server::tagged::encode_numeric_response(
        t::TELEMETRY_COMPONENT,
        method,
        id,
        &result[..used],
        out,
    )
}

pub(crate) fn receive_tagged_telemetry(
    record: dmesh_server::tagged::Record<'_>,
) -> Option<alloc::vec::Vec<u8>> {
    let mut response = [0u8; dmesh_server::telemetry::TELEMETRY_RESPONSE_MAX_BYTES + 32];
    let used = encode_telemetry_response_record(record, &mut response)?;
    Some(alloc::vec::Vec::from(&response[..used]))
}

/// Serve raw-Wi-Fi lab and injection operations through the normal tagged
/// stream registry. These operations deliberately have no direct fallback.
pub(crate) fn receive_tagged_raw_wifi(
    record: dmesh_server::tagged::Record<'_>,
) -> Option<alloc::vec::Vec<u8>> {
    use dmesh_server::raw_wifi as wifi;

    let id = record.id?;
    if record.to.is_some()
        || record.component != Some(dmesh_server::tagged::Name::Tag(wifi::RAW_WIFI_COMPONENT))
    {
        return None;
    }
    let method = match record.method? {
        dmesh_server::tagged::Name::Tag(method) => method,
        _ => return None,
    };
    let mut result = [0u8; wifi::RAW_WIFI_RESPONSE_MAX_BYTES];
    let result_used = if method == wifi::RAW_WIFI_METHOD_TX {
        match wifi::decode_raw_wifi_tx_record(record)
            .and_then(crate::wifi_radio_inject_esp::transmit_raw_action)
        {
            Ok(bytes) => {
                let mut encoder = dmesh_server::cbor::Encoder::new(&mut result);
                encoder
                    .text_value(alloc::format!("radio raw action sent bytes={bytes}").as_bytes())?;
                encoder.len()
            }
            Err(error) => {
                return dmesh_server::tagged::encode_numeric_error(
                    wifi::RAW_WIFI_COMPONENT,
                    method,
                    id,
                    error.as_bytes(),
                    &mut result,
                )
                .map(|used| alloc::vec::Vec::from(&result[..used]));
            }
        }
    } else {
        match wifi::decode_raw_wifi_handler_record(record)
            .and_then(|request| crate::wifi_radio_control_esp::handle_encoded(request, &mut result))
        {
            Ok(used) => used,
            Err(error) => {
                return dmesh_server::tagged::encode_numeric_error(
                    wifi::RAW_WIFI_COMPONENT,
                    method,
                    id,
                    error.as_bytes(),
                    &mut result,
                )
                .map(|used| alloc::vec::Vec::from(&result[..used]));
            }
        }
    };
    let mut response = [0u8; wifi::RAW_WIFI_RESPONSE_MAX_BYTES + 32];
    let used = dmesh_server::tagged::encode_numeric_response(
        wifi::RAW_WIFI_COMPONENT,
        method,
        id,
        &result[..result_used],
        &mut response,
    )?;
    Some(alloc::vec::Vec::from(&response[..used]))
}

/// Handle one unmarked UART frame after the adapter has copied it unchanged.
/// The shared direct endpoint owns long-header parsing and response framing,
/// so UART has the same direct allowlist as NOW and UDP6. All application
/// operations, including telemetry and raw-Wi-Fi, use normal QUIC streams.
pub(crate) fn receive_uart_raw_ingress(
    _item: crate::shared_ingress_esp::IngressPacket,
    packet: &[u8],
) {
    // This worker is the single UART raw ingress owner, so a fixed response
    // scratch does not add a bearer queue. The physical adapter sees only
    // complete PPP fields; `ConnectionlessMessage` retains the envelope.
    static mut RESPONSE: [u8; crate::TRANSPORT_MTU] = [0; crate::TRANSPORT_MTU];
    let response_scratch = unsafe {
        // `addr_of_mut!` avoids manufacturing a mutable reference to the
        // static. The UART raw worker is its sole owner, as documented above.
        &mut *core::ptr::addr_of_mut!(RESPONSE)
    };
    let disposition = dmesh_server::direct::ConnectionlessMessage::receive(
        packet,
        response_scratch,
        |payload, response| {
            if let Some(announce) = dmesh_server::announce::decode_announce(payload) {
                crate::wifi_raw_udp6_esp::record_connectionless_announce(announce, [0; 6]);
                return dmesh_server::direct::ConnectionlessDisposition::Handled;
            }
            let mut response_len = 0;
            if receive_direct_request(payload, |record| {
                if record.len() <= response.len() {
                    response[..record.len()].copy_from_slice(record);
                    response_len = record.len();
                }
            }) {
                if response_len == 0 {
                    dmesh_server::direct::ConnectionlessDisposition::Handled
                } else {
                    dmesh_server::direct::ConnectionlessDisposition::Response(response_len)
                }
            } else {
                dmesh_server::direct::ConnectionlessDisposition::NotHandled
            }
        },
    );
    if let dmesh_server::direct::ConnectionlessDisposition::Response(used) = disposition {
        let response_scratch = unsafe { &*core::ptr::addr_of!(RESPONSE) };
        let _ = crate::uart_esp::send_connectionless_packet(&response_scratch[..used]);
    }
}

/// Fixed boot identity and lifecycle callback owned by Main. It is created
/// once from `fw/main`; Core has no role selector or product policy branch.
pub(crate) struct MainRuntimeService {
    pub(crate) role: u8,
    pub(crate) partition: u8,
    pub(crate) boot_message: &'static [u8],
    pub(crate) mark_healthy: fn(),
}

/// The sole mutable owner of Main's event-driven runtime.
///
/// Constructed once after boot bring-up and retained by the FreeRTOS Main task
/// for its lifetime. Adapter callbacks never receive this object: they put a
/// compact event on the bounded queue, and this owner applies all driver and
/// power effects after the blocking receive returns.
struct MainCoordinator {
    service: MainRuntimeService,
    radio: MainRadioState,
    runtime_state: dmesh_server::main_runtime_state::MainRuntimeState,
    soft_sleep: bool,
}

/// Immutable facts derived from one dequeued Main event.
///
/// Produced once by `prepare_event` after any adapter completion has been
/// recorded. Carrying a copied complete profile prevents later code in the
/// event turn from re-reading mutable profile storage or inferring why it was
/// woken.
struct MainEventWork {
    profile: crate::TransportProfile,
    generation: u32,
    now_ms: u64,
    profile_changed: bool,
}

impl MainCoordinator {
    /// Block until a queued profile/callback event or an armed one-shot
    /// deadline is due. This is the coordinator's only loop wake source.
    fn next_event(&self) -> MainRuntimeEvent {
        self.service.next_event(
            self.radio.transition_announced_generation,
            (self.radio.sleepy_awake_until_ms != 0).then_some(self.radio.sleepy_awake_until_ms),
        )
    }

    /// Classify and service the non-policy portion of one queued event.
    /// Called immediately after the blocking receive, exactly once per owner
    /// turn. A deadline names only its due adapters; it is never a general
    /// polling pass. STA reconnect is similarly one explicit effect of a
    /// disconnected callback, not an observer retry.
    fn prepare_event(&mut self, event: MainRuntimeEvent) -> MainEventWork {
        let deadline_services = match event {
            MainRuntimeEvent::Deadline { services }
            | MainRuntimeEvent::AdapterComplete { services } => services,
            MainRuntimeEvent::ProfileChanged { .. } => 0,
        };
        let sta_lifecycle_completion = deadline_services & DEADLINE_STA_LIFECYCLE != 0;
        if sta_lifecycle_completion {
            self.radio.sta_associated = crate::wifi_esp::sta_associated();
        }
        if deadline_services != 0 {
            service_radio_deadline(deadline_services);
        }
        let now_ms = (unsafe { esp_idf_sys::esp_timer_get_time() }.max(0) as u64) / 1_000;
        let profile = crate::core_runtime::transport_profile_snapshot();
        let generation = match event {
            MainRuntimeEvent::Deadline { .. } | MainRuntimeEvent::AdapterComplete { .. } => {
                self.radio.transition_announced_generation
            }
            MainRuntimeEvent::ProfileChanged { generation } => generation,
        };
        if sta_lifecycle_completion
            && self.radio.wifi_started
            && wants_sta(&profile)
            && !self.radio.sta_associated
        {
            self.radio.sta_retry_pending = true;
        }
        let periodic_due = (self.radio.nan_now_started || self.radio.wifi_started)
            && now_ms.saturating_sub(self.radio.last_discovery_announce_ms)
                >= ACTIVE_DISCOVERY_INTERVAL_MS;
        if periodic_due && self.radio.sta_retry_pending {
            // Start the scan-first retry before announcing: the association
            // outcome may change what the next announce can truthfully say.
            self.radio.sta_retry_due = true;
        } else if periodic_due {
            let _ = maybe_send_periodic_discovery(
                now_ms,
                self.radio.nan_now_started,
                self.radio.nan_now_started && profile.now != 2,
                self.radio.wifi_started,
                &mut self.radio.last_discovery_announce_ms,
            );
        }
        MainEventWork {
            profile,
            generation,
            now_ms,
            profile_changed: matches!(event, MainRuntimeEvent::ProfileChanged { .. }),
        }
    }

    /// Commit the requested-profile half of one classified event.
    /// Called after `prepare_event` and before any radio transition. Only a
    /// `ProfileChanged` record can reconfigure PM or advance the portable
    /// desired state; deadline completions can merely finish/retry the already
    /// committed generation. The return value says whether the radio effect is
    /// still pending for this event.
    fn reduce_profile_request(&mut self, work: &MainEventWork) -> bool {
        let effect = if work.profile_changed {
            self.runtime_state.reduce(
                dmesh_server::main_runtime_state::MainEvent::ProfileRequested {
                    mode: requested_mode(&work.profile),
                    sleepy: is_sleepy_profile(&work.profile),
                    generation: work.generation,
                    request_id: 0,
                },
            )
        } else {
            dmesh_server::main_runtime_state::MainEffect::None
        };
        if work.profile_changed {
            // Keep automatic idle sleep enabled on the C6 canary. Classic
            // ESP32 remains on the narrow DW8-only policy while its PM path
            // is diagnosed independently.
            #[cfg(target_arch = "riscv32")]
            let _ = crate::power_esp::configure(true);
            #[cfg(not(target_arch = "riscv32"))]
            let _ = crate::power_esp::configure(is_sleepy_profile(&work.profile));
            if is_sleepy_profile(&work.profile) {
                // Arm a single deadline after the radio transition settles.
                // Without this, a volatile DW8 request has no subsequent
                // Main-owner wake on which to evaluate explicit light sleep.
                self.radio.sleepy_awake_until_ms = work.now_ms.saturating_add(5_000);
                crate::commands::send_response(b"sleep DW8 armed: command window 5000ms");
            }
            record_power_completion(&mut self.runtime_state);
        }
        self.runtime_state
            .record_queue_overflow(take_event_queue_drops());
        matches!(
            effect,
            dmesh_server::main_runtime_state::MainEffect::ApplyRadio { generation, .. }
                if generation == work.generation
        ) || work.generation != self.radio.transition_announced_generation
    }
}

impl MainRuntimeService {
    pub(crate) const fn new(
        role: u8,
        partition: u8,
        boot_message: &'static [u8],
        mark_healthy: fn(),
    ) -> Self {
        Self {
            role,
            partition,
            boot_message,
            mark_healthy,
        }
    }

    /// Wait for ingress, the next radio deadline, or Main's explicit sleepy
    /// command-window expiry. Called once per worker turn; this blocks in
    /// FreeRTOS and does not spin the CPU or run an idle reconciliation tick.
    pub(crate) fn next_event(
        &self,
        last_generation: u32,
        sleep_deadline_ms: Option<u64>,
    ) -> MainRuntimeEvent {
        wait_for_event(last_generation, sleep_deadline_ms)
    }

    pub(crate) fn run(self) {
        run_main_service(self);
    }
}

/// Boot and register Main's one event-driven coordinator.
///
/// This function performs bounded one-time setup only. Once it creates the
/// coordinator, all profile, callback, timer, radio, and sleep effects are
/// serialized by its FreeRTOS event owner.
pub(crate) fn run_main_service(service: MainRuntimeService) {
    // ROM UART markers are intentionally limited to early boot diagnosis.
    // They run before Main owns the UART driver, so a reset before the normal
    // tagged boot record still identifies the last completed initializer.
    unsafe { esp_idf_sys::esp_rom_printf(b"DMESH main: link\n\0".as_ptr().cast()) };
    esp_idf_sys::link_patches();
    // Establish persistent identity before any bearer starts. A later
    // announce merely loads and uses this committed binary key; it never
    // generates a transport-specific identity.
    if load_or_create_identity_private_key().is_none() {
        unsafe { esp_idf_sys::esp_rom_printf(b"DMESH main: identity failed\n\0".as_ptr().cast()) };
    } else {
        unsafe { esp_idf_sys::esp_rom_printf(b"DMESH main: identity\n\0".as_ptr().cast()) };
    }
    // Main's single event owner handles explicit STA lifecycle callbacks.
    if !crate::main_runtime::initialize_event_queue() {
        unsafe {
            esp_idf_sys::esp_rom_printf(b"DMESH main: event-queue failed\n\0".as_ptr().cast())
        };
        return;
    }
    unsafe { esp_idf_sys::esp_rom_printf(b"DMESH main: event-queue\n\0".as_ptr().cast()) };
    // The initial profile uses the default 115200 selector. USB-JTAG targets
    // ignore this value; classic UART targets configure the mapped baud here.
    if !unsafe { crate::uart_esp::install_l2_driver(1) } {
        unsafe {
            esp_idf_sys::esp_rom_printf(b"DMESH main: uart-install failed\n\0".as_ptr().cast())
        };
        return;
    }
    unsafe { esp_idf_sys::esp_rom_printf(b"DMESH main: uart-install\n\0".as_ptr().cast()) };
    // A complete private NVS profile is the only boot-time STA authority.
    // In its absence Main retains the ordinary NAN/NOW startup and accepts a
    // later volatile transport.start command.
    let boot_power_policy = crate::main_runtime::boot_power_policy_from_nvs();
    let sleepy_boot = service.role == 1 && boot_power_policy.sleepy;
    // PM is selected once from the boot policy, before the Wi-Fi owner starts.
    // Failure is observable through the runtime power state but must not turn
    // a boot into a radio busy-loop or prevent recovery through USB-JTAG.
    #[cfg(target_arch = "riscv32")]
    let _ = crate::power_esp::configure(true);
    #[cfg(not(target_arch = "riscv32"))]
    let _ = crate::power_esp::configure(sleepy_boot);
    unsafe { esp_idf_sys::esp_rom_printf(b"DMESH main: power\n\0".as_ptr().cast()) };
    crate::profile_store::with_profile(|params| {
        params.command_mode = service.role == 2 || !sleepy_boot;
        if sleepy_boot {
            params.requested_transport = Some(dmesh_server::control::TransportKind::Nan);
            params.nan_dw_interval = 8;
            params.now = 2;
            params.ap = 0;
            // UART is an explicit profile choice, not a sleepy-boot or
            // light-sleep prerequisite.  Preserve the configured/default
            // value so a DW8 node remains diagnosable unless its operator
            // explicitly selected `uart=off`.
        } else if service.role == 1 && !crate::main_runtime::apply_sta_profile_from_nvs(params) {
            // Main's active default is NAN+NOW only. An AP is an explicit
            // transport.start personality, not an unconditional boot side
            // effect: enabling its beacon/DTIM workload beside NAN can brown
            // out a USB-powered LoRa board before a controller can choose a
            // needed AP/STA row. DW1 keeps directed NAN control reachable.
            // Record the same NAN epoch in the requested profile as the
            // physical `init_nan_now` call below. Without this assignment,
            // an otherwise identical first transport.start looks like a
            // None-to-NAN transition and needlessly tears down the just
            // initialized Wi-Fi driver.
            params.requested_transport = Some(dmesh_server::control::TransportKind::Nan);
            // `init_nan_now` resolves an unset channel to six. Preserve that
            // resolved value in the desired profile as well, because control
            // planes correctly send the explicit channel in a NAN+NOW start.
            // Likewise, this is already a running Main radio epoch rather
            // than a merely prepared profile. These normalizations make the
            // first equivalent declaration idempotent instead of scheduling
            // an unnecessary driver replacement.
            params.sta_channel = 6;
            params.run_requested = true;
            params.nan_dw_interval = 1;
            params.ap = 0;
        }
    });
    if service.role == 1 && !sleepy_boot {
        // The coordinator blocks for an ingress or timer event after setup.
        // Therefore the active boot profile must arm the physical UART before
        // creating its reader: otherwise the first UART command is the event
        // needed to enable UART, which is an unreachable bootstrap state.
        crate::core_runtime::apply_uart_profile(true);
    }
    if !unsafe {
        crate::uart_esp::start_shared_l2(
            crate::core_runtime::receive_uart_ingress,
            crate::main_runtime::receive_uart_raw_ingress,
        )
    } {
        unsafe {
            esp_idf_sys::esp_rom_printf(b"DMESH main: uart-start failed\n\0".as_ptr().cast())
        };
        return;
    }
    // The writer reports only a capacity edge; the shared ingress worker
    // remains the one owner of QUIC-lite state and decides whether another
    // UART packet is ready. This preserves the one-record classic-ESP32
    // egress budget without a periodic poll or a private bulk queue.
    crate::uart_esp::set_egress_notify(Some(crate::core_runtime::schedule_uart_egress_ready));
    unsafe { esp_idf_sys::esp_rom_printf(b"DMESH main: uart-start\n\0".as_ptr().cast()) };
    // Register once before any bearer accepts traffic. The handler table is
    // fixed-size and shared by UDP6/QUIC and NOW action adapters; no per-bearer
    // command implementation or queue is created here.
    let _ = dmesh_server::services::register_tagged_component(
        dmesh_server::control::CONTROL_COMPONENT,
        crate::main_runtime::receive_tagged_control,
    );
    // `discovery.nodes` is the bounded production inventory read used by a
    // relay controller to select its next hop.  The compact direct form is
    // retained for UART/NAN/NOW diagnostics only; normal administration uses
    // this correlated QUIC-stream handler.
    let _ = dmesh_server::services::register_tagged_component(
        dmesh_server::announce::ANNOUNCE_COMPONENT,
        crate::main_runtime::receive_tagged_discovery,
    );
    let _ = dmesh_server::services::register_tagged_component(
        dmesh_server::telemetry::TELEMETRY_COMPONENT,
        crate::main_runtime::receive_tagged_telemetry,
    );
    let _ = dmesh_server::services::register_tagged_component(
        dmesh_server::raw_wifi::RAW_WIFI_COMPONENT,
        crate::main_runtime::receive_tagged_raw_wifi,
    );
    let _ = dmesh_server::services::register_tagged_component(
        crate::main_runtime::RUNTIME_COMPONENT,
        crate::main_runtime::receive_tagged_snapshot,
    );
    let _ = dmesh_server::services::register_tagged_component(
        crate::main_runtime::POWER_COMPONENT,
        crate::main_runtime::receive_tagged_power_snapshot,
    );
    let _ = dmesh_server::services::register_tagged_component(
        crate::main_runtime::MEMORY_COMPONENT,
        crate::main_runtime::receive_tagged_memory_snapshot,
    );
    // Relay desired state is administered only on an authenticated QUIC
    // stream. Connection setup remains an Initial long-header operation, not relay control.
    let _ = dmesh_server::services::register_tagged_component(
        dmesh_server::relay::RELAY_COMPONENT,
        crate::relay_main::receive_tagged_relay,
    );
    crate::wifi_nan_dw_capture_esp::set_service_info_handler(Some(
        crate::main_runtime::receive_nan_service_info,
    ));
    // The ROC callback only wakes this owner after ESP-IDF releases the
    // request slot; Main then resumes the deferred NAN deadline service.
    crate::wifi_nonpromisc_probe_esp::set_completion_handler(Some(
        crate::main_runtime::receive_roc_completion,
    ));
    crate::wifi_esp::set_sta_lifecycle_handler(Some(crate::main_runtime::receive_sta_lifecycle));
    // The UART driver and common direct-control receiver are live before the
    // boot proof is emitted. Main uses this point to clear the Stage2
    // boot-failure marker; Recovery deliberately supplies a no-op callback.
    (service.mark_healthy)();
    crate::commands::send_response(service.boot_message);
    crate::main_runtime::send_startup_discovery_uart(service.role, service.partition);
    // A valid NVS profile begins the Main STA canary directly; otherwise Main
    // starts its active unassociated AP+NAN+NOW epoch with DW1.
    let initial_profile = crate::core_runtime::transport_profile_snapshot();
    let mut state = crate::main_runtime::MainRadioState::new(
        sleepy_boot,
        crate::profile_store::generation(),
        (unsafe { esp_idf_sys::esp_timer_get_time() }.max(0) as u64) / 1_000,
    );
    // The control UART is available for the boot proof above.  Afterwards it
    // follows the requested profile exactly, including an explicit `uart=off`
    // on a sleepy boot; DW8 itself never silently changes this choice.
    crate::main_runtime::apply_uart_profile(
        service.role,
        &initial_profile,
        &mut state.applied_uart,
    );
    if crate::main_runtime::wants_sta(&initial_profile) {
        // NVS only supplies the boot declaration. Apply it through the same
        // complete STA epoch path used by an accepted `transport.start`, so
        // the driver setup and Main's applied-state markers cannot diverge.
        crate::main_runtime::start_sta_epoch(
            &initial_profile,
            crate::profile_store::generation(),
            &mut state,
        );
    } else {
        crate::core_runtime::prepare_espnow_association(&initial_profile);
        state.nan_now_started = crate::wifi_esp::init_nan_now(
            &initial_profile,
            crate::core_runtime::receive_main_espnow,
        );
    }
    if state.nan_now_started {
        crate::wifi_espnow_esp::set_poll_handler(Some(crate::core_runtime::poll_espnow));
        crate::main_runtime::send_startup_records_on_now(
            service.boot_message,
            service.role,
            service.partition,
        );
    }
    let soft_sleep = sleepy_boot && boot_power_policy.soft_sleep;
    // This state is owned only by this task. Ingress paths enqueue profile
    // generations; they never borrow or mutate it directly.
    let mut runtime_state = dmesh_server::main_runtime_state::MainRuntimeState::default();
    let _ = runtime_state.reduce(dmesh_server::main_runtime_state::MainEvent::Boot);
    // Record the actual requested boot personality before the first timer
    // event can consider a sleep boundary.
    let _ = runtime_state.reduce(dmesh_server::main_runtime_state::MainEvent::BootProfile {
        mode: crate::main_runtime::requested_mode(&initial_profile),
        sleepy: sleepy_boot,
    });
    crate::main_runtime::record_power_completion(&mut runtime_state);
    // Boot has just completed the only synchronous radio effect. Project its
    // observed result now, rather than leaving a status client to infer a
    // live NAN/NOW epoch from the requested boot profile alone.
    let _ = runtime_state.reduce(dmesh_server::main_runtime_state::MainEvent::RadioApplied {
        generation: crate::profile_store::generation(),
        lifecycle: crate::main_runtime::applied_lifecycle(
            &initial_profile,
            state.wifi_started,
            state.nan_now_started,
            state.sta_associated,
        ),
    });
    crate::main_runtime::publish_snapshot(runtime_state.snapshot());
    let mut coordinator = MainCoordinator {
        service,
        radio: state,
        runtime_state,
        soft_sleep,
    };
    loop {
        // This is a cooperative event/timer loop, not a busy spin. Callback
        // paths publish only atomics/bounded records; the owner blocks until
        // a profile transition or a one-shot NAN/ROC deadline arrives.
        let event = coordinator.next_event();
        let work = coordinator.prepare_event(event);
        let transition_pending = coordinator.reduce_profile_request(&work);
        // Borrow disjoint coordinator fields for the policy/effect portion of
        // this already-classified turn. This keeps the task ownership boundary
        // explicit while callbacks remain unable to touch mutable state.
        let service = &coordinator.service;
        let mut state = &mut coordinator.radio;
        let mut runtime_state = &mut coordinator.runtime_state;
        let soft_sleep = coordinator.soft_sleep;
        let now_ms = work.now_ms;
        let requested_sta_start_generation = work.generation;
        let snapshot = work.profile;
        if crate::main_runtime::apply_radio_transition(
            service.role,
            &snapshot,
            requested_sta_start_generation,
            now_ms,
            &mut state,
            transition_pending,
        ) {
            continue;
        }
        if crate::main_runtime::apply_sleep_boundary(
            service.role,
            &snapshot,
            requested_sta_start_generation,
            now_ms,
            soft_sleep,
            &mut state,
            &mut runtime_state,
        ) {
            continue;
        }
        let _ = runtime_state.reduce(dmesh_server::main_runtime_state::MainEvent::RadioApplied {
            generation: requested_sta_start_generation,
            lifecycle: crate::main_runtime::applied_lifecycle(
                &snapshot,
                state.wifi_started,
                state.nan_now_started,
                state.sta_associated,
            ),
        });
        crate::main_runtime::publish_snapshot(runtime_state.snapshot());
        if RESET_REQUESTED.swap(false, Ordering::AcqRel) {
            // Give the raw worker a bounded opportunity to transmit the
            // response it already produced before Main resets the chip.
            let ticks = ((250_u64 * u64::from(esp_idf_sys::configTICK_RATE_HZ))
                .div_ceil(1_000)
                .max(1)) as esp_idf_sys::TickType_t;
            unsafe { esp_idf_sys::vTaskDelay(ticks) };
            // A controlled remote reset must explicitly leave the AP before
            // ROM starts. Otherwise the AP can retain a stale STA entry until
            // its own inactivity timer, which makes the following STA test
            // look associated before this device has rejoined.
            crate::wifi_esp::stop_sta_for_reset();
            unsafe { esp_idf_sys::esp_restart() };
        }
        // Raw Ethernet owns its FreeRTOS ingress task and accepts
        // host-initiated QUIC-lite services. There is no legacy client
        // fallback: a profile only controls association and raw bearer
        // runtime settings.
    }
}

impl MainRadioState {
    /// Construct Main's initial unassociated epoch. Called exactly once after
    /// the boot profile has been applied and before any bearer can enqueue a
    /// profile replacement.
    pub(crate) fn new(sleepy_boot: bool, initial_generation: u32, now_ms: u64) -> Self {
        Self {
            nan_now_started: false,
            wifi_started: false,
            sta_associated: false,
            sta_retry_pending: false,
            sta_retry_due: false,
            applied_raw_tx_rate: None,
            applied_sta_driver_tx: None,
            applied_sta_bssid_check_disabled: None,
            applied_sta_ampdu_enabled: None,
            applied_sta_11b_rates_disabled: None,
            applied_sta_raw_rx_enabled: None,
            applied_ack_frequency: None,
            applied_ack_delay_ms: None,
            applied_tx_burst_packets: None,
            applied_sta_start_generation: 0,
            transition_announced_generation: 0,
            applied_nan_start_generation: initial_generation,
            sta_extensions_enabled: false,
            applied_nan_dw_interval: None,
            applied_uart: None,
            last_discovery_announce_ms: 0,
            // A light-sleep wake needs one whole command window before a new
            // sleep decision. At cold boot this uses the same five seconds.
            sleepy_awake_until_ms: if sleepy_boot {
                now_ms.saturating_add(5_000)
            } else {
                0
            },
        }
    }
}

/// Main's fixed identity passed to the platform runtime owner. Keeping it
/// here prevents a shared helper from selecting a product role at runtime.
pub struct MainRuntime {
    mark_healthy: fn(),
}

impl MainRuntime {
    pub const fn new(mark_healthy: fn()) -> Self {
        Self { mark_healthy }
    }

    /// Start the Main event owner. Called exactly once from `fw/main` after
    /// ESP-IDF has entered `app_main`; Recovery has its own entry point.
    pub fn run(self) {
        MainRuntimeService::new(1, 1, b"main core boot", self.mark_healthy).run();
    }
}

/// Start the active Main runtime and its Stage2 health callback.
pub fn run(mark_healthy: fn()) {
    MainRuntime::new(mark_healthy).run();
}
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicU32, AtomicUsize, Ordering};

use dmesh_server::main_runtime_state::MainRuntimeSnapshot;

/// Bearer-neutral component for one read-only Main runtime snapshot.
pub const RUNTIME_COMPONENT: u64 = 101;
pub const RUNTIME_SNAPSHOT: u64 = 1;
/// Schedule a controlled Main restart after the tagged response has left its
/// QUIC-lite association. This is not a modem-line reset.
pub const RUNTIME_RESET: u64 = 2;
/// Read-only ESP PM state. Separate from the portable runtime snapshot because
/// frequency/PM-lock details are platform measurements, not transport policy.
pub const POWER_COMPONENT: u64 = 102;
pub const POWER_SNAPSHOT: u64 = 1;
/// Read-only shared-ingress allocation and stack telemetry.  This is separate
/// from PM because it measures allocator headroom and the only packet worker,
/// not a requested power policy.
pub const MEMORY_COMPONENT: u64 = 103;
pub const MEMORY_SNAPSHOT: u64 = 1;

// A status handler may run on a bearer worker while Main owns its mutable
// state. Publish a copy through this seqlock instead of borrowing that state
// or taking the radio-owner lock from callback/ingress context.
static SNAPSHOT_SEQUENCE: AtomicU32 = AtomicU32::new(0);
static SNAPSHOT_WORDS: [AtomicU32; 22] = [const { AtomicU32::new(0) }; 22];
static RESET_REQUESTED: AtomicBool = AtomicBool::new(false);

fn snapshot_words(snapshot: MainRuntimeSnapshot) -> [u32; 22] {
    [
        u32::from(snapshot.desired_mode),
        snapshot.desired_generation,
        snapshot.request_id,
        u32::from(snapshot.sleepy),
        u32::from(snapshot.radio_lifecycle),
        snapshot.applied_generation,
        u32::from(snapshot.power_lifecycle),
        u32::from(snapshot.sleep_blockers),
        u32::from(snapshot.last_error),
        snapshot.stale_completion_count,
        snapshot.queue_overflow_count,
        u32::from(snapshot.wake_cause),
        u32::from(snapshot.cpu_mhz),
        u32::from(snapshot.pm_min_mhz),
        u32::from(snapshot.pm_max_mhz),
        u32::from(snapshot.pm_automatic_light_sleep),
        u32::from(snapshot.pm_configured),
        snapshot.light_sleep_attempts,
        snapshot.light_sleep_entries,
        snapshot.light_sleep_skipped,
        snapshot.last_sleep_requested_us,
        snapshot.last_sleep_duration_us,
    ]
}

fn snapshot_from_words(words: [u32; 22]) -> MainRuntimeSnapshot {
    MainRuntimeSnapshot {
        desired_mode: words[0] as u8,
        desired_generation: words[1],
        request_id: words[2],
        sleepy: words[3] != 0,
        radio_lifecycle: words[4] as u8,
        applied_generation: words[5],
        power_lifecycle: words[6] as u8,
        sleep_blockers: words[7] as u16,
        last_error: words[8] as u16,
        stale_completion_count: words[9],
        queue_overflow_count: words[10],
        wake_cause: words[11] as u8,
        cpu_mhz: words[12] as u16,
        pm_min_mhz: words[13] as u16,
        pm_max_mhz: words[14] as u16,
        pm_automatic_light_sleep: words[15] != 0,
        pm_configured: words[16] != 0,
        light_sleep_attempts: words[17],
        light_sleep_entries: words[18],
        light_sleep_skipped: words[19],
        last_sleep_requested_us: words[20],
        last_sleep_duration_us: words[21],
    }
}

/// Publish a complete, redacted status projection after Main handles an event.
/// Called only by the Main owner; readers retry if they observe an in-progress
/// write, so no raw profile credentials or mutable references escape.
pub(crate) fn publish_snapshot(snapshot: MainRuntimeSnapshot) {
    SNAPSHOT_SEQUENCE.fetch_add(1, Ordering::AcqRel);
    for (slot, value) in SNAPSHOT_WORDS.iter().zip(snapshot_words(snapshot)) {
        slot.store(value, Ordering::Relaxed);
    }
    SNAPSHOT_SEQUENCE.fetch_add(1, Ordering::Release);
}

/// Read one internally consistent runtime projection for a bounded status
/// response. Called by bearer workers; it does not wait on the Main task.
pub(crate) fn published_snapshot() -> MainRuntimeSnapshot {
    loop {
        let before = SNAPSHOT_SEQUENCE.load(Ordering::Acquire);
        if before & 1 != 0 {
            continue;
        }
        let mut words = [0; 22];
        for (slot, value) in SNAPSHOT_WORDS.iter().zip(words.iter_mut()) {
            *value = slot.load(Ordering::Relaxed);
        }
        if SNAPSHOT_SEQUENCE.load(Ordering::Acquire) == before {
            return snapshot_from_words(words);
        }
    }
}

/// Serve a correlated, bounded runtime snapshot over any tagged bearer.
/// Called by the generic tagged dispatcher, not by the Main owner. The
/// seqlock copy above is therefore the only cross-task boundary. Result keys
/// are stable numeric fields: `0..=2` desired mode/generation/request, `3`
/// sleepy, `4..=6` applied radio/generation/power, `7..=8` blockers/error,
/// `9..=11` are stale-completion, queue-overflow, and wake-cause counters;
/// `12..=16` are applied CPU/PM measurements and `17..=21` are explicit
/// light-sleep attempt/entry/skip/duration metrics. These are values observed
/// by the Main owner after a PM effect, not inferred policy requests.
pub(crate) fn receive_tagged_snapshot(
    record: dmesh_server::tagged::Record<'_>,
) -> Option<alloc::vec::Vec<u8>> {
    let id = record.id?;
    let dmesh_server::tagged::Name::Tag(method) = record.method? else {
        return None;
    };
    if method == RUNTIME_RESET {
        // The packet worker returns this acknowledgement before the Main
        // owner observes the marker and restarts the chip.
        RESET_REQUESTED.store(true, Ordering::Release);
        request_deadline_recheck();
        let mut response = [0u8; 96];
        let used = dmesh_server::tagged::encode_numeric_data_response(
            RUNTIME_COMPONENT,
            RUNTIME_RESET,
            id,
            b"reset scheduled",
            true,
            &mut response,
        )?;
        return Some(alloc::vec::Vec::from(&response[..used]));
    }
    if method != RUNTIME_SNAPSHOT {
        return None;
    }
    let snapshot = published_snapshot();
    let fields = snapshot_words(snapshot);
    let mut result = [0u8; 224];
    let mut encoder = dmesh_server::cbor::Encoder::new(&mut result);
    encoder.map(fields.len() as u64)?;
    for (index, value) in fields.iter().enumerate() {
        encoder.uint(index as u64)?;
        encoder.uint(u64::from(*value))?;
    }
    let used = encoder.len();
    drop(encoder);
    let mut response = [0u8; 288];
    let used = dmesh_server::tagged::encode_numeric_response(
        RUNTIME_COMPONENT,
        RUNTIME_SNAPSHOT,
        id,
        &result[..used],
        &mut response,
    )?;
    Some(alloc::vec::Vec::from(&response[..used]))
}

/// Serve Main's bounded ESP PM measurement over any tagged bearer. Called by
/// the generic dispatcher, never by the PM adapter or a timer callback.
pub(crate) fn receive_tagged_power_snapshot(
    record: dmesh_server::tagged::Record<'_>,
) -> Option<alloc::vec::Vec<u8>> {
    let id = record.id?;
    let dmesh_server::tagged::Name::Tag(method) = record.method? else {
        return None;
    };
    if method != POWER_SNAPSHOT {
        return None;
    }
    let power = crate::power_esp::status();
    let values = [
        u32::from(power.cpu_mhz),
        u32::from(power.min_mhz),
        u32::from(power.max_mhz),
        u32::from(power.automatic_light_sleep),
        u32::from(power.configured),
        power.light_sleep_attempts,
        power.light_sleep_entries,
        power.light_sleep_skipped,
        power.last_sleep_requested_us,
        power.last_sleep_duration_us,
    ];
    let mut result = [0u8; 96];
    let mut encoder = dmesh_server::cbor::Encoder::new(&mut result);
    encoder.map(values.len() as u64)?;
    for (index, value) in values.iter().enumerate() {
        encoder.uint(index as u64)?;
        encoder.uint(u64::from(*value))?;
    }
    let used = encoder.len();
    drop(encoder);
    let mut response = [0u8; 160];
    let used = dmesh_server::tagged::encode_numeric_response(
        POWER_COMPONENT,
        POWER_SNAPSHOT,
        id,
        &result[..used],
        &mut response,
    )?;
    Some(alloc::vec::Vec::from(&response[..used]))
}

/// Serve the common packet-ingress memory watermark over any tagged bearer.
/// The callback only copies atomics maintained by that worker; it neither
/// allocates a packet slot nor waits on the worker queue, so querying memory
/// cannot perturb the watermark being observed.
///
/// Result fields: `0` packet-pool slots, `1` free packet-pool slots, `2`
/// bounded admission drops, `3` worker stack bytes, `4` worker running, `5`
/// starts, `6` creation failures, `7` minimum remaining stack words, `8`
/// current internal 8-bit heap bytes, `9` minimum internal heap bytes, and
/// `10` the current largest internal free block. The minimums are monotonic
/// since boot and make an actual heap/stack or packet-pool limit visible
/// before changing a bearer-specific policy.
pub(crate) fn receive_tagged_memory_snapshot(
    record: dmesh_server::tagged::Record<'_>,
) -> Option<alloc::vec::Vec<u8>> {
    let id = record.id?;
    let dmesh_server::tagged::Name::Tag(method) = record.method? else {
        return None;
    };
    if method != MEMORY_SNAPSHOT {
        return None;
    }
    let memory = crate::shared_ingress_esp::memory_stats();
    let values = [
        memory.packet_slots,
        memory.packet_slots_available,
        memory.packet_drops,
        memory.worker_stack_bytes,
        u32::from(memory.worker_running),
        memory.worker_starts,
        memory.worker_create_failures,
        memory.worker_stack_min_free_words,
        memory.free_internal_bytes,
        memory.min_free_internal_bytes,
        memory.largest_internal_block_bytes,
    ];
    let mut result = [0u8; 96];
    let mut encoder = dmesh_server::cbor::Encoder::new(&mut result);
    encoder.map(values.len() as u64)?;
    for (index, value) in values.iter().enumerate() {
        encoder.uint(index as u64)?;
        encoder.uint(u64::from(*value))?;
    }
    let used = encoder.len();
    drop(encoder);
    let mut response = [0u8; 160];
    let used = dmesh_server::tagged::encode_numeric_response(
        MEMORY_COMPONENT,
        MEMORY_SNAPSHOT,
        id,
        &result[..used],
        &mut response,
    )?;
    Some(alloc::vec::Vec::from(&response[..used]))
}
