/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "sdkconfig.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_rom_serial_output.h"
#include "esp_rom_sys.h"
#include "esp_rom_gpio.h"
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#if CONFIG_IDF_TARGET_ESP32C6
#include "soc/rtc.h"
#include "soc/lp_wdt_reg.h"
#else
#include "soc/rtc_cntl_reg.h"
#endif
#include "soc/soc.h"
#include "bootloader_init.h"
#include "bootloader_utility.h"
#include "bootloader_common.h"
#include "nvs_bootloader.h"
#include "boot_health_rtc.h"
#include "boot_protocol.h"
#include "bootloader_flash_priv.h"

#define RECOVERY_INDEX FACTORY_INDEX
#define MAIN_INDEX 0 /* ota_0; factory (-1) is Recovery */
#define STAGE2_NAMESPACE "stg2"
/* The command arrives through managed lmesh, not a locally polled UART
 * client.  It is sent immediately after reset, so the development window can
 * remain short and bounded. */
/* The selector is sent through the managed UART forward after the reset
 * pulse.  CP210x reset/forward scheduling can consume several hundred ms;
 * keep a bounded but generous window so the packet is not lost while still
 * returning to normal partition selection promptly on an idle boot. */
#define UART_BOOT_WINDOW_MS 1000
#define BOOT_LOOP_WINDOW_TICKS 1000000u /* about 5 s at the ESP32 slow clock */
#define FAILURE_LIMIT 6
#define RAPID_RESET_COUNT 3
#define BOOT_KIND_NORMAL 1u
#define BOOT_KIND_MAIN_FAILURE 2u
#define BOOT_KIND_RECOVERY_REQUEST 3u
#define BOOT_KIND_USER_RESET 4u
#define BOOT_KIND_DEEP_SLEEP 5u
static const char *TAG = "dmesh-boot";

static void feed_bootloader_wdt(void)
{
#if CONFIG_IDF_TARGET_ESP32C6
    REG_WRITE(LP_WDT_WPROTECT_REG, 0x50D83AA1u);
    REG_SET_BIT(LP_WDT_FEED_REG, LP_WDT_RTC_WDT_FEED);
    REG_WRITE(LP_WDT_WPROTECT_REG, 0);
#else
    WRITE_PERI_REG(RTC_CNTL_WDTWPROTECT_REG, RTC_CNTL_WDT_WKEY_V);
    REG_SET_BIT(RTC_CNTL_WDTFEED_REG, RTC_CNTL_WDT_FEED);
    WRITE_PERI_REG(RTC_CNTL_WDTWPROTECT_REG, 0);
#endif
}

static void disable_bootloader_wdt(void)
{
#if CONFIG_IDF_TARGET_ESP32C6
    REG_WRITE(LP_WDT_WPROTECT_REG, 0x50D83AA1u);
    REG_WRITE(LP_WDT_CONFIG0_REG, 0);
    REG_SET_BIT(LP_WDT_FEED_REG, LP_WDT_RTC_WDT_FEED);
    REG_WRITE(LP_WDT_WPROTECT_REG, 0);
#else
    WRITE_PERI_REG(RTC_CNTL_WDTWPROTECT_REG, RTC_CNTL_WDT_WKEY_V);
    WRITE_PERI_REG(RTC_CNTL_WDTCONFIG0_REG, 0);
    REG_SET_BIT(RTC_CNTL_WDTFEED_REG, RTC_CNTL_WDT_FEED);
    WRITE_PERI_REG(RTC_CNTL_WDTWPROTECT_REG, 0);
#endif
}

static uint64_t rtc_boot_ticks(void)
{
#if CONFIG_IDF_TARGET_ESP32C6
    return rtc_time_get();
#else
    return ((uint64_t)(REG_READ(RTC_CNTL_TIME1_REG) & 0xffffu) << 32) |
           REG_READ(RTC_CNTL_TIME0_REG);
#endif
}

typedef struct {
    uint8_t magic;
    uint8_t generation;
    uint8_t recovery_failures;
    uint8_t main_failures;
    uint8_t reserved;
    uint32_t boot_times[4];
    uint8_t boot_kinds[4];
} boot_health_state_t;

static boot_health_state_t *boot_health_state(void)
{
    rtc_retain_mem_t *retain = bootloader_common_get_rtc_retain_mem();
    boot_health_state_t *state = (boot_health_state_t *)retain->custom;
    if (state->magic != DMESH_BOOT_HEALTH_MAGIC ||
        state->generation != DMESH_BOOT_HEALTH_GENERATION) {
        /* The custom RTC area is excluded from the IDF retain CRC. */
        state->magic = DMESH_BOOT_HEALTH_MAGIC;
        state->generation = DMESH_BOOT_HEALTH_GENERATION;
        state->recovery_failures = 0;
        state->main_failures = 0;
        state->reserved = 0;
        memset(state->boot_times, 0, sizeof(state->boot_times));
        memset(state->boot_kinds, 0, sizeof(state->boot_kinds));
    }
    return state;
}

static bool read_u32(const char *key, uint32_t *value)
{
    nvs_bootloader_read_list_t item = {
        .namespace_name = STAGE2_NAMESPACE,
        .key_name = key,
        .value_type = NVS_TYPE_U32,
    };
    esp_err_t err = nvs_bootloader_read("nvs", 1, &item);
    if (err != ESP_OK || item.result_code != ESP_OK) return false;
    *value = item.value.u32_val;
    return true;
}

static bool uart_boot_enabled(void)
{
    uint32_t value = 1;
    bool configured = read_u32("uart_boot", &value);
    /* Missing or malformed configuration is development-safe for existing
     * boards. Production provisioning must write stg2:uart_boot=0. */
    ESP_LOGI(TAG, "uart_boot configured=%d value=%u enabled=%d",
             configured, (unsigned)value, configured ? (value != 0) : 1);
    return !configured || value != 0;
}

/* A managed USB-UART reset is the explicit host handoff path.  Keep the
 * bounded selector window there even when NVS defaults to Main; normal
 * software/RTC boots must not pay that delay.  ESP32-C6 reports this as
 * RESET_REASON_USB_UART_HPSYS (0x15). */
static bool uart_selector_reset(void)
{
#if CONFIG_IDF_TARGET_ESP32C6
    return esp_rom_get_reset_reason(0) == 0x15;
#else
    return false;
#endif
}

static void boot_identity_rtc_values(uint8_t *handoff, uint8_t *main_failures,
                                     uint8_t *recovery_failures,
                                     uint8_t *recent_resets)
{
    boot_health_state_t *health = boot_health_state();
    *handoff = DMESH_RTC_HANDOFF;
    *main_failures = health->main_failures;
    *recovery_failures = health->recovery_failures;
    uint64_t now_ticks = rtc_boot_ticks();
    for (unsigned i = 0; i < 4; ++i) {
        uint32_t previous = health->boot_times[i];
        uint32_t delta = (uint32_t)now_ticks - previous;
        uint8_t kind = health->boot_kinds[i];
        if (previous != 0 && delta <= BOOT_LOOP_WINDOW_TICKS &&
            kind != BOOT_KIND_RECOVERY_REQUEST &&
            kind != BOOT_KIND_DEEP_SLEEP) {
            ++*recent_resets;
        }
    }
}

static bool boot_cbor_uint(const uint8_t **cursor, const uint8_t *end,
                           uint64_t *value)
{
    if (*cursor >= end) return false;
    uint8_t first = *(*cursor)++;
    uint8_t additional = first & 0x1f;
    if ((first >> 5) != 0) return false;
    if (additional < 24) { *value = additional; return true; }
    size_t width = additional == 24 ? 1 : additional == 25 ? 2 :
                   additional == 26 ? 4 : additional == 27 ? 8 : 0;
    if (width == 0 || (size_t)(end - *cursor) < width) return false;
    uint64_t result = 0;
    for (size_t i = 0; i < width; ++i) result = (result << 8) | *(*cursor)++;
    *value = result;
    return true;
}

/* Decode only the boot selector envelope: {0:60010,6:[partition]}.
 * Selectors deliberately require definite-length CBOR; identity events use
 * indefinite-length CBOR for compatibility with the lmesh matcher. */
static int boot_cbor_selector(const uint8_t *data, size_t length)
{
    const uint8_t *cursor = data;
    const uint8_t *end = data + length;
    if (cursor >= end || *cursor++ != 0xa2) return 0;
    uint64_t method = 0, method_id = 0, payload_key = 0;
    if (!boot_cbor_uint(&cursor, end, &method) || method != 0 ||
        !boot_cbor_uint(&cursor, end, &method_id) || method_id != DMESH_BOOT_METHOD_SELECT ||
        !boot_cbor_uint(&cursor, end, &payload_key) || payload_key != 6 ||
        cursor >= end || *cursor++ != 0x81) return 0;
    uint64_t partition = 0;
    if (!boot_cbor_uint(&cursor, end, &partition) || cursor != end) return 0;
    return partition == DMESH_BOOT_PARTITION_RECOVERY ? 1 :
           partition == DMESH_BOOT_PARTITION_MAIN ? 2 : 0;
}

/* Emit this before partition selection, including a persisted Recovery
 * target, so a failed NVS read cannot be inferred only from a later Main
 * boot. The values after stage2_version are configured and target. */
static void emit_boot_identity(bool boot_target_configured, uint32_t boot_target)
{
    uint8_t mac[6] = {0};
    (void)esp_efuse_read_field_blob(ESP_EFUSE_MAC_FACTORY, mac, 48);
    uint8_t handoff = 0, main_failures = 0, recovery_failures = 0;
    uint8_t recent_resets = 0;
    boot_identity_rtc_values(&handoff, &main_failures, &recovery_failures,
                             &recent_resets);
    uint8_t payload[128];
    size_t payload_len = dmesh_boot_identity_event(
        payload, sizeof(payload), DMESH_BOOT_ROLE_STAGE2,
        DMESH_BOOT_PARTITION_BOOTLOADER,
        (uint8_t)esp_rom_get_reset_reason(0), handoff,
        main_failures, recovery_failures, recent_resets, rtc_boot_ticks(),
        boot_target_configured, boot_target, mac);
    uint8_t wire[256];
    size_t wire_len = dmesh_boot_frame_encode(payload, payload_len, wire,
                                              sizeof(wire));
    for (size_t i = 0; i < wire_len; ++i) {
        esp_rom_output_tx_one_char(wire[i]);
    }
}

static int uart_boot_requested(void)
{

    const uint32_t polls = UART_BOOT_WINDOW_MS * 1000;

    bool in_frame = false;
    bool escaped = false;
    uint8_t frame[64];
    size_t frame_len = 0;
    /* Managed USB/UART forwards normally preserve the PPP delimiters. Keep a
     * tiny rolling window as well: a forward which has already consumed or
     * normalized delimiters must not make the exact, self-delimiting selector
     * disappear during the short boot handoff. */
    uint8_t raw_selector[10] = {0};
    size_t raw_selector_len = 0;
    for (uint32_t poll = 0; poll < polls; ++poll) {
        if ((poll & 0x3ffu) == 0) {
            feed_bootloader_wdt();
        }
        uint8_t byte = 0;
        if (esp_rom_output_rx_one_char(&byte) == 0) {
            if (raw_selector_len < sizeof(raw_selector)) {
                raw_selector[raw_selector_len++] = byte;
            } else {
                memmove(raw_selector, raw_selector + 1, sizeof(raw_selector) - 1);
                raw_selector[sizeof(raw_selector) - 1] = byte;
            }
            if (raw_selector_len == sizeof(raw_selector)) {
                int selector = boot_cbor_selector(raw_selector, sizeof(raw_selector));
                if (selector != 0) return selector;
            }
            if (byte == DMESH_BOOT_WIRE_FLAG) {
                if (in_frame && !escaped) {
                    int selector = boot_cbor_selector(frame, frame_len);
                    if (selector != 0) return selector;
                }
                in_frame = true; escaped = false; frame_len = 0;
                continue;
            }
            if (in_frame) {
                if (escaped) {
                    if (frame_len < sizeof(frame)) frame[frame_len++] = byte ^ DMESH_BOOT_WIRE_ESCAPE_XOR;
                    escaped = false;
                } else if (byte == DMESH_BOOT_WIRE_ESCAPE) {
                    escaped = true;
                } else if (frame_len < sizeof(frame)) {
                    frame[frame_len++] = byte;
                }
            }
        }
        esp_rom_delay_us(1);
    }
    return false;
}

static void uart_recovery_failed(bool uart_enabled, uint8_t recovery_failures,
                                 uint8_t main_failures)
{
    if (!uart_enabled) return;
    uint8_t payload[64];
    size_t payload_len = dmesh_boot_recovery_failed_event(
        payload, sizeof(payload), recovery_failures, main_failures);
    uint8_t wire[128];
    size_t wire_len = dmesh_boot_frame_encode(payload, payload_len, wire,
                                              sizeof(wire));
    for (size_t i = 0; i < wire_len; ++i) {
        esp_rom_output_tx_one_char(wire[i]);
    }
}

static void halt_for_uart(const char *reason)
{
    ESP_LOGE(TAG, "HALT uart_flash_required reason=%s reset_reason=%d",
             reason, esp_rom_get_reset_reason(0));
    /* This is reachable only after the Main crash loop has exhausted the
     * Recovery retry budget. Do not restart into the same broken image. */
    disable_bootloader_wdt();
    while (true) {
        esp_rom_delay_us(1000000);
    }
}

static int select_partition(void)
{
    /* A verified Recovery image explicitly hands off to Main through this
     * volatile RTC byte. It must outrank the persistent lab command-mode
     * Recovery override: otherwise a successful Wi-Fi update loops straight
     * back into Recovery and can never satisfy its post-update Main proof.
     * Recovery writes this only after all manifest block digests and flash
     * worker completions succeed. */
    if (DMESH_RTC_HANDOFF == DMESH_BOOT_HEALTH_HANDOFF_MAIN) {
        ESP_LOGW(TAG, "RTC handoff overrides NVS target with Main");
        /* The handoff is explicitly one-shot.  Leaving it set would make a
         * completed update permanently veto the operator's later Recovery
         * setting, including normal command-mode performance testing. */
        DMESH_RTC_HANDOFF = DMESH_BOOT_HEALTH_HANDOFF_NORMAL;
        return MAIN_INDEX;
    }
    /* Explicit lab/operator override. Unlike the UART selector, this is read
     * before the boot window, so repeated Recovery diagnostics neither wait
     * for UART nor accidentally fall through to Main. Values are partition
     * IDs: 1=Main, 2=Recovery; missing or invalid values preserve policy. */
    uint32_t boot_target = 0;
    bool boot_target_configured = read_u32("boot_target", &boot_target);
    emit_boot_identity(boot_target_configured, boot_target);
    if (boot_target_configured) {
        if (boot_target == DMESH_BOOT_PARTITION_RECOVERY) {
            ESP_LOGW(TAG, "NVS boot_target selects Recovery");
            return RECOVERY_INDEX;
        }
        if (boot_target == DMESH_BOOT_PARTITION_MAIN) {
            /* Main is the persistent default, not a veto on an explicit
             * managed UART Recovery selection made immediately after reset. */
            if (uart_boot_enabled() && uart_selector_reset()) {
                int uart = uart_boot_requested();
                if (uart == 1) {
                    ESP_LOGW(TAG, "UART selector overrides NVS Main with Recovery");
                    return RECOVERY_INDEX;
                }
            }
            ESP_LOGW(TAG, "NVS boot_target selects Main");
            return MAIN_INDEX;
        }
        ESP_LOGW(TAG, "ignoring invalid NVS boot_target=%u", (unsigned)boot_target);
    }
    /* Main only enters deep sleep after reaching a stable runtime state. Its
     * wake must therefore be the fastest path and must not be redirected by
     * stale UART or RTC handoff state. */
    if (esp_rom_get_reset_reason(0) == RESET_REASON_CORE_DEEP_SLEEP) {
        ESP_LOGI(TAG, "deep-sleep resume selects Main");
        return MAIN_INDEX;
    }

    bool uart_enabled = uart_boot_enabled();
    int uart = uart_enabled ? uart_boot_requested() : 0;
    /* Partition handoff is volatile RTC state. A verified Recovery transfer
     * may request Main above; this remaining path handles Recovery requests.
     * A stale value is cleared by the next successful transition. */
    bool request = false;
    boot_health_state_t *health = boot_health_state();
    uint8_t handoff = DMESH_RTC_HANDOFF;
    uint8_t event = DMESH_RTC_HEALTH_EVENT;
    bool main_was_healthy = event == DMESH_BOOT_HEALTH_MAIN_OK;
    bool main_crash_loop = !main_was_healthy && health->main_failures != 0;
    if (event == DMESH_BOOT_HEALTH_MAIN_OK) {
        health->main_failures = 0;
        /* Keep rapid-reset timestamps across a healthy Main boot.  A
         * deliberate sequence of external RTS resets must be able to select
         * Recovery even when Main normally reaches MAIN_OK.  Old entries are
         * ignored by BOOT_LOOP_WINDOW_TICKS and Recovery_OK clears the whole
         * history after a successful update. */
    }
    /* Health events are informational/counter updates.  The partition
     * decision is the separate RTC handoff byte and never touches NVS. */
    DMESH_RTC_HEALTH_EVENT = 0;
    uint64_t now_ticks = rtc_boot_ticks();
    unsigned recent = 0;
    for (unsigned i = 0; i < 4; ++i) {
        uint32_t previous = health->boot_times[i];
        uint32_t delta = (uint32_t)now_ticks - previous;
        uint8_t kind = health->boot_kinds[i];
        if (previous != 0 && delta <= BOOT_LOOP_WINDOW_TICKS &&
            kind != BOOT_KIND_RECOVERY_REQUEST &&
            kind != BOOT_KIND_DEEP_SLEEP) {
            ++recent;
        }
    }
    memmove(&health->boot_times[1], &health->boot_times[0],
            sizeof(health->boot_times) - sizeof(health->boot_times[0]));
    memmove(&health->boot_kinds[1], &health->boot_kinds[0],
            sizeof(health->boot_kinds) - sizeof(health->boot_kinds[0]));
    health->boot_times[0] = (uint32_t)now_ticks;
    health->boot_kinds[0] = main_crash_loop ? BOOT_KIND_MAIN_FAILURE :
                            main_was_healthy ? BOOT_KIND_USER_RESET :
                            handoff != DMESH_BOOT_HEALTH_HANDOFF_NORMAL || uart == 1 ?
                                BOOT_KIND_RECOVERY_REQUEST : BOOT_KIND_NORMAL;
    ESP_LOGW(TAG, "select uart_enabled=%d uart=%d handoff=%u request=%d recent_boots=%u main_failures=%u recovery_failures=%u reset_reason=%d",
             uart_enabled, uart, handoff, request, recent, health->main_failures,
             health->recovery_failures,
             esp_rom_get_reset_reason(0));

    if (recent + 1 >= RAPID_RESET_COUNT && !request && !uart) {
        ESP_LOGW(TAG, "rapid reboot history selects Recovery");
        request = true;
    }

    /* An explicit physical RECOVER selector is the last-resort repair path.
     * It remains usable even when RTC health state has exhausted the
     * automatic Recovery retry budget. */
    if (uart == 2) {
        ESP_LOGW(TAG, "explicit UART Main overrides recovery request");
        return MAIN_INDEX;
    }
    if (uart == 1) {
        ESP_LOGW(TAG, "explicit UART Recovery overrides failure limit");
        return RECOVERY_INDEX;
    }

    if (handoff == DMESH_BOOT_HEALTH_HANDOFF_MAIN) {
        ESP_LOGW(TAG, "RTC handoff selects Main");
        return MAIN_INDEX;
    }
    if (handoff == DMESH_BOOT_HEALTH_HANDOFF_RECOVERY) {
        ESP_LOGW(TAG, "RTC handoff selects Recovery");
        request = true;
    }

    if (request) {
        if (health->recovery_failures >= FAILURE_LIMIT) {
            ESP_LOGW(TAG, "recovery failed %u times; %s",
                     health->recovery_failures,
                     main_crash_loop ? "halting" : "falling back to Main");
            uart_recovery_failed(uart_enabled, health->recovery_failures,
                                 health->main_failures);
            if (main_crash_loop) {
                halt_for_uart("main_and_recovery_failed");
            }
            ESP_LOGW(TAG, "Recovery failure falls back to Main");
            ++health->main_failures;
            return MAIN_INDEX;
        }
        ++health->recovery_failures;
        ESP_LOGI(TAG, "attempt Recovery number=%u/%u",
                 health->recovery_failures, FAILURE_LIMIT);
        return RECOVERY_INDEX;
    }

    if (health->main_failures >= FAILURE_LIMIT) {
        ESP_LOGW(TAG, "Main failed %u times; falling back to Recovery",
                 health->main_failures);
        if (health->recovery_failures >= FAILURE_LIMIT) {
            halt_for_uart("main_and_recovery_failed");
        }
        ++health->recovery_failures;
        return RECOVERY_INDEX;
    }
    ++health->main_failures;
    ESP_LOGI(TAG, "attempt Main number=%u/%u", health->main_failures, FAILURE_LIMIT);
    return MAIN_INDEX;
}

void __attribute__((noreturn)) call_start_cpu0(void)
{
    if (bootloader_init() != ESP_OK) {
        bootloader_reset();
    }

    bootloader_state_t bs = {0};
    if (!bootloader_utility_load_partition_table(&bs)) {
        ESP_LOGE(TAG, "partition table load failed");
        bootloader_reset();
    }

    bootloader_utility_load_boot_image(&bs, select_partition());
    bootloader_reset();
}

#if CONFIG_LIBC_NEWLIB
struct _reent *__getreent(void)
{
    return _GLOBAL_REENT;
}
#endif
