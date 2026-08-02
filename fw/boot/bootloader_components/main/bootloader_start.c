/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "sdkconfig.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_rom_uart.h"
#include "esp_rom_sys.h"
#include "esp_rom_gpio.h"
#include "soc/rtc_cntl_reg.h"
#include "soc/soc.h"
#include "bootloader_init.h"
#include "bootloader_utility.h"
#include "bootloader_common.h"
#include "nvs_bootloader.h"
#include "boot_health_rtc.h"
#include "boot_protocol.h"

#define RECOVERY_INDEX FACTORY_INDEX
#define MAIN_INDEX 0 /* ota_0; factory (-1) is Recovery */
#define RECOVERY_NAMESPACE "recovery"
#define REQUEST_MAGIC 0x52455131u /* REQ1 */
#define UART_BOOT_WINDOW_MS 50
#define BOOT_LOOP_WINDOW_TICKS 1000000u /* about 5 s at the ESP32 slow clock */
#define FAILURE_LIMIT 6
static const char *TAG = "dmesh-boot";

static void feed_bootloader_wdt(void)
{
    if (READ_PERI_REG(RTC_CNTL_WDTWPROTECT_REG) != RTC_CNTL_WDT_WKEY_V) {
        WRITE_PERI_REG(RTC_CNTL_WDTWPROTECT_REG, RTC_CNTL_WDT_WKEY_V);
        REG_SET_BIT(RTC_CNTL_WDTFEED_REG, RTC_CNTL_WDT_FEED);
        WRITE_PERI_REG(RTC_CNTL_WDTWPROTECT_REG, 0);
    } else {
        REG_SET_BIT(RTC_CNTL_WDTFEED_REG, RTC_CNTL_WDT_FEED);
    }
}

static uint64_t rtc_boot_ticks(void)
{
    return ((uint64_t)(REG_READ(RTC_CNTL_TIME1_REG) & 0xffffu) << 32) |
           REG_READ(RTC_CNTL_TIME0_REG);
}

#if CONFIG_BOOTLOADER_CUSTOM_RESERVE_RTC
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
#endif

static bool parse_u32(const char *text, uint32_t *value)
{
    if (text == NULL || *text == '\0') {
        return false;
    }
    uint32_t parsed = 0;
    unsigned base = 10;
    const char *cursor = text;
    if (cursor[0] == '0' && (cursor[1] == 'x' || cursor[1] == 'X')) {
        base = 16;
        cursor += 2;
    }
    if (*cursor == '\0') {
        return false;
    }
    for (; *cursor != '\0'; ++cursor) {
        uint32_t digit;
        if (*cursor >= '0' && *cursor <= '9') {
            digit = (uint32_t)(*cursor - '0');
        } else if (base == 16 && *cursor >= 'a' && *cursor <= 'f') {
            digit = (uint32_t)(*cursor - 'a' + 10);
        } else if (base == 16 && *cursor >= 'A' && *cursor <= 'F') {
            digit = (uint32_t)(*cursor - 'A' + 10);
        } else {
            return false;
        }
        if (digit >= base || parsed > (UINT32_MAX - digit) / base) {
            return false;
        }
        parsed = parsed * base + digit;
    }
    *value = parsed;
    return true;
}

static bool read_u32(const char *key, uint32_t *value)
{
    nvs_bootloader_read_list_t item = {
        .namespace_name = RECOVERY_NAMESPACE,
        .key_name = key,
        .value_type = NVS_TYPE_U32,
    };
    esp_err_t u32_return = nvs_bootloader_read("nvs", 1, &item);
    if (u32_return == ESP_OK &&
        item.result_code == ESP_OK) {
        *value = item.value.u32_val;
        return true;
    }

    char text[24] = {0};
    item = (nvs_bootloader_read_list_t){
        .namespace_name = RECOVERY_NAMESPACE,
        .key_name = key,
        .value_type = NVS_TYPE_STR,
        .value.str_val = {
            .buff_ptr = text,
            .buff_len = sizeof(text),
        },
    };
    esp_err_t str_return = nvs_bootloader_read("nvs", 1, &item);
    if (str_return == ESP_OK &&
        item.result_code == ESP_OK) {
        text[sizeof(text) - 1] = '\0';
        bool parsed = parse_u32(text, value);
        return parsed;
    }
    return false;
}

static bool recovery_requested(void)
{
    uint32_t magic = 0;
    uint32_t version = 0;
    bool magic_ok = read_u32("request_magic", &magic);
    bool version_ok = read_u32("request_version", &version);
    /* Older provisioned images stored request_magic in a form that the
     * bootloader NVS reader rejects. Version=1 remains an explicit request
     * marker for those devices; new writers still provide and validate magic. */
    bool requested = version_ok && version == 1 &&
                     (!magic_ok || magic == REQUEST_MAGIC);
    ESP_LOGW(TAG, "request magic_ok=%d magic=0x%08x version_ok=%d version=%u requested=%d",
             magic_ok, (unsigned)magic, version_ok, (unsigned)version, requested);
    return requested;
}

static bool uart_boot_requested(void)
{
    static const char wanted[] = "RECOVER";
    size_t matched = 0;
    uint8_t hello[DMESH_BOOT_HELLO_LEN] = {
        DMESH_BOOT_MAGIC_0, DMESH_BOOT_MAGIC_1, DMESH_BOOT_MAGIC_2,
        DMESH_BOOT_MAGIC_3, DMESH_BOOT_VERSION, DMESH_BOOT_KIND_HELLO,
        DMESH_BOOT_ROLE_STAGE2, DMESH_BOOT_PARTITION_BOOTLOADER,
        (uint8_t)esp_rom_get_reset_reason(0), 0,
    };
    uint16_t now = (uint16_t)rtc_boot_ticks();
    hello[10] = (uint8_t)(now >> 8);
    hello[11] = (uint8_t)now;
    uint8_t wire[DMESH_BOOT_HELLO_LEN * 2 + 2];
    size_t wire_len = dmesh_boot_frame_encode(hello, sizeof(hello), wire,
                                              sizeof(wire));
    for (size_t i = 0; i < wire_len; ++i) {
        esp_rom_output_tx_one_char(wire[i]);
    }

    const uint32_t polls = UART_BOOT_WINDOW_MS * 1000;

    bool in_frame = false;
    bool escaped = false;
    uint8_t frame[DMESH_BOOT_COMMAND_LEN];
    size_t frame_len = 0;
    for (uint32_t poll = 0; poll < polls; ++poll) {
        if ((poll & 0x3ffu) == 0) {
            feed_bootloader_wdt();
        }
        uint8_t byte = 0;
        if (esp_rom_output_rx_one_char(&byte) == 0) {
            if (byte == DMESH_BOOT_WIRE_FLAG) {
                if (in_frame && !escaped && frame_len == DMESH_BOOT_COMMAND_LEN &&
                    dmesh_boot_is_magic(frame, frame_len) &&
                    frame[4] == DMESH_BOOT_VERSION &&
                    frame[5] == DMESH_BOOT_KIND_COMMAND &&
                    frame[6] == DMESH_BOOT_COMMAND_RECOVERY) {
                    return true;
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
            if (byte == (uint8_t)wanted[matched]) {
                ++matched;
                if (matched == sizeof(wanted) - 1) {
                    return true;
                }
            } else {
                matched = byte == (uint8_t)wanted[0] ? 1 : 0;
            }
        }
        esp_rom_delay_us(1);
    }
    return false;
}

static void halt_for_uart(const char *reason)
{
    ESP_LOGE(TAG, "HALT uart_flash_required reason=%s reset_reason=%d",
             reason, esp_rom_get_reset_reason(0));
    /* Do not restart into the same broken image. A UART flash is required. */
    while (true) {
        esp_rom_delay_us(1000000);
    }
}

static int select_partition(void)
{
    bool uart = uart_boot_requested();
    bool request = recovery_requested();
#if CONFIG_BOOTLOADER_RESERVE_RTC_MEM
    boot_health_state_t *health = boot_health_state();
    uint8_t event = DMESH_RTC_HEALTH_EVENT;
    if (event == DMESH_BOOT_HEALTH_MAIN_OK) {
        health->main_failures = 0;
        memset(health->boot_times, 0, sizeof(health->boot_times));
        memset(health->boot_kinds, 0, sizeof(health->boot_kinds));
    }
    if (event == DMESH_BOOT_HEALTH_RECOVERY_OK) {
        /* Recovery completed its transaction and is about to reboot.  The
         * next boot must be a fresh Main attempt; retaining the old Main
         * failure threshold would immediately select Recovery again. */
        health->recovery_failures = 0;
        health->main_failures = 0;
        memset(health->boot_times, 0, sizeof(health->boot_times));
        memset(health->boot_kinds, 0, sizeof(health->boot_kinds));
    }
    /* Consume the volatile handoff marker. No NVS write is needed. */
    DMESH_RTC_HEALTH_EVENT = 0;
    uint64_t now_ticks = rtc_boot_ticks();
    unsigned recent = 0;
    for (unsigned i = 0; i < 4; ++i) {
        uint32_t previous = health->boot_times[i];
        uint32_t delta = (uint32_t)now_ticks - previous;
        if (previous != 0 && delta <= BOOT_LOOP_WINDOW_TICKS) {
            ++recent;
        }
    }
    memmove(&health->boot_times[1], &health->boot_times[0],
            sizeof(health->boot_times) - sizeof(health->boot_times[0]));
    memmove(&health->boot_kinds[1], &health->boot_kinds[0],
            sizeof(health->boot_kinds) - sizeof(health->boot_kinds[0]));
    health->boot_times[0] = (uint32_t)now_ticks;
    health->boot_kinds[0] = 1;
    ESP_LOGI(TAG, "select uart=%d request=%d recent_boots=%u main_failures=%u recovery_failures=%u reset_reason=%d",
             uart, request, recent, health->main_failures,
             health->recovery_failures, esp_rom_get_reset_reason(0));

    if (recent >= 3 && !request && !uart) {
        ESP_LOGW(TAG, "rapid reboot history selects Recovery");
        request = true;
    }

    if (uart || request) {
        if (health->recovery_failures >= FAILURE_LIMIT) {
            ESP_LOGW(TAG, "recovery failed %u times; falling back to Main",
                     health->recovery_failures);
            if (health->main_failures >= FAILURE_LIMIT) {
                halt_for_uart("main_and_recovery_failed");
            }
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
#else
    ESP_LOGI(TAG, "RTC failure counters unavailable; select recovery=%d uart=%d request=%d",
             uart || request, uart, request);
    if (uart || request) {
        return RECOVERY_INDEX;
    }
    return MAIN_INDEX;
#endif
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
