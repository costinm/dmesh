/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "sdkconfig.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_rom_sys.h"
#if CONFIG_IDF_TARGET_ESP32C6
#include "soc/rtc.h"
#else
#include "soc/rtc_cntl_reg.h"
#endif
#include "soc/soc.h"
#include "bootloader_init.h"
#include "bootloader_utility.h"
#include "bootloader_common.h"
#include "nvs_bootloader.h"
#include "boot_health_rtc.h"

#define RECOVERY_INDEX FACTORY_INDEX
#define MAIN_INDEX 0 /* ota_0; factory (-1) is Recovery */
#define STAGE2_NAMESPACE "stg2"

/* NVS stg2:boot_target partition IDs: 1=Main, 2=Recovery. */
#define BOOT_TARGET_MAIN 1u
#define BOOT_TARGET_RECOVERY 2u

#define BOOT_LOOP_WINDOW_TICKS 1000000u /* about 5 s at the ESP32 slow clock */
#define FAILURE_LIMIT 6
#define RAPID_RESET_COUNT 3

#define BOOT_KIND_NORMAL 1u
#define BOOT_KIND_MAIN_FAILURE 2u
#define BOOT_KIND_RECOVERY_REQUEST 3u
#define BOOT_KIND_USER_RESET 4u
#define BOOT_KIND_DEEP_SLEEP 5u

static const char *TAG = "dmesh-boot";

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

static int select_partition(void)
{
    uint32_t boot_target = 0;
    bool boot_target_configured = read_u32("boot_target", &boot_target);
    int reset_reason = esp_rom_get_reset_reason(0);

    boot_health_state_t *health = boot_health_state();
    uint8_t handoff = DMESH_RTC_HANDOFF;
    uint8_t event = DMESH_RTC_HEALTH_EVENT;
    bool main_was_healthy = event == DMESH_BOOT_HEALTH_MAIN_OK;
    bool main_crash_loop = !main_was_healthy && health->main_failures != 0;

    ESP_LOGI(TAG,
             "stage2 v=%u boot: reset_reason=%d handoff=%u health_event=%u "
             "main_failures=%u recovery_failures=%u nv_boot_target=%u configured=%d",
             (unsigned)DMESH_STAGE2_VERSION, reset_reason, (unsigned)handoff,
             (unsigned)event, (unsigned)health->main_failures,
             (unsigned)health->recovery_failures, (unsigned)boot_target,
             (int)boot_target_configured);

    /* A verified Recovery image hands off to Main through this volatile RTC
     * byte. It must outrank the persistent NVS override, otherwise a
     * completed update loops straight back into Recovery and can never
     * satisfy its post-update Main proof. The handoff is one-shot. */
    if (handoff == DMESH_BOOT_HEALTH_HANDOFF_MAIN) {
        DMESH_RTC_HANDOFF = DMESH_BOOT_HEALTH_HANDOFF_NORMAL;
        ESP_LOGW(TAG, "select Main: Recovery handoff");
        return MAIN_INDEX;
    }

    /* Explicit operator override, configured by writing NVS. */
    if (boot_target_configured) {
        if (boot_target == BOOT_TARGET_RECOVERY) {
            ESP_LOGW(TAG, "select Recovery: NVS boot_target");
            return RECOVERY_INDEX;
        }
        if (boot_target == BOOT_TARGET_MAIN) {
            ESP_LOGW(TAG, "select Main: NVS boot_target");
            return MAIN_INDEX;
        }
        ESP_LOGW(TAG, "ignoring invalid NVS boot_target=%u", (unsigned)boot_target);
    }

    /* Main only enters deep sleep after reaching a stable runtime state. Its
     * wake must be the fastest path and must not be redirected by stale RTC
     * health state. */
    if (reset_reason == RESET_REASON_CORE_DEEP_SLEEP) {
        ESP_LOGI(TAG, "select Main: deep-sleep resume");
        return MAIN_INDEX;
    }

    if (main_was_healthy) {
        health->main_failures = 0;
    }
    /* Health events are one-shot counter updates. The partition decision is
     * the separate RTC handoff byte and never touches NVS. */
    DMESH_RTC_HEALTH_EVENT = 0;

    /* A verified Main `boot.recovery` request is a new explicit repair
     * attempt. It is one-shot, consumed here, and must not be vetoed by
     * stale failures accumulated by the automatic crash-loop fallback. */
    bool explicit_recovery = handoff == DMESH_BOOT_HEALTH_HANDOFF_RECOVERY;
    if (explicit_recovery) {
        DMESH_RTC_HANDOFF = DMESH_BOOT_HEALTH_HANDOFF_NORMAL;
    }

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
                        explicit_recovery ? BOOT_KIND_RECOVERY_REQUEST : BOOT_KIND_NORMAL;

    bool request = explicit_recovery;
    if (recent + 1 >= RAPID_RESET_COUNT) {
        ESP_LOGW(TAG, "rapid reboot history: %u boots in window requests Recovery",
                 recent + 1);
        request = true;
    }

    if (request) {
        if (!explicit_recovery && health->recovery_failures >= FAILURE_LIMIT) {
            if (main_crash_loop) {
                /* Both budgets are exhausted and the RTC state survives
                 * resets, so halting here would halt on every later start.
                 * Boot Recovery and let it decide: it stays in its bounded
                 * repair state until an operator flashes a new image. */
                ++health->recovery_failures;
                ESP_LOGW(TAG, "select Recovery: both budgets exhausted; Recovery decides");
                return RECOVERY_INDEX;
            }
            ESP_LOGW(TAG, "Recovery failed %u times; falling back to Main",
                     (unsigned)health->recovery_failures);
            ++health->main_failures;
            ESP_LOGW(TAG, "select Main: Recovery failure fallback");
            return MAIN_INDEX;
        }
        ++health->recovery_failures;
        ESP_LOGW(TAG, "select Recovery: request %u/%u",
                 (unsigned)health->recovery_failures, (unsigned)FAILURE_LIMIT);
        return RECOVERY_INDEX;
    }

    if (health->main_failures >= FAILURE_LIMIT) {
        ESP_LOGW(TAG, "Main failed %u times; falling back to Recovery",
                 (unsigned)health->main_failures);
        ++health->recovery_failures;
        ESP_LOGW(TAG, "select Recovery: Main failure fallback");
        return RECOVERY_INDEX;
    }

    ++health->main_failures;
    ESP_LOGI(TAG, "select Main: default %u/%u",
             (unsigned)health->main_failures, (unsigned)FAILURE_LIMIT);
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
