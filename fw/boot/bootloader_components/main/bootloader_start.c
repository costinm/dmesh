/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>
#include <stddef.h>
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
#include "soc/soc_caps.h"
#if CONFIG_IDF_TARGET_ESP32
#include "soc/spi_reg.h"
#else
#include "soc/spi_mem_reg.h"
#endif
#include "bootloader_init.h"
#include "bootloader_utility.h"
#include "bootloader_common.h"
#include "bootloader_flash_priv.h"
#include "esp_app_format.h"
#include "flash_qio_mode.h"
#include "nvs_bootloader.h"
#include "boot_health_rtc.h"

/* Stage2 chooses the code read mode per boot (stg2:flash). A QIO build
 * would enable QIO in bootloader_init() for every image, Recovery included. */
#if CONFIG_ESPTOOLPY_FLASHMODE_QIO || CONFIG_ESPTOOLPY_FLASHMODE_QOUT
#error "Build Stage2 as DIO; it enables QIO for Main at runtime"
#endif

#define RECOVERY_INDEX FACTORY_INDEX
#define MAIN_INDEX 0 /* ota_0; factory (-1) is Recovery */
#define STAGE2_NAMESPACE "stg2"

/* NVS stg2:boot_target partition IDs: 1=Main, 2=Recovery. */
#define BOOT_TARGET_MAIN 1u
#define BOOT_TARGET_RECOVERY 2u

/* NVS stg2:flash code read mode for Main. Recovery always runs in DIO. */
#define FLASH_MODE_DIO 1u
#define FLASH_MODE_QIO 2u
#define FLASH_MODE_AUTO 3u /* default: QIO until a QIO boot fails, then DIO */

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
    uint8_t reserved;   /* DMESH_RTC_HEALTH_EVENT */
    uint8_t handoff;    /* DMESH_RTC_HANDOFF; kept across reinitialization */
    uint8_t flash;      /* DMESH_RTC_FLASH */
    uint8_t reserved2;
    uint32_t boot_times[4];
    uint8_t boot_kinds[4];
} boot_health_state_t;
_Static_assert(offsetof(boot_health_state_t, handoff) + DMESH_RTC_CUSTOM_OFFSET ==
               DMESH_RTC_HANDOFF_OFFSET, "RTC handoff offset");
_Static_assert(offsetof(boot_health_state_t, flash) + DMESH_RTC_CUSTOM_OFFSET ==
               DMESH_RTC_FLASH_OFFSET, "RTC flash offset");
_Static_assert(offsetof(boot_health_state_t, boot_times) == 8, "RTC layout unchanged");

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
        state->flash = 0;
        state->reserved2 = 0;
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

/* An autodetect QIO trial passes only when that Main boot reported MAIN_OK.
 * A crash, an image check failure, a fallback to Recovery, or a reset before
 * Main is healthy disables autodetected QIO until RTC memory is lost. */
static void account_qio_trial(boot_health_state_t *health, uint8_t event)
{
    /* Older Stage2 builds left this byte as uninitialized padding. Keep only
     * the persistent bits; stale garbage can at worst select DIO until power
     * is lost. ACTIVE describes one boot and is recomputed below. */
    uint8_t flash = health->flash &
                    (DMESH_RTC_FLASH_QIO_TRIAL | DMESH_RTC_FLASH_QIO_FAILED);
    if (flash & DMESH_RTC_FLASH_QIO_TRIAL) {
        flash &= (uint8_t)~DMESH_RTC_FLASH_QIO_TRIAL;
        if (event != DMESH_BOOT_HEALTH_MAIN_OK) {
            flash |= DMESH_RTC_FLASH_QIO_FAILED;
        }
    }
    health->flash = flash;
}

static bool cache_reads_qio(void)
{
#if CONFIG_IDF_TARGET_ESP32
    return (REG_READ(SPI_CTRL_REG(0)) & SPI_FREAD_QIO) != 0;
#else
    return (REG_READ(SPI_MEM_CTRL_REG(0)) & SPI_MEM_FREAD_QIO) != 0;
#endif
}

static bool main_header_present(const bootloader_state_t *bs)
{
    esp_image_header_t header;
    return bs->ota[MAIN_INDEX].size != 0 &&
           bootloader_flash_read(bs->ota[MAIN_INDEX].offset, &header, sizeof(header), true) == ESP_OK &&
           header.magic == ESP_IMAGE_HEADER_MAGIC;
}

/* Select the code read mode for the image about to load. Only Main may run
 * in QIO; Recovery is the repair path and always stays in DIO. */
static const char *apply_flash_mode(const bootloader_state_t *bs, int partition_index)
{
    boot_health_state_t *health = boot_health_state();
    uint32_t mode = FLASH_MODE_AUTO;
    (void)read_u32("flash", &mode);
    if (mode < FLASH_MODE_DIO || mode > FLASH_MODE_AUTO) {
        ESP_LOGW(TAG, "ignoring invalid NVS flash=%u; using DIO", (unsigned)mode);
        mode = FLASH_MODE_DIO;
    }
    if (partition_index != MAIN_INDEX) {
        return "dio-recovery";
    }
    if (mode == FLASH_MODE_DIO) {
        return "dio";
    }
    if (mode == FLASH_MODE_AUTO && (health->flash & DMESH_RTC_FLASH_QIO_FAILED)) {
        return "dio-fallback";
    }
    /* Recovery erases Main's first sector before writing it. Without a header
     * the loader falls through to Recovery, which must not inherit QIO. */
    if (!main_header_present(bs)) {
        return "dio-no-main";
    }
#if SOC_SPI_MEM_SUPPORT_FLASH_OPI_MODE
    if (bootloader_flash_is_octal_mode_enabled()) {
        return "octal";
    }
#endif
    bootloader_enable_qio_mode();
    if (!cache_reads_qio()) {
        /* The chip did not accept its quad-enable bit; IDF stayed in DIO. */
        if (mode == FLASH_MODE_AUTO) {
            health->flash |= DMESH_RTC_FLASH_QIO_FAILED;
        }
        return "dio-qe-failed";
    }
    health->flash |= DMESH_RTC_FLASH_QIO_ACTIVE;
    if (mode == FLASH_MODE_AUTO) {
        health->flash |= DMESH_RTC_FLASH_QIO_TRIAL;
        /* Only this boot's MAIN_OK may confirm the trial. A deep-sleep resume
         * would otherwise carry the previous boot's marker. */
        DMESH_RTC_HEALTH_EVENT = 0;
    }
    return "qio";
}

static int select_partition(void)
{
    uint32_t boot_target = 0;
    bool boot_target_configured = read_u32("boot_target", &boot_target);
    int reset_reason = esp_rom_get_reset_reason(0);

    boot_health_state_t *health = boot_health_state();
    uint8_t handoff = DMESH_RTC_HANDOFF;
    uint8_t event = DMESH_RTC_HEALTH_EVENT;
    /* Keep this one ROM-console line available when normal bootloader logs
     * are disabled. It proves the handoff byte seen by Stage2 without
     * changing the boot decision or requiring any UART input protocol. */
    esp_rom_printf("DMESH stage2: handoff=%u event=%u reset=%d rtc_flash=0x%x\n",
                   (unsigned)handoff, (unsigned)event, reset_reason,
                   (unsigned)health->flash);
    account_qio_trial(health, event);
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

    /* Explicit Main requests are one-shot and outrank a persistent selector. */
    bool explicit_recovery = handoff == DMESH_BOOT_HEALTH_HANDOFF_RECOVERY;
    if (explicit_recovery) {
        DMESH_RTC_HANDOFF = DMESH_BOOT_HEALTH_HANDOFF_NORMAL;
    }

    /* Explicit operator override, configured by writing NVS. */
    if (boot_target_configured && !explicit_recovery) {
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
    if (reset_reason == RESET_REASON_CORE_DEEP_SLEEP && !explicit_recovery) {
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

    int partition_index = select_partition();
    const char *flash_mode = apply_flash_mode(&bs, partition_index);
    /* ROM-visible selection evidence: when an app returns immediately to
     * Stage2 this distinguishes a selected-but-unbootable image from a wrong
     * partition decision, without introducing a control path. */
    esp_rom_printf("DMESH stage2: load partition=%d flash=%s\n", partition_index, flash_mode);
    bootloader_utility_load_boot_image(&bs, partition_index);
    bootloader_reset();
}

#if CONFIG_LIBC_NEWLIB
struct _reent *__getreent(void)
{
    return _GLOBAL_REENT;
}
#endif
