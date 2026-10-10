#pragma once

/* Local C copy of the RTC layout contract. Rust Main and Recovery use
 * dmesh-fw-transport/src/rtc.rs; API.md documents the byte offsets. Keep this
 * pre-Rust Stage2 header synchronized with that module. */

#include <stdint.h>
#include "sdkconfig.h"
#include "soc/soc.h"

#define DMESH_BOOT_HEALTH_MAGIC 0x48u
#define DMESH_BOOT_HEALTH_GENERATION 2u
#define DMESH_BOOT_HEALTH_MAIN_START 1u
#define DMESH_BOOT_HEALTH_MAIN_OK 2u
#define DMESH_BOOT_HEALTH_HANDOFF_NORMAL 0u
#define DMESH_BOOT_HEALTH_HANDOFF_RECOVERY 1u
#define DMESH_BOOT_HEALTH_HANDOFF_MAIN 2u
#define DMESH_RTC_RETAIN_RAW_SIZE (((12 + 0x20u + 4 + 7) / 8) * 8)
#define DMESH_RTC_CUSTOM_OFFSET 12
#define DMESH_RTC_HEALTH_EVENT_OFFSET (DMESH_RTC_CUSTOM_OFFSET + 4)
#define DMESH_RTC_HANDOFF_OFFSET (DMESH_RTC_CUSTOM_OFFSET + 5)
/* Stage2-owned flash read-mode state. Apps may read it but never write it. */
#define DMESH_RTC_FLASH_OFFSET (DMESH_RTC_CUSTOM_OFFSET + 6)
#define DMESH_RTC_FLASH_QIO_TRIAL 0x01u  /* autodetect booted Main in QIO */
#define DMESH_RTC_FLASH_QIO_FAILED 0x02u /* a QIO trial never reached MAIN_OK */
#define DMESH_RTC_FLASH_QIO_ACTIVE 0x04u /* the current boot reads code in QIO */

#if CONFIG_IDF_TARGET_ESP32C6
/* C6 application code cannot write SOC_RTC_DRAM_LOW. Share this writable
 * high-end RTC block with Main and Recovery instead. */
#define DMESH_RTC_RETAIN_BASE (SOC_RTC_DRAM_HIGH - DMESH_RTC_RETAIN_RAW_SIZE)
#elif ESP_ROM_HAS_LP_ROM
#define DMESH_RTC_RETAIN_BASE SOC_RTC_DRAM_LOW
#else
#define DMESH_RTC_RETAIN_BASE (SOC_RTC_DRAM_HIGH - DMESH_RTC_RETAIN_RAW_SIZE)
#endif

#define DMESH_RTC_HEALTH_EVENT (*(volatile uint8_t *)(DMESH_RTC_RETAIN_BASE + DMESH_RTC_HEALTH_EVENT_OFFSET))
#define DMESH_RTC_HANDOFF (*(volatile uint8_t *)(DMESH_RTC_RETAIN_BASE + DMESH_RTC_HANDOFF_OFFSET))
#define DMESH_RTC_FLASH (*(volatile uint8_t *)(DMESH_RTC_RETAIN_BASE + DMESH_RTC_FLASH_OFFSET))

static inline void dmesh_boot_health_write(uint8_t event)
{
    DMESH_RTC_HEALTH_EVENT = event;
}

static inline void dmesh_boot_handoff_write(uint8_t handoff)
{
    DMESH_RTC_HANDOFF = handoff;
}
