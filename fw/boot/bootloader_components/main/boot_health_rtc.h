#pragma once

/* Local copy of the RTC layout contract. The schema and offsets are described
 * in fw/boot/API.md; keep the Main/Recovery copies synchronized. */

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

#if ESP_ROM_HAS_LP_ROM
#define DMESH_RTC_RETAIN_BASE SOC_RTC_DRAM_LOW
#else
#define DMESH_RTC_RETAIN_BASE (SOC_RTC_DRAM_HIGH - DMESH_RTC_RETAIN_RAW_SIZE)
#endif

#define DMESH_RTC_HEALTH_EVENT (*(volatile uint8_t *)(DMESH_RTC_RETAIN_BASE + DMESH_RTC_HEALTH_EVENT_OFFSET))
#define DMESH_RTC_HANDOFF (*(volatile uint8_t *)(DMESH_RTC_RETAIN_BASE + DMESH_RTC_HANDOFF_OFFSET))

static inline void dmesh_boot_health_write(uint8_t event)
{
    DMESH_RTC_HEALTH_EVENT = event;
}

static inline void dmesh_boot_handoff_write(uint8_t handoff)
{
    DMESH_RTC_HANDOFF = handoff;
}
