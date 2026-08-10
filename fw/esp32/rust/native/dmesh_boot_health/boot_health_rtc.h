#pragma once

/* Local Main copy of the RTC layout contract. Keep synchronized with the
 * stage2/Recovery copies and with fw/boot/API.md. */

#include <stdint.h>
#include "sdkconfig.h"
#include "soc/soc.h"

#define DMESH_RTC_RETAIN_RAW_SIZE (((12 + 0x20u + 4 + 7) / 8) * 8)
#define DMESH_RTC_CUSTOM_OFFSET 12
#define DMESH_RTC_HEALTH_EVENT_OFFSET (DMESH_RTC_CUSTOM_OFFSET + 4)
#define DMESH_RTC_HANDOFF_OFFSET (DMESH_RTC_CUSTOM_OFFSET + 5)
/* custom+8..27 is stage2's retained boot history after C alignment. */
#define DMESH_RTC_DRY_RUN_OFFSET (DMESH_RTC_CUSTOM_OFFSET + 28)
#if ESP_ROM_HAS_LP_ROM
#define DMESH_RTC_RETAIN_BASE SOC_RTC_DRAM_LOW
#else
#define DMESH_RTC_RETAIN_BASE (SOC_RTC_DRAM_HIGH - DMESH_RTC_RETAIN_RAW_SIZE)
#endif
#define DMESH_RTC_HEALTH_EVENT (*(volatile uint8_t *)(DMESH_RTC_RETAIN_BASE + DMESH_RTC_HEALTH_EVENT_OFFSET))
#define DMESH_RTC_HANDOFF (*(volatile uint8_t *)(DMESH_RTC_RETAIN_BASE + DMESH_RTC_HANDOFF_OFFSET))
#define DMESH_RTC_DRY_RUN (*(volatile uint8_t *)(DMESH_RTC_RETAIN_BASE + DMESH_RTC_DRY_RUN_OFFSET))
static inline void dmesh_boot_health_write(uint8_t event) { DMESH_RTC_HEALTH_EVENT = event; }
static inline void dmesh_boot_handoff_write(uint8_t handoff) { DMESH_RTC_HANDOFF = handoff; }
static inline void dmesh_boot_dry_run_write(uint8_t dry_run) { DMESH_RTC_DRY_RUN = dry_run ? 1 : 0; }
