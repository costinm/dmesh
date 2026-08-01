/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

/*
 * The second-stage bootloader reserves rtc_retain_mem_t in RTC fast RAM.
 * Its custom field is deliberately outside the IDF CRC.  Keep the layout
 * calculation here in sync with esp_image_format.h so applications can mark
 * a boot attempt without opening or committing NVS.
 */
#include <stdint.h>

#include "sdkconfig.h"
#include "soc/soc.h"

#ifndef CONFIG_BOOTLOADER_CUSTOM_RESERVE_RTC_SIZE
#define CONFIG_BOOTLOADER_CUSTOM_RESERVE_RTC_SIZE 0x10
#endif

#define DMESH_BOOT_HEALTH_MAGIC 0x48u
#define DMESH_BOOT_HEALTH_GENERATION 2u
#define DMESH_BOOT_HEALTH_MAIN_START 1u
#define DMESH_BOOT_HEALTH_MAIN_OK 2u
#define DMESH_BOOT_HEALTH_RECOVERY_START 3u
#define DMESH_BOOT_HEALTH_RECOVERY_OK 4u

#define DMESH_RTC_RETAIN_RAW_SIZE \
    (((12 + CONFIG_BOOTLOADER_CUSTOM_RESERVE_RTC_SIZE + 4 + 7) / 8) * 8)
#define DMESH_RTC_CUSTOM_OFFSET 12
#define DMESH_RTC_HEALTH_EVENT_OFFSET \
    (DMESH_RTC_CUSTOM_OFFSET + 4)

#if ESP_ROM_HAS_LP_ROM
#define DMESH_RTC_RETAIN_BASE SOC_RTC_DRAM_LOW
#else
#define DMESH_RTC_RETAIN_BASE \
    (SOC_RTC_DRAM_HIGH - DMESH_RTC_RETAIN_RAW_SIZE)
#endif

#define DMESH_RTC_HEALTH_EVENT \
    (*(volatile uint8_t *)(DMESH_RTC_RETAIN_BASE + DMESH_RTC_HEALTH_EVENT_OFFSET))

static inline void dmesh_boot_health_write(uint8_t event)
{
    DMESH_RTC_HEALTH_EVENT = event;
}
