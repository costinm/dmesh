/* SPDX-License-Identifier: Apache-2.0 */
#include "boot_health_rtc.h"
#include "boot_health_flash.h"

void dmesh_boot_health_set(uint8_t event)
{
    dmesh_boot_health_write(event);
    if (event == DMESH_BOOT_HEALTH_MAIN_OK ||
        event == DMESH_BOOT_HEALTH_RECOVERY_OK) {
        dmesh_boot_journal_clear();
    }
}
