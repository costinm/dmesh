/* SPDX-License-Identifier: Apache-2.0 */
#include "boot_health_rtc.h"
#include <stdbool.h>

void dmesh_boot_health_set(uint8_t event)
{
    dmesh_boot_health_write(event);
}

void dmesh_boot_handoff_set(uint8_t handoff)
{
    dmesh_boot_handoff_write(handoff);
}

void dmesh_boot_dry_run_set(bool dry_run)
{
    dmesh_boot_dry_run_write(dry_run);
}
