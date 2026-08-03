/* SPDX-License-Identifier: Apache-2.0 */
#include "boot_health_rtc.h"

void dmesh_boot_health_set(uint8_t event)
{
    dmesh_boot_health_write(event);
}
