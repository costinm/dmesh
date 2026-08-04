/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

/* The final sector of the fixed 4 MiB data area is reserved for the boot
 * selector. It is outside the FAT data range used by Main. The journal is
 * intentionally tiny and append-only so a reset does not require an NVS
 * commit or a sector erase on every boot. */
#define DMESH_BOOT_JOURNAL_OFFSET 0x3ff000u
#define DMESH_BOOT_JOURNAL_SECTOR_SIZE 0x1000u
#define DMESH_BOOT_JOURNAL_BYTE_OFFSET DMESH_BOOT_JOURNAL_OFFSET

/* Main calls this only after it reaches its healthy point. The implementation
 * is a no-op when the journal is already clear. */
void dmesh_boot_journal_clear(void);
