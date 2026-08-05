/* SPDX-License-Identifier: Apache-2.0 */
#include "boot_health_flash.h"

#include "esp_flash.h"

void dmesh_boot_journal_clear(void)
{
    uint32_t word = UINT32_MAX;
    if (esp_flash_read(NULL, &word, DMESH_BOOT_JOURNAL_BYTE_OFFSET, sizeof(word)) != ESP_OK ||
        (uint8_t)word == 0xff) {
        return;
    }
    (void)esp_flash_erase_region(NULL, DMESH_BOOT_JOURNAL_OFFSET,
                                 DMESH_BOOT_JOURNAL_SECTOR_SIZE);
}
