/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sdkconfig.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_rom_uart.h"
#include "esp_rom_sys.h"
#include "esp_rom_gpio.h"
#include "bootloader_init.h"
#include "bootloader_utility.h"
#include "bootloader_common.h"
#include "nvs_bootloader.h"

#define RECOVERY_INDEX FACTORY_INDEX
#define MAIN_INDEX 0
#define RECOVERY_NAMESPACE "recovery"
#define REQUEST_MAGIC 0x52455131u /* REQ1 */
#define BUTTON_GPIO 0
#define BUTTON_HOLD_SECONDS 3
#define UART_BOOT_WINDOW_MS 3000
#define RESET_LIMIT 3

static const char *TAG = "dmesh-boot";

static bool read_u32(const char *key, uint32_t *value)
{
    char text[24] = {0};
    nvs_bootloader_read_list_t item = {
        .namespace_name = RECOVERY_NAMESPACE,
        .key_name = key,
        .value_type = NVS_TYPE_STR,
        .value.str_val = {
            .buff_ptr = text,
            .buff_len = sizeof(text),
        },
    };
    if (nvs_bootloader_read("nvs", 1, &item) == ESP_OK &&
        item.result_code == ESP_OK) {
        char *end = NULL;
        unsigned long parsed = strtoul(text, &end, 0);
        if (end != text && *end == '\0' && parsed <= UINT32_MAX) {
            *value = (uint32_t)parsed;
            return true;
        }
    }

    item.value_type = NVS_TYPE_U32;
    if (nvs_bootloader_read("nvs", 1, &item) == ESP_OK &&
        item.result_code == ESP_OK) {
        *value = item.value.u32_val;
        return true;
    }
    return false;
}

static bool recovery_requested(void)
{
    uint32_t magic = 0;
    uint32_t version = 0;
    if (!read_u32("request_magic", &magic) ||
        !read_u32("request_version", &version)) {
        return false;
    }
    return magic == REQUEST_MAGIC && version == 1;
}

static bool recovery_button_held(void)
{
    return bootloader_common_check_long_hold_gpio_level(
               BUTTON_GPIO, BUTTON_HOLD_SECONDS, false) == GPIO_LONG_HOLD;
}

static bool uart_boot_requested(void)
{
    static const char wanted[] = "BOOT";
    size_t matched = 0;
    const uint32_t polls = UART_BOOT_WINDOW_MS * 1000;

    for (uint32_t poll = 0; poll < polls; ++poll) {
        uint8_t byte = 0;
        if (esp_rom_output_rx_one_char(&byte) == 0) {
            if (byte == (uint8_t)wanted[matched]) {
                ++matched;
                if (matched == sizeof(wanted) - 1) {
                    return true;
                }
            } else {
                matched = byte == (uint8_t)wanted[0] ? 1 : 0;
            }
        }
        esp_rom_delay_us(1);
    }
    return false;
}

static bool crash_loop(void)
{
#if CONFIG_BOOTLOADER_RESERVE_RTC_MEM
    return bootloader_common_get_rtc_retain_mem_reboot_counter() >= RESET_LIMIT;
#else
    return false;
#endif
}

static int select_partition(void)
{
    bool button = recovery_button_held();
    bool uart = uart_boot_requested();
    bool request = recovery_requested();
    bool loop = crash_loop();

    ESP_LOGI(TAG, "select recovery=%d button=%d uart=%d request=%d crash_loop=%d",
             button || uart || request || loop, button, uart, request, loop);

    if (button || uart || request || loop) {
        return RECOVERY_INDEX;
    }

#if CONFIG_BOOTLOADER_RESERVE_RTC_MEM
    bootloader_common_update_rtc_retain_mem(NULL, true);
#endif
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

    bootloader_utility_load_boot_image(&bs, select_partition());
    bootloader_reset();
}

#if CONFIG_LIBC_NEWLIB
struct _reent *__getreent(void)
{
    return _GLOBAL_REENT;
}
#endif
