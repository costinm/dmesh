#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Small, target-specific wrapper around Espressif's internal RX filter hooks.
 * These symbols are present in the ESP-IDF Wi-Fi binary for the supported
 * ESP32, ESP32-S3, and ESP32-C6 targets, but are not a public API. */

enum {
    DMESH_WIFI_FILTER_IF_STA = 0,
    DMESH_WIFI_FILTER_IF_AP = 1,
    DMESH_WIFI_FILTER_IF_NAN = 2,
};

/* The Wi-Fi driver must already be initialized when this is called. */
int dmesh_wifi_filter_set_bssid(uint8_t interface_id,
                                const uint8_t bssid[6],
                                bool enabled);

bool dmesh_wifi_filter_supported(void);
