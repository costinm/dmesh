#include "dmesh_wifi_filter.h"

#include "esp_err.h"

/* Internal libpp symbols. Their implementation programs the MAC BSSID
 * comparator, avoiding a software-only discard after the RX DMA path. */
extern void ic_set_bssid(uint8_t interface_id, uint8_t *bssid);
extern void ic_rx_enable_bssid_check(uint8_t interface_id);
extern void ic_rx_disable_bssid_check(uint8_t interface_id);
/* The BSSID comparator is gated by this receive-policy bit in libpp.  Merely
 * enabling the comparator leaves promiscuous RX unchanged on current IDF
 * builds, which is why this must be set alongside the check hook. */
extern bool ic_set_rx_policy_ubssid_check(uint8_t interface_id, uint8_t enabled);

static bool valid_interface(uint8_t interface_id)
{
    return interface_id <= DMESH_WIFI_FILTER_IF_NAN;
}

int dmesh_wifi_filter_set_bssid(uint8_t interface_id,
                                const uint8_t bssid[6],
                                bool enabled)
{
    if (!valid_interface(interface_id) || bssid == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    ic_set_bssid(interface_id, (uint8_t *)bssid);
    (void)ic_set_rx_policy_ubssid_check(interface_id, enabled ? 1 : 0);
    if (enabled) {
        ic_rx_enable_bssid_check(interface_id);
    } else {
        ic_rx_disable_bssid_check(interface_id);
    }
    return ESP_OK;
}

bool dmesh_wifi_filter_supported(void)
{
    return true;
}
