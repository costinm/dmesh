#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t dmesh_nimble_init(void);
int32_t dmesh_nimble_start_scan(uint32_t duration_ms);
int32_t dmesh_nimble_stop_scan(void);
int32_t dmesh_nimble_start_advertising(const uint8_t *adv, uint8_t adv_len,
                                        uint16_t min_units, uint16_t max_units);
int32_t dmesh_nimble_stop_advertising(void);
int32_t dmesh_nimble_stop_service(void);
int32_t dmesh_nimble_start_coc_server(uint16_t psm);
int32_t dmesh_nimble_connect_coc(const uint8_t *peer_addr, uint8_t peer_addr_type,
                                 uint16_t psm);
int32_t dmesh_nimble_coc_send(const uint8_t *data, uint16_t len);
int32_t dmesh_nimble_coc_tx_pending(void);

void dmesh_nimble_on_ready(const uint8_t *addr, uint8_t addr_type);
void dmesh_nimble_on_connect(uint16_t conn_handle);
void dmesh_nimble_on_disconnect(uint16_t reason);
void dmesh_nimble_on_coc_write(const uint8_t *data, uint16_t len);
void dmesh_nimble_on_coc_state(uint8_t connected);
void dmesh_nimble_on_coc_tx_ready(void);
void dmesh_nimble_on_scan_result(uint8_t addr_type, const uint8_t *addr,
                                 int rssi, uint8_t matched);
void dmesh_nimble_on_scan_state(uint8_t scanning);
void dmesh_nimble_on_auth_complete(uint8_t bonded);
void dmesh_nimble_on_log(const char *line);

#ifdef __cplusplus
}
#endif
