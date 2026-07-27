#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t dmesh_nimble_init(void);
int32_t dmesh_nimble_start_advertising(const uint8_t *adv, uint8_t adv_len,
                                       uint16_t min_units, uint16_t max_units);
int32_t dmesh_nimble_stop_advertising(void);
int32_t dmesh_nimble_notify(const uint8_t *data, uint16_t len);
int32_t dmesh_nimble_clear_bonds(void);
uint16_t dmesh_nimble_tx_handle(void);
uint16_t dmesh_nimble_rx_handle(void);
int32_t dmesh_nimble_enable_sleep(void);
int32_t dmesh_nimble_disable_sleep(void);

void dmesh_nimble_on_ready(const uint8_t *addr, uint8_t addr_type);
void dmesh_nimble_on_connect(uint16_t conn_handle, const uint8_t *addr,
                             uint8_t encrypted, uint8_t authenticated,
                             uint8_t bonded);
void dmesh_nimble_on_disconnect(uint16_t reason);
void dmesh_nimble_on_subscribe(uint16_t attr_handle, uint8_t notify);
void dmesh_nimble_on_write(const uint8_t *data, uint16_t len);
void dmesh_nimble_on_log(const char *line);

#ifdef __cplusplus
}
#endif
