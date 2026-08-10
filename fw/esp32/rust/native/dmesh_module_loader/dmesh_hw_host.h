#pragma once

#include "dmesh_hw_abi.h"

extern dmesh_hw_host_v1 dmesh_hw_host;
void dmesh_hw_host_reset(void);
void dmesh_hw_host_request_stop(bool stop);
void dmesh_hw_host_set_spi(int (*transfer)(void *user, const uint8_t *tx,
                                           uint8_t *rx, size_t len));
