#pragma once

#include <stdbool.h>
#include <stdint.h>

// Arm the negotiated, device-first TCP flash session. An empty remote_ip
// makes the device listen; otherwise it connects to the numeric IPv4 host.
// The negotiated manifest supplies the target and image size.
bool dmesh_flash_tcp_start(uint16_t port, const char *remote_ip);
void dmesh_flash_tcp_poll(void);
bool dmesh_flash_tcp_accept(void);
bool dmesh_flash_tcp_finished(void);
