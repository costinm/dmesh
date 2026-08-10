#pragma once

#include <stdbool.h>
#include <stdint.h>

// Arm the negotiated, device-first TCP flash session. An empty remote_ip
// makes the device listen; otherwise it connects to the numeric IPv4 host.
// The negotiated manifest supplies the target and image size.
bool dmesh_flash_tcp_start(uint16_t port, const char *remote_ip);
// Extended form: request a target from the host server.  `target` is one of
// boot, stage2, partition, recovery, nvs, data, main, or module.  For module,
// `module` is the DMOD name (for example hello or lora). `dry_run` requests
// manifest/block verification without erasing or writing flash.
bool dmesh_flash_tcp_start_target(uint16_t port, const char *remote_ip,
                                  const char *target, const char *module,
                                  bool dry_run);
// Clear the completion result from a prior session before asynchronously
// starting a new one. Returns false if a worker is still active.
bool dmesh_flash_tcp_prepare(void);
void dmesh_flash_tcp_poll(void);
bool dmesh_flash_tcp_accept(void);
bool dmesh_flash_tcp_finished(void);
// True only while a negotiated worker is actually pending. An IP STA may be
// active for a module dry-run without a Recovery flash worker being active.
bool dmesh_flash_tcp_active(void);
