#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool dmesh_module_flash_supported(void);
void dmesh_module_loader_init(void);
bool dmesh_module_loader_header_valid(void);
bool dmesh_module_loader_task_done(void);
int dmesh_module_loader_last_result(void);
bool dmesh_module_psram_exec_supported(void);
const char *dmesh_module_psram_exec_reason(void);
int dmesh_module_start_task(const char *name, uint32_t offset, uint32_t size,
                            const uint8_t *payload, size_t payload_len,
                            const uint8_t *args, size_t args_len);
