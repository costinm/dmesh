#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dmesh_lora_abi.h"

bool dmesh_module_flash_supported(void);
void dmesh_module_loader_init(void);
bool dmesh_module_loader_header_valid(void);
bool dmesh_module_loader_is_lora(void);
uint32_t dmesh_module_loader_offset(void);
uint32_t dmesh_module_loader_image_size(void);
uint32_t dmesh_module_loader_required_stack_words(void);
int dmesh_module_lora_configure(const dmesh_lora_config_v1 *config);
/* Update the immutable module-facing configuration without tearing down the
 * SPI bus. The caller should queue a `reconfigure` command afterwards. */
int dmesh_module_lora_update_config(const dmesh_lora_config_v1 *config);
int dmesh_module_lora_command(const uint8_t *args, size_t args_len,
                              const uint8_t *payload, size_t payload_len);
/* Stop an executing module before the flash transport erases its raw data
 * region. Returns false if the task does not quiesce within timeout_ms. */
bool dmesh_module_loader_prepare_flash(uint32_t timeout_ms);
bool dmesh_module_loader_task_done(void);
int dmesh_module_loader_last_result(void);
uint32_t dmesh_module_loader_runtime_ms(void);
uint32_t dmesh_module_loader_max_runtime_ms(void);
uint32_t dmesh_module_loader_task_runs(void);
uint32_t dmesh_module_loader_stack_high_water_words(void);
bool dmesh_module_psram_exec_supported(void);
const char *dmesh_module_psram_exec_reason(void);
int dmesh_module_start_task(const char *name, uint32_t offset, uint32_t size,
                            const uint8_t *payload, size_t payload_len,
                            const uint8_t *args, size_t args_len);
