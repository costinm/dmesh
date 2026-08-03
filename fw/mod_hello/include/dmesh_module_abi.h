#pragma once

#include <stddef.h>
#include <stdint.h>

#include "dmesh_lora_abi.h"

#define DMESH_MODULE_ABI_VERSION 1u
#define DMESH_MODULE_MAGIC 0x444f4d44u /* little-endian bytes: DMOD */
#define DMESH_MODULE_HEADER_SIZE 64u

typedef int (*dmesh_module_log_line_fn)(void *user, const uint8_t *data, size_t len);
/* Queues a command for Main's serialized command registry. The return value
 * only reports whether it was queued; command completion is asynchronous. */
typedef int (*dmesh_module_call_service_fn)(void *user,
                                            const uint8_t *service, size_t service_len,
                                            const uint8_t *payload, size_t payload_len,
                                            const uint8_t *args, size_t args_len);

typedef struct {
    uint32_t abi_version;
    uint32_t size;
    void *user;
    dmesh_module_log_line_fn log_line;
    dmesh_module_call_service_fn call_service;
    const dmesh_lora_host_v1 *lora_host;
} dmesh_module_context_t;

typedef int (*dmesh_module_entry_fn)(const dmesh_module_context_t *context,
                                     const uint8_t *payload, size_t payload_len,
                                     const uint8_t *args, size_t args_len);

/* Little-endian, fixed-size wrapper prepended to the position-independent
 * module code. The flat payload starts at entry_offset. */
typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t abi_version;
    uint16_t header_size;
    uint32_t entry_offset;
    uint32_t image_size;
    char name[16];
    uint8_t reserved[32];
} dmesh_module_header_t;
