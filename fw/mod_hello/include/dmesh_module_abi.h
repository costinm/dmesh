#pragma once

#include <stddef.h>
#include <stdint.h>

#include "dmesh_lora_abi.h"
#include "../../modules/include/dmesh_hw_abi.h"
#include "../../mod_flash/include/dmesh_flash_abi.h"

#define DMESH_MODULE_ABI_VERSION 4u
#define DMESH_MODULE_MAGIC 0x444f4d44u
#define DMESH_MODULE_HEADER_SIZE 64u
#define DMESH_MODULE_FLAG_FIXED_VMA (1u << 0)

typedef int (*dmesh_module_log_line_fn)(void *user, const uint8_t *data, size_t len);
typedef int (*dmesh_module_call_service_fn)(void *user, uint16_t service_tag,
                                            const uint8_t *payload, size_t payload_len,
                                            uint8_t *response, size_t response_capacity,
                                            size_t *response_len, uint32_t timeout_ms);
typedef int (*dmesh_module_get_setting_fn)(void *user, const uint8_t *key, size_t key_len,
                                           uint8_t *value, size_t value_capacity,
                                           size_t *value_len);
typedef int (*dmesh_module_set_setting_fn)(void *user, const uint8_t *key, size_t key_len,
                                           const uint8_t *value, size_t value_len);
enum {
    DMESH_MODULE_EVENT_EMPTY = 0,
    DMESH_MODULE_EVENT_U64 = 1,
    DMESH_MODULE_EVENT_I64 = 2,
    DMESH_MODULE_EVENT_BYTES = 3,
    DMESH_MODULE_EVENT_TEXT = 4,
    DMESH_MODULE_EVENT_CBOR = 5,
};
typedef struct {
    uint16_t event_id;
    uint8_t value_type;
    uint8_t flags;
    const uint8_t *value;
    size_t value_len;
} dmesh_module_event_v1;
typedef int (*dmesh_module_emit_event_fn)(void *user,
                                          const dmesh_module_event_v1 *event);
typedef void *(*dmesh_module_alloc_fn)(void *user, size_t size, size_t align);

typedef struct dmesh_module_host_v1 dmesh_module_host_v1;
typedef struct {
    uint32_t abi_version;
    uint32_t size;
    void *user;
    dmesh_module_log_line_fn log_line;
    dmesh_module_call_service_fn call_service;
    dmesh_module_get_setting_fn get_setting;
    dmesh_module_set_setting_fn set_setting;
    dmesh_module_emit_event_fn emit_event;
    const dmesh_lora_host_v1 *lora_host;
    const dmesh_lora_config_v1 *lora_config;
    const dmesh_module_host_v1 *host;
    /* Additive; older modules validate only the prefix above. */
    const dmesh_flash_host_v1 *flash_host;
} dmesh_module_context_t;

typedef int (*dmesh_module_entry_fn)(const dmesh_module_context_t *context,
                                     const uint8_t *payload, size_t payload_len,
                                     const uint8_t *args, size_t args_len);

typedef struct dmesh_module_host_v1 {
    uint32_t abi_version;
    uint32_t size;
    uint32_t features;
    void *user;
    dmesh_module_log_line_fn log_line;
    dmesh_module_call_service_fn call_service;
    dmesh_module_get_setting_fn get_setting;
    dmesh_module_set_setting_fn set_setting;
    dmesh_module_emit_event_fn emit_event;
    const dmesh_hw_host_v1 *hw;
    /* Main-owned transient bump allocation. No free; pointers expire when
     * the module invocation/task is stopped. */
    dmesh_module_alloc_fn alloc;
} dmesh_module_host_v1;

/* Numeric-only DMOD header. Human service names are schema/controller data. */
typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t abi_version;
    uint16_t header_size;
    uint32_t entry_offset;
    uint32_t image_size;
    uint16_t service_tag;
    uint16_t slot_count;
    uint32_t code_vma;
    uint32_t data_vma;
    uint32_t required_stack_words;
    uint32_t required_host_features;
    uint32_t flags;
    uint8_t reserved[24];
} dmesh_module_header_t;
