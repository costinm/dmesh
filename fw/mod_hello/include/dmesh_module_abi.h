#pragma once

#include <stddef.h>
#include <stdint.h>

#include "dmesh_lora_abi.h"

#define DMESH_MODULE_ABI_VERSION 2u
#define DMESH_MODULE_MAGIC 0x444f4d44u /* little-endian bytes: DMOD */
#define DMESH_MODULE_HEADER_SIZE 64u
#define DMESH_MODULE_FLAG_FIXED_VMA (1u << 0)

typedef int (*dmesh_module_log_line_fn)(void *user, const uint8_t *data, size_t len);
/* Queues a command for Main's serialized command registry. The return value
 * only reports whether it was queued; command completion is asynchronous.
 * Module-originated callbacks are bounded/non-blocking; a busy queue may
 * return a negative result and the module may retry later. */
typedef int (*dmesh_module_call_service_fn)(void *user,
                                            const uint8_t *service, size_t service_len,
                                            const uint8_t *payload, size_t payload_len,
                                            const uint8_t *args, size_t args_len);

typedef int (*dmesh_module_get_setting_fn)(void *user,
                                           const uint8_t *key, size_t key_len,
                                           uint8_t *value, size_t value_capacity,
                                           size_t *value_len);
typedef int (*dmesh_module_set_setting_fn)(void *user,
                                           const uint8_t *key, size_t key_len,
                                           const uint8_t *value, size_t value_len);
enum {
    DMESH_MODULE_EVENT_EMPTY = 0,
    DMESH_MODULE_EVENT_U64 = 1,
    DMESH_MODULE_EVENT_I64 = 2,
    DMESH_MODULE_EVENT_BYTES = 3,
    DMESH_MODULE_EVENT_TEXT = 4,
};
typedef struct {
    uint16_t event_id;
    uint8_t value_type;
    uint8_t flags;
    const uint8_t *value;
    size_t value_len;
} dmesh_module_event_v1;
#if UINTPTR_MAX == 0xffffffffu
_Static_assert(sizeof(dmesh_module_event_v1) == 12, "dmesh_module_event_v1 ABI size");
#endif
typedef int (*dmesh_module_emit_event_fn)(void *user,
                                          const dmesh_module_event_v1 *event);

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
} dmesh_module_context_t;

#if UINTPTR_MAX == 0xffffffffu
 _Static_assert(sizeof(dmesh_module_context_t) == 40, "dmesh_module_context_t ABI size");
#endif

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
    /* FreeRTOS stack depth requested by the module, in words. The loader
     * clamps this to its supported bounds before creating the task. */
    uint32_t required_stack_words;
    /* Reserved for host feature negotiation and module flags. */
    uint32_t required_host_features;
    uint32_t flags;
    uint8_t reserved[20];
} dmesh_module_header_t;
