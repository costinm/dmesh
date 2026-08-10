#pragma once

/* Copy of the tiny stage2 wire encoder described by fw/boot/API.md. Keep
 * changes synchronized with the Recovery copy and the human-readable API. */

#include <stddef.h>
#include <stdint.h>

#define DMESH_BOOT_WIRE_FLAG 0x7e
#define DMESH_BOOT_WIRE_ESCAPE 0x7d
#define DMESH_BOOT_WIRE_ESCAPE_XOR 0x20
#define DMESH_BOOT_EVENT_IDENTITY 60000u
#define DMESH_BOOT_EVENT_RECOVERY_FAILED 60004u
#define DMESH_BOOT_METHOD_SELECT 60010u
#define DMESH_BOOT_ROLE_STAGE2 3
#define DMESH_BOOT_PARTITION_BOOTLOADER 0
#define DMESH_BOOT_PARTITION_MAIN 1
#define DMESH_BOOT_PARTITION_RECOVERY 2
#define DMESH_BOOT_HEALTH_HANDOFF_NORMAL 0u
#define DMESH_BOOT_HEALTH_HANDOFF_RECOVERY 1u
#define DMESH_BOOT_HEALTH_HANDOFF_MAIN 2u
#define DMESH_BOOT_HEALTH_MAIN_OK 2u
#ifndef DMESH_STAGE2_VERSION
#define DMESH_STAGE2_VERSION 0u
#endif

static inline size_t dmesh_boot_frame_encode(const uint8_t *payload, size_t length,
                                             uint8_t *out, size_t capacity)
{
    size_t cursor = 0;
    if (capacity == 0) return 0;
    out[cursor++] = DMESH_BOOT_WIRE_FLAG;
    for (size_t i = 0; i < length; ++i) {
        uint8_t byte = payload[i];
        if (byte == DMESH_BOOT_WIRE_FLAG || byte == DMESH_BOOT_WIRE_ESCAPE) {
            if (cursor + 2 >= capacity) return 0;
            out[cursor++] = DMESH_BOOT_WIRE_ESCAPE;
            out[cursor++] = byte ^ DMESH_BOOT_WIRE_ESCAPE_XOR;
        } else {
            if (cursor + 1 >= capacity) return 0;
            out[cursor++] = byte;
        }
    }
    if (cursor >= capacity) return 0;
    out[cursor++] = DMESH_BOOT_WIRE_FLAG;
    return cursor;
}

static inline size_t dmesh_cbor_put_uint(uint8_t *out, size_t capacity, uint64_t value)
{
    if (value < 24) {
        if (capacity == 0) return 0;
        out[0] = (uint8_t)value;
        return 1;
    }
    size_t width = value <= 0xff ? 1 : value <= 0xffff ? 2 :
                   value <= 0xffffffffu ? 4 : 8;
    if (capacity < width + 1) return 0;
    out[0] = (uint8_t)(width == 1 ? 24 : width == 2 ? 25 : width == 4 ? 26 : 27);
    for (size_t i = 0; i < width; ++i) out[width - i] = (uint8_t)(value >> (i * 8));
    return width + 1;
}

static inline size_t dmesh_boot_identity_event(uint8_t *payload, size_t capacity,
                                               uint8_t role, uint8_t partition,
                                               uint8_t reset_reason, uint8_t handoff,
                                               uint8_t main_failures, uint8_t recovery_failures,
                                               uint8_t recent_resets, uint64_t rtc_tick,
                                               const uint8_t mac[6])
{
    size_t cursor = 0, n;
    if (capacity < 1) return 0;
    payload[cursor++] = 0xbf;
    n = dmesh_cbor_put_uint(payload + cursor, capacity - cursor, 7); if (!n) return 0; cursor += n;
    n = dmesh_cbor_put_uint(payload + cursor, capacity - cursor, DMESH_BOOT_EVENT_IDENTITY); if (!n) return 0; cursor += n;
    n = dmesh_cbor_put_uint(payload + cursor, capacity - cursor, 6); if (!n) return 0; cursor += n;
    if (cursor + 1 > capacity) return 0;
    payload[cursor++] = 0x9f;
    uint64_t values[] = {role, partition, reset_reason, handoff, main_failures,
                         recovery_failures, recent_resets, rtc_tick,
                         DMESH_STAGE2_VERSION};
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        n = dmesh_cbor_put_uint(payload + cursor, capacity - cursor, values[i]);
        if (!n) return 0;
        cursor += n;
    }
    if (capacity - cursor < 8) return 0;
    payload[cursor++] = 0x46;
    for (size_t i = 0; i < 6; ++i) payload[cursor++] = mac[i];
    payload[cursor++] = 0xff;
    payload[cursor++] = 0xff;
    return cursor;
}

/* Identity uses indefinite-length CBOR while selectors use definite-length
 * CBOR intentionally; lmesh::radio::is_boot_identity_payload matches the
 * former wire shape. */
static inline size_t dmesh_boot_recovery_failed_event(uint8_t *payload,
                                                     size_t capacity,
                                                     uint8_t recovery_failures,
                                                     uint8_t main_failures)
{
    size_t cursor = 0, n;
    if (capacity < 1) return 0;
    payload[cursor++] = 0xbf;
    n = dmesh_cbor_put_uint(payload + cursor, capacity - cursor, 7); if (!n) return 0; cursor += n;
    n = dmesh_cbor_put_uint(payload + cursor, capacity - cursor, DMESH_BOOT_EVENT_RECOVERY_FAILED); if (!n) return 0; cursor += n;
    n = dmesh_cbor_put_uint(payload + cursor, capacity - cursor, 6); if (!n) return 0; cursor += n;
    if (capacity - cursor < 4) return 0;
    payload[cursor++] = 0x9f;
    n = dmesh_cbor_put_uint(payload + cursor, capacity - cursor, DMESH_BOOT_ROLE_STAGE2); if (!n) return 0; cursor += n;
    n = dmesh_cbor_put_uint(payload + cursor, capacity - cursor, DMESH_BOOT_PARTITION_RECOVERY); if (!n) return 0; cursor += n;
    n = dmesh_cbor_put_uint(payload + cursor, capacity - cursor, recovery_failures); if (!n) return 0; cursor += n;
    n = dmesh_cbor_put_uint(payload + cursor, capacity - cursor, main_failures); if (!n) return 0; cursor += n;
    payload[cursor++] = 0xff;
    payload[cursor++] = 0xff;
    return cursor;
}
