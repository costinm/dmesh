#pragma once

/* Copy of the tiny Recovery wire encoder described by fw/boot/API.md. Keep
 * schema IDs and tuple order synchronized with the stage2 copy. */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define DMESH_BOOT_WIRE_FLAG 0x7e
#define DMESH_BOOT_WIRE_ESCAPE 0x7d
#define DMESH_BOOT_WIRE_ESCAPE_XOR 0x20
#define DMESH_BOOT_EVENT_IDENTITY 60000u
#define DMESH_BOOT_EVENT_RECOVERY_FAILED 60004u
#define DMESH_BOOT_EVENT_FLASH_COMPLETE 60001u
#define DMESH_BOOT_EVENT_FLASH_ERROR 60002u
#define DMESH_BOOT_EVENT_NETWORK_UP 60003u
#define DMESH_BOOT_ROLE_RECOVERY 2
#define DMESH_BOOT_PARTITION_RECOVERY 2
#define DMESH_BOOT_HEALTH_HANDOFF_MAIN 2u
#define DMESH_BOOT_HEALTH_HANDOFF_RECOVERY 1u

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

static inline size_t dmesh_cbor_put_head(uint8_t *out, size_t capacity,
                                         uint8_t major, uint64_t value)
{
    if (value < 24) {
        if (capacity == 0) return 0;
        out[0] = (uint8_t)((major << 5) | value);
        return 1;
    }
    size_t width = value <= 0xff ? 1 : value <= 0xffff ? 2 :
                   value <= 0xffffffffu ? 4 : 8;
    if (capacity < width + 1) return 0;
    out[0] = (uint8_t)((major << 5) | (width == 1 ? 24 : width == 2 ? 25 : width == 4 ? 26 : 27));
    for (size_t i = 0; i < width; ++i) out[width - i] = (uint8_t)(value >> (i * 8));
    return width + 1;
}

static inline size_t dmesh_cbor_put_uint(uint8_t *out, size_t capacity, uint64_t value)
{
    return dmesh_cbor_put_head(out, capacity, 0, value);
}

static inline size_t dmesh_cbor_put_int(uint8_t *out, size_t capacity, int64_t value)
{
    return value >= 0 ? dmesh_cbor_put_uint(out, capacity, (uint64_t)value) :
           dmesh_cbor_put_head(out, capacity, 1, (uint64_t)(-1 - value));
}

static inline size_t dmesh_cbor_put_bytes(uint8_t *out, size_t capacity,
                                          const uint8_t *data, size_t length)
{
    size_t head = dmesh_cbor_put_head(out, capacity, 2, length);
    if (head == 0 || capacity - head < length) return 0;
    memcpy(out + head, data, length);
    return head + length;
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
                         recovery_failures, recent_resets, rtc_tick};
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        n = dmesh_cbor_put_uint(payload + cursor, capacity - cursor, values[i]);
        if (!n) return 0;
        cursor += n;
    }
    n = dmesh_cbor_put_bytes(payload + cursor, capacity - cursor, mac, 6);
    if (!n) return 0;
    cursor += n;
    if (cursor + 2 > capacity) return 0;
    payload[cursor++] = 0xff; payload[cursor++] = 0xff;
    return cursor;
}

static inline size_t dmesh_boot_flash_event_encode(uint8_t *payload, size_t capacity,
                                                   uint64_t event_id, uint8_t role,
                                                   uint8_t target, uint32_t blocks,
                                                   uint32_t received, uint32_t bytes,
                                                   uint32_t elapsed_ms, uint32_t speed_bps,
                                                   const uint8_t *error, size_t error_length)
{
    size_t cursor = 0, n;
    if (capacity < 1) return 0;
    payload[cursor++] = 0xbf;
    n = dmesh_cbor_put_uint(payload + cursor, capacity - cursor, 7); if (!n) return 0; cursor += n;
    n = dmesh_cbor_put_uint(payload + cursor, capacity - cursor, event_id); if (!n) return 0; cursor += n;
    n = dmesh_cbor_put_uint(payload + cursor, capacity - cursor, 6); if (!n) return 0; cursor += n;
    if (cursor + 1 > capacity) return 0;
    payload[cursor++] = 0x9f;
    uint64_t values[] = {role, target, blocks, received, bytes, elapsed_ms, speed_bps};
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        n = dmesh_cbor_put_uint(payload + cursor, capacity - cursor, values[i]);
        if (!n) return 0;
        cursor += n;
    }
    if (error != NULL && error_length != 0) {
        n = dmesh_cbor_put_bytes(payload + cursor, capacity - cursor, error, error_length);
        if (!n) return 0;
        cursor += n;
    }
    if (cursor + 2 > capacity) return 0;
    payload[cursor++] = 0xff; payload[cursor++] = 0xff;
    return cursor;
}
