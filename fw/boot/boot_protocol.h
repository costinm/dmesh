/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

/*
 * Small boot handoff protocol.  It deliberately has no serializer: these
 * bytes are a stable, fixed layout which can also be interpreted as a
 * compact CBOR-like record by higher layers.  PPP/HDLC framing is used only
 * on the UART, where it provides delimiters and escaping.  TCP uses DRS2's
 * length-prefixed frames instead.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DMESH_BOOT_WIRE_FLAG 0x7e
#define DMESH_BOOT_WIRE_ESCAPE 0x7d
#define DMESH_BOOT_WIRE_ESCAPE_XOR 0x20
#define DMESH_BOOT_MAGIC_0 'D'
#define DMESH_BOOT_MAGIC_1 'M'
#define DMESH_BOOT_MAGIC_2 'B'
#define DMESH_BOOT_MAGIC_3 '1'
#define DMESH_BOOT_VERSION 1
#define DMESH_BOOT_KIND_HELLO 1
#define DMESH_BOOT_KIND_COMMAND 2
#define DMESH_BOOT_COMMAND_RECOVERY 1
#define DMESH_BOOT_COMMAND_STA 2
#define DMESH_BOOT_ROLE_STAGE2 3
#define DMESH_BOOT_ROLE_MAIN 1
#define DMESH_BOOT_ROLE_RECOVERY 2
#define DMESH_BOOT_PARTITION_MAIN 1
#define DMESH_BOOT_PARTITION_RECOVERY 2
#define DMESH_BOOT_PARTITION_BOOTLOADER 0

#define DMESH_BOOT_HELLO_LEN 18
#define DMESH_BOOT_COMMAND_LEN 8
/* DMB1 command packet for Recovery's open-STA handoff.  The four length
 * bytes are followed by endpoint, local IPv4, SSID, and password bytes. */
#define DMESH_BOOT_STA_HEADER_LEN 11

static inline bool dmesh_boot_is_magic(const uint8_t *p, size_t length)
{
    return length >= 4 && p[0] == DMESH_BOOT_MAGIC_0 &&
           p[1] == DMESH_BOOT_MAGIC_1 && p[2] == DMESH_BOOT_MAGIC_2 &&
           p[3] == DMESH_BOOT_MAGIC_3;
}

static inline size_t dmesh_boot_frame_encode(const uint8_t *payload,
                                             size_t length, uint8_t *out,
                                             size_t capacity)
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
