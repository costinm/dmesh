#include "dmesh_flash_tcp.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include "esp_chip_info.h"
#include "esp_private/esp_clk.h"
#include "esp_err.h"
#include "esp_flash.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "esp_mac.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"
#include "nvs.h"

#define TAG "dmesh-flash"
#define PROTOCOL_MAGIC 0x44525332u /* DRS2 */
#define PROTOCOL_VERSION 1u
#define FRAME_HELLO 1u
#define FRAME_READ_PARTITION_TABLE 2u
#define FRAME_PARTITION_TABLE 3u
#define FRAME_HASH_QUERY 4u
#define FRAME_HASH_LIST 5u
#define FRAME_MANIFEST 6u
#define FRAME_MISSING 7u
#define FRAME_BLOCK 8u
#define FRAME_ACK 9u
#define FRAME_DONE 10u
#define FRAME_READ_BLOCK 11u
#define FRAME_BLOCK_DATA 12u
#define FRAME_SPARSE_MANIFEST 13u
#define FRAME_MANIFEST_READY 14u
#define FRAME_FAST_UNSIGNED 15u
#define FRAME_FAST_READY 16u
#define FRAME_ERROR 255u

#define TARGET_BOOT 1u
#define TARGET_PARTITION 2u
#define TARGET_RECOVERY 3u
#define TARGET_NVS 4u
#define TARGET_DATA 5u
#define TARGET_MAIN 6u
#define TARGET_MODULE 7u
#define BOOT_LIMIT 0x7000u
#define PARTITION_LIMIT 0x1000u
#define BOOT_HEAP_STACK 8192
#define BLOCK_SIZE 4096u
#define MAX_BLOCKS 1024u
#define PARTITION_TABLE_SIZE 0x1000u
#define DATA_PARTITION_START 0x3c0000u
#define TRUST_KEY_SIZE 65u
#define TRUST_NAMESPACE "recovery"
#define CONNECT_RETRY_COUNT 150u /* 30 seconds at 200 ms per attempt */
#define CONNECT_RETRY_DELAY_MS 200u

#if defined(DMESH_FLASH_ROLE_RECOVERY)
#define FLASH_ROLE 2u
#define FLASH_PARTITION 2u
#else
#define FLASH_ROLE 1u
#define FLASH_PARTITION 1u
#endif

#if CONFIG_IDF_TARGET_ESP32
#define BOOT_FLASH_ADDRESS 0x1000u
#else
#define BOOT_FLASH_ADDRESS 0x0u
#endif

typedef struct {
    uint16_t port;
    int listener;
    char remote_ip[16];
} flash_job_t;

typedef struct {
    uint8_t target;
    uint32_t start;
    uint32_t block_size;
    uint32_t count;
    uint32_t image_size;
    const esp_partition_t *partition;
    esp_partition_t raw_partition;
    uint8_t partition_sha[32];
    uint8_t image_sha[32];
    uint8_t key_fp[32];
    uint8_t *hashes;
    bool no_ack;
    uint32_t changed_count;
    uint32_t *indices;
    uint32_t *lengths;
    uint8_t *changed_hashes;
} manifest_t;

static flash_job_t active = {.listener = -1};
static volatile bool flash_pending;
static volatile bool flash_done;
static volatile bool flash_result;
static TaskHandle_t flash_task;

static uint32_t get_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void put_u32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24); p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8); p[3] = (uint8_t)value;
}

static bool recv_all(int fd, void *buffer, size_t length)
{
    uint8_t *cursor = (uint8_t *)buffer;
    while (length != 0) {
        int received = recv(fd, cursor, length, 0);
        if (received <= 0) return false;
        cursor += received;
        length -= (size_t)received;
    }
    return true;
}

static bool send_all(int fd, const void *buffer, size_t length)
{
    const uint8_t *cursor = (const uint8_t *)buffer;
    while (length != 0) {
        int sent = send(fd, cursor, length, 0);
        if (sent <= 0) return false;
        cursor += sent;
        length -= (size_t)sent;
    }
    return true;
}

static bool send_frame(int fd, uint16_t type, const void *payload, uint16_t length)
{
    uint8_t header[8];
    put_u32(header, PROTOCOL_MAGIC);
    header[4] = (uint8_t)(type >> 8); header[5] = (uint8_t)type;
    header[6] = (uint8_t)(length >> 8); header[7] = (uint8_t)length;
    return send_all(fd, header, sizeof(header)) &&
           (length == 0 || send_all(fd, payload, length));
}

static bool recv_frame(int fd, uint16_t *type, uint8_t **payload, uint16_t *length)
{
    uint8_t header[8];
    if (!recv_all(fd, header, sizeof(header)) || get_u32(header) != PROTOCOL_MAGIC) return false;
    *type = ((uint16_t)header[4] << 8) | header[5];
    if (*type == 0) return false;
    *length = ((uint16_t)header[6] << 8) | header[7];
    *payload = NULL;
    if (*length != 0) {
        *payload = malloc(*length);
        if (*payload == NULL || !recv_all(fd, *payload, *length)) {
            free(*payload); *payload = NULL; return false;
        }
    }
    return true;
}

static bool connect_remote(int fd, const char *address, uint16_t port)
{
    ESP_LOGI(TAG, "connect start remote=%s:%u retries=%u", address,
             (unsigned)port, (unsigned)CONNECT_RETRY_COUNT);
    struct sockaddr_in remote = {.sin_family = AF_INET, .sin_port = htons(port)};
    if (inet_aton(address, &remote.sin_addr) == 0) {
        ESP_LOGE(TAG, "connect invalid remote=%s", address);
        return false;
    }
    for (unsigned attempt = 0; attempt < CONNECT_RETRY_COUNT; ++attempt) {
        if (connect(fd, (struct sockaddr *)&remote, sizeof(remote)) == 0) {
            ESP_LOGI(TAG, "connect success attempt=%u", attempt + 1);
            return true;
        }
        int error = errno;
        if (attempt == 0 || ((attempt + 1) % 10u) == 0) {
            ESP_LOGW(TAG, "connect remote=%s:%u attempt=%u/%u errno=%d",
                     address, (unsigned)port, attempt + 1,
                     (unsigned)CONNECT_RETRY_COUNT, error);
        }
        vTaskDelay(pdMS_TO_TICKS(CONNECT_RETRY_DELAY_MS));
    }
    ESP_LOGE(TAG, "connect remote=%s:%u exhausted retries errno=%d", address,
             (unsigned)port, errno);
    return false;
}

static const esp_partition_t *partition_for(uint8_t target)
{
    if (target == TARGET_MAIN) {
        return esp_partition_find_first(ESP_PARTITION_TYPE_APP,
                                        ESP_PARTITION_SUBTYPE_ANY, "main");
    }
    if (target == TARGET_RECOVERY) {
        return esp_partition_find_first(ESP_PARTITION_TYPE_APP,
                                        ESP_PARTITION_SUBTYPE_APP_FACTORY,
                                        "recovery_app");
    }
    if (target == TARGET_NVS) {
        return esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
                                        ESP_PARTITION_SUBTYPE_DATA_NVS, "nvs");
    }
    return NULL;
}

static bool target_partition(uint8_t target, const esp_partition_t **out,
                             esp_partition_t *raw, uint32_t *limit)
{
    *out = NULL;
#if defined(DMESH_FLASH_ROLE_RECOVERY)
    /* Recovery executes from recovery_app.  Erasing or writing that
     * partition while it is running invalidates the code and can reset the
     * chip in the middle of the TCP session.  Main is the only component
     * allowed to update Recovery. */
    if (target == TARGET_RECOVERY) {
        ESP_LOGE(TAG, "refusing self-update of recovery_app");
        return false;
    }
#endif
    if (target == TARGET_BOOT || target == TARGET_PARTITION) {
        memset(raw, 0, sizeof(*raw));
        raw->flash_chip = esp_flash_default_chip;
        raw->type = ESP_PARTITION_TYPE_DATA;
        raw->subtype = ESP_PARTITION_SUBTYPE_ANY;
        raw->address = target == TARGET_BOOT ? BOOT_FLASH_ADDRESS : 0x8000;
        raw->size = target == TARGET_BOOT ? BOOT_LIMIT : PARTITION_LIMIT;
        raw->erase_size = 0x1000;
        raw->encrypted = false; raw->readonly = false;
        *out = raw; *limit = raw->size; return true;
    }
    if (target == TARGET_DATA || target == TARGET_MODULE) {
        uint32_t flash_size = 0;
        if (esp_flash_get_physical_size(NULL, &flash_size) != ESP_OK ||
            flash_size <= DATA_PARTITION_START) return false;
        memset(raw, 0, sizeof(*raw));
        raw->flash_chip = esp_flash_default_chip;
        raw->type = ESP_PARTITION_TYPE_DATA;
        raw->subtype = ESP_PARTITION_SUBTYPE_ANY;
        raw->address = DATA_PARTITION_START;
        raw->size = flash_size - DATA_PARTITION_START;
        raw->erase_size = 0x1000;
        raw->encrypted = false; raw->readonly = false;
        *out = raw; *limit = raw->size; return true;
    }
    *out = partition_for(target);
    if (*out == NULL) return false;
    *limit = (*out)->size;
    return true;
}

static bool sha256_partition(const esp_partition_t *partition, uint32_t offset,
                             uint32_t length, uint8_t digest[32])
{
    uint8_t buffer[BLOCK_SIZE];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    if (mbedtls_sha256_starts(&ctx, 0) != 0) return false;
    while (length != 0) {
        size_t part = length > sizeof(buffer) ? sizeof(buffer) : length;
        if (esp_partition_read(partition, offset, buffer, part) != ESP_OK ||
            mbedtls_sha256_update(&ctx, buffer, part) != 0) {
            mbedtls_sha256_free(&ctx); return false;
        }
        offset += (uint32_t)part; length -= (uint32_t)part;
    }
    bool ok = mbedtls_sha256_finish(&ctx, digest) == 0;
    mbedtls_sha256_free(&ctx); return ok;
}

static bool block_hash(const esp_partition_t *partition, uint32_t offset,
                       uint32_t length, uint8_t out[4])
{
    uint8_t digest[32];
    if (!sha256_partition(partition, offset, length, digest)) return false;
    memcpy(out, digest, 4); return true;
}

static int load_trust_key(uint8_t key[TRUST_KEY_SIZE])
{
    nvs_handle_t handle;
    if (nvs_open(TRUST_NAMESPACE, NVS_READONLY, &handle) != ESP_OK) return 0;
    size_t length = TRUST_KEY_SIZE;
    esp_err_t err = nvs_get_blob(handle, "trust_key", key, &length);
    nvs_close(handle);
    if (err == ESP_ERR_NVS_NOT_FOUND) return 0;
    if (err != ESP_OK || length != TRUST_KEY_SIZE || key[0] != 0x04) return -1;
    return 1;
}

static bool key_fingerprint(const uint8_t key[TRUST_KEY_SIZE], uint8_t out[32])
{
    return mbedtls_sha256(key, TRUST_KEY_SIZE, out, 0) == 0;
}

static bool verify_manifest_signature(const uint8_t *data, size_t length,
                                      const uint8_t signature[64],
                                      const uint8_t key[TRUST_KEY_SIZE])
{
    uint8_t digest[32];
    if (mbedtls_sha256(data, length, digest, 0) != 0) return false;
    mbedtls_ecp_group group; mbedtls_ecp_point point;
    mbedtls_mpi r; mbedtls_mpi s;
    mbedtls_ecp_group_init(&group); mbedtls_ecp_point_init(&point);
    mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
    bool ok = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
              mbedtls_ecp_point_read_binary(&group, &point, key, TRUST_KEY_SIZE) == 0 &&
              mbedtls_mpi_read_binary(&r, signature, 32) == 0 &&
              mbedtls_mpi_read_binary(&s, signature + 32, 32) == 0 &&
              mbedtls_ecdsa_verify(&group, digest, sizeof(digest), &point, &r, &s) == 0;
    mbedtls_mpi_free(&s); mbedtls_mpi_free(&r); mbedtls_ecp_point_free(&point);
    mbedtls_ecp_group_free(&group); return ok;
}

static bool send_hello(int fd)
{
    uint8_t payload[71] = {0}; uint8_t mac[6] = {0}; uint8_t key[65]; uint8_t fp[32] = {0};
    esp_chip_info_t chip = {0}; esp_chip_info(&chip); (void)esp_read_mac(mac, ESP_MAC_WIFI_STA);
    uint32_t flash = 0; (void)esp_flash_get_physical_size(NULL, &flash);
    put_u32(payload + 8, (uint32_t)esp_clk_cpu_freq());
    put_u32(payload + 12, 40); put_u32(payload + 16, flash);
    put_u32(payload + 20, heap_caps_get_total_size(MALLOC_CAP_8BIT));
    put_u32(payload + 24, heap_caps_get_free_size(MALLOC_CAP_8BIT));
    payload[0] = (uint8_t)chip.model; payload[1] = (uint8_t)chip.revision;
    memcpy(payload + 2, mac, sizeof(mac));
    /* Append role/partition so the original 69-byte prefix, including MAC,
     * remains compatible with older hosts. */
    payload[69] = FLASH_ROLE;
    payload[70] = FLASH_PARTITION;
#if CONFIG_SPIRAM
    put_u32(payload + 28, (uint32_t)heap_caps_get_total_size(MALLOC_CAP_SPIRAM));
    put_u32(payload + 32, (uint32_t)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
#endif
    int key_state = load_trust_key(key);
    payload[36] = key_state > 0 ? 1 : 0;
    if (key_state > 0 && key_fingerprint(key, fp)) memcpy(payload + 37, fp, 32);
    return send_frame(fd, FRAME_HELLO, payload, sizeof(payload));
}

static bool send_partition_table(int fd)
{
    esp_partition_t raw = {0}; const esp_partition_t *partition = NULL; uint32_t limit = 0;
    if (!target_partition(TARGET_PARTITION, &partition, &raw, &limit)) return false;
    uint8_t table[PARTITION_TABLE_SIZE];
    if (esp_partition_read(partition, 0, table, sizeof(table)) != ESP_OK) return false;
    return send_frame(fd, FRAME_PARTITION_TABLE, table, sizeof(table));
}

static bool send_hash_list(int fd, const uint8_t *query, uint16_t query_len)
{
    if (query_len != 20) return false;
    uint8_t target = query[0]; uint32_t start = get_u32(query + 4);
    uint32_t block = get_u32(query + 8); uint32_t count = get_u32(query + 12);
    uint32_t image_size = get_u32(query + 16);
    if (block != BLOCK_SIZE || count == 0 || count > MAX_BLOCKS) return false;
    if (image_size == 0 || image_size > count * block) return false;
    const esp_partition_t *partition = NULL; esp_partition_t raw = {0}; uint32_t limit = 0;
    if (!target_partition(target, &partition, &raw, &limit) || start > limit ||
        count > (limit - start + block - 1) / block) return false;
    uint32_t length = 20 + count * 4; uint8_t *response = malloc(length);
    if (response == NULL) return false;
    memcpy(response, query, 20);
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t hash_length = image_size - i * block;
        if (hash_length > block) hash_length = block;
        if (!block_hash(partition, start + i * block, hash_length,
                        response + 20 + i * 4)) {
            free(response); return false;
        }
    }
    bool ok = send_frame(fd, FRAME_HASH_LIST, response, (uint16_t)length);
    free(response); return ok;
}

static bool parse_manifest(const uint8_t *data, uint16_t length, manifest_t *manifest)
{
    const size_t fixed = 116; const size_t signature = 64;
    if (length < fixed + signature || data[0] == 0 || data[2] > 1 || data[3] != 0) return false;
    manifest->target = data[0]; manifest->start = get_u32(data + 4);
    manifest->block_size = get_u32(data + 8); manifest->count = get_u32(data + 12);
    manifest->image_size = get_u32(data + 16);
    manifest->no_ack = data[2] == 1;
    if (manifest->block_size != BLOCK_SIZE || manifest->count == 0 || manifest->count > MAX_BLOCKS ||
        manifest->image_size == 0 || manifest->image_size > manifest->count * BLOCK_SIZE ||
        manifest->start % BLOCK_SIZE != 0 || manifest->image_size % 4 != 0 ||
        length != fixed + manifest->count * 4 + signature) return false;
    memcpy(manifest->partition_sha, data + 20, 32); memcpy(manifest->image_sha, data + 52, 32);
    memcpy(manifest->key_fp, data + 84, 32);
    manifest->hashes = malloc(manifest->count * 4);
    if (manifest->hashes == NULL) return false;
    memcpy(manifest->hashes, data + fixed, manifest->count * 4);
    uint8_t key[TRUST_KEY_SIZE], fp[32]; int key_state = load_trust_key(key);
    bool verified = false;
    if (key_state < 0) goto fail;
    if (key_state == 0) {
        uint8_t zero[32] = {0}; verified = memcmp(manifest->key_fp, zero, 32) == 0;
    } else if (key_fingerprint(key, fp) && memcmp(fp, manifest->key_fp, 32) == 0) {
        verified = verify_manifest_signature(data, fixed + manifest->count * 4,
                                             data + fixed + manifest->count * 4, key);
    }
    if (!verified) goto fail;
    return true;
fail:
    free(manifest->hashes); manifest->hashes = NULL; return false;
}

static bool validate_manifest_partition(manifest_t *manifest)
{
    const esp_partition_t *partition = NULL; uint32_t limit = 0;
    if (!target_partition(manifest->target, &partition, &manifest->raw_partition, &limit) ||
        manifest->start > limit || manifest->image_size > limit - manifest->start) return false;
    manifest->partition = partition;
    uint8_t actual_table_sha[32];
    esp_partition_t table_raw = {0}; const esp_partition_t *table = NULL; uint32_t table_limit = 0;
    if (!target_partition(TARGET_PARTITION, &table, &table_raw, &table_limit) ||
        !sha256_partition(table, 0, PARTITION_TABLE_SIZE, actual_table_sha) ||
        memcmp(actual_table_sha, manifest->partition_sha, 32) != 0) return false;
    return true;
}

static bool parse_sparse_manifest(const uint8_t *data, uint16_t length, manifest_t *manifest)
{
    const size_t fixed = 120; const size_t entry_size = 12; const size_t signature = 64;
    if (length < fixed + signature || data[0] == 0 || data[2] > 1 || data[3] != 0) return false;
    manifest->target = data[0]; manifest->start = get_u32(data + 4);
    manifest->block_size = get_u32(data + 8); manifest->count = get_u32(data + 12);
    manifest->image_size = get_u32(data + 16); manifest->changed_count = get_u32(data + 20);
    manifest->no_ack = data[2] == 1;
    if (manifest->block_size != BLOCK_SIZE || manifest->count == 0 || manifest->count > MAX_BLOCKS ||
        manifest->image_size == 0 || manifest->image_size > manifest->count * BLOCK_SIZE ||
        manifest->start % BLOCK_SIZE != 0 || manifest->image_size % 4 != 0 ||
        manifest->changed_count > manifest->count ||
        length != fixed + manifest->changed_count * entry_size + signature) return false;
    memcpy(manifest->partition_sha, data + 24, 32);
    memcpy(manifest->image_sha, data + 56, 32);
    memcpy(manifest->key_fp, data + 88, 32);
    if (!validate_manifest_partition(manifest)) return false;
    if (manifest->changed_count != 0) {
        manifest->indices = malloc(manifest->changed_count * sizeof(uint32_t));
        manifest->lengths = malloc(manifest->changed_count * sizeof(uint32_t));
        manifest->changed_hashes = malloc(manifest->changed_count * 4);
        if (manifest->indices == NULL || manifest->lengths == NULL || manifest->changed_hashes == NULL) goto fail;
    }
    for (uint32_t i = 0; i < manifest->changed_count; ++i) {
        const uint8_t *entry = data + fixed + i * entry_size;
        uint32_t relative_offset = get_u32(entry);
        uint32_t index = relative_offset / BLOCK_SIZE;
        uint32_t block_length = get_u32(entry + 4);
        uint32_t expected = manifest->image_size - index * BLOCK_SIZE;
        if (relative_offset % BLOCK_SIZE != 0 || index >= manifest->count ||
            block_length == 0 || block_length > BLOCK_SIZE ||
            block_length != (expected > BLOCK_SIZE ? BLOCK_SIZE : expected)) goto fail;
        for (uint32_t prior = 0; prior < i; ++prior)
            if (manifest->indices[prior] == index) goto fail;
        manifest->indices[i] = index; manifest->lengths[i] = block_length;
        memcpy(manifest->changed_hashes + i * 4, entry + 8, 4);
    }
    {
        uint8_t key[TRUST_KEY_SIZE], fp[32]; int key_state = load_trust_key(key);
        bool verified = false;
        if (key_state < 0) goto fail;
        if (key_state == 0) {
            uint8_t zero[32] = {0}; verified = memcmp(manifest->key_fp, zero, 32) == 0;
        } else if (key_fingerprint(key, fp) && memcmp(fp, manifest->key_fp, 32) == 0) {
            verified = verify_manifest_signature(data, fixed + manifest->changed_count * entry_size,
                                                 data + fixed + manifest->changed_count * entry_size, key);
        }
        if (!verified) goto fail;
    }
    return true;
fail:
    free(manifest->indices); free(manifest->lengths); free(manifest->changed_hashes);
    manifest->indices = NULL; manifest->lengths = NULL; manifest->changed_hashes = NULL;
    return false;
}

static bool erase_sparse_manifest(const manifest_t *manifest)
{
    for (uint32_t i = 0; i < manifest->changed_count; ++i) {
        if (esp_partition_erase_range(manifest->partition,
                                      manifest->start + manifest->indices[i] * BLOCK_SIZE,
                                      BLOCK_SIZE) != ESP_OK) return false;
    }
    return true;
}

static bool sparse_entry(const manifest_t *manifest, uint32_t index,
                         uint32_t *block_length, const uint8_t **expected_hash)
{
    for (uint32_t i = 0; i < manifest->changed_count; ++i) {
        if (manifest->indices[i] == index) {
            *block_length = manifest->lengths[i]; *expected_hash = manifest->changed_hashes + i * 4;
            return true;
        }
    }
    return false;
}

static bool receive_sparse_block(int fd, manifest_t *manifest, const uint8_t *data, uint16_t length)
{
    if (length < 12) return false;
    uint32_t index = get_u32(data + 4), block_length = get_u32(data + 8);
    uint32_t expected_length = 0; const uint8_t *expected_hash = NULL;
    if (data[0] != manifest->target || !sparse_entry(manifest, index, &expected_length, &expected_hash) ||
        block_length != expected_length || length != 12 + block_length) return false;
    uint8_t digest[32];
    if (mbedtls_sha256(data + 12, block_length, digest, 0) != 0 ||
        memcmp(digest, expected_hash, 4) != 0) return false;
    if (esp_partition_write(manifest->partition, manifest->start + index * BLOCK_SIZE,
                            data + 12, block_length) != ESP_OK) return false;
    uint8_t *verify = malloc(block_length); bool ok = verify != NULL &&
        esp_partition_read(manifest->partition, manifest->start + index * BLOCK_SIZE, verify, block_length) == ESP_OK &&
        memcmp(verify, data + 12, block_length) == 0;
    free(verify); return ok;
}

static bool parse_fast_unsigned_manifest(const uint8_t *data, uint16_t length,
                                         manifest_t *manifest)
{
    const size_t fixed = 116;
    uint32_t limit = 0;
    uint8_t key[TRUST_KEY_SIZE];
    uint8_t zero[32] = {0};
    if (length != fixed || data[0] == 0 || data[2] != 0 || data[3] != 0) return false;
    manifest->target = data[0]; manifest->start = get_u32(data + 4);
    manifest->block_size = get_u32(data + 8); manifest->count = get_u32(data + 12);
    manifest->image_size = get_u32(data + 16);
    if (manifest->block_size != BLOCK_SIZE || manifest->count == 0 || manifest->count > MAX_BLOCKS ||
        manifest->image_size == 0 || manifest->image_size > manifest->count * BLOCK_SIZE ||
        manifest->start % BLOCK_SIZE != 0 || manifest->image_size % 4 != 0 ||
        load_trust_key(key) < 0 || memcmp(data + 84, zero, sizeof(zero)) != 0) return false;
    memcpy(manifest->partition_sha, data + 20, 32);
    memcpy(manifest->image_sha, data + 52, 32);
    memcpy(manifest->key_fp, data + 84, 32);
    return target_partition(manifest->target, &manifest->partition,
                            &manifest->raw_partition, &limit) &&
           manifest->start <= limit && manifest->image_size <= limit - manifest->start;
}

static bool receive_fast_unsigned_block(manifest_t *manifest, const uint8_t *data, uint16_t length)
{
    if (length < 12 || data[0] != manifest->target) return false;
    uint32_t index = get_u32(data + 4);
    uint32_t block_length = get_u32(data + 8);
    if (index >= manifest->count || block_length == 0 || block_length > BLOCK_SIZE ||
        block_length + index * BLOCK_SIZE > manifest->image_size || length != 12 + block_length)
        return false;
    uint32_t offset = manifest->start + index * BLOCK_SIZE;
    ESP_LOGI(TAG, "fast block start target=%u index=%u address=0x%x length=%u",
             (unsigned)manifest->target, (unsigned)index,
             (unsigned)(manifest->partition->address + offset), (unsigned)block_length);
    esp_err_t err = esp_partition_erase_range(manifest->partition, offset, BLOCK_SIZE);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "fast block erase failed target=%u index=%u address=0x%x err=0x%x",
                 (unsigned)manifest->target, (unsigned)index,
                 (unsigned)(manifest->partition->address + offset), (unsigned)err);
        return false;
    }
    ESP_LOGI(TAG, "fast block erased target=%u index=%u", (unsigned)manifest->target,
             (unsigned)index);
    err = esp_partition_write(manifest->partition, offset, data + 12, block_length);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "fast block write failed target=%u index=%u address=0x%x err=0x%x",
                 (unsigned)manifest->target, (unsigned)index,
                 (unsigned)(manifest->partition->address + offset), (unsigned)err);
        return false;
    }
    ESP_LOGI(TAG, "fast block complete target=%u index=%u", (unsigned)manifest->target,
             (unsigned)index);
    return true;
}

static bool send_missing(int fd, manifest_t *manifest, const char **error)
{
    const esp_partition_t *partition = NULL; uint32_t limit = 0;
    if (!target_partition(manifest->target, &partition, &manifest->raw_partition, &limit) ||
        manifest->start > limit || manifest->image_size > limit - manifest->start) {
        *error = "target partition unavailable";
        return false;
    }
    manifest->partition = partition;
    uint8_t actual_table_sha[32];
    esp_partition_t table_raw = {0}; const esp_partition_t *table = NULL; uint32_t table_limit = 0;
    if (!target_partition(TARGET_PARTITION, &table, &table_raw, &table_limit) ||
        !sha256_partition(table, 0, PARTITION_TABLE_SIZE, actual_table_sha) ||
        memcmp(actual_table_sha, manifest->partition_sha, 32) != 0) {
        *error = "partition table mismatch";
        return false;
    }
    uint32_t bytes = (manifest->count + 7) / 8; uint8_t *response = malloc(20 + bytes);
    if (response == NULL) { *error = "missing-map allocation failed"; return false; }
    memset(response, 0, 20 + bytes);
    response[0] = manifest->target; put_u32(response + 4, manifest->start);
    put_u32(response + 8, manifest->block_size); put_u32(response + 12, manifest->count);
    put_u32(response + 16, manifest->image_size);
    for (uint32_t i = 0; i < manifest->count; ++i) {
        uint32_t length = manifest->image_size - i * BLOCK_SIZE;
        if (length > BLOCK_SIZE) length = BLOCK_SIZE;
        uint8_t hash[4];
        if (!block_hash(partition, manifest->start + i * BLOCK_SIZE, length, hash)) {
            free(response); *error = "target hash read failed"; return false;
        }
        if (memcmp(hash, manifest->hashes + i * 4, 4) != 0) response[20 + i / 8] |= (uint8_t)(1u << (i % 8));
    }
    bool ok = send_frame(fd, FRAME_MISSING, response, (uint16_t)(20 + bytes));
    free(response); return ok;
}

static bool receive_block(int fd, manifest_t *manifest, const uint8_t *data, uint16_t length)
{
    if (length < 12) return false;
    uint32_t index = get_u32(data + 4), block_length = get_u32(data + 8);
    if (data[0] != manifest->target || index >= manifest->count || block_length > BLOCK_SIZE ||
        block_length + index * BLOCK_SIZE > manifest->image_size || length != 12 + block_length)
        return false;
    uint8_t digest[32]; if (mbedtls_sha256(data + 12, block_length, digest, 0) != 0 ||
        memcmp(digest, manifest->hashes + index * 4, 4) != 0) return false;
    if (esp_partition_erase_range(manifest->partition, manifest->start + index * BLOCK_SIZE, BLOCK_SIZE) != ESP_OK ||
        esp_partition_write(manifest->partition, manifest->start + index * BLOCK_SIZE, data + 12, block_length) != ESP_OK)
        return false;
    uint8_t *verify = malloc(block_length); bool ok = verify != NULL &&
        esp_partition_read(manifest->partition, manifest->start + index * BLOCK_SIZE, verify, block_length) == ESP_OK &&
        memcmp(verify, data + 12, block_length) == 0;
    free(verify); return ok;
}

static bool receive_session(int fd)
{
    manifest_t manifest = {0}; bool sparse = false; bool fast_unsigned = false;
    const char *failure = "flash protocol failed";
    bool ok = send_hello(fd); uint16_t type = 0, length = 0; uint8_t *payload = NULL;
    if (!ok || !recv_frame(fd, &type, &payload, &length) || type != FRAME_READ_PARTITION_TABLE) {
        failure = "partition-table request failed"; goto fail;
    }
    free(payload); payload = NULL; if (!send_partition_table(fd)) goto fail;
    if (!recv_frame(fd, &type, &payload, &length)) { failure = "manifest receive failed"; goto fail; }
    if (type == FRAME_FAST_UNSIGNED) {
        fast_unsigned = true;
        if (!parse_fast_unsigned_manifest(payload, length, &manifest)) goto fail;
        ESP_LOGI(TAG, "fast manifest target=%u start=0x%x size=%u blocks=%u",
                 (unsigned)manifest.target, (unsigned)manifest.start,
                 (unsigned)manifest.image_size, (unsigned)manifest.count);
        uint8_t ready[4]; put_u32(ready, manifest.count);
        free(payload); payload = NULL;
        if (!send_frame(fd, FRAME_FAST_READY, ready, sizeof(ready))) goto fail_manifest;
    } else {
        if (type != FRAME_HASH_QUERY || !send_hash_list(fd, payload, length)) {
            failure = "hash query failed"; goto fail;
        }
        free(payload); payload = NULL;
    }
    if (!fast_unsigned && !recv_frame(fd, &type, &payload, &length)) {
        failure = "manifest receive failed"; goto fail;
    }
    if (!fast_unsigned && type == FRAME_SPARSE_MANIFEST) {
        sparse = true;
        if (!parse_sparse_manifest(payload, length, &manifest) || !erase_sparse_manifest(&manifest)) goto fail;
        uint8_t ready[4]; put_u32(ready, manifest.changed_count);
        free(payload); payload = NULL;
        if (!send_frame(fd, FRAME_MANIFEST_READY, ready, sizeof(ready))) goto fail_manifest;
    } else if (!fast_unsigned) {
        if (type != FRAME_MANIFEST || !parse_manifest(payload, length, &manifest)) {
            failure = "invalid legacy manifest"; goto fail;
        }
        free(payload); payload = NULL;
        if (!send_missing(fd, &manifest, &failure)) goto fail_manifest;
    }
    while (true) {
        if (!recv_frame(fd, &type, &payload, &length)) goto fail_manifest;
        ESP_LOGI(TAG, "received frame type=%u length=%u", (unsigned)type, (unsigned)length);
        if (type == FRAME_DONE) { free(payload); payload = NULL; break; }
        if (type == FRAME_HASH_QUERY) {
            bool hashes_ok = send_hash_list(fd, payload, length);
            free(payload); payload = NULL;
            if (!hashes_ok) goto fail_manifest;
            continue;
        }
        if (type != FRAME_BLOCK || (fast_unsigned ? !receive_fast_unsigned_block(&manifest, payload, length) :
                                     (sparse ? !receive_sparse_block(fd, &manifest, payload, length) :
                                               !receive_block(fd, &manifest, payload, length)))) goto fail_manifest;
        uint32_t block_index = get_u32(payload + 4);
        free(payload); payload = NULL;
        if (!fast_unsigned && !manifest.no_ack) {
            uint8_t ack[5] = {0}; put_u32(ack, block_index);
            if (!send_frame(fd, FRAME_ACK, ack, sizeof(ack))) goto fail_manifest;
        }
    }
    if (!fast_unsigned) {
        uint8_t final_sha[32];
        if (!sha256_partition(manifest.partition, manifest.start, manifest.image_size, final_sha) ||
            memcmp(final_sha, manifest.image_sha, sizeof(final_sha)) != 0) goto fail_manifest;
    }
    free(manifest.hashes); free(manifest.indices); free(manifest.lengths); free(manifest.changed_hashes);
    (void)send_frame(fd, FRAME_DONE, NULL, 0);
    ESP_LOGI(TAG, "negotiated flash complete target=%u size=%u blocks=%u mode=%s", manifest.target,
             (unsigned)manifest.image_size,
             (unsigned)(fast_unsigned ? manifest.count : (sparse ? manifest.changed_count : manifest.count)),
             fast_unsigned ? "unsigned-fast" : (sparse ? "sparse" : "verified")); return true;
fail:
    free(payload); payload = NULL;
fail_manifest:
    free(payload); free(manifest.hashes); free(manifest.indices); free(manifest.lengths);
    free(manifest.changed_hashes);
    ESP_LOGE(TAG, "negotiated session failed: %s", failure);
    (void)send_frame(fd, FRAME_ERROR, failure, (uint16_t)strlen(failure)); return false;
}

static void flash_worker(void *arg)
{
    (void)arg;
    ESP_LOGI(TAG, "flash worker start");
    ESP_LOGI(TAG, "flash worker socket");
    int client = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (client < 0) {
        ESP_LOGE(TAG, "socket create failed errno=%d", errno);
        goto done;
    }
    if (active.remote_ip[0] != '\0') {
        if (!connect_remote(client, active.remote_ip, active.port)) { close(client); goto done; }
    } else {
        active.listener = client; int reuse = 1;
        (void)setsockopt(client, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        struct sockaddr_in endpoint = {.sin_family = AF_INET, .sin_port = htons(active.port), .sin_addr.s_addr = htonl(INADDR_ANY)};
        if (bind(client, (struct sockaddr *)&endpoint, sizeof(endpoint)) != 0 || listen(client, 1) != 0) { close(client); goto done; }
        int accepted = accept(client, NULL, NULL); close(client); active.listener = -1;
        if (accepted < 0) goto done;
        client = accepted;
    }
    ESP_LOGI(TAG, "flash worker connected");
    flash_result = receive_session(client); close(client);
    ESP_LOGI(TAG, "flash worker session result=%d", flash_result);
done:
    if (!flash_result) ESP_LOGE(TAG, "negotiated session transport failed");
    active.listener = -1; flash_done = true; flash_pending = false; flash_task = NULL; vTaskDelete(NULL);
}

bool dmesh_flash_tcp_start(uint16_t port, const char *remote_ip)
{
    if (port == 0 || (flash_pending && !flash_done)) return false;
    if (active.listener >= 0) close(active.listener);
    memset(&active, 0, sizeof(active)); active.listener = -1; active.port = port;
    if (remote_ip != NULL) strncpy(active.remote_ip, remote_ip, sizeof(active.remote_ip) - 1);
    flash_done = false; flash_result = false; flash_pending = true;
    if (xTaskCreatePinnedToCore(flash_worker, "dmesh_flash", BOOT_HEAP_STACK, NULL, 4, &flash_task, 1) != pdPASS) {
        flash_pending = false; return false;
    }
    ESP_LOGI(TAG, "negotiated session armed port=%u remote=%s", (unsigned)port,
             active.remote_ip[0] != '\0' ? active.remote_ip : "listen"); return true;
}

void dmesh_flash_tcp_poll(void) {}

bool dmesh_flash_tcp_accept(void)
{
    return flash_done && flash_result;
}

bool dmesh_flash_tcp_finished(void)
{
    return flash_done;
}
