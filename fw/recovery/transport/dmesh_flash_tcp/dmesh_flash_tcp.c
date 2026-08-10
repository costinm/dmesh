#include "dmesh_flash_tcp.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>

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
#include "nvs.h"
#include "esp_timer.h"
#include "sha/sha_parallel_engine.h"
#if defined(DMESH_FLASH_USE_LEGACY_MBEDTLS)
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#else
#include "psa/crypto.h"
#endif

#define TAG "dmesh-flash"
#define PROTOCOL_MAGIC 0x44525332u /* DRS2 */
#define PROTOCOL_VERSION 1u
#define FRAME_HELLO 1u
#define FRAME_MANIFEST 6u
#define FRAME_BLOCK 8u
#define FRAME_ACK 9u
#define FRAME_DONE 10u
#define FRAME_FLOW_PULSE 11u
#define FRAME_PROGRESS 12u
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
#define MANIFEST_PUBLIC_KEY_SIZE 65u
#define TRUST_NAMESPACE "recovery"
#define CONNECT_RETRY_COUNT 150u /* 30 seconds at 200 ms per attempt */
#define CONNECT_RETRY_DELAY_MS 200u
#define HELLO_EXTENDED_LEN 90u
#define HELLO_MODULE_MAX 16u
#define HELLO_CAP_FIXED_LAYOUT 0x01u
#define HELLO_CAP_FAST_BLOCK_SHA 0x02u
#define HELLO_CAP_DIRECT_MANIFEST 0x04u
#define HELLO_REQ_DRY_RUN 0x08u /* mode explicitly armed by Main/Recovery */
#define MANIFEST_FLAG_DRY_RUN 0x01u
#define FINAL_ACK_TIMEOUT_SEC 30
#define DEVICE_PROGRESS_INTERVAL_BLOCKS 64u

/* Main does not need a flash-event sink. Recovery supplies a strong
 * implementation that emits the documented PPP event; keeping the silent
 * default here avoids a separate boot-events package. */
__attribute__((weak)) void dmesh_flash_event(bool success, uint8_t target,
                                             uint32_t blocks, uint32_t received,
                                             uint32_t bytes, uint32_t elapsed_ms,
                                             uint32_t speed_bps, const char *error)
{
    (void)success; (void)target; (void)blocks; (void)received; (void)bytes;
    (void)elapsed_ms; (void)speed_bps; (void)error;
}

typedef struct {
    uint16_t port;
    int listener;
    char remote_ip[16];
    char target[16];
    char module[HELLO_MODULE_MAX + 1];
    bool dry_run;
} flash_job_t;

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

/* Development images may exercise the new key/TOFU fields without making a
 * bad signature or a deliberately incomplete test stream unrecoverable.
 * Production builds leave this disabled. */
#ifndef DMESH_FLASH_DEV_MODE
#define DMESH_FLASH_DEV_MODE 0
#endif

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
    uint8_t public_key[MANIFEST_PUBLIC_KEY_SIZE];
    uint8_t manifest_version;
    uint8_t *hashes;
    bool no_ack;
    bool dry_run;
    const uint8_t *nvs_data;
    uint16_t nvs_length;
} manifest_t;

static bool validate_manifest_partition(manifest_t *manifest);

static flash_job_t active = {.listener = -1};
static volatile bool flash_pending;
static volatile bool flash_done;

/* Names remain a host/controller compatibility surface. The device slot is
 * selected by the numeric service allocation shared with Main's loader. */
static uint16_t module_service_tag(void)
{
    if (strcmp(active.module, "lora") == 0) return 43u;
    if (strcmp(active.module, "hw") == 0) return 45u;
    if (strcmp(active.module, "hello") == 0) return 46u;
    return 0;
}

static uint32_t module_slot_offset(void)
{
    uint16_t tag = module_service_tag();
    return tag >= 43u && tag <= 100u ? ((uint32_t)tag - 43u) * 0x10000u : 0u;
}
static volatile bool flash_result;
static TaskHandle_t flash_task;

static uint32_t get_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static uint16_t get_u16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static void put_u32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24); p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8); p[3] = (uint8_t)value;
}

static const char *frame_name(uint16_t type)
{
    switch (type) {
    case FRAME_HELLO: return "hello";
    case FRAME_MANIFEST: return "manifest";
    case FRAME_BLOCK: return "block";
    case FRAME_ACK: return "ack";
    case FRAME_DONE: return "done";
    case FRAME_FLOW_PULSE: return "flow-pulse";
    case FRAME_PROGRESS: return "progress";
    case FRAME_ERROR: return "error";
    default: return "unknown";
    }
}

static bool recv_all(int fd, void *buffer, size_t length)
{
    uint8_t *cursor = (uint8_t *)buffer;
    while (length != 0) {
        int received = recv(fd, cursor, length, 0);
        if (received <= 0) {
            ESP_LOGW(TAG, "recv failed fd=%d want=%u received=%d errno=%d",
                     fd, (unsigned)length, received, errno);
            return false;
        }
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
        if (sent <= 0) {
            ESP_LOGW(TAG, "send failed fd=%d want=%u sent=%d errno=%d",
                     fd, (unsigned)length, sent, errno);
            return false;
        }
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

static bool recv_frame(int fd, uint16_t *type, uint8_t **payload, uint16_t *length);

static bool wait_final_ack(int fd)
{
    struct timeval timeout = {.tv_sec = FINAL_ACK_TIMEOUT_SEC, .tv_usec = 0};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
        ESP_LOGW(TAG, "final acknowledgement timeout unavailable errno=%d", errno);
    }
    uint16_t type = 0, length = 0; uint8_t *payload = NULL;
    bool received = recv_frame(fd, &type, &payload, &length);
    bool acknowledged = received && type == FRAME_ACK && length == 0;
    if (received && !acknowledged) {
        ESP_LOGW(TAG, "unexpected final acknowledgement frame type=%u length=%u",
                 (unsigned)type, (unsigned)length);
    } else if (!received) {
        /* Older flash servers stop after receiving the device DONE. Do not
         * turn that compatibility case into a failed Recovery boot. */
        ESP_LOGW(TAG, "final acknowledgement not received; continuing with reboot");
    }
    free(payload);
    return acknowledged;
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

static bool connect_remote(int *connected_fd, const char *address, uint16_t port)
{
    *connected_fd = -1;
    ESP_LOGI(TAG, "connect start remote=%s:%u retries=%u", address,
             (unsigned)port, (unsigned)CONNECT_RETRY_COUNT);
    struct sockaddr_in remote = {.sin_family = AF_INET, .sin_port = htons(port)};
    if (inet_aton(address, &remote.sin_addr) == 0) {
        ESP_LOGE(TAG, "connect invalid remote=%s", address);
        return false;
    }
    for (unsigned attempt = 0; attempt < CONNECT_RETRY_COUNT; ++attempt) {
        /* A failed lwIP connect leaves the socket in a terminal state on
         * some error paths (notably while the AP route/ARP entry is still
         * coming up).  Retrying connect() on that descriptor only repeats
         * ENOTCONN/EINVAL and can strand Recovery until its next reboot.
         * Each attempt therefore gets a fresh descriptor. */
        int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        if (fd < 0) {
            ESP_LOGW(TAG, "connect socket create failed attempt=%u/%u errno=%d",
                     attempt + 1, (unsigned)CONNECT_RETRY_COUNT, errno);
            vTaskDelay(pdMS_TO_TICKS(CONNECT_RETRY_DELAY_MS));
            continue;
        }
        if (connect(fd, (struct sockaddr *)&remote, sizeof(remote)) == 0) {
            *connected_fd = fd;
            ESP_LOGI(TAG, "connect success attempt=%u", attempt + 1);
            return true;
        }
        int error = errno;
        close(fd);
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

static void configure_flash_socket(int fd)
{
    /* Recovery bulk-erases the target, then writes one 4 KiB block at a time
     * while TCP continues to receive. The default lwIP receive window is only
     * a few blocks and can
     * collapse on the high-latency direct AP, leaving the host in repeated
     * retransmission/backoff while the device is still making progress. Keep
     * the buffer bounded within Recovery's RAM budget, but allow several
     * dozen blocks to queue behind the flash worker. */
    /* TCP_WND_DEFAULT is 65535 without window scaling on classic ESP32.
     * Passing 65536 overflows the lwIP window-sized socket option and has
     * been observed as errno=109 (ETOOMANYREFS), leaving the socket at an
     * implementation-dependent buffer size. */
    int receive_buffer = 65520;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receive_buffer,
                   sizeof(receive_buffer)) != 0) {
        ESP_LOGW(TAG, "flash socket receive buffer not updated requested=%d errno=%d",
                 receive_buffer, errno);
    } else {
        int actual = 0; socklen_t actual_length = sizeof(actual);
        if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &actual, &actual_length) == 0) {
            ESP_LOGI(TAG, "flash socket receive buffer=%d", actual);
        }
    }
    int no_delay = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &no_delay,
                   sizeof(no_delay)) != 0) {
        ESP_LOGW(TAG, "flash socket TCP_NODELAY unavailable errno=%d", errno);
    }
    ESP_LOGI(TAG, "tcp config mss=%d wnd=%d snd_buf=%d timer_ms=%d",
             TCP_MSS, TCP_WND, TCP_SND_BUF, TCP_TMR_INTERVAL);
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
        if (target == TARGET_MODULE) {
            uint32_t offset = module_slot_offset();
            if (raw->size <= offset) return false;
            raw->address += offset;
            raw->size -= offset;
        }
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
#if defined(DMESH_FLASH_USE_LEGACY_MBEDTLS)
    mbedtls_sha256_context context;
    mbedtls_sha256_init(&context);
    if (mbedtls_sha256_starts(&context, 0) != 0) return false;
    while (length != 0) {
        size_t part = length > sizeof(buffer) ? sizeof(buffer) : length;
        if (esp_partition_read(partition, offset, buffer, part) != ESP_OK ||
            mbedtls_sha256_update(&context, buffer, part) != 0) {
            mbedtls_sha256_free(&context); return false;
        }
        offset += (uint32_t)part; length -= (uint32_t)part;
    }
    bool ok = mbedtls_sha256_finish(&context, digest) == 0;
    mbedtls_sha256_free(&context); return ok;
#else
    if (psa_crypto_init() != PSA_SUCCESS) return false;
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    if (psa_hash_setup(&operation, PSA_ALG_SHA_256) != PSA_SUCCESS) return false;
    while (length != 0) {
        size_t part = length > sizeof(buffer) ? sizeof(buffer) : length;
        if (esp_partition_read(partition, offset, buffer, part) != ESP_OK ||
            psa_hash_update(&operation, buffer, part) != PSA_SUCCESS) {
            psa_hash_abort(&operation); return false;
        }
        offset += (uint32_t)part; length -= (uint32_t)part;
    }
    size_t digest_length = 0;
    return psa_hash_finish(&operation, digest, 32, &digest_length) == PSA_SUCCESS &&
           digest_length == 32;
#endif
}

static bool sha256_bytes(const uint8_t *data, size_t length, uint8_t digest[32])
{
    /* Block validation is on the hot receive path. Keep the P-256 manifest
     * verifier on PSA, but use the direct fixed-size SHA implementation here;
     * constructing a PSA operation for every 4 KiB block needlessly holds up
     * lwIP's receive window on the no-PSRAM ESP32 Recovery image. */
    esp_sha(SHA2_256, data, length, digest);
    return true;
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
    return sha256_bytes(key, TRUST_KEY_SIZE, out);
}

static bool public_key_fingerprint(const uint8_t key[MANIFEST_PUBLIC_KEY_SIZE],
                                   uint8_t out[32])
{
    return key[0] == 0x04 && key_fingerprint(key, out);
}

static bool public_key_is_zero(const uint8_t key[MANIFEST_PUBLIC_KEY_SIZE])
{
    for (size_t i = 0; i < MANIFEST_PUBLIC_KEY_SIZE; ++i)
        if (key[i] != 0) return false;
    return true;
}

static bool save_trust_key(const uint8_t key[TRUST_KEY_SIZE])
{
    nvs_handle_t handle;
    if (key[0] != 0x04 || nvs_open(TRUST_NAMESPACE, NVS_READWRITE, &handle) != ESP_OK)
        return false;
    esp_err_t err = nvs_set_blob(handle, "trust_key", key, TRUST_KEY_SIZE);
    if (err == ESP_OK) err = nvs_commit(handle);
    nvs_close(handle);
    ESP_LOGI(TAG, "TOFU trust key save=%s", esp_err_to_name(err));
    return err == ESP_OK;
}

static bool verify_manifest_signature(const uint8_t *data, size_t length,
                                      const uint8_t signature[64],
                                      const uint8_t key[TRUST_KEY_SIZE])
{
    uint8_t digest[32];
    if (!sha256_bytes(data, length, digest)) return false;
#if defined(DMESH_FLASH_USE_LEGACY_MBEDTLS)
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
#else
    if (psa_crypto_init() != PSA_SUCCESS) return false;
    psa_key_attributes_t attributes = psa_key_attributes_init();
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    psa_key_id_t key_id = 0;
    psa_status_t status = psa_import_key(&attributes, key, TRUST_KEY_SIZE, &key_id);
    psa_reset_key_attributes(&attributes);
    if (status != PSA_SUCCESS) return false;
    status = psa_verify_hash(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                             digest, sizeof(digest), signature, 64);
    (void)psa_destroy_key(key_id);
    return status == PSA_SUCCESS;
#endif
}

static bool authenticate_manifest(const uint8_t *data, size_t body_length,
                                  const uint8_t signature[64], manifest_t *manifest)
{
    uint8_t stored_key[TRUST_KEY_SIZE], fingerprint[32];
    int key_state = load_trust_key(stored_key);
    if (key_state < 0) {
        ESP_LOGW(TAG, "malformed stored trust key");
#if DMESH_FLASH_DEV_MODE
        return true;
#else
        return false;
#endif
    }

    const uint8_t *candidate = NULL;
    if (manifest->manifest_version >= 1 &&
        public_key_fingerprint(manifest->public_key, fingerprint)) {
        candidate = manifest->public_key;
    }

    if (key_state == 0) {
        /* TOFU: an unkeyed device accepts the manifest so development and
         * first provisioning are not blocked. If a complete key and a real
         * signature are supplied, verify opportunistically and retain the key
         * only after that verification succeeds. */
        if (candidate && !public_key_is_zero(manifest->public_key) &&
            memcmp(signature, (uint8_t[64]){0}, 64) != 0) {
            bool valid = verify_manifest_signature(data, body_length, signature, candidate);
            ESP_LOGI(TAG, "TOFU signature=%s", valid ? "valid" : "not-valid");
            if (valid) (void)save_trust_key(candidate);
        }
        return true;
    }

    bool key_matches = key_fingerprint(stored_key, fingerprint) &&
        (candidate != NULL ? memcmp(candidate, stored_key, TRUST_KEY_SIZE) == 0
                            : memcmp(fingerprint, manifest->key_fp, 32) == 0);
    bool valid = key_matches && verify_manifest_signature(data, body_length, signature,
                                                            stored_key);
    if (!valid) {
        ESP_LOGW(TAG, "manifest signature/key check failed key_matches=%d", key_matches);
#if DMESH_FLASH_DEV_MODE
        return true;
#else
        return false;
#endif
    }
    return true;
}

static uint8_t target_id(const char *target)
{
    if (target == NULL) return 0;
    if (strcmp(target, "boot") == 0 || strcmp(target, "stage2") == 0) return TARGET_BOOT;
    if (strcmp(target, "partition") == 0 || strcmp(target, "partition-table") == 0) return TARGET_PARTITION;
    if (strcmp(target, "recovery") == 0) return TARGET_RECOVERY;
    if (strcmp(target, "nvs") == 0) return TARGET_NVS;
    if (strcmp(target, "data") == 0) return TARGET_DATA;
    if (strcmp(target, "main") == 0) return TARGET_MAIN;
    if (strcmp(target, "module") == 0) return TARGET_MODULE;
    return 0;
}

static bool send_hello(int fd)
{
    uint8_t payload[HELLO_EXTENDED_LEN] = {0}; uint8_t mac[6] = {0}; uint8_t key[65]; uint8_t fp[32] = {0};
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
    // Bytes 71..88 are an optional extension.  A zero target preserves the
    // old client behavior and makes the server use its configured default.
    payload[71] = target_id(active.target);
    if (payload[71] == TARGET_MODULE && active.module[0] != '\0') {
        size_t length = strnlen(active.module, HELLO_MODULE_MAX);
        payload[72] = (uint8_t)length;
        memcpy(payload + 73, active.module, length);
    }
    /* The partition layout is fixed together with boot, Recovery, and Main.
     * Bit 1 means the device checks incoming block SHA values; bit 2 means
     * the manifest is the first frame after HELLO. There is no device hash
     * scan, missing bitmap, sparse mode, or partition-table exchange. */
    payload[89] = HELLO_CAP_FIXED_LAYOUT | HELLO_CAP_FAST_BLOCK_SHA |
                  HELLO_CAP_DIRECT_MANIFEST |
                  (active.dry_run ? HELLO_REQ_DRY_RUN : 0);
#if CONFIG_SPIRAM
    put_u32(payload + 28, (uint32_t)heap_caps_get_total_size(MALLOC_CAP_SPIRAM));
    put_u32(payload + 32, (uint32_t)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
#endif
    int key_state = load_trust_key(key);
    payload[36] = key_state > 0 ? 1 : 0;
    if (key_state > 0 && key_fingerprint(key, fp)) memcpy(payload + 37, fp, 32);
    return send_frame(fd, FRAME_HELLO, payload, sizeof(payload));
}

static bool parse_manifest(const uint8_t *data, uint16_t length, manifest_t *manifest)
{
    const size_t signature = 64;
    if (length < 4) return false;
    const size_t fixed = data[3] == 2 ? 151 : (data[3] == 1 ? 149 : 116);
    if (length < fixed + signature || data[0] == 0 ||
        (data[1] & (uint8_t)~MANIFEST_FLAG_DRY_RUN) != 0 ||
        data[2] > 1 || data[3] > 2) return false;
    manifest->manifest_version = data[3];
    manifest->target = data[0]; manifest->start = get_u32(data + 4);
    manifest->block_size = get_u32(data + 8); manifest->count = get_u32(data + 12);
    manifest->image_size = get_u32(data + 16);
    manifest->no_ack = data[2] == 1;
    manifest->dry_run = (data[1] & MANIFEST_FLAG_DRY_RUN) != 0;
    if (manifest->block_size != BLOCK_SIZE || manifest->count == 0 || manifest->count > MAX_BLOCKS ||
        manifest->image_size == 0 || manifest->image_size > manifest->count * BLOCK_SIZE ||
        manifest->start % BLOCK_SIZE != 0 || manifest->image_size % 4 != 0 ||
        length != fixed + manifest->count * 4 + signature) return false;
    memcpy(manifest->partition_sha, data + 20, 32); memcpy(manifest->image_sha, data + 52, 32);
    if (manifest->manifest_version == 1) {
        memcpy(manifest->public_key, data + 84, MANIFEST_PUBLIC_KEY_SIZE);
        if (!public_key_fingerprint(manifest->public_key, manifest->key_fp))
            memset(manifest->key_fp, 0, sizeof(manifest->key_fp));
    } else {
        memcpy(manifest->key_fp, data + 84, 32);
    }
    if (manifest->manifest_version == 2) {
        manifest->nvs_length = get_u16(data + 149);
        if (manifest->nvs_length > 2048) return false;
        manifest->nvs_data = data + fixed;
    }
    size_t body_end = fixed + manifest->nvs_length + manifest->count * 4;
    if (length != body_end + signature) return false;
    manifest->hashes = malloc(manifest->count * 4);
    if (manifest->hashes == NULL) return false;
    memcpy(manifest->hashes, data + fixed + manifest->nvs_length, manifest->count * 4);
    if (!authenticate_manifest(data, body_end, data + body_end, manifest)) goto fail;
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

static bool erase_manifest_image(const manifest_t *manifest)
{
    uint32_t erase_size = (manifest->image_size + BLOCK_SIZE - 1u) &
                          ~(BLOCK_SIZE - 1u);
    if (erase_size < manifest->image_size ||
        manifest->start > manifest->partition->size ||
        erase_size > manifest->partition->size - manifest->start) {
        ESP_LOGE(TAG, "bulk erase range invalid start=0x%x size=%u partition=%u",
                 (unsigned)manifest->start, (unsigned)erase_size,
                 (unsigned)manifest->partition->size);
        return false;
    }
    esp_err_t result = esp_partition_erase_range(manifest->partition,
                                                  manifest->start, erase_size);
    if (result != ESP_OK) {
        ESP_LOGE(TAG, "bulk erase failed start=0x%x size=%u err=0x%x",
                 (unsigned)manifest->start, (unsigned)erase_size,
                 (unsigned)result);
        return false;
    }
    ESP_LOGI(TAG, "bulk erase complete start=0x%x size=%u",
             (unsigned)manifest->start, (unsigned)erase_size);
    return true;
}

static bool apply_manifest_nvs(const manifest_t *manifest)
{
    if (manifest->nvs_length == 0) return true;
    const uint8_t *cursor = manifest->nvs_data;
    size_t remaining = manifest->nvs_length;
    nvs_handle_t handles[8] = {0};
    char namespaces[8][16] = {{0}};
    size_t handle_count = 0;
    while (remaining != 0) {
        if (remaining < 6) return false;
        uint8_t namespace_length = cursor[0];
        uint8_t key_length = cursor[1];
        uint8_t type = cursor[2];
        uint16_t value_length = get_u16(cursor + 4);
        cursor += 6; remaining -= 6;
        if (namespace_length == 0 || namespace_length >= sizeof(namespaces[0]) ||
            key_length == 0 || key_length > 15 || value_length > remaining ||
            namespace_length + key_length + value_length > remaining) return false;
        char namespace_name[16] = {0};
        char key[16] = {0};
        memcpy(namespace_name, cursor, namespace_length); cursor += namespace_length; remaining -= namespace_length;
        memcpy(key, cursor, key_length); cursor += key_length; remaining -= key_length;
        if ((strcmp(namespace_name, "recovery") == 0 &&
             (strcmp(key, "request_magic") == 0 || strcmp(key, "request_version") == 0 ||
              strcmp(key, "uart_boot") == 0)) || strcmp(namespace_name, "boot") == 0) {
            return false;
        }
        nvs_handle_t handle = 0;
        size_t handle_index = 0;
        for (; handle_index < handle_count; ++handle_index)
            if (strcmp(namespaces[handle_index], namespace_name) == 0) { handle = handles[handle_index]; break; }
        if (handle == 0) {
            if (handle_count >= 8 || nvs_open(namespace_name, NVS_READWRITE, &handle) != ESP_OK) return false;
            strlcpy(namespaces[handle_count], namespace_name, sizeof(namespaces[0]));
            handles[handle_count++] = handle;
        }
        esp_err_t result = ESP_FAIL;
        switch (type) {
        case 1: if (value_length == 1) result = nvs_set_u8(handle, key, cursor[0]); break;
        case 2: if (value_length == 2) result = nvs_set_u16(handle, key, get_u16(cursor)); break;
        case 3: if (value_length == 4) result = nvs_set_u32(handle, key, get_u32(cursor)); break;
        case 4: {
            if (value_length == 8) { uint64_t value = 0; for (int i = 0; i < 8; ++i) value = (value << 8) | cursor[i]; result = nvs_set_u64(handle, key, value); }
            break;
        }
        case 5: if (value_length == 4) result = nvs_set_i32(handle, key, (int32_t)get_u32(cursor)); break;
        case 6: if (value_length > 0 && cursor[value_length - 1] == 0) result = nvs_set_str(handle, key, (const char *)cursor); break;
        case 7: result = nvs_set_blob(handle, key, cursor, value_length); break;
        case 8: if (value_length == 1) result = nvs_set_u8(handle, key, cursor[0] ? 1 : 0); break;
        default: break;
        }
        if (result != ESP_OK) { for (size_t i = 0; i < handle_count; ++i) nvs_close(handles[i]); return false; }
        cursor += value_length; remaining -= value_length;
    }
    for (size_t i = 0; i < handle_count; ++i) {
        if (nvs_commit(handles[i]) != ESP_OK) { for (size_t j = 0; j < handle_count; ++j) nvs_close(handles[j]); return false; }
    }
    for (size_t i = 0; i < handle_count; ++i) nvs_close(handles[i]);
    return true;
}

static bool receive_block(manifest_t *manifest, const uint8_t *data, uint16_t length)
{
    if (length < 12) {
        ESP_LOGE(TAG, "block rejected: short frame length=%u", (unsigned)length);
        return false;
    }
    uint32_t index = get_u32(data + 4), block_length = get_u32(data + 8);
    if (data[0] != manifest->target || index >= manifest->count || block_length > BLOCK_SIZE ||
        block_length + index * BLOCK_SIZE > manifest->image_size || length != 12 + block_length) {
        ESP_LOGE(TAG, "block rejected: target=%u expected=%u index=%u/%u length=%u block_length=%u",
                 (unsigned)data[0], (unsigned)manifest->target, (unsigned)index,
                 (unsigned)manifest->count, (unsigned)length, (unsigned)block_length);
        return false;
    }
#if !DMESH_FLASH_DEV_MODE
    uint8_t digest[32]; if (!sha256_bytes(data + 12, block_length, digest) ||
        memcmp(digest, manifest->hashes + index * 4, 4) != 0) {
        ESP_LOGE(TAG, "block hash mismatch index=%u length=%u", (unsigned)index,
                 (unsigned)block_length);
        return false;
    }
#endif
    if (manifest->dry_run) return true;
    esp_err_t write = esp_partition_write(manifest->partition,
                                           manifest->start + index * BLOCK_SIZE,
                                           data + 12, block_length);
    if (write != ESP_OK) {
        ESP_LOGE(TAG, "block write failed index=%u err=0x%x", (unsigned)index, (unsigned)write);
        return false;
    }
    /* Match esptool's write verification: read the just-written bytes back
     * and compare them with the received TCP payload. The payload was already
     * checked against the signed manifest hash; hashing the flash again would
     * add work without improving this physical-write check. */
    uint8_t readback[BLOCK_SIZE];
    esp_err_t read = esp_partition_read(manifest->partition,
                                        manifest->start + index * BLOCK_SIZE,
                                        readback, block_length);
    if (read != ESP_OK) {
        ESP_LOGE(TAG, "block readback failed index=%u err=0x%x", (unsigned)index, (unsigned)read);
        return false;
    }
    if (memcmp(readback, data + 12, block_length) != 0) {
        ESP_LOGE(TAG, "block readback mismatch index=%u length=%u", (unsigned)index,
                 (unsigned)block_length);
        return false;
    }
    return true;
}

static bool receive_session(int fd)
{
    int64_t started_us = esp_timer_get_time();
    manifest_t manifest = {0};
    uint32_t received_blocks = 0;
    uint32_t flow_pulses = 0;
    uint32_t progress_packets = 0;
    uint64_t block_work_us = 0;
    uint8_t *received_map = NULL;
    const char *failure = "flash protocol failed";
    ESP_LOGI(TAG, "session start fd=%d", fd);
    bool ok = send_hello(fd); uint16_t type = 0, length = 0; uint8_t *payload = NULL;
    if (!ok || !recv_frame(fd, &type, &payload, &length)) {
        failure = "manifest request failed"; goto fail;
    }
    ESP_LOGI(TAG, "manifest frame received type=%u name=%s length=%u",
             (unsigned)type, frame_name(type), (unsigned)length);
    if (type != FRAME_MANIFEST || !parse_manifest(payload, length, &manifest)) {
        failure = "invalid P-256 manifest"; goto fail;
    }
    if (!validate_manifest_partition(&manifest)) {
        failure = "manifest partition validation failed"; goto fail_manifest;
    }
    if (!manifest.dry_run && !erase_manifest_image(&manifest)) {
        failure = "bulk erase failed"; goto fail_manifest;
    }
    received_map = calloc((manifest.count + 7u) / 8u, 1);
    if (received_map == NULL) {
        failure = "receipt map allocation failed"; goto fail_manifest;
    }
    ESP_LOGI(TAG, "waiting blocks mode=%s target=%u count=%u",
             manifest.dry_run ? "dry-run" : "manifest",
             (unsigned)manifest.target, (unsigned)manifest.count);
    free(payload); payload = NULL;
    while (true) {
        if (!recv_frame(fd, &type, &payload, &length)) {
            failure = "block receive failed"; goto fail_manifest;
        }
        if (type == FRAME_DONE) {
            free(payload); payload = NULL;
            if (received_blocks != manifest.count) {
                failure = "manifest transfer incomplete"; goto fail_manifest;
            }
            ESP_LOGI(TAG, "received done blocks=%u", (unsigned)received_blocks);
            break;
        }
        if (type == FRAME_FLOW_PULSE) {
            if (length != 4) {
                failure = "invalid flow pulse";
                goto fail_manifest;
            }
            flow_pulses++;
            if (flow_pulses == 1 || (flow_pulses % 16u) == 0) {
                ESP_LOGI(TAG, "flow pulse count=%u after_block=%u",
                         (unsigned)flow_pulses, (unsigned)get_u32(payload));
            }
            free(payload); payload = NULL;
            continue;
        }
        if (type != FRAME_BLOCK || length < 12) {
            failure = "block validation or write failed"; goto fail_manifest;
        }
        uint32_t block_index = get_u32(payload + 4);
        if (block_index >= manifest.count) {
            failure = "block index out of range"; goto fail_manifest;
        }
        uint8_t mask = (uint8_t)(1u << (block_index & 7u));
        uint8_t *seen = &received_map[block_index / 8u];
        if ((*seen & mask) != 0) {
            failure = "duplicate block"; goto fail_manifest;
        }
        int64_t block_started_us = esp_timer_get_time();
        bool block_ok = receive_block(&manifest, payload, length);
        block_work_us += (uint64_t)(esp_timer_get_time() - block_started_us);
        if (!block_ok) {
            failure = manifest.dry_run ? "block SHA validation failed" :
                      "block validation, write, or readback failed";
            goto fail_manifest;
        }
        *seen |= mask;
        received_blocks++;
        if (received_blocks == 1 || received_blocks == manifest.count ||
            (received_blocks % 16u) == 0) {
            ESP_LOGI(TAG, "block progress received=%u/%u last_index=%u",
                     (unsigned)received_blocks, (unsigned)manifest.count,
                     (unsigned)block_index);
        }
        if ((received_blocks % DEVICE_PROGRESS_INTERVAL_BLOCKS) == 0 &&
            received_blocks < manifest.count) {
            /* One-way diagnostic only: this is not a per-block ACK or pacing
             * protocol. Keep it sparse so a diagnostic return packet can
             * never materially compete with the host's block stream. The
             * host still sends a small flow pulse every four blocks for
             * packet captures and TCP-window observation. */
            uint8_t progress[12];
            put_u32(progress, received_blocks);
            put_u32(progress + 4,
                    (uint32_t)((esp_timer_get_time() - started_us) / 1000));
            put_u32(progress + 8, (uint32_t)(block_work_us / 1000));
            if (!send_frame(fd, FRAME_PROGRESS, progress, sizeof(progress))) {
                failure = "progress packet send failed";
                goto fail_manifest;
            }
            progress_packets++;
        }
        free(payload); payload = NULL;
        if (!manifest.no_ack) {
            uint8_t ack[5] = {0}; put_u32(ack, block_index);
            if (!send_frame(fd, FRAME_ACK, ack, sizeof(ack))) {
                failure = "block ack send failed"; goto fail_manifest;
            }
        }
    }
    if (!apply_manifest_nvs(&manifest)) {
        failure = "manifest NVS settings rejected";
        goto fail_manifest;
    }
    free(received_map); free(manifest.hashes);
    if (!send_frame(fd, FRAME_DONE, NULL, 0)) {
        ESP_LOGW(TAG, "final DONE send failed; continuing with completed flash");
    } else {
        (void)wait_final_ack(fd);
    }
    uint32_t elapsed_ms = (uint32_t)((esp_timer_get_time() - started_us) / 1000);
    uint32_t speed_bps = elapsed_ms == 0 ? 0 :
        (uint32_t)(((uint64_t)manifest.image_size * 8u * 1000u) / elapsed_ms);
    dmesh_flash_event(true, manifest.target,
                      manifest.count,
                      received_blocks, manifest.image_size, elapsed_ms,
                      speed_bps, NULL);
    ESP_LOGI(TAG, "negotiated flash complete target=%u size=%u blocks=%u received=%u pulses=%u progress=%u mode=%s",
             manifest.target,
             (unsigned)manifest.image_size,
             (unsigned)manifest.count,
             (unsigned)received_blocks,
             (unsigned)flow_pulses,
             (unsigned)progress_packets,
             manifest.dry_run ? "dry-run" : "flash"); return true;
fail:
    free(payload); payload = NULL;
fail_manifest:
    free(payload); free(received_map); free(manifest.hashes);
    ESP_LOGE(TAG, "negotiated session failed: %s target=%u received=%u",
             failure, (unsigned)manifest.target, (unsigned)received_blocks);
    uint32_t failure_elapsed_ms = (uint32_t)((esp_timer_get_time() - started_us) / 1000);
    uint32_t failure_speed_bps = failure_elapsed_ms == 0 ? 0 :
        (uint32_t)(((uint64_t)manifest.image_size * 8u * 1000u) / failure_elapsed_ms);
    dmesh_flash_event(false, manifest.target, manifest.count,
                      received_blocks, manifest.image_size,
                      failure_elapsed_ms, failure_speed_bps, failure);
    (void)send_frame(fd, FRAME_ERROR, failure, (uint16_t)strlen(failure)); return false;
}

static void flash_worker(void *arg)
{
    (void)arg;
    ESP_LOGI(TAG, "flash worker start");
    ESP_LOGI(TAG, "flash worker socket");
    int client = -1;
    if (active.remote_ip[0] != '\0') {
        if (!connect_remote(&client, active.remote_ip, active.port)) goto done;
    } else {
        client = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        if (client < 0) {
            ESP_LOGE(TAG, "socket create failed errno=%d", errno);
            goto done;
        }
        active.listener = client; int reuse = 1;
        (void)setsockopt(client, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        struct sockaddr_in endpoint = {.sin_family = AF_INET, .sin_port = htons(active.port), .sin_addr.s_addr = htonl(INADDR_ANY)};
        if (bind(client, (struct sockaddr *)&endpoint, sizeof(endpoint)) != 0 || listen(client, 1) != 0) { close(client); goto done; }
        int accepted = accept(client, NULL, NULL); close(client); active.listener = -1;
        if (accepted < 0) goto done;
        client = accepted;
    }
    ESP_LOGI(TAG, "flash worker connected");
    configure_flash_socket(client);
    flash_result = receive_session(client); close(client);
    ESP_LOGI(TAG, "flash worker session result=%d", flash_result);
done:
    if (!flash_result) ESP_LOGE(TAG, "negotiated session transport failed");
    active.listener = -1; flash_done = true; flash_pending = false; flash_task = NULL; vTaskDelete(NULL);
}

bool dmesh_flash_tcp_start_target(uint16_t port, const char *remote_ip,
                                  const char *target, const char *module,
                                  bool dry_run)
{
    if (port == 0 || (flash_pending && !flash_done)) return false;
    if (active.listener >= 0) close(active.listener);
    memset(&active, 0, sizeof(active)); active.listener = -1; active.port = port;
    if (remote_ip != NULL) strncpy(active.remote_ip, remote_ip, sizeof(active.remote_ip) - 1);
    strlcpy(active.target, target != NULL && target[0] != '\0' ? target : "main",
            sizeof(active.target));
    if (module != NULL) strlcpy(active.module, module, sizeof(active.module));
    active.dry_run = dry_run;
    flash_done = false; flash_result = false; flash_pending = true;
    /* Wi-Fi is pinned to CPU0 and lwIP/TCPIP to CPU1 by the Recovery profile.
     * Keep the blocking frame reader and per-block SHA work with TCPIP on
     * CPU1, leaving the Wi-Fi driver interrupt/task core free to replenish
     * the receive path. TCPIP has a much higher priority than this worker, so
     * a blocking recv() still yields to the network task without an explicit
     * FreeRTOS yield in the transfer loop. Single-core targets use core 0. */
#if CONFIG_FREERTOS_NUMBER_OF_CORES > 1
    const BaseType_t flash_core = 1;
#else
    const BaseType_t flash_core = 0;
#endif
    if (xTaskCreatePinnedToCore(flash_worker, "dmesh_flash", BOOT_HEAP_STACK, NULL, 4, &flash_task, flash_core) != pdPASS) {
        flash_pending = false; return false;
    }
    ESP_LOGI(TAG, "negotiated session armed port=%u remote=%s mode=%s", (unsigned)port,
    active.remote_ip[0] != '\0' ? active.remote_ip : "listen",
    active.dry_run ? "dry-run" : "flash"); return true;
}

bool dmesh_flash_tcp_prepare(void)
{
    if (flash_pending && !flash_done) return false;
    // A completed worker leaves these bits set until the next start. Clear
    // them at control-plane acceptance so an asynchronous STA-start failure
    // cannot be reported as the previous session's success.
    flash_done = false;
    flash_result = false;
    return true;
}

bool dmesh_flash_tcp_start(uint16_t port, const char *remote_ip)
{
    return dmesh_flash_tcp_start_target(port, remote_ip, "main", NULL, false);
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

bool dmesh_flash_tcp_active(void)
{
    return flash_pending && !flash_done;
}
