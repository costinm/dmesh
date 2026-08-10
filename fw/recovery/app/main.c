#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "esp_task_wdt.h"
#include "esp_wifi.h"
#include "driver/uart.h"
#if CONFIG_IDF_TARGET_ESP32C6
#include "driver/usb_serial_jtag.h"
#endif
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "boot_protocol.h"
#include "dmesh_flash_tcp.h"
#include "sdkconfig.h"
#include "soc/soc.h"

#define TAG "dmesh-recovery"
#define RECOVERY_NAMESPACE "recovery"
#define BOOTSTRAP_HOST "10.78.0.1"
#if CONFIG_IDF_TARGET_ESP32S3
#define DEFAULT_PORT 3337
#else
#define DEFAULT_PORT 3336
#endif
#define DIRECT_DMESH_PREFIX "Direct-"
/* Keep the UART command task alive long enough for the second-stage
 * RECOVER/STA handoff. Transport settings are RAM-only; the RTC bit selects
 * Recovery/Main and no flash write is needed for a retry. */
#define UART_COMMAND_GRACE_MS 1500
#define RECOVERY_METHOD_ID 68u
#define RECOVERY_FLASH_ATTEMPTS 10u
#define RECOVERY_FLASH_WAIT_SEC 900u
#define CBOR_INDEFINITE UINT64_MAX

static char ssid[33];
static char remote_host[128];
static char local_address[32];
static uint16_t remote_port = DEFAULT_PORT;
static bool recovery_dry_run;

/* Recovery only needs to select Main after a successful download. Keep this
 * tiny local write separate from the boot health layout owned by stage2. */
/* boot_health_rtc.h documents the shared retained layout: custom starts at
 * 12, health_event is custom+4, and handoff is custom+5.  Do not add the
 * health-event offset again here; stage2 reads the byte at custom+5. */
#define RECOVERY_RTC_HANDOFF_OFFSET (12 + 5)
/* custom+8..27 belongs to stage2's retained boot history (the uint32 array is
 * naturally aligned after custom+0..4). Keep this flag
 * after that structure so a stage2 reboot record cannot clear it. */
#define RECOVERY_RTC_DRY_RUN_OFFSET (12 + 28)
#define RECOVERY_RTC_RETAIN_SIZE (((12 + 0x20u + 4 + 7) / 8) * 8)
#if ESP_ROM_HAS_LP_ROM
#define RECOVERY_RTC_RETAIN_BASE SOC_RTC_DRAM_LOW
#else
#define RECOVERY_RTC_RETAIN_BASE (SOC_RTC_DRAM_HIGH - RECOVERY_RTC_RETAIN_SIZE)
#endif

static void recovery_set_handoff(uint8_t handoff)
{
    *(volatile uint8_t *)(RECOVERY_RTC_RETAIN_BASE + RECOVERY_RTC_HANDOFF_OFFSET) = handoff;
}

static uint8_t recovery_get_handoff(void)
{
    return *(volatile uint8_t *)(RECOVERY_RTC_RETAIN_BASE + RECOVERY_RTC_HANDOFF_OFFSET);
}

static void recovery_set_dry_run(bool dry_run)
{
    *(volatile uint8_t *)(RECOVERY_RTC_RETAIN_BASE + RECOVERY_RTC_DRY_RUN_OFFSET) =
        dry_run ? 1 : 0;
    recovery_dry_run = dry_run;
}

static bool recovery_get_dry_run(void)
{
    uint8_t value = *(volatile uint8_t *)(RECOVERY_RTC_RETAIN_BASE + RECOVERY_RTC_DRY_RUN_OFFSET);
    return value == 1;
}

static int recovery_write(const void *data, size_t length)
{
#if CONFIG_IDF_TARGET_ESP32C6
    return usb_serial_jtag_write_bytes(data, length, 0);
#else
    return uart_write_bytes(UART_NUM_0, data, length);
#endif
}

void dmesh_flash_event(bool success, uint8_t target,
                       uint32_t blocks, uint32_t received,
                       uint32_t bytes, uint32_t elapsed_ms,
                       uint32_t speed_bps, const char *error)
{
    uint8_t payload[256];
    uint8_t wire[520];
    const uint8_t *error_bytes = (const uint8_t *)error;
    size_t error_length = error == NULL ? 0 : strnlen(error, 96);
    size_t payload_length = dmesh_boot_flash_event_encode(
        payload, sizeof(payload),
        success ? DMESH_BOOT_EVENT_FLASH_COMPLETE : DMESH_BOOT_EVENT_FLASH_ERROR,
        DMESH_BOOT_ROLE_RECOVERY, target, blocks, received, bytes,
        elapsed_ms, speed_bps, error_bytes, error_length);
    size_t wire_length = dmesh_boot_frame_encode(payload, payload_length,
                                                  wire, sizeof(wire));
    if (wire_length != 0) (void)recovery_write(wire, wire_length);
}

static int recovery_read(void *data, size_t length, TickType_t wait)
{
#if CONFIG_IDF_TARGET_ESP32C6
    return usb_serial_jtag_read_bytes(data, length, wait);
#else
    return uart_read_bytes(UART_NUM_0, data, length, wait);
#endif
}

static void recovery_console_init(void)
{
#if CONFIG_IDF_TARGET_ESP32C6
    usb_serial_jtag_driver_config_t config = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&config));
#else
    /* The Recovery image owns UART0 for its entire lifetime.  Do not rely on
     * the console component having installed the driver: that is a build
     * configuration detail and previously left the first boot packet (and
     * sometimes the reader task) with no usable UART backend. */
    if (!uart_is_driver_installed(UART_NUM_0)) {
        ESP_ERROR_CHECK(uart_driver_install(UART_NUM_0, 2048, 2048, 0, NULL, 0));
    }
    uart_config_t config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    ESP_ERROR_CHECK(uart_param_config(UART_NUM_0, &config));
#endif
}

static void schedule_recovery_restart(bool reboot_main);

static bool set_unconfigured_defaults(void)
{
    uint8_t mac[6] = {0};
    if (remote_host[0] == '\0') {
        strlcpy(remote_host, BOOTSTRAP_HOST, sizeof(remote_host));
        ESP_LOGI(TAG, "using bootstrap host=%s port=%u",
                 remote_host, (unsigned)remote_port);
    }
    if (local_address[0] != '\0') {
        return true;
    }
    if (esp_read_mac(mac, ESP_MAC_WIFI_STA) != ESP_OK) {
        ESP_LOGE(TAG, "cannot derive bootstrap address from STA MAC");
        return false;
    }
    /* Keep all unconfigured boards on the lab 10.78/16 link while making
     * each address deterministic from the final two MAC octets. */
    snprintf(local_address, sizeof(local_address), "10.78.%u.%u",
             (unsigned)mac[4], (unsigned)mac[5]);
    ESP_LOGI(TAG, "using bootstrap local_ip=%s from STA MAC %02x:%02x",
             local_address, mac[4], mac[5]);
    return true;
}

static void send_boot_identity(void)
{
    uint8_t mac[6] = {0};
    (void)esp_read_mac(mac, ESP_MAC_WIFI_STA);
    uint8_t payload[128];
    size_t payload_length = dmesh_boot_identity_event(
        payload, sizeof(payload), DMESH_BOOT_ROLE_RECOVERY,
        DMESH_BOOT_PARTITION_RECOVERY, (uint8_t)esp_reset_reason(),
        recovery_get_handoff(), 0, 0, 0, 0, mac);
    uint8_t wire[256];
    size_t length = dmesh_boot_frame_encode(payload, payload_length, wire,
                                             sizeof(wire));
    if (length != 0) {
        (void)recovery_write(wire, length);
    }
}

static void send_network_up_event(const char *ip, const wifi_ap_record_t *ap)
{
    uint8_t payload[128];
    uint8_t wire[256];
    size_t cursor = 0;
    size_t n;
    payload[cursor++] = 0xbf;
    n = dmesh_cbor_put_uint(payload + cursor, sizeof(payload) - cursor, 7); if (!n) return; cursor += n;
    n = dmesh_cbor_put_uint(payload + cursor, sizeof(payload) - cursor, DMESH_BOOT_EVENT_NETWORK_UP); if (!n) return; cursor += n;
    n = dmesh_cbor_put_uint(payload + cursor, sizeof(payload) - cursor, 6); if (!n) return; cursor += n;
    payload[cursor++] = 0x9f;
    n = dmesh_cbor_put_uint(payload + cursor, sizeof(payload) - cursor, DMESH_BOOT_ROLE_RECOVERY); if (!n) return; cursor += n;
    n = dmesh_cbor_put_bytes(payload + cursor, sizeof(payload) - cursor,
                             (const uint8_t *)ip, strnlen(ip, 31)); if (!n) return; cursor += n;
    n = dmesh_cbor_put_bytes(payload + cursor, sizeof(payload) - cursor, ap->bssid, 6); if (!n) return; cursor += n;
    n = dmesh_cbor_put_int(payload + cursor, sizeof(payload) - cursor, ap->rssi); if (!n) return; cursor += n;
    if (cursor + 2 > sizeof(payload)) return;
    payload[cursor++] = 0xff; payload[cursor++] = 0xff;
    size_t length = dmesh_boot_frame_encode(payload, cursor, wire, sizeof(wire));
    if (length != 0) (void)recovery_write(wire, length);
}

static void restart_task(void *arg)
{
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(150));
    esp_restart();
    vTaskDelete(NULL);
}

static bool save_sta_request(char *line);

typedef struct {
    const uint8_t *data;
    size_t length;
    size_t offset;
} cbor_reader_t;

static bool cbor_head(cbor_reader_t *reader, uint8_t *major, uint64_t *argument)
{
    if (reader->offset >= reader->length) return false;
    uint8_t first = reader->data[reader->offset++];
    *major = first >> 5;
    uint8_t additional = first & 0x1f;
    if (additional == 31) {
        *argument = CBOR_INDEFINITE;
        return true;
    }
    if (additional < 24) {
        *argument = additional;
        return true;
    }
    size_t width = additional == 24 ? 1 : additional == 25 ? 2 :
                   additional == 26 ? 4 : additional == 27 ? 8 : 0;
    if (width == 0 || width > reader->length - reader->offset) return false;
    uint64_t value = 0;
    for (size_t i = 0; i < width; ++i) value = (value << 8) | reader->data[reader->offset++];
    *argument = value;
    return true;
}

static bool cbor_uint(cbor_reader_t *reader, uint64_t *value)
{
    uint8_t major;
    return cbor_head(reader, &major, value) && major == 0;
}

static bool cbor_bool(cbor_reader_t *reader, bool *value)
{
    if (reader->offset >= reader->length) return false;
    uint8_t byte = reader->data[reader->offset++];
    if (byte == 0xf4) { *value = false; return true; }
    if (byte == 0xf5) { *value = true; return true; }
    return false;
}

static bool cbor_text(cbor_reader_t *reader, char *out, size_t capacity)
{
    uint8_t major;
    uint64_t length;
    if (!cbor_head(reader, &major, &length) || major != 3 ||
        length >= capacity || length > reader->length - reader->offset) return false;
    memcpy(out, reader->data + reader->offset, (size_t)length);
    out[length] = '\0';
    reader->offset += (size_t)length;
    return true;
}

static bool cbor_skip(cbor_reader_t *reader)
{
    uint8_t major;
    uint64_t argument;
    if (!cbor_head(reader, &major, &argument)) return false;
    if (major == 0 || major == 1 || major == 7) return true;
    if (major == 2 || major == 3) {
        if (argument > reader->length - reader->offset) return false;
        reader->offset += (size_t)argument;
        return true;
    }
    if (major == 4 || major == 5) {
        if (argument == CBOR_INDEFINITE) {
            while (reader->offset < reader->length &&
                   reader->data[reader->offset] != 0xff) {
                if (!cbor_skip(reader)) return false;
                if (major == 5 && !cbor_skip(reader)) return false;
            }
            if (reader->offset >= reader->length) return false;
            reader->offset++;
            return true;
        }
        uint64_t count = argument * (major == 5 ? 2 : 1);
        for (uint64_t i = 0; i < count; ++i) if (!cbor_skip(reader)) return false;
        return true;
    }
    return false;
}

static void set_recovery_log_level(const char *value)
{
    if (value == NULL || value[0] == '\0') return;
    char *end = NULL;
    long parsed = strtol(value, &end, 10);
    if (end == value || *end != '\0' || parsed < 0 || parsed > 5) {
        ESP_LOGE(TAG, "protocol invalid log_level=%s", value);
        return;
    }
    esp_log_level_set("*", (esp_log_level_t)parsed);
    ESP_LOGW(TAG, "protocol log_level=%ld", parsed);
}

static bool handle_recovery_cbor(const uint8_t *data, size_t length)
{
    cbor_reader_t reader = {.data = data, .length = length, .offset = 0};
    uint8_t major;
    uint64_t count;
    if (!cbor_head(&reader, &major, &count) || major != 5 ||
        (count != CBOR_INDEFINITE && count > 16)) return false;
    char method[32] = {0};
    char op[32] = {0};
    char endpoint[128] = {0};
    char local_ip[32] = {0};
    char network[33] = {0};
    char password[33] = {0};
    char port_text[16] = {0};
    char log_level[8] = {0};
    bool dry_run = false;
    bool dry_run_seen = false;
    uint64_t fields_seen = 0;
    while (count == CBOR_INDEFINITE ?
           (reader.offset < reader.length && reader.data[reader.offset] != 0xff) :
           fields_seen < count) {
        uint64_t key;
        if (!cbor_uint(&reader, &key)) return false;
        if (key == 0) {
            uint8_t method_major = reader.offset < reader.length ? reader.data[reader.offset] >> 5 : 7;
            if (method_major == 0) {
                uint64_t method_id;
                if (!cbor_uint(&reader, &method_id)) return false;
                snprintf(method, sizeof(method), "%llu", (unsigned long long)method_id);
            } else if (!cbor_text(&reader, method, sizeof(method))) {
                return false;
            }
        } else if (key == 6) {
            uint8_t payload_major;
            uint64_t fields;
            if (!cbor_head(&reader, &payload_major, &fields) || payload_major != 5 ||
                (fields != CBOR_INDEFINITE && fields > 16)) return false;
            uint64_t fields_seen = 0;
            while (fields == CBOR_INDEFINITE ?
                   (reader.offset < reader.length && reader.data[reader.offset] != 0xff) :
                   fields_seen < fields) {
                char name[32] = {0};
                if (!cbor_text(&reader, name, sizeof(name))) return false;
                char *destination = NULL;
                size_t destination_size = 0;
                if (strcmp(name, "op") == 0) { destination = op; destination_size = sizeof(op); }
                else if (strcmp(name, "server") == 0) { destination = endpoint; destination_size = sizeof(endpoint); }
                else if (strcmp(name, "ip") == 0) { destination = local_ip; destination_size = sizeof(local_ip); }
                else if (strcmp(name, "ssid") == 0) { destination = network; destination_size = sizeof(network); }
                else if (strcmp(name, "password") == 0) { destination = password; destination_size = sizeof(password); }
                else if (strcmp(name, "port") == 0) { destination = port_text; destination_size = sizeof(port_text); }
                else if (strcmp(name, "log_level") == 0) { destination = log_level; destination_size = sizeof(log_level); }
                if (strcmp(name, "dry_run") == 0) {
                    if (!cbor_bool(&reader, &dry_run)) return false;
                    dry_run_seen = true;
                } else if (destination != NULL) {
                    uint8_t value_major = reader.offset < reader.length ? reader.data[reader.offset] >> 5 : 7;
                    if (value_major == 0) {
                        uint64_t value;
                        if (!cbor_uint(&reader, &value)) return false;
                        snprintf(destination, destination_size, "%llu", (unsigned long long)value);
                    } else if (!cbor_text(&reader, destination, destination_size)) {
                        return false;
                    }
                } else if (!cbor_skip(&reader)) {
                    return false;
                }
                ++fields_seen;
            }
            if (fields == CBOR_INDEFINITE) {
                if (reader.offset >= reader.length || reader.data[reader.offset] != 0xff) return false;
                reader.offset++;
            }
        } else if (!cbor_skip(&reader)) {
            return false;
        }
        ++fields_seen;
    }
    if (count == CBOR_INDEFINITE) {
        if (reader.offset >= reader.length || reader.data[reader.offset] != 0xff) return false;
        reader.offset++;
    }
    if (reader.offset != reader.length) return false;
    if (strcmp(method, "recovery") != 0 && strcmp(method, "68") != 0) return false;
    set_recovery_log_level(log_level);
    if (strcmp(op, "REBOOT_MAIN") == 0 || strcmp(op, "reboot_main") == 0) {
        schedule_recovery_restart(true);
        return true;
    }
    if (strcmp(op, "RETRY_MAIN") == 0 || strcmp(op, "retry_main") == 0) {
        schedule_recovery_restart(false);
        return true;
    }
    if (endpoint[0] == '\0' && network[0] == '\0' && local_ip[0] == '\0') return true;
    if (endpoint[0] == '\0' || network[0] == '\0' || local_ip[0] == '\0') {
        ESP_LOGE(TAG, "protocol recovery transport missing server/ssid/ip");
        return false;
    }
    char line[256];
    unsigned port = port_text[0] == '\0' ? DEFAULT_PORT : (unsigned)strtoul(port_text, NULL, 10);
    bool requested_dry_run = dry_run_seen ? dry_run : recovery_dry_run;
    /* The managed handoff is commonly repeated while waiting for Recovery to
     * join the AP. Do not restart an idempotent request: it can interrupt an
     * already healthy transfer. */
    if (password[0] == '\0' &&
        port <= UINT16_MAX &&
        strcmp(endpoint, remote_host) == 0 &&
        strcmp(local_ip, local_address) == 0 &&
        strcmp(network, ssid) == 0 &&
        (uint16_t)port == remote_port &&
        requested_dry_run == recovery_dry_run) {
        return true;
    }
    recovery_set_dry_run(requested_dry_run);
    snprintf(line, sizeof(line), "STA %s:%u %s %s %s%s", endpoint, port, local_ip,
             network, password, requested_dry_run ? " dryrun" : "");
    if (!save_sta_request(line)) {
        ESP_LOGE(TAG, "protocol recovery transport save failed");
        return false;
    }
    ESP_LOGW(TAG, "protocol recovery transport updated server=%s port=%u", endpoint, port);
    /* Recovery may already be in its network/flash loop when this packet
     * arrives. Restart while retaining the RTC Recovery handoff so the next
     * boot uses the new runtime transport. */
    schedule_recovery_restart(false);
    return true;
}

static void schedule_recovery_restart(bool reboot_main)
{
    if (reboot_main) {
        /* A normal Recovery completion tells stage2 that the next boot is a
         * fresh Main attempt. */
        recovery_set_handoff(DMESH_BOOT_HEALTH_HANDOFF_MAIN);
    } else {
        /* Keep the RTC handoff pointed at Recovery for a retry. */
        recovery_set_handoff(DMESH_BOOT_HEALTH_HANDOFF_RECOVERY);
    }
    xTaskCreate(restart_task, "recovery_restart", 2048, NULL,
                configMAX_PRIORITIES - 1, NULL);
    vTaskDelete(NULL);
}

static bool save_sta_request(char *line)
{
    char *save = NULL;
    char *command = strtok_r(line, " \t\r\n", &save);
    char *endpoint = strtok_r(NULL, " \t\r\n", &save);
    char *local_ip = strtok_r(NULL, " \t\r\n", &save);
    char *network = strtok_r(NULL, " \t\r\n", &save);
    char *network_password = strtok_r(NULL, " \t\r\n", &save);
    char *mode = strtok_r(NULL, " \t\r\n", &save);
    if (command == NULL || strcmp(command, "STA") != 0 || endpoint == NULL ||
        local_ip == NULL || network == NULL) {
        return false;
    }
    if (network_password != NULL && strcmp(network_password, "dryrun") == 0) {
        mode = network_password;
        network_password = NULL;
    }
    if (network_password != NULL && network_password[0] != '\0') {
        ESP_LOGW(TAG, "rejecting non-open STA request");
        return false;
    }
    char *colon = strrchr(endpoint, ':');
    if (colon == NULL || colon[1] == '\0') {
        return false;
    }
    unsigned long parsed = strtoul(colon + 1, NULL, 10);
    if (parsed == 0 || parsed > UINT16_MAX) {
        return false;
    }
    *colon = '\0';

    if (mode != NULL && strcmp(mode, "dryrun") != 0 && strcmp(mode, "flash") != 0) {
        return false;
    }

    strlcpy(ssid, network, sizeof(ssid));
    strlcpy(remote_host, endpoint, sizeof(remote_host));
    strlcpy(local_address, local_ip, sizeof(local_address));
    remote_port = (uint16_t)parsed;
    /* An old/repeated STA command has no mode field. Preserve the explicit
     * device-side dry-run request across that compatibility path; only an
     * explicit `dryrun` or `flash` token changes the RTC selection. */
    if (mode != NULL) {
        recovery_set_dry_run(strcmp(mode, "dryrun") == 0);
    }
    ESP_LOGI(TAG, "STA request applied runtime-only ssid=%s server=%s port=%lu ip=%s",
             ssid, remote_host, parsed, local_address);
    return true;
}

static void uart_command_task(void *arg)
{
    (void)arg;
    uint8_t frame[512];
    size_t frame_length = 0;
    bool in_frame = false;
    bool escaped = false;
    while (true) {
        uint8_t byte;
        /* Do not sleep inside the UART driver's blocking read.  On the
         * classic ESP32 this can leave the Recovery task below the task-WDT
         * service point while the managed forward is idle.  Polling keeps
         * PPP reception active and lets Recovery continue its network/flash
         * supervision even when no UART packet is arriving. */
        int got = recovery_read(&byte, 1, 0);
        if (got != 1) {
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }
        if (byte == DMESH_BOOT_WIRE_FLAG) {
            if (in_frame && frame_length != 0) {
                if (!handle_recovery_cbor(frame, frame_length)) {
                    ESP_LOGE(TAG, "protocol rejected PPP-CBOR packet length=%u first=0x%02x",
                             (unsigned)frame_length, frame[0]);
                }
            }
            in_frame = true;
            escaped = false;
            frame_length = 0;
            continue;
        }
        if (!in_frame) {
            continue;
        }
        if (escaped) {
            if (frame_length < sizeof(frame)) frame[frame_length++] = byte ^ DMESH_BOOT_WIRE_ESCAPE_XOR;
            escaped = false;
        } else if (byte == DMESH_BOOT_WIRE_ESCAPE) {
            escaped = true;
        } else if (frame_length < sizeof(frame)) {
            frame[frame_length++] = byte;
        }
    }
}

static bool trust_key_present(void)
{
    nvs_handle_t nvs;
    uint8_t key[96];
    size_t length = sizeof(key);
    bool present = false;
    if (nvs_open(RECOVERY_NAMESPACE, NVS_READONLY, &nvs) == ESP_OK) {
        present = nvs_get_blob(nvs, "trust_key", key, &length) == ESP_OK && length != 0;
        nvs_close(nvs);
    }
    return present;
}

static bool direct_dmesh_ssid(const uint8_t *name, size_t length)
{
    static const char prefix[] = DIRECT_DMESH_PREFIX;
    if (length < sizeof(prefix) - 1 ||
        strncmp((const char *)name, prefix, sizeof(prefix) - 1) != 0) {
        return false;
    }
    for (size_t i = sizeof(prefix) - 1; i + 5 <= length; ++i) {
        if ((name[i] == 'D' || name[i] == 'd') &&
            (name[i + 1] == 'M' || name[i + 1] == 'm') &&
            (name[i + 2] == 'E' || name[i + 2] == 'e') &&
            (name[i + 3] == 'S' || name[i + 3] == 's') &&
            (name[i + 4] == 'H' || name[i + 4] == 'h')) {
            return true;
        }
    }
    return false;
}

static bool select_direct_dmesh_ssid(void)
{
    uint16_t count = 0;
    esp_err_t err = esp_wifi_scan_start(NULL, true);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "sta scan start failed error=%s", esp_err_to_name(err));
        return false;
    }
    err = esp_wifi_scan_get_ap_num(&count);
    if (err != ESP_OK || count == 0) {
        ESP_LOGW(TAG, "sta scan found no APs error=%s", esp_err_to_name(err));
        return false;
    }
    if (count > 16) {
        count = 16;
    }
    wifi_ap_record_t *records = calloc(count, sizeof(*records));
    if (records == NULL) {
        ESP_LOGE(TAG, "sta scan record allocation failed count=%u", (unsigned)count);
        return false;
    }
    err = esp_wifi_scan_get_ap_records(&count, records);
    bool found = false;
    if (err == ESP_OK) {
        for (uint16_t i = 0; i < count; ++i) {
            size_t length = strnlen((const char *)records[i].ssid,
                                    sizeof(records[i].ssid));
            if (records[i].authmode == WIFI_AUTH_OPEN &&
                direct_dmesh_ssid(records[i].ssid, length)) {
                strlcpy(ssid, (const char *)records[i].ssid, sizeof(ssid));
                ESP_LOGI(TAG, "sta scan selected open ssid=%s rssi=%d channel=%u",
                         ssid, records[i].rssi, (unsigned)records[i].primary);
                found = true;
                break;
            }
        }
    }
    free(records);
    if (!found) {
        ESP_LOGW(TAG, "sta scan found no open Direct-*-Dmesh AP error=%s",
                 esp_err_to_name(err));
    }
    return found;
}

static bool start_network(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    if (remote_host[0] == '\0') {
        ESP_LOGE(TAG, "minimal STA profile requires numeric server");
        return false;
    }

    esp_netif_t *netif = esp_netif_create_default_wifi_sta();
    uint16_t netif_mtu = 0;
    if (esp_netif_get_mtu(netif, &netif_mtu) == ESP_OK) {
        ESP_LOGI(TAG, "sta netif mtu=%d tcp_mss=%d", netif_mtu, CONFIG_LWIP_TCP_MSS);
    } else {
        ESP_LOGW(TAG, "sta netif mtu unavailable tcp_mss=%d", CONFIG_LWIP_TCP_MSS);
    }
    wifi_init_config_t config = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&config));
    /* The IDF warning is emitted on every association poll and is not a
     * useful Recovery diagnostic. The structured network-up event below is
     * the single positive state transition we expose. */
    esp_log_level_set("wifi", ESP_LOG_ERROR);
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

    wifi_config_t wifi = {0};
    bool scan_for_direct = ssid[0] == '\0';
    wifi.sta.password[0] = '\0';
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    if (ssid[0] != '\0') {
        strlcpy((char *)wifi.sta.ssid, ssid, sizeof(wifi.sta.ssid));
    }
    if (local_address[0] != '\0') {
        esp_netif_ip_info_t static_ip = {0};
        uint32_t parsed_ip = esp_ip4addr_aton(local_address);
        if (parsed_ip == 0) {
            ESP_LOGE(TAG, "invalid sta ip=%s", local_address);
            return false;
        }
        static_ip.ip.addr = parsed_ip;
        IP4_ADDR(&static_ip.gw, 10, 78, 0, 1);
        IP4_ADDR(&static_ip.netmask, 255, 255, 0, 0);
        ESP_ERROR_CHECK(esp_netif_dhcpc_stop(netif));
        ESP_ERROR_CHECK(esp_netif_set_ip_info(netif, &static_ip));
        ESP_LOGI(TAG, "sta_static_ip=%s", local_address);
    }
    ESP_ERROR_CHECK(esp_wifi_start());
    /* Recovery is an active STA flash client, not a sleepy Main node. Keep
     * modem power save disabled for the entire network/DRS2 session; otherwise
     * the direct AP can see multi-second gaps and TCP collapses its congestion
     * window while the flash worker is still healthy. */
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));

    /* Keep Recovery resident while the infrastructure AP is temporarily
     * absent. A reset is deliberately not used as a network retry: stage2
     * should only count actual boot failures, not a failed association. */
    for (;;) {
        TickType_t window_start = xTaskGetTickCount();
        TickType_t window_ticks = pdMS_TO_TICKS(30 * 1000);
        bool configured = false;
        esp_netif_ip_info_t ip = {0};
        while ((xTaskGetTickCount() - window_start) < window_ticks) {
            if (scan_for_direct && !configured) {
                ssid[0] = '\0';
                if (!select_direct_dmesh_ssid()) {
                    vTaskDelay(pdMS_TO_TICKS(1000));
                    continue;
                }
            }
            strlcpy((char *)wifi.sta.ssid, ssid, sizeof(wifi.sta.ssid));
            if (!configured) {
                ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi));
                /* Re-apply this at every association.  The Wi-Fi driver may
                 * restore its profile after a disconnect/reconnect; Recovery
                 * must remain an awake TCP client throughout the flash. */
                esp_err_t ps_error = esp_wifi_set_ps(WIFI_PS_NONE);
                if (ps_error != ESP_OK) {
                    ESP_LOGE(TAG, "sta power-save disable failed error=%s",
                             esp_err_to_name(ps_error));
                }
                esp_err_t connect_error = esp_wifi_connect();
                ESP_LOGI(TAG, "network=sta-open ssid=%s connect=%s", ssid,
                         esp_err_to_name(connect_error));
                configured = true;
            }
            wifi_ap_record_t ap = {0};
            if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK &&
                esp_netif_get_ip_info(netif, &ip) == ESP_OK && ip.ip.addr != 0) {
                /* Also apply it after association, where the driver has
                 * finished loading the STA profile. */
                esp_err_t ps_error = esp_wifi_set_ps(WIFI_PS_NONE);
                if (ps_error != ESP_OK) {
                    ESP_LOGE(TAG, "associated power-save disable failed error=%s",
                             esp_err_to_name(ps_error));
                }
                send_network_up_event(local_address, &ap);
                return true;
            }
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        ESP_LOGW(TAG, "sta attempt window expired; sleeping before retry");
        (void)esp_wifi_disconnect();
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

void recovery_app_main(void)
{
    recovery_console_init();
    recovery_dry_run = recovery_get_dry_run();
    /* Emit the role/partition identity before any persistent-state work.  If
     * NVS is damaged, the managed forward must still be able to distinguish
     * a loaded Recovery image from a stage2 boot loop and send a repair
     * transport packet. */
    send_boot_identity();
    esp_err_t nvs_error = nvs_flash_init();
    if (nvs_error == ESP_ERR_NVS_NO_FREE_PAGES ||
        nvs_error == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS init requires repair error=%s; erasing NVS",
                 esp_err_to_name(nvs_error));
        ESP_ERROR_CHECK(nvs_flash_erase());
        nvs_error = nvs_flash_init();
    }
    ESP_ERROR_CHECK(nvs_error);
    /* Keep the UART task alive for the entire network/flash lifetime so a
     * control packet can update the runtime transport without blocking the
     * flash worker. */
    xTaskCreate(uart_command_task, "recovery_uart", 6144, NULL, 5, NULL);
    if (!set_unconfigured_defaults()) {
        esp_restart();
    }
    bool key_present = trust_key_present();
    ESP_LOGI(TAG, "boot ssid=%s remote=%s key=%d dry_run=%d",
             ssid, remote_host, key_present, recovery_dry_run);

    ESP_LOGI(TAG, "waiting %u ms for explicit UART transport override",
             (unsigned)UART_COMMAND_GRACE_MS);
    vTaskDelay(pdMS_TO_TICKS(UART_COMMAND_GRACE_MS));

    if (!start_network()) {
        esp_restart();
    }
    /* Recovery is single-purpose: it only downloads Main. Main owns module,
     * data, and other partition operations. Keep the target explicit so a
     * stale host default cannot turn a Recovery boot into another operation. */
    bool ok = false;
    for (unsigned session = 0; session < RECOVERY_FLASH_ATTEMPTS && !ok; ++session) {
        if (!dmesh_flash_tcp_start_target(remote_port, remote_host, "main", NULL,
                                          recovery_dry_run)) {
            ESP_LOGE(TAG, "unable to arm negotiated Main TCP session attempt=%u/%u",
                     session + 1, RECOVERY_FLASH_ATTEMPTS);
            vTaskDelay(pdMS_TO_TICKS(500));
            continue;
        }
        /* Hashing/readback and erase/write can take several minutes over the
         * sleepy/AP path. Keep a healthy transfer from becoming a Recovery
         * reboot at the old 180-second limit. A completed failed worker is
         * re-armed immediately on the next session iteration. */
        for (unsigned tick = 0; tick < RECOVERY_FLASH_WAIT_SEC * 10u; ++tick) {
            if (dmesh_flash_tcp_accept()) { ok = true; break; }
            if (dmesh_flash_tcp_finished()) break;
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        if (!ok && session + 1 < RECOVERY_FLASH_ATTEMPTS) {
            ESP_LOGE(TAG, "Main TCP attempt failed; retrying attempt=%u/%u",
                     session + 1, RECOVERY_FLASH_ATTEMPTS);
            vTaskDelay(pdMS_TO_TICKS(500));
        }
    }
    ESP_LOGI(TAG, "negotiated Main flash result=%s attempts=%u wait_limit_sec=%u",
             ok ? "ok" : "failed", RECOVERY_FLASH_ATTEMPTS,
             RECOVERY_FLASH_WAIT_SEC);
    if (ok && recovery_dry_run) {
        /* A dry run is a transport/hash measurement. Do not select Main or
         * reboot into it after receiving the image; leave Recovery available
         * for another command or an explicit reboot. */
        ESP_LOGI(TAG, "dry-run complete; remaining in Recovery");
        while (true) vTaskDelay(pdMS_TO_TICKS(1000));
    }
    if (ok) {
        recovery_set_handoff(DMESH_BOOT_HEALTH_HANDOFF_MAIN);
    }
    esp_restart();
}
