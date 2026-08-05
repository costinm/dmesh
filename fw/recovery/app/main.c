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
#include "esp_wifi.h"
#include "driver/uart.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "boot_health_rtc.h"
#include "boot_health_flash.h"
#include "boot_protocol.h"
#include "dmesh_flash_tcp.h"

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
 * RECOVER/STA handoff. Without this grace period, a stale or unreachable
 * NVS request can make Recovery attempt TCP and restart before the explicit
 * UART transport arrives. */
#define UART_COMMAND_GRACE_MS 1500

static char ssid[33];
static char remote_host[128];
static char local_address[32];
static uint16_t remote_port = DEFAULT_PORT;
static char uart_ssid[33];
static char uart_remote[128];
static uint16_t uart_port;

static void clear_recovery_request(void);

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
    uint8_t payload[DMESH_BOOT_HELLO_LEN] = {
        DMESH_BOOT_MAGIC_0, DMESH_BOOT_MAGIC_1, DMESH_BOOT_MAGIC_2,
        DMESH_BOOT_MAGIC_3, DMESH_BOOT_VERSION, DMESH_BOOT_KIND_HELLO,
        DMESH_BOOT_ROLE_RECOVERY, DMESH_BOOT_PARTITION_RECOVERY,
        (uint8_t)esp_reset_reason(), 0, 0, 0,
    };
    (void)esp_read_mac(payload + 12, ESP_MAC_WIFI_STA);
    uint8_t wire[DMESH_BOOT_HELLO_LEN * 2 + 2];
    size_t length = dmesh_boot_frame_encode(payload, sizeof(payload), wire,
                                             sizeof(wire));
    if (length != 0) {
        (void)uart_write_bytes(UART_NUM_0, wire, length);
    }
}

static void restart_task(void *arg)
{
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(150));
    esp_restart();
    vTaskDelete(NULL);
}

static bool save_sta_request(char *line);

static bool save_sta_packet(const uint8_t *packet, size_t length)
{
    if (length < DMESH_BOOT_STA_HEADER_LEN ||
        !dmesh_boot_is_magic(packet, length) ||
        packet[4] != DMESH_BOOT_VERSION ||
        packet[5] != DMESH_BOOT_KIND_COMMAND ||
        packet[6] != DMESH_BOOT_COMMAND_STA) {
        return false;
    }
    size_t endpoint_length = packet[7];
    if (length < DMESH_BOOT_STA_HEADER_LEN + endpoint_length + 3) {
        return false;
    }
    size_t cursor = 8;
    size_t local_length = packet[cursor++];
    size_t ssid_length = packet[cursor++];
    size_t password_length = packet[cursor++];
    size_t fields_length = endpoint_length + local_length + ssid_length + password_length;
    if (fields_length > length - cursor || fields_length > 220 ||
        endpoint_length == 0 || local_length == 0 || ssid_length == 0 ||
        endpoint_length >= 128 || local_length >= 32 || ssid_length >= sizeof(ssid) ||
        password_length >= 32) {
        return false;
    }
    char line[256];
    int written = snprintf(line, sizeof(line), "STA %.*s %.*s %.*s %.*s",
                           (int)endpoint_length, packet + cursor,
                           (int)local_length, packet + cursor + endpoint_length,
                           (int)ssid_length, packet + cursor + endpoint_length + local_length,
                           (int)password_length,
                           packet + cursor + endpoint_length + local_length + ssid_length);
    return written > 0 && (size_t)written < sizeof(line) && save_sta_request(line);
}

static void schedule_recovery_restart(bool reboot_main)
{
    if (reboot_main) {
        /* A normal Recovery completion tells stage2 that the next boot is a
         * fresh Main attempt.  Clear only the one-shot request marker; keep
         * the saved STA configuration for a future explicit update. */
        clear_recovery_request();
        dmesh_boot_journal_clear();
        dmesh_boot_health_write(DMESH_BOOT_HEALTH_RECOVERY_OK);
        const char response[] = "REBOOT_MAIN accepted\n";
        (void)uart_write_bytes(UART_NUM_0, response, sizeof(response) - 1);
    } else {
        /* Leave request_version/request_magic intact.  Stage2 will select
         * Recovery again and the configured Main transfer will be retried. */
        const char response[] = "RETRY_MAIN accepted\n";
        (void)uart_write_bytes(UART_NUM_0, response, sizeof(response) - 1);
    }
    xTaskCreate(restart_task, "recovery_restart", 2048, NULL,
                configMAX_PRIORITIES - 1, NULL);
    vTaskDelete(NULL);
}

static bool handle_recovery_command(char *line)
{
    if (strcmp(line, "REBOOT_MAIN") == 0) {
        schedule_recovery_restart(true);
        return true;
    }
    if (strcmp(line, "RETRY_MAIN") == 0) {
        schedule_recovery_restart(false);
        return true;
    }
    return false;
}

static void save_sta_and_restart(char *line)
{
    if (!save_sta_request(line)) {
        return;
    }
    /* Keep the reset outside the UART parser call stack. */
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
    if (command == NULL || strcmp(command, "STA") != 0 || endpoint == NULL ||
        local_ip == NULL || network == NULL) {
        return false;
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

    nvs_handle_t nvs;
    if (nvs_open(RECOVERY_NAMESPACE, NVS_READWRITE, &nvs) != ESP_OK) {
        return false;
    }
    esp_err_t err = nvs_set_str(nvs, "request_magic", "0x52455131");
    if (err == ESP_OK) err = nvs_set_str(nvs, "request_version", "1");
    if (err == ESP_OK) err = nvs_set_str(nvs, "ssid", network);
    if (err == ESP_OK) err = nvs_set_str(nvs, "server", endpoint);
    if (err == ESP_OK) err = nvs_set_str(nvs, "ip", local_ip);
    if (err == ESP_OK) err = nvs_set_u16(nvs, "port", (uint16_t)parsed);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    ESP_LOGI(TAG, "STA request saved ssid=%s server=%s port=%lu ip=%s result=%s",
             network, endpoint, parsed, local_ip, esp_err_to_name(err));
    return err == ESP_OK;
}

static void uart_command_task(void *arg)
{
    (void)arg;
    char line[256];
    size_t length = 0;
    uint8_t frame[sizeof(line)];
    size_t frame_length = 0;
    bool in_frame = false;
    bool escaped = false;
    while (true) {
        uint8_t byte;
        int got = uart_read_bytes(UART_NUM_0, &byte, 1, pdMS_TO_TICKS(100));
        if (got != 1) {
            continue;
        }
        if (byte == DMESH_BOOT_WIRE_FLAG) {
            if (in_frame && frame_length != 0) {
                if (frame_length < sizeof(line)) {
                    if (save_sta_packet(frame, frame_length)) {
                        xTaskCreate(restart_task, "recovery_restart", 2048, NULL,
                                    configMAX_PRIORITIES - 1, NULL);
                        vTaskDelete(NULL);
                        return;
                    }
                    memcpy(line, frame, frame_length);
                    line[frame_length] = '\0';
                    if (handle_recovery_command(line)) {
                        return;
                    }
                    save_sta_and_restart(line);
                }
            }
            in_frame = true;
            escaped = false;
            frame_length = 0;
            continue;
        }
        if (in_frame) {
            if (escaped) {
                if (frame_length < sizeof(frame)) {
                    frame[frame_length++] = byte ^ DMESH_BOOT_WIRE_ESCAPE_XOR;
                }
                escaped = false;
            } else if (byte == DMESH_BOOT_WIRE_ESCAPE) {
                escaped = true;
            } else if (frame_length < sizeof(frame)) {
                frame[frame_length++] = byte;
            }
            continue;
        }
        if (byte == '\n' || byte == '\r') {
            if (length != 0) {
                line[length] = '\0';
                if (handle_recovery_command(line)) {
                    return;
                }
                save_sta_and_restart(line);
                length = 0;
            }
        } else if (length + 1 < sizeof(line)) {
            line[length++] = (char)byte;
        } else {
            length = 0;
        }
    }
}

static void read_uart_override(void)
{
    if (!uart_is_driver_installed(UART_NUM_0)) {
        uart_config_t config = {
            .baud_rate = 115200,
            .data_bits = UART_DATA_8_BITS,
            .parity = UART_PARITY_DISABLE,
            .stop_bits = UART_STOP_BITS_1,
            .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
            .source_clk = UART_SCLK_DEFAULT,
        };
        if (uart_param_config(UART_NUM_0, &config) != ESP_OK ||
            uart_driver_install(UART_NUM_0, 512, 0, 0, NULL, 0) != ESP_OK) {
            return;
        }
    }

    char input[256] = {0};
    int length = uart_read_bytes(UART_NUM_0, (uint8_t *)input, sizeof(input) - 1,
                                 pdMS_TO_TICKS(500));
    if (length <= 0) {
        return;
    }
    input[length] = '\0';
    char *cursor = input;
    while (*cursor == ' ' || *cursor == '\r' || *cursor == '\n' || *cursor == '\t') {
        ++cursor;
    }
    if (strncmp(cursor, "RECOVER", 7) == 0 &&
        (cursor[7] == '\0' || cursor[7] == ' ' || cursor[7] == '\t')) {
        /* The second-stage bootloader consumes the RECOVER selector itself.
         * When it does, Recovery receives only the remaining arguments. */
        cursor += 7;
    } else {
        /* Accept the continuation left by the bootloader: endpoint IP, local
         * IP, and open-network SSID. */
        char probe[128] = {0};
        strlcpy(probe, cursor, sizeof(probe));
        char *probe_save = NULL;
        char *first = strtok_r(probe, " \t\r\n", &probe_save);
        if (first == NULL || strchr(first, ':') == NULL) {
            return;
        }
    }
    char *save = NULL;
    char *endpoint = strtok_r(cursor, " \t\r\n", &save);
    char *local_ip = strtok_r(NULL, " \t\r\n", &save);
    char *network = strtok_r(NULL, " \t\r\n", &save);
    char *network_password = strtok_r(NULL, " \t\r\n", &save);
    if (endpoint == NULL || local_ip == NULL || network == NULL) {
        return;
    }
    char *colon = strrchr(endpoint, ':');
    if (colon != NULL && colon[1] != '\0') {
        unsigned long parsed = strtoul(colon + 1, NULL, 10);
        if (parsed > 0 && parsed <= UINT16_MAX) {
            *colon = '\0';
            uart_port = (uint16_t)parsed;
        }
    }
    strlcpy(uart_remote, endpoint, sizeof(uart_remote));
    strlcpy(uart_ssid, network, sizeof(uart_ssid));
    strlcpy(local_address, local_ip, sizeof(local_address));
    if (network_password != NULL && network_password[0] != '\0') {
        ESP_LOGW(TAG, "rejecting non-open UART STA request");
        uart_remote[0] = '\0';
        uart_ssid[0] = '\0';
        return;
    }
    ESP_LOGI(TAG, "uart override remote=%s port=%u ssid=%s", uart_remote,
             (unsigned)uart_port, uart_ssid);
}

static bool read_string(nvs_handle_t nvs, const char *key, char *out, size_t size)
{
    size_t length = size;
    esp_err_t err = nvs_get_str(nvs, key, out, &length);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        out[0] = '\0';
        return false;
    }
    if (err != ESP_OK || length == 0 || out[length - 1] != '\0') {
        out[0] = '\0';
        return false;
    }
    return true;
}

static void load_request(void)
{
    nvs_handle_t nvs;
    esp_err_t open_error = nvs_open(RECOVERY_NAMESPACE, NVS_READONLY, &nvs);
    if (open_error != ESP_OK) {
        ESP_LOGW(TAG, "nvs namespace open failed error=%s", esp_err_to_name(open_error));
        return;
    }
    bool have_ssid = read_string(nvs, "ssid", ssid, sizeof(ssid));
    bool have_server = read_string(nvs, "server", remote_host, sizeof(remote_host));
    bool have_local = read_string(nvs, "ip", local_address, sizeof(local_address));
    esp_err_t port_error = nvs_get_u16(nvs, "port", &remote_port);
    if (remote_port == 0) {
        remote_port = DEFAULT_PORT;
    }
    ESP_LOGI(TAG, "nvs ssid=%d server=%d ip=%d port=%u port_error=%s",
             have_ssid, have_server, have_local, (unsigned)remote_port,
             esp_err_to_name(port_error));
    nvs_close(nvs);
}

static bool ensure_recovery_request(void)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(RECOVERY_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "request ensure open failed error=%s", esp_err_to_name(err));
        return false;
    }
    err = nvs_set_u32(nvs, "request_magic", 0x52455131u);
    if (err == ESP_OK) {
        err = nvs_set_u32(nvs, "request_version", 1);
    }
    if (err == ESP_OK) {
        err = nvs_commit(nvs);
    }
    nvs_close(nvs);
    ESP_LOGI(TAG, "request ensure result=%s", esp_err_to_name(err));
    return err == ESP_OK;
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
    wifi_init_config_t config = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&config));
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
                esp_err_t connect_error = esp_wifi_connect();
                ESP_LOGI(TAG, "network=sta-open ssid=%s connect=%s", ssid,
                         esp_err_to_name(connect_error));
                configured = true;
            }
            wifi_ap_record_t ap = {0};
            if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK &&
                esp_netif_get_ip_info(netif, &ip) == ESP_OK && ip.ip.addr != 0) {
                ESP_LOGI(TAG, "sta_ip=" IPSTR, IP2STR(&ip.ip));
                return true;
            }
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        ESP_LOGW(TAG, "sta attempt window expired; sleeping before retry");
        (void)esp_wifi_disconnect();
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

static void clear_recovery_request(void)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(RECOVERY_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "request clear open failed error=%s", esp_err_to_name(err));
        return;
    }
    /* Keep the transport configuration, including the provisioned static IP,
     * for the next recovery request. Only the one-shot request marker is
     * cleared after a successful image write. */
    const char *keys[] = {"request_magic", "request_version", "flags"};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        esp_err_t erase_error = nvs_erase_key(nvs, keys[i]);
        if (erase_error != ESP_OK && erase_error != ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGE(TAG, "request clear key=%s error=%s", keys[i],
                     esp_err_to_name(erase_error));
            nvs_close(nvs);
            return;
        }
    }
    err = nvs_commit(nvs);
    nvs_close(nvs);
    ESP_LOGI(TAG, "request clear result=%s", esp_err_to_name(err));
}

void recovery_app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    dmesh_boot_health_write(DMESH_BOOT_HEALTH_RECOVERY_START);
    /* Recovery is an update worker, not a passive boot target.  Keep the
     * stage2 one-shot marker armed until the Main transfer succeeds, so an
     * AP outage, TCP drop, or board reset returns here for another attempt. */
    if (!ensure_recovery_request()) {
        ESP_LOGE(TAG, "cannot arm automatic Main retry marker");
    }
    read_uart_override();
    send_boot_identity();
    xTaskCreate(uart_command_task, "recovery_uart", 6144, NULL, 5, NULL);
    load_request();
    if (uart_ssid[0] != '\0') {
        strlcpy(ssid, uart_ssid, sizeof(ssid));
        strlcpy(remote_host, uart_remote, sizeof(remote_host));
        remote_port = uart_port == 0 ? DEFAULT_PORT : uart_port;
    }
    if (!set_unconfigured_defaults()) {
        esp_restart();
    }
    bool key_present = trust_key_present();
    ESP_LOGI(TAG, "boot ssid=%s remote=%s key=%d", ssid, remote_host, key_present);

    ESP_LOGI(TAG, "waiting %u ms for explicit UART transport override",
             (unsigned)UART_COMMAND_GRACE_MS);
    vTaskDelay(pdMS_TO_TICKS(UART_COMMAND_GRACE_MS));

    if (!start_network()) {
        esp_restart();
    }
    if (!dmesh_flash_tcp_start(remote_port, remote_host)) {
        ESP_LOGE(TAG, "unable to start negotiated TCP session");
        esp_restart();
    }
    bool ok = false;
    for (unsigned attempt = 0; attempt < 1800; ++attempt) {
        if (dmesh_flash_tcp_accept()) { ok = true; break; }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    ESP_LOGI(TAG, "negotiated flash result=%s", ok ? "ok" : "failed");
    if (ok) {
        clear_recovery_request();
        dmesh_boot_journal_clear();
        dmesh_boot_health_write(DMESH_BOOT_HEALTH_RECOVERY_OK);
    }
    esp_restart();
}
