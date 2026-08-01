#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "esp_event.h"
#include "esp_log.h"
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

#define TAG "dmesh-recovery"
#define RECOVERY_NAMESPACE "recovery"
#define DEFAULT_PORT 3333
#define MAX_IMAGE_SIZE (3 * 1024 * 1024)
#define STREAM_MAGIC 0x44525331u /* DRS1 */
/* Keep the UART command task alive long enough for the second-stage
 * RECOVER/STA handoff. Without this grace period, a stale or unreachable
 * NVS request can make Recovery attempt TCP and restart before the explicit
 * UART transport arrives. */
#define UART_COMMAND_GRACE_MS 7000

static char ssid[33];
static char password[65];
static char remote_host[128];
static char local_address[32];
static uint16_t remote_port = DEFAULT_PORT;
static char uart_ssid[33];
static char uart_remote[128];
static uint16_t uart_port;

static void restart_task(void *arg)
{
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(150));
    esp_restart();
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
    while (true) {
        uint8_t byte;
        int got = uart_read_bytes(UART_NUM_0, &byte, 1, pdMS_TO_TICKS(100));
        if (got != 1) {
            continue;
        }
        if (byte == '\n' || byte == '\r') {
            if (length != 0) {
                line[length] = '\0';
                if (save_sta_request(line)) {
                    /* Do not restart while this task is still unwinding the
                     * token/NVS/logging call chain.  In particular, the S3
                     * UART/NVS path needs more stack and a clean reset task. */
                    xTaskCreate(restart_task, "recovery_restart", 2048, NULL,
                                configMAX_PRIORITIES - 1, NULL);
                    vTaskDelete(NULL);
                }
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
         * IP, SSID, and optional password. */
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
    password[0] = '\0';
    if (network_password != NULL) {
        strlcpy(password, network_password, sizeof(password));
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
    bool have_password = read_string(nvs, "password", password, sizeof(password));
    bool have_server = read_string(nvs, "server", remote_host, sizeof(remote_host));
    bool have_local = read_string(nvs, "ip", local_address, sizeof(local_address));
    esp_err_t port_error = nvs_get_u16(nvs, "port", &remote_port);
    if (remote_port == 0) {
        remote_port = DEFAULT_PORT;
    }
    ESP_LOGI(TAG, "nvs ssid=%d password=%d server=%d ip=%d port=%u port_error=%s",
             have_ssid, have_password, have_server, have_local, (unsigned)remote_port,
             esp_err_to_name(port_error));
    nvs_close(nvs);
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

static void start_network(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_netif_t *netif;
    wifi_init_config_t config = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&config));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

    if (ssid[0] != '\0') {
        netif = esp_netif_create_default_wifi_sta();
        wifi_config_t wifi = {0};
        strlcpy((char *)wifi.sta.ssid, ssid, sizeof(wifi.sta.ssid));
        strlcpy((char *)wifi.sta.password, password, sizeof(wifi.sta.password));
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi));
        if (local_address[0] != '\0') {
            esp_netif_ip_info_t static_ip = {0};
            uint32_t parsed_ip = esp_ip4addr_aton(local_address);
            if (parsed_ip == 0) {
                ESP_LOGE(TAG, "invalid sta ip=%s", local_address);
            } else {
                static_ip.ip.addr = parsed_ip;
                IP4_ADDR(&static_ip.gw, 10, 78, 0, 1);
                IP4_ADDR(&static_ip.netmask, 255, 255, 255, 0);
                ESP_ERROR_CHECK(esp_netif_dhcpc_stop(netif));
                ESP_ERROR_CHECK(esp_netif_set_ip_info(netif, &static_ip));
                ESP_LOGI(TAG, "sta_static_ip=%s", local_address);
            }
        }
        ESP_ERROR_CHECK(esp_wifi_start());
        ESP_ERROR_CHECK(esp_wifi_connect());
        ESP_LOGI(TAG, "network=sta ssid=%s", ssid);
        wifi_ap_record_t ap = {0};
        esp_netif_ip_info_t ip = {0};
        for (unsigned attempt = 0; attempt < 150; ++attempt) {
            if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK &&
                esp_netif_get_ip_info(netif, &ip) == ESP_OK && ip.ip.addr != 0) {
                ESP_LOGI(TAG, "sta_ip=" IPSTR, IP2STR(&ip.ip));
                break;
            }
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        if (ip.ip.addr == 0) {
            ESP_LOGE(TAG, "sta address timeout");
        }
    } else {
        netif = esp_netif_create_default_wifi_ap();
        wifi_config_t wifi = {0};
        uint8_t mac[6] = {0};
        ESP_ERROR_CHECK(esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP));
        snprintf((char *)wifi.ap.ssid, sizeof(wifi.ap.ssid),
                 "ESP32S3_8_BOOT_%02X%02X", mac[4], mac[5]);
        wifi.ap.ssid_len = strlen((char *)wifi.ap.ssid);
        wifi.ap.channel = 6;
        wifi.ap.max_connection = 1;
        wifi.ap.authmode = WIFI_AUTH_OPEN;
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi));
        ESP_ERROR_CHECK(esp_netif_dhcps_stop(netif));
        esp_netif_ip_info_t ip = {0};
        IP4_ADDR(&ip.ip, 192, 168, 4, 1);
        IP4_ADDR(&ip.gw, 192, 168, 4, 1);
        IP4_ADDR(&ip.netmask, 255, 255, 255, 0);
        ESP_ERROR_CHECK(esp_netif_set_ip_info(netif, &ip));
        ESP_ERROR_CHECK(esp_netif_dhcps_start(netif));
        ESP_ERROR_CHECK(esp_wifi_start());
        ESP_ERROR_CHECK(esp_wifi_set_bandwidth(WIFI_IF_AP, WIFI_BW_HT20));
        ESP_LOGI(TAG, "network=ap ssid=%s ip=%s open=true", wifi.ap.ssid, RECOVERY_AP_IP);
    }
    (void)netif;
}

static int connect_remote(void)
{
    char port[8];
    snprintf(port, sizeof(port), "%u", (unsigned)remote_port);
    struct addrinfo hints = {.ai_socktype = SOCK_STREAM};
    struct addrinfo *result = NULL;
    if (getaddrinfo(remote_host, port, &hints, &result) != 0 || result == NULL) {
        return -1;
    }
    int fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (fd >= 0 && connect(fd, result->ai_addr, result->ai_addrlen) != 0) {
        close(fd);
        fd = -1;
    }
    freeaddrinfo(result);
    return fd;
}

static int accept_client(void)
{
    int server = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (server < 0) {
        return -1;
    }
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(remote_port),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    int one = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) != 0 || listen(server, 1) != 0) {
        close(server);
        return -1;
    }
    ESP_LOGI(TAG, "tcp_server port=%u", (unsigned)remote_port);
    int client = accept(server, NULL, NULL);
    close(server);
    return client;
}

static int recv_all(int fd, void *buffer, size_t length)
{
    size_t received = 0;
    while (received < length) {
        int count = recv(fd, (uint8_t *)buffer + received, length - received, 0);
        if (count <= 0) {
            return (int)received;
        }
        received += (size_t)count;
    }
    return (int)received;
}

static bool receive_bootstrap_image(int fd)
{
    uint32_t header[3];
    int header_bytes = recv_all(fd, header, sizeof(header));
    if (header_bytes != sizeof(header)) {
        ESP_LOGE(TAG, "bootstrap header recv failed bytes=%d errno=%d", header_bytes, errno);
        return false;
    }
    uint32_t image_size = ntohl(header[2]);
    if (ntohl(header[0]) != STREAM_MAGIC || ntohl(header[1]) != 0 ||
        image_size == 0 || image_size > MAX_IMAGE_SIZE) {
        ESP_LOGE(TAG, "bootstrap header rejected magic=%08" PRIx32 " target=%" PRIu32
                 " size=%" PRIu32, ntohl(header[0]), ntohl(header[1]), image_size);
        return false;
    }

    uint32_t remaining = image_size;
    const esp_partition_t *main_part = esp_partition_find_first(
        ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_APP_OTA_0, "main");
    if (main_part == NULL || remaining > main_part->size) {
        ESP_LOGE(TAG, "bootstrap partition rejected partition=%p size=%" PRIu32,
                 (void *)main_part, main_part == NULL ? 0 : main_part->size);
        return false;
    }
    uint32_t erase_size = (remaining + 0xfff) & ~0xfff;
    ESP_LOGI(TAG, "bootstrap image size=%" PRIu32 " erase=%" PRIu32, remaining, erase_size);
    esp_err_t erase_error = esp_partition_erase_range(main_part, 0, erase_size);
    if (erase_error != ESP_OK) {
        ESP_LOGE(TAG, "bootstrap erase failed offset=0 size=%" PRIu32 " error=%s",
                 erase_size, esp_err_to_name(erase_error));
        return false;
    }

    uint8_t buffer[4096];
    uint32_t offset = 0;
    while (remaining != 0) {
        size_t want = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
        int got = recv_all(fd, buffer, want);
        if (got != (int)want) {
            ESP_LOGE(TAG, "bootstrap recv failed offset=%" PRIu32 " want=%u got=%d errno=%d",
                     offset, (unsigned)want, got, errno);
            return false;
        }
        esp_err_t write_error = esp_partition_write(main_part, offset, buffer, want);
        if (write_error != ESP_OK) {
            ESP_LOGE(TAG, "bootstrap write failed offset=%" PRIu32 " size=%u error=%s",
                     offset, (unsigned)want, esp_err_to_name(write_error));
            return false;
        }
        offset += want;
        remaining -= want;
    }
    return true;
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
    read_uart_override();
    xTaskCreate(uart_command_task, "recovery_uart", 6144, NULL, 5, NULL);
    load_request();
    if (uart_ssid[0] != '\0') {
        strlcpy(ssid, uart_ssid, sizeof(ssid));
        strlcpy(remote_host, uart_remote, sizeof(remote_host));
        remote_port = uart_port == 0 ? DEFAULT_PORT : uart_port;
    }
    bool key_present = trust_key_present();
    ESP_LOGI(TAG, "boot ssid=%s remote=%s key=%d", ssid, remote_host, key_present);

    ESP_LOGI(TAG, "waiting %u ms for explicit UART transport override",
             (unsigned)UART_COMMAND_GRACE_MS);
    vTaskDelay(pdMS_TO_TICKS(UART_COMMAND_GRACE_MS));

    start_network();
    int fd = remote_host[0] != '\0' ? connect_remote() : accept_client();
    if (fd < 0) {
        ESP_LOGE(TAG, "tcp connection failed");
        esp_restart();
    }

    if (key_present) {
        ESP_LOGI(TAG, "signed TCP stream required; bootstrap rejected");
        close(fd);
        esp_restart();
    }
    bool ok = receive_bootstrap_image(fd);
    close(fd);
    ESP_LOGI(TAG, "bootstrap result=%s", ok ? "ok" : "failed");
    if (ok) {
        clear_recovery_request();
        dmesh_boot_health_write(DMESH_BOOT_HEALTH_RECOVERY_OK);
    }
    esp_restart();
}
