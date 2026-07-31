#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
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
#include "nvs.h"
#include "nvs_flash.h"

#define TAG "dmesh-recovery"
#define RECOVERY_NAMESPACE "recovery"
#define DEFAULT_PORT 3333
#define MAX_IMAGE_SIZE (3 * 1024 * 1024)
#define STREAM_MAGIC 0x44525331u /* DRS1 */
#define RECOVERY_AP_IP "192.168.4.1"

static char ssid[33];
static char password[65];
static char remote_host[128];
static uint16_t remote_port = DEFAULT_PORT;

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
    if (nvs_open(RECOVERY_NAMESPACE, NVS_READONLY, &nvs) != ESP_OK) {
        return;
    }
    read_string(nvs, "ssid", ssid, sizeof(ssid));
    read_string(nvs, "password", password, sizeof(password));
    read_string(nvs, "server", remote_host, sizeof(remote_host));
    nvs_get_u16(nvs, "port", &remote_port);
    if (remote_port == 0) {
        remote_port = DEFAULT_PORT;
    }
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
        ESP_ERROR_CHECK(esp_wifi_start());
        ESP_ERROR_CHECK(esp_wifi_connect());
        ESP_LOGI(TAG, "network=sta ssid=%s", ssid);
    } else {
        netif = esp_netif_create_default_wifi_ap();
        wifi_config_t wifi = {0};
        uint8_t mac[6] = {0};
        ESP_ERROR_CHECK(esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP));
        snprintf((char *)wifi.ap.ssid, sizeof(wifi.ap.ssid),
                 "ESP32S3_8_BOOT_%02X%02X", mac[4], mac[5]);
        wifi.ap.ssid_len = strlen((char *)wifi.ap.ssid);
        /* lmesh's small bootstrap join helper uses the fixed test channel. */
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

static bool receive_bootstrap_image(int fd)
{
    uint32_t header[3];
    if (recv(fd, header, sizeof(header), MSG_WAITALL) != sizeof(header) ||
        ntohl(header[0]) != STREAM_MAGIC || ntohl(header[1]) != 0 ||
        ntohl(header[2]) == 0 || ntohl(header[2]) > MAX_IMAGE_SIZE) {
        ESP_LOGE(TAG, "bootstrap stream header rejected");
        return false;
    }

    uint32_t remaining = ntohl(header[2]);
    const esp_partition_t *main_part = esp_partition_find_first(
        ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_APP_OTA_0, "main");
    if (main_part == NULL || remaining > main_part->size) {
        return false;
    }
    if (esp_partition_erase_range(main_part, 0, (remaining + 0xfff) & ~0xfff) != ESP_OK) {
        return false;
    }

    uint8_t buffer[4096];
    uint32_t offset = 0;
    while (remaining != 0) {
        size_t want = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
        int got = recv(fd, buffer, want, MSG_WAITALL);
        if (got != (int)want || esp_partition_write(main_part, offset, buffer, want) != ESP_OK) {
            return false;
        }
        offset += want;
        remaining -= want;
    }
    return true;
}

void recovery_app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    load_request();
    bool key_present = trust_key_present();
    ESP_LOGI(TAG, "boot ssid=%s remote=%s key=%d", ssid, remote_host, key_present);

    start_network();
    int fd = remote_host[0] != '\0' ? connect_remote() : accept_client();
    if (fd < 0) {
        ESP_LOGE(TAG, "tcp connection failed");
        return;
    }

    if (key_present) {
        ESP_LOGI(TAG, "signed TCP stream required; bootstrap rejected");
        close(fd);
        return;
    }
    bool ok = receive_bootstrap_image(fd);
    close(fd);
    ESP_LOGI(TAG, "bootstrap result=%s", ok ? "ok" : "failed");
    if (ok) {
        esp_restart();
    }
}
