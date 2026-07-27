#include "dmesh_nimble.h"

#include <stdio.h>
#include <string.h>

#include "esp_err.h"
#include "esp_attr.h"
#include "esp_log.h"
#include "sdkconfig.h"
#include "hal/gpio_ll.h"
#include "soc/gpio_struct.h"
#if CONFIG_IDF_TARGET_ESP32
#include "esp_bt.h"
#endif
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "host/ble_hs.h"
#include "host/ble_hs_id.h"
#include "host/ble_hs_mbuf.h"
#include "host/ble_store.h"
#include "host/ble_uuid.h"
#include "host/util/util.h"
#include "nimble/nimble_port.h"
#include "os/os_mbuf.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#include "store/config/ble_store_config.h"

void ble_store_config_init(void);

static const char *TAG = "dmesh_nimble";

static volatile TaskHandle_t s_button_irq_task;
static volatile TaskHandle_t s_lora_irq_task;
static volatile bool s_button_irq_pending;
static volatile bool s_lora_irq_pending;

void dmesh_button_irq_set_task(void *task) {
    s_button_irq_task = (TaskHandle_t)task;
    s_button_irq_pending = false;
}

void dmesh_lora_irq_set_task(void *task) {
    s_lora_irq_task = (TaskHandle_t)task;
    s_lora_irq_pending = false;
}

void dmesh_button_irq_rearm(void) {
    s_button_irq_pending = false;
}

void dmesh_lora_irq_rearm(void) {
    s_lora_irq_pending = false;
}

static void IRAM_ATTR notify_task_from_gpio_isr(volatile TaskHandle_t *task,
                                                 volatile bool *pending) {
    TaskHandle_t target = *task;
    if (target == NULL || *pending) {
        return;
    }
    *pending = true;
    BaseType_t higher_priority_task_woken = pdFALSE;
    vTaskGenericNotifyGiveFromISR(target, 0, &higher_priority_task_woken);
    if (higher_priority_task_woken == pdTRUE) {
        portYIELD_FROM_ISR();
    }
}

void IRAM_ATTR dmesh_button_gpio_isr(void *arg) {
    (void)arg;
    notify_task_from_gpio_isr(&s_button_irq_task, &s_button_irq_pending);
}

void IRAM_ATTR dmesh_lora_gpio_isr(void *arg) {
    const uint32_t pin = (uint32_t)(uintptr_t)arg;
    // The configured LoRa IRQ pin is asserted for every modem event. Mask it before waking the
    // task so a noisy or uncleared radio IRQ cannot repeatedly enter the GPIO
    // dispatcher and starve CPU0. The LoRa task reads/clears the chip IRQ and
    // re-enables this pin for the next mode-specific event.
    if (pin < 32) {
        gpio_ll_intr_disable(&GPIO, pin);
        gpio_ll_clear_intr_status(&GPIO, 1U << pin);
    } else {
        gpio_ll_intr_disable(&GPIO, pin);
        gpio_ll_clear_intr_status_high(&GPIO, 1U << (pin - 32));
    }
    notify_task_from_gpio_isr(&s_lora_irq_task, &s_lora_irq_pending);
}

static uint8_t s_addr_type;
static uint8_t s_addr[6];
static bool s_started;
static bool s_synced;
static bool s_adv_wanted;
static uint8_t s_adv_data[31];
static uint8_t s_adv_len;
static uint16_t s_adv_min = 0x20;
static uint16_t s_adv_max = 0x40;
static uint16_t s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
static bool s_notify_enabled;

static uint16_t s_rx_handle;
static uint16_t s_tx_handle;

static int dmesh_gap_event(struct ble_gap_event *event, void *arg);
static int dmesh_chr_access(uint16_t conn_handle, uint16_t attr_handle,
                            struct ble_gatt_access_ctxt *ctxt, void *arg);

static const ble_uuid128_t dmesh_service_uuid =
    BLE_UUID128_INIT(0x03, 0x00, 0x68, 0x73, 0x65, 0x4d, 0x42, 0x8c,
                     0x6f, 0x4a, 0x2a, 0x4f, 0x80, 0x6f, 0x6b, 0x5f);
static const ble_uuid128_t dmesh_rx_uuid =
    BLE_UUID128_INIT(0x04, 0x00, 0x68, 0x73, 0x65, 0x4d, 0x42, 0x8c,
                     0x6f, 0x4a, 0x2a, 0x4f, 0x80, 0x6f, 0x6b, 0x5f);
static const ble_uuid128_t dmesh_tx_uuid =
    BLE_UUID128_INIT(0x05, 0x00, 0x68, 0x73, 0x65, 0x4d, 0x42, 0x8c,
                     0x6f, 0x4a, 0x2a, 0x4f, 0x80, 0x6f, 0x6b, 0x5f);

static const struct ble_gatt_svc_def dmesh_svcs[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &dmesh_service_uuid.u,
        .characteristics =
            (struct ble_gatt_chr_def[]){
                {
                    .uuid = &dmesh_rx_uuid.u,
                    .access_cb = dmesh_chr_access,
                    .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP,
                    .val_handle = &s_rx_handle,
                },
                {
                    .uuid = &dmesh_tx_uuid.u,
                    .access_cb = dmesh_chr_access,
                    .flags = BLE_GATT_CHR_F_NOTIFY,
                    .val_handle = &s_tx_handle,
                },
                {0},
            },
    },
    {0},
};

static void log_line(const char *line) {
    ESP_LOGI(TAG, "%s", line);
    dmesh_nimble_on_log(line);
}

static int start_adv_now(void) {
    int rc;
    struct ble_gap_adv_params params = {0};
    const uint8_t scan_rsp[] = {
        0x06, 0x09, 'D', 'M', 'e', 's', 'h',
    };

    if (!s_synced || s_adv_len == 0) {
        return 0;
    }

    ble_gap_adv_stop();

    rc = ble_gap_adv_set_data(s_adv_data, s_adv_len);
    if (rc != 0) {
        return rc;
    }
    rc = ble_gap_adv_rsp_set_data(scan_rsp, sizeof(scan_rsp));
    if (rc != 0) {
        return rc;
    }

    params.conn_mode = BLE_GAP_CONN_MODE_UND;
    params.disc_mode = BLE_GAP_DISC_MODE_GEN;
    params.itvl_min = s_adv_min;
    params.itvl_max = s_adv_max;

    rc = ble_gap_adv_start(s_addr_type, NULL, BLE_HS_FOREVER, &params,
                           dmesh_gap_event, NULL);
    if (rc == 0) {
        s_adv_wanted = true;
    }
    return rc;
}

static int dmesh_chr_access(uint16_t conn_handle, uint16_t attr_handle,
                            struct ble_gatt_access_ctxt *ctxt, void *arg) {
    if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR && attr_handle == s_rx_handle) {
        uint8_t buf[512];
        uint16_t len = 0;
        struct os_mbuf *om = ctxt->om;
        while (om != NULL) {
            uint16_t chunk = OS_MBUF_PKTLEN(om);
            if ((size_t)len + chunk > sizeof(buf)) {
                return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
            }
            int rc = ble_hs_mbuf_to_flat(om, buf + len, sizeof(buf) - len, &chunk);
            if (rc != 0) {
                return BLE_ATT_ERR_UNLIKELY;
            }
            len += chunk;
            break;
        }
        dmesh_nimble_on_write(buf, len);
        return 0;
    }
    return BLE_ATT_ERR_UNLIKELY;
}

static int dmesh_gap_event(struct ble_gap_event *event, void *arg) {
    struct ble_gap_conn_desc desc;
    int rc;

    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            s_conn_handle = event->connect.conn_handle;
            s_notify_enabled = false;
            memset(&desc, 0, sizeof(desc));
            rc = ble_gap_conn_find(event->connect.conn_handle, &desc);
            if (rc == 0) {
                dmesh_nimble_on_connect(event->connect.conn_handle,
                                        desc.peer_id_addr.val,
                                        desc.sec_state.encrypted,
                                        desc.sec_state.authenticated,
                                        desc.sec_state.bonded);
            } else {
                uint8_t zero[6] = {0};
                dmesh_nimble_on_connect(event->connect.conn_handle, zero, 0, 0, 0);
            }
        } else if (s_adv_wanted) {
            start_adv_now();
        }
        return 0;
    case BLE_GAP_EVENT_DISCONNECT:
        s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
        s_notify_enabled = false;
        dmesh_nimble_on_disconnect(event->disconnect.reason);
        if (s_adv_wanted) {
            start_adv_now();
        }
        return 0;
    case BLE_GAP_EVENT_SUBSCRIBE:
        if (event->subscribe.attr_handle == s_tx_handle) {
            s_notify_enabled = event->subscribe.cur_notify;
            dmesh_nimble_on_subscribe(event->subscribe.attr_handle,
                                      event->subscribe.cur_notify);
        }
        return 0;
    case BLE_GAP_EVENT_ENC_CHANGE:
        if (ble_gap_conn_find(event->enc_change.conn_handle, &desc) == 0) {
            dmesh_nimble_on_connect(event->enc_change.conn_handle,
                                    desc.peer_id_addr.val,
                                    desc.sec_state.encrypted,
                                    desc.sec_state.authenticated,
                                    desc.sec_state.bonded);
        }
        return 0;
    case BLE_GAP_EVENT_ADV_COMPLETE:
        if (s_adv_wanted) {
            start_adv_now();
        }
        return 0;
    default:
        return 0;
    }
}

static void on_stack_reset(int reason) {
    char line[80];
    snprintf(line, sizeof(line), "event type=nimble.reset reason=%d", reason);
    log_line(line);
}

static void on_stack_sync(void) {
    int rc = ble_hs_util_ensure_addr(0);
    if (rc == 0) {
        rc = ble_hs_id_infer_auto(0, &s_addr_type);
    }
    if (rc == 0) {
        rc = ble_hs_id_copy_addr(s_addr_type, s_addr, NULL);
    }
    s_synced = rc == 0;
    if (s_synced) {
        dmesh_nimble_on_ready(s_addr, s_addr_type);
        if (s_adv_wanted) {
            start_adv_now();
        }
    } else {
        char line[80];
        snprintf(line, sizeof(line), "event type=nimble.sync ok=false rc=%d", rc);
        log_line(line);
    }
}

static void gatts_register_cb(struct ble_gatt_register_ctxt *ctxt, void *arg) {
    (void)ctxt;
    (void)arg;
}

static void nimble_host_task(void *param) {
    (void)param;
    nimble_port_run();
    vTaskDelete(NULL);
}

int32_t dmesh_nimble_init(void) {
    if (s_started) {
        return 0;
    }

    int rc = nimble_port_init();
    if (rc != ESP_OK) {
        return rc;
    }

    ble_svc_gap_init();
    ble_svc_gap_device_name_set("DMesh");
    ble_svc_gatt_init();

    rc = ble_gatts_count_cfg(dmesh_svcs);
    if (rc != 0) {
        return rc;
    }
    rc = ble_gatts_add_svcs(dmesh_svcs);
    if (rc != 0) {
        return rc;
    }

    ble_hs_cfg.reset_cb = on_stack_reset;
    ble_hs_cfg.sync_cb = on_stack_sync;
    ble_hs_cfg.gatts_register_cb = gatts_register_cb;
    ble_hs_cfg.store_status_cb = ble_store_util_status_rr;
    ble_hs_cfg.sm_bonding = 1;
    ble_hs_cfg.sm_mitm = 0;
    ble_hs_cfg.sm_sc = 1;
    ble_hs_cfg.sm_io_cap = BLE_HS_IO_NO_INPUT_OUTPUT;

    ble_store_config_init();

    BaseType_t created =
        xTaskCreate(nimble_host_task, "dmesh-nimble", 4096, NULL, 5, NULL);
    if (created != pdPASS) {
        return ESP_FAIL;
    }
    s_started = true;
    log_line("event type=nimble.init ok=true");
    return 0;
}

int32_t dmesh_nimble_start_advertising(const uint8_t *adv, uint8_t adv_len,
                                       uint16_t min_units, uint16_t max_units) {
    if (adv == NULL || adv_len == 0 || adv_len > sizeof(s_adv_data)) {
        return ESP_ERR_INVALID_ARG;
    }
    memcpy(s_adv_data, adv, adv_len);
    s_adv_len = adv_len;
    s_adv_min = min_units;
    s_adv_max = max_units < min_units ? min_units : max_units;
    s_adv_wanted = true;
    return start_adv_now();
}

int32_t dmesh_nimble_stop_advertising(void) {
    s_adv_wanted = false;
    if (!s_started || !s_synced) {
        return 0;
    }
    ble_gap_adv_stop();
    return 0;
}

int32_t dmesh_nimble_notify(const uint8_t *data, uint16_t len) {
    if (s_conn_handle == BLE_HS_CONN_HANDLE_NONE || !s_notify_enabled) {
        return BLE_HS_ENOTCONN;
    }
    struct os_mbuf *om = ble_hs_mbuf_from_flat(data, len);
    if (om == NULL) {
        return BLE_HS_ENOMEM;
    }
    return ble_gatts_notify_custom(s_conn_handle, s_tx_handle, om);
}

int32_t dmesh_nimble_clear_bonds(void) {
    int rc = ble_store_clear();
    return rc == 0 ? 0 : rc;
}

uint16_t dmesh_nimble_tx_handle(void) {
    return s_tx_handle;
}

uint16_t dmesh_nimble_rx_handle(void) {
    return s_rx_handle;
}

int32_t dmesh_nimble_enable_sleep(void) {
#if CONFIG_IDF_TARGET_ESP32
    return esp_bt_sleep_enable();
#else
    return ESP_ERR_NOT_SUPPORTED;
#endif
}

int32_t dmesh_nimble_disable_sleep(void) {
#if CONFIG_IDF_TARGET_ESP32
    return esp_bt_sleep_disable();
#else
    return ESP_ERR_NOT_SUPPORTED;
#endif
}
