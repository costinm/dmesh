#include "dmesh_nimble.h"

#include <stdio.h>
#include <string.h>

#include "esp_err.h"
#include "esp_attr.h"
#include "esp_log.h"
#include "sdkconfig.h"
#include "hal/gpio_ll.h"
#include "soc/gpio_struct.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "host/ble_gap.h"
#include "host/ble_hs.h"
#include "host/ble_hs_id.h"
#include "host/ble_l2cap.h"
#include "host/util/util.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "nimble/nimble_npl.h"
#include "freertos/semphr.h"
#include "os/os_mbuf.h"
#include "syscfg/syscfg.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

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
static struct ble_npl_event s_adv_start_event;
static bool s_adv_start_event_ready;
/* GAP APIs are individually serialized by NimBLE, but replacing an
 * advertisement is a stop / configure / start transaction.  Firmware command
 * handling and companion polling run in different tasks, so protect the
 * whole transaction rather than allowing their individual GAP calls to
 * interleave. */
static SemaphoreHandle_t s_adv_lock;
static uint8_t s_adv_data[31];
static uint8_t s_adv_len;
static uint16_t s_adv_min = 0x20;
static uint16_t s_adv_max = 0x40;

#if MYNEWT_VAL(BLE_L2CAP_COC_MAX_NUM) >= 1
/* A deliberately small, opt-in CoC transport.  The application creates the
 * server only after a `ble coc=true` command; normal GATT/rendezvous traffic
 * does not allocate a channel. */
/* CoC itself is reliable and segments/reassembles below this SDU size.  Keep
 * a normal QUIC-lite packet plus stream framing in one bounded application
 * buffer; 256 was only the original echo-test ceiling. */
#define DMESH_COC_MTU 1152
#define DMESH_COC_BUF_COUNT 4
static os_membuf_t s_coc_mem[OS_MEMPOOL_SIZE(DMESH_COC_BUF_COUNT, DMESH_COC_MTU)];
static struct os_mempool s_coc_mempool;
static struct os_mbuf_pool s_coc_pool;
static bool s_coc_pool_ready;
static bool s_coc_server_started;
static uint16_t s_coc_psm;
static uint16_t s_coc_psm_requested;
static struct ble_l2cap_chan *s_coc_chan;
static struct ble_npl_event s_coc_start_event;
static bool s_coc_start_event_ready;
static struct ble_npl_event s_coc_tx_event;
static bool s_coc_tx_event_ready;
static uint8_t s_coc_tx_buf[DMESH_COC_MTU];
static uint16_t s_coc_tx_len;
static bool s_coc_tx_pending;
static SemaphoreHandle_t s_coc_tx_lock;
#endif

static int dmesh_gap_event(struct ble_gap_event *event, void *arg);
static int start_adv_now(void);
static void log_line(const char *line);

static void dmesh_adv_start_event_cb(struct ble_npl_event *event) {
    (void)event;
    /* GAP procedures must be started by the NimBLE host task. Firmware
     * command/rendezvous code only records the advertisement to publish. */
    if (s_adv_wanted) {
        int rc = start_adv_now();
        if (rc != 0) {
            char line[96];
            snprintf(line, sizeof(line),
                     "event type=ble.advertise state=failed rc=%d", rc);
            log_line(line);
        }
    }
}

static void log_line(const char *line) {
    ESP_LOGI(TAG, "%s", line);
    dmesh_nimble_on_log(line);
}

#if MYNEWT_VAL(BLE_L2CAP_COC_MAX_NUM) >= 1
static int dmesh_coc_recv_ready(struct ble_l2cap_chan *chan) {
    struct os_mbuf *sdu = os_mbuf_get_pkthdr(&s_coc_pool, 0);
    if (sdu == NULL) {
        return BLE_HS_ENOMEM;
    }
    return ble_l2cap_recv_ready(chan, sdu);
}

static int dmesh_coc_send_now(const uint8_t *data, uint16_t len) {
    if (data == NULL || len == 0 || len > DMESH_COC_MTU || s_coc_chan == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    struct os_mbuf *tx = os_mbuf_get_pkthdr(&s_coc_pool, 0);
    if (tx == NULL) {
        return BLE_HS_ENOMEM;
    }
    if (os_mbuf_append(tx, data, len) != 0) {
        os_mbuf_free_chain(tx);
        return BLE_HS_EMSGSIZE;
    }
    int rc = ble_l2cap_send(s_coc_chan, tx);
    if (rc != 0) {
        os_mbuf_free_chain(tx);
    }
    return rc;
}

static void dmesh_coc_tx_event_cb(struct ble_npl_event *event) {
    (void)event;
    if (s_coc_tx_lock == NULL || xSemaphoreTake(s_coc_tx_lock, portMAX_DELAY) != pdTRUE) {
        return;
    }
    uint16_t len = s_coc_tx_len;
    bool pending = s_coc_tx_pending;
    s_coc_tx_pending = false;
    int rc = pending ? dmesh_coc_send_now(s_coc_tx_buf, len) : 0;
    xSemaphoreGive(s_coc_tx_lock);
    if (rc != 0) {
        char line[96];
        snprintf(line, sizeof(line), "event type=ble.coc state=tx_failed rc=%d", rc);
        log_line(line);
    }
}

int32_t dmesh_nimble_coc_send(const uint8_t *data, uint16_t len) {
    if (data == NULL || len == 0 || len > DMESH_COC_MTU || !s_coc_tx_event_ready) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_coc_tx_lock == NULL || xSemaphoreTake(s_coc_tx_lock, portMAX_DELAY) != pdTRUE) {
        return ESP_ERR_INVALID_STATE;
    }
    if (s_coc_chan == NULL || s_coc_tx_pending) {
        xSemaphoreGive(s_coc_tx_lock);
        return ESP_ERR_INVALID_STATE;
    }
    memcpy(s_coc_tx_buf, data, len);
    s_coc_tx_len = len;
    s_coc_tx_pending = true;
    xSemaphoreGive(s_coc_tx_lock);
    ble_npl_eventq_put(nimble_port_get_dflt_eventq(), &s_coc_tx_event);
    return 0;
}

static int dmesh_coc_event(struct ble_l2cap_event *event, void *arg) {
    (void)arg;
    switch (event->type) {
    case BLE_L2CAP_EVENT_COC_ACCEPT:
        return dmesh_coc_recv_ready(event->accept.chan);
    case BLE_L2CAP_EVENT_COC_CONNECTED:
        if (event->connect.status != 0) {
            char line[96];
            snprintf(line, sizeof(line), "event type=ble.coc state=connect_failed rc=%d psm=0x%04x",
                     event->connect.status, s_coc_psm);
            log_line(line);
        } else {
            s_coc_chan = event->connect.chan;
            dmesh_nimble_on_coc_state(1);
            log_line("event type=ble.coc state=connected");
        }
        return 0;
    case BLE_L2CAP_EVENT_COC_DATA_RECEIVED: {
        struct os_mbuf *rx = event->receive.sdu_rx;
        if (rx != NULL) {
            uint16_t len = OS_MBUF_PKTLEN(rx);
            uint8_t buf[DMESH_COC_MTU];
            uint16_t copied = 0;
            if (len <= sizeof(buf) &&
                ble_hs_mbuf_to_flat(rx, buf, sizeof(buf), &copied) == 0 &&
                copied == len) {
                dmesh_nimble_on_coc_write(buf, len);
            }
            os_mbuf_free_chain(rx);
        }
        return dmesh_coc_recv_ready(event->receive.chan);
    }
    case BLE_L2CAP_EVENT_COC_DISCONNECTED:
        if (s_coc_chan == event->disconnect.chan) {
            s_coc_chan = NULL;
            dmesh_nimble_on_coc_state(0);
        }
        log_line("event type=ble.coc state=disconnected");
        return 0;
    default:
        return 0;
    }
}
#endif

#if MYNEWT_VAL(BLE_L2CAP_COC_MAX_NUM) >= 1
static void dmesh_coc_start_if_requested(void);

static void dmesh_coc_start_event_cb(struct ble_npl_event *event) {
    (void)event;
    /* The default queue is consumed by nimble_port_run(), i.e. the NimBLE
     * host task.  Do not create a listening PSM from the UART command task. */
    dmesh_coc_start_if_requested();
}

/* NimBLE host APIs must run on its host task. The firmware command handler
 * runs on the application task, so it records a request and the next NimBLE
 * callback creates the server. Calling ble_l2cap_create_server directly from
 * the command task can block the console behind the host lock. */
static void dmesh_coc_start_if_requested(void) {
    if (s_coc_server_started || s_coc_psm_requested == 0 || !s_coc_pool_ready) {
        return;
    }
    int rc = ble_l2cap_create_server(s_coc_psm_requested, DMESH_COC_MTU,
                                     dmesh_coc_event, NULL);
    if (rc == 0) {
        s_coc_psm = s_coc_psm_requested;
        s_coc_server_started = true;
        log_line("event type=ble.coc state=server_ready");
    } else {
        char line[96];
        snprintf(line, sizeof(line), "event type=ble.coc state=server_failed rc=%d psm=0x%04x",
                 rc, s_coc_psm_requested);
        log_line(line);
    }
}
#endif

static int start_adv_now(void) {
    int rc;
    struct ble_gap_adv_params params = {0};
    const uint8_t scan_rsp[] = {
        0x06, 0x09, 'D', 'M', 'e', 's', 'h',
    };

    if (!s_synced || s_adv_len == 0) {
        return 0;
    }

    if (s_adv_lock == NULL || xSemaphoreTake(s_adv_lock, portMAX_DELAY) != pdTRUE) {
        return ESP_ERR_INVALID_STATE;
    }

    rc = ble_gap_adv_stop();
    /* Stopping an already-idle advertiser is harmless. Report every other
     * failure with a distinct stage so the Android companion lab can diagnose
     * the transition without logcat. */
    /* Classic ESP32 reports EALREADY for an idle advertiser; ESP32-S3's
     * NimBLE host reports EINVAL for the same harmless stop. */
    if (rc != 0 && rc != BLE_HS_EALREADY && rc != BLE_HS_EINVAL) {
        xSemaphoreGive(s_adv_lock);
        return 1000 + rc;
    }

    rc = ble_gap_adv_set_data(s_adv_data, s_adv_len);
    if (rc != 0) {
        xSemaphoreGive(s_adv_lock);
        return 2000 + rc;
    }
    rc = ble_gap_adv_rsp_set_data(scan_rsp, sizeof(scan_rsp));
    if (rc != 0) {
        xSemaphoreGive(s_adv_lock);
        return 3000 + rc;
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
    xSemaphoreGive(s_adv_lock);
    return rc == 0 ? 0 : 4000 + rc;
}

static int dmesh_gap_event(struct ble_gap_event *event, void *arg) {
    (void)arg;
#if MYNEWT_VAL(BLE_L2CAP_COC_MAX_NUM) >= 1
    dmesh_coc_start_if_requested();
#endif
    /* Keep this callback deliberately small: it runs on the NimBLE host task.
     * Do not query the peer, restart advertising, emit console records, or
     * wake other radios here. */
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            dmesh_nimble_on_connect(event->connect.conn_handle);
            log_line("event type=ble.gap state=connected");
        } else {
            char line[80];
            snprintf(line, sizeof(line), "event type=ble.gap state=connect_failed rc=%d",
                     event->connect.status);
            log_line(line);
        }
        break;
    case BLE_GAP_EVENT_DISCONNECT:
        dmesh_nimble_on_disconnect(event->disconnect.reason);
        {
            char line[80];
            snprintf(line, sizeof(line), "event type=ble.gap state=disconnected reason=%d",
                     event->disconnect.reason);
            log_line(line);
        }
        /* LE advertising stops while a central owns the GAP connection.  CoC
         * is intentionally short-lived, so retain the requested rendezvous
         * advertisement for the next Android connection after disconnect. */
        if (s_adv_wanted) {
            int rc = start_adv_now();
            if (rc != 0) {
                char line[96];
                snprintf(line, sizeof(line),
                         "event type=ble.advertise state=restart_failed rc=%d", rc);
                log_line(line);
            } else {
                log_line("event type=ble.advertise state=restarted");
            }
        }
        break;
    default:
        break;
    }
    return 0;
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
#if MYNEWT_VAL(BLE_L2CAP_COC_MAX_NUM) >= 1
        dmesh_coc_start_if_requested();
#endif
        if (s_adv_wanted) {
            start_adv_now();
        }
    } else {
        char line[80];
        snprintf(line, sizeof(line), "event type=nimble.sync ok=false rc=%d", rc);
        log_line(line);
    }
}

static void nimble_host_task(void *param) {
    (void)param;
    nimble_port_run();
    nimble_port_freertos_deinit();
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

    /* CoC-only companion mode deliberately has no DMesh GATT application
     * service.  ATT/GATT remains part of the BLE stack, but the only public
     * rendezvous is advertising and all DMesh payloads use an LE CoC channel.
     * This avoids retaining a notify subscription simply to carry data. */

    ble_hs_cfg.reset_cb = on_stack_reset;
    ble_hs_cfg.sync_cb = on_stack_sync;
    /* Establish basic ATT/GATT for CoC negotiation.  DMesh does not expose a
     * GATT payload or bond-management control surface. */
    ble_hs_cfg.sm_bonding = 0;
    ble_hs_cfg.sm_mitm = 0;
    ble_hs_cfg.sm_sc = 1;
    ble_hs_cfg.sm_io_cap = BLE_HS_IO_NO_INPUT_OUTPUT;

#if MYNEWT_VAL(BLE_L2CAP_COC_MAX_NUM) >= 1
    rc = os_mempool_init(&s_coc_mempool, DMESH_COC_BUF_COUNT, DMESH_COC_MTU,
                         s_coc_mem, "dmesh_coc");
    if (rc != 0) {
        return rc;
    }
    rc = os_mbuf_pool_init(&s_coc_pool, &s_coc_mempool, DMESH_COC_MTU,
                           DMESH_COC_BUF_COUNT);
    if (rc != 0) {
        return rc;
    }
    s_coc_pool_ready = true;
    ble_npl_event_init(&s_coc_start_event, dmesh_coc_start_event_cb, NULL);
    s_coc_start_event_ready = true;
    s_coc_tx_lock = xSemaphoreCreateMutex();
    if (s_coc_tx_lock == NULL) {
        return ESP_ERR_NO_MEM;
    }
    ble_npl_event_init(&s_coc_tx_event, dmesh_coc_tx_event_cb, NULL);
    s_coc_tx_event_ready = true;
#endif

    s_adv_lock = xSemaphoreCreateMutex();
    if (s_adv_lock == NULL) {
        return ESP_ERR_NO_MEM;
    }
    ble_npl_event_init(&s_adv_start_event, dmesh_adv_start_event_cb, NULL);
    s_adv_start_event_ready = true;

    /* ESP-IDF owns controller enablement and host-task affinity.  The manual
     * xTaskCreate path can run nimble_port_run without enabling the controller
     * and stalls the application/UART task on classic ESP32. */
    nimble_port_freertos_init(nimble_host_task);
    s_started = true;
    log_line("event type=nimble.init ok=true");
    return 0;
}

int32_t dmesh_nimble_start_coc_server(uint16_t psm) {
#if MYNEWT_VAL(BLE_L2CAP_COC_MAX_NUM) >= 1
    if (!s_started || !s_coc_pool_ready) {
        return ESP_ERR_INVALID_STATE;
    }
    if (psm < 0x0080 || psm > 0x00ff) {
        /* The Android public client API accepts application dynamic LE PSMs
         * in this range.  IPSP's assigned PSM is intentionally not exposed
         * by this raw echo probe. */
        return ESP_ERR_INVALID_ARG;
    }
    if (s_coc_server_started) {
        return psm == s_coc_psm ? 0 : ESP_ERR_INVALID_STATE;
    }
    s_coc_psm_requested = psm;
    if (!s_coc_start_event_ready) {
        return ESP_ERR_INVALID_STATE;
    }
    /* The listener itself is installed only by the NimBLE host task.  Queue
     * that work after sync; the UART command may take several seconds while
     * the controller starts, so callers must use the BLE command timeout. */
    if (s_synced) {
        ble_npl_eventq_put(nimble_port_get_dflt_eventq(), &s_coc_start_event);
    }
    return 0;
#else
    (void)psm;
    return ESP_ERR_NOT_SUPPORTED;
#endif
}

#if MYNEWT_VAL(BLE_L2CAP_COC_MAX_NUM) < 1
int32_t dmesh_nimble_coc_send(const uint8_t *data, uint16_t len) {
    (void)data;
    (void)len;
    return ESP_ERR_NOT_SUPPORTED;
}
#endif

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
    if (!s_started || !s_adv_start_event_ready) {
        return ESP_ERR_INVALID_STATE;
    }
    ble_npl_eventq_put(nimble_port_get_dflt_eventq(), &s_adv_start_event);
    return 0;
}

int32_t dmesh_nimble_stop_advertising(void) {
    s_adv_wanted = false;
    if (!s_started || !s_synced) {
        return 0;
    }
    if (s_adv_lock == NULL || xSemaphoreTake(s_adv_lock, portMAX_DELAY) != pdTRUE) {
        return ESP_ERR_INVALID_STATE;
    }
    ble_gap_adv_stop();
    xSemaphoreGive(s_adv_lock);
    return 0;
}
