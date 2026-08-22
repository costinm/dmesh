#include "dmesh_hw_host.h"

#include <stdbool.h>
#include <string.h>

#include "driver/gpio.h"
#include "driver/i2c.h"
#include "esp_adc/adc_oneshot.h"
#include "esp_err.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

extern int32_t dmesh_ws2812_write(uint8_t gpio, uint8_t red, uint8_t green,
                                  uint8_t blue);

typedef struct {
    uint16_t event_id;
    int32_t value;
} hw_event_t;

typedef struct {
    bool used;
    int pin;
    uint16_t event_id;
} hw_irq_slot_t;

static QueueHandle_t event_queue;
static hw_irq_slot_t irq_slots[8];
static volatile bool stop_requested;
static bool stop_reported;
static int (*generic_spi_transfer)(void *user, const uint8_t *tx, uint8_t *rx, size_t len);

static void ensure_queue(void)
{
    if (event_queue == NULL) event_queue = xQueueCreate(16, sizeof(hw_event_t));
}

static void IRAM_ATTR hw_gpio_isr(void *arg)
{
    hw_irq_slot_t *slot = (hw_irq_slot_t *)arg;
    if (slot == NULL || !slot->used || event_queue == NULL) return;
    hw_event_t event = {.event_id = slot->event_id,
                        .value = gpio_get_level((gpio_num_t)slot->pin)};
    BaseType_t higher = pdFALSE;
    (void)xQueueSendFromISR(event_queue, &event, &higher);
    if (higher) portYIELD_FROM_ISR();
}

static int gpio_configure(void *user, int pin, int mode, int pull, int level)
{
    (void)user;
    if (pin < 0 || pin > 48) return ESP_ERR_INVALID_ARG;
    gpio_mode_t gpio_mode = mode == DMESH_HW_MODE_INPUT ? GPIO_MODE_INPUT :
        mode == DMESH_HW_MODE_OUTPUT ? GPIO_MODE_OUTPUT : GPIO_MODE_INPUT_OUTPUT;
    esp_err_t err = gpio_reset_pin((gpio_num_t)pin);
    if (err != ESP_OK) return err;
    err = gpio_set_direction((gpio_num_t)pin, gpio_mode);
    if (err != ESP_OK) return err;
    (void)gpio_pullup_dis((gpio_num_t)pin);
    (void)gpio_pulldown_dis((gpio_num_t)pin);
    if (pull == DMESH_HW_PULL_UP) (void)gpio_pullup_en((gpio_num_t)pin);
    if (pull == DMESH_HW_PULL_DOWN) (void)gpio_pulldown_en((gpio_num_t)pin);
    if (mode != DMESH_HW_MODE_INPUT) err = gpio_set_level((gpio_num_t)pin, level != 0);
    return err;
}

static int gpio_read(void *user, int pin)
{
    (void)user;
    if (pin < 0 || pin > 48) return ESP_ERR_INVALID_ARG;
    return gpio_get_level((gpio_num_t)pin);
}

static int gpio_write(void *user, int pin, int level)
{
    (void)user;
    if (pin < 0 || pin > 48) return ESP_ERR_INVALID_ARG;
    return gpio_set_level((gpio_num_t)pin, level != 0);
}

static int adc_read(void *user, int pin, uint32_t ref_mv, int *raw, uint32_t *mv)
{
    (void)user;
    if (raw == NULL || mv == NULL) return ESP_ERR_INVALID_ARG;
    adc_unit_t unit;
    adc_channel_t channel;
    esp_err_t err = adc_oneshot_io_to_channel(pin, &unit, &channel);
    if (err != ESP_OK || unit != ADC_UNIT_1) return err != ESP_OK ? err : ESP_ERR_NOT_SUPPORTED;
    adc_oneshot_unit_handle_t handle = NULL;
    adc_oneshot_unit_init_cfg_t init = {.unit_id = unit, .clk_src = 0,
                                        .ulp_mode = ADC_ULP_MODE_DISABLE};
    err = adc_oneshot_new_unit(&init, &handle);
    if (err != ESP_OK) return err;
    adc_oneshot_chan_cfg_t cfg = {.atten = ADC_ATTEN_DB_12, .bitwidth = ADC_BITWIDTH_12};
    err = adc_oneshot_config_channel(handle, channel, &cfg);
    if (err == ESP_OK) err = adc_oneshot_read(handle, channel, raw);
    if (err == ESP_OK) *mv = (uint32_t)(((*raw < 0 ? 0 : *raw) * ref_mv + 2047) / 4095);
    (void)adc_oneshot_del_unit(handle);
    return err;
}

static int adc_read_ex(void *user, int pin, uint32_t ref_mv, int *raw, uint32_t *mv,
                       int *unit_out, int *channel_out)
{
    (void)user;
    if (raw == NULL || mv == NULL) return ESP_ERR_INVALID_ARG;
    adc_unit_t unit;
    adc_channel_t channel;
    esp_err_t err = adc_oneshot_io_to_channel(pin, &unit, &channel);
    if (err != ESP_OK || unit != ADC_UNIT_1) return err != ESP_OK ? err : ESP_ERR_NOT_SUPPORTED;
    adc_oneshot_unit_handle_t handle = NULL;
    adc_oneshot_unit_init_cfg_t init = {.unit_id = unit, .clk_src = 0,
                                        .ulp_mode = ADC_ULP_MODE_DISABLE};
    err = adc_oneshot_new_unit(&init, &handle);
    if (err != ESP_OK) return err;
    adc_oneshot_chan_cfg_t cfg = {.atten = ADC_ATTEN_DB_12, .bitwidth = ADC_BITWIDTH_12};
    err = adc_oneshot_config_channel(handle, channel, &cfg);
    if (err == ESP_OK) err = adc_oneshot_read(handle, channel, raw);
    if (err == ESP_OK) {
        *mv = (uint32_t)(((*raw < 0 ? 0 : *raw) * ref_mv + 2047) / 4095);
        if (unit_out != NULL) *unit_out = (int)unit + 1;
        if (channel_out != NULL) *channel_out = (int)channel;
    }
    (void)adc_oneshot_del_unit(handle);
    return err;
}

static int i2c_transfer(void *user, int port, int sda, int scl, uint32_t frequency,
                        uint8_t address, const uint8_t *tx, size_t tx_len,
                        uint8_t *rx, size_t rx_len, uint32_t timeout_ms)
{
    (void)user;
    if (port < 0 || port > 1 || (tx_len != 0 && tx == NULL) || (rx_len != 0 && rx == NULL))
        return ESP_ERR_INVALID_ARG;
    i2c_port_t bus = (i2c_port_t)port;
    i2c_config_t cfg = {.mode = I2C_MODE_MASTER, .sda_io_num = sda, .scl_io_num = scl,
                        .sda_pullup_en = GPIO_PULLUP_ENABLE,
                        .scl_pullup_en = GPIO_PULLUP_ENABLE,
                        .master.clk_speed = frequency < 10000 ? 10000 : frequency};
    esp_err_t err = i2c_param_config(bus, &cfg);
    if (err != ESP_OK) return err;
    (void)i2c_driver_delete(bus);
    err = i2c_driver_install(bus, cfg.mode, 0, 0, 0);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) return err;
    TickType_t timeout = pdMS_TO_TICKS(timeout_ms > 0 ? timeout_ms : 1000);
    if (rx_len != 0) {
        if (tx_len > 255) err = ESP_ERR_INVALID_SIZE;
        else err = i2c_master_write_read_device(bus, address, tx, tx_len, rx, rx_len, timeout);
    } else if (tx_len != 0) {
        err = i2c_master_write_to_device(bus, address, tx, tx_len, timeout);
    }
    (void)i2c_driver_delete(bus);
    return err;
}

static int rgbled_write(void *user, int pin, uint8_t r, uint8_t g, uint8_t b)
{
    (void)user;
    return dmesh_ws2812_write((uint8_t)pin, r, g, b);
}

static int spi_transfer(void *user, const uint8_t *tx, uint8_t *rx, size_t len)
{
    if (generic_spi_transfer == NULL) return ESP_ERR_NOT_SUPPORTED;
    return generic_spi_transfer(user, tx, rx, len);
}

static int irq_register(void *user, int pin, int edge, uint16_t event_id)
{
    (void)user;
    ensure_queue();
    for (size_t i = 0; i < sizeof(irq_slots) / sizeof(irq_slots[0]); ++i) {
        if (!irq_slots[i].used) {
            hw_irq_slot_t *slot = &irq_slots[i];
            slot->pin = pin; slot->event_id = event_id; slot->used = true;
            esp_err_t err = gpio_install_isr_service(ESP_INTR_FLAG_IRAM);
            if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) { slot->used = false; return err; }
            err = gpio_set_intr_type((gpio_num_t)pin,
                edge == DMESH_HW_IRQ_RISING ? GPIO_INTR_POSEDGE :
                edge == DMESH_HW_IRQ_BOTH ? GPIO_INTR_ANYEDGE : GPIO_INTR_NEGEDGE);
            if (err == ESP_OK) err = gpio_isr_handler_add((gpio_num_t)pin, hw_gpio_isr, slot);
            if (err == ESP_OK) err = gpio_intr_enable((gpio_num_t)pin);
            if (err != ESP_OK) slot->used = false;
            return err;
        }
    }
    return ESP_ERR_NO_MEM;
}

static int irq_unregister(void *user, int pin)
{
    (void)user;
    for (size_t i = 0; i < sizeof(irq_slots) / sizeof(irq_slots[0]); ++i) {
        if (irq_slots[i].used && irq_slots[i].pin == pin) {
            (void)gpio_intr_disable((gpio_num_t)pin);
            (void)gpio_isr_handler_remove((gpio_num_t)pin);
            irq_slots[i].used = false;
            return 0;
        }
    }
    return ESP_ERR_NOT_FOUND;
}

static int irq_enable(void *user, int pin, int enabled)
{
    (void)user;
    return enabled ? gpio_intr_enable((gpio_num_t)pin) : gpio_intr_disable((gpio_num_t)pin);
}

static int event_wait(void *user, uint32_t timeout_ms, uint16_t *event_id, int32_t *value)
{
    (void)user;
    if (event_id == NULL || value == NULL) return ESP_ERR_INVALID_ARG;
    ensure_queue();
    hw_event_t event;
    if (xQueueReceive(event_queue, &event, pdMS_TO_TICKS(timeout_ms)) != pdTRUE) return 1;
    *event_id = event.event_id; *value = event.value;
    return 0;
}

static int should_stop(void *user)
{
    (void)user;
    if (stop_requested && !stop_reported) {
        ESP_LOGI("dmesh_hw", "module stop requested");
        stop_reported = true;
    }
    return stop_requested ? 1 : 0;
}
static int sleep_ms(void *user, uint32_t ms) { (void)user; vTaskDelay(pdMS_TO_TICKS(ms)); return 0; }
static uint64_t now_ms(void *user) { (void)user; return (uint64_t)(xTaskGetTickCount() * portTICK_PERIOD_MS); }

dmesh_hw_host_v1 dmesh_hw_host = {
    .abi_version = DMESH_HW_ABI_VERSION, .size = sizeof(dmesh_hw_host_v1),
    .features = 0, .user = NULL, .gpio_config = gpio_configure,
    .gpio_read = gpio_read, .gpio_write = gpio_write, .adc_read = adc_read,
    .i2c_transfer = i2c_transfer, .spi_transfer = spi_transfer,
    .rgbled_write = rgbled_write, .irq_register = irq_register,
    .irq_unregister = irq_unregister, .irq_enable = irq_enable,
    .event_wait = event_wait, .should_stop = should_stop, .sleep_ms = sleep_ms,
    .now_ms = now_ms, .adc_read_ex = adc_read_ex,
};

void dmesh_hw_host_reset(void)
{
    stop_requested = false;
    stop_reported = false;
    memset(irq_slots, 0, sizeof(irq_slots));
}

void dmesh_hw_host_request_stop(bool stop) { stop_requested = stop; }

void dmesh_hw_host_set_spi(int (*transfer)(void *user, const uint8_t *tx,
                                           uint8_t *rx, size_t len))
{
    generic_spi_transfer = transfer;
}
