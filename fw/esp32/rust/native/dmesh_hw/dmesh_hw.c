#include "dmesh_hw.h"

#include "driver/rmt_common.h"
#include "driver/rmt_encoder.h"
#include "driver/rmt_tx.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "hal/gpio_types.h"
#include "driver/usb_serial_jtag.h"

int32_t dmesh_usb_serial_install(void) {
#if CONFIG_IDF_TARGET_ESP32C6
    usb_serial_jtag_driver_config_t config = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
    config.rx_buffer_size = 2048;
    config.tx_buffer_size = 2048;
    return usb_serial_jtag_driver_install(&config);
#else
    return ESP_ERR_NOT_SUPPORTED;
#endif
}

int32_t dmesh_usb_serial_read(void *buffer, uint32_t length, uint32_t ticks) {
#if CONFIG_IDF_TARGET_ESP32C6
    return usb_serial_jtag_read_bytes(buffer, length, ticks);
#else
    (void)buffer; (void)length; (void)ticks;
    return -1;
#endif
}

int32_t dmesh_usb_serial_write(const void *buffer, uint32_t length) {
#if CONFIG_IDF_TARGET_ESP32C6
    return usb_serial_jtag_write_bytes(buffer, length, 0);
#else
    (void)buffer; (void)length;
    return -1;
#endif
}

static void cleanup_rmt(rmt_channel_handle_t channel,
                        rmt_encoder_handle_t encoder) {
    if (channel != NULL) {
        (void)rmt_disable(channel);
        (void)rmt_del_channel(channel);
    }
    if (encoder != NULL) {
        (void)rmt_del_encoder(encoder);
    }
}

int32_t dmesh_ws2812_write(uint8_t gpio, uint8_t red, uint8_t green,
                           uint8_t blue) {
    esp_err_t err;
    rmt_channel_handle_t channel = NULL;
    rmt_encoder_handle_t encoder = NULL;
    uint8_t grb[3] = {green, red, blue};

    rmt_tx_channel_config_t channel_config = {
        .gpio_num = (gpio_num_t)gpio,
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .resolution_hz = 10000000,
        .mem_block_symbols = 64,
        .trans_queue_depth = 1,
    };
    err = rmt_new_tx_channel(&channel_config, &channel);
    if (err != ESP_OK) {
        cleanup_rmt(channel, encoder);
        return err;
    }

    rmt_bytes_encoder_config_t encoder_config = {
        .bit0 =
            {
                .duration0 = 3,
                .level0 = 1,
                .duration1 = 9,
                .level1 = 0,
            },
        .bit1 =
            {
                .duration0 = 9,
                .level0 = 1,
                .duration1 = 3,
                .level1 = 0,
            },
        .flags.msb_first = 1,
    };
    err = rmt_new_bytes_encoder(&encoder_config, &encoder);
    if (err != ESP_OK) {
        cleanup_rmt(channel, encoder);
        return err;
    }

    err = rmt_enable(channel);
    if (err != ESP_OK) {
        cleanup_rmt(channel, encoder);
        return err;
    }

    rmt_transmit_config_t tx_config = {
        .loop_count = 0,
        .flags.eot_level = 0,
    };
    err = rmt_transmit(channel, encoder, grb, sizeof(grb), &tx_config);
    if (err == ESP_OK) {
        err = rmt_tx_wait_all_done(channel, 100);
    }
    vTaskDelay(pdMS_TO_TICKS(1));
    cleanup_rmt(channel, encoder);
    return err;
}
