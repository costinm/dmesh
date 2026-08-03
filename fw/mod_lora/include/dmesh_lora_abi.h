#pragma once

#include <stddef.h>
#include <stdint.h>

#define DMESH_LORA_ABI_VERSION 1u
#define DMESH_LORA_MAX_PACKET 255u

typedef enum {
    DMESH_LORA_CHIP_UNKNOWN = 0,
    DMESH_LORA_CHIP_SX127X = 1,
    DMESH_LORA_CHIP_SX126X = 2,
} dmesh_lora_chip_t;

typedef enum {
    DMESH_LORA_OK = 0,
    DMESH_LORA_ERR_ARGUMENT = -1,
    DMESH_LORA_ERR_UNSUPPORTED = -2,
    DMESH_LORA_ERR_IO = -3,
    DMESH_LORA_ERR_TIMEOUT = -4,
    DMESH_LORA_ERR_BUSY = -5,
    DMESH_LORA_ERR_PACKET = -6,
} dmesh_lora_result_t;

typedef int (*dmesh_lora_spi_transfer_fn)(void *user, const uint8_t *tx, uint8_t *rx, size_t len);
typedef int (*dmesh_lora_gpio_write_fn)(void *user, int pin, int level);
typedef int (*dmesh_lora_gpio_read_fn)(void *user, int pin);
typedef int (*dmesh_lora_irq_configure_fn)(void *user, int pin, int active_level);
typedef int (*dmesh_lora_irq_enable_fn)(void *user, int pin, int enabled);
typedef int (*dmesh_lora_wait_irq_fn)(void *user, uint32_t timeout_ms);
typedef uint64_t (*dmesh_lora_now_ms_fn)(void *user);
typedef int (*dmesh_lora_log_fn)(void *user, const uint8_t *data, size_t len);
typedef int (*dmesh_lora_packet_fn)(void *user, const uint8_t *data, size_t len, int16_t rssi_dbm, int8_t snr_db);

typedef struct {
    uint32_t abi_version;
    uint32_t size;
    uint32_t features;
    void *user;
    dmesh_lora_spi_transfer_fn spi_transfer;
    dmesh_lora_gpio_write_fn gpio_write;
    dmesh_lora_gpio_read_fn gpio_read;
    dmesh_lora_irq_configure_fn irq_configure;
    dmesh_lora_irq_enable_fn irq_enable;
    dmesh_lora_wait_irq_fn wait_irq;
    dmesh_lora_now_ms_fn now_ms;
    dmesh_lora_log_fn log_line;
    dmesh_lora_packet_fn emit_packet;
} dmesh_lora_host_v1;

typedef struct {
    uint32_t abi_version;
    uint32_t size;
    dmesh_lora_chip_t chip;
    uint32_t frequency_hz;
    uint32_t bandwidth_hz;
    uint32_t spreading_factor;
    int32_t spi_host;
    uint8_t sync_word;
    uint8_t tx_power;
    int8_t reset_pin;
    int8_t cs_pin;
    int8_t irq_pin;
    int8_t busy_pin;
} dmesh_lora_config_v1;
