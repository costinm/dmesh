#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Generic hardware ABI shared by Main and flat no-std DMODs. This contract is
 * independent of Recovery and the mesh application. */
typedef struct {
    uint32_t abi_version;
    uint32_t size;
    uint32_t features;
    void *user;
    int (*gpio_config)(void *user, int pin, int mode, int pull, int level);
    int (*gpio_read)(void *user, int pin);
    int (*gpio_write)(void *user, int pin, int level);
    int (*adc_read)(void *user, int pin, uint32_t ref_mv, int *raw, uint32_t *mv);
    int (*i2c_transfer)(void *user, int port, int sda, int scl, uint32_t frequency,
                        uint8_t address, const uint8_t *tx, size_t tx_len,
                        uint8_t *rx, size_t rx_len, uint32_t timeout_ms);
    int (*spi_transfer)(void *user, const uint8_t *tx, uint8_t *rx, size_t len);
    int (*rgbled_write)(void *user, int pin, uint8_t red, uint8_t green, uint8_t blue);
    int (*irq_register)(void *user, int pin, int edge, uint16_t event_id);
    int (*irq_unregister)(void *user, int pin);
    int (*irq_enable)(void *user, int pin, int enabled);
    int (*event_wait)(void *user, uint32_t timeout_ms, uint16_t *event_id, int32_t *value);
    int (*should_stop)(void *user);
    int (*sleep_ms)(void *user, uint32_t ms);
    uint64_t (*now_ms)(void *user);
    /* Additive metadata path; adc_read remains stable for older modules. */
    int (*adc_read_ex)(void *user, int pin, uint32_t ref_mv, int *raw,
                       uint32_t *mv, int *unit, int *channel);
} dmesh_hw_host_v1;

#define DMESH_HW_ABI_VERSION 1u
#define DMESH_HW_MODE_INPUT 0
#define DMESH_HW_MODE_OUTPUT 1
#define DMESH_HW_MODE_INPUT_OUTPUT 2
#define DMESH_HW_PULL_NONE 0
#define DMESH_HW_PULL_UP 1
#define DMESH_HW_PULL_DOWN 2
#define DMESH_HW_IRQ_FALLING 1
#define DMESH_HW_IRQ_RISING 2
#define DMESH_HW_IRQ_BOTH 3
