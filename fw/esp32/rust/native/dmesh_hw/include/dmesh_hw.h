#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t dmesh_ws2812_write(uint8_t gpio, uint8_t red, uint8_t green,
                           uint8_t blue);

// IRAM-only GPIO callbacks used by Rust tasks. Their only responsibility is
// to notify a FreeRTOS task; all parsing, logging, and radio work stays out of
// the interrupt context.
void dmesh_button_irq_set_task(void *task);
void dmesh_button_irq_rearm(void);
void dmesh_button_gpio_isr(void *arg);
void dmesh_lora_irq_set_task(void *task);
void dmesh_lora_irq_rearm(void);
void dmesh_lora_gpio_isr(void *arg);

#ifdef __cplusplus
}
#endif
