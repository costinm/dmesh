/*
 * Core/Recovery has no board peripherals or legacy Main command loop.  These
 * weak ABI hooks let it link the module loader for inspection/control and
 * report unsupported callbacks to a module.  Main's hardware adapters supply
 * strong definitions when present, without making the loader Main-owned.
 */
#include <stddef.h>
#include <stdint.h>

__attribute__((weak)) int32_t dmesh_ws2812_write(uint8_t gpio, uint8_t red,
                                                   uint8_t green, uint8_t blue)
{
    (void)gpio; (void)red; (void)green; (void)blue;
    return -1;
}

__attribute__((weak)) void dmesh_lora_irq_set_task(void *task) { (void)task; }
__attribute__((weak)) void dmesh_lora_irq_rearm(void) {}
__attribute__((weak)) void dmesh_lora_gpio_isr(void *arg) { (void)arg; }
