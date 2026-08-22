#include "dmesh_module_loader.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "esp_err.h"
#include "esp_flash.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "esp_cache.h"
#include "hal/mmu_hal.h"
#include "hal/mmu_types.h"
#if CONFIG_IDF_TARGET_ESP32
#include "esp_attr.h"
#include "esp_private/cache_utils.h"
#include "esp_private/esp_cache_esp32_private.h"
#include "hal/cache_ll.h"
#include "hal/cache_types.h"
#endif
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "esp_sleep.h"
#include "lwip/netif.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "dmesh_module_abi.h"
#include "dmesh_hw_host.h"

#define MODULE_ALIGN 0x10000u
/* xTaskCreate* takes stack depth in words (4 bytes on ESP32), not bytes.
 * mod_lora's RX loop owns bounded packet/FIFO buffers and invokes the SPI,
 * GPIO, event, and service callbacks from this task. 4096 words was enough
 * for the tiny hello module but left little headroom for the SX126x path.
 * Reserve 16K words (~64 KiB) so future ABI callbacks can grow without
 * coupling the module to Main's stack or heap. */
#define MODULE_TASK_STACK_DEFAULT 16384u
#define MODULE_TASK_STACK_MIN 4096u
#define MODULE_TASK_STACK_MAX 32768u
#define MODULE_TASK_PRIORITY 1u
#define MODULE_MAX_ARGUMENTS 4096u
#define LORA_COMMAND_MAX 128u
#define LORA_SPI_MAX_TRANSFER 272u
#define MODULE_DATA_START 0x3c0000u
#define MODULE_SERVICE_TAG_MIN 43u
#define MODULE_SERVICE_TAG_MAX 100u
#define MODULE_ARENA_SIZE (32u * 1024u)

static bool service_tag_offset(uint16_t service_tag, uint32_t *offset)
{
    if (offset == NULL || service_tag < MODULE_SERVICE_TAG_MIN ||
        service_tag > MODULE_SERVICE_TAG_MAX) return false;
    *offset = ((uint32_t)service_tag - MODULE_SERVICE_TAG_MIN) * MODULE_ALIGN;
    return true;
}

static bool header_service_window(const dmesh_module_header_t *header,
                                  uint16_t service_tag, uint32_t offset,
                                  uint32_t partition_size)
{
    uint32_t expected_offset = 0;
    if (header == NULL || !service_tag_offset(service_tag, &expected_offset) ||
        offset != expected_offset || header->service_tag != service_tag ||
        header->slot_count == 0 || header->image_size < DMESH_MODULE_HEADER_SIZE ||
        header->image_size > (uint32_t)header->slot_count * MODULE_ALIGN ||
        offset > partition_size || header->image_size > partition_size - offset) {
        return false;
    }
    return true;
}

/* The fixed-VMA experiment is deliberately opt-in through the DMOD header.
 * These windows are in the instruction linear region but well above the
 * normal application image. The module build links its code at
 * WINDOW + DMESH_MODULE_HEADER_SIZE; the mapped page still starts at the
 * 64-KiB-aligned module slot so the header and code share an aligned MMU
 * window. The window may span multiple 64 KiB pages. */
#if CONFIG_IDF_TARGET_ESP32S3
#define MODULE_FIXED_VADDR 0x43000000u
#define MODULE_FIXED_DATA_VADDR 0x3d000000u
/* Modules are mapped in whole 64-KiB MMU pages.  mod_lora is currently
 * slightly larger than two pages, so reserve four pages rather than making
 * an otherwise valid image fail before its entry point is reached. */
#define MODULE_FIXED_WINDOW_SIZE 0x40000u
#elif CONFIG_IDF_TARGET_ESP32
#define MODULE_FIXED_VADDR 0x40300000u
#define MODULE_FIXED_DATA_VADDR 0x3f700000u
#define MODULE_FIXED_WINDOW_SIZE 0x20000u
#endif

#if defined(MODULE_FIXED_VADDR)
_Static_assert((MODULE_FIXED_VADDR % 0x10000u) == 0, "module code alias must be MMU aligned");
_Static_assert((MODULE_FIXED_DATA_VADDR % 0x10000u) == 0, "module data alias must be MMU aligned");
_Static_assert(MODULE_FIXED_WINDOW_SIZE % 0x10000u == 0, "module window must be MMU-page aligned");
#if CONFIG_IDF_TARGET_ESP32
/* Main's classic ESP32 IROM begins at 0x400d0000. Keep the dynamic module
 * window above the application image rather than replacing Main's code. */
_Static_assert(MODULE_FIXED_VADDR >= 0x40300000u, "classic module alias overlaps Main IROM");
_Static_assert(MODULE_FIXED_DATA_VADDR >= 0x3f700000u, "classic module alias overlaps Main DROM");
#endif
#endif

static const char *TAG = "dmesh-module";

uint8_t dmesh_module_loader_ip_netif_flags(void *esp_netif)
{
    if (esp_netif == NULL) return 0;
    struct netif *netif = (struct netif *)esp_netif_get_netif_impl(esp_netif);
    return netif == NULL ? 0 : netif->flags;
}




uint8_t dmesh_module_loader_ip_netif_default(void *esp_netif)
{
    if (esp_netif == NULL) return 0;
    struct netif *netif = (struct netif *)esp_netif_get_netif_impl(esp_netif);
    return netif != NULL && netif_default == netif;
}

uint8_t dmesh_module_loader_ip_netif_io_state(void *esp_netif)
{
    if (esp_netif == NULL) return 0;
    struct netif *netif = (struct netif *)esp_netif_get_netif_impl(esp_netif);
    if (netif == NULL) return 0;
    uint8_t result = 0;
    if (netif->output != NULL) result |= 1u;
    if (netif->linkoutput != NULL) result |= 2u;
    if (netif->state != NULL) result |= 4u;
    if (netif->hwaddr_len != 0) result |= 8u;
    return result;
}

uint32_t dmesh_module_loader_ip_netif_addr(void *esp_netif, uint8_t which)
{
    if (esp_netif == NULL) return 0;
    struct netif *netif = (struct netif *)esp_netif_get_netif_impl(esp_netif);
    if (netif == NULL) return 0;
    if (which == 0) return netif->ip_addr.u_addr.ip4.addr;
    if (which == 1) return netif->netmask.u_addr.ip4.addr;
    if (which == 2) return netif->gw.u_addr.ip4.addr;
    return 0;
}


static dmesh_module_header_t cached_header;
static uint32_t cached_offset;
static esp_partition_t cached_raw_partition;
static const esp_partition_t *cached_partition;
static bool cached_header_valid;
static volatile bool cached_task_done;
static volatile bool cached_task_running;
static volatile uint64_t running_service_mask;
static volatile int cached_last_result = -999;
static volatile uint32_t cached_task_start_ms;
static volatile uint32_t cached_last_runtime_ms;
static volatile uint32_t cached_max_runtime_ms;
static volatile uint32_t cached_task_runs;
static volatile uint32_t cached_last_stack_high_water_words;
/* Main discards ESP_LOG output in normal operation; expose coarse diagnostic
 * state through module status instead. */
static volatile uint32_t cached_task_stage;
static volatile uint32_t cached_spi_calls;
static volatile uint32_t cached_spi_errors;
static volatile uint32_t cached_lora_poll_count;
static volatile uint32_t cached_lora_irq_wakes;
static volatile uint32_t cached_lora_irq_timeouts;
static volatile uint32_t cached_last_lora_payload_len;
static volatile uint32_t cached_last_lora_command_len;
static volatile uint32_t cached_module_event_calls;
static volatile uint32_t cached_last_module_event_id;
static volatile uint32_t cached_entry_args_len;
static char cached_entry_args[16];
static char cached_last_lora_command[16];
static TaskHandle_t cached_task_handle;
static char cached_task_name[16];
static volatile uint16_t cached_task_service_tag;
static portMUX_TYPE lora_command_mux = portMUX_INITIALIZER_UNLOCKED;

/* Main-owned transient memory map for module calls. The arena is reset before
 * each entry invocation and after it returns; modules must not retain these
 * pointers across calls or task restarts. */
static uint8_t module_arena[MODULE_ARENA_SIZE] __attribute__((aligned(16)));
static size_t module_arena_used;

static void module_arena_reset(void)
{
    module_arena_used = 0;
}

static void *module_alloc(void *user, size_t size, size_t align)
{
    (void)user;
    if (size == 0 || align == 0 || (align & (align - 1u)) != 0) return NULL;
    uintptr_t base = (uintptr_t)module_arena;
    uintptr_t current = base + module_arena_used;
    uintptr_t aligned = (current + align - 1u) & ~(align - 1u);
    if (aligned < current || aligned < base || aligned - base > MODULE_ARENA_SIZE ||
        size > MODULE_ARENA_SIZE - (size_t)(aligned - base)) return NULL;
    module_arena_used = (size_t)(aligned - base) + size;
    return (void *)aligned;
}

static bool service_running(uint16_t service_tag)
{
    if (service_tag < MODULE_SERVICE_TAG_MIN || service_tag > MODULE_SERVICE_TAG_MAX) return false;
    return (running_service_mask & (UINT64_C(1) << (service_tag - MODULE_SERVICE_TAG_MIN))) != 0;
}

static void service_set_running(uint16_t service_tag, bool running)
{
    if (service_tag < MODULE_SERVICE_TAG_MIN || service_tag > MODULE_SERVICE_TAG_MAX) return;
    uint64_t bit = UINT64_C(1) << (service_tag - MODULE_SERVICE_TAG_MIN);
    portENTER_CRITICAL(&lora_command_mux);
    if (running) running_service_mask |= bit;
    else running_service_mask &= ~bit;
    cached_task_running = running_service_mask != 0;
    portEXIT_CRITICAL(&lora_command_mux);
}
static spi_device_handle_t lora_spi;
static dmesh_lora_config_v1 lora_config = {
    .abi_version = DMESH_LORA_ABI_VERSION, .size = sizeof(dmesh_lora_config_v1),
    .spi_host = 2,
    .chip = DMESH_LORA_CHIP_SX127X, .reset_pin = 14, .cs_pin = 18,
    .irq_pin = 26, .busy_pin = -1, .sck_pin = 5, .miso_pin = 19, .mosi_pin = 27,
    .board_power_pin = -1, .board_power_level = 1,
    .sx1262_dio2_rf_switch = 0, .sx1262_tcxo_mv = 0,
    .sx1262_pa_duty = 4, .sx1262_pa_hp = 7,
    .sx1262_pa_device = 0, .sx1262_pa_lut = 1,
    .sx1262_sync_word = 0x24b4, .sx1262_rx_timeout_ms = 0,
    .coding_rate = 5, .preamble = 16, .crc = 1,
};

static spi_host_device_t lora_spi_host_device(void)
{
#if CONFIG_IDF_TARGET_ESP32C6
    /* C6 has no SPI3_HOST; map both persisted host values to SPI2. */
    return SPI2_HOST;
#else
    return lora_config.spi_host == 1 ? SPI2_HOST : SPI3_HOST;
#endif
}
static uint8_t lora_command_args[LORA_COMMAND_MAX];
static uint8_t lora_command_payload[DMESH_LORA_MAX_PACKET];
static size_t lora_command_args_len;
static size_t lora_command_payload_len;
static bool lora_command_pending;
static int log_line(void *user, const uint8_t *data, size_t len);

#if defined(MODULE_FIXED_VADDR)
static uint32_t module_mmu_id(void)
{
#if SOC_MMU_PER_EXT_MEM_TARGET
    return mmu_hal_get_id_from_target(MMU_TARGET_FLASH0);
#else
    /* ESP32/ESP32-S3 use the shared flash MMU table.  The ID is fixed at
     * zero; mmu_hal_get_id_from_target() is not declared by those targets. */
    return 0;
#endif
}

#if CONFIG_IDF_TARGET_ESP32
/* IDF's public esp_mmu_map() has safe cache handling, but does not accept a
 * caller-selected virtual address.  Keep the fixed-VMA experiment safe by
 * reproducing its small IRAM mapping critical section here.  Every operation
 * while caches are stopped is either IRAM or an inline HAL primitive. */
static IRAM_ATTR NOINLINE_ATTR void map_fixed_aliases_esp32(
    uint32_t paddr, uint32_t len, uint32_t code_vaddr, uint32_t data_vaddr,
    uint32_t *code_len, uint32_t *data_len)
{
    const uint32_t page_size = mmu_hal_pages_to_bytes(0, 1);
    uint32_t mapped = 0;
    spi_flash_disable_interrupts_caches_and_other_cpu();
    mmu_hal_map_region(0, MMU_TARGET_FLASH0, code_vaddr, paddr,
                       len, &mapped);
#if !CONFIG_ESP_SYSTEM_SINGLE_CORE_MODE
    mmu_hal_map_region(1, MMU_TARGET_FLASH0, code_vaddr, paddr,
                       len, &mapped);
#endif
    *code_len = mapped;
    mmu_hal_map_region(0, MMU_TARGET_FLASH0, data_vaddr, paddr,
                       len, &mapped);
#if !CONFIG_ESP_SYSTEM_SINGLE_CORE_MODE
    mmu_hal_map_region(1, MMU_TARGET_FLASH0, data_vaddr, paddr,
                       len, &mapped);
#endif
    *data_len = mapped;
    cache_bus_mask_t buses = cache_ll_l1_get_bus(0, code_vaddr, len);
    buses |= cache_ll_l1_get_bus(0, data_vaddr, len);
    cache_ll_l1_enable_bus(0, buses);
#if !CONFIG_ESP_SYSTEM_SINGLE_CORE_MODE
    cache_ll_l1_enable_bus(1, buses);
#endif
    cache_sync();
    spi_flash_enable_interrupts_caches_and_other_cpu();
    (void)page_size;
}
#endif

static esp_err_t map_fixed_module(const esp_partition_t *partition, uint32_t offset,
                                  uint32_t image_size, const uint8_t **out_base,
                                  uint32_t *out_mapped_size, uint32_t code_vaddr,
                                  uint32_t data_vaddr)
{
    if (partition == NULL || out_base == NULL || out_mapped_size == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (offset > partition->size || image_size == 0 ||
        image_size > partition->size - offset ||
        offset % MODULE_ALIGN != 0 || partition->address > UINT32_MAX - offset) {
        ESP_LOGE(TAG, "fixed module source rejected address=0x%08lx offset=0x%08lx partition=0x%08lx image=0x%08lx",
                 (unsigned long)partition->address, (unsigned long)offset,
                 (unsigned long)partition->size, (unsigned long)image_size);
        return ESP_ERR_INVALID_ARG;
    }
    const uint32_t paddr = partition->address + offset;
    const uint32_t mmu_id = module_mmu_id();
    const uint32_t page_size = mmu_hal_pages_to_bytes(mmu_id, 1);
    if (page_size == 0 || (code_vaddr % page_size) != 0 ||
        (data_vaddr % page_size) != 0 ||
        code_vaddr > UINT32_MAX - MODULE_FIXED_WINDOW_SIZE ||
        data_vaddr > UINT32_MAX - MODULE_FIXED_WINDOW_SIZE ||
        (code_vaddr < data_vaddr + MODULE_FIXED_WINDOW_SIZE &&
         data_vaddr < code_vaddr + MODULE_FIXED_WINDOW_SIZE) ||
        (paddr % page_size) != 0 || image_size > MODULE_FIXED_WINDOW_SIZE) {
        ESP_LOGE(TAG, "fixed module window rejected code=0x%08lx data=0x%08lx page=0x%08lx image=0x%08lx",
                 (unsigned long)code_vaddr, (unsigned long)data_vaddr,
                 (unsigned long)page_size, (unsigned long)image_size);
        return ESP_ERR_INVALID_ARG;
    }
    ESP_LOGI(TAG, "fixed module window 128k code=0x%08lx data=0x%08lx page=0x%08lx image=0x%08lx",
             (unsigned long)code_vaddr, (unsigned long)data_vaddr,
             (unsigned long)page_size, (unsigned long)image_size);
    uint32_t mapped_size = 0;
    const uint32_t rounded_size =
        ((image_size + page_size - 1u) / page_size) * page_size;
    if (rounded_size == 0 || rounded_size > MODULE_FIXED_WINDOW_SIZE ||
        code_vaddr > UINT32_MAX - rounded_size ||
        data_vaddr > UINT32_MAX - rounded_size) {
        ESP_LOGE(TAG, "fixed module mapping size rejected rounded=0x%08lx window=0x%08x",
                 (unsigned long)rounded_size, MODULE_FIXED_WINDOW_SIZE);
        return ESP_ERR_INVALID_SIZE;
    }
#if CONFIG_IDF_TARGET_ESP32
    uint32_t data_mapped_size = 0;
    map_fixed_aliases_esp32(paddr, image_size, code_vaddr, data_vaddr,
                            &mapped_size, &data_mapped_size);
#else
    mmu_hal_map_region(mmu_id, MMU_TARGET_FLASH0, code_vaddr, paddr,
                       image_size, &mapped_size);
#endif
    if (mapped_size < rounded_size || mapped_size > MODULE_FIXED_WINDOW_SIZE) {
        ESP_LOGE(TAG, "fixed code mapping incomplete requested=0x%08lx mapped=0x%08lx",
                 (unsigned long)rounded_size, (unsigned long)mapped_size);
        mmu_hal_unmap_region(mmu_id, code_vaddr, mapped_size);
        return ESP_FAIL;
    }
    /* Xtensa literals and Rust string constants are ordinary data loads. The
     * code and data buses have different virtual aliases, so map the same
     * contiguous flash image into both. MODULE_DATA_VMA in the fixed linker
     * script points .rodata at this corresponding data-bus window. */
#if !CONFIG_IDF_TARGET_ESP32
    uint32_t data_mapped_size = 0;
    mmu_hal_map_region(mmu_id, MMU_TARGET_FLASH0, data_vaddr, paddr,
                       image_size, &data_mapped_size);
#endif
    if (data_mapped_size < rounded_size || data_mapped_size > MODULE_FIXED_WINDOW_SIZE) {
        ESP_LOGE(TAG, "fixed data mapping incomplete requested=0x%08lx mapped=0x%08lx",
                 (unsigned long)rounded_size, (unsigned long)data_mapped_size);
        mmu_hal_unmap_region(mmu_id, code_vaddr, mapped_size);
        mmu_hal_unmap_region(mmu_id, data_vaddr, data_mapped_size);
        return ESP_FAIL;
    }
    /* The HAL only changes MMU entries. Invalidate both caches so a previous
     * module occupying either alias cannot be executed/read accidentally. */
    esp_err_t sync_err = ESP_OK;
#if !CONFIG_IDF_TARGET_ESP32
    sync_err = esp_cache_msync((void *)code_vaddr, mapped_size,
                               ESP_CACHE_MSYNC_FLAG_DIR_M2C |
                               ESP_CACHE_MSYNC_FLAG_TYPE_INST);
    if (sync_err == ESP_OK) {
        sync_err = esp_cache_msync((void *)data_vaddr, data_mapped_size,
                                   ESP_CACHE_MSYNC_FLAG_DIR_M2C |
                                   ESP_CACHE_MSYNC_FLAG_TYPE_DATA);
    }
#endif
    if (sync_err != ESP_OK) {
        mmu_hal_unmap_region(mmu_id, code_vaddr, mapped_size);
        mmu_hal_unmap_region(mmu_id, data_vaddr, data_mapped_size);
        return sync_err;
    }
    *out_base = (const uint8_t *)(uintptr_t)code_vaddr;
    *out_mapped_size = mapped_size;
    return ESP_OK;
}

static void unmap_fixed_module(uint32_t mapped_size, uint32_t code_vaddr, uint32_t data_vaddr)
{
    if (mapped_size == 0) return;
    const uint32_t mmu_id = module_mmu_id();
    mmu_hal_unmap_region(mmu_id, code_vaddr, mapped_size);
    mmu_hal_unmap_region(mmu_id, data_vaddr, mapped_size);
}
#endif

/* Read the small fixed header through the flash MMU. The synthetic raw data
 * partition is intentionally not passed through esp_partition_read here:
 * header probes are part of the command path and must not wait on a blocking
 * flash-driver transaction. */
static esp_err_t read_module_header(const esp_partition_t *partition, uint32_t offset,
                                    dmesh_module_header_t *header)
{
    if (partition == NULL || header == NULL || offset > partition->size ||
        partition->size - offset < sizeof(*header)) return ESP_ERR_INVALID_ARG;
    const void *mapped = NULL;
    esp_partition_mmap_handle_t handle = 0;
    esp_err_t err = esp_partition_mmap(partition, offset, sizeof(*header),
                                       ESP_PARTITION_MMAP_DATA, &mapped, &handle);
    if (err != ESP_OK || mapped == NULL) return err != ESP_OK ? err : ESP_FAIL;
    memcpy(header, mapped, sizeof(*header));
    esp_partition_munmap(handle);
    return ESP_OK;
}
extern void dmesh_lora_irq_set_task(void *task);
extern void dmesh_lora_irq_rearm(void);
extern void dmesh_lora_gpio_isr(void *arg);
extern int dmesh_module_call_service(uint16_t service_tag,
                                     const uint8_t *payload, size_t payload_len,
                                     uint8_t *response, size_t response_capacity,
                                     size_t *response_len, uint32_t timeout_ms);
extern int dmesh_module_get_setting(const uint8_t *key, size_t key_len,
                                    uint8_t *value, size_t value_capacity,
                                    size_t *value_len);
extern int dmesh_module_set_setting(const uint8_t *key, size_t key_len,
                                    const uint8_t *value, size_t value_len);
extern int dmesh_module_emit_event(uint16_t event_id, uint8_t value_type, uint8_t flags,
                                   const uint8_t *payload, size_t payload_len);

static int get_setting(void *user, const uint8_t *key, size_t key_len,
                       uint8_t *value, size_t value_capacity, size_t *value_len)
{
    (void)user;
    return dmesh_module_get_setting(key, key_len, value, value_capacity, value_len);
}
static int set_setting(void *user, const uint8_t *key, size_t key_len,
                       const uint8_t *value, size_t value_len)
{
    (void)user;
    return dmesh_module_set_setting(key, key_len, value, value_len);
}
static int emit_event(void *user, const dmesh_module_event_v1 *event)
{
    (void)user;
    if (event == NULL) return -1;
    cached_module_event_calls++;
    cached_last_module_event_id = event->event_id;
    return dmesh_module_emit_event(event->event_id, event->value_type, event->flags,
                                   event->value, event->value_len);
}

static int lora_spi_transfer(void *user, const uint8_t *tx, uint8_t *rx, size_t len)
{
    (void)user;
    cached_spi_calls++;
    cached_task_stage = 6;
    /* SX126x reads include opcode/address/status bytes around a 255-byte
     * packet, so the SPI transaction is larger than the radio payload. */
    if (lora_spi == NULL || tx == NULL || rx == NULL || len == 0 || len > LORA_SPI_MAX_TRANSFER) {
        cached_spi_errors++;
        return -1;
    }
    /* SX126x holds BUSY high while a command is being processed. Waiting in
     * the module's dedicated task keeps this host primitive synchronous and
     * prevents a command from being clocked into the radio too early. The
     * timeout is finite so a missing/stuck BUSY signal cannot wedge Main. */
    if (lora_config.busy_pin >= 0) {
        const TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(100);
        while (gpio_get_level((gpio_num_t)lora_config.busy_pin) != 0) {
            if ((int32_t)(xTaskGetTickCount() - deadline) >= 0) {
                cached_spi_errors++;
                return DMESH_LORA_ERR_BUSY;
            }
            vTaskDelay(pdMS_TO_TICKS(1));
        }
    }
    spi_transaction_t t = {0};
    t.length = len * 8;
    t.tx_buffer = tx;
    t.rx_buffer = rx;
    /* Do not use spi_device_transmit here: a module must never be able to
     * wedge Main indefinitely on a claimed bus or missing radio. Queue the
     * transaction and bound both queueing and completion waits. */
    const TickType_t spi_timeout = pdMS_TO_TICKS(100);
    esp_err_t spi_err = spi_device_queue_trans(lora_spi, &t, spi_timeout);
    if (spi_err != ESP_OK) {
        cached_spi_errors++;
        return -1;
    }
    spi_transaction_t *completed = NULL;
    spi_err = spi_device_get_trans_result(lora_spi, &completed, spi_timeout);
    if (spi_err != ESP_OK || completed != &t) {
        ESP_LOGE(TAG, "module SPI complete failed err=%s completed=%p expected=%p",
                 esp_err_to_name(spi_err), (void *)completed, (void *)&t);
        cached_spi_errors++;
        return -1;
    }
    /* SX126x commands are not complete when CS rises: the chip keeps BUSY
     * asserted while it applies the command. The former Main driver waited
     * after every transaction; without this wait a following GET_IRQ_STATUS
     * can race SET_TX and observe zero IRQ bits. Keep the bound finite so a
     * dead radio cannot wedge the module task. */
    if (lora_config.busy_pin >= 0) {
        const TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(100);
        while (gpio_get_level((gpio_num_t)lora_config.busy_pin) != 0) {
            if ((int32_t)(xTaskGetTickCount() - deadline) >= 0) {
                cached_spi_errors++;
                return DMESH_LORA_ERR_BUSY;
            }
            vTaskDelay(pdMS_TO_TICKS(1));
        }
    }
    cached_task_stage = 7;
    return 0;
}

static int lora_gpio_write(void *user, int pin, int level)
{ (void)user; return gpio_set_level((gpio_num_t)pin, level) == ESP_OK ? 0 : -1; }
static int lora_gpio_read(void *user, int pin)
{ (void)user; return gpio_get_level((gpio_num_t)pin); }
static int lora_irq_configure(void *user, int pin, int active_level)
{
    (void)user;
    if (pin < 0 || pin > 48) return -1;
    esp_err_t err = gpio_set_direction((gpio_num_t)pin, GPIO_MODE_INPUT);
    if (err != ESP_OK) return -1;
    err = gpio_install_isr_service(ESP_INTR_FLAG_IRAM);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) return -1;
    /* Reconfiguration is also the module stop operation. Do not leave an
     * ISR or a light-sleep wake source attached to a radio being upgraded. */
    (void)gpio_intr_disable((gpio_num_t)pin);
    (void)gpio_isr_handler_remove((gpio_num_t)pin);
    (void)gpio_wakeup_disable((gpio_num_t)pin);
    if (active_level == 0) return 0;
    if (gpio_set_intr_type((gpio_num_t)pin, GPIO_INTR_POSEDGE) != ESP_OK) return -1;
    err = gpio_isr_handler_add((gpio_num_t)pin, dmesh_lora_gpio_isr,
                               (void *)(uintptr_t)pin);
    if (err != ESP_OK) return -1;
    /* The edge ISR wakes the module task while awake. The level wake source
     * is what brings an ESP32 out of automatic light sleep when DIO0 goes
     * high; the task clears the radio IRQ before re-enabling the GPIO edge. */
    if (gpio_wakeup_enable((gpio_num_t)pin, GPIO_INTR_HIGH_LEVEL) != ESP_OK) {
        (void)gpio_isr_handler_remove((gpio_num_t)pin);
        return -1;
    }
    if (esp_sleep_enable_gpio_wakeup() != ESP_OK) {
        (void)gpio_wakeup_disable((gpio_num_t)pin);
        (void)gpio_isr_handler_remove((gpio_num_t)pin);
        return -1;
    }
    return 0;
}
static int lora_irq_enable(void *user, int pin, int enabled)
{
    (void)user;
    if (pin < 0 || pin > 48) return -1;
    if (enabled) {
        if (gpio_wakeup_enable((gpio_num_t)pin, GPIO_INTR_HIGH_LEVEL) != ESP_OK) return -1;
        if (esp_sleep_enable_gpio_wakeup() != ESP_OK) return -1;
        return gpio_intr_enable((gpio_num_t)pin) == ESP_OK ? 0 : -1;
    }
    (void)gpio_wakeup_disable((gpio_num_t)pin);
    return gpio_intr_disable((gpio_num_t)pin) == ESP_OK ? 0 : -1;
}
static int lora_wait_irq(void *user, uint32_t timeout_ms)
{
    (void)user;
    if (timeout_ms > 1000u) timeout_ms = 1000u;
    dmesh_lora_irq_rearm();
    TickType_t ticks = pdMS_TO_TICKS(timeout_ms);
    /* On the 10 ms tick configuration, a 5 ms module poll otherwise rounds
     * to zero and becomes a busy loop. Always yield for at least one tick. */
    if (timeout_ms != 0 && ticks == 0) ticks = 1;
    if (ulTaskGenericNotifyTake(0, pdTRUE, ticks) != 0) {
        cached_lora_irq_wakes++;
        return 0;
    }
    cached_lora_irq_timeouts++;
    return 1;
}
static uint64_t lora_now_ms(void *user)
{ (void)user; return (uint64_t)(xTaskGetTickCount() * portTICK_PERIOD_MS); }
static int lora_emit_packet(void *user, const uint8_t *data, size_t len, int16_t rssi, int8_t snr)
{
    (void)user;
    if (data == NULL || len == 0 || len > DMESH_LORA_MAX_PACKET) return -1;
    char args[64];
    int args_len = snprintf(args, sizeof(args), "op=lora_rx rssi=%d snr=%d", rssi, snr);
    if (args_len <= 0 || (size_t)args_len >= sizeof(args)) return -1;
    (void)args;
    return dmesh_module_call_service(101u, data, len, NULL, 0, NULL, 50);
}
static int lora_poll_command(void *user, uint8_t *args, size_t *args_len,
                             uint8_t *payload, size_t *payload_len)
{
    (void)user;
    if (args == NULL || args_len == NULL || payload == NULL || payload_len == NULL) return -1;
    portENTER_CRITICAL(&lora_command_mux);
    if (!lora_command_pending) {
        portEXIT_CRITICAL(&lora_command_mux);
        return -1;
    }
    if (*args_len < lora_command_args_len || *payload_len < lora_command_payload_len) {
        portEXIT_CRITICAL(&lora_command_mux);
        return -2;
    }
    memcpy(args, lora_command_args, lora_command_args_len);
    memcpy(payload, lora_command_payload, lora_command_payload_len);
    cached_lora_poll_count++;
    cached_last_lora_payload_len = (uint32_t)lora_command_payload_len;
    cached_last_lora_command_len = (uint32_t)lora_command_args_len;
    memset(cached_last_lora_command, 0, sizeof(cached_last_lora_command));
    size_t command_copy = lora_command_args_len < sizeof(cached_last_lora_command) - 1u
        ? lora_command_args_len : sizeof(cached_last_lora_command) - 1u;
    memcpy(cached_last_lora_command, lora_command_args, command_copy);
    *args_len = lora_command_args_len;
    *payload_len = lora_command_payload_len;
    lora_command_pending = false;
    portEXIT_CRITICAL(&lora_command_mux);
    return 0;
}

static dmesh_lora_host_v1 lora_host = {
    .abi_version = DMESH_LORA_ABI_VERSION,
    .size = sizeof(dmesh_lora_host_v1),
    .features = 0,
    .user = NULL,
    .spi_transfer = lora_spi_transfer,
    .gpio_write = lora_gpio_write,
    .gpio_read = lora_gpio_read,
    .irq_configure = lora_irq_configure,
    .irq_enable = lora_irq_enable,
    .wait_irq = lora_wait_irq,
    .now_ms = lora_now_ms,
    .log_line = log_line,
    .emit_packet = lora_emit_packet,
    .poll_command = lora_poll_command,
};

static void lora_host_init(void)
{
    if (lora_config.board_power_pin >= 0) {
        gpio_num_t power = (gpio_num_t)lora_config.board_power_pin;
        (void)gpio_reset_pin(power);
        (void)gpio_set_direction(power, GPIO_MODE_OUTPUT);
        (void)gpio_set_level(power, lora_config.board_power_level != 0 ? 1 : 0);
        /* Give an externally powered radio/TCXO a bounded settling interval
         * before asserting its reset line. */
        vTaskDelay(pdMS_TO_TICKS(2));
    }
    if (lora_config.busy_pin >= 0) {
        gpio_num_t busy = (gpio_num_t)lora_config.busy_pin;
        (void)gpio_reset_pin(busy);
        (void)gpio_set_direction(busy, GPIO_MODE_INPUT);
    }
    if (lora_config.reset_pin >= 0) {
        gpio_num_t reset = (gpio_num_t)lora_config.reset_pin;
        (void)gpio_reset_pin(reset);
        (void)gpio_set_direction(reset, GPIO_MODE_OUTPUT);
        (void)gpio_set_level(reset, 0);
        vTaskDelay(pdMS_TO_TICKS(10));
        (void)gpio_set_level(reset, 1);
        vTaskDelay(pdMS_TO_TICKS(20));
        if (lora_config.busy_pin >= 0) {
            const TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(500);
            while (gpio_get_level((gpio_num_t)lora_config.busy_pin) != 0) {
                if ((int32_t)(xTaskGetTickCount() - deadline) >= 0) break;
                vTaskDelay(pdMS_TO_TICKS(1));
            }
        }
    }
    if (lora_spi != NULL) return;
    /* Match Main's persisted ESP host enum: 1=SPI2/HSPI, 2=SPI3/VSPI. */
    spi_host_device_t host = lora_spi_host_device();
    spi_bus_config_t bus = {
        .mosi_io_num = lora_config.mosi_pin >= 0 ? lora_config.mosi_pin :
                       (lora_config.spi_host == 1 ? 10 : 27),
        .miso_io_num = lora_config.miso_pin >= 0 ? lora_config.miso_pin :
                       (lora_config.spi_host == 1 ? 11 : 19),
        .sclk_io_num = lora_config.sck_pin >= 0 ? lora_config.sck_pin :
                       (lora_config.spi_host == 1 ? 9 : 5),
        .quadwp_io_num = -1, .quadhd_io_num = -1, .max_transfer_sz = LORA_SPI_MAX_TRANSFER,
    };
    esp_err_t bus_err = spi_bus_initialize(host, &bus, SPI_DMA_CH_AUTO);
    bool bus_owned = bus_err == ESP_OK;
    if (bus_err != ESP_OK && bus_err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "LoRa SPI bus init failed host=%d err=%s pins=%d/%d/%d",
                 (int)host, esp_err_to_name(bus_err), bus.mosi_io_num,
                 bus.miso_io_num, bus.sclk_io_num);
        return;
    }
    spi_device_interface_config_t dev = {
        .clock_speed_hz = 1000000, .mode = 0,
        .spics_io_num = lora_config.cs_pin >= 0 ? lora_config.cs_pin :
                        (lora_config.spi_host == 2 ? 8 : 18), .queue_size = 1,
    };
    esp_err_t device_err = spi_bus_add_device(host, &dev, &lora_spi);
    if (device_err != ESP_OK || lora_spi == NULL) {
        ESP_LOGE(TAG, "LoRa SPI device add failed host=%d err=%s cs=%d bus_err=%s",
                 (int)host, esp_err_to_name(device_err), dev.spics_io_num,
                 esp_err_to_name(bus_err));
        lora_spi = NULL;
        if (bus_owned) (void)spi_bus_free(host);
    } else {
        ESP_LOGI(TAG, "LoRa SPI ready host=%d cs=%d pins=%d/%d/%d max_transfer=%u",
                 (int)host, dev.spics_io_num, bus.mosi_io_num, bus.miso_io_num,
                 bus.sclk_io_num, (unsigned)LORA_SPI_MAX_TRANSFER);
    }
}


static const esp_partition_t *resolve_module_partition(void)
{
    const esp_partition_t *partition = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, "data");
    /* Current Rust fleet tables call the flash-backed blob store
     * `dmesh_store`; Recovery's module target deliberately aliases this
     * partition. Keep the legacy `data` name first for early boards. */
    if (partition == NULL) {
        partition = esp_partition_find_first(
            ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, "dmesh_store");
    }
    if (partition != NULL) {
        /* The raw data/module region is intentionally the tail of flash. A
         * legacy table may describe only its first 256 KiB; extend the local
         * view to the detected physical end so module placement matches the
         * Recovery protocol on larger chips. */
        uint32_t flash_size = 0;
        if (esp_flash_get_physical_size(esp_flash_default_chip, &flash_size) == ESP_OK &&
            flash_size > partition->address &&
            partition->address + partition->size < flash_size) {
            cached_raw_partition = *partition;
            cached_raw_partition.size = flash_size - partition->address;
            cached_partition = &cached_raw_partition;
            return cached_partition;
        }
        return partition;
    }
    uint32_t flash_size = 0;
    if (esp_flash_get_physical_size(esp_flash_default_chip, &flash_size) != ESP_OK ||
        flash_size <= MODULE_DATA_START) return NULL;
    memset(&cached_raw_partition, 0, sizeof(cached_raw_partition));
    cached_raw_partition.flash_chip = esp_flash_default_chip;
    cached_raw_partition.type = ESP_PARTITION_TYPE_DATA;
    cached_raw_partition.subtype = ESP_PARTITION_SUBTYPE_ANY;
    cached_raw_partition.address = MODULE_DATA_START;
    cached_raw_partition.size = flash_size - MODULE_DATA_START;
    cached_raw_partition.erase_size = 0x1000;
    cached_partition = &cached_raw_partition;
    return cached_partition;
}

void dmesh_module_loader_init(void)
{
    ESP_LOGI(TAG, "startup init enter");
    dmesh_hw_host_set_spi(lora_spi_transfer);
    dmesh_hw_host_reset();
    cached_header_valid = false;
    cached_offset = 0;
    cached_task_done = false;
    cached_task_running = false;
    running_service_mask = 0;
    cached_last_result = -999;
    cached_task_start_ms = 0;
    cached_last_runtime_ms = 0;
    cached_max_runtime_ms = 0;
    cached_task_runs = 0;
    cached_last_stack_high_water_words = 0;
    cached_lora_poll_count = 0;
    cached_last_lora_payload_len = 0;
    cached_last_lora_command_len = 0;
    cached_module_event_calls = 0;
    cached_last_module_event_id = 0;
    cached_entry_args_len = 0;
    memset(cached_entry_args, 0, sizeof(cached_entry_args));
    memset(cached_last_lora_command, 0, sizeof(cached_last_lora_command));
    cached_task_handle = NULL;
    memset(cached_task_name, 0, sizeof(cached_task_name));
    cached_task_service_tag = 0;
    cached_partition = resolve_module_partition();
    if (cached_partition == NULL || cached_partition->size < DMESH_MODULE_HEADER_SIZE) {
        ESP_LOGW(TAG, "module header unavailable partition=%p", (void *)cached_partition);
        return;
    }
    ESP_LOGI(TAG, "startup partition address=0x%08lx size=0x%08lx",
             (unsigned long)cached_partition->address,
             (unsigned long)cached_partition->size);
    /* The first experiment uses one deterministic slot. Do not scan the
     * extended raw data region from a command handler; later index/compaction
     * work can add discovery without changing explicit offset invocation. */
    const uint32_t offset = 0;
    dmesh_module_header_t candidate;
    if (read_module_header(cached_partition, offset, &candidate) == ESP_OK &&
        candidate.magic == DMESH_MODULE_MAGIC &&
        candidate.abi_version == DMESH_MODULE_ABI_VERSION &&
        candidate.header_size == DMESH_MODULE_HEADER_SIZE &&
        candidate.entry_offset >= DMESH_MODULE_HEADER_SIZE &&
        candidate.entry_offset % 4u == 0 &&
        candidate.entry_offset < candidate.image_size &&
        candidate.image_size <= cached_partition->size - offset) {
        cached_header = candidate;
        cached_offset = offset;
        cached_header_valid = true;
    }
    ESP_LOGI(TAG, "startup header valid=%s tag=%u offset=0x%08lx entry=0x%08lx image=0x%08lx",
             cached_header_valid ? "true" : "false", (unsigned long)cached_offset,
             (unsigned)cached_header.service_tag,
             (unsigned long)cached_header.entry_offset,
             (unsigned long)cached_header.image_size);
}

bool dmesh_module_loader_refresh_header(void)
{
    if (cached_task_running) return false;
    if (cached_partition == NULL) cached_partition = resolve_module_partition();
    cached_header_valid = false;
    cached_offset = 0;
    if (cached_partition == NULL || cached_partition->size < DMESH_MODULE_HEADER_SIZE) {
        return false;
    }
    dmesh_module_header_t candidate;
    const uint32_t offset = 0;
    if (read_module_header(cached_partition, offset, &candidate) != ESP_OK ||
        candidate.magic != DMESH_MODULE_MAGIC ||
        candidate.abi_version != DMESH_MODULE_ABI_VERSION ||
        candidate.header_size != DMESH_MODULE_HEADER_SIZE ||
        candidate.entry_offset < DMESH_MODULE_HEADER_SIZE ||
        candidate.entry_offset % 4u != 0 ||
        candidate.entry_offset >= candidate.image_size ||
        candidate.image_size > cached_partition->size - offset) {
        ESP_LOGW(TAG, "module header refresh rejected after update");
        return false;
    }
    cached_header = candidate;
    cached_offset = offset;
    cached_header_valid = true;
    ESP_LOGI(TAG, "module header refreshed tag=%u entry=0x%08lx image=0x%08lx",
             cached_header.service_tag, (unsigned long)cached_header.entry_offset,
             (unsigned long)cached_header.image_size);
    return true;
}

bool dmesh_module_loader_header_valid(void) { return cached_header_valid; }
bool dmesh_module_loader_is_lora(void)
{
    return cached_header_valid && cached_header.service_tag == 43u;
}
uint32_t dmesh_module_loader_offset(void) { return cached_offset; }
uint32_t dmesh_module_loader_image_size(void)
{
    return cached_header_valid ? cached_header.image_size : 0;
}
uint32_t dmesh_module_loader_required_stack_words(void)
{
    return cached_header_valid ? cached_header.required_stack_words : 0u;
}

int dmesh_module_lora_configure(const dmesh_lora_config_v1 *config)
{
    if (config == NULL || config->abi_version != DMESH_LORA_ABI_VERSION ||
        config->size < sizeof(dmesh_lora_config_v1)) return -1;
    /* Command handlers call this on every public `lora` operation. Never
     * tear down the SPI device underneath a running module task: the task is
     * using the same host table and a concurrent bus removal can turn a
     * normal tx/stop command into an intermittent I/O failure. A running
     * task consumes the updated immutable configuration on its next command;
     * the critical section keeps the 40-byte ABI copy publication bounded. */
    if (service_running(43u)) {
        portENTER_CRITICAL(&lora_command_mux);
        lora_config = *config;
        portEXIT_CRITICAL(&lora_command_mux);
        return 0;
    }
    if (lora_spi != NULL) {
        spi_bus_remove_device(lora_spi);
        lora_spi = NULL;
        /* Keep teardown's host mapping identical to lora_host_init(): the
         * persisted enum uses 1=SPI2/HSPI and 2=SPI3/VSPI. Freeing the
         * opposite bus leaves the real bus allocated and can make the next
         * module invocation fail or collide with another peripheral. */
        spi_bus_free(lora_spi_host_device());
    }
    lora_config = *config;
    lora_host_init();
    if (lora_spi == NULL) {
        cached_task_done = true;
        cached_last_result = -30;
        return -2;
    }
    return 0;
}
int dmesh_module_lora_update_config(const dmesh_lora_config_v1 *config)
{
    if (config == NULL || config->abi_version != DMESH_LORA_ABI_VERSION ||
        config->size < sizeof(dmesh_lora_config_v1)) return -1;
    if (!service_running(43u)) {
        lora_config = *config;
        return 0;
    }
    /* The persistent task reads this object when it handles a command. Keep
     * the copy serialized with command publication; callers may queue an
     * explicit `reconfigure` when they need the RX registers reapplied. */
    portENTER_CRITICAL(&lora_command_mux);
    lora_config = *config;
    portEXIT_CRITICAL(&lora_command_mux);
    return 0;
}
int dmesh_module_lora_command(const uint8_t *args, size_t args_len,
                              const uint8_t *payload, size_t payload_len)
{
    if (args == NULL || args_len == 0 || args_len > LORA_COMMAND_MAX ||
        payload_len > DMESH_LORA_MAX_PACKET || (payload_len != 0 && payload == NULL)) return -1;
    if (!service_running(43u)) return -21;
    portENTER_CRITICAL(&lora_command_mux);
    if (lora_command_pending) {
        portEXIT_CRITICAL(&lora_command_mux);
        return -20;
    }
    memcpy(lora_command_args, args, args_len);
    if (payload_len != 0) memcpy(lora_command_payload, payload, payload_len);
    lora_command_args_len = args_len;
    lora_command_payload_len = payload_len;
    lora_command_pending = true;
    portEXIT_CRITICAL(&lora_command_mux);
    return 0;
}

bool dmesh_module_loader_prepare_flash(uint32_t timeout_ms)
{
    if (!cached_task_running) return true;
    if (service_running(45u)) dmesh_hw_host_request_stop(true);
    if (service_running(43u)) {
    static const uint8_t stop[] = "stop";
    /* Flash erases disable the instruction cache while the module is mapped
     * from this same raw data region. Replace any queued radio command with a
     * bounded stop request before the TCP worker can touch the partition. */
    portENTER_CRITICAL(&lora_command_mux);
    memcpy(lora_command_args, stop, sizeof(stop) - 1);
    lora_command_args_len = sizeof(stop) - 1;
    lora_command_payload_len = 0;
    lora_command_pending = true;
    portEXIT_CRITICAL(&lora_command_mux);
    }
    TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(timeout_ms);
    while (cached_task_running) {
        if ((int32_t)(xTaskGetTickCount() - deadline) >= 0) return false;
        vTaskDelay(pdMS_TO_TICKS(1));
    }
    return true;
}
bool dmesh_module_loader_task_done(void) { return cached_task_done; }
int dmesh_module_loader_last_result(void) { return cached_last_result; }
uint32_t dmesh_module_loader_runtime_ms(void)
{
    uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
    if (cached_task_running) return now - cached_task_start_ms;
    return cached_last_runtime_ms;
}
uint32_t dmesh_module_loader_max_runtime_ms(void) { return cached_max_runtime_ms; }
uint32_t dmesh_module_loader_task_runs(void) { return cached_task_runs; }
uint32_t dmesh_module_loader_stack_high_water_words(void)
{
    TaskHandle_t task = cached_task_handle;
    return task == NULL ? cached_last_stack_high_water_words :
        (uint32_t)uxTaskGetStackHighWaterMark(task);
}
uint32_t dmesh_module_loader_stage(void) { return cached_task_stage; }
uint32_t dmesh_module_loader_spi_calls(void) { return cached_spi_calls; }
uint32_t dmesh_module_loader_spi_errors(void) { return cached_spi_errors; }
uint32_t dmesh_module_loader_lora_poll_count(void) { return cached_lora_poll_count; }
uint32_t dmesh_module_loader_lora_irq_wakes(void) { return cached_lora_irq_wakes; }
uint32_t dmesh_module_loader_lora_irq_timeouts(void) { return cached_lora_irq_timeouts; }
uint32_t dmesh_module_loader_last_lora_payload_len(void) { return cached_last_lora_payload_len; }
uint32_t dmesh_module_loader_last_lora_command_len(void) { return cached_last_lora_command_len; }
uint32_t dmesh_module_loader_module_event_calls(void) { return cached_module_event_calls; }
uint32_t dmesh_module_loader_last_module_event_id(void) { return cached_last_module_event_id; }
uint32_t dmesh_module_loader_entry_args_len(void) { return cached_entry_args_len; }
const char *dmesh_module_loader_entry_args(void) { return cached_entry_args; }
const char *dmesh_module_loader_last_lora_command(void) { return cached_last_lora_command; }

typedef struct {
    uint16_t service_tag;
    uint16_t reserved;
    uint32_t offset;
    uint32_t size;
    size_t payload_len;
    size_t args_len;
    uint32_t stack_words;
    uint8_t bytes[];
} module_job_t;

static int module_stack_words(uint32_t offset, uint32_t *out)
{
    if (out == NULL || cached_partition == NULL || offset > cached_partition->size ||
        cached_partition->size - offset < sizeof(dmesh_module_header_t)) {
        ESP_LOGE(TAG, "module stack header bounds offset=0x%08lx partition=%p address=0x%08lx size=0x%08lx",
                 (unsigned long)offset, (void *)cached_partition,
                 cached_partition != NULL ? (unsigned long)cached_partition->address : 0ul,
                 cached_partition != NULL ? (unsigned long)cached_partition->size : 0ul);
        return -1;
    }
    dmesh_module_header_t header;
    esp_err_t read_err = read_module_header(cached_partition, offset, &header);
    if (read_err != ESP_OK) {
        ESP_LOGE(TAG, "module stack header read failed offset=0x%08lx address=0x%08lx err=%s",
                 (unsigned long)offset, (unsigned long)cached_partition->address,
                 esp_err_to_name(read_err));
        return -1;
    }
    if (header.magic != DMESH_MODULE_MAGIC || header.abi_version != DMESH_MODULE_ABI_VERSION ||
        header.header_size != DMESH_MODULE_HEADER_SIZE) {
        ESP_LOGE(TAG, "module stack header invalid offset=0x%08lx magic=0x%08lx abi=%u header=%u image=0x%08lx stack=%lu tag=%u",
                 (unsigned long)offset, (unsigned long)header.magic,
                 (unsigned)header.abi_version, (unsigned)header.header_size,
                 (unsigned long)header.image_size, (unsigned long)header.required_stack_words,
                 (unsigned)header.service_tag);
        return -1;
    }
    uint32_t requested = header.required_stack_words;
    if (requested == 0) requested = MODULE_TASK_STACK_DEFAULT;
    if (requested < MODULE_TASK_STACK_MIN) requested = MODULE_TASK_STACK_MIN;
    if (requested > MODULE_TASK_STACK_MAX) return -2;
    *out = requested;
    return 0;
}

static int log_line(void *user, const uint8_t *data, size_t len)
{
    (void)user;
    if (data == NULL) return -1;
    char line[97];
    size_t copied = len < sizeof(line) - 1u ? len : sizeof(line) - 1u;
    memcpy(line, data, copied);
    line[copied] = '\0';
    /* Main normally suppresses INFO logs. Module protocol diagnostics are
     * deliberately WARN-level so a failed asynchronous transfer remains
     * visible through the managed PPP log without reopening raw UART text. */
    ESP_LOGW(TAG, "module log=%s%s", line, copied == len ? "" : "...");
    return copied == len ? 0 : -2;
}

static int call_service(void *user, uint16_t service_tag,
                        const uint8_t *payload, size_t payload_len,
                        uint8_t *response, size_t response_capacity,
                        size_t *response_len, uint32_t timeout_ms)
{
    (void)user;
    if (timeout_ms == 0 || timeout_ms > 250u) timeout_ms = 250u;
    return dmesh_module_call_service(service_tag, payload, payload_len,
                                     response, response_capacity, response_len,
                                     timeout_ms);
}

static dmesh_module_host_v1 common_host = {
    .abi_version = DMESH_MODULE_ABI_VERSION,
    .size = sizeof(dmesh_module_host_v1),
    .features = 0,
    .user = NULL,
    .log_line = log_line,
    .call_service = call_service,
    .get_setting = get_setting,
    .set_setting = set_setting,
    .emit_event = emit_event,
    .hw = &dmesh_hw_host,
    .alloc = module_alloc,
};

static int32_t flash_erase(void *user, uint32_t address, uint32_t length)
{
    (void)user;
    esp_err_t error = esp_flash_erase_region(esp_flash_default_chip, address, length);
    return error == ESP_OK ? 0 : -(int32_t)error;
}

static int32_t flash_write(void *user, uint32_t address, const uint8_t *data, size_t length)
{
    (void)user;
    esp_err_t error = esp_flash_write(esp_flash_default_chip, data, address, length);
    return error == ESP_OK ? 0 : -(int32_t)error;
}

uint32_t dmesh_module_loader_partition_size(void)
{
    return cached_partition == NULL ? 0 : cached_partition->size;
}

int dmesh_module_loader_flash_erase(uint32_t address, uint32_t length)
{
    if (cached_partition == NULL || address > cached_partition->size ||
        length > cached_partition->size - address ||
        (address & 0xfffu) != 0 || (length & 0xfffu) != 0) return -1;
    return flash_erase(NULL, cached_partition->address + address, length);
}

int dmesh_module_loader_flash_write(uint32_t address, const uint8_t *data,
                                    size_t length)
{
    if (cached_partition == NULL || data == NULL || address > cached_partition->size ||
        length > cached_partition->size - address) return -1;
    return flash_write(NULL, cached_partition->address + address, data, length);
}

static const esp_partition_t *dmesh_main_partition(void)
{
    return esp_partition_find_first(ESP_PARTITION_TYPE_APP,
                                    ESP_PARTITION_SUBTYPE_ANY, "main");
}

int dmesh_main_flash_erase(uint32_t length)
{
    const esp_partition_t *partition = dmesh_main_partition();
    if (partition == NULL || length == 0 || length > partition->size) return -1;
    uint32_t erase = (length + 0xfffu) & ~0xfffu;
    return esp_partition_erase_range(partition, 0, erase);
}

int dmesh_main_flash_write(uint32_t offset, const uint8_t *data, size_t length)
{
    const esp_partition_t *partition = dmesh_main_partition();
    if (partition == NULL || data == NULL || offset > partition->size ||
        length > partition->size - offset) return -1;
    return esp_partition_write(partition, offset, data, length);
}

bool dmesh_module_flash_supported(void)
{
    return true;
}

bool dmesh_module_psram_exec_supported(void)
{
    /* A heap allocation in PSRAM is data-addressable, not a portable dynamic
     * instruction mapping. S2/S3 XiP is an image/linker configuration, and
     * classic ESP32 does not provide this experiment with executable PSRAM. */
    return false;
}

const char *dmesh_module_psram_exec_reason(void)
{
    return "dynamic PSRAM execution is unsupported; use flash instruction mmap";
}

static int invoke_now(uint16_t expected_service_tag, uint32_t offset, uint32_t size,
                      const uint8_t *payload, size_t payload_len,
                      const uint8_t *args, size_t args_len)
{
    module_arena_reset();
    cached_task_stage = 3;
    if (offset % MODULE_ALIGN != 0) return -1;
    const esp_partition_t *partition = cached_partition;
    if (partition == NULL || offset > partition->size ||
        partition->size - offset < DMESH_MODULE_HEADER_SIZE) return -2;

    /* The startup scan caches the preferred module (currently lora), but a
     * generic module command may explicitly target any aligned slot. Read
     * that slot's header instead of requiring it to be the cached one. */
    dmesh_module_header_t selected_header;
    esp_err_t read_err = read_module_header(partition, offset, &selected_header);
    if (read_err != ESP_OK) return -3;
    const dmesh_module_header_t *header = &selected_header;
    if (size == 0) size = partition->size - offset;
    if (size > partition->size - offset) return -2;
    if (header->magic != DMESH_MODULE_MAGIC ||
        header->abi_version != DMESH_MODULE_ABI_VERSION ||
        header->header_size != DMESH_MODULE_HEADER_SIZE ||
        header->image_size < DMESH_MODULE_HEADER_SIZE ||
        header->entry_offset < DMESH_MODULE_HEADER_SIZE ||
        header->entry_offset % 4u != 0 ||
        header->entry_offset >= header->image_size ||
        header->image_size > size) return -4;
    if (!header_service_window(header, expected_service_tag, offset,
                               partition->size)) return -5;

    const void *mapped = NULL;
    esp_partition_mmap_handle_t handle = 0;
    uint32_t fixed_mapped_size = 0;
    bool fixed_mapping = false;
    esp_err_t err;
#if defined(MODULE_FIXED_VADDR)
    if ((header->flags & DMESH_MODULE_FLAG_FIXED_VMA) != 0) {
        err = map_fixed_module(partition, offset, header->image_size,
                               (const uint8_t **)&mapped, &fixed_mapped_size,
                               header->code_vma, header->data_vma);
        fixed_mapping = err == ESP_OK;
    } else
#endif
    {
        err = esp_partition_mmap(partition, offset, header->image_size,
                                  ESP_PARTITION_MMAP_INST, &mapped, &handle);
    }
    if (err != ESP_OK || mapped == NULL) return -3;
    ESP_LOGI(TAG, "map base=%p fixed=%s size=%lu magic=0x%08lx abi=%u header=%u entry=0x%08lx image=0x%08lx",
             mapped, fixed_mapping ? "true" : "false", (unsigned long)size,
             (unsigned long)header->magic,
             (unsigned)header->abi_version, (unsigned)header->header_size,
             (unsigned long)header->entry_offset, (unsigned long)header->image_size);
    int result = -4;
    bool header_matches = header->magic == DMESH_MODULE_MAGIC &&
        header->abi_version == DMESH_MODULE_ABI_VERSION &&
        header->header_size == DMESH_MODULE_HEADER_SIZE &&
        header->service_tag == expected_service_tag &&
        header_service_window(header, expected_service_tag, offset, partition->size) &&
        header->entry_offset >= DMESH_MODULE_HEADER_SIZE &&
        header->entry_offset % 4u == 0 &&
        header->entry_offset < header->image_size && header->image_size <= size;
    if (header_matches) {
        cached_task_stage = 4;
        const uint8_t *base = mapped;
        dmesh_module_entry_fn entry = (dmesh_module_entry_fn)(base + header->entry_offset);
        ESP_LOGI(TAG, "invoke entry=%p context_size=%u payload=%lu args=%lu",
                 (void *)entry, (unsigned)sizeof(dmesh_module_context_t),
                 (unsigned long)payload_len, (unsigned long)args_len);
        cached_entry_args_len = (uint32_t)args_len;
        memset(cached_entry_args, 0, sizeof(cached_entry_args));
        size_t entry_copy = args_len < sizeof(cached_entry_args) - 1u
            ? args_len : sizeof(cached_entry_args) - 1u;
        if (args != NULL && entry_copy != 0) memcpy(cached_entry_args, args, entry_copy);
        dmesh_module_context_t context = {
            .abi_version = DMESH_MODULE_ABI_VERSION, .size = sizeof(context),
            .user = NULL, .log_line = log_line, .call_service = call_service,
            .get_setting = get_setting, .set_setting = set_setting,
            .emit_event = emit_event,
            .lora_host = &lora_host,
            .lora_config = &lora_config,
            .host = &common_host,
        };
        result = entry(&context, payload, payload_len, args, args_len);
    } else {
        ESP_LOGE(TAG, "module validation rejected expected_tag=%u actual_tag=%u magic=0x%08lx abi=%u header=%u entry=0x%08lx image=0x%08lx bound=0x%08lx fixed_flag=%s",
                 (unsigned)expected_service_tag, (unsigned)header->service_tag,
                 (unsigned long)header->magic, (unsigned)header->abi_version,
                 (unsigned)header->header_size, (unsigned long)header->entry_offset,
                 (unsigned long)header->image_size, (unsigned long)size,
                 (header->flags & DMESH_MODULE_FLAG_FIXED_VMA) != 0 ? "true" : "false");
    }
    if (fixed_mapping) {
#if defined(MODULE_FIXED_VADDR)
        unmap_fixed_module(fixed_mapped_size, header->code_vma, header->data_vma);
#endif
    } else {
        esp_partition_munmap(handle);
    }
    module_arena_reset();
    return result;
}

static void module_task(void *arg)
{
    module_job_t *job = arg;
    cached_task_stage = 1;
    ESP_LOGI(TAG, "module task enter tag=%u payload=%u args=%u",
             (unsigned)job->service_tag, (unsigned)job->payload_len,
             (unsigned)job->args_len);
    /* A completed Recovery handoff may leave the shared stop flag set while
     * this task is being queued. Clear only that stale request at the task
     * boundary; later flash preparation still stops the running task. */
    if (job->service_tag == 45u) dmesh_hw_host_request_stop(false);
    if (job->service_tag == 43u) dmesh_lora_irq_set_task(xTaskGetCurrentTaskHandle());
    const uint8_t *payload = job->bytes;
    const uint8_t *args = job->bytes + job->payload_len;
    uint32_t started_ms = (uint32_t)(esp_timer_get_time() / 1000);
    cached_task_start_ms = started_ms;
    cached_task_runs++;
    cached_task_stage = 2;
    int result = invoke_now(job->service_tag, job->offset, job->size, payload, job->payload_len,
                            args, job->args_len);
    cached_task_stage = 5;
    ESP_LOGI(TAG, "module task invoke returned result=%d", result);
    uint32_t elapsed_ms = (uint32_t)(esp_timer_get_time() / 1000) - started_ms;
    cached_last_runtime_ms = elapsed_ms;
    if (elapsed_ms > cached_max_runtime_ms) cached_max_runtime_ms = elapsed_ms;
    cached_last_result = result;
    cached_last_stack_high_water_words =
        (uint32_t)uxTaskGetStackHighWaterMark(xTaskGetCurrentTaskHandle());
    cached_task_done = true;
    cached_task_stage = 8;
    service_set_running(job->service_tag, false);
    if (job->service_tag == 43u) dmesh_lora_irq_set_task(NULL);
    cached_task_handle = NULL;
    memset(cached_task_name, 0, sizeof(cached_task_name));
    cached_task_service_tag = 0;
    if (result <= -100) {
        ESP_LOGE(TAG, "module entry rejected ABI/host contract offset=0x%08lx result=%d; task exited safely",
                 (unsigned long)job->offset, result);
    } else {
        ESP_LOGI(TAG, "module task complete offset=0x%08lx result=%d",
                 (unsigned long)job->offset, result);
    }
    free(job);
    vTaskDelete(NULL);
}

int dmesh_module_start_service(uint16_t service_tag, uint32_t offset, uint32_t size,
                            const uint8_t *payload, size_t payload_len,
                            const uint8_t *args, size_t args_len)
{
    /* Keep each ABI rejection distinct: the Rust caller receives this code in
     * its command response and cannot otherwise diagnose an asynchronous task
     * start failure over NAN. */
    uint32_t expected_offset = 0;
    if (!service_tag_offset(service_tag, &expected_offset)) return -11;
    if (offset != expected_offset) return -12;
    if (service_running(service_tag)) return -19;
    if (payload_len > MODULE_MAX_ARGUMENTS) return -14;
    if (args_len > MODULE_MAX_ARGUMENTS) return -15;
    if (payload_len + args_len > MODULE_MAX_ARGUMENTS) return -16;
    if (payload_len != 0 && payload == NULL) return -17;
    if (args_len != 0 && args == NULL) return -18;
    uint32_t stack_words = 0;
    int stack_rc = module_stack_words(offset, &stack_words);
    if (stack_rc != 0) return stack_rc == -2 ? -22 : -23;
    module_job_t *job = malloc(sizeof(*job) + payload_len + args_len);
    if (job == NULL) return -2;
    job->service_tag = service_tag;
    job->reserved = 0;
    job->offset = offset; job->size = size;
    job->payload_len = payload_len; job->args_len = args_len;
    if (payload_len != 0) memcpy(job->bytes, payload, payload_len);
    if (args_len != 0) memcpy(job->bytes + payload_len, args, args_len);
    cached_task_done = false;
    cached_last_result = -999;
    cached_task_start_ms = (uint32_t)(esp_timer_get_time() / 1000);
    service_set_running(service_tag, true);
    cached_task_service_tag = service_tag;
    snprintf(cached_task_name, sizeof(cached_task_name), "tag-%u", (unsigned)service_tag);
    if (service_tag == 45u) dmesh_hw_host_request_stop(false);
    job->stack_words = stack_words;
    /* Module code must not starve Main's UART/control task if an IRQ or SPI
     * callback returns immediately. Keep it at the cooperative application
     * priority; the host wait callback supplies the normal event wakeup. */
    if (xTaskCreatePinnedToCore(module_task, "dmesh_mod", job->stack_words,
                                job, MODULE_TASK_PRIORITY, &cached_task_handle,
                                tskNO_AFFINITY) != pdPASS) {
        service_set_running(service_tag, false);
        cached_task_done = true;
        cached_task_handle = NULL;
        free(job);
        return -3;
    }
    return 0;
}

/* Transitional host-side alias. The device runtime is numeric; this wrapper
 * is retained only while Main and the flash command surface migrate. */
int dmesh_module_start_task(const char *name, uint32_t offset, uint32_t size,
                            const uint8_t *payload, size_t payload_len,
                            const uint8_t *args, size_t args_len)
{
    if (name == NULL) return -11;
    uint16_t tag = 0;
    if (strcmp(name, "lora") == 0) tag = 43;
    else if (strcmp(name, "hw") == 0) tag = 45;
    else if (strcmp(name, "hello") == 0) tag = 46;
    else return -12;
    return dmesh_module_start_service(tag, offset, size, payload, payload_len,
                                      args, args_len);
}
