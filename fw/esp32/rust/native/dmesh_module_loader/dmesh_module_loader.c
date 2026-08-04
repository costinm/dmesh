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
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "dmesh_module_abi.h"

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
#define MODULE_DATA_START 0x3c0000u

/* The fixed-VMA experiment is deliberately opt-in through the DMOD header.
 * These windows are in the instruction linear region but well above the
 * normal application image. The module build links its code at
 * WINDOW + DMESH_MODULE_HEADER_SIZE; the mapped page still starts at the
 * 64-KiB-aligned module slot so the header and code share one MMU page. */
#if CONFIG_IDF_TARGET_ESP32S3
#define MODULE_FIXED_VADDR 0x43000000u
#define MODULE_FIXED_DATA_VADDR 0x3d000000u
#define MODULE_FIXED_WINDOW_SIZE 0x10000u
#elif CONFIG_IDF_TARGET_ESP32
#define MODULE_FIXED_VADDR 0x400d0000u
#define MODULE_FIXED_DATA_VADDR 0x3f400000u
#define MODULE_FIXED_WINDOW_SIZE 0x10000u
#endif

static const char *TAG = "dmesh-module";
static dmesh_module_header_t cached_header;
static uint32_t cached_offset;
static esp_partition_t cached_raw_partition;
static const esp_partition_t *cached_partition;
static bool cached_header_valid;
static volatile bool cached_task_done;
static volatile bool cached_task_running;
static volatile int cached_last_result = -999;
static volatile uint32_t cached_task_start_ms;
static volatile uint32_t cached_last_runtime_ms;
static volatile uint32_t cached_max_runtime_ms;
static volatile uint32_t cached_task_runs;
static volatile uint32_t cached_last_stack_high_water_words;
static TaskHandle_t cached_task_handle;
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
static portMUX_TYPE lora_command_mux = portMUX_INITIALIZER_UNLOCKED;
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

static esp_err_t map_fixed_module(const esp_partition_t *partition, uint32_t offset,
                                  uint32_t image_size, const uint8_t **out_base,
                                  uint32_t *out_mapped_size)
{
    if (partition == NULL || out_base == NULL || out_mapped_size == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    const uint32_t paddr = partition->address + offset;
    const uint32_t mmu_id = module_mmu_id();
    const uint32_t page_size = mmu_hal_pages_to_bytes(mmu_id, 1);
    if (page_size == 0 || (MODULE_FIXED_VADDR % page_size) != 0 ||
        (paddr % page_size) != 0 || image_size > MODULE_FIXED_WINDOW_SIZE) {
        return ESP_ERR_INVALID_ARG;
    }
    uint32_t mapped_size = 0;
    const uint32_t rounded_size =
        ((image_size + page_size - 1u) / page_size) * page_size;
    if (rounded_size > MODULE_FIXED_WINDOW_SIZE) return ESP_ERR_INVALID_SIZE;
    mmu_hal_map_region(mmu_id, MMU_TARGET_FLASH0, MODULE_FIXED_VADDR, paddr,
                       image_size, &mapped_size);
    if (mapped_size < rounded_size) {
        mmu_hal_unmap_region(mmu_id, MODULE_FIXED_VADDR, mapped_size);
        return ESP_FAIL;
    }
    /* Xtensa literals and Rust string constants are ordinary data loads. The
     * code and data buses have different virtual aliases, so map the same
     * contiguous flash image into both. MODULE_DATA_VMA in the fixed linker
     * script points .rodata at this corresponding data-bus window. */
    uint32_t data_mapped_size = 0;
    mmu_hal_map_region(mmu_id, MMU_TARGET_FLASH0, MODULE_FIXED_DATA_VADDR, paddr,
                       image_size, &data_mapped_size);
    if (data_mapped_size < rounded_size) {
        mmu_hal_unmap_region(mmu_id, MODULE_FIXED_VADDR, mapped_size);
        mmu_hal_unmap_region(mmu_id, MODULE_FIXED_DATA_VADDR, data_mapped_size);
        return ESP_FAIL;
    }
    /* The HAL only changes MMU entries. Invalidate both caches so a previous
     * module occupying either alias cannot be executed/read accidentally. */
    esp_err_t sync_err = esp_cache_msync((void *)MODULE_FIXED_VADDR, mapped_size,
                                         ESP_CACHE_MSYNC_FLAG_DIR_M2C |
                                         ESP_CACHE_MSYNC_FLAG_TYPE_INST);
    if (sync_err == ESP_OK) {
        sync_err = esp_cache_msync((void *)MODULE_FIXED_DATA_VADDR, data_mapped_size,
                                   ESP_CACHE_MSYNC_FLAG_DIR_M2C |
                                   ESP_CACHE_MSYNC_FLAG_TYPE_DATA);
    }
    if (sync_err != ESP_OK) {
        mmu_hal_unmap_region(mmu_id, MODULE_FIXED_VADDR, mapped_size);
        mmu_hal_unmap_region(mmu_id, MODULE_FIXED_DATA_VADDR, data_mapped_size);
        return sync_err;
    }
    *out_base = (const uint8_t *)(uintptr_t)MODULE_FIXED_VADDR;
    *out_mapped_size = mapped_size;
    return ESP_OK;
}

static void unmap_fixed_module(uint32_t mapped_size)
{
    if (mapped_size == 0) return;
    const uint32_t mmu_id = module_mmu_id();
    mmu_hal_unmap_region(mmu_id, MODULE_FIXED_VADDR, mapped_size);
    mmu_hal_unmap_region(mmu_id, MODULE_FIXED_DATA_VADDR, mapped_size);
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
extern int dmesh_module_call_service(const uint8_t *service, size_t service_len,
                                     const uint8_t *payload, size_t payload_len,
                                     const uint8_t *args, size_t args_len);
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
    return dmesh_module_emit_event(event->event_id, event->value_type, event->flags,
                                   event->value, event->value_len);
}

static int lora_spi_transfer(void *user, const uint8_t *tx, uint8_t *rx, size_t len)
{
    (void)user;
    if (lora_spi == NULL || tx == NULL || rx == NULL || len == 0 || len > 256) return -1;
    /* SX126x holds BUSY high while a command is being processed. Waiting in
     * the module's dedicated task keeps this host primitive synchronous and
     * prevents a command from being clocked into the radio too early. The
     * timeout is finite so a missing/stuck BUSY signal cannot wedge Main. */
    if (lora_config.busy_pin >= 0) {
        const TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(100);
        while (gpio_get_level((gpio_num_t)lora_config.busy_pin) != 0) {
            if ((int32_t)(xTaskGetTickCount() - deadline) >= 0) return DMESH_LORA_ERR_BUSY;
            vTaskDelay(pdMS_TO_TICKS(1));
        }
    }
    spi_transaction_t t = {0};
    t.length = len * 8;
    t.tx_buffer = tx;
    t.rx_buffer = rx;
    if (spi_device_transmit(lora_spi, &t) != ESP_OK) return -1;
    /* SX126x commands are not complete when CS rises: the chip keeps BUSY
     * asserted while it applies the command. The former Main driver waited
     * after every transaction; without this wait a following GET_IRQ_STATUS
     * can race SET_TX and observe zero IRQ bits. Keep the bound finite so a
     * dead radio cannot wedge the module task. */
    if (lora_config.busy_pin >= 0) {
        const TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(100);
        while (gpio_get_level((gpio_num_t)lora_config.busy_pin) != 0) {
            if ((int32_t)(xTaskGetTickCount() - deadline) >= 0) return DMESH_LORA_ERR_BUSY;
            vTaskDelay(pdMS_TO_TICKS(1));
        }
    }
    return 0;
}

static int lora_gpio_write(void *user, int pin, int level)
{ (void)user; return gpio_set_level((gpio_num_t)pin, level) == ESP_OK ? 0 : -1; }
static int lora_gpio_read(void *user, int pin)
{ (void)user; return gpio_get_level((gpio_num_t)pin); }
static int lora_irq_configure(void *user, int pin, int active_level)
{
    (void)user;
    (void)active_level;
    esp_err_t err = gpio_set_direction((gpio_num_t)pin, GPIO_MODE_INPUT);
    if (err != ESP_OK) return -1;
    err = gpio_install_isr_service(ESP_INTR_FLAG_IRAM);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) return -1;
    (void)gpio_isr_handler_remove((gpio_num_t)pin);
    if (gpio_set_intr_type((gpio_num_t)pin, GPIO_INTR_POSEDGE) != ESP_OK) return -1;
    return gpio_isr_handler_add((gpio_num_t)pin, dmesh_lora_gpio_isr,
                                (void *)(uintptr_t)pin) == ESP_OK ? 0 : -1;
}
static int lora_irq_enable(void *user, int pin, int enabled)
{ (void)user; return enabled ? gpio_intr_enable((gpio_num_t)pin) : gpio_intr_disable((gpio_num_t)pin); }
static int lora_wait_irq(void *user, uint32_t timeout_ms)
{
    (void)user;
    dmesh_lora_irq_rearm();
    /* This is the only intentionally waiting module primitive. It runs in
     * the module's dedicated FreeRTOS task and always has a finite timeout;
     * Main's command path never invokes it. */
    if (timeout_ms > 1000u) timeout_ms = 1000u;
    return ulTaskGenericNotifyTake(0, pdTRUE, pdMS_TO_TICKS(timeout_ms)) != 0 ? 0 : 1;
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
    static const uint8_t service[] = "module";
    return dmesh_module_call_service(service, sizeof(service) - 1, data, len,
                                      (const uint8_t *)args, (size_t)args_len);
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
    spi_host_device_t host = lora_config.spi_host == 1 ? SPI2_HOST : SPI3_HOST;
    spi_bus_config_t bus = {
        .mosi_io_num = lora_config.mosi_pin >= 0 ? lora_config.mosi_pin :
                       (lora_config.spi_host == 1 ? 10 : 27),
        .miso_io_num = lora_config.miso_pin >= 0 ? lora_config.miso_pin :
                       (lora_config.spi_host == 1 ? 11 : 19),
        .sclk_io_num = lora_config.sck_pin >= 0 ? lora_config.sck_pin :
                       (lora_config.spi_host == 1 ? 9 : 5),
        .quadwp_io_num = -1, .quadhd_io_num = -1, .max_transfer_sz = 256,
    };
    if (spi_bus_initialize(host, &bus, SPI_DMA_CH_AUTO) != ESP_OK && lora_spi == NULL) {
        /* The legacy path may already own the bus; the module will report an
         * IO error and Main can use its fallback. */
        return;
    }
    spi_device_interface_config_t dev = {
        .clock_speed_hz = 1000000, .mode = 0,
        .spics_io_num = lora_config.cs_pin >= 0 ? lora_config.cs_pin :
                        (lora_config.spi_host == 2 ? 8 : 18), .queue_size = 1,
    };
    (void)spi_bus_add_device(host, &dev, &lora_spi);
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
    cached_header_valid = false;
    cached_offset = 0;
    cached_task_done = false;
    cached_task_running = false;
    cached_last_result = -999;
    cached_task_start_ms = 0;
    cached_last_runtime_ms = 0;
    cached_max_runtime_ms = 0;
    cached_task_runs = 0;
    cached_last_stack_high_water_words = 0;
    cached_task_handle = NULL;
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
    ESP_LOGI(TAG, "startup header valid=%s offset=0x%08lx name=%s entry=0x%08lx image=0x%08lx",
             cached_header_valid ? "true" : "false", (unsigned long)cached_offset,
             cached_header.name,
             (unsigned long)cached_header.entry_offset,
             (unsigned long)cached_header.image_size);
}

bool dmesh_module_loader_header_valid(void) { return cached_header_valid; }
bool dmesh_module_loader_is_lora(void)
{
    return cached_header_valid && strncmp(cached_header.name, "lora", sizeof(cached_header.name)) == 0;
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
    if (cached_task_running) {
        portENTER_CRITICAL(&lora_command_mux);
        lora_config = *config;
        portEXIT_CRITICAL(&lora_command_mux);
        return 0;
    }
    if (lora_spi != NULL) {
        spi_bus_remove_device(lora_spi);
        lora_spi = NULL;
        spi_bus_free(lora_config.spi_host == 2 ? SPI2_HOST : SPI3_HOST);
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
    if (!cached_task_running) {
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
    if (!cached_task_running) return -21;
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

typedef struct {
    char name[16];
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
        cached_partition->size - offset < sizeof(dmesh_module_header_t)) return -1;
    dmesh_module_header_t header;
    if (read_module_header(cached_partition, offset, &header) != ESP_OK ||
        header.magic != DMESH_MODULE_MAGIC || header.abi_version != DMESH_MODULE_ABI_VERSION ||
        header.header_size != DMESH_MODULE_HEADER_SIZE) return -1;
    uint32_t requested = header.required_stack_words;
    if (requested == 0) requested = MODULE_TASK_STACK_DEFAULT;
    if (requested < MODULE_TASK_STACK_MIN) requested = MODULE_TASK_STACK_MIN;
    if (requested > MODULE_TASK_STACK_MAX) return -2;
    *out = requested;
    return 0;
}

extern int dmesh_module_call_service(const uint8_t *service, size_t service_len,
                                     const uint8_t *payload, size_t payload_len,
                                     const uint8_t *args, size_t args_len);

static int log_line(void *user, const uint8_t *data, size_t len)
{
    (void)user;
    if (data == NULL) return -1;
    char line[97];
    size_t copied = len < sizeof(line) - 1u ? len : sizeof(line) - 1u;
    memcpy(line, data, copied);
    line[copied] = '\0';
    ESP_LOGI(TAG, "module log=%s%s", line, copied == len ? "" : "...");
    return copied == len ? 0 : -2;
}

static int call_service(void *user, const uint8_t *service, size_t service_len,
                        const uint8_t *payload, size_t payload_len,
                        const uint8_t *args, size_t args_len)
{
    (void)user;
    return dmesh_module_call_service(service, service_len, payload, payload_len, args, args_len);
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

static int invoke_now(const char *expected_name, uint32_t offset, uint32_t size,
                      const uint8_t *payload, size_t payload_len,
                      const uint8_t *args, size_t args_len)
{
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

    const void *mapped = NULL;
    esp_partition_mmap_handle_t handle = 0;
    uint32_t fixed_mapped_size = 0;
    bool fixed_mapping = false;
    esp_err_t err;
#if defined(MODULE_FIXED_VADDR)
    if ((header->flags & DMESH_MODULE_FLAG_FIXED_VMA) != 0) {
        err = map_fixed_module(partition, offset, header->image_size,
                               (const uint8_t **)&mapped, &fixed_mapped_size);
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
        strncmp(header->name, expected_name, sizeof(header->name)) == 0 &&
        header->entry_offset >= DMESH_MODULE_HEADER_SIZE &&
        header->entry_offset % 4u == 0 &&
        header->entry_offset < header->image_size && header->image_size <= size;
    if (header_matches) {
        const uint8_t *base = mapped;
        dmesh_module_entry_fn entry = (dmesh_module_entry_fn)(base + header->entry_offset);
        ESP_LOGI(TAG, "invoke entry=%p context_size=%u payload=%lu args=%lu",
                 (void *)entry, (unsigned)sizeof(dmesh_module_context_t),
                 (unsigned long)payload_len, (unsigned long)args_len);
        dmesh_module_context_t context = {
            .abi_version = DMESH_MODULE_ABI_VERSION, .size = sizeof(context),
            .user = NULL, .log_line = log_line, .call_service = call_service,
            .get_setting = get_setting, .set_setting = set_setting,
            .emit_event = emit_event,
            .lora_host = &lora_host,
            .lora_config = &lora_config,
        };
        result = entry(&context, payload, payload_len, args, args_len);
    } else {
        ESP_LOGE(TAG, "module validation rejected expected=%s actual=%.*s magic=0x%08lx abi=%u header=%u entry=0x%08lx image=0x%08lx bound=0x%08lx fixed_flag=%s",
                 expected_name != NULL ? expected_name : "(null)",
                 (int)sizeof(header->name), header->name,
                 (unsigned long)header->magic, (unsigned)header->abi_version,
                 (unsigned)header->header_size, (unsigned long)header->entry_offset,
                 (unsigned long)header->image_size, (unsigned long)size,
                 (header->flags & DMESH_MODULE_FLAG_FIXED_VMA) != 0 ? "true" : "false");
    }
    if (fixed_mapping) {
#if defined(MODULE_FIXED_VADDR)
        unmap_fixed_module(fixed_mapped_size);
#endif
    } else {
        esp_partition_munmap(handle);
    }
    return result;
}

static void module_task(void *arg)
{
    module_job_t *job = arg;
    dmesh_lora_irq_set_task(xTaskGetCurrentTaskHandle());
    const uint8_t *payload = job->bytes;
    const uint8_t *args = job->bytes + job->payload_len;
    uint32_t started_ms = (uint32_t)(esp_timer_get_time() / 1000);
    cached_task_start_ms = started_ms;
    cached_task_runs++;
    int result = invoke_now(job->name, job->offset, job->size, payload, job->payload_len,
                            args, job->args_len);
    uint32_t elapsed_ms = (uint32_t)(esp_timer_get_time() / 1000) - started_ms;
    cached_last_runtime_ms = elapsed_ms;
    if (elapsed_ms > cached_max_runtime_ms) cached_max_runtime_ms = elapsed_ms;
    cached_last_result = result;
    cached_last_stack_high_water_words =
        (uint32_t)uxTaskGetStackHighWaterMark(xTaskGetCurrentTaskHandle());
    cached_task_done = true;
    cached_task_running = false;
    dmesh_lora_irq_set_task(NULL);
    cached_task_handle = NULL;
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

int dmesh_module_start_task(const char *name, uint32_t offset, uint32_t size,
                            const uint8_t *payload, size_t payload_len,
                            const uint8_t *args, size_t args_len)
{
    /* Keep each ABI rejection distinct: the Rust caller receives this code in
     * its command response and cannot otherwise diagnose an asynchronous task
     * start failure over NAN. */
    if (cached_task_running) return -19;
    if (name == NULL) return -11;
    if (name[0] == '\0') return -12;
    if (strnlen(name, 16) >= 16) return -13;
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
    strncpy(job->name, name, sizeof(job->name));
    job->name[sizeof(job->name) - 1] = '\0';
    job->offset = offset; job->size = size;
    job->payload_len = payload_len; job->args_len = args_len;
    if (payload_len != 0) memcpy(job->bytes, payload, payload_len);
    if (args_len != 0) memcpy(job->bytes + payload_len, args, args_len);
    cached_task_done = false;
    cached_last_result = -999;
    cached_task_start_ms = (uint32_t)(esp_timer_get_time() / 1000);
    cached_task_running = true;
    job->stack_words = stack_words;
    /* Module code must not starve Main's UART/control task if an IRQ or SPI
     * callback returns immediately. Keep it at the cooperative application
     * priority; the host wait callback supplies the normal event wakeup. */
    if (xTaskCreatePinnedToCore(module_task, "dmesh_mod", job->stack_words,
                                job, MODULE_TASK_PRIORITY, &cached_task_handle,
                                tskNO_AFFINITY) != pdPASS) {
        cached_task_running = false;
        cached_task_done = true;
        cached_task_handle = NULL;
        free(job);
        return -3;
    }
    return 0;
}
