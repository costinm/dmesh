#include "dmesh_module_loader.h"

#include <stdlib.h>
#include <string.h>

#include "esp_err.h"
#include "esp_flash.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "dmesh_module_abi.h"

#define MODULE_ALIGN 0x10000u
#define MODULE_TASK_STACK 4096u
#define MODULE_MAX_ARGUMENTS 4096u
#define MODULE_DATA_START 0x3c0000u

static const char *TAG = "dmesh-module";
static dmesh_module_header_t cached_header;
static esp_partition_t cached_raw_partition;
static const esp_partition_t *cached_partition;
static bool cached_header_valid;
static volatile bool cached_task_done;
static volatile int cached_last_result = -999;

static const esp_partition_t *resolve_module_partition(void)
{
    const esp_partition_t *partition = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, "data");
    if (partition != NULL) return partition;
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
    cached_task_done = false;
    cached_last_result = -999;
    cached_partition = resolve_module_partition();
    if (cached_partition == NULL || cached_partition->size < DMESH_MODULE_HEADER_SIZE) {
        ESP_LOGW(TAG, "module header unavailable partition=%p", (void *)cached_partition);
        return;
    }
    ESP_LOGI(TAG, "startup partition address=0x%08lx size=0x%08lx",
             (unsigned long)cached_partition->address,
             (unsigned long)cached_partition->size);
    esp_err_t read_err = esp_partition_read(cached_partition, 0, &cached_header,
                                             sizeof(cached_header));
    if (read_err != ESP_OK) {
        ESP_LOGW(TAG, "module header read failed err=0x%08lx", (unsigned long)read_err);
        return;
    }
    cached_header_valid = cached_header.magic == DMESH_MODULE_MAGIC &&
        cached_header.abi_version == DMESH_MODULE_ABI_VERSION &&
        cached_header.header_size == DMESH_MODULE_HEADER_SIZE &&
        cached_header.entry_offset >= DMESH_MODULE_HEADER_SIZE &&
        cached_header.entry_offset % 4u == 0 &&
        cached_header.entry_offset < cached_header.image_size &&
        cached_header.image_size <= cached_partition->size;
    ESP_LOGI(TAG, "startup header valid=%s name=%s entry=0x%08lx image=0x%08lx",
             cached_header_valid ? "true" : "false", cached_header.name,
             (unsigned long)cached_header.entry_offset,
             (unsigned long)cached_header.image_size);
}

bool dmesh_module_loader_header_valid(void) { return cached_header_valid; }
bool dmesh_module_loader_task_done(void) { return cached_task_done; }
int dmesh_module_loader_last_result(void) { return cached_last_result; }

typedef struct {
    char name[16];
    uint32_t offset;
    uint32_t size;
    size_t payload_len;
    size_t args_len;
    uint8_t bytes[];
} module_job_t;

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
    if (size < DMESH_MODULE_HEADER_SIZE || offset % MODULE_ALIGN != 0) return -1;
    const esp_partition_t *partition = cached_partition;
    if (!cached_header_valid || partition == NULL || offset != 0 ||
        offset > partition->size || size > partition->size - offset) return -2;

    const dmesh_module_header_t *header = &cached_header;
    if (header->image_size > size) return -4;

    const void *mapped = NULL;
    esp_partition_mmap_handle_t handle = 0;
    esp_err_t err = esp_partition_mmap(partition, offset, header->image_size,
                             ESP_PARTITION_MMAP_INST, &mapped, &handle);
    if (err != ESP_OK || mapped == NULL) return -3;
    ESP_LOGI(TAG, "map base=%p size=%lu magic=0x%08lx abi=%u header=%u entry=0x%08lx image=0x%08lx",
             mapped, (unsigned long)size, (unsigned long)header->magic,
             (unsigned)header->abi_version, (unsigned)header->header_size,
             (unsigned long)header->entry_offset, (unsigned long)header->image_size);
    int result = -4;
    if (header->magic == DMESH_MODULE_MAGIC &&
        header->abi_version == DMESH_MODULE_ABI_VERSION &&
        header->header_size == DMESH_MODULE_HEADER_SIZE &&
        strncmp(header->name, expected_name, sizeof(header->name)) == 0 &&
        header->entry_offset >= DMESH_MODULE_HEADER_SIZE &&
        header->entry_offset % 4u == 0 &&
        header->entry_offset < header->image_size && header->image_size <= size) {
        const uint8_t *base = mapped;
        dmesh_module_entry_fn entry = (dmesh_module_entry_fn)(base + header->entry_offset);
        ESP_LOGI(TAG, "invoke entry=%p context_size=%u payload=%lu args=%lu",
                 (void *)entry, (unsigned)sizeof(dmesh_module_context_t),
                 (unsigned long)payload_len, (unsigned long)args_len);
        dmesh_module_context_t context = {
            .abi_version = DMESH_MODULE_ABI_VERSION, .size = sizeof(context),
            .user = NULL, .log_line = log_line, .call_service = call_service,
        };
        result = entry(&context, payload, payload_len, args, args_len);
    }
    esp_partition_munmap(handle);
    return result;
}

static void module_task(void *arg)
{
    module_job_t *job = arg;
    const uint8_t *payload = job->bytes;
    const uint8_t *args = job->bytes + job->payload_len;
    int result = invoke_now(job->name, job->offset, job->size, payload, job->payload_len,
                            args, job->args_len);
    cached_last_result = result;
    cached_task_done = true;
    ESP_LOGI(TAG, "module task complete offset=0x%08lx result=%d",
             (unsigned long)job->offset, result);
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
    if (name == NULL) return -11;
    if (name[0] == '\0') return -12;
    if (strnlen(name, 16) >= 16) return -13;
    if (payload_len > MODULE_MAX_ARGUMENTS) return -14;
    if (args_len > MODULE_MAX_ARGUMENTS) return -15;
    if (payload_len + args_len > MODULE_MAX_ARGUMENTS) return -16;
    if (payload_len != 0 && payload == NULL) return -17;
    if (args_len != 0 && args == NULL) return -18;
    module_job_t *job = malloc(sizeof(*job) + payload_len + args_len);
    if (job == NULL) return -2;
    strncpy(job->name, name, sizeof(job->name));
    job->name[sizeof(job->name) - 1] = '\0';
    job->offset = offset; job->size = size;
    job->payload_len = payload_len; job->args_len = args_len;
    if (payload_len != 0) memcpy(job->bytes, payload, payload_len);
    if (args_len != 0) memcpy(job->bytes + payload_len, args, args_len);
    if (xTaskCreatePinnedToCore(module_task, "dmesh_mod", MODULE_TASK_STACK,
                                job, 4, NULL, tskNO_AFFINITY) != pdPASS) {
        free(job);
        return -3;
    }
    return 0;
}
