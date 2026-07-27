#include "dmesh_pm.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_attr.h"
#include "esp_err.h"
#include "esp_pm.h"
#include "esp_timer.h"

#if CONFIG_PM_LIGHT_SLEEP_CALLBACKS

/* Sleep callbacks run with the PM lock held. Split 64-bit values avoid
 * non-IRAM atomic helpers on 32-bit Xtensa. */
typedef struct {
    volatile uint32_t lo;
    volatile uint32_t hi;
} split_u64_t;

static volatile uint32_t s_attempts;
static volatile uint32_t s_entries;
static volatile uint32_t s_skipped;
static volatile uint32_t s_max_us;
static split_u64_t s_expected_us;
static split_u64_t s_slept_us;
static volatile int64_t s_epoch_us;
static bool s_registered;

static inline void IRAM_ATTR add_split(split_u64_t *value, uint64_t add) {
    uint32_t old_lo = value->lo;
    uint32_t add_lo = (uint32_t)add;
    value->lo = old_lo + add_lo;
    value->hi += (uint32_t)(add >> 32) + (value->lo < old_lo);
}

static uint64_t read_split(const split_u64_t *value) {
    uint32_t hi_before;
    uint32_t lo;
    uint32_t hi_after;
    do {
        hi_before = value->hi;
        lo = value->lo;
        hi_after = value->hi;
    } while (hi_before != hi_after);
    return ((uint64_t)hi_after << 32) | lo;
}

static esp_err_t IRAM_ATTR on_sleep_enter(int64_t expected_us, void *arg) {
    (void)arg;
    s_attempts++;
    if (expected_us > 0) {
        add_split(&s_expected_us, (uint64_t)expected_us);
    }
    return ESP_OK;
}

static esp_err_t IRAM_ATTR on_sleep_exit(int64_t slept_us, void *arg) {
    (void)arg;
    if (slept_us > 0) {
        uint32_t duration = slept_us > UINT32_MAX ? UINT32_MAX : (uint32_t)slept_us;
        s_entries++;
        add_split(&s_slept_us, (uint64_t)slept_us);
        if (duration > s_max_us) {
            s_max_us = duration;
        }
    } else {
        s_skipped++;
    }
    return ESP_OK;
}

int32_t dmesh_pm_metrics_init(void) {
    if (s_registered) {
        return ESP_OK;
    }
    esp_pm_sleep_cbs_register_config_t config = {
        .enter_cb = on_sleep_enter,
        .exit_cb = on_sleep_exit,
        .enter_cb_user_arg = NULL,
        .exit_cb_user_arg = NULL,
        .enter_cb_prior = 100,
        .exit_cb_prior = 100,
    };
    esp_err_t err = esp_pm_light_sleep_register_cbs(&config);
    if (err == ESP_OK) {
        s_registered = true;
        dmesh_pm_metrics_reset();
    }
    return err;
}

void dmesh_pm_metrics_reset(void) {
    s_attempts = 0;
    s_entries = 0;
    s_skipped = 0;
    s_max_us = 0;
    s_expected_us.lo = 0;
    s_expected_us.hi = 0;
    s_slept_us.lo = 0;
    s_slept_us.hi = 0;
    s_epoch_us = esp_timer_get_time();
}

void dmesh_pm_metrics_snapshot(dmesh_pm_metrics_t *out) {
    if (out == NULL) {
        return;
    }
    out->attempts = s_attempts;
    out->entries = s_entries;
    out->skipped = s_skipped;
    out->expected_us = read_split(&s_expected_us);
    out->slept_us = read_split(&s_slept_us);
    out->max_us = s_max_us;
    int64_t elapsed = esp_timer_get_time() - s_epoch_us;
    out->tracked_us = elapsed > 0 ? (uint64_t)elapsed : 0;
}

#else

int32_t dmesh_pm_metrics_init(void) { return ESP_ERR_NOT_SUPPORTED; }
void dmesh_pm_metrics_reset(void) {}
void dmesh_pm_metrics_snapshot(dmesh_pm_metrics_t *out) {
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }
}

#endif

int32_t dmesh_pm_dump_locks(char *out, size_t out_len) {
    if (out == NULL || out_len == 0) {
        return -ESP_ERR_INVALID_ARG;
    }
    char *dump = NULL;
    size_t dump_len = 0;
    FILE *stream = open_memstream(&dump, &dump_len);
    if (stream == NULL) {
        return -ESP_ERR_NO_MEM;
    }
    int32_t err = esp_pm_dump_locks(stream);
    fclose(stream);
    if (err != ESP_OK) {
        free(dump);
        return -err;
    }
    size_t copied = dump_len < out_len - 1 ? dump_len : out_len - 1;
    memcpy(out, dump, copied);
    out[copied] = '\0';
    free(dump);
    return (int32_t)copied;
}
