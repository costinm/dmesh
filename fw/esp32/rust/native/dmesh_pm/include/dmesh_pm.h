#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t attempts;
    uint32_t entries;
    uint32_t skipped;
    uint64_t expected_us;
    uint64_t slept_us;
    uint32_t max_us;
    uint64_t tracked_us;
} dmesh_pm_metrics_t;

int32_t dmesh_pm_metrics_init(void);
void dmesh_pm_metrics_reset(void);
void dmesh_pm_metrics_snapshot(dmesh_pm_metrics_t *out);
int32_t dmesh_pm_dump_locks(char *out, size_t out_len);

#ifdef __cplusplus
}
#endif
