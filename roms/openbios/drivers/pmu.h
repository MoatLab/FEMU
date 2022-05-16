#ifndef __PMU_H__
#define __PMU_H__

#include "adb_bus.h"

typedef struct pmu_t {
    phys_addr_t base;
    adb_bus_t *adb_bus;
} pmu_t;

pmu_t *pmu_init (const char *path, phys_addr_t base);

int pmu_request(pmu_t *dev, uint8_t cmd,
                uint8_t in_len, uint8_t *in_data,
                uint8_t *out_len, uint8_t *out_data);

#endif /* __PMU_H__ */
