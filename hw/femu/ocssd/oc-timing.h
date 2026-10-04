#ifndef __FEMU_OC_TIMING_H
#define __FEMU_OC_TIMING_H

typedef struct FemuCtrl FemuCtrl;

void set_latency(FemuCtrl *n);
void oc_set_latency(FemuCtrl *n, uint32_t rd_upper, uint32_t rd_lower,
                    uint32_t wr_upper, uint32_t wr_lower, uint32_t erase,
                    uint32_t xfer);
bool oc_timing_geometry_ok(FemuCtrl *n, Error **errp);
#endif
