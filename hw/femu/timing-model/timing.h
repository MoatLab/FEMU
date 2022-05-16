#ifndef __FEMU_TIMING_MODEL
#define __FEMU_TIMING_MODEL

typedef struct FemuCtrl FemuCtrl;

int64_t advance_channel_timestamp(FemuCtrl *n, int ch, uint64_t now, int opcode);
int64_t advance_chip_timestamp(FemuCtrl *n, int lunid, uint64_t now, int opcode,
                               uint8_t page_type);
void set_latency(FemuCtrl *n);
#endif
