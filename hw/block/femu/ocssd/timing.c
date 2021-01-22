#include "qemu/osdep.h"
#include "hw/pci/msix.h"
#include "qemu/error-report.h"

#include "../nvme.h"
#include "./oc12.h"
#include "./nand.h"
#include "./timing.h"

int64_t advance_channel_timestamp(FemuCtrl *n, int ch, uint64_t now, int opcode)
{
    uint64_t start_data_xfer_ts;
    uint64_t data_ready_ts;

    /* TODO: Considering channel-level timing */
    return now;

    pthread_spin_lock(&n->chnl_locks[ch]);
    if (now < n->chnl_next_avail_time[ch]) {
        start_data_xfer_ts = n->chnl_next_avail_time[ch];
    } else {
        start_data_xfer_ts = now;
    }

    switch (opcode) {
    case OC12_CMD_READ:
    case OC12_CMD_WRITE:
        data_ready_ts = start_data_xfer_ts + n->chnl_pg_xfer_lat_ns * 2;
        break;
    case OC12_CMD_ERASE:
        data_ready_ts = start_data_xfer_ts;
        break;
    default:
        femu_err("opcode=%d\n", opcode);
        assert(0);
    }

    n->chnl_next_avail_time[ch] = data_ready_ts;
    pthread_spin_unlock(&n->chnl_locks[ch]);

    return data_ready_ts;
}

int64_t advance_chip_timestamp(FemuCtrl *n, int lunid, uint64_t now, int opcode,
                               bool is_upg)
{
    int64_t lat;
    int64_t io_done_ts;

    switch (opcode) {
    case OC12_CMD_READ:
        lat = (is_upg) ? n->upg_rd_lat_ns : n->lpg_rd_lat_ns;
        break;
    case OC12_CMD_WRITE:
        lat = (is_upg) ? n->upg_wr_lat_ns : n->lpg_wr_lat_ns;
        break;
    case OC12_CMD_ERASE:
        lat = n->blk_er_lat_ns;
        break;
    default:
        assert(0);
    }

    pthread_spin_lock(&n->chip_locks[lunid]);
    if (now < n->chip_next_avail_time[lunid]) {
        n->chip_next_avail_time[lunid] += lat;
    } else {
        n->chip_next_avail_time[lunid] = now + lat;
    }
    io_done_ts = n->chip_next_avail_time[lunid];
    pthread_spin_unlock(&n->chip_locks[lunid]);

    return io_done_ts;
}

