/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Firmware time of a collection move (fw_gc_page_ns). Pure arithmetic with
 * no FTL state, so the unit test (tests/unit/test-gc-fw.c) builds it with
 * the media layer alone.
 *
 * Each FTL has one GC firmware line. A move takes one slot of @cost ns on
 * it, after its data is in controller DRAM; the program of the move starts
 * when the slot ends:
 *
 *   LUN s    [read]
 *   GC fw          [slot]
 *   LUN d                [program]
 */
#ifndef __FEMU_BBSSD_FTL_GC_FW_MATH_H
#define __FEMU_BBSSD_FTL_GC_FW_MATH_H

#include <stdint.h>

/**
 * gc_fw_slot_end - when the firmware slot of one move ends
 * @ready: when the move can start: its read end, or now for a copyback
 * @now: the device time
 * @free: when the GC firmware line is free
 * @cost: firmware time of one move, ns
 *
 * The slot starts at the latest of the three times. The caller sets the
 * line free at the returned time once the move is booked.
 */
static inline uint64_t gc_fw_slot_end(uint64_t ready, uint64_t now,
                                      uint64_t free, uint64_t cost)
{
    uint64_t start = ready > free ? ready : free;

    if (now > start) {
        start = now;
    }
    return start + cost;
}

#endif
