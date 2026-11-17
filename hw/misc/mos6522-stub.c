/*
 * QEMU MOS6522 VIA stubs
 *
 * Copyright (c) Linaro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "monitor/monitor.h"
#include "monitor/hmp.h"

void hmp_info_via(Monitor *mon, const QDict *qdict)
{
    monitor_printf(mon, "MOS6522 VIA is not available in this QEMU\n");
}
