/*
 * Human Monitor 'info sgx' stub (CONFIG_SGX)
 *
 * Copyright (c) Linaro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "monitor/hmp.h"
#include "monitor/monitor.h"

void hmp_info_sgx(Monitor *mon, const QDict *qdict)
{
    monitor_printf(mon, "SGX is not available in this QEMU\n");
}
