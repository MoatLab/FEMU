/* SPDX-License-Identifier: GPL-2.0-or-later */
/* query-femu for a build without the femu device. */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-femu.h"

FemuInfo *coroutine_fn qmp_query_femu(const char *path, bool has_nsid,
                                      uint32_t nsid, bool has_kind,
                                      FemuQueryKind kind, bool has_offset,
                                      uint32_t offset, bool has_limit,
                                      uint32_t limit, Error **errp)
{
    error_setg(errp, "this QEMU is built without the femu device");
    return NULL;
}
