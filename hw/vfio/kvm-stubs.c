/*
 * Stubs for kvm helpers
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"

#include "hw/vfio/kvm-spapr.h"
#include "hw/vfio/vfio-device.h"
#include "qapi/error.h"
#include "vfio-helpers.h"

void vfio_kvm_device_close(void)
{
    return;
}

int vfio_kvm_device_add_fd(int fd, Error **errp)
{
    return 0;
}

int vfio_kvm_device_del_fd(int fd, Error **errp)
{
    return 0;
}

bool vfio_spapr_kvm_attach_tce(VFIOContainer *bcontainer,
                               MemoryRegionSection *section,
                               Error **errp)
{
    g_assert_not_reached();
}
