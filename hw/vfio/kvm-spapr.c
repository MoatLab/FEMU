/*
 * VFIO sPAPR KVM specific functions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include <sys/ioctl.h>
#include <linux/vfio.h>
#include <linux/kvm.h>

#include "hw/vfio/vfio-container-legacy.h"
#include "hw/vfio/kvm-spapr.h"
#include "qapi/error.h"
#include "trace.h"
#include "vfio-helpers.h"

bool vfio_spapr_kvm_attach_tce(VFIOContainer *bcontainer,
                               MemoryRegionSection *section,
                               Error **errp)
{
    VFIOLegacyContainer *container = VFIO_IOMMU_LEGACY(bcontainer);
    VFIOGroup *group;
    IOMMUMemoryRegion *iommu_mr = IOMMU_MEMORY_REGION(section->mr);
    struct kvm_vfio_spapr_tce param;
    struct kvm_device_attr attr = {
        .group = KVM_DEV_VFIO_GROUP,
        .attr = KVM_DEV_VFIO_GROUP_SET_SPAPR_TCE,
        .addr = (uint64_t)(unsigned long)&param,
    };

    if (!memory_region_iommu_get_attr(iommu_mr, IOMMU_ATTR_SPAPR_TCE_FD,
                &param.tablefd)) {
        QLIST_FOREACH(group, &container->group_list, container_next) {
            param.groupfd = group->fd;
            if (ioctl(vfio_kvm_device_fd, KVM_SET_DEVICE_ATTR, &attr)) {
                error_setg_errno(errp, errno,
                        "vfio: failed GROUP_SET_SPAPR_TCE for "
                        "KVM VFIO device %d and group fd %d",
                        param.tablefd, param.groupfd);
                return false;
            }
            trace_vfio_spapr_group_attach(param.groupfd, param.tablefd);
        }
    }
    return true;
}
