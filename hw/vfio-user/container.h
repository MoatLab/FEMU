/*
 * vfio-user specific definitions.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_VFIO_USER_CONTAINER_H
#define HW_VFIO_USER_CONTAINER_H

#include "qemu/osdep.h"

#include "hw/vfio/vfio-container-base.h"
#include "hw/vfio-user/proxy.h"

/* MMU container sub-class for vfio-user. */
typedef struct VFIOUserContainer {
    VFIOContainerBase bcontainer;
    VFIOUserProxy *proxy;
} VFIOUserContainer;

OBJECT_DECLARE_SIMPLE_TYPE(VFIOUserContainer, VFIO_IOMMU_USER);

#endif /* HW_VFIO_USER_CONTAINER_H */
