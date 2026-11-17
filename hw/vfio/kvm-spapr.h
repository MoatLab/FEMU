/*
 * VFIO sPAPR KVM specific functions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "hw/vfio/vfio-container.h"
#include "qapi/error.h"

bool vfio_spapr_kvm_attach_tce(VFIOContainer *bcontainer,
                               MemoryRegionSection *section,
                               Error **errp);
