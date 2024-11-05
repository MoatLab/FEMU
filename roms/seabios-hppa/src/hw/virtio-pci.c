/* virtio-pci.c - pci interface for virtio interface
 *
 * (c) Copyright 2008 Bull S.A.S.
 *
 *  Author: Laurent Vivier <Laurent.Vivier@bull.net>
 *
 * some parts from Linux Virtio PCI driver
 *
 *  Copyright IBM Corp. 2007
 *  Authors: Anthony Liguori  <aliguori@us.ibm.com>
 *
 *  Adopted for Seabios: Gleb Natapov <gleb@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPLv3
 * See the COPYING file in the top-level directory.
 */

#include "config.h" // CONFIG_DEBUG_LEVEL
#include "malloc.h" // free
#include "output.h" // dprintf
#include "pci.h" // pci_config_readl
#include "pcidevice.h" // struct pci_device
#include "pci_regs.h" // PCI_BASE_ADDRESS_0
#include "string.h" // memset
#include "virtio-pci.h"
#include "virtio-mmio.h"
#include "virtio-ring.h"

u64 _vp_read(struct vp_cap *cap, u32 offset, u8 size)
{
    u64 var = 0;

    switch (cap->mode) {
    case VP_ACCESS_IO:
    {
        u32 addr = cap->ioaddr + offset;
        switch (size) {
        case 8:
            var = inl(addr);
            var |= (u64)inl(addr+4) << 32;
            break;
        case 4:
            var = inl(addr);
            break;
        case 2:
            var = inw(addr);
            break;
        case 1:
            var = inb(addr);
            break;
        }
        break;
    }

    case VP_ACCESS_MMIO:
    {
        void *addr = cap->memaddr + offset;
        switch (size) {
        case 8:
            var = readl(addr);
            var |= (u64)readl(addr+4) << 32;
            break;
        case 4:
            var = readl(addr);
            break;
        case 2:
            var = readw(addr);
            break;
        case 1:
            var = readb(addr);
            break;
        }
        break;
    }

    case VP_ACCESS_PCICFG:
    {
        u32 addr = cap->baroff + offset;
        pci_config_writeb(cap->bdf, cap->cfg +
                          offsetof(struct virtio_pci_cfg_cap, cap.bar),
                          cap->bar);
        pci_config_writel(cap->bdf, cap->cfg +
                          offsetof(struct virtio_pci_cfg_cap, cap.offset),
                          addr);
        pci_config_writel(cap->bdf, cap->cfg +
                          offsetof(struct virtio_pci_cfg_cap, cap.length),
                          (size > 4) ? 4 : size);
        switch (size) {
        case 8:
            var = pci_config_readl(cap->bdf, cap->cfg +
                                   offsetof(struct virtio_pci_cfg_cap, pci_cfg_data));
            pci_config_writel(cap->bdf, cap->cfg +
                              offsetof(struct virtio_pci_cfg_cap, cap.offset),
                              addr + 4);
            var |= (u64)pci_config_readl(cap->bdf, cap->cfg +
                                         offsetof(struct virtio_pci_cfg_cap, pci_cfg_data)) << 32;
            break;
        case 4:
            var = pci_config_readl(cap->bdf, cap->cfg +
                                   offsetof(struct virtio_pci_cfg_cap, pci_cfg_data));
            break;
        case 2:
            var = pci_config_readw(cap->bdf, cap->cfg +
                                   offsetof(struct virtio_pci_cfg_cap, pci_cfg_data));
            break;
        case 1:
            var = pci_config_readb(cap->bdf, cap->cfg +
                                   offsetof(struct virtio_pci_cfg_cap, pci_cfg_data));
            break;
        }
    }
    }
    dprintf(9, "vp read   %x (%d) -> 0x%llx\n", cap->ioaddr + offset, size, var);
    return var;
}

void _vp_write(struct vp_cap *cap, u32 offset, u8 size, u64 var)
{
    dprintf(9, "vp write  %x (%d) <- 0x%llx\n", cap->ioaddr + offset, size, var);

    switch (cap->mode) {
    case VP_ACCESS_IO:
    {
        u32 addr = cap->ioaddr + offset;
        switch (size) {
        case 4:
            outl(var, addr);
            break;
        case 2:
            outw(var, addr);
            break;
        case 1:
            outb(var, addr);
            break;
        }
        break;
    }

    case VP_ACCESS_MMIO:
    {
        void *addr = cap->memaddr + offset;
        switch (size) {
        case 4:
            writel(addr, var);
            break;
        case 2:
            writew(addr, var);
            break;
        case 1:
            writeb(addr, var);
            break;
        }
        break;
    }

    case VP_ACCESS_PCICFG:
    {
        u32 addr = cap->baroff + offset;
        pci_config_writeb(cap->bdf, cap->cfg +
                          offsetof(struct virtio_pci_cfg_cap, cap.bar),
                          cap->bar);
        pci_config_writel(cap->bdf, cap->cfg +
                          offsetof(struct virtio_pci_cfg_cap, cap.offset),
                          addr);
        pci_config_writel(cap->bdf, cap->cfg +
                          offsetof(struct virtio_pci_cfg_cap, cap.length),
                          size);
        switch (size) {
        case 4:
            pci_config_writel(cap->bdf, cap->cfg +
                              offsetof(struct virtio_pci_cfg_cap, pci_cfg_data),
                              var);
            break;
        case 2:
            pci_config_writew(cap->bdf, cap->cfg +
                              offsetof(struct virtio_pci_cfg_cap, pci_cfg_data),
                              var);
            break;
        case 1:
            pci_config_writeb(cap->bdf, cap->cfg +
                              offsetof(struct virtio_pci_cfg_cap, pci_cfg_data),
                              var);
            break;
        }
    }
    }
}

u64 vp_get_features(struct vp_device *vp)
{
    u32 f0, f1;

    if (vp->use_mmio) {
        vp_write(&vp->common, virtio_mmio_cfg, device_feature_select, 0);
        f0 = vp_read(&vp->common, virtio_mmio_cfg, device_feature);
        f1 = 0;
    } else if (vp->use_modern) {
        vp_write(&vp->common, virtio_pci_common_cfg, device_feature_select, 0);
        f0 = vp_read(&vp->common, virtio_pci_common_cfg, device_feature);
        vp_write(&vp->common, virtio_pci_common_cfg, device_feature_select, 1);
        f1 = vp_read(&vp->common, virtio_pci_common_cfg, device_feature);
    } else {
        f0 = vp_read(&vp->legacy, virtio_pci_legacy, host_features);
        f1 = 0;
    }
    return ((u64)f1 << 32) | f0;
}

void vp_set_features(struct vp_device *vp, u64 features)
{
    u32 f0, f1;

    f0 = features;
    f1 = features >> 32;

    if (vp->use_mmio) {
        vp_write(&vp->common, virtio_mmio_cfg, guest_feature_select, f0);
        vp_write(&vp->common, virtio_mmio_cfg, guest_feature, f0);
    } else if (vp->use_modern) {
        vp_write(&vp->common, virtio_pci_common_cfg, guest_feature_select, 0);
        vp_write(&vp->common, virtio_pci_common_cfg, guest_feature, f0);
        vp_write(&vp->common, virtio_pci_common_cfg, guest_feature_select, 1);
        vp_write(&vp->common, virtio_pci_common_cfg, guest_feature, f1);
    } else {
        vp_write(&vp->legacy, virtio_pci_legacy, guest_features, f0);
    }
}

u8 vp_get_status(struct vp_device *vp)
{
    if (vp->use_mmio) {
        return vp_read(&vp->common, virtio_mmio_cfg, device_status);
    } else if (vp->use_modern) {
        return vp_read(&vp->common, virtio_pci_common_cfg, device_status);
    } else {
        return vp_read(&vp->legacy, virtio_pci_legacy, status);
    }
}

void vp_set_status(struct vp_device *vp, u8 status)
{
    if (status == 0)        /* reset */
        return;
    if (vp->use_mmio) {
        vp_write(&vp->common, virtio_mmio_cfg, device_status, status);
    } else if (vp->use_modern) {
        vp_write(&vp->common, virtio_pci_common_cfg, device_status, status);
    } else {
        vp_write(&vp->legacy, virtio_pci_legacy, status, status);
    }
}

u8 vp_get_isr(struct vp_device *vp)
{
    if (vp->use_mmio) {
        return vp_read(&vp->common, virtio_mmio_cfg, irq_status);
    } else if (vp->use_modern) {
        return vp_read(&vp->isr, virtio_pci_isr, isr);
    } else {
        return vp_read(&vp->legacy, virtio_pci_legacy, isr);
    }
}

void vp_reset(struct vp_device *vp)
{
    if (vp->use_mmio) {
        vp_write(&vp->common, virtio_mmio_cfg, device_status, 0);
        vp_read(&vp->common, virtio_mmio_cfg, irq_status);
    } else if (vp->use_modern) {
        vp_write(&vp->common, virtio_pci_common_cfg, device_status, 0);
        vp_read(&vp->isr, virtio_pci_isr, isr);
    } else {
        vp_write(&vp->legacy, virtio_pci_legacy, status, 0);
        vp_read(&vp->legacy, virtio_pci_legacy, isr);
    }
}

void vp_notify(struct vp_device *vp, struct vring_virtqueue *vq)
{
    if (vp->use_mmio) {
        vp_write(&vp->common, virtio_mmio_cfg, queue_notify, vq->queue_index);
    } else if (vp->use_modern) {
        u32 offset = vq->queue_notify_off * vp->notify_off_multiplier;
        switch (vp->notify.mode) {
        case VP_ACCESS_IO:
            outw(vq->queue_index, vp->notify.ioaddr + offset);
            break;
        case VP_ACCESS_MMIO:
            writew(vp->notify.memaddr + offset, vq->queue_index);
            break;
        case VP_ACCESS_PCICFG:
            pci_config_writeb(vp->notify.bdf, vp->notify.cfg +
                              offsetof(struct virtio_pci_cfg_cap, cap.bar),
                              vp->notify.bar);
            pci_config_writel(vp->notify.bdf, vp->notify.cfg +
                              offsetof(struct virtio_pci_cfg_cap, cap.offset),
                              vp->notify.baroff + offset);
            pci_config_writel(vp->notify.bdf, vp->notify.cfg +
                              offsetof(struct virtio_pci_cfg_cap, cap.length),
                              2);
            pci_config_writew(vp->notify.bdf, vp->notify.cfg +
                              offsetof(struct virtio_pci_cfg_cap, pci_cfg_data),
                              vq->queue_index);
        }
        dprintf(9, "vp notify %x (%d) -- 0x%x\n",
                vp->notify.ioaddr, 2, vq->queue_index);
    } else {
        vp_write(&vp->legacy, virtio_pci_legacy, queue_notify, vq->queue_index);
    }
}

int vp_find_vq(struct vp_device *vp, int queue_index,
               struct vring_virtqueue **p_vq)
{
   u16 num;

   ASSERT32FLAT();
   struct vring_virtqueue *vq = *p_vq = memalign_high(PAGE_SIZE, sizeof(*vq));
   if (!vq) {
       warn_noalloc();
       goto fail;
   }
   memset(vq, 0, sizeof(*vq));


   /* select the queue */
   if (vp->use_mmio) {
       vp_write(&vp->common, virtio_mmio_cfg, queue_select, queue_index);
   } else if (vp->use_modern) {
       vp_write(&vp->common, virtio_pci_common_cfg, queue_select, queue_index);
   } else {
       vp_write(&vp->legacy, virtio_pci_legacy, queue_sel, queue_index);
   }

   /* check if the queue is available */
   if (vp->use_mmio) {
       num = vp_read(&vp->common, virtio_mmio_cfg, queue_num_max);
       if (num > MAX_QUEUE_NUM)
           num = MAX_QUEUE_NUM;
       vp_write(&vp->common, virtio_mmio_cfg, queue_num, num);
   } else if (vp->use_modern) {
       num = vp_read(&vp->common, virtio_pci_common_cfg, queue_size);
       if (num > MAX_QUEUE_NUM) {
           vp_write(&vp->common, virtio_pci_common_cfg, queue_size,
                    MAX_QUEUE_NUM);
           num = vp_read(&vp->common, virtio_pci_common_cfg, queue_size);
       }
   } else {
       num = vp_read(&vp->legacy, virtio_pci_legacy, queue_num);
   }
   if (!num) {
       dprintf(1, "ERROR: queue size is 0\n");
       goto fail;
   }
   if (num > MAX_QUEUE_NUM) {
       dprintf(1, "ERROR: queue size %d > %d\n", num, MAX_QUEUE_NUM);
       goto fail;
   }

   /* check if the queue is already active */
   if (vp->use_mmio) {
       /* TODO */;
   } else if (vp->use_modern) {
       if (vp_read(&vp->common, virtio_pci_common_cfg, queue_enable)) {
           dprintf(1, "ERROR: queue already active\n");
           goto fail;
       }
   } else {
       if (vp_read(&vp->legacy, virtio_pci_legacy, queue_pfn)) {
           dprintf(1, "ERROR: queue already active\n");
           goto fail;
       }
   }
   vq->queue_index = queue_index;

   /* initialize the queue */
   struct vring * vr = &vq->vring;
   vring_init(vr, num, (unsigned char*)&vq->queue);

   /* activate the queue
    *
    * NOTE: vr->desc is initialized by vring_init()
    */

   if (vp->use_mmio) {
       if (vp_read(&vp->common, virtio_mmio_cfg, version) == 2) {
           vp_write(&vp->common, virtio_mmio_cfg, queue_desc_lo,
                    (unsigned long)virt_to_phys(vr->desc));
           vp_write(&vp->common, virtio_mmio_cfg, queue_desc_hi, 0);
           vp_write(&vp->common, virtio_mmio_cfg, queue_driver_lo,
                    (unsigned long)virt_to_phys(vr->avail));
           vp_write(&vp->common, virtio_mmio_cfg, queue_driver_hi, 0);
           vp_write(&vp->common, virtio_mmio_cfg, queue_device_lo,
                    (unsigned long)virt_to_phys(vr->used));
           vp_write(&vp->common, virtio_mmio_cfg, queue_device_hi, 0);
           vp_write(&vp->common, virtio_mmio_cfg, queue_ready, 1);
       } else {
           vp_write(&vp->common, virtio_mmio_cfg, legacy_guest_page_size,
                    (unsigned long)1 << PAGE_SHIFT);
           vp_write(&vp->common, virtio_mmio_cfg, legacy_queue_pfn,
                    (unsigned long)virt_to_phys(vr->desc) >> PAGE_SHIFT);
       }
   } else if (vp->use_modern) {
       vp_write(&vp->common, virtio_pci_common_cfg, queue_desc_lo,
                (unsigned long)virt_to_phys(vr->desc));
       vp_write(&vp->common, virtio_pci_common_cfg, queue_desc_hi, 0);
       vp_write(&vp->common, virtio_pci_common_cfg, queue_avail_lo,
                (unsigned long)virt_to_phys(vr->avail));
       vp_write(&vp->common, virtio_pci_common_cfg, queue_avail_hi, 0);
       vp_write(&vp->common, virtio_pci_common_cfg, queue_used_lo,
                (unsigned long)virt_to_phys(vr->used));
       vp_write(&vp->common, virtio_pci_common_cfg, queue_used_hi, 0);
       vp_write(&vp->common, virtio_pci_common_cfg, queue_enable, 1);
       vq->queue_notify_off = vp_read(&vp->common, virtio_pci_common_cfg,
                                      queue_notify_off);
   } else {
       vp_write(&vp->legacy, virtio_pci_legacy, queue_pfn,
                (unsigned long)virt_to_phys(vr->desc) >> PAGE_SHIFT);
   }
   return num;

fail:
   free(vq);
   *p_vq = NULL;
   return -1;
}

void vp_init_simple(struct vp_device *vp, struct pci_device *pci)
{
    u8 cap = pci_find_capability(pci->bdf, PCI_CAP_ID_VNDR, 0);
    struct vp_cap *vp_cap;
    const char *mode;
    u32 offset, base, mul;
    u64 addr;
    u8 type;

    memset(vp, 0, sizeof(*vp));
    while (cap != 0) {
        type = pci_config_readb(pci->bdf, cap +
                                offsetof(struct virtio_pci_cap, cfg_type));
        switch (type) {
        case VIRTIO_PCI_CAP_COMMON_CFG:
            vp_cap = &vp->common;
            break;
        case VIRTIO_PCI_CAP_NOTIFY_CFG:
            vp_cap = &vp->notify;
            mul = offsetof(struct virtio_pci_notify_cap, notify_off_multiplier);
            vp->notify_off_multiplier = pci_config_readl(pci->bdf, cap + mul);
            break;
        case VIRTIO_PCI_CAP_ISR_CFG:
            vp_cap = &vp->isr;
            break;
        case VIRTIO_PCI_CAP_DEVICE_CFG:
            vp_cap = &vp->device;
            break;
        case VIRTIO_PCI_CAP_PCI_CFG:
            vp->common.cfg = cap;
            vp->common.bdf = pci->bdf;
            vp->notify.cfg = cap;
            vp->notify.bdf = pci->bdf;
            vp->isr.cfg = cap;
            vp->isr.bdf = pci->bdf;
            vp->device.cfg = cap;
            vp->device.bdf = pci->bdf;
            vp_cap = NULL;
            dprintf(1, "pci dev %pP virtio cap at 0x%x type %d"
                    " [pci cfg access]\n", pci, cap, type);
            break;
        default:
            vp_cap = NULL;
            break;
        }
        if (vp_cap && !vp_cap->cap) {
            vp_cap->cap = cap;
            vp_cap->bar = pci_config_readb(pci->bdf, cap +
                                           offsetof(struct virtio_pci_cap, bar));
            offset = pci_config_readl(pci->bdf, cap +
                                      offsetof(struct virtio_pci_cap, offset));
            base = PCI_BASE_ADDRESS_0 + 4 * vp_cap->bar;
            addr = pci_config_readl(pci->bdf, base);
            if (addr & PCI_BASE_ADDRESS_SPACE_IO) {
                addr &= PCI_BASE_ADDRESS_IO_MASK;
                vp_cap->mode = VP_ACCESS_IO;
            } else if ((addr & PCI_BASE_ADDRESS_MEM_TYPE_MASK) ==
                       PCI_BASE_ADDRESS_MEM_TYPE_64) {
                addr &= PCI_BASE_ADDRESS_MEM_MASK;
                addr |= (u64)pci_config_readl(pci->bdf, base + 4) << 32;
                vp_cap->mode = (addr > 0xffffffffll) ?
                    VP_ACCESS_PCICFG : VP_ACCESS_MMIO;
            } else {
                addr &= PCI_BASE_ADDRESS_MEM_MASK;
                vp_cap->mode = VP_ACCESS_MMIO;
            }
            switch (vp_cap->mode) {
            case VP_ACCESS_IO:
            {
                u32 addr = pci_enable_iobar(pci, base);
                if (!addr)
                    return;
                vp_cap->ioaddr = addr + offset;
                mode = "io";
                break;
            }
            case VP_ACCESS_MMIO:
            {
                void *addr = pci_enable_membar(pci, base);
                if (!addr)
                    return;
                vp_cap->memaddr = addr + offset;
                mode = "mmio";
                break;
            }
            case VP_ACCESS_PCICFG:
                mode = "pcicfg";
                vp_cap->baroff = offset;
                break;
            default:
                mode = "Huh?";
                break;
            }
            dprintf(1, "pci dev %pP virtio cap at 0x%x type %d "
                    "bar %d at 0x%08llx off +0x%04x [%s]\n",
                    pci, vp_cap->cap, type, vp_cap->bar, addr, offset, mode);
        }

        cap = pci_find_capability(pci->bdf, PCI_CAP_ID_VNDR, cap);
    }

    if (vp->common.cap && vp->notify.cap && vp->isr.cap && vp->device.cap) {
        dprintf(1, "pci dev %pP using modern (1.0) virtio mode\n", pci);
        vp->use_modern = 1;
    } else {
        dprintf(1, "pci dev %pP using legacy (0.9.5) virtio mode\n", pci);
        vp->legacy.bar = 0;
        vp->legacy.ioaddr = pci_enable_iobar(pci, PCI_BASE_ADDRESS_0);
        if (!vp->legacy.ioaddr)
            return;
        vp->legacy.mode = VP_ACCESS_IO;
    }

    vp_reset(vp);
    pci_enable_busmaster(pci);
    vp_set_status(vp, VIRTIO_CONFIG_S_ACKNOWLEDGE |
                  VIRTIO_CONFIG_S_DRIVER );
}
