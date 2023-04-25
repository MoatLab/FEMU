// Virtio block boot support.
//
// Copyright (C) 2010 Red Hat Inc.
//
// Authors:
//  Gleb Natapov <gnatapov@redhat.com>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_GLOBALFLAT
#include "config.h" // CONFIG_*
#include "block.h" // struct drive_s
#include "malloc.h" // free
#include "output.h" // dprintf
#include "pcidevice.h" // foreachpci
#include "pci_ids.h" // PCI_DEVICE_ID_VIRTIO_BLK
#include "pci_regs.h" // PCI_VENDOR_ID
#include "stacks.h" // run_thread
#include "std/disk.h" // DISK_RET_SUCCESS
#include "string.h" // memset
#include "util.h" // usleep, bootprio_find_pci_device, is_bootprio_strict
#include "virtio-pci.h"
#include "virtio-mmio.h"
#include "virtio-ring.h"
#include "virtio-blk.h"

#define min(a, b) ({\
		typeof(a) _a = a;\
		typeof(b) _b = b;\
		_a < _b ? _a : _b; })

struct virtiodrive_s {
    struct drive_s drive;
    struct vring_virtqueue *vq;
    struct vp_device vp;
};

void
virtio_blk_op_one_segment(struct virtiodrive_s *vdrive,
    int write, struct vring_list sg[])
{
    struct vring_virtqueue *vq = vdrive->vq;

    /* Add to virtqueue and kick host */
    if (write)
        vring_add_buf(vq, sg, 2, 1, 0, 0);
    else
        vring_add_buf(vq, sg, 1, 2, 0, 0);
    vring_kick(&vdrive->vp, vq, 1);

    /* Wait for reply */
    while (!vring_more_used(vq))
        usleep(5);

    /* Reclaim virtqueue element */
        vring_get_buf(vq, NULL);

    /**
    ** Clear interrupt status register. Avoid leaving interrupts stuck
    ** if VRING_AVAIL_F_NO_INTERRUPT was ignored and interrupts were raised.
    **/
    vp_get_isr(&vdrive->vp);
}

static int
virtio_blk_op(struct disk_op_s *op, int write)
{
    struct virtiodrive_s *vdrive =
        container_of(op->drive_fl, struct virtiodrive_s, drive);
    struct virtio_blk_outhdr hdr = {
        .type = write ? VIRTIO_BLK_T_OUT : VIRTIO_BLK_T_IN,
        .ioprio = 0,
        .sector = op->lba,
    };
    u8 status = VIRTIO_BLK_S_UNSUPP;
    struct vring_list sg[] = {
        {
            .addr       = (void*)(&hdr),
            .length     = sizeof(hdr),
        },
        {
            .addr       = op->buf_fl,
            .length     = vdrive->drive.blksize * op->count,
        },
        {
            .addr       = (void*)(&status),
            .length     = sizeof(status),
        },
    };
    u32 max_io_size =
        vdrive->drive.max_segment_size * vdrive->drive.max_segments;
    u16 blk_num_max;

    if (vdrive->drive.blksize != 0 && max_io_size != 0)
        blk_num_max = (u16)(max_io_size / vdrive->drive.blksize);
    else
        /* default blk_num_max if hardware doesnot advise a proper value */
        blk_num_max = 64;

    if (op->count <= blk_num_max) {
        virtio_blk_op_one_segment(vdrive, write, sg);
    } else {
        void *p  = op->buf_fl;
        u16 count = op->count;

        while (count > 0) {
            u16 blk_num = min(count, blk_num_max);
            sg[1].length = vdrive->drive.blksize * blk_num;
            sg[1].addr = p;
            virtio_blk_op_one_segment(vdrive, write, sg);
            if (status == VIRTIO_BLK_S_OK) {
                hdr.sector += blk_num;
                p += sg[1].length;
                count -= blk_num;
            } else {
                break;
            }
        }
    }
    return status == VIRTIO_BLK_S_OK ? DISK_RET_SUCCESS : DISK_RET_EBADTRACK;
}

int
virtio_blk_process_op(struct disk_op_s *op)
{
    if (! CONFIG_VIRTIO_BLK)
        return 0;
    switch (op->command) {
    case CMD_READ:
        return virtio_blk_op(op, 0);
    case CMD_WRITE:
        return virtio_blk_op(op, 1);
    default:
        return default_process_op(op);
    }
}

static void
init_virtio_blk(void *data)
{
    struct pci_device *pci = data;
    u8 status = VIRTIO_CONFIG_S_ACKNOWLEDGE | VIRTIO_CONFIG_S_DRIVER;
    dprintf(1, "found virtio-blk at %pP\n", pci);
    struct virtiodrive_s *vdrive = malloc_low(sizeof(*vdrive));
    if (!vdrive) {
        warn_noalloc();
        return;
    }
    memset(vdrive, 0, sizeof(*vdrive));
    vdrive->drive.type = DTYPE_VIRTIO_BLK;
    vdrive->drive.cntl_id = pci->bdf;

    vp_init_simple(&vdrive->vp, pci);

    if (vdrive->vp.use_modern) {
        struct vp_device *vp = &vdrive->vp;
        u64 features = vp_get_features(vp);
        u64 version1 = 1ull << VIRTIO_F_VERSION_1;
        u64 iommu_platform = 1ull << VIRTIO_F_IOMMU_PLATFORM;
        u64 blk_size = 1ull << VIRTIO_BLK_F_BLK_SIZE;
        u64 max_segments = 1ull << VIRTIO_BLK_F_SEG_MAX;
        u64 max_segment_size = 1ull << VIRTIO_BLK_F_SIZE_MAX;

        if (!(features & version1)) {
            dprintf(1, "modern device without virtio_1 feature bit: %pP\n", pci);
            goto fail;
        }

        features = features & (version1 | iommu_platform | blk_size
                        | max_segments | max_segment_size);
        vp_set_features(vp, features);
        status |= VIRTIO_CONFIG_S_FEATURES_OK;
        vp_set_status(vp, status);
        if (!(vp_get_status(vp) & VIRTIO_CONFIG_S_FEATURES_OK)) {
            dprintf(1, "device didn't accept features: %pP\n", pci);
            goto fail;
        }

        if (features & max_segment_size)
            vdrive->drive.max_segment_size =
                vp_read(&vp->device, struct virtio_blk_config, size_max);

        if (features & max_segments)
            vdrive->drive.max_segments =
                vp_read(&vp->device, struct virtio_blk_config, seg_max);

        vdrive->drive.sectors =
            vp_read(&vp->device, struct virtio_blk_config, capacity);
        if (features & blk_size) {
            vdrive->drive.blksize =
                vp_read(&vp->device, struct virtio_blk_config, blk_size);
        } else {
            vdrive->drive.blksize = DISK_SECTOR_SIZE;
        }
        if (vdrive->drive.blksize != DISK_SECTOR_SIZE) {
            dprintf(1, "virtio-blk %pP block size %d is unsupported\n",
                    pci, vdrive->drive.blksize);
            goto fail;
        }
        dprintf(3, "virtio-blk %pP blksize=%d sectors=%u size_max=%u "
                "seg_max=%u.\n", pci, vdrive->drive.blksize,
                (u32)vdrive->drive.sectors, vdrive->drive.max_segment_size,
                vdrive->drive.max_segments);

        vdrive->drive.pchs.cylinder =
            vp_read(&vp->device, struct virtio_blk_config, cylinders);
        vdrive->drive.pchs.head =
            vp_read(&vp->device, struct virtio_blk_config, heads);
        vdrive->drive.pchs.sector =
            vp_read(&vp->device, struct virtio_blk_config, sectors);
    }

    if (vp_find_vq(&vdrive->vp, 0, &vdrive->vq) < 0 ) {
        dprintf(1, "fail to find vq for virtio-blk %pP\n", pci);
        goto fail;
    }

    if (!vdrive->vp.use_modern) {
        struct virtio_blk_config cfg;
        vp_get_legacy(&vdrive->vp, 0, &cfg, sizeof(cfg));

        u64 f = vp_get_features(&vdrive->vp);
        vdrive->drive.blksize = (f & (1 << VIRTIO_BLK_F_BLK_SIZE)) ?
            cfg.blk_size : DISK_SECTOR_SIZE;

        if (f & (1 << VIRTIO_BLK_F_SIZE_MAX))
            vdrive->drive.max_segment_size = cfg.size_max;

        if (f & (1 << VIRTIO_BLK_F_SEG_MAX))
            vdrive->drive.max_segments = cfg.seg_max;

        vdrive->drive.sectors = cfg.capacity;
        dprintf(3, "virtio-blk %pP blksize=%d sectors=%u size_max=%u "
                "seg_max=%u.\n", pci, vdrive->drive.blksize,
                (u32)vdrive->drive.sectors, vdrive->drive.max_segment_size,
                vdrive->drive.max_segments);

        if (vdrive->drive.blksize != DISK_SECTOR_SIZE) {
            dprintf(1, "virtio-blk %pP block size %d is unsupported\n",
                    pci, vdrive->drive.blksize);
            goto fail;
        }
        vdrive->drive.pchs.cylinder = cfg.cylinders;
        vdrive->drive.pchs.head = cfg.heads;
        vdrive->drive.pchs.sector = cfg.sectors;
    }

    char *desc = znprintf(MAXDESCSIZE, "Virtio disk PCI:%pP", pci);
    boot_add_hd(&vdrive->drive, desc, bootprio_find_pci_device(pci));

    status |= VIRTIO_CONFIG_S_DRIVER_OK;
    vp_set_status(&vdrive->vp, status);

    boot_lchs_find_pci_device(pci, &vdrive->drive.lchs);
    return;

fail:
    vp_reset(&vdrive->vp);
    free(vdrive->vq);
    free(vdrive);
}

void
init_virtio_blk_mmio(void *mmio)
{
    u8 status = VIRTIO_CONFIG_S_ACKNOWLEDGE | VIRTIO_CONFIG_S_DRIVER;
    dprintf(1, "found virtio-blk-mmio at %p\n", mmio);
    struct virtiodrive_s *vdrive = malloc_low(sizeof(*vdrive));
    if (!vdrive) {
        warn_noalloc();
        return;
    }
    memset(vdrive, 0, sizeof(*vdrive));
    vdrive->drive.type = DTYPE_VIRTIO_BLK;
    vdrive->drive.cntl_id = (u32)mmio;

    vp_init_mmio(&vdrive->vp, mmio);

    struct vp_device *vp = &vdrive->vp;
    u64 features = vp_get_features(vp);
    u64 version1 = 1ull << VIRTIO_F_VERSION_1;
    u64 blk_size = 1ull << VIRTIO_BLK_F_BLK_SIZE;
    u64 max_segments = 1ull << VIRTIO_BLK_F_SEG_MAX;
    u64 max_segment_size = 1ull << VIRTIO_BLK_F_SIZE_MAX;

    features = features & (version1 | blk_size
            | max_segments | max_segment_size);
    vp_set_features(vp, features);
    status |= VIRTIO_CONFIG_S_FEATURES_OK;
    vp_set_status(vp, status);
    if (!(vp_get_status(vp) & VIRTIO_CONFIG_S_FEATURES_OK)) {
        dprintf(1, "device didn't accept features: %p\n", mmio);
        goto fail;
    }

    if (vp_find_vq(&vdrive->vp, 0, &vdrive->vq) < 0 ) {
        dprintf(1, "fail to find vq for virtio-blk-mmio %p\n", mmio);
        goto fail;
    }

    if (features & max_segment_size)
        vdrive->drive.max_segment_size =
            vp_read(&vp->device, struct virtio_blk_config, size_max);

    if (features & max_segments)
        vdrive->drive.max_segments =
            vp_read(&vp->device, struct virtio_blk_config, seg_max);

    vdrive->drive.sectors =
        vp_read(&vp->device, struct virtio_blk_config, capacity);
    if (features & blk_size) {
        vdrive->drive.blksize =
            vp_read(&vp->device, struct virtio_blk_config, blk_size);
    } else {
        vdrive->drive.blksize = DISK_SECTOR_SIZE;
    }
    if (vdrive->drive.blksize != DISK_SECTOR_SIZE) {
        dprintf(1, "virtio-blk-mmio %p block size %d is unsupported\n",
                mmio, vdrive->drive.blksize);
        goto fail;
    }
    dprintf(1, "virtio-blk-mmio %p blksize=%d sectors=%u size_max=%u "
            "seg_max=%u.\n", mmio, vdrive->drive.blksize,
            (u32)vdrive->drive.sectors, vdrive->drive.max_segment_size,
            vdrive->drive.max_segments);

    vdrive->drive.pchs.cylinder =
        vp_read(&vp->device, struct virtio_blk_config, cylinders);
    vdrive->drive.pchs.head =
        vp_read(&vp->device, struct virtio_blk_config, heads);
    vdrive->drive.pchs.sector =
        vp_read(&vp->device, struct virtio_blk_config, sectors);

    char *desc = znprintf(MAXDESCSIZE, "Virtio disk mmio:%p", mmio);
    boot_add_hd(&vdrive->drive, desc, bootprio_find_mmio_device(mmio));

    status |= VIRTIO_CONFIG_S_DRIVER_OK;
    vp_set_status(&vdrive->vp, status);
    return;

fail:
    vp_reset(&vdrive->vp);
    free(vdrive->vq);
    free(vdrive);
}

void
virtio_blk_setup(void)
{
    u8 skip_nonbootable = is_bootprio_strict();

    ASSERT32FLAT();
    if (! CONFIG_VIRTIO_BLK)
        return;

    dprintf(3, "init virtio-blk\n");

    struct pci_device *pci;
    foreachpci(pci) {
        if (pci->vendor != PCI_VENDOR_ID_REDHAT_QUMRANET ||
            (pci->device != PCI_DEVICE_ID_VIRTIO_BLK_09 &&
             pci->device != PCI_DEVICE_ID_VIRTIO_BLK_10))
            continue;

        if (skip_nonbootable && bootprio_find_pci_device(pci) < 0) {
            dprintf(1, "skipping init of a non-bootable virtio-blk at %pP\n",
                    pci);
            continue;
        }

        run_thread(init_virtio_blk, pci);
    }
}
