/*
 * OpenBIOS virtio-1.0 virtio-blk driver
 *
 * Copyright (c) 2013 Alexander Graf <agraf@suse.de>
 * Copyright (c) 2018 Mark Cave-Ayland <mark.cave-ayland@ilande.co.uk>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or (at
 * your option) any later version. See the COPYING file in the top-level
 * directory.
 */

#include "config.h"
#include "libc/byteorder.h"
#include "libc/vsprintf.h"
#include "libopenbios/bindings.h"
#include "libopenbios/ofmem.h"
#include "kernel/kernel.h"
#include "drivers/drivers.h"

#include "virtio.h"

#define VRING_WAIT_REPLY_TIMEOUT 10000

static uint8_t virtio_cfg_read8(uint64_t cfg_addr, int addr)
{
    return in_8((uint8_t *)(uintptr_t)(cfg_addr + addr));
}

static void virtio_cfg_write8(uint64_t cfg_addr, int addr, uint8_t value)
{
    out_8((uint8_t *)(uintptr_t)(cfg_addr + addr), value);
}

static uint16_t virtio_cfg_read16(uint64_t cfg_addr, int addr)
{
    return in_le16((uint16_t *)(uintptr_t)(cfg_addr + addr));
}

static void virtio_cfg_write16(uint64_t cfg_addr, int addr, uint16_t value)
{
    out_le16((uint16_t *)(uintptr_t)(cfg_addr + addr), value);
}

static uint32_t virtio_cfg_read32(uint64_t cfg_addr, int addr)
{
    return in_le32((uint32_t *)(uintptr_t)(cfg_addr + addr));
}

static void virtio_cfg_write32(uint64_t cfg_addr, int addr, uint32_t value)
{
    out_le32((uint32_t *)(uintptr_t)(cfg_addr + addr), value);
}

static uint64_t virtio_cfg_read64(uint64_t cfg_addr, int addr)
{
    uint64_t q = ((uint64_t)virtio_cfg_read32(cfg_addr + 4, addr) << 32);
    q |= virtio_cfg_read32(cfg_addr, addr);

    return q;
}

static void virtio_cfg_write64(uint64_t cfg_addr, int addr, uint64_t value)
{
    virtio_cfg_write32(cfg_addr, addr, (value & 0xffffffff));
    virtio_cfg_write32(cfg_addr, addr + 4, ((value >> 32) & 0xffffffff));
}

static long virtio_notify(VDev *vdev, int vq_idx, long cookie)
{
    uint16_t notify_offset = virtio_cfg_read16(vdev->common_cfg, VIRTIO_PCI_COMMON_Q_NOFF);

    virtio_cfg_write16(vdev->notify_base, notify_offset +
                        vq_idx * vdev->notify_mult, vq_idx);

    return 0;
}

/***********************************************
 *             Virtio functions                *
 ***********************************************/

static void vring_init(VRing *vr, VqInfo *info)
{
    void *p = (void *) (uintptr_t)info->queue;

    vr->id = info->index;
    vr->num = info->num;
    vr->desc = p;
    vr->avail = (void *)((uintptr_t)p + info->num * sizeof(VRingDesc));
    vr->used = (void *)(((unsigned long)&vr->avail->ring[info->num]
               + info->align - 1) & ~(info->align - 1));

    /* Zero out all relevant field */
    vr->avail->flags = __cpu_to_le16(0);
    vr->avail->idx = __cpu_to_le16(0);

    /* We're running with interrupts off anyways, so don't bother */
    vr->used->flags = __cpu_to_le16(VRING_USED_F_NO_NOTIFY);
    vr->used->idx = __cpu_to_le16(0);
    vr->used_idx = 0;
    vr->next_idx = 0;
    vr->cookie = 0;
}

static int vring_notify(VDev *vdev, VRing *vr)
{
    return virtio_notify(vdev, vr->id, vr->cookie);
}

static void vring_send_buf(VRing *vr, uint64_t p, int len, int flags)
{
    /* For follow-up chains we need to keep the first entry point */
    if (!(flags & VRING_HIDDEN_IS_CHAIN)) {
        vr->avail->ring[__le16_to_cpu(vr->avail->idx) % vr->num] = __cpu_to_le16(vr->next_idx);
    }

    vr->desc[vr->next_idx].addr = __cpu_to_le64(p);
    vr->desc[vr->next_idx].len = __cpu_to_le32(len);
    vr->desc[vr->next_idx].flags = __cpu_to_le16(flags & ~VRING_HIDDEN_IS_CHAIN);
    vr->desc[vr->next_idx].next = __cpu_to_le16(vr->next_idx);
    vr->desc[vr->next_idx].next = __cpu_to_le16(__le16_to_cpu(vr->desc[vr->next_idx].next) + 1);
    vr->next_idx++;

    /* Chains only have a single ID */
    if (!(flags & VRING_DESC_F_NEXT)) {
        vr->avail->idx = __cpu_to_le16(__le16_to_cpu(vr->avail->idx) + 1);
    }
}

static int vr_poll(VDev *vdev, VRing *vr)
{
    if (__le16_to_cpu(vr->used->idx) == vr->used_idx) {
        vring_notify(vdev, vr);
        return 0;
    }

    vr->used_idx = __le16_to_cpu(vr->used->idx);
    vr->next_idx = 0;
    vr->desc[0].len = __cpu_to_le32(0);
    vr->desc[0].flags = __cpu_to_le16(0);
    return 1; /* vr has been updated */
}

/*
 * Wait for the host to reply.
 *
 * timeout is in msecs if > 0.
 *
 * Returns 0 on success, 1 on timeout.
 */
static int vring_wait_reply(VDev *vdev)
{
    ucell target_ms, get_ms;

    fword("get-msecs");
    target_ms = POP();
    target_ms += vdev->wait_reply_timeout;

    /* Wait for any queue to be updated by the host */
    do {
        int i, r = 0;

        for (i = 0; i < vdev->nr_vqs; i++) {
            r += vr_poll(vdev, &vdev->vrings[i]);
        }

        if (r) {
            return 0;
        }

        fword("get-msecs");
        get_ms = POP();

    } while (!vdev->wait_reply_timeout || (get_ms < target_ms));

    return 1;
}

static uint64_t vring_addr_translate(VDev *vdev, void *p)
{
    ucell mode;
    uint64_t iova;

    iova = ofmem_translate(pointer2cell(p), &mode);
    return iova;
}

/***********************************************
 *               Virtio block                  *
 ***********************************************/

static int virtio_blk_read_many(VDev *vdev,
                                uint64_t offset, void *load_addr, int len)
{
    VirtioBlkOuthdr out_hdr;
    u8 status;
    VRing *vr = &vdev->vrings[vdev->cmd_vr_idx];
    uint8_t discard[VIRTIO_SECTOR_SIZE];

    uint64_t start_sector = offset / virtio_get_block_size(vdev);
    int head_len = offset & (virtio_get_block_size(vdev) - 1);
    uint64_t end_sector = (offset + len + virtio_get_block_size(vdev) - 1) /
                            virtio_get_block_size(vdev);
    int tail_len = end_sector * virtio_get_block_size(vdev) - (offset + len);

    /* Tell the host we want to read */
    out_hdr.type = __cpu_to_le32(VIRTIO_BLK_T_IN);
    out_hdr.ioprio = __cpu_to_le32(99);
    out_hdr.sector = __cpu_to_le64(virtio_sector_adjust(vdev, start_sector));

    vring_send_buf(vr, vring_addr_translate(vdev, &out_hdr), sizeof(out_hdr),
                   VRING_DESC_F_NEXT);

    /* Discarded head */
    if (head_len) {
        vring_send_buf(vr, vring_addr_translate(vdev, &discard), head_len,
                       VRING_DESC_F_WRITE | VRING_HIDDEN_IS_CHAIN |
                       VRING_DESC_F_NEXT);
    }

    /* This is where we want to receive data */
    vring_send_buf(vr, vring_addr_translate(vdev, load_addr), len,
                   VRING_DESC_F_WRITE | VRING_HIDDEN_IS_CHAIN |
                   VRING_DESC_F_NEXT);

    /* Discarded tail */
    if (tail_len) {
        vring_send_buf(vr, vring_addr_translate(vdev, &discard), tail_len,
                       VRING_DESC_F_WRITE | VRING_HIDDEN_IS_CHAIN |
                       VRING_DESC_F_NEXT);
    }

    /* status field */
    vring_send_buf(vr, vring_addr_translate(vdev, &status), sizeof(u8),
                   VRING_DESC_F_WRITE | VRING_HIDDEN_IS_CHAIN);

    /* Now we can tell the host to read */
    vring_wait_reply(vdev);

    return status;
}

int virtio_read_many(VDev *vdev, uint64_t offset, void *load_addr, int len)
{
    switch (vdev->senseid) {
    case VIRTIO_ID_BLOCK:
        return virtio_blk_read_many(vdev, offset, load_addr, len);
    }
    return -1;
}

static int virtio_read(VDev *vdev, uint64_t offset, void *load_addr, int len)
{
    return virtio_read_many(vdev, offset, load_addr, len);
}

int virtio_get_block_size(VDev *vdev)
{
    switch (vdev->senseid) {
    case VIRTIO_ID_BLOCK:
        return vdev->config.blk.blk_size << vdev->config.blk.physical_block_exp;
    }
    return 0;
}

static void
ob_virtio_configure_device(VDev *vdev)
{
    uint32_t feature;
    uint8_t status;
    int i;

    /* Indicate we recognise the device */
    status = virtio_cfg_read8(vdev->common_cfg, VIRTIO_PCI_COMMON_STATUS);
    status |= VIRTIO_CONFIG_S_ACKNOWLEDGE | VIRTIO_CONFIG_S_DRIVER;
    virtio_cfg_write8(vdev->common_cfg, VIRTIO_PCI_COMMON_STATUS, status);

    /* Negotiate features: acknowledge VIRTIO_F_VERSION_1 for 1.0 specification
       little-endian access */
    virtio_cfg_write32(vdev->common_cfg, VIRTIO_PCI_COMMON_DFSELECT, 0x1);
    virtio_cfg_write32(vdev->common_cfg, VIRTIO_PCI_COMMON_GFSELECT, 0x1);
    feature = virtio_cfg_read32(vdev->common_cfg, VIRTIO_PCI_COMMON_DF);
    feature &= (1ULL << (VIRTIO_F_VERSION_1 - 32));
    virtio_cfg_write32(vdev->common_cfg, VIRTIO_PCI_COMMON_GF, feature);

    status = virtio_cfg_read8(vdev->common_cfg, VIRTIO_PCI_COMMON_STATUS);
    status |= VIRTIO_CONFIG_S_FEATURES_OK;
    virtio_cfg_write8(vdev->common_cfg, VIRTIO_PCI_COMMON_STATUS, status);

    vdev->senseid = VIRTIO_ID_BLOCK;
    vdev->nr_vqs = 1;
    vdev->cmd_vr_idx = 0;
    vdev->wait_reply_timeout = VRING_WAIT_REPLY_TIMEOUT;
    vdev->scsi_block_size = VIRTIO_SCSI_BLOCK_SIZE;
    vdev->blk_factor = 1;

    for (i = 0; i < vdev->nr_vqs; i++) {
        VqInfo info = {
            .queue = (uintptr_t) vdev->ring_area + (i * VIRTIO_RING_SIZE),
            .align = VIRTIO_PCI_VRING_ALIGN,
            .index = i,
            .num = 0,
        };

        virtio_cfg_write16(vdev->common_cfg, VIRTIO_PCI_COMMON_Q_SELECT, i);

        info.num = virtio_cfg_read16(vdev->common_cfg, VIRTIO_PCI_COMMON_Q_SIZE);
        if (info.num > VIRTIO_MAX_RING_ENTRIES) {
            info.num = VIRTIO_MAX_RING_ENTRIES;
            virtio_cfg_write16(vdev->common_cfg, VIRTIO_PCI_COMMON_Q_SIZE, info.num);
        }

        vring_init(&vdev->vrings[i], &info);

        /* Set block information */
        vdev->guessed_disk_nature = VIRTIO_GDN_NONE;
        vdev->config.blk.blk_size = VIRTIO_SECTOR_SIZE;
        vdev->config.blk.physical_block_exp = 0;

        /* Read sectors */
        vdev->config.blk.capacity = virtio_cfg_read64(vdev->device_cfg, 0);

        /* Set queue addresses */
        virtio_cfg_write64(vdev->common_cfg, VIRTIO_PCI_COMMON_Q_DESCLO,
                            vring_addr_translate(vdev, &vdev->vrings[i].desc[0]));
        virtio_cfg_write64(vdev->common_cfg, VIRTIO_PCI_COMMON_Q_AVAILLO,
                            vring_addr_translate(vdev, &vdev->vrings[i].avail[0]));
        virtio_cfg_write64(vdev->common_cfg, VIRTIO_PCI_COMMON_Q_USEDLO,
                            vring_addr_translate(vdev, &vdev->vrings[i].used[0]));

        /* Enable queue */
        virtio_cfg_write16(vdev->common_cfg, VIRTIO_PCI_COMMON_Q_ENABLE, 1);
    }

    /* Initialisation complete */
    status |= VIRTIO_CONFIG_S_DRIVER_OK;
    virtio_cfg_write8(vdev->common_cfg, VIRTIO_PCI_COMMON_STATUS, status);

    vdev->configured = 1;
}

static void
ob_virtio_disk_open(VDev **_vdev)
{
    VDev *vdev;
    phandle_t ph;

    PUSH(find_ih_method("vdev", my_self()));
    fword("execute");
    *_vdev = cell2pointer(POP());
    vdev = *_vdev;

    vdev->pos = 0;

    if (!vdev->configured) {
       ob_virtio_configure_device(vdev);
    }

    /* interpose disk-label */
    ph = find_dev("/packages/disk-label");
    fword("my-args");
    PUSH_ph( ph );
    fword("interpose");

    RET(-1);
}

static void
ob_virtio_disk_close(VDev **_vdev)
{
    return;
}

/* ( pos.d -- status ) */
static void
ob_virtio_disk_seek(VDev **_vdev)
{
    VDev *vdev = *_vdev;
    uint64_t pos;

    pos = ((uint64_t)POP()) << 32;
    pos |= POP();

    /* Make sure we are within the physical limits */
    if (pos < (vdev->config.blk.capacity * virtio_get_block_size(vdev))) {
        vdev->pos = pos;
        PUSH(0);
    } else {
        PUSH(1);
    }

    return;
}

/* ( addr len -- actual ) */
static void
ob_virtio_disk_read(VDev **_vdev)
{
    VDev *vdev = *_vdev;
    ucell len = POP();
    uint8_t *addr = (uint8_t *)POP();

    virtio_read(vdev, vdev->pos, addr, len);

    vdev->pos += len;

    PUSH(len);
}

static void set_virtio_alias(const char *path, int idx)
{
    phandle_t aliases;
    char name[9];

    aliases = find_dev("/aliases");

    snprintf(name, sizeof(name), "virtio%d", idx);

    set_property(aliases, name, path, strlen(path) + 1);
}

DECLARE_UNNAMED_NODE(ob_virtio_disk, 0, sizeof(VDev *));

NODE_METHODS(ob_virtio_disk) = {
    { "open",      ob_virtio_disk_open          },
    { "close",     ob_virtio_disk_close         },
    { "seek",      ob_virtio_disk_seek          },
    { "read",      ob_virtio_disk_read          },
};

static void
ob_virtio_open(VDev **_vdev)
{
    PUSH(-1);
}

static void
ob_virtio_close(VDev **_vdev)
{
    return;
}

static void
ob_virtio_dma_alloc(__attribute__((unused)) VDev **_vdev)
{
    call_parent_method("dma-alloc");
}

static void
ob_virtio_dma_free(__attribute__((unused)) VDev **_vdev)
{
    call_parent_method("dma-free");
}

static void
ob_virtio_dma_map_in(__attribute__((unused)) VDev **_vdev)
{
    call_parent_method("dma-map-in");
}

static void
ob_virtio_dma_map_out(__attribute__((unused)) VDev **_vdev)
{
    call_parent_method("dma-map-out");
}

static void
ob_virtio_dma_sync(__attribute__((unused)) VDev **_vdev)
{
    call_parent_method("dma-sync");
}

DECLARE_UNNAMED_NODE(ob_virtio, 0, sizeof(VDev *));

NODE_METHODS(ob_virtio) = {
    { "open",          ob_virtio_open        },
    { "close",         ob_virtio_close       },
    { "dma-alloc",     ob_virtio_dma_alloc   },
    { "dma-free",      ob_virtio_dma_free    },
    { "dma-map-in",    ob_virtio_dma_map_in  },
    { "dma-map-out",   ob_virtio_dma_map_out },
    { "dma-sync",      ob_virtio_dma_sync    },
};

void ob_virtio_init(const char *path, const char *dev_name, uint64_t common_cfg,
                    uint64_t device_cfg, uint64_t notify_base, uint32_t notify_mult,
                    int idx)
{
    char buf[256];
    ucell addr;
    VDev *vdev;

    /* Open ob_virtio */
    BIND_NODE_METHODS(get_cur_dev(), ob_virtio);

    vdev = malloc(sizeof(VDev));
    vdev->common_cfg = common_cfg;
    vdev->device_cfg = device_cfg;
    vdev->notify_base = notify_base;
    vdev->notify_mult = notify_mult;
    vdev->configured = 0;

    PUSH(pointer2cell(vdev));
    feval("value vdev");

    PUSH(sizeof(VRing) * VIRTIO_MAX_VQS);
    feval("dma-alloc");
    addr = POP();
    vdev->vrings = cell2pointer(addr);

    PUSH((VIRTIO_RING_SIZE * 2 + VIRTIO_PCI_VRING_ALIGN) * VIRTIO_MAX_VQS);
    feval("dma-alloc");
    addr = POP();
    vdev->ring_area = cell2pointer(addr);

    fword("new-device");
    push_str("disk");
    fword("device-name");
    push_str("block");
    fword("device-type");

    PUSH(pointer2cell(vdev));
    feval("value vdev");

    BIND_NODE_METHODS(get_cur_dev(), ob_virtio_disk);
    fword("finish-device");

    snprintf(buf, sizeof(buf), "%s/disk", path);
    set_virtio_alias(buf, idx);
}
