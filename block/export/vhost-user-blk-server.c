/*
 * Sharing QEMU block devices via vhost-user protocal
 *
 * Parts of the code based on nbd/server.c.
 *
 * Copyright (c) Coiby Xu <coiby.xu@gmail.com>.
 * Copyright (c) 2020 Red Hat, Inc.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 */
#include "qemu/osdep.h"
#include "block/block.h"
#include "contrib/libvhost-user/libvhost-user.h"
#include "standard-headers/linux/virtio_blk.h"
#include "qemu/vhost-user-server.h"
#include "vhost-user-blk-server.h"
#include "qapi/error.h"
#include "qom/object_interfaces.h"
#include "sysemu/block-backend.h"
#include "util/block-helpers.h"

enum {
    VHOST_USER_BLK_NUM_QUEUES_DEFAULT = 1,
};
struct virtio_blk_inhdr {
    unsigned char status;
};

typedef struct VuBlkReq {
    VuVirtqElement elem;
    int64_t sector_num;
    size_t size;
    struct virtio_blk_inhdr *in;
    struct virtio_blk_outhdr out;
    VuServer *server;
    struct VuVirtq *vq;
} VuBlkReq;

/* vhost user block device */
typedef struct {
    BlockExport export;
    VuServer vu_server;
    uint32_t blk_size;
    QIOChannelSocket *sioc;
    struct virtio_blk_config blkcfg;
    bool writable;
} VuBlkExport;

static void vu_blk_req_complete(VuBlkReq *req)
{
    VuDev *vu_dev = &req->server->vu_dev;

    /* IO size with 1 extra status byte */
    vu_queue_push(vu_dev, req->vq, &req->elem, req->size + 1);
    vu_queue_notify(vu_dev, req->vq);

    free(req);
}

static int coroutine_fn
vu_blk_discard_write_zeroes(BlockBackend *blk, struct iovec *iov,
                            uint32_t iovcnt, uint32_t type)
{
    struct virtio_blk_discard_write_zeroes desc;
    ssize_t size = iov_to_buf(iov, iovcnt, 0, &desc, sizeof(desc));
    if (unlikely(size != sizeof(desc))) {
        error_report("Invalid size %zd, expect %zu", size, sizeof(desc));
        return -EINVAL;
    }

    uint64_t range[2] = { le64_to_cpu(desc.sector) << 9,
                          le32_to_cpu(desc.num_sectors) << 9 };
    if (type == VIRTIO_BLK_T_DISCARD) {
        if (blk_co_pdiscard(blk, range[0], range[1]) == 0) {
            return 0;
        }
    } else if (type == VIRTIO_BLK_T_WRITE_ZEROES) {
        if (blk_co_pwrite_zeroes(blk, range[0], range[1], 0) == 0) {
            return 0;
        }
    }

    return -EINVAL;
}

static void coroutine_fn vu_blk_virtio_process_req(void *opaque)
{
    VuBlkReq *req = opaque;
    VuServer *server = req->server;
    VuVirtqElement *elem = &req->elem;
    uint32_t type;

    VuBlkExport *vexp = container_of(server, VuBlkExport, vu_server);
    BlockBackend *blk = vexp->export.blk;

    struct iovec *in_iov = elem->in_sg;
    struct iovec *out_iov = elem->out_sg;
    unsigned in_num = elem->in_num;
    unsigned out_num = elem->out_num;

    /* refer to hw/block/virtio_blk.c */
    if (elem->out_num < 1 || elem->in_num < 1) {
        error_report("virtio-blk request missing headers");
        goto err;
    }

    if (unlikely(iov_to_buf(out_iov, out_num, 0, &req->out,
                            sizeof(req->out)) != sizeof(req->out))) {
        error_report("virtio-blk request outhdr too short");
        goto err;
    }

    iov_discard_front(&out_iov, &out_num, sizeof(req->out));

    if (in_iov[in_num - 1].iov_len < sizeof(struct virtio_blk_inhdr)) {
        error_report("virtio-blk request inhdr too short");
        goto err;
    }

    /* We always touch the last byte, so just see how big in_iov is.  */
    req->in = (void *)in_iov[in_num - 1].iov_base
              + in_iov[in_num - 1].iov_len
              - sizeof(struct virtio_blk_inhdr);
    iov_discard_back(in_iov, &in_num, sizeof(struct virtio_blk_inhdr));

    type = le32_to_cpu(req->out.type);
    switch (type & ~VIRTIO_BLK_T_BARRIER) {
    case VIRTIO_BLK_T_IN:
    case VIRTIO_BLK_T_OUT: {
        ssize_t ret = 0;
        bool is_write = type & VIRTIO_BLK_T_OUT;
        req->sector_num = le64_to_cpu(req->out.sector);

        if (is_write && !vexp->writable) {
            req->in->status = VIRTIO_BLK_S_IOERR;
            break;
        }

        int64_t offset = req->sector_num * vexp->blk_size;
        QEMUIOVector qiov;
        if (is_write) {
            qemu_iovec_init_external(&qiov, out_iov, out_num);
            ret = blk_co_pwritev(blk, offset, qiov.size, &qiov, 0);
        } else {
            qemu_iovec_init_external(&qiov, in_iov, in_num);
            ret = blk_co_preadv(blk, offset, qiov.size, &qiov, 0);
        }
        if (ret >= 0) {
            req->in->status = VIRTIO_BLK_S_OK;
        } else {
            req->in->status = VIRTIO_BLK_S_IOERR;
        }
        break;
    }
    case VIRTIO_BLK_T_FLUSH:
        if (blk_co_flush(blk) == 0) {
            req->in->status = VIRTIO_BLK_S_OK;
        } else {
            req->in->status = VIRTIO_BLK_S_IOERR;
        }
        break;
    case VIRTIO_BLK_T_GET_ID: {
        size_t size = MIN(iov_size(&elem->in_sg[0], in_num),
                          VIRTIO_BLK_ID_BYTES);
        snprintf(elem->in_sg[0].iov_base, size, "%s", "vhost_user_blk");
        req->in->status = VIRTIO_BLK_S_OK;
        req->size = elem->in_sg[0].iov_len;
        break;
    }
    case VIRTIO_BLK_T_DISCARD:
    case VIRTIO_BLK_T_WRITE_ZEROES: {
        int rc;

        if (!vexp->writable) {
            req->in->status = VIRTIO_BLK_S_IOERR;
            break;
        }

        rc = vu_blk_discard_write_zeroes(blk, &elem->out_sg[1], out_num, type);
        if (rc == 0) {
            req->in->status = VIRTIO_BLK_S_OK;
        } else {
            req->in->status = VIRTIO_BLK_S_IOERR;
        }
        break;
    }
    default:
        req->in->status = VIRTIO_BLK_S_UNSUPP;
        break;
    }

    vu_blk_req_complete(req);
    return;

err:
    free(req);
}

static void vu_blk_process_vq(VuDev *vu_dev, int idx)
{
    VuServer *server = container_of(vu_dev, VuServer, vu_dev);
    VuVirtq *vq = vu_get_queue(vu_dev, idx);

    while (1) {
        VuBlkReq *req;

        req = vu_queue_pop(vu_dev, vq, sizeof(VuBlkReq));
        if (!req) {
            break;
        }

        req->server = server;
        req->vq = vq;

        Coroutine *co =
            qemu_coroutine_create(vu_blk_virtio_process_req, req);
        qemu_coroutine_enter(co);
    }
}

static void vu_blk_queue_set_started(VuDev *vu_dev, int idx, bool started)
{
    VuVirtq *vq;

    assert(vu_dev);

    vq = vu_get_queue(vu_dev, idx);
    vu_set_queue_handler(vu_dev, vq, started ? vu_blk_process_vq : NULL);
}

static uint64_t vu_blk_get_features(VuDev *dev)
{
    uint64_t features;
    VuServer *server = container_of(dev, VuServer, vu_dev);
    VuBlkExport *vexp = container_of(server, VuBlkExport, vu_server);
    features = 1ull << VIRTIO_BLK_F_SIZE_MAX |
               1ull << VIRTIO_BLK_F_SEG_MAX |
               1ull << VIRTIO_BLK_F_TOPOLOGY |
               1ull << VIRTIO_BLK_F_BLK_SIZE |
               1ull << VIRTIO_BLK_F_FLUSH |
               1ull << VIRTIO_BLK_F_DISCARD |
               1ull << VIRTIO_BLK_F_WRITE_ZEROES |
               1ull << VIRTIO_BLK_F_CONFIG_WCE |
               1ull << VIRTIO_BLK_F_MQ |
               1ull << VIRTIO_F_VERSION_1 |
               1ull << VIRTIO_RING_F_INDIRECT_DESC |
               1ull << VIRTIO_RING_F_EVENT_IDX |
               1ull << VHOST_USER_F_PROTOCOL_FEATURES;

    if (!vexp->writable) {
        features |= 1ull << VIRTIO_BLK_F_RO;
    }

    return features;
}

static uint64_t vu_blk_get_protocol_features(VuDev *dev)
{
    return 1ull << VHOST_USER_PROTOCOL_F_CONFIG |
           1ull << VHOST_USER_PROTOCOL_F_INFLIGHT_SHMFD;
}

static int
vu_blk_get_config(VuDev *vu_dev, uint8_t *config, uint32_t len)
{
    VuServer *server = container_of(vu_dev, VuServer, vu_dev);
    VuBlkExport *vexp = container_of(server, VuBlkExport, vu_server);

    g_return_val_if_fail(len <= sizeof(struct virtio_blk_config), -1);

    memcpy(config, &vexp->blkcfg, len);
    return 0;
}

static int
vu_blk_set_config(VuDev *vu_dev, const uint8_t *data,
                    uint32_t offset, uint32_t size, uint32_t flags)
{
    VuServer *server = container_of(vu_dev, VuServer, vu_dev);
    VuBlkExport *vexp = container_of(server, VuBlkExport, vu_server);
    uint8_t wce;

    /* don't support live migration */
    if (flags != VHOST_SET_CONFIG_TYPE_MASTER) {
        return -EINVAL;
    }

    if (offset != offsetof(struct virtio_blk_config, wce) ||
        size != 1) {
        return -EINVAL;
    }

    wce = *data;
    vexp->blkcfg.wce = wce;
    blk_set_enable_write_cache(vexp->export.blk, wce);
    return 0;
}

/*
 * When the client disconnects, it sends a VHOST_USER_NONE request
 * and vu_process_message will simple call exit which cause the VM
 * to exit abruptly.
 * To avoid this issue,  process VHOST_USER_NONE request ahead
 * of vu_process_message.
 *
 */
static int vu_blk_process_msg(VuDev *dev, VhostUserMsg *vmsg, int *do_reply)
{
    if (vmsg->request == VHOST_USER_NONE) {
        dev->panic(dev, "disconnect");
        return true;
    }
    return false;
}

static const VuDevIface vu_blk_iface = {
    .get_features          = vu_blk_get_features,
    .queue_set_started     = vu_blk_queue_set_started,
    .get_protocol_features = vu_blk_get_protocol_features,
    .get_config            = vu_blk_get_config,
    .set_config            = vu_blk_set_config,
    .process_msg           = vu_blk_process_msg,
};

static void blk_aio_attached(AioContext *ctx, void *opaque)
{
    VuBlkExport *vexp = opaque;

    vexp->export.ctx = ctx;
    vhost_user_server_attach_aio_context(&vexp->vu_server, ctx);
}

static void blk_aio_detach(void *opaque)
{
    VuBlkExport *vexp = opaque;

    vhost_user_server_detach_aio_context(&vexp->vu_server);
    vexp->export.ctx = NULL;
}

static void
vu_blk_initialize_config(BlockDriverState *bs,
                         struct virtio_blk_config *config,
                         uint32_t blk_size,
                         uint16_t num_queues)
{
    config->capacity = cpu_to_le64(bdrv_getlength(bs) >> BDRV_SECTOR_BITS);
    config->blk_size = cpu_to_le32(blk_size);
    config->size_max = cpu_to_le32(0);
    config->seg_max = cpu_to_le32(128 - 2);
    config->min_io_size = cpu_to_le16(1);
    config->opt_io_size = cpu_to_le32(1);
    config->num_queues = cpu_to_le16(num_queues);
    config->max_discard_sectors = cpu_to_le32(32768);
    config->max_discard_seg = cpu_to_le32(1);
    config->discard_sector_alignment = cpu_to_le32(config->blk_size >> 9);
    config->max_write_zeroes_sectors = cpu_to_le32(32768);
    config->max_write_zeroes_seg = cpu_to_le32(1);
}

static void vu_blk_exp_request_shutdown(BlockExport *exp)
{
    VuBlkExport *vexp = container_of(exp, VuBlkExport, export);

    vhost_user_server_stop(&vexp->vu_server);
}

static int vu_blk_exp_create(BlockExport *exp, BlockExportOptions *opts,
                             Error **errp)
{
    VuBlkExport *vexp = container_of(exp, VuBlkExport, export);
    BlockExportOptionsVhostUserBlk *vu_opts = &opts->u.vhost_user_blk;
    Error *local_err = NULL;
    uint64_t logical_block_size;
    uint16_t num_queues = VHOST_USER_BLK_NUM_QUEUES_DEFAULT;

    vexp->writable = opts->writable;
    vexp->blkcfg.wce = 0;

    if (vu_opts->has_logical_block_size) {
        logical_block_size = vu_opts->logical_block_size;
    } else {
        logical_block_size = BDRV_SECTOR_SIZE;
    }
    check_block_size(exp->id, "logical-block-size", logical_block_size,
                     &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return -EINVAL;
    }
    vexp->blk_size = logical_block_size;
    blk_set_guest_block_size(exp->blk, logical_block_size);

    if (vu_opts->has_num_queues) {
        num_queues = vu_opts->num_queues;
    }
    if (num_queues == 0) {
        error_setg(errp, "num-queues must be greater than 0");
        return -EINVAL;
    }

    vu_blk_initialize_config(blk_bs(exp->blk), &vexp->blkcfg,
                             logical_block_size, num_queues);

    blk_add_aio_context_notifier(exp->blk, blk_aio_attached, blk_aio_detach,
                                 vexp);

    if (!vhost_user_server_start(&vexp->vu_server, vu_opts->addr, exp->ctx,
                                 num_queues, &vu_blk_iface, errp)) {
        blk_remove_aio_context_notifier(exp->blk, blk_aio_attached,
                                        blk_aio_detach, vexp);
        return -EADDRNOTAVAIL;
    }

    return 0;
}

static void vu_blk_exp_delete(BlockExport *exp)
{
    VuBlkExport *vexp = container_of(exp, VuBlkExport, export);

    blk_remove_aio_context_notifier(exp->blk, blk_aio_attached, blk_aio_detach,
                                    vexp);
}

const BlockExportDriver blk_exp_vhost_user_blk = {
    .type               = BLOCK_EXPORT_TYPE_VHOST_USER_BLK,
    .instance_size      = sizeof(VuBlkExport),
    .create             = vu_blk_exp_create,
    .delete             = vu_blk_exp_delete,
    .request_shutdown   = vu_blk_exp_request_shutdown,
};
