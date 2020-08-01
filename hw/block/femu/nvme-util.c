/*
 * QEMU NVM Express Controller
 *
 * Copyright (c) 2012, Intel Corporation
 *
 * Written by Keith Busch <keith.busch@intel.com>
 *
 * This code is licensed under the GNU GPL v2 or later.
 */

/**
 * Reference Specs: http://www.nvmexpress.org, 1.3, 1.2, 1.1, 1.0e
 *
 *  http://www.nvmexpress.org/resources/
 */

/**
 * Usage: add options:
 *      -drive file=<file>,if=none,id=<drive_id>
 *      -device nvme,drive=<drive_id>,serial=<serial>,id=<id[optional]>
 *
 * The "file" option must point to a path to a real file that you will use as
 * the backing storage for your NVMe device. It must be a non-zero length, as
 * this will be the disk image that your nvme controller will use to carve up
 * namespaces for storage.
 *
 * Note the "drive" option's "id" name must match the "device nvme" drive's
 * name to link the block device used for backing storage to the nvme
 * interface.
 *
 * Advanced optional options:
 *
 *  namespaces=<int> : Namespaces to make out of the backing storage, Default:1
 *  queues=<int>     : Number of possible IO Queues, Default:64
 *  entries=<int>    : Maximum number of Queue entires possible, Default:0x7ff
 *  max_cqes=<int>   : Maximum completion queue entry size, Default:0x4
 *  max_sqes=<int>   : Maximum submission queue entry size, Default:0x6
 *  mpsmin=<int>     : Minimum page size supported, Default:0
 *  mpsmax=<int>     : Maximum page size supported, Default:0
 *  stride=<int>     : Doorbell stride, Default:0
 *  aerl=<int>       : Async event request limit, Default:3
 *  acl=<int>        : Abort command limit, Default:3
 *  elpe=<int>       : Error log page entries, Default:3
 *  mdts=<int>       : Maximum data transfer size, Default:5
 *  cqr=<int>        : Contiguous queues required, Default:1
 *  vwc=<int>        : Volatile write cache enabled, Default:0
 *  intc=<int>       : Interrupt configuration disabled, Default:0
 *  intc_thresh=<int>: Interrupt coalesce threshold, Default:0
 *  intc_ttime=<int> : Interrupt coalesce time 100's of usecs, Default:0
 *  nlbaf=<int>      : Number of logical block formats, Default:1
 *  lba_index=<int>  : Default namespace block format index, Default:0
 *  extended=<int>   : Use extended-lba for meta-data, Default:0
 *  dpc=<int>        : Data protection capabilities, Default:0
 *  dps=<int>        : Data protection settings, Default:0
 *  mc=<int>         : Meta-data capabilities, Default:0
 *  meta=<int>       : Meta-data size, Default:0
 *  oncs=<oncs>      : Optional NVMe command support, Default:DSM
 *  oacs=<oacs>      : Optional Admin command support, Default:Format
 *  cmbsz=<cmbsz>    : Controller Memory Buffer CMBSZ register, Default:0
 *  cmbloc=<cmbloc>  : Controller Memory Buffer CMBLOC register, Default:0
 *  lver=<int>         : version of the LightNVM standard to use, Default:1
 *  ll2pmode=<int>     : LightNVM op. mode. 1: hybrid, 0: full host-based. Default: 1
 *  lsec_size=<int>    : Controller Sector Size. Default: 4096
 *  lsecs_per_pg=<int> : Number of sectors in a flash page. Default: 1
 *  lpgs_per_blk=<int> : Number of pages per flash block. Default: 256
 *  lmax_sec_per_rq=<int> : Maximum number of sectors per I/O request. Default: 64
 *  lmtype=<int>       : Media type. Default: 0 (NAND Flash Memory)
 *  lfmtype=<int>      : Flash media type. Default: 0 (SLC)
 *  lnum_ch=<int>      : Number of controller channels. Default: 1
 *  lnum_lun=<int>     : Number of LUNs per channel, Default:1
 *  lnum_pln=<int>     : Number of flash planes per LUN. Supported single (1),
 *  dual (2) and quad (4) plane modes. Defult: 1
 *  lreadl2ptbl=<int>  : Load logical to physical table. 1: yes, 0: no. Default: 1
 *  lbbtable=<file>    : Load bad block table from file destination (Provide path
 *  to file. If no file is provided a bad block table will be generated. Look
 *  at lbbfrequency. Default: Null (no file).
 *  lbbfrequency:<int> : Bad block frequency for generating bad block table. If
 *  no frequency is provided LNVM_DEFAULT_BB_FREQ will be used.
 *  lmetadata=<file>   : Load metadata from file destination
 *  lmetasize=<int>    : LightNVM metadata (OOB) size. Default: 16
 *  lb_err_write       : First ppa to inject write error. Default: 0 (disabled)
 *  ln_err_write       : Number of ppas affected by write error injection
 *  ldebug             : Enable LightNVM debugging. Default: 0 (disabled)
 *  lstrict            : Enable strict checks. Necessary for pblk (disabled)
 *
 * The logical block formats all start at 512 byte blocks and double for the
 * next index. If meta-data is non-zero, half the logical block formats will
 * have 0 meta-data, the remaining will start the block size over at 512, but
 * with the meta-data size set accordingly. Multiple meta-data sizes are not
 * supported.
 *
 * Parameters will be verified against conflicting capabilities and attributes
 * and fail to load if there is a conflict or a configuration the emulated
 * device is unable to handle.
 *
 * Note that when a CMB is requested the NVMe version is set to 1.2,
 * for all other cases it is set to 1.1.
 *
 */

/**
 * Hot-plug support
 *
 * To hot add a new nvme device, startup the qemu monitor. The easiest way is
 * to add '-monitor stdio' option on your startup. At the monitor command line,
 * run:
 *
 * (qemu) drive_add "" if=none,id=<new_drive_id>,file=</path/to/backing/file>
 * (qemu) device_add nvme,drive=<new_drive_id>,serial=<serial>,id=<new_id>[,<optional options>]
 *
 * To hot remove the device, run:
 *
 * (qemu) device_del <id>
 *
 * You must have provided the "id" field for device_del to work. You may query
 * the available devices by running "info pci" from the qemu monitor.
 *
 * To query what disks are available to be used as a backing storage, run "info
 * block". You cannot assign the same block device to more than one storage
 * interface.
 */

/**
 * Controller Memory Buffer: For now, you can only turn it on or off, but can't
 * tune the exact settings.
 */

#include "qemu/osdep.h"
#include "hw/block/block.h"
#include "sysemu/kvm.h"
#include "hw/pci/msix.h"
#include "hw/pci/msi.h"
#include "qemu/error-report.h"

#include "nvme.h"


void femu_nvme_addr_read(FemuCtrl *n, hwaddr addr, void *buf, int size)
{
    if (n->cmbsz && addr >= n->ctrl_mem.addr &&
            addr < (n->ctrl_mem.addr + int128_get64(n->ctrl_mem.size))) {
        memcpy(buf, (void *)&n->cmbuf[addr - n->ctrl_mem.addr], size);
    } else {
        pci_dma_read(&n->parent_obj, addr, buf, size);
    }
}

void femu_nvme_addr_write(FemuCtrl *n, hwaddr addr, void *buf, int size)
{
    if (n->cmbsz && addr >= n->ctrl_mem.addr &&
            addr < (n->ctrl_mem.addr + int128_get64(n->ctrl_mem.size))) {
        memcpy((void *)&n->cmbuf[addr - n->ctrl_mem.addr], buf, size);
        return;
    } else {
        pci_dma_write(&n->parent_obj, addr, buf, size);
    }
}

int nvme_check_sqid(FemuCtrl *n, uint16_t sqid)
{
    return sqid <= n->num_io_queues && n->sq[sqid] != NULL ? 0 : -1;
}

int nvme_check_cqid(FemuCtrl *n, uint16_t cqid)
{
    return cqid <= n->num_io_queues && n->cq[cqid] != NULL ? 0 : -1;
}

void nvme_inc_cq_tail(NvmeCQueue *cq)
{
    cq->tail++;
    if (cq->tail >= cq->size) {
        cq->tail = 0;
        cq->phase = !cq->phase;
    }
}

void nvme_inc_sq_head(NvmeSQueue *sq)
{
    sq->head = (sq->head + 1) % sq->size;
}

void nvme_update_cq_head(NvmeCQueue *cq)
{
    if (cq->db_addr_hva) {
        cq->head = *(uint32_t *)(cq->db_addr_hva);
        return;
    }

    if (cq->db_addr) {
        femu_nvme_addr_read(cq->ctrl, cq->db_addr, &cq->head, sizeof(cq->head));
    }
}

uint8_t nvme_cq_full(NvmeCQueue *cq)
{
    nvme_update_cq_head(cq);

    return (cq->tail + 1) % cq->size == cq->head;
}

uint8_t nvme_sq_empty(NvmeSQueue *sq)
{
    return sq->head == sq->tail;
}

void nvme_isr_notify_legacy(void *opaque)
{
    NvmeCQueue *cq = opaque;
    FemuCtrl *n = cq->ctrl;

    if (cq->irq_enabled) {
        if (msix_enabled(&(n->parent_obj))) {
            msix_notify(&(n->parent_obj), cq->vector);
        } else if (msi_enabled(&(n->parent_obj))) {
            if (!(n->bar.intms & (1 << cq->vector))) {
                msi_notify(&(n->parent_obj), cq->vector);
            }
        } else {
            pci_irq_pulse(&n->parent_obj);
        }
    }
}

void nvme_isr_notify_admin(void *opaque)
{
    return nvme_isr_notify_legacy(opaque);
}

void nvme_isr_notify_io(void *opaque)
{
    NvmeCQueue *cq = opaque;

    /* Coperd: utilize irqfd mechanism */
    if (cq->irq_enabled && cq->virq) {
        event_notifier_set(&cq->guest_notifier);
        return;
    }

    /* Coperd: fall back */
    nvme_isr_notify_legacy(opaque);
}

uint64_t *nvme_setup_discontig(FemuCtrl *n, uint64_t prp_addr,
    uint16_t queue_depth, uint16_t entry_size)
{
    int i;
    uint16_t prps_per_page = n->page_size >> 3;
    uint64_t prp[prps_per_page];
    uint16_t total_prps = DIV_ROUND_UP(queue_depth * entry_size, n->page_size);
    uint64_t *prp_list = g_malloc0(total_prps * sizeof(*prp_list));

    for (i = 0; i < total_prps; i++) {
        if (i % prps_per_page == 0 && i < total_prps - 1) {
            if (!prp_addr || prp_addr & (n->page_size - 1)) {
                g_free(prp_list);
                return NULL;
            }
            femu_nvme_addr_write(n, prp_addr, (uint8_t *)&prp, sizeof(prp));
            prp_addr = le64_to_cpu(prp[prps_per_page - 1]);
        }
        prp_list[i] = le64_to_cpu(prp[i % prps_per_page]);
        if (!prp_list[i] || prp_list[i] & (n->page_size - 1)) {
            g_free(prp_list);
            return NULL;
        }
    }

    return prp_list;
}

hwaddr nvme_discontig(uint64_t *dma_addr, uint16_t page_size,
    uint16_t queue_idx, uint16_t entry_size)
{
    uint16_t entries_per_page = page_size / entry_size;
    uint16_t prp_index = queue_idx / entries_per_page;
    uint16_t index_in_prp = queue_idx % entries_per_page;

    return dma_addr[prp_index] + index_in_prp * entry_size;
}

uint16_t nvme_map_prp(QEMUSGList *qsg, QEMUIOVector *iov,
        uint64_t prp1, uint64_t prp2, uint32_t len, FemuCtrl *n)
{
    hwaddr trans_len = n->page_size - (prp1 % n->page_size);
    trans_len = MIN(len, trans_len);
    int num_prps = (len >> n->page_bits) + 1;
    bool cmb = false;

    if (!prp1) {
        return NVME_INVALID_FIELD | NVME_DNR;
    } else if (n->cmbsz && prp1 >= n->ctrl_mem.addr &&
            prp1 < n->ctrl_mem.addr + int128_get64(n->ctrl_mem.size)) {
        cmb = true;
        qsg->nsg = 0;
        qemu_iovec_init(iov, num_prps);
        qemu_iovec_add(iov, (void *)&n->cmbuf[prp1-n->ctrl_mem.addr], trans_len);
    } else {
        pci_dma_sglist_init(qsg, &n->parent_obj, num_prps);
        qemu_sglist_add(qsg, prp1, trans_len);
    }

    len -= trans_len;
    if (len) {
        if (!prp2) {
            goto unmap;
        }
        if (len > n->page_size) {
            uint64_t prp_list[n->max_prp_ents];
            uint32_t nents, prp_trans;
            int i = 0;

            nents = (len + n->page_size - 1) >> n->page_bits;
            prp_trans = MIN(n->max_prp_ents, nents) * sizeof(uint64_t);
            femu_nvme_addr_read(n, prp2, (void *)prp_list, prp_trans);
            while (len != 0) {
                uint64_t prp_ent = le64_to_cpu(prp_list[i]);

                if (i == n->max_prp_ents - 1 && len > n->page_size) {
                    if (!prp_ent || prp_ent & (n->page_size - 1)) {
                        goto unmap;
                    }

                    i = 0;
                    nents = (len + n->page_size - 1) >> n->page_bits;
                    prp_trans = MIN(n->max_prp_ents, nents) * sizeof(uint64_t);
                    femu_nvme_addr_read(n, prp_ent, (void *)prp_list,
                            prp_trans);
                    prp_ent = le64_to_cpu(prp_list[i]);
                }

                if (!prp_ent || prp_ent & (n->page_size - 1)) {
                    goto unmap;
                }

                trans_len = MIN(len, n->page_size);
                if (!cmb){
                    qemu_sglist_add(qsg, prp_ent, trans_len);
                } else {
                    qemu_iovec_add(iov, (void *)&n->cmbuf[prp_ent - n->ctrl_mem.addr], trans_len);
                }
                len -= trans_len;
                i++;
            }
        } else {
            if (prp2 & (n->page_size - 1)) {
                goto unmap;
            }
            if (!cmb) {
                qemu_sglist_add(qsg, prp2, len);
            } else {
                qemu_iovec_add(iov, (void *)&n->cmbuf[prp2 - n->ctrl_mem.addr], trans_len);
            }
        }
    }

    return NVME_SUCCESS;

unmap:
    if (!cmb) {
        qemu_sglist_destroy(qsg);
    } else {
        qemu_iovec_destroy(iov);
    }

    return NVME_INVALID_FIELD | NVME_DNR;
}

uint16_t nvme_dma_write_prp(FemuCtrl *n, uint8_t *ptr, uint32_t len,
        uint64_t prp1, uint64_t prp2)
{
    QEMUSGList qsg;
    QEMUIOVector iov;
    uint16_t status = NVME_SUCCESS;

    if (nvme_map_prp(&qsg, &iov, prp1, prp2, len, n)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (qsg.nsg > 0) {
        if (dma_buf_write(ptr, len, &qsg)) {
            status = NVME_INVALID_FIELD | NVME_DNR;
        }
        qemu_sglist_destroy(&qsg);
    } else {
        if (qemu_iovec_from_buf(&iov, 0, ptr, len) != len) {
            status = NVME_INVALID_FIELD | NVME_DNR;
        }
        qemu_iovec_destroy(&iov);
    }

    return status;
}

uint16_t nvme_dma_read_prp(FemuCtrl *n, uint8_t *ptr, uint32_t len,
        uint64_t prp1, uint64_t prp2)
{
    QEMUSGList qsg;
    QEMUIOVector iov;
    uint16_t status = NVME_SUCCESS;

    if (nvme_map_prp(&qsg, &iov, prp1, prp2, len, n)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (qsg.nsg > 0) {
        if (dma_buf_read(ptr, len, &qsg)) {
            status = NVME_INVALID_FIELD | NVME_DNR;
        }
        qemu_sglist_destroy(&qsg);
    } else {
        if (qemu_iovec_to_buf(&iov, 0, ptr, len) != len) {
            status = NVME_INVALID_FIELD | NVME_DNR;
        }
        qemu_iovec_destroy(&iov);
    }

    return status;
}

void nvme_set_error_page(FemuCtrl *n, uint16_t sqid, uint16_t cid,
        uint16_t status, uint16_t location, uint64_t lba, uint32_t nsid)
{
    NvmeErrorLog *elp;

    elp = &n->elpes[n->elp_index];
    elp->error_count = n->error_count++;
    elp->sqid = sqid;
    elp->cid = cid;
    elp->status_field = status;
    elp->param_error_location = location;
    elp->lba = lba;
    elp->nsid = nsid;
    n->elp_index = (n->elp_index + 1) % n->elpe;
    ++n->num_errors;
}

uint16_t femu_nvme_rw_check_req(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
        NvmeRequest *req, uint64_t slba, uint64_t elba, uint32_t nlb,
        uint16_t ctrl, uint64_t data_size, uint64_t meta_size)
{
    if (elba > le64_to_cpu(ns->id_ns.nsze)) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_LBA_RANGE,
                offsetof(NvmeRwCmd, nlb), elba, ns->id);
        return NVME_LBA_RANGE | NVME_DNR;
    }
    if (n->id_ctrl.mdts && data_size > n->page_size * (1 << n->id_ctrl.mdts)) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
                offsetof(NvmeRwCmd, nlb), nlb, ns->id);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (meta_size) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
                offsetof(NvmeRwCmd, control), ctrl, ns->id);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if ((ctrl & NVME_RW_PRINFO_PRACT) && !(ns->id_ns.dps & DPS_TYPE_MASK)) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
                offsetof(NvmeRwCmd, control), ctrl, ns->id);
        /* Not contemplated in LightNVM for now */
        if (n->femu_mode == FEMU_WHITEBOX_MODE) {
            return 0;
        }
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (!req->is_write && find_next_bit(ns->uncorrectable, elba, slba) < elba) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_UNRECOVERED_READ,
                offsetof(NvmeRwCmd, slba), elba, ns->id);
        return NVME_UNRECOVERED_READ;
    }

    return 0;
}

uint16_t femu_oc_rw_check_req(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
        NvmeRequest *req, uint64_t *psl, uint32_t nr_pages, uint32_t nlb,
        uint16_t ctrl, uint64_t data_size, uint64_t meta_size)
{
	uint32_t i;
	uint64_t slba = psl[0];
	uint64_t elba = psl[nr_pages-1];

	for (i = 0; i < nr_pages; i++) {
		if (psl[i] > le64_to_cpu(ns->id_ns.nsze)) {
			nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_LBA_RANGE,
                offsetof(NvmeRwCmd, nlb), psl[i], ns->id);
			return NVME_LBA_RANGE | NVME_DNR;
		}
	}
    if (n->id_ctrl.mdts && data_size > n->page_size * (1 << n->id_ctrl.mdts)) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
                offsetof(NvmeRwCmd, nlb), nlb, ns->id);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (meta_size) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
                offsetof(NvmeRwCmd, control), ctrl, ns->id);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if ((ctrl & NVME_RW_PRINFO_PRACT) && !(ns->id_ns.dps & DPS_TYPE_MASK)) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
                offsetof(NvmeRwCmd, control), ctrl, ns->id);
        /* Not contemplated in LightNVM for now */
        if (n->femu_mode == FEMU_WHITEBOX_MODE) {
            return 0;
        }
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (!req->is_write && find_next_bit(ns->uncorrectable, elba, slba) < elba) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_UNRECOVERED_READ,
                offsetof(NvmeRwCmd, slba), elba, ns->id);
        return NVME_UNRECOVERED_READ;
    }

    return 0;
}

int nvme_add_kvm_msi_virq(FemuCtrl *n, NvmeCQueue *cq)
{
    int virq;
    int vector_n;

    if (!msix_enabled(&(n->parent_obj))) {
        error_report("MSIX is mandatory for the device");
        return -1;
    }

    if (event_notifier_init(&cq->guest_notifier, 0)) {
        error_report("Initiated guest notifier failed");
        return -1;
    }
    event_notifier_set_handler(&cq->guest_notifier, NULL);

    vector_n = cq->vector;

    virq = kvm_irqchip_add_msi_route(kvm_state, vector_n, &n->parent_obj);
    if (virq < 0) {
        error_report("Route MSIX vector to KVM failed");
        event_notifier_cleanup(&cq->guest_notifier);
        return -1;
    }
    cq->virq = virq;
    femu_debug("%s,cq[%d]->virq=%d\n", __func__, cq->cqid, virq);

    return 0;
}

void nvme_remove_kvm_msi_virq(NvmeCQueue *cq)
{
    kvm_irqchip_release_virq(kvm_state, cq->virq);
    event_notifier_cleanup(&cq->guest_notifier);
    cq->virq = -1;
}

int nvme_set_guest_notifier(FemuCtrl *n, EventNotifier *notifier, uint32_t qid)
{
    return 0;
}

int nvme_vector_unmask(PCIDevice *dev, unsigned vector, MSIMessage msg)
{
    FemuCtrl *n = container_of(dev, FemuCtrl, parent_obj);
    NvmeCQueue *cq;
    EventNotifier *e;
    uint32_t qid;
    int ret;

    for (qid = 1; qid <= n->num_io_queues; qid++) {
        cq = n->cq[qid];
        if (!cq) {
            continue;
        }

        if (cq->vector == vector) {
            e = &cq->guest_notifier;
            ret = kvm_irqchip_update_msi_route(kvm_state, cq->virq, msg, dev);
            if (ret < 0) {
                error_report("nvme: msi irq update vector %u failed", vector);
                return ret;
            }

            kvm_irqchip_commit_routes(kvm_state);
            ret = kvm_irqchip_add_irqfd_notifier_gsi(kvm_state, e,
                    NULL, cq->virq);
            if (ret < 0) {
                error_report("nvme: msi add irqfd gsi vector %u failed, ret %d",
                        vector, ret);
                return ret;
            }
            return 0;
        }
    }

    return 0;
}

void nvme_vector_mask(PCIDevice *dev, unsigned vector)
{
    FemuCtrl *n = container_of(dev, FemuCtrl, parent_obj);
    NvmeCQueue *cq;
    EventNotifier *e;
    uint32_t qid;
    int ret;

    for (qid = 1; qid <= n->num_io_queues; qid++) {
        cq = n->cq[qid];
        if (!cq) {
            continue;
        }

        if (cq->vector == vector) {
            e = &cq->guest_notifier;
            ret = kvm_irqchip_remove_irqfd_notifier_gsi(kvm_state, e, cq->virq);
            if (ret != 0) {
                error_report("nvme: remove_irqfd_notifier_gsi failed");
            }
            return;
        }
    }
}

void nvme_vector_poll(PCIDevice *dev, unsigned int vector_start,
        unsigned int vector_end)
{
    FemuCtrl *n = container_of(dev, FemuCtrl, parent_obj);
    NvmeCQueue *cq;
    EventNotifier *e;
    uint32_t qid, vector;

    for (qid = 1; qid <= n->num_io_queues; qid++) {
        cq = n->cq[qid];
        if (!cq) {
            continue;
        }

        vector = cq->vector;
        if (vector < vector_end && vector >= vector_start) {
            e = &cq->guest_notifier;
            if (!msix_is_masked(dev, vector)) {
                continue;
            }

            if (event_notifier_test_and_clear(e)) {
                msix_set_pending(dev, vector);
            }
        }
    }
}

uint16_t nvme_create_cq(FemuCtrl *n, NvmeCmd *cmd)
{
    NvmeCQueue *cq;
    NvmeCreateCq *c = (NvmeCreateCq *)cmd;
    uint16_t cqid = le16_to_cpu(c->cqid);
    uint16_t vector = le16_to_cpu(c->irq_vector);
    uint16_t qsize = le16_to_cpu(c->qsize);
    uint16_t qflags = le16_to_cpu(c->cq_flags);
    uint64_t prp1 = le64_to_cpu(c->prp1);
    int ret;

    if (!cqid || (cqid && !nvme_check_cqid(n, cqid))) {
        return NVME_INVALID_CQID | NVME_DNR;
    }
    if (!qsize || qsize > NVME_CAP_MQES(n->bar.cap)) {
        return NVME_MAX_QSIZE_EXCEEDED | NVME_DNR;
    }
    if (!prp1) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (vector > n->num_io_queues) {
        return NVME_INVALID_IRQ_VECTOR | NVME_DNR;
    }
    if (!(NVME_CQ_FLAGS_PC(qflags)) && NVME_CAP_CQR(n->bar.cap)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (n->cq[cqid] != NULL) {
        nvme_free_cq(n->cq[cqid], n);
    }

    cq = g_malloc0(sizeof(*cq));
    assert(cq != NULL);
    if (nvme_init_cq(cq, n, prp1, cqid, vector, qsize + 1,
                NVME_CQ_FLAGS_IEN(qflags), NVME_CQ_FLAGS_PC(qflags))) {
        g_free(cq);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (cq->irq_enabled) {
        ret = nvme_add_kvm_msi_virq(n, cq);
        if (ret < 0) {
            error_report("nvme: add kvm msix virq failed\n");
            return -1;
        }

        ret = nvme_set_guest_notifier(n, &cq->guest_notifier, cq->cqid);
        if (ret < 0) {
            error_report("nvme: set guest notifier failed\n");
            return -1;
        }
    }

    if (cq->irq_enabled && !n->vector_poll_started) {
        n->vector_poll_started = true;
        if (msix_set_vector_notifiers(&n->parent_obj, nvme_vector_unmask,
                    nvme_vector_mask, nvme_vector_poll)) {
            error_report("nvme: msix_set_vector_notifiers failed\n");
            return -1;
        }
    }

    assert(cq->is_active == false);
    cq->is_active = true;

    return NVME_SUCCESS;
}

void nvme_cmb_write(void *opaque, hwaddr addr, uint64_t data, unsigned size)
{
    FemuCtrl *n = (FemuCtrl *)opaque;

    memcpy(&n->cmbuf[addr], &data, size);
}

uint64_t nvme_cmb_read(void *opaque, hwaddr addr, unsigned size)
{
    uint64_t val;
    FemuCtrl *n = (FemuCtrl *)opaque;

    memcpy(&val, &n->cmbuf[addr], size);

    return val;
}

void nvme_update_sq_tail(NvmeSQueue *sq)
{
    if (sq->db_addr_hva) {
        sq->tail = *((uint32_t *)sq->db_addr_hva);
        return;
    }

    if (sq->db_addr) {
        femu_nvme_addr_read(sq->ctrl, sq->db_addr, &sq->tail, sizeof(sq->tail));
    }
}

void nvme_clear_guest_notifier(FemuCtrl *n)
{
    NvmeCQueue *cq;
    uint32_t qid;

    for (qid = 1; qid <= n->num_io_queues; qid++) {
        cq = n->cq[qid];
        if (!cq) {
            break;
        }

        if (cq->irq_enabled) {
            nvme_remove_kvm_msi_virq(cq);
        }
    }

    if (n->vector_poll_started) {
        msix_unset_vector_notifiers(&n->parent_obj);
        n->vector_poll_started = false;
    }
}

uint16_t nvme_set_db_memory(FemuCtrl *n, const NvmeCmd *cmd)
{
    uint64_t dbs_addr = le64_to_cpu(cmd->prp1);
    uint64_t eis_addr = le64_to_cpu(cmd->prp2);
    uint8_t stride = n->db_stride;
    int dbbuf_entry_sz = 1 << (2 + stride);
    AddressSpace *as = pci_get_address_space(&n->parent_obj);
    dma_addr_t dbs_tlen = n->page_size, eis_tlen = n->page_size;
    int i;

    /* Addresses should not be NULL and should be page aligned. */
    if (dbs_addr == 0 || dbs_addr & (n->page_size - 1) ||
            eis_addr == 0 || eis_addr & (n->page_size - 1)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    n->dbs_addr = dbs_addr;
    n->eis_addr = eis_addr;
    n->dbs_addr_hva = (uint64_t)dma_memory_map(as, dbs_addr, &dbs_tlen, 0);
    n->eis_addr_hva = (uint64_t)dma_memory_map(as, eis_addr, &eis_tlen, 0);

    for (i = 1; i <= n->num_io_queues; i++) {
        NvmeSQueue *sq = n->sq[i];
        NvmeCQueue *cq = n->cq[i];

        if (sq) {
            /* Submission queue tail pointer location, 2 * QID * stride. */
            sq->db_addr = dbs_addr + 2 * i * dbbuf_entry_sz;
            sq->db_addr_hva = n->dbs_addr_hva + 2 * i * dbbuf_entry_sz;
            sq->eventidx_addr = eis_addr + 2 * i * dbbuf_entry_sz;
            sq->eventidx_addr_hva = n->eis_addr_hva + 2 * i * dbbuf_entry_sz;
            femu_debug("DBBUF,sq[%d]:db=%" PRIu64 ",ei=%" PRIu64 "\n", i,
                    sq->db_addr, sq->eventidx_addr);
        }
        if (cq) {
            /* Completion queue head pointer location, (2 * QID + 1) * stride. */
            cq->db_addr = dbs_addr + (2 * i + 1) * dbbuf_entry_sz;
            cq->db_addr_hva = n->dbs_addr_hva + (2 * i + 1) * dbbuf_entry_sz;
            cq->eventidx_addr = eis_addr + (2 * i + 1) * dbbuf_entry_sz;
            cq->eventidx_addr_hva = n->eis_addr_hva + (2 * i + 1) * dbbuf_entry_sz;
            femu_debug("DBBUF,cq[%d]:db=%" PRIu64 ",ei=%" PRIu64 "\n", i,
                    cq->db_addr, cq->eventidx_addr);
        }
    }

    assert(n->dataplane_started == false);
    if (!n->poller_on) {
        /* Coperd: make sure this only run once across all controller resets */
        femu_create_nvme_poller(n);
        n->poller_on = true;
    }
    n->dataplane_started = true;
    femu_debug("nvme_set_db_memory returns SUCCESS!\n");

    return NVME_SUCCESS;
}
