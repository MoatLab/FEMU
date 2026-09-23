#include "./nvme.h"

/*
 * Does this transfer land inside the controller memory buffer? The buffer is a
 * base address register, so it has no address until the host maps it, and an
 * unmapped region reports zero: without the mapped test every guest address
 * below the buffer's size was taken as an offset into it, so a queue or a list
 * the host had put in low memory was read and written from the wrong place and
 * the controller simply stopped answering.
 */
bool nvme_addr_is_cmb(FemuCtrl *n, uint64_t addr, uint64_t len)
{
    uint64_t base, size;

    if (!n->cmbsz || !memory_region_is_mapped(&n->ctrl_mem)) {
        return false;
    }

    base = n->ctrl_mem.addr;
    size = int128_get64(n->ctrl_mem.size);

    return addr >= base && addr - base < size && len <= size - (addr - base);
}

void nvme_addr_read(FemuCtrl *n, hwaddr addr, void *buf, int size)
{
    if (nvme_addr_is_cmb(n, addr, size)) {
        memcpy(buf, (void *)&n->cmbuf[addr - n->ctrl_mem.addr], size);
    } else {
        pci_dma_read(&n->parent_obj, addr, buf, size);
    }
}

void nvme_addr_write(FemuCtrl *n, hwaddr addr, void *buf, int size)
{
    if (nvme_addr_is_cmb(n, addr, size)) {
        memcpy((void *)&n->cmbuf[addr - n->ctrl_mem.addr], buf, size);
    } else {
        pci_dma_write(&n->parent_obj, addr, buf, size);
    }
}

/*
 * Add a stretch of the controller memory buffer to the transfer. The address
 * the host gives is an offset into a buffer this device owns, so both ends
 * have to land inside it: only the start of the first entry was ever checked,
 * and every entry after it was turned into a host pointer with no check at
 * all, which let a host reach memory outside the buffer entirely.
 */
static bool nvme_cmb_iovec_add(FemuCtrl *n, QEMUIOVector *iov, uint64_t addr,
                               uint64_t len)
{
    if (!nvme_addr_is_cmb(n, addr, len)) {
        return false;
    }
    qemu_iovec_add(iov, (void *)&n->cmbuf[addr - n->ctrl_mem.addr], len);

    return true;
}

uint16_t nvme_map_prp(QEMUSGList *qsg, QEMUIOVector *iov, uint64_t prp1,
                      uint64_t prp2, uint32_t len, FemuCtrl *n)
{
    hwaddr trans_len = n->page_size - (prp1 % n->page_size);
    trans_len = MIN(len, trans_len);
    int num_prps = (len >> n->page_bits) + 1;
    bool cmb = false;

    if (!prp1) {
        return NVME_INVALID_FIELD | NVME_DNR;
    } else if (nvme_addr_is_cmb(n, prp1, 1)) {
        cmb = true;
        qsg->nsg = 0;
        qemu_iovec_init(iov, num_prps);
        if (!nvme_cmb_iovec_add(n, iov, prp1, trans_len)) {
            goto unmap;
        }
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
            uint64_t *prp_list = g_malloc0(sizeof(uint64_t) * n->max_prp_ents);
            uint32_t nents, prp_trans;
            int i = 0;

            /* a list pointer addresses whole entries */
            if (prp2 & (sizeof(uint64_t) - 1)) {
                g_free(prp_list);
                goto unmap;
            }

            /*
             * The first list may start part way into its page, and the last
             * entry before the end of that page is what points at the next
             * list (Base 2.3, Figure 110), so the page holds fewer entries
             * than a whole one.
             */
            nents = (n->page_size - (prp2 & (n->page_size - 1))) >> 3;
            prp_trans = nents * sizeof(uint64_t);
            nvme_addr_read(n, prp2, (void *)prp_list, prp_trans);
            while (len != 0) {
                uint64_t prp_ent = le64_to_cpu(prp_list[i]);

                if (i == nents - 1 && len > n->page_size) {
                    if (!prp_ent || prp_ent & (n->page_size - 1)) {
                        g_free(prp_list);
                        goto unmap;
                    }

                    i = 0;
                    nents = (len + n->page_size - 1) >> n->page_bits;
                    nents = MIN(n->max_prp_ents, nents);
                    prp_trans = nents * sizeof(uint64_t);
                    nvme_addr_read(n, prp_ent, (void *)prp_list,
                                   prp_trans);
                    prp_ent = le64_to_cpu(prp_list[i]);
                }

                if (!prp_ent || prp_ent & (n->page_size - 1)) {
                    g_free(prp_list);
                    goto unmap;
                }

                trans_len = MIN(len, n->page_size);
                if (!cmb) {
                    qemu_sglist_add(qsg, prp_ent, trans_len);
                } else if (!nvme_cmb_iovec_add(n, iov, prp_ent, trans_len)) {
                    g_free(prp_list);
                    goto unmap;
                }
                len -= trans_len;
                i++;
            }
            g_free(prp_list);
        } else {
            if (prp2 & (n->page_size - 1)) {
                goto unmap;
            }
            if (!cmb) {
                qemu_sglist_add(qsg, prp2, len);
            } else if (!nvme_cmb_iovec_add(n, iov, prp2, len)) {
                /* the remaining length, not the first entry's */
                goto unmap;
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

/*
 * Map an NVMe SGL into a QEMUSGList, the PRP-path equivalent of nvme_map_prp.
 * Supports address SGLs: DATA_BLOCK descriptors (a direct segment) and
 * SEGMENT / LAST_SEGMENT descriptors (which point at a further array of
 * descriptors in guest memory). Bit-bucket and keyed SGLs are rejected, and
 * so is any subtype but address: the offset one exists only for fabrics.
 * CMB-resident SGLs are not special-cased (rare); the descriptors are read
 * from guest memory via nvme_addr_read. Builds the same qsg the backend_rw
 * path consumes, so no other code path changes.
 */
uint16_t nvme_map_sgl(QEMUSGList *qsg, QEMUIOVector *iov,
                      NvmeSglDescriptor sgl, uint32_t len, FemuCtrl *n)
{
    const int max_descrs = 4096; /* guard against a runaway/looping SGL */
    int nsegs = 0;
    bool inited = false;
    uint16_t status = NVME_SGL_DESCR_TYPE_INVALID;

    /* worst case one descriptor per controller page; grow lazily */
    pci_dma_sglist_init(qsg, &n->parent_obj, (len >> n->page_bits) + 1);
    inited = true;

    while (len) {
        uint8_t type = NVME_SGL_TYPE(sgl.type);

        if (NVME_SGL_SUBTYPE(sgl.type)) {
            status = NVME_SGL_DESCR_TYPE_INVALID;
            goto inval;
        }
        if (type == NVME_SGL_DESCR_TYPE_DATA_BLOCK) {
            uint32_t dlen = le32_to_cpu(sgl.len);

            /* a bare data block must describe the whole transfer */
            if (dlen != len) {
                status = NVME_DATA_SGL_LEN_INVALID;
                goto inval;
            }
            qemu_sglist_add(qsg, le64_to_cpu(sgl.addr), dlen);
            len = 0;
            break;
        } else if (type == NVME_SGL_DESCR_TYPE_SEGMENT ||
                   type == NVME_SGL_DESCR_TYPE_LAST_SEGMENT) {
            /* the descriptor points at an array of descriptors in guest mem */
            uint32_t seg_bytes = le32_to_cpu(sgl.len);
            uint64_t seg_addr = le64_to_cpu(sgl.addr);
            int ndesc = seg_bytes / sizeof(NvmeSglDescriptor);
            NvmeSglDescriptor *descs;
            int i;
            bool chained = false;

            if (!ndesc || seg_bytes % sizeof(NvmeSglDescriptor)) {
                status = NVME_INVALID_SGL_SEG_DESCR;
                goto inval;
            }
            if (ndesc > max_descrs) {
                status = NVME_INVALID_NUM_SGL_DESCRS;
                goto inval;
            }
            descs = g_malloc(seg_bytes);
            nvme_addr_read(n, seg_addr, descs, seg_bytes);
            for (i = 0; i < ndesc && len; i++) {
                uint8_t dt = NVME_SGL_TYPE(descs[i].type);
                uint32_t dl = le32_to_cpu(descs[i].len);

                if (NVME_SGL_SUBTYPE(descs[i].type)) {
                    status = NVME_SGL_DESCR_TYPE_INVALID;
                    g_free(descs);
                    goto inval;
                }
                /* only the final entry of a non-last segment may chain */
                if (dt == NVME_SGL_DESCR_TYPE_DATA_BLOCK) {
                    if (!dl || dl > len) {
                        status = NVME_DATA_SGL_LEN_INVALID;
                        g_free(descs);
                        goto inval;
                    }
                    qemu_sglist_add(qsg, le64_to_cpu(descs[i].addr), dl);
                    len -= dl;
                    if (++nsegs > max_descrs) {
                        status = NVME_INVALID_NUM_SGL_DESCRS;
                        g_free(descs);
                        goto inval;
                    }
                } else if ((dt == NVME_SGL_DESCR_TYPE_SEGMENT ||
                            dt == NVME_SGL_DESCR_TYPE_LAST_SEGMENT) &&
                           i == ndesc - 1) {
                    /* chain: continue the outer loop with this descriptor.
                     * Count the follow so a cyclic segment list cannot spin
                     * the poller forever. */
                    if (++nsegs > max_descrs) {
                        status = NVME_INVALID_NUM_SGL_DESCRS;
                        g_free(descs);
                        goto inval;
                    }
                    sgl = descs[i];
                    chained = true;
                    break;
                } else {
                    /* a segment anywhere but last, or an unsupported type */
                    status = (dt == NVME_SGL_DESCR_TYPE_SEGMENT ||
                              dt == NVME_SGL_DESCR_TYPE_LAST_SEGMENT) ?
                             NVME_INVALID_SGL_SEG_DESCR :
                             NVME_SGL_DESCR_TYPE_INVALID;
                    g_free(descs);
                    goto inval;
                }
            }
            g_free(descs);
            if (type == NVME_SGL_DESCR_TYPE_LAST_SEGMENT) {
                break;
            }
            if (!chained) {
                /* a non-last segment must chain from its end */
                status = NVME_INVALID_SGL_SEG_DESCR;
                goto inval;
            }
        } else {
            status = NVME_SGL_DESCR_TYPE_INVALID; /* bit-bucket, keyed, ... */
            goto inval;
        }
    }

    if (len) {
        status = NVME_DATA_SGL_LEN_INVALID; /* under-described transfer */
        goto inval;
    }
    (void)iov;
    return NVME_SUCCESS;

inval:
    if (inited) {
        qemu_sglist_destroy(qsg);
    }
    return status | NVME_DNR;
}

/* Copy between a buffer and a mapped transfer, then release the mapping. */
static uint16_t dma_copy(QEMUSGList *qsg, QEMUIOVector *iov, uint8_t *ptr,
                         uint32_t len, bool to_host)
{
    uint16_t status = NVME_SUCCESS;

    if (qsg->nsg > 0) {
        uint64_t resid = to_host ?
            dma_buf_read(ptr, len, NULL, qsg, MEMTXATTRS_UNSPECIFIED) :
            dma_buf_write(ptr, len, NULL, qsg, MEMTXATTRS_UNSPECIFIED);

        if (resid) {
            status = NVME_INVALID_FIELD | NVME_DNR;
        }
        qemu_sglist_destroy(qsg);
    } else {
        size_t done = to_host ? qemu_iovec_from_buf(iov, 0, ptr, len) :
                                qemu_iovec_to_buf(iov, 0, ptr, len);

        if (done != len) {
            status = NVME_INVALID_FIELD | NVME_DNR;
        }
        qemu_iovec_destroy(iov);
    }

    return status;
}

uint16_t dma_write_prp(FemuCtrl *n, uint8_t *ptr, uint32_t len, uint64_t prp1,
                       uint64_t prp2)
{
    QEMUSGList qsg;
    QEMUIOVector iov;

    if (nvme_map_prp(&qsg, &iov, prp1, prp2, len, n)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    return dma_copy(&qsg, &iov, ptr, len, false);
}

uint16_t dma_read_prp(FemuCtrl *n, uint8_t *ptr, uint32_t len, uint64_t prp1,
                      uint64_t prp2)
{
    QEMUSGList qsg;
    QEMUIOVector iov;

    if (nvme_map_prp(&qsg, &iov, prp1, prp2, len, n)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    return dma_copy(&qsg, &iov, ptr, len, true);
}

/*
 * Map the data pointer of an I/O command: a PRP pair, or an SGL descriptor
 * when PSDT says so. SGL support is reported for the whole controller, so
 * every I/O command with a data buffer has to honour it, not only Read and
 * Write.
 */
uint16_t femu_map_dptr(FemuCtrl *n, NvmeCmd *cmd, QEMUSGList *qsg,
                       QEMUIOVector *iov, uint32_t len)
{
    if (cmd->psdt == NVME_PSDT_PRP) {
        return nvme_map_prp(qsg, iov, le64_to_cpu(cmd->dptr.prp1),
                            le64_to_cpu(cmd->dptr.prp2), len, n);
    }
    if (!n->sgl || cmd->psdt > NVME_PSDT_SGL_MPTR_SGL) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    return nvme_map_sgl(qsg, iov, cmd->dptr.sgl, len, n);
}

/* host to controller, through an I/O command's data pointer */
uint16_t dma_write_cmd(FemuCtrl *n, NvmeCmd *cmd, uint8_t *ptr, uint32_t len)
{
    QEMUSGList qsg;
    QEMUIOVector iov;
    uint16_t status;

    status = femu_map_dptr(n, cmd, &qsg, &iov, len);
    if (status) {
        return status;
    }

    return dma_copy(&qsg, &iov, ptr, len, false);
}

/* controller to host, through an I/O command's data pointer */
uint16_t dma_read_cmd(FemuCtrl *n, NvmeCmd *cmd, uint8_t *ptr, uint32_t len)
{
    QEMUSGList qsg;
    QEMUIOVector iov;
    uint16_t status;

    status = femu_map_dptr(n, cmd, &qsg, &iov, len);
    if (status) {
        return status;
    }

    return dma_copy(&qsg, &iov, ptr, len, true);
}
