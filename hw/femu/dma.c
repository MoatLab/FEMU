#include "./nvme.h"

void nvme_addr_read(FemuCtrl *n, hwaddr addr, void *buf, int size)
{
    if (n->cmbsz && addr >= n->ctrl_mem.addr &&
        addr < (n->ctrl_mem.addr + int128_get64(n->ctrl_mem.size)) &&
        (uint64_t)size <= (n->ctrl_mem.addr + int128_get64(n->ctrl_mem.size)) - addr) {
        memcpy(buf, (void *)&n->cmbuf[addr - n->ctrl_mem.addr], size);
    } else {
        pci_dma_read(&n->parent_obj, addr, buf, size);
    }
}

void nvme_addr_write(FemuCtrl *n, hwaddr addr, void *buf, int size)
{
    if (n->cmbsz && addr >= n->ctrl_mem.addr &&
        addr < (n->ctrl_mem.addr + int128_get64(n->ctrl_mem.size)) &&
        (uint64_t)size <= (n->ctrl_mem.addr + int128_get64(n->ctrl_mem.size)) - addr) {
        memcpy((void *)&n->cmbuf[addr - n->ctrl_mem.addr], buf, size);
    } else {
        pci_dma_write(&n->parent_obj, addr, buf, size);
    }
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
            uint64_t *prp_list = g_malloc0(sizeof(uint64_t) * n->max_prp_ents);
            uint32_t nents, prp_trans;
            int i = 0;

            nents = (len + n->page_size - 1) >> n->page_bits;
            prp_trans = MIN(n->max_prp_ents, nents) * sizeof(uint64_t);
            nvme_addr_read(n, prp2, (void *)prp_list, prp_trans);
            while (len != 0) {
                uint64_t prp_ent = le64_to_cpu(prp_list[i]);

                if (i == n->max_prp_ents - 1 && len > n->page_size) {
                    if (!prp_ent || prp_ent & (n->page_size - 1)) {
                        goto unmap;
                    }

                    i = 0;
                    nents = (len + n->page_size - 1) >> n->page_bits;
                    prp_trans = MIN(n->max_prp_ents, nents) * sizeof(uint64_t);
                    nvme_addr_read(n, prp_ent, (void *)prp_list,
                                   prp_trans);
                    prp_ent = le64_to_cpu(prp_list[i]);
                }

                if (!prp_ent || prp_ent & (n->page_size - 1)) {
                    free(prp_list);
                    goto unmap;
                }

                trans_len = MIN(len, n->page_size);
                if (!cmb){
                    qemu_sglist_add(qsg, prp_ent, trans_len);
                } else {
                    uint64_t off = prp_ent - n->ctrl_mem.addr;
                    qemu_iovec_add(iov, (void *)&n->cmbuf[off], trans_len);
                }
                len -= trans_len;
                i++;
            }
            free(prp_list);
        } else {
            if (prp2 & (n->page_size - 1)) {
                goto unmap;
            }
            if (!cmb) {
                qemu_sglist_add(qsg, prp2, len);
            } else {
                uint64_t off = prp2 - n->ctrl_mem.addr;
                qemu_iovec_add(iov, (void *)&n->cmbuf[off], trans_len);
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
 * descriptors in guest memory). Bit-bucket and keyed SGLs are rejected.
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

    /* worst case one descriptor per controller page; grow lazily */
    pci_dma_sglist_init(qsg, &n->parent_obj, (len >> n->page_bits) + 1);
    inited = true;

    while (len) {
        uint8_t type = NVME_SGL_TYPE(sgl.type);

        if (type == NVME_SGL_DESCR_TYPE_DATA_BLOCK) {
            uint32_t dlen = le32_to_cpu(sgl.len);

            if (!dlen || dlen > len) {
                goto inval;
            }
            qemu_sglist_add(qsg, le64_to_cpu(sgl.addr), dlen);
            len -= dlen;
            if (++nsegs > max_descrs) {
                goto inval;
            }
            /* a bare data block must consume the whole transfer */
            if (len) {
                goto inval;
            }
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

            if (!ndesc || ndesc > max_descrs) {
                goto inval;
            }
            descs = g_malloc(seg_bytes);
            nvme_addr_read(n, seg_addr, descs, seg_bytes);
            for (i = 0; i < ndesc && len; i++) {
                uint8_t dt = NVME_SGL_TYPE(descs[i].type);
                uint32_t dl = le32_to_cpu(descs[i].len);

                /* only the final entry of a non-last segment may chain */
                if (dt == NVME_SGL_DESCR_TYPE_DATA_BLOCK) {
                    if (!dl || dl > len) {
                        g_free(descs);
                        goto inval;
                    }
                    qemu_sglist_add(qsg, le64_to_cpu(descs[i].addr), dl);
                    len -= dl;
                    if (++nsegs > max_descrs) {
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
                        g_free(descs);
                        goto inval;
                    }
                    sgl = descs[i];
                    chained = true;
                    break;
                } else {
                    g_free(descs);
                    goto inval;
                }
            }
            g_free(descs);
            if (type == NVME_SGL_DESCR_TYPE_LAST_SEGMENT) {
                break;
            }
            if (!chained) {
                goto inval;   /* a non-last segment must chain from its end */
            }
        } else {
            goto inval; /* bit-bucket, keyed, vendor: unsupported */
        }
    }

    if (len) {
        goto inval; /* under-described transfer */
    }
    (void)iov;
    return NVME_SUCCESS;

inval:
    if (inited) {
        qemu_sglist_destroy(qsg);
    }
    return NVME_INVALID_FIELD | NVME_DNR;
}

uint16_t dma_write_prp(FemuCtrl *n, uint8_t *ptr, uint32_t len, uint64_t prp1,
                       uint64_t prp2)
{
    QEMUSGList qsg;
    QEMUIOVector iov;
    uint16_t status = NVME_SUCCESS;

    if (nvme_map_prp(&qsg, &iov, prp1, prp2, len, n)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (qsg.nsg > 0) {
        if (dma_buf_write(ptr, len, NULL, &qsg, MEMTXATTRS_UNSPECIFIED)) {
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

uint16_t dma_read_prp(FemuCtrl *n, uint8_t *ptr, uint32_t len, uint64_t prp1,
                      uint64_t prp2)
{
    QEMUSGList qsg;
    QEMUIOVector iov;
    uint16_t status = NVME_SUCCESS;

    if (nvme_map_prp(&qsg, &iov, prp1, prp2, len, n)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (qsg.nsg > 0) {
        if (dma_buf_read(ptr, len, NULL, &qsg, MEMTXATTRS_UNSPECIFIED)) {
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