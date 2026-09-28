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

/*
 * Pollers and the FTL thread copy guest data without the BQL, and an access
 * served by a device's handlers takes it. A pause holds the BQL while it waits
 * for those threads, so neither side would progress. Only memory the host can
 * reach directly qualifies: ROM refuses writes and a RAM device is served as
 * I/O, so both are refused along with registers, as a master abort would be.
 */
static bool femu_dma_direct(FemuCtrl *n, dma_addr_t addr, dma_addr_t len,
                            bool to_host)
{
    AddressSpace *as = pci_get_address_space(&n->parent_obj);

    if (len && addr > UINT64_MAX - (len - 1)) {
        return false;
    }
    RCU_READ_LOCK_GUARD();
    while (len) {
        hwaddr xlat;
        hwaddr l = len;
        MemoryRegion *mr = address_space_translate(as, addr, &xlat, &l,
                                                   to_host, FEMU_DMA_ATTRS);

        if (!l || !memory_access_is_direct(mr, to_host, FEMU_DMA_ATTRS)) {
            return false;
        }
        addr += l;
        len -= l;
    }
    return true;
}

/* The CMB belongs to this device, so it is copied without dispatch. */
MemTxResult femu_dma_rw(FemuCtrl *n, dma_addr_t addr, void *buf,
                        dma_addr_t len, bool to_host)
{
    if (nvme_addr_is_cmb(n, addr, len)) {
        uint8_t *cmb = &n->cmbuf[addr - n->ctrl_mem.addr];

        memcpy(to_host ? cmb : buf, to_host ? buf : cmb, len);
        return MEMTX_OK;
    }
    if (!femu_dma_direct(n, addr, len, to_host)) {
        return MEMTX_ACCESS_ERROR;
    }
    return pci_dma_rw(&n->parent_obj, addr, buf, len,
                      to_host ? DMA_DIRECTION_FROM_DEVICE :
                                DMA_DIRECTION_TO_DEVICE, FEMU_DMA_ATTRS);
}

MemTxResult femu_dma_set(FemuCtrl *n, dma_addr_t addr, uint8_t c,
                         dma_addr_t len)
{
    if (nvme_addr_is_cmb(n, addr, len)) {
        memset(&n->cmbuf[addr - n->ctrl_mem.addr], c, len);
        return MEMTX_OK;
    }
    if (!femu_dma_direct(n, addr, len, true)) {
        return MEMTX_ACCESS_ERROR;
    }
    return dma_memory_set(pci_get_address_space(&n->parent_obj), addr, c, len,
                          FEMU_DMA_ATTRS);
}

MemTxResult nvme_addr_read(FemuCtrl *n, hwaddr addr, void *buf, int size)
{
    MemTxResult ret = femu_dma_read(n, addr, buf, size);

    if (ret) {
        /* a read the bus refuses returns all ones */
        memset(buf, 0xff, size);
    }
    return ret;
}

void nvme_addr_write(FemuCtrl *n, hwaddr addr, void *buf, int size)
{
    femu_dma_write(n, addr, buf, size);
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

/*
 * A cut waits for the FTL with the BQL held. Pin every RAM span before copying
 * so payload DMA never calls an MMIO handler or changes its mapping mid-copy.
 * The CMB is device-owned memory and can also be copied directly.
 */
static uint16_t nvme_power_dma(FemuCtrl *n, QEMUSGList *qsg, uint8_t *buf,
                                bool to_host)
{
    typedef struct NvmeRamSpan {
        void *ptr;
        hwaddr len;
        bool ram;
    } NvmeRamSpan;
    g_autoptr(GArray) spans = g_array_new(false, false, sizeof(NvmeRamSpan));
    uint16_t status = NVME_DATA_TRAS_ERROR | NVME_DNR;
    size_t off = 0;
    int i;

    for (i = 0; i < qsg->nsg; i++) {
        hwaddr addr = qsg->sg[i].base;
        hwaddr left = qsg->sg[i].len;

        if (left && addr > UINT64_MAX - (left - 1)) {
            goto out;
        }
        while (left) {
            NvmeRamSpan span = { .len = left };

            if (nvme_addr_is_cmb(n, addr, left)) {
                span.ptr = n->cmbuf + addr - n->ctrl_mem.addr;
            } else {
                MemoryRegion *mr;
                hwaddr xlat;

                RCU_READ_LOCK_GUARD();
                mr = address_space_translate(qsg->as, addr, &xlat, &span.len,
                                             to_host, MEMTXATTRS_UNSPECIFIED);
                if (!span.len || !memory_region_is_ram(mr) ||
                    !memory_access_is_direct(mr, true,
                                             MEMTXATTRS_UNSPECIFIED)) {
                    goto out;
                }
                memory_region_ref(mr);
                span.ptr = (uint8_t *)memory_region_get_ram_ptr(mr) + xlat;
                span.ram = true;
            }
            g_array_append_val(spans, span);
            addr += span.len;
            left -= span.len;
        }
    }

    for (i = 0; i < spans->len; i++) {
        NvmeRamSpan *span = &g_array_index(spans, NvmeRamSpan, i);

        if (to_host) {
            memcpy(span->ptr, buf + off, span->len);
        } else {
            memcpy(buf + off, span->ptr, span->len);
        }
        off += span->len;
    }
    status = NVME_SUCCESS;
out:
    for (i = 0; i < spans->len; i++) {
        NvmeRamSpan *span = &g_array_index(spans, NvmeRamSpan, i);

        if (span->ram) {
            /* Release the RAM reference and account for guest-memory writes. */
            address_space_unmap(qsg->as, span->ptr, span->len, to_host,
                             status == NVME_SUCCESS ? span->len : 0);
        }
    }
    return status;
}

/* Indirect lists need the same restriction as the payload they describe. */
static uint16_t nvme_read_list(FemuCtrl *n, hwaddr addr, void *buf, int size)
{
    QEMUSGList qsg;
    uint16_t status;

    if (!n->power_loss) {
        return nvme_addr_read(n, addr, buf, size) ?
               NVME_DATA_TRAS_ERROR | NVME_DNR : NVME_SUCCESS;
    }
    pci_dma_sglist_init(&qsg, &n->parent_obj, 1);
    qemu_sglist_add(&qsg, addr, size);
    status = nvme_power_dma(n, &qsg, buf, false);
    qemu_sglist_destroy(&qsg);
    return status;
}

uint16_t nvme_map_prp(QEMUSGList *qsg, QEMUIOVector *iov, uint64_t prp1,
                      uint64_t prp2, uint32_t len, FemuCtrl *n)
{
    hwaddr trans_len = n->page_size - (prp1 % n->page_size);
    trans_len = MIN(len, trans_len);
    int num_prps = (len >> n->page_bits) + 1;
    uint16_t status = NVME_INVALID_FIELD | NVME_DNR;
    bool cmb = false;

    if (!prp1) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    /* the first entry may start anywhere in its page, but on a dword */
    if (prp1 & 0x3) {
        return NVME_INVALID_PRP_OFFSET | NVME_DNR;
    } else if (!n->power_loss && nvme_addr_is_cmb(n, prp1, 1)) {
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
                status = NVME_INVALID_PRP_OFFSET | NVME_DNR;
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
            if (nvme_read_list(n, prp2, prp_list, prp_trans)) {
                g_free(prp_list);
                status = NVME_DATA_TRAS_ERROR | NVME_DNR;
                goto unmap;
            }
            while (len != 0) {
                uint64_t prp_ent = le64_to_cpu(prp_list[i]);

                if (i == nents - 1 && len > n->page_size) {
                    if (!prp_ent || prp_ent & (n->page_size - 1)) {
                        g_free(prp_list);
                        if (prp_ent) {
                            status = NVME_INVALID_PRP_OFFSET | NVME_DNR;
                        }
                        goto unmap;
                    }

                    i = 0;
                    nents = (len + n->page_size - 1) >> n->page_bits;
                    nents = MIN(n->max_prp_ents, nents);
                    prp_trans = nents * sizeof(uint64_t);
                    if (nvme_read_list(n, prp_ent, prp_list, prp_trans)) {
                        g_free(prp_list);
                        status = NVME_DATA_TRAS_ERROR | NVME_DNR;
                        goto unmap;
                    }
                    prp_ent = le64_to_cpu(prp_list[i]);
                }

                /* every entry after the first starts a page (Figure 110) */
                if (!prp_ent || prp_ent & (n->page_size - 1)) {
                    g_free(prp_list);
                    if (prp_ent) {
                        status = NVME_INVALID_PRP_OFFSET | NVME_DNR;
                    }
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
                status = NVME_INVALID_PRP_OFFSET | NVME_DNR;
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

    return status;
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
            if (nvme_read_list(n, seg_addr, descs, seg_bytes)) {
                g_free(descs);
                status = NVME_DATA_TRAS_ERROR;
                goto inval;
            }
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
static uint16_t dma_copy(FemuCtrl *n, QEMUSGList *qsg, QEMUIOVector *iov,
                         uint8_t *ptr,
                         uint32_t len, bool to_host)
{
    uint16_t status = NVME_SUCCESS;

    if (n->power_loss && qsg->nsg > 0) {
        status = nvme_power_dma(n, qsg, ptr, to_host);
        qemu_sglist_destroy(qsg);
    } else if (qsg->nsg > 0) {
        uint32_t left = len;
        int i;

        for (i = 0; i < qsg->nsg && left; i++) {
            dma_addr_t l = MIN(left, qsg->sg[i].len);

            if (femu_dma_rw(n, qsg->sg[i].base, ptr, l, to_host)) {
                status = NVME_DATA_TRAS_ERROR | NVME_DNR;
                break;
            }
            ptr += l;
            left -= l;
        }
        if (left && status == NVME_SUCCESS) {
            status = NVME_DATA_TRAS_ERROR | NVME_DNR;
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

/*
 * Send @len bytes of @ptr to the host and zeroes after them, up to @xfer, for
 * a report the host may ask for more of than there is. The zeroes come from a
 * fixed page, so a request of gigabytes needs no buffer of its own.
 */
static uint16_t dma_copy_fill(QEMUSGList *qsg, QEMUIOVector *iov,
                              const uint8_t *ptr, uint32_t len, uint32_t xfer)
{
    static const uint8_t zeroes[4096];
    uint16_t status = NVME_SUCCESS;
    uint64_t pos = 0;
    int i;

    if (qsg->nsg == 0) {
        size_t done = qemu_iovec_from_buf(iov, 0, ptr, len);

        done += qemu_iovec_memset(iov, len, 0, xfer - len);
        qemu_iovec_destroy(iov);
        return done == xfer ? NVME_SUCCESS : NVME_INVALID_FIELD | NVME_DNR;
    }

    for (i = 0; i < qsg->nsg && status == NVME_SUCCESS; i++) {
        dma_addr_t addr = qsg->sg[i].base;
        dma_addr_t left = qsg->sg[i].len;

        while (left && status == NVME_SUCCESS) {
            const uint8_t *src = pos < len ? ptr + pos : zeroes;
            dma_addr_t n = pos < len ? MIN(left, len - pos) :
                                       MIN(left, sizeof(zeroes));

            if (dma_memory_write(qsg->as, addr, src, n,
                                 FEMU_DMA_ATTRS) != MEMTX_OK) {
                status = NVME_DATA_TRAS_ERROR | NVME_DNR;
            }
            addr += n;
            left -= n;
            pos += n;
        }
    }
    qemu_sglist_destroy(qsg);

    return status;
}

uint16_t dma_write_prp(FemuCtrl *n, uint8_t *ptr, uint32_t len, uint64_t prp1,
                       uint64_t prp2)
{
    QEMUSGList qsg;
    QEMUIOVector iov;
    uint16_t status = nvme_map_prp(&qsg, &iov, prp1, prp2, len, n);

    if (status) {
        return status;
    }

    return dma_copy(n, &qsg, &iov, ptr, len, false);
}

uint16_t dma_read_prp(FemuCtrl *n, uint8_t *ptr, uint32_t len, uint64_t prp1,
                      uint64_t prp2)
{
    QEMUSGList qsg;
    QEMUIOVector iov;
    uint16_t status = nvme_map_prp(&qsg, &iov, prp1, prp2, len, n);

    if (status) {
        return status;
    }

    return dma_copy(n, &qsg, &iov, ptr, len, true);
}

uint16_t dma_read_prp_fill(FemuCtrl *n, const uint8_t *ptr, uint32_t len,
                           uint32_t xfer, uint64_t prp1, uint64_t prp2)
{
    QEMUSGList qsg;
    QEMUIOVector iov;
    uint16_t status;

    if (!xfer) {
        return NVME_SUCCESS;
    }
    status = nvme_map_prp(&qsg, &iov, prp1, prp2, xfer, n);
    if (status) {
        return status;
    }

    return dma_copy_fill(&qsg, &iov, ptr, MIN(len, xfer), xfer);
}

/*
 * Map the data pointer of an I/O command: a PRP pair, or an SGL descriptor
 * when PSDT says so. SGL support is reported for the whole controller, so
 * every I/O command with a data buffer has to honour it, not only Read and
 * Write.
 */
/*
 * Rebuild @qsg with one entry per @unit bytes. The Open-Channel backends pair
 * each scatter entry with one address, so a page that holds several sectors
 * has to become one entry per sector. An entry that is not a whole number of
 * units cannot be paired this way and the list is left as it is, for the
 * caller's own check to refuse.
 */
void femu_sglist_split(FemuCtrl *n, QEMUSGList *qsg, uint32_t unit)
{
    QEMUSGList split;
    dma_addr_t off;
    int i;

    for (i = 0; i < qsg->nsg; i++) {
        if (qsg->sg[i].len % unit) {
            return;
        }
    }
    if (qsg->nsg == 0 || qsg->nsg == qsg->size / unit) {
        return;
    }

    pci_dma_sglist_init(&split, &n->parent_obj, qsg->size / unit);
    for (i = 0; i < qsg->nsg; i++) {
        for (off = 0; off < qsg->sg[i].len; off += unit) {
            qemu_sglist_add(&split, qsg->sg[i].base + off, unit);
        }
    }
    qemu_sglist_destroy(qsg);
    *qsg = split;
}

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

    return dma_copy(n, &qsg, &iov, ptr, len, false);
}

/* as dma_read_cmd(), then zeroes up to @xfer */
uint16_t dma_read_cmd_fill(FemuCtrl *n, NvmeCmd *cmd, const uint8_t *ptr,
                           uint32_t len, uint32_t xfer)
{
    QEMUSGList qsg;
    QEMUIOVector iov;
    uint16_t status;

    /* an empty SGL maps no iov either, so there is nothing to release */
    if (!xfer) {
        return NVME_SUCCESS;
    }
    status = femu_map_dptr(n, cmd, &qsg, &iov, xfer);
    if (status) {
        return status;
    }

    return dma_copy_fill(&qsg, &iov, ptr, MIN(len, xfer), xfer);
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

    return dma_copy(n, &qsg, &iov, ptr, len, true);
}
