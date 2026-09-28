/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 16-bit protection information, following hw/nvme/dif.c. */
#include "nvme-pi.h"

/* from Linux kernel (crypto/crct10dif_common.c) */
static const uint16_t crc16_t10dif_table[256] = {
    0x0000, 0x8BB7, 0x9CD9, 0x176E, 0xB205, 0x39B2, 0x2EDC, 0xA56B,
    0xEFBD, 0x640A, 0x7364, 0xF8D3, 0x5DB8, 0xD60F, 0xC161, 0x4AD6,
    0x54CD, 0xDF7A, 0xC814, 0x43A3, 0xE6C8, 0x6D7F, 0x7A11, 0xF1A6,
    0xBB70, 0x30C7, 0x27A9, 0xAC1E, 0x0975, 0x82C2, 0x95AC, 0x1E1B,
    0xA99A, 0x222D, 0x3543, 0xBEF4, 0x1B9F, 0x9028, 0x8746, 0x0CF1,
    0x4627, 0xCD90, 0xDAFE, 0x5149, 0xF422, 0x7F95, 0x68FB, 0xE34C,
    0xFD57, 0x76E0, 0x618E, 0xEA39, 0x4F52, 0xC4E5, 0xD38B, 0x583C,
    0x12EA, 0x995D, 0x8E33, 0x0584, 0xA0EF, 0x2B58, 0x3C36, 0xB781,
    0xD883, 0x5334, 0x445A, 0xCFED, 0x6A86, 0xE131, 0xF65F, 0x7DE8,
    0x373E, 0xBC89, 0xABE7, 0x2050, 0x853B, 0x0E8C, 0x19E2, 0x9255,
    0x8C4E, 0x07F9, 0x1097, 0x9B20, 0x3E4B, 0xB5FC, 0xA292, 0x2925,
    0x63F3, 0xE844, 0xFF2A, 0x749D, 0xD1F6, 0x5A41, 0x4D2F, 0xC698,
    0x7119, 0xFAAE, 0xEDC0, 0x6677, 0xC31C, 0x48AB, 0x5FC5, 0xD472,
    0x9EA4, 0x1513, 0x027D, 0x89CA, 0x2CA1, 0xA716, 0xB078, 0x3BCF,
    0x25D4, 0xAE63, 0xB90D, 0x32BA, 0x97D1, 0x1C66, 0x0B08, 0x80BF,
    0xCA69, 0x41DE, 0x56B0, 0xDD07, 0x786C, 0xF3DB, 0xE4B5, 0x6F02,
    0x3AB1, 0xB106, 0xA668, 0x2DDF, 0x88B4, 0x0303, 0x146D, 0x9FDA,
    0xD50C, 0x5EBB, 0x49D5, 0xC262, 0x6709, 0xECBE, 0xFBD0, 0x7067,
    0x6E7C, 0xE5CB, 0xF2A5, 0x7912, 0xDC79, 0x57CE, 0x40A0, 0xCB17,
    0x81C1, 0x0A76, 0x1D18, 0x96AF, 0x33C4, 0xB873, 0xAF1D, 0x24AA,
    0x932B, 0x189C, 0x0FF2, 0x8445, 0x212E, 0xAA99, 0xBDF7, 0x3640,
    0x7C96, 0xF721, 0xE04F, 0x6BF8, 0xCE93, 0x4524, 0x524A, 0xD9FD,
    0xC7E6, 0x4C51, 0x5B3F, 0xD088, 0x75E3, 0xFE54, 0xE93A, 0x628D,
    0x285B, 0xA3EC, 0xB482, 0x3F35, 0x9A5E, 0x11E9, 0x0687, 0x8D30,
    0xE232, 0x6985, 0x7EEB, 0xF55C, 0x5037, 0xDB80, 0xCCEE, 0x4759,
    0x0D8F, 0x8638, 0x9156, 0x1AE1, 0xBF8A, 0x343D, 0x2353, 0xA8E4,
    0xB6FF, 0x3D48, 0x2A26, 0xA191, 0x04FA, 0x8F4D, 0x9823, 0x1394,
    0x5942, 0xD2F5, 0xC59B, 0x4E2C, 0xEB47, 0x60F0, 0x779E, 0xFC29,
    0x4BA8, 0xC01F, 0xD771, 0x5CC6, 0xF9AD, 0x721A, 0x6574, 0xEEC3,
    0xA415, 0x2FA2, 0x38CC, 0xB37B, 0x1610, 0x9DA7, 0x8AC9, 0x017E,
    0x1F65, 0x94D2, 0x83BC, 0x080B, 0xAD60, 0x26D7, 0x31B9, 0xBA0E,
    0xF0D8, 0x7B6F, 0x6C01, 0xE7B6, 0x42DD, 0xC96A, 0xDE04, 0x55B3
};

static uint16_t femu_pi_crc(uint16_t crc, const uint8_t *buf, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        crc = (crc << 8) ^ crc16_t10dif_table[((crc >> 8) ^ buf[i]) & 0xff];
    }
    return crc;
}

uint16_t femu_pi_check_ref(NvmeNamespace *ns, uint16_t control,
                           uint64_t slba, uint32_t ref)
{
    if (femu_pi_type(ns) == DPS_TYPE_1 &&
        (control & NVME_RW_PRINFO_PRCHK_REF) && (uint32_t)slba != ref) {
        return NVME_INVALID_PROT_INFO | NVME_DNR;
    }
    return NVME_SUCCESS;
}

uint16_t femu_pi_check(NvmeNamespace *ns, const uint8_t *data,
                       const uint8_t *meta, uint32_t nlb, uint16_t control,
                       uint64_t slba, uint32_t ref, uint16_t app, uint16_t mask)
{
    uint16_t ms = nvme_ns_ms(ns);
    uint16_t off = femu_pi_offset(ns);
    uint32_t ds = 1U << NVME_ID_NS_LBADS(ns);
    uint8_t type = femu_pi_type(ns);
    uint16_t status = femu_pi_check_ref(ns, control, slba, ref);
    uint32_t i;

    if (status) {
        return status;
    }
    for (i = 0; i < nlb; i++, data += ds, meta += ms) {
        const uint8_t *pi = meta + off;
        uint16_t stored_app = lduw_be_p(pi + 2);
        uint32_t stored_ref = ldl_be_p(pi + 4);
        bool escape = stored_app == 0xffff &&
                      (type != DPS_TYPE_3 || stored_ref == UINT32_MAX);

        if (!escape) {
            if (control & NVME_RW_PRINFO_PRCHK_GUARD) {
                uint16_t crc = femu_pi_crc(0, data, ds);

                crc = femu_pi_crc(crc, meta, off);
                if (lduw_be_p(pi) != crc) {
                    return NVME_E2E_GUARD_ERROR;
                }
            }
            if ((control & NVME_RW_PRINFO_PRCHK_APP) &&
                (stored_app & mask) != (app & mask)) {
                return NVME_E2E_APP_ERROR;
            }
            if (type != DPS_TYPE_3 &&
                (control & NVME_RW_PRINFO_PRCHK_REF) && stored_ref != ref) {
                return NVME_E2E_REF_ERROR;
            }
        }
        if (type != DPS_TYPE_3) {
            ref++;
        }
    }
    return NVME_SUCCESS;
}

/* Read the pair and allocation state under the same lock. */
void femu_pi_snapshot(NvmeNamespace *ns, uint64_t slba, uint32_t nlb,
                       uint8_t *data, uint8_t *meta)
{
    uint16_t ms = nvme_ns_ms(ns);
    uint16_t off = femu_pi_offset(ns);
    uint32_t ds = 1U << NVME_ID_NS_LBADS(ns);
    uint8_t *base = ns->ctrl->mbe->logical_space;
    uint32_t i;

    qemu_mutex_lock(&ns->mdata_lock);
    memcpy(data, base + ns->backend_offset + slba * ds, (size_t)nlb * ds);
    memcpy(meta, ns->mdata + slba * ms, (size_t)nlb * ms);
    for (i = 0; i < nlb; i++) {
        if (!test_bit(slba + i, ns->util)) {
            uint8_t *pi = meta + i * ms + off;
            uint16_t guard = 0xffff;

            if (ns->id_ns.dlfeat & (1 << 4)) {
                guard = femu_pi_crc(0, data + (size_t)i * ds, ds);
                guard = femu_pi_crc(guard, meta + i * ms, off);
            }
            stw_be_p(pi, guard);
            memset(pi + 2, 0xff, 6);
        }
    }
    qemu_mutex_unlock(&ns->mdata_lock);
}

void femu_pi_generate(NvmeNamespace *ns, const uint8_t *data, uint8_t *meta,
                       uint32_t nlb, uint32_t ref, uint16_t app)
{
    uint16_t ms = nvme_ns_ms(ns);
    uint16_t off = femu_pi_offset(ns);
    uint32_t ds = 1U << NVME_ID_NS_LBADS(ns);
    uint8_t type = femu_pi_type(ns);
    uint32_t i;

    for (i = 0; i < nlb; i++, data += ds, meta += ms) {
        uint16_t guard = femu_pi_crc(0, data, ds);

        guard = femu_pi_crc(guard, meta, off);
        stw_be_p(meta + off, guard);
        stw_be_p(meta + off + 2, app);
        stl_be_p(meta + off + 4, ref);
        if (type != DPS_TYPE_3) {
            ref++;
        }
    }
}

/* Only an eight-byte metadata format omits PI from a PRACT transfer. */
uint16_t femu_pi_transfer(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                          uint8_t *data, uint8_t *meta, bool to_host)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)cmd;
    uint32_t nlb = le16_to_cpu(rw->nlb) + 1;
    uint32_t ds = 1U << NVME_ID_NS_LBADS(ns);
    uint16_t ms = nvme_ns_ms(ns);
    bool pract = le16_to_cpu(rw->control) & NVME_RW_PRINFO_PRACT;
    bool extended = NVME_ID_NS_FLBAS_EXTENDED(ns->id_ns.flbas);
    uint64_t mptr = le64_to_cpu(rw->mptr);
    uint64_t len;
    uint16_t status;
    uint32_t i;

    if (pract && ms == 8) {
        ms = 0;
    }
    len = (uint64_t)nlb * (ds + (extended ? ms : 0));
    if (len > UINT32_MAX || nvme_check_mdts(n, len)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (extended && ms) {
        uint32_t unit = ds + ms;
        g_autofree uint8_t *buf = g_malloc(len);

        if (!to_host) {
            status = dma_write_cmd(n, cmd, buf, len);
            if (status) {
                return status;
            }
        }
        for (i = 0; i < nlb; i++) {
            if (to_host) {
                memcpy(buf + (size_t)i * unit, data + (size_t)i * ds, ds);
                memcpy(buf + (size_t)i * unit + ds, meta + i * ms, ms);
            } else {
                memcpy(data + (size_t)i * ds, buf + (size_t)i * unit, ds);
                memcpy(meta + i * ms, buf + (size_t)i * unit + ds, ms);
            }
        }
        return to_host ? dma_read_cmd(n, cmd, buf, len) : NVME_SUCCESS;
    }
    if (ms && (cmd->psdt == NVME_PSDT_SGL_MPTR_SGL || (mptr & 3) ||
               mptr > UINT64_MAX - (uint64_t)nlb * ms)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (!to_host && ms &&
        femu_dma_read(n, mptr, meta, (size_t)nlb * ms)) {
        return NVME_DATA_TRAS_ERROR | NVME_DNR;
    }
    status = to_host ? dma_read_cmd(n, cmd, data, len) :
                       dma_write_cmd(n, cmd, data, len);
    if (!status && to_host && ms &&
        femu_dma_write(n, mptr, meta, (size_t)nlb * ms)) {
        return NVME_DATA_TRAS_ERROR | NVME_DNR;
    }
    return status;
}

uint16_t femu_pi_rw(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                    NvmeRequest *req)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)cmd;
    uint64_t slba = le64_to_cpu(rw->slba);
    uint32_t nlb = le16_to_cpu(rw->nlb) + 1;
    uint16_t control = le16_to_cpu(rw->control);
    uint32_t ref = le32_to_cpu(rw->reftag);
    uint16_t app = le16_to_cpu(rw->apptag);
    uint16_t ms = nvme_ns_ms(ns);
    size_t len = (size_t)nlb << NVME_ID_NS_LBADS(ns);
    g_autofree uint8_t *data = NULL;
    g_autofree uint8_t *meta = NULL;
    uint16_t status;

    if (!req->is_write || !(control & NVME_RW_PRINFO_PRACT)) {
        status = femu_pi_check_ref(ns, control, slba, ref);
        if (status) {
            return status;
        }
    }
    if (len > UINT32_MAX) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    data = g_malloc(len);
    meta = g_malloc0((size_t)nlb * ms);
    if (req->is_write) {
        status = femu_pi_transfer(n, ns, cmd, data, meta, false);
        if (status) {
            return status;
        }
        if (control & NVME_RW_PRINFO_PRACT) {
            femu_pi_generate(ns, data, meta, nlb, ref, app);
        } else {
            status = femu_pi_check(ns, data, meta, nlb, control, slba,
                                   ref, app, le16_to_cpu(rw->appmask));
            if (status) {
                return status;
            }
        }
        qemu_mutex_lock(&ns->mdata_lock);
        memcpy((uint8_t *)n->mbe->logical_space + ns->backend_offset +
               (slba << NVME_ID_NS_LBADS(ns)), data, len);
        memcpy(ns->mdata + slba * ms, meta, (size_t)nlb * ms);
        nvme_mark_written(ns, slba, nlb);
        qemu_mutex_unlock(&ns->mdata_lock);
    } else {
        femu_pi_snapshot(ns, slba, nlb, data, meta);
        status = femu_pi_check(ns, data, meta, nlb, control, slba,
                               ref, app, le16_to_cpu(rw->appmask));
        if (status) {
            return status;
        }
        status = femu_pi_transfer(n, ns, cmd, data, meta, true);
        if (status) {
            return status;
        }
    }
    req->slba = slba;
    req->nlb = nlb;
    req->status = NVME_SUCCESS;
    return NVME_SUCCESS;
}

uint16_t femu_pi_compare(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)cmd;
    uint64_t slba = le64_to_cpu(rw->slba);
    uint32_t nlb = le16_to_cpu(rw->nlb) + 1;
    uint16_t control = le16_to_cpu(rw->control);
    uint32_t ref = le32_to_cpu(rw->reftag);
    uint16_t app = le16_to_cpu(rw->apptag);
    uint16_t mask = le16_to_cpu(rw->appmask);
    uint16_t ms = nvme_ns_ms(ns);
    uint16_t off = femu_pi_offset(ns);
    uint64_t len = (uint64_t)nlb << NVME_ID_NS_LBADS(ns);
    uint64_t xfer = len;
    g_autofree uint8_t *data = NULL;
    g_autofree uint8_t *meta = NULL;
    g_autofree uint8_t *host = NULL;
    g_autofree uint8_t *hmeta = NULL;
    uint16_t status;
    uint32_t i;

    if (control & NVME_RW_PRINFO_PRACT) {
        return NVME_INVALID_PROT_INFO | NVME_DNR;
    }
    if (NVME_ID_NS_FLBAS_EXTENDED(ns->id_ns.flbas)) {
        xfer += (uint64_t)nlb * ms;
    }
    if (xfer > UINT32_MAX || nvme_check_mdts(n, xfer)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (find_next_bit(ns->uncorrectable, slba + nlb, slba) < slba + nlb) {
        return NVME_UNRECOVERED_READ;
    }
    data = g_malloc(len);
    host = g_malloc(len);
    meta = g_malloc((size_t)nlb * ms);
    hmeta = g_malloc((size_t)nlb * ms);
    status = femu_pi_transfer(n, ns, cmd, host, hmeta, false);
    if (status) {
        return status;
    }
    status = femu_pi_check(ns, host, hmeta, nlb, control, slba, ref, app, mask);
    if (status) {
        return status;
    }
    femu_pi_snapshot(ns, slba, nlb, data, meta);
    status = femu_pi_check(ns, data, meta, nlb, control, slba, ref, app, mask);
    if (status) {
        return status;
    }
    if (memcmp(data, host, len)) {
        return NVME_CMP_FAILURE;
    }
    /* Compare only the metadata outside the checked PI tuple. */
    for (i = 0; i < nlb; i++) {
        if (memcmp(meta + i * ms, hmeta + i * ms, off) ||
            memcmp(meta + i * ms + off + 8, hmeta + i * ms + off + 8,
                   ms - off - 8)) {
            return NVME_CMP_FAILURE;
        }
    }
    return NVME_SUCCESS;
}

uint16_t femu_pi_zeroes(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)cmd;
    uint64_t slba = le64_to_cpu(rw->slba);
    uint32_t nlb = le16_to_cpu(rw->nlb) + 1;
    uint16_t control = le16_to_cpu(rw->control);
    uint16_t ms = nvme_ns_ms(ns);
    uint32_t ds = 1U << NVME_ID_NS_LBADS(ns);
    uint8_t *data = (uint8_t *)n->mbe->logical_space + ns->backend_offset +
                    slba * ds;
    uint8_t *meta = ns->mdata + slba * ms;

    if (!(control & NVME_RW_PRINFO_PRACT) &&
        (control & (NVME_RW_PRINFO_PRCHK_GUARD | NVME_RW_PRINFO_PRCHK_APP |
                    NVME_RW_PRINFO_PRCHK_REF))) {
        return NVME_INVALID_PROT_INFO | NVME_DNR;
    }
    if (control & NVME_WZ_DEAC) {
        nvme_deallocate_range(n, ns, slba, nlb);
        return NVME_SUCCESS;
    }
    qemu_mutex_lock(&ns->mdata_lock);
    memset(data, 0, (size_t)nlb * ds);
    memset(meta, 0, (size_t)nlb * ms);
    if (control & NVME_RW_PRINFO_PRACT) {
        femu_pi_generate(ns, data, meta, nlb, le32_to_cpu(rw->reftag),
                         le16_to_cpu(rw->apptag));
    }
    nvme_mark_written(ns, slba, nlb);
    qemu_mutex_unlock(&ns->mdata_lock);
    return NVME_SUCCESS;
}

uint16_t femu_pi_copy_compatible(NvmeNamespace *src, NvmeNamespace *dst,
                                 uint16_t read_control, uint16_t write_control)
{
    bool spi = femu_pi_type(src);
    bool dpi = femu_pi_type(dst);
    uint16_t sms = nvme_ns_ms(src);
    uint16_t dms = nvme_ns_ms(dst);

    if (NVME_ID_NS_LBADS(src) != NVME_ID_NS_LBADS(dst)) {
        return NVME_NS_INCOMPATIBLE | NVME_DNR;
    }
    if (spi && dpi &&
        ((read_control ^ write_control) & NVME_RW_PRINFO_PRACT)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (spi == dpi) {
        if (sms == dms && (!spi || src->id_ns.dps == dst->id_ns.dps)) {
            return NVME_SUCCESS;
        }
    } else if (spi) {
        if (sms == 8 && !dms && (read_control & NVME_RW_PRINFO_PRACT)) {
            return NVME_SUCCESS;
        }
    } else if (!sms && dms == 8 && (write_control & NVME_RW_PRINFO_PRACT)) {
        return NVME_SUCCESS;
    }
    return NVME_NS_INCOMPATIBLE | NVME_DNR;
}
