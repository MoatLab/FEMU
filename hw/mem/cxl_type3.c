/*
 * CXL Type 3 (memory expander) device
 *
 * Copyright(C) 2020 Intel Corporation.
 *
 * This work is licensed under the terms of the GNU GPL, version 2. See the
 * COPYING file in the top-level directory.
 *
 * SPDX-License-Identifier: GPL-v2-only
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/error-report.h"
#include "qapi/qapi-commands-cxl.h"
#include "hw/mem/memory-device.h"
#include "hw/mem/pc-dimm.h"
#include "hw/pci/pci.h"
#include "hw/qdev-properties.h"
#include "qapi/error.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/pmem.h"
#include "qemu/range.h"
#include "qemu/rcu.h"
#include "qemu/guest-random.h"
#include "sysemu/hostmem.h"
#include "sysemu/numa.h"
#include "hw/cxl/cxl.h"
#include "hw/pci/msix.h"

#define DWORD_BYTE 4

/* Default CDAT entries for a memory region */
enum {
    CT3_CDAT_DSMAS,
    CT3_CDAT_DSLBIS0,
    CT3_CDAT_DSLBIS1,
    CT3_CDAT_DSLBIS2,
    CT3_CDAT_DSLBIS3,
    CT3_CDAT_DSEMTS,
    CT3_CDAT_NUM_ENTRIES
};

static void ct3_build_cdat_entries_for_mr(CDATSubHeader **cdat_table,
                                          int dsmad_handle, MemoryRegion *mr,
                                          bool is_pmem, uint64_t dpa_base)
{
    CDATDsmas *dsmas;
    CDATDslbis *dslbis0;
    CDATDslbis *dslbis1;
    CDATDslbis *dslbis2;
    CDATDslbis *dslbis3;
    CDATDsemts *dsemts;

    dsmas = g_malloc(sizeof(*dsmas));
    *dsmas = (CDATDsmas) {
        .header = {
            .type = CDAT_TYPE_DSMAS,
            .length = sizeof(*dsmas),
        },
        .DSMADhandle = dsmad_handle,
        .flags = is_pmem ? CDAT_DSMAS_FLAG_NV : 0,
        .DPA_base = dpa_base,
        .DPA_length = memory_region_size(mr),
    };

    /* For now, no memory side cache, plausiblish numbers */
    dslbis0 = g_malloc(sizeof(*dslbis0));
    *dslbis0 = (CDATDslbis) {
        .header = {
            .type = CDAT_TYPE_DSLBIS,
            .length = sizeof(*dslbis0),
        },
        .handle = dsmad_handle,
        .flags = HMAT_LB_MEM_MEMORY,
        .data_type = HMAT_LB_DATA_READ_LATENCY,
        .entry_base_unit = 10000, /* 10ns base */
        .entry[0] = 15, /* 150ns */
    };

    dslbis1 = g_malloc(sizeof(*dslbis1));
    *dslbis1 = (CDATDslbis) {
        .header = {
            .type = CDAT_TYPE_DSLBIS,
            .length = sizeof(*dslbis1),
        },
        .handle = dsmad_handle,
        .flags = HMAT_LB_MEM_MEMORY,
        .data_type = HMAT_LB_DATA_WRITE_LATENCY,
        .entry_base_unit = 10000,
        .entry[0] = 25, /* 250ns */
    };

    dslbis2 = g_malloc(sizeof(*dslbis2));
    *dslbis2 = (CDATDslbis) {
        .header = {
            .type = CDAT_TYPE_DSLBIS,
            .length = sizeof(*dslbis2),
        },
        .handle = dsmad_handle,
        .flags = HMAT_LB_MEM_MEMORY,
        .data_type = HMAT_LB_DATA_READ_BANDWIDTH,
        .entry_base_unit = 1000, /* GB/s */
        .entry[0] = 16,
    };

    dslbis3 = g_malloc(sizeof(*dslbis3));
    *dslbis3 = (CDATDslbis) {
        .header = {
            .type = CDAT_TYPE_DSLBIS,
            .length = sizeof(*dslbis3),
        },
        .handle = dsmad_handle,
        .flags = HMAT_LB_MEM_MEMORY,
        .data_type = HMAT_LB_DATA_WRITE_BANDWIDTH,
        .entry_base_unit = 1000, /* GB/s */
        .entry[0] = 16,
    };

    dsemts = g_malloc(sizeof(*dsemts));
    *dsemts = (CDATDsemts) {
        .header = {
            .type = CDAT_TYPE_DSEMTS,
            .length = sizeof(*dsemts),
        },
        .DSMAS_handle = dsmad_handle,
        /*
         * NV: Reserved - the non volatile from DSMAS matters
         * V: EFI_MEMORY_SP
         */
        .EFI_memory_type_attr = is_pmem ? 2 : 1,
        .DPA_offset = 0,
        .DPA_length = memory_region_size(mr),
    };

    /* Header always at start of structure */
    cdat_table[CT3_CDAT_DSMAS] = (CDATSubHeader *)dsmas;
    cdat_table[CT3_CDAT_DSLBIS0] = (CDATSubHeader *)dslbis0;
    cdat_table[CT3_CDAT_DSLBIS1] = (CDATSubHeader *)dslbis1;
    cdat_table[CT3_CDAT_DSLBIS2] = (CDATSubHeader *)dslbis2;
    cdat_table[CT3_CDAT_DSLBIS3] = (CDATSubHeader *)dslbis3;
    cdat_table[CT3_CDAT_DSEMTS] = (CDATSubHeader *)dsemts;
}

static int ct3_build_cdat_table(CDATSubHeader ***cdat_table, void *priv)
{
    g_autofree CDATSubHeader **table = NULL;
    CXLType3Dev *ct3d = priv;
    MemoryRegion *volatile_mr = NULL, *nonvolatile_mr = NULL;
    int dsmad_handle = 0;
    int cur_ent = 0;
    int len = 0;

    if (!ct3d->hostpmem && !ct3d->hostvmem) {
        return 0;
    }

    if (ct3d->hostvmem) {
        volatile_mr = host_memory_backend_get_memory(ct3d->hostvmem);
        if (!volatile_mr) {
            return -EINVAL;
        }
        len += CT3_CDAT_NUM_ENTRIES;
    }

    if (ct3d->hostpmem) {
        nonvolatile_mr = host_memory_backend_get_memory(ct3d->hostpmem);
        if (!nonvolatile_mr) {
            return -EINVAL;
        }
        len += CT3_CDAT_NUM_ENTRIES;
    }

    table = g_malloc0(len * sizeof(*table));

    /* Now fill them in */
    if (volatile_mr) {
        ct3_build_cdat_entries_for_mr(table, dsmad_handle++, volatile_mr,
                                      false, 0);
        cur_ent = CT3_CDAT_NUM_ENTRIES;
    }

    if (nonvolatile_mr) {
        uint64_t base = volatile_mr ? memory_region_size(volatile_mr) : 0;
        ct3_build_cdat_entries_for_mr(&(table[cur_ent]), dsmad_handle++,
                                      nonvolatile_mr, true, base);
        cur_ent += CT3_CDAT_NUM_ENTRIES;
    }
    assert(len == cur_ent);

    *cdat_table = g_steal_pointer(&table);

    return len;
}

static void ct3_free_cdat_table(CDATSubHeader **cdat_table, int num, void *priv)
{
    int i;

    for (i = 0; i < num; i++) {
        g_free(cdat_table[i]);
    }
    g_free(cdat_table);
}

static bool cxl_doe_cdat_rsp(DOECap *doe_cap)
{
    CDATObject *cdat = &CXL_TYPE3(doe_cap->pdev)->cxl_cstate.cdat;
    uint16_t ent;
    void *base;
    uint32_t len;
    CDATReq *req = pcie_doe_get_write_mbox_ptr(doe_cap);
    CDATRsp rsp;

    assert(cdat->entry_len);

    /* Discard if request length mismatched */
    if (pcie_doe_get_obj_len(req) <
        DIV_ROUND_UP(sizeof(CDATReq), DWORD_BYTE)) {
        return false;
    }

    ent = req->entry_handle;
    base = cdat->entry[ent].base;
    len = cdat->entry[ent].length;

    rsp = (CDATRsp) {
        .header = {
            .vendor_id = CXL_VENDOR_ID,
            .data_obj_type = CXL_DOE_TABLE_ACCESS,
            .reserved = 0x0,
            .length = DIV_ROUND_UP((sizeof(rsp) + len), DWORD_BYTE),
        },
        .rsp_code = CXL_DOE_TAB_RSP,
        .table_type = CXL_DOE_TAB_TYPE_CDAT,
        .entry_handle = (ent < cdat->entry_len - 1) ?
                        ent + 1 : CXL_DOE_TAB_ENT_MAX,
    };

    memcpy(doe_cap->read_mbox, &rsp, sizeof(rsp));
    memcpy(doe_cap->read_mbox + DIV_ROUND_UP(sizeof(rsp), DWORD_BYTE),
           base, len);

    doe_cap->read_mbox_len += rsp.header.length;

    return true;
}

static uint32_t ct3d_config_read(PCIDevice *pci_dev, uint32_t addr, int size)
{
    CXLType3Dev *ct3d = CXL_TYPE3(pci_dev);
    uint32_t val;

    if (pcie_doe_read_config(&ct3d->doe_cdat, addr, size, &val)) {
        return val;
    }

    return pci_default_read_config(pci_dev, addr, size);
}

static void ct3d_config_write(PCIDevice *pci_dev, uint32_t addr, uint32_t val,
                              int size)
{
    CXLType3Dev *ct3d = CXL_TYPE3(pci_dev);

    pcie_doe_write_config(&ct3d->doe_cdat, addr, val, size);
    pci_default_write_config(pci_dev, addr, val, size);
    pcie_aer_write_config(pci_dev, addr, val, size);
}

/*
 * Null value of all Fs suggested by IEEE RA guidelines for use of
 * EU, OUI and CID
 */
#define UI64_NULL ~(0ULL)

static void build_dvsecs(CXLType3Dev *ct3d)
{
    CXLComponentState *cxl_cstate = &ct3d->cxl_cstate;
    uint8_t *dvsec;
    uint32_t range1_size_hi, range1_size_lo,
             range1_base_hi = 0, range1_base_lo = 0,
             range2_size_hi = 0, range2_size_lo = 0,
             range2_base_hi = 0, range2_base_lo = 0;

    /*
     * Volatile memory is mapped as (0x0)
     * Persistent memory is mapped at (volatile->size)
     */
    if (ct3d->hostvmem) {
        range1_size_hi = ct3d->hostvmem->size >> 32;
        range1_size_lo = (2 << 5) | (2 << 2) | 0x3 |
                         (ct3d->hostvmem->size & 0xF0000000);
        if (ct3d->hostpmem) {
            range2_size_hi = ct3d->hostpmem->size >> 32;
            range2_size_lo = (2 << 5) | (2 << 2) | 0x3 |
                             (ct3d->hostpmem->size & 0xF0000000);
        }
    } else {
        range1_size_hi = ct3d->hostpmem->size >> 32;
        range1_size_lo = (2 << 5) | (2 << 2) | 0x3 |
                         (ct3d->hostpmem->size & 0xF0000000);
    }

    dvsec = (uint8_t *)&(CXLDVSECDevice){
        .cap = 0x1e,
        .ctrl = 0x2,
        .status2 = 0x2,
        .range1_size_hi = range1_size_hi,
        .range1_size_lo = range1_size_lo,
        .range1_base_hi = range1_base_hi,
        .range1_base_lo = range1_base_lo,
        .range2_size_hi = range2_size_hi,
        .range2_size_lo = range2_size_lo,
        .range2_base_hi = range2_base_hi,
        .range2_base_lo = range2_base_lo,
    };
    cxl_component_create_dvsec(cxl_cstate, CXL2_TYPE3_DEVICE,
                               PCIE_CXL_DEVICE_DVSEC_LENGTH,
                               PCIE_CXL_DEVICE_DVSEC,
                               PCIE_CXL31_DEVICE_DVSEC_REVID, dvsec);

    dvsec = (uint8_t *)&(CXLDVSECRegisterLocator){
        .rsvd         = 0,
        .reg0_base_lo = RBI_COMPONENT_REG | CXL_COMPONENT_REG_BAR_IDX,
        .reg0_base_hi = 0,
        .reg1_base_lo = RBI_CXL_DEVICE_REG | CXL_DEVICE_REG_BAR_IDX,
        .reg1_base_hi = 0,
    };
    cxl_component_create_dvsec(cxl_cstate, CXL2_TYPE3_DEVICE,
                               REG_LOC_DVSEC_LENGTH, REG_LOC_DVSEC,
                               REG_LOC_DVSEC_REVID, dvsec);
    dvsec = (uint8_t *)&(CXLDVSECDeviceGPF){
        .phase2_duration = 0x603, /* 3 seconds */
        .phase2_power = 0x33, /* 0x33 miliwatts */
    };
    cxl_component_create_dvsec(cxl_cstate, CXL2_TYPE3_DEVICE,
                               GPF_DEVICE_DVSEC_LENGTH, GPF_DEVICE_DVSEC,
                               GPF_DEVICE_DVSEC_REVID, dvsec);

    dvsec = (uint8_t *)&(CXLDVSECPortFlexBus){
        .cap                     = 0x26, /* 68B, IO, Mem, non-MLD */
        .ctrl                    = 0x02, /* IO always enabled */
        .status                  = 0x26, /* same as capabilities */
        .rcvd_mod_ts_data_phase1 = 0xef, /* WTF? */
    };
    cxl_component_create_dvsec(cxl_cstate, CXL2_TYPE3_DEVICE,
                               PCIE_CXL3_FLEXBUS_PORT_DVSEC_LENGTH,
                               PCIE_FLEXBUS_PORT_DVSEC,
                               PCIE_CXL3_FLEXBUS_PORT_DVSEC_REVID, dvsec);
}

static void hdm_decoder_commit(CXLType3Dev *ct3d, int which)
{
    int hdm_inc = R_CXL_HDM_DECODER1_BASE_LO - R_CXL_HDM_DECODER0_BASE_LO;
    ComponentRegisters *cregs = &ct3d->cxl_cstate.crb;
    uint32_t *cache_mem = cregs->cache_mem_registers;
    uint32_t ctrl;

    ctrl = ldl_le_p(cache_mem + R_CXL_HDM_DECODER0_CTRL + which * hdm_inc);
    /* TODO: Sanity checks that the decoder is possible */
    ctrl = FIELD_DP32(ctrl, CXL_HDM_DECODER0_CTRL, ERR, 0);
    ctrl = FIELD_DP32(ctrl, CXL_HDM_DECODER0_CTRL, COMMITTED, 1);

    stl_le_p(cache_mem + R_CXL_HDM_DECODER0_CTRL + which * hdm_inc, ctrl);
}

static void hdm_decoder_uncommit(CXLType3Dev *ct3d, int which)
{
    int hdm_inc = R_CXL_HDM_DECODER1_BASE_LO - R_CXL_HDM_DECODER0_BASE_LO;
    ComponentRegisters *cregs = &ct3d->cxl_cstate.crb;
    uint32_t *cache_mem = cregs->cache_mem_registers;
    uint32_t ctrl;

    ctrl = ldl_le_p(cache_mem + R_CXL_HDM_DECODER0_CTRL + which * hdm_inc);

    ctrl = FIELD_DP32(ctrl, CXL_HDM_DECODER0_CTRL, ERR, 0);
    ctrl = FIELD_DP32(ctrl, CXL_HDM_DECODER0_CTRL, COMMITTED, 0);

    stl_le_p(cache_mem + R_CXL_HDM_DECODER0_CTRL + which * hdm_inc, ctrl);
}

static int ct3d_qmp_uncor_err_to_cxl(CxlUncorErrorType qmp_err)
{
    switch (qmp_err) {
    case CXL_UNCOR_ERROR_TYPE_CACHE_DATA_PARITY:
        return CXL_RAS_UNC_ERR_CACHE_DATA_PARITY;
    case CXL_UNCOR_ERROR_TYPE_CACHE_ADDRESS_PARITY:
        return CXL_RAS_UNC_ERR_CACHE_ADDRESS_PARITY;
    case CXL_UNCOR_ERROR_TYPE_CACHE_BE_PARITY:
        return CXL_RAS_UNC_ERR_CACHE_BE_PARITY;
    case CXL_UNCOR_ERROR_TYPE_CACHE_DATA_ECC:
        return CXL_RAS_UNC_ERR_CACHE_DATA_ECC;
    case CXL_UNCOR_ERROR_TYPE_MEM_DATA_PARITY:
        return CXL_RAS_UNC_ERR_MEM_DATA_PARITY;
    case CXL_UNCOR_ERROR_TYPE_MEM_ADDRESS_PARITY:
        return CXL_RAS_UNC_ERR_MEM_ADDRESS_PARITY;
    case CXL_UNCOR_ERROR_TYPE_MEM_BE_PARITY:
        return CXL_RAS_UNC_ERR_MEM_BE_PARITY;
    case CXL_UNCOR_ERROR_TYPE_MEM_DATA_ECC:
        return CXL_RAS_UNC_ERR_MEM_DATA_ECC;
    case CXL_UNCOR_ERROR_TYPE_REINIT_THRESHOLD:
        return CXL_RAS_UNC_ERR_REINIT_THRESHOLD;
    case CXL_UNCOR_ERROR_TYPE_RSVD_ENCODING:
        return CXL_RAS_UNC_ERR_RSVD_ENCODING;
    case CXL_UNCOR_ERROR_TYPE_POISON_RECEIVED:
        return CXL_RAS_UNC_ERR_POISON_RECEIVED;
    case CXL_UNCOR_ERROR_TYPE_RECEIVER_OVERFLOW:
        return CXL_RAS_UNC_ERR_RECEIVER_OVERFLOW;
    case CXL_UNCOR_ERROR_TYPE_INTERNAL:
        return CXL_RAS_UNC_ERR_INTERNAL;
    case CXL_UNCOR_ERROR_TYPE_CXL_IDE_TX:
        return CXL_RAS_UNC_ERR_CXL_IDE_TX;
    case CXL_UNCOR_ERROR_TYPE_CXL_IDE_RX:
        return CXL_RAS_UNC_ERR_CXL_IDE_RX;
    default:
        return -EINVAL;
    }
}

static int ct3d_qmp_cor_err_to_cxl(CxlCorErrorType qmp_err)
{
    switch (qmp_err) {
    case CXL_COR_ERROR_TYPE_CACHE_DATA_ECC:
        return CXL_RAS_COR_ERR_CACHE_DATA_ECC;
    case CXL_COR_ERROR_TYPE_MEM_DATA_ECC:
        return CXL_RAS_COR_ERR_MEM_DATA_ECC;
    case CXL_COR_ERROR_TYPE_CRC_THRESHOLD:
        return CXL_RAS_COR_ERR_CRC_THRESHOLD;
    case CXL_COR_ERROR_TYPE_RETRY_THRESHOLD:
        return CXL_RAS_COR_ERR_RETRY_THRESHOLD;
    case CXL_COR_ERROR_TYPE_CACHE_POISON_RECEIVED:
        return CXL_RAS_COR_ERR_CACHE_POISON_RECEIVED;
    case CXL_COR_ERROR_TYPE_MEM_POISON_RECEIVED:
        return CXL_RAS_COR_ERR_MEM_POISON_RECEIVED;
    case CXL_COR_ERROR_TYPE_PHYSICAL:
        return CXL_RAS_COR_ERR_PHYSICAL;
    default:
        return -EINVAL;
    }
}

static void ct3d_reg_write(void *opaque, hwaddr offset, uint64_t value,
                           unsigned size)
{
    CXLComponentState *cxl_cstate = opaque;
    ComponentRegisters *cregs = &cxl_cstate->crb;
    CXLType3Dev *ct3d = container_of(cxl_cstate, CXLType3Dev, cxl_cstate);
    uint32_t *cache_mem = cregs->cache_mem_registers;
    bool should_commit = false;
    bool should_uncommit = false;
    int which_hdm = -1;

    assert(size == 4);
    g_assert(offset < CXL2_COMPONENT_CM_REGION_SIZE);

    switch (offset) {
    case A_CXL_HDM_DECODER0_CTRL:
        should_commit = FIELD_EX32(value, CXL_HDM_DECODER0_CTRL, COMMIT);
        should_uncommit = !should_commit;
        which_hdm = 0;
        break;
    case A_CXL_HDM_DECODER1_CTRL:
        should_commit = FIELD_EX32(value, CXL_HDM_DECODER0_CTRL, COMMIT);
        should_uncommit = !should_commit;
        which_hdm = 1;
        break;
    case A_CXL_HDM_DECODER2_CTRL:
        should_commit = FIELD_EX32(value, CXL_HDM_DECODER0_CTRL, COMMIT);
        should_uncommit = !should_commit;
        which_hdm = 2;
        break;
    case A_CXL_HDM_DECODER3_CTRL:
        should_commit = FIELD_EX32(value, CXL_HDM_DECODER0_CTRL, COMMIT);
        should_uncommit = !should_commit;
        which_hdm = 3;
        break;
    case A_CXL_RAS_UNC_ERR_STATUS:
    {
        uint32_t capctrl = ldl_le_p(cache_mem + R_CXL_RAS_ERR_CAP_CTRL);
        uint32_t fe = FIELD_EX32(capctrl, CXL_RAS_ERR_CAP_CTRL,
                                 FIRST_ERROR_POINTER);
        CXLError *cxl_err;
        uint32_t unc_err;

        /*
         * If single bit written that corresponds to the first error
         * pointer being cleared, update the status and header log.
         */
        if (!QTAILQ_EMPTY(&ct3d->error_list)) {
            if ((1 << fe) ^ value) {
                CXLError *cxl_next;
                /*
                 * Software is using wrong flow for multiple header recording
                 * Following behavior in PCIe r6.0 and assuming multiple
                 * header support. Implementation defined choice to clear all
                 * matching records if more than one bit set - which corresponds
                 * closest to behavior of hardware not capable of multiple
                 * header recording.
                 */
                QTAILQ_FOREACH_SAFE(cxl_err, &ct3d->error_list, node,
                                    cxl_next) {
                    if ((1 << cxl_err->type) & value) {
                        QTAILQ_REMOVE(&ct3d->error_list, cxl_err, node);
                        g_free(cxl_err);
                    }
                }
            } else {
                /* Done with previous FE, so drop from list */
                cxl_err = QTAILQ_FIRST(&ct3d->error_list);
                QTAILQ_REMOVE(&ct3d->error_list, cxl_err, node);
                g_free(cxl_err);
            }

            /*
             * If there is another FE, then put that in place and update
             * the header log
             */
            if (!QTAILQ_EMPTY(&ct3d->error_list)) {
                uint32_t *header_log = &cache_mem[R_CXL_RAS_ERR_HEADER0];
                int i;

                cxl_err = QTAILQ_FIRST(&ct3d->error_list);
                for (i = 0; i < CXL_RAS_ERR_HEADER_NUM; i++) {
                    stl_le_p(header_log + i, cxl_err->header[i]);
                }
                capctrl = FIELD_DP32(capctrl, CXL_RAS_ERR_CAP_CTRL,
                                     FIRST_ERROR_POINTER, cxl_err->type);
            } else {
                /*
                 * If no more errors, then follow recommendation of PCI spec
                 * r6.0 6.2.4.2 to set the first error pointer to a status
                 * bit that will never be used.
                 */
                capctrl = FIELD_DP32(capctrl, CXL_RAS_ERR_CAP_CTRL,
                                     FIRST_ERROR_POINTER,
                                     CXL_RAS_UNC_ERR_CXL_UNUSED);
            }
            stl_le_p((uint8_t *)cache_mem + A_CXL_RAS_ERR_CAP_CTRL, capctrl);
        }
        unc_err = 0;
        QTAILQ_FOREACH(cxl_err, &ct3d->error_list, node) {
            unc_err |= 1 << cxl_err->type;
        }
        stl_le_p((uint8_t *)cache_mem + offset, unc_err);

        return;
    }
    case A_CXL_RAS_COR_ERR_STATUS:
    {
        uint32_t rw1c = value;
        uint32_t temp = ldl_le_p((uint8_t *)cache_mem + offset);
        temp &= ~rw1c;
        stl_le_p((uint8_t *)cache_mem + offset, temp);
        return;
    }
    default:
        break;
    }

    stl_le_p((uint8_t *)cache_mem + offset, value);
    if (should_commit) {
        hdm_decoder_commit(ct3d, which_hdm);
    } else if (should_uncommit) {
        hdm_decoder_uncommit(ct3d, which_hdm);
    }
}

static bool cxl_setup_memory(CXLType3Dev *ct3d, Error **errp)
{
    DeviceState *ds = DEVICE(ct3d);

    if (!ct3d->hostmem && !ct3d->hostvmem && !ct3d->hostpmem) {
        error_setg(errp, "at least one memdev property must be set");
        return false;
    } else if (ct3d->hostmem && ct3d->hostpmem) {
        error_setg(errp, "[memdev] cannot be used with new "
                         "[persistent-memdev] property");
        return false;
    } else if (ct3d->hostmem) {
        /* Use of hostmem property implies pmem */
        ct3d->hostpmem = ct3d->hostmem;
        ct3d->hostmem = NULL;
    }

    if (ct3d->hostpmem && !ct3d->lsa) {
        error_setg(errp, "lsa property must be set for persistent devices");
        return false;
    }

    if (ct3d->hostvmem) {
        MemoryRegion *vmr;
        char *v_name;

        vmr = host_memory_backend_get_memory(ct3d->hostvmem);
        if (!vmr) {
            error_setg(errp, "volatile memdev must have backing device");
            return false;
        }
        memory_region_set_nonvolatile(vmr, false);
        memory_region_set_enabled(vmr, true);
        host_memory_backend_set_mapped(ct3d->hostvmem, true);
        if (ds->id) {
            v_name = g_strdup_printf("cxl-type3-dpa-vmem-space:%s", ds->id);
        } else {
            v_name = g_strdup("cxl-type3-dpa-vmem-space");
        }
        address_space_init(&ct3d->hostvmem_as, vmr, v_name);
        ct3d->cxl_dstate.vmem_size = memory_region_size(vmr);
        ct3d->cxl_dstate.mem_size += memory_region_size(vmr);
        g_free(v_name);
    }

    if (ct3d->hostpmem) {
        MemoryRegion *pmr;
        char *p_name;

        pmr = host_memory_backend_get_memory(ct3d->hostpmem);
        if (!pmr) {
            error_setg(errp, "persistent memdev must have backing device");
            return false;
        }
        memory_region_set_nonvolatile(pmr, true);
        memory_region_set_enabled(pmr, true);
        host_memory_backend_set_mapped(ct3d->hostpmem, true);
        if (ds->id) {
            p_name = g_strdup_printf("cxl-type3-dpa-pmem-space:%s", ds->id);
        } else {
            p_name = g_strdup("cxl-type3-dpa-pmem-space");
        }
        address_space_init(&ct3d->hostpmem_as, pmr, p_name);
        ct3d->cxl_dstate.pmem_size = memory_region_size(pmr);
        ct3d->cxl_dstate.mem_size += memory_region_size(pmr);
        g_free(p_name);
    }

    return true;
}

static DOEProtocol doe_cdat_prot[] = {
    { CXL_VENDOR_ID, CXL_DOE_TABLE_ACCESS, cxl_doe_cdat_rsp },
    { }
};

static void ct3_realize(PCIDevice *pci_dev, Error **errp)
{
    ERRP_GUARD();
    CXLType3Dev *ct3d = CXL_TYPE3(pci_dev);
    CXLComponentState *cxl_cstate = &ct3d->cxl_cstate;
    ComponentRegisters *regs = &cxl_cstate->crb;
    MemoryRegion *mr = &regs->component_registers;
    uint8_t *pci_conf = pci_dev->config;
    unsigned short msix_num = 6;
    int i, rc;

    QTAILQ_INIT(&ct3d->error_list);

    if (!cxl_setup_memory(ct3d, errp)) {
        return;
    }

    pci_config_set_prog_interface(pci_conf, 0x10);

    pcie_endpoint_cap_init(pci_dev, 0x80);
    if (ct3d->sn != UI64_NULL) {
        pcie_dev_ser_num_init(pci_dev, 0x100, ct3d->sn);
        cxl_cstate->dvsec_offset = 0x100 + 0x0c;
    } else {
        cxl_cstate->dvsec_offset = 0x100;
    }

    ct3d->cxl_cstate.pdev = pci_dev;
    build_dvsecs(ct3d);

    regs->special_ops = g_new0(MemoryRegionOps, 1);
    regs->special_ops->write = ct3d_reg_write;

    cxl_component_register_block_init(OBJECT(pci_dev), cxl_cstate,
                                      TYPE_CXL_TYPE3);

    pci_register_bar(
        pci_dev, CXL_COMPONENT_REG_BAR_IDX,
        PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64, mr);

    cxl_device_register_block_init(OBJECT(pci_dev), &ct3d->cxl_dstate,
                                   &ct3d->cci);
    pci_register_bar(pci_dev, CXL_DEVICE_REG_BAR_IDX,
                     PCI_BASE_ADDRESS_SPACE_MEMORY |
                         PCI_BASE_ADDRESS_MEM_TYPE_64,
                     &ct3d->cxl_dstate.device_registers);

    /* MSI(-X) Initialization */
    rc = msix_init_exclusive_bar(pci_dev, msix_num, 4, NULL);
    if (rc) {
        goto err_address_space_free;
    }
    for (i = 0; i < msix_num; i++) {
        msix_vector_use(pci_dev, i);
    }

    /* DOE Initialization */
    pcie_doe_init(pci_dev, &ct3d->doe_cdat, 0x190, doe_cdat_prot, true, 0);

    cxl_cstate->cdat.build_cdat_table = ct3_build_cdat_table;
    cxl_cstate->cdat.free_cdat_table = ct3_free_cdat_table;
    cxl_cstate->cdat.private = ct3d;
    cxl_doe_cdat_init(cxl_cstate, errp);
    if (*errp) {
        goto err_free_special_ops;
    }

    pcie_cap_deverr_init(pci_dev);
    /* Leave a bit of room for expansion */
    rc = pcie_aer_init(pci_dev, PCI_ERR_VER, 0x200, PCI_ERR_SIZEOF, NULL);
    if (rc) {
        goto err_release_cdat;
    }
    cxl_event_init(&ct3d->cxl_dstate, 2);

    return;

err_release_cdat:
    cxl_doe_cdat_release(cxl_cstate);
err_free_special_ops:
    g_free(regs->special_ops);
err_address_space_free:
    if (ct3d->hostpmem) {
        address_space_destroy(&ct3d->hostpmem_as);
    }
    if (ct3d->hostvmem) {
        address_space_destroy(&ct3d->hostvmem_as);
    }
    return;
}

static void ct3_exit(PCIDevice *pci_dev)
{
    CXLType3Dev *ct3d = CXL_TYPE3(pci_dev);
    CXLComponentState *cxl_cstate = &ct3d->cxl_cstate;
    ComponentRegisters *regs = &cxl_cstate->crb;

    pcie_aer_exit(pci_dev);
    cxl_doe_cdat_release(cxl_cstate);
    g_free(regs->special_ops);
    if (ct3d->hostpmem) {
        address_space_destroy(&ct3d->hostpmem_as);
    }
    if (ct3d->hostvmem) {
        address_space_destroy(&ct3d->hostvmem_as);
    }
}

static bool cxl_type3_dpa(CXLType3Dev *ct3d, hwaddr host_addr, uint64_t *dpa)
{
    int hdm_inc = R_CXL_HDM_DECODER1_BASE_LO - R_CXL_HDM_DECODER0_BASE_LO;
    uint32_t *cache_mem = ct3d->cxl_cstate.crb.cache_mem_registers;
    unsigned int hdm_count;
    uint32_t cap;
    uint64_t dpa_base = 0;
    int i;

    cap = ldl_le_p(cache_mem + R_CXL_HDM_DECODER_CAPABILITY);
    hdm_count = cxl_decoder_count_dec(FIELD_EX32(cap,
                                                 CXL_HDM_DECODER_CAPABILITY,
                                                 DECODER_COUNT));

    for (i = 0; i < hdm_count; i++) {
        uint64_t decoder_base, decoder_size, hpa_offset, skip;
        uint32_t hdm_ctrl, low, high;
        int ig, iw;

        low = ldl_le_p(cache_mem + R_CXL_HDM_DECODER0_BASE_LO + i * hdm_inc);
        high = ldl_le_p(cache_mem + R_CXL_HDM_DECODER0_BASE_HI + i * hdm_inc);
        decoder_base = ((uint64_t)high << 32) | (low & 0xf0000000);

        low = ldl_le_p(cache_mem + R_CXL_HDM_DECODER0_SIZE_LO + i * hdm_inc);
        high = ldl_le_p(cache_mem + R_CXL_HDM_DECODER0_SIZE_HI + i * hdm_inc);
        decoder_size = ((uint64_t)high << 32) | (low & 0xf0000000);

        low = ldl_le_p(cache_mem + R_CXL_HDM_DECODER0_DPA_SKIP_LO +
                       i * hdm_inc);
        high = ldl_le_p(cache_mem + R_CXL_HDM_DECODER0_DPA_SKIP_HI +
                        i * hdm_inc);
        skip = ((uint64_t)high << 32) | (low & 0xf0000000);
        dpa_base += skip;

        hpa_offset = (uint64_t)host_addr - decoder_base;

        hdm_ctrl = ldl_le_p(cache_mem + R_CXL_HDM_DECODER0_CTRL + i * hdm_inc);
        iw = FIELD_EX32(hdm_ctrl, CXL_HDM_DECODER0_CTRL, IW);
        ig = FIELD_EX32(hdm_ctrl, CXL_HDM_DECODER0_CTRL, IG);
        if (!FIELD_EX32(hdm_ctrl, CXL_HDM_DECODER0_CTRL, COMMITTED)) {
            return false;
        }
        if (((uint64_t)host_addr < decoder_base) ||
            (hpa_offset >= decoder_size)) {
            int decoded_iw = cxl_interleave_ways_dec(iw, &error_fatal);

            if (decoded_iw == 0) {
                return false;
            }

            dpa_base += decoder_size / decoded_iw;
            continue;
        }

        *dpa = dpa_base +
            ((MAKE_64BIT_MASK(0, 8 + ig) & hpa_offset) |
             ((MAKE_64BIT_MASK(8 + ig + iw, 64 - 8 - ig - iw) & hpa_offset)
              >> iw));

        return true;
    }
    return false;
}

static int cxl_type3_hpa_to_as_and_dpa(CXLType3Dev *ct3d,
                                       hwaddr host_addr,
                                       unsigned int size,
                                       AddressSpace **as,
                                       uint64_t *dpa_offset)
{
    MemoryRegion *vmr = NULL, *pmr = NULL;

    if (ct3d->hostvmem) {
        vmr = host_memory_backend_get_memory(ct3d->hostvmem);
    }
    if (ct3d->hostpmem) {
        pmr = host_memory_backend_get_memory(ct3d->hostpmem);
    }

    if (!vmr && !pmr) {
        return -ENODEV;
    }

    if (!cxl_type3_dpa(ct3d, host_addr, dpa_offset)) {
        return -EINVAL;
    }

    if (*dpa_offset > ct3d->cxl_dstate.mem_size) {
        return -EINVAL;
    }

    if (vmr) {
        if (*dpa_offset < memory_region_size(vmr)) {
            *as = &ct3d->hostvmem_as;
        } else {
            *as = &ct3d->hostpmem_as;
            *dpa_offset -= memory_region_size(vmr);
        }
    } else {
        *as = &ct3d->hostpmem_as;
    }

    return 0;
}

MemTxResult cxl_type3_read(PCIDevice *d, hwaddr host_addr, uint64_t *data,
                           unsigned size, MemTxAttrs attrs)
{
    CXLType3Dev *ct3d = CXL_TYPE3(d);
    uint64_t dpa_offset = 0;
    AddressSpace *as = NULL;
    int res;

    res = cxl_type3_hpa_to_as_and_dpa(ct3d, host_addr, size,
                                      &as, &dpa_offset);
    if (res) {
        return MEMTX_ERROR;
    }

    if (sanitize_running(&ct3d->cci)) {
        qemu_guest_getrandom_nofail(data, size);
        return MEMTX_OK;
    }

    return address_space_read(as, dpa_offset, attrs, data, size);
}

MemTxResult cxl_type3_write(PCIDevice *d, hwaddr host_addr, uint64_t data,
                            unsigned size, MemTxAttrs attrs)
{
    CXLType3Dev *ct3d = CXL_TYPE3(d);
    uint64_t dpa_offset = 0;
    AddressSpace *as = NULL;
    int res;

    res = cxl_type3_hpa_to_as_and_dpa(ct3d, host_addr, size,
                                      &as, &dpa_offset);
    if (res) {
        return MEMTX_ERROR;
    }

    if (sanitize_running(&ct3d->cci)) {
        return MEMTX_OK;
    }

    return address_space_write(as, dpa_offset, attrs, &data, size);
}

static void ct3d_reset(DeviceState *dev)
{
    CXLType3Dev *ct3d = CXL_TYPE3(dev);
    uint32_t *reg_state = ct3d->cxl_cstate.crb.cache_mem_registers;
    uint32_t *write_msk = ct3d->cxl_cstate.crb.cache_mem_regs_write_mask;

    cxl_component_register_init_common(reg_state, write_msk, CXL2_TYPE3_DEVICE);
    cxl_device_register_init_t3(ct3d);

    /*
     * Bring up an endpoint to target with MCTP over VDM.
     * This device is emulating an MLD with single LD for now.
     */
    cxl_initialize_t3_fm_owned_ld_mctpcci(&ct3d->vdm_fm_owned_ld_mctp_cci,
                                          DEVICE(ct3d), DEVICE(ct3d),
                                          512); /* Max payload made up */
    cxl_initialize_t3_ld_cci(&ct3d->ld0_cci, DEVICE(ct3d), DEVICE(ct3d),
                             512); /* Max payload made up */

}

static Property ct3_props[] = {
    DEFINE_PROP_LINK("memdev", CXLType3Dev, hostmem, TYPE_MEMORY_BACKEND,
                     HostMemoryBackend *), /* for backward compatibility */
    DEFINE_PROP_LINK("persistent-memdev", CXLType3Dev, hostpmem,
                     TYPE_MEMORY_BACKEND, HostMemoryBackend *),
    DEFINE_PROP_LINK("volatile-memdev", CXLType3Dev, hostvmem,
                     TYPE_MEMORY_BACKEND, HostMemoryBackend *),
    DEFINE_PROP_LINK("lsa", CXLType3Dev, lsa, TYPE_MEMORY_BACKEND,
                     HostMemoryBackend *),
    DEFINE_PROP_UINT64("sn", CXLType3Dev, sn, UI64_NULL),
    DEFINE_PROP_STRING("cdat", CXLType3Dev, cxl_cstate.cdat.filename),
    DEFINE_PROP_END_OF_LIST(),
};

static uint64_t get_lsa_size(CXLType3Dev *ct3d)
{
    MemoryRegion *mr;

    if (!ct3d->lsa) {
        return 0;
    }

    mr = host_memory_backend_get_memory(ct3d->lsa);
    return memory_region_size(mr);
}

static void validate_lsa_access(MemoryRegion *mr, uint64_t size,
                                uint64_t offset)
{
    assert(offset + size <= memory_region_size(mr));
    assert(offset + size > offset);
}

static uint64_t get_lsa(CXLType3Dev *ct3d, void *buf, uint64_t size,
                    uint64_t offset)
{
    MemoryRegion *mr;
    void *lsa;

    if (!ct3d->lsa) {
        return 0;
    }

    mr = host_memory_backend_get_memory(ct3d->lsa);
    validate_lsa_access(mr, size, offset);

    lsa = memory_region_get_ram_ptr(mr) + offset;
    memcpy(buf, lsa, size);

    return size;
}

static void set_lsa(CXLType3Dev *ct3d, const void *buf, uint64_t size,
                    uint64_t offset)
{
    MemoryRegion *mr;
    void *lsa;

    if (!ct3d->lsa) {
        return;
    }

    mr = host_memory_backend_get_memory(ct3d->lsa);
    validate_lsa_access(mr, size, offset);

    lsa = memory_region_get_ram_ptr(mr) + offset;
    memcpy(lsa, buf, size);
    memory_region_set_dirty(mr, offset, size);

    /*
     * Just like the PMEM, if the guest is not allowed to exit gracefully, label
     * updates will get lost.
     */
}

static bool set_cacheline(CXLType3Dev *ct3d, uint64_t dpa_offset, uint8_t *data)
{
    MemoryRegion *vmr = NULL, *pmr = NULL;
    AddressSpace *as;

    if (ct3d->hostvmem) {
        vmr = host_memory_backend_get_memory(ct3d->hostvmem);
    }
    if (ct3d->hostpmem) {
        pmr = host_memory_backend_get_memory(ct3d->hostpmem);
    }

    if (!vmr && !pmr) {
        return false;
    }

    if (dpa_offset + CXL_CACHE_LINE_SIZE > ct3d->cxl_dstate.mem_size) {
        return false;
    }

    if (vmr) {
        if (dpa_offset < memory_region_size(vmr)) {
            as = &ct3d->hostvmem_as;
        } else {
            as = &ct3d->hostpmem_as;
            dpa_offset -= memory_region_size(vmr);
        }
    } else {
        as = &ct3d->hostpmem_as;
    }

    address_space_write(as, dpa_offset, MEMTXATTRS_UNSPECIFIED, &data,
                        CXL_CACHE_LINE_SIZE);
    return true;
}

void cxl_set_poison_list_overflowed(CXLType3Dev *ct3d)
{
        ct3d->poison_list_overflowed = true;
        ct3d->poison_list_overflow_ts =
            cxl_device_get_timestamp(&ct3d->cxl_dstate);
}

void qmp_cxl_inject_poison(const char *path, uint64_t start, uint64_t length,
                           Error **errp)
{
    Object *obj = object_resolve_path(path, NULL);
    CXLType3Dev *ct3d;
    CXLPoison *p;

    if (length % 64) {
        error_setg(errp, "Poison injection must be in multiples of 64 bytes");
        return;
    }
    if (start % 64) {
        error_setg(errp, "Poison start address must be 64 byte aligned");
        return;
    }
    if (!obj) {
        error_setg(errp, "Unable to resolve path");
        return;
    }
    if (!object_dynamic_cast(obj, TYPE_CXL_TYPE3)) {
        error_setg(errp, "Path does not point to a CXL type 3 device");
        return;
    }

    ct3d = CXL_TYPE3(obj);

    QLIST_FOREACH(p, &ct3d->poison_list, node) {
        if (((start >= p->start) && (start < p->start + p->length)) ||
            ((start + length > p->start) &&
             (start + length <= p->start + p->length))) {
            error_setg(errp,
                       "Overlap with existing poisoned region not supported");
            return;
        }
    }

    if (ct3d->poison_list_cnt == CXL_POISON_LIST_LIMIT) {
        cxl_set_poison_list_overflowed(ct3d);
        return;
    }

    p = g_new0(CXLPoison, 1);
    p->length = length;
    p->start = start;
    /* Different from injected via the mbox */
    p->type = CXL_POISON_TYPE_INTERNAL;

    QLIST_INSERT_HEAD(&ct3d->poison_list, p, node);
    ct3d->poison_list_cnt++;
}

/* For uncorrectable errors include support for multiple header recording */
void qmp_cxl_inject_uncorrectable_errors(const char *path,
                                         CXLUncorErrorRecordList *errors,
                                         Error **errp)
{
    Object *obj = object_resolve_path(path, NULL);
    static PCIEAERErr err = {};
    CXLType3Dev *ct3d;
    CXLError *cxl_err;
    uint32_t *reg_state;
    uint32_t unc_err;
    bool first;

    if (!obj) {
        error_setg(errp, "Unable to resolve path");
        return;
    }

    if (!object_dynamic_cast(obj, TYPE_CXL_TYPE3)) {
        error_setg(errp, "Path does not point to a CXL type 3 device");
        return;
    }

    err.status = PCI_ERR_UNC_INTN;
    err.source_id = pci_requester_id(PCI_DEVICE(obj));
    err.flags = 0;

    ct3d = CXL_TYPE3(obj);

    first = QTAILQ_EMPTY(&ct3d->error_list);
    reg_state = ct3d->cxl_cstate.crb.cache_mem_registers;
    while (errors) {
        uint32List *header = errors->value->header;
        uint8_t header_count = 0;
        int cxl_err_code;

        cxl_err_code = ct3d_qmp_uncor_err_to_cxl(errors->value->type);
        if (cxl_err_code < 0) {
            error_setg(errp, "Unknown error code");
            return;
        }

        /* If the error is masked, nothing to do here */
        if (!((1 << cxl_err_code) &
              ~ldl_le_p(reg_state + R_CXL_RAS_UNC_ERR_MASK))) {
            errors = errors->next;
            continue;
        }

        cxl_err = g_malloc0(sizeof(*cxl_err));

        cxl_err->type = cxl_err_code;
        while (header && header_count < 32) {
            cxl_err->header[header_count++] = header->value;
            header = header->next;
        }
        if (header_count > 32) {
            error_setg(errp, "Header must be 32 DWORD or less");
            return;
        }
        QTAILQ_INSERT_TAIL(&ct3d->error_list, cxl_err, node);

        errors = errors->next;
    }

    if (first && !QTAILQ_EMPTY(&ct3d->error_list)) {
        uint32_t *cache_mem = ct3d->cxl_cstate.crb.cache_mem_registers;
        uint32_t capctrl = ldl_le_p(cache_mem + R_CXL_RAS_ERR_CAP_CTRL);
        uint32_t *header_log = &cache_mem[R_CXL_RAS_ERR_HEADER0];
        int i;

        cxl_err = QTAILQ_FIRST(&ct3d->error_list);
        for (i = 0; i < CXL_RAS_ERR_HEADER_NUM; i++) {
            stl_le_p(header_log + i, cxl_err->header[i]);
        }

        capctrl = FIELD_DP32(capctrl, CXL_RAS_ERR_CAP_CTRL,
                             FIRST_ERROR_POINTER, cxl_err->type);
        stl_le_p(cache_mem + R_CXL_RAS_ERR_CAP_CTRL, capctrl);
    }

    unc_err = 0;
    QTAILQ_FOREACH(cxl_err, &ct3d->error_list, node) {
        unc_err |= (1 << cxl_err->type);
    }
    if (!unc_err) {
        return;
    }

    stl_le_p(reg_state + R_CXL_RAS_UNC_ERR_STATUS, unc_err);
    pcie_aer_inject_error(PCI_DEVICE(obj), &err);

    return;
}

void qmp_cxl_inject_correctable_error(const char *path, CxlCorErrorType type,
                                      Error **errp)
{
    static PCIEAERErr err = {};
    Object *obj = object_resolve_path(path, NULL);
    CXLType3Dev *ct3d;
    uint32_t *reg_state;
    uint32_t cor_err;
    int cxl_err_type;

    if (!obj) {
        error_setg(errp, "Unable to resolve path");
        return;
    }
    if (!object_dynamic_cast(obj, TYPE_CXL_TYPE3)) {
        error_setg(errp, "Path does not point to a CXL type 3 device");
        return;
    }

    err.status = PCI_ERR_COR_INTERNAL;
    err.source_id = pci_requester_id(PCI_DEVICE(obj));
    err.flags = PCIE_AER_ERR_IS_CORRECTABLE;

    ct3d = CXL_TYPE3(obj);
    reg_state = ct3d->cxl_cstate.crb.cache_mem_registers;
    cor_err = ldl_le_p(reg_state + R_CXL_RAS_COR_ERR_STATUS);

    cxl_err_type = ct3d_qmp_cor_err_to_cxl(type);
    if (cxl_err_type < 0) {
        error_setg(errp, "Invalid COR error");
        return;
    }
    /* If the error is masked, nothting to do here */
    if (!((1 << cxl_err_type) &
          ~ldl_le_p(reg_state + R_CXL_RAS_COR_ERR_MASK))) {
        return;
    }

    cor_err |= (1 << cxl_err_type);
    stl_le_p(reg_state + R_CXL_RAS_COR_ERR_STATUS, cor_err);

    pcie_aer_inject_error(PCI_DEVICE(obj), &err);
}

static void cxl_assign_event_header(CXLEventRecordHdr *hdr,
                                    const QemuUUID *uuid, uint32_t flags,
                                    uint8_t length, uint64_t timestamp)
{
    st24_le_p(&hdr->flags, flags);
    hdr->length = length;
    memcpy(&hdr->id, uuid, sizeof(hdr->id));
    stq_le_p(&hdr->timestamp, timestamp);
}

static const QemuUUID gen_media_uuid = {
    .data = UUID(0xfbcd0a77, 0xc260, 0x417f,
                 0x85, 0xa9, 0x08, 0x8b, 0x16, 0x21, 0xeb, 0xa6),
};

static const QemuUUID dram_uuid = {
    .data = UUID(0x601dcbb3, 0x9c06, 0x4eab, 0xb8, 0xaf,
                 0x4e, 0x9b, 0xfb, 0x5c, 0x96, 0x24),
};

static const QemuUUID memory_module_uuid = {
    .data = UUID(0xfe927475, 0xdd59, 0x4339, 0xa5, 0x86,
                 0x79, 0xba, 0xb1, 0x13, 0xb7, 0x74),
};

#define CXL_GMER_VALID_CHANNEL                          BIT(0)
#define CXL_GMER_VALID_RANK                             BIT(1)
#define CXL_GMER_VALID_DEVICE                           BIT(2)
#define CXL_GMER_VALID_COMPONENT                        BIT(3)

static int ct3d_qmp_cxl_event_log_enc(CxlEventLog log)
{
    switch (log) {
    case CXL_EVENT_LOG_INFORMATIONAL:
        return CXL_EVENT_TYPE_INFO;
    case CXL_EVENT_LOG_WARNING:
        return CXL_EVENT_TYPE_WARN;
    case CXL_EVENT_LOG_FAILURE:
        return CXL_EVENT_TYPE_FAIL;
    case CXL_EVENT_LOG_FATAL:
        return CXL_EVENT_TYPE_FATAL;
/* DCD not yet supported */
    default:
        return -EINVAL;
    }
}
/* Component ID is device specific.  Define this as a string. */
void qmp_cxl_inject_general_media_event(const char *path, CxlEventLog log,
                                        uint8_t flags, uint64_t dpa,
                                        uint8_t descriptor, uint8_t type,
                                        uint8_t transaction_type,
                                        bool has_channel, uint8_t channel,
                                        bool has_rank, uint8_t rank,
                                        bool has_device, uint32_t device,
                                        const char *component_id,
                                        Error **errp)
{
    Object *obj = object_resolve_path(path, NULL);
    CXLEventGenMedia gem;
    CXLEventRecordHdr *hdr = &gem.hdr;
    CXLDeviceState *cxlds;
    CXLType3Dev *ct3d;
    uint16_t valid_flags = 0;
    uint8_t enc_log;
    int rc;

    if (!obj) {
        error_setg(errp, "Unable to resolve path");
        return;
    }
    if (!object_dynamic_cast(obj, TYPE_CXL_TYPE3)) {
        error_setg(errp, "Path does not point to a CXL type 3 device");
        return;
    }
    ct3d = CXL_TYPE3(obj);
    cxlds = &ct3d->cxl_dstate;

    rc = ct3d_qmp_cxl_event_log_enc(log);
    if (rc < 0) {
        error_setg(errp, "Unhandled error log type");
        return;
    }
    enc_log = rc;

    memset(&gem, 0, sizeof(gem));
    cxl_assign_event_header(hdr, &gen_media_uuid, flags, sizeof(gem),
                            cxl_device_get_timestamp(&ct3d->cxl_dstate));

    stq_le_p(&gem.phys_addr, dpa);
    gem.descriptor = descriptor;
    gem.type = type;
    gem.transaction_type = transaction_type;

    if (has_channel) {
        gem.channel = channel;
        valid_flags |= CXL_GMER_VALID_CHANNEL;
    }

    if (has_rank) {
        gem.rank = rank;
        valid_flags |= CXL_GMER_VALID_RANK;
    }

    if (has_device) {
        st24_le_p(gem.device, device);
        valid_flags |= CXL_GMER_VALID_DEVICE;
    }

    if (component_id) {
        strncpy((char *)gem.component_id, component_id,
                sizeof(gem.component_id) - 1);
        valid_flags |= CXL_GMER_VALID_COMPONENT;
    }

    stw_le_p(&gem.validity_flags, valid_flags);

    if (cxl_event_insert(cxlds, enc_log, (CXLEventRecordRaw *)&gem)) {
        cxl_event_irq_assert(ct3d);
    }
}

#define CXL_DRAM_VALID_CHANNEL                          BIT(0)
#define CXL_DRAM_VALID_RANK                             BIT(1)
#define CXL_DRAM_VALID_NIBBLE_MASK                      BIT(2)
#define CXL_DRAM_VALID_BANK_GROUP                       BIT(3)
#define CXL_DRAM_VALID_BANK                             BIT(4)
#define CXL_DRAM_VALID_ROW                              BIT(5)
#define CXL_DRAM_VALID_COLUMN                           BIT(6)
#define CXL_DRAM_VALID_CORRECTION_MASK                  BIT(7)

void qmp_cxl_inject_dram_event(const char *path, CxlEventLog log, uint8_t flags,
                               uint64_t dpa, uint8_t descriptor,
                               uint8_t type, uint8_t transaction_type,
                               bool has_channel, uint8_t channel,
                               bool has_rank, uint8_t rank,
                               bool has_nibble_mask, uint32_t nibble_mask,
                               bool has_bank_group, uint8_t bank_group,
                               bool has_bank, uint8_t bank,
                               bool has_row, uint32_t row,
                               bool has_column, uint16_t column,
                               bool has_correction_mask,
                               uint64List *correction_mask,
                               Error **errp)
{
    Object *obj = object_resolve_path(path, NULL);
    CXLEventDram dram;
    CXLEventRecordHdr *hdr = &dram.hdr;
    CXLDeviceState *cxlds;
    CXLType3Dev *ct3d;
    uint16_t valid_flags = 0;
    uint8_t enc_log;
    int rc;

    if (!obj) {
        error_setg(errp, "Unable to resolve path");
        return;
    }
    if (!object_dynamic_cast(obj, TYPE_CXL_TYPE3)) {
        error_setg(errp, "Path does not point to a CXL type 3 device");
        return;
    }
    ct3d = CXL_TYPE3(obj);
    cxlds = &ct3d->cxl_dstate;

    rc = ct3d_qmp_cxl_event_log_enc(log);
    if (rc < 0) {
        error_setg(errp, "Unhandled error log type");
        return;
    }
    enc_log = rc;

    memset(&dram, 0, sizeof(dram));
    cxl_assign_event_header(hdr, &dram_uuid, flags, sizeof(dram),
                            cxl_device_get_timestamp(&ct3d->cxl_dstate));
    stq_le_p(&dram.phys_addr, dpa);
    dram.descriptor = descriptor;
    dram.type = type;
    dram.transaction_type = transaction_type;

    if (has_channel) {
        dram.channel = channel;
        valid_flags |= CXL_DRAM_VALID_CHANNEL;
    }

    if (has_rank) {
        dram.rank = rank;
        valid_flags |= CXL_DRAM_VALID_RANK;
    }

    if (has_nibble_mask) {
        st24_le_p(dram.nibble_mask, nibble_mask);
        valid_flags |= CXL_DRAM_VALID_NIBBLE_MASK;
    }

    if (has_bank_group) {
        dram.bank_group = bank_group;
        valid_flags |= CXL_DRAM_VALID_BANK_GROUP;
    }

    if (has_bank) {
        dram.bank = bank;
        valid_flags |= CXL_DRAM_VALID_BANK;
    }

    if (has_row) {
        st24_le_p(dram.row, row);
        valid_flags |= CXL_DRAM_VALID_ROW;
    }

    if (has_column) {
        stw_le_p(&dram.column, column);
        valid_flags |= CXL_DRAM_VALID_COLUMN;
    }

    if (has_correction_mask) {
        int count = 0;
        while (correction_mask && count < 4) {
            stq_le_p(&dram.correction_mask[count],
                     correction_mask->value);
            count++;
            correction_mask = correction_mask->next;
        }
        valid_flags |= CXL_DRAM_VALID_CORRECTION_MASK;
    }

    stw_le_p(&dram.validity_flags, valid_flags);

    if (cxl_event_insert(cxlds, enc_log, (CXLEventRecordRaw *)&dram)) {
        cxl_event_irq_assert(ct3d);
    }
    return;
}

void qmp_cxl_inject_memory_module_event(const char *path, CxlEventLog log,
                                        uint8_t flags, uint8_t type,
                                        uint8_t health_status,
                                        uint8_t media_status,
                                        uint8_t additional_status,
                                        uint8_t life_used,
                                        int16_t temperature,
                                        uint32_t dirty_shutdown_count,
                                        uint32_t corrected_volatile_error_count,
                                        uint32_t corrected_persist_error_count,
                                        Error **errp)
{
    Object *obj = object_resolve_path(path, NULL);
    CXLEventMemoryModule module;
    CXLEventRecordHdr *hdr = &module.hdr;
    CXLDeviceState *cxlds;
    CXLType3Dev *ct3d;
    uint8_t enc_log;
    int rc;

    if (!obj) {
        error_setg(errp, "Unable to resolve path");
        return;
    }
    if (!object_dynamic_cast(obj, TYPE_CXL_TYPE3)) {
        error_setg(errp, "Path does not point to a CXL type 3 device");
        return;
    }
    ct3d = CXL_TYPE3(obj);
    cxlds = &ct3d->cxl_dstate;

    rc = ct3d_qmp_cxl_event_log_enc(log);
    if (rc < 0) {
        error_setg(errp, "Unhandled error log type");
        return;
    }
    enc_log = rc;

    memset(&module, 0, sizeof(module));
    cxl_assign_event_header(hdr, &memory_module_uuid, flags, sizeof(module),
                            cxl_device_get_timestamp(&ct3d->cxl_dstate));

    module.type = type;
    module.health_status = health_status;
    module.media_status = media_status;
    module.additional_status = additional_status;
    module.life_used = life_used;
    stw_le_p(&module.temperature, temperature);
    stl_le_p(&module.dirty_shutdown_count, dirty_shutdown_count);
    stl_le_p(&module.corrected_volatile_error_count,
             corrected_volatile_error_count);
    stl_le_p(&module.corrected_persistent_error_count,
             corrected_persist_error_count);

    if (cxl_event_insert(cxlds, enc_log, (CXLEventRecordRaw *)&module)) {
        cxl_event_irq_assert(ct3d);
    }
}

static void ct3_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(oc);
    CXLType3Class *cvc = CXL_TYPE3_CLASS(oc);

    pc->realize = ct3_realize;
    pc->exit = ct3_exit;
    pc->class_id = PCI_CLASS_MEMORY_CXL;
    pc->vendor_id = PCI_VENDOR_ID_INTEL;
    pc->device_id = 0xd93; /* LVF for now */
    pc->revision = 1;

    pc->config_write = ct3d_config_write;
    pc->config_read = ct3d_config_read;

    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    dc->desc = "CXL Memory Device (Type 3)";
    dc->reset = ct3d_reset;
    device_class_set_props(dc, ct3_props);

    cvc->get_lsa_size = get_lsa_size;
    cvc->get_lsa = get_lsa;
    cvc->set_lsa = set_lsa;
    cvc->set_cacheline = set_cacheline;
}

static const TypeInfo ct3d_info = {
    .name = TYPE_CXL_TYPE3,
    .parent = TYPE_PCI_DEVICE,
    .class_size = sizeof(struct CXLType3Class),
    .class_init = ct3_class_init,
    .instance_size = sizeof(CXLType3Dev),
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_CXL_DEVICE },
        { INTERFACE_PCIE_DEVICE },
        {}
    },
};

static void ct3d_registers(void)
{
    type_register_static(&ct3d_info);
}

type_init(ct3d_registers);
