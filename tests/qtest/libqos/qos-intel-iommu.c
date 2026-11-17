/*
 * QOS Intel IOMMU (VT-d) Module Implementation
 *
 * This module provides Intel IOMMU-specific helper functions for libqos tests.
 *
 * Copyright (c) 2026 Fengyuan Yu <15fengyuan@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/i386/intel_iommu_internal.h"
#include "tests/qtest/libqos/pci.h"
#include "tests/qtest/libqos/pci-pc.h"
#include "qos-iommu-testdev.h"
#include "qos-intel-iommu.h"

/* Bounded poll for the invalidation-wait Status Write. */
#define QVTD_INV_WAIT_POLL_MAX_ITERS    1000
#define QVTD_INV_WAIT_POLL_INTERVAL_US  1000

#define QVTD_AW_48BIT_ENCODING    2

uint32_t qvtd_expected_dma_result(QVTDTestContext *ctx)
{
    return ctx->config.expected_result;
}

uint32_t qvtd_build_dma_attrs(void)
{
    /*
     * VT-d obtains the Requester ID (Source ID) from PCI bus/devfn routing
     * via pci_device_iommu_address_space(), not from DMA attributes.
     *
     * For scalable mode, iommu-testdev does not set MemTxAttrs.pid,
     * so the device's VTDAddressSpace has pasid=PCI_NO_PASID.
     * vtd_do_iommu_translate() remaps PCI_NO_PASID to PASID_0
     * when root_scalable is set, which matches the PASID=0 entry
     * we configure in qvtd_build_pasid_table_entry().
     */
    return 0;
}

static void qvtd_build_root_entry(QTestState *qts, uint8_t bus,
                                  uint64_t context_table_ptr,
                                  QVTDTransMode mode)
{
    uint64_t root_entry_addr = QVTD_ROOT_TABLE_BASE +
                               (bus * sizeof(VTDRootEntry));
    uint64_t lo, hi;

    if (qvtd_is_scalable(mode)) {
        /*
         * Scalable-mode Root Entry (Section 9.2):
         * lo = Lower Context Table Pointer + LP (Lower Present)
         * hi = Upper Context Table Pointer + UP (Upper Present)
         *
         * Lower table covers devfn 0-127, Upper covers devfn 128-255.
         * Only lower half is needed for test device (devfn < 128).
         */
        lo = (context_table_ptr & VTD_ROOT_ENTRY_CTP) | VTD_ROOT_ENTRY_P;
        hi = 0;  /* UP=0: upper context table not present */
    } else {
        /*
         * Legacy Root Entry (Section 9.1):
         * lo = Context Table Pointer + Present
         * hi = Reserved
         */
        lo = (context_table_ptr & VTD_ROOT_ENTRY_CTP) | VTD_ROOT_ENTRY_P;
        hi = 0;
    }

    qtest_writeq(qts, root_entry_addr, lo);
    qtest_writeq(qts, root_entry_addr + 8, hi);
}

static void qvtd_build_context_entry(QTestState *qts, uint16_t sid,
                                     QVTDTransMode mode, uint64_t ssptptr)
{
    uint8_t devfn = sid & 0xff;
    uint64_t context_entry_addr = QVTD_CONTEXT_TABLE_BASE +
                                 (devfn * VTD_CTX_ENTRY_LEGACY_SIZE);
    uint64_t lo, hi;

    if (mode == QVTD_TM_LEGACY_PT) {
        /*
         * Pass-through mode (Section 9.3):
         * lo: P + FPD(=0, fault enabled) + TT(=Pass-through)
         * hi: DID + AW
         */
        lo = VTD_CONTEXT_ENTRY_P | VTD_CONTEXT_TT_PASS_THROUGH;
        hi = ((uint64_t)QVTD_DOMAIN_ID << 8) | QVTD_AW_48BIT_ENCODING;
    } else {
        /*
         * Translated mode (Section 9.3):
         * lo: P + FPD(=0, fault enabled) + TT(=Multi-level) + SSPTPTR
         * hi: DID + AW(=48-bit, 4-level)
         */
        lo = VTD_CONTEXT_ENTRY_P | VTD_CONTEXT_TT_MULTI_LEVEL |
             (ssptptr & VTD_CONTEXT_ENTRY_SSPTPTR);
        hi = ((uint64_t)QVTD_DOMAIN_ID << 8) | QVTD_AW_48BIT_ENCODING;
    }

    qtest_writeq(qts, context_entry_addr, lo);
    qtest_writeq(qts, context_entry_addr + 8, hi);
}

static void qvtd_build_scalable_context_entry(QTestState *qts, uint16_t sid)
{
    uint8_t devfn = sid & 0xff;
    uint64_t ce_addr = QVTD_CONTEXT_TABLE_BASE +
                       (devfn * VTD_CTX_ENTRY_SCALABLE_SIZE);

    /*
     * Scalable-Mode Context Entry (Section 9.4), 32 bytes = 4 qwords:
     *
     * val[0]: P + FPD(=0) + DTE(=0) + PASIDE(=0) + PRE(=0) + HPTE(=0)
     *         + EPTR(=0) + PDTS(=0) + PASIDDIRPTR
     * val[1]: RID_PASID(=0) + PDTTE(=0) + PRE(=0) + RID_CG(=0)
     * val[2]: Reserved (must be 0)
     * val[3]: Reserved (must be 0)
     */
    qtest_writeq(qts, ce_addr,
                 (QVTD_PASID_DIR_BASE & VTD_PASID_DIR_BASE_ADDR_MASK) |
                 VTD_CONTEXT_ENTRY_P);
    qtest_writeq(qts, ce_addr + 8, 0);
    qtest_writeq(qts, ce_addr + 16, 0);
    qtest_writeq(qts, ce_addr + 24, 0);
}

static void qvtd_build_pasid_dir_entry(QTestState *qts)
{
    uint64_t addr = QVTD_PASID_DIR_BASE +
                    VTD_PASID_DIR_INDEX(0) * VTD_PASID_DIR_ENTRY_SIZE;

    /*
     * PASID Directory Entry (Section 9.5):
     * P + FPD(=0, fault enabled) + SMPTBLPTR
     */
    qtest_writeq(qts, addr,
                 (QVTD_PASID_TABLE_BASE & VTD_PASID_TABLE_BASE_ADDR_MASK) |
                 VTD_PASID_ENTRY_P);
}

static void qvtd_build_pasid_table_entry(QTestState *qts, QVTDTransMode mode,
                                         uint64_t ptptr)
{
    uint64_t addr = QVTD_PASID_TABLE_BASE +
                    VTD_PASID_TABLE_INDEX(0) * VTD_PASID_ENTRY_SIZE;
    uint64_t val0, val1, val2;

    /*
     * Scalable-Mode PASID Table Entry (Section 9.6), 64 bytes = 8 qwords:
     *
     * val[0]: P + FPD(=0) + AW + PGTT + SSADE(=0) + SSPTPTR
     * val[1]: DID + PWSNP(=0) + PGSNP(=0)
     *         + CD(=0) + EMTE(=0) + PAT(=0): Memory Type,
     *           all Reserved(0) since QEMU ECAP.MTS=0
     * val[2]: SRE(=0) + FSPM(=0, 4-level) + WPE(=0) + IGN + EAFE(=0) + FSPTPTR
     * val[3]: Reserved (must be 0)
     * val[4]: HPT fields, Reserved(0) since QEMU ECAP.HPTS=0
     * val[5]: HPT fields, Reserved(0) since QEMU ECAP.HPTS=0
     * val[6]: Reserved (must be 0)
     * val[7]: Reserved (must be 0)
     */
    switch (mode) {
    case QVTD_TM_SCALABLE_PT:
        val0 = VTD_PASID_ENTRY_P |
               ((uint64_t)VTD_SM_PASID_ENTRY_PT << 6);
        val1 = (uint64_t)QVTD_DOMAIN_ID;
        val2 = 0;
        break;
    case QVTD_TM_SCALABLE_SLT:
        val0 = VTD_PASID_ENTRY_P |
               ((uint64_t)VTD_SM_PASID_ENTRY_SST << 6) |
               ((uint64_t)QVTD_AW_48BIT_ENCODING << 2) |
               (ptptr & VTD_SM_PASID_ENTRY_SSPTPTR);
        val1 = (uint64_t)QVTD_DOMAIN_ID;
        val2 = 0;
        break;
    case QVTD_TM_SCALABLE_FLT:
        /*
         * val[2] fields for FLT (Section 9.6):
         * SRE(=0, user-level DMA only) + FSPM(=0, 4-level) +
         * WPE(=0, no supervisor write-protect) + IGN + EAFE(=0) + FSPTPTR
         */
        val0 = VTD_PASID_ENTRY_P |
               ((uint64_t)VTD_SM_PASID_ENTRY_FST << 6);
        val1 = (uint64_t)QVTD_DOMAIN_ID;
        val2 = ptptr & QVTD_SM_PASID_ENTRY_FSPTPTR;
        break;
    default:
        g_assert_not_reached();
    }

    qtest_writeq(qts, addr, val0);
    qtest_writeq(qts, addr + 8, val1);
    qtest_writeq(qts, addr + 16, val2);
    qtest_writeq(qts, addr + 24, 0);
    qtest_writeq(qts, addr + 32, 0);
    qtest_writeq(qts, addr + 40, 0);
    qtest_writeq(qts, addr + 48, 0);
    qtest_writeq(qts, addr + 56, 0);
}

/*
 * VT-d second-level paging helpers.
 * 4-level, 48-bit address space, 9 bits per level index.
 */
static uint32_t qvtd_get_table_index(uint64_t iova, int level)
{
    int shift = VTD_PAGE_SHIFT + VTD_LEVEL_BITS * (level - 1);

    return (iova >> shift) & ((1u << VTD_LEVEL_BITS) - 1);
}

static uint64_t qvtd_get_table_addr(uint64_t base, int level, uint64_t iova)
{
    return base + (qvtd_get_table_index(iova, level) * QVTD_PTE_SIZE);
}

static uint64_t qvtd_get_pte_attrs(void)
{
    /* Second-level: R/W in every paging entry (Section 3.7.1) */
    return VTD_SS_R | VTD_SS_W;
}

static uint64_t qvtd_get_fl_pte_attrs(bool is_leaf)
{
    /* First-level: x86 page table format (VT-d spec Section 9.9) */
    uint64_t attrs = VTD_FS_P | VTD_FS_RW | VTD_FS_US | VTD_FS_A;

    if (is_leaf) {
        attrs |= VTD_FS_D;
    }
    return attrs;
}

uint64_t qvtd_leaf_pte_addr(uint64_t iova)
{
    return qvtd_get_table_addr(QVTD_PT_L1_BASE, 1, iova);
}

uint64_t qvtd_make_leaf_pte(uint64_t pa, QVTDTransMode mode)
{
    uint64_t attrs;

    /*
     * Reuse the same leaf attributes qvtd_setup_translation_tables() writes,
     * so a rewritten PTE stays consistent with the initial mapping.  US=1 in
     * the first-level format is required because the PASID entry runs with
     * SRE=0, which makes every DMA appear as a user-mode access
     * (VT-d 3.6.2 / 9.9).
     */
    if (mode == QVTD_TM_SCALABLE_FLT) {
        attrs = qvtd_get_fl_pte_attrs(true);
    } else {
        attrs = qvtd_get_pte_attrs();
    }
    return (pa & VTD_PAGE_MASK_4K) | attrs;
}

void qvtd_setup_translation_tables(QTestState *qts, uint64_t iova,
                                   QVTDTransMode mode)
{
    bool is_fl = (mode == QVTD_TM_SCALABLE_FLT);
    uint64_t non_leaf_attrs, leaf_attrs;

    if (is_fl) {
        non_leaf_attrs = qvtd_get_fl_pte_attrs(false);
        leaf_attrs = qvtd_get_fl_pte_attrs(true);
    } else {
        /* Second-level: all levels use identical R/W attrs (spec 3.7.1) */
        non_leaf_attrs = qvtd_get_pte_attrs();
        leaf_attrs = non_leaf_attrs;
    }

    g_test_message("Page table setup: IOVA=0x%" PRIx64
                   " PA=0x%" PRIx64 " %s",
                   (uint64_t)iova, (uint64_t)QVTD_PT_VAL,
                   is_fl ? "first-level" : "second-level");

    /* PML4 (L4) -> PDPT (L3) -> PD (L2) -> PT (L1) -> PA */
    qtest_writeq(qts, qvtd_get_table_addr(QVTD_PT_L4_BASE, 4, iova),
                 QVTD_PT_L3_BASE | non_leaf_attrs);
    qtest_writeq(qts, qvtd_get_table_addr(QVTD_PT_L3_BASE, 3, iova),
                 QVTD_PT_L2_BASE | non_leaf_attrs);
    qtest_writeq(qts, qvtd_get_table_addr(QVTD_PT_L2_BASE, 2, iova),
                 QVTD_PT_L1_BASE | non_leaf_attrs);
    qtest_writeq(qts, qvtd_get_table_addr(QVTD_PT_L1_BASE, 1, iova),
                 (QVTD_PT_VAL & VTD_PAGE_MASK_4K) | leaf_attrs);
}

void qvtd_program_regs(QTestState *qts, uint64_t iommu_base,
                       QVTDTransMode mode)
{
    uint32_t gcmd = 0;
    uint64_t rtaddr = QVTD_ROOT_TABLE_BASE;

    /* Set SMT bit for scalable mode (VT-d spec Section 9.1) */
    if (qvtd_is_scalable(mode)) {
        rtaddr |= VTD_RTADDR_SMT;
    }

    /* Set Root Table Address */
    qtest_writeq(qts, iommu_base + DMAR_RTADDR_REG, rtaddr);

    /* Set Root Table Pointer and verify */
    gcmd |= VTD_GCMD_SRTP;
    qtest_writel(qts, iommu_base + DMAR_GCMD_REG, gcmd);
    g_assert(qtest_readl(qts, iommu_base + DMAR_GSTS_REG) & VTD_GSTS_RTPS);

    /* Setup Invalidation Queue */
    qtest_writeq(qts, iommu_base + DMAR_IQA_REG,
                 QVTD_IQ_BASE | QVTD_IQ_QS);
    qtest_writeq(qts, iommu_base + DMAR_IQH_REG, 0);
    qtest_writeq(qts, iommu_base + DMAR_IQT_REG, 0);

    /* Enable Queued Invalidation and verify */
    gcmd |= VTD_GCMD_QIE;
    qtest_writel(qts, iommu_base + DMAR_GCMD_REG, gcmd);
    g_assert(qtest_readl(qts, iommu_base + DMAR_GSTS_REG) & VTD_GSTS_QIES);

    /* Setup Fault Event MSI */
    qtest_writel(qts, iommu_base + DMAR_FECTL_REG, 0x0);
    qtest_writel(qts, iommu_base + DMAR_FEDATA_REG, QVTD_FAULT_IRQ_DATA);
    qtest_writel(qts, iommu_base + DMAR_FEADDR_REG, QVTD_FAULT_IRQ_ADDR);

    /* Enable translation and verify */
    gcmd |= VTD_GCMD_TE;
    qtest_writel(qts, iommu_base + DMAR_GCMD_REG, gcmd);
    g_assert(qtest_readl(qts, iommu_base + DMAR_GSTS_REG) & VTD_GSTS_TES);
}

uint32_t qvtd_build_translation(QTestState *qts, QVTDTransMode mode,
                                uint16_t sid)
{
    uint8_t bus = (sid >> 8) & 0xff;

    g_test_message("Build translation: IOVA=0x%" PRIx64 " PA=0x%" PRIx64
                   " mode=%d",
                   (uint64_t)QVTD_IOVA, (uint64_t)QVTD_PT_VAL, mode);

    /* Clear IOMMU structure regions to avoid stale entries */
    qtest_memset(qts, QVTD_ROOT_TABLE_BASE, 0, 0x1000);
    qtest_memset(qts, QVTD_PT_L4_BASE, 0, 0x4000);

    if (qvtd_is_scalable(mode)) {
        /* Scalable: 32B context entries need 8KB */
        qtest_memset(qts, QVTD_CONTEXT_TABLE_BASE, 0, 0x2000);
        qtest_memset(qts, QVTD_PASID_DIR_BASE, 0, 0x1000);
        qtest_memset(qts, QVTD_PASID_TABLE_BASE, 0, 0x1000);
    } else {
        qtest_memset(qts, QVTD_CONTEXT_TABLE_BASE, 0, 0x1000);
    }

    qvtd_build_root_entry(qts, bus, QVTD_CONTEXT_TABLE_BASE, mode);

    if (qvtd_is_scalable(mode)) {
        /* Scalable path: context -> PASID dir -> PASID entry -> page tables */
        qvtd_build_scalable_context_entry(qts, sid);
        qvtd_build_pasid_dir_entry(qts);

        if (mode == QVTD_TM_SCALABLE_PT) {
            qvtd_build_pasid_table_entry(qts, mode, 0);
        } else {
            qvtd_setup_translation_tables(qts, QVTD_IOVA, mode);
            qvtd_build_pasid_table_entry(qts, mode, QVTD_PT_L4_BASE);
        }
    } else {
        /* Legacy path */
        if (mode == QVTD_TM_LEGACY_PT) {
            qvtd_build_context_entry(qts, sid, mode, 0);
        } else {
            qvtd_setup_translation_tables(qts, QVTD_IOVA, mode);
            qvtd_build_context_entry(qts, sid, mode, QVTD_PT_L4_BASE);
        }
    }

    return 0;
}

uint32_t qvtd_setup_and_enable_translation(QVTDTestContext *ctx)
{
    uint32_t build_result;

    /* Build translation structures first */
    build_result = qvtd_build_translation(ctx->qts, ctx->config.trans_mode,
                                          ctx->sid);
    if (build_result != 0) {
        g_test_message("Build failed: mode=%u sid=%u status=0x%x",
                       ctx->config.trans_mode, ctx->sid, build_result);
        ctx->trans_status = build_result;
        return ctx->trans_status;
    }

    /* Program IOMMU registers (sets root table pointer, enables translation) */
    qvtd_program_regs(ctx->qts, ctx->iommu_base, ctx->config.trans_mode);

    ctx->trans_status = 0;
    return ctx->trans_status;
}

static bool qvtd_validate_test_result(QVTDTestContext *ctx)
{
    uint32_t expected = qvtd_expected_dma_result(ctx);

    g_test_message("-> Validating result: expected=0x%x actual=0x%x",
                   expected, ctx->dma_result);
    return (ctx->dma_result == expected);
}

static uint32_t qvtd_single_translation_setup(void *opaque)
{
    return qvtd_setup_and_enable_translation(opaque);
}

static uint32_t qvtd_single_translation_attrs(void *opaque)
{
    return qvtd_build_dma_attrs();
}

static bool qvtd_single_translation_validate(void *opaque)
{
    return qvtd_validate_test_result(opaque);
}

static void qvtd_single_translation_report(void *opaque, uint32_t dma_result)
{
    QVTDTestContext *ctx = opaque;

    if (dma_result != 0) {
        g_test_message("DMA failed: mode=%u result=0x%x",
                       ctx->config.trans_mode, dma_result);
    } else {
        g_test_message("-> DMA succeeded: mode=%u",
                       ctx->config.trans_mode);
    }
}

void qvtd_run_translation_case(QTestState *qts, QPCIDevice *dev,
                               QPCIBar bar, uint64_t iommu_base,
                               const QVTDTestConfig *cfg)
{
    QVTDTestContext ctx = {
        .qts = qts,
        .dev = dev,
        .bar = bar,
        .iommu_base = iommu_base,
        .config = *cfg,
        .sid = dev->devfn,
    };

    QOSIOMMUTestdevDmaCfg dma = {
        .dev = dev,
        .bar = bar,
        .iova = QVTD_IOVA,
        .gpa = cfg->dma_gpa,
        .len = cfg->dma_len,
    };

    qtest_memset(qts, cfg->dma_gpa, 0x00, cfg->dma_len);
    qos_iommu_testdev_single_translation(&dma, &ctx,
                                         qvtd_single_translation_setup,
                                         qvtd_single_translation_attrs,
                                         qvtd_single_translation_validate,
                                         qvtd_single_translation_report,
                                         &ctx.dma_result);

    if (ctx.dma_result == 0 && ctx.config.expected_result == 0) {
        g_autofree uint8_t *buf = NULL;

        buf = g_malloc(ctx.config.dma_len);
        qtest_memread(ctx.qts, ctx.config.dma_gpa, buf, ctx.config.dma_len);

        for (int i = 0; i < ctx.config.dma_len; i++) {
            uint8_t expected;

            expected = (ITD_DMA_WRITE_VAL >> ((i % 4) * 8)) & 0xff;
            g_assert_cmpuint(buf[i], ==, expected);
        }
    }
}

const char *qvtd_iommu_args(QVTDTransMode mode)
{
    switch (mode) {
    case QVTD_TM_SCALABLE_FLT:
        return "-device intel-iommu,scalable-mode=on,fsts=on ";
    case QVTD_TM_SCALABLE_PT:
    case QVTD_TM_SCALABLE_SLT:
        return "-device intel-iommu,scalable-mode=on ";
    default:
        return "-device intel-iommu ";
    }
}

bool qvtd_check_caps(QTestState *qts, QVTDTransMode mode)
{
    uint64_t ecap = qtest_readq(qts,
                                Q35_HOST_BRIDGE_IOMMU_ADDR + DMAR_ECAP_REG);

    /* All scalable modes require SMTS */
    if (qvtd_is_scalable(mode) && !(ecap & VTD_ECAP_SMTS)) {
        g_test_skip("ECAP.SMTS not supported");
        return false;
    }

    switch (mode) {
    case QVTD_TM_SCALABLE_PT:
        if (!(ecap & VTD_ECAP_PT)) {
            g_test_skip("ECAP.PT not supported");
            return false;
        }
        break;
    case QVTD_TM_SCALABLE_SLT:
        if (!(ecap & VTD_ECAP_SSTS)) {
            g_test_skip("ECAP.SSTS not supported");
            return false;
        }
        break;
    case QVTD_TM_SCALABLE_FLT:
        if (!(ecap & VTD_ECAP_FSTS)) {
            g_test_skip("ECAP.FSTS not supported");
            return false;
        }
        break;
    default:
        break;
    }

    return true;
}

static void qvtd_save_pci_dev(QPCIDevice *dev, int devfn, void *data)
{
    QPCIDevice **pdev = (QPCIDevice **)data;

    *pdev = dev;
}

QPCIDevice *qvtd_setup_qtest_pci_device(QTestState *qts, QPCIBus **pcibus,
                                        QPCIBar *bar)
{
    QPCIDevice *dev = NULL;

    *pcibus = qpci_new_pc(qts, NULL);
    g_assert(*pcibus != NULL);

    qpci_device_foreach(*pcibus, IOMMU_TESTDEV_VENDOR_ID,
                        IOMMU_TESTDEV_DEVICE_ID, qvtd_save_pci_dev, &dev);

    g_assert(dev);
    qpci_device_enable(dev);
    *bar = qpci_iomap(dev, 0, NULL);
    g_assert_false(bar->is_io);

    return dev;
}

/*
 * Write a 128-bit invalidation descriptor at the current tail and advance
 * IQT_REG.  Internal helper for the IOTLB / wait variants below.
 */
static uint32_t qvtd_submit_inv_desc(QTestState *qts, uint64_t iommu_base,
                                     uint64_t desc_lo, uint64_t desc_hi,
                                     uint32_t tail)
{
    uint64_t desc_addr = QVTD_IQ_BASE + (uint64_t)tail * QVTD_IQ_DESC_SIZE;

    qtest_writeq(qts, desc_addr, desc_lo);
    qtest_writeq(qts, desc_addr + 8, desc_hi);
    tail++;

    qtest_writeq(qts, iommu_base + DMAR_IQT_REG,
                 (uint64_t)tail << QVTD_IQT_SHIFT);
    return tail;
}

uint32_t qvtd_submit_inv_wait_and_poll(QTestState *qts, uint64_t iommu_base,
                                       uint32_t tail)
{
    uint64_t lo, hi;
    uint32_t status = 0;
    int i;

    qtest_writel(qts, QVTD_INV_WAIT_ADDR, 0);

    lo = VTD_INV_DESC_WAIT | VTD_INV_DESC_WAIT_SW |
         ((uint64_t)QVTD_INV_WAIT_DATA << VTD_INV_DESC_WAIT_DATA_SHIFT);
    hi = QVTD_INV_WAIT_ADDR;

    tail = qvtd_submit_inv_desc(qts, iommu_base, lo, hi, tail);

    for (i = 0; i < QVTD_INV_WAIT_POLL_MAX_ITERS; i++) {
        status = qtest_readl(qts, QVTD_INV_WAIT_ADDR);
        if (status == QVTD_INV_WAIT_DATA) {
            return tail;
        }
        g_usleep(QVTD_INV_WAIT_POLL_INTERVAL_US);
    }

    g_assert_cmphex(status, ==, QVTD_INV_WAIT_DATA);
    return tail;
}

uint32_t qvtd_submit_iotlb_global_inv(QTestState *qts, uint64_t iommu_base,
                                      uint32_t tail)
{
    uint64_t lo = VTD_INV_DESC_IOTLB | VTD_INV_DESC_IOTLB_GLOBAL;

    return qvtd_submit_inv_desc(qts, iommu_base, lo, 0, tail);
}

uint32_t qvtd_submit_iotlb_domain_inv(QTestState *qts, uint64_t iommu_base,
                                      uint16_t domain_id, uint32_t tail)
{
    uint64_t lo = VTD_INV_DESC_IOTLB | VTD_INV_DESC_IOTLB_DOMAIN |
                  ((uint64_t)domain_id << 16);

    return qvtd_submit_inv_desc(qts, iommu_base, lo, 0, tail);
}

uint32_t qvtd_submit_iotlb_page_inv(QTestState *qts, uint64_t iommu_base,
                                    uint16_t domain_id, uint64_t addr,
                                    uint8_t am, uint32_t tail)
{
    uint64_t lo = VTD_INV_DESC_IOTLB | VTD_INV_DESC_IOTLB_PAGE |
                  ((uint64_t)domain_id << 16);
    /*
     * AM selects the invalidation range per VT-d 6.5.2.4:
     *   am=0  → 4 KB,  am=9 → 2 MB,  am=18 → 1 GB.
     * IH (hi[6]) is left clear, requesting full invalidation
     * including non-leaf paging-structure caches.
     */
    uint64_t hi = (addr & ~0xfffULL) | (am & 0x3fULL);

    return qvtd_submit_inv_desc(qts, iommu_base, lo, hi, tail);
}
