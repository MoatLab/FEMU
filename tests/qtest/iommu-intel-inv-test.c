/*
 * QTest for Intel IOMMU (VT-d) IOTLB invalidation via Invalidation Queue
 *
 * Validates that IOTLB invalidation descriptors submitted through the
 * queued invalidation interface correctly flush cached translations,
 * forcing the IOMMU to re-walk page tables on subsequent DMA.
 *
 * Copyright (c) 2026 Intel Corporation.
 *
 * Author: Junjie Cao <junjie.cao@intel.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "libqtest.h"
#include "libqos/pci.h"
#include "libqos/pci-pc.h"
#include "hw/i386/intel_iommu_internal.h"
#include "hw/misc/iommu-testdev.h"
#include "libqos/qos-intel-iommu.h"
#include "libqos/qos-iommu-testdev.h"

#define DMA_LEN                4

/*
 * Second DMA target page, chosen to fall well outside any address used by
 * qos-intel-iommu's fixed structure layout.
 */
#define QVTD_PT_VAL_B          (QVTD_MEM_BASE + 0x00200000)

/*
 * A second IOVA/target page for the page-selectivity test.  QVTD_IOVA_2 is
 * QVTD_IOVA + 4K: it shares the L4/L3/L2 walk built by
 * qvtd_build_translation() and differs only in the leaf (L1) slot, so mapping
 * it costs one extra leaf PTE.  QVTD_PT_VAL_2 is its distinct target page.
 */
#define QVTD_IOVA_2            (QVTD_IOVA + 0x1000)
#define QVTD_PT_VAL_2          (QVTD_MEM_BASE + 0x00300000)

typedef enum {
    IOTLB_INV_GLOBAL,
    IOTLB_INV_DOMAIN,
    IOTLB_INV_PAGE,
} IOTLBInvGranularity;

/*
 * Core invalidation test, parameterized by translation mode and
 * invalidation granularity.
 *
 * The iommu-testdev device performs DMA writes via the IOMMU (using the
 * IOVA) and verifies by reading back from the expected GPA directly.  If
 * the IOTLB is stale, the DMA write lands at the old PA while readback
 * uses the GPA we supply, causing a mismatch (ITD_DMA_ERR_MISMATCH).
 *
 * Test sequence:
 *   1. Setup translation: IOVA -> PA_A
 *   2. DMA(gpa=PA_A) -> success (IOTLB populates cache)
 *   3. Modify PTE: IOVA -> PA_B (no invalidation)
 *   4. DMA(gpa=PA_B) -> MISMATCH (stale IOTLB directs write to PA_A)
 *   5. Issue IOTLB invalidation + wait
 *   6. DMA(gpa=PA_B) -> success (cache flushed, fresh page walk)
 *
 * Phase 4 depends on QEMU's IOTLB caching the Phase 1 translation; if a
 * future change makes IOTLB caching lazy this assertion would no longer
 * exercise the stale-cache path.
 */
static void run_iotlb_inv_test(QVTDTransMode mode, IOTLBInvGranularity gran)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *dev;
    QPCIBar bar;
    uint32_t tail = 0;
    uint32_t result;
    uint64_t pa_a, pa_b;

    if (!qtest_has_machine("q35")) {
        g_test_skip("q35 machine not available");
        return;
    }

    qts = qtest_initf("-machine q35 -smp 1 -m 512 -net none "
                      "%s -device iommu-testdev",
                      qvtd_iommu_args(mode));

    if (!qvtd_check_caps(qts, mode)) {
        qtest_quit(qts);
        return;
    }

    dev = qvtd_setup_qtest_pci_device(qts, &pcibus, &bar);

    /*
     * The IOMMU translates an IOVA to a page base, then the page offset
     * from the IOVA is added.  So GPA = page_base + (IOVA & 0xfff).
     */
    pa_a = (QVTD_PT_VAL & VTD_PAGE_MASK_4K) + (QVTD_IOVA & 0xfff);
    pa_b = (QVTD_PT_VAL_B & VTD_PAGE_MASK_4K) + (QVTD_IOVA & 0xfff);

    /* --- Phase 1: Setup and initial DMA (populates IOTLB) --- */
    qvtd_build_translation(qts, mode, dev->devfn);
    qvtd_program_regs(qts, Q35_HOST_BRIDGE_IOMMU_ADDR, mode);

    qtest_memset(qts, pa_a, 0, DMA_LEN);
    qtest_memset(qts, pa_b, 0, DMA_LEN);

    result = qos_iommu_testdev_trigger_dma(dev, bar, QVTD_IOVA, pa_a,
                                           DMA_LEN, 0);
    g_assert_cmpuint(result, ==, 0);

    /* --- Phase 2: Modify PTE without invalidation -> stale IOTLB --- */
    qtest_writeq(qts, qvtd_leaf_pte_addr(QVTD_IOVA),
                 qvtd_make_leaf_pte(QVTD_PT_VAL_B & VTD_PAGE_MASK_4K, mode));
    qtest_memset(qts, pa_a, 0, DMA_LEN);
    qtest_memset(qts, pa_b, 0, DMA_LEN);

    result = qos_iommu_testdev_trigger_dma(dev, bar, QVTD_IOVA, pa_b,
                                           DMA_LEN, 0);
    g_assert_cmpuint(result, ==, ITD_DMA_ERR_MISMATCH);

    /* --- Phase 3: Invalidate IOTLB -> fresh page walk succeeds --- */
    switch (gran) {
    case IOTLB_INV_GLOBAL:
        tail = qvtd_submit_iotlb_global_inv(qts, Q35_HOST_BRIDGE_IOMMU_ADDR,
                                            tail);
        break;
    case IOTLB_INV_DOMAIN:
        tail = qvtd_submit_iotlb_domain_inv(qts, Q35_HOST_BRIDGE_IOMMU_ADDR,
                                            QVTD_DOMAIN_ID, tail);
        break;
    case IOTLB_INV_PAGE:
        tail = qvtd_submit_iotlb_page_inv(qts, Q35_HOST_BRIDGE_IOMMU_ADDR,
                                          QVTD_DOMAIN_ID, QVTD_IOVA, 0,
                                          tail);
        break;
    }
    tail = qvtd_submit_inv_wait_and_poll(qts, Q35_HOST_BRIDGE_IOMMU_ADDR,
                                         tail);

    qtest_memset(qts, pa_a, 0, DMA_LEN);
    qtest_memset(qts, pa_b, 0, DMA_LEN);

    result = qos_iommu_testdev_trigger_dma(dev, bar, QVTD_IOVA, pa_b,
                                           DMA_LEN, 0);
    g_assert_cmpuint(result, ==, 0);

    g_free(dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

/*
 * Page-selectivity test: verify that a page-selective invalidation flushes
 * the named page and touches other cached pages only as far as the model
 * intends.  run_iotlb_inv_test() caches a single entry, so it cannot tell a
 * page-selective flush from a domain-wide or global one; this test caches two
 * pages in the same domain and checks the second one's fate.
 *
 * The expected fate of the second page depends on the translation level:
 *
 *   - second-level (legacy / scalable-slt): a page-selective descriptor
 *     evicts only the matching gfn, so IOVA_2 survives.
 *   - first-level (scalable-flt): QEMU invalidates all first-stage entries of
 *     the domain on a page-selective descriptor (vtd_hash_remove_by_page()
 *     returns true for any pgtt==FST entry of the domain, matching the VT-d
 *     spec for first-stage IOTLB invalidation), so IOVA_2 is flushed too.
 *
 * Method: map IOVA -> PA_A and IOVA_2 -> PA_A_2, DMA both to populate two
 * IOTLB entries, rewrite both leaf PTEs to PA_B* without invalidating, then
 * page-invalidate IOVA only.  IOVA always re-walks to PA_B.  For IOVA_2 we
 * verify the DMA against its *original* page PA_A_2: if the entry survived,
 * the stale cache still serves PA_A_2 (success); if it was flushed, the fresh
 * walk reaches PA_B_2 and mismatches PA_A_2.  So a survived entry gives
 * success and a flushed entry gives MISMATCH, and we assert whichever the
 * mode requires -- catching both an over-matching second-level flush and a
 * regression that stopped flushing first-stage entries domain-wide.
 */
static void run_page_selectivity_test(QVTDTransMode mode)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *dev;
    QPCIBar bar;
    uint32_t tail = 0;
    uint32_t result;
    uint64_t pa_a, pa_b, pa_a2, pa_b2;
    bool fl_domain_wide = (mode == QVTD_TM_SCALABLE_FLT);

    if (!qtest_has_machine("q35")) {
        g_test_skip("q35 machine not available");
        return;
    }

    qts = qtest_initf("-machine q35 -smp 1 -m 512 -net none "
                      "%s -device iommu-testdev",
                      qvtd_iommu_args(mode));

    if (!qvtd_check_caps(qts, mode)) {
        qtest_quit(qts);
        return;
    }

    dev = qvtd_setup_qtest_pci_device(qts, &pcibus, &bar);

    pa_a = (QVTD_PT_VAL & VTD_PAGE_MASK_4K) + (QVTD_IOVA & 0xfff);
    pa_b = (QVTD_PT_VAL_B & VTD_PAGE_MASK_4K) + (QVTD_IOVA & 0xfff);
    pa_a2 = (QVTD_PT_VAL_2 & VTD_PAGE_MASK_4K) + (QVTD_IOVA_2 & 0xfff);
    pa_b2 = (QVTD_PT_VAL_B & VTD_PAGE_MASK_4K) + (QVTD_IOVA_2 & 0xfff);

    /* --- Setup: IOVA -> PA_A (built by helper) and IOVA_2 -> PA_A_2 --- */
    qvtd_build_translation(qts, mode, dev->devfn);
    qtest_writeq(qts, qvtd_leaf_pte_addr(QVTD_IOVA_2),
                 qvtd_make_leaf_pte(QVTD_PT_VAL_2 & VTD_PAGE_MASK_4K, mode));
    qvtd_program_regs(qts, Q35_HOST_BRIDGE_IOMMU_ADDR, mode);

    /* Populate both IOTLB entries. */
    qtest_memset(qts, pa_a, 0, DMA_LEN);
    qtest_memset(qts, pa_a2, 0, DMA_LEN);
    result = qos_iommu_testdev_trigger_dma(dev, bar, QVTD_IOVA, pa_a,
                                           DMA_LEN, 0);
    g_assert_cmpuint(result, ==, 0);
    result = qos_iommu_testdev_trigger_dma(dev, bar, QVTD_IOVA_2, pa_a2,
                                           DMA_LEN, 0);
    g_assert_cmpuint(result, ==, 0);

    /* Rewrite both leaf PTEs to PA_B* without invalidating. */
    qtest_writeq(qts, qvtd_leaf_pte_addr(QVTD_IOVA),
                 qvtd_make_leaf_pte(QVTD_PT_VAL_B & VTD_PAGE_MASK_4K, mode));
    qtest_writeq(qts, qvtd_leaf_pte_addr(QVTD_IOVA_2),
                 qvtd_make_leaf_pte(QVTD_PT_VAL_B & VTD_PAGE_MASK_4K, mode));

    /* Page-selective invalidation of IOVA only. */
    tail = qvtd_submit_iotlb_page_inv(qts, Q35_HOST_BRIDGE_IOMMU_ADDR,
                                      QVTD_DOMAIN_ID, QVTD_IOVA, 0, tail);
    tail = qvtd_submit_inv_wait_and_poll(qts, Q35_HOST_BRIDGE_IOMMU_ADDR,
                                         tail);

    /* IOVA was flushed: fresh walk reaches PA_B. */
    qtest_memset(qts, pa_a, 0, DMA_LEN);
    qtest_memset(qts, pa_b, 0, DMA_LEN);
    result = qos_iommu_testdev_trigger_dma(dev, bar, QVTD_IOVA, pa_b,
                                           DMA_LEN, 0);
    g_assert_cmpuint(result, ==, 0);

    /*
     * IOVA_2's fate, verified against its original page PA_A_2:
     *   - second-level: entry survives, stale cache serves PA_A_2 -> success;
     *   - first-level: entry was flushed domain-wide, fresh walk reaches
     *     PA_B_2 -> MISMATCH against PA_A_2.
     */
    qtest_memset(qts, pa_a2, 0, DMA_LEN);
    qtest_memset(qts, pa_b2, 0, DMA_LEN);
    result = qos_iommu_testdev_trigger_dma(dev, bar, QVTD_IOVA_2, pa_a2,
                                           DMA_LEN, 0);
    if (fl_domain_wide) {
        g_assert_cmpuint(result, ==, ITD_DMA_ERR_MISMATCH);
    } else {
        g_assert_cmpuint(result, ==, 0);
    }

    g_free(dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

/*
 * scalable-flt is covered here even though, per the VT-d spec, first-level
 * mappings are invalidated with the PASID-based descriptor
 * (VTD_INV_DESC_PIOTLB).  QEMU keeps first- and second-level mappings in a
 * single IOTLB that the legacy VTD_INV_DESC_IOTLB descriptor flushes for
 * every level, so this test drives that descriptor across all modes.
 * PASID-selective (PIOTLB) invalidation is a separate path, left for a
 * follow-up.
 */
static const struct {
    const char *name;
    QVTDTransMode mode;
} trans_modes[] = {
    { "legacy",        QVTD_TM_LEGACY_TRANS },
    { "scalable-slt",  QVTD_TM_SCALABLE_SLT },
    { "scalable-flt",  QVTD_TM_SCALABLE_FLT },
};

static const struct {
    const char *name;
    IOTLBInvGranularity gran;
} granularities[] = {
    { "global", IOTLB_INV_GLOBAL },
    { "domain", IOTLB_INV_DOMAIN },
    { "page",   IOTLB_INV_PAGE   },
};

typedef struct {
    QVTDTransMode mode;
    IOTLBInvGranularity gran;
} TestCase;

static void test_iotlb_inv(const void *opaque)
{
    const TestCase *tc = opaque;

    run_iotlb_inv_test(tc->mode, tc->gran);
}

static void test_page_selectivity(const void *opaque)
{
    const QVTDTransMode *mode = opaque;

    run_page_selectivity_test(*mode);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    for (size_t m = 0; m < ARRAY_SIZE(trans_modes); m++) {
        for (size_t g = 0; g < ARRAY_SIZE(granularities); g++) {
            TestCase *tc = g_new(TestCase, 1);
            char *path;

            tc->mode = trans_modes[m].mode;
            tc->gran = granularities[g].gran;

            path = g_strdup_printf("/iommu-testdev/intel/iotlb-inv/%s-%s",
                                   granularities[g].name,
                                   trans_modes[m].name);
            qtest_add_data_func_full(path, tc, test_iotlb_inv, g_free);
            g_free(path);
        }
    }

    for (size_t m = 0; m < ARRAY_SIZE(trans_modes); m++) {
        QVTDTransMode *mode = g_new(QVTDTransMode, 1);
        char *path;

        *mode = trans_modes[m].mode;
        path = g_strdup_printf(
            "/iommu-testdev/intel/iotlb-inv/page-selective/%s",
            trans_modes[m].name);
        qtest_add_data_func_full(path, mode, test_page_selectivity, g_free);
        g_free(path);
    }

    return g_test_run();
}
