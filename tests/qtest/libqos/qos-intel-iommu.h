/*
 * QOS Intel IOMMU (VT-d) Module
 *
 * This module provides Intel IOMMU-specific helper functions for libqos tests,
 * encapsulating VT-d setup, assertion, and cleanup operations.
 *
 * Copyright (c) 2026 Fengyuan Yu <15fengyuan@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef QTEST_LIBQOS_INTEL_IOMMU_H
#define QTEST_LIBQOS_INTEL_IOMMU_H

#include "hw/misc/iommu-testdev.h"
#include "hw/i386/intel_iommu_internal.h"

/*
 * Guest memory layout for IOMMU structures.
 * All structures are placed in guest physical memory inside the 512MB RAM.
 * Using 256MB mark (0x10000000) as base to ensure all structures fit in RAM.
 */
#define QVTD_MEM_BASE             0x10000000ULL

/* Root Entry Table: 256 entries * 16 bytes = 4KB */
#define QVTD_ROOT_TABLE_BASE      (QVTD_MEM_BASE + 0x00000000)

/* Context Entry Table: 256 entries, 16B (legacy) or 32B (scalable) per entry */
#define QVTD_CONTEXT_TABLE_BASE   (QVTD_MEM_BASE + 0x00001000)

/* Page Tables: 4-level hierarchy for 48-bit address translation */
#define QVTD_PT_L4_BASE           (QVTD_MEM_BASE + 0x00010000)  /* PML4 */
#define QVTD_PT_L3_BASE           (QVTD_MEM_BASE + 0x00011000)  /* PDPT */
#define QVTD_PT_L2_BASE           (QVTD_MEM_BASE + 0x00012000)  /* PD */
#define QVTD_PT_L1_BASE           (QVTD_MEM_BASE + 0x00013000)  /* PT */

/*
 * Invalidation Queue.
 * IQA_REG bits[2:0] = QS, entries = 1 << (QS + 8), each entry 16 bytes.
 */
#define QVTD_IQ_BASE              (QVTD_MEM_BASE + 0x00020000)
#define QVTD_IQ_QS                0    /* QS=0 → 256 entries */
#define QVTD_IQ_DESC_SIZE         16   /* 128-bit descriptor (iq_dw=0) */
#define QVTD_IQT_SHIFT            4    /* IQT_REG[18:4] is the tail index */

/*
 * Invalidation Wait Descriptor with Status Write (VT-d 6.5.2.8).
 * The IOMMU writes QVTD_INV_WAIT_DATA to QVTD_INV_WAIT_ADDR after all
 * preceding invalidation descriptors complete.
 */
#define QVTD_INV_WAIT_ADDR        (QVTD_MEM_BASE + 0x00040000)
#define QVTD_INV_WAIT_DATA        0x1u

/*
 * Fault Event MSI configuration.
 */
#define QVTD_FAULT_IRQ_ADDR       0xfee00000   /* APIC base */
#define QVTD_FAULT_IRQ_DATA       0x0

/* Scalable mode PASID structures */
#define QVTD_PASID_DIR_BASE        (QVTD_MEM_BASE + 0x00030000)
#define QVTD_PASID_TABLE_BASE      (QVTD_MEM_BASE + 0x00031000)

/* Page table entry size (8 bytes per PTE) */
#define QVTD_PTE_SIZE             sizeof(uint64_t)

/* FSPTPTR mask: same as VTD_SM_PASID_ENTRY_SSPTPTR, bits[63:12] */
#define QVTD_SM_PASID_ENTRY_FSPTPTR   VTD_SM_PASID_ENTRY_SSPTPTR

/* Default Domain ID for single-domain tests */
#define QVTD_DOMAIN_ID            0

/* Test IOVA and target physical address */
#define QVTD_IOVA                 0x0000000010200567ull
#define QVTD_PT_VAL               (QVTD_MEM_BASE + 0x00100000)

/*
 * Translation modes supported by Intel IOMMU
 */
typedef enum QVTDTransMode {
    QVTD_TM_LEGACY_PT,          /* Legacy pass-through mode */
    QVTD_TM_LEGACY_TRANS,       /* Legacy translated mode (4-level paging) */
    QVTD_TM_SCALABLE_PT,        /* Scalable pass-through mode */
    QVTD_TM_SCALABLE_SLT,       /* Scalable Second Level Translation */
    QVTD_TM_SCALABLE_FLT,       /* Scalable First Level Translation */
} QVTDTransMode;

static inline bool qvtd_is_scalable(QVTDTransMode mode)
{
    return mode == QVTD_TM_SCALABLE_PT ||
           mode == QVTD_TM_SCALABLE_SLT ||
           mode == QVTD_TM_SCALABLE_FLT;
}

typedef struct QVTDTestConfig {
    QVTDTransMode trans_mode;     /* Translation mode */
    uint64_t dma_gpa;             /* GPA for readback validation */
    uint32_t dma_len;             /* DMA length for testing */
    uint32_t expected_result;     /* Expected DMA result */
} QVTDTestConfig;

typedef struct QVTDTestContext {
    QTestState *qts;              /* QTest state handle */
    QPCIDevice *dev;              /* PCI device handle */
    QPCIBar bar;                  /* PCI BAR for MMIO access */
    QVTDTestConfig config;        /* Test configuration */
    uint64_t iommu_base;          /* Intel IOMMU base address */
    uint32_t trans_status;        /* Translation configuration status */
    uint32_t dma_result;          /* DMA operation result */
    uint16_t sid;                 /* Source ID (bus:devfn) */
} QVTDTestContext;

/*
 * qvtd_setup_and_enable_translation - Complete translation setup and enable
 *
 * @ctx: Test context containing configuration and device handles
 *
 * Returns: Translation status (0 = success, non-zero = error)
 *
 * This function performs the complete translation setup sequence:
 * 1. Builds VT-d structures (root/context entry, page tables)
 * 2. Programs IOMMU registers and enables translation
 * 3. Returns configuration status
 */
uint32_t qvtd_setup_and_enable_translation(QVTDTestContext *ctx);

/*
 * qvtd_build_translation - Build Intel IOMMU translation structures
 *
 * @qts: QTest state handle
 * @mode: Translation mode (pass-through or translated)
 * @sid: Source ID (bus:devfn)
 *
 * Returns: Build status (0 = success, non-zero = error)
 *
 * Constructs all necessary VT-d translation structures in guest memory:
 * - Root Entry for the device's bus
 * - Context Entry for the device
 * - Complete 4-level page table hierarchy (if translated mode)
 */
uint32_t qvtd_build_translation(QTestState *qts, QVTDTransMode mode,
                                uint16_t sid);

/*
 * qvtd_program_regs - Program Intel IOMMU registers and enable translation
 *
 * @qts: QTest state handle
 * @iommu_base: IOMMU base address
 * @mode: Translation mode (scalable modes set RTADDR SMT bit)
 *
 * Programs IOMMU registers with the following sequence:
 * 1. Set root table pointer (SRTP), with SMT bit for scalable mode
 * 2. Setup invalidation queue (QIE)
 * 3. Configure fault event MSI
 * 4. Enable translation (TE)
 *
 * Each step verifies completion via GSTS register read-back.
 */
void qvtd_program_regs(QTestState *qts, uint64_t iommu_base,
                       QVTDTransMode mode);

/*
 * qvtd_setup_translation_tables - Setup complete VT-d page table hierarchy
 *
 * @qts: QTest state handle
 * @iova: Input Virtual Address to translate
 * @mode: Translation mode
 *
 * This builds the 4-level page table structure for translating
 * the given IOVA to PA through Intel VT-d. The structure is:
 * - PML4 (Level 4): IOVA bits [47:39]
 * - PDPT (Level 3): IOVA bits [38:30]
 * - PD (Level 2): IOVA bits [29:21]
 * - PT (Level 1): IOVA bits [20:12]
 * - Page offset: IOVA bits [11:0]
 *
 * The function writes all necessary Page Table Entries (PTEs) to guest
 * memory using qtest_writeq(), setting up the complete translation path
 * that the VT-d hardware will traverse during DMA operations.
 */
void qvtd_setup_translation_tables(QTestState *qts, uint64_t iova,
                                   QVTDTransMode mode);

/* Calculate expected DMA result */
uint32_t qvtd_expected_dma_result(QVTDTestContext *ctx);

/* Build DMA attributes for Intel VT-d */
uint32_t qvtd_build_dma_attrs(void);

/* High-level test execution helpers */
void qvtd_run_translation_case(QTestState *qts, QPCIDevice *dev,
                               QPCIBar bar, uint64_t iommu_base,
                               const QVTDTestConfig *cfg);

/*
 * qvtd_iommu_args - Build the -device intel-iommu command-line fragment
 *                   for the requested translation mode.
 */
const char *qvtd_iommu_args(QVTDTransMode mode);

/*
 * qvtd_check_caps - Check whether the running QEMU exposes the ECAP bits
 *                   required by @mode.  Calls g_test_skip() and returns
 *                   false when a required capability is missing.
 */
bool qvtd_check_caps(QTestState *qts, QVTDTransMode mode);

/*
 * qvtd_setup_qtest_pci_device - Create a QPCIBus, locate the iommu-testdev
 *                               PCI function, enable it and map BAR0.
 *
 * On success, *pcibus and *bar are populated and the returned QPCIDevice
 * must be released by the caller via g_free().
 */
QPCIDevice *qvtd_setup_qtest_pci_device(QTestState *qts, QPCIBus **pcibus,
                                        QPCIBar *bar);

/*
 * qvtd_leaf_pte_addr - Address of the leaf (L1) PTE for @iova, assuming
 *                      the hierarchy was built by
 *                      qvtd_setup_translation_tables() with 4 KB leaves.
 */
uint64_t qvtd_leaf_pte_addr(uint64_t iova);

/*
 * qvtd_make_leaf_pte - Build a leaf PTE value mapping @pa, for the
 *                      4-level / 4 KB-leaf layout used by
 *                      qvtd_setup_translation_tables().
 *                      Selects FLT or SLT/legacy attributes from @mode.
 */
uint64_t qvtd_make_leaf_pte(uint64_t pa, QVTDTransMode mode);

/*
 * qvtd_submit_inv_wait_and_poll - Submit an Invalidation Wait Descriptor
 *                                 with Status Write and poll until the
 *                                 IOMMU writes the expected status data.
 *
 * Asserts on timeout.  Returns the new tail index.
 */
uint32_t qvtd_submit_inv_wait_and_poll(QTestState *qts, uint64_t iommu_base,
                                       uint32_t tail);

/*
 * qvtd_submit_iotlb_global_inv  - global IOTLB invalidation.
 * qvtd_submit_iotlb_domain_inv  - domain-selective IOTLB invalidation.
 * qvtd_submit_iotlb_page_inv    - page-selective IOTLB invalidation;
 *                                 @addr must be 4 KB aligned.  @am
 *                                 selects the address mask per VT-d
 *                                 6.5.2.4 (am=0 → single 4 KB page).
 */
uint32_t qvtd_submit_iotlb_global_inv(QTestState *qts, uint64_t iommu_base,
                                      uint32_t tail);
uint32_t qvtd_submit_iotlb_domain_inv(QTestState *qts, uint64_t iommu_base,
                                      uint16_t domain_id, uint32_t tail);
uint32_t qvtd_submit_iotlb_page_inv(QTestState *qts, uint64_t iommu_base,
                                    uint16_t domain_id, uint64_t addr,
                                    uint8_t am, uint32_t tail);

#endif /* QTEST_LIBQOS_INTEL_IOMMU_H */
