/*
 * Emulation of MPIPL (Memory Preserving Initial Program Load), aka fadump
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PNV_MPIPL_H
#define PNV_MPIPL_H

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#include "exec/hwaddr.h"
#include "qemu/compiler.h"

typedef struct MdstTableEntry MdstTableEntry;
typedef struct MdrtTableEntry MdrtTableEntry;
typedef struct MpiplPreservedState MpiplPreservedState;
typedef struct MpiplRegDataHdr MpiplRegDataHdr;
typedef struct MpiplRegEntry MpiplRegEntry;
typedef struct MpiplProcDumpArea MpiplProcDumpArea;
typedef struct MpiplPreservedCPUState MpiplPreservedCPUState;

/*
 * Following offsets are copied from skiboot source code.
 * These need to be updated if this changes in a future skiboot version
 */
/* Use 768 bytes for SPIRAH */
#define SPIRAH_OFF      0x00010000
#define SPIRAH_SIZE     0x300

/* Use 256 bytes for processor dump area */
#define PROC_DUMP_AREA_OFF  (SPIRAH_OFF + SPIRAH_SIZE)
#define PROC_DUMP_AREA_SIZE 0x100

#define PROCIN_OFF      (PROC_DUMP_AREA_OFF + PROC_DUMP_AREA_SIZE)
#define PROCIN_SIZE     0x800

/* Offsets of MDST and MDDT tables from skiboot base */
#define MDST_TABLE_OFF      (PROCIN_OFF + PROCIN_SIZE)
#define MDST_TABLE_SIZE     0x400

#define MDDT_TABLE_OFF      (MDST_TABLE_OFF + MDST_TABLE_SIZE)
#define MDDT_TABLE_SIZE     0x400
/*
 * Offset of the dump result table MDRT. Hostboot will write to this
 * memory after moving memory content from source to destination memory.
 */
#define MDRT_TABLE_OFF         0x01c00000
#define MDRT_TABLE_SIZE        0x00008000

/* HRMOR_BIT copied from skiboot */
#define HRMOR_BIT (1ull << 63)

#define NUM_REGS_PER_CPU 66 /*(32 GPRs, 34 SPRs)*/

/*
 * Memory Dump Source Table (MDST)
 *
 * Format of this table is same as Memory Dump Source Table defined in HDAT
 */
struct MdstTableEntry {
    uint64_t  addr;
    uint8_t data_region;
    uint8_t dump_type;
    uint16_t  reserved;
    uint32_t  size;
} QEMU_PACKED;

/* Memory dump destination table (MDDT) has same structure as MDST */
typedef MdstTableEntry MddtTableEntry;

/*
 * Memory dump result table (MDRT)
 *
 * List of the memory ranges that have been included in the dump. This table is
 * filled by hostboot and passed to OPAL on second boot. OPAL/payload will use
 * this table to extract the dump.
 *
 * Note: This structure differs from HDAT, but matches the structure
 * skiboot uses
 */
struct MdrtTableEntry {
    uint64_t  src_addr;
    uint64_t  dest_addr;
    uint8_t data_region;
    uint8_t dump_type;  /* unused */
    uint16_t  reserved;   /* unused */
    uint32_t  size;
    uint64_t  padding;    /* unused */
} QEMU_PACKED;

/* Maximum length of mdst/mddt/mdrt tables */
#define MDST_MAX_ENTRIES    (MDST_TABLE_SIZE / sizeof(MdstTableEntry))
#define MDDT_MAX_ENTRIES    (MDDT_TABLE_SIZE / sizeof(MddtTableEntry))
#define MDRT_MAX_ENTRIES    (MDRT_TABLE_SIZE / sizeof(MdrtTableEntry))

static_assert(MDST_MAX_ENTRIES == MDDT_MAX_ENTRIES,
        "Maximum entries in MDDT must match MDST");
static_assert(MDRT_MAX_ENTRIES >= MDST_MAX_ENTRIES,
        "MDRT should support atleast having number of entries as in MDST");

/*
 * Processor Dump Area
 *
 * This contains the information needed for having processor
 * state captured during a platform dump.
 *
 * As mentioned in HDAT, following the P9 specific format
 */
struct MpiplProcDumpArea {
    uint32_t  thread_size;    /* Size of each thread register entry */
#define PROC_DUMP_AREA_VERSION_P9    0x1    /* P9 format */
    uint8_t version;
    uint8_t reserved[11];
    uint64_t  alloc_addr;    /* Destination memory to place register data */
    uint32_t  reserved2;
    uint32_t  alloc_size;    /* Allocated size */
    uint64_t  dest_addr;     /* Destination address */
    uint32_t  reserved3;
    uint32_t  act_size;      /* Actual data size */
} QEMU_PACKED;

/*
 * "Architected Register Data" in the HDAT spec
 *
 * Acts as a header to the register entries for a particular thread
 */
struct MpiplRegDataHdr {
    uint32_t pir;         /* PIR of thread */
    uint8_t  core_state;  /* Stop state of the overall core */
    uint8_t  reserved[3];
    uint32_t off_regentries;  /* Offset to Register Entries Array */
    uint32_t num_regentries;  /* Number of Register Entries in Array */
    uint32_t alloc_size;  /* Allocated size for each Register Entry */
    uint32_t act_size;    /* Actual size for each Register Entry */
} QEMU_PACKED;

struct MpiplRegEntry {
    uint32_t reg_type;
    uint32_t reg_num;
    uint64_t reg_val;
} QEMU_PACKED;

struct MpiplPreservedCPUState {
    MpiplRegDataHdr hdr;

    /* Length of 'reg_entries' is hdr.num_regentries */
    MpiplRegEntry  reg_entries[NUM_REGS_PER_CPU];
};

/* Preserved state to be saved in PnvMachineState */
struct MpiplPreservedState {
    /* skiboot_base will be valid only after OPAL sends relocated base to SBE */
    hwaddr     skiboot_base;
    bool       is_next_boot_mpipl;

    MdrtTableEntry *mdrt_table;
    uint32_t num_mdrt_entries;

    MpiplProcDumpArea proc_area;

    MpiplPreservedCPUState *cpu_states;
    uint32_t num_cpu_states;
};

#endif
