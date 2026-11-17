/*
 * Emulation of MPIPL (Memory Preserving Initial Program Load), aka fadump
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/units.h"
#include "system/address-spaces.h"
#include "system/cpus.h"
#include "system/hw_accel.h"
#include "system/memory.h"
#include "system/runstate.h"
#include "hw/ppc/pnv.h"
#include "hw/ppc/pnv_mpipl.h"
#include <math.h>

#define MDST_TABLE_RELOCATED                            \
    (pnv->mpipl_state.skiboot_base + MDST_TABLE_OFF)
#define MDDT_TABLE_RELOCATED                            \
    (pnv->mpipl_state.skiboot_base + MDDT_TABLE_OFF)
#define MDRT_TABLE_RELOCATED                            \
    (pnv->mpipl_state.skiboot_base + MDRT_TABLE_OFF)
#define PROC_DUMP_RELOCATED                             \
    (pnv->mpipl_state.skiboot_base + PROC_DUMP_AREA_OFF)

/*
 * Preserve the memory regions as pointed by MDST table
 *
 * During this, the memory region pointed by entries in MDST, are 'copied'
 * as it is to the memory region pointed by corresponding entry in MDDT
 *
 * Notes: All reads should consider data coming from skiboot as big-endian,
 *        and data written should also be in big-endian
 */
static bool pnv_mpipl_preserve_mem(PnvMachineState *pnv)
{
    g_autofree MdstTableEntry *mdst = g_malloc(MDST_TABLE_SIZE);
    g_autofree MddtTableEntry *mddt = g_malloc(MDDT_TABLE_SIZE);
    g_autofree MdrtTableEntry *mdrt = g_malloc0(MDRT_TABLE_SIZE);
    AddressSpace *default_as = &address_space_memory;
    MemTxResult io_result;
    MemTxAttrs attrs;
    uint64_t src_addr, dest_addr;
    uint32_t data_len;
    uint64_t num_chunks, chunk_id = 0;
    int mdrt_idx = 0;

    /* Mark the memory transactions as privileged memory access */
    attrs.user = 0;
    attrs.memory = 1;

    if (pnv->mpipl_state.mdrt_table) {
        /*
         * MDRT table allocated from some past crash, free the memory to
         * prevent memory leak
         */
        g_free(pnv->mpipl_state.mdrt_table);
        pnv->mpipl_state.num_mdrt_entries = 0;
    }

    io_result = address_space_read(default_as, MDST_TABLE_RELOCATED, attrs,
            mdst, MDST_TABLE_SIZE);
    if (io_result != MEMTX_OK) {
        qemu_log_mask(LOG_GUEST_ERROR,
            "MPIPL: Failed to read MDST table at: 0x" TARGET_FMT_lx "\n",
            MDST_TABLE_RELOCATED);

        return false;
    }

    io_result = address_space_read(default_as, MDDT_TABLE_RELOCATED, attrs,
            mddt, MDDT_TABLE_SIZE);
    if (io_result != MEMTX_OK) {
        qemu_log_mask(LOG_GUEST_ERROR,
            "MPIPL: Failed to read MDDT table at: 0x" TARGET_FMT_lx "\n",
            MDDT_TABLE_RELOCATED);

        return false;
    }

    /* Try to read all entries */
    for (int i = 0; i < MDST_MAX_ENTRIES; ++i) {
        g_autofree uint8_t *copy_buffer = NULL;
        bool is_copy_failed = false;

        /* Considering entry with address and size as 0, as end of table */
        if ((mdst[i].addr == 0) && (mdst[i].size == 0)) {
            break;
        }

        if (mdst[i].size != mddt[i].size) {
            qemu_log_mask(LOG_TRACE,
                    "Warning: Invalid entry, size mismatch in MDST & MDDT\n");
            continue;
        }

        if (mdst[i].data_region != mddt[i].data_region) {
            qemu_log_mask(LOG_TRACE,
                    "Warning: Invalid entry, region mismatch in MDST & MDDT\n");
            continue;
        }

        src_addr  = be64_to_cpu(mdst[i].addr) & ~HRMOR_BIT;
        dest_addr = be64_to_cpu(mddt[i].addr) & ~HRMOR_BIT;
        data_len   = be32_to_cpu(mddt[i].size);

#define COPY_CHUNK_SIZE  ((size_t)(32 * MiB))
        copy_buffer = g_try_malloc(COPY_CHUNK_SIZE);
        if (copy_buffer == NULL) {
            qemu_log_mask(LOG_GUEST_ERROR,
                "MPIPL: Failed allocating memory (size: %zu) for copying"
                " reserved memory regions\n", COPY_CHUNK_SIZE);
            is_copy_failed = true;
            continue;
        }

        chunk_id = 0;
        num_chunks = ceil((data_len * 1.0f) / COPY_CHUNK_SIZE);
        while (chunk_id < num_chunks) {
            /* Take minimum of bytes left to copy, and chunk size */
            uint64_t copy_len = MIN(
                            data_len - (chunk_id * COPY_CHUNK_SIZE),
                            COPY_CHUNK_SIZE
                        );

            /* Copy the source region to destination */
            io_result = address_space_read(default_as, src_addr, attrs,
                    copy_buffer, copy_len);
            if (io_result != MEMTX_OK) {
                qemu_log_mask(LOG_GUEST_ERROR,
                    "MPIPL: Failed to read region at: 0x%" PRIx64 "\n",
                    src_addr);
                is_copy_failed = true;
                break;
            }

            io_result = address_space_write(default_as, dest_addr, attrs,
                    copy_buffer, copy_len);
            if (io_result != MEMTX_OK) {
                qemu_log_mask(LOG_GUEST_ERROR,
                    "MPIPL: Failed to write region at: 0x%" PRIx64 "\n",
                    dest_addr);
                is_copy_failed = true;
                break;
            }

            src_addr += COPY_CHUNK_SIZE;
            dest_addr += COPY_CHUNK_SIZE;
            ++chunk_id;
        }
#undef COPY_CHUNK_SIZE

        if (is_copy_failed) {
            /*
             * HDAT doesn't specify an error code in MDRT for failed copy,
             * and doesn't specify how this is to be handled
             * Hence just skip adding an entry in MDRT, as done for size
             * mismatch or other inconsistency between MDST/MDDT
             */
            continue;
        }

        /* Populate entry in MDRT table if preserving successful */
        mdrt[mdrt_idx].src_addr    = cpu_to_be64(src_addr);
        mdrt[mdrt_idx].dest_addr   = cpu_to_be64(dest_addr);
        mdrt[mdrt_idx].size        = cpu_to_be32(data_len);
        mdrt[mdrt_idx].data_region = mdst[i].data_region;
        ++mdrt_idx;
    }

    pnv->mpipl_state.mdrt_table = g_steal_pointer(&mdrt);
    pnv->mpipl_state.num_mdrt_entries = mdrt_idx;

    return true;
}

static void do_store_cpu_regs(CPUState *cpu, MpiplPreservedCPUState *state)
{
    CPUPPCState *env = cpu_env(cpu);
    MpiplRegDataHdr *regs_hdr = &state->hdr;
    MpiplRegEntry *reg_entries = state->reg_entries;
    MpiplRegEntry *curr_reg_entry;
    uint32_t num_saved_regs = 0;

    cpu_synchronize_state(cpu);

    regs_hdr->pir = cpu_to_be32(env->spr[SPR_PIR]);

    /* QEMU CPUs are not in Power Saving Mode */
    regs_hdr->core_state = 0xff;

    regs_hdr->off_regentries = 0;
    regs_hdr->num_regentries = cpu_to_be32(NUM_REGS_PER_CPU);

    regs_hdr->alloc_size = cpu_to_be32(sizeof(MpiplRegEntry));
    regs_hdr->act_size   = cpu_to_be32(sizeof(MpiplRegEntry));

#define REG_TYPE_GPR  0x1
#define REG_TYPE_SPR  0x2
#define REG_TYPE_TIMA 0x3

/*
 * ID numbers used by f/w while populating certain registers
 *
 * Copied these defines from the linux kernel
 */
#define REG_ID_NIP          0x7D0
#define REG_ID_MSR          0x7D1
#define REG_ID_CCR          0x7D2

    curr_reg_entry = reg_entries;

#define REG_ENTRY(type, num, val)                          \
    do {                                               \
        curr_reg_entry->reg_type = cpu_to_be32(type);  \
        curr_reg_entry->reg_num  = cpu_to_be32(num);   \
        curr_reg_entry->reg_val  = cpu_to_be64(val);   \
        ++curr_reg_entry;                              \
        ++num_saved_regs;                            \
    } while (0)

    /* Save the GPRs */
    for (int gpr_id = 0; gpr_id < 32; ++gpr_id) {
        REG_ENTRY(REG_TYPE_GPR, gpr_id, env->gpr[gpr_id]);
    }

    REG_ENTRY(REG_TYPE_SPR, SPR_ACOP, env->spr[SPR_ACOP]);
    REG_ENTRY(REG_TYPE_SPR, SPR_AMR, env->spr[SPR_AMR]);
    REG_ENTRY(REG_TYPE_SPR, SPR_BESCR, env->spr[SPR_BESCR]);
    REG_ENTRY(REG_TYPE_SPR, SPR_CFAR, env->spr[SPR_CFAR]);
    REG_ENTRY(REG_TYPE_SPR, SPR_CIABR, env->spr[SPR_CIABR]);

    REG_ENTRY(REG_TYPE_SPR, SPR_CTR, env->spr[SPR_CTR]);
    REG_ENTRY(REG_TYPE_SPR, SPR_CTRL, env->spr[SPR_CTRL]);
    REG_ENTRY(REG_TYPE_SPR, SPR_DABR, env->spr[SPR_DABR]);
    REG_ENTRY(REG_TYPE_SPR, SPR_DABRX, env->spr[SPR_DABRX]);
    REG_ENTRY(REG_TYPE_SPR, SPR_DAR, env->spr[SPR_DAR]);
    REG_ENTRY(REG_TYPE_SPR, SPR_DAWR0, env->spr[SPR_DAWR0]);
    REG_ENTRY(REG_TYPE_SPR, SPR_DAWR1, env->spr[SPR_DAWR1]);
    REG_ENTRY(REG_TYPE_SPR, SPR_DAWRX0, env->spr[SPR_DAWRX0]);
    REG_ENTRY(REG_TYPE_SPR, SPR_DAWRX1, env->spr[SPR_DAWRX1]);
    REG_ENTRY(REG_TYPE_SPR, SPR_DPDES, env->spr[SPR_DPDES]);
    REG_ENTRY(REG_TYPE_SPR, SPR_DSCR, env->spr[SPR_DSCR]);
    REG_ENTRY(REG_TYPE_SPR, SPR_DSISR, env->spr[SPR_DSISR]);
    REG_ENTRY(REG_TYPE_SPR, SPR_EBBHR, env->spr[SPR_EBBHR]);
    REG_ENTRY(REG_TYPE_SPR, SPR_EBBRR, env->spr[SPR_EBBRR]);

    REG_ENTRY(REG_TYPE_SPR, SPR_FSCR, env->spr[SPR_FSCR]);

    REG_ENTRY(REG_TYPE_SPR, SPR_CTR, env->ctr);
    REG_ENTRY(REG_TYPE_SPR, SPR_DAR, env->spr[SPR_DAR]);
    REG_ENTRY(REG_TYPE_SPR, SPR_DSISR, env->spr[SPR_DSISR]);
    REG_ENTRY(REG_TYPE_SPR, SPR_LR, env->lr);
    REG_ENTRY(REG_TYPE_SPR, REG_ID_MSR, env->msr);
    REG_ENTRY(REG_TYPE_SPR, REG_ID_NIP, env->nip);
    REG_ENTRY(REG_TYPE_SPR, SPR_XER, env->xer);
    REG_ENTRY(REG_TYPE_SPR, SPR_SRR0, env->spr[SPR_SRR0]);
    REG_ENTRY(REG_TYPE_SPR, SPR_SRR1, env->spr[SPR_SRR1]);
    REG_ENTRY(REG_TYPE_SPR, SPR_HSRR0, env->spr[SPR_HSRR0]);
    REG_ENTRY(REG_TYPE_SPR, SPR_HSRR1, env->spr[SPR_HSRR1]);
    REG_ENTRY(REG_TYPE_SPR, SPR_CFAR, env->spr[SPR_CFAR]);
    REG_ENTRY(REG_TYPE_SPR, SPR_HMER, env->spr[SPR_HMER]);
    REG_ENTRY(REG_TYPE_SPR, SPR_HMEER, env->spr[SPR_HMEER]);

    /*
     * Ensure the number of registers saved match the number of
     * registers per cpu
     *
     * This will help catch an error if in future a new register entry
     * is added/removed while not modifying NUM_PER_CPU_REGS
     */
    assert(num_saved_regs == NUM_REGS_PER_CPU);
}

static bool pnv_mpipl_preserve_cpu_state(PnvMachineState *pnv)
{
    MachineState *machine = MACHINE(pnv);
    uint32_t num_cpus = machine->smp.cpus;
    MpiplPreservedCPUState *state;
    CPUState *cpu;
    AddressSpace *default_as = &address_space_memory;
    MemTxResult io_result;
    MemTxAttrs attrs;

    /* Mark the memory transactions as privileged memory access */
    attrs.user = 0;
    attrs.memory = 1;

    if (pnv->mpipl_state.cpu_states) {
        /*
         * CPU States might have been allocated from some past crash, free the
         * memory to preven memory leak
         */
        g_free(pnv->mpipl_state.cpu_states);
        pnv->mpipl_state.num_cpu_states = 0;
    }

    pnv->mpipl_state.cpu_states = g_malloc_n(num_cpus,
            sizeof(MpiplPreservedCPUState));
    pnv->mpipl_state.num_cpu_states = num_cpus;

    state = pnv->mpipl_state.cpu_states;

    /* Preserve the Processor Dump Area */
    io_result = address_space_read(default_as, PROC_DUMP_RELOCATED, attrs,
            &pnv->mpipl_state.proc_area, sizeof(MpiplProcDumpArea));
    if (io_result != MEMTX_OK) {
        qemu_log_mask(LOG_GUEST_ERROR,
            "MPIPL: Failed to read Proc Dump Area at: 0x" TARGET_FMT_lx "\n",
            PROC_DUMP_RELOCATED);

        return false;
    }

    CPU_FOREACH(cpu) {
        do_store_cpu_regs(cpu, state);
        ++state;
    }

    return true;
}

/*
 * Write the preserved CPU state data in Processor Dump Area (PROC_DUMP_AREA)
 *
 * Returns true if everything went fine, else false for any error
 */
static bool pnv_mpipl_write_cpu_state(PnvMachineState *pnv)
{
    MpiplProcDumpArea *proc_area = &pnv->mpipl_state.proc_area;
    MpiplPreservedCPUState *cpu_state = pnv->mpipl_state.cpu_states;
    const uint32_t num_cpu_states = pnv->mpipl_state.num_cpu_states;
    hwaddr next_regentries_hdr;
    AddressSpace *default_as = &address_space_memory;
    MemTxResult io_result;
    MemTxAttrs attrs;

    /* Mark the memory transactions as privileged memory access */
    attrs.user = 0;
    attrs.memory = 1;

    if (be32_to_cpu(proc_area->alloc_size) <
       (num_cpu_states * sizeof(MpiplPreservedCPUState))) {
        qemu_log_mask(LOG_GUEST_ERROR,
            "MPIPL: Size of buffer allocate by skiboot (%u bytes) is not"
            "enough to save all CPUs registers needed (%zu bytes)",
            be32_to_cpu(proc_area->alloc_size),
            num_cpu_states * sizeof(MpiplPreservedCPUState));

        return false;
    }

    proc_area->version = PROC_DUMP_AREA_VERSION_P9;

    /*
     * This is the stride kernel/firmware should use to jump from a
     * register entries header to next CPU's header
     */
    proc_area->thread_size = cpu_to_be32(sizeof(MpiplPreservedCPUState));

    /* Write the header and register entries for each CPU */
    next_regentries_hdr = be64_to_cpu(proc_area->alloc_addr) & (~HRMOR_BIT);
    for (int i = 0; i < num_cpu_states; ++i) {
        io_result = address_space_write(default_as, next_regentries_hdr, attrs,
            &cpu_state->hdr, sizeof(MpiplRegDataHdr));
        if (io_result != MEMTX_OK) {
            qemu_log_mask(LOG_GUEST_ERROR,
                "MPIPL: Failed to write RegEntries Header\n");
            return false;
        }

        io_result = address_space_write(default_as,
            next_regentries_hdr + sizeof(MpiplRegDataHdr), attrs,
            &cpu_state->reg_entries,
            NUM_REGS_PER_CPU * (sizeof(MpiplRegEntry)));
        if (io_result != MEMTX_OK) {
            qemu_log_mask(LOG_GUEST_ERROR,
                "MPIPL: Failed to write Register Entries\n");
            return false;
        }

        /*
         * According to HDAT section:
         *  "15.3.1.5 Architected Register Data content":
         *
         * The next register entries header will be at current header +
         * "Thread Register State Entry size"
         *
         * Note: proc_area.thread_size == sizeof(MpiplPreservedCPUState)
         */
        next_regentries_hdr += sizeof(MpiplPreservedCPUState);
        ++cpu_state;
    }

    /* Point the destination address to the preserved memory region */
    proc_area->dest_addr = proc_area->alloc_addr;
    proc_area->act_size  = cpu_to_be32(num_cpu_states *
            sizeof(MpiplPreservedCPUState));

    io_result = address_space_write(default_as, PROC_DUMP_AREA_OFF, attrs,
        proc_area, sizeof(MpiplProcDumpArea));
    if (io_result != MEMTX_OK) {
        qemu_log_mask(LOG_GUEST_ERROR,
            "MPIPL: Failed to write Register Entries\n");
        return false;
    }

    return true;
}

/*
 * Write the preserved MDRT table, representing preserved memory regions
 *
 * Returns true if everything went fine, else false for any error
 */
static bool pnv_mpipl_write_mdrt(PnvMachineState *pnv)
{
    MpiplPreservedState *state = &pnv->mpipl_state;
    AddressSpace *default_as = &address_space_memory;
    MemTxResult io_result;
    MemTxAttrs attrs;

    /* Mark the memory transactions as privileged memory access */
    attrs.user = 0;
    attrs.memory = 1;

    /*
     * Generally writes from platform during MPIPL don't go to a relocated
     * skiboot address
     *
     * Though for MDRT we are doing so, as this is the address skiboot
     * considers by default for MDRT
     *
     * MDRT/MDST/MDDT base addresses are actually meant to be shared by
     * platform in SPIRA structures.
     *
     * Not implementing SPIRA as it increases complexity for no gains.
     * Using the default address skiboot expects for MDRT, which is the
     * relocated MDRT, hence writing to it
     *
     * Other tables like MDST/MDDT should not be written to relocated
     * addresses, as skiboot will overwrite anything from SKIBOOT_BASE till
     * SKIBOOT_BASE+SKIBOOT_SIZE (which is 0x30000000-0x31c00000 by default)
     */
    io_result = address_space_write(default_as, MDRT_TABLE_RELOCATED, attrs,
            state->mdrt_table,
            state->num_mdrt_entries * sizeof(MdrtTableEntry));
    if (io_result != MEMTX_OK) {
        qemu_log_mask(LOG_GUEST_ERROR, "MPIPL: Failed to write MDRT table\n");
        return false;
    }

    return true;
}

void do_mpipl_preserve(PnvMachineState *pnv)
{
    pause_all_vcpus();

    pnv_mpipl_preserve_mem(pnv);
    pnv_mpipl_preserve_cpu_state(pnv);

    /* Mark next boot as Memory-preserving boot */
    pnv->mpipl_state.is_next_boot_mpipl = true;

    /*
     * Do a guest reset.
     * Next reset will see 'is_next_boot_mpipl' as true, and trigger MPIPL
     *
     * Requirement:
     * GUEST_RESET is expected to NOT clear the memory, as is the case when
     * this is merged
     */
    qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
}

bool do_mpipl_write(PnvMachineState *pnv)
{
    return pnv_mpipl_write_mdrt(pnv) && pnv_mpipl_write_cpu_state(pnv);
}
