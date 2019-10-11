/* Support for writing ELF notes for ARM architectures
 *
 * Copyright (C) 2015 Red Hat Inc.
 *
 * Author: Andrew Jones <drjones@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "elf.h"
#include "sysemu/dump.h"

/* struct user_pt_regs from arch/arm64/include/uapi/asm/ptrace.h */
struct aarch64_user_regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
} QEMU_PACKED;

QEMU_BUILD_BUG_ON(sizeof(struct aarch64_user_regs) != 272);

/* struct elf_prstatus from include/uapi/linux/elfcore.h */
struct aarch64_elf_prstatus {
    char pad1[32]; /* 32 == offsetof(struct elf_prstatus, pr_pid) */
    uint32_t pr_pid;
    char pad2[76]; /* 76 == offsetof(struct elf_prstatus, pr_reg) -
                            offsetof(struct elf_prstatus, pr_ppid) */
    struct aarch64_user_regs pr_reg;
    uint32_t pr_fpvalid;
    char pad3[4];
} QEMU_PACKED;

QEMU_BUILD_BUG_ON(sizeof(struct aarch64_elf_prstatus) != 392);

/* struct user_fpsimd_state from arch/arm64/include/uapi/asm/ptrace.h
 *
 * While the vregs member of user_fpsimd_state is of type __uint128_t,
 * QEMU uses an array of uint64_t, where the high half of the 128-bit
 * value is always in the 2n+1'th index. Thus we also break the 128-
 * bit values into two halves in this reproduction of user_fpsimd_state.
 */
struct aarch64_user_vfp_state {
    uint64_t vregs[64];
    uint32_t fpsr;
    uint32_t fpcr;
    char pad[8];
} QEMU_PACKED;

QEMU_BUILD_BUG_ON(sizeof(struct aarch64_user_vfp_state) != 528);

struct aarch64_note {
    Elf64_Nhdr hdr;
    char name[8]; /* align_up(sizeof("CORE"), 4) */
    union {
        struct aarch64_elf_prstatus prstatus;
        struct aarch64_user_vfp_state vfp;
    };
} QEMU_PACKED;

#define AARCH64_NOTE_HEADER_SIZE offsetof(struct aarch64_note, prstatus)
#define AARCH64_PRSTATUS_NOTE_SIZE \
            (AARCH64_NOTE_HEADER_SIZE + sizeof(struct aarch64_elf_prstatus))
#define AARCH64_PRFPREG_NOTE_SIZE \
            (AARCH64_NOTE_HEADER_SIZE + sizeof(struct aarch64_user_vfp_state))

static void aarch64_note_init(struct aarch64_note *note, DumpState *s,
                              const char *name, Elf64_Word namesz,
                              Elf64_Word type, Elf64_Word descsz)
{
    memset(note, 0, sizeof(*note));

    note->hdr.n_namesz = cpu_to_dump32(s, namesz);
    note->hdr.n_descsz = cpu_to_dump32(s, descsz);
    note->hdr.n_type = cpu_to_dump32(s, type);

    memcpy(note->name, name, namesz);
}

static int aarch64_write_elf64_prfpreg(WriteCoreDumpFunction f,
                                       CPUARMState *env, int cpuid,
                                       DumpState *s)
{
    struct aarch64_note note;
    int ret, i;

    aarch64_note_init(&note, s, "CORE", 5, NT_PRFPREG, sizeof(note.vfp));

    for (i = 0; i < 32; ++i) {
        uint64_t *q = aa64_vfp_qreg(env, i);
        note.vfp.vregs[2*i + 0] = cpu_to_dump64(s, q[0]);
        note.vfp.vregs[2*i + 1] = cpu_to_dump64(s, q[1]);
    }

    if (s->dump_info.d_endian == ELFDATA2MSB) {
        /* For AArch64 we must always swap the vfp.regs's 2n and 2n+1
         * entries when generating BE notes, because even big endian
         * hosts use 2n+1 for the high half.
         */
        for (i = 0; i < 32; ++i) {
            uint64_t tmp = note.vfp.vregs[2*i];
            note.vfp.vregs[2*i] = note.vfp.vregs[2*i+1];
            note.vfp.vregs[2*i+1] = tmp;
        }
    }

    note.vfp.fpsr = cpu_to_dump32(s, vfp_get_fpsr(env));
    note.vfp.fpcr = cpu_to_dump32(s, vfp_get_fpcr(env));

    ret = f(&note, AARCH64_PRFPREG_NOTE_SIZE, s);
    if (ret < 0) {
        return -1;
    }

    return 0;
}

int arm_cpu_write_elf64_note(WriteCoreDumpFunction f, CPUState *cs,
                             int cpuid, void *opaque)
{
    struct aarch64_note note;
    CPUARMState *env = &ARM_CPU(cs)->env;
    DumpState *s = opaque;
    uint64_t pstate, sp;
    int ret, i;

    aarch64_note_init(&note, s, "CORE", 5, NT_PRSTATUS, sizeof(note.prstatus));

    note.prstatus.pr_pid = cpu_to_dump32(s, cpuid);
    note.prstatus.pr_fpvalid = cpu_to_dump32(s, 1);

    if (!is_a64(env)) {
        aarch64_sync_32_to_64(env);
        pstate = cpsr_read(env);
        sp = 0;
    } else {
        pstate = pstate_read(env);
        sp = env->xregs[31];
    }

    for (i = 0; i < 31; ++i) {
        note.prstatus.pr_reg.regs[i] = cpu_to_dump64(s, env->xregs[i]);
    }
    note.prstatus.pr_reg.sp = cpu_to_dump64(s, sp);
    note.prstatus.pr_reg.pc = cpu_to_dump64(s, env->pc);
    note.prstatus.pr_reg.pstate = cpu_to_dump64(s, pstate);

    ret = f(&note, AARCH64_PRSTATUS_NOTE_SIZE, s);
    if (ret < 0) {
        return -1;
    }

    return aarch64_write_elf64_prfpreg(f, env, cpuid, s);
}

/* struct pt_regs from arch/arm/include/asm/ptrace.h */
struct arm_user_regs {
    uint32_t regs[17];
    char pad[4];
} QEMU_PACKED;

QEMU_BUILD_BUG_ON(sizeof(struct arm_user_regs) != 72);

/* struct elf_prstatus from include/uapi/linux/elfcore.h */
struct arm_elf_prstatus {
    char pad1[24]; /* 24 == offsetof(struct elf_prstatus, pr_pid) */
    uint32_t pr_pid;
    char pad2[44]; /* 44 == offsetof(struct elf_prstatus, pr_reg) -
                            offsetof(struct elf_prstatus, pr_ppid) */
    struct arm_user_regs pr_reg;
    uint32_t pr_fpvalid;
} QEMU_PACKED arm_elf_prstatus;

QEMU_BUILD_BUG_ON(sizeof(struct arm_elf_prstatus) != 148);

/* struct user_vfp from arch/arm/include/asm/user.h */
struct arm_user_vfp_state {
    uint64_t vregs[32];
    uint32_t fpscr;
} QEMU_PACKED;

QEMU_BUILD_BUG_ON(sizeof(struct arm_user_vfp_state) != 260);

struct arm_note {
    Elf32_Nhdr hdr;
    char name[8]; /* align_up(sizeof("LINUX"), 4) */
    union {
        struct arm_elf_prstatus prstatus;
        struct arm_user_vfp_state vfp;
    };
} QEMU_PACKED;

#define ARM_NOTE_HEADER_SIZE offsetof(struct arm_note, prstatus)
#define ARM_PRSTATUS_NOTE_SIZE \
            (ARM_NOTE_HEADER_SIZE + sizeof(struct arm_elf_prstatus))
#define ARM_VFP_NOTE_SIZE \
            (ARM_NOTE_HEADER_SIZE + sizeof(struct arm_user_vfp_state))

static void arm_note_init(struct arm_note *note, DumpState *s,
                          const char *name, Elf32_Word namesz,
                          Elf32_Word type, Elf32_Word descsz)
{
    memset(note, 0, sizeof(*note));

    note->hdr.n_namesz = cpu_to_dump32(s, namesz);
    note->hdr.n_descsz = cpu_to_dump32(s, descsz);
    note->hdr.n_type = cpu_to_dump32(s, type);

    memcpy(note->name, name, namesz);
}

static int arm_write_elf32_vfp(WriteCoreDumpFunction f, CPUARMState *env,
                               int cpuid, DumpState *s)
{
    struct arm_note note;
    int ret, i;

    arm_note_init(&note, s, "LINUX", 6, NT_ARM_VFP, sizeof(note.vfp));

    for (i = 0; i < 32; ++i) {
        note.vfp.vregs[i] = cpu_to_dump64(s, *aa32_vfp_dreg(env, i));
    }

    note.vfp.fpscr = cpu_to_dump32(s, vfp_get_fpscr(env));

    ret = f(&note, ARM_VFP_NOTE_SIZE, s);
    if (ret < 0) {
        return -1;
    }

    return 0;
}

int arm_cpu_write_elf32_note(WriteCoreDumpFunction f, CPUState *cs,
                             int cpuid, void *opaque)
{
    struct arm_note note;
    CPUARMState *env = &ARM_CPU(cs)->env;
    DumpState *s = opaque;
    int ret, i, fpvalid = !!arm_feature(env, ARM_FEATURE_VFP);

    arm_note_init(&note, s, "CORE", 5, NT_PRSTATUS, sizeof(note.prstatus));

    note.prstatus.pr_pid = cpu_to_dump32(s, cpuid);
    note.prstatus.pr_fpvalid = cpu_to_dump32(s, fpvalid);

    for (i = 0; i < 16; ++i) {
        note.prstatus.pr_reg.regs[i] = cpu_to_dump32(s, env->regs[i]);
    }
    note.prstatus.pr_reg.regs[16] = cpu_to_dump32(s, cpsr_read(env));

    ret = f(&note, ARM_PRSTATUS_NOTE_SIZE, s);
    if (ret < 0) {
        return -1;
    } else if (fpvalid) {
        return arm_write_elf32_vfp(f, env, cpuid, s);
    }

    return 0;
}

int cpu_get_dump_info(ArchDumpInfo *info,
                      const GuestPhysBlockList *guest_phys_blocks)
{
    ARMCPU *cpu;
    CPUARMState *env;
    GuestPhysBlock *block;
    hwaddr lowest_addr = ULLONG_MAX;

    if (first_cpu == NULL) {
        return -1;
    }

    cpu = ARM_CPU(first_cpu);
    env = &cpu->env;

    /* Take a best guess at the phys_base. If we get it wrong then crash
     * will need '--machdep phys_offset=<phys-offset>' added to its command
     * line, which isn't any worse than assuming we can use zero, but being
     * wrong. This is the same algorithm the crash utility uses when
     * attempting to guess as it loads non-dumpfile formatted files.
     */
    QTAILQ_FOREACH(block, &guest_phys_blocks->head, next) {
        if (block->target_start < lowest_addr) {
            lowest_addr = block->target_start;
        }
    }

    if (arm_feature(env, ARM_FEATURE_AARCH64)) {
        info->d_machine = EM_AARCH64;
        info->d_class = ELFCLASS64;
        info->page_size = (1 << 16); /* aarch64 max pagesize */
        if (lowest_addr != ULLONG_MAX) {
            info->phys_base = lowest_addr;
        }
    } else {
        info->d_machine = EM_ARM;
        info->d_class = ELFCLASS32;
        info->page_size = (1 << 12);
        if (lowest_addr < UINT_MAX) {
            info->phys_base = lowest_addr;
        }
    }

    /* We assume the relevant endianness is that of EL1; this is right
     * for kernels, but might give the wrong answer if you're trying to
     * dump a hypervisor that happens to be running an opposite-endian
     * kernel.
     */
    info->d_endian = (env->cp15.sctlr_el[1] & SCTLR_EE) != 0
                     ? ELFDATA2MSB : ELFDATA2LSB;

    return 0;
}

ssize_t cpu_get_note_size(int class, int machine, int nr_cpus)
{
    ARMCPU *cpu = ARM_CPU(first_cpu);
    CPUARMState *env = &cpu->env;
    size_t note_size;

    if (class == ELFCLASS64) {
        note_size = AARCH64_PRSTATUS_NOTE_SIZE;
        note_size += AARCH64_PRFPREG_NOTE_SIZE;
    } else {
        note_size = ARM_PRSTATUS_NOTE_SIZE;
        if (arm_feature(env, ARM_FEATURE_VFP)) {
            note_size += ARM_VFP_NOTE_SIZE;
        }
    }

    return note_size * nr_cpus;
}
