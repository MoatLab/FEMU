/*
 * RISC-V CPU helpers for qemu.
 *
 * Copyright (c) 2016-2017 Sagar Karandikar, sagark@eecs.berkeley.edu
 * Copyright (c) 2017-2018 SiFive, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "tcg/tcg-op.h"
#include "trace.h"
#include "semihosting/common-semi.h"

int riscv_cpu_mmu_index(CPURISCVState *env, bool ifetch)
{
#ifdef CONFIG_USER_ONLY
    return 0;
#else
    return env->priv;
#endif
}

void cpu_get_tb_cpu_state(CPURISCVState *env, target_ulong *pc,
                          target_ulong *cs_base, uint32_t *pflags)
{
    CPUState *cs = env_cpu(env);
    RISCVCPU *cpu = RISCV_CPU(cs);

    uint32_t flags = 0;

    *pc = env->xl == MXL_RV32 ? env->pc & UINT32_MAX : env->pc;
    *cs_base = 0;

    if (riscv_has_ext(env, RVV) || cpu->cfg.ext_zve32f || cpu->cfg.ext_zve64f) {
        /*
         * If env->vl equals to VLMAX, we can use generic vector operation
         * expanders (GVEC) to accerlate the vector operations.
         * However, as LMUL could be a fractional number. The maximum
         * vector size can be operated might be less than 8 bytes,
         * which is not supported by GVEC. So we set vl_eq_vlmax flag to true
         * only when maxsz >= 8 bytes.
         */
        uint32_t vlmax = vext_get_vlmax(env_archcpu(env), env->vtype);
        uint32_t sew = FIELD_EX64(env->vtype, VTYPE, VSEW);
        uint32_t maxsz = vlmax << sew;
        bool vl_eq_vlmax = (env->vstart == 0) && (vlmax == env->vl) &&
                           (maxsz >= 8);
        flags = FIELD_DP32(flags, TB_FLAGS, VILL, env->vill);
        flags = FIELD_DP32(flags, TB_FLAGS, SEW, sew);
        flags = FIELD_DP32(flags, TB_FLAGS, LMUL,
                    FIELD_EX64(env->vtype, VTYPE, VLMUL));
        flags = FIELD_DP32(flags, TB_FLAGS, VL_EQ_VLMAX, vl_eq_vlmax);
    } else {
        flags = FIELD_DP32(flags, TB_FLAGS, VILL, 1);
    }

#ifdef CONFIG_USER_ONLY
    flags |= TB_FLAGS_MSTATUS_FS;
    flags |= TB_FLAGS_MSTATUS_VS;
#else
    flags |= cpu_mmu_index(env, 0);
    if (riscv_cpu_fp_enabled(env)) {
        flags |= env->mstatus & MSTATUS_FS;
    }

    if (riscv_cpu_vector_enabled(env)) {
        flags |= env->mstatus & MSTATUS_VS;
    }

    if (riscv_has_ext(env, RVH)) {
        if (env->priv == PRV_M ||
            (env->priv == PRV_S && !riscv_cpu_virt_enabled(env)) ||
            (env->priv == PRV_U && !riscv_cpu_virt_enabled(env) &&
                get_field(env->hstatus, HSTATUS_HU))) {
            flags = FIELD_DP32(flags, TB_FLAGS, HLSX, 1);
        }

        flags = FIELD_DP32(flags, TB_FLAGS, MSTATUS_HS_FS,
                           get_field(env->mstatus_hs, MSTATUS_FS));

        flags = FIELD_DP32(flags, TB_FLAGS, MSTATUS_HS_VS,
                           get_field(env->mstatus_hs, MSTATUS_VS));
    }
#endif

    flags = FIELD_DP32(flags, TB_FLAGS, XL, env->xl);
    if (env->cur_pmmask < (env->xl == MXL_RV32 ? UINT32_MAX : UINT64_MAX)) {
        flags = FIELD_DP32(flags, TB_FLAGS, PM_MASK_ENABLED, 1);
    }
    if (env->cur_pmbase != 0) {
        flags = FIELD_DP32(flags, TB_FLAGS, PM_BASE_ENABLED, 1);
    }

    *pflags = flags;
}

void riscv_cpu_update_mask(CPURISCVState *env)
{
    target_ulong mask = -1, base = 0;
    /*
     * TODO: Current RVJ spec does not specify
     * how the extension interacts with XLEN.
     */
#ifndef CONFIG_USER_ONLY
    if (riscv_has_ext(env, RVJ)) {
        switch (env->priv) {
        case PRV_M:
            if (env->mmte & M_PM_ENABLE) {
                mask = env->mpmmask;
                base = env->mpmbase;
            }
            break;
        case PRV_S:
            if (env->mmte & S_PM_ENABLE) {
                mask = env->spmmask;
                base = env->spmbase;
            }
            break;
        case PRV_U:
            if (env->mmte & U_PM_ENABLE) {
                mask = env->upmmask;
                base = env->upmbase;
            }
            break;
        default:
            g_assert_not_reached();
        }
    }
#endif
    if (env->xl == MXL_RV32) {
        env->cur_pmmask = mask & UINT32_MAX;
        env->cur_pmbase = base & UINT32_MAX;
    } else {
        env->cur_pmmask = mask;
        env->cur_pmbase = base;
    }
}

#ifndef CONFIG_USER_ONLY

/*
 * The HS-mode is allowed to configure priority only for the
 * following VS-mode local interrupts:
 *
 * 0  (Reserved interrupt, reads as zero)
 * 1  Supervisor software interrupt
 * 4  (Reserved interrupt, reads as zero)
 * 5  Supervisor timer interrupt
 * 8  (Reserved interrupt, reads as zero)
 * 13 (Reserved interrupt)
 * 14 "
 * 15 "
 * 16 "
 * 18 Debug/trace interrupt
 * 20 (Reserved interrupt)
 * 22 "
 * 24 "
 * 26 "
 * 28 "
 * 30 (Reserved for standard reporting of bus or system errors)
 */

static const int hviprio_index2irq[] = {
    0, 1, 4, 5, 8, 13, 14, 15, 16, 18, 20, 22, 24, 26, 28, 30 };
static const int hviprio_index2rdzero[] = {
    1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

int riscv_cpu_hviprio_index2irq(int index, int *out_irq, int *out_rdzero)
{
    if (index < 0 || ARRAY_SIZE(hviprio_index2irq) <= index) {
        return -EINVAL;
    }

    if (out_irq) {
        *out_irq = hviprio_index2irq[index];
    }

    if (out_rdzero) {
        *out_rdzero = hviprio_index2rdzero[index];
    }

    return 0;
}

/*
 * Default priorities of local interrupts are defined in the
 * RISC-V Advanced Interrupt Architecture specification.
 *
 * ----------------------------------------------------------------
 *  Default  |
 *  Priority | Major Interrupt Numbers
 * ----------------------------------------------------------------
 *  Highest  | 63 (3f), 62 (3e), 31 (1f), 30 (1e), 61 (3d), 60 (3c),
 *           | 59 (3b), 58 (3a), 29 (1d), 28 (1c), 57 (39), 56 (38),
 *           | 55 (37), 54 (36), 27 (1b), 26 (1a), 53 (35), 52 (34),
 *           | 51 (33), 50 (32), 25 (19), 24 (18), 49 (31), 48 (30)
 *           |
 *           | 11 (0b),  3 (03),  7 (07)
 *           |  9 (09),  1 (01),  5 (05)
 *           | 12 (0c)
 *           | 10 (0a),  2 (02),  6 (06)
 *           |
 *           | 47 (2f), 46 (2e), 23 (17), 22 (16), 45 (2d), 44 (2c),
 *           | 43 (2b), 42 (2a), 21 (15), 20 (14), 41 (29), 40 (28),
 *           | 39 (27), 38 (26), 19 (13), 18 (12), 37 (25), 36 (24),
 *  Lowest   | 35 (23), 34 (22), 17 (11), 16 (10), 33 (21), 32 (20)
 * ----------------------------------------------------------------
 */
static const uint8_t default_iprio[64] = {
 [63] = IPRIO_DEFAULT_UPPER,
 [62] = IPRIO_DEFAULT_UPPER + 1,
 [31] = IPRIO_DEFAULT_UPPER + 2,
 [30] = IPRIO_DEFAULT_UPPER + 3,
 [61] = IPRIO_DEFAULT_UPPER + 4,
 [60] = IPRIO_DEFAULT_UPPER + 5,

 [59] = IPRIO_DEFAULT_UPPER + 6,
 [58] = IPRIO_DEFAULT_UPPER + 7,
 [29] = IPRIO_DEFAULT_UPPER + 8,
 [28] = IPRIO_DEFAULT_UPPER + 9,
 [57] = IPRIO_DEFAULT_UPPER + 10,
 [56] = IPRIO_DEFAULT_UPPER + 11,

 [55] = IPRIO_DEFAULT_UPPER + 12,
 [54] = IPRIO_DEFAULT_UPPER + 13,
 [27] = IPRIO_DEFAULT_UPPER + 14,
 [26] = IPRIO_DEFAULT_UPPER + 15,
 [53] = IPRIO_DEFAULT_UPPER + 16,
 [52] = IPRIO_DEFAULT_UPPER + 17,

 [51] = IPRIO_DEFAULT_UPPER + 18,
 [50] = IPRIO_DEFAULT_UPPER + 19,
 [25] = IPRIO_DEFAULT_UPPER + 20,
 [24] = IPRIO_DEFAULT_UPPER + 21,
 [49] = IPRIO_DEFAULT_UPPER + 22,
 [48] = IPRIO_DEFAULT_UPPER + 23,

 [11] = IPRIO_DEFAULT_M,
 [3]  = IPRIO_DEFAULT_M + 1,
 [7]  = IPRIO_DEFAULT_M + 2,

 [9]  = IPRIO_DEFAULT_S,
 [1]  = IPRIO_DEFAULT_S + 1,
 [5]  = IPRIO_DEFAULT_S + 2,

 [12] = IPRIO_DEFAULT_SGEXT,

 [10] = IPRIO_DEFAULT_VS,
 [2]  = IPRIO_DEFAULT_VS + 1,
 [6]  = IPRIO_DEFAULT_VS + 2,

 [47] = IPRIO_DEFAULT_LOWER,
 [46] = IPRIO_DEFAULT_LOWER + 1,
 [23] = IPRIO_DEFAULT_LOWER + 2,
 [22] = IPRIO_DEFAULT_LOWER + 3,
 [45] = IPRIO_DEFAULT_LOWER + 4,
 [44] = IPRIO_DEFAULT_LOWER + 5,

 [43] = IPRIO_DEFAULT_LOWER + 6,
 [42] = IPRIO_DEFAULT_LOWER + 7,
 [21] = IPRIO_DEFAULT_LOWER + 8,
 [20] = IPRIO_DEFAULT_LOWER + 9,
 [41] = IPRIO_DEFAULT_LOWER + 10,
 [40] = IPRIO_DEFAULT_LOWER + 11,

 [39] = IPRIO_DEFAULT_LOWER + 12,
 [38] = IPRIO_DEFAULT_LOWER + 13,
 [19] = IPRIO_DEFAULT_LOWER + 14,
 [18] = IPRIO_DEFAULT_LOWER + 15,
 [37] = IPRIO_DEFAULT_LOWER + 16,
 [36] = IPRIO_DEFAULT_LOWER + 17,

 [35] = IPRIO_DEFAULT_LOWER + 18,
 [34] = IPRIO_DEFAULT_LOWER + 19,
 [17] = IPRIO_DEFAULT_LOWER + 20,
 [16] = IPRIO_DEFAULT_LOWER + 21,
 [33] = IPRIO_DEFAULT_LOWER + 22,
 [32] = IPRIO_DEFAULT_LOWER + 23,
};

uint8_t riscv_cpu_default_priority(int irq)
{
    if (irq < 0 || irq > 63) {
        return IPRIO_MMAXIPRIO;
    }

    return default_iprio[irq] ? default_iprio[irq] : IPRIO_MMAXIPRIO;
};

static int riscv_cpu_pending_to_irq(CPURISCVState *env,
                                    int extirq, unsigned int extirq_def_prio,
                                    uint64_t pending, uint8_t *iprio)
{
    int irq, best_irq = RISCV_EXCP_NONE;
    unsigned int prio, best_prio = UINT_MAX;

    if (!pending) {
        return RISCV_EXCP_NONE;
    }

    irq = ctz64(pending);
    if (!riscv_feature(env, RISCV_FEATURE_AIA)) {
        return irq;
    }

    pending = pending >> irq;
    while (pending) {
        prio = iprio[irq];
        if (!prio) {
            if (irq == extirq) {
                prio = extirq_def_prio;
            } else {
                prio = (riscv_cpu_default_priority(irq) < extirq_def_prio) ?
                       1 : IPRIO_MMAXIPRIO;
            }
        }
        if ((pending & 0x1) && (prio <= best_prio)) {
            best_irq = irq;
            best_prio = prio;
        }
        irq++;
        pending = pending >> 1;
    }

    return best_irq;
}

static uint64_t riscv_cpu_all_pending(CPURISCVState *env)
{
    uint32_t gein = get_field(env->hstatus, HSTATUS_VGEIN);
    uint64_t vsgein = (env->hgeip & (1ULL << gein)) ? MIP_VSEIP : 0;

    return (env->mip | vsgein) & env->mie;
}

int riscv_cpu_mirq_pending(CPURISCVState *env)
{
    uint64_t irqs = riscv_cpu_all_pending(env) & ~env->mideleg &
                    ~(MIP_SGEIP | MIP_VSSIP | MIP_VSTIP | MIP_VSEIP);

    return riscv_cpu_pending_to_irq(env, IRQ_M_EXT, IPRIO_DEFAULT_M,
                                    irqs, env->miprio);
}

int riscv_cpu_sirq_pending(CPURISCVState *env)
{
    uint64_t irqs = riscv_cpu_all_pending(env) & env->mideleg &
                    ~(MIP_VSSIP | MIP_VSTIP | MIP_VSEIP);

    return riscv_cpu_pending_to_irq(env, IRQ_S_EXT, IPRIO_DEFAULT_S,
                                    irqs, env->siprio);
}

int riscv_cpu_vsirq_pending(CPURISCVState *env)
{
    uint64_t irqs = riscv_cpu_all_pending(env) & env->mideleg &
                    (MIP_VSSIP | MIP_VSTIP | MIP_VSEIP);

    return riscv_cpu_pending_to_irq(env, IRQ_S_EXT, IPRIO_DEFAULT_S,
                                    irqs >> 1, env->hviprio);
}

static int riscv_cpu_local_irq_pending(CPURISCVState *env)
{
    int virq;
    uint64_t irqs, pending, mie, hsie, vsie;

    /* Determine interrupt enable state of all privilege modes */
    if (riscv_cpu_virt_enabled(env)) {
        mie = 1;
        hsie = 1;
        vsie = (env->priv < PRV_S) ||
               (env->priv == PRV_S && get_field(env->mstatus, MSTATUS_SIE));
    } else {
        mie = (env->priv < PRV_M) ||
              (env->priv == PRV_M && get_field(env->mstatus, MSTATUS_MIE));
        hsie = (env->priv < PRV_S) ||
               (env->priv == PRV_S && get_field(env->mstatus, MSTATUS_SIE));
        vsie = 0;
    }

    /* Determine all pending interrupts */
    pending = riscv_cpu_all_pending(env);

    /* Check M-mode interrupts */
    irqs = pending & ~env->mideleg & -mie;
    if (irqs) {
        return riscv_cpu_pending_to_irq(env, IRQ_M_EXT, IPRIO_DEFAULT_M,
                                        irqs, env->miprio);
    }

    /* Check HS-mode interrupts */
    irqs = pending & env->mideleg & ~env->hideleg & -hsie;
    if (irqs) {
        return riscv_cpu_pending_to_irq(env, IRQ_S_EXT, IPRIO_DEFAULT_S,
                                        irqs, env->siprio);
    }

    /* Check VS-mode interrupts */
    irqs = pending & env->mideleg & env->hideleg & -vsie;
    if (irqs) {
        virq = riscv_cpu_pending_to_irq(env, IRQ_S_EXT, IPRIO_DEFAULT_S,
                                        irqs >> 1, env->hviprio);
        return (virq <= 0) ? virq : virq + 1;
    }

    /* Indicate no pending interrupt */
    return RISCV_EXCP_NONE;
}

bool riscv_cpu_exec_interrupt(CPUState *cs, int interrupt_request)
{
    if (interrupt_request & CPU_INTERRUPT_HARD) {
        RISCVCPU *cpu = RISCV_CPU(cs);
        CPURISCVState *env = &cpu->env;
        int interruptno = riscv_cpu_local_irq_pending(env);
        if (interruptno >= 0) {
            cs->exception_index = RISCV_EXCP_INT_FLAG | interruptno;
            riscv_cpu_do_interrupt(cs);
            return true;
        }
    }
    return false;
}

/* Return true is floating point support is currently enabled */
bool riscv_cpu_fp_enabled(CPURISCVState *env)
{
    if (env->mstatus & MSTATUS_FS) {
        if (riscv_cpu_virt_enabled(env) && !(env->mstatus_hs & MSTATUS_FS)) {
            return false;
        }
        return true;
    }

    return false;
}

/* Return true is vector support is currently enabled */
bool riscv_cpu_vector_enabled(CPURISCVState *env)
{
    if (env->mstatus & MSTATUS_VS) {
        if (riscv_cpu_virt_enabled(env) && !(env->mstatus_hs & MSTATUS_VS)) {
            return false;
        }
        return true;
    }

    return false;
}

void riscv_cpu_swap_hypervisor_regs(CPURISCVState *env)
{
    uint64_t mstatus_mask = MSTATUS_MXR | MSTATUS_SUM |
                            MSTATUS_SPP | MSTATUS_SPIE | MSTATUS_SIE |
                            MSTATUS64_UXL | MSTATUS_VS;

    if (riscv_has_ext(env, RVF)) {
        mstatus_mask |= MSTATUS_FS;
    }
    bool current_virt = riscv_cpu_virt_enabled(env);

    g_assert(riscv_has_ext(env, RVH));

    if (current_virt) {
        /* Current V=1 and we are about to change to V=0 */
        env->vsstatus = env->mstatus & mstatus_mask;
        env->mstatus &= ~mstatus_mask;
        env->mstatus |= env->mstatus_hs;

        env->vstvec = env->stvec;
        env->stvec = env->stvec_hs;

        env->vsscratch = env->sscratch;
        env->sscratch = env->sscratch_hs;

        env->vsepc = env->sepc;
        env->sepc = env->sepc_hs;

        env->vscause = env->scause;
        env->scause = env->scause_hs;

        env->vstval = env->stval;
        env->stval = env->stval_hs;

        env->vsatp = env->satp;
        env->satp = env->satp_hs;
    } else {
        /* Current V=0 and we are about to change to V=1 */
        env->mstatus_hs = env->mstatus & mstatus_mask;
        env->mstatus &= ~mstatus_mask;
        env->mstatus |= env->vsstatus;

        env->stvec_hs = env->stvec;
        env->stvec = env->vstvec;

        env->sscratch_hs = env->sscratch;
        env->sscratch = env->vsscratch;

        env->sepc_hs = env->sepc;
        env->sepc = env->vsepc;

        env->scause_hs = env->scause;
        env->scause = env->vscause;

        env->stval_hs = env->stval;
        env->stval = env->vstval;

        env->satp_hs = env->satp;
        env->satp = env->vsatp;
    }
}

target_ulong riscv_cpu_get_geilen(CPURISCVState *env)
{
    if (!riscv_has_ext(env, RVH)) {
        return 0;
    }

    return env->geilen;
}

void riscv_cpu_set_geilen(CPURISCVState *env, target_ulong geilen)
{
    if (!riscv_has_ext(env, RVH)) {
        return;
    }

    if (geilen > (TARGET_LONG_BITS - 1)) {
        return;
    }

    env->geilen = geilen;
}

bool riscv_cpu_virt_enabled(CPURISCVState *env)
{
    if (!riscv_has_ext(env, RVH)) {
        return false;
    }

    return get_field(env->virt, VIRT_ONOFF);
}

void riscv_cpu_set_virt_enabled(CPURISCVState *env, bool enable)
{
    if (!riscv_has_ext(env, RVH)) {
        return;
    }

    /* Flush the TLB on all virt mode changes. */
    if (get_field(env->virt, VIRT_ONOFF) != enable) {
        tlb_flush(env_cpu(env));
    }

    env->virt = set_field(env->virt, VIRT_ONOFF, enable);

    if (enable) {
        /*
         * The guest external interrupts from an interrupt controller are
         * delivered only when the Guest/VM is running (i.e. V=1). This means
         * any guest external interrupt which is triggered while the Guest/VM
         * is not running (i.e. V=0) will be missed on QEMU resulting in guest
         * with sluggish response to serial console input and other I/O events.
         *
         * To solve this, we check and inject interrupt after setting V=1.
         */
        riscv_cpu_update_mip(env_archcpu(env), 0, 0);
    }
}

bool riscv_cpu_two_stage_lookup(int mmu_idx)
{
    return mmu_idx & TB_FLAGS_PRIV_HYP_ACCESS_MASK;
}

int riscv_cpu_claim_interrupts(RISCVCPU *cpu, uint64_t interrupts)
{
    CPURISCVState *env = &cpu->env;
    if (env->miclaim & interrupts) {
        return -1;
    } else {
        env->miclaim |= interrupts;
        return 0;
    }
}

uint64_t riscv_cpu_update_mip(RISCVCPU *cpu, uint64_t mask, uint64_t value)
{
    CPURISCVState *env = &cpu->env;
    CPUState *cs = CPU(cpu);
    uint64_t gein, vsgein = 0, old = env->mip;
    bool locked = false;

    if (riscv_cpu_virt_enabled(env)) {
        gein = get_field(env->hstatus, HSTATUS_VGEIN);
        vsgein = (env->hgeip & (1ULL << gein)) ? MIP_VSEIP : 0;
    }

    if (!qemu_mutex_iothread_locked()) {
        locked = true;
        qemu_mutex_lock_iothread();
    }

    env->mip = (env->mip & ~mask) | (value & mask);

    if (env->mip | vsgein) {
        cpu_interrupt(cs, CPU_INTERRUPT_HARD);
    } else {
        cpu_reset_interrupt(cs, CPU_INTERRUPT_HARD);
    }

    if (locked) {
        qemu_mutex_unlock_iothread();
    }

    return old;
}

void riscv_cpu_set_rdtime_fn(CPURISCVState *env, uint64_t (*fn)(uint32_t),
                             uint32_t arg)
{
    env->rdtime_fn = fn;
    env->rdtime_fn_arg = arg;
}

void riscv_cpu_set_aia_ireg_rmw_fn(CPURISCVState *env, uint32_t priv,
                                   int (*rmw_fn)(void *arg,
                                                 target_ulong reg,
                                                 target_ulong *val,
                                                 target_ulong new_val,
                                                 target_ulong write_mask),
                                   void *rmw_fn_arg)
{
    if (priv <= PRV_M) {
        env->aia_ireg_rmw_fn[priv] = rmw_fn;
        env->aia_ireg_rmw_fn_arg[priv] = rmw_fn_arg;
    }
}

void riscv_cpu_set_mode(CPURISCVState *env, target_ulong newpriv)
{
    if (newpriv > PRV_M) {
        g_assert_not_reached();
    }
    if (newpriv == PRV_H) {
        newpriv = PRV_U;
    }
    /* tlb_flush is unnecessary as mode is contained in mmu_idx */
    env->priv = newpriv;
    env->xl = cpu_recompute_xl(env);
    riscv_cpu_update_mask(env);

    /*
     * Clear the load reservation - otherwise a reservation placed in one
     * context/process can be used by another, resulting in an SC succeeding
     * incorrectly. Version 2.2 of the ISA specification explicitly requires
     * this behaviour, while later revisions say that the kernel "should" use
     * an SC instruction to force the yielding of a load reservation on a
     * preemptive context switch. As a result, do both.
     */
    env->load_res = -1;
}

/*
 * get_physical_address_pmp - check PMP permission for this physical address
 *
 * Match the PMP region and check permission for this physical address and it's
 * TLB page. Returns 0 if the permission checking was successful
 *
 * @env: CPURISCVState
 * @prot: The returned protection attributes
 * @tlb_size: TLB page size containing addr. It could be modified after PMP
 *            permission checking. NULL if not set TLB page for addr.
 * @addr: The physical address to be checked permission
 * @access_type: The type of MMU access
 * @mode: Indicates current privilege level.
 */
static int get_physical_address_pmp(CPURISCVState *env, int *prot,
                                    target_ulong *tlb_size, hwaddr addr,
                                    int size, MMUAccessType access_type,
                                    int mode)
{
    pmp_priv_t pmp_priv;
    target_ulong tlb_size_pmp = 0;

    if (!riscv_feature(env, RISCV_FEATURE_PMP)) {
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        return TRANSLATE_SUCCESS;
    }

    if (!pmp_hart_has_privs(env, addr, size, 1 << access_type, &pmp_priv,
                            mode)) {
        *prot = 0;
        return TRANSLATE_PMP_FAIL;
    }

    *prot = pmp_priv_to_page_prot(pmp_priv);
    if (tlb_size != NULL) {
        if (pmp_is_range_in_tlb(env, addr & ~(*tlb_size - 1), &tlb_size_pmp)) {
            *tlb_size = tlb_size_pmp;
        }
    }

    return TRANSLATE_SUCCESS;
}

/* get_physical_address - get the physical address for this virtual address
 *
 * Do a page table walk to obtain the physical address corresponding to a
 * virtual address. Returns 0 if the translation was successful
 *
 * Adapted from Spike's mmu_t::translate and mmu_t::walk
 *
 * @env: CPURISCVState
 * @physical: This will be set to the calculated physical address
 * @prot: The returned protection attributes
 * @addr: The virtual address to be translated
 * @fault_pte_addr: If not NULL, this will be set to fault pte address
 *                  when a error occurs on pte address translation.
 *                  This will already be shifted to match htval.
 * @access_type: The type of MMU access
 * @mmu_idx: Indicates current privilege level
 * @first_stage: Are we in first stage translation?
 *               Second stage is used for hypervisor guest translation
 * @two_stage: Are we going to perform two stage translation
 * @is_debug: Is this access from a debugger or the monitor?
 */
static int get_physical_address(CPURISCVState *env, hwaddr *physical,
                                int *prot, target_ulong addr,
                                target_ulong *fault_pte_addr,
                                int access_type, int mmu_idx,
                                bool first_stage, bool two_stage,
                                bool is_debug)
{
    /* NOTE: the env->pc value visible here will not be
     * correct, but the value visible to the exception handler
     * (riscv_cpu_do_interrupt) is correct */
    MemTxResult res;
    MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
    int mode = mmu_idx & TB_FLAGS_PRIV_MMU_MASK;
    bool use_background = false;
    hwaddr ppn;
    RISCVCPU *cpu = env_archcpu(env);
    int napot_bits = 0;
    target_ulong napot_mask;

    /*
     * Check if we should use the background registers for the two
     * stage translation. We don't need to check if we actually need
     * two stage translation as that happened before this function
     * was called. Background registers will be used if the guest has
     * forced a two stage translation to be on (in HS or M mode).
     */
    if (!riscv_cpu_virt_enabled(env) && two_stage) {
        use_background = true;
    }

    /* MPRV does not affect the virtual-machine load/store
       instructions, HLV, HLVX, and HSV. */
    if (riscv_cpu_two_stage_lookup(mmu_idx)) {
        mode = get_field(env->hstatus, HSTATUS_SPVP);
    } else if (mode == PRV_M && access_type != MMU_INST_FETCH) {
        if (get_field(env->mstatus, MSTATUS_MPRV)) {
            mode = get_field(env->mstatus, MSTATUS_MPP);
        }
    }

    if (first_stage == false) {
        /* We are in stage 2 translation, this is similar to stage 1. */
        /* Stage 2 is always taken as U-mode */
        mode = PRV_U;
    }

    if (mode == PRV_M || !riscv_feature(env, RISCV_FEATURE_MMU)) {
        *physical = addr;
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        return TRANSLATE_SUCCESS;
    }

    *prot = 0;

    hwaddr base;
    int levels, ptidxbits, ptesize, vm, sum, mxr, widened;

    if (first_stage == true) {
        mxr = get_field(env->mstatus, MSTATUS_MXR);
    } else {
        mxr = get_field(env->vsstatus, MSTATUS_MXR);
    }

    if (first_stage == true) {
        if (use_background) {
            if (riscv_cpu_mxl(env) == MXL_RV32) {
                base = (hwaddr)get_field(env->vsatp, SATP32_PPN) << PGSHIFT;
                vm = get_field(env->vsatp, SATP32_MODE);
            } else {
                base = (hwaddr)get_field(env->vsatp, SATP64_PPN) << PGSHIFT;
                vm = get_field(env->vsatp, SATP64_MODE);
            }
        } else {
            if (riscv_cpu_mxl(env) == MXL_RV32) {
                base = (hwaddr)get_field(env->satp, SATP32_PPN) << PGSHIFT;
                vm = get_field(env->satp, SATP32_MODE);
            } else {
                base = (hwaddr)get_field(env->satp, SATP64_PPN) << PGSHIFT;
                vm = get_field(env->satp, SATP64_MODE);
            }
        }
        widened = 0;
    } else {
        if (riscv_cpu_mxl(env) == MXL_RV32) {
            base = (hwaddr)get_field(env->hgatp, SATP32_PPN) << PGSHIFT;
            vm = get_field(env->hgatp, SATP32_MODE);
        } else {
            base = (hwaddr)get_field(env->hgatp, SATP64_PPN) << PGSHIFT;
            vm = get_field(env->hgatp, SATP64_MODE);
        }
        widened = 2;
    }
    /* status.SUM will be ignored if execute on background */
    sum = get_field(env->mstatus, MSTATUS_SUM) || use_background || is_debug;
    switch (vm) {
    case VM_1_10_SV32:
      levels = 2; ptidxbits = 10; ptesize = 4; break;
    case VM_1_10_SV39:
      levels = 3; ptidxbits = 9; ptesize = 8; break;
    case VM_1_10_SV48:
      levels = 4; ptidxbits = 9; ptesize = 8; break;
    case VM_1_10_SV57:
      levels = 5; ptidxbits = 9; ptesize = 8; break;
    case VM_1_10_MBARE:
        *physical = addr;
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        return TRANSLATE_SUCCESS;
    default:
      g_assert_not_reached();
    }

    CPUState *cs = env_cpu(env);
    int va_bits = PGSHIFT + levels * ptidxbits + widened;
    target_ulong mask, masked_msbs;

    if (TARGET_LONG_BITS > (va_bits - 1)) {
        mask = (1L << (TARGET_LONG_BITS - (va_bits - 1))) - 1;
    } else {
        mask = 0;
    }
    masked_msbs = (addr >> (va_bits - 1)) & mask;

    if (masked_msbs != 0 && masked_msbs != mask) {
        return TRANSLATE_FAIL;
    }

    int ptshift = (levels - 1) * ptidxbits;
    int i;

#if !TCG_OVERSIZED_GUEST
restart:
#endif
    for (i = 0; i < levels; i++, ptshift -= ptidxbits) {
        target_ulong idx;
        if (i == 0) {
            idx = (addr >> (PGSHIFT + ptshift)) &
                           ((1 << (ptidxbits + widened)) - 1);
        } else {
            idx = (addr >> (PGSHIFT + ptshift)) &
                           ((1 << ptidxbits) - 1);
        }

        /* check that physical address of PTE is legal */
        hwaddr pte_addr;

        if (two_stage && first_stage) {
            int vbase_prot;
            hwaddr vbase;

            /* Do the second stage translation on the base PTE address. */
            int vbase_ret = get_physical_address(env, &vbase, &vbase_prot,
                                                 base, NULL, MMU_DATA_LOAD,
                                                 mmu_idx, false, true,
                                                 is_debug);

            if (vbase_ret != TRANSLATE_SUCCESS) {
                if (fault_pte_addr) {
                    *fault_pte_addr = (base + idx * ptesize) >> 2;
                }
                return TRANSLATE_G_STAGE_FAIL;
            }

            pte_addr = vbase + idx * ptesize;
        } else {
            pte_addr = base + idx * ptesize;
        }

        int pmp_prot;
        int pmp_ret = get_physical_address_pmp(env, &pmp_prot, NULL, pte_addr,
                                               sizeof(target_ulong),
                                               MMU_DATA_LOAD, PRV_S);
        if (pmp_ret != TRANSLATE_SUCCESS) {
            return TRANSLATE_PMP_FAIL;
        }

        target_ulong pte;
        if (riscv_cpu_mxl(env) == MXL_RV32) {
            pte = address_space_ldl(cs->as, pte_addr, attrs, &res);
        } else {
            pte = address_space_ldq(cs->as, pte_addr, attrs, &res);
        }

        if (res != MEMTX_OK) {
            return TRANSLATE_FAIL;
        }

        if (riscv_cpu_sxl(env) == MXL_RV32) {
            ppn = pte >> PTE_PPN_SHIFT;
        } else if (cpu->cfg.ext_svpbmt || cpu->cfg.ext_svnapot) {
            ppn = (pte & (target_ulong)PTE_PPN_MASK) >> PTE_PPN_SHIFT;
        } else {
            ppn = pte >> PTE_PPN_SHIFT;
            if ((pte & ~(target_ulong)PTE_PPN_MASK) >> PTE_PPN_SHIFT) {
                return TRANSLATE_FAIL;
            }
        }

        if (!(pte & PTE_V)) {
            /* Invalid PTE */
            return TRANSLATE_FAIL;
        } else if (!cpu->cfg.ext_svpbmt && (pte & PTE_PBMT)) {
            return TRANSLATE_FAIL;
        } else if (!(pte & (PTE_R | PTE_W | PTE_X))) {
            /* Inner PTE, continue walking */
            if (pte & (PTE_D | PTE_A | PTE_U | PTE_ATTR)) {
                return TRANSLATE_FAIL;
            }
            base = ppn << PGSHIFT;
        } else if ((pte & (PTE_R | PTE_W | PTE_X)) == PTE_W) {
            /* Reserved leaf PTE flags: PTE_W */
            return TRANSLATE_FAIL;
        } else if ((pte & (PTE_R | PTE_W | PTE_X)) == (PTE_W | PTE_X)) {
            /* Reserved leaf PTE flags: PTE_W + PTE_X */
            return TRANSLATE_FAIL;
        } else if ((pte & PTE_U) && ((mode != PRV_U) &&
                   (!sum || access_type == MMU_INST_FETCH))) {
            /* User PTE flags when not U mode and mstatus.SUM is not set,
               or the access type is an instruction fetch */
            return TRANSLATE_FAIL;
        } else if (!(pte & PTE_U) && (mode != PRV_S)) {
            /* Supervisor PTE flags when not S mode */
            return TRANSLATE_FAIL;
        } else if (ppn & ((1ULL << ptshift) - 1)) {
            /* Misaligned PPN */
            return TRANSLATE_FAIL;
        } else if (access_type == MMU_DATA_LOAD && !((pte & PTE_R) ||
                   ((pte & PTE_X) && mxr))) {
            /* Read access check failed */
            return TRANSLATE_FAIL;
        } else if (access_type == MMU_DATA_STORE && !(pte & PTE_W)) {
            /* Write access check failed */
            return TRANSLATE_FAIL;
        } else if (access_type == MMU_INST_FETCH && !(pte & PTE_X)) {
            /* Fetch access check failed */
            return TRANSLATE_FAIL;
        } else {
            /* if necessary, set accessed and dirty bits. */
            target_ulong updated_pte = pte | PTE_A |
                (access_type == MMU_DATA_STORE ? PTE_D : 0);

            /* Page table updates need to be atomic with MTTCG enabled */
            if (updated_pte != pte) {
                /*
                 * - if accessed or dirty bits need updating, and the PTE is
                 *   in RAM, then we do so atomically with a compare and swap.
                 * - if the PTE is in IO space or ROM, then it can't be updated
                 *   and we return TRANSLATE_FAIL.
                 * - if the PTE changed by the time we went to update it, then
                 *   it is no longer valid and we must re-walk the page table.
                 */
                MemoryRegion *mr;
                hwaddr l = sizeof(target_ulong), addr1;
                mr = address_space_translate(cs->as, pte_addr,
                    &addr1, &l, false, MEMTXATTRS_UNSPECIFIED);
                if (memory_region_is_ram(mr)) {
                    target_ulong *pte_pa =
                        qemu_map_ram_ptr(mr->ram_block, addr1);
#if TCG_OVERSIZED_GUEST
                    /* MTTCG is not enabled on oversized TCG guests so
                     * page table updates do not need to be atomic */
                    *pte_pa = pte = updated_pte;
#else
                    target_ulong old_pte =
                        qatomic_cmpxchg(pte_pa, pte, updated_pte);
                    if (old_pte != pte) {
                        goto restart;
                    } else {
                        pte = updated_pte;
                    }
#endif
                } else {
                    /* misconfigured PTE in ROM (AD bits are not preset) or
                     * PTE is in IO space and can't be updated atomically */
                    return TRANSLATE_FAIL;
                }
            }

            /* for superpage mappings, make a fake leaf PTE for the TLB's
               benefit. */
            target_ulong vpn = addr >> PGSHIFT;

            if (cpu->cfg.ext_svnapot && (pte & PTE_N)) {
                napot_bits = ctzl(ppn) + 1;
                if ((i != (levels - 1)) || (napot_bits != 4)) {
                    return TRANSLATE_FAIL;
                }
            }

            napot_mask = (1 << napot_bits) - 1;
            *physical = (((ppn & ~napot_mask) | (vpn & napot_mask) |
                          (vpn & (((target_ulong)1 << ptshift) - 1))
                         ) << PGSHIFT) | (addr & ~TARGET_PAGE_MASK);

            /* set permissions on the TLB entry */
            if ((pte & PTE_R) || ((pte & PTE_X) && mxr)) {
                *prot |= PAGE_READ;
            }
            if ((pte & PTE_X)) {
                *prot |= PAGE_EXEC;
            }
            /* add write permission on stores or if the page is already dirty,
               so that we TLB miss on later writes to update the dirty bit */
            if ((pte & PTE_W) &&
                    (access_type == MMU_DATA_STORE || (pte & PTE_D))) {
                *prot |= PAGE_WRITE;
            }
            return TRANSLATE_SUCCESS;
        }
    }
    return TRANSLATE_FAIL;
}

static void raise_mmu_exception(CPURISCVState *env, target_ulong address,
                                MMUAccessType access_type, bool pmp_violation,
                                bool first_stage, bool two_stage)
{
    CPUState *cs = env_cpu(env);
    int page_fault_exceptions, vm;
    uint64_t stap_mode;

    if (riscv_cpu_mxl(env) == MXL_RV32) {
        stap_mode = SATP32_MODE;
    } else {
        stap_mode = SATP64_MODE;
    }

    if (first_stage) {
        vm = get_field(env->satp, stap_mode);
    } else {
        vm = get_field(env->hgatp, stap_mode);
    }

    page_fault_exceptions = vm != VM_1_10_MBARE && !pmp_violation;

    switch (access_type) {
    case MMU_INST_FETCH:
        if (riscv_cpu_virt_enabled(env) && !first_stage) {
            cs->exception_index = RISCV_EXCP_INST_GUEST_PAGE_FAULT;
        } else {
            cs->exception_index = page_fault_exceptions ?
                RISCV_EXCP_INST_PAGE_FAULT : RISCV_EXCP_INST_ACCESS_FAULT;
        }
        break;
    case MMU_DATA_LOAD:
        if (two_stage && !first_stage) {
            cs->exception_index = RISCV_EXCP_LOAD_GUEST_ACCESS_FAULT;
        } else {
            cs->exception_index = page_fault_exceptions ?
                RISCV_EXCP_LOAD_PAGE_FAULT : RISCV_EXCP_LOAD_ACCESS_FAULT;
        }
        break;
    case MMU_DATA_STORE:
        if (two_stage && !first_stage) {
            cs->exception_index = RISCV_EXCP_STORE_GUEST_AMO_ACCESS_FAULT;
        } else {
            cs->exception_index = page_fault_exceptions ?
                RISCV_EXCP_STORE_PAGE_FAULT : RISCV_EXCP_STORE_AMO_ACCESS_FAULT;
        }
        break;
    default:
        g_assert_not_reached();
    }
    env->badaddr = address;
    env->two_stage_lookup = two_stage;
}

hwaddr riscv_cpu_get_phys_page_debug(CPUState *cs, vaddr addr)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    hwaddr phys_addr;
    int prot;
    int mmu_idx = cpu_mmu_index(&cpu->env, false);

    if (get_physical_address(env, &phys_addr, &prot, addr, NULL, 0, mmu_idx,
                             true, riscv_cpu_virt_enabled(env), true)) {
        return -1;
    }

    if (riscv_cpu_virt_enabled(env)) {
        if (get_physical_address(env, &phys_addr, &prot, phys_addr, NULL,
                                 0, mmu_idx, false, true, true)) {
            return -1;
        }
    }

    return phys_addr & TARGET_PAGE_MASK;
}

void riscv_cpu_do_transaction_failed(CPUState *cs, hwaddr physaddr,
                                     vaddr addr, unsigned size,
                                     MMUAccessType access_type,
                                     int mmu_idx, MemTxAttrs attrs,
                                     MemTxResult response, uintptr_t retaddr)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;

    if (access_type == MMU_DATA_STORE) {
        cs->exception_index = RISCV_EXCP_STORE_AMO_ACCESS_FAULT;
    } else if (access_type == MMU_DATA_LOAD) {
        cs->exception_index = RISCV_EXCP_LOAD_ACCESS_FAULT;
    } else {
        cs->exception_index = RISCV_EXCP_INST_ACCESS_FAULT;
    }

    env->badaddr = addr;
    env->two_stage_lookup = riscv_cpu_virt_enabled(env) ||
                            riscv_cpu_two_stage_lookup(mmu_idx);
    riscv_raise_exception(&cpu->env, cs->exception_index, retaddr);
}

void riscv_cpu_do_unaligned_access(CPUState *cs, vaddr addr,
                                   MMUAccessType access_type, int mmu_idx,
                                   uintptr_t retaddr)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    switch (access_type) {
    case MMU_INST_FETCH:
        cs->exception_index = RISCV_EXCP_INST_ADDR_MIS;
        break;
    case MMU_DATA_LOAD:
        cs->exception_index = RISCV_EXCP_LOAD_ADDR_MIS;
        break;
    case MMU_DATA_STORE:
        cs->exception_index = RISCV_EXCP_STORE_AMO_ADDR_MIS;
        break;
    default:
        g_assert_not_reached();
    }
    env->badaddr = addr;
    env->two_stage_lookup = riscv_cpu_virt_enabled(env) ||
                            riscv_cpu_two_stage_lookup(mmu_idx);
    riscv_raise_exception(env, cs->exception_index, retaddr);
}

bool riscv_cpu_tlb_fill(CPUState *cs, vaddr address, int size,
                        MMUAccessType access_type, int mmu_idx,
                        bool probe, uintptr_t retaddr)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    vaddr im_address;
    hwaddr pa = 0;
    int prot, prot2, prot_pmp;
    bool pmp_violation = false;
    bool first_stage_error = true;
    bool two_stage_lookup = false;
    int ret = TRANSLATE_FAIL;
    int mode = mmu_idx;
    /* default TLB page size */
    target_ulong tlb_size = TARGET_PAGE_SIZE;

    env->guest_phys_fault_addr = 0;

    qemu_log_mask(CPU_LOG_MMU, "%s ad %" VADDR_PRIx " rw %d mmu_idx %d\n",
                  __func__, address, access_type, mmu_idx);

    /* MPRV does not affect the virtual-machine load/store
       instructions, HLV, HLVX, and HSV. */
    if (riscv_cpu_two_stage_lookup(mmu_idx)) {
        mode = get_field(env->hstatus, HSTATUS_SPVP);
    } else if (mode == PRV_M && access_type != MMU_INST_FETCH &&
               get_field(env->mstatus, MSTATUS_MPRV)) {
        mode = get_field(env->mstatus, MSTATUS_MPP);
        if (riscv_has_ext(env, RVH) && get_field(env->mstatus, MSTATUS_MPV)) {
            two_stage_lookup = true;
        }
    }

    if (riscv_cpu_virt_enabled(env) ||
        ((riscv_cpu_two_stage_lookup(mmu_idx) || two_stage_lookup) &&
         access_type != MMU_INST_FETCH)) {
        /* Two stage lookup */
        ret = get_physical_address(env, &pa, &prot, address,
                                   &env->guest_phys_fault_addr, access_type,
                                   mmu_idx, true, true, false);

        /*
         * A G-stage exception may be triggered during two state lookup.
         * And the env->guest_phys_fault_addr has already been set in
         * get_physical_address().
         */
        if (ret == TRANSLATE_G_STAGE_FAIL) {
            first_stage_error = false;
            access_type = MMU_DATA_LOAD;
        }

        qemu_log_mask(CPU_LOG_MMU,
                      "%s 1st-stage address=%" VADDR_PRIx " ret %d physical "
                      TARGET_FMT_plx " prot %d\n",
                      __func__, address, ret, pa, prot);

        if (ret == TRANSLATE_SUCCESS) {
            /* Second stage lookup */
            im_address = pa;

            ret = get_physical_address(env, &pa, &prot2, im_address, NULL,
                                       access_type, mmu_idx, false, true,
                                       false);

            qemu_log_mask(CPU_LOG_MMU,
                    "%s 2nd-stage address=%" VADDR_PRIx " ret %d physical "
                    TARGET_FMT_plx " prot %d\n",
                    __func__, im_address, ret, pa, prot2);

            prot &= prot2;

            if (ret == TRANSLATE_SUCCESS) {
                ret = get_physical_address_pmp(env, &prot_pmp, &tlb_size, pa,
                                               size, access_type, mode);

                qemu_log_mask(CPU_LOG_MMU,
                              "%s PMP address=" TARGET_FMT_plx " ret %d prot"
                              " %d tlb_size " TARGET_FMT_lu "\n",
                              __func__, pa, ret, prot_pmp, tlb_size);

                prot &= prot_pmp;
            }

            if (ret != TRANSLATE_SUCCESS) {
                /*
                 * Guest physical address translation failed, this is a HS
                 * level exception
                 */
                first_stage_error = false;
                env->guest_phys_fault_addr = (im_address |
                                              (address &
                                               (TARGET_PAGE_SIZE - 1))) >> 2;
            }
        }
    } else {
        /* Single stage lookup */
        ret = get_physical_address(env, &pa, &prot, address, NULL,
                                   access_type, mmu_idx, true, false, false);

        qemu_log_mask(CPU_LOG_MMU,
                      "%s address=%" VADDR_PRIx " ret %d physical "
                      TARGET_FMT_plx " prot %d\n",
                      __func__, address, ret, pa, prot);

        if (ret == TRANSLATE_SUCCESS) {
            ret = get_physical_address_pmp(env, &prot_pmp, &tlb_size, pa,
                                           size, access_type, mode);

            qemu_log_mask(CPU_LOG_MMU,
                          "%s PMP address=" TARGET_FMT_plx " ret %d prot"
                          " %d tlb_size " TARGET_FMT_lu "\n",
                          __func__, pa, ret, prot_pmp, tlb_size);

            prot &= prot_pmp;
        }
    }

    if (ret == TRANSLATE_PMP_FAIL) {
        pmp_violation = true;
    }

    if (ret == TRANSLATE_SUCCESS) {
        tlb_set_page(cs, address & ~(tlb_size - 1), pa & ~(tlb_size - 1),
                     prot, mmu_idx, tlb_size);
        return true;
    } else if (probe) {
        return false;
    } else {
        raise_mmu_exception(env, address, access_type, pmp_violation,
                            first_stage_error,
                            riscv_cpu_virt_enabled(env) ||
                                riscv_cpu_two_stage_lookup(mmu_idx));
        riscv_raise_exception(env, cs->exception_index, retaddr);
    }

    return true;
}
#endif /* !CONFIG_USER_ONLY */

/*
 * Handle Traps
 *
 * Adapted from Spike's processor_t::take_trap.
 *
 */
void riscv_cpu_do_interrupt(CPUState *cs)
{
#if !defined(CONFIG_USER_ONLY)

    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    bool write_gva = false;
    uint64_t s;

    /* cs->exception is 32-bits wide unlike mcause which is XLEN-bits wide
     * so we mask off the MSB and separate into trap type and cause.
     */
    bool async = !!(cs->exception_index & RISCV_EXCP_INT_FLAG);
    target_ulong cause = cs->exception_index & RISCV_EXCP_INT_MASK;
    uint64_t deleg = async ? env->mideleg : env->medeleg;
    target_ulong tval = 0;
    target_ulong htval = 0;
    target_ulong mtval2 = 0;

    if  (cause == RISCV_EXCP_SEMIHOST) {
        if (env->priv >= PRV_S) {
            env->gpr[xA0] = do_common_semihosting(cs);
            env->pc += 4;
            return;
        }
        cause = RISCV_EXCP_BREAKPOINT;
    }

    if (!async) {
        /* set tval to badaddr for traps with address information */
        switch (cause) {
        case RISCV_EXCP_INST_GUEST_PAGE_FAULT:
        case RISCV_EXCP_LOAD_GUEST_ACCESS_FAULT:
        case RISCV_EXCP_STORE_GUEST_AMO_ACCESS_FAULT:
        case RISCV_EXCP_INST_ADDR_MIS:
        case RISCV_EXCP_INST_ACCESS_FAULT:
        case RISCV_EXCP_LOAD_ADDR_MIS:
        case RISCV_EXCP_STORE_AMO_ADDR_MIS:
        case RISCV_EXCP_LOAD_ACCESS_FAULT:
        case RISCV_EXCP_STORE_AMO_ACCESS_FAULT:
        case RISCV_EXCP_INST_PAGE_FAULT:
        case RISCV_EXCP_LOAD_PAGE_FAULT:
        case RISCV_EXCP_STORE_PAGE_FAULT:
            write_gva = true;
            tval = env->badaddr;
            break;
        case RISCV_EXCP_ILLEGAL_INST:
            tval = env->bins;
            break;
        default:
            break;
        }
        /* ecall is dispatched as one cause so translate based on mode */
        if (cause == RISCV_EXCP_U_ECALL) {
            assert(env->priv <= 3);

            if (env->priv == PRV_M) {
                cause = RISCV_EXCP_M_ECALL;
            } else if (env->priv == PRV_S && riscv_cpu_virt_enabled(env)) {
                cause = RISCV_EXCP_VS_ECALL;
            } else if (env->priv == PRV_S && !riscv_cpu_virt_enabled(env)) {
                cause = RISCV_EXCP_S_ECALL;
            } else if (env->priv == PRV_U) {
                cause = RISCV_EXCP_U_ECALL;
            }
        }
    }

    trace_riscv_trap(env->mhartid, async, cause, env->pc, tval,
                     riscv_cpu_get_trap_name(cause, async));

    qemu_log_mask(CPU_LOG_INT,
                  "%s: hart:"TARGET_FMT_ld", async:%d, cause:"TARGET_FMT_lx", "
                  "epc:0x"TARGET_FMT_lx", tval:0x"TARGET_FMT_lx", desc=%s\n",
                  __func__, env->mhartid, async, cause, env->pc, tval,
                  riscv_cpu_get_trap_name(cause, async));

    if (env->priv <= PRV_S &&
            cause < TARGET_LONG_BITS && ((deleg >> cause) & 1)) {
        /* handle the trap in S-mode */
        if (riscv_has_ext(env, RVH)) {
            uint64_t hdeleg = async ? env->hideleg : env->hedeleg;

            if (riscv_cpu_virt_enabled(env) && ((hdeleg >> cause) & 1)) {
                /* Trap to VS mode */
                /*
                 * See if we need to adjust cause. Yes if its VS mode interrupt
                 * no if hypervisor has delegated one of hs mode's interrupt
                 */
                if (cause == IRQ_VS_TIMER || cause == IRQ_VS_SOFT ||
                    cause == IRQ_VS_EXT) {
                    cause = cause - 1;
                }
                write_gva = false;
            } else if (riscv_cpu_virt_enabled(env)) {
                /* Trap into HS mode, from virt */
                riscv_cpu_swap_hypervisor_regs(env);
                env->hstatus = set_field(env->hstatus, HSTATUS_SPVP,
                                         env->priv);
                env->hstatus = set_field(env->hstatus, HSTATUS_SPV,
                                         riscv_cpu_virt_enabled(env));


                htval = env->guest_phys_fault_addr;

                riscv_cpu_set_virt_enabled(env, 0);
            } else {
                /* Trap into HS mode */
                env->hstatus = set_field(env->hstatus, HSTATUS_SPV, false);
                htval = env->guest_phys_fault_addr;
                write_gva = false;
            }
            env->hstatus = set_field(env->hstatus, HSTATUS_GVA, write_gva);
        }

        s = env->mstatus;
        s = set_field(s, MSTATUS_SPIE, get_field(s, MSTATUS_SIE));
        s = set_field(s, MSTATUS_SPP, env->priv);
        s = set_field(s, MSTATUS_SIE, 0);
        env->mstatus = s;
        env->scause = cause | ((target_ulong)async << (TARGET_LONG_BITS - 1));
        env->sepc = env->pc;
        env->stval = tval;
        env->htval = htval;
        env->pc = (env->stvec >> 2 << 2) +
            ((async && (env->stvec & 3) == 1) ? cause * 4 : 0);
        riscv_cpu_set_mode(env, PRV_S);
    } else {
        /* handle the trap in M-mode */
        if (riscv_has_ext(env, RVH)) {
            if (riscv_cpu_virt_enabled(env)) {
                riscv_cpu_swap_hypervisor_regs(env);
            }
            env->mstatus = set_field(env->mstatus, MSTATUS_MPV,
                                     riscv_cpu_virt_enabled(env));
            if (riscv_cpu_virt_enabled(env) && tval) {
                env->mstatus = set_field(env->mstatus, MSTATUS_GVA, 1);
            }

            mtval2 = env->guest_phys_fault_addr;

            /* Trapping to M mode, virt is disabled */
            riscv_cpu_set_virt_enabled(env, 0);
        }

        s = env->mstatus;
        s = set_field(s, MSTATUS_MPIE, get_field(s, MSTATUS_MIE));
        s = set_field(s, MSTATUS_MPP, env->priv);
        s = set_field(s, MSTATUS_MIE, 0);
        env->mstatus = s;
        env->mcause = cause | ~(((target_ulong)-1) >> async);
        env->mepc = env->pc;
        env->mtval = tval;
        env->mtval2 = mtval2;
        env->pc = (env->mtvec >> 2 << 2) +
            ((async && (env->mtvec & 3) == 1) ? cause * 4 : 0);
        riscv_cpu_set_mode(env, PRV_M);
    }

    /* NOTE: it is not necessary to yield load reservations here. It is only
     * necessary for an SC from "another hart" to cause a load reservation
     * to be yielded. Refer to the memory consistency model section of the
     * RISC-V ISA Specification.
     */

    env->two_stage_lookup = false;
#endif
    cs->exception_index = RISCV_EXCP_NONE; /* mark handled to qemu */
}
