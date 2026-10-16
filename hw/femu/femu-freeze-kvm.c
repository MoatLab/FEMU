/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/host-utils.h"
#include "hw/core/cpu.h"
#include "system/kvm.h"
#include "femu-freeze.h"

#if defined(CONFIG_KVM) && defined(TARGET_I386)
#include <linux/kvm.h>

/*
 * The guest reads its time from the kvmclock and from the TSC. Both follow
 * the host clock, also while the vCPUs are stopped, so a stop alone hides
 * nothing. Setting the kvmclock back is not enough either: the guest vDSO
 * reads the pvclock page of vCPU 0, and KVM rewrites that page only when
 * vCPU 0 next enters the guest. A halted vCPU 0 keeps the old page, which
 * maps the TSC to the old kvmclock. So move the TSC of every vCPU back by
 * the span the kvmclock lost: the old page then reads the time a new one
 * does.
 *
 * KVM_SET_CLOCK installs its value at an instant of its own, so the span is
 * not known in advance. Read the clock with the host TSC before and after
 * the set: the host TSC runs on through the set, so the clock the guest
 * would have read at the second sample, less the clock it reads, is the
 * span. The guest TSC must run at the host rate, so a host cycle is a guest
 * cycle, and the kvmclock counts host cycles with the pvclock scale of
 * the host TSC rate, which KVM reports in kHz.
 */
#define FEMU_FREEZE_CLOCK_FLAGS (KVM_CLOCK_TSC_STABLE | KVM_CLOCK_HOST_TSC)
#define FEMU_FREEZE_MAX_SKEW_NS (10 * 1000 * 1000)

static struct {
    uint64_t clock;     /* the kvmclock at the stop */
    uint64_t tsc;       /* the host TSC at the stop */
    uint32_t frac;      /* the part of a cycle not yet moved, in 2^-32 */
    uint32_t mul;       /* the pvclock scale of the host TSC rate */
    int shift;
    int n;
    uint64_t *offset;   /* the TSC offset of each vCPU at the stop */
} fk;

static int femu_freeze_tsc_offset(CPUState *cpu, int ioctl, uint64_t *off)
{
    struct kvm_device_attr attr = {
        .group = KVM_VCPU_TSC_CTRL,
        .attr = KVM_VCPU_TSC_OFFSET,
        .addr = (uint64_t)(uintptr_t)off,
    };

    return kvm_vcpu_ioctl(cpu, ioctl, &attr);
}

/* read the kvmclock with the host TSC of the same instant */
static int femu_freeze_get_clock(struct kvm_clock_data *data)
{
    int ret;

    memset(data, 0, sizeof(*data));
    ret = kvm_vm_ioctl(kvm_state, KVM_GET_CLOCK, data);
    if (ret < 0) {
        return ret;
    }
    if ((data->flags & FEMU_FREEZE_CLOCK_FLAGS) != FEMU_FREEZE_CLOCK_FLAGS) {
        return -ENOTSUP;
    }
    return 0;
}

static int femu_freeze_set_clock(uint64_t clock)
{
    struct kvm_clock_data data = { .clock = clock };

    return kvm_vm_ioctl(kvm_state, KVM_SET_CLOCK, &data);
}

/*
 * The kvmclock converts host TSC cycles to ns as the guest pvclock does:
 * ns = ((cycles << shift) * mul) >> 32, with a right shift for a negative
 * shift. KVM derives mul and shift from the host TSC rate with
 * kvm_get_time_scale(); this is the same computation.
 */
static void femu_freeze_time_scale(uint64_t base_hz)
{
    uint64_t scaled64 = NANOSECONDS_PER_SECOND;
    uint64_t tps64 = base_hz;
    uint32_t tps32;
    int shift = 0;

    while (tps64 > scaled64 * 2 || tps64 & 0xffffffff00000000ULL) {
        tps64 >>= 1;
        shift--;
    }
    tps32 = (uint32_t)tps64;
    while (tps32 <= scaled64 || scaled64 & 0xffffffff00000000ULL) {
        if (scaled64 & 0xffffffff00000000ULL || tps32 & 0x80000000) {
            scaled64 >>= 1;
        } else {
            tps32 <<= 1;
        }
        shift++;
    }
    fk.shift = shift;
    fk.mul = (scaled64 << 32) / tps32;
}

/* pvclock_scale_delta(): ns in @cycles, rounded down as the guest does */
static uint64_t femu_freeze_scale(uint64_t cycles)
{
    uint64_t lo;
    uint64_t hi;

    cycles = fk.shift < 0 ? cycles >> -fk.shift : cycles << fk.shift;
    mulu64(&lo, &hi, cycles, fk.mul);
    return hi << 32 | lo >> 32;
}

/*
 * The inverse: the cycles in @ns, as a whole part and a 32-bit fraction.
 * Return false when the whole part does not fit 64 bits.
 */
static bool femu_freeze_cycles(uint64_t ns, uint64_t *whole, uint32_t *frac)
{
    uint64_t lo = 0;
    uint64_t hi = ns;

    /* ns * 2^64 / mul is the cycles in 32.32 fixed point, before the shift */
    divu128(&lo, &hi, fk.mul);
    if (fk.shift < 0) {
        if (hi >> (32 + fk.shift)) {
            return false;
        }
        hi = hi << -fk.shift | lo >> (64 + fk.shift);
        lo <<= -fk.shift;
    } else if (fk.shift > 0) {
        lo = lo >> fk.shift | hi << (64 - fk.shift);
        hi >>= fk.shift;
    }
    if (hi >> 32) {
        return false;
    }
    *whole = hi << 32 | lo >> 32;
    *frac = lo;
    return true;
}

/*
 * The kvmclock must have run at that rate over the stop, within 100 ppm and
 * the 2 ns the two samples round: else the host TSC rate is not the one
 * KVM reported, and the conversions above do not hold.
 */
static bool femu_freeze_rate_ok(uint64_t ns, uint64_t cycles)
{
    uint64_t want = femu_freeze_scale(cycles);
    uint64_t diff = ns > want ? ns - want : want - ns;

    return diff <= 2 + want / 10000;
}

/*
 * Static checks only. The kvmclock is not stable before the vCPUs first
 * run, so each stop checks that again.
 */
bool femu_freeze_kvm_check(Error **errp)
{
    struct kvm_device_attr attr = {
        .group = KVM_VCPU_TSC_CTRL,
        .attr = KVM_VCPU_TSC_OFFSET,
    };
    CPUState *cpu;
    int host_khz;

    if (!kvm_enabled()) {
        return true;
    }
    /* the capability lists the flags KVM_GET_CLOCK can return */
    if (!(kvm_check_extension(kvm_state, KVM_CAP_ADJUST_CLOCK) &
          KVM_CLOCK_HOST_TSC) ||
        !kvm_check_extension(kvm_state, KVM_CAP_VM_TSC_CONTROL)) {
        error_setg(errp, "csd_pause needs KVM_CLOCK_HOST_TSC and "
                   "KVM_CAP_VM_TSC_CONTROL (Linux 6.0 or later)");
        return false;
    }
    host_khz = kvm_vm_ioctl(kvm_state, KVM_GET_TSC_KHZ);
    if (host_khz > 0) {
        femu_freeze_time_scale(host_khz * 1000ULL);
    }
    CPU_FOREACH(cpu) {
        if (kvm_vcpu_ioctl(cpu, KVM_HAS_DEVICE_ATTR, &attr) < 0) {
            error_setg(errp, "csd_pause needs the KVM TSC offset attribute");
            return false;
        }
        if (host_khz <= 0 ||
            kvm_vcpu_ioctl(cpu, KVM_GET_TSC_KHZ) != host_khz) {
            error_setg(errp, "csd_pause needs the guest TSC at the host "
                       "rate; do not set tsc-frequency");
            return false;
        }
    }
    return true;
}

int femu_freeze_kvm_save(void)
{
    struct kvm_clock_data data;
    CPUState *cpu;
    int ret;
    int n = 0;

    if (!kvm_enabled()) {
        return 0;
    }
    ret = femu_freeze_get_clock(&data);
    if (ret < 0) {
        warn_report_once("femu: csd_pause skips a stop: the kvmclock is not "
                         "stable on a TSC host clock (%s)", strerror(-ret));
        return ret;
    }
    fk.clock = data.clock;
    fk.tsc = data.host_tsc;

    CPU_FOREACH(cpu) {
        n++;
    }
    if (fk.n != n) {
        fk.offset = g_renew(uint64_t, fk.offset, n);
        fk.n = n;
    }
    n = 0;
    CPU_FOREACH(cpu) {
        ret = femu_freeze_tsc_offset(cpu, KVM_GET_DEVICE_ATTR,
                                     &fk.offset[n++]);
        if (ret < 0) {
            warn_report_once("femu: csd_pause skips a stop: no TSC offset "
                             "(%s)", strerror(-ret));
            return ret;
        }
    }
    return 0;
}

/*
 * Hide the span since femu_freeze_kvm_save() from the guest, with the vCPUs
 * stopped. Return 0 and the span in ns, or -errno with the clocks as they
 * were. Once the clock is set the guest clocks agree only when every TSC
 * offset moves too; a failure from there on returns FEMU_FREEZE_KVM_FATAL,
 * since no set can restore the clock to the instant: the vCPUs must not run
 * on clocks that disagree.
 */
int femu_freeze_kvm_restore(uint64_t *span)
{
    struct kvm_clock_data c1;
    struct kvm_clock_data c2;
    uint64_t dh;
    uint64_t whole = 0;
    uint64_t cyc = 0;
    uint64_t off;
    uint32_t frac = 0;
    int64_t dc;
    int64_t lost = 0;
    int64_t least;
    CPUState *cpu;
    int ret;
    int i = 0;

    *span = 0;
    if (!kvm_enabled()) {
        return 0;
    }
    ret = femu_freeze_get_clock(&c1);
    if (ret == 0 && (c1.clock <= fk.clock || c1.host_tsc <= fk.tsc ||
                     !femu_freeze_rate_ok(c1.clock - fk.clock,
                                          c1.host_tsc - fk.tsc))) {
        ret = -ERANGE;
    }
    if (ret == 0) {
        ret = femu_freeze_set_clock(fk.clock);
    }
    if (ret < 0) {
        warn_report_once("femu: csd_pause shows a stop to the guest: %s",
                         strerror(-ret));
        return ret;
    }

    /*
     * Before the set the clock was C1 at host cycle H1; the guest would now
     * read C1 + scale(H2 - H1). It reads C2, so it lost that less C2. In
     * cycles, with no rounding of the scale to ns:
     *
     *   cycles = (H2 - H1) + (C1 - C2) / rate
     *
     * The fraction carries to the next stop. What stays is the rounding
     * of the two clock samples, about 1 ns a stop; an old pvclock page
     * keeps the sum until its vCPU runs again. The set came after the
     * first sample, so the loss is at least C1 - C0.
     */
    ret = femu_freeze_get_clock(&c2);
    if (ret == 0) {
        dh = c2.host_tsc - c1.host_tsc;
        dc = (int64_t)(c1.clock - c2.clock);
        lost = dc + (int64_t)femu_freeze_scale(dh);
        least = (int64_t)(c1.clock - fk.clock) - 1000;
        if (lost < least ||
            !femu_freeze_cycles(dc < 0 ? -dc : dc, &whole, &frac)) {
            ret = -ERANGE;
        }
    }
    if (ret == 0) {
        if (dc >= 0) {
            cyc = dh + whole;
        } else {
            /* dh - (whole + frac / 2^32) */
            cyc = dh - whole - (frac != 0);
            frac = -frac;
        }
        cyc += ((uint64_t)fk.frac + frac) >> 32;
        frac += fk.frac;
    }

    CPU_FOREACH(cpu) {
        if (ret < 0) {
            break;
        }
        off = fk.offset[i++] - cyc;
        ret = femu_freeze_tsc_offset(cpu, KVM_SET_DEVICE_ATTR, &off);
    }
    if (ret < 0) {
        error_report("femu: csd_pause could not move the guest TSC with "
                     "the kvmclock: %s", strerror(-ret));
        return FEMU_FREEZE_KVM_FATAL;
    }
    fk.frac = frac;
    *span = lost;
    return 0;
}

#else

bool femu_freeze_kvm_check(Error **errp)
{
    if (kvm_enabled()) {
        error_setg(errp, "csd_pause supports KVM only on x86");
        return false;
    }
    return true;
}

int femu_freeze_kvm_save(void)
{
    return 0;
}

int femu_freeze_kvm_restore(uint64_t *span)
{
    *span = 0;
    return 0;
}

#endif
