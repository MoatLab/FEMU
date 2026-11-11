/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Raw bit error model of host reads (rber_ppb).
 *
 * A synthetic, uncalibrated model of the read tail that retries and soft
 * decode cause. Each codeword of a page passes or fails each decode attempt
 * with a chance from a Poisson CDF of its expected bit errors. A failed
 * attempt costs one more page read on the same LUN and channel. A codeword
 * that no decode corrects fails the read; the model never changes data.
 *
 *   lambda   = min(rber * 2^(PE/pe_d + age/age_d + reads/rd_d) * bits, cap)
 *   lambda_k = lambda * (f + (1 - f) * gain^-k)       k = 0 .. rr_steps
 *   codeword passes attempt k when u < F(hard_bits; lambda_k)
 *   soft decode passes when u < F(soft_bits; lambda_rr_steps)
 */

#include "qemu/osdep.h"
#include <math.h>
#include "ftl.h"
#include "ftl-internal.h"
#include "ftl-rber-math.h"

/*
 * The next decode draw in [0, 1): the top 53 bits of the generator, or the
 * next value of a qtest script. A script that runs short gives 1.0, which
 * fails every attempt, and is counted.
 */
static double rber_draw(struct ssd *ssd)
{
    if (unlikely(ssd->rber_scripted)) {
        if (ssd->rber_script_pos < ssd->rber_script_len) {
            return ssd->rber_script[ssd->rber_script_pos++];
        }
        ssd->rber_script_short++;
        return 1.0;
    }
    return rber_unit(rber_splitmix(&ssd->rber_rng));
}

/* ln(j) for j up to the largest threshold, filled once at realize */
static double rber_logj[FTL_RBER_BITS_MAX + 1];

void ftl_rber_init_tables(void)
{
    static gsize done;

    /* once per process: a running FTL may read the table meanwhile */
    if (g_once_init_enter(&done)) {
        rber_fill_logj(rber_logj, FTL_RBER_BITS_MAX);
        g_once_init_leave(&done, 1);
    }
}

/* the expected bit errors of one codeword of the page at @ppa */
static double rber_lambda(struct ssd *ssd, struct ppa *ppa, uint64_t now,
                          uint64_t reads)
{
    struct ssdparams *spp = &ssd->sp;
    struct line *line = get_line(ssd, ppa);
    uint64_t bits = (uint64_t)spp->ecc_cw_bytes * 8;
    double cap = fmin(4.0 * MAX(spp->ecc_hard_bits, spp->ecc_soft_bits),
                      (double)bits);
    double lg = log2(spp->rber_ppb * 1e-9) + log2((double)bits);

    if (spp->rber_pe_double) {
        lg += (double)get_blk(ssd, ppa)->erase_cnt / spp->rber_pe_double;
    }
    if (spp->rber_age_double_sec) {
        uint64_t from = spp->pd_open_age ? line->open_time : line->close_time;
        double age = (double)ssd_data_age_ns(ssd, from, now) /
                     NANOSECONDS_PER_SECOND;

        lg += age / spp->rber_age_double_sec;
    }
    if (spp->rber_read_double) {
        lg += (double)reads / spp->rber_read_double;
    }
    /* compare in log2 so a large exponent never overflows exp2() */
    return lg >= log2(cap) ? cap : exp2(lg);
}

/*
 * ssd_rber_read - extra decode work of one host page read
 * @done: when the first read of the page ends
 * @reads: block reads before this one
 *
 * Draws the decode outcome of each codeword, then books each retry and soft
 * pass as a page read after the one before. Returns the time the page data
 * is ready.
 *
 * With rrl, the Read Recovery Level bounds the recovery: level 9 has no
 * soft decode, level 15 (Fast Fail) one hard decode. A codeword that no
 * decode corrects fails the read, at every level: ssd_read() sees
 * rber_failed. rber_timing_only keeps the old rule, which charges the
 * time and lets the read pass.
 */
uint64_t ssd_rber_read(struct ssd *ssd, struct ppa *ppa, const NandLoc *loc,
                       uint64_t done, uint64_t reads)
{
    struct ssdparams *spp = &ssd->sp;
    uint32_t cws = (uint64_t)spp->secs_per_pg * spp->secsz / spp->ecc_cw_bytes;
    double lam = rber_lambda(ssd, ppa, done, reads);
    double f = spp->rr_floor_pct / 100.0;
    double hard[FTL_RBER_STEPS_MAX + 1];
    double soft = 0;
    uint64_t first = done;
    uint32_t retries = 0;
    bool need_soft = false;
    bool limit = false;
    double att = 1.0;
    int level = ssd->n->rrl && ssd->rrl_read ?
                qatomic_read(&ssd->n->rrl_level) : NVME_RRL_DEFAULT;
    uint32_t steps = level >= NVME_RRL_FAST_FAIL ? 0 : spp->rr_steps;
    bool soft_ok = level <= NVME_RRL_DEFAULT && spp->ecc_soft_bits;

    for (uint32_t k = 0; k <= spp->rr_steps; k++) {
        hard[k] = rber_cdf(spp->ecc_hard_bits, lam * (f + (1 - f) * att),
                           rber_logj);
        att /= spp->rr_gain;
    }
    if (spp->ecc_soft_bits) {
        att *= spp->rr_gain;
        soft = rber_cdf(spp->ecc_soft_bits, lam * (f + (1 - f) * att),
                        rber_logj);
    }

    for (uint32_t i = 0; i < cws; i++) {
        uint32_t depth = steps;
        bool hard_ok = false;

        for (uint32_t k = 0; k <= steps; k++) {
            if (rber_pass(rber_draw(ssd), hard[k])) {
                depth = k;
                hard_ok = true;
                break;
            }
        }
        retries = MAX(retries, depth);
        if (hard_ok) {
            continue;
        }
        /*
         * Nothing corrected the codeword: the read fails, as on a drive
         * (Unrecovered Read Error), unless rber_timing_only keeps the old
         * rule that charges time only.
         */
        if (soft_ok) {
            need_soft = true;
            if (!rber_pass(rber_draw(ssd), soft)) {
                limit = true;
                ssd->rber_failed |= !ssd->sp.rber_timing_only;
            }
        } else if (level > NVME_RRL_DEFAULT) {
            /* the level stops here: the read fails */
            ssd->rber_failed = true;
            limit = true;
        } else {
            limit = true;
            ssd->rber_failed |= !ssd->sp.rber_timing_only;
        }
    }

    if (retries) {
        qatomic_set(&ssd->rber_ctr[0], ssd->rber_ctr[0] + 1);
        qatomic_set(&ssd->rber_ctr[1], ssd->rber_ctr[1] + retries);
    }
    if (need_soft) {
        qatomic_set(&ssd->rber_ctr[2], ssd->rber_ctr[2] + 1);
    }
    if ((retries || need_soft) && ssd->rber_recovered != UINT64_MAX) {
        qatomic_set(&ssd->rber_recovered, ssd->rber_recovered + 1);
    }
    if (limit) {
        qatomic_set(&ssd->rber_ctr[3], ssd->rber_ctr[3] + 1);
    }
    for (uint32_t k = 0; k < retries; k++) {
        done = ssd_media_read_pass(ssd, ppa, loc, done);
    }
    if (need_soft) {
        for (uint32_t s = 0; s < spp->rr_soft_senses; s++) {
            done = ssd_media_read_pass(ssd, ppa, loc, done);
        }
        done += spp->rr_soft_ns;
    }
    qatomic_set(&ssd->rber_last_extra_ns, done - first);
    return done;
}

/* the C0h counters; the FTL thread writes them, the main loop reads them */
void ssd_rber_counters(struct ssd *ssd, uint64_t out[4])
{
    for (int i = 0; i < 4; i++) {
        out[i] = ssd ? qatomic_read(&ssd->rber_ctr[i]) : 0;
    }
}
