/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Silent data corruption faults (sdc=on) and the internal LBA check
 * (e2e_check), OCP 2.7 E2E-4 and E2E-5.
 *
 * With power_loss the FTL thread installs every write's payload, one page
 * at a time, so a fault is drawn there (femu_sdc_fault()). It leaves wrong
 * bytes in the store, as a media fault would:
 *
 *   flip       the page is written with one bit changed
 *   lost       the old bytes stay, though the write completes
 *   misdirect  the old bytes stay; the new ones land in the next page
 *
 * Each namespace marks the blocks a fault spoiled. A drive keeps an LBA
 * tag and a version with each block; the mark stands in for a tag or
 * version that no longer matches. With e2e_check every read of a marked
 * block fails with Unrecovered Read Error and counts in C0h Detected
 * Errors. Without it the read returns the wrong bytes with success: the
 * silent corruption the host must find itself. A later write of a block
 * clears its mark. This is a fault model with a known answer, not a
 * detector that could find corruption FEMU did not inject.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "qemu/cutils.h"
#include "nvme.h"

static const char *const sdc_names[] = {
    [FEMU_SDC_FLIP] = "flip",
    [FEMU_SDC_LOST] = "lost",
    [FEMU_SDC_MISDIRECT] = "misdirect",
};

static int sdc_kind_parse(const char *s)
{
    for (int i = FEMU_SDC_FLIP; i <= FEMU_SDC_MISDIRECT; i++) {
        if (!strcmp(s, sdc_names[i])) {
            return i;
        }
    }
    return strcmp(s, "mix") ? -1 : 0;
}

/* realize: check the properties */
bool femu_sdc_init(FemuCtrl *n, Error **errp)
{
    int kind = n->sdc_kind ? sdc_kind_parse(n->sdc_kind) : 0;

    if (!n->sdc) {
        if (n->sdc_ppm || n->sdc_kind) {
            error_setg(errp, "sdc_ppm and sdc_kind need sdc=on");
            return false;
        }
        return true;
    }
    if (!n->power_loss) {
        /* the FTL thread then installs every payload, one command at a time */
        error_setg(errp, "sdc needs power_loss=on");
        return false;
    }
    /*
     * awupf_lbas: a misdirected page is outside the transaction it would
     * have to roll back with.
     */
    if (n->durable_at_done || n->persist_file || n->awupf_lbas) {
        error_setg(errp, "sdc is not supported with %s",
                   n->durable_at_done ? "durable_at_done" :
                   n->persist_file ? "persist_file" : "awupf_lbas");
        return false;
    }
    if (n->sdc_ppm > 1000000 || kind < 0) {
        error_setg(errp, "sdc_ppm must be 0 to 1000000 and sdc_kind flip, "
                   "lost, misdirect or mix");
        return false;
    }
    n->sdc_kind_v = kind;
    n->sdc_rng = n->sdc_seed ? n->sdc_seed : 1;
    return true;
}

/* a namespace's marks, all clear; false when there is no memory */
bool femu_sdc_ns_alloc(NvmeNamespace *ns, uint64_t blks)
{
    g_free(ns->sdc);
    ns->sdc = NULL;
    if (!ns->ctrl->sdc) {
        return true;
    }
    ns->sdc = bitmap_try_new(blks);
    return ns->sdc || !blks;
}

/* blocks written whole or deallocated hold no spoiled data any more */
void femu_sdc_clear(NvmeNamespace *ns, uint64_t slba, uint64_t nlb)
{
    if (ns->sdc) {
        bitmap_clear(ns->sdc, slba, nlb);
    }
}

/*
 * A read of [@slba, @elba) fails: a block is uncorrectable, or the check
 * finds a spoiled one, the first of which goes to *@bad. Every read path
 * asks here (Read, Verify, Compare, Copy sources). Only the FTL thread
 * reaches the counters, as sdc needs power_loss; log readers load them.
 */
bool femu_lba_bad(NvmeNamespace *ns, uint64_t slba, uint64_t elba,
                  uint64_t *bad)
{
    FemuCtrl *n = ns->ctrl;
    uint64_t b = find_next_bit(ns->uncorrectable, elba, slba);
    uint32_t c0;

    if (b < elba) {
        *bad = b;
        return true;
    }
    if (!ns->sdc || !n->e2e_check) {
        return false;
    }
    b = find_next_bit(ns->sdc, elba, slba);
    if (b >= elba) {
        return false;
    }
    *bad = b;
    /* C0h holds 32 bits and stops at the top; SMART counts on */
    c0 = qatomic_read(&n->e2e_detected);
    if (c0 != UINT32_MAX) {
        qatomic_set(&n->e2e_detected, c0 + 1);
    }
    qatomic_set(&n->e2e_detected_all, qatomic_read(&n->e2e_detected_all) + 1);
    return true;
}

static uint64_t sdc_next(FemuCtrl *n)
{
    uint64_t x = n->sdc_rng;

    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    n->sdc_rng = x;
    return x;
}

/*
 * The FTL thread installs blocks [@slba, @elba) of one page: the fault
 * this install takes, 0 for none. *@flip_lba is the block a flip spoils.
 */
int femu_sdc_fault(NvmeNamespace *ns, uint64_t slba, uint64_t elba,
                   uint64_t *flip_lba)
{
    FemuCtrl *n = ns->ctrl;
    int kind;

    if (!ns->sdc || slba >= elba) {
        return 0;
    }
    *flip_lba = slba;
    /* x-sdc fills the slot only while it is empty, so it holds still here */
    kind = qatomic_load_acquire(&n->sdc_one_kind);
    if (kind) {
        uint64_t lba = n->sdc_one_lba;

        if (n->sdc_one_nsid == ns->id && lba >= slba && lba < elba) {
            *flip_lba = lba;
            qatomic_store_release(&n->sdc_one_kind, 0);
            return kind;
        }
    }
    if (!n->sdc_ppm || sdc_next(n) % 1000000 >= n->sdc_ppm) {
        return 0;
    }
    kind = n->sdc_kind_v ? n->sdc_kind_v : 1 + sdc_next(n) % 3;
    *flip_lba = slba + sdc_next(n) % (elba - slba);
    return kind;
}

/*
 * qtest: "<nsid>:<kind>:<lba>" puts one fault on the next install of lba,
 * into an empty slot only: the FTL thread owns a filled one.
 */
static void femu_sdc_test_set(Object *obj, const char *value, Error **errp)
{
    FemuCtrl *n = FEMU(obj);
    g_auto(GStrv) f = g_strsplit(value, ":", 0);
    NvmeNamespace *ns = NULL;
    uint64_t nsid = 0;
    uint64_t lba = 0;
    int k = -1;

    if (n->sdc && g_strv_length(f) == 3 &&
        !qemu_strtou64(f[0], NULL, 10, &nsid) && nsid <= UINT32_MAX &&
        !qemu_strtou64(f[2], NULL, 10, &lba)) {
        ns = nvme_ns(n, nsid);
        k = sdc_kind_parse(f[1]);
    }
    if (k <= 0 || !ns || !ns->sdc || lba >= ns->ns_blks) {
        error_setg(errp, "x-sdc needs sdc=on and <nsid>:<kind>:<lba> of a "
                   "namespace");
        return;
    }
    if (qatomic_load_acquire(&n->sdc_one_kind)) {
        error_setg(errp, "x-sdc: a fault is already waiting");
        return;
    }
    n->sdc_one_lba = lba;
    n->sdc_one_nsid = nsid;
    /* the FTL thread reads the kind first, then the rest */
    qatomic_store_release(&n->sdc_one_kind, k);
}

void femu_sdc_add_props(Object *obj)
{
    object_property_add_str(obj, "x-sdc", NULL, femu_sdc_test_set);
}
