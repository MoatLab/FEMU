/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/units.h"
#include "qemu/target-info.h"
#include "qemu/log.h"
#include "user/guest-base.h"
#include "user/mmap-min-addr.h"
#include "user/guest-base.h"
#include "user/guest-host.h"
#include "user/probe-guest-base.h"
#include "user/selfmap.h"
#include "exec/target_page.h"
#include <sys/shm.h>

/* Linux and FreeBSD use different flags to express NOREPLACE. */
#ifdef __FreeBSD__
#define MAP_FIXED_NOREPLACE  (MAP_FIXED | MAP_EXCL)
#endif

uintptr_t guest_base;
bool have_guest_base;

/**
 * pgb_try_mmap:
 * @addr: host start address
 * @addr_last: host last address
 * @keep: do not unmap the probe region
 *
 * Return 1 if [@addr, @addr_last] is not mapped in the host,
 * return 0 if it is not available to map, and -1 on mmap error.
 * If @keep, the region is left mapped on success, otherwise unmapped.
 */
static int pgb_try_mmap(uintptr_t addr, uintptr_t addr_last, bool keep)
{
    size_t size = addr_last - addr + 1;
    void *p = mmap((void *)addr, size, PROT_NONE,
                   MAP_ANONYMOUS | MAP_PRIVATE |
                   MAP_NORESERVE | MAP_FIXED_NOREPLACE, -1, 0);
    int ret;

    if (p == MAP_FAILED) {
        return errno == EEXIST ? 0 : -1;
    }
    ret = p == (void *)addr;
    if (!keep || !ret) {
        munmap(p, size);
    }
    return ret;
}

/**
 * pgb_try_mmap_skip_brk(uintptr_t addr, uintptr_t size, uintptr_t brk)
 * @addr: host address
 * @addr_last: host last address
 * @brk: host brk
 *
 * Like pgb_try_mmap, but additionally reserve some memory following brk.
 */
static int pgb_try_mmap_skip_brk(uintptr_t addr, uintptr_t addr_last,
                                 uintptr_t brk, bool keep)
{
    uintptr_t brk_last = brk + 16 * MiB - 1;

    /* Do not map anything close to the host brk. */
    if (addr <= brk_last && brk <= addr_last) {
        return 0;
    }
    return pgb_try_mmap(addr, addr_last, keep);
}

/**
 * pgb_try_mmap_set:
 * @ga: set of guest addrs
 * @base: guest_base
 * @brk: host brk
 *
 * Return true if all @ga can be mapped by the host at @base.
 * On success, retain the mapping at index 0 for reserved_va.
 */

typedef struct PGBAddrs {
    PGBRange bounds[3];
    int nbounds;
} PGBAddrs;

static bool pgb_try_mmap_set(const PGBAddrs *ga, uintptr_t base, uintptr_t brk)
{
    for (int i = ga->nbounds - 1; i >= 0; --i) {
        if (pgb_try_mmap_skip_brk(ga->bounds[i].lo + base,
                                  ga->bounds[i].hi + base,
                                  brk, i == 0 && reserved_va) <= 0) {
            return false;
        }
    }
    return true;
}

/**
 * pgb_addr_set:
 * @ga: output set of guest addrs
 * @image_range: fixed guest image addresses
 * @identity: create for identity mapping
 *
 * Fill in @ga with the image, COMMPAGE and NULL page.
 */
static bool pgb_addr_set(PGBAddrs *ga, const PGBRange *image_range,
                         const PGBRange *commpage_range, bool try_identity)
{
    int n;

    /*
     * With a low commpage, or a guest mapped very low,
     * we may not be able to use the identity map.
     */
    if (try_identity) {
        if (commpage_range && commpage_range->lo < mmap_min_addr) {
            return false;
        }
        if (image_range && image_range->lo < mmap_min_addr) {
            return false;
        }
    }

    memset(ga, 0, sizeof(*ga));
    n = 0;

    if (reserved_va) {
        ga->bounds[n].lo = try_identity ? mmap_min_addr : 0;
        ga->bounds[n].hi = reserved_va;
        n++;
        /* Low COMMPAGE and NULL handled by reserving from 0. */
    } else {
        /* Add any low COMMPAGE or NULL page. */
        if (!try_identity || (commpage_range && commpage_range->lo == 0)) {
            ga->bounds[n].lo = 0;
            ga->bounds[n].hi = TARGET_PAGE_SIZE - 1;
            n++;
        }

        /* Add the guest image for ET_EXEC. */
        if (image_range) {
            ga->bounds[n++] = *image_range;
        }
    }

    /* Add any high COMMPAGE not covered by reserved_va. */
    if (commpage_range && reserved_va < commpage_range->hi) {
        ga->bounds[n].lo = commpage_range->lo & qemu_real_host_page_mask();
        ga->bounds[n].hi = commpage_range->hi;
        n++;
    }

    ga->nbounds = n;
    return true;
}

static void pgb_fail_in_use(const char *image_name)
{
    error_report("%s: requires virtual address space that is in use "
                 "(omit the -B option or choose a different value)",
                 image_name);
    exit(EXIT_FAILURE);
}

static void pgb_fixed(const char *image_name, const PGBRange *image_range,
                      const PGBRange *commpage_range, uintptr_t align)
{
    PGBAddrs ga;
    uintptr_t brk = (uintptr_t)sbrk(0);

    if (!QEMU_IS_ALIGNED(guest_base, align)) {
        fprintf(stderr, "Requested guest base %p does not satisfy "
                "host minimum alignment (0x%" PRIxPTR ")\n",
                (void *)guest_base, align);
        exit(EXIT_FAILURE);
    }

    if (!pgb_addr_set(&ga, image_range, commpage_range, !guest_base)
        || !pgb_try_mmap_set(&ga, guest_base, brk)) {
        pgb_fail_in_use(image_name);
    }
}

/**
 * pgb_find_fallback:
 *
 * This is a fallback method for finding holes in the host address space
 * if we don't have the benefit of being able to access /proc/self/map.
 * It can potentially take a very long time as we can only dumbly iterate
 * up the host address space seeing if the allocation would work.
 */
static uintptr_t pgb_find_fallback(const PGBAddrs *ga, uintptr_t align,
                                   uintptr_t brk)
{
    /* TODO: come up with a better estimate of how much to skip. */
    uintptr_t skip = sizeof(uintptr_t) == 4 ? MiB : GiB;

    for (uintptr_t base = skip; ; base += skip) {
        base = ROUND_UP(base, align);
        if (pgb_try_mmap_set(ga, base, brk)) {
            return base;
        }
        if (base >= -skip) {
            return -1;
        }
    }
}

static uintptr_t pgb_try_itree(const PGBAddrs *ga, uintptr_t base,
                               IntervalTreeRoot *root)
{
    for (int i = ga->nbounds - 1; i >= 0; --i) {
        uintptr_t s = base + ga->bounds[i].lo;
        uintptr_t l = base + ga->bounds[i].hi;
        IntervalTreeNode *n;

        if (l < s) {
            /* Wraparound. Skip to advance S to mmap_min_addr. */
            return mmap_min_addr - s;
        }

        n = interval_tree_iter_first(root, s, l);
        if (n != NULL) {
            /* Conflict.  Skip to advance S to LAST + 1. */
            return n->last - s + 1;
        }
    }
    return 0;  /* success */
}

static uintptr_t pgb_find_itree(const PGBAddrs *ga, IntervalTreeRoot *root,
                                uintptr_t align, uintptr_t brk)
{
    uintptr_t last = sizeof(uintptr_t) == 4 ? MiB : GiB;
    uintptr_t base, skip;

    while (true) {
        base = ROUND_UP(last, align);
        if (base < last) {
            return -1;
        }

        skip = pgb_try_itree(ga, base, root);
        if (skip == 0) {
            break;
        }

        last = base + skip;
        if (last < base) {
            return -1;
        }
    }

    /*
     * We've chosen 'base' based on holes in the interval tree,
     * but we don't yet know if it is a valid host address.
     * Because it is the first matching hole, if the host addresses
     * are invalid we know there are no further matches.
     */
    return pgb_try_mmap_set(ga, base, brk) ? base : -1;
}

static void pgb_dynamic(const char *image_name, const PGBRange *image_range,
                        const PGBRange *commpage_range, uintptr_t align)
{
    IntervalTreeRoot *root;
    uintptr_t brk, ret;
    PGBAddrs ga;

    /* Try the identity map first. */
    if (pgb_addr_set(&ga, image_range, commpage_range, true)) {
        brk = (uintptr_t)sbrk(0);
        if (pgb_try_mmap_set(&ga, 0, brk)) {
            guest_base = 0;
            return;
        }
    }

    /*
     * Rebuild the address set for non-identity map.
     * This differs in the mapping of the guest NULL page.
     */
    pgb_addr_set(&ga, image_range, commpage_range, false);

    root = read_self_maps();

    /* Read brk after we've read the maps, which will malloc. */
    brk = (uintptr_t)sbrk(0);

    if (!root) {
        ret = pgb_find_fallback(&ga, align, brk);
    } else {
        /*
         * Reserve the area close to the host brk.
         * This will be freed with the rest of the tree.
         */
        IntervalTreeNode *b = g_new0(IntervalTreeNode, 1);
        b->start = brk;
        b->last = brk + 16 * MiB - 1;
        interval_tree_insert(b, root);

        ret = pgb_find_itree(&ga, root, align, brk);
        free_self_maps(root);
    }

    if (ret == -1) {
        int w = target_long_bits() / 4;

        error_report("%s: Unable to find a guest_base to satisfy all "
                     "guest address mapping requirements", image_name);

        for (int i = 0; i < ga.nbounds; ++i) {
            error_printf("  %0*" VADDR_PRIx "-%0*" VADDR_PRIx "\n",
                         w, ga.bounds[i].lo,
                         w, ga.bounds[i].hi);
        }
        exit(EXIT_FAILURE);
    }
    guest_base = ret;
}

void probe_guest_base(const char *image_name, const PGBRange *image_range,
                      const PGBRange *commpage_range)
{
    /* In order to use host shmat, we must be able to honor SHMLBA.  */
    uintptr_t align = MAX(SHMLBA, TARGET_PAGE_SIZE);

    /* Sanity check the guest binary. */
    if (reserved_va && image_range && image_range->hi > reserved_va) {
        error_report("%s: requires more than reserved virtual "
                     "address space (0x%" VADDR_PRIx " > 0x%lx)",
                     image_name, image_range->hi, reserved_va);
        exit(EXIT_FAILURE);
    }

    if (have_guest_base) {
        pgb_fixed(image_name, image_range, commpage_range, align);
    } else {
        pgb_dynamic(image_name, image_range, commpage_range, align);
    }

    assert(QEMU_IS_ALIGNED(guest_base, align));
    qemu_log_mask(CPU_LOG_PAGE, "Locating guest address space "
                  "@ 0x%" PRIx64 "\n", (uint64_t)guest_base);
}
