/*
 * bbssd FTL page-mapping: forward (maptbl) and reverse (rmap) table setup, plus
 * the pluggable L2P mapping-scheme registry. The flat maptbl/rmap here stay the
 * source of truth; "page" (default) translates directly and "dftl" adds the
 * demand-cache cost model in ftl-map-cmt.c. Split out of ftl.c.
 */
#include "qemu/osdep.h"
#include "ftl.h"
#include "ftl-internal.h"

void ssd_init_maptbl(struct ssd *ssd)
{
    struct ssdparams *spp = &ssd->sp;

    ssd->maptbl = g_malloc0(sizeof(struct ppa) * spp->tt_pgs);
    for (int i = 0; i < spp->tt_pgs; i++) {
        ssd->maptbl[i].ppa = UNMAPPED_PPA;
    }
}

void ssd_init_rmap(struct ssd *ssd)
{
    struct ssdparams *spp = &ssd->sp;

    ssd->rmap = g_malloc0(sizeof(uint64_t) * spp->tt_pgs);
    for (int i = 0; i < spp->tt_pgs; i++) {
        ssd->rmap[i] = INVALID_LPN;
    }
}

/*
 * Pluggable L2P mapping schemes. A scheme is a vtable (femu_mapping_ops),
 * name-selected by the mapping device property like the gc_policy registry. The
 * interface is a translate (read) plus a prepare/commit write split and a
 * GC-relocation commit. "page" is the original full-DRAM mapping (bit-identical);
 * "dftl" reuses the same flat updates but sets uses_cmt so the datapath charges
 * the demand-cache cost from ftl-map-cmt.c.
 */

/*
 * page/dftl translate: the flat L2P lookup. Any dftl cache cost is charged at the
 * call site via cmt_touch, which keeps this path bit-identical.
 */
static struct ppa femu_map_page_translate(struct ssd *ssd, uint64_t lpn)
{
    return get_maptbl_ent(ssd, lpn);
}

/* page/dftl prepare_write: always place in the data class. */
static struct map_write_plan femu_map_page_prepare_write(struct ssd *ssd,
                                                         uint64_t lpn, int io_type)
{
    (void)ssd; (void)lpn; (void)io_type;
    return (struct map_write_plan){ .target_class = FEMU_MAP_CLASS_DATA };
}

/*
 * page/dftl commit_write: invalidate the old mapping, then point lpn at new_ppa.
 * This is the verbatim flat-L2P update from the original ssd_write.
 */
static void femu_map_page_commit_write(struct ssd *ssd, uint64_t lpn,
                                       struct ppa *new_ppa)
{
    struct ppa old = get_maptbl_ent(ssd, lpn);

    if (mapped_ppa(&old)) {
        mark_page_invalid(ssd, &old);
        set_rmap_ent(ssd, INVALID_LPN, &old);
    }
    set_maptbl_ent(ssd, lpn, new_ppa);
    set_rmap_ent(ssd, lpn, new_ppa);
}

/*
 * page/dftl gc_relocate_commit: point lpn at the GC-relocated ppa. This is the
 * verbatim maptbl/rmap update from the original gc_write_page.
 */
static void femu_map_page_gc_relocate_commit(struct ssd *ssd, uint64_t lpn,
                                             struct ppa *old_ppa,
                                             struct ppa *new_ppa)
{
    (void)old_ppa;
    set_maptbl_ent(ssd, lpn, new_ppa);
    set_rmap_ent(ssd, lpn, new_ppa);
}

static const struct femu_mapping_ops femu_mapping_schemes[] = {
    {
        .name          = "page",
        .uses_cmt      = false,
        .translate     = femu_map_page_translate,
        .prepare_write = femu_map_page_prepare_write,
        .commit_write  = femu_map_page_commit_write,
        .gc_relocate_commit = femu_map_page_gc_relocate_commit,
    },
    {
        .name          = "dftl",
        .uses_cmt      = true,
        .translate     = femu_map_page_translate,
        .prepare_write = femu_map_page_prepare_write,
        .commit_write  = femu_map_page_commit_write,
        .gc_relocate_commit = femu_map_page_gc_relocate_commit,
    },
};

/* Resolve a mapping name to its ops; default to page for NULL/unknown. */
const struct femu_mapping_ops *femu_mapping_scheme_lookup(const char *name)
{
    if (name) {
        for (size_t i = 0; i < ARRAY_SIZE(femu_mapping_schemes); i++) {
            if (!strcmp(name, femu_mapping_schemes[i].name)) {
                return &femu_mapping_schemes[i];
            }
        }
    }
    return &femu_mapping_schemes[0]; /* default: page-level */
}

bool femu_mapping_scheme_uses_cmt(const struct femu_mapping_ops *ops)
{
    return ops && ops->uses_cmt;
}
