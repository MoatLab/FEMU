/*
 * Data-remanence experiment logging (debug only; all paths are off unless the
 * FEMU_EXP_LOG / FEMU_DUMP_LPN environment variables are set). Watches specific
 * LPNs/blocks that carry a configured marker and logs their movement through the
 * datapath and GC. Split out of ftl.c; the datapath, GC, and init call the
 * handlers declared in ftl-internal.h.
 */
#include "qemu/osdep.h"
#include "ftl.h"
#include "ftl-internal.h"

/*
 * Deleted-data-remanence experiment instrumentation (debug only; does not change
 * FTL behavior). Gated by environment variables read once at init:
 *   FEMU_EXP_LOG   non-empty -> emit [EXP] log lines to stderr
 *   FEMU_SECRET    a marker string; only pages whose backend bytes contain it are
 *                  tracked and logged, to keep the output focused
 *   FEMU_DUMP_LPN  hex-dump this LPN's backend page on every read
 * stderr is used so the output stays unbuffered through a tee pipe.
 */
bool exp_log_enabled;
static const char *exp_secret;       /* NULL, or the (non-empty) marker string */
uint64_t exp_dump_lpn;
bool exp_dump_lpn_set;

void exp_load_cfg(void)
{
    const char *v;

    v = getenv("FEMU_EXP_LOG");
    exp_log_enabled = (v && v[0] != '\0');

    v = getenv("FEMU_SECRET");
    exp_secret = (v && v[0] != '\0') ? v : NULL;

    v = getenv("FEMU_DUMP_LPN");
    if (v && v[0] != '\0') {
        exp_dump_lpn = strtoull(v, NULL, 0);
        exp_dump_lpn_set = true;
    }
}

/* EXP_LOG / PPA_FMT / PPA_ARG now live in ftl-internal.h (shared with the GC). */

/*
 * Hex+ASCII dump of one LPN's bytes from the DRAM backend. Note: the data lives
 * at the LBA offset (lpn * page_bytes) in the logical space, not at a PPA.
 */
void femu_dbg_dump_lpn(struct ssd *ssd, uint64_t lpn)
{
    struct ssdparams *spp = &ssd->sp;
    uint64_t page_bytes = (uint64_t)spp->secs_per_pg * spp->secsz; /* 4096 */
    uint64_t off = lpn * page_bytes;
    struct ppa ppa = get_maptbl_ent(ssd, lpn);
    uint8_t *base;

    if (!ssd->n || !ssd->n->mbe || !ssd->n->mbe->logical_space) {
        fprintf(stderr, "[DUMP] backend not ready\n");
        return;
    }
    if (off + page_bytes > (uint64_t)ssd->n->mbe->size) {
        fprintf(stderr, "[DUMP] lpn=%lu out of range\n", lpn);
        return;
    }
    base = (uint8_t *)ssd->n->mbe->logical_space + off;

    fprintf(stderr, "[DUMP] lpn=%lu off=0x%lx mapped=%d", lpn, off,
            mapped_ppa(&ppa));
    if (mapped_ppa(&ppa))
        fprintf(stderr, " " PPA_FMT, PPA_ARG(&ppa));
    fprintf(stderr, "\n");
    for (uint64_t i = 0; i < page_bytes; i += 16) {
        fprintf(stderr, "  %08lx  ", off + i);
        for (int j = 0; j < 16; j++)
            fprintf(stderr, "%02x ", base[i + j]);
        fprintf(stderr, " |");
        for (int j = 0; j < 16; j++) {
            uint8_t c = base[i + j];
            fprintf(stderr, "%c", (c >= 0x20 && c < 0x7f) ? c : '.');
        }
        fprintf(stderr, "|\n");
    }
}

/* Scan the whole backend for the marker string and report which LPN holds it. */
void femu_dbg_scan_secret(struct ssd *ssd, const char *tag)
{
    const char *sec = exp_secret;
    struct ssdparams *spp = &ssd->sp;
    uint64_t page_bytes, size;
    uint8_t *buf;
    size_t slen;
    int hits = 0;

    if (!sec || !ssd->n || !ssd->n->mbe || !ssd->n->mbe->logical_space)
        return;

    page_bytes = (uint64_t)spp->secs_per_pg * spp->secsz;
    buf = (uint8_t *)ssd->n->mbe->logical_space;
    size = (uint64_t)ssd->n->mbe->size;
    slen = strlen(sec);

    for (uint64_t i = 0; i + slen <= size; i++) {
        if (buf[i] == (uint8_t)sec[0] && memcmp(buf + i, sec, slen) == 0) {
            fprintf(stderr, "[SCAN:%s] FOUND '%s' at off=0x%lx lpn=%lu\n",
                    tag, sec, i, i / page_bytes);
            hits++;
            i += slen - 1;
        }
    }
    if (!hits)
        fprintf(stderr, "[SCAN:%s] '%s' NOT present in backend\n", tag, sec);
}

/* Track only the LPNs/blocks that carry the marker, to keep the log focused. */
#define EXP_MAX_WATCH 256
static uint64_t exp_watch_lpn[EXP_MAX_WATCH];
static int exp_watch_lpn_cnt = 0;
uint8_t exp_watch_blk[1 << BLK_BITS]; /* block (line) id -> watched? */

bool exp_lpn_watched(uint64_t lpn)
{
    for (int i = 0; i < exp_watch_lpn_cnt; i++)
        if (exp_watch_lpn[i] == lpn)
            return true;
    return false;
}

void exp_watch_lpn_add(uint64_t lpn)
{
    if (exp_lpn_watched(lpn))
        return;
    if (exp_watch_lpn_cnt < EXP_MAX_WATCH)
        exp_watch_lpn[exp_watch_lpn_cnt++] = lpn;
}

/* Does this LPN's backend page currently contain the marker string? */
bool femu_dbg_lpn_has_secret(struct ssd *ssd, uint64_t lpn)
{
    const char *sec = exp_secret;
    struct ssdparams *spp = &ssd->sp;
    uint64_t page_bytes, off;
    uint8_t *base;
    size_t slen;

    if (!sec)
        return false;
    if (!ssd->n || !ssd->n->mbe || !ssd->n->mbe->logical_space)
        return false;
    page_bytes = (uint64_t)spp->secs_per_pg * spp->secsz;
    off = lpn * page_bytes;
    if (off + page_bytes > (uint64_t)ssd->n->mbe->size)
        return false;
    base = (uint8_t *)ssd->n->mbe->logical_space + off;
    slen = strlen(sec);
    for (uint64_t i = 0; i + slen <= page_bytes; i++)
        if (base[i] == (uint8_t)sec[0] && memcmp(base + i, sec, slen) == 0)
            return true;
    return false;
}
