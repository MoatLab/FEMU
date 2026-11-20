/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * query-stats provider "femu", target "femu": the counters of each femu
 * device for the generic QMP commands query-stats and query-stats-schemas.
 *
 * Each device gives one result for the controller (nsid 0) and one for
 * each attached bbssd namespace. All of them carry the device's QOM path,
 * and the stat "nsid" tells them apart.
 *
 * query-stats is not a coroutine command, so it must not wait for the FTL
 * thread as query-femu does. The FTL thread publishes a copy of the
 * counters of each FTL between two requests instead: about once a
 * millisecond while it is busy, and at once when it goes quiet or
 * resumes. The command
 * reads that copy under a sequence count. The poller counters are single
 * words that the pollers store atomically, and the stage times use the
 * sequence count of query-femu-stages. No thread waits for the command,
 * and the command gives up on a copy that stays busy past a deadline.
 *
 *  FTL thread                         main loop (BQL)
 *  ----------                         ---------------
 *  request, request, ...              query-stats
 *  between two: ssd_stats_publish()   ssd_stats_read(): retry while the
 *    seq++ ; copy ; seq++     <------   sequence is odd or moved, until
 *                                       the deadline
 */
#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "qemu/host-utils.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "qapi/qapi-types-stats.h"
#include "qapi/qapi-types-femu.h"
#include "system/stats.h"
#include "qom/object.h"
#include "nvme.h"
#include "femu-query.h"

/* the FTL thread publishes at most this often while it stays busy */
#define FEMU_STATS_PERIOD_NS    (1 * SCALE_MS)
/* how long query-stats tries to read the stages, then the FTLs, of a device */
#define FEMU_STATS_READ_NS      (1 * SCALE_MS)

/* the stats, in the order of the schema and of every result */
enum {
    FEMU_STAT_NSID,
    /* controller */
    FEMU_STAT_HOST_READ_COMMANDS,
    FEMU_STAT_HOST_WRITE_COMMANDS,
    FEMU_STAT_HOST_READ_BYTES,
    FEMU_STAT_HOST_WRITE_BYTES,
    FEMU_STAT_STAGE,            /* FEMU_STAGE_NR groups of 4 */
    FEMU_STAT_RETURNED_AFTER_DUE = FEMU_STAT_STAGE + FEMU_STAGE_NR * 4,
    /* bbssd namespace */
    FEMU_STAT_GENERATION,
    FEMU_STAT_PAGE_SIZE,
    FEMU_STAT_FTL_NSID,
    FEMU_STAT_HOST_WRITE_PAGES,
    FEMU_STAT_NAND_WRITE_PAGES,
    FEMU_STAT_GC_WRITE_PAGES,
    FEMU_STAT_BLOCK_ERASES,
    FEMU_STAT_PAD_WRITE_PAGES,
    FEMU_STAT_MAP_WRITE_PAGES,
    FEMU_STAT_MAP_READ_PAGES,
    FEMU_STAT_PARITY_WRITE_PAGES,
    FEMU_STAT_DEGRADED_READS,
    FEMU_STAT_LOST_PAGES,
    FEMU_STAT_LOST_BLOCKS,
    FEMU_STAT_IDLE_RECLAIMS,
    FEMU_STAT_IDLE_REFRESHES,
    FEMU_STAT_WAF,
    FEMU_STAT_FREE_LINES,
    FEMU_STAT_VICTIM_LINES,
    FEMU_STAT_FULL_LINES,
    FEMU_STAT_RETIRED_LINES,
    FEMU_STAT_SPARE_LINES,
    FEMU_STAT_TOTAL_LINES,
    FEMU_STAT_NS_HOST_WRITE_PAGES,
    FEMU_STAT_NS_NAND_WRITE_PAGES,
    FEMU_STAT_NS_GC_WRITE_PAGES,
    FEMU_STAT_NS_WAF,
    FEMU_STAT_NR,
};

/* the four stats of each I/O stage, from FEMU_STAT_STAGE + 4 * stage */
enum {
    FEMU_STAT_STAGE_COMMANDS,
    FEMU_STAT_STAGE_TIME,
    FEMU_STAT_STAGE_TIME_SUM,
    FEMU_STAT_STAGE_TIME_MAX,
    FEMU_STAT_PER_STAGE,
};

QEMU_BUILD_BUG_ON(FEMU_STAT_PER_STAGE != 4);

typedef struct FemuStatDef {
    const char *name;
    StatsType type;
    bool has_unit;
    StatsUnit unit;
    int16_t exponent;           /* of base 10 */
} FemuStatDef;

#define FEMU_COUNT(n)   { (n), STATS_TYPE_CUMULATIVE, false, 0, 0 }
#define FEMU_LEVEL(n)   { (n), STATS_TYPE_INSTANT, false, 0, 0 }
#define FEMU_MILLI(n)   { (n), STATS_TYPE_INSTANT, false, 0, -3 }
#define FEMU_BYTES(n, t) { (n), (t), true, STATS_UNIT_BYTES, 0 }

/* the stage entries get their names in femu_stats_register() */
static FemuStatDef femu_stat_defs[FEMU_STAT_NR] = {
    [FEMU_STAT_NSID] = FEMU_LEVEL("nsid"),
    [FEMU_STAT_HOST_READ_COMMANDS] = FEMU_COUNT("host-read-commands"),
    [FEMU_STAT_HOST_WRITE_COMMANDS] = FEMU_COUNT("host-write-commands"),
    [FEMU_STAT_HOST_READ_BYTES] = FEMU_BYTES("host-read-bytes",
                                             STATS_TYPE_CUMULATIVE),
    [FEMU_STAT_HOST_WRITE_BYTES] = FEMU_BYTES("host-write-bytes",
                                              STATS_TYPE_CUMULATIVE),
    [FEMU_STAT_RETURNED_AFTER_DUE] = FEMU_COUNT("returned-after-due"),
    [FEMU_STAT_GENERATION] = FEMU_LEVEL("generation"),
    [FEMU_STAT_PAGE_SIZE] = FEMU_BYTES("page-size", STATS_TYPE_INSTANT),
    [FEMU_STAT_FTL_NSID] = FEMU_LEVEL("ftl-nsid"),
    [FEMU_STAT_HOST_WRITE_PAGES] = FEMU_COUNT("host-write-pages"),
    [FEMU_STAT_NAND_WRITE_PAGES] = FEMU_COUNT("nand-write-pages"),
    [FEMU_STAT_GC_WRITE_PAGES] = FEMU_COUNT("gc-write-pages"),
    [FEMU_STAT_BLOCK_ERASES] = FEMU_COUNT("block-erases"),
    [FEMU_STAT_PAD_WRITE_PAGES] = FEMU_COUNT("pad-write-pages"),
    [FEMU_STAT_MAP_WRITE_PAGES] = FEMU_COUNT("map-write-pages"),
    [FEMU_STAT_MAP_READ_PAGES] = FEMU_COUNT("map-read-pages"),
    [FEMU_STAT_PARITY_WRITE_PAGES] = FEMU_COUNT("parity-write-pages"),
    [FEMU_STAT_DEGRADED_READS] = FEMU_COUNT("degraded-reads"),
    [FEMU_STAT_LOST_PAGES] = FEMU_COUNT("lost-pages"),
    [FEMU_STAT_LOST_BLOCKS] = FEMU_COUNT("lost-blocks"),
    [FEMU_STAT_IDLE_RECLAIMS] = FEMU_COUNT("idle-reclaims"),
    [FEMU_STAT_IDLE_REFRESHES] = FEMU_COUNT("idle-refreshes"),
    [FEMU_STAT_WAF] = FEMU_MILLI("waf"),
    [FEMU_STAT_FREE_LINES] = FEMU_LEVEL("free-lines"),
    [FEMU_STAT_VICTIM_LINES] = FEMU_LEVEL("victim-lines"),
    [FEMU_STAT_FULL_LINES] = FEMU_LEVEL("full-lines"),
    [FEMU_STAT_RETIRED_LINES] = FEMU_LEVEL("retired-lines"),
    [FEMU_STAT_SPARE_LINES] = FEMU_LEVEL("spare-lines"),
    [FEMU_STAT_TOTAL_LINES] = FEMU_LEVEL("total-lines"),
    [FEMU_STAT_NS_HOST_WRITE_PAGES] = FEMU_COUNT("ns-host-write-pages"),
    [FEMU_STAT_NS_NAND_WRITE_PAGES] = FEMU_COUNT("ns-nand-write-pages"),
    [FEMU_STAT_NS_GC_WRITE_PAGES] = FEMU_COUNT("ns-gc-write-pages"),
    [FEMU_STAT_NS_WAF] = FEMU_MILLI("ns-waf"),
};

/* the values of one result; a stat is in the result when has[] is set */
typedef struct FemuStatVals {
    bool has[FEMU_STAT_NR];
    uint64_t v[FEMU_STAT_NR];
    struct uint64List *list[FEMU_STAT_NR];
} FemuStatVals;

static void femu_stat_set(FemuStatVals *sv, int i, uint64_t v)
{
    sv->has[i] = true;
    sv->v[i] = v;
}

/* 1000 * @num / @den with a 128-bit product; UINT64_MAX when it overflows */
static uint64_t femu_stats_milli(uint64_t num, uint64_t den)
{
    uint64_t lo;
    uint64_t hi;

    mulu64(&lo, &hi, num, 1000);
    if (hi >= den) {
        return UINT64_MAX;
    }
    divu128(&lo, &hi, den);
    return lo;
}

/* @a + @b, or UINT64_MAX when the sum overflows */
static uint64_t femu_stats_add_sat(uint64_t a, uint64_t b)
{
    uint64_t r;

    return uadd64_overflow(a, b, &r) ? UINT64_MAX : r;
}

/*
 * The stats of one result, in schema order: HMP "info stats" walks the
 * schema forward. The names filter applies to every stat, nsid included,
 * as for any provider; a client that filters asks for nsid too. NULL when
 * the filter leaves no stat.
 */
static StatsList *femu_stats_list(FemuStatVals *sv, strList *names)
{
    StatsList *stats = NULL;
    StatsList **tail = &stats;

    for (int i = 0; i < FEMU_STAT_NR; i++) {
        Stats *st;

        if (!sv->has[i]) {
            continue;
        }
        if (!apply_str_list_filter(femu_stat_defs[i].name, names)) {
            g_clear_pointer(&sv->list[i], qapi_free_uint64List);
            continue;
        }
        st = g_new0(Stats, 1);
        st->name = g_strdup(femu_stat_defs[i].name);
        st->value = g_new0(StatsValue, 1);
        if (femu_stat_defs[i].type == STATS_TYPE_LOG2_HISTOGRAM) {
            st->value->type = QTYPE_QLIST;
            st->value->u.list = g_steal_pointer(&sv->list[i]);
        } else {
            st->value->type = QTYPE_QNUM;
            st->value->u.scalar = sv->v[i];
        }
        QAPI_LIST_APPEND(tail, st);
    }
    return stats;
}

/* true when the names filter keeps one of the stats [@lo, @hi) */
static bool femu_stats_wanted(strList *names, int lo, int hi)
{
    for (int i = lo; i < hi; i++) {
        if (apply_str_list_filter(femu_stat_defs[i].name, names)) {
            return true;
        }
    }
    return false;
}

/*
 * Host commands and bytes, and with io_stages the stage times. The stage
 * times are left out when a poller holds its set past @deadline.
 */
static void femu_stats_ctrl(FemuCtrl *n, FemuStatVals *sv, strList *names,
                            int64_t deadline)
{
    g_autofree FemuStageSet *sum = NULL;
    uint64_t rd_cmds = 0;
    uint64_t wr_cmds = 0;
    uint64_t rd_bytes = 0;
    uint64_t wr_bytes = 0;

    femu_stat_set(sv, FEMU_STAT_NSID, 0);
    /* the counters exist once the controller was first enabled */
    for (uint32_t p = 1; n->poller_ctr && p <= n->nr_pollers; p++) {
        FemuPollerCtr *c = &n->poller_ctr[p];

        rd_cmds += qatomic_read(&c->nr_host_rd_cmds);
        wr_cmds += qatomic_read(&c->nr_host_wr_cmds);
        rd_bytes += qatomic_read(&c->nr_host_rd_bytes);
        wr_bytes += qatomic_read(&c->nr_host_wr_bytes);
    }
    femu_stat_set(sv, FEMU_STAT_HOST_READ_COMMANDS, rd_cmds);
    femu_stat_set(sv, FEMU_STAT_HOST_WRITE_COMMANDS, wr_cmds);
    femu_stat_set(sv, FEMU_STAT_HOST_READ_BYTES, rd_bytes);
    femu_stat_set(sv, FEMU_STAT_HOST_WRITE_BYTES, wr_bytes);

    /* copy the stage sets only when a stage stat is asked for */
    if (!n->io_stages ||
        !femu_stats_wanted(names, FEMU_STAT_STAGE,
                           FEMU_STAT_RETURNED_AFTER_DUE + 1)) {
        return;
    }
    sum = g_new0(FemuStageSet, 1);
    if (!femu_query_stage_total(n, sum, deadline)) {
        return;
    }
    for (int st = 0; st < FEMU_STAGE_NR; st++) {
        const FemuStageHist *h = &sum->st[st];
        int i = FEMU_STAT_STAGE + st * FEMU_STAT_PER_STAGE;
        uint64List **ltail = &sv->list[i + FEMU_STAT_STAGE_TIME];

        femu_stat_set(sv, i + FEMU_STAT_STAGE_COMMANDS, h->count);
        sv->has[i + FEMU_STAT_STAGE_TIME] = true;
        for (int b = 0; b < FEMU_STAGE_BUCKETS; b++) {
            QAPI_LIST_APPEND(ltail, h->buckets[b]);
        }
        femu_stat_set(sv, i + FEMU_STAT_STAGE_TIME_SUM, h->sum_ns);
        femu_stat_set(sv, i + FEMU_STAT_STAGE_TIME_MAX, h->max_ns);
    }
    femu_stat_set(sv, FEMU_STAT_RETURNED_AFTER_DUE, sum->returned_after_due);
}

/*
 * One bbssd namespace, under the "present when" rules of query-femu. The
 * FTL counters go in the result of the first namespace that reports their
 * FTL (@ftl_nsid 0); a namespace that shares it names that one instead.
 * False when the FTL's copy stayed busy past @deadline.
 */
static bool femu_stats_ns(NvmeNamespace *ns, uint32_t ftl_nsid,
                          FemuStatVals *sv, int64_t deadline)
{
    FemuStatsNs s;
    uint64_t media;

    if (!ssd_stats_read(ns->ssd, ns->id, &s, deadline)) {
        return false;
    }
    femu_stat_set(sv, FEMU_STAT_NSID, ns->id);
    femu_stat_set(sv, FEMU_STAT_GENERATION, ns->creation_generation);
    femu_stat_set(sv, FEMU_STAT_PAGE_SIZE, s.page_size);
    if (s.ns_ctr_on) {
        femu_stat_set(sv, FEMU_STAT_NS_HOST_WRITE_PAGES, s.ns_host_pages);
        femu_stat_set(sv, FEMU_STAT_NS_NAND_WRITE_PAGES, s.ns_nand_pages);
        femu_stat_set(sv, FEMU_STAT_NS_GC_WRITE_PAGES, s.ns_gc_pages);
        if (s.ns_host_pages) {
            femu_stat_set(sv, FEMU_STAT_NS_WAF,
                          femu_stats_milli(femu_stats_add_sat(s.ns_nand_pages,
                                                              s.ns_gc_pages),
                                           s.ns_host_pages));
        }
    }
    if (ftl_nsid) {
        femu_stat_set(sv, FEMU_STAT_FTL_NSID, ftl_nsid);
        return true;
    }

    femu_stat_set(sv, FEMU_STAT_HOST_WRITE_PAGES, s.host_pages);
    femu_stat_set(sv, FEMU_STAT_NAND_WRITE_PAGES, s.nand_pages);
    femu_stat_set(sv, FEMU_STAT_GC_WRITE_PAGES, s.gc_pages);
    femu_stat_set(sv, FEMU_STAT_BLOCK_ERASES, s.erases);
    if (s.pad_pages) {
        femu_stat_set(sv, FEMU_STAT_PAD_WRITE_PAGES, s.pad_pages);
    }
    if (s.tp_on) {
        femu_stat_set(sv, FEMU_STAT_MAP_WRITE_PAGES, s.map_pages);
        femu_stat_set(sv, FEMU_STAT_MAP_READ_PAGES, s.map_reads);
    }
    if (s.parity_on) {
        femu_stat_set(sv, FEMU_STAT_PARITY_WRITE_PAGES, s.parity_pages);
        femu_stat_set(sv, FEMU_STAT_DEGRADED_READS, s.degraded_reads);
    }
    if (s.rain_on) {
        femu_stat_set(sv, FEMU_STAT_LOST_PAGES, s.lost_pages);
        femu_stat_set(sv, FEMU_STAT_LOST_BLOCKS, s.lost_blocks);
    }
    if (s.maint_on) {
        femu_stat_set(sv, FEMU_STAT_IDLE_RECLAIMS, s.idle_reclaims);
        femu_stat_set(sv, FEMU_STAT_IDLE_REFRESHES, s.idle_refreshes);
    }
    /* the formula of query-femu, from the same copy as the parts */
    if (s.host_pages) {
        media = femu_stats_add_sat(s.nand_pages, s.gc_pages);
        media = femu_stats_add_sat(media, s.map_pages);
        media = femu_stats_add_sat(media, s.pad_pages);
        media = femu_stats_add_sat(media, s.parity_pages);
        femu_stat_set(sv, FEMU_STAT_WAF,
                      femu_stats_milli(media, s.host_pages));
    }
    if (!s.fdp) {
        femu_stat_set(sv, FEMU_STAT_FREE_LINES, s.free_lines);
        femu_stat_set(sv, FEMU_STAT_VICTIM_LINES, s.victim_lines);
        femu_stat_set(sv, FEMU_STAT_FULL_LINES, s.full_lines);
        femu_stat_set(sv, FEMU_STAT_RETIRED_LINES, s.retired_lines);
        femu_stat_set(sv, FEMU_STAT_SPARE_LINES, s.spare_lines);
        femu_stat_set(sv, FEMU_STAT_TOTAL_LINES, s.total_lines);
    }
    return true;
}

/* a namespace whose counters an FTL of its own (or a shared one) holds */
static bool femu_stats_ns_ok(NvmeNamespace *ns)
{
    return ns && NS_BBSSD(ns) && ns->ssd && !ns->ssd_borrowed;
}

typedef struct FemuStatsArgs {
    StatsResultList **result;
    strList *names;
} FemuStatsArgs;

/*
 * One device. add_stats_entry() puts each result first in the list, so
 * the results of the device go in from the last one; the reply then reads
 * controller, namespace 1, namespace 2, and so on.
 */
static int femu_stats_dev(Object *obj, void *opaque)
{
    FemuStatsArgs *args = opaque;
    FemuCtrl *n = (FemuCtrl *)object_dynamic_cast(obj, TYPE_NVME);
    g_autoptr(GPtrArray) lists = NULL;
    g_autoptr(GHashTable) ftls = NULL;
    g_autofree char *path = NULL;
    g_autofree FemuStatVals *sv = NULL;
    int64_t deadline;
    StatsList *stats;

    if (!n || !DEVICE(n)->realized) {
        return 0;
    }
    deadline = qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + FEMU_STATS_READ_NS;
    path = object_get_canonical_path(obj);
    lists = g_ptr_array_new();
    ftls = g_hash_table_new(g_direct_hash, g_direct_equal);
    sv = g_new0(FemuStatVals, 1);

    femu_stats_ctrl(n, sv, args->names, deadline);
    g_ptr_array_add(lists, femu_stats_list(sv, args->names));
    /* the stage copy may have used up its time; the FTLs get their own */
    deadline = qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + FEMU_STATS_READ_NS;
    for (uint32_t nsid = 1; nsid <= n->namespace_limit; nsid++) {
        NvmeNamespace *ns = nvme_ns(n, nsid);
        uint32_t ftl_nsid;

        if (!femu_stats_ns_ok(ns)) {
            continue;
        }
        ftl_nsid = GPOINTER_TO_UINT(g_hash_table_lookup(ftls, ns->ssd));
        memset(sv, 0, sizeof(*sv));
        if (!femu_stats_ns(ns, ftl_nsid, sv, deadline)) {
            continue;
        }
        if (!ftl_nsid) {
            g_hash_table_insert(ftls, ns->ssd, GUINT_TO_POINTER(nsid));
        }
        g_ptr_array_add(lists, femu_stats_list(sv, args->names));
    }
    for (guint i = lists->len; i > 0; i--) {
        stats = g_ptr_array_index(lists, i - 1);
        if (stats) {
            add_stats_entry(args->result, STATS_PROVIDER_FEMU, path, stats);
        }
    }
    return 0;
}

static void femu_stats_cb(StatsResultList **result, StatsTarget target,
                          strList *names, strList *targets, Error **errp)
{
    FemuStatsArgs args = { .result = result, .names = names };

    if (target != STATS_TARGET_FEMU) {
        return;
    }
    object_child_foreach_recursive(object_get_root(), femu_stats_dev, &args);
}

static void femu_stats_schemas_cb(StatsSchemaList **result, Error **errp)
{
    StatsSchemaValueList *list = NULL;
    StatsSchemaValueList **tail = &list;

    for (int i = 0; i < FEMU_STAT_NR; i++) {
        const FemuStatDef *d = &femu_stat_defs[i];
        StatsSchemaValue *v = g_new0(StatsSchemaValue, 1);

        v->name = g_strdup(d->name);
        v->type = d->type;
        v->has_unit = d->has_unit;
        v->unit = d->unit;
        v->exponent = d->exponent;
        if (d->exponent) {
            v->has_base = true;
            v->base = 10;
        }
        QAPI_LIST_APPEND(tail, v);
    }
    add_stats_schema(result, STATS_PROVIDER_FEMU, STATS_TARGET_FEMU, list);
}

/*
 * FTL thread, between two passes: publish the copy of each FTL of the
 * controller, once per FTL. It holds ftl_in_sweep as for a request, so a
 * caller that paused the controller (to free a namespace, say) knows it
 * is done. Controllers that share namespaces hold the namespace lock, as
 * their requests do. False when the controller is paused: nothing is
 * published then.
 */
static bool femu_stats_publish(FemuCtrl *n)
{
    bool shared = nvme_ns_shared(n);
    uint64_t pass = ++n->stats_pub_count;

    n->ftl_in_sweep = true;
    smp_mb();   /* publish the flag before re-reading the pause state */
    if (!n->dataplane_started) {
        n->ftl_in_sweep = false;
        return false;
    }
    if (shared) {
        qemu_mutex_lock(&n->subsys->ns_lock);
    }
    for (uint32_t nsid = 1; nsid <= n->namespace_limit; nsid++) {
        NvmeNamespace *ns = nvme_ns(n, nsid);
        struct ssd *ssd;

        if (!femu_stats_ns_ok(ns)) {
            continue;
        }
        /* a shared FTL copies all its namespaces in one go */
        ssd = ns->ssd;
        if (ssd->stats_pub_by == n && ssd->stats_pub_pass == pass) {
            continue;
        }
        ssd->stats_pub_by = n;
        ssd->stats_pub_pass = pass;
        ssd_stats_publish(ssd);
    }
    if (shared) {
        qemu_mutex_unlock(&n->subsys->ns_lock);
    }
    n->ftl_in_sweep = false;
    return true;
}

/*
 * FTL thread, once per pass that ran a request (@busy) or idle work
 * (@idle), that follows such a pass, or that follows a resume. While the
 * counters keep changing, publish once per FEMU_STATS_PERIOD_NS, and look
 * at the clock only every 32nd busy pass. Publish at once on the first
 * quiet pass and after a resume. Only a publish that ran clears the need.
 */
void femu_stats_tick(FemuCtrl *n, bool busy, bool idle)
{
    uint32_t epoch = qatomic_read(&n->stats_epoch);
    int64_t now;

    if (busy || idle) {
        n->stats_dirty = true;
        if (busy && (++n->stats_passes & 31)) {
            return;
        }
        now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
        if (now - n->stats_pub_ns < FEMU_STATS_PERIOD_NS) {
            return;
        }
    } else {
        now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    }
    if (femu_stats_publish(n)) {
        n->stats_dirty = false;
        n->stats_epoch_seen = epoch;
        n->stats_pub_ns = now;
    }
}

static void femu_stats_register(void)
{
    static const char *const suffix[FEMU_STAT_PER_STAGE] = {
        [FEMU_STAT_STAGE_COMMANDS] = "commands",
        [FEMU_STAT_STAGE_TIME] = "time",
        [FEMU_STAT_STAGE_TIME_SUM] = "time-sum",
        [FEMU_STAT_STAGE_TIME_MAX] = "time-max",
    };
    static const StatsType type[FEMU_STAT_PER_STAGE] = {
        [FEMU_STAT_STAGE_COMMANDS] = STATS_TYPE_CUMULATIVE,
        [FEMU_STAT_STAGE_TIME] = STATS_TYPE_LOG2_HISTOGRAM,
        [FEMU_STAT_STAGE_TIME_SUM] = STATS_TYPE_CUMULATIVE,
        [FEMU_STAT_STAGE_TIME_MAX] = STATS_TYPE_PEAK,
    };

    /* FemuIoStage numbers the stages as FEMU_STAGE_* does */
    QEMU_BUILD_BUG_ON(FEMU_IO_STAGE__MAX != FEMU_STAGE_NR);
    for (int st = 0; st < FEMU_STAGE_NR; st++) {
        for (int k = 0; k < FEMU_STAT_PER_STAGE; k++) {
            FemuStatDef *d = &femu_stat_defs[FEMU_STAT_STAGE +
                                             st * FEMU_STAT_PER_STAGE + k];

            d->name = g_strdup_printf("%s-%s", FemuIoStage_str(st),
                                      suffix[k]);
            d->type = type[k];
            /* the command count has no unit; the times are nanoseconds */
            if (k != FEMU_STAT_STAGE_COMMANDS) {
                d->has_unit = true;
                d->unit = STATS_UNIT_SECONDS;
                d->exponent = -9;
            }
        }
    }
    add_stats_callbacks(STATS_PROVIDER_FEMU, femu_stats_cb,
                        femu_stats_schemas_cb);
}

type_init(femu_stats_register)
