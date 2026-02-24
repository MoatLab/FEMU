#include "cache.h"
#include "cache_impl.h"
#include "cache_plugin.h"
#include "policy/cache_policy.h"
#include "cache_backend.h"
#include "hw/femu/femu.h"
#include "../../ftl/ftl.h"
#include "../cxlssd.h"
#include "../der_kvm.h"
#include <glib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>

static int lpn_cmp(const void *a, const void *b)
{
    const CacheEntry *ea = a;
    const CacheEntry *eb = b;
    if (ea->lpn < eb->lpn) return -1;
    if (ea->lpn > eb->lpn) return 1;
    return 0;
}

int cylon_cache_backend_init(FemuCtrl *n, CylonCacheBackend *out)
{
    int fd;
    int64_t csize;
    void *p;

    out->buf_space = NULL;
    out->buf_size = 0;
    out->hpa_base = 0;

    if (!n->mbe) {
        return 0;
    }
    out->buf_space = n->mbe->logical_space;
    out->buf_size = n->bufsz ? (int64_t)n->bufsz * 1024 * 1024 : 0;

    if (!n->cache_backend_dev || !n->bufsz) {
        return 0;
    }

    csize = (int64_t)n->bufsz * 1024 * 1024;
    fd = open(n->cache_backend_dev, O_RDWR);
    if (fd < 0) {
        femu_err("Failed to open cache backend device %s: %s\n",
                 n->cache_backend_dev, strerror(errno));
        return -1;
    }

    p = mmap(NULL, (size_t)csize, PROT_READ | PROT_WRITE, MAP_SHARED,
             fd, (off_t)n->cache_bdev_offset);
    close(fd);
    if (p == MAP_FAILED) {
        femu_err("Failed to mmap cache backend %s: %s\n",
                 n->cache_backend_dev, strerror(errno));
        return -1;
    }

    if (mlock(p, (size_t)csize) != 0) {
        munmap(p, (size_t)csize);
        femu_err("Failed to mlock cache backend\n");
        return -1;
    }

    out->buf_space = p;
    out->buf_size = csize;
    out->hpa_base = n->cache_hpa_base;

    femu_log("Cylon DER cache backend: %s offset 0x%" PRIx64 " size %" PRId64 " MB, hpa_base 0x%" PRIx64 "\n",
             n->cache_backend_dev, (uint64_t)n->cache_bdev_offset, (int64_t)n->bufsz, out->hpa_base);
    return 0;
}

void cylon_cache_backend_fini(CylonCacheBackend *b)
{
    if (b && b->buf_space && b->buf_size > 0) {
        void *p = b->buf_space;
        size_t sz = (size_t)b->buf_size;
        munlock(p, sz);
        munmap(p, sz);
    }
    if (b) {
        b->buf_space = NULL;
        b->buf_size = 0;
        b->hpa_base = 0;
    }
}

/* ---- Core cache API (Cache *, CacheEntry *) ---- */

void cache_flush_page(struct ssd *ssd, lpn_t lpn)
{
    Cxlssd *ctx = cxlssd_ctx_from_ssd(ssd);
    Cache *c;
    CacheEntry key = { .lpn = lpn };
    CacheEntry *e;

    if (!ctx || !ctx->cache || !ctx->cache->cache_data) {
        return;
    }
    c = (Cache *)ctx->cache->cache_data;
    if (!c->cache_buf || !c->nand_buf) {
        return;
    }
    e = g_tree_lookup(c->tree, &key);
    if (!e) {
        return;
    }
    memcpy((char *)c->nand_buf + (size_t)(lpn * CACHE_PAGE_SIZE),
           (const char *)c->cache_buf + (size_t)(e->slot_id * CACHE_PAGE_SIZE),
           CACHE_PAGE_SIZE);
}

void cache_set_backend(Cache *c, void *cache_buf, int64_t cache_buf_size,
                       void *nand_buf, int64_t nand_size)
{
    if (!c) return;
    c->cache_buf = cache_buf;
    c->cache_buf_size = cache_buf_size;
    c->nand_buf = nand_buf;
    c->nand_size = nand_size;
    c->nr_slots = (cache_buf_size > 0 && cache_buf) ? (uint32_t)(cache_buf_size / CACHE_PAGE_SIZE) : 0;
    c->next_slot = 0;
}

Cache *cache_create(struct ssd *ssd, int policy_id, int size, CacheWay way)
{
    const CachePolicy *policy = cache_policy_get(policy_id);
    if (!policy || size <= 0) {
        return NULL;
    }

    Cache *c = g_malloc0(sizeof(Cache));
    c->ssd = ssd;
    c->policy_id = policy_id;
    c->policy = policy;
    c->size = size;
    c->way = way;
    c->nr_sets = (way == CACHE_WAY_FULL) ? 1 : (size + (1 << way) - 1) / (1 << way);
    if (c->nr_sets <= 0) {
        c->nr_sets = 1;
    }
    c->tree = g_tree_new(lpn_cmp);
    c->policy_private = NULL;
    c->cache_buf = NULL;
    c->nand_buf = NULL;
    c->nr_slots = 0;
    c->next_slot = 0;
    c->sets = g_malloc0(sizeof(CacheSet) * (size_t)c->nr_sets);
    for (int i = 0; i < c->nr_sets; i++) {
        QTAILQ_INIT(&c->sets[i].queue);
        c->sets[i].policy_private = NULL;
    }

    if (policy->init) {
        policy->init(c);
    }
    return c;
}

void cache_destroy(Cache *c)
{
    if (!c) return;
    if (c->policy && c->policy->cleanup) {
        c->policy->cleanup(c);
    }
    if (c->sets) {
        g_free(c->sets);
    }
    if (c->tree) {
        g_tree_destroy(c->tree);
    }
    g_free(c);
}

CacheEntry *cache_lookup(Cache *c, lpn_t lpn)
{
    CacheEntry key = { .lpn = lpn };
    return g_tree_lookup(c->tree, &key);
}

/* High-level insert: eviction (epte_set_trap + flush), memcpy, epte_set_direct, then policy insert */
int cylon_cache_insert(Cache *c, CacheEntry *entry, int prefetch)
{
    struct ssd *ssd = cache_get_ssd(c);
    Cxlssd *ctx = cxlssd_ctx_from_ssd(ssd);
    CacheSet *set = cache_get_set(c, entry->lpn);
    CacheWay way = cache_get_way(c);
    int ent_max = (way == CACHE_WAY_FULL) ? cache_get_size(c) : (1 << way);
    CacheEntry key = { .lpn = entry->lpn };

    (void)prefetch;

    if (!c->policy || !c->policy->insert_entry || !c->policy->evict_victim) {
        return -1;
    }

    if (g_tree_lookup(c->tree, &key)) {
        return c->policy->insert_entry(c, entry);
    }

    while (set->count >= ent_max) {
        CacheEntry *victim = c->policy->evict_victim(c, set);
        if (!victim) {
            return -1;
        }
        if (ctx && ctx->der_kvm) {
            if (der_kvm_epte_set_trap(ctx, victim->lpn) < 0) {
                fprintf(stderr, "Cylon cache: failed to set trap EPTE for page %lld\n",
                        (long long)victim->lpn);
            }
        }
        fprintf(stderr, "Cylon cache: evicted page %lld from slot %u (hpa 0x%llx)\n",
                    (long long)victim->lpn, victim->slot_id, (long long)ctx->cache_backend.hpa_base + (uint64_t)victim->slot_id * CACHE_PAGE_SIZE);

        cache_flush_page(ssd, victim->lpn);
        g_tree_remove(c->tree, victim);
        cache_dec_entry_count(c);
        cache_dec_set_count(set);
        c->stats.evict_count++;
        entry->slot_id = victim->slot_id;
        cache_entry_free(victim);
    }

    if (entry->slot_id == 0 && c->cache_buf && c->nr_slots > 0) {
        entry->slot_id = c->next_slot % c->nr_slots;
        c->next_slot++;
    }

    if (c->cache_buf && c->nand_buf && c->nr_slots > 0) {
        memcpy((char *)c->cache_buf + (size_t)(entry->slot_id * CACHE_PAGE_SIZE),
               (const char *)c->nand_buf + (size_t)(entry->lpn * CACHE_PAGE_SIZE),
               CACHE_PAGE_SIZE);
    }

    if (ctx && ctx->der_kvm && ctx->cache_backend.buf_space) {
        uint64_t hpa = ctx->cache_backend.hpa_base
            + (uint64_t)entry->slot_id * CACHE_PAGE_SIZE;
        if (der_kvm_epte_set_driect(ctx, entry->lpn, hpa) < 0) {
            fprintf(stderr, "Cylon cache: failed to set direct EPTE for page %lld (hpa 0x%llx)\n",
                    (long long)entry->lpn, (long long)hpa);
        }
    }

    fprintf(stderr, "Cylon cache: inserted page %lld into slot %u (hpa 0x%llx)\n",
            (long long)entry->lpn, entry->slot_id, (long long)ctx->cache_backend.hpa_base + (uint64_t)entry->slot_id * CACHE_PAGE_SIZE);
    return c->policy->insert_entry(c, entry);
}

/* ---- Plugin ops (cache_ops_t: void *cache_data, struct cache_entry *) ---- */

static struct cache_entry *plugin_lookup(void *cache_data, lpn_t lpn)
{
    Cache *c = (Cache *)cache_data;
    return (struct cache_entry *)cache_lookup(c, lpn);
}

static void plugin_set_dirty(struct cache_entry *e, bool dirty)
{
    if (e) {
        ((CacheEntry *)e)->dirty = dirty;
    }
}

static bool plugin_is_dirty(struct cache_entry *e)
{
    return e ? ((CacheEntry *)e)->dirty : false;
}

static void plugin_insert(void *cache_data, struct cache_entry *e, int prefetch)
{
    Cache *c = (Cache *)cache_data;
    cylon_cache_insert(c, (CacheEntry *)e, prefetch);
}

static struct cache_entry *plugin_entry_init(void *cache_data, lpn_t lpn)
{
    CacheEntry *e = g_malloc0(sizeof(CacheEntry));
    e->lpn = lpn;
    e->dirty = false;
    e->policy_data = NULL;
    e->slot_id = 0;
    (void)cache_data;
    return (struct cache_entry *)e;
}

static uint32_t plugin_get_slot_id(struct cache_entry *e)
{
    return e ? ((CacheEntry *)e)->slot_id : 0;
}

static const cache_ops_t cylon_cache_ops = {
    .lookup = plugin_lookup,
    .set_dirty = plugin_set_dirty,
    .is_dirty = plugin_is_dirty,
    .insert = plugin_insert,
    .entry_init = plugin_entry_init,
    .get_slot_id = plugin_get_slot_id,
};

/* ---- Plugin create/destroy ---- */

static CacheWay cache_way_from_rep(uint8_t buffer_way)
{
    return (buffer_way >= CACHE_WAY_FULL) ? CACHE_WAY_FULL : (CacheWay)buffer_way;
}

static bool policy_registered;

struct cache_plugin *cylon_cache_plugin_create(FemuCtrl *n)
{
    if (!n->ssd || n->bufsz == 0) {
        return NULL;
    }
    if (!policy_registered) {
        cache_policy_register_all();
        policy_registered = true;
    }

    int size = (int)((n->bufsz * 1024ULL * 1024ULL) / 4096);
    if (size <= 0) {
        size = 1024;
    }
    CacheWay way = cache_way_from_rep(n->buffer_way);
    int policy_id = (int)n->rep;
    if (policy_id <= CACHE_POLICY_NONE || policy_id >= CACHE_POLICY_MAX) {
        policy_id = CACHE_POLICY_LIFO;
    }

    Cache *c = cache_create(n->ssd, policy_id, size, way);
    if (!c) {
        return NULL;
    }
    {
        Cxlssd *ctx = cxlssd_ctx_from_ctrl(n);
        if (ctx && ctx->cache_backend.buf_space && ctx->cache_backend.buf_size > 0 && n->mbe) {
            cache_set_backend(c, ctx->cache_backend.buf_space, ctx->cache_backend.buf_size,
                             n->mbe->logical_space, n->mbe->size);
        }
    }

    struct cache_plugin *p = g_malloc0(sizeof(struct cache_plugin));
    p->cache_data = c;
    p->ops = cylon_cache_ops;
    return p;
}

void cylon_cache_plugin_destroy(struct cache_plugin *p)
{
    if (!p) return;
    cache_destroy((Cache *)p->cache_data);
    g_free(p);
}
