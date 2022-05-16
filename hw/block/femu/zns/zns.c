#include "./zns.h"
#define EXPECTING_STORAGE_CAPACITY  (4 *GiB)
#define MIN_DISCARD_GRANULARITY     (4 * KiB)
#define NVME_DEFAULT_ZONE_SIZE      (128 * MiB)
#define NVME_DEFAULT_MAX_AZ_SIZE    (128 * KiB)

static void *zns_thread(void *arg);

static inline uint32_t zns_zone_idx(NvmeNamespace *ns, uint64_t slba)
{
    FemuCtrl *n = ns->ctrl;
    //INHO, n->zone_size_log2 = 18, return slba >> n->zone_size_log2
    //0>>18, 10 >> 18 
    //femu_err("in zns.c:14 zns_zone_idx ; n->zone_size_log2 %d slba %ld ", n->zone_size_log2, slba);
    return (n->zone_size_log2 > 0 ? slba >> n->zone_size_log2 : slba /
            n->zone_size);
}
/**
 * @brief Inhoinno, get slba, return chnl index considerring controller-level zone mapping
 *  
 * @param ns        namespace
 * @param slba      start lba
 * @param factor    1-to-N, N is factor
 * @return chnl_idx
 */
static inline uint64_t zns_advanced_chnl_idx(NvmeNamespace *ns, uint64_t slba)
{
    FemuCtrl *n = ns->ctrl;
    struct zns * zns = n->zns;
    struct zns_ssdparams *spp = &zns->sp;
    uint64_t factor = spp->chnls_per_zone;  /* Now factor = N w.r.t 1-to-N mapping */
    uint64_t zone_idx = zns_zone_idx(ns, slba);
    uint64_t slpa = slba >> 3;
    //            = slpa << 3 >> (22) >> (19)
    uint64_t zone_size = NVME_DEFAULT_ZONE_SIZE / MIN_DISCARD_GRANULARITY;
    uint64_t zperrow = spp->nchnls / factor ; /* zones per row */

    uint64_t base = (zone_idx / zperrow)*(zperrow*zone_size) + ((zone_idx % zperrow)*(spp->nchnls/zperrow));
    uint64_t iter = (slpa / factor) % (zone_size/factor);
    uint64_t iter_value = spp->nchnls;
    uint64_t mod = slpa%factor;
    //femu_err("In zns_advanced_chnl_idx (zidx : %ld, zsz : %ld, spla : %ld) base(%ld)+ iter(%ld)*iter_value(%ld) + mod(%ld) = %ld \n",zone_idx,zone_size,slpa, base,iter,iter_value,mod,(base + iter*iter_value + mod));
    // return ppa % nchnls
    return (base + iter*iter_value + mod) % spp->nchnls;
}

static inline uint64_t zns_get_multiway_ppn_idx(NvmeNamespace *ns, uint64_t slba){
    FemuCtrl *n = ns->ctrl;
    struct zns * zns = n->zns;
    struct zns_ssdparams *spp = &zns->sp;
    uint64_t zone_size = NVME_DEFAULT_ZONE_SIZE / MIN_DISCARD_GRANULARITY;
    uint64_t degree = spp->chnls_per_zone;  /* w.r.t 1-to-N mapping */
    uint64_t way    = spp->ways;
    uint64_t zone_idx = zns_zone_idx(ns, slba);
    uint64_t slpa = slba >> 3;
    //            = slba >> (22) << (19)

    uint64_t b_iter         =zone_idx % (spp->nchnls / degree);
    uint64_t b_iter_value   =spp->csze_pages * degree;
    uint64_t b_mod          =(zone_idx * degree / spp->nchnls)*(zone_size/way/degree);
    uint64_t base           =(b_iter * b_iter_value) + b_mod;

    uint64_t iter           =(slpa / degree) % way;
    uint64_t iter_value     =spp->csze_pages * spp->nchnls; //Inhoinno, Actually this is : spp->csze_pages * chips_per_row;
    uint64_t mod            =(slpa % degree) * spp->csze_pages;
    uint64_t mod_zpn        =(zone_idx > 0)? (slpa % (zone_idx*zone_size))/(degree * way) : slpa/(degree * way); 

    //femu_err("In zns_advanced_chnl_idx (zidx : %ld, zsz : %ld, spla : %ld) base(%ld)+ iter(%ld)*iter_value(%ld) + mod(%ld) = %ld \n",zone_idx,zone_size,slpa, base,iter,iter_value,mod,(base + iter*iter_value + mod));
    // return ppa % nchnls
    return (base + iter*iter_value + mod + mod_zpn);
}

static inline uint64_t zns_get_multiway_chip_idx(NvmeNamespace *ns, uint64_t slba){
    FemuCtrl *n = ns->ctrl;
    struct zns * zns = n->zns;
    struct zns_ssdparams *spp = &zns->sp;
    return (zns_get_multiway_ppn_idx(ns,slba)/spp->csze_pages);
}

static inline uint64_t zns_get_multiway_chnl_idx(NvmeNamespace *ns, uint64_t slba)
{
    FemuCtrl *n = ns->ctrl;
    struct zns * zns = n->zns;
    struct zns_ssdparams *spp = &zns->sp;
    return zns_get_multiway_chip_idx(ns, slba) % spp->nchnls;
}


static inline NvmeZone *zns_get_zone_by_slba(NvmeNamespace *ns, uint64_t slba)
{
    FemuCtrl *n = ns->ctrl;
    uint32_t zone_idx = zns_zone_idx(ns, slba);
    #ifdef INHOINNO_VERBOSE_SETTING
    femu_err("zns.c : zns_get_zone_by_slba(), to inhoinno \n");
    #endif
    assert(zone_idx < n->num_zones);
    return &n->zone_array[zone_idx];
}

static int zns_init_zone_geometry(NvmeNamespace *ns, Error **errp)
{
    FemuCtrl *n = ns->ctrl;
    uint64_t zone_size, zone_cap;
    uint32_t lbasz = 1 << zns_ns_lbads(ns);
    #ifdef INHOINNO_VERBOSE_SETTING
    femu_err("zns.c : zns_init_zone_geometry(), to inhoinno \n");
    #endif
    if (n->zone_size_bs) {
        zone_size = n->zone_size_bs;
    } else {
        zone_size = NVME_DEFAULT_ZONE_SIZE;
    }

    if (n->zone_cap_bs) {
        zone_cap = n->zone_cap_bs;
    } else {
        zone_cap = zone_size;
    }

    if (zone_cap > zone_size) {
        femu_err("zone capacity %luB > zone size %luB", zone_cap, zone_size);
        return -1;
    }
    if (zone_size < lbasz) {
        femu_err("zone size %luB too small, must >= %uB", zone_size, lbasz);
        return -1;
    }
    if (zone_cap < lbasz) {
        femu_err("zone capacity %luB too small, must >= %uB", zone_cap, lbasz);
        return -1;
    }

    n->zone_size = zone_size / lbasz;
    femu_err("zns.c : zns_init_zone_geometry, 62:n->zone_size(%ld) = zone_size(%ld) / lbasz(%d) to inhoinno", n->zone_size, zone_size, lbasz);
    n->zone_capacity = zone_cap / lbasz;
    n->num_zones = ns->size / lbasz / n->zone_size;
    // ?         = ?        / 512   /  128MB / 512;

    if (n->max_open_zones > n->num_zones) {
        femu_err("max_open_zones value %u exceeds the number of zones %u",
                 n->max_open_zones, n->num_zones);
        return -1;
    }
    if (n->max_active_zones > n->num_zones) {
        femu_err("max_active_zones value %u exceeds the number of zones %u",
                 n->max_active_zones, n->num_zones);
        return -1;
    }

    if (n->zd_extension_size) {
        if (n->zd_extension_size & 0x3f) {
            femu_err("zone descriptor extension size must be multiples of 64B");
            return -1;
        }
        if ((n->zd_extension_size >> 6) > 0xff) {
            femu_err("zone descriptor extension size is too large");
            return -1;
        }
    }

    return 0;
}

static void zns_init_zoned_state(NvmeNamespace *ns)
{
    FemuCtrl *n = ns->ctrl;
    uint64_t start = 0, zone_size = n->zone_size;
    uint64_t capacity = n->num_zones * zone_size;
    NvmeZone *zone;
    int i;
    #ifdef INHOINNO_VERBOSE_SETTING
    femu_err("zns.c : zns_init_zoned_state(), to inhoinno \n");
    #endif
    n->zone_array = g_new0(NvmeZone, n->num_zones);
    if (n->zd_extension_size) {
        n->zd_extensions = g_malloc0(n->zd_extension_size * n->num_zones);
    }

    QTAILQ_INIT(&n->exp_open_zones);
    QTAILQ_INIT(&n->imp_open_zones);
    QTAILQ_INIT(&n->closed_zones);
    QTAILQ_INIT(&n->full_zones);

    zone = n->zone_array;
    for (i = 0; i < n->num_zones; i++, zone++) {
        if (start + zone_size > capacity) {
            zone_size = capacity - start;
        }
        zone->d.zt = NVME_ZONE_TYPE_SEQ_WRITE;
        zns_set_zone_state(zone, NVME_ZONE_STATE_EMPTY);
        zone->d.za = 0;
        zone->d.zcap = n->zone_capacity;
        zone->d.zslba = start;
        zone->d.wp = start;
        zone->w_ptr = start;
        start += zone_size;
    }

    n->zone_size_log2 = 0;
    if (is_power_of_2(n->zone_size)) {
        n->zone_size_log2 = 63 - clz64(n->zone_size);   // 18 = 63 - 45
        femu_err("zns_init_zoned_state : n->zone_size_log2 %d to inhoinno\n", n->zone_size_log2);
        femu_err("zns_init_zoned_state : n->zone_size %ld to inhoinno\n", n->zone_capacity);

    }
}

static void  zns_init_zone_identify(FemuCtrl *n, NvmeNamespace *ns, int lba_index)
{
    NvmeIdNsZoned *id_ns_z;
    #ifdef INHOINNO_VERBOSE_SETTING
    femu_err("zns.c : zns_init_zone_identify(), to inhoinno \n");
    #endif
    zns_init_zoned_state(ns);

    id_ns_z = g_malloc0(sizeof(NvmeIdNsZoned));

    /* MAR/MOR are zeroes-based, 0xffffffff means no limit */
    id_ns_z->mar = cpu_to_le32(n->max_active_zones - 1);
    id_ns_z->mor = cpu_to_le32(n->max_open_zones - 1);
    id_ns_z->zoc = 0;
    id_ns_z->ozcs = n->cross_zone_read ? 0x01 : 0x00;

    id_ns_z->lbafe[lba_index].zsze = cpu_to_le64(n->zone_size);
    id_ns_z->lbafe[lba_index].zdes = n->zd_extension_size >> 6; /* Units of 64B */

    n->csi = NVME_CSI_ZONED;
    ns->id_ns.nsze = cpu_to_le64(n->num_zones * n->zone_size);
    ns->id_ns.ncap = ns->id_ns.nsze;
    ns->id_ns.nuse = ns->id_ns.ncap;

    /* NvmeIdNs */
    /*
     * The device uses the BDRV_BLOCK_ZERO flag to determine the "deallocated"
     * status of logical blocks. Since the spec defines that logical blocks
     * SHALL be deallocated when then zone is in the Empty or Offline states,
     * we can only support DULBE if the zone size is a multiple of the
     * calculated NPDG.
     */
    if (n->zone_size % (ns->id_ns.npdg + 1)) {
        femu_err("the zone size (%"PRIu64" blocks) is not a multiple of the"
                 "calculated deallocation granularity (%"PRIu16" blocks); DULBE"
                 "support disabled", n->zone_size, ns->id_ns.npdg + 1);
        ns->id_ns.nsfeat &= ~0x4;
    }

    n->id_ns_zoned = id_ns_z;
}

static void zns_clear_zone(NvmeNamespace *ns, NvmeZone *zone)
{
    FemuCtrl *n = ns->ctrl;
    uint8_t state;
    #ifdef INHOINNO_VERBOSE_SETTING
    femu_err("zns.c : zns_clear_zone(), to inhoinno \n");
    #endif
    zone->w_ptr = zone->d.wp;
    state = zns_get_zone_state(zone);
    if (zone->d.wp != zone->d.zslba ||
        (zone->d.za & NVME_ZA_ZD_EXT_VALID)) {
        if (state != NVME_ZONE_STATE_CLOSED) {
            zns_set_zone_state(zone, NVME_ZONE_STATE_CLOSED);
        }
        zns_aor_inc_active(ns);
        QTAILQ_INSERT_HEAD(&n->closed_zones, zone, entry);
    } else {
        zns_set_zone_state(zone, NVME_ZONE_STATE_EMPTY);
    }
}

static void zns_zoned_ns_shutdown(NvmeNamespace *ns)
{
    FemuCtrl *n = ns->ctrl;
    NvmeZone *zone, *next;
    #ifdef INHOINNO_VERBOSE_SETTING
    femu_err("zns.c : zns_zoned_ns_shutdown(), to inhoinno \n");
    #endif
    QTAILQ_FOREACH_SAFE(zone, &n->closed_zones, entry, next) {
        QTAILQ_REMOVE(&n->closed_zones, zone, entry);
        zns_aor_dec_active(ns);
        zns_clear_zone(ns, zone);
    }
    QTAILQ_FOREACH_SAFE(zone, &n->imp_open_zones, entry, next) {
        QTAILQ_REMOVE(&n->imp_open_zones, zone, entry);
        zns_aor_dec_open(ns);
        zns_aor_dec_active(ns);
        zns_clear_zone(ns, zone);
    }
    QTAILQ_FOREACH_SAFE(zone, &n->exp_open_zones, entry, next) {
        QTAILQ_REMOVE(&n->exp_open_zones, zone, entry);
        zns_aor_dec_open(ns);
        zns_aor_dec_active(ns);
        zns_clear_zone(ns, zone);
    }

    assert(n->nr_open_zones == 0);
}

void zns_ns_shutdown(NvmeNamespace *ns)
{
    FemuCtrl *n = ns->ctrl;
    #ifdef INHOINNO_VERBOSE_SETTING
    femu_err("zns.c : zns_ns_shutdown(), to inhoinno \n");
    #endif
    if (n->zoned) {
        zns_zoned_ns_shutdown(ns);
    }
}

void zns_ns_cleanup(NvmeNamespace *ns)
{
    FemuCtrl *n = ns->ctrl;
    #ifdef INHOINNO_VERBOSE_SETTING
    femu_err("zns.c : zns_ns_cleanup(), to inhoinno \n");
    #endif
    if (n->zoned) {
        g_free(n->id_ns_zoned);
        g_free(n->zone_array);
        g_free(n->zd_extensions);
    }
}

static void zns_assign_zone_state(NvmeNamespace *ns, NvmeZone *zone,
                                  NvmeZoneState state)
{
    FemuCtrl *n = ns->ctrl;
    #ifdef INHOINNO_VERBOSE_SETTING
    femu_err("zns.c : zns_assign_zone_state(), to inhoinno \n");
    #endif
    if (QTAILQ_IN_USE(zone, entry)) {
        switch (zns_get_zone_state(zone)) {
        case NVME_ZONE_STATE_EXPLICITLY_OPEN:
            QTAILQ_REMOVE(&n->exp_open_zones, zone, entry);
            break;
        case NVME_ZONE_STATE_IMPLICITLY_OPEN:
            QTAILQ_REMOVE(&n->imp_open_zones, zone, entry);
            break;
        case NVME_ZONE_STATE_CLOSED:
            QTAILQ_REMOVE(&n->closed_zones, zone, entry);
            break;
        case NVME_ZONE_STATE_FULL:
            QTAILQ_REMOVE(&n->full_zones, zone, entry);
        default:
            ;
        }
    }

    zns_set_zone_state(zone, state);

    switch (state) {
    case NVME_ZONE_STATE_EXPLICITLY_OPEN:
        QTAILQ_INSERT_TAIL(&n->exp_open_zones, zone, entry);
        break;
    case NVME_ZONE_STATE_IMPLICITLY_OPEN:
        QTAILQ_INSERT_TAIL(&n->imp_open_zones, zone, entry);
        break;
    case NVME_ZONE_STATE_CLOSED:
        QTAILQ_INSERT_TAIL(&n->closed_zones, zone, entry);
        break;
    case NVME_ZONE_STATE_FULL:
        QTAILQ_INSERT_TAIL(&n->full_zones, zone, entry);
    case NVME_ZONE_STATE_READ_ONLY:
        break;
    default:
        zone->d.za = 0;
    }
}

/*
 * Check if we can open a zone without exceeding open/active limits.
 * AOR stands for "Active and Open Resources" (see TP 4053 section 2.5).
 */
static int zns_aor_check(NvmeNamespace *ns, uint32_t act, uint32_t opn)
{
    FemuCtrl *n = ns->ctrl;
    #ifdef INHOINNO_VERBOSE_SETTING
    femu_err("zns.c : zns_aor_check(), to inhoinno \n");
    #endif
    if (n->max_active_zones != 0 &&
        n->nr_active_zones + act > n->max_active_zones) {
        return NVME_ZONE_TOO_MANY_ACTIVE | NVME_DNR;
    }
    if (n->max_open_zones != 0 &&
        n->nr_open_zones + opn > n->max_open_zones) {
        return NVME_ZONE_TOO_MANY_OPEN | NVME_DNR;
    }

    return NVME_SUCCESS;
}

static uint16_t zns_check_zone_state_for_write(NvmeZone *zone)
{
    uint16_t status;
    #ifdef INHOINNO_VERBOSE_SETTING
    femu_err("zns.c : zns_check_zone_state_for_write(), to inhoinno \n");
    #endif
    switch (zns_get_zone_state(zone)) {
    case NVME_ZONE_STATE_EMPTY:
    case NVME_ZONE_STATE_IMPLICITLY_OPEN:
    case NVME_ZONE_STATE_EXPLICITLY_OPEN:
    case NVME_ZONE_STATE_CLOSED:
        status = NVME_SUCCESS;
        break;
    case NVME_ZONE_STATE_FULL:
        status = NVME_ZONE_FULL;
        break;
    case NVME_ZONE_STATE_OFFLINE:
        status = NVME_ZONE_OFFLINE;
        break;
    case NVME_ZONE_STATE_READ_ONLY:
        status = NVME_ZONE_READ_ONLY;
        break;
    default:
        assert(false);
    }

    return status;
}

static uint16_t zns_check_zone_write(FemuCtrl *n, NvmeNamespace *ns,
                                      NvmeZone *zone, uint64_t slba,
                                      uint32_t nlb, bool append)
{
    uint16_t status;
    #ifdef INHOINNO_VERBOSE_SETTING
    femu_err("zns.c : zns_check_zone_write(), to inhoinno \n");
    #endif
    if (unlikely((slba + nlb) > zns_zone_wr_boundary(zone))) {
        femu_err("zns.c :388 zns_check_zone_write(), boundary error slba%ld nlb%d to inhoinno \n", slba, nlb);
        status = NVME_ZONE_BOUNDARY_ERROR;
    } else {
        status = zns_check_zone_state_for_write(zone);
    }

    if (status != NVME_SUCCESS) {
    } else {
        assert(zns_wp_is_valid(zone));
        if (append) {
            if (unlikely(slba != zone->d.zslba)) {
                status = NVME_INVALID_FIELD;
            }
            if (zns_l2b(ns, nlb) > (n->page_size << n->zasl)) {
                status = NVME_INVALID_FIELD;
            }
        } else if ( unlikely(slba != zone->w_ptr) ) {
            femu_err("zns.c :405 zns_check_zone_write(), NVME_ZONE_INVALID_WRITE slba%ld nlb %d zone->w_ptr%ld zidx%d to inhoinno \n", slba, nlb,zone->w_ptr, zns_zone_idx(ns,slba));
            status = NVME_ZONE_INVALID_WRITE;   
        }
    }
    return status;
}

static uint16_t zns_check_zone_state_for_read(NvmeZone *zone)
{
    uint16_t status;
    #ifdef INHOINNO_VERBOSE_SETTING
    femu_err("zns.c : zns_check_zone_state_for_read(), to inhoinno \n");
    #endif
    switch (zns_get_zone_state(zone)) {
    case NVME_ZONE_STATE_EMPTY:
    case NVME_ZONE_STATE_IMPLICITLY_OPEN:
    case NVME_ZONE_STATE_EXPLICITLY_OPEN:
    case NVME_ZONE_STATE_FULL:
    case NVME_ZONE_STATE_CLOSED:
    case NVME_ZONE_STATE_READ_ONLY:
        status = NVME_SUCCESS;
        break;
    case NVME_ZONE_STATE_OFFLINE:
        status = NVME_ZONE_OFFLINE;
        break;
    default:
        assert(false);
    }

    return status;
}

static uint16_t zns_check_zone_read(NvmeNamespace *ns, uint64_t slba,
                                    uint32_t nlb)
{
    FemuCtrl *n = ns->ctrl;
    NvmeZone *zone = zns_get_zone_by_slba(ns, slba);
    uint64_t bndry = zns_zone_rd_boundary(ns, zone);
    uint64_t end = slba + nlb;
    uint16_t status;
    #ifdef INHOINNO_VERBOSE_SETTING
    femu_err("zns.c : zns_check_zone_read(), to inhoinno \n");
    #endif
    status = zns_check_zone_state_for_read(zone);
    if (status != NVME_SUCCESS) {
        ;
    } else if (unlikely(end > bndry)) {
        if (!n->cross_zone_read) {
            status = NVME_ZONE_BOUNDARY_ERROR;
        } else {
            /*
             * Read across zone boundary - check that all subsequent
             * zones that are being read have an appropriate state.
             */
            do {
                zone++;
                status = zns_check_zone_state_for_read(zone);
                if (status != NVME_SUCCESS) {
                    break;
                }
            } while (end > zns_zone_rd_boundary(ns, zone));
        }
    }

    return status;
}

static void zns_auto_transition_zone(NvmeNamespace *ns)
{
    FemuCtrl *n = ns->ctrl;
    NvmeZone *zone;
    #ifdef INHOINNO_VERBOSE_SETTING
    femu_err("zns.c : zns_auto_transition_zone(), to inhoinno \n");
    #endif
    if (n->max_open_zones &&
        n->nr_open_zones == n->max_open_zones) {
        zone = QTAILQ_FIRST(&n->imp_open_zones);
        if (zone) {
             /* Automatically close this implicitly open zone */
            QTAILQ_REMOVE(&n->imp_open_zones, zone, entry);
            zns_aor_dec_open(ns);
            zns_assign_zone_state(ns, zone, NVME_ZONE_STATE_CLOSED);
        }
    }
}

static uint16_t zns_auto_open_zone(NvmeNamespace *ns, NvmeZone *zone)
{
    uint16_t status = NVME_SUCCESS;
    uint8_t zs = zns_get_zone_state(zone);
    #ifdef INHOINNO_VERBOSE_SETTING
    femu_err("zns.c : zns_auto_open_zone(), to inhoinno \n");
    #endif
    if (zs == NVME_ZONE_STATE_EMPTY) {
        zns_auto_transition_zone(ns);
        status = zns_aor_check(ns, 1, 1);
    } else if (zs == NVME_ZONE_STATE_CLOSED) {
        zns_auto_transition_zone(ns);
        status = zns_aor_check(ns, 0, 1);
    }

    return status;
}

static void zns_finalize_zoned_write(NvmeNamespace *ns, NvmeRequest *req,
                                     bool failed)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)&req->cmd;
    NvmeZone *zone;
    NvmeZonedResult *res = (NvmeZonedResult *)&req->cqe;
    uint64_t slba;
    uint32_t nlb;
    #ifdef INHOINNO_VERBOSE_SETTING
    femu_err("zns.c : zns_finalize_zoned_write(), to inhoinno \n");
    #endif
    slba = le64_to_cpu(rw->slba);
    nlb = le16_to_cpu(rw->nlb) + 1;
    zone = zns_get_zone_by_slba(ns, slba);

    zone->d.wp += nlb;

    if (failed) {
        res->slba = 0;
    }

    if (zone->d.wp == zns_zone_wr_boundary(zone)) {
        switch (zns_get_zone_state(zone)) {
        case NVME_ZONE_STATE_IMPLICITLY_OPEN:
        case NVME_ZONE_STATE_EXPLICITLY_OPEN:
            zns_aor_dec_open(ns);
            /* fall through */
        case NVME_ZONE_STATE_CLOSED:
            zns_aor_dec_active(ns);
            /* fall through */
        case NVME_ZONE_STATE_EMPTY:
            zns_assign_zone_state(ns, zone, NVME_ZONE_STATE_FULL);
            /* fall through */
        case NVME_ZONE_STATE_FULL:
            break;
        default:
            assert(false);
        }
    }
}

static uint64_t zns_advance_zone_wp(NvmeNamespace *ns, NvmeZone *zone,
                                    uint32_t nlb)
{
    uint64_t result = zone->w_ptr;
    uint8_t zs;

    zone->w_ptr += nlb;

    if (zone->w_ptr < zns_zone_wr_boundary(zone)) {
        zs = zns_get_zone_state(zone);
        switch (zs) {
        case NVME_ZONE_STATE_EMPTY:
            zns_aor_inc_active(ns);
            /* fall through */
        case NVME_ZONE_STATE_CLOSED:
            zns_aor_inc_open(ns);
            zns_assign_zone_state(ns, zone, NVME_ZONE_STATE_IMPLICITLY_OPEN);
        }
    }

    return result;
}

struct zns_zone_reset_ctx {
    NvmeRequest *req;
    NvmeZone    *zone;
};

static void zns_aio_zone_reset_cb(NvmeRequest *req, NvmeZone *zone)
{
    NvmeNamespace *ns = req->ns;

    /* FIXME, We always assume reset SUCCESS */
    switch (zns_get_zone_state(zone)) {
    case NVME_ZONE_STATE_EXPLICITLY_OPEN:
    case NVME_ZONE_STATE_IMPLICITLY_OPEN:
        zns_aor_dec_open(ns);
    case NVME_ZONE_STATE_CLOSED:
        zns_aor_dec_active(ns);
    case NVME_ZONE_STATE_FULL:
        zone->w_ptr = zone->d.zslba;
        zone->d.wp = zone->w_ptr;
        zns_assign_zone_state(ns, zone, NVME_ZONE_STATE_EMPTY);
    default:
        break;
    }
}

typedef uint16_t (*op_handler_t)(NvmeNamespace *, NvmeZone *, NvmeZoneState,
                                 NvmeRequest *);

enum NvmeZoneProcessingMask {
    NVME_PROC_CURRENT_ZONE    = 0,
    NVME_PROC_OPENED_ZONES    = 1 << 0,
    NVME_PROC_CLOSED_ZONES    = 1 << 1,
    NVME_PROC_READ_ONLY_ZONES = 1 << 2,
    NVME_PROC_FULL_ZONES      = 1 << 3,
};

static uint16_t zns_open_zone(NvmeNamespace *ns, NvmeZone *zone,
                              NvmeZoneState state, NvmeRequest *req)
{
    uint16_t status;
    #ifdef INHOINNO_VERBOSE_SETTING
    femu_err("zns.c : zns_open_zone(), to inhoinno \n");
    #endif
    switch (state) {
    case NVME_ZONE_STATE_EMPTY:
        status = zns_aor_check(ns, 1, 0);
        if (status != NVME_SUCCESS) {
            return status;
        }
        zns_aor_inc_active(ns);
    case NVME_ZONE_STATE_CLOSED:
        status = zns_aor_check(ns, 0, 1);
        if (status != NVME_SUCCESS) {
            if (state == NVME_ZONE_STATE_EMPTY) {
                zns_aor_dec_active(ns);
            }
            return status;
        }
        zns_aor_inc_open(ns);
    case NVME_ZONE_STATE_IMPLICITLY_OPEN:
        zns_assign_zone_state(ns, zone, NVME_ZONE_STATE_EXPLICITLY_OPEN);
    case NVME_ZONE_STATE_EXPLICITLY_OPEN:
        return NVME_SUCCESS;
    default:
        return NVME_ZONE_INVAL_TRANSITION;
    }
}

static uint16_t zns_close_zone(NvmeNamespace *ns, NvmeZone *zone,
                               NvmeZoneState state, NvmeRequest *req)
{
    switch (state) {
    case NVME_ZONE_STATE_EXPLICITLY_OPEN:
    case NVME_ZONE_STATE_IMPLICITLY_OPEN:
        zns_aor_dec_open(ns);
        zns_assign_zone_state(ns, zone, NVME_ZONE_STATE_CLOSED);
    case NVME_ZONE_STATE_CLOSED:
        return NVME_SUCCESS;
    default:
        return NVME_ZONE_INVAL_TRANSITION;
    }
}

static uint16_t zns_finish_zone(NvmeNamespace *ns, NvmeZone *zone,
                                NvmeZoneState state, NvmeRequest *req)
{
    switch (state) {
    case NVME_ZONE_STATE_EXPLICITLY_OPEN:
    case NVME_ZONE_STATE_IMPLICITLY_OPEN:
        zns_aor_dec_open(ns);
    case NVME_ZONE_STATE_CLOSED:
        zns_aor_dec_active(ns);
    case NVME_ZONE_STATE_EMPTY:
        zone->w_ptr = zns_zone_wr_boundary(zone);
        zone->d.wp = zone->w_ptr;
        zns_assign_zone_state(ns, zone, NVME_ZONE_STATE_FULL);
    case NVME_ZONE_STATE_FULL:
        return NVME_SUCCESS;
    default:
        return NVME_ZONE_INVAL_TRANSITION;
    }
}

static uint16_t zns_reset_zone(NvmeNamespace *ns, NvmeZone *zone,
                               NvmeZoneState state, NvmeRequest *req)
{
    switch (state) {
    case NVME_ZONE_STATE_EMPTY:
        return NVME_SUCCESS;
    case NVME_ZONE_STATE_EXPLICITLY_OPEN:
    case NVME_ZONE_STATE_IMPLICITLY_OPEN:
    case NVME_ZONE_STATE_CLOSED:
    case NVME_ZONE_STATE_FULL:
        break;
    default:
        return NVME_ZONE_INVAL_TRANSITION;
    }

    zns_aio_zone_reset_cb(req, zone);

    return NVME_SUCCESS;
}

static uint16_t zns_offline_zone(NvmeNamespace *ns, NvmeZone *zone,
                                 NvmeZoneState state, NvmeRequest *req)
{
    switch (state) {
    case NVME_ZONE_STATE_READ_ONLY:
        zns_assign_zone_state(ns, zone, NVME_ZONE_STATE_OFFLINE);
    case NVME_ZONE_STATE_OFFLINE:
        return NVME_SUCCESS;
    default:
        return NVME_ZONE_INVAL_TRANSITION;
    }
}

static uint16_t zns_set_zd_ext(NvmeNamespace *ns, NvmeZone *zone)
{
    uint16_t status;
    uint8_t state = zns_get_zone_state(zone);

    if (state == NVME_ZONE_STATE_EMPTY) {
        status = zns_aor_check(ns, 1, 0);
        if (status != NVME_SUCCESS) {
            return status;
        }
        zns_aor_inc_active(ns);
        zone->d.za |= NVME_ZA_ZD_EXT_VALID;
        zns_assign_zone_state(ns, zone, NVME_ZONE_STATE_CLOSED);
        return NVME_SUCCESS;
    }

    return NVME_ZONE_INVAL_TRANSITION;
}

static uint16_t zns_bulk_proc_zone(NvmeNamespace *ns, NvmeZone *zone,
                                   enum NvmeZoneProcessingMask proc_mask,
                                   op_handler_t op_hndlr, NvmeRequest *req)
{
    uint16_t status = NVME_SUCCESS;
    NvmeZoneState zs = zns_get_zone_state(zone);
    bool proc_zone;

    switch (zs) {
    case NVME_ZONE_STATE_IMPLICITLY_OPEN:
    case NVME_ZONE_STATE_EXPLICITLY_OPEN:
        proc_zone = proc_mask & NVME_PROC_OPENED_ZONES;
        break;
    case NVME_ZONE_STATE_CLOSED:
        proc_zone = proc_mask & NVME_PROC_CLOSED_ZONES;
        break;
    case NVME_ZONE_STATE_READ_ONLY:
        proc_zone = proc_mask & NVME_PROC_READ_ONLY_ZONES;
        break;
    case NVME_ZONE_STATE_FULL:
        proc_zone = proc_mask & NVME_PROC_FULL_ZONES;
        break;
    default:
        proc_zone = false;
    }

    if (proc_zone) {
        status = op_hndlr(ns, zone, zs, req);
    }

    return status;
}

static uint16_t zns_do_zone_op(NvmeNamespace *ns, NvmeZone *zone,
                               enum NvmeZoneProcessingMask proc_mask,
                               op_handler_t op_hndlr, NvmeRequest *req)
{
    FemuCtrl *n = ns->ctrl;
    NvmeZone *next;
    uint16_t status = NVME_SUCCESS;
    int i;

    if (!proc_mask) {
        status = op_hndlr(ns, zone, zns_get_zone_state(zone), req);
    } else {
        if (proc_mask & NVME_PROC_CLOSED_ZONES) {
            QTAILQ_FOREACH_SAFE(zone, &n->closed_zones, entry, next) {
                status = zns_bulk_proc_zone(ns, zone, proc_mask, op_hndlr,
                                             req);
                if (status && status != NVME_NO_COMPLETE) {
                    goto out;
                }
            }
        }
        if (proc_mask & NVME_PROC_OPENED_ZONES) {
            QTAILQ_FOREACH_SAFE(zone, &n->imp_open_zones, entry, next) {
                status = zns_bulk_proc_zone(ns, zone, proc_mask, op_hndlr,
                                             req);
                if (status && status != NVME_NO_COMPLETE) {
                    goto out;
                }
            }

            QTAILQ_FOREACH_SAFE(zone, &n->exp_open_zones, entry, next) {
                status = zns_bulk_proc_zone(ns, zone, proc_mask, op_hndlr,
                                             req);
                if (status && status != NVME_NO_COMPLETE) {
                    goto out;
                }
            }
        }
        if (proc_mask & NVME_PROC_FULL_ZONES) {
            QTAILQ_FOREACH_SAFE(zone, &n->full_zones, entry, next) {
                status = zns_bulk_proc_zone(ns, zone, proc_mask, op_hndlr,
                                             req);
                if (status && status != NVME_NO_COMPLETE) {
                    goto out;
                }
            }
        }

        if (proc_mask & NVME_PROC_READ_ONLY_ZONES) {
            for (i = 0; i < n->num_zones; i++, zone++) {
                status = zns_bulk_proc_zone(ns, zone, proc_mask, op_hndlr,
                                             req);
                if (status && status != NVME_NO_COMPLETE) {
                    goto out;
                }
            }
        }
    }

out:
    return status;
}

static uint16_t zns_get_mgmt_zone_slba_idx(FemuCtrl *n, NvmeCmd *c,
                                           uint64_t *slba, uint32_t *zone_idx)
{
    NvmeNamespace *ns = &n->namespaces[0];
    uint32_t dw10 = le32_to_cpu(c->cdw10);
    uint32_t dw11 = le32_to_cpu(c->cdw11);

    if (!n->zoned) {
        return NVME_INVALID_OPCODE | NVME_DNR;
    }

    *slba = ((uint64_t)dw11) << 32 | dw10;
    if (unlikely(*slba >= ns->id_ns.nsze)) {
        *slba = 0;
        return NVME_LBA_RANGE | NVME_DNR;
    }

    *zone_idx = zns_zone_idx(ns, *slba);
    assert(*zone_idx < n->num_zones);

    return NVME_SUCCESS;
}

static uint16_t zns_zone_mgmt_send(FemuCtrl *n, NvmeRequest *req)
{
    NvmeCmd *cmd = (NvmeCmd *)&req->cmd;
    NvmeNamespace *ns = req->ns;
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);
    NvmeZone *zone;
    uintptr_t *resets;
    uint8_t *zd_ext;
    uint32_t dw13 = le32_to_cpu(cmd->cdw13);
    uint64_t slba = 0;
    uint32_t zone_idx = 0;
    uint16_t status;
    uint8_t action;
    bool all;
    enum NvmeZoneProcessingMask proc_mask = NVME_PROC_CURRENT_ZONE;

    action = dw13 & 0xff;
    all = dw13 & 0x100;

    req->status = NVME_SUCCESS;

    if (!all) {
        status = zns_get_mgmt_zone_slba_idx(n, cmd, &slba, &zone_idx);
        if (status) {
            return status;
        }
    }

    zone = &n->zone_array[zone_idx];
    if (slba != zone->d.zslba) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    switch (action) {
    case NVME_ZONE_ACTION_OPEN:
        if (all) {
            proc_mask = NVME_PROC_CLOSED_ZONES;
        }
        status = zns_do_zone_op(ns, zone, proc_mask, zns_open_zone, req);
        break;
    case NVME_ZONE_ACTION_CLOSE:
        if (all) {
            proc_mask = NVME_PROC_OPENED_ZONES;
        }
        status = zns_do_zone_op(ns, zone, proc_mask, zns_close_zone, req);
        break;
    case NVME_ZONE_ACTION_FINISH:
        if (all) {
            proc_mask = NVME_PROC_OPENED_ZONES | NVME_PROC_CLOSED_ZONES;
        }
        status = zns_do_zone_op(ns, zone, proc_mask, zns_finish_zone, req);
        break;
    case NVME_ZONE_ACTION_RESET:
        resets = (uintptr_t *)&req->opaque;

        if (all) {
            proc_mask = NVME_PROC_OPENED_ZONES | NVME_PROC_CLOSED_ZONES |
                NVME_PROC_FULL_ZONES;
        }
        *resets = 1;
        status = zns_do_zone_op(ns, zone, proc_mask, zns_reset_zone, req);
        (*resets)--;
        return NVME_SUCCESS;
    case NVME_ZONE_ACTION_OFFLINE:
        if (all) {
            proc_mask = NVME_PROC_READ_ONLY_ZONES;
        }
        status = zns_do_zone_op(ns, zone, proc_mask, zns_offline_zone, req);
        break;
    case NVME_ZONE_ACTION_SET_ZD_EXT:
        if (all || !n->zd_extension_size) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        zd_ext = zns_get_zd_extension(ns, zone_idx);
        status = dma_write_prp(n, (uint8_t *)zd_ext, n->zd_extension_size, prp1,
                               prp2);
        if (status) {
            return status;
        }
        status = zns_set_zd_ext(ns, zone);
        if (status == NVME_SUCCESS) {
            return status;
        }
        break;
    default:
        status = NVME_INVALID_FIELD;
    }

    if (status) {
        status |= NVME_DNR;
    }

    return status;
}

static bool zns_zone_matches_filter(uint32_t zafs, NvmeZone *zl)
{
    NvmeZoneState zs = zns_get_zone_state(zl);

    switch (zafs) {
    case NVME_ZONE_REPORT_ALL:
        return true;
    case NVME_ZONE_REPORT_EMPTY:
        return zs == NVME_ZONE_STATE_EMPTY;
    case NVME_ZONE_REPORT_IMPLICITLY_OPEN:
        return zs == NVME_ZONE_STATE_IMPLICITLY_OPEN;
    case NVME_ZONE_REPORT_EXPLICITLY_OPEN:
        return zs == NVME_ZONE_STATE_EXPLICITLY_OPEN;
    case NVME_ZONE_REPORT_CLOSED:
        return zs == NVME_ZONE_STATE_CLOSED;
    case NVME_ZONE_REPORT_FULL:
        return zs == NVME_ZONE_STATE_FULL;
    case NVME_ZONE_REPORT_READ_ONLY:
        return zs == NVME_ZONE_STATE_READ_ONLY;
    case NVME_ZONE_REPORT_OFFLINE:
        return zs == NVME_ZONE_STATE_OFFLINE;
    default:
        return false;
    }
}

static uint16_t zns_zone_mgmt_recv(FemuCtrl *n, NvmeRequest *req)
{
    NvmeCmd *cmd = (NvmeCmd *)&req->cmd;
    NvmeNamespace *ns = req->ns;
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);
    /* cdw12 is zero-based number of dwords to return. Convert to bytes */
    uint32_t data_size = (le32_to_cpu(cmd->cdw12) + 1) << 2;
    uint32_t dw13 = le32_to_cpu(cmd->cdw13);
    uint32_t zone_idx, zra, zrasf, partial;
    uint64_t max_zones, nr_zones = 0;
    uint16_t status;
    uint64_t slba, capacity = zns_ns_nlbas(ns);
    NvmeZoneDescr *z;
    NvmeZone *zone;
    NvmeZoneReportHeader *header;
    void *buf, *buf_p;
    size_t zone_entry_sz;

    req->status = NVME_SUCCESS;

    status = zns_get_mgmt_zone_slba_idx(n, cmd, &slba, &zone_idx);
    if (status) {
        return status;
    }

    zra = dw13 & 0xff;
    if (zra != NVME_ZONE_REPORT && zra != NVME_ZONE_REPORT_EXTENDED) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (zra == NVME_ZONE_REPORT_EXTENDED && !n->zd_extension_size) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    zrasf = (dw13 >> 8) & 0xff;
    if (zrasf > NVME_ZONE_REPORT_OFFLINE) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (data_size < sizeof(NvmeZoneReportHeader)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    status = nvme_check_mdts(n, data_size);
    if (status) {
        return status;
    }

    partial = (dw13 >> 16) & 0x01;

    zone_entry_sz = sizeof(NvmeZoneDescr);
    if (zra == NVME_ZONE_REPORT_EXTENDED) {
        zone_entry_sz += n->zd_extension_size;
    }

    max_zones = (data_size - sizeof(NvmeZoneReportHeader)) / zone_entry_sz;
    buf = g_malloc0(data_size);

    zone = &n->zone_array[zone_idx];
    for (; slba < capacity; slba += n->zone_size) {
        if (partial && nr_zones >= max_zones) {
            break;
        }
        if (zns_zone_matches_filter(zrasf, zone++)) {
            nr_zones++;
        }
    }
    header = (NvmeZoneReportHeader *)buf;
    header->nr_zones = cpu_to_le64(nr_zones);

    buf_p = buf + sizeof(NvmeZoneReportHeader);
    for (; zone_idx < n->num_zones && max_zones > 0; zone_idx++) {
        zone = &n->zone_array[zone_idx];
        if (zns_zone_matches_filter(zrasf, zone)) {
            z = (NvmeZoneDescr *)buf_p;
            buf_p += sizeof(NvmeZoneDescr);

            z->zt = zone->d.zt;
            z->zs = zone->d.zs;
            z->zcap = cpu_to_le64(zone->d.zcap);
            z->zslba = cpu_to_le64(zone->d.zslba);
            z->za = zone->d.za;

            if (zns_wp_is_valid(zone)) {
                z->wp = cpu_to_le64(zone->d.wp);
            } else {
                z->wp = cpu_to_le64(~0ULL);
            }

            if (zra == NVME_ZONE_REPORT_EXTENDED) {
                if (zone->d.za & NVME_ZA_ZD_EXT_VALID) {
                    memcpy(buf_p, zns_get_zd_extension(ns, zone_idx),
                           n->zd_extension_size);
                }
                buf_p += n->zd_extension_size;
            }

            max_zones--;
        }
    }

    status = dma_read_prp(n, (uint8_t *)buf, data_size, prp1, prp2);

    g_free(buf);

    return status;
}

static inline bool nvme_csi_has_nvm_support(NvmeNamespace *ns)
{
    switch (ns->ctrl->csi) {
    case NVME_CSI_NVM:
    case NVME_CSI_ZONED:
        return true;
    }
    return false;
}

static inline uint16_t zns_check_bounds(NvmeNamespace *ns, uint64_t slba,
                                        uint32_t nlb)
{
    uint64_t nsze = le64_to_cpu(ns->id_ns.nsze);

    if (unlikely(UINT64_MAX - slba < nlb || slba + nlb > nsze)) {
        return NVME_LBA_RANGE | NVME_DNR;
    }

    return NVME_SUCCESS;
}

static uint16_t zns_map_dptr(FemuCtrl *n, size_t len, NvmeRequest *req)
{
    uint64_t prp1, prp2;

    switch (req->cmd.psdt) {
    case NVME_PSDT_PRP:
        prp1 = le64_to_cpu(req->cmd.dptr.prp1);
        prp2 = le64_to_cpu(req->cmd.dptr.prp2);

        return nvme_map_prp(&req->qsg, &req->iov, prp1, prp2, len, n);
    default:
        return NVME_INVALID_FIELD;
    }
}

static uint16_t zns_do_write(FemuCtrl *n, NvmeRequest *req, bool append,
                             bool wrz)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)&req->cmd;
    NvmeNamespace *ns = req->ns;
    uint64_t slba = le64_to_cpu(rw->slba);
    uint32_t nlb = (uint32_t)le16_to_cpu(rw->nlb) + 1;
    uint64_t data_size = zns_l2b(ns, nlb);
    uint64_t data_offset;
    NvmeZone *zone;
    NvmeZonedResult *res = (NvmeZonedResult *)&req->cqe;
    uint16_t status;

    #ifdef INHOINNO_VERBOSE_SETTING
    femu_err("zns.c : zns_do_write(), to inhoinno \n");
    #endif


    if (!wrz) {
        status = nvme_check_mdts(n, data_size);
        if (status) {
            goto err;
        }
    }

    status = zns_check_bounds(ns, slba, nlb);
    if (status) {
        goto err;
    }

    zone = zns_get_zone_by_slba(ns, slba);

    status = zns_check_zone_write(n, ns, zone, slba, nlb, append);
    if (status) {
        goto err;
    }

    status = zns_auto_open_zone(ns, zone);
    if (status) {
        goto err;
    }

    if (append) {
        slba = zone->w_ptr;
    }

    res->slba = zns_advance_zone_wp(ns, zone, nlb);

    data_offset = zns_l2b(ns, slba);

    if (!wrz) {
        status = zns_map_dptr(n, data_size, req);
        if (status) {
            goto err;
        }

        backend_rw(n->mbe, &req->qsg, &data_offset, req->is_write);
    }

    zns_finalize_zoned_write(ns, req, false);
    return NVME_SUCCESS;

err:
    printf("****************Append Failed***************\n");
    return status | NVME_DNR;
}

static uint16_t zns_admin_cmd(FemuCtrl *n, NvmeCmd *cmd)
{

    switch (cmd->opcode) {
    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

static inline uint16_t zns_zone_append(FemuCtrl *n, NvmeRequest *req)
{
    return zns_do_write(n, req, true, false);
}

static uint16_t zns_check_dulbe(NvmeNamespace *ns, uint64_t slba, uint32_t nlb)
{
    return NVME_SUCCESS;
}

static uint16_t zns_read(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                         NvmeRequest *req)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)&req->cmd;
    uint64_t slba = le64_to_cpu(rw->slba);
    uint32_t nlb = (uint32_t)le16_to_cpu(rw->nlb) + 1;
    uint64_t data_size = zns_l2b(ns, nlb);
    uint64_t data_offset;
    uint16_t status;

    assert(n->zoned);
    req->is_write = false;

    #ifdef INHOINNO_VERBOSE_SETTING
    femu_err("zns.c : zns_read(), to inhoinno \n");
    #endif

    status = nvme_check_mdts(n, data_size);
    if (status) {
        goto err;
    }

    status = zns_check_bounds(ns, slba, nlb);
    if (status) {
        goto err;
    }

    status = zns_check_zone_read(ns, slba, nlb);
    if (status) {
        goto err;
    }

    status = zns_map_dptr(n, data_size, req);
    if (status) {
        goto err;
    }

    if (NVME_ERR_REC_DULBE(n->features.err_rec)) {
        status = zns_check_dulbe(ns, slba, nlb);
        if (status) {
            goto err;
        }
    }

    data_offset = zns_l2b(ns, slba);

    backend_rw(n->mbe, &req->qsg, &data_offset, req->is_write);
    return NVME_SUCCESS;

err:
    return status | NVME_DNR;
}

static uint16_t zns_write(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                          NvmeRequest *req)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)cmd;
    uint64_t slba = le64_to_cpu(rw->slba);
    uint32_t nlb = (uint32_t)le16_to_cpu(rw->nlb) + 1;
    uint64_t data_size = zns_l2b(ns, nlb);
    uint64_t data_offset;
    NvmeZone *zone=NULL;
    NvmeZonedResult *res = (NvmeZonedResult *)&req->cqe;
    uint16_t status;

    #ifdef INHOINNO_VERBOSE_SETTING
    femu_err("zns.c : zns_write(), to inhoinno \n");
    #endif
    assert(n->zoned);
    req->is_write = true;
    status = nvme_check_mdts(n, data_size);
    if (status) {
        goto err;
    }

    status = zns_check_bounds(ns, slba, nlb);
    if (status) {
        goto err;
    }

    zone = zns_get_zone_by_slba(ns, slba);

    status = zns_check_zone_write(n, ns, zone, slba, nlb, false);
    if (status) {
        goto err;
    }
    status = zns_auto_open_zone(ns, zone);
    if (status) {
        goto err;
    }

    res->slba = zns_advance_zone_wp(ns, zone, nlb);
    data_offset = zns_l2b(ns, slba);
    status = zns_map_dptr(n, data_size, req);   //dptr:data pointer
    if (status) {
        goto err;
    }
    
    //femu_err("*********ZONE WRITE :: zns_map_dptr *********\n");
    //sprintf(msg1, "status : %d \n", status);
    //fprintf(stderr,"%s", msg1);

    backend_rw(n->mbe, &req->qsg, &data_offset, req->is_write); //dram.c:backend_rw()
    zns_finalize_zoned_write(ns, req, false);

    //femu_err("*********ZONE WRITE :: NVME_SUCCESS!! *********\n");
    //sprintf(msg1, "status : %d \n", status);
    //fprintf(stderr,"%s", msg1);
    return NVME_SUCCESS;

err:
    //sprintf(bf, "status : %x\n", status);
    if (zone != NULL)
        femu_err("ZONE STATE : %x", zns_get_zone_state(zone));
    femu_err("*********ZONE WRITE FAILED*********, STATUS : %x\n",status);
    //femu_err(bf);
    
    return status | NVME_DNR;
}

static uint16_t zns_io_cmd(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                           NvmeRequest *req)
{
    #ifdef INHOINNO_VERBOSE_SETTING
    femu_err("zns.c : zns_io_cmd(), to inhoinno \n");
    #endif

    switch (cmd->opcode) {
    case NVME_CMD_READ:
        return zns_read(n, ns, cmd, req);
    case NVME_CMD_WRITE:
        return zns_write(n, ns, cmd, req);
    case NVME_CMD_ZONE_MGMT_SEND:
        return zns_zone_mgmt_send(n, req);
    case NVME_CMD_ZONE_MGMT_RECV:
        return zns_zone_mgmt_recv(n, req);
    case NVME_CMD_ZONE_APPEND:
        return zns_zone_append(n, req);
    }

    return NVME_INVALID_OPCODE | NVME_DNR;
}

static void zns_set_ctrl_str(FemuCtrl *n)
{
    static int fsid_zns = 0;
    const char *zns_mn = "FEMU ZNS-SSD Controller"; //inhoinno: if i make another dev, rename this one
    const char *zns_sn = "vZNSSD";                  //virtual ZNSSSd

    nvme_set_ctrl_name(n, zns_mn, zns_sn, &fsid_zns);
}

static void zns_set_ctrl(FemuCtrl *n)
{
    uint8_t *pci_conf = n->parent_obj.config;

    zns_set_ctrl_str(n);
    pci_config_set_vendor_id(pci_conf, PCI_VENDOR_ID_INTEL);
    pci_config_set_device_id(pci_conf, 0x5845);
}

static int zns_init_zone_cap(FemuCtrl *n)
{
    n->zoned = true;
    n->zasl_bs = NVME_DEFAULT_MAX_AZ_SIZE;
    n->zone_size_bs = NVME_DEFAULT_ZONE_SIZE;
    n->zone_cap_bs = 0;
    n->cross_zone_read = false;
    n->max_active_zones = 0;
    n->max_open_zones = 0;
    n->zd_extension_size = 0;

    return 0;
}

static int zns_start_ctrl(FemuCtrl *n)
{
    /* Coperd: let's fail early before anything crazy happens */
    assert(n->page_size == 4096);
    #ifdef INHOINNO_VERBOSE_SETTING
    femu_err("zns.c : zns_start_ctrl(), to inhoinno \n");
    #endif
    if (!n->zasl_bs) {
        n->zasl = n->mdts;
    } else {
        if (n->zasl_bs < n->page_size) {
            femu_err("ZASL too small (%dB), must >= 1 page (4K)\n", n->zasl_bs);
            return -1;
        }
        /* @inhoinno : what is this for? */
        n->zasl = 31 - clz32(n->zasl_bs / n->page_size);
    }

    return 0;
}

static void zns_init(FemuCtrl *n, Error **errp)
{
    NvmeNamespace *ns = &n->namespaces[0];
    struct zns *zns = n->zns = g_malloc0(sizeof(struct zns));

    #ifdef INHOINNO_VERBOSE_SETTING
        femu_err("zns.c : zns_init(), to inhoinno \n");
    #endif

    zns_set_ctrl(n);
    zns_init_zone_cap(n);
    if (zns_init_zone_geometry(ns, errp) != 0) {
        return;
    }

    zns_init_zone_identify(n, ns, 0);
    
    /* Init zns ssd channel mapping */
    zns->dataplane_started_ptr = &n->dataplane_started;
    zns->ssdname = (char*)n->devname;
    znsssd_init(n);
}

static void znsssd_init_params(FemuCtrl * n, struct zns_ssdparams *spp){
    spp->pg_rd_lat = NAND_READ_LATENCY;
    spp->pg_wr_lat = NAND_PROG_LATENCY;
    spp->blk_er_lat = NAND_ERASE_LATENCY;
    spp->ch_xfer_lat = NAND_PROG_LATENCY/4;
    /**
     * @brief Inhoinno : To show difference between 1-to-1 mapping, and 1-to-N mapping,
     * at least one param among these four should be configured in zns ssd.
     * 1. SSD size  2. zone size 3. # of chnls 4. # of chnls per zone
     */
    spp->nchnls         = 32;           /* FIXME : = ZNS_MAX_CHANNEL channel configuration*/
    spp->zones          = n->num_zones; /* FIXME : = MAX_STORAGE_CAPACITY / ZONE_SIZE*/
    spp->chnls_per_zone = 32;
    spp->ways           = 4;
    
    /* TO REAL STORAGE SIZE */
    spp->csze_pages     = (((int64_t)n->memsz) * 1024 * 1024) / MIN_DISCARD_GRANULARITY / spp->nchnls / spp->ways;
    spp->nchips         = (((int64_t)n->memsz) * 1024 * 1024) / MIN_DISCARD_GRANULARITY / spp->csze_pages;
}

/**
 * @brief 
 * @Inhoinno: we need to make zns ssd latency emulation
 * in order to emulate controller-level mapping in ZNS
 * for example, 1-to-1 mapping or 1-to-All mapping (zone-channel) 
 * @param FemuCtrl for mapping channel for zones
 * @return none 
 */
static void zns_init_ch(struct zns_ssd_channel *ch, struct zns_ssdparams *spp)
{
    //ch->nzones = spp->chnls_per_zone;
    /* ch->lun = g_malloc0(sizeof(struct nand_lun) * ch->nluns);
    for (int i = 0; i < ch->nluns; i++) {
        ssd_init_nand_lun(&ch->lun[i], spp);
    }*/
    ch->next_ch_avail_time = 0;
    ch->busy = 0;
}

void znsssd_init(FemuCtrl * n){
    struct zns *zns = n->zns; 
    struct zns_ssdparams *spp = &zns->sp; 
    //znsssd_assert(ssd);
    zns->namespaces = n->namespaces;
    znsssd_init_params(n, spp);
    
    //for(uint64_t slba = 0; slba < (1<<15) ; slba+=8)
    //    femu_err("In zns.c 1460 : lpa %ld chnl %ld\n", slba>>3 , zns_get_multiway_chnl_idx(n->namespaces, slba));

    #ifdef INHOINNO_VERBOSE_SETTING
    femu_err("zns.c : znsssd_init(), to inhoinno \n");
    #endif

    /* initialize zns ssd internal layout architecture */
    zns->ch     = g_malloc0(sizeof(struct zns_ssd_channel) * spp->nchnls);
    zns->chips  = g_malloc0(sizeof(struct zns_ssd_chip) * spp->nchips);
    zns->zone_array = n->zone_array;
    zns->num_zones = spp->zones;

    for (int i = 0; i < spp->nchnls; i++) {
        zns_init_ch(&zns->ch[i], spp);
    }
    qemu_thread_create(&zns->zns_thread, "FEMU ZNS Thread", zns_thread, n, QEMU_THREAD_JOINABLE);
}

static void zns_exit(FemuCtrl *n)
{
    /*
     * Release any extra resource (zones) allocated for ZNS mode
     */
}

int nvme_register_znssd(FemuCtrl *n)
{
    #ifdef INHOINNO_VERBOSE_SETTING
    femu_err("zns.c : nvme_register_znsssd(), to inhoinno \n");
    #endif
    n->ext_ops = (FemuExtCtrlOps) {
        .state            = NULL,
        .init             = zns_init,
        .exit             = zns_exit,
        .rw_check_req     = NULL,
        .start_ctrl       = zns_start_ctrl,
        .admin_cmd        = zns_admin_cmd,
        .io_cmd           = zns_io_cmd,
        .get_log          = NULL,
    };

    return 0;
}

static uint64_t znsssd_write(ZNS *zns, NvmeRequest *req){
    //FEMU only supports 1 namespace for now (see femu.c:365)
    //and FEMU ZNS Extension use a single thread which mean lockless operations(ch->available_time += ~~) if thread increased
    
    NvmeRwCmd *rw = (NvmeRwCmd *)&req->cmd;
    struct NvmeNamespace *ns = req->ns;
    struct zns_ssdparams * spp = &zns->sp; 
    uint64_t slba = le64_to_cpu(rw->slba);
    uint32_t nlb = (uint32_t)le16_to_cpu(rw->nlb) + 1;
    zns_ssd_chip *chip = NULL;
    uint64_t currlat = 0, maxlat= 0;
    uint32_t my_chip_idx = 0;
    uint64_t nand_stime =0;
    uint64_t cmd_stime = (req->stime == 0) ? qemu_clock_get_ns(QEMU_CLOCK_REALTIME) : req->stime ;
#if ADVANCE_PER_CH_ENDTIME
    zns_ssd_channel *chnl =NULL;
    uint32_t my_chnl_idx = 0;
    uint64_t chnl_stime =0;
#endif
    
#if ZONE_RESET_WHEN_ZONE_STATE_IS_FULL
    //femu_err("In znsssd_write(N : %ld), req->slba %ld , slba >> 3 : %ld my_chnl_idx %d to inhoinno \n",zns->sp.chnls_per_zone ,slba, slba>>3, my_chnl_idx);
    //femu_err("In znsssd_write, start_zone_idx, %ld end_zone_idx, %ld, to inhoinno \n",start_zone_idx, end_zone_idx );
#endif

    for (uint32_t i = 0; i<nlb ; i+=8){
        //Inhoinno : Interleaving per 4KB
        slba += i;
        my_chip_idx=zns_get_multiway_chip_idx(ns, slba);
        chip = &(zns->chips[my_chip_idx]);
#if !(ADVANCE_PER_CH_ENDTIME)
        //Inhoinno:  Single thread emulation so assume we dont need lock per chnl
        nand_stime = (chip->next_avail_time < cmd_stime) ? cmd_stime : \
                     chip->next_avail_time;
        chip->next_avail_time = nand_stime + spp->pg_wr_lat;
        currlat= chip->next_avail_time - cmd_stime ; //Inhoinno : = T_channel + T_chip(=chnl->next_available_time) - stime; // FIXME like this 
        maxlat = (maxlat < currlat)? currlat : maxlat;
#endif
#if ADVANCE_PER_CH_ENDTIME
        my_chnl_idx=zns_get_multiway_chnl_idx(ns, slba);
        chnl = &(zns->ch[my_chnl_idx]);
        chnl_stime = (chnl->next_ch_avail_time < cmd_stime) ? cmd_stime : \
                     chnl->next_ch_avail_time;
        chnl->next_ch_avail_time = chnl_stime + spp->ch_xfer_lat;

        // write: then do NAND program 
        nand_stime = (chip->next_avail_time < chnl->next_ch_avail_time) ? \
            chnl->next_ch_avail_time : chip->next_avail_time;
        chip->next_avail_time = nand_stime + spp->pg_wr_lat;
        currlat = chip->next_avail_time - cmd_stime;
        maxlat = (maxlat < currlat)? currlat : maxlat;
#endif

    }
    return maxlat;

}
static uint64_t znsssd_read(ZNS *zns, NvmeRequest *req){
    // FEMU only supports 1 namespace for now (see femu.c:365) 
    // and FEMU ZNS Extension use a single thread which mean lockless operations(ch->available_time += ~~) if thread increased 

    NvmeRwCmd *rw = (NvmeRwCmd *)&req->cmd;
    uint64_t slba = le64_to_cpu(rw->slba);
    uint32_t nlb = (uint32_t)le16_to_cpu(rw->nlb) + 1;
    struct NvmeNamespace *ns = req->ns;
    struct zns_ssdparams * spp = &zns->sp; 
    zns_ssd_chip *chip = NULL;
    uint64_t currlat = 0, maxlat= 0;
    uint32_t my_chip_idx = 0;
    uint64_t nand_stime =0;
    uint64_t cmd_stime = (req->stime == 0) ? qemu_clock_get_ns(QEMU_CLOCK_REALTIME) : req->stime ;
#if ADVANCE_PER_CH_ENDTIME
    zns_ssd_channel *chnl =NULL;
    uint32_t my_chnl_idx = 0;
    uint64_t chnl_stime =0;
#endif
    
    for (uint64_t i = 0; i<nlb ; i+=8){
        //Inhoinno : Interleaving per 4KB
        slba += i;
        my_chip_idx=zns_get_multiway_chip_idx(ns, slba);
        chip = &(zns->chips[my_chip_idx]);
        //Inhoinno:  Single thread emulation so assume we dont need lock per chnl
        nand_stime = (chip->next_avail_time < cmd_stime) ? cmd_stime : \
                     chip->next_avail_time;
#if !(ADVANCE_PER_CH_ENDTIME)

        chip->next_avail_time = nand_stime + spp->pg_rd_lat;
        currlat= chip->next_avail_time - cmd_stime ; //Inhoinno : = T_channel + T_chip(=chnl->next_available_time) - stime; // FIXME like this 
        maxlat = (maxlat < currlat)? currlat : maxlat;
#endif
#if ADVANCE_PER_CH_ENDTIME
        my_chnl_idx=zns_get_multiway_chnl_idx(ns, slba);
        chnl = &(zns->ch[my_chnl_idx]);
        
        chip->next_avail_time = nand_stime + spp->pg_rd_lat;

        //read: then data transfer through channel
        chnl_stime = (chnl->next_ch_avail_time < chip->next_avail_time) ? \
            chip->next_avail_time : chnl->next_ch_avail_time;
        chnl->next_ch_avail_time = chnl_stime + spp->ch_xfer_lat;

        currlat = chnl->next_ch_avail_time - cmd_stime;
        maxlat = (maxlat < currlat)? currlat : maxlat;
#endif

    }
    return maxlat;
}
/**
 * @brief 
 * @Inhoinno: in order to emulate latency in zns ssd,
 * make a qemu thread and polling request in sq and 
 * emulate latency time, then update req->time related member
*/
static void *zns_thread(void *arg){
    FemuCtrl *n = (FemuCtrl *)arg;
    struct zns *zns = n->zns;
    NvmeRequest *req = NULL;
    uint64_t lat = 0;
    int rc=1;
    int i;

    #ifdef INHOINNO_VERBOSE_SETTING
        femu_err(" *zns_thread, channel allocated to inhoinno \n");
    #endif
    
    while (!*(zns->dataplane_started_ptr)) {
        usleep(100000);
    }
    // FIXME: not safe, to handle ->to_ftl and ->to_poller gracefully 
    zns->to_zone = n->to_ftl;
    zns->to_poller = n->to_poller;
    femu_err("In zns_thread, FemuCtrl, %d to inhoinno \n", n->mdts);

    while (1) {
        for (i = 1; i <= n->num_poller; i++) {
            if (!zns->to_zone[i] || !femu_ring_count(zns->to_zone[i]))
                continue;
            //ISSUE : this is problem?
            rc = femu_ring_dequeue(zns->to_zone[i], (void *)&req, 1);
            if (rc != 1) {
                femu_err("FEMU: ZNS_thread to_zone dequeue failed\n");
            }

            //ftl_assert(req);
            switch (req->cmd.opcode) {
            case NVME_CMD_WRITE:
                //zns_write(n,n->namespaces,&(req->cmd),req);
                lat = znsssd_write(zns, req);
                break;
            //case NVME_CMD_ZONE_APPEND:
                //lat = znsssd_dowrite(zns, req);
                //break;
            case NVME_CMD_READ:
                //zns_read(n,n->namespaces,&(req->cmd),req);
                lat = znsssd_read(zns, req);
                break;
            case NVME_CMD_DSM:
                lat = 0;
                break;
            default:
                //ftl_err("ZNS SSD received unkown request type, ERROR\n");
                ;
            }

            req->reqlat = lat;
            req->expire_time += lat;
            
            rc = femu_ring_enqueue(zns->to_poller[i], (void *)&req, 1);
            if (rc != 1) {
                femu_err("ZNS_thread to_poller enqueue failed\n");
            }
            
            // no gc in zns, only reset zone 
            //TODO: Copy-back op
        }

    }

    return NULL;
}