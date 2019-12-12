#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/cutils.h"
#include "qemu/log.h"
#include "hw/block/block.h"
#include "hw/pci/msix.h"
#include "sysemu/sysemu.h"
#include "sysemu/block-backend.h"
#include "qapi/error.h"

#include "hw/qdev-core.h"

#include "hw/block/nvme.h"
#include "hw/block/ocssd.h"
#include "hw/block/ocssd-ns.h"

uint8_t ocssd_ns_calc_wi(OcssdNamespace *ons, uint32_t pe_cycles)
{
    return (pe_cycles * 255) / ons->params.pe_cycles;
}

static inline int _addr_valid(OcssdNamespace *ons, uint64_t lba)
{
    OcssdIdGeo *geo = &ons->id.geo;
    OcssdAddrF *addrf = &ons->addrf;

    return ocssd_addrf_sectr(addrf, lba) < geo->clba &&
        ocssd_addrf_chunk(addrf, lba) < geo->num_chk &&
        ocssd_addrf_punit(addrf, lba) < geo->num_pu &&
        ocssd_addrf_group(addrf, lba) < geo->num_grp;
}

OcssdChunkDescriptor *ocssd_ns_get_chunk(OcssdNamespace *ons, uint64_t lba)
{
    if (!_addr_valid(ons, lba)) {
        return NULL;
    }

    return &ons->info.descr[ocssd_ns_chk_idx(ons, lba)];
}

OcssdChunkAcctDescriptor *ocssd_ns_get_chunk_acct(OcssdNamespace *ons,
    uint64_t lba)
{
    if (!_addr_valid(ons, lba)) {
        return NULL;
    }

    return &ons->acct.descr[ocssd_ns_chk_idx(ons, lba)];
}

static inline uint64_t _make_lba(OcssdAddrF *addrf, uint16_t group,
    uint16_t punit, uint32_t chunk, uint32_t sectr)
{
    return sectr << addrf->sec_offset
        | chunk << addrf->chk_offset
        | punit << addrf->pu_offset
        | group << addrf->grp_offset;
}

static inline OcssdChunkState _str_to_chunk_state(char *s)
{
    if (!strcmp(s, "FREE")) {
        return OCSSD_CHUNK_FREE;
    }

    if (!strcmp(s, "OFFLINE")) {
        return OCSSD_CHUNK_OFFLINE;
    }

    if (!strcmp(s, "OPEN")) {
        return OCSSD_CHUNK_OPEN;
    }

    if (!strcmp(s, "CLOSED")) {
        return OCSSD_CHUNK_CLOSED;
    }

    return -1;
}

static inline OcssdChunkType _str_to_chunk_type(char *s)
{
    if (!strcmp(s, "SEQ") || !strcmp(s, "SEQUENTIAL")) {
        return OCSSD_CHUNK_TYPE_SEQUENTIAL;
    }

    if (!strcmp(s, "RAN") || !strcmp(s, "RANDOM")) {
        return OCSSD_CHUNK_TYPE_RANDOM;
    }

    return -1;
}

static int _parse_string(const char *s, const char *k, char **v)
{
    char *p = strstr(s, k);
    if (!p) {
        return 0;
    }

    return sscanf(p + strlen(k), "%ms", v);
}

static int _parse_uint8(const char *s, const char *k, uint8_t *v)
{
    char *p = strstr(s, k);
    if (!p) {
        return 0;
    }

    return sscanf(p + strlen(k), "0x%"SCNx8, v) ||
        sscanf(p + strlen(k), "%"SCNu8, v);
}

static int _parse_uint16(const char *s, const char *k, uint16_t *v)
{
    char *p = strstr(s, k);
    if (!p) {
        return 0;
    }

    return sscanf(p + strlen(k), "0x%"SCNx16, v) ||
        sscanf(p + strlen(k), "%"SCNu16, v);
}

static int _parse_uint32(const char *s, const char *k, uint32_t *v)
{
    char *p = strstr(s, k);
    if (!p) {
        return 0;
    }

    return sscanf(p + strlen(k), "0x%"SCNx32, v) ||
        sscanf(p + strlen(k), "%"SCNu32, v);
}

static int _parse_uint64(const char *s, const char *k, uint64_t *v)
{
    char *p = strstr(s, k);
    if (!p) {
        return 0;
    }

    return sscanf(p + strlen(k), "0x%"SCNx64, v) ||
        sscanf(p + strlen(k), "%"SCNu64, v);
}

static bool _parse_wildcard(const char *s, const char *k)
{
    char *v;
    bool found = false;
    if (!_parse_string(s, k, &v)) {
        return false;
    }

    if (strcmp(v, "*") == 0) {
        found = true;
    }

    free(v);

    return found;
}

static int _parse_lba_part_uint16(const char *s, const char *k,
    uint16_t *bgn, uint16_t *end, uint16_t end_defval)
{
    if (!bgn || !end) {
        return 1;
    }

    if (_parse_wildcard(s, k)) {
        *bgn = 0;
        *end = end_defval;

        return 1;
    }

    if (!_parse_uint16(s, k, bgn)) {
        return 0;
    }

    *end = *bgn + 1;

    return 1;
}

static int _parse_lba_part_uint32(const char *s, const char *k,
    uint32_t *bgn, uint32_t *end, uint32_t end_defval)
{
    if (!bgn || !end) {
        return 1;
    }

    if (_parse_wildcard(s, k)) {
        *bgn = 0;
        *end = end_defval;

        return 1;
    }

    if (!_parse_uint32(s, k, bgn)) {
        return 0;
    }

    *end = *bgn + 1;

    return 1;
}

static int _parse_lba_parts(OcssdIdGeo *geo, const char *s,
    uint16_t *grp_bgn, uint16_t *grp_end, uint16_t *pu_bgn,
    uint16_t *pu_end, uint32_t *chk_bgn, uint32_t *chk_end,
    uint32_t *sec_bgn, uint32_t *sec_end, Error **errp)
{
    if (!_parse_lba_part_uint16(s, "group=", grp_bgn, grp_end, geo->num_grp)) {
        error_setg(errp, "could not parse group");
        return 0;
    }

    if (!_parse_lba_part_uint16(s, "punit=", pu_bgn, pu_end, geo->num_pu)) {
        error_setg(errp, "could not parse punit");
        return 0;
    }

    if (!_parse_lba_part_uint32(s, "chunk=", chk_bgn, chk_end, geo->num_chk)) {
        error_setg(errp, "could not parse chunk");
        return 0;
    }

    if (!_parse_lba_part_uint32(s, "sectr=", sec_bgn, sec_end, geo->clba)) {
        error_setg(errp, "could not parse sectr");
        return 0;
    }

    return 1;
}

static int _parse_and_update_reset_error_injection(OcssdNamespace *ons,
    const char *s, Error **errp)
{
    OcssdIdGeo *geo = &ons->id.geo;
    uint16_t group, group_end, punit, punit_end;
    uint32_t chunk, chunk_end;
    uint64_t idx;
    uint8_t prob;
    Error *local_err = NULL;

    size_t slen = strlen(s);
    if (slen == 1 || (slen > 1 && s[0] == '#')) {
        return 0;
    }


    if (!_parse_lba_parts(geo, s, &group, &group_end, &punit, &punit_end,
        &chunk, &chunk_end, NULL, NULL, &local_err)) {
        error_propagate_prepend(errp, local_err, "could not parse chunk slba");
        return 1;
    }

    if (!_parse_uint8(s, "prob=", &prob)) {
        error_setg(errp, "could not parse probability");
        return 1;
    }

    if (prob > 100) {
        error_setg(errp, "invalid probability");
        return 1;
    }

    for (uint16_t g = group; g < group_end; g++) {
        for (uint16_t p = punit; p < punit_end; p++) {
            for (uint32_t c = chunk; c < chunk_end; c++) {
                idx = ocssd_ns_chk_idx(ons,
                    _make_lba(&ons->addrf, g, p, c, 0));
                ons->resetfail[idx] = prob;
            }
        }
    }

    return 0;
}

static int _parse_and_update_write_error_injection(OcssdNamespace *ons,
    const char *s, Error **errp)
{
    OcssdIdGeo *geo = &ons->id.geo;
    uint16_t group, group_end, punit, punit_end;
    uint32_t chunk, chunk_end, sectr, sectr_end;
    uint64_t sectr_idx;
    uint8_t prob;
    Error *local_err = NULL;

    size_t slen = strlen(s);
    if (slen == 1 || (slen > 1 && s[0] == '#')) {
        return 0;
    }

    if (!_parse_lba_parts(geo, s, &group, &group_end, &punit, &punit_end,
        &chunk, &chunk_end, &sectr, &sectr_end, &local_err)) {
        error_propagate_prepend(errp, local_err, "could not parse lba");
        return 1;
    }

    if (!_parse_uint8(s, "prob=", &prob)) {
        error_setg(errp, "could not parse probability");
        return 1;
    }

    if (prob > 100) {
        error_setg(errp, "invalid probability");
        return 1;
    }

    for (uint16_t g = group; g < group_end; g++) {
        for (uint16_t p = punit; p < punit_end; p++) {
            for (uint32_t c = chunk; c < chunk_end; c++) {
                for (uint32_t s = sectr; s < sectr_end; s++) {
                    sectr_idx = ocssd_ns_sectr_idx(ons, _make_lba(
                        &ons->addrf, g, p, c, s));
                    ons->writefail[sectr_idx] = prob;
                }
            }
        }
    }

    return 0;
}

static int _parse_and_update_chunk_info(OcssdNamespace *ons, const char *s,
    Error **errp)
{
    char *v;
    OcssdChunkDescriptor *chk;
    OcssdChunkAcctDescriptor *chk_acct;
    OcssdIdGeo *geo = &ons->id.geo;
    uint16_t group, group_end, punit, punit_end;
    uint32_t chunk, chunk_end, pe_cycles;
    uint64_t cnlb, wp, slba;
    int state = 0, type = 0;
    bool cnlb_parsed = false, wp_parsed = false, pe_cycles_parsed = false;
    bool state_parsed = false, type_parsed = false;
    Error *local_err = NULL;

    size_t slen = strlen(s);
    if (slen == 1 || (slen > 1 && s[0] == '#')) {
        return 0;
    }

    if (!_parse_lba_parts(geo, s, &group, &group_end, &punit, &punit_end,
        &chunk, &chunk_end, NULL, NULL, &local_err)) {
        error_propagate_prepend(errp, local_err, "could not parse chunk slba");
        return 1;
    }

    if (_parse_string(s, "state=", &v)) {
        state_parsed = true;
        state = _str_to_chunk_state(v);
        free(v);

        if (state < 0) {
            error_setg(errp, "invalid chunk state");
            return 1;
        }
    }

    if (_parse_string(s, "type=", &v)) {
        type_parsed = true;
        type = _str_to_chunk_type(v);
        free(v);

        if (type < 0) {
            error_setg(errp, "invalid chunk type");
            return 1;
        }
    }

    if (_parse_uint64(s, "cnlb=", &cnlb)) {
        cnlb_parsed = true;
    }

    if (_parse_uint64(s, "wp=", &wp)) {
        wp_parsed = true;
    }

    if (_parse_uint32(s, "pe_cycles=", &pe_cycles)) {
        pe_cycles = true;
    }

    if (state_parsed) {
        if (state == OCSSD_CHUNK_OFFLINE && wp_parsed) {
            error_setg(errp, "invalid wp; state is offline");
            return 1;
        }
    }

    if (type_parsed) {
        if (type == OCSSD_CHUNK_TYPE_RANDOM && wp_parsed) {
            error_setg(errp, "invalid wp; type has random write capability");
            return 1;
        }
    }

    for (uint16_t g = group; g < group_end; g++) {
        for (uint16_t p = punit; p < punit_end; p++) {
            for (uint32_t c = chunk; c < chunk_end; c++) {
                slba = _make_lba(&ons->addrf, g, p, c, 0);
                chk = ocssd_ns_get_chunk(ons, slba);
                chk_acct = ocssd_ns_get_chunk_acct(ons, slba);
                if (!chk) {
                    error_setg(errp, "invalid lba");
                    return 1;
                }

                if (state_parsed) {
                    /*
                     * Reset the wear index and pe_cycles to zero if the
                     * persisted state is OFFLINE and we move to another state.
                     * If the number of pe_cycles is also changed, it will be
                     * updated subsequently.
                     */
                    if (chk->state == OCSSD_CHUNK_OFFLINE &&
                        state != OCSSD_CHUNK_OFFLINE) {
                        chk->wear_index = 0;
                        chk_acct->pe_cycles = 0;
                    }

                    if (state == OCSSD_CHUNK_OFFLINE) {
                        chk->wp = UINT64_MAX;
                    }

                    if (state == OCSSD_CHUNK_FREE) {
                        chk->wp = 0;
                    }

                    chk->state = state;
                }

                if (type_parsed) {
                    chk->type = type;
                    if (chk->type == OCSSD_CHUNK_TYPE_RANDOM) {
                        chk->wp = UINT64_MAX;
                    }
                }

                if (cnlb_parsed) {
                    chk->cnlb = cnlb;
                    if (chk->cnlb > ons->id.geo.clba) {
                        error_setg(errp, "invalid chunk cnlb");
                        return 1;
                    }

                    if (chk->cnlb != ons->id.geo.clba) {
                        chk->type |= OCSSD_CHUNK_TYPE_SHRINKED;
                    }
                }

                if (wp_parsed) {
                    chk->wp = wp;
                    if (chk->wp > chk->cnlb) {
                        error_setg(errp, "invalid chunk wp");
                        return 1;
                    }
                }

                if (pe_cycles_parsed) {
                    if (pe_cycles > ons->params.pe_cycles) {
                        error_setg(errp, "invalid number of pe_cycles");
                        return 1;
                    }

                    chk->wear_index = ocssd_ns_calc_wi(ons, pe_cycles);
                    chk_acct->pe_cycles = pe_cycles;
                }
            }
        }
    }

    return 0;
}

static uint64_t ocssd_ns_calc_blks(OcssdNamespace *ons)
{
    NvmeNamespace *ns = NVME_NS(ons);
    return ons->hdr.ns_size / (nvme_ns_lbads_bytes(ns) + nvme_ns_ms(ns));
}

static uint64_t ocssd_ns_calc_info_size(OcssdNamespace *ons)
{
    OcssdIdGeo *geo = &ons->id.geo;
    uint64_t chks_total = geo->num_grp * geo->num_pu * geo->num_chk;

    return QEMU_ALIGN_UP(chks_total * sizeof(OcssdChunkDescriptor),
        ons->hdr.sector_size);
}

static uint64_t ocssd_ns_calc_acct_size(OcssdNamespace *ons)
{
    OcssdIdGeo *geo = &ons->id.geo;
    uint64_t chks_total = geo->num_grp * geo->num_pu * geo->num_chk;

    return QEMU_ALIGN_UP(chks_total * sizeof(OcssdChunkAcctDescriptor),
        ons->hdr.sector_size);
}

static int ocssd_ns_load_chunk_acct(OcssdNamespace *ons)
{
    NvmeNamespace *ns = NVME_NS(ons);
    BlockBackend *blk = ns->conf.blk;
    return blk_pread(blk, ons->acct.blk_offset, ons->acct.descr,
        ons->acct.size);
}

static int ocssd_ns_load_chunk_info(OcssdNamespace *ons)
{
    NvmeNamespace *ns = NVME_NS(ons);
    BlockBackend *blk = ns->conf.blk;
    return blk_pread(blk, ons->info.blk_offset, ons->info.descr,
        ons->info.size);
}

static int ocssd_ns_load_chunk_info_from_file(OcssdNamespace *ons,
    const char *fname, Error **errp)
{
    ssize_t n;
    size_t len = 0;
    int line_num = 0;
    char *line = NULL;
    Error *local_err = NULL;
    FILE *fp;
    int failed = 0;

    fp = fopen(fname, "r");
    if (!fp) {
        error_setg_errno(errp, errno, "could not open chunk info file");
        return 1;
    }

    while ((n = getline(&line, &len, fp)) != -1) {
        line_num++;
        if (_parse_and_update_chunk_info(ons, line, &local_err)) {
            error_propagate_prepend(errp, local_err,
                "could not parse chunk info (line %d): ", line_num);
            failed = 1;
            break;
        }
    }

    free(line);
    fclose(fp);

    return failed;
}

static int ocssd_ns_load_write_error_injection_from_file(OcssdNamespace *ons,
    const char *fname, Error **errp)
{
    ssize_t n;
    size_t len = 0;
    int line_num = 0;
    char *line = NULL;
    Error *local_err = NULL;
    FILE *fp;
    int failed = 0;

    fp = fopen(fname, "r");
    if (!fp) {
        error_setg_errno(errp, errno,
            "could not open write error injection file (%s): ", fname);
        return 1;
    }

    while ((n = getline(&line, &len, fp)) != -1) {
        line_num++;
        if (_parse_and_update_write_error_injection(ons, line, &local_err)) {
            error_propagate_prepend(errp, local_err,
                "could not parse write error injection (line %d): ", line_num);
            failed = 1;
            break;
        }
    }

    free(line);
    fclose(fp);

    return failed;
}

static int ocssd_ns_load_reset_error_injection_from_file(OcssdNamespace *ons,
    const char *fname, Error **errp)
{
    ssize_t n;
    size_t len = 0;
    int line_num = 0;
    char *line = NULL;
    Error *local_err = NULL;
    FILE *fp;
    int failed = 0;

    fp = fopen(fname, "r");
    if (!fp) {
        error_setg_errno(errp, errno,
            "could not open reset error injection file (%s): ", fname);
        return 1;
    }

    while ((n = getline(&line, &len, fp)) != -1) {
        line_num++;
        if (_parse_and_update_reset_error_injection(ons, line, &local_err)) {
            error_propagate_prepend(errp, local_err,
                "could not parse reset error injection (line %d): ", line_num);
            failed = 1;
            break;
        }
    }

    free(line);
    fclose(fp);

    return failed;
}

static int ocssd_ns_init(OcssdNamespace *ons, Error **errp)
{
    NvmeNamespace *ns = NVME_NS(ons);
    NvmeIdNs *id_ns = &ns->id_ns;
    OcssdNamespaceParams *params = &ons->params;
    BlockBackend *blk = ns->conf.blk;
    OcssdIdentity *id = &ons->id;
    OcssdIdGeo *geo = &id->geo;
    OcssdAddrF *addrf = &ons->addrf;

    uint64_t ns_blks;
    int ret;

    nvme_ns_init_identify(ns);

    /*
     * In addition to checking if the device has the NVME_QUIRK_LIGHTNVM quirk,
     * the Linux NVMe driver also checks if the first byte of the
     * vendor specific area in the identify namespace structure is set to 0x1.
     *
     * This is non-standard and Linux specific.
     */
    id_ns->vs[0] = 0x1;

    ret = blk_pread(blk, ns->blk_offset, id, sizeof(OcssdIdentity));
    if (ret < 0) {
        error_setg_errno(errp, -ret,
            "could not read namespace identity structure: ");
        return 1;
    }
    ns->blk_offset += sizeof(OcssdIdentity);

    if (params->geometry.num_grp != id->geo.num_grp) {
        error_setg(errp, "geometry changed; invalid number of groups");
        return 1;
    }

    if (params->geometry.num_pu != id->geo.num_pu) {
        error_setg(errp, "geometry changed; invalid number of parallel units");
        return 1;
    }

    if (params->geometry.num_chk != id->geo.num_chk) {
        error_setg(errp, "geometry changed; invalid number of chunks");
        return 1;
    }

    if (params->geometry.clba != id->geo.clba) {
        error_setg(errp, "geometry has changed; invalid number of sectors");
        return 1;
    }

    if (params->wdr.ws_min != UINT32_MAX) {
        id->wrt.ws_min = cpu_to_le32(params->wdr.ws_min);
    } else {
        params->wdr.ws_min = le32_to_cpu(id->wrt.ws_min);
    }

    if (params->wdr.ws_opt != UINT32_MAX) {
        id->wrt.ws_opt = cpu_to_le32(params->wdr.ws_opt);
    } else {
        params->wdr.ws_opt = le32_to_cpu(id->wrt.ws_opt);
    }

    if (params->wdr.mw_cunits != UINT32_MAX) {
        id->wrt.mw_cunits = cpu_to_le32(params->wdr.mw_cunits);
    } else {
        params->wdr.mw_cunits = le32_to_cpu(id->wrt.mw_cunits);
    }

    if (params->mccap != UINT32_MAX) {
        id->mccap = cpu_to_le32(params->mccap);
    } else {
        params->mccap = le32_to_cpu(id->mccap);
    }

    if (params->wit != UINT8_MAX) {
        id->wit = params->wit;
    } else {
        params->wit = id->wit;
    }

    id_ns->lbaf[0].ds = 63 - clz64(ons->hdr.sector_size);
    id_ns->lbaf[0].ms = ons->hdr.md_size;
    id_ns->nlbaf = 0;
    id_ns->flbas = 0;
    id_ns->mc = ons->hdr.md_size ? 0x2 : 0;

    ons->acct.size = ocssd_ns_calc_acct_size(ons);
    ons->acct.descr = g_malloc0(ons->acct.size);
    ons->acct.blk_offset = ns->blk_offset;
    ns->blk_offset += ons->acct.size;

    ons->info.size = ocssd_ns_calc_info_size(ons);
    ons->info.descr = g_malloc0(ons->info.size);
    ons->info.blk_offset = ns->blk_offset;
    ns->blk_offset += ons->info.size;

    ns_blks = ocssd_ns_calc_blks(ons);
    ns_blks -= (sizeof(OcssdIdentity) + ons->info.size) /
        nvme_ns_lbads_bytes(ns);

    ns->blk_offset_md = ns->blk_offset + nvme_ns_lbads_bytes(ns) * ns_blks;

    ons->chks_per_grp = geo->num_chk * geo->num_pu;
    ons->chks_total   = ons->chks_per_grp * geo->num_grp;
    ons->secs_per_chk = geo->clba;
    ons->secs_per_pu  = ons->secs_per_chk * geo->num_chk;
    ons->secs_per_grp = ons->secs_per_pu  * geo->num_pu;
    ons->secs_total   = ons->secs_per_grp * geo->clba;

    ocssd_ns_optimal_addrf(addrf, &id->lbaf);

    /*
     * Size of device (NSZE) is the entire address space (though some space is
     * not usable).
     */
    id_ns->nuse = id_ns->nsze =
        1ULL << (id->lbaf.sec_len + id->lbaf.chk_len +
            id->lbaf.pu_len + id->lbaf.grp_len);

    /*
     * Namespace capacity (NCAP) is set to the actual usable size in logical
     * blocks.
     */
    id_ns->ncap = ns_blks;

    ret = ocssd_ns_load_chunk_info(ons);
    if (ret < 0) {
        error_setg_errno(errp, -ret, "could not load chunk info");
        return 1;
    }

    ret = ocssd_ns_load_chunk_acct(ons);
    if (ret < 0) {
        error_setg_errno(errp, -ret, "could not load chunk acct");
        return 1;
    }

    return 0;
}

static int ocssd_ns_init_blk(OcssdNamespace *ons, Error **errp)
{
    NvmeNamespace *ns = NVME_NS(ons);
    OcssdNamespaceParams *params = &ons->params;
    OcssdFormatHeader hdr;
    OcssdIdLBAF lbaf;
    OcssdAddrF addrf;
    OcssdIdentity id;
    OcssdChunkDescriptor *chk;
    OcssdChunkAcctDescriptor *acct;

    BlockBackend *blk = ns->conf.blk;
    uint64_t perm, shared_perm;

    uint16_t num_grp, num_pu;
    uint32_t num_chk, clba;
    uint64_t sec_size, usable_size, ns_size, info_size, acct_size;
    uint64_t chks_total, secs_total, offset, nblks, fake_size;

    Error *local_err = NULL;
    int ret;

    num_grp = params->geometry.num_grp;
    num_pu = params->geometry.num_pu;
    num_chk = params->geometry.num_chk;
    clba = params->geometry.clba;

    if (params->wdr.ws_min == UINT32_MAX) {
        params->wdr.ws_min = OCSSD_WDR_WS_MIN_DEFAULT;
    }

    if (params->wdr.ws_opt == UINT32_MAX) {
        params->wdr.ws_opt = OCSSD_WDR_WS_OPT_DEFAULT;
    }

    if (params->wdr.mw_cunits == UINT32_MAX) {
        params->wdr.mw_cunits = OCSSD_WDR_MW_CUNITS_DEFAULT;
    }

    if (params->mccap == UINT32_MAX) {
        params->mccap = OCSSD_MCCAP_DEFAULT;
    }

    if (params->wit == UINT8_MAX) {
        params->wit = OCSSD_WIT_DEFAULT;
    }

    blk_get_perm(blk, &perm, &shared_perm);

    ret = blk_set_perm(blk, perm | BLK_PERM_RESIZE, shared_perm, &local_err);
    if (ret) {
        error_propagate_prepend(errp, local_err, "blk_set_perm: ");
        return ret;
    }

    sec_size = 1 << params->lbads;
    chks_total = num_grp * num_pu * num_chk;
    info_size = QEMU_ALIGN_UP(chks_total * sizeof(OcssdChunkDescriptor),
        sec_size);
    acct_size = QEMU_ALIGN_UP(chks_total * sizeof(OcssdChunkAcctDescriptor),
        sec_size);

    secs_total = chks_total * clba;

    /*
     * The ocssd format begins with a 4k header followed by a single namespace
     * section.
     *
     * A namespace section consists of a 4k OcssdIdentify block, an accounting
     * region and a chunk info region. The accounting and chunk info regions
     * are of variable size (in multiples of the sector size). Then comes a
     * data section that contains a region dedicated to data and a region for
     * metadata afterwards.
     *
     *     [Format header          ] 4096 bytes
     *     [OCSSD identity/geometry] 4096 bytes
     *     [Accounting             ] sector_size * n
     *     [Chunk info             ] sector_size * m
     *     [Namespace data         ] sector_size * k
     *     [Namespace meta data    ] md_size * k
     *
     * , where 'n' is the number of sectors required to hold accounting
     * information on all chunks, 'm' is the number of sectors required to hold
     * chunk information and 'k' is the number of available LBAs.
     *
     */

    usable_size = secs_total * (sec_size + ns->params.ms);
    ns_size = usable_size + sizeof(OcssdIdentity) + acct_size + info_size;

    blk_set_allow_write_beyond_eof(blk, true);

    ret = blk_truncate(blk, 0, PREALLOC_MODE_OFF, &local_err);
    if (ret < 0) {
        error_propagate_prepend(errp, local_err, "blk_truncate: ");
        return ret;
    }

    /*
     * Calculate an "optimal" LBA address format that uses as few bits as
     * possible.
     */
    lbaf = (OcssdIdLBAF) {
        .sec_len = 32 - clz32(clba - 1),
        .chk_len = 32 - clz32(num_chk - 1),
        .pu_len  = 32 - clz32(num_pu - 1),
        .grp_len = 32 - clz32(num_grp - 1),
    };

    ocssd_ns_optimal_addrf(&addrf, &lbaf);

    hdr = (OcssdFormatHeader) {
        .magic       = cpu_to_le32(OCSSD_MAGIC),
        .version     = cpu_to_le32(0x1),
        .md_size     = cpu_to_le32(ns->params.ms),
        .sector_size = cpu_to_le64(sec_size),
        .ns_size     = cpu_to_le64(ns_size),
        .pe_cycles   = cpu_to_le32(params->pe_cycles),
        .lbaf        = lbaf,
    };

    ret = blk_pwrite(blk, 0, &hdr, sizeof(OcssdFormatHeader), 0);
    if (ret < 0) {
        error_setg_errno(errp, -ret, "blk_pwrite: ");
        return ret;
    }

    offset = sizeof(OcssdFormatHeader);
    id = (OcssdIdentity) {
        .ver.major = 2,
        .ver.minor = 0,
        .lbaf = lbaf,
        .mccap = cpu_to_le32(params->mccap),
        .wit = params->wit,
        .geo = (OcssdIdGeo) {
            .num_grp = cpu_to_le16(num_grp),
            .num_pu  = cpu_to_le16(num_pu),
            .num_chk = cpu_to_le32(num_chk),
            .clba    = cpu_to_le32(clba),
        },
        .wrt = (OcssdIdWrt) {
            .ws_min    = cpu_to_le32(params->wdr.ws_min),
            .ws_opt    = cpu_to_le32(params->wdr.ws_opt),
            .mw_cunits = cpu_to_le32(params->wdr.mw_cunits),
        },
        .perf = (OcssdIdPerf) {
            .trdt = cpu_to_le32(70000),
            .trdm = cpu_to_le32(100000),
            .tprt = cpu_to_le32(1900000),
            .tprm = cpu_to_le32(3500000),
            .tbet = cpu_to_le32(3000000),
            .tbem = cpu_to_le32(3000000),
        },
    };

    ret = blk_pwrite(blk, offset, &id, sizeof(OcssdIdentity), 0);
    if (ret < 0) {
        error_setg_errno(errp, -ret, "blk_pwrite: ");
        return ret;
    }

    offset += sizeof(OcssdIdentity);

    acct = g_malloc0(acct_size);
    ret = blk_pwrite(blk, offset, acct, acct_size, 0);
    g_free(acct);
    if (ret < 0) {
        error_setg_errno(errp, -ret, "blk_pwrite: ");
        return ret;
    }

    offset += acct_size;

    chk = g_malloc0(info_size);
    for (int i = 0; i < chks_total; i++) {
        chk[i].state = OCSSD_CHUNK_FREE;
        chk[i].type = OCSSD_CHUNK_TYPE_SEQUENTIAL;
        chk[i].wear_index = 0;
        chk[i].slba = (i / (num_chk * num_pu)) << addrf.grp_offset
            | (i % (num_chk * num_pu) / num_chk) << addrf.pu_offset
            | (i % num_chk) << addrf.chk_offset;
        chk[i].cnlb = cpu_to_le32(clba);
        chk[i].wp = 0;
    }

    ret = blk_pwrite(blk, offset, chk, info_size, 0);
    g_free(chk);
    if (ret < 0) {
        error_setg_errno(errp, -ret, "blk_pwrite: ");
        return ret;
    }

    offset += info_size + usable_size;

    /*
     * Calculate the size according to the address space.
     *
     * The hierarchical addressing in OCSSD can lead to read requests at
     * logical block addresses that are invalid under the geometry so truncate
     * the image to account for this.
     */
    nblks = 1 << (lbaf.grp_len + lbaf.pu_len + lbaf.chk_len +
        lbaf.sec_len);
    fake_size = sizeof(OcssdFormatHeader) + sizeof(OcssdIdentity) + info_size +
        acct_size + nblks * (sec_size + ns->params.ms);

    ret = blk_truncate(blk, fake_size, PREALLOC_MODE_OFF, &local_err);
    if (ret < 0) {
        error_propagate_prepend(errp, local_err, "blk_truncate: ");
        return ret;
    }

    blk_set_allow_write_beyond_eof(blk, false);

    ret = blk_set_perm(blk, perm, shared_perm, &local_err);
    if (ret) {
        error_propagate_prepend(errp, local_err, "blk_set_perm: ");
        return ret;
    }

    return 0;
}

static void ocssd_ns_realize(DeviceState *dev, Error **errp)
{
    BusState *s = qdev_get_parent_bus(dev);
    OcssdNamespace *ons = OCSSD_NS(dev);

    NvmeCtrl *n = NVME(s->parent);
    NvmeNamespace *ns = NVME_NS(dev);

    Error *local_err = NULL;
    int ret;

    if (nvme_ns_check_constraints(ns, &local_err)) {
        error_propagate_prepend(errp, local_err,
            "nvme_ns_check_constraints: ");
        return;
    }

    if (nvme_ns_init_blk(ns, &n->id_ctrl, &local_err)) {
        error_propagate_prepend(errp, local_err, "nvme_ns_init_blk: ");
        return;
    }

    if (!blk_getlength(ns->conf.blk)) {
        ret = ocssd_ns_init_blk(ons, &local_err);
        if (ret < 0) {
            error_propagate_prepend(errp, local_err, "ocssd_ns_init_blk: ");
            return;
        }
    }

    ret = blk_pread(ns->conf.blk, 0, &ons->hdr, sizeof(OcssdFormatHeader));
    if (ret < 0) {
        error_setg(errp, "could not read block format header");
        return;
    }

    if (ns->params.ms != ons->hdr.md_size) {
        error_setg(errp, "geometry changed; invalid metadata bytes");
        return;
    }

    if (1 << ons->params.lbads != ons->hdr.sector_size) {
        error_setg(errp, "geometry changed; invalid sector size");
        return;
    }

    if (ons->params.pe_cycles != ons->hdr.pe_cycles) {
        error_setg(errp, "geometry changed; invalid number of p/e cycles");
        return;
    }

    ns->blk_offset = ons->hdr.sector_size;
    ns->params.ms = ons->hdr.md_size;

    ocssd_ns_init(ons, &local_err);

    if (ons->params.chunkinfo_fname) {
        if (ocssd_ns_load_chunk_info_from_file(ons,
            ons->params.chunkinfo_fname, &local_err)) {
            error_propagate_prepend(errp, local_err,
                "could not load chunk info from file");
            return;
        }

        ret = blk_pwrite(ns->conf.blk, ons->info.blk_offset, ons->info.descr,
            ons->info.size, 0);
        if (ret < 0) {
            error_setg_errno(errp, -ret, "could not commit chunk info");
            return;
        }

        ret = blk_pwrite(ns->conf.blk, ons->acct.blk_offset, ons->acct.descr,
            ons->acct.size, 0);
        if (ret < 0) {
            error_setg_errno(errp, -ret, "could not commit chunk acct");
            return;
        }
    }

    for (int i = 0; i < ons->chks_total; i++) {
        OcssdChunkDescriptor *cnk = &ons->info.descr[i];
        ons->wear_index_total += cnk->wear_index;
    }

    ons->wear_index_avg = ons->wear_index_total / ons->chks_total;

    ons->resetfail = NULL;
    if (ons->params.resetfail_fname) {
        ons->resetfail = g_malloc0_n(ons->chks_total, sizeof(*ons->resetfail));
        if (!ons->resetfail) {
            error_setg_errno(errp, ENOMEM, "could not allocate memory");
            return;
        }

        if (ocssd_ns_load_reset_error_injection_from_file(ons,
            ons->params.resetfail_fname, &local_err)) {
            error_propagate_prepend(errp, local_err,
                "could not load reset error injection from file");
            return;
        }
    }

    ons->writefail = NULL;
    if (ons->params.writefail_fname) {
        ons->writefail = g_malloc0_n(ons->secs_total, sizeof(*ons->writefail));
        if (!ons->writefail) {
            error_setg_errno(errp, ENOMEM, "could not allocate memory");
            return;
        }

        if (ocssd_ns_load_write_error_injection_from_file(ons,
            ons->params.writefail_fname, &local_err)) {
            error_propagate_prepend(errp, local_err,
                "could not load write error injection from file");
            return;
        }

        /*
         * We fail resets for a chunk after a write failure to it, so make sure
         * to allocate the resetfailure buffer if it has not been already.
         */
        if (!ons->resetfail) {
            ons->resetfail = g_malloc0_n(ons->chks_total,
                sizeof(*ons->resetfail));
        }
    }

    if (nvme_register_namespace(n, ns, &local_err)) {
        error_propagate_prepend(errp, local_err, "nvme_register_namespace: ");
        return;
    }
}

static Property ocssd_ns_props[] = {
    DEFINE_OCSSD_NS_PROPERTIES(OcssdNamespace, params),
    DEFINE_PROP_END_OF_LIST(),
};

static void ocssd_ns_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);

    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);

    dc->bus_type = TYPE_NVME_BUS;
    dc->realize = ocssd_ns_realize;
    dc->props = ocssd_ns_props;
    dc->desc = "virtual ocssd namespace";
}

static const TypeInfo ocssd_ns_info = {
    .name = TYPE_OCSSD_NS,
    .parent = TYPE_NVME_NS,
    .class_init = ocssd_ns_class_init,
    .instance_size = sizeof(OcssdNamespace),
};

static void ocssd_ns_register_types(void)
{
    type_register_static(&ocssd_ns_info);
}

type_init(ocssd_ns_register_types)
