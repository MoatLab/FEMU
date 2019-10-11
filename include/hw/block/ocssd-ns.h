#ifndef OCSSD_NS_H
#define OCSSD_NS_H

#include "block/ocssd.h"

#define DEFINE_OCSSD_NS_PROPERTIES(_state, _props) \
    DEFINE_PROP_UINT16("num_grp", _state, _props.geometry.num_grp, 2), \
    DEFINE_PROP_UINT16("num_pu", _state, _props.geometry.num_pu, 4), \
    DEFINE_PROP_UINT32("num_chk", _state, _props.geometry.num_chk, 60), \
    DEFINE_PROP_UINT32("clba", _state, _props.geometry.clba, 4096), \
    DEFINE_PROP_UINT8("lbads", _state, _props.lbads, 12), \
    DEFINE_PROP_UINT32("pe_cycles", _state, _props.pe_cycles, 1000), \
    DEFINE_PROP_UINT32("mccap", _state, _props.mccap, UINT32_MAX), \
    DEFINE_PROP_UINT32("ws_min", _state, _props.wdr.ws_min, UINT32_MAX), \
    DEFINE_PROP_UINT32("ws_opt", _state, _props.wdr.ws_opt, UINT32_MAX), \
    DEFINE_PROP_UINT32("mw_cunits", _state, _props.wdr.mw_cunits, UINT32_MAX), \
    DEFINE_PROP_UINT8("wit", _state, _props.wit, UINT8_MAX), \
    DEFINE_PROP_STRING("resetfail", _state, _props.resetfail_fname), \
    DEFINE_PROP_STRING("writefail", _state, _props.writefail_fname), \
    DEFINE_PROP_STRING("chunkinfo", _state, _props.chunkinfo_fname)

#define OCSSD_MCCAP_DEFAULT 0x5
#define OCSSD_WIT_DEFAULT 10
#define OCSSD_WDR_WS_MIN_DEFAULT 4
#define OCSSD_WDR_WS_OPT_DEFAULT 8
#define OCSSD_WDR_MW_CUNITS_DEFAULT 24

typedef struct OcssdNamespaceParams {
    uint32_t mccap;
    uint8_t  wit;

    struct {
        uint16_t num_grp;
        uint16_t num_pu;
        uint32_t num_chk;
        uint32_t clba;
    } geometry;

    struct {
        uint32_t ws_min;
        uint32_t ws_opt;
        uint32_t mw_cunits;
    } wdr;

    uint32_t pe_cycles;
    uint8_t  lbads;

    char *chunkinfo_fname;
    char *resetfail_fname;
    char *writefail_fname;
} OcssdNamespaceParams;

typedef struct OcssdAddrF {
    uint64_t grp_mask;
    uint64_t pu_mask;
    uint64_t chk_mask;
    uint64_t sec_mask;
    uint8_t  grp_offset;
    uint8_t  pu_offset;
    uint8_t  chk_offset;
    uint8_t  sec_offset;
} OcssdAddrF;

static inline uint64_t ocssd_addrf_sectr(OcssdAddrF *addrf, uint64_t lba)
{
    return (lba & addrf->sec_mask) >> addrf->sec_offset;
}

static inline uint64_t ocssd_addrf_chunk(OcssdAddrF *addrf, uint64_t lba)
{
    return (lba & addrf->chk_mask) >> addrf->chk_offset;
}

static inline uint64_t ocssd_addrf_punit(OcssdAddrF *addrf, uint64_t lba)
{
    return (lba & addrf->pu_mask) >> addrf->pu_offset;
}

static inline uint64_t ocssd_addrf_group(OcssdAddrF *addrf, uint64_t lba)
{
    return (lba & addrf->grp_mask) >> addrf->grp_offset;
}

typedef struct OcssdChunkAcctDescriptor {
    uint32_t pe_cycles;
} OcssdChunkAcctDescriptor;

typedef struct OcssdChunkAcct {
    uint64_t blk_offset;
    uint64_t size;

    OcssdChunkAcctDescriptor *descr;
} OcssdChunkAcct;

typedef struct OcssdChunkInfo {
    uint64_t blk_offset;
    uint64_t size;

    OcssdChunkDescriptor *descr;
} OcssdChunkInfo;

#define TYPE_OCSSD_NS "ocssd-ns"
#define OCSSD_NS(obj) \
    OBJECT_CHECK(OcssdNamespace, (obj), TYPE_OCSSD_NS)

typedef struct OcssdNamespace {
    NvmeNamespace parent_obj;

    OcssdFormatHeader hdr;
    OcssdIdentity     id;
    OcssdAddrF        addrf;

    /* reset and write fail error probabilities indexed by namespace */
    uint8_t *resetfail;
    uint8_t *writefail;

    /* derived values (convenience) */
    uint32_t chks_per_grp;
    uint32_t chks_total;
    uint32_t secs_per_chk;
    uint32_t secs_per_pu;
    uint32_t secs_per_grp;
    uint32_t secs_total;

    /* wear index tracking */
    uint8_t  wear_index_avg;
    uint64_t wear_index_total;

    OcssdChunkInfo info;
    OcssdChunkAcct acct;

    OcssdNamespaceParams params;
} OcssdNamespace;

OcssdChunkDescriptor *ocssd_ns_get_chunk(OcssdNamespace *ons,
    uint64_t lba);
OcssdChunkAcctDescriptor *ocssd_ns_get_chunk_acct(OcssdNamespace *ons,
    uint64_t lba);

uint8_t ocssd_ns_calc_wi(OcssdNamespace *ons, uint32_t pe_cycles);

static inline uint64_t ocssd_ns_sectr_idx(OcssdNamespace *ons, uint64_t lba)
{
    OcssdAddrF *addrf = &ons->addrf;

    return ocssd_addrf_sectr(addrf, lba) +
        ocssd_addrf_chunk(addrf, lba) * ons->secs_per_chk +
        ocssd_addrf_punit(addrf, lba) * ons->secs_per_pu +
        ocssd_addrf_group(addrf, lba) * ons->secs_per_grp;
}

static inline uint64_t ocssd_ns_chk_idx(OcssdNamespace *ons, uint64_t lba)
{
    OcssdIdGeo *geo = &ons->id.geo;
    OcssdAddrF *addrf = &ons->addrf;

    return ocssd_addrf_chunk(addrf, lba) +
        ocssd_addrf_punit(addrf, lba) * geo->num_chk +
        ocssd_addrf_group(addrf, lba) * ons->chks_per_grp;
}

#endif /* OCSSD_NS_H */
