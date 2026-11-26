/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * NVM Sets (Base 2.3, 3.2.2) for Predictable Latency Mode with plm=on.
 *
 * Predictable Latency Mode (8.1.20) works per NVM Set, and a set lives in
 * one Endurance Group, which FEMU reports only with a femu-subsys. So
 * plm=on gives one set, NVMSETID 1, in Endurance Group 1, over the one
 * bbssd FTL of the controller:
 *
 *   femu-subsys --- controller (rrl=on, plm=on)
 *                     namespace 1 --> NVM Set 1 --> Endurance Group 1
 *
 *   Identify Controller   CTRATT.NSETS, NSETIDMAX 1
 *   Identify Namespace    NVMSETID 1 (CNS 00h and 08h)
 *   CNS 04h               the NVM Set List: one entry
 *   Feature 12h           NVM Set scope: CDW11 NVMSETID must be 1
 *   Feature 13h           LPE and the thresholds (Figure 423)
 *   Feature 14h           the host selects DTWIN or NDWIN
 *   Log 0Ah, 0Bh          the window, events and estimates of set 1
 *
 * Who writes the window state, and how a log read gets it:
 *
 *   main loop: Set 13h, 14h, reset --> pause --> window, counters --> resume
 *   FTL thread: after a request or idle step --> seqlock write of the snapshot
 *   main loop: Get Log 0Ah, 0Bh --> seqlock read + qatomic reads, no pause
 *
 * With plm=off, none of this changes what the controller reports.
 */

#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "qemu/main-loop.h"
#include "qemu/timer.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "nvme.h"
#include "bbssd/ftl.h"

/* bytes of one NVM Set Attributes Entry (Figure 334) */
#define FEMU_PLM_SET_ENTRY  128
/* Figure 423 and the log 0Ah page (Figure 224) */
#define FEMU_PLM_CFG_SIZE   512
#define FEMU_PLM_LOG_SIZE   512
/* log 0Bh: the header and one entry per set up to NSETIDMAX (Figure 225) */
#define FEMU_PLM_AGG_SIZE   (8 + 2 * FEMU_PLM_NVMSETID)

/* PLMW of log 0Ah byte 0, and WSEL of Feature 14h */
enum {
    FEMU_PLMW_OFF   = 0,
    FEMU_PLMW_DTWIN = 1,
    FEMU_PLMW_NDWIN = 2,
};

/* ETYP bits of log 0Ah, at the same places as the ENEV bits of 13h */
#define FEMU_PLM_WARN       0x7u            /* DTRW, DTWW, DTTW */
#define FEMU_PLM_MVEAT      (1u << 14)
#define FEMU_PLM_DEAT       (1u << 15)
#define FEMU_PLM_ETYP       (FEMU_PLM_WARN | FEMU_PLM_MVEAT | FEMU_PLM_DEAT)
/* in the event word: set 1 has an entry in log 0Bh */
#define FEMU_PLM_ENTRY      (1u << 16)

#define FEMU_PLM_MS_MAX     3600000u
#define FEMU_PLM_READS_MAX  (1ULL << 40)

/**
 * femu_plm_check - validate plm at realize
 * @n: the controller
 * @errp: set on a refusal
 *
 * One namespace on one page-mapped bbssd FTL, with Read Recovery Levels
 * (8.1.20 needs them) and a femu-subsys (a set needs an Endurance Group).
 * The refused features keep GC state of their own, or change media work
 * outside the host commands; the later windows could not hold it back.
 * The window limits must be in range, and need plm=on.
 */
bool femu_plm_check(FemuCtrl *n, Error **errp)
{
    const BbCtrlParams *p = &n->bb_params;
    const char *map = p->mapping_scheme;
    const char *tier = p->tier_mode;
    const FemuPlm *pl = &n->plm_st;
    const char *why = NULL;

    if (!n->plm) {
        if (pl->dtwin_ms != FEMU_PLM_DTWIN_MS) {
            why = "plm_dtwin_ms";
        } else if (pl->dtwin_reads != FEMU_PLM_DTWIN_READS) {
            why = "plm_dtwin_reads";
        } else if (pl->ndwin_ms != FEMU_PLM_NDWIN_MS) {
            why = "plm_ndwin_ms";
        } else if (pl->ndwin_min_ms) {
            why = "plm_ndwin_min_ms";
        }
        if (why) {
            error_setg(errp, "femu: %s needs plm=on", why);
            return false;
        }
        return true;
    }
    if (!pl->dtwin_ms || pl->dtwin_ms > FEMU_PLM_MS_MAX) {
        why = "plm_dtwin_ms must be 1 to 3600000";
    } else if (!pl->dtwin_reads || pl->dtwin_reads > FEMU_PLM_READS_MAX) {
        why = "plm_dtwin_reads must be 1 to 2^40";
    } else if (pl->ndwin_ms > FEMU_PLM_MS_MAX) {
        why = "plm_ndwin_ms must be 0 to 3600000";
    } else if (pl->ndwin_min_ms > pl->ndwin_ms) {
        why = "plm_ndwin_min_ms must be 0 to plm_ndwin_ms";
    }
    if (why) {
        error_setg(errp, "femu: %s", why);
        return false;
    }
    if (n->femu_mode != FEMU_BBSSD_MODE) {
        why = "a femu_mode other than 1";
    } else if (n->namespace_modes && n->namespace_modes[0]) {
        why = "namespace_modes";
    } else if (n->ns_mgmt || nvme_ns_shared(n)) {
        why = "managed or shared namespaces";
    } else if (n->subsys && n->subsys->endgrp.fdp.enabled) {
        why = "FDP";
    } else if (n->ocp) {
        why = "ocp";
    } else if (p->gc_pace) {
        why = "gc_pace";
    } else if (n->streams) {
        why = "streams";
    } else if (tier && *tier && strcmp(tier, "off")) {
        why = "tier_mode";
    } else if (n->cxl_dev) {
        why = "cxl_ssd";
    } else if (n->power_loss) {
        why = "power_loss";
    } else if (n->persist_file) {
        why = "persist_file";
    }
    if (why) {
        error_setg(errp, "femu: plm is not supported with %s", why);
        return false;
    }
    if (!n->rrl) {
        why = "rrl=on";
    } else if (!n->subsys) {
        why = "a femu-subsys";
    } else if (n->num_namespaces != 1) {
        why = "exactly one namespace";
    } else if (map && *map && strcmp(map, "page")) {
        why = "mapping=page";
    }
    if (why) {
        error_setg(errp, "femu: plm needs %s", why);
        return false;
    }
    return true;
}

/*
 * R4KRT, in 100 ns: one NAND page read and the channel time of 4 KiB, the
 * time of a lone 4 KiB read that meets no other work.
 */
static uint32_t femu_plm_r4krt(FemuCtrl *n, struct ssd *ssd)
{
    const BbCtrlParams *p = &n->bb_params;
    uint64_t page_b = (uint64_t)p->secs_per_pg * p->secsz;
    uint64_t t;

    if (!ssd || !page_b) {
        return 0;
    }
    t = (uint64_t)MAX(ssd->sp.pg_rd_lat, 0) +
        (uint64_t)MAX(ssd->sp.ch_xfer_lat, 0) * 4096 / page_b;
    return MIN(DIV_ROUND_UP(t, 100), UINT32_MAX);
}

/*
 * OWS in bytes: NOWS + 1 blocks. With no NOWS hint (perf_hints off) it is
 * 0h, which Figure 334 defines as not specified.
 */
static uint32_t femu_plm_ows(NvmeNamespace *ns)
{
    uint64_t nows = le16_to_cpu(ns->id_ns.nows);

    if (!nows) {
        return 0;
    }
    return MIN((nows + 1) << NVME_ID_NS_LBADS(ns), UINT32_MAX);
}

/**
 * femu_plm_nvmset_list - Identify CNS 04h, the NVM Set List
 * @n: the controller
 * @cmd: the Identify command
 *
 * The sets from NVMSETID CDW11 bits 15:0 on (Figure 332). Set 1 is the
 * only one, so a start of 0 or 1 lists it and a higher start lists none.
 * TNVMSC is the capacity of the one namespace, as TNVMCAP; with no
 * Namespace Management, UNVMSC is 0.
 */
uint16_t femu_plm_nvmset_list(FemuCtrl *n, NvmeCmd *cmd)
{
    uint8_t list[NVME_IDENTIFY_DATA_SIZE] = {};
    uint16_t start = le32_to_cpu(cmd->cdw11) & 0xffff;
    NvmeNamespace *ns = &n->namespaces[0];
    uint8_t *e = list + FEMU_PLM_SET_ENTRY;

    if (!n->plm) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (start <= FEMU_PLM_NVMSETID) {
        list[0] = 1;                                    /* NUMENT */
        stw_le_p(e, FEMU_PLM_NVMSETID);                 /* NSETID */
        stw_le_p(e + 2, 1);                             /* ENDGID */
        stl_le_p(e + 8, femu_plm_r4krt(n, ns->ssd));    /* R4KRT */
        stl_le_p(e + 12, femu_plm_ows(ns));             /* OWS */
        memcpy(e + 16, n->id_ctrl.tnvmcap, 16);         /* TNVMSC */
    }
    return dma_read_prp(n, list, sizeof(list), le64_to_cpu(cmd->dptr.prp1),
                        le64_to_cpu(cmd->dptr.prp2));
}

/*
 * Writes, in units of OWS, before forced GC (design 2.4): the free lines
 * above gc_thres_lines_high and the free pages of the open line, less
 * the pages that the write buffer still has to program.
 */
static uint64_t femu_plm_room(const FemuPlm *pl, uint64_t free_lines,
                              uint64_t open_free, uint64_t buf_pages)
{
    uint64_t pages = open_free;

    if (free_lines > pl->high_lines) {
        pages += (free_lines - pl->high_lines) * pl->line_pages;
    }
    pages = pages > buf_pages ? pages - buf_pages : 0;
    return pages * pl->page_bytes / pl->unit;
}

/*
 * Publish the FTL state that log 0Ah needs. The FTL thread calls this
 * after each request and idle step, inside the sweep; a main-loop writer
 * calls it under a pause. So one
 * thread writes at a time. @entry starts a new DTWIN, whose DTWWE low
 * point starts at the room of now. Inside a DTWIN the low point only
 * falls, so DTWWE never rises (8.1.20.1).
 */
static void femu_plm_snap(FemuCtrl *n, bool entry)
{
    FemuPlm *pl = &n->plm_st;
    struct ssd *ssd = n->ssd;
    struct line *open;
    FemuPlmSnap s;
    uint64_t room;

    if (!ssd || !pl->unit) {
        return;
    }
    open = ssd->wp.curline;
    s.free_lines = MAX(ssd->lm.free_line_cnt, 0);
    s.open_free = 0;
    if (open && (uint64_t)(open->vpc + open->ipc) < pl->line_pages) {
        s.open_free = pl->line_pages - (open->vpc + open->ipc);
    }
    s.buf_pages = MAX(ssd->write_buffer_cnt, 0);
    room = femu_plm_room(pl, s.free_lines, s.open_free, s.buf_pages);
    if (entry) {
        s.dtwwe_min = room;
    } else {
        s.dtwwe_min = pl->snap.dtwwe_min;
        if (qatomic_read(&pl->window) == FEMU_PLMW_DTWIN) {
            s.dtwwe_min = MIN(s.dtwwe_min, room);
        }
    }
    seqlock_write_begin(&pl->seq);
    pl->snap = s;
    seqlock_write_end(&pl->seq);
}

void femu_plm_publish(FemuCtrl *n)
{
    femu_plm_snap(n, false);
}

/**
 * femu_plm_init - derive the window limits from the FTL
 * @n: the controller
 * @errp: set on a refusal
 *
 * DTWWT is the room of a full NDWIN: free lines at the NDWIN target and
 * an empty buffer. The target is gc_thres_lines, at least one line above
 * gc_thres_lines_high, and at most the lines that the user data leaves
 * free with the open line and one spare (design 2.5).
 */
bool femu_plm_init(FemuCtrl *n, Error **errp)
{
    FemuPlm *pl = &n->plm_st;
    NvmeNamespace *ns = &n->namespaces[0];
    struct ssd *ssd = ns->ssd;
    uint64_t user_lines;
    uint64_t fmax;
    uint64_t target;

    if (!n->plm) {
        return true;
    }
    if (!ssd || !ssd->sp.pgs_per_line) {
        error_setg(errp, "femu: plm needs %s", "the bbssd FTL of namespace 1");
        return false;
    }
    pl->page_bytes = (uint64_t)ssd->sp.secs_per_pg * ssd->sp.secsz;
    pl->line_pages = ssd->sp.pgs_per_line;
    pl->high_lines = MAX(ssd->sp.gc_thres_lines_high, 0);
    pl->unit = femu_plm_ows(ns);
    if (!pl->unit) {
        pl->unit = pl->page_bytes;
    }
    user_lines = DIV_ROUND_UP(ns->size / pl->page_bytes, pl->line_pages);
    fmax = (uint64_t)ssd->sp.tt_lines > user_lines + 2 ?
           ssd->sp.tt_lines - user_lines - 2 : 0;
    target = MAX((uint64_t)MAX(ssd->sp.gc_thres_lines, 0),
                 pl->high_lines + 1);
    target = MIN(target, fmax);
    pl->dtwwt = femu_plm_room(pl, target, 0, 0);
    if (!pl->dtwwt) {
        error_setg(errp, "femu: plm needs %s",
                   "free lines above gc_thres_pcent_high");
        return false;
    }
    femu_plm_snap(n, false);
    return true;
}

/*
 * Enter window @w: the DTWIN amounts count from now. The caller is the
 * main loop with the data plane paused, or realize and reset.
 */
static void femu_plm_window(FemuCtrl *n, uint8_t w)
{
    FemuPlm *pl = &n->plm_st;

    qatomic_set(&pl->reads, 0);
    qatomic_set(&pl->writes, 0);
    qatomic_set(&pl->start_ms, femu_dev_now(n) / SCALE_MS);
    qatomic_set(&pl->window, w);
    femu_plm_snap(n, w == FEMU_PLMW_DTWIN);
}

/*
 * Features 13h and 14h do not persist across a reset (Figure 403): PLM
 * is disabled, the thresholds are zero and no event is pending. The
 * level of Feature 12h stays.
 */
void femu_plm_reset(FemuCtrl *n)
{
    FemuPlm *pl = &n->plm_st;

    if (!n->plm) {
        return;
    }
    pl->lpe = false;
    memset(pl->cfg, 0, sizeof(pl->cfg));
    qatomic_set(&pl->events, 0);
    femu_plm_window(n, FEMU_PLMW_OFF);
}

/**
 * femu_plm_event - record events of set 1
 * @n: the controller
 * @etyp: ETYP bits of log 0Ah
 *
 * MVEAT and DEAT always set their ETYP bit. A warning bit sets only
 * while its ENEV bit is set. The log 0Bh entry comes only for a bit
 * whose ENEV bit is set (Figures 223 to 225).
 */
void femu_plm_event(FemuCtrl *n, uint32_t etyp)
{
    FemuPlm *pl = &n->plm_st;
    uint32_t enev = lduw_le_p(pl->cfg);
    uint32_t set = etyp & (FEMU_PLM_MVEAT | FEMU_PLM_DEAT);

    set |= etyp & enev & FEMU_PLM_WARN;
    if (etyp & enev & FEMU_PLM_ETYP) {
        set |= FEMU_PLM_ENTRY;
    }
    if (set) {
        qatomic_or(&pl->events, set);
    }
}

/* CDW11 of 13h, 14h and the LSI of log 0Ah name set 1; 31:16 reserved */
static bool femu_plm_set_ok(uint32_t dw11)
{
    return dw11 == FEMU_PLM_NVMSETID;
}

/**
 * femu_plm_get_feature - Get Features 13h and 14h, Select 0 to 2
 * @n: the controller
 * @cmd: the command; NSID and NVMSETID were checked by the caller
 * @cqe: Dword 0
 *
 * 13h returns LPE in Dword 0 and the Figure 423 structure as data. The
 * default and the saved value are LPE 0 with zero thresholds. 14h needs
 * PLM enabled (5.2.26.1.13); its default is NDWIN, where LPE=1 starts.
 */
uint16_t femu_plm_get_feature(FemuCtrl *n, NvmeCmd *cmd, NvmeCqe *cqe)
{
    FemuPlm *pl = &n->plm_st;
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint8_t sel = NVME_GETFEAT_SELECT(dw10);
    bool cur = sel == NVME_GETFEAT_SELECT_CURRENT;
    uint8_t zero[FEMU_PLM_CFG_SIZE] = { 0 };

    /*
     * Neither feature is saveable, so Saved answers as Default does, as
     * for 12h and HCTM.
     */
    if (sel != NVME_GETFEAT_SELECT_CURRENT &&
        sel != NVME_GETFEAT_SELECT_DEFAULT &&
        sel != NVME_GETFEAT_SELECT_SAVED) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (NVME_GETSETFEAT_FID(dw10) == NVME_PLM_WINDOW) {
        /* PLM off: refused for every Select, Default too (5.2.26.1.13) */
        if (!pl->lpe) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        cqe->n.result = cpu_to_le32(cur ? qatomic_read(&pl->window) :
                                    FEMU_PLMW_NDWIN);
        return NVME_SUCCESS;
    }
    cqe->n.result = cpu_to_le32(cur && pl->lpe);
    return dma_read_prp(n, cur ? pl->cfg : zero, FEMU_PLM_CFG_SIZE,
                        le64_to_cpu(cmd->dptr.prp1),
                        le64_to_cpu(cmd->dptr.prp2));
}

/*
 * Figure 423: ENEV bits 13:3, bytes 31:2 and bytes 511:56 are reserved.
 * DTRT, DTWT and DTTT take any value.
 */
static bool femu_plm_cfg_ok(const uint8_t *cfg)
{
    return !(lduw_le_p(cfg) & ~FEMU_PLM_ETYP) &&
           buffer_is_zero(cfg + 2, 30) &&
           buffer_is_zero(cfg + 56, FEMU_PLM_CFG_SIZE - 56);
}

/**
 * femu_plm_set_feature - Set Features 13h and 14h
 * @n: the controller
 * @cmd: the command; NSID and SV were checked by the caller
 * @cqe: unused
 *
 * 13h stores the thresholds; LPE=1 enters NDWIN (5.2.26.1.12), also from
 * DTWIN, and LPE=0 disables PLM. Events stay until log 0Ah is read. 14h
 * selects the window at once; a DTWIN while in DTWIN keeps its amounts,
 * so a host cannot renew the budget without an NDWIN. Both change state
 * that the FTL thread reads, so they pause the data plane.
 */
uint16_t femu_plm_set_feature(FemuCtrl *n, NvmeCmd *cmd, NvmeCqe *cqe)
{
    FemuPlm *pl = &n->plm_st;
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);
    uint32_t dw12 = le32_to_cpu(cmd->cdw12);
    uint8_t cfg[FEMU_PLM_CFG_SIZE];
    uint8_t wsel = dw12 & 0x7;
    uint16_t status;
    bool resume;

    if (!femu_plm_set_ok(dw11)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (NVME_GETSETFEAT_FID(dw10) == NVME_PLM_CONFIG) {
        if (dw12 & ~0x1u) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        status = dma_write_prp(n, cfg, sizeof(cfg),
                               le64_to_cpu(cmd->dptr.prp1),
                               le64_to_cpu(cmd->dptr.prp2));
        if (status) {
            return status;
        }
        if (!femu_plm_cfg_ok(cfg)) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        resume = nvme_pause_pollers(n);
        memcpy(pl->cfg, cfg, sizeof(cfg));
        pl->lpe = dw12 & 0x1;
        if (pl->lpe || qatomic_read(&pl->window) != FEMU_PLMW_OFF) {
            femu_plm_window(n, pl->lpe ? FEMU_PLMW_NDWIN : FEMU_PLMW_OFF);
        }
        nvme_resume_pollers(n, resume);
        return NVME_SUCCESS;
    }

    if ((dw12 & ~0x7u) || (wsel != FEMU_PLMW_DTWIN &&
                           wsel != FEMU_PLMW_NDWIN) || !pl->lpe) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (qatomic_read(&pl->window) != wsel) {
        resume = nvme_pause_pollers(n);
        femu_plm_window(n, wsel);
        nvme_resume_pollers(n, resume);
    }
    return NVME_SUCCESS;
}

/**
 * femu_plm_set_log - Get Log Page 0Ah, Predictable Latency Per NVM Set
 * @n: the controller
 * @cmd: the command; LSI in CDW11 bits 31:16 names the set
 * @len: bytes to transfer
 * @off: byte offset in the 512-byte page
 * @rae: Retain Asynchronous Event
 *
 * No pause: the FTL state comes from the seqlock snapshot and the rest
 * from qatomic reads. A read without RAE clears the ETYP bits and the
 * log 0Bh entry it reported; an event set during the read stays.
 *
 *   window   DTWRE               DTWWE                       DTWTE
 *   off      0                   0                           0
 *   NDWIN    DTWRT               min(DTWWT, room)            DTWTM
 *   DTWIN    DTWRT - reads       min(DTWWT - writes, low)    DTWTM - time
 */
uint16_t femu_plm_set_log(FemuCtrl *n, NvmeCmd *cmd, uint32_t len,
                          uint64_t off, bool rae)
{
    FemuPlm *pl = &n->plm_st;
    uint8_t log[FEMU_PLM_LOG_SIZE] = { 0 };
    uint32_t lsi = le32_to_cpu(cmd->cdw11) >> 16;
    FemuPlmSnap s;
    unsigned int seq;
    uint8_t window;
    uint32_t ev;
    uint64_t reads;
    uint64_t writes;
    int64_t time_ms;
    uint64_t dtwre = 0;
    uint64_t dtwwe = 0;
    uint64_t dtwte = 0;
    uint32_t n_bytes;
    uint16_t status;

    if (!femu_plm_set_ok(lsi) || off >= sizeof(log)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    do {
        seq = seqlock_read_begin(&pl->seq);
        s = pl->snap;
    } while (seqlock_read_retry(&pl->seq, seq));
    window = qatomic_read(&pl->window);
    ev = qatomic_read(&pl->events);

    if (window == FEMU_PLMW_NDWIN) {
        dtwre = pl->dtwin_reads;
        dtwwe = MIN(pl->dtwwt, femu_plm_room(pl, s.free_lines, s.open_free,
                                             s.buf_pages));
        dtwte = pl->dtwin_ms;
    } else if (window == FEMU_PLMW_DTWIN) {
        reads = qatomic_read(&pl->reads);
        writes = qatomic_read(&pl->writes);
        time_ms = femu_dev_now(n) / SCALE_MS - qatomic_read(&pl->start_ms);
        dtwre = pl->dtwin_reads > reads ? pl->dtwin_reads - reads : 0;
        dtwwe = pl->dtwwt > writes ? pl->dtwwt - writes : 0;
        dtwwe = MIN(dtwwe, s.dtwwe_min);
        dtwte = time_ms < pl->dtwin_ms ? pl->dtwin_ms - MAX(time_ms, 0) : 0;
    }

    log[0] = window;                                /* STSNVMS.PLMW */
    stw_le_p(log + 2, ev & FEMU_PLM_ETYP);          /* ETYP */
    stq_le_p(log + 32, pl->dtwin_reads);            /* DTWRT */
    stq_le_p(log + 40, pl->dtwwt);                  /* DTWWT */
    stq_le_p(log + 48, pl->dtwin_ms);               /* DTWTM */
    stq_le_p(log + 56, pl->ndwin_ms);               /* NTWTMH */
    stq_le_p(log + 64, pl->ndwin_min_ms);           /* NTWTML */
    stq_le_p(log + 128, dtwre);                     /* DTWRE */
    stq_le_p(log + 136, dtwwe);                     /* DTWWE */
    stq_le_p(log + 144, dtwte);                     /* DTWTE */

    n_bytes = MIN(sizeof(log) - off, len);
    status = dma_read_prp(n, log + off, n_bytes,
                          le64_to_cpu(cmd->dptr.prp1),
                          le64_to_cpu(cmd->dptr.prp2));
    /* only a read that returned ETYP (bytes 3:2) clears what it reported */
    if (!status && !rae && ev && off <= 2 && off + n_bytes >= 4) {
        qatomic_and(&pl->events, ~ev);
    }
    return status;
}

/**
 * femu_plm_event_log - Get Log Page 0Bh, Predictable Latency Event Aggregate
 * @n: the controller
 * @cmd: the command
 * @len: bytes to transfer
 * @off: byte offset
 * @rae: Retain Asynchronous Event
 *
 * NUMENT and one entry for set 1 while it has an event pending. Bytes
 * past the 10-byte page read as zeros, at any offset (5.2.12.1.12). A
 * read without RAE ends the Notice for this page; the entry stays until
 * log 0Ah is read.
 */
uint16_t femu_plm_event_log(FemuCtrl *n, NvmeCmd *cmd, uint32_t len,
                            uint64_t off, bool rae)
{
    uint8_t log[FEMU_PLM_AGG_SIZE] = { 0 };
    g_autofree uint8_t *buf = g_malloc0(len);
    uint16_t status;

    if (qatomic_read(&n->plm_st.events) & FEMU_PLM_ENTRY) {
        log[0] = 1;                                 /* NUMENT */
        stw_le_p(log + 8, FEMU_PLM_NVMSETID);       /* entry 1 */
    }
    if (off < sizeof(log)) {
        memcpy(buf, log + off, MIN(sizeof(log) - off, len));
    }
    status = dma_read_prp(n, buf, len, le64_to_cpu(cmd->dptr.prp1),
                          le64_to_cpu(cmd->dptr.prp2));
    if (!status && !rae) {
        nvme_clear_ns_events(n, NVME_AER_TYPE_NOTICE, NVME_LOG_PLM_EVENTS, 0,
                             true);
        qemu_bh_schedule(n->aer_bh);
    }
    return status;
}

/* qtest only: record the ETYP bits written, as the FTL thread will */
static void femu_plm_test_event(Object *obj, Visitor *v, const char *name,
                                void *opaque, Error **errp)
{
    FemuCtrl *n = FEMU(obj);
    uint32_t etyp;

    if (!visit_type_uint32(v, name, &etyp, errp)) {
        return;
    }
    if (!n->plm || (etyp & ~FEMU_PLM_ETYP)) {
        error_setg(errp, "x-plm-event takes ETYP bits 0 to 2, 14 and 15 "
                   "with plm=on");
        return;
    }
    femu_plm_event(n, etyp);
}

void femu_plm_add_props(Object *obj)
{
    object_property_add(obj, "x-plm-event", "uint32", NULL,
                        femu_plm_test_event, NULL, NULL);
}
