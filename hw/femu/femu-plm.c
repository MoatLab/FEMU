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
 * What the FTL thread does in each window (design 2.1):
 *
 *   work                                     DTWIN     NDWIN
 *   host commands, Flush, full-buffer destage  run       run
 *   forced GC at gc_thres_lines_high           exit (*)  run
 *   background and idle GC, maint_idle         hold      run
 *   idle write-back, read reclaim, retention   hold      run
 *   wear levelling, RAIN rebuild, aged pad     hold      run
 *   preparation GC up to plm_ndwin_lines       hold      run
 *
 * A held item keeps its state and runs in the next NDWIN. (*) A forced
 * GC pass with a victim first moves the set to NDWIN with ETYP DEAT,
 * then runs. A failed die is a DEAT too, and so is a forced GC in the
 * drain of a cache disable, which the host caused. Format NVM and
 * Sanitize move the set to NDWIN before their drain, with no event.
 *
 * The FTL thread counts the DTWIN reads and writes, and leaves DTWIN on
 * its own when one passes its limit, or when the time ends (MVEAT):
 *
 *   request --> count reads (4 KiB), writes (OWS) --> femu_plm_step()
 *   idle pass, DTWIN time up ------------------------> femu_plm_step()
 *   femu_plm_step(): reads > DTWRT, writes > DTWWT or time >= DTWTM
 *                    --> NDWIN, ETYP MVEAT
 *
 * An event and its notice (Figures 223 to 225, 5.2.2):
 *
 *   MVEAT, DEAT --------------------------> ETYP bit, also with ENEV clear
 *   estimate < DTRT, DTWT or DTTT, ENEV --> warning bit, once per DTWIN
 *   ENEV bit set --> log 0Bh entry --> new, AEC bit 12? --> AEN 04h/0Bh
 *   the Notice stays masked until the host reads log 0Bh
 *
 * A Set 14h DTWIN from NDWIN waits until plm_ndwin_min_ms (NTWTML) has
 * passed in NDWIN and the media work booked at its arrival has ended
 * (design 5.2). Meanwhile the window stays NDWIN, the FTL starts no
 * background work, and later admin commands run:
 *
 *   Set 14h DTWIN --> held, timer at the deadline --> CQE, DTWIN
 *   reset, teardown -----------------------------> no CQE
 *   Abort of it ---------------------------------> CQE 07h, then the Abort
 *   Set 13h LPE=0 -------------------------------> CQE 02h, then the 13h
 *   Set 14h, Set 13h LPE=1, Format, Sanitize ----> CQE 0Ch, then the command
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
#define FEMU_PLM_DTTW       (1u << 2)
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
        } else if (pl->ndwin_lines) {
            why = "plm_ndwin_lines";
        } else if (pl->dtwin_writes) {
            why = "plm_dtwin_writes";
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

/*
 * The most free lines that NDWIN can reach (design 2.5): the lines in
 * service, less the lines the user data fills when packed, the open
 * write pointer lines and one spare.
 */
static uint64_t femu_plm_fmax(NvmeNamespace *ns, struct ssd *ssd,
                              uint64_t page_bytes)
{
    uint64_t usable = 0;
    uint64_t user;
    uint64_t wps;

    for (int i = 0; i < ssd->sp.tt_lines; i++) {
        struct line *l = &ssd->lm.lines[i];

        usable += !l->retired && !l->spare && !l->reserve;
    }
    user = DIV_ROUND_UP(DIV_ROUND_UP(ns->size, page_bytes),
                        MAX(ssd->sp.line_data_pgs, 1));
    wps = 1 + ssd->sp.hot_cold_sep + ssd->sp.gc_frontier;
    return usable > user + wps + 1 ? usable - user - wps - 1 : 0;
}

/**
 * femu_plm_init - derive the window limits from the FTL
 * @n: the controller
 * @errp: set on a refusal
 *
 * The NDWIN target is plm_ndwin_lines, from one line above
 * gc_thres_lines_high to what the user data leaves free. By default it
 * is gc_thres_lines, kept in that range (design 2.5). DTWWT is the room
 * of a full NDWIN: free lines at the target and an empty buffer.
 */
bool femu_plm_init(FemuCtrl *n, Error **errp)
{
    FemuPlm *pl = &n->plm_st;
    NvmeNamespace *ns = &n->namespaces[0];
    struct ssd *ssd = ns->ssd;
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
    fmax = femu_plm_fmax(ns, ssd, pl->page_bytes);
    /* no target fits: forced GC would start before NDWIN could end */
    if (fmax <= pl->high_lines) {
        error_setg(errp, "femu: plm needs %s",
                   "free lines above gc_thres_pcent_high");
        return false;
    }
    if (pl->ndwin_lines &&
        (pl->ndwin_lines <= pl->high_lines || pl->ndwin_lines > fmax)) {
        error_setg(errp, "femu: plm_ndwin_lines must be %d to %d",
                   (int)(pl->high_lines + 1), (int)fmax);
        return false;
    }
    target = pl->ndwin_lines;
    if (!target) {
        target = MAX((uint64_t)MAX(ssd->sp.gc_thres_lines, 0),
                     pl->high_lines + 1);
        target = MIN(target, fmax);
    }
    pl->dtwwt = femu_plm_room(pl, target, 0, 0);
    if (!pl->dtwwt) {
        error_setg(errp, "femu: plm needs %s",
                   "free lines above gc_thres_pcent_high");
        return false;
    }
    /* more writes than a full NDWIN leaves room for would force GC */
    if (pl->dtwin_writes > pl->dtwwt) {
        error_setg(errp, "femu: plm_dtwin_writes must be 0 to %" PRIu64,
                   pl->dtwwt);
        return false;
    }
    if (pl->dtwin_writes) {
        pl->dtwwt = pl->dtwin_writes;
    }
    ssd->plm = true;
    ssd->plm_lines = target;
    femu_plm_snap(n, false);
    /* the held Set 14h; its deadline is on the clock of femu_dev_now() */
    pl->hold_timer = timer_new_ns(QEMU_CLOCK_REALTIME, femu_plm_timer_cb, n);
    return true;
}

/*
 * The reliable estimates DTWRE, DTWWE and DTWTE at @now_ms, in the order
 * of their ETYP and ENEV bits (design 2.4). In DTWIN each one only
 * falls: the amounts only grow, and the DTWWE low point only falls.
 *
 *   window   DTWRE               DTWWE                       DTWTE
 *   off      0                   0                           0
 *   NDWIN    DTWRT               min(DTWWT, room)            DTWTM (*)
 *   DTWIN    DTWRT - reads       min(DTWWT - writes, low)    DTWTM - time
 *
 * (*) After a DEAT, the time the aborted DTWIN had left, so the host can
 * line the set up with others again (8.1.20.1).
 */
static void femu_plm_estimates(FemuPlm *pl, const FemuPlmSnap *s,
                               uint8_t window, int64_t now_ms, uint64_t *est)
{
    uint64_t reads;
    uint64_t writes;
    int64_t time_ms;

    est[0] = est[1] = est[2] = 0;
    if (window == FEMU_PLMW_NDWIN) {
        est[0] = pl->dtwin_reads;
        est[1] = MIN(pl->dtwwt, femu_plm_room(pl, s->free_lines,
                                              s->open_free, s->buf_pages));
        est[2] = qatomic_read(&pl->ndwin_dtwte);
    } else if (window == FEMU_PLMW_DTWIN) {
        reads = qatomic_read(&pl->reads);
        writes = qatomic_read(&pl->writes);
        time_ms = now_ms - qatomic_read(&pl->start_ms);
        est[0] = pl->dtwin_reads > reads ? pl->dtwin_reads - reads : 0;
        est[1] = pl->dtwwt > writes ? pl->dtwwt - writes : 0;
        est[1] = MIN(est[1], s->dtwwe_min);
        est[2] = time_ms < pl->dtwin_ms ? pl->dtwin_ms - MAX(time_ms, 0) : 0;
    }
}

/*
 * The FTL work of window @w: background work holds in DTWIN, and the
 * preparation runs in NDWIN. A held Set 14h holds as DTWIN does.
 */
static void femu_plm_flags(FemuCtrl *n, uint8_t w)
{
    struct ssd *ssd = n->ssd;

    if (ssd && ssd->plm) {
        qatomic_set(&ssd->plm_hold, w == FEMU_PLMW_DTWIN);
        qatomic_set(&ssd->plm_prep, w == FEMU_PLMW_NDWIN);
    }
}

/*
 * Enter window @w: the DTWIN amounts count from now. The caller is the
 * main loop with the data plane paused, realize and reset, or the FTL
 * thread inside its sweep for an autonomous exit.
 */
static void femu_plm_window(FemuCtrl *n, uint8_t w)
{
    FemuPlm *pl = &n->plm_st;

    femu_plm_flags(n, w);
    qatomic_set(&pl->ndwin_dtwte, pl->dtwin_ms);
    pl->rd_bytes = 0;
    pl->wr_bytes = 0;
    qatomic_set(&pl->reads, 0);
    qatomic_set(&pl->writes, 0);
    qatomic_set(&pl->warned, 0);
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

/*
 * When a held Set 14h DTWIN may complete (design 5.2): NTWTML after the
 * NDWIN entry, and the end of the media work booked when it came. So the
 * DTWIN starts with no GC work on the dies, and later host I/O does not
 * move the deadline. The caller holds the pause, so the FTL is idle.
 */
static int64_t femu_plm_hold_end(FemuCtrl *n)
{
    FemuPlm *pl = &n->plm_st;
    int64_t end = 0;

    /* start_ms rounds down: one more ms keeps at least NTWTML */
    if (pl->ndwin_min_ms) {
        end = (qatomic_read(&pl->start_ms) + 1 + pl->ndwin_min_ms) *
              SCALE_MS;
    }
    if (n->ssd) {
        end = MAX(end, (int64_t)ssd_media_last_end(n->ssd));
    }
    return end;
}

/* the admin CQ of the held Set 14h has room for @need more CQEs */
static bool femu_plm_hold_room(FemuCtrl *n, uint32_t need)
{
    NvmeCQueue *cq = n->cq[n->plm_st.hold.cqid];

    if (!cq) {
        return true;
    }
    return cq->size - 1 - (cq->tail + cq->size - cq->head) % cq->size >=
           need;
}

/*
 * Post the held Set 14h: at its deadline with success, or at once when a
 * drop set an error in @hold_sc. @need is 2 when a command's own CQE
 * follows. Without room the timer tries again. Success enters DTWIN; an
 * error leaves NDWIN and lets the FTL work again. Returns true when no
 * command is held any more.
 */
static bool femu_plm_hold_post(FemuCtrl *n, uint32_t need)
{
    FemuPlm *pl = &n->plm_st;
    NvmeAerResult res = { 0 };
    bool resume;

    if (!pl->held) {
        return true;
    }
    if (pl->hold_sc == NVME_SUCCESS && femu_dev_now(n) < pl->hold_end) {
        timer_mod(pl->hold_timer, pl->hold_end);
        return false;
    }
    if (!femu_plm_hold_room(n, need)) {
        timer_mod(pl->hold_timer, femu_dev_now(n) + SCALE_MS);
        return false;
    }
    pl->held = false;
    timer_del(pl->hold_timer);
    resume = nvme_pause_pollers(n);
    if (pl->hold_sc == NVME_SUCCESS) {
        femu_plm_window(n, FEMU_PLMW_DTWIN);
    } else {
        femu_plm_flags(n, qatomic_read(&pl->window));
    }
    nvme_resume_pollers(n, resume);
    nvme_post_held_cqe(n, &pl->hold, &res, 0, pl->hold_sc);
    return true;
}

/*
 * A command ends the held Set 14h with @sc, and its own CQE comes next.
 * The admin queue fetches it with room for two CQEs, so the held one
 * posts first. A size-2 admin CQ has room for one only. Then @must keeps
 * @sc for the timer, which posts the held CQE after the command's own;
 * without @must the hold stays as it was. Returns true when nothing is
 * held any more.
 */
static bool femu_plm_hold_drop(FemuCtrl *n, uint16_t sc, bool must)
{
    FemuPlm *pl = &n->plm_st;

    if (!pl->held) {
        return true;
    }
    if (!femu_plm_hold_room(n, 2) && !must) {
        return false;
    }
    /* a drop that waits for room keeps its status */
    if (pl->hold_sc == NVME_SUCCESS) {
        pl->hold_sc = sc;
    }
    return femu_plm_hold_post(n, 2);
}

/* the deadline of the held Set 14h passed, or its CQ had no room */
void femu_plm_timer_cb(void *opaque)
{
    FemuCtrl *n = opaque;

    if (n->plm_st.held && femu_plm_hold_post(n, 1) && n->sq[0]) {
        /* commands that waited for room for two CQEs run now */
        nvme_process_sq_admin(n->sq[0]);
    }
}

/**
 * femu_plm_abort - Abort of a held Set 14h
 * @n: the controller
 * @cid: the CID that the Abort names on the admin queue
 *
 * The held command completes with Command Abort Requested before the
 * Abort does. Returns true when @cid named it.
 */
bool femu_plm_abort(FemuCtrl *n, uint16_t cid)
{
    FemuPlm *pl = &n->plm_st;

    if (!pl->held || pl->hold.sqid || le16_to_cpu(pl->hold.cid) != cid) {
        return false;
    }
    femu_plm_hold_drop(n, NVME_CMD_ABORT_REQ, true);
    return true;
}

/**
 * femu_plm_drop - a reset, a shutdown or teardown ends the held Set 14h
 * @n: the controller
 *
 * The queues go, so the command never completes (design 5.3). The FTL
 * works as the window says again.
 */
void femu_plm_drop(FemuCtrl *n)
{
    FemuPlm *pl = &n->plm_st;
    bool resume;

    if (pl->hold_timer) {
        timer_del(pl->hold_timer);
    }
    if (!pl->held) {
        return;
    }
    pl->held = false;
    resume = nvme_pause_pollers(n);
    femu_plm_flags(n, qatomic_read(&pl->window));
    nvme_resume_pollers(n, resume);
}

/**
 * femu_plm_format - a Format NVM or a Sanitize is about to change the media
 * @n: the controller
 *
 * The set leaves DTWIN before the drain of the command, with no ETYP bit
 * and no event (design D2): the host asked for this media work. A forced
 * GC in the drain then finds NDWIN, so it is no excursion. A held Set
 * 14h ends with Command Sequence Error, first when the CQ has room for
 * two (femu_plm_hold_drop()). The caller is the main
 * loop; the pause nests in one the caller holds.
 */
void femu_plm_format(FemuCtrl *n)
{
    bool resume;

    if (!n->plm) {
        return;
    }
    femu_plm_hold_drop(n, NVME_CMD_SEQ_ERROR, true);
    resume = nvme_pause_pollers(n);
    if (qatomic_read(&n->plm_st.window) == FEMU_PLMW_DTWIN) {
        femu_plm_window(n, FEMU_PLMW_NDWIN);
    }
    nvme_resume_pollers(n, resume);
}

/**
 * femu_plm_event - record events of set 1
 * @n: the controller
 * @etyp: ETYP bits of log 0Ah
 *
 * MVEAT and DEAT always set their ETYP bit. A warning bit sets only
 * while its ENEV bit is set. The log 0Bh entry comes only for a bit
 * whose ENEV bit is set (Figures 223 to 225). A new entry raises the
 * Notice when AEC bit 12 is set (5.2.26.1.5). Until the host reads log
 * 0Bh, the Notice type stays masked, so a later entry waits (5.2.2).
 * The FTL thread or the main loop may call it: the AEN queue has its
 * own lock, and the main loop posts the AEN.
 */
void femu_plm_event(FemuCtrl *n, uint32_t etyp)
{
    FemuPlm *pl = &n->plm_st;
    uint32_t enev = lduw_le_p(pl->cfg);
    uint32_t set = etyp & (FEMU_PLM_MVEAT | FEMU_PLM_DEAT);
    uint32_t old;

    set |= etyp & enev & FEMU_PLM_WARN;
    if (etyp & enev & FEMU_PLM_ETYP) {
        set |= FEMU_PLM_ENTRY;
    }
    if (!set) {
        return;
    }
    old = qatomic_fetch_or(&pl->events, set);
    if ((set & ~old & FEMU_PLM_ENTRY) &&
        (qatomic_read(&n->features.async_config) & NVME_AEC_PLEA)) {
        nvme_enqueue_event(n, NVME_AER_TYPE_NOTICE, NVME_AER_INFO_PLEA,
                           NVME_LOG_PLM_EVENTS);
    }
}

/*
 * An autonomous exit from DTWIN with ETYP bit @etyp. The FTL thread calls
 * it inside its sweep, or the main loop under a pause.
 */
static void femu_plm_exit(FemuCtrl *n, uint32_t etyp)
{
    if (qatomic_read(&n->plm_st.window) != FEMU_PLMW_DTWIN) {
        return;
    }
    femu_plm_window(n, FEMU_PLMW_NDWIN);
    femu_plm_event(n, etyp);
}

/**
 * femu_plm_count - count a request of the FTL thread toward DTWIN
 * @n: the controller
 * @req: a request that ran its FTL step
 *
 * Reads in 4 KiB units: Read, Compare, Verify and the source of a Copy.
 * Writes in OWS units: Write, Write Zeroes and the target of a Copy.
 * The bytes add up over the window and round up to units once, so
 * sixteen 4 KiB writes with a 64 KiB OWS are one write. Write Zeroes
 * counts also with DEAC, as its blocks change. A failed command, DSM
 * and Flush count nothing.
 */
void femu_plm_count(FemuCtrl *n, NvmeRequest *req)
{
    FemuPlm *pl = &n->plm_st;
    uint64_t bytes;
    uint64_t r = 0;
    uint64_t w = 0;

    if (qatomic_read(&pl->window) != FEMU_PLMW_DTWIN || !req->ns ||
        req->status != NVME_SUCCESS) {
        return;
    }
    bytes = (uint64_t)req->nlb << NVME_ID_NS_LBADS(req->ns);
    switch (req->cmd.opcode) {
    case NVME_CMD_READ:
    case NVME_CMD_COMPARE:
    case NVME_CMD_VERIFY:
        r = bytes;
        break;
    case NVME_CMD_WRITE:
    case NVME_CMD_WRITE_ZEROES:
        w = bytes;
        break;
    case NVME_CMD_COPY:
        /* the source ranges hold as many blocks as the target */
        r = bytes;
        w = bytes;
        break;
    default:
        return;
    }
    /* the main loop zeroes them only under a pause */
    pl->rd_bytes += r;
    pl->wr_bytes += w;
    qatomic_set(&pl->reads, DIV_ROUND_UP(pl->rd_bytes, 4096));
    qatomic_set(&pl->writes, DIV_ROUND_UP(pl->wr_bytes, pl->unit));
}

/*
 * The warnings of a DTWIN (Figure 423): each one fires once, when its
 * estimate falls below its threshold (DTRT, DTWT, DTTT at bytes 32, 40
 * and 48) while its ENEV bit is set.
 */
static void femu_plm_warn(FemuCtrl *n, int64_t now_ms)
{
    FemuPlm *pl = &n->plm_st;
    uint32_t want = lduw_le_p(pl->cfg) & FEMU_PLM_WARN & ~pl->warned;
    uint32_t warn = 0;
    uint64_t est[3];

    if (!want) {
        return;
    }
    femu_plm_estimates(pl, &pl->snap, FEMU_PLMW_DTWIN, now_ms, est);
    for (int i = 0; i < 3; i++) {
        if ((want & (1u << i)) && est[i] < ldq_le_p(pl->cfg + 32 + 8 * i)) {
            warn |= 1u << i;
        }
    }
    if (warn) {
        pl->warned |= warn;
        femu_plm_event(n, warn);
    }
}

/**
 * femu_plm_step - the end of an FTL step with plm=on
 * @n: the controller
 *
 * The FTL thread calls it inside its sweep, after a request or an idle
 * step. It publishes the snapshot for log 0Ah. In DTWIN it gives the
 * warnings whose estimate fell below its threshold. It leaves for NDWIN
 * once the reads pass DTWRT, the writes pass DTWWT or the time reaches
 * DTWTM (8.1.20.1), with ETYP MVEAT.
 */
void femu_plm_step(FemuCtrl *n)
{
    FemuPlm *pl = &n->plm_st;
    int64_t now_ms;

    if (!n->ssd || !pl->unit) {
        return;
    }
    femu_plm_snap(n, false);
    if (qatomic_read(&pl->window) != FEMU_PLMW_DTWIN) {
        return;
    }
    now_ms = femu_dev_now(n) / SCALE_MS;
    femu_plm_warn(n, now_ms);
    if (qatomic_read(&pl->reads) > pl->dtwin_reads ||
        qatomic_read(&pl->writes) > pl->dtwwt ||
        now_ms - qatomic_read(&pl->start_ms) >= pl->dtwin_ms) {
        femu_plm_exit(n, FEMU_PLM_MVEAT);
    }
}

/**
 * femu_plm_excursion - work that DTWIN cannot hold starts
 * @n: the controller
 *
 * A Deterministic Excursion (8.1.20.1): the set leaves DTWIN with ETYP
 * DEAT before the work, so DTWIN never holds the GC that a write needs.
 * do_gc_pass() calls it for a forced pass with a victim, and
 * ssd_rain_fail() for a failed die. The FTL thread calls it inside its
 * sweep, or the main loop under a pause, so one thread owns the window.
 * DTWTE in NDWIN keeps the time the DTWIN had left.
 */
void femu_plm_excursion(FemuCtrl *n)
{
    FemuPlm *pl = &n->plm_st;
    int64_t t;

    if (qatomic_read(&pl->window) != FEMU_PLMW_DTWIN) {
        return;
    }
    t = femu_dev_now(n) / SCALE_MS - qatomic_read(&pl->start_ms);
    femu_plm_exit(n, FEMU_PLM_DEAT);
    qatomic_set(&pl->ndwin_dtwte,
                t < pl->dtwin_ms ? pl->dtwin_ms - MAX(t, 0) : 0);
}

/*
 * femu_plm_idle_due - whether the idle FTL thread has a DTWIN step: the
 * time limit and the time warning need no request to pass
 *
 * bb_plm_idle() asks outside ftl_in_sweep, where a main-loop Set 13h or
 * 14h may change cfg and warned. The answer is a hint only: the step
 * inside the sweep checks again.
 */
bool femu_plm_idle_due(FemuCtrl *n)
{
    FemuPlm *pl = &n->plm_st;
    uint32_t want;
    int64_t t;

    if (qatomic_read(&pl->window) != FEMU_PLMW_DTWIN) {
        return false;
    }
    t = femu_dev_now(n) / SCALE_MS - qatomic_read(&pl->start_ms);
    if (t >= pl->dtwin_ms) {
        return true;
    }
    /* DTWTE below DTTT, with DTTW enabled and not given yet */
    want = lduw_le_p(pl->cfg) & FEMU_PLM_DTTW & ~qatomic_read(&pl->warned);
    return want &&
           (uint64_t)(pl->dtwin_ms - MAX(t, 0)) < ldq_le_p(pl->cfg + 48);
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
 * NDWIN takes effect at once. 14h DTWIN from NDWIN is held to the
 * deadline of femu_plm_hold_end() and returns NVME_NO_COMPLETE. A DTWIN
 * while in DTWIN keeps its amounts, so a host cannot renew the budget
 * without an NDWIN. A held 14h ends before either command runs (design
 * 5.3). Both change state that the FTL thread reads, so they pause the
 * data plane.
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
    int64_t end;
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
        /*
         * LPE=0: no PLM for the held 14h (5.2.26.1.13); LPE=1: a new NDWIN.
         * In a size-2 admin CQ the held CQE cannot post before this one.
         * Then nothing changes, so the host may send this 13h again.
         */
        if (!femu_plm_hold_drop(n, (dw12 & 0x1) ? NVME_CMD_SEQ_ERROR :
                                NVME_INVALID_FIELD | NVME_DNR, false)) {
            return NVME_CMD_SEQ_ERROR;
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
    /* this 14h replaces a held one; no room changes nothing, as for 13h */
    if (!femu_plm_hold_drop(n, NVME_CMD_SEQ_ERROR, false)) {
        return NVME_CMD_SEQ_ERROR;
    }
    /* under the pause: the FTL thread may have left DTWIN on its own */
    resume = nvme_pause_pollers(n);
    if (wsel == FEMU_PLMW_DTWIN &&
        qatomic_read(&pl->window) == FEMU_PLMW_NDWIN) {
        end = femu_plm_hold_end(n);
        if (end > femu_dev_now(n)) {
            /* NDWIN stays, with no new background work until the end */
            pl->held = true;
            pl->hold_sc = NVME_SUCCESS;
            pl->hold_end = end;
            femu_plm_flags(n, FEMU_PLMW_DTWIN);
            nvme_resume_pollers(n, resume);
            timer_mod(pl->hold_timer, end);
            return NVME_NO_COMPLETE;
        }
    }
    if (qatomic_read(&pl->window) != wsel) {
        femu_plm_window(n, wsel);
    }
    nvme_resume_pollers(n, resume);
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
 * log 0Bh entry it reported; an event set during the read stays. The
 * estimates are those of femu_plm_estimates().
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
    uint64_t est[3];
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
    femu_plm_estimates(pl, &s, window, femu_dev_now(n) / SCALE_MS, est);

    log[0] = window;                                /* STSNVMS.PLMW */
    stw_le_p(log + 2, ev & FEMU_PLM_ETYP);          /* ETYP */
    stq_le_p(log + 32, pl->dtwin_reads);            /* DTWRT */
    stq_le_p(log + 40, pl->dtwwt);                  /* DTWWT */
    stq_le_p(log + 48, pl->dtwin_ms);               /* DTWTM */
    stq_le_p(log + 56, pl->ndwin_ms);               /* NTWTMH */
    stq_le_p(log + 64, pl->ndwin_min_ms);           /* NTWTML */
    stq_le_p(log + 128, est[0]);                    /* DTWRE */
    stq_le_p(log + 136, est[1]);                    /* DTWWE */
    stq_le_p(log + 144, est[2]);                    /* DTWTE */

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
    uint32_t seen = qatomic_read(&n->plm_st.events);
    uint32_t etyp;
    uint16_t status;

    if (seen & FEMU_PLM_ENTRY) {
        log[0] = 1;                                 /* NUMENT */
        stw_le_p(log + 8, FEMU_PLM_NVMSETID);       /* entry 1 */
    }
    if (off < sizeof(log)) {
        memcpy(buf, log + off, MIN(sizeof(log) - off, len));
    }
    status = dma_read_prp(n, buf, len, le64_to_cpu(cmd->dptr.prp1),
                          le64_to_cpu(cmd->dptr.prp2));
    /* qtest only: an entry that comes after the copy, as from the FTL */
    etyp = qatomic_xchg(&n->plm_st.after_copy, 0);
    if (etyp) {
        femu_plm_event(n, etyp);
    }
    if (!status && !rae) {
        nvme_clear_ns_events(n, NVME_AER_TYPE_NOTICE, NVME_LOG_PLM_EVENTS, 0,
                             true);
        /*
         * The FTL thread may add the entry after the copy above. Its
         * notice was just dropped, and the host did not see the entry:
         * send the notice again.
         */
        if (!(seen & FEMU_PLM_ENTRY) &&
            (qatomic_read(&n->plm_st.events) & FEMU_PLM_ENTRY) &&
            (qatomic_read(&n->features.async_config) & NVME_AEC_PLEA)) {
            nvme_enqueue_event(n, NVME_AER_TYPE_NOTICE, NVME_AER_INFO_PLEA,
                               NVME_LOG_PLM_EVENTS);
        }
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

/*
 * qtest only: the next log 0Bh read records these ETYP bits after its
 * copy and before it drops the queued notice, as the FTL thread may
 */
static void femu_plm_test_after_copy(Object *obj, Visitor *v,
                                     const char *name, void *opaque,
                                     Error **errp)
{
    FemuCtrl *n = FEMU(obj);
    uint32_t etyp;

    if (!visit_type_uint32(v, name, &etyp, errp)) {
        return;
    }
    if (!n->plm || (etyp & ~FEMU_PLM_ETYP)) {
        error_setg(errp, "x-plm-after-copy takes ETYP bits 0 to 2, 14 and "
                   "15 with plm=on");
        return;
    }
    qatomic_set(&n->plm_st.after_copy, etyp);
}

/*
 * qtest only: the FTL side of the window, "hold prep stalled free target
 * steps erases copies reclaims write-backs", read with the controller
 * paused
 */
static char *femu_plm_test_ftl(Object *obj, Error **errp)
{
    FemuCtrl *n = FEMU(obj);
    struct ssd *ssd = n->plm ? n->ssd : NULL;
    char *out;
    bool resume;

    if (!ssd || !ssd->plm) {
        error_setg(errp, "x-plm-ftl needs plm=on");
        return NULL;
    }
    resume = nvme_pause_pollers(n);
    out = g_strdup_printf("%d %d %d %d %d %" PRIu64 " %" PRIu64 " %" PRIu64
                          " %" PRIu64 " %" PRIu64,
                          ssd->plm_hold, ssd->plm_prep, ssd->plm_stalled,
                          ssd->lm.free_line_cnt, ssd->plm_lines,
                          ssd->plm_steps, ssd->total_erases,
                          ssd->gc_write_pages, ssd->read_reclaims,
                          ssd->buffer_bg_pages);
    nvme_resume_pollers(n, resume);
    return out;
}

/*
 * qtest only: set the NDWIN target past what plm_ndwin_lines allows, so
 * a test can reach the state where no step frees a line
 */
static void femu_plm_test_lines(Object *obj, Visitor *v, const char *name,
                                void *opaque, Error **errp)
{
    FemuCtrl *n = FEMU(obj);
    struct ssd *ssd = n->plm ? n->ssd : NULL;
    uint32_t lines;
    bool resume;

    if (!visit_type_uint32(v, name, &lines, errp)) {
        return;
    }
    if (!ssd || !ssd->plm || !lines ||
        lines > (uint32_t)ssd->sp.tt_lines) {
        error_setg(errp, "x-plm-lines takes 1 to the line count with plm=on");
        return;
    }
    resume = nvme_pause_pollers(n);
    ssd->plm_lines = lines;
    /* a new target may be in reach: try again */
    qatomic_set(&ssd->plm_stalled, false);
    nvme_resume_pollers(n, resume);
}

/*
 * qtest only: set DTWWT past the room of a full NDWIN, so a test can
 * write more in one DTWIN than plm_dtwin_writes allows
 */
static void femu_plm_test_dtwwt(Object *obj, Visitor *v, const char *name,
                                void *opaque, Error **errp)
{
    FemuCtrl *n = FEMU(obj);
    FemuPlm *pl = &n->plm_st;
    uint64_t dtwwt;
    bool resume;

    if (!visit_type_uint64(v, name, &dtwwt, errp)) {
        return;
    }
    if (!n->plm || !pl->unit || !dtwwt) {
        error_setg(errp, "x-plm-dtwwt takes 1 or more with plm=on");
        return;
    }
    resume = nvme_pause_pollers(n);
    pl->dtwwt = dtwwt;
    femu_plm_snap(n, false);
    nvme_resume_pollers(n, resume);
}

void femu_plm_add_props(Object *obj)
{
    object_property_add(obj, "x-plm-after-copy", "uint32", NULL,
                        femu_plm_test_after_copy, NULL, NULL);
    object_property_add(obj, "x-plm-dtwwt", "uint64", NULL,
                        femu_plm_test_dtwwt, NULL, NULL);
    object_property_add(obj, "x-plm-event", "uint32", NULL,
                        femu_plm_test_event, NULL, NULL);
    object_property_add_str(obj, "x-plm-ftl", femu_plm_test_ftl, NULL);
    object_property_add(obj, "x-plm-lines", "uint32", NULL,
                        femu_plm_test_lines, NULL, NULL);
}
