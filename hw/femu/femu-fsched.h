/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Command lines of events_file: the grammar and the matcher.
 *
 *   @<match>#N <action> [options]          the Nth matching command
 *   @<match>%PPM~SEED <action> [options]   each match, with odds PPM
 *   <match> = <op>[,ns=<nsid>][,lba=<a>-<b>]
 *
 * The code here needs no QEMU: the caller gives the device facts and a
 * decoded view of each command, so a unit test can drive it alone.
 */
#ifndef FEMU_FSCHED_H
#define FEMU_FSCHED_H

#define FEMU_FS_PPM_ONE     1000000u
#define FEMU_FS_ERR_LEN     160
#define FEMU_FS_DELAY_MAX   600000u     /* ms, ten minutes */
#define FEMU_FS_SEED_MAX    ((uint64_t)INT64_MAX)
#define FEMU_FS_ACT_LEN     48          /* longest ana= or slow= token */

/* NVMe opcodes of the commands a line can match */
#define FEMU_FS_OPC_FLUSH   0x00
#define FEMU_FS_OPC_WRITE   0x01
#define FEMU_FS_OPC_READ    0x02
#define FEMU_FS_OPC_WZERO   0x08

enum {
    FEMU_FS_OP_ANY,
    FEMU_FS_OP_READ,
    FEMU_FS_OP_WRITE,
    FEMU_FS_OP_FUA,
    FEMU_FS_OP_FLUSH,
    FEMU_FS_OP_WZERO,
};

enum {
    FEMU_FS_ACT_POWER_LOSS,
    FEMU_FS_ACT_CFS,
    FEMU_FS_ACT_HANG,
    FEMU_FS_ACT_WRITE_FAIL,
    FEMU_FS_ACT_WB_FAIL,
    FEMU_FS_ACT_FUA_LIE,
    FEMU_FS_ACT_READ_UNC,
    FEMU_FS_ACT_FLUSH_LIE,
    FEMU_FS_ACT_SDC,
    FEMU_FS_ACT_DELAY,
    FEMU_FS_ACT_SLOW,
    FEMU_FS_ACT_ANA,
    FEMU_FS_ACT_NR,
};

/* the lines of a group compete: the first selected one in file order wins */
enum {
    FEMU_FS_GRP_TERMINAL,
    FEMU_FS_GRP_DATA,
    FEMU_FS_GRP_SDC,
    FEMU_FS_GRP_TIMING,
    FEMU_FS_GRP_NONE,           /* each selected line applies */
    FEMU_FS_GRP_NR,
};

/* what one command did to one line */
enum {
    FEMU_FS_OUT_NONE,           /* no match, or matched but not selected */
    FEMU_FS_OUT_APPLIED,
    FEMU_FS_OUT_SUPERSEDED,     /* an earlier line of its group won */
    FEMU_FS_OUT_NO_EFFECT,      /* won, but the command does not allow it */
};

/* why a winner has no effect, for its record */
enum {
    FEMU_FS_WHY_NONE,
    FEMU_FS_WHY_FUA,            /* the original command has FUA */
    FEMU_FS_WHY_PRE,            /* a cut or cfs at pre: no command runs */
    FEMU_FS_WHY_HANG,           /* a hang won: no CQE comes to delay */
    FEMU_FS_WHY_PLP,            /* working plp: the buffer is power safe */
    FEMU_FS_WHY_ATOMIC,         /* an awupf transaction programs directly */
    FEMU_FS_WHY_NO_BUFFER,      /* the write buffer takes no write now */
    FEMU_FS_WHY_CMD_FAILED,     /* the command failed after the match */
    FEMU_FS_WHY_DURABLE,        /* no buffered page is left volatile */
    FEMU_FS_WHY_SLOTS_FULL,     /* wb-fail: every fault slot is taken */
    FEMU_FS_WHY_MARKED,         /* wb-fail: its pages carry an older mark */
    FEMU_FS_WHY_NOT_MODELLED,   /* ana= and slow= act on time lines only */
    FEMU_FS_WHY_OUTSIDE,        /* sdc: its block is not one the Write puts */
    /* reclaim: what gave back a command that a hang or a cfs holds */
    FEMU_FS_WHY_SQ_DELETED,     /* Delete I/O Submission Queue */
    FEMU_FS_WHY_RESET,          /* Controller Reset (CC.EN to 0) */
    FEMU_FS_WHY_SHUTDOWN,       /* a shutdown (CC.SHN) */
    FEMU_FS_WHY_POWER_CUT,      /* simulate-power-loss */
    FEMU_FS_WHY_UNPLUG,         /* device_del, or QEMU exit */
};

/* what the FTL did with a command that a lie selected */
typedef struct FemuFsLie {
    uint8_t act;                /* FEMU_FS_ACT_FLUSH_LIE or _FUA_LIE */
    bool failed;                /* the command did not succeed */
    bool plp;                   /* plp works */
    bool buffer;                /* the write buffer takes writes */
    bool atomic;                /* fua-lie: the write was a transaction */
    uint32_t pages;             /* buffered pages the lie leaves volatile */
} FemuFsLie;

/*
 * wb-fail state. A fault slot holds one selection: the Write as the line
 * saw it, kept apart from the request, which the queue reuses. A failure
 * is one marked page that a write-back met. It is pending until a
 * completion reports it, reserved while that completion waits to post,
 * and gone when report=once posts it. report=sticky keeps it pending
 * until a Controller Reset.
 *
 *   pending --(collect)--> reserved --(CQE posted, once)--> gone
 *      ^                       |
 *      +---(CQE dropped)-------+
 *
 * The caller holds one lock around every call here.
 */
#define FEMU_WB_SLOTS       256     /* live fault slots of a controller */
#define FEMU_WB_SC_WF       0x0280  /* Write Fault (SCT 2h, SC 80h) */
#define FEMU_WB_SC_INTERNAL 0x0006  /* Internal Error (SCT 0h, SC 06h) */
#define FEMU_WB_SC_DNR      0x4000

enum { FEMU_WB_PENDING = 1, FEMU_WB_RESERVED };

typedef struct FemuWbSlot {
    uint32_t refs;              /* 0: free; selection, marks and failures */
    uint8_t mode;               /* FEMU_FS_WB_* */
    uint8_t report;             /* FEMU_FS_REPORT_* */
    bool aer;
    uint16_t line;
    uint16_t sqid;
    uint16_t cid;
    uint32_t nsid;
    uint32_t nlb;
    uint64_t slba;
    uint64_t match;
    uint64_t sel_id;            /* id of its select record */
    uint32_t marked;            /* pages it marked */
    bool skipped;               /* a page it wrote kept an older mark */
} FemuWbSlot;

typedef struct FemuWbFail {
    uint16_t slot;              /* index into FemuWbTab.slot */
    uint8_t state;              /* FEMU_WB_PENDING or FEMU_WB_RESERVED */
    uint8_t report;             /* FEMU_FS_REPORT_* of its slot */
    uint32_t nsid;
    uint32_t lbas;              /* the blocks of the page */
    uint64_t page_slba;         /* the first block of the page */
    uint64_t fail_id;           /* id of its fail record */
    uint64_t found;             /* stamp of the drain that met it */
    uint64_t tok;               /* the completion that holds or reported it */
} FemuWbFail;

typedef struct FemuWbTab {
    FemuWbSlot slot[FEMU_WB_SLOTS];
    FemuWbFail *fail;
    uint32_t nr;
    uint32_t cap;               /* the caller grows @fail before an add */
} FemuWbTab;

enum { FEMU_FS_GRAIN_PAGE, FEMU_FS_GRAIN_LBA };
enum { FEMU_FS_WB_UNC, FEMU_FS_WB_OLD };
enum { FEMU_FS_REPORT_STICKY, FEMU_FS_REPORT_ONCE };
enum { FEMU_FS_SDC_FLIP = 1, FEMU_FS_SDC_LOST, FEMU_FS_SDC_MISDIRECT };

/*
 * A power-loss command line at its cut. keep=PPM writes back each
 * buffered page (grain=page) or block (grain=lba) with odds PPM before
 * the rest rolls back; the draws run in buffer order from the line's
 * own splitmix64 stream. The evidence is the blocks each fate took, as
 * ranges, packed into chunk records of one kind each, rolled back
 * first. The ranges of a kind are sorted by (nsid, slba), and ranges
 * that touch or overlap merge, so the order is not buffer order:
 *
 *   buffer:   p0 K   p2 R   p1 R   p3 K      (K kept, R rolled back)
 *   ranges:   rolled back [p1..p2]   kept [p0] [p3]
 *   chunks:   0: rolled_back, 1 range   1: kept, 2 ranges
 *
 * At most FEMU_FS_CUT_CHUNKS chunks of FEMU_FS_CUT_RANGES ranges are
 * kept. A full store of one kind merges before it drops a range. A cut
 * that drops a range sets @truncated.
 */
#define FEMU_FS_CUT_RANGES  8
#define FEMU_FS_CUT_CHUNKS  8
#define FEMU_FS_CUT_MAX     (FEMU_FS_CUT_RANGES * FEMU_FS_CUT_CHUNKS)

enum { FEMU_FS_KIND_ROLLED_BACK, FEMU_FS_KIND_KEPT, FEMU_FS_KINDS };

/* 16 bytes: one range of the cut evidence */
typedef struct FemuFsRange {
    uint64_t slba;
    uint32_t nlb;
    uint16_t nsid;
    uint8_t kind;               /* FEMU_FS_KIND_* */
    uint8_t pad;
} FemuFsRange;

_Static_assert(sizeof(FemuFsRange) == 16, "a cut range is 16 bytes");

typedef struct FemuFsCut {
    uint32_t keep;              /* PPM of the line */
    uint8_t grain;              /* FEMU_FS_GRAIN_* */
    uint64_t *rng;              /* the line's draw state, which moves on */

    uint32_t kept_pages;        /* pages written back, whole or in part */
    uint32_t rolled_back_pages; /* pages with a block rolled back */
    uint32_t rolled_back_lie_pages; /* of those, pages a lie called durable */
    uint64_t ranges;            /* merged ranges plus dropped ones */
    uint64_t dropped;           /* ranges with no room after a merge */
    bool partial;               /* durable_at_done gave back pages too */
    uint32_t nr[FEMU_FS_KINDS]; /* the ranges stored in @r */
    bool open[FEMU_FS_KINDS];   /* @cur holds a range that can still grow */
    FemuFsRange cur[FEMU_FS_KINDS];
    FemuFsRange r[FEMU_FS_KINDS][FEMU_FS_CUT_MAX];
} FemuFsCut;

/**
 * femu_fs_cut_draw - draw the fate of each block of one buffered page
 * @c: the cut; with no @rng it keeps no block and draws nothing
 * @keep: out: one byte per block, 1 when it is written back
 * @lbas: the blocks of the page
 *
 * grain=page takes one draw for the page, grain=lba one for each block.
 *
 * Returns the blocks kept.
 */
uint32_t femu_fs_cut_draw(FemuFsCut *c, uint8_t *keep, uint32_t lbas);

/**
 * femu_fs_cut_page - note what became of one buffered page
 * @c: the cut
 * @nsid: its namespace
 * @slba: its first block
 * @keep: the draws of femu_fs_cut_draw(), or NULL when all rolled back
 * @lbas: its blocks
 * @lie: a lie called the page durable
 *
 * Call it in buffer order, after the write-back. A page whose write-back
 * failed passes NULL: none of its blocks was kept. A full store of one
 * kind sorts and merges its ranges before it drops one.
 */
void femu_fs_cut_page(FemuFsCut *c, uint16_t nsid, uint64_t slba,
                      const uint8_t *keep, uint32_t lbas, bool lie);

/**
 * femu_fs_cut_end - close the last ranges once every page is noted
 * @c: the cut
 *
 * Sorts the ranges of each kind by (nsid, slba) and merges the ones that
 * touch or overlap, then sets @ranges to the merged count plus the
 * dropped ones.
 *
 * Returns the chunks to write, and sets *@truncated when the ranges do
 * not fit them, when a range was dropped, or when @partial says the
 * ranges miss some pages.
 */
uint32_t femu_fs_cut_end(FemuFsCut *c, bool *truncated);

/**
 * femu_fs_cut_chunk - the ranges of one chunk
 * @c: the cut, after femu_fs_cut_end()
 * @i: the chunk, from 0
 * @out: room for FEMU_FS_CUT_RANGES ranges
 *
 * Returns the ranges in @out, all of the same kind, in (nsid, slba)
 * order. They are not in buffer order.
 */
uint32_t femu_fs_cut_chunk(const FemuFsCut *c, uint32_t i, FemuFsRange *out);

/* the device facts that decide which lines realize accepts */
typedef struct FemuFsDev {
    bool bbssd;
    bool ns_mgmt;
    bool namespace_modes;
    bool subsys;
    bool shared_ftl;
    bool cxl_ssd;
    bool power_loss;
    bool vwc;
    bool durable_at_done;
    bool fdp;
    bool buffer_low;            /* buffer_low_pcent set */
    bool sdc;
    uint32_t awupf_lbas;
    uint32_t nr_ns;             /* namespace ids 1 to nr_ns */
    const uint64_t *nsze;       /* blocks of namespace i + 1; 0 for none */
} FemuFsDev;

/* a command as the line sees it: the SQE copy, never guest memory */
typedef struct FemuFsView {
    uint8_t opc;
    bool fua;                   /* a Write with CDW12 bit 30 */
    uint32_t nsid;
    uint64_t slba;
    uint32_t nlb;               /* blocks, from 1 */
} FemuFsView;

typedef struct FemuFsLine {
    int line;                   /* in the file, from 1 */
    uint8_t op;
    uint8_t act;
    uint8_t grp;
    bool ppm_trigger;           /* %PPM~SEED, else #N */
    bool has_ns;
    bool has_lba;
    uint32_t nsid;
    uint64_t lba_lo;
    uint64_t lba_hi;
    uint64_t nth;
    uint32_t ppm;
    uint64_t seed;
    uint64_t rng;               /* FTL thread only */

    /* options of the action, checked and kept for the action */
    bool has_keep;
    uint32_t keep;
    uint8_t grain;
    uint64_t keep_seed;
    uint64_t keep_rng;          /* main loop: the keep= draw state */
    uint8_t wb_mode;
    uint8_t wb_report;
    bool wb_aer;
    uint8_t sdc_kind;
    bool has_sdc_lba;
    uint64_t sdc_lba;
    uint32_t delay_ms;
    char action[FEMU_FS_ACT_LEN];   /* the ana= or slow= token */

    /*
     * Written by the FTL thread alone and read by the main loop, so they
     * move with relaxed atomic stores and are read with atomic loads.
     */
    uint64_t matched;
    uint64_t selected;          /* applied + superseded + no_effect */
    uint64_t applied;
    uint64_t superseded;
    uint64_t no_effect;
    /*
     * A #N line has selected once. A flag apart from @matched, which may
     * wrap: a wrap must not make the Nth match come round again.
     */
    bool done;
} FemuFsLine;

/*
 * The sdc override of one Write. The FTL thread installs the Write a page
 * at a time; femu_sdc_fault() runs the x-sdc slot and the sdc_ppm draws
 * of each install as without the override, so their sequence stays the
 * same, then asks here. The install that holds @lba takes the override
 * in place of what they gave, once:
 *
 *   install [s, e) --> x-sdc slot, draws --> kind K, block B
 *              @lba in [s, e), not hit? --> kind @kind, block @lba;
 *                                           @was_kind = K, @was_lba = B
 */
typedef struct FemuFsSdc {
    const void *req;            /* the Write; no other request takes it */
    uint8_t kind;               /* FEMU_FS_SDC_* */
    uint64_t lba;               /* the block it spoils */
    bool hit;                   /* an install took it */
    uint8_t was_kind;           /* the fault it replaced, 0 for none */
    uint64_t was_lba;           /* the block of that fault */
} FemuFsSdc;

/**
 * femu_fs_sdc_set - prepare the override of a Write that an sdc line won
 * @o: the override
 * @l: the line
 * @v: the Write as the line saw it
 * @req: the request of the Write
 *
 * The block is lba= of the line, or the first block of the Write.
 */
void femu_fs_sdc_set(FemuFsSdc *o, const FemuFsLine *l, const FemuFsView *v,
                     const void *req);

/**
 * femu_fs_sdc_take - the fault one page install takes, with the override
 * @o: the override
 * @slba: the first block of the install
 * @elba: the block after its last
 * @kind: in, the fault the slot or the draws gave, 0 for none; out, the
 *        fault the install takes
 * @lba: in and out, the same for the block a flip spoils
 *
 * Returns true when the install takes the override.
 */
bool femu_fs_sdc_take(FemuFsSdc *o, uint64_t slba, uint64_t elba, int *kind,
                      uint64_t *lba);

/**
 * femu_fs_draw - the next draw of a splitmix64 stream, 0 to 999999
 * @rng: the state, advanced by one
 *
 * A line with odds PPM selects a match when its draw is below PPM, so
 * PPM 0 never selects and PPM 1000000 always does.
 */
uint32_t femu_fs_draw(uint64_t *rng);

/**
 * femu_fs_splitmix64 - one step of splitmix64
 * @x: the state, advanced by one
 *
 * The time windows of events_file draw from the same generator.
 */
uint64_t femu_fs_splitmix64(uint64_t *x);

/**
 * femu_fs_parse - check one command line and compile it
 * @dev: the facts of the device being realized
 * @s: the line, stripped, starting with '@'
 * @lineno: its line number in the file
 * @l: the compiled line
 * @err: the reason for a refused line
 * @errlen: the size of @err
 *
 * An ana= or slow= action comes back with its token in @l->action; the
 * caller checks it against the device as for a time line.
 *
 * Returns true for an accepted line.
 */
bool femu_fs_parse(const FemuFsDev *dev, const char *s, int lineno,
                   FemuFsLine *l, char *err, size_t errlen);

/**
 * femu_fs_xfer_ms - metadata bytes per block that count toward MDTS
 * @ms: the metadata size of the format in use
 * @extended: the format interleaves metadata with the data
 * @pi_type: the protection type of the namespace, 0 for none
 * @pi_size: the size of one protection tuple
 * @pract: the command sets PRACT
 *
 * As the Read and Write handler counts it: extended metadata moves with
 * the data, except where PRACT makes the controller insert or strip a
 * metadata area that is only the tuple.
 */
uint32_t femu_fs_xfer_ms(uint16_t ms, bool extended, uint8_t pi_type,
                         uint16_t pi_size, bool pract);

/**
 * femu_fs_view_ok - the checks a command passes before a line sees it
 * @v: the view, of an opcode in the set and an attached namespace
 * @nsze: the blocks of that namespace
 * @lbads: log2 of its block size
 * @xfer_ms: metadata bytes per block in the transfer (femu_fs_xfer_ms())
 * @mdts_shift: log2 of the transfer limit in bytes; 0 for no limit
 *
 * A Flush has no range. A Read or Write also stays within MDTS.
 */
bool femu_fs_view_ok(const FemuFsView *v, uint64_t nsze, unsigned lbads,
                     uint32_t xfer_ms, unsigned mdts_shift);

/**
 * femu_fs_act_name - the name of an action, as a line gives it
 * @act: a FEMU_FS_ACT_*
 */
const char *femu_fs_act_name(uint8_t act);

/**
 * femu_fs_match - run one checked command through every line
 * @l: the lines, in file order
 * @nr: their number
 * @v: the view of the command, which no action changes
 * @out: one FEMU_FS_OUT_* per line
 * @why: one FEMU_FS_WHY_* per line, set for FEMU_FS_OUT_NO_EFFECT; or NULL
 * @eff: the command as the winning actions leave it
 *
 * Each matching line counts the match and draws, in file order. In each
 * group the first selected line wins; a later one is superseded. A winner
 * that the original command does not allow has no effect. A power-loss
 * or cfs winner leaves every other winner with no effect, and a hang
 * winner does that to a delay.
 */
void femu_fs_match(FemuFsLine *l, int nr, const FemuFsView *v,
                   uint8_t *out, uint8_t *why, FemuFsView *eff);

/**
 * femu_fs_terminal - the terminal action a command runs
 * @l: the lines, in file order
 * @nr: their number
 * @out: the outcomes femu_fs_match() gave
 *
 * The terminal group has one winner at most. A superseded line or one
 * with no effect does not count.
 *
 * Returns FEMU_FS_ACT_POWER_LOSS, FEMU_FS_ACT_CFS or FEMU_FS_ACT_HANG,
 * or FEMU_FS_ACT_NR for none.
 */
uint8_t femu_fs_terminal(const FemuFsLine *l, int nr, const uint8_t *out);

/**
 * femu_fs_lie_why - why a selected lie had no effect
 * @s: what the FTL did with the command
 *
 * A lie needs a successful command, a write buffer that plp does not
 * protect, and a buffered page it leaves volatile: for flush-lie any
 * page in the buffer, for fua-lie a page of the write.
 *
 * Returns FEMU_FS_WHY_NONE when the lie had its effect.
 */
uint8_t femu_fs_lie_why(const FemuFsLie *s);

/**
 * femu_wb_slot_get - take a free fault slot
 * @t: the table
 *
 * The slot comes back zeroed with one reference, the selection's, which
 * the caller drops once the command has run.
 *
 * Returns its index, or -1 when every slot is taken.
 */
int femu_wb_slot_get(FemuWbTab *t);

/**
 * femu_wb_slot_put - drop one reference of a slot
 * @t: the table
 * @s: the slot
 *
 * The last reference frees the slot.
 */
void femu_wb_slot_put(FemuWbTab *t, int s);

/**
 * femu_wb_fail_add - note that a write-back met a marked page
 * @t: the table, with room for one more failure
 * @f: the failure; its state becomes pending
 *
 * The failure takes over the reference that the page's mark held.
 */
void femu_wb_fail_add(FemuWbTab *t, const FemuWbFail *f);

/**
 * femu_wb_pending - whether a drain of @nsid has a failure to report
 * @t: the table
 * @nsid: the namespace, or 0 for all
 *
 * A failure that another completion holds is not this drain's to report.
 */
bool femu_wb_pending(const FemuWbTab *t, uint32_t nsid);

/**
 * femu_wb_collect - the failures one draining completion reports
 * @t: the table
 * @nsid: the namespace, or 0 for all
 * @tok: the completion, never 0; each failure it reports gets it
 * @admin: an Admin command, which reports Internal Error
 * @held: set when the completion now holds a report=once failure
 *
 * Every pending failure of @nsid is reported. A report=once failure is
 * then reserved for @tok, so no other completion reports it. A sticky
 * one stays pending and sets DNR, since a retry fails too.
 *
 * Returns the status, Write Fault for I/O or Internal Error for Admin,
 * with DNR for a sticky failure; 0 when there is nothing to report.
 */
uint16_t femu_wb_collect(FemuWbTab *t, uint32_t nsid, uint64_t tok,
                         bool admin, bool *held);

/**
 * femu_wb_publish - the completion @tok posted: consume what it holds
 * @t: the table
 * @tok: the completion
 *
 * Returns the failures consumed.
 */
uint32_t femu_wb_publish(FemuWbTab *t, uint64_t tok);

/**
 * femu_wb_unreserve - the completion @tok will never post
 * @t: the table
 * @tok: the completion
 *
 * What it held is pending again, for the next draining completion.
 *
 * Returns the failures returned.
 */
uint32_t femu_wb_unreserve(FemuWbTab *t, uint64_t tok);

/**
 * femu_wb_clear - drop every failure
 * @t: the table
 * @slots: also free every slot, which no buffered page names any more
 */
void femu_wb_clear(FemuWbTab *t, bool slots);

/**
 * femu_wb_lba_lost - whether a failed write-back loses block @i of a page
 * @now: the bytes of the page in the buffer
 * @undo: the bytes of the page on the media
 * @st_now: the state of each block now (written, uncorrectable, sdc)
 * @st_undo: the state of each block on the media
 * @i: the block
 * @lba_bytes: the bytes of a block
 *
 * A block that a buffered write changed loses that version. A block no
 * buffered write changed keeps its data.
 */
bool femu_wb_lba_lost(const uint8_t *now, const uint8_t *undo,
                      const uint8_t *st_now, const uint8_t *st_undo,
                      uint32_t i, uint32_t lba_bytes);

/**
 * femu_wb_apply_why - why a selected wb-fail marked no page
 * @slot: it got a fault slot
 * @failed: the Write failed
 * @buffer: the write buffer took writes
 * @atomic: the Write was one awupf transaction
 * @marked: a page of the Write already had a mark
 * @pages: the pages it marked
 *
 * Returns FEMU_FS_WHY_NONE when it marked a page.
 */
uint8_t femu_wb_apply_why(bool slot, bool failed, bool buffer, bool atomic,
                          bool marked, uint32_t pages);

/*
 * When a schedule runs. events_start=enable starts it at the first
 * enable, events_start=qmp at femu-events-start. A stop freezes the
 * time: on a resume the epoch moves on by the time the stop lasted, so
 * a time line still runs that long after the start, not counting the
 * stop. The caller keeps the match counts frozen while it is stopped.
 *
 *   WAITING --start--> RUNNING --stop--> STOPPED --start--> RUNNING
 */
typedef struct FemuFsRun {
    bool started;
    bool stopped;
    int64_t epoch;              /* ns: the times count from here */
    int64_t stop_at;            /* ns: when the stop came */
} FemuFsRun;

/* what femu_fs_run_start() and femu_fs_run_stop() return */
enum {
    FEMU_FS_RUN_OK,
    FEMU_FS_RUN_RUNNING,        /* start: it already runs */
    FEMU_FS_RUN_WAITING,        /* stop: it has not started */
    FEMU_FS_RUN_STOPPED,        /* stop: it is stopped already */
};

/**
 * femu_fs_run_start - start a waiting schedule, or resume a stopped one
 * @r: the schedule
 * @now: the time now, in ns, of a clock that never goes back
 *
 * Returns FEMU_FS_RUN_OK, or FEMU_FS_RUN_RUNNING with @r unchanged.
 */
int femu_fs_run_start(FemuFsRun *r, int64_t now);

/**
 * femu_fs_run_stop - stop a running schedule
 * @r: the schedule
 * @now: the time now, on the clock of femu_fs_run_start()
 *
 * Returns FEMU_FS_RUN_OK, or FEMU_FS_RUN_WAITING or FEMU_FS_RUN_STOPPED
 * with @r unchanged.
 */
int femu_fs_run_stop(FemuFsRun *r, int64_t now);

/**
 * femu_fs_done - whether no line can select again
 * @l: the lines
 * @nr: their number
 *
 * Each #N line has selected and no line has odds.
 */
bool femu_fs_done(const FemuFsLine *l, int nr);

#endif
