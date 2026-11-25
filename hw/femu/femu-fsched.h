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

enum { FEMU_FS_GRAIN_PAGE, FEMU_FS_GRAIN_LBA };
enum { FEMU_FS_WB_UNC, FEMU_FS_WB_OLD };
enum { FEMU_FS_REPORT_STICKY, FEMU_FS_REPORT_ONCE };
enum { FEMU_FS_SDC_FLIP = 1, FEMU_FS_SDC_LOST, FEMU_FS_SDC_MISDIRECT };

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
 * femu_fs_match - run one checked command through every line
 * @l: the lines, in file order
 * @nr: their number
 * @v: the view of the command, which no action changes
 * @out: one FEMU_FS_OUT_* per line
 * @eff: the command as the winning actions leave it
 *
 * Each matching line counts the match and draws, in file order. In each
 * group the first selected line wins; a later one is superseded. A winner
 * that the original command does not allow has no effect. A power-loss
 * or cfs winner leaves every other winner with no effect, and a hang
 * winner does that to a delay.
 */
void femu_fs_match(FemuFsLine *l, int nr, const FemuFsView *v,
                   uint8_t *out, FemuFsView *eff);

/**
 * femu_fs_done - whether no line can select again
 * @l: the lines
 * @nr: their number
 *
 * Each #N line has selected and no line has odds.
 */
bool femu_fs_done(const FemuFsLine *l, int nr);

#endif
