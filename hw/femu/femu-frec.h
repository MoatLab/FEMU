/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * The fault record ring of events_file: what each command line selected.
 *
 *   producer (FTL thread)               reader (main loop)
 *   ---------------------               ------------------
 *   id = ++next_id                      h = head (acquire)
 *   room? no  --> dropped, id range     for each stored record k < h:
 *         yes --> slot seq = 2k+1         s = seq; copy; s again
 *                 copy the record         s == 2k+2 both times? keep it
 *                 slot seq = 2k+2         else the producer took the slot
 *                 head = k+1 (release)
 *
 * The ring has a fixed size. With no consumer it is a window: the oldest
 * record gives way and counts as overwritten. With a consumer (events_log)
 * a full ring drops the new record, counts it and notes its id; the
 * consumer frees slots as it writes them out. Ids come from a counter of
 * their own, so a dropped record leaves a gap that a reader can name.
 *
 * One producer and one consumer at a time: a caller with several holds
 * its own lock around femu_fr_put(). The reader takes no lock, so a query
 * never stalls the FTL thread, and it may run beside the consumer.
 * Nothing here needs QEMU, so the unit test
 * (hw/femu/tests/unit/test-fsched.c) drives it alone.
 */
#ifndef FEMU_FREC_H
#define FEMU_FREC_H

#include "femu-fsched.h"

#define FEMU_FR_SLOTS_MIN       1u
#define FEMU_FR_SLOTS_MAX       65536u
#define FEMU_FR_SLOTS_DEF       4096u
#define FEMU_FR_INFO_MAX        4096u   /* records one query gives */
#define FEMU_FR_DROP_RANGES     16      /* dropped id ranges kept */
#define FEMU_FR_REC_MAX         256     /* bytes of one record, at most */
#define FEMU_FR_JSON_MAX        1024    /* bytes of one events_log line */

/* who made a record */
enum {
    FEMU_FR_ORIGIN_SCHED_CMD = 1,       /* a command line of events_file */
    FEMU_FR_ORIGIN_SCHED_TIME,          /* a time line: a power cut */
    FEMU_FR_ORIGIN_QMP,                 /* simulate-power-loss */
};

/* the step of a fault a record tells of */
enum {
    FEMU_FR_PHASE_SELECT = 1,           /* a line selected a command */
    FEMU_FR_PHASE_APPLY,                /* the FTL ran it: what came of it */
    FEMU_FR_PHASE_FAIL,                 /* wb-fail: a write-back met a mark */
    FEMU_FR_PHASE_REPORT,               /* wb-fail: a completion reports it */
    FEMU_FR_PHASE_SUPERSEDE,            /* wb-fail: a full rewrite cleared it */
    FEMU_FR_PHASE_RECLAIM,              /* a held command went back */
    FEMU_FR_PHASE_EVIDENCE,             /* power-loss: one chunk of ranges */
};

/* what came of the selection */
enum {
    FEMU_FR_OUT_SELECTED = 1,           /* the line won its group */
    FEMU_FR_OUT_SUPERSEDED,             /* an earlier line of its group won */
    FEMU_FR_OUT_NO_EFFECT,              /* won, but with no effect: see why */
    FEMU_FR_OUT_DONE,                   /* the effect took place */
    FEMU_FR_OUT_MARKED,                 /* wb-fail marked buffered pages */
    FEMU_FR_OUT_UNC,                    /* the lost blocks read as errors */
    FEMU_FR_OUT_OLD,                    /* the lost blocks read old data */
    FEMU_FR_OUT_REPORTED,               /* a completion carries the error */
    FEMU_FR_OUT_RECLAIMED,              /* a held command left with no CQE */
};

/* wb-fail: who met a failure (fail), or when (report) */
enum {
    FEMU_FR_FOUND_CMD = 1,              /* fail: the drain of a command */
    FEMU_FR_FOUND_BG,                   /* fail: a drain with no command */
    FEMU_FR_FOUND_SELF,                 /* report: this command's drain */
    FEMU_FR_FOUND_PENDING,              /* report: an earlier drain */
};

/*
 * One record, a fixed binary item. The fields a stage does not use stay
 * 0: cause names a parent record, and status the CQE status a later
 * report carries.
 */
typedef struct FemuFrRec {
    uint64_t id;                /* from 1, in the order of the records */
    uint64_t cause;             /* id of the parent record; 0 for none */
    uint64_t step;              /* commands the FTL thread took, this one too */
    uint64_t match;             /* matches of the line, this one too */
    uint64_t slba;              /* 0 for a Flush */
    uint32_t nlb;               /* blocks, from 1; 0 for a Flush */
    uint32_t nsid;
    uint16_t line;              /* in events_file, from 1 */
    uint16_t sqid;
    uint16_t cid;
    uint16_t status;
    uint8_t origin;             /* FEMU_FR_ORIGIN_* */
    uint8_t phase;              /* FEMU_FR_PHASE_* */
    uint8_t act;                /* FEMU_FS_ACT_* */
    uint8_t outcome;            /* FEMU_FR_OUT_* */
    /* FEMU_FS_WHY_*: for FEMU_FR_OUT_NO_EFFECT, or the reclaim path */
    uint8_t why;
    uint8_t opc;
    uint8_t fua;
    uint8_t found;              /* wb-fail fail and report: FEMU_FR_FOUND_* */
    /*
     * apply of a lie: the buffered pages that took the lie mark. For
     * flush-lie that is every page the Flush left in the buffer. apply
     * of wb-fail: the pages it marked.
     */
    uint32_t pages;
    uint16_t fslot;             /* wb-fail: the fault slot, from 1 */
    uint16_t lost;              /* wb-fail fail: the blocks it lost */
    union {
        /*
         * wb-fail fail: bit i for block slba + i that the failure lost.
         * It holds the first 64 blocks of the page; lost counts them all.
         */
        uint64_t lba_mask;
        /* delay apply: the ms of the line, which a "done" added */
        uint32_t delay_ms;
        /* power-loss apply: the cut summary */
        struct {
            uint64_t cqe_boundary;      /* I/O CQEs posted at the fence */
            uint64_t ranges;
            uint32_t kept_pages;
            uint32_t rolled_back_pages;
            uint32_t rolled_back_lie_pages;
            uint8_t chunks;
            bool truncated;
        } cut;
        /* power-loss evidence: one chunk, its cause the summary */
        struct {
            uint8_t idx;                /* from 0 */
            uint8_t total;              /* the chunks of the cut */
            uint8_t kind;               /* FEMU_FS_KIND_* */
            uint8_t nr;                 /* ranges in @r */
            FemuFsRange r[FEMU_FS_CUT_RANGES];
        } chunk;
    };
} FemuFrRec;

_Static_assert(sizeof(FemuFrRec) <= FEMU_FR_REC_MAX,
               "a fault record fits its 256-byte limit");
_Static_assert(sizeof(FemuFrRec) % sizeof(uint64_t) == 0,
               "a fault record moves as whole 64-bit words");

#define FEMU_FR_WORDS   (sizeof(FemuFrRec) / sizeof(uint64_t))

/* 216 bytes: the record as atomic words, and its sequence word */
typedef struct FemuFrSlot {
    uint64_t seq;               /* 2k+1 while record k is written, then 2k+2 */
    uint64_t w[FEMU_FR_WORDS];
} FemuFrSlot;

/* dropped ids lo to hi, both included */
typedef struct FemuFrIdRange {
    uint64_t lo;
    uint64_t hi;
} FemuFrIdRange;

typedef struct FemuFrRing {
    FemuFrSlot *slot;
    uint32_t size;
    bool window;                /* no consumer: the oldest record gives way */

    /* written by the producer, read by anyone with atomic loads */
    uint64_t next_id;           /* the last id given */
    uint64_t head;              /* records stored, ever */
    uint64_t dropped;
    uint64_t overwritten;
    uint32_t nr_drop;           /* ranges in @drop */
    FemuFrIdRange drop[FEMU_FR_DROP_RANGES];

    /* written by the consumer: records before it are free */
    uint64_t tail;
} FemuFrRing;

/**
 * femu_fr_init - set up an empty ring
 * @r: the ring
 * @slot: @size zeroed slots, which the caller owns
 * @size: FEMU_FR_SLOTS_MIN to FEMU_FR_SLOTS_MAX
 * @window: true when no consumer frees slots
 */
void femu_fr_init(FemuFrRing *r, FemuFrSlot *slot, uint32_t size,
                  bool window);

/**
 * femu_fr_put - give a record an id and store it, or count it dropped
 * @r: the ring
 * @rec: the record; femu_fr_put() sets its id
 *
 * Never waits. Only one producer may run at a time.
 *
 * Returns the id, which a child record names as its cause whether this
 * record was stored or dropped.
 */
uint64_t femu_fr_put(FemuFrRing *r, FemuFrRec *rec);

/**
 * femu_fr_read - copy the records the ring holds now, oldest first
 * @r: the ring
 * @out: room for @max records
 * @max: at most this many, the newest kept
 *
 * Safe while the producer runs. A record the producer overwrites during
 * the copy is left out, never returned torn.
 *
 * Returns the number of records in @out, in id order.
 */
uint32_t femu_fr_read(const FemuFrRing *r, FemuFrRec *out, uint32_t max);

/**
 * femu_fr_pop - take the oldest record a consumer has not freed
 * @r: a ring with a consumer (not a window)
 * @out: the record
 *
 * The one consumer calls it; the slot is free for the producer after.
 *
 * Returns false when the ring is empty.
 */
bool femu_fr_pop(FemuFrRing *r, FemuFrRec *out);

/**
 * femu_fr_peek - copy the oldest record a consumer has not freed
 * @r: a ring with a consumer (not a window)
 * @out: the record
 *
 * The slot stays taken until femu_fr_release(), so a consumer can write
 * the record out before a reader stops seeing it.
 *
 * Returns false when the ring is empty.
 */
bool femu_fr_peek(const FemuFrRing *r, FemuFrRec *out);

/**
 * femu_fr_release - free the slot of the record femu_fr_peek() copied
 * @r: a ring with a consumer, not empty
 */
void femu_fr_release(FemuFrRing *r);

/**
 * femu_fr_pending - records a consumer has not taken yet
 * @r: a ring with a consumer (not a window)
 */
uint64_t femu_fr_pending(const FemuFrRing *r);

/**
 * femu_fr_dropped_ids - the first dropped id ranges
 * @r: the ring
 * @out: room for FEMU_FR_DROP_RANGES ranges
 *
 * Returns the number of ranges in @out.
 */
uint32_t femu_fr_dropped_ids(const FemuFrRing *r, FemuFrIdRange *out);

/**
 * femu_fr_name_origin - the name of a FEMU_FR_ORIGIN_* value
 * @v: the value
 */
const char *femu_fr_name_origin(uint8_t v);

/**
 * femu_fr_name_phase - the name of a FEMU_FR_PHASE_* value
 * @v: the value
 */
const char *femu_fr_name_phase(uint8_t v);

/**
 * femu_fr_name_outcome - the name of a FEMU_FR_OUT_* value
 * @v: the value
 */
const char *femu_fr_name_outcome(uint8_t v);

/**
 * femu_fr_name_found - the name of a FEMU_FR_FOUND_* value
 * @v: the value
 */
const char *femu_fr_name_found(uint8_t v);

/**
 * femu_fr_name_why - the name of a FEMU_FS_WHY_* reason
 * @v: the value, not FEMU_FS_WHY_NONE
 */
const char *femu_fr_name_why(uint8_t v);

/**
 * femu_fr_name_kind - the name of a FEMU_FS_KIND_* value of cut evidence
 * @v: the value
 */
const char *femu_fr_name_kind(uint8_t v);

/**
 * femu_fr_json - one record as a JSON line for events_log
 * @rec: the record
 * @buf: the line, with a newline and a NUL
 * @len: the size of @buf, FEMU_FR_JSON_MAX is enough
 *
 * Returns the length of the line, without the NUL.
 */
int femu_fr_json(const FemuFrRec *rec, char *buf, size_t len);

#endif
