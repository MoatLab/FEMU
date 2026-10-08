# The BlackBox FTL

This chapter describes the flash translation layer (FTL) behind BlackBox mode
(`femu_mode=1`): how it maps logical pages to NAND pages, how it organises
NAND into lines and write pointers, how it collects garbage, and how its
write buffer, read cache, wear and refresh models work. It is written for
readers who want to know what the model does, where its time goes, and how
to change it. To run the mode, read the [BlackBox guide](../modes/blackbox.md)
first; this chapter does not repeat its launch and guest steps.

The code lives in `hw/femu/bbssd/`. The same FTL serves CSD namespaces, which
build it through the same `ssd_init()`. KV namespaces call `ssd_init()` for
the geometry and NAND timing but run their own key-value FTL. A
`femu-cxl-ssd` builds a private instance on its own worker thread.

NAND operation timing (per-LUN timelines, the channel bus, suspend, ECC
tiers) is the subject of the [NAND timing chapter](nand-timing.md) in this
directory, and of [the timing model](../concepts/timing-model.md). This
chapter covers what the FTL asks of the NAND, not how long each operation
takes.

## Place in the hierarchy

```text
  guest NVMe driver
        |  SQ doorbell
        v
  +---------------------------+   copies the payload between guest memory
  | femu-poller thread(s)     |   and the host memory backend, then hands
  |  nvme_rw(), nvme_dsm(),...|   every I/O request to the FTL ring
  +---------------------------+
        |  to_ftl[i]                       ^ to_poller[i]
        v                                  |
  +---------------------------------------------------------------+
  | FEMU-FTL-Thread: femu_ftl_thread() -> bb_ftl_process_req()    |
  |                                                               |
  |   +-------------+  +--------------+  +----------------------+ |
  |   | mapping     |  | write buffer |  | read cache           | |
  |   | page, dftl, |  | (LPNs, LRU)  |  | (LPNs, timing only)  | |
  |   | hybrid,fast |  +--------------+  +----------------------+ |
  |   +-------------+                                             |
  |   +---------------------------------------------------------+ |
  |   | line management, write pointers, GC, read reclaim       | |
  |   +---------------------------------------------------------+ |
  +---------------------------------------------------------------+
        |  ssd_advance_status(): one read, program or erase
        v
  +---------------------------------------------------------------+
  | NAND media layer (hw/femu/nand/nand-media.c)                  |
  |   per-LUN next-available times, optional channel bus          |
  +---------------------------------------------------------------+
```

Two things follow from this picture.

- **The FTL models time and placement, not data.** The poller copies the
  payload to the host memory backend before the request reaches the FTL. The
  FTL tracks which NAND page each logical page would occupy and how long each
  operation takes, but it never stores the payload. The one exception is the
  power-loss model (`power_loss=on`), which runs the data copy on the FTL
  thread and keeps undo copies of buffered pages; see
  [Power loss](#power-loss).
- **The FTL returns a duration.** Each handler returns the time the request
  spends in the device, measured from the request's arrival time `stime`.
  The FTL thread adds it to `req->expire_time`, and the poller completes the
  request when the host clock reaches that time.

## The FTL thread and its queues

```text
   poller 1                   FEMU-FTL-Thread                  poller 1
  +---------+  to_ftl[1]   +-------------------------+ to_poller[1] +-----------+
  | SQ scan |------------->|                         |------------->| pq[1]     |
  +---------+   (rte_ring) |  for i in 1..nr_pollers |              | ordered by|
   poller 2                |    dequeue one request  |              | expire_   |
  +---------+  to_ftl[2]   |    lat = femu_ftl_      |  to_poller[2]| time; CQE |
  | SQ scan |------------->|      process_req(req)   |------------->| posted    |
  +---------+              |    expire_time += lat   |              | when now  |
      ...                  |    enqueue to_poller[i] |              | >= expire |
                           +-------------------------+              +-----------+
                                       |
                                       | after every request:
                                       v
                           background GC check (one victim)
```

- **One thread per controller.** `femu_ftl_thread()` in `hw/femu/femu.c`
  starts at realize when a namespace is bbssd, ZNS or CSD (or the controller
  shares a bbssd subsystem), after every namespace is built. It is joined at
  device removal.
- **One pair of rings per poller.** Each poller `i` feeds `to_ftl[i]` and
  reads `to_poller[i]`. The FTL thread visits the rings in turn and takes one
  request from each non-empty ring per pass, so no poller can starve another.
- **Every I/O command goes through the ring**, including Flush, Dataset
  Management and commands that already failed in the I/O layer. A failed
  request is not processed: `bb_ftl_process_req()` returns 0 for it, and the
  poller posts the carried error status.
- **No lock protects the FTL state.** The FTL thread is the only writer of
  the mapping, the lines, the write buffer and the caches. With Streams on,
  each request runs under `n->streams_lock`; on a shared subsystem namespace
  it runs under the subsystem's `ns_lock`. An NVMe controller linked to a
  `femu-cxl-ssd` runs its requests on its own FTL thread against the
  medium's FTL, under the medium's lock, which also serializes the medium's
  worker.
- **Admin commands that change FTL state pause the dataplane.**
  `nvme_pause_pollers()` waits until the FTL thread is outside a request (the
  `ftl_in_sweep` flag), so the run-time switch (admin opcode 0xEF), the
  volatile write cache feature, Format and Sanitize change FTL state with
  nothing in flight.

`bb_ftl_process_req()` in `hw/femu/bbssd/ftl.c` dispatches on the opcode:

| Opcode | Handler | What the FTL does |
| --- | --- | --- |
| Read | `ssd_read()` | translate each page; buffer hit, read cache hit or NAND read |
| Write | `ssd_write()` | foreground GC, read reclaim, then buffer or program each page |
| Write Zeroes | `ssd_write_zeroes()` | with the Deallocate bit: unmap; without it: program the range |
| Dataset Management | `ssd_trim()` | deallocate each range |
| Copy | `ssd_copy()` | read every source range, then write the destination |
| Flush | `ssd_buffer_destage(ssd, 0, ...)` | program everything the write buffer holds |
| I/O Management Send | `ssd_fdp_update_ruhs()` | FDP only: update reclaim unit handles |

Read and Write latency is the largest per-page latency of the request: pages
on different LUNs proceed in parallel, and pages on one LUN queue on its
timeline. Copy costs the slowest source read plus the destination write.
After the opcode handler, the thread runs one background GC step if the
device is past the background watermark ([Triggers](#triggers-and-watermarks)).

## Data structures

All of the FTL's state hangs off `struct ssd` (`hw/femu/bbssd/ftl.h`), one
per bbssd or CSD namespace.

### Physical page address

A `struct ppa` packs a NAND location into 64 bits:

```text
 63  62          51 50      44 43  40 39      32 31            16 15             0
+---+--------------+----------+------+----------+----------------+----------------+
|rsv|  ch (12)     | lun (7)  |pl (4)| sec (8)  |   pg (16)      |   blk (16)     |
+---+--------------+----------+------+----------+----------------+----------------+
```

The field widths bound the geometry: at most 4096 channels, 128 LUNs per
channel, 16 planes per LUN, 65536 blocks per plane, 65536 pages per block and
256 sectors per page. `bb_check_geometry()` refuses larger values, and also
refuses a geometry whose total sector count exceeds `INT_MAX`, because the
derived totals in `struct ssdparams` are `int`. The FTL always addresses
whole pages; the `sec` field is unused by the mapping.

### NAND state

```text
ssd->ch[nchs]
  .next_ch_avail_time
  .lun[luns_per_ch]
     .next_lun_avail_time          <- the timeline every NAND op is gated on
     .pl[pls_per_lun]
        .blk[blks_per_pl]
           .vpc, .ipc              valid and invalid page counts
           .erase_cnt              P/E cycles of this block
           .read_cnt               reads since the last erase
           .pg[pgs_per_blk].status FREE, VALID or INVALID
```

A page goes FREE -> VALID when it is programmed (`mark_page_valid()`),
VALID -> INVALID when its logical page is overwritten, deallocated or moved
by a log-block merge (`mark_page_invalid()`), and back to FREE when its block
is erased (`mark_block_free()`). A page that line GC relocates stays VALID
until its block is erased. Closing a stream's line marks its unwritten pages
INVALID directly.

### Mapping tables

```text
 maptbl: logical page -> physical page        rmap: physical page -> logical page
 (one struct ppa per logical page)            (indexed by ppa2pgidx(), one u64 each)

  LPN    PPA                                   pgidx                     LPN
 +-----+--------------------------+           +------------------------+-----+
 |  0  | ch0 lun0 pl0 blk7 pg3    |---------->| ch0 lun0 pl0 blk7 pg3  |  0  |
 |  1  | UNMAPPED                 |           | ch1 lun0 pl0 blk7 pg3  |  5  |
 |  2  | ch3 lun1 pl0 blk2 pg0    |           | ...                    | ... |
 | ... | ...                      |           | (stale copy)           | INV |
 +-----+--------------------------+           +------------------------+-----+
```

`maptbl` is the forward map and `rmap` the reverse map that GC uses to find
which logical page a valid physical page holds. Both have one entry per NAND
page (`tt_pgs`), 8 bytes each: 32 MiB apiece for the default 16 GiB geometry.
Every mapping scheme keeps these two tables as the source of truth.

### Lines

```c
typedef struct line {
    int id;              /* the block index this line spans */
    int ipc, vpc;        /* invalid and valid pages over the whole line */
    size_t pos;          /* slot in the victim priority queue, 0 if none */
    uint64_t close_time; /* when the line filled; age-based policies */
    uint64_t close_seq;  /* order in which lines filled; the FIFO key */
    uint64_t stream_tag; /* Streams: the stream whose data it holds */
    bool reclaiming;     /* being rewritten by read reclaim */
    ...
} line;
```

`struct line_mgmt` keeps a free list (a FIFO), a victim priority queue keyed
by valid page count (by `close_seq` under `gc_policy=fifo`), and a full list.

## Address mapping

### From LBA to logical page

`ssd_lpn_range()` turns an LBA range into a range of logical page numbers
(LPNs). A page is `secsz * secs_per_pg` bytes. The byte offset is the LBA
times the LBA size, plus the namespace's offset in the backend:

```text
  LPN = (backend_offset + slba * lba_size) / page_size
```

So a namespace's LPNs start where its data starts in the backend. A
controller with Namespace Management on uses offset 0, because each managed
namespace has a private FTL. A request whose last LPN is at or beyond
`tt_pgs` fails with LBA Out of Range.

### Page mapping (`mapping=page`)

The default. `translate()` returns `maptbl[lpn]`. A write invalidates the old
physical page, if any, and points the LPN at the new one. A read of an LPN
with no mapping costs no NAND time.

### DFTL (`mapping=dftl`)

DFTL keeps the page-level mapping on NAND and caches the translation pages
that are in use. FEMU models the cost of that cache, not its contents: the
flat `maptbl` stays the source of truth, and `cmt_touch()` in
`hw/femu/bbssd/ftl-map-cmt.c` charges NAND time for misses.

```text
  host read/write of lpn
        |
        v
  tp_id = lpn / lpn_per_tp          lpn_per_tp = page_size / 8
        |                           (512 for a 4 KiB page)
        v
  +-------------------------------+
  | cached mapping table (CMT)    |  capacity = mapping_cache_mb / page_size
  | CLOCK, one slot per TP        |  slots
  +-------------------------------+
     | hit: no cost; a write marks the slot dirty
     | miss:
     v
  evict a slot by CLOCK
     | dirty victim: program it on LUN (victim tp_id % tt_luns)
     v
  read the TP on LUN (tp_id % tt_luns), after the write-back
     |
     v
  latency = write-back + read, charged to this request
```

With `mapping_cache_mb` left at 0, DFTL uses 4 MiB, which holds 1024
translation pages and so covers 2 GiB of logical space on a 4 KiB page. The
translation-page traffic occupies the LUN timelines like any other NAND
operation but is not counted as host or GC writes. Host reads, host writes and
buffer write-backs are charged; GC relocation, deallocate, Write Zeroes and
the FDP write path update `maptbl` without a CMT access.

### Log-block mapping: BAST (`mapping=hybrid`) and FAST (`mapping=fast`)

The two log-block schemes write every page through a separate LOG write
pointer and model the merges a log-block FTL has to run. Like DFTL, they use
`maptbl` for correctness, so a read always finds the newest copy. A logical
block (LBN) is `pgs_per_blk` consecutive LPNs.

```text
 hybrid (BAST): one log per logical block      fast (FAST): one sequential log
                                               plus a shared random-write pool
  pool of 16 logs                               SW log: one LBN, in-order run
 +--------+--------+-----+--------+            +--------------------------+
 | LBN 12 | LBN 40 | ... | free   |            | LBN 7: off 0,1,2,...     |
 | used 9 | used 256      |        |            +--------------------------+
 +--------+--------+-----+--------+            RW pool: 16 blocks of pages,
      |        |                               any LBN, dirty LBN list
      |        +-- full: merge                 +--------------------------+
      |                                        | LBN 3, LBN 90, LBN 12... |
      +-- pool exhausted: merge the fullest    +--------------------------+
                                                     | pool full: merge two
  merge:                                             | dirty LBNs per pass
   written in order (offset i at slot i)?            v
     yes -> switch merge: erase the old       random merge: relocate each
            data block, no copies             live page of those LBNs
     no  -> full merge: relocate each live    SW log full in order:
            page of the LBN to DATA space     switch merge, one erase
```

- **hybrid** follows BAST (Kim et al. 2002): one log per logical block, from a
  pool of 16. Each program consumes a log slot, overwritten or not; neither an
  overwrite nor a deallocate frees a slot, only a merge does. After every
  programmed page, if a log is full or every log in the pool is taken, the
  fullest log is merged. A log written strictly in order switch-merges for
  the cost of one erase. Any other log full-merges: every live page of its
  LBN is read and programmed into DATA-class space, counted as GC writes.
  Hybrid counts its merges for log page C0h. The scheme models merge cost,
  not BAST's physical block placement: logs of different LBNs share physical
  lines, and line GC still runs underneath and can add copies.
- **fast** follows FAST (Lee et al. 2007): a single sequential-write log for
  an in-order run that starts at offset 0 of an LBN, and a shared pool of 16
  blocks' worth of pages for everything else. When the pool fills (or the
  dirty-LBN list reaches its 4095 limit), a reclaim relocates the live pages
  of up to two dirty LBNs, and repeats on later writes until the pool is
  no longer full. A full in-order sequential log switch-merges with one
  erase. The sequential log is released only when it fills in order; a
  broken run keeps holding it, and later sequential runs go to the shared
  pool. FAST
  reclaims once per request, not once per page, and its merge counts are not
  exported.

Merge reads, programs and erases are charged to the request that triggered
the merge, and the relocated pages count in the write amplification factor.

### Choosing a scheme

| `mapping` | Models | Extra cost charged | Extra write pointer | Counters |
| --- | --- | --- | --- | --- |
| `page` | a full page map in DRAM | none | none | none |
| `dftl` | a page map on NAND with a cache of translation pages | translation page read on a miss, program on a dirty eviction | none | none exported |
| `hybrid` | BAST log blocks | switch and full merges per log | LOG | C0h bytes 88 to 111 |
| `fast` | FAST log blocks | bounded random merges, sequential switch merges | LOG | none exported |

Streams need `page` or `dftl`. FDP supports only `page`.

## Lines, superblocks and write pointers

### A line is a superblock

A line is the block with the same index on every plane of every LUN of every
channel. There are `blks_per_pl` lines, each `nchs * luns_per_ch *
pls_per_lun` blocks wide. A write pointer fills a line in this order:
channel first, then LUN, then plane, then page.

```text
            ch0     ch1     ch2   ...  ch7
  lun0  pg0 [ 0 ]   [ 1 ]   [ 2 ]       [ 7 ]     numbers are the order in
  lun1  pg0 [ 8 ]   [ 9 ]   [10 ]       [15 ]     which the write pointer
  ...                                             hands out pages of line N
  lun7  pg0 [56 ]   [57 ]   [58 ]       [63 ]     (one plane per LUN)
  lun0  pg1 [64 ]   [65 ]   ...
  ...
  lun7  pg255                          [16383]   -> line full, take the next
                                                    free line
```

Consecutive pages land on different channels, then different LUNs, so a
large write or a burst of small ones spreads over the whole device. With
several planes, the pointer sweeps every channel and LUN on plane 0, then on
plane 1, and so on, before the page index moves on.

### Why there are several write pointers

Each write pointer holds one line open and appends to it. Data written
through one pointer shares lines, so the lines die together or not. Keeping
data of different lifetimes apart is what makes GC victims mostly invalid.
The FTL has these pointers:

| Pointer | In `struct ssd` | Takes | Opened |
| --- | --- | --- | --- |
| data | `wp` | host writes (only first writes with `hot_cold_sep=on`), GC relocations, read reclaim, merge relocations | at init |
| hot | `hot_wp` | overwrites of mapped pages, with `hot_cold_sep=on` | on first use |
| log | `log_wp` | every host write under `hybrid` or `fast` | on first use |
| stream | `stream_wp[i]` | writes of open stream `i` | on first use |
| stream GC | `stream_gc_wp` | relocated pages of a released stream | on first use |
| reclaim unit | per handle | FDP placement; see [FDP](../features/fdp.md) | FDP init |

When a hot or log pointer cannot get a line, the write falls back to the
data pointer. Every open pointer pins a line, so `bb_check_capacity()` adds
one reserved line per pointer the configuration can hold open
([Capacity](#over-provisioning-and-capacity)).

### Hot/cold separation

With `hot_cold_sep=on` and page or DFTL mapping, `prepare_write()` sends a
write to the hot pointer when its LPN is already mapped. An overwrite is the
cheapest predictor of another overwrite, so hot lines fill with pages that
are invalidated together. GC relocations go through the data pointer, so
pages that survive a collection join the cold data. The log-block schemes
ignore the setting, but the extra reserved line is still counted. FDP
refuses it.

### Line state machine

```text
                 +-------------------------------------------------+
                 |                                                 |
                 v                                                 |
            +---------+  a write pointer takes it  +----------+    |
  init ---->|  FREE   |--------------------------->|   OPEN   |    |
            | (FIFO)  |                            | (curline)|    |
            +---------+                            +----------+    |
                 ^                                   |       |     |
                 |                    last page      |       |     |
                 |                    programmed,    |       |     |
                 |                    all valid      |       |     |
                 |                                   v       |     |
                 |                             +--------+    |     |
                 |                             |  FULL  |    | last page programmed,
                 |                             | (list) |    | some invalid
                 |                             +--------+    |     |
                 |          first invalidation     |         |     |
                 |                                 v         v     |
                 |                             +----------------+  |
                 |                             |    VICTIM      |  |
                 |                             | priority queue |  |
                 |                             | keyed by vpc   |  |
                 |                             +----------------+  |
                 |        selected by gc_policy   |                |
                 |                                v                |
                 |                         +-------------+         |
                 +-------------------------| COLLECTING  |         |
                   relocate valid pages,   | in no list  |         |
                   erase every block       +-------------+         |
                                                                   |
   read reclaim: FULL or VICTIM -> COLLECTING (reclaiming=true) ---+
   Streams: a released stream's partly written OPEN line has its
   free pages marked invalid and joins VICTIM (or FREE if empty)
```

An open line belongs to no list; invalidations only lower its valid count.
When a line fills, `close_time` and `close_seq` are set. The free list is a FIFO: lines are
taken from the head and returned to the tail. The FTL has no explicit wear
levelling; the FIFO spreads erases over the free lines.

## Garbage collection

The code is in `hw/femu/bbssd/ftl-line-gc.c`.

### Triggers and watermarks

The two watermarks are stored as free-line counts:

```text
  gc_thres_lines      = (int)((1 - gc_thres_pcent/100)      * tt_lines)
  gc_thres_lines_high = (int)((1 - gc_thres_pcent_high/100) * tt_lines),
                        at least 1 with hot_cold_sep, Streams, or a hybrid
                        or fast mapping (bb_gc_forced_lines())
```

The floor matters below 20 lines, where the default high watermark rounds to
zero. A second write pointer can then take the last free line while the data
pointer, which GC writes into, is nearly full, and GC would have nowhere to
put a victim's pages (with Streams, GC refuses such a victim outright). One
free line always holds a whole victim. The floor costs those small
geometries one line of exposable capacity.

| Kind | When | Where | Victim filter | How many |
| --- | --- | --- | --- | --- |
| Background | free lines <= `gc_thres_lines` | after every request that reaches the FTL without an error, any opcode | the chosen line must have at least 1/8 of its pages invalid | one line |
| Foreground (forced) | free lines <= `gc_thres_lines_high` | at the start of a write, and before every page that a write, a write-back of the buffer, or Write Zeroes without Deallocate programs | none | repeats until above the watermark or no victim |

Forced GC runs per page, not once per command: one command can program more
lines than the watermark keeps free, and a collection that starts after the
last line is gone has nowhere to move pages to.

A GC step returns -1 when there is no victim, when the background filter
rejects it, or when the victim's valid pages cannot all be moved; the forced
loop then stops. With Streams on, a step also fails
when it frees nothing, because lines of distinct retired streams cannot be
combined, or when the victim holds valid pages and no line is free.

### Victim policies

`gc_policy` selects one entry of `femu_ftl_policies[]`:

| `gc_policy` | Chooses | Cost per choice |
| --- | --- | --- |
| `greedy` | the line with the fewest valid pages: the top of the priority queue | O(log n) |
| `random` | a uniformly random line of the queue, drawn from the seeded generator; a background step puts it back if it fails the 1/8 filter | O(log n) |
| `cost-benefit` | the largest age x (1 - u) / 2u, with u = vpc / pgs_per_line and age = now - close_time, compared in 128-bit integers; a line with no valid pages always wins | O(n) scan |
| `fifo` | the line that filled first (lowest `close_seq`), whatever its valid count: the top of the queue, which this policy orders by `close_seq` | O(1) to find, O(log n) to remove |
| `d-choice` | the fewest valid pages among 4 queue slots drawn from the seeded generator; a slot can be picked twice | O(1) sample |

Only lines in the victim queue are candidates. A line that closed with every
page valid stays in the full list until something invalidates one of its
pages. Under `fifo` the queue is keyed by `close_seq`, which does not change
while a line is queued, so an invalidation lowers the valid count without
moving the line.

`random`, `d-choice` and the FDP `gc_strategy=2` (random) draw from a
splitmix64 generator in each namespace's FTL (`ftl_gc_rand()`), seeded from
`gc_seed` (default 0). The same configuration, seed and command sequence pick
the same victims and give the same write amplification; give each run a
different `gc_seed` to vary it. The other policies use no random numbers.
`cost-benefit` still reads the host clock for line age, so its picks depend
on when commands arrive.

### Collecting a line

```text
  do_gc(force)
    |
    v
  victim = policy->select_victim_line(force)  -- none? return -1
    |
    v
  move: for ch, lun, pl, each page of block (ch, lun, pl, victim->id):
    if VALID:
      new = next page of the data pointer        (stream pointer for
            (takes a free line if it has none)    Streams data)
      none? requeue the victim, return -1
      NAND read at the old page                  (GC_IO)
      lpn = rmap[old]
      maptbl[lpn] = new, rmap[new] = lpn
      old page -> INVALID, rmap[old] = none
      NAND program at the new page               (GC_IO)
      gc_write_pages++
    |
    v
  erase: for ch in 0..nchs-1, lun in 0..luns_per_ch-1:
    mark each plane's block free: erase_cnt++, read_cnt = 0
    one multi-plane erase of the LUN's blocks    (GC_IO, tplebsy between
                                                  planes)
    |
    v
  line -> free list tail
```

The relocated page goes wherever the data pointer is, not to the victim's
LUN: the model has no copyback. Every valid page is moved before any block
is erased. If the data pointer runs out of lines part way, the victim goes
back to the victim queue (or the full list, if nothing was moved from a full
line) holding the pages it still has, and nothing is erased. The pages that
were moved are already invalid in the victim, so its counts stay true and a
later step moves only what is left. Writes that then find no line fail with
Capacity Exceeded. The watermark floor, per-page forced GC and the capacity
reserve keep a valid configuration from getting there.

### How GC time is charged

GC operations enter the NAND model with `stime = 0`, which the media bridge
replaces with the current host time. Each one moves its LUN's
next-available time forward, and the latency it returns is discarded. GC
time therefore reaches the host only through the LUN timelines: a later host
read or program on a LUN that GC is using starts when GC is done with it.

```text
  LUN 3 timeline   |--host W--|--GC R--|--GC W--|--GC W--|--erase-------|--host R--|
                              ^                                         ^
                              GC starts at "now"                        a read that
                                                                        arrived here
                                                                        waits until
                                                                        the erase ends
```

- In background GC the request that triggered it has already been timed, so
  it pays nothing. The requests that follow pay, on the LUNs GC occupied.
- In foreground GC the write itself waits, because its own programs queue
  behind the GC operations on the same LUNs.
- Admin opcode 0xEF code 2 turns GC timing off (`enable_gc_delay`): GC still
  moves the pages and erases the blocks, but issues no NAND operations. Code
  1 turns it back on.

The LUN field `gc_endtime` is updated as GC programs and erases, and the
channel field is never written; nothing reads either.

### FDP reclaim units

With Flexible Data Placement the FTL places data in reclaim units, one line
each, through per-handle write pointers, and collects reclaim units instead
of lines (`do_gc_fdp_style()` in `hw/femu/bbssd/ftl-fdp.c`). `gc_strategy`
picks that victim policy; `gc_policy` and the other FTL knobs listed under
[Interactions](#interactions-and-refusals) are refused. The [FDP chapter](fdp.md)
and the [FDP guide](../features/fdp.md) describe
it.

Both collectors record a page move through one helper, `ssd_gc_move_page()`,
and time it through `ssd_gc_charge_move()`. Each keeps its own destination
and write frontier: line GC writes to the data or stream pointer, FDP to the
handle's collection reclaim unit.

## Write buffer

The write buffer models DRAM in front of the NAND. It holds logical page
numbers, not data: a write it accepts costs a DRAM access, and the program
is charged later to whatever forces the page out. Repeated writes to a
buffered page cost one program. The code is in
`hw/femu/bbssd/ftl-datapath.c`.

```text
  host write, pages P..Q
        |
        v
  forced GC if free lines <= high watermark; one read-reclaim step
        |
        v
  buffer enabled, not FUA, not a stream write? ---- no ----+
        | yes                                              |
        v                                                  v
  for each page:                                  drop buffered copies of
    already held? -> move to tail, write hit      these pages; if the cache
    else if count >= watermark:                   was disabled, write back
        write back `batch` pages from the head    everything
        (oldest first), cost charged to this                |
        write                                               v
    insert at tail                                program each page
        |                                         (NAND time)
        v
  latency = max(DRAM access, write-back cost)

  watermark = max(1, (int)(buffer_size * buffer_thres_pcent / 100))
  batch     = max(1, buffer_size - watermark)
  DRAM access = pg_rd_lat / 16 (1000 ns when pg_rd_lat is 0)
```

- **Structure.** A tail queue in order of last write, LRU (`write_buffer`) and a GLib
  tree keyed by LPN (`wb_tree`) for lookup. Capacity is `buffer_size` pages.
- **Admission is per page.** A command larger than the buffer cannot push it
  past its size: it writes back a batch whenever the buffer is at the
  watermark. If a write-back frees nothing because the device is out of
  lines, the write fails with Capacity Exceeded.
- **Write-back** (`ssd_buffer_destage()`) takes pages from the head (the
  least recently written), runs forced GC as needed, charges the DFTL lookup and
  programs each page exactly as a direct write would. Hybrid merges after
  each page as usual; FAST merges once per batch. A page costs the same buffered or not; only the request
  that pays differs.
- **Reads.** A read of a buffered page costs one DRAM access and does not
  reach NAND, even when the buffer has stopped accepting writes.
- **FUA and stream writes** program directly. A direct write first drops any
  buffered copy of its own pages, so an older version is never programmed
  after the newer one.
- **Deallocate** drops buffered copies before unmapping, so discarded data is
  never programmed later.
- **Flush** reaches the FTL like any other command and writes back the whole
  buffer, charged to the Flush.
- **Volatile write cache.** With `vwc=1` the controller advertises a cache.
  When the host turns it off with feature 06h, the buffer stops accepting
  writes and the next write drains it. With `vwc=0` the buffer still works,
  and the host has no way to turn it off; Linux sends no Flush to a
  controller that advertises no cache.

`host_write_pages` counts pages when the host writes them and
`nand_write_pages` when they are programmed, so a buffer that absorbs
overwrites makes the write amplification factor drop below 1.

### Power loss

With `power_loss=on`, the poller no longer touches payload: the FTL thread
runs the whole I/O command (`nvme_power_io()`), so the data copy and the
buffer change together. The first time a page enters the buffer, the FTL
saves the page's previous bytes and per-LBA state as an undo record. When
the page is programmed the record is dropped. Setting the QOM property
`simulate-power-loss` ([runtime properties](../reference/runtime-properties.md#power-loss-trigger))
resets the controller, restores every buffered page from its undo record,
empties the buffer and counts an unsafe shutdown.

In this mode a normal shutdown, turning the cache off and Sanitize first
write back every namespace's buffer; Flush, Format, Dataset Management,
Copy, Write Zeroes (except on a PI-formatted namespace) and Write
Uncorrectable write back their own namespace's. If the device has no
line to write to, they fail with Capacity Exceeded (a shutdown sets
Controller Fatal Status instead) rather than claim the data is durable. An FUA write programs a whole NAND page, so buffered
neighbours in that page become durable with it.

## Read cache

`read_cache_mb` adds a DRAM read cache in front of NAND reads
(`hw/femu/bbssd/ftl-cache.c`). Like the write buffer it holds LPNs only.

```text
  host read of a mapped lpn (not in the write buffer)
        |
        v
  lookup in an open-addressed hash over capacity slots
     hit:  cost pg_rd_lat / 16, no NAND read, no block read count
     miss: insert (evict by cache_evict if full), then NAND read
```

- Capacity is `read_cache_mb` MiB divided by the page size.
- Only reads fill it. A host overwrite, a deallocate and a power cut remove
  the page's entry. A GC relocation does not, since the content is the same.
- `cache_evict` picks the victim: `clock` (second chance), `random` (a
  fixed-seed generator, so runs repeat), `lru` (exact, by scan) or `arc`, a
  scan-resistant 2Q variant that evicts pages read once before pages read
  twice. It is not full ARC.
- Hit and miss counts are kept in `ssd->rcache` but not exported.

## Deallocate, Write Zeroes, Format and Sanitize

- **Dataset Management deallocate** (`ssd_trim()`) unmaps every LPN of every
  range: it drops the buffered copy, invalidates the physical page, clears
  `maptbl` and `rmap`, and drops the read cache entry. A log-block scheme does
  this through its `trim()` hook. A range past the device is skipped. The
  latency is `trim_lat_ns` times the number of ranges, or 0.
- **Write Zeroes with Deallocate** unmaps the range in the same way and costs
  no time. **Without Deallocate** it programs the range directly, after
  forced GC if needed, and counts the pages as host writes.
- **Format** and **Sanitize** call `bbssd_deallocate_all()` on BlackBox
  namespaces (not CSD), which unmaps every LPN of the namespace's FTL. The lines keep their wear.

ONCS bit 0x8 (Write Zeroes) and 0x100 (Copy) are off unless `oncs` sets them.

## Wear, read reclaim and retention refresh

### Program/erase cycles

Every erase increments the block's `erase_cnt` and the FTL-wide
`total_erases`. SMART Percentage Used is

```text
  percentage_used = min(255, total_erases * 100 / (tt_blks * rated_pe_cycles))
```

where `rated_pe_cycles` is `pe_cycles_rated`, or the rating of
`nand_cell_type` (SLC 100000, MLC 3000, TLC 1000, QLC 300), or 0, in which
case the field reads 0. With `blk_pe_limit`, the denominator is the sum of
every block's own erase limit at start, spare lines included, so the figure
only grows. `nand_bad_blocks` marks a number of blocks as
factory bad for SMART Available Spare only: `100 - bad * 100 / tt_blks`.
Placement ignores them. With several namespaces the controller reports the
most worn namespace and the lowest spare.

With `ecc_step_ns` set, a block's erase count (one tier per 750 erases) and
the age of its line add time to each read. That model belongs to the NAND
timing chapter.

### Read reclaim and retention refresh

```text
  host NAND read of block B in line L
        |
        +-- read_reclaim_limit set and B.read_cnt >= limit   --+
        +-- retention_limit_sec set and now - L.close_time >= -+--> queue L
            limit                                              (one line at
                                                                a time)
  next host write:
        |
        v
  do_read_reclaim(): queued line, high watermark not reached,
  at least 2 free lines, L full or in the victim queue?
        | yes
        v
  take L out of its list, reclaiming = true, collect L like GC
  read_reclaims++ or retention_refreshes++
```

Every NAND read the FTL issues, host, GC or merge, increments its block's
`read_cnt` (GC reads are issued only while GC timing is on); an erase
resets it. Reads answered by the write buffer, the read cache or a DFTL
translation page do not count. The rewrite happens on a write, where
relocation already costs something, so a read never stalls behind a whole
line. One line is refreshed per write at most. A line that nothing reads is
never refreshed, and a workload that only reads refreshes nothing: FEMU runs
no background media scan. The request is dropped if GC collects the line first, or if the line is
still open for writing when the next write checks it.

## Fault insertion

`err_read_unc_ppm` and `err_write_fail_ppm` turn a rate into a period,
`1000000 / ppm`, at least 1. Every Nth Read command completes with
Unrecovered Read Error (with DNR, as every Unrecovered Read Error in FEMU
is) and every Nth Write command with Write Fault. The
counters run per namespace FTL, so a run repeats exactly. The command is
still timed and, for a write, still programmed and mapped; only its status
changes. The injected counts feed SMART Media and Data Integrity Errors.
Write Zeroes and Copy are never failed.

## Over-provisioning and capacity

### The reserve

`bb_check_capacity()` in `hw/femu/bbssd/bb.c` refuses a namespace that would
leave GC no room. The reserve, in lines:

```text
  reserve = gc_thres_lines_high      forced watermark, with its floor
          + 1                        data pointer
          + 1 if hot_cold_sep        hot pointer
          + 1 if mapping is hybrid or fast   log pointer
          + streams.max + 1 if streams       stream and stream GC pointers

  usable  = (blks_per_pl - reserve) * pages_per_line * page_size
  refused when the namespace is larger than usable,
  or when blks_per_pl <= reserve
```

Each namespace has its own FTL built from the whole geometry, so the check
applies per namespace.

### Sizing the namespace

Without `op_pcent`, the backend is `devsz_mb` MiB, split across the
namespaces, and the spare area is whatever the geometry has beyond that.
With `op_pcent`, the backend is the raw NAND capacity and each namespace
gets `raw * 100 / (100 + op_pcent) / namespaces`, rounded down to 512 bytes
(an even split unless `namespace_sizes` is given); `devsz_mb` is ignored.

### Worked example: the default geometry

The default properties describe 8 channels x 8 LUNs x 1 plane x 256 blocks x
256 pages x 8 sectors x 512 bytes:

```text
  page            = 8 x 512                      = 4 KiB
  NAND pages      = 8 x 8 x 1 x 256 x 256        = 4,194,304
  raw capacity    = 4,194,304 x 4 KiB            = 16 GiB
  lines           = blks_per_pl                  = 256
  blocks per line = 8 x 8 x 1                    = 64
  pages per line  = 64 x 256                     = 16,384   (64 MiB)

  background GC   = (int)(0.25 x 256)            = 64 free lines  (75% used)
  forced GC       = (int)(0.05 x 256)            = 12 free lines  (95% used)
  victim filter   = 16,384 / 8                   = 2,048 invalid pages

  reserve         = 12 + 1                       = 13 lines
  usable          = 243 x 64 MiB                 = 15,552 MiB

  devsz_mb=12288 (the launcher):  12 GiB = 192 lines of data
     -> the data pointer holds a line from init, so free lines reach
        64 and background GC starts as the last of the 192 lines is
        opened, just before one full pass completes
  op_pcent=25:  16 GiB x 100 / 125               = 13,107.2 MiB exposed
  op_pcent=7:   16 GiB x 100 / 107               = 15,312.1 MiB exposed

  host memory for the FTL: maptbl 32 MiB + rmap 32 MiB
                           + page status 16 MiB + block and line arrays
```

With the default `devsz_mb` of 1024 the same geometry exposes 1 GiB, about
6% of the NAND, and GC barely runs. To give GC work on a small device,
shrink the geometry instead; this one has 512 MiB of NAND and exposes about
410 MiB:

<!-- femu-example: ftl-op-small -->
```
-device femu,femu_mode=1,nchs=2,luns_per_ch=4,blks_per_pl=64,op_pcent=25
```

## Run-time controls

Admin opcode 0xEF changes the FTL while the guest runs. Only a BlackBox
controller accepts it. Codes 1 to 4 apply to every namespace with an FTL,
with the dataplane paused; codes 5 to 7 act on the controller.

| CDW10 | Effect |
| --- | --- |
| 1 | GC operations take NAND time (the default) |
| 2 | GC operations take no NAND time |
| 3 | flat read, program, erase times back to 40 us, 200 us, 2 ms |
| 4 | flat read, program and erase times to 0 |
| 5 | reset the poller completion counters |
| 6, 7 | turn the per-request log lines on or off |

Codes 3 and 4 set the built-in flat times, not the values given on the
command line, and do not affect `nand_cell_type` tables. See
[changing timing at run time](../concepts/timing-model.md#changing-timing-at-run-time).

## Statistics

### Vendor log page C0h

`nvme_collect_media_stats()` in `hw/femu/nvme-admin.c` sums the FTL counters
over the controller's bbssd, CSD and KV namespaces.
[log-pages-and-counters.md](../reference/log-pages-and-counters.md#vendor-log-page-c0h)
lists the offsets.

| C0h field | FTL counter | Moves when |
| --- | --- | --- |
| WAF x 1000 | (nand + gc) x 1000 / host | after the first host write |
| host write pages | `host_write_pages` | Write, the destination of Copy, and Write Zeroes without Deallocate, per page, buffered or not |
| GC write pages | `gc_write_pages` | GC, read reclaim and log-block merges relocate a page |
| NAND write pages | `nand_write_pages` | a host page is programmed |
| max block reads | largest `read_cnt` | NAND reads; reset by erase |
| read reclaims, retention refreshes | `read_reclaims`, `retention_refreshes` | a queued line is rewritten |
| buffer reads and read hits | `sp.read_cnt`, `sp.read_hit_cnt` | host read pages, and those the buffer held |
| buffer writes and write hits | `sp.write_cnt`, `sp.write_hit_cnt` | host write pages, and those already buffered |
| hybrid switch, full merges, merge erases | `struct femu_map_hybrid` | `mapping=hybrid` only |

The buffer read and write counts move with or without a buffer, so their
ratio is the hit rate. Telemetry log 07h captures the same 512 bytes.

### SMART and Endurance Group

| Field | Source |
| --- | --- |
| Percentage Used | `ssd_percentage_used()`, most worn namespace |
| Available Spare | `ssd_available_spare()`, lowest namespace; below 20 sets the spare critical warning |
| Media and Data Integrity Errors | injected read and write faults (and ZNS write faults) |
| Data units, host commands | the pollers' host I/O counters, not the FTL |
| Endurance Group Media Units Written | (NAND + GC write pages) x page size, in units of 10^9 bytes rounded up; needs a `femu-subsys` |

### Counters kept but not exported

DFTL hits and misses (`ssd->cmt`), read cache hits and misses
(`ssd->rcache`), FAST merge counts and the per-block `erase_cnt` stay inside
the FTL. `debug_ftl=on` prints hybrid and FAST merge counts to stdout.

## Parameters

Every property is listed with its type, default and range in the
[property reference](../reference/properties.md); this table says what each
does inside the FTL and what it interacts with.

### Geometry and capacity

[NAND geometry](../reference/properties.md#nand-geometry-bbssd-csd-kv),
[mode and capacity](../reference/properties.md#mode-capacity-and-namespaces)

| Property | Effect in the FTL | Interacts with |
| --- | --- | --- |
| `secsz`, `secs_per_pg` | page size; LPN = byte offset / page size | the LBA format; DFTL entries per translation page |
| `pgs_per_blk` | pages per block and per line column; the log-block merge unit | at most 512 with `nand_cell_type` |
| `blks_per_pl` | the number of lines | the watermarks and the reserve are fractions of it |
| `pls_per_lun`, `luns_per_ch`, `nchs` | line width and write striping | parallelism; `tplebsy` for multi-plane erase; `mp_program`, `mp_read` for multi-plane program and read |
| `devsz_mb`, `namespaces`, `namespace_sizes` | the exposed capacity | must fit the usable lines per namespace |
| `op_pcent` | exposes a fixed fraction of raw NAND | overrides `devsz_mb`; refused with `cxl_ssd` |

### Garbage collection, mapping and caches

[Garbage collection, mapping and caches](../reference/properties.md#garbage-collection-mapping-and-caches)

| Property | Effect in the FTL | Interacts with |
| --- | --- | --- |
| `gc_thres_pcent` | background GC watermark | must not exceed `gc_thres_pcent_high` |
| `gc_thres_pcent_high` | forced GC watermark; sizes the reserve | lower values cost exposed capacity |
| `gc_policy` | line victim selection | refused with FDP |
| `gc_seed` | seed for the `random` and `d-choice` policies and FDP random reclaim | no effect on the other policies |
| `gc_strategy` | reclaim unit victim selection | FDP only |
| `mapping` | L2P scheme | `hybrid` and `fast` reserve a line and refuse Streams; FDP needs `page` |
| `mapping_cache_mb` | DFTL cache size | used only with `mapping=dftl` |
| `read_cache_mb`, `cache_evict` | read cache size and eviction | hit time is `pg_rd_lat` / 16 at realize; 0xEF does not change it |
| `hot_cold_sep` | hot write pointer for overwrites | page or DFTL only; reserves a line; refused with FDP |
| `buffer_size`, `buffer_thres_pcent` | write buffer capacity in pages, and the write-back watermark | `vwc`, `power_loss`; refused with FDP |
| `fdp_trim_erase_all` | FDP deallocate resets every reclaim unit | FDP only |
| `debug_ftl` | prints invalid page transitions and merge counts | none |

### Reliability and wear

[Reliability and wear](../reference/properties.md#reliability-and-wear)

| Property | Effect in the FTL | Interacts with |
| --- | --- | --- |
| `pe_cycles_rated` | Percentage Used denominator | overrides the `nand_cell_type` rating |
| `nand_bad_blocks` | Available Spare | placement ignores it |
| wear events | the FTL thread sets a pending SMART warning bit when the spare crosses below 20 or the first block is overworn; the controller's event bottom half raises it if Asynchronous Event Configuration enables it | once each; a controller reset drops a pending bit |
| `spare_lines` | per-plane pool of replacement blocks: a worn-out block swaps its whole state with a spare block of its plane, so addresses do not change; Available Spare follows the emptiest plane | needs `blk_pe_limit`; the namespace must fit without the spare lines |
| `blk_pe_limit`, `blk_pe_spread`, `blk_pe_seed` | per-block erase limit; after a line erase that takes a block to it, the line retires while usable lines stay at or above the namespace's lines + forced collection lines + 2 and an open line and a free line remain; otherwise the block stays in service (overworn) and sets SMART critical warning bit 2 | refused with the settings the parameter manual lists |
| `ecc_step_ns`, `ecc_retention_sec` | read time grows with erase count and line age | `ecc_retention_sec` refused with FDP |
| `err_read_unc_ppm`, `err_write_fail_ppm` | fixed-period command failures | counted in SMART media errors |
| `read_reclaim_limit` | read count that queues a line for rewrite | needs host writes to act; refused with FDP |
| `retention_limit_sec` | line age that queues a line for rewrite | same |

### NAND timing the FTL charges

[NAND timing](../reference/properties.md#nand-timing-bbssd-csd-kv)

The FTL charges `trim_lat_ns` per deallocate range (refused with FDP) and
issues a multi-plane erase per LUN during GC, whose inter-plane time is
`tplebsy`. All the other timing properties are applied by the NAND media
layer.

### Controller properties the FTL reads

| Property | Where documented | Effect in the FTL |
| --- | --- | --- |
| `vwc` | [controller identity](../reference/properties.md#controller-identity-and-capabilities) | lets the host turn the write buffer off |
| `oncs` | same | Write Zeroes and Copy reach the FTL only when enabled |
| `power_loss` | [power loss](../reference/properties.md#namespace-management-streams-and-power-loss) | undo records and `simulate-power-loss` |
| `streams`, `streams.max` | same | per-stream write pointers; reserve `streams.max + 1` lines |

### Interactions and refusals

- **FDP** refuses `buffer_size`, `hot_cold_sep`, `read_reclaim_limit`,
  `retention_limit_sec`, `ecc_retention_sec`, `trim_lat_ns`, a `mapping`
  other than `page` and a `gc_policy` other than `greedy`, with
  `FEMU bbssd: <name> has no effect under FDP`.
- **Unknown names** for `mapping`, `gc_policy` and `cache_evict` are refused
  at realize.
- **Watermarks** outside [1, 100], or a high watermark below the low one, are
  refused.
- **The write buffer** is off when `power_loss=on` and `vwc=0`, and while the
  host has the advertised cache turned off.
- **DFTL cache size** has no effect under `page`, `hybrid` or `fast`.

Examples, each checked by `check-doc-examples.py`:

<!-- femu-example: ftl-dftl -->
```
-device femu,devsz_mb=1024,femu_mode=1,mapping=dftl,mapping_cache_mb=8
```

<!-- femu-example: ftl-hot-cold-cb -->
```
-device femu,devsz_mb=1024,femu_mode=1,hot_cold_sep=on,gc_policy=cost-benefit
```

<!-- femu-example: ftl-buffer-vwc -->
```
-device femu,devsz_mb=1024,femu_mode=1,buffer_size=4096,buffer_thres_pcent=75,vwc=1
```

<!-- femu-example: ftl-hybrid -->
```
-device femu,devsz_mb=1024,femu_mode=1,mapping=hybrid
```

## Validation status

What the automated tests check:

| Area | Test | Checks |
| --- | --- | --- |
| BAST merges | unit test `test-femu-hybrid-oracle`; qtests `hybrid-oracle-*`, `hybrid-batch-occupancy`, `hybrid-destage-occupancy`, `hybrid-switch-trim-erase`, `hybrid-trim-occupancy` | the unit test checks the reference model; the qtests compare FEMU's switch, full merge and erase counts against it, including deallocate and the write buffer |
| Victim queue | unit test `test-femu-pqueue` | priority queue operations, including random pop driven by the caller's number; pop, remove and random pop leave the detached element's index at 0; pop equals removing the top and random pop equals removing the drawn slot, slot for slot |
| Reproducible GC | qtests `gc-seed-d-choice`, `gc-seed-random`, `gc-seed-fifo` | two devices with the same configuration and 2048 random page writes report the same relocation count every 32 writes and the same WAF; a third with another `gc_seed` differs (FIFO: matches) |
| NAND timing | unit test `test-femu-nand-media` | the media layer the FTL calls |
| C0h counters | qtest `media-counters` | host and NAND page counts and the WAF move with writes |
| Write buffer | qtest `buffer-counters`, `flush-without-vwc` and `power-loss-*` | hit counts; Flush (also with `vwc=0`), FUA, write-back, cache disable, shutdown and power-cut rollback |
| Streams | qtest `streams-gc` and the other `streams-*` cases | stream placement and GC of stream lines |
| GC with no free line | qtests `gc-no-destination`, `gc-no-destination-hot-cold`, `streams-gc-floor`, `gc-no-destination-fdp` | on a geometry whose forced watermark rounds to zero, random single-page and 64-page writes never fail, no mapping names an erased page and no valid page is orphaned (read through the qtest-only `x-ftl-check` property) |
| Charged work for a fixed workload | qtests `ftl-trace-bbssd`, `ftl-trace-hot-cold`, `ftl-trace-fdp` | a seeded queue-depth-one write and read workload with collection gives exact command, host, NAND, relocated-page and erase counts and exact read, program and erase commands charged to the media layer, and a digest of the order in which lines or reclaim units were collected (qtest-only `x-ftl-trace`; the digest is the last field, a running FNV-style hash of each collected victim's id, updated once per collection, read reclaim included); a refactor of the allocator, collection or media charge must not move them. A different victim policy or a dropped or duplicated charge fails it. The modelled-latency sum depends on host load and is only held to 25%, so NAND timing values are left to `test-femu-nand-media` |
| Victim order of each policy | qtests `ftl-trace-random`, `ftl-trace-d-choice`, `ftl-trace-fifo`, `ftl-trace-fdp-random`, `ftl-trace-fdp-noisy`, `ftl-trace-fdp-noisy-ii`, `ftl-trace-fdp-reread` | the same workload under `gc_policy=random`, `d-choice` and `fifo`, and under FDP `gc_strategy=2` and `4`, gives exact counts, with a fixed `gc_seed` where the policy samples. The NOISY cases write two placement identifiers, so the per-handle heaps compare their tops; in `-ii` one handle is Initially Isolated and has no heap of its own. `ftl-trace-fdp-reread` reads a page after each overwrite, which adds background passes whose refusals move the greedy tie order. A changed draw, tie break or heap key fails the matching case: the victim digest catches a change that leaves the counts equal, such as FDP random with `gc_seed=7` and each draw one higher; cost-benefit has no exact pin, because it reads the host real-time clock |
| Read reclaim | qtest `ftl-trace-read-reclaim` | with `read_reclaim_limit=2` and a read after each overwrite, 83 lines are rewritten, some of them taken from the victim heap, and the trace counts are exact |
| Refused FDP strategies | qtest `fdp-gc-strategy-refused` | `gc_strategy` values other than 0, 1, 2 and 4 are refused at realize |
| Multi-plane program and read | qtests `ftl-trace-mp-off`, `ftl-trace-mp-on`, `ftl-trace-mp-one-plane`, `ftl-trace-mp-fdp-off`, `ftl-trace-mp-fdp-read`, `mp-program-scopes-off`, `mp-program-scopes-on`, `multiplane-warnings`, `config-refused` | with two planes per LUN and reads of 16 pages, `mp_program=1,mp_read=1` keeps every command, page and erase count of the same workload with them off, issues fewer read and program commands, and models less time before collection starts, where that time is exact; with one plane the trace equals `ftl-trace-bbssd`; under FDP the trace with `mp_read=1` equals the one without it; a full row written by Write Zeroes or by a buffer write-back takes 4 program commands instead of 8; a setting that changes nothing warns and a negative busy time is refused |
| Format, Sanitize | qtests `format-ftl`, `sanitize` | after Format, GC relocates nothing; Sanitize status and zeroed data (the FTL state is not checked) |
| Robustness | qtests `io-fuzz`, `io-fuzz-fdp`, `config-refused` | malformed I/O, refused configurations |
| Start-up | `doc-examples` | every tagged example on this page and the BlackBox guide starts and moves one block |

Apart from the exact counts above, no automated test checks the
behaviour of the `cost-benefit` policy, `dftl` and `fast` mapping, hot/cold
separation, the read cache, retention refresh, read and write
fault insertion on BlackBox, or the wear and spare figures. They are covered only by the
start-up examples and by guest runs during development; `femu-test.sh`
([guest-side tests](../guides/testing.md#guest-side-tests)) checks that the
counters move. FEMU's latencies and write amplification have not been
calibrated against a specific commercial drive.

## Limits

- Data placement is modelled per page; the FTL never tracks sectors within a
  page, so writes smaller than a page cost a whole page program.
- GC relocations go through the data pointer (or a stream pointer for
  stream data), never back to the victim's LUN (no copyback), and GC runs on the FTL thread, one line at a
  time.
- There is no explicit wear levelling, and bad blocks do not affect
  placement.
- Read reclaim and retention refresh act only on reads followed by writes.
- `cost-benefit` GC uses the host clock for age, so it is not reproducible
  run to run.
- An injected write fault still programs and maps the data.
- FAST merge counts and DFTL and read cache hit rates are not exported.
- Each namespace's FTL is built from the whole geometry, so host memory for
  the FTL grows with the namespace count.

## Extending the FTL

### Adding a GC victim policy

1. Write `static struct line *select_victim_line_<name>(struct ssd *ssd,
   bool force)` in `hw/femu/bbssd/ftl-line-gc.c`. Candidates are the lines in
   `ssd->lm.victim_line_pq`; slots `1` to `size - 1` of `pq->d[]` hold them.
2. Apply the background filter: when `!force` and the line has fewer than
   `pgs_per_line / 8` invalid pages, return NULL and leave the queue as it
   was.
3. Remove the chosen line with `pqueue_remove()` (or `pqueue_pop()` for the
   top), which sets `line->pos` to 0. The victim count is the queue size,
   so there is no counter to keep. `reclaim_line()` expects a line that is
   in no list.
4. Add `{ .name = "<name>", .select_victim_line = ... }` to
   `femu_ftl_policies[]`. `femu_ftl_policy_known()` then accepts the name.
5. Describe it in the `gc_policy` description in `hw/femu/femu-props.c`,
   regenerate the property reference, and add a qtest that tells the policy
   apart from greedy.

### Adding a mapping scheme

1. Implement `struct femu_mapping_ops` in a new `ftl-map-<name>.c`: at least
   `translate`, `prepare_write`, `commit_write` and `gc_relocate_commit`.
   Keep `maptbl` and `rmap` correct: `commit_write` must invalidate the old
   page and set both tables, because GC and reads depend on them.
2. Keep private state in `ssd->map_priv`, allocated in `init` and freed in
   `exit`.
3. Set `uses_log_class` if writes go through the LOG pointer; the reserve
   then grows by one line and Streams are refused. Set `uses_cmt` to get the
   DFTL cost model.
4. For merges, provide `needs_reclaim` and `reclaim(ssd, budget)`.
   `reclaim()` charges its own NAND operations and returns the latency to add
   to the triggering request. `reclaim_per_page` runs it after every page
   instead of once per request. Allocate a destination before invalidating
   the source, so a full device never loses the only copy.
5. Provide `trim` if the scheme keeps per-page state.
6. Add the ops to `femu_mapping_extra[]` in `hw/femu/bbssd/ftl-map.c`, declare
   them in `ftl-internal.h`, and add the file to the FEMU source list in
   `hw/femu/meson.build`.

Run the unit tests and the qtests ([testing guide](../guides/testing.md)),
and check that the C0h counters move for the new code path: a counter that
never changes in a mode means the mode is not reached.

## Source map

| File | Contents |
| --- | --- |
| `hw/femu/bbssd/bb.c` | mode registration, `bb_check_capacity()`, FDP refusals, the 0xEF switch, teardown |
| `hw/femu/bbssd/ftl.c` | `ssd_init()`, `bb_ftl_process_req()`, Copy, counters, Percentage Used, Available Spare, `ssd_free()` |
| `hw/femu/bbssd/ftl.h` | `struct ssd`, `struct ppa`, lines, write pointers, the mapping and policy ops |
| `hw/femu/bbssd/ftl-internal.h` | address helpers, `ssd_lpn_range()`, GC watermark tests |
| `hw/femu/bbssd/ftl-geom.c` | `bb_check_geometry()`, `ssd_init_params()`, NAND array allocation |
| `hw/femu/bbssd/ftl-datapath.c` | read, write, write buffer, deallocate, Write Zeroes, power-loss rollback |
| `hw/femu/bbssd/ftl-line-gc.c` | lines, write pointers, Streams pointers, GC, victim policies, read reclaim |
| `hw/femu/bbssd/ftl-map.c` | `maptbl`, `rmap`, page and DFTL schemes, scheme registry |
| `hw/femu/bbssd/ftl-map-cmt.c` | DFTL cached mapping table cost |
| `hw/femu/bbssd/ftl-map-hybrid.c` | BAST log-block scheme and its C0h counters |
| `hw/femu/bbssd/ftl-map-fast.c` | FAST log-block scheme |
| `hw/femu/bbssd/ftl-cache.c` | read cache and its eviction policies |
| `hw/femu/bbssd/ftl-media.c` | bridge to the NAND media layer, block read counts |
| `hw/femu/bbssd/ftl-fdp.c` | FDP reclaim units, handles and their GC |
| `hw/femu/bbssd/ftl-exp.c` | debug tracing of marked pages, off unless `FEMU_EXP_LOG` or `FEMU_DUMP_LPN` is set |
| `hw/femu/femu.c` | the FTL thread, `op_pcent` sizing, `simulate-power-loss` |
| `hw/femu/nvme-admin.c` | C0h, SMART and Endurance Group counters, Sanitize, the cache feature |

## Related pages

- [BlackBox guide](../modes/blackbox.md): launch, guest use, refusals
- [Timing model](../concepts/timing-model.md)
- [Architecture](../concepts/architecture.md#bbssd)
- [Measuring](../guides/measuring.md#write-amplification-and-media-counters-c0h)
- [Log pages and counters](../reference/log-pages-and-counters.md)
- [Property reference](../reference/properties.md)
