# NAND media and timing model

This chapter describes the component that decides how long a flash operation
takes in FEMU. It covers the geometry the model works on, the time it charges
for a page read, a page program and a block erase, how operations on the same
die, plane or channel wait for each other, and how those times become the
completion time of an NVMe command. It also covers the two models that sit
after the media: the host link and the controller firmware CPU.

The [timing model concept page](../concepts/timing-model.md) explains the
same model from the user's side. This page is for readers who want the
algorithms, the data structures and the source.

## Contents

- [Purpose and place in FEMU](#purpose-and-place-in-femu)
- [Geometry](#geometry)
- [Data structures](#data-structures)
- [Operation timing](#operation-timing)
- [Cell types and page types](#cell-types-and-page-types)
- [Channel bus](#channel-bus)
- [Plane parallelism and multi-plane operations](#plane-parallelism-and-multi-plane-operations)
- [Program and erase suspend](#program-and-erase-suspend)
- [ECC read time](#ecc-read-time)
- [From operations to a completion time](#from-operations-to-a-completion-time)
- [How garbage collection is charged](#how-garbage-collection-is-charged)
- [Host link and firmware CPU](#host-link-and-firmware-cpu)
- [OCSSD timing model](#ocssd-timing-model)
- [Runtime switches](#runtime-switches)
- [Parameters](#parameters)
- [Statistics](#statistics)
- [Calibrating against a real device](#calibrating-against-a-real-device)
- [Validation status](#validation-status)
- [What is not modelled](#what-is-not-modelled)
- [Adding a timing feature](#adding-a-timing-feature)
- [Source map](#source-map)

## Purpose and place in FEMU

FEMU copies a command's data as soon as it parses the command. Timing is
computed separately: a model works out when the command would have finished
on the emulated device, and the poller holds the completion until the host
clock reaches that time. The NAND media model is the part of that computation
that charges flash operations.

There are two media engines:

- The **media layer**, `nand_media_op()` in `hw/femu/nand/nand-media.c`.
  BBSSD, CSD, KV, ZNS and the FTL behind a `femu-cxl-ssd` use it. It never
  includes a controller header. Each mode decodes its own address into a
  `NandLoc`, gives the layer a configuration, and lends it pointers to its
  busy-until fields.
- The **OCSSD model**, `hw/femu/timing-model/timing.c`. Open-Channel 1.2 and
  2.0 use it. It is older, keeps its state in the controller, and is
  described in [OCSSD timing model](#ocssd-timing-model).

```text
 guest NVMe command
        |
        v
 +--------------------+   stamps stime, copies data
 | poller (nvme-io.c) |------------------------------------------+
 +--------------------+                                          |
        | to_ftl ring                                            |
        v                                                        |
 +--------------------+   per mode: page list -> NAND ops        |
 | FTL                |   bbssd/ftl-datapath.c, zns/zftl.c,      |
 | (FTL thread, or    |   kvssd/kvssd-ftl.c (in the poller)      |
 |  poller for KV)    |                                          |
 +--------------------+                                          |
        | NandLoc + op + stime                                   |
        v                                                        |
 +--------------------+   array time, gates, bus phases,         |
 | NAND media layer   |   suspend, ECC; returns done - stime     |
 | nand/nand-media.c  |                                          |
 +--------------------+                                          |
        | per-command latency = max over its operations          |
        v                                                        |
 expire_time = stime + latency                                   |
        |                                                        |
        v                                                        |
 +--------------------+   host link, firmware CPU, then the      |
 | poller completion  |   priority queue by expire_time  <-------+
 +--------------------+
        |
        v
 CQE posted on the first sweep at or after expire_time
```

| Mode | Engine | Built in | Called from |
| --- | --- | --- | --- |
| BBSSD, CSD | media layer | `bb_nand_media_init()` in `bbssd/ftl-media.c` | FTL thread |
| KV | media layer, through the BBSSD wrapper | `ssd_init()` from `kvssd/kvssd-ftl.c` | poller |
| ZNS | media layer | `zns_nand_media_init()` in `zns/zftl.c` | FTL thread |
| `femu-cxl-ssd` | media layer, through the BBSSD wrapper | `femu_cxl_start()` in `cxlssd/cxlssd.c` | `femu-cxl-ftl` worker |
| OCSSD 1.2, 2.0 | `timing-model/timing.c` | `init_nand_flash()` | poller |
| NoSSD | none | | |

## Geometry

Every mode that models NAND describes it with the same hierarchy. Only the
names of the properties and the field widths differ.

```text
 device
 +-- channel 0 .. nchs-1             one shared bus per channel
     +-- LUN 0 .. luns_per_ch-1      a die: runs one array operation at a time
         |                           (one per plane under the ZNS plane gate)
         +-- plane 0 .. pls_per_lun-1
             +-- block 0 .. blks_per_pl-1   erase unit
                 +-- page 0 .. pgs_per_blk-1  program and read unit
                     +-- sector 0 .. secs_per_pg-1  (secsz bytes each)

 BBSSD line (superblock) k = block k on every (channel, LUN, plane)
 lines = blks_per_pl     pages per line = nchs * luns_per_ch * pls_per_lun * pgs_per_blk
```

### Address formats

| Mode | Address | Fields, low bit first | Where |
| --- | --- | --- | --- |
| BBSSD, CSD, KV | `struct ppa` | blk 16, pg 16, sec 8, pl 4, lun 7, ch 12, reserved 1 | `bbssd/ftl.h` |
| ZNS | `struct ppa` | spg 2, pg 16, blk 16, fc (LUN) 8, pl 3, ch 7, valid 1, reserved 8 | `zns/zns.h` |
| OCSSD 1.2 | 64-bit PPA with masks and offsets from the geometry | ch, lun, pln, blk, pg, sec | `PPA_*` macros in `nand/nand.h` |
| OCSSD 2.0 | 64-bit LBA with group, parallel unit, chunk, sector fields | group, PU, chunk, sector | `OC20_LBA_GET_*` in `ocssd/` |

A field width is an upper bound on its axis. `bb_check_geometry()` in
`bbssd/ftl-geom.c` refuses a count larger than its field can hold, and refuses
a geometry whose total sector count does not fit in a signed 32-bit integer.
`zns_check_params()` bounds each ZNS axis by its field. `oc_timing_geometry_ok()`
requires every OCSSD axis to be non-zero, `lnum_ch` at most 32 and
`lnum_ch * lnum_lun` at most 128, the sizes of the per-chip arrays.

### How pages land on the geometry

The timing a workload sees depends on where the FTL puts its pages, because
the media model only charges what it is asked to.

- **BBSSD, CSD, KV** allocate from a write pointer that moves channel first,
  then LUN, then plane, then page
  (`ssd_advance_write_pointer_common()` in `bbssd/ftl-line-gc.c`). Consecutive
  pages of a large write therefore land on different channels, then different
  LUNs, and are programmed in parallel.
- **ZNS** buffers writes in a per-zone write cache. A flush programs one
  program unit per plane: `zns_flash_type` pages of 16 KiB (`ZNS_PAGE_SIZE`)
  per plane, charged as one program operation per plane (`zns_wc_flush()` in
  `zns/zftl.c`). A 4 KiB logical page is a sub-page (`spg`) of a 16 KiB page.
- **OCSSD** takes physical addresses from the host, so the host chooses the
  parallelism.

## Data structures

The media layer's types are in `hw/femu/nand/nand-media.h`.

| Type | Fields that matter | Role |
| --- | --- | --- |
| `NandLoc` | `ch`, `lun`, `pl`, `blk`, `pg`, `flash_type`, `page_type`, `pe_cycles`, `age_sec` | One operation's position and the facts timing depends on. Filled by the mode's decoder (`bb_decode_loc()`, `zns_advance_status()`). |
| `NandMediaTiming` | `rd_ns`, `wr_ns`, `er_ns` (flat); `rd_table_ns`, `wr_table_ns`, `er_table_ns` (by cell and page type); `pgtype_mult`; `cmd_addr_ns`, `page_xfer_ns`, `status_ns`; `tplebsy_ns` and three unused multi-plane and cache-read times; `ecc_*`; `tsusp_ns` | Every duration. |
| `NandMediaPolicy` | `array_gate`, `channel_mode`, `pe_suspend`, `ecc_on_read`, `use_flat_timing`, `cache_read` | Which mechanisms are on. |
| `NandTimelineOps` | `ch_avail`, `lun_avail`, `plane_avail`, `page_reg_ready`, `lock_lun`, `unlock_lun` | Accessors that return pointers into the mode's own busy-until fields. |
| `NandMedia` | `cfg`, `bus_res` (per-channel booked windows), `susp` (per-position suspend state) | One instance per namespace FTL. |
| `NandOpCompletion` | `done_ns`, `latency_ns` | Absolute end time, and `done_ns - stime`. |

The busy-until times ("availability timestamps") live in the mode's
structures, not in the media layer:

| Resource | BBSSD, CSD, KV | ZNS | OCSSD |
| --- | --- | --- | --- |
| Channel bus | `ssd_channel.next_ch_avail_time` | `zns_ch.next_ch_avail_time` | `FemuCtrl.chnl_next_avail_time[]` plus `chnl_reservations[]` |
| LUN (die) | `nand_lun.next_lun_avail_time` | `zns_fc.next_fc_avail_time` (never consulted) | `FemuCtrl.chip_next_avail_time[]` |
| Plane | not kept | `zns_plane.next_plane_avail_time` | not kept |

Each mode configures the layer differently:

| Setting | BBSSD, CSD, KV, CXL | ZNS |
| --- | --- | --- |
| `array_gate` | `NAND_GATE_LUN_ONLY` | `NAND_GATE_PLANE_ONLY` |
| `channel_mode` | `NAND_CH_STAGED` when any bus phase is non-zero, else `NAND_CH_OFF` | same rule |
| `use_flat_timing` | true when `nand_cell_type=0`, false with a cell type | false (per-type table, page type always 0) |
| `pe_suspend` | `pe_suspend` property | `zns_pe_suspend` property |
| `ecc_on_read` | true; the adder is still 0 unless `ecc_step_ns` is set | false |
| `cache_read` | false | false |

The enum also has `NAND_CH_NOOP` and `NAND_GATE_LUN_AND_PLANE`. No mode
selects either today.

## Operation timing

### Array time

`array_lat()` picks the time the die spends on the operation:

```text
 erase   : flat ? er_ns : er_table_ns[flash_type]
 read    : (flat ? rd_ns : rd_table_ns[flash_type][page_type]) + ecc_extra
 program : flat ? wr_ns : wr_table_ns[flash_type][page_type]
           if flat and pgtype_lat:  * pgtype_mult[page_type] / 1000
```

### Phase sequence of one operation

With the channel bus off (the default), an operation is one array phase:

```text
 start = max(stime, gate busy-until)
 done  = start + array time
 gate busy-until = done
```

With the bus on (`NAND_CH_STAGED`), each operation also has bus phases.
"Now" phases queue on the bus in arrival order; a read's data-out happens
after the array finishes, so it is booked as a future window
([Channel bus](#channel-bus)).

```text
 READ     |cmd/addr|..wait for die..|=== tR array ===|data-out|status|
           bus now                   die              bus later  bus later

 PROGRAM  |cmd/addr|data-in|..wait for die..|======= tPROG array =======|
           bus now  bus now                   die  (done = array end)

 ERASE    |cmd/addr|..wait for die..|=========== tBERS array ===========|status|
           bus now                   die                                 bus later
```

A program completes when its array phase ends. A read completes after its
status phase, an erase after its status phase. A zero-length phase touches
nothing, so a bus with only `pg_xfer_lat` set has no command or status cost.

### Default times

| Mode | Read | Program | Erase | Source |
| --- | --- | --- | --- | --- |
| BBSSD, CSD, KV flat (`nand_cell_type=0`) | `pg_rd_lat` 40 us | `pg_wr_lat` 200 us | `blk_er_lat` 2 ms | property defaults in `femu.c` |
| `femu-cxl-ssd` | `read-ns` 40 us | `program-ns` 200 us | `erase-ns` 2 ms | `cxlssd/qemu-adapter.c` |
| ZNS SLC | 4 us | 75 us | 2 ms | `zns/zns.h`, erase from `nand/nand.h` |
| ZNS TLC | 32 us | 937.5 us | 3 ms | same |
| ZNS QLC (default `zns_flash_type`) | 85 us | 12.196 ms | 3 ms | same |
| ZNS MLC, PLC | none built in | none built in | none built in | realize refuses them unless all three `zns_*_lat` are set |

The ZNS program time covers a whole program unit (`zns_flash_type` pages of
16 KiB on one plane). The header cites the ISSCC papers the figures come from.

## Cell types and page types

### BBSSD, CSD, KV: `nand_cell_type`

| `nand_cell_type` | Cell | Read by page type (us) | Program by page type (us) | Erase |
| --- | --- | --- | --- | --- |
| 0 | flat | `pg_rd_lat` | `pg_wr_lat`, optionally scaled by `pgtype_lat` | `blk_er_lat` |
| 1 | SLC | 40 | 800 | 2 ms |
| 2 | MLC | lower 48, upper 64 | lower 850, upper 2300 | 3 ms |
| 3 | TLC | 56.5, 77.5, 106 | 820.5, 2225, 5734 | 3 ms |
| 4 | QLC | 59.325, 85.25, 127.2, 169.6 | 861.525, 2447.5, 6880.8, 9174.4 | 3 ms |

Values come from `nand/nand.h`: MLC from a profile of Micron L95B parts, TLC
from SimpleSSD, QLC scaled from the TLC values. Any other value is reset to 0
with a message (`ssd_init()` in `bbssd/ftl.c`); PLC has no table here. With a
cell type set, `pg_rd_lat`, `pg_wr_lat` and `blk_er_lat` no longer set NAND
times (`pg_rd_lat` still sets the write buffer and read cache hit cost), and
`pgs_per_blk` must be at most 512, the size of the page-type tables.

The page type of page `pg` in a block comes from the pairing tables
`mlc_tbl`, `tlc_tbl` and `qlc_tbl`, built by `init_nand_flash()` in
`nand/nand.c`; `slc_tbl` is all zeros. They follow a shadow programming order: the first pages of
a block are lower pages, then consecutive pairs of pages cycle through the
page types from lower to upper.

### BBSSD, CSD, KV: `pgtype_lat` and `cell_pages`

With `nand_cell_type=0` and `pgtype_lat` non-zero, the flat program time is
multiplied by a factor that depends on the page's position in its wordline.
The page type is `pg % cell_pages`; `cell_pages` 0 is set to 3 when
`pgtype_lat` is on (`ssd_init()`). The factors, in thousandths, are in
`bb_nand_media_init()`:

| `cell_pages` | Page type 0 | 1 | 2 | 3 | 4 |
| --- | --- | --- | --- | --- | --- |
| 1 | 1000 | | | | |
| 2 | 600 | 1400 | | | |
| 3 | 600 | 1000 | 1400 | | |
| 4 | 500 | 850 | 1150 | 1500 | |
| 5 | 400 | 750 | 1000 | 1250 | 1600 |

Each row averages to 1000, so the mean program time stays `pg_wr_lat` when
`pgs_per_blk` is a multiple of `cell_pages`.
Reads and erases are not scaled.

### ZNS and OCSSD

ZNS keeps one read, program and erase time per cell type and always uses page
type 0. Each `zns_*_lat` property replaces the built-in value for the
configured `zns_flash_type` only. OCSSD uses the `nand_cell_type` tables
above, selected by `flash_type`; Open-Channel 1.2 looks up the page type of
each page, Open-Channel 2.0 always uses page type 0.

## Channel bus

The bus is modelled only when a phase has a duration: `cmd_addr_lat`,
`pg_xfer_lat` (or `ch_xfer_lat` when `pg_xfer_lat` is 0) or `status_lat` for
BBSSD, CSD and KV; `zns_cmd_addr_lat`, `zns_pg_xfer_lat` or `zns_status_lat`
for ZNS. Otherwise transfers take no time and channels never contend.

Two kinds of phase share a channel:

- `bus_now()`: command/address, a program's data-in. It starts at
  `max(earliest, ch_avail)`, moves past any booked window it would overlap,
  and advances `ch_avail` to its end.
- `bus_later()`: a read's data-out and status, which happen after the array
  finishes. It starts no earlier than `ch_avail` and is booked as a window `[start, end)` in `bus_res[ch]` and does
  not advance `ch_avail`, so another die's "now" phase can use the bus before
  the window opens.

Windows that ended before the current operation's `stime` are pruned. A
channel holds at most `NAND_BUS_RES_MAX` (32) windows; when it is full, the
data-out is charged FIFO from `ch_avail` instead.

```text
 channel 0 bus, cmd/addr 1 us, data 10 us (times in us)

 0   1        11 12 13                 52        62
 |P c|P data-in|R1c|R2c|.... idle .....|R1 out   |
                                       ^ booked window, R1's array ended at 52
 a phase that arrives at 20 fits in the idle gap; one that would overlap
 [52,62) moves to 62
```

## Plane parallelism and multi-plane operations

The array gate decides which operations exclude each other:

```text
 LUN gate (BBSSD, CSD, KV)             plane gate (ZNS)
 LUN 0: [pl0 op][pl1 op][pl0 op]       LUN 0 pl0: [op][op]
        one at a time per LUN                pl1: [op][op]  in parallel
```

Under the LUN gate, all planes of a LUN are busy together, so
`pls_per_lun > 1` adds capacity and line width but no single-operation
parallelism, except for the one batched operation below.

`nand_media_multiplane()` runs one operation on several planes of a LUN:

```text
 per plane i:  cmd/addr on bus (+ data-in for a program); tplXbsy between planes
 array:        start = max(bus end, gate of every plane); done = start + array time
 read:         status, then per plane cmd/addr + data-out (booked windows)
 program/erase: status (if set)
```

| Operation | Batched across planes | Caller |
| --- | --- | --- |
| Erase of a line's block on every plane of a LUN | yes, one erase time plus `tplebsy` per extra plane | BBSSD GC (`bbssd/ftl-line-gc.c`), FDP GC (`bbssd/ftl-fdp.c`), KV reclaim (`kvssd/kvssd-ftl.c`) |
| Host reads and programs | no, one operation per page | `bbssd/ftl-datapath.c` |
| GC page moves | no | `gc_read_page()`, `gc_write_page()` |
| ZNS zone reset | no batching needed: each plane has its own gate, so per-plane erases overlap | `zns_zone_reset()` |
| Copyback (`nand_media_copyback()`) | not called | none |

`tplpbsy`, `tplrbsy` and `trcbsy` are accepted for compatibility and have no
effect; setting them warns at realize. With the defaults (no bus, no
`tplebsy`) a two-plane erase takes exactly one erase time.

## Program and erase suspend

With `pe_suspend` (BBSSD, CSD, KV) or `zns_pe_suspend` (ZNS), a read that
finds its LUN (ZNS: plane) running a program or erase goes ahead of it. The
layer keeps, per position, `pe_end` (when the newest program or erase there
ends) and `rd_end` (when the newest read there ends). `suspend_read_start()`
decides:

```text
 read arrives at t, gate busy until B
 if t >= B or t >= pe_end:           ordinary gate (nothing to suspend)
 elif rd_end > t:                    join the open suspension
     start = rd_end,      shift = tR
 else:                               open a suspension
     start = t + tsusp,   shift = tR + tsusp
 done = start + tR
 pe_end += shift; every gate busy-until > t += shift; rd_end = done
```

Only programs and erases are suspended: a read that finds the die busy with
another read waits for it. Reads that queue behind an open suspension pay
`tsusp_ns` once. A read that arrives after the suspension's reads have ended
opens a new one and pays it again.

Worked example, one LUN, `pg_wr_lat` 200 us, `pg_rd_lat` 40 us,
`tsusp_ns` 5 us, bus off. Numbers produced by `nand_media_op()`:

```text
 time (us)   0        50 55    95     135  150 155   195             330            530
 LUN busy    |== P ===|ss|  R1  |  R2  |= P =|ss| R3 |====== P ======|===== W2 =====|

 P  program  arrives 0     runs 0-50, 135-150, 195-330 (suspended twice)
 R1 read     arrives 50    opens a suspension: starts 50 + 5, done 95
 R2 read     arrives 60    joins it behind R1: starts 95, done 135, no tsusp
 R3 read     arrives 150   R1 and R2 are over, so it opens a new one: 155-195
 W2 program  arrives 160   waits for the LUN until P ends: 330-530
 (ss = tsusp_ns)

 P's die time: 200 alone; with the reads 200 + (5+40) + 40 + (5+40) = 330
```

P's own command still completes at 200. Its latency was computed when it
was issued and is never revisited. Suspension moves only the die's
busy-until time, from 200 to 330, so operations issued afterwards, such as
W2, start after 330. A suspended program or erase never makes its own
command complete afterwards; it delays the commands that follow.

`nand_media_multiplane()` does not consult the suspend state, so a read
issued through it never suspends; only erases use it today. The state is
read and written without a lock, so operations on one position must be
serialized. BBSSD and ZNS run them on the single FTL thread. A device
with suspend on also leaves the lock-free fast path described in
[Concurrency](#concurrency).

## ECC read time

`ecc_step_ns` adds read time for worn or old data (`ecc_extra_ns()`):

```text
 tiers = pe_cycles / 750  +  age_sec / ecc_retention_sec   (second term only if set)
 tiers = min(tiers, 4)
 extra read time = tiers * ecc_step_ns
```

`pe_cycles` is the block's erase count, `age_sec` the time since its line was
filled (`line.close_time`). The constants are `FEMU_ECC_PE_PER_TIER` and
`FEMU_ECC_MAX_TIERS` in `bbssd/ftl.h`. A multi-plane read pays the largest
extra of its planes. Read-retry as a sequence of separate array reads is not
modelled; this adder stands in for it. ZNS and OCSSD have no ECC time.

## From operations to a completion time

### The per-operation rule

For every resource the operation needs, it starts no earlier than that
resource's busy-until time, and it moves the resource's busy-until time to
when it stops using it. With the bus off and the LUN gate this reduces to:

```text
 done(op)      = max(stime, lun_avail) + array_time(op)
 lun_avail     = done(op)
 latency(op)   = done(op) - stime
```

`stime` is the command's submission time, stamped by the poller from
`QEMU_CLOCK_REALTIME` (`nvme-io.c`; a test-only property switches it to the
virtual clock). Background work (GC) passes `stime = 0`,
which the wrappers replace with the current time.

### The per-command rule

The FTL issues all of a command's NAND operations with the command's `stime`
and returns the largest latency:

```text
 latency(cmd) = max over the command's operations of latency(op)
                (and of write buffer, read cache and mapping cache costs)
 expire_time  = stime + latency(cmd)            femu_ftl_thread(), femu.c
```

Then the poller adds the optional [host link and firmware CPU](#host-link-and-firmware-cpu)
models and queues the request in a priority queue ordered by `expire_time`.
The completion is posted on the first poller sweep at or after it.

### Worked example: operations overlapped across LUNs and channels

Geometry 2 channels by 2 LUNs, 1 plane, flat 40 us read and 200 us program,
staged bus with `cmd_addr_lat=1000` and `pg_xfer_lat=10000`. Four operations
arrive at time 0 in this order. The numbers are what `nand_media_op()`
returns.

```text
 op   target       arrives
 P    ch0 LUN0     0       program
 R1   ch0 LUN1     0       read
 R2   ch0 LUN0     0       read (same LUN as P)
 R3   ch1 LUN0     0       read (other channel)

 time (us)   0 1   11 12 13      51 52  62          211        251 261
 ch0 bus     |c|-d--|c |c |       .  |o1-|            .          |o2-|
             P P    R1 R2             R1             .           R2
 ch0 LUN0      .    [===== P tPROG 200 ======================)[R2 tR )
 ch0 LUN1           [R1 tR 40)
 ch1 bus     |c|                 |o3-|
 ch1 LUN0      [R3 tR 40)

 done:  P 211   R1 62   R2 261   R3 51
```

- P: command 0-1, data-in 1-11, array 11-211.
- R1: its command waits for P's data-in (11-12), its array runs on the idle
  LUN1 (12-52), its data-out is booked 52-62.
- R2: command 12-13, then waits for LUN0 until P ends at 211, array 211-251,
  data-out 251-261.
- R3: on channel 1, which nothing else uses: 0-1, 1-41, 41-51.

With the bus off, the same four operations end at P 200, R1 40, R2 240,
R3 40. With `pe_suspend=1` and `tsusp_ns=5000`, R2 suspends P instead: it
starts at 13 + 5 = 18, ends its array at 58, waits for R1's booked window and
moves its data at 62-72 (done 72), and the die stays busy until 256. P's
own completion stays at 211.

If R1 and R2 were the two pages of one 8 KiB read command, its media latency
would be max(62, 261) = 261 us.

### Worked example: full command completion

A host read of two written 4 KiB pages on idle LUNs of the default BBSSD (bus off),
with `pcie_bandwidth_mbps=4000`, `pcie_prop_delay_ns=500` and
`fw_cpu_ns=1000`, submitted at time S:

```text
 S                       stime stamped by the poller
 S + 40 000              FTL: max(40 000, 40 000) -> expire_time
 S + 40 000 .. 42 048    link: 8192 B * 1000 / 4000 MB/s = 2 048 ns on the
                         device-to-host queue (starts at max(queue free, expire))
 S + 42 548              + propagation 500 ns
 S + 42 548 .. 43 548    firmware core: max(core free, expire) + 1 000 ns
 S + 43 548              expire_time; CQE posted on the first sweep at or after it
```

The link and firmware queues are shared by every command of the controller,
so under load each command also waits for the ones queued before it on those
queues.

### Concurrency

- BBSSD and ZNS call the layer from the single `FEMU-FTL-Thread`, so their
  timelines need no lock. KV calls it from the poller and `femu-cxl-ssd` from
  its `femu-cxl-ftl` worker, each under its own device lock.
- With the LUN gate, no bus and no suspend, `nand_media_op()` updates
  `next_lun_avail_time` with a compare-and-swap loop that gives the same
  result as a locked read-max-add-store. Any other configuration takes the
  general path, which calls `lock_lun`/`unlock_lun` when the mode provides
  them; BBSSD and ZNS do not.
- The OCSSD model takes a spinlock per chip and per channel.

## How garbage collection is charged

GC operations go through the same timelines as host operations, with
`stime = 0` (the current time) and `type = GC_IO`:

- `gc_read_page()` charges a read of each valid page, `gc_write_page()` a
  program at its new location, and `reclaim_line()` one multi-plane erase
  per LUN (`bbssd/ftl-line-gc.c`). All of a victim's pages are moved before
  any of its blocks is erased, so the erases follow the last relocation.
  FDP GC does the same in `bbssd/ftl-fdp.c`.
- The returned latency is discarded. GC never adds to a command's latency
  directly. It makes LUNs and channels busy, and the host operations that
  need them afterwards wait.
- **Foreground GC** runs when the share of used lines has reached
  `gc_thres_pcent_high`: at the start of `ssd_write()`, and before each page
  that a write, a write buffer destage or a Write Zeroes programs
  (`bbssd/ftl-datapath.c`), until the share drops below it. The command's own programs then queue behind the
  GC operations on the LUNs they share.
- **Read reclaim** (`read_reclaim_limit`, `retention_limit_sec`) rewrites one
  queued line through `reclaim_line()` at the start of a write, charged the
  same way as GC.
- **Background GC** runs one victim after a request finishes in
  `bb_ftl_process_req()` (`bbssd/ftl.c`), once the latency of that request
  has been computed. It delays the commands that follow.
- Because GC is stamped with the current time and a host command with its
  submission time, a command submitted before a GC pass can still wait for it
  when the FTL thread gets to the command after the pass.
- GC time can be turned off with 0xEF code 2 ([Runtime switches](#runtime-switches)).
  GC still moves pages and erases blocks; its operations are then not
  charged at all.

```text
 LUN 3 timeline during foreground GC for one write (bus off)
 |-- GC read --|-- GC program --| ... |== multi-plane erase ==|-- host program --|
 ^ write arrives                                                                  ^ write's done
```

KV is different. Its reclaim erases and compaction moves are stamped with
the triggering command's `stime`, the command completes when the last of
them and of its own operations does (`kvssd/kvssd-ftl.c`), and 0xEF does not
apply to KV, so they cannot be switched off.

ZNS has no device GC. A Zone Reset charges one erase per block of the zone on
every plane it spans, with the command's `stime`, and returns the largest
(`zns_zone_reset()`).

### Costs that are not NAND operations

The FTL adds these to a command's latency alongside its NAND operations:

- **BBSSD write buffer** (`buffer_size` > 0): a write the buffer accepts costs
  `pg_rd_lat / 16` (1 us when `pg_rd_lat` is 0), plus the programs of any
  destage it forces. A Flush pays for programming everything buffered
  (`bbssd/ftl.c`). A read of a buffered page costs the same DRAM access.
- **BBSSD read cache and DFTL mapping cache**: a hit costs a DRAM access; a
  mapping miss adds a NAND read of the translation page, after a program if
  the evicted entry is dirty.
- **ZNS write cache**: a write only enters the zone's write cache and pays
  `SRAM_WRITE_LATENCY_NS` (1 us) per 4 KiB page, summed over the command
  (`zns_write()` in `zns/zftl.c`). It pays program time only when the cache
  fills, or when it has to evict another zone's cache. A cache holds one
  stripe: 16 KiB * `zns_flash_type` * `zns_num_plane` * `zns_num_ch` *
  `zns_num_lun`. A read of data still in the cache is not mapped yet and
  costs nothing.

## Host link and firmware CPU

Both are applied in `nvme_process_cq_cpl()` in `hw/femu/nvme-io.c`, after the
media latency is in `expire_time` and before the request enters the priority
queue. Both are off by default.

| Model | Applies to | Computation |
| --- | --- | --- |
| Link transfer (`pcie_bandwidth_mbps`) | NVMe Read and Write (opcodes 01h and 02h) in BBSSD, CSD, KV, ZNS and NoSSD; KV store and retrieve share those opcodes and use the bytes moved. Not Zone Append, and not the Open-Channel vector commands, so OCSSD 1.2 never pays it | `trans = bytes * 1000 / MBps` ns. One queue per direction: writes on `pcie_rx_next_avail_time`, reads on `pcie_tx_next_avail_time`. `start = max(queue, expire)`, `queue = start + trans` |
| Propagation (`pcie_prop_delay_ns`) | same | `expire = queue + delay`; does not occupy the queue |
| Firmware CPU (`fw_cpu_ns`) | Read, Write (01h, 02h) and Zone Append; not the Open-Channel vector commands | one modelled core: `start = max(core, expire)`, `core = start + fw_cpu_ns`, `expire = core` |

The link is modelled after the media for both directions. A read's transfer
to the host never overlaps its NAND time, and a write's transfer from the
host is charged after its programs, not before them. The firmware cost is charged at the end of a command,
which caps the command rate at about one per `fw_cpu_ns` but does not delay
the start of the media operations. The link model is enabled when either link property is non-zero
(`pcie_enabled` in `femu.c`).

## OCSSD timing model

Open-Channel devices use `hw/femu/timing-model/timing.c`:

- `advance_chip_timestamp()`: per chip (flat LUN id `ch * num_lun + lun`), if
  the chip is busy, its busy-until time grows by the operation time;
  otherwise it becomes `now + time`. That is the same as
  `max(now, busy) + time`. Times come from the `flash_type` table.
- `advance_channel_timestamp()` books a transfer FIFO on the channel;
  `advance_read_channel_timestamp()` books a read's data-out as a future
  window, the same idea as `bus_later()`.
- A write moves its data over the channel, then programs the chip. A read
  occupies the chip, then moves its data out. Erase charges each chip in the
  address list.
- Open-Channel 1.2 charges a channel transfer only with
  `oc12_channel_timing=on`: `ch_xfer_lat` ns per page, or the table value
  for `flash_type` when it is 0, scaled by the sectors used out of
  `lsecs_per_pg`. Open-Channel 2.0 charges no channel time and uses page
  type 0.
- Open-Channel 1.2 charges one chip operation per NAND page of the address
  list. Open-Channel 2.0 groups addresses that differ only in the sector
  field, which spans the whole chunk, so a run of consecutive sectors in one
  chunk pays one chip operation whatever its length.
- The latency is `max over operations of (done - stime)`, written straight
  into `expire_time` in the poller (`oc12_advance_status()`,
  `oc20_advance_status()`).
- Open-Channel 1.2 keeps its data-out windows in an unbounded list per
  channel, where the media layer caps its list at 32.

## Runtime switches

A BBSSD controller accepts the vendor admin command 0xEF (`bb_flip()` in
`bbssd/bb.c`). The action is in CDW10. For codes 1 to 4 it pauses the
pollers, applies the change to every namespace of the controller that has a
BBSSD FTL, and resumes them. Controllers of every other mode return Invalid
Opcode.

| CDW10 | Constant (`bbssd/ftl.h`) | Effect on timing |
| --- | --- | --- |
| 1 | `FEMU_ENABLE_GC_DELAY` | GC operations are charged (default) |
| 2 | `FEMU_DISABLE_GC_DELAY` | GC operations are not charged |
| 3 | `FEMU_ENABLE_DELAY_EMU` | Flat read, program and erase set to the built-in 40 us, 200 us and 2 ms, not to the command-line values |
| 4 | `FEMU_DISABLE_DELAY_EMU` | Flat read, program and erase set to 0 |
| 5 | accounting reset | Prints and resets the per-poller completion counters; no timing change |
| 6, 7 | `FEMU_ENABLE_LOG`, `FEMU_DISABLE_LOG` | Per-command debug log on or off; no timing change |

Codes 3 and 4 refresh only the flat `rd_ns`, `wr_ns` and `er_ns` in the
media layer (`bb_nand_media_refresh_timing()`). With `nand_cell_type` 1 to 4
the flat times are not used, so the codes have no effect on NAND time. They
never change the channel bus phases, `pgtype_lat`, ECC time or
`trim_lat_ns`. Code 4 makes a write buffer hit cost 1 us; the read cache
keeps the hit cost it computed at start.
On a controller linked to a `femu-cxl-ssd`, codes 1 to 4 change the medium's
FTL instead, and code 3 restores its `read-ns`, `program-ns` and `erase-ns`.

From the guest:

```sh
sudo nvme admin-passthru /dev/nvme0 --opcode=0xef --cdw10=2   # stop charging GC
sudo nvme admin-passthru /dev/nvme0 --opcode=0xef --cdw10=4   # zero NAND times
```

The vendor command 0xEE (`NVME_ADM_CMD_FEMU_DEBUG`) sets an Open-Channel
controller's NAND times at run time, in nanoseconds: CDW10 upper page read,
CDW11 lower page read, CDW12 upper page program, CDW13 lower page program,
CDW14 block erase and CDW15 channel transfer per page. The lower page is
page type 0 and the upper page the highest page type of `flash_type`; the
centre pages of TLC and QLC keep their table times, and SLC, with one page
type, takes the lower page values. The times belong to that controller
(`FemuCtrl.oc_pg_rd_lat` and the fields beside it, filled from the
`flash_type` table by `set_latency()`), so other devices are not affected.
Other modes refuse 0xEE with Invalid Field.

```sh
sudo nvme admin-passthru /dev/nvme0 --opcode=0xee --cdw10=64000 --cdw11=48000 \
    --cdw12=2300000 --cdw13=850000 --cdw14=3000000 --cdw15=52433
```

## Parameters

The generated [property reference](../reference/properties.md) is the
authority for types, defaults and ranges. This table groups the timing
properties and states how they interact.

| Group | Properties | Interactions |
| --- | --- | --- |
| [Geometry](../reference/properties.md#nand-geometry-bbssd-csd-kv) | `secsz`, `secs_per_pg`, `pgs_per_blk`, `blks_per_pl`, `pls_per_lun`, `luns_per_ch`, `nchs` | `nchs * luns_per_ch` is the number of independent dies. `pls_per_lun` adds no read or program parallelism under the LUN gate. |
| [Array times](../reference/properties.md#nand-timing-bbssd-csd-kv) | `pg_rd_lat`, `pg_wr_lat`, `blk_er_lat` | Ignored when `nand_cell_type` is 1 to 4. 0xEF codes 3 and 4 overwrite them. `pg_rd_lat / 16` is also the cost of a write buffer hit. |
| [Cell type](../reference/properties.md#nand-timing-bbssd-csd-kv) | `nand_cell_type`, `cell_pages`, `pgtype_lat` | `pgtype_lat` applies only with `nand_cell_type=0`. `nand_cell_type` limits `pgs_per_blk` to 512. |
| [Bus phases](../reference/properties.md#nand-timing-bbssd-csd-kv) | `cmd_addr_lat`, `pg_xfer_lat`, `ch_xfer_lat`, `status_lat` | Any non-zero value turns the bus on. `pg_xfer_lat` takes precedence over `ch_xfer_lat`. |
| [Multi-plane](../reference/properties.md#nand-timing-bbssd-csd-kv) | `tplebsy` (`tplpbsy`, `tplrbsy`, `trcbsy` have no effect) | Used only by multi-plane erase, so only with `pls_per_lun > 1`. |
| [Suspend](../reference/properties.md#nand-timing-bbssd-csd-kv) | `pe_suspend`, `tsusp_ns` | `tsusp_ns` matters only with `pe_suspend`. |
| [ECC](../reference/properties.md#reliability-and-wear) | `ecc_step_ns`, `ecc_retention_sec` | `ecc_retention_sec` matters only with `ecc_step_ns`. |
| [Other FTL costs](../reference/properties.md#nand-timing-bbssd-csd-kv) | `trim_lat_ns` | Charged per Dataset Management range by the FTL, not by the media layer. Refused with FDP. |
| [ZNS](../reference/properties.md#zns) | `zns_num_ch`, `zns_num_lun`, `zns_num_plane`, `zns_num_blk`, `zns_flash_type`, `zns_pg_rd_lat`, `zns_pg_wr_lat`, `zns_blk_er_lat`, `zns_cmd_addr_lat`, `zns_pg_xfer_lat`, `zns_status_lat`, `zns_pe_suspend`, `zns_tsusp_ns` | The `zns_*_lat` overrides apply to the configured cell type only. `zns_num_plane` scales the program unit. |
| [OCSSD](../reference/properties.md#ocssd-open-channel) | `flash_type`, `oc12_channel_timing`, `ch_xfer_lat`, `lnum_ch`, `lnum_lun`, `lnum_pln`, `lsecs_per_pg`, `lpgs_per_blk` | `ch_xfer_lat` is shared with BBSSD. `lnum_ch` is at most 32 and `lnum_ch * lnum_lun` at most 128. |
| [Host link and firmware](../reference/properties.md#host-link-and-controller-firmware) | `pcie_bandwidth_mbps`, `pcie_prop_delay_ns`, `fw_cpu_ns` | Applied after the media time, to the opcodes listed in [Host link and firmware CPU](#host-link-and-firmware-cpu). |
| [`femu-cxl-ssd`](../reference/properties.md#nand-geometry-and-timing) | `channels`, `luns-per-channel`, `pages-per-block`, `blocks-per-plane`, `read-ns`, `program-ns`, `erase-ns`, `channel-ns` | One plane per LUN; feeds the same media layer. |

A BBSSD configuration with the bus and suspend on:

<!-- femu-example: nand-timing-staged -->
```text
-device femu,devsz_mb=1024,femu_mode=1,cmd_addr_lat=1000,pg_xfer_lat=10000,pe_suspend=1,tsusp_ns=5000
```

A BBSSD with TLC page-type timing:

<!-- femu-example: nand-timing-tlc -->
```text
-device femu,devsz_mb=1024,femu_mode=1,nand_cell_type=3
```

## Statistics

The media layer keeps no counters of its own. What it charges shows up in:

- **Latency seen by the guest**: `fio` completion latency. This is the
  primary output of the model.
- **Vendor log page C0h** (BBSSD, CSD): host, NAND and GC page counts, write
  amplification, buffer hits. See
  [log pages and counters](../reference/log-pages-and-counters.md).
- **Per-block counters** used by the model: `nand_block.erase_cnt` (ECC
  tiers, SMART Percentage Used) and `nand_block.read_cnt` (read reclaim),
  updated in `ssd_advance_status()` and on erase.
- **`femu-cxl-ssd`**: the QOM counter `media-time-ns`, the sum of the
  latencies the FTL returned. See
  [runtime properties](../reference/runtime-properties.md).
- **Debug**: `nand_lun.gc_endtime` records when the last GC operation on a
  LUN ends; nothing reports it.

## Calibrating against a real device

1. **Take array times from the datasheet.** `pg_rd_lat` is tR,
   `pg_wr_lat` is tPROG, `blk_er_lat` is tBERS. For a part with different
   lower and upper page times, either use `nand_cell_type` if one of the
   built-in tables is close, or set the mean tPROG and turn on `pgtype_lat`
   with `cell_pages` equal to bits per cell.
2. **Derive the bus phases from the interface rate.** `pg_xfer_lat` is the
   page size divided by the interface rate: a 16 KiB page on an 8-bit bus at
   1600 MT/s takes 16384 / 1.6e9 s, about 10.2 us. `cmd_addr_lat` and
   `status_lat` are the command, address and status cycle times, usually well
   under 1 us.
3. **Match the parallelism.** Set `nchs` and `luns_per_ch` to the device's
   channels and dies per channel, and `secs_per_pg * secsz` to its page size.
4. **Check the unloaded latency.** Write the range first (a read of an
   unwritten page costs nothing), then run a queue depth 1 4 KiB random read.
   The median completion latency should be about tR plus the data-out and
   status phases plus guest and poller overhead. Measure that overhead once
   with flat timing, no bus phases, no caches and 0xEF code 4, and subtract
   it.
5. **Check the saturated throughput.** A random read at high queue depth
   should approach `nchs * luns_per_ch / tR` operations per second when the
   bus is not the limit, or `nchs / (pg_xfer_lat + cmd_addr_lat + status_lat)`
   when it is. Compare with the real device at the same queue depth.
6. **Add the host side.** If the real device's peak is below what the media
   allows, set `pcie_bandwidth_mbps` to its link rate and `fw_cpu_ns` to
   the inverse of its peak command rate.
7. **Check GC separately.** Precondition the device, run sustained random
   writes, and compare the write amplification in log page C0h and the
   steady-state write bandwidth. Toggle 0xEF codes 1 and 2 to see how much of
   the gap GC time explains.

Give each poller and the FTL thread its own host core while measuring;
[performance tuning](../guides/performance-tuning.md) and
[measuring](../guides/measuring.md) cover the setup.

## Validation status

- **Unit tests**: `hw/femu/tests/unit/test-nand-media.c` checks the media
  layer's arithmetic without QEMU: ECC tiers, the staged bus and its booked
  windows, the plane gate with the bus, multi-plane erase against serial
  erases, copyback, and program/erase suspend. Run it with
  `make -C hw/femu/tests check`.
- **qtests**: `hw/femu/tests/qtest/femu-test.c` covers the OCSSD 1.2 channel
  model (`oc12-channel-timing`, `oc12-channel-gap`, `oc12-channel-default`,
  `oc12-channel-off`, `oc12-ppa-timing`, `oc12-flash-type`, `oc12-page-count`,
  `oc12-transfer-cost`, and the exact per-command times of `oc12-trace-on` and
  `oc12-trace-off`), the warning for the timing properties that have no
  effect (`ignored-props`), the 0xEF flips on a linked `femu-cxl-ssd`
  (`cxl-nvme-flip`), and the two example configurations on this page
  (`doc-examples`).
- **Not covered by automated tests**: BBSSD and ZNS timing inside QEMU, the
  host link, `fw_cpu_ns`, the 0xEF flips on a plain BBSSD controller, and
  end-to-end guest latency against a reference device. The built-in MLC table is a profile of real
  parts; the other tables are from published papers, as cited in the
  headers. Check numbers that matter to you with the calibration steps above.

```sh
make -C hw/femu/tests check
```

## What is not modelled

- Read-retry as repeated array reads, soft-decision decoding, and read
  disturb errors. The ECC adder is a fixed time per tier, and data is never
  corrupted.
- Multi-plane reads and programs: host pages are issued one plane at a time.
  Only line erases are batched.
- Cache read pipelining: the code path exists but no mode enables it. There
  is no cache program model.
- Copyback for GC. The function exists and has no caller, because GC's
  destination is almost never on the source LUN.
- Program suspend for programs, or erase suspend by another erase. Only reads
  suspend.
- Per-die power or thermal limits, and temperature-dependent timing.
- Plane-level parallelism for BBSSD, CSD and KV reads and programs (the gate
  is per LUN), and the channel bus for OCSSD 2.0.
- PLC outside ZNS. ZNS accepts PLC with times you supply; BBSSD resets
  `nand_cell_type=5` to 0 and OCSSD refuses `flash_type=5`.
- Queueing inside the controller other than the link and the single
  firmware core: there is no DRAM bandwidth or NAND controller queue model.
- Timing accuracy below the poller sweep. A completion is posted on the first
  sweep after it is due, and a poller without its own host core adds delay.

## Adding a timing feature

1. **Decide the resource.** If the feature makes an existing resource busy for
   longer, it is an `array_lat()` or bus-phase change. If it adds a resource,
   add an accessor to `NandTimelineOps` and keep the state in the mode's
   structures, like the existing busy-until fields.
2. **Add the duration to `NandMediaTiming` and a switch to `NandMediaPolicy`**
   in `nand/nand-media.h`. Default it to 0 or off so that existing
   configurations keep their exact timing. The layer must not include a
   controller header or branch on the mode.
3. **Implement it in `nand-media.c`.** Keep the max() ordering of the existing
   paths. A phase that happens at issue goes through `bus_now()`; one that
   happens after the array goes through `bus_later()`.
4. **Wire the property.** Add it with `DEFINE_PROP_*` in `femu.c` and a
   description in `femu-props.c`, copy it into `ssdparams` in
   `ssd_init_params()` (`bbssd/ftl-geom.c`), validate it in
   `bb_check_geometry()`, and set the media config in `bb_nand_media_init()`.
   For ZNS, the same in `zns_init_params()` and `zns_nand_media_init()`.
5. **Test the arithmetic** in `tests/unit/test-nand-media.c`. Include a case
   that fails if the feature is ignored, so the test cannot pass with the
   feature off.
6. **Update the docs.** Regenerate the property reference with
   `gen-property-docs.py`, add the parameter to this page and to the
   [timing model concept page](../concepts/timing-model.md), and add a
   CHANGELOG entry. [Keeping the documentation
   correct](../development/docs-maintenance.md) lists the checks.

## Source map

| File | What it holds |
| --- | --- |
| [`hw/femu/nand/nand-media.h`](../../nand/nand-media.h) | Media layer types and API: `NandLoc`, `NandMediaTiming`, `NandMediaPolicy`, `NandTimelineOps`, `nand_media_op()`, `nand_media_multiplane()`, `nand_media_copyback()` |
| [`hw/femu/nand/nand-media.c`](../../nand/nand-media.c) | Array time, gates, bus booking (`bus_now()`, `bus_later()`), suspend, ECC, multi-plane, copyback |
| [`hw/femu/nand/nand.h`](../../nand/nand.h), [`nand.c`](../../nand/nand.c) | Cell-type timing tables, page pairing tables, rated P/E cycles |
| [`hw/femu/bbssd/ftl-media.c`](../../bbssd/ftl-media.c) | BBSSD adapter: `bb_decode_loc()`, `bb_nand_media_init()`, `ssd_advance_status()`, `ssd_advance_status_multiplane()`, `bb_nand_media_refresh_timing()` |
| [`hw/femu/bbssd/ftl-geom.c`](../../bbssd/ftl-geom.c) | Geometry checks and parameter copy (`bb_check_geometry()`, `ssd_init_params()`) |
| [`hw/femu/bbssd/ftl-datapath.c`](../../bbssd/ftl-datapath.c) | Host read and write: per-page operations and max latency |
| [`hw/femu/bbssd/ftl-line-gc.c`](../../bbssd/ftl-line-gc.c) | Write pointer order, GC reads, programs and multi-plane erase |
| [`hw/femu/bbssd/bb.c`](../../bbssd/bb.c) | 0xEF handler (`bb_flip()`, `bb_flip_apply()`) |
| [`hw/femu/zns/zftl.c`](../../zns/zftl.c) | ZNS adapter, write cache flush, zone reset erase |
| [`hw/femu/zns/zns.c`](../../zns/zns.c), [`zns.h`](../../zns/zns.h) | ZNS timing values and property overrides (`zns_init_params()`) |
| [`hw/femu/timing-model/timing.c`](../../timing-model/timing.c) | OCSSD chip and channel timestamps |
| [`hw/femu/ocssd/oc12.c`](../../ocssd/oc12.c), [`oc20.c`](../../ocssd/oc20.c) | OCSSD per-command timing (`oc12_advance_status()`, `oc20_advance_status()`) |
| [`hw/femu/femu.c`](../../femu.c) | FTL thread: `expire_time += latency`; timing properties |
| [`hw/femu/nvme-io.c`](../../nvme-io.c) | `stime` stamp, host link and firmware CPU models, priority queue and completion |
| [`hw/femu/tests/unit/test-nand-media.c`](../../tests/unit/test-nand-media.c) | Media layer unit tests |
