# Tiered NAND: a pSLC pool in front of dense NAND

Many TLC and QLC SSDs write host data to a fast cache first. The cache is
ordinary NAND that the drive programs with one bit per NAND unit (pSLC).
Later the drive moves the cached data to the dense blocks. This move is a
fold.

FEMU can model this in a [BlackBox](../modes/blackbox.md) SSD. The tier is
off by default. With the tier off, FEMU allocates no tier state, and timing,
counters and garbage collection do not change.

Use it to study the write cliff of a full cache, the cost of a fold, and
the read speed of data in the cache.

## What it models

```
 host write --> pSLC frontier --> pool line full --> fold FIFO
                    |                                    |
     pool empty:    |                                    v
     direct  --> dense frontier            read pSLC page (tier_pslc_read_ns)
     through --> fold first, then pool     program dense page (TLC/QLC time)
                                           erase pool blocks (tier_pslc_erase_ns)
                                           line back to the free pool
```

- The pool is static. `tier_static_mb` of host data sets its size in whole
  lines. The pool lines come from the over-provisioning and stay pSLC for
  their life.
- A pool block holds `pgs_per_blk / b` pages, rounded down per block. `b` is
  2 for MLC, 3 for TLC and 4 for QLC (`nand_cell_type`).
- Host writes, FUA writes, Write Zeroes and Copy destinations go to the pool
  while it has a free page.
- A folded pool line is free again only when its erase ends.
- When the pool has no free page, `tier_full_policy` decides:
  - `direct` (default): the page goes to the dense lines. This also applies
    while the free pool lines still erase.
  - `through`: the write waits for the erase of a free pool line. With no
    free line, it folds the oldest pool line first and waits for that fold.
- With `direct`, the end of a request folds one pool line when the pool has
  no free page left. Version 1 has no other fold trigger.
- A fold takes the oldest full pool line. Each valid page is read in pSLC
  mode, then programmed on the dense frontier. The program starts only when
  the read data is ready.
- The erase of the pool line waits for the last program of the fold. Pages
  that the host deallocated or overwrote before the fold do not move.
- Reads of pool pages take `tier_pslc_read_ns`. Programs take
  `tier_pslc_prog_ns`. The built-in SLC times of `nand_cell_type=1` do not
  change.

The pool never enters the dense free list or the garbage collection victim
queue. Dense garbage collection works as before on the dense lines.

## Launch

The tier needs `nand_cell_type` 2 (MLC), 3 (TLC) or 4 (QLC). A 1 GiB TLC
device with a 64 MiB pool:

<!-- femu-example: tiered-nand-static -->
```
-device femu,femu_mode=1,devsz_mb=1024,nand_cell_type=3,tier_mode=static,tier_static_mb=64
```

With the default geometry a pool line holds 64 blocks of 85 pages, so the
pool takes 4 lines.

## Properties

| Property | Default | Meaning |
| --- | --- | --- |
| `tier_mode` | unset (off) | `static` or `dynamic` turns the tier on |
| `tier_static_mb` | `0` | host data in MiB the static pool holds |
| `tier_full_policy` | unset (`direct`) | `direct` or `through` |
| `tier_pslc_read_ns` | `25000` | pSLC page read time in ns |
| `tier_pslc_prog_ns` | `200000` | pSLC page program time in ns |
| `tier_pslc_erase_ns` | `3500000` | pSLC block erase time in ns |
| `tier_pslc_pe_cycles` | `0` | pSLC erase rating; 0 is 30 times the dense rating |
| `tier_max_mb` | `0` | `dynamic`: cap of the borrowed lines in MiB; 0 sets no cap |
| `tier_shrink_pct` | `50` | `dynamic`: fill in % where the pool starts to shrink |
| `tier_idle_ms` | `0` | quiet time in ms before an idle fold; 0 turns idle folds off |
| `tier_lazy_pct` | `0` | idle folds: 0 folds every closed line; else only while use is above this % |

The full descriptions are in the
[property reference](../reference/properties.md#pslc-tier-bbssd).

## Dynamic pool

With `tier_mode=dynamic`, the pool also borrows free dense lines while the
device has room. `tier_static_mb` is then a floor and can be 0. A borrowed
line goes back to the dense free list after its fold:

```
 dense free --borrow--> open --> closed (FIFO) --fold--> dense free
```

The number of borrowed lines the pool may hold falls as the device fills:

```
 lines
 max |________
     |        \
     |         \
   0 +---------+--\---> logical fill (valid host pages / exported pages)
     0      shrink   100%
```

- `max` is `tier_max_mb` in whole lines, rounded down, or every line when
  it is 0. Realize refuses a cap below one pool line.
- The fill counts mapped FTL pages. A deallocate of part of a page unmaps
  the whole FTL page, as without the tier.
- `shrink` is `tier_shrink_pct`. Above it, the allowance falls in a straight
  line to 0 at a full device.
- After each request, a pool that holds more closed borrowed lines than the
  fill allows folds the oldest ones until it does not. The open line folds
  after it fills.
- When the pool has no line and may borrow none, the end of the request
  folds the oldest pool line, as in a static pool.

FEMU borrows a line only when three rules hold:

1. The fill allows one more borrowed line.
2. The dense lines that stay still hold every valid page, plus one full pool
   line.
3. The dense free lines stay above the forced garbage collection threshold.

Before each host page, FEMU checks rule 2 again for the page. When the page
would break it, a borrowed line folds first. So a full device always has
dense room for every page, and the pool shrinks to its floor.

`tier_full_policy=through` needs a static floor, so `dynamic` with
`through` also needs `tier_static_mb` above 0.

A 4 GiB TLC device with no fixed pool and a cache of up to 1 GiB:

<!-- femu-example: tiered-nand-dynamic -->
```
-device femu,femu_mode=1,devsz_mb=4096,nchs=8,luns_per_ch=8,pgs_per_blk=256,blks_per_pl=256,nand_cell_type=3,tier_mode=dynamic,tier_max_mb=1024
```

## Idle folds

By default a pool line folds only when a host write needs room. With
`tier_idle_ms` above 0, the device also folds in idle time, so the next
burst finds free pool lines:

```
 burst --> pool full --> quiet for tier_idle_ms --> step, step, ... --> next burst
                                                     |
                          each step: at most one page per LUN, then wait
                          until the work of that step ends
```

- The idle time counts from the end of the last host request and of the
  NAND work it queued, such as GC. The PCIe transfer time is not part of it.
- A step moves at most one page from each LUN. The next step starts only
  when the programs (and, at the end of a line, the erases) of the last one
  end. So idle work adds at most one step on a LUN to a host command.
- A host request between two steps runs as usual. A fold that the request
  needs takes the half-moved line first and moves all of it.
- At the forced GC mark (`gc_thres_pcent_high`), idle folds stop until a
  host write runs GC. An idle step never runs dense GC.
- The open pool line does not fold at idle, so one open line can stay.
- `tier_lazy_pct=0` (eager) folds every closed line. A value of 1 to 99
  (lazy) folds only while the closed and open lines are above that percent
  of the pool. The pool is the static lines plus the borrowed lines the
  fill allows. Lazy keeps more recent data in pSLC.
- An idle fold of a borrowed line gives it back to the dense free list.
- Idle folds charge their time, as other folds do.

A 4 GiB TLC device with a 512 MiB static pool that folds after 100 ms of
quiet time:

<!-- femu-example: tiered-nand-idle -->
```
-device femu,femu_mode=1,devsz_mb=4096,nchs=8,luns_per_ch=8,pgs_per_blk=256,blks_per_pl=256,nand_cell_type=3,tier_mode=static,tier_static_mb=512,tier_idle_ms=100
```

## Write buffer

With `buffer_size`, host pages wait in DRAM first. A write-back places
each page as a direct write does: in the pool when it has room, else by
`tier_full_policy`. A buffered page leaves DRAM only after it has a place.

```
 host write --> DRAM buffer --> write-back --> pool page (pSLC)
                                          \-> dense page (full pool, direct)
 idle write-back: next page needs a fold --> stop, upkeep owed
 idle FTL thread: upkeep step (one page per LUN) --> pool room --> write-back
```

- The fill counts mapped pages only. A buffered page with no mapping counts
  once a write-back places it. A buffered overwrite of a mapped page counts
  once, as before.
- The idle write-back (`buffer_low_pcent`) runs no fold and no forced
  garbage collection. When the next page needs a fold, it stops and the
  pool owes an upkeep fold.
- Upkeep runs on the idle FTL thread whatever `tier_idle_ms` and
  `tier_lazy_pct` say. Each step moves at most one page of each LUN, as an
  idle fold does. It folds a stopped fold first, then a borrowed line that
  Rule B or Rule C gives back, then the oldest closed line of a full pool.
- An optional idle fold waits while the idle write-back has pages to write.
- A Flush and a foreground write-back may fold, as a direct write does.
- x-tier-check reports the upkeep steps and the idle write-backs that
  stopped for a fold.

## Capacity

The exported capacity does not change. Realize checks that the dense lines
alone can hold the whole namespace plus the garbage collection reserve. The
check counts the static pool only; a dynamic pool keeps the same rule at run
time (see [Dynamic pool](#dynamic-pool)):

```
 (lines - pool lines - reserve lines) x dense pages per line  >=  exported pages
```

Each valid pool page counts as a mapped page, so the dense lines can always
take a fold of the whole pool.

When the check fails, realize refuses the device and names the pool. Lower
`tier_static_mb`, or raise `op_pcent` or `blks_per_pl`.

## Wear

FEMU counts the pSLC erases of each block. The wear of a block is the share
of each rating it used:

```
 wear = dense erases / dense rating + pSLC erases / pSLC rating
```

The dense rating is `pe_cycles_rated`, or the rating of `nand_cell_type`.
In version 1 this figure is for tests only. SMART Percentage Used still
counts every erase against the dense rating, so it shows more wear than the
figure. The ECC wear tiers would make the same error, so realize refuses
`ecc_step_ns` with the tier.

## Counters

- Log page C0h offset 16 (pages relocated) includes the fold pages. A fold
  page is never counted twice.
- Log page C0h offset 24 (pages programmed) counts host pages in the pool
  and in the dense lines, but not fold pages.
- `query-femu` does not report the tier yet. Pool lines show as unlisted.

## Example: the write cliff

One run on a CloudLab d760 host wrote 3 GiB once, in sequence, at 128 KiB
and queue depth 32. The device was a 4 GiB TLC BlackBox SSD with 64 dies
and a 1 GiB pool:

<!-- femu-example: tiered-nand-cliff -->
```
-device femu,femu_mode=1,devsz_mb=4096,nchs=8,luns_per_ch=8,pgs_per_blk=256,blks_per_pl=256,nand_cell_type=3,tier_mode=static,tier_static_mb=1024
```

The pool takes 49 lines (1041 MiB). The write rate drops when the pool
is full:

```
 MiB/s
 1231 |##########
      |          #
   30 |           ###########################
      +----------+---------------------------> MiB written
               ~1024 (pool full)

 policy   drop at    after       folds   relocated pages
 direct   1024 MiB   29.3 MiB/s  81      440640 (81 x 5440)
 through  1008 MiB   30.1 MiB/s  96      522240 (96 x 5440)
```

Without the tier, the same write runs at about 85 MiB/s from start to end.
After the drop, host pages and fold work share the same dies, so the rate
falls below the plain TLC rate. The rates depend on the host.

## Presets

These are starting points, not values from one datasheet. Each needs a
device with enough over-provisioning for the pool.

```
 consumer TLC    nand_cell_type=3,tier_mode=static,tier_static_mb=6144
 consumer QLC    nand_cell_type=4,tier_mode=static,tier_static_mb=24576,tier_full_policy=through
 industrial TLC  nand_cell_type=3,tier_mode=static,tier_static_mb=2048
```

With the default zero bus times, a fold costs only array time. To charge
the channel too, set a bus profile such as `pg_xfer_lat` or `onfi_mode`.

## Limits

- bbssd only, with one namespace and `page` or `dftl` mapping.
- With `dftl`, translation pages stay on dense lines. They do not count in
  the fill, and the dense room for host pages leaves their lines out.
- Realize refuses the tier with FDP, KV, ZNS, CSD, OCSSD, `mapping` other
  than `page` or `dftl`, `power_loss`, Streams, `hot_cold_sep`,
  `gc_pace` and `gc_copyback`.
- Realize also refuses it with `blk_pe_limit`, `wl_spread`,
  `read_reclaim_limit`, `retention_limit_sec`, the `pd_*` properties,
  `onfi_cache_read`, `pe_suspend` and `ecc_step_ns`.
- With `mp_program`, pool pages program as multi-plane commands, as dense
  pages do. A fold first charges the programs that the multi-plane batches
  still hold, so it never reads a page before its program. That charge
  goes to the request that holds them.
- With `pe_suspend`, a read could move the end of a fold program past the
  time the erase waits for, so the tier refuses it.
- `tier_full_policy=through` needs `tier_static_mb` above 0. A static pool
  always needs it. A dynamic pool needs it only with `through`.
- Folds always charge their time. `enable_gc_delay` off (the GC delay flip)
  does not remove the fold cost.
- Dense programs use the FEMU page model: one program per page, timed by its
  page type. A one-shot word line program is a later option.
- A fold that a host write needs moves a whole pool line in one step. Host
  requests do not run between its page moves. Idle folds move one step at
  a time.
- No read promotion yet.

## Credit

The design studies Hybrid_FEMU by Funny-Boy-Max (GitHub #113) and the thesis
'Research on Read Performance Optimization Techniques for Hybrid Solid-State
Drives' (Zhao Yumiao, 2024). FEMU uses no code from Hybrid_FEMU.
