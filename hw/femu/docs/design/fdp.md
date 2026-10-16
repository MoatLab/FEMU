# FDP: Flexible Data Placement

This chapter describes how FEMU implements NVMe Flexible Data Placement
(FDP): how the subsystem builds reclaim groups, reclaim units and reclaim
unit handles, how a write is placed, how reclaim units map onto the BlackBox
FTL's NAND, how garbage collection works under placement, and what the FDP
log pages and features report. To launch an FDP device and write with
placement identifiers from a guest, read the [FDP feature guide](../features/fdp.md)
first. FEMU's FDP support comes from WARP (FAST '26); the guide has its
[citation](../features/fdp.md#citation).

## Purpose

FDP lets the host group writes it expects to die together. The device
offers reclaim unit handles (RUHs); each write may name one through a
placement identifier, and the device puts all writes of one handle into the
same open reclaim unit (RU). When an RU holds data of similar lifetime, it is
mostly invalid by the time garbage collection picks it, so GC copies less
and write amplification drops. FEMU models the host-visible FDP interface
and backs it with a placement-aware write and GC path in the BlackBox FTL,
so you can measure that effect.

FDP is not a `femu_mode`. It is turned on with `fdp=on` on a `femu-subsys`
device, and a controller joins the subsystem with `subsys=`. Only a BlackBox
(bbssd) namespace has the placement data path. A NoSSD namespace counts the
host side of FDP ([NoSSD namespaces](#nossd-namespaces)).

## Place in the hierarchy

```text
 femu-subsys device, fdp=on              NVMe subsystem
   |  endurance group 1 (NvmeEnduranceGroup.fdp)
   |    configuration: nrg reclaim groups x nru reclaim units, nruh handles
   |    host-visible state: RUH type and attributes, RUAMW per RU,
   |    HBMW/MBMW/MBE, host and controller event rings
   |
   +-- femu device, femu_mode=1, subsys=   one controller
         |
         +-- namespace 2 ...                 its own handle list, the same FTL
         +-- namespace 1                     placement handles PH 0..nruh-1
               |                             (default: PH i -> RUH i)
               +-- struct ssd (BlackBox FTL)
                     FemuRuHandle[nruh]       per group: active RU and
                                              collection RU; counters
                     FemuReclaimGroup[nrg]    its dies, free list, full
                                              list, victim queues
                     FemuReclaimUnit[nrg][nru] one block index on the dies
                                              of its group, write pointer,
                                              valid pages
                     lines -> blocks on the channels, LUNs and planes of
                              the group (every die with one group)
```

Two layers of state exist side by side. The subsystem holds what the host
sees (`NvmeRuHandle`, `NvmeReclaimUnit` with its RUAMW, the statistics and
events) in `nvme.h`. The FTL holds what places and collects data
(`FemuRuHandle`, `FemuReclaimGroup`, `FemuReclaimUnit` in
`bbssd/ftl.h`). Each FTL object points at its host-visible twin, and the
write path updates both.

## Configuration

`nvme_subsys_setup_fdp()` in `femu.c` builds one endurance group (ID 1)
with a single FDP configuration when the subsystem is realized:

| Item | Value | Property |
| --- | --- | --- |
| Reclaim groups (NRG) | 1 to 128 | `fdp.nrg` |
| Reclaim units per group | as set, at most 65536 | `fdp.nru` |
| Reclaim unit handles (NRUH) | 1 to `fdp.nru`, at most 16366 (the descriptor size of log 20h is 16 bits); must be set | `fdp.nruh` |
| Handle type (RUHT) | Persistently Isolated; with `fdp.isolation_mode` non-zero the last handle is Initially Isolated | `fdp.isolation_mode` |
| Reclaim unit size (RUNS) | one BlackBox superblock of the dies of a group (see below); the subsystem default of 96 MiB applies only when no bbssd controller overwrites it | `fdp.runs` |
| Reclaim group identifier format (RGIF) | the bits that hold `nrg - 1`: 0 with one group, 1 with two; the placement handle keeps the rest, at least enough for `MIN(nruh, 128)` handles | derived |
| MAXPIDS | `MIN(128, NRG x NRUH)`, reported zero-based, so below NRG x NRUH (Base 2.3, Figure 287) | derived |
| Event filter | every supported event type enabled on every handle | Set Features 1Eh |

With FDP on, a controller that joins runs `nvme_ns_init_fdp()` for each
namespace. It takes the placement handle list of the namespace from its
entry in `namespace_phls`, if set. Unset, the list holds the first
`MIN(fdp.nruh, 128)` handles in order. Each placement handle then selects
the RUH of the same number. A list holds at most 128 handles (NVM Command
Set 1.2, Figure 125). The namespace's ENDGID is 1, and each handle's RUAMW
starts at a full unit. The
controller then sets CTRATT bit 19 (FDP), and the effects log lists I/O
Management Send and Receive for NVM namespaces. Without FDP, and on
namespaces of other command sets, the two commands fail with Invalid Command
Opcode. CTRATT bit 4 (Endurance Groups), ENDGIDMAX = 1 and each
namespace's ENDGID = 1 come with any subsystem, FDP or not, since its one
endurance group is what log 09h reports.
The Endurance Group List (Identify CNS 19h) lists group 1 when CDW11 asks
for identifiers from 0 or 1; without a subsystem, CNS 19h is refused.

The BlackBox side (`bb.c`, `ftl-fdp.c`) adds the following, for a CSD
namespace as for a bbssd one, since CSD runs the same FTL
(`bb_init_fdp()`):

- RUNS is overwritten with the bytes of one superblock of a group:
  `nchs * luns_per_ch * pls_per_lun * pgs_per_blk * secs_per_pg * secsz /
  fdp.nrg`. `fdp.runs` must be unset or exactly that.
- Each group has `min(lines, fdp.nru)` reclaim units (`lines_per_ru = 1`).
  A unit is one block index on the dies of the group. Lines left over are
  not used by the placement write path.
- Each group needs at least `2 * fdp.nruh + 1` units: one open unit per
  handle, one collection unit per handle, and one spare.
- `gc_thres_pcent` and `gc_thres_pcent_high` set the free-unit watermarks
  instead of free-line watermarks. The forced watermark keeps at least one
  unit free, even where the percentage rounds to none, unless
  `gc_thres_pcent_high` is 100 (`bb_fdp_forced_units()`): a pass can fill its
  destination part way through a victim and needs a free unit to go on.
- The namespace must fit in the units left after the reserve
  (`bb_check_capacity()`), or the controller is refused at realize:

  ```text
  in each group:
  reserve = fdp.nruh                    one open unit per handle
          + Persistently Isolated handles one collection unit each
          + forced watermark            free units forced GC keeps
  usable  = (units - reserve) * unit size     (refused if units <= reserve)
  every namespace together must fit in usable: the host may send all of
  its data to one group (Base 2.3, 8.1.11)
  ```

  The Initially Isolated handle collects into its open unit and adds
  nothing. The namespaces are checked against the whole pool together:
  every namespace of the controller places into the one FTL, FDP takes a
  single controller, and namespace management is refused with it. A 1 MiB namespace on 64 KiB superblocks with four Persistently
  Isolated handles needs 16 + 4 + 4 + 1 = 25 units; with 19 or 23 lines,
  both accepted before, random writes over all four handles failed nearly
  all of them. A partly exposed last page counts as a whole one. bbssd
  refuses a namespace that does not fit rather than shrink
  it, as it does without placement and with `op_pcent`.

## Several namespaces

Reclaim units and handles belong to the endurance group (Base 2.3,
8.1.11). Each namespace reaches the handles through its own placement
handle list (PHL), and namespaces may share a handle. FEMU follows that
model: every bbssd namespace of an FDP controller places into one FTL, the
one namespace 1 builds.

```text
 namespace_phls=0:1,,1:2            endurance group 1, one struct ssd
 ns 1  PH 0 -> RUH 0  ------------>  RUH 0  units ...
       PH 1 -> RUH 1  --+--------->  RUH 1  units ...   (shared)
 ns 2  PH 0 -> RUH 1  --+
       PH 1 -> RUH 2  ------------>  RUH 2  units ...
                                     RUH 3  units ...   (unused: RUHA 0)
 LPN = (backend_offset of the namespace + LBA * block size) / page size
       [ ns 1 slice      | ns 2 slice      ]   no page holds two namespaces
```

| Part | How it works | Code |
| --- | --- | --- |
| FTL | namespace 1 builds it; later namespaces point at it (`ssd_shared`); the owner's exit clears their pointers | `bb_init()`, `bb_ns_exit()` |
| Address | each namespace keeps its slice of the logical pages: `ssd_ns_byte_base()` adds its backend offset | `ssd_lpn_range()` |
| Handles | the FTL builds every handle `0 .. fdp.nruh - 1`; a handle no list names holds its open unit too | `femu_fdp_ssd_init_ru_handles()` |
| Placement | a write's PID selects a placement handle of its namespace's list | `fdp_place()` |
| RUAMW | counts blocks of the format of the namespaces that use the handle (`NvmeRuHandle.lbads`) | `fdp_ru_ruamw()` |
| Format, Sanitize | drop the pages of the slice of the namespace only | `ssd_deallocate_fdp_ns()` |
| SMART, C0h, log 09h, thermal | count the shared FTL once | `nvme_collect_media_stats()` |
| Release | a handle no remaining namespace lists is unused again; its byte counters stay | `nvme_ns_detach_fdp()` |

Rules at realize (`nvme_check_phls()`, `nvme_check_fdp_namespaces()`):

- `namespace_phls` needs `fdp=on`, one entry per namespace, 1 to
  `MIN(fdp.nruh, 128)` handles per entry, each below `fdp.nruh`, none twice.
  Unset gives every namespace every handle. That list can be longer than
  128 when `fdp.nruh` is, as it always could.
- With more than one namespace, every namespace runs bbssd, or every one
  NoSSD. A bbssd namespace size is a whole number of NAND pages, so no page
  holds blocks of two namespaces. `fdp_trim_erase_all` is refused, since it
  erases every namespace.
- The sum of the namespace sizes must fit in the units left after the
  reserve, as one namespace does.

Namespaces that share a handle share the format (NVM Command Set 1.2,
5.2.5 and 5.2.21). A Format of one of them to another index fails with
Invalid Format. A Format of every namespace (NSID FFFFFFFFh) takes the
bitmaps of all of them first, so it changes all or none.

Events from the FTL name a namespace by the data:

```text
 move of page lpn  --> namespace whose slice holds it
 80h  NSID and LBA of that namespace; PID from its list
      a run of another namespace's pages ends the event: one 80h per run
 81h  the namespace of the move that changed the handle
 01h, 81h of an open-unit refresh   no data: the first namespace that
                                    lists the handle
 a namespace that does not list the handle --> the first one that does
 no namespace lists it               --> no NSID, no PID
```

The write buffer is part of the shared FTL. A Flush of one namespace writes
back the held pages of all of them, which Flush allows.

Statistics stay per endurance group and per handle: a shared handle adds
the writes of every namespace that uses it. query-femu reports the PHL of
each namespace (`placement-handles`) and the namespace whose FTL holds the
units (`ftl-nsid`).

NoSSD namespaces have no FTL. They report their lists in RUH Status and
count their writes as [NoSSD namespaces](#nossd-namespaces) says.

## Reclaim groups

A reclaim group is a set of dies. Base 2.3 (3.2.4) gives each handle a
reclaim unit in each group and keeps collection inside a group (Figure
288). It does not say which media a group holds. FEMU follows physical FDP
SSDs: a group is a set of dies that work in parallel, and a unit is a
superblock of those dies.

```text
 dies d = ch * luns_per_ch + lun, D = nchs * luns_per_ch
 group of d = d / (D / nrg)
   nrg divides nchs            --> nchs / nrg whole channels per group
   nchs divides nrg, and
   nrg / nchs divides luns_per_ch --> luns_per_ch * nchs / nrg LUNs of one
                                     channel per group
   anything else               --> refused at realize (bb_check_fdp_groups())

 unit (g, j) = block index b_j on every plane of every die of group g
 write pointer of a unit: steps over the window ch0..ch0+nch-1,
                          lun0..lun0+nlun-1 of its group (ssd_wp_step())
```

| Part | How it works | Code |
| --- | --- | --- |
| Lines | with more than one group, each group has its own line per block index; `get_line()` takes the group of the die; with one group the lines are those of line mode | `femu_fdp_ssd_init_reclaim_group()` |
| Frontiers | each handle has an active unit and a collection unit in each group | `FemuRuHandle.rus[]`, `gc_rus[]`, `fdp_set_active()` |
| Placement | a valid PID names the group; a write without one goes to the group with the most free units, in turn on a tie | `fdp_place()`, `fdp_select_rg()` |
| Collection | runs per group: foreground in the group of the write, background in every group under its watermark; victims and destinations stay in the group | `fdp_gc_until_clear()`, `bb_ftl_process_req()` |
| Erase, pad, copyback | walk the dies of the unit's group only | `fdp_collect_ru()`, `ssd_pad_line()`, `fdp_reclaim_ru_copyback()` |
| Write buffer | each held page keeps its group; a write-back skips a group with no room; a write at the watermark whose buffer holds only such pages goes to its own unit at once | `fdp_buffer_destage_some()`, `fdp_buffered_write()` |
| RUH Update | writes back the held pages of the named pairs only | `fdp_buffer_destage_update()` |
| Refresh | the unit's group must have room; with more than one group a queued refresh that cannot run is dropped, and the next read queues it again | `fdp_do_read_reclaim()` |
| Check | `x-fdp-check` adds, for each unit, the valid pages of its blocks on the dies of its group, and compares them with its valid count | `fdp_check_dies()` |

A logical block must be whole NAND pages with more than one group
(`bb_check_fdp_block()`). The FTL maps whole pages. A write of part of a
page would program the whole page into the group of the write. The other
blocks of the page would then change group with it. With one group the
FDP-2 rule stays: the handle of the last write to a page takes the page.

## NoSSD namespaces

A NoSSD namespace has no NAND model. The backend stores each byte of data
once and no controller write exists. `nvme_fdp_host_write()` counts on the
poller, under `stats_lock` of the endurance group, since several pollers
write at once:

```text
 Write, Copy, Write Zeroes (DEAC 0)  --> HBMW += bytes, MBMW += bytes,
                                         RUAMW of rus[g] of the handle -= blocks
 Write Zeroes (DEAC 1), Write Uncorrectable --> HBMW += bytes only
 unit full (RUAMW would reach 0)     --> fresh unit: RUAMW = full - rest
 RUH Update: unit part written       --> event 00h, fresh unit
             unit empty              --> stays, no event (Base 2.3, 7.4.1.1)
 invalid PID                         --> placement handle 0, group in turn,
                                         event 03h
```

MBE stays 0. Realize refuses a logical block larger than `fdp.runs`. A
Format to such a block fails with Invalid Format. So a unit holds at least
one block. RUH Update holds `stats_lock` across its whole list, and RUH
Status and the FDP Statistics log read under it.

## Placement of writes

```text
 Write: CDW12 bits 23:20 DTYPE, CDW13 bits 31:16 DSPEC
   |
   | DTYPE == 2 (data placement) and DSPEC is a valid placement identifier?
   |   no  -> placement handle 0, in the group with the most free units
   |          (if DTYPE was 2: host event "Invalid Placement Identifier")
   |   yes -> PID = (RG << (16 - RGIF)) | PH ;  with RGIF 0, PID = PH
   v
 PH --ns->fdp.phs[]--> RUH --rus[RG]--> active RU --wptr--> next page
   |
   | per FTL page (secsz * secs_per_pg, 4 KiB by default): invalidate the old copy, map LPN -> new page,
   | RUAMW -= logical blocks written, advance the write pointer,
   | charge a NAND program
   v
 RU full -> retire it (full list or victim queue), take a free RU
            for this handle; none free -> Capacity Exceeded
```

`ssd_stream_write_lpns()` does this on the FTL thread. Write, Write Zeroes
without the Deallocate bit, and the destination of Copy all go through it;
Copy and Write Zeroes read their placement fields from the same CDW12 and
CDW13 bits.

The order inside `ssd_stream_write_lpns()` is:

1. If the handle has no active unit (the last one filled and no free unit
   was left), take a free unit without running GC; if there is none, fail
   with Capacity Exceeded. A unit that fills on a command's last page
   therefore makes the next write to that handle fail when the device is
   full.
2. Run foreground GC while the free-unit count is at or below the high
   watermark (see [Garbage collection](#garbage-collection)).
3. Place the pages, running foreground GC again before each one: a command
   can take more units than the watermark keeps free. If the device runs out
   part way, the command completes with Capacity Exceeded and only the pages
   already placed count.

Writes of different handles never share an RU, but they share the NAND of
their group. Every RU of a group spans the dies of the group. So
concurrent handles of one group compete for the same planes and channel
buses.

### Reclaim units over NAND

An RU is one BlackBox line: block `b` on every channel, LUN and plane. Its
write pointer moves across channels first, then LUNs, then planes, then
down the pages of the block, so consecutive pages of one handle land on
different dies:

```text
 RU k = line k (block index k), nchs=4, luns_per_ch=2, pls_per_lun=2

 page order:   ch0/L0/pl0  ch1/L0/pl0  ch2/L0/pl0  ch3/L0/pl0
               ch0/L1/pl0  ch1/L1/pl0  ch2/L1/pl0  ch3/L1/pl0
               ch0/L0/pl1  ...                     ch3/L1/pl1   <- page 0 done
               ch0/L0/pl0 (page 1) ...                          <- page 1
               ...                                 last page    <- RU full

 RUNS = all of that = one superblock
```

`fdp_advance_ru_pointer()` implements the order; `fdp_get_new_page()`
turns the pointer into an address. The NAND timing of each program is the
BlackBox timing (see [NAND timing](nand-timing.md)).

### Reclaim Unit Handle Update

I/O Management Send with operation 1 (RUH Update) lists placement
identifiers. The poller checks every identifier first and fails the command
with Invalid Field if one is invalid, so nothing changes. On a bbssd
namespace `ssd_fdp_update_ruhs()` then, for each handle:

- skips a handle that has no current unit (device full); the command still
  succeeds;
- keeps the current unit if nothing was written to it yet. The handle does
  not move, so no event follows (Base 2.3, 7.4.1.1 lets an empty unit
  stay);
- otherwise first runs foreground GC passes in the group, as a write does,
  while its free units are at or below the forced watermark. An update
  that took the last free units would leave collection no unit to move
  pages into. A pass into an Initially Isolated handle can fill the old
  unit and move the handle, which then counts as the update;
- then takes a fresh unit, with one GC pass if none is free, and retires
  the old one as if it had filled. If no unit can be freed, the command
  fails with Capacity Exceeded;
- when the handle moves off a unit that still had room (RUAMW not zero),
  records host event "Reclaim Unit Not Fully Written". The handle must
  have that event enabled.

Each identifier names a handle and a group, and moves that pair only.

I/O Management Receive with operation 1 (RUH Status) returns one descriptor
per placement handle and reclaim group: PID, RUHID, EARUTR (always 0) and
the RUAMW of the handle's current unit, or 0 while the handle has none
because its last unit filled with no free unit to follow it.

RUAMW is the room left in a unit, in logical blocks. Each unit counts the
bytes programmed into it since its erase, from every path:

```text
 host program (direct, FUA, Write Zeroes) --+
 buffer write-back                         --+--> ru->prog_bytes += page size
 relocation (collection, refresh, copyback) -+         |
 pad (pd_open_close_sec)                   --+         v
                          RUAMW = (RU size - prog_bytes) >> LBA size bits
 unit freed (erase)  --> prog_bytes = 0, RUAMW = a full unit
 Format              --> RUAMW from prog_bytes again, in the new LBA size
```

Collection writes into the active unit of the last handle of an
Initially Isolated configuration, so that handle's RUAMW drops for the
moved pages too. The remaining bytes round down once, so a page smaller
than a block counts the same on every path. `x-fdp-check` (a test hook)
counts a unit whose bytes differ from its valid and invalid pages, or
whose RUAMW differs from the room they leave.

## Garbage collection

```text
                take (handle needs a unit)
   +--------+ -------------------------> +--------+
   |  free  |                            | active |  curr_ru of one handle,
   +--------+ <---------+                +--------+  or a handle's GC unit
        ^               |                    |
        |               | GC: relocate       | full (or left by RUH Update)
        |               | valid pages,       v
        |               | erase blocks   all pages valid?
        |               |                 yes -> full list
        |               |                 no  -> victim queue(s)
        |               |                    |
        |               +--------------------+  a page in a full-list unit
        |                                       is invalidated: unit moves
        +-- erased unit returns to the free list of its reclaim group
```

### When it runs

- Background: after every request the FTL thread handles, each reclaim
  group whose free units are at or below
  `(1 - gc_thres_pcent / 100) * units` runs one pass. A background pass
  puts its victim back, whatever the policy, unless the victim is empty or
  an erase would give back at least 1/8 of its pages. Those pages are the
  invalid ones plus, for a unit that RUH Update retired part written, the
  ones it never wrote. Cost-benefit skips units that fail this check and
  takes the best-scoring unit that passes, so an old unit with little to
  free does not stall the pass.
- Foreground: before a placed write and before each of its pages, it
  checks the free units of the write's group. While they are at or below
  `(1 - gc_thres_pcent_high / 100) * units` (at least one unless
  `gc_thres_pcent_high` is 100), it runs passes in that group. It stops
  when the pressure clears or no victim is left. The host write waits for them.
  RUH Update runs the same passes before it takes a unit. Foreground
  passes, and the passes RUH Update runs, always collect their victim.

### Victim selection

`gc_strategy` selects the policy, or `gc_policy` by name. A `gc_policy`
other than `greedy` needs `gc_strategy=0`; unset or `greedy`, it leaves
the choice to `gc_strategy`.

| `gc_strategy` | `gc_policy` | Policy |
| --- | --- | --- |
| 0 (default) | `greedy` | greedy: the unit with the fewest valid pages |
| 1 | `cost-benefit` | cost-benefit: an empty unit first, otherwise the largest `(1 - u) * age / u`, with `u` the valid pages over all the unit's pages (pages a part-written unit never wrote count as freed) and `age` the time since a page in the unit was last invalidated, computed at selection time; a unit retired with no page invalidated is aged from its retirement |
| 2 | `random` | random among the victims |
| - | `fifo` | the unit retired first; an empty unit goes before it, and a background pass takes the oldest unit it accepts |
| - | `d-choice` | the fewest valid pages among 4 random draws from the victims, with replacement; the first of equal counts wins; an empty unit goes first |
| 4 | - | per handle: the unit with the fewest valid pages among the per-handle queues, in the group, of Persistently Isolated handles that hold units there, falling back to greedy |

### Where relocated data goes

The handle type decides the destination of the valid pages, which is what
"isolation" means here:

```text
 victim from a Persistently Isolated handle h
     -> h's own GC unit in the victim's group (gc_rus[g], taken from the
        free list of the group on demand)
        data of h stays apart from every other handle, before and after GC

 victim from an Initially Isolated handle
     -> the current unit of the last handle (RUH nruh-1) in the group
        data may be mixed with other relocated data after GC
```

With the default `fdp.isolation_mode=0` every handle is Persistently
Isolated. With it set, only the last handle is Initially Isolated, so its
relocated data goes back into its own current unit.

A pass copies every valid page of the victim, invalidating each old copy as
it goes, and only then erases the planes of each LUN as one multi-plane
erase when `enable_gc_delay` is on (the default). It adds the copied bytes
to MBMW and the erased bytes to MBE, records the controller events of
[Events](#events), and returns the unit to the free list. If the
destination runs out of space part way, the pass stops before it erases
anything. The pages already moved live at their new location, and the rest
stay in the victim. The victim goes back on the queue for a later pass.

With `gc_copyback` on, the pass takes the victim's pages in the order of
the destination dies. A page whose destination is on its own die and plane
moves by copyback, with no data on the channel. A copyback skips
ECC, so on a real SSD its bit errors are not corrected; FEMU models no bit
errors, so only timing changes ([copyback](ftl.md#copyback-gc_copyback)).

Both destinations can be left without a unit: one that fills with no free
unit to follow it is dropped. The next pass with a page to move takes a free
unit for it from the victim's reclaim group, whatever state the handle's
own current unit is in. A victim with no valid page left needs no
destination, so it is collected even when no unit is free; that is how a
device that ran out gets a unit back once the host deallocates or
overwrites data.

### Deallocate

Dataset Management deallocate on an FDP namespace unmaps the given ranges;
the pages become invalid and GC reclaims their units later. Write Zeroes
with the Deallocate bit does the same. `fdp_trim_erase_all` (test only)
instead resets every unit, handle and mapping on any Dataset Management
deallocate, ignoring the ranges; Write Zeroes with Deallocate still unmaps
only its range.

## Log pages and features

All four FDP log pages take endurance group 1 in the Log Specific
Identifier, and need a subsystem with FDP on. FEMU fixes FDP at realize.
So with FDP off, the controller has no FDP capability (CTRATT bit 19 is
clear). The pages then fail with Invalid Log Page, and log 00h does not
list them.

| Log | Content | Code |
| --- | --- | --- |
| 20h FDP Configurations | header with NUMFDPC 0 (one configuration), then one descriptor: FDPA (valid, RGIF), NRG, NRUH, MAXPIDS, NNSS 256, RUNS, and NRUH handle descriptors with the RUHT of each handle | `nvme_fdp_confs()` |
| 21h Reclaim Unit Handle Usage | header with NRUH, then one descriptor per handle with its RUHA (1 = host-specified for a handle some namespace lists, 0 for one no list names) | `nvme_fdp_ruh_usage()` |
| 22h FDP Statistics | HBMW, MBMW and MBE as 128-bit counters, which stop at the 128-bit maximum | `nvme_fdp_stats()` |
| 23h FDP Events | number of events, then the events of the ring selected by LSP bit 0 (1 = host events, 0 = controller events) | `nvme_fdp_events()` |

### The 21h layout

The log is an 8-byte header followed by one 8-byte Reclaim Unit Handle
Usage Descriptor per handle, as the specification defines it. Each
descriptor holds the handle's RUHA in byte 0, and bytes 1 to 7 are
reserved. `NvmeRuhuDescr` in `nvme.h` has that layout, and a
`QEMU_BUILD_BUG_ON` keeps it at 8 bytes. The log is `8 + 8 * NRUH` bytes:

```text
 offset      content
 0           NRUH (2 bytes), reserved (6 bytes)
 8           handle 0: RUHA, reserved
 16          handle 1: RUHA, reserved
 8 + 8 * i   handle i: RUHA, reserved
```

The log carries no per-handle byte counters. The endurance-group totals are
in 22h.

### Statistics

| Counter | Grows by | Where |
| --- | --- | --- |
| HBMW (host bytes with metadata written) | bytes of the logical blocks a Write, Copy or Write Zeroes without Deallocate wrote, in the pages it actually programmed or the buffer took (`fdp_host_bytes()`); and the bytes of the blocks of a Write Zeroes with Deallocate or a Write Uncorrectable, which NVM Command Set 1.2, 4.1.4.6 counts too, though they program no page | `fdp_count_write()`, `fdp_buffered_write()`, `ssd_fdp_count_unprogrammed()` |
| MBMW (media bytes with metadata written) | the bytes of the pages programmed for the host, plus bytes relocated by GC, plus pad bytes (`pd_open_close_sec`) | `fdp_count_write()`, `do_gc_fdp_style()`, `fdp_pd_leave_ru()` |
| MBE (media bytes erased) | bytes of every block erased by GC | `do_gc_fdp_style()` |

The ratio MBMW / HBMW is the write amplification of the endurance group.
A write smaller than a page programs the whole page, so it raises the
ratio above 1, as it does on a real device.
The counters are charged after the write, from the pages it placed, so a
write that ran out of space adds only what it wrote. They are reset by a
deallocate with `fdp_trim_erase_all` set.

### Events

There are two rings of 63 events each, one for host events and one for
controller events. When a ring is full the oldest event is overwritten.
Each event carries the Timestamp feature's current value.

| Type | Ring | Generated when |
| --- | --- | --- |
| 0h Reclaim Unit Not Fully Written | host | RUH Update moves a handle off a unit that still had room; an empty unit stays and logs nothing |
| 3h Invalid Placement Identifier | host | a placed write (Write, Copy, Write Zeroes, Write Uncorrectable) on a bbssd or NoSSD namespace has DTYPE 2 and a DSPEC that is not a valid PID; PIV with that DSPEC, NSIDV, and LV with the group and handle the controller selected (Base 2.3, Figure 296); checked against the event filter of placement handle 0 |
| 80h Media Reallocated | controller | a collection or refresh pass moved pages of a unit of the Initially Isolated handle; one event per pass, split around each 81h the pass causes, also for a pass that stops part way; checked against that handle's filter |
| 81h Implicitly Modified Reclaim Unit Handle | controller | a move, not the host, gave the Initially Isolated handle a new unit: the moves filled its active unit and a free unit follows, or the pass takes a unit for a handle left with none; checked against that handle's filter |
| 1h Reclaim Unit Active Time Limit Exceeded | host | `pd_open_close_sec`: the controller padded a handle's active unit and gave the handle a fresh one; LV, NSIDV and PIV as for 81h |
| 81h, program disturb | controller | `pd_open_read_limit`: the controller took a handle's active unit away to refresh it; this one also for a Persistently Isolated handle |
| 2h | | accepted by the event filter, never generated |

A Persistently Isolated handle moves its data into a collection unit that
the host never sees, so its moves log no event. A host write that fills a
unit is a host action and logs no 81h either.

```
 pass over victim unit V of handle h
   |
   +-- h Persistently Isolated --> moves into h's gc_ru ------> no event
   |
   +-- h Initially Isolated ----> moves into h's active unit
          |  a move fills it, next unit follows --> 80h (moves so far)
          |                                         81h (h)
          |  pass ends, moves not yet reported --> 80h (the rest)
```

Both events have LV set, with the victim's reclaim group and handle. The
FTL belongs to one namespace, so NSIDV and PIV are set too. PID encodes
the victim's reclaim group and the lowest placement handle of that
namespace that maps to the handle. The
Event Type Specific field of 80h is in NVM Command Set 1.2, Figure 112. It
holds LBAV, the number of blocks moved (at most FFFFh) and one of them.

The FTL moves whole pages, so the count takes only the blocks of a moved
page that a host write programmed into it. The FTL notes those blocks as it
programs each page, in 512-byte pieces. The block reported is the first such
block. With a page size that is not a multiple of 512 bytes, the FTL keeps
no such record, and 80h reports no count and no block. The FTL drops a handle's active unit when it fills with no free
unit. That logs nothing, and the unit taken later logs the 81h.

The FTL maps whole pages. A host write of part of a page programs the whole
page through the write's handle. The other blocks of that page then change
handle with it. That is a host action, and FEMU logs no 80h for it.

Get and Set Features 1Eh (FDP Events) read and change the enabled event
types of one placement handle, named in CDW11; an unsupported type in a Set
fails with Invalid Field. Get Features 1Dh (FDP Mode) for endurance group 1
reports that FDP is on. Both features exist only with FDP on; otherwise they
fail with Invalid Field, and log 12h does not list them. Set Features 1Dh
fails with Invalid Field for an endurance group other than 1, and otherwise with
Command Sequence Error, since the mode may only change while the endurance group has
no namespaces and FEMU builds the namespace at realize.

## Threads, locks and where latency is charged

| Work | Thread | Notes |
| --- | --- | --- |
| Parsing DTYPE and DSPEC, validating RUH Update identifiers, I/O Management Receive | poller | data copy to the DRAM backend happens here too |
| Placement, RU rotation, GC, deallocate, RUH Update on bbssd | FTL thread | sole owner of the FTL structures |
| Event append | poller or FTL thread | `events_lock` in the endurance group |
| Counters of log 22h; NoSSD RUAMW | FTL thread, poller | `stats_lock` in the endurance group, taken before `events_lock` |
| Log pages 20h to 23h, Features 1Dh and 1Eh | admin path | 23h reads under `events_lock` |

A placed write is charged the largest NAND program latency of its pages,
after any foreground GC passes, whose erases and relocations occupy the
same LUNs. GC programs and erases use the BlackBox timing with
`enable_gc_delay` (see [the FTL chapter](ftl.md)).

## Parameters

Subsystem properties are in the
[Flexible Data Placement section](../reference/properties.md#flexible-data-placement)
of the property reference; the controller-side ones are under
[garbage collection, mapping and caches](../reference/properties.md#garbage-collection-mapping-and-caches).

| Property | On | Effect and interactions |
| --- | --- | --- |
| `fdp` | `femu-subsys` | Turns FDP on. Refused together with `ns_mgmt=on`. |
| `fdp.nruh` | `femu-subsys` | Handles and placement handles. Required. Raises the units the geometry must supply. |
| `fdp.nru` | `femu-subsys` | Units per group; the FTL uses at most one per line. |
| `fdp.nrg` | `femu-subsys` | Groups; with bbssd a set of dies each, see [Reclaim groups](#reclaim-groups). |
| `fdp.runs` | `femu-subsys` | Unset, or the superblock size of a group. |
| `fdp.isolation_mode` | `femu-subsys` | Non-zero makes the last handle Initially Isolated. |
| `gc_strategy` | `femu` | Victim policy, above. No effect without FDP. |
| `fdp_trim_erase_all` | `femu` | Whole-device reset on deallocate. No effect without FDP. |
| `gc_thres_pcent`, `gc_thres_pcent_high` | `femu` | Background and foreground watermarks, as fractions of the units. |
| `gc_copyback` | `femu` | Moves collected pages on their die; off by default. A copyback skips ECC (timing only in FEMU). |
| BlackBox geometry (`nchs`, `luns_per_ch`, `pls_per_lun`, `blks_per_pl`, `pgs_per_blk`, `secs_per_pg`, `secsz`) | `femu` | Sets RUNS (one superblock of a group) and the number of lines, hence units. |

Refused under FDP on a bbssd controller:

- `hot_cold_sep`: the placement handle of a write names its unit, and the
  hot write pointer writes past it;
- `mapping=hybrid` and `mapping=fast`, whose log and data lines are not
  FDP-aware;
- a `gc_policy` other than `greedy` together with a `gc_strategy` other
  than 0.

The FTL applies `trim_lat_ns` and `ecc_retention_sec` as without FDP. A unit's lines
take their close time when the unit retires, and lose it when collection
frees the unit.

`read_reclaim_limit` and `retention_limit_sec` refresh a whole reclaim unit.
A read queues the unit of its line, as in line mode. The next write moves
its valid pages to where collection would move them, then erases the unit.

```
 read of unit U: read count >= read_reclaim_limit, or age >= retention_limit_sec
   --> U queued (one at a time)
 next write: U's group not at the high watermark, 2 or more free units
   (with more than one group, else the request is dropped)
   --> U active (rus[g] or gc_rus[g]) --> request dropped
   --> U full or a victim            --> taken off its list
   --> move every valid page, no copyback --> erase U, free U
   --> C0h read_reclaims or retention_refreshes + 1, MBMW + moved bytes
```

The refresh logs the same FDP events as a collection pass (see
[Events](#events)).

`buffer_size` puts the write buffer in front of placed writes. The buffer
models time only: it holds page numbers, and the backend holds the data.
Each held page keeps the handle and group of its last write. A write-back
programs each page into the active unit of its own handle in its own
group, so a unit takes only the pages of its handle.

```
 Write or Copy, no FUA, cache on
   --> each page: held?  no, and buffer at the watermark
         --> write back the oldest (buffer_size - watermark) pages
         --> still at the watermark: the page goes to its own unit at
             once if its group has room, else Capacity Exceeded
   --> entry {lpn, handle, group, written 512-byte pieces} := this write
   --> HBMW += bytes of the blocks written; C0h host pages, 72 and 80 count
 write-back of entry e
   --> collect in e.group; e.handle has no unit there and none is free:
       e stays, and so do the later pages of e.group; go on with the rest
   --> program into e.handle's active unit, RUAMW of that unit drops
   --> MBMW of the group and of e.handle += page size; e leaves the buffer
```

The FTL maps whole pages. The handle of the last write to a page takes
the whole page, with or without the buffer, also when two handles wrote
different blocks of it. The other commands:

| Command | Effect on held pages |
| --- | --- |
| Flush | writes every held page back; Capacity Exceeded if one finds no room, and those stay held |
| Write with FUA, Write Zeroes without Deallocate | program at once; a held copy of a page goes when this command programs that page |
| Volatile Write Cache off (feature 06h) | writes every held page back first; if one finds no room, the command fails and the cache stays on |
| DSM Deallocate, Write Zeroes with Deallocate, Format | drop the held copy, which never reaches the media |
| I/O Management Send, RUH Update | writes back the held pages of the named (handle, group) pairs first, so they land in the units the handles named before the update; if one of them finds no room, no handle moves and the command returns Capacity Exceeded |
| Read | a held page is served from the buffer |

HBMW counts the blocks a write accepts, and MBMW pages that reach the
media, so MBMW can be below HBMW when the buffer absorbs rewrites. RUAMW drops
when a page reaches its unit, for written back and direct pages alike
(see RUAMW above). The
admin commands above charge no modelled time for their write-back.

The program disturb actions work on units too
([NAND timing](nand-timing.md#program-disturb-actions)). A unit today is one
line, so its open time is the open time of that line.

```
 pd_open_read_limit: unit U queued for a part-programmed block
   next write --> U a handle's curr_ru --> fresh unit to the handle first,
                                           U retired with its free pages
                                           unprogrammed; 81h (handle)
              --> U a handle's gc_ru   --> U retired, gc_ru cleared; no event
              --> then the refresh above; C0h pd_open_reclaims + 1
 pd_open_close_sec: curr_ru or gc_ru open past the limit, at a request
   --> its free pages padded, U retired, MBMW + pad bytes
   --> curr_ru: fresh unit to the handle; host event 1h (handle)
   --> ERUTL stays 0: the limit counts from the first program
```

The fresh unit is taken before anything changes. With no free unit to
spare, or a group at the high watermark, nothing changes. The handle's
`curr_ru`, `rus[rg]` and the unit the host is shown change together. The
configuration descriptor keeps ERUTL at 0 (not reported). ERUTL times a
unit from when the handle takes it, but the limit here counts from the
first program, so an empty unit is never padded.
Collection that frees a queued unit first drops the request, and the
counters do not move. A collection of a queued unit does not use copyback.

Refused on any controller with FDP: a second controller in the
subsystem, `meta`, `streams`, a KV namespace.
Each message is listed in the [feature guide](../features/fdp.md#limits-and-refusals).

A device with eight handles, every one Persistently Isolated except the
last:

<!-- femu-example: design-fdp-isolation -->
```text
-device femu-subsys,id=fdp8,fdp=on,fdp.nruh=8,fdp.isolation_mode=1 -device femu,devsz_mb=1024,femu_mode=1,subsys=fdp8,gc_strategy=1
```

## Statistics and outputs

| Output | What it shows |
| --- | --- |
| Logs 20h to 23h | configuration, handle usage, endurance-group byte counters, events |
| Vendor log C0h | write amplification and page counts of the FTL; placed writes count as host and programmed pages, relocations as GC pages ([log pages and counters](../reference/log-pages-and-counters.md#vendor-log-page-c0h)) |
| SMART / Health (02h) | host data units and commands, as for every mode |
| `FEMU_FDP_DEBUG` in QEMU's environment | traces of RU rotation and GC passes on stderr |

## Validation

| Check | What it covers |
| --- | --- |
| qtest cases in `hw/femu/tests/qtest/femu-test.c` | `fdp-ns-phl`, `fdp-ns-cmds`, `fdp-ns-format-shared`, `fdp-ns-format-apart`, `fdp-ns-events`, `fdp-ns-knobs`, `fdp-ns-nossd`, `fdp-ns-refused`, `fdp-ns-replace`, `fdp-replace-full` (several namespaces, and a replaced controller whose handle had no unit; `x-fdp-ns-mapped` gives each namespace's mapped pages), `fdp-events`, `fdp-features`, `fdp-report-length`, `fdp-ruh-usage`, `fdp-write-zeroes`, `fdp-write-zeroes-placed`, `fdp-ruh-update`, `fdp-ruh-update-full`, `fdp-background-gc`, `fdp-cb-unwritten-age`, `fdp-cb-utilization`, `fdp-cb-background`, `wide-lba-fdp`, `io-fuzz-fdp`, `copy-fdp`, `log-contents-fdp`, `ns-mgmt-unavailable-fdp`, `fdp-csd-knobs`, `fdp-knobs-refused`, `fdp-policy-fifo`, `fdp-policy-fifo-greedy`, `fdp-policy-fifo-empty`, `fdp-policy-fifo-csd`, `fdp-policy-fifo-background`, `fdp-policy-cb`, `fdp-policy-cb-strategy`, `fdp-policy-cb-greedy`, `fdp-policy-refused`, `fdp-dftl`, `fdp-dftl-page`, `fdp-dftl-csd`, `fdp-buffer-isolation`, `fdp-buffer-isolation-csd`, `fdp-buffer-rehandle`, `fdp-buffer-dealloc`, `fdp-buffer-fua`, `fdp-buffer-vwc`, `fdp-buffer-update`, `fdp-buffer-full`, `fdp-buffer-copy`, `fdp-events-gc-ii-part-buffer`, `fdp-events-gc-ii-mix-buffer`, `fdp-events-gc-ii-fua-buffer`, `fdp-events-gc-ii-redo-buffer`, `fdp-csd-runs`, `fdp-gc-strategy-refused`, `fdp-events-gc-pi`, `fdp-events-gc-ii`, `fdp-events-gc-ii-cb`, `fdp-events-gc-ii-4k`, `fdp-events-gc-ii-part`, `fdp-events-gc-ii-rot`, `fdp-events-gc-ii-mask`, `fdp-events-gc-ii-no80`, `fdp-events-gc-ii-no81`, `fdp-events-gc-ii-other`, `fdp-events-gc-ii-empty`, `fdp-events-rf-pi`, `fdp-events-rf-ii`, `fdp-events-rf-ii-part`, `fdp-confs` (log 20h), `fdp-invalid-pid` and `fdp-invalid-pid-nossd` (event 03h), `fdp-unprogrammed`, `fdp-nossd-counts`, `fdp-runs-block`; reclaim groups: `fdp-confs-rg2`, `fdp-rg2-place`, `fdp-rg3-place`, `fdp-rg4-place` (PIDs, RUH Status, placement by group from query-femu, group selection, RUH Update of one pair), `fdp-rg2-gc`, `fdp-rg2-gc-cb`, `fdp-rg2-gc-ii`, `fdp-rg4-gc` (the whole namespace through one group, collection in it, no page and no erase in another), `fdp-rg2-buffer` (a full group does not stop another) |
| Exact traces and victim-order digests (qtest-only `x-ftl-trace`) | `ftl-trace-fdp` and `ftl-trace-fdp-reread` (greedy), `ftl-trace-fdp-random` (`gc_strategy=2`), `ftl-trace-fdp-policy-random` (`gc_policy=random`, the same trace), `ftl-trace-fdp-fifo` and `ftl-trace-fdp-d-choice` (`gc_policy`), `ftl-trace-fdp-knobs-off` (`gc_policy=greedy`, `mapping=page` and `buffer_size=0` given: the `ftl-trace-fdp` trace), `ftl-trace-fdp-noisy` and `ftl-trace-fdp-noisy-ii` (`gc_strategy=4` on two handles, the second one Initially Isolated in `-ii`), `ftl-trace-fdp-trim-erase-all` (`fdp_trim_erase_all=1` while both kinds of heap hold victims; afterwards the mapping holds exactly the pages written since) |
| Documentation examples | each tagged FDP example starts under qtest and moves one block |
| `hw/femu/scripts/fdp-test-nvme-admin.sh` | in-guest nvme-cli checks against the `run-blackbox-fdp.sh` configuration; manual |
| `hw/femu/tests/unit/test-pqueue.c` | the priority queue the victim queues are built on |

## Limits

- One FDP configuration and one controller per FDP subsystem.
- An RU is exactly one block index on the dies of its group; RUNS cannot
  be smaller or larger than that superblock.
- Only bbssd places data. A NoSSD controller counts the host side
  ([NoSSD namespaces](#nossd-namespaces)). CSD uses the bbssd path, with
  the same refused knobs and RUNS, and without its memory and compute
  namespaces. ZNS, OCSSD and KV are refused (Base 2.3, 8.1.11).
- With more than one group, each group holds the whole exposed capacity,
  and a logical block is whole NAND pages.
- query-femu shows the FDP state of bbssd namespaces only.
- The FTL thread writes the RUAMW of bbssd units, and pollers read it for
  RUH Status with no lock, as before. The counters of log 22h change and
  are read under `stats_lock`.
- A bbssd write that runs out of room counts the pages it programmed or
  the buffer took before the failure. A NoSSD command that fails counts
  nothing, except a two-page write whose second transfer fails: the whole
  blocks of its first page count.
- Page or DFTL mapping only.
- The CSD NVM-to-AFDM transfer reads the mapping only, without FDP as
  well: a page the write buffer holds and never wrote back costs no read.
- EARUTR is always 0; ERUTL is not reported.
- The handle counters of query-femu are 64-bit and stop at their largest
  value.
- Metadata, Streams and Namespace Management do not combine with FDP.

## How to extend it

- Larger reclaim units: `lines_per_ru` in `ssd_init_fdp_params()` is the
  hook, but `fdp_advance_ru_pointer()` retires a unit after its first line;
  it must walk `ru->lines[]` first.
- A new victim policy: add a value to the GC strategy enum in
  `bbssd/ftl.h`, a case in `select_victim_ru()` that chooses a unit without
  removing it, and accept the value in the geometry checks of
  `bbssd/ftl-geom.c`. Queue, remove and reorder victims only through
  `fdp_victim_enqueue()`, `fdp_victim_dequeue()` and
  `fdp_victim_reprioritize()`, which keep the group heap (`pos`) and the
  handle heap (`ruh_pos`) in step.
- A new event: generate it with `nvme_fdp_record_event()` after checking the
  handle's filter, and add the type to `nvme_fdp_events_supported[]` and
  `nvme_fdp_evf_shifts[]` in `nvme.h`.

## Source map

| File | What is there |
| --- | --- |
| `hw/femu/femu.c` | `femu-subsys` properties, `nvme_subsys_setup_fdp()`, `nvme_ns_init_fdp()`, `nvme_ns_refresh_fdp()`, `namespace_phls`, single-controller and multi-namespace checks, CTRATT |
| `hw/femu/nvme.h` | FDP wire structures (configuration, usage, statistics, events, RUH status), endurance group and handle state, event tables |
| `hw/femu/nvme-io.c` | DTYPE and DSPEC parsing, PID helpers, event recording, I/O Management Send and Receive |
| `hw/femu/nvme-admin.c` | log pages 20h to 23h, Features 1Dh and 1Eh, supported logs, effects log |
| `hw/femu/bbssd/ftl-fdp.c` | reclaim group, unit and handle setup, placed write, RU rotation, RUH Update, GC, deallocate |
| `hw/femu/bbssd/bb.c` | FDP checks on the bbssd geometry and refused knobs, RUNS |
| `hw/femu/bbssd/ftl.c` | FTL-thread dispatch to the FDP paths, background GC trigger |
| `hw/femu/scripts/run-blackbox-fdp.sh` | launcher |

## Related pages

- [FDP feature guide](../features/fdp.md)
- [BlackBox mode](../modes/blackbox.md)
- [Namespaces and subsystems](namespaces.md)
- [Property reference: Flexible Data Placement](../reference/properties.md#flexible-data-placement)
