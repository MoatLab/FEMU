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
(bbssd) namespace has the placement data path.

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
         +-- namespace 1                     placement handles PH 0..nruh-1
               |                             (PH i -> RUH i)
               +-- struct ssd (BlackBox FTL)
                     FemuRuHandle[nruh]       current RU, GC RU, counters
                     FemuReclaimGroup[nrg]    free list, full list,
                                              victim queues
                     FemuReclaimUnit[nru]     one line (superblock) each,
                                              write pointer, valid pages
                     lines -> blocks on every channel, LUN and plane
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
| Reclaim groups (NRG) | 1; any other value is refused | `fdp.nrg` |
| Reclaim units per group | as set, at most 65536 | `fdp.nru` |
| Reclaim unit handles (NRUH) | 1 to `fdp.nru`; must be set | `fdp.nruh` |
| Handle type (RUHT) | Persistently Isolated; with `fdp.isolation_mode` non-zero the last handle is Initially Isolated | `fdp.isolation_mode` |
| Reclaim unit size (RUNS) | one BlackBox superblock (see below); the subsystem default of 96 MiB applies only when no bbssd controller overwrites it | `fdp.runs` |
| Reclaim group identifier format (RGIF) | 0 with one group | derived |
| MAXPIDS | 128 (reported zero-based as 127) | fixed |
| Event filter | every supported event type enabled on every handle | Set Features 1Eh |

When a controller joins, `nvme_ns_init_fdp()` gives namespace 1 every
handle in order: placement handle `i` is RUH `i`, the namespace's ENDGID is
1, and each handle's RUAMW starts at a full unit. The controller then sets
CTRATT bit 19 (FDP), and the effects log lists I/O Management Send and
Receive. CTRATT bit 4 (Endurance Groups), ENDGIDMAX = 1 and each
namespace's ENDGID = 1 come with any subsystem, FDP or not, since its one
endurance group is what log 09h reports.

The BlackBox side (`bb.c`, `ftl-fdp.c`) adds the following, for a CSD
namespace as for a bbssd one, since CSD runs the same FTL
(`bb_init_fdp()`):

- RUNS is overwritten with the bytes of one superblock:
  `nchs * luns_per_ch * pls_per_lun * pgs_per_blk * secs_per_pg * secsz`.
  `fdp.runs` must be unset or exactly that.
- The FTL uses `min(lines, fdp.nru)` reclaim units, one line each
  (`lines_per_ru = 1`). Lines left over are not used by the placement write
  path.
- It needs at least `fdp.nruh * fdp.nrg + fdp.nruh + 1` units: one open unit
  per handle, one collection unit per handle, and one spare.
- `gc_thres_pcent` and `gc_thres_pcent_high` set the free-unit watermarks
  instead of free-line watermarks. The forced watermark keeps at least one
  unit free, even where the percentage rounds to none, unless
  `gc_thres_pcent_high` is 100 (`bb_fdp_forced_units()`): a pass can fill its
  destination part way through a victim and needs a free unit to go on.
- The namespace must fit in the units left after the reserve
  (`bb_check_capacity()`), or the controller is refused at realize:

  ```text
  reserve = fdp.nruh * fdp.nrg          one open unit per handle and group
          + Persistently Isolated handles one collection unit each
          + forced watermark            free units forced GC keeps
  usable  = (units - reserve) * superblock size
  ```

  The Initially Isolated handle collects into its open unit and adds
  nothing. One namespace is checked against the whole pool because nothing
  else can draw on it: FDP takes a single namespace and a single controller,
  and namespace management is refused with it. A 1 MiB namespace on 64 KiB superblocks with four Persistently
  Isolated handles needs 16 + 4 + 4 + 1 = 25 units; with 19 or 23 lines,
  both accepted before, random writes over all four handles failed nearly
  all of them. A partly exposed last page counts as a whole one. bbssd
  refuses a namespace that does not fit rather than shrink
  it, as it does without placement and with `op_pcent`.

## Placement of writes

```text
 Write: CDW12 bits 23:20 DTYPE, CDW13 bits 31:16 DSPEC
   |
   | DTYPE == 2 (data placement) and DSPEC is a valid placement identifier?
   |   no  -> placement handle 0, reclaim group 0
   |          (if DTYPE was 2: host event "Invalid Placement Identifier")
   |   yes -> PID = (RG << (16 - RGIF)) | PH ;  with RGIF 0, PID = PH
   v
 PH --ns->fdp.phs[]--> RUH --curr_ru--> active RU --wptr--> next page
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

Writes of different handles never share an RU, but they share the NAND:
every RU spans all channels, so concurrent handles compete for the same
planes and channel buses.

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
- keeps the current unit if nothing was written to it yet;
- otherwise takes a fresh unit (running one GC pass if none is free) and
  retires the old one as if it had filled, or fails the command with
  Capacity Exceeded if no unit can be freed;
- in both cases records a host event "Reclaim Unit Not Fully Written" when
  the unit still had room (RUAMW not zero) and that event is enabled on the
  handle, so an update of a handle whose unit is still empty records one
  too.

I/O Management Receive with operation 1 (RUH Status) returns one descriptor
per placement handle and reclaim group: PID, RUHID, EARUTR (always 0) and
the RUAMW of the handle's current unit, or 0 while the handle has none
because its last unit filled with no free unit to follow it.

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

- Background: after every request the FTL thread handles, if a reclaim
  group's free units are at or below
  `(1 - gc_thres_pcent / 100) * units`, it runs one pass. A background pass
  puts its victim back, whatever the policy, unless the victim is empty or
  at least 1/8 of its pages are invalid.
- Foreground: before a placed write and before each of its pages, while
  free units are at or below `(1 - gc_thres_pcent_high / 100) * units` (at
  least one unless `gc_thres_pcent_high` is 100), it
  runs passes until the pressure clears or no victim is left. The host write waits for them.
  Foreground passes, and the pass RUH Update may run, always collect their
  victim.

### Victim selection

`gc_strategy` selects the policy. The BlackBox `gc_policy` property does
not apply under FDP and only `greedy` is accepted with it.

| `gc_strategy` | Policy |
| --- | --- |
| 0 (default) | greedy: the unit with the fewest valid pages |
| 1 | cost-benefit: an empty unit first, otherwise the largest `(1 - u) * age / u`, with `u` the valid pages over the pages written (over the unit's pages until a page is invalidated) and `age` the time since a page in the unit was last invalidated, computed at selection time; a unit never invalidated counts as maximally old |
| 2 | random among the victims |
| 4 | per handle: the unit with the fewest valid pages among the per-handle queues of Persistently Isolated handles, falling back to greedy |

### Where relocated data goes

The handle type decides the destination of the valid pages, which is what
"isolation" means here:

```text
 victim from a Persistently Isolated handle h
     -> h's own GC unit (gc_ru, taken from the free list on demand)
        data of h stays apart from every other handle, before and after GC

 victim from an Initially Isolated handle
     -> the current unit of the last handle (RUH nruh-1)
        data may be mixed with other relocated data after GC
```

With the default `fdp.isolation_mode=0` every handle is Persistently
Isolated. With it set, only the last handle is Initially Isolated, so its
relocated data goes back into its own current unit.

A pass copies every valid page of the victim, invalidating each old copy as
it goes, and only then erases the planes of each LUN as one multi-plane
erase when `enable_gc_delay` is on (the default). It adds the copied bytes
to MBMW and the erased bytes to MBE, records a controller event for the
handle, and returns the unit to the free list. If the destination runs out
of space part way, the pass stops before erasing anything: the pages already
moved live at their new location, the rest stay in the victim, and the
victim goes back on the queue to be finished by a later pass.

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
Identifier, and need a subsystem (without one they fail with Invalid Log
Page); 21h, 22h and 23h fail with FDP Disabled when FDP is off. The supported log pages list (00h) shows them only while
FDP is on.

| Log | Content | Code |
| --- | --- | --- |
| 20h FDP Configurations | header with NUMFDPC 0 (one configuration), then one descriptor: FDPA (valid, RGIF), NRG, NRUH, MAXPIDS, NNSS 256, RUNS, and NRUH handle descriptors with the RUHT of each handle | `nvme_fdp_confs()` |
| 21h Reclaim Unit Handle Usage | header with NRUH, then one descriptor per handle with its RUHA (1 = host-specified for every handle the namespace was given) | `nvme_fdp_ruh_usage()` |
| 22h FDP Statistics | HBMW, MBMW and MBE as 128-bit counters; FEMU fills the low 64 bits | `nvme_fdp_stats()` |
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
| HBMW (host bytes with metadata written) | bytes a Write, Copy or Write Zeroes without Deallocate actually programmed | `fdp_count_write()` |
| MBMW (media bytes with metadata written) | the same host bytes, plus bytes relocated by GC | `fdp_count_write()`, `do_gc_fdp_style()` |
| MBE (media bytes erased) | bytes of every block erased by GC | `do_gc_fdp_style()` |

The ratio MBMW / HBMW is the write amplification of the endurance group.
The counters are charged after the write, from the pages it placed, so a
write that ran out of space adds only what it wrote. They are reset by a
deallocate with `fdp_trim_erase_all` set.

### Events

There are two rings of 63 events each, one for host events and one for
controller events. When a ring is full the oldest event is overwritten.
Each event carries the Timestamp feature's current value.

| Type | Ring | Generated when |
| --- | --- | --- |
| 0h Reclaim Unit Not Fully Written | host | RUH Update moves a handle off a unit that still had room |
| 3h Invalid Placement Identifier | host | a placed write (Write, Copy, Write Zeroes) on a bbssd namespace has DTYPE 2 and a DSPEC that is not a valid PID; checked against the event filter of placement handle 0; other modes never raise it |
| 81h (implicit reclaim unit change) | controller | GC frees a unit of the handle |
| 1h, 2h, 80h | | accepted by the event filter, never generated |

Get and Set Features 1Eh (FDP Events) read and change the enabled event
types of one placement handle, named in CDW11; an unsupported type in a Set
fails with Invalid Field. Get Features 1Dh (FDP Mode) for endurance group 1
reports whether FDP is on. Set Features 1Dh fails with Invalid Field for an
endurance group other than 1 or without a subsystem, and otherwise with
Command Sequence Error, since the mode may only change while the endurance group has
no namespaces and FEMU builds the namespace at realize.

## Threads, locks and where latency is charged

| Work | Thread | Notes |
| --- | --- | --- |
| Parsing DTYPE and DSPEC, validating RUH Update identifiers, I/O Management Receive | poller | data copy to the DRAM backend happens here too |
| Placement, RU rotation, GC, deallocate, RUH Update on bbssd | FTL thread | sole owner of the FTL structures |
| Event append | poller or FTL thread | `events_lock` in the endurance group |
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
| `fdp.nrg` | `femu-subsys` | Must be 1. |
| `fdp.runs` | `femu-subsys` | Unset, or the superblock size. |
| `fdp.isolation_mode` | `femu-subsys` | Non-zero makes the last handle Initially Isolated. |
| `gc_strategy` | `femu` | Victim policy, above. No effect without FDP. |
| `fdp_trim_erase_all` | `femu` | Whole-device reset on deallocate. No effect without FDP. |
| `gc_thres_pcent`, `gc_thres_pcent_high` | `femu` | Background and foreground watermarks, as fractions of the units. |
| BlackBox geometry (`nchs`, `luns_per_ch`, `pls_per_lun`, `blks_per_pl`, `pgs_per_blk`, `secs_per_pg`, `secsz`) | `femu` | Sets RUNS (one superblock) and the number of lines, hence units. |

Refused under FDP on a bbssd controller: `buffer_size`, `hot_cold_sep`,
`read_reclaim_limit`, `retention_limit_sec`, `ecc_retention_sec`,
`trim_lat_ns`, a `mapping` other than `page`, and a `gc_policy` other than
`greedy`. Refused on any controller with FDP: more than one namespace, a
second controller in the subsystem, `meta`, `streams`, a KV namespace.
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
| qtest cases in `hw/femu/tests/qtest/femu-test.c` | `fdp-events`, `fdp-features`, `fdp-report-length`, `fdp-ruh-usage`, `fdp-write-zeroes`, `fdp-write-zeroes-placed`, `fdp-ruh-update`, `fdp-ruh-update-full`, `wide-lba-fdp`, `io-fuzz-fdp`, `copy-fdp`, `log-contents-fdp`, `ns-mgmt-unavailable-fdp`, `fdp-csd-knobs`, `fdp-csd-runs` |
| Documentation examples | each tagged FDP example starts under qtest and moves one block |
| `hw/femu/scripts/fdp-test-nvme-admin.sh` | in-guest nvme-cli checks against the `run-blackbox-fdp.sh` configuration; manual |
| `hw/femu/tests/unit/test-pqueue.c` | the priority queue the victim queues are built on |

## Limits

- One reclaim group, one FDP configuration, one namespace and one
  controller per FDP subsystem.
- An RU is exactly one line; RUNS cannot be smaller or larger than a
  superblock.
- Only bbssd places data. A NoSSD, ZNS or OCSSD controller in an FDP
  subsystem answers the log pages and features, and RUH Update resets
  the handle's RUAMW and records event 0h if the unit still had room; no
  data is placed. CSD uses the bbssd path, with the same refused knobs and
  RUNS. KV is refused.
- Page mapping only, no write buffer, no read reclaim or retention model
  under FDP.
- EARUTR is always 0; there is no active reclaim unit time limit, so event
  1h is never raised.
- The 128-bit statistics carry only their low 64 bits.
- Metadata, Streams and Namespace Management do not combine with FDP.

## How to extend it

- More reclaim groups: the FTL keeps one active unit per handle; a group
  other than 0 needs a current unit per (handle, group) before `fdp.nrg`
  can be lifted in `nvme_subsys_setup_fdp()`.
- Larger reclaim units: `lines_per_ru` in `ssd_init_fdp_params()` is the
  hook, but `fdp_advance_ru_pointer()` retires a unit after its first line;
  it must walk `ru->lines[]` first.
- A new victim policy: add a value to the GC strategy enum in
  `bbssd/ftl.h`, a case in `select_victim_ru()`, and accept it in the
  geometry checks of `bbssd/ftl-geom.c`. Keep the two heap positions
  (`pos` for the group queue, `ruh_pos` for a handle queue) separate.
- A new event: generate it with `nvme_fdp_record_event()` after checking the
  handle's filter, and add the type to `nvme_fdp_events_supported[]` and
  `nvme_fdp_evf_shifts[]` in `nvme.h`.

## Source map

| File | What is there |
| --- | --- |
| `hw/femu/femu.c` | `femu-subsys` properties, `nvme_subsys_setup_fdp()`, `nvme_ns_init_fdp()`, `nvme_ns_refresh_fdp()`, single-controller and single-namespace checks, CTRATT |
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
