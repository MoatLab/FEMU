# ZNS: the zoned namespace model

This chapter describes how FEMU implements the NVMe Zoned Namespace (ZNS)
command set: the zone state machine, how zones are laid out on the emulated
NAND, where each cost is charged, and what every property changes. To run a
ZNS device and use it from a guest, read the [ZNS mode guide](../modes/zns.md)
first; this page explains what happens inside.

## Purpose

A zoned namespace splits its logical blocks into zones. The host writes each
zone sequentially at the zone's write pointer, or with Zone Append, and
resets a zone before it writes it again. The device keeps no page-level
remapping for overwrites and runs no garbage collection; reclaiming space is
the host's job. FEMU's ZNS mode gives you:

- the zone state machine of the ZNS specification, with open and active
  zone limits, Zone Append, Zone Random Write Area (ZRWA), conventional
  zones, zone descriptor extensions and the Changed Zone List log page;
- a zone-to-NAND layout that decides which channels, LUNs and planes a zone
  occupies, so zone width changes internal parallelism;
- a per-zone write cache and NAND read, program and erase timing, so a
  zoned workload sees realistic latency.

ZNS is selected with `femu_mode=3` for the whole controller, or per
namespace with `znssd` in `namespace_modes` (see
[namespaces](namespaces.md#per-namespace-modes)).

## Place in the hierarchy

```text
 guest: blkzone, nvme zns, fio --zonemode=zbd, zoned btrfs/f2fs, zonefs
   |
   | NVMe queues (Read, Write, Zone Append, Zone Mgmt Send/Receive)
   v
 poller thread  -- nvme-io.c: nvme_io_cmd() --> ns->ext_ops.io_cmd = zns_io_cmd()
   |               zns.c: zone checks, write pointer, state machine,
   |                      data copy to the DRAM backend (backend_rw)
   | to_ftl ring
   v
 FTL thread     -- femu.c: femu_ftl_process_req() --> zftl.c: zns_ftl_process_req()
   |               write cache, L2P table, zone erase, NAND timing
   v
 NAND media     -- nand/: nand_media_op(), plane-gated timelines,
                   optional channel bus and program/erase suspend
   |
   | latency added to req->expire_time; to_poller ring
   v
 poller completes the command when the clock passes expire_time
```

The data itself always lives in the controller's DRAM backend. The NAND
model holds no data: it tracks where each 4 KiB logical page would sit and
how long each operation takes. The general request path is described in
[architecture](../concepts/architecture.md#2-frontend).

## Data structures

| Structure | File | Fields that matter |
| --- | --- | --- |
| `NvmeZone` | `zns/zns.h` | `d` (the zone descriptor the host reads: type `zt`, state `zs`, attributes `za`, `zcap`, `zslba`, `wp`), `w_ptr` (the write pointer used to place writes), list `entry` |
| `NvmeNamespace` (zoned part) | `nvme.h` | `zone_array`, `num_zones`, `zone_size` and `zone_capacity` in logical blocks, `zone_size_log2`, the lists `exp_open_zones`, `imp_open_zones`, `closed_zones`, `full_zones`, the counters `nr_open_zones` and `nr_active_zones` with their limits, the ZRWA fields `zrwa_size`, `zrwafg_size`, `zrwa_num`, `zrwa_avail`, `zd_extensions`, `id_ns_zoned` |
| `struct zns_ssd` | `zns/zns.h` | NAND geometry (`num_ch`, `num_lun`, `num_plane`, `num_blk`, `num_page`), the `ch -> fc -> plane -> blk` tree with per-block `page_wp`, `maptbl` (L2P per 4 KiB page), `cache` (write caches), `program_unit`, `stripe_unit`, `chnls_per_zone`, `zone_wp_slot[]`, `media`, `zone_lock`, the changed zone list |
| `struct zns_write_cache` | `zns/zns.h` | `sblk` (the zone it serves), `used`, `cap`, `lpns[]` |

There are two write pointers per zone. `w_ptr` moves when a write is
accepted, before its data is copied, so that two writes on different
pollers, or two appends, never get the same LBA. `d.wp` is the pointer the
host sees in a zone report; it moves when the write is finalized after the
copy. Without a ZRWA they agree once every accepted write has finished.

## Zone geometry

### Size, capacity and count

There is no zone size property. `zns_init_zone_cap()` derives it from the
namespace size and the `zns_` geometry, with a fixed 16 KiB NAND page
(`ZNS_PAGE_SIZE`):

```text
pages per block  = namespace bytes / 16 KiB / (zns_num_ch * zns_num_lun * zns_num_blk)
zone width       = zns_chnls_per_zone, or zns_num_ch when it is 0
zone size        = zone width * zns_num_lun * zns_num_plane * pages per block * 16 KiB
zone count       = namespace bytes / zone size          (rounded down)
zone capacity    = zns_zone_cap, or the zone size when it is 0
```

The namespace exposes `zone count * zone size` blocks (NSZE). Bytes past the
last whole zone are not exposed. Each zone's capacity is the same; a zone
accepts writes only below `ZSLBA + ZCAP` and reads up to `ZSLBA + ZSZE`.
The [mode guide](../modes/zns.md#zone-size-and-zone-count) has a table of
zone sizes for common settings.

### Zone layout over NAND

Zone `i` occupies one block index in a set of channels. With full-width
zones (`zns_chnls_per_zone` unset) the zone owns block `i` on every channel,
LUN and plane:

```text
 full width: zns_num_ch=4, zns_num_lun=2, zns_num_plane=2

             ch0         ch1         ch2         ch3
          LUN0 LUN1   LUN0 LUN1   LUN0 LUN1   LUN0 LUN1
  pl0     b0   b0     b0   b0     b0   b0     b0   b0     <- zone 0 = block 0
  pl1     b0   b0     b0   b0     b0   b0     b0   b0        everywhere
  pl0     b1   b1     b1   b1     b1   b1     b1   b1     <- zone 1 = block 1
  pl1     b1   b1     b1   b1     b1   b1     b1   b1
  ...
```

A narrower zone spans `zns_chnls_per_zone` channels. The channels form
`groups = zns_num_ch / zns_chnls_per_zone` groups, and the zones that share
one block index sit in different groups:

```text
 zns_num_ch=4, zns_chnls_per_zone=2 -> 2 channel groups

             group 0 (ch0, ch1)      group 1 (ch2, ch3)
  block 0    zone 0                  zone 1
  block 1    zone 2                  zone 3
  block 2    zone 4                  zone 5

  zone i: channels (i % groups) * width .. + width - 1, block i / groups
```

So narrowing the zones doubles the zone count for each halving of the
width, and each zone has fewer channels to program in parallel. The
geometry check refuses a configuration with more zones than
`zns_num_blk * groups`, since every zone needs its own block.

### Placement inside a zone

`get_new_page()` in `zftl.c` picks the next location from the zone's slot
counter `zone_wp_slot[zone]`. A slot is one (channel, LUN) pair. Slots go
channel first, then LUN:

```text
 slot s (full width):  ch = s % zns_num_ch
                       lun = (s / zns_num_ch) % zns_num_lun
 slot s (narrow):      ch = (zone % groups) * width + s % width
                       lun = (s / width) % zns_num_lun

 one slot programs, on each plane of that LUN, zns_flash_type pages of
 16 KiB (4 logical 4 KiB pages each):

   program unit = 16 KiB * zns_flash_type * zns_num_plane
   stripe unit  = program unit * zns_num_ch * zns_num_lun
```

With `run-zns.sh` (8 channels, 4 LUNs, 2 planes, QLC) the program unit is
128 KiB and the stripe unit 4 MiB. Each block keeps its own page write
pointer `page_wp`; a zone reset sets it, and the zone's slot counter, back to
zero.

## Zone state machine

The states and transitions below are the ones `zns.c` implements. Every
transition the host drives goes through `zns_assign_zone_state()`, which
also moves the zone between the per-state lists.

```text
     +-------+   write, append
     | Empty |----------------------------------------------------+
     +-------+                                                    |
      |  |  |      Open      +-----------------+   Open   +-------v---------+
      |  |  +--------------->| Explicitly Open |<---------| Implicitly Open |
      |  |                   +-----------------+          +-----------------+
      |  |                     |           ^                |           ^
      |  |               Close |           | Open    Close, |           | write
      |  |                     v           |     auto close v           |
      |  |  Set ZD Ext     +-----------------------------------------------+
      |  +---------------->|                    Closed                     |
      |                    +-----------------------------------------------+
      |  Finish            +-----------------------------------------------+
      +------------------->|                     Full                      |
                           +-----------------------------------------------+

  also to Full: a write that reaches ZCAP, or Finish, from either Open state
  or Closed
  Reset: Explicitly Open, Implicitly Open, Closed, Full --> Empty
  controller: injected write fault --> Read Only --(Offline action)--> Offline
```

| From | Event | To | Code |
| --- | --- | --- | --- |
| Empty | write or Zone Append | Implicitly Open | `zns_auto_open_zone()`, `zns_advance_zone_wp()` |
| Empty, Implicitly Open, Closed | Open Zone | Explicitly Open | `zns_open_zone()` |
| Empty | Set Zone Descriptor Extension | Closed (extension valid) | `zns_set_zd_ext()` |
| Implicitly or Explicitly Open | Close Zone | Closed | `zns_close_zone()` |
| Implicitly Open | another zone needs an open resource at the open limit | Closed | `zns_auto_transition_zone()` |
| Closed | write | Implicitly Open | `zns_advance_zone_wp()` |
| Empty, Open, Closed | Finish Zone | Full | `zns_finish_zone()` |
| Open, Closed | write reaches the zone capacity | Full | `zns_finalize_zoned_write()` |
| Open, Closed, Full | Reset Zone | Empty | `zns_reset_zone()` |
| any but Read Only | injected write fault on the zone | Read Only | `zns_nvme_rw()` |
| Read Only | Offline Zone | Offline | `zns_offline_zone()` |

Read Only and Offline are final: Reset and Finish refuse them with Invalid
Zone State Transition. Reads work in every state except Offline. Writes are
refused in Full (Zone Is Full), Read Only (Zone Is Read Only) and Offline
(Zone Is Offline).

Reset and Offline also deallocate the zone's slice of the DRAM backend
(`zns_deallocate_zone()`), so a read of a reset zone returns zeros, as the
specification requires for Empty and Offline zones.

Zone state lives only in QEMU memory. It survives a controller reset and a
guest reboot, and is lost when QEMU exits. `zns_ns_shutdown()`, which moves
open zones to Closed (or Empty when they hold nothing), runs only when the
device is removed.

### Open and active resources

`zns_max_open` and `zns_max_active` set the limits; 0 means no limit, and
then FEMU does not count. An active zone is one that is open or closed;
an open zone is implicitly or explicitly open.

```text
 write to an Empty zone, or Open of an Empty zone:
   1. need an active resource      -> else Too Many Active Zones, nothing changes
   2. at the open limit? close the oldest Implicitly Open zone
   3. need an open resource        -> else Too Many Open Zones
 write to a Closed zone: steps 2 and 3 only
```

Only implicitly open zones are closed to make room, oldest first. If every
open zone is explicitly open, the command fails with Too Many Open Zones.
Open with Select All opens every closed zone or none: it fails up front if
the closed zones would not fit under the open limit.

## Commands

`zns_io_cmd()` handles Read, Write, Zone Append, Zone Management Send and
Zone Management Receive. Other I/O opcodes go through the common path in
`nvme-io.c`, with these zoned rules:

- Compare is checked like a Read (`zns_check_compare()`).
- Dataset Management, Write Zeroes, Copy and Write Uncorrectable fail with
  Invalid Opcode on a zoned namespace: they would change blocks without
  going through the state machine.
- Flush and the I/O Management commands behave as on any namespace.

### Read and Write

A Write must start exactly at `w_ptr` and end at or below the zone
capacity, or it fails with Zone Invalid Write or Zone Boundary Error. A Read
must stay inside its zone unless cross-zone reads are on; see
[below](#reads-across-zone-boundaries).

### Zone Append

Zone Append names the zone by its ZSLBA. Under `zone_lock` the poller reads
`w_ptr`, places the data there, and advances the pointer in one step, so
appends on different queues never overlap. The completion carries the LBA
where the data landed. An append fails with Invalid Field when it does not
name a zone start or exceeds the Zone Append Size Limit, and with Zone
Boundary Error when it would cross the zone capacity.

The limit comes from `zns_zasl_bs` in bytes. At controller enable,
`zns_start_ctrl()` converts it to ZASL, a power of two in units of the
4 KiB controller page, which Identify Controller for CSI 2 reports. With
`zns_zasl_bs=0` Identify reports ZASL 0, and appends are held to MDTS
instead. Realize refuses a value that is not a power-of-two multiple of
4 KiB, rather than round it down.

### Zone Management Send

| Action | Select All acts on | Notes |
| --- | --- | --- |
| Close (01h) | open zones | |
| Finish (02h) | open and closed zones | moves `w_ptr` and `wp` to the capacity; does not program the write cache |
| Open (03h) | closed zones, all or none | bit 9 of CDW13 also allocates a ZRWA (single zone only) |
| Reset (04h) | open, closed and full zones | descriptor changes on the poller; the erase runs on the FTL thread |
| Offline (05h) | read-only zones | |
| Set Zone Descriptor Extension (10h) | not allowed | data is staged first and copied only if the zone is Empty |
| ZRWA Flush (11h) | not allowed | see [ZRWA](#zone-random-write-area-zrwa) |

A single-zone action must name the zone's start LBA, except ZRWA Flush,
which names a boundary inside the zone. Every action runs under the
namespace's `zone_lock`.

### Zone Management Receive

Report Zones (00h) and Extended Report Zones (01h, only with
`zns_zd_ext_size` set) return a 64-byte header with the matching zone count,
then one 64-byte descriptor per zone, followed in the extended report by
that zone's extension. The filter field takes the states 0 to 7, plus 9 for
zones with the Finished by Controller, Finish Recommended or Reset
Recommended attribute; FEMU never sets those attributes, so filter 9 always
reports none. The Partial Report bit limits the count to the descriptors
that fit. The write pointer field is all ones for Full, Read Only and
Offline zones and for conventional zones. The report is built under
`zone_lock`, so it is a consistent snapshot.

## Optional zone features

### Zone Random Write Area (ZRWA)

A ZRWA lets the host write anywhere in a window above the write pointer and
commit the window later. `zns_zrwa_size` (ZRWAS) and `zns_zrwafg_size`
(ZRWAFG, the flush granularity) are in logical blocks; `zns_zrwa_num` is
how many zones may hold a ZRWA at once (NUMZRWA).

```text
        w_ptr                      w_ptr + ZRWAS              w_ptr + 2*ZRWAS
          |<------- ZRWA window ------->|<-- implicit flush area -->|
  zone: [..committed..|.................|...........................|....]
                      ^ a write may start anywhere in here ---------^
  a write that ends past the window moves w_ptr up by whole ZRWAFG units
  ZRWA Flush to LBA x (inside the window, x - w_ptr + 1 a multiple of
  ZRWAFG) sets w_ptr = x + 1
```

- A ZRWA is allocated by Open Zone, or by Set Zone Descriptor Extension,
  with CDW13 bit 9, on an Empty zone while `zrwa_avail` is non-zero;
  otherwise the command fails with Invalid Zone Operation or No ZRWA
  Resources.
- Writes must start in `[w_ptr, w_ptr + 2 * ZRWAS)` and stay below the
  zone capacity. Zone Append to a ZRWA zone fails with Invalid Zone
  Operation.
- When `w_ptr` reaches the capacity the zone becomes Full and the resource
  goes back. Finish, Reset and Offline also return it.
- Identify Namespace for CSI 2 sets OZCS bit 1 (ZRWASUP), NUMZRWA
  (zero-based), ZRWAS, ZRWAFG and ZRWACAP bit 0 (explicit flush).

Realize refuses a ZRWA configuration where ZRWAS or ZRWAFG exceed 65535,
ZRWAS is not a multiple of ZRWAFG, the zone capacity is not a multiple of
ZRWAFG, `zns_zrwa_num` is 0, or the granularity or count is set without a
window.

### Conventional zones

`zns_num_conv_zones=N` makes the first N zones conventional (zone type 1).
A conventional zone accepts writes anywhere inside it, keeps no write
pointer, never changes state, and rejects Zone Append (Invalid Field) and
every zone management action (Invalid Zone State Transition). N above the
zone count is lowered to the zone count. The ZNS specification defines only
sequential-write-required zones, so Linux refuses a namespace that reports
a conventional zone; the [mode guide](../modes/zns.md#optional-zone-features)
explains the consequence.

### Reads across zone boundaries

`zns_cross_zone_read=on` sets OZCS bit 0 (Read Across Zone Boundaries). A
read that runs past its zone is then accepted if every zone it touches is
readable (not Offline). Without it, such a read fails with Zone Boundary
Error.

### Zone descriptor extensions

`zns_zd_ext_size` sets a per-zone extension in bytes, a multiple of 64 and
at most 255 units of 64. Identify reports it in LBAFE.ZDES. Setting an
extension takes an Empty zone to Closed with the Zone Descriptor Extension
Valid attribute, and needs an active resource.

### Changed Zone List and Zone Descriptor Changed notices

The Changed Zone List log page (BFh) lists zones whose descriptor changed
for a reason the host did not cause. The ZNS specification excludes every
change that follows a Zone Management Send, a write that opens or fills a
zone, and the controller closing a zone to free a resource. In FEMU the only
change left is the injected write fault: with `err_write_fail_ppm` set, one
write in `1000000 / err_write_fail_ppm` completes with Write Fault and its
zone becomes Read Only. That zone's ZSLBA is added to the list by
`zns_record_changed_zone()`.

```text
 failed write --> zone Read Only --> changed_zones[] (dedup, up to 511)
                                       |
                    AEC bit 27 set? ---+--> Asynchronous Event Notice,
                    (Set Features 0Bh)      Zone Descriptor Changed,
                                            log page BFh, this NSID
 Get Log Page BFh, NSID = the zoned namespace:
   8-byte count, then 8-byte ZSLBAs (count FFFFh and no entries on overflow)
   read without RAE: list and pending event cleared
```

- The list is per namespace. The command must name the zoned namespace's
  NSID: 0, FFFFFFFFh or a non-zoned namespace fail. The offset must be a
  multiple of 8.
- Identify Controller advertises OAES bit 27 (ZDCN) whenever a zoned
  namespace exists. The notice itself is sent only when the host has set
  bit 27 of Asynchronous Event Configuration; the list is kept either way.
  Linux does not set that bit, which is why `scripts/zone-aen-probe.c` sets
  it itself.
- The supported log pages list (log 00h) shows BFh for CSI 2 only.

## Threads, locks and where latency is charged

| Work | Thread | Lock |
| --- | --- | --- |
| Zone checks, auto open, `w_ptr` advance, append placement | poller of the submission queue | `zns->zone_lock` |
| Data copy between guest memory and the DRAM backend | poller | none (the LBA range was reserved under the lock) |
| `d.wp` update, Full transition, injected fault | poller | `zone_lock` |
| Zone Management Send and Receive, reset state change | poller | `zone_lock` |
| Changed Zone List read | admin path | `zone_lock` |
| Write cache, L2P table, block page pointers, erase, NAND timing | the controller's FTL thread | single owner, no lock |

One FTL thread serves every ZNS, bbssd and CSD namespace of a controller
(`femu_ftl_thread()` in `femu.c`). It returns a latency for each request,
which is added to `expire_time`; the poller posts the completion once the
clock passes it. See [timing model](../concepts/timing-model.md#compute-then-hold).

What each command is charged, in `zftl.c`:

| Command | Cost |
| --- | --- |
| Write, Zone Append | the larger of two figures: 1 us for each 4 KiB logical page put into the zone's write cache, summed over the pages added since the request's last cache flush, and the program time of any cache this write caused to be programmed (an evicted cache, or this zone's cache when it filled) |
| Read | the largest NAND read time over the 4 KiB pages it touches that have been programmed; pages still in a write cache, or never written, cost nothing |
| Zone Reset | the largest erase time over the blocks of each reset zone; zones reset by one command share planes, so the command ends with its last erase |
| Open, Close, Finish, Report, Offline | nothing |

### Write cache

A write cache holds the logical page numbers of one zone's partial stripe;
its capacity is one stripe unit (`stripe unit / 4 KiB` pages). There are
`zns_num_wc` caches, or `zns_max_open` when that is 0, or 3 when both are 0.

```text
 write to zone z
   cache bound to z?  yes -> append LPNs
                      no  -> take an empty cache, else evict the fullest
                             cache (program it now, cost charged to this
                             write), bind it to z
   cache full?        program it: one program unit per slot, each plane of
                      the slot's LUN one NAND program op, L2P updated
 Zone Reset of z: drop z's cache without programming it
```

Fewer caches than zones written at once makes writes evict each other's
caches and pay a program each time. That is why the default follows
`zns_max_open`. The [timing model](../concepts/timing-model.md#zns-write-cache)
puts this in context with the other modes.

### NAND timing

`zns_nand_media_init()` hands the timing to the shared NAND media layer
(see `design/nand-timing.md`) with:

- one latency per cell type for read, program and erase, from the
  `zns_flash_type` row of the built-in table in `zns/zns.h` and
  `nand/nand.h`, replaced by `zns_pg_rd_lat`, `zns_pg_wr_lat` and
  `zns_blk_er_lat` when set; MLC and PLC have no built-in row and need all
  three;
- the array gated per plane only (`NAND_GATE_PLANE_ONLY`): operations on
  different planes of one LUN overlap, operations on one plane queue;
- a shared channel bus only if `zns_cmd_addr_lat`, `zns_pg_xfer_lat` or
  `zns_status_lat` is non-zero;
- program and erase suspend for reads if `zns_pe_suspend` is non-zero, with
  `zns_tsusp_ns` charged per preempting read.

## Parameters

All ZNS properties are on the `femu` device and are listed with types and
defaults in the [ZNS section of the property reference](../reference/properties.md#zns).
The geometry and limits are controller-wide: every zoned namespace of a
controller uses the same `zns_` values with its own size.

| Group | Properties | Interactions |
| --- | --- | --- |
| Geometry | `zns_num_ch`, `zns_num_lun`, `zns_num_plane`, `zns_num_blk`, `zns_chnls_per_zone` | Set zone size and count with the namespace size. `zns_num_ch` 1 to 128 and `zns_num_plane` 1 to 8 (PPA field widths). Pages per block must come out in 1 to 65536. `zns_chnls_per_zone` must divide `zns_num_ch`. |
| Zone shape | `zns_zone_cap`, `zns_num_conv_zones`, `zns_zd_ext_size` | `zns_zone_cap` between one logical block and the zone size. |
| Limits | `zns_max_open`, `zns_max_active` | Each at most the zone count; open at most active when both are set. `zns_max_open` also sets the default cache count. |
| Write cache | `zns_num_wc` | At most the zone count. |
| ZRWA | `zns_zrwa_size`, `zns_zrwafg_size`, `zns_zrwa_num` | All three together, or none. |
| Reads, appends | `zns_cross_zone_read`, `zns_zasl_bs` | `zns_zasl_bs` 0 follows `mdts`. |
| Timing | `zns_flash_type`, `zns_pg_rd_lat`, `zns_pg_wr_lat`, `zns_blk_er_lat`, `zns_cmd_addr_lat`, `zns_pg_xfer_lat`, `zns_status_lat`, `zns_pe_suspend`, `zns_tsusp_ns` | Cell type also multiplies the program unit. All latencies are in ns and must not be negative. |
| Shared with other modes | `devsz_mb`, `namespaces`, `namespace_sizes`, `namespace_modes`, `lba_index`, `nlbaf`, `mdts`, `err_write_fail_ppm` | `lba_index` must select a block of 4 KiB or less. |

The BlackBox geometry and timing properties (`nchs`, `pg_rd_lat` and so on)
do not apply to a zoned namespace. The controller also refuses to become
ready unless the host selects a 4 KiB memory page (CC.MPS).

A device with 64 MiB zones of half width on an 8-channel geometry:

<!-- femu-example: design-zns-narrow -->
```text
-device femu,devsz_mb=2048,femu_mode=3,zns_num_ch=8,zns_num_lun=4,zns_num_plane=2,zns_num_blk=32,zns_chnls_per_zone=4,zns_max_open=8,zns_max_active=16
```

## Statistics and outputs

| Output | What it shows | Source |
| --- | --- | --- |
| Zone report (Zone Management Receive) | state, write pointer, capacity and attributes of each zone | `zns_zone_mgmt_recv()` |
| Changed Zone List (BFh) | zones taken read only by injected write faults | `zns_changed_zone_list()` |
| SMART / Health (02h) | host data units and commands read and written, counted on the poller for every mode; Media Errors includes the injected ZNS write faults | `nvme-io.c`, `zns_media_errors()` |
| Vendor log C0h | not filled for zoned namespaces: ZNS runs no garbage collection, so there is no write amplification to report | [log pages and counters](../reference/log-pages-and-counters.md#vendor-log-page-c0h) |
| QEMU log | the ZNS geometry, program unit, stripe unit and cache count at realize (`[FEMU] Log:` lines) | `zns_init_params()` |

## Validation

| Check | What it covers |
| --- | --- |
| qtest cases in `hw/femu/tests/qtest/femu-test.c` | `zone-reset`, `zone-open-limits`, `zone-active-limit`, `zone-append-parallel`, `zoned-append-limit`, `zoned-append-mdts0`, `zone-bad-dptr`, `zone-report-length`, `mdts0-zone-report`, `zoned-format-index`, `zoned-compare`, `zone-change-notice`, `zrwa-reopen`, `zrwa-write-bounds`, `zrwa-odd-granule`, `zrwa-zd-ext`, `io-fuzz-zoned` |
| Documentation examples | each tagged ZNS example starts under qtest, identifies the controller and writes and reads one block |
| `hw/femu/scripts/zone-aen-probe.c` | in-guest, manual: Zone Descriptor Changed notice end to end with `err_write_fail_ppm` |
| Guest tools | `blkzone`, `nvme zns`, fio `--zonemode=zbd` on a Linux guest, as in the [mode guide](../modes/zns.md#verify) |

The NAND timing goes through the same media layer as bbssd, whose timing
math has unit tests in `hw/femu/tests/unit/test-nand-media.c`.

## Limits

- No zone attribute is ever set by the controller: no Finish Recommended,
  Reset Recommended or Finished by Controller, and ZOC is 0 (no variable
  zone capacity, no zone active excursions).
- The only zone change the host does not cause is the injected write fault.
  Zones never go read only or offline because of wear.
- No wear, retention or read disturb model, and no garbage collection.
- Finish does not program the zone's write cache, and Close does not either.
  A read of data that is still in a write cache costs nothing.
- One latency per cell type: no page-type (LSB/MSB) difference and no
  program/erase cycle effect.
- The zone geometry properties are shared by all zoned namespaces of a
  controller.
- Zone state and data exist only in QEMU memory and are lost when QEMU
  exits. A large namespace needs that much free host memory.
- Namespace Management cannot create zoned namespaces, and metadata and
  Streams are refused on them (see [namespaces](namespaces.md)).

## How to extend it

- A new zone management action: add a case to `zns_zone_mgmt_send()` and an
  `op_handler_t` that `zns_do_zone_op()` can apply to one zone or a list.
  Return resources through the same ladder the existing handlers use
  (`zns_aor_dec_open()`, `zns_aor_dec_active()`, `zns_zrwa_release()`).
- A new reason for a zone to change on its own: change the state, then call
  `zns_record_changed_zone()`. Never call it from a host-driven transition;
  the specification excludes those from the log.
- New timing: extend `zns_nand_media_init()` and `zns_advance_status()` in
  `zftl.c`; the media layer does the plane and channel bookkeeping. Work that
  touches the L2P table, block page pointers or timelines must run on the
  FTL thread, as Zone Reset does through `req->zone_resets`.
- A new property: declare it in `femu.c` next to the other `zns_` ones, add
  the field to `ZNSCtrlParams`, copy it per namespace in
  `nvme_init_namespaces()` if it is a per-zone limit, validate it in
  `zns_check_params()` or `zns_init_zone_geometry()`, give it a description
  and topic so `gen-property-docs.py` documents it, and add a qtest case.

## Source map

| File | What is there |
| --- | --- |
| `hw/femu/zns/zns.h` | zone and zoned Identify structures, `struct zns_ssd`, write cache, built-in cell timings, open and active counters |
| `hw/femu/zns/zns.c` | geometry checks, zone state machine, Read/Write/Append, Zone Management Send and Receive, ZRWA, Changed Zone List, Identify, mode registration (`nvme_register_znssd()`) |
| `hw/femu/zns/zftl.c` | zone-to-NAND placement, write cache, L2P table, zone reset and erase, media layer setup, `zns_ftl_process_req()` |
| `hw/femu/zns/zftl.h` | `zns_zone_reset()`, debug and assert macros |
| `hw/femu/femu.c` | `zns_` property definitions, per-namespace copies of the zone limits, FTL thread dispatch |
| `hw/femu/nvme-io.c` | opcode filtering for zoned namespaces, host counters |
| `hw/femu/nvme-admin.c` | Identify Controller CSI 2 (ZASL), OAES.ZDCN, supported log pages, SMART media errors |
| `hw/femu/nand/` | shared NAND media timing |

## Related pages

- [ZNS mode guide](../modes/zns.md)
- [Namespaces and subsystems](namespaces.md)
- [Timing model](../concepts/timing-model.md)
- [Property reference: ZNS](../reference/properties.md#zns)
