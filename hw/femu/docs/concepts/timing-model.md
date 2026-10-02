# Timing model

FEMU makes an emulated SSD take as long as a real one would. This page
explains how it computes that time, how it makes the guest wait for it, which
properties change it, and how to check what it did. The
[architecture page](architecture.md) shows where each step runs.

## Compute, then hold

FEMU does not slow down the data copy. An NVMe command's data is copied
between guest memory and the memory backend as soon as the command is
parsed. Separately, a model computes when the command would have finished on
the emulated device, and the poller does not post the completion before that
time:

1. The poller stamps the command with the current host time, `stime`, read
   from `QEMU_CLOCK_REALTIME`. Its completion time starts equal to it.
2. The mode's model adds the command's latency to the completion time.
3. The poller keeps completed commands in a priority queue ordered by
   completion time and posts each one once the host clock passes it
   (`nvme_process_cq_cpl()` in `hw/femu/nvme-io.c`).

Two things follow from this:

- Time in the model is host wall-clock time, and the guest sees the same
  clock. A 200 us program makes the guest wait 200 us.
- The model gives a lower bound. A completion is posted on the first poller
  sweep after it is due, so a poller that does not get a host CPU (too few
  cores, no pinning) adds delay on top. Give each `femu-poller` and the
  `FEMU-FTL-Thread` its own core when you measure latency.

The CXL SSD works differently: the vCPU thread that made the access waits out
the media time itself before the access completes (see
[CXL SSD](#cxl-ssd)).

## Which mode charges what

| Mode | Time charged for | Computed in |
| --- | --- | --- |
| NoSSD | nothing | n/a |
| BBSSD | NAND reads, programs and erases; write buffer and read cache hits; DFTL mapping misses; GC; deallocate (`trim_lat_ns`) | `FEMU-FTL-Thread` |
| CSD | as BBSSD, plus program run time on a compute unit and copies into device memory | FTL thread; compute units on the `femu-csd-cu` threads; copies in the poller |
| ZNS | NAND reads, programs and erases; write cache accesses | `FEMU-FTL-Thread` |
| KV | NAND reads and programs for values, erases on reclaim, and a fixed per-command cost of one page read | poller |
| OCSSD | NAND reads, programs and erases, optional channel transfer | poller |

Optional host-link and firmware-CPU models apply on top of any NVMe mode (see
[Host link and controller firmware](#host-link-and-controller-firmware)).

## NAND operations

`nand_media_op()` in `hw/femu/nand/nand-media.c` computes one read, program or
erase. BBSSD, CSD, KV and ZNS all use it; OCSSD uses its own older model.

### Operation times

The array time of an operation comes from one of two sources:

- **Flat times** (BBSSD, CSD, KV with `nand_cell_type=0`, the default):
  every read takes `pg_rd_lat`, every program `pg_wr_lat`, every erase
  `blk_er_lat`, in nanoseconds. Defaults are 40 us, 200 us and 2 ms.
  `pgtype_lat` with `cell_pages` scales the program time by the page's
  position in its wordline (lower to upper).
- **Cell-type tables**: `nand_cell_type` 1 to 4 (SLC, MLC, TLC, QLC) uses the
  built-in per-page-type read and program times and erase time in
  `hw/femu/nand/nand.h`, and ignores the flat times.
- **ZNS** uses one built-in value per cell type for `zns_flash_type`
  (`hw/femu/zns/zns.h`; SLC, TLC and QLC have one), unless `zns_pg_rd_lat`,
  `zns_pg_wr_lat` or `zns_blk_er_lat` overrides it.

Properties: [NAND timing](../reference/properties.md#nand-timing-bbssd-csd-kv),
[ZNS](../reference/properties.md#zns).

### Parallelism

The media layer keeps a busy-until time for each unit that can work on its
own:

- **BBSSD, CSD, KV**: one per LUN. An operation starts at the later of its
  own start time and the LUN's busy-until time, and the LUN is busy until the
  operation ends. All planes of a LUN are busy together. Erasing a whole
  line (GC, FDP GC and KV reclaim) with `pls_per_lun` > 1 erases the same
  block on every plane of a LUN as one operation, which takes one erase time
  instead of one per plane.
- **ZNS**: one per plane, so the planes of a LUN work in parallel.

Different LUNs (or ZNS planes) never wait for each other. A command that
covers several pages issues them all at its start time, and its latency is
that of the slowest page. Because the BBSSD write pointer moves across
channels first and then LUNs, consecutive pages of a large write fall on
different LUNs and are programmed in parallel.

Properties: [NAND geometry](../reference/properties.md#nand-geometry-bbssd-csd-kv).

### Channel bus

The channel bus is off by default: transfers between controller and NAND
take no time and channels never contend. It is turned on when any bus phase
has a non-zero time:

| Phase | BBSSD, CSD, KV | ZNS |
| --- | --- | --- |
| Command and address | `cmd_addr_lat` | `zns_cmd_addr_lat` |
| Page data transfer | `pg_xfer_lat`, or `ch_xfer_lat` when `pg_xfer_lat` is 0 | `zns_pg_xfer_lat` |
| Status read | `status_lat` | `zns_status_lat` |

With the bus on, phases on one channel run one at a time. A program sends its
command and data over the bus before the array starts. A read sends its
command, waits for the array, then moves its data out; the data-out is booked
for when it will happen, so other LUNs can use the bus in the meantime.

### Program and erase suspend, ECC

- `pe_suspend` (`zns_pe_suspend` for ZNS) lets a read go ahead of a program or
  erase that is running on its LUN (plane for ZNS). The first such read pays
  `tsusp_ns` (`zns_tsusp_ns`); the suspended operation then ends later by
  `tsusp_ns` plus the time of every read that went ahead of it.
- `ecc_step_ns` adds read time for worn or old blocks: one step per 750
  erases of the block, plus one per `ecc_retention_sec` seconds since its line
  was filled, at most four steps.

Properties: [NAND timing](../reference/properties.md#nand-timing-bbssd-csd-kv),
[Reliability and wear](../reference/properties.md#reliability-and-wear).

## BBSSD FTL costs

On top of the NAND operations, the BBSSD FTL (also used by CSD) charges:

- **Write buffer** (`buffer_size` > 0, in pages): a write the buffer accepts
  costs one DRAM access, `pg_rd_lat` / 16 (2.5 us with the defaults). When
  the buffer passes `buffer_thres_pcent`, the write that pushed it there also
  pays for programming a batch of buffered pages. A read of a buffered page
  costs the same DRAM access and does not reach NAND. Flush programs
  everything buffered and pays for it. FUA writes and stream writes skip the
  buffer.
- **Read cache** (`read_cache_mb` > 0): a hit costs a DRAM access instead of a
  NAND read.
- **Mapping cache** (`mapping=dftl`): a miss in the cached mapping table of
  `mapping_cache_mb` adds a NAND read of the translation page, after a NAND
  program if the entry it replaces is dirty.
- **Deallocate**: `trim_lat_ns` per Dataset Management range.

Properties: [Garbage collection, mapping and
caches](../reference/properties.md#garbage-collection-mapping-and-caches).

## Garbage collection

GC moves valid pages out of a victim line and erases it. Its NAND reads,
programs and erases go through the same per-LUN timelines as host commands,
so a host command that needs a LUN that GC is using waits for it. That is
how GC shows up in host latency.

- **Background GC** runs one line after a request, on the FTL thread, when
  the share of lines in use has reached `gc_thres_pcent` (default 75).
- **Foreground GC** runs inside a write when the share has reached
  `gc_thres_pcent_high` (default 95), and repeats until it drops below. The
  write waits for the LUNs it needs, which GC has just made busy.
- `gc_policy` picks the victim line. Write amplification depends on it and on
  how full the device is.

GC time can be switched off at run time with the vendor command below; GC
still moves the pages, but its NAND operations then take no time.

ZNS has no device GC: the host resets zones, and a reset charges the erase of
the zone's blocks.

## ZNS write cache

A ZNS write goes into a per-zone SRAM write cache and costs 1 us per 4 KiB
page. When the cache is full, or another zone needs it, the cached pages are
programmed across the zone's planes and the write that triggered it pays for
the program. `zns_num_wc` sets the number of caches (default:
`zns_max_open`, or 3 when that is 0).

## OCSSD

OCSSD keeps a busy-until time per chip (LUN) and per channel in
`hw/femu/timing-model/timing.c`. A write first moves its data over the channel,
then programs the chip; a read occupies the chip, then moves its data out.
Open-Channel 1.2 charges channel transfer only with `oc12_channel_timing=on`,
using `ch_xfer_lat` per page or the `flash_type` table value when that is 0.
Open-Channel 2.0 charges no channel time. Read, program and erase times come
from the `flash_type` table (SLC, MLC, TLC, QLC) and can be changed at run
time with vendor admin command 0xEE.

Properties: [OCSSD](../reference/properties.md#ocssd-open-channel).

## KV and CSD

KV computes its latency in the poller with the BBSSD NAND model: value
pages are read and programmed, reclaim erases are charged to the command that
triggers them, and every command pays one page read for the index lookup,
on a LUN chosen by the key's hash. A command completes when its last NAND
operation does.

CSD runs a program on the compute unit that frees up first. A program holds
its unit for its declared run time, or for its measured host run time
multiplied by the program's own scale, or by `csf_runtime_scale` when it
gives none. `nr_cu` sets how many units run at once. A copy from the
namespace into device memory costs `pg_rd_lat`.

Properties: [CSD](../reference/properties.md#csd-computational-storage).

## Host link and controller firmware

Three optional models apply to every NVMe mode. They are added in the poller
after the media time and before the completion is queued:

- `pcie_bandwidth_mbps`: each Read and Write is charged its size divided by
  this bandwidth, on one queue per direction, so transfers in the same
  direction wait for each other.
- `pcie_prop_delay_ns`: a fixed delay added to each Read and Write after its
  transfer.
- `fw_cpu_ns`: a fixed cost per Read, Write and Zone Append on one modelled
  controller core, which caps the command rate at about one per `fw_cpu_ns`.

All three are 0 (off) by default. With any of them on, NoSSD also completes
through the priority queue instead of inside the sweep.

Properties: [Host link and controller
firmware](../reference/properties.md#host-link-and-controller-firmware).

## CXL SSD

A `femu-cxl-ssd` access is timed on the vCPU thread that made it:

| Access | Media time |
| --- | --- |
| Cache hit | none |
| Read miss | one NAND page read; nothing if the FTL has never mapped the page |
| Write miss | one NAND page read to fill the page, which then becomes dirty |
| Eviction of a dirty page | one NAND page program, charged to the access that caused it |
| Prefetched page | none for the page itself; a dirty page it evicts is written back at the access's cost |
| Any access with `cache-pages=0` | a NAND read or program for every access |
| Access through a direct mapping (`der=memslot` or `cylon`) | none, and it is not counted; it never reaches QEMU. A `memslot` mapped page counts as dirty, so its eviction costs a program |

The access hands the page to the `femu-cxl-ftl` worker, which runs the same
BBSSD FTL and NAND model as above and returns the latency. The vCPU then waits
out what is left of it with the BQL released: it sleeps until 100 us before
the deadline and spins for the rest. Other properties:

- Geometry and NAND times: `channels`, `luns-per-channel`, `pages-per-block`,
  `blocks-per-plane`, `read-ns`, `program-ns`, `erase-ns`, `channel-ns`, and
  GC thresholds `gc-threshold`, `gc-threshold-high`.
- `ftl=off` charges no media time at all.
- `cylon-first-touch-program=on` charges a program instead of a free read on
  the first access to an unmapped page; `cylon-free-writeback=on` makes
  dirty write-backs free. Both reproduce published Cylon experiments and are
  off by default.
- `concurrent-misses` decides whether misses to different pages wait for the
  media together or one after another.

`flush-cache` (QMP) and cache control commands on BAR5 also wait for the
media time of the write-backs they cause, on the thread that runs them.

Properties: [femu-cxl-ssd
cache](../reference/properties.md#cache), [NAND geometry and
timing](../reference/properties.md#nand-geometry-and-timing).

## Changing timing at run time

A BBSSD controller (`femu_mode=1`) accepts the vendor admin command 0xEF,
with the action in CDW10. It applies to every namespace of the controller
that has a BBSSD FTL. From the guest:

```sh
sudo nvme admin-passthru /dev/nvme0 --opcode=0xef --cdw10=2
```

| CDW10 | Effect |
| --- | --- |
| 1 | GC NAND operations take time (the default) |
| 2 | GC NAND operations take no time |
| 3 | Set the flat read, program and erase times to the built-in 40 us, 200 us and 2 ms |
| 4 | Set the flat read, program and erase times to 0 |
| 5 | Print the number of completions posted 20 us or more after they were due and the total number of completions to QEMU's standard output, then reset both |
| 6, 7 | Turn per-command debug logging on or off; it prints only in a build with `FEMU_DEBUG_NVME` defined |

Code 3 restores the built-in values, not the ones given on the command line.
Codes 3 and 4 change only the flat times: channel bus phases, the
`nand_cell_type` tables, `ecc_step_ns` and `trim_lat_ns` stay in force, and
write buffer and read cache hits still cost 1 us when `pg_rd_lat` is 0.
For a controller linked to a CXL SSD, it restores the medium's `read-ns`,
`program-ns`, `erase-ns` and `channel-ns` instead.

## Measuring

- **Latency seen by the guest**: run `fio` with a direct I/O engine and read
  the completion latency (`clat`). With an idle device and queue depth 1, a
  4 KiB random read on BBSSD should take about `pg_rd_lat` plus guest and
  poller overhead. Write the range first: a read of a page that was never
  written is not charged any NAND time.
- **Write amplification and media counters**: the vendor log page C0h holds
  the write amplification factor, host and NAND page counts, GC copies, write
  buffer hits and more. Read it with
  `sudo nvme get-log /dev/nvme0 --log-id=0xc0 --log-len=512 -b`. The layout is
  in [log pages and counters](../reference/log-pages-and-counters.md#vendor-log-page-c0h).
- **Health**: `sudo nvme smart-log /dev/nvme0` reports Percentage Used and
  Available Spare from the wear model, and host read and write totals.
- **CXL SSD**: the device's QOM counters, read with `qom-get` through QMP,
  include `media-time-ns` (total media time charged), `media-reads`,
  `media-writes`, `cache-hits`, `cache-misses` and the direct mapping counters.
  `media-full` must stay 0 for a valid measurement. See
  [runtime properties](../reference/runtime-properties.md#media-counters).

## Related pages

- [Architecture](architecture.md)
- [Choosing a mode](choosing-a-mode.md)
- [Device property reference](../reference/properties.md)
- [CXL SSD design note](../cxlssd.md)
