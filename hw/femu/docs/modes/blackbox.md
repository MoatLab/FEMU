# BlackBox SSD (BBSSD)

BlackBox mode (`femu_mode=1`) emulates a conventional NVMe SSD: the device
runs its own flash translation layer (FTL), garbage collection (GC) and NAND
timing, and the guest sees an ordinary block device. Use it to study how a
host workload behaves on a real-looking SSD: latency under GC, write
amplification, the effect of over-provisioning, caches and write buffers.

If you want a drive with no media timing at all, use [NoSSD](nossd.md). If you
want the host to run the FTL, use [OCSSD](ocssd.md) or [ZNS](zns.md).

## Requirements

- Host and guest: see [the mode table](../concepts/choosing-a-mode.md#every-mode-at-a-glance)
  and [requirements.md](../getting-started/requirements.md#kernel-per-mode).
  Any guest kernel with the NVMe driver works.
- Host memory: the whole namespace lives in host DRAM. `run-blackbox.sh`
  creates a 12 GiB device, so it needs about 17 GiB of free RAM
  ([memory planning](../getting-started/requirements.md#memory)).
- Guest tools: `nvme-cli` and `fio`, both in the image from
  `make-guest-image.sh`.

## Launch

From `build-femu/`, with a guest image in place:

<!-- femu-example: blackbox-launcher -->
```bash
./run-blackbox.sh
```

The script prints the `-device` line it builds. It is equivalent to:

<!-- femu-example: blackbox-device -->
```
-device femu,devsz_mb=12288,namespaces=1,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=256,blks_per_pl=256,pls_per_lun=1,luns_per_ch=8,nchs=8,pg_rd_lat=40000,pg_wr_lat=200000,blk_er_lat=2000000,ch_xfer_lat=0,gc_thres_pcent=75,gc_thres_pcent_high=95
```

To change the geometry or latency, edit the variables at the top of
`run-blackbox.sh`. Its console output goes to `build-femu/log`.

## Configuration

Every property below is listed with its default and range in the
[property reference](../reference/properties.md). This section says which
ones matter for BlackBox and how they interact.

### Capacity and geometry

Properties: [mode and capacity](../reference/properties.md#mode-capacity-and-namespaces),
[NAND geometry](../reference/properties.md#nand-geometry-bbssd-csd-kv).

The NAND geometry is `nchs` channels, each with `luns_per_ch` LUNs, each
with `pls_per_lun` planes of `blks_per_pl` blocks of `pgs_per_blk` pages. A
page is `secs_per_pg` sectors of `secsz` bytes. The raw NAND capacity is
the product of all seven. With the defaults it is 16 GiB
(8 x 8 x 1 x 256 x 256 x 8 x 512 = 17,179,869,184 bytes), and a page is
4 KiB.

The namespace the guest sees is `devsz_mb` MiB, which can be smaller than
the raw NAND. The rest is spare area for GC. FEMU refuses a namespace that
leaves GC no free lines (see [Limits and refusals](#limits-and-refusals)).
A line is one block on every plane of every LUN, so there are `blks_per_pl`
lines.

To state the over-provisioning directly, set `op_pcent`. FEMU then backs the
device with the full raw NAND and exposes `raw / (1 + op_pcent/100)`, and
`devsz_mb` is ignored. This example has 512 MiB of NAND and exposes about
410 MiB:

<!-- femu-example: blackbox-op -->
```
-device femu,femu_mode=1,nchs=2,luns_per_ch=4,blks_per_pl=64,op_pcent=25
```

### NAND timing

Properties: [NAND timing](../reference/properties.md#nand-timing-bbssd-csd-kv).
How the time is computed: [timing model](../concepts/timing-model.md#nand-operations).

- `pg_rd_lat`, `pg_wr_lat` and `blk_er_lat` set flat read, program and erase
  times in nanoseconds.
- `nand_cell_type` (1 SLC, 2 MLC, 3 TLC, 4 QLC) replaces the flat times with
  built-in per-page-type timing:

<!-- femu-example: blackbox-tlc -->
```
-device femu,devsz_mb=1024,femu_mode=1,nand_cell_type=3
```

- `cmd_addr_lat`, `pg_xfer_lat` (or `ch_xfer_lat`) and `status_lat` add a
  shared channel bus. It is modelled only when one of them is non-zero.
- `pe_suspend` and `tsusp_ns` let a read suspend a program or erase on its
  LUN.
- `trim_lat_ns` charges each Dataset Management deallocate range.

### Garbage collection

Properties: [garbage collection, mapping and caches](../reference/properties.md#garbage-collection-mapping-and-caches).

Background GC starts when the share of lines in use reaches
`gc_thres_pcent` (75). Foreground GC runs inside writes from
`gc_thres_pcent_high` (95). `gc_policy` picks the victim line:

- `greedy` (the default): the line with the fewest valid pages.
- `random`: a random line among the GC candidates.
- `cost-benefit`: the line with the largest age x (1 - u) / 2u, where u is
  the share of valid pages.
- `fifo`: the oldest closed line.
- `d-choice`: samples 4 candidate lines at random (a line can be drawn
  twice) and takes the one with the fewest valid pages.

`random` and `d-choice` draw from a generator seeded by `gc_seed` (default
0), so the same configuration and workload pick the same victims and give the
same write amplification on every run. Set a different `gc_seed` per run to
vary them.

### Mapping and caches

Properties: [garbage collection, mapping and caches](../reference/properties.md#garbage-collection-mapping-and-caches).

- `mapping`: `page` (default, a full table in DRAM), `dftl` (a cached table
  of `mapping_cache_mb` MiB whose misses cost NAND reads), `hybrid` or `fast`
  (log-block schemes).
- `read_cache_mb` and `cache_evict` add a DRAM read cache. It models timing
  only: a hit costs DRAM time and skips the NAND read, but the cache holds no
  data, so NAND stays the source of truth. `cache_evict` is `clock` (the
  default), `random`, `lru` or `arc` (a scan-resistant 2Q variant, not full
  ARC).

The two log-block schemes follow published designs:

| `mapping` | Model |
| --- | --- |
| `hybrid` | BAST log-block mapping (Kim 2002): one log block per data block, merged when that log block fills or the log pool runs out |
| `fast` | FAST log-block mapping (Lee et al. 2007): a sequential log block plus a shared, fully associative pool for random writes |

Both suit some workloads more than others: sequential overwrites merge
cheaply, random overwrites force full merges. A merge is charged to the NAND
timeline and counted as relocated pages, so it shows in latency and in the
write amplification factor.
- `hot_cold_sep` writes overwrites of mapped pages to separate lines.

### Write buffer and power loss

Properties: [garbage collection, mapping and caches](../reference/properties.md#garbage-collection-mapping-and-caches),
[namespace management, streams and power loss](../reference/properties.md#namespace-management-streams-and-power-loss).

`buffer_size` is the DRAM write buffer capacity in NAND pages, not bytes.
Once the buffer is `buffer_thres_pcent` full, the next write programs a batch
of the least recently written pages. A write the buffer absorbs costs no
NAND time; the cost moves to the write that evicts it. Flush drains the
buffer. Set `vwc=1` so that the guest sees a volatile write cache: Linux
then sends Flush, and the guest can turn the buffer off with feature 06h. A read of a page the buffer
still holds costs no NAND time, and deallocating such a page drops it
instead of writing it out later.

<!-- femu-example: blackbox-buffer -->
```
-device femu,devsz_mb=1024,femu_mode=1,buffer_size=1024,vwc=1
```

`power_loss=on` makes the buffer hold data, and the QOM property
`simulate-power-loss` drops what it holds
([runtime properties](../reference/runtime-properties.md#power-loss-trigger)).

### Wear, retention and errors

Properties: [reliability and wear](../reference/properties.md#reliability-and-wear).

All of these are off by default.

- `ecc_step_ns` and `ecc_retention_sec` make reads of worn or old blocks
  slower.
- `pe_cycles_rated` and `nand_bad_blocks` feed SMART Percentage Used and
  Available Spare.
- Log page C0h counts plane reads, programs and erases. With
  `energy_read_nj`, `energy_prog_nj` and `energy_erase_nj` set from a part's
  datasheet, it also reports their energy in uJ.
- `wl_spread` turns on static wear levelling. When the lines in service
  differ by more than that many erases, the least worn full line moves into
  the most worn free line, so cold data rests on worn blocks and young blocks
  rejoin the rotation. It runs only when the data write pointer has just
  taken an empty line, which it exchanges for the worn one, so it adds no
  write pointer, and it copies at most a quarter of what the host writes.
- `age_scale` makes data age faster than wall time for `retention_limit_sec`
  and `ecc_retention_sec`, so a study of months of retention runs in
  minutes. I/O timing and collection order stay as they are.
- `blk_pe_limit` gives each block an erase limit (`blk_pe_spread` varies it
  per block, from `blk_pe_seed`). When a line's erase takes a block to its
  limit, the line leaves service if enough lines remain: the namespace's
  lines, the free lines forced collection keeps, an open line to write into
  and one free line. Otherwise the block stays in service and sets the SMART
  reliability warning (critical warning bit 2). Writes never fail because of
  wear.
- `spare_lines` holds lines back as spare blocks. A worn-out block is first
  replaced by a spare of its plane, when every plane with a worn-out block in
  the line has one. SMART Available Spare is then the spare blocks the
  emptiest plane has left; without spare lines, it is the lines retirement can
  still take.
- When the spare falls below its threshold, or the first block stays in
  service past its limit, the controller raises a SMART asynchronous event
  (information 02h or 00h) if the host enabled bit 0 or bit 2 of
  Asynchronous Event Configuration. Each is raised once.
- With `blk_pe_limit`, SMART Percentage Used counts erases against the sum
  of the blocks' limits. `query-femu` shows retired and spare lines with
  their own states.
- `err_read_unc_ppm` and `err_write_fail_ppm` fail a fixed share of reads or
  writes. The failures come at a fixed period, so a run repeats exactly.
- `read_reclaim_limit` and `retention_limit_sec` rewrite lines that were read
  too often or hold old data. The line is picked on a read and rewritten on a
  following write, so a workload that never writes never triggers it.

Both refresh knobs act only when something reads the line. A region nothing
reads is never refreshed: modelling a background media scan would need a
timer that FEMU does not run.

`read_reclaim_limit` is the number of reads a block may take before its line
is refreshed:

<!-- femu-example: blackbox-read-reclaim -->
```
-device femu,devsz_mb=1024,femu_mode=1,read_reclaim_limit=100000
```

The line is chosen on the read but rewritten on the next write, where
relocation already costs something, so a read never waits behind a whole
line. One line is queued at a time and at most one is refreshed per write,
so the rate follows how often the host writes, not how hard it reads. The
cost shows up as write amplification. On a 512 MiB region read six times
over with a low limit, 5 lines were refreshed and 77824 pages relocated, and
the write amplification factor went from 1.000 to 1.542. Lowering the limit
from 500 to 10 moved it only from 1.542 to 1.628. A workload that only reads
never refreshes anything, where a real drive would do it in the background,
so model read-only ageing some other way.

### Host link and controller firmware

Properties: [host link and controller firmware](../reference/properties.md#host-link-and-controller-firmware).

`pcie_bandwidth_mbps`, `pcie_prop_delay_ns` and `fw_cpu_ns` add link and
firmware time to every Read and Write. See the
[timing model](../concepts/timing-model.md#host-link-and-controller-firmware).

### Features on top of BlackBox

- [Flexible Data Placement](../features/fdp.md) (`femu-subsys,fdp=on`).
- [Several namespaces](../features/multi-namespace.md), each with its own FTL.
- [Namespace management, metadata and protection information](../features/ns-management-and-pi.md).
- Streams (`streams=on`), which needs `mapping` `page` or `dftl`.

## Use it from the guest

These commands run inside the guest. From the host, prefix each with
`./run-guest-ssh.sh` as in the [quick start](../getting-started/quick-start.md).

Check the device:

```sh
sudo nvme list
sudo nvme id-ctrl /dev/nvme0 | grep -E '^(mn|sn) '
```

The model is `FEMU BlackBox-SSD Controller` and the serial number starts
with `vSSD`.

Write before you read. A read of a page that was never written costs no
NAND time, so a read benchmark on a fresh device measures nothing. Fill the
range first, then read it:

```sh
sudo fio --name=fill --filename=/dev/nvme0n1 --direct=1 --ioengine=libaio \
    --rw=write --bs=128k --iodepth=16 --size=4G
sudo fio --name=rr --filename=/dev/nvme0n1 --direct=1 --ioengine=libaio \
    --rw=randread --bs=4k --iodepth=1 --size=4G --runtime=30 --time_based
```

With an idle device and queue depth 1, the completion latency (`clat`) is
about `pg_rd_lat` plus guest and poller overhead.

To make GC run, write more than the free lines hold. GC starts when 75% of
the lines are in use, so on the default 16 GiB of NAND that takes about
12 GiB of writes, one pass over the 12 GiB namespace. Random writes over
the namespace several times keep GC busy:

```sh
sudo fio --name=age --filename=/dev/nvme0n1 --direct=1 --ioengine=libaio \
    --rw=randwrite --bs=4k --iodepth=32 --loops=5
```

Read the write amplification factor and media counters from the vendor log
page C0h. The first four bytes are the WAF times 1000, bytes 4 to 7 are
reserved, and the three 8-byte counters from byte 8 are host pages written,
pages GC moved, and pages programmed:

```sh
sudo nvme get-log /dev/nvme0 --log-id=0xc0 --log-len=512 -b | od -An -t u4 -N 4
sudo nvme get-log /dev/nvme0 --log-id=0xc0 --log-len=512 -b | od -An -t u8 -j 8 -N 24 -w24
```

[log-pages-and-counters.md](../reference/log-pages-and-counters.md#vendor-log-page-c0h)
lists every field. Wear and host totals are in the SMART log:

```sh
sudo nvme smart-log /dev/nvme0
```

The vendor admin command 0xEF switches GC time and the NAND times on or off
while the guest runs, for example to fill a device quickly:

```sh
sudo nvme admin-passthru /dev/nvme0 --opcode=0xef --cdw10=4   # NAND times to 0
sudo nvme admin-passthru /dev/nvme0 --opcode=0xef --cdw10=3   # back to 40 us, 200 us, 2 ms
```

Code 3 restores the built-in times, not the ones on your command line.
Codes 3 and 4 change only the flat times, so they have no effect with
`nand_cell_type` set. The
[timing model](../concepts/timing-model.md#changing-timing-at-run-time) lists
every code.

## Limits and refusals

FEMU checks the configuration at realize and stops QEMU with a message.
The common ones:

| Message | Cause and fix |
| --- | --- |
| `FEMU bbssd: namespace 1 exposes 1024 MiB of the 1024 MiB this geometry has, leaving garbage collection no room; expose at most 960 MiB per namespace (lower devsz_mb, or set op_pcent)` | `devsz_mb` (or the namespace size) does not leave the free lines GC needs. Lower `devsz_mb`, grow the geometry, or set `op_pcent`. |
| `FEMU bbssd: the geometry has only N lines, fewer than the M garbage collection needs free` | `blks_per_pl` is too small for the reserve that `gc_thres_pcent_high`, `hot_cold_sep`, Streams and log-block mapping add up to. |
| `FEMU bbssd: nchs must be greater than 0, got 0` | A geometry property is 0 or negative. The same message names any of them. |
| `FEMU bbssd: the geometry describes N sectors, which exceeds the 2147483647 the FTL can address; ...` | The NAND is too large; reduce one of the geometry properties. |
| `FEMU bbssd: unknown mapping "x"`, `unknown gc_policy "x"`, `unknown cache_evict "x"; ...` | A misspelled policy name. |

If the host cannot allocate `devsz_mb` (or, with `op_pcent`, the raw NAND)
of memory, QEMU aborts in GLib with `failed to allocate N bytes` and a core
dump.

Reserve per namespace: `(1 - gc_thres_pcent_high/100) * blks_per_pl` lines,
rounded down, plus one for the write pointer, one more with `hot_cold_sep`,
one more with `mapping=hybrid` or `fast`, and `streams.max + 1` with Streams.
The namespace must fit in the remaining lines.

## Verify

1. `sudo nvme list` in the guest shows `/dev/nvme0n1` with model
   `FEMU BlackBox-SSD Controller` and the size you set.
2. After a 4 KiB random write run, the C0h WAF reads 1000 or more and the
   host page counter (byte 8) equals the pages fio wrote.
3. A queue depth 1 random read of written data takes about `pg_rd_lat`.

## Troubleshooting

- **Reads are faster than the configured latency.**
  The range was never written. Unwritten pages have no mapping and cost no
  NAND time. Fill the range first.
- **The WAF stays at 1.000.** GC has not run, or found only lines with no
  valid pages, as after a sequential overwrite. GC starts after about 12 GiB
  of writes on the default geometry. Run random writes over the namespace
  more than once, or use `op_pcent` to make the namespace a known fraction
  of the NAND.
- **`Property 'femu.cell_type' not found`, or `flash_type` has no effect.**
  The BlackBox cell type is `nand_cell_type`. `flash_type` belongs to OCSSD.
- **QEMU aborts with `failed to allocate`.** The device is in host DRAM. Lower
  `devsz_mb` or free host memory.
- **Latency is higher than the model.** Completions are posted by the
  poller, which needs a host core. Give each `femu-poller` thread and the
  `FEMU-FTL-Thread` a core of its own
  ([timing model](../concepts/timing-model.md#compute-then-hold)).
- **Data is gone after QEMU exits.** FEMU keeps the device only in host
  memory and writes nothing to a file. A guest reboot keeps the data.

Related issues: #16, #50, #52, #92, #113, #130, #132, #137.

## Related pages

- [Timing model](../concepts/timing-model.md)
- [Architecture: the BBSSD FTL](../concepts/architecture.md#bbssd)
- [Quick start](../getting-started/quick-start.md), which runs this mode end
  to end
- [Device property reference](../reference/properties.md)
