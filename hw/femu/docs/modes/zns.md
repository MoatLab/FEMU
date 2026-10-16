# Zoned Namespace SSD (ZNS)

ZNS mode (`femu_mode=3`) emulates an NVMe SSD with the Zoned Namespace
command set. The namespace is divided into zones. The host writes each zone
sequentially at its write pointer (or with Zone Append), and resets a zone
before writing it again. The device runs no garbage collection: reclaiming
space is the host's job. FEMU models the zone state machine, open and active
zone limits, a pool of zone write caches and the NAND time of each read, program
and erase.

Use it to develop and measure zoned software: zoned file systems (btrfs,
f2fs), zonefs, RocksDB or other log-structured stores, and zone-aware
schedulers. For a conventional SSD with a device FTL, use
[BlackBox](blackbox.md).

## Requirements

- Host and guest: see [the mode table](../concepts/choosing-a-mode.md#every-mode-at-a-glance)
  and [requirements.md](../getting-started/requirements.md#kernel-per-mode).
  The guest kernel needs zoned block device support
  (`CONFIG_BLK_DEV_ZONED=y`) and must be new enough to drive NVMe ZNS. The
  Linux 6.8 image from `make-guest-image.sh` works.
- The host driver must set a 4 KiB NVMe memory page size (CC.MPS), as Linux
  does. The controller refuses to become ready with another page size.
- Guest tools: `nvme-cli` with the `zns` commands, `blkzone` from
  util-linux, and `fio` for zoned workloads (`--zonemode=zbd`).

## Launch

From `build-femu/`:

<!-- femu-example: zns-launcher -->
```bash
./run-zns.sh
```

The FEMU device in that script is:

<!-- femu-example: zns-device -->
```
-device femu,devsz_mb=4096,namespaces=1,zns_num_ch=8,zns_num_lun=4,zns_num_plane=2,zns_num_blk=32,zns_flash_type=4,femu_mode=3
```

That is a 4 GiB namespace with 16 zones of 256 MiB and 512-byte logical
blocks. The variables at the top of `run-zns.sh` set the geometry.

## Configuration

ZNS has its own geometry and timing properties, all prefixed `zns_`. The
BlackBox geometry and timing properties (`nchs`, `pg_rd_lat` and so on) do
not apply. Every property is in the [ZNS section of the property
reference](../reference/properties.md#zns).

### Zone size and zone count

There is no zone size property. The zone size follows from the namespace
size and the geometry:

```
pages per block = namespace size / 16 KiB / (zns_num_ch * zns_num_lun * zns_num_blk)
zone width      = zns_chnls_per_zone, or zns_num_ch when it is 0
zone LUNs       = zns_luns_per_zone, or zns_num_lun when it is 0
zone size       = zone width * zone LUNs * zns_num_plane * pages per block * 16 KiB
zone count      = namespace size / zone size
                = zns_num_ch * zns_num_lun * zns_num_blk
                  / (zone width * zone LUNs * zns_num_plane)
```

So, when the divisions are exact, the zone count does not depend on the
namespace size, and the zone size grows with it. Pages per block are rounded
down, so an uneven size gives a smaller zone and a leftover. Some configurations:

| Settings | Namespace | Zones | Zone size |
| --- | --- | --- | --- |
| no `zns_` properties, `devsz_mb=1024` | 1 GiB | 16 | 64 MiB |
| `run-zns.sh` | 4 GiB | 16 | 256 MiB |
| `run-zns.sh` with `zns_num_blk=128` | 4 GiB | 64 | 64 MiB |
| `run-zns.sh` with `zns_chnls_per_zone=2` | 4 GiB | 64 | 64 MiB |

To get more, smaller zones, raise `zns_num_blk` or narrow the zones with
`zns_chnls_per_zone`, which must divide `zns_num_ch`:

<!-- femu-example: zns-more-zones -->
```
-device femu,devsz_mb=4096,femu_mode=3,zns_num_ch=8,zns_num_lun=4,zns_num_plane=2,zns_num_blk=128

-device femu,devsz_mb=4096,femu_mode=3,zns_num_ch=8,zns_num_lun=4,zns_num_plane=2,zns_num_blk=32,zns_chnls_per_zone=2
```

A narrower zone spans fewer channels, so a single zone has less internal
parallelism.

`zns_luns_per_zone` narrows a zone on the LUN axis in the same way. It must
divide `zns_num_lun`. With both at 1, each zone owns one die, as in the
single-die zone of ConfZNS (SYSTOR '23):

<!-- femu-example: zns-one-die-zones -->
```
-device femu,devsz_mb=4096,femu_mode=3,zns_num_ch=8,zns_num_lun=4,zns_num_plane=2,zns_num_blk=32,zns_chnls_per_zone=1,zns_luns_per_zone=1
```

`zns_zone_order` sets which axis a zone fills first. `ch` (the default)
puts consecutive programs on different channels. `lun` puts them on the
LUNs of one channel, so their page transfers take turns on that channel:

```
 zns_chnls_per_zone=2, zns_luns_per_zone=2: the slots of one zone

 order ch:   slot 0 ch0/LUN0   slot 1 ch1/LUN0   slot 2 ch0/LUN1   slot 3 ch1/LUN1
 order lun:  slot 0 ch0/LUN0   slot 1 ch0/LUN1   slot 2 ch1/LUN0   slot 3 ch1/LUN1
```

Linux uses a ZNS namespace only when its zone size is a power of two. Keep
`devsz_mb` (or each ZNS namespace's size), `zns_num_ch`, `zns_num_lun`,
`zns_num_plane` and `zns_num_blk` powers of two, or
check the result with the formula above.

`zns_zone_cap` sets a zone capacity below the zone size, in bytes. The host
can write only the first `zns_zone_cap` bytes of each zone.

### Logical block size

The namespace starts with 512-byte blocks. `lba_index` picks another of the
`nlbaf` formats (512 bytes doubling with each index), so `lba_index=3` gives
4 KiB blocks. ZNS accepts block sizes up to 4 KiB.

<!-- femu-example: zns-4k -->
```
-device femu,devsz_mb=4096,femu_mode=3,lba_index=3
```

Properties: [LBA formats](../reference/properties.md#lba-formats-metadata-and-protection).

### Open and active zone limits

`zns_max_open` and `zns_max_active` set the Maximum Open and Maximum Active
Resources. Both default to 0, which means no limit. Neither may exceed the
zone count, and `zns_max_open` may not exceed `zns_max_active`:

<!-- femu-example: zns-limits -->
```
-device femu,devsz_mb=4096,femu_mode=3,zns_num_ch=8,zns_num_lun=4,zns_num_plane=2,zns_num_blk=128,zns_max_active=16,zns_max_open=8
```

`zns_num_wc` sets the size of the pool of zone write caches. A zone being
written takes a cache from the pool; a write goes into it and costs 1 us per
4 KiB page. The cached pages are programmed when the cache fills, or when
another zone needs a cache and none is free. The default is
`zns_max_open`, or 3 when that is 0.

### NAND timing

`zns_flash_type` picks the cell type: 1 SLC, 2 MLC, 3 TLC, 4 QLC (the
default) or 5 PLC. SLC, TLC and QLC have built-in read, program and erase
times. MLC and PLC have none, so they need `zns_pg_rd_lat`, `zns_pg_wr_lat`
and `zns_blk_er_lat`. Those three also override the built-in times for the
other types. `zns_cmd_addr_lat`, `zns_pg_xfer_lat` and `zns_status_lat` add a
shared channel bus, and `zns_pe_suspend` with `zns_tsusp_ns` lets reads
suspend a program or erase. By default each plane runs on its own.
`zns_lun_contention=1` makes the planes of one LUN take turns, as on one die.
A zone reset then erases the planes of a LUN in one multi-plane operation.
By default a reset of a non-empty zone erases every block of the zone.
`zns_reset_by_fill=1` erases only the blocks that hold programmed pages, so
the reset time and the wear follow the zone's fill. See the [timing model](../concepts/timing-model.md#zns-write-cache).

A read takes one latency per flash type by default. `zns_page_types=1` gives
each read the latency of its page type, from SLC to QLC. A program writes a
whole wordline, one page of each type, so it keeps its one latency. A
flush after a partial eviction can start in the middle of a wordline and
still pays one program time. The
spread between types comes from the shared NAND table. It is scaled so that
the mean over a wordline is the read latency of the flash type, which
`zns_pg_rd_lat` can set.

```
 QLC wordline, read latency 85 us (the default mean)
 page type    lower   lower-center   upper-center   upper
 shared (us)  59.3    85.3           127.2          169.6
 ZNS (us)     45.7    65.7            98.0          130.6    mean 85
```

`zns_ecc_step_ns` adds ECC read time as the block wears, as bbssd
`ecc_step_ns` does: one step per 750 erases of the block, up to 4 steps.
ZNS counts the wear only, with no retention term. Both are off by default.
`zns_ecc_step_ns`, and `zns_pg_rd_lat` with `zns_page_types`, must be at
most one hour.

### Optional zone features

All of these are off by default.

- **Zone Random Write Area.** Set `zns_zrwa_size` and `zns_zrwafg_size` (in
  logical blocks) and `zns_zrwa_num` (zones that may hold one at once). A zone
  opened with the ZRWA flag accepts writes anywhere in a window above the
  write pointer. The write pointer advances only in whole flush-granularity
  units: when a write crosses the end of the window, or when the host
  flushes explicitly. Finishing or resetting the zone returns its ZRWA
  resource. With all three properties at 0 the namespace advertises no ZRWA.

<!-- femu-example: zns-zrwa -->
```
-device femu,devsz_mb=1024,femu_mode=3,zns_zrwa_size=64,zns_zrwafg_size=8,zns_zrwa_num=2
```

- **Conventional zones.** `zns_num_conv_zones=N` makes the first N zones
  accept writes anywhere inside the zone. They keep no write pointer
  (reported as all ones) and reject zone management and Zone Append. Leave
  it at 0 for a Linux guest: the NVMe ZNS command set defines only the
  sequential-write-required zone type, so Linux rejects a conventional zone,
  fails the whole zone report with `EINVAL`, and the namespace reports no
  zones, which leaves it unusable for zoned btrfs, f2fs, zonefs or
  dm-zoned. To mix
  random-write and zoned capacity, give the controller a
  [BlackBox namespace and a ZNS namespace](../features/multi-namespace.md)
  instead.
- **Reads across zone boundaries.** By default a read that runs past the end
  of its zone fails with a zone boundary error. `zns_cross_zone_read=on`
  allows it and advertises OZCS bit 0, which tells the host it may issue
  one. Every zone the read spans must still be in a readable state.
- **Zone Append size limit.** `zns_zasl_bs` (default 128 KiB) caps one Zone
  Append, and must be a power-of-two multiple of 4 KiB, because Identify
  reports the limit (ZASL) as a power-of-two count of 4 KiB pages; other
  values are refused, not rounded down. 0 follows `mdts`. The host reads
  ZASL to size its appends, and a larger append fails with Invalid Field in
  Command.
- **Zone descriptor extensions.** `zns_zd_ext_size` in bytes, a multiple of
  64.
- **Write failures.** `err_write_fail_ppm` fails a fixed share of writes. The
  zone of a failed write becomes read only and is added to the Changed Zone
  List log page.
- **Finish Zone Recommended and Zone Active Excursions.** A zone that is
  written but not finished holds part-programmed blocks, which a real device
  does not keep open for long. `zns_fzr_sec=N` sets Finish Zone Recommended
  (FZR) on a zone N seconds of guest time after its first write. `zns_frl_sec=M`
  reports FRL M in Identify and sets ZOC.ZAE. M seconds after FZR, the
  controller finishes the zone itself and sets Zone Finished by Controller
  (ZFC). Both changes enter the Changed Zone List (ZNS 1.4, 5.5 and 5.6).

```text
 first write --(zns_fzr_sec)--> FZR, FZRTL 00b, changed zone
   host finishes, fills or resets the zone --> FZR cleared, no event
   else --(zns_frl_sec)--> zone Full, ZFC, FZR cleared, changed zone
 checks run once a second of guest time; a paused VM does not age zones
```

A finished zone takes no more writes, so the device programs the pages its
write cache still holds for the zone:

```
 host Finish        --> zone Full --> FTL programs the cache --> command completes
 controller finish  --> zone Full --> next command on the FTL thread programs it,
                                      from the time of the finish
 Finish of a Full zone --> completes when those programs end
```

A host Finish completes after these programs. After a finish by the
controller, later commands wait for the programs on the planes. Writes that
reach the FTL thread after the finish of their zone are programmed together,
by the next command that is not a read and has another target. A deleted
queue or a controller reset drops a Finish command, but its programs still
happen. A Reset that it drops before the FTL thread runs it erases nothing,
as before. That zone's Finish programs resume after the next Reset that
the FTL thread runs for it; a Reset of an Empty zone does not count. A zone with a write still in flight waits for the
next check. A zone that writes fill keeps its cache until eviction, as
before.

<!-- femu-example: zns-fzr -->
```
-device femu,devsz_mb=1024,femu_mode=3,zns_fzr_sec=60,zns_frl_sec=300
```

## Use it from the guest

Check that Linux sees a zoned device:

```sh
sudo nvme list
cat /sys/block/nvme0n1/queue/zoned        # host-managed
cat /sys/block/nvme0n1/queue/nr_zones
cat /sys/block/nvme0n1/queue/chunk_sectors   # zone size in 512-byte sectors
sudo nvme zns id-ns /dev/nvme0n1
```

The model is `FEMU ZMS-SSD Controller [by Misao]` and the serial number
starts with `vZNSSD`.

List the zones, with their state and write pointer:

```sh
sudo nvme zns report-zones /dev/nvme0n1 -d 4
sudo blkzone report /dev/nvme0n1
```

Manage one zone by its start LBA (`-s`), or every zone (`-a`):

```sh
sudo nvme zns open-zone /dev/nvme0n1 -s 0
sudo nvme zns finish-zone /dev/nvme0n1 -s 0
sudo nvme zns reset-zone /dev/nvme0n1 -s 0
sudo nvme zns reset-zone /dev/nvme0n1 -a
```

Append 4 KiB to zone 0 and let the device pick the LBA:

```sh
head -c 4096 /dev/urandom > data.bin
sudo nvme zns zone-append /dev/nvme0n1 -s 0 -z 4096 -d data.bin
```

Write sequentially with fio, read the written zones back at random, then
reset the zones before the next run:

```sh
sudo fio --name=zns --filename=/dev/nvme0n1 --direct=1 --ioengine=psync \
    --zonemode=zbd --rw=write --bs=128k --size=1G
sudo fio --name=zr --filename=/dev/nvme0n1 --direct=1 --ioengine=psync \
    --zonemode=zbd --rw=randread --bs=4k --size=1G --runtime=30 --time_based
sudo blkzone reset /dev/nvme0n1
```

With ZRWA configured, open a zone with the ZRWA flag, write inside its window
with passthrough write commands (the block layer always writes at the write
pointer), then commit the window up to an LBA. With `zns_zrwafg_size=8`, the
flush must end on a multiple of 8 blocks:

```sh
sudo nvme zns open-zone /dev/nvme0n1 -s 0 --zrwaa
sudo nvme zns zrwa-flush-zone /dev/nvme0n1 -l 63
```

Read the Changed Zone List log page (BFh). It needs an explicit namespace:

```sh
sudo nvme get-log /dev/nvme0 --log-id=0xbf --log-len=4096 --namespace-id=1
```

### Changed Zone List

The page is per namespace, which is why the command above names one:
nvme-cli otherwise sends the broadcast identifier. It holds an 8-byte count
followed by up to 511 zone start LBAs, and lists only zone changes the host
did not cause. As the ZNS specification requires, it leaves out changes
that follow a Zone Management Send command, writes that open or fill a
zone, and the controller closing a zone to free a resource. Reading it
without `--rae` clears both the list and the event behind it, once the
page reached the host. A read whose transfer fails clears nothing, and a
zone that changes during a read keeps its entry for the next one. A notice
names its namespace in dword 1 of the completion. Notice events stay
masked until the host reads the list of that namespace; a read of another
namespace's list leaves them masked.

With `err_write_fail_ppm` and `zns_fzr_sec` unset nothing adds to the
list, and it stays empty. With it set, one write in every 1,000,000 / `err_write_fail_ppm`
fails and makes its zone read only, the way a controller does when it can
no longer program the zone. The failing write completes with Write Fault,
later writes to that zone are refused as read only, the zone is added to
this list. A host that enabled Zone Descriptor Changed notices (bit 27 of
Asynchronous Event Configuration, Set Features 0Bh) and has an Asynchronous
Event Request outstanding then gets the notice; without that bit the zone
is still listed, but no event is raised. The failures come at a fixed count, so a
run repeats exactly. `hw/femu/scripts/zone-aen-probe.c` checks this path
and sets bit 27 itself, since Linux leaves it clear. Add
`,err_write_fail_ppm=10000` to the device in `run-zns.sh`, copy the probe
into the guest, and run it on a fresh device; it prints `ZAEN PASS`:

```sh
gcc -O2 -o zone-aen-probe zone-aen-probe.c   # inside the guest
sudo ./zone-aen-probe /dev/nvme0 /dev/nvme0n1
```

Do not run `mkfs.ext4` on the namespace: it needs random writes. Use a file system with zoned support, zonefs, or zone-aware
applications.

## Limits and refusals

| Message | Cause and fix |
| --- | --- |
| `max_open_zones value 20 exceeds the number of zones 16` | `zns_max_open` above the zone count. |
| `max_active_zones value N exceeds the number of zones M` | `zns_max_active` above the zone count. |
| `zns_num_wc value N exceeds the number of zones M`, `zns_num_wc (N) exceeds the M zones this geometry can have at most` | `zns_num_wc` above the zone count. |
| `max_open_zones value 10 exceeds max_active_zones 8` | `zns_max_open` above `zns_max_active`. |
| `zns_chnls_per_zone 3 must divide zns_num_ch 2` | The zone width must divide the channel count. |
| `zns_luns_per_zone 3 must divide zns_num_lun 4` | The LUNs of a zone must divide the LUN count. |
| `zns_zone_order must be ch or lun, not 'die'` | An unknown fill order. |
| `zns_flash_type 2 has no built-in timing; set zns_pg_rd_lat, zns_pg_wr_lat and zns_blk_er_lat` | MLC or PLC without the three latencies. |
| `zns_flash_type must be in [1, 5]` | A cell type outside SLC to PLC. |
| `zns_frl_sec needs zns_fzr_sec: an excursion follows Finish Zone Recommended` | Set `zns_fzr_sec` too, or drop `zns_frl_sec`. |
| `zoned namespaces need a logical block of 4 KiB or less; lba_index selects 8192 bytes` | `lba_index` picks a block larger than 4 KiB. |
| `zns geometry gives N pages per block; must be in [1, 65536]` | The namespace is too small or too large for `zns_num_ch * zns_num_lun * zns_num_blk`. |
| `FEMU zns: N zones exceed M blocks per plane ...` | Raise `zns_num_blk` or the namespace size. |
| `the device is too small to hold a single zone of N logical blocks` | The geometry gives less than one zone: `zns_num_ch * zns_num_lun * zns_num_blk` is below the zone width times the zone LUNs times `zns_num_plane`. Raise `zns_num_blk` or `zns_num_ch`, or lower `zns_num_plane`, `zns_chnls_per_zone` or `zns_luns_per_zone`. |
| `zns_zrwafg_size must be between 1 and 65535 when ZRWA is enabled, got 0` | ZRWA needs all three `zns_zrwa*` properties. Other messages check that the window is a multiple of the flush granularity and that the zone capacity is too. |
| `zns_zasl_bs N must be a power-of-two multiple of the 4096 byte controller page size` | Fix `zns_zasl_bs`. |

On a zoned namespace, Dataset Management (deallocate), Write Zeroes, Write
Uncorrectable and Copy fail with Invalid Opcode: they would change blocks
without going through the zone state machine. Reset the zone instead.

A Zone Management Send command waits until every write to its zones that
the controller already accepted has its data copied. So a Reset sent while
a write to the zone is in flight on another queue acts after that write:
the data and the zone descriptor are correct. The FTL timing model takes
each queue's requests in that queue's order, and it can still see the two
commands in the other order. An older write can then refill the write
cache after the Reset, or a newer write can lose its cache entries to it.
That changes later mappings, media counters and read latencies, not data.
To keep the model exact, wait for every write to a zone to complete before
you reset it, and for the Reset to complete before you write it again.

## Verify

1. `cat /sys/block/nvme0n1/queue/zoned` prints `host-managed`.
2. `nr_zones` and `chunk_sectors` match the zone count and size from the
   formula above.
3. `sudo nvme zns report-zones /dev/nvme0n1 -d 1` shows zone 0 empty; after
   the fio run the first zones are full and their write pointers moved.
4. From the host, the QMP command
   [`query-femu`](../reference/query-femu.md) with `kind` `zones` shows the
   same zone states and write pointers. It needs no guest tools.
5. For a check under a real workload, the `zenfs-crash` suite of
   `guest-conformance.sh` runs a RocksDB crash test on ZenFS. See
   [ZenFS crash test](../guides/testing.md#zenfs-crash-test).

## Troubleshooting

- **`nvme list` shows the device but `nr_zones` is 0, or `blkzone` says
  `unable to determine zone size`.** The guest kernel cannot drive ZNS. Use
  a kernel from the requirements table; the image from
  `make-guest-image.sh` works. Check `dmesg` for the reason. A message with
  `invalid zone size` means the zone size is not a power of two.
- **No zoned device after setting `zns_num_conv_zones`.** Linux rejects
  conventional zones and fails the whole zone report. Set it back to 0.
- **The device disappears after a geometry change.** The geometry is checked
  at realize, so a bad one stops QEMU with a message from the table above.
  Read the console log (`run-zns.sh` writes `build-femu/log`).
- **I want 4 KiB blocks.** Set `lba_index=3`. Older guides patched
  `zns.c`; that is no longer needed.
- **I want a different zone size or more zones.** Change the geometry, not
  the code. See [Zone size and zone count](#zone-size-and-zone-count).
- **A large ZNS device fails with `failed to allocate N bytes`.** The
  namespace lives in host DRAM. A 256 GiB device needs 256 GiB of free host
  memory.
- **fio fails with an I/O error on the first write.** The zone is full or not
  at its start. Reset the zones (`blkzone reset /dev/nvme0n1`) and run with
  `--zonemode=zbd`.

Related issues: #57, #76, #112, #115, #126, #144, #161, #177, #182, #193.

## Related pages

- [Timing model: ZNS write cache](../concepts/timing-model.md#zns-write-cache)
- [Architecture: other FTLs](../concepts/architecture.md#other-ftls)
- [Multiple namespaces](../features/multi-namespace.md), to mix zoned and
  conventional namespaces
- [Device property reference: ZNS](../reference/properties.md#zns)
- [QMP query-femu](../reference/query-femu.md), to read the zones from the
  host
