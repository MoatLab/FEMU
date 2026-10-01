<!--
Maintained by hand. No generator is committed, so a property added to the
DEFINE_PROP_ tables in hw/femu/femu.c or hw/femu/cxlssd/qemu-adapter.c does
not appear here until someone adds it.
-->

# Configuration reference

Properties of the `femu` and `femu-subsys` devices, and of `femu-cxl-ssd` at the end.

`femu` defines 145 properties, `femu-subsys` 8 and `femu-cxl-ssd` 24. This page does not yet list these `femu` properties: `bbssd_ns_limit`, `learly_reset`, `ns_mgmt` (the `femu-subsys` property of the same name is listed), `oc12_channel_timing`, `pel_file`, `pe_suspend`, `pi`, `power_loss`, `streams`, `streams.max`, `tsusp_ns`, `zns_num_wc`, `zns_pe_suspend` and `zns_tsusp_ns`. `./qemu-system-x86_64 -device femu,help` prints every `femu` property the binary accepts.

Most have a default that leaves the feature off, so a working configuration names only the handful it needs.

## Device and capacity

| Property | Type | Default | Meaning |
| --- | --- | --- | --- |
| `devsz_mb` | uint32 | `1024` | Capacity of the emulated device in MiB. Split across namespaces unless namespace_sizes says otherwise. |
| `namespaces` | uint32 | `1` | Number of namespaces (default 1) |
| `namespace_sizes` | string | `--` | Per-namespace capacity, comma-separated and empty for an even split, e.g. '3G,,1G'. |
| `namespace_modes` | string | `--` | Per-namespace override of femu_mode, comma-separated and empty for the default, e.g. 'bbssd,,znssd'. |
| `femu_mode` | uint8 | `FEMU_NOSSD_MODE` | Which SSD the controller emulates: 0 OpenChannel, 1 black-box, 2 no-SSD, 3 zoned, 4 computational storage, 5 key-value. |
| `serial` | string | `--` | Serial number the controller reports in Identify Controller. |
| `nqn` | string | `--` | _undocumented_ |

## SSD geometry

| Property | Type | Default | Meaning |
| --- | --- | --- | --- |
| `secsz` | int32 | `512` | Sector size (bytes) |
| `secs_per_pg` | int32 | `8` | Sectors per page |
| `pgs_per_blk` | int32 | `256` | Pages per block |
| `blks_per_pl` | int32 | `256` | Blocks per plane |
| `pls_per_lun` | int32 | `1` | Planes per LUN. Above one, a line spans every plane of a block index and erases batch across them. |
| `luns_per_ch` | int32 | `8` | LUNs per channel |
| `nchs` | int32 | `8` | Number of channels |

## NAND timing

| Property | Type | Default | Meaning |
| --- | --- | --- | --- |
| `pg_rd_lat` | int32 | `40000` | Page read latency (ns) |
| `pg_wr_lat` | int32 | `200000` | Page write latency (ns) |
| `blk_er_lat` | int32 | `2000000` | Block erase latency (ns) |
| `ch_xfer_lat` | int32 | `0` | _undocumented_ |
| `cmd_addr_lat` | int32 | `0` | Channel bus phases (ns): command/address cycle, |
| `pg_xfer_lat` | int32 | `0` | page data transfer, status read. Any non-zero |
| `status_lat` | int32 | `0` | value adds a shared per-channel bus to the model |
| `trim_lat_ns` | int32 | `0` | Latency charged per TRIM range |
| `tplpbsy` | int32 | `0` | _undocumented_ |
| `tplrbsy` | int32 | `0` | _undocumented_ |
| `tplebsy` | int32 | `0` | _undocumented_ |
| `trcbsy` | int32 | `0` | _undocumented_ |

## NAND media and reliability

| Property | Type | Default | Meaning |
| --- | --- | --- | --- |
| `nand_cell_type` | uint8 | `0` | Cell type as a number: 0 keeps the flat `pg_rd_lat`/`pg_wr_lat`/`blk_er_lat` timing; 1 SLC, 2 MLC, 3 TLC, 4 QLC use the built-in per-type latency tables. Other values print an error and fall back to flat timing. Read by the black-box FTL only. |
| `cell_pages` | int32 | `0` | _undocumented_ |
| `pgtype_lat` | int32 | `0` | _undocumented_ |
| `flash_type` | uint8 | `MLC` | _undocumented_ |
| `ecc_step_ns` | int32 | `0` | Extra read latency per correction tier, charged as the block wears or its data ages. Zero disables it. |
| `ecc_retention_sec` | int32 | `0` | Seconds of data age per correction tier, alongside the wear-driven tiers. |
| `nand_bad_blocks` | uint32 | `0` | Blocks marked bad at initialisation, which the SMART available-spare figure then reflects. |
| `pe_cycles_rated` | uint32 | `0` | Program/erase cycles the media is rated for, which SMART percentage-used measures the average block's erase count against. Zero takes the figure `nand_cell_type` implies, and with neither set the device reports no life estimate. |
| `err_read_unc_ppm` | uint32 | `0` | Uncorrectable reads injected per million, reported to the host as a media error. |
| `err_write_fail_ppm` | uint32 | `0` | Write failures injected per million. On a zoned namespace the zone goes read-only. |
| `read_reclaim_limit` | int32 | `0` | Reads a block may take before its line is refreshed. Zero disables read-disturb reclaim. |
| `retention_limit_sec` | int32 | `0` | How long data may sit programmed before a read queues its line for a refresh. Zero disables it. |

## Garbage collection and mapping

| Property | Type | Default | Meaning |
| --- | --- | --- | --- |
| `gc_thres_pcent` | int32 | `75` | GC trigger threshold (percent of lines in use) |
| `gc_thres_pcent_high` | int32 | `95` | _undocumented_ |
| `gc_policy` | string | `--` | Victim selection: greedy, random, cost-benefit, fifo or d-choice. |
| `gc_strategy` | int32 | `0` | _undocumented_ |
| `op_pcent` | uint32 | `0` | Over-provisioning as a percentage of capacity, withheld from the host and left for garbage collection. |
| `mapping` | string | `--` | Logical-to-physical scheme: page, dftl, hybrid or fast. |
| `mapping_cache_mb` | uint32 | `0` | Translation-cache size in MiB, charged as real reads on a miss. Applies to dftl. |
| `hot_cold_sep` | bool | `false` | Separate frequently and rarely rewritten data onto different lines to lower write amplification. |

## Caching and buffering

| Property | Type | Default | Meaning |
| --- | --- | --- | --- |
| `read_cache_mb` | uint32 | `0` | Device read-cache size in MiB. Zero disables it. |
| `cache_evict` | string | `--` | Read-cache eviction policy: clock, random, lru or arc. |
| `buffer_size` | int32 | `0` | Write-buffer capacity in flash pages. Zero disables it; the buffer holds page numbers for timing, not data. |
| `buffer_thres_pcent` | int32 | `90` | Occupancy at which the write buffer starts flushing, as a percentage of buffer_size. |

## Host link and controller

| Property | Type | Default | Meaning |
| --- | --- | --- | --- |
| `pcie_bandwidth_mbps` | uint32 | `0` | Host-link bandwidth in MB/s, charged per transfer. Zero leaves the link unmodelled. |
| `pcie_prop_delay_ns` | uint32 | `0` | Host-link propagation delay in nanoseconds, charged per completion. |
| `fw_cpu_ns` | uint64 | `0` | Controller firmware time charged per command, serialised on one core. Zero disables it. |
| `queues` | uint32 | `8` | Number of I/O queue pairs the controller supports. |
| `entries` | uint32 | `0x7ff` | Maximum queue entries, reported as the queue-size limit in the controller capabilities. |
| `mdts` | uint8 | `10` | Maximum data transfer size, as a power of two of the minimum page size. |

## Everything else

Properties that mostly mirror the NVMe identify fields, the OpenChannel geometry, or the computational-storage engine. They are listed for completeness.

| Property | Type | Default | Meaning | Set on |
| --- | --- | --- | --- | --- |
| `acl` | uint8 | `3` | _undocumented_ | set on `-device femu,...` |
| `aerl` | uint8 | `3` | _undocumented_ | set on `-device femu,...` |
| `cmbloc` | uint32 | `0` | _undocumented_ | set on `-device femu,...` |
| `cxl_ssd` | link | `--` | A `femu-cxl-ssd` whose memory and FTL a bbssd controller's one namespace shares; see the CXL SSD section. | set on `-device femu,...` |
| `cmbsz` | uint32 | `0` | _undocumented_ | set on `-device femu,...` |
| `context_switch_time` | uint64 | `200` | this port, so they have no effect | set on `-device femu,...` |
| `cqr` | uint8 | `1` | _undocumented_ | set on `-device femu,...` |
| `csd_program_dir` | string | `--` | Host directory CSD shared-library and uBPF programs are loaded from. The guest names a file in it, without `/`. Unset, only phantom programs load. | set on `-device femu,...` |
| `csf_runtime_scale` | uint16 | `3` | A program that names no runtime is charged its host | set on `-device femu,...` |
| `debug_ftl` | bool | `false` | Print bbssd page-state violations on the GC path, and periodic merge counts under `mapping=hybrid` or `fast`. The `ftl_assert` checks are compiled in only with `FEMU_DEBUG_FTL` or `FEMU_FTL_ASSERT`. | set on `-device femu,...` |
| `did` | uint16 | `0x1f1f` | _undocumented_ | set on `-device femu,...` |
| `dlfeat` | uint8 | `1` | _undocumented_ | set on `-device femu,...` |
| `dpc` | uint8 | `0` | Protection types offered (Identify DPC); must be 0 with `meta` | set on `-device femu,...` |
| `dps` | uint8 | `0` | Protection type in use (Identify DPS); must be 0 with `meta` | set on `-device femu,...` |
| `elpe` | uint8 | `3` | _undocumented_ | set on `-device femu,...` |
| `extended` | uint8 | `0` | Boot with metadata interleaved with the data (extended LBAs); needs `mc` bit 0 | set on `-device femu,...` |
| `fdm_size` | uint64 | `0` | Functional data memory size (MB), required | set on `-device femu,...` |
| `fdp` | bool | `false` | Enable Flexible Data Placement on the subsystem. | set on `-device femu-subsys,...` |
| `fdp.isolation_mode` | uint32 | `0` | _undocumented_ | set on `-device femu-subsys,...` |
| `fdp.nrg` | uint32 | `1` | Number of reclaim groups. | set on `-device femu-subsys,...` |
| `fdp.nru` | uint64 | `128` | Reclaim units per group. | set on `-device femu-subsys,...` |
| `fdp.nruh` | uint16 | `0` | Number of reclaim unit handles the subsystem exposes. | set on `-device femu-subsys,...` |
| `fdp.runs` | size | `0` | Size of one reclaim unit in bytes. Unset, a bbssd controller uses one superblock (the only size it accepts) and other modes 96 MiB. | set on `-device femu-subsys,...` |
| `fdp_trim_erase_all` | int32 | `0` | _undocumented_ | set on `-device femu,...` |
| `hiops_inline` | bool | `true` | _undocumented_ | set on `-device femu,...` |
| `intc` | uint8 | `0` | _undocumented_ | set on `-device femu,...` |
| `intc_thresh` | uint8 | `0` | _undocumented_ | set on `-device femu,...` |
| `intc_time` | uint8 | `0` | _undocumented_ | set on `-device femu,...` |
| `lba_index` | uint8 | `0` | _undocumented_ | set on `-device femu,...` |
| `lmax_sec_per_rq` | uint8 | `64` | _undocumented_ | set on `-device femu,...` |
| `lmetasize` | uint16 | `16` | _undocumented_ | set on `-device femu,...` |
| `lnum_ch` | uint8 | `2` | _undocumented_ | set on `-device femu,...` |
| `lnum_lun` | uint8 | `8` | _undocumented_ | set on `-device femu,...` |
| `lnum_pln` | uint8 | `2` | _undocumented_ | set on `-device femu,...` |
| `lpgs_per_blk` | uint16 | `512` | _undocumented_ | set on `-device femu,...` |
| `lsec_size` | uint16 | `4096` | _undocumented_ | set on `-device femu,...` |
| `lsecs_per_pg` | uint8 | `4` | _undocumented_ | set on `-device femu,...` |
| `lver` | uint8 | `0x2` | _undocumented_ | set on `-device femu,...` |
| `max_cqes` | uint8 | `0x4` | _undocumented_ | set on `-device femu,...` |
| `max_sqes` | uint8 | `0x6` | _undocumented_ | set on `-device femu,...` |
| `mc` | uint8 | `0` | Metadata capabilities: bit 0 interleaved, bit 1 separate buffer; Format may pick either one offered | set on `-device femu,...` |
| `meta` | uint8 | `0` | Metadata bytes per block, carried through MPTR or interleaved with the data (see `mc`, `extended`); block and no-SSD modes, no placement, no protection information. Each block size is then offered without metadata (formats 0 to `nlbaf`-1) and with it (the next `nlbaf`), and the device boots on the one with it | set on `-device femu,...` |
| `mpsmax` | uint8 | `0` | _undocumented_ | set on `-device femu,...` |
| `mpsmin` | uint8 | `0` | _undocumented_ | set on `-device femu,...` |
| `ms` | uint8 | `16` | _undocumented_ | set on `-device femu,...` |
| `ms_max` | uint8 | `64` | _undocumented_ | set on `-device femu,...` |
| `multipoller_enabled` | uint8 | `0` | _undocumented_ | set on `-device femu,...` |
| `nlbaf` | uint8 | `5` | Number of block sizes, 512 bytes doubling; at most 8 with `meta` | set on `-device femu,...` |
| `nr_cu` | uint8 | `4` | Compute units; programs queue for the first free one | set on `-device femu,...` |
| `nr_thread` | uint8 | `4` | Accepted for CEMU config compatibility only: the | set on `-device femu,...` |
| `oacs` | uint16 | `NVME_OACS_FORMAT` | _undocumented_ | set on `-device femu,...` |
| `oncs` | uint16 | `NVME_ONCS_DSM | NVME_ONCS_FEATURES` | Optional NVM commands the controller advertises. Compare (0x1), Write Uncorrectable (0x2), Write Zeroes (0x8) and Verify (0x80) and Copy (0x100) are off unless named here. | set on `-device femu,...` |
| `poller_ratio` | uint32 | `1` | _undocumented_ | set on `-device femu,...` |
| `sgl` | bool | `false` | _undocumented_ | set on `-device femu,...` |
| `stride` | uint8 | `0` | _undocumented_ | set on `-device femu,...` |
| `subsys` | link | `TYPE_NVME_SUBSYS` | _undocumented_ | set on `-device femu,...` |
| `temperature` | uint16 | `NVME_TEMPERATURE` | _undocumented_ | set on `-device femu,...` |
| `time_slice` | uint64 | `200000` | threaded scheduler they configure is not part of | set on `-device femu,...` |
| `vid` | uint16 | `0x1d1d` | _undocumented_ | set on `-device femu,...` |
| `vwc` | uint8 | `0` | Advertise a volatile write cache, which is what makes Flush reachable. | set on `-device femu,...` |
| `zns_blk_er_lat` | int64 | `0` | _undocumented_ | set on `-device femu,...` |
| `zns_chnls_per_zone` | uint32 | `0` | Channels a zone spans (0 = all of them) | set on `-device femu,...` |
| `zns_cmd_addr_lat` | int64 | `0` | Channel bus phases (ns): command/address cycle, | set on `-device femu,...` |
| `zns_cross_zone_read` | bool | `false` | Allow reads to span zone boundaries (OZCS bit 0) | set on `-device femu,...` |
| `zns_flash_type` | int32 | `QLC` | _undocumented_ | set on `-device femu,...` |
| `zns_max_active` | uint32 | `0` | Max active zones (0 = unlimited) | set on `-device femu,...` |
| `zns_max_open` | uint32 | `0` | Max open zones (0 = unlimited) | set on `-device femu,...` |
| `zns_num_blk` | uint8 | `32` | _undocumented_ | set on `-device femu,...` |
| `zns_num_ch` | uint8 | `2` | _undocumented_ | set on `-device femu,...` |
| `zns_num_conv_zones` | uint32 | `0` | Leading conventional zones (0 = all sequential) | set on `-device femu,...` |
| `zns_num_lun` | uint8 | `4` | _undocumented_ | set on `-device femu,...` |
| `zns_num_plane` | uint8 | `2` | _undocumented_ | set on `-device femu,...` |
| `zns_pg_rd_lat` | int64 | `0` | NAND read / program / erase time (ns) for the | set on `-device femu,...` |
| `zns_pg_wr_lat` | int64 | `0` | configured cell type; 0 keeps the built-in value | set on `-device femu,...` |
| `zns_pg_xfer_lat` | int64 | `0` | page data transfer, status read. Any non-zero | set on `-device femu,...` |
| `zns_status_lat` | int64 | `0` | value adds a shared per-channel bus to the model | set on `-device femu,...` |
| `zns_zasl_bs` | uint32 | `128 * 1024` | Max Zone Append transfer in bytes (0 = follow MDTS) | set on `-device femu,...` |
| `zns_zd_ext_size` | uint32 | `0` | Zone-descriptor extension bytes (0 = none) | set on `-device femu,...` |
| `zns_zone_cap` | size | `0` | Usable bytes per zone (0 = the whole zone) | set on `-device femu,...` |
| `zns_zrwa_num` | uint32 | `0` | Zones that may hold a ZRWA at once | set on `-device femu,...` |
| `zns_zrwa_size` | uint64 | `0` | ZRWA window in LBAs (0 = ZRWA disabled) | set on `-device femu,...` |
| `zns_zrwafg_size` | uint64 | `0` | ZRWA flush granularity in LBAs | set on `-device femu,...` |

## Vendor log page C0h

`nvme get-log /dev/nvme0 --log-id=0xc0 --log-len=512 -b` returns the emulator's
own media counters, little-endian at these offsets:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | Write amplification factor, scaled by 1000 |
| 8 | 8 | Pages the host asked to program |
| 16 | 8 | Pages relocated by garbage collection |
| 24 | 8 | Pages actually programmed |
| 32 | 8 | Reads of the most-read block since its erase |
| 40 | 8 | Lines rewritten because of read stress |
| 48 | 8 | Lines rewritten because of retention age |
| 56 | 8 | Host read pages the write buffer saw |
| 64 | 8 | Of those, pages the buffer held |
| 72 | 8 | Host write pages the write buffer saw |
| 80 | 8 | Of those, pages the buffer already held |
| 88 | 8 | Log-block switch merges (`mapping=hybrid` only) |
| 96 | 8 | Log-block full merges |
| 104 | 8 | Erases charged to log-block merges |

Bytes 4-7 and 112-511 are reserved and read as zero.

They were previously written into the SMART log from byte 192, which NVMe Base
2.0 assigned to the composite temperature times, the temperature sensors and
the thermal transition counts.

The same counters can be captured through the standard Telemetry Host-Initiated
log (07h): `nvme telemetry-log /dev/nvme0 --output-file=telemetry.bin` takes a snapshot and
saves it. Data Area 1 is one 512-byte block laid out as above, and it stays as
captured until the next capture. The Controller-Initiated log (08h) never holds
data, because the controller does not capture on its own.

`nvme get-log /dev/nvme0 --log-id=0 --log-len=1024 -b` lists every log page the
controller answers, four bytes per identifier with bit 0 set for the ones it
supports, so this page can be discovered rather than assumed.

---

Rows marked _undocumented_ list only the type and default; filling them in is tracked as documentation work.

## CXL SSD

`-device femu-cxl-ssd` selects a CXL Type-3 device with a private instance of
FEMU's current black-box FTL and NAND media. Existing `femu` modes and ordinary
`cxl-type3` devices keep their existing behavior. Use the inherited
`volatile-memdev` link with a memory backend sized in multiples of 256 MiB, up
to 120 GiB. Realize rejects persistent memory (`persistent-memdev`), the
legacy `memdev` link, dynamic capacity, and an `lsa` label backend together
with `lsa-control=on`; with `lsa-control=off` an `lsa` backend keeps the
parent's label semantics. The device realizes in any topology a plain
`cxl-type3` accepts; the direct modes map pages only in the one topology
described under `der`. See [the design note](cxlssd.md) and
[scripts/run-cxlssd.sh](../scripts/run-cxlssd.sh).

A bbssd `femu` controller with `cxl_ssd=<id>` serves the same medium as an
NVMe namespace: one payload and one FTL behind both. List the `femu-cxl-ssd`
first; the controller takes its size and geometry from it. Writing the
namespace changes CXL-resident data, so do not put a filesystem on it while
the range is in use as memory. See "NVMe front end" in the design note.

All properties below belong to `femu-cxl-ssd`, not `femu`. They are set with
`-device femu-cxl-ssd,...`; the ones marked runtime can also be changed later
with `qom-set`.

| Property | Type | Default | Meaning |
| --- | --- | --- | --- |
| `cache-pages` | uint32 | 1024 | Number of 4 KiB resident pages; zero disables the cache and sends every access to the media. At most the media page count, and divisible by `cache-ways`. |
| `cache-ways` | uint32 | 16 | Entries per set, runtime. Nonzero, and must divide `cache-pages` (with no cache, at most the media page count); there is no other upper bound. One means direct mapped (WAY_1); `cache-pages` means fully associative. A runtime change first checks that pinned pages fit the new geometry, then revokes direct mappings, writes dirty entries back, rebuilds the cache with the pinned pages still resident, maps a direct ratio again and waits for the modeled media cost. |
| `cache-policy` | string | `fifo` when unset | `fifo`, `lifo`, `clock`, or `s3-fifo`. |
| `prefetch-degree` | uint32 | 0 | Pages inserted after each demand miss, runtime. At most the media page count; one access prefetches at most `cache-pages` pages. Prefetch performs no NAND read. |
| `prefetch-stride` | uint32 | 1 | Distance from the missed page to the first prefetched page, runtime. At most the media page count. |
| `ftl` | bool | on | Charge cache misses and dirty writeback to the current FTL/NAND model. Off keeps memory functionality with no media timing, leaves the media counters at zero and cannot be linked to an NVMe controller. |
| `channels` | uint32 | 4 | NAND channels, 1 through 4096. |
| `luns-per-channel` | uint32 | 4 | LUNs per channel, 1 through 128. There is one plane per LUN. |
| `pages-per-block` | uint32 | 256 | 4 KiB pages per block, 1 through 65536. |
| `blocks-per-plane` | uint32 | 0 | Blocks per plane, 2 through 65536. Zero sizes it to cover 5/4 of the media plus four more blocks per plane, room for GC. An explicit value must cover the media, and total sectors must fit the FTL's signed 32-bit counts. |
| `gc-threshold` | uint32 | 75 | Percent of lines in use at which background GC starts, 1 through 100. |
| `gc-threshold-high` | uint32 | 95 | Percent at which GC is forced, from `gc-threshold` through 100. |
| `read-ns` | uint64 | 40000 | NAND page read time; zero through one second in nanoseconds. |
| `program-ns` | uint64 | 200000 | NAND page program time; same range. |
| `erase-ns` | uint64 | 2000000 | NAND block erase time; same range. |
| `channel-ns` | uint64 | 0 | Channel transfer time per page; same range. |
| `cylon-first-touch-program` | bool | off | Charge a NAND program instead of a free read when a read reaches a page the FTL has never mapped, as in Cylon's experiments. The program maps the page and counts in `media-writes`, not `media-reads`. |
| `cylon-free-writeback` | bool | off | Write dirty pages back on eviction and flush with no NAND program and no media time, as in Cylon's experiments. |
| `der` | string | off | `off`: MMIO without probes. `memslot`: QEMU aliases using ordinary KVM; refused under TCG. `cylon`: published mapped-SPT interface, requiring shared preallocated hugetlb backing, locking and readable PFNs; unsupported hosts warn once and retain MMIO. Other values fail realize. The direct modes map pages only for a single endpoint directly below the one root port of a host bridge without HDM decoders, in a single-target window, with non-interleaved endpoint decoders; elsewhere they stay on MMIO and count `der-fallbacks`. See `cxlssd.md` for kernel restrictions. |
| `cylon-kernel-ack` | bool | off | Required with `der=cylon`: states that the host runs a Cylon kernel with the dual-slot fixes (see `cxlssd.md`, "Host kernel"). Not verified by the device. |
| `concurrent-misses` | on/off/auto | auto | Let misses to different pages wait for the media together. `auto` does so while a direct mode is active; with `der=off` it would make guest atomics lose updates (see `cxlssd.md`, "Thread ownership"). |
| `der-replace-rate` | uint32 | 64 | With `der=memslot` and the shared 1024-alias budget full, the most cache aliases per second that a hot page may displace; zero disables replacement. |
| `cca` | bool | off | Register BAR5 with the caching API (pin, unpin, invalidate, uncached ranges, query). See "Caching API" in `cxlssd.md` and `hw/femu/tools/cca/`. |
| `lsa-control` | bool | off | Accept Cylon's control commands through Get LSA (`cxl read-labels mem0 -s COMMAND -O ARGUMENT`) on an internal 128 MiB label area. See "Experiment controls" in `cxlssd.md`. |
| `log-dir` | string | working directory | Directory for `cxlssd-stats.log`, `cxlssd-io-N.log` and `cxlssd-spt.log`. |
| `tracefs-dir` | string | unset | Host tracefs directory that commands 91 and 81 start and stop; unset, they change nothing on the host. |
| `log-limit` | size | 64M | Cap on each log file. An I/O log closes when it reaches the limit, the statistics log takes no more appends once it reaches it, and the SPT dump stops there with a final `truncated at log-limit` line. Zero makes command 13 open no file and the statistics log take no appends. |

The following QOM properties are available through `qom-get` / `qom-set` at
`/machine/peripheral/<device-id>`, besides the runtime ones above. Counters
marked "event" are cleared by `stats-reset`; the rest keep counting.

| Property | Access | Meaning |
| --- | --- | --- |
| `flush-cache` | write bool | Setting true revokes direct mappings, writes dirty entries back, drops unpinned entries, maps a direct ratio again and waits for the modeled media cost. Pinned pages are written back but stay resident and pinned. False does nothing. A full NAND reports an error and retains the unwritten entry. A memslot ratio that no longer fits the alias budget also reports an error; it stays configured and maps again on a later access once there is room. |
| `stats-reset` | write bool | Setting true copies the current values into the `last-*` properties, then clears the event counters and the CCA event counters. Membership, gauges, media totals and DER totals are kept. |
| `der-ratio` | read/write uint64 | Direct ratio: 0 (off), 50, 75, 90, 95, 97, 98, 99, 995, 999 or 100. Needs `der=memslot` or `der=cylon` and no CCA uncached range. Same as commands 90 and 80; see "Direct ratios" in `cxlssd.md`. |
| `control-argument` | read/write uint64 | Argument for the next `control-command`. |
| `control-command` | read/write uint64 | Writing runs that experiment control command with `control-argument` before `qom-set` returns and reports its error; reading returns the last command. The commands are listed under "Experiment controls" in `cxlssd.md`. |
| `control-status` | read uint64 | Result of the last control command, from QOM or Get LSA: 0 success, 1 error, 2 a Get LSA command still queued. |
| `media-time-ns` | read uint64 | Sum of modeled latency returned by FTL requests, including resource contention. |
| `media-reads` | read uint64 | Read requests sent to the FTL: every miss that fills the cache (a write miss reads the page first), every read with no cache or of an uncached page, and PIN fills. A page the FTL has never mapped costs no NAND read time; its contents come from the memory backend and read as zero only when the backend is zero-filled. |
| `media-writes` | read uint64 | User page programs completed by the shared FTL, including those of a linked NVMe controller; excludes GC copying. |
| `media-full` | read uint64 | Event. Accesses that found no NAND page for a program or a dirty victim's write-back, which happens once NAND without over-provisioning (`blocks-per-plane` covering the media exactly) is full. The access still completes from the memory backend, uncached, so the data is kept but its timing is not modeled; the first occurrence warns. A measurement is valid only while this stays zero. |
| `cache-entries` | read uint64 | Resident pages, pinned ones included. |
| `cache-hits` | read uint64 | Event. MMIO page lookups that found a resident entry, reads and writes together. Direct accesses are unobserved. |
| `cache-misses` | read uint64 | Event. MMIO page lookups that missed, including accesses with no cache. |
| `read-hits`, `read-misses` | read uint64 | Event. `cache-hits` and `cache-misses` for reads only, as Cylon counts them. |
| `write-hits`, `write-misses` | read uint64 | Event. The same for writes. |
| `cache-inserts` | read uint64 | Event. Resident admissions by demand misses, prefetches and PIN fills, across all policies. |
| `cache-evictions` | read uint64 | Event. Entries the replacement policy removed, including the unpinned entries a flush or way change writes back and drops. Pages dropped by CCA INVALIDATE or CACHE_DISABLE, or by a linked NVMe command, are not counted here. |
| `prefetch-inserts` | read uint64 | Event. Pages inserted by prefetch. |
| `last-read-hits`, `last-read-misses`, `last-write-hits`, `last-write-misses`, `last-inserts`, `last-evictions`, `last-entries`, `last-prefetch-inserts` | read uint64 | `read-hits`, `read-misses`, `write-hits`, `write-misses`, `cache-inserts`, `cache-evictions`, `cache-entries` and `prefetch-inserts` as they were at the last `stats-reset` or command 1. |
| `invalidations` | read uint64 | Generation bumped by every PCI configuration write, component register write, reset and CCI command (except Get LSA on the primary mailbox with `lsa-control=on`); each revokes all direct mappings. |
| `nvme-drops` | read uint64 | Resident pages a linked NVMe write, copy or deallocate dropped or, if pinned, cleaned. |
| `log-dropped` | read uint64 | Statistics appends refused by the rate limit or the size limit, I/O logs closed at `log-limit` (and command 13 with `log-limit=0`), and SPT dumps truncated at `log-limit`. |
| `der-probes` | read uint64 | Probe attempts; one per realize with `der=cylon`, zero for `off` and `memslot`. |
| `der-active` | read bool | Whether direct mapping is available. Memslot is active from realize; Cylon becomes active after a decoded access installs and validates its slot. |
| `der-mapped` | read uint64 | Pages currently mapped for direct guest access. |
| `der-remaps` | read uint64 | Successfully installed direct page mappings. |
| `der-revocations` | read uint64 | Direct page mappings removed. |
| `der-quiet-revocations` | read uint64 | Cylon revocations of entries whose accessed bit was still clear, done without a TLB flush. |
| `der-replacements` | read uint64 | Memslot cache aliases displaced by a hotter page; each is also one remap and one revocation. |
| `der-fallbacks` | read uint64 | Refused mapping attempts and device disablements: a full alias budget, a page whose HPA does not decode to that DPA, no eligible window, and a direct ratio that does not fit the budget, including each retry of one waiting to be mapped again. |
| `cca-commands` | read uint64 | Event. Caching API commands completed, whatever their status. |
| `cca-errors` | read uint64 | Event. Completed commands with a nonzero status. |
| `cca-pin-fills` | read uint64 | Event. Pages PIN read from the media to make them resident. |
| `cca-writebacks` | read uint64 | Event. Dirty pages programmed by caching API commands, both drops and evictions caused by PIN fills. |
| `cca-dropped` | read uint64 | Event. Resident pages INVALIDATE and CACHE_DISABLE dropped. |
| `cca-pinned-set-misses` | read uint64 | Event. Misses served from the media because every way of the set is pinned. |
| `cca-pinned` | read uint64 | Pages currently pinned. |
| `cca-uncached` | read uint64 | Pages currently in CCA uncached ranges. |

`test-change-dpa`, `test-slot-reservation` and `test-media-disabled` exist
only under qtest, for the device's own tests.
