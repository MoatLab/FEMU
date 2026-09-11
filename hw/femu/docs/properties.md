<!--
Generated from the DEFINE_PROP_ tables in hw/femu/femu.c and the other mode
sources. Do not edit by hand: a property added to the source will not appear
here until this is regenerated, and an edit here will be overwritten.
-->

# Configuration reference

Every property FEMU accepts, read from the source so this page cannot drift from the emulator it documents.

There are 135 of them. Most have a default that leaves the feature off, so a working configuration names only the handful it needs.

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
| `nand_cell_type` | uint8 | `0` | Bits per cell: slc, mlc, tlc, qlc or plc. Selects the page-type latency table. |
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
| `buffer_size` | int32 | `0` | Write-buffer capacity in MiB. Zero disables it; the buffer holds page numbers for timing, not data. |
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
| `cmbsz` | uint32 | `0` | _undocumented_ | set on `-device femu,...` |
| `context_switch_time` | uint64 | `200` | this port, so they have no effect | set on `-device femu,...` |
| `cqr` | uint8 | `1` | _undocumented_ | set on `-device femu,...` |
| `csf_runtime_scale` | uint16 | `3` | A program that names no runtime is charged its host | set on `-device femu,...` |
| `debug_ftl` | bool | `false` | report FTL invariant violations instead of aborting | set on `-device femu,...` |
| `did` | uint16 | `0x1f1f` | _undocumented_ | set on `-device femu,...` |
| `dlfeat` | uint8 | `1` | _undocumented_ | set on `-device femu,...` |
| `dpc` | uint8 | `0` | _undocumented_ | set on `-device femu,...` |
| `dps` | uint8 | `0` | _undocumented_ | set on `-device femu,...` |
| `elpe` | uint8 | `3` | _undocumented_ | set on `-device femu,...` |
| `extended` | uint8 | `0` | _undocumented_ | set on `-device femu,...` |
| `fdm_size` | uint64 | `0` | Functional data memory size (MB), required | set on `-device femu,...` |
| `fdp` | bool | `false` | Enable Flexible Data Placement on the subsystem. | set on `-device femu-subsys,...` |
| `fdp.isolation_mode` | uint32 | `0` | _undocumented_ | set on `-device femu-subsys,...` |
| `fdp.nrg` | uint32 | `1` | Number of reclaim groups. | set on `-device femu-subsys,...` |
| `fdp.nru` | uint64 | `128` | Reclaim units per group. | set on `-device femu-subsys,...` |
| `fdp.nruh` | uint16 | `0` | Number of reclaim unit handles the subsystem exposes. | set on `-device femu-subsys,...` |
| `fdp.runs` | size | `NVME_DEFAULT_RU_SIZE` | Size of one reclaim unit in bytes. | set on `-device femu-subsys,...` |
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
| `mc` | uint8 | `0` | _undocumented_ | set on `-device femu,...` |
| `meta` | uint8 | `0` | _undocumented_ | set on `-device femu,...` |
| `mpsmax` | uint8 | `0` | _undocumented_ | set on `-device femu,...` |
| `mpsmin` | uint8 | `0` | _undocumented_ | set on `-device femu,...` |
| `ms` | uint8 | `16` | _undocumented_ | set on `-device femu,...` |
| `ms_max` | uint8 | `64` | _undocumented_ | set on `-device femu,...` |
| `multipoller_enabled` | uint8 | `0` | _undocumented_ | set on `-device femu,...` |
| `nlbaf` | uint8 | `5` | _undocumented_ | set on `-device femu,...` |
| `nr_cu` | uint8 | `4` | Compute units; programs queue for the first free one | set on `-device femu,...` |
| `nr_thread` | uint8 | `4` | Accepted for CEMU config compatibility only: the | set on `-device femu,...` |
| `oacs` | uint16 | `NVME_OACS_FORMAT` | _undocumented_ | set on `-device femu,...` |
| `oncs` | uint16 | `NVME_ONCS_DSM | NVME_ONCS_FEATURES` | Optional NVM commands the controller advertises. Compare, Write Zeroes and Write Uncorrectable are off unless named here. | set on `-device femu,...` |
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

They were previously written into the SMART log from byte 192, which NVMe Base
2.0 assigned to the composite temperature times, the temperature sensors and
the thermal transition counts.

`nvme get-log /dev/nvme0 --log-id=0 --log-len=1024 -b` lists every log page the
controller answers, four bytes per identifier with bit 0 set for the ones it
supports, so this page can be discovered rather than assumed.

---

75 of 136 properties carry a description today. The rest are listed with their type and default only; filling them in is tracked as documentation work.
