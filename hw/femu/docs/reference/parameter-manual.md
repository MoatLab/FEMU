# Parameter manual

This manual explains how to configure an emulated device: the ways a
parameter reaches FEMU, then every group of parameters by component, with
what each one means, its unit, the values it accepts, and how it interacts
with the others. It ends with worked configurations.

The [property reference](properties.md) is generated from the binary and
is the authority on names, types and defaults. This manual never states a
default; each group links to its table there. Run-time properties and
counters are in [runtime-properties.md](runtime-properties.md).

## Contents

1. [How parameters reach FEMU](#1-how-parameters-reach-femu)
2. [Devices and how they combine](#2-devices-and-how-they-combine)
3. [Controller](#3-controller)
4. [Namespaces and subsystems](#4-namespaces-and-subsystems)
5. [NAND geometry](#5-nand-geometry)
6. [NAND timing](#6-nand-timing)
7. [FTL: mapping, caches and write buffer](#7-ftl-mapping-caches-and-write-buffer)
8. [Garbage collection](#8-garbage-collection)
9. [Reliability, wear and fault insertion](#9-reliability-wear-and-fault-insertion)
10. [Host link and controller firmware](#10-host-link-and-controller-firmware)
11. [ZNS](#11-zns)
12. [FDP](#12-fdp)
13. [OCSSD, CSD and KV](#13-ocssd-csd-and-kv)
14. [CXL SSD](#14-cxl-ssd)
15. [Accepted for compatibility, no effect](#15-accepted-for-compatibility-no-effect)
16. [Worked configurations](#16-worked-configurations)

## 1. How parameters reach FEMU

### 1.1 Device options on the QEMU command line

Every FEMU parameter is a property of one of three QEMU devices, given on
the command line when QEMU starts:

<!-- femu-untested: syntax outline with placeholder values -->
```text
-device femu-subsys,id=SUB,prop=value,...     NVMe subsystem (FDP, shared namespaces)
-device femu-cxl-ssd,id=CXL,prop=value,...    CXL Type-3 SSD
-device femu,id=CTRL,prop=value,...           NVMe controller and its namespaces
```

The rules of QEMU's option syntax apply:

- Options are separated by commas. A comma inside a value is written twice:
  `namespace_modes=bbssd,,znssd` is the list `bbssd,znssd`.
- Booleans take `on` or `off` (QEMU also accepts `yes`/`no` and
  `true`/`false`).
- Properties of type `size` take a number of bytes or a QEMU size with a
  suffix (`64M`, `4G`). Integer properties take plain numbers, decimal or
  `0x` hexadecimal; their unit is in the property name or in this manual
  (`_mb` MiB, `_ns` and `_lat` nanoseconds, `_pcent` percent).
- A property that links to another device (`subsys`, `cxl_ssd`) names the
  other device's `id`, and that device must come earlier on the command
  line.
- A misspelled name stops QEMU with `Property 'femu.NAME' not found`.

Static properties are read once, when QEMU creates (realizes) the device.
Realize checks the values and their combinations and stops QEMU with a
message naming the rule that failed; the "Limits and refusals" section of
each [mode page](../modes/blackbox.md#limits-and-refusals) lists them.
`./qemu-system-x86_64 -device femu,help` prints every property with its
type, default and description; `femu-subsys,help` and
`femu-cxl-ssd,help` do the same for the other two devices.

### 1.2 Configuration files

`hw/femu/scripts/ssd-config.sh` expands a file of `key = value` lines into
the same `-device` options, so a configuration can be read, commented and
kept in version control. Keys are property names, `mode = bbssd` stands for
`femu_mode`, and a `[subsys]` section becomes a `femu-subsys` device that
the controller joins. The script checks names against the binary in
`FEMU_BIN`; QEMU still checks the values.
[Tutorial 09](../tutorials/09-ssd-config-files.md) walks through it, and
[scripts and tools](scripts.md#configuration-files) describes the shipped
files.

### 1.3 Run-time properties over QMP

A few properties can be read or changed while the guest runs, with QMP
`qom-get` and `qom-set` on `/machine/peripheral/<id>`:

- `femu`: `simulate-power-loss`, a write-only trigger for the power-cut
  model ([power loss](#7-ftl-mapping-caches-and-write-buffer)).
- `femu-cxl-ssd`: the cache tunables `cache-ways`, `prefetch-degree` and
  `prefetch-stride` (also accepted on `-device`), the actions
  `flush-cache`, `stats-reset`, `der-ratio` and `control-command`, and
  every counter.

The full list is [runtime-properties.md](runtime-properties.md).
`femu` and `femu-subsys` have no counter properties; their counters are
NVMe log pages ([log pages and counters](log-pages-and-counters.md)).

### 1.4 Run-time switches from the guest

These are not parameters, but they change the model while the guest runs:

- Vendor admin command 0xEF on a BlackBox controller turns GC time and the
  flat NAND times off and on, and reports late completions
  ([timing model](../concepts/timing-model.md#changing-timing-at-run-time)).
- Set Features 06h (Volatile Write Cache) turns the write buffer off and on
  when `vwc=1`; Set Features 20h (Key Value Configuration) sets EDNEK on a
  KV namespace; Set Features 04h and 0Bh set the temperature threshold and
  the asynchronous events the host wants.

### 1.5 Environment variables

A few debugging and host-placement aids are environment variables of the
QEMU process, not properties:
[environment variables](properties.md#environment-variables).

## 2. Devices and how they combine

```text
  femu-subsys (optional)                femu-cxl-ssd (optional)
  FDP, shared namespaces                CXL memory over NAND
        ^ subsys=SUB                          ^ cxl_ssd=CXL
        |                                     |
  femu (NVMe controller) ---------------------+
    controller parameters        section 3
    femu_mode, namespaces        section 4
    per-mode parameters:
      bbssd, CSD   geometry 5, timing 6, FTL 7, GC 8, reliability 9
      KV           geometry 5, timing 6, part of 8
      ZNS          zns_* 11
      OCSSD, CSD   section 13
    host link, firmware          section 10
```

A `femu` controller runs one mode per namespace. `femu_mode` picks it for
every namespace, and `namespace_modes` per namespace. Only the parameters
of the modes in use have an effect; the description of each property in
[properties.md](properties.md) names the modes it applies to. A property
of a mode that no namespace runs has no effect. The properties of
[section 15](#15-accepted-for-compatibility-no-effect) have no effect in
any mode and warn when set.

## 3. Controller

These shape the NVMe controller the guest driver sees, whatever the mode.

### 3.1 Queues and pollers

Reference: [queues, pollers and interrupts](properties.md#queues-pollers-and-interrupts).

| Parameter | Unit | Valid values | Meaning |
| --- | --- | --- | --- |
| `queues` | count | 1 to 2047 | I/O submission and completion queue pairs the controller offers; MSI-X vectors are `queues` + 1 |
| `entries` | count, 0's based | 1 to 65534 | CAP.MQES; queues may have up to `entries` + 1 entries |
| `multipoller_enabled` | 0 or 1 | 0, 1 | 0: one poller thread for every I/O queue; 1: several, see `poller_ratio` |
| `poller_ratio` | queues per poller | 0 or more (0 counts as 1) | with `multipoller_enabled=1`, `ceil(queues / poller_ratio)` pollers, each serving a round-robin share of the queues |
| `stride` | power of two | 0 to 12 | doorbell stride CAP.DSTRD: doorbells are `4 << stride` bytes apart |
| `max_sqes`, `max_cqes` | power of two | 6 and 4 only | Identify SQES and CQES; the only accepted values are the 64-byte and 16-byte entries |
| `aerl` | count, 0's based | 0 to 255 | outstanding Asynchronous Event Requests the controller holds |
| `elpe` | count, 0's based | 0 to 255 | Error Information log entries kept |
| `hiops_inline` | bool | `on`, `off` | NoSSD only: performance option, on by default; set off only when debugging |
| `intc`, `intc_thresh`, `intc_time` | as named | `intc` 0 or 1 | initial values of the Interrupt Coalescing and Interrupt Vector Configuration features; reported only, interrupts are not coalesced |

Interactions:

- Every poller spins on a host core while the controller is enabled. The
  number of pollers follows `queues`, not the number of queues the guest
  creates, so set `queues` to the guest's vCPU count when you turn on more
  pollers ([performance tuning](../guides/performance-tuning.md#pollers-and-queues)).

### 3.2 Identity, capabilities and transfers

Reference: [controller identity and capabilities](properties.md#controller-identity-and-capabilities).

| Parameter | Unit | Valid values | Meaning |
| --- | --- | --- | --- |
| `vid`, `did` | PCI IDs | 16-bit | PCI vendor and device ID; `vid` is also Identify VID |
| `mdts` | power of two | 0 to 255; 0 = no limit | largest transfer, 2^(12 + `mpsmin` + `mdts`) bytes |
| `mpsmin`, `mpsmax` | power of two | `mpsmin` <= `mpsmax` <= 15 | host memory page sizes the controller accepts, 2^(12 + n) bytes |
| `cqr` | 0 or 1 | 0, 1 | 1 requires physically contiguous queues |
| `vwc` | 0 or 1 | 0, 1 | advertise a volatile write cache; makes Flush drain the write buffer and feature 06h usable |
| `oacs` | bit mask | only bit 1 (0x2) | Format NVM support; clearing it refuses Format NVM |
| `oncs` | bit mask | 0x1 Compare, 0x2 Write Uncorrectable, 0x4 Dataset Management, 0x8 Write Zeroes, 0x10 Save/Select, 0x80 Verify, 0x100 Copy | optional NVM commands; Timestamp is always added |
| `sgl` | bool | `on`, `off` | accept scatter gather lists; OCSSD ignores it |
| `cmbsz`, `cmbloc` | registers | `cmbsz` size x unit a power of two; `cmbloc` BAR field 2 | Controller Memory Buffer; 0 means none |
| `temperature` | kelvin | 16-bit | composite temperature in the SMART log, compared with the threshold feature |
| `pel_file` | host path | a writable path | keeps the Persistent Event log and power cycle count across QEMU runs ([retention](log-pages-and-counters.md#persistent-event-log-retention)) |

Interactions:

- Write Zeroes, Compare, Copy and Verify are unreachable until you set
  their `oncs` bit, and Flush does nothing without `vwc=1`. A test of those
  commands on a default controller tests nothing.
- With ZNS, `mdts` also caps Zone Append when `zns_zasl_bs=0`.

### 3.3 LBA formats, metadata and protection

Reference: [LBA formats, metadata and protection](properties.md#lba-formats-metadata-and-protection).

| Parameter | Unit | Valid values | Meaning |
| --- | --- | --- | --- |
| `nlbaf` | count | 1 to 16, at most 8 with `meta` | LBA formats offered: 512 bytes, doubling with each |
| `lba_index` | index | below `nlbaf` | format the namespaces boot with; ZNS needs 4 KiB or less |
| `meta` | bytes per block | NoSSD and bbssd only | metadata per logical block; each format is then also offered with metadata |
| `mc` | bit mask | bit 0 interleaved, bit 1 separate | Metadata Capabilities; required with `meta` |
| `extended` | 0 or 1 | needs `mc` bit 0 | boot with metadata interleaved (extended LBAs) |
| `pi` | bool | needs `meta` >= 8 | offer protection information types 1 to 3 to Format and Create |
| `dpc`, `dps` | bit masks | `dpc` 0 with `meta`; leave `dps` 0 | Identify fields; use `pi` instead |

Interactions: `meta` is refused with FDP, with `dpc` or `dps`, and with any
namespace that is not NoSSD or bbssd; `pi` is refused with `power_loss`
and `cxl_ssd`
([namespace management, metadata and PI](../features/ns-management-and-pi.md)).

## 4. Namespaces and subsystems

Reference: [mode, capacity and namespaces](properties.md#mode-capacity-and-namespaces),
[namespace management, streams and power loss](properties.md#namespace-management-streams-and-power-loss),
[shared namespaces](properties.md#shared-namespaces).
Design: [subsystems, controllers and namespaces](../design/namespaces.md).

| Parameter | Unit | Valid values | Meaning |
| --- | --- | --- | --- |
| `femu_mode` | mode number | 0 OCSSD, 1 bbssd, 2 NoSSD, 3 ZNS, 4 CSD, 5 KV | mode of every namespace unless `namespace_modes` is set |
| `devsz_mb` | MiB | 32-bit | host memory backend, split across the namespaces; ignored with `op_pcent` |
| `namespaces` | count | 1 to 256; OCSSD and FDP 1 | namespaces present from boot |
| `namespace_sizes` | bytes, QEMU sizes | one entry per namespace, each >= 512 bytes, sum <= backend | size of each namespace; unset splits the backend evenly |
| `namespace_modes` | list | `nossd`, `bbssd`, `znssd`, `ocssd`, `csd`, `kvssd`, one per namespace | mode of each namespace |
| `op_pcent` | percent | bbssd; not with `cxl_ssd` | back the device with the full NAND and expose NAND / (1 + `op_pcent`/100) |
| `ns_mgmt` (`femu`) | bool | standalone NoSSD or bbssd controller | Namespace Management and Attachment from the guest |
| `bbssd_ns_limit` | count | 1 to 256, >= `namespaces` | most bbssd namespaces `ns_mgmt` may allocate, each with its own FTL |
| `streams`, `streams.max` | bool, count | `streams.max` 1 to 32 | the Streams directive; bbssd separates streams per FTL page |
| `power_loss` | bool | see interactions | roll back writes still in the write buffer on a simulated power cut |
| `subsys` | device id | a `femu-subsys` listed earlier | join a subsystem |
| `ns_mgmt` (`femu-subsys`) | bool | NoSSD and bbssd controllers, not with `fdp` | one namespace table and backend shared by every controller of the subsystem |
| `nqn` (`femu-subsys`) | string | any | subsystem NQN suffix |

Interactions:

- Namespaces are packed one after another in the backend. Each bbssd or
  CSD namespace has its own FTL built from the whole NAND geometry, so each
  must fit that geometry on its own with room for GC
  ([the reserve](../design/ftl.md#the-reserve)). Each ZNS namespace builds
  its zones from its own size.
- `op_pcent` overrides `devsz_mb`: the backend becomes the raw NAND, and
  each namespace gets its share of `NAND x 100 / (100 + op_pcent)`.
- A controller may hold at most one CSD namespace; OCSSD takes the whole
  controller.
- `ns_mgmt` on `femu` stays off without an error unless every namespace
  runs `femu_mode` with `dps` 0; with a shared subsystem use the
  subsystem's `ns_mgmt`.
- `streams` needs bbssd with `mapping` `page` or `dftl` (or NoSSD, where it
  has no placement effect), and is refused with FDP or a shared subsystem.
  bbssd reserves `streams.max` + 1 lines for it.
- `power_loss` needs `buffer_size` > 0, `vwc=1` and page-aligned
  namespaces, and is refused with `meta`, `pi`, `ns_mgmt`, `subsys`,
  `namespace_modes` and `cxl_ssd`.

## 5. NAND geometry

Applies to bbssd, CSD and KV. Reference:
[NAND geometry](properties.md#nand-geometry-bbssd-csd-kv). Design:
[geometry](../design/nand-timing.md#geometry).

| Parameter | Unit | Valid values | Meaning |
| --- | --- | --- | --- |
| `secsz` | bytes | > 0 | sector size |
| `secs_per_pg` | sectors | 1 to 256 | sectors per NAND page; page size = `secs_per_pg` x `secsz` |
| `pgs_per_blk` | pages | 1 to 65536; <= 512 with `nand_cell_type` | pages per block |
| `blks_per_pl` | blocks | 1 to 65536 | blocks per plane; also the number of lines |
| `pls_per_lun` | planes | 1 to 16 | planes per LUN |
| `luns_per_ch` | LUNs | 1 to 128 | LUNs (dies) per channel |
| `nchs` | channels | 1 to 4096 | channels |

Derived quantities:

```text
page           = secs_per_pg x secsz bytes
NAND capacity  = nchs x luns_per_ch x pls_per_lun x blks_per_pl x pgs_per_blk x page
lines          = blks_per_pl          (a line is one block on every plane of every LUN)
line size      = nchs x luns_per_ch x pls_per_lun x pgs_per_blk x page
parallel units = nchs x luns_per_ch   (LUNs work in parallel; planes of a LUN together)
```

Interactions:

- The total sector count must fit in a signed 32-bit integer.
- Without `op_pcent`, the namespace is `devsz_mb` and must leave GC its
  reserve of lines; the reserve grows with `gc_thres_pcent_high`,
  `hot_cold_sep`, log-block mapping and Streams
  ([the reserve](../design/ftl.md#the-reserve)).
- Fewer, larger lines make GC coarser; more LUNs and channels raise
  throughput, not single-request latency.

## 6. NAND timing

Applies to bbssd, CSD and KV; ZNS has its own in [section 11](#11-zns).
Reference: [NAND timing](properties.md#nand-timing-bbssd-csd-kv). Design:
[NAND media and timing](../design/nand-timing.md).

| Parameter | Unit | Valid values | Meaning |
| --- | --- | --- | --- |
| `pg_rd_lat`, `pg_wr_lat`, `blk_er_lat` | ns | 32-bit | flat page read, page program and block erase times, used when `nand_cell_type` is 0 |
| `nand_cell_type` | type | 0 flat, 1 SLC, 2 MLC, 3 TLC, 4 QLC; others fall back to 0 | built-in per-page-type tables instead of the flat times |
| `pgtype_lat`, `cell_pages` | flag, bits per cell | `cell_pages` 0 to 5 | with `nand_cell_type` 0, scale the program time by the page's position in its wordline |
| `cmd_addr_lat` | ns | >= 0 | channel bus command and address phase |
| `pg_xfer_lat` | ns | >= 0 | channel bus data phase per page; 0 uses `ch_xfer_lat` |
| `ch_xfer_lat` | ns | >= 0 | data phase when `pg_xfer_lat` is 0; also the OCSSD 1.2 transfer time |
| `status_lat` | ns | >= 0 | channel bus status phase |
| `tplebsy` | ns | >= 0 | busy time between the planes of a multi-plane erase (GC with `pls_per_lun` > 1) |
| `pe_suspend`, `tsusp_ns` | flag, ns | `tsusp_ns` >= 0 | let a read suspend a program or erase on its LUN, at a cost of `tsusp_ns` |
| `trim_lat_ns` | ns per range | >= 0; bbssd and CSD; refused with FDP | time charged per Dataset Management deallocate range |

Interactions:

- The channel bus is modelled only when `cmd_addr_lat`, `pg_xfer_lat` (or
  `ch_xfer_lat`) or `status_lat` is non-zero; phases on one channel then
  run one at a time.
- Vendor command 0xEF codes 3 and 4 change only the flat times; they have
  no effect while `nand_cell_type` is set.
- Read time also grows with `ecc_step_ns` ([section 9](#9-reliability-wear-and-fault-insertion)).
- [Tutorial 05](../tutorials/05-latency-tuning.md) measures each of these.

## 7. FTL: mapping, caches and write buffer

Applies to bbssd and CSD. Reference:
[garbage collection, mapping and caches](properties.md#garbage-collection-mapping-and-caches).
Design: [the BlackBox FTL](../design/ftl.md).

| Parameter | Unit | Valid values | Meaning |
| --- | --- | --- | --- |
| `mapping` | name | `page`, `dftl`, `hybrid`, `fast` | logical-to-physical scheme: a full page table, a cached page table, BAST or FAST log-block mapping |
| `mapping_cache_mb` | MiB | 32-bit; 0 picks the built-in size | with `mapping=dftl`, the cached part of the table; a miss costs a NAND read |
| `read_cache_mb` | MiB | 0 disables | DRAM read cache; a hit costs DRAM time instead of a NAND read |
| `cache_evict` | name | `clock`, `random`, `lru`, `arc` | read cache eviction policy |
| `hot_cold_sep` | bool | `page` or `dftl` mapping; refused with FDP | write overwrites of mapped pages to separate hot lines |
| `buffer_size` | NAND pages, not bytes | >= 0; refused with FDP | DRAM write buffer; 0 programs every write directly |
| `buffer_thres_pcent` | percent | 1 to 100 when `buffer_size` > 0 | fill level at which buffered pages are written to NAND |
| `debug_ftl` | bool | | print FTL invariant violations and log-block merge counts |

Interactions:

- The write buffer models timing; the data lives in the backend. With
  `vwc=1` the guest sees a volatile write cache: Flush drains the buffer,
  FUA writes skip it, and feature 06h turns it off. With `power_loss=on`
  the buffer also holds data, which `simulate-power-loss` drops.
- `hybrid` and `fast` reserve one more line and count merges in log page
  C0h; `hot_cold_sep` reserves one more line.
- `mapping_cache_mb` has no effect except under `dftl`.
- Unknown names for `mapping`, `gc_policy` and `cache_evict` are refused.

## 8. Garbage collection

Applies to bbssd and CSD; KV uses `gc_thres_pcent` only. Reference:
[garbage collection, mapping and caches](properties.md#garbage-collection-mapping-and-caches).
Design: [garbage collection](../design/ftl.md#garbage-collection).

| Parameter | Unit | Valid values | Meaning |
| --- | --- | --- | --- |
| `gc_thres_pcent` | percent of lines in use | 1 to 100 | background GC starts; KV: share of the NAND usable for values |
| `gc_thres_pcent_high` | percent of lines in use | `gc_thres_pcent` to 100 | forced GC inside writes; also sizes the reserve |
| `gc_policy` | name | `greedy`, `random`, `cost-benefit`, `fifo`, `d-choice`; without FDP | victim line policy |
| `gc_strategy` | number | 0 greedy, 1 cost-benefit, 2 random, 4 per-handle; FDP only | victim reclaim unit policy |
| `fdp_trim_erase_all` | flag | FDP only | a deallocate resets every reclaim unit instead of the given ranges |

Interactions:

- Background GC takes only a line with at least 1/8 of its pages invalid;
  forced GC takes the best line whatever it holds.
- Set `gc_thres_pcent` above the share of the NAND the namespace fills.
  Below it, background GC never stops and the WAF settles near 8
  ([tutorial 02](../tutorials/02-gc-and-waf.md#3-the-gc-threshold)).
- The reserve is `(1 - gc_thres_pcent_high / 100) x blks_per_pl` lines,
  rounded down, plus the write pointers; the namespace must fit in the
  rest.

## 9. Reliability, wear and fault insertion

Applies to bbssd, CSD and KV unless noted. Reference:
[reliability and wear](properties.md#reliability-and-wear). Design:
[wear, read reclaim and retention refresh](../design/ftl.md#wear-read-reclaim-and-retention-refresh).

| Parameter | Unit | Valid values | Meaning |
| --- | --- | --- | --- |
| `ecc_step_ns` | ns per tier | 0 disables | extra read time per ECC tier: one per 750 erases of the block, one per `ecc_retention_sec` of data age, at most 4 |
| `ecc_retention_sec` | seconds | 0 counts wear only; refused with FDP | data age that adds one tier |
| `pe_cycles_rated` | P/E cycles | 0 takes the rating of `nand_cell_type` | denominator of SMART Percentage Used |
| `nand_bad_blocks` | blocks | capped at the block count | blocks bad from the start; lowers SMART Available Spare |
| `err_read_unc_ppm` | per million | 0 disables; bbssd and CSD | reads that fail as Unrecovered Read Error, at a fixed period |
| `err_write_fail_ppm` | per million | 0 disables; bbssd, CSD and ZNS | writes that fail; a ZNS zone then becomes read only |
| `read_reclaim_limit` | reads | 0 disables; bbssd and CSD; refused with FDP | a block read this often since its erase gets its line rewritten on a following write |
| `retention_limit_sec` | seconds | 0 disables; bbssd and CSD; refused with FDP | a read that hits a line filled at least this long ago queues the line, which is rewritten on a following write |

Interactions: faults come at a fixed period, so a run repeats exactly.
Read reclaim and retention refresh act only when the host reads and then
writes; their cost appears as write amplification.

## 10. Host link and controller firmware

Applies to every NVMe mode. Reference:
[host link and controller firmware](properties.md#host-link-and-controller-firmware).
Design: [host link and firmware CPU](../design/nand-timing.md#host-link-and-firmware-cpu).

| Parameter | Unit | Valid values | Meaning |
| --- | --- | --- | --- |
| `pcie_bandwidth_mbps` | MB/s (10^6 bytes) | 0 disables | each Read and Write is charged its size at this rate, on one queue per direction |
| `pcie_prop_delay_ns` | ns | 0 disables | fixed delay added to each Read and Write after its transfer |
| `fw_cpu_ns` | ns per command | 0 disables | firmware time per Read, Write and Zone Append on one modelled core; caps the rate at about one command per `fw_cpu_ns` |

## 11. ZNS

Reference: [ZNS](properties.md#zns). Design: [ZNS](../design/zns.md).

| Parameter | Unit | Valid values | Meaning |
| --- | --- | --- | --- |
| `zns_num_ch` | channels | 1 to 128 | channels |
| `zns_num_lun` | LUNs | >= 1 | LUNs per channel |
| `zns_num_plane` | planes | 1 to 8 | planes per LUN; the program unit grows with it |
| `zns_num_blk` | blocks | >= 1 | blocks per plane |
| `zns_chnls_per_zone` | channels | divides `zns_num_ch`; 0 = all | zone width |
| `zns_zone_cap` | bytes | one block to the zone size; 0 = zone size | writable part of each zone |
| `zns_flash_type` | type | 1 SLC, 2 MLC, 3 TLC, 4 QLC, 5 PLC | cell type; MLC and PLC need the three times below |
| `zns_pg_rd_lat`, `zns_pg_wr_lat`, `zns_blk_er_lat` | ns | >= 0; 0 = built-in | override the cell type's times |
| `zns_cmd_addr_lat`, `zns_pg_xfer_lat`, `zns_status_lat` | ns | >= 0 | channel bus phases |
| `zns_pe_suspend`, `zns_tsusp_ns` | flag, ns | | reads suspend a program or erase on their plane |
| `zns_max_open`, `zns_max_active` | zones | <= zone count, open <= active; 0 = no limit | Maximum Open and Active Resources |
| `zns_num_wc` | write caches | <= zone count; 0 picks from `zns_max_open` | zone write caches |
| `zns_zasl_bs` | bytes | power-of-two multiple of 4 KiB; 0 follows `mdts` | Zone Append size limit |
| `zns_zd_ext_size` | bytes | multiple of 64, up to 16320 | zone descriptor extension size |
| `zns_num_conv_zones` | zones | capped at the zone count | leading conventional zones; Linux rejects them |
| `zns_zrwa_size`, `zns_zrwafg_size`, `zns_zrwa_num` | blocks, blocks, zones | all three set or all 0 | Zone Random Write Area window, flush granularity and resources |
| `zns_cross_zone_read` | bool | | allow reads across zone boundaries |

Derived quantities (when the divisions are exact):

```text
pages per block = namespace size / 16 KiB / (zns_num_ch x zns_num_lun x zns_num_blk)
zone width      = zns_chnls_per_zone, or zns_num_ch when 0
zone size       = zone width x zns_num_lun x zns_num_plane x pages per block x 16 KiB
zone count      = zns_num_ch x zns_num_blk / (zone width x zns_num_plane)
```

Interactions:

- The zone count does not depend on the namespace size; the zone size
  grows with it. Linux uses a zoned namespace only when the zone size is a
  power of two, so keep the size and the geometry powers of two.
- `lba_index` must select a block of 4 KiB or less.
- `zns_zrwa_size` must be a multiple of `zns_zrwafg_size`, and the zone
  capacity a multiple of `zns_zrwafg_size`.
- The BlackBox geometry and timing properties do not apply to ZNS.

## 12. FDP

Set on `femu-subsys`, which a bbssd controller joins with `subsys=`.
Reference: [Flexible Data Placement](properties.md#flexible-data-placement).
Design: [FDP](../design/fdp.md).

| Parameter | Unit | Valid values | Meaning |
| --- | --- | --- | --- |
| `fdp` | bool | | FDP in endurance group 1 for the joining controller |
| `fdp.nruh` | handles | 1 to `fdp.nru`; required with `fdp=on` | reclaim unit handles, the placement identifiers the host can name |
| `fdp.nru` | reclaim units | `fdp.nruh` to 65536 | reclaim units per group; bbssd uses at most one per line and needs `2 x fdp.nruh + 1` |
| `fdp.nrg` | groups | 1 only | reclaim groups |
| `fdp.runs` | bytes | 0, or one line's size with bbssd | reclaim unit size; 0 lets FEMU choose |
| `fdp.isolation_mode` | number | 0, or any other value | 0: every handle Persistently Isolated; otherwise the last one Initially Isolated |

Interactions:

- The subsystem takes one controller with one namespace, and must come
  first on the command line.
- The controller's `gc_strategy` and `fdp_trim_erase_all` apply;
  `gc_policy` other than `greedy`, `mapping` other than `page`,
  `buffer_size`, `hot_cold_sep`, `read_reclaim_limit`,
  `retention_limit_sec`, `ecc_retention_sec`, `trim_lat_ns`, `meta`,
  `streams` and `ns_mgmt` are refused.
- KV is refused under FDP; NoSSD, ZNS and OCSSD report FDP but ignore it
  for placement.

## 13. OCSSD, CSD and KV

### OCSSD

Reference: [OCSSD](properties.md#ocssd-open-channel).

| Parameter | Unit | Valid values | Meaning |
| --- | --- | --- | --- |
| `lver` | version | 1 (1.2) or 2 (2.0) | Open-Channel version |
| `flash_type` | type | 1 SLC, 2 MLC, 3 TLC, 4 QLC | cell type for the built-in timing tables |
| `lnum_ch`, `lnum_lun` | count | `lnum_ch` 1 to 32, `lnum_ch x lnum_lun` <= 128 | channels (2.0 groups) and LUNs (parallel units) |
| `lnum_pln` | planes | > 0; 1.2: 1, 2 or 4 | planes per LUN |
| `lpgs_per_blk`, `lsecs_per_pg` | count | > 0; 1.2: pages <= 512 | pages per block, sectors per page |
| `lsec_size`, `lmetasize`, `lmax_sec_per_rq` | bytes, bytes, sectors | 1.2 only | sector size, out-of-band bytes, most sectors per vector command |
| `oc12_channel_timing` | bool | 1.2 only | charge channel transfer per page, `ch_xfer_lat` or the `flash_type` value |
| `learly_reset` | flag | 2.0 only | report the early reset capability |

OCSSD takes the whole controller: one namespace, no `namespace_modes`
neighbours.

### CSD

Reference: [CSD](properties.md#csd-computational-storage). CSD builds the
bbssd FTL, so sections 5 to 9 apply.

| Parameter | Unit | Valid values | Meaning |
| --- | --- | --- | --- |
| `fdm_size` | MiB | > 0, required | functional data memory |
| `nr_cu` | compute units | 1 to 64 | programs run on the first free unit |
| `csf_runtime_scale` | multiplier | > 0 | host run time multiplier for programs that declare no run time |
| `csd_program_dir` | host directory | | where shared-object and uBPF programs load from; unset allows only the built-in program type |

### KV

KV uses the geometry (section 5), the NAND timing (section 6), and
`gc_thres_pcent` as the share of the NAND usable for values. The FTL,
mapping, cache and write buffer properties do not apply, and the GC
capacity check of bbssd is not made: a namespace larger than the NAND
starts, with its value space clamped. Design: [KV](../design/kvssd.md).

## 14. CXL SSD

`femu-cxl-ssd` is a separate device below a CXL root port. Reference:
[`femu-cxl-ssd`](properties.md#femu-cxl-ssd-cxl-type-3-ssd) and its
[runtime properties](runtime-properties.md#femu-cxl-ssd-cxl-type-3-ssd).
Design: [CXL SSD](../design/cxl-ssd.md).

| Parameter | Unit | Valid values | Meaning |
| --- | --- | --- | --- |
| `volatile-memdev` | memory backend id | required; a non-zero multiple of 256 MiB, at most 120 GiB | the backend that holds the data; its size is the device capacity |
| `cache-pages` | 4 KiB pages | 0, or up to the media page count and divisible by `cache-ways` | DRAM page cache; 0 sends every access to the media |
| `cache-ways` | ways | non-zero, divides `cache-pages` | set associativity; 1 is direct mapped; changeable at run time |
| `cache-policy` | name | `fifo`, `lifo`, `clock`, `s3-fifo` | replacement within a set |
| `prefetch-degree`, `prefetch-stride` | pages | up to the media page count | pages inserted after a miss, and their distance; changeable at run time |
| `ftl` | bool | | `off` charges no media time and cannot be linked to an NVMe controller |
| `channels`, `luns-per-channel` | count | 1 to 4096, 1 to 128 | NAND channels and LUNs (one plane each) |
| `pages-per-block`, `blocks-per-plane` | count | 1 to 65536; blocks 2 to 65536, or 0 to size it | NAND blocks; 0 leaves spare room for GC |
| `read-ns`, `program-ns`, `erase-ns`, `channel-ns` | ns | at most one second | NAND times |
| `gc-threshold`, `gc-threshold-high` | percent | 1 to 100, high >= low | GC watermarks |
| `der` | name | `off`, `memslot`, `cylon` | direct mapping of cached pages into the guest |
| `der-replace-rate` | per second | 0 disables | `memslot` alias replacements a hot page may cause |
| `cylon-kernel-ack` | bool | must be on with `der=cylon` | states that the host runs a fixed Cylon kernel |
| `concurrent-misses` | on, off, auto | | misses to different pages wait for the media together |
| `cylon-first-touch-program`, `cylon-free-writeback` | bool | | media rules of the published Cylon experiments |
| `cca` | bool | | the caching API on BAR 5 |
| `lsa-control` | bool | not with an `lsa` backend | experiment commands through Get LSA; trusted guests only |
| `log-dir`, `tracefs-dir`, `log-limit` | path, path, bytes | `log-limit` 0 opens no I/O log | where the control channel writes, and how much |

Interactions:

- The machine needs `cxl=on`, a `pxb-cxl` host bridge, a `cxl-rp` root
  port and a `cxl-fmw` window at least as large as the backend;
  `run-cxlssd.sh` builds them.
- `der=memslot` needs KVM. `der=cylon` needs a Cylon host kernel, a shared,
  preallocated hugetlbfs backend and `smm=off`; without them it falls back
  to MMIO with a warning.
- A `femu` controller with `cxl_ssd=<id>` serves the same medium as an NVMe
  namespace. It needs `femu_mode=1`, one namespace, `ftl=on` on the CXL
  device, `devsz_mb` unset or equal to the medium's size, and none of
  `ns_mgmt`, `subsys`, `streams`, `power_loss`, `buffer_size`, `op_pcent`,
  `meta`, `pi` or `dps`. The medium's geometry and timing apply, not the
  controller's ([CXL NVMe link](../features/cxl-nvme-link.md)).

## 15. Accepted for compatibility, no effect

These properties exist so that old command lines still start. Setting one
to anything but its default prints a warning at realize.

| Device | Properties |
| --- | --- |
| `femu` | `serial`, `ms`, `ms_max`, `dlfeat`, `tplpbsy`, `tplrbsy`, `trcbsy`, `nr_thread`, `time_slice`, `context_switch_time` |

`nr_thread` is still refused at 0 by CSD. Identify Controller reports a
serial number FEMU generates, whatever `serial` says.

## 16. Worked configurations

Each configuration below is started by the documentation checks, which
also write and read one block through it.

### A TLC drive with a channel bus and read suspend

A 4 GiB namespace over the default geometry, TLC page-type timing, a 10 us
page transfer and 2 us command and status phases on each channel, and reads
that suspend a program or erase for 15 us of overhead:

<!-- femu-example: pm-tlc-bus -->
```
-device femu,femu_mode=1,devsz_mb=4096,nand_cell_type=3,cmd_addr_lat=2000,pg_xfer_lat=10000,status_lat=2000,pe_suspend=1,tsusp_ns=15000
```

### DFTL with caches and a write buffer

A DFTL table with 8 MiB cached, a 64 MiB read cache with LRU eviction, and
a write buffer of 4096 pages (16 MiB) that the guest sees as a volatile
write cache. `oncs=0x1c` adds Write Zeroes to the defaults:

<!-- femu-example: pm-dftl-caches -->
```
-device femu,femu_mode=1,devsz_mb=2048,mapping=dftl,mapping_cache_mb=8,read_cache_mb=64,cache_evict=lru,buffer_size=4096,buffer_thres_pcent=75,vwc=1,oncs=0x1c
```

### A GC study drive

512 MiB of NAND with 25% spare, GC only when forced, cost-benefit victims
and hot/cold separation, as in
[tutorial 02](../tutorials/02-gc-and-waf.md):

<!-- femu-example: pm-gc-study -->
```
-device femu,femu_mode=1,nchs=2,luns_per_ch=4,blks_per_pl=64,op_pcent=25,gc_thres_pcent=95,gc_policy=cost-benefit,hot_cold_sep=on
```

### A ZNS drive with 4 KiB blocks, limits and ZRWA

64 zones of 64 MiB, 4 KiB logical blocks, 8 open and 16 active zones, and a
ZRWA of 64 blocks flushed in units of 8 on up to 4 zones at once:

<!-- femu-example: pm-zns -->
```
-device femu,femu_mode=3,devsz_mb=4096,zns_num_ch=8,zns_num_lun=4,zns_num_plane=2,zns_num_blk=128,lba_index=3,zns_max_open=8,zns_max_active=16,zns_zrwa_size=64,zns_zrwafg_size=8,zns_zrwa_num=4
```

### FDP with eight handles

Eight placement handles over the default geometry's 256 lines, with
cost-benefit reclaim unit selection:

<!-- femu-example: pm-fdp -->
```
-device femu-subsys,id=fdp0,fdp=on,fdp.nruh=8 -device femu,femu_mode=1,devsz_mb=2048,subsys=fdp0,gc_strategy=1
```

### Mixed namespaces on a modelled link

A 3 GiB BlackBox namespace and a 1 GiB ZNS namespace on one controller,
with a 3500 MB/s host link, 1 us of propagation delay and 2 us of firmware
time per command:

<!-- femu-example: pm-mixed-link -->
```
-device femu,femu_mode=1,devsz_mb=4096,namespaces=2,namespace_sizes=3G,,1G,namespace_modes=bbssd,,znssd,pcie_bandwidth_mbps=3500,pcie_prop_delay_ns=1000,fw_cpu_ns=2000
```

### Wear and faults

A drive rated for 3000 program/erase cycles, with 100 bad blocks, an ECC step of
5 us, one read in 100,000 uncorrectable and one write in 1,000,000 failed:

<!-- femu-example: pm-wear-faults -->
```
-device femu,femu_mode=1,devsz_mb=1024,pe_cycles_rated=3000,nand_bad_blocks=100,ecc_step_ns=5000,err_read_unc_ppm=10,err_write_fail_ppm=1
```

### Namespace management

A controller that starts with one bbssd namespace and lets the guest create
up to four:

<!-- femu-example: pm-ns-mgmt -->
```
-device femu,femu_mode=1,devsz_mb=2048,ns_mgmt=on,bbssd_ns_limit=4
```

### A CXL SSD and an NVMe view of it

A 256 MiB `femu-cxl-ssd` with a 1024-page, 4-way `s3-fifo` cache below a
CXL host bridge, and a `femu` controller that serves the same medium as an
NVMe namespace:

<!-- femu-example: pm-cxl-link -->
```bash
./qemu-system-x86_64 -machine q35,cxl=on \
    -object memory-backend-ram,id=cxlmem,size=256M \
    -device pxb-cxl,id=cxl.0,bus=pcie.0,bus_nr=52 \
    -device cxl-rp,id=cxl-rp0,bus=cxl.0,chassis=0,slot=0 \
    -device femu-cxl-ssd,id=cxlssd,bus=cxl-rp0,volatile-memdev=cxlmem,cache-pages=1024,cache-ways=4,cache-policy=s3-fifo \
    -device femu,id=nvme0,bus=pcie.0,femu_mode=1,cxl_ssd=cxlssd \
    -M cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.size=256M
```

## Related pages

- [Device property reference](properties.md) and
  [runtime properties](runtime-properties.md), generated from the binary
- [Tutorials](../tutorials/README.md)
- [Design](../design/README.md)
- [Log pages and counters](log-pages-and-counters.md)
