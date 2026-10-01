# Choosing a mode

An NVMe `femu` device emulates one kind of SSD, chosen with `femu_mode`.
Features such as Flexible Data Placement or several namespaces are added on
top of a mode with more properties. The CXL SSD is a separate device type,
`femu-cxl-ssd`, not a `femu_mode`.

If you set nothing, you get NoSSD: `femu_mode` defaults to 2.

## `femu_mode` values

| Value | Name | Emulates |
| --- | --- | --- |
| 0 | OCSSD | An Open-Channel SSD. The host runs the FTL. `lver=1` selects Open-Channel 1.2, `lver=2` (default) selects 2.0. |
| 1 | BBSSD | A conventional ("black-box") SSD with a device FTL, garbage collection and NAND timing. |
| 2 | NoSSD | An NVMe drive with no media timing. Default. |
| 3 | ZNS | A Zoned Namespace SSD (NVMe Zoned Namespace command set). |
| 4 | CSD | A computational storage drive that runs programs next to the data, on top of the BBSSD FTL. |
| 5 | KV | A key-value SSD (NVMe Key Value command set). |

Any other value fails realize with "femu_mode must be 0 (OpenChannel), 1
(black-box), 2 (no-SSD), 3 (zoned), 4 (computational storage) or 5
(key-value)". With `femu_mode=0`, an `lver` other than 1 or 2 fails too.

## Decision table

Settings are added to `-device femu,...` unless the row says otherwise. Each
launcher is in `hw/femu/scripts/`. Mode and feature guides are being written;
until they exist, the [top-level README](../../../../README.md) and the
[property reference](../reference/properties.md) cover each mode.

| Goal | Mode or feature | Key settings | Launcher | Guide |
| --- | --- | --- | --- | --- |
| Fastest emulated NVMe drive, for host software stack work | NoSSD | `femu_mode=2` (or nothing) | `run-nossd.sh` | `modes/nossd.md` (guide coming) |
| A conventional SSD with realistic latency, GC and write amplification | BBSSD | `femu_mode=1`; geometry `nchs`, `luns_per_ch`, `pls_per_lun`, `blks_per_pl`, `pgs_per_blk`; timing `pg_rd_lat`, `pg_wr_lat`, `blk_er_lat` | `run-blackbox.sh` | `modes/blackbox.md` (guide coming) |
| A zoned drive for ZNS-aware filesystems and databases | ZNS | `femu_mode=3`; `zns_num_ch`, `zns_num_lun`, `zns_num_plane`, `zns_num_blk`, `zns_flash_type` | `run-zns.sh` | `modes/zns.md` (guide coming) |
| Host-managed flash: your own FTL in the host | OCSSD | `femu_mode=0`, `lver=2` (or 1); `lnum_ch`, `lnum_lun`, `lnum_pln`, `lpgs_per_blk` | `run-whitebox.sh` | `modes/ocssd.md` (guide coming) |
| Store and fetch values by key, with no file system | KV | `femu_mode=5` | none | `modes/kvssd.md` (guide coming) |
| Run filters or other programs inside the drive | CSD | `femu_mode=4`, `fdm_size` (required), `nr_cu`, `csd_program_dir` | `run-csd.sh` | `modes/csd.md` (guide coming) |
| Steer writes to reclaim units to reduce write amplification | FDP on BBSSD | `-device femu-subsys,id=s0,fdp=on,fdp.nruh=N` before the controller, then `femu_mode=1,subsys=s0` | `run-blackbox-fdp.sh` | `features/fdp.md` (guide coming) |
| Several namespaces on one controller, possibly of different modes | multi-namespace | `namespaces=N`, optional `namespace_sizes=...`, `namespace_modes=...` | none | `features/multi-namespace.md` (guide coming) |
| Create and delete namespaces from the guest | Namespace Management | `ns_mgmt=on` on a NoSSD or BBSSD controller; `bbssd_ns_limit` for BBSSD | none | `features/namespace-management-and-pi.md` (guide coming) |
| Metadata and end-to-end protection information | metadata, PI | `meta=8` (or more), `mc`, `pi=on` | none | `features/namespace-management-and-pi.md` (guide coming) |
| SSD capacity that the guest uses as memory, with SSD timing on cache misses | CXL SSD | `-device femu-cxl-ssd,volatile-memdev=...` on a CXL topology; `cache-pages`, `cache-policy`, `der` | `run-cxlssd.sh` | `modes/cxl-ssd.md` (guide coming); [design note](../cxlssd.md) |
| The same CXL medium also as an NVMe block device | CXL NVMe front end | `femu-cxl-ssd` first, then `-device femu,femu_mode=1,cxl_ssd=<id>` | none | `features/cxl-nvme-link.md` (guide coming) |

Commas inside a property value are doubled on the QEMU command line, for
example `namespace_modes=bbssd,,znssd`.

## Which features combine

The checks below are made at realize; a combination they refuse stops QEMU
with an error naming the rule.

**Flexible Data Placement.** `fdp=on` is a property of `femu-subsys`. Only
BBSSD has an FDP write path; other modes accept a subsystem with FDP, but
placement then has no effect on where data goes. FDP requires a single
controller in the subsystem, a single namespace (`namespaces=1`), `fdp.nrg=1`
and `fdp.nruh` from 1 to `fdp.nru`. It cannot be combined with a KV namespace,
`meta`, Streams or a subsystem with `ns_mgmt=on`. A BBSSD controller under FDP
also refuses `buffer_size`, `hot_cold_sep`, `read_reclaim_limit`,
`retention_limit_sec`, `ecc_retention_sec`, `trim_lat_ns`, a `mapping` other
than `page` and a `gc_policy` other than `greedy`.

**Several namespaces and per-namespace modes.** `namespaces` is 1 to 256. The
backend of `devsz_mb` MiB is split evenly, or by `namespace_sizes`.
`namespace_modes` lists one mode per namespace from `nossd`, `bbssd`, `znssd`,
`ocssd`, `csd` and `kvssd`; without it every namespace runs `femu_mode`. Limits:

- OCSSD supports one namespace only, and the controller must be OCSSD too.
- At most one CSD namespace per controller.
- ZNS, KV, BBSSD and NoSSD namespaces can be mixed.
- `meta` and Streams need every namespace to be NoSSD or BBSSD.

**Namespace Management.** `ns_mgmt=on` takes effect only when the controller
and every namespace are NoSSD, or every one is BBSSD; with other modes, or
with `dps`, it is accepted and stays off. On a controller that joins a
subsystem without `ns_mgmt`, it fails realize. To share namespaces between controllers, set
`ns_mgmt=on` on the `femu-subsys` instead. A shared subsystem takes NoSSD or
BBSSD controllers that all have the same mode, `meta`, `mc`, `pi`, `dpc`,
`nlbaf`, `vwc` and `oncs`, and no Streams, `dps` or `namespace_modes`.

**Metadata and protection information.** `meta` (bytes per block) works on
NoSSD and BBSSD namespaces only, not with FDP, and needs a matching `mc` bit.
`pi=on` offers protection information types 1 to 3 when `meta` is at least 8;
the guest selects one with Format NVM or Namespace Management. `pi` cannot be
combined with `power_loss` or `cxl_ssd`.

**CXL NVMe front end.** A `femu` controller with `cxl_ssd=<id>` must be BBSSD
with one namespace, and must not use `namespace_modes`, `namespace_sizes`,
`ns_mgmt`, `subsys`, `streams`, `power_loss`, `buffer_size`, `op_pcent`,
`meta`, `pi` or `dps`. The `femu-cxl-ssd` must come first on the command line
and have `ftl=on`. Its geometry and timing apply; the controller's own are
ignored, and `devsz_mb` must be left at its default or equal the CXL
medium's size.

**Other combinations.**

- Streams (`streams=on`): NoSSD or BBSSD, not with FDP or a shared subsystem;
  BBSSD needs `mapping` `page` or `dftl`.
- Power-loss model (`power_loss=on`): BBSSD with `buffer_size` > 0,
  page-aligned namespaces, and no `meta`, `pi`, `ns_mgmt`, `subsys`,
  `namespace_modes` or `cxl_ssd`. Without `vwc=1` the write buffer holds
  nothing, so there is nothing to lose.
- ZNS needs a logical block size of 4 KiB or less (`lba_index`).

## Guest requirements

The full table, with kernel configuration for CXL, is in
[requirements.md](../getting-started/requirements.md#kernel-per-mode). In
short:

| Mode | Guest kernel | Guest tools |
| --- | --- | --- |
| NoSSD, BBSSD, CSD | any kernel with the NVMe driver | `nvme-cli`, `fio`; CSD guest tools in `hw/femu/tests/csd/` |
| FDP | any kernel with the NVMe driver | placement hints through passthrough commands or io_uring |
| ZNS | 5.9 or newer with `CONFIG_BLK_DEV_ZONED=y` | `nvme-cli` 1.12 or newer for `nvme zns` |
| KV | 5.13 or newer; the namespace appears as `/dev/ngXnY`, not as a block device | `nvme io-passthru` |
| OCSSD | 4.16 to 5.14 (Open-Channel 2.0 needs 4.17 or newer); LightNVM was removed in 5.15 | SPDK on 5.15 and newer |
| CXL SSD | CXL region and DAX support (`CONFIG_CXL_BUS`, `CXL_PCI`, `CXL_ACPI`, `CXL_MEM`, `CXL_PORT`, `CXL_REGION`, `DEV_DAX`, `DEV_DAX_KMEM`) | `cxl-cli`, `daxctl` |

The image built by `make-guest-image.sh` runs Linux 6.8 and covers every mode
except OCSSD.

## Related pages

- [Architecture](architecture.md): how the modes fit into FEMU.
- [Timing model](timing-model.md): what each mode charges time for.
- [Device property reference](../reference/properties.md)
