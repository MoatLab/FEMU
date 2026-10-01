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
launcher is in `hw/femu/scripts/`. Each guide covers launch, configuration,
guest-side use, refusals and troubleshooting for its mode or feature.

| Goal | Mode or feature | Key settings | Launcher | Guide |
| --- | --- | --- | --- | --- |
| Fastest emulated NVMe drive, for host software stack work | NoSSD | `femu_mode=2` (or nothing) | `run-nossd.sh` | [NoSSD](../modes/nossd.md) |
| A conventional SSD with realistic latency, GC and write amplification | BBSSD | `femu_mode=1`; geometry `nchs`, `luns_per_ch`, `pls_per_lun`, `blks_per_pl`, `pgs_per_blk`; timing `pg_rd_lat`, `pg_wr_lat`, `blk_er_lat` | `run-blackbox.sh` | [BlackBox](../modes/blackbox.md) |
| A zoned drive for ZNS-aware filesystems and databases | ZNS | `femu_mode=3`; `zns_num_ch`, `zns_num_lun`, `zns_num_plane`, `zns_num_blk`, `zns_flash_type` | `run-zns.sh` | [ZNS](../modes/zns.md) |
| Host-managed flash: your own FTL in the host | OCSSD | `femu_mode=0`, `lver=2` (or 1); `lnum_ch`, `lnum_lun`, `lnum_pln`, `lpgs_per_blk` | `run-whitebox.sh` | [OCSSD](../modes/ocssd.md) |
| Store and fetch values by key, with no file system | KV | `femu_mode=5` | none | [KV](../modes/kvssd.md) |
| Run filters or other programs inside the drive | CSD | `femu_mode=4`, `fdm_size` (required), `nr_cu`, `csd_program_dir` | `run-csd.sh` | [CSD](../modes/csd.md) |
| Steer writes to reclaim units to reduce write amplification | FDP on BBSSD | `-device femu-subsys,id=s0,fdp=on,fdp.nruh=N` before the controller, then `femu_mode=1,subsys=s0` | `run-blackbox-fdp.sh` | [FDP](../features/fdp.md) |
| Several namespaces on one controller, possibly of different modes | multi-namespace | `namespaces=N`, optional `namespace_sizes=...`, `namespace_modes=...` | none | [Several namespaces](../features/multi-namespace.md) |
| Create and delete namespaces from the guest | Namespace Management | `ns_mgmt=on` on a NoSSD or BBSSD controller; `bbssd_ns_limit` for BBSSD | none | [Namespace management](../features/ns-management-and-pi.md#namespace-management) |
| Metadata and end-to-end protection information | metadata, PI | `meta=8` (or more), `mc`, `pi=on` | none | [Metadata and PI](../features/ns-management-and-pi.md#metadata-and-protection-information) |
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

## Every mode at a glance

Generated from [`modes.py`](../modes.py): how to turn each mode or feature
on, the guest kernel and tools it needs, what the host needs, and what CI
checks. [requirements.md](../getting-started/requirements.md#kernel-per-mode)
has the guest kernel configuration in more detail.

<!-- modes-table:start -->
<!-- Generated from hw/femu/docs/modes.py by hw/femu/scripts/gen-mode-table.py; edit modes.py, not this table. -->

| Mode or feature | Use it for | Turn it on with | Guest kernel | Guest tools | Host needs | Launcher | Checked |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [NoSSD](../modes/nossd.md) | fast NVMe device in DRAM, no flash timing | `femu_mode=2` (the default) | any with the NVMe driver | nvme-cli, fio | none beyond the common ones | `run-nossd.sh` | CI: realize, Identify, write and read back |
| [BlackBox SSD (BBSSD)](../modes/blackbox.md) | a commercial SSD: device FTL, GC, NAND timing | `femu_mode=1` | any with the NVMe driver | nvme-cli, fio | about 17 GiB free RAM for the launcher's 12 GiB device | `run-blackbox.sh` | CI: realize, Identify, write and read back; guest: [quick start, run end to end](../getting-started/quick-start.md) |
| [Zoned Namespace (ZNS)](../modes/zns.md) | zoned storage research | `femu_mode=3` | 5.9 or newer with `CONFIG_BLK_DEV_ZONED=y`; 4 KiB guest pages | nvme-cli 1.12 or newer for `nvme zns` | none beyond the common ones | `run-zns.sh` | CI: realize, Identify, write and read back |
| [Open-Channel SSD 1.2](../modes/ocssd.md) | host-managed FTL research | `femu_mode=0,lver=1` | 4.16 to 5.14 (LightNVM was removed in 5.15) | LightNVM tools, or SPDK on newer kernels | none beyond the common ones | `run-whitebox.sh` | CI: realize, Identify |
| [Open-Channel SSD 2.0](../modes/ocssd.md) | host-managed FTL research | `femu_mode=0` (`lver=2` is the default) | 4.17 to 5.14 (LightNVM was removed in 5.15) | LightNVM tools, or SPDK on newer kernels | none beyond the common ones | `run-whitebox.sh` | CI: realize, Identify |
| [Key-value SSD (KV)](../modes/kvssd.md) | key-value store research | `femu_mode=5` | 5.13 or newer; no block device, the namespace is `/dev/ngXnY` | nvme-cli `io-passthru`, `hw/femu/scripts/kv-probe.c` | none beyond the common ones | none | CI: realize, Identify, store and retrieve |
| [Computational storage (CSD)](../modes/csd.md) | running programs next to the data | `femu_mode=4,fdm_size=<MiB>` | any with the NVMe driver | `hw/femu/tests/csd` tools | `csd_program_dir` for shared-library programs; `--enable-csd-ubpf` build for eBPF programs | `run-csd.sh` | CI: realize, Identify, write and read back |
| [Flexible Data Placement (FDP)](../features/fdp.md) | placement hints on a BBSSD | `femu-subsys,fdp=on,fdp.nruh=<n>` and `femu,femu_mode=1,subsys=<id>` | any with the NVMe driver; placement hints need passthrough or io_uring commands | nvme-cli with `nvme fdp` | none beyond the common ones | `run-blackbox-fdp.sh` | CI: realize, Identify, write and read back |
| [Multiple namespaces](../features/multi-namespace.md) | several namespaces, each with its own mode | `namespaces=<n>`, optionally `namespace_sizes` and `namespace_modes` | any with the NVMe driver (ZNS namespaces need what ZNS needs) | nvme-cli | none beyond the common ones | none | CI: realize, Identify, write and read back |
| [Namespace management](../features/ns-management-and-pi.md#namespace-management) | create, delete and attach namespaces at run time | `ns_mgmt=on` on a NoSSD or BBSSD controller; `femu-subsys,ns_mgmt=on` to share namespaces | any with the NVMe driver | nvme-cli `create-ns`, `attach-ns` | none beyond the common ones | none | CI: realize, Identify, write and read back |
| [Metadata and protection information](../features/ns-management-and-pi.md#metadata-and-protection-information) | per-block metadata, PI types 1 to 3 | `meta=<bytes>,mc=<mask>`, plus `pi=on` with `meta` of 8 or more | `CONFIG_BLK_DEV_INTEGRITY=y` to use metadata formats through the block layer | nvme-cli `format` | none beyond the common ones | none | CI: realize, Identify, write and read back |
| [CXL SSD, `der=off`](../cxlssd.md) | CXL memory backed by flash, all accesses trapped | `femu-cxl-ssd` below `pxb-cxl` and `cxl-rp` on `-machine q35,cxl=on` | `CONFIG_CXL_BUS`, `CXL_PCI`, `CXL_ACPI`, `CXL_MEM`, `CXL_PORT`, `CXL_REGION`, `DEV_DAX`, `DEV_DAX_KMEM` | `cxl-cli`, `daxctl`, `ndctl` | a build with `CONFIG_CXL_MEM_DEVICE` | `run-cxlssd.sh` | CI: realize |
| [CXL SSD, `der=memslot`](../cxlssd.md) | cached pages mapped into the guest as KVM memory slots | `der=memslot` on `femu-cxl-ssd` | as for `der=off` | as for `der=off` | KVM (TCG is refused) | `run-cxlssd.sh` | CI: realize |
| [CXL SSD, `der=cylon`](../cxlssd.md) | cached pages mapped by a Cylon host kernel | `der=cylon,cylon-kernel-ack=on` on `femu-cxl-ssd` | as for `der=off` | as for `der=off` | Cylon host kernel; KVM with EPT A/D bits and the TDP MMU; 4 KiB host pages; a shared, preallocated hugetlb backend. Without them the device warns and uses MMIO | `run-cxlssd.sh` | CI: realize |
| [CXL caching API (CCA)](../../tools/cca/README.md) | guest pins, unpins and invalidates cached pages | `cca=on` on `femu-cxl-ssd` | as for `der=off`; a devdax region | `hw/femu/tools/cca` (`ccactl`, `cca-test`), run as root | as for `der=off` | `run-cxlssd.sh` | CI: realize |
| [NVMe front end on a CXL SSD](../cxlssd.md) | the same media as CXL memory and as an NVMe namespace | `femu,bus=pcie.0,femu_mode=1,cxl_ssd=<id>` after the `femu-cxl-ssd` | as for `der=off`, plus the NVMe driver | as for `der=off`, plus nvme-cli | as for `der=off` | none | CI: realize, Identify, write and read back |
<!-- modes-table:end -->

The image built by `make-guest-image.sh` runs Linux 6.8 and covers every mode
except OCSSD.

## Related pages

- [Architecture](architecture.md): how the modes fit into FEMU.
- [Timing model](timing-model.md): what each mode charges time for.
- [Device property reference](../reference/properties.md)
- Mode guides: [NoSSD](../modes/nossd.md), [BlackBox](../modes/blackbox.md),
  [ZNS](../modes/zns.md), [OCSSD](../modes/ocssd.md), [KV](../modes/kvssd.md),
  [CSD](../modes/csd.md)
- Feature guides: [FDP](../features/fdp.md),
  [several namespaces](../features/multi-namespace.md),
  [namespace management and PI](../features/ns-management-and-pi.md)
