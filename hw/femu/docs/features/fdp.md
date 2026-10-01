# Flexible Data Placement (FDP)

Flexible Data Placement lets the host tell the SSD which writes belong
together. The device groups its NAND into reclaim units and offers a few
reclaim unit handles. Each write may carry a placement identifier that names
a handle, and the device puts all writes of one handle into the same open
reclaim unit. When data with similar lifetimes shares a reclaim unit, GC
finds it mostly invalid and copies less, so write amplification drops.

FDP is not a `femu_mode`. It is a property of an NVMe subsystem,
`femu-subsys`, which a [BlackBox](../modes/blackbox.md) controller joins.
In FEMU a reclaim unit is one superblock (line) of the BlackBox FTL.

Use it to measure how placement hints from an application, a file system or
fio change write amplification and tail latency.

## Requirements

- Host and guest: see [the mode table](../concepts/choosing-a-mode.md#every-mode-at-a-glance)
  and [requirements.md](../getting-started/requirements.md#kernel-per-mode).
  Any guest kernel with the NVMe driver sees the device.
- Placement hints: the guest has to send them. Ordinary writes through the
  block device carry no placement identifier unless the guest kernel adds
  one, so use passthrough commands (`nvme write` with a directive), or fio's
  `io_uring_cmd` engine on the generic device `/dev/ng0n1`.
- Guest tools: nvme-cli with the `fdp` commands (2.x), and fio built with
  `io_uring_cmd` support for placement from fio.

## Launch

From `build-femu/`:

<!-- femu-example: fdp-launcher -->
```bash
./run-blackbox-fdp.sh
```

The script builds two devices. The subsystem must come first on the command
line, because the controller names it with `subsys=`:

<!-- femu-example: fdp-device -->
```
-device femu-subsys,id=femu-subsys-0,nqn=subsys0,fdp=on,fdp.nruh=4,fdp.nrg=1,fdp.nru=256 -device femu,devsz_mb=12288,namespaces=1,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=256,blks_per_pl=256,pls_per_lun=1,luns_per_ch=8,nchs=8,pg_rd_lat=40000,pg_wr_lat=200000,blk_er_lat=2000000,ch_xfer_lat=0,gc_thres_pcent=75,gc_thres_pcent_high=95,subsys=femu-subsys-0
```

The shortest form, with the default 64 MiB reclaim units and 128 of them:

<!-- femu-example: fdp-minimal -->
```
-device femu-subsys,id=fdp0,fdp=on,fdp.nruh=4 -device femu,devsz_mb=1024,femu_mode=1,subsys=fdp0
```

`run-blackbox-fdp.sh` writes its console output to `/tmp/femu-fdp.log`.

## Configuration

### Subsystem

Properties: [Flexible Data Placement](../reference/properties.md#flexible-data-placement).

- `fdp=on` turns FDP on for the controller that joins the subsystem. An FDP
  subsystem takes a single controller.
- `fdp.nruh`: number of reclaim unit handles, that is, placement handles the
  host can name. Required, at least 1.
- `fdp.nru`: reclaim units per reclaim group (default 128). FEMU uses at most
  one per superblock, so the effective count is the smaller of `fdp.nru` and
  `blks_per_pl`. It needs at least `2 * fdp.nruh + 1` of them: one open unit
  per handle, one spare per handle for GC, and one more.
- `fdp.nrg`: reclaim groups. Must be 1.
- `fdp.runs`: reclaim unit size in bytes. Leave it at 0, or set it to the
  size of one superblock: `nchs * luns_per_ch * pls_per_lun * pgs_per_blk *
  secs_per_pg * secsz` (64 MiB with the default geometry).
- `fdp.isolation_mode`: 0 makes every handle Persistently Isolated; any other
  value makes the last handle Initially Isolated.

### Controller

The controller is an ordinary BlackBox controller with `subsys=<id>`, so the
[BlackBox geometry, timing and GC properties](../modes/blackbox.md#configuration)
apply. Two properties are specific to FDP
([garbage collection, mapping and caches](../reference/properties.md#garbage-collection-mapping-and-caches)):

- `gc_strategy`: how GC picks a victim reclaim unit: 0 greedy (default),
  1 cost-benefit, 2 random, 4 per-handle. `gc_policy` does not apply under FDP.
- `fdp_trim_erase_all`: non-zero makes a deallocate reset every reclaim unit
  instead of the given ranges.

`FEMU_FDP_DEBUG` in QEMU's environment prints placement and reclaim traces
([environment variables](../reference/properties.md#environment-variables)).

## Use it from the guest

Check that the controller supports FDP. Bit 19 (0x80000) of CTRATT is FDP:

```sh
sudo nvme id-ctrl /dev/nvme0 | grep ctratt
```

Read the configuration, handle usage, statistics and events of endurance
group 1:

```sh
sudo nvme fdp configs /dev/nvme0 -e 1
sudo nvme fdp usage /dev/nvme0 -e 1
sudo nvme fdp stats /dev/nvme0 -e 1
sudo nvme fdp events /dev/nvme0 -e 1 -E
sudo nvme fdp status /dev/nvme0n1
```

`configs` lists the handles and the reclaim unit size, `usage` gives each
handle's attributes, `stats` gives host and media bytes written, and
`status` lists the placement identifiers the namespace accepts with the
space left in each one's reclaim unit (RUAMW).
Every handle backs a placement handle of the namespace, so `usage` reports
each one as host specified:

```text
Reclaim Unit Handle 0 Attributes: 0x1 (Host Specified)
Reclaim Unit Handle 1 Attributes: 0x1 (Host Specified)
Reclaim Unit Handle 2 Attributes: 0x1 (Host Specified)
Reclaim Unit Handle 3 Attributes: 0x1 (Host Specified)
```

`events -E` shows host events, such as a write with an invalid placement
identifier; every event type is enabled by default.

### Write with a placement identifier

A write with directive type 2 (data placement) uses the directive specific
field as its placement identifier. This writes 8 blocks of 512 bytes at
LBA 0 through handle 1:

```sh
head -c 4096 /dev/urandom > data.bin
sudo nvme write /dev/nvme0n1 -s 0 -c 7 -z 4096 -d data.bin -T 2 -S 1
```

A write with no directive, or with an identifier the namespace does not
have, goes to handle 0. An invalid identifier also logs a host event.

fio places data from its `io_uring_cmd` engine. It reads the placement
identifier list from the device and cycles through the entries whose
indexes are listed in `fdp_pli`:

```sh
sudo fio --name=fdp --filename=/dev/ng0n1 --ioengine=io_uring_cmd --cmd_type=nvme \
    --fdp=1 --fdp_pli=0,1,2,3 --rw=randwrite --bs=4k --iodepth=16 --size=4G
```

### Measure the effect

The vendor log page C0h reports the write amplification factor for FDP as
for plain BlackBox. Compare a run with placement against the same run
without it:

```sh
sudo nvme get-log /dev/nvme0 --log-id=0xc0 --log-len=512 -b | od -An -t u4 -N 4
```

## Limits and refusals

| Message | Cause and fix |
| --- | --- |
| `fdp.nruh must be non-zero` | Set `fdp.nruh`. |
| `fdp.nruh (200) must not exceed fdp.nru (128)` | More handles than reclaim units. |
| `fdp.nrg must be 1: placement into a reclaim group other than the first is not implemented` | Leave `fdp.nrg` at 1. |
| `FEMU bbssd: placement needs N reclaim units for M handles across 1 groups and this geometry gives K; raise blks_per_pl or fdp.nru, or lower fdp.nruh` | Too few reclaim units for the handles. |
| `FEMU bbssd: fdp.runs must be 67108864, the size of one superblock of this geometry, or unset` | `fdp.runs` does not match the geometry. |
| `FDP supports a single namespace; set namespaces=1 or disable FDP on the subsystem` | `namespaces` above 1. |
| `femu-subsys with fdp=on takes a single controller` | A second controller joins the FDP subsystem. |
| `FEMU bbssd: buffer_size has no effect under FDP` | FDP has its own write path. The same message names `hot_cold_sep`, `read_reclaim_limit`, `retention_limit_sec`, `ecc_retention_sec`, `trim_lat_ns`, a `mapping` other than `page` and a `gc_policy` other than `greedy`. |
| `meta: not supported with placement (fdp)` | `meta` (with a valid `mc`) under FDP. |
| `streams requires bbssd or NoSSD with FDP disabled` | `streams=on` under FDP. |
| `the key-value command set and FDP cannot share a controller: ...` | A KV namespace under FDP. |
| `namespace management does not support FDP` | `ns_mgmt=on` together with `fdp=on` on the subsystem. |
| `Device 'fdp0' not found` | The controller comes before its subsystem on the command line. |

NoSSD, ZNS and OCSSD controllers accept an FDP subsystem, report FDP to the
host, and ignore it for placement. KV is refused. CSD goes through the
BlackBox FDP write path, but that combination is not tested.

When every reclaim unit is in use and GC cannot free one, a write fails with
Capacity Exceeded and QEMU prints `ssd_stream_write: device full, no RU for
ruh N`.

## Verify

1. `ctratt` has bit 19 set, and `nvme fdp configs` shows `fdp.nruh` handles
   in one reclaim group.
2. After writes with `-T 2 -S 1`, `nvme fdp status /dev/nvme0n1` shows the
   RUAMW of placement identifier 1 going down.
3. `nvme fdp stats` shows host bytes written growing with your writes.

## Troubleshooting

- **`Property 'femu.fdp' not found`, or FDP does not show up.** FDP is a
  property of `femu-subsys`, not of `femu`. Create the subsystem first and
  join it with `subsys=`.
- **QEMU crashed in GC under a long write workload (`select_victim_ru`,
  `victim_ru_get_pri`, `No free RUs left`).** These were bugs in the reclaim
  unit victim queue, fixed on master. Update FEMU.
- **The WAF is the same with and without placement.** Check that the writes
  really carry directive type 2: block-device writes do not unless the guest
  kernel sets placement. Use `nvme write -T 2 -S N` or fio with
  `--ioengine=io_uring_cmd --fdp=1`.

Related issues: #153, #186, #189, #191.

## Related pages

- [BlackBox SSD](../modes/blackbox.md)
- [Choosing a mode: which features combine](../concepts/choosing-a-mode.md#which-features-combine)
- [Architecture: features that are not modes](../concepts/architecture.md#3-mode-backends)
