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
FEMU's FDP support comes from WARP; if you use it, cite WARP as well as FEMU
([citation](#citation)).

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
  per handle, one spare per handle for GC, and one more. The namespace gets
  what is left once each handle has a unit open, each Persistently Isolated
  handle one to collect into, and forced GC its free units (at least one
  unless `gc_thres_pcent_high` is 100);
  a larger `devsz_mb` is refused. See
  [the reserve](../design/fdp.md#configuration).
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
  1 cost-benefit, 2 random, 4 per-handle.
  The random strategy draws from a generator seeded by `gc_seed`, so it
  repeats run to run.
- `gc_policy`: the same choice by name. `cost-benefit` and `random` are
  strategies 1 and 2; `fifo` and `d-choice` exist only by name. A name
  other than `greedy` needs `gc_strategy=0`. `d-choice` draws from the
  same generator.
- `buffer_size`, `buffer_thres_pcent`, `vwc`: the write buffer holds placed
  writes. Each held page goes to the unit of the handle that last wrote
  it, and RUH Update writes the buffer back first
  ([design](../design/fdp.md#parameters)).
- `mapping=dftl`: a placed write charges the translation page of each
  page it programs.
- `fdp_trim_erase_all`: non-zero makes a deallocate reset every reclaim unit
  instead of the given ranges.

`FEMU_FDP_DEBUG` in QEMU's environment prints placement and reclaim traces
([environment variables](../reference/properties.md#environment-variables)).

### Several namespaces

Reclaim units and handles belong to the endurance group, so namespaces of
one FDP controller share them. Each namespace has its own placement handle
list (PHL): placement handle `i` of the namespace selects reclaim unit
handle `phl[i]`. Two namespaces may list the same handle; their writes then
go to the same reclaim unit.

```text
 namespace_phls=0:1,,2:1
 ns 1: PH 0 -> RUH 0, PH 1 -> RUH 1  --+
 ns 2: PH 0 -> RUH 2, PH 1 -> RUH 1  --+--> RUH 1 is shared; RUH 3 is unused
```

<!-- femu-example: fdp-namespaces -->
```
-device femu-subsys,id=fdp0,fdp=on,fdp.nruh=4 -device femu,devsz_mb=1024,femu_mode=1,subsys=fdp0,namespaces=2,namespace_phls=0:1,,2:1
```

- `namespace_phls`: one entry per namespace, separated by commas (`,,` on
  the QEMU command line). An entry lists handle IDs separated by `:`. Each
  entry has 1 to `MIN(fdp.nruh, 128)` IDs, each below `fdp.nruh`, none twice.
  Unset, every namespace gets every handle in order.
- Every namespace is BlackBox, or every one is NoSSD. BlackBox namespaces
  share one FTL, each in its own slice of the logical pages. Thus a
  namespace size must be a whole number of NAND pages. The sum of the sizes must fit
  in the reclaim units, as one namespace must.
- `nvme fdp status /dev/nvme0n2` lists the placement identifiers of
  namespace 2 with the handle each selects. `nvme fdp usage` reports a
  handle no list names as unused (RUHA 0).
- Statistics (log 22h) and C0h count the endurance group: a shared handle
  adds the writes of every namespace that uses it.
- Namespaces that share a handle keep one format. A Format of one of them
  to another LBA format fails with Invalid Format; format them together
  with NSID FFFFFFFFh. Namespaces with no shared handle may differ, and
  RUAMW counts the blocks of each handle's namespaces.
- Event 80h names the namespace of the blocks it counts. It carries the
  placement identifier of that namespace; a collection that moves blocks of two
  namespaces logs one 80h for each run of them. Events without moved data
  (01h, and 81h of a refresh) name the first namespace that lists the handle.
- The write buffer (`buffer_size`) belongs to the shared FTL. A Flush of
  one namespace writes back the held pages of every namespace, which the
  specification allows. A RUH Update does the same before it moves a handle.
- NoSSD namespaces have no media: RUH Status and RUH Update work, and no
  bytes are counted.

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
space left in each one's reclaim unit (RUAMW). Every page programmed into
the unit counts. This includes pages that collection moves into the unit
of an Initially Isolated handle. A Format does not give the room back.
By default every handle backs a placement handle of the namespace, so
`usage` reports each one as host specified:

```text
Reclaim Unit Handle 0 Attributes: 0x1 (Host Specified)
Reclaim Unit Handle 1 Attributes: 0x1 (Host Specified)
Reclaim Unit Handle 2 Attributes: 0x1 (Host Specified)
Reclaim Unit Handle 3 Attributes: 0x1 (Host Specified)
```

`events -E` shows host events, such as a write with an invalid placement
identifier; every event type is enabled by default. Without `-E`, `events`
shows controller events. When collection or a read refresh moves data of the
Initially Isolated handle, it logs 80h (Media Reallocated) with the number
of blocks moved. When such a move gives that handle a new reclaim unit, it
logs 81h (Implicitly Modified Reclaim Unit Handle).

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

### Enable the Data Placement Directive

The spec asks the host to enable the Data Placement Directive per namespace
before it writes with directive type 2. FEMU reports the directive in the
Identify directive and accepts the enable. It also places writes with
directive type 2 when the host did not enable the directive, because the
Linux driver does not enable it.

```sh
# enable (Directive Send, Identify directive, Enable Directive, type 2)
sudo nvme dir-send /dev/nvme0n1 -n 1 -D 0 -O 1 -T 2 -e 1
# check: Data Placement is supported, enabled and kept across a reset
sudo nvme dir-receive /dev/nvme0n1 -n 1 -D 0 -O 1 -H
```

```
 Directive Receive, Identify (bytes 0, 32, 64; bit 2 = Data Placement)
   supported  01h | 04h        enabled  01h, or 05h after the enable
   kept across a controller reset: 04h
 Directive Send, enable type 2:  nsid FFFFFFFFh -> Invalid Namespace or Format
                                 no FDP          -> FDP Disabled
 any command with directive type 2 -> Invalid Field (it has no operations)
 enabled: Write, Write Zeroes or Copy naming a type other than 0 or 2 -> Invalid Field
```

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

The QMP command [`query-femu`](../reference/query-femu.md) reads the same
state from the host, with no guest tools. It shows the bytes that each
reclaim unit handle wrote and moved, and the state of each reclaim unit:

```json
{"execute": "query-femu", "arguments": {"kind": "reclaim-units"}}
```

## Limits and refusals

| Message | Cause and fix |
| --- | --- |
| `fdp.nruh must be non-zero` | Set `fdp.nruh`. |
| `fdp.nruh (200) must not exceed fdp.nru (128)` | More handles than reclaim units. |
| `fdp.nrg must be 1: placement into a reclaim group other than the first is not implemented` | Leave `fdp.nrg` at 1. |
| `FEMU bbssd: placement needs N reclaim units for M handles across 1 groups and this geometry gives K; raise blks_per_pl or fdp.nru, or lower fdp.nruh` | Too few reclaim units for the handles. |
| `FEMU bbssd: namespace 1 exposes 1024 KiB, but placement keeps 9 of the 24 reclaim units for 4 handles and collection, leaving 960 KiB; lower devsz_mb or fdp.nruh, raise blks_per_pl, or raise op_pcent` | The namespace does not fit in what placement leaves. |
| `FEMU bbssd: fdp.runs must be 67108864, the size of one superblock of this geometry, or unset` | `fdp.runs` does not match the geometry. |
| `FDP with more than one namespace needs every namespace in bbssd mode or every one in nossd mode` | Namespaces of other modes, or of mixed modes, with `namespaces` above 1. |
| `FDP with more than one namespace needs namespace sizes in whole NAND pages (4096 bytes); namespace 1 has 526336 bytes` | Set `namespace_sizes` to multiples of the page size. |
| `fdp_trim_erase_all erases every namespace; it needs a single namespace` | The test knob with more than one namespace. |
| `FEMU bbssd: the 2 namespaces expose 2048 KiB, but placement keeps 9 of the 25 reclaim units ...` | The namespaces together do not fit in the reclaim units. |
| `namespace_phls needs fdp=on on the subsystem` | Placement handle lists without FDP. |
| `namespace_phls count must equal namespaces=2` | One entry per namespace. |
| `namespace_phls: namespace 1 names handle '4'; handles are 0 to 3` | An ID that is not a handle. |
| `namespace_phls: namespace 1 lists handle 0 twice` | An ID twice in one list. |
| `namespace_phls: namespace 2 lists no handle` | An empty entry. |
| `femu-subsys with fdp=on takes a single controller` | A second controller joins the FDP subsystem. |
| `FEMU bbssd: set gc_policy or gc_strategy under FDP, not both` | Both pick the reclaim unit strategy. Set one of them, or leave `gc_policy` at `greedy`. |
| `FEMU bbssd: hot_cold_sep is not supported under FDP: the placement handle of a write chooses its reclaim unit, ...` | The placement handle of a write names its reclaim unit, and the hot write pointer writes past it. Give hot data a placement handle of its own. |
| `FEMU bbssd: mapping=hybrid is not supported under FDP: the log-block mappings write and merge through lines that are not FDP-aware; use page or dftl` | The same for `mapping=fast`. The log-block mappings keep their own log and data lines. A CSD controller gets these messages with `FEMU csd:`. |
| `meta: not supported with placement (fdp)` | `meta` (with a valid `mc`) under FDP. |
| `streams requires bbssd or NoSSD with FDP disabled` | `streams=on` under FDP. |
| `the key-value command set and FDP cannot share a controller: ...` | A KV namespace under FDP. |
| `namespace management does not support FDP` | `ns_mgmt=on` together with `fdp=on` on the subsystem. |
| `Device 'fdp0' not found` | The controller comes before its subsystem on the command line. |

NoSSD controllers accept an FDP subsystem and count its writes, with no
media to place on. ZNS, OCSSD and KV are refused: an FDP endurance group
holds namespaces of the NVM command set only (Base 2.3, 8.1.10). CSD goes
through the BlackBox FDP write path, with the same refusals and reclaim unit
size as BlackBox, and without its memory and compute namespaces.

When every reclaim unit is in use and GC cannot free one, a write fails with
Capacity Exceeded and QEMU prints `ssd_stream_write: device full, no RU for
ruh N`. Deallocating or overwriting data gives GC units to free again, and
writes succeed once it has.

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

## Citation

FDP support in FEMU comes from WARP, the FDP SSD emulator described in
[Characterizing and Emulating FDP SSDs with WARP](https://www.usenix.org/conference/fast26/presentation/song)
(FAST '26). If you use the FDP mode, please also cite:

```bibtex
@inproceedings{Song+26-WARP,
  author    = {Inho Song and Shoaib Asif Qazi and Javier Gonz{\'a}lez and
               Matias Bj{\o}rling and Sam H. Noh and Huaicheng Li},
  title     = {{Characterizing and Emulating FDP SSDs with WARP}},
  booktitle = {24th USENIX Conference on File and Storage Technologies (FAST 26)},
  pages     = {347--362},
  year      = {2026},
}
```

## Related pages

- [BlackBox SSD](../modes/blackbox.md)
- [Choosing a mode: which features combine](../concepts/choosing-a-mode.md#which-features-combine)
- [Architecture: features that are not modes](../concepts/architecture.md#3-mode-backends)
