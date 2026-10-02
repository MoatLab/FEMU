# Subsystems, controllers and namespaces

This chapter describes how FEMU arranges NVMe subsystems, controllers and
namespaces: how a controller's memory backend is split between namespaces,
how each namespace runs its own mode, how Namespace Management creates and
deletes namespaces at run time, how a subsystem shares namespaces between
controllers, and where metadata and protection information are kept. For
usage, see [several namespaces](../features/multi-namespace.md) and
[namespace management, metadata and PI](../features/ns-management-and-pi.md).

## Purpose

An NVMe device is a subsystem of one or more controllers; each controller
exposes namespaces, and each namespace is a range of logical blocks with its
own command set. FEMU models this so you can:

- give one controller several namespaces, each in a different mode, such as
  a BlackBox namespace next to a ZNS namespace;
- create, delete, attach and detach namespaces from the guest;
- attach one namespace to several controllers;
- store per-block metadata and protection information.

## Place in the hierarchy

```text
 femu-subsys device id=S [ns_mgmt=on] [fdp=on]     optional; not on any bus
   |  CNTLID table (up to 256), SUBNQN, endurance group (FDP),
   |  shared storage object (ns_mgmt=on only)
   |
   +-- femu device, subsys=S       controller CNTLID 0   (PCIe endpoint)
   |      queues, pollers, one FTL thread
   |      namespace table: 256 slots, NSID = slot + 1
   |        NSID 1  mode A  -> backend bytes [0, size1)
   |        NSID 2  mode B  -> backend bytes [size1, size1 + size2)
   |        ...
   |      DRAM backend (devsz_mb)
   |
   +-- femu device, subsys=S       controller CNTLID 1
          its own namespaces and backend, unless the subsystem has ns_mgmt=on

 femu device, no subsys=          a controller without a subsystem: the same,
                                    with CNTLID 0 and no subsystem features
```

There is no namespace `-device`. Namespaces live inside the controller (or
the subsystem's storage object) and are built from controller properties.
`femu-subsys` creates an `nvme-bus`, but no FEMU device plugs into it.

## Data structures

| Structure | File | Fields that matter |
| --- | --- | --- |
| `NvmeSubsystem` | `nvme.h` | `ctrls[256]` (CNTLID slots), `subnqn`, `endgrp` (FDP), `ns_mgmt`, `storage` (the shared storage object), `ns_lock` |
| `FemuCtrl` | `nvme.h` | `namespaces` (256 slots), `num_namespaces` (boot count), `namespace_limit` (slots in use: the boot count, or 256 with Namespace Management), `namespace_pool_size`, `mbe` (DRAM backend), `attached_ns` (per-controller attachment bitmap for shared namespaces), `cntlid`, `ext_ops` (the controller's mode table) |
| `NvmeNamespace` | `nvme.h` | `id`, `size` (bytes the host sees), `extent_size` (bytes reserved in the backend), `backend_offset`, `start_block`, `femu_mode`, `csi`, `ext_ops` (this namespace's mode table), `allocated`, `attached`, `util` and `uncorrectable` bitmaps, `mdata`, the mode state (`ssd` for bbssd and CSD, `zns` for ZNS), `endgrp` and `fdp` |

## Namespace sizes and backend partitioning

Every controller has one DRAM backend of `devsz_mb` MiB, created in
`femu_realize()`. For bbssd with `op_pcent` the backend is the full NAND
capacity of the geometry instead, and the exposed capacity is that NAND
capacity divided by `1 + op_pcent / 100`, so the spare space is `op_pcent`
percent of the exposed size (`op_pcent=25` exposes 80 % of the NAND).

`nvme_resolve_ns_sizes()` then sizes the boot namespaces:

- `namespace_sizes` unset: the exposed capacity is split evenly, each share rounded
  down to 512 bytes.
- `namespace_sizes` set: one size per namespace, each at least one 512-byte
  sector; the sum must fit in the exposed capacity (`devsz_mb`, or the
  over-provisioned NAND capacity with `op_pcent`), all of it, whatever the
  namespace count.

Either way each size is then rounded down to whole logical blocks of the
format `lba_index` selects (`512 << lba_index` bytes), so no slice ends in
part of a block the host cannot address and every slice starts on a block
boundary. A KV namespace is sized in bytes and is rounded to 512 bytes only.
A size smaller than one logical block leaves an empty namespace.

`nvme_init_namespaces()` packs the slices in NSID order. Each namespace
records where its slice starts in `backend_offset`, and every data path
adds it to the byte offset of an LBA, so no namespace can reach another's
data:

```text
 devsz_mb=4096, namespaces=4, namespace_modes=nossd,,bbssd,,znssd,,kvssd

 backend  0        1 GiB      2 GiB      3 GiB      4 GiB
          +----------+----------+----------+----------+
          | NSID 1   | NSID 2   | NSID 3   | NSID 4   |
          | nossd    | bbssd    | znssd    | kvssd    |
          +----------+----------+----------+----------+
 backend_offset: 0    1 GiB      2 GiB      3 GiB

 byte of LBA x in NSID n = backend_offset(n) + x * logical block size
```

The namespace's NSZE, NCAP and NUSE start as its slice size divided by the
logical block size of its format. A zoned namespace then lowers NSZE to its
whole zones (see [ZNS](zns.md#size-capacity-and-count)); a KV namespace
measures its capacity in bytes.

The pool reported to the host is the sum of the boot slices: TNVMCAP is the
pool size and UNVMCAP the part no namespace holds. Backend space past the
last boot slice, including what the rounding above leaves, is not in the
pool and no namespace uses it.

## Per-namespace modes

`namespace_modes` gives each namespace its own mode, from the tokens
`nossd`, `bbssd`, `znssd`, `ocssd`, `csd` and `kvssd`. Unset, every
namespace runs `femu_mode`. `nvme_resolve_ns_modes()` parses the list.

```text
 femu_realize()
   nvme_init_namespaces()        sizes, slices, modes, per-namespace checks
   nvme_register_extensions()    controller ext_ops = table of femu_mode
                                 (used by the admin paths)
   for each namespace:
     nvme_register_extensions_ns()   ns->ext_ops = table of the ns's mode
     ns->ext_ops.init(n, ns)         bb_init, zns_init, kvssd_init, ...
   start one FTL thread if any namespace is bbssd, ZNS or CSD
```

At run time the mode is chosen per command, not per controller:

- I/O commands that the common path in `nvme-io.c` does not handle itself
  go to `ns->ext_ops.io_cmd` of the namespace the command names.
- The controller's single FTL thread routes each request by
  `req->ns`: ZNS namespaces to `zns_ftl_process_req()`, bbssd and CSD
  namespaces to `bb_ftl_process_req()`; NoSSD and KV cost nothing there.
- Each namespace reports its own command set (CSI 2 for ZNS, 1 for KV,
  0 otherwise). The controller always advertises NVM, Zoned and KV in its
  I/O Command Set list; only the Changed Zone List entry in the supported
  log pages depends on a zoned namespace being present.

The controller's model number and serial come from its own `femu_mode`.
Every namespace still advances its mode's serial counter as it starts, so
serials keep their values, but only a namespace of the controller's mode
names the controller. When none does (a KV controller whose KV namespace is
not namespace 1, for example), the controller is named from `femu_mode` once
its namespaces are up (`nvme_set_ctrl_name()`).

Each namespace keeps its own mode state. Every bbssd or CSD namespace has a
complete FTL with the full NAND geometry, and must fit in that geometry on
its own with room for GC. Every ZNS namespace builds its own zones from the
shared `zns_` properties and its own size. Every KV namespace has its own
key space.

| Rule | Why | Where |
| --- | --- | --- |
| `ocssd` only as the controller's own mode, and only with one namespace | Open-Channel tables are controller-wide | `nvme_init_namespaces()` |
| at most one `csd` namespace per controller | CSD keeps controller-wide state | `nvme_init_namespaces()` |
| no `kvssd` with FDP | placement takes every line, leaving the KV store none | `nvme_init_namespaces()` |
| `meta` and `streams` need every namespace to be `nossd` or `bbssd` | only the block data path carries them | `nvme_init_namespaces()` |
| one namespace with FDP | the FDP write path addresses the FTL by command LBA, not slice | `nvme_init_namespaces()` |

## Namespace management

With `ns_mgmt=on` on a controller, and when the controller and every boot
namespace run the same mode, NoSSD or bbssd, with no `dps` and no FDP
(`nvme_ns_mgmt_supported()`), the controller:

- reports NN = 256 and opens all 256 slots (`namespace_limit`);
- sets OACS bit 3 (Namespace Management) and OAES Namespace Attribute
  notices;
- reports each namespace's NVMCAP.

In any other configuration `ns_mgmt=on` adds no Namespace Management.
Realize refuses it outright with a subsystem that lacks `ns_mgmt`, and with
`power_loss` or `cxl_ssd`.

### Create, attach, detach, delete

```text
 pool = sum of boot slices          (all of it in use at boot)

   | NSID 1 (2 GiB)        | NSID 2 (2 GiB)        |     Delete NSID 2
   | NSID 1 (2 GiB)        |      free 2 GiB       |     Create 1 GiB
   | NSID 1 (2 GiB)        | NSID 2 (1 GiB) | free |     detached until Attach

 create: lowest free NSID; extent = first gap that fits (first fit)
```

Namespace Management Create (`nvme_ns_mgmt()` in `nvme-admin.c`, then
`nvme_ns_create()` in `femu.c`):

- accepts only the NVM command set, with NCAP equal to NSZE (a smaller NCAP
  fails with Thin Provisioning Not Supported), an LBA format the controller
  offers, and a PI setting only if `pi=on`;
- rounds the size up to a NAND page for bbssd (`secs_per_pg * secsz`) and to
  4 KiB for NoSSD;
- takes the lowest free NSID and the first gap in the pool that fits
  (`nvme_ns_find_extent()`); no gap fails with Namespace Insufficient
  Capacity;
- for bbssd, refuses a new namespace once `bbssd_ns_limit` namespaces are
  allocated, and refuses one that would leave its FTL no room for GC;
- zeroes the slice, builds the mode state, and leaves the namespace
  detached.

The controller pauses its pollers and FTL thread around create and delete,
so no request runs against a half-built or half-freed namespace. Attach and
detach flip `attached` (or a bit of `attached_ns` for shared namespaces)
and send Attached Namespace Attribute Changed notices to the controllers
they affect. Delete releases the slice; the gap is reused by the next
create.

## Subsystems and shared namespaces

A controller joins a subsystem with `subsys=<id>`; the subsystem must come
first on the command line. `nvme_init_subsys()` gives it the lowest free
CNTLID. What else is shared depends on the subsystem's properties:

| Subsystem | Controllers | What they share |
| --- | --- | --- |
| plain | any number | only the CNTLID space; each keeps its own namespaces and backend, and none can use Namespace Management, so the controller lists (CNS 12h, 13h) are not available |
| `fdp=on` | one | the endurance group and its FDP state ([FDP](fdp.md)) |
| `ns_mgmt=on` | any number, NoSSD or bbssd, all alike | one namespace table, backend and set of FTLs, and the SUBNQN |

A controller with `streams=on` also cannot share a subsystem.

### Shared namespaces

```text
 femu-subsys,ns_mgmt=on
   storage object (an unrealized femu, a copy of the first controller's
   properties): namespace table, DRAM backend, one FTL per bbssd namespace
       ^                      ^                       ^
       | attached_ns bitmap   | attached_ns bitmap    |
   controller A (CNTLID 0)  controller B (CNTLID 1)   ...
   own queues, pollers, FTL thread (bbssd only), namespace-change log
   all I/O decode and FTL work of every controller under subsys->ns_lock
```

- The subsystem must be realized before its controllers. The first
  controller builds the boot namespaces; `nvme_subsys_take_storage()` then
  moves them, with the backend, to a storage object that copies the first
  controller's properties. That controller starts with every boot namespace
  attached; later controllers start with none.
- Later controllers must match the first in mode, `meta`, `pi`, `mc`, `dpc`,
  `nlbaf`, `vwc` and `oncs`. Their own capacity and geometry properties do
  not create storage.
- Identify Controller reports CMIC bit 1 (multiple controllers) and the
  subsystem's NQN; each namespace reports NMIC from its creation, and a
  private namespace cannot be attached to two controllers at once.
- `subsys->ns_lock` serializes command decode on the pollers and request
  processing on the FTL threads of all controllers, so two controllers
  never run the same FTL at once.
- The namespaces and backend outlive any one controller. They are released
  when the subsystem is removed and its last controller has left.

`femu-subsys` with both `ns_mgmt=on` and `fdp=on` is refused.

## Metadata and protection information

```text
 Identify Namespace LBA formats with meta=8, nlbaf=5:
   index 0..4   512 B, 1 KiB, 2 KiB, 4 KiB, 8 KiB      no metadata
   index 5..9   the same sizes                          8 bytes metadata
   boot format = nlbaf + lba_index (5 with lba_index=0)

 where the bytes live:
   data      DRAM backend, at backend_offset + LBA * block size
   metadata  ns->mdata, a separate host buffer of (blocks * meta) bytes,
             one entry per LBA, under ns->mdata_lock
   transfer  separate buffer (MPTR, mc bit 1), or interleaved after each
             block in the data buffer (extended LBA, mc bit 0)
```

- `meta` sets the metadata bytes per block and doubles the format list.
  `nlbaf` is then at most 8.
- With `pi=on` and `meta` of 8 or more, Identify reports DPC 1Fh: PI types 1
  to 3, in the first or last 8 bytes of the metadata. The host picks a type
  with Format NVM or at Namespace Management create. FEMU generates the PI
  when PRACT is set and checks the guard (CRC-16 T10-DIF), application tag
  and reference tag as the PRCHK bits ask (`nvme-pi.c`).
- `dpc` and `dps` describe PI without these paths. A non-zero `dps` cannot
  pass the realize checks, so use `pi`.
- Metadata and PI work only on NoSSD and bbssd namespaces and not with FDP.

## Threads and locks

| Lock | Protects | Taken by |
| --- | --- | --- |
| `subsys->ns_lock` | the shared namespace table and FTLs (shared namespaces only) | pollers around command decode, FTL threads around each request |
| `ns->mdata_lock` | the metadata buffer of one namespace | every metadata read and write |
| poller pause (`nvme_pause_pollers()`) | namespace lifecycle, Format, Sanitize | admin path; pauses every controller of a shared subsystem |

## Parameters

Properties are in the property reference under
[mode, capacity and namespaces](../reference/properties.md#mode-capacity-and-namespaces),
[namespace management, streams and power loss](../reference/properties.md#namespace-management-streams-and-power-loss),
[LBA formats, metadata and protection](../reference/properties.md#lba-formats-metadata-and-protection)
and [shared namespaces](../reference/properties.md#shared-namespaces).

| Property | On | Effect and interactions |
| --- | --- | --- |
| `devsz_mb` | `femu` | Backend size, split between the boot namespaces. |
| `namespaces` | `femu` | Boot namespaces, 1 to 256. |
| `namespace_sizes` | `femu` | Per-namespace sizes; commas doubled on the QEMU command line. |
| `namespace_modes` | `femu` | Per-namespace modes; see the rules above. Refused with a shared subsystem. |
| `op_pcent` | `femu` | bbssd: backend = NAND capacity; exposed capacity = NAND capacity / (1 + op_pcent / 100). |
| `ns_mgmt` | `femu`, `femu-subsys` | Namespace Management; on the subsystem, shared namespaces. A controller with it cannot join a subsystem without it. |
| `bbssd_ns_limit` | `femu` | bbssd namespaces allocated at once, 1 to 256 and at least `namespaces`. Each has a full FTL in host memory. |
| `subsys` | `femu` | Joins a `femu-subsys`. |
| `nqn` | `femu-subsys` | SUBNQN suffix; reaches Identify only on a shared subsystem. |
| `meta`, `mc`, `extended`, `pi`, `nlbaf`, `lba_index`, `dpc`, `dps` | `femu` | Formats, metadata and PI, above. |

A NoSSD namespace and a ZNS namespace of different sizes on one controller:

<!-- femu-example: design-ns-mixed -->
```text
-device femu,devsz_mb=2048,femu_mode=2,namespaces=2,namespace_sizes=1G,,1G,namespace_modes=nossd,,znssd
```

## Statistics and outputs

| Output | Scope |
| --- | --- |
| Identify Controller TNVMCAP, UNVMCAP | the controller's namespace pool |
| Identify Namespace NSZE, NCAP, NUSE, NVMCAP | one namespace (NVMCAP with Namespace Management) |
| Namespace lists (CNS 02h, 10h), controller lists (CNS 12h, 13h) | 12h and 13h answer only with Namespace Management; 02h and 10h on any controller |
| Changed Namespace List (04h) | namespaces attached, detached, deleted or reformatted, per controller; filled only with Namespace Management |
| SMART / Health (02h) | the controller, summed over its namespaces |
| Vendor log C0h | summed over the bbssd, CSD and KV namespaces ([log pages and counters](../reference/log-pages-and-counters.md#vendor-log-page-c0h)) |

## Validation

qtest cases in `hw/femu/tests/qtest/femu-test.c`:

- layout and modes: `namespace-capacity`, `namespace-identity`,
  `namespace-mixed-identity` and its `-bbssd` and `-kv` variants,
  `namespace-sizes-rounding`, `namespace-large`, `namespace-empty-slice`,
  `namespace-kv-byte-capacity`, `kv-namespaces`, `namespace-sparse`;
- management: the `ns-mgmt-*` cases (lifecycle, capacity, `bbssd_ns_limit`,
  notices, validation, unsupported modes and FDP), `namespace-lifecycle`,
  `namespace-allocated`, `ns-retire-*`;
- shared namespaces: the `ns-shared-*` cases and `ns-mgmt-subsys`;
- metadata and PI: `metadata`, `metadata-bbssd`, `metadata-extended`, and the
  `pi-*` cases.

Every tagged documentation example with several namespaces or controllers
is also started under qtest and moves one block on namespace 1.

## Limits

- Namespace Management creates only NoSSD or bbssd namespaces of the
  controller's own mode, and only on controllers whose namespaces all run
  that mode. It does not create zoned, KV, CSD or Open-Channel namespaces.
- Each bbssd namespace has a full-size FTL; there is no scaled geometry for
  small namespaces, which is why `bbssd_ns_limit` exists.
- Allocated Namespace Attribute notices are not advertised.
- Shared namespaces need homogeneous NoSSD or bbssd controllers without
  Streams, `dps` or `namespace_modes`.
- All namespaces and metadata live in host memory and are lost when QEMU
  exits.

## How to extend it

- A new mode token: add it to `nvme_mode_from_token()`, register its table in
  `nvme_register_extensions()`, add any per-namespace restriction to
  `nvme_init_namespaces()`, and keep `hw/femu/docs/modes.py` in step.
- A mode that keeps controller-wide state must refuse a second namespace of
  that mode, as CSD does, or move the state into the namespace.
- Namespace Management for another mode: `nvme_ns_mgmt_supported()`,
  `nvme_ns_create()` and the capacity checks in `nvme_ns_mgmt()` are the
  places that limit it to NoSSD and bbssd.
- Any new data path must add `ns->backend_offset` to its byte offsets.

## Source map

| File | What is there |
| --- | --- |
| `hw/femu/femu.c` | `femu-subsys` device, CNTLID registration, namespace sizing, packing and per-namespace mode setup (`nvme_init_namespaces()`), `nvme_ns_create()`, extent search, shared storage (`nvme_subsys_take_storage()`), capacity reporting |
| `hw/femu/nvme.h` | `NvmeSubsystem`, `NvmeNamespace`, `nvme_ns()` and attachment helpers |
| `hw/femu/nvme-admin.c` | Namespace Management and Attachment, Identify lists, Format NVM |
| `hw/femu/nvme-io.c` | per-namespace dispatch, backend offsets, metadata transfer |
| `hw/femu/nvme-pi.c`, `hw/femu/nvme-pi.h` | protection information generation and checks |

## Related pages

- [Several namespaces and devices](../features/multi-namespace.md)
- [Namespace management, metadata and PI](../features/ns-management-and-pi.md)
- [ZNS](zns.md) and [FDP](fdp.md)
- [Architecture](../concepts/architecture.md)
