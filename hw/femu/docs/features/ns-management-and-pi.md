# Namespace management, metadata and protection information

This page covers two optional NVMe features of NoSSD and
[BlackBox](../modes/blackbox.md) controllers:

- [Namespace management](#namespace-management): the guest creates,
  deletes, attaches and detaches namespaces while it runs.
- [Metadata and protection information](#metadata-and-protection-information):
  extra bytes stored with every logical block, and end-to-end protection
  information (PI) types 1 to 3 in them.

Both are off by default. Use them to test host software that manages
namespaces, or that writes and checks per-block metadata and PI, without
hardware that supports them.

## Requirements

- Host and guest: see [the mode table](../concepts/choosing-a-mode.md#every-mode-at-a-glance)
  and [requirements.md](../getting-started/requirements.md#kernel-per-mode).
- Namespace management: any guest kernel with the NVMe driver, and nvme-cli
  (`create-ns`, `attach-ns`).
- Metadata through the block layer: a guest kernel with
  `CONFIG_BLK_DEV_INTEGRITY=y`. Without it, use passthrough commands.

## Namespace management

### What it does

With `ns_mgmt=on`, the controller advertises Namespace Management and
Namespace Attachment and reports 256 as its namespace count. The namespaces
from `namespaces` and `namespace_sizes` are created at boot, and together
they define the capacity pool: the pool is the sum of their sizes, and at
boot all of it is in use (`unvmcap` is 0). To create a namespace, the guest
first deletes one, then allocates from the space it freed. A namespace the
guest creates is detached until the guest attaches it.

It takes effect only when the controller and every boot namespace run the
same mode, NoSSD or BlackBox. With another mode it is accepted and stays off.

### Launch

A BlackBox controller with two 2 GiB boot namespaces, a 4 GiB pool:

<!-- femu-example: ns-mgmt-bbssd -->
```
-device femu,devsz_mb=4096,femu_mode=1,ns_mgmt=on,namespaces=2
```

A NoSSD controller:

<!-- femu-example: ns-mgmt-nossd -->
```
-device femu,devsz_mb=4096,femu_mode=2,ns_mgmt=on,namespaces=2
```

To share namespaces between controllers, set `ns_mgmt=on` on a
`femu-subsys` and join it with `subsys=`. The subsystem comes first:

<!-- femu-example: ns-mgmt-shared -->
```
-device femu-subsys,id=shared,ns_mgmt=on -device femu,id=ctrl-a,subsys=shared,femu_mode=2,devsz_mb=64 -device femu,id=ctrl-b,subsys=shared,femu_mode=2
```

The first controller sets up the pool and the boot namespaces; later ones
join with nothing attached. [Configuration changes](../CONFIGURATION-CHANGES.md#shared-namespace-management-opt-in)
describes the shared model in full.

### Configuration

Properties: [namespace management, streams and power loss](../reference/properties.md#namespace-management-streams-and-power-loss),
[shared namespaces](../reference/properties.md#shared-namespaces).

- `ns_mgmt`: on a standalone controller, or on `femu-subsys` for shared
  namespaces. A controller with `ns_mgmt=on` cannot join a subsystem that
  does not have it.
- `bbssd_ns_limit` (BlackBox only, default 4): the most namespaces that may
  be allocated at once, detached ones included. Each BlackBox namespace has
  its own FTL with the full NAND geometry, so this bounds host memory.
- `namespaces` and `namespace_sizes`: the boot namespaces, whose sizes add
  up to the pool. Space that no boot namespace covers is not in the pool.

A shared subsystem takes NoSSD or BlackBox controllers that all have the
same mode, `meta`, `mc`, `pi`, `dpc`, `nlbaf`, `vwc` and `oncs`, and no
Streams, `dps` or `namespace_modes`.

### Use it from the guest

Check that the controller offers it, and find its controller ID:

```sh
sudo nvme id-ctrl /dev/nvme0 | grep -E '^(oacs|nn|cntlid|tnvmcap|unvmcap) '
```

`oacs` has bit 3 (0x8) set, `nn` is 256, and `unvmcap` is the free capacity
in bytes.

With the BlackBox example above, delete boot namespace 2 to free 2 GiB,
create a 1 GiB namespace of 512-byte blocks (LBA format 0) in it, attach it
to this controller, use it, then remove it:

```sh
sudo nvme delete-ns /dev/nvme0 --namespace-id=2
sudo nvme create-ns /dev/nvme0 --nsze=2097152 --ncap=2097152 --flbas=0
sudo nvme attach-ns /dev/nvme0 --namespace-id=2 --controllers=0
sudo nvme ns-rescan /dev/nvme0
sudo nvme list
sudo nvme detach-ns /dev/nvme0 --namespace-id=2 --controllers=0
sudo nvme delete-ns /dev/nvme0 --namespace-id=2
```

`create-ns` prints the new namespace ID; use it in the commands after it.
`--controllers` takes the `cntlid` from `id-ctrl`. `nsze` and `ncap` are in
logical blocks and must be equal: an `ncap` below `nsze` fails with Thin
Provisioning Not Supported, and a zero or larger one with Invalid Field. A
BlackBox namespace is rounded up to whole NAND pages.

### Limits

| Message or status | Cause and fix |
| --- | --- |
| `bbssd_ns_limit must be between 1 and 256 and cover the boot namespaces` | `namespaces` above `bbssd_ns_limit`, or the limit out of range. |
| `ns_mgmt=on does not support subsys; use a standalone controller` | `ns_mgmt=on` on a controller whose subsystem lacks it. Set it on the `femu-subsys` instead. |
| `shared namespaces require homogeneous NoSSD or bbssd without Streams or default protection` | A ZNS, KV, CSD or OCSSD controller, or Streams, `dps` or `namespace_modes`, in a shared subsystem. |
| `shared namespace mode and capabilities must match` | Controllers in one shared subsystem differ in mode or format properties. |
| `namespace management does not support FDP` | `ns_mgmt=on` and `fdp=on` on one subsystem. |
| Namespace Insufficient Capacity | The pool has no free space (delete a namespace first), or a BlackBox namespace would not leave GC its free lines. |
| Namespace Identifier Unavailable | All 256 IDs are used, or `bbssd_ns_limit` is reached. |
| Thin Provisioning Not Supported | `ncap` below `nsze`. |
| I/O Command Set Not Supported | A command set other than NVM; the guest can create only block namespaces. |

## Metadata and protection information

### What it does

`meta=<bytes>` adds that many metadata bytes to every logical block. The
controller then offers each LBA format twice: formats `0` to `nlbaf - 1`
without metadata, and formats `nlbaf` to `2 * nlbaf - 1` with it. The
namespace boots on the metadata version of `lba_index`. With the default
`nlbaf=5` and `lba_index=0`, that is format 5: 512-byte blocks with
metadata.

The metadata travels either in a separate buffer (`mc` bit 1, 0x2) or
interleaved with the data as extended LBAs (`mc` bit 0, 0x1). `extended=1`
boots on the interleaved layout.

With `pi=on` and `meta` of 8 or more, the controller also offers protection
information types 1, 2 and 3, in the first or the last 8 bytes of the
metadata. The guest selects a type with Format NVM, or with `--dps` when it
creates a namespace. The controller generates and checks PI as the command
asks (PRACT and PRCHK bits).

### Launch

8 bytes of separate metadata with PI available:

<!-- femu-example: pi-separate -->
```
-device femu,devsz_mb=1024,femu_mode=1,meta=8,mc=2,pi=on
```

8 bytes of interleaved metadata, booting on the extended layout:

<!-- femu-example: meta-extended -->
```
-device femu,devsz_mb=1024,femu_mode=1,meta=8,mc=1,extended=1
```

### Configuration

Properties: [LBA formats, metadata and protection](../reference/properties.md#lba-formats-metadata-and-protection).

- `meta`: metadata bytes per block. NoSSD and BlackBox namespaces only.
- `mc`: which layouts the controller supports, separate (0x2), interleaved
  (0x1) or both (0x3). Required with `meta`.
- `extended`: boot on the interleaved layout. Needs bit 0 of `mc`.
- `pi`: offer PI types 1 to 3. Needs `meta` of 8 or more; with less it is
  accepted and offers nothing.
- `nlbaf`: at most 8 with `meta`, since each format is offered twice.
- `dpc` and `dps` describe PI without metadata support; leave them at 0 and
  use `pi`.

### Use it from the guest

Look at the formats and the protection capabilities:

```sh
sudo nvme id-ns /dev/nvme0n1 -H | grep -E 'LBA Format|dpc|dps|mc'
```

Reformat to 512-byte blocks with 8 bytes of separate metadata and PI type 1
in the last 8 bytes (`--pil=0`), then check that the namespace changed:

```sh
sudo nvme format /dev/nvme0n1 --lbaf=5 --pi=1 --pil=0 --ms=0 --force
sudo nvme id-ns /dev/nvme0n1 | grep -E '^(flbas|dps) '
```

Write and read one block and let the controller generate and check the PI
(`--prinfo=0xf`: PRACT plus the guard, application tag and reference tag
checks; the reference tag of LBA 0 is 0):

```sh
head -c 512 /dev/urandom > blk.bin
sudo nvme write /dev/nvme0n1 -s 0 -c 0 -z 512 -d blk.bin --prinfo=0xf --ref-tag=0
sudo nvme read /dev/nvme0n1 -s 0 -c 0 -z 512 -d out.bin --prinfo=0xf --ref-tag=0
cmp blk.bin out.bin
```

With `CONFIG_BLK_DEV_INTEGRITY=y`, Linux generates and verifies PI for
ordinary block I/O on such a namespace by itself.

### Limits

| Message | Cause and fix |
| --- | --- |
| `meta/extended need a matching metadata capability (mc)` | `mc` must have bit 0 when `extended=1`, and bit 1 otherwise. |
| `meta: at most 8 block sizes (nlbaf), each is also offered with metadata` | Lower `nlbaf`. |
| `meta: namespace N runs a mode without metadata support (block or no-SSD only)` | Every namespace must be NoSSD or BlackBox. |
| `meta: not supported with placement (fdp)` | Metadata and FDP do not combine. |
| `meta: protection information (dpc, dps) is not supported` | `dpc` or `dps` with `meta`; use `pi`. |
| `dps needs 8 bytes of metadata and a matching dpc` | Use `pi=on` instead of `dps`. |
| `power_loss requires bbssd, buffer_size > 0, and no metadata, namespace management or subsystem` | `meta` or `pi` with `power_loss`. |

At run time, a Format NVM that asks for a PI type when `pi` is off, a PI
type with less than 8 bytes of metadata, or a layout `mc` does not allow
fails with Invalid Format. On a type 1 namespace, a command whose reference
tag is not the low 32 bits of its LBA fails with Invalid Protection
Information. A check against stored PI that fails returns the matching
End-to-end Guard, Application Tag or Reference Tag Check Error.

## Verify

1. Namespace management: `oacs` has bit 3 set, and a created and attached
   namespace appears in `nvme list` with the size you asked for.
2. Metadata: `nvme id-ns /dev/nvme0n1` shows a non-zero `ms` for the current
   format, and `dpc` is `0x1f` with `pi=on`.
3. PI: the write and read above succeed, and a read with `--ref-tag=1` for
   LBA 0 fails with Invalid Protection Information.

## Troubleshooting

- **`ns_mgmt=on` but `oacs` has no Namespace Management bit.** The controller
  or a boot namespace is not NoSSD or BlackBox, or the modes differ. The
  property is silently off in that case.
- **`create-ns` fails with Insufficient Capacity.** The pool is the boot
  namespaces, and they use all of it at boot. Delete a namespace first.
- **A new namespace does not appear.** It is detached after creation. Attach
  it with the controller ID from `id-ctrl`, then run `nvme ns-rescan`.
- **The namespace shows a size of 0 after formatting with metadata.** The
  guest kernel cannot use that format through the block layer, usually
  because it lacks `CONFIG_BLK_DEV_INTEGRITY` or the format interleaves the
  metadata. Use passthrough commands on `/dev/ng0n1`, or a separate-buffer
  format on a kernel with integrity support.

Related issues: #121.

## Related pages

- [Several namespaces](multi-namespace.md)
- [Configuration changes: shared namespace management](../CONFIGURATION-CHANGES.md#shared-namespace-management-opt-in)
- [Choosing a mode: which features combine](../concepts/choosing-a-mode.md#which-features-combine)
