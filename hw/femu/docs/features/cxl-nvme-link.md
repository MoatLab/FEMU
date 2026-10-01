<!--
SPDX-License-Identifier: GPL-2.0-or-later
-->

# CXL NVMe link

A BBSSD NVMe controller can serve the medium of a
[`femu-cxl-ssd`](../modes/cxl-ssd.md) as its namespace. The guest then sees
the same bytes twice: as CXL memory and as an NVMe block device. Both front
ends share one memory backend and one FTL, so one mapping table, one garbage
collector and one set of NAND counters cover both.

Use it to study software that moves data between a memory path and a block
path on one device. For most other uses, give the guest one view at a time.

## Turning it on

Add a `femu` controller with `femu_mode=1` and `cxl_ssd=<id>` after the
`femu-cxl-ssd` on the command line. With `run-cxlssd.sh`, whose device id is
`cxlssd`:

<!-- femu-example: cxl-nvme-link-launch -->
```bash
../femu-scripts/run-cxlssd.sh \
    -device femu,id=nvme0,bus=pcie.0,femu_mode=1,cxl_ssd=cxlssd \
    -drive file=$HOME/images/u20s.qcow2,if=virtio \
    -netdev user,id=net0,hostfwd=tcp::8080-:22 \
    -device virtio-net-pci,netdev=net0
```

On a full command line:

<!-- femu-example: cxl-nvme-link-cmdline -->
```bash
./qemu-system-x86_64 -machine q35,cxl=on,smm=off -accel kvm -cpu host -smp 4 -m 4G \
    -object memory-backend-ram,id=cxlmem,size=256M \
    -device pxb-cxl,id=cxl.0,bus=pcie.0,bus_nr=52 \
    -device cxl-rp,id=rp0,bus=cxl.0,chassis=0,slot=0 \
    -device femu-cxl-ssd,id=cxlssd,bus=rp0,volatile-memdev=cxlmem \
    -device femu,id=nvme0,bus=pcie.0,femu_mode=1,cxl_ssd=cxlssd \
    -M cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.size=256M
```

Give the controller a bus outside the CXL hierarchy. Without `bus=`, QEMU
picks the `pxb-cxl` bus and refuses with "Only PCI/PCIe bridges can be
plugged into pxb-cxl". `bus=pcie.0` is the simplest choice; use a
`pcie-root-port` instead if you want to unplug the controller at run time (see
[Unplugging](#unplugging)).

In the guest the namespace appears as `/dev/nvme0n1` (with the NVMe driver),
next to the CXL memdev. The namespace size is the medium's size.

## Rules at realize

Realize fails with a message naming the rule when one is broken:

| Rule | Message |
| --- | --- |
| The `femu-cxl-ssd` exists and comes first on the command line | `Device 'cxlssd' not found` |
| `cxl_ssd` names a `femu-cxl-ssd` | `Invalid parameter type for 'cxl_ssd', expected: femu-cxl-ssd` |
| The `femu-cxl-ssd` is realized and not being removed | `cxl_ssd must name a realized femu-cxl-ssd` |
| The `femu-cxl-ssd` has `ftl=on` (the default) | `cxl_ssd requires the femu-cxl-ssd to have ftl=on` |
| One controller per medium | `the femu-cxl-ssd already serves an NVMe controller` |
| `femu_mode=1` | `cxl_ssd requires femu_mode=1` |
| One namespace; no `namespace_modes` or `namespace_sizes` | `cxl_ssd requires a single bbssd namespace` |
| No `ns_mgmt` and no `subsys` | `cxl_ssd requires no namespace management or subsystem` |
| No `streams`, `power_loss`, `buffer_size` or `op_pcent` | `cxl_ssd requires no streams, power_loss, buffer_size or op_pcent` |
| No `meta`, `pi` or `dps` | `cxl_ssd requires no metadata or protection information` |
| `devsz_mb` unset, 1024 or the medium's size in MiB | `devsz_mb must be unset or N, the size of the femu-cxl-ssd` |

The medium's geometry and NAND timings apply. The controller's own
geometry and timing properties are ignored.

## What the controller offers

- Read, Write, Flush, Dataset Management (Deallocate), and the optional
  commands you enable with `oncs` (for example `oncs=0x10c` adds Write
  Zeroes and Copy). Write Zeroes is off by default, as on any FEMU
  controller.
- Format NVM is not advertised and Sanitize is refused. Both would rewrite
  the whole medium behind the CXL cache.
- SMART, vendor log page C0h and the write amplification factor report the
  shared FTL. CXL traffic does not count as NVMe host I/O.
- The timing admin command 0xEF works. Codes 1 and 2 (GC delay on and off)
  and 3 and 4 (NAND times) act on the shared FTL and so affect CXL misses
  too; code 3 restores the medium's `read-ns`, `program-ns`, `erase-ns` and
  `channel-ns`. Codes 5 to 7 affect the NVMe side only.

## Consistency between the two views

The data is consistent without any action from you:

- An NVMe read returns the most recent CXL store, whether the page is clean,
  dirty in the cache or direct-mapped.
- A CXL access after an NVMe write completes sees the NVMe data.
- Accesses that overlap in time with no synchronization in the guest have
  no defined order, as on real hardware.

What happens to the cache and the counters:

1. Write, Write Zeroes, Copy (its destination) and Deallocate drop every
   page they touch from the CXL cache before the command completes, without
   writing it back: the command already programmed or unmapped the page.
   `nvme-drops` counts these pages, and the pinned pages of rule 2.
2. A page pinned through the [caching API](cxl-cca.md) stays pinned and
   resident but becomes clean.
3. NVMe reads leave the cache alone and are charged a NAND read even when
   the page is cached.
4. CXL stores mark the blocks they cover as written, so Deallocated or
   Unwritten Logical Block errors (DULBE) and Get LBA Status see them. A
   trapped CXL load marks nothing, but with `der=memslot` or `der=cylon` any
   access that maps a page, a load or a prefetch included, marks the whole
   page, since stores through the mapping are invisible. Linking to a medium
   that was already accessed marks every block. A Deallocate does not clear pages that a
   direct ratio maps; they stay marked as written.
5. NVMe Flush does not flush the CXL cache. The medium is volatile memory.
6. A long cache operation (a flush, a `cache-ways` change, a caching API
   chunk) delays NVMe write completions until it ends. Reads do not wait.

Do not mount a filesystem on the namespace while the guest also uses the
CXL region. The filesystem would overwrite CXL-resident data, and kernel
memory when the region is onlined as system RAM. Use one view at a time
unless your workload coordinates the two.

`media-writes` on the `femu-cxl-ssd` includes NVMe writes; it is updated
before each NVMe write, Write Zeroes, Copy or Deallocate completes.

## Concurrent misses and atomicity

`concurrent-misses` on the `femu-cxl-ssd` controls whether CXL misses to
different pages wait for the media together:

| Value | Behaviour |
| --- | --- |
| `auto` (default) | Together while a direct mode (`der=memslot` or `der=cylon`) is active, one at a time otherwise |
| `on` | Always together |
| `off` | Always one at a time |

With `der=off`, a guest `lock`-prefixed read-modify-write on CXL memory
reaches the device as a separate read and write, so it is never atomic.
With misses one at a time, other vCPUs rarely get between the two (under 1%
of `lock add` increments were lost with four vCPUs in FEMU's tests). With
`concurrent-misses=on` about half were lost. Do not combine `der=off` with
`concurrent-misses=on` for anything that uses atomic operations on the
region. In the direct modes, on a page that is direct-mapped the write lands
on the page the read mapped, and none were lost either way. A `memslot`
page left on MMIO because the alias budget is full behaves as with
`der=off`.

<!-- femu-example: cxl-nvme-link-concurrent -->
```bash
DER=memslot ../femu-scripts/run-cxlssd.sh \
    -global femu-cxl-ssd.concurrent-misses=on \
    -device femu,id=nvme0,bus=pcie.0,femu_mode=1,cxl_ssd=cxlssd
```

## Unplugging

While the link exists, `device_del` of the `femu-cxl-ssd` fails with
"femu-cxl-ssd is in use by NVMe controller nvme0". Remove the controller
first, then the medium. A controller on `pcie.0` cannot be unplugged
("Bus 'pcie.0' does not support hotplugging"), so for this put it on a
root port:

<!-- femu-untested: the example check drops pcie-root-port devices, so bus=hp0 cannot resolve -->
```bash
../femu-scripts/run-cxlssd.sh \
    -device pcie-root-port,id=hp0,bus=pcie.0,chassis=5,slot=5 \
    -device femu,id=nvme0,bus=hp0,femu_mode=1,cxl_ssd=cxlssd
```

Then, over QMP, with the guest running so it can acknowledge each removal:

```text
{"execute": "device_del", "arguments": {"id": "nvme0"}}
{"execute": "device_del", "arguments": {"id": "cxlssd"}}
```

The guest can still remove the medium by powering off its root port slot,
which QEMU allows without asking. The controller then keeps working as a
plain BBSSD over the same bytes until you remove it; the CXL cache goes
away with the device. A CXL reset or disabled CXL media leaves the NVMe path
working.

## Checking it in a guest

FEMU's guest runs checked, in all three `der` modes, that data written
through devdax reads back through NVMe and the reverse, that Deallocate
reports DULBE errors and reads zeros through devdax, and that `fio` random
writes on one half of the namespace run alongside a devdax writer on the
other half with both halves verified through both paths. Long runs past the
garbage collection threshold have not been checked in a guest.

The guest needs the NVMe driver (`CONFIG_BLK_DEV_NVME`) in addition to the
CXL options in [guest requirements](../modes/cxl-ssd.md#guest-requirements).
Its `nvme-cli` reads the logs as on any BBSSD:

```sh
sudo nvme list
sudo nvme get-log /dev/nvme0 --log-id=0xc0 --log-len=512 -b | xxd | head
```

## Related pages

- [CXL SSD](../modes/cxl-ssd.md)
- [CXL caching API](cxl-cca.md)
- [CXL SSD design note](../cxlssd.md#nvme-front-end)
- [Log pages and counters](../reference/log-pages-and-counters.md)
