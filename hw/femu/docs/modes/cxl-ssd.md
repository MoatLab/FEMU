<!--
SPDX-License-Identifier: GPL-2.0-or-later
-->

# CXL SSD

`femu-cxl-ssd` is a CXL Type-3 memory device whose capacity is backed by
emulated NAND flash. The guest sees ordinary CXL memory: it creates a region,
then uses it as a DAX device or onlines it as system RAM on its own NUMA node.
Behind the memory interface, FEMU keeps a DRAM page cache in front of the same
BBSSD FTL and NAND timing model that `femu_mode=1` uses. A cache hit costs no
media time; a miss costs a NAND read, and evicting a dirty page costs a NAND
program.

This page shows how to run it. The [design note](../cxlssd.md) explains how it
works inside, and the [property reference](../reference/properties.md#femu-cxl-ssd-cxl-type-3-ssd)
lists every property. The device comes from Cylon (FAST '26); if you use it,
cite Cylon as well as FEMU ([citation](#citation)).

Related pages:

- [CXL caching API](../features/cxl-cca.md): let the guest pin, drop and
  uncache pages through BAR5.
- [CXL NVMe link](../features/cxl-nvme-link.md): serve the same medium as an
  NVMe namespace too.

## What it emulates

| Part | What FEMU does |
| --- | --- |
| Interface | A CXL Type-3 volatile memory device, a subclass of QEMU's `cxl-type3`. The guest CXL driver enumerates it as a memdev (`mem0`). |
| Capacity | The memory backend named by `volatile-memdev`: 256 MiB to 120 GiB, in steps of 256 MiB. The data lives there. |
| Cache | `cache-pages` pages of 4 KiB (default 1024, so 4 MiB), `cache-ways` ways per set, policy `fifo`, `lifo`, `clock` or `s3-fifo`. |
| Media | The BBSSD FTL: page mapping, garbage collection, NAND read, program and erase times, channels and LUNs. |
| Direct mapping | Optional (`der`). Cached pages are mapped into the guest so hits run at DRAM speed with no exit to QEMU. |
| Persistence | None. It is volatile memory. Data is lost when QEMU exits. |
| Migration | Not supported. `migrate` fails with "State blocked by non-migratable device '...'". |

Every guest access that is not direct-mapped is an MMIO exit to QEMU. The
vCPU that made the access waits out the modelled media time before the load
or store completes. The [timing model](../concepts/timing-model.md#cxl-ssd)
lists what each kind of access costs.

## Host requirements

- An x86-64 Linux host with KVM. QEMU must be built for `x86_64-softmmu`;
  `femu-cxl-ssd` is built by default (see [build](../getting-started/build.md)).
- Host RAM for the media size, the guest RAM, and the FTL mapping tables.
- Hugepages are optional for `der=off` and `der=memslot`. `der=cylon` needs a
  shared, preallocated hugetlbfs backend (see [`der=cylon`](#dercylon)).
- `der=cylon` also needs a modified host kernel. The other modes run on a
  stock kernel.

To reserve 2 MiB hugepages for a 256 MiB device, for example:

```sh
echo 128 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
grep HugePages_Free /proc/meminfo
mount | grep hugetlbfs          # usually /dev/hugepages
```

Give the pages back with `echo 0 | sudo tee ...` after QEMU exits.

## Guest requirements

The guest kernel needs the CXL stack with region support and the DAX drivers:

| Option | Why |
| --- | --- |
| `CONFIG_CXL_BUS`, `CXL_PCI`, `CXL_ACPI`, `CXL_MEM`, `CXL_PORT` | Enumerate the host bridge, root port and memdev |
| `CONFIG_CXL_REGION` | Create a region over the device |
| `CONFIG_CXL_REGION_INVALIDATION_TEST` | Needed inside a VM. A guest cannot invalidate CPU caches by address range, and without this option Linux refuses to commit the region. The option skips that step |
| `CONFIG_DEV_DAX`, `CONFIG_DEV_DAX_CXL` | Expose the region as `/dev/daxX.Y` |
| `CONFIG_DEV_DAX_KMEM` | Online the region as system RAM. kmem may claim a new RAM region on its own; `daxctl reconfigure-device` switches it back |
| `CONFIG_MEMORY_HOTPLUG`, `CONFIG_MEMORY_HOTREMOVE`, `CONFIG_ZONE_DEVICE` | Memory hotplug support that kmem and DAX need |
| `CONFIG_FS_DAX` | Not needed for RAM regions; the validated guests had it on |

The guest runs validated in FEMU's own testing used Linux 6.12 with these
options. Check a guest kernel's configuration with:

```sh
grep -E 'CONFIG_(CXL_REGION|CXL_REGION_INVALIDATION_TEST|DEV_DAX|DEV_DAX_CXL|DEV_DAX_KMEM|FS_DAX)=' \
    /boot/config-$(uname -r)
```

Guest tools: `cxl` (cxl-cli), `daxctl` and `ndctl`. They come from the ndctl
project; `./make-guest-image.sh --cxl` installs them (see
[guest image](../getting-started/guest-image.md)). `numactl` helps when you
use the region as system RAM.

## Launching

### With `run-cxlssd.sh`

`hw/femu/scripts/run-cxlssd.sh` builds a command line with one `pxb-cxl` host
bridge, one `cxl-rp` root port, the `femu-cxl-ssd` and a single-target CXL
window. Settings come from environment variables; arguments after the script
name go to QEMU unchanged. It does not add a guest disk or network, so pass
them yourself. From `build-femu/`:

<!-- femu-example: cxl-ssd-launch -->
```bash
../femu-scripts/run-cxlssd.sh \
    -drive file=$HOME/images/u20s.qcow2,if=none,id=hd0 \
    -device virtio-blk-pci,drive=hd0,bus=pcie.0 \
    -netdev user,id=net0,hostfwd=tcp::8080-:22 \
    -device virtio-net-pci,netdev=net0,bus=pcie.0
```

The script looks for QEMU at `./qemu-system-x86_64`; set `QEMU` to use another
binary. `DRY_RUN=1` prints the command instead of running it. It never runs
`sudo` and changes no host settings.

Its defaults follow the published Cylon experiments and differ from the
device's own defaults:

| Variable | Script default | Device default | Property |
| --- | --- | --- | --- |
| `CXL_SIZE` | `256M` | (required) | backend size, `M` or `G` suffix |
| `CACHE_PAGES` | size in MiB / 20 * 256 (a cache of 1/20 of the media) | 1024 | `cache-pages` |
| `CACHE_WAYS` | 1 (direct mapped); `full` means `CACHE_PAGES` | 16 | `cache-ways` |
| `CACHE_POLICY` | `fifo` | `fifo` | `cache-policy` |
| `CHANNELS`, `LUNS_PER_CHANNEL` | 8, 8 | 4, 4 | `channels`, `luns-per-channel` |
| `LSA_CONTROL` | `on` | `off` | `lsa-control` |
| `BLOCKS_PER_PLANE` | 768 for `48G`, 1536 for `96G`, else 0 | 0 | `blocks-per-plane` |

The other variables (`DER`, `CYLON_KERNEL_ACK`, `PREFETCH_DEGREE`,
`PREFETCH_STRIDE`, `PAGES_PER_BLOCK`, `READ_NS`, `PROGRAM_NS`, `ERASE_NS`,
`CHANNEL_NS`, `GC_THRESHOLD`, `GC_THRESHOLD_HIGH`, `FTL`,
`CYLON_FIRST_TOUCH_PROGRAM`, `CYLON_FREE_WRITEBACK`, `LOG_DIR`, `LOG_LIMIT`,
`TRACEFS_DIR`, `CXL_BACKEND`, `ACCEL`, `CPU`, `CPUS`, `RAM`) keep the
device defaults; the comment at the top of the script lists them all. The
`48G` and `96G` presets leave no spare NAND blocks, as in Cylon. Without
spare blocks the NAND fills up and accesses complete uncached (see
[Counters](#counters), `media-full`).

A property the script has no variable for can be set with `-global`, which
applies to every `femu-cxl-ssd`:

<!-- femu-example: cxl-ssd-global -->
```bash
../femu-scripts/run-cxlssd.sh -global femu-cxl-ssd.concurrent-misses=on
```

### The equivalent command line

This is equivalent to the script with its defaults. The script also passes
the remaining properties at their default values:

<!-- femu-example: cxl-ssd-cmdline -->
```bash
./qemu-system-x86_64 -machine q35,cxl=on,smm=off -accel kvm \
    -cpu host -smp 4 -m 4G \
    -object memory-backend-ram,id=cxlmem,size=256M \
    -device pxb-cxl,id=cxl.0,bus=pcie.0,bus_nr=52 \
    -device cxl-rp,id=cxl-rp0,bus=cxl.0,chassis=0,slot=0 \
    -device femu-cxl-ssd,id=cxlssd,bus=cxl-rp0,volatile-memdev=cxlmem,cache-pages=3072,cache-ways=1,cache-policy=fifo,der=off,channels=8,luns-per-channel=8,lsa-control=on \
    -M cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.size=256M \
    -drive file=$HOME/images/u20s.qcow2,if=none,id=hd0 \
    -device virtio-blk-pci,drive=hd0,bus=pcie.0 \
    -netdev user,id=net0,hostfwd=tcp::8080-:22 \
    -device virtio-net-pci,netdev=net0,bus=pcie.0 \
    -nographic
```

The pieces:

- `-machine q35,cxl=on` turns on CXL support in the machine.
- `pxb-cxl` is a CXL host bridge, `cxl-rp` a root port below it, and the
  `femu-cxl-ssd` sits below the root port.
- `cxl-fmw.0` is the fixed memory window, the host physical address range
  where the guest maps the region. Its size must be at least the media size.
- `volatile-memdev` names the backend that holds the data.
- `smm=off` is required by `der=cylon` and harmless otherwise.

To give the guest its own kernel, add
`-kernel bzImage -append "root=/dev/vda1 console=ttyS0"` with the root
partition of your image.

## Creating the region in the guest

Log in (`ssh -i ~/images/femu-guest-key -p 8080 femu@localhost` with the
image from `make-guest-image.sh`) and work as root. Find the memdev and the root
decoder:

```sh
cxl list -M          # the memdev, normally mem0, with its ram_size
cxl list -D -d root  # the root decoder, normally decoder0.0
```

Create a RAM region over the whole device:

```sh
cxl create-region -d decoder0.0 -t ram -w 1 -m mem0
daxctl list
```

`daxctl list` shows one device, for example `dax0.0`. If kmem already
claimed it as system RAM (`daxctl list` shows `"mode":"system-ram"`),
switch it back with `daxctl reconfigure-device --mode=devdax --force dax0.0`.
If `cxl create-region` fails and `dmesg` reports that the CPU cache could
not be synchronized, the kernel lacks `CONFIG_CXL_REGION_INVALIDATION_TEST`.

### As a DAX device

In devdax mode, programs `mmap()` `/dev/dax0.0` and load and store directly.
Mapping offsets and lengths must be multiples of the device's alignment, which
`daxctl list` shows as `align` (normally 2 MiB). Every access reaches the device; nothing in
the guest page cache sits in front of it. The [caching API](../features/cxl-cca.md)
tools expect this mode.

### As system RAM on a NUMA node

`daxctl` hands the region to the kmem driver, which onlines it as memory:

```sh
daxctl reconfigure-device --mode=system-ram --force dax0.0
numactl -H                     # a new node with memory and no CPUs
numactl --membind=1 ./my-workload
```

The region becomes its own NUMA node only when the guest has an ACPI SRAT,
which QEMU generates when the guest RAM is described with `-numa`. Without
it the guest has no NUMA information and the new memory gets no node of its
own. Pass the guest RAM as a NUMA node; the memory
backend size must equal `-m` (4G with the script's default `RAM`):

<!-- femu-example: cxl-ssd-numa -->
```bash
../femu-scripts/run-cxlssd.sh \
    -object memory-backend-ram,id=ram0,size=4G \
    -numa node,nodeid=0,cpus=0-3,memdev=ram0 \
    -drive file=$HOME/images/u20s.qcow2,if=none,id=hd0 \
    -device virtio-blk-pci,drive=hd0,bus=pcie.0 \
    -netdev user,id=net0,hostfwd=tcp::8080-:22 \
    -device virtio-net-pci,netdev=net0,bus=pcie.0
```

With this the CXL window becomes node 1. FEMU's guest runs wrote and verified
data on node 1 in all three `der` modes; long workloads on it have not been
checked. With `der=off` each access to the
node exits to QEMU, so expect a workload there to run orders of magnitude
slower than on node 0; use `der=memslot` or `der=cylon` to serve cache hits
at memory speed.

## Cache

| Property | Default | Meaning |
| --- | --- | --- |
| `cache-pages` | 1024 | Pages of 4 KiB the cache holds. 0 disables the cache: every read is a NAND read and every write a NAND program. At most the media page count, and divisible by `cache-ways` |
| `cache-ways` | 16 | Entries per set. 1 is direct mapped; equal to `cache-pages` is fully associative |
| `cache-policy` | `fifo` | Replacement within a set: `fifo` drops the oldest entry, `lifo` the newest, `clock` the first without a recent reference, `s3-fifo` uses small, main and ghost queues |

What an access costs:

- A hit costs no media time.
- A read miss reads the page from NAND and inserts it. A page the FTL has
  never mapped costs no media time, though it still counts in `media-reads`; its contents come from the
  backend, which reads as zeros for a fresh `memory-backend-ram`.
- A write miss reads the page as a read miss does, then the write makes it
  dirty.
- Evicting a dirty page programs it to NAND, and the access that caused the
  eviction pays for it. A clean eviction is free.

`cache-ways`, `prefetch-degree` and `prefetch-stride` can be changed while
the guest runs with `qom-set`. Changing `cache-ways` writes back dirty pages
and rebuilds the cache. `flush-cache` writes back every dirty page and drops
the cache, waiting for the modelled media time; it is how you start a
measurement from a cold cache:

```text
{"execute": "qom-set", "arguments": {"path": "/machine/peripheral/cxlssd", "property": "flush-cache", "value": true}}
{"execute": "qom-set", "arguments": {"path": "/machine/peripheral/cxlssd", "property": "cache-ways", "value": 4}}
```

The path ends with the `id=` of the device; `run-cxlssd.sh` uses `cxlssd`.

### Fast load

`fast-load=true` speeds up warmup and data loading phases that are not
measured. While it is on, an access does not wait for its modelled media
time. Everything else still runs: the FTL request, cache inserts and
evictions, prefetch, direct mapping and every counter. The NAND timelines
still advance, so the skipped time builds up as a backlog on the LUNs.

`fast-load=false` is a barrier. It waits for the accesses in progress, then
waits until the modelled NAND is idle, and only then returns. It does not
flush the cache. `fast-load-drain-ns` gives the time that this wait took.
After it returns, accesses pay the full media time again.

```text
{"execute": "qom-set", "arguments": {"path": "/machine/peripheral/cxlssd", "property": "fast-load", "value": true}}
{"execute": "qom-set", "arguments": {"path": "/machine/peripheral/cxlssd", "property": "fast-load", "value": false}}
{"execute": "qom-get", "arguments": {"path": "/machine/peripheral/cxlssd", "property": "fast-load-drain-ns"}}
```

The contract is narrow:

- Only the wait at the end of an access is skipped. Flush, `cache-ways`
  changes, caching API commands and a linked NVMe controller keep their
  timing.
- A serial access sequence gives the same cache and media counters with
  `fast-load` on or off. `media-time-ns` can differ, because accesses that
  arrive sooner queue behind each other on a LUN.
- With concurrent accesses, the final state is not guaranteed to be the
  same. Shorter page holds change which evictions succeed, and a guest that
  runs faster can issue its accesses in a different order.
- Use it for warmup and loading only. Compare measured phases against a
  normal run if the starting state matters.

### Prefetch

On a miss, after inserting the missed page, the device inserts up to
`prefetch-degree` more pages starting `prefetch-stride` pages after it: the
pages `[page + stride, page + stride + degree)`. Pages already cached or past
the end of the media are skipped. Prefetched pages are inserted with no NAND
read and no media time; a dirty page they evict is still programmed. The
degree is capped at `cache-pages`. The default degree is 0, which turns
prefetch off.

<!-- femu-example: cxl-ssd-cache -->
```bash
CACHE_PAGES=4096 CACHE_WAYS=16 CACHE_POLICY=s3-fifo PREFETCH_DEGREE=4 \
    ../femu-scripts/run-cxlssd.sh
```

### NAND geometry and timing

| Property | Default | Meaning |
| --- | --- | --- |
| `channels` | 4 | NAND channels, 1 to 4096 |
| `luns-per-channel` | 4 | LUNs per channel, 1 to 128, one plane each |
| `pages-per-block` | 256 | 4 KiB pages per block |
| `blocks-per-plane` | 0 | 0 sizes the NAND to 5/4 of the media plus 4 blocks per plane, which leaves room for garbage collection |
| `read-ns`, `program-ns`, `erase-ns` | 40000, 200000, 2000000 | Page read, page program and block erase times, at most one second |
| `channel-ns` | 0 | Channel transfer time per page |
| `gc-threshold`, `gc-threshold-high` | 75, 95 | Percent of lines in use at which garbage collection starts and is forced |
| `ftl` | `on` | `off` charges no media time at all; the device behaves as plain memory with a cache in front |

Sectors are 512 bytes, eight per 4 KiB page. Misses on different LUNs
overlap in the NAND model. Two switches reproduce the media model of the
published Cylon experiments and are off by default:
`cylon-first-touch-program=on` charges a program instead of a free read the
first time an unmapped page is read, and `cylon-free-writeback=on` makes
dirty write-backs free.

<!-- femu-example: cxl-ssd-nand -->
```bash
CXL_SIZE=1G CHANNELS=8 LUNS_PER_CHANNEL=4 READ_NS=50000 PROGRAM_NS=500000 \
    ../femu-scripts/run-cxlssd.sh
```

## Direct mapping: `der`

With `der=off` every load and store traps to QEMU, even a cache hit. That
gives exact counts and exact timing, but a hit costs microseconds. The other
two modes map cached pages straight into the guest, so hits run at DRAM speed
without an exit.

| Mode | How hits are served | Needs | Limits |
| --- | --- | --- | --- |
| `off` (default) | Every access traps to QEMU | Nothing | Slow hits; every hit is counted and timed |
| `memslot` | Cached pages become KVM memory slot aliases | KVM. Refused under TCG | At most 1024 mapped pages (4 MiB) across all devices |
| `cylon` | Cached pages are written into KVM's page tables by a Cylon host kernel | The fixed Cylon host kernel, a hugetlb backend, `cylon-kernel-ack=on` | Only on that kernel; falls back to MMIO elsewhere |

As a reference point, one host (Xeon Gold 6548Y+, 256 MiB device, 1024-page
cache) measured a median cached load of about 3.0 us with `off` and 105 ns
with `memslot` and with `cylon`.

What changes in the direct modes:

- A direct hit never reaches QEMU, so it is not counted in `cache-hits`,
  does not update the `clock` or `s3-fifo` reference state, and has no media
  time.
- Direct mapping works only in the topology `run-cxlssd.sh` builds: one
  endpoint directly below the only root port of a host bridge, in a window
  with one target, not interleaved. Elsewhere the device still works, all
  accesses use MMIO, and `der-fallbacks` counts the refused mappings.
- Mappings are revoked before an eviction, a flush, a PCI configuration or
  decoder change, a CXL mailbox command (except a control Get LSA, below), a
  reset and unplug. The page maps
  again on its next access.
- `der-ratio` maps a fixed fraction of all pages, whether cached or not, to
  reproduce Cylon's direct ratio experiments. See the design note.

### `der=memslot`

<!-- femu-example: cxl-ssd-memslot -->
```bash
DER=memslot ../femu-scripts/run-cxlssd.sh
```

Each mapped page is a one-page alias in the guest address space. All
`femu-cxl-ssd` devices share a budget of 1024 aliases (4 MiB), fewer when KVM
runs short of free memory slots. A cached page that finds the budget full is
served by MMIO at `der=off` cost and counts in `der-fallbacks`. When the hot
set moves, a cached page that takes 256 trapped hits while the budget is full
replaces this device's oldest alias that does not hold a pinned page, at most
`der-replace-rate` times per second (default 64; 0 disables replacement).
Every mapped page is treated as dirty, because writes through an alias are
invisible to QEMU, so its eviction costs a program.

Realize refuses `der=memslot` under TCG ("der=memslot is not supported with
TCG; use KVM, or der=off"): the alias changes would race with other vCPUs'
TLBs. Use `memslot` for hot sets of up to 4 MiB on a stock kernel.

### `der=cylon`

`cylon` writes direct entries into KVM's EPT page tables through two ioctls
of the Cylon host kernel. It has no per-page alias cost, samples EPT dirty
bits so clean pages are not programmed on eviction, and suits hot sets and
caches larger than 4 MiB.

It needs all of these on the host; FEMU checks the ones it can:

- A Cylon kernel with the dual-slot fixes on MoatLab/Cylon `master`. The
  published CylonLinux 6.4.6 corrupts host memory with this interface. FEMU
  cannot tell the two apart, so realize fails unless you set
  `cylon-kernel-ack=on` to state that the fixed kernel is running.
- For workloads that use vector instructions (most programs, through glibc),
  a Cylon kernel from MoatLab/Cylon `master` at 8c13c5cf2 or later, which adds
  `KVM_CAP_CYLON_FAULT_EXIT`. An older kernel loops forever, or crashes the
  host, when such an instruction touches an uncached page; FEMU warns at slot
  install when the capability is missing.
- KVM on Intel with EPT, EPT A/D bits, the TDP MMU and MMIO caching enabled,
  4 KiB host base pages and no dirty ring.
- A hugetlbfs memory backend with `share=on` and `prealloc=on`. The device
  locks it with `mlock()` and reads `/proc/self/pagemap`, so run QEMU as
  root.
- `-machine smm=off` and the same CPU model on every vCPU (`run-cxlssd.sh`
  does both).

<!-- femu-untested: needs a Cylon host kernel and reserved hugepages -->
```bash
sudo DER=cylon CYLON_KERNEL_ACK=on \
    CXL_BACKEND=memory-backend-file,mem-path=/dev/hugepages,share=on,prealloc=on \
    ../femu-scripts/run-cxlssd.sh
```

When a check fails the device prints one warning naming the first missing
requirement, keeps working on MMIO as with `der=off`, and `der-active` reads
false. On a stock kernel:

<!-- femu-example: cxl-ssd-cylon-fallback; allow-warning: FEMU CXL DER unavailable -->
```bash
DER=cylon CYLON_KERNEL_ACK=on ../femu-scripts/run-cxlssd.sh
```

<!-- femu-untested: output of the example above, not a command -->
```text
qemu-system-x86_64: -device femu-cxl-ssd,...: warning: FEMU CXL DER unavailable: Cylon GET_LINEAR_SPT/SET_SPTE_FLAG require a Cylon KVM host; using MMIO
```

While a `cylon` VM runs, do not migrate, offline or soft-offline the hugetlb
pages, and do not run idle page tracking (`/sys/kernel/mm/page_idle`) or
DAMON on the QEMU process. The design note's
[host and guest restrictions](../cxlssd.md#host-and-guest-restrictions)
explain why.

### Concurrent misses

`concurrent-misses` decides whether misses to different pages wait for the
media together or one at a time. `auto` (default) overlaps them only while a
direct mode is active; `on` and `off` force it. With `der=off`, a guest's
`lock`-prefixed read-modify-write reaches the device as a separate read and
write and is never atomic. Overlapping misses make lost updates common
(about half of `lock add` increments with four vCPUs in FEMU's tests); one
miss at a time keeps them rare but not absent. Do not rely on atomic
operations to `der=off` memory, and keep `concurrent-misses` at `auto` or
`off` there.

## Control channel through the label area

`lsa-control=on` lets the guest send experiment commands with the CXL
Get LSA mailbox command, in the form Cylon's scripts use: the read size is
the command and the read offset its argument.

```sh
cxl read-labels mem0 -s 1 -O 42 -o /tmp/status.bin   # command 1, argument 42
od -An -tu1 -N1 /tmp/status.bin                     # 0 ok, 1 error, 2 queued
```

| Command | Argument and effect |
| --- | --- |
| 1 | Append a statistics snapshot tagged with the argument to `cxlssd-stats.log`, then reset the event counters as `stats-reset` does |
| 2 | Write dirty pages back and drop unpinned pages, as `flush-cache` |
| 3 | Set the ways: 0 to 4 mean 1, 2, 4, 8, 16 ways; 5 means fully associative |
| 5 | Set `prefetch-degree` |
| 7 | Set `prefetch-stride` |
| 9, 11 | Flush and clear the cache, as 2 |
| 13 | Open the next per-access log, `cxlssd-io-N.log` (64 names, reused in turn) |
| 15 | Close the per-access log |
| 17 | Dump the current direct mappings to `cxlssd-spt.log` |
| 90, 80 | Set a direct ratio / remove it. The ratio is one of 50, 75, 90, 95, 97, 98, 99, 995 (99.5%), 999 (99.9%) or 100 percent, and 0 means 100. Setting one needs `der=memslot` or `der=cylon`; `memslot` refuses a ratio needing more aliases than are free, which on a 256 MiB device leaves 99 and up |
| 91, 81 | Empty the host trace buffer and start tracing / stop tracing, in `tracefs-dir` |

Byte zero of the data returned is the status: 0 success, 1 error, 2 queued.
Commands 1, 5, 7, 13, 15, 17, 80, 81, 90 and 91 run at once unless the device
is busy, and report 0 or 1. Flushes and way changes (2, 3, 9, 11), unknown
commands and anything that finds the device busy are queued and run after
the read returns, from QEMU's main loop; their byte zero is 2, and an error
shows only in `control-status` over QMP, which reads 2 until the queue
drains and then 0 or 1 for the last command. A read larger than the mailbox
payload also returns 1. Commands 2, 3, 9 and 11 also clear the cache event counters.

`lsa-control` is off by default on the device and on in `run-cxlssd.sh`. With
it on, the device serves a 128 MiB internal label area and refuses an `lsa`
backend. Turn it off for guests you do not trust: commands 1, 13 and 17 let
the guest create and write files on the host in `log-dir` (the working
directory by default), and commands 91 and 81 let it write the host's
`tracing_on` and `trace` files when `tracefs-dir` is set. Each file is
capped at `log-limit` (64 MiB by default), statistics appends are rate
limited, and `log-dropped` counts what was refused.

<!-- femu-example: cxl-ssd-no-lsa -->
```bash
LSA_CONTROL=off LOG_DIR=/tmp/cxl-logs ../femu-scripts/run-cxlssd.sh
```

The same commands are available from the host whatever `lsa-control` says:
set `control-argument`, then `control-command`, with `qom-set`. The command
runs before `qom-set` returns, and an invalid argument is reported as a QMP
error.

## Counters

The device's counters are QOM properties. Start QEMU with a QMP socket by
adding `-qmp unix:/tmp/qmp.sock,server=on,wait=off` after the script name,
then read them with QEMU's `scripts/qmp/qom-get`, from the QEMU source tree:

```sh
export QMP_SOCKET=/tmp/qmp.sock
scripts/qmp/qom-get /machine/peripheral/cxlssd.cache-misses
scripts/qmp/qom-get /machine/peripheral/cxlssd.media-time-ns
```

or send raw QMP, for example with `socat - UNIX-CONNECT:/tmp/qmp.sock`:

```text
{"execute": "qmp_capabilities"}
{"execute": "qom-get", "arguments": {"path": "/machine/peripheral/cxlssd", "property": "media-reads"}}
```

The ones you need most:

| Counter | Meaning |
| --- | --- |
| `cache-hits`, `cache-misses`, `read-hits`, `read-misses`, `write-hits`, `write-misses` | Trapped lookups; direct hits are not counted |
| `cache-entries`, `cache-evictions`, `prefetch-inserts` | Cache occupancy and churn |
| `media-reads`, `media-writes`, `media-time-ns` | NAND page reads, page programs and total modelled media time |
| `media-full` | Accesses whose NAND program found no free page. That program is not timed and the access completes uncached; a fill read already issued is still charged. A measurement is valid only while it is 0 |
| `der-active`, `der-mapped`, `der-fallbacks` | Whether direct mapping is on, how many pages are mapped now, and refused mappings |

`qom-set ... stats-reset true` copies the counters to the `last-*` properties
and clears the cache, prefetch and caching API event counters. The media
counters, `media-full` and the `der-*` counters are never cleared; measure
them as differences between two reads. The full list is in
[runtime properties](../reference/runtime-properties.md#femu-cxl-ssd-cxl-type-3-ssd).

## Limits

- No live migration and no snapshots of device state.
- Volatile only: no persistent memory or dynamic capacity (`memdev`,
  `persistent-memdev`, `volatile-dc-memdev` and `num-dc-regions` are
  refused). An `lsa` label backend works only with `lsa-control=off`.
- Direct mapping needs the single-endpoint topology above.
- With `der=off`, every access costs an exit to QEMU; large workloads take
  hours. Use a small device and cache when you only need correct behaviour.

## Citation

`femu-cxl-ssd` comes from Cylon, described in
[Cylon: Fast and Accurate Full-System Emulation of CXL-SSDs](https://www.usenix.org/conference/fast26/presentation/yoon)
(FAST '26). If you use the CXL SSD mode, please also cite:

```bibtex
@inproceedings{Yoon+26-Cylon,
  author    = {Dongha Yoon and Hansen Idden and Jinshu Liu and Berkay Inceisci and
               Sam H. Noh and Huaicheng Li},
  title     = {{Cylon: Fast and Accurate Full-System Emulation of CXL-SSDs}},
  booktitle = {24th USENIX Conference on File and Storage Technologies (FAST 26)},
  pages     = {313--327},
  year      = {2026},
}
```

## Related pages

- [CXL SSD design note](../cxlssd.md)
- [CXL caching API](../features/cxl-cca.md)
- [CXL NVMe link](../features/cxl-nvme-link.md)
- [Timing model](../concepts/timing-model.md#cxl-ssd)
- [Device properties](../reference/properties.md#femu-cxl-ssd-cxl-type-3-ssd)
