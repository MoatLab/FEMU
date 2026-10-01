# Tutorial 08: a CXL SSD as memory

You start a guest with `femu-cxl-ssd`, a CXL Type-3 memory device whose
capacity is backed by emulated NAND behind a DRAM page cache. You find the
device in the guest, turn it into a memory region, use the region as a DAX
device and as a NUMA node, and read the device's counters from the host
over QMP. It takes about twenty minutes.

You need: the variables from [Before you start](README.md#before-you-start),
about 3 GiB of free host memory, and `socat` on the host. The guest needs
the CXL tools (`cxl`, `daxctl`) and a kernel that can commit a CXL region
inside a virtual machine; step 4 explains what that takes.

## Background

The guest sees ordinary CXL memory. Behind it, FEMU keeps a cache of 4 KiB
pages in front of the BlackBox FTL and NAND model. A cache hit costs no
media time, a miss costs a NAND page read, and evicting a dirty page costs
a NAND program. With the default `der=off`, every guest load or store to
the device exits to QEMU, and the vCPU waits out the media time before the
access completes ([CXL SSD design](../design/cxl-ssd.md#the-media-path)).

The device needs a CXL topology: a CXL host bridge, a root port below it,
the device below the root port, and a fixed memory window on the machine.
`run-cxlssd.sh` builds all of it.

## 1. Start the guest (on the host)

`run-cxlssd.sh` adds no guest disk and no network; you pass them after the
script name. Put them on the main PCIe bus with `bus=pcie.0`: without it,
QEMU may place them on the CXL host bridge, which accepts only bridges,
and stops with `Only PCI/PCIe bridges can be plugged into pxb-cxl`. From
`build-femu/`:

<!-- femu-example: tut08-boot -->
```bash
RAM=2G ../femu-scripts/run-cxlssd.sh \
    -object memory-backend-ram,id=ram0,size=2G \
    -numa node,nodeid=0,cpus=0-3,memdev=ram0 \
    -drive file=$OSIMGF,if=none,id=hd0 \
    -device virtio-blk-pci,drive=hd0,bus=pcie.0 \
    -netdev user,id=net0,hostfwd=tcp::$SSH_PORT-:22 \
    -device virtio-net-pci,netdev=net0,bus=pcie.0 \
    -qmp unix:$PWD/qmp-cxl.sock,server=on,wait=off
```

| Part | Why |
| --- | --- |
| `RAM=2G` | the guest's RAM; the script's default is 4G |
| `-object memory-backend-ram,...` and `-numa node,...` | describe the guest RAM as NUMA node 0, so QEMU builds an ACPI SRAT and the CXL memory can become a node of its own; the backend size must equal the guest RAM |
| `-drive`, `-device virtio-blk-pci` | the guest disk |
| `-netdev`, `-device virtio-net-pci` | SSH to the guest on `SSH_PORT` |
| `-qmp unix:...` | the socket you read the counters through in step 6 |

The script's defaults give a 256 MiB device with a 3072-page (12 MiB)
direct-mapped cache, 8 channels of 8 LUNs, and `lsa-control=on`, which
lets the guest send experiment commands that write files on the host
([run-cxlssd.sh](../reference/scripts.md#launchers) lists every variable).
`DRY_RUN=1` in front prints the QEMU command instead of running it.

## 2. Install the guest tools

The image from `make-guest-image.sh --cxl` already has them. Otherwise, in
the guest (`./run-guest-ssh.sh`):

```sh
sudo apt-get install -y cxl daxctl ndctl linux-modules-extra-$(uname -r)
sudo modprobe cxl_acpi
sudo modprobe cxl_pci
```

## 3. Find the device

```sh
sudo cxl list -M
sudo cxl list -D -d root
```

```text
[
  {
    "memdev":"mem0",
    "ram_size":268435456,
    "serial":0,
    "host":"0000:35:00.0"
  }
]
[
  {
    "decoder":"decoder0.0",
    "resource":4563402752,
    "size":268435456,
    "interleave_ways":1,
    "max_available_extent":268435456,
    "pmem_capable":true,
    "volatile_capable":true,
    "accelmem_capable":true,
    "nr_targets":1
  }
]
```

`mem0` is the `femu-cxl-ssd` with 256 MiB of volatile capacity, and
`decoder0.0` is the root decoder of the fixed memory window.

## 4. Create a region

```sh
sudo cxl create-region -d decoder0.0 -t ram -w 1 -m mem0
```

With the stock Ubuntu 24.04 kernel this fails:

```text
cxl region: create_region: region0: failed to commit decode: No such device or address
cxl region: cmd_create_region: created 0 regions
```

and `dmesg` says `cxl region0: Failed to synchronize CPU cache state`.
Linux invalidates the CPU caches over the new range before it commits a
region, and a virtual machine cannot do that. A guest kernel built with
`CONFIG_CXL_REGION_INVALIDATION_TEST=y` skips the step. Check yours with:

```sh
grep -E 'CONFIG_(CXL_REGION|CXL_REGION_INVALIDATION_TEST|DEV_DAX_CXL|DEV_DAX_KMEM)=' \
    /boot/config-$(uname -r)
```

[CXL SSD guest requirements](../modes/cxl-ssd.md#guest-requirements) lists
every option the guest kernel needs. The rest of this tutorial assumes such
a kernel. Its output is illustrative: it was not captured for this page.
FEMU's own guest runs used Linux 6.12 with these options and wrote and
verified data on the region as a NUMA node.

On such a kernel the region is created and appears as a DAX device:

```sh
sudo daxctl list
```

```text
[
  {
    "chardev":"dax0.0",
    "size":268435456,
    "target_node":1,
    "align":2097152,
    "mode":"devdax"
  }
]
```

If `mode` is `system-ram`, the kmem driver claimed the region on its own;
`sudo daxctl reconfigure-device --mode=devdax --force dax0.0` gives it back.

## 5. Use the region

### As a DAX device

A program maps `/dev/dax0.0` and loads and stores directly. Offsets and
lengths must be multiples of `align` (2 MiB). This writes and reads back
one page:

```sh
sudo python3 -c '
import mmap, os
fd = os.open("/dev/dax0.0", os.O_RDWR)
m = mmap.mmap(fd, 2 << 20)
m[0:4096] = b"femu" * 1024
print(m[0:8])
'
```

Every access traps to QEMU (`der=off`), so each costs microseconds even on
a cache hit; keep test working sets small.

### As a NUMA node

```sh
sudo daxctl reconfigure-device --mode=system-ram --force dax0.0
numactl -H
numactl --membind=1 dd if=/dev/zero of=/dev/null bs=1M count=64
```

`numactl -H` shows a node 1 with memory and no CPUs: the CXL SSD. Memory a
program allocates with `--membind=1` lives on the emulated NAND behind the
cache. Expect such a program to run orders of magnitude slower than on
node 0 with `der=off`; `der=memslot` maps cached pages into the guest so
hits run at DRAM speed ([direct mapping](../modes/cxl-ssd.md#direct-mapping-der)).

## 6. Read the counters (on the host)

The counters are QOM properties of the device, whose `id` is `cxlssd`.
QEMU's `scripts/qmp/qom-get` reads one; run it from the FEMU source tree:

```sh
export QMP_SOCKET=build-femu/qmp-cxl.sock
for p in cache-pages cache-ways cache-hits cache-misses media-reads media-writes media-time-ns media-full der-active; do
    echo "$p: $(python3 scripts/qmp/qom-get /machine/peripheral/cxlssd.$p)"
done
```

On the guest of this tutorial, which could not create a region, every
access counter is still 0:

```text
cache-pages: 3072
cache-ways: 1
cache-hits: 0
cache-misses: 0
media-reads: 0
media-writes: 0
media-time-ns: 0
media-full: 0
der-active: False
```

After a workload on the region, `cache-misses`, `media-reads` and
`media-time-ns` grow, and `cache-hits` counts the accesses the cache
served. `media-full` must stay 0: a non-zero value means some accesses
found no free NAND page and completed with no media time, and the run is
not valid.

To change a setting or start from a cold cache, send raw QMP, for example
with `socat`. `flush-cache` writes dirty pages back and empties the cache;
`cache-ways` can change while the guest runs:

```sh
printf '%s\n' '{"execute":"qmp_capabilities"}' \
  '{"execute":"qom-set","arguments":{"path":"/machine/peripheral/cxlssd","property":"flush-cache","value":true}}' \
  '{"execute":"qom-set","arguments":{"path":"/machine/peripheral/cxlssd","property":"cache-ways","value":4}}' \
  '{"execute":"qom-get","arguments":{"path":"/machine/peripheral/cxlssd","property":"cache-ways"}}' |
  socat -t 2 - UNIX-CONNECT:build-femu/qmp-cxl.sock
```

```text
{"QMP": {"version": {"qemu": {"micro": 0, "minor": 1, "major": 10}, "package": ""}, "capabilities": ["oob"]}}
{"return": {}}
{"return": {}}
{"return": {}}
{"return": 4}
```

`stats-reset` (also a `qom-set` to `true`) clears the cache event counters
but not the media counters, so measure those as the difference of two
reads ([runtime properties](../reference/runtime-properties.md#femu-cxl-ssd-cxl-type-3-ssd)).

## What you learned

- `run-cxlssd.sh` builds the CXL topology; guest devices you add go on
  `bus=pcie.0`.
- The guest sees `mem0` and a root decoder; committing a region inside a
  VM needs `CONFIG_CXL_REGION_INVALIDATION_TEST`.
- The region works as a DAX device or, with an SRAT from `-numa`, as a
  CPU-less NUMA node.
- The counters are QOM properties read over QMP; `media-full` must stay 0.

## Next

- [CXL SSD](../modes/cxl-ssd.md) covers the cache options, prefetch,
  direct mapping and the control channel.
- [The CXL SSD design page](../design/cxl-ssd.md) explains the cache, the
  write-back path and direct mapping.
- [The caching API](../features/cxl-cca.md) lets the guest pin and drop
  pages itself.
