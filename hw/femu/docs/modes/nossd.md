# NoSSD

NoSSD mode (`femu_mode=2`, the default) emulates an NVMe drive with no media
model. Reads and writes copy data between guest memory and a host DRAM
buffer and complete as soon as the poller finishes the copy. There is no
FTL, no GC and no NAND time.

Use it when the storage device should not be the bottleneck: work on the
host I/O stack, the NVMe driver, polling, SPDK or io_uring, or as an upper
bound to compare a timed mode against. For a device with SSD latency and
garbage collection, use [BlackBox](blackbox.md).

## Requirements

- Host and guest: see [the mode table](../concepts/choosing-a-mode.md#every-mode-at-a-glance)
  and [requirements.md](../getting-started/requirements.md#kernel-per-mode).
  Any guest kernel with the NVMe driver works.
- Host memory: `devsz_mb` plus guest RAM plus about 1 GiB for QEMU, about
  9 GiB for `run-nossd.sh` (a 4 GiB device and a 4 GiB guest).
- Host cores: the pollers spin on host cores. For throughput work, give each
  `femu-poller` thread a core of its own.

## Launch

From `build-femu/`:

<!-- femu-example: nossd-launcher -->
```bash
./run-nossd.sh
```

The FEMU device in that script is:

<!-- femu-example: nossd-device -->
```
-device femu,devsz_mb=4096,id=nvme0
```

`femu_mode` is not set, so it is 2. Writing `femu_mode=2` has the same
effect.

## Configuration

NoSSD ignores the NAND geometry, timing and FTL properties. These are the
ones that change its behaviour.

### Capacity and namespaces

Properties: [mode, capacity and namespaces](../reference/properties.md#mode-capacity-and-namespaces).

`devsz_mb` is the namespace size. `namespaces`, `namespace_sizes` and
`namespace_modes` split it into several namespaces
([multi-namespace guide](../features/multi-namespace.md)).

### Queues and pollers

Properties: [queues, pollers and interrupts](../reference/properties.md#queues-pollers-and-interrupts).

- `queues` sets the number of I/O queue pairs (default 8).
- By default one poller thread serves every I/O queue. With
  `multipoller_enabled=1`, FEMU runs `ceil(queues / poller_ratio)` pollers,
  each owning a round-robin share of the queues:

<!-- femu-example: nossd-pollers -->
```
-device femu,devsz_mb=4096,queues=8,multipoller_enabled=1,poller_ratio=2
```

  This starts four pollers. Give each one a host core.

### Host link and controller firmware

Properties: [host link and controller firmware](../reference/properties.md#host-link-and-controller-firmware).

`pcie_bandwidth_mbps`, `pcie_prop_delay_ns` and `fw_cpu_ns` add link and
firmware time to each Read and Write. With any of them set, NoSSD completes
commands through the same timed queue as the other modes instead of in the
poller sweep, which adds work per command.

<!-- femu-example: nossd-link -->
```
-device femu,devsz_mb=4096,pcie_bandwidth_mbps=3500,pcie_prop_delay_ns=1000
```

The preset `hw/femu/scripts/configs/nossd.conf` sets all three to the
figures of the NVMeCHA FPGA controller with a null backend (Qiu et al.,
IEEE TCAD, doi:10.1109/TCAD.2021.3088784): a 7000 MB/s link and about
2.4 us per 4 KiB read. A 4 KiB transfer at 7000 MB/s takes 585 ns, so with 1300 ns of
link delay and 500 ns of firmware a 4 KiB Read or Write costs 2385 ns, and
the link holds 4 KiB I/O near the controller's 1.7 million IOPS. FEMU charges
writes the same as reads, below the controller's 3.2 us, and the guest also
sees FEMU's own per-command time on top.
[`ssd-config.sh`](../tutorials/09-ssd-config-files.md) expands it to:

<!-- femu-example: nossd-preset -->
```
-device femu,id=nvme0,devsz_mb=4096,namespaces=1,pcie_bandwidth_mbps=7000,pcie_prop_delay_ns=1300,fw_cpu_ns=500,femu_mode=2
```

### Optional commands and features

Properties: [controller identity and capabilities](../reference/properties.md#controller-identity-and-capabilities),
[LBA formats, metadata and protection](../reference/properties.md#lba-formats-metadata-and-protection).

- `oncs` turns on optional NVM commands. The default (0x19d) offers Compare,
  Dataset Management, Write Zeroes, Save/Select, Verify and Copy. Add 0x2 for
  Write Uncorrectable.
- NoSSD supports [namespace management, metadata and protection information](../features/ns-management-and-pi.md)
  and Streams (`streams=on`, which tracks streams but places nothing).

## Use it from the guest

Check the device:

```sh
sudo nvme list
sudo nvme id-ctrl /dev/nvme0 | grep -E '^(mn|sn) '
```

The model is `FEMU NoSSD NVMe Controller` and the serial number starts with
`vNoSSD`.

Measure latency and throughput with fio. Unlike BlackBox, unwritten blocks
read at the same speed as written ones:

```sh
sudo fio --name=lat --filename=/dev/nvme0n1 --direct=1 --ioengine=io_uring \
    --rw=randread --bs=4k --iodepth=1 --runtime=30 --time_based
sudo fio --name=tput --filename=/dev/nvme0n1 --direct=1 --ioengine=io_uring \
    --rw=randread --bs=4k --iodepth=64 --numjobs=4 --group_reporting \
    --runtime=30 --time_based
```

The SMART log counts host reads and writes in every mode, NoSSD included:

```sh
sudo nvme smart-log /dev/nvme0
```

The vendor log page C0h stays zero: NoSSD has no media to count.

## Limits and refusals

| Message | Cause and fix |
| --- | --- |
| `multipoller_enabled must be 0 (one poller for all queues) or 1 (each poller owns poller_ratio queues)` | Any other value. |
| `queues must be in [1, 2047]` | `queues` out of range. |
| `oncs may only set Compare, Write Uncorrectable, DSM, Write Zeroes, Save/Select Feature Support, Verify and Copy` | A bit FEMU does not implement. |

If the host cannot allocate `devsz_mb` of memory, QEMU aborts in GLib with
`failed to allocate N bytes`.

## Verify

1. `sudo nvme list` shows the model `FEMU NoSSD NVMe Controller`.
2. A queue depth 1 random read reports a completion latency of a few
   microseconds to tens of microseconds, depending on the host, with no
   difference between written and unwritten blocks.
3. `sudo nvme smart-log /dev/nvme0` shows the read and write command counts
   moving.

## Troubleshooting

- **Throughput does not grow with more guest jobs.** A single poller serves
  every queue by default. Set `multipoller_enabled=1` with a `poller_ratio`
  that leaves one poller per host core you can spare, and pin the threads.
- **Latency varies from run to run.** The pollers compete with vCPUs and
  other host work. Pin vCPUs and pollers to separate cores, and keep the host
  CPU at a fixed frequency (see
  [performance tuning](../guides/performance-tuning.md)).
- **Data is gone after QEMU exits.** FEMU keeps the device only in host
  memory. A guest reboot keeps the data.

Related issues: #52, #69.

## Related pages

- [Choosing a mode](../concepts/choosing-a-mode.md)
- [Architecture: pollers](../concepts/architecture.md#pollers)
- [Timing model](../concepts/timing-model.md)
