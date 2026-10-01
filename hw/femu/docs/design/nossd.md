# NoSSD: the mode without a media model

This chapter describes NoSSD (`femu_mode=2`, the default): what it leaves
out compared with the other modes, the path a command takes, and when to use
it. To run the mode, see the [NoSSD guide](../modes/nossd.md).

## Purpose

NoSSD is a plain NVMe namespace stored in host memory. It keeps FEMU's whole
NVMe frontend (queues, pollers, admin commands, optional commands,
namespaces) and drops everything below it:

| Layer | BlackBox (`femu_mode=1`) | NoSSD |
| --- | --- | --- |
| NVMe frontend, pollers | yes | yes |
| FTL: mapping, write buffer, GC, wear | yes, on the FTL thread | none |
| NAND timing: chips, channels, planes | yes | none |
| FTL thread | started | not started for NoSSD namespaces |
| Data | memory backend | memory backend |
| Completion time | arrival + FTL and NAND time | arrival, plus optional link and firmware time |

A command completes as soon as the poller has copied its data. What the
guest then measures is the cost of the emulation itself: the guest driver,
the doorbell exit, the poller, the copy and the interrupt.

Use NoSSD when:

- the storage device should not be the bottleneck, for example to work on
  the guest's I/O stack, the NVMe driver, io_uring or SPDK;
- you need an upper bound to compare a timed mode against. The difference
  between a BlackBox run and a NoSSD run with the same queues and pollers is
  mostly the time FEMU charges for the media and the FTL, but it also
  includes the cost of BlackBox's longer path through the FTL thread;
- you test NVMe features that do not depend on media, such as namespace
  management, metadata and protection information, or Streams.

Use [BlackBox](../modes/blackbox.md) when you need SSD latency, garbage
collection or write amplification.

## Place in the hierarchy

```text
  guest NVMe driver
        |  submission queue entry, doorbell
  +-----v------------------------------------------------------+
  | poller thread (femu-poller), one sweep                     |
  |                                                            |
  |  nvme_process_sq_io()                                      |
  |    stamp arrival time (stime = expire_time = now)          |
  |    nvme_io_cmd()                                           |
  |      Flush, DSM, Compare, Write Zeroes, Copy, ...  (shared)|
  |      Read, Write -> nop_io_cmd() -> nvme_rw()              |
  |                       map PRP or SGL, copy to backend     |
  |    complete: via the poller's priority queue (see below)   |
  +-----+------------------------------------------------------+
        |
  +-----v---------------------------+
  | memory backend  backend/dram.c  |   devsz_mb of host memory
  +---------------------------------+

  not used by NoSSD namespaces:  FTL thread, struct ssd, NAND media model
```

`nvme_register_nossd()` (`hw/femu/nossd/nop.c`) installs a handler table with
three entries that do work: `init` and `init_ctrl_name`, which set the
model and serial strings, and `io_cmd`, which sends Read and Write to the shared `nvme_rw()`
and returns Invalid Opcode for anything else that reaches it. The optional
commands (Dataset Management, Compare, Write Zeroes, Copy, Verify, Write
Uncorrectable) are handled in `nvme_io_cmd()` before the mode is consulted,
when `oncs` turns them on. With `streams=on`, a successful write also
records its stream, though NoSSD places nothing differently.

## Data path

`nvme_rw()` checks the LBA range and MDTS, maps the guest's PRP or SGL
list, and copies between guest memory and the memory backend, normally
with `backend_rw()`. The copy is done on the poller thread before the command
completes. The backend is one `devsz_mb` buffer allocated at realize; FEMU
tries to pin it with `mlock()` and prints a notice when `RLIMIT_MEMLOCK` is
too small, since page faults would then add to the measured latency.
Namespaces are slices of that buffer
([multi-namespace guide](../features/multi-namespace.md)).

The data survives a guest reboot and is lost when QEMU exits.

## Completion path

Every request is stamped with its arrival time as both its start time and
its completion time (`expire_time`). NoSSD adds nothing to it, so a NoSSD
request is due the moment it is stamped.

```text
  fetch -> execute -> copy -> to_ftl ring
        -> nvme_process_cq_cpl(): + link time, firmware time
        -> priority queue -> post when due -> interrupt
```

With no FTL thread, the poller drains its own `to_ftl` ring at the end of
the sweep, so the request is posted in the same sweep unless a link or
firmware time pushes it into the future or the completion queue is full. A
completion that finds the queue full waits in a per-poller backlog. When a
black-box, ZNS or CSD namespace on the same controller has started the FTL
thread, the request goes through that thread and back.

[`hiops_inline`](../reference/properties.md#queues-pollers-and-interrupts)
applies to NoSSD only: performance option, on by default; set off only when
debugging.

## Threads and pollers

NoSSD runs on the poller threads alone. How many there are, and which queues
each owns, is set by
[`multipoller_enabled` and `poller_ratio`](../reference/properties.md#queues-pollers-and-interrupts)
as in every mode; the
[architecture page](../concepts/architecture.md#pollers) explains the split.
Because there is no media time to hide behind, the pollers' CPU is the
device's speed limit in this mode. Give each poller a host core of its own,
away from the vCPUs, and see
[performance tuning](../guides/performance-tuning.md).

## Timing

None from the media. The optional models in the
[host link and controller firmware](../reference/properties.md#host-link-and-controller-firmware)
group apply to NoSSD as to every mode:

- `pcie_bandwidth_mbps`: transfer time per Read and Write on one
  device-wide link queue per
  direction;
- `pcie_prop_delay_ns`: a fixed delay after each transfer;
- `fw_cpu_ns`: a fixed time per Read, Write and Zone Append on one
  modelled controller core.


## Parameters

NoSSD ignores the NAND geometry, NAND timing and FTL properties. The ones
that matter:

| Group | Properties |
| --- | --- |
| [Mode, capacity and namespaces](../reference/properties.md#mode-capacity-and-namespaces) | `devsz_mb`, `namespaces`, `namespace_sizes`, `namespace_modes` |
| [Queues, pollers and interrupts](../reference/properties.md#queues-pollers-and-interrupts) | `queues`, `multipoller_enabled`, `poller_ratio`, `hiops_inline`, `mdts` |
| [Host link and controller firmware](../reference/properties.md#host-link-and-controller-firmware) | `pcie_bandwidth_mbps`, `pcie_prop_delay_ns`, `fw_cpu_ns` |
| [Controller identity and capabilities](../reference/properties.md#controller-identity-and-capabilities) | `oncs`, `cmbsz`, `vwc` |
| [LBA formats, metadata and protection](../reference/properties.md#lba-formats-metadata-and-protection) | `meta`, `mc`, `pi`, `nlbaf`, `lba_index` |
| [Namespace management, streams and power loss](../reference/properties.md#namespace-management-streams-and-power-loss) | `ns_mgmt`, `streams` |

A NoSSD device with four pollers, each owning two of eight queues:

<!-- femu-example: design-nossd-pollers -->
```text
-device femu,devsz_mb=1024,queues=8,multipoller_enabled=1,poller_ratio=2
```

## Counters

- The SMART log counts host read and write commands and bytes, kept per
  poller and summed when the log is read.
- The vendor log page C0h stays zero on a controller whose namespaces are
  all NoSSD: there is no media to count. Black-box, CSD and KV namespaces on
  the same controller fill it.

## Validation status

- NoSSD is the default mode, so most qtest cases in
  `hw/femu/tests/qtest/femu-test.c` run on it through the default device
  options. Cases named for it include `io-fuzz-nossd`, a fuzzer over I/O
  command fields, and the namespace management cases `ns-retire-nossd`,
  `ns-shared-remove-nossd` and `ns-shared-retire-nossd`. The poller cases
  `poller-burst`, `poller-burst-per-queue`, `poller-burst-sharded` and
  `shared-cq-pollers` run on NoSSD because it is the default.
- The documentation check starts each NoSSD example and writes and reads
  back one block.
- In a guest, `femu-test.sh` runs its block checks on a NoSSD namespace.

## Limits

- No latency model, so results say nothing about SSD behaviour.
- Throughput is bounded by poller CPU and by how the host schedules the
  pollers and vCPUs, which varies from run to run unless they are pinned.
- Host memory equal to `devsz_mb` is allocated at realize. If the
  allocation fails, QEMU aborts. If it succeeds but cannot be pinned, the
  pages are faulted in as they are used, and a host short of memory may run
  out then instead.
- Data is not kept across QEMU restarts.

Refusal messages are listed in the
[NoSSD guide](../modes/nossd.md#limits-and-refusals).

## Extending the mode

- **A fixed device latency.** Add a constant to `req->expire_time` in
  `nop_io_cmd()` and run with `hiops_inline=off`; the completion step
  then holds the request until it is due.
- **Another I/O command.** Add a case to `nop_io_cmd()` for a NoSSD-only
  command, or to `nvme_io_cmd()` in `hw/femu/nvme-io.c` when every block mode
  should get it.
- **Starting point for a new mode.** `hw/femu/nossd/nop.c` is the smallest
  complete mode. Copy it and register it in `nvme_register_extensions()` in
  `hw/femu/femu.c`. Then add the new `femu_mode` value to the enum in
  `hw/femu/nvme.h`, raise the bound in the realize check
  (`nvme_check_constraints()`, which refuses values above the KV mode), teach
  `backend_rw()` in `hw/femu/backend/dram.c` the mode (it asserts on an
  unknown one), add a token to `nvme_mode_from_token()` for
  `namespace_modes`, and add a `modes.py` entry.

## Source map

| File | Contents |
| --- | --- |
| [`hw/femu/nossd/nop.c`](../../nossd/nop.c) | the mode: handler table, Read and Write dispatch, model string |
| [`hw/femu/nvme-io.c`](../../nvme-io.c) | `nvme_process_sq_io()`, `nvme_io_cmd()`, `nvme_rw()`, `nvme_process_cq_cpl()`, `nvme_poller()` |
| [`hw/femu/backend/dram.c`](../../backend/dram.c) | the memory backend and `backend_rw()` |
| [`hw/femu/femu.c`](../../femu.c) | mode registration, FTL thread decision |

## Related pages

- [NoSSD guide](../modes/nossd.md): launching, fio examples, troubleshooting
- [Architecture: pollers](../concepts/architecture.md#pollers)
- [Timing model: host link and controller firmware](../concepts/timing-model.md#host-link-and-controller-firmware)
