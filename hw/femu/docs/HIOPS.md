# FEMU high-IOPS (NoSSD) — optimizations, results, and reproduction

This document describes a set of optimizations that let FEMU's **NoSSD** mode
(`-device femu` with no FTL — an SCM/NVRAM-style zero-latency device) sustain
high IOPS for a single VM, the configuration that achieves it, and a complete
reproduction harness.

On a 2-socket Intel Xeon Gold 6548Y+ host (Emerald Rapids, 64 physical / 128
logical cores), a **single FEMU VM** sustains, for 512 B random reads:

| Workload driver | 512 B | 4 KiB |
|---|---|---|
| **SPDK** (bdevperf) | **80.0M IOPS** | 37.1M (145 GB/s) |
| **fio** (SPDK plugin) | **63.5M IOPS** | 34.3M (141 GB/s) |
| fio (kernel io_uring) | 3.2M | 3.0M |

All write/verify runs pass (`crc32c`, 0 miscompares). 4 KiB is bounded by the
host's cross-socket memory bandwidth (~141–145 GB/s); the 512 B figure is the
protocol-path headline.

## What's included

These changes are upstreamed as a series of focused commits. The first three are
mode-agnostic and benefit every device mode; the rest are gated to NoSSD and have
no effect on bbssd/zns/ocssd/csd.

| Area | Change |
|---|---|
| Shadow doorbell | Publish the dbbuf eventidx one slot behind the ring position so the guest actually suppresses its SQ-tail / CQ-head doorbell MMIO (each a VM-exit). FEMU busy-polls, so it never needs the notification. |
| Scaling | Shard the per-I/O accounting into cacheline-isolated per-poller counters (removes a shared-line ping-pong across pollers/sockets). |
| Scaling | Decouple poller threads from queues: `poller_ratio` lets M pollers each sweep a round-robin shard of N≥M queues (default 1 = one poller per queue). |
| NoSSD fast path | Complete zero-latency NoSSD I/O inline in the SQ sweep (`hiops_inline`, default on) instead of bouncing it through the FTL ring + priority queue; single-PRP transfers copy directly and skip the sglist allocation. |
| NUMA placement | `FEMU_MBE_INTERLEAVE=<node>` binds the emulated-SSD backend buffer to a NUMA node — the device half of strict socket isolation. |

## The configuration that achieves it

Two things matter beyond the code:

1. **Run SPDK in the guest, not the kernel block stack.** The guest kernel
   io_uring / blk-mq / nvme path caps at ~3M IOPS here; SPDK's userspace
   poll-mode driver bypasses it. Drive it with one queue pair per core
   (`bdevperf -C`, or `numjobs=N` with the SPDK fio plugin).
2. **Strict socket isolation on a 2-socket host.** Pin the guest's vCPUs and RAM
   to one socket; pin FEMU's poller threads and the emulated backend to the
   other (`FEMU_MBE_INTERLEAVE`). Only the per-I/O emulation copy crosses the
   inter-socket link, and the guest and the emulation stop contending for the
   same cores and DRAM bandwidth. On this host that isolation lifts SPDK 512 B
   from ~45M (un-pinned) to 80M.

The measured peak used: a 48-vCPU guest on one socket (1 GiB hugepages),
`-device femu,queues=48,multipoller_enabled=1,poller_ratio=1`, the backend bound
to the other socket, and 48 SPDK reactors at QD128.

Driving the device from the guest **kernel** (no SPDK) works too but is far
slower — the kernel I/O stack, not FEMU, becomes the wall.

## Reproduce

A complete, parameterized harness lives in `femu-scripts/hiops/` — host check,
VM launch (guest→node0, backend→node1), guest SPDK bind, vCPU/poller pinning,
and the measurement (SPDK bdevperf or fio-on-SPDK). See
`femu-scripts/hiops/README.md` for the host kernel cmdline, the guest-image
prerequisites (SPDK + fio build), and the run commands. A simpler single-socket
runner for casual use is `femu-scripts/run-nossd-hiops.sh`.

## Notes

- The optimizations change only per-command work, queue lifecycle, and thread/
  memory placement; the device's externally visible behavior is unchanged.
- The dbbuf eventidx is a pure MMIO-suppression hint and is correct only because
  FEMU sweeps every active queue unconditionally; a future move to adaptive/halt
  polling would have to revert it (documented in-code).
