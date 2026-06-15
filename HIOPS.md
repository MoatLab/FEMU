# FEMU high-IOPS (NoSSD) notes

This document describes a small set of upstream optimizations and bug fixes that
let FEMU's **NoSSD** mode (`-device femu` with no FTL, i.e. an SCM/NVRAM-style
zero-latency device) sustain high IOPS. The optimizations were measured on
NoSSD mode but are mode-agnostic in effect; the bug fixes address pre-existing
issues in the shared NVMe path.

## What's included

| Area | Change |
|---|---|
| Fast-path | Software-prefetch the next SQE in the poller sweep; zero only `cqe.res64` per command instead of the full 16-byte CQE. |
| Async events | Handle `Async Event Request` (hold it pending) instead of returning `INVALID_OPCODE`, so AER-posting drivers (e.g. SPDK) don't retry in a tight loop. |
| Correctness | Publish/acquire barrier so a poller never sees a half-initialized SQ under fast queue creation. |
| Correctness | Poller quiesce handshake so a controller reset / guest reboot can't free queues out from under a mid-sweep poller (the poller-vs-free use-after-free; see the commit for the scope and a note on the separate, pre-existing FTL-ring reset race). |

## Driving NoSSD at high IOPS

The throughput knobs are the standard FEMU device properties:

- `multipoller_enabled=1` — one poller thread per IO queue (vs. a single poller).
- `queues=<N>` — number of IO queues; scale with the guest's CPU count.

A ready-to-run example is `femu-scripts/run-nossd-hiops.sh` (a thin variant of
`run-nossd.sh` that enables the multipoller and a configurable queue count). All
parameters are environment-overridable; see the script header.

Inside the guest, use a polled, high-queue-depth engine (e.g. fio with
`io_uring`/`io_uring_cmd`, `iodepth` and per-core jobs) to drive the queues.

## Notes

- These optimizations change only per-command work and queue lifecycle ordering;
  the device's externally visible behavior is unchanged.
- The barriers and the quiesce handshake are at queue-creation / sweep-entry /
  controller-reset boundaries, not in the per-command inner loop.
