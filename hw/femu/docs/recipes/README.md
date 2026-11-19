# Workload recipes

A recipe runs the storage side of one AI workload on a FEMU device. The
guest needs no accelerator. A sleep, a CPU program or an fio job stands
for the accelerator.

> **Status: not yet validated on a host.** No recipe on these pages has
> run on FEMU. The device lines pass the lint of the documentation
> check, which reads the tags and starts no device. No QEMU has started
> these device lines yet. Each page lists what a primary source confirms
> and what no run confirms. Treat each command as a draft until this
> note goes away.

| Recipe | Workload | Device | Guest script |
| --- | --- | --- | --- |
| [DLIO](dlio.md) | dataset write, training reads, checkpoint writes | BBSSD, 3 GiB namespace | `recipe-dlio-guest.sh` |
| [DiskANN](diskann.md) | build a vector index on the SSD, then search it | BBSSD, 1.5 GiB namespace, read reclaim | `recipe-diskann-guest.sh` |
| [KV-cache offload](kv-cache-offload.md) | store and load cache entries of two tenants on a raw namespace | BBSSD with FDP, and a control with no FDP | `recipe-kv-offload-guest.sh` |

```
 host                                   guest (KVM, no accelerator)
 ----                                   ---------------------------
 QEMU + FEMU bbssd device  <---NVMe---  recipe-*-guest.sh
   |  io_trace=FILE (CSV)                 install the tool (pinned version)
   |  QMP socket                          run the workload, with a time limit
   v                                      read log page C0h, before and after
 femu-stat.py        live counters        check that the counters moved
 femu-trace2fio.py   shape report         last line: <NAME>_RESULT=PASS|FAIL|SETUP-ERROR
```

## What a recipe gives

Each page has the same parts.

1. The exact `-device` line. The documentation check of the CI starts
   it under qtest.
2. The guest setup, with a pinned version of each tool.
3. The guest script and its environment variables.
4. What to read from FEMU: the counters, the WAF, the I/O trace and the
   shape report.
5. The behaviour to expect, with the reason. It is a prediction until a
   run confirms it.
6. What no run has confirmed.

## What a result is

A recipe studies the SSD model: latency percentiles, write
amplification, garbage collection and read reclaim. It does not measure
the speed of the emulator.

- Report results of the device model. Do not report a command rate of
  the emulator as a result.
- State the effective configuration with each result.
  `femu-config-check.py` reports it.
- Check that FEMU kept up: [timing model](../concepts/timing-model.md).
- Report relative results, such as a run against its control. An
  absolute number needs a calibration against a real drive.

`PASS` from a guest script means that the workload ran and the stated
counters moved. It is not a statement on performance.

## Before you start

You need a built FEMU and a guest image, as in the
[quick start](../getting-started/quick-start.md). The recipes use the
shell variables of the tutorials:
[Before you start](../tutorials/README.md#before-you-start).

Copy the scripts of a recipe to the guest from `build-femu/` on the
host. This command copies the scripts of all three recipes:

```sh
tar -C ../femu-scripts -c recipe-guest-lib.sh recipe-dlio-guest.sh \
    recipe-diskann-guest.sh recipe-kv-offload-guest.sh \
    fio/gpu-kv-offload-fdp.fio | ./run-guest-ssh.sh tar -x
```

Each script needs `recipe-guest-lib.sh` in its own directory. Each
script needs `--yes`, because it writes over the namespace. Two of the
scripts download and build a tool, so the guest needs network access.

## The counters that each script reads

```
 sample before --> workload phase --> sample after --> difference
   log page C0h:        host pages, GC pages, programmed pages,
                        plane reads, reads of the most-read block,
                        lines rewritten for read stress
   /sys/block/N/stat:   sectors read and written at the block layer
```

A script prints one `<NAME>_COUNTERS=` line for each phase. The WAF on
that line is (programmed pages + GC pages) / host pages over the phase.
Pad pages and translation pages are not in it.
[Log pages and counters](../reference/log-pages-and-counters.md#vendor-log-page-c0h)
describes each field.

The block layer counts show that an I/O left the guest page cache. The
C0h counts show that the I/O reached the FTL and the NAND model. A check
needs both.

## The I/O trace and the shape report

Add `io_trace=FILE` to the `femu` device of a recipe to capture each
I/O command. FEMU does not write over a file, so use a new name for each
run. Stop QEMU after the run, then read the shape on the host:

```sh
python3 hw/femu/scripts/femu-trace2fio.py --block-size 512 femu-trace.csv
```

Each recipe page states what to expect in the report.
[Trace replay and I/O shapes](../guides/trace-replay.md) describes the
report and the replay.

## Related pages

- [Measuring](../guides/measuring.md): counters, the trace format and
  repeatable numbers.
- [QMP query-femu](../reference/query-femu.md): the FTL state from the
  host.
- [Scripts and tools](../reference/scripts.md): each script and its
  arguments.
