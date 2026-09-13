# QLC placement measurement harness

What drives the experiment: it boots a FEMU device from this checkout, fills it
with an image whose byte layout decides which QLC page class every bit-plane
lands on, proves the placement landed with the device's own counters, and
replays a recorded MoE inference trace against it.

Only the FEMU-host half is here. The GPU host's analysis and plotting
(`compose_e2e.py`, `make_figures.py`, `timed_replay.py`, and the quantiser
tooling) stays there, because it needs the model weights and a GPU.

## Layout

    exp/moe_bcq/femu_run/         run the experiment
      run_device.sh               one device: boot, fill, then N replays
      drive_multi.sh              confusion check once, then a replay per trace
      run_policy.sh               older path: one device, one replay
      drive_run.sh                its driver
      run_sweep.sh, preflight.sh  sweep wrapper and its guard
      guest_replay.sh             runs inside the guest: fill and read-back
      class_confusion.c           reads one class back and counts what the
                                  device says it read -- the placement check
      probe_map.c, mark_write.c   LPN -> PPA probes, for diagnosing a fill
      verify_fill_256.py          checks the queue satisfies the fill contract
      audit_handoff.py            re-derives a binary's totals from the JSONL

    exp/moe_bcq/femu_handoff/packages/
      replay_v1.c                 the guest replayer, QD=32 O_DIRECT AIO
      REPLAYER_V1.md              the binary format it consumes

    exp/gating_nand/femu/make_seed.py   cloud-init seed carrying the binaries
    scripts/femu_compose.sh            compose wrapper
    scripts/build_replay.sh            builds the guest replayer
    runs/femu/run01.env                per-run environment template

## Where the rest lives

Three things are kept apart by who owns them, because the copies that used to
exist on both hosts drifted -- one pair of mapper copies ended up 64 lines
apart, and an edit to run_policy.sh was reverted twice by a sync.

| | |
|---|---|
| this repository | the harness, `replay_v1.c`, the emulator |
| `MoE_Trace` | the mapper, `bundle.py`, the rest of the trace tooling |
| neither, they are data | payload, layouts, `replay_qd32.bin`, images |

The split has a consequence worth stating plainly: **building an image needs
`MoE_Trace`.** `qlc_aligned_mapper.py materialize` turns a layout and a payload
into the image this harness fills a device from, and it is not in this
repository. Clone `MoE_Trace` alongside, or have the image built where that
tooling already is and shipped as data.

Nothing here calls it, so the harness runs without it once an image exists.

## What it needs that is not here

The payload (`planes.bin`, `scales.bin`, about 15 GB for the two models), the
collected traces, and the layouts built from them. They are data, not code, and
are distributed separately. A guest image is also needed: an Ubuntu 22.04 cloud
image, with a per-run qcow2 overlay -- 20.04 will not do, because replay_v1
needs a kernel new enough for the AIO path.

## Running one device

    bash exp/moe_bcq/femu_run/run_device.sh DEVICE_TAG IMAGE_BASENAME IMAGE_PAGES SPECFILE

`IMAGE_BASENAME` is an image under `runs/femu/images/`, `IMAGE_PAGES` its page
count from the layout summary, and `SPECFILE` a list of `<run name> <binary>`
lines, one replay each. All of them share the device, which is the point: the
placement is a property of the image, so every trace that shares the placement
has to be replayed on the same fill. Re-filling per trace would re-run
out-of-place allocation and land the pages on different physical classes.

The device geometry comes from the compose defaults in the parent checkout
(64 GiB, 2 channels x 4 LUNs, 512 pages per block, `op_pcent=7`) and needs no
argument. `runs/femu/run01.env` restates them and adds the per-run pieces: the
QLC counter path, the payload disk, the container name.

## Two things that will waste a day if you skip them

**Fill in 256 KiB writes.** This queue's `max_segments` is 127, so a larger
O_DIRECT write splits at 508 KiB, which falls in the middle of the 32nd 16 KiB
flash page. That page then belongs to both fragments and is programmed twice;
out-of-place update spends an extra physical page, and every later page shifts
one slot along. `guest_replay.sh` checks the queue before filling and dies if
the contract does not hold. This is configuration-dependent, which is why the
PPA check below stays in the procedure.

**A matching read-back hash does not mean the placement is right.** Three early
runs passed SHA-256 read-back and were still wrong: correct data says nothing
about which cell holds it. `drive_multi.sh` therefore reads every class back
across the whole image and asserts the counter diagonal before any replay. A
partial range would miss exactly the pages a drifted fill puts out of place.

## Checking a result

Each replay writes `groups.jsonl.gz` (per-group timing, the only record of the
prefill/decode split) and `replay.csv` (the QLC counter snapshot for that
replay) into `records/<run name>/`. `replay_v1` resets the counters when it
starts and snapshots them when it ends, so consecutive replays on one device
report independently -- verified by comparing every run's per-class page counts
against the counts its own compiled binary implies, which agreed exactly across
24 runs.
