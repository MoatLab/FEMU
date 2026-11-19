# Recipe: LLM KV-cache offload on a raw namespace with FDP

> **Status: not yet validated on a host.** This recipe has not run on
> FEMU. The device lines pass the lint of the documentation check,
> which starts no device. fio 3.36 parses
> the job file. No run confirms the guest script or the expected
> behaviour. The LMCache commands in section 7 come from the LMCache
> documents and have not run at all.

An inference server keeps the key-value cache of a session, so that a
later request does not compute the prompt again. The cache of many
sessions does not fit in accelerator memory. A server can move it to an
SSD and load it when the session resumes.

This recipe is an fio stand-in for that server. Two tenants store cache
entries on a raw namespace. The entries of one tenant live for a short
time on average, and the entries of the other tenant live longer. With
Flexible Data Placement (FDP), each tenant writes through its own
placement identifier.

```
 namespace (raw, no file system)
 |-- short tenant 12% --|------- long tenant 63% -------|--- load 25% ---|
   store 24 MiB/s          store 8 MiB/s                  load 32 MiB/s
   placement index 0       placement index 1              (prefill: 2)

 one entry = 32 commands of 128 KiB in a row = 4 MiB
 fio, io_uring_cmd --> /dev/ng0n1 --> FEMU bbssd with FDP
                                        one reclaim unit handle per tenant
```

## Why a stand-in

[LMCache](https://docs.lmcache.ai) has a raw block backend with FDP
placement. Its documents list an NVIDIA GPU and CUDA as install
conditions. No document states that the full package runs on a host
with no CUDA library. Section 7 has the LMCache commands for a reader
who can try them.

The fio job gives the I/O shape and the placement of such a backend. It
does not give the metadata writes, the eviction policy or the slot
layout of LMCache.

## 1. Start the guest (on the host)

With FDP:

<!-- femu-example: recipe-kv-fdp-boot -->
```bash
./qemu-system-x86_64 -name femu-recipe-kv,debug-threads=on \
    -enable-kvm -cpu host -smp 4 -m 4G \
    -device virtio-scsi-pci,id=scsi0 -device scsi-hd,drive=hd0 \
    -drive file=$OSIMGF,if=none,cache=none,format=qcow2,id=hd0 \
    -net user,hostfwd=tcp::$SSH_PORT-:22 -net nic,model=virtio \
    -device femu-subsys,id=fdp0,fdp=on,fdp.nruh=4 \
    -device femu,id=femu0,femu_mode=1,devsz_mb=1536,nchs=4,luns_per_ch=4,blks_per_pl=128,subsys=fdp0,io_stages=on \
    -qmp unix:/tmp/femu-qmp.sock,server=on,wait=off \
    -nographic
```

The control has the same device with no FDP subsystem:

<!-- femu-example: recipe-kv-control-boot -->
```bash
./qemu-system-x86_64 -name femu-recipe-kv,debug-threads=on \
    -enable-kvm -cpu host -smp 4 -m 4G \
    -device virtio-scsi-pci,id=scsi0 -device scsi-hd,drive=hd0 \
    -drive file=$OSIMGF,if=none,cache=none,format=qcow2,id=hd0 \
    -net user,hostfwd=tcp::$SSH_PORT-:22 -net nic,model=virtio \
    -device femu,id=femu0,femu_mode=1,devsz_mb=1536,nchs=4,luns_per_ch=4,blks_per_pl=128,io_stages=on \
    -qmp unix:/tmp/femu-qmp.sock,server=on,wait=off \
    -nographic
```

| Option | Meaning |
| --- | --- |
| `femu-subsys,id=fdp0,fdp=on` | a subsystem with FDP; it must come before the controller that names it |
| `fdp.nruh=4` | four reclaim unit handles, so placement identifiers 0 to 3 |
| `femu_mode=1` | BlackBox mode: the device runs its own FTL, GC and NAND timing |
| `nchs=4,luns_per_ch=4,blks_per_pl=128` | 2 GiB of NAND in 128 lines of 16 MiB; each line is one reclaim unit |
| `devsz_mb=1536` | a 1.5 GiB namespace, 75% of the NAND |
| `subsys=fdp0` | the controller joins the subsystem |
| `io_stages=on` | stage times for `femu-stat.py` and `query-femu-stages` |

To capture a trace, add `,io_trace=/var/tmp/kv-trace.csv` to the `femu`
device. The file must not exist. Restart QEMU before each run, so that
each run starts from an empty device.

## 2. Guest setup

The guest image from `make-guest-image.sh` has fio 3.36 and nvme-cli
2.8. The script installs nothing.

| Fact | Source | State |
| --- | --- | --- |
| The `io_uring_cmd` engine sends NVMe commands through `/dev/ngXnY` | the fio documentation | checked |
| fio has FDP placement (`fdp`, `fdp_pli`) from version 3.34 | the fio commit history | checked |
| NVMe passthrough through io_uring needs Linux 5.19 or newer | the Linux source at v5.19 and v5.18 | checked |
| fio 3.36 parses `gpu-kv-offload-fdp.fio` with `FEMU_FDP` 0 and 1 | a local `fio --parse-only` | checked |
| The job runs on a FEMU device | none | not confirmed |

## 3. Run

In the guest, as root:

```sh
sudo bash recipe-kv-offload-guest.sh --yes nvme0n1
```

```
 step      action
 --------  -----------------------------------------------------------
 prefill   write each of the three regions one time, at 64 MiB/s for
           each region; with FDP, through placement indexes 0, 1 and 2
           (fio rounds the percent limits to 128 KiB, so one block
           between two regions can stay empty; no job reads it)
 sample    log page C0h, block layer counts, FDP statistics
 run       fio/gpu-kv-offload-fdp.fio for 240 s
 sample    the same counters again
 verdict   KVO_RESULT=...
```

The script selects FDP when the namespace reports three placement
identifiers or more. A status query that fails selects the control, and
the script prints `KVO_FDP_SELECT=auto status_query=failed`. Set
`KVO_FDP=1` to make FDP a condition of the run. `KVO_FDP=0` runs the
control on an FDP device too.

| Variable | Default | Meaning |
| --- | --- | --- |
| `KVO_FDP` | by the device | 1: place each store; 0: no placement |
| `KVO_RUNTIME` | 240 | seconds of the run |
| `KVO_CONTROL` | none | `no-store`: run the load job alone, so the check that the stores ran must fail. `frozen-counters`: use the first counter sample two times, so the counter checks must fail |

The last line of the script is the verdict:

```text
KVO_RESULT=PASS recipe=kv-offload fdp=1 runtime=240 stored_bytes=N waf=N control=none
```

The verdict is `PASS`, `FAIL` or `SETUP-ERROR`, and the exit status is
0, 1 or 2 in that order. The script also writes the verdict line to the
file `DONE` in its scratch directory.

### The rate limit

Each job of `gpu-kv-offload-fdp.fio` has a fixed `rate`. The total is 32
MiB/s of stores and 32 MiB/s of loads. The limit is a proposed cap. No
run has shown that FEMU posts each completion at its due time at this
rate. Before you read a latency, check the `past-due` row, the rate
that fio reached and the fio latency of the run.
[The rate limit](../guides/trace-replay.md#the-rate-limit) gives the
rules. Do not remove or raise a limit to report a speed of the emulator.

### What the script checks

| Check | A defect that makes it fail |
| --- | --- |
| with FDP, the namespace reports three placement identifiers or more | the controller did not join the FDP subsystem |
| the prefill and the run exit 0 inside their time limits | a command fails, or the device stops |
| fio reports I/O for each of the three jobs, and no error | a job did not start |
| the C0h host pages grow by 90% of the bytes that fio stored | the stores did not reach the FTL |
| with FDP, the FDP statistics count 90% of the bytes that fio stored | the device did not count the placed writes |

Two controls show that checks can fail. `KVO_CONTROL=no-store` tests
the check that the stores ran. The verdict must be `FAIL` with
`KVO_FAIL=no-store`. `KVO_CONTROL=frozen-counters` tests the two counter
checks. The verdict must be `FAIL` with
`KVO_FAIL=c0-host-pages-below-stores`.

The script does not prove that each store went to its own handle. Read
the bytes of each handle on the host for that (section 4).

## 4. What to measure

```
 source                         value
 -----------------------------  ----------------------------------------
 KVO_COUNTERS= (guest script)   host, GC and NAND pages and the WAF of
                                the run
 KVO_FDP_STATS= (guest script)  host bytes of the FDP statistics log
 femu-stat.py (host)            host and media bytes of each handle, the
                                WAF of each handle, reclaim unit counts
 fio (workdir/run.json)         latency percentiles of each job
 io_trace + femu-trace2fio.py   size mix, sequential share, depth
```

The main result is the WAF of the FDP run against the WAF of the
control run. Run each one on a fresh QEMU.

On the host, read the bytes of each handle two times: when the script
prints `KVO_PREFILL=ok`, and after the verdict.

```sh
python3 hw/femu/scripts/femu-stat.py /tmp/femu-qmp.sock --once
```

`femu-stat.py --once` counts from the start of the device, so the
prefill is in each value. The prefill writes 12%, 63% and 25% of the
namespace through handles 0, 1 and 2. Subtract the first reading from
the second reading to get the bytes and the WAF of the run.

The fio latency of a store or a load is the latency of one 128 KiB
command. The time to load one entry spans its 32 commands. Find it in
the trace, from the first fetch to the last CQE of the entry.

For the shape report, expect reads and writes in the `131072` size
line. Expect a sequential share near 31 of 32 for each kind, when each
job stays on one CPU.

## 5. Expected behaviour

No run has confirmed these predictions.

| Prediction | Reason |
| --- | --- |
| The control run has a WAF above 1. | The prefill makes the whole namespace valid, which is 75% of the NAND. The stores then write 5 times the namespace size in 240 s. GC starts when free lines are few, and its victim lines still hold valid pages. |
| The FDP run has a lower WAF than the control run. | With no placement, short and long entries share lines, so a victim line holds long entries that GC must copy. With placement, the reclaim units of the short tenant hold its entries only. |
| With FDP, the short tenant handle has a lower WAF than the long tenant handle. | The short tenant writes the size of its region about each 8 s. Its pages thus become invalid sooner on average. |
| The host bytes of handle 0 grow about 3 times as fast as the host bytes of handle 1 during the run. | The store rates are 24 MiB/s and 8 MiB/s. The prefill is not in this ratio. |
| The 99th percentile latency of a load is above its median in both runs. | A load waits when GC or a store keeps its die busy. |

The size of the WAF difference is not predicted. It depends on the fill
level, the region sizes and the GC options. A run at another fill level
can show no difference.

The lifetimes are statistical. fio picks the start of each entry at
random, on a 128 KiB boundary and with replacement. An entry can thus
overlap an older entry in part. A store of one region size does not
write over each entry of the region. A reclaim unit of the short tenant
can thus keep valid pages.

## 6. Limits

- No run exists. Section 5 is a set of predictions.
- The job is a stand-in. It has two mean lifetimes, a fixed entry size,
  no fixed entry slots and no eviction policy.
- The job has no deallocate. A server that trims evicted entries gives
  GC more free space.
- The WAF on the `KVO_COUNTERS=` line leaves out pad pages and
  translation pages.
- The limit caps the mean rate, not each burst. Check the `past-due`
  row of `femu-stat.py` for each run.

## 7. LMCache raw block backend (not run)

The LMCache documents describe a `raw_block` adapter and a benchmark
command that needs no inference engine. The commands below are copies
from those documents. No part of this section has run.

```sh
pip install 'lmcache[raw-block]'
lmcache bench l2 \
    --l2-adapter '{"type":"raw_block","device_path":"/dev/nvme0n1","slot_bytes":4194304,"use_odirect":true,"block_align":4096}' \
    --data-size-kb 1024 \
    --l1-align-bytes 4096
```

The adapter options for NVMe passthrough with FDP, from the same
documents:

```text
{"type": "raw_block", "device_path": "/dev/ng0n1", "slot_bytes": 1048576,
 "io_engine": "io_uring", "use_uring_cmd": true, "fdp_enabled": true,
 "use_odirect": false}
```

| Fact | Source | State |
| --- | --- | --- |
| The `raw_block` adapter, its options and FDP placement by `cache_salt` prefix | <https://docs.lmcache.ai/mp/l2_storage/raw_block.html> | checked on 2026-11-19 |
| `lmcache bench l2` needs no inference engine and no server | <https://docs.lmcache.ai/cli/bench.html> | checked |
| The newest release is `v0.5.7.post1` | the release list of the repository | checked |
| The install conditions name an NVIDIA GPU and CUDA 12.1 or newer | the LMCache install page | checked |
| The package runs on a host with no CUDA library | none | not confirmed |
| `lmcache bench l2` sets a `cache_salt`, so that FDP places its stores | none | not confirmed |
| The adapter works on a FEMU namespace | none | not confirmed |

The LMCache page states that a `cache_salt` with no prefix uses no FDP
directive. A benchmark with no prefix thus gives no placement.

## Related pages

- [Workload recipes](README.md): the common steps and the result rules.
- [Tutorial 04](../tutorials/04-fdp.md): FDP by hand, with nvme-cli and
  fio.
- [Flexible Data Placement](../features/fdp.md): each option and
  refusal.
- [Trace replay and I/O shapes](../guides/trace-replay.md): the other
  rate-limited job files.
