# Trace replay and I/O shapes

This page shows how to capture the I/O of a workload once and replay it
many times. It also describes five fio job files that give the I/O
shapes of an accelerator workload with no accelerator in the guest.

```
 live run (once)                             replay (many times)
 guest workload --> FEMU, io_trace=FILE      fio --read_iolog --> FEMU
                        |                            ^
                        v                            |
               trace CSV (host file)                 |
                        |                            |
                        v                            |
               femu-trace2fio.py ----------> fio I/O log, version 3
                        |
                        v
               shape report: mix, sizes, queues, depth,
               arrival gaps, bursts, sequential share

 scripts/fio/gpu-*.fio (fixed rate) --> fio --> FEMU, io_trace=FILE
                                                      |
                                                      v
                                   femu-trace2fio.py: check the shape
```

All tools are in `hw/femu/scripts/`. They need Python 3 and no other
package. [Scripts and tools](../reference/scripts.md) lists their
arguments.

## Capture a trace

Add `io_trace=FILE` to the `femu` device. FEMU then writes one CSV line
per completed I/O command to FILE on the host.
[Per-command I/O trace](measuring.md#per-command-io-trace-io_trace)
describes each field.

Run the workload in the guest and wait for it to end. Then stop QEMU.
QEMU flushes the trace when it exits.

The trace holds completed commands only. A command that is not complete
when QEMU exits is not in it, and the file does not show that. QEMU
prints a warning when it drops trace lines.

## Convert the trace

```sh
femu-trace2fio.py --block-size 512 --device-size 4g \
    --filename /dev/nvme0n1 --iolog workload.iolog femu-trace.csv
```

The trace holds LBAs and no LBA size, so `--block-size` is necessary.
Give the LBA size of the namespace: 512 for `lba_index=0`, 4k for
`lba_index=3`. `--filename` is the namespace device in the guest. The
tool prints the shape report and writes the I/O log. It does not write
over a file. Without `--iolog` it prints the report only.

The tool checks each line before it writes a result. A wrong line stops
it with exit status 1 and the line number.

| Fault | Message |
| --- | --- |
| a line with a field count other than 9 | `N fields, not 9` |
| a field that is not a number | `is not a decimal number`, `is not a 0x hex number` |
| a field too wide for its NVMe field | `is above` |
| a range on a command that has none in the trace | `a range on opcode` |
| a CQE time below the fetch time | `the time goes backward` |
| a range past `--device-size` | `ends past the device size` |
| a start LBA with no block count | `half a range` |
| two namespaces and no `--nsid` | `select one namespace with --nsid` |
| a last line with no newline | `the trace is cut short` |
| an offset, length or time that fio cannot hold | `above what fio can hold` |
| `--iolog` and no read or write to replay | `no read or write to replay` |

Options:

| Option | Effect |
| --- | --- |
| `--nsid N` | use the commands of namespace N |
| `--filename PATH` | device name in the I/O log; necessary with `--iolog` |
| `--device-size BYTES` | size of the replay target; without it the tool does not check the ranges |
| `--time-scale F` | divide each time stamp by F; 2 replays at twice the speed |
| `--lba-scale F` | multiply each start LBA by F and round down, for a target of another size |
| `--strict` | fail when the tool cannot replay a command |
| `--buckets N` | number of time slices in the depth profile (default 10) |
| `--burst-gap NS` | a gap above NS between two fetches starts a new burst (default 1000000) |

Sizes accept the suffixes k, m, g and t (powers of 1024). Scales accept
a fraction such as `1/2`.

### What the replay holds

```
 trace command                    I/O log action
 -------------------------------  ---------------------------------
 Read with a range, status 0      read  <byte offset> <byte length>
 Write with a range, status 0     write <byte offset> <byte length>
 Flush, status 0                  sync 0 0
 Dataset Management (trim)        none: the trace holds no range
 Compare, Write Zeroes, Verify,   none: fio has no such action
   Copy, zone commands
 each other opcode                none
 a command with a status above 0  none
```

The report counts each command that is not replayed, by name. An opcode
with no name shows as `opcode-0xNN`.

A replay of a workload that trims leaves more valid data on the device
than the live run. Use `--strict` when that matters.

The opcode names are those of the NVM and zoned command sets. The trace
does not hold the command set of a namespace. A Read or Write opcode
with no range, as on a key-value namespace, counts as `other`.

The I/O log time is the fetch time of the command, in microseconds from
the first fetch. The tool sorts the commands by fetch time. The trace
file itself is in completion order. Two commands with one fetch time
keep the completion order, and the `arrival` line counts these ties.

## Read the shape report

```
trace: 9 commands, namespace 1, block size 512
mix (kind, commands, share):
  read  5 55.6%
  write 2 22.2%
  flush 1 11.1%
  trim  1 11.1%
  other 0 0.0%
  failed 1
  bytes read 12800 written 16384
sizes (bytes up to, reads, writes):
  512 1 0
  4096 3 0
  8192 0 2
queues (sqid, commands, share, bursts, largest burst):
  1 5 55.6% 1 5
  2 4 44.4% 2 3
depth (fetch to CQE): max 3 mean 0.16 over 4053000 ns
  slices (start_ns, max, mean):
  0 3 0.29
  2026500 2 0.03
arrival (gap between fetches, ns): min 1000 mean 500375 p50 1000 p99 3680000 max 3680000 ties 0
bursts (all queues, gap up to 1000000 ns): count 2 mean 4.50 max 6
sequential (same queue, same kind): read 1 of 4 25.0%, write 1 of 2 50.0%
replay: 7 commands (read 4, write 2, sync 1)
not replayed: dsm 1, failed 1
```

| Section | Meaning |
| --- | --- |
| `mix` | commands per kind; `failed` counts a status above 0; the byte counts cover successful reads and writes with a range |
| `sizes` | successful reads and writes per size, rounded up to a power of two |
| `queues` | commands per submission queue, with the bursts of that queue alone |
| `depth` | commands between fetch and CQE: the maximum and the mean over time, for the whole trace and per time slice |
| `arrival` | gap between two fetches in a row; the percentiles use the nearest rank |
| `bursts` | runs of fetches with no gap above `--burst-gap`, over all queues together |
| `sequential` | reads (or writes) that start where the previous read (or write) on the same queue ended |

The depth is the depth inside the device. Time in the submission queue
before the fetch is not in it. A fetch time is the time when a poller
took the command, so one poller pass gives a small burst. Two commands
that meet at one time count as an overlap.

## Import a public trace

`femu-trace-import.py` turns a public trace into an `io_trace` file.
`femu-trace2fio.py` then reads it as it reads a capture of a live run.

```
 public trace --> femu-trace-import.py --> io_trace CSV --> femu-trace2fio.py --> fio I/O log
                  one volume, whole blocks,                 report, time sort,
                  fold to --device-size                     --time-scale
```

```sh
femu-trace-import.py --format alibaba --volume 27 --block-size 512 \
    --device-size 4g --fold scale --volume-sizes device_size.csv \
    --out vol27.csv io_traces.csv.gz
femu-trace2fio.py --block-size 512 --device-size 4g \
    --filename /dev/nvme0n1 --iolog vol27.iolog vol27.csv
```

Use the same `--block-size` and `--device-size` for both tools. The
tool reads a `.gz` file directly. It never writes over a file.

### Formats

| `--format` | Trace set | Columns, in order | Units |
| --- | --- | --- | --- |
| `msr` | MSR Cambridge, SNIA IOTTA | `Timestamp,Hostname,DiskNumber,Type,Offset,Size,ResponseTime` | Windows filetime (100 ns), bytes; `Type` is `Read` or `Write` |
| `alibaba` | Alibaba block traces 2020 | `device_id,opcode,offset,length,timestamp` | bytes, microseconds; `opcode` is `R` or `W` |
| `tencent` | Tencent CBS, SNIA IOTTA | `Timestamp,Offset,Size,IOType,VolumeID` | 512-byte sectors, time unit not confirmed; `IOType` 0 is read, 1 is write |
| `cachelib` | Meta CacheLib key-value cache traces | by header name: `key`, `op`, `size`, `key_size`; optional `op_time`, `op_count`, `usecase` | bytes, time unit not confirmed |

The column tables come from these pages:

- the Alibaba README: https://github.com/alibaba/block-traces
- the trace list of the cacheMon group: https://github.com/cacheMon/cache_dataset

Read the page of your trace set before a study. The sources do not
confirm the time unit of the Tencent and CacheLib sets. So for these
formats, give the unit with `--time-unit` on the command line. The first three formats accept one optional header
line with the names above. A CacheLib trace needs its header
line, because the tool reads its columns by name.

### Volumes and the device size

A trace file can hold many volumes. The volume is `HOST:DISK` for `msr`
(for example `usr:0`), `device_id` for `alibaba` and `VolumeID` for
`tencent`. The tool uses one volume. With no `--volume` and two volumes
in the file, it stops. `--list-volumes` prints each volume with its
request count and its largest end byte.

The tool rounds each byte range out to whole blocks and counts the
unaligned ranges. It drops a request of size 0. It splits a long range
into several commands at one time. A command holds at most 65536 blocks
and less than 4 GiB, the limits of `femu-trace2fio.py` and fio.

A volume can be larger than the FEMU namespace. `--fold` sets what
happens then:

```
 --fold none   (default)  a range past --device-size is an error
 --fold wrap              block modulo the device size: keeps the local order,
                          puts two parts of the volume on one place (more overwrites);
                          a range across the device end goes on at block 0
 --fold scale             start block x device / volume, length kept: keeps the
                          order of the volume, shrinks the gaps (ranges can overlap);
                          a range across the device end moves down to end there
 each fold                a range larger than the device is an error
```

`--fold scale` takes the volume size from `--volume-size`, from
`--volume-sizes` (the Alibaba `device_size.csv` file), or from the
largest end of the whole volume in the trace. The summary names the
source. A range past a given volume size is an error. Both folds
change the overwrite pattern, so a WAF from a folded trace is not the
WAF of the original volume.

### Time

The tool runs its steps in this order:

```
 select the volume (whole file) --> sort by time (file order for equal times)
   --> repeat a CacheLib line op_count times --> --spread
   --> --duration, then --limit (in requests) --> whole blocks --> fold --> split
```

- The first request of the volume is time 0. The output is in time
  order. The summary counts the requests that are out of order in the
  file.
- A trace with coarse times puts many requests at one time. `--spread`
  places the k-th of n requests at one time t at t + k/n of one time
  unit. The trace does not hold those times.
- `--duration SEC` keeps the requests before the first time plus SEC.
  `--limit N` then keeps the first N requests. A CacheLib miss counts as
  a request.
- `femu-trace2fio.py` starts the I/O log at the first command. A
  request with no command (a miss, size 0) at the start does not move
  the replay.
- To replay faster or slower, use `femu-trace2fio.py --time-scale`.

Only MSR has a latency (`ResponseTime`, from the original disk). Each
piece of a split MSR request has it. For the other formats, the tool
writes the submit time as the CQE time. In the shape report of an
imported trace, the `depth` and `queues` lines do not show the original
system. The tool puts each command on queue 1. Do not set the fio
`iodepth` from them.

### CacheLib traces

A key-value trace has no block address. The tool puts the objects in a
FIFO log over the namespace:

```
 SET k, size above 0  --> write ceil((key_size + size) / block) blocks at the
                          log head; an older copy of k becomes dead space
 SET k, size 0        --> no command; the log does not change
 GET k, GET_LEASE k   --> k in the log: read its blocks; else a miss, no command
 DELETE k             --> k leaves the log; no command (io_trace has no trim range)
 object past the end  --> the rest of the device is skipped; the head goes to block 0
 head reaches an old  --> each object that the new one overwrites, in whole
 object                   or in part, leaves the log
```

- This is a simple model, not the CacheLib engine. It has no DRAM tier
  and no small-object engine. It ignores `ttl` and `cache_hits`, and a
  GET reads the stored extent, not the `size` of the GET line.
- A line stands for `op_count` requests, as in the CacheBench replay of
  CacheLib.
- One key of two `usecase` values is two objects.
- A trace with no `op_time` column needs `--rate N`. The tool then gives
  line i the time i / N seconds, a synthetic clock.
- `--max-bad` is not for CacheLib traces: a skipped line changes each
  later state of the model.

### Bad lines

A bad line stops the tool with exit status 1 and the line number. A
number field takes decimal digits only: no sign, no fraction.
`--max-bad N` skips up to N bad lines and prints the count and the first
line numbers. A bad header line always stops the tool. Exit status 2 is
a usage or file error.

The tool writes the output file only after a successful run, so a
failed run leaves no file. The tool holds the selected volume in
memory, and so does `femu-trace2fio.py`. For a large trace, select a
short window with `--duration` or `--limit`.

## Replay

Copy the I/O log to the guest, then run fio there:

```sh
sudo fio --name=replay --read_iolog=workload.iolog \
    --ioengine=io_uring --direct=1 --iodepth=64
```

- The I/O log names the device, so the job needs no `filename`. Use
  `--replay_redirect=/dev/nvme1n1` for another device.
- Set `iodepth` to the `depth` maximum of the report or above. A lower
  value makes fio fall behind the trace. For an imported trace, the
  depth is not a measurement: use a high value such as 64.
- fio follows the time stamps of the capture. Do not set
  `replay_no_stall`: it removes the time of the workload from the result.
- fio needs version 3.31 or newer for this log format.

The replay is close to the capture, not equal to it.

```
 capture                         replay through /dev/nvme0n1
 ------------------------------  ---------------------------------------
 one command per trace line      the block layer can split or merge it
 one queue per guest CPU         one fio job, so few queues
 Flush                           fsync, which gives zero or more Flushes
```

To check a replay, capture it with `io_trace` and convert that trace
too. Compare `bytes read` and `bytes written` of the two reports. The
command counts and the `sizes` lines can differ for the reasons above.

## I/O shapes of an accelerator workload

`hw/femu/scripts/fio/` holds five job files. Each gives the storage side
of one workload phase. CPU threads in the guest submit the I/O, so the
guest needs no accelerator.

| Job file | Phase | Shape |
| --- | --- | --- |
| `gpu-model-load.fio` | model and dataset load | 4 jobs, sequential 1 MiB reads, one quarter of the namespace each |
| `gpu-small-random-read.fio` | vector search, graph sampling | 8 jobs, random reads of 512 B and 4 KiB, bursts of 64 with a pause |
| `gpu-checkpoint-burst.fio` | checkpoint | 1 MiB sequential writes for 2 s, then a pause of 8 s |
| `gpu-kv-offload.fio` | KV-cache offload | entries of 4 MiB (32 commands of 128 KiB), one store job and one load job |
| `gpu-kv-offload-fdp.fio` | KV-cache offload of two tenants | the same entries; a short-lived and a long-lived store job, each with its own placement index, and one load job |

```sh
sudo FEMU_DEV=/dev/ng0n1 fio gpu-small-random-read.fio
```

`FEMU_DEV` names the NVMe generic character device of the namespace.
The jobs use the `io_uring_cmd` engine, which needs Linux 5.19 or newer
and fio 3.31 or newer. `gpu-checkpoint-burst.fio` needs fio 3.34 or
newer for its first pause. `gpu-small-random-read.fio` needs a 512-byte
LBA format. The write jobs write over the namespace.

`gpu-kv-offload-fdp.fio` also needs `FEMU_FDP` (1 for placement, 0 for
none) and `FEMU_RUNTIME` (seconds). With `FEMU_FDP=1` it needs fio 3.34
or newer and an FDP namespace. The
[KV-cache offload recipe](../recipes/kv-cache-offload.md) runs it with a
prefill and reads the counters.

The shapes come from public descriptions of these workloads. They are
not traces of a real accelerator.

### The rate limit

Each job has a fixed `rate` or `rate_iops` option.

```
 question                               tool
 -------------------------------------  --------------------------------
 how does the SSD model behave under    these job files, with the limit
 this shape? (read time, GC, WAF,
 tail latency, read disturb)
 how fast is the emulator?              not these job files
```

FEMU gives each command a completion time from the SSD model. That time
is valid only while the host keeps up with the load. The limit keeps the
mean load low. It does not prove that the host kept up in each burst.
Check that for each run: [timing model](../concepts/timing-model.md).

Rules:

- Do not remove or raise a limit to report a speed of the emulator.
- Report results of the device model: latency percentiles, WAF, GC
  counts, read reclaim counts.
- State the effective configuration with each result.
  `femu-config-check.py` reports it.

A limit caps the mean rate. After a pause, fio lets the start of a burst
run without a delay. The pauses in the burst jobs keep the mean rate
below the limit, so each burst stays whole.

`check-fio-jobs.py` checks that each job has a limit for each direction
it uses. CI runs it. It reads the files only, so it does not see an
option on the fio command line.

```sh
python3 hw/femu/scripts/check-fio-jobs.py
```

### Check a shape

Run a job with `io_trace=FILE` on the device, then give the trace to
`femu-trace2fio.py`.

| Job file | What the report must show |
| --- | --- |
| `gpu-model-load.fio` | reads only; all in the `1048576` size line; a high sequential share |
| `gpu-small-random-read.fio` | reads only; half in the `512` line and half in the `4096` line; per queue, a largest burst that is a multiple of 64 |
| `gpu-checkpoint-burst.fio` | writes only; a depth profile that falls to 0 in the pause |
| `gpu-kv-offload.fio` | reads and writes in the `131072` line; a sequential share near 31 of 32 for each kind, when each job stays on one CPU |
| `gpu-kv-offload-fdp.fio` | the same as `gpu-kv-offload.fio` |

A queue is not a job. The guest maps each CPU to a queue, so two jobs
on one CPU share a queue, and a job that moves changes its queue. Give
the guest 8 CPUs or more and the device `queues=8` or more for the small
read job. Add `cpus_allowed_policy=split` with `cpus_allowed=0-7` to the
job when each job must keep one queue.

## Related pages

- [Workload recipes](../recipes/README.md): DLIO, DiskANN and KV-cache
  offload on a FEMU device.
- [Measuring](measuring.md): counters, the I/O trace format and steady
  state.
- [Scripts and tools](../reference/scripts.md): each script and its
  arguments.
- [Timing model](../concepts/timing-model.md): when a completion time is
  valid.
