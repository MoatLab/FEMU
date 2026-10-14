# Measuring

How to read FEMU's counters, measure latency and throughput from the guest,
and get numbers that repeat from run to run. Commands in `sh` blocks run
inside the guest unless they say otherwise. From the host, prefix a single
command with `./run-guest-ssh.sh` as in the
[quick start](../getting-started/quick-start.md); run multi-line blocks in a
shell inside the guest (`./run-guest-ssh.sh` with no arguments).

Before you measure anything, tune the host as in
[performance tuning](performance-tuning.md). Most surprising numbers come
from a FEMU thread that did not get a core.

## What FEMU can tell you

| Source | Read with | Modes | What it holds |
| --- | --- | --- | --- |
| Vendor log page C0h | `nvme get-log --log-id=0xc0` | BlackBox (with or without FDP), CSD, KV | WAF, host, GC and NAND page counts, write buffer hits, read reclaim, log-block merges |
| SMART log | `nvme smart-log` | every NVMe mode | data read and written, command counts, Percentage Used, Available Spare, media errors |
| FDP statistics | `nvme fdp stats` | BlackBox with FDP | host and media bytes written |
| `query-femu`, `query-femu-stages` | QMP on the host, or [`femu-stat.py`](#live-counters-on-the-host-femu-stat) | BlackBox (with or without FDP), ZNS; NAND timing for CSD, KV, OCSSD | host, NAND, GC and pad pages, WAF, line, reclaim unit and zone counts, I/O stage times |
| QOM counters | QMP `qom-get` on the host | `femu-cxl-ssd` | cache hits and misses, media reads, programs and time, direct mapping |
| fio | in the guest | every block mode | latency and throughput as the guest sees them |

ZNS, NoSSD and OCSSD leave the C0h counters at zero. ZNS has no device
garbage collection: the host resets zones.

The guest's own tools show I/O from the guest's side: `iostat -x 1` per
device, `iotop` per process, `dstat -cdn` for CPU, disk and network
together.

## Write amplification and media counters (C0h)

The first 4 bytes of log page C0h are the write amplification factor (WAF)
times 1000. The three 8-byte counters from byte 8 are pages the host wrote,
pages garbage collection moved, and pages programmed for the host:

```sh
sudo nvme get-log /dev/nvme0 --log-id=0xc0 --log-len=512 -b | od -An -t u4 -N 4
sudo nvme get-log /dev/nvme0 --log-id=0xc0 --log-len=512 -b | od -An -t u8 -j 8 -N 24 -w24
```

FEMU computes the WAF as
`(pages programmed + pages GC moved) x 1000 / pages the host wrote`. The
counters are summed over every BlackBox, CSD and KV namespace of the
controller, and they count from the moment QEMU started the device (or
from when namespace management created the namespace). The WAF
in the log is therefore the WAF since start, not the WAF of your last run.
To measure one run, read the counters before and after it and use the
differences:

```sh
c0() {
    sudo nvme get-log /dev/nvme0 --log-id=0xc0 --log-len=512 -b |
        od -An -t u8 -j 8 -N 24 -w24
}
c0 > before.txt
sudo fio --name=run --filename=/dev/nvme0n1 --direct=1 --ioengine=libaio \
    --rw=randwrite --bs=4k --iodepth=32 --size=4G
c0 > after.txt
paste before.txt after.txt | awk '{ h = $4 - $1; g = $5 - $2; n = $6 - $3;
    printf "host %d  gc %d  nand %d  WAF %.3f\n", h, g, n, (n + g) / h }'
```

Pages the write buffer absorbs (`buffer_size`) count as host pages but not
as programmed pages until they leave the buffer, so with a buffer the WAF
of a short run can be below 1. The other fields (read reclaim, write
buffer hits, log-block merges) are listed in
[log pages and counters](../reference/log-pages-and-counters.md#vendor-log-page-c0h).

GC starts when `gc_thres_pcent` (75% by default) of the lines are in use. A
WAF of 1.000 after a run means GC has not run yet, or found no valid pages
to move. To make GC run, write more than the free space, as in
[the BlackBox guide](../modes/blackbox.md#use-it-from-the-guest).

## SMART and FDP statistics

```sh
sudo nvme smart-log /dev/nvme0
```

FEMU fills these SMART fields:

- `data_units_read`, `data_units_written`: thousands of 512-byte units the
  host moved, rounded up.
- `host_read_commands`, `host_write_commands`.
- `percentage_used`: wear of the most worn namespace, from erase counts and
  `pe_cycles_rated` (or the rating of `nand_cell_type`); 0 when neither is
  set.
- `available_spare`: the worst namespace, from `nand_bad_blocks`.
- `media_errors`, `num_err_log_entries`, `temperature` (the `temperature`
  property), power-on hours and unsafe shutdowns.

With FDP, the endurance group statistics give host and media bytes written.
Their ratio is the WAF over the endurance group, every FDP namespace of the
subsystem:

```sh
sudo nvme fdp stats /dev/nvme0 -e 1
```

## Live counters on the host: femu-stat

`hw/femu/scripts/femu-stat.py` shows the FTL counters of a running VM from
the host, like `top`. It needs no guest tools. It polls the QMP commands
[`query-femu`](../reference/query-femu.md) and
[`query-femu-stages`](../reference/query-femu.md#io-stage-times-query-femu-stages)
on the QMP socket of QEMU. It never resets the counts.

```
 femu-stat.py --connect--> QMP socket of QEMU
      every --interval s:  query-femu          per namespace state
                           query-femu-stages   I/O stage histograms
      this sample - last sample --> view (or one JSON line)
```

Start QEMU with a QMP socket. `io_stages=on` adds the stage times:

<!-- femu-example: femu-stat-qmp -->
```
-device femu,id=femu0,devsz_mb=1024,femu_mode=1,io_stages=on -qmp unix:/tmp/femu-qmp.sock,server=on,wait=off
```

Then, on the host:

```sh
python3 hw/femu/scripts/femu-stat.py /tmp/femu-qmp.sock
python3 hw/femu/scripts/femu-stat.py /tmp/femu-qmp.sock --once
python3 hw/femu/scripts/femu-stat.py localhost:4444 --json --count 60 > stat.jsonl
```

This is a BlackBox namespace after the guest wrote 200 pages in one second:

```
femu-stat  2026-10-14T05:40:20  interval 1.00 s  /tmp/femu-qmp.sock
/machine/peripheral/femu0  bbssd
  ns 1 bbssd
    total:    host 264  nand 264  gc 0  pad 0  erases 0
    interval: host +200  nand +200  gc +0  pad +0  erases +0  (host 200.0/s, gc 0.0/s, erases 0.0/s)
    WAF: 1.000 since start, 1.000 interval
    lines: free 255 of 256, victim 0, full 0, retired 0, spare 0
    media: bus phases not charged
  stages (interval):
    stage          count      mean         p50         p99      max*
    submit           200     2.4us     <=2.0us     <=8.2us    41.0us
    ftl              200     829ns     <=1.0us     <=2.0us    94.9ms
    hold             200   196.8us   <=197.8us   <=197.8us   197.8us
    post-delay       200     235ns     <=255ns     <=1.0us   274.1us
    total            200   200.2us   <=262.1us   <=262.1us    94.9ms
    past-due         200     235ns     <=255ns     <=1.0us    94.7ms
    * max since the counts were reset; p50 and p99 are bucket bounds
```

What each namespace shows depends on what `query-femu` returns for it:

| Mode | Shown |
| --- | --- |
| `bbssd` | host, NAND, GC and pad pages and block erases, with the change over the interval; host, GC and erase rates; WAF since start and over the interval; line counts |
| `bbssd` with FDP | the same counters, reclaim unit counts, and host and media bytes per handle with the WAF of each handle over the interval |
| `znssd` | zone counts by state, and the open and active zone limits |
| `csd`, `kvssd`, `ocssd` | the NAND bus timing only |
| `nossd`, or a namespace on a `femu-cxl-ssd` medium | the error that `query-femu` gives; the other namespaces still show |
| a mode or counter that the tool does not know | its members by their QMP names |

Read the figures as follows:

- The interval WAF is (NAND + GC + pad pages) / host pages over the
  interval. It is `-` when the host wrote no page in the interval.
- Host pages count NAND pages. A 512-byte write to one page counts as one
  page, so the page rate is not a byte rate.
- p50 and p99 are the bounds of the histogram bucket that holds them. A
  bucket spans a factor of two. The tool caps the upper bound at the
  largest time counted, so a bound can be narrower than its bucket. The
  last bucket has no upper bound of its own; without the cap it shows as
  `>=`.
- `max*` is the largest time since the stage counts were last reset. The
  histograms do not give the largest time of one interval.
- The first sample has no interval. Its figures are totals since the device
  started, or since the last reset of the stage counts.
- A counter that goes down starts a new baseline for its group: the
  namespace counters, the stages, or one FDP handle. This detection is best
  effort. A namespace that is deleted and created again between two samples
  can show a wrong interval.
- Each namespace and each command is a separate copy, so two namespaces can
  show slightly different times. The stage counts of a busy device can
  differ by the commands in flight.
- A `bbssd` namespace reports nothing until the guest enables the
  controller.

Options: `--interval SEC` (default 1), `--count N`, `--once`, `--json`
(one object per sample on one line), `--ns 1,2` (namespaces to show) and
`--path QOMPATH` (one device, repeatable). With `--json`, the keys are the
QMP member names. The tool exits with status 2 when it cannot connect, finds
no `femu` device, or loses the connection. On a terminal it redraws the
screen; in a pipe it prints one block per sample.

## CXL SSD counters

The `femu-cxl-ssd` counters are QOM properties, read on the host through
QMP. Add a QMP socket to the `run-cxlssd.sh` command line
(`-qmp unix:/tmp/qmp.sock,server=on,wait=off`), then on the host, from the
QEMU source tree:

```sh
export QMP_SOCKET=/tmp/qmp.sock
scripts/qmp/qom-get /machine/peripheral/cxlssd.cache-misses
scripts/qmp/qom-get /machine/peripheral/cxlssd.media-time-ns
scripts/qmp/qom-get /machine/peripheral/cxlssd.media-full
```

`cxlssd` is the `id=` that `run-cxlssd.sh` gives the device.

- `stats-reset` clears the cache, prefetch and caching API (`cca-*`) event
  counters. It copies the cache and prefetch counters to the `last-*`
  properties first. It does not clear the media
  counters (`media-reads`, `media-writes`, `media-time-ns`) or the `der-*`
  counters, so measure those as differences between two reads.
- `media-full` must stay 0. A non-zero value means some NAND programs found
  no free page and were not timed, and the run is not valid. The
  over-provisioning rule at realize keeps it at 0.
- `gc-stalls` and `gc-stall-ns` show how often and how long writes waited
  for forced garbage collection. Take differences, as for the media
  counters. `gc-stall-max-ns` is the longest single wait. Waits of a second
  or more come from the NAND timing or queued NAND work; more
  `blocks-per-plane` make them shorter.
- Accesses served through a direct mapping (`der=memslot` or `cylon`) never
  reach QEMU and are not counted as hits.

The full list is in
[runtime properties](../reference/runtime-properties.md#femu-cxl-ssd-cxl-type-3-ssd).

## Latency and throughput with fio

Use `--direct=1` so the guest page cache does not answer for the device.
Report the completion latency (`clat`) percentiles, not only the mean.

### NoSSD

NoSSD has no media time, so it measures FEMU's own path. Unwritten blocks
read as fast as written ones.

```sh
sudo fio --name=lat --filename=/dev/nvme0n1 --direct=1 --ioengine=io_uring \
    --rw=randread --bs=4k --iodepth=1 --runtime=30 --time_based
sudo fio --name=tput --filename=/dev/nvme0n1 --direct=1 --ioengine=io_uring \
    --rw=randread --bs=4k --iodepth=64 --numjobs=4 --group_reporting \
    --runtime=30 --time_based
```

For throughput beyond one poller, see
[pollers and queues](performance-tuning.md#pollers-and-queues).

### BlackBox and CSD

A read of a page that was never written costs no NAND time. Fill the range
first, then read it:

```sh
sudo fio --name=fill --filename=/dev/nvme0n1 --direct=1 --ioengine=libaio \
    --rw=write --bs=128k --iodepth=16 --size=4G
sudo fio --name=rr --filename=/dev/nvme0n1 --direct=1 --ioengine=libaio \
    --rw=randread --bs=4k --iodepth=1 --size=4G --runtime=30 --time_based
```

On an idle device at queue depth 1, a 4 KiB read takes about `pg_rd_lat`
(40 us by default) plus the guest's and the poller's overhead, and a 4 KiB
write about `pg_wr_lat` (200 us) when there is no write buffer. Measure the
overhead on a NoSSD device with the same guest and subtract it.

To see GC in the latency, age the device first: random writes over the
whole namespace, several times, until the C0h WAF stops rising. Then
measure. The tail percentiles (`clat` 99th and above) show GC; the median
mostly does not.

### ZNS

Write sequentially inside zones, and reset the zones between runs:

```sh
sudo fio --name=zns --filename=/dev/nvme0n1 --direct=1 --ioengine=psync \
    --zonemode=zbd --rw=write --bs=128k --size=1G
sudo fio --name=zr --filename=/dev/nvme0n1 --direct=1 --ioengine=psync \
    --zonemode=zbd --rw=randread --bs=4k --size=1G --runtime=30 --time_based
sudo blkzone reset /dev/nvme0n1
```

A write costs 1 us per 4 KiB page while it fits in the zone's write cache;
the write that fills the cache pays for programming it
([timing model](../concepts/timing-model.md#zns-write-cache)).

### FDP

fio places data with its `io_uring_cmd` engine on the generic node. Run the
same job with and without `--fdp=1` and compare the WAF:

```sh
sudo fio --name=fdp --filename=/dev/ng0n1 --ioengine=io_uring_cmd --cmd_type=nvme \
    --fdp=1 --fdp_pli=0,1,2,3 --rw=randwrite --bs=4k --iodepth=16 --size=4G
```

### KV, OCSSD and CXL

- KV has no block device, and fio has no key-value engine. Time the
  passthrough commands in your own program; `kv-probe.c` is a starting
  point ([KV guide](../modes/kvssd.md#with-kv-probe)).
- OCSSD needs a guest kernel older than 5.15 with pblk, or SPDK
  ([OCSSD guide](../modes/ocssd.md)).
- For the CXL SSD, run your workload on the DAX device or NUMA node of the
  region ([CXL SSD guide](../modes/cxl-ssd.md#creating-the-region-in-the-guest)),
  and read the QOM counters above before and after.

## Repeatable numbers

1. **Fix the host.** Pin vCPUs, pollers and the FTL thread to their own
   cores, set the CPU frequency policy to performance, and keep other work
   off those cores ([performance tuning](performance-tuning.md)).
2. **Record the setup.** The FEMU commit, the `-device` line
   (`run-blackbox.sh`, `run-blackbox-fdp.sh` and `run-csd.sh` print it;
   `DRY_RUN=1 ../femu-scripts/run-cxlssd.sh` prints the CXL command), the guest kernel and the fio job file. A number without these
   cannot be compared.
3. **Start from a known state.** Restart QEMU between configurations. The
   device memory and every counter start from zero when QEMU starts; a
   guest reboot or controller reset keeps both. A namespace created with
   namespace management starts its counters at zero, and deleting one
   removes its counts from C0h. Then precondition: fill the range you will read,
   and for steady-state write numbers, overwrite at random until the WAF
   stops changing.
4. **Measure intervals, not totals.** Read C0h, SMART or the QOM counters
   before and after each run and use the differences.
5. **Run long enough, more than once.** Use `--time_based` with a
   `--ramp_time`, run each point at least three times, and report the median
   and the spread.
6. **Check FEMU kept up.** On a BlackBox controller, vendor command 0xEF
   with CDW10 5 prints to QEMU's console how many completions were posted 20
   us or more after they were due, out of all completions, and resets both
   counts. `run-blackbox.sh` copies the console to `build-femu/log`. Its
   standard output goes through a pipe there, so the line can appear only
   later; put `stdbuf -oL` in front of `./qemu-system-x86_64` on the
   launcher's `sudo` line to see it at once. Reset the counts before a run,
   read them after:

   ```sh
   sudo nvme admin-passthru /dev/nvme0 --opcode=0xef --cdw10=5
   ```

   The line ends with the two counts as `A/B`. If A is more than a small
   share of B, the pollers did not get enough CPU and the latencies are
   longer than the model.
7. **Keep the timing switches in mind.** 0xEF codes 2 and 4 turn GC time and
   NAND time off until you turn them back on with 1 and 3, and code 3
   restores the built-in times, not the ones on your command line
   ([timing model](../concepts/timing-model.md#changing-timing-at-run-time)).
   Restart QEMU after using them.

## Related pages

- [Timing model](../concepts/timing-model.md)
- [Log pages and counters](../reference/log-pages-and-counters.md)
- [Runtime properties](../reference/runtime-properties.md)
- [Performance tuning](performance-tuning.md)

Related issues: #7, #15, #92, #130, #137, #151.
