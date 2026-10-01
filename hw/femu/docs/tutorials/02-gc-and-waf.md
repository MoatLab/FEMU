# Tutorial 02: garbage collection and write amplification

You make garbage collection (GC) run on a BlackBox SSD, measure the write
amplification factor (WAF) of one run from the counters in log page C0h,
and then change four things and watch the WAF move: the GC threshold, the
over-provisioning, the victim policy, and hot/cold separation. Each
measurement takes under a minute.

You need: [tutorial 01](01-first-ssd.md) done once, the variables from
[Before you start](README.md#before-you-start), and about 7 GiB of free
host memory.

## Background

The FTL writes every host page to a fresh NAND page and marks the old copy
invalid. A line (one block on every LUN) fills up with a mix of valid and
invalid pages. GC picks a victim line, copies its valid pages elsewhere and
erases it. Every copy is a NAND program the host did not ask for, so

```text
WAF = (pages programmed for the host + pages GC copied) / pages the host wrote
```

A WAF of 1 means GC copied nothing. The C0h counters hold the three page
counts since the device started. [The BlackBox FTL](../design/ftl.md#garbage-collection)
describes GC in full; this tutorial needs two facts from it:

- **Background GC** runs after a request once the share of lines in use
  reaches `gc_thres_pcent`. It collects one line at a time, and only a
  line with at least 1/8 of its pages invalid.
- **Forced GC** runs inside a write once the share reaches
  `gc_thres_pcent_high`. It takes the policy's victim however few invalid
  pages it holds, and repeats until enough lines are free.

## 1. The device

Every run in this tutorial uses the drive from tutorial 01, 2 GiB of NAND
in 128 lines of 16 MiB, and changes one or two options:

<!-- femu-example: tut02-base -->
```
-device femu,femu_mode=1,nchs=4,luns_per_ch=4,blks_per_pl=128,op_pcent=25
```

Start QEMU with the command line of
[tutorial 01, step 2](01-first-ssd.md#2-start-the-guest-on-the-host),
with this `-device` line in place of its own. You restart QEMU for every
configuration: the counters, the mapping and the NAND state start from
zero only when QEMU starts.

## 2. The measurement script

In the guest, save this as `waf-run.sh`:

```sh
cat > waf-run.sh <<'EOF'
# Usage: bash waf-run.sh [extra fio options]
c0() {
    sudo nvme get-log /dev/nvme0 --log-id=0xc0 --log-len=512 -b |
        od -An -t u8 -j 8 -N 24 -w24
}
# Optional: GC and NAND operations take no time, so the runs finish in
# seconds. The page counts do not depend on time.
sudo nvme admin-passthru /dev/nvme0 --opcode=0xef --cdw10=2 >/dev/null
sudo nvme admin-passthru /dev/nvme0 --opcode=0xef --cdw10=4 >/dev/null
# 1. Fill the whole drive once.
sudo fio --name=fill --filename=/dev/nvme0n1 --direct=1 --ioengine=libaio \
    --rw=write --bs=128k --iodepth=16 >/dev/null
# 2. Age it: random overwrites until GC is in a steady state.
sudo fio --name=age --filename=/dev/nvme0n1 --direct=1 --ioengine=libaio \
    --rw=randwrite --bs=4k --iodepth=32 --io_size=4G --randrepeat=0 "$@" >/dev/null
# 3. Measure one run as the difference of two counter reads.
c0 > before.txt
sudo fio --name=run --filename=/dev/nvme0n1 --direct=1 --ioengine=libaio \
    --rw=randwrite --bs=4k --iodepth=32 --io_size=4G --randrepeat=0 "$@" >/dev/null
c0 > after.txt
paste before.txt after.txt | awk '{ h = $4 - $1; g = $5 - $2; n = $6 - $3;
    printf "host %d  gc %d  nand %d  WAF %.3f\n", h, g, n, (n + g) / h }'
EOF
```

Three things in it matter:

- **Steady state.** The first pass over a fresh drive copies nothing, so
  its WAF is 1. The script fills the drive, then ages it with 4 GiB of
  random writes (about 2.5 times its size) before it measures.
- **Differences, not totals.** The counters count since QEMU started. The
  script reads them before and after the measured run and divides the
  differences.
- **Time switched off.** Vendor command 0xEF with code 2 makes GC take no
  time and code 4 sets the flat NAND times to 0. GC still copies the same pages,
  so the WAF is unchanged, and a run takes seconds instead of minutes. Code
  3 would restore the built-in times, not the ones on your command line, so
  restart QEMU before you measure latency again
  ([run-time controls](../design/ftl.md#run-time-controls)). Leave the two
  lines out if you want the latency as well.

Run it:

```sh
bash waf-run.sh
```

```text
host 1048576  gc 7357952  nand 1048576  WAF 8.017
```

The measured run wrote 1048576 pages (4 GiB) and GC copied 7.36 million:
eight NAND programs for each host write. That is far more than an SSD with
25% spare should need. The next step shows why.

## 3. The GC threshold

`gc_thres_pcent` defaults to 75. This drive exposes 1 / 1.25 = 80% of its
NAND, so once it is full, more than 75% of its lines always hold data and
background GC never stops. It collects any line that is at least 1/8
invalid, so it takes lines that are still 7/8 valid: it copies 7 valid
pages for each invalid page it frees. Seven GC copies plus the host's own
program per page written is the WAF of 8.

Raise the threshold above the fill level. Restart QEMU for each line,
then run `bash waf-run.sh`:

<!-- femu-example: tut02-threshold -->
```
-device femu,femu_mode=1,nchs=4,luns_per_ch=4,blks_per_pl=128,op_pcent=25,gc_thres_pcent=90

-device femu,femu_mode=1,nchs=4,luns_per_ch=4,blks_per_pl=128,op_pcent=25,gc_thres_pcent=95
```

| `gc_thres_pcent` | WAF |
| --- | --- |
| 75 (default) | 8.017 |
| 90 | 4.590 |
| 95 | 3.273 |

At 95, `gc_thres_pcent` equals `gc_thres_pcent_high` in this
configuration, so background GC starts only where forced GC does. By then the lines hold more invalid pages, and each
collection frees more space per copy. Set `gc_thres_pcent` above the share
of the NAND your namespace fills, or the background GC rate is what you
measure.

## 4. Over-provisioning

Keep `gc_thres_pcent=90` and change `op_pcent`:

<!-- femu-example: tut02-op -->
```
-device femu,femu_mode=1,nchs=4,luns_per_ch=4,blks_per_pl=128,op_pcent=7,gc_thres_pcent=90

-device femu,femu_mode=1,nchs=4,luns_per_ch=4,blks_per_pl=128,op_pcent=15,gc_thres_pcent=90

-device femu,femu_mode=1,nchs=4,luns_per_ch=4,blks_per_pl=128,op_pcent=50,gc_thres_pcent=90

-device femu,femu_mode=1,nchs=4,luns_per_ch=4,blks_per_pl=128,op_pcent=100,gc_thres_pcent=90
```

| `op_pcent` | Share of NAND exposed | WAF |
| --- | --- | --- |
| 7 | 93% | 43.945 |
| 15 | 87% | 8.000 |
| 25 | 80% | 4.590 |
| 50 | 67% | 1.970 |
| 100 | 50% | 1.028 |

Read the table this way:

- At 15% the namespace fills 87% of the NAND. With the open lines and the
  invalid pages on top of that, the share of lines in use stays at the 90%
  threshold, background GC keeps running, and it is the case of step 3
  again: WAF 8.
- At 7% almost no line is free, forced GC runs inside most writes, and it
  takes victims that are nearly all valid. Forced GC has no 1/8 filter, so
  the WAF has no ceiling: 44 programs per host write.
- From 25% up, more spare means emptier victims and a WAF that falls
  towards 1.

FEMU refuses a namespace that leaves GC too few lines at start-up
([the reserve](../design/ftl.md#the-reserve)); 7% is close to the
smallest this geometry accepts.

## 5. The victim policy

Go back to `op_pcent=25` with `gc_thres_pcent=95`, and try each
`gc_policy`:

<!-- femu-example: tut02-policy -->
```
-device femu,femu_mode=1,nchs=4,luns_per_ch=4,blks_per_pl=128,op_pcent=25,gc_thres_pcent=95,gc_policy=greedy

-device femu,femu_mode=1,nchs=4,luns_per_ch=4,blks_per_pl=128,op_pcent=25,gc_thres_pcent=95,gc_policy=fifo

-device femu,femu_mode=1,nchs=4,luns_per_ch=4,blks_per_pl=128,op_pcent=25,gc_thres_pcent=95,gc_policy=random

-device femu,femu_mode=1,nchs=4,luns_per_ch=4,blks_per_pl=128,op_pcent=25,gc_thres_pcent=95,gc_policy=cost-benefit

-device femu,femu_mode=1,nchs=4,luns_per_ch=4,blks_per_pl=128,op_pcent=25,gc_thres_pcent=95,gc_policy=d-choice
```

Run the uniform workload (`bash waf-run.sh`) and a skewed one, where a few
pages take most of the writes:

```sh
bash waf-run.sh --random_distribution=zipf:1.2
```

| `gc_policy` | WAF, uniform | WAF, zipf 1.2 |
| --- | --- | --- |
| `greedy` | 3.277 | 5.961 |
| `fifo` | 3.277 | 6.052 |
| `random` | 5.087 | 6.122 |
| `cost-benefit` | 3.269 | 5.798 |
| `d-choice` | 3.660 | 5.898 |

With uniform writes, every line ages the same way, so the line with the
fewest valid pages is also the oldest, and `greedy`, `fifo` and
`cost-benefit` choose alike. `random` and `d-choice` (best of 4 random
lines) pick worse victims. With skewed writes the WAF is higher for every
policy: hot and cold pages share lines, and each collection copies cold
pages that will not change again. The policy cannot fix that; separating
the data can.

## 6. Hot/cold separation

`hot_cold_sep=on` writes overwrites (pages that already had a mapping) to
their own lines, so hot pages are invalidated together and cold pages stay
together ([hot/cold separation](../design/ftl.md#hotcold-separation)):

<!-- femu-example: tut02-hotcold -->
```
-device femu,femu_mode=1,nchs=4,luns_per_ch=4,blks_per_pl=128,op_pcent=25,gc_thres_pcent=95,hot_cold_sep=on

-device femu,femu_mode=1,nchs=4,luns_per_ch=4,blks_per_pl=128,op_pcent=25,gc_thres_pcent=95,gc_policy=cost-benefit,hot_cold_sep=on
```

| Configuration, zipf 1.2 | WAF |
| --- | --- |
| `greedy` | 5.961 |
| `greedy`, `hot_cold_sep=on` | 2.394 |
| `cost-benefit`, `hot_cold_sep=on` | 1.646 |

Separation more than halves the WAF. With hot and cold data in different
lines, the age term of `cost-benefit` now pays off: it leaves young hot
lines alone until more of their pages are invalid.

## What you learned

- Measure the WAF of a run as the ratio of counter differences, after the
  drive is full and aged.
- Background GC with a threshold below the fill level runs all the time and
  holds the WAF near 8; set `gc_thres_pcent` above the share of NAND you
  expose.
- Spare capacity is the strongest lever. Below a few percent, forced GC
  has no limit.
- Victim policies differ little under uniform writes; under skew, separate
  hot from cold data first.

## Next

- [Tutorial 04](04-fdp.md) lets the host do the separating, with
  Flexible Data Placement.
- [Tutorial 05](05-latency-tuning.md) measures latency instead of page
  counts.
- [Measuring](../guides/measuring.md#write-amplification-and-media-counters-c0h)
  covers the counters and repeatable runs in more depth.
