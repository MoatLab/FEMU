# Tutorial 05: latency tuning

You change the parts of FEMU's timing model one at a time: the flat NAND
times, the cell type, the channel bus, the host link and the controller
firmware cost. For each one you predict the effect, measure it with fio,
and compare. It takes about twenty minutes.

You need: [tutorial 01](01-first-ssd.md), the variables from
[Before you start](README.md#before-you-start), and about 5 GiB of free
host memory. Read [performance tuning](../guides/performance-tuning.md)
first if you want numbers that repeat to the microsecond: a poller or FTL
thread that has to share a core adds delay the model did not ask for.

## Background

FEMU copies the data of a command at once, computes when the command would
have finished on the emulated device, and posts the completion no earlier
than that ([the timing model](../concepts/timing-model.md#compute-then-hold)).
A queue depth 1 latency is therefore the model's time plus a fixed
overhead of the guest and of FEMU itself. Each step below changes one term
of the model; [NAND media and timing](../design/nand-timing.md) has the
formulas.

## 1. The device and the measurement

Every run uses a small BlackBox SSD, 512 MiB of NAND in 2 channels of 4
LUNs, and adds one option to it:

<!-- femu-example: tut05-base -->
```
-device femu,femu_mode=1,nchs=2,luns_per_ch=4,blks_per_pl=64,op_pcent=25
```

Start QEMU with the command line of
[tutorial 01, step 2](01-first-ssd.md#2-start-the-guest-on-the-host) and
this `-device` line, restarting QEMU for each configuration. In the guest,
fill the first 256 MiB (a read of a page never written costs no NAND
time), then run four measurements:

```sh
sudo fio --name=fill --filename=/dev/nvme0n1 --direct=1 --ioengine=libaio \
    --rw=write --bs=128k --iodepth=16 --size=256M
F="--filename=/dev/nvme0n1 --direct=1 --ioengine=libaio --size=256M --runtime=8 --time_based"
sudo fio --name=rd4k   $F --rw=randread  --bs=4k   --iodepth=1
sudo fio --name=wr4k   $F --rw=randwrite --bs=4k   --iodepth=1
sudo fio --name=rd128k $F --rw=randread  --bs=128k --iodepth=1
sudo fio --name=qd32   $F --rw=randread  --bs=4k   --iodepth=32
```

Read the median (`clat` 50.00th percentile) of the first three and the
IOPS of the last. The writes stay inside 256 MiB of a 410 MiB namespace,
so garbage collection does not run.

## 2. The baseline

With the default timing (40 us read, 200 us program, no channel bus):

| Test | Result |
| --- | --- |
| 4 KiB read, QD1 | 44.3 us |
| 4 KiB write, QD1 | 203.8 us |
| 128 KiB read, QD1 | 288.8 us |
| 4 KiB read, QD32 | 176,880 IOPS |

A 4 KiB read is `pg_rd_lat` plus about 4 us. A 128 KiB read is 32 pages.
The FTL spreads consecutive pages over the channels and then the LUNs, so
the 32 pages sit on all 8 LUNs, 4 each, and the LUNs work in parallel: the
read costs far less than 32 x 40 us. At queue depth 32, 8 LUNs reading in
parallel allow at most 8 / 40 us = 200,000 reads per second; FEMU delivers
88% of that.

## 3. Flat NAND times

<!-- femu-example: tut05-flat -->
```
-device femu,femu_mode=1,nchs=2,luns_per_ch=4,blks_per_pl=64,op_pcent=25,pg_rd_lat=80000,pg_wr_lat=400000
```

Prediction: reads and writes take 40 us and 200 us longer, and QD32
throughput halves.

| Test | Baseline | 80 us / 400 us |
| --- | --- | --- |
| 4 KiB read, QD1 | 44.3 us | 84.5 us |
| 4 KiB write, QD1 | 203.8 us | 423.9 us |
| 4 KiB read, QD32 | 176,880 IOPS | 89,317 IOPS |

## 4. Cell type

`nand_cell_type` replaces the flat times with built-in tables that give
each page type in a wordline its own time
([cell types](../design/nand-timing.md#cell-types-and-page-types)). TLC
(3) has lower, center and upper pages read in 56.5, 77.5 and 106 us:

<!-- femu-example: tut05-tlc -->
```
-device femu,femu_mode=1,nchs=2,luns_per_ch=4,blks_per_pl=64,op_pcent=25,nand_cell_type=3
```

| Test | Baseline | TLC |
| --- | --- | --- |
| 4 KiB read, QD1 | 44.3 us | 81.4 us |
| 4 KiB read, QD1, 99th percentile | 52.0 us | 114.2 us |
| 4 KiB write, QD1 | 203.8 us | 2310.1 us |
| 4 KiB read, QD32 | 176,880 IOPS | 89,449 IOPS |

The read median sits near the average of the three page types, and the
99th percentile near the upper page. TLC programs take milliseconds.
`pg_rd_lat`, `pg_wr_lat` and `blk_er_lat` have no effect while
`nand_cell_type` is set.

## 5. The channel bus

By default, moving a page between controller and NAND takes no time. Any
non-zero bus phase turns the channel bus on; `pg_xfer_lat` is the data
transfer per page, and transfers on one channel run one at a time:

<!-- femu-example: tut05-bus -->
```
-device femu,femu_mode=1,nchs=2,luns_per_ch=4,blks_per_pl=64,op_pcent=25,pg_xfer_lat=20000
```

| Test | Baseline | 20 us transfer |
| --- | --- | --- |
| 4 KiB read, QD1 | 44.3 us | 63.7 us |
| 128 KiB read, QD1 | 288.8 us | 432.1 us |
| 4 KiB read, QD32 | 176,880 IOPS | 98,056 IOPS |

A single page read gains exactly one transfer. Under load the two channels
become the limit: each moves one page per 20 us, 100,000 pages per second
for both, which is where QD32 lands.

## 6. The host link

`pcie_bandwidth_mbps` charges each Read and Write its size divided by the
link bandwidth, on one queue per direction
([host link](../design/nand-timing.md#host-link-and-firmware-cpu)):

<!-- femu-example: tut05-link -->
```
-device femu,femu_mode=1,nchs=2,luns_per_ch=4,blks_per_pl=64,op_pcent=25,pcie_bandwidth_mbps=1000
```

| Test | Baseline | 1000 MB/s link |
| --- | --- | --- |
| 4 KiB read, QD1 | 44.3 us | 47.9 us |
| 128 KiB read, QD1 | 288.8 us | 432.1 us |

128 KiB at 1000 MB/s is 131 us, and the 128 KiB read grew by 143 us. A
4 KiB read pays 4 us. `pcie_prop_delay_ns` adds a fixed delay on top.

## 7. Controller firmware

`fw_cpu_ns` charges a fixed cost per Read, Write and Zone Append on one
modelled controller core, so commands queue behind each other there:

<!-- femu-example: tut05-fw -->
```
-device femu,femu_mode=1,nchs=2,luns_per_ch=4,blks_per_pl=64,op_pcent=25,fw_cpu_ns=20000
```

| Test | Baseline | 20 us firmware |
| --- | --- | --- |
| 4 KiB read, QD1 | 44.3 us | 63.7 us |
| 4 KiB write, QD1 | 203.8 us | 230.4 us |
| 4 KiB read, QD32 | 176,880 IOPS | 49,534 IOPS |

At queue depth 1 the cost simply adds. Under load one core finishes one
command per 20 us, 50,000 per second, and that becomes the limit no matter
how many LUNs the NAND has.

## What you learned

- Queue depth 1 latency is the modelled time plus a few microseconds; each
  timing option moves it by what you configured.
- Throughput is set by whichever resource saturates first: LUNs, channels
  with the bus on, or the firmware core.
- `nand_cell_type` gives a spread of read times rather than one value.

The numbers above come from one run per configuration on a 20-core host
where other work was running, so expect yours to differ by a few
microseconds. The relations between them should hold.

## Next

- [NAND media and timing](../design/nand-timing.md) has the rules these
  measurements follow, including program suspend and ECC read time.
- [Measuring](../guides/measuring.md#latency-and-throughput-with-fio) and
  [performance tuning](../guides/performance-tuning.md) explain how to pin
  FEMU's threads and get repeatable numbers.
- [Tutorial 06](06-multi-namespace.md) puts several modes on one
  controller.
