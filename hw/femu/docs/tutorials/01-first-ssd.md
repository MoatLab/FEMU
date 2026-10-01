# Tutorial 01: your first SSD

You start a guest with a small BlackBox SSD (BBSSD) from a QEMU command
line you write yourself, look at the device the guest sees, measure read
and write latency with fio, and read the write amplification factor (WAF)
from the device. It takes about ten minutes.

The [quick start](../getting-started/quick-start.md) does something
similar with `run-blackbox.sh`, which builds a 12 GiB device. This
tutorial uses a 2 GiB device so that the whole drive can be filled in
seconds, and it explains each option.

You need: a built FEMU and guest image, the variables from
[Before you start](README.md#before-you-start), and about 7 GiB of free
host memory (2 GiB for the device, 4 GiB for the guest).

## 1. Choose the geometry

A BBSSD is NAND flash organised as channels, LUNs (dies) per channel,
planes per LUN, blocks per plane and pages per block. This tutorial uses
4 channels of 4 LUNs, one plane, 128 blocks per plane and the default 256
pages of 4 KiB per block:

```text
NAND     = 4 channels x 4 LUNs x 1 plane x 128 blocks x 256 pages x 4 KiB = 2 GiB
line     = one block on every LUN = 16 blocks = 16 MiB; there are 128 lines
```

A line (a superblock) is the unit garbage collection (GC) reclaims. The
guest must not see all of the NAND: GC needs spare room to move data into.
`op_pcent=25` exposes `NAND / 1.25`, about 1.6 GiB, and keeps the rest as
spare. With `op_pcent` set, `devsz_mb` is ignored and the device is sized
from the geometry.

## 2. Start the guest (on the host)

From `build-femu/`:

<!-- femu-example: tut01-boot -->
```bash
./qemu-system-x86_64 -name femu-tut01,debug-threads=on \
    -enable-kvm -cpu host -smp 4 -m 4G \
    -device virtio-scsi-pci,id=scsi0 -device scsi-hd,drive=hd0 \
    -drive file=$OSIMGF,if=none,cache=none,format=qcow2,id=hd0 \
    -net user,hostfwd=tcp::$SSH_PORT-:22 -net nic,model=virtio \
    -device femu,femu_mode=1,nchs=4,luns_per_ch=4,blks_per_pl=128,op_pcent=25 \
    -nographic
```

Everything except the last `-device` line is an ordinary guest: KVM, 4
vCPUs, 4 GiB of RAM, the guest image on a virtio-scsi disk, and user
networking that forwards `SSH_PORT` to the guest's SSH port.
`debug-threads=on` names FEMU's threads, which
[performance tuning](../guides/performance-tuning.md#threads-and-cores)
needs. The FEMU device:

| Option | Meaning |
| --- | --- |
| `femu_mode=1` | BlackBox mode: the device runs its own FTL, GC and NAND timing |
| `nchs=4,luns_per_ch=4,blks_per_pl=128` | the geometry from step 1; the page size and pages per block keep their defaults |
| `op_pcent=25` | 25% over-provisioning |

Wait for the `femu-guest login:` prompt, about 30 seconds. Leave this
terminal running. To stop QEMU, press `Ctrl-a` then `x`.

## 3. Look at the device

In a second terminal, open a shell in the guest with `./run-guest-ssh.sh`,
then:

```sh
sudo nvme list
```

```text
Node                  Generic               SN                   Model                                    Namespace  Usage                      Format           FW Rev
--------------------- --------------------- -------------------- ---------------------------------------- ---------- -------------------------- ---------------- --------
/dev/nvme0n1          /dev/ng0n1            vSSD0                FEMU BlackBox-SSD Controller             0x1          1.72  GB /   1.72  GB    512   B +  0 B   1.0
```

1.72 GB is 2 GiB / 1.25. The guest's own disk is `/dev/sda`. The
namespace uses 512-byte blocks; `cat /sys/block/nvme0n1/size` prints
`3355443`, the size in 512-byte sectors.

## 4. Read before writing: no NAND time

Measure 4 KiB random reads at queue depth 1 on the empty drive:

```sh
sudo fio --name=rr0 --filename=/dev/nvme0n1 --direct=1 --ioengine=libaio \
    --rw=randread --bs=4k --iodepth=1 --runtime=10 --time_based
```

The median completion latency (`clat` 50.00th) is about 8 us. A page that
was never written has no mapping, so the FTL charges it no NAND read: what
you see is the guest's and FEMU's own overhead. A read benchmark on a fresh
device measures nothing, so always write the range first.

## 5. Fill the drive

Write the whole namespace once, sequentially:

```sh
sudo fio --name=fill --filename=/dev/nvme0n1 --direct=1 --ioengine=libaio \
    --rw=write --bs=128k --iodepth=16
```

```text
  write: IOPS=2499, BW=312MiB/s (328MB/s)(1638MiB/5244msec); 0 zone resets
```

## 6. Read the WAF

The vendor log page C0h holds FEMU's media counters. The first 4 bytes are
the WAF times 1000. The three 8-byte counters from byte 8 are the pages the
host wrote, the pages GC moved, and the pages programmed for the host
([log pages and counters](../reference/log-pages-and-counters.md#vendor-log-page-c0h)):

```sh
sudo nvme get-log /dev/nvme0 --log-id=0xc0 --log-len=512 -b | od -An -t u4 -N 4
sudo nvme get-log /dev/nvme0 --log-id=0xc0 --log-len=512 -b | od -An -t u8 -j 8 -N 24 -w24
```

```text
       1000
               419424                    0               419424
```

The WAF is `(pages programmed + pages GC moved) x 1000 / pages the host
wrote`. 1000 means 1.000: each 4 KiB page the host wrote was programmed
once, and GC has moved nothing. 419424 pages are the 13107 whole 128 KiB
blocks fio wrote.

## 7. Measure written data

Now read the written data at queue depth 1:

```sh
sudo fio --name=rr --filename=/dev/nvme0n1 --direct=1 --ioengine=libaio \
    --rw=randread --bs=4k --iodepth=1 --runtime=15 --time_based
```

```text
    clat percentiles (usec):
     |  1.00th=[   44],  5.00th=[   45], 10.00th=[   45], 20.00th=[   45],
     | 30.00th=[   45], 40.00th=[   45], 50.00th=[   46], 60.00th=[   47],
     | 70.00th=[   48], 80.00th=[   49], 90.00th=[   49], 95.00th=[   50],
     | 99.00th=[   58], 99.50th=[   66], 99.90th=[  116], 99.95th=[  141],
```

The median is 46 us: the default NAND page read time `pg_rd_lat` of 40 us
plus about 6 us of guest and poller overhead. Then random writes:

```sh
sudo fio --name=rw --filename=/dev/nvme0n1 --direct=1 --ioengine=libaio \
    --rw=randwrite --bs=4k --iodepth=1 --runtime=15 --time_based
```

```text
    clat percentiles (usec):
     |  1.00th=[  204],  5.00th=[  206], 10.00th=[  206], 20.00th=[  208],
     | 30.00th=[  208], 40.00th=[  208], 50.00th=[  208], 60.00th=[  210],
     | 70.00th=[  210], 80.00th=[  212], 90.00th=[  215], 95.00th=[  219],
     | 99.00th=[  269], 99.50th=[  297], 99.90th=[54789], 99.95th=[55313],
```

The median is 208 us, the program time `pg_wr_lat` of 200 us plus
overhead. The 99.9th percentile is 55 ms. After the fill, more than 75%
of the lines are in use, so GC is armed. Every overwrite leaves an invalid
page behind, and once a line has 1/8 of its pages invalid, GC reads its
valid pages, programs them elsewhere and erases it. This run gets there
towards its end, and a write that needs a LUN GC is busy with waits for
it. That is why GC shows in the slowest 0.1% and not in the median. Read
the counters again:

```text
       1477
               472826               225792               472826
```

GC has moved 225792 pages for 472826 host pages: WAF 1.477.

## 8. Shut down

```sh
sudo poweroff
```

QEMU exits in the first terminal. The data on the emulated SSD is gone:
FEMU keeps it only in host memory. A guest reboot keeps it.

## What you learned

- A FEMU SSD is one `-device femu` option on an ordinary QEMU command line.
- `op_pcent` sets the spare area directly; the geometry sets the NAND size.
- Unwritten pages cost no NAND time; write before you read.
- Queue depth 1 latency is the NAND time plus a few microseconds of
  overhead; GC shows up in the tail.
- Log page C0h gives the WAF and the page counters since the device
  started.

## Next

- [Tutorial 02](02-gc-and-waf.md) makes GC run on purpose and changes what
  it does.
- [The BlackBox FTL](../design/ftl.md) explains lines, write pointers and
  GC; [NAND media and timing](../design/nand-timing.md) explains where the
  40 and 200 us come from.
- [BlackBox SSD](../modes/blackbox.md) lists every option of the mode.
