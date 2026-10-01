# Tutorial 03: zoned namespaces

You start a guest with a Zoned Namespace (ZNS) SSD, read its zone report,
move one zone through every state by hand, append data and let the device
pick the address, hit the open-zone limit on purpose, then write with
fio's zoned mode and mount zonefs. It takes about fifteen minutes.

You need: the variables from [Before you start](README.md#before-you-start)
and about 5 GiB of free host memory. The guest image from
`make-guest-image.sh` has a kernel with ZNS support (Linux 6.8), nvme-cli,
`blkzone` and fio. The zonefs step installs two more packages, so the
guest needs network access.

## Background

A zoned namespace is divided into zones. Each zone has a write pointer:
the host writes the zone only at its write pointer (or with Zone Append,
where the device picks the address), and must reset the zone before it
writes it again. The device runs no garbage collection; reclaiming space is
the host's job. Each zone is in one state, and these are the moves you make in this
tutorial:

| From | Event | To |
| --- | --- | --- |
| Empty or Closed | a write or an append | Implicitly Opened |
| Empty, Implicitly Opened or Closed | Open Zone | Explicitly Opened |
| Implicitly or Explicitly Opened | Close Zone | Closed |
| Opened or Closed | Finish Zone, or the write pointer reaches the zone capacity | Full |
| Opened, Closed or Full | Reset Zone | Empty |

Opened zones count against Maximum Open Resources, and opened plus closed
zones against Maximum Active Resources. The
[ZNS design page](../design/zns.md#zone-state-machine) has the full state
machine.

## 1. Start the guest (on the host)

<!-- femu-example: tut03-boot -->
```bash
./qemu-system-x86_64 -name femu-tut03,debug-threads=on \
    -enable-kvm -cpu host -smp 4 -m 4G \
    -device virtio-scsi-pci,id=scsi0 -device scsi-hd,drive=hd0 \
    -drive file=$OSIMGF,if=none,cache=none,format=qcow2,id=hd0 \
    -net user,hostfwd=tcp::$SSH_PORT-:22 -net nic,model=virtio \
    -device femu,femu_mode=3,devsz_mb=1024,zns_max_open=4,zns_max_active=6 \
    -nographic
```

| Option | Meaning |
| --- | --- |
| `femu_mode=3` | ZNS |
| `devsz_mb=1024` | a 1 GiB namespace |
| `zns_max_open=4`, `zns_max_active=6` | at most 4 open zones and 6 open or closed ones; 0, the default, means no limit |

With the default ZNS geometry (2 channels, 4 LUNs, 2 planes, 32 blocks)
the namespace has 16 zones; their size grows with the namespace, so 1 GiB
gives 64 MiB zones ([zone size](../modes/zns.md#zone-size-and-zone-count)).
The default cell type is QLC.

## 2. Check that Linux sees a zoned device

Open a shell in the guest with `./run-guest-ssh.sh`, then:

```sh
sudo nvme list
cd /sys/block/nvme0n1/queue
cat zoned nr_zones chunk_sectors max_open_zones max_active_zones
cd
```

```text
/dev/nvme0n1          /dev/ng0n1            vZNSSD0              FEMU ZMS-SSD Controller [by Misao]       0x1          1.07  GB /   1.07  GB    512   B +  0 B   1.0
host-managed
16
131072
4
6
```

`chunk_sectors` is the zone size in 512-byte sectors: 131072 x 512 bytes =
64 MiB. The ZNS Identify Namespace data reports the limits 0's based:

```sh
sudo nvme zns id-ns /dev/nvme0n1 | grep -E '^(mar|mor) '
```

```text
mar     : 0x5
mor     : 0x3
```

## 3. Read the zone report

```sh
sudo nvme zns report-zones /dev/nvme0n1 -d 3
sudo blkzone report -c 3 /dev/nvme0n1
```

```text
nr_zones: 16
SLBA: 0          WP: 0          Cap: 0x20000    State: 0x10 Type: 0x2  Attrs: 0    AttrsInfo: 0
SLBA: 0x20000    WP: 0x20000    Cap: 0x20000    State: 0x10 Type: 0x2  Attrs: 0    AttrsInfo: 0
SLBA: 0x40000    WP: 0x40000    Cap: 0x20000    State: 0x10 Type: 0x2  Attrs: 0    AttrsInfo: 0
  start: 0x000000000, len 0x020000, cap 0x020000, wptr 0x000000 reset:0 non-seq:0, zcond: 1(em) [type: 2(SEQ_WRITE_REQUIRED)]
  start: 0x000020000, len 0x020000, cap 0x020000, wptr 0x000000 reset:0 non-seq:0, zcond: 1(em) [type: 2(SEQ_WRITE_REQUIRED)]
  start: 0x000040000, len 0x020000, cap 0x020000, wptr 0x000000 reset:0 non-seq:0, zcond: 1(em) [type: 2(SEQ_WRITE_REQUIRED)]
```

nvme-cli prints the write pointer as an absolute LBA, `blkzone` relative
to the zone start. The two tools name the states differently:

| State | nvme-cli `State` | `blkzone` `zcond` |
| --- | --- | --- |
| Empty | 0x10 | 1 (em) |
| Implicitly Opened | 0x20 | 2 (oi) |
| Explicitly Opened | 0x30 | 3 (oe) |
| Closed | 0x40 | 4 (cl) |
| Read Only | 0xd0 | 13 (ro) |
| Full | 0xe0 | 14 (fu) |
| Offline | 0xf0 | 15 (of) |

Every zone is sequential-write-required (type 2) and starts Empty.

## 4. Append, then move a zone through its states

Append 4 KiB to zone 0 twice. The device writes at the write pointer and
reports where the data went:

```sh
head -c 4096 /dev/urandom > data.bin
sudo nvme zns zone-append /dev/nvme0n1 -s 0 -z 4096 -d data.bin
sudo nvme zns zone-append /dev/nvme0n1 -s 0 -z 4096 -d data.bin
sudo nvme zns report-zones /dev/nvme0n1 -d 1
```

```text
Success appended data to LBA 0
Success appended data to LBA 8
nr_zones: 16
SLBA: 0          WP: 0x10       Cap: 0x20000    State: 0x20 Type: 0x2  Attrs: 0    AttrsInfo: 0
```

The write pointer moved 16 blocks (2 x 4 KiB), and the write opened the
zone implicitly (0x20). Read the data back and compare:

```sh
sudo nvme read /dev/nvme0n1 -s 0 -c 7 -z 4096 -d out.bin
cmp data.bin out.bin && echo same
```

Close it, then explicitly open four other zones, and try a fifth:

```sh
sudo nvme zns close-zone /dev/nvme0n1 -s 0
for z in 1 2 3 4; do
    sudo nvme zns open-zone /dev/nvme0n1 -s $((z * 0x20000))
done
sudo nvme zns open-zone /dev/nvme0n1 -s 0xa0000
```

```text
zns-close-zone: Success, action:1 zone:0 all:0 zcapc:0 nsid:1
zns-open-zone: Success zone slba:20000 nsid:1
zns-open-zone: Success zone slba:40000 nsid:1
zns-open-zone: Success zone slba:60000 nsid:1
zns-open-zone: Success zone slba:80000 nsid:1
NVMe status: Too Many Open Zones: The controller does not allow additional open zones(0x41be)
```

Four zones are open, the limit `zns_max_open=4` allows no fifth. Zone 0 is
Closed (0x40): it no longer counts as open, but it still counts as active.
Finish one of the open zones, which makes it Full without writing it:

```sh
sudo nvme zns finish-zone /dev/nvme0n1 -s 0x20000
sudo nvme zns report-zones /dev/nvme0n1 -d 2 | tail -1
```

```text
zns-finish-zone: Success, action:2 zone:20000 all:0 zcapc:0 nsid:1
SLBA: 0x20000    WP: 0xffffffffffffffff Cap: 0x20000    State: 0xe0 Type: 0x2  Attrs: 0    AttrsInfo: 0
```

A Full zone has no write pointer; it reads as all ones. Reset every zone
to start over:

```sh
sudo nvme zns reset-zone /dev/nvme0n1 -a
```

## 5. Write with fio's zoned mode

`--zonemode=zbd` makes fio write each zone at its write pointer and
respect the open-zone limit:

```sh
sudo fio --name=zw --filename=/dev/nvme0n1 --direct=1 --ioengine=psync \
    --zonemode=zbd --rw=write --bs=128k --size=256M
sudo blkzone report -c 5 /dev/nvme0n1
```

```text
  write: IOPS=650, BW=81.3MiB/s (85.3MB/s)(256MiB/3148msec); 0 zone resets
  start: 0x000000000, len 0x020000, cap 0x020000, wptr 0x020000 reset:0 non-seq:0, zcond:14(fu) [type: 2(SEQ_WRITE_REQUIRED)]
  start: 0x000020000, len 0x020000, cap 0x020000, wptr 0x020000 reset:0 non-seq:0, zcond:14(fu) [type: 2(SEQ_WRITE_REQUIRED)]
  start: 0x000040000, len 0x020000, cap 0x020000, wptr 0x020000 reset:0 non-seq:0, zcond:14(fu) [type: 2(SEQ_WRITE_REQUIRED)]
  start: 0x000060000, len 0x020000, cap 0x020000, wptr 0x020000 reset:0 non-seq:0, zcond:14(fu) [type: 2(SEQ_WRITE_REQUIRED)]
  start: 0x000080000, len 0x020000, cap 0x020000, wptr 0x000000 reset:0 non-seq:0, zcond: 1(em) [type: 2(SEQ_WRITE_REQUIRED)]
```

256 MiB filled four 64 MiB zones, which are now Full. Read them back at
random:

```sh
sudo fio --name=zr --filename=/dev/nvme0n1 --direct=1 --ioengine=psync \
    --zonemode=zbd --rw=randread --bs=4k --size=256M --runtime=8 --time_based
```

The average completion latency is about 89 us: the built-in QLC page read
time of 85 us plus overhead. A ZNS write goes to a zone write cache at 1 us
per 4 KiB page; the write that fills the cache pays for programming it
([write cache](../design/zns.md#write-cache)). Reset the zones before the
next step:

```sh
sudo blkzone reset /dev/nvme0n1
```

## 6. Mount zonefs

zonefs exposes each zone as a file. The cloud kernel ships the module in
`linux-modules-extra`:

```sh
sudo apt-get install -y zonefs-tools linux-modules-extra-$(uname -r)
sudo mkzonefs -f /dev/nvme0n1
sudo modprobe zonefs
sudo mkdir -p /mnt/zonefs
sudo mount -t zonefs /dev/nvme0n1 /mnt/zonefs
ls /mnt/zonefs; ls /mnt/zonefs/seq | wc -l
```

```text
seq
15
```

zonefs keeps its super block in zone 0, and the other 15 zones are the
files `seq/0` to `seq/14`. A file can only grow by appending, with direct
I/O:

```sh
sudo dd if=/dev/urandom of=/mnt/zonefs/seq/0 bs=1M count=8 oflag=direct,append conv=notrunc
ls -l /mnt/zonefs/seq/0
sudo blkzone report -c 2 /dev/nvme0n1
```

```text
8388608 bytes (8.4 MB, 8.0 MiB) copied, 0.109279 s, 76.8 MB/s
-rw-r----- 1 root root 8388608 Oct  1 16:28 /mnt/zonefs/seq/0
  start: 0x000000000, len 0x020000, cap 0x020000, wptr 0x020000 reset:0 non-seq:0, zcond:14(fu) [type: 2(SEQ_WRITE_REQUIRED)]
  start: 0x000020000, len 0x020000, cap 0x020000, wptr 0x004000 reset:0 non-seq:0, zcond: 2(oi) [type: 2(SEQ_WRITE_REQUIRED)]
```

The file size is the zone's write pointer (0x4000 sectors = 8 MiB), and
the zone is implicitly open. Truncating the file to 0 resets the zone:

```sh
sudo truncate -s 0 /mnt/zonefs/seq/0
sudo blkzone report -c 2 /dev/nvme0n1 | tail -1
sudo umount /mnt/zonefs
```

```text
  start: 0x000020000, len 0x020000, cap 0x020000, wptr 0x000000 reset:0 non-seq:0, zcond: 1(em) [type: 2(SEQ_WRITE_REQUIRED)]
```

Do not run `mkfs.ext4` on a zoned namespace: it needs random writes. A
zoned file system such as f2fs also needs a randomly writable device for
its metadata; [tutorial 06](06-multi-namespace.md) shows how to put a
BlackBox namespace next to the zoned one. That combination was not run for
this page.

## What you learned

- A ZNS namespace is a host-managed zoned block device; zone size and
  count follow from the namespace size and the `zns_` geometry.
- Writes and appends open zones implicitly; open, close, finish and reset
  move them by hand; the device enforces the open and active limits.
- fio (`--zonemode=zbd`) and zonefs work on FEMU's ZNS as on real
  hardware.

## Next

- [ZNS mode](../modes/zns.md) covers ZRWA, zone capacity, conventional
  zones and the other options.
- [The ZNS design page](../design/zns.md) explains the zone layout over
  NAND and where time is charged.
- [Tutorial 04](04-fdp.md) shows the other way to let the host place
  data: Flexible Data Placement.
