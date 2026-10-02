# Tutorial 06: several namespaces, several modes

You start one FEMU controller with four namespaces, each in a different
mode: a BlackBox SSD, a zoned namespace, a NoSSD namespace with no media
timing, and a key-value namespace. You find each one in the guest, use it,
and see which counters belong to which. It takes about ten minutes.

You need: the variables from [Before you start](README.md#before-you-start)
and about 6 GiB of free host memory. Tutorials [01](01-first-ssd.md),
[03](03-zns.md) and [07](07-kv.md) explain each mode on its own.

## Background

A controller's `femu_mode` sets its default mode. `namespaces` sets how
many namespaces exist from boot, `namespace_sizes` how big each is (the
default splits `devsz_mb` evenly), and `namespace_modes` the mode of each.
The namespaces are packed one after another in the controller's memory.
Each BlackBox namespace gets its own FTL built from the whole NAND
geometry; each ZNS namespace builds its own zones; each KV namespace has
its own key space
([namespaces design page](../design/namespaces.md#per-namespace-modes)).

## 1. Start the guest (on the host)

<!-- femu-example: tut06-boot -->
```bash
./qemu-system-x86_64 -name femu-tut06,debug-threads=on \
    -enable-kvm -cpu host -smp 4 -m 4G \
    -device virtio-scsi-pci,id=scsi0 -device scsi-hd,drive=hd0 \
    -drive file=$OSIMGF,if=none,cache=none,format=qcow2,id=hd0 \
    -net user,hostfwd=tcp::$SSH_PORT-:22 -net nic,model=virtio \
    -device femu,femu_mode=1,devsz_mb=2048,namespaces=4,namespace_modes=bbssd,,znssd,,nossd,,kvssd \
    -nographic
```

A comma inside a property value is written twice on the QEMU command
line, so `namespace_modes=bbssd,,znssd,,nossd,,kvssd` is the list
`bbssd,znssd,nossd,kvssd`. A single comma would end the property, and QEMU
would read `znssd` as the name of the next one. The 2 GiB backend is split
into four 512 MiB namespaces.

## 2. Find the namespaces

In the guest (`./run-guest-ssh.sh`):

```sh
sudo nvme list
sudo nvme list-ns /dev/nvme0
```

```text
Node                  Generic               SN                   Model                                    Namespace  Usage                      Format           FW Rev
--------------------- --------------------- -------------------- ---------------------------------------- ---------- -------------------------- ---------------- --------
/dev/nvme0n1          /dev/ng0n1            vSSD0                FEMU BlackBox-SSD Controller             0x1        536.87  MB / 536.87  MB    512   B +  0 B   1.0
/dev/nvme0n2          /dev/ng0n2            vSSD0                FEMU BlackBox-SSD Controller             0x2        536.87  MB / 536.87  MB    512   B +  0 B   1.0
/dev/nvme0n3          /dev/ng0n3            vSSD0                FEMU BlackBox-SSD Controller             0x3        536.87  MB / 536.87  MB    512   B +  0 B   1.0
nvme0n4               /dev/ng0n4            vSSD0                FEMU BlackBox-SSD Controller             0x4        536.87  MB /   0.00   B    512   B +  0 B   1.0
[   0]:0x1
[   1]:0x2
[   2]:0x3
[   3]:0x4
```

Namespaces 1 to 3 have block devices. Namespace 4, the KV one, has only
the generic character device `/dev/ng0n4`: Linux has no block driver for
the key-value command set.

The model and serial number are the controller's, and they come from its
own `femu_mode` (BlackBox here), not from the namespaces' modes. Tell
the namespaces apart by what they report:

```sh
for n in 1 2 3; do
    echo nvme0n$n $(cat /sys/block/nvme0n$n/queue/zoned) $(cat /sys/block/nvme0n$n/size)
done
```

```text
nvme0n1 none 1048576
nvme0n2 host-managed 1048576
nvme0n3 none 1048576
```

Namespace 2 is the zoned one. Each is 1048576 sectors of 512 bytes, 512 MiB.

## 3. Use each one

The BlackBox namespace pays NAND program time, the NoSSD namespace pays
none:

```sh
sudo fio --name=n1 --filename=/dev/nvme0n1 --direct=1 --ioengine=libaio \
    --rw=randwrite --bs=4k --iodepth=1 --size=64M --runtime=5 --time_based
sudo fio --name=n3 --filename=/dev/nvme0n3 --direct=1 --ioengine=libaio \
    --rw=randwrite --bs=4k --iodepth=1 --size=64M --runtime=5 --time_based
```

The average completion latency is about 206 us on `nvme0n1` (the 200 us
program) and about 5.5 us on `nvme0n3`.

The zoned namespace builds its zones from its own size: 16 zones of 32 MiB,
half the size of the 1 GiB namespace in [tutorial 03](03-zns.md):

```sh
sudo blkzone report -c 2 /dev/nvme0n2
```

```text
  start: 0x000000000, len 0x010000, cap 0x010000, wptr 0x000000 reset:0 non-seq:0, zcond: 1(em) [type: 2(SEQ_WRITE_REQUIRED)]
  start: 0x000010000, len 0x010000, cap 0x010000, wptr 0x000000 reset:0 non-seq:0, zcond: 1(em) [type: 2(SEQ_WRITE_REQUIRED)]
```

Store and retrieve a value in the KV namespace. With several namespaces,
Linux refuses I/O passthrough on the controller node `/dev/nvme0`, so use
the generic node, and name the namespace with `-n 4`:

```sh
head -c 64 /dev/urandom > value.bin
sudo nvme io-passthru /dev/ng0n4 -O 0x01 -n 4 --cdw10=64 --cdw11=4 \
    --cdw2=0x42424242 -l 64 -w -i value.bin
sudo nvme io-passthru /dev/ng0n4 -O 0x02 -n 4 --cdw10=64 --cdw11=4 \
    --cdw2=0x42424242 -l 64 -r -b > out.bin
cmp value.bin out.bin && echo match
```

```text
IO Command Write is Success and result: 0x00000040
IO Command Read is Success and result: 0x00000040
match
```

The same Retrieve sent to `/dev/nvme0` fails with
`passthru: Invalid argument`. [Tutorial 07](07-kv.md) explains the command
fields.

## 4. Whose counters

Log page C0h is per controller. It sums the BlackBox, CSD and KV
namespaces, and ignores NoSSD and ZNS
([counters](../reference/log-pages-and-counters.md#vendor-log-page-c0h)).
After the two fio runs above, before the KV store:

```sh
sudo nvme get-log /dev/nvme0 --log-id=0xc0 --log-len=512 -b | od -An -t u8 -j 8 -N 24 -w24
```

```text
                24046                    0                24046
```

24046 pages are the BlackBox run alone (5 seconds at about 4,800 writes
per second); the 2.7 GiB written to the NoSSD namespace in the same time
is not counted. The SMART log (`sudo nvme smart-log /dev/nvme0`) counts
the successful Read, Write and Zone Append commands of every namespace,
NoSSD and ZNS included; KV Store and Retrieve share those opcodes and are
counted too.

## What you learned

- `namespaces`, `namespace_sizes` and `namespace_modes` build several
  namespaces on one controller; commas inside a value are doubled.
- Each mode keeps its own behaviour: zone geometry, NAND timing, key space.
- A KV namespace has only a generic node, and on a controller with several
  namespaces passthrough needs that node.
- C0h counts only BlackBox, CSD and KV namespaces; NoSSD and ZNS do not
  add to it.

## Next

- [Several namespaces and devices](../features/multi-namespace.md) lists
  the limits and refusals, and how to start several controllers.
- [Namespace management](../features/ns-management-and-pi.md) creates and
  deletes namespaces from the guest while it runs.
- [Subsystems, controllers and namespaces](../design/namespaces.md)
  explains how the backend is partitioned.
