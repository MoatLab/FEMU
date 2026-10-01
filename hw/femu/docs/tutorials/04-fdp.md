# Tutorial 04: Flexible Data Placement

You start a BlackBox SSD with Flexible Data Placement (FDP), read its FDP
configuration and status with nvme-cli, write through a placement
identifier and watch the reclaim unit fill, and then run a workload with
data of two lifetimes, with and without placement, to see what placement
does to the write amplification factor (WAF). It takes about fifteen
minutes.

You need: [tutorial 02](02-gc-and-waf.md) is helpful background, the
variables from [Before you start](README.md#before-you-start), and about
5 GiB of free host memory. The guest image has nvme-cli 2.8, which has the
`fdp` commands, and fio 3.36, which can place writes through its
`io_uring_cmd` engine.

## Background

FDP lets the host say which writes belong together. The device groups its
NAND into reclaim units and offers a few reclaim unit handles. A write may
carry a placement identifier that names a handle; all writes of one handle
go into that handle's open reclaim unit. If data that dies together shares
a reclaim unit, garbage collection (GC) finds it mostly invalid and copies
little.

In FEMU, FDP is not a mode. It is a property of an NVMe subsystem
(`femu-subsys`) that a BlackBox controller joins, and a reclaim unit is one
line (superblock) of the BlackBox FTL. See
[the FDP design page](../design/fdp.md#placement-of-writes).

## 1. Start the guest (on the host)

<!-- femu-example: tut04-boot -->
```bash
./qemu-system-x86_64 -name femu-tut04,debug-threads=on \
    -enable-kvm -cpu host -smp 4 -m 4G \
    -device virtio-scsi-pci,id=scsi0 -device scsi-hd,drive=hd0 \
    -drive file=$OSIMGF,if=none,cache=none,format=qcow2,id=hd0 \
    -net user,hostfwd=tcp::$SSH_PORT-:22 -net nic,model=virtio \
    -device femu-subsys,id=fdp0,fdp=on,fdp.nruh=4 \
    -device femu,femu_mode=1,devsz_mb=384,nchs=2,luns_per_ch=4,blks_per_pl=64,subsys=fdp0 \
    -nographic
```

| Option | Meaning |
| --- | --- |
| `femu-subsys,id=fdp0,fdp=on` | a subsystem with FDP in endurance group 1; it must come before the controller that names it |
| `fdp.nruh=4` | four reclaim unit handles, so placement identifiers 0 to 3 |
| `nchs=2,luns_per_ch=4,blks_per_pl=64` | 512 MiB of NAND in 64 lines of 8 MiB; each line is one reclaim unit |
| `devsz_mb=384` | a 384 MiB namespace, 75% of the NAND |
| `subsys=fdp0` | the controller joins the subsystem |

`fdp.nru` keeps its default of 128 reclaim units, but FEMU uses at most
one per line, so this device has 64.

## 2. Check FDP from the guest

In the guest (`./run-guest-ssh.sh`):

```sh
sudo nvme id-ctrl /dev/nvme0 | grep ctratt
sudo nvme fdp configs /dev/nvme0 -e 1
```

```text
ctratt    : 0x80010
FDP Attributes: 0x80
Vendor Specific Size: 0
Number of Reclaim Groups: 1
Number of Reclaim Unit Handles: 4
Number of Namespaces Supported: 256
Reclaim Unit Nominal Size: 8388608
Estimated Reclaim Unit Time Limit: 0
Reclaim Unit Handle List:
  [0]: Persistently Isolated
  [1]: Persistently Isolated
  [2]: Persistently Isolated
  [3]: Persistently Isolated
```

Bit 19 (0x80000) of CTRATT says the controller supports FDP. The reclaim
unit is 8 MiB, one line of this geometry. The namespace's placement
identifiers and the room left in each one's reclaim unit:

```sh
sudo nvme fdp status /dev/nvme0n1
```

```text
Placement Identifier 0; Reclaim Unit Handle Identifier 0
  Estimated Active Reclaim Unit Time Remaining (EARUTR): 0
  Reclaim Unit Available Media Writes (RUAMW): 16384
...
```

RUAMW counts logical blocks: 16384 x 512 bytes = 8 MiB, an empty reclaim
unit. The output repeats for identifiers 1 to 3.

Do not rely on `nvme fdp usage` with FEMU at this version: FEMU's Reclaim
Unit Handle Usage descriptors are 24 bytes long instead of the 8 bytes
nvme-cli reads, so nvme-cli reports handles 1 and 2 as unused when every
handle is in use.

## 3. Write through a placement identifier

A write with directive type 2 (data placement) carries its placement
identifier in the directive specific field (`-S`). Write 4 KiB three times
through identifier 1:

```sh
head -c 4096 /dev/urandom > d.bin
for i in 1 2 3; do
    sudo nvme write /dev/nvme0n1 -s $((i * 8)) -c 7 -z 4096 -d d.bin -T 2 -S 1
done
sudo nvme fdp status /dev/nvme0n1 | grep RUAMW
```

```text
  Reclaim Unit Available Media Writes (RUAMW): 16384
  Reclaim Unit Available Media Writes (RUAMW): 16360
  Reclaim Unit Available Media Writes (RUAMW): 16384
  Reclaim Unit Available Media Writes (RUAMW): 16384
```

Only identifier 1's reclaim unit lost room: 3 writes of 8 blocks. A write
without a directive, or with an identifier the namespace does not have,
goes to handle 0. The endurance group statistics count bytes:

```sh
sudo nvme fdp stats /dev/nvme0 -e 1
```

```text
Host Bytes with Metadata Written (HBMW): 12288
Media Bytes with Metadata Written (MBMW): 12288
Media Bytes Erased (MBE): 0
```

This output is illustrative: it is what a fresh device reports after the
three writes. HBMW is what the host wrote; MBMW also counts what GC copied,
so MBMW / HBMW is the WAF over the endurance group.

## 4. Measure what placement does

The workload mixes two lifetimes: a hot 64 MiB region that takes random
overwrites, and a cold 320 MiB region rewritten sequentially. Without
placement both go into the same reclaim units, and GC copies cold pages
whenever it collects a unit full of dead hot pages. With placement, hot
writes use identifier 0 and cold writes identifier 1.

Save this in the guest as `fdp-run.sh`. It follows the method of
[tutorial 02](02-gc-and-waf.md#2-the-measurement-script): switch time off,
precondition, then measure the counter differences of one run.

```sh
cat > fdp-run.sh <<'EOF'
# Usage: FDP=0 bash fdp-run.sh, or FDP=1 bash fdp-run.sh
c0() {
    sudo nvme get-log /dev/nvme0 --log-id=0xc0 --log-len=512 -b |
        od -An -t u8 -j 8 -N 24 -w24
}
sudo nvme admin-passthru /dev/nvme0 --opcode=0xef --cdw10=2 >/dev/null
sudo nvme admin-passthru /dev/nvme0 --opcode=0xef --cdw10=4 >/dev/null
P= H= C=
if [ "$FDP" = 1 ]; then P=--fdp=1 H=--fdp_pli=0 C=--fdp_pli=1; fi
J="--filename=/dev/ng0n1 --ioengine=io_uring_cmd --cmd_type=nvme --bs=4k --iodepth=8 $P"
sudo fio --name=prefill $J $C --rw=write --size=384M >/dev/null
c0 > before.txt
sudo fio $J --randrepeat=0 \
    --name=hot $H --rw=randwrite --offset=0 --size=64M --io_size=1G \
    --name=cold $C --rw=write --offset=64M --size=320M --io_size=1G >/dev/null
c0 > after.txt
paste before.txt after.txt | awk '{ h = $4 - $1; g = $5 - $2; n = $6 - $3;
    printf "host %d  gc %d  nand %d  WAF %.3f\n", h, g, n, (n + g) / h }'
sudo nvme fdp stats /dev/nvme0 -e 1
EOF
```

fio's `io_uring_cmd` engine sends NVMe commands through the generic node
`/dev/ng0n1`. With `--fdp=1` it reads the namespace's placement identifiers
and uses the ones whose indexes `--fdp_pli` lists, one per job here.

Restart QEMU (step 1) before each run, so that both start from an empty
device, and run once each way:

```sh
FDP=0 bash fdp-run.sh
```

```text
host 524288  gc 3524608  nand 524288  WAF 7.723
Host Bytes with Metadata Written (HBMW): 2550136832
Media Bytes with Metadata Written (MBMW): 16986931200
Media Bytes Erased (MBE): 16567500800
```

```sh
FDP=1 bash fdp-run.sh
```

```text
host 524288  gc 1977855  nand 524288  WAF 4.772
Host Bytes with Metadata Written (HBMW): 2550136832
Media Bytes with Metadata Written (MBMW): 10651430912
Media Bytes Erased (MBE): 10234101760
```

The host wrote the same 2.55 GB (384 MiB of prefill plus 2 GiB) in both
runs. Placement cut the pages GC copied by 44% and the WAF of the measured
run from 7.72 to 4.77. The FDP statistics count since the device started,
prefill included: MBMW / HBMW falls from 6.66 to 4.18.

The WAF with placement is still well above 1 because the hot region is
written at random: its own reclaim units still hold a mix of live and dead
pages when GC takes them. Try `gc_strategy=1` (cost-benefit) on the
controller, or more handles and a third lifetime.

## What you learned

- FDP lives on `femu-subsys`; the controller joins it with `subsys=`.
- `nvme fdp configs`, `status` and `stats` show the handles, the room left
  in each reclaim unit, and host against media bytes.
- Placement only helps when the writes carry it: `nvme write -T 2 -S N`,
  or fio with `--ioengine=io_uring_cmd --fdp=1` on the generic node.
- Separating lifetimes by placement cuts GC copies.

## Next

- [Flexible Data Placement](../features/fdp.md) lists every option,
  refusal and the other log pages.
- [The FDP design page](../design/fdp.md) explains how reclaim units map
  to lines and how GC chooses one.
- [Tutorial 05](05-latency-tuning.md) turns from page counts to latency.
