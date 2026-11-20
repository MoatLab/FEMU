# Lab 4: when placement pays

**Learning goal.** You predict when Flexible Data Placement (FDP) lowers
the WAF, and when the GC rules hide its effect. You compare a device
with no FDP and a device with FDP on three geometries. You then form a
hypothesis for a result that no simple model explains, and test it with
per-handle counters.

**Time.** About 25 minutes: six QEMU starts and six runs of about one
minute each. The seventh run is optional.

**Before you start.** Do [lab 1](lab1-gc-and-waf.md) and
[tutorial 04](../tutorials/04-fdp.md). Lab 1 explains the floor regime,
which this lab needs.

## 1. Background: the lesson of an earlier run

An earlier FEMU study ran a cache workload of two tenants on a raw
namespace. It ran each device with and without FDP placement. The
results, on the d760 host in November 2026:

```
 device                                       no FDP   FDP     source
 fill at the background threshold (75%)       7.756    7.764   runs of 2026-11-19
 fill at 50% of the NAND, default thresholds  1.748    1.230   d760 runs 398d, 398c
```

At the threshold, placement changed nothing. The background pass took
each victim as soon as 1/8 of its pages were invalid. Victims of both
runs were about 87% valid, so the 1/8 rule set the WAF, not the
placement. With spare lines, GC waited longer, and placement lowered
the WAF by about a third. That study used another workload and geometry,
so its numbers are not the expected values of this lab.

```
 GC rule sets the WAF                      data placement sets the WAF
 (floor regime of lab 1)                   (background regime, spare lines)
 victim taken at 1/8 invalid  ---------->  victim taken when it is the emptiest
 FDP = no FDP                              FDP < no FDP
```

## 2. The workload

The job of tutorial 04, on a 384 MiB namespace:

```
 namespace 384 MiB
 |-- hot 64 MiB --|------------------ cold 320 MiB ------------------|
   random 4 KiB      sequential 4 KiB rewrites
   1 GiB of writes   1 GiB of writes
   FDP: index 0      FDP: index 1 (the prefill too)
```

`lab-fdp.sh` fills the namespace once with 4 KiB writes, then runs the
two jobs at the same time. There is no aging step, as in tutorial 04,
so the result includes the first GC after the fill. Each job writes
exactly 1 GiB, so each has 50% of the host writes of the run. The two
jobs run at different speeds, so the share changes during the run.

## 3. The devices

Base geometry, 512 MiB of NAND in 64 lines of 8 MiB, with FDP:

<!-- femu-example: lab4-fdp-boot -->
```bash
./qemu-system-x86_64 -name femu-lab4,debug-threads=on \
    -enable-kvm -cpu host -smp 4 -m 4G \
    -device virtio-scsi-pci,id=scsi0 -device scsi-hd,drive=hd0 \
    -drive file=$OSIMGF,if=none,cache=none,format=qcow2,id=hd0 \
    -net user,hostfwd=tcp::$SSH_PORT-:22 -net nic,model=virtio \
    -device femu-subsys,id=fdp0,fdp=on,fdp.nruh=4 \
    -device femu,femu_mode=1,devsz_mb=384,nchs=2,luns_per_ch=4,blks_per_pl=64,subsys=fdp0 \
    -qmp unix:/tmp/femu-qmp.sock,server=on,wait=off \
    -nographic
```

The same geometry with no FDP:

<!-- femu-example: lab4-plain-boot -->
```bash
./qemu-system-x86_64 -name femu-lab4,debug-threads=on \
    -enable-kvm -cpu host -smp 4 -m 4G \
    -device virtio-scsi-pci,id=scsi0 -device scsi-hd,drive=hd0 \
    -drive file=$OSIMGF,if=none,cache=none,format=qcow2,id=hd0 \
    -net user,hostfwd=tcp::$SSH_PORT-:22 -net nic,model=virtio \
    -device femu,femu_mode=1,devsz_mb=384,nchs=2,luns_per_ch=4,blks_per_pl=64 \
    -qmp unix:/tmp/femu-qmp.sock,server=on,wait=off \
    -nographic
```

The two other geometries change only the `femu` device. Put these lines
in place of the `femu-subsys` and `femu` lines of the commands above.
Variant `thres95` moves the background threshold to the forced one:

<!-- femu-example: lab4-thres95 -->
```
-device femu-subsys,id=fdp0,fdp=on,fdp.nruh=4
-device femu,femu_mode=1,devsz_mb=384,nchs=2,luns_per_ch=4,blks_per_pl=64,gc_thres_pcent=95,subsys=fdp0

-device femu,femu_mode=1,devsz_mb=384,nchs=2,luns_per_ch=4,blks_per_pl=64,gc_thres_pcent=95
```

Variant `spare` doubles the NAND, to 128 lines, and keeps the namespace:

<!-- femu-example: lab4-spare -->
```
-device femu-subsys,id=fdp0,fdp=on,fdp.nruh=4
-device femu,femu_mode=1,devsz_mb=384,nchs=2,luns_per_ch=4,blks_per_pl=128,subsys=fdp0

-device femu,femu_mode=1,devsz_mb=384,nchs=2,luns_per_ch=4,blks_per_pl=128
```

`fdp.nru` keeps its default of 128 reclaim units, so each line of each
geometry is one reclaim unit.

The runs, one QEMU start each:

```
 run  geometry  device   script mode   note
 1    base      no FDP   untagged
 2    base      FDP      fdp
 3    thres95   no FDP   untagged
 4    thres95   FDP      fdp
 5    spare     no FDP   untagged
 6    spare     FDP      fdp
 7    base      FDP      untagged      optional: FDP device, writes with no placement
```

## 4. Predict (hand in before the run)

1. For each geometry, compute the lines of data (D), `bg_free` and the
   free lines after the prefill. Name the regime of lab 1 for the
   device with no FDP.
2. Predict the WAF of runs 1 to 6. For runs 3 to 6, use the two model
   scenarios below.

Scenario A, one shared log: both classes mix in one log of T lines,
with T = lines - `bg_free` - 1 (one open line):

```
 W = sum_i r_i / (1 - exp(-x_i)),   x_i = r_i T / (D_i W)
 hot: r = 0.5, D = 8 lines        cold: r = 0.5, D = 40 lines
```

Scenario B, placement that works: the cold stream rewrites whole units
in order, so its units die whole and need no copy (WAF 1). The hot data
gets the pool that the cold data leaves:

```
 T   = lines - bg_free - 6        (FDP keeps about 6 units open)
 T_h = T - 41                     (40 cold lines and one open cold unit)
 W   = 0.5 x 1 + 0.5 x W_h,       W_h from D / T_h = (1 - u) / (-ln u), D = 8
```

```sh
python3 ../femu-scripts/labs/lab-waf-model.py classes --pool 60 --class 0.5:8 --class 0.5:40
python3 ../femu-scripts/labs/lab-waf-model.py classes --pool 14 --class 1:8
```

Both scenarios are first-order models. Neither is a bound on what
FEMU measures.

## 5. Run

In the guest, once for each run:

```sh
sudo bash lab-fdp.sh fdp
sudo bash lab-fdp.sh untagged
```

```
LAB4 mode=fdp host=524288 gc=N nand=524288 forced_waits=N forced_passes=N waf=N hbmw=N mbmw=N check=ok
```

The script checks that an FDP namespace reports two placement
identifiers or more. On a device with no FDP, the `hbmw` and `mbmw`
fields are absent.

For question 7, read the counters of each handle on the host. Split the
script in two steps and sample between them:

```sh
sudo bash lab-fdp.sh fdp prefill
```

```sh
python3 ../femu-scripts/femu-stat.py /tmp/femu-qmp.sock --once --json > before.json
```

```sh
sudo bash lab-fdp.sh fdp run
```

```sh
python3 ../femu-scripts/femu-stat.py /tmp/femu-qmp.sock --once --json > after.json
```

The first and the third command run in the guest. The other two run on
the host. Each handle has `host-bytes` and `media-bytes`
([query-femu](../reference/query-femu.md)). The WAF of a handle over the
run is the media difference over the host difference.

## 6. Measure

| Value | Counter | How |
| --- | --- | --- |
| WAF of the run | C0h 8, 16, 24 | `waf=` in the `LAB4` line |
| forced GC | C0h 192, 200 | `forced_waits=`, `forced_passes=` |
| WAF since start, FDP | FDP statistics, MBMW / HBMW | `hbmw=`, `mbmw=`; they include the prefill |
| WAF of each handle | `query-femu`, `host-bytes` and `media-bytes` | `femu-stat.py --once --json`, before and after the run |

## 7. Questions

Easy:

1. Which property turns FDP on? How many placement identifiers does the
   namespace have? What is a reclaim unit in FEMU?
2. Give `bg_free` and the free lines after the prefill for the base and
   the spare geometry.

Medium:

3. Run 1 is in the floor regime of lab 1. Compare its WAF with 8, and
   give the reason for any gap.
4. Compare runs 3 to 6 with the two scenarios. Which scenario is closer
   for each run? Give one reason for each gap.
5. In run 7, where do the writes go? Compare its WAF with run 1, and
   say what differs inside the device.

Hard:

6. Use section 1. Why can placement not lower the WAF when the device
   sits in the floor regime? Use the victim valid share in the answer.
7. Run 2 is also at the floor, but its WAF is far below run 1. Propose
   a hypothesis. Name the per-handle measurement that can disprove it,
   and do it.

Challenge:

8. Propose one change to the GC rules that lets placement pay at the
   default threshold. Say what it costs.

## 8. Expected ranges

Read this section after you hand in your prediction.

| Run | Geometry | Device | WAF | Source |
| --- | --- | --- | --- | --- |
| 1 | base | no FDP | to be measured; model 8.00 (floor) | `lab-waf-model.py uniform --lines 64 --fill 0.75` |
| 2 | base | FDP | 4.772 | measured, tutorial 04, commit `1a03ded0f` |
| 3 | thres95 | no FDP | to be measured; scenario A 2.82 | model, T = 64 - 3 - 1 = 60 |
| 4 | thres95 | FDP | to be measured; scenario B 1.20 | model, T_h = 64 - 3 - 6 - 41 = 14, W_h = 1.40 |
| 5 | spare | no FDP | to be measured; scenario A 1.37 | model, T = 128 - 32 - 1 = 95 |
| 6 | spare | FDP | to be measured; scenario B 1.00 | model, T_h = 128 - 32 - 6 - 41 = 49, W_h = 1.00 |
| 7 | base | FDP, untagged | 7.723 | measured, tutorial 04, commit `1a03ded0f` |

Scenario A treats the cold class as random writes. The cold job writes
in order, so scenario A is a rough guide. Expect runs 2 and 7 within a
few percent of the tutorial values. A larger difference is a result to
explain.
