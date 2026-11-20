# Lab 3: DFTL and the mapping cache

**Learning goal.** You predict the miss ratio of the cached mapping table
(CMT) of a demand-based FTL (DFTL) from the cache size and the working
set. You then measure what a miss costs: translation page reads,
translation page programs and read latency.

**Time.** About 15 minutes: two QEMU starts. The NAND time stays on in
this lab, because it reads the latency.

**Before you start.** Do [lab 1](lab1-gc-and-waf.md). Read
[DFTL](../design/ftl.md#dftl-mappingdftl) in the FTL design page.

## 1. Background: the CMT

With `mapping=dftl`, the logical-to-physical map lives on NAND in
translation pages (TPs). The CMT in controller DRAM holds whole TPs.

```
 one TP = 4 KiB / 8 bytes = 512 mappings = 512 pages x 4 KiB = 2 MiB of logical space
 CMT    = mapping_cache_mb x 1 MiB / 4 KiB TPs        (0 means 4 MiB)

 host read or write of page p, tp = p / 512
   tp in the CMT   --> hit: no NAND cost
   tp not in CMT   --> miss: CLOCK picks a victim slot
                        victim dirty --> program it (tp_prog, C0h 280)
                        read tp from NAND (tp_read, C0h 288), if it has a copy
   a write makes its slot dirty
```

FEMU still keeps the full map in host memory to answer each lookup. The
CMT is a cost model: it decides which lookups pay a TP read. So
`mapping_cache_mb` does not bound the memory that QEMU uses.

A TP has a NAND copy only after its first program. After the fill of
this lab, each TP outside the CMT has one, so each miss reads a TP.

Take uniform random access over a working set of W MiB. Let the CMT
cover C MiB of logical space. A first model of the miss ratio is

```
 m = max(0, 1 - C / W)
 C = (mapping_cache_mb x 1 MiB / 4 KiB) x 2 MiB
```

A miss on a read waits for the TP read before the data read starts. At
queue depth 1 with the default 40 us page read, a first model is

```
 mean read latency ~ L_hit + m x 40 us
 L_hit = one data read plus the host and guest overhead (unknown)
```

The overhead does not cancel in a ratio of two latencies. It cancels in
a difference, so the lab predicts the difference.

For random writes, a miss also reads the TP and takes a slot. When each
slot is dirty, each miss programs one TP. So the first model gives m
TP programs for each host write. C0h 280 also counts other TP work,
which question 6 asks about.

## 2. The devices

Start QEMU with the command line of
[tutorial 01, step 2](../tutorials/01-first-ssd.md#2-start-the-guest-on-the-host),
with one of these `-device` lines in place of its own. Both have 2 GiB
of NAND and a 1 GiB namespace.

<!-- femu-example: lab3-dftl -->
```
-device femu,femu_mode=1,nchs=4,luns_per_ch=4,blks_per_pl=128,devsz_mb=1024,mapping=dftl,mapping_cache_mb=1

-device femu,femu_mode=1,nchs=4,luns_per_ch=4,blks_per_pl=128,devsz_mb=1024,mapping=dftl
```

The first line has a 1 MiB CMT. The second line is the control, with
the default 4 MiB CMT.

## 3. Predict (hand in before the run)

For each device:

1. How many TPs does the namespace have? How many fit in the CMT? How
   much logical space does the CMT cover?
2. The fill writes the namespace once, in order. How many TPs does it
   program, and how many does it read?
3. Give m for the random reads over W = 256, 768 and 1024 MiB.
4. Give the difference of the mean read latency between W = 1024 MiB
   and W = 256 MiB.
5. Give the TP programs for each host page of the random writes.

## 4. Run

In the guest, once for each device:

```sh
sudo bash lab-dftl.sh
```

The output has eight lines. This copy leaves out some fields, and `N`
stands for a number:

```
LAB3 step=fill host=262144 tp_prog=N tp_read=N waf=N
LAB3 step=warm ws=256 tp_read=N tp_prog=N
LAB3 step=read ws=256 reads=32768 tp_read=N tp_prog=N miss=N mean_us=N
LAB3 step=warm ws=768 tp_read=N tp_prog=N
LAB3 step=read ws=768 reads=32768 tp_read=N tp_prog=N miss=N mean_us=N
LAB3 step=warm ws=1024 tp_read=N tp_prog=N
LAB3 step=read ws=1024 reads=32768 tp_read=N tp_prog=N miss=N mean_us=N
LAB3 step=write host=65536 gc=N tp_prog=N tp_read=N tp_per_host=N check=ok
```

The script does these steps:

1. It fills the namespace with sequential 128 KiB writes.
2. For each W, it warms the CMT with 32 MiB of reads over the first W
   MiB. It then measures 128 MiB of the same reads.
3. Each read is a random 4 KiB read at queue depth 1.
4. It writes 256 MiB in random 4 KiB writes at queue depth 32 over the
   namespace. By the model, GC does not start here; `gc=0` shows it.

`LAB_WS`, `LAB_WARM_MB`, `LAB_READ_MB` and `LAB_WRITE_MB` change the
sizes.

## 5. Measure

| Value | Counter | How |
| --- | --- | --- |
| miss ratio of the reads | C0h 288 / host reads | `miss=` in each `step=read` line |
| TP programs | C0h 280 | `tp_prog=` |
| read latency | fio, completion latency | `mean_us=`, `p50_us=`, `p99_us=` |
| TP programs per host write | C0h 280 / C0h 8 | `tp_per_host=` |
| WAF with the TP programs | C0h 8, 16, 24, 280 | `waf=`; C0h byte 0 counts TP programs too |

## 6. Questions

Easy:

1. How many TPs does a 1 GiB namespace need? How many does a 1 MiB CMT
   hold?
2. Why does the fill program TPs with the 1 MiB CMT and none with the
   4 MiB CMT?

Medium:

3. Compare the measured miss ratio with m for each W. Which W has the
   largest error? Give a reason.
4. The warm step at W = 256 MiB programs TPs. Why do reads cause NAND
   programs? When does this stop?
5. Compare `p50_us` at W = 256 MiB with `p99_us` at W = 1024 MiB.
   Which accesses does each one show?

Hard:

6. Run `LAB_WRITE_MB=1024 sudo -E bash lab-dftl.sh` on a fresh 1 MiB
   device. GC now runs in the write step. Predict whether `tp_per_host`
   rises above m, then measure it. Which FTL work programs TPs, other
   than a dirty eviction? Use the DFTL section of the design page.

Challenge:

7. A 4 TiB SSD has 4 KiB pages and 8-byte map entries. How much DRAM
   holds its full map? Size a CMT for a miss ratio of 10% under uniform
   random reads over the whole drive. Why do real workloads miss less?

## 7. Expected ranges

Read this section after you hand in your prediction. No run of this lab
is on record yet. Each value is a model value, to be measured.

| Step | 1 MiB CMT (model) | 4 MiB CMT (model) |
| --- | --- | --- |
| fill, `tp_prog` | 256: the TPs that leave the CMT | 0 |
| fill, `tp_read` | 0: a new TP has no NAND copy | 0 |
| warm W = 256, `tp_read` | about 128: TPs 0 to 127 are not in the CMT after the fill | 0 |
| read W = 256, `miss` | about 0 | 0 |
| read W = 768, `miss` | 0.333 | 0 |
| read W = 1024, `miss` | 0.500 | 0 |
| `mean_us` at W = 1024 minus at W = 256 | 0.5 x 40 us = 20 us | about 0 |
| warm and read steps, sum of `tp_prog` | at most 256, the dirty TPs left by the fill | 0 |
| write, `gc` | 0 | 0 |
| write, `tp_per_host` | about 0.5 | 0 |

Sources: the model of section 1, with `lab-waf-model.py dftl --cmt-mb 1
--ws-mb W`. The model has four assumptions:

- each access is uniform over W;
- the CMT holds exactly 256 TPs;
- the warm step brings the CMT to its steady state;
- no dirty eviction runs on the LUN of a read in the measured step.
