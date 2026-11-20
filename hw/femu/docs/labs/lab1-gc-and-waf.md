# Lab 1: GC and WAF

**Learning goal.** You predict the write amplification factor (WAF) of a
BlackBox SSD from two inputs. The first is the share of the NAND that
the namespace fills. The second is the pair of garbage collection (GC)
thresholds. You then name the GC regime that sets the WAF: background,
floor or forced.

**Time.** About 20 minutes: seven QEMU starts of about 30 seconds and
seven runs of under a minute each.

**Before you start.** Read [Background](../tutorials/02-gc-and-waf.md#background)
in tutorial 02, and do [Before the first lab](README.md#before-the-first-lab).

## 1. Background: three operating regions

The device has 128 lines. A line is one block on each of the 16 LUNs:
16 x 256 pages of 4 KiB, or 16 MiB. The FTL turns the two thresholds
into counts of free lines:

```
 bg_free     = int((1 - gc_thres_pcent / 100)      x 128)   background GC
 forced_free = int((1 - gc_thres_pcent_high / 100) x 128)   forced GC
 defaults: gc_thres_pcent = 75 --> 32 lines, gc_thres_pcent_high = 95 --> 6 lines

 free lines  128 ............ bg_free ............ forced_free ..... 0
                  no GC      | background pass   | forced pass     |
                             | after each command| inside a write  |
                             | victim needs 1/8  | any victim      |
                             | of pages invalid  |                 |
```

The namespace holds D lines of data. With `op_pcent=P`, the namespace is
128 x 100 / (100 + P) lines. A first-order model puts the device in one
of three operating regions. This lab calls them regimes:

```
 T_bg = 128 - bg_free - 1          the lines GC can use while it keeps bg_free
 T_f  = 128 - forced_free - 1      the lines GC can use at the forced threshold
 (the "- 1" is the open line of the write pointer)

 D / T_bg <= 0.936  --> background regime: WAF from the FIFO model with T_bg
 else D / T_f <= 0.936 --> floor regime:  victims at the 1/8 limit, WAF ~ 8
 else              --> forced regime:     WAF from the FIFO model with T_f
```

The FIFO model: a victim keeps a share u of valid pages, with

```
 D / T = (1 - u) / (-ln u)          WAF = 1 / (1 - u)
```

The number 0.936 is D / T at u = 7/8. At that point a victim has exactly
1/8 of its pages invalid, the least that the background pass accepts.

The FTL does not compute D / T. It makes one background attempt after
each request and runs forced GC inside a write. Both kinds can run in
one interval. So `forced_passes` is evidence of the regime, and the
model makes no exact claim for it. With `gc_thres_pcent=95`, the two
thresholds are equal, so forced passes can occur in the background
regime too.

## 2. The devices

Start QEMU with the command line of
[tutorial 01, step 2](../tutorials/01-first-ssd.md#2-start-the-guest-on-the-host),
with one of these `-device` lines in place of its own. Restart QEMU for
each line.

Part A, the background threshold:

<!-- femu-example: lab1-threshold -->
```
-device femu,femu_mode=1,nchs=4,luns_per_ch=4,blks_per_pl=128,op_pcent=25

-device femu,femu_mode=1,nchs=4,luns_per_ch=4,blks_per_pl=128,op_pcent=25,gc_thres_pcent=90

-device femu,femu_mode=1,nchs=4,luns_per_ch=4,blks_per_pl=128,op_pcent=25,gc_thres_pcent=95
```

Part B, the spare capacity, with `gc_thres_pcent=90`:

<!-- femu-example: lab1-spare -->
```
-device femu,femu_mode=1,nchs=4,luns_per_ch=4,blks_per_pl=128,op_pcent=7,gc_thres_pcent=90

-device femu,femu_mode=1,nchs=4,luns_per_ch=4,blks_per_pl=128,op_pcent=15,gc_thres_pcent=90

-device femu,femu_mode=1,nchs=4,luns_per_ch=4,blks_per_pl=128,op_pcent=50,gc_thres_pcent=90

-device femu,femu_mode=1,nchs=4,luns_per_ch=4,blks_per_pl=128,op_pcent=100,gc_thres_pcent=90
```

Part B also uses the `op_pcent=25,gc_thres_pcent=90` run of part A.

## 3. Predict (hand in before the run)

Fill in this table for the seven configurations. Use a calculator or
`lab-waf-model.py uniform`. Write one sentence for each regime that you
name.

```
 gc_thres_pcent  op_pcent  D (lines)  bg_free  T_bg  D/T_bg  regime  WAF  forced_passes > 0?
 75              25
 90              25
 95              25
 90              7
 90              15
 90              50
 90              100
```

## 4. Run

In the guest, once for each configuration:

```sh
sudo bash lab-gc-waf.sh
```

```text
LAB1 host=1048576 gc=... nand=1048576 forced_waits=... forced_passes=... pad=0 tp_prog=0 tp_read=0 waf=... check=ok
```

The script fills the namespace, ages it with 4 GiB of random 4 KiB
writes, and measures one more 4 GiB run. The NAND time is off, so a run
takes seconds. The measured run writes 1048576 pages.

## 5. Measure

| Value | Counter | How |
| --- | --- | --- |
| WAF of the run | C0h 8, 16, 24 | `waf=` in the `LAB1` line |
| forced GC | C0h 192, 200 | `forced_waits=` and `forced_passes=` |
| copies per host write | C0h 16 / C0h 8 | `gc / host`; it equals WAF - 1 here |

## 6. Questions

Easy:

1. A fresh drive takes one sequential pass over the whole namespace.
   What is the WAF of that pass, and why?
2. Compute `bg_free` and `forced_free` for the default thresholds on
   this device.

Medium:

3. At `gc_thres_pcent=75` and `op_pcent=25`, the WAF is near 8. Which
   regime is this? Which line of code sets the 8?
4. `op_pcent=15` and `op_pcent=25`, both at `gc_thres_pcent=90`, differ
   by less than 10% in spare capacity. Why does the WAF fall from about
   8 to under 5?

Hard:

5. At `op_pcent=7`, the WAF is above 40. Why does no limit near 8 apply
   here? Which counter shows the regime?
6. At `op_pcent=100`, the FIFO model gives 1.37 and the device gives
   about 1.03. Name two assumptions of the model that the run does not
   meet. Hint: compare the victim policy. Read the fio documentation
   of `norandommap`. To separate the two causes, run
   `sudo bash lab-gc-waf.sh --norandommap` on this device.

Challenge:

7. A vendor ships this geometry with `op_pcent=25`. Find the smallest
   `gc_thres_pcent` that keeps the background regime. Give its model
   WAF. Why can a vendor still pick a lower threshold?

## 7. Expected ranges

Read this section after you hand in your prediction.

| `gc_thres_pcent` | `op_pcent` | Regime (model) | WAF, model | WAF, measured | forced_passes |
| --- | --- | --- | --- | --- | --- |
| 75 | 25 | floor | 8.00 | 8.017 | to be measured; few or none expected |
| 90 | 25 | background | 4.74 | 4.590 | to be measured; few or none expected |
| 95 | 25 | background | 3.44 | 3.273 | to be measured; equal thresholds, some possible |
| 90 | 7 | forced | 44.2 | 43.945 | to be measured; many expected |
| 90 | 15 | floor | 8.00 | 8.000 | to be measured; few or none expected |
| 90 | 50 | background | 2.14 | 1.970 | to be measured; few or none expected |
| 90 | 100 | background | 1.37 | 1.028 | to be measured; few or none expected |
| 90 | 100, `--norandommap` | background | 1.37 | to be measured | to be measured |

Sources:

- Measured WAF: [tutorial 02](../tutorials/02-gc-and-waf.md), with the
  same device lines and the same workload, at commit `1a03ded0f`.
- Model: `lab-waf-model.py uniform --lines 128 --fill F --gc G`, with
  F = 100 / (100 + `op_pcent`).

Expect a measured WAF within a few percent of the tutorial values. A
larger difference is a result to explain.
