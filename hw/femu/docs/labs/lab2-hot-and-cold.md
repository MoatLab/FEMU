# Lab 2: hot and cold data

**Learning goal.** You find out which data `hot_cold_sep=on` keeps apart,
and you predict for which workloads that lowers the WAF. You then see
why a victim policy that looks at age helps only after the separation.

**Time.** About 20 minutes: seven QEMU starts and seven runs of under a
minute each.

**Before you start.** Do [lab 1](lab1-gc-and-waf.md). Read
[hot/cold separation](../design/ftl.md#hotcold-separation) and
[why there are several write pointers](../design/ftl.md#why-there-are-several-write-pointers)
in the FTL design page.

## 1. Background: what the rule separates

With `hot_cold_sep=on`, the FTL sends each host write to one of two
write pointers. The rule looks at one fact only: has this logical page
a mapping now?

```
 host write of page p
      |
      +-- p has no mapping (first write) ---------> data pointer --+
      |                                                            |
      +-- p has a mapping (overwrite) ------------> hot pointer    |
                                                                   |
 GC copy of a valid page ---------------------------> data pointer-+
                                                    (with first writes)
```

The rule does not count writes and keeps no history. Think about what
it does after the fill, when each page has a mapping. The second open
line also costs one line of the pool.

fio picks the pages of `uniform` with a random map: each page gets one
write in each pass over the namespace, in a random order. The `zipf`
and `hot80` jobs have no such map, so a page can get two writes in a
row.

The workloads, each 4 KiB random writes:

| Name | fio option | Write pattern |
| --- | --- | --- |
| `uniform` | none | every page has the same chance |
| `zipf` | `--random_distribution=zipf:1.2` | a few pages take most writes |
| `hot80` | `--random_distribution=zoned:80/20:20/80` | 80% of the writes go to the first 20% of the namespace |

## 2. The devices

Start QEMU with the command line of
[tutorial 01, step 2](../tutorials/01-first-ssd.md#2-start-the-guest-on-the-host),
with one of these `-device` lines in place of its own. All three keep
`op_pcent=25`, `gc_thres_pcent=95` and `gc_thres_base=raw`, so GC runs in
the background regime of lab 1.

<!-- femu-example: lab2-devices -->
```
-device femu,femu_mode=1,nchs=4,luns_per_ch=4,blks_per_pl=128,op_pcent=25,gc_thres_pcent=95,gc_thres_base=raw

-device femu,femu_mode=1,nchs=4,luns_per_ch=4,blks_per_pl=128,op_pcent=25,gc_thres_pcent=95,hot_cold_sep=on,gc_thres_base=raw

-device femu,femu_mode=1,nchs=4,luns_per_ch=4,blks_per_pl=128,op_pcent=25,gc_thres_pcent=95,gc_policy=cost-benefit,hot_cold_sep=on,gc_thres_base=raw
```

The runs, one QEMU start each:

```
 run  device                       workload
 1    off                          uniform
 2    hot_cold_sep=on              uniform
 3    off                          zipf
 4    hot_cold_sep=on              zipf
 5    off                          hot80
 6    hot_cold_sep=on              hot80
 7    cost-benefit, hot_cold_sep   zipf
```

## 3. Predict (hand in before the run)

1. For runs 2, 4 and 6, compare the WAF with the run of the same
   workload and `hot_cold_sep` off. Give one reason for each.
2. For `hot80`, compute two model scenarios with the classes model
   below: one shared log, and one log for each class. Say where you
   expect runs 5 and 6 to fall against them, and why.

The classes model has class i with a share r_i of the host writes and
D_i lines of data, in a pool of T lines:

```
 one shared log:   W = sum_i r_i / (1 - exp(-x_i)),   x_i = r_i T / (D_i W)
 one log a class:  W = sum_i r_i / (1 - u_i),         D_i / T_i = (1 - u_i) / (-ln u_i)
                   the best split T_1 + T_2 = T

 hot80 on this device: D = 102.4 lines, T = 128 - 6 - 1 = 121 lines
   hot class:  r = 0.8, D = 0.2 x 102.4 = 20.48 lines
   cold class: r = 0.2, D = 0.8 x 102.4 = 81.92 lines
```

```sh
python3 ../femu-scripts/labs/lab-waf-model.py classes --pool 121 --class 0.8:20.48 --class 0.2:81.92
python3 ../femu-scripts/labs/lab-waf-model.py classes --pool 120 --class 0.8:20.48 --class 0.2:81.92
```

Use T = 121 for the device with `hot_cold_sep` off and T = 120 with it
on. Neither scenario is the rule of section 1, and neither is a bound.
The one-log-a-class scenario sorts pages by their class. The rule sorts
host writes from GC copies.

## 4. Run

In the guest, for each run:

```sh
sudo bash lab-hot-cold.sh uniform
```

```text
LAB2 workload=uniform host=1048576 gc=... nand=1048576 ... waf=... check=ok
```

Use `zipf` or `hot80` in place of `uniform` for the other runs. The
method is the one of lab 1: fill, age with 4 GiB of the workload, then
measure one more 4 GiB run.

## 5. Measure

| Value | Counter | How |
| --- | --- | --- |
| WAF of the run | C0h 8, 16, 24 | `waf=` in the `LAB2` line |
| GC copies per host write | C0h 16 / C0h 8 | `gc / host` |

Optional, on the host: QMP `query-femu` shows the lines of each state
while the run goes on ([query-femu](../reference/query-femu.md)).

Run 7 can differ from the tutorial value by more than the others.
`cost-benefit` computes the age of a line from the host clock. So two
runs with the NAND time off can pick other victims.

## 6. Questions

Easy:

1. With `hot_cold_sep=on`, which pointer takes a first write, an
   overwrite, and a GC copy?
2. Why does `hot_cold_sep=on` reserve one more line at start?

Medium:

3. After the fill, every host write is an overwrite. So which two kinds
   of pages does the rule keep apart after the fill?
4. Explain runs 3 and 4: why does the separation more than halve the
   WAF under zipf?

Hard:

5. Explain runs 1 and 2. Under fio's random map, a page that survived
   GC has had no write for a long time in this pass. Is its next write
   nearer or further than for an average page? What does that predict
   for the separation? What changes with `--norandommap`?
6. Under uniform writes, `cost-benefit` and `greedy` give almost the
   same WAF (tutorial 02, section 5). Why does `cost-benefit` gain much
   in run 7?

Challenge:

7. Run 6 falls between the two numbers of the classes model. Why does
   the rule not reach the one-log-a-class number? Describe a rule that
   comes closer, and the state it must keep for each page.

## 7. Expected ranges

Read this section after you hand in your prediction.

| Run | Device | Workload | WAF | Source |
| --- | --- | --- | --- | --- |
| 1 | off | uniform | 3.277 | measured, tutorial 02 (`gc_policy=greedy`) |
| 2 | on | uniform | to be measured; the uniform model gives 3.59 for the pool with one more open line (3.44 without it) | model |
| 3 | off | zipf | 5.961 | measured, tutorial 02 |
| 4 | on | zipf | 2.394 | measured, tutorial 02 |
| 5 | off | hot80 | to be measured; scenario "shared log", T = 121: 3.79 | model |
| 6 | on | hot80 | to be measured; scenarios at T = 120: "shared log" 3.95, "one log a class" 2.57 | model |
| 7 | cost-benefit, on | zipf | 1.646 | measured, tutorial 02 |

Sources:

- Measured: [tutorial 02](../tutorials/02-gc-and-waf.md), sections 5 and
  6, at commit `1a03ded0f`. The default `gc_policy` is `greedy`.
- Model: `lab-waf-model.py uniform` and `classes`, as in section 3. The
  uniform model of lab 1 is about 5% high at this fill. The model of
  run 2 has only the cost of the extra line. It leaves out the effect of
  the random map that question 5 asks about.
