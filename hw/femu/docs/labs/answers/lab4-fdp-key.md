# Answer key: lab 4, when placement pays

For the instructor. The lab is [lab 4](../lab4-fdp.md). Runs 2 and 7
have measured values from tutorial 04. The other runs are to be
measured.

## Prediction

```
 geometry  lines  D   bg_free  forced_free  free after prefill  no-FDP regime
 base      64     48  16       3            16                  floor
 thres95   64     48  3        3            16                  background
 spare     128    48  32       6            80                  background
```

D = 384 MiB / 8 MiB = 48 lines. The free lines after the prefill leave
out the open units.

```
 run  device   scenario    model WAF   measured
 1    no FDP   floor       8.00        to be measured
 2    FDP      none fits   none        4.772 (tutorial 04)
 3    no FDP   A, T = 60   2.82        to be measured
 4    FDP      B, T_h = 14 1.20        to be measured
 5    no FDP   A, T = 95   1.37        to be measured
 6    FDP      B, T_h = 49 1.00        to be measured
 7    untagged none        none        7.723 (tutorial 04)
```

## Questions

**Q1.** `femu-subsys` with `fdp=on`; the controller joins it with
`subsys=`. `fdp.nruh=4` gives placement identifiers 0 to 3. A reclaim
unit is one line (superblock) of the FTL, 8 MiB here.

**Q2.** Base: `bg_free` is 16, and 64 - 48 = 16 lines are free after
the prefill. GC starts at once. Spare: `bg_free` is 32, and 80 lines are
free. GC starts after about 48 lines of writes.

**Q3.** The model puts run 1 at the floor: T_bg = 47 is smaller than D,
and D / T_f = 0.80. Expect a WAF near 8, at most 8 for background GC
alone. Accept these reasons for a value below 8:

- the run starts right after the prefill, with no aging;
- the run ends with lines programmed but not yet collected;
- the cold job writes in order, so some lines die whole.

**Q4.** Scenario A treats the cold class as random writes, which it is
not. In a shared log, the sequential cold pages die in the order of
their writes, so A can be high or low. Scenario B assumes that each
cold unit dies whole before GC takes it. Accept any reason that names
an assumption and the direction of its error.

**Q5.** Untagged writes on an FDP device use placement handle 0. All
writes share the units of one handle, as in one log. FDP still keeps
its own open units and a GC destination for the handle, and its reserve
differs. So run 7 and run 1 can differ, though both mix the classes.

**Q6.** At the floor, the background pass takes a victim soon after 1/8
of its pages are invalid. Each victim is then about 7/8 valid, whatever
the placement. In the earlier study, the victims of both runs were 87%
valid. Placement helps only when GC waits long enough for the units of
short-lived data to empty.

**Q7.** No hypothesis is confirmed yet. Grade the hypothesis, the test
and the reading of the data. Two candidates, with the result that
disproves each:

```
 hypothesis                                   per-handle WAF it predicts   disproved if
 H1: the cold units die whole in order, and   cold (index 1) near 1,       cold WAF well
     GC takes hot units at the 1/8 limit      hot (index 0) near 8;        above 1
                                              total 0.5 x 1 + 0.5 x 8 = 4.5
 H2: hot units lose pages fast after they     hot well below 8, cold       hot WAF near 8
     close, so GC finds them emptier than     above 1
     7/8 valid; cold units pay the 1/8 rule
```

The test: the WAF of each handle over the run, from `host-bytes` and
`media-bytes` of `femu-stat.py --once --json` before and after the run.
A student who measures both handles and rejects one hypothesis with the
data gets full points.

**Q8.** Accept one of these, with its cost:

- Raise `gc_thres_pcent` (runs 3 and 4). GC keeps fewer free lines, so
  a write burst meets forced GC sooner.
- Run the background pass only in idle time. A busy device then
  collects only by forced GC, inside host writes.
- Raise the 1/8 share. FEMU has no property for it; it is a code
  change. Victims then free more space, and GC may wait too long.

## Grading notes

- Section 1 of the lab gives the earlier study as a lesson. Its numbers
  are not expected values of this lab.
- Runs 2 and 7 ran at an older commit (`1a03ded0f`), not on master.
  Report a difference of more than a few percent as a result.
