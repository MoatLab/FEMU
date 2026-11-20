# Answer key: lab 1, GC and WAF

For the instructor. The lab is [lab 1](../lab1-gc-and-waf.md).

## Prediction table

`lab-waf-model.py uniform --lines 128 --fill F --gc G` gives these rows,
with F = 100 / (100 + `op_pcent`):

```
 gc_thres_pcent  op_pcent  D (lines)  bg_free  T_bg  D/T_bg  regime      WAF   forced
 75              25        102.4      32       95    1.078   floor       8.00  few
 90              25        102.4      12       115   0.890   background  4.74  few
 95              25        102.4      6        121   0.846   background  3.44  some
 90              7         119.6      12       115   1.040   forced      44.2  many
 90              15        111.3      12       115   0.968   floor       8.00  few
 90              50        85.3       12       115   0.742   background  2.14  few
 90              100       64.0       12       115   0.557   background  1.37  few
```

For the floor and forced rows, the model uses T_f = 128 - 6 - 1 = 121.
The floor test is D / T_f <= 0.936. At `gc_thres_pcent=95`, the two
thresholds are equal, so some forced passes can run.

## Questions

**Q1.** The WAF is 1. A fresh drive has no invalid page. The background
pass runs once the free lines fall to `bg_free`, but no line has 1/8 of
its pages invalid. So GC copies nothing.

**Q2.** `bg_free = int(0.25 x 128) = 32` and
`forced_free = int(0.05 x 128) = 6`.

**Q3.** The floor regime. The background pool is 95 lines for 102.4
lines of data, so the pass cannot keep 32 lines free. The free count
falls, and the pass takes a line soon after 1/8 of it is invalid. Such
a victim gives about 1 free page for 7 copies, so the WAF is near 8.

Under background GC alone, 8 is an upper limit. The test is in
`bbssd/ftl-line-gc.c`: a victim with `ipc < ssd_line_data_pgs(...) / 8`
is refused when not forced. By the model, the free count stays above 6
(D / T_f = 0.846), so few or no forced passes run.

**Q4.** The boundary of the floor regime lies between the two. At
`op_pcent=15`, D / T_bg = 0.968, above 0.936: floor, WAF 8. At
`op_pcent=25`, D / T_bg = 0.890: background, u = 0.79, WAF 4.7. A small
change of D moves the device across the boundary.

**Q5.** At `op_pcent=7`, even the forced pool is too small for the 1/8
limit (D / T_f = 0.988). The forced pass has no 1/8 test. Its victims
are about 98% valid, so WAF = 1 / (1 - 0.977), about 44. `forced_passes`
and `forced_waits` are large. In the other rows, the model expects few
or none.

**Q6.** Two assumptions fail.

- Victim choice. The model takes the oldest line (FIFO). Greedy takes
  the line with the fewest valid pages. At a low fill, the valid counts
  spread wide, and the least valid line is far below the mean.
- Independent writes. The model gives each page the same chance of a
  write at each step. fio's random map writes each page once in each
  pass. A page then lives about one pass, not an exponential time.

The `--norandommap` run keeps greedy and removes the second cause. Its
WAF is to be measured. If it moves close to 1.37, the random map was
the main cause. Give full points for both causes and a correct reading
of the extra run.

**Q7.** The background test is 102.4 / (127 - bg_free) <= 0.936, so
`bg_free` <= 17. `int((1 - g / 100) x 128) <= 17` gives g = 86. The
model WAF at 86 is 7.41, so the gain over the floor is small.

A lower threshold keeps more free lines. A write burst then runs longer
before forced GC stalls the host. The price is a higher WAF.

## Grading notes

- Accept a WAF within 10% of the model for the background rows, if the
  argument uses the pool T and not the full 128 lines.
- Some students use 128 lines as T. They predict about 2.7 for
  `op_pcent=25`. Take off points for the argument. Ask them to explain
  the measured 3.27 to 4.59.
- The keys are public in the FEMU repository. For graded work, change
  the geometry, for example `blks_per_pl=96`, and compute new answers
  with `lab-waf-model.py`.
