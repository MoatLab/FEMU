# Answer key: lab 2, hot and cold data

For the instructor. The lab is [lab 2](../lab2-hot-and-cold.md).

## Prediction

```
 run  device             workload  direction against "off"   model scenario
 2    hot_cold_sep=on    uniform   open question (Q5)         3.44 --> 3.59 (line cost only)
 4    hot_cold_sep=on    zipf      much lower                 measured 5.961 --> 2.394
 6    hot_cold_sep=on    hot80     lower                      T = 120: shared 3.95, one a class 2.57
```

The two scenarios for `hot80`:

```
 lab-waf-model.py classes --pool 121 --class 0.8:20.48 --class 0.2:81.92
   one log 3.79, one per class 2.47
 lab-waf-model.py classes --pool 120 --class 0.8:20.48 --class 0.2:81.92
   one log 3.95, one per class 2.57
```

Neither scenario is a bound on FEMU. The rule of the lab sorts host
writes from GC copies, not pages by class. Grade the argument for the
position of runs 5 and 6, not the position itself.

## Questions

**Q1.** A first write goes to the data pointer. An overwrite goes to the
hot pointer. A GC copy goes to the data pointer.

**Q2.** Each pointer holds one open line. The capacity check adds one
reserved line for the hot pointer (`bbssd/bb.c`, the `hot_cold_sep`
branch of the reserve).

**Q3.** After the fill, the rule keeps host writes apart from GC copies.
A page that survives a GC pass moves to the data lines. A page that the
host writes again goes to the hot lines.

**Q4.** Under zipf, a page that survives until its line is a victim is
likely cold. The separation puts such pages together in data lines.
Those lines stay valid, and GC seldom takes them. The hot lines hold
pages that die soon, so their victims hold few valid pages.

**Q5.** This question has no measured answer yet. Accept a clear
argument in either direction.

- With the random map, each page gets one write in each pass. A page
  that survived GC has likely had no write yet in this pass. Its next
  write is then nearer than average. The separation puts such pages in
  the data lines, which can raise the WAF of run 2.
- With `--norandommap`, a write does not depend on the age of a page.
  A survivor then has the same chance of a write as any page. The
  separation gives no gain, and the extra line raises the model WAF
  from 3.44 to 3.59.

**Q6.** Under uniform writes, the oldest line is also the line with the
fewest valid pages, so the two policies pick the same victims. After the
separation, old lines are cold and still mostly valid. Young hot lines
lose pages fast. Cost-benefit waits for a hot line to lose more pages,
and greedy does not wait.

**Q7.** The rule sees only "has a mapping". After the fill, a rare write
to a cold page also goes to the hot lines. A hot page that GC copies
goes to the data lines. So each kind of line holds some pages of the
other class.

A closer rule keeps a write count for each page or each region. The
count decays with time, and the rule sends a page by its count. The
price is DRAM for the counts.

## Grading notes

- Runs 2, 5 and 6 have no measured value yet. Grade the argument.
- Run 7 can move between runs, because `cost-benefit` reads the host
  clock. Accept a value within about 10% of 1.646.
