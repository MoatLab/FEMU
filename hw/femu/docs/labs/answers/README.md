# Answer keys

For the instructor. One key for each lab:

| Lab | Key |
| --- | --- |
| [1 GC and WAF](../lab1-gc-and-waf.md) | [lab1-gc-and-waf-key.md](lab1-gc-and-waf-key.md) |
| [2 Hot and cold](../lab2-hot-and-cold.md) | [lab2-hot-and-cold-key.md](lab2-hot-and-cold-key.md) |
| [3 DFTL](../lab3-dftl.md) | [lab3-dftl-key.md](lab3-dftl-key.md) |
| [4 FDP](../lab4-fdp.md) | [lab4-fdp-key.md](lab4-fdp-key.md) |

The keys are public, as is all of the FEMU repository. For graded work,
change the device lines, then compute the new answers with
`lab-waf-model.py`:

```
 keep                            change
 ------------------------------  -----------------------------------------
 the method and the questions    blks_per_pl, op_pcent, gc_thres_pcent,
                                 mapping_cache_mb, the working sets (LAB_WS)
```

A value marked "to be measured" has no run behind it yet. Do not grade
a student against such a value. Grade the argument, and ask the student
to report the measured value with the `LAB` line.
