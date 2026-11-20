# Answer key: lab 3, DFTL and the mapping cache

For the instructor. The lab is [lab 3](../lab3-dftl.md). No run of this
lab is on record yet. The values below come from the model and from
the DFTL section of the [FTL design page](../../design/ftl.md#dftl-mappingdftl).

## Prediction

```
                                  1 MiB CMT               4 MiB CMT
 TPs of the namespace             1 GiB / 2 MiB = 512     512
 TPs in the CMT                   1 MiB / 4 KiB = 256     1024
 logical space covered            512 MiB                 2 GiB (all of it)
 fill: TP programs                256                     0
 fill: TP reads                   0                       0
 m at W = 256, 768, 1024 MiB      0, 0.333, 0.5           0, 0, 0
 mean latency, W 1024 minus 256   about 20 us             about 0
 TP programs per host write       about 0.5               0
```

## Questions

**Q1.** 512 TPs. A 1 MiB CMT holds 256 of them.

**Q2.** The fill touches the 512 TPs in order. With 256 slots, each TP
after the first 256 takes the slot of a TP that the fill made dirty.
That victim is programmed: 256 programs. A new TP has no NAND copy, so
the fill reads none. With 1024 slots, no TP leaves the CMT.

**Q3.** The model is uniform and assumes a steady CMT. Accept any of
these reasons, with the data:

- CLOCK is not a perfect random or LRU cache over a short step.
- fio's random map makes the reads of a step a permutation, not
  independent picks.
- At W = 256, a few first touches can remain after the warm step.

**Q4.** After the fill, the CMT holds TPs 256 to 511, all dirty. The
warm step at W = 256 reads TPs 0 to 127, and each first touch misses.
Each miss evicts one of the dirty TPs, and a dirty victim is programmed.
When the dirty TPs are gone, reads program nothing. Over the warm and
read steps the sum is at most 256.

**Q5.** `p50_us` at W = 256 shows a hit: one data read. `p99_us` at
W = 1024 shows a miss: a TP read, then the data read. The difference is
near one page read, 40 us.

**Q6.** Expect `tp_per_host` above m. The value is to be measured. Two
kinds of TP work come with GC:

- GC moves valid data pages, and each move changes a mapping. A changed
  TP in the CMT only gets dirty. A changed TP outside the CMT goes
  pending. The FTL publishes it at the end of the victim with one read
  and one program.
- GC also moves the valid pages of TP lines. C0h 280 counts those moves.

**Q7.** 4 TiB / 4 KiB = 2^30 pages, x 8 bytes = 8 GiB of map. For m = 0.1
under uniform reads, the CMT must cover 90% of the drive: 7.2 GiB.

Real workloads have locality. A sequential stream touches one TP for
512 pages. A skewed workload touches a few TPs most of the time.

## Grading notes

- Q5: some students compare `p50_us` and `p99_us` of one step. At
  m = 0.5, the median sits at the edge of the two kinds of reads, so
  that comparison is weak. Ask for the two steps of the question.
- Q6: give full points only for both parts, the published TPs and the
  moved TP pages.
- A latency ratio is not a valid answer to prediction 4. The host and
  guest overhead does not cancel in a ratio.
