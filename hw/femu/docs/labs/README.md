# Teaching labs

Four graded labs for a course on storage systems. Each lab takes one
mechanism of the BlackBox FTL. The student predicts a number, measures it
on an emulated SSD, and explains the difference. Each lab runs in under
30 minutes on one VM.

| Lab | Mechanism | The student learns to | Device |
| --- | --- | --- | --- |
| [1 GC and WAF](lab1-gc-and-waf.md) | garbage collection (GC) thresholds and spare capacity | predict the write amplification factor (WAF) and name the GC regime | BBSSD, 2 GiB of NAND |
| [2 Hot and cold](lab2-hot-and-cold.md) | `hot_cold_sep` and the victim policy | tell which data a separation rule keeps apart, and when that helps | BBSSD, 2 GiB of NAND |
| [3 DFTL](lab3-dftl.md) | `mapping=dftl` and its cached mapping table | predict the miss ratio of the mapping cache and its cost in reads, programs and latency | BBSSD, 2 GiB of NAND |
| [4 FDP](lab4-fdp.md) | Flexible Data Placement | predict when placement lowers the WAF, and when it cannot | BBSSD with FDP, 512 MiB and 1 GiB of NAND |

The labs build on [tutorial 02](../tutorials/02-gc-and-waf.md) and
[tutorial 04](../tutorials/04-fdp.md). Those pages show the steps once.
A lab asks for a prediction first, then the measurement, then an
explanation. The answer keys for the instructor are in
[answers/](answers/README.md).

## Before the first lab

You need a built FEMU, a guest image and the three shell variables of
[Before you start](../tutorials/README.md#before-you-start). Copy the lab
scripts into the guest from `build-femu/`:

```sh
for f in lab-common.sh lab-gc-waf.sh lab-hot-cold.sh lab-dftl.sh lab-fdp.sh; do
    ./run-guest-ssh.sh "cat > $f" < ../femu-scripts/labs/$f
done
```

The guest image from `make-guest-image.sh` has fio 3.36, nvme-cli 2.8
and Python 3. The scripts need nothing else.

The model script runs on the host. It needs only Python 3:

```sh
python3 ../femu-scripts/labs/lab-waf-model.py --self-test
```

## The method of every lab

```
 restart QEMU            the counters, the mapping and the NAND start at zero
      |
      v
 time off (labs 1,2,4)   vendor command 0xEF, codes 2 and 4: GC and NAND
      |                  operations take no time; page counts do not change
      v
 fill                    write the namespace once, sequential 128 KiB
      |
      v
 age                     the measured workload, about 2.5 x the namespace
      |
      v
 snapshot C0h --> measured run --> snapshot C0h
                                        |
                                        v
 WAF of the run = (d nand + d gc + d tp_prog + d pad) / d host
 ("d" = the counter after the run minus the counter before it)
```

Restart QEMU for each configuration. The lab script does the other
steps. Its last line starts with `LAB` and the lab number. The
`check=ok` field says that the host page count moved with the bytes
that fio wrote. A `check=FAIL` line is no result: look for a wrong
device node or a failed fio step.

The counters come from the vendor log page C0h
([log pages and counters](../reference/log-pages-and-counters.md#vendor-log-page-c0h)):

| Name in the line | C0h offset | Meaning |
| --- | --- | --- |
| `host` | 8 | pages the host wrote |
| `gc` | 16 | pages GC copied |
| `nand` | 24 | pages programmed for the host |
| `forced_waits` | 192 | host writes that waited for forced GC |
| `forced_passes` | 200 | forced GC passes |
| `pad` | 264 | pad pages |
| `tp_prog` | 280 | translation pages programmed (`mapping=dftl`) |
| `tp_read` | 288 | translation pages read (`mapping=dftl`) |

## How to grade

Each lab has three parts with points:

| Part | Points | What the student hands in |
| --- | --- | --- |
| Prediction | 30 | the predicted values and the formula or argument, written before the run |
| Measurement | 30 | the `LAB` lines and a table of the results |
| Questions | 40 | answers to the questions, easy to hard |

Grade a prediction by its argument, not by its distance from the
measurement. A wrong prediction with a clear argument and a correct
explanation of the error gets full points.

## The model

`lab-waf-model.py` holds three first-order models. Each lab page gives
the formula, so a student can also work with a calculator.

```
 FIFO log, uniform random overwrites:
   alpha = D / T = (1 - u) / (-ln u)        WAF = 1 / (1 - u)
   D = data lines, T = lines of the pool, u = valid share of a victim
```

```sh
python3 ../femu-scripts/labs/lab-waf-model.py uniform --lines 128 --fill 0.8 --gc 95
python3 ../femu-scripts/labs/lab-waf-model.py classes --pool 121 --class 0.8:20.48 --class 0.2:81.92
python3 ../femu-scripts/labs/lab-waf-model.py dftl --cmt-mb 1 --ws-mb 1024
```

The models are simple on purpose. The FTL picks victims by a policy, not
in FIFO order, and its GC rules have limits that a model leaves out.
Each lab asks the student to explain where the model and the
measurement differ.

## Where the expected values come from

Every expected value on a lab page names its source:

- **measured**: a run of the same device line and workload, with the
  commit and the host. Values from tutorials 02 and 04 ran at commit
  `1a03ded0f`. Later commits can move them by a few percent.
- **model**: a value of `lab-waf-model.py`, with no run behind it. The
  device value is **to be measured**. Each lab page gives the formula.
