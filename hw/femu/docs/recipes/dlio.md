# Recipe: DLIO training and checkpoint I/O

> **Status: one run passed on a host (2026-11-21).** One run on an x86
> host with KVM used the device line of section 1, with `io_trace`
> added. The guest ran Ubuntu 24.04.5 with kernel 6.8.0-139-generic.
> The install of DLIO `v2.0.1` and the guest script worked, and the
> verdict was `PASS`. Section 5 lists each prediction with the measured
> value. No run has checked `DLIO_CONTROL=page-cache`, other option
> values or the repeatability of the numbers.

[DLIO](https://github.com/argonne-lcf/dlio_benchmark) gives the storage
I/O of a deep learning training job. It writes a dataset, reads it in
batches and writes checkpoints. A sleep stands for the accelerator, so
the guest needs none. MLPerf Storage uses DLIO in the same way.

```
 DLIO in the guest (no accelerator)
   generate:  72 npz files of 16 MiB ---- buffered writes, then sync ---+
   train:     read a batch (O_DIRECT) --> sleep 0.05 s --> next batch   |
              after each epoch: write a checkpoint of 256 MiB           |
                                                                        v
                                       ext4 on /dev/nvme0n1 --> FEMU bbssd
                                              FTL --> NAND model --> due time
```

## 1. Start the guest (on the host)

<!-- femu-example: recipe-dlio-boot -->
```bash
./qemu-system-x86_64 -name femu-recipe-dlio,debug-threads=on \
    -enable-kvm -cpu host -smp 4 -m 8G \
    -device virtio-scsi-pci,id=scsi0 -device scsi-hd,drive=hd0 \
    -drive file=$OSIMGF,if=none,cache=none,format=qcow2,id=hd0 \
    -net user,hostfwd=tcp::$SSH_PORT-:22 -net nic,model=virtio \
    -device femu,id=femu0,femu_mode=1,devsz_mb=3072,nchs=8,luns_per_ch=8,blks_per_pl=64,io_stages=on \
    -qmp unix:/tmp/femu-qmp.sock,server=on,wait=off \
    -nographic
```

| Option | Meaning |
| --- | --- |
| `femu_mode=1` | BlackBox mode: the device runs its own FTL, GC and NAND timing |
| `nchs=8,luns_per_ch=8,blks_per_pl=64` | 4 GiB of NAND in 64 lines of 64 MiB |
| `devsz_mb=3072` | a 3 GiB namespace, 75% of the NAND |
| `io_stages=on` | stage times for `femu-stat.py` and `query-femu-stages` |
| `id=femu0` and `-qmp` | a QMP socket for the host tools |

The device needs about 3 GiB of host memory, and the guest needs 8 GiB more.
To capture a trace, add `,io_trace=/var/tmp/dlio-trace.csv` to the
`femu` device. The file must not exist.

## 2. Guest setup

The guest script does the setup. These are its steps, for a setup by
hand:

```sh
sudo apt-get install -y git build-essential python3-dev python3-venv \
    openmpi-bin libopenmpi-dev
git clone https://github.com/argonne-lcf/dlio_benchmark
cd dlio_benchmark
git checkout v2.0.1
python3 -m venv ~/dlio-venv
~/dlio-venv/bin/pip install .
```

| Fact | Source | State |
| --- | --- | --- |
| Tag `v2.0.1` is commit `b56c74183c64` | the tag list of the repository | checked on 2026-11-19 |
| `git clone`, then `pip install .` | `docs/source/install.rst` at the tag | checked |
| `mpi4py` is necessary, so an MPI library is necessary | `setup.py` at the tag | checked |
| The OpenMPI packages | the CI file of the repository, on Ubuntu 22.04 | checked for 22.04; OpenMPI 4.1.6 installed on Ubuntu 24.04 in one run |
| The install brings TensorFlow, PyTorch and a DALI package | `setup.py` at the tag | checked; the size on disk is not known |
| Python 3.12 of Ubuntu 24.04 | the CI tests Python 3.9 to 3.11; one run on FEMU | confirmed by one run with Python 3.12.3 |
| A run with no `mpirun` | `README.md` at the tag | checked; confirmed by one run |
| `checkpoint.fsync` has no effect | `utils/config.py` and `checkpointing/base_checkpointing.py` at the tag | checked |

The install is large. Keep several GiB free on the guest disk.

## 3. Run

In the guest, as root:

```sh
sudo bash recipe-dlio-guest.sh --yes nvme0n1
```

The script makes an ext4 file system on the namespace. It runs DLIO two
times with the base workload `unet3d_a100`, made small by options.

```
 phase      DLIO options (each starts with ++workload.)
 ---------  ----------------------------------------------------------
 both       dataset.data_folder, dataset.num_files_train=64,
            dataset.num_files_eval=8, dataset.num_samples_per_file=1,
            dataset.record_length_bytes=16777216,
            dataset.record_length_bytes_stdev=0,
            checkpoint.checkpoint_folder, workflow.evaluation=False
 generate   workflow.generate_data=True, workflow.train=False,
            workflow.checkpoint=False
 train      workflow.train=True, workflow.checkpoint=True,
            train.epochs=2, train.computation_time=0.05,
            reader.batch_size=4, reader.read_threads=0,
            reader.odirect=True, checkpoint.checkpoint_after_epoch=1,
            checkpoint.epochs_between_checkpoints=1,
            model.model_size_bytes=268435456
```

`train.computation_time` is the sleep for one batch. It stands for the
accelerator. `reader.odirect=True` makes DLIO read each npz file with
`O_DIRECT`, so the guest page cache does not answer for the device.

The size key is `record_length_bytes`. The DLIO configuration page
names it `record_length`, but the loader at tag `v2.0.1` reads
`record_length_bytes` only.

The script does not set `checkpoint.fsync`. At tag `v2.0.1` the loader
stores that option under one name, and the checkpoint code reads
another name. The option thus has no effect. DLIO writes a checkpoint
to the page cache, and the script calls `sync` after each DLIO run.

| Variable | Default | Meaning |
| --- | --- | --- |
| `DLIO_REF` | `v2.0.1` | tag or commit of DLIO |
| `DLIO_PREFIX` | `/opt/femu-dlio` | the Python environment; an install of the same ref is used again |
| `DLIO_FILES` | 64 | training files |
| `DLIO_RECORD_BYTES` | 16777216 | bytes of one file |
| `DLIO_EPOCHS` | 2 | epochs |
| `DLIO_BATCH` | 4 | samples in one batch |
| `DLIO_COMPUTE_SEC` | 0.05 | sleep for one batch |
| `DLIO_MODEL_BYTES` | 268435456 | bytes of one checkpoint |
| `DLIO_TIMEOUT` | 1800 | seconds for each DLIO run |
| `DLIO_INSTALL_TIMEOUT` | 3600 | seconds for the install |
| `DLIO_CONTROL` | none | `page-cache`: read from the page cache, so the read checks must fail |

The last line of the script is the verdict:

```text
DLIO_RESULT=PASS recipe=dlio ref=v2.0.1 dataset_bytes=N epochs=2 checkpoint_bytes=N waf=N control=none
```

The verdict is `PASS`, `FAIL` or `SETUP-ERROR`, and the exit status is
0, 1 or 2 in that order. The script also writes the verdict line to the
file `DONE` in its scratch directory.

### What the script checks

| Phase | Check | A defect that makes it fail |
| --- | --- | --- |
| generate | the dataset has at least half of the configured size | a size option with a wrong name has no effect |
| generate | the block layer and the C0h host pages each count 90% of the dataset | the files stay in the page cache |
| train | DLIO writes `summary.json` | the run stopped early |
| train | the block layer reads 90% of the training files | the page cache answers the reads |
| train | the C0h plane read count grows | the reads do not reach the NAND model |
| train | after the `sync` of the script, the block layer and the C0h host pages each count 90% of one checkpoint | the size option has no effect, or the checkpoint is not on the namespace |

`DLIO_CONTROL=page-cache` shows that the read check can fail. The script
then reads the files into the page cache and switches `O_DIRECT` off.
The verdict must be `FAIL` with `DLIO_FAIL=train-block-reads`.

The checks show I/O traffic. They do not show that a checkpoint can be
loaded again.

## 4. What to measure

```
 source                         value
 -----------------------------  ---------------------------------------
 DLIO_COUNTERS= (guest script)  host, GC and NAND pages and the WAF of
                                each phase; plane reads; block bytes
 DLIO_TRAIN= (guest script)     mean accelerator utilization of DLIO
 femu-stat.py (host)            live WAF, line counts, stage times
 io_trace + femu-trace2fio.py   size mix, queues, depth, bursts
```

On the host, while the script runs:

```sh
python3 hw/femu/scripts/femu-stat.py /tmp/femu-qmp.sock
```

The `past-due` row shows whether completions landed at the due time of
the model. Report it with each latency result.

The accelerator utilization comes from `summary.json` of DLIO
(`train_au_mean_percentage`). It is the share of time that the emulated
accelerator did not wait for data.

For the shape report, give the trace to `femu-trace2fio.py` with
`--block-size 512`.

## 5. Expected behaviour

One run on 2026-11-21 measured these values. One run is one sample.

| Prediction | Reason | Run of 2026-11-21 |
| --- | --- | --- |
| The generate phase has a WAF near 1.0. | The dataset fills 1.1 GiB of an empty 3 GiB namespace. GC finds no line to collect. | Confirmed: WAF 1.000, 0 GC pages, 295061 host pages. |
| The checkpoint writes reach the device in bursts, at times that the guest writeback sets. | DLIO writes a checkpoint to the page cache with no `fsync` at this tag. The kernel writes it out afterwards, and the last part at the `sync` of the script. | Partly confirmed: the trace has no write during the training reads. Both checkpoints reached the device together, 537067520 bytes in one burst of 0.5 s after the training reads. |
| The WAF of the train phase stays near 1.0 with the default options. | Two checkpoints of 256 MiB do not fill the free space. | Confirmed: WAF 1.000, 0 GC pages, 131115 host pages. |
| The read sizes follow the block layer, not the 16 MiB file. | The guest splits a large `O_DIRECT` read at the request size limit of the block layer. | Confirmed: no read is above 2 MiB, and 1546 of 2096 reads are in the `2097152` size line. |
| A longer `DLIO_COMPUTE_SEC` raises the accelerator utilization. | The sleep hides the read time of a batch. | No run confirms it. The run used 0.05 s only and gave 70.40%. |

More epochs do not predict a higher WAF. A new checkpoint file takes
new blocks, and the old checkpoint stays valid for the FTL. GC gains
no space from a line of valid pages. A WAF study of checkpoints needs
a workload that writes over the same blocks, which this recipe is not.

## 6. Limits

- One run exists. It confirms three predictions of section 5 and a
  part of a fourth. One prediction has no run.
- DLIO marks the utilization of 70.40% as below its own expectation
  (`train_au_meet_expectation` is `fail`). The guest script does not
  check this value.
- The dataset is small. A dataset below the guest memory size gives
  real device reads only with `O_DIRECT`. DLIO supports `O_DIRECT` for
  the `npy` and `npz` formats only.
- The sleep time is not a measured time of a real accelerator.
- The script does not load a checkpoint.
- The checkpoint timing is the timing of the guest writeback, not of an
  `fsync` after each checkpoint.
- The WAF on the `DLIO_COUNTERS=` line leaves out pad pages and
  translation pages.

## Related pages

- [Workload recipes](README.md): the common steps and the result rules.
- [BlackBox mode](../modes/blackbox.md): geometry, GC and the write
  buffer.
- [Measuring](../guides/measuring.md): the counters and the trace.
