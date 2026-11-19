# Recipe: DiskANN vector search on the SSD

> **Status: not yet validated on a host.** This recipe has not run on
> FEMU. The device line passes the lint of the documentation check,
> which starts no device. The DiskANN
> commands come from the DiskANN repository at tag `0.7.0`. No run
> confirms the guest script, the build on Ubuntu 24.04 or the expected
> behaviour.

[DiskANN](https://github.com/microsoft/DiskANN) keeps a graph index of
vectors in one file on the SSD. A query walks the graph. Each step
reads a few 4 KiB sectors with `O_DIRECT` through Linux AIO. The
workload is thus many small random reads at a low queue depth for each
thread.

```
 build (once)                             search (each query)
 base vectors (RAM) --> graph --> index   start at the entry point
        sequential writes to the file     read W sectors of 4 KiB (O_DIRECT)
                                          pick the nearest nodes, read again
                                          stop when the list of L nodes is done
                         |                        |
                         v                        v
                 ext4 on /dev/nvme0n1 ----> FEMU bbssd: FTL --> NAND model
```

## 1. Start the guest (on the host)

<!-- femu-example: recipe-diskann-boot -->
```bash
./qemu-system-x86_64 -name femu-recipe-diskann,debug-threads=on \
    -enable-kvm -cpu host -smp 4 -m 8G \
    -device virtio-scsi-pci,id=scsi0 -device scsi-hd,drive=hd0 \
    -drive file=$OSIMGF,if=none,cache=none,format=qcow2,id=hd0 \
    -net user,hostfwd=tcp::$SSH_PORT-:22 -net nic,model=virtio \
    -device femu,id=femu0,femu_mode=1,devsz_mb=1536,nchs=4,luns_per_ch=4,blks_per_pl=128,read_reclaim_limit=5000,io_stages=on \
    -qmp unix:/tmp/femu-qmp.sock,server=on,wait=off \
    -nographic
```

| Option | Meaning |
| --- | --- |
| `femu_mode=1` | BlackBox mode: the device runs its own FTL, GC and NAND timing |
| `nchs=4,luns_per_ch=4,blks_per_pl=128` | 2 GiB of NAND in 128 lines of 16 MiB |
| `devsz_mb=1536` | a 1.5 GiB namespace, 75% of the NAND |
| `read_reclaim_limit=5000` | a block that takes 5000 page reads marks its line for a rewrite |
| `io_stages=on` | stage times for `femu-stat.py` and `query-femu-stages` |
| `id=femu0` and `-qmp` | a QMP socket for the host tools |

The limit of 5000 is low on purpose, so that a short run can reach it.
To capture a trace, add `,io_trace=/var/tmp/diskann-trace.csv` to the
`femu` device. The file must not exist.

## 2. Guest setup

The guest script does the setup. These are its steps, for a setup by
hand:

```sh
sudo apt install make cmake g++ libaio-dev libgoogle-perftools-dev \
    clang-format libboost-all-dev
sudo apt install libmkl-full-dev
git clone https://github.com/microsoft/DiskANN
cd DiskANN
git checkout 0.7.0
mkdir build && cd build && cmake -DCMAKE_BUILD_TYPE=Release .. && make -j
```

| Fact | Source | State |
| --- | --- | --- |
| The C++ tools are on tag `0.7.0` and branch `cpp_main`; `main` is Rust | `README.md` on `main` | checked on 2026-11-19 |
| Tag `0.7.0` is commit `df225d32da81` | the tag list of the repository | checked |
| The `apt` packages and the `cmake` line | `README.md` at the tag, section for Ubuntu 20.04 or newer | checked |
| A build with GCC 13 on Ubuntu 24.04 | none | not confirmed |
| `libmkl-full-dev` on Ubuntu 24.04 | none | not confirmed |
| The tool options | `workflows/SSD_index.md` and the tool sources at the tag | checked |
| The tool paths `apps/` and `apps/utils/` in the build directory | the examples in `workflows/SSD_index.md` | checked; `rand_data_gen` not confirmed |
| `search_disk_index` opens the index with `O_DIRECT` and reads sectors of 4096 bytes with libaio | `src/linux_aligned_file_reader.cpp` at the tag | checked |

When the tag does not build, try `DISKANN_REF=cpp_main`. That branch is
not pinned, so record its commit with the result. The script prints it.

## 3. Run

In the guest, as root:

```sh
sudo bash recipe-diskann-guest.sh --yes nvme0n1
```

The script makes an ext4 file system on the namespace and runs four
tools. The data files are in the scratch directory of the script. The
index is on the namespace.

```sh
rand_data_gen --data_type float --output_file base.fbin -D 96 -N 200000 --norm 1.0
rand_data_gen --data_type float --output_file query.fbin -D 96 -N 2000 --norm 1.0
compute_groundtruth --data_type float --dist_fn l2 --base_file base.fbin \
    --query_file query.fbin --gt_file truth --K 100
build_disk_index --data_type float --dist_fn l2 --data_path base.fbin \
    --index_path_prefix MNT/index -R 32 -L 50 -B 0.006 -M 1 -T 4
search_disk_index --data_type float --dist_fn l2 --index_path_prefix MNT/index \
    --query_file query.fbin --gt_file truth -K 10 -L 20 40 80 \
    --result_path result --num_nodes_to_cache 0 -T 4 -W 2
```

| Option | Meaning |
| --- | --- |
| `-R 32 -L 50` | graph degree and build list size |
| `-B 0.006` | memory of the index at search time, in GB; it sets the size of the compressed vectors in RAM |
| `-M 1` | memory of the build, in GB |
| `-L 20 40 80` | three search list sizes; a longer list reads more sectors for each query |
| `-W 2` | beam width: sectors that one step reads at the same time |
| `--num_nodes_to_cache 0` | keep no graph node in RAM, so each step reads the SSD |

The script drops the guest page cache between build and search.

| Variable | Default | Meaning |
| --- | --- | --- |
| `DISKANN_REF` | `0.7.0` | tag, branch or commit of DiskANN |
| `DISKANN_PREFIX` | `/opt/femu-diskann` | the build; a build of the same ref is used again |
| `DISKANN_JOBS` | the number of CPUs | build jobs |
| `DISKANN_POINTS` | 200000 | base vectors |
| `DISKANN_DIM` | 96 | dimensions |
| `DISKANN_QUERIES` | 2000 | query vectors |
| `DISKANN_LISTS` | `20 40 80` | search list sizes; each must be 10 or more, because the tool skips a list size below K |
| `DISKANN_THREADS` | 4 | build and search threads |
| `DISKANN_SEARCH_GB` | 0.006 | `-B` |
| `DISKANN_BUILD_GB` | 1 | `-M` |
| `DISKANN_TIMEOUT` | 3600 | seconds for each DiskANN tool |
| `DISKANN_INSTALL_TIMEOUT` | 3600 | seconds for the install |
| `DISKANN_CONTROL` | none | `index-off-device`: put the index in the scratch directory, so the device checks must fail |

The last line of the script is the verdict:

```text
DISKANN_RESULT=PASS recipe=diskann ref=0.7.0 points=200000 queries=2000 index_bytes=N search_read_bytes=N control=none
```

The verdict is `PASS`, `FAIL` or `SETUP-ERROR`, and the exit status is
0, 1 or 2 in that order. The script also writes the verdict line to the
file `DONE` in its scratch directory.

### What the script checks

| Phase | Check | A defect that makes it fail |
| --- | --- | --- |
| build | the file `index_disk.index` exists | the build stopped early |
| build | the block layer and the C0h host pages each count 90% of the index file | the index stays in the page cache |
| search | a result file of the expected size exists for each list size | the tool skipped a list size, or stopped early |
| search | the block layer reads one 4 KiB sector or more for each query at each list size | the index is not on the namespace, or RAM answers the queries |
| search | the C0h plane read count grows | the reads do not reach the NAND model |

`DISKANN_CONTROL=index-off-device` shows that the device checks can
fail. The verdict must then be `FAIL`.

The script does not check the recall or the latency. The base vectors
are random, and random vectors give a low recall.

## 4. What to measure

```
 source                           value
 -------------------------------  -------------------------------------
 DISKANN_SEARCH: (guest script)   the result table of search_disk_index,
                                  one line for each list size
 DISKANN_COUNTERS= (guest script) pages, WAF, plane reads, block bytes,
                                  reads of the most-read block, lines
                                  rewritten for read stress
 femu-stat.py (host)              stage times and the past-due share
 io_trace + femu-trace2fio.py     size mix, queues, depth, bursts
```

The result table of `search_disk_index` has these columns: `L`,
`Beamwidth`, `QPS`, `Mean Latency`, `99.9 Latency`, `Mean IOs`, `CPU (s)`
and the recall. The DiskANN workflow page gives the latency in
microseconds and `Mean IOs` in 4 KiB reads for each query.

The latency in that table is the time of a whole query, with the CPU
work of the search. The read latency of the device is in the trace:
`t_cqe_ns - t_submit_ns` for each command.

For the search phase, expect this shape report:

- reads only, apart from a few file system writes;
- most reads in the `4096` size line (the block layer can merge two
  neighbour sectors into one `8192` read);
- a low sequential share;
- a depth maximum near the thread count times the beam width.

## 5. Expected behaviour

No run has confirmed these predictions.

| Prediction | Reason |
| --- | --- |
| `Mean IOs` grows with the list size L. | A longer list makes the search visit more nodes, and each node is a sector read. |
| The mean query latency grows with L by about the added reads times the read time of the model. | Each step waits for its sector reads before the next step. |
| The 99.9th percentile latency of a query is well above the mean. | Reads of one die wait for each other, and four threads read at random. |
| `max_block_reads` grows by about one read for each query. | Each query starts at the same entry point, so one flash block takes a read for each query. |
| `read_reclaim_lines` rises only when a write follows the reads. | FEMU queues at most one line on a read and rewrites it on a following write. The search writes no data, apart from file system writes. |
| The search phase has no useful WAF. | The search writes no data. The script prints `-`, or a value from a few file system writes. |

To see the read reclaim, write to the namespace after the search and
read log page C0h again. A write rewrites at most one queued line. FEMU
can delay the rewrite when free lines are few, and it drops a line that
the write pointer still fills. The count after one write can thus stay
the same. A rewrite shows as write amplification.

## 6. Limits

- No run exists. Section 5 is a set of predictions.
- The prediction on the entry point reads follows from the search
  algorithm. No source states the read count of one block.
- The vectors are random, so the recall has no meaning.
- The index of 200000 vectors is small. The query latency of a large
  index has more steps and more reads.
- The query latency holds CPU time of the guest. Do not read it as a
  device latency.
- The read reclaim limit of 5000 is far below a real limit. It makes the
  mechanism visible. It is not a model of a real part.

## Related pages

- [Workload recipes](README.md): the common steps and the result rules.
- [BlackBox mode](../modes/blackbox.md#wear-retention-and-errors): read
  reclaim and the other refresh options.
- [Timing model](../concepts/timing-model.md): when a completion time is
  valid.
