# Recipe: RocksDB db_bench on the SSD

> **Status: partly validated on a host (2026-11-21).** One run on an
> x86 host with KVM used the device line of section 1, with `io_trace`
> added. The guest ran Ubuntu 24.04.5 with kernel 6.8.0-139-generic.
> RocksDB `v9.10.0` built, the three phases ran and the verdict was
> `PASS`. The low spare device of section 5 has not run, so no run
> tests the predictions of section 6 that compare the two devices. No
> run has checked `ROCKSDB_CONTROL=db-off-device`.
>
> That run had one overwrite pass. It wrote 1.71 GB, and GC did not
> start. The overwrite phase now runs five passes, so that the device
> passes its GC threshold. No run has tested this change yet.

[RocksDB](https://github.com/facebook/rocksdb) is a key-value store
with a log-structured merge tree (LSM tree). `db_bench` is its
benchmark tool. A write goes to a write-ahead log and to a memtable in
memory. A full memtable becomes a sorted table file (a flush).
Compaction merges table files into the next level and deletes the old
files.

```
 Put(key, value)
   |--> write-ahead log (WAL) ------------------------> deleted after the flush
   |--> memtable (32 MiB) --flush--> L0 table files
                                       |  compaction: read, merge, write
                                       v
                                     L1 (128 MiB) --> L2 --> ...
                                       |
                                       v
                   ext4 on /dev/nvme0n1 ----> FEMU bbssd: FTL --> NAND model
```

The recipe shows two write amplifications in series. RocksDB writes
each user byte several times (flush and compaction). The FTL then
writes each host byte one or more times (GC). The guest sees the
first. FEMU shows the second.

```
 user bytes --(LSM)--> table bytes --(+ WAL, ext4)--> host bytes --(GC)--> NAND bytes
 rocksdb.bytes.written  flush.write.bytes            C0h host pages     C0h NAND and
                        + compact.write.bytes                           GC pages
```

## 1. Start the guest (on the host)

<!-- femu-example: recipe-rocksdb-boot -->
```bash
./qemu-system-x86_64 -name femu-recipe-rocksdb,debug-threads=on \
    -enable-kvm -cpu host -smp 4 -m 8G \
    -device virtio-scsi-pci,id=scsi0 -device scsi-hd,drive=hd0 \
    -drive file=$OSIMGF,if=none,cache=none,format=qcow2,id=hd0 \
    -net user,hostfwd=tcp::$SSH_PORT-:22 -net nic,model=virtio \
    -device femu,id=femu0,femu_mode=1,devsz_mb=1536,nchs=4,luns_per_ch=4,blks_per_pl=192,gc_thres_pcent=90,io_stages=on \
    -qmp unix:/tmp/femu-qmp.sock,server=on,wait=off \
    -nographic
```

| Option | Meaning |
| --- | --- |
| `femu_mode=1` | BlackBox mode: the device runs its own FTL, GC and NAND timing |
| `nchs=4,luns_per_ch=4,blks_per_pl=192` | 3 GiB of NAND in 192 lines of 16 MiB |
| `devsz_mb=1536` | a 1.5 GiB namespace, 50% of the NAND |
| `gc_thres_pcent=90` | background GC starts at 19 free lines; section 5 gives the reason |
| `io_stages=on` | stage times for `femu-stat.py` and `query-femu-stages` |
| `id=femu0` and `-qmp` | a QMP socket for the host tools |

The guest needs 8 GiB of memory for the RocksDB build. To capture a
trace, add `,io_trace=/var/tmp/rocksdb-trace.csv` to the `femu` device.
The file must not exist. Restart QEMU before each run, so that each run
starts from an empty device.

## 2. Guest setup

The guest script does the setup. These are its steps, for a setup by
hand:

```sh
sudo apt install build-essential git libgflags-dev e2fsprogs
git init rocksdb && cd rocksdb
git fetch --depth 1 https://github.com/facebook/rocksdb.git v9.10.0
git checkout FETCH_HEAD
make -j"$(nproc)" DEBUG_LEVEL=0 PORTABLE=1 DISABLE_WARNING_AS_ERROR=1 db_bench
```

| Fact | Source | State |
| --- | --- | --- |
| Tag `v9.10.0` builds with `make DEBUG_LEVEL=0 DISABLE_WARNING_AS_ERROR=1` on the guest image | `zenfs-crash-guest.sh` uses the same tag and options; one run of this recipe | confirmed by one run, with `PORTABLE=1` |
| GCC 13 reports a false array-bounds error in RocksDB 9.10 | the comment in `zenfs-crash-guest.sh`; one run of this recipe | one run showed one `-Warray-bounds` warning in `memtable/wbwi_memtable.h`, and the build ended; the log does not show whether the warning is false or name the compiler |
| `db_bench` needs gflags; without it the tool prints a note and exits | the RocksDB `INSTALL.md` | not checked against the tag; one build with `libgflags-dev` 2.2.2 passed |
| The names of the statistics counters and the format of the result line | the `db_bench` source at `v9.10.0` | checked by a review; in one run the script read each value |

`DEBUG_LEVEL=0` makes a release build. The default build of the
Makefile keeps the assertions and runs slower. `PORTABLE=1` leaves out
`-march=native`, so the binary does not depend on the host CPU.

## 3. Run

In the guest, as root:

```sh
sudo bash recipe-rocksdb-guest.sh --yes nvme0n1
```

The script makes an ext4 file system on the namespace and runs three
`db_bench` phases on it. Each phase is a new process, so each phase has
its own statistics. Each phase ends with the `flush` and
`waitforcompaction` benchmarks. Thus the statistics and the counters
cover the same finished work.

```
 phase      benchmark               options of the phase
 ---------  ----------------------  ---------------------------------------
 fill       fillrandom              --use_existing_db=0
 overwrite  overwrite               --use_existing_db=1 --writes=2000000
                                    (5 passes of 400000 writes)
 mixed      readrandomwriterandom   --use_existing_db=1 --readwritepercent=90
                                    --threads=2 --reads=150000

 before each phase: write back and drop the page cache, read C0h
 in each phase:     BENCHMARK, then flush, then waitforcompaction,
                    then db_bench prints its statistics
 after each phase:  write back, read C0h again, parse the db_bench log
```

The options of all phases:

```sh
db_bench --db=MNT/db --num=400000 --key_size=16 --value_size=1000 \
    --compression_type=none --seed=42 --statistics=1 --histogram=1 \
    --write_buffer_size=33554432 --target_file_size_base=33554432 \
    --max_bytes_for_level_base=134217728 --max_background_jobs=2 \
    --bloom_bits=10 --cache_size=8388608 --use_direct_reads=1 \
    --benchmarks=BENCHMARK,flush,waitforcompaction OPTIONS-OF-THE-PHASE
```

| Option | Meaning |
| --- | --- |
| `--num=400000 --value_size=1000` | about 406 MB of keys and values; the fill writes random keys, so some keys repeat. One Put is 1032 bytes of write batch, so the user bytes are about 413 MB for the fill and for each overwrite pass |
| `--writes=2000000` (overwrite only) | `ROCKSDB_OVERWRITE_PASSES` x `--num` random writes over the same `--num` keys, in one process |
| `--compression_type=none` | the byte counts do not depend on the data |
| `--seed=42` | the same keys in each run, so two runs compare |
| `--write_buffer_size`, `--target_file_size_base` | 32 MiB memtables and table files |
| `--max_bytes_for_level_base` | a level 1 of 128 MiB, so a small database gets several levels |
| `--use_direct_reads=1` | reads use `O_DIRECT`, so a read that the 8 MiB block cache does not hold goes to the device |
| `--reads=150000 --threads=2` | the mixed phase does 300000 operations; a count, not a duration, so the run time and the trace stay small |

| Variable | Default | Meaning |
| --- | --- | --- |
| `ROCKSDB_REF` | `v9.10.0` | tag, branch or commit of RocksDB |
| `ROCKSDB_PREFIX` | `/opt/femu-rocksdb` | the build; a build of the same ref is used again |
| `ROCKSDB_JOBS` | the number of CPUs | build jobs |
| `ROCKSDB_NUM` | 400000 | keys of the fill, and writes of each overwrite pass |
| `ROCKSDB_OVERWRITE_PASSES` | 5 | overwrite passes; the overwrite phase does this many times `ROCKSDB_NUM` writes |
| `ROCKSDB_VALUE_SIZE` | 1000 | value bytes |
| `ROCKSDB_MIXED_READS` | 150000 | operations of each thread in the mixed phase |
| `ROCKSDB_THREADS` | 2 | threads of the mixed phase |
| `ROCKSDB_SEED` | 42 | seed of the keys |
| `ROCKSDB_TIMEOUT` | 1800 | seconds for each phase |
| `ROCKSDB_INSTALL_TIMEOUT` | 3600 | seconds for all install steps together |
| `ROCKSDB_CONTROL` | none | `db-off-device`: put the database in the scratch directory, so the device checks must fail |

The last line of the script is the verdict:

```text
ROCKSDB_RESULT=PASS recipe=rocksdb ref=v9.10.0 num=400000 overwrite_passes=5 value_size=1000 user_bytes=N lsm_write_bytes=N lsm_wa=N device_waf=N control=none
```

The verdict is `PASS`, `FAIL` or `SETUP-ERROR`, and the exit status is
0, 1 or 2 in that order. The script also writes the verdict line to the
file `DONE` in its scratch directory.

### What the script checks

| Phase | Check | A defect that makes it fail |
| --- | --- | --- |
| each | `db_bench` exits 0 inside its time limit and prints its result line | the tool stopped, or the file system failed |
| each | the result line has the planned operation count | the phase stopped early, or ran with other options |
| each | the log has no `get error:` line | a read found a checksum or I/O error, and the phase continued |
| each | the statistics hold the user, flush, compaction and keys-written counts | the tool printed no statistics |
| fill, overwrite | each operation wrote a key; the overwrite does `ROCKSDB_OVERWRITE_PASSES` x `ROCKSDB_NUM` operations | the phase ran with other options |
| fill, overwrite | the block layer writes and the C0h host pages each count 90% of the flush and compaction bytes | the table files did not reach the device |
| overwrite | compaction wrote bytes | the LSM tree did not compact, so `lsm_wa` shows flushes only |
| mixed | 5% to 15% of the operations wrote a key | the phase ran with other options |
| mixed | the block layer reads 1 KiB or more for each key read | the reads stay in memory, or the database is not on the namespace |
| mixed | the C0h plane read count grows | the reads do not reach the NAND model |

The write checks leave out the WAL bytes. RocksDB syncs each table file
that a flush or a compaction writes. A WAL file can go away before the
kernel writes it back.

The read check is loose, and it is an empirical check of this
workload, not a bound. The fill writes 400000 random keys with
replacement, so about a third of the keys are absent. A bloom filter can
answer an absent key with no read.

`ROCKSDB_CONTROL=db-off-device` shows that the device checks can fail.
The verdict must then be `FAIL`.

### Why five overwrite passes

Background GC starts when the free lines fall to the threshold. Before
GC, each host page goes to a new NAND page. So GC starts after a fixed
count of host bytes, whatever ext4 does with its blocks.

```
 device       lines  free at start  GC at    host bytes before GC starts
 section 1    192    191            19 free  (191 - 19) x 16 MiB = 2.89 GB
 low spare    128    127            12 free  (127 - 12) x 16 MiB = 1.93 GB
```

The first run gives the host bytes of each part. mkfs and the file
system wrote 0.06 GB, the fill 0.75 GB, one overwrite pass 0.87 GB and
the mixed phase 0.03 GB. Thus N passes write about 0.84 + 0.87 x N GB.

```
 passes  host bytes  section 1 device         low spare device
 1       1.71 GB     no GC (the first run)    no GC
 5       5.18 GB     GC from pass 2.4 on      GC from pass 1.3 on

 free lines, section 1 device
 191 |*.
     |   *.  1 pass
  90 |------x
     |          *.
  19 |==============*======== GC threshold ==========  GC keeps the free lines near 19
     +-------------+--------------------------------> host bytes
     0           2.89 GB                    5.18 GB (5 passes)
```

Five passes start GC on the section 1 device even with 40% fewer bytes
in each pass. These are predictions from one run, not measured values.

## 4. What to measure

```
 source                            value
 --------------------------------  ---------------------------------------
 ROCKSDB_BENCH= (guest script)     operations per second, user bytes, flush,
                                   compaction and WAL bytes, keys read
 ROCKSDB_LATENCY= (guest script)   P50, P99, P99.9, P99.99 in microseconds,
                                   for reads and writes of each phase
 ROCKSDB_COUNTERS= (guest script)  pages, WAF, plane reads, block bytes
 ROCKSDB_EFFECT= (guest script)    LSM, host and device write amplification
                                   over the three phases
 femu-stat.py (host)               stage times and the past-due share
 io_trace + femu-trace2fio.py      size mix, queues, depth, bursts
```

The values of `ROCKSDB_EFFECT=`:

```
 user_bytes    = rocksdb.bytes.written (write batch bytes)
 payload_bytes = keys written x (16 + value size)
 lsm_wa        = (flush bytes + compaction bytes) / user bytes
 host_wa       = C0h host pages x 4096 / user bytes
 device_waf    = (C0h NAND pages + GC pages) / C0h host pages
 end_to_end_wa = (C0h NAND pages + GC pages) x 4096 / user bytes
               = host_wa x device_waf
```

The host bytes also hold the WAL, the file system journal and the
metadata. So `host_wa` is above `lsm_wa`, and `end_to_end_wa` is not
`lsm_wa x device_waf`.

The latency of `db_bench` is the time of one operation in the guest. A
write latency is mostly memtable time, except when RocksDB stalls the
writes because compaction is behind. A read latency holds one or more
device reads. The trace gives the device latency of each command as
`t_cqe_ns - t_submit_ns` in nanoseconds. Before you compare latencies, read the
past-due share that `femu-stat.py` prints. A high share means that FEMU
did not keep up, so the latency is not the latency of the model.

For the mixed phase, the first draft of this page expected most reads
in the `4096` size line. One run contradicts it. Of 208109 reads in the
whole trace, 202599 were 4608 bytes long, so the report puts most reads
in the `8192` line. Writes from flush and compaction are large.

## 5. The contrast pair: spare capacity

The second device line has the same namespace on less NAND:

<!-- femu-example: recipe-rocksdb-lowop-boot -->
```bash
./qemu-system-x86_64 -name femu-recipe-rocksdb,debug-threads=on \
    -enable-kvm -cpu host -smp 4 -m 8G \
    -device virtio-scsi-pci,id=scsi0 -device scsi-hd,drive=hd0 \
    -drive file=$OSIMGF,if=none,cache=none,format=qcow2,id=hd0 \
    -net user,hostfwd=tcp::$SSH_PORT-:22 -net nic,model=virtio \
    -device femu,id=femu0,femu_mode=1,devsz_mb=1536,nchs=4,luns_per_ch=4,blks_per_pl=128,gc_thres_pcent=90,io_stages=on \
    -qmp unix:/tmp/femu-qmp.sock,server=on,wait=off \
    -nographic
```

```
 device        lines  namespace  spare lines   background GC   forced GC
 section 1     192    96 lines   96 (50%)      19 free lines   9 free lines
 low spare     128    96 lines   32 (25%)      12 free lines   6 free lines

 background GC = floor((1 - gc_thres_pcent / 100) x lines),       gc_thres_pcent = 90
 forced GC     = floor((1 - gc_thres_pcent_high / 100) x lines),  default 95
```

The guest cannot tell the two devices apart: the namespace, Identify and
the file system are the same. Run the guest script on each device, on a
fresh QEMU, and compare the two `ROCKSDB_EFFECT=` lines.

Both lines set `gc_thres_pcent=90`. With the default of 75, the
background threshold of the low spare device is its spare count. When
ext4 fills the namespace, background GC then does not stop, and the WAF
can go near 8
([parameter manual](../reference/parameter-manual.md#8-garbage-collection)).
That is a different effect. The recipe does not prove that ext4 fills
the namespace.

## 6. Expected behaviour

One run on 2026-11-21 used the device of section 1 only. The low spare
device has not run, so no run confirms a difference between the two.

| Prediction | Reason | Run of 2026-11-21 |
| --- | --- | --- |
| Hypothesis: `lsm_wa` is about the same on both devices. | The keys, the options and the file system size are the same. But the device speed can change which files a compaction picks, so measure the difference. | No run confirms it. Section 1 device: `lsm_wa` 1.922. |
| `device_waf` is higher on the low spare device, if ext4 writes most blocks of the namespace. | The file system has no `discard` option, so the FTL keeps the pages of deleted table files as valid until ext4 writes those blocks again. GC copies the valid pages of a victim, and with less spare capacity a victim holds more of them. | No run confirms it. Section 1 device: `device_waf` 1.000. |
| `end_to_end_wa` follows `device_waf`. | It is `host_wa x device_waf`, and `host_wa` changes less than `device_waf`. | No run confirms it. Section 1 device: `host_wa` 1.928, `end_to_end_wa` 1.928. |
| The write P99 and P99.9 of fill and overwrite are higher on the low spare device. | GC keeps the dies busy, compaction falls behind, and RocksDB stalls the writes. | No run confirms it. Section 1 device: P99 6.21 and 6.94 us, P99.9 14.29 and 14.36 us. |
| The read P99 of the mixed phase is higher on the low spare device. | A read waits when GC or a flush keeps its die busy. | No run confirms it. Section 1 device: P99 103.15 us. |
| GC runs on both devices. | Five overwrite passes write about 5.2 GB of host bytes, and GC starts after 2.89 GB (section 1 device) or 1.93 GB (low spare device). See section 3. | Contradicted with one overwrite pass on the section 1 device: 0 GC pages and 0 block erases. The phases wrote 1651412992 host bytes, and 90 of 192 lines were free at the end. No run has used five passes. |

The host bytes of the three phases were about 1.03 times the namespace of
1610612736 bytes. The section 1 device thus kept far more free lines
than its background GC threshold of 19. The low spare device has 32
spare lines, and its result is not known. The recipe now runs five
overwrite passes for this reason.

GC copies a page only when a victim line still holds valid data. A
line that holds only deleted table files gives an erase and no GC page.
The WAL, the journal and two background jobs mix data in each line, so
the prediction is that most victims hold some valid pages.

When both devices show the same `device_waf`, ext4 may have written only
a part of the namespace. Each device then has more spare capacity than
the table of section 5 shows. Compare the NAND bytes with the size of
the NAND, and read the free lines with `query-femu`.

## 7. Limits

- One run exists, on the device of section 1 only, with one overwrite
  pass. It contradicts the prediction that GC runs on that device. No
  run has used five passes. The other predictions of section 6 need
  the low spare device.
- One run is one sample. Background compaction makes the timing of a
  run vary, so compare more than one run of each device.
- The database is small, about 406 MB of data.
- The script mounts ext4 with no discard option. A real deployment can
  mount with `discard` or run `fstrim`, which lowers the device WAF.
- The latency of `db_bench` holds guest CPU time. Do not read it as a
  device latency.
- The recipe does not check the WAL bytes on the device, and the WAF
  on the `ROCKSDB_COUNTERS=` lines leaves out pad pages and translation
  pages.

## Related pages

- [Workload recipes](README.md): the common steps and the result rules.
- [Tutorial 02: GC and WAF](../tutorials/02-gc-and-waf.md): how the GC
  thresholds set the WAF.
- [Timing model](../concepts/timing-model.md): when a completion time is
  valid.
