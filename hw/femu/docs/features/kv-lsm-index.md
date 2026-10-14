# LSM-tree key index for KV namespaces

A key-value namespace keeps a device index from each key to the place of
its value. By default this index is an open-addressed hash in device
DRAM. With `kv_index=lsm`, the index is an LSM tree instead. The model
follows PinK: Im et al., "PinK: High-speed In-storage Key-value Store with
Bounded Tails", USENIX ATC '20. The tree changes what a command costs:
lookups read meta pages from flash, and merges read and program them.

Use it to study how the index of a KV-SSD shapes latency. It shows the
tail latency of flash lookups, the write interference of merges, and the
effect of the DRAM that pins the top levels.

## Requirements

- A KV namespace: `femu_mode=5`, or `kvssd` in `namespace_modes`
  ([KV mode](../modes/kvssd.md)).
- Nothing in the guest beyond what KV mode needs. The index is not
  visible to the host, except through the time of each command and the
  order of List.

## Launch

<!-- femu-example: kv-lsm-index -->
```
-device femu,femu_mode=5,devsz_mb=64,kv_index=lsm
```

Small knobs make the tree deep with few keys, which suits a short test:

<!-- femu-example: kv-lsm-index-small -->
```
-device femu,femu_mode=5,devsz_mb=64,kv_index=lsm,kv_lsm_memtable_keys=16,kv_lsm_size_ratio=2,kv_lsm_pinned_levels=0
```

`run-kvssd.sh` takes the index from the environment: `KV_INDEX=lsm`, and
`KV_LSM_OPTS` for the knobs. The guest recipe `kv-bench-guest.sh` runs the
same against both indexes.

## Properties

| Property | Default | Range | Meaning |
| --- | --- | --- | --- |
| `kv_index` | `hash` | `hash`, `lsm` | the key index of every KV namespace of the controller |
| `kv_lsm_memtable_keys` | 1024 | 16 to 65536 | records the DRAM memtable holds before it flushes |
| `kv_lsm_size_ratio` | 10 | 2 to 64 | level `i` holds `memtable_keys * ratio^i` records |
| `kv_lsm_pinned_levels` | 1 | 0 to 24 | top levels held whole in DRAM, with no flash I/O |

The default memtable size is the 1024 keys of PinK. Each KV namespace has
its own tree.

## The model

```
          device DRAM                             flash (meta pages)
 +--------------------+
 | memtable (sorted)  |  Store, Delete (tombstone), GC reinsert
 +---------+----------+
           | full: flush
 +---------v----------+
 | L1 (pinned)        |  no flash I/O
 +---------+----------+
           | over its capacity: merge the whole level down
 +---------v----------+        +---------------------------+
 | L2 level list      |------->| L2 meta pages, sorted     |
 | (first key, addr)  |        +-------------+-------------+
 +--------------------+                      | merge
 | L3 level list      |------->| L3 meta pages             |
 +--------------------+        +---------------------------+
```

- A record holds a key and a value pointer. A meta page holds
  `page size / 32` records (128 for 4 KiB pages).
- A level list in DRAM holds the first key of each meta page. Thus a
  lookup reads at most one meta page in each unpinned level.
- A merge takes the whole upper level. It reads and rewrites only the
  pages of the lower level that its key range overlaps.
- An overwrite adds a new record; a Delete adds a tombstone. Merges drop
  the older records. A tombstone drops in the deepest level.
- The value space and the values are the same as with the hash index.

## What each command costs

```
 Retrieve:  t0 |-- L2 meta read --|-- L3 meta read --|-- value read --|
                base read (one page on a hashed LUN) from t0, beside them
            latency = MAX(base, meta reads + value read)
```

| Command | Index cost |
| --- | --- |
| Retrieve, Exist | a lookup: one meta page read per unpinned level whose key range holds the key, one after the other, until a record is found |
| Store | none (a blind insert into the memtable); with the SIKE or SINKE option, a lookup |
| Delete | none (a blind tombstone, also for an absent key); with EDNEK set, a lookup, and no tombstone for an absent key |
| List | each meta page its walk enters; the pages of one level one after the other, the levels side by side |
| a flushing Store or Delete | the flush and merges, in the background (below) |

Every KV command keeps the base read of the hash index. The meta page
reads come on top of it, so the default `kv_index=hash` times are
unchanged.

### Merges run in the background

```
 Store k (memtable full)  |--value program--|--base--|         latency of Store k
 merges, queued:                      reads |-r-|-r-|  programs |-p-|-p-|
 next command on a busy LUN                             ...waits...|----|
```

- A merge reads its input pages, then programs its output pages.
- The next merge of a cascade starts when the one before has programmed.
- A flush comes before a new key goes into a full memtable. With 16
  memtable keys, the 17th distinct key flushes. An update of a key in the
  memtable does not flush.
- The I/O starts at the arrival time of the command that flushes. It is
  not in that command's latency.
- Later commands on the same LUNs wait behind it. A device that cannot
  merge as fast as the host writes shows this in every command.

### Value garbage collection

KV value collection (`kv_compact()`) moves every live value when the value
space is full. With the LSM tree it works as PinK does (section 4.5 of
the paper):

1. For each key whose newest record is in an unpinned level, read its
   meta page once, to check the value.
2. Move the values, after those reads.
3. Put those keys back into the memtable, since their meta pages hold the
   old pointer. Their merges wait for the moves.

The command that triggers the collection pays steps 1 and 2, as it pays
the moves with the hash index.

## List order

List returns the keys in byte order, from the first key at or after the
start key, then from the smallest key (the wrap). Each live key comes back
once. A live start key comes first. A merge keeps the order, so a host
that walks the namespace page by page sees each key once. The hash index
returns the same keys in table order.

## With kv_timing=model

`kv_timing=model` replaces the time of a Store and of a Retrieve that
finds its key ([workload-mix timing](../modes/kvssd.md#workload-mix-timing-kv_timingmodel)).
The tree still runs: its reads, programs and counters are the same. Its
I/O loads the LUN timelines, so an Exist, a Delete or a List, which keep
the NAND time, can wait behind it. The model time does not change.

## Counters

The `lsm` member of the namespace in `query-femu` shows the tree
([query-femu](../reference/query-femu.md)). It has the
memtable, each level, and counters of each kind of meta page I/O.
`femu-stat.py` prints them with their change over each interval.

The meta page I/O is not in the host, NAND or GC write counters of the
health log or log page C0h. Thus the write amplification there is the
ratio of value pages, as for the cached mapping table of BlackBox.

## Limits

- Meta pages take channel and LUN time on placeholder addresses. They take
  no value space, no line and no erase.
- A Store or Delete that the tree answers blind frees the old value pages
  at once. A real device finds them only at a merge.
- There is no Bloom filter. PinK also has none.
- With the ECC properties on, a meta page read takes the read time of the
  placeholder block, as the hash base read does.

| Message | Cause and fix |
| --- | --- |
| `kv_index=X is not hash or lsm` | Use `hash` or `lsm`. |
| `kv_lsm_memtable_keys, kv_lsm_size_ratio and kv_lsm_pinned_levels need kv_index=lsm` | A knob other than its default with the hash index. |
| `kv_lsm_memtable_keys=N is not 16 to 65536` (and the other ranges) | Use a value in the range of the table above. |
| `kv_index=lsm and the kv_lsm_* knobs need a key-value namespace ...` | The device has no KV namespace. |
| `FEMU kvssd: kv_index=lsm needs a page of at least 32 bytes` | Use a larger `secsz` or `secs_per_pg`. |

## Verify

1. `query-femu` on the namespace has an `lsm` member.
2. After a load, its `levels` list grows and `flushes` counts up.
3. `kv-bench` passes in the guest, as with the hash index.

## Related pages

- [KV mode](../modes/kvssd.md)
- [KV design: the key index](../design/kvssd.md#key-index)
- [query-femu](../reference/query-femu.md)
