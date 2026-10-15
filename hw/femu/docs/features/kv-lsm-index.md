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
- A host that enables the controller with CC.CSS 110b, as Linux does. KV
  I/O fails with Invalid Command Opcode under 000b.
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
          device DRAM                             flash: meta lines
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
                                flash: value lines (values in log order)
```

- A record holds a key and a value pointer. A meta page holds
  `page size / 32` records (128 for 4 KiB pages).
- Meta pages are real NAND pages, on their own write pointer. Their lines
  hold no value, as PinK keeps meta segments apart from data segments.
- A merge programs new pages and releases the pages it replaces. Value GC
  also collects meta lines.
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
            latency = meta reads + value read
```

| Command | Index cost |
| --- | --- |
| Retrieve, Exist | a lookup: one meta page read per unpinned level whose key range holds the key, one after the other, until a record is found |
| Store | none (a blind insert into the memtable); with the SIKE or SINKE option, a lookup |
| Delete | none (a blind tombstone, also for an absent key); with EDNEK set, a lookup, and no tombstone for an absent key |
| List | each meta page its walk enters; the pages of one level one after the other, the levels side by side |
| a flushing Store or Delete | the flush and merges, in the background (below) |

A command pays only the flash that the tree reads or programs. It pays no
base read: that read is the cost model of the hash index, which keeps it.
Thus an Exist that the memtable answers takes no NAND time. A blind Delete
takes none either, unless it runs value GC.

### Merges run in the background

```
 Store k (memtable full)  |--value program--|                 latency of Store k
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

### Old values stay on flash until the tree drops them

A blind Store or Delete does not look the key up, so the device does not
know the old value yet. Its pages stay valid on flash. They become
garbage when the tree drops the old record:

```
 Store k (blind)     new record (k, v2) in the memtable
                     v1 pages: still VALID on flash
 merge over k        drops (k, v1): v1 pages INVALID
 value GC finds v1   newest record of k is v2: v1 page INVALID now
```

- An overwrite of a key that the memtable holds replaces the record
  there, so the old pages go at once.
- NUSE drops at the Delete or the overwrite, as the KV specification
  defines it. Only the flash keeps the old pages.
- `valid-value-pages` in `query-femu` counts the pages that are still
  valid, with these old ones.

### Value garbage collection

Value GC starts in a Store or a Delete when the free lines fall to the GC
threshold that `gc_thres_pcent` sets. As PinK does (section 4.5 of the
paper), it collects one victim line at a time:

1. The victim is the line with the fewest valid pages. With no invalid
   page anywhere, a Store with no room takes the full value lines.
2. For each value on the victim, look its key up. This reads the meta
   pages of the unpinned levels, once each, level by level.
3. A value that the newest record names moves to a new page, after its
   read. A stale value is released, with no move.
4. A moved key with its record in an unpinned level goes back into the
   memtable. Its merges wait for the moves.
5. The victim is erased.

A meta line moves its valid meta pages, and the level list follows them.
The Store that runs the collection waits for it. GC ends when the free
lines are above the threshold and the Store has room. A victim that gives
no free page also ends it, unless a Store still needs room. Then GC tries
more queued victims, at most as many as the queue held at the start, and
each full line once.

A Store can still have no room while Deletes or old records sit in the
levels. The device then merges every run into the deepest level at once. The
tombstones and the records they hide drop there. GC then collects the
meta pages that this frees.

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
([query-femu](../reference/query-femu.md#kv-lsm-index)). It has the
memtable, each level, and counters of each kind of meta page I/O.
`femu-stat.py` prints them with their change over each interval.

A merge program counts as a page programmed (`nand_write_pages`), not as
a page the host asked for. In `gc_write_pages`, GC counts each meta page
or value it moves as a page relocated. Thus the write amplification of
the health log and of log page C0h includes the index.

## Limits

- Meta pages take NAND pages, but no value space: NUSE counts keys and
  values only. A Store leaves free a reserve: two lines, and the pages of
  a merge that rewrites every record. A Store that would use the reserve
  gets Capacity Exceeded.
- A merge that finds too few free pages changes nothing. Every merge
  leaves one line free, for value GC. A Store whose flush fails gets
  Capacity Exceeded. A Delete keeps its tombstone in the memtable over its
  capacity, so it succeeds; the next put flushes again.
- There is no Bloom filter. PinK also has none.
- With `kv_timing=model`, the model time also hides the time of value GC,
  as it hides the other NAND time of a Store.

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
