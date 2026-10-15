# KV value packing

A key-value namespace packs small values into shared NAND pages, as real
KV-SSDs do. PinK (Im et al., USENIX ATC '20) appends values to a value
log. The Samsung KV-SSD firmware, KAML and iLSM also put several small
values in one page. Packing is on by default (`kv_pack=on`).

Without packing, a 100 byte value programs a whole 4 KiB page. That model
wastes 97% of the page, so small-value WAF, GC load and capacity are far
from a device. `kv_pack=off` keeps that model for old results.

## Requirements

- A KV namespace: `femu_mode=5`, or `kvssd` in `namespace_modes`
  ([KV mode](../modes/kvssd.md)).
- Both key indexes: the hash (default) and `kv_index=lsm`
  ([LSM-tree key index](kv-lsm-index.md)).
- Nothing in the guest. The host sees packing only in the time of each
  command and in the counters.

## Launch

Packing needs no property:

<!-- femu-example: kv-pack -->
```
-device femu,femu_mode=5,devsz_mb=64
```

With a volatile write cache, so that Flush programs the open page:

<!-- femu-example: kv-pack-vwc -->
```
-device femu,femu_mode=5,devsz_mb=64,vwc=1
```

The old model, one value or more per page:

<!-- femu-example: kv-pack-off -->
```
-device femu,femu_mode=5,devsz_mb=64,kv_pack=off
```

## The model

```text
 Store (value + 32 byte header fits a page)
   |
   v
 open page in controller DRAM (one per namespace)
 +----------------------------------------------+
 | hdr v1 | hdr v2 | hdr v3 |   free             |
 +----------------------------------------------+
   |  the next record does not fit
   |  (dead records are dropped first)
   v
 program the page (padded) --> packed page on NAND
                                 page header: the owner of each value
```

- A value packs when its record fits a page. A record is the value and
  a 32 byte header: the key, the length, a version and the offset. A
  value log record holds the key, so that GC can find the index entry.
- A value never crosses a page. Thus a Retrieve reads one page.
- A larger value takes whole pages, as before. A zero-length value
  takes no page.
- The index entry holds the page and the offset of a packed value.
- With the hash index, an overwrite or a Delete makes the old record
  dead at once. With `kv_index=lsm`, a new record that replaces one in
  the memtable kills the old record at once. An old record in a level
  stays live until a merge drops it or value GC finds it stale (as for
  whole pages). A page stays valid until its last record dies.
- Dead records in the open page are dropped before every program, as a
  write buffer drops a replaced page. The old and the new record must fit
  the page together: `2 * (length + 32) <= page size`, so up to 2016
  bytes with 4 KiB pages. Then 200 overwrites of one key program nothing.
  This needs the open page to stay in DRAM (not `vwc=1` with WCE
  cleared), no Flush and no other key. With the LSM tree, the key must
  also stay in its memtable.
- The Store whose record fills the page with live records programs it
  after the record it replaced is released.

## Durability

KV Store has no FUA bit (KV 1.3, Figure 30). The Base spec rules for the
volatile write cache apply:

| Configuration | The open page | Store time |
| --- | --- | --- |
| `vwc=0` (default) | stays in DRAM; the cache is non-volatile (Base 2.3, 5.2.26.1.4 note) | the DRAM time |
| `vwc=1`, WCE set | stays in DRAM until Flush or shutdown | the DRAM time |
| `vwc=1`, WCE cleared | programmed with each Store, padded (Base 2.3, 5.2.26.1.4) | the program time |

| Event | Action |
| --- | --- |
| Flush, `vwc=1`, WCE set | programs the open page; waits for every earlier program of packed values (Base 2.3, 7.2) |
| Flush otherwise | no effect, as the spec asks |
| Set Features 06h clears WCE | programs the open page of every KV namespace first |
| CC.SHN | programs the open page of every KV namespace |
| the next record does not fit, or the page is full of live records | programs the open page; the Store that needs the room, or fills the page, waits for it |

The DRAM time is `pg_rd_lat / 16`, the time a bbssd write buffer charges.
The program at Set Features and at shutdown loads the LUNs; the admin
command and the shutdown status do not wait for it. FEMU models no power
loss for KV, so the index in device DRAM needs no journal.

## What each command costs

| Command | Packed value |
| --- | --- |
| Store, record in the open page | the DRAM time, and the index cost |
| Store whose record does not fit, or fills the page | the program of the full page |
| Retrieve, value in the open page | the DRAM time, and the index cost |
| Retrieve, value on NAND | one page read (the whole page, as the media model reads whole pages) |
| Flush | the open page program, and the earlier programs |

The index cost is the hash base read, or the LSM lookup. With
`kv_timing=model`, Store and Retrieve take the model time; packing then
changes only the NAND load, the space and the counters.

## Garbage collection

```text
 victim = closed line with the fewest live bytes
          (each closed line once per GC run)
   |
   v
 packed page: read it once
   each live record --> GC page (programmed when full, and before the erase)
   lsm: a stale version --> released, no move
 whole page or meta page --> moved as before
   |
   v
 erase the victim
```

- Live bytes count a record of each live packed value, and a full page
  for a whole value or a meta page.
- A full line can hold dead records. Thus full lines are victims too.
- The GC page is programmed before the victim is erased. A moved value
  is never only in DRAM.

## Counters

| Counter | With packing |
| --- | --- |
| C0h pages programmed (offset 24) | each packed page and each whole value page |
| C0h host pages (offset 8) | the value bytes of the Stores, in whole pages |
| C0h GC pages (offset 16) | each GC page and each moved whole page |
| C0h WAF | programmed pages over host pages |

The host page count rounds down. Thus the WAF is exact only after many
pages.

## Properties

| Property | Type | Default | Meaning |
| --- | --- | --- | --- |
| `kv_pack` | bool | on | on: values whose record fits a page share pages; off: each value takes whole pages |

`kv_pack=off` with no KV namespace is refused:
`kv_pack=off needs a key-value namespace (femu_mode=5 or kvssd in namespace_modes)`.

## Limits

- One open page per namespace. A device can hold more pages in DRAM;
  that changes only when programs happen.
- The Store that forces a program waits for it, as a bbssd write waits
  for the destage it forces.
- A Store needs one free page more while the open page holds a live
  value, so that a Flush always finds its page.

## Validation

The qtests `kv-pack-pages`, `kv-pack-off`, `kv-pack-overwrite`,
`kv-pack-overwrite-off`, `kv-pack-flush`, `kv-pack-flush-wait`,
`kv-pack-read-time`, `kv-pack-gc` and `kv-pack-gc-lsm` cover packing.
`FEMU_KV_CHECK` checks each page header, each owner and the live bytes
of each line.

## Related pages

- [KV mode](../modes/kvssd.md)
- [KV design](../design/kvssd.md#value-packing)
- [LSM-tree key index](kv-lsm-index.md)
- [Log pages and counters](../reference/log-pages-and-counters.md#vendor-log-page-c0h)
