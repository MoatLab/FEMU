# QMP query-stats (provider femu)

QEMU has two generic QMP commands for statistics: `query-stats` and
`query-stats-schemas`. FEMU adds the provider `femu` and the target
`femu` to them. A tool that already reads KVM statistics can then read
the FEMU counters with the same code.

Use this page to read the counters of every `femu` device in one call.
Use [`query-femu`](query-femu.md) for the full state of one namespace,
for example the zones or the reclaim units.

```
 QMP client             main loop (BQL)                device threads
 ----------             ---------------                --------------
 query-stats ------->  for each femu device:
  target femu            controller: sum poller   <--- pollers store each
                           counters                    counter atomically
                         stages: copy each set    <--- pollers update under
                           (give up after 1 ms)        a sequence count
                         each FTL: read the copy  <--- FTL thread copies its
                           (give up after 1 ms)        counters between two
                                                       requests
 reply  <-------------  one result per controller and per namespace
```

The command never waits for the FTL thread or a poller. It needs no
enabled controller: realize publishes the empty FTL.

## Start a device with a QMP socket

<!-- femu-example: query-stats-qmp -->
```
-device femu,id=femu0,devsz_mb=1024,femu_mode=1,io_stages=on -qmp unix:/tmp/femu-qmp.sock,server=on,wait=off
```

## Request

```
{ "execute": "query-stats",
  "arguments": { "target": "femu",
                 "providers": [ { "provider": "femu" } ] } }

{ "execute": "query-stats-schemas",
  "arguments": { "provider": "femu" } }
```

| Argument | Effect |
| --- | --- |
| `target` | Must be `femu`. The targets `vm`, `vcpu` and `cryptodev` return no FEMU result. |
| `providers[].names` | Keep only these stats. The filter applies to every stat, `nsid` too. |

A result whose stats the filter removes is left out. A client that
filters and needs to know the namespace must also ask for `nsid`:

```
{ "execute": "query-stats",
  "arguments": { "target": "femu",
                 "providers": [ { "provider": "femu",
                                  "names": [ "nsid", "waf" ] } ] } }
```

## Results

Each device gives one result for its controller, then one for each
attached BlackBox (`bbssd`) namespace, in NSID order. Every result has
the QOM path of the device in `qom-path`. The stat `nsid` tells the
results apart: 0 is the controller.

```
 qom-path /machine/peripheral/femu0
   nsid 0   host commands and bytes, I/O stage times
   nsid 1   FTL counters of namespace 1
   nsid 2   FTL counters of namespace 2 (or ftl-nsid 1 with shared_ftl=on)
```

A BlackBox namespace with FDP gives its page counters and WAF, without
the line counts. Its reclaim unit counts are only in `query-femu`.
Namespaces in other modes (ZNS, CSD, KV, OCSSD, NoSSD) give no namespace
result in this release. Use `query-femu` for them.

### Controller (nsid 0)

| Stat | Type | Unit | Meaning |
| --- | --- | --- | --- |
| `nsid` | instant | | 0 |
| `host-read-commands` | cumulative | | Read commands the pollers counted, as for SMART |
| `host-write-commands` | cumulative | | Write and Zone Append commands the pollers counted, as for SMART |
| `host-read-bytes` | cumulative | bytes | Bytes those reads moved |
| `host-write-bytes` | cumulative | bytes | Bytes those writes moved |
| `STAGE-commands` | cumulative | | Commands timed in the stage |
| `STAGE-time` | log2-histogram | seconds, 10^-9 | 40 buckets of the stage time |
| `STAGE-time-sum` | cumulative | seconds, 10^-9 | Sum of the stage times |
| `STAGE-time-max` | peak | seconds, 10^-9 | Longest stage time |
| `returned-after-due` | cumulative | | Commands that completed after their due time |

STAGE is `submit`, `ftl`, `hold`, `post-delay`, `total` or `past-due`,
as in [`query-femu-stages`](query-femu.md#io-stage-times-query-femu-stages).
The stage stats need `io_stages=on`. Bucket i of a histogram holds the
times from 2^i to 2^(i+1)-1 ns. Bucket 0 also holds 0, and bucket 39
holds every longer time.

The command counts start when the guest first enables the controller.
Before that, they are 0.

### BlackBox namespace (nsid 1 and up)

| Stat | Type | Unit | Present when |
| --- | --- | --- | --- |
| `nsid` | instant | | always |
| `generation` | instant | | always: changes when the namespace is created again |
| `page-size` | instant | bytes | always |
| `ftl-nsid` | instant | | the namespace shares the FTL of the namespace named here |
| `host-write-pages` | cumulative | | the namespace reports its FTL |
| `nand-write-pages` | cumulative | | the namespace reports its FTL |
| `gc-write-pages` | cumulative | | the namespace reports its FTL |
| `block-erases` | cumulative | | the namespace reports its FTL |
| `pad-write-pages` | cumulative | | the FTL programmed pad pages |
| `map-write-pages`, `map-read-pages` | cumulative | | translation pages are on |
| `parity-write-pages`, `degraded-reads` | cumulative | | die or RAIN parity is on |
| `lost-pages`, `lost-blocks` | cumulative | | RAIN parity is on |
| `idle-reclaims`, `idle-refreshes` | cumulative | | idle maintenance is on |
| `waf` | instant | 10^-3 | `host-write-pages` is not 0 |
| `free-lines`, `victim-lines`, `full-lines`, `retired-lines`, `spare-lines`, `total-lines` | instant | | the namespace reports its FTL, without FDP |
| `ns-host-write-pages`, `ns-nand-write-pages`, `ns-gc-write-pages` | cumulative | | the FTL counts per namespace |
| `ns-waf` | instant | 10^-3 | `ns-host-write-pages` is not 0 |

The rules follow the `query-femu` reply. Each value equals the
`query-femu` value of the same name, taken at the same point.

`waf` is 1000 times the `query-femu` WAF, rounded down:

```
 waf = 1000 * (nand + gc + map + pad + parity write pages) / host write pages
```

A value that does not fit in 64 bits reads as 2^64 - 1.

### A shared FTL

With `shared_ftl=on`, several namespaces use one FTL. The first
namespace of that FTL reports the FTL counters and the line counts. The
other namespaces report `ftl-nsid` with the NSID of the first one, and
their own `ns-*` counters. A sum over the namespaces then counts each
FTL once.

## Types and units

`query-stats-schemas` returns one schema, for provider `femu` and
target `femu`, with the stats in the order of every result. HMP walks the
schema in this order.

| Type | Meaning for a client |
| --- | --- |
| cumulative | Goes up only, while `generation` stays the same |
| instant | A level now; it can go up and down |
| peak | The largest value so far |
| log2-histogram | A list of 40 cumulative bucket counts |

A stat with an `exponent` also has `base` 10. The value times
10^exponent gives the quantity in the unit. For example, `total-time-sum`
of 2500 is 2.5 microseconds.

`query-femu-stages reset=true` restarts the `query-femu-stages` values.
The query-stats stage values keep counting, so they stay cumulative.

When the host creates a namespace again (Namespace Management), its FTL
starts from 0, and `generation` changes. A client that sees a new
`generation` must start its rates again.

## Consistency and cost

```
 FTL thread                                main loop
 ----------                                ---------
 request ... request                       query-stats
   | no request waiting                      |
   v                                         v
 publish: seq odd, copy, seq even  ----->  read copy; seq moved? read again
 (busy: at most once per 1 ms)              still moving after 1 ms? leave the
                                            namespace out of this reply
```

- The FTL counters of a namespace come from one copy. The FTL thread
  makes it between two requests, so the values of one result agree.
- While the FTL runs requests without a break, it publishes about once
  a millisecond. It checks the clock every 32 busy passes, so a long
  request or a descheduled thread makes the copy older. After the last
  request, and after each resume of the controller, the next pass
  publishes at once.
- The command and byte counts of the controller and the stage times come
  from the pollers, at the time of the call. They can be a little ahead
  of the FTL copy.
- A poller can stop inside its stage update. After 1 ms, the reply then
  has no stage stats for that controller. The other stats stay.
- A namespace whose copy stays busy for 1 ms has no result in that reply.

The FTL thread pays one copy of about 20 words per FTL, at most once a
millisecond. A pass reads the clock only every 32 busy passes.

## HMP

`info stats femu * femu` prints each result under the QOM path of its
device. HMP numbers the histogram buckets from 1.

```
/machine/peripheral/femu0
    nsid (instant): 0
    host-write-bytes (cumulative, B): 1048576
    total-time (log2-histogram, ns): [1]=0 [2]=0 ... [40]=0
/machine/peripheral/femu0
    nsid (instant): 1
    waf (instant, * 10^-3): 1333
    free-lines (instant): 12
```

## Prometheus

`femu-prom.py --source query-stats` reads this command instead of
`query-femu`. See [scripts](scripts.md). It reads every device in one
call and does not wait for the FTL thread. It reports the same series:
the page counters, WAF from the raw page counts, and the line counts.
It also reports `femu_namespace_generation`.

- A namespace with `ftl-nsid` gets the series of the FTL it shares.
  `query-femu` does the same. A sum over its namespaces counts that FTL more than
  once.
- A namespace that a reply leaves out has no series in that scrape.
  `femu_scrape_errors` does not count it.

## Related pages

- [QMP query-femu](query-femu.md)
- [Measuring FEMU](../guides/measuring.md)
- [Scripts and tools](scripts.md)
