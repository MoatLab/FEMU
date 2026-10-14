# QMP query-femu

`query-femu` is a QMP command that reports the FTL state of a FEMU NVMe
controller to the host. It needs no guest tools. The schema is in
`qapi/femu.json`, and `query-qmp-schema` also returns it.

This release supports BlackBox (`bbssd`) namespaces, also with flexible
data placement (FDP), and zoned (`znssd`) namespaces. For a `csd`,
`kvssd` or `ocssd` namespace the reply has the NAND bus timing only. A
selected `nossd` namespace, or one backed by a `femu-cxl-ssd` medium,
returns an error that names the mode.
A controller in an unsupported mode returns that error even when the
guest has not enabled it.

```
 QMP client                main loop                    device threads
 ----------                ---------                    --------------
 query-femu --------> check args, size buffers
                           |
                           |-- znssd: try the zone lock ----- pollers hold it
                           |   busy? sleep, try again         for zone changes
                           |   copy zones, unlock
                           |
                           |-- bbssd: post request ---------> FTL thread copies
                           |   sleep until done <------------ between 2 requests
                           |
 reply  <------------ build one entry per namespace
```

## Start a device with a QMP socket

<!-- femu-example: query-femu-qmp -->
```
-device femu,id=femu0,devsz_mb=1024,femu_mode=1 -qmp unix:/tmp/femu-qmp.sock,server=on,wait=off
```

For a `bbssd` namespace, the guest must enable the controller before a
query works. The NVMe driver does this when it binds to the device. A
`znssd` namespace needs no enabled controller.

## Arguments

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `path` | string | the only `femu` device | QOM path of the device, for example `/machine/peripheral/femu0` |
| `nsid` | integer | every attached namespace | the namespace to report |
| `kind` | `summary`, `lines`, `zones` or `reclaim-units` | `summary` | `lines` adds one record per line of a `bbssd` namespace; `zones` adds one record per zone of a `znssd` namespace; `reclaim-units` adds one record per reclaim unit of an FDP namespace |
| `offset` | integer | 0 | with a listing kind, the first record to report |
| `limit` | integer | 256 | with a listing kind, the most records to report, 1 to 4096 |

`offset` and `limit` with `kind` `summary` are an error. With a listing
kind, give `nsid` if the controller has more than one namespace. Each
listing kind fits one namespace type:

```
 kind            bbssd   bbssd + FDP   znssd   csd, kvssd, ocssd
 summary         yes     yes           yes     yes (media only)
 lines           yes     error         error   error
 reclaim-units   error   yes           error   error
 zones           error   error         yes     error
```

## Reply

The reply has the device `path`, the controller `mode` and one entry in
`namespaces` for each selected namespace. Each entry has `nsid` and
`mode` (`ocssd`, `bbssd`, `nossd`, `znssd`, `csd` or `kvssd`). The `mode`
selects the other members of the entry.

### BlackBox namespaces

A `bbssd` entry has these members:

| Member | Content |
| --- | --- |
| `geometry` | `channels`, `luns-per-channel`, `planes-per-lun`, `blocks-per-plane`, `pages-per-block`, `page-size` (bytes) and `pages-per-line` |
| `counters` | `host-write-pages`, `nand-write-pages`, `gc-write-pages`, `block-erases`, `pad-write-pages` (only after a pad), and `waf` |
| `media` | the NAND bus timing: see [Media timing](#media-timing) |
| `line-counts` | lines that are `free`, `victim`, `full`, `retired` and `spare`, and the `total`; absent with FDP |
| `fdp` | with FDP only: see [FDP namespaces](#fdp-namespaces) |
| `lines` | with `kind` `lines`: `id`, `state`, `vpc`, `ipc`, `erase-min` and `erase-max` of each line |
| `offset`, `next-offset` | with `kind` `lines` or `reclaim-units`: the first record in the listing, and the offset of the next call; `next-offset` is absent after the last record |

The page counters are the counters of [log page C0h](log-pages-and-counters.md#vendor-log-page-c0h)
for one namespace. C0h adds them over the namespaces of the controller.
`waf` is (`nand-write-pages` + `gc-write-pages` + `pad-write-pages`) /
`host-write-pages` as a
real number, and it is absent until the host writes a page. C0h reports the
same value multiplied by 1000 as an integer.

`block-erases` is the sum of the erase counts of all blocks. C0h does not
report it. A line contains the same block index in every plane of every
LUN, so `erase-min` and `erase-max` give the range of the erase counts in
the line.

The `state` of a line is one of these values:

| State | Meaning |
| --- | --- |
| `free` | on the free list, erased |
| `open` | a write pointer programs it |
| `full` | closed, and all its pages are valid |
| `victim` | closed with invalid pages, a garbage collection candidate |
| `reclaiming` | garbage collection moves its valid pages |
| `unlisted` | on no list; a correct FTL does not report this state |
| `retired` | out of service: a block in it wore out (`blk_pe_limit`) |
| `spare` | held back so its blocks can replace worn-out ones (`spare_lines`) |

### FDP namespaces

With FDP, reclaim units hold the lines, so the entry has `fdp` in place of
`line-counts`. The `geometry` and `counters` members do not change. `fdp`
has these members:

| Member | Content |
| --- | --- |
| `reclaim-groups`, `units-per-group` | reclaim groups, and reclaim units in each group |
| `pages-per-unit` | NAND pages in each reclaim unit |
| `handles` | each reclaim unit handle: `id`, `type` (`initially-isolated` or `persistently-isolated`), `host-bytes` and `media-bytes` |
| `unit-counts` | reclaim units that are `free`, `open`, `full` and `victim`, and the `total` |
| `reclaim-units` | with `kind` `reclaim-units`: `group`, `unit`, `handle`, `state`, `vpc`, `ipc`, `erase-min` and `erase-max` of each unit, by group and then by unit |

`host-bytes` counts the NAND pages that the host wrote through the
handle, in bytes, so a 512-byte write on a 4 KiB page adds 4096.
`media-bytes` adds the data that garbage collection moved out of the
handle's units, and the pad pages that closed its units
(`pd_open_close_sec`). Both keep their values when a controller replaces another
on the same subsystem.
The FDP Statistics log (log page 22h) reports the sum of each counter over
the handles. Its fields are Host Bytes with Metadata Written (HBMW) and
Media Bytes with Metadata Written (MBMW). The counters stop at the largest 64-bit value.

```
 host write via handle h  --> host-bytes[h] += n   media-bytes[h] += n
 GC moves m bytes out of
 a unit that h wrote      -->                      media-bytes[h] += m
 p pad bytes close a unit
 that h owns              -->                      media-bytes[h] += p
 log page 22h: HBMW = sum(host-bytes)   MBMW = sum(media-bytes)
```

The `state` of a unit is `free`, `open`, `full`, `victim` or `unlisted`.
An `open` unit gets host data or collected data from a handle. A `victim`
unit has invalid or unwritten pages. A Reclaim Unit Handle Update makes a
`victim` of the open unit, also when it is not full. A correct
FTL does not report `unlisted`. `handle` is the handle that wrote the unit, and it
is absent for a free unit. Page counts are in NAND pages.

### Zoned namespaces

A `znssd` entry has these members. Addresses and sizes are in logical
blocks.

| Member | Content |
| --- | --- |
| `lba-size` | bytes per logical block |
| `zone-size`, `zone-capacity` | logical blocks per zone, and the writable part of a zone |
| `max-open`, `max-active` | the zone resource limits; 0 means no limit |
| `zone-counts` | zones that are `empty`, `implicitly-open`, `explicitly-open`, `closed`, `read-only`, `full` and `offline`, and the `total` |
| `media` | the NAND bus timing: see [Media timing](#media-timing) |
| `zones` | with `kind` `zones`: `index`, `type`, `state`, `start-lba`, `capacity`, `write-pointer` and `zrwa` of each zone |
| `offset`, `next-offset` | with `kind` `zones`: the first zone in `zones`, and the offset of the next call; `next-offset` is absent after the last zone |

The `state` and `write-pointer` of a zone are the values Report Zones
gives. `write-pointer` is absent where Report Zones has no valid write
pointer: in a `conventional` zone, and in a `full`, `read-only` or
`offline` zone. `type` is `sequential` or `conventional`. `zrwa` is true
when the zone holds a zone random write area.

### Media timing

Every namespace entry except `nossd` has a `media` member. A `csd`,
`kvssd` or `ocssd` entry has this member only. It gives the bus phases
the [NAND media layer](../design/nand-timing.md) charges, after its
fallbacks. Times are in ns.

```
 knobs (pg_xfer_lat, cmd_addr_lat, status_lat, tpl*bsy, onfi_mode, ...)
   |
   v
 media config --> fallbacks (a command phase of 0 takes cmd_addr_lat;
   |                          the bus off sets every bus phase to 0)
   v
 query-femu "media"  =  what each op is charged
```

| Member | Content |
| --- | --- |
| `staged-bus` | true when the channel bus phases are charged |
| `onfi-profile`, `onfi-mode` | true when `onfi_mode` 0 to 26 or `onfi_param_page` sets the bus phases; `onfi-mode` is present only then, and with a parameter page and `onfi_mode=-1` it is the highest mode the page lists |
| `column-cycles`, `row-cycles` | the address cycles of each command with the profile: 2 and 3, or the page's byte 101; 0 without the profile |
| `page-transfer-ns` | one page on the bus |
| `read-command-ns`, `program-command-ns`, `erase-command-ns` | the command and address phase of each op |
| `copyback-read-command-ns`, `copyback-program-command-ns` | the two command phases of a copyback |
| `status-ns` | one status read |
| `data-out-lead-ns`, `data-out-tail-ns` | the command and preamble before the page of a read, and the postamble and turnaround after it; with `sca`, the lead is the column select on the CA bus plus the tCCS wait, which holds no bus |
| `plane-select-ns` | the column select before each page of a multi-plane read |
| `data-in-edges-ns`, `program-confirm-ns` | the burst edges of the page of a program, and the confirm cycle after it |
| `plane-read-busy-ns`, `plane-program-busy-ns`, `plane-erase-busy-ns` | tPLRBSY, tPLPBSY and tPLEBSY between the planes of a multi-plane op; they apply with the bus on or off |
| `onfi-order` | a read reads its status before its data out, and a program or erase ends at its status |
| `page-register-hold` | an op sends its command only when its LUN is ready, and holds the LUN until its last bus phase ends |
| `status-per-plane` | a multi-plane program or erase reads one status per plane |
| `sca` | `onfi_sca` is on: the command, status and confirm members are times on the separate CA bus, and the channel bus carries only data bursts. The lead and plane select are the CA column select plus the tCCS wait, which holds no bus |
| `data-in-gap-ns`, `data-out-edges-ns` | with `sca`, the wait from a program command to its data burst (tCDL - SCE - tSCD - tWPRE2, as tCDL ends with the write preamble), and the burst time of a read without the page; 0 otherwise |

With `onfi_mode=26`, 4 KiB pages and two LUNs on a channel, `media` holds
the values of the [ONFI 6.0 profile table](../design/nand-timing.md#onfi-60-profile-bbssd-csd-kv):

```json
"media": {"staged-bus": true, "onfi-profile": true, "onfi-mode": 26,
          "column-cycles": 2, "row-cycles": 3, "page-transfer-ns": 855, "read-command-ns": 275,
          "program-command-ns": 562, "erase-command-ns": 225,
          "copyback-read-command-ns": 275, "copyback-program-command-ns": 275,
          "status-ns": 321, "data-out-lead-ns": 200, "data-out-tail-ns": 115,
          "plane-select-ns": 200, "data-in-edges-ns": 57,
          "program-confirm-ns": 125, "plane-read-busy-ns": 500,
          "plane-program-busy-ns": 500, "plane-erase-busy-ns": 500,
          "data-in-gap-ns": 0, "data-out-edges-ns": 0, "sca": false,
          "onfi-order": true, "page-register-hold": true,
          "status-per-plane": true}
```

With `onfi_sca=1` on the same device, the CA bus lengths replace the
command members: `read-command-ns` 184, `program-command-ns` 84,
`status-ns` 277, `data-out-lead-ns` 84 and `data-out-tail-ns` 0. Then
`data-in-gap-ns` is 313 and `data-out-edges-ns` is 168.

A default `bbssd` device has no bus phases: `staged-bus` and every rule
are false, and every time is 0. With `cmd_addr_lat=1000`, the five
command phases and `plane-select-ns` report 1000, because they fall back
to it. OCSSD 1.2 keeps a page time also with `oc12_channel_timing` off,
but the bus is off, so `page-transfer-ns` reports 0.

The command reads `media` when it starts, under the BQL. Realize sets
the values. Later only admin commands change them (delay emulation,
OCSSD timing), and these also run under the BQL. Thus a namespace that
reports only `media` needs no enabled controller.

With `kv_timing=model`, a KV namespace still charges its NAND ops, so
`media` is correct for the media timelines. The time a Store or Retrieve
command takes comes from the model instead.

## Example

```json
{"execute": "query-femu", "arguments": {"path": "/machine/peripheral/femu0", "kind": "lines", "limit": 2}}
```

```json
{"return": {"path": "/machine/peripheral/femu0", "mode": "bbssd", "namespaces": [{
  "nsid": 1, "mode": "bbssd",
  "geometry": {"channels": 8, "luns-per-channel": 8, "planes-per-lun": 1,
               "blocks-per-plane": 256, "pages-per-block": 256,
               "page-size": 4096, "pages-per-line": 16384},
  "counters": {"host-write-pages": 20480, "nand-write-pages": 20480,
               "gc-write-pages": 0, "block-erases": 0, "waf": 1.0},
  "media": {"staged-bus": false, "onfi-profile": false, "column-cycles": 0,
            "row-cycles": 0, "page-transfer-ns": 0,
            "read-command-ns": 0, "program-command-ns": 0, "erase-command-ns": 0,
            "copyback-read-command-ns": 0, "copyback-program-command-ns": 0,
            "status-ns": 0, "data-out-lead-ns": 0, "data-out-tail-ns": 0,
            "plane-select-ns": 0, "data-in-edges-ns": 0, "program-confirm-ns": 0,
            "plane-read-busy-ns": 0, "plane-program-busy-ns": 0,
            "plane-erase-busy-ns": 0, "data-in-gap-ns": 0,
            "data-out-edges-ns": 0, "sca": false, "onfi-order": false,
            "page-register-hold": false, "status-per-plane": false},
  "line-counts": {"free": 254, "victim": 0, "full": 1, "retired": 0, "spare": 0,
                  "total": 256},
  "lines": [{"id": 0, "state": "full", "vpc": 16384, "ipc": 0, "erase-min": 0, "erase-max": 0},
            {"id": 1, "state": "open", "vpc": 4096, "ipc": 0, "erase-min": 0, "erase-max": 0}],
  "offset": 0, "next-offset": 2}]}}
```

To read all lines, call again with `offset` set to `next-offset` until the
reply has no `next-offset`.

An FDP namespace with four handles, just after the guest enabled it.
Each handle has one unit open:

```json
{"execute": "query-femu", "arguments": {"kind": "reclaim-units", "limit": 1}}
```

```json
{"return": {"path": "/machine/peripheral/femu0", "mode": "bbssd", "namespaces": [{
  "nsid": 1, "mode": "bbssd",
  "geometry": {"channels": 2, "luns-per-channel": 2, "planes-per-lun": 1,
               "blocks-per-plane": 25, "pages-per-block": 4,
               "page-size": 4096, "pages-per-line": 16},
  "counters": {"host-write-pages": 0, "nand-write-pages": 0,
               "gc-write-pages": 0, "block-erases": 0},
  "media": {"staged-bus": false, "onfi-profile": false, "column-cycles": 0,
            "row-cycles": 0, "page-transfer-ns": 0,
            "read-command-ns": 0, "program-command-ns": 0, "erase-command-ns": 0,
            "copyback-read-command-ns": 0, "copyback-program-command-ns": 0,
            "status-ns": 0, "data-out-lead-ns": 0, "data-out-tail-ns": 0,
            "plane-select-ns": 0, "data-in-edges-ns": 0, "program-confirm-ns": 0,
            "plane-read-busy-ns": 0, "plane-program-busy-ns": 0,
            "plane-erase-busy-ns": 0, "data-in-gap-ns": 0,
            "data-out-edges-ns": 0, "sca": false, "onfi-order": false,
            "page-register-hold": false, "status-per-plane": false},
  "fdp": {"reclaim-groups": 1, "units-per-group": 25, "pages-per-unit": 16,
          "handles": [{"id": 0, "type": "persistently-isolated",
                       "host-bytes": 0, "media-bytes": 0},
                      {"id": 1, "type": "persistently-isolated",
                       "host-bytes": 0, "media-bytes": 0},
                      {"id": 2, "type": "persistently-isolated",
                       "host-bytes": 0, "media-bytes": 0},
                      {"id": 3, "type": "persistently-isolated",
                       "host-bytes": 0, "media-bytes": 0}],
          "unit-counts": {"free": 21, "open": 4, "full": 0, "victim": 0,
                          "total": 25},
          "reclaim-units": [{"group": 0, "unit": 0, "handle": 0,
                             "state": "open", "vpc": 0, "ipc": 0,
                             "erase-min": 0, "erase-max": 0}]},
  "offset": 0, "next-offset": 1}]}}
```

A zoned namespace with one zone written and one zone finished:

```json
{"execute": "query-femu", "arguments": {"kind": "zones", "limit": 2}}
```

```json
{"return": {"path": "/machine/peripheral/femu0", "mode": "znssd", "namespaces": [{
  "nsid": 1, "mode": "znssd", "lba-size": 512,
  "zone-size": 131072, "zone-capacity": 131072, "max-open": 0, "max-active": 0,
  "zone-counts": {"empty": 14, "implicitly-open": 1, "explicitly-open": 0,
                  "closed": 0, "read-only": 0, "full": 1, "offline": 0,
                  "total": 16},
  "media": {"staged-bus": false, "onfi-profile": false, "column-cycles": 0,
            "row-cycles": 0, "page-transfer-ns": 0,
            "read-command-ns": 0, "program-command-ns": 0, "erase-command-ns": 0,
            "copyback-read-command-ns": 0, "copyback-program-command-ns": 0,
            "status-ns": 0, "data-out-lead-ns": 0, "data-out-tail-ns": 0,
            "plane-select-ns": 0, "data-in-edges-ns": 0, "program-confirm-ns": 0,
            "plane-read-busy-ns": 0, "plane-program-busy-ns": 0,
            "plane-erase-busy-ns": 0, "data-in-gap-ns": 0,
            "data-out-edges-ns": 0, "sca": false, "onfi-order": false,
            "page-register-hold": false, "status-per-plane": false},
  "zones": [{"index": 0, "type": "sequential", "state": "full",
             "start-lba": 0, "capacity": 131072, "zrwa": false},
            {"index": 1, "type": "sequential", "state": "implicitly-open",
             "start-lba": 131072, "capacity": 131072,
             "write-pointer": 131080, "zrwa": false}],
  "offset": 0, "next-offset": 2}]}}
```

## Consistency and cost

The FTL thread of the controller copies the state of a `bbssd` namespace
between two I/O requests. Thus the counters, line counts and lines of one
namespace in one reply agree with each other. The same holds for the
handles and reclaim units of an FDP namespace. The main loop copies a
`znssd` namespace while it holds the zone lock, so its zone counts and
zones also agree. Different namespaces, and different calls, show
different points in time. A listing in pages is not one snapshot.

The pollers hold the zone lock while they change a zone, and for a whole
Report Zones command. The main loop does not wait on the lock: when a
poller holds it, the command sleeps and tries again. The zone counts are
kept with each state change, so the copy reads only the zones it lists.

The copy occupies the FTL thread for a short time. It does not stop the
pollers, and the main loop continues while the command waits. With
`kind` `lines`, the FTL thread walks the free, full and victim lists of the
namespace once per call. With FDP, it walks the unit lists of each reclaim
group once per call, also for a summary. The command fails with an error in these cases:

- A `bbssd` namespace is selected and the controller is not enabled.
- The FTL thread does not take the query in 5 seconds, for example because
  an admin command pauses the controller.
- The zone lock of a `znssd` namespace stays busy for 5 seconds.
- The device is removed during the query.
- A namespace changes during the query.

Only one query at a time can wait on a device.

## I/O stage times: query-femu-stages

With `io_stages=on`, the pollers time each I/O command in stages, and the
QMP command `query-femu-stages` returns one histogram per stage. It shows
where the time of a command goes, and how far the real completion lands
after the time the model gives it.

```
 fetch --> handoff to FTL --> back from FTL --> ready --> CQE posted
   | submit |      ftl       |     hold      | post-delay |
   |<-------------------------- total ------------------------->|
 ready = the later of the model's due time and the return from the FTL
 past-due = due time --> CQE posted   (the completion-time metric; not in total)
```

| Stage | From, to |
| --- | --- |
| `submit` | the fetch of the command, to its handoff to the FTL ring |
| `ftl` | the handoff, to its return from the FTL, in host time |
| `hold` | the return, to ready |
| `post-delay` | ready, to the posted entry |
| `total` | the fetch, to the posted entry |
| `past-due` | the model's due time, to the posted entry |

For a command that goes through the FTL ring, the first four stages add up
to the total time. A large `past-due` means that completions land later than the
model says. `returned-after-due` counts the commands that came back from
the FTL after their due time; for those, `hold` is 0.

Each stage has `count`, `sum-ns`, `max-ns` and 40 `buckets`. Bucket i holds
the commands that took 2^i to 2^(i+1) - 1 ns. Bucket 0 also holds 0 ns,
and bucket 39 also holds every longer time.

```json
{"execute": "query-femu-stages", "arguments": {"reset": true}}
```

`reset` stops the pollers, reads and clears the counts, and starts them
again, so no command is lost between two replies. Commands that complete
without the FTL ring (NoSSD with `hiops_inline` on, CSD programs) count in
`post-delay`, `past-due` and `total` only. Commands that a namespace delete
retired are not counted, and admin commands are not timed. Without `reset`,
a reply taken during I/O can differ by the commands in flight. Without
`io_stages=on` the command fails.
