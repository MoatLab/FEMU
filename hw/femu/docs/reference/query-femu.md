# QMP query-femu

`query-femu` is a QMP command that reports the FTL state of a FEMU NVMe
controller to the host. It needs no guest tools. The schema is in
`qapi/femu.json`, and `query-qmp-schema` also returns it.

This release supports only BlackBox (`bbssd`) namespaces. A selected
namespace in another mode, with flexible data placement, or backed by a
`femu-cxl-ssd` medium returns an error that names the mode. A controller
in an unsupported mode returns that error even when the guest has not
enabled it.

## Start a device with a QMP socket

<!-- femu-example: query-femu-qmp -->
```
-device femu,id=femu0,devsz_mb=1024,femu_mode=1 -qmp unix:/tmp/femu-qmp.sock,server=on,wait=off
```

The guest must enable the controller before a query works. The NVMe driver
does this when it binds to the device.

## Arguments

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `path` | string | the only `femu` device | QOM path of the device, for example `/machine/peripheral/femu0` |
| `nsid` | integer | every attached namespace | the namespace to report |
| `kind` | `summary` or `lines` | `summary` | `lines` adds one record per line |
| `offset` | integer | 0 | with `lines`, the first line to report |
| `limit` | integer | 256 | with `lines`, the most lines to report, 1 to 4096 |

`offset` and `limit` with `kind` `summary` are an error. With `kind`
`lines`, give `nsid` if the controller has more than one namespace.

## Reply

The reply has the device `path`, the controller `mode` and one entry in
`namespaces` for each selected namespace. Each entry has these members:

| Member | Content |
| --- | --- |
| `nsid`, `mode` | the namespace and its mode: `ocssd`, `bbssd`, `nossd`, `znssd`, `csd` or `kvssd` |
| `geometry` | `channels`, `luns-per-channel`, `planes-per-lun`, `blocks-per-plane`, `pages-per-block`, `page-size` (bytes) and `pages-per-line` |
| `counters` | `host-write-pages`, `nand-write-pages`, `gc-write-pages`, `block-erases`, and `waf` |
| `line-counts` | lines that are `free`, `victim`, `full`, `retired` and `spare`, and the `total` |
| `lines` | with `kind` `lines`: `id`, `state`, `vpc`, `ipc`, `erase-min` and `erase-max` of each line |
| `offset`, `next-offset` | with `kind` `lines`: the first line in `lines`, and the offset of the next call; `next-offset` is absent after the last line |

The page counters are the counters of [log page C0h](log-pages-and-counters.md#vendor-log-page-c0h)
for one namespace. C0h adds them over the namespaces of the controller.
`waf` is (`nand-write-pages` + `gc-write-pages`) / `host-write-pages` as a
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
  "line-counts": {"free": 254, "victim": 0, "full": 1, "retired": 0, "spare": 0,
                  "total": 256},
  "lines": [{"id": 0, "state": "full", "vpc": 16384, "ipc": 0, "erase-min": 0, "erase-max": 0},
            {"id": 1, "state": "open", "vpc": 4096, "ipc": 0, "erase-min": 0, "erase-max": 0}],
  "offset": 0, "next-offset": 2}]}}
```

To read all lines, call again with `offset` set to `next-offset` until the
reply has no `next-offset`.

## Consistency and cost

The FTL thread of the controller copies the state of a namespace between
two I/O requests. Thus the counters, line counts and lines of one namespace
in one reply agree with each other. Different namespaces, and different
calls, show different points in time. A listing in pages is not one
snapshot.

The copy occupies the FTL thread for a short time. It does not stop the
pollers, and the main loop continues while the command waits. With
`kind` `lines`, the FTL thread walks the free, full and victim lists of the
namespace once per call. The command fails with an error in these cases:

- The controller is not enabled.
- The FTL thread does not take the query in 5 seconds, for example because
  an admin command pauses the controller.
- The device is removed during the query.
- A namespace changes during the query.

Only one query at a time can wait on a device.
