# Extension interface: modes, mapping schemes and GC policies

FEMU has three tables of hooks. A new mode, a new L2P mapping scheme or a
new GC victim policy plugs in through one of them. This page gives the
contract of each table: the hooks, the context that calls them, the time
units, and what a hook may change.

| Table | Header | Version constant | Selected by |
| --- | --- | --- | --- |
| `FemuExtCtrlOps` | `hw/femu/femu-ext-ops.h` | `FEMU_EXT_OPS_VERSION` | `femu_mode` or `mode`, `namespace_modes` |
| `struct femu_mapping_ops` | `hw/femu/bbssd/ftl-ops.h` | `FEMU_FTL_OPS_VERSION` | `mapping` |
| `struct femu_ftl_policy_ops` | `hw/femu/bbssd/ftl-ops.h` | `FEMU_FTL_OPS_VERSION` | `gc_policy` |

The headers hold the kernel-doc of each member. The interface is internal
to the C code and has no binary compatibility promise. The version
constant tells out-of-tree code which contract it compiles against.

```
 femu_mode / namespace_modes        mapping=NAME              gc_policy=NAME
          |                              |                          |
 femu_ext_ops_lookup()      femu_mapping_scheme_lookup()  femu_ftl_policy_lookup()
          |                              |                          |
 FemuCtrl.ext_ops (copy)            ssd->mapping               ssd->policy
 NvmeNamespace.ext_ops (copy)            |                          |
          |                   bbssd FTL: bbssd, CSD, FDP, KV, femu-cxl-ssd
 NVMe front end
```

## Version rule

| Change | Version |
| --- | --- |
| A new optional hook, where NULL keeps the old behaviour | no change |
| A new required hook, a changed signature or a changed rule | add one |
| A removed hook | add one |

Version 1 of both tables is the set in the headers today.

## Mode tables (`FemuExtCtrlOps`)

Each mode exports one constant table, for example `femu_bbssd_ext_ops` in
`hw/femu/bbssd/bb.c`. `femu_ext_ops_lookup()` in `hw/femu/femu.c` maps a
mode to its table. Realize copies the table of the controller's mode into
the controller, and the table of each namespace's mode into that
namespace.

```
 realize
   n->ext_ops  = table of the controller's mode (OC 2.0 adds its state)
   for each namespace:
     ns->ext_ops = table of the namespace's mode, state NULL
     ns->ext_ops.init(n, ns, errp)
 CC.EN      start_ctrl of each distinct mode, controller copy first
 I/O        ns->ext_ops.io_cmd
 admin      n->ext_ops.admin_cmd_cqe, else n->ext_ops.admin_cmd
 Get Log    ns->ext_ops.get_log if set, else n->ext_ops.get_log
 ns delete  ns->ext_ops.ns_exit
 unrealize  exit of each distinct mode, controller copy first
```

| Hook | Context | I/O processing |
| --- | --- | --- |
| `init`, `ns_exit` | BQL: realize, or Namespace Management on a vCPU | not started, or paused |
| `init_ctrl_name` | BQL: realize | not started |
| `exit` | BQL: realize undo, unrealize | stopped |
| `start_ctrl` | BQL: the CC.EN write | not running |
| `admin_cmd`, `admin_cmd_cqe`, `get_log` | BQL: the admin queue | runs |
| `io_cmd` | a poller thread, or the FTL thread with `power_loss` | runs; no BQL; the subsystem `ns_lock` when the namespace is shared |

Rules:

- `io_cmd`, `admin_cmd`, `admin_cmd_cqe` and `get_log` return an NVMe
  status, and zero is success. The front end returns it with no other hook
  tried. `start_ctrl` returns 0 or -1. `init` reports through its `Error`.
- `io_cmd` never takes the BQL. It copies guest memory with `femu_dma_rw()`.
  Request times keep the clock that set them (`femu_io_now()`).
- `exit` runs at most once per mode and controller. It also runs after a
  realize that failed before `init`. `ns_exit` may run before it for the
  same namespace.
- A table has a unique `name` and an `io_cmd`, and at most one of
  `admin_cmd` and `admin_cmd_cqe`. Its `state` is NULL.
- Two tables never share a `start_ctrl` or an `exit` function. The walk of
  the distinct modes keys on `name`.

`femu_ext_ops_check()` and `femu_ext_ops_check_set()` enforce the rules
that they can see. The lookup stops QEMU on a table that fails them. The
checks apply to the exported tables, not to live copies.

The `state` member has two scopes:

- The controller copy holds controller-wide state. OC 2.0 keeps its chunk
  state there from registration on. KV points it at the store of its first
  namespace.
- A namespace copy holds the state of that namespace, as KV does.

CSD keeps its controller state in `FemuCtrl.csd_ctrl_state`, because
another mode can use the controller copy.

Three paths copy a table in another way:

- The memory and compute namespaces of CSD copy the CSD table with no
  `init` and no state.
- A controller on shared storage copies the table into the storage object.
  No controller of shared storage runs `exit`. The last release of the
  storage runs `ns_exit` for each slot.
- Namespace Management create copies the table and runs `init`. It does not
  run `init_ctrl_name`.

Admin commands reach only the controller copy. An admin opcode of a
namespace in another mode is therefore not served.

## Mapping schemes and GC policies (`ftl-ops.h`)

The bbssd FTL runs under bbssd, CSD, FDP, KV and `femu-cxl-ssd`. KV refuses
every `gc_policy` except `greedy` and keeps its own mapping and victim
choice. `femu-cxl-ssd` has neither property, so it runs `page` and
`greedy`.

```
 write  prepare_write -> allocate -> commit_write -> program
        -> needs_reclaim / reclaim
 read   translate
 GC     select_victim_line -> for each valid page: gc_relocate_commit
 trim   trim, or the flat invalidation when trim is NULL
```

FDP host writes and trims update the maps directly, with no
`prepare_write`, `commit_write` or `trim`. FDP relocation calls
`gc_relocate_commit`.

One FTL can have more than one caller thread. The callers take turns:

| Caller | When |
| --- | --- |
| `FEMU-FTL-Thread` of a controller | I/O, GC, reclaim, flush and destage; on shared storage, under the subsystem `ns_lock` |
| the `femu-cxl-ftl` worker, and the FTL thread of a linked controller | I/O of a `femu-cxl-ssd` medium and of its linked controller, under the lock of the medium |
| BQL context, with the callers above stopped or paused | realize (`ssd_init`, preconditioning, restore of a saved FTL), unrealize, Format, namespace create and delete, probes such as the Streams one |

`nvme_pause_pollers()` pauses the NVMe controllers only. It does not pause
the `femu-cxl-ftl` worker, so a BQL caller on a CXL medium also needs the
lock of the medium.

Rules:

- No hook takes a lock, sleeps, or touches guest memory.
- Times are `uint64_t` nanoseconds of the device clock. The caller joins
  the latency of `reclaim()` to the request with MAX. Line ages use
  `ssd_age_now()`. FDP cost-benefit keeps microseconds.
- A mapping operation keeps `maptbl` and `rmap` inverse to each other. The
  hook and its caller share this work: `gc_relocate_commit` maps the new
  page, and the caller then invalidates the old one.
- A mapping scheme changes page and line counts only through the helpers in
  `ftl-internal.h`. Its own state lives in `ssd->map_priv`.
- `reclaim(ssd, budget)`: `hybrid` does at most `budget` merges. `fast`
  does one full pass and ignores `budget`.
- A mapping scheme has `translate`, `prepare_write`, `commit_write` and
  `gc_relocate_commit`. It has both `needs_reclaim` and `reclaim`, or
  neither. `reclaim_per_page` needs both.
- `map_write_plan.may_need_reclaim` is set by `hybrid` and `fast`. No caller
  reads it today.
- A GC policy reads `ssd->lm.victim_line_pq` and the line fields. It removes
  the line it returns from the queue. When it returns NULL, the queue keeps
  the same lines, but `random` can change the heap order of equal keys.
- A GC policy tests its candidate with `gc_line_worth()`: a background pass
  needs at least `ssd_line_data_pgs() / 8` invalid pages, rounded down.
- A GC policy draws random numbers only from `ftl_gc_rand()`, so `gc_seed`
  fixes the victim order of the policies that sample. `cost-benefit` reads
  the host clock, so its order is not fixed.
- `fdp_strategy` is the reclaim unit strategy that the policy name selects
  under FDP. `FEMU_FDP_FROM_GC_STRATEGY` leaves that choice to
  `gc_strategy`. Zero is refused, so a table cannot omit the field.

`femu_mapping_ops_check()` and `femu_ftl_policy_ops_check()` enforce the
table rules. The lookups stop QEMU on a table that fails them.

To add a scheme or a policy, follow
[Extending the FTL](../design/ftl.md#extending-the-ftl).

## Tests

| Test | What it fixes |
| --- | --- |
| unit `test-femu-ext-ops` | each table check refuses one bad case per rule; the distinct walk keeps the first table of each name, in order |
| qtests `ftl-trace-*` | the counts and the victim digest of `greedy`, `random`, `d-choice` and `fifo` on one workload, also under FDP; `cost-benefit` reads the host clock, so only the `combo-policy-cost-benefit-*` invariants cover it |
| qtests `hybrid-oracle-*` | the `hybrid` scheme against a C oracle |
| qtests `zoned-append-limit`, `namespace-mixed-identity-*`, `query-media-mixed` | the table of each namespace's mode, and `start_ctrl` of a mode that only a namespace runs |
