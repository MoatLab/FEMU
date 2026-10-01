# Configuration changes that affect existing command lines

FEMU used to accept some device properties that it then ignored, and to fail
some configuration checks without saying so. Both are now reported at device
realize. A command line that ran before may therefore stop, with a message
naming the property. Nothing here changes a configuration that was already
being honoured.

## Refused at realize (previously accepted and ignored)

| Property | Why it is refused |
|---|---|
| any violated controller constraint | The check ran but returned silently, leaving QEMU up with no FEMU PCI device and no namespaces. The reason is now reported. |
| `mpsmax` below `mpsmin` or above 15 | The test used to be inverted, so `mpsmax=1` was rejected and `mpsmin=1,mpsmax=0` accepted, advertising CAP.MPSMIN above CAP.MPSMAX. |
| `meta` with `dpc` or `dps`, with `nlbaf` above 8, or without a matching `mc` | Metadata is implemented for NoSSD and bbssd (separate buffer or interleaved with the data), but not together with the legacy protection settings; use `pi` for protection information. Before metadata was implemented, any non-zero `meta` was refused. |
| `cell_pages` above 5 | Indexed past the page-type multiplier table. |
| `nand_cell_type` with `pgs_per_blk` above 512 | Read past the page-type latency tables. |
| `gc_strategy` outside {0,1,2,4} | Other values silently fell back to greedy or never collected at all. |
| `zns_flash_type` 0, 6 or above, or MLC/PLC without explicit latencies | 0 gives a zero-length write cache and an endless flush loop; 6+ indexes past the timing tables; MLC and PLC have no built-in figures, so every NAND operation cost nothing. |
| `femu_mode` above 5 | No mode registers command handlers for it (6 was a SmartSSD placeholder), so the controller came up with none. |
| `multipoller_enabled` other than 0 or 1 | Values above 1 started several pollers that each swept every queue, so two pollers could run and complete the same command. |
| `lver` other than 1 or 2 with `femu_mode=0` | No Open-Channel handlers were registered for it. |
| `flash_type` outside 1 to 4 with `femu_mode=0` | OCSSD 2.0 indexed the SLC to PLC timing tables with it unchecked, so 6 or above read past them; 0 and 5 have no built-in figures. OCSSD 1.2 already refused them. |
| `zns_num_plane` above 8, `zns_num_ch` above 128, or a page count above 65536 | Wrapped and aliased onto lower indices in the PPA. |
| `zns_chnls_per_zone` that does not divide `zns_num_ch` | Was silently replaced by the full channel width. |
| bbssd knobs under FDP: `buffer_size`, `hot_cold_sep`, `read_reclaim_limit`, `retention_limit_sec`, `ecc_retention_sec`, `trim_lat_ns`, non-default `mapping` or `gc_policy` | FDP keeps its own write and reclaim path; none of these reach it. |

If one of these stops a run, remove the property. It was not doing anything.

## Behaviour changes (still boots, numbers move)

- A CSD namespace now goes through its FTL, so reads and writes take NAND time
  instead of completing instantly. A pure-CSD device previously timed out on
  its first I/O and the kernel disabled the controller.
- A namespace whose mode differs from the controller's is routed by its own
  mode. A bbssd namespace on a NoSSD controller no longer completes inline.
- `pcie_bandwidth_mbps`, `pcie_prop_delay_ns` and `fw_cpu_ns` now apply to
  NoSSD. Setting any of them takes the request off the inline completion path,
  which costs throughput; leaving them unset keeps the previous path.
- `cmd_addr_lat`, `pg_xfer_lat`, `status_lat` and `ch_xfer_lat` now add channel
  bus time on bbssd. The bundled run scripts pass 0 and are unaffected.
- `zns_cmd_addr_lat`, `zns_pg_xfer_lat` and `zns_status_lat` add the same
  channel bus to ZNS. They default to 0, which leaves ZNS timing exactly as it
  was; a negative value is refused at realize.
- Temperature threshold Set Features accepts only TMPSEL 0 and Fh; other
  selectors are rejected rather than stored as part of the value.
- An aborted command completes as Command Abort Requested rather than Invalid
  Opcode.
- FDP RUAMW counts down in LBAs, so it drains at the documented rate and
  reaches zero; cost-benefit victim selection now orders by age and utilisation
  rather than insertion.

## Shared Namespace Management (opt-in)

With `femu-subsys,ns_mgmt=on`, the subsystem owns one namespace table,
backend capacity pool and full-geometry FTL per bbssd namespace. This prevents
controllers allocating the same NSID independently or deleting only a private
copy. Realize the subsystem before its controllers. The first controller
establishes the pool and boot namespaces; later controllers join that pool with
no initial attachments. Namespace Attachment selects their active namespaces.

The subsystem copies the first controller's properties into an unrealized
configuration object as its storage context, independently of PCI transport
lifetime. This context has no queues or workers. Its namespace table and
backend survive removal of that controller, including removal of every controller.
They are released at subsystem teardown after its last controller has left. Namespace identity and the creation
sequence belong to this context. Controllers must agree on the storage mode and
format capabilities. Runtime construction uses the original storage configuration,
including capacity, geometry, media options and the bbssd namespace cap; those
properties on later controllers do not create additional storage.

Each controller keeps its own queues, pollers, FTL thread, attachment bitmap and
namespace-change log. Pollers reach the common table through their controller;
active lookup additionally checks that controller's attachment bitmap. A subsystem
mutex serializes data and FTL processing. Existing pause/resume interfaces pause
all controllers in a managed subsystem, so Format, Sanitize and lifecycle changes
cannot race another controller's workers. Delete retires namespace references in
every controller's request containers before releasing storage, without waiting
for guest consumption of a full CQ. Detach retires only the selected controllers.
Reset preserves attachments. Transport removal stops its workers and drops its
attachments without releasing the subsystem's namespaces.

CNS 10h/11h describe the common allocated set. CNS 02h describes the issuing
controller's attachments. CNS 12h lists attached controllers and CNS 13h lists
eligible controllers, in ascending order with inclusive CNTID filtering.
Attach/detach records changes and sends enabled Attached Namespace Attribute
Changed notices on each affected controller. Delete does the same except that
its issuer receives no notice. Allocated Namespace Attribute notices are not
advertised. Create produces a detached namespace and no attached-set notice.

The model is opt-in on the subsystem. Existing standalone management and
unmanaged subsystems retain their behavior. Only homogeneous NoSSD or bbssd is
supported; FDP and Streams remain excluded. Full-geometry bbssd allocation and
its namespace-count cap are retained. Scaled FTL geometry, allocated-namespace
notices, persistent storage and other namespace modes are outside this change.

For example, realize a NoSSD subsystem and two controllers in this order:

<!-- femu-example: shared-namespaces -->
```sh
-device femu-subsys,id=shared,ns_mgmt=on \
-device femu,id=ctrl-a,subsys=shared,femu_mode=2,devsz_mb=64 \
-device femu,id=ctrl-b,subsys=shared,femu_mode=2
```

Only ctrl-a initially has the boot namespace attached. Controller lists report
the assigned CNTLIDs; use Namespace Attachment to expose it through ctrl-b too.
Create honors NMIC: private namespaces can move between controllers but cannot
be attached to two simultaneously. Shared namespaces permit both attachments.
