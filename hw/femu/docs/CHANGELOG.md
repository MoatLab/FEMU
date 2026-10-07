# Changelog

User-visible changes to FEMU. Each entry names the commits it comes from;
`git show <hash>` has the details.

## Unreleased (since femu-v9.0.1)

655 commits after the `femu-v9.0.1` tag (2024-06-20), dated 2024-08-07 to
2026-10-01, plus the documentation and script fixes that close this list.
Tests, CI-only changes, internal refactoring and wording fixes are not
listed one by one.

### QEMU base

- FEMU now builds on QEMU 10.1.0 instead of 9.0.1, with device registration moved to the current QEMU APIs (eafddfdd0).
- Two QEMU TCG fixes are carried from upstream QEMU. Without them a vCPU could resolve a stale memory section after a device was unplugged and stop QEMU with an assertion (ef516ed58, c66409e3b).
- Two QEMU CXL fixes are carried: the background command timer is freed with its CCI, and a CXL Type 3 device releases its mapped backends when realize fails (43040a04c, 6153becf8).
- QEMU's network block drivers are left out of the FEMU build, which fixes compilation against libnfs 6 (81c4385fc).

### New devices, modes and features

#### CXL SSD (new device)

- New `femu-cxl-ssd` device: a CXL memory device whose accesses go through a DRAM buffer cache and FEMU's FTL and NAND timing (bb9aea670, a8627fcf9, 7777c0d53, 6ffe34f17).
- The buffer cache gained runtime controls, scalable associativity, per-page pin and remove, and NAND geometry properties for larger capacities (f5ba3ff12, 38b314181, 76f180b9d).
- Direct mapping modes `der=memslot` and `der=cylon` map hot pages straight into the guest, with configurable direct mapping ratios and LSA mailbox commands to control them (80803505b, b3e042a84, 1f26fb2df, 8266a291e, a1e550885).
- A CXL caching API is served on BAR5, with a guest library, the `ccactl` tool and a guest self-test (924714c18, 1235e87d2, ec3af4ba4, 0a357d11e, defd999b8).
- Cache misses to different pages wait for the media together, by default only while a direct mode is active, and long media waits sleep instead of spinning (b72d14dbe, 64d424dd2, 133c553ca, 145fcfe4b).
- A bbssd NVMe controller can share a `femu-cxl-ssd` medium through `cxl_ssd=<id>`, with writes, deallocates and flips kept consistent between the two front ends (146a240dc, d73a5b780, a7a3c5678, 353bbe107, 287e5c885, 6783d50af).
- A runtime `fast-load` switch on `femu-cxl-ssd` lets warmup and data loading skip the wait for modelled media time while the FTL, cache and counters still run. Switching it off waits for the queued NAND work, reported in `fast-load-drain-ns`, so measurement starts on an idle model.
- With `der=cylon` on a host kernel that has `KVM_CAP_CYLON_FAULT_EXIT`, an instruction KVM cannot decode (VEX, EVEX, most SSE with a memory operand) on an unmapped page no longer hangs its vCPU: FEMU fills and maps the page and the guest runs the instruction natively, or stops the VM with a report when the page cannot be mapped or the instruction makes no progress (100,000 consecutive refills at one RIP). Instruction fetches from an unmapped page (for example a shared library cached on the CXL node) are mapped, not emulated, so code such as `endbr64` runs natively. New property `cylon-emul-exit` and counters `der-emul-exit`, `der-emul-fills`, `der-emul-fetch-fills` and `der-emul-failures`.
- The `femu-cxl-ssd` FTL worker wakes only the access whose request it finished, instead of every waiting access. On a `der=cylon` test with 8 and 16 vCPUs doing random reads that all miss a 256-page cache, throughput rose about 40% (65k to 91k and 70k to 98k accesses/s), because waiters no longer wake for other requests.

#### New modes and data placement

- Flexible Data Placement (FDP) on a new `femu-subsys` device, with reclaim unit handles, FDP log pages, I/O Management commands and several GC strategies (c966d341a, 6df00de01).
- FDP placement features can be read and enabled by a Linux host, and the host sees its active reclaim unit and remaining space (8f00c7117, 9a66fe52d).
- Computational Storage Drive mode (`femu_mode=4`) with program load and execute commands, routed through the bbssd FTL (eb01bb73b, 50b65ca91).
- CSD `nr_cu` and `csf_runtime_scale` now take effect (202ab7afb).
- A CSD runtime shorter than the program's own run on the host cannot be reached, since the completion carries the result; QEMU now warns once when that happens (b8e8d6b45).
- Key-value SSD mode (`femu_mode=5`) with store, retrieve, list, delete and exist commands (e72465909).
- Every KV namespace has its own command set and key space, the KV command set is advertised to the host, and the KV Configuration feature is served (39664d242, e62db84f2, e4949509c).

#### Namespaces

- Multiple namespaces per controller via `namespaces` and `namespace_sizes` (140b2891e, 2e25897fe).
- Namespaces on one controller can run different modes via `namespace_modes` (053fd8936).
- Opt-in Namespace Management and Attachment (`ns_mgmt=on`) for NoSSD and bbssd, with a bbssd namespace cap (`bbssd_ns_limit`) (b12bc8754, d9c9f2251, b48799800, e0fa92f19, 42369e0bd).
- Namespace attribute changes are reported through AER and log page 04h, and recorded in the Persistent Event log (3630d6fa0, cc9e271b4).
- Namespaces can be created with protection information (c213b120c).
- Shared namespace management across controllers of one `femu-subsys,ns_mgmt=on`, with the subsystem owning namespace storage (ca80e3dc5, 23844afaa, feebe635c, 76cc58f63, 97fc6ae0a, 349f12d40).

#### Metadata, protection information and Streams

- Separate LBA metadata (`meta`, `mc`) on bbssd and NoSSD namespaces (62d149dd5).
- Metadata interleaved with data (extended LBAs, `extended=1` or Format with MSET) (ba36f0f68).
- Opt-in protection information formats (`pi=on`), with generation and checking on Read, Write, Verify, Compare, Write Zeroes and Copy (bb2f3fb06, d1d8e1593, 617f09c10, 1854c1940, f6dc00f46, 98fcaedea, 8f7382c2a, 9661e5adb).
- Opt-in Streams directive (`streams`, `streams.max`), with stream writes placed on separate bbssd write frontiers (623637942, 8e7387268, cb459a65b, e3529d48f).

#### NVMe commands, features and log pages

- SGL data transfers (`sgl`), now honoured on every I/O command that carries data (1fa43530d, d24705851).
- DULBE and Write Zeroes with Deallocate report deallocated blocks (98247b96f).
- TRIM (Dataset Management deallocate) on bbssd (d749928e9).
- Verify command (e8c2c8933).
- Copy command, including copies between namespaces (descriptor format 2) (b16b3b3ae, 04b3da484).
- Device Self-test and its log (b3e5965d4).
- Sanitize block erase and the Sanitize Status log (4997dbdd9).
- Telemetry Host-Initiated and Controller-Initiated logs (d859ad4d6).
- Get LBA Status and the LBA Status Information log (bfc02d6a3).
- Timestamp feature (5323f363b).
- Persistent Event log, with format, sanitize, telemetry, error and Set Features events, optionally kept across runs in `pel_file` (87ea8154c, 93dddf1d2, 276c93e23, 3a368e984).
- Asynchronous Event Requests are accepted and events are reported (7d5d2f84f, b53ec7122).
- Supported Log Pages (log 00h) and the I/O Command Set Profile feature are answered (1b15f38df, 481eb6df2).
- SMART reports host data units and command counts, available spare (with an optional `nand_bad_blocks` model), percentage used (from the cell type or `pe_cycles_rated`) and media errors (f07d117f1, a20d9ac94, a8a28d451, df8a3492a, e25ddf7be).
- The Endurance Group log is filled in (074b63f4f).
- Media counters (write amplification, host and relocated pages, write buffer hits, read reclaims, retention refreshes) are reported in vendor log page C0h (e57448e41, 4cb1f9ba7, e9746f6bf, e7f182b87).
- A QMP command, `query-femu`, reports the geometry, write counters, line counts and per-line state of bbssd namespaces to the host. The FTL thread copies the state between two requests ([reference](reference/query-femu.md)).
- Opt-in power loss model (`power_loss`) that drops data still held in the volatile write buffer and records the event in SMART and the event log (46602b0e7, 303c77aef, 7679c443d).

#### ZNS

- Write buffer and FTL for the ZNS SSD, and zone reset charged with erase time (0326ab489, b3272c013).
- Configurable zone resource limits (`zns_max_active`, `zns_max_open`) and zone descriptor extension size (6404dd233).
- Optional conventional zones (`zns_num_conv_zones`) (6e7395b55).
- Configurable zone width (`zns_chnls_per_zone`) (e04e4e901).
- Zone Random Write Area support (`zns_zrwa_*`) (b18f56b2b, 9f51854d7).
- An injected write fault (`err_write_fail_ppm`) takes the zone read only and lists it in the Changed Zone List (ccdae5d3b).
- Changed Zone List log page (569608a41).
- Configurable reads across zone boundaries (`zns_cross_zone_read`) and Zone Append size limit (`zns_zasl_bs`) (78caee058, bca834133).
- ZNS takes NAND timing from the shared media layer, with configurable read, program and erase times and an opt-in channel bus (3d6056020, 34bbe45fa, 2a4ebc2cb).
- Configurable write cache count (`zns_num_wc`) (66f432117).
- Optional program/erase suspend for reads (`zns_pe_suspend`, `zns_tsusp_ns`) (9ec423985).

#### BlackBox SSD (bbssd) and NAND media

- NAND operation timing moved into a shared media layer used by bbssd and ZNS (46cb582c9, 711d537bc).
- Pluggable GC victim selection (`gc_policy`: greedy, random, cost-benefit, fifo, d-choice) (7222d6744).
- Opt-in DRAM read cache (`read_cache_mb`, `cache_evict`) (3b21542de, fc5d3ded0).
- Pluggable L2P mapping (`mapping`: page, dftl, hybrid, fast) with a modelled mapping cache (`mapping_cache_mb`) (64a19a6f3, 46e4261f9, 0f9b6aeab).
- Write amplification accounting, and a `debug_ftl` switch that prints page-state violations found on the GC path (e57448e41).
- Optional cell-type NAND timing (`nand_cell_type`, `cell_pages`, `pgtype_lat`, ONFI phase times, `ecc_step_ns`) (e405dbcbc).
- Optional modelled TRIM time (`trim_lat_ns`) and explicit over-provisioning (`op_pcent`) (1027eb240, 6a4559ee4).
- DRAM write buffer (`buffer_size`, `buffer_thres_pcent`) with Flush, FUA and volatile write cache support (6a8daec7a, d4d03f127, 0ee6d211b).
- Hot/cold separation of overwritten pages (`hot_cold_sep`) (4ded2e928).
- Read reclaim (`read_reclaim_limit`) and retention refresh (`retention_limit_sec`) (7f9b4f6af, 4e09c4797, e7f182b87).
- Data age feeds the ECC read model (`ecc_retention_sec`) (f9433e9ab, 13f2b85de).
- More than one plane per LUN (`pls_per_lun`) in bbssd, FDP and KV, with a line's planes erased in one operation (0f554fb7d, 3699e980d, 9c8228d28, 7276af2d8).
- Channel bus phases (`cmd_addr_lat`, `pg_xfer_lat`, `status_lat`, `ch_xfer_lat`) are added to the timing when set (c274ba7d9).
- A read can suspend an in-flight program or erase (`pe_suspend`, `tsusp_ns`) (9ec423985, 6a5c498a8).
- Opt-in multi-plane program and read (`mp_program`, `mp_read`, with `pls_per_lun > 1`): host programs or reads of the same page on several planes of a LUN take one array time, plus `tplpbsy` or `tplrbsy` between planes. Placement and page counts do not change. The defaults leave the timing unchanged, FDP is not affected, and a negative busy time is refused.
- Optional debug logging to study whether deleted data remains on the device (18ba6557c, 45e61ae41).

#### Timing and fault models

- Fault insertion (`err_read_unc_ppm`, `err_write_fail_ppm`), a host link model (`pcie_bandwidth_mbps`, `pcie_prop_delay_ns`) and a controller CPU model (`fw_cpu_ns`), now also applied to NoSSD (7bfac4c3a, 2cdd55c52).

#### Open-Channel SSD

- Opt-in OC 1.2 channel transfer timing (`oc12_channel_timing`) (d174f9551, 5cf3996c0).
- OC 2.0 gets media timings, chunk resets are charged as erases, an unwritten block reads as the predefined pattern, and a host can reset a chunk it has not filled (b652c3d87, 9d176f891, 00daad11c, 90ff859c1).

#### NoSSD

- Poller threads decoupled from queues (`poller_ratio`), and I/O counters kept per poller (0b192893b, 6b1592746).
- The backend memory can be bound to or interleaved across NUMA nodes with `FEMU_MBE_INTERLEAVE` (3594d27c6).

### Configuration changes and new refusals

A command line that ran before may stop at realize, with a message naming
the property. Each of these was accepted before and then ignored, or failed a
check without saying so. Nothing here changes a configuration that was
already being honoured. If one of these stops a run, remove the property: it
was not doing anything.

#### Refused at realize (previously accepted and ignored)

| Property | Why it is refused | Commits |
|---|---|---|
| any violated controller constraint | The check ran but returned silently, leaving QEMU up with no FEMU PCI device and no namespaces. The reason is now reported. | 9716c0a9f |
| `mpsmax` below `mpsmin` or above 15 | The test used to be inverted, so `mpsmax=1` was rejected and `mpsmin=1,mpsmax=0` accepted, advertising CAP.MPSMIN above CAP.MPSMAX. | 9716c0a9f |
| `meta` with `dpc` or `dps`, with `nlbaf` above 8, or without a matching `mc` | Metadata is implemented for NoSSD and bbssd (separate buffer or interleaved with the data), but not together with the legacy protection settings; use `pi` for protection information. Before metadata was implemented, any non-zero `meta` was refused. | d589ce2b8, 62d149dd5, ba36f0f68, bb2f3fb06 |
| `cell_pages` above 5 | Indexed past the page-type multiplier table. | d589ce2b8 |
| `nand_cell_type` with `pgs_per_blk` above 512 | Read past the page-type latency tables. | d589ce2b8 |
| `gc_strategy` outside {0,1,2,4} | Other values silently fell back to greedy or never collected at all. | d589ce2b8 |
| `gc_policy` other than greedy with `femu_mode=5` | KV reclaims by taking the emptiest line off the shared victim queue; another policy reorders that queue (fifo by a close order KV never records), so KV took a line that was not the emptiest. | |
| `zns_flash_type` 0, 6 or above, or MLC/PLC without explicit latencies | 0 gives a zero-length write cache and an endless flush loop; 6+ indexes past the timing tables; MLC and PLC have no built-in figures, so every NAND operation cost nothing. | b234d27c8 |
| `femu_mode` above 5 | No mode registers command handlers for it (6 was a SmartSSD placeholder), so the controller came up with none. | c3b8e88ef |
| `multipoller_enabled` other than 0 or 1 | Values above 1 started several pollers that each swept every queue, so two pollers could run and complete the same command. | de5fcd972 |
| `lver` other than 1 or 2 with `femu_mode=0` | No Open-Channel handlers were registered for it. | 498afdd7a |
| `flash_type` outside 1 to 4 with `femu_mode=0` | OCSSD 2.0 indexed the SLC to PLC timing tables with it unchecked, so 6 or above read past them; 0 and 5 have no built-in figures. OCSSD 1.2 already refused them. | 4891d870e |
| `zns_num_plane` above 8, `zns_num_ch` above 128, or a page count above 65536 | Wrapped and aliased onto lower indices in the PPA. | b234d27c8 |
| `zns_chnls_per_zone` that does not divide `zns_num_ch` | Was silently replaced by the full channel width. | b234d27c8 |
| bbssd knobs under FDP: `buffer_size`, `hot_cold_sep`, `read_reclaim_limit`, `retention_limit_sec`, `ecc_retention_sec`, `trim_lat_ns`, non-default `mapping` or `gc_policy` | FDP keeps its own write and reclaim path; none of these reach it. | d589ce2b8 |

#### Other new refusals

- Invalid bbssd and zoned geometries, and a bbssd namespace with no room left for garbage collection; CSD and KV, and every mode a controller serves, now run the same checks (b4bbd93e0, 1ac931d86, ceb2b5bf7, 5ccbe3f24, bf8961b9b, 0b82aa58a).
- Invalid ZRWA configurations, page sizes ZNS cannot serve, and more write caches than zones (b89cde46d, 154775e62, fcfa0d581).
- Unknown `mapping` or `gc_policy` names, and a negative suspend overhead (29c397f38, 2ae58aa55).
- A CSD controller with more than one namespace (b425007c2).
- FDP with more than one reclaim group, and other placement configurations the device cannot serve (f08762450, 8ed17a495).
- An FDP namespace larger than what is left once each handle has a reclaim unit open, each Persistently Isolated handle one to collect into, and forced GC its free units. Such a namespace was accepted and then failed most random writes. A partly exposed last page now counts as a whole one in this check, with or without placement (89f34939f).
- Open-Channel namespaces on a controller in another mode, and OCSSD geometries the timing model cannot index (8cd92eec5, 598498e93, f4e85634a, 707d8c8c1).
- Controller memory buffer settings that do not fit, including any CMB BAR other than 2 (1c3a5a2a2, 9d6e13cd3).
- Queue entry sizes other than 64 and 16 bytes (23b21cc38).
- A format with protection information but no metadata room for it (1c9808bcd).
- On `femu-cxl-ssd`, a direct ratio without DER, and `der=memslot` under TCG (34b9f8f9e, d03b0606e, f1182b72e).

#### Accepted with a warning (still no effect)

- `serial`, `ms`, `ms_max`, `dlfeat`, `trcbsy`, and the CSD `nr_thread`, `time_slice` and `context_switch_time` are still accepted, but nothing reads them, so a value other than the default now prints one warning at realize naming the property; for `ms` it points to `meta` (f67568880). `tplpbsy` and `tplrbsy` were on this list; they now set the multi-plane program and read busy times, and warn only when set without `mp_program` or `mp_read`.

#### Behaviour changes (still boots, numbers move)

- A CSD namespace now goes through its FTL, so reads and writes take NAND time
  instead of completing instantly. A pure-CSD device previously timed out on
  its first I/O and the kernel disabled the controller (50b65ca91).
- A namespace whose mode differs from the controller's is routed by its own
  mode. A bbssd namespace on a NoSSD controller no longer completes inline
  (50b65ca91).
- `pcie_bandwidth_mbps`, `pcie_prop_delay_ns` and `fw_cpu_ns` now apply to
  NoSSD. Setting any of them takes the request off the inline completion path,
  which costs throughput; leaving them unset keeps the previous path (2cdd55c52).
- `cmd_addr_lat`, `pg_xfer_lat`, `status_lat` and `ch_xfer_lat` now add channel
  bus time on bbssd. The bundled run scripts pass 0 and are unaffected
  (c274ba7d9).
- `zns_cmd_addr_lat`, `zns_pg_xfer_lat` and `zns_status_lat` add the same
  channel bus to ZNS. They default to 0, which leaves ZNS timing exactly as it
  was; a negative value is refused at realize (2a4ebc2cb).
- Temperature threshold Set Features accepts only TMPSEL 0 and Fh; other
  selectors are rejected rather than stored as part of the value (c7eaa6b4a).
- An aborted command completes as Command Abort Requested rather than Invalid
  Opcode (03a4eee3c).
- FDP RUAMW counts down in LBAs, so it drains at the documented rate and
  reaches zero; cost-benefit victim selection now orders by age and utilisation
  rather than insertion (9a66fe52d).
- The data plane starts when the host enables the controller rather than on Doorbell Buffer Config, so hosts that never send that command (SPDK, FreeBSD, Windows, older Linux) now work (04f04b86e).
- Failure to lock the backend memory is a warning instead of a fatal error (847864637).
- The media counters moved from the SMART log's temperature fields to vendor log page C0h (4cb1f9ba7).
- The register BAR is at least 16 KiB (01c79c442).
- Under FDP, forced GC keeps at least one reclaim unit free unless `gc_thres_pcent_high` is 100. Below 20 units the watermark rounded to none, and a pass that filled its destination part way had no unit to go on with (89f34939f).
- With `hot_cold_sep`, Streams, or a `hybrid` or `fast` mapping, forced GC keeps at least one line free. Below 20 lines, where the watermark used to round to zero, such a namespace can expose one line less (5a81d02cd).
- OC 1.2 Identify no longer advertises hybrid commands, and unsupported OC 1.2 block opcodes are rejected (f5fc7d573, 6b5081821).
- The `run-*.sh` launchers name QEMU's threads (`-name ...,debug-threads=on`), so `ps -T` and `top -H` show `femu-poller`, `FEMU-FTL-Thread` and `CPU N/KVM` (e29fe6ee2).

The shared namespace model behind `femu-subsys,ns_mgmt=on` is described in
[namespace management](features/ns-management-and-pi.md#shared-namespaces-in-detail).

### Fixes

#### Crashes, memory safety and teardown

- Fixed a memory leak and build errors from the previous release (b11ce9631, 1c2d358c1).
- Fixed ZNS plane allocation and the DSM buffer size (f863d7a8e, 805b9c8e6).
- Fixed a submission queue setup race and a poller use-after-free on controller reset or guest reboot (7100e6179, ac89117b2).
- Fixed priority queue heap repair, which affected FDP victim selection (e2d5413ff, 66067fabc, a4ed1d8c9).
- I/O past the device geometry is refused instead of accessing out of bounds (8848d724d).
- Widened bbssd and ZNS physical address fields so large channel, LUN and plane counts no longer alias (2e4c7fe82, d7c5aff58).
- Fixed an out-of-bounds write in ZNS zone reset with a narrow zone width, and ZNS backend addressing within a namespace (02a11cc51, 316ecf9df, cba095fb5).
- Fixed OCSSD writes past the backing store and many OCSSD bounds checks on vector lists, chunk info, bad block tables, offsets and addresses (fca17a8c6, f2ccb06ab, e8d415a07, 11aafda03, b37e7dd58, ff6e8bb4b, 58ba9f515, 98641558d, d44f0c4c1, 761f78757, 42ae8360e, 1f135b961, d5a5b788b, 91412b74d, 3838cf6bf, 1c9f737fe, 0d6d5926f).
- The FTL thread and pollers are stopped and every mode's state released on device removal, controller reset and failed realize (da76e206a, 06c7579b2, 81fa5697a, b3608d3f4, d0998ea16, 5a4107c14, 6610ecba1, f050a8bce, 3ba1ddec4, 42ba3cf4a, 817d34363, 36d1ef4b0, 52a579830, 8e8dc4431, 8c1fb192f, 0b7c53826, 9b0dd6eb0).
- Fixed leaks of aborted requests, DSM range lists, PRP lists and dropped command lists (03a4eee3c, f3fdbe7c0, 1c498adad, 10aaf11e2, c501af95e).
- A host address is no longer written into guest memory when setting up a non-contiguous queue, and Identify transfers the structure rather than a whole memory page (037d9c9c2, 14f4224d3).
- Queues with 64 KiB pages no longer crash QEMU, and queues are mapped by their length in bytes (cbebe5e10, 49880d0a0).
- Shadow doorbell values are bounds-checked as ring positions and the buffers are one page each (e082da2c1, b95d305b5, 33584d6b8).
- Controller DMA from device threads is restricted to directly reachable memory, which avoids a VM hang on data pointers into device registers (fbfe674c2, 60e4b2d5d).
- Report and log buffers are bounded and their lengths checked before transfer (608749b8d, 40656e5a1, 062bcdb02, 0ddcc33bd, 3106c1205).
- CSD program loads are bounded and confined to `csd_program_dir` (f1d5f3736).
- CSD programs run on `nr_cu` compute unit threads (`femu-csd-cu`) instead of the poller, so a long program no longer stalls I/O on every queue or the vCPU that sends a CSD admin command; a loaded program can no longer be reloaded in place while it runs, and deleting a queue or resetting the controller under a running program drops its result safely (4596ba498).
- Running out of lines refuses the write instead of aborting, and FDP reports device full instead of asserting or following a null reclaim unit (49ada8834, e1c4e9174, 59128ab66, e7913d89c, c0ae29cb4, cbda78bf6, 37b9b84f9, f05f128a9).
- Zone state is locked, reset zones are erased on the media thread, and asynchronous events are raised from the main loop (fe8e931e3, 5001ae15c, 89e1c4b04).
- FDP event rings are serialized and the written and uncorrectable bitmaps are updated atomically across pollers (645424c86, daaa6a3db).
- The BlackBox flip command applies to every namespace of the controller (3b7d88d63).
- `femu-cxl-ssd` no longer advertises that unmapped pages read as zeros (3c85bfd86).
- Many `femu-cxl-ssd` lifecycle, decoder and mapping fixes, including teardown while callers wait on invalidation, little-endian forwarding, and keeping stores when NAND has no page for write-back (9e0223c19, bb7e28722, 51c420143, d31c48d92, ec8b1ac7d, 02a872661, 4505cd9a7, 86ba15078, 842d4ff72, b322efb8f, 2d0c1404e).

#### Data correctness

- Compare reads the stored data instead of a zeroed buffer (7589ee012).
- FDP TRIM honours the requested LBA ranges instead of erasing the whole device (0cc20e897).
- Fixed FDP victim accounting, foreground GC under write pressure, the initial reclaim unit, and the FDP Events log offset (cee9670a5, 247151a16, f9fc94d4f, 438e485a1).
- bbssd maps blocks by their real size, so 4 KiB formats no longer share logical pages (bb63df5a3).
- Fixed ZNS zone append, Zone Append bounds, zone open on write, zone resource counts, multi-zone reset, and zone write caches keyed by zone (07acf491a, 27949b51f, 3fd4f34e6, 8129cfd16, 340522142, 99ce4fb2b, 9a3449362, 347a8a691).
- A ZNS write refused for its data pointer no longer moves the write pointer (6343c4d22).
- FDP Write Zeroes is placed by its own directive fields and counted in HBMW and MBMW, instead of reusing the placement of an earlier command (834abe2cb).
- Write Zeroes and deallocate address the backend per namespace, program the media where required, and drop buffered copies (f44ce6499, 9005cf952, 373de039b, 783131b7d, 22988e07b).
- The write buffer no longer resurrects deallocated pages and is bounded (d4d03f127, 0ee6d211b).
- A Format rebuilds per-block state (a79474e73, 7e7e36161).
- Writes clear the invalid status set by Write Uncorrectable (026eb0ef0).
- CSD and KV commands address the namespace they name, and each namespace gets its own mode state (a93de9d54, aa6a5a8f7, d2a770601, ce5ad913f).
- A KV command completes when its last NAND operation does: a Store that compacts no longer counts the compaction wait twice, and still pays for it when it then fails. The per-command index read is charged on a LUN chosen by the key's hash instead of always on the LUN at address 0, which had every KV command queue on one LUN (4ca11c2a0, 1e5385ae4).
- Vendor admin command 0xEE sets an Open-Channel controller's read, program, erase and channel times; it used to write fields nothing read. Other modes refuse it with Invalid Field (949d01eb9, cdbd5bb36).
- `namespace_sizes` may add up to all of `devsz_mb` when the namespace count does not divide it, and each size is rounded down to whole logical blocks, so TNVMCAP counts only addressable capacity (d8cdd4d22).
- A CSD controller in an FDP subsystem refuses the same knobs as a BlackBox one and reports the superblock as its reclaim unit size, instead of 96 MiB (207bb12d4).
- bbssd GC no longer erases a line it could not empty, which left mappings pointing at erased pages and made every later write fail. Forced GC runs before every page a command programs, so a large write on a device with fewer than 20 lines no longer runs it out of space (5a81d02cd).
- FDP GC moves all of a reclaim unit's pages before erasing any block, retires each moved page's old copy, and runs foreground GC per page. A pass that stopped part way used to leave the unit with erased blocks counted again later (c7b373186).
- FDP GC takes a new unit for a collection destination that was dropped when it filled with nothing free, and collects a unit with no valid pages without one. GC used to stop for good once the destination was gone, so a full device stayed full even after the host deallocated everything (22a0fc5ee).
- An FDP handle whose last unit filled with nothing free reports no room in RUH Status. It used to report the room of its retired unit, which GC could free and give to another handle (4e7a06666).
- The `random` and `d-choice` GC policies and FDP's random reclaim strategy draw victims from a generator seeded by the new `gc_seed` property instead of the wall clock and `rand()`, so the same configuration and workload give the same victims and WAF on every run. `fifo` finds its victim at the top of a queue ordered by close order instead of scanning every line, with the same victims as before (04ba1c0aa).
- FDP background GC counts the pages a unit never wrote as reclaimable. A unit that RUH Update retired holding a few valid pages had none invalid, so each background pass took it from the top of the victim queue, refused it and stopped; units behind it were collected only under the foreground watermark (beb9878ac).
- FDP cost-benefit GC ages a unit retired with no page invalidated from its retirement. It used to count from time zero, so a part-written unit left by RUH Update outscored every other victim; with few pages to free, background GC refused it on every pass and collected nothing. (a9e0e1af6)
- FDP cost-benefit GC measures a unit's utilization against all its pages at every invalidation, as it already did at retirement. The first overwrite in a part-written unit used to measure it against the pages written only, so a unit holding 3 valid pages of 16 scored as 3 of 4 full and lost to units that cost more to collect. (529d70960)
- FDP background cost-benefit GC takes the best-scoring unit with enough to free. A unit with one invalid page and an old invalidation could outscore every other victim; the pass refused it and collected nothing until the others aged past it or the foreground watermark was reached.

#### Spec conformance and host compatibility

- Commands complete on the completion queue they were bound to, and submission queues that share a completion queue are served (7a3f1d9fa, dc4289f91).
- Completions are not posted into a full queue and the phase tag is written last (6f998742f, 04ce8b1a7).
- I/O interrupts are delivered without a KVM route, and pin interrupts work with shadow doorbells (8ebffbaa4, 34621540e, 4ca1be945).
- Create SQ/CQ reject out-of-range queue IDs and invalid interrupt vectors, and return the specified statuses (b3bbaedb0, 7580dd341, edefcd7c5).
- Fixed controller configuration and admin queue registers, feature reset on controller reset, and the fatal status cleared on disable (330ed2aab, f2ea41361, ab63717c5).
- Get Log Page reads its identifier and offset correctly and serves every log from the requested offset (a6b0d5897, ef8b755ee, 23fc538ea).
- Feature identifier, selector and save bit are decoded, and namespace-scoped features take a namespace (2380e4ecc, 1729244c2).
- Identify reports total NVM capacity and the fields a host relies on (907ad6ff1, 8530bc287).
- Fixed the error and SMART logs, the log directories, Format secure erase decoding, data pointer and transfer size statuses, and bad doorbell reporting (325e02cfd, c52d9ff9c, adfc12e93, bdb6f6b59, 225c6bdee).
- Fixed the AER count, Zone Append limit, KV MDTS and vector masking (7b5dbbc77).
- A failed data transfer is reported as an error, PRP lists starting inside a page are followed, and SGL errors use their own status codes (29175cb05, ecbef8416, c9344bd4c, e310fdb43).
- The Changed Zone List reports only unsolicited changes, ZNS follows the zone resource, compare and notice rules, and commands that rewrite a zone behind its back are refused (7a6f01f8a, 41a6c189f, 99d2194e0, ed38b0728).
- A reset zone holds no data, an offline zone returns its resources, and zone geometry is reported for the namespace's format (bce5e1c3e, 2c7062ed0, 901d0908f, b4d9585ca, f0f989c21).
- KV list entries are padded to 4 bytes, NVM-only commands are refused on KV namespaces, and KV Identify requires a KV namespace (240e21c43, f5a7d7bc8, 5ec9ee859).
- FDP reports the reclaim unit size the FTL uses and moves a handle to a new reclaim unit on update (7fe32c556, 78de60448).
- The FDP Reclaim Unit Handle Usage log uses 8 byte descriptors, so `nvme fdp usage` reports every handle as host specified instead of reading some as unused, and the placement logs store their fields little endian (ca844c994, a85b869fc).
- With `namespace_modes`, the controller's model number and serial come from its own `femu_mode` instead of the namespace brought up last (efdb98643, c3f968029).
- SMART wear counters are summed across namespaces (4a4f0d9bf).
- Counters fixed to move in every mode: FDP and KV write amplification and bytes, KV relocations, FDP erases (f4b3ac376, 980fb7886, 37464e4bd, ce20d8c06, 4c7d9c22a, 749e09fef, 2a16553c9, ba0c49338).
- OC 1.2 enforces its bad block table: a write or erase that names a factory bad, grown bad or device reserved block fails with Write Fault. Set Bad Block Table marks the plane it is given instead of another block's plane, and keeps the table's counts current (933addb72).
- Abort no longer rewrites the aborted command in the host's submission queue: the controller marks it and completes it with Command Abort Requested when fetched. An Abort run with more than `acl` others queued behind it fails with Abort Command Limit Exceeded (7b7eaf133).
- Logs 12h (Feature Identifiers Supported and Effects) and 13h (NVMe-MI Commands Supported and Effects) are answered and listed in log 00h. A feature that needs something absent, such as Volatile Write Cache without `vwc=1`, is an invalid field for every selector (7b36b4c25).
- Enabling with a CC.CSS value that CAP.CSS does not offer fails the controller, and admin commands that name SGLs are refused (992dc9911, 2ff5e3925).
- Every Unrecovered Read Error and Compare Failure sets Do Not Retry (f8efff85a).
- Identify reports one read-only firmware slot, matching the firmware log (989df3cea).
- OACS, ONCS, OCFS, LPA, SANICAP and logs 00h and 05h are built from one capability registry, and a qtest checks them against what every mode answers (a1c67d97f, 933fb3f15).
- Log 05h lists each mode's own commands (BBSSD 0xEF, the Open-Channel and CSD commands, Flush on KV namespaces) and no longer lists Read and Write for Open-Channel 1.2, which refuses them (99eabe2c1).
- Log 00h lists the Open-Channel 2.0 chunk information page (CAh) (209b499b6).
- Get Log Page answers a page log 00h lists for no command set with Invalid Log Page, so the endurance group and FDP pages without a subsystem no longer answer Invalid Field (87d5f1372).
- A zoned namespace reports no Copy limits in Identify Namespace, since it refuses Copy (92b3763a3).
- The controller reports NVMe 2.1 instead of 1.4, with what that requires: CAP.CRMS and the CRTO register, BPCAP 01b, Identify CNS 1Fh, CNS 00h refused for a Key Value namespace (Invalid I/O Command Set), CSI-specific log pages refused for an unknown command set, and CNS 07h refused for a set CC.CSS does not enable. Open-Channel stays at 1.4 (409db7bb3).
- CAP.AMS no longer claims weighted round robin, which nothing arbitrated by, and enabling with another CC.AMS fails (409db7bb3).
- A controller in a subsystem reports its endurance group (CTRATT bit 4, ENDGIDMAX, each namespace's ENDGID, the Key Value Identify structure included) whether or not FDP is on, as log 09h already did (409db7bb3).

### Documentation and tooling

- Documentation moved under `hw/femu/docs/` with getting-started, concepts, mode and feature guides, an FAQ, security notes and a doc map (e00c70f99, 034670c4c, 62a565ae0, fb1cf3ce6, 28aa224b7, 0bcb5cae2).
- CXL SSD, caching API and NVMe link guides, and a reference for every `femu-cxl-ssd` property and counter (41b318ef2, 9ec16a701, 93bfbf5c9, ccaa5d190, dcea2b9a8).
- A property reference generated from the binary and checked in CI, with every device property described in its help text (a6118d051, 9489cf692, 37aaccf27, c2a12a2eb).
- The mode table is generated from `modes.py`, and every documented command line is tested (6a97f8755, 12361d7f7, 573da0a1b).
- Refusals and behaviour changes that affect existing command lines are listed (9e93cb94f); that list is now part of this changelog.
- The `vwc` description no longer claims `vwc=0` makes Flush a no-op: Flush drains the bbssd write buffer either way (f48a6bc6f).
- Documentation of the SMART vendor area, vendor log page, endurance rating, mapping schemes, GC and cache options (4e1f5bce5, 77fa23981, 9f52a098d, 658e4c9e6).
- README refreshed: build hosts for the QEMU 10.1 base, binary path, guest image steps, namespace and plane limits, debugging switches, and links to the new docs (4f327242c, a967b15fa, 4dbeea46d, b5c68a96f, f2d9dee99, b2ae45483, 65332b21a, 10f30e231).
- Added CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, CITATION.cff and ROADMAP files (599a36676, da692f5d9).
- `ssd-config.sh` expands an INI-style config file into the device arguments, checking keys against the binary (7f605016e).
- `femu-test.sh` checks a device from inside the guest for block, zoned, KV and CSD namespaces (9fee8190c, 2244a1b9c, c17a31ea9).
- `make-guest-image.sh` builds an Ubuntu 24.04 guest image, and the run scripts accept `IMGDIR`, `OSIMGF` and another SSH port (e877f2dc0, e74535012, 66bb3068e).
- The build script fails on a compile error, and the config self-test fails when FEMU does not survive (a1bf37caf, da7c1fcfe).
- The config self-test requires each device to come up, not only its property names to be accepted. That caught `zns.conf`, which asked for more active zones than it has and was refused at every size (b509a23a5).
- Config presets for OCSSD, CSD, KV and NoSSD (NoSSD with link and firmware time from the NVMeCHA controller), and a `run-kvssd.sh` launcher (04eb9b06d).
- A key-value probe tool and a corrected KV wire format description (9ab75f5dc).
- `pin.sh` no longer names a CPU past the last one, and now pins the pollers, the FTL thread and the CXL SSD's `femu-cxl-ftl` and `femu-cxl-cca` threads as well as the vCPUs (e29fe6ee2, 56e0e2f27).
- Every launcher, the legacy scripts and `make-guest-image.sh` name QEMU's threads with `debug-threads=on` (e29fe6ee2, 56e0e2f27).
- The documentation example check realizes the guest's disks and NICs too, with stand-in backends, so a device the machine cannot plug (a NIC without `bus=pcie.0` on a `cxl=on` machine) fails the check (ac5a152fe).
- `kv-probe.c` comments describe what it checks and which device nodes it can use (dfc1bd606).
- GitHub Actions CI on several Ubuntu releases, with pinned actions, a read-only token, sanitizer builds, link checks and steps that can actually fail (3b4708763, daf890b7f, c613ae5ac, 4164e551b, 8d4762608, 89ff3ed38, e3700422c).
- qtests and unit tests for FEMU now live under `hw/femu/tests/`, including a NAND media unit test run by meson and FTL checks turned on in CI (d72e30a34, 6549d6094, cc926e1e9, 8241ccc7f).
- Seeded fuzzers for admin, I/O, zoned, FDP, KV, Open-Channel 2.0 and CSD commands, run on sanitizer builds in CI (8a57a3e27, 6d6d927d0, 9798a6574, dff3d9f72, 28eaf2afa, 2dbb18a82, 243fc0b66, 2f1208402, 692d9a106).

### Removed or legacy

- `femu_mode=6` (an unimplemented SmartSSD placeholder) is no longer accepted (c3b8e88ef).
- QEMU network block drivers are no longer built (81c4385fc).
- Three NAND media policy flags that nothing read were dropped (2e29d7efb).
- OC 1.2 no longer advertises hybrid commands it does not implement (f5fc7d573).

