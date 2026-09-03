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
| `mpsmax` vs `mpsmin` | The test was inverted, so `mpsmax=1` was rejected and `mpsmin=1,mpsmax=0` accepted, advertising CAP.MPSMIN above CAP.MPSMAX. |
| `meta` non-zero | LBA metadata is not implemented; every read and write failed at runtime. |
| `cell_pages` above 5 | Indexed past the page-type multiplier table. |
| `nand_cell_type` with `pgs_per_blk` above 512 | Read past the page-type latency tables. |
| `gc_strategy` outside {0,1,2,4} | Other values silently fell back to greedy or never collected at all. |
| `zns_flash_type` 0, 6 or above, or MLC/PLC without explicit latencies | 0 gives a zero-length write cache and an endless flush loop; 6+ indexes past the timing tables; MLC and PLC have no built-in figures, so every NAND operation cost nothing. |
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
- Temperature threshold Set Features accepts only TMPSEL 0 and Fh; other
  selectors are rejected rather than stored as part of the value.
- An aborted command completes as Command Abort Requested rather than Invalid
  Opcode.
- FDP RUAMW counts down in LBAs, so it drains at the documented rate and
  reaches zero; cost-benefit victim selection now orders by age and utilisation
  rather than insertion.
