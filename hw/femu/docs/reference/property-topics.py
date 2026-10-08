# SPDX-License-Identifier: GPL-2.0-or-later
#
# Input to hw/femu/scripts/gen-property-docs.py.
#
# Each FEMU-defined property belongs to exactly one topic, and 'runtime'
# topics go to runtime-properties.md. Descriptions live in the code
# (hw/femu/femu-props.c, hw/femu/cxlssd/props.c), so `-device <type>,help`
# prints them; only properties inherited from a QEMU parent type, whose
# help text FEMU does not own, are described here. test_only lists the
# properties that exist only under qtest; --check fails if any list here
# disagrees with the binary.

DEVICES = [
    {
        "type": "femu",
        "title": "NVMe controller",
        "parent": "pci-device",
        "test_only": ["x-ftl-check", "x-ftl-trace", "x-ns-test", "x-oc12-clock",
                      "x-oc12-trace", "x-query-delay-ms", "x-stream-test"],
        "topics": [
            {
                "title": "Mode, capacity and namespaces",
                "kind": "static",
                "props": [
                    "femu_mode", "devsz_mb", "namespaces", "namespace_sizes",
                    "namespace_modes", "op_pcent", "subsys", "cxl_ssd",
                    "pel_file", "serial",
                ],
            },
            {
                "title": "Queues, pollers and interrupts",
                "kind": "static",
                "props": [
                    "queues", "entries", "max_sqes", "max_cqes", "stride",
                    "multipoller_enabled", "poller_ratio", "hiops_inline",
                    "aerl", "elpe", "mdts", "intc", "intc_thresh", "intc_time",
                ],
            },
            {
                "title": "Controller identity and capabilities",
                "kind": "static",
                "props": [
                    "vid", "did", "acl", "cqr", "vwc", "temperature", "mpsmin",
                    "mpsmax", "oacs", "oncs", "sgl", "cmbsz", "cmbloc",
                ],
            },
            {
                "title": "LBA formats, metadata and protection",
                "kind": "static",
                "props": [
                    "nlbaf", "lba_index", "extended", "meta", "mc", "pi",
                    "dpc", "dps", "ms", "ms_max", "dlfeat",
                ],
            },
            {
                "title": "Namespace management, streams and power loss",
                "kind": "static",
                "props": [
                    "ns_mgmt", "bbssd_ns_limit", "streams", "streams.max",
                    "power_loss",
                ],
            },
            {
                "title": "NAND geometry (bbssd, CSD, KV)",
                "kind": "static",
                "props": [
                    "secsz", "secs_per_pg", "pgs_per_blk", "blks_per_pl",
                    "pls_per_lun", "luns_per_ch", "nchs",
                ],
            },
            {
                "title": "NAND timing (bbssd, CSD, KV)",
                "kind": "static",
                "props": [
                    "pg_rd_lat", "pg_wr_lat", "blk_er_lat", "ch_xfer_lat",
                    "cmd_addr_lat", "pg_xfer_lat", "status_lat", "tplpbsy",
                    "tplrbsy", "tplebsy", "mp_program", "mp_read",
                    "trcbsy", "trim_lat_ns",
                    "pe_suspend", "tsusp_ns", "nand_cell_type", "cell_pages",
                    "pgtype_lat",
                ],
            },
            {
                "title": "Reliability and wear",
                "kind": "static",
                "props": [
                    "ecc_step_ns", "ecc_retention_sec", "pe_cycles_rated",
                    "nand_bad_blocks", "blk_pe_limit", "blk_pe_spread",
                    "blk_pe_seed", "spare_lines", "err_read_unc_ppm",
                    "err_write_fail_ppm", "read_reclaim_limit",
                    "retention_limit_sec", "age_scale",
                ],
            },
            {
                "title": "Garbage collection, mapping and caches",
                "kind": "static",
                "props": [
                    "gc_thres_pcent", "gc_thres_pcent_high", "gc_policy",
                    "gc_seed", "gc_strategy", "mapping", "mapping_cache_mb",
                    "read_cache_mb", "cache_evict", "hot_cold_sep",
                    "buffer_size", "buffer_thres_pcent", "fdp_trim_erase_all",
                    "debug_ftl",
                ],
            },
            {
                "title": "Host link and controller firmware",
                "kind": "static",
                "props": [
                    "pcie_bandwidth_mbps", "pcie_prop_delay_ns", "fw_cpu_ns",
                ],
            },
            {
                "title": "ZNS",
                "kind": "static",
                "props": [
                    "zns_num_ch", "zns_num_lun", "zns_num_plane",
                    "zns_num_blk", "zns_flash_type", "zns_pg_rd_lat",
                    "zns_pg_wr_lat", "zns_blk_er_lat", "zns_cmd_addr_lat",
                    "zns_pg_xfer_lat", "zns_status_lat", "zns_pe_suspend",
                    "zns_tsusp_ns", "zns_max_active", "zns_max_open",
                    "zns_num_wc", "zns_zd_ext_size", "zns_num_conv_zones",
                    "zns_zone_cap", "zns_chnls_per_zone", "zns_zrwa_size",
                    "zns_zrwafg_size", "zns_zrwa_num", "zns_cross_zone_read",
                    "zns_zasl_bs",
                ],
            },
            {
                "title": "OCSSD (Open-Channel)",
                "kind": "static",
                "props": [
                    "lver", "flash_type", "oc12_channel_timing", "lsec_size",
                    "lsecs_per_pg", "lpgs_per_blk", "lmax_sec_per_rq",
                    "lnum_ch", "lnum_lun", "lnum_pln", "lmetasize",
                    "learly_reset",
                ],
            },
            {
                "title": "CSD (computational storage)",
                "kind": "static",
                "props": [
                    "fdm_size", "nr_cu", "nr_thread", "time_slice",
                    "context_switch_time", "csf_runtime_scale",
                    "csd_program_dir",
                ],
            },
            {
                "title": "Power loss trigger",
                "kind": "runtime",
                "props": [
                    "simulate-power-loss",
                ],
            },
        ],
    },
    {
        "type": "femu-subsys",
        "title": "NVMe subsystem",
        "parent": "device",
        "test_only": [],
        "topics": [
            {
                "title": "Shared namespaces",
                "kind": "static",
                "props": [
                    "ns_mgmt", "nqn",
                ],
            },
            {
                "title": "Flexible Data Placement",
                "kind": "static",
                "props": [
                    "fdp", "fdp.runs", "fdp.nrg", "fdp.nruh", "fdp.nru",
                    "fdp.isolation_mode",
                ],
            },
        ],
    },
    {
        "type": "femu-cxl-ssd",
        "title": "CXL Type-3 SSD",
        "parent": "pci-device",
        "inherits_from": "cxl-type3",
        "test_only": ["test-change-dpa", "test-fault", "test-fault-decode",
                      "test-fault-fill", "test-fill",
                      "test-fill-race", "test-map", "test-media-disabled",
                      "test-owner", "test-rip",
                      "test-prefetch-race",
                      "test-prefetch-race-end", "test-protect",
                      "test-protect-window",
                      "test-slot-reservation", "test-unprotect",
                      "test-revoke-ahead", "test-revoke-ahead-keep",
                      "test-storm", "test-storm-wait", "test-storm-served",
                      "test-storm-stops", "test-storm-ns"],
        "topics": [
            {
                "title": "Cache",
                "kind": "static",
                "props": [
                    "cache-pages", "cache-policy",
                ],
            },
            {
                "title": "NAND geometry and timing",
                "kind": "static",
                "props": [
                    "ftl", "channels", "luns-per-channel", "pages-per-block",
                    "blocks-per-plane", "gc-threshold", "gc-threshold-high",
                    "read-ns", "program-ns", "erase-ns", "channel-ns",
                    "cylon-first-touch-program", "cylon-free-writeback",
                ],
            },
            {
                "title": "Direct mapping (DER)",
                "kind": "static",
                "props": [
                    "der", "der-replace-rate", "cylon-kernel-ack",
                    "cylon-emul-exit", "cylon-never-emulate",
                    "cylon-revoke-batch", "concurrent-misses",
                ],
            },
            {
                "title": "Caching API, control channel and logs",
                "kind": "static",
                "props": [
                    "cca", "lsa-control", "log-dir", "tracefs-dir",
                    "log-limit",
                ],
            },
            {
                "title": "Cache tunables (also accepted on -device)",
                "kind": "runtime",
                "props": [
                    "cache-ways", "prefetch-degree", "prefetch-stride",
                ],
            },
            {
                "title": "Actions and control",
                "kind": "runtime",
                "props": [
                    "der-ratio", "control-command", "control-argument",
                    "control-status", "flush-cache", "stats-reset",
                    "fast-load", "fast-load-drain-ns",
                ],
            },
            {
                "title": "Cache counters",
                "kind": "runtime",
                "props": [
                    "cache-entries", "cache-hits", "cache-misses", "read-hits",
                    "read-misses", "write-hits", "write-misses",
                    "cache-inserts", "cache-evictions", "prefetch-inserts",
                ],
            },
            {
                "title": "Snapshot counters",
                "kind": "runtime",
                "props": [
                    "last-read-hits", "last-read-misses", "last-write-hits",
                    "last-write-misses", "last-inserts", "last-evictions",
                    "last-entries", "last-prefetch-inserts",
                ],
            },
            {
                "title": "Media counters",
                "kind": "runtime",
                "props": [
                    "media-time-ns", "media-reads", "media-writes",
                    "media-full", "gc-stalls", "gc-stall-ns",
                ],
            },
            {
                "title": "Direct mapping counters",
                "kind": "runtime",
                "props": [
                    "der-active", "der-probes", "der-mapped", "der-remaps",
                    "der-revocations", "der-quiet-revocations",
                    "der-replacements", "der-fallbacks", "der-emul-exit",
                    "der-emul-v2", "der-fault-reads", "der-fault-writes",
                    "der-fault-fetches", "der-fault-page-walks",
                    "der-fault-emulated", "der-fault-unprotected",
                    "der-fault-conflicts", "der-fault-overflows",
                    "der-revoke-flushes", "der-revoked-ahead",
                    "der-ahead-remaps", "der-fault-bql", "der-emul-fills",
                    "der-emul-fetch-fills",
                    "der-emul-failures",
                ],
            },
            {
                "title": "Caching API counters",
                "kind": "runtime",
                "props": [
                    "cca-commands", "cca-errors", "cca-pinned", "cca-uncached",
                    "cca-pin-fills", "cca-writebacks", "cca-dropped",
                    "cca-pinned-set-misses",
                ],
            },
            {
                "title": "Other counters",
                "kind": "runtime",
                "props": [
                    "invalidations", "nvme-drops", "log-dropped",
                ],
            },
        ],
        "inherited": {
            "cdat": (
                "Host file holding the CDAT table returned over DOE; unset "
                "builds a table from the backends; femu-cxl-ssd leaves it "
                "unchanged"
            ),
            "lsa": (
                "Label storage area backend served by Get and Set LSA; "
                "femu-cxl-ssd accepts it only with lsa-control=off"
            ),
            "memdev": (
                "Legacy persistent memory backend of cxl-type3; femu-cxl-ssd "
                "refuses it at realize"
            ),
            "num-dc-regions": (
                "Number of dynamic capacity regions; femu-cxl-ssd requires it "
                "to stay 0"
            ),
            "persistent-memdev": (
                "Persistent memory backend of cxl-type3; femu-cxl-ssd refuses "
                "it at realize"
            ),
            "sn": (
                "PCIe Device Serial Number; the default (2^64 - 1) means "
                "unset, which gives no serial number capability; femu-cxl-ssd "
                "leaves it unchanged"
            ),
            "volatile-dc-memdev": (
                "Dynamic capacity memory backend; femu-cxl-ssd refuses it at "
                "realize"
            ),
            "volatile-memdev": (
                "Required: ID of the host memory backend that holds the "
                "device data, a non-zero multiple of 256 MiB, at most 120 "
                "GiB; der=cylon needs a hugetlbfs file backend with share=on "
                "and prealloc=on, or direct mapping falls back to MMIO with a "
                "warning"
            ),
            "x-speed": (
                "PCIe link speed the device reports; femu-cxl-ssd leaves it "
                "unchanged and its timing does not depend on it"
            ),
            "x-width": (
                "PCIe link width the device reports; femu-cxl-ssd leaves it "
                "unchanged and its timing does not depend on it"
            ),
        },
    },
]
