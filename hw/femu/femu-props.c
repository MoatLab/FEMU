/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Property help text for the femu and femu-subsys devices.
 *
 * Mode names follow femu_mode: OCSSD (0), bbssd (1, black box), NoSSD (2),
 * ZNS (3), CSD (4) and KV (5). CSD builds the bbssd FTL, so the bbssd
 * geometry, timing and FTL properties apply to it; KV uses only the bbssd
 * geometry and NAND timing and runs its own placement and reclaim.
 */
#include "qemu/osdep.h"
#include "femu-props.h"

void femu_describe_class(ObjectClass *oc, const FemuPropDesc *descs)
{
    for (; descs->name; descs++) {
        g_assert(object_class_property_find(oc, descs->name));
        object_class_property_set_description(oc, descs->name, descs->desc);
    }
}

void femu_describe_object(Object *obj, const FemuPropDesc *descs)
{
    for (; descs->name; descs++) {
        g_assert(object_property_find(obj, descs->name));
        object_property_set_description(obj, descs->name, descs->desc);
    }
}

static const FemuPropDesc femu_subsys_descs[] = {
    { "ns_mgmt",
      "Keep one namespace table and one backend in the subsystem, shared by "
      "every controller that names it with subsys=; NoSSD and bbssd "
      "controllers only, and not with fdp" },
    { "nqn",
      "Subsystem name reported as nqn.2019-08.org.qemu:<nqn> by controllers "
      "that share namespaces through this subsystem; unset uses the device "
      "id" },
    { "fdp",
      "Enable Flexible Data Placement in endurance group 1 for controllers "
      "that join this subsystem; only bbssd places data by reclaim unit" },
    { "fdp.runs",
      "Reclaim unit size in bytes; 0 means 96 MiB, and a bbssd controller "
      "accepts only 0 or the size of one superblock, which it then uses" },
    { "fdp.nrg",
      "Number of FDP reclaim groups; must be 1, placement into other groups "
      "is not implemented" },
    { "fdp.nruh",
      "Number of FDP reclaim unit handles (placement handles), from 1 to "
      "fdp.nru; must be set when fdp=on" },
    { "fdp.nru",
      "Number of reclaim units in each reclaim group, from fdp.nruh to "
      "65536; bbssd uses at most one per superblock and needs at least 2 "
      "* fdp.nruh + 1 of them" },
    { "fdp.isolation_mode",
      "0 makes every reclaim unit handle Persistently Isolated; any other "
      "value makes the last handle Initially Isolated" },
    { NULL, NULL }
};

static const FemuPropDesc femu_ctrl_descs[] = {
    /* mode, capacity and namespaces */
    { "femu_mode",
      "Emulated SSD type: 0 OCSSD (Open-Channel), 1 bbssd (black-box "
      "FTL), 2 NoSSD (no media timing), 3 ZNS, 4 CSD (computational), 5 "
      "KV; other values fail realize" },
    { "devsz_mb",
      "Size of the host memory backend in MiB, split across namespaces "
      "unless namespace_sizes is set; bbssd with op_pcent sizes from the "
      "NAND geometry instead" },
    { "namespaces",
      "Number of namespaces created at boot, 1 to 256; OCSSD and FDP "
      "support only 1" },
    { "namespace_sizes",
      "Comma-separated size in bytes of each namespace (QEMU size syntax "
      "such as 4G,2G), one non-empty entry per namespace, summing to at most "
      "the backend; unset splits the backend evenly" },
    { "namespace_modes",
      "Comma-separated mode of each namespace from nossd, bbssd, znssd, "
      "ocssd, csd and kvssd, one entry per namespace; unset gives every "
      "namespace femu_mode" },
    { "op_pcent",
      "Over-provisioning in percent for bbssd: back the device with the "
      "full NAND capacity and expose capacity/(1 + op_pcent/100); 0 keeps "
      "devsz_mb sizing, not with cxl_ssd" },
    { "serial",
      "No effect, kept for compatibility; Identify Controller reports a "
      "serial number FEMU generates. Setting it warns at realize" },
    { "pel_file",
      "Host file that keeps the Persistent Event Log and power cycle count "
      "across runs, created if missing; a corrupt or incompatible file "
      "fails realize" },
    { "subsys",
      "ID of a femu-subsys device to join, created before this controller; "
      "needed for FDP, shared namespaces and the Endurance Group log" },
    { "cxl_ssd",
      "ID of a femu-cxl-ssd, listed before this controller, whose memory "
      "and FTL this bbssd controller serves as its one namespace" },

    /* queues, pollers and interrupts */
    { "queues",
      "Number of I/O submission and completion queue pairs, 1 to 2047; "
      "MSI-X vectors are queues + 1" },
    { "entries",
      "Value reported as CAP.MQES (0's based), 1 to 65534; the controller "
      "accepts queues of up to entries + 1 entries" },
    { "max_sqes",
      "Submission queue entry size as a power of two (Identify SQES); "
      "must be 6, 64-byte entries" },
    { "max_cqes",
      "Completion queue entry size as a power of two (Identify CQES); "
      "must be 4, 16-byte entries" },
    { "stride",
      "Doorbell stride (CAP.DSTRD): doorbells are 4 << stride bytes apart, "
      "0 to 12" },
    { "multipoller_enabled",
      "0 runs one poller thread for all I/O queues; 1 runs ceil(queues / "
      "poller_ratio) pollers, each owning a round-robin share of the "
      "queues; other values fail realize" },
    { "poller_ratio",
      "I/O queues per poller thread when multipoller_enabled=1; 0 is "
      "treated as 1, one poller per queue" },
    { "hiops_inline",
      "NoSSD only: performance option, on by default; set off only when "
      "debugging" },
    { "aerl",
      "Asynchronous Event Request Limit (Identify AERL, 0's based): the "
      "controller holds up to aerl + 1 outstanding requests" },
    { "elpe",
      "Error Log Page Entries (Identify ELPE, 0's based): the Error "
      "Information log keeps the newest elpe + 1 entries" },
    { "mdts",
      "Maximum Data Transfer Size as a power of two of the minimum memory "
      "page size (2^(12 + mpsmin + mdts) bytes); 0 means no limit" },
    { "intc",
      "Initial Coalescing Disable bit (0 or 1) of the Interrupt Vector "
      "Configuration feature; the value is reported, interrupts are not "
      "coalesced" },
    { "intc_thresh",
      "Initial aggregation threshold of the Interrupt Coalescing feature; "
      "the value is reported, interrupts are not coalesced" },
    { "intc_time",
      "Initial aggregation time, in 100 microsecond units, of the Interrupt "
      "Coalescing feature; the value is reported, interrupts are not "
      "coalesced" },

    /* controller identity and capabilities */
    { "vid",
      "PCI vendor ID, also reported as the Identify Controller PCI Vendor "
      "ID" },
    { "did",
      "PCI device ID of the controller function" },
    { "acl",
      "Abort Command Limit reported in Identify Controller (0's based); "
      "it does not change how Abort is handled" },
    { "cqr",
      "CAP.CQR: 1 requires physically contiguous queues, 0 allows "
      "PRP-list queues" },
    { "vwc",
      "1 advertises a volatile write cache: Flush then drains the bbssd "
      "write buffer and the host can turn the buffer off with feature "
      "06h; 0 makes Flush a no-op and refuses feature 06h; 0 or 1" },
    { "temperature",
      "Composite temperature in kelvin reported by the SMART log and "
      "compared with the temperature threshold feature; default 323 (50 C)" },
    { "mpsmin",
      "CAP.MPSMIN: smallest host memory page size as 2^(12 + mpsmin) bytes; "
      "must not exceed mpsmax" },
    { "mpsmax",
      "CAP.MPSMAX: largest host memory page size as 2^(12 + mpsmax) bytes, "
      "from mpsmin to 15" },
    { "oacs",
      "Optional Admin Command Support; only bit 1 (Format NVM, 0x2) may be "
      "set, and clearing it refuses Format NVM" },
    { "oncs",
      "Optional NVM Command Support bit mask: 0x1 Compare, 0x2 Write "
      "Uncorrectable, 0x4 Dataset Management, 0x8 Write Zeroes, 0x10 "
      "Save/Select, 0x80 Verify, 0x100 Copy; Timestamp is always added" },
    { "sgl",
      "Advertise and accept address scatter gather lists for data transfer; "
      "OCSSD ignores it" },
    { "cmbsz",
      "Controller Memory Buffer size register; 0 means no buffer, otherwise "
      "the size field times the unit must be a non-zero power of two" },
    { "cmbloc",
      "Controller Memory Buffer location register; its BAR field must be 2 "
      "when cmbsz is set" },

    /* namespace format and metadata */
    { "nlbaf",
      "Number of LBA formats, 1 to 16 (at most 8 with meta): 512-byte "
      "blocks doubling with each format" },
    { "lba_index",
      "LBA format the namespaces boot with, below nlbaf; ZNS needs a block "
      "size of 4 KiB or less" },
    { "extended",
      "1 boots with metadata interleaved with the data (extended LBAs); "
      "needs bit 0 of mc; 0 or 1" },
    { "meta",
      "Metadata bytes per logical block, NoSSD and bbssd only, not with FDP, "
      "dpc or dps; each format is then also offered with metadata" },
    { "mc",
      "Metadata Capabilities bit mask: bit 0 interleaved (extended LBAs), "
      "bit 1 separate buffer; required when meta is set" },
    { "pi",
      "Offer end-to-end protection information types 1 to 3 when meta is at "
      "least 8 bytes and allow Format and Create to select them; not with "
      "power_loss or cxl_ssd" },
    { "dpc",
      "Data Protection Capabilities reported in Identify Namespace when pi "
      "is off; must be 0 with meta" },
    { "dps",
      "Data Protection Type Settings reported in Identify Namespace; a "
      "non-zero value needs 8 bytes of metadata, which meta refuses, so "
      "leave it 0 and use pi" },
    { "ms",
      "No effect, kept for compatibility; meta sets the metadata size. A "
      "value other than the default warns at realize" },
    { "ms_max",
      "No effect, kept for compatibility; OCSSD 2.0 reports a single LBA "
      "format. A value other than the default warns at realize" },
    { "dlfeat",
      "No effect, kept for compatibility; Identify Namespace always reports "
      "DLFEAT 0x9 (deallocated blocks read as zeroes). A value other than "
      "the default warns at realize" },

    /* namespace management, streams and power loss */
    { "ns_mgmt",
      "Enable Namespace Management and Attachment on a standalone NoSSD "
      "or bbssd controller whose namespaces all run femu_mode with dps 0, "
      "otherwise it stays off without an error; with a shared subsystem "
      "use femu-subsys ns_mgmt" },
    { "bbssd_ns_limit",
      "Most bbssd namespaces that may be allocated with ns_mgmt, including "
      "detached ones, 1 to 256 and at least namespaces; each has its own "
      "FTL" },
    { "streams",
      "Enable the Streams directive; bbssd separates streams per FTL page "
      "(SWS) and needs page or dftl mapping, NoSSD has no placement "
      "effect; not with FDP or a shared subsystem" },
    { "streams.max",
      "Number of stream slots with streams=on, 1 to 32; bbssd reserves "
      "streams.max + 1 lines for them" },
    { "power_loss",
      "bbssd: roll back writes still in the write buffer on a simulated "
      "power cut and enable simulate-power-loss; needs buffer_size > 0, "
      "vwc=1, page-aligned namespaces, and no meta, pi, ns_mgmt, subsys, "
      "namespace_modes or cxl_ssd" },

    /* geometry: bbssd, CSD and KV */
    { "secsz",
      "bbssd, CSD, KV: sector size in bytes, greater than 0" },
    { "secs_per_pg",
      "bbssd, CSD, KV: sectors per NAND page, 1 to 256" },
    { "pgs_per_blk",
      "bbssd, CSD, KV: pages per NAND block, 1 to 65536, at most 512 with "
      "nand_cell_type" },
    { "blks_per_pl",
      "bbssd, CSD, KV: blocks per plane, 1 to 65536; also the number of "
      "lines (superblocks)" },
    { "pls_per_lun",
      "bbssd, CSD, KV: planes per LUN, 1 to 16" },
    { "luns_per_ch",
      "bbssd, CSD, KV: LUNs (dies) per channel, 1 to 128" },
    { "nchs",
      "bbssd, CSD, KV: number of channels, 1 to 4096; the total sector count "
      "must fit in a signed 32-bit integer" },

    /* NAND timing: bbssd, CSD and KV */
    { "pg_rd_lat",
      "bbssd, CSD, KV: NAND page read time in ns when nand_cell_type is 0" },
    { "pg_wr_lat",
      "bbssd, CSD, KV: NAND page program time in ns when nand_cell_type is "
      "0" },
    { "blk_er_lat",
      "bbssd, CSD, KV: NAND block erase time in ns when nand_cell_type is "
      "0" },
    { "ch_xfer_lat",
      "Channel transfer time per page in ns: the data phase for bbssd, CSD "
      "and KV when pg_xfer_lat is 0, and the OCSSD 1.2 transfer time with "
      "oc12_channel_timing" },
    { "cmd_addr_lat",
      "bbssd, CSD, KV: command and address phase on the channel bus in "
      "ns; the bus is modelled only when this, pg_xfer_lat (or "
      "ch_xfer_lat) or status_lat is non-zero" },
    { "pg_xfer_lat",
      "bbssd, CSD, KV: page data transfer phase on the channel bus in ns; "
      "0 uses ch_xfer_lat" },
    { "status_lat",
      "bbssd, CSD, KV: status read phase on the channel bus in ns" },
    { "tplpbsy",
      "No effect, kept for compatibility; programs are issued one plane at "
      "a time. A value other than the default warns at realize" },
    { "tplrbsy",
      "No effect, kept for compatibility; reads are issued one plane at a "
      "time. A value other than the default warns at realize" },
    { "tplebsy",
      "bbssd, CSD, KV: busy time in ns between the planes of a "
      "multi-plane erase, which garbage collection issues when "
      "pls_per_lun > 1" },
    { "trcbsy",
      "No effect, kept for compatibility; no mode enables the cache read "
      "model. A value other than the default warns at realize" },
    { "trim_lat_ns",
      "bbssd, CSD: time in ns charged per Dataset Management deallocate "
      "range; refused with FDP" },
    { "pe_suspend",
      "bbssd, CSD, KV: non-zero lets a read suspend a program or erase on "
      "its LUN instead of waiting for it to finish" },
    { "tsusp_ns",
      "bbssd, CSD, KV: overhead in ns added to a read that suspends a "
      "program or erase, 0 or more" },
    { "nand_cell_type",
      "bbssd, CSD, KV: 0 uses the flat pg_rd_lat, pg_wr_lat and blk_er_lat; "
      "1 SLC, 2 MLC, 3 TLC or 4 QLC uses built-in per-page-type timing "
      "(other values fall back to 0)" },
    { "cell_pages",
      "bbssd, CSD, KV: bits per cell (pages per wordline) for the "
      "pgtype_lat model, 0 to 5; 0 with pgtype_lat means 3" },
    { "pgtype_lat",
      "bbssd, CSD, KV: non-zero scales the program time by page type "
      "(lower to upper) using cell_pages, when nand_cell_type is 0" },

    /* reliability and wear */
    { "ecc_step_ns",
      "bbssd, CSD, KV: extra read time in ns per ECC tier, one tier per "
      "750 erases of the block plus one per ecc_retention_sec of data "
      "age, at most 4 tiers; 0 turns the model off" },
    { "ecc_retention_sec",
      "bbssd, CSD, KV: data age in seconds that adds one ECC tier, with "
      "ecc_step_ns; 0 counts wear only; refused with FDP" },
    { "pe_cycles_rated",
      "bbssd, CSD, KV: rated program/erase cycles used for SMART Percentage "
      "Used; 0 takes the rating of nand_cell_type, or reports none" },
    { "nand_bad_blocks",
      "bbssd, CSD, KV: blocks marked bad at start, capped at the block "
      "count, which lowers SMART Available Spare" },
    { "err_read_unc_ppm",
      "bbssd, CSD: reads per million that fail as Unrecovered Read Error, "
      "injected at a fixed period; 0 disables" },
    { "err_write_fail_ppm",
      "bbssd, CSD and ZNS: writes per million that fail, injected at a "
      "fixed period (a ZNS zone then goes read-only); 0 disables" },
    { "read_reclaim_limit",
      "bbssd, CSD: when a host read finds its block has taken this many "
      "reads since its erase, that line is queued and rewritten on a "
      "following write, one line at a time; 0 disables, refused with FDP" },
    { "retention_limit_sec",
      "bbssd, CSD: when a host read hits a line filled at least this many "
      "seconds earlier, the line is queued and rewritten on a following "
      "write; 0 disables, refused with FDP" },

    /* garbage collection, mapping and caches */
    { "gc_thres_pcent",
      "bbssd, CSD: percent of lines in use at which background garbage "
      "collection starts, 1 to 100; KV uses it only as the fraction of "
      "NAND usable for values" },
    { "gc_thres_pcent_high",
      "bbssd, CSD: percent of lines in use at which garbage collection is "
      "forced, from gc_thres_pcent to 100" },
    { "gc_policy",
      "bbssd, CSD without FDP: line victim policy, one of greedy, random, "
      "cost-benefit, fifo or d-choice; unset is greedy" },
    { "gc_strategy",
      "bbssd with FDP: reclaim unit victim strategy, 0 greedy, 1 "
      "cost-benefit, 2 random or 4 per-handle" },
    { "mapping",
      "bbssd, CSD: logical-to-physical mapping scheme, one of page, dftl, "
      "hybrid or fast; unset is page, and FDP supports only page" },
    { "mapping_cache_mb",
      "bbssd, CSD with mapping=dftl: size of the cached mapping table in "
      "MiB; 0 means 4" },
    { "read_cache_mb",
      "bbssd, CSD: size of the DRAM read cache in MiB; 0 disables it" },
    { "cache_evict",
      "bbssd, CSD: read cache eviction policy, one of clock, random, lru "
      "or arc; unset is clock" },
    { "hot_cold_sep",
      "bbssd, CSD with mapping page or dftl: write overwrites of mapped "
      "pages to separate hot lines; refused with FDP" },
    { "buffer_size",
      "bbssd, CSD: DRAM write buffer capacity in NAND pages, not bytes; 0 "
      "programs every write directly" },
    { "buffer_thres_pcent",
      "bbssd, CSD: buffer fill level in percent at which buffered pages "
      "are written to NAND, 1 to 100 when buffer_size > 0" },
    { "fdp_trim_erase_all",
      "bbssd with FDP: non-zero makes a deallocate reset every reclaim unit "
      "instead of the given ranges" },
    { "debug_ftl",
      "bbssd, CSD, KV: print a message when a page is programmed while "
      "not free or invalidated while not valid, and print merge counts "
      "for hybrid and fast mapping" },

    /* host link and controller firmware */
    { "pcie_bandwidth_mbps",
      "Host link bandwidth in MB/s (10^6 bytes); each Read or Write is "
      "charged its transfer time on a per-direction link queue; 0 "
      "disables the bandwidth charge" },
    { "pcie_prop_delay_ns",
      "Host link propagation delay in ns added to each Read or Write "
      "after its link transfer; 0 disables it" },
    { "fw_cpu_ns",
      "Controller firmware time in ns charged to each Read, Write and "
      "Zone Append, serialized on one modelled core; 0 disables it" },

    /* ZNS */
    { "zns_num_ch",
      "ZNS: number of channels, 1 to 128" },
    { "zns_num_lun",
      "ZNS: LUNs (dies) per channel, 1 or more" },
    { "zns_num_plane",
      "ZNS: planes per LUN, 1 to 8; the program unit grows with it" },
    { "zns_num_blk",
      "ZNS: blocks per plane, 1 or more; the zone count is zns_num_blk "
      "times zns_num_ch divided by the zone width and zns_num_plane" },
    { "zns_flash_type",
      "ZNS: cell type, 1 SLC, 2 MLC, 3 TLC, 4 QLC or 5 PLC; MLC and PLC "
      "have no built-in timing and need zns_pg_rd_lat, zns_pg_wr_lat and "
      "zns_blk_er_lat" },
    { "zns_pg_rd_lat",
      "ZNS: page read time in ns, 0 or more; 0 uses the built-in time of "
      "zns_flash_type" },
    { "zns_pg_wr_lat",
      "ZNS: page program time in ns, 0 or more; 0 uses the built-in time "
      "of zns_flash_type" },
    { "zns_blk_er_lat",
      "ZNS: block erase time in ns, 0 or more; 0 uses the built-in time of "
      "zns_flash_type" },
    { "zns_cmd_addr_lat",
      "ZNS: command and address phase on the channel bus in ns, 0 or more" },
    { "zns_pg_xfer_lat",
      "ZNS: page data transfer phase on the channel bus in ns, 0 or more" },
    { "zns_status_lat",
      "ZNS: status read phase on the channel bus in ns, 0 or more" },
    { "zns_pe_suspend",
      "ZNS: non-zero lets a read suspend a program or erase on its plane" },
    { "zns_tsusp_ns",
      "ZNS: overhead in ns added to a read that suspends a program or "
      "erase, 0 or more" },
    { "zns_max_active",
      "ZNS: Maximum Active Resources (zones), at most the zone count; 0 "
      "means no limit" },
    { "zns_max_open",
      "ZNS: Maximum Open Resources (zones), at most the zone count and "
      "zns_max_active; 0 means no limit" },
    { "zns_num_wc",
      "ZNS: number of zone write caches; 0 uses zns_max_open, or 3 when "
      "that is 0" },
    { "zns_zd_ext_size",
      "ZNS: zone descriptor extension size in bytes, a multiple of 64 up to "
      "16320; 0 means none" },
    { "zns_num_conv_zones",
      "ZNS: number of leading conventional zones, which take random writes; "
      "capped at the zone count" },
    { "zns_zone_cap",
      "ZNS: zone capacity in bytes, at least one logical block and at most "
      "the zone size; 0 means the zone size" },
    { "zns_chnls_per_zone",
      "ZNS: channels one zone spans (zone width), dividing zns_num_ch; 0 "
      "means all channels" },
    { "zns_zrwa_size",
      "ZNS: Zone Random Write Area size in logical blocks, at most 65535 "
      "and a multiple of zns_zrwafg_size; 0 disables ZRWA" },
    { "zns_zrwafg_size",
      "ZNS: ZRWA flush granularity in logical blocks, 1 to 65535 with "
      "ZRWA and 0 without; the zone capacity must be a multiple of it" },
    { "zns_zrwa_num",
      "ZNS: number of zones that may hold a ZRWA at once, 1 or more with "
      "ZRWA and 0 without" },
    { "zns_cross_zone_read",
      "ZNS: allow reads that cross zone boundaries (Read Across Zone "
      "Boundaries)" },
    { "zns_zasl_bs",
      "ZNS: Zone Append size limit in bytes, a power-of-two multiple of 4 "
      "KiB; 0 follows mdts" },

    /* OCSSD */
    { "lver",
      "OCSSD: Open-Channel version, 1 for 1.2 or 2 for 2.0; other values "
      "fail realize" },
    { "flash_type",
      "OCSSD: cell type for the built-in timing tables, 1 SLC, 2 MLC, 3 "
      "TLC or 4 QLC; other values fail realize" },
    { "oc12_channel_timing",
      "OCSSD 1.2: charge channel transfer time for each page accessed, "
      "scaled by the sectors used out of lsecs_per_pg; ch_xfer_lat sets "
      "ns per page and 0 uses the flash_type value; off, transfers take "
      "no time" },
    { "lsec_size",
      "OCSSD 1.2: sector size in bytes reported in the geometry, greater "
      "than 0 in both versions; data moves at the namespace block size, "
      "and OCSSD 2.0 always uses 4096" },
    { "lsecs_per_pg",
      "OCSSD: sectors per page, greater than 0" },
    { "lpgs_per_blk",
      "OCSSD: pages per block, greater than 0 and at most 512 for OCSSD "
      "1.2" },
    { "lmax_sec_per_rq",
      "OCSSD 1.2: most sectors in one vector command; OCSSD 2.0 uses 64" },
    { "lnum_ch",
      "OCSSD: channels (2.0 groups), 1 to 32, with lnum_ch * lnum_lun at "
      "most 128" },
    { "lnum_lun",
      "OCSSD: LUNs (2.0 parallel units) per channel, 1 or more, with "
      "lnum_ch * lnum_lun at most 128" },
    { "lnum_pln",
      "OCSSD: planes per LUN, greater than 0; OCSSD 1.2 accepts 1, 2 or 4" },
    { "lmetasize",
      "OCSSD 1.2: out-of-band metadata bytes per sector; OCSSD 2.0 uses 16" },
    { "learly_reset",
      "OCSSD 2.0: non-zero reports the early reset capability, so the host "
      "may reset a chunk it has not filled" },

    /* CSD */
    { "fdm_size",
      "CSD: functional data memory size in MiB; required, greater than 0" },
    { "nr_cu",
      "CSD: number of compute units, 1 to 64; programs wait for the first "
      "free unit" },
    { "nr_thread",
      "No effect, kept for CEMU compatibility; CSD still refuses 0. A "
      "value other than the default warns at realize" },
    { "time_slice",
      "No effect, kept for CEMU compatibility. A value other than the "
      "default warns at realize" },
    { "context_switch_time",
      "No effect, kept for CEMU compatibility. A value other than the "
      "default warns at realize" },
    { "csf_runtime_scale",
      "CSD: non-zero multiplier applied to the host run time of a program "
      "that sets neither a runtime nor its own scale" },
    { "csd_program_dir",
      "CSD: host directory that shared-object and uBPF programs are "
      "loaded from, named by a file name with no slash that must resolve "
      "inside it; unset allows only the built-in phantom program type" },
    { NULL, NULL }
};

static const FemuPropDesc femu_ctrl_runtime_descs[] = {
    { "simulate-power-loss",
      "Write-only: setting true on a realized controller with power_loss=on "
      "drops the write buffer and resets the controller as a power cut "
      "would" },
    { NULL, NULL }
};

void femu_subsys_describe_props(ObjectClass *oc)
{
    femu_describe_class(oc, femu_subsys_descs);
}

void femu_ctrl_describe_props(ObjectClass *oc)
{
    femu_describe_class(oc, femu_ctrl_descs);
}

void femu_ctrl_describe_runtime(Object *obj)
{
    femu_describe_object(obj, femu_ctrl_runtime_descs);
}
