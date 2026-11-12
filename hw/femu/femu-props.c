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
    { "rotational",
      "Report endurance group 1 as rotational media: the RMEDIA bit of its "
      "namespaces, log 09h EGRMEDIA, log 16h and a fixed Spinup Control "
      "feature; timing does not change; not with fdp, znssd, kvssd or "
      "ocssd namespaces" },
    { "fdp",
      "Enable Flexible Data Placement in endurance group 1 for controllers "
      "that join this subsystem; only bbssd places data by reclaim unit" },
    { "fdp.runs",
      "Reclaim unit size in bytes; 0 means 96 MiB, and a bbssd controller "
      "accepts only 0 or the size of one superblock of the dies of a "
      "reclaim group, which it then uses" },
    { "fdp.nrg",
      "Number of FDP reclaim groups, from 1 to 128; with bbssd a group is "
      "a set of dies (whole channels, or LUNs of one channel), nrg must "
      "divide nchs or be a multiple of it that divides nchs * luns_per_ch, "
      "a logical block must be whole NAND pages, and each group must hold "
      "the whole namespace" },
    { "fdp.nruh",
      "Number of FDP reclaim unit handles (placement handles), from 1 to "
      "fdp.nru and at most 16366; must be set when fdp=on" },
    { "fdp.nru",
      "Number of reclaim units in each reclaim group, from fdp.nruh to "
      "65536; bbssd uses at most one per superblock and needs at least 2 "
      "* fdp.nruh + 1 of them, and the namespace must fit in the units "
      "left once each handle has one open, each Persistently Isolated "
      "handle one to collect into, and forced collection its free ones" },
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
    { "mode",
      "the emulated SSD type by name: ocssd, bbssd, nossd, zns (or znssd), "
      "csd or kv (or kvssd); it sets femu_mode, and a femu_mode other than "
      "2 must name the same type; unset (default) leaves femu_mode" },
    { "devsz_mb",
      "Size of the host memory backend in MiB, split across namespaces "
      "unless namespace_sizes is set; bbssd with op_pcent sizes from the "
      "NAND geometry instead" },
    { "namespaces",
      "Number of namespaces created at boot, 1 to 256; OCSSD supports only "
      "1, and FDP more than 1 only when all are bbssd or all nossd" },
    { "namespace_sizes",
      "Comma-separated size in bytes of each namespace (QEMU size syntax "
      "such as 4G,2G), one non-empty entry per namespace, summing to at most "
      "the backend; unset splits the backend evenly" },
    { "namespace_modes",
      "Comma-separated mode of each namespace from nossd, bbssd, znssd (or "
      "zns), ocssd, csd and kvssd (or kv), one entry per namespace; unset "
      "gives every namespace femu_mode" },
    { "namespace_phls",
      "FDP placement handle list of each namespace: comma-separated entries, "
      "one per namespace, each a ':'-separated list of reclaim unit handle "
      "IDs such as 0:1,,2 (placement handle i selects entry i); needs fdp=on, "
      "and unset gives every namespace every handle" },
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
    { "persist_file",
      "bbssd, NoSSD: host file that keeps the data and the deallocated "
      "and uncorrectable blocks across runs; realize loads it, unplug or "
      "the end of QEMU saves it. A file of another mode, size, namespace "
      "layout or LBA format fails realize, and FILE.lock keeps a second "
      "user out. Format NVM keeps the LBA format. The FTL state is kept "
      "only with persist_ftl. Not with namespace_modes, ns_mgmt, shared "
      "namespaces, cxl_ssd, metadata or sanitize_ms" },
    { "rrl",
      "bbssd with rber_ppb: Read Recovery Levels (Feature 12h, levels 4, "
      "9 and 15). Level 4 (default) recovers as the retry model does; 9 "
      "skips soft decode and 15 (Fast Fail) makes one hard decode, and a "
      "codeword they leave uncorrected fails the read; off (default)" },
    { "io_trace",
      "host file for an I/O trace: one CSV line per completed I/O command "
      "(t_submit_ns, t_cqe_ns, sqid, cid, nsid, opcode, slba, nlb, status), "
      "in every mode; the file must not exist; unset (default) is off" },
    { "events_file",
      "host file of timed actions, read at realize: lines '<ms> <action>' "
      "or '<ms>+<window>~<seed> <action>', the action ana=<group>:<state> "
      "(state 1 to 3, needs ana=on), power-loss (needs power_loss=on) or "
      "slow=<ch>:<lun>:<pct> (needs die_slow=on); "
      "times count from the first enable and survive resets; see "
      "query-femu-events; not with csd_pause; unset (default) is off" },
    { "die_slow",
      "bbssd, CSD: on makes the array time of each LUN settable at run "
      "time with the die-slow property or a slow= action of events_file, "
      "for a die that turns slow; one namespace only, not with ns_mgmt, "
      "namespace_modes, subsys or cxl_ssd; query-femu lists slow LUNs; "
      "off (default) adds nothing to the media path" },
    { "die_stats",
      "bbssd: count, per LUN, the array bookings, the ones that waited for "
      "a busy LUN, the wait and the array time, for query-femu kind dies; "
      "not with plane_reads, pe_suspend, read priority, cache reads or bus "
      "timing yet; off (default) adds nothing to the media path" },
    { "persist_ftl",
      "bbssd with mapping=page: persist_file keeps the FTL state too "
      "(mapping, page and block state, lines, write pointer, counters), "
      "so a restarted drive continues as it was; a file of other geometry, "
      "mapping, GC or NAND timing properties fails realize. Not with "
      "FDP or the FTL features whose state it does not keep (realize "
      "names the property); off (default)" },
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
    { "wrr",
      "weighted round robin with an urgent class: CAP.AMS offers it and "
      "the host may set CC.AMS 001b; needs one poller (multipoller_enabled=0, "
      "or poller_ratio of at least queues); off (default) is round robin "
      "only" },
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
    { "io_stages",
      "Time each I/O command in five stages (submit, ftl, hold, "
      "post-delay, total) for the QMP command query-femu-stages; off by "
      "default" },
    { "stage_ns",
      "with io_stages: also time the Read and the write commands of each "
      "NVM or zoned namespace, NSID 1 to 8, apart, in ns; "
      "query-femu-stages returns them with nsid; not with ns_mgmt; off "
      "(default)" },
    { "intc",
      "Initial Coalescing Disable bit (0 or 1) of the Interrupt Vector "
      "Configuration feature for every vector" },
    { "intc_thresh",
      "Initial aggregation threshold (0's based entries) of the Interrupt "
      "Coalescing feature; coalescing runs when it and intc_time are "
      "non-zero" },
    { "intc_time",
      "Initial aggregation time, in 100 microsecond units, of the Interrupt "
      "Coalescing feature; coalescing runs when it and intc_thresh are "
      "non-zero" },

    /* controller identity and capabilities */
    { "vid",
      "PCI vendor ID, also reported as the Identify Controller PCI Vendor "
      "ID" },
    { "did",
      "PCI device ID of the controller function" },
    { "acl",
      "Abort Command Limit reported in Identify Controller (0's based); "
      "an Abort run with more than acl others queued behind it fails" },
    { "cqr",
      "CAP.CQR: 1 requires physically contiguous queues, 0 allows "
      "PRP-list queues" },
    { "vwc",
      "1 advertises a volatile write cache, which the host can turn off "
      "with feature 06h to stop bbssd buffering writes; 0 advertises none "
      "and refuses feature 06h. Flush drains the bbssd write buffer either "
      "way. On KV with 1, Flush programs the open page of packed values, "
      "and with the cache off each Store programs it; 0 or 1" },
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
      "Save/Select, 0x80 Verify, 0x100 Copy; the default 0x19d sets all but "
      "Write Uncorrectable; Timestamp is always added" },
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
    { "awupf_lbas",
      "with power_loss: a Write, Write Zeroes or Copy of at most N blocks "
      "that spans pages runs as one transaction, so a cut or a failed "
      "placement finds it all old or all new; AWUN and AWUPF become N - 1; "
      "a power of two from 2 to 65536 that fits MDTS; not with "
      "durable_at_done or err_write_fail_ppm; 0 (default) is one block" },
    { "atomic_write_lbas",
      "Namespace atomic write unit in blocks: NAWUN and the boundary "
      "NABSN become N - 1, from block 0. 0 (default) keeps one block; "
      "else a power of two from 2 to 65536 that fits MDTS at the largest "
      "block size. The power-fail unit stays one block. bbssd and NoSSD "
      "only; refused with power_loss, ns_mgmt, namespace_modes and a "
      "subsystem" },
    { "ps_max_watts",
      "Maximum Power of power state 0 in watts, 1 to 127 (default 25); with "
      "ocp, the lowest valid DSSD power state of C4h and C7h; FEMU does not "
      "cap its modelled power at it" },
    { "fw_slots",
      "number of firmware slots, 1 to 7; 0 (default) means 1, or 3 with ocp; "
      "slot 1 is read only; with 2 or more, Firmware Image Download and "
      "Firmware Commit work and activation needs no reset; not with a "
      "femu-subsys or a CXL device" },
    { "sanitize_ms",
      "bbssd, NoSSD: a Sanitize runs in the background for this many ms; "
      "while it runs, I/O and most admin commands fail with Sanitize In "
      "Progress, and its end sends Sanitize Operation Completed; up to "
      "3600000; not with a femu-subsys or power_loss; 0 (default) finishes "
      "before the command completes" },
    { "sanitize_ops",
      "with Sanitize: also Crypto Erase and Overwrite (SANICAP CES, OWS); not "
      "with power_loss; off (default) offers Block Erase only" },
    { "ana",
      "ANA reporting (Base 2.3, 8.1.1): one ANA group per namespace, log 0Ch, "
      "CMIC bit 3 and the ANA Change notice; the runtime property ana-state "
      "sets a group's state through this controller; must match on every "
      "controller of a femu-subsys; off (default)" },
    { "power_limit",
      "with power_states: Power Limit (feature 23h, Base 2.3 8.1.18.6); a "
      "host limit in watts prohibits the power states whose MP is above "
      "it and renumbers the rest; not with persist_file; off (default)" },
    { "ns_wp",
      "bbssd, NoSSD: Namespace Write Protection (feature 84h, Base 2.3 "
      "8.1.17), the No Write Protect and Write Protect states; writes to a "
      "protected namespace fail with Namespace Is Write Protected; not with "
      "FDP, ns_mgmt, shared namespaces, cxl_ssd or persist_file; off "
      "(default)" },
    { "sanitize_ns",
      "bbssd, NoSSD with sanitize_ops: Sanitize Namespace (8Ch, Base 2.3 "
      "5.2.23), a crypto erase of one namespace while other namespaces keep "
      "their data, one at a time; log 81h by NSID; not with a femu-subsys, "
      "ns_mgmt, cxl_ssd or persist_file; off (default)" },
    { "cancel",
      "bbssd, NoSSD: Cancel (I/O 18h, Base 2.3 7.1) aborts commands of its "
      "own submission queue, one by CID or all of a namespace; commands "
      "past the FTL step abort at once (CMDA), the others when the step "
      "ends (CEDA); needs mapping=page; not with buffer_size, cxl_ssd, "
      "ocp, power_loss or a femu-subsys; off (default)" },
    { "shared_ftl",
      "bbssd: the namespaces share the FTL and NAND array of namespace 1, "
      "each in its own slice of the logical pages, so writes and GC of one "
      "slow the I/O of another; sizes in whole NAND pages; needs "
      "mapping=page; not with a femu-subsys, ns_mgmt, power_loss, "
      "persist_ftl, ns_wp, sanitize_ns or telemetry_da4; off (default)" },
    { "power_states",
      "bbssd, CSD: four power states (Base 2.3, 8.1.18). PS1 and PS2 stretch "
      "NAND array time by throttle_light_pct and throttle_heavy_pct; PS3 is "
      "non-operational, and an I/O command wakes it 5 ms later; Autonomous "
      "Power State Transition (0Ch); not with ocp or a femu-subsys; off "
      "(default) keeps one power state" },
    { "reservations",
      "Reservations (Base 2.3, 8.1.24): Reservation Register, Report, Acquire "
      "and Release, the Host Identifier (81h), Reservation Notification Mask "
      "(82h) and Reservation Persistence (83h) features, and log 80h; ONCS "
      "bit 5; not with Open-Channel; off (default)" },
    { "lockdown",
      "Command and Feature Lockdown: the Lockdown command (24h), log 14h "
      "and OACS bit 10; the host can prohibit most admin commands and "
      "changeable Feature Identifiers on the admin queue until QEMU stops; "
      "not with a femu-subsys; off (default)" },
    { "hmb_mb",
      "bbssd with mapping=dftl: ask the host for a Host Memory Buffer of "
      "this many MiB (Identify HMPRE and HMMIN). While the host has it "
      "enabled (Set Features 0Dh), the mapping table lives there: a lookup "
      "costs hmb_ns and reads no translation page. 0 (default) is off" },
    { "hmb_ns",
      "with hmb_mb, ns per mapping lookup in the Host Memory Buffer, the "
      "PCIe round trip; 0 or more (default 1000)" },
    { "crypto_mbps",
      "throughput in MB/s of the inline encryption engine of a "
      "self-encrypting drive; the data a command reads or programs (Read, "
      "Write, Zone Append, Compare, Verify, Write Zeroes that programs, "
      "twice for Copy, key-value and memory transfers) passes the one "
      "engine, after the media and the host link; a failed command pays "
      "nothing, and a reset clears the engine. 0 (default) is off" },
    { "telemetry_da4",
      "report Data Area 4 in the telemetry logs (07h, 08h) when the host "
      "sets ETDAS in Host Behavior Support: one 512-byte counter block per "
      "namespace after the controller block; also the Maximum Created Data "
      "Area field of log 07h; not with FDP; off (default)" },
    { "ocp",
      "bbssd, CSD: report the OCP 2.7 SMART Extended (C0h) and Error "
      "Recovery (C1h) logs behind the OCP UUID; the FEMU C0h counters move "
      "to UUID index 2; not with a femu-subsys; off (default) keeps C0h as "
      "the FEMU counters" },
    { "nand_profile",
      "bbssd, CSD, KV, ZNS: file of a versioned NAND profile (base read, "
      "program and erase times and bus phases), relative to the working "
      "directory; the timing properties it sets must keep their defaults; "
      "unset (default) uses the properties" },
    { "ocp_profile",
      "with ocp=on: 13 letters, A or B, one per OCP 2.7 device profile "
      "setting DP-CFG-1 to DP-CFG-13; unset (default) is BAABABAAAABAB, the "
      "settings FEMU meets; B for DP-CFG-7 turns on Write Uncorrectable; A "
      "for DP-CFG-1, 4, 6, 11 or 13 is refused, and ocp needs lba_index 0" },
    { "perf_hints",
      "bbssd, CSD: report the optimal write and deallocate granularity "
      "(NPWG, NPWA, NPDG, NPDA) as one flash page and NOWS as one stripe, "
      "for the format in use; off (default) reports 0 (one block). "
      "Refused with FDP and ns_mgmt" },
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
      "Offer end-to-end protection information types 1 to 3, in the last 8 "
      "bytes of metadata, when meta is at least 8 bytes, and allow Format "
      "and Create to select them; not with power_loss or cxl_ssd" },
    { "pci_pm",
      "a PCI Power Management capability (D0, D3hot) with "
      "No_Soft_Reset: outside D0 the PCI core turns the BARs off, and "
      "back in D0 the controller keeps its state; off (default) has no "
      "PM capability" },
    { "pif",
      "with pi: the protection information guard; 0 (default) is the "
      "16-bit CRC with 8-byte tuples, 2 the 64-bit CRC with 16-byte "
      "tuples and 48-bit reference tags (CTRATT.ELBAS, CNS 05h); 2 needs "
      "meta of 16 or more, and Copy is refused on those namespaces" },
    { "dpc",
      "Data Protection Capabilities reported in Identify Namespace when pi "
      "is off; must be 0 with meta, and bit 3 (first 8 bytes) is refused "
      "except on OCSSD" },
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
    { "plp",
      "with power_loss: power-loss protection; a cut writes the buffer "
      "back, FUA and Flush complete without the media, and vwc=0 keeps the "
      "buffer; C0h reports plp_health as Capacitor Health; with ocp=on it "
      "needs vwc=0; not with durable_at_done or rain_parity; off (default)" },
    { "plp_health",
      "with plp: hold-up energy at realize in percent, 0 to 65534; below 1 "
      "the check at enable and every C6h minutes (default 15) fails the "
      "protection; 120 (default)" },
    { "plp_fail_mode",
      "with plp: what a failed protection does, rom (default, writes fail "
      "82h), wtm (write-through) or normal; sets the C2h factory value, "
      "and ocp DP-CFG-6 B needs rom; Critical Warning bit 4 and a SMART "
      "event in every mode" },
    { "durable_at_done",
      "with power_loss: a written page is durable when its NAND program "
      "ends, not when it is booked; a cut restores the pages whose program "
      "had not ended, Flush, cache disable and shutdown wait for the last "
      "program; on a namespace with metadata, Copy and Write Zeroes "
      "without Deallocate fail with Invalid Field; not with mp_program, "
      "pe_suspend, read_prio, prog_pass2_ns, die_parity, rain_parity, ns_wp "
      "or sanitize_ns; off (default)" },
    { "ready_ms",
      "time from CC.EN to CSTS.RDY in ms of guest time, below 7500; admin "
      "commands queued before ready run then; 0 (default) is ready at once" },
    { "shutdown_ms",
      "time in ms of guest time CSTS.SHST reads 01b (in progress) after a "
      "shutdown, below 5000; the shutdown work is done before it; 0 "
      "(default) is complete at once" },
    { "recovery_ms",
      "time from CC.EN to CSTS.RDY for the first start after a power cut, "
      "in ms, 0 or ready_ms to 7499; 0 (default) uses ready_ms" },

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
    { "onfi_mode",
      "bbssd, CSD, KV: ONFI 6.0 NV-LPDDR4 timing mode 0 to 26; the channel "
      "bus phases then follow the spec for that mode and pg_rd_lat, "
      "pg_wr_lat and blk_er_lat stay the array times; -1 (default) is off. "
      "Refused with cmd_addr_lat, pg_xfer_lat, ch_xfer_lat, status_lat, "
      "pe_suspend or read_prio" },
    { "onfi_mts",
      "bbssd, CSD, KV: with onfi_mode, the page payload rate in MT/s in "
      "place of the mode's own rate, 1 to 100000; 0 (default) uses the mode" },
    { "onfi_spare_bytes",
      "bbssd, CSD, KV: with onfi_mode, the spare bytes moved with each page "
      "on the bus; the page on the bus must be an even number of bytes; 0 "
      "(default) moves the data bytes only" },
    { "onfi_tccs_ns",
      "bbssd, CSD, KV: with onfi_mode, tCCS in ns from a datasheet, paid "
      "before a data out when several LUNs share a channel and per plane of "
      "a multi-plane read; ONFI 6.0 gives no value, so 0 (default) pays "
      "nothing" },
    { "onfi_sca",
      "bbssd, CSD, KV: with the ONFI profile, non-zero selects the SCA "
      "protocol (ONFI 6.0 Section 5): commands, addresses and status use a "
      "separate CA bus, and the channel bus carries only the data bursts; "
      "0 (default) is the conventional protocol" },
    { "onfi_cache_read",
      "bbssd, CSD: with the ONFI profile, non-zero reads the pages of one "
      "read command that land on one LUN as a read cache sequence "
      "(31h, 00h-addr-31h, 3Fh; ONFI 6.0 Section 6.15), or as plain reads "
      "when the sequence would end later on an idle LUN. Refused with "
      "mp_read, mapping=dftl and read_cache_mb; 0 (default) is off" },
    { "onfi_param_page",
      "bbssd, CSD, KV: path of an ONFI 6.0 parameter page image (256 bytes "
      "per copy, CRC checked, redundant copies tried). It turns the ONFI "
      "profile on, gives the mode when onfi_mode is -1, and sets the spare "
      "bytes and address cycles. Realize refuses a page whose geometry, "
      "features or modes do not match the device; unset (default) uses none" },
    { "tplpbsy",
      "bbssd, CSD: busy time in ns between the planes of a multi-plane "
      "program; only with mp_program, and a value without it warns at "
      "realize. Negative is refused" },
    { "tplrbsy",
      "bbssd, CSD: busy time in ns between the planes of a multi-plane "
      "read; only with mp_read, and a value without it warns at realize. "
      "Negative is refused" },
    { "mp_program",
      "bbssd, CSD: non-zero charges programs of the same page on several "
      "planes of a LUN as one multi-plane command (one array time); needs "
      "pls_per_lun > 1 and no FDP, and warns at realize otherwise" },
    { "mp_read",
      "bbssd, CSD: non-zero charges host reads of the same page on several "
      "planes of a LUN as one multi-plane command (one array time); needs "
      "pls_per_lun > 1 and no FDP, and warns at realize otherwise" },
    { "plane_first",
      "bbssd, CSD: non-zero makes write pointers fill the planes of a LUN "
      "before the next channel, so consecutive pages form one multi-plane "
      "program with mp_program; needs pls_per_lun > 1 and no FDP, and "
      "warns at realize otherwise" },
    { "tplebsy",
      "bbssd, CSD, KV: busy time in ns between the planes of a "
      "multi-plane erase, which garbage collection issues when "
      "pls_per_lun > 1" },
    { "trcbsy",
      "bbssd, CSD: tRCBSY in ns, the busy time of each copy in a read "
      "cache sequence; only with onfi_cache_read, and a value without it "
      "warns at realize. 0 (default) takes 3000, the ONFI 6.0 typical "
      "value. Negative is refused with onfi_cache_read" },
    { "trim_lat_ns",
      "bbssd, CSD: time in ns charged per Dataset Management deallocate "
      "range, with or without FDP" },
    { "pe_suspend",
      "bbssd, CSD, KV: non-zero lets a read suspend a program or erase on "
      "its LUN instead of waiting for it to finish" },
    { "tsusp_ns",
      "bbssd, CSD, KV: overhead in ns added to a read that suspends a "
      "program or erase, 0 or more" },
    { "pe_suspend_max",
      "bbssd, CSD, KV: with pe_suspend, the suspensions one program or "
      "erase allows; a read past them waits for it; 0 (default) allows any" },
    { "tresume_ns",
      "bbssd, CSD, KV: with pe_suspend, ns added to a suspended program or "
      "erase each time it resumes, 0 or more (default 0)" },
    { "read_prio",
      "bbssd, CSD, KV: non-zero lets a read go ahead of the programs and "
      "erases queued on its LUN; it waits only for the one that runs. "
      "Plain channel model only (no bus phases or ONFI)" },
    { "prog_pass2_ns",
      "bbssd, CSD: time in ns of the fine program pass of a wordline; the "
      "program time is the coarse pass. The fine pass runs on the die when "
      "prog_pass2_lag later wordlines of the block are programmed, or when "
      "the block fills; until then a read of the wordline comes from the "
      "controller buffer. 0 (default) is one pass" },
    { "prog_pass2_lag",
      "bbssd, CSD: with prog_pass2_ns, the wordlines programmed after one "
      "before its fine pass, 1 to 16; 0 (default) means 1" },
    { "die_parity",
      "bbssd, CSD: non-zero books one parity program per full stripe, one "
      "page per die at a plane and page index, on a die that rotates with "
      "the page; it costs die time and counts in WAF, not space. Needs two "
      "dies and mapping=page; not with mp_program, mp_read, "
      "onfi_cache_read, gc_copyback, rber_ppb, KV, namespace_modes or FDP. "
      "0 (default) is off" },
    { "rain_parity",
      "bbssd, CSD: 1 keeps one parity page in each stripe of a line (one "
      "page per die at a plane and page index), as RAIN on a datacenter "
      "drive: the parity page rotates over the dies and takes space, so "
      "the spare space drops by one die in N and WAF counts one parity "
      "program per N - 1 data pages. A failed die (failed_die) is out of "
      "every line opened after it fails, and its pages read from the other "
      "dies of their stripe. Dies fail one at a time: a new failure needs "
      "the lines from before the last one moved (rain_rebuild), and two "
      "members left. Needs two to 1024 dies (three with "
      "failed_die) and mapping=page; not with die_parity or what it "
      "refuses, prog_pass2_ns, wl_spread, pd_open_close_sec, Streams, "
      "durable_at_done, gc_pace, blk_pe_limit, persist_ftl or the pSLC "
      "tier. 0 (default) is off" },
    { "rain_rebuild",
      "bbssd, CSD: with rain_parity, each write moves at most one line "
      "opened before the last die failure into a line without that die, "
      "when lines are to spare; off (default): only GC moves them" },
    { "parity_xor_ns",
      "bbssd, CSD: with die_parity or rain_parity, controller time in ns "
      "before each "
      "parity program and added to a read of the failed die; 0 (default)" },
    { "failed_die",
      "bbssd, CSD: with die_parity or rain_parity, the die (channel * "
      "luns_per_ch + LUN) "
      "that has failed: a host read there reads the other dies of its "
      "stripe in parallel; -1 (default) is none" },
    { "inject_die",
      "bbssd, CSD: with ocp=on, the die (channel * luns_per_ch + LUN) that "
      "OCP event injection 0016h (NAND Die Offline) takes offline; 0 "
      "(default)" },
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
      "ecc_step_ns; 0 counts wear only" },
    { "rber_ppb",
      "bbssd: fresh raw bit error rate of host reads in parts per 10^9; "
      "it adds read-retry and soft decode time to host reads, and a "
      "codeword that no decode corrects fails the read with Unrecovered "
      "Read Error. 0 (default) turns the model off. At most 10^9; refused "
      "with bus "
      "phase or ONFI timing, pe_suspend, read_prio, mp_read, onfi_cache_read, "
      "gc_copyback, ecc_step_ns, the pSLC tier and cxl_ssd" },
    { "rber_timing_only",
      "bbssd with rber_ppb: on lets a read whose codeword no decode "
      "corrects pass, charging only the time (the earlier rule); levels 9 "
      "and 15 of rrl still fail it. Off (default): it fails with "
      "Unrecovered Read Error" },
    { "rber_pe_double",
      "bbssd with rber_ppb: block erases that double the raw bit error "
      "rate; 0 (default) leaves wear out" },
    { "rber_age_double_sec",
      "bbssd with rber_ppb: data age in seconds that doubles the raw "
      "bit error rate, from the line close, or the first program with "
      "pd_open_age; 0 (default) leaves age out" },
    { "rber_read_double",
      "bbssd with rber_ppb: block reads since its erase that double the "
      "raw bit error rate; 0 (default) leaves read disturb out" },
    { "ecc_cw_bytes",
      "bbssd with rber_ppb: data bytes per ECC codeword, 256 or more; "
      "it divides the page into 16 codewords or fewer" },
    { "ecc_hard_bits",
      "bbssd with rber_ppb: bit errors per codeword that hard decode "
      "corrects, 1 to 1024" },
    { "ecc_soft_bits",
      "bbssd with rber_ppb: bit errors per codeword that soft decode "
      "corrects, ecc_hard_bits to 1024; 0 turns soft decode off" },
    { "rr_steps",
      "bbssd with rber_ppb: read-retry steps before soft decode, 0 to "
      "16; each step is one more page read" },
    { "rr_gain",
      "bbssd with rber_ppb: each retry step divides the reducible part "
      "of the error mean by this, 2 to 16" },
    { "rr_floor_pct",
      "bbssd with rber_ppb: percent of the error mean that no retry "
      "removes, 0 to 100" },
    { "rr_soft_senses",
      "bbssd with rber_ppb: page reads of one soft decode, 0 to 8" },
    { "rr_soft_ns",
      "bbssd with rber_ppb: controller time in ns of one soft decode, "
      "at most 10^7; it does not hold the LUN" },
    { "rber_seed",
      "bbssd with rber_ppb: seed of the decode outcome generator; the "
      "same seed and trace give the same counts" },
    { "pd_edge_wls",
      "bbssd, CSD, KV: program disturb, bottom wordlines of each block whose "
      "reads take pd_edge_tiers more ECC tiers; set with pd_edge_tiers and "
      "ecc_step_ns; 0 (default) turns the term off. A wordline is "
      "the pages per wordline of nand_cell_type (else the effective "
      "cell_pages, 3 with pgtype_lat, else 1) contiguous pages" },
    { "pd_edge_tiers",
      "bbssd, CSD, KV: program disturb, ECC tiers added to a read of a "
      "pd_edge_wls wordline, 0 to 4, under the shared tier cap; chosen "
      "values for sensitivity studies, not fitted to error rates" },
    { "pd_open_tiers",
      "bbssd, CSD, KV: program disturb, ECC tiers added to a read of a block "
      "that is only part programmed, 0 to 4, under the shared tier cap; "
      "needs ecc_step_ns; 0 (default) turns the term off" },
    { "pd_open_age",
      "bbssd, CSD, KV: data age for the ECC age tiers counts from the first "
      "program of the line instead of the line close, so open data ages "
      "too; one time per line; needs ecc_step_ns and ecc_retention_sec; "
      "off (default)" },
    { "pd_open_read_limit",
      "bbssd, CSD, FDP: program disturb, reads of a part-programmed block "
      "that queue its line or reclaim unit; the next Write rewrites it, "
      "after it seals a frontier line or retires a frontier unit with its "
      "free pages unprogrammed; not above a non-zero "
      "read_reclaim_limit; 0 (default) turns it off" },
    { "pd_open_close_sec",
      "bbssd, CSD, FDP: program disturb, seconds of device time (age_scale) "
      "a frontier line or reclaim unit may stay open after its first "
      "program; the next request pads its free pages and closes it; under "
      "FDP the handle gets a fresh unit and event 1h; 0 (default) turns it "
      "off" },
    { "pe_cycles_rated",
      "bbssd, CSD, KV, ZNS: rated program/erase cycles used for SMART "
      "Percentage Used; 0 takes the rating of nand_cell_type (ZNS: "
      "zns_flash_type), or reports none" },
    { "nand_bad_blocks",
      "bbssd, CSD, KV: blocks marked bad at start, capped at the block "
      "count, which lowers SMART Available Spare" },
    { "blk_pe_limit",
      "bbssd, CSD, also FDP: mean program/erase cycles a block survives "
      "before it wears out; 0 (default) turns wear-out off. When no block "
      "can replace a worn-out one, the media goes read-only (eol_read_only). "
      "Under FDP a worn-out block retires its reclaim unit" },
    { "blk_pe_spread",
      "bbssd, CSD, also FDP: how far each block's limit varies from "
      "blk_pe_limit, in percent, 0 to 90" },
    { "blk_pe_seed",
      "bbssd, CSD, also FDP: seed of the per-block erase limits; one seed "
      "gives the same limits on every run" },
    { "energy_read_nj",
      "bbssd, CSD, KV: energy of one plane read in nJ, for the energy total "
      "in log page C0h; 0 (default) gives no figure" },
    { "energy_prog_nj",
      "bbssd, CSD, KV: energy of one plane program in nJ, for the energy "
      "total in log page C0h; 0 (default) gives no figure" },
    { "energy_erase_nj",
      "bbssd, CSD, KV: energy of one plane erase in nJ, for the energy total "
      "in log page C0h; 0 (default) gives no figure" },
    { "thermal_tau_ms",
      "time constant of the package, ms: the composite temperature moves "
      "towards temperature + power * thermal_r at this rate, where power is "
      "idle_mw plus the energy of the NAND plane operations (energy_*_nj) per "
      "second; 0 (default) turns the model off" },
    { "thermal_r",
      "thermal resistance from the package to ambient, mK per mW (K per W); "
      "needed with thermal_tau_ms" },
    { "plane_reads",
      "bbssd, CSD: reads on different planes of one die overlap; a program or "
      "erase still holds the whole die; plain channel model only (no ONFI, bus "
      "phases, pe_suspend or read_prio); no effect with one plane per LUN" },
    { "throttle",
      "bbssd, CSD: thermal throttling on the thermal model (needs "
      "thermal_tau_ms); enables feature 10h (HCTM) and stretches NAND "
      "array time at the light or heavy level" },
    { "throttle_light_pct",
      "with throttle: NAND array time at the light level, in percent of "
      "nominal, 100 to throttle_heavy_pct" },
    { "throttle_heavy_pct",
      "with throttle: NAND array time at the heavy level, in percent of "
      "nominal, up to 1000" },
    { "hot_k",
      "with throttle and ocp=off: autonomous protection enters the heavy "
      "level at this temperature in kelvin and leaves 2 K below; 0 "
      "(default) is off; ocp=on uses 350 K and 348 K" },
    { "idle_mw",
      "power with no NAND operations, mW, for the thermal model and "
      "power_meas" },
    { "power_meas",
      "Power Measurement (Base 2.3, 8.1.19.1): log page 25h and feature 25h, "
      "estimated from idle_mw and energy_*_nj; one controller, not with "
      "persist_file, ns_mgmt or shared namespaces; off (default)" },
    { "thermal_step_ms",
      "how often the thermal model updates the temperature, ms, 1 to 60000; "
      "100 (default)" },
    { "spare_lines",
      "bbssd, CSD: lines held back, needs blk_pe_limit; their blocks "
      "replace worn-out blocks of the same plane, and SMART Available Spare "
      "is the spare blocks the emptiest plane has left, in percent" },
    { "eol_read_only",
      "bbssd, CSD, with blk_pe_limit: on (default) puts the media in "
      "read-only mode when no block can replace a worn-out one, with "
      "reserve lines for the writes in flight; needs mdts 1 or more and "
      "limits Write Zeroes (WZSL) to mdts and Copy (MCL) to mdts or one "
      "block. off keeps a worn-out block in service with the SMART "
      "reliability warning. Under FDP each reclaim group holds reserve "
      "units" },
    { "err_read_unc_ppm",
      "bbssd, CSD: reads per million that fail as Unrecovered Read Error, "
      "injected at a fixed period; 0 disables" },
    { "err_write_fail_ppm",
      "bbssd, CSD and ZNS: writes per million that fail, injected at a "
      "fixed period (a ZNS zone then goes read-only); 0 disables" },
    { "read_reclaim_limit",
      "bbssd, CSD: when a host read finds its block has taken this many "
      "reads since its erase, that line is queued and rewritten on a "
      "following write, one line at a time (under FDP, its reclaim unit); "
      "0 disables" },
    { "retention_limit_sec",
      "bbssd, CSD: when a host read hits a line filled at least this many "
      "seconds earlier, the line is queued and rewritten on a following "
      "write (under FDP, its reclaim unit); 0 disables" },
    { "wl_spread",
      "bbssd, CSD: static wear levelling starts when the erases of lines in "
      "service differ by more than this and stops at half of it; it moves "
      "the least worn full line into the most worn free line and copies at "
      "most a quarter of the host pages; 0 (default) turns it off" },
    { "gc_pace",
      "bbssd, CSD: collect the victim line a few pages per host page "
      "written, in proportion to its valid pages, instead of in one pass; "
      "the forced pass stays as the last resort; off (default)" },
    { "gc_copyback",
      "bbssd, CSD, FDP: collection moves a page on its die (copyback) when "
      "the destination is on the same channel, LUN and plane; collection "
      "takes victim pages in the order of the destination dies. A copyback "
      "skips ECC: the data never reaches the controller, so a real SSD "
      "does not correct its bit errors, and they can add up over repeated "
      "copybacks. FEMU models no bit errors, so here only the timing "
      "changes. For that reason a page whose read has extra ECC time, and "
      "every read reclaim or retention refresh, moves off-chip. Not for "
      "KV. Refused with gc_pace, pe_suspend, read_prio, cxl_ssd, "
      "namespace_modes, ns_mgmt, shared namespaces and the hybrid and fast mappings; off "
      "(default)" },
    { "age_scale",
      "bbssd, CSD: data ages this many times faster than wall time, for "
      "retention_limit_sec, ecc_retention_sec and rber_age_double_sec "
      "only; 1 (default) or more. "
      "I/O timing and garbage collection order do not change" },

    /* garbage collection, mapping and caches */
    { "gc_thres_pcent",
      "bbssd, CSD: percent of lines in use at which background garbage "
      "collection starts, 1 to 100; KV uses it only as the fraction of "
      "NAND usable for values" },
    { "gc_thres_pcent_high",
      "bbssd, CSD: percent of lines in use at which garbage collection is "
      "forced, from gc_thres_pcent to 100; under FDP it keeps at least one "
      "reclaim unit free unless it is 100" },
    { "gc_policy",
      "bbssd, CSD: victim policy, one of greedy, random, cost-benefit, fifo "
      "or d-choice; unset is greedy. Under FDP it picks the reclaim unit "
      "strategy, and a name other than greedy needs gc_strategy=0" },
    { "gc_seed",
      "bbssd, CSD: seed for the victims the random and d-choice gc_policy "
      "and the FDP random gc_strategy pick; the same seed and workload pick "
      "the same victims, so vary it to vary runs" },
    { "gc_strategy",
      "bbssd with FDP: reclaim unit victim strategy, 0 greedy, 1 "
      "cost-benefit, 2 random or 4 per-handle; a gc_policy other than "
      "greedy picks it instead" },
    { "mapping",
      "bbssd, CSD: logical-to-physical mapping scheme, one of page, dftl, "
      "hybrid or fast; unset is page, and FDP takes page or dftl" },
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
    { "gc_frontier",
      "bbssd, CSD: write the pages garbage collection copies to lines of "
      "their own, apart from host writes; refused with FDP, cxl_ssd, "
      "gc_pace, Streams, and retention_limit_sec without pd_open_close_sec" },
    { "gc_idle_ms",
      "bbssd with one namespace and page mapping: quiet time in ms after "
      "which the device collects lines in the background, one victim at a "
      "time; 0 (default) collects only on the write path" },
    { "maint_idle",
      "bbssd with gc_idle_ms: idle steps also run the queued read reclaim "
      "and scan closed lines for retention age, 16 line ids a step, in turns "
      "with idle collection; a reclaim that waits for free lines lets "
      "collection run first; off (default) leaves both to the write path" },
    { "gc_idle_pcent",
      "bbssd with gc_idle_ms: idle collection runs while the line fill is "
      "above this percent, as gc_thres_pcent counts it; 0 (default) takes "
      "gc_thres_pcent, else 1 to 99" },
    { "buffer_size",
      "bbssd, CSD: DRAM write buffer capacity in NAND pages, not bytes; 0 "
      "programs every write directly" },
    { "l2p_dram_ns",
      "bbssd, CSD: controller DRAM time in ns of each logical-to-physical "
      "lookup, added to the mapping cost of every host page read and "
      "written, 0 or more; not with onfi_cache_read or FDP; 0 (default) "
      "charges none" },
    { "dram_hit_ns",
      "bbssd, CSD: controller DRAM time in ns of one page that the write "
      "buffer or the read cache answers, 0 or more; a read takes the most "
      "of its pages, and a buffered write pays it once; 0 (default) is "
      "pg_rd_lat / 16 (1 ns at least), or 1000 ns when pg_rd_lat is 0" },
    { "iu_pages",
      "bbssd, CSD: the indirection unit in pages, 0 to 64; above 1, a write "
      "that covers part of a unit reads the unit's other mapped pages and "
      "programs them again (read-modify-write) on the write path, not for "
      "Write Zeroes; not with buffer_size, streams, mp_program, "
      "end-of-life read-only or FDP; 0 or 1 (default) maps each page" },
    { "buffer_low_pcent",
      "bbssd, CSD: with buffer_size, an idle FTL thread writes buffered "
      "pages back, one per die once all dies are free, until the fill "
      "level falls to this percent; below buffer_thres_pcent; not with "
      "shared namespaces or power_loss; 0 (default) writes back only when "
      "the buffer reaches buffer_thres_pcent" },
    { "buffer_thres_pcent",
      "bbssd, CSD: buffer fill level in percent at which buffered pages "
      "are written to NAND, 1 to 100 when buffer_size > 0" },

    /* pSLC tier */
    { "tier_mode",
      "bbssd: off (unset), static or dynamic; static keeps a pool of lines "
      "in pSLC mode in front of the dense lines, and host writes go there "
      "first. dynamic also borrows free dense lines for the pool while the "
      "device has room. Needs nand_cell_type 2, 3 or 4 and page or dftl "
      "mapping; under FDP only static with the direct policy; refused with "
      "more than one namespace, Streams and the wear, refresh and pd_* "
      "features" },
    { "tier_full_policy",
      "bbssd with a tier_mode: what a host page does when the pool "
      "has no free page; direct (unset) writes it to the dense lines, "
      "through folds the oldest pool line first and writes it to the pool" },
    { "tier_static_mb",
      "bbssd with a tier_mode: host data in MiB the static pSLC pool holds; "
      "the pool takes enough whole lines out of the over-provisioning, and "
      "realize refuses a pool that leaves the namespace too little room. "
      "Above 0 for static and for through; with dynamic it is the floor "
      "the pool keeps" },
    { "tier_pslc_read_ns",
      "bbssd with a tier_mode: time in ns of one pSLC page read, at "
      "most 10 s" },
    { "tier_pslc_prog_ns",
      "bbssd with a tier_mode: time in ns of one pSLC page program, "
      "at most 10 s" },
    { "tier_pslc_erase_ns",
      "bbssd with a tier_mode: time in ns of one pSLC block erase, at "
      "most 10 s" },
    { "tier_pslc_pe_cycles",
      "bbssd with a tier_mode: rated erase cycles of a block in pSLC "
      "mode, for the tier wear figure; 0 (default) takes 30 times the "
      "dense rating" },
    { "tier_max_mb",
      "bbssd with tier_mode=dynamic: host data in MiB the borrowed lines may "
      "hold at most; 0 (default) sets no cap, and the free space alone "
      "limits the pool" },
    { "tier_shrink_pct",
      "bbssd with tier_mode=dynamic: logical fill in percent at which the "
      "pool starts to give borrowed lines back, 0 to 99; above it the "
      "allowance falls in a line to 0 at a full device" },
    { "tier_idle_ms",
      "bbssd with a tier_mode: quiet time in ms after which the device folds "
      "pool lines in the background, one bounded step at a time; 0 "
      "(default) folds only when a write needs room" },
    { "tier_lazy_pct",
      "bbssd with tier_idle_ms: 0 (default) folds every closed pool line at "
      "idle; 1 to 99 folds only while the pool lines in use are above this "
      "percent of the pool" },
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
    { "pcie_write_first",
      "with the host link model: on (default) books a write's transfer "
      "before its media, as on a real drive; off charges it after the "
      "programs, the order before this option" },
    { "fw_cpu_ns",
      "Controller firmware time in ns charged to each Read, Write and "
      "Zone Append, serialized on one modelled core; 0 disables it" },
    { "fw_read_ns",
      "Controller firmware time in ns for each Read; 0 (default) takes "
      "fw_cpu_ns" },
    { "fw_write_ns",
      "Controller firmware time in ns for each Write and Zone Append; 0 "
      "(default) takes fw_cpu_ns" },
    { "fw_other_ns",
      "Controller firmware time in ns for each I/O command other than Read, "
      "Write and Zone Append; 0 (default) charges none" },
    { "fw_cores",
      "Controller firmware cores, 1 (default) to 64; each command takes the "
      "core that is free soonest" },

    /* ZNS */
    { "zns_num_ch",
      "ZNS: number of channels, 1 to 128" },
    { "zns_num_lun",
      "ZNS: LUNs (dies) per channel, 1 or more" },
    { "zns_num_plane",
      "ZNS: planes per LUN, 1 to 8; the program unit grows with it" },
    { "zns_num_blk",
      "ZNS: blocks per plane, 1 or more; the zone count is zns_num_blk "
      "times zns_num_ch times zns_num_lun, divided by the zone width, the "
      "zone LUNs and zns_num_plane" },
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
    { "zns_lun_contention",
      "ZNS: non-zero makes the planes of one LUN share the die, so their "
      "operations run one at a time; a zone reset erases each LUN's planes "
      "in one multi-plane operation" },
    { "zns_reset_by_fill",
      "ZNS: non-zero makes a zone reset erase only the blocks that hold "
      "programmed pages, so its time and wear follow the zone's fill" },
    { "zns_fzr_sec",
      "ZNS: seconds a zone may stay written but not finished before the "
      "controller sets Finish Zone Recommended and reports the zone as "
      "changed; 0 disables" },
    { "zns_frl_sec",
      "ZNS: Finish Recommended Limit in seconds: after it, the controller "
      "finishes a zone with Finish Zone Recommended itself (a Zone Active "
      "Excursion); 0 means no excursion; needs zns_fzr_sec" },
    { "zns_rzr_sec",
      "ZNS: seconds a zone may stay Full before the controller sets Reset "
      "Zone Recommended and reports the zone as changed; 0 disables" },
    { "zns_rrl_sec",
      "ZNS: Reset Recommended Limit in seconds: after it, the controller "
      "refreshes a zone with Reset Zone Recommended itself and clears it; "
      "0 means no refresh; needs zns_rzr_sec" },
    { "zns_page_types",
      "ZNS: non-zero gives each read the latency of its page type (lower "
      "to upper page), spread around the read latency of the flash type; "
      "programs keep one latency per wordline" },
    { "zns_ecc_step_ns",
      "ZNS: ECC read time in ns added per 750 erases of the block, up to 4 "
      "steps, as bbssd ecc_step_ns; 0 or more" },
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
    { "zns_luns_per_zone",
      "ZNS: LUNs one zone spans on each of its channels, dividing "
      "zns_num_lun; 0 means all LUNs" },
    { "zns_zone_order",
      "ZNS: ch (default) fills a zone channel first, then LUN; lun fills "
      "it LUN first, so consecutive programs share a channel" },
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
    { "oc20_page_types",
      "OCSSD 2.0: charge each read and program the time of its page type "
      "(lower to upper page) from the flash_type tables, as OCSSD 1.2 "
      "does; off, every page takes the lower page time" },
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
    { "csd_slm_size",
      "CSD: MiB of a memory namespace (NVMe SLM 1.2, CSI 03h) added after "
      "the configured namespaces, 1 to 1024; 0 adds none" },
    { "csd_cp",
      "CSD: add a compute namespace (NVMe CP 1.2, CSI 04h) after the memory "
      "namespace; needs csd_slm_size" },
    { "csd_legacy_opcodes",
      "CSD: take the old CEMU admin opcodes 21h, 22h, 23h and 25h instead "
      "of the vendor specific C5h, C8h, C9h and CDh; needs a CSD namespace" },
    { "csd_pause",
      "CSD: stop the guest, its vCPUs and clocks, while the host runs a "
      "program, so the guest sees only the modelled run time; needs KVM on "
      "x86 (host Linux 6.0 or later), the guest TSC at the host rate, and "
      "only bbssd and CSD namespaces, none shared" },
    { "csd_pause_max_ms",
      "CSD with csd_pause: the longest stop, 1 to 60000 ms; past it the "
      "guest runs again and sees the rest of the host run" },
    { "kv_timing",
      "KV: media (default) times every command on the NAND model; model "
      "times Store and Retrieve from the workload mix of the last 16 of "
      "them, with the Samsung KVSSD emulator fit" },
    { "kv_model_coeffs",
      "KV with kv_timing=model: 36 comma-separated numbers, the intercept "
      "then the 35 polynomial coefficients; unset uses the Samsung fit" },
    { "kv_index",
      "KV: the key index; hash (default) is an open-addressed hash in "
      "device DRAM, lsm a PinK-style LSM tree whose unpinned levels cost "
      "flash reads on lookup and flash reads and programs on compaction" },
    { "kv_lsm_memtable_keys",
      "KV with kv_index=lsm: keys the DRAM memtable holds before it "
      "flushes to level 1, 16 to 65536" },
    { "kv_lsm_size_ratio",
      "KV with kv_index=lsm: how many times more entries a level holds "
      "than the one above, 2 to 64; level i holds memtable keys times "
      "ratio^i entries" },
    { "kv_lsm_pinned_levels",
      "KV with kv_index=lsm: top levels held whole in DRAM, with no flash "
      "I/O, 0 to 24" },
    { "kv_pack",
      "KV: on (default) packs values below a page into shared NAND pages "
      "through an open page in controller DRAM; off gives each value whole "
      "pages, the model before packing" },
    { "kv_max_keys",
      "KV: the key limit of each KV namespace, reported as MNK; 0 "
      "(default) sizes it from the flash: with kv_pack the 1-byte values "
      "it holds, at most 4194303, else the old two index slots per 4 KiB; "
      "1 to 1610612735 sets it, at 85 bytes of hash index DRAM a key" },
    { NULL, NULL }
};

static const FemuPropDesc femu_ctrl_runtime_descs[] = {
    { "ana-state",
      "with ana=on: \"g:s\" sets the ANA state of group g (the namespace "
      "ID) through this controller: 1 Optimized, 2 Non-Optimized, 3 "
      "Inaccessible, 4 Persistent Loss; reading lists every group" },
    { "simulate-power-loss",
      "Write-only: setting true on a realized controller with power_loss=on "
      "drops the write buffer and resets the controller as a power cut "
      "would" },
    { "die-slow",
      "with die_slow=on: \"<ch>:<lun>:<pct>\" sets the array time of one "
      "LUN to pct percent of nominal (100 to 10000), for ops booked from "
      "then on; reading lists the LUNs not at 100" },
    { "plp-health",
      "with plp=on: the hold-up energy now, 0 to 65534 percent; the next "
      "check (at enable and every C6h minutes) fails the protection below "
      "1, and a cut below 1 keeps nothing" },
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
