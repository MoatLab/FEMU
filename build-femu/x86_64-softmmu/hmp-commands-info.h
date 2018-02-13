

{
.name       = "version",
.args_type  = "",
.params     = "",
.help       = "show the version of QEMU",
.cmd        = hmp_info_version,
},


{
.name       = "network",
.args_type  = "",
.params     = "",
.help       = "show the network state",
.cmd        = hmp_info_network,
},


{
.name       = "chardev",
.args_type  = "",
.params     = "",
.help       = "show the character devices",
.cmd        = hmp_info_chardev,
},


{
.name       = "block",
.args_type  = "nodes:-n,verbose:-v,device:B?",
.params     = "[-n] [-v] [device]",
.help       = "show info of one block device or all block devices "
"(-n: show named nodes; -v: show details)",
.cmd        = hmp_info_block,
},


{
.name       = "blockstats",
.args_type  = "",
.params     = "",
.help       = "show block device statistics",
.cmd        = hmp_info_blockstats,
},


{
.name       = "block-jobs",
.args_type  = "",
.params     = "",
.help       = "show progress of ongoing block device operations",
.cmd        = hmp_info_block_jobs,
},


{
.name       = "registers",
.args_type  = "",
.params     = "",
.help       = "show the cpu registers",
.cmd        = hmp_info_registers,
},


#if defined(TARGET_I386)
{
.name       = "lapic",
.args_type  = "",
.params     = "",
.help       = "show local apic state",
.cmd        = hmp_info_local_apic,
},
#endif


#if defined(TARGET_I386)
{
.name       = "ioapic",
.args_type  = "",
.params     = "",
.help       = "show io apic state",
.cmd        = hmp_info_io_apic,
},
#endif


{
.name       = "cpus",
.args_type  = "",
.params     = "",
.help       = "show infos for each CPU",
.cmd        = hmp_info_cpus,
},


{
.name       = "history",
.args_type  = "",
.params     = "",
.help       = "show the command line history",
.cmd        = hmp_info_history,
},


{
.name       = "irq",
.args_type  = "",
.params     = "",
.help       = "show the interrupts statistics (if available)",
.cmd        = hmp_info_irq,
},


{
.name       = "pic",
.args_type  = "",
.params     = "",
.help       = "show PIC state",
.cmd        = hmp_info_pic,
},


{
.name       = "pci",
.args_type  = "",
.params     = "",
.help       = "show PCI info",
.cmd        = hmp_info_pci,
},


#if defined(TARGET_I386) || defined(TARGET_SH4) || defined(TARGET_SPARC) || \
defined(TARGET_PPC) || defined(TARGET_XTENSA)
{
.name       = "tlb",
.args_type  = "",
.params     = "",
.help       = "show virtual to physical memory mappings",
.cmd        = hmp_info_tlb,
},
#endif


#if defined(TARGET_I386)
{
.name       = "mem",
.args_type  = "",
.params     = "",
.help       = "show the active virtual memory mappings",
.cmd        = hmp_info_mem,
},
#endif


{
.name       = "mtree",
.args_type  = "flatview:-f",
.params     = "[-f]",
.help       = "show memory tree (-f: dump flat view for address spaces)",
.cmd        = hmp_info_mtree,
},


{
.name       = "jit",
.args_type  = "",
.params     = "",
.help       = "show dynamic compiler info",
.cmd        = hmp_info_jit,
},


{
.name       = "opcount",
.args_type  = "",
.params     = "",
.help       = "show dynamic compiler opcode counters",
.cmd        = hmp_info_opcount,
},


{
.name       = "kvm",
.args_type  = "",
.params     = "",
.help       = "show KVM information",
.cmd        = hmp_info_kvm,
},


{
.name       = "numa",
.args_type  = "",
.params     = "",
.help       = "show NUMA information",
.cmd        = hmp_info_numa,
},


{
.name       = "usb",
.args_type  = "",
.params     = "",
.help       = "show guest USB devices",
.cmd        = hmp_info_usb,
},


{
.name       = "usbhost",
.args_type  = "",
.params     = "",
.help       = "show host USB devices",
.cmd        = hmp_info_usbhost,
},


{
.name       = "profile",
.args_type  = "",
.params     = "",
.help       = "show profiling information",
.cmd        = hmp_info_profile,
},


{
.name       = "capture",
.args_type  = "",
.params     = "",
.help       = "show capture information",
.cmd        = hmp_info_capture,
},


{
.name       = "snapshots",
.args_type  = "",
.params     = "",
.help       = "show the currently saved VM snapshots",
.cmd        = hmp_info_snapshots,
},


{
.name       = "status",
.args_type  = "",
.params     = "",
.help       = "show the current VM status (running|paused)",
.cmd        = hmp_info_status,
},


{
.name       = "mice",
.args_type  = "",
.params     = "",
.help       = "show which guest mouse is receiving events",
.cmd        = hmp_info_mice,
},


{
.name       = "vnc",
.args_type  = "",
.params     = "",
.help       = "show the vnc server status",
.cmd        = hmp_info_vnc,
},


#if defined(CONFIG_SPICE)
{
.name       = "spice",
.args_type  = "",
.params     = "",
.help       = "show the spice server status",
.cmd        = hmp_info_spice,
},
#endif


{
.name       = "name",
.args_type  = "",
.params     = "",
.help       = "show the current VM name",
.cmd        = hmp_info_name,
},


{
.name       = "uuid",
.args_type  = "",
.params     = "",
.help       = "show the current VM UUID",
.cmd        = hmp_info_uuid,
},


{
.name       = "cpustats",
.args_type  = "",
.params     = "",
.help       = "show CPU statistics",
.cmd        = hmp_info_cpustats,
},


#if defined(CONFIG_SLIRP)
{
.name       = "usernet",
.args_type  = "",
.params     = "",
.help       = "show user network stack connection states",
.cmd        = hmp_info_usernet,
},
#endif


{
.name       = "migrate",
.args_type  = "",
.params     = "",
.help       = "show migration status",
.cmd        = hmp_info_migrate,
},


{
.name       = "migrate_capabilities",
.args_type  = "",
.params     = "",
.help       = "show current migration capabilities",
.cmd        = hmp_info_migrate_capabilities,
},


{
.name       = "migrate_parameters",
.args_type  = "",
.params     = "",
.help       = "show current migration parameters",
.cmd        = hmp_info_migrate_parameters,
},


{
.name       = "migrate_cache_size",
.args_type  = "",
.params     = "",
.help       = "show current migration xbzrle cache size",
.cmd        = hmp_info_migrate_cache_size,
},


{
.name       = "balloon",
.args_type  = "",
.params     = "",
.help       = "show balloon information",
.cmd        = hmp_info_balloon,
},


{
.name       = "qtree",
.args_type  = "",
.params     = "",
.help       = "show device tree",
.cmd        = hmp_info_qtree,
},


{
.name       = "qdm",
.args_type  = "",
.params     = "",
.help       = "show qdev device model list",
.cmd        = hmp_info_qdm,
},


{
.name       = "qom-tree",
.args_type  = "path:s?",
.params     = "[path]",
.help       = "show QOM composition tree",
.cmd        = hmp_info_qom_tree,
},


{
.name       = "roms",
.args_type  = "",
.params     = "",
.help       = "show roms",
.cmd        = hmp_info_roms,
},


{
.name       = "trace-events",
.args_type  = "name:s?,vcpu:i?",
.params     = "[name] [vcpu]",
.help       = "show available trace-events & their state "
"(name: event name pattern; vcpu: vCPU to query, default is any)",
.cmd = hmp_info_trace_events,
.command_completion = info_trace_events_completion,
},


{
.name       = "tpm",
.args_type  = "",
.params     = "",
.help       = "show the TPM device",
.cmd        = hmp_info_tpm,
},


{
.name       = "memdev",
.args_type  = "",
.params     = "",
.help       = "show memory backends",
.cmd        = hmp_info_memdev,
},


{
.name       = "memory-devices",
.args_type  = "",
.params     = "",
.help       = "show memory devices",
.cmd        = hmp_info_memory_devices,
},


{
.name       = "iothreads",
.args_type  = "",
.params     = "",
.help       = "show iothreads",
.cmd        = hmp_info_iothreads,
},


{
.name       = "rocker",
.args_type  = "name:s",
.params     = "name",
.help       = "Show rocker switch",
.cmd        = hmp_rocker,
},


{
.name       = "rocker-ports",
.args_type  = "name:s",
.params     = "name",
.help       = "Show rocker ports",
.cmd        = hmp_rocker_ports,
},


{
.name       = "rocker-of-dpa-flows",
.args_type  = "name:s,tbl_id:i?",
.params     = "name [tbl_id]",
.help       = "Show rocker OF-DPA flow tables",
.cmd        = hmp_rocker_of_dpa_flows,
},


{
.name       = "rocker-of-dpa-groups",
.args_type  = "name:s,type:i?",
.params     = "name [type]",
.help       = "Show rocker OF-DPA groups",
.cmd        = hmp_rocker_of_dpa_groups,
},


#if defined(TARGET_S390X)
{
.name       = "skeys",
.args_type  = "addr:l",
.params     = "address",
.help       = "Display the value of a storage key",
.cmd        = hmp_info_skeys,
},
#endif


{
.name       = "dump",
.args_type  = "",
.params     = "",
.help       = "Display the latest dump status",
.cmd        = hmp_info_dump,
},


{
.name       = "hotpluggable-cpus",
.args_type  = "",
.params     = "",
.help       = "Show information about hotpluggable CPUs",
.cmd        = hmp_hotpluggable_cpus,
},



{
.name       = "vm-generation-id",
.args_type  = "",
.params     = "",
.help       = "Show Virtual Machine Generation ID",
.cmd = hmp_info_vm_generation_id,
},


