/* AUTO-GENERATED FILE FOR QEMU */
#define PARISC_MODEL "9000/778/B160L"
#define PARISC_PDC_MODEL 0x5020, 0x481, 0x0,\
0x2020202, 0x7794d7fe, 0x100000f0, 0x4, 0xba, 0xba
#define PARISC_PDC_VERSION 0x0008
#define PARISC_PDC_CPUID 0x01e8
#define PARISC_PDC_CAPABILITIES 0x0002
#define PARISC_PDC_ENTRY_ORG 0x4800
#define PARISC_PDC_CACHE_INFO\
	0x10000, 0x41402000, 0x0000, 0x0020, 0x0400\
	, 0x0002, 0x10000, 0x41402000, 0x0000, 0x0020\
	, 0x0400, 0x0002, 0x0060, 0xd2000, 0x0000\
	, 0x0000, 0x0001, 0x0000, 0x0000, 0x0001\
	, 0x0001, 0x0060, 0xd2000, 0x0000, 0x0000\
	, 0x0001, 0x0000, 0x0000, 0x0001, 0x0001

#define HPA_ffc00000_DESCRIPTION "Phantom PseudoBC GSC+ Port"
static struct pdc_system_map_mod_info mod_info_hpa_ffc00000 = {
	.mod_addr = 0xffc00000,
	.mod_pgs = 0x1,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_ffc00000 = {
	.path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, .mod = 0x8  },
	.layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_ffc00000 = {
	.hversion_model = 0x0050,
	.hversion = 0x0040,
	.spa = 0x0000,
	.type = 0x0007,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0000,
	.sversion_opt = 0x0000,
	.rev = 0x0000,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x0000,
	.length = 0x0000,
	/* pad: 0x0000, 0x0000 */
};
#define HPA_ffc00000_num_addr 0
#define HPA_ffc00000_add_addr 0

#define HPA_fff80000_DESCRIPTION "Dino PCI Bridge"
static struct pdc_system_map_mod_info mod_info_hpa_fff80000 = {
	.mod_addr = 0xfff80000,
	.mod_pgs = 0x1,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fff80000 = {
	.path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0xff, 0xff, 0x8 }, .mod = 0x0  },
	.layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fff80000 = {
	.hversion_model = 0x0068,
	.hversion = 0x0003,
	.spa = 0x0000,
	.type = 0x004d,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0005,
	.sversion_opt = 0x0000,
	.rev = 0x0000,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x0000,
	.length = 0x0000,
	/* pad: 0x0000, 0x0000 */
};
#define HPA_fff80000_num_addr 0
#define HPA_fff80000_add_addr 0

#define HPA_fff83000_DESCRIPTION "Merlin+ 132 Dino RS-232"
static struct pdc_system_map_mod_info mod_info_hpa_fff83000 = {
	.mod_addr = 0xfff83000,
	.mod_pgs = 0x1,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fff83000 = {
	.path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0xff, 0x8, 0x0 }, .mod = 0x3f  },
	.layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fff83000 = {
	.hversion_model = 0x0002,
	.hversion = 0x0020,
	.spa = 0x0000,
	.type = 0x008a,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0046,
	.sversion_opt = 0x0000,
	.rev = 0x0000,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x6729,
	.length = 0x0002,
	/* pad: 0x0000, 0x0000 */
};
#define HPA_fff83000_num_addr 0
#define HPA_fff83000_add_addr 0

#define HPA_fff8c000_DESCRIPTION "Merlin 160 Core FW-SCSI"
static struct pdc_system_map_mod_info mod_info_hpa_fff8c000 = {
	.mod_addr = 0xfff8c000,
	.mod_pgs = 0x1,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fff8c000 = {
	.path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0xff, 0xff, 0x8 }, .mod = 0xc  },
	.layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fff8c000 = {
	.hversion_model = 0x0003,
	.hversion = 0x00d0,
	.spa = 0x0000,
	.type = 0x0084,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0044,
	.sversion_opt = 0x00c0,
	.rev = 0x0099,
	.dep = 0x0000,
	.features = 0x0001,
	.checksum = 0xc5e9,
	.length = 0x0002,
	/* pad: 0x0000, 0x0000 */
};
#define HPA_fff8c000_num_addr 0
#define HPA_fff8c000_add_addr 0

#define HPA_ffd00000_DESCRIPTION "Merlin 160 Core BA"
static struct pdc_system_map_mod_info mod_info_hpa_ffd00000 = {
	.mod_addr = 0xffd00000,
	.mod_pgs = 0x1,
	.add_addrs = 0x2,
};
static struct pdc_module_path mod_path_hpa_ffd00000 = {
	.path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0xff, 0xff, 0x8 }, .mod = 0x10  },
	.layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_ffd00000 = {
	.hversion_model = 0x0003,
	.hversion = 0x00d0,
	.spa = 0x0080,
	.type = 0x004b,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0040,
	.sversion_opt = 0x0080,
	.rev = 0x0000,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x0000,
	.length = 0x0000,
	/* pad: 0x0000, 0x0000 */
};
#define HPA_ffd00000_num_addr 2
#define HPA_ffd00000_add_addr 0xffd0c000, 0xffc00000,

#define HPA_ffd05000_DESCRIPTION "Merlin 160 Core RS-232"
static struct pdc_system_map_mod_info mod_info_hpa_ffd05000 = {
	.mod_addr = 0xffd05000,
	.mod_pgs = 0x1,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_ffd05000 = {
	.path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0xff, 0x8, 0x10 }, .mod = 0x4  },
	.layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_ffd05000 = {
	.hversion_model = 0x0003,
	.hversion = 0x00d0,
	.spa = 0x0000,
	.type = 0x008a,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0046,
	.sversion_opt = 0x0000,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x6309,
	.length = 0x0002,
	/* pad: 0x0000, 0x0000 */
};
#define HPA_ffd05000_num_addr 0
#define HPA_ffd05000_add_addr 0

#define HPA_ffd06000_DESCRIPTION "Merlin 160 Core SCSI"
static struct pdc_system_map_mod_info mod_info_hpa_ffd06000 = {
	.mod_addr = 0xffd06000,
	.mod_pgs = 0x1,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_ffd06000 = {
	.path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0xff, 0x8, 0x10 }, .mod = 0x5  },
	.layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_ffd06000 = {
	.hversion_model = 0x0003,
	.hversion = 0x00d0,
	.spa = 0x0080,
	.type = 0x008a,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0041,
	.sversion_opt = 0x0000,
	.rev = 0x0099,
	.dep = 0x0000,
	.features = 0x0001,
	.checksum = 0x4d41,
	.length = 0x0002,
	/* pad: 0x0000, 0x0000 */
};
#define HPA_ffd06000_num_addr 0
#define HPA_ffd06000_add_addr 0

#define HPA_ffd07000_DESCRIPTION "Merlin 160 Core LAN (802.3)"
static struct pdc_system_map_mod_info mod_info_hpa_ffd07000 = {
	.mod_addr = 0xffd07000,
	.mod_pgs = 0x1,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_ffd07000 = {
	.path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0xff, 0x8, 0x10 }, .mod = 0x6  },
	.layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_ffd07000 = {
	.hversion_model = 0x0003,
	.hversion = 0x00d0,
	.spa = 0x0080,
	.type = 0x008a,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0045,
	.sversion_opt = 0x0000,
	.rev = 0x0002,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0xd8fa,
	.length = 0x0002,
	/* pad: 0x0000, 0x0000 */
};
#define HPA_ffd07000_num_addr 0
#define HPA_ffd07000_add_addr 0

#define HPA_ffd02000_DESCRIPTION "Merlin 160 Core Centronics"
static struct pdc_system_map_mod_info mod_info_hpa_ffd02000 = {
	.mod_addr = 0xffd02000,
	.mod_pgs = 0x1,
	.add_addrs = 0x2,
};
static struct pdc_module_path mod_path_hpa_ffd02000 = {
	.path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0xff, 0x8, 0x10 }, .mod = 0x0  },
	.layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_ffd02000 = {
	.hversion_model = 0x0003,
	.hversion = 0x00d0,
	.spa = 0x0080,
	.type = 0x000a,
	.sversion_rev = 0x0000,
	.sversion_model = 0x003a,
	.sversion_opt = 0x0000,
	.rev = 0x0000,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x0000,
	.length = 0x0000,
	/* pad: 0x0000, 0x0000 */
};
#define HPA_ffd02000_num_addr 2
#define HPA_ffd02000_add_addr 0xffd01000, 0xffd03000,

#define HPA_ffd04000_DESCRIPTION "Merlin 160 Core Audio"
static struct pdc_system_map_mod_info mod_info_hpa_ffd04000 = {
	.mod_addr = 0xffd04000,
	.mod_pgs = 0x1,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_ffd04000 = {
	.path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0xff, 0x8, 0x10 }, .mod = 0x1  },
	.layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_ffd04000 = {
	.hversion_model = 0x0003,
	.hversion = 0x00d4,
	.spa = 0x0080,
	.type = 0x000a,
	.sversion_rev = 0x0000,
	.sversion_model = 0x003d,
	.sversion_opt = 0x0080,
	.rev = 0x0000,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x0000,
	.length = 0x0000,
	/* pad: 0x0000, 0x0000 */
};
#define HPA_ffd04000_num_addr 0
#define HPA_ffd04000_add_addr 0

#define HPA_ffd08000_DESCRIPTION "Merlin 160 Core PS/2 Port"
static struct pdc_system_map_mod_info mod_info_hpa_ffd08000 = {
	.mod_addr = 0xffd08000,
	.mod_pgs = 0x1,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_ffd08000 = {
	.path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0xff, 0x8, 0x10 }, .mod = 0x7  },
	.layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_ffd08000 = {
	.hversion_model = 0x0003,
	.hversion = 0x00d0,
	.spa = 0x0000,
	.type = 0x008a,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0042,
	.sversion_opt = 0x0000,
	.rev = 0x0000,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x6e05,
	.length = 0x0002,
	/* pad: 0x0000, 0x0000 */
};
#define HPA_ffd08000_num_addr 0
#define HPA_ffd08000_add_addr 0

#define HPA_ffd08100_DESCRIPTION "Merlin 160 Core PS/2 Port"
static struct pdc_system_map_mod_info mod_info_hpa_ffd08100 = {
	.mod_addr = 0xffd08100,
	.mod_pgs = 0x1,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_ffd08100 = {
	.path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0xff, 0x8, 0x10 }, .mod = 0x8  },
	.layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_ffd08100 = {
	.hversion_model = 0x0003,
	.hversion = 0x00d0,
	.spa = 0x0000,
	.type = 0x000a,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0042,
	.sversion_opt = 0x0000,
	.rev = 0x0000,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x0000,
	.length = 0x0000,
	/* pad: 0x0000, 0x0000 */
};
#define HPA_ffd08100_num_addr 0
#define HPA_ffd08100_add_addr 0

#define HPA_fa000000_DESCRIPTION "Coral SGC Graphics"
static struct pdc_system_map_mod_info mod_info_hpa_fa000000 = {
	.mod_addr = 0xfa000000,
	.mod_pgs = 0x2000,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fa000000 = {
	.path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0xff, 0xff, 0x8 }, .mod = 0x4  },
	.layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fa000000 = {
	.hversion_model = 0x0000,
	.hversion = 0x0040,
	.spa = 0x0000,
	.type = 0x008a,
	.sversion_rev = 0x0000,
	.sversion_model = 0x003b,
	.sversion_opt = 0x0080,
	.rev = 0x00fa,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x67d0,
	.length = 0x0002,
	/* pad: 0x0000, 0x0000 */
};
#define HPA_fa000000_num_addr 0
#define HPA_fa000000_add_addr 0

#define HPA_f4000000_DESCRIPTION "Coral SGC Graphics"
static struct pdc_system_map_mod_info mod_info_hpa_f4000000 = {
	.mod_addr = 0xf4000000,
	.mod_pgs = 0x2000,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_f4000000 = {
	.path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0xff, 0xff, 0x8 }, .mod = 0x8  },
	.layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_f4000000 = {
	.hversion_model = 0x0000,
	.hversion = 0x0040,
	.spa = 0x0000,
	.type = 0x008a,
	.sversion_rev = 0x0000,
	.sversion_model = 0x003b,
	.sversion_opt = 0x0080,
	.rev = 0x00f4,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x67d0,
	.length = 0x0002,
	/* pad: 0x0000, 0x0000 */
};
#define HPA_f4000000_num_addr 0
#define HPA_f4000000_add_addr 0

#define HPA_f8000000_DESCRIPTION "Gecko GSC Core Graphics"
static struct pdc_system_map_mod_info mod_info_hpa_f8000000 = {
	.mod_addr = 0xf8000000,
	.mod_pgs = 0x2000,
	.add_addrs = 0x1,
};
static struct pdc_module_path mod_path_hpa_f8000000 = {
	.path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, .mod = 0x1  },
	.layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_f8000000 = {
	.hversion_model = 0x0001,
	.hversion = 0x0060,
	.spa = 0x0000,
	.type = 0x008a,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0042,
	.sversion_opt = 0x0080,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x67d0,
	.length = 0x0002,
	/* pad: 0x0000, 0x0000 */
};
#define HPA_f8000000_num_addr 0
#define HPA_f8000000_add_addr 0

#define HPA_fff10000_DESCRIPTION "Merlin L2 160 (9000/778/B160L)"
static struct pdc_system_map_mod_info mod_info_hpa_fff10000 = {
	.mod_addr = CPU_HPA,
	.mod_pgs = 0x1,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fff10000 = {
	.path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, .mod = 0x3e  },
	.layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fff10000 = {
	.hversion_model = 0x0050,
	.hversion = 0x0020,
	.spa = 0x0000,
	.type = 0x0040,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0002,
	.sversion_opt = 0x0040,
	.rev = 0x0000,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x0000,
	.length = 0x0000,
	/* pad: 0x0000, 0x0000 */
};
#define HPA_fff10000_num_addr 0
#define HPA_fff10000_add_addr 0

#define HPA_fffbf000_DESCRIPTION "Memory"
static struct pdc_system_map_mod_info mod_info_hpa_fffbf000 = {
	.mod_addr = 0xfffbf000,
	.mod_pgs = 0x1,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffbf000 = {
	.path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, .mod = 0x3f  },
	.layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffbf000 = {
	.hversion_model = 0x0006,
	.hversion = 0x0070,
	.spa = 0x001f,
	.type = 0x0041,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0004,
	.sversion_opt = 0x0080,
	.rev = 0x0000,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x0000,
	.length = 0x0000,
	/* pad: 0x0000, 0x0000 */
};
#define HPA_fffbf000_num_addr 0
#define HPA_fffbf000_add_addr 0

#define HPA_fff81000_DESCRIPTION "Merlin+ 132 Dino PS/2 Port"
static struct pdc_system_map_mod_info mod_info_hpa_fff81000 = {
	.mod_addr = 0x0,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fff81000 = {
	.path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0xff, 0xff, 0x8 }, .mod = 0x0  },
	.layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fff81000 = {
	.hversion_model = 0x0002,
	.hversion = 0x0020,
	.spa = 0x0080,
	.type = 0x004a,
	.sversion_rev = 0x0000,
	.sversion_model = 0x004b,
	.sversion_opt = 0x0000,
	.rev = 0x0000,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x0000,
	.length = 0x0000,
	/* pad: 0x0000, 0x0000 */
};
#define HPA_fff81000_num_addr 0
#define HPA_fff81000_add_addr 0

#define PARISC_DEVICE_LIST \
	{	.hpa = 0xffc00000,\
		.iodc = &iodc_data_hpa_ffc00000,\
		.mod_info = &mod_info_hpa_ffc00000,\
		.mod_path = &mod_path_hpa_ffc00000,\
		.num_addr = HPA_ffc00000_num_addr,\
		.add_addr = { HPA_ffc00000_add_addr } },\
	{	.hpa = 0xfff80000,\
		.iodc = &iodc_data_hpa_fff80000,\
		.mod_info = &mod_info_hpa_fff80000,\
		.mod_path = &mod_path_hpa_fff80000,\
		.num_addr = HPA_fff80000_num_addr,\
		.add_addr = { HPA_fff80000_add_addr } },\
	{	.hpa = 0xfff83000,\
		.iodc = &iodc_data_hpa_fff83000,\
		.mod_info = &mod_info_hpa_fff83000,\
		.mod_path = &mod_path_hpa_fff83000,\
		.num_addr = HPA_fff83000_num_addr,\
		.add_addr = { HPA_fff83000_add_addr } },\
	{	.hpa = 0xfff8c000,\
		.iodc = &iodc_data_hpa_fff8c000,\
		.mod_info = &mod_info_hpa_fff8c000,\
		.mod_path = &mod_path_hpa_fff8c000,\
		.num_addr = HPA_fff8c000_num_addr,\
		.add_addr = { HPA_fff8c000_add_addr } },\
	{	.hpa = 0xffd00000,\
		.iodc = &iodc_data_hpa_ffd00000,\
		.mod_info = &mod_info_hpa_ffd00000,\
		.mod_path = &mod_path_hpa_ffd00000,\
		.num_addr = HPA_ffd00000_num_addr,\
		.add_addr = { HPA_ffd00000_add_addr } },\
	{	.hpa = 0xffd05000,\
		.iodc = &iodc_data_hpa_ffd05000,\
		.mod_info = &mod_info_hpa_ffd05000,\
		.mod_path = &mod_path_hpa_ffd05000,\
		.num_addr = HPA_ffd05000_num_addr,\
		.add_addr = { HPA_ffd05000_add_addr } },\
	{	.hpa = 0xffd06000,\
		.iodc = &iodc_data_hpa_ffd06000,\
		.mod_info = &mod_info_hpa_ffd06000,\
		.mod_path = &mod_path_hpa_ffd06000,\
		.num_addr = HPA_ffd06000_num_addr,\
		.add_addr = { HPA_ffd06000_add_addr } },\
	{	.hpa = 0xffd07000,\
		.iodc = &iodc_data_hpa_ffd07000,\
		.mod_info = &mod_info_hpa_ffd07000,\
		.mod_path = &mod_path_hpa_ffd07000,\
		.num_addr = HPA_ffd07000_num_addr,\
		.add_addr = { HPA_ffd07000_add_addr } },\
	{	.hpa = 0xffd02000,\
		.iodc = &iodc_data_hpa_ffd02000,\
		.mod_info = &mod_info_hpa_ffd02000,\
		.mod_path = &mod_path_hpa_ffd02000,\
		.num_addr = HPA_ffd02000_num_addr,\
		.add_addr = { HPA_ffd02000_add_addr } },\
	{	.hpa = 0xffd04000,\
		.iodc = &iodc_data_hpa_ffd04000,\
		.mod_info = &mod_info_hpa_ffd04000,\
		.mod_path = &mod_path_hpa_ffd04000,\
		.num_addr = HPA_ffd04000_num_addr,\
		.add_addr = { HPA_ffd04000_add_addr } },\
	{	.hpa = 0xffd08000,\
		.iodc = &iodc_data_hpa_ffd08000,\
		.mod_info = &mod_info_hpa_ffd08000,\
		.mod_path = &mod_path_hpa_ffd08000,\
		.num_addr = HPA_ffd08000_num_addr,\
		.add_addr = { HPA_ffd08000_add_addr } },\
	{	.hpa = 0xffd08100,\
		.iodc = &iodc_data_hpa_ffd08100,\
		.mod_info = &mod_info_hpa_ffd08100,\
		.mod_path = &mod_path_hpa_ffd08100,\
		.num_addr = HPA_ffd08100_num_addr,\
		.add_addr = { HPA_ffd08100_add_addr } },\
	{	.hpa = 0xfa000000,\
		.iodc = &iodc_data_hpa_fa000000,\
		.mod_info = &mod_info_hpa_fa000000,\
		.mod_path = &mod_path_hpa_fa000000,\
		.num_addr = HPA_fa000000_num_addr,\
		.add_addr = { HPA_fa000000_add_addr } },\
	{	.hpa = 0xf4000000,\
		.iodc = &iodc_data_hpa_f4000000,\
		.mod_info = &mod_info_hpa_f4000000,\
		.mod_path = &mod_path_hpa_f4000000,\
		.num_addr = HPA_f4000000_num_addr,\
		.add_addr = { HPA_f4000000_add_addr } },\
	{	.hpa = 0xf8000000,\
		.iodc = &iodc_data_hpa_f8000000,\
		.mod_info = &mod_info_hpa_f8000000,\
		.mod_path = &mod_path_hpa_f8000000,\
		.num_addr = HPA_f8000000_num_addr,\
		.add_addr = { HPA_f8000000_add_addr } },\
	{	.hpa = CPU_HPA,\
		.iodc = &iodc_data_hpa_fff10000,\
		.mod_info = &mod_info_hpa_fff10000,\
		.mod_path = &mod_path_hpa_fff10000,\
		.num_addr = HPA_fff10000_num_addr,\
		.add_addr = { HPA_fff10000_add_addr } },\
	{	.hpa = 0xfffbf000,\
		.iodc = &iodc_data_hpa_fffbf000,\
		.mod_info = &mod_info_hpa_fffbf000,\
		.mod_path = &mod_path_hpa_fffbf000,\
		.num_addr = HPA_fffbf000_num_addr,\
		.add_addr = { HPA_fffbf000_add_addr } },\
	{	.hpa = 0xfff81000,\
		.iodc = &iodc_data_hpa_fff81000,\
		.mod_info = &mod_info_hpa_fff81000,\
		.mod_path = &mod_path_hpa_fff81000,\
		.num_addr = HPA_fff81000_num_addr,\
		.add_addr = { HPA_fff81000_add_addr } },\
	{ 0, }
