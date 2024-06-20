/* HP 715/64 */

/* AUTO-GENERATED HEADER FILE FOR SEABIOS FIRMWARE */
/* generated with Linux kernel */
/* search for PARISC_QEMU_MACHINE_HEADER in Linux */

#if 0
1. Mirage Jr GSC Builtin Graphics [1] at 0xf8000000 { type:10, hv:0x12, sv:0x85, rev:0x0 }
2. Mirage Jr Core BA [2] at 0xf0100000 { type:11, hv:0x28, sv:0x81, rev:0x0 }
3. Mirage Jr Core SCSI [2:0:1] at 0xf0106000 { type:10, hv:0x28, sv:0x82, rev:0x0 }
4. Mirage Jr Core LAN (802.3) [2:0:2] at 0xf0107000 { type:10, hv:0x28, sv:0x8a, rev:0x0 }
5. Mirage Jr Core RS-232 [2:0:4] at 0xf0105000 { type:10, hv:0x28, sv:0x8c, rev:0x0 }
6. Mirage Jr Core Centronics [2:0:6] at 0xf0102000 { type:10, hv:0x28, sv:0x74, rev:0x0 }
7. Mirage Jr Audio [2:0:8] at 0xf0104000 { type:10, hv:0x28, sv:0x7b, rev:0x0 }
8. Mirage Jr Core PC Floppy [2:0:10] at 0xf010a000 { type:10, hv:0x28, sv:0x83, rev:0x0 }
9. Mirage Jr Core PS/2 Port [2:0:11] at 0xf0108000 { type:10, hv:0x28, sv:0x84, rev:0x0 }
10. Mirage Jr Core PS/2 Port [2:0:12] at 0xf0108100 { type:10, hv:0x28, sv:0x84, rev:0x0 }
11. Mirage Jr Wax EISA BA [4] at 0xfc000000 { type:11, hv:0x28, sv:0x90, rev:0x0 }
12. Mirage Jr Wax BA [5] at 0xf0200000 { type:11, hv:0x12, sv:0x8e, rev:0x0 }
13. Mirage Jr Wax HIL [5:0:1] at 0xf0201000 { type:10, hv:0x12, sv:0x73, rev:0x0 }
14. Mirage Jr Wax RS-232 [5:0:2] at 0xf0202000 { type:10, hv:0x12, sv:0x8c, rev:0x0 }
15. Mirage Jr (715/64) [8] at 0xfffbe000 { type:0, hv:0x60a, sv:0x4, rev:0x0 }
16. Memory [9] at 0xfffbf000 { type:1, hv:0x4a, sv:0x9, rev:0x0 }
#endif

#define PARISC_MODEL "9000/715"

#define PARISC_PDC_MODEL 0x60a0, 0x481, 0x0, 0x0, 0x0, 0x0, 0x4, 0x72, 0x72, 0x0

#define PARISC_PDC_VERSION 0x000c

#define PARISC_PDC_CPUID 0x0000

#define PARISC_PDC_CAPABILITIES 0x0002

#define PARISC_PDC_ENTRY_ORG 0xf0012870

#define PARISC_PDC_CACHE_INFO \
	0x20000, 0x61402000, 0x0000, 0x0020, 0x1000 \
	, 0x0001, 0x20000, 0x61402000, 0x0000, 0x0020 \
	, 0x1000, 0x0001, 0x0040, 0xd2000, 0x0000 \
	, 0x0000, 0x0001, 0x0000, 0x0000, 0x0001 \
	, 0x0001, 0x0040, 0xd2000, 0x0000, 0x0000 \
	, 0x0001, 0x0000, 0x0000, 0x0001, 0x0001


#define HPA_f8000000_715_DESCRIPTION "Mirage Jr GSC Builtin Graphics"
static struct pdc_system_map_mod_info mod_info_hpa_f8000000_715 = {
	.mod_addr = 0x52,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_f8000000_715 = {
	.path = { .flags = 0x1, .bc = { 0x20, 0x80, 0x8a, 0x0, 0x0, 0x85 }, .mod = 0x0  },
	.layers = { 0x1000000, 0xed260002, 0x0, 0xf, 0x114b6b5c, 0x114a1de8 }
};
static struct pdc_iodc iodc_data_hpa_f8000000_715 = {
	.hversion_model = 0x0001,
	.hversion = 0x0020,
	.spa = 0x0080,
	.type = 0x008a,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0042,
	.sversion_opt = 0x0080,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0xed26,
	.length = 0x0002,
	/* pad: 0x0000, 0x000f */
};
#define HPA_f8000000_715_num_addr 0
#define HPA_f8000000_715_add_addr 0


#define HPA_f0100000_DESCRIPTION "Mirage Jr Core BA"
static struct pdc_system_map_mod_info mod_info_hpa_f0100000 = {
	.mod_addr = 0x45,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_f0100000 = {
	.path = { .flags = 0x2, .bc = { 0x80, 0x80, 0x8b, 0x0, 0x0, 0x81 }, .mod = 0x0  },
	.layers = { 0x0, 0xfbe50000, 0x0, 0xf, 0x114b6b5c, 0x114a1de8 }
};
static struct pdc_iodc iodc_data_hpa_f0100000 = {
	.hversion_model = 0x0002,
	.hversion = 0x0080,
	.spa = 0x0080,
	.type = 0x008b,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0040,
	.sversion_opt = 0x0080,
	.rev = 0x0000,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0xfbe5,
	.length = 0x0000,
	/* pad: 0x0000, 0x000f */
};
#define HPA_f0100000_num_addr 0
#define HPA_f0100000_add_addr 0

#define HPA_f0106000_DESCRIPTION "Mirage Jr Core SCSI"
static struct pdc_system_map_mod_info mod_info_hpa_f0106000 = {
	.mod_addr = 0x47,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_f0106000 = {
	.path = { .flags = 0x2, .bc = { 0x80, 0x80, 0x8a, 0x0, 0x0, 0x82 }, .mod = 0x0  },
	.layers = { 0x1000000, 0xe8a10002, 0x0, 0xf, 0x114b6b5c, 0x114a1de8 }
};
static struct pdc_iodc iodc_data_hpa_f0106000 = {
	.hversion_model = 0x0002,
	.hversion = 0x0080,
	.spa = 0x0080,
	.type = 0x008a,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0041,
	.sversion_opt = 0x0000,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0xe8a1,
	.length = 0x0002,
	/* pad: 0x0000, 0x000f */
};
#define HPA_f0106000_num_addr 0
#define HPA_f0106000_add_addr 0


#define HPA_f0107000_DESCRIPTION "Mirage Jr Core LAN (802.3)"
static struct pdc_system_map_mod_info mod_info_hpa_f0107000 = {
	.mod_addr = 0x4e,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_f0107000 = {
	.path = { .flags = 0x2, .bc = { 0x80, 0x80, 0x8a, 0x0, 0x0, 0x8a }, .mod = 0x0  },
	.layers = { 0x2000000, 0xda120002, 0x0, 0xf, 0x114b6b5c, 0x114a1de8 }
};
static struct pdc_iodc iodc_data_hpa_f0107000 = {
	.hversion_model = 0x0002,
	.hversion = 0x0080,
	.spa = 0x0080,
	.type = 0x008a,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0045,
	.sversion_opt = 0x0000,
	.rev = 0x0002,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0xda12,
	.length = 0x0002,
	/* pad: 0x0000, 0x000f */
};
#define HPA_f0107000_num_addr 0
#define HPA_f0107000_add_addr 0


#define HPA_f0105000_DESCRIPTION "Mirage Jr Core RS-232"
static struct pdc_system_map_mod_info mod_info_hpa_f0105000 = {
	.mod_addr = 0x49,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_f0105000 = {
	.path = { .flags = 0x2, .bc = { 0x80, 0x80, 0x8a, 0x0, 0x0, 0x8c }, .mod = 0x0  },
	.layers = { 0x1000000, 0xe3f30002, 0x0, 0xf, 0x114b6b5c, 0x114a1de8 }
};
static struct pdc_iodc iodc_data_hpa_f0105000 = {
	.hversion_model = 0x0002,
	.hversion = 0x0080,
	.spa = 0x0080,
	.type = 0x008a,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0046,
	.sversion_opt = 0x0000,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0xe3f3,
	.length = 0x0002,
	/* pad: 0x0000, 0x000f */
};
#define HPA_f0105000_num_addr 0
#define HPA_f0105000_add_addr 0


#define HPA_f0102000_DESCRIPTION "Mirage Jr Core Centronics"
static struct pdc_system_map_mod_info mod_info_hpa_f0102000 = {
	.mod_addr = 0x4d,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_f0102000 = {
	.path = { .flags = 0x2, .bc = { 0x80, 0x80, 0xa, 0x0, 0x0, 0x74 }, .mod = 0x0  },
	.layers = { 0x1000000, 0xe3f30002, 0x0, 0xf, 0x114b6b5c, 0x114a1de8 }
};
static struct pdc_iodc iodc_data_hpa_f0102000 = {
	.hversion_model = 0x0002,
	.hversion = 0x0080,
	.spa = 0x0080,
	.type = 0x000a,
	.sversion_rev = 0x0000,
	.sversion_model = 0x003a,
	.sversion_opt = 0x0000,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0xe3f3,
	.length = 0x0002,
	/* pad: 0x0000, 0x000f */
};
#define HPA_f0102000_num_addr 0
#define HPA_f0102000_add_addr 0


#define HPA_f0104000_DESCRIPTION "Mirage Jr Audio"
static struct pdc_system_map_mod_info mod_info_hpa_f0104000 = {
	.mod_addr = 0x43,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_f0104000 = {
	.path = { .flags = 0x2, .bc = { 0x80, 0x80, 0xa, 0x0, 0x0, 0x7b }, .mod = 0x0  },
	.layers = { 0x1000000, 0xe3f30002, 0x0, 0xf, 0x114b6b5c, 0x114a1de8 }
};
static struct pdc_iodc iodc_data_hpa_f0104000 = {
	.hversion_model = 0x0002,
	.hversion = 0x0080,
	.spa = 0x0080,
	.type = 0x000a,
	.sversion_rev = 0x0000,
	.sversion_model = 0x003d,
	.sversion_opt = 0x0080,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0xe3f3,
	.length = 0x0002,
	/* pad: 0x0000, 0x000f */
};
#define HPA_f0104000_num_addr 0
#define HPA_f0104000_add_addr 0


#define HPA_f010a000_DESCRIPTION "Mirage Jr Core PC Floppy"
static struct pdc_system_map_mod_info mod_info_hpa_f010a000 = {
	.mod_addr = 0x4c,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_f010a000 = {
	.path = { .flags = 0x2, .bc = { 0x80, 0x80, 0xa, 0x0, 0x0, 0x83 }, .mod = 0x0  },
	.layers = { 0x1000000, 0xe3f30002, 0x0, 0xf, 0x114b6b5c, 0x114a1de8 }
};
static struct pdc_iodc iodc_data_hpa_f010a000 = {
	.hversion_model = 0x0002,
	.hversion = 0x0080,
	.spa = 0x0080,
	.type = 0x000a,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0041,
	.sversion_opt = 0x0080,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0xe3f3,
	.length = 0x0002,
	/* pad: 0x0000, 0x000f */
};
#define HPA_f010a000_num_addr 0
#define HPA_f010a000_add_addr 0


#define HPA_f0108000_DESCRIPTION "Mirage Jr Core PS/2 Port"
static struct pdc_system_map_mod_info mod_info_hpa_f0108000 = {
	.mod_addr = 0x4c,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_f0108000 = {
	.path = { .flags = 0x2, .bc = { 0x80, 0x80, 0x8a, 0x0, 0x0, 0x84 }, .mod = 0x0  },
	.layers = { 0x1000000, 0xedbd0002, 0x0, 0xf, 0x114b6b5c, 0x114a1de8 }
};
static struct pdc_iodc iodc_data_hpa_f0108000 = {
	.hversion_model = 0x0002,
	.hversion = 0x0080,
	.spa = 0x0080,
	.type = 0x008a,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0042,
	.sversion_opt = 0x0000,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0xedbd,
	.length = 0x0002,
	/* pad: 0x0000, 0x000f */
};
#define HPA_f0108000_num_addr 0
#define HPA_f0108000_add_addr 0


#define HPA_f0108100_DESCRIPTION "Mirage Jr Core PS/2 Port"
static struct pdc_system_map_mod_info mod_info_hpa_f0108100 = {
	.mod_addr = 0x4c,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_f0108100 = {
	.path = { .flags = 0x2, .bc = { 0x80, 0x80, 0x8a, 0x0, 0x0, 0x84 }, .mod = 0x0  },
	.layers = { 0x1000000, 0xedbd0002, 0x0, 0xf, 0x114b6b5c, 0x114a1de8 }
};
static struct pdc_iodc iodc_data_hpa_f0108100 = {
	.hversion_model = 0x0002,
	.hversion = 0x0080,
	.spa = 0x0080,
	.type = 0x008a,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0042,
	.sversion_opt = 0x0000,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0xedbd,
	.length = 0x0002,
	/* pad: 0x0000, 0x000f */
};
#define HPA_f0108100_num_addr 0
#define HPA_f0108100_add_addr 0


#define HPA_fc000000_DESCRIPTION "Mirage Jr Wax EISA BA"
static struct pdc_system_map_mod_info mod_info_hpa_fc000000 = {
	.mod_addr = 0x49,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fc000000 = {
	.path = { .flags = 0x2, .bc = { 0x80, 0x1a, 0xb, 0x0, 0x0, 0x90 }, .mod = 0x0  },
	.layers = { 0x1000000, 0xedbd0002, 0x0, 0xf, 0x114b6b5c, 0x114a1de8 }
};
static struct pdc_iodc iodc_data_hpa_fc000000 = {
	.hversion_model = 0x0002,
	.hversion = 0x0080,
	.spa = 0x001a,
	.type = 0x000b,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0048,
	.sversion_opt = 0x0000,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0xedbd,
	.length = 0x0002,
	/* pad: 0x0000, 0x000f */
};
#define HPA_fc000000_num_addr 0
#define HPA_fc000000_add_addr 0


#define HPA_f0200000_DESCRIPTION "Mirage Jr Wax BA"
static struct pdc_system_map_mod_info mod_info_hpa_f0200000 = {
	.mod_addr = 0x44,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_f0200000 = {
	.path = { .flags = 0x1, .bc = { 0x20, 0x1a, 0xb, 0x0, 0x0, 0x8e }, .mod = 0x0  },
	.layers = { 0x1000000, 0xedbd0002, 0x0, 0xf, 0x114b6b5c, 0x114a1de8 }
};
static struct pdc_iodc iodc_data_hpa_f0200000 = {
	.hversion_model = 0x0001,
	.hversion = 0x0020,
	.spa = 0x001a,
	.type = 0x000b,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0047,
	.sversion_opt = 0x0000,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0xedbd,
	.length = 0x0002,
	/* pad: 0x0000, 0x000f */
};
#define HPA_f0200000_num_addr 0
#define HPA_f0200000_add_addr 0

#define HPA_f0201000_DESCRIPTION "Mirage Jr Wax HIL"
static struct pdc_system_map_mod_info mod_info_hpa_f0201000 = {
	.mod_addr = 0x45,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_f0201000 = {
	.path = { .flags = 0x1, .bc = { 0x20, 0x0, 0x8a, 0x0, 0x0, 0x73 }, .mod = 0x0  },
	.layers = { 0x1000000, 0x81670002, 0x0, 0xf, 0x114b6b5c, 0x114a1de8 }
};
static struct pdc_iodc iodc_data_hpa_f0201000 = {
	.hversion_model = 0x0001,
	.hversion = 0x0020,
	.spa = 0x0000,
	.type = 0x008a,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0039,
	.sversion_opt = 0x0080,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x8167,
	.length = 0x0002,
	/* pad: 0x0000, 0x000f */
};
#define HPA_f0201000_num_addr 0
#define HPA_f0201000_add_addr 0


#define HPA_f0202000_DESCRIPTION "Mirage Jr Wax RS-232"
static struct pdc_system_map_mod_info mod_info_hpa_f0202000 = {
	.mod_addr = 0x48,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_f0202000 = {
	.path = { .flags = 0x1, .bc = { 0x20, 0x80, 0x8a, 0x0, 0x0, 0x8c }, .mod = 0x0  },
	.layers = { 0x1000000, 0xe3f30002, 0x0, 0xf, 0x114b6b5c, 0x114a1de8 }
};
static struct pdc_iodc iodc_data_hpa_f0202000 = {
	.hversion_model = 0x0001,
	.hversion = 0x0020,
	.spa = 0x0080,
	.type = 0x008a,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0046,
	.sversion_opt = 0x0000,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0xe3f3,
	.length = 0x0002,
	/* pad: 0x0000, 0x000f */
};
#define HPA_f0202000_num_addr 0
#define HPA_f0202000_add_addr 0


#define HPA_fffbe000_DESCRIPTION "Mirage Jr (715/64)"
static struct pdc_system_map_mod_info mod_info_hpa_fffbe000 = {
	.mod_addr = 0x46,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffbe000 = {
	.path = { .flags = 0x60, .bc = { 0xa0, 0x0, 0x0, 0x0, 0x0, 0x4 }, .mod = 0x81  },
	.layers = { 0x1000000, 0xe3f30002, 0x0, 0xf, 0x114b6b5c, 0x114a1de8 }
};
static struct pdc_iodc iodc_data_hpa_fffbe000 = {
	.hversion_model = 0x0060,
	.hversion = 0x00a0,
	.spa = 0x0000,
	.type = 0x0000,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0002,
	.sversion_opt = 0x0040,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0xe3f3,
	.length = 0x0002,
	/* pad: 0x0000, 0x000f */
};
#define HPA_fffbe000_num_addr 0
#define HPA_fffbe000_add_addr 0


#define HPA_fffbf000_715_DESCRIPTION "Memory"
static struct pdc_system_map_mod_info mod_info_hpa_fffbf000_715 = {
	.mod_addr = 0x3a,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffbf000_715 = {
	.path = { .flags = 0x4, .bc = { 0xa0, 0x1c, 0x1, 0x0, 0x0, 0x9 }, .mod = 0x0  },
	.layers = { 0x1000000, 0xe3f30002, 0x0, 0xf, 0x114b6b5c, 0x114a1de8 }
};
static struct pdc_iodc iodc_data_hpa_fffbf000_715 = {
	.hversion_model = 0x0004,
	.hversion = 0x00a0,
	.spa = 0x001c,
	.type = 0x0001,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0004,
	.sversion_opt = 0x0080,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0xe3f3,
	.length = 0x0002,
	/* pad: 0x0000, 0x000f */
};
#define HPA_fffbf000_715_num_addr 0
#define HPA_fffbf000_715_add_addr 0



#define PARISC_DEVICE_LIST \
	{	.hpa = 0xf8000000,\
		.iodc = &iodc_data_hpa_f8000000_715,\
		.mod_info = &mod_info_hpa_f8000000_715,\
		.mod_path = &mod_path_hpa_f8000000_715,\
		.num_addr = HPA_f8000000_715_num_addr,\
		.add_addr = { HPA_f8000000_715_add_addr } },\
	{	.hpa = 0xf0100000,\
		.iodc = &iodc_data_hpa_f0100000,\
		.mod_info = &mod_info_hpa_f0100000,\
		.mod_path = &mod_path_hpa_f0100000,\
		.num_addr = HPA_f0100000_num_addr,\
		.add_addr = { HPA_f0100000_add_addr } },\
	{	.hpa = 0xf0106000,\
		.iodc = &iodc_data_hpa_f0106000,\
		.mod_info = &mod_info_hpa_f0106000,\
		.mod_path = &mod_path_hpa_f0106000,\
		.num_addr = HPA_f0106000_num_addr,\
		.add_addr = { HPA_f0106000_add_addr } },\
	{	.hpa = 0xf0107000,\
		.iodc = &iodc_data_hpa_f0107000,\
		.mod_info = &mod_info_hpa_f0107000,\
		.mod_path = &mod_path_hpa_f0107000,\
		.num_addr = HPA_f0107000_num_addr,\
		.add_addr = { HPA_f0107000_add_addr } },\
	{	.hpa = 0xf0105000,\
		.iodc = &iodc_data_hpa_f0105000,\
		.mod_info = &mod_info_hpa_f0105000,\
		.mod_path = &mod_path_hpa_f0105000,\
		.num_addr = HPA_f0105000_num_addr,\
		.add_addr = { HPA_f0105000_add_addr } },\
	{	.hpa = 0xf0102000,\
		.iodc = &iodc_data_hpa_f0102000,\
		.mod_info = &mod_info_hpa_f0102000,\
		.mod_path = &mod_path_hpa_f0102000,\
		.num_addr = HPA_f0102000_num_addr,\
		.add_addr = { HPA_f0102000_add_addr } },\
	{	.hpa = 0xf0104000,\
		.iodc = &iodc_data_hpa_f0104000,\
		.mod_info = &mod_info_hpa_f0104000,\
		.mod_path = &mod_path_hpa_f0104000,\
		.num_addr = HPA_f0104000_num_addr,\
		.add_addr = { HPA_f0104000_add_addr } },\
	{	.hpa = 0xf010a000,\
		.iodc = &iodc_data_hpa_f010a000,\
		.mod_info = &mod_info_hpa_f010a000,\
		.mod_path = &mod_path_hpa_f010a000,\
		.num_addr = HPA_f010a000_num_addr,\
		.add_addr = { HPA_f010a000_add_addr } },\
	{	.hpa = 0xf0108000,\
		.iodc = &iodc_data_hpa_f0108000,\
		.mod_info = &mod_info_hpa_f0108000,\
		.mod_path = &mod_path_hpa_f0108000,\
		.num_addr = HPA_f0108000_num_addr,\
		.add_addr = { HPA_f0108000_add_addr } },\
	{	.hpa = 0xf0108100,\
		.iodc = &iodc_data_hpa_f0108100,\
		.mod_info = &mod_info_hpa_f0108100,\
		.mod_path = &mod_path_hpa_f0108100,\
		.num_addr = HPA_f0108100_num_addr,\
		.add_addr = { HPA_f0108100_add_addr } },\
	{	.hpa = 0xfc000000,\
		.iodc = &iodc_data_hpa_fc000000,\
		.mod_info = &mod_info_hpa_fc000000,\
		.mod_path = &mod_path_hpa_fc000000,\
		.num_addr = HPA_fc000000_num_addr,\
		.add_addr = { HPA_fc000000_add_addr } },\
	{	.hpa = 0xf0200000,\
		.iodc = &iodc_data_hpa_f0200000,\
		.mod_info = &mod_info_hpa_f0200000,\
		.mod_path = &mod_path_hpa_f0200000,\
		.num_addr = HPA_f0200000_num_addr,\
		.add_addr = { HPA_f0200000_add_addr } },\
	{	.hpa = 0xf0201000,\
		.iodc = &iodc_data_hpa_f0201000,\
		.mod_info = &mod_info_hpa_f0201000,\
		.mod_path = &mod_path_hpa_f0201000,\
		.num_addr = HPA_f0201000_num_addr,\
		.add_addr = { HPA_f0201000_add_addr } },\
	{	.hpa = 0xf0202000,\
		.iodc = &iodc_data_hpa_f0202000,\
		.mod_info = &mod_info_hpa_f0202000,\
		.mod_path = &mod_path_hpa_f0202000,\
		.num_addr = HPA_f0202000_num_addr,\
		.add_addr = { HPA_f0202000_add_addr } },\
	{	.hpa = 0xfffbe000,\
		.iodc = &iodc_data_hpa_fffbe000,\
		.mod_info = &mod_info_hpa_fffbe000,\
		.mod_path = &mod_path_hpa_fffbe000,\
		.num_addr = HPA_fffbe000_num_addr,\
		.add_addr = { HPA_fffbe000_add_addr } },\
	{	.hpa = 0xfffbf000,\
		.iodc = &iodc_data_hpa_fffbf000_715,\
		.mod_info = &mod_info_hpa_fffbf000_715,\
		.mod_path = &mod_path_hpa_fffbf000_715,\
		.num_addr = HPA_fffbf000_715_num_addr,\
		.add_addr = { HPA_fffbf000_715_add_addr } },\
	{ 0, }
