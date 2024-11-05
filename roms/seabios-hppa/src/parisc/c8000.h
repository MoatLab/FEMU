/* HP 9000/785/C8000 */
/* AUTO-GENERATED HEADER FILE FOR SEABIOS FIRMWARE */
/* generated with Linux kernel */
/* search for PARISC_QEMU_MACHINE_HEADER in Linux */

#if 0
1. Crestone Peak Mako+ Slow [128] at 0xfffffffffe780000 { type:0, hv:0x89b, sv:0x4, rev:0x0 }
2. Crestone Peak Mako+ Slow [129] at 0xfffffffffe781000 { type:0, hv:0x89b, sv:0x4, rev:0x0 }
3. Crestone Peak Mako+ Slow [152] at 0xfffffffffe798000 { type:0, hv:0x89b, sv:0x4, rev:0x0 }
4. Crestone Peak Mako+ Slow [153] at 0xfffffffffe799000 { type:0, hv:0x89b, sv:0x4, rev:0x0 }
5. Memory [8] at 0xfffffffffed08000 { type:1, hv:0xb6, sv:0x9, rev:0x0 }
6. Pluto BC McKinley Port [0] at 0xfffffffffed00000 { type:12, hv:0x880, sv:0xc, rev:0x0 }
7. Mercury PCI Bridge [0:0] at 0xfffffffffed20000 { type:13, hv:0x783, sv:0xa, rev:0x0 }
8. Mercury PCI Bridge [0:2] at 0xfffffffffed24000 { type:13, hv:0x783, sv:0xa, rev:0x0 }
9. Mercury PCI Bridge [0:3] at 0xfffffffffed26000 { type:13, hv:0x783, sv:0xa, rev:0x0 }
10. Quicksilver AGP Bridge [0:4] at 0xfffffffffed28000 { type:13, hv:0x784, sv:0xa, rev:0x0 }
11. BMC IPMI Mgmt Ctlr [16] at 0xfffffff0f05b0000 { type:15, hv:0x4, sv:0xc0, rev:0x0 }
12. Crestone Peak Core RS-232 [17] at 0xfffffff0f05e0000 { type:10, hv:0x76, sv:0xad, rev:0x0 }
13. Crestone Peak Core RS-232 [18] at 0xfffffff0f05e2000 { type:10, hv:0x76, sv:0xad, rev:0x0 }
#endif

#define PARISC_MODEL "9000/785/C8000"

#define PARISC_PDC_MODEL 0x89b0, 0x491, 0x0, 0x2, 0x5737c9e22415d308, 0x100000f0, 0x8, 0xb2, 0xb2, 0x1

#define PARISC_PDC_VERSION 0x0401

#define PARISC_PDC_CPUID 0x028a

#define PARISC_PDC_CAPABILITIES 0x0035

#define PARISC_PDC_ENTRY_ORG 0xfffffff0f0ffffa4

#define PARISC_PDC_CACHE_INFO \
	0x4000000, 0x1882000, 0x0000, 0x0080, 0x80000 \
	, 0x0001, 0x4000000, 0x1882000, 0x0000, 0x0080 \
	, 0x80000, 0x0001, 0x00f0, 0xd2300, 0x0000 \
	, 0x0000, 0x0001, 0x0000, 0x0000, 0x0001 \
	, 0x0001, 0x00f0, 0xd2000, 0x0000, 0x0000 \
	, 0x0001, 0x0000, 0x0000, 0x0001, 0x0001


audit: type=2000 audit(1705653084.992:1): state=initialized audit_enabled=0 res=1
#define HPA_fffffffffe780000_DESCRIPTION "Crestone Peak Mako+ Slow"
static struct pdc_system_map_mod_info mod_info_hpa_fffffffffe780000 = {
	.mod_addr = 0x0,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffffffe780000 = {
	.path = { .flags = 0x89, .bc = { 0xb0, 0x0, 0x40, 0x0, 0x0, 0x4 }, .mod = 0xffffff91  },
	.layers = { 0x1000000, 0x3e5e0002, 0x40000, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffe780000 = {
	.hversion_model = 0x0089,
	.hversion = 0x00b0,
	.spa = 0x0000,
	.type = 0x0040,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0002,
	.sversion_opt = 0x0048,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x3e5e,
	.length = 0x0002,
	/* pad: 0x40000, 0x0000 */
};
#define HPA_fffffffffe780000_num_addr 0
#define HPA_fffffffffe780000_add_addr 0


#define HPA_fffffffffe781000_DESCRIPTION "Crestone Peak Mako+ Slow"
static struct pdc_system_map_mod_info mod_info_hpa_fffffffffe781000 = {
	.mod_addr = 0x0,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffffffe781000 = {
	.path = { .flags = 0x89, .bc = { 0xb0, 0x0, 0x40, 0x0, 0x0, 0x4 }, .mod = 0xffffff91  },
	.layers = { 0x1000000, 0x3e5e0002, 0x40000, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffe781000 = {
	.hversion_model = 0x0089,
	.hversion = 0x00b0,
	.spa = 0x0000,
	.type = 0x0040,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0002,
	.sversion_opt = 0x0048,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x3e5e,
	.length = 0x0002,
	/* pad: 0x40000, 0x0000 */
};
#define HPA_fffffffffe781000_num_addr 0
#define HPA_fffffffffe781000_add_addr 0


#define HPA_fffffffffe798000_DESCRIPTION "Crestone Peak Mako+ Slow"
static struct pdc_system_map_mod_info mod_info_hpa_fffffffffe798000 = {
	.mod_addr = 0x0,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffffffe798000 = {
	.path = { .flags = 0x89, .bc = { 0xb0, 0x0, 0x40, 0x0, 0x0, 0x4 }, .mod = 0xffffff91  },
	.layers = { 0x1000000, 0x3e5e0002, 0x40000, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffe798000 = {
	.hversion_model = 0x0089,
	.hversion = 0x00b0,
	.spa = 0x0000,
	.type = 0x0040,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0002,
	.sversion_opt = 0x0048,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x3e5e,
	.length = 0x0002,
	/* pad: 0x40000, 0x0000 */
};
#define HPA_fffffffffe798000_num_addr 0
#define HPA_fffffffffe798000_add_addr 0


#define HPA_fffffffffe799000_DESCRIPTION "Crestone Peak Mako+ Slow"
static struct pdc_system_map_mod_info mod_info_hpa_fffffffffe799000 = {
	.mod_addr = 0x0,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffffffe799000 = {
	.path = { .flags = 0x89, .bc = { 0xb0, 0x0, 0x40, 0x0, 0x0, 0x4 }, .mod = 0xffffff91  },
	.layers = { 0x1000000, 0x3e5e0002, 0x40000, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffe799000 = {
	.hversion_model = 0x0089,
	.hversion = 0x00b0,
	.spa = 0x0000,
	.type = 0x0040,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0002,
	.sversion_opt = 0x0048,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x3e5e,
	.length = 0x0002,
	/* pad: 0x40000, 0x0000 */
};
#define HPA_fffffffffe799000_num_addr 0
#define HPA_fffffffffe799000_add_addr 0


#define HPA_fffffffffed08000_DESCRIPTION "Memory"
static struct pdc_system_map_mod_info mod_info_hpa_fffffffffed08000 = {
	.mod_addr = 0x0,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffffffed08000 = {
	.path = { .flags = 0xb, .bc = { 0x60, 0x1f, 0x41, 0x0, 0x0, 0x9 }, .mod = 0x0  },
	.layers = { 0x1000000, 0x3e5e0002, 0x40000, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffed08000 = {
	.hversion_model = 0x000b,
	.hversion = 0x0060,
	.spa = 0x001f,
	.type = 0x0041,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0004,
	.sversion_opt = 0x0080,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x3e5e,
	.length = 0x0002,
	/* pad: 0x40000, 0x0000 */
};
#define HPA_fffffffffed08000_num_addr 0
#define HPA_fffffffffed08000_add_addr 0


#define HPA_fffffffffed00000_DESCRIPTION "Pluto BC McKinley Port"
static struct pdc_system_map_mod_info mod_info_hpa_fffffffffed00000 = {
	.mod_addr = 0x0,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffffffed00000 = {
	.path = { .flags = 0x88, .bc = { 0x0, 0x0, 0x4c, 0x0, 0x0, 0xc }, .mod = 0x10  },
	.layers = { 0x1000000, 0x3e5e0002, 0x40000, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffed00000 = {
	.hversion_model = 0x0088,
	.hversion = 0x0000,
	.spa = 0x0000,
	.type = 0x004c,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0006,
	.sversion_opt = 0x0008,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x3e5e,
	.length = 0x0002,
	/* pad: 0x40000, 0x0000 */
};
#define HPA_fffffffffed00000_num_addr 0
#define HPA_fffffffffed00000_add_addr 0


#define HPA_fffffffffed20000_DESCRIPTION "Mercury PCI Bridge"
static struct pdc_system_map_mod_info mod_info_hpa_fffffffffed20000 = {
	.mod_addr = 0x0,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffffffed20000 = {
	.path = { .flags = 0x78, .bc = { 0x30, 0x0, 0x4d, 0x0, 0x0, 0xa }, .mod = 0x0  },
	.layers = { 0x1000000, 0x3e5e0002, 0x40000, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffed20000 = {
	.hversion_model = 0x0078,
	.hversion = 0x0030,
	.spa = 0x0000,
	.type = 0x004d,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0005,
	.sversion_opt = 0x0000,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x3e5e,
	.length = 0x0002,
	/* pad: 0x40000, 0x0000 */
};
#define HPA_fffffffffed20000_num_addr 0
#define HPA_fffffffffed20000_add_addr 0


#define HPA_fffffffffed24000_DESCRIPTION "Mercury PCI Bridge"
static struct pdc_system_map_mod_info mod_info_hpa_fffffffffed24000 = {
	.mod_addr = 0x0,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffffffed24000 = {
	.path = { .flags = 0x78, .bc = { 0x30, 0x0, 0x4d, 0x0, 0x0, 0xa }, .mod = 0x0  },
	.layers = { 0x1000000, 0x3e5e0002, 0x40000, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffed24000 = {
	.hversion_model = 0x0078,
	.hversion = 0x0030,
	.spa = 0x0000,
	.type = 0x004d,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0005,
	.sversion_opt = 0x0000,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x3e5e,
	.length = 0x0002,
	/* pad: 0x40000, 0x0000 */
};
#define HPA_fffffffffed24000_num_addr 0
#define HPA_fffffffffed24000_add_addr 0


#define HPA_fffffffffed26000_DESCRIPTION "Mercury PCI Bridge"
static struct pdc_system_map_mod_info mod_info_hpa_fffffffffed26000 = {
	.mod_addr = 0x0,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffffffed26000 = {
	.path = { .flags = 0x78, .bc = { 0x30, 0x0, 0x4d, 0x0, 0x0, 0xa }, .mod = 0x0  },
	.layers = { 0x1000000, 0x3e5e0002, 0x40000, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffed26000 = {
	.hversion_model = 0x0078,
	.hversion = 0x0030,
	.spa = 0x0000,
	.type = 0x004d,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0005,
	.sversion_opt = 0x0000,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x3e5e,
	.length = 0x0002,
	/* pad: 0x40000, 0x0000 */
};
#define HPA_fffffffffed26000_num_addr 0
#define HPA_fffffffffed26000_add_addr 0


#define HPA_fffffffffed28000_DESCRIPTION "Quicksilver AGP Bridge"
static struct pdc_system_map_mod_info mod_info_hpa_fffffffffed28000 = {
	.mod_addr = 0x0,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffffffed28000 = {
	.path = { .flags = 0x78, .bc = { 0x40, 0x0, 0x4d, 0x0, 0x0, 0xa }, .mod = 0x0  },
	.layers = { 0x1000000, 0x3e5e0002, 0x40000, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffed28000 = {
	.hversion_model = 0x0078,
	.hversion = 0x0040,
	.spa = 0x0000,
	.type = 0x004d,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0005,
	.sversion_opt = 0x0000,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x3e5e,
	.length = 0x0002,
	/* pad: 0x40000, 0x0000 */
};
#define HPA_fffffffffed28000_num_addr 0
#define HPA_fffffffffed28000_add_addr 0


#define HPA_fffffff0f05b0000_DESCRIPTION "BMC IPMI Mgmt Ctlr"
static struct pdc_system_map_mod_info mod_info_hpa_fffffff0f05b0000 = {
	.mod_addr = 0x0,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffff0f05b0000 = {
	.path = { .flags = 0x0, .bc = { 0x40, 0x0, 0x4f, 0x0, 0x0, 0xc0 }, .mod = 0x0  },
	.layers = { 0x1000000, 0x3e5e0002, 0x40000, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffff0f05b0000 = {
	.hversion_model = 0x0000,
	.hversion = 0x0040,
	.spa = 0x0000,
	.type = 0x004f,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0060,
	.sversion_opt = 0x0000,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x3e5e,
	.length = 0x0002,
	/* pad: 0x40000, 0x0000 */
};
#define HPA_fffffff0f05b0000_num_addr 0
#define HPA_fffffff0f05b0000_add_addr 0


#define HPA_fffffff0f05e0000_DESCRIPTION "Crestone Peak Core RS-232"
static struct pdc_system_map_mod_info mod_info_hpa_fffffff0f05e0000 = {
	.mod_addr = 0x0,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffff0f05e0000 = {
	.path = { .flags = 0x7, .bc = { 0x60, 0x0, 0x8a, 0x0, 0x0, 0xad }, .mod = 0x0  },
	.layers = { 0x1000000, 0x3e5e0002, 0x40000, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffff0f05e0000 = {
	.hversion_model = 0x0007,
	.hversion = 0x0060,
	.spa = 0x0000,
	.type = 0x008a,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0056,
	.sversion_opt = 0x0080,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x3e5e,
	.length = 0x0002,
	/* pad: 0x40000, 0x0000 */
};
#define HPA_fffffff0f05e0000_num_addr 0
#define HPA_fffffff0f05e0000_add_addr 0


#define HPA_fffffff0f05e2000_DESCRIPTION "Crestone Peak Core RS-232"
static struct pdc_system_map_mod_info mod_info_hpa_fffffff0f05e2000 = {
	.mod_addr = 0x0,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffff0f05e2000 = {
	.path = { .flags = 0x7, .bc = { 0x60, 0x0, 0x8a, 0x0, 0x0, 0xad }, .mod = 0x0  },
	.layers = { 0x1000000, 0x3e5e0002, 0x40000, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffff0f05e2000 = {
	.hversion_model = 0x0007,
	.hversion = 0x0060,
	.spa = 0x0000,
	.type = 0x008a,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0056,
	.sversion_opt = 0x0080,
	.rev = 0x0001,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x3e5e,
	.length = 0x0002,
	/* pad: 0x40000, 0x0000 */
};
#define HPA_fffffff0f05e2000_num_addr 0
#define HPA_fffffff0f05e2000_add_addr 0



#define PARISC_DEVICE_LIST \
	{	.hpa = 0xfffffffffe780000,\
		.iodc = &iodc_data_hpa_fffffffffe780000,\
		.mod_info = &mod_info_hpa_fffffffffe780000,\
		.mod_path = &mod_path_hpa_fffffffffe780000,\
		.num_addr = HPA_fffffffffe780000_num_addr,\
		.add_addr = { HPA_fffffffffe780000_add_addr } },\
	{	.hpa = 0xfffffffffe781000,\
		.iodc = &iodc_data_hpa_fffffffffe781000,\
		.mod_info = &mod_info_hpa_fffffffffe781000,\
		.mod_path = &mod_path_hpa_fffffffffe781000,\
		.num_addr = HPA_fffffffffe781000_num_addr,\
		.add_addr = { HPA_fffffffffe781000_add_addr } },\
	{	.hpa = 0xfffffffffe798000,\
		.iodc = &iodc_data_hpa_fffffffffe798000,\
		.mod_info = &mod_info_hpa_fffffffffe798000,\
		.mod_path = &mod_path_hpa_fffffffffe798000,\
		.num_addr = HPA_fffffffffe798000_num_addr,\
		.add_addr = { HPA_fffffffffe798000_add_addr } },\
	{	.hpa = 0xfffffffffe799000,\
		.iodc = &iodc_data_hpa_fffffffffe799000,\
		.mod_info = &mod_info_hpa_fffffffffe799000,\
		.mod_path = &mod_path_hpa_fffffffffe799000,\
		.num_addr = HPA_fffffffffe799000_num_addr,\
		.add_addr = { HPA_fffffffffe799000_add_addr } },\
	{	.hpa = 0xfffffffffed08000,\
		.iodc = &iodc_data_hpa_fffffffffed08000,\
		.mod_info = &mod_info_hpa_fffffffffed08000,\
		.mod_path = &mod_path_hpa_fffffffffed08000,\
		.num_addr = HPA_fffffffffed08000_num_addr,\
		.add_addr = { HPA_fffffffffed08000_add_addr } },\
	{	.hpa = 0xfffffffffed00000,\
		.iodc = &iodc_data_hpa_fffffffffed00000,\
		.mod_info = &mod_info_hpa_fffffffffed00000,\
		.mod_path = &mod_path_hpa_fffffffffed00000,\
		.num_addr = HPA_fffffffffed00000_num_addr,\
		.add_addr = { HPA_fffffffffed00000_add_addr } },\
	{	.hpa = 0xfffffffffed20000,\
		.iodc = &iodc_data_hpa_fffffffffed20000,\
		.mod_info = &mod_info_hpa_fffffffffed20000,\
		.mod_path = &mod_path_hpa_fffffffffed20000,\
		.num_addr = HPA_fffffffffed20000_num_addr,\
		.add_addr = { HPA_fffffffffed20000_add_addr } },\
	{	.hpa = 0xfffffffffed24000,\
		.iodc = &iodc_data_hpa_fffffffffed24000,\
		.mod_info = &mod_info_hpa_fffffffffed24000,\
		.mod_path = &mod_path_hpa_fffffffffed24000,\
		.num_addr = HPA_fffffffffed24000_num_addr,\
		.add_addr = { HPA_fffffffffed24000_add_addr } },\
	{	.hpa = 0xfffffffffed26000,\
		.iodc = &iodc_data_hpa_fffffffffed26000,\
		.mod_info = &mod_info_hpa_fffffffffed26000,\
		.mod_path = &mod_path_hpa_fffffffffed26000,\
		.num_addr = HPA_fffffffffed26000_num_addr,\
		.add_addr = { HPA_fffffffffed26000_add_addr } },\
	{	.hpa = 0xfffffffffed28000,\
		.iodc = &iodc_data_hpa_fffffffffed28000,\
		.mod_info = &mod_info_hpa_fffffffffed28000,\
		.mod_path = &mod_path_hpa_fffffffffed28000,\
		.num_addr = HPA_fffffffffed28000_num_addr,\
		.add_addr = { HPA_fffffffffed28000_add_addr } },\
	{	.hpa = 0xfffffff0f05b0000,\
		.iodc = &iodc_data_hpa_fffffff0f05b0000,\
		.mod_info = &mod_info_hpa_fffffff0f05b0000,\
		.mod_path = &mod_path_hpa_fffffff0f05b0000,\
		.num_addr = HPA_fffffff0f05b0000_num_addr,\
		.add_addr = { HPA_fffffff0f05b0000_add_addr } },\
	{	.hpa = 0xfffffff0f05e0000,\
		.iodc = &iodc_data_hpa_fffffff0f05e0000,\
		.mod_info = &mod_info_hpa_fffffff0f05e0000,\
		.mod_path = &mod_path_hpa_fffffff0f05e0000,\
		.num_addr = HPA_fffffff0f05e0000_num_addr,\
		.add_addr = { HPA_fffffff0f05e0000_add_addr } },\
	{	.hpa = 0xfffffff0f05e2000,\
		.iodc = &iodc_data_hpa_fffffff0f05e2000,\
		.mod_info = &mod_info_hpa_fffffff0f05e2000,\
		.mod_path = &mod_path_hpa_fffffff0f05e2000,\
		.num_addr = HPA_fffffff0f05e2000_num_addr,\
		.add_addr = { HPA_fffffff0f05e2000_add_addr } },\
	{ 0, }
