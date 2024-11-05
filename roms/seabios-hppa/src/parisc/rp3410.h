/* HP rp3410 server */
/* AUTO-GENERATED HEADER FILE FOR SEABIOS FIRMWARE */
/* generated with Linux kernel */
/* search for PARISC_QEMU_MACHINE_HEADER in Linux */

#if 0
Found devices:
1. Storm Peak DC- Slow Mako+ [128] at 0xfffffffffe780000 { type:0, hv:0x897, sv:0x4, rev:0x0 }
2. Everest Mako Memory [8] at 0xfffffffffed08000 { type:1, hv:0xaf, sv:0x9, rev:0x0 }
3. Pluto BC McKinley Port [0] at 0xfffffffffed00000 { type:12, hv:0x880, sv:0xc, rev:0x0 }
4. Mercury PCI Bridge [0:0] at 0xfffffffffed20000 { type:13, hv:0x783, sv:0xa, rev:0x0 }
5. Mercury PCI Bridge [0:1] at 0xfffffffffed22000 { type:13, hv:0x783, sv:0xa, rev:0x0 }
6. Mercury PCI Bridge [0:2] at 0xfffffffffed24000 { type:13, hv:0x783, sv:0xa, rev:0x0 }
7. Mercury PCI Bridge [0:3] at 0xfffffffffed26000 { type:13, hv:0x783, sv:0xa, rev:0x0 }
8. Mercury PCI Bridge [0:4] at 0xfffffffffed28000 { type:13, hv:0x783, sv:0xa, rev:0x0 }
9. Mercury PCI Bridge [0:6] at 0xfffffffffed2c000 { type:13, hv:0x783, sv:0xa, rev:0x0 }
10. Mercury PCI Bridge [0:7] at 0xfffffffffed2e000 { type:13, hv:0x783, sv:0xa, rev:0x0 }
11. BMC IPMI Mgmt Ctlr [16] at 0xfffffff0f05b0000 { type:15, hv:0x4, sv:0xc0, rev:0x0 }

lspci:
00:01.0 USB controller: NEC Corporation OHCI USB Controller (rev 41)
00:01.1 USB controller: NEC Corporation OHCI USB Controller (rev 41)
00:01.2 USB controller: NEC Corporation uPD72010x USB 2.0 Controller (rev 02)
00:02.0 IDE interface: Silicon Image, Inc. SiI 0649 Ultra ATA/100 PCI to ATA Host Controller (rev 02)
20:01.0 SCSI storage controller: Broadcom / LSI 53c1010 66MHz  Ultra3 SCSI Adapter (rev 01)
20:01.1 SCSI storage controller: Broadcom / LSI 53c1010 66MHz  Ultra3 SCSI Adapter (rev 01)
20:02.0 Ethernet controller: Broadcom Inc. and subsidiaries NetXtreme BCM5701 Gigabit Ethernet (rev 15)
80:01.0 VGA compatible controller: Advanced Micro Devices, Inc. [AMD/ATI] RV200 [Radeon 7500/7500 LE]
e0:01.0 Communication controller: Hewlett-Packard Company Device 0000 (rev 01)
e0:01.1 Serial controller: Hewlett-Packard Company Diva Serial [GSP] Multiport UART (rev 03)
e0:02.0 VGA compatible controller: Advanced Micro Devices, Inc. [AMD/ATI] Device 0000
#endif

#define PARISC_MODEL "9000/800/rp3410  "

#define PARISC_PDC_MODEL 0x8970, 0x491, 0x0, 0x2, 0x3e00247d927e0697, 0x100000f0, 0x8, 0xb2, 0xb2

#define PARISC_PDC_VERSION 0x0302

#define PARISC_PDC_CPUID 0x0285

#define PARISC_PDC_CAPABILITIES 0x0035

#define PARISC_PDC_ENTRY_ORG 0xfffffff0f0ffffa4

#define PARISC_PDC_CACHE_INFO \
	0x4000000, 0x1882000, 0x0000, 0x0080, 0x80000 \
	, 0x0001, 0x4000000, 0x1882000, 0x0000, 0x0080 \
	, 0x80000, 0x0001, 0x00f0, 0xd2300, 0x0000 \
	, 0x0000, 0x0001, 0x0000, 0x0000, 0x0001 \
	, 0x0001, 0x00f0, 0xd2000, 0x0000, 0x0000 \
	, 0x0001, 0x0000, 0x0000, 0x0001, 0x0001


#define HPA_fffffffffe780000_DESCRIPTION "Storm Peak DC- Slow Mako+"
static struct pdc_system_map_mod_info mod_info_hpa_fffffffffe780000 = {
	.mod_addr = 0x0,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffffffe780000 = {
	.path = { .flags = 0x89, .bc = { 0x70, 0x0, 0x40, 0x0, 0x0, 0x4 }, .mod = 0xffffff91  },
	.layers = { 0x0, 0x0, 0x40000, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffe780000 = {
	.hversion_model = 0x0089,
	.hversion = 0x0070,
	.spa = 0x0000,
	.type = 0x0040,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0002,
	.sversion_opt = 0x0048,
	.rev = 0x0000,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x0000,
	.length = 0x0000,
	/* pad: 0x40000, 0x0000 */
};
#define HPA_fffffffffe780000_num_addr 0
#define HPA_fffffffffe780000_add_addr 0


#define HPA_fffffffffed08000_DESCRIPTION "Everest Mako Memory"
static struct pdc_system_map_mod_info mod_info_hpa_fffffffffed08000 = {
	.mod_addr = 0x0,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffffffed08000 = {
	.path = { .flags = 0xa, .bc = { 0xf0, 0x1f, 0x41, 0x0, 0x0, 0x9 }, .mod = 0x0  },
	.layers = { 0x0, 0x0, 0x40000, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffed08000 = {
	.hversion_model = 0x000a,
	.hversion = 0x00f0,
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
	.layers = { 0x0, 0x0, 0x40000, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffed00000 = {
	.hversion_model = 0x0088,
	.hversion = 0x0000,
	.spa = 0x0000,
	.type = 0x004c,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0006,
	.sversion_opt = 0x0008,
	.rev = 0x0000,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x0000,
	.length = 0x0000,
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
	.layers = { 0x0, 0x0, 0x40000, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffed20000 = {
	.hversion_model = 0x0078,
	.hversion = 0x0030,
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
	/* pad: 0x40000, 0x0000 */
};
#define HPA_fffffffffed20000_num_addr 0
#define HPA_fffffffffed20000_add_addr 0


#define HPA_fffffffffed22000_DESCRIPTION "Mercury PCI Bridge"
static struct pdc_system_map_mod_info mod_info_hpa_fffffffffed22000 = {
	.mod_addr = 0x0,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffffffed22000 = {
	.path = { .flags = 0x78, .bc = { 0x30, 0x0, 0x4d, 0x0, 0x0, 0xa }, .mod = 0x0  },
	.layers = { 0x0, 0x0, 0x40000, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffed22000 = {
	.hversion_model = 0x0078,
	.hversion = 0x0030,
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
	/* pad: 0x40000, 0x0000 */
};
#define HPA_fffffffffed22000_num_addr 0
#define HPA_fffffffffed22000_add_addr 0


#define HPA_fffffffffed24000_DESCRIPTION "Mercury PCI Bridge"
static struct pdc_system_map_mod_info mod_info_hpa_fffffffffed24000 = {
	.mod_addr = 0x0,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffffffed24000 = {
	.path = { .flags = 0x78, .bc = { 0x30, 0x0, 0x4d, 0x0, 0x0, 0xa }, .mod = 0x0  },
	.layers = { 0x0, 0x0, 0x40000, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffed24000 = {
	.hversion_model = 0x0078,
	.hversion = 0x0030,
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
	.layers = { 0x0, 0x0, 0x40000, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffed26000 = {
	.hversion_model = 0x0078,
	.hversion = 0x0030,
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
	/* pad: 0x40000, 0x0000 */
};
#define HPA_fffffffffed26000_num_addr 0
#define HPA_fffffffffed26000_add_addr 0


#define HPA_fffffffffed28000_DESCRIPTION "Mercury PCI Bridge"
static struct pdc_system_map_mod_info mod_info_hpa_fffffffffed28000 = {
	.mod_addr = 0x0,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffffffed28000 = {
	.path = { .flags = 0x78, .bc = { 0x30, 0x0, 0x4d, 0x0, 0x0, 0xa }, .mod = 0x0  },
	.layers = { 0x0, 0x0, 0x40000, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffed28000 = {
	.hversion_model = 0x0078,
	.hversion = 0x0030,
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
	/* pad: 0x40000, 0x0000 */
};
#define HPA_fffffffffed28000_num_addr 0
#define HPA_fffffffffed28000_add_addr 0


#define HPA_fffffffffed2c000_DESCRIPTION "Mercury PCI Bridge"
static struct pdc_system_map_mod_info mod_info_hpa_fffffffffed2c000 = {
	.mod_addr = 0x0,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffffffed2c000 = {
	.path = { .flags = 0x78, .bc = { 0x30, 0x0, 0x4d, 0x0, 0x0, 0xa }, .mod = 0x0  },
	.layers = { 0x0, 0x0, 0x40000, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffed2c000 = {
	.hversion_model = 0x0078,
	.hversion = 0x0030,
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
	/* pad: 0x40000, 0x0000 */
};
#define HPA_fffffffffed2c000_num_addr 0
#define HPA_fffffffffed2c000_add_addr 0


#define HPA_fffffffffed2e000_DESCRIPTION "Mercury PCI Bridge"
static struct pdc_system_map_mod_info mod_info_hpa_fffffffffed2e000 = {
	.mod_addr = 0x0,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffffffed2e000 = {
	.path = { .flags = 0x78, .bc = { 0x30, 0x0, 0x4d, 0x0, 0x0, 0xa }, .mod = 0x0  },
	.layers = { 0x0, 0x0, 0x40000, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffed2e000 = {
	.hversion_model = 0x0078,
	.hversion = 0x0030,
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
	/* pad: 0x40000, 0x0000 */
};
#define HPA_fffffffffed2e000_num_addr 0
#define HPA_fffffffffed2e000_add_addr 0


#define HPA_fffffff0f05b0000_DESCRIPTION "BMC IPMI Mgmt Ctlr"
static struct pdc_system_map_mod_info mod_info_hpa_fffffff0f05b0000 = {
	.mod_addr = 0x0,
	.mod_pgs = 0x0,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffff0f05b0000 = {
	.path = { .flags = 0x0, .bc = { 0x40, 0x0, 0x4f, 0x0, 0x0, 0xc0 }, .mod = 0x0  },
	.layers = { 0x0, 0x0, 0x40000, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffff0f05b0000 = {
	.hversion_model = 0x0000,
	.hversion = 0x0040,
	.spa = 0x0000,
	.type = 0x004f,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0060,
	.sversion_opt = 0x0000,
	.rev = 0x0000,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x0000,
	.length = 0x0000,
	/* pad: 0x40000, 0x0000 */
};
#define HPA_fffffff0f05b0000_num_addr 0
#define HPA_fffffff0f05b0000_add_addr 0



#define PARISC_DEVICE_LIST \
	{	.hpa = 0xfffffffffe780000,\
		.iodc = &iodc_data_hpa_fffffffffe780000,\
		.mod_info = &mod_info_hpa_fffffffffe780000,\
		.mod_path = &mod_path_hpa_fffffffffe780000,\
		.num_addr = HPA_fffffffffe780000_num_addr,\
		.add_addr = { HPA_fffffffffe780000_add_addr } },\
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
	{	.hpa = 0xfffffffffed22000,\
		.iodc = &iodc_data_hpa_fffffffffed22000,\
		.mod_info = &mod_info_hpa_fffffffffed22000,\
		.mod_path = &mod_path_hpa_fffffffffed22000,\
		.num_addr = HPA_fffffffffed22000_num_addr,\
		.add_addr = { HPA_fffffffffed22000_add_addr } },\
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
	{	.hpa = 0xfffffffffed2c000,\
		.iodc = &iodc_data_hpa_fffffffffed2c000,\
		.mod_info = &mod_info_hpa_fffffffffed2c000,\
		.mod_path = &mod_path_hpa_fffffffffed2c000,\
		.num_addr = HPA_fffffffffed2c000_num_addr,\
		.add_addr = { HPA_fffffffffed2c000_add_addr } },\
	{	.hpa = 0xfffffffffed2e000,\
		.iodc = &iodc_data_hpa_fffffffffed2e000,\
		.mod_info = &mod_info_hpa_fffffffffed2e000,\
		.mod_path = &mod_path_hpa_fffffffffed2e000,\
		.num_addr = HPA_fffffffffed2e000_num_addr,\
		.add_addr = { HPA_fffffffffed2e000_add_addr } },\
	{	.hpa = 0xfffffff0f05b0000,\
		.iodc = &iodc_data_hpa_fffffff0f05b0000,\
		.mod_info = &mod_info_hpa_fffffff0f05b0000,\
		.mod_path = &mod_path_hpa_fffffff0f05b0000,\
		.num_addr = HPA_fffffff0f05b0000_num_addr,\
		.add_addr = { HPA_fffffff0f05b0000_add_addr } },\
	{ 0, }
