/* HP J6700 workstation */
/* AUTO-GENERATED HEADER FILE FOR SEABIOS FIRMWARE */
/* generated with Linux kernel */
/* search for PARISC_QEMU_MACHINE_HEADER in Linux */

#if 0
Found devices:
1. Astro BC Runway Port [10] at 0xfffffffffed00000 { type:12, hv:0x582, sv:0xb, rev:0x0 }
2. Elroy PCI Bridge [10:0] at 0xfffffffffed30000 { type:13, hv:0x782, sv:0xa, rev:0x0 }
3. Elroy PCI Bridge [10:2] at 0xfffffffffed34000 { type:13, hv:0x782, sv:0xa, rev:0x0 }
4. Elroy PCI Bridge [10:4] at 0xfffffffffed38000 { type:13, hv:0x782, sv:0xa, rev:0x0 }
5. Elroy PCI Bridge [10:6] at 0xfffffffffed3c000 { type:13, hv:0x782, sv:0xa, rev:0x0 }
6. Duet W2 [32] at 0xfffffffffffa0000 { type:0, hv:0x5dd, sv:0x4, rev:0x0 }
7. Duet W2 [34] at 0xfffffffffffa2000 { type:0, hv:0x5dd, sv:0x4, rev:0x0 }
8. Memory [49] at 0xfffffffffed10200 { type:1, hv:0xa, sv:0x9, rev:0x0 }

lspci:
00:0c.0 Ethernet controller: Digital Equipment Corporation DECchip 21142/43 (rev 41)
00:0d.0 Multimedia audio controller: Analog Devices Device 1889
00:0e.0 IDE interface: National Semiconductor Corporation 87415/87560 IDE (rev 03)
00:0e.1 Bridge: National Semiconductor Corporation 87560 Legacy I/O (rev 01)
00:0e.2 USB controller: National Semiconductor Corporation USB Controller (rev 02)
00:0f.0 SCSI storage controller: Broadcom / LSI 53C896/897 (rev 07)
00:0f.1 SCSI storage controller: Broadcom / LSI 53C896/897 (rev 07)
01:01.0 Ethernet controller: Broadcom Inc. and subsidiaries NetXtreme BCM5701 Gigabit Ethernet (rev 15)
02:02.0 Display controller: Hewlett-Packard Company Visualize FX (rev 02)
#endif

#define PARISC_MODEL "9000/785/J6700"

#define PARISC_PDC_MODEL 0x5dd0, 0x491, 0x0, 0x2, 0x77a95f12, 0x100000f0, 0x8, 0xb2, 0xb2

#define PARISC_PDC_VERSION 0x0203

#define PARISC_PDC_CPUID 0x0267

#define PARISC_PDC_CAPABILITIES 0x0007

#define PARISC_PDC_ENTRY_ORG 0xfffffff0f0000018

#define PARISC_PDC_CACHE_INFO \
	0xc0000, 0x91802000, 0x20000, 0x0040, 0x0c00 \
	, 0x0001, 0x180000, 0xb1802000, 0x0000, 0x0040 \
	, 0x6000, 0x0001, 0x00f0, 0xd2300, 0x0000 \
	, 0x0000, 0x0001, 0x0000, 0x0000, 0x0001 \
	, 0x0001, 0x00f0, 0xd2000, 0x0000, 0x0000 \
	, 0x0001, 0x0000, 0x0000, 0x0001, 0x0001


#define HPA_fffffffffed00000_DESCRIPTION "Astro BC Runway Port"
static struct pdc_system_map_mod_info mod_info_hpa_fffffffffed00000 = {
	.mod_addr = 0xfed00000,
	.mod_pgs = 0x8,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffffffed00000 = {
	.path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, .mod = 0xa  },
	.layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffed00000 = {
	.hversion_model = 0x0058,
	.hversion = 0x0020,
	.spa = 0x0000,
	.type = 0x000c,
	.sversion_rev = 0x0000,
	.sversion_model = 0x0005,
	.sversion_opt = 0x0088,
	.rev = 0x0000,
	.dep = 0x0000,
	.features = 0x0000,
	.checksum = 0x0000,
	.length = 0x0000,
	/* pad: 0x0000, 0x0000 */
};
#define HPA_fffffffffed00000_num_addr 0
#define HPA_fffffffffed00000_add_addr 0


#define HPA_fffffffffed30000_DESCRIPTION "Elroy PCI Bridge"
static struct pdc_system_map_mod_info mod_info_hpa_fffffffffed30000 = {
	.mod_addr = 0xfed30000,
	.mod_pgs = 0x2,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffffffed30000 = {
	.path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xa }, .mod = 0x0  },
	.layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffed30000 = {
	.hversion_model = 0x0078,
	.hversion = 0x0020,
	.spa = 0x0000,
	.type = 0x000d,
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
#define HPA_fffffffffed30000_num_addr 0
#define HPA_fffffffffed30000_add_addr 0


#define HPA_fffffffffed34000_DESCRIPTION "Elroy PCI Bridge"
static struct pdc_system_map_mod_info mod_info_hpa_fffffffffed34000 = {
	.mod_addr = 0xfed34000,
	.mod_pgs = 0x2,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffffffed34000 = {
	.path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xa }, .mod = 0x2  },
	.layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffed34000 = {
	.hversion_model = 0x0078,
	.hversion = 0x0020,
	.spa = 0x0000,
	.type = 0x000d,
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
#define HPA_fffffffffed34000_num_addr 0
#define HPA_fffffffffed34000_add_addr 0


#define HPA_fffffffffed38000_DESCRIPTION "Elroy PCI Bridge"
static struct pdc_system_map_mod_info mod_info_hpa_fffffffffed38000 = {
	.mod_addr = 0xfed38000,
	.mod_pgs = 0x2,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffffffed38000 = {
	.path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xa }, .mod = 0x4  },
	.layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffed38000 = {
	.hversion_model = 0x0078,
	.hversion = 0x0020,
	.spa = 0x0000,
	.type = 0x000d,
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
#define HPA_fffffffffed38000_num_addr 0
#define HPA_fffffffffed38000_add_addr 0


#define HPA_fffffffffed3c000_DESCRIPTION "Elroy PCI Bridge"
static struct pdc_system_map_mod_info mod_info_hpa_fffffffffed3c000 = {
	.mod_addr = 0xfed3c000,
	.mod_pgs = 0x2,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffffffed3c000 = {
	.path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xa }, .mod = 0x6  },
	.layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffed3c000 = {
	.hversion_model = 0x0078,
	.hversion = 0x0020,
	.spa = 0x0000,
	.type = 0x000d,
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
#define HPA_fffffffffed3c000_num_addr 0
#define HPA_fffffffffed3c000_add_addr 0


#define HPA_fffffffffffa0000_DESCRIPTION "Duet W2"
static struct pdc_system_map_mod_info mod_info_hpa_fffffffffffa0000 = {
	.mod_addr = 0xfffa0000,
	.mod_pgs = 0x1,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffffffffa0000 = {
	.path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, .mod = 0x20  },
	.layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffffa0000 = {
	.hversion_model = 0x005d,
	.hversion = 0x00d0,
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
	/* pad: 0x0000, 0x0000 */
};
#define HPA_fffffffffffa0000_num_addr 0
#define HPA_fffffffffffa0000_add_addr 0


#define HPA_fffffffffffa2000_DESCRIPTION "Duet W2"
static struct pdc_system_map_mod_info mod_info_hpa_fffffffffffa2000 = {
	.mod_addr = 0xfffa2000,
	.mod_pgs = 0x1,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffffffffa2000 = {
	.path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, .mod = 0x22  },
	.layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffffa2000 = {
	.hversion_model = 0x005d,
	.hversion = 0x00d0,
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
	/* pad: 0x0000, 0x0000 */
};
#define HPA_fffffffffffa2000_num_addr 0
#define HPA_fffffffffffa2000_add_addr 0


#define HPA_fffffffffed10200_DESCRIPTION "Memory"
static struct pdc_system_map_mod_info mod_info_hpa_fffffffffed10200 = {
	.mod_addr = 0xfed10200,
	.mod_pgs = 0x8,
	.add_addrs = 0x0,
};
static struct pdc_module_path mod_path_hpa_fffffffffed10200 = {
	.path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, .mod = 0x31  },
	.layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
};
static struct pdc_iodc iodc_data_hpa_fffffffffed10200 = {
	.hversion_model = 0x0000,
	.hversion = 0x00a0,
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
#define HPA_fffffffffed10200_num_addr 0
#define HPA_fffffffffed10200_add_addr 0


#define PARISC_DEVICE_LIST \
	{	.hpa = 0xfffffffffed00000,\
		.iodc = &iodc_data_hpa_fffffffffed00000,\
		.mod_info = &mod_info_hpa_fffffffffed00000,\
		.mod_path = &mod_path_hpa_fffffffffed00000,\
		.num_addr = HPA_fffffffffed00000_num_addr,\
		.add_addr = { HPA_fffffffffed00000_add_addr } },\
	{	.hpa = 0xfffffffffed30000,\
		.iodc = &iodc_data_hpa_fffffffffed30000,\
		.mod_info = &mod_info_hpa_fffffffffed30000,\
		.mod_path = &mod_path_hpa_fffffffffed30000,\
		.num_addr = HPA_fffffffffed30000_num_addr,\
		.add_addr = { HPA_fffffffffed30000_add_addr } },\
	{	.hpa = 0xfffffffffed34000,\
		.iodc = &iodc_data_hpa_fffffffffed34000,\
		.mod_info = &mod_info_hpa_fffffffffed34000,\
		.mod_path = &mod_path_hpa_fffffffffed34000,\
		.num_addr = HPA_fffffffffed34000_num_addr,\
		.add_addr = { HPA_fffffffffed34000_add_addr } },\
	{	.hpa = 0xfffffffffed38000,\
		.iodc = &iodc_data_hpa_fffffffffed38000,\
		.mod_info = &mod_info_hpa_fffffffffed38000,\
		.mod_path = &mod_path_hpa_fffffffffed38000,\
		.num_addr = HPA_fffffffffed38000_num_addr,\
		.add_addr = { HPA_fffffffffed38000_add_addr } },\
	{	.hpa = 0xfffffffffed3c000,\
		.iodc = &iodc_data_hpa_fffffffffed3c000,\
		.mod_info = &mod_info_hpa_fffffffffed3c000,\
		.mod_path = &mod_path_hpa_fffffffffed3c000,\
		.num_addr = HPA_fffffffffed3c000_num_addr,\
		.add_addr = { HPA_fffffffffed3c000_add_addr } },\
	{	.hpa = 0xfffffffffffa0000,\
		.iodc = &iodc_data_hpa_fffffffffffa0000,\
		.mod_info = &mod_info_hpa_fffffffffffa0000,\
		.mod_path = &mod_path_hpa_fffffffffffa0000,\
		.num_addr = HPA_fffffffffffa0000_num_addr,\
		.add_addr = { HPA_fffffffffffa0000_add_addr } },\
	{	.hpa = 0xfffffffffffa2000,\
		.iodc = &iodc_data_hpa_fffffffffffa2000,\
		.mod_info = &mod_info_hpa_fffffffffffa2000,\
		.mod_path = &mod_path_hpa_fffffffffffa2000,\
		.num_addr = HPA_fffffffffffa2000_num_addr,\
		.add_addr = { HPA_fffffffffffa2000_add_addr } },\
	{	.hpa = 0xfffffffffed10200,\
		.iodc = &iodc_data_hpa_fffffffffed10200,\
		.mod_info = &mod_info_hpa_fffffffffed10200,\
		.mod_path = &mod_path_hpa_fffffffffed10200,\
		.num_addr = HPA_fffffffffed10200_num_addr,\
		.add_addr = { HPA_fffffffffed10200_add_addr } },\
	{ 0, }
