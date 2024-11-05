/*
 *   OpenBIOS pci driver
 *
 *   This driver is compliant to the
 *   PCI bus binding to IEEE 1275-1994 Rev 2.1
 *
 *   (C) 2004 Stefan Reinauer
 *   (C) 2005 Ed Schouten <ed@fxq.nl>
 *
 *   Some parts from OpenHackWare-0.4, Copyright (c) 2004-2005 Jocelyn Mayer
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "libopenbios/ofmem.h"
#include "kernel/kernel.h"
#include "drivers/pci.h"
#include "libc/byteorder.h"
#include "libc/vsprintf.h"

#include "drivers/drivers.h"
#include "drivers/vga.h"
#include "packages/video.h"
#include "libopenbios/video.h"
#include "timer.h"
#include "pci.h"
#include "pci_database.h"
#ifdef CONFIG_DRIVER_MACIO
#include "macio.h"
#endif
#ifdef CONFIG_DRIVER_USB
#include "drivers/usb.h"
#endif
#ifdef CONFIG_DRIVER_VIRTIO_BLK
#include "virtio.h"
#endif

#if defined (CONFIG_DEBUG_PCI)
# define PCI_DPRINTF(format, ...) printk(format, ## __VA_ARGS__)
#else
# define PCI_DPRINTF(format, ...) do { } while (0)
#endif

#define set_bool_property(ph, name) set_property(ph, name, NULL, 0);

/* DECLARE data structures for the nodes.  */

DECLARE_UNNAMED_NODE( ob_pci_bus_node, INSTALL_OPEN, 2*sizeof(int) );
DECLARE_UNNAMED_NODE( ob_pci_bridge_node, INSTALL_OPEN, 2*sizeof(int) );
DECLARE_UNNAMED_NODE( ob_pci_simple_node, 0, 2*sizeof(int) );

const pci_arch_t *arch;

#define IS_NOT_RELOCATABLE	0x80000000
#define IS_PREFETCHABLE		0x40000000
#define IS_ALIASED		0x20000000

static int encode_int32_cells(int num_cells, u32 *prop, ucell val)
{
    int i = 0;

    /* hi ... lo */
    for (i=0; i < num_cells; ++i) {
        prop[num_cells - i - 1] = val;
        val >>= 16;
        val >>= 16;
    }

    return num_cells;
}

static inline int pci_encode_phys_addr(u32 *phys, int flags, int space_code,
				 pci_addr dev, uint8_t reg, uint64_t addr)
{

	/* phys.hi */

	phys[0] = flags | (space_code << 24) | dev | reg;

	/* phys.mid */

	phys[1] = addr >> 32;

	/* phys.lo */

	phys[2] = addr;

	return 3;
}

static inline int pci_encode_size(u32 *prop, uint64_t size)
{
    return encode_int32_cells(2, prop, size);
}

static int host_address_cells(void)
{
    return get_int_property(find_dev("/"), "#address-cells", NULL);
}

static int host_encode_phys_addr(u32 *prop, ucell addr)
{
    return encode_int32_cells(host_address_cells(), prop, addr);
}

static int host_size_cells(void)
{
    return get_int_property(find_dev("/"), "#size-cells", NULL);
}

/*
static int parent_address_cells(void)
{
    phandle_t parent_ph = ih_to_phandle(my_parent());
    return get_int_property(parent_ph, "#address-cells", NULL);
}

static int parent_size_cells(void)
{
    phandle_t parent_ph = ih_to_phandle(my_parent());
    return get_int_property(parent_ph, "#size-cells", NULL);
}
*/

#if defined(CONFIG_DEBUG_PCI)
static void dump_reg_property(const char* description, int nreg, u32 *reg)
{
    int i;
    printk("%s reg", description);
    for (i=0; i < nreg; ++i) {
        printk(" %08X", reg[i]);
    }
    printk("\n");
}
#endif

static unsigned long pci_bus_addr_to_host_addr(int space, uint32_t ba)
{
    if (space == IO_SPACE) {
        return arch->io_base + (unsigned long)ba;
    } else if (space == MEMORY_SPACE_32) {
        return arch->host_pci_base + (unsigned long)ba;
    } else {
        /* Return unaltered to aid debugging property values */
        return (unsigned long)ba;
    }
}

static inline void pci_decode_pci_addr(pci_addr addr, int *flags,
                                       int *space_code, uint32_t *mask)
{
    *flags = 0;

    if (addr & 0x01) {
        *space_code = IO_SPACE;
        *mask = 0x00000001;
    } else {
        if (addr & 0x04) {
            *space_code = MEMORY_SPACE_64;
            *flags |= IS_NOT_RELOCATABLE; /* XXX: why not relocatable? */
        } else {
            *space_code = MEMORY_SPACE_32;
        }

        if (addr & 0x08) {
            *flags |= IS_PREFETCHABLE;
        }

        *mask = 0x0000000F;
    }
}

static void
ob_pci_open(int *idx)
{
	int ret=1;
	RET ( -ret );
}

static void
ob_pci_close(int *idx)
{
}

/* ( str len -- phys.lo phys.mid phys.hi ) */

static void
ob_pci_decode_unit(int *idx)
{
	ucell hi, mid, lo;
	const char *arg = pop_fstr_copy();
	int dev, fn, reg, ss, n, p, t;
	int bus, len;
	char *ptr;

	PCI_DPRINTF("ob_pci_decode_unit idx=%p\n", idx);

	fn = 0;
	reg = 0;
	n = 0;
	p = 0;
	t = 0;

	ptr = (char*)arg;
	if (*ptr == 'n') {
		n = IS_NOT_RELOCATABLE;
		ptr++;
	}
	if (*ptr == 'i') {
		ss = IO_SPACE;
		ptr++;
		if (*ptr == 't') {
			t = IS_ALIASED;
			ptr++;
		}

		/* DD,F,RR,NNNNNNNN */

		dev = strtol(ptr, &ptr, 16);
		ptr++;
		fn = strtol(ptr, &ptr, 16);
		ptr++;
		reg = strtol(ptr, &ptr, 16);
		ptr++;
		lo = strtol(ptr, &ptr, 16);
		mid = 0;

	} else if (*ptr == 'm') {
		ss = MEMORY_SPACE_32;
		ptr++;
		if (*ptr == 't') {
			t = IS_ALIASED;
			ptr++;
		}
		if (*ptr == 'p') {
			p = IS_PREFETCHABLE;
			ptr++;
		}

		/* DD,F,RR,NNNNNNNN */

		dev = strtol(ptr, &ptr, 16);
		ptr++;
		fn = strtol(ptr, &ptr, 16);
		ptr++;
		reg = strtol(ptr, &ptr, 16);
		ptr++;
		lo = strtol(ptr, &ptr, 16);
		mid = 0;

	} else if (*ptr == 'x') {
		unsigned long long addr64;
		ss = MEMORY_SPACE_64;
		ptr++;
		if (*ptr == 'p') {
			p = IS_PREFETCHABLE;
			ptr++;
		}

		/* DD,F,RR,NNNNNNNNNNNNNNNN */

		dev = strtol(ptr, &ptr, 16);
		ptr++;
		fn = strtol(ptr, &ptr, 16);
		ptr++;
		reg = strtol(ptr, &ptr, 16);
		ptr++;
		addr64 = strtoll(ptr, &ptr, 16);
		lo = (ucell)addr64;
		mid = addr64 >> 32;

	} else {
		ss = CONFIGURATION_SPACE;
		/* "DD" or "DD,FF" */
		dev = strtol(ptr, &ptr, 16);
		if (*ptr == ',') {
			ptr++;
			fn = strtol(ptr, NULL, 16);
		}
		lo = 0;
		mid = 0;
	}
	free((char*)arg);

	bus = get_int_property(get_cur_dev(), "bus-range", &len);

	hi = n | p | t | (ss << 24) | (bus << 16) | (dev << 11) | (fn << 8) | reg;

	PUSH(lo);
	PUSH(mid);
	PUSH(hi);

	PCI_DPRINTF("ob_pci_decode_unit idx=%p addr="
	        FMT_ucellx " " FMT_ucellx " " FMT_ucellx "\n",
	        idx, lo, mid, hi);
}

/*  ( phys.lo phy.mid phys.hi -- str len ) */

static void
ob_pci_encode_unit(int *idx)
{
	char buf[28];
	cell hi = POP();
	cell mid = POP();
	cell lo = POP();
        int n, p, t, ss, dev, fn, reg;

	n = hi & IS_NOT_RELOCATABLE;
	p = hi & IS_PREFETCHABLE;
	t = hi & IS_ALIASED;
	ss = (hi >> 24) & 0x03;

	dev = (hi >> 11) & 0x1F;
	fn = (hi >> 8) & 0x07;
	reg = hi & 0xFF;

	switch(ss) {
	case CONFIGURATION_SPACE:

		if (fn == 0)	/* DD */
        		snprintf(buf, sizeof(buf), "%x", dev);
		else		/* DD,F */
        		snprintf(buf, sizeof(buf), "%x,%x", dev, fn);
		break;

	case IO_SPACE:

		/* [n]i[t]DD,F,RR,NNNNNNNN */
                snprintf(buf, sizeof(buf), "%si%s%x,%x,%x," FMT_ucellx,
			 n ? "n" : "",	/* relocatable */
			 t ? "t" : "",	/* aliased */
			 dev, fn, reg, t ? lo & 0x03FF : lo);
		break;

	case MEMORY_SPACE_32:

		/* [n]m[t][p]DD,F,RR,NNNNNNNN */
                snprintf(buf, sizeof(buf), "%sm%s%s%x,%x,%x," FMT_ucellx,
			 n ? "n" : "",	/* relocatable */
			 t ? "t" : "",	/* aliased */
			 p ? "p" : "",	/* prefetchable */
			 dev, fn, reg, lo );
		break;

	case MEMORY_SPACE_64:

		/* [n]x[p]DD,F,RR,NNNNNNNNNNNNNNNN */
        	snprintf(buf, sizeof(buf), "%sx%s%x,%x,%x,%llx",
			 n ? "n" : "",	/* relocatable */
			 p ? "p" : "",	/* prefetchable */
                         dev, fn, reg, ((long long)mid << 32) | (long long)lo);
		break;
	}
	push_str(buf);

	PCI_DPRINTF("ob_pci_encode_unit space=%d dev=%d fn=%d buf=%s\n",
	        ss, dev, fn, buf);
}

/* Map PCI MMIO or IO space from the BAR address. Note it is up to the caller
   to understand whether the resulting address is in MEM or IO space and
   use the appropriate accesses */
static ucell ob_pci_map(uint32_t ba, ucell size) {
	phys_addr_t phys;
	uint32_t mask;
	int flags, space_code;
	ucell virt;
	
	pci_decode_pci_addr(ba, &flags, &space_code, &mask);

	phys = pci_bus_addr_to_host_addr(space_code,
			ba & ~mask);
	
#if defined(CONFIG_OFMEM)
	ofmem_claim_phys(phys, size, 0);

#if defined(CONFIG_PPC)
	/* For some reason PPC gets upset when virt != phys for map-in... */
	virt = ofmem_claim_virt(phys, size, 0);
#else
	virt = ofmem_claim_virt(-1, size, size);
#endif

	ofmem_map(phys, virt, size, ofmem_arch_io_translation_mode(phys));

#else
	virt = size;	/* Keep compiler quiet */
	virt = phys;
#endif

	return virt;
}

static void ob_pci_unmap(ucell virt, ucell size) {
#if defined(CONFIG_OFMEM)
	ofmem_unmap(virt, size); 
#endif
}

/* ( pci-addr.lo pci-addr.mid pci-addr.hi size -- virt ) */

static void
ob_pci_bus_map_in(int *idx)
{
	uint32_t ba;
	ucell size;
	ucell virt;

	PCI_DPRINTF("ob_pci_bar_map_in idx=%p\n", idx);

	size = POP();
	POP();
	POP();
	ba = POP();

	virt = ob_pci_map(ba, size);

	PUSH(virt);
}

static void
ob_pci_dma_alloc(int *idx)
{
    call_parent_method("dma-alloc");
}

static void
ob_pci_dma_free(int *idx)
{
    call_parent_method("dma-free");
}

static void
ob_pci_dma_map_in(int *idx)
{
    call_parent_method("dma-map-in");
}

static void
ob_pci_dma_map_out(int *idx)
{
    call_parent_method("dma-map-out");
}

static void
ob_pci_dma_sync(int *idx)
{
    call_parent_method("dma-sync");
}

NODE_METHODS(ob_pci_bus_node) = {
	{ "open",		ob_pci_open		},
	{ "close",		ob_pci_close		},
	{ "decode-unit",	ob_pci_decode_unit	},
	{ "encode-unit",	ob_pci_encode_unit	},
	{ "pci-map-in",		ob_pci_bus_map_in	},
	{ "dma-alloc",		ob_pci_dma_alloc	},
	{ "dma-free",		ob_pci_dma_free		},
	{ "dma-map-in",		ob_pci_dma_map_in	},
	{ "dma-map-out",	ob_pci_dma_map_out	},
	{ "dma-sync",		ob_pci_dma_sync		},
};

/* ( pci-addr.lo pci-addr.mid pci-addr.hi size -- virt ) */

static void
ob_pci_bridge_map_in(int *idx)
{
	/* As per the IEEE-1275 PCI specification, chain up to the parent */
	call_parent_method("pci-map-in");
}

NODE_METHODS(ob_pci_bridge_node) = {
	{ "open",		ob_pci_open		},
	{ "close",		ob_pci_close		},
	{ "decode-unit",	ob_pci_decode_unit	},
	{ "encode-unit",	ob_pci_encode_unit	},
	{ "pci-map-in",		ob_pci_bridge_map_in	},
	{ "dma-alloc",		ob_pci_dma_alloc	},
	{ "dma-free",		ob_pci_dma_free		},
	{ "dma-map-in",		ob_pci_dma_map_in	},
	{ "dma-map-out",	ob_pci_dma_map_out	},
	{ "dma-sync",		ob_pci_dma_sync		},
};

NODE_METHODS(ob_pci_simple_node) = {
	{ "open",		ob_pci_open		},
	{ "close",		ob_pci_close		},
};

static void pci_set_bus_range(const pci_config_t *config)
{
	phandle_t dev = find_dev(config->path);
	u32 props[2];

	props[0] = config->secondary_bus;
	props[1] = config->subordinate_bus;

	PCI_DPRINTF("setting bus range for %s PCI device, "
	        "package handle " FMT_ucellx " "
            "bus primary=%d secondary=%d subordinate=%d\n",
            config->path,
            dev,
            config->primary_bus,
            config->secondary_bus,
            config->subordinate_bus);


	set_property(dev, "bus-range", (char *)props, 2 * sizeof(props[0]));
}

static void ob_pci_reload_device_path(phandle_t phandle, pci_config_t *config);

static void pci_host_set_reg(phandle_t phandle, pci_config_t *config)
{
    phandle_t dev = phandle;

    /* at most 2 integers for address and size */
    u32 props[4];
    int ncells = 0;

    ncells += encode_int32_cells(host_address_cells(), props + ncells,
            arch->cfg_base);

    ncells += encode_int32_cells(host_size_cells(), props + ncells,
            arch->cfg_len);

    set_property(dev, "reg", (char *)props, ncells * sizeof(props[0]));

    ob_pci_reload_device_path(dev, config);

#if defined(CONFIG_DEBUG_PCI)
    dump_reg_property("pci_host_set_reg", 4, props);
#endif
}

/* child-phys : parent-phys : size */
/* 3 cells for PCI : 2 cells for 64bit parent : 2 cells for PCI */

static void pci_host_set_ranges(const pci_config_t *config)
{
	phandle_t dev = get_cur_dev();
	u32 props[32];
	int ncells = 0;
	pci_range_t range;
	int i;
	
	for (i = 0; i < 4; i++) {
		range = arch->host_ranges[i];
	    
		/* End of range list reached */
		if (range.type == 0x0 && range.len == 0x0) {
			break;
		}
	
		ncells += pci_encode_phys_addr(props + ncells, 0, range.type,
						0, 0, range.parentaddr);
		ncells += host_encode_phys_addr(props + ncells, range.childaddr);
		ncells += pci_encode_size(props + ncells, range.len);
	}
	
	set_property(dev, "ranges", (char *)props, ncells * sizeof(props[0]));
}

int host_config_cb(const pci_config_t *config)
{
	pci_host_set_ranges(config);

	return 0;
}

static int sabre_configure(phandle_t dev)
{
        uint32_t props[28];

        /* Sabre has a custom reg property from the default */
        props[0] = 0x1fe;
        props[1] = 0x0;
        props[2] = 0x0;
        props[3] = 0x10000;
        props[4] = 0x1fe;
        props[5] = 0x1000000;
        props[6] = 0x0;
        props[7] = 0x100;
        set_property(dev, "reg", (char *)props, 8 * sizeof(props[0]));

        props[0] = 0xc0000000;
        props[1] = 0x20000000;
        set_property(dev, "virtual-dma", (char *)props, 2 * sizeof(props[0]));
        props[0] = 1;
        set_property(dev, "#virtual-dma-size-cells", (char *)props,
                     sizeof(props[0]));
        set_property(dev, "#virtual-dma-addr-cells", (char *)props,
                     sizeof(props[0]));

        set_property(dev, "no-streaming-cache", (char *)props, 0);

        props[0] = 0x000007f0;
        props[1] = 0x000007ee;
        props[2] = 0x000007ef;
        props[3] = 0x000007e5;
        set_property(dev, "interrupts", (char *)props, 4 * sizeof(props[0]));
        props[0] = 0x0000001f;
        set_property(dev, "upa-portid", (char *)props, 1 * sizeof(props[0]));
        return 0;
}

int sabre_config_cb(const pci_config_t *config)
{
    host_config_cb(config);

    return sabre_configure(get_cur_dev());
}

int bridge_config_cb(const pci_config_t *config)
{
	phandle_t aliases;

	aliases = find_dev("/aliases");
	set_property(aliases, "bridge", config->path, strlen(config->path) + 1);

	return 0;
}

int simba_config_cb(const pci_config_t *config)
{
    u32 props[128];
    int ncells = 0;

    bridge_config_cb(config);

    /* Configure the simba ranges as per the mostly undocumented
       PCI config register in Linux's apb_fake_ranges():
      
       pci@1,1 (pciA):
           IO: 0x1fe02000000-0x1fe027fffff
          MEM: 0x1ff20000000-0x1ff5fffffff
          
       pci@1 (pciB):
           IO: 0x1fe02800000-0x1fe02ffffff
          MEM: 0x1ff60000000-0x1ff9fffffff
    */

    switch (PCI_FN(config->dev)) {
    case 1:
        /* IO: 0x1fe02000000-0x1fe027fffff */
        pci_config_write8(config->dev, 0xde, 0x0f);

        /* MEM: 0x1ff20000000-0x1ff5fffffff */
        pci_config_write8(config->dev, 0xdf, 0x06);

        /* Onboard NIC: slot 1, intno 0x21 */
        ncells += pci_encode_phys_addr(props + ncells, 0, 0, PCI_ADDR(1, 1, 0), 0, 0);
        props[ncells++] = 0x1;
        props[ncells++] = find_dev("/pci");
        props[ncells++] = 0x21;

        /* Onboard IDE: slot 3, intno 0x20 */
        ncells += pci_encode_phys_addr(props + ncells, 0, 0, PCI_ADDR(1, 3, 0), 0, 0);
        props[ncells++] = 0x1;
        props[ncells++] = find_dev("/pci");
        props[ncells++] = 0x20;
        set_property(get_cur_dev(), "interrupt-map", (char *)props, ncells * sizeof(props[0]));

        props[0] = 0x00fff800;
        props[1] = 0x0;
        props[2] = 0x0;
        props[3] = 0x7;
        set_property(get_cur_dev(), "interrupt-map-mask", (char *)props, 4 * sizeof(props[0]));
        break;

    case 0:
        /* IO: 0x1fe02800000-0x1fe02ffffff */
        pci_config_write8(config->dev, 0xde, 0xf0);

        /* MEM: 0x1ff60000000-0x1ff9fffffff */
        pci_config_write8(config->dev, 0xdf, 0x18);
        break;
    }

    return 0;
}

int ide_config_cb2 (const pci_config_t *config)
{
	ob_ide_init(config->path,
		    config->assigned[0] & ~0x0000000F,
		    (config->assigned[1] & ~0x0000000F) + 2,
		    config->assigned[2] & ~0x0000000F,
		    (config->assigned[3] & ~0x0000000F) + 2);
	return 0;
}

int eth_config_cb (const pci_config_t *config)
{
	phandle_t ph = get_cur_dev();

	set_property(ph, "network-type", "ethernet", 9);
	set_property(ph, "removable", "network", 8);
	set_property(ph, "category", "net", 4);

        return 0;
}

int sunhme_config_cb(const pci_config_t *config)
{
	phandle_t ph = get_cur_dev();
	
	set_int_property(ph, "hm-rev", 0x21);
	
	return eth_config_cb(config);
}

int rtl8139_config_cb(const pci_config_t *config)
{
#ifdef CONFIG_PPC
	/* Apple's OF seemingly enables bus mastering on some cards by
	 * default, which means that some buggy drivers forget to
	 * explicitly set it (OS X, MorphOS). Mimic this behaviour so
	 * that these buggy drivers work under emulation. */
	if (is_apple()) {
		ob_pci_enable_bus_master(config);
	}
#endif

	return eth_config_cb(config);
}

int sungem_config_cb (const pci_config_t *config)
{
	phandle_t ph = get_cur_dev();
	uint32_t val, *mmio;
	uint8_t mac[6];
	ucell virt;

#define MAC_ADDR0	(0x6080UL/4)	/* MAC Address 0 Register	*/
#define MAC_ADDR1	(0x6084UL/4)	/* MAC Address 1 Register	*/
#define MAC_ADDR2	(0x6088UL/4)	/* MAC Address 2 Register	*/

	/* Map PCI memory BAR 0 to access the sungem registers */
	virt = ob_pci_map(config->assigned[0], 0x8000);
	mmio = (void *)(uintptr_t)virt;
	
	val = __le32_to_cpu(*(mmio + MAC_ADDR0));
	mac[5] = val & 0xff;
	mac[4] = (val >> 8) & 0xff;
	val = __le32_to_cpu(*(mmio + MAC_ADDR1));
	mac[3] = val & 0xff;
	mac[2] = (val >> 8) & 0xff;
	val = __le32_to_cpu(*(mmio + MAC_ADDR2));
	mac[1] = val & 0xff;
	mac[0] = (val >> 8) & 0xff;
	set_property(ph, "local-mac-address", (char *)mac, 6);
	
	ob_pci_unmap(virt, 0x8000);
	return 0;
}

int virtio_blk_config_cb(const pci_config_t *config)
{
#ifdef CONFIG_DRIVER_VIRTIO_BLK
	pci_addr addr;
	uint8_t idx, cap_idx, cap_vndr;
	uint8_t cfg_type, bar;
	uint16_t status;
	uint32_t offset, notify_mult = 0;
	uint64_t common_cfg = 0, device_cfg = 0, notify_base = 0;

	addr = PCI_ADDR(
		PCI_BUS(config->dev),
		PCI_DEV(config->dev),
		PCI_FN(config->dev));

	idx = (uint8_t)(pci_config_read16(addr, PCI_DEVICE_ID) & 0xff) - 1;

	/*  Check PCI capabilties: if they don't exist then we're certainly not
		a 1.0 device */
	status = pci_config_read16(addr, PCI_STATUS);
	if (!(status & PCI_STATUS_CAP_LIST)) {
		return 0;
	}

	/* Locate VIRTIO_PCI_CAP_COMMON_CFG and VIRTIO_PCI_CAP_DEVICE_CFG */
	cap_idx = pci_config_read8(addr, PCI_CAPABILITY_LIST);
	while ((cap_vndr = pci_config_read8(addr, cap_idx)) != 0) {
		if (cap_vndr == PCI_CAP_ID_VNDR) {
			cfg_type = pci_config_read8(addr, cap_idx + 0x3);
			bar = pci_config_read8(addr, cap_idx + 0x4);
			offset = pci_config_read32(addr, cap_idx + 0x8);

			switch (cfg_type) {
			case VIRTIO_PCI_CAP_COMMON_CFG:
				common_cfg = arch->host_pci_base + (config->assigned[bar] & ~0x0000000F) + offset;
				break;
			case VIRTIO_PCI_CAP_NOTIFY_CFG:
				notify_base = arch->host_pci_base + (config->assigned[bar] & ~0x0000000F) + offset;
				notify_mult = pci_config_read32(addr, cap_idx + 16);
				break;
			case VIRTIO_PCI_CAP_DEVICE_CFG:
				device_cfg = arch->host_pci_base + (config->assigned[bar] & ~0x0000000F) + offset;
				break;
			}
		}

		cap_idx = pci_config_read8(addr, cap_idx + 1);
	}

	/* If we didn't find the required configuration then exit */
	if (common_cfg == 0 || device_cfg == 0 || notify_base == 0) {
		return 0;
	}

	/* Enable bus mastering to ensure vring processing will run. */
	ob_pci_enable_bus_master(config);

	ob_virtio_init(config->path, "virtio-blk", common_cfg, device_cfg,
					notify_base, notify_mult, idx);
#endif
	return 0;
}

/*
 * "Designing PCI Cards and Drivers for Power Macintosh Computers", p. 454
 *
 *  "AAPL,address" provides an array of 32-bit logical addresses
 *  Nth entry corresponding to Nth "assigned-address" base address entry.
 */

static void pci_set_AAPL_address(const pci_config_t *config)
{
	phandle_t dev = get_cur_dev();
	cell props[7];
	uint32_t mask;
	int ncells, i, flags, space_code;

	ncells = 0;
	for (i = 0; i < 6; i++) {
		if (!config->assigned[i] || !config->sizes[i])
			continue;
		pci_decode_pci_addr(config->assigned[i],
				    &flags, &space_code, &mask);

		props[ncells++] = pci_bus_addr_to_host_addr(space_code,
					config->assigned[i] & ~mask);
	}
	if (ncells)
		set_property(dev, "AAPL,address", (char *)props,
			     ncells * sizeof(cell));
}

static void pci_set_assigned_addresses(phandle_t phandle,
                                       const pci_config_t *config, int num_bars)
{
	phandle_t dev = phandle;
	u32 props[32];
	int ncells;
	int i;
	uint32_t mask;
	int flags, space_code;

	ncells = 0;
	for (i = 0; i < num_bars; i++) {
		/* consider only bars with non-zero region size */
		if (!config->sizes[i])
			continue;
		pci_decode_pci_addr(config->assigned[i],
				    &flags, &space_code, &mask);

		ncells += pci_encode_phys_addr(props + ncells,
				     flags, space_code, config->dev,
				     PCI_BASE_ADDR_0 + (i * sizeof(uint32_t)),
				     config->assigned[i] & ~mask);

		props[ncells++] = 0x00000000;
		props[ncells++] = config->sizes[i];
	}
	if (ncells)
		set_property(dev, "assigned-addresses", (char *)props,
			     ncells * sizeof(props[0]));
}

/* call after writing "reg" property to update config->path */
static void ob_pci_reload_device_path(phandle_t phandle, pci_config_t *config)
{
    /* since "name" and "reg" are now assigned
       we need to reload current node name */
    char *new_path = get_path_from_ph(phandle);
    if (new_path) {
        if (0 != strcmp(config->path, new_path)) {
            PCI_DPRINTF("\n=== CHANGED === package path old=%s new=%s\n",
                    config->path, new_path);
            strncpy(config->path, new_path, sizeof(config->path));
            config->path[sizeof(config->path)-1] = '\0';
        }
        free(new_path);
    } else {
        PCI_DPRINTF("\n=== package path old=%s new=NULL\n", config->path);
    }
}

static void pci_set_reg(phandle_t phandle,
                        pci_config_t *config, int num_bars)
{
	phandle_t dev = phandle;
	u32 props[38];
	int ncells;
	int i;
	uint32_t mask;
	int space_code, flags;

    ncells = 0;

    /* first (addr, size) pair is the beginning of configuration address space */
	ncells += pci_encode_phys_addr(props + ncells, 0, CONFIGURATION_SPACE,
			     config->dev, 0, 0);

	ncells += pci_encode_size(props + ncells, 0);

	for (i = 0; i < num_bars; i++) {
		/* consider only bars with non-zero region size */
		if (!config->sizes[i])
			continue;

		pci_decode_pci_addr(config->regions[i],
				    &flags, &space_code, &mask);

		ncells += pci_encode_phys_addr(props + ncells,
				     flags, space_code, config->dev,
				     PCI_BASE_ADDR_0 + (i * sizeof(uint32_t)),
				     config->regions[i] & ~mask);

		/* set size */
		ncells += pci_encode_size(props + ncells, config->sizes[i]);
	}

	set_property(dev, "reg", (char *)props, ncells * sizeof(props[0]));
    ob_pci_reload_device_path(dev, config);

#if defined(CONFIG_DEBUG_PCI)
    dump_reg_property("pci_set_reg", ncells, props);
#endif
}


static void pci_set_ranges(const pci_config_t *config)
{
	phandle_t dev = get_cur_dev();
	u32 props[32];
	int ncells;
  	int i;
	uint32_t mask;
	int flags;
	int space_code;

	ncells = 0;
	for (i = 0; i < 6; i++) {
		if (!config->assigned[i] || !config->sizes[i])
			continue;

		/* child address */

		props[ncells++] = 0x00000000;

		/* parent address */

		pci_decode_pci_addr(config->assigned[i],
				    &flags, &space_code, &mask);
		ncells += pci_encode_phys_addr(props + ncells, flags, space_code,
				     config->dev, 0x10 + i * 4,
				     config->assigned[i] & ~mask);

		/* size */

		props[ncells++] = config->sizes[i];
  	}
	set_property(dev, "ranges", (char *)props, ncells * sizeof(props[0]));
}

int macio_heathrow_config_cb (const pci_config_t *config)
{
	pci_set_ranges(config);

#ifdef CONFIG_DRIVER_MACIO
        ob_macio_heathrow_init(config->path, config->assigned[0] & ~0x0000000F);
#endif
	return 0;
}

int macio_keylargo_config_cb (const pci_config_t *config)
{
        pci_set_ranges(config);

#ifdef CONFIG_DRIVER_MACIO
        ob_macio_keylargo_init(config->path, config->assigned[0] & ~0x0000000F);
#endif
        return 0;
}

int vga_config_cb (const pci_config_t *config)
{
#ifdef CONFIG_PPC
        unsigned long rom;
        uint32_t rom_size, size, bar;
        phandle_t ph;
#endif
        if (config->assigned[0] != 0x00000000) {
            setup_video();

#ifdef CONFIG_PPC
            if (config->assigned[6]) {
                    rom = pci_bus_addr_to_host_addr(MEMORY_SPACE_32,
                                                    config->assigned[6] & ~0x0000000F);
                    rom_size = config->sizes[6];

                    bar = pci_config_read32(config->dev, PCI_ROM_ADDRESS);
                    bar |= PCI_ROM_ADDRESS_ENABLE;
                    pci_config_write32(config->dev, PCI_COMMAND, bar);
                    ph = get_cur_dev();

                    if (rom_size >= 8) {
                            const char *p;

                            p = (const char *)rom;
                            if (p[0] == 'N' && p[1] == 'D' && p[2] == 'R' && p[3] == 'V') {
                                    size = *(uint32_t*)(p + 4);
                                    set_property(ph, "driver,AAPL,MacOS,PowerPC",
                                                 p + 8, size);
                            } else if (p[0] == 'J' && p[1] == 'o' &&
                                       p[2] == 'y' && p[3] == '!') {
                                    set_property(ph, "driver,AAPL,MacOS,PowerPC",
                                                 p, rom_size);
                            }
                    }
            }
#endif

            /* Currently we don't read FCode from the hardware but execute
             * it directly */
            feval("['] vga-driver-fcode 2 cells + 1 byte-load");

#ifdef CONFIG_MOL
            /* Install special words for Mac On Linux */
            molvideo_init();
#endif
        }

	return 0;
}

int ebus_config_cb(const pci_config_t *config)
{
#ifdef CONFIG_DRIVER_EBUS
    phandle_t dev = get_cur_dev();
    uint32_t props[12];
    int ncells;
    int i;
    uint32_t mask;
    int flags, space_code;
    ucell virt;
    phys_addr_t io_phys_base = 0;

    /* Serial */
    props[0] = 0x14;
    props[1] = 0x3f8;
    props[2] = 1;
    props[3] = find_dev("/pci");
    props[4] = 0x2b;
    
    /* PS2 keyboard */
    props[5] = 0x14;
    props[6] = 0x60;
    props[7] = 1;
    props[8] = find_dev("/pci");
    props[9] = 0x29;
    
    set_property(dev, "interrupt-map", (char *)props, 10 * sizeof(props[0]));

    props[0] = 0x000001ff;
    props[1] = 0xffffffff;
    props[2] = 3;
    set_property(dev, "interrupt-map-mask", (char *)props, 3 * sizeof(props[0]));

    /* Build ranges property from the BARs */
    ncells = 0;
    for (i = 0; i < 6; i++) {
        /* consider only bars with non-zero region size */
        if (!config->sizes[i])
            continue;

        pci_decode_pci_addr(config->assigned[i],
                            &flags, &space_code, &mask);

        props[ncells++] = PCI_BASE_ADDR_0 + (i * sizeof(uint32_t));
        props[ncells++] = 0x0;

        ncells += pci_encode_phys_addr(props + ncells,
                                       flags, space_code, config->dev,
                                       PCI_BASE_ADDR_0 + (i * sizeof(uint32_t)),
                                       config->assigned[i] & ~mask);

        props[ncells++] = config->sizes[i];

        /* Store base of IO space for NVRAM */
        if (io_phys_base == 0x0 && space_code == IO_SPACE) {
            io_phys_base = pci_bus_addr_to_host_addr(space_code, config->assigned[i] & ~mask);
        }
    }

    set_property(dev, "ranges", (char *)props, ncells * sizeof(props[0]));

    /*  Build eeprom node */
    fword("new-device");
    PUSH(0x14);
    fword("encode-int");
    PUSH(0x2000);
    fword("encode-int");
    fword("encode+");
    PUSH(0x2000);
    fword("encode-int");
    fword("encode+");
    push_str("reg");
    fword("property");

    push_str("mk48t59");
    fword("model");

    /* OpenSolaris (e.g. Milax) requires the RTC to be pre-mapped by the PROM */
    virt = ofmem_map_io(io_phys_base + 0x2000, 0x2000);
    PUSH(virt);
    fword("encode-int");
    push_str("address");
    fword("property");
    
    push_str("eeprom");
    fword("device-name");
    fword("finish-device");

    /* Build power node */
    fword("new-device");
    PUSH(0x14);
    fword("encode-int");
    PUSH(0x7240);
    fword("encode-int");
    fword("encode+");
    PUSH(0x4);
    fword("encode-int");
    fword("encode+");
    push_str("reg");
    fword("property");

    PUSH(0);
    PUSH(0);
    push_str("button");
    fword("property");

    PUSH(1);
    fword("encode-int");
    push_str("interrupts");
    fword("property");

    /* Map the power registers so we can use them */
    virt = ofmem_map_io(io_phys_base + 0x7240, 0x4);
    PUSH(virt);
    fword("encode-int");
    push_str("address");
    fword("property");

    push_str("power");
    fword("device-name");
    fword("finish-device");

#ifdef CONFIG_DRIVER_FLOPPY
    ob_floppy_init(config->path, "fdthree", 0x3f0ULL, 0);
#endif
#ifdef CONFIG_DRIVER_PC_SERIAL
    ob_pc_serial_init(config->path, "su", (PCI_BASE_ADDR_1 | 0ULL) << 32, 0x3f8ULL, 0);
#endif
#ifdef CONFIG_DRIVER_PC_KBD
    ob_pc_kbd_init(config->path, "kb_ps2", NULL, (PCI_BASE_ADDR_1 | 0ULL) << 32, 0x60ULL, 1, 0);
#endif
#endif
    return 0;
}

int i82378_config_cb(const pci_config_t *config)
{
#ifdef CONFIG_DRIVER_PC_SERIAL
    ob_pc_serial_init(config->path, "serial", arch->io_base, 0x3f8ULL, 0);
#endif
#ifdef CONFIG_DRIVER_PC_KBD
    ob_pc_kbd_init(config->path, "keyboard", NULL, arch->io_base, 0x60ULL, 0, 0);
#endif
#ifdef CONFIG_DRIVER_IDE
    ob_ide_init(config->path, 0x1f0, 0x3f6, 0x170, 0x376);
#endif

    return 0;
}

int usb_ohci_config_cb(const pci_config_t *config)
{
#ifdef CONFIG_DRIVER_USB
    pci_addr addr = PCI_ADDR(
        PCI_BUS(config->dev), PCI_DEV(config->dev), PCI_FN(config->dev));

    ob_usb_ohci_init(config->path, addr);
#endif
    return 0;
}

int lsi53c810_config_cb(const pci_config_t *config)
{    
#ifdef CONFIG_DRIVER_LSI_53C810
    uint64_t mmio, ram;

    /* Enable PCI bus mastering */
    ob_pci_enable_bus_master(config);
    
    /* Map PCI memory BAR 1: LSI MMIO */
    mmio = ob_pci_map(config->assigned[1], 0x400);

    /* Map PCI memory BAR 2: LSI RAM */
    ram = ob_pci_map(config->assigned[2], 0x400);    
    
    ob_lsi_init(config->path, mmio, ram);
#endif
    return 0;
}

void ob_pci_enable_bus_master(const pci_config_t *config)
{
	/* Enable bus mastering for the PCI device */
	uint16_t cmd;
	pci_addr addr = PCI_ADDR(
		PCI_BUS(config->dev), PCI_DEV(config->dev), PCI_FN(config->dev));

	cmd = pci_config_read16(addr, PCI_COMMAND);
	cmd |= PCI_COMMAND_BUS_MASTER;
	pci_config_write16(addr, PCI_COMMAND, cmd);
}

static void ob_pci_add_properties(phandle_t phandle,
                                  pci_addr addr, const pci_dev_t *pci_dev,
                                  const pci_config_t *config, int num_bars)
{
	/* cannot use get_cur_dev() path resolution since "name" and "reg"
	   properties are being changed */
	phandle_t dev=phandle;
	int status,id;
	uint16_t vendor_id, device_id;
	uint8_t rev;
	uint8_t class_prog;
	uint32_t class_code;
	char path[256];

	vendor_id = pci_config_read16(addr, PCI_VENDOR_ID);
	device_id = pci_config_read16(addr, PCI_DEVICE_ID);
	rev = pci_config_read8(addr, PCI_REVISION_ID);
	class_prog = pci_config_read8(addr, PCI_CLASS_PROG);
	class_code = pci_config_read16(addr, PCI_CLASS_DEVICE);

    /* Default path if we don't match anything */
    snprintf(path, sizeof(path), "pci%x,%x", vendor_id, device_id);

    if (pci_dev) {
        /**/
        if (pci_dev->name) {
            push_str(pci_dev->name);
            fword("device-name");
        } else {
            push_str(path);
            fword("device-name");
        }
    } else {
        PCI_DPRINTF("*** missing pci_dev\n");
        push_str(path);
        fword("device-name");
    }

	/* create properties as described in 2.5 */

	set_int_property(dev, "vendor-id", vendor_id);
	set_int_property(dev, "device-id", device_id);
	set_int_property(dev, "revision-id", rev);
	set_int_property(dev, "class-code", class_code << 8 | class_prog);

	if (config->irq_pin) {
		if (is_oldworld()) {
			set_int_property(dev, "AAPL,interrupts", config->irq_line);
		} else {
			set_int_property(dev, "interrupts", config->irq_pin);
		}
	}

	set_int_property(dev, "min-grant", pci_config_read8(addr, PCI_MIN_GNT));
	set_int_property(dev, "max-latency", pci_config_read8(addr, PCI_MAX_LAT));

	status=pci_config_read16(addr, PCI_STATUS);

	set_int_property(dev, "devsel-speed",
			(status&PCI_STATUS_DEVSEL_MASK)>>10);

	if(status&PCI_STATUS_FAST_BACK)
		set_bool_property(dev, "fast-back-to-back");
	if(status&PCI_STATUS_66MHZ)
		set_bool_property(dev, "66mhz-capable");
	if(status&PCI_STATUS_UDF)
		set_bool_property(dev, "udf-supported");

	id=pci_config_read16(addr, PCI_SUBSYSTEM_VENDOR_ID);
	if(id)
		set_int_property(dev, "subsystem-vendor-id", id);
	id=pci_config_read16(addr, PCI_SUBSYSTEM_ID);
	if(id)
		set_int_property(dev, "subsystem-id", id);

	set_int_property(dev, "cache-line-size",
			pci_config_read16(addr, PCI_CACHE_LINE_SIZE));

	if (pci_dev) {
		if (pci_dev->type) {
			push_str(pci_dev->type);
			fword("device-type");
		}
		if (pci_dev->model) {
			push_str(pci_dev->model);
			fword("model");
		}
		if (pci_dev->compat)
			set_property(dev, "compatible",
				     pci_dev->compat, pci_compat_len(pci_dev));

		if (pci_dev->acells)
			set_int_property(dev, "#address-cells",
					      pci_dev->acells);
		if (pci_dev->scells)
			set_int_property(dev, "#size-cells",
					       pci_dev->scells);
		if (pci_dev->icells)
			set_int_property(dev, "#interrupt-cells",
					      pci_dev->icells);
	}

	pci_set_assigned_addresses(phandle, config, num_bars);

	if (is_apple() && is_oldworld())
		pci_set_AAPL_address(config);

	PCI_DPRINTF("\n");
}

#ifdef CONFIG_XBOX
static char pci_xbox_ignore_device (int bus, int devnum, int fn)
{
	/*
	 * The Xbox MCPX chipset is a derivative of the nForce 1
	 * chipset. It almost has the same bus layout; some devices
	 * cannot be used, because they have been removed.
	 */

	/*
	 * Devices 00:00.1 and 00:00.2 used to be memory controllers on
	 * the nForce chipset, but on the Xbox, using them will lockup
	 * the chipset.
	 */
	if ((bus == 0) && (devnum == 0) && ((fn == 1) || (fn == 2)))
		return 1;

	/*
	 * Bus 1 only contains a VGA controller at 01:00.0. When you try
	 * to probe beyond that device, you only get garbage, which
	 * could cause lockups.
	 */
	if ((bus == 1) && ((devnum != 0) || (fn != 0)))
		return 1;

	/*
	 * Bus 2 used to contain the AGP controller, but the Xbox MCPX
	 * doesn't have one. Probing it can cause lockups.
	 */
	if (bus >= 2)
		return 1;

	return 0;
}
#endif

static void ob_pci_configure_bar(pci_addr addr, pci_config_t *config,
                                 int reg, int config_addr,
                                 uint32_t *p_omask,
                                 unsigned long *mem_base,
                                 unsigned long *io_base)
{
        uint32_t smask, amask, size, reloc, min_align;
        unsigned long base;

        config->assigned[reg] = 0x00000000;
        config->sizes[reg] = 0x00000000;

        if ((*p_omask & 0x0000000f) == 0x4) {
                /* 64 bits memory mapping */
                PCI_DPRINTF("Skipping 64 bit BARs for %s\n", config->path);
                return;
        }

        config->regions[reg] = pci_config_read32(addr, config_addr);

        /* get region size */

        pci_config_write32(addr, config_addr, 0xffffffff);
        smask = pci_config_read32(addr, config_addr);
        if (smask == 0x00000000 || smask == 0xffffffff)
                return;

        if (smask & 0x00000001 && reg != 6) {
                /* I/O space */
                base = *io_base;
                min_align = 1 << 7;
                amask = 0x00000001;
        } else {
                /* Memory Space */
                base = *mem_base;
                min_align = 1 << 16;
                amask = 0x0000000F;
                if (reg == 6) {
                        smask |= 1; /* ROM */
                }
        }
        *p_omask = smask & amask;
        smask &= ~amask;
        size = (~smask) + 1;
        config->sizes[reg] = size;
        reloc = base;
        if (size < min_align)
                size = min_align;
        reloc = (reloc + size -1) & ~(size - 1);
        if (*io_base == base) {
                PCI_DPRINTF("changing io_base from 0x%lx to 0x%x\n",
                            *io_base, reloc + size);
                *io_base = reloc + size;
        } else {
                PCI_DPRINTF("changing mem_base from 0x%lx to 0x%x\n",
                            *mem_base, reloc + size);
                *mem_base = reloc + size;
        }
        PCI_DPRINTF("Configuring BARs for %s: reloc 0x%x omask 0x%x "
                    "io_base 0x%lx mem_base 0x%lx size 0x%x\n",
                    config->path, reloc, *p_omask, *io_base, *mem_base, size);
        pci_config_write32(addr, config_addr, reloc | *p_omask);
        config->assigned[reg] = reloc | *p_omask;
}

static void ob_pci_configure_irq(pci_addr addr, pci_config_t *config)
{
        uint8_t irq_pin, irq_line;

        irq_pin =  pci_config_read8(addr, PCI_INTERRUPT_PIN);
        if (irq_pin) {
                config->irq_pin = irq_pin;
                irq_pin = (((config->dev >> 11) & 0x1F) + irq_pin - 1) & 3;
                irq_line = arch->irqs[irq_pin];
                pci_config_write8(addr, PCI_INTERRUPT_LINE, irq_line);
                config->irq_line = irq_line;
        } else
                config->irq_line = -1;
}

static void
ob_pci_configure(pci_addr addr, pci_config_t *config, int num_regs, int rom_bar,
                 unsigned long *mem_base, unsigned long *io_base)

{
        uint32_t omask, mask;
        uint16_t cmd;
        int reg, flags, space_code;
        pci_addr config_addr;

        ob_pci_configure_irq(addr, config);

        omask = 0x00000000;
        for (reg = 0; reg < num_regs; ++reg) {
                config_addr = PCI_BASE_ADDR_0 + reg * 4;

                ob_pci_configure_bar(addr, config, reg, config_addr,
                                     &omask, mem_base,
                                     io_base);

                /* Ignore 64-bit BAR MSBs (always map in 32-bit space) */
                pci_decode_pci_addr(config->assigned[reg],
                                    &flags, &space_code, &mask);

                if (space_code == MEMORY_SPACE_64) {
                    reg++;
                }
        }

        if (rom_bar) {
                config_addr = rom_bar;
                ob_pci_configure_bar(addr, config, reg, config_addr,
                                     &omask, mem_base, io_base);
        }
        cmd = pci_config_read16(addr, PCI_COMMAND);
        cmd |= PCI_COMMAND_IO | PCI_COMMAND_MEMORY;
        pci_config_write16(addr, PCI_COMMAND, cmd);
}

static phandle_t ob_configure_pci_device(const char* parent_path,
        int *bus_num, unsigned long *mem_base, unsigned long *io_base,
        int bus, int devnum, int fn, int *p_is_multi);

static void ob_scan_pci_bus(int *bus_num, unsigned long *mem_base,
                            unsigned long *io_base, const char *path,
                            int bus)
{
	int devnum, fn, is_multi;

	PCI_DPRINTF("\nScanning bus %d at %s...\n", bus, path);

	for (devnum = 0; devnum < 32; devnum++) {
		is_multi = 0;
		for (fn = 0; fn==0 || (is_multi && fn<8); fn++) {
		    ob_configure_pci_device(path, bus_num, mem_base, io_base,
		            bus, devnum, fn, &is_multi);

		}
	}
}

#if defined(CONFIG_SPARC64)

/* Convert device/irq pin to interrupt property */
#define SUN4U_PCIAINTERRUPT(dev, irq_pin) \
            ((((dev >> 11) << 2) + irq_pin - 1) & 0x1f)
            
#define SUN4U_PCIBINTERRUPT(dev, irq_pin) \
            ((0x10 + (((dev >> 11) << 2) + irq_pin - 1)) & 0x1f)

static void ob_pci_simbaB_bus_interrupt(ucell dnode, u32 *props, int *ncells, u32 addr, u32 intno)
{
    *ncells += pci_encode_phys_addr(props + *ncells, 0, 0, addr, 0, 0);
    props[(*ncells)++] = intno;
    props[(*ncells)++] = dnode;
    props[(*ncells)++] = SUN4U_PCIBINTERRUPT(addr, intno);
}

static void ob_pci_bus_set_interrupt_map(phandle_t pcibus, phandle_t dnode,
              void (*func)(ucell dnode, u32 *props, int *ncells, u32 addr, u32 intno));

static void ob_scan_sabre_pci_bus(int *bus_num, unsigned long *mem_base,
                            unsigned long *io_base, const char *path,
                            int bus)
{
	int devnum, fn, is_multi;
	phandle_t ph;

	PCI_DPRINTF("\nScanning sabre bus %d at %s...\n", bus, path);
	
	/* Horrible sabre hack: the PCI bridge with the on-board devices
	   is located at devfn (1,1) so if we use the standard scan function
	   we end up with our ioports not mapped at io_base == 0x0 which
	   breaks many assumptions in OpenBIOS. Hence do a custom scan for
	   sabre which does things in the right order. */
	for (devnum = 0; devnum < 32; devnum++) {
		is_multi = 0;
		
		if (devnum == 1) {
			/* Force io_base/mem_base to match the pciA simba range */
			*io_base = 0x0;       /* because of arch->iobase */
			*mem_base = 0x20000000;
			
			ob_configure_pci_device(path, bus_num, mem_base, io_base,
				bus, 1, 1, &is_multi);
			
			/* Force io_base/mem_base to match the pciB simba range */
			*io_base = 0x800000;  /* because of arch->iobase */
			*mem_base = 0x60000000;
			
			ph = ob_configure_pci_device(path, bus_num, mem_base, io_base,
				bus, 1, 0, &is_multi);
			
			/* Set up pciB interrupt map */
                        ob_pci_bus_set_interrupt_map(ph, find_dev("/pci"), ob_pci_simbaB_bus_interrupt);
		} else {
			for (fn = 0; fn==0 || (is_multi && fn<8); fn++) {
				ob_configure_pci_device(path, bus_num, mem_base, io_base,
					bus, devnum, fn, &is_multi);
			}
		}
	}
}
#endif

static void ob_configure_pci_bridge(pci_addr addr,
                                    int *bus_num, unsigned long *mem_base,
                                    unsigned long *io_base,
                                    int primary_bus, pci_config_t *config)
{
    unsigned long old_mem_base, old_io_base, io_scan_limit;
    uint16_t cmd;
    phandle_t ph;

    config->primary_bus = primary_bus;
    pci_config_write8(addr, PCI_PRIMARY_BUS, config->primary_bus);

    config->secondary_bus = *bus_num;
    pci_config_write8(addr, PCI_SECONDARY_BUS, config->secondary_bus);

    config->subordinate_bus = 0xff;
    pci_config_write8(addr, PCI_SUBORDINATE_BUS, config->subordinate_bus);

    PCI_DPRINTF("scanning new pci bus %u under bridge %s\n",
            config->secondary_bus, config->path);

    /* Temporarily add bus-range property to allow the secondary bus to
       determine its bus num */
    ph = find_dev(config->path);
    set_int_property(ph, "bus-range", *bus_num);

    /* Always expose the legacy ioports on the first PCI bridge. If we
       must have legacy devices behind a PCI bridge then they must be
       on the first one discovered to ensure that the ioports will work. */
    if (primary_bus > 0 && *io_base < 0x1000) {
        *io_base = 0x0;
    }

    /* Align mem_base up to nearest MB, io_base up to nearest 4K */
    old_mem_base = (*mem_base + 0xfffff - 1) & ~(0xfffff - 1);
    *mem_base = old_mem_base;
    old_io_base = (*io_base + 0xfff - 1) & ~(0xfff - 1);
    *io_base = old_io_base;

    /* Set the base limit registers */
    pci_config_write16(addr, PCI_MEMORY_BASE, ((*mem_base >> 16) & ~(0xf)));
    pci_config_write16(addr, PCI_IO_BASE_UPPER, (*io_base >> 16));
    pci_config_write8(addr, PCI_IO_BASE, ((*io_base >> 8) & ~(0xf)));

    /* Always ensure legacy ioports are accessible during enumeration.
       Some drivers (e.g. IDE) will attempt ioport access as part of
       the configuration process, so we allow them during the secondary
       bus scan and then set the correct IO limit below. */
    io_scan_limit = *io_base + 0xffff;
    pci_config_write16(addr, PCI_IO_LIMIT_UPPER, (io_scan_limit >> 16));
    pci_config_write8(addr, PCI_IO_LIMIT, (io_scan_limit >> 8) & ~(0xf));

    /* make pci bridge parent device, prepare for recursion */
    
#if defined(CONFIG_SPARC64)
    /* Horrible hack for sabre */
    int vid = pci_config_read16(addr, PCI_VENDOR_ID);
    int did = pci_config_read16(addr, PCI_DEVICE_ID);

    if (vid == PCI_VENDOR_ID_SUN && did == PCI_DEVICE_ID_SUN_SABRE) {
        ob_scan_sabre_pci_bus(bus_num, mem_base, io_base,
                        config->path, config->secondary_bus);       
    } else {
        ob_scan_pci_bus(bus_num, mem_base, io_base,
                        config->path, config->secondary_bus);
    }
#else
    ob_scan_pci_bus(bus_num, mem_base, io_base,
                    config->path, config->secondary_bus);
#endif
    /* bus scan updates *bus_num to last revealed pci bus number */
    config->subordinate_bus = *bus_num;
    pci_config_write8(addr, PCI_SUBORDINATE_BUS, config->subordinate_bus);

    PCI_DPRINTF("bridge %s PCI bus primary=%d secondary=%d subordinate=%d\n",
            config->path, config->primary_bus, config->secondary_bus,
            config->subordinate_bus);

    /* Align mem_base up to nearest MB, io_base up to nearest 4K */
    *mem_base = (*mem_base + 0xfffff - 1) & ~(0xfffff - 1);
    *io_base = (*io_base + 0xfff - 1) & ~(0xfff - 1);

    /* Set the limit registers */
    pci_config_write16(addr, PCI_MEMORY_LIMIT, (((*mem_base - 1) >> 16) & ~(0xf)));
    pci_config_write16(addr, PCI_IO_LIMIT_UPPER, ((*io_base - 1) >> 16));
    pci_config_write8(addr, PCI_IO_LIMIT, (((*io_base - 1) >> 8) & ~(0xf)));

    /* Disable unused address spaces */
    cmd = pci_config_read16(addr, PCI_COMMAND);
    if (*mem_base == old_mem_base) {
        pci_config_write16(addr, PCI_COMMAND, (cmd & ~PCI_COMMAND_MEMORY));
    }

    if (*io_base == old_io_base) {
        pci_config_write16(addr, PCI_COMMAND, (cmd & ~PCI_COMMAND_IO));
    }

    pci_set_bus_range(config);
}

static int ob_pci_read_identification(int bus, int devnum, int fn,
                                 int *p_vid, int *p_did,
                                 uint8_t *p_class, uint8_t *p_subclass)
{
    int vid, did;
    uint32_t ccode;
    pci_addr addr;

#ifdef CONFIG_XBOX
    if (pci_xbox_ignore_device (bus, devnum, fn))
        return;
#endif
    addr = PCI_ADDR(bus, devnum, fn);
    vid = pci_config_read16(addr, PCI_VENDOR_ID);
    did = pci_config_read16(addr, PCI_DEVICE_ID);

    if (vid==0xffff || vid==0) {
        return 0;
    }

    if (p_vid) {
        *p_vid = vid;
    }

    if (p_did) {
        *p_did = did;
    }

    ccode = pci_config_read16(addr, PCI_CLASS_DEVICE);

    if (p_class) {
        *p_class = ccode >> 8;
    }

    if (p_subclass) {
        *p_subclass = ccode;
    }

    return 1;
}

static phandle_t ob_configure_pci_device(const char* parent_path,
        int *bus_num, unsigned long *mem_base, unsigned long *io_base,
        int bus, int devnum, int fn, int *p_is_multi)
{
    int vid, did;
    unsigned int htype;
    pci_addr addr;
    pci_config_t config = {};
        const pci_dev_t *pci_dev;
    uint8_t class, subclass, iface;
    int num_bars, rom_bar;
    uint32_t props[3];
    char *unit_str;

    phandle_t phandle = 0, t;
    int is_host_bridge = 0;

    if (!ob_pci_read_identification(bus, devnum, fn, &vid, &did, &class, &subclass)) {
        return 0;
    }

    addr = PCI_ADDR(bus, devnum, fn);
    iface = pci_config_read8(addr, PCI_CLASS_PROG);

    pci_dev = pci_find_device(class, subclass, iface,
                  vid, did);

    PCI_DPRINTF("%x:%x.%x - %x:%x - ", bus, devnum, fn,
            vid, did);

    htype = pci_config_read8(addr, PCI_HEADER_TYPE);

    if (fn == 0) {
        if (p_is_multi) {
            *p_is_multi = htype & 0x80;
        }
    }

    if (class == PCI_BASE_CLASS_BRIDGE &&
            subclass == PCI_SUBCLASS_BRIDGE_HOST) {
        is_host_bridge = 1;
    }

    /* stop adding host bridge accessible from it's primary bus
       PCI host bridge is to be added by host code
    */
    if (is_host_bridge) {
        /* reuse device tree node */
        PCI_DPRINTF("host bridge found - ");

        t = find_dev(parent_path);
        if (get_property(t, "vendor-id", NULL)) {
            PCI_DPRINTF("host bridge already configured\n");
            return 0;
        }
    } else if (pci_dev == NULL || pci_dev->name == NULL) {
        snprintf(config.path, sizeof(config.path),
                "%s/pci%x,%x", parent_path, vid, did);
    } else {
        snprintf(config.path, sizeof(config.path),
                "%s/%s", parent_path, pci_dev->name);
    }

    fword("new-device");

    PCI_DPRINTF("%s - ", config.path);

    config.dev = addr & 0x00FFFFFF;

    if (!is_host_bridge) {
        /* Get encoded address for set-args */
        pci_encode_phys_addr(props, 0, CONFIGURATION_SPACE, config.dev, 0, 0);
        PUSH(props[2]);
        PUSH(props[1]);
        PUSH(props[0]);
        call_parent_method("encode-unit");

        unit_str = pop_fstr_copy();

        /* Call set-args to set up my-space and my-address */
        PUSH(0);
        PUSH(0);
        push_str(unit_str);
        fword("set-args");

        free(unit_str);
    }

    phandle = get_cur_dev();

    switch (class) {
    case PCI_BASE_CLASS_BRIDGE:
        if (subclass != PCI_SUBCLASS_BRIDGE_HOST) {
            BIND_NODE_METHODS(phandle, ob_pci_bridge_node);
        } else {
            BIND_NODE_METHODS(phandle, ob_pci_bus_node);
        }
        break;
    }

    if (htype & PCI_HEADER_TYPE_BRIDGE) {
        num_bars = 2;
        rom_bar  = PCI_ROM_ADDRESS1;
    } else {
        num_bars = 6;
        rom_bar  = PCI_ROM_ADDRESS;
    }

    ob_pci_configure(addr, &config, num_bars, rom_bar,
                     mem_base, io_base);

    ob_pci_add_properties(phandle, addr, pci_dev, &config, num_bars);

    if (!is_host_bridge) {
        pci_set_reg(phandle, &config, num_bars);
    } else {
        pci_host_set_reg(phandle, &config);
    }

    /* call device-specific configuration callback */
    if (pci_dev && pci_dev->config_cb) {
        //activate_device(config.path);
        pci_dev->config_cb(&config);
    }

    /* if devices haven't supplied open/close words then supply them with simple defaults */
    if (!find_package_method("open", phandle) && !find_package_method("close", phandle)) {
        BIND_NODE_METHODS(phandle, ob_pci_simple_node);
    }

    /* scan bus behind bridge device */
    //if (htype & PCI_HEADER_TYPE_BRIDGE && class == PCI_BASE_CLASS_BRIDGE) {
    if ( class == PCI_BASE_CLASS_BRIDGE &&
            ( subclass == PCI_SUBCLASS_BRIDGE_PCI ||
              subclass == PCI_SUBCLASS_BRIDGE_HOST ) ) {

        if (subclass == PCI_SUBCLASS_BRIDGE_PCI) {
            /* reserve next pci bus number for this PCI bridge */
            ++(*bus_num);
        }

        ob_configure_pci_bridge(addr, bus_num, mem_base, io_base, bus, &config);
    }

    fword("finish-device");

    return phandle;
}

static void ob_pci_set_available(phandle_t host, unsigned long mem_base, unsigned long io_base)
{
    /* Create an available property for both memory and IO space */
    uint32_t props[10];
    int ncells;

    ncells = 0;
    ncells += pci_encode_phys_addr(props + ncells, 0, MEMORY_SPACE_32, 0, 0, mem_base);
    ncells += pci_encode_size(props + ncells, arch->mem_len - mem_base);
    ncells += pci_encode_phys_addr(props + ncells, 0, IO_SPACE, 0, 0, io_base);
    ncells += pci_encode_size(props + ncells, arch->io_len - io_base);

    set_property(host, "available", (char *)props, ncells * sizeof(props[0]));
}

#if defined(CONFIG_PPC)
static phandle_t ob_pci_host_set_interrupt_map(phandle_t host)
{
    /* Set the host bridge interrupt map, returning the phandle
       of the interrupt controller */
    phandle_t dnode, target_node;
    char *path, buf[256];

    /* Oldworld macs do interrupt maps differently */
    if (is_oldworld()) {
        return 0;
    }

    PCI_DPRINTF("setting up interrupt map for host %x\n", host);
    dnode = dt_iterate_type(0, "open-pic");
    path = get_path_from_ph(host);
    if (dnode && path) {
        /* patch in openpic interrupt-parent properties */
        snprintf(buf, sizeof(buf), "%s/mac-io", path);
        target_node = find_dev(buf);
        set_int_property(target_node, "interrupt-parent", dnode);

        snprintf(buf, sizeof(buf), "%s/mac-io/escc/ch-a", path);
        target_node = find_dev(buf);
        set_int_property(target_node, "interrupt-parent", dnode);

        snprintf(buf, sizeof(buf), "%s/mac-io/escc/ch-b", path);
        target_node = find_dev(buf);
        set_int_property(target_node, "interrupt-parent", dnode);

        snprintf(buf, sizeof(buf), "%s/mac-io/escc-legacy/ch-a", path);
        target_node = find_dev(buf);
        set_int_property(target_node, "interrupt-parent", dnode);

        snprintf(buf, sizeof(buf), "%s/mac-io/escc-legacy/ch-b", path);
        target_node = find_dev(buf);
        set_int_property(target_node, "interrupt-parent", dnode);

        /* QEMU only emulates 2 of the 3 ata buses currently */
        /* On a new world Mac these are not numbered but named by the
         * ATA version they support. Thus we have: ata-3, ata-3, ata-4
         * On g3beige they all called just ide.
         * We take 2 x ata-3 buses which seems to work for
         * at least the clients we care about */
        snprintf(buf, sizeof(buf), "%s/mac-io/ata-3@20000", path);
        target_node = find_dev(buf);
        set_int_property(target_node, "interrupt-parent", dnode);

        snprintf(buf, sizeof(buf), "%s/mac-io/ata-3@21000", path);
        target_node = find_dev(buf);
        set_int_property(target_node, "interrupt-parent", dnode);

        snprintf(buf, sizeof(buf), "%s/mac-io/via-cuda", path);
        target_node = find_dev(buf);
        set_int_property(target_node, "interrupt-parent", dnode);

        snprintf(buf, sizeof(buf), "%s/mac-io/via-pmu", path);
        target_node = find_dev(buf);
        if (target_node) {
            set_int_property(target_node, "interrupt-parent", dnode);
        }

        snprintf(buf, sizeof(buf), "%s/mac-io/gpio/extint-gpio1", path);
        target_node = find_dev(buf);
        if (target_node) {
            set_int_property(target_node, "interrupt-parent", dnode);
        }

        snprintf(buf, sizeof(buf), "%s/mac-io/gpio/programmer-switch", path);
        target_node = find_dev(buf);
        if (target_node) {
            set_int_property(target_node, "interrupt-parent", dnode);
        }

        target_node = find_dev(path);
        set_int_property(target_node, "interrupt-parent", dnode);

        return dnode;
    }

    return host;
}

static void ob_pci_host_bus_interrupt(ucell dnode, u32 *props, int *ncells, u32 addr, u32 intno)
{
    *ncells += pci_encode_phys_addr(props + *ncells, 0, 0, addr, 0, 0);

    props[(*ncells)++] = intno;
    props[(*ncells)++] = dnode;
    if (!is_apple() && (PCI_DEV(addr) == 1 && PCI_FN(addr) == 0)) {
        /* On PReP machine the LSI SCSI has fixed routing to IRQ 13 */
        props[(*ncells)++] = 13;
    } else {
        props[(*ncells)++] = arch->irqs[((intno - 1) + (addr >> 11)) & 3];
    }
    props[(*ncells)++] = 1;
}

#elif defined(CONFIG_SPARC64)
            
static phandle_t ob_pci_host_set_interrupt_map(phandle_t host)
{
    return host;
}
           
static void ob_pci_host_bus_interrupt(ucell dnode, u32 *props, int *ncells, u32 addr, u32 intno)
{
    /* Note: this is invalid when the Simba bridges are in place
       as it is impossible to physically plug hardware into the PCI
       root bus (and no hardware support for mapping these interrupts
       either) */
    return;
}

#else

static phandle_t ob_pci_host_set_interrupt_map(phandle_t host)
{
    return host;
}

static void ob_pci_host_bus_interrupt(ucell dnode, u32 *props, int *ncells, u32 addr, u32 intno)
{
    return;
}
#endif

static void ob_pci_bus_set_interrupt_map(phandle_t pcibus, phandle_t dnode,
              void (*func)(ucell dnode, u32 *props, int *ncells, u32 addr, u32 intno))
{
    /* Set interrupt-map for PCI devices with an interrupt pin present */
    phandle_t pci_childnode = 0;
    u32 props[128], intno;
    int i, ncells = 0, len;
    u32 *val, addr;
    char *reg;
    
    /* If no destination node specified, do nothing */
    if (dnode == 0) {
        return;
    }

    PUSH(pcibus);
    fword("child");
    pci_childnode = POP();
    while (pci_childnode) {
        intno = get_int_property(pci_childnode, "interrupts", &len);
        if (len && intno) {
            reg = get_property(pci_childnode, "reg", &len);
            if (len && reg) {
                val = (u32 *)reg;

                for (i = 0; i < (len / sizeof(u32)); i += 5) {
                    addr = val[i];

                    /* Device address is in 1st 32-bit word of encoded PCI address for config space */
                    if ((addr & PCI_RANGE_TYPE_MASK) == PCI_RANGE_CONFIG) {
                        (*func)(dnode, props, &ncells, addr, intno);
                    }
                }
            }
        }

        PUSH(pci_childnode);
        fword("peer");
        pci_childnode = POP();
    }

    if (ncells) {
        set_property(pcibus, "interrupt-map", (char *)props, ncells * sizeof(props[0]));

        props[0] = 0x00fff800;
        props[1] = 0x0;
        props[2] = 0x0;
        props[3] = 0x7;
        set_property(pcibus, "interrupt-map-mask", (char *)props, 4 * sizeof(props[0]));
    }
}

int ob_pci_init(void)
{
    int bus, devnum, fn;
    uint8_t class, subclass;
    unsigned long mem_base, io_base;

    pci_config_t config = {}; /* host bridge */
    phandle_t phandle_host = 0, intc;

    PCI_DPRINTF("Initializing PCI host bridge...\n");

    /* Find all PCI bridges */

    mem_base = arch->pci_mem_base;
    /* I/O ports under 0x400 are used by devices mapped at fixed
       location. */
    io_base = 0x400;

    bus = 0;

    for (devnum = 0; devnum < 32; devnum++) {
        /* scan only fn 0 */
        fn = 0;

        if (!ob_pci_read_identification(bus, devnum, fn,
                                        0, 0, &class, &subclass)) {
            continue;
        }

        if (class != PCI_BASE_CLASS_BRIDGE || subclass != PCI_SUBCLASS_BRIDGE_HOST) {
            continue;
        }

        /* create root node for host PCI bridge */

        /* configure  */
        strncpy(config.path, "", sizeof(config.path));

        phandle_host = ob_configure_pci_device(config.path, &bus, &mem_base, &io_base,
                bus, devnum, fn, 0);

        /* we expect single host PCI bridge
           but this may be machine-specific */
        break;
    }

    /* create available attributes for the PCI bridge */
    ob_pci_set_available(phandle_host, mem_base, io_base);

    /* configure the host bridge interrupt map */
    intc = ob_pci_host_set_interrupt_map(phandle_host);
    ob_pci_bus_set_interrupt_map(phandle_host, intc, ob_pci_host_bus_interrupt);

    return 0;
}
