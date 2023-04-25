// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __PLATFORM_H
#define __PLATFORM_H

/* Some fwd declarations for types used further down */
struct phb;
struct pci_device;
struct pci_slot;
struct errorlog;
struct npu2;
struct pau;

enum resource_id {
	RESOURCE_ID_KERNEL,
	RESOURCE_ID_INITRAMFS,
	RESOURCE_ID_CAPP,
	RESOURCE_ID_IMA_CATALOG,
	RESOURCE_ID_VERSION,
	RESOURCE_ID_KERNEL_FW,
};
#define RESOURCE_SUBID_NONE 0
#define RESOURCE_SUBID_SUPPORTED 1


struct bmc_hw_config {
	uint32_t scu_revision_id;
	uint32_t mcr_configuration;
	uint32_t mcr_scu_mpll;
	uint32_t mcr_scu_strap;
};

struct bmc_sw_config {
	/*
	 * Map IPMI_OEM_X to vendor commands for this BMC
	 * 0 = unimplimented
	 */
	uint32_t ipmi_oem_partial_add_esel;
	uint32_t ipmi_oem_pnor_access_status;
	uint32_t ipmi_oem_hiomap_cmd;
};

struct bmc_platform {
	const char *name;
	const struct bmc_hw_config *hw;
	const struct bmc_sw_config *sw;
};

struct ocapi_phy_setup {
	int tx_ffe_pre_coeff;
	int tx_ffe_post_coeff;
	int tx_ffe_boost_en;
};

/* OpenCAPI platform-specific I2C information */
struct platform_ocapi {
	uint8_t i2c_engine;		/* I2C engine number */
	uint8_t i2c_port;		/* I2C port number */
	uint8_t i2c_reset_addr;		/* I2C address for reset */
	uint8_t i2c_reset_brick2;	/* I2C pin to write to reset brick 2 */
	uint8_t i2c_reset_brick3;	/* I2C pin to write to reset brick 3 */
	uint8_t i2c_reset_brick4;	/* I2C pin to write to reset brick 4 */
	uint8_t i2c_reset_brick5;	/* I2C pin to write to reset brick 5 */
	uint8_t i2c_presence_addr;	/* I2C address for presence detection */
	uint8_t i2c_presence_brick2;	/* I2C pin to read for presence on brick 2 */
	uint8_t i2c_presence_brick3;	/* I2C pin to read for presence on brick 3 */
	uint8_t i2c_presence_brick4;	/* I2C pin to read for presence on brick 4 */
	uint8_t i2c_presence_brick5;	/* I2C pin to read for presence on brick 5 */
	bool odl_phy_swap;		/* Swap ODL1 to use brick 2 rather than
					 * brick 1 lanes */
	uint8_t i2c_dev_addr;		/* I2C device address */
	uint8_t i2c_intreset_pin;	/* I2C pin to write to reset */
	uint8_t i2c_predetect_pin;	/* I2C pin to read for presence */
	int64_t (*i2c_assert_reset)(uint8_t i2c_bus_id);
	int64_t (*i2c_deassert_reset)(uint8_t i2c_bus_id);
	const char *(*ocapi_slot_label)(uint32_t chip_id, uint32_t brick_index);
	const struct ocapi_phy_setup *phy_setup;
};

struct dt_node;

/*
 * Just for FSP platforms, allows us to partly decouple
 * FSP specific code from core code.
 */
struct platform_psi {
	void (*psihb_interrupt)(void);
	void (*link_established)(void);
	void (*fsp_interrupt)(void);
};

/*
 * Some PRD functionality is platform specific.
 */
struct platform_prd {
	void (*msg_response)(uint32_t rc);
	int (*send_error_log)(uint32_t plid, uint32_t dsize, void *data);
	int (*send_hbrt_msg)(void *data, u64 dsize);
	int (*wakeup)(uint32_t i_core, uint32_t i_mode);
	int (*fsp_occ_load_start_status)(u64 chipid, s64 status);
	int (*fsp_occ_reset_status)(u64 chipid, s64 status);
};

/*
 * Each platform can provide a set of hooks
 * that can affect the generic code
 */
struct platform {
	const char	*name;

	/*
	 * If BMC is constant, bmc platform specified here.
	 * Platforms can also call set_bmc_platform() if BMC platform is
	 * not a constant.
	 */
	const struct bmc_platform *bmc;

	/*
	 * PSI handling code. FSP specific.
	 */
	const struct platform_psi *psi;

	/*
	 * Platform specific PRD handling
	 */
	const struct platform_prd *prd;

	/* OpenCAPI platform-specific I2C information */
	const struct platform_ocapi *ocapi;

	/* NPU device detection */
	void		(*npu2_device_detect)(struct npu2 *npu);

	/* PAU device detection */
	void		(*pau_device_detect)(struct pau *pau);

	/*
	 * Probe platform, return true on a match, called before
	 * any allocation has been performed outside of the heap
	 * so the platform can perform additional memory reservations
	 * here if needed.
	 *
	 * Only the boot CPU is running at this point and the cpu_thread
	 * structure for secondaries have not been initialized yet. The
	 * timebases are not synchronized.
	 *
	 * Services available:
	 *
	 * - Memory allocations / reservations
	 * - XSCOM
	 * - FSI
	 * - Host Services
	 */
	bool		(*probe)(void);

	/*
	 * This is called right after the secondary processors are brought
	 * up and the timebases in sync to perform any additional platform
	 * specific initializations. On FSP based machines, this is where
	 * the FSP driver is brought up.
	 */
	void		(*init)(void);

	/*
	 * Called once every thread is back in skiboot as part of fast reboot.
	 */
	void		(*fast_reboot_init)(void);

	/*
	 * These are used to power down and reboot the machine
	 */
	int64_t		(*cec_power_down)(uint64_t request);
	int64_t		(*cec_reboot)(void);

	/*
	 * This is called once per PHB before probing. It allows the
	 * platform to setup some PHB private data that can be used
	 * later on by calls such as pci_get_slot_info() below. The
	 * "index" argument is the PHB index within the IO HUB (or
	 * P8 chip).
	 *
	 * This is called before the PHB HW has been initialized.
	 */
	void		(*pci_setup_phb)(struct phb *phb, unsigned int index);

	/*
	 * This is called before resetting the PHBs (lift PERST) and
	 * probing the devices. The PHBs have already been initialized.
	 */
	void		(*pre_pci_fixup)(void);
	/*
	 * Called during PCI scan for each device. For bridges, this is
	 * called before its children are probed. This is called for
	 * every device and for the PHB itself with a NULL pd though
	 * typically the implementation will only populate the slot
	 * info structure for bridge ports
	 */
	void		(*pci_get_slot_info)(struct phb *phb,
					     struct pci_device *pd);

	/*
	 * Called for each device during pci_add_device_nodes() descend
	 * to create the device tree, in order to get the correct per-platform
	 * preference for the ibm,loc-code property
	 */
	void		(*pci_add_loc_code)(struct dt_node *np,
					     struct pci_device *pd);

	/*
	 * Called after PCI probe is complete and before inventory is
	 * displayed in console. This can either run platform fixups or
	 * can be used to send the inventory to a service processor.
	 */
	void		(*pci_probe_complete)(void);

	/*
	 * If the above is set to skiboot, the handler is here
	 */
	void		(*external_irq)(unsigned int chip_id);

	/*
	 * nvram ops.
	 *
	 * Note: To keep the FSP driver simple, we only ever read the
	 * whole nvram once at boot and we do this passing a dst buffer
	 * that is 4K aligned. The read is asynchronous, the backend
	 * must call nvram_read_complete() when done (it's allowed to
	 * do it recursively from nvram_read though).
	 */
	int		(*nvram_info)(uint32_t *total_size);
	int		(*nvram_start_read)(void *dst, uint32_t src,
					    uint32_t len);
	int		(*nvram_write)(uint32_t dst, void *src, uint32_t len);

	int (*secvar_init)(void);

	/*
	 * OCC timeout. This return how long we should wait for the OCC
	 * before timing out. This lets us use a high value on larger FSP
	 * machines and cut it off completely on BML boots and OpenPower
	 * machines without pre-existing OCC firmware. Returns a value in
	 * seconds.
	 */
	uint32_t	(*occ_timeout)(void);

	int		(*elog_commit)(struct errorlog *buf);

	/*
	 * Initiate loading an external resource (e.g. kernel payload, OCC)
	 * into a preallocated buffer.
	 * This is designed to asynchronously load external resources.
	 * Returns OPAL_SUCCESS or error.
	 */
	int		(*start_preload_resource)(enum resource_id id,
						  uint32_t idx,
						  void *buf, size_t *len);

	/*
	 * Returns true when resource is loaded.
	 * Only has to return true once, for the
	 * previous start_preload_resource call for this resource.
	 * If not implemented, will return true and start_preload_resource
	 * *must* have synchronously done the load.
	 * Returns OPAL_SUCCESS, OPAL_BUSY or an error code
	 */
	int		(*resource_loaded)(enum resource_id id, uint32_t idx);

	/*
	 * Executed just prior to creating the dtb for the kernel.
	 */
	void		(*finalise_dt)(bool is_reboot);

	/*
	 * Executed just prior to handing control over to the payload.
	 * Used to terminate watchdogs, etc.
	 */
	void		(*exit)(void);

	/*
	 * Read a sensor value
	 */
	int64_t		(*sensor_read)(uint32_t sensor_hndl, int token,
				       __be64 *sensor_data);
	/*
	 * Return the heartbeat time
	 */
	int		(*heartbeat_time)(void);

	/*
	 * OPAL terminate
	 */
	void __attribute__((noreturn)) (*terminate)(const char *msg);

	/*
	 * SEEPROM update routine
	 */
	void		(*seeprom_update)(void);

	/*
	 * Operator Panel display
	 * Physical FSP op panel or LPC port 80h
	 * or any other "get boot status out to the user" thing.
	 */
	void (*op_display)(enum op_severity sev, enum op_module mod,
			   uint16_t code);

	/*
	 * VPD load.
	 * Currently FSP specific.
	 */
	void (*vpd_iohub_load)(struct dt_node *hub_node);
};

extern struct platform __platforms_start;
extern struct platform __platforms_end;

extern struct platform	platform;
extern const struct bmc_platform *bmc_platform;

extern bool manufacturing_mode;

#define DECLARE_PLATFORM(name)\
static const struct platform __used __section(".platforms") name ##_platform

extern void probe_platform(void);

extern int start_preload_resource(enum resource_id id, uint32_t subid,
				  void *buf, size_t *len);

extern int resource_loaded(enum resource_id id, uint32_t idx);

extern int wait_for_resource_loaded(enum resource_id id, uint32_t idx);

extern void set_bmc_platform(const struct bmc_platform *bmc);

#endif /* __PLATFORM_H */
