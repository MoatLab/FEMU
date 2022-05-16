// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * OPAL Platform abstraction
 *
 * Some OPAL calls may/may not call into the struct platform that's
 * probed during boot. There's also a bunch of platform specific init
 * and configuration that's called.
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <stdlib.h>
#include <skiboot.h>
#include <opal.h>
#include <console.h>
#include <timebase.h>
#include <cpu.h>
#include <chip.h>
#include <xscom.h>
#include <errorlog.h>
#include <bt.h>
#include <nvram.h>
#include <npu2.h>
#include <platforms/astbmc/astbmc.h>

bool manufacturing_mode = false;
struct platform	platform;

DEFINE_LOG_ENTRY(OPAL_RC_ABNORMAL_REBOOT, OPAL_PLATFORM_ERR_EVT, OPAL_CEC,
		 OPAL_CEC_HARDWARE, OPAL_ERROR_PANIC,
		 OPAL_ABNORMAL_POWER_OFF);

/*
 * Various wrappers for platform functions
 */
static int64_t opal_cec_power_down(uint64_t request)
{
	prlog(PR_NOTICE, "OPAL: Shutdown request type 0x%llx...\n", request);

	opal_quiesce(QUIESCE_HOLD, -1);

	console_complete_flush();

	if (platform.cec_power_down)
		return platform.cec_power_down(request);

	return OPAL_SUCCESS;
}
opal_call(OPAL_CEC_POWER_DOWN, opal_cec_power_down, 1);

static int64_t full_reboot(void)
{
	prlog(PR_NOTICE, "OPAL: Reboot request...\n");

	console_complete_flush();

	if (platform.cec_reboot)
		return platform.cec_reboot();

	return OPAL_SUCCESS;
}

static int64_t opal_cec_reboot(void)
{
	opal_quiesce(QUIESCE_HOLD, -1);

	/*
	 * Fast-reset was enabled by default for a long time in an attempt to
	 * make it more stable by exercising it more frequently. This resulted
	 * in a fair amount of pain due to mis-behaving hardware and confusion
	 * about what a "reset" is supposed to do exactly. Additionally,
	 * secure variables require a full reboot to work at all.
	 *
	 * Due to all that fast-reset should only be used if it's explicitly
	 * enabled. It started life as a debug hack and should remain one.
	 */
	if (nvram_query_eq_safe("fast-reset", "1"))
		fast_reboot();

	return full_reboot();
}
opal_call(OPAL_CEC_REBOOT, opal_cec_reboot, 0);

static int64_t opal_cec_reboot2(uint32_t reboot_type, char *diag)
{
	struct errorlog *buf;

	opal_quiesce(QUIESCE_HOLD, -1);

	switch (reboot_type) {
	case OPAL_REBOOT_NORMAL:
		return opal_cec_reboot();
	case OPAL_REBOOT_PLATFORM_ERROR:
		prlog(PR_EMERG,
			  "OPAL: Reboot requested due to Platform error.\n");
		buf = opal_elog_create(&e_info(OPAL_RC_ABNORMAL_REBOOT), 0);
		if (buf) {
			log_append_msg(buf,
			  "OPAL: Reboot requested due to Platform error.");
			if (diag) {
				/* Add user section "DESC" */
				log_add_section(buf, OPAL_ELOG_SEC_DESC);
				log_append_data(buf, diag, strlen(diag));
			}
			log_commit(buf);
		} else {
			prerror("OPAL: failed to log an error\n");
		}
		disable_fast_reboot("Reboot due to Platform Error");
		console_complete_flush();
		return xscom_trigger_xstop();
	case OPAL_REBOOT_FULL_IPL:
		prlog(PR_NOTICE, "Reboot: Full reboot requested");
		return full_reboot();
	case OPAL_REBOOT_MPIPL:
		prlog(PR_NOTICE, "Reboot: OS reported error. Performing MPIPL\n");
		console_complete_flush();
		if (platform.terminate)
			platform.terminate("OS reported error. Performing MPIPL\n");
		else
			full_reboot();
		for (;;);
		break;
	case OPAL_REBOOT_FAST:
		prlog(PR_NOTICE, "Reboot: Fast reboot requested by OS\n");
		fast_reboot();
		prlog(PR_NOTICE, "Reboot: Fast reboot failed\n");
		return OPAL_UNSUPPORTED;
	default:
		prlog(PR_NOTICE, "OPAL: Unsupported reboot request %d\n", reboot_type);
		return OPAL_UNSUPPORTED;
		break;
	}
	return OPAL_SUCCESS;
}
opal_call(OPAL_CEC_REBOOT2, opal_cec_reboot2, 2);

static bool generic_platform_probe(void)
{
	if (dt_find_by_path(dt_root, "bmc")) {
		/* We appear to have a BMC... so let's cross our fingers
		 * and see if we can do anything!
		 */
		prlog(PR_ERR, "GENERIC BMC PLATFORM: **GUESSING** that there's "
		      "*maybe* a BMC we can talk to.\n");
		prlog(PR_ERR, "THIS IS ****UNSUPPORTED****, BRINGUP USE ONLY.\n");
		astbmc_early_init();
	} else {
		uart_init();
	}

	return true;
}

static void generic_platform_init(void)
{
	if (uart_enabled())
		set_opal_console(&uart_opal_con);

	if (dt_find_by_path(dt_root, "bmc")) {
		prlog(PR_ERR, "BMC-GUESSWORK: Here be dragons with a taste for human flesh\n");
		astbmc_init();
	} else {
		/* Otherwise we go down the ultra-minimal path */

		/* Enable a BT interface if we find one too */
		bt_init();
	}

	/* Fake a real time clock */
	fake_rtc_init();
}

static int64_t generic_cec_power_down(uint64_t request __unused)
{
	return OPAL_UNSUPPORTED;
}

static int generic_resource_loaded(enum resource_id id, uint32_t subid)
{
	if (dt_find_by_path(dt_root, "bmc"))
		return flash_resource_loaded(id, subid);

	return OPAL_EMPTY;
}

static int generic_start_preload_resource(enum resource_id id, uint32_t subid,
				 void *buf, size_t *len)
{
	if (dt_find_by_path(dt_root, "bmc"))
		return flash_start_preload_resource(id, subid, buf, len);

	return OPAL_EMPTY;
}

/* These values will work for a ZZ booted using BML */
static const struct platform_ocapi generic_ocapi = {
	.i2c_engine          = 1,
	.i2c_port            = 4,
	.i2c_reset_addr      = 0x20,
	.i2c_reset_brick2    = (1 << 1),
	.i2c_reset_brick3    = (1 << 6),
	.i2c_reset_brick4    = 0, /* unused */
	.i2c_reset_brick5    = 0, /* unused */
	.i2c_presence_addr   = 0x20,
	.i2c_presence_brick2 = (1 << 2), /* bottom connector */
	.i2c_presence_brick3 = (1 << 7), /* top connector */
	.i2c_presence_brick4 = 0, /* unused */
	.i2c_presence_brick5 = 0, /* unused */
	.odl_phy_swap        = true,
};

static struct bmc_platform generic_bmc = {
	.name = "generic",
};

static struct platform generic_platform = {
	.name		= "generic",
	.bmc		= &generic_bmc,
	.probe          = generic_platform_probe,
	.init		= generic_platform_init,
	.nvram_info	= fake_nvram_info,
	.nvram_start_read = fake_nvram_start_read,
	.nvram_write	= fake_nvram_write,
	.cec_power_down	= generic_cec_power_down,
	.start_preload_resource	= generic_start_preload_resource,
	.resource_loaded	= generic_resource_loaded,
	.ocapi		= &generic_ocapi,
	.npu2_device_detect = npu2_i2c_presence_detect, /* Assumes ZZ */
};

const struct bmc_platform *bmc_platform = &generic_bmc;

void set_bmc_platform(const struct bmc_platform *bmc)
{
	if (bmc)
		prlog(PR_NOTICE, "PLAT: Detected BMC platform %s\n", bmc->name);
	else
		bmc = &generic_bmc;

	bmc_platform = bmc;
}

void probe_platform(void)
{
	struct platform *platforms = &__platforms_start;
	unsigned int i;

	/* Detect Manufacturing mode */
	if (dt_find_property(dt_root, "ibm,manufacturing-mode")) {
		/**
		 * @fwts-label ManufacturingMode
		 * @fwts-advice You are running in manufacturing mode.
		 * This mode should only be enabled in a factory during
		 * manufacturing.
		 */
		prlog(PR_NOTICE, "PLAT: Manufacturing mode ON\n");
		manufacturing_mode = true;
	}

	for (i = 0; &platforms[i] < &__platforms_end; i++) {
		if (platforms[i].probe && platforms[i].probe()) {
			platform = platforms[i];
			break;
		}
	}
	if (!platform.name) {
		platform = generic_platform;
		if (platform.probe)
			platform.probe();
	}

	prlog(PR_NOTICE, "PLAT: Detected %s platform\n", platform.name);

	set_bmc_platform(platform.bmc);
}


int start_preload_resource(enum resource_id id, uint32_t subid,
			   void *buf, size_t *len)
{
	if (!platform.start_preload_resource)
		return OPAL_UNSUPPORTED;

	return platform.start_preload_resource(id, subid, buf, len);
}

int resource_loaded(enum resource_id id, uint32_t idx)
{
	if (!platform.resource_loaded)
		return OPAL_SUCCESS;

	return platform.resource_loaded(id, idx);
}

int wait_for_resource_loaded(enum resource_id id, uint32_t idx)
{
	int r = resource_loaded(id, idx);
	int waited = 0;

	while(r == OPAL_BUSY) {
		opal_run_pollers();
		r = resource_loaded(id, idx);
		if (r != OPAL_BUSY)
			break;
		time_wait_ms_nopoll(5);
		waited+=5;
	}

	prlog(PR_TRACE, "PLATFORM: wait_for_resource_loaded %x/%x %u ms\n",
	      id, idx, waited);
	return r;
}

void op_display(enum op_severity sev, enum op_module mod, uint16_t code)
{
	if (platform.op_display)
		platform.op_display(sev, mod, code);
}
