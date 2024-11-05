// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */


#include <skiboot.h>
#include <fsp.h>
#include <fsp-sysparam.h>
#include <opal.h>
#include <console.h>
#include <hostservices.h>
#include <ipmi.h>
#include <debug_descriptor.h>
#include <occ.h>

#include "ibm-fsp.h"

static void map_debug_areas(void)
{
	uint64_t t, i;

	/* Our memcons is in a section of its own and already
	 * aligned to 4K. The buffers are mapped as a whole
	 */
	fsp_tce_map(PSI_DMA_MEMCONS, &memcons, 0x1000);
	fsp_tce_map(PSI_DMA_LOG_BUF, (void*)INMEM_CON_START, INMEM_CON_LEN);

	debug_descriptor.memcons_tce = cpu_to_be32(PSI_DMA_MEMCONS);
	t = be64_to_cpu(memcons.obuf_phys) - INMEM_CON_START + PSI_DMA_LOG_BUF;
	debug_descriptor.memcons_obuf_tce = cpu_to_be32(t);
	t = be64_to_cpu(memcons.ibuf_phys) - INMEM_CON_START + PSI_DMA_LOG_BUF;
	debug_descriptor.memcons_ibuf_tce = cpu_to_be32(t);

	t = PSI_DMA_TRACE_BASE;
	for (i = 0; i < be32_to_cpu(debug_descriptor.num_traces); i++) {
		/*
		 * Trace buffers are misaligned by 0x10 due to the lock
		 * in the trace structure, and their size is also not
		 * completely aligned. (They are allocated so that with
		 * the lock included, they do cover entire multiple of
		 * a 4K page however).
		 *
		 * This means we have to map the lock into the TCEs and
		 * align everything. Not a huge deal but needs to be
		 * taken into account.
		 *
		 * Note: Maybe we should map them read-only...
		 */
		uint64_t tstart, tend, toff, tsize;
		uint64_t trace_phys = be64_to_cpu(debug_descriptor.trace_phys[i]);
		uint32_t trace_size = be32_to_cpu(debug_descriptor.trace_size[i]);

		tstart = ALIGN_DOWN(trace_phys, 0x1000);
		tend = ALIGN_UP(trace_phys + trace_size, 0x1000);
		toff = trace_phys - tstart;
		tsize = tend - tstart;

		fsp_tce_map(t, (void *)tstart, tsize);
		debug_descriptor.trace_tce[i] = cpu_to_be32(t + toff);
		t += tsize;
	}
}


void ibm_fsp_init(void)
{
	/* Early initializations of the FSP interface */
	fsp_init();
	map_debug_areas();
	fsp_sysparam_init();

	/* Get ready to receive E0 class messages. We need to respond
	 * to some of these for the init sequence to make forward progress
	 */
	fsp_console_preinit();

	/* Get ready to receive OCC related messages */
	occ_fsp_init();

	/* Get ready to receive Memory [Un]corretable Error messages. */
	fsp_memory_err_init();

	/* Initialize elog access */
	fsp_elog_read_init();
	fsp_elog_write_init();

	/* Initiate dump service */
	fsp_dump_init();

	/* Start FSP/HV state controller & perform OPL */
	fsp_opl();

	/* Preload hostservices lids */
	hservices_lid_preload();

	/* Initialize SP attention area */
	fsp_attn_init();

	/* Initialize monitoring of TOD topology change event notification */
	fsp_chiptod_init();

	/* Send MDST table notification to FSP */
	op_display(OP_LOG, OP_MOD_INIT, 0x0000);
	fsp_mdst_table_init();

	/* Initialize the panel */
	op_display(OP_LOG, OP_MOD_INIT, 0x0001);
	fsp_oppanel_init();

	/* Start the surveillance process */
	op_display(OP_LOG, OP_MOD_INIT, 0x0002);
	fsp_init_surveillance();

	/* IPMI */
	fsp_ipmi_init();
	ipmi_opal_init();

	/* Initialize sensor access */
	op_display(OP_LOG, OP_MOD_INIT, 0x0003);
	fsp_init_sensor();

	/* LED */
	op_display(OP_LOG, OP_MOD_INIT, 0x0004);
	fsp_led_init();

	/* Monitor for DIAG events */
	op_display(OP_LOG, OP_MOD_INIT, 0x0005);
	fsp_init_diag();

	/* Finish initializing the console */
	op_display(OP_LOG, OP_MOD_INIT, 0x0006);
	fsp_console_init();

	/* Read our initial RTC value */
	op_display(OP_LOG, OP_MOD_INIT, 0x0008);
	fsp_rtc_init();

	/* Initialize code update access */
	op_display(OP_LOG, OP_MOD_INIT, 0x0009);
	fsp_code_update_init();

	/* EPOW */
	op_display(OP_LOG, OP_MOD_INIT, 0x000A);
	fsp_epow_init();

	/* EPOW */
	op_display(OP_LOG, OP_MOD_INIT, 0x000B);
	fsp_dpo_init();

	/* Setup console */
	if (fsp_present())
		fsp_console_add_nodes();

	if (proc_gen >= proc_gen_p9)
		prd_init();

	preload_io_vpd();
}

void ibm_fsp_finalise_dt(bool is_reboot)
{
	if (is_reboot)
		return;

	/*
	 * LED related SPCN commands might take a while to
	 * complete. Call this as late as possible to
	 * ensure we have all the LED information.
	 */
	create_led_device_nodes();

	/*
	 * OCC takes few secs to boot.  Call this as late as
	 * as possible to avoid delay.
	 */
	occ_pstates_init();

	/* Wait for FW VPD data read to complete */
	fsp_code_update_wait_vpd(true);

	fsp_console_select_stdout();
}

void ibm_fsp_exit(void)
{
	op_panel_disable_src_echo();

	/* Clear SRCs on the op-panel when Linux starts */
	op_panel_clear_src();
}

int64_t ibm_fsp_cec_reboot(void)
{
	uint32_t cmd = FSP_CMD_REBOOT;

	if (!fsp_present())
		return OPAL_UNSUPPORTED;

	/* Flash new firmware */
	if (fsp_flash_term_hook &&
	    fsp_flash_term_hook() == OPAL_SUCCESS)
		cmd = FSP_CMD_DEEP_REBOOT;

	/* Clear flash hook */
	fsp_flash_term_hook = NULL;

	printf("FSP: Sending 0x%02x reboot command to FSP...\n", cmd);

	/* If that failed, talk to the FSP */
	if (fsp_sync_msg(fsp_mkmsg(cmd, 0), true))
		return OPAL_BUSY_EVENT;

	return OPAL_SUCCESS;
}

int64_t ibm_fsp_cec_power_down(uint64_t request)
{
	/* Request is:
	 *
	 * 0 = normal
	 * 1 = immediate
	 * (we do not allow 2 for "pci cfg reset" just yet)
	 */

	if (request !=0 && request != 1)
		return OPAL_PARAMETER;

	if (!fsp_present())
		return OPAL_UNSUPPORTED;

	/* Flash new firmware */
	if (fsp_flash_term_hook)
		fsp_flash_term_hook();

	/* Clear flash hook */
	fsp_flash_term_hook = NULL;

	printf("FSP: Sending shutdown command to FSP...\n");

	if (fsp_sync_msg(fsp_mkmsg(FSP_CMD_POWERDOWN_NORM, 1, request), true))
		return OPAL_BUSY_EVENT;

	fsp_reset_links();
	return OPAL_SUCCESS;
}

int64_t ibm_fsp_sensor_read(uint32_t sensor_hndl, int token,
				__be64 *sensor_data)
{
	return fsp_opal_read_sensor(sensor_hndl, token, sensor_data);
}

int __attrconst fsp_heartbeat_time(void)
{
	/* Same as core/timer.c HEARTBEAT_DEFAULT_MS * 10 */
	return 200 * 10;
}

static void fsp_psihb_interrupt(void)
{
	/* Poll the console buffers on any interrupt since we don't
	 * get send notifications
	 */
	fsp_console_poll(NULL);
}

struct platform_psi fsp_platform_psi = {
	.psihb_interrupt = fsp_psihb_interrupt,
	.link_established = fsp_reinit_fsp,
	.fsp_interrupt = fsp_interrupt,
};

struct platform_prd fsp_platform_prd = {
	.msg_response = hservice_hbrt_msg_response,
	.send_error_log = hservice_send_error_log,
	.send_hbrt_msg = hservice_send_hbrt_msg,
	.wakeup = hservice_wakeup,
	.fsp_occ_load_start_status = fsp_occ_load_start_status,
	.fsp_occ_reset_status = fsp_occ_reset_status,
};
