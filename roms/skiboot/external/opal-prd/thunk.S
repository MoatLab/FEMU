// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2015-2017 IBM Corp */
	
#include <endian.h>
#include <asm/unistd.h>

#ifndef __NR_switch_endian
#define __NR_switch_endian 363
#endif

/* a constant to use in the SI field of a little-endian D-form instruction */
#define le_si16(x) (((x & 0xff) << 24) | ((x & 0xff00) << 8))

	.text

	/*
	 * Call into a HBRT BE function
	 * Func desc (opd) will be in BE
	 * Use ldbrx to load from opd
	 */

call_be:

	/* Before we switch, we need to perform some ABI
	 * conversion. We are currently running LE with the
	 * new ABI v2. The GPR content is the same, we do
	 * need save/restore and adjust r2. At this point r11
	 * contain the OPD
	 */
	nop
	nop

	/* We first create a stack frame compatible with BE, we
	 * do a big one just in case... we save LR into our caller's
	 * frame and r2 in our own frame. This is a BE formatted
	 * frame so we store it as 40(r1), not 24(r1)
	 */
	stdu %r1,-128(%r1)
	mflr %r0
	std %r0,(128 + 16)(%r1)
	std %r2,40(%r1)

	/* Grab the target r2 and function pointer */
#if __BYTE_ORDER == __LITTLE_ENDIAN
	ldbrx %r0, 0, %r11
	li %r2, 8
	ldbrx %r2, %r2, %r11
#else
	ld %r0,0(%r11)
	ld %r2,8(%r11)
#endif

	mtlr %r0

#if __BYTE_ORDER == __LITTLE_ENDIAN
	/* Switch to the "other endian" */
	li %r0,__NR_switch_endian
	sc

	/* Branch to LR */
	.long 0x2100804e /* (byteswapped blrl) */

	/* Switch endian back */
	.long 0x00000038 | le_si16(__NR_switch_endian)
			/* byteswapped li %r0,__NR_switch_endian */
	.long 0x02000044 /* byteswapped sc */
#else
	bctrl
#endif
	/* Recover our r2, LR, undo stack frame ... */
	ld %r2,40(%r1)
	ld  %r0,(128+16)(%r1)
	addi %r1,%r1,128
	mtlr %r0
	blr

#define CALL_THUNK(name, idx) 		 	 \
	.globl call_##name			;\
call_##name:					;\
	ld %r11,hservice_runtime_fixed@got(%r2)	;\
	ld %r11,(idx * 8)(%r11)			;\
	b call_be

	/* Instanciate call to HBRT thunks */
	CALL_THUNK(cxxtestExecute, 1)
	CALL_THUNK(get_lid_list, 2)
	CALL_THUNK(occ_load, 3)
	CALL_THUNK(occ_start, 4)
	CALL_THUNK(occ_stop, 5)
	CALL_THUNK(process_occ_error, 6)
	CALL_THUNK(enable_attns, 7)
	CALL_THUNK(disable_attns, 8)
	CALL_THUNK(handle_attns, 9)
	CALL_THUNK(process_occ_reset, 10)
	CALL_THUNK(enable_occ_actuation, 11)
	CALL_THUNK(apply_attr_override, 12)
	CALL_THUNK(mfg_htmgt_pass_thru, 13)
	CALL_THUNK(run_command, 14)
	CALL_THUNK(verify_container, 15)
	CALL_THUNK(sbe_message_passing, 16)
	CALL_THUNK(load_pm_complex, 17)
	CALL_THUNK(start_pm_complex, 18)
	CALL_THUNK(reset_pm_complex, 19)
	CALL_THUNK(get_ipoll_events, 20)
	CALL_THUNK(firmware_notify, 21)
	CALL_THUNK(prepare_hbrt_update, 22)

	.globl call_hbrt_init
call_hbrt_init:
	ld %r11,hbrt_entry@got(%r2)
	b call_be

#if __BYTE_ORDER == __LITTLE_ENDIAN
	/* Callback from HBRT, stack conversion and call into C code,
	 * we arrive here from the thunk macro with r11 containing the
	 * target function and r2 already set from the OPD.
	 */
call_le:
	/* Create a LE stack frame, save LR */
	stdu %r1,-32(%r1)
	mflr %r0
	std %r0,(32+16)(%r1)

	/* Branch to original function */
	mtlr	%r12
	blrl

	/* Restore stack and LR */
	ld  %r0,(32+16)(%r1)
	addi %r1,%r1,32
	mtlr %r0

	/* Switch endian back to BE */
	li %r0,__NR_switch_endian
	sc

	/* Return to BE */
	.long 0x2000804e /* byteswapped blr */

	/* Callback from HBRT. There is one entry point per function.
	 *
	 * We assume the proper r2 is already set via the OPD, so we grab our
	 * target function pointer in r12 and jump to call_le
	 */
#define CALLBACK_THUNK(name)							 \
	.pushsection ".text","ax" 						;\
	.globl	name##_thunk							;\
name##_thunk:									;\
	.long 0x00000038 | le_si16(__NR_switch_endian)				;\
			/* byteswapped li %r0,__NR_switch_endian */		;\
	.long 0x02000044 /* byteswapped sc */					;\
	ld %r12,name@got(%r2)							;\
	b call_le								;\
	.popsection								;\
	.pushsection ".data.thunk_opd","aw" 					;\
1:	.llong name##_thunk, .TOC., 0 						;\
	.popsection								;\
	.llong 1b
#else /* __BYTE_ORDER == __LITTLE_ENDIAN */
#define CALLBACK_THUNK(name)							 \
	.llong name
#endif

#define DISABLED_THUNK(name) .llong 0x0

	/* Here's the callback table generation. It creates the table and
	 * all the thunks for all the callbacks from HBRT to us
	 */
	.data
	.globl hinterface
	.globl __hinterface_start
__hinterface_start:
hinterface:
	/* HBRT interface version */
	.llong 1

	/* Callout pointers */
	CALLBACK_THUNK(hservice_puts)
	CALLBACK_THUNK(hservice_assert)
	CALLBACK_THUNK(hservice_set_page_execute)
	CALLBACK_THUNK(hservice_malloc)
	CALLBACK_THUNK(hservice_free)
	CALLBACK_THUNK(hservice_realloc)
	DISABLED_THUNK(hservice_send_error_log)
	CALLBACK_THUNK(hservice_scom_read)
	CALLBACK_THUNK(hservice_scom_write)
	DISABLED_THUNK(hservice_lid_load)
	DISABLED_THUNK(hservice_lid_unload)
	CALLBACK_THUNK(hservice_get_reserved_mem)
	CALLBACK_THUNK(hservice_wakeup)
	CALLBACK_THUNK(hservice_nanosleep)
	DISABLED_THUNK(hservice_report_occ_failure)
	CALLBACK_THUNK(hservice_clock_gettime)
	CALLBACK_THUNK(hservice_pnor_read)
	CALLBACK_THUNK(hservice_pnor_write)
	CALLBACK_THUNK(hservice_i2c_read)
	CALLBACK_THUNK(hservice_i2c_write)
	CALLBACK_THUNK(hservice_ipmi_msg)
	CALLBACK_THUNK(hservice_memory_error)
	CALLBACK_THUNK(hservice_get_interface_capabilities)
	DISABLED_THUNK(hservice_map_phys_mem)
	DISABLED_THUNK(hservice_unmap_phys_mem)
	DISABLED_THUNK(hservice_hcode_scom_update)
	CALLBACK_THUNK(hservice_firmware_request)
.globl __hinterface_pad
__hinterface_pad:
	/* Reserved space for future growth */
	.space 27*8,0
.globl __hinterface_end
__hinterface_end:
	/* Eye catcher for debugging */
	.llong 0xdeadbeef

