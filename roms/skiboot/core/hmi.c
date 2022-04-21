// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Deal with Hypervisor Maintenance Interrupts
 *
 * Copyright 2013-2019 IBM Corp.
 */

#define pr_fmt(fmt)	"HMI: " fmt

#include <skiboot.h>
#include <opal.h>
#include <opal-msg.h>
#include <processor.h>
#include <chiptod.h>
#include <xscom.h>
#include <xscom-p8-regs.h>
#include <xscom-p9-regs.h>
#include <xscom-p10-regs.h>
#include <pci.h>
#include <cpu.h>
#include <chip.h>
#include <npu-regs.h>
#include <npu2-regs.h>
#include <npu2.h>
#include <npu.h>
#include <capp.h>
#include <nvram.h>
#include <cpu.h>

/*
 * P9 HMER register layout:
 * +===+==========+============================+========+===================+
 * |Bit|Name      |Description                 |PowerKVM|Action             |
 * |   |          |                            |HMI     |                   |
 * |   |          |                            |enabled |                   |
 * |   |          |                            |for this|                   |
 * |   |          |                            |bit ?   |                   |
 * +===+==========+============================+========+===================+
 * |0  |malfunctio|A processor core in the     |Yes     |Raise attn from    |
 * |   |n_allert  |system has checkstopped     |        |sapphire resulting |
 * |   |          |(failed recovery) and has   |        |xstop              |
 * |   |          |requested a CP Sparing      |        |                   |
 * |   |          |to occur. This is           |        |                   |
 * |   |          |broadcasted to every        |        |                   |
 * |   |          |processor in the system     |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |1  |Reserved  |reserved                    |n/a     |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |2  |proc_recv_|Processor recovery occurred |Yes     |Log message and    |
 * |   |done      |error-bit in fir not masked |        |continue working.  |
 * |   |          |(see bit 11)                |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |3  |proc_recv_|Processor went through      |Yes     |Log message and    |
 * |   |error_mask|recovery for an error which |        |continue working.  |
 * |   |ed        |is actually masked for      |        |                   |
 * |   |          |reporting                   |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |4  |          |Timer facility experienced  |Yes     |Raise attn from    |
 * |   |tfac_error|an error.                   |        |sapphire resulting |
 * |   |          |TB, DEC, HDEC, PURR or SPURR|        |xstop              |
 * |   |          |may be corrupted (details in|        |                   |
 * |   |          |TFMR)                       |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |5  |          |TFMR SPR itself is          |Yes     |Raise attn from    |
 * |   |tfmr_parit|corrupted.                  |        |sapphire resulting |
 * |   |y_error   |Entire timing facility may  |        |xstop              |
 * |   |          |be compromised.             |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |6  |ha_overflo| UPS (Uniterrupted Power    |No      |N/A                |
 * |   |w_warning |System) Overflow indication |        |                   |
 * |   |          |indicating that the UPS     |        |                   |
 * |   |          |DirtyAddrTable has          |        |                   |
 * |   |          |reached a limit where it    |        |                   |
 * |   |          |requires PHYP unload support|        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |7  |reserved  |reserved                    |n/a     |n/a                |
 * |---+----------+----------------------------+--------+-------------------|
 * |8  |xscom_fail|An XSCOM operation caused by|No      |We handle it by    |
 * |   |          |a cache inhibited load/store|        |manually reading   |
 * |   |          |from this thread failed. A  |        |HMER register.     |
 * |   |          |trap register is            |        |                   |
 * |   |          |available.                  |        |                   |
 * |   |          |                            |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |9  |xscom_done|An XSCOM operation caused by|No      |We handle it by    |
 * |   |          |a cache inhibited load/store|        |manually reading   |
 * |   |          |from this thread completed. |        |HMER register.     |
 * |   |          |If hypervisor               |        |                   |
 * |   |          |intends to use this bit, it |        |                   |
 * |   |          |is responsible for clearing |        |                   |
 * |   |          |it before performing the    |        |                   |
 * |   |          |xscom operation.            |        |                   |
 * |   |          |NOTE: this bit should always|        |                   |
 * |   |          |be masked in HMEER          |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |10 |reserved  |reserved                    |n/a     |n/a                |
 * |---+----------+----------------------------+--------+-------------------|
 * |11 |proc_recv_|Processor recovery occurred |y       |Log message and    |
 * |   |again     |again before bit2 or bit3   |        |continue working.  |
 * |   |          |was cleared                 |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |12-|reserved  |was temperature sensor      |n/a     |n/a                |
 * |15 |          |passed the critical point on|        |                   |
 * |   |          |the way up                  |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |16 |          |SCOM has set a reserved FIR |No      |n/a                |
 * |   |scom_fir_h|bit to cause recovery       |        |                   |
 * |   |m         |                            |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |17 |trig_fir_h|Debug trigger has set a     |No      |n/a                |
 * |   |mi        |reserved FIR bit to cause   |        |                   |
 * |   |          |recovery                    |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |18 |reserved  |reserved                    |n/a     |n/a                |
 * |---+----------+----------------------------+--------+-------------------|
 * |19 |reserved  |reserved                    |n/a     |n/a                |
 * |---+----------+----------------------------+--------+-------------------|
 * |20 |hyp_resour|A hypervisor resource error |y       |Raise attn from    |
 * |   |ce_err    |occurred: data parity error |        |sapphire resulting |
 * |   |          |on, SPRC0:3; SPR_Modereg or |        |xstop.             |
 * |   |          |HMEER.                      |        |                   |
 * |   |          |Note: this bit will cause an|        |                   |
 * |   |          |check_stop when (HV=1, PR=0 |        |                   |
 * |   |          |and EE=0)                   |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |21-|          |if bit 8 is active, the     |No      |We handle it by    |
 * |23 |xscom_stat|reason will be detailed in  |        |Manually reading   |
 * |   |us        |these bits. see chapter 11.1|        |HMER register.     |
 * |   |          |This bits are information   |        |                   |
 * |   |          |only and always masked      |        |                   |
 * |   |          |(mask = '0')                |        |                   |
 * |   |          |If hypervisor intends to use|        |                   |
 * |   |          |this bit, it is responsible |        |                   |
 * |   |          |for clearing it before      |        |                   |
 * |   |          |performing the xscom        |        |                   |
 * |   |          |operation.                  |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |24-|Not       |Not implemented             |n/a     |n/a                |
 * |63 |implemente|                            |        |                   |
 * |   |d         |                            |        |                   |
 * +-- +----------+----------------------------+--------+-------------------+
 *
 * Above HMER bits can be enabled/disabled by modifying
 * SPR_HMEER_HMI_ENABLE_MASK #define in include/processor.h
 * If you modify support for any of the bits listed above, please make sure
 * you change the above table to refelct that.
 *
 * NOTE: Per Dave Larson, never enable 8,9,21-23
 */

/*
 * P10 HMER register layout:
 * Bit   Name                Description
 * 0     malfunction_alert   A processor core in the system has checkstopped
 *                           (failed recovery). This is broadcasted to every
 *                           processor in the system
 *
 * 1     reserved            reserved
 *
 * 2     proc_rcvy_done      Processor recovery occurred error-bit in fir not
 *                           masked (see bit 11)
 *
 * 3     reserved            reserved
 *
 * 4     tfac_error          Timer facility experienced an error. TB, DEC,
 *                           HDEC, PURR or SPURR may be corrupted (details in
 *                           TFMR)
 *
 * 5     tfx_error           Error occurred on transfer from tfac shadow to
 *                           core
 *
 * 6     spurr_scale_limit   Nominal frequency exceeded 399 percent
 *
 * 7     reserved            reserved
 *
 * 8     xscom_fail          An XSCOM operation caused by a cache inhibited
 *                           load/store from this thread failed. A trap
 *                           register is available.
 *
 * 9     xscom_done          An XSCOM operation caused by a cache inhibited
 *                           load/store from this thread completed. If
 *                           hypervisor intends to use this bit, it is
 *                           responsible for clearing it before performing the
 *                           xscom operation. NOTE: this bit should always be
 *                           masked in HMEER
 *
 * 10    reserved            reserved
 *
 * 11    proc_rcvy_again     Processor recovery occurred again before bit 2
 *                           was cleared
 *
 * 12-15 reserved            reserved
 *
 * 16    scom_fir_hmi        An error inject to PC FIR has occurred to set HMI.
 *                           This error inject can also set FIR(61) to cause
 *                           recovery.
 *
 * 17    reserved            reserved
 *
 * 18    trig_fir_hmi        Debug trigger has occurred to set HMI. This
 *                           trigger can also set FIR(60) to cause recovery
 *
 * 19-20 reserved            reserved
 *
 * 21-23 xscom_status        If bit 8 is active, the reason will be detailed in
 *                           these bits. These bits are information only and
 *                           always masked (mask = ‘0’) If hypervisor intends
 *                           to use this field, it is responsible for clearing
 *                           it before performing the xscom operation.
 *
 * 24:63 Not implemented     Not implemented.
 *
 * P10 HMEER enabled bits:
 * Name                      Action
 * malfunction_alert         Decode and log FIR bits.
 * proc_rcvy_done            Log and continue.
 * tfac_error                Log and attempt to recover time facilities.
 * tfx_error                 Log and attempt to recover time facilities.
 * spurr_scale_limit         Log and continue. XXX?
 * proc_rcvy_again           Log and continue.
 */

/* Used for tracking cpu threads inside hmi handling. */
#define HMI_STATE_CLEANUP_DONE	0x100
#define CORE_THREAD_MASK	0x0ff
#define SUBCORE_THREAD_MASK(s_id, t_count) \
		((((1UL) << (t_count)) - 1) << ((s_id) * (t_count)))
#define SINGLE_THREAD_MASK(t_id)	((1UL) << (t_id))

/*
 * Number of iterations for the various timeouts. We can't use the timebase
 * as it might be broken. We measured experimentally that 40 millions loops
 * of cpu_relax() gives us more than 1s. The margin is comfortable enough.
 */
#define TIMEOUT_LOOPS		40000000

/* TFMR other errors. (other than bit 26 and 45) */
#define SPR_TFMR_OTHER_ERRORS	\
	(SPR_TFMR_TBST_CORRUPT | SPR_TFMR_TB_MISSING_SYNC |	\
	 SPR_TFMR_TB_MISSING_STEP | SPR_TFMR_FW_CONTROL_ERR |	\
	 SPR_TFMR_PURR_PARITY_ERR | SPR_TFMR_SPURR_PARITY_ERR |	\
	 SPR_TFMR_DEC_PARITY_ERR | SPR_TFMR_TFMR_CORRUPT |	\
	 SPR_TFMR_CHIP_TOD_INTERRUPT)

/* TFMR "all core" errors (sent to all threads) */
#define SPR_TFMR_CORE_ERRORS	\
	(SPR_TFMR_TBST_CORRUPT | SPR_TFMR_TB_MISSING_SYNC |	\
	 SPR_TFMR_TB_MISSING_STEP | SPR_TFMR_FW_CONTROL_ERR |	\
	 SPR_TFMR_TFMR_CORRUPT | SPR_TFMR_TB_RESIDUE_ERR |	\
	 SPR_TFMR_HDEC_PARITY_ERROR | SPR_TFMR_TFAC_XFER_ERROR)

/* TFMR "thread" errors  */
#define SPR_TFMR_THREAD_ERRORS \
	(SPR_TFMR_PURR_PARITY_ERR | SPR_TFMR_SPURR_PARITY_ERR |	\
	 SPR_TFMR_DEC_PARITY_ERR)

/*
 * Starting from p9, core inits are setup to escalate all core
 * local checkstop to system checkstop. Review this list when that changes.
 */
static const struct core_xstop_bit_info {
	uint8_t bit;		/* CORE FIR bit number */
	enum OpalHMI_CoreXstopReason reason;
} xstop_bits[] = {
	{ 3, CORE_CHECKSTOP_IFU_REGFILE },
	{ 5, CORE_CHECKSTOP_IFU_LOGIC },
	{ 8, CORE_CHECKSTOP_PC_DURING_RECOV },
	{ 10, CORE_CHECKSTOP_ISU_REGFILE },
	{ 12, CORE_CHECKSTOP_ISU_LOGIC },
	{ 21, CORE_CHECKSTOP_FXU_LOGIC },
	{ 25, CORE_CHECKSTOP_VSU_LOGIC },
	{ 26, CORE_CHECKSTOP_PC_RECOV_IN_MAINT_MODE },
	{ 32, CORE_CHECKSTOP_LSU_REGFILE },
	{ 36, CORE_CHECKSTOP_PC_FWD_PROGRESS },
	{ 38, CORE_CHECKSTOP_LSU_LOGIC },
	{ 45, CORE_CHECKSTOP_PC_LOGIC },
	{ 48, CORE_CHECKSTOP_PC_HYP_RESOURCE },
	{ 52, CORE_CHECKSTOP_PC_HANG_RECOV_FAILED },
	{ 54, CORE_CHECKSTOP_PC_AMBI_HANG_DETECTED },
	{ 63, CORE_CHECKSTOP_PC_SPRD_HYP_ERR_INJ },
};

struct core_fir_bit_info {
	uint8_t bit;		/* CORE FIR bit number */
	const char *reason;
};

static const struct core_fir_bit_info p9_recoverable_bits[] = {
	{ 0, "IFU - SRAM (ICACHE parity, etc)" },
	{ 2, "IFU - RegFile" },
	{ 4, "IFU - Logic" },
	{ 9, "ISU - RegFile" },
	{ 11, "ISU - Logic" },
	{ 13, "ISU - Recoverable due to not in MT window" },
	{ 24, "VSU - Logic" },
	{ 27, "VSU - DFU logic" },
	{ 29, "LSU - SRAM (DCACHE parity, etc)" },
	{ 31, "LSU - RegFile" },
	/* The following 3 bits may be set by SRAM errors. */
	{ 33, "LSU - TLB multi hit" },
	{ 34, "LSU - SLB multi hit" },
	{ 35, "LSU - ERAT multi hit" },
	{ 37, "LSU - Logic" },
	{ 39, "LSU - Recoverable due to not in MT window" },
	{ 43, "PC - Thread hang recovery" },
};

static const struct core_fir_bit_info p10_core_fir_bits[] = {
	{ 0,  "IFU - SRAM recoverable error (ICACHE parity error, etc.)" },
	{ 1,  "PC - TC checkstop" },
	{ 2,  "IFU - RegFile recoverable error" },
	{ 3,  "IFU - RegFile core checkstop" },
	{ 4,  "IFU - Logic recoverable error" },
	{ 5,  "IFU - Logic core checkstop" },
	{ 7,  "VSU - Inference accumulator recoverable error" },
	{ 8,  "PC - Recovery core checkstop" },
	{ 9,  "VSU - Slice Target File (STF) recoverable error" },
	{ 11, "ISU - Logic recoverable error" },
	{ 12, "ISU - Logic core checkstop" },
	{ 14, "ISU - Machine check received while ME=0 checkstop" },
	{ 15, "ISU - UE from L2" },
	{ 16, "ISU - Number of UEs from L2 above threshold" },
	{ 17, "ISU - UE on CI load" },
	{ 18, "MMU - TLB recoverable error" },
	{ 19, "MMU - SLB error" },
	{ 21, "MMU - CXT recoverable error" },
	{ 22, "MMU - Logic core checkstop" },
	{ 23, "MMU - MMU system checkstop" },
	{ 24, "VSU - Logic recoverable error" },
	{ 25, "VSU - Logic core checkstop" },
	{ 26, "PC - In maint mode and recovery in progress" },
	{ 28, "PC - PC system checkstop" },
	{ 29, "LSU - SRAM recoverable error (DCACHE parity error, etc.)" },
	{ 30, "LSU - Set deleted" },
	{ 31, "LSU - RegFile recoverable error" },
	{ 32, "LSU - RegFile core checkstop" },
	{ 33, "MMU - TLB multi hit error occurred" },
	{ 34, "MMU - SLB multi hit error occurred" },
	{ 35, "LSU - ERAT multi hit error occurred" },
	{ 36, "PC - Forward progress error" },
	{ 37, "LSU - Logic recoverable error" },
	{ 38, "LSU - Logic core checkstop" },
	{ 41, "LSU - System checkstop" },
	{ 43, "PC - Thread hang recoverable error" },
	{ 45, "PC - Logic core checkstop" },
	{ 47, "PC - TimeBase facility checkstop" },
	{ 52, "PC - Hang recovery failed core checkstop" },
	{ 53, "PC - Core internal hang detected" },
	{ 55, "PC - Nest hang detected" },
	{ 56, "PC - Other core chiplet recoverable error" },
	{ 57, "PC - Other core chiplet core checkstop" },
	{ 58, "PC - Other core chiplet system checkstop" },
	{ 59, "PC - SCOM satellite error detected" },
	{ 60, "PC - Debug trigger error inject" },
	{ 61, "PC - SCOM or firmware recoverable error inject" },
	{ 62, "PC - Firmware checkstop error inject" },
	{ 63, "PC - Firmware SPRC / SPRD checkstop" },
};

static const struct nx_xstop_bit_info {
	uint8_t bit;		/* NX FIR bit number */
	enum OpalHMI_NestAccelXstopReason reason;
} nx_dma_xstop_bits[] = {
	{ 1, NX_CHECKSTOP_SHM_INVAL_STATE_ERR },
	{ 15, NX_CHECKSTOP_DMA_INVAL_STATE_ERR_1 },
	{ 16, NX_CHECKSTOP_DMA_INVAL_STATE_ERR_2 },
	{ 20, NX_CHECKSTOP_DMA_CH0_INVAL_STATE_ERR },
	{ 21, NX_CHECKSTOP_DMA_CH1_INVAL_STATE_ERR },
	{ 22, NX_CHECKSTOP_DMA_CH2_INVAL_STATE_ERR },
	{ 23, NX_CHECKSTOP_DMA_CH3_INVAL_STATE_ERR },
	{ 24, NX_CHECKSTOP_DMA_CH4_INVAL_STATE_ERR },
	{ 25, NX_CHECKSTOP_DMA_CH5_INVAL_STATE_ERR },
	{ 26, NX_CHECKSTOP_DMA_CH6_INVAL_STATE_ERR },
	{ 27, NX_CHECKSTOP_DMA_CH7_INVAL_STATE_ERR },
	{ 31, NX_CHECKSTOP_DMA_CRB_UE },
	{ 32, NX_CHECKSTOP_DMA_CRB_SUE },
};

static const struct nx_xstop_bit_info nx_pbi_xstop_bits[] = {
	{ 12, NX_CHECKSTOP_PBI_ISN_UE },
};

static struct lock hmi_lock = LOCK_UNLOCKED;
static uint32_t malf_alert_scom;
static uint32_t nx_status_reg;
static uint32_t nx_dma_engine_fir;
static uint32_t nx_pbi_fir;

static int setup_scom_addresses(void)
{
	switch (proc_gen) {
	case proc_gen_p8:
		malf_alert_scom = P8_MALFUNC_ALERT;
		nx_status_reg = P8_NX_STATUS_REG;
		nx_dma_engine_fir = P8_NX_DMA_ENGINE_FIR;
		nx_pbi_fir = P8_NX_PBI_FIR;
		return 1;
	case proc_gen_p9:
		malf_alert_scom = P9_MALFUNC_ALERT;
		nx_status_reg = P9_NX_STATUS_REG;
		nx_dma_engine_fir = P9_NX_DMA_ENGINE_FIR;
		nx_pbi_fir = P9_NX_PBI_FIR;
		return 1;
	case proc_gen_p10:
		malf_alert_scom = P10_MALFUNC_ALERT;
		nx_status_reg = P10_NX_STATUS_REG;
		nx_dma_engine_fir = P10_NX_DMA_ENGINE_FIR;
		nx_pbi_fir = P10_NX_PBI_FIR;
		return 1;
	default:
		prerror("%s: Unknown CPU type\n", __func__);
		break;
	}
	return 0;
}

static int queue_hmi_event(struct OpalHMIEvent *hmi_evt, int recover, uint64_t *out_flags)
{
	size_t size;

	/* Don't queue up event if recover == -1 */
	if (recover == -1)
		return 0;

	/* set disposition */
	if (recover == 1)
		hmi_evt->disposition = OpalHMI_DISPOSITION_RECOVERED;
	else if (recover == 0)
		hmi_evt->disposition = OpalHMI_DISPOSITION_NOT_RECOVERED;

	/*
	 * V2 of struct OpalHMIEvent is of (5 * 64 bits) size and well packed
	 * structure. Hence use uint64_t pointer to pass entire structure
	 * using 5 params in generic message format. Instead of hard coding
	 * num_params divide the struct size by 8 bytes to get exact
	 * num_params value.
	 */
	size = ALIGN_UP(sizeof(*hmi_evt), sizeof(u64));

	*out_flags |= OPAL_HMI_FLAGS_NEW_EVENT;

	/* queue up for delivery to host. */
	return _opal_queue_msg(OPAL_MSG_HMI_EVT, NULL, NULL,
				size, hmi_evt);
}

static int read_core_fir(uint32_t chip_id, uint32_t core_id, uint64_t *core_fir)
{
	int rc;

	switch (proc_gen) {
	case proc_gen_p8:
		rc = xscom_read(chip_id,
			XSCOM_ADDR_P8_EX(core_id, P8_CORE_FIR), core_fir);
		break;
	case proc_gen_p9:
		rc = xscom_read(chip_id,
			XSCOM_ADDR_P9_EC(core_id, P9_CORE_FIR), core_fir);
		break;
	case proc_gen_p10:
		rc = xscom_read(chip_id,
			XSCOM_ADDR_P10_EC(core_id, P10_CORE_FIR), core_fir);
		break;
	default:
		rc = OPAL_HARDWARE;
	}
	return rc;
}

static int read_core_wof(uint32_t chip_id, uint32_t core_id, uint64_t *core_wof)
{
	int rc;

	switch (proc_gen) {
	case proc_gen_p9:
		rc = xscom_read(chip_id,
			XSCOM_ADDR_P9_EC(core_id, P9_CORE_WOF), core_wof);
		break;
	case proc_gen_p10:
		rc = xscom_read(chip_id,
			XSCOM_ADDR_P10_EC(core_id, P10_CORE_WOF), core_wof);
		break;
	default:
		rc = OPAL_HARDWARE;
	}
	return rc;
}

static bool decode_core_fir(struct cpu_thread *cpu,
				struct OpalHMIEvent *hmi_evt)
{
	uint64_t core_fir;
	uint32_t core_id;
	int i, swkup_rc;
	bool found = false;
	int64_t ret;
	const char *loc;

	/* Sanity check */
	if (!cpu || !hmi_evt)
		return false;

	core_id = pir_to_core_id(cpu->pir);

	/* Force the core to wakeup, otherwise reading core_fir is unrealiable
	 * if stop-state 5 is enabled.
	 */
	swkup_rc = dctl_set_special_wakeup(cpu);

	/* Get CORE FIR register value. */
	ret = read_core_fir(cpu->chip_id, core_id, &core_fir);

	if (!swkup_rc)
		dctl_clear_special_wakeup(cpu);


	if (ret == OPAL_WRONG_STATE) {
		/*
		 * CPU is asleep, so it probably didn't cause the checkstop.
		 * If no other HMI cause is found a "catchall" checkstop
		 * will be raised, so if this CPU should've been awake the
		 * error will be handled appropriately.
		 */
		prlog(PR_DEBUG,
		      "FIR read failed, chip %d core %d asleep\n",
		      cpu->chip_id, core_id);
		return false;
	} else if (ret != OPAL_SUCCESS) {
		prerror("XSCOM error reading CORE FIR\n");
		/* If the FIR can't be read, we should checkstop. */
		return true;
	}

	if (!core_fir)
		return false;

	loc = chip_loc_code(cpu->chip_id);
	prlog(PR_INFO, "[Loc: %s]: CHIP ID: %x, CORE ID: %x, FIR: %016llx\n",
			loc ? loc : "Not Available",
			cpu->chip_id, core_id, core_fir);

	if (proc_gen == proc_gen_p10) {
		for (i = 0; i < ARRAY_SIZE(p10_core_fir_bits); i++) {
			if (core_fir & PPC_BIT(p10_core_fir_bits[i].bit))
				prlog(PR_INFO, "    %s\n", p10_core_fir_bits[i].reason);
		}
	}

	/* Check CORE FIR bits and populate HMI event with error info. */
	for (i = 0; i < ARRAY_SIZE(xstop_bits); i++) {
		if (core_fir & PPC_BIT(xstop_bits[i].bit)) {
			found = true;
			hmi_evt->u.xstop_error.xstop_reason
					|= cpu_to_be32(xstop_bits[i].reason);
		}
	}
	return found;
}

static void find_core_checkstop_reason(struct OpalHMIEvent *hmi_evt,
				       uint64_t *out_flags)
{
	struct cpu_thread *cpu;

	/* Initialize HMI event */
	hmi_evt->severity = OpalHMI_SEV_FATAL;
	hmi_evt->type = OpalHMI_ERROR_MALFUNC_ALERT;
	hmi_evt->u.xstop_error.xstop_type = CHECKSTOP_TYPE_CORE;

	/*
	 * Check CORE FIRs and find the reason for core checkstop.
	 * Send a separate HMI event for each core that has checkstopped.
	 */
	for_each_cpu(cpu) {
		/* GARDed CPUs are marked unavailable. Skip them.  */
		if (cpu->state == cpu_state_unavailable)
			continue;

		/* Only check on primaries (ie. core), not threads */
		if (cpu->is_secondary)
			continue;

		/* Initialize xstop_error fields. */
		hmi_evt->u.xstop_error.xstop_reason = 0;
		hmi_evt->u.xstop_error.u.pir = cpu_to_be32(cpu->pir);

		if (decode_core_fir(cpu, hmi_evt))
			queue_hmi_event(hmi_evt, 0, out_flags);
	}
}

static void find_capp_checkstop_reason(int flat_chip_id,
				       struct OpalHMIEvent *hmi_evt,
				       uint64_t *out_flags)
{
	struct capp_info info;
	struct phb *phb;
	uint64_t capp_fir;
	uint64_t capp_fir_mask;
	uint64_t capp_fir_action0;
	uint64_t capp_fir_action1;
	uint64_t reg;
	int64_t rc;

	/* CAPP exists on P8 and P9 only */
	if (proc_gen != proc_gen_p8 && proc_gen != proc_gen_p9)
		return;

	/* Find the CAPP on the chip associated with the HMI. */
	for_each_phb(phb) {
		/* get the CAPP info */
		rc = capp_get_info(flat_chip_id, phb, &info);
		if (rc == OPAL_PARAMETER)
			continue;

		if (xscom_read(flat_chip_id, info.capp_fir_reg, &capp_fir) ||
		    xscom_read(flat_chip_id, info.capp_fir_mask_reg,
			       &capp_fir_mask) ||
		    xscom_read(flat_chip_id, info.capp_fir_action0_reg,
			       &capp_fir_action0) ||
		    xscom_read(flat_chip_id, info.capp_fir_action1_reg,
			       &capp_fir_action1)) {
			prerror("CAPP: Couldn't read CAPP#%d (PHB:#%x) FIR registers by XSCOM!\n",
				info.capp_index, info.phb_index);
			continue;
		}

		if (!(capp_fir & ~capp_fir_mask))
			continue;

		prlog(PR_DEBUG, "CAPP#%d (PHB:#%x): FIR 0x%016llx mask 0x%016llx\n",
		      info.capp_index, info.phb_index, capp_fir,
		      capp_fir_mask);
		prlog(PR_DEBUG, "CAPP#%d (PHB:#%x): ACTION0 0x%016llx, ACTION1 0x%016llx\n",
		      info.capp_index, info.phb_index, capp_fir_action0,
		      capp_fir_action1);

		/*
		 * If this bit is set (=1) a Recoverable Error has been
		 * detected
		 */
		xscom_read(flat_chip_id, info.capp_err_status_ctrl_reg, &reg);
		if ((reg & PPC_BIT(0)) != 0) {
			phb_lock(phb);
			phb->ops->set_capp_recovery(phb);
			phb_unlock(phb);

			hmi_evt->severity = OpalHMI_SEV_NO_ERROR;
			hmi_evt->type = OpalHMI_ERROR_CAPP_RECOVERY;
			queue_hmi_event(hmi_evt, 1, out_flags);

			return;
		}
	}
}

static void find_nx_checkstop_reason(int flat_chip_id,
				     struct OpalHMIEvent *hmi_evt,
				     uint64_t *out_flags)
{
	uint64_t nx_status;
	uint64_t nx_dma_fir;
	uint64_t nx_pbi_fir_val;
	int i;

	/* Get NX status register value. */
	if (xscom_read(flat_chip_id, nx_status_reg, &nx_status) != 0) {
		prerror("XSCOM error reading NX_STATUS_REG\n");
		return;
	}

	/* Check if NX has driven an HMI interrupt. */
	if (!(nx_status & NX_HMI_ACTIVE))
		return;

	/* Initialize HMI event */
	hmi_evt->severity = OpalHMI_SEV_FATAL;
	hmi_evt->type = OpalHMI_ERROR_MALFUNC_ALERT;
	hmi_evt->u.xstop_error.xstop_type = CHECKSTOP_TYPE_NX;
	hmi_evt->u.xstop_error.u.chip_id = cpu_to_be32(flat_chip_id);

	/* Get DMA & Engine FIR data register value. */
	if (xscom_read(flat_chip_id, nx_dma_engine_fir, &nx_dma_fir) != 0) {
		prerror("XSCOM error reading NX_DMA_ENGINE_FIR\n");
		return;
	}

	/* Get PowerBus Interface FIR data register value. */
	if (xscom_read(flat_chip_id, nx_pbi_fir, &nx_pbi_fir_val) != 0) {
		prerror("XSCOM error reading NX_PBI_FIR\n");
		return;
	}

	/* Find NX checkstop reason and populate HMI event with error info. */
	for (i = 0; i < ARRAY_SIZE(nx_dma_xstop_bits); i++)
		if (nx_dma_fir & PPC_BIT(nx_dma_xstop_bits[i].bit))
			hmi_evt->u.xstop_error.xstop_reason
				|= cpu_to_be32(nx_dma_xstop_bits[i].reason);

	for (i = 0; i < ARRAY_SIZE(nx_pbi_xstop_bits); i++)
		if (nx_pbi_fir_val & PPC_BIT(nx_pbi_xstop_bits[i].bit))
			hmi_evt->u.xstop_error.xstop_reason
				|= cpu_to_be32(nx_pbi_xstop_bits[i].reason);

	/*
	 * Set NXDMAENGFIR[38] to signal PRD that service action is required.
	 * Without this inject, PRD will not be able to do NX unit checkstop
	 * error analysis. NXDMAENGFIR[38] is a spare bit and used to report
	 * a software initiated attention.
	 *
	 * The behavior of this bit and all FIR bits are documented in
	 * RAS spreadsheet.
	 */
	xscom_write(flat_chip_id, nx_dma_engine_fir, PPC_BIT(38));

	/* Send an HMI event. */
	queue_hmi_event(hmi_evt, 0, out_flags);
}

static bool phb_is_npu2(struct dt_node *dn)
{
	return (dt_node_is_compatible(dn, "ibm,power9-npu-pciex") ||
		dt_node_is_compatible(dn, "ibm,power9-npu-opencapi-pciex"));
}

static void add_npu2_xstop_reason(uint32_t *xstop_reason, uint8_t reason)
{
	int i, reason_count;
	uint8_t *ptr;

	reason_count = sizeof(*xstop_reason) / sizeof(reason);
	ptr = (uint8_t *) xstop_reason;
	for (i = 0; i < reason_count; i++) {
		if (*ptr == 0) {
			*ptr = reason;
			break;
		}
		ptr++;
	}
}

static void encode_npu2_xstop_reason(uint32_t *xstop_reason,
				uint64_t fir, int fir_number)
{
	int bit;
	uint8_t reason;

	/*
	 * There are three 64-bit FIRs but the xstop reason field of
	 * the hmi event is only 32-bit. Encode which FIR bit is set as:
	 * - 2 bits for the FIR number
	 * - 6 bits for the bit number (0 -> 63)
	 *
	 * So we could even encode up to 4 reasons for the HMI, if
	 * that can ever happen
	 */
	while (fir) {
		bit = ilog2(fir);
		reason = fir_number << 6;
		reason |= (63 - bit); // IBM numbering
		add_npu2_xstop_reason(xstop_reason, reason);
		fir ^= 1ULL << bit;
	}
}

static void find_npu2_checkstop_reason(int flat_chip_id,
				      struct OpalHMIEvent *hmi_evt,
				      uint64_t *out_flags)
{
	struct phb *phb;
	int i;
	bool npu2_hmi_verbose = false, found = false;
	uint64_t npu2_fir;
	uint64_t npu2_fir_mask;
	uint64_t npu2_fir_action0;
	uint64_t npu2_fir_action1;
	uint64_t npu2_fir_addr;
	uint64_t npu2_fir_mask_addr;
	uint64_t npu2_fir_action0_addr;
	uint64_t npu2_fir_action1_addr;
	uint64_t fatal_errors;
	uint32_t xstop_reason = 0;
	int total_errors = 0;
	const char *loc;

	/* NPU2 only */
	if (PVR_TYPE(mfspr(SPR_PVR)) != PVR_TYPE_P9)
		return;

	/* Find the NPU on the chip associated with the HMI. */
	for_each_phb(phb) {
		/* NOTE: if a chip ever has >1 NPU this will need adjusting */
		if (phb_is_npu2(phb->dt_node) &&
		    (dt_get_chip_id(phb->dt_node) == flat_chip_id)) {
			found = true;
			break;
		}
	}

	/* If we didn't find a NPU on the chip, it's not our checkstop. */
	if (!found)
		return;

	npu2_fir_addr = NPU2_FIR_REGISTER_0;
	npu2_fir_mask_addr = NPU2_FIR_REGISTER_0 + NPU2_FIR_MASK_OFFSET;
	npu2_fir_action0_addr = NPU2_FIR_REGISTER_0 + NPU2_FIR_ACTION0_OFFSET;
	npu2_fir_action1_addr = NPU2_FIR_REGISTER_0 + NPU2_FIR_ACTION1_OFFSET;

	for (i = 0; i < NPU2_TOTAL_FIR_REGISTERS; i++) {
		/* Read all the registers necessary to find a checkstop condition. */
		if (xscom_read(flat_chip_id, npu2_fir_addr, &npu2_fir) ||
			xscom_read(flat_chip_id, npu2_fir_mask_addr, &npu2_fir_mask) ||
			xscom_read(flat_chip_id, npu2_fir_action0_addr, &npu2_fir_action0) ||
			xscom_read(flat_chip_id, npu2_fir_action1_addr, &npu2_fir_action1)) {
			prerror("HMI: Couldn't read NPU FIR register%d with XSCOM\n", i);
			continue;
		}

		fatal_errors = npu2_fir & ~npu2_fir_mask & npu2_fir_action0 & npu2_fir_action1;

		if (fatal_errors) {
			loc = chip_loc_code(flat_chip_id);
			if (!loc)
				loc = "Not Available";
			prlog(PR_ERR, "NPU: [Loc: %s] P:%d FIR#%d FIR 0x%016llx mask 0x%016llx\n",
					loc, flat_chip_id, i, npu2_fir, npu2_fir_mask);
			prlog(PR_ERR, "NPU: [Loc: %s] P:%d ACTION0 0x%016llx, ACTION1 0x%016llx\n",
					loc, flat_chip_id, npu2_fir_action0, npu2_fir_action1);
			total_errors++;

			encode_npu2_xstop_reason(&xstop_reason, fatal_errors, i);
		}

		/* Can't do a fence yet, we are just logging fir information for now */
		npu2_fir_addr += NPU2_FIR_OFFSET;
		npu2_fir_mask_addr += NPU2_FIR_OFFSET;
		npu2_fir_action0_addr += NPU2_FIR_OFFSET;
		npu2_fir_action1_addr += NPU2_FIR_OFFSET;

	}

	if (!total_errors)
		return;

	npu2_hmi_verbose = nvram_query_eq_safe("npu2-hmi-verbose", "true");
	/* Force this for now until we sort out something better */
	npu2_hmi_verbose = true;

	if (npu2_hmi_verbose) {
		npu2_dump_scoms(flat_chip_id);
		prlog(PR_ERR, " _________________________ \n");
		prlog(PR_ERR, "<    It's Debug time!     >\n");
		prlog(PR_ERR, " ------------------------- \n");
		prlog(PR_ERR, "       \\   ,__,            \n");
		prlog(PR_ERR, "        \\  (oo)____        \n");
		prlog(PR_ERR, "           (__)    )\\      \n");
		prlog(PR_ERR, "              ||--|| *     \n");
	}

	/* Set up the HMI event */
	hmi_evt->severity = OpalHMI_SEV_WARNING;
	hmi_evt->type = OpalHMI_ERROR_MALFUNC_ALERT;
	hmi_evt->u.xstop_error.xstop_type = CHECKSTOP_TYPE_NPU;
	hmi_evt->u.xstop_error.xstop_reason = cpu_to_be32(xstop_reason);
	hmi_evt->u.xstop_error.u.chip_id = cpu_to_be32(flat_chip_id);

	/* Marking the event as recoverable so that we don't crash */
	queue_hmi_event(hmi_evt, 1, out_flags);
}

static void find_npu_checkstop_reason(int flat_chip_id,
				      struct OpalHMIEvent *hmi_evt,
				      uint64_t *out_flags)
{
	struct phb *phb;
	struct npu *p = NULL;

	uint64_t npu_fir;
	uint64_t npu_fir_mask;
	uint64_t npu_fir_action0;
	uint64_t npu_fir_action1;
	uint64_t fatal_errors;

	/* Only check for NPU errors if the chip has a NPU */
	if (PVR_TYPE(mfspr(SPR_PVR)) != PVR_TYPE_P8NVL)
		return find_npu2_checkstop_reason(flat_chip_id, hmi_evt, out_flags);

	/* Find the NPU on the chip associated with the HMI. */
	for_each_phb(phb) {
		/* NOTE: if a chip ever has >1 NPU this will need adjusting */
		if (dt_node_is_compatible(phb->dt_node, "ibm,power8-npu-pciex") &&
		    (dt_get_chip_id(phb->dt_node) == flat_chip_id)) {
			p = phb_to_npu(phb);
			break;
		}
	}

	/* If we didn't find a NPU on the chip, it's not our checkstop. */
	if (p == NULL)
		return;

	/* Read all the registers necessary to find a checkstop condition. */
	if (xscom_read(flat_chip_id,
		       p->at_xscom + NX_FIR, &npu_fir) ||
	    xscom_read(flat_chip_id,
		       p->at_xscom + NX_FIR_MASK, &npu_fir_mask) ||
	    xscom_read(flat_chip_id,
		       p->at_xscom + NX_FIR_ACTION0, &npu_fir_action0) ||
	    xscom_read(flat_chip_id,
		       p->at_xscom + NX_FIR_ACTION1, &npu_fir_action1)) {
		prerror("Couldn't read NPU registers with XSCOM\n");
		return;
	}

	fatal_errors = npu_fir & ~npu_fir_mask & npu_fir_action0 & npu_fir_action1;

	/* If there's no errors, we don't need to do anything. */
	if (!fatal_errors)
		return;

	prlog(PR_DEBUG, "NPU: FIR 0x%016llx mask 0x%016llx\n",
	      npu_fir, npu_fir_mask);
	prlog(PR_DEBUG, "NPU: ACTION0 0x%016llx, ACTION1 0x%016llx\n",
	      npu_fir_action0, npu_fir_action1);

	/* Set the NPU to fenced since it can't recover. */
	npu_set_fence_state(p, true);

	/* Set up the HMI event */
	hmi_evt->severity = OpalHMI_SEV_WARNING;
	hmi_evt->type = OpalHMI_ERROR_MALFUNC_ALERT;
	hmi_evt->u.xstop_error.xstop_type = CHECKSTOP_TYPE_NPU;
	hmi_evt->u.xstop_error.u.chip_id = cpu_to_be32(flat_chip_id);

	/* The HMI is "recoverable" because it shouldn't crash the system */
	queue_hmi_event(hmi_evt, 1, out_flags);
}

static void decode_malfunction(struct OpalHMIEvent *hmi_evt, uint64_t *out_flags)
{
	int i;
	uint64_t malf_alert, flags;

	flags = 0;

	if (!setup_scom_addresses()) {
		prerror("Failed to setup scom addresses\n");
		/* Send an unknown HMI event. */
		hmi_evt->u.xstop_error.xstop_type = CHECKSTOP_TYPE_UNKNOWN;
		hmi_evt->u.xstop_error.xstop_reason = 0;
		queue_hmi_event(hmi_evt, false, out_flags);
		return;
	}

	xscom_read(this_cpu()->chip_id, malf_alert_scom, &malf_alert);

	if (!malf_alert)
		return;

	for (i = 0; i < 64; i++) {
		if (malf_alert & PPC_BIT(i)) {
			xscom_write(this_cpu()->chip_id, malf_alert_scom,
								~PPC_BIT(i));
			find_capp_checkstop_reason(i, hmi_evt, &flags);
			find_nx_checkstop_reason(i, hmi_evt, &flags);
			find_npu_checkstop_reason(i, hmi_evt, &flags);
		}
	}

	find_core_checkstop_reason(hmi_evt, &flags);

	/*
	 * If we fail to find checkstop reason, send an unknown HMI event.
	 */
	if (!(flags & OPAL_HMI_FLAGS_NEW_EVENT)) {
		hmi_evt->u.xstop_error.xstop_type = CHECKSTOP_TYPE_UNKNOWN;
		hmi_evt->u.xstop_error.xstop_reason = 0;
		queue_hmi_event(hmi_evt, false, &flags);
	}
	*out_flags |= flags;
}

/*
 * This will "rendez-vous" all threads on the core to the rendez-vous
 * id "sig". You need to make sure that "sig" is different from the
 * previous rendez vous. The sig value must be between 0 and 7 with
 * boot time being set to 0.
 *
 * Note: in theory, we could just use a flip flop "sig" in the thread
 * structure (binary rendez-vous with no argument). This is a bit more
 * debuggable and better at handling timeouts (arguably).
 *
 * This should be called with the no lock held
 */
static void hmi_rendez_vous(uint32_t sig)
{
	struct cpu_thread *t = this_cpu();
	uint32_t my_id = cpu_get_thread_index(t);
	uint32_t my_shift = my_id << 2;
	uint32_t *sptr = t->core_hmi_state_ptr;
	uint32_t val, prev, shift, i;
	uint64_t timeout;

	assert(sig <= 0x7);

	/*
	 * Mark ourselves as having reached the rendez vous point with
	 * the exit bit cleared
	 */
	do {
		val = prev = *sptr;
		val &= ~(0xfu << my_shift);
		val |= sig << my_shift;
	} while (cmpxchg32(sptr, prev, val) != prev);

	/*
	 * Wait for everybody else to reach that point, ignore the
	 * exit bit as another thread could have already set it.
	 */
	for (i = 0; i < cpu_thread_count; i++) {
		shift = i << 2;

		timeout = TIMEOUT_LOOPS;
		while (((*sptr >> shift) & 0x7) != sig && --timeout)
			cpu_relax();
		if (!timeout)
			prlog(PR_ERR, "Rendez-vous stage 1 timeout, CPU 0x%x"
			      " waiting for thread %d (sptr=%08x)\n",
						      t->pir, i, *sptr);
	}

	/* Set the exit bit */
	do {
		val = prev = *sptr;
		val &= ~(0xfu << my_shift);
		val |= (sig | 8) << my_shift;
	} while (cmpxchg32(sptr, prev, val) != prev);

	/* At this point, we need to wait for everybody else to have a value
	 * that is *not* sig. IE. they either have set the exit bit *or* they
	 * have changed the rendez-vous (meaning they have moved on to another
	 * rendez vous point).
	 */
	for (i = 0; i < cpu_thread_count; i++) {
		shift = i << 2;

		timeout = TIMEOUT_LOOPS;
		while (((*sptr >> shift) & 0xf) == sig && --timeout)
			cpu_relax();
		if (!timeout)
			prlog(PR_ERR, "Rendez-vous stage 2 timeout, CPU 0x%x"
			      " waiting for thread %d (sptr=%08x)\n",
						      t->pir, i, *sptr);
	}
}

static void hmi_print_debug(const uint8_t *msg, uint64_t hmer)
{
	const char *loc;
	uint32_t core_id, thread_index;

	core_id = pir_to_core_id(this_cpu()->pir);
	thread_index = cpu_get_thread_index(this_cpu());

	loc = chip_loc_code(this_cpu()->chip_id);
	if (!loc)
		loc = "Not Available";

	/* Also covers P10 SPR_HMER_TFAC_SHADOW_XFER_ERROR */
	if (hmer & (SPR_HMER_TFAC_ERROR | SPR_HMER_TFMR_PARITY_ERROR)) {
		prlog(PR_DEBUG, "[Loc: %s]: P:%d C:%d T:%d: TFMR(%016lx) %s\n",
			loc, this_cpu()->chip_id, core_id, thread_index,
			mfspr(SPR_TFMR), msg);
	} else {
		prlog(PR_DEBUG, "[Loc: %s]: P:%d C:%d T:%d: %s\n",
			loc, this_cpu()->chip_id, core_id, thread_index,
			msg);
	}
}

static int handle_thread_tfac_error(uint64_t tfmr, uint64_t *out_flags)
{
	int recover = 1;

	if (tfmr & SPR_TFMR_DEC_PARITY_ERR)
		*out_flags |= OPAL_HMI_FLAGS_DEC_LOST;
	if (!tfmr_recover_local_errors(tfmr))
		recover = 0;
	tfmr &= ~(SPR_TFMR_PURR_PARITY_ERR |
		  SPR_TFMR_SPURR_PARITY_ERR |
		  SPR_TFMR_DEC_PARITY_ERR);
	return recover;
}

static int64_t opal_handle_hmi(void);

static void opal_handle_hmi_job(void *data __unused)
{
	opal_handle_hmi();
}

/*
 * Queue hmi handling job If secondaries are still in OPAL
 * This function is called by thread 0.
 */
static struct cpu_job **hmi_kick_secondaries(void)
{
	struct cpu_thread *ts = this_cpu();
	struct cpu_job **hmi_jobs = NULL;
	int job_sz = sizeof(struct cpu_job *) * cpu_thread_count;
	int i;

	for (i = 1; i < cpu_thread_count; i++) {
		ts = next_cpu(ts);

		/* Is this thread still in OPAL ? */
		if (ts->state == cpu_state_active) {
			if (!hmi_jobs) {
				hmi_jobs = zalloc(job_sz);
				assert(hmi_jobs);
			}

			prlog(PR_DEBUG, "Sending hmi job to thread %d\n", i);
			hmi_jobs[i] = cpu_queue_job(ts, "handle_hmi_job",
					opal_handle_hmi_job, NULL);
		}
	}
	return hmi_jobs;
}

static int handle_all_core_tfac_error(uint64_t tfmr, uint64_t *out_flags)
{
	struct cpu_thread *t, *t0;
	int recover = -1;
	struct cpu_job **hmi_jobs = NULL;

	t = this_cpu();
	t0 = find_cpu_by_pir(cpu_get_thread0(t));

	if (t == t0 && t0->state == cpu_state_os)
		hmi_jobs = hmi_kick_secondaries();

	/* Rendez vous all threads */
	hmi_rendez_vous(1);

	/* We use a lock here as some of the TFMR bits are shared and I
	 * prefer avoiding doing the cleanup simultaneously.
	 */
	lock(&hmi_lock);

	/* First handle corrupt TFMR otherwise we can't trust anything.
	 * We'll use a lock here so that the threads don't try to do it at
	 * the same time
	 */
	if (tfmr & SPR_TFMR_TFMR_CORRUPT) {
		/* Check if it's still in error state */
		if (mfspr(SPR_TFMR) & SPR_TFMR_TFMR_CORRUPT)
			if (!recover_corrupt_tfmr()) {
				unlock(&hmi_lock);
				recover = 0;
				goto error_out;
			}

		tfmr = mfspr(SPR_TFMR);

		/* We could have got new thread errors in the meantime */
		if (tfmr & SPR_TFMR_THREAD_ERRORS) {
			recover = handle_thread_tfac_error(tfmr, out_flags);
			tfmr &= ~SPR_TFMR_THREAD_ERRORS;
		}
		if (!recover) {
			unlock(&hmi_lock);
			goto error_out;
		}
	}

	/* Tell the OS ... */
	if (tfmr & SPR_TFMR_HDEC_PARITY_ERROR)
		*out_flags |= OPAL_HMI_FLAGS_HDEC_LOST;

	/* Cleanup bad HDEC or TB on all threads or subcures before we clear
	 * the error conditions
	 */
	tfmr_cleanup_core_errors(tfmr);

	/* Unlock before next rendez-vous */
	unlock(&hmi_lock);

	/* Second rendez vous, ensure the above cleanups are all done before
	 * we proceed further
	 */
	hmi_rendez_vous(2);

	/* We can now clear the error conditions in the core. */
	recover = tfmr_clear_core_errors(tfmr);
	if (recover == 0)
		goto error_out;

	/* Third rendez-vous. We could in theory do the timebase resync as
	 * part of the previous one, but I prefer having all the error
	 * conditions cleared before we start trying.
	 */
	hmi_rendez_vous(3);

	/* Now perform the actual TB recovery on thread 0 */
	if (t == t0)
		recover = chiptod_recover_tb_errors(&this_cpu()->tb_resynced);

error_out:
	/* Last rendez-vous */
	hmi_rendez_vous(4);

	/* Now all threads have gone past rendez-vous 3 and not yet past another
	 * rendez-vous 1, so the value of tb_resynced of thread 0 of the core
	 * contains an accurate indication as to whether the timebase was lost.
	 */
	if (t0->tb_resynced)
		*out_flags |= OPAL_HMI_FLAGS_TB_RESYNC;

	if (t == t0 && hmi_jobs) {
		int i;
		for (i = 1; i < cpu_thread_count; i++)
			if (hmi_jobs[i])
				cpu_wait_job(hmi_jobs[i], true);
		free(hmi_jobs);
	}

	return recover;
}

static uint64_t read_tfmr_t0(void)
{
	uint64_t tfmr_t0;
	uint32_t chip_id = this_cpu()->chip_id;
	uint32_t core_id = pir_to_core_id(this_cpu()->pir);

	lock(&hmi_lock);

	xscom_write(chip_id, XSCOM_ADDR_P9_EC(core_id, P9_SCOM_SPRC),
			SETFIELD(P9_SCOMC_SPR_SELECT, 0, P9_SCOMC_TFMR_T0));
	xscom_read(chip_id, XSCOM_ADDR_P9_EC(core_id, P9_SCOM_SPRD),
				&tfmr_t0);
	unlock(&hmi_lock);
	return tfmr_t0;
}

/* P9 errata: In theory, an HDEC error is sent to all threads. However,
 * due to an errata on P9 where TFMR bit 26 (HDEC parity) cannot be
 * cleared on thread 1..3, I am not confident we can do a rendez-vous
 * in all cases.
 *
 * Our current approach is to ignore that error unless it is present
 * on thread 0 TFMR. Also, ignore TB residue error due to a similar
 * errata as above.
 */
static void validate_latched_errors(uint64_t *tfmr)
{
	if ((*tfmr & (SPR_TFMR_HDEC_PARITY_ERROR | SPR_TFMR_TB_RESIDUE_ERR))
				&& this_cpu()->is_secondary) {
		uint64_t tfmr_t0 = read_tfmr_t0();

		if (!(tfmr_t0 & SPR_TFMR_HDEC_PARITY_ERROR))
			*tfmr &= ~SPR_TFMR_HDEC_PARITY_ERROR;

		if (!(tfmr_t0 & SPR_TFMR_TB_RESIDUE_ERR))
			*tfmr &= ~SPR_TFMR_TB_RESIDUE_ERR;
	}
}

static int handle_tfac_errors(struct OpalHMIEvent *hmi_evt, uint64_t *out_flags)
{
	int recover = -1;
	uint64_t tfmr = mfspr(SPR_TFMR);

	/* Initialize the hmi event with old value of TFMR */
	hmi_evt->tfmr = cpu_to_be64(tfmr);

	/* A TFMR parity/corrupt error makes us ignore all the local stuff.*/
	if (tfmr & SPR_TFMR_TFMR_CORRUPT) {
		/* Mark TB as invalid for now as we don't trust TFMR, we'll fix
		 * it up later
		 */
		this_cpu()->tb_invalid = true;
		goto bad_tfmr;
	}

	this_cpu()->tb_invalid = !(tfmr & SPR_TFMR_TB_VALID);

	if (proc_gen == proc_gen_p9)
		validate_latched_errors(&tfmr);

	/* First, handle thread local errors */
	if (tfmr & SPR_TFMR_THREAD_ERRORS) {
		recover = handle_thread_tfac_error(tfmr, out_flags);
		tfmr &= ~SPR_TFMR_THREAD_ERRORS;
	}

 bad_tfmr:

	/* Let's see if we still have a all-core error to deal with, if
	 * not, we just bail out
	 */
	if (tfmr & SPR_TFMR_CORE_ERRORS) {
		int recover2;

		/* Only update "recover" if it's not already 0 (non-recovered)
		 */
		recover2 = handle_all_core_tfac_error(tfmr, out_flags);
		if (recover != 0)
			recover = recover2;
	} else if (tfmr & SPR_TFMR_CHIP_TOD_INTERRUPT) {
		int recover2;

		/*
		 * There are some TOD errors which do not affect working of
		 * TOD and TB. They stay in valid state. Hence we don't need
		 * rendez vous.
		 *
		 * TOD errors that affects TOD/TB will report a global error
		 * on TFMR alongwith bit 51, and they will go in rendez vous.
		 */
		recover2 = chiptod_recover_tod_errors();
		if (recover != 0)
			recover = recover2;
	} else if (this_cpu()->tb_invalid) {
		/* This shouldn't happen, TB is invalid and no global error
		 * was reported. We just return for now assuming one will
		 * be. We can't do a rendez vous without a core-global HMI.
		 */
		prlog(PR_ERR, "HMI: TB invalid without core error reported ! "
			"CPU=%x, TFMR=0x%016lx\n", this_cpu()->pir,
						mfspr(SPR_TFMR));
	}

	if (recover != -1 && hmi_evt) {
		hmi_evt->severity = OpalHMI_SEV_ERROR_SYNC;
		hmi_evt->type = OpalHMI_ERROR_TFAC;
		queue_hmi_event(hmi_evt, recover, out_flags);
	}

	/* Set the TB state looking at TFMR register before we head out. */
	this_cpu()->tb_invalid = !(mfspr(SPR_TFMR) & SPR_TFMR_TB_VALID);

	if (this_cpu()->tb_invalid) {
		*out_flags |= OPAL_HMI_FLAGS_TOD_TB_FAIL;
		prlog(PR_WARNING, "Failed to get TB in running state! "
			"CPU=%x, TFMR=%016lx\n", this_cpu()->pir,
					mfspr(SPR_TFMR));
	}

	return recover;
}

static int handle_hmi_exception(uint64_t hmer, struct OpalHMIEvent *hmi_evt,
				uint64_t *out_flags)
{
	struct cpu_thread *cpu = this_cpu();
	int recover = 1;
	uint64_t handled = 0;

	prlog(PR_DEBUG, "Received HMI interrupt: HMER = 0x%016llx\n", hmer);
	/* Initialize the hmi event with old value of HMER */
	if (hmi_evt)
		hmi_evt->hmer = cpu_to_be64(hmer);

	/* Handle Timer/TOD errors separately */
	if (hmer & (SPR_HMER_TFAC_ERROR | SPR_HMER_TFMR_PARITY_ERROR)) {
		hmi_print_debug("Timer Facility Error", hmer);
		handled = hmer & (SPR_HMER_TFAC_ERROR | SPR_HMER_TFMR_PARITY_ERROR);
		mtspr(SPR_HMER, ~handled);
		recover = handle_tfac_errors(hmi_evt, out_flags);
		handled = 0;
	}

	lock(&hmi_lock);
	/*
	 * Not all HMIs would move TB into invalid state. Set the TB state
	 * looking at TFMR register. TFMR will tell us correct state of
	 * TB register.
	 */
	if (hmer & SPR_HMER_PROC_RECV_DONE) {
		uint32_t chip_id = pir_to_chip_id(cpu->pir);
		uint32_t core_id = pir_to_core_id(cpu->pir);
		uint64_t core_wof;

		hmi_print_debug("Processor recovery occurred.", hmer);
		if (!read_core_wof(chip_id, core_id, &core_wof)) {
			int i;

			prlog(PR_DEBUG, "Core WOF = 0x%016llx recovered error:\n", core_wof);
			if (proc_gen <= proc_gen_p9) {
				for (i = 0; i < ARRAY_SIZE(p9_recoverable_bits); i++) {
					if (core_wof & PPC_BIT(p9_recoverable_bits[i].bit))
						prlog(PR_DEBUG, "    %s\n", p9_recoverable_bits[i].reason);
				}
			} else if (proc_gen == proc_gen_p10) {
				for (i = 0; i < ARRAY_SIZE(p10_core_fir_bits); i++) {
					if (core_wof & PPC_BIT(p10_core_fir_bits[i].bit))
						prlog(PR_DEBUG, "    %s\n", p10_core_fir_bits[i].reason);
				}
			}
		}

		handled |= SPR_HMER_PROC_RECV_DONE;
		if (cpu_is_thread0(cpu) && hmi_evt) {
			hmi_evt->severity = OpalHMI_SEV_NO_ERROR;
			hmi_evt->type = OpalHMI_ERROR_PROC_RECOV_DONE;
			queue_hmi_event(hmi_evt, recover, out_flags);
		}
	}

	if ((proc_gen <= proc_gen_p9) && (hmer & SPR_HMER_PROC_RECV_ERROR_MASKED)) {
		handled |= SPR_HMER_PROC_RECV_ERROR_MASKED;
		if (cpu_is_thread0(cpu) && hmi_evt) {
			hmi_evt->severity = OpalHMI_SEV_NO_ERROR;
			hmi_evt->type = OpalHMI_ERROR_PROC_RECOV_MASKED;
			queue_hmi_event(hmi_evt, recover, out_flags);
		}
		hmi_print_debug("Processor recovery Done (masked).", hmer);
	}

	if (hmer & SPR_HMER_PROC_RECV_AGAIN) {
		handled |= SPR_HMER_PROC_RECV_AGAIN;
		if (cpu_is_thread0(cpu) && hmi_evt) {
			hmi_evt->severity = OpalHMI_SEV_NO_ERROR;
			hmi_evt->type = OpalHMI_ERROR_PROC_RECOV_DONE_AGAIN;
			queue_hmi_event(hmi_evt, recover, out_flags);
		}
		hmi_print_debug("Processor recovery occurred again before"
				"bit2 was cleared\n", hmer);
	}

	/* XXX: what to do with this? */
	if (hmer & SPR_HMER_SPURR_SCALE_LIMIT) {
		handled |= SPR_HMER_SPURR_SCALE_LIMIT;
		if (cpu_is_thread0(cpu) && hmi_evt) {
			hmi_evt->severity = OpalHMI_SEV_NO_ERROR;
			hmi_evt->type = OpalHMI_ERROR_PROC_RECOV_DONE;
			queue_hmi_event(hmi_evt, recover, out_flags);
		}
		hmi_print_debug("Turbo versus nominal frequency exceeded limit.", hmer);
	}

	/* Assert if we see malfunction alert, we can not continue. */
	if (hmer & SPR_HMER_MALFUNCTION_ALERT) {
		handled |= SPR_HMER_MALFUNCTION_ALERT;

		hmi_print_debug("Malfunction Alert", hmer);
		recover = 0;
		if (hmi_evt)
			decode_malfunction(hmi_evt, out_flags);
	}

	/* Assert if we see Hypervisor resource error, we can not continue. */
	if ((proc_gen <= proc_gen_p9) && (hmer & SPR_HMER_HYP_RESOURCE_ERR)) {
		handled |= SPR_HMER_HYP_RESOURCE_ERR;

		hmi_print_debug("Hypervisor resource error", hmer);
		recover = 0;
		if (hmi_evt) {
			hmi_evt->severity = OpalHMI_SEV_FATAL;
			hmi_evt->type = OpalHMI_ERROR_HYP_RESOURCE;
			queue_hmi_event(hmi_evt, recover, out_flags);
		}
	}

	/* XXX: what to do with this? */
	if ((proc_gen <= proc_gen_p9) && (hmer & SPR_HMER_THD_WAKE_BLOCKED_TM_SUSPEND)) {
		handled |= SPR_HMER_THD_WAKE_BLOCKED_TM_SUSPEND;
		hmer &= ~SPR_HMER_THD_WAKE_BLOCKED_TM_SUSPEND;

		hmi_print_debug("Attempted to wake thread when threads in TM suspend mode.", hmer);
		if (hmi_evt) {
			hmi_evt->severity = OpalHMI_SEV_NO_ERROR;
			hmi_evt->type = OpalHMI_ERROR_PROC_RECOV_DONE,
				queue_hmi_event(hmi_evt, recover, out_flags);
		}
	}

	if ((proc_gen <= proc_gen_p9) && (hmer & SPR_HMER_TRIG_FIR_HMI)) {
		handled |= SPR_HMER_TRIG_FIR_HMI;
		hmer &= ~SPR_HMER_TRIG_FIR_HMI;

		hmi_print_debug("Clearing unknown debug trigger", hmer);
		if (hmi_evt) {
			hmi_evt->severity = OpalHMI_SEV_NO_ERROR;
			hmi_evt->type = OpalHMI_ERROR_DEBUG_TRIG_FIR,
				queue_hmi_event(hmi_evt, recover, out_flags);
		}
	}
	if ((proc_gen == proc_gen_p10) && (hmer & SPR_HMER_P10_TRIG_FIR_HMI)) {
		handled |= SPR_HMER_P10_TRIG_FIR_HMI;
		hmer &= ~SPR_HMER_P10_TRIG_FIR_HMI;

		hmi_print_debug("Clearing unknown debug trigger", hmer);
		if (hmi_evt) {
			hmi_evt->severity = OpalHMI_SEV_NO_ERROR;
			hmi_evt->type = OpalHMI_ERROR_DEBUG_TRIG_FIR,
				queue_hmi_event(hmi_evt, recover, out_flags);
		}
	}

	if (recover == 0)
		disable_fast_reboot("Unrecoverable HMI");
	/*
	 * HMER bits are sticky, once set to 1 they remain set to 1 until
	 * they are set to 0. Reset the error source bit to 0, otherwise
	 * we keep getting HMI interrupt again and again. Writing to HMER
	 * acts as an AND, so we write mask of all 1's except for the bits
	 * we want to clear.
	 */
	mtspr(SPR_HMER, ~handled);
	unlock(&hmi_lock);
	return recover;
}

static int64_t opal_handle_hmi(void)
{
	uint64_t hmer, dummy_flags;
	struct OpalHMIEvent hmi_evt;

	/*
	 * Compiled time check to see size of OpalHMIEvent do not exceed
	 * that of struct opal_msg.
	 */
	BUILD_ASSERT(sizeof(struct opal_msg) >= sizeof(struct OpalHMIEvent));

	memset(&hmi_evt, 0, sizeof(struct OpalHMIEvent));
	hmi_evt.version = OpalHMIEvt_V2;

	hmer = mfspr(SPR_HMER);		/* Get HMER register value */
	handle_hmi_exception(hmer, &hmi_evt, &dummy_flags);

	return OPAL_SUCCESS;
}
opal_call(OPAL_HANDLE_HMI, opal_handle_hmi, 0);

static int64_t opal_handle_hmi2(__be64 *out_flags)
{
	uint64_t hmer, flags = 0;
	struct OpalHMIEvent hmi_evt;

	/*
	 * Compiled time check to see size of OpalHMIEvent do not exceed
	 * that of struct opal_msg.
	 */
	BUILD_ASSERT(sizeof(struct opal_msg) >= sizeof(struct OpalHMIEvent));

	memset(&hmi_evt, 0, sizeof(struct OpalHMIEvent));
	hmi_evt.version = OpalHMIEvt_V2;

	hmer = mfspr(SPR_HMER);		/* Get HMER register value */
	handle_hmi_exception(hmer, &hmi_evt, &flags);
	*out_flags = cpu_to_be64(flags);

	return OPAL_SUCCESS;
}
opal_call(OPAL_HANDLE_HMI2, opal_handle_hmi2, 1);
