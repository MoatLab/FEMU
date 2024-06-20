/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *   Anup Patel <anup.patel@wdc.com>
 *   Nick Kossifidis <mick@ics.forth.gr>
 */

#include <sbi/riscv_asm.h>
#include <sbi/riscv_atomic.h>
#include <sbi/riscv_barrier.h>
#include <sbi/sbi_bitops.h>
#include <sbi/sbi_domain.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_hsm.h>
#include <sbi/sbi_init.h>
#include <sbi/sbi_ipi.h>
#include <sbi/sbi_platform.h>
#include <sbi/sbi_pmu.h>
#include <sbi/sbi_string.h>
#include <sbi/sbi_tlb.h>

struct sbi_ipi_data {
	unsigned long ipi_type;
};

_Static_assert(
	8 * sizeof(((struct sbi_ipi_data*)0)->ipi_type) == SBI_IPI_EVENT_MAX,
	"type of sbi_ipi_data.ipi_type has changed, please redefine SBI_IPI_EVENT_MAX"
	);

static unsigned long ipi_data_off;
static const struct sbi_ipi_device *ipi_dev = NULL;
static const struct sbi_ipi_event_ops *ipi_ops_array[SBI_IPI_EVENT_MAX];

static int sbi_ipi_send(struct sbi_scratch *scratch, u32 remote_hartindex,
			u32 event, void *data)
{
	int ret = 0;
	struct sbi_scratch *remote_scratch = NULL;
	struct sbi_ipi_data *ipi_data;
	const struct sbi_ipi_event_ops *ipi_ops;

	if ((SBI_IPI_EVENT_MAX <= event) ||
	    !ipi_ops_array[event])
		return SBI_EINVAL;
	ipi_ops = ipi_ops_array[event];

	remote_scratch = sbi_hartindex_to_scratch(remote_hartindex);
	if (!remote_scratch)
		return SBI_EINVAL;

	ipi_data = sbi_scratch_offset_ptr(remote_scratch, ipi_data_off);

	if (ipi_ops->update) {
		ret = ipi_ops->update(scratch, remote_scratch,
				      remote_hartindex, data);
		if (ret != SBI_IPI_UPDATE_SUCCESS)
			return ret;
	} else if (scratch == remote_scratch) {
		/*
		 * IPI events with an update() callback are expected to return
		 * SBI_IPI_UPDATE_BREAK for self-IPIs. For other events, check
		 * for self-IPI and execute the callback directly here.
		 */
		ipi_ops->process(scratch);
		return 0;
	}

	/*
	 * Set IPI type on remote hart's scratch area and
	 * trigger the interrupt.
	 *
	 * Multiple harts may be trying to send IPI to the
	 * remote hart so call sbi_ipi_raw_send() only when
	 * the ipi_type was previously zero.
	 */
	if (!__atomic_fetch_or(&ipi_data->ipi_type,
				BIT(event), __ATOMIC_RELAXED))
		ret = sbi_ipi_raw_send(remote_hartindex);

	sbi_pmu_ctr_incr_fw(SBI_PMU_FW_IPI_SENT);

	return ret;
}

static int sbi_ipi_sync(struct sbi_scratch *scratch, u32 event)
{
	const struct sbi_ipi_event_ops *ipi_ops;

	if ((SBI_IPI_EVENT_MAX <= event) ||
	    !ipi_ops_array[event])
		return SBI_EINVAL;
	ipi_ops = ipi_ops_array[event];

	if (ipi_ops->sync)
		ipi_ops->sync(scratch);

	return 0;
}

/**
 * As this this function only handlers scalar values of hart mask, it must be
 * set to all online harts if the intention is to send IPIs to all the harts.
 * If hmask is zero, no IPIs will be sent.
 */
int sbi_ipi_send_many(ulong hmask, ulong hbase, u32 event, void *data)
{
	int rc = 0;
	bool retry_needed;
	ulong i, m;
	struct sbi_hartmask target_mask = {0};
	struct sbi_domain *dom = sbi_domain_thishart_ptr();
	struct sbi_scratch *scratch = sbi_scratch_thishart_ptr();

	/* Find the target harts */
	if (hbase != -1UL) {
		rc = sbi_hsm_hart_interruptible_mask(dom, hbase, &m);
		if (rc)
			return rc;
		m &= hmask;

		for (i = hbase; m; i++, m >>= 1) {
			if (m & 1UL)
				sbi_hartmask_set_hartid(i, &target_mask);
		}
	} else {
		hbase = 0;
		while (!sbi_hsm_hart_interruptible_mask(dom, hbase, &m)) {
			for (i = hbase; m; i++, m >>= 1) {
				if (m & 1UL)
					sbi_hartmask_set_hartid(i, &target_mask);
			}
			hbase += BITS_PER_LONG;
		}
	}

	/* Send IPIs */
	do {
		retry_needed = false;
		sbi_hartmask_for_each_hartindex(i, &target_mask) {
			rc = sbi_ipi_send(scratch, i, event, data);
			if (rc < 0)
				goto done;
			if (rc == SBI_IPI_UPDATE_RETRY)
				retry_needed = true;
			else
				sbi_hartmask_clear_hartindex(i, &target_mask);
			rc = 0;
		}
	} while (retry_needed);

done:
	/* Sync IPIs */
	sbi_ipi_sync(scratch, event);

	return rc;
}

int sbi_ipi_event_create(const struct sbi_ipi_event_ops *ops)
{
	int i, ret = SBI_ENOSPC;

	if (!ops || !ops->process)
		return SBI_EINVAL;

	for (i = 0; i < SBI_IPI_EVENT_MAX; i++) {
		if (!ipi_ops_array[i]) {
			ret = i;
			ipi_ops_array[i] = ops;
			break;
		}
	}

	return ret;
}

void sbi_ipi_event_destroy(u32 event)
{
	if (SBI_IPI_EVENT_MAX <= event)
		return;

	ipi_ops_array[event] = NULL;
}

static void sbi_ipi_process_smode(struct sbi_scratch *scratch)
{
	csr_set(CSR_MIP, MIP_SSIP);
}

static struct sbi_ipi_event_ops ipi_smode_ops = {
	.name = "IPI_SMODE",
	.process = sbi_ipi_process_smode,
};

static u32 ipi_smode_event = SBI_IPI_EVENT_MAX;

int sbi_ipi_send_smode(ulong hmask, ulong hbase)
{
	return sbi_ipi_send_many(hmask, hbase, ipi_smode_event, NULL);
}

void sbi_ipi_clear_smode(void)
{
	csr_clear(CSR_MIP, MIP_SSIP);
}

static void sbi_ipi_process_halt(struct sbi_scratch *scratch)
{
	sbi_hsm_hart_stop(scratch, true);
}

static struct sbi_ipi_event_ops ipi_halt_ops = {
	.name = "IPI_HALT",
	.process = sbi_ipi_process_halt,
};

static u32 ipi_halt_event = SBI_IPI_EVENT_MAX;

int sbi_ipi_send_halt(ulong hmask, ulong hbase)
{
	return sbi_ipi_send_many(hmask, hbase, ipi_halt_event, NULL);
}

void sbi_ipi_process(void)
{
	unsigned long ipi_type;
	unsigned int ipi_event;
	const struct sbi_ipi_event_ops *ipi_ops;
	struct sbi_scratch *scratch = sbi_scratch_thishart_ptr();
	struct sbi_ipi_data *ipi_data =
			sbi_scratch_offset_ptr(scratch, ipi_data_off);
	u32 hartindex = sbi_hartid_to_hartindex(current_hartid());

	sbi_pmu_ctr_incr_fw(SBI_PMU_FW_IPI_RECVD);
	sbi_ipi_raw_clear(hartindex);

	ipi_type = atomic_raw_xchg_ulong(&ipi_data->ipi_type, 0);
	ipi_event = 0;
	while (ipi_type) {
		if (ipi_type & 1UL) {
			ipi_ops = ipi_ops_array[ipi_event];
			if (ipi_ops)
				ipi_ops->process(scratch);
		}
		ipi_type = ipi_type >> 1;
		ipi_event++;
	}
}

int sbi_ipi_raw_send(u32 hartindex)
{
	if (!ipi_dev || !ipi_dev->ipi_send)
		return SBI_EINVAL;

	/*
	 * Ensure that memory or MMIO writes done before
	 * this function are not observed after the memory
	 * or MMIO writes done by the ipi_send() device
	 * callback. This also allows the ipi_send() device
	 * callback to use relaxed MMIO writes.
	 *
	 * This pairs with the wmb() in sbi_ipi_raw_clear().
	 */
	wmb();

	ipi_dev->ipi_send(hartindex);
	return 0;
}

void sbi_ipi_raw_clear(u32 hartindex)
{
	if (ipi_dev && ipi_dev->ipi_clear)
		ipi_dev->ipi_clear(hartindex);

	/*
	 * Ensure that memory or MMIO writes after this
	 * function returns are not observed before the
	 * memory or MMIO writes done by the ipi_clear()
	 * device callback. This also allows ipi_clear()
	 * device callback to use relaxed MMIO writes.
	 *
	 * This pairs with the wmb() in sbi_ipi_raw_send().
	 */
	wmb();
}

const struct sbi_ipi_device *sbi_ipi_get_device(void)
{
	return ipi_dev;
}

void sbi_ipi_set_device(const struct sbi_ipi_device *dev)
{
	if (!dev || ipi_dev)
		return;

	ipi_dev = dev;
}

int sbi_ipi_init(struct sbi_scratch *scratch, bool cold_boot)
{
	int ret;
	struct sbi_ipi_data *ipi_data;

	if (cold_boot) {
		ipi_data_off = sbi_scratch_alloc_offset(sizeof(*ipi_data));
		if (!ipi_data_off)
			return SBI_ENOMEM;
		ret = sbi_ipi_event_create(&ipi_smode_ops);
		if (ret < 0)
			return ret;
		ipi_smode_event = ret;
		ret = sbi_ipi_event_create(&ipi_halt_ops);
		if (ret < 0)
			return ret;
		ipi_halt_event = ret;
	} else {
		if (!ipi_data_off)
			return SBI_ENOMEM;
		if (SBI_IPI_EVENT_MAX <= ipi_smode_event ||
		    SBI_IPI_EVENT_MAX <= ipi_halt_event)
			return SBI_ENOSPC;
	}

	ipi_data = sbi_scratch_offset_ptr(scratch, ipi_data_off);
	ipi_data->ipi_type = 0x00;

	/*
	 * Initialize platform IPI support. This will also clear any
	 * pending IPIs for current/calling HART.
	 */
	ret = sbi_platform_ipi_init(sbi_platform_ptr(scratch), cold_boot);
	if (ret)
		return ret;

	/* Enable software interrupts */
	csr_set(CSR_MIE, MIP_MSIP);

	return 0;
}

void sbi_ipi_exit(struct sbi_scratch *scratch)
{
	/* Disable software interrupts */
	csr_clear(CSR_MIE, MIP_MSIP);

	/* Process pending IPIs */
	sbi_ipi_process();

	/* Platform exit */
	sbi_platform_ipi_exit(sbi_platform_ptr(scratch));
}
