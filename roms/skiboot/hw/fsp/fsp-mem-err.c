// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Sometimes some memory needs to go and sit in the naughty corner
 *
 * Copyright 2013-2019 IBM Corp.
 */

#define pr_fmt(fmt) "FSPMEMERR: " fmt
#include <skiboot.h>
#include <opal.h>
#include <opal-msg.h>
#include <lock.h>
#include <fsp.h>
#include <errorlog.h>

/* FSP sends real address of 4K memory page. */
#define MEM_ERR_PAGE_SIZE_4K	(1UL << 12)

/* maximum number of error event to hold until linux consumes it. */
#define MERR_MAX_RECORD		1024

struct fsp_mem_err_node {
	struct list_node list;
	struct OpalMemoryErrorData data;
};

static LIST_HEAD(merr_free_list);
static LIST_HEAD(mem_error_list);
/*
 * lock is used to protect overwriting of merr_free_list and mem_error_list
 * list.
 */
static struct lock mem_err_lock = LOCK_UNLOCKED;

DEFINE_LOG_ENTRY(OPAL_RC_MEM_ERR_RES, OPAL_PLATFORM_ERR_EVT, OPAL_MEM_ERR,
			OPAL_MISC_SUBSYSTEM, OPAL_PREDICTIVE_ERR_GENERAL,
			OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_MEM_ERR_DEALLOC, OPAL_PLATFORM_ERR_EVT, OPAL_MEM_ERR,
			OPAL_MISC_SUBSYSTEM, OPAL_PREDICTIVE_ERR_GENERAL,
			OPAL_NA);

static bool send_response_to_fsp(u32 cmd_sub_mod)
{
	struct fsp_msg *rsp;
	int rc = -ENOMEM;

	rsp = fsp_mkmsg(cmd_sub_mod, 0);
	if (rsp)
		rc = fsp_queue_msg(rsp, fsp_freemsg);
	if (rc) {
		fsp_freemsg(rsp);
		/* XXX Generate error logs */
		prerror("Error %d queueing FSP memory error reply\n", rc);
		return false;
	}
	return true;
}

/*
 * Queue up the memory error message for delivery.
 *
 * queue_event_for_delivery get called from two places.
 * 1) from queue_mem_err_node when new fsp mem error is available and
 * 2) from completion callback indicating that linux has consumed an message.
 *
 * TODO:
 * There is a chance that, we may not get a free slot to queue our event
 * for delivery to linux during both the above invocations. In that case
 * we end up holding events with us until next fsp memory error comes in.
 * We need to address this case either here OR fix up messaging infrastructure
 * to make sure at least one slot will always be available per message type.
 *
 * XXX: BenH: I changed the msg infrastructure to attempt an allocation
 *            in that case, at least until we clarify a bit better how
 *            we want to handle things.
 */
static void queue_event_for_delivery(void *data __unused, int staus __unused)
{
	struct fsp_mem_err_node *entry;
	uint64_t *merr_data;
	int rc;

	lock(&mem_err_lock);
	entry = list_pop(&mem_error_list, struct fsp_mem_err_node, list);
	unlock(&mem_err_lock);

	if (!entry)
		return;

	/*
	 * struct OpalMemoryErrorData is of (4 * 64 bits) size and well packed
	 * structure. Hence use uint64_t pointer to pass entire structure
	 * using 4 params in generic message format.
	 */
	merr_data = (uint64_t *)&entry->data;

	/* queue up for delivery */
	rc = opal_queue_msg(OPAL_MSG_MEM_ERR, NULL, queue_event_for_delivery,
			    cpu_to_be64(merr_data[0]),
			    cpu_to_be64(merr_data[1]),
			    cpu_to_be64(merr_data[2]),
			    cpu_to_be64(merr_data[3]));
	lock(&mem_err_lock);
	if (rc) {
		/*
		 * Failed to queue up the event for delivery. No free slot
		 * available. There is a chance that we are trying to queue
		 * up multiple event at the same time. We may already have
		 * at least one event queued up, in that case we will be
		 * called again through completion callback and we should
		 * be able to grab empty slot then.
		 *
		 * For now, put this node back on mem_error_list.
		 */
		list_add(&mem_error_list, &entry->list);
	} else
		list_add(&merr_free_list, &entry->list);
	unlock(&mem_err_lock);
}

static int queue_mem_err_node(struct OpalMemoryErrorData *merr_evt)
{
	struct fsp_mem_err_node *entry;

	lock(&mem_err_lock);
	entry = list_pop(&merr_free_list, struct fsp_mem_err_node, list);
	if (!entry) {
		printf("Failed to queue up memory error event.\n");
		unlock(&mem_err_lock);
		return -ENOMEM;
	}

	entry->data = *merr_evt;
	list_add(&mem_error_list, &entry->list);
	unlock(&mem_err_lock);

	/* Queue up the event for delivery to OS. */
	queue_event_for_delivery(NULL, OPAL_SUCCESS);
	return 0;
}

/* Check if memory resilience event for same address already exists. */
static bool is_resilience_event_exist(u64 paddr)
{
	struct fsp_mem_err_node *entry;
	struct OpalMemoryErrorData *merr_evt;
	int found = 0;

	lock(&mem_err_lock);
	list_for_each(&mem_error_list, entry, list) {
		merr_evt = &entry->data;
		if ((merr_evt->type == OPAL_MEM_ERR_TYPE_RESILIENCE) &&
		    (be64_to_cpu(merr_evt->u.resilience.physical_address_start)
							    == paddr)) {
			found = 1;
			break;
		}
	}
	unlock(&mem_err_lock);
	return !!found;
}

/*
 * handle Memory Resilience error message.
 * Section 28.2 of Hypervisor to FSP Mailbox Interface Specification.
 *
 * The flow for Memory Resilence Event is:
 * 1. PRD component in FSP gets a recoverable attention from hardware when
 *    there is a corretable/uncorrectable memory error to free up a page.
 * 2. PRD sends Memory Resilence Command to hypervisor with the real address of
 *    the 4K memory page in which the error occurred.
 * 3. The hypervisor acknowledges with a status immediately. Immediate
 *    acknowledgment doesn’t require the freeing of the page to be completed.
 */
static bool handle_memory_resilience(u32 cmd_sub_mod, u64 paddr)
{
	int rc = 0;
	struct OpalMemoryErrorData mem_err_evt;
	struct errorlog *buf;

	memset(&mem_err_evt, 0, sizeof(struct OpalMemoryErrorData));
	/* Check arguments */
	if (paddr == 0) {
		prerror("memory resilience: Invalid real address.\n");
		return send_response_to_fsp(FSP_RSP_MEM_RES |
					    FSP_STATUS_GENERIC_ERROR);
	}

	/* Check if event already exist for same address. */
	if (is_resilience_event_exist(paddr))
		goto send_response;

	/* Populate an event. */
	mem_err_evt.version = OpalMemErr_V1;
	mem_err_evt.type = OPAL_MEM_ERR_TYPE_RESILIENCE;

	switch (cmd_sub_mod) {
	case FSP_CMD_MEM_RES_CE:
		/*
		 * Should we keep counter for corrected errors in
		 * sapphire OR let linux (PowerNV) handle it?
		 *
		 * For now, send corrected errors to linux and let
		 * linux handle corrected errors thresholding.
		 */
		mem_err_evt.flags |= cpu_to_be16(OPAL_MEM_CORRECTED_ERROR);
		mem_err_evt.u.resilience.resil_err_type =
					OPAL_MEM_RESILIENCE_CE;
		break;
	case FSP_CMD_MEM_RES_UE:
		mem_err_evt.u.resilience.resil_err_type =
					OPAL_MEM_RESILIENCE_UE;
		break;
	case FSP_CMD_MEM_RES_UE_SCRB:
		mem_err_evt.u.resilience.resil_err_type =
					OPAL_MEM_RESILIENCE_UE_SCRUB;
		break;
	}
	mem_err_evt.u.resilience.physical_address_start = cpu_to_be64(paddr);
	mem_err_evt.u.resilience.physical_address_end =
		cpu_to_be64(paddr + MEM_ERR_PAGE_SIZE_4K);

	/* Queue up the event and inform OS about it. */
	rc = queue_mem_err_node(&mem_err_evt);

send_response:
	/* Queue up an OK response to the resilience message itself */
	if (!rc)
		return send_response_to_fsp(FSP_RSP_MEM_RES);
	else {
		buf = opal_elog_create(&e_info(OPAL_RC_MEM_ERR_RES), 0);
		log_append_msg(buf,
			"OPAL_MEM_ERR: Cannot queue up memory "
			"resilience error event to the OS");
		log_add_section(buf, OPAL_ELOG_SEC_DESC);
		log_append_data(buf, (char *) &mem_err_evt,
					   sizeof(struct OpalMemoryErrorData));
		log_commit(buf);
		return false;
	}
}

/* update existing event entry if match is found. */
static bool update_memory_deallocation_event(u64 paddr_start, u64 paddr_end)
{
	struct fsp_mem_err_node *entry;
	struct OpalMemoryErrorData *merr_evt;
	int found = 0;

	lock(&mem_err_lock);
	list_for_each(&mem_error_list, entry, list) {
		merr_evt = &entry->data;
		if ((merr_evt->type == OPAL_MEM_ERR_TYPE_DYN_DALLOC) &&
		    (be64_to_cpu(merr_evt->u.dyn_dealloc.physical_address_start)
							    == paddr_start)) {
			found = 1;
			if (be64_to_cpu(merr_evt->u.dyn_dealloc.physical_address_end)
								< paddr_end)
				merr_evt->u.dyn_dealloc.physical_address_end =
					cpu_to_be64(paddr_end);
			break;
		}
	}
	unlock(&mem_err_lock);
	return !!found;
}

/*
 * Handle dynamic memory deallocation message.
 *
 * When a condition occurs in which we need to do a large scale memory
 * deallocation, PRD will send a starting and ending address of an area of
 * memory to Hypervisor. Hypervisor then need to use this to deallocate all
 * pages between and including the addresses.
 *
 */
static bool handle_memory_deallocation(u64 paddr_start, u64 paddr_end)
{
	int rc = 0;
	u8 err = 0;
	struct OpalMemoryErrorData mem_err_evt;
	struct errorlog *buf;

	memset(&mem_err_evt, 0, sizeof(struct OpalMemoryErrorData));
	/* Check arguments */
	if ((paddr_start == 0) || (paddr_end == 0)) {
		prerror("memory deallocation: Invalid "
			"starting/ending real address.\n");
		err = FSP_STATUS_GENERIC_ERROR;
	}

	/* If we had an error, send response to fsp and return */
	if (err)
		return send_response_to_fsp(FSP_RSP_MEM_DYN_DEALLOC | err);

	/*
	 * FSP can send dynamic memory deallocation multiple times for the
	 * same address/address ranges. Hence check and update if we already
	 * have sam event queued.
	 */
	if (update_memory_deallocation_event(paddr_start, paddr_end))
		goto send_response;

	/* Populate an new event. */
	mem_err_evt.version = OpalMemErr_V1;
	mem_err_evt.type = OPAL_MEM_ERR_TYPE_DYN_DALLOC;
	mem_err_evt.u.dyn_dealloc.dyn_err_type =
					OPAL_MEM_DYNAMIC_DEALLOC;
	mem_err_evt.u.dyn_dealloc.physical_address_start = cpu_to_be64(paddr_start);
	mem_err_evt.u.dyn_dealloc.physical_address_end = cpu_to_be64(paddr_end);

	/* Queue up the event and inform OS about it. */
	rc = queue_mem_err_node(&mem_err_evt);

send_response:
	/* Queue up an OK response to the memory deallocation message itself */
	if (!rc)
		return send_response_to_fsp(FSP_RSP_MEM_DYN_DEALLOC);
	else {
		buf = opal_elog_create(&e_info(OPAL_RC_MEM_ERR_DEALLOC), 0);
		log_append_msg(buf,
			"OPAL_MEM_ERR: Cannot queue up memory "
			"deallocation error event to the OS");
		log_add_section(buf, OPAL_ELOG_SEC_DESC);
		log_append_data(buf, (char *)&mem_err_evt,
					   sizeof(struct OpalMemoryErrorData));
		log_commit(buf);
		return false;
	}
}

/* Receive a memory error mesages and handle it. */
static bool fsp_mem_err_msg(u32 cmd_sub_mod, struct fsp_msg *msg)
{
	u64 paddr_start, paddr_end;

	printf("Received 0x%08ux command\n", cmd_sub_mod);
	switch (cmd_sub_mod) {
	case FSP_CMD_MEM_RES_CE:
	case FSP_CMD_MEM_RES_UE:
	case FSP_CMD_MEM_RES_UE_SCRB:
		/*
		 * We get the memory relilence command from FSP for
		 * correctable/Uncorrectable/scrub UE errors with real
		 * address of 4K memory page in which the error occurred.
		 */
		paddr_start = be64_to_cpu(*((__be64 *)&msg->data.bytes[0]));
		printf("Got memory resilience error message for "
		       "paddr=0x%016llux\n", paddr_start);
		return handle_memory_resilience(cmd_sub_mod, paddr_start);
	case FSP_CMD_MEM_DYN_DEALLOC:
		paddr_start = be64_to_cpu(*((__be64 *)&msg->data.bytes[0]));
		paddr_end = be64_to_cpu(*((__be64 *)&msg->data.bytes[8]));
		printf("Got dynamic memory deallocation message: "
		       "paddr_start=0x%016llux, paddr_end=0x%016llux\n",
		       paddr_start, paddr_end);
		return handle_memory_deallocation(paddr_start, paddr_end);
	}
	return false;
}

/*
 * pre allocate memory to hold maximum of 128 memory error event until linux
 * consumes it.
 */
static int init_merr_free_list(uint32_t num_entries)
{
	struct fsp_mem_err_node *entry;
	int i;

	entry = zalloc(sizeof(struct fsp_mem_err_node) * num_entries);
	if (!entry)
		return -ENOMEM;

	for (i = 0; i < num_entries; ++i, entry++)
		list_add_tail(&merr_free_list, &entry->list);

	return 0;
}

static struct fsp_client fsp_mem_err_client = {
	.message = fsp_mem_err_msg,
};

void fsp_memory_err_init(void)
{
	int rc;

	printf("Intializing fsp memory handling.\n");
	/* If we have an FSP, register for notifications */
	if (!fsp_present())
		return;

	/* pre allocate memory for 128 record */
	rc = init_merr_free_list(MERR_MAX_RECORD);
	if (rc < 0)
		return;

	fsp_register_client(&fsp_mem_err_client, FSP_MCLASS_MEMORY_ERR);
}
