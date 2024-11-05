// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * There's some system level parameters that aren't over IPMI or NVRAM
 * but that the FSP exposes through this interface.
 *
 * We expose these through an OPAL API as there really isn't any other/better
 * way of doing so.
 *
 * Copyright 2013-2017 IBM Corp.
 */

#include <skiboot.h>
#include <fsp.h>
#include <opal.h>
#include <device.h>
#include <lock.h>
#include <processor.h>
#include <psi.h>
#include <opal-msg.h>
#include <fsp-sysparam.h>

struct sysparam_comp_data {
	uint32_t param_len;
	uint64_t async_token;
};

struct sysparam_req {
	sysparam_compl_t	completion;
	void			*comp_data;
	void			*ubuf;
	uint32_t		ulen;
	struct fsp_msg		msg;
	struct fsp_msg		resp;
	bool			done;
};

static struct sysparam_attr {
	const char	*name;
	uint32_t	id;
	uint32_t	length;
	uint8_t		perm;
} sysparam_attrs[] = {
#define _R	OPAL_SYSPARAM_READ
#define _W	OPAL_SYSPARAM_WRITE
#define _RW	OPAL_SYSPARAM_RW
	{"surveillance",	SYS_PARAM_SURV, 	4,	_RW},
	{"hmc-management", 	SYS_PARAM_HMC_MANAGED,	4,	_R},
	{"cupd-policy",		SYS_PARAM_FLASH_POLICY, 4,	_RW},
	{"plat-hmc-managed",	SYS_PARAM_NEED_HMC,	4,	_RW},
	{"fw-license-policy",	SYS_PARAM_FW_LICENSE,	4,	_RW},
	{"world-wide-port-num", SYS_PARAM_WWPN,		12,	_W},
	{"default-boot-device",	SYS_PARAM_DEF_BOOT_DEV,	1,	_RW},
	{"next-boot-device",	SYS_PARAM_NEXT_BOOT_DEV,1,	_RW},
	{"console-select",	SYS_PARAM_CONSOLE_SELECT,1,	_RW},
	{"boot-device-path",	SYS_PARAM_BOOT_DEV_PATH,48,	_RW}
#undef _R
#undef _W
#undef _RW
};

static int fsp_sysparam_process(struct sysparam_req *r)
{
	u32 param_id, len;
	int stlen = 0;
	u8 fstat;
	/* Snapshot completion before we set the "done" flag */
	sysparam_compl_t comp = r->completion;
	void *cdata = r->comp_data;

	if (r->msg.state != fsp_msg_done) {
		prerror("FSP: Request for sysparam 0x%x got FSP failure!\n",
			fsp_msg_get_data_word(&r->msg, 0));
		stlen = -1; /* XXX Find saner error codes */
		goto complete;
	}

	param_id = fsp_msg_get_data_word(&r->resp, 0);
	len = fsp_msg_get_data_word(&r->resp, 1) & 0xffff;

	/* Check params validity */
	if (param_id != fsp_msg_get_data_word(&r->msg, 0)) {
		prerror("FSP: Request for sysparam 0x%x got resp. for 0x%x!\n",
			fsp_msg_get_data_word(&r->msg, 0), param_id);
		stlen = -2; /* XXX Sane error codes */
		goto complete;
	}
	if (len > r->ulen) {
		prerror("FSP: Request for sysparam 0x%x truncated!\n",
			param_id);
		len = r->ulen;
	}

	/* Decode the request status */
	fstat = (r->msg.resp->word1 >> 8) & 0xff;
	switch(fstat) {
	case 0x00: /* XXX Is that even possible ? */
	case 0x11: /* Data in request */
		memcpy(r->ubuf, &r->resp.data.bytes[8], len);
		/* fallthrough */
	case 0x12: /* Data in TCE */
		stlen = len;
		break;
	default:
		stlen = -fstat;
	}
 complete:
	/* Call completion if any */
	if (comp)
		comp(fsp_msg_get_data_word(&r->msg, 0), stlen, cdata);
	
	free(r);

	return stlen;
}

static void fsp_sysparam_get_complete(struct fsp_msg *msg)
{
	struct sysparam_req *r = container_of(msg, struct sysparam_req, msg);

	/* If it's an asynchronous request, process it now */
	if (r->completion) {
		fsp_sysparam_process(r);
		return;
	}

	/* Else just set the done flag */

	/* Another CPU can be polling on the "done" flag without the
	 * lock held, so let's order the udpates to the structure
	 */
	lwsync();
	r->done = true;
}

int fsp_get_sys_param(uint32_t param_id, void *buffer, uint32_t length,
		      sysparam_compl_t async_complete, void *comp_data)
{
	struct sysparam_req *r;
	uint64_t baddr, tce_token;
	int rc;

	if (!fsp_present())
		return -ENODEV;
	/*
	 * XXX FIXME: We currently always allocate the sysparam_req here
	 * however, we want to avoid runtime allocations as much as
	 * possible, so if this is going to be used a lot at runtime,
	 * we probably want to pre-allocate a pool of these
	 */
	if (length > 4096)
		return -EINVAL;
	r = zalloc(sizeof(struct sysparam_req));
	if (!r)
		return -ENOMEM;
	r->completion = async_complete;
	r->comp_data = comp_data;
	r->done = false;
	r->ubuf = buffer;
	r->ulen = length;
	r->msg.resp = &r->resp;

	/* Map always 1 page ... easier that way and none of that
	 * is performance critical
	 */
	baddr = (uint64_t)buffer;
	fsp_tce_map(PSI_DMA_GET_SYSPARAM, (void *)(baddr & ~0xffful), 0x1000);
	tce_token = PSI_DMA_GET_SYSPARAM | (baddr & 0xfff);
	fsp_fillmsg(&r->msg, FSP_CMD_QUERY_SPARM, 3,
		    param_id, length, tce_token);
	rc = fsp_queue_msg(&r->msg, fsp_sysparam_get_complete);

	if (rc)
		free(r);

	/* Asynchronous operation or queueing failure, return */
	if (rc || async_complete)
		return rc;

	/* Synchronous operation requested, spin and process */
	while(!r->done)
		opal_run_pollers();

	/* Will free the request */
	return fsp_sysparam_process(r);
}

static void fsp_opal_getparam_complete(uint32_t param_id __unused, int err_len,
		void *data)
{
	struct sysparam_comp_data *comp_data = data;
	int rc = OPAL_SUCCESS;

	if (comp_data->param_len != err_len)
		rc = OPAL_INTERNAL_ERROR;

	opal_queue_msg(OPAL_MSG_ASYNC_COMP, NULL, NULL,
			cpu_to_be64(comp_data->async_token),
			cpu_to_be64(rc));
	free(comp_data);
}

static void fsp_opal_setparam_complete(struct fsp_msg *msg)
{
	struct sysparam_comp_data *comp_data = msg->user_data;
	u8 fstat;
	uint32_t param_id;
	int rc = OPAL_SUCCESS;

	if (msg->state != fsp_msg_done) {
		prerror("FSP: Request for set sysparam 0x%x got FSP failure!\n",
				fsp_msg_get_data_word(msg, 0));
		rc = OPAL_INTERNAL_ERROR;
		goto out;
	}

	param_id = fsp_msg_get_data_word(msg->resp, 0);
	if (param_id != fsp_msg_get_data_word(msg, 0)) {
		prerror("FSP: Request for set sysparam 0x%x got resp. for 0x%x!"
				"\n", fsp_msg_get_data_word(msg, 0), param_id);
		rc = OPAL_INTERNAL_ERROR;
		goto out;
	}

	fstat = (msg->resp->word1 >> 8) & 0xff;
	switch (fstat) {
	case 0x00:
		rc = OPAL_SUCCESS;
		break;
	case 0x22:
		prerror("%s: Response status 0x%x, invalid data\n", __func__,
				fstat);
		rc = OPAL_INTERNAL_ERROR;
		break;
	case 0x24:
		prerror("%s: Response status 0x%x, DMA error\n", __func__,
				fstat);
		rc = OPAL_INTERNAL_ERROR;
		break;
	default:
		rc = OPAL_INTERNAL_ERROR;
		break;
	}

out:
	opal_queue_msg(OPAL_MSG_ASYNC_COMP, NULL, NULL,
			cpu_to_be64(comp_data->async_token),
			cpu_to_be64(rc));
	free(comp_data);
	fsp_freemsg(msg);
}

/* OPAL interface for PowerNV to read the system parameter from FSP */
static int64_t fsp_opal_get_param(uint64_t async_token, uint32_t param_id,
				  uint64_t buffer, uint64_t length)
{
	struct sysparam_comp_data *comp_data;
	int count, rc, i;

	if (!fsp_present())
		return OPAL_HARDWARE;

	count = ARRAY_SIZE(sysparam_attrs);
	for (i = 0; i < count; i++)
		if (sysparam_attrs[i].id == param_id)
			break;
	if (i == count)
		return OPAL_PARAMETER;

	if (length < sysparam_attrs[i].length)
		return OPAL_PARAMETER;
	if (!(sysparam_attrs[i].perm & OPAL_SYSPARAM_READ))
		return OPAL_PERMISSION;

	comp_data = zalloc(sizeof(struct sysparam_comp_data));
	if (!comp_data)
		return OPAL_NO_MEM;

	comp_data->param_len = sysparam_attrs[i].length;
	comp_data->async_token = async_token;
	rc = fsp_get_sys_param(param_id, (void *)buffer,
			sysparam_attrs[i].length, fsp_opal_getparam_complete,
			comp_data);
	if (rc) {
		free(comp_data);
		prerror("%s: Error %d queuing param request\n", __func__, rc);
		return OPAL_INTERNAL_ERROR;
	}

	return OPAL_ASYNC_COMPLETION;
}

/* OPAL interface for PowerNV to update the system parameter to FSP */
static int64_t fsp_opal_set_param(uint64_t async_token, uint32_t param_id,
				  uint64_t buffer, uint64_t length)
{
	struct sysparam_comp_data *comp_data;
	struct fsp_msg *msg;
	uint64_t tce_token;
	int count, rc, i;

	if (!fsp_present())
		return OPAL_HARDWARE;

	count = ARRAY_SIZE(sysparam_attrs);
	for (i = 0; i < count; i++)
		if (sysparam_attrs[i].id == param_id)
			break;
	if (i == count)
		return OPAL_PARAMETER;

	if (length < sysparam_attrs[i].length)
		return OPAL_PARAMETER;
	if (!(sysparam_attrs[i].perm & OPAL_SYSPARAM_WRITE))
		return OPAL_PERMISSION;

	fsp_tce_map(PSI_DMA_SET_SYSPARAM, (void *)(buffer & ~0xffful), 0x1000);
	tce_token = PSI_DMA_SET_SYSPARAM | (buffer & 0xfff);

	msg = fsp_mkmsg(FSP_CMD_SET_SPARM_2, 4, param_id, length,
			tce_token >> 32, tce_token);
	if (!msg) {
		prerror("%s: Failed to allocate the message\n", __func__);
		return OPAL_INTERNAL_ERROR;
	}

	comp_data = zalloc(sizeof(struct sysparam_comp_data));
	if (!comp_data) {
		fsp_freemsg(msg);
		return OPAL_NO_MEM;
	}

	comp_data->param_len = length;
	comp_data->async_token = async_token;
	msg->user_data = comp_data;

	rc = fsp_queue_msg(msg, fsp_opal_setparam_complete);
	if (rc) {
		free(comp_data);
		fsp_freemsg(msg);
		prerror("%s: Failed to queue the message\n", __func__);
		return OPAL_INTERNAL_ERROR;
	}

	return OPAL_ASYNC_COMPLETION;
}

struct sysparam_notify_entry {
	struct	list_node	link;
	sysparam_update_notify	notify;
};

static LIST_HEAD(sysparam_update_notifiers);

/* Add client to notifier chain */
void sysparam_add_update_notifier(sysparam_update_notify notify)
{
	struct sysparam_notify_entry *entry;

	entry = zalloc(sizeof(struct sysparam_notify_entry));
	assert(entry);

	entry->notify = notify;
	list_add_tail(&sysparam_update_notifiers, &entry->link);
}

/* Remove client from notifier chain */
void sysparam_del_update_notifier(sysparam_update_notify notify)
{
	struct sysparam_notify_entry *entry;

	list_for_each(&sysparam_update_notifiers, entry, link) {
		if (entry->notify == notify) {
			list_del(&entry->link);
			free(entry);
			return;
		}
	}
}

/* Update notification chain */
static void sysparam_run_update_notifier(struct fsp_msg *msg)
{
	bool ret;
	struct sysparam_notify_entry *entry;

	list_for_each(&sysparam_update_notifiers, entry, link) {
		ret = entry->notify(msg);
		if (ret == true)
			break;
	}
}

static bool fsp_sysparam_msg(u32 cmd_sub_mod, struct fsp_msg *msg)
{
	struct fsp_msg *rsp;
	int rc = -ENOMEM;

	switch(cmd_sub_mod) {
	case FSP_CMD_SP_SPARM_UPD_0:
	case FSP_CMD_SP_SPARM_UPD_1:
		printf("FSP: Got sysparam update, param ID 0x%x\n",
		       fsp_msg_get_data_word(msg, 0));

		sysparam_run_update_notifier(msg);

		rsp = fsp_mkmsg((cmd_sub_mod & 0xffff00) | 0x008000, 0);
		if (rsp)
			rc = fsp_queue_msg(rsp, fsp_freemsg);
		if (rc) {
			prerror("FSP: Error %d queuing sysparam reply\n", rc);
			/* What to do here ? R/R ? */
			fsp_freemsg(rsp);
		}
		return true;
	}
	return false;
}

static struct fsp_client fsp_sysparam_client = {
	.message = fsp_sysparam_msg,
};

static void add_opal_sysparam_node(void)
{
	struct dt_node *sysparams;
	char *names, *s;
	__be32 *ids, *lens;
	uint8_t *perms;
	unsigned int i, count, size = 0;

	if (!fsp_present())
		return;

	sysparams = dt_new(opal_node, "sysparams");
	dt_add_property_string(sysparams, "compatible", "ibm,opal-sysparams");

	count = ARRAY_SIZE(sysparam_attrs);
	for (i = 0; i < count; i++)
		size = size + strlen(sysparam_attrs[i].name) + 1;

	names = zalloc(size);
	if (!names) {
		prerror("%s: Failed to allocate memory for parameter names\n",
				__func__);
		return;
	}

	ids = zalloc(count * sizeof(*ids));
	if (!ids) {
		prerror("%s: Failed to allocate memory for parameter ids\n",
				__func__);
		goto out_free_name;
	}

	lens = zalloc(count * sizeof(*lens));
	if (!lens) {
		prerror("%s: Failed to allocate memory for parameter length\n",
				__func__);
		goto out_free_id;
	}

	perms = zalloc(count * sizeof(*perms));
	if (!perms) {
		prerror("%s: Failed to allocate memory for parameter length\n",
				__func__);
		goto out_free_len;
	}

	s = names;
	for (i = 0; i < count; i++) {
		strcpy(s, sysparam_attrs[i].name);
		s = s + strlen(sysparam_attrs[i].name) + 1;

		ids[i] = cpu_to_be32(sysparam_attrs[i].id);
		lens[i] = cpu_to_be32(sysparam_attrs[i].length);
		perms[i] = sysparam_attrs[i].perm;
	}

	dt_add_property(sysparams, "param-name", names, size);
	dt_add_property(sysparams, "param-id", ids, count * sizeof(*ids));
	dt_add_property(sysparams, "param-len", lens, count * sizeof(*lens));
	dt_add_property(sysparams, "param-perm", perms, count * sizeof(*perms));

	free(perms);

out_free_len:
	free(lens);
out_free_id:
	free(ids);
out_free_name:
	free(names);
}

void fsp_sysparam_init(void)
{
	if (!fsp_present())
		return;

	/* Register change notifications */
	fsp_register_client(&fsp_sysparam_client, FSP_MCLASS_SERVICE);

	/* Register OPAL interfaces */
	opal_register(OPAL_GET_PARAM, fsp_opal_get_param, 4);
	opal_register(OPAL_SET_PARAM, fsp_opal_set_param, 4);

	/* Add device-tree nodes */
	add_opal_sysparam_node();
}
