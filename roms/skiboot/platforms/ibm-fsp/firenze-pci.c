// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#define pr_fmt(fmt)  "FIRENZE-PCI: " fmt
#include <skiboot.h>
#include <device.h>
#include <fsp.h>
#include <lock.h>
#include <timer.h>
#include <xscom.h>
#include <pci-cfg.h>
#include <pci.h>
#include <pci-slot.h>
#include <phb3.h>
#include <chip.h>
#include <i2c.h>

#include "ibm-fsp.h"
#include "lxvpd.h"

/* Dump PCI slots before sending to FSP */
#define FIRENZE_PCI_INVENTORY_DUMP

/*
 * Firenze PCI slot states to override the default set.
 * Refer to pci-slot.h for the default PCI state set
 * when you're going to change below values.
 */
#define FIRENZE_PCI_SLOT_NORMAL			PCI_SLOT_STATE_NORMAL
#define FIRENZE_PCI_SLOT_LINK			PCI_SLOT_STATE_LINK
#define   FIRENZE_PCI_SLOT_LINK_START		(FIRENZE_PCI_SLOT_LINK + 1)
#define FIRENZE_PCI_SLOT_HRESET			PCI_SLOT_STATE_HRESET
#define   FIRENZE_PCI_SLOT_HRESET_START		(FIRENZE_PCI_SLOT_HRESET + 1)
#define FIRENZE_PCI_SLOT_FRESET			PCI_SLOT_STATE_FRESET
#define   FIRENZE_PCI_SLOT_FRESET_START		(FIRENZE_PCI_SLOT_FRESET + 1)
#define   FIRENZE_PCI_SLOT_FRESET_WAIT_RSP	(FIRENZE_PCI_SLOT_FRESET + 2)
#define   FIRENZE_PCI_SLOT_FRESET_DELAY		(FIRENZE_PCI_SLOT_FRESET + 3)
#define   FIRENZE_PCI_SLOT_FRESET_POWER_STATE	(FIRENZE_PCI_SLOT_FRESET + 4)
#define   FIRENZE_PCI_SLOT_FRESET_POWER_OFF	(FIRENZE_PCI_SLOT_FRESET + 5)
#define   FIRENZE_PCI_SLOT_FRESET_POWER_ON	(FIRENZE_PCI_SLOT_FRESET + 6)
#define   FIRENZE_PCI_SLOT_PERST_DEASSERT	(FIRENZE_PCI_SLOT_FRESET + 7)
#define   FIRENZE_PCI_SLOT_PERST_DELAY		(FIRENZE_PCI_SLOT_FRESET + 8)
#define FIRENZE_PCI_SLOT_GPOWER			PCI_SLOT_STATE_GPOWER
#define   FIRENZE_PCI_SLOT_GPOWER_START		(FIRENZE_PCI_SLOT_GPOWER + 1)
#define FIRENZE_PCI_SLOT_SPOWER			PCI_SLOT_STATE_SPOWER
#define   FIRENZE_PCI_SLOT_SPOWER_START		(FIRENZE_PCI_SLOT_SPOWER + 1)
#define   FIRENZE_PCI_SLOT_SPOWER_DONE		(FIRENZE_PCI_SLOT_SPOWER + 2)

/* Timeout for power status */
#define FIRENZE_PCI_SLOT_RETRIES	500
#define FIRENZE_PCI_SLOT_DELAY		10	/* ms */
#define FIRENZE_PCI_I2C_TIMEOUT		500	/* ms */

/*
 * Need figure out more stuff later: LED and presence
 * detection sensors are accessed from PSI/FSP.
 */
struct firenze_pci_slot {
	struct lxvpd_pci_slot	lxvpd_slot;	/* LXVPD slot data    */

	/* Next slot state */
	uint32_t		next_state;

	/* Power management */
	struct i2c_bus		*i2c_bus;	/* Where MAX5961 seats   */
	struct i2c_request	*req;		/* I2C request message   */
	uint8_t			i2c_rw_buf[8];	/* I2C read/write buffer */
	uint8_t			power_mask;	/* Bits for power status */
	uint8_t			power_on;	/* Bits for power on     */
	uint8_t			power_off;	/* Bits for power off    */
	uint8_t			*power_status;	/* Last power status     */
	uint16_t		perst_reg;	/* PERST config register */
	uint16_t		perst_bit;	/* PERST bit             */
};

struct firenze_pci_slot_info {
	uint8_t		index;
	const char	*label;
	uint8_t		external_power_mgt;
	uint8_t		inband_perst;
	uint8_t		chip_id;
	uint8_t		master_id;
	uint8_t		port_id;
	uint8_t		slave_addr;
	uint8_t		channel;
	uint8_t		power_status;
	uint8_t		buddy;
};

struct firenze_pci_slot_fixup_info {
	const char	*label;
	uint8_t		reg;
	uint8_t		val;
};

struct firenze_pci_inv {
	__be32		hw_proc_id;
	__be16		slot_idx;
	__be16		reserved;
	__be16		vendor_id;
	__be16		device_id;
	__be16		subsys_vendor_id;
	__be16		subsys_device_id;
} __packed;

struct firenze_pci_inv_data {
	__be32			version;	/* currently 1 */
	__be32			num_entries;
	__be32			entry_size;
	__be32			entry_offset;
	struct firenze_pci_inv	entries[];
} __packed;

/*
 * Note: According to Tuleta system workbook, I didn't figure
 * out the I2C mapping info for slot C14/C15.
 */
static struct firenze_pci_inv_data *firenze_inv_data;
static uint32_t firenze_inv_cnt;
static struct firenze_pci_slot_info firenze_pci_slots[] = {
	{ 0x0B,  "C7", 1, 1,    0, 1, 0, 0x35, 1, 0xAA,  0 },
	{ 0x11, "C14", 0, 1,    0, 0, 0, 0x00, 0, 0xAA,  1 },
	{ 0x0F, "C11", 1, 1,    0, 1, 0, 0x32, 1, 0xAA,  2 },
	{ 0x10, "C12", 1, 1,    0, 1, 0, 0x39, 0, 0xAA,  3 },
	{ 0x0A,  "C6", 1, 1,    0, 1, 0, 0x35, 0, 0xAA,  0 },
	{ 0x12, "C15", 0, 1,    0, 0, 0, 0x00, 0, 0xAA,  5 },
	{ 0x01, "USB", 0, 0,    0, 0, 0, 0x00, 0, 0xAA,  6 },
	{ 0x0C,  "C8", 1, 1,    0, 1, 0, 0x36, 0, 0xAA,  7 },
	{ 0x0D,  "C9", 1, 1,    0, 1, 0, 0x36, 1, 0xAA,  7 },
	{ 0x0E, "C10", 1, 1,    0, 1, 0, 0x32, 0, 0xAA,  2 },
	{ 0x09,  "C5", 1, 1, 0x10, 1, 0, 0x39, 1, 0xAA, 10 },
	{ 0x08,  "C4", 1, 1, 0x10, 1, 0, 0x39, 0, 0xAA, 10 },
	{ 0x07,  "C3", 1, 1, 0x10, 1, 0, 0x3A, 1, 0xAA, 12 },
	{ 0x06,  "C2", 1, 1, 0x10, 1, 0, 0x3A, 0, 0xAA, 12 }
};

/*
 * I2C power controller register fix up table. Not sure what they do, but
 * they seem to relate to the fast-trip setpoint.
 */
static struct firenze_pci_slot_fixup_info firenze_pci_slot_fixup_tbl[] = {
	{ "C3",  0x5e, 0xfb },
	{ "C3",  0x5b, 0xff },
	{ "C5",  0x5e, 0xfb },
	{ "C5",  0x5b, 0xff },
	{ "C6",  0x5e, 0xfa },
	{ "C6",  0x5a, 0xff },
	{ "C6",  0x5b, 0xff },
	{ "C7",  0x5e, 0xfa },
	{ "C7",  0x5a, 0xff },
	{ "C7",  0x5b, 0xff }
};

static void firenze_pci_add_inventory(struct phb *phb,
				      struct pci_device *pd)
{
	struct lxvpd_pci_slot *lxvpd_slot;
	struct firenze_pci_inv *entry;
	struct proc_chip *chip;
	size_t size;
	bool need_init = false;
	u32 num_entries;
	u16 tmp16;

	/*
	 * Do we need to add that to the FSP inventory for power
	 * management?
	 *
	 * For now, we only add devices that:
	 *
	 *  - Are function 0
	 *  - Are not an RC or a downstream bridge
	 *  - Have a direct parent that has a slot entry
	 *  - Slot entry says pluggable
	 *  - Aren't an upstream switch that has slot info
	 */
	if (!pd || !pd->parent)
		return;
	if (pd->bdfn & 7)
		return;
	if (pd->dev_type == PCIE_TYPE_ROOT_PORT ||
	    pd->dev_type == PCIE_TYPE_SWITCH_DNPORT)
		return;
	if (pd->dev_type == PCIE_TYPE_SWITCH_UPPORT &&
	    pd->slot && pd->slot->data)
		return;
	if (!pd->parent->slot ||
	    !pd->parent->slot->data)
		return;
	lxvpd_slot = pd->parent->slot->data;
	if (!lxvpd_slot->pluggable)
		return;

	/* Check if we need to do some (Re)allocation */
	if (!firenze_inv_data ||
            be32_to_cpu(firenze_inv_data->num_entries) == firenze_inv_cnt) {
		need_init = !firenze_inv_data;

		/* (Re)allocate the block to the new size */
		firenze_inv_cnt += 4;
		size = sizeof(struct firenze_pci_inv_data) +
		       sizeof(struct firenze_pci_inv) * firenze_inv_cnt;
                firenze_inv_data = realloc(firenze_inv_data, size);
	}

	/* Initialize the header for a new inventory */
	if (need_init) {
		firenze_inv_data->version = cpu_to_be32(1);
		firenze_inv_data->num_entries = 0;
		firenze_inv_data->entry_size =
			cpu_to_be32(sizeof(struct firenze_pci_inv));
		firenze_inv_data->entry_offset =
			cpu_to_be32(offsetof(struct firenze_pci_inv_data, entries));
	}

	/* Append slot entry */
	num_entries = be32_to_cpu(firenze_inv_data->num_entries);
	firenze_inv_data->num_entries = cpu_to_be32(num_entries + 1);
	entry = &firenze_inv_data->entries[num_entries];
	chip = get_chip(dt_get_chip_id(phb->dt_node));
	if (!chip) {
		/**
		 * @fwts-label FirenzePCIInventory
		 * @fwts-advice Device tree didn't contain enough information
		 * to correctly report back PCI inventory. Service processor
		 * is likely to be missing information about what hardware
		 * is physically present in the machine.
		 */
		prlog(PR_ERR, "No chip device node for PHB%04x\n",
		      phb->opal_id);
                return;
	}

	entry->hw_proc_id = cpu_to_be32(chip->pcid);
	entry->reserved = 0;
	if (pd->parent &&
	    pd->parent->slot &&
	    pd->parent->slot->data) {
		lxvpd_slot = pd->parent->slot->data;
		entry->slot_idx = cpu_to_be16(lxvpd_slot->slot_index);
	}

	pci_cfg_read16(phb, pd->bdfn, PCI_CFG_VENDOR_ID, &tmp16);
	entry->vendor_id = cpu_to_be16(tmp16);
	pci_cfg_read16(phb, pd->bdfn, PCI_CFG_DEVICE_ID, &tmp16);
	entry->device_id = cpu_to_be16(tmp16);
        if (pd->is_bridge) {
                int64_t ssvc = pci_find_cap(phb, pd->bdfn,
					    PCI_CFG_CAP_ID_SUBSYS_VID);
		if (ssvc <= 0) {
			entry->subsys_vendor_id = cpu_to_be16(0xffff);
			entry->subsys_device_id = cpu_to_be16(0xffff);
		} else {
			pci_cfg_read16(phb, pd->bdfn,
				       ssvc + PCICAP_SUBSYS_VID_VENDOR, &tmp16);
			entry->subsys_vendor_id = cpu_to_be16(tmp16);
			pci_cfg_read16(phb, pd->bdfn,
				       ssvc + PCICAP_SUBSYS_VID_DEVICE, &tmp16);
			entry->subsys_device_id = cpu_to_be16(tmp16);
		}
        } else {
		pci_cfg_read16(phb, pd->bdfn, PCI_CFG_SUBSYS_VENDOR_ID, &tmp16);
		entry->subsys_vendor_id = cpu_to_be16(tmp16);
		pci_cfg_read16(phb, pd->bdfn, PCI_CFG_SUBSYS_ID, &tmp16);
		entry->subsys_device_id = cpu_to_be16(tmp16);
	}
}

static void firenze_dump_pci_inventory(void)
{
#ifdef FIRENZE_PCI_INVENTORY_DUMP
	struct firenze_pci_inv *e;
	uint32_t i;

	if (!firenze_inv_data)
		return;

	prlog(PR_INFO, "Dumping Firenze PCI inventory\n");
	prlog(PR_INFO, "HWP SLT VDID DVID SVID SDID\n");
	prlog(PR_INFO, "---------------------------\n");
	for (i = 0; i < be32_to_cpu(firenze_inv_data->num_entries); i++) {
		e = &firenze_inv_data->entries[i];

		prlog(PR_INFO, "%03d %03d %04x %04x %04x %04x\n",
				 be32_to_cpu(e->hw_proc_id),
				 be16_to_cpu(e->slot_idx),
				 be16_to_cpu(e->vendor_id),
				 be16_to_cpu(e->device_id),
				 be16_to_cpu(e->subsys_vendor_id),
				 be16_to_cpu(e->subsys_device_id));
	}
#endif /* FIRENZE_PCI_INVENTORY_DUMP */
}

void firenze_pci_send_inventory(void)
{
	uint64_t base, abase, end, aend, offset;
	int64_t rc;

	if (!firenze_inv_data)
		return;

	/* Dump the inventory */
	prlog(PR_INFO, "Sending %d inventory to FSP\n",
	      be32_to_cpu(firenze_inv_data->num_entries));
	firenze_dump_pci_inventory();

	/* Memory location for inventory */
        base = (uint64_t)firenze_inv_data;
        end = base + sizeof(struct firenze_pci_inv_data) +
			be32_to_cpu(firenze_inv_data->num_entries) *
			be32_to_cpu(firenze_inv_data->entry_size);
	abase = base & ~0xffful;
	aend = (end + 0xffful) & ~0xffful;
	offset = PSI_DMA_PCIE_INVENTORY + (base & 0xfff);

	/* We can only accomodate so many entries in the PSI map */
	if ((aend - abase) > PSI_DMA_PCIE_INVENTORY_SIZE) {
		/**
		 * @fwts-label FirenzePCIInventoryTooLarge
		 * @fwts-advice More PCI inventory than we can send to service
		 * processor. The service processor will have an incomplete
		 * view of the world.
		 */
		prlog(PR_ERR, "Inventory (%lld bytes) too large\n",
		      aend - abase);
		goto bail;
	}

	/* Map this in the TCEs */
	fsp_tce_map(PSI_DMA_PCIE_INVENTORY, (void *)abase, aend - abase);

	/* Send FSP message */
	rc = fsp_sync_msg(fsp_mkmsg(FSP_CMD_PCI_POWER_CONF, 3,
				    hi32(offset), lo32(offset),
				    end - base), true);
	if (rc)
	{
		/**
		 * @fwts-label FirenzePCIInventoryError
		 * @fwts-advice Error communicating with service processor
		 * when sending PCI Inventory.
		 */
		prlog(PR_ERR, "Error %lld sending inventory\n", rc);
	}

	/* Unmap */
	fsp_tce_unmap(PSI_DMA_PCIE_INVENTORY, aend - abase);
bail:
	/*
	 * We free the inventory. We'll have to redo that on hotplug
	 * when we support it but that isn't the case yet
	 */
	free(firenze_inv_data);
	firenze_inv_data = NULL;
	firenze_inv_cnt = 0;
}

/* The function is called when the I2C request is completed
 * successfully, or with errors.
 */
static void firenze_i2c_req_done(int rc, struct i2c_request *req)
{
	struct pci_slot *slot = req->user_data;
	uint32_t state;

	/* Check if there are errors for the completion */
	if (rc) {
		/**
		 * @fwts-label FirenzePCII2CError
		 * @fwts-advice On Firenze platforms, I2C is used to control
		 * power to PCI slots. Errors here mean we may be in trouble
		 * in regards to PCI slot power on/off.
		 */
		prlog(PR_ERR, "Error %d from I2C request on slot %016llx\n",
		      rc, slot->id);
		return;
	}

	/* Check the request type */
	if (req->op != SMBUS_READ && req->op != SMBUS_WRITE) {
		/**
		 * @fwts-label FirenzePCII2CInvalid
		 * @fwts-advice Likely a coding error: invalid I2C request.
		 */
		prlog(PR_ERR, "Invalid I2C request %d on slot %016llx\n",
		      req->op, slot->id);
		return;
	}

	/* After writting power status to I2C slave, we need at least
	 * 5ms delay for the slave to settle down. We also have the
	 * delay after reading the power status as well.
	 */
	switch (slot->state) {
	case FIRENZE_PCI_SLOT_FRESET_WAIT_RSP:
		prlog(PR_DEBUG, "%016llx FRESET: I2C request completed\n",
		      slot->id);
		state = FIRENZE_PCI_SLOT_FRESET_DELAY;
		break;
	case FIRENZE_PCI_SLOT_SPOWER_START:
		prlog(PR_DEBUG, "%016llx SPOWER: I2C request completed\n",
		      slot->id);
		state = FIRENZE_PCI_SLOT_SPOWER_DONE;
		break;
	default:
		/**
		 * @fwts-label FirenzePCISlotI2CStateError
		 * @fwts-advice The Firenze platform uses I2C to control
		 * power to PCI slots. Something went wrong in the state
		 * machine controlling that. Slots may/may not have power.
		 */
		prlog(PR_ERR, "Wrong state %08x on slot %016llx\n",
		      slot->state, slot->id);
		return;
	}

	/* Switch to net state */
	pci_slot_set_state(slot, state);
}

/* This function is called to setup normal PCI device or PHB slot.
 * For the later case, the slot doesn't have the associated PCI
 * device. Besides, the I2C response timeout is set to 5s. We might
 * improve I2C in future to support priorized requests so that the
 * timeout can be shortened.
 */
static int64_t firenze_pci_slot_freset(struct pci_slot *slot)
{
	struct firenze_pci_slot *plat_slot = slot->data;
	uint8_t *pval, presence = 1;
	uint32_t timeout;

	switch (slot->state) {
	case FIRENZE_PCI_SLOT_NORMAL:
	case FIRENZE_PCI_SLOT_FRESET_START:
		prlog(PR_DEBUG, "%016llx FRESET: Starts\n",
		      slot->id);

		/* Bail if nothing is connected */
		if (slot->ops.get_presence_state)
			slot->ops.get_presence_state(slot, &presence);
		if (!presence) {
			prlog(PR_DEBUG, "%016llx FRESET: No device\n",
			      slot->id);
			return OPAL_SUCCESS;
		}

		/* Prepare link down */
		if (slot->ops.prepare_link_change) {
			prlog(PR_DEBUG, "%016llx FRESET: Prepares link down\n",
			      slot->id);
			slot->ops.prepare_link_change(slot, false);
		}

		/* Send I2C request */
		prlog(PR_DEBUG, "%016llx FRESET: Check power state\n",
		      slot->id);
		plat_slot->next_state =
			FIRENZE_PCI_SLOT_FRESET_POWER_STATE;
		plat_slot->req->op = SMBUS_READ;
		slot->retries = FIRENZE_PCI_SLOT_RETRIES;
		pci_slot_set_state(slot,
			FIRENZE_PCI_SLOT_FRESET_WAIT_RSP);
		if (pci_slot_has_flags(slot, PCI_SLOT_FLAG_BOOTUP))
			plat_slot->req->timeout = FIRENZE_PCI_I2C_TIMEOUT;
		else
			plat_slot->req->timeout = 0ul;
		i2c_queue_req(plat_slot->req);
		return pci_slot_set_sm_timeout(slot,
				msecs_to_tb(FIRENZE_PCI_SLOT_DELAY));
	case FIRENZE_PCI_SLOT_FRESET_WAIT_RSP:
		if (slot->retries-- == 0) {
			prlog(PR_DEBUG, "%016llx FRESET: Timeout waiting for %08x\n",
			      slot->id, plat_slot->next_state);
			goto out;
		}

		check_timers(false);
		return pci_slot_set_sm_timeout(slot,
				msecs_to_tb(FIRENZE_PCI_SLOT_DELAY));
	case FIRENZE_PCI_SLOT_FRESET_DELAY:
		prlog(PR_DEBUG, "%016llx FRESET: Delay %dms on I2C completion\n",
		      slot->id, FIRENZE_PCI_SLOT_DELAY);
		pci_slot_set_state(slot, plat_slot->next_state);
		return pci_slot_set_sm_timeout(slot,
				msecs_to_tb(FIRENZE_PCI_SLOT_DELAY));
	case FIRENZE_PCI_SLOT_FRESET_POWER_STATE:
		/* Update last power status */
		pval = (uint8_t *)(plat_slot->req->rw_buf);
		*plat_slot->power_status = *pval;

		/* Power is on, turn it off */
		if (((*pval) & plat_slot->power_mask) == plat_slot->power_on) {
			prlog(PR_DEBUG, "%016llx FRESET: Power (%02x) on, turn off\n",
			      slot->id, *pval);
			(*pval) &= ~plat_slot->power_mask;
			(*pval) |= plat_slot->power_off;
			plat_slot->req->op = SMBUS_WRITE;
			slot->retries = FIRENZE_PCI_SLOT_RETRIES;
			plat_slot->next_state =
				FIRENZE_PCI_SLOT_FRESET_POWER_OFF;
			pci_slot_set_state(slot,
				FIRENZE_PCI_SLOT_FRESET_WAIT_RSP);

			if (pci_slot_has_flags(slot, PCI_SLOT_FLAG_BOOTUP))
				timeout = FIRENZE_PCI_I2C_TIMEOUT;
			else
				timeout = 0ul;
			plat_slot->req->timeout = timeout;

			i2c_queue_req(plat_slot->req);
			return pci_slot_set_sm_timeout(slot,
					msecs_to_tb(FIRENZE_PCI_SLOT_DELAY));
		}

		/* Power is off, turn it on */
		/* Fallthrough */
	case FIRENZE_PCI_SLOT_FRESET_POWER_OFF:
		/* Update last power status */
		pval = (uint8_t *)(plat_slot->req->rw_buf);
		*plat_slot->power_status = *pval;

		prlog(PR_DEBUG, "%016llx FRESET: Power (%02x) off, turn on\n",
		      slot->id, *pval);
		(*pval) &= ~plat_slot->power_mask;
		(*pval) |= plat_slot->power_on;
		plat_slot->req->op = SMBUS_WRITE;
		plat_slot->next_state =
			FIRENZE_PCI_SLOT_FRESET_POWER_ON;
		slot->retries = FIRENZE_PCI_SLOT_RETRIES;
		pci_slot_set_state(slot,
			FIRENZE_PCI_SLOT_FRESET_WAIT_RSP);

		if (pci_slot_has_flags(slot, PCI_SLOT_FLAG_BOOTUP))
			plat_slot->req->timeout = FIRENZE_PCI_I2C_TIMEOUT;
		else
			plat_slot->req->timeout = 0ul;
		i2c_queue_req(plat_slot->req);
		return pci_slot_set_sm_timeout(slot,
				msecs_to_tb(FIRENZE_PCI_SLOT_DELAY));
	case FIRENZE_PCI_SLOT_FRESET_POWER_ON:
		/* Update last power status */
		pval = (uint8_t *)(plat_slot->req->rw_buf);
		*plat_slot->power_status = *pval;

		pci_slot_set_state(slot, FIRENZE_PCI_SLOT_LINK_START);
		return slot->ops.poll_link(slot);
	default:
		prlog(PR_DEBUG, "%016llx FRESET: Unexpected state %08x\n",
		      slot->id, slot->state);
	}

out:
	pci_slot_set_state(slot, FIRENZE_PCI_SLOT_NORMAL);
	return OPAL_HARDWARE;
}

static int64_t firenze_pci_slot_perst(struct pci_slot *slot)
{
	struct firenze_pci_slot *plat_slot = slot->data;
	uint8_t presence = 1;
	uint16_t ctrl;

	switch (slot->state) {
	case FIRENZE_PCI_SLOT_NORMAL:
	case FIRENZE_PCI_SLOT_FRESET_START:
		prlog(PR_DEBUG, "%016llx PERST: Starts\n",
		      slot->id);

		/* Bail if nothing is connected */
		if (slot->ops.get_presence_state)
			slot->ops.get_presence_state(slot, &presence);
		if (!presence) {
			prlog(PR_DEBUG, "%016llx PERST: No device\n",
			      slot->id);
			return OPAL_SUCCESS;
		}

		/* Prepare link down */
		if (slot->ops.prepare_link_change) {
			prlog(PR_DEBUG, "%016llx PERST: Prepare link down\n",
			      slot->id);
			slot->ops.prepare_link_change(slot, false);
		}

		/* Assert PERST */
		prlog(PR_DEBUG, "%016llx PERST: Assert\n",
		      slot->id);
		pci_cfg_read16(slot->phb, slot->pd->bdfn,
			       plat_slot->perst_reg, &ctrl);
		ctrl |= plat_slot->perst_bit;
		pci_cfg_write16(slot->phb, slot->pd->bdfn,
				plat_slot->perst_reg, ctrl);
		pci_slot_set_state(slot,
			FIRENZE_PCI_SLOT_PERST_DEASSERT);
		return pci_slot_set_sm_timeout(slot, msecs_to_tb(250));
	case FIRENZE_PCI_SLOT_PERST_DEASSERT:
		/* Deassert PERST */
		pci_cfg_read16(slot->phb, slot->pd->bdfn,
			       plat_slot->perst_reg, &ctrl);
		ctrl &= ~plat_slot->perst_bit;
		pci_cfg_write16(slot->phb, slot->pd->bdfn,
				plat_slot->perst_reg, ctrl);
		pci_slot_set_state(slot,
			FIRENZE_PCI_SLOT_PERST_DELAY);
		return pci_slot_set_sm_timeout(slot, msecs_to_tb(1500));
	case FIRENZE_PCI_SLOT_PERST_DELAY:
		pci_slot_set_state(slot, FIRENZE_PCI_SLOT_LINK_START);
		return slot->ops.poll_link(slot);
	default:
		prlog(PR_DEBUG, "%016llx PERST: Unexpected state %08x\n",
		      slot->id, slot->state);
	}

	pci_slot_set_state(slot, FIRENZE_PCI_SLOT_NORMAL);
	return OPAL_HARDWARE;
}

static int64_t firenze_pci_slot_get_power_state(struct pci_slot *slot,
						uint8_t *val)
{
	if (slot->state != FIRENZE_PCI_SLOT_NORMAL)
	{
		/**
		 * @fwts-label FirenzePCISlotGPowerState
		 * @fwts-advice Unexpected state in the FIRENZE PCI Slot
		 * state machine. This could mean PCI is not functioning
		 * correctly.
		 */
		prlog(PR_ERR, "%016llx GPOWER: Unexpected state %08x\n",
		      slot->id, slot->state);
	}

	*val = slot->power_state;
	return OPAL_SUCCESS;
}

static int64_t firenze_pci_slot_set_power_state(struct pci_slot *slot,
						uint8_t val)
{
	struct firenze_pci_slot *plat_slot = slot->data;
	uint8_t *pval;

	if (slot->state != FIRENZE_PCI_SLOT_NORMAL)
	{
		/**
		 * @fwts-label FirenzePCISlotSPowerState
		 * @fwts-advice Unexpected state in the FIRENZE PCI Slot
		 * state machine. This could mean PCI is not functioning
		 * correctly.
		 */
		prlog(PR_ERR, "%016llx SPOWER: Unexpected state %08x\n",
		      slot->id, slot->state);
	}

	if (val != PCI_SLOT_POWER_OFF && val != PCI_SLOT_POWER_ON)
		return OPAL_PARAMETER;

	if (!pci_slot_has_flags(slot, PCI_SLOT_FLAG_ENFORCE) &&
	    slot->power_state == val)
		return OPAL_SUCCESS;

	/* Update with the requested power state and bail immediately when
	 * surprise hotplug is supported on the slot. It keeps the power
	 * supply to the slot on and it guarentees the link state change
	 * events will be raised properly during surprise hot add/remove.
	 */
	if (!pci_slot_has_flags(slot, PCI_SLOT_FLAG_ENFORCE) &&
	    slot->surprise_pluggable) {
		slot->power_state = val;
		return OPAL_SUCCESS;
	}

	slot->power_state = val;
	pci_slot_set_state(slot, FIRENZE_PCI_SLOT_SPOWER_START);

	plat_slot->req->op = SMBUS_WRITE;
	pval = (uint8_t *)plat_slot->req->rw_buf;
	if (val == PCI_SLOT_POWER_ON) {
		*pval = *plat_slot->power_status;
		(*pval) &= ~plat_slot->power_mask;
		(*pval) |= plat_slot->power_on;
	} else {
		*pval = *plat_slot->power_status;
		(*pval) &= ~plat_slot->power_mask;
		(*pval) |= plat_slot->power_off;
	}

	if (pci_slot_has_flags(slot, PCI_SLOT_FLAG_BOOTUP))
		plat_slot->req->timeout = FIRENZE_PCI_I2C_TIMEOUT;
	else
		plat_slot->req->timeout = 0ul;
	i2c_queue_req(plat_slot->req);

	return OPAL_ASYNC_COMPLETION;
}

static struct i2c_bus *firenze_pci_find_i2c_bus(uint8_t chip,
						uint8_t eng,
						uint8_t port)
{
	struct dt_node *np, *child;
	uint32_t reg;

	/* Iterate I2C masters */
	dt_for_each_compatible(dt_root, np, "ibm,power8-i2cm") {
		if (!np->parent ||
		    !dt_node_is_compatible(np->parent, "ibm,power8-xscom"))
			continue;

		/* Check chip index */
		reg = dt_prop_get_u32(np->parent, "ibm,chip-id");
		if (reg != chip)
			continue;

		/* Check I2C master index */
		reg = dt_prop_get_u32(np, "chip-engine#");
		if (reg != eng)
			continue;

		/* Iterate I2C buses */
		dt_for_each_child(np, child) {
			if (!dt_node_is_compatible(child, "ibm,power8-i2c-port"))
				continue;

			/* Check I2C port index */
			reg = dt_prop_get_u32(child, "reg");
			if (reg != port)
				continue;

			reg = dt_prop_get_u32(child, "ibm,opal-id");
			return i2c_find_bus_by_id(reg);
		}
	}

	return NULL;
}

static int64_t firenze_pci_slot_fixup_one_reg(struct pci_slot *slot,
			struct firenze_pci_slot_fixup_info *fixup)
{
	struct firenze_pci_slot *plat_slot = slot->data;
	struct i2c_request req;
	uint8_t buf;
	int64_t rc;

	/*
	 * Fill out our own request structure since we don't want to invoke the
	 * normal completion handler.
	 */
	memset(&req, 0, sizeof(req));
	req.dev_addr     = plat_slot->req->dev_addr;
	req.bus	         = plat_slot->req->bus;
	req.offset       = fixup->reg;
	req.offset_bytes = 1;
	req.rw_buf       = &buf;
	req.rw_len       = 1;
	req.timeout      = FIRENZE_PCI_I2C_TIMEOUT;

	req.op = SMBUS_WRITE;
	buf = fixup->val;
	rc = i2c_request_sync(&req);
	if (rc < 0)
		return rc;

	/*
	 * Check the register fixup has been applied. It's not the end of the
	 * world we don't, but eh...
	 */
	req.op = SMBUS_READ;
	rc = i2c_request_sync(&req);
	if (rc == OPAL_SUCCESS && buf != fixup->val) {
		prlog(PR_ERR, "Error verifying fixup [%s] - (%02x, %02x, %02x)\n",
		      fixup->label, fixup->reg, fixup->val, buf);
	}

	return rc;
}

static void firenze_pci_slot_fixup(struct pci_slot *slot,
				   struct firenze_pci_slot_info *info)
{
	int64_t rc, i, applied = 0;
	const uint32_t *p;
	uint64_t id;

	p = dt_prop_get_def(dt_root, "ibm,vpd-lx-info", NULL);
	id = p ? (((uint64_t)p[1] << 32) | p[2]) : 0ul;
	if (id != LX_VPD_2S4U_BACKPLANE &&
	    id != LX_VPD_1S4U_BACKPLANE)
		return;

	for (i = 0; i < ARRAY_SIZE(firenze_pci_slot_fixup_tbl); i++) {
		struct firenze_pci_slot_fixup_info *fixup =
				&firenze_pci_slot_fixup_tbl[i];

		if (strcmp(info->label, fixup->label))
			continue;

		rc = firenze_pci_slot_fixup_one_reg(slot, fixup);
		if (rc) {
			prlog(PR_ERR, "I2C error (%lld) applying fixup [%s] - (%02x, %02x)\n",
			      rc, fixup->label, fixup->reg, fixup->val);
			return;
		}

		applied++;
	}

	if (applied)
		prlog(PR_INFO, "Applied %lld fixups for [%s]\n",
		      applied, info->label);
}

static void firenze_pci_setup_power_mgt(struct pci_slot *slot,
					struct firenze_pci_slot *plat_slot,
					struct firenze_pci_slot_info *info)
{
	plat_slot->i2c_bus = firenze_pci_find_i2c_bus(info->chip_id,
						      info->master_id,
						      info->port_id);
	if (!plat_slot->i2c_bus)
		return;

	plat_slot->req = zalloc(sizeof(*plat_slot->req));
	if (!plat_slot->req)
		return;

	plat_slot->req->dev_addr	= info->slave_addr;
	plat_slot->req->offset_bytes	= 1;
	plat_slot->req->rw_buf		= plat_slot->i2c_rw_buf;
	plat_slot->req->rw_len		= 1;
	plat_slot->req->completion	= firenze_i2c_req_done;
	plat_slot->req->user_data	= slot;
	plat_slot->req->bus		= plat_slot->i2c_bus;

	firenze_pci_slot_fixup(slot, info);

	/*
	 * For all slots, the register used to change the power state is
	 * always 0x69. It could have been set to something else in the
	 * above fixup. Lets fix it to 0x69 here.
	 *
	 * The power states of two slots are controlled by one register.
	 * This means two slots have to share data buffer for power states,
	 * which are tracked by struct firenze_pci_slot_info::power_status.
	 * With it, we can avoid affecting slot#B's power state when trying
	 * to adjust that on slot#A. Also, the initial power states for all
	 * slots are assumed to be PCI_SLOT_POWER_ON.
	 */
	plat_slot->req->offset  = 0x69;
	plat_slot->power_status = &firenze_pci_slots[info->buddy].power_status;
	switch (info->channel) {
	case 0:
		plat_slot->power_mask = 0x33;
		plat_slot->power_on   = 0x22;
		plat_slot->power_off  = 0;
		break;
	case 1:
		plat_slot->power_status = &firenze_pci_slots[info->buddy].power_status;
		plat_slot->power_mask = 0xcc;
		plat_slot->power_on   = 0x88;
		plat_slot->power_off  = 0;
		break;
	default:
		prlog(PR_ERR, "%016llx: Invalid channel %d\n",
		      slot->id, info->channel);
	}
}

static void firenze_pci_slot_init(struct pci_slot *slot)
{
	struct lxvpd_pci_slot *s = slot->data;
	struct firenze_pci_slot *plat_slot = slot->data;
	struct firenze_pci_slot_info *info = NULL;
	uint32_t vdid;
	int i;

	/* Init the slot info from the LXVPD */
	slot->ops.add_properties = lxvpd_add_slot_properties;

	/* Search for power control information in the per-system table */
	for (i = 0; i < ARRAY_SIZE(firenze_pci_slots); i++) {
		if (firenze_pci_slots[i].index == s->slot_index &&
		    !strcmp(firenze_pci_slots[i].label, s->label)) {
			info = &firenze_pci_slots[i];
			break;
		}
	}
	if (!info)
		return;

	/* Search I2C bus for external power mgt */
	if (slot->power_ctl)
		firenze_pci_setup_power_mgt(slot, plat_slot, info);

	/*
	 * If the slot has external power logic, to override the
	 * default power management methods. Because of the bad
	 * I2C design, the API supplied by I2C is really hard to
	 * be utilized. To figure out power status retrival or
	 * configuration after we have a blocking API for that.
	 */
	if (plat_slot->req) {
		slot->ops.freset = firenze_pci_slot_freset;
		slot->ops.get_power_state = firenze_pci_slot_get_power_state;
		slot->ops.set_power_state = firenze_pci_slot_set_power_state;
		prlog(PR_DEBUG, "%016llx: External power mgt initialized\n",
		      slot->id);
	} else if (info->inband_perst) {
		/*
		 * For PLX downstream ports, PCI config register can be
		 * leveraged to do PERST. If the slot doesn't have external
		 * power management stuff, lets try to stick to the PERST
		 * logic if applicable
		 */
		if (slot->pd->dev_type == PCIE_TYPE_SWITCH_DNPORT) {
			pci_cfg_read32(slot->phb, slot->pd->bdfn,
				       PCI_CFG_VENDOR_ID, &vdid);
			switch (vdid) {
			case 0x873210b5:        /* PLX8732 */
			case 0x874810b5:        /* PLX8748 */
				plat_slot->perst_reg = 0x80;
				plat_slot->perst_bit = 0x0400;
				slot->ops.freset = firenze_pci_slot_perst;
				break;
			}
		}
	}
}

void firenze_pci_setup_phb(struct phb *phb, unsigned int index)
{
	uint32_t hub_id;

	/* Grab Hub ID used to parse VPDs */
	hub_id = dt_prop_get_u32_def(phb->dt_node, "ibm,hub-id", 0);

	/* Process the pcie slot entries from the lx vpd lid */
	lxvpd_process_slot_entries(phb, dt_root, hub_id,
				   index, sizeof(struct firenze_pci_slot));
}

void firenze_pci_get_slot_info(struct phb *phb, struct pci_device *pd)
{
	struct pci_slot *slot;
	struct lxvpd_pci_slot *s;

	/* Prepare the PCI inventory */
	firenze_pci_add_inventory(phb, pd);

	if (pd->dev_type != PCIE_TYPE_ROOT_PORT &&
	    pd->dev_type != PCIE_TYPE_SWITCH_UPPORT &&
	    pd->dev_type != PCIE_TYPE_SWITCH_DNPORT &&
	    pd->dev_type != PCIE_TYPE_PCIE_TO_PCIX)
		return;

	/* Create PCIe slot */
	slot = pcie_slot_create(phb, pd);
	if (!slot)
		return;

	/* Root complex inherits methods from PHB slot */
	if (!pd->parent && phb->slot)
		memcpy(&slot->ops, &phb->slot->ops, sizeof(struct pci_slot_ops));

	/* Patch PCIe slot */
	s = lxvpd_get_slot(slot);
	if (s) {
		lxvpd_extract_info(slot, s);
		firenze_pci_slot_init(slot);
	}
}

void firenze_pci_add_loc_code(struct dt_node *np, struct pci_device *pd)
{
	struct dt_node *p;
	const char *blcode = NULL;
	char *lcode;
	uint32_t class_code;
	uint8_t class,sub;
	uint8_t pos, len;


	/*
	 * prefer fully-qualified slot-location-code, walk-up parent tree
	 * to find one
	 */
	for (p = np->parent; p; p = p->parent) {
		blcode = dt_prop_get_def(p, "ibm,slot-location-code", NULL);
		if (blcode)
			break;
	}

	/* try the node itself if none is found */
	if (!blcode)
		blcode = dt_prop_get_def(np, "ibm,slot-location-code", NULL);

	if (!blcode) {
		/* still not found, fall back to ibm,loc-code */

		for (p = np->parent; p; p = p->parent) {
			blcode = dt_prop_get_def(p, "ibm,loc-code", NULL);
			if (blcode)
				break;
		}
	}

	if (!blcode) {
		prlog(PR_ERR,
			"No suitable location code to add for device PHB#%04x:%02x:%02x.%x\n",
			pd->phb->opal_id, PCI_BUS_NUM(pd->bdfn),
			PCI_DEV(pd->bdfn), PCI_FUNC(pd->bdfn));
		return;
	}

	/* ethernet devices get port codes */
	class_code = dt_prop_get_u32(np, "class-code");
	class = class_code >> 16;
	sub = (class_code >> 8) & 0xff;

	if (class == 0x02 && sub == 0x00) {
		/* There's usually several spaces at the end of the property.
		   Test for, but don't rely on, that being the case */
		len = strlen(blcode);
		for (pos = 0; pos < len; pos++)
			if (blcode[pos] == ' ') break;
		if (pos + 3 < len)
			lcode = strdup(blcode);
		else {
			lcode = malloc(pos + 3);
			memcpy(lcode, blcode, len);
		}
		lcode[pos++] = '-';
		lcode[pos++] = 'T';
		lcode[pos++] = (char)PCI_FUNC(pd->bdfn) + '1';
		lcode[pos++] = '\0';
		dt_add_property_string(np, "ibm,loc-code", lcode);
		free(lcode);
	} else {
		dt_add_property_string(np, "ibm,loc-code", blcode);
	}
}
