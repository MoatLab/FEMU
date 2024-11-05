// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#define pr_fmt(fmt) "LXVPD: " fmt

#include <skiboot.h>
#include <device.h>
#include <vpd.h>
#include <pci.h>
#include <pci-cfg.h>
#include <pci-slot.h>

#include "lxvpd.h"

/*
 * Currently, the lxvpd PCI slot struct is shared by multiple
 * platforms (Apollo and Firenze), but each slot still has
 * platform specific features. In order for unified data structs,
 * "struct lxvpd_slot" is expected to be embedded in platform
 * PCI slot struct. "entry_size" indicates the size of platform
 * specific PCI slot instance.
 */
struct lxvpd_pci_slot_data {
	uint8_t		num_slots;
	int32_t		entry_size;	/* Size of platform PCI slot  */
	void		*slots;		/* Data of platform PCI slots */
};

static bool lxvpd_supported_slot(struct phb *phb, struct pci_device *pd)
{
	/* PHB should always be valid */
	if (!phb)
		return false;

	/* We expect platform slot for root complex */
	if (!pd)
		return true;

	/* We support the root complex at the top level */
	if (pd->dev_type == PCIE_TYPE_ROOT_PORT && !pd->parent)
		return true;

	/* We support an upstream switch port below the root complex */
	if (pd->dev_type == PCIE_TYPE_SWITCH_UPPORT &&
	    pd->parent && pd->parent->dev_type == PCIE_TYPE_ROOT_PORT &&
	    !pd->parent->parent)
		return true;

	/* We support a downstream switch port below an upstream port
	 * below the root complex
	 */
	if (pd->dev_type == PCIE_TYPE_SWITCH_DNPORT &&
	    pd->parent && pd->parent->dev_type == PCIE_TYPE_SWITCH_UPPORT &&
	    pd->parent->parent &&
	    pd->parent->parent->dev_type == PCIE_TYPE_ROOT_PORT &&
	    !pd->parent->parent->parent)
		return true;

	/* Anything else, bail */
	return false;
}

void *lxvpd_get_slot(struct pci_slot *slot)
{
	struct phb *phb = slot->phb;
	struct pci_device *pd = slot->pd;
	struct lxvpd_pci_slot_data *sdata = phb->platform_data;
	struct lxvpd_pci_slot *s = NULL;
	uint8_t slot_num = pd ? PCI_DEV(pd->bdfn) : 0xff;
	bool is_phb = (pd && pd->parent) ? false : true;
	uint8_t index;

	/* Check if we have slot info */
	if (!sdata) {
		prlog(PR_DEBUG, "PHB%04x not have VPD data\n",
			  phb->opal_id);
		return NULL;
	}

	/* Platform slot attached ? */
	s = slot->data;
	if (s) {
		prlog(PR_DEBUG, "Slot %016llx had platform data [%s]\n",
			  slot->id, s->label);
		return s;
	}

	/*
	 * This code only handles PHBs and PCIe switches at the
	 * top level. We do not handle any other switch nor any
	 * other type of PCI/PCI-X bridge. Generally, we have
	 * more strict rules to support slot than PCI core.
	 */
	if (!lxvpd_supported_slot(phb, pd)) {
		prlog(PR_DEBUG, "Slot %016llx not supported\n",
			  slot->id);
		return NULL;
	}

	/* Iterate the platform slot array */
	for (index = 0; index < sdata->num_slots; index++) {
		s = sdata->slots + (index * sdata->entry_size);

		/* Match PHB with switch_id == 0 */
		if (is_phb && s->switch_id == 0) {
			slot->data = s;
			s->pci_slot = slot;
			prlog(PR_DEBUG, "Found [%s] for PHB slot %016llx\n",
				  s->label, slot->id);

			return s;
		}

		/* Match downstream switch port with switch_id != 0 */
		if (!is_phb && s->switch_id != 0 && !s->upstream_port &&
		    s->dev_id == slot_num) {
			slot->data = s;
			s->pci_slot = slot;
			prlog(PR_DEBUG, "Found [%s] for slot %016llx\n",
				  s->label, slot->id);

			return s;
		}
	}

	prlog(PR_DEBUG, "No data found for %sslot %016llx\n",
		  is_phb ? "PHB " : " ", slot->id);
	return NULL;
}

void lxvpd_extract_info(struct pci_slot *slot, struct lxvpd_pci_slot *s)
{
	slot->pluggable      = s->pluggable ? 1 : 0;
	slot->power_ctl      = s->power_ctl ? 1 : 0;
	slot->power_led_ctl  = s->pwr_led_ctl;
	slot->attn_led_ctl   = s->attn_led_ctl;
	slot->connector_type = s->connector_type;
	slot->card_desc      = s->card_desc;
	slot->card_mech      = s->card_mech;
	slot->wired_lanes    = s->wired_lanes;

	prlog(PR_DEBUG, "[%s]: pluggable: %d power_ctrl: %d\n",
		s->label, (int) s->pluggable, (int) s->power_ctl);
}

static struct lxvpd_pci_slot_data *lxvpd_alloc_slots(struct phb *phb,
						     uint8_t count,
						     uint32_t slot_size)
{
	struct lxvpd_pci_slot_data *sdata;

	sdata = zalloc(sizeof(struct lxvpd_pci_slot_data) + count * slot_size);
	assert(sdata);
	sdata->num_slots   = count;
	sdata->entry_size  = slot_size;
	sdata->slots       = sdata + 1;
	phb->platform_data = sdata;

	return sdata;
}

static void lxvpd_format_label(char *dst, const char *src, size_t len)
{
	int i;

	memcpy(dst, src, len);

	/* Remove blank suffix */
	for (i = strlen(dst) - 1; i >= 0; i--) {
		if (dst[i] != ' ')
			break;

		dst[i] = 0;
	}
}

static void lxvpd_parse_1004_map(struct phb *phb,
				 const uint8_t *sm,
				 uint8_t size,
				 uint32_t slot_size)
{
	struct lxvpd_pci_slot_data *sdata;
	struct lxvpd_pci_slot *s;
	const struct pci_slot_entry_1004 *entry;
	uint8_t num_slots, slot;

	num_slots = (size / sizeof(struct pci_slot_entry_1004));
	sdata = lxvpd_alloc_slots(phb, num_slots, slot_size);

	/* Iterate through the entries in the keyword */
	entry = (const struct pci_slot_entry_1004 *)sm;
	for (slot = 0; slot < num_slots; slot++, entry++) {
		s = sdata->slots + slot * sdata->entry_size;

		/* Figure out PCI slot info */
		lxvpd_format_label(s->label, entry->label, 3);
		s->slot_index     = entry->slot_index;
		s->switch_id      = entry->pba >> 4;
		s->vswitch_id     = entry->pba & 0xf;
		s->dev_id         = entry->sba;
		s->pluggable      = ((entry->p0.byte & 0x20) == 0);
		s->power_ctl      = !!(entry->p0.byte & 0x40);
		s->bus_clock      = entry->p2.bus_clock - 4;
		s->connector_type = entry->p2.connector_type - 5;
		s->card_desc      = entry->p3.byte >> 6;
		if (entry->p3.byte < 0xc0)
			s->card_desc -= 4;
		s->card_mech      = (entry->p3.byte >> 4) & 0x3;
		s->pwr_led_ctl    = (entry->p3.byte & 0xf) >> 2;
		s->attn_led_ctl   = entry->p3.byte & 0x3;

		switch(entry->p1.wired_lanes) {
		case 1: s->wired_lanes = PCI_SLOT_WIRED_LANES_PCIX_32;  break;
		case 2: /* fall through */
		case 3: s->wired_lanes = PCI_SLOT_WIRED_LANES_PCIX_64;  break;
		case 4: s->wired_lanes = PCI_SLOT_WIRED_LANES_PCIE_X1;  break;
		case 5: s->wired_lanes = PCI_SLOT_WIRED_LANES_PCIE_X4;  break;
		case 6: s->wired_lanes = PCI_SLOT_WIRED_LANES_PCIE_X8;  break;
		case 7: s->wired_lanes = PCI_SLOT_WIRED_LANES_PCIE_X16; break;
		default:
			s->wired_lanes = PCI_SLOT_WIRED_LANES_UNKNOWN;
		}

		prlog(PR_DEBUG, "1004 Platform data [%s] %02x %02x on PHB%04x\n",
			  s->label, s->switch_id, s->dev_id, phb->opal_id);
	}
}

static void lxvpd_parse_1005_map(struct phb *phb,
				 const uint8_t *sm,
				 uint8_t size,
				 uint32_t slot_size)
{
	struct lxvpd_pci_slot_data *sdata;
	struct lxvpd_pci_slot *s;
	const struct pci_slot_entry_1005 *entry;
	uint8_t num_slots, slot;

	num_slots = (size / sizeof(struct pci_slot_entry_1005));
	sdata = lxvpd_alloc_slots(phb, num_slots, slot_size);

	/* Iterate through the entries in the keyword */
	entry = (const struct pci_slot_entry_1005 *)sm;
	for (slot = 0; slot < num_slots; slot++, entry++) {
		s = sdata->slots + slot * sdata->entry_size;

		/* Put slot info into pci device structure */
		lxvpd_format_label(s->label, entry->label, 8);
		s->slot_index     = entry->slot_index;
		s->switch_id      = entry->pba >> 4;
		s->vswitch_id     = entry->pba & 0xf;
		s->dev_id         = entry->switch_device_id;
		s->pluggable      = (entry->p0.pluggable == 0);
		s->power_ctl      = entry->p0.power_ctl;
		s->upstream_port  = entry->p0.upstream_port;
		s->bus_clock      = entry->p2.bus_clock;
		s->connector_type = entry->p2.connector_type;
		s->card_desc      = entry->p3.byte >> 6;
		s->card_mech      = (entry->p3.byte >> 4) & 0x3;
		s->pwr_led_ctl    = (entry->p3.byte & 0xf) >> 2;
		s->attn_led_ctl   = entry->p3.byte & 0x3;
		s->wired_lanes    = entry->p1.wired_lanes;
		if (s->wired_lanes > PCI_SLOT_WIRED_LANES_PCIE_X32)
			s->wired_lanes = PCI_SLOT_WIRED_LANES_UNKNOWN;

		prlog(PR_DEBUG, "1005 Platform data [%s] %02x %02x %s on PHB%04x\n",
			  s->label, s->switch_id, s->dev_id,
			  s->upstream_port ? "upstream" : "downstream",
			  phb->opal_id);
	}
}

void lxvpd_process_slot_entries(struct phb *phb,
				struct dt_node *node,
				uint8_t chip_id,
				uint8_t index,
				uint32_t slot_size)
{
	const void *lxvpd;
	const uint8_t *pr_rec, *pr_end, *sm;
	size_t lxvpd_size, pr_size;
	const beint16_t *mf = NULL;
	char record[5] = "PR00";
	uint8_t mf_sz, sm_sz;
	bool found = false;

	record[2] += chip_id;
	record[3] += index;
	record[4] = 0;

	/* Get LX VPD pointer */
	lxvpd = dt_prop_get_def_size(node, "ibm,io-vpd", NULL, &lxvpd_size);
	if (!lxvpd) {
		prlog(PR_WARNING, "No data found for PHB%04x %s\n",
			   phb->opal_id, record);
		return;
	}

	pr_rec = vpd_find_record(lxvpd, lxvpd_size, record, &pr_size);
	if (!pr_rec) {
		prlog(PR_WARNING, "Record %s not found on PHB%04x\n",
			   record, phb->opal_id);
		return;
	}

	/* As long as there's still something in the PRxy record */
	prlog(PR_DEBUG, "PHB%04x record %s has %ld bytes\n",
		  phb->opal_id, record, pr_size);
	pr_end = pr_rec + pr_size;
	while (pr_rec < pr_end) {
		pr_size = pr_end - pr_rec;

		/* Find the next MF keyword */
		mf = vpd_find_keyword(pr_rec, pr_size, "MF", &mf_sz);
		/* And the corresponding SM */
		sm = vpd_find_keyword(pr_rec, pr_size, "SM", &sm_sz);
		if (!mf || !sm) {
			if (!found)
				prlog(PR_WARNING, "Slot Map keyword %s not found\n",
					   record);
			return;
		}

		prlog(PR_DEBUG, "Found 0x%04x map...\n", be16_to_cpu(*mf));
		switch (be16_to_cpu(*mf)) {
		case 0x1004:
			lxvpd_parse_1004_map(phb, sm + 1, sm_sz - 1, slot_size);
			found = true;
			break;
		case 0x1005:
			lxvpd_parse_1005_map(phb, sm + 1, sm_sz - 1, slot_size);
			found = true;
			break;
			/* Add support for 0x1006 maps ... */
		}

		pr_rec = sm + sm_sz;
	}
}

void lxvpd_add_slot_properties(struct pci_slot *slot,
			       struct dt_node *np)
{
	struct phb *phb = slot->phb;
	struct lxvpd_pci_slot *s = slot->data;
	char loc_code[LOC_CODE_SIZE];
	size_t base_loc_code_len, slot_label_len;

	/* Check if we have platform specific slot */
	if (!s || !np)
		return;

	/* Check PHB base location code */
	if (!phb->base_loc_code)
		return;

	/* Check location length is valid */
	base_loc_code_len = strlen(phb->base_loc_code);
	slot_label_len = strlen(s->label);
	if ((base_loc_code_len + slot_label_len + 1) >= LOC_CODE_SIZE)
		return;

	/* Location code */
	strcpy(loc_code, phb->base_loc_code);
	strcat(loc_code, "-");
	strcat(loc_code, s->label);
	dt_add_property(np, "ibm,slot-location-code",
			loc_code, strlen(loc_code) + 1);
	dt_add_property_string(np, "ibm,slot-label",
			       s->label);
}
