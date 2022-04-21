// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * PCIe OPAL Calls
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <skiboot.h>
#include <opal-api.h>
#include <pci.h>
#include <pci-cfg.h>
#include <pci-slot.h>
#include <opal-msg.h>
#include <timebase.h>
#include <timer.h>

#define OPAL_PCICFG_ACCESS_READ(op, cb, type)	\
static int64_t opal_pci_config_##op(uint64_t phb_id,			\
				    uint64_t bus_dev_func,		\
				    uint64_t offset, type data)		\
{									\
	struct phb *phb = pci_get_phb(phb_id);				\
	int64_t rc;							\
									\
	if (!opal_addr_valid((void *)data))				\
		return OPAL_PARAMETER;					\
									\
	if (!phb)							\
		return OPAL_PARAMETER;					\
	phb_lock(phb);							\
	rc = phb->ops->cfg_##cb(phb, bus_dev_func, offset, data);	\
	phb_unlock(phb);						\
									\
	return rc;							\
}

#define OPAL_PCICFG_ACCESS_WRITE(op, cb, type)	\
static int64_t opal_pci_config_##op(uint64_t phb_id,			\
				    uint64_t bus_dev_func,		\
				    uint64_t offset, type data)		\
{									\
	struct phb *phb = pci_get_phb(phb_id);				\
	int64_t rc;							\
									\
	if (!phb)							\
		return OPAL_PARAMETER;					\
	phb_lock(phb);						\
	rc = phb->ops->cfg_##cb(phb, bus_dev_func, offset, data);	\
	phb_unlock(phb);						\
									\
	return rc;							\
}

OPAL_PCICFG_ACCESS_READ(read_byte,		read8, uint8_t *)
OPAL_PCICFG_ACCESS_READ(read_half_word,		read16, uint16_t *)
OPAL_PCICFG_ACCESS_READ(read_word,		read32, uint32_t *)
OPAL_PCICFG_ACCESS_WRITE(write_byte,		write8, uint8_t)
OPAL_PCICFG_ACCESS_WRITE(write_half_word,	write16, uint16_t)
OPAL_PCICFG_ACCESS_WRITE(write_word,		write32, uint32_t)

static int64_t opal_pci_config_read_half_word_be(uint64_t phb_id,
						 uint64_t bus_dev_func,
						 uint64_t offset,
						 __be16 *__data)
{
	uint16_t data;
	int64_t rc;

	rc = opal_pci_config_read_half_word(phb_id, bus_dev_func, offset, &data);
	*__data = cpu_to_be16(data);

	return rc;
}

static int64_t opal_pci_config_read_word_be(uint64_t phb_id,
						 uint64_t bus_dev_func,
						 uint64_t offset,
						 __be32 *__data)
{
	uint32_t data;
	int64_t rc;

	rc = opal_pci_config_read_word(phb_id, bus_dev_func, offset, &data);
	*__data = cpu_to_be32(data);

	return rc;
}


opal_call(OPAL_PCI_CONFIG_READ_BYTE, opal_pci_config_read_byte, 4);
opal_call(OPAL_PCI_CONFIG_READ_HALF_WORD, opal_pci_config_read_half_word_be, 4);
opal_call(OPAL_PCI_CONFIG_READ_WORD, opal_pci_config_read_word_be, 4);
opal_call(OPAL_PCI_CONFIG_WRITE_BYTE, opal_pci_config_write_byte, 4);
opal_call(OPAL_PCI_CONFIG_WRITE_HALF_WORD, opal_pci_config_write_half_word, 4);
opal_call(OPAL_PCI_CONFIG_WRITE_WORD, opal_pci_config_write_word, 4);

static struct lock opal_eeh_evt_lock = LOCK_UNLOCKED;
static uint64_t opal_eeh_evt = 0;

void opal_pci_eeh_set_evt(uint64_t phb_id)
{
	lock(&opal_eeh_evt_lock);
	opal_eeh_evt |= 1ULL << phb_id;
	opal_update_pending_evt(OPAL_EVENT_PCI_ERROR, OPAL_EVENT_PCI_ERROR);
	unlock(&opal_eeh_evt_lock);
}

void opal_pci_eeh_clear_evt(uint64_t phb_id)
{
	lock(&opal_eeh_evt_lock);
	opal_eeh_evt &= ~(1ULL << phb_id);
	if (!opal_eeh_evt)
		opal_update_pending_evt(OPAL_EVENT_PCI_ERROR, 0);
	unlock(&opal_eeh_evt_lock);
}

static int64_t opal_pci_eeh_freeze_status(uint64_t phb_id, uint64_t pe_number,
					  uint8_t *freeze_state,
					  __be16 *__pci_error_type,
					  __be64 *__phb_status)
{
	struct phb *phb = pci_get_phb(phb_id);
	uint16_t pci_error_type;
	int64_t rc;

	if (!opal_addr_valid(freeze_state) || !opal_addr_valid(__pci_error_type)
		|| !opal_addr_valid(__phb_status))
		return OPAL_PARAMETER;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->eeh_freeze_status)
		return OPAL_UNSUPPORTED;
	phb_lock(phb);

	if (__phb_status)
		prlog(PR_ERR, "PHB#%04llx: %s: deprecated PHB status\n",
				phb_id, __func__);

	rc = phb->ops->eeh_freeze_status(phb, pe_number, freeze_state,
					 &pci_error_type, NULL);
	*__pci_error_type = cpu_to_be16(pci_error_type);
	phb_unlock(phb);

	return rc;
}
opal_call(OPAL_PCI_EEH_FREEZE_STATUS, opal_pci_eeh_freeze_status, 5);

static int64_t opal_pci_eeh_freeze_clear(uint64_t phb_id, uint64_t pe_number,
					 uint64_t eeh_action_token)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->eeh_freeze_clear)
		return OPAL_UNSUPPORTED;
	phb_lock(phb);
	rc = phb->ops->eeh_freeze_clear(phb, pe_number, eeh_action_token);
	phb_unlock(phb);

	return rc;
}
opal_call(OPAL_PCI_EEH_FREEZE_CLEAR, opal_pci_eeh_freeze_clear, 3);

static int64_t opal_pci_eeh_freeze_set(uint64_t phb_id, uint64_t pe_number,
				       uint64_t eeh_action_token)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->eeh_freeze_set)
		return OPAL_UNSUPPORTED;
	phb_lock(phb);
	rc = phb->ops->eeh_freeze_set(phb, pe_number, eeh_action_token);
	phb_unlock(phb);

	return rc;
}
opal_call(OPAL_PCI_EEH_FREEZE_SET, opal_pci_eeh_freeze_set, 3);

static int64_t opal_pci_err_inject(uint64_t phb_id, uint64_t pe_number,
				   uint32_t type, uint32_t func,
				   uint64_t addr, uint64_t mask)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops || !phb->ops->err_inject)
		return OPAL_UNSUPPORTED;

	if (type != OPAL_ERR_INJECT_TYPE_IOA_BUS_ERR &&
	    type != OPAL_ERR_INJECT_TYPE_IOA_BUS_ERR64)
		return OPAL_PARAMETER;

	phb_lock(phb);
	rc = phb->ops->err_inject(phb, pe_number, type, func, addr, mask);
	phb_unlock(phb);

	return rc;
}
opal_call(OPAL_PCI_ERR_INJECT, opal_pci_err_inject, 6);

static int64_t opal_pci_phb_mmio_enable(uint64_t phb_id, uint16_t window_type,
					uint16_t window_num, uint16_t enable)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->phb_mmio_enable)
		return OPAL_UNSUPPORTED;
	phb_lock(phb);
	rc = phb->ops->phb_mmio_enable(phb, window_type, window_num, enable);
	phb_unlock(phb);

	return rc;
}
opal_call(OPAL_PCI_PHB_MMIO_ENABLE, opal_pci_phb_mmio_enable, 4);

static int64_t opal_pci_set_phb_mem_window(uint64_t phb_id,
					   uint16_t window_type,
					   uint16_t window_num,
					   uint64_t addr,
					   uint64_t pci_addr,
					   uint64_t size)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->set_phb_mem_window)
		return OPAL_UNSUPPORTED;
	phb_lock(phb);
	rc = phb->ops->set_phb_mem_window(phb, window_type, window_num,
					  addr, pci_addr, size);
	phb_unlock(phb);

	return rc;
}
opal_call(OPAL_PCI_SET_PHB_MEM_WINDOW, opal_pci_set_phb_mem_window, 6);

static int64_t opal_pci_map_pe_mmio_window(uint64_t phb_id, uint64_t pe_number,
					   uint16_t window_type,
					   uint16_t window_num,
					   uint16_t segment_num)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->map_pe_mmio_window)
		return OPAL_UNSUPPORTED;
	phb_lock(phb);
	rc = phb->ops->map_pe_mmio_window(phb, pe_number, window_type,
					  window_num, segment_num);
	phb_unlock(phb);

	return rc;
}
opal_call(OPAL_PCI_MAP_PE_MMIO_WINDOW, opal_pci_map_pe_mmio_window, 5);

static int64_t opal_pci_set_pe(uint64_t phb_id, uint64_t pe_number,
			       uint64_t bus_dev_func, uint8_t bus_compare,
			       uint8_t dev_compare, uint8_t func_compare,
			       uint8_t pe_action)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->set_pe)
		return OPAL_UNSUPPORTED;
	phb_lock(phb);
	rc = phb->ops->set_pe(phb, pe_number, bus_dev_func, bus_compare,
			      dev_compare, func_compare, pe_action);
	phb_unlock(phb);

	return rc;
}
opal_call(OPAL_PCI_SET_PE, opal_pci_set_pe, 7);

static int64_t opal_pci_set_peltv(uint64_t phb_id, uint32_t parent_pe,
				  uint32_t child_pe, uint8_t state)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->set_peltv)
		return OPAL_UNSUPPORTED;
	phb_lock(phb);
	rc = phb->ops->set_peltv(phb, parent_pe, child_pe, state);
	phb_unlock(phb);

	return rc;
}
opal_call(OPAL_PCI_SET_PELTV, opal_pci_set_peltv, 4);

static int64_t opal_pci_set_mve(uint64_t phb_id, uint32_t mve_number,
				uint64_t pe_number)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->set_mve)
		return OPAL_UNSUPPORTED;
	phb_lock(phb);
	rc = phb->ops->set_mve(phb, mve_number, pe_number);
	phb_unlock(phb);

	return rc;
}
opal_call(OPAL_PCI_SET_MVE, opal_pci_set_mve, 3);

static int64_t opal_pci_set_mve_enable(uint64_t phb_id, uint32_t mve_number,
				       uint32_t state)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->set_mve_enable)
		return OPAL_UNSUPPORTED;
	phb_lock(phb);
	rc = phb->ops->set_mve_enable(phb, mve_number, state);
	phb_unlock(phb);

	return rc;
}
opal_call(OPAL_PCI_SET_MVE_ENABLE, opal_pci_set_mve_enable, 3);

static int64_t opal_pci_msi_eoi(uint64_t phb_id,
				uint32_t hwirq)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->pci_msi_eoi)
		return OPAL_UNSUPPORTED;
	phb_lock(phb);
	rc = phb->ops->pci_msi_eoi(phb, hwirq);
	phb_unlock(phb);

	return rc;
}
opal_call(OPAL_PCI_MSI_EOI, opal_pci_msi_eoi, 2);

static int64_t opal_pci_tce_kill(uint64_t phb_id,
				 uint32_t kill_type,
				 uint64_t pe_number, uint32_t tce_size,
				 uint64_t dma_addr, uint32_t npages)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->tce_kill)
		return OPAL_UNSUPPORTED;
	phb_lock(phb);
	rc = phb->ops->tce_kill(phb, kill_type, pe_number, tce_size,
				dma_addr, npages);
	phb_unlock(phb);

	return rc;
}
opal_call(OPAL_PCI_TCE_KILL, opal_pci_tce_kill, 6);

static int64_t opal_pci_set_xive_pe(uint64_t phb_id, uint64_t pe_number,
				    uint32_t xive_num)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->set_xive_pe)
		return OPAL_UNSUPPORTED;
	phb_lock(phb);
	rc = phb->ops->set_xive_pe(phb, pe_number, xive_num);
	phb_unlock(phb);

	return rc;
}
opal_call(OPAL_PCI_SET_XIVE_PE, opal_pci_set_xive_pe, 3);

static int64_t opal_get_msi_32(uint64_t phb_id, uint32_t mve_number,
			       uint32_t xive_num, uint8_t msi_range,
			       __be32 *__msi_address, __be32 *__message_data)
{
	struct phb *phb = pci_get_phb(phb_id);
	uint32_t msi_address;
	uint32_t message_data;
	int64_t rc;

	if (!opal_addr_valid(__msi_address) || !opal_addr_valid(__message_data))
		return OPAL_PARAMETER;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->get_msi_32)
		return OPAL_UNSUPPORTED;
	phb_lock(phb);
	rc = phb->ops->get_msi_32(phb, mve_number, xive_num, msi_range,
				  &msi_address, &message_data);
	phb_unlock(phb);

	*__msi_address = cpu_to_be32(msi_address);
	*__message_data = cpu_to_be32(message_data);

	return rc;
}
opal_call(OPAL_GET_MSI_32, opal_get_msi_32, 6);

static int64_t opal_get_msi_64(uint64_t phb_id, uint32_t mve_number,
			       uint32_t xive_num, uint8_t msi_range,
			       __be64 *__msi_address, __be32 *__message_data)
{
	struct phb *phb = pci_get_phb(phb_id);
	uint64_t msi_address;
	uint32_t message_data;
	int64_t rc;

	if (!opal_addr_valid(__msi_address) || !opal_addr_valid(__message_data))
		return OPAL_PARAMETER;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->get_msi_64)
		return OPAL_UNSUPPORTED;
	phb_lock(phb);
	rc = phb->ops->get_msi_64(phb, mve_number, xive_num, msi_range,
				  &msi_address, &message_data);
	phb_unlock(phb);

	*__msi_address = cpu_to_be64(msi_address);
	*__message_data = cpu_to_be32(message_data);

	return rc;
}
opal_call(OPAL_GET_MSI_64, opal_get_msi_64, 6);

static int64_t opal_pci_map_pe_dma_window(uint64_t phb_id, uint64_t pe_number,
					  uint16_t window_id,
					  uint16_t tce_levels,
					  uint64_t tce_table_addr,
					  uint64_t tce_table_size,
					  uint64_t tce_page_size)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->map_pe_dma_window)
		return OPAL_UNSUPPORTED;
	phb_lock(phb);
	rc = phb->ops->map_pe_dma_window(phb, pe_number, window_id,
					 tce_levels, tce_table_addr,
					 tce_table_size, tce_page_size);
	phb_unlock(phb);

	return rc;
}
opal_call(OPAL_PCI_MAP_PE_DMA_WINDOW, opal_pci_map_pe_dma_window, 7);

static int64_t opal_pci_map_pe_dma_window_real(uint64_t phb_id,
					       uint64_t pe_number,
					       uint16_t window_id,
					       uint64_t pci_start_addr,
					       uint64_t pci_mem_size)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->map_pe_dma_window_real)
		return OPAL_UNSUPPORTED;
	phb_lock(phb);
	rc = phb->ops->map_pe_dma_window_real(phb, pe_number, window_id,
					      pci_start_addr, pci_mem_size);
	phb_unlock(phb);

	return rc;
}
opal_call(OPAL_PCI_MAP_PE_DMA_WINDOW_REAL, opal_pci_map_pe_dma_window_real, 5);

static int64_t opal_phb_set_option(uint64_t phb_id, uint64_t opt,
				   uint64_t setting)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;

	if (!phb->ops->set_option)
		return OPAL_UNSUPPORTED;

	phb_lock(phb);
	rc = phb->ops->set_option(phb, opt, setting);
	phb_unlock(phb);

	return rc;
}
opal_call(OPAL_PHB_SET_OPTION, opal_phb_set_option, 3);

static int64_t opal_phb_get_option(uint64_t phb_id, uint64_t opt,
				   __be64 *setting)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb || !setting)
		return OPAL_PARAMETER;

	if (!phb->ops->get_option)
		return OPAL_UNSUPPORTED;

	phb_lock(phb);
	rc = phb->ops->get_option(phb, opt, setting);
	phb_unlock(phb);

	return rc;
}
opal_call(OPAL_PHB_GET_OPTION, opal_phb_get_option, 3);

static int64_t opal_pci_reset(uint64_t id, uint8_t reset_scope,
                              uint8_t assert_state)
{
	struct pci_slot *slot = pci_slot_find(id);
	struct phb *phb = slot ? slot->phb : NULL;
	int64_t rc = OPAL_SUCCESS;

	if (!slot || !phb)
		return OPAL_PARAMETER;
	if (assert_state != OPAL_ASSERT_RESET &&
	    assert_state != OPAL_DEASSERT_RESET)
		return OPAL_PARAMETER;

	phb_lock(phb);

	switch(reset_scope) {
	case OPAL_RESET_PHB_COMPLETE:
		/* Complete reset is applicable to PHB slot only */
		if (!slot->ops.creset || slot->pd) {
			rc = OPAL_UNSUPPORTED;
			break;
		}

		if (assert_state != OPAL_ASSERT_RESET)
			break;

		rc = slot->ops.creset(slot);
		if (rc < 0)
			prlog(PR_ERR, "SLOT-%016llx: Error %lld on complete reset\n",
			      slot->id, rc);
		break;
	case OPAL_RESET_PCI_FUNDAMENTAL:
		if (!slot->ops.freset) {
			rc = OPAL_UNSUPPORTED;
			break;
		}

		/* We need do nothing on deassert time */
		if (assert_state != OPAL_ASSERT_RESET)
			break;

		rc = slot->ops.freset(slot);
		if (rc < 0)
			prlog(PR_ERR, "SLOT-%016llx: Error %lld on fundamental reset\n",
			      slot->id, rc);
		break;
	case OPAL_RESET_PCI_HOT:
		if (!slot->ops.hreset) {
			rc = OPAL_UNSUPPORTED;
			break;
		}

		/* We need do nothing on deassert time */
		if (assert_state != OPAL_ASSERT_RESET)
			break;

		rc = slot->ops.hreset(slot);
		if (rc < 0)
			prlog(PR_ERR, "SLOT-%016llx: Error %lld on hot reset\n",
			      slot->id, rc);
		break;
	case OPAL_RESET_PCI_IODA_TABLE:
		/* It's allowed on PHB slot only */
		if (slot->pd || !phb->ops || !phb->ops->ioda_reset) {
			rc = OPAL_UNSUPPORTED;
			break;
		}

		if (assert_state != OPAL_ASSERT_RESET)
			break;

		rc = phb->ops->ioda_reset(phb, true);
		break;
	case OPAL_RESET_PHB_ERROR:
		/* It's allowed on PHB slot only */
		if (slot->pd || !phb->ops || !phb->ops->papr_errinjct_reset) {
			rc = OPAL_UNSUPPORTED;
			break;
		}

		if (assert_state != OPAL_ASSERT_RESET)
			break;

		rc = phb->ops->papr_errinjct_reset(phb);
		break;
	default:
		rc = OPAL_UNSUPPORTED;
	}
	phb_unlock(phb);

	return (rc > 0) ? tb_to_msecs(rc) : rc;
}
opal_call(OPAL_PCI_RESET, opal_pci_reset, 3);

static int64_t opal_pci_reinit(uint64_t phb_id,
			       uint64_t reinit_scope,
			       uint64_t data)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops || !phb->ops->pci_reinit)
		return OPAL_UNSUPPORTED;

	phb_lock(phb);
	rc = phb->ops->pci_reinit(phb, reinit_scope, data);
	phb_unlock(phb);

	return rc;
}
opal_call(OPAL_PCI_REINIT, opal_pci_reinit, 3);

static int64_t opal_pci_poll(uint64_t id)
{
	struct pci_slot *slot = pci_slot_find(id);
	struct phb *phb = slot ? slot->phb : NULL;
	int64_t rc;

	if (!slot || !phb)
		return OPAL_PARAMETER;
	if (!slot->ops.run_sm)
		return OPAL_UNSUPPORTED;

	phb_lock(phb);
	rc = slot->ops.run_sm(slot);
	phb_unlock(phb);

	/* Return milliseconds for caller to sleep: round up */
	if (rc > 0) {
		rc = tb_to_msecs(rc);
		if (rc == 0)
			rc = 1;
	}

	return rc;
}
opal_call(OPAL_PCI_POLL, opal_pci_poll, 1);

static int64_t opal_pci_get_presence_state(uint64_t id, uint64_t data)
{
	struct pci_slot *slot = pci_slot_find(id);
	struct phb *phb = slot ? slot->phb : NULL;
	uint8_t *presence = (uint8_t *)data;
	int64_t rc;

	if (!opal_addr_valid(presence))
		return OPAL_PARAMETER;

	if (!slot || !phb)
		return OPAL_PARAMETER;
	if (!slot->ops.get_presence_state)
		return OPAL_UNSUPPORTED;

	phb_lock(phb);
	rc = slot->ops.get_presence_state(slot, presence);
	phb_unlock(phb);

	return rc;
}
opal_call(OPAL_PCI_GET_PRESENCE_STATE, opal_pci_get_presence_state, 2);

static int64_t opal_pci_get_power_state(uint64_t id, uint64_t data)
{
	struct pci_slot *slot = pci_slot_find(id);
	struct phb *phb = slot ? slot->phb : NULL;
	uint8_t *power_state = (uint8_t *)data;
	int64_t rc;

	if (!opal_addr_valid(power_state))
		return OPAL_PARAMETER;

	if (!slot || !phb)
		return OPAL_PARAMETER;
	if (!slot->ops.get_power_state)
		return OPAL_UNSUPPORTED;

	phb_lock(phb);
	rc = slot->ops.get_power_state(slot, power_state);
	phb_unlock(phb);

	return rc;
}
opal_call(OPAL_PCI_GET_POWER_STATE, opal_pci_get_power_state, 2);

static u32 get_slot_phandle(struct pci_slot *slot)
{
	struct phb *phb = slot->phb;
	struct pci_device *pd = slot->pd;

	if (pd)
		return pd->dn->phandle;
	else
		return phb->dt_node->phandle;
}

static void rescan_slot_devices(struct pci_slot *slot)
{
	struct phb *phb = slot->phb;
	struct pci_device *pd = slot->pd;

	/*
	 * prepare_link_change() is called (if needed) by the state
	 * machine during the slot reset or link polling
	 */
	if (phb->phb_type != phb_type_npu_v2_opencapi) {
		pci_scan_bus(phb, pd->secondary_bus,
			     pd->subordinate_bus, &pd->children, pd, true);
		pci_add_device_nodes(phb, &pd->children, pd->dn,
				     &phb->lstate, 0);
	} else {
		pci_scan_bus(phb, 0, 0xff, &phb->devices, NULL, true);
		pci_add_device_nodes(phb, &phb->devices,
				     phb->dt_node, &phb->lstate, 0);
		phb->ops->phb_final_fixup(phb);
	}
}

static void remove_slot_devices(struct pci_slot *slot)
{
	struct phb *phb = slot->phb;
	struct pci_device *pd = slot->pd;

	if (phb->phb_type != phb_type_npu_v2_opencapi)
		pci_remove_bus(phb, &pd->children);
	else
		pci_remove_bus(phb, &phb->devices);
}

static void link_up_timer(struct timer *t, void *data,
			  uint64_t now __unused)
{
	struct pci_slot *slot = data;
	struct phb *phb = slot->phb;
	uint8_t link;
	int64_t rc = 0;

	if (!phb_try_lock(phb)) {
		schedule_timer(&slot->timer, msecs_to_tb(10));
		return;
	}

	rc = slot->ops.run_sm(slot);
	if (rc < 0)
		goto out;
	if (rc > 0) {
		schedule_timer(t, rc);
		phb_unlock(phb);
		return;
	}

	if (slot->ops.get_link_state(slot, &link) != OPAL_SUCCESS)
		link = 0;
	if (!link) {
		rc = OPAL_HARDWARE;
		goto out;
	}

	rescan_slot_devices(slot);
out:
	opal_queue_msg(OPAL_MSG_ASYNC_COMP, NULL, NULL,
		       cpu_to_be64(slot->async_token),
		       cpu_to_be64(get_slot_phandle(slot)),
		       cpu_to_be64(slot->power_state),
		       rc <= 0 ? cpu_to_be64(rc) : cpu_to_be64(OPAL_BUSY));
	phb_unlock(phb);
}

static bool training_needed(struct pci_slot *slot)
{
	struct phb *phb = slot->phb;
	struct pci_device *pd = slot->pd;

	/* only for opencapi slots for now */
	if (!pd && phb->phb_type == phb_type_npu_v2_opencapi)
		return true;
	return false;
}

static void wait_for_link_up_and_rescan(struct pci_slot *slot)
{
	int64_t rc = 1;

	/*
	 * Links for PHB slots need to be retrained by triggering a
	 * fundamental reset. Other slots also need to be tested for
	 * readiness
	 */
	if (training_needed(slot)) {
		pci_slot_set_state(slot, PCI_SLOT_STATE_NORMAL);
		rc = slot->ops.freset(slot);
		if (rc < 0) {
			opal_queue_msg(OPAL_MSG_ASYNC_COMP, NULL, NULL,
				       cpu_to_be64(slot->async_token),
				       cpu_to_be64(get_slot_phandle(slot)),
				       cpu_to_be64(slot->power_state),
				       cpu_to_be64(rc))
			return;
		}
	} else {
		pci_slot_set_state(slot, PCI_SLOT_STATE_LINK_START_POLL);
		rc = msecs_to_tb(20);
	}
	init_timer(&slot->timer, link_up_timer, slot);
	schedule_timer(&slot->timer, rc);
}

static void set_power_timer(struct timer *t __unused, void *data,
			    uint64_t now __unused)
{
	struct pci_slot *slot = data;
	struct phb *phb = slot->phb;

	if (!phb_try_lock(phb)) {
		schedule_timer(&slot->timer, msecs_to_tb(10));
		return;
	}

	switch (slot->state) {
	case PCI_SLOT_STATE_SPOWER_START:
		if (slot->retries-- == 0) {
			pci_slot_set_state(slot, PCI_SLOT_STATE_NORMAL);
			opal_queue_msg(OPAL_MSG_ASYNC_COMP, NULL, NULL,
				       cpu_to_be64(slot->async_token),
				       cpu_to_be64(get_slot_phandle(slot)),
				       cpu_to_be64(slot->power_state),
				       cpu_to_be64(OPAL_BUSY));
		} else {
			schedule_timer(&slot->timer, msecs_to_tb(10));
		}

		break;
	case PCI_SLOT_STATE_SPOWER_DONE:
		if (slot->power_state == OPAL_PCI_SLOT_POWER_OFF) {
			remove_slot_devices(slot);
			pci_slot_set_state(slot, PCI_SLOT_STATE_NORMAL);
			opal_queue_msg(OPAL_MSG_ASYNC_COMP, NULL, NULL,
				       cpu_to_be64(slot->async_token),
				       cpu_to_be64(get_slot_phandle(slot)),
				       cpu_to_be64(OPAL_PCI_SLOT_POWER_OFF),
				       cpu_to_be64(OPAL_SUCCESS));
			break;
		}

		/* Power on */
		wait_for_link_up_and_rescan(slot);
		break;
	default:
		prlog(PR_ERR, "PCI SLOT %016llx: Unexpected state 0x%08x\n",
		      slot->id, slot->state);
	}
	phb_unlock(phb);
}

static int64_t opal_pci_set_power_state(uint64_t async_token,
					uint64_t id,
					uint64_t data)
{
	struct pci_slot *slot = pci_slot_find(id);
	struct phb *phb = slot ? slot->phb : NULL;
	struct pci_device *pd = slot ? slot->pd : NULL;
	uint8_t *state = (uint8_t *)data;
	int64_t rc;

	if (!slot || !phb)
		return OPAL_PARAMETER;

	if (!opal_addr_valid(state))
		return OPAL_PARAMETER;

	phb_lock(phb);
	switch (*state) {
	case OPAL_PCI_SLOT_POWER_OFF:
		if (!slot->ops.prepare_link_change ||
		    !slot->ops.set_power_state) {
			phb_unlock(phb);
			return OPAL_UNSUPPORTED;
		}

		slot->async_token = async_token;
		slot->ops.prepare_link_change(slot, false);
		rc = slot->ops.set_power_state(slot, PCI_SLOT_POWER_OFF);
		break;
	case OPAL_PCI_SLOT_POWER_ON:
		if (!slot->ops.set_power_state ||
		    !slot->ops.get_link_state) {
			phb_unlock(phb);
			return OPAL_UNSUPPORTED;
		}

		slot->async_token = async_token;
		rc = slot->ops.set_power_state(slot, PCI_SLOT_POWER_ON);
		break;
	case OPAL_PCI_SLOT_OFFLINE:
		if (!pd) {
			phb_unlock(phb);
			return OPAL_PARAMETER;
		}

		pci_remove_bus(phb, &pd->children);
		phb_unlock(phb);
		return OPAL_SUCCESS;
	case OPAL_PCI_SLOT_ONLINE:
		if (!pd) {
			phb_unlock(phb);
			return OPAL_PARAMETER;
		}
		pci_scan_bus(phb, pd->secondary_bus, pd->subordinate_bus,
			     &pd->children, pd, true);
		pci_add_device_nodes(phb, &pd->children, pd->dn,
				     &phb->lstate, 0);
		phb_unlock(phb);
		return OPAL_SUCCESS;
	default:
		rc = OPAL_PARAMETER;
	}

	/*
	 * OPAL_ASYNC_COMPLETION is returned when delay is needed to change
	 * the power state in the backend. When it can be finished without
	 * delay, OPAL_SUCCESS is returned. The PCI topology needs to be
	 * updated in both cases.
	 */
	if (rc == OPAL_ASYNC_COMPLETION) {
		slot->retries = 500;
		init_timer(&slot->timer, set_power_timer, slot);
		schedule_timer(&slot->timer, msecs_to_tb(10));
	} else if (rc == OPAL_SUCCESS) {
		if (*state == OPAL_PCI_SLOT_POWER_OFF) {
			remove_slot_devices(slot);
		} else {
			wait_for_link_up_and_rescan(slot);
			rc = OPAL_ASYNC_COMPLETION;
		}
	}

	phb_unlock(phb);
	return rc;
}
opal_call(OPAL_PCI_SET_POWER_STATE, opal_pci_set_power_state, 3);

static int64_t opal_pci_get_phb_diag_data2(uint64_t phb_id,
					   void *diag_buffer,
					   uint64_t diag_buffer_len)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!opal_addr_valid(diag_buffer))
		return OPAL_PARAMETER;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->get_diag_data2)
		return OPAL_UNSUPPORTED;
	phb_lock(phb);
	rc = phb->ops->get_diag_data2(phb, diag_buffer, diag_buffer_len);
	phb_unlock(phb);

	return rc;
}
opal_call(OPAL_PCI_GET_PHB_DIAG_DATA2, opal_pci_get_phb_diag_data2, 3);

static int64_t opal_pci_next_error(uint64_t phb_id, __be64 *__first_frozen_pe,
				   __be16 *__pci_error_type, __be16 *__severity)
{
	struct phb *phb = pci_get_phb(phb_id);
	uint64_t first_frozen_pe;
	uint16_t pci_error_type;
	uint16_t severity;
	int64_t rc;

	if (!opal_addr_valid(__first_frozen_pe) ||
		!opal_addr_valid(__pci_error_type) || !opal_addr_valid(__severity))
		return OPAL_PARAMETER;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->next_error)
		return OPAL_UNSUPPORTED;
	phb_lock(phb);

	opal_pci_eeh_clear_evt(phb_id);
	rc = phb->ops->next_error(phb, &first_frozen_pe, &pci_error_type,
				  &severity);
	phb_unlock(phb);

	*__first_frozen_pe = cpu_to_be64(first_frozen_pe);
	*__pci_error_type = cpu_to_be16(pci_error_type);
	*__severity = cpu_to_be16(severity);

	return rc;
}
opal_call(OPAL_PCI_NEXT_ERROR, opal_pci_next_error, 4);

static int64_t opal_pci_set_phb_capi_mode(uint64_t phb_id, uint64_t mode, uint64_t pe_number)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->set_capi_mode)
		return OPAL_UNSUPPORTED;

	phb_lock(phb);
	rc = phb->ops->set_capi_mode(phb, mode, pe_number);
	phb_unlock(phb);
	return rc;
}
opal_call(OPAL_PCI_SET_PHB_CAPI_MODE, opal_pci_set_phb_capi_mode, 3);

static int64_t opal_pci_set_p2p(uint64_t phbid_init, uint64_t phbid_target,
				uint64_t desc, uint16_t pe_number)
{
	struct phb *phb_init = pci_get_phb(phbid_init);
	struct phb *phb_target = pci_get_phb(phbid_target);

	if (!phb_init || !phb_target)
		return OPAL_PARAMETER;
	/*
	 * Having the 2 devices under the same PHB may require tuning
	 * the configuration of intermediate switch(es), more easily
	 * done from linux. And it shouldn't require a PHB config
	 * change.
	 * Return an error for the time being.
	 */
	if (phb_init == phb_target)
		return OPAL_UNSUPPORTED;
	if (!phb_init->ops->set_p2p || !phb_target->ops->set_p2p)
		return OPAL_UNSUPPORTED;
	/*
	 * Loads would be supported on p9 if the 2 devices are under
	 * the same PHB, but we ruled it out above.
	 */
	if (desc & OPAL_PCI_P2P_LOAD)
		return OPAL_UNSUPPORTED;

	phb_lock(phb_init);
	phb_init->ops->set_p2p(phb_init, OPAL_PCI_P2P_INITIATOR, desc,
			pe_number);
	phb_unlock(phb_init);

	phb_lock(phb_target);
	phb_target->ops->set_p2p(phb_target, OPAL_PCI_P2P_TARGET, desc,
				pe_number);
	phb_unlock(phb_target);
	return OPAL_SUCCESS;
}
opal_call(OPAL_PCI_SET_P2P, opal_pci_set_p2p, 4);

static int64_t opal_pci_get_pbcq_tunnel_bar(uint64_t phb_id, __be64 *__addr)
{
	struct phb *phb = pci_get_phb(phb_id);
	uint64_t addr;

	if (!opal_addr_valid(__addr))
		return OPAL_PARAMETER;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->get_tunnel_bar)
		return OPAL_UNSUPPORTED;

	phb_lock(phb);
	phb->ops->get_tunnel_bar(phb, &addr);
	phb_unlock(phb);

	*__addr = cpu_to_be64(addr);

	return OPAL_SUCCESS;
}
opal_call(OPAL_PCI_GET_PBCQ_TUNNEL_BAR, opal_pci_get_pbcq_tunnel_bar, 2);

static int64_t opal_pci_set_pbcq_tunnel_bar(uint64_t phb_id, uint64_t addr)
{
	struct phb *phb = pci_get_phb(phb_id);
	int64_t rc;

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->set_tunnel_bar)
		return OPAL_UNSUPPORTED;

	phb_lock(phb);
	rc = phb->ops->set_tunnel_bar(phb, addr);
	phb_unlock(phb);
	return rc;
}
opal_call(OPAL_PCI_SET_PBCQ_TUNNEL_BAR, opal_pci_set_pbcq_tunnel_bar, 2);
