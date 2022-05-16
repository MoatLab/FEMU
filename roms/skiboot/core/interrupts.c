// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Excuse me, you do work for me now?
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <skiboot.h>
#include <chip.h>
#include <cpu.h>
#include <fsp.h>
#include <interrupts.h>
#include <opal.h>
#include <io.h>
#include <cec.h>
#include <device.h>
#include <ccan/str/str.h>
#include <timer.h>
#include <sbe-p8.h>
#include <sbe-p9.h>

/* ICP registers */
#define ICP_XIRR		0x4	/* 32-bit access */
#define ICP_CPPR		0x4	/* 8-bit access */
#define ICP_MFRR		0xc	/* 8-bit access */

static LIST_HEAD(irq_sources);
static LIST_HEAD(irq_sources2);
static struct lock irq_lock = LOCK_UNLOCKED;

void __register_irq_source(struct irq_source *is, bool secondary)
{
	struct irq_source *is1;
	struct list_head *list = secondary ? &irq_sources2 : &irq_sources;

	prlog(PR_DEBUG, "IRQ: Registering %04x..%04x ops @%p (data %p)%s\n",
	      is->start, is->end - 1, is->ops, is->data,
	      secondary ? " [secondary]" : "");

	lock(&irq_lock);
	list_for_each(list, is1, link) {
		if (is->end > is1->start && is->start < is1->end) {
			prerror("register IRQ source overlap !\n");
			prerror("  new: %x..%x old: %x..%x\n",
				is->start, is->end - 1,
				is1->start, is1->end - 1);
			assert(0);
		}
	}
	list_add_tail(list, &is->link);
	unlock(&irq_lock);
}

void register_irq_source(const struct irq_source_ops *ops, void *data,
			 uint32_t start, uint32_t count)
{
	struct irq_source *is;

	is = zalloc(sizeof(struct irq_source));
	assert(is);
	is->start = start;
	is->end = start + count;
	is->ops = ops;
	is->data = data;

	__register_irq_source(is, false);
}

void unregister_irq_source(uint32_t start, uint32_t count)
{
	struct irq_source *is;

	/* Note: We currently only unregister from the primary sources */
	lock(&irq_lock);
	list_for_each(&irq_sources, is, link) {
		if (start >= is->start && start < is->end) {
			if (start != is->start ||
			    count != (is->end - is->start)) {
				prerror("unregister IRQ source mismatch !\n");
				prerror("start:%x, count: %x match: %x..%x\n",
					start, count, is->start, is->end);
				assert(0);
			}
			list_del(&is->link);
			unlock(&irq_lock);
			/* XXX Add synchronize / RCU */
			free(is);
			return;
		}
	}
	unlock(&irq_lock);
	prerror("unregister IRQ source not found !\n");
	prerror("start:%x, count: %x\n", start, count);
	assert(0);
}

struct irq_source *irq_find_source(uint32_t isn)
{
	struct irq_source *is;

	lock(&irq_lock);
	/*
	 * XXX This really needs some kind of caching !
	 */
	list_for_each(&irq_sources, is, link) {
		if (isn >= is->start && isn < is->end) {
			unlock(&irq_lock);
			return is;
		}
	}
	list_for_each(&irq_sources2, is, link) {
		if (isn >= is->start && isn < is->end) {
			unlock(&irq_lock);
			return is;
		}
	}
	unlock(&irq_lock);

	return NULL;
}

void irq_for_each_source(void (*cb)(struct irq_source *, void *), void *data)
{
	struct irq_source *is;

	lock(&irq_lock);
	list_for_each(&irq_sources, is, link)
		cb(is, data);
	list_for_each(&irq_sources2, is, link)
		cb(is, data);
	unlock(&irq_lock);
}

/*
 * This takes a 6-bit chip id and returns a 20 bit value representing
 * the PSI interrupt. This includes all the fields above, ie, is a
 * global interrupt number.
 *
 * For P8, this returns the base of the 8-interrupts block for PSI
 */
uint32_t get_psi_interrupt(uint32_t chip_id)
{
	uint32_t irq;

	switch(proc_gen) {
	case proc_gen_p8:
		irq = p8_chip_irq_block_base(chip_id, P8_IRQ_BLOCK_MISC);
		irq += P8_IRQ_MISC_PSI_BASE;
		break;
	default:
		assert(false);
	};

	return irq;
}


struct dt_node *add_ics_node(void)
{
	struct dt_node *ics = dt_new_addr(dt_root, "interrupt-controller", 0);
	bool has_xive;

	if (!ics)
		return NULL;

	has_xive = proc_gen >= proc_gen_p9;

	dt_add_property_cells(ics, "reg", 0, 0, 0, 0);
	dt_add_property_strings(ics, "compatible",
				has_xive ? "ibm,opal-xive-vc" : "IBM,ppc-xics",
				"IBM,opal-xics");
	dt_add_property_cells(ics, "#address-cells", 0);
	dt_add_property_cells(ics, "#interrupt-cells", 2);
	dt_add_property_string(ics, "device_type",
			       "PowerPC-Interrupt-Source-Controller");
	dt_add_property(ics, "interrupt-controller", NULL, 0);

	return ics;
}

uint32_t get_ics_phandle(void)
{
	struct dt_node *i;

	for (i = dt_first(dt_root); i; i = dt_next(dt_root, i)) {
		if (streq(i->name, "interrupt-controller@0")) {
			return i->phandle;
		}
	}
	abort();
}

void add_opal_interrupts(void)
{
	struct irq_source *is;
	unsigned int i, ns, tns = 0, count = 0;
	uint32_t isn;
	__be32 *irqs = NULL;
	char *names = NULL;

	lock(&irq_lock);
	list_for_each(&irq_sources, is, link) {
		/*
		 * Don't even consider sources that don't have an interrupts
		 * callback or don't have an attributes one.
		 */
		if (!is->ops->interrupt || !is->ops->attributes)
			continue;
		for (isn = is->start; isn < is->end; isn++) {
			uint64_t attr = is->ops->attributes(is, isn);
			uint32_t iflags;
			char *name;

			if (attr & IRQ_ATTR_TARGET_LINUX)
				continue;
			if (attr & IRQ_ATTR_TYPE_MSI)
				iflags = 0;
			else
				iflags = 1;
			name = is->ops->name ? is->ops->name(is, isn) : NULL;
			ns = name ? strlen(name) : 0;
			prlog(PR_DEBUG, "irq %x name: %s %s\n",
			      isn,
			      name ? name : "<null>",
			      iflags ? "[level]" : "[edge]");
			names = realloc(names, tns + ns + 1);
			if (name) {
				strcpy(names + tns, name);
				tns += (ns + 1);
				free(name);
			} else
				names[tns++] = 0;
			i = count++;
			irqs = realloc(irqs, 8 * count);
			irqs[i*2] = cpu_to_be32(isn);
			irqs[i*2+1] = cpu_to_be32(iflags);
		}
	}
	unlock(&irq_lock);

	/* First create the standard "interrupts" property and the
	 * corresponding names property
	 */
	dt_add_property_cells(opal_node, "interrupt-parent", get_ics_phandle());
	dt_add_property(opal_node, "interrupts", irqs, count * 8);
	dt_add_property(opal_node, "opal-interrupts-names", names, tns);
	dt_add_property(opal_node, "interrupt-names", names, tns);

	/* Now "reduce" it to the old style "opal-interrupts" property
	 * format by stripping out the flags. The "opal-interrupts"
	 * property has one cell per interrupt, it is not a standard
	 * "interrupt" property.
	 *
	 * Note: Even if empty, create it, otherwise some bogus error
	 * handling in Linux can cause problems.
	 */
	for (i = 1; i < count; i++)
		irqs[i] = irqs[i * 2];
	dt_add_property(opal_node, "opal-interrupts", irqs, count * 4);

	free(irqs);
	free(names);
}

/*
 * This is called at init time (and one fast reboot) to sanitize the
 * ICP. We set our priority to 0 to mask all interrupts and make sure
 * no IPI is on the way. This is also called on wakeup from nap
 */
void reset_cpu_icp(void)
{
	void *icp = this_cpu()->icp_regs;

	if (!icp)
		return;

	/* Dummy fetch */
	in_be32(icp + ICP_XIRR);

	/* Clear pending IPIs */
	out_8(icp + ICP_MFRR, 0xff);

	/* Set priority to max, ignore all incoming interrupts, EOI IPIs */
	out_be32(icp + ICP_XIRR, 2);
}

/* Used by the PSI code to send an EOI during reset. This will also
 * set the CPPR to 0 which should already be the case anyway
 */
void icp_send_eoi(uint32_t interrupt)
{
	void *icp = this_cpu()->icp_regs;

	if (!icp)
		return;

	/* Set priority to max, ignore all incoming interrupts */
	out_be32(icp + ICP_XIRR, interrupt & 0xffffff);
}

/* This is called before winkle or nap, we clear pending IPIs and
 * set our priority to 1 to mask all but the IPI.
 */
void icp_prep_for_pm(void)
{
	void *icp = this_cpu()->icp_regs;

	if (!icp)
		return;

	/* Clear pending IPIs */
	out_8(icp + ICP_MFRR, 0xff);

	/* Set priority to 1, ignore all incoming interrupts, EOI IPIs */
	out_be32(icp + ICP_XIRR, 0x01000002);
}

/* This is called to wakeup somebody from winkle */
void icp_kick_cpu(struct cpu_thread *cpu)
{
	void *icp = cpu->icp_regs;

	if (!icp)
		return;

	/* Send high priority IPI */
	out_8(icp + ICP_MFRR, 0);
}

/* Returns the number of chip ID bits used for interrupt numbers */
static uint32_t p8_chip_id_bits(uint32_t chip)
{
	struct proc_chip *proc_chip = get_chip(chip);

	assert(proc_chip);
	switch (proc_chip->type) {
	case PROC_CHIP_P8_MURANO:
	case PROC_CHIP_P8_VENICE:
		return 6;
		break;

	case PROC_CHIP_P8_NAPLES:
		return 5;
		break;

	default:
		/* This shouldn't be called on non-P8 based systems */
		assert(0);
		return 0;
		break;
	}
}

/* The chip id mask is the upper p8_chip_id_bits of the irq number */
static uint32_t chip_id_mask(uint32_t chip)
{
	uint32_t chip_id_bits = p8_chip_id_bits(chip);
	uint32_t chip_id_mask;

	chip_id_mask = ((1 << chip_id_bits) - 1);
	chip_id_mask <<= P8_IRQ_BITS - chip_id_bits;
	return chip_id_mask;
}

/* The block mask is what remains of the 19 bit irq number after
 * removing the upper 5 or 6 bits for the chip# and the lower 11 bits
 * for the number of bits per block. */
static uint32_t block_mask(uint32_t chip)
{
	uint32_t chip_id_bits = p8_chip_id_bits(chip);
	uint32_t irq_block_mask;

	irq_block_mask = P8_IRQ_BITS - chip_id_bits - P8_IVE_BITS;
	irq_block_mask = ((1 << irq_block_mask) - 1) << P8_IVE_BITS;
	return irq_block_mask;
}

uint32_t p8_chip_irq_block_base(uint32_t chip, uint32_t block)
{
	uint32_t irq;

	assert(chip < (1 << p8_chip_id_bits(chip)));
	irq = SETFIELD(chip_id_mask(chip), 0, chip);
	irq = SETFIELD(block_mask(chip), irq, block);

	return irq;
}

uint32_t p8_chip_irq_phb_base(uint32_t chip, uint32_t phb)
{
	assert(chip < (1 << p8_chip_id_bits(chip)));

	return p8_chip_irq_block_base(chip, phb + P8_IRQ_BLOCK_PHB_BASE);
}

uint32_t p8_irq_to_chip(uint32_t irq)
{
	/* This assumes we only have one type of cpu in a system,
	 * which should be ok. */
	return GETFIELD(chip_id_mask(this_cpu()->chip_id), irq);
}

uint32_t p8_irq_to_block(uint32_t irq)
{
	return GETFIELD(block_mask(this_cpu()->chip_id), irq);
}

uint32_t p8_irq_to_phb(uint32_t irq)
{
	return p8_irq_to_block(irq) - P8_IRQ_BLOCK_PHB_BASE;
}

bool __irq_source_eoi(struct irq_source *is, uint32_t isn)
{
	if (!is->ops->eoi)
		return false;

	is->ops->eoi(is, isn);
	return true;
}

bool irq_source_eoi(uint32_t isn)
{
	struct irq_source *is = irq_find_source(isn);

	if (!is)
		return false;

	return __irq_source_eoi(is, isn);
}

static int64_t opal_set_xive(uint32_t isn, uint16_t server, uint8_t priority)
{
	struct irq_source *is = irq_find_source(isn);

	if (!is || !is->ops->set_xive)
		return OPAL_PARAMETER;

	return is->ops->set_xive(is, isn, server, priority);
}
opal_call(OPAL_SET_XIVE, opal_set_xive, 3);

static int64_t opal_get_xive(uint32_t isn, __be16 *server, uint8_t *priority)
{
	struct irq_source *is = irq_find_source(isn);
	uint16_t s;
	int64_t ret;

	if (!opal_addr_valid(server))
		return OPAL_PARAMETER;

	if (!is || !is->ops->get_xive)
		return OPAL_PARAMETER;

	ret = is->ops->get_xive(is, isn, &s, priority);
	*server = cpu_to_be16(s);
	return ret;
}
opal_call(OPAL_GET_XIVE, opal_get_xive, 3);

static int64_t opal_handle_interrupt(uint32_t isn, __be64 *outstanding_event_mask)
{
	struct irq_source *is = irq_find_source(isn);
	int64_t rc = OPAL_SUCCESS;

	if (!opal_addr_valid(outstanding_event_mask))
		return OPAL_PARAMETER;

	/* No source ? return */
	if (!is || !is->ops->interrupt) {
		rc = OPAL_PARAMETER;
		goto bail;
	}

	/* Run it */
	is->ops->interrupt(is, isn);

	/* Check timers if SBE timer isn't working */
	if (!p8_sbe_timer_ok() && !p9_sbe_timer_ok())
		check_timers(true);

	/* Update output events */
 bail:
	if (outstanding_event_mask)
		*outstanding_event_mask = cpu_to_be64(opal_pending_events);

	return rc;
}
opal_call(OPAL_HANDLE_INTERRUPT, opal_handle_interrupt, 2);

void init_interrupts(void)
{
	struct dt_node *icp;
	const struct dt_property *sranges;
	struct cpu_thread *cpu;
	u32 base, count, i;
	u64 addr, size;

	dt_for_each_compatible(dt_root, icp, "ibm,ppc-xicp") {
		sranges = dt_require_property(icp,
					      "ibm,interrupt-server-ranges",
					      -1);
		base = dt_get_number(sranges->prop, 1);
		count = dt_get_number(sranges->prop + 4, 1);
		for (i = 0; i < count; i++) {
			addr = dt_get_address(icp, i, &size);
			cpu = find_cpu_by_server(base + i);
			if (cpu)
				cpu->icp_regs = (void *)addr;
		}
	}
}

