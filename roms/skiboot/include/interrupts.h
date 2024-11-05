// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __INTERRUPTS_H
#define __INTERRUPTS_H

#include <stdint.h>
#include <ccan/list/list.h>

/* Note about interrupt numbers on P8
 * ==================================
 *
 * On P8 the interrupts numbers are just a flat space of 19-bit,
 * there is no BUID or similar.
 *
 * However, various unit tend to require blocks of interrupt that
 * are naturally power-of-two aligned
 *
 * Our P8 Interrupt map consits thus of dividing the chip space
 * into "blocks" of 2048 interrupts. Block 0 is for random chip
 * interrupt sources (NX, PSI, OCC, ...) and keeps sources 0..15
 * clear to avoid conflits with IPIs etc.... Block 1..n are assigned
 * to PHB 0..n respectively. The number of blocks is determined by the
 * number of bits assigned to chips.
 *
 * That gives us an interrupt number made of:
 *  18               n+1 n   11  10                         0
 *  |                  | |    | |                           |
 * +--------------------+------+-----------------------------+
 * |        Chip#       | PHB# |             IVE#            |
 * +--------------------+------+-----------------------------+
 *
 * Where n = 18 - p8_chip_id_bits
 *
 * For P8 we have 6 bits for Chip# as defined by p8_chip_id_bits. We
 * therefore support a max of 2^6 = 64 chips.
 *
 * For P8NVL we have an extra PHB and so we assign 5 bits for Chip#
 * and therefore support a max of 32 chips.
 *
 * Each PHB supports 2K interrupt sources, which is shared by
 * LSI and MSI. With default configuration, MSI would use range
 * [0, 0x7f7] and LSI would use [0x7f8, 0x7ff]. The interrupt
 * source should be combined with IRSN to form final hardware
 * IRQ.
 *
 */

uint32_t p8_chip_irq_block_base(uint32_t chip, uint32_t block);
uint32_t p8_chip_irq_phb_base(uint32_t chip, uint32_t phb);
uint32_t p8_irq_to_chip(uint32_t irq);
uint32_t p8_irq_to_block(uint32_t irq);
uint32_t p8_irq_to_phb(uint32_t irq);

/* Total number of bits in the P8 interrupt space */
#define P8_IRQ_BITS		19

/* Number of bits per block */
#define P8_IVE_BITS		11

#define P8_IRQ_BLOCK_MISC	0
#define P8_IRQ_BLOCK_PHB_BASE	1

/* Assignment of the "MISC" block:
 * -------------------------------
 *
 * PSI interface has 6 interrupt sources:
 *
 * FSP, OCC, FSI, LPC, Local error, Host error
 *
 * and thus needs a block of 8
 */
#define P8_IRQ_MISC_PSI_BASE		0x10	/* 0x10..0x17 */

/* These are handled by skiboot */
#define P8_IRQ_PSI_FSP			0
#define P8_IRQ_PSI_OCC			1
#define P8_IRQ_PSI_FSI			2
#define P8_IRQ_PSI_LPC			3
#define P8_IRQ_PSI_LOCAL_ERR		4
#define P8_IRQ_PSI_EXTERNAL		5	/* Used for UART */
#define P8_IRQ_PSI_IRQ_COUNT		6

/* TBD: NX, AS, ...
 */

/* Note about interrupt numbers on P9
 * ==================================
 *
 * P9 uses a completely different interrupt controller, XIVE.
 *
 * It targets objects using a combination of block number and
 * index within a block. However, we try to avoid exposing that
 * split to the OS in order to keep some abstraction in case the
 * way we allocate these change.
 *
 * The lowest level entity in Xive is the ESB (state bits).
 *
 * Those are spread between PHBs, PSI bridge and XIVE itself which
 * provide a large amount of state bits for IPIs and other SW and HW
 * generated interrupts by sources that don't have their own ESB logic
 *
 * Due to that spread, they aren't a good representation of a global
 * interrupt number.
 *
 * Each such source however needs to be targetted at an EAS (IVT)
 * entry in a table which will control targetting information and
 * associate that interrupt with a logical number.
 *
 * Thus that table entry number represents a good "global interrupt
 * number". Additionally, for the host OS, we will keep the logical
 * number equal to the global number.
 *
 * The details of how these are assigned on P9 can be found in
 * hw/xive.c. P9 HW will only use a subset of the definitions and
 * functions in this file (or the corresponding core/interrupts.c).
 */

struct irq_source;

/*
 * IRQ sources register themselves here.
 *
 * The "attributes" callback provides various attributes specific to
 * a given interrupt, such as whether it's targetted at OPAL or the
 * OS, or whether it's frequent or infrequent. The latter will be used
 * later to optimize the lookup of the sources array by providing a small
 * cache of the frequent interrupts.
 *
 * The "eoi" callback is used for XIVE interrupts in XICS emulation
 * though we might expose it at some point in XIVE native mode for
 * interrupts that require special EOI operations such as possibly
 * the LPC interrupts on P9 that need a latch cleared in the LPCHC.
 *
 * The "name" callback returns a name for the interrupt in a new
 * malloc()'ed block. The caller will free() it. NULL is acceptable.
 */
struct irq_source_ops {
	int64_t (*set_xive)(struct irq_source *is, uint32_t isn,
			    uint16_t server, uint8_t priority);
	int64_t (*get_xive)(struct irq_source *is, uint32_t isn,
			    uint16_t *server, uint8_t *priority);
	uint64_t (*attributes)(struct irq_source *is, uint32_t isn);
/* LSB is the target */
#define IRQ_ATTR_TARGET_OPAL		0x0
#define IRQ_ATTR_TARGET_LINUX		0x1
/* For OPAL interrupts, estimate frequency */
#define IRQ_ATTR_TARGET_RARE		0x0
#define IRQ_ATTR_TARGET_FREQUENT	0x2
/* For OPAL interrupts, level vs. edge setting */
#define IRQ_ATTR_TYPE_LSI		0x0
#define IRQ_ATTR_TYPE_MSI		0x4
	void (*interrupt)(struct irq_source *is, uint32_t isn);
	void (*eoi)(struct irq_source *is, uint32_t isn);
	char *(*name)(struct irq_source *is, uint32_t isn);
};

struct irq_source {
	uint32_t			start;
	uint32_t			end;
	const struct irq_source_ops	*ops;
	void				*data;
	struct list_node		link;
};

extern void __register_irq_source(struct irq_source *is, bool secondary);
extern void register_irq_source(const struct irq_source_ops *ops, void *data,
				uint32_t start, uint32_t count);
extern void unregister_irq_source(uint32_t start, uint32_t count);
extern struct irq_source *irq_find_source(uint32_t isn);

/* Warning: callback is called with internal source lock held
 * so don't call back into any of our irq_ APIs from it
 */
extern void irq_for_each_source(void (*cb)(struct irq_source *, void *),
				void *data);

extern uint32_t get_psi_interrupt(uint32_t chip_id);

extern struct dt_node *add_ics_node(void);
extern void add_opal_interrupts(void);
extern uint32_t get_ics_phandle(void);

struct cpu_thread;

extern void reset_cpu_icp(void);
extern void icp_send_eoi(uint32_t interrupt);
extern void icp_prep_for_pm(void);
extern void icp_kick_cpu(struct cpu_thread *cpu);

extern void init_interrupts(void);

extern bool irq_source_eoi(uint32_t isn);
extern bool __irq_source_eoi(struct irq_source *is, uint32_t isn);


#endif /* __INTERRUPTS_H */
