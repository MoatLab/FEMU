// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2019 IBM Corp. */

#define pr_fmt(fmt) "DIO: " fmt

#include <chip.h>
#include <dio-p9.h>
#include <opal.h>
#include <xscom.h>
#include <xscom-p9-regs.h>

void p9_dio_init(void)
{
	struct dt_node *xn;
	struct proc_chip *chip;
	struct p9_dio *dio;

	if (proc_gen < proc_gen_p9)
		return;

	dt_for_each_compatible(dt_root, xn, "ibm,xscom") {
		dio = zalloc(sizeof(struct p9_dio));
		assert(dio);
		chip = get_chip(dt_get_chip_id(xn));
		assert(chip);
		chip->dio = dio;
	}
}

int dio_interrupt_register(struct proc_chip *chip,
		int port, dio_interrupt_callback callback)
{
	u64 val;
	int rc;

	assert(chip);
	assert(chip->dio);

	if (port < 0 || port >= NUM_OF_P9_DIO_PORTS)
		return OPAL_PARAMETER;

	if (chip->dio->callbacks[port]) /* This port already has a callback */
		return OPAL_PARAMETER;

	rc = xscom_read(chip->id, P9_GPIO_INTERRUPT_ENABLE, &val);
	if (rc != OPAL_SUCCESS) {
		prlog(PR_ERR, "XSCOM error %d reading reg 0x%llx\n",
				rc, P9_GPIO_INTERRUPT_ENABLE);
		return OPAL_HARDWARE;
	}

	val |= PPC_BIT(port);
	rc = xscom_write(chip->id, P9_GPIO_INTERRUPT_ENABLE, val);
	if (rc != OPAL_SUCCESS) {
		prlog(PR_ERR, "XSCOM error %d writing reg 0x%llx\n",
				rc, P9_GPIO_INTERRUPT_ENABLE);
		return OPAL_HARDWARE;
	}

	chip->dio->callbacks[port] = callback;

	return OPAL_SUCCESS;
}

int dio_interrupt_deregister(struct proc_chip* chip,
		int port, dio_interrupt_callback callback)
{
	u64 val;
	int rc;

	assert(chip);
	assert(chip->dio);

	if (port < 0 || port >= NUM_OF_P9_DIO_PORTS)
		return OPAL_PARAMETER;

	if (chip->dio->callbacks[port] != callback)
		return OPAL_PARAMETER;

	rc = xscom_read(chip->id, P9_GPIO_INTERRUPT_ENABLE, &val);
	if (rc != OPAL_SUCCESS) {
		prlog(PR_ERR, "XSCOM error %d reading reg 0x%llx\n",
				rc, P9_GPIO_INTERRUPT_ENABLE);
		return OPAL_HARDWARE;
	}

	val &= ~PPC_BIT(port);
	rc = xscom_write(chip->id, P9_GPIO_INTERRUPT_ENABLE, val);
	if (rc != OPAL_SUCCESS) {
		prlog(PR_ERR, "XSCOM error %d writing reg 0x%llx\n",
				rc, P9_GPIO_INTERRUPT_ENABLE);
		return OPAL_HARDWARE;
	}

	chip->dio->callbacks[port] = NULL;

	return OPAL_SUCCESS;
}

void dio_interrupt_handler(uint32_t chip_id)
{
	struct proc_chip *chip;
	u64 val;
	int rc;
	int i;

	chip = get_chip(chip_id);
	if (chip == NULL || chip->dio == NULL)
		return;

	rc = xscom_read(chip->id, P9_GPIO_INTERRUPT_STATUS, &val);
	if (rc != OPAL_SUCCESS) {
		prlog(PR_ERR, "XSCOM error %d reading reg 0x%llx\n",
				rc, P9_GPIO_INTERRUPT_STATUS);
		return;
	}

	for (i = 0; i < NUM_OF_P9_DIO_PORTS; ++i) {
		if (val & PPC_BIT(i)) {
			if (chip->dio->callbacks[i])
				chip->dio->callbacks[i](chip);
			else
				prlog(PR_ERR,
					"DIO interrupt triggerd on chip 0x%x"
					" port %d but no handler\n",
					chip->id, i);
			/* Write 1 to clear the interrupt status */
			xscom_write(chip->id, P9_GPIO_INTERRUPT_CONDITION,
					val & PPC_BIT(i));
		}
	}
}
