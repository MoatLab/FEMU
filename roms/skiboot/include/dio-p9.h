// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2019 IBM Corp. */

#ifndef __DIO_H
#define __DIO_H

struct proc_chip;

/* Initialize the P9 DIO */
extern void p9_dio_init(void);

/* The function typedef for dio interrupt callback */
typedef void (*dio_interrupt_callback)(struct proc_chip *chip);

/* Register dio interrupt on GPIO port.
 * This effectively enables the DIO interrupt on the GPIO port,
 * and callback will be called when the interrupt is triggered */
extern int dio_interrupt_register(struct proc_chip *chip,
		int port, dio_interrupt_callback c);

/* Deregister dio interrupt on GPIO port.
 * This effectively disables the DIO interrupt on the GPIO port. */
extern int dio_interrupt_deregister(struct proc_chip *chip,
		int port, dio_interrupt_callback c);

/* The function to be called when DIO interrupt is triggered */
extern void dio_interrupt_handler(uint32_t chip_id);


#define NUM_OF_P9_DIO_PORTS	3 /* P9 has GPIO port 0~2 for interrupts */

struct p9_dio {
	dio_interrupt_callback callbacks[NUM_OF_P9_DIO_PORTS];
};

#endif	/* __DIO_H */
