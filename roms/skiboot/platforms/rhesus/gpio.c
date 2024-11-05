// SPDX-License-Identifier: Apache-2.0
/* Copyright 2013-2014 Google Corp. */

#include <stdint.h>
#include "ec/config.h"
#include "ec/gpio.h"

int ec_gpio_setup(EcGpioPort port, uint8_t pin,
                  int is_output, int pullup_enable)
{
    uint8_t ddr_reg;
    if (pin > 7) {
        return -1;
    }

    /* Set data direction */
    ec_outb(EC_GPIO_INDEX,
            port * EC_GPIO_PORT_SKIP + EC_GPIO_DDR_OFFSET);
    ddr_reg = ec_inb(EC_GPIO_DATA);
    if (is_output) {
        ddr_reg |= (1 << pin);
    } else {
        ddr_reg &= ~(1 << pin);
    }
    ec_outb(EC_GPIO_DATA, ddr_reg);

    /* Set pullup enable for output GPOs */
    if (is_output)
    {
        uint8_t pup_reg;
        ec_outb(EC_GPIO_INDEX,
                port * EC_GPIO_PORT_SKIP + EC_GPIO_PUP_OFFSET);
        pup_reg = ec_inb(EC_GPIO_DATA);
        if (pullup_enable) {
            pup_reg |= (1 << pin);
        } else {
            pup_reg &= ~(1 << pin);
        }
        ec_outb(EC_GPIO_DATA, pup_reg);
    }

    return 0;
}

int ec_gpio_read(EcGpioPort port, uint8_t pin)
{
    uint8_t pin_reg;
    if (pin > 7) {
        return -1;
    }

    ec_outb(EC_GPIO_INDEX,
            port * EC_GPIO_PORT_SKIP + EC_GPIO_PIN_OFFSET);
    pin_reg = ec_inb(EC_GPIO_DATA);
    return !!(pin_reg & (1 << pin));
}

int ec_gpio_set(EcGpioPort port, uint8_t pin, int val)
{
    uint8_t data_reg;
    if (pin > 7) {
        return -1;
    }

    ec_outb(EC_GPIO_INDEX,
            port * EC_GPIO_PORT_SKIP + EC_GPIO_DATA_OFFSET);
    data_reg = ec_inb(EC_GPIO_DATA);
    if (val) {
        data_reg |= (1 << pin);
    } else {
        data_reg &= ~(1 << pin);
    }
    ec_outb(EC_GPIO_DATA, data_reg);
    return 0;
}
