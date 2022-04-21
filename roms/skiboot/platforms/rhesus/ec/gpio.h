// SPDX-License-Identifier: Apache-2.0
/* Copyright 2013-2014 Google Corp. */

/**
 * @file gpio.h
 *
 * @brief Public interface of the EC GPIO device driver
 *
 */

#ifndef __EC_GPIO_H_
#define __EC_GPIO_H_

#ifdef __cplusplus
extern "C" {
#endif

#define EC_GPIO_INPUT  0
#define EC_GPIO_OUTPUT 1
#define EC_GPIO_PULLUP_DISABLE 0
#define EC_GPIO_PULLUP_ENABLE  1

// Sets up a GPIO as output or input.
// Returns: <0 on error
int ec_gpio_setup(EcGpioPort port, uint8_t pin,
                  int is_output, int pullup_enable);

// Reads the current value of an input GPIO.
// Returns: GPIO value (0,1) or <0 on error.
int ec_gpio_read(EcGpioPort port, uint8_t pin);

// Sets the driving value of an output GPIO.  Port should already be set
// to output mode.
// Returns: <0 on error
int ec_gpio_set(EcGpioPort port, uint8_t pin, int val);

#ifdef __cplusplus
}
#endif

#endif  // __EC_GPIO_H_
