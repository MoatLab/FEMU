// SPDX-License-Identifier: Apache-2.0
/* Copyright 2013-2014 IBM Corp. */

/**
 * @file config.H
 *
 * @brief Definitions for EC configuration values.
 *
 */

#ifndef __EC_CONFIG_H_
#define __EC_CONFIG_H_

#include <stdint.h>

#define EC_RTC_PORT_BASE    (0x70) // RTC/CMOS LPC base address
#define EC_RTC_BLOCK_SIZE   (512)  // Size of addressable data in RTC
#define EC_RTC_CENTURY      (1)    // 1 if century format is enabled
#if EC_RTC_CENTURY
#define EC_RTC_BBRAM_OFFSET (0x33) // Offset of NV data (= size of calendar)
#else
#define EC_RTC_BBRAM_OFFSET (0x0E) // Offset of NV data (= size of calendar)
#endif // #if EC_RTC_CENTURY

#define EC_RTCDD_READ_TRIES  (2)      // Times to try the RTC if updating
#define EC_RTCDD_RETRY_DELAY (300000) // Delay between RTC read retries in ns
                                      // based on update time of 244 + 30.5 µs

#define EC_GPIO_INDEX        0x200
#define EC_GPIO_DATA         0x201
#define EC_GPIO_NUM_PORTS    17
#define EC_GPIO_PORT_SKIP    4

#define EC_GPIO_DATA_OFFSET  0x0
#define EC_GPIO_DDR_OFFSET   0x1
#define EC_GPIO_PIN_OFFSET   0x2
#define EC_GPIO_PUP_OFFSET   0x3

typedef enum EcGpioPort {
    EC_GPIO_PORT_A = 0,
    EC_GPIO_PORT_B = 1,
    EC_GPIO_PORT_C = 2,
    EC_GPIO_PORT_D = 3,
    EC_GPIO_PORT_E = 4,
    EC_GPIO_PORT_F = 5,
    EC_GPIO_PORT_G = 6,
    EC_GPIO_PORT_H = 7,
    // skip port I
    EC_GPIO_PORT_J = 8,
    EC_GPIO_PORT_K = 9,
    EC_GPIO_PORT_L = 10,
    EC_GPIO_PORT_M = 11,
    EC_GPIO_PORT_N = 12,
    // skip port O
    EC_GPIO_PORT_P = 13,
    EC_GPIO_PORT_Q = 14,
    EC_GPIO_PORT_R = 15,
    EC_GPIO_PORT_S = 16,
} EcGpioPort;

#ifdef __cplusplus
extern "C" {
#endif
void ec_outb(uint16_t, uint8_t);
uint8_t ec_inb(uint16_t);
#ifdef __cplusplus
}
#endif

#endif  // __EC_CONFIG_H_
