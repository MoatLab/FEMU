/*
 * Copyright (c) 2025 ASPEED
 * Copyright (c) 2018-2019 Nordic Semiconductor ASA
 * Copyright (c) 2015 Wind River Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Public APIs for UART drivers
 */

#ifndef __AST27X0_INCLUDE_UART_H__
#define __AST27X0_INCLUDE_UART_H__

#define UART12  0x14C33B00

/**
 * @brief UART Interface
 * @defgroup uart_interface UART Interface
 * @since 1.0
 * @version 1.0.0
 * @ingroup io_interfaces
 * @{
 */

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Parity modes */
enum uart_config_parity {
	UART_CFG_PARITY_NONE,   /**< No parity */
	UART_CFG_PARITY_ODD,    /**< Odd parity */
	UART_CFG_PARITY_EVEN,   /**< Even parity */
	UART_CFG_PARITY_MARK,   /**< Mark parity */
	UART_CFG_PARITY_SPACE,  /**< Space parity */
};

/** @brief Number of stop bits. */
enum uart_config_stop_bits {
	UART_CFG_STOP_BITS_0_5,  /**< 0.5 stop bit */
	UART_CFG_STOP_BITS_1,    /**< 1 stop bit */
	UART_CFG_STOP_BITS_1_5,  /**< 1.5 stop bits */
	UART_CFG_STOP_BITS_2,    /**< 2 stop bits */
};

/** @brief Number of data bits. */
enum uart_config_data_bits {
	UART_CFG_DATA_BITS_5,    /**< 5 data bits */
	UART_CFG_DATA_BITS_6,    /**< 6 data bits */
	UART_CFG_DATA_BITS_7,    /**< 7 data bits */
	UART_CFG_DATA_BITS_8,    /**< 8 data bits */
	UART_CFG_DATA_BITS_9,    /**< 9 data bits */
};

/**
 * @brief Hardware flow control options.
 *
 * With flow control set to none, any operations related to flow control
 * signals can be managed by user with uart_line_ctrl functions.
 * In other cases, flow control is managed by hardware/driver.
 */
enum uart_config_flow_control {
	UART_CFG_FLOW_CTRL_NONE,
	UART_CFG_FLOW_CTRL_RTS_CTS,
	UART_CFG_FLOW_CTRL_DTR_DSR,
	UART_CFG_FLOW_CTRL_RS485,
};

/**
 * @brief UART controller configuration structure
 */
struct uart_config {
	uint32_t baudrate;  /**< Baudrate setting in bps */
	uint8_t parity;     /**< Parity bit, use @ref uart_config_parity */
	uint8_t stop_bits;  /**< Stop bits, use @ref uart_config_stop_bits */
	uint8_t data_bits;  /**< Data bits, use @ref uart_config_data_bits */
	uint8_t flow_ctrl;  /**< Flow control setting, use @ref uart_config_flow_control */
};

void uart_aspeed_poll_out(unsigned char c);
int uart_aspeed_init(uintptr_t base);

#ifdef __cplusplus
}
#endif

#endif /* __AST27X0_INCLUDE_UART_H__ */
