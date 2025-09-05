/*
 * Copyright (C) 2025 ASPEED Technology Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdint.h>
#include <uart.h>
#include <io.h>

/* UART registers */
#define UART_THR 0x00
#define UART_DLL 0x00
#define UART_DLH 0x04
#define UART_FCR 0x08
#define UART_LCR 0x0c
#define UART_LSR 0x14

/* UART_FCR */
#define UART_FCR_TRIG_MASK      GENMASK(7, 6)
#define UART_FCR_TRIG_SHIFT     6
#define UART_FCR_TX_RST         BIT(2)
#define UART_FCR_RX_RST         BIT(1)
#define UART_FCR_EN             BIT(0)

/* UART_LCR */
#define UART_LCR_DLAB           BIT(7)
#define UART_LCR_PARITY_MODE    BIT(4)
#define UART_LCR_PARITY_EN      BIT(3)
#define UART_LCR_STOP           BIT(2)
#define UART_LCR_CLS_MASK       GENMASK(1, 0)
#define UART_LCR_CLS_SHIFT      0

/* UART_LSR */
#define UART_LSR_THRE   BIT(5)

struct uart_aspeed_config {
    uintptr_t base;
};

struct uart_aspeed_config uart_dev_cfg;

static int uart_aspeed_configure(struct uart_aspeed_config *dev_cfg,
                                 const struct uart_config *uart_cfg)
{
    uint32_t clk_rate;
    uint32_t divisor;
    uint32_t reg;
    int rc = 0;

    if (!dev_cfg || !uart_cfg) {
        return -1;
    }

    clk_rate = 1846153;
    divisor = clk_rate / (16 * uart_cfg->baudrate);

    reg = readl(dev_cfg->base + UART_LCR);
    reg |= UART_LCR_DLAB;
    writel(reg, dev_cfg->base + UART_LCR);

    writel(divisor & 0xf, dev_cfg->base + UART_DLL);
    writel(divisor >> 8, dev_cfg->base + UART_DLH);

    reg &= ~(UART_LCR_DLAB | UART_LCR_CLS_MASK | UART_LCR_STOP);

    switch (uart_cfg->data_bits) {
    case UART_CFG_DATA_BITS_5:
        reg |= ((0x0 << UART_LCR_CLS_SHIFT) & UART_LCR_CLS_MASK);
        break;
    case UART_CFG_DATA_BITS_6:
        reg |= ((0x1 << UART_LCR_CLS_SHIFT) & UART_LCR_CLS_MASK);
        break;
    case UART_CFG_DATA_BITS_7:
        reg |= ((0x2 << UART_LCR_CLS_SHIFT) & UART_LCR_CLS_MASK);
        break;
    case UART_CFG_DATA_BITS_8:
        reg |= ((0x3 << UART_LCR_CLS_SHIFT) & UART_LCR_CLS_MASK);
        break;
    default:
        rc = -1;
        goto out;
    }

    switch (uart_cfg->stop_bits) {
    case UART_CFG_STOP_BITS_1:
        reg &= ~(UART_LCR_STOP);
        break;
    case UART_CFG_STOP_BITS_2:
        reg |= UART_LCR_STOP;
        break;
    default:
        rc = -1;
        goto out;
    }

    switch (uart_cfg->parity) {
    case UART_CFG_PARITY_NONE:
        reg &= ~(UART_LCR_PARITY_EN);
        break;
    case UART_CFG_PARITY_ODD:
        reg |= UART_LCR_PARITY_EN;
        break;
    case UART_CFG_PARITY_EVEN:
        reg |= (UART_LCR_PARITY_EN | UART_LCR_PARITY_MODE);
        break;
    default:
        rc = -1;
        goto out;
    }

    writel(reg, dev_cfg->base + UART_LCR);

    /*
     * enable FIFO, generate the interrupt at 8th byte
     */
    reg = ((0x2 << UART_FCR_TRIG_SHIFT) & UART_FCR_TRIG_MASK) |
          UART_FCR_TX_RST |
          UART_FCR_RX_RST |
          UART_FCR_EN;
    writel(reg, dev_cfg->base + UART_FCR);

out:
    return rc;
};

void uart_aspeed_poll_out(unsigned char c)
{
    uint32_t sts;

    do {
        sts = readl(uart_dev_cfg.base + UART_LSR);
    } while (!(sts & UART_LSR_THRE));

    writel(c, uart_dev_cfg.base + UART_THR);
}

int uart_aspeed_init(uintptr_t base)
{
    struct uart_config uart_cfg;
    int rc = 0;

    uart_dev_cfg.base = base;

    uart_cfg.baudrate = 115200;
    uart_cfg.parity = UART_CFG_PARITY_NONE;
    uart_cfg.stop_bits = UART_CFG_STOP_BITS_1;
    uart_cfg.data_bits = UART_CFG_DATA_BITS_8;
    uart_cfg.flow_ctrl = UART_CFG_FLOW_CTRL_NONE;

    rc = uart_aspeed_configure(&uart_dev_cfg, &uart_cfg);

    return rc;
}

