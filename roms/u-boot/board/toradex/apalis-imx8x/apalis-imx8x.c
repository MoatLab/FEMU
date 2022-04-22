// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2020 Toradex
 */

#include <common.h>
#include <cpu_func.h>
#include <init.h>

#include <asm/arch/clock.h>
#include <asm/arch/imx8-pins.h>
#include <asm/arch/iomux.h>
#include <asm/arch/sci/sci.h>
#include <asm/arch/sys_proto.h>
#include <asm/global_data.h>
#include <asm/gpio.h>
#include <asm/io.h>
#include <env.h>
#include <errno.h>
#include <linux/libfdt.h>

#include "../common/tdx-cfg-block.h"

DECLARE_GLOBAL_DATA_PTR;

#define UART_PAD_CTRL	((SC_PAD_CONFIG_OUT_IN << PADRING_CONFIG_SHIFT) | \
			 (SC_PAD_ISO_OFF << PADRING_LPCONFIG_SHIFT) | \
			 (SC_PAD_28FDSOI_DSE_DV_HIGH << PADRING_DSE_SHIFT) | \
			 (SC_PAD_28FDSOI_PS_PU << PADRING_PULL_SHIFT))

static iomux_cfg_t uart1_pads[] = {
	SC_P_UART1_RX | MUX_PAD_CTRL(UART_PAD_CTRL),
	SC_P_UART1_TX | MUX_PAD_CTRL(UART_PAD_CTRL),
};

static void setup_iomux_uart(void)
{
	imx8_iomux_setup_multiple_pads(uart1_pads, ARRAY_SIZE(uart1_pads));
}

void board_mem_get_layout(u64 *phys_sdram_1_start,
			  u64 *phys_sdram_1_size,
			  u64 *phys_sdram_2_start,
			  u64 *phys_sdram_2_size)
{
	u32 is_dualx = 0, val = 0;
	sc_err_t scierr = sc_misc_otp_fuse_read(-1, 6, &val);

	if (scierr == SC_ERR_NONE) {
		/* DX has two A35 cores disabled */
		is_dualx = (val & 0xf) != 0x0;
	}

	*phys_sdram_1_start = PHYS_SDRAM_1;
	if (is_dualx)
		/* Our DX based SKUs only have 1 GB RAM */
		*phys_sdram_1_size = SZ_1G;
	else
		*phys_sdram_1_size = PHYS_SDRAM_1_SIZE;
	*phys_sdram_2_start = PHYS_SDRAM_2;
	*phys_sdram_2_size = PHYS_SDRAM_2_SIZE;
}

int board_early_init_f(void)
{
	sc_pm_clock_rate_t rate;
	sc_err_t err = 0;

	/*
	 * This works around that having only UART3 up the baudrate is 1.2M
	 * instead of 115.2k. Set UART0 clock root to 80 MHz
	 */
	rate = 80000000;
	err = sc_pm_set_clock_rate(-1, SC_R_UART_0, SC_PM_CLK_PER, &rate);
	if (err != SC_ERR_NONE)
		return 0;

	/* Set UART3 clock root to 80 MHz and enable it */
	rate = SC_80MHZ;
	err = sc_pm_setup_uart(SC_R_UART_1, rate);
	if (err != SC_ERR_NONE)
		return 0;

	setup_iomux_uart();

	return 0;
}

#if IS_ENABLED(CONFIG_DM_GPIO)
static void board_gpio_init(void)
{
	/* TODO */
}
#else
static inline void board_gpio_init(void) {}
#endif

#if IS_ENABLED(CONFIG_FEC_MXC)
#include <miiphy.h>

int board_phy_config(struct phy_device *phydev)
{
	if (phydev->drv->config)
		phydev->drv->config(phydev);

	return 0;
}
#endif

int checkboard(void)
{
	puts("Model: Toradex Apalis iMX8X\n");

	build_info();
	print_bootinfo();

	return 0;
}

int board_init(void)
{
	board_gpio_init();

	return 0;
}

/*
 * Board specific reset that is system reset.
 */
void reset_cpu(void)
{
	/* TODO */
}

#if defined(CONFIG_OF_LIBFDT) && defined(CONFIG_OF_BOARD_SETUP)
int ft_board_setup(void *blob, struct bd_info *bd)
{
	return ft_common_board_setup(blob, bd);
}
#endif

int board_mmc_get_env_dev(int devno)
{
	return devno;
}

int board_late_init(void)
{
#ifdef CONFIG_ENV_VARS_UBOOT_RUNTIME_CONFIG
/* TODO move to common */
	env_set("board_name", "Apalis iMX8X");
#endif

	return 0;
}
