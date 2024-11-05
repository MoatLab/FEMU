// SPDX-License-Identifier: GPL-2.0
/*
 * MediaTek timer driver
 *
 * Copyright (C) 2018 MediaTek Inc.
 * Author: Ryder Lee <ryder.lee@mediatek.com>
 */

#include <clk.h>
#include <common.h>
#include <dm.h>
#include <timer.h>
#include <asm/io.h>
#include <linux/bitops.h>

#define MTK_GPT4_CTRL	0x40
#define MTK_GPT4_CLK	0x44
#define MTK_GPT4_CNT	0x48

#define GPT4_ENABLE	BIT(0)
#define GPT4_CLEAR	BIT(1)
#define GPT4_FREERUN	GENMASK(5, 4)
#define GPT4_CLK_SYS	0x0
#define GPT4_CLK_DIV1	0x0

struct mtk_timer_priv {
	void __iomem *base;
};

static u64 mtk_timer_get_count(struct udevice *dev)
{
	struct mtk_timer_priv *priv = dev_get_priv(dev);
	u32 val = readl(priv->base + MTK_GPT4_CNT);

	return timer_conv_64(val);
}

static int mtk_timer_probe(struct udevice *dev)
{
	struct timer_dev_priv *uc_priv = dev_get_uclass_priv(dev);
	struct mtk_timer_priv *priv = dev_get_priv(dev);
	struct clk clk, parent;
	int ret;

	priv->base = dev_read_addr_ptr(dev);
	if (!priv->base)
		return -ENOENT;

	ret = clk_get_by_index(dev, 0, &clk);
	if (ret)
		return ret;

	ret = clk_get_by_index(dev, 1, &parent);
	if (!ret) {
		ret = clk_set_parent(&clk, &parent);
		if (ret)
			return ret;
	}

	uc_priv->clock_rate = clk_get_rate(&clk);
	if (!uc_priv->clock_rate)
		return -EINVAL;

	/*
	 * Initialize the timer:
	 * 1. set clock source to system clock with clock divider setting to 1
	 * 2. set timer mode to free running
	 * 3. reset timer counter to 0 then enable the timer
	 */
	writel(GPT4_CLK_SYS | GPT4_CLK_DIV1, priv->base + MTK_GPT4_CLK);
	writel(GPT4_FREERUN | GPT4_CLEAR | GPT4_ENABLE,
	       priv->base + MTK_GPT4_CTRL);

	return 0;
}

static const struct timer_ops mtk_timer_ops = {
	.get_count = mtk_timer_get_count,
};

static const struct udevice_id mtk_timer_ids[] = {
	{ .compatible = "mediatek,timer" },
	{ .compatible = "mediatek,mt6577-timer" },
	{ }
};

U_BOOT_DRIVER(mtk_timer) = {
	.name = "mtk_timer",
	.id = UCLASS_TIMER,
	.of_match = mtk_timer_ids,
	.priv_auto	= sizeof(struct mtk_timer_priv),
	.probe = mtk_timer_probe,
	.ops = &mtk_timer_ops,
	.flags = DM_FLAG_PRE_RELOC,
};
