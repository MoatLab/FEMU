/*
 * Radio tuning for Philips SA2400 on RTL8180
 *
 * Copyright 2007 Andrea Merello <andreamrl@tiscali.it>
 *
 * Modified slightly for iPXE, June 2009 by Joshua Oreman.
 *
 * Code from the BSD driver and the rtl8181 project have been
 * very useful to understand certain things
 *
 * I want to thanks the Authors of such projects and the Ndiswrapper
 * project Authors.
 *
 * A special Big Thanks also is for all people who donated me cards,
 * making possible the creation of the original rtl8180 driver
 * from which this code is derived!
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <unistd.h>
#include <ipxe/pci.h>
#include <ipxe/net80211.h>

#include "rtl818x.h"

FILE_LICENCE(GPL2_ONLY);

#define SA2400_ANTENNA 0x91
#define SA2400_DIG_ANAPARAM_PWR1_ON 0x8
#define SA2400_ANA_ANAPARAM_PWR1_ON 0x28
#define SA2400_ANAPARAM_PWR0_ON 0x3

/* RX sensitivity in dbm */
#define SA2400_MAX_SENS 85

#define SA2400_REG4_FIRDAC_SHIFT 7

static const u32 sa2400_chan[] = {
	0x00096c, /* ch1 */
	0x080970,
	0x100974,
	0x180978,
	0x000980,
	0x080984,
	0x100988,
	0x18098c,
	0x000994,
	0x080998,
	0x10099c,
	0x1809a0,
	0x0009a8,
	0x0009b4, /* ch 14 */
};

static void write_sa2400(struct net80211_device *dev, u8 addr, u32 data)
{
	struct rtl818x_priv *priv = dev->priv;
	u32 phy_config;

	/* MAC will bang bits to the sa2400. sw 3-wire is NOT used */
	phy_config = 0xb0000000;

	phy_config |= ((u32)(addr & 0xf)) << 24;
	phy_config |= data & 0xffffff;

	/* This was originally a 32-bit write to a typecast
	   RFPinsOutput, but gcc complained about aliasing rules. -JBO */
	rtl818x_iowrite16(priv, &priv->map->RFPinsOutput, phy_config & 0xffff);
	rtl818x_iowrite16(priv, &priv->map->RFPinsEnable, phy_config >> 16);

	mdelay(3);
}

static void sa2400_write_phy_antenna(struct net80211_device *dev, short chan)
{
	struct rtl818x_priv *priv = dev->priv;
	u8 ant = SA2400_ANTENNA;

	if (priv->rfparam & RF_PARAM_ANTBDEFAULT)
		ant |= BB_ANTENNA_B;

	if (chan == 14)
		ant |= BB_ANTATTEN_CHAN14;

	rtl818x_write_phy(dev, 0x10, ant);

}

static void sa2400_rf_set_channel(struct net80211_device *dev,
				  struct net80211_channel *channelp)
{
	struct rtl818x_priv *priv = dev->priv;
	int channel = channelp->channel_nr;
	u32 txpw = priv->txpower[channel - 1] & 0xFF;
	u32 chan = sa2400_chan[channel - 1];

	write_sa2400(dev, 7, txpw);

	sa2400_write_phy_antenna(dev, channel);

	write_sa2400(dev, 0, chan);
	write_sa2400(dev, 1, 0xbb50);
	write_sa2400(dev, 2, 0x80);
	write_sa2400(dev, 3, 0);
}

static void sa2400_rf_stop(struct net80211_device *dev)
{
	write_sa2400(dev, 4, 0);
}

static void sa2400_rf_init(struct net80211_device *dev)
{
	struct rtl818x_priv *priv = dev->priv;
	u32 anaparam, txconf;
	u8 firdac;
	int analogphy = priv->rfparam & RF_PARAM_ANALOGPHY;

	anaparam = priv->anaparam;
	anaparam &= ~(1 << ANAPARAM_TXDACOFF_SHIFT);
	anaparam &= ~ANAPARAM_PWR1_MASK;
	anaparam &= ~ANAPARAM_PWR0_MASK;

	if (analogphy) {
		anaparam |= SA2400_ANA_ANAPARAM_PWR1_ON << ANAPARAM_PWR1_SHIFT;
		firdac = 0;
	} else {
		anaparam |= (SA2400_DIG_ANAPARAM_PWR1_ON << ANAPARAM_PWR1_SHIFT);
		anaparam |= (SA2400_ANAPARAM_PWR0_ON << ANAPARAM_PWR0_SHIFT);
		firdac = 1 << SA2400_REG4_FIRDAC_SHIFT;
	}

	rtl818x_set_anaparam(priv, anaparam);

	write_sa2400(dev, 0, sa2400_chan[0]);
	write_sa2400(dev, 1, 0xbb50);
	write_sa2400(dev, 2, 0x80);
	write_sa2400(dev, 3, 0);
	write_sa2400(dev, 4, 0x19340 | firdac);
	write_sa2400(dev, 5, 0x1dfb | (SA2400_MAX_SENS - 54) << 15);
	write_sa2400(dev, 4, 0x19348 | firdac); /* calibrate VCO */

	if (!analogphy)
		write_sa2400(dev, 4, 0x1938c); /*???*/

	write_sa2400(dev, 4, 0x19340 | firdac);

	write_sa2400(dev, 0, sa2400_chan[0]);
	write_sa2400(dev, 1, 0xbb50);
	write_sa2400(dev, 2, 0x80);
	write_sa2400(dev, 3, 0);
	write_sa2400(dev, 4, 0x19344 | firdac); /* calibrate filter */

	/* new from rtl8180 embedded driver (rtl8181 project) */
	write_sa2400(dev, 6, 0x13ff | (1 << 23)); /* MANRX */
	write_sa2400(dev, 8, 0); /* VCO */

	if (analogphy) {
		rtl818x_set_anaparam(priv, anaparam |
				     (1 << ANAPARAM_TXDACOFF_SHIFT));

		txconf = rtl818x_ioread32(priv, &priv->map->TX_CONF);
		rtl818x_iowrite32(priv, &priv->map->TX_CONF,
			txconf | RTL818X_TX_CONF_LOOPBACK_CONT);

		write_sa2400(dev, 4, 0x19341); /* calibrates DC */

		/* a 5us delay is required here,
		 * we rely on the 3ms delay introduced in write_sa2400 */

		write_sa2400(dev, 4, 0x19345);

		/* a 20us delay is required here,
		 * we rely on the 3ms delay introduced in write_sa2400 */

		rtl818x_iowrite32(priv, &priv->map->TX_CONF, txconf);

		rtl818x_set_anaparam(priv, anaparam);
	}
	/* end new code */

	write_sa2400(dev, 4, 0x19341 | firdac); /* RTX MODE */

	/* baseband configuration */
	rtl818x_write_phy(dev, 0, 0x98);
	rtl818x_write_phy(dev, 3, 0x38);
	rtl818x_write_phy(dev, 4, 0xe0);
	rtl818x_write_phy(dev, 5, 0x90);
	rtl818x_write_phy(dev, 6, 0x1a);
	rtl818x_write_phy(dev, 7, 0x64);

	sa2400_write_phy_antenna(dev, 1);

	rtl818x_write_phy(dev, 0x11, 0x80);

	if (rtl818x_ioread8(priv, &priv->map->CONFIG2) &
	    RTL818X_CONFIG2_ANTENNA_DIV)
		rtl818x_write_phy(dev, 0x12, 0xc7); /* enable ant diversity */
	else
		rtl818x_write_phy(dev, 0x12, 0x47); /* disable ant diversity */

	rtl818x_write_phy(dev, 0x13, 0x90 | priv->csthreshold);

	rtl818x_write_phy(dev, 0x19, 0x0);
	rtl818x_write_phy(dev, 0x1a, 0xa0);
}

struct rtl818x_rf_ops sa2400_rf_ops __rtl818x_rf_driver = {
	.name		= "Philips SA2400",
	.id		= 3,
	.init		= sa2400_rf_init,
	.stop		= sa2400_rf_stop,
	.set_chan	= sa2400_rf_set_channel
};
