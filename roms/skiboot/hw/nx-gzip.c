// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * NX GZIP (p9) accellerator support
 *
 * Copyright 2016-2017 IBM Corp.
 */

#include <skiboot.h>
#include <chip.h>
#include <xscom.h>
#include <io.h>
#include <cpu.h>
#include <nx.h>

#define EE			(1) /* enable gzip engine */

static int nx_cfg_gzip_umac(struct dt_node *node, u32 gcid, u32 pb_base)
{
	int rc;
	u64 umac_bar, umac_notify;
	struct dt_node *nx_node;
	static u32 nxgzip_tid = 1; /* tid counter within coprocessor type */

	nx_node = dt_new(node, "ibm,gzip-high-fifo");
	umac_bar = pb_base + NX_P9_GZIP_HIGH_PRI_RX_FIFO_BAR;
	umac_notify = pb_base + NX_P9_GZIP_HIGH_PRI_RX_FIFO_NOTIFY_MATCH;

	rc = nx_cfg_rx_fifo(nx_node, "ibm,p9-nx-gzip", "High", gcid,
				NX_CT_GZIP, nxgzip_tid++, umac_bar,
				umac_notify);
	if (rc)
		return rc;

	nx_node = dt_new(node, "ibm,gzip-normal-fifo");
	umac_bar = pb_base + NX_P9_GZIP_NORMAL_PRI_RX_FIFO_BAR;
	umac_notify = pb_base + NX_P9_GZIP_NORMAL_PRI_RX_FIFO_NOTIFY_MATCH;

	rc = nx_cfg_rx_fifo(nx_node, "ibm,p9-nx-gzip", "Normal", gcid,
				NX_CT_GZIP, nxgzip_tid++, umac_bar,
				umac_notify);

	return rc;
}

static int nx_cfg_gzip_dma(u32 gcid, u64 xcfg)
{
	u64 cfg;
	int rc;

	rc = xscom_read(gcid, xcfg, &cfg);
	if (rc)
		return rc;

	cfg = SETFIELD(NX_DMA_CFG_GZIP_COMPRESS_PREFETCH, cfg,
		       DMA_COMPRESS_PREFETCH);
	cfg = SETFIELD(NX_DMA_CFG_GZIP_DECOMPRESS_PREFETCH, cfg,
		       DMA_DECOMPRESS_PREFETCH);

	cfg = SETFIELD(NX_DMA_CFG_GZIP_COMPRESS_MAX_RR, cfg,
		       DMA_COMPRESS_MAX_RR);
	cfg = SETFIELD(NX_DMA_CFG_GZIP_DECOMPRESS_MAX_RR, cfg,
		       DMA_DECOMPRESS_MAX_RR);

	rc = xscom_write(gcid, xcfg, cfg);
	if (rc)
		prerror("NX%d: ERROR: DMA config failure %d\n", gcid, rc);
	else
		prlog(PR_DEBUG, "NX%d:   DMA 0x%016lx\n", gcid,
		      (unsigned long)cfg);

	return rc;
}

static int nx_cfg_gzip_ee(u32 gcid, u64 xcfg)
{
	u64 cfg;
	int rc;

	rc = xscom_read(gcid, xcfg, &cfg);
	if (rc)
		return rc;

	cfg = SETFIELD(NX_P9_EE_CFG_CH4, cfg, EE);

	rc = xscom_write(gcid, xcfg, cfg);
	if (rc)
		prerror("NX%d: ERROR: Engine Enable failure %d\n", gcid, rc);
	else
		prlog(PR_DEBUG, "NX%d:   Engine Enable 0x%016lx\n",
		      gcid, (unsigned long)cfg);

	return rc;
}

void p9_nx_enable_gzip(struct dt_node *node, u32 gcid, u32 pb_base)
{
	u64 cfg_dma, cfg_ee;
	int rc;

	prlog(PR_INFO, "NX%d: gzip at 0x%x\n", gcid, pb_base);

	cfg_dma = pb_base + NX_P9_DMA_CFG;
	cfg_ee = pb_base + NX_P9_EE_CFG;

	rc = nx_cfg_gzip_dma(gcid, cfg_dma);
	if (rc)
		return;

	rc = nx_cfg_gzip_ee(gcid, cfg_ee);
	if (rc)
		return;

	rc = nx_cfg_gzip_umac(node, gcid, pb_base);
	if (rc)
		return;

	prlog(PR_INFO, "NX%d: gzip Coprocessor Enabled\n", gcid);
}
