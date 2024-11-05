// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * NX Cryptographic accellerators
 *
 * Copyright 2015-2019 IBM Corp.
 */

#include <skiboot.h>
#include <chip.h>
#include <xscom.h>
#include <io.h>
#include <cpu.h>
#include <nx.h>

/* Configuration settings  */
#define CFG_SYM_FC_ENABLE	(0) /* disable all sym functions */
#define CFG_SYM_ENABLE		(0) /* disable sym engines */
#define CFG_ASYM_FC_ENABLE	(0) /* disable all asym functions */
#define CFG_ASYM_ENABLE		(0) /* disable asym engines */
#define CFG_CRB_IQ_SYM		(0) /* don't use any extra input queues */
#define CFG_CRB_IQ_ASYM	(0) /* don't use any extra input queues */
#define AES_SHA_MAX_RR		(1) /* valid range: 1-8 */
#define AES_SHA_CSB_WR		NX_DMA_CSB_WR_PDMA
#define AES_SHA_COMPLETION_MODE	NX_DMA_COMPLETION_MODE_PDMA
#define AES_SHA_CPB_WR		NX_DMA_CPB_WR_DMA_NOPAD
#define AES_SHA_OUTPUT_DATA_WR	NX_DMA_OUTPUT_DATA_WR_DMA
#define AMF_MAX_RR		(1) /* valid range: 1-8 */
#define AMF_CSB_WR		NX_DMA_CSB_WR_PDMA
#define AMF_COMPLETION_MODE	NX_DMA_COMPLETION_MODE_PDMA
#define AMF_CPB_WR		(0) /* CPB WR not done with AMF */
#define AMF_OUTPUT_DATA_WR	NX_DMA_OUTPUT_DATA_WR_DMA
#define EE_CH7			(0) /* disable engine AMF 3(P8) */
#define EE_CH6			(0) /* disable engine AMF 2(P8) */
#define EE_CH5			(0) /* disable engine AMF 1(P8) */
#define EE_CH4			(0) /* disable engine SYM AMF 0(P8) */
#define EE_CH3			(0) /* disable engine SYM 1 */
#define EE_CH2			(0) /* disable engine SYM 0 */

static int nx_cfg_sym(u32 gcid, u64 xcfg)
{
	u64 cfg, ci, ct;
	int rc, instance = gcid + 1;

	BUILD_ASSERT(MAX_CHIPS < NX_SYM_CFG_CI_MAX);

	rc = xscom_read(gcid, xcfg, &cfg);
	if (rc) {
                prerror("NX%d: ERROR: XSCOM SYM config read failure %d\n",
		 gcid, rc);
		return rc;
	}

	ct = GETFIELD(NX_SYM_CFG_CT, cfg);
	if (!ct)
		prlog(PR_INFO, "NX%d:   SYM CT set to %u\n", gcid, NX_CT_SYM);
	else if (ct == NX_CT_SYM)
		prlog(PR_INFO, "NX%d:   SYM CT already set to %u\n",
		      gcid, NX_CT_SYM);
	else
		prlog(PR_INFO, "NX%d:   SYM CT already set to %u, "
		      "changing to %u\n", gcid, (unsigned int)ct, NX_CT_SYM);
	ct = NX_CT_SYM;
	cfg = SETFIELD(NX_SYM_CFG_CT, cfg, ct);

	/* Coprocessor Instance must be shifted left.
	 * See hw doc Section 5.5.1.
	 */
	ci = GETFIELD(NX_SYM_CFG_CI, cfg) >> NX_SYM_CFG_CI_LSHIFT;
	if (!ci)
		prlog(PR_INFO, "NX%d:   SYM CI set to %d\n", gcid, instance);
	else if (ci == instance)
		prlog(PR_INFO, "NX%d:   SYM CI already set to %u\n", gcid,
		      (unsigned int)ci);
	else
		prlog(PR_INFO, "NX%d:   SYM CI already set to %u, "
		      "changing to %d\n", gcid, (unsigned int)ci, instance);
	ci = instance;
	cfg = SETFIELD(NX_SYM_CFG_CI, cfg, ci << NX_SYM_CFG_CI_LSHIFT);

	cfg = SETFIELD(NX_SYM_CFG_FC_ENABLE, cfg, CFG_SYM_FC_ENABLE);

	cfg = SETFIELD(NX_SYM_CFG_ENABLE, cfg, CFG_SYM_ENABLE);

	rc = xscom_write(gcid, xcfg, cfg);
	if (rc)
		prerror("NX%d: ERROR: SYM CT %u CI %u config failure %d\n",
			gcid, (unsigned int)ct, (unsigned int)ci, rc);
	else
		prlog(PR_DEBUG, "NX%d:   SYM Config 0x%016lx\n",
		      gcid, (unsigned long)cfg);

	return rc;
}

static int nx_cfg_asym(u32 gcid, u64 xcfg)
{
	u64 cfg, ci, ct;
	int rc, instance = gcid + 1;

	BUILD_ASSERT(MAX_CHIPS < NX_ASYM_CFG_CI_MAX);

	rc = xscom_read(gcid, xcfg, &cfg);
	if (rc) {
                prerror("NX%d: ERROR: XSCOM ASYM config read failure %d\n",
		 gcid, rc);
		return rc;
	}

	ct = GETFIELD(NX_ASYM_CFG_CT, cfg);
	if (!ct)
		prlog(PR_INFO, "NX%d:   ASYM CT set to %u\n",
		      gcid, NX_CT_ASYM);
	else if (ct == NX_CT_ASYM)
		prlog(PR_INFO, "NX%d:   ASYM CT already set to %u\n",
		      gcid, NX_CT_ASYM);
	else
		prlog(PR_INFO, "NX%d:   ASYM CT already set to %u, "
		      "changing to %u\n", gcid, (unsigned int)ct, NX_CT_ASYM);
	ct = NX_CT_ASYM;
	cfg = SETFIELD(NX_ASYM_CFG_CT, cfg, ct);

	/* Coprocessor Instance must be shifted left.
	 * See hw doc Section 5.5.1.
	 */
	ci = GETFIELD(NX_ASYM_CFG_CI, cfg) >> NX_ASYM_CFG_CI_LSHIFT;
	if (!ci)
		prlog(PR_INFO, "NX%d:   ASYM CI set to %d\n", gcid, instance);
	else if (ci == instance)
		prlog(PR_INFO, "NX%d:   ASYM CI already set to %u\n", gcid,
		      (unsigned int)ci);
	else
		prlog(PR_INFO, "NX%d:   ASYM CI already set to %u, "
		      "changing to %d\n", gcid, (unsigned int)ci, instance);
	ci = instance;
	cfg = SETFIELD(NX_ASYM_CFG_CI, cfg, ci << NX_ASYM_CFG_CI_LSHIFT);

	cfg = SETFIELD(NX_ASYM_CFG_FC_ENABLE, cfg, CFG_ASYM_FC_ENABLE);

	cfg = SETFIELD(NX_ASYM_CFG_ENABLE, cfg, CFG_ASYM_ENABLE);

	rc = xscom_write(gcid, xcfg, cfg);
	if (rc)
		prerror("NX%d: ERROR: ASYM CT %u CI %u config failure %d\n",
			gcid, (unsigned int)ct, (unsigned int)ci, rc);
	else
		prlog(PR_DEBUG, "NX%d:   ASYM Config 0x%016lx\n",
		      gcid, (unsigned long)cfg);

	return rc;
}

static int nx_cfg_dma(u32 gcid, u64 xcfg)
{
	u64 cfg;
	int rc;

	rc = xscom_read(gcid, xcfg, &cfg);
	if (rc) {
                prerror("NX%d: ERROR: XSCOM DMA config read failure %d\n",
		 gcid, rc);
		return rc;
	}

	cfg = SETFIELD(NX_DMA_CFG_AES_SHA_MAX_RR, cfg,
		       AES_SHA_MAX_RR);
	cfg = SETFIELD(NX_DMA_CFG_AES_SHA_CSB_WR, cfg,
		       AES_SHA_CSB_WR);
	cfg = SETFIELD(NX_DMA_CFG_AES_SHA_COMPLETION_MODE, cfg,
		       AES_SHA_COMPLETION_MODE);
	cfg = SETFIELD(NX_DMA_CFG_AES_SHA_CPB_WR, cfg,
		       AES_SHA_CPB_WR);
	cfg = SETFIELD(NX_DMA_CFG_AES_SHA_OUTPUT_DATA_WR, cfg,
		       AES_SHA_OUTPUT_DATA_WR);

	cfg = SETFIELD(NX_DMA_CFG_AMF_MAX_RR, cfg,
		       AMF_MAX_RR);
	cfg = SETFIELD(NX_DMA_CFG_AMF_CSB_WR, cfg,
		       AMF_CSB_WR);
	cfg = SETFIELD(NX_DMA_CFG_AMF_COMPLETION_MODE, cfg,
		       AMF_COMPLETION_MODE);
	cfg = SETFIELD(NX_DMA_CFG_AMF_CPB_WR, cfg,
		       AMF_CPB_WR);
	cfg = SETFIELD(NX_DMA_CFG_AMF_OUTPUT_DATA_WR, cfg,
		       AMF_OUTPUT_DATA_WR);

	rc = xscom_write(gcid, xcfg, cfg);
	if (rc)
		prerror("NX%d: ERROR: DMA config failure %d\n", gcid, rc);
	else
		prlog(PR_DEBUG, "NX%d:   DMA 0x%016lx\n", gcid,
		      (unsigned long)cfg);

	return rc;
}

static int nx_cfg_iq(u32 gcid, u64 xcfg)
{
	u64 cfg;
	int rc;

	rc = xscom_read(gcid, xcfg, &cfg);
	if (rc) {
                prerror("NX%d: ERROR: XSCOM CRB IQ config read failure %d\n",
		 gcid, rc);
		return rc;
	}

	cfg = SETFIELD(NX_CRB_IQ_SYM, cfg, CFG_CRB_IQ_SYM);
	cfg = SETFIELD(NX_CRB_IQ_ASYM, cfg, CFG_CRB_IQ_ASYM);

	rc = xscom_write(gcid, xcfg, cfg);
	if (rc)
		prerror("NX%d: ERROR: CRB Input Queue failure %d\n", gcid, rc);
	else
		prlog(PR_DEBUG, "NX%d:   CRB Input Queue 0x%016lx\n",
		      gcid, (unsigned long)cfg);

	return rc;
}

static int nx_cfg_ee(u32 gcid, u64 xcfg)
{
	u64 cfg;
	int rc;

	rc = xscom_read(gcid, xcfg, &cfg);
	if (rc) {
                prerror("NX%d: ERROR: XSCOM EE config read failure %d\n",
		 gcid, rc);
		return rc;
	}

	cfg = SETFIELD(NX_EE_CFG_CH7, cfg, EE_CH7);
	cfg = SETFIELD(NX_EE_CFG_CH6, cfg, EE_CH6);
	cfg = SETFIELD(NX_EE_CFG_CH5, cfg, EE_CH5);
	cfg = SETFIELD(NX_EE_CFG_CH4, cfg, EE_CH4);
	cfg = SETFIELD(NX_EE_CFG_CH3, cfg, EE_CH3);
	cfg = SETFIELD(NX_EE_CFG_CH2, cfg, EE_CH2);

	rc = xscom_write(gcid, xcfg, cfg);
	if (rc)
		prerror("NX%d: ERROR: Engine Enable failure %d\n", gcid, rc);
	else
		prlog(PR_DEBUG, "NX%d:   Engine Enable 0x%016lx\n",
		      gcid, (unsigned long)cfg);

	return rc;
}

void nx_create_crypto_node(struct dt_node *node)
{
	u32 gcid;
	u32 pb_base;
	u64 cfg_dma, cfg_sym, cfg_asym, cfg_iq, cfg_ee;
	int rc;

	gcid = dt_get_chip_id(node);
	pb_base = dt_get_address(node, 0, NULL);

	prlog(PR_INFO, "NX%d: Crypto at 0x%x\n", gcid, pb_base);

	if (dt_node_is_compatible(node, "ibm,power8-nx")) {
		cfg_dma = pb_base + NX_P8_DMA_CFG;
		cfg_sym = pb_base + NX_P8_SYM_CFG;
		cfg_asym = pb_base + NX_P8_ASYM_CFG;
		cfg_iq = pb_base + NX_P8_CRB_IQ;
		cfg_ee = pb_base + NX_P8_EE_CFG;
	} else if (dt_node_is_compatible(node, "ibm,power9-nx")) {
		prlog(PR_INFO, "NX%d: POWER9 nx-crypto not yet supported\n",
		      gcid);
		return;
	} else {
		prerror("NX%d: ERROR: Unknown NX type!\n", gcid);
		return;
	}

	rc = nx_cfg_dma(gcid, cfg_dma);
	if (rc)
		return;

	rc = nx_cfg_sym(gcid, cfg_sym);
	if (rc)
		return;

	rc = nx_cfg_asym(gcid, cfg_asym);
	if (rc)
		return;

	rc = nx_cfg_iq(gcid, cfg_iq);
	if (rc)
		return;

	rc = nx_cfg_ee(gcid, cfg_ee);
	if (rc)
		return;

	prlog(PR_INFO, "NX%d: Crypto Coprocessors Disabled (not supported)\n", gcid);
}
