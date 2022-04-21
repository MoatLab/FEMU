// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * OPAL calls to get/set Power Shift Ratio (PSR)
 *
 * i.e. when something has to be throttled, what gets throttled?
 *
 * Copyright 2017 IBM Corp.
 */

#include <psr.h>

static int opal_get_power_shift_ratio(u32 handle, int token __unused,
				      __be32 *__ratio)
{
	if (!__ratio || !opal_addr_valid(__ratio))
		return OPAL_PARAMETER;

	if (psr_get_class(handle) == PSR_CLASS_OCC) {
		u32 ratio;
		int rc;

		rc = occ_get_psr(handle, &ratio);
		*__ratio = cpu_to_be32(ratio);
		return rc;
	}

	return OPAL_UNSUPPORTED;
};

opal_call(OPAL_GET_POWER_SHIFT_RATIO, opal_get_power_shift_ratio, 3);

static int opal_set_power_shift_ratio(u32 handle, int token,
				      u32 ratio)
{
	if (psr_get_class(handle) == PSR_CLASS_OCC)
		return occ_set_psr(handle, token, ratio);

	return OPAL_UNSUPPORTED;
};

opal_call(OPAL_SET_POWER_SHIFT_RATIO, opal_set_power_shift_ratio, 3);
