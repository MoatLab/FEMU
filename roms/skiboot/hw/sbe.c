// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

/*
 * SBE communication driver (common code)
 */

#define pr_fmt(fmt) "SBE: " fmt

#include <sbe.h>
#include <sbe-p8.h>
#include <sbe-p9.h>
#include <skiboot.h>
#include <stdbool.h>

bool sbe_has_timer = false;
bool sbe_timer_good = false;

void sbe_update_timer_expiry(uint64_t target)
{
	assert(sbe_has_timer);

	if (proc_gen == proc_gen_p9 || proc_gen == proc_gen_p10 || proc_gen == proc_gen_p11)
		p9_sbe_update_timer_expiry(target);

#ifdef CONFIG_P8
	if (proc_gen == proc_gen_p8)
		p8_sbe_update_timer_expiry(target);
#endif
}

bool sbe_timer_ok(void)
{
	return sbe_timer_good;
}

bool sbe_timer_present(void)
{
	return sbe_has_timer;
}
