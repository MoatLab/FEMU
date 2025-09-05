// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2021 Stewart Smith */

#define pr_fmt(fmt)  "HWPROBE: " fmt
#include <skiboot.h>
#include <string.h>

static bool hwprobe_deps_satisfied(const struct hwprobe *hwp)
{
	struct hwprobe *hwprobe;
	const char **dep;
	unsigned int i;

	dep = hwp->deps;
	if (dep == NULL)
		return true;


	prlog(PR_TRACE, "Checking deps for %s\n", hwp->name);

	while (*dep != NULL) {
		prlog(PR_TRACE, "Checking %s dep %s\n", hwp->name, *dep);
		hwprobe = &__hwprobes_start;
		for (i = 0; &hwprobe[i] < &__hwprobes_end; i++) {
			if(strcmp(hwprobe[i].name, *dep) == 0 &&
			   !hwprobe[i].probed)
				return false;
		}
		dep++;
	}

	prlog(PR_TRACE, "deps for %s are satisfied!\n", hwp->name);
	return true;

}

void probe_hardware(void)
{
	struct hwprobe *hwprobe;
	unsigned int i;
	bool work_todo = true;
	bool did_something = true;

	while (work_todo) {
		work_todo = false;
		did_something = false;
		hwprobe = &__hwprobes_start;
		prlog(PR_DEBUG, "Begin loop\n");
		for (i = 0; &hwprobe[i] < &__hwprobes_end; i++) {
			if (hwprobe[i].probed)
				continue;
			if (hwprobe_deps_satisfied(&hwprobe[i])) {
				prlog(PR_DEBUG, "Probing %s...\n", hwprobe[i].name);
				if (hwprobe[i].probe)
					hwprobe[i].probe();
				did_something = true;
				hwprobe[i].probed = true;
			} else {
				prlog(PR_DEBUG, "Dependencies for %s not yet satisfied, skipping\n",
				      hwprobe[i].name);
				work_todo = true;
			}
		}

		if (work_todo && !did_something) {
			prlog(PR_ERR, "Cannot satisfy dependencies! Bailing out\n");
			break;
		}
	}
}
