// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Load kernel modules needed for opal-prd
 *
 * Copyright 2015 IBM Corp.
 */

#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "module.h"
#include "opal-prd.h"

int insert_module(const char *module)
{
	int status;
	pid_t pid;

	pid = fork();
	if (!pid) {
		execlp("modprobe", "modprobe", module, NULL);
		err(EXIT_FAILURE, "Failed to run modprobe");
	}

	pid = waitpid(pid, &status, 0);
	if (pid < 0) {
		pr_log(LOG_ERR, "KMOD: waitpid failed for "
				"modprobe process: %m");
		return -1;
	}

	if (!WIFEXITED(status)) {
		pr_log(LOG_WARNING, "KMOD: modprobe %s: process didn't "
				"exit cleanly", module);
		return -1;
	}

	if (WEXITSTATUS(status) != 0) {
		pr_log(LOG_WARNING, "KMOD: modprobe %s failed, status %d",
				module, WEXITSTATUS(status));
		return -1;
	}

	return 0;
}

