/*****************************************************************************
 * pxelinux.cfg-style config file support.
 *
 * See https://www.syslinux.org/wiki/index.php?title=PXELINUX for information
 * about the pxelinux config file layout.
 *
 * Copyright 2018 Red Hat, Inc.
 *
 * This program and the accompanying materials are made available under the
 * terms of the BSD License which accompanies this distribution, and is
 * available at http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     Thomas Huth, Red Hat Inc. - initial implementation
 *****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "tftp.h"
#include "pxelinux.h"

/**
 * Call tftp() and report errors (excet "file-not-found" errors)
 */
static int pxelinux_tftp_load(filename_ip_t *fnip, void *buffer, int len,
                              int retries)
{
	tftp_err_t tftp_err;
	int rc, ecode;

	rc = tftp(fnip, buffer, len, retries, &tftp_err);

	if (rc > 0) {
		printf("\r  TFTP: Received %s (%d bytes)\n",
		       fnip->filename, rc);
	} else if (rc == -3) {
		/* Ignore file-not-found (since we are probing the files)
		 * and simply erase the "Receiving data:  0 KBytes" string */
		printf("\r                           \r");
	} else {
		const char *errstr = NULL;
		rc = tftp_get_error_info(fnip, &tftp_err, rc, &errstr, &ecode);
		if (errstr)
			printf("\r  TFTP error: %s\n", errstr);
	}

	return rc;
}

/**
 * Try to load a pxelinux.cfg file by probing the possible file names.
 * Note that this function will overwrite filename_ip_t->filename.
 */
static int pxelinux_load_cfg(filename_ip_t *fn_ip, uint8_t *mac, const char *uuid,
                             int retries, char *cfgbuf, int cfgbufsize)
{
	int rc;
	unsigned idx;
	char *baseptr;

	/* Did we get a usable base directory via DHCP? */
	if (fn_ip->pl_prefix) {
		idx = strlen(fn_ip->pl_prefix);
		/* Do we have enough space left to store a UUID file name? */
		if (idx > sizeof(fn_ip->filename) - 36) {
			puts("Error: pxelinux prefix is too long!");
			return -1;
		}
		strcpy(fn_ip->filename, fn_ip->pl_prefix);
		baseptr = &fn_ip->filename[idx];
	} else {
		/* Try to get a usable base directory from the DHCP bootfile name */
		baseptr = strrchr(fn_ip->filename, '/');
		if (!baseptr)
			baseptr = fn_ip->filename;
		else
			++baseptr;
		/* Check that we've got enough space to store "pxelinux.cfg/"
		 * and the UUID (which is the longest file name) there */
		if ((size_t)(baseptr - fn_ip->filename) > (sizeof(fn_ip->filename) - 50)) {
			puts("Error: The bootfile string is too long for "
			     "deriving the pxelinux.cfg file name from it.");
			return -1;
		}
		strcpy(baseptr, "pxelinux.cfg/");
		baseptr += strlen(baseptr);
	}

	puts("Trying pxelinux.cfg files...");

	/* Try to load config file according to file name in DHCP option 209 */
	if (fn_ip->pl_cfgfile) {
		if (strlen(fn_ip->pl_cfgfile) + strlen(fn_ip->filename)
		    > sizeof(fn_ip->filename)) {
			puts("Error: pxelinux.cfg prefix + filename too long!");
			return -1;
		}
		strcpy(baseptr, fn_ip->pl_cfgfile);
		rc = pxelinux_tftp_load(fn_ip, cfgbuf, cfgbufsize, retries);
		if (rc > 0) {
			return rc;
		}
	}

	/* Try to load config file with name based on the VM UUID */
	if (uuid) {
		strcpy(baseptr, uuid);
		rc = pxelinux_tftp_load(fn_ip, cfgbuf, cfgbufsize, retries);
		if (rc > 0) {
			return rc;
		}
	}

	/* Look for config file with MAC address in its name */
	sprintf(baseptr, "01-%02x-%02x-%02x-%02x-%02x-%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	rc = pxelinux_tftp_load(fn_ip, cfgbuf, cfgbufsize, retries);
	if (rc > 0) {
		return rc;
	}

	/* Look for config file with IP address in its name */
	if (fn_ip->ip_version == 4) {
		sprintf(baseptr, "%02X%02X%02X%02X",
			(fn_ip->own_ip >> 24) & 0xff,
			(fn_ip->own_ip >> 16) & 0xff,
			(fn_ip->own_ip >> 8) & 0xff,
			fn_ip->own_ip & 0xff);
		for (idx = 0; idx <= 7; idx++) {
			baseptr[8 - idx] = 0;
			rc = pxelinux_tftp_load(fn_ip, cfgbuf, cfgbufsize,
			                        retries);
			if (rc > 0) {
				return rc;
			}
		}
	}

	/* Try "default" config file */
	strcpy(baseptr, "default");
	rc = pxelinux_tftp_load(fn_ip, cfgbuf, cfgbufsize, retries);

	return rc;
}

/**
 * Parse a pxelinux-style configuration file.
 * The discovered entries are filled into the "struct pl_cfg_entry entries[]"
 * array. Note that the callers must keep the cfg buffer valid as long as
 * they wish to access the "struct pl_cfg_entry" entries, since the pointers
 * in entries point to the original location in the cfg buffer area. The cfg
 * buffer is altered for this, too, e.g. terminating NUL-characters are put
 * into the right locations.
 * @param cfg          Pointer to the buffer with contents of the config file.
 *                     The caller must make sure that it is NUL-terminated.
 * @param cfgsize      Size of the cfg data (including the terminating NUL)
 * @param entries      Pointer to array where the results should be put into
 * @param max_entries  Number of available slots in the entries array
 * @param def_ent      Used to return the index of the default entry
 * @return             Number of valid entries
 */
int pxelinux_parse_cfg(char *cfg, int cfgsize, struct pl_cfg_entry *entries,
                       int max_entries, int *def_ent)
{
	int num_entries = 0;
	char *ptr = cfg, *nextptr, *eol, *arg;
	char *defaultlabel = NULL;

	*def_ent = 0;

	while (ptr < cfg + cfgsize && num_entries < max_entries) {
		eol = strchr(ptr, '\n');
		if (!eol) {
			eol = cfg + cfgsize - 1;
		}
		nextptr = eol + 1;
		do {
			*eol-- = '\0';	/* Remove spaces, tabs and returns */
		} while (eol >= ptr &&
		         (*eol == '\r' || *eol == ' ' || *eol == '\t'));
		while (*ptr == ' ' || *ptr == '\t') {
			ptr++;
		}
		if (*ptr == 0 || *ptr == '#') {
			goto nextline;	/* Ignore comments and empty lines */
		}
		arg = strchr(ptr, ' ');	/* Search space between cmnd and arg */
		if (!arg) {
			arg = strchr(ptr, '\t');
		}
		if (!arg) {
			printf("Failed to parse this line:\n %s\n", ptr);
			goto nextline;
		}
		*arg++ = 0;
		while (*arg == ' ' || *arg == '\t') {
			arg++;
		}
		if (!strcasecmp("default", ptr)) {
			defaultlabel = arg;
		} else if (!strcasecmp("label", ptr)) {
			entries[num_entries].label = arg;
			if (defaultlabel && !strcmp(arg, defaultlabel)) {
				*def_ent = num_entries;
			}
			num_entries++;
		} else if (!strcasecmp("kernel", ptr) && num_entries) {
			entries[num_entries - 1].kernel = arg;
		} else if (!strcasecmp("initrd", ptr) && num_entries) {
			entries[num_entries - 1].initrd = arg;
		} else if (!strcasecmp("append", ptr) && num_entries) {
			entries[num_entries - 1].append = arg;
		} else {
			printf("Command '%s' is not supported.\n", ptr);
		}
nextline:
		ptr = nextptr;
	}

	return num_entries;
}

/**
 * Try to load and parse a pxelinux-style configuration file.
 * @param fn_ip        must contain server and client IP information
 * @param mac          MAC address which should be used for probing
 * @param uuid         UUID which should be used for probing (can be NULL)
 * @param retries      Amount of TFTP retries before giving up
 * @param cfgbuf       Pointer to the buffer where config file should be loaded
 * @param cfgsize      Size of the cfgbuf buffer
 * @param entries      Pointer to array where the results should be put into
 * @param max_entries  Number of available slots in the entries array
 * @param def_ent      Used to return the index of the default entry
 * @return             Number of valid entries
 */
int pxelinux_load_parse_cfg(filename_ip_t *fn_ip, uint8_t *mac, const char *uuid,
                            int retries, char *cfgbuf, int cfgsize,
                            struct pl_cfg_entry *entries, int max_entries,
                            int *def_ent)
{
	int rc;

	rc = pxelinux_load_cfg(fn_ip, mac, uuid, retries, cfgbuf, cfgsize - 1);
	if (rc < 0)
		return rc;
	assert(rc < cfgsize);

	cfgbuf[rc++] = '\0';	/* Make sure it is NUL-terminated */

	return pxelinux_parse_cfg(cfgbuf, rc, entries, max_entries, def_ent);
}
