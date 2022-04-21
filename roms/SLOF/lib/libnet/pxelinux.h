/*****************************************************************************
 * Definitions for pxelinux-style config file support
 *
 * Copyright 2018 Red Hat, Inc.
 *
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     Thomas Huth, Red Hat Inc. - initial implementation
 *****************************************************************************/

#ifndef LIBNET_PXELINUX_H
#define LIBNET_PXELINUX_H

/* This structure holds the data from one pxelinux.cfg file entry */
struct pl_cfg_entry {
    const char *label;
    const char *kernel;
    const char *initrd;
    const char *append;
};

int pxelinux_parse_cfg(char *cfg, int cfgsize, struct pl_cfg_entry *entries,
                       int max_entries, int *def_ent);
int pxelinux_load_parse_cfg(filename_ip_t *fn_ip, uint8_t *mac, const char *uuid,
                            int retries, char *cfgbuf, int cfgsize,
                            struct pl_cfg_entry *entries,
                            int max_entries, int *def_ent);

#endif
