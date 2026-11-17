/*
 * Utility function to get QEMU's own process map
 *
 * Copyright (c) 2020 Linaro Ltd
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "user/selfmap.h"
#ifdef __FreeBSD__
#include <sys/sysctl.h>
#include <sys/user.h>
#endif

IntervalTreeRoot *read_self_maps(void)
{
#ifdef __linux__
    IntervalTreeRoot *root;
    gchar *maps, **lines;
    guint i, nlines;

    if (!g_file_get_contents("/proc/self/maps", &maps, NULL, NULL)) {
        return NULL;
    }

    root = g_new0(IntervalTreeRoot, 1);
    lines = g_strsplit(maps, "\n", 0);
    nlines = g_strv_length(lines);

    for (i = 0; i < nlines; i++) {
        gchar **fields = g_strsplit(lines[i], " ", 6);
        guint nfields = g_strv_length(fields);

        if (nfields > 4) {
            uint64_t start, end, offset, inode;
            unsigned dev_maj, dev_min;
            int errors = 0;
            const char *p;

            errors |= qemu_strtou64(fields[0], &p, 16, &start);
            errors |= qemu_strtou64(p + 1, NULL, 16, &end);
            errors |= qemu_strtou64(fields[2], NULL, 16, &offset);
            errors |= qemu_strtoui(fields[3], &p, 16, &dev_maj);
            errors |= qemu_strtoui(p + 1, NULL, 16, &dev_min);
            errors |= qemu_strtou64(fields[4], NULL, 10, &inode);

            if (!errors) {
                size_t path_len;
                MapInfo *e;

                if (nfields == 6) {
                    p = fields[5];
                    p += strspn(p, " ");
                    path_len = strlen(p) + 1;
                } else {
                    p = NULL;
                    path_len = 0;
                }

                e = g_malloc0(sizeof(*e) + path_len);

                e->itree.start = start;
                e->itree.last = end - 1;
                e->offset = offset;
                e->dev = makedev(dev_maj, dev_min);
                e->inode = inode;

                e->is_read  = fields[1][0] == 'r';
                e->is_write = fields[1][1] == 'w';
                e->is_exec  = fields[1][2] == 'x';
                e->is_priv  = fields[1][3] == 'p';

                if (path_len) {
                    e->path = memcpy(e + 1, p, path_len);
                }

                interval_tree_insert(&e->itree, root);
            }
        }
        g_strfreev(fields);
    }
    g_strfreev(lines);
    g_free(maps);

    return root;
#elif defined(__FreeBSD__)
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_VMMAP, getpid() };
    size_t len = 0;
    g_autofree void *buf = NULL;
    IntervalTreeRoot *root;

    /* Probe for buffer size. */
    if (sysctl(mib, ARRAY_SIZE(mib), NULL, &len, NULL, 0) < 0) {
        return NULL;
    }

    buf = g_malloc(len);
    if (sysctl(mib, ARRAY_SIZE(mib), buf, &len, NULL, 0) < 0) {
        return NULL;
    }

    root = g_new0(IntervalTreeRoot, 1);

    for (size_t i = 0; i < len; ) {
        struct kinfo_vmentry *k = buf + i;
        MapInfo *e = g_new0(MapInfo, 1);

        e->itree.start = k->kve_start;
        e->itree.last = k->kve_end - 1;

        /*
         * TODO: The rest of the fields in MapInfo are used by linux-user
         * for the implementation of open_self_maps().  These fields are
         * quite specific to the textual format of /proc/self/maps.
         *
         * We may need something different to emulate KERN_PROC_VMMAP
         * in bsd-user, but so far they're unused -- leave them zeroed.
         */

        interval_tree_insert(&e->itree, root);
        i += k->kve_structsize;
    }

    return root;
#else
# error
#endif
}

/**
 * free_self_maps:
 * @root: an interval tree
 *
 * Free a tree of MapInfo structures.
 * Since we allocated each MapInfo in one chunk, we need not consider the
 * contents and can simply free each RBNode.
 */

static void free_rbnode(RBNode *n)
{
    if (n) {
        free_rbnode(n->rb_left);
        free_rbnode(n->rb_right);
        g_free(n);
    }
}

void free_self_maps(IntervalTreeRoot *root)
{
    if (root) {
        free_rbnode(root->rb_root.rb_node);
        g_free(root);
    }
}
