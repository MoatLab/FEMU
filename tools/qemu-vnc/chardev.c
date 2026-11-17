/*
 * Standalone VNC server connecting to QEMU via D-Bus display interface.
 *
 * Copyright (C) 2026 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"

#include "qemu/sockets.h"
#include "qemu/error-report.h"
#include "qapi/util.h"
#include "qapi-types-char.h"
#include "ui/dbus-display1.h"
#include "trace.h"
#include "qemu-vnc.h"

typedef struct ChardevRegisterData {
    QemuDBusDisplay1Chardev *proxy;
    int local_fd;
    char *name;
    bool echo;
    ChardevVCEncoding encoding;
} ChardevRegisterData;

static void
on_chardev_register_finished(GObject *source_object,
                             GAsyncResult *res,
                             gpointer user_data)
{
    ChardevRegisterData *data = user_data;
    g_autoptr(GError) err = NULL;
    QemuTextConsole *tc;

    if (!qemu_dbus_display1_chardev_call_register_finish(
            data->proxy, NULL, res, &err)) {
        error_report("Chardev Register failed for %s: %s",
                     data->name, err->message);
        close(data->local_fd);
        goto out;
    }

    tc = qemu_vnc_text_console_new(data->name, data->local_fd, data->echo,
                                   data->encoding);
    if (!tc) {
        close(data->local_fd);
        goto out;
    }

    trace_qemu_vnc_chardev_connected(data->name);

out:
    g_object_unref(data->proxy);
    g_free(data->name);
    g_free(data);
}

/* Default chardevs to expose as VNC text consoles */
static const char * const default_names[] = {
    "org.qemu.console.serial.0",
    "org.qemu.monitor.hmp.0",
    NULL,
};

/* Active chardev names list (points to CLI args or default_names) */
static const char * const *names;

static void
chardev_register(QemuDBusDisplay1Chardev *proxy,
                 ChardevVCEncoding encoding)
{
    g_autoptr(GUnixFDList) fd_list = NULL;
    ChardevRegisterData *data;
    const char *name;
    int pair[2];
    int idx;

    name = qemu_dbus_display1_chardev_get_name(proxy);
    if (!name || !g_strv_contains(names, name)) {
        return;
    }

    if (qemu_socketpair(AF_UNIX, SOCK_STREAM, 0, pair) < 0) {
        error_report("chardev socketpair failed: %s", strerror(errno));
        return;
    }

    fd_list = g_unix_fd_list_new();
    idx = g_unix_fd_list_append(fd_list, pair[1], NULL);
    close(pair[1]);

    data = g_new0(ChardevRegisterData, 1);
    data->proxy = g_object_ref(proxy);
    data->local_fd = pair[0];
    data->name = g_strdup(name);
    data->echo = qemu_dbus_display1_chardev_get_echo(proxy);
    data->encoding = encoding;

    qemu_dbus_display1_chardev_call_register(
        proxy, g_variant_new_handle(idx),
        G_DBUS_CALL_FLAGS_NONE, -1,
        fd_list, NULL,
        on_chardev_register_finished, data);
}

void chardev_setup(const char * const *chardev_names,
                   GDBusObjectManager *manager)
{
    GList *objects, *l;

    names = chardev_names ? chardev_names : default_names;

    objects = g_dbus_object_manager_get_objects(manager);
    for (l = objects; l; l = l->next) {
        GDBusObject *obj = l->data;
        const char *path = g_dbus_object_get_object_path(obj);
        g_autoptr(GDBusInterface) iface = NULL;
        g_autoptr(GDBusInterface) enc_iface = NULL;
        ChardevVCEncoding encoding = CHARDEV_VC_ENCODING_UTF8;

        if (!g_str_has_prefix(path, DBUS_DISPLAY1_ROOT "/Chardev_")) {
            continue;
        }

        iface = g_dbus_object_get_interface(
            obj, "org.qemu.Display1.Chardev");
        if (!iface) {
            continue;
        }

        enc_iface = g_dbus_object_get_interface(
            obj, "org.qemu.Display1.Chardev.VCEncoding");
        if (enc_iface) {
            const char *enc_str =
                qemu_dbus_display1_chardev_vcencoding_get_encoding(
                    QEMU_DBUS_DISPLAY1_CHARDEV_VCENCODING(enc_iface));
            int enc = qapi_enum_parse(&ChardevVCEncoding_lookup,
                                      enc_str, -1, NULL);
            if (enc >= 0) {
                encoding = enc;
            }
        }

        chardev_register(QEMU_DBUS_DISPLAY1_CHARDEV(iface), encoding);
    }
    g_list_free_full(objects, g_object_unref);
}
