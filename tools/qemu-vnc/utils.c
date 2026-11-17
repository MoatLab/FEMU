/*
 * Standalone VNC server connecting to QEMU via D-Bus display interface.
 *
 * Copyright (C) 2026 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"

#include "qemu/error-report.h"
#include "qemu-vnc.h"

static GDBusConnection *
dbus_p2p_from_fd(int fd)
{
    g_autoptr(GError) err = NULL;
    g_autoptr(GSocket) socket = NULL;
    g_autoptr(GSocketConnection) socketc = NULL;
    GDBusConnection *conn;

    socket = g_socket_new_from_fd(fd, &err);
    if (!socket) {
        error_report("Failed to create socket: %s", err->message);
        return NULL;
    }

    socketc = g_socket_connection_factory_create_connection(socket);
    if (!socketc) {
        error_report("Failed to create socket connection");
        return NULL;
    }

    conn = g_dbus_connection_new_sync(
        G_IO_STREAM(socketc), NULL,
        G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
        G_DBUS_CONNECTION_FLAGS_DELAY_MESSAGE_PROCESSING,
        NULL, NULL, &err);
    if (!conn) {
        error_report("Failed to create D-Bus connection: %s", err->message);
        return NULL;
    }

    return conn;
}

static gpointer
p2p_server_setup_thread(gpointer data)
{
    return dbus_p2p_from_fd(GPOINTER_TO_INT(data));
}

GThread *
p2p_dbus_thread_new(int fd)
{
    return g_thread_new("p2p-server-setup",
                         p2p_server_setup_thread,
                         GINT_TO_POINTER(fd));
}
