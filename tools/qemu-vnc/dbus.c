/*
 * D-Bus interface for qemu-vnc standalone VNC server.
 *
 * Copyright (C) 2026 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"

#include "qemu/cutils.h"
#include "qapi-types-trace.h"
#include "system/system.h"
#include "qapi/qapi-types-ui.h"
#include "qapi/qapi-commands-ui.h"
#include "qemu-vnc.h"
#include "qemu-vnc1.h"
#include "qapi/qapi-emit-events.h"
#include "qobject/qdict.h"
#include "ui/vnc.h"
#include "trace.h"

typedef struct VncDbusClient {
    QemuVnc1ClientSkeleton *skeleton;
    char *path;
    char *host;
    char *service;
    unsigned int id;
    QTAILQ_ENTRY(VncDbusClient) next;
} VncDbusClient;

static QemuVnc1ServerSkeleton *server_skeleton;
static GDBusObjectManagerServer *obj_manager;
static unsigned int next_client_id;

static QTAILQ_HEAD(, VncDbusClient)
    dbus_clients = QTAILQ_HEAD_INITIALIZER(dbus_clients);

static VncDbusClient *vnc_dbus_find_client(const char *host,
                                           const char *service)
{
    VncDbusClient *c;

    QTAILQ_FOREACH(c, &dbus_clients, next) {
        if (g_str_equal(c->host, host) &&
            g_str_equal(c->service, service)) {
            return c;
        }
    }
    return NULL;
}

static void vnc_dbus_update_clients_property(void)
{
    VncDbusClient *c;
    GPtrArray *paths;
    const char **strv;

    paths = g_ptr_array_new();
    QTAILQ_FOREACH(c, &dbus_clients, next) {
        g_ptr_array_add(paths, c->path);
    }
    g_ptr_array_add(paths, NULL);

    strv = (const char **)paths->pdata;
    qemu_vnc1_server_set_clients(QEMU_VNC1_SERVER(server_skeleton), strv);
    g_ptr_array_free(paths, TRUE);
}

void vnc_dbus_client_connected(const char *host, const char *service,
                               const char *family, bool websocket)
{
    VncDbusClient *c;
    g_autoptr(GDBusObjectSkeleton) obj = NULL;

    if (!server_skeleton) {
        return;
    }

    c = g_new0(VncDbusClient, 1);
    c->id = next_client_id++;
    c->host = g_strdup(host);
    c->service = g_strdup(service);
    c->path = g_strdup_printf("/org/qemu/Vnc1/Client_%u", c->id);

    c->skeleton = QEMU_VNC1_CLIENT_SKELETON(qemu_vnc1_client_skeleton_new());
    qemu_vnc1_client_set_host(QEMU_VNC1_CLIENT(c->skeleton), host);
    qemu_vnc1_client_set_service(QEMU_VNC1_CLIENT(c->skeleton), service);
    qemu_vnc1_client_set_family(QEMU_VNC1_CLIENT(c->skeleton), family);
    qemu_vnc1_client_set_web_socket(QEMU_VNC1_CLIENT(c->skeleton), websocket);
    qemu_vnc1_client_set_x509_dname(QEMU_VNC1_CLIENT(c->skeleton), "");
    qemu_vnc1_client_set_sasl_username(QEMU_VNC1_CLIENT(c->skeleton), "");

    obj = g_dbus_object_skeleton_new(c->path);
    g_dbus_object_skeleton_add_interface(
        obj, G_DBUS_INTERFACE_SKELETON(c->skeleton));
    g_dbus_object_manager_server_export(obj_manager, obj);

    QTAILQ_INSERT_TAIL(&dbus_clients, c, next);
    vnc_dbus_update_clients_property();

    qemu_vnc1_server_emit_client_connected(
        QEMU_VNC1_SERVER(server_skeleton), c->path);
}

void vnc_dbus_client_initialized(const char *host, const char *service,
                                 const char *x509_dname,
                                 const char *sasl_username)
{
    VncDbusClient *c;

    if (!server_skeleton) {
        return;
    }

    c = vnc_dbus_find_client(host, service);
    if (!c) {
        trace_qemu_vnc_client_not_found(host, service);
        return;
    }

    if (x509_dname) {
        qemu_vnc1_client_set_x509_dname(
            QEMU_VNC1_CLIENT(c->skeleton), x509_dname);
    }
    if (sasl_username) {
        qemu_vnc1_client_set_sasl_username(
            QEMU_VNC1_CLIENT(c->skeleton), sasl_username);
    }

    qemu_vnc1_server_emit_client_initialized(
        QEMU_VNC1_SERVER(server_skeleton), c->path);
}

void vnc_dbus_client_disconnected(const char *host, const char *service)
{
    VncDbusClient *c;

    if (!server_skeleton) {
        return;
    }

    c = vnc_dbus_find_client(host, service);
    if (!c) {
        trace_qemu_vnc_client_not_found(host, service);
        return;
    }

    qemu_vnc1_server_emit_client_disconnected(
        QEMU_VNC1_SERVER(server_skeleton), c->path);

    g_dbus_object_manager_server_unexport(obj_manager, c->path);
    QTAILQ_REMOVE(&dbus_clients, c, next);
    vnc_dbus_update_clients_property();

    g_object_unref(c->skeleton);
    g_free(c->path);
    g_free(c->host);
    g_free(c->service);
    g_free(c);
}

static gboolean
on_set_password(QemuVnc1Server *iface,
                GDBusMethodInvocation *invocation,
                const gchar *password,
                gpointer user_data)
{
    Error *err = NULL;

    if (vnc_display_password("default", password, &err) < 0) {
        g_dbus_method_invocation_return_error(
            invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
            "%s", error_get_pretty(err));
        error_free(err);
        return TRUE;
    }

    qemu_vnc1_server_complete_set_password(iface, invocation);
    return TRUE;
}

static gboolean
on_expire_password(QemuVnc1Server *iface,
                   GDBusMethodInvocation *invocation,
                   const gchar *time_str,
                   gpointer user_data)
{
    time_t when;

    if (g_str_equal(time_str, "now")) {
        when = 0;
    } else if (g_str_equal(time_str, "never")) {
        when = TIME_MAX;
    } else if (time_str[0] == '+') {
        int seconds;
        if (qemu_strtoi(time_str + 1, NULL, 10, &seconds) < 0) {
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS,
                "Invalid time format: %s", time_str);
            return TRUE;
        }
        when = time(NULL) + seconds;
    } else {
        int64_t epoch;
        if (qemu_strtoi64(time_str, NULL, 10, &epoch) < 0) {
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS,
                "Invalid time format: %s", time_str);
            return TRUE;
        }
        when = epoch;
    }

    if (vnc_display_pw_expire("default", when) < 0) {
        g_dbus_method_invocation_return_error(
            invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
            "Failed to set password expiry");
        return TRUE;
    }

    qemu_vnc1_server_complete_expire_password(iface, invocation);
    return TRUE;
}

static gboolean
on_reload_certificates(QemuVnc1Server *iface,
                       GDBusMethodInvocation *invocation,
                       gpointer user_data)
{
    Error *err = NULL;

    if (!vnc_display_reload_certs("default", &err)) {
        g_dbus_method_invocation_return_error(
            invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
            "%s", error_get_pretty(err));
        error_free(err);
        return TRUE;
    }

    qemu_vnc1_server_complete_reload_certificates(iface, invocation);
    return TRUE;
}

static gboolean
on_add_client(QemuVnc1Server *iface,
              GDBusMethodInvocation *invocation,
              GUnixFDList *fd_list,
              GVariant *arg_socket,
              gboolean skipauth,
              gpointer user_data)
{
    gint32 handle = g_variant_get_handle(arg_socket);
    g_autoptr(GError) err = NULL;
    int fd;

    fd = g_unix_fd_list_get(fd_list, handle, &err);
    if (fd < 0) {
        g_dbus_method_invocation_return_error(
            invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
            "Failed to get fd: %s", err->message);
        return TRUE;
    }

    vnc_display_add_client("default", fd, skipauth);

    qemu_vnc1_server_complete_add_client(iface, invocation, NULL);
    return TRUE;
}

static void vnc_dbus_add_listeners(VncInfo2 *info)
{
    GVariantBuilder builder;
    VncServerInfo2List *entry;

    g_variant_builder_init(&builder, G_VARIANT_TYPE("aa{sv}"));

    for (entry = info->server; entry; entry = entry->next) {
        VncServerInfo2 *s = entry->value;
        const char *vencrypt_str = "";

        if (s->has_vencrypt) {
            vencrypt_str = VncVencryptSubAuth_str(s->vencrypt);
        }

        g_variant_builder_open(&builder, G_VARIANT_TYPE("a{sv}"));
        g_variant_builder_add(&builder, "{sv}", "Host",
                              g_variant_new_string(s->host));
        g_variant_builder_add(&builder, "{sv}", "Service",
                              g_variant_new_string(s->service));
        g_variant_builder_add(&builder, "{sv}", "Family",
                              g_variant_new_string(
                                  NetworkAddressFamily_str(s->family)));
        g_variant_builder_add(&builder, "{sv}", "WebSocket",
                              g_variant_new_boolean(s->websocket));
        g_variant_builder_add(&builder, "{sv}", "Auth",
                              g_variant_new_string(
                                  VncPrimaryAuth_str(s->auth)));
        g_variant_builder_add(&builder, "{sv}", "VencryptSubAuth",
                              g_variant_new_string(vencrypt_str));
        g_variant_builder_close(&builder);
    }

    qemu_vnc1_server_set_listeners(
        QEMU_VNC1_SERVER(server_skeleton),
        g_variant_builder_end(&builder));
}

void vnc_dbus_setup(GDBusConnection *bus)
{
    g_autoptr(GDBusObjectSkeleton) server_obj = NULL;
    g_autoptr(VncInfo2List) info_list = NULL;
    Error *err = NULL;
    const char *auth_str = "none";
    const char *vencrypt_str = "";

    obj_manager = g_dbus_object_manager_server_new("/org/qemu/Vnc1");

    server_skeleton = QEMU_VNC1_SERVER_SKELETON(
        qemu_vnc1_server_skeleton_new());

    qemu_vnc1_server_set_name(QEMU_VNC1_SERVER(server_skeleton),
                              qemu_name ? qemu_name : "");
    qemu_vnc1_server_set_clients(QEMU_VNC1_SERVER(server_skeleton), NULL);

    /* Query auth info from the VNC display */
    info_list = qmp_query_vnc_servers(&err);
    if (info_list) {
        VncInfo2 *info = info_list->value;
        auth_str = VncPrimaryAuth_str(info->auth);
        if (info->has_vencrypt) {
            vencrypt_str = VncVencryptSubAuth_str(info->vencrypt);
        }
        vnc_dbus_add_listeners(info);
    }

    qemu_vnc1_server_set_auth(QEMU_VNC1_SERVER(server_skeleton), auth_str);
    qemu_vnc1_server_set_vencrypt_sub_auth(
        QEMU_VNC1_SERVER(server_skeleton), vencrypt_str);

    g_signal_connect(server_skeleton, "handle-set-password",
                     G_CALLBACK(on_set_password), NULL);
    g_signal_connect(server_skeleton, "handle-expire-password",
                     G_CALLBACK(on_expire_password), NULL);
    g_signal_connect(server_skeleton, "handle-reload-certificates",
                     G_CALLBACK(on_reload_certificates), NULL);
    g_signal_connect(server_skeleton, "handle-add-client",
                     G_CALLBACK(on_add_client), NULL);

    server_obj = g_dbus_object_skeleton_new("/org/qemu/Vnc1/Server");
    g_dbus_object_skeleton_add_interface(
        server_obj, G_DBUS_INTERFACE_SKELETON(server_skeleton));
    g_dbus_object_manager_server_export(obj_manager, server_obj);

    g_dbus_object_manager_server_set_connection(obj_manager, bus);

    if (g_dbus_connection_get_flags(bus)
        & G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION) {
        g_bus_own_name_on_connection(
            bus, "org.qemu.vnc",
            G_BUS_NAME_OWNER_FLAGS_NONE,
            NULL, NULL, NULL, NULL);
    }
}

void vnc_action_shutdown(VncState *vs)
{
    VncDbusClient *c;

    c = vnc_dbus_find_client(vs->info->host, vs->info->service);
    if (!c) {
        trace_qemu_vnc_client_not_found(vs->info->host, vs->info->service);
        return;
    }

    qemu_vnc1_client_emit_shutdown_request(QEMU_VNC1_CLIENT(c->skeleton));
}

void vnc_action_reset(VncState *vs)
{
    VncDbusClient *c;

    c = vnc_dbus_find_client(vs->info->host, vs->info->service);
    if (!c) {
        trace_qemu_vnc_client_not_found(vs->info->host, vs->info->service);
        return;
    }

    qemu_vnc1_client_emit_reset_request(QEMU_VNC1_CLIENT(c->skeleton));
}

/*
 * Override the stub qapi_event_emit() to capture VNC events
 * and forward them to the D-Bus interface.
 */
void qapi_event_emit(QAPIEvent event, QDict *qdict)
{
    QDict *data, *client;
    const char *host, *service, *family;
    bool websocket;

    if (event != QAPI_EVENT_VNC_CONNECTED &&
        event != QAPI_EVENT_VNC_INITIALIZED &&
        event != QAPI_EVENT_VNC_DISCONNECTED) {
        return;
    }

    data = qdict_get_qdict(qdict, "data");
    if (!data) {
        return;
    }

    client = qdict_get_qdict(data, "client");
    if (!client) {
        return;
    }

    host = qdict_get_str(client, "host");
    service = qdict_get_str(client, "service");
    family = qdict_get_str(client, "family");
    websocket = qdict_get_bool(client, "websocket");

    switch (event) {
    case QAPI_EVENT_VNC_CONNECTED:
        vnc_dbus_client_connected(host, service, family, websocket);
        break;
    case QAPI_EVENT_VNC_INITIALIZED: {
        const char *x509_dname = NULL;
        const char *sasl_username = NULL;

        if (qdict_haskey(client, "x509_dname")) {
            x509_dname = qdict_get_str(client, "x509_dname");
        }
        if (qdict_haskey(client, "sasl_username")) {
            sasl_username = qdict_get_str(client, "sasl_username");
        }
        vnc_dbus_client_initialized(host, service,
                                    x509_dname, sasl_username);
        break;
    }
    case QAPI_EVENT_VNC_DISCONNECTED:
        vnc_dbus_client_disconnected(host, service);
        break;
    default:
        break;
    }
}

void vnc_dbus_emit_leaving(const char *reason)
{
    if (!server_skeleton) {
        return;
    }

    qemu_vnc1_server_emit_leaving(QEMU_VNC1_SERVER(server_skeleton), reason);
}

void vnc_dbus_cleanup(void)
{
    VncDbusClient *c, *next;

    QTAILQ_FOREACH_SAFE(c, &dbus_clients, next, next) {
        g_dbus_object_manager_server_unexport(obj_manager, c->path);
        QTAILQ_REMOVE(&dbus_clients, c, next);
        g_object_unref(c->skeleton);
        g_free(c->path);
        g_free(c->host);
        g_free(c->service);
        g_free(c);
    }

    g_clear_object(&server_skeleton);
    g_clear_object(&obj_manager);
}
