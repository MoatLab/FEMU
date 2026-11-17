/*
 * D-Bus VNC server (qemu-vnc) end-to-end test
 *
 * Copyright (c) 2026 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include <gio/gio.h>
#include <gvnc.h>
#include <sys/un.h>
#include "qemu/sockets.h"
#include "libqtest.h"
#include "qemu-vnc1.h"
#ifdef CONFIG_TASN1
#include "tests/unit/crypto-tls-x509-helpers.h"
#endif

#define VNC_TEST_TIMEOUT_MS 10000

typedef struct DbusTest {
    QTestState *qts;
    GSubprocess *vnc_subprocess;
    GTestDBus *bus;
    GDBusConnection *bus_conn;
    GMainLoop *loop;
    char *vnc_sock_path;
    char *tmp_dir;
    char *bus_addr;
} DbusTest;

typedef struct LifecycleData {
    DbusTest *dt;
    QemuVnc1Server *server_proxy;
    VncConnection *conn;
    char *client_path;
    gboolean got_connected;
    gboolean got_initialized;
    gboolean got_disconnected;
} LifecycleData;

static QemuVnc1Server *
create_server_proxy(GDBusConnection *bus_conn, GError **errp)
{
    return qemu_vnc1_server_proxy_new_sync(
        bus_conn,
        G_DBUS_PROXY_FLAGS_NONE,
        "org.qemu.vnc",
        "/org/qemu/Vnc1/Server",
        NULL, errp);
}

static void
on_vnc_error(VncConnection *self, const char *msg)
{
    g_error("vnc-error: %s", msg);
}

static void
on_vnc_auth_failure(VncConnection *self, const char *msg)
{
    g_error("vnc-auth-failure: %s", msg);
}

static void
on_vnc_initialized(VncConnection *self, GMainLoop *loop)
{
    const char *name = vnc_connection_get_name(self);

    g_assert_cmpstr(name, ==, "QEMU (dbus-vnc-test)");
    g_main_loop_quit(loop);
}

static gboolean
timeout_cb(gpointer data)
{
    g_error("test timed out");
    return G_SOURCE_REMOVE;
}

static int
connect_unix_socket(const char *path)
{
    int fd;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    g_assert(fd >= 0);

    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int
wait_for_vnc_socket(const char *path, int timeout_ms)
{
    int elapsed = 0;
    const int interval = 50;

    while (elapsed < timeout_ms) {
        int fd = connect_unix_socket(path);

        if (fd >= 0) {
            return fd;
        }

        g_usleep(interval * 1000);
        elapsed += interval;
    }
    return -1;
}

static GSubprocess *
spawn_qemu_vnc(int dbus_fd, const char *sock_path)
{
    const char *binary;
    g_autoptr(GError) err = NULL;
    g_autoptr(GSubprocessLauncher) launcher = NULL;
    GSubprocess *proc;
    g_autofree char *fd_str = NULL;
    g_autofree char *vnc_addr = NULL;

    binary = g_getenv("QTEST_QEMU_VNC_BINARY");
    g_assert(binary != NULL);

    fd_str = g_strdup_printf("%d", dbus_fd);
    vnc_addr = g_strdup_printf("unix:%s", sock_path);

    launcher = g_subprocess_launcher_new(G_SUBPROCESS_FLAGS_NONE);
    g_subprocess_launcher_take_fd(launcher, dbus_fd, dbus_fd);

    proc = g_subprocess_launcher_spawn(launcher, &err,
                                       binary,
                                       "--dbus-p2p-fd", fd_str,
                                       "--vnc-addr", vnc_addr,
                                       NULL);
    g_assert_no_error(err);
    g_assert(proc != NULL);

    return proc;
}

static GSubprocess *
spawn_qemu_vnc_bus_full(const char *dbus_addr, const char *sock_path,
                        const char *const *extra_args)
{
    const char *binary;
    g_autoptr(GError) err = NULL;
    g_autoptr(GSubprocessLauncher) launcher = NULL;
    g_autoptr(GPtrArray) argv = NULL;
    GSubprocess *proc;
    g_autofree char *vnc_addr = NULL;

    binary = g_getenv("QTEST_QEMU_VNC_BINARY");
    g_assert(binary != NULL);

    vnc_addr = g_strdup_printf("unix:%s", sock_path);

    argv = g_ptr_array_new();
    g_ptr_array_add(argv, (gpointer)binary);
    g_ptr_array_add(argv, (gpointer)"--dbus-address");
    g_ptr_array_add(argv, (gpointer)dbus_addr);
    g_ptr_array_add(argv, (gpointer)"--bus-name");
    g_ptr_array_add(argv, (gpointer)"org.qemu");
    g_ptr_array_add(argv, (gpointer)"--vnc-addr");
    g_ptr_array_add(argv, (gpointer)vnc_addr);

    if (extra_args) {
        for (int i = 0; extra_args[i]; i++) {
            g_ptr_array_add(argv, (gpointer)extra_args[i]);
        }
    }

    g_ptr_array_add(argv, NULL);

    launcher = g_subprocess_launcher_new(G_SUBPROCESS_FLAGS_NONE);
    proc = g_subprocess_launcher_spawnv(launcher,
        (const char *const *)argv->pdata, &err);
    g_assert_no_error(err);
    g_assert(proc != NULL);

    return proc;
}


static void
name_appeared_cb(GDBusConnection *connection,
                 const gchar *name,
                 const gchar *name_owner,
                 gpointer user_data)
{
    gboolean *appeared = user_data;
    *appeared = TRUE;
}

static bool
setup_dbus_test_full(DbusTest *dt, const char *const *vnc_extra_args)
{
    g_autoptr(GError) err = NULL;
    g_auto(GStrv) addr_parts = NULL;
    g_autofree char *qemu_args = NULL;

    if (!g_getenv("QTEST_QEMU_VNC_BINARY")) {
        g_test_skip("QTEST_QEMU_VNC_BINARY not set");
        return false;
    }

    dt->bus = g_test_dbus_new(G_TEST_DBUS_NONE);
    g_test_dbus_up(dt->bus);

    /* remove ,guid=foo part */
    addr_parts = g_strsplit(g_test_dbus_get_bus_address(dt->bus), ",", 2);
    dt->bus_addr = g_strdup(addr_parts[0]);

    dt->bus_conn = g_dbus_connection_new_for_address_sync(
        g_test_dbus_get_bus_address(dt->bus),
        G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
        G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
        NULL, NULL, &err);
    g_assert_no_error(err);

    qemu_args = g_strdup_printf("-display dbus,addr=%s "
                                "-name dbus-vnc-test", dt->bus_addr);
    dt->qts = qtest_init(qemu_args);

    dt->tmp_dir = g_dir_make_tmp("dbus-vnc-test-XXXXXX", NULL);
    g_assert(dt->tmp_dir != NULL);
    dt->vnc_sock_path = g_build_filename(dt->tmp_dir, "vnc.sock", NULL);
    dt->vnc_subprocess = spawn_qemu_vnc_bus_full(dt->bus_addr,
                                                 dt->vnc_sock_path,
                                                 vnc_extra_args);

    /*
     * Wait for the org.qemu.vnc bus name to appear, which indicates
     * qemu-vnc has fully initialized (connected to QEMU, set up the
     * display, exported its D-Bus interfaces, and opened the VNC
     * socket).
     */
    {
        guint watch_id, timeout_id;
        gboolean appeared = FALSE;

        watch_id = g_bus_watch_name_on_connection(
            dt->bus_conn, "org.qemu.vnc",
            G_BUS_NAME_WATCHER_FLAGS_NONE,
            name_appeared_cb, NULL, &appeared, NULL);
        timeout_id = g_timeout_add_seconds(10, timeout_cb, NULL);

        while (!appeared) {
            if (!g_main_context_iteration(NULL, TRUE)) {
                break;
            }
        }

        g_bus_unwatch_name(watch_id);
        g_source_remove(timeout_id);

        if (!appeared) {
            g_test_fail();
            g_test_message("Timed out waiting for org.qemu.vnc bus name");
            return false;
        }
    }

    return true;
}

static bool
setup_dbus_test(DbusTest *dt)
{
    return setup_dbus_test_full(dt, NULL);
}

static void
cleanup_dbus_test(DbusTest *dt)
{
    if (dt->bus_conn) {
        g_dbus_connection_close_sync(dt->bus_conn, NULL, NULL);
        g_object_unref(dt->bus_conn);
    }
    if (dt->vnc_subprocess) {
        g_subprocess_force_exit(dt->vnc_subprocess);
        g_subprocess_wait(dt->vnc_subprocess, NULL, NULL);
        g_object_unref(dt->vnc_subprocess);
    }
    if (dt->vnc_sock_path) {
        unlink(dt->vnc_sock_path);
        g_free(dt->vnc_sock_path);
    }
    if (dt->tmp_dir) {
        rmdir(dt->tmp_dir);
        g_free(dt->tmp_dir);
    }
    if (dt->qts) {
        qtest_quit(dt->qts);
    }
    if (dt->bus) {
        g_test_dbus_down(dt->bus);
        g_object_unref(dt->bus);
    }
    g_free(dt->bus_addr);
}

static void
test_dbus_vnc_basic(void)
{
    DbusTest dt = { 0 };
    VncConnection *conn = NULL;
    GMainLoop *loop = NULL;
    int pair[2];
    int vnc_fd;
    guint timeout_id;

    if (!g_getenv("QTEST_QEMU_VNC_BINARY")) {
        g_test_skip("QTEST_QEMU_VNC_BINARY not set");
        return;
    }

    dt.qts = qtest_init("-display dbus,p2p=yes -name dbus-vnc-test");

    g_assert_cmpint(qemu_socketpair(AF_UNIX, SOCK_STREAM, 0, pair), ==, 0);
    qtest_qmp_add_client(dt.qts, "@dbus-display", pair[1]);
    close(pair[1]);

    dt.tmp_dir = g_dir_make_tmp("dbus-vnc-test-XXXXXX", NULL);
    g_assert(dt.tmp_dir != NULL);
    dt.vnc_sock_path = g_build_filename(dt.tmp_dir, "vnc.sock", NULL);

    dt.vnc_subprocess = spawn_qemu_vnc(pair[0], dt.vnc_sock_path);

    vnc_fd = wait_for_vnc_socket(dt.vnc_sock_path, VNC_TEST_TIMEOUT_MS);
    g_assert(vnc_fd >= 0);

    loop = g_main_loop_new(NULL, FALSE);

    conn = vnc_connection_new();
    g_signal_connect(conn, "vnc-error",
                     G_CALLBACK(on_vnc_error), NULL);
    g_signal_connect(conn, "vnc-auth-failure",
                     G_CALLBACK(on_vnc_auth_failure), NULL);
    g_signal_connect(conn, "vnc-initialized",
                     G_CALLBACK(on_vnc_initialized), loop);
    vnc_connection_set_auth_type(conn, VNC_CONNECTION_AUTH_NONE);
    vnc_connection_open_fd(conn, vnc_fd);

    timeout_id = g_timeout_add_seconds(10, timeout_cb, NULL);
    g_main_loop_run(loop);
    g_source_remove(timeout_id);

    if (conn) {
        vnc_connection_shutdown(conn);
        g_object_unref(conn);
    }
    g_clear_pointer(&loop, g_main_loop_unref);
    cleanup_dbus_test(&dt);
}

static void
test_dbus_vnc_server_props(void)
{
    DbusTest dt = { 0 };
    QemuVnc1Server *proxy = NULL;
    g_autoptr(GError) err = NULL;
    const gchar *const *clients;
    GVariant *listeners;

    if (!setup_dbus_test(&dt)) {
        goto cleanup;
    }

    proxy = create_server_proxy(dt.bus_conn, &err);
    g_assert_no_error(err);
    g_assert_nonnull(proxy);

    g_assert_cmpstr(qemu_vnc1_server_get_name(proxy), ==,
                    "dbus-vnc-test");
    g_assert_cmpstr(qemu_vnc1_server_get_auth(proxy), ==,
                    "none");
    g_assert_cmpstr(qemu_vnc1_server_get_vencrypt_sub_auth(proxy), ==,
                    "");

    clients = qemu_vnc1_server_get_clients(proxy);
    g_assert_nonnull(clients);
    g_assert_cmpint(g_strv_length((gchar **)clients), ==, 0);

    listeners = qemu_vnc1_server_get_listeners(proxy);
    g_assert_nonnull(listeners);
    g_assert_cmpint(g_variant_n_children(listeners), >, 0);

cleanup:
    g_clear_object(&proxy);
    cleanup_dbus_test(&dt);
}

static void
on_client_connected(QemuVnc1Server *proxy,
                    const gchar *client_path,
                    LifecycleData *data)
{
    data->got_connected = TRUE;
    data->client_path = g_strdup(client_path);
}

static void
on_client_initialized(QemuVnc1Server *proxy,
                      const gchar *client_path,
                      LifecycleData *data)
{
    data->got_initialized = TRUE;
    g_main_loop_quit(data->dt->loop);
}

static void
on_client_disconnected(QemuVnc1Server *proxy,
                       const gchar *client_path,
                       LifecycleData *data)
{
    data->got_disconnected = TRUE;
    g_main_loop_quit(data->dt->loop);
}

static void
test_dbus_vnc_client_lifecycle(void)
{
    DbusTest dt = { 0 };
    QemuVnc1Server *server_proxy = NULL;
    QemuVnc1Client *client_proxy = NULL;
    g_autoptr(GError) err = NULL;
    LifecycleData ldata = { 0 };
    int vnc_fd;
    guint timeout_id;

    if (!setup_dbus_test(&dt)) {
        goto cleanup;
    }

    server_proxy = create_server_proxy(dt.bus_conn, &err);
    g_assert_no_error(err);

    ldata.dt = &dt;
    ldata.server_proxy = server_proxy;

    g_signal_connect(server_proxy, "client-connected",
                     G_CALLBACK(on_client_connected), &ldata);
    g_signal_connect(server_proxy, "client-initialized",
                     G_CALLBACK(on_client_initialized), &ldata);
    g_signal_connect(server_proxy, "client-disconnected",
                     G_CALLBACK(on_client_disconnected), &ldata);

    vnc_fd = wait_for_vnc_socket(dt.vnc_sock_path, VNC_TEST_TIMEOUT_MS);
    g_assert(vnc_fd >= 0);

    ldata.conn = vnc_connection_new();
    g_signal_connect(ldata.conn, "vnc-error",
                     G_CALLBACK(on_vnc_error), NULL);
    g_signal_connect(ldata.conn, "vnc-auth-failure",
                     G_CALLBACK(on_vnc_auth_failure), NULL);
    vnc_connection_set_auth_type(ldata.conn, VNC_CONNECTION_AUTH_NONE);
    vnc_connection_open_fd(ldata.conn, vnc_fd);

    /* wait for ClientInitialized */
    dt.loop = g_main_loop_new(NULL, FALSE);
    timeout_id = g_timeout_add_seconds(10, timeout_cb, NULL);
    g_main_loop_run(dt.loop);
    g_source_remove(timeout_id);

    g_assert_true(ldata.got_connected);
    g_assert_true(ldata.got_initialized);
    g_assert_nonnull(ldata.client_path);

    /* Check client properties while still connected */
    client_proxy = qemu_vnc1_client_proxy_new_sync(
        dt.bus_conn,
        G_DBUS_PROXY_FLAGS_NONE,
        "org.qemu.vnc",
        ldata.client_path,
        NULL, &err);
    g_assert_no_error(err);

    g_assert_cmpstr(qemu_vnc1_client_get_family(client_proxy), ==,
                    "unix");
    g_assert_false(qemu_vnc1_client_get_web_socket(client_proxy));
    g_assert_cmpstr(qemu_vnc1_client_get_x509_dname(client_proxy), ==,
                    "");
    g_assert_cmpstr(qemu_vnc1_client_get_sasl_username(client_proxy),
                    ==, "");

    /* disconnect and wait for ClientDisconnected */
    vnc_connection_shutdown(ldata.conn);
    timeout_id = g_timeout_add_seconds(10, timeout_cb, NULL);
    g_main_loop_run(dt.loop);
    g_source_remove(timeout_id);

    g_assert_true(ldata.got_disconnected);

    g_object_unref(ldata.conn);
    g_main_loop_unref(dt.loop);
    dt.loop = NULL;
    g_free(ldata.client_path);

cleanup:
    g_clear_object(&server_proxy);
    g_clear_object(&client_proxy);
    cleanup_dbus_test(&dt);
}

static void
test_dbus_vnc_no_password(void)
{
    DbusTest dt = { 0 };
    QemuVnc1Server *proxy = NULL;
    g_autoptr(GError) err = NULL;
    gboolean ret;

    if (!setup_dbus_test(&dt)) {
        goto cleanup;
    }

    proxy = create_server_proxy(dt.bus_conn, &err);
    g_assert_no_error(err);

    /*
     * With default auth=none, SetPassword should return an error
     * because VNC password authentication is not enabled.
     */
    ret = qemu_vnc1_server_call_set_password_sync(
        proxy, "secret",
        G_DBUS_CALL_FLAGS_NONE, -1, NULL, &err);
    g_assert_false(ret);
    g_assert_error(err, G_DBUS_ERROR, G_DBUS_ERROR_FAILED);
    g_clear_error(&err);

    ret = qemu_vnc1_server_call_expire_password_sync(
        proxy, "never",
        G_DBUS_CALL_FLAGS_NONE, -1, NULL, &err);
    g_assert_no_error(err);
    g_assert_true(ret);

    ret = qemu_vnc1_server_call_expire_password_sync(
        proxy, "+3600",
        G_DBUS_CALL_FLAGS_NONE, -1, NULL, &err);
    g_assert_no_error(err);
    g_assert_true(ret);

cleanup:
    g_clear_object(&proxy);
    cleanup_dbus_test(&dt);
}

typedef struct PasswordData {
    DbusTest *dt;
    VncConnection *conn;
    const char *password;
    gboolean auth_succeeded;
    gboolean auth_failed;
} PasswordData;

G_GNUC_BEGIN_IGNORE_DEPRECATIONS
static void
on_pw_vnc_auth_credential(VncConnection *conn, GValueArray *creds,
                          PasswordData *data)
{
    for (guint i = 0; i < creds->n_values; i++) {
        int type = g_value_get_enum(g_value_array_get_nth(creds, i));

        if (type == VNC_CONNECTION_CREDENTIAL_PASSWORD) {
            vnc_connection_set_credential(conn, type, data->password);
        }
    }
}
G_GNUC_END_IGNORE_DEPRECATIONS

static void
on_pw_vnc_initialized(VncConnection *conn, PasswordData *data)
{
    data->auth_succeeded = TRUE;
    g_main_loop_quit(data->dt->loop);
}

static void
on_pw_vnc_auth_failure(VncConnection *conn, const char *msg,
                       PasswordData *data)
{
    data->auth_failed = TRUE;
    g_main_loop_quit(data->dt->loop);
}

static void
on_pw_vnc_error(VncConnection *conn, const char *msg,
                PasswordData *data)
{
    data->auth_failed = TRUE;
    g_main_loop_quit(data->dt->loop);
}

static void
test_dbus_vnc_password_auth(void)
{
    DbusTest dt = { 0 };
    QemuVnc1Server *proxy = NULL;
    g_autoptr(GError) err = NULL;
    PasswordData pdata = { 0 };
    const char *extra_args[] = { "--password", NULL };
    int vnc_fd;
    guint timeout_id;
    gboolean ret;

    if (!setup_dbus_test_full(&dt, extra_args)) {
        goto cleanup;
    }

    proxy = create_server_proxy(dt.bus_conn, &err);
    g_assert_no_error(err);

    g_assert_cmpstr(qemu_vnc1_server_get_auth(proxy), ==, "vnc");

    ret = qemu_vnc1_server_call_set_password_sync(
        proxy, "testpass123",
        G_DBUS_CALL_FLAGS_NONE, -1, NULL, &err);
    g_assert_no_error(err);
    g_assert_true(ret);

    vnc_fd = wait_for_vnc_socket(dt.vnc_sock_path, VNC_TEST_TIMEOUT_MS);
    g_assert(vnc_fd >= 0);

    pdata.dt = &dt;
    pdata.password = "testpass123";
    pdata.conn = vnc_connection_new();

    g_signal_connect(pdata.conn, "vnc-error",
                     G_CALLBACK(on_pw_vnc_error), &pdata);
    g_signal_connect(pdata.conn, "vnc-auth-failure",
                     G_CALLBACK(on_pw_vnc_auth_failure), &pdata);
    g_signal_connect(pdata.conn, "vnc-auth-credential",
                     G_CALLBACK(on_pw_vnc_auth_credential), &pdata);
    g_signal_connect(pdata.conn, "vnc-initialized",
                     G_CALLBACK(on_pw_vnc_initialized), &pdata);
    vnc_connection_set_auth_type(pdata.conn, VNC_CONNECTION_AUTH_VNC);
    vnc_connection_open_fd(pdata.conn, vnc_fd);

    dt.loop = g_main_loop_new(NULL, FALSE);
    timeout_id = g_timeout_add_seconds(10, timeout_cb, NULL);
    g_main_loop_run(dt.loop);
    g_source_remove(timeout_id);

    g_assert_true(pdata.auth_succeeded);
    g_assert_false(pdata.auth_failed);

    vnc_connection_shutdown(pdata.conn);
    g_object_unref(pdata.conn);
    g_main_loop_unref(dt.loop);
    dt.loop = NULL;

cleanup:
    g_clear_object(&proxy);
    cleanup_dbus_test(&dt);
}

static void
test_dbus_vnc_sasl_authz_no_sasl(void)
{
    const char *binary;
    g_autoptr(GError) err = NULL;
    g_autoptr(GSubprocess) proc = NULL;
    gboolean ok;

    binary = g_getenv("QTEST_QEMU_VNC_BINARY");
    if (!binary) {
        g_test_skip("QTEST_QEMU_VNC_BINARY not set");
        return;
    }

    proc = g_subprocess_new(G_SUBPROCESS_FLAGS_STDERR_SILENCE,
                            &err,
                            binary,
                            "--sasl-authz", "authz0",
                            NULL);
    g_assert_no_error(err);
    g_assert_nonnull(proc);

    ok = g_subprocess_wait(proc, NULL, &err);
    g_assert_no_error(err);
    g_assert_true(ok);
    g_assert_false(g_subprocess_get_successful(proc));
}

#ifdef CONFIG_VNC_SASL
static void
test_dbus_vnc_sasl_server_props(void)
{
    DbusTest dt = { 0 };
    QemuVnc1Server *proxy = NULL;
    g_autoptr(GError) err = NULL;
    const char *extra_args[] = { "--sasl", NULL };

    if (!setup_dbus_test_full(&dt, extra_args)) {
        goto cleanup;
    }

    proxy = create_server_proxy(dt.bus_conn, &err);
    g_assert_no_error(err);
    g_assert_nonnull(proxy);

    g_assert_cmpstr(qemu_vnc1_server_get_auth(proxy), ==, "sasl");

cleanup:
    g_clear_object(&proxy);
    cleanup_dbus_test(&dt);
}

#define SASL_TEST_USER "testuser"
#define SASL_TEST_PASS "testpass123"

typedef struct SaslAuthData {
    DbusTest *dt;
    const char *username;
    const char *password;
    gboolean auth_succeeded;
    gboolean auth_failed;
} SaslAuthData;

typedef struct SaslTestData {
    DbusTest dt;
    SaslAuthData sdata;
    char *sasl_dir;
    char *db_path;
} SaslTestData;

G_GNUC_BEGIN_IGNORE_DEPRECATIONS
static void
on_sasl_vnc_auth_credential(VncConnection *conn, GValueArray *creds,
                            SaslAuthData *data)
{
    for (guint i = 0; i < creds->n_values; i++) {
        int type = g_value_get_enum(g_value_array_get_nth(creds, i));

        switch (type) {
        case VNC_CONNECTION_CREDENTIAL_USERNAME:
            vnc_connection_set_credential(conn, type, data->username);
            break;
        case VNC_CONNECTION_CREDENTIAL_PASSWORD:
            vnc_connection_set_credential(conn, type, data->password);
            break;
        }
    }
}
G_GNUC_END_IGNORE_DEPRECATIONS

static void
on_sasl_vnc_initialized(VncConnection *conn, SaslAuthData *data)
{
    data->auth_succeeded = TRUE;
    g_main_loop_quit(data->dt->loop);
}

static void
on_sasl_vnc_auth_failure(VncConnection *conn, const char *msg,
                         SaslAuthData *data)
{
    data->auth_failed = TRUE;
    g_main_loop_quit(data->dt->loop);
}

static void
on_sasl_vnc_error(VncConnection *conn, const char *msg,
                  SaslAuthData *data)
{
    data->auth_failed = TRUE;
    g_main_loop_quit(data->dt->loop);
}

/*
 * Create a SASL configuration directory with a qemu.conf and a
 * sasldb2 user database.  Returns the path to the sasldb file,
 * or NULL if saslpasswd2 is not available.
 */
static char *
create_sasl_config(const char *dir, const char *username,
                   const char *password)
{
    g_autofree char *conf_path = g_strdup_printf("%s/qemu.conf", dir);
    g_autofree char *db_path = g_strdup_printf("%s/sasldb2", dir);
    g_autoptr(GError) err = NULL;
    g_autoptr(GSubprocess) proc = NULL;
    g_autofree char *conf = NULL;
    GOutputStream *stdin_stream;
    gboolean ok;

    /* use PLAIN, and local auxprop sasldb plugin */
    conf = g_strdup_printf(
        "mech_list: plain\n"
        "pwcheck_method: auxprop\n"
        "auxprop_plugin: sasldb\n"
        "sasldb_path: %s\n", db_path);
    g_assert_true(g_file_set_contents(conf_path, conf, -1, NULL));

    proc = g_subprocess_new(
        G_SUBPROCESS_FLAGS_STDIN_PIPE |
        G_SUBPROCESS_FLAGS_STDOUT_SILENCE |
        G_SUBPROCESS_FLAGS_STDERR_SILENCE,
        &err,
        "saslpasswd2", "-f", db_path, "-a", "qemu", "-p", "-c",
        username, NULL);
    if (!proc) {
        return NULL;
    }

    stdin_stream = g_subprocess_get_stdin_pipe(proc);
    g_output_stream_write_all(stdin_stream, password,
                              strlen(password), NULL, NULL, NULL);
    g_output_stream_close(stdin_stream, NULL, NULL);

    ok = g_subprocess_wait_check(proc, NULL, &err);
    if (!ok) {
        return NULL;
    }

    return g_strdup(db_path);
}

static void
cleanup_sasl_config(const char *dir, const char *db_path)
{
    g_autofree char *conf = g_strdup_printf("%s/qemu.conf", dir);

    unlink(conf);
    if (db_path) {
        unlink(db_path);
    }
    rmdir(dir);
}

/*
 * Set up SASL environment: create temp config dir, sasldb, and
 * start qemu-vnc with the given extra_args.  Returns FALSE if the
 * test should be skipped.
 */
static gboolean
setup_sasl_test(SaslTestData *st, const char **extra_args)
{
    if (!g_getenv("QTEST_QEMU_VNC_BINARY")) {
        g_test_skip("QTEST_QEMU_VNC_BINARY not set");
        return FALSE;
    }

    st->sasl_dir = g_dir_make_tmp("dbus-vnc-sasl-XXXXXX", NULL);
    g_assert_nonnull(st->sasl_dir);

    st->db_path = create_sasl_config(st->sasl_dir, SASL_TEST_USER,
                                     SASL_TEST_PASS);
    if (!st->db_path) {
        g_test_skip("saslpasswd2 not available or failed");
        cleanup_sasl_config(st->sasl_dir, NULL);
        return FALSE;
    }

    g_setenv("SASL_CONF_PATH", st->sasl_dir, TRUE);

    if (!setup_dbus_test_full(&st->dt, extra_args)) {
        return FALSE;
    }

    return TRUE;
}

/*
 * Connect to the VNC server using SASL and run the main loop
 * until authentication completes or times out.
 */
static void
run_sasl_auth(SaslTestData *st, const char *username,
              const char *password)
{
    VncConnection *conn;
    guint timeout_id;
    int vnc_fd;

    st->sdata.dt = &st->dt;
    st->sdata.username = username;
    st->sdata.password = password;

    vnc_fd = wait_for_vnc_socket(st->dt.vnc_sock_path, VNC_TEST_TIMEOUT_MS);
    g_assert(vnc_fd >= 0);

    conn = vnc_connection_new();
    g_signal_connect(conn, "vnc-error",
                     G_CALLBACK(on_sasl_vnc_error), &st->sdata);
    g_signal_connect(conn, "vnc-auth-failure",
                     G_CALLBACK(on_sasl_vnc_auth_failure), &st->sdata);
    g_signal_connect(conn, "vnc-auth-credential",
                     G_CALLBACK(on_sasl_vnc_auth_credential),
                     &st->sdata);
    g_signal_connect(conn, "vnc-initialized",
                     G_CALLBACK(on_sasl_vnc_initialized), &st->sdata);
    vnc_connection_set_auth_type(conn, VNC_CONNECTION_AUTH_SASL);
    vnc_connection_open_fd(conn, vnc_fd);

    st->dt.loop = g_main_loop_new(NULL, FALSE);
    timeout_id = g_timeout_add_seconds(10, timeout_cb, NULL);
    g_main_loop_run(st->dt.loop);
    g_source_remove(timeout_id);

    g_signal_handlers_disconnect_by_data(conn, &st->sdata);
    vnc_connection_shutdown(conn);
    g_object_unref(conn);
    g_main_loop_unref(st->dt.loop);
    st->dt.loop = NULL;
}

static void
cleanup_sasl_test(SaslTestData *st)
{
    cleanup_dbus_test(&st->dt);
    g_unsetenv("SASL_CONF_PATH");
    cleanup_sasl_config(st->sasl_dir, st->db_path);
    g_free(st->sasl_dir);
    g_free(st->db_path);
}

static void
test_dbus_vnc_sasl_auth(void)
{
    SaslTestData st = { 0 };
    const char *extra_args[] = { "--sasl", NULL };

    if (!setup_sasl_test(&st, extra_args)) {
        return;
    }

    run_sasl_auth(&st, SASL_TEST_USER, SASL_TEST_PASS);

    g_assert_true(st.sdata.auth_succeeded);
    g_assert_false(st.sdata.auth_failed);

    cleanup_sasl_test(&st);
}

static void
test_dbus_vnc_sasl_auth_bad_password(void)
{
    SaslTestData st = { 0 };
    const char *extra_args[] = { "--sasl", NULL };

    if (!setup_sasl_test(&st, extra_args)) {
        return;
    }

    run_sasl_auth(&st, SASL_TEST_USER, "wrongpassword");

    g_assert_false(st.sdata.auth_succeeded);
    g_assert_true(st.sdata.auth_failed);

    cleanup_sasl_test(&st);
}

static void
test_dbus_vnc_sasl_authz_denied(void)
{
    SaslTestData st = { 0 };
    const char *extra_args[] = {
        "--sasl",
        "--object",
        "authz-simple,id=authz0,identity=otheruser",
        "--sasl-authz", "authz0",
        NULL
    };

    if (!setup_sasl_test(&st, extra_args)) {
        return;
    }

    run_sasl_auth(&st, SASL_TEST_USER, SASL_TEST_PASS);

    g_assert_false(st.sdata.auth_succeeded);
    g_assert_true(st.sdata.auth_failed);

    cleanup_sasl_test(&st);
}
#endif /* CONFIG_VNC_SASL */

static void
test_dbus_vnc_tls_authz_no_creds(void)
{
    const char *binary;
    g_autoptr(GError) err = NULL;
    g_autoptr(GSubprocess) proc = NULL;
    gboolean ok;

    binary = g_getenv("QTEST_QEMU_VNC_BINARY");
    if (!binary) {
        g_test_skip("QTEST_QEMU_VNC_BINARY not set");
        return;
    }

    proc = g_subprocess_new(G_SUBPROCESS_FLAGS_STDERR_SILENCE,
                            &err,
                            binary,
                            "--tls-authz", "authz0",
                            NULL);
    g_assert_no_error(err);
    g_assert_nonnull(proc);

    ok = g_subprocess_wait(proc, NULL, &err);
    g_assert_no_error(err);
    g_assert_true(ok);
    g_assert_false(g_subprocess_get_successful(proc));
}

#ifdef CONFIG_TASN1
#define CLIENT_CERT_CN "qemu-vnc-test"

static char *
create_tls_certs(const char *dir)
{
    char *keyfile = g_strdup_printf("%s/key.pem", dir);
    char *cacert = g_strdup_printf("%s/ca-cert.pem", dir);
    char *servercert = g_strdup_printf("%s/server-cert.pem", dir);
    char *serverkey = g_strdup_printf("%s/server-key.pem", dir);
    char *clientcert = g_strdup_printf("%s/client-cert.pem", dir);

    test_tls_init(keyfile);
    g_assert(link(keyfile, serverkey) == 0);

    TLS_ROOT_REQ_SIMPLE(cacertreq, cacert);
    TLS_CERT_REQ_SIMPLE_SERVER(servercertreq, cacertreq,
                               servercert, "localhost", NULL);
    TLS_CERT_REQ_SIMPLE_CLIENT(clientcertreq, cacertreq,
                               CLIENT_CERT_CN, clientcert);

    test_tls_deinit_cert(&clientcertreq);
    test_tls_deinit_cert(&servercertreq);
    test_tls_deinit_cert(&cacertreq);

    g_free(cacert);
    g_free(servercert);
    g_free(serverkey);
    g_free(clientcert);
    return keyfile;
}

static void
cleanup_tls_certs(const char *dir, const char *keyfile)
{
    g_autofree char *cacert = g_strdup_printf("%s/ca-cert.pem", dir);
    g_autofree char *servercert = g_strdup_printf("%s/server-cert.pem", dir);
    g_autofree char *serverkey = g_strdup_printf("%s/server-key.pem", dir);
    g_autofree char *clientcert = g_strdup_printf("%s/client-cert.pem", dir);

    unlink(cacert);
    unlink(servercert);
    unlink(serverkey);
    unlink(clientcert);
    unlink(keyfile);
    test_tls_cleanup(keyfile);
    rmdir(dir);
}

/*
 * Do a minimal VNC/VeNCrypt negotiation on @fd up to the point where
 * the TLS handshake should begin, then perform a GnuTLS handshake
 * using the given credentials.
 */
static bool
try_raw_tls_connect(int fd, gnutls_certificate_credentials_t cred)
{
    char buf[13];
    uint8_t num_types, type;
    uint8_t vencrypt_ver[2], ack;
    uint8_t num_sub;
    uint32_t subtype;
    gnutls_session_t session;
    int ret;
    bool success;

    /* RFB version exchange */
    g_assert_cmpint(read(fd, buf, 12), ==, 12);
    g_assert_cmpint(write(fd, "RFB 003.008\n", 12), ==, 12);

    /* Select VeNCrypt (type 19) from the auth list */
    g_assert_cmpint(read(fd, &num_types, 1), ==, 1);
    for (int i = 0; i < num_types; i++) {
        g_assert_cmpint(read(fd, &type, 1), ==, 1);
    }
    type = 19;
    g_assert_cmpint(write(fd, &type, 1), ==, 1);

    /* VeNCrypt version exchange */
    g_assert_cmpint(read(fd, vencrypt_ver, 2), ==, 2);
    g_assert_cmpint(write(fd, vencrypt_ver, 2), ==, 2);
    g_assert_cmpint(read(fd, &ack, 1), ==, 1);
    g_assert_cmpint(ack, ==, 0);

    /* Select x509-none (260) sub-auth */
    g_assert_cmpint(read(fd, &num_sub, 1), ==, 1);
    for (int i = 0; i < num_sub; i++) {
        g_assert_cmpint(read(fd, &subtype, 4), ==, 4);
    }
    subtype = htonl(260);
    g_assert_cmpint(write(fd, &subtype, 4), ==, 4);

    /* Server sends 1-byte ack (1 = accepted) before TLS starts */
    g_assert_cmpint(read(fd, &ack, 1), ==, 1);
    g_assert_cmpint(ack, ==, 1);

    /* TLS handshake */
    g_assert_cmpint(gnutls_init(&session, GNUTLS_CLIENT), >=, 0);
    g_assert_cmpint(
        gnutls_set_default_priority(session), >=, 0);
    g_assert_cmpint(
        gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred),
        >=, 0);
    gnutls_transport_set_int(session, fd);

    do {
        ret = gnutls_handshake(session);
    } while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);

    if (ret < 0) {
        success = false;
    } else {
        /*
         * Try reading the VNC security-result (4 bytes) — if the
         * server rejected us it will have closed the connection.
         */
        char tmp[4];
        do {
            ret = gnutls_record_recv(session, tmp, sizeof(tmp));
        } while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);
        success = (ret > 0);
    }

    gnutls_deinit(session);
    return success;
}

static void
test_dbus_vnc_tls_server_props(void)
{
    DbusTest dt = { 0 };
    QemuVnc1Server *proxy = NULL;
    g_autoptr(GError) err = NULL;
    g_autofree char *tls_dir = NULL;
    g_autofree char *keyfile = NULL;

    if (!g_getenv("QTEST_QEMU_VNC_BINARY")) {
        g_test_skip("QTEST_QEMU_VNC_BINARY not set");
        return;
    }

    tls_dir = g_dir_make_tmp("dbus-vnc-tls-XXXXXX", NULL);
    g_assert_nonnull(tls_dir);
    keyfile = create_tls_certs(tls_dir);

    {
        const char *extra_args[] = {
            "--tls-creds", tls_dir, NULL
        };
        if (!setup_dbus_test_full(&dt, extra_args)) {
            goto cleanup;
        }
    }

    proxy = create_server_proxy(dt.bus_conn, &err);
    g_assert_no_error(err);
    g_assert_nonnull(proxy);

    g_assert_cmpstr(qemu_vnc1_server_get_auth(proxy), ==, "vencrypt");
    g_assert_cmpstr(qemu_vnc1_server_get_vencrypt_sub_auth(proxy), ==,
                    "x509-none");

    /*
     * With verify-peer=no, a client without a certificate should
     * be able to connect successfully through TLS.
     */
    {
        g_autofree char *ca_path =
            g_strdup_printf("%s/ca-cert.pem", tls_dir);
        gnutls_certificate_credentials_t cred;
        int fd;

        g_assert_cmpint(
            gnutls_certificate_allocate_credentials(&cred), >=, 0);
        g_assert_cmpint(
            gnutls_certificate_set_x509_trust_file(
                cred, ca_path, GNUTLS_X509_FMT_PEM), >=, 0);

        fd = wait_for_vnc_socket(dt.vnc_sock_path, VNC_TEST_TIMEOUT_MS);
        g_assert(fd >= 0);
        g_assert_true(try_raw_tls_connect(fd, cred));
        close(fd);

        gnutls_certificate_free_credentials(cred);
    }

cleanup:
    g_clear_object(&proxy);
    cleanup_dbus_test(&dt);
    cleanup_tls_certs(tls_dir, keyfile);
}

static void
test_dbus_vnc_tls_authz(void)
{
    DbusTest dt = { 0 };
    g_autofree char *tls_dir = NULL;
    g_autofree char *keyfile = NULL;
    g_autofree char *ca_path = NULL;

    if (!g_getenv("QTEST_QEMU_VNC_BINARY")) {
        g_test_skip("QTEST_QEMU_VNC_BINARY not set");
        return;
    }

    tls_dir = g_dir_make_tmp("dbus-vnc-tls-XXXXXX", NULL);
    g_assert_nonnull(tls_dir);
    keyfile = create_tls_certs(tls_dir);

    /*
     * The client cert has CN=qemu-vnc-test, so the DN string
     * reported by GnuTLS is "CN=qemu-vnc-test".  Configure
     * authz-simple to accept exactly that identity.
     */
    {
        g_autofree char *identity =
            g_strdup_printf("CN=%s", CLIENT_CERT_CN);
        const char *extra_args[] = {
            "--tls-creds", tls_dir,
            "--object",
            NULL, /* filled below */
            "--tls-authz", "authz0",
            NULL
        };
        g_autofree char *object_arg =
            g_strdup_printf("authz-simple,id=authz0,identity=%s", identity);
        extra_args[3] = object_arg;

        if (!setup_dbus_test_full(&dt, extra_args)) {
            goto cleanup;
        }
    }

    ca_path = g_strdup_printf("%s/ca-cert.pem", tls_dir);

    /*
     * Connect without a client certificate.
     * With verify-peer=yes the TLS handshake must fail.
     */
    {
        gnutls_certificate_credentials_t cred;
        int fd;

        g_assert_cmpint(
            gnutls_certificate_allocate_credentials(&cred), >=, 0);
        g_assert_cmpint(
            gnutls_certificate_set_x509_trust_file(
                cred, ca_path, GNUTLS_X509_FMT_PEM), >=, 0);

        fd = wait_for_vnc_socket(dt.vnc_sock_path, VNC_TEST_TIMEOUT_MS);
        g_assert(fd >= 0);
        g_assert_false(try_raw_tls_connect(fd, cred));
        close(fd);

        gnutls_certificate_free_credentials(cred);
    }

    /*
     * Connect with a valid client certificate whose DN
     * matches the authz-simple identity.  This must succeed.
     */
    {
        g_autofree char *cert_path =
            g_strdup_printf("%s/client-cert.pem", tls_dir);
        g_autofree char *key_path =
            g_strdup_printf("%s/key.pem", tls_dir);
        gnutls_certificate_credentials_t cred;
        int fd;

        g_assert_cmpint(
            gnutls_certificate_allocate_credentials(&cred), >=, 0);
        g_assert_cmpint(
            gnutls_certificate_set_x509_trust_file(
                cred, ca_path, GNUTLS_X509_FMT_PEM), >=, 0);
        g_assert_cmpint(
            gnutls_certificate_set_x509_key_file(
                cred, cert_path, key_path, GNUTLS_X509_FMT_PEM), >=, 0);

        fd = wait_for_vnc_socket(dt.vnc_sock_path, VNC_TEST_TIMEOUT_MS);
        g_assert(fd >= 0);
        g_assert_true(try_raw_tls_connect(fd, cred));
        close(fd);

        gnutls_certificate_free_credentials(cred);
    }

cleanup:
    cleanup_dbus_test(&dt);
    cleanup_tls_certs(tls_dir, keyfile);
}
#endif /* CONFIG_TASN1 */

int
main(int argc, char **argv)
{
    g_log_set_always_fatal(G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL);

    /*
     * Flaky test:
     * ERROR:../tests/qtest/dbus-vnc-test.c:621:test_dbus_vnc_password_auth:
     * assertion failed (qemu_vnc1_server_get_auth(proxy) == "vnc"): ("none" ==
     * "vnc")
     */
    if (!getenv("QEMU_TEST_FLAKY_TESTS")) {
        g_test_skip("QEMU_TEST_FLAKY_TESTS not set");
        return 0;
    }
    if (getenv("GTK_VNC_DEBUG")) {
        vnc_util_set_debug(true);
    }

    g_test_init(&argc, &argv, NULL);

    qtest_add_func("/dbus-vnc/basic", test_dbus_vnc_basic);
    qtest_add_func("/dbus-vnc/server-props", test_dbus_vnc_server_props);
    qtest_add_func("/dbus-vnc/client-lifecycle",
                   test_dbus_vnc_client_lifecycle);
    qtest_add_func("/dbus-vnc/no-password", test_dbus_vnc_no_password);
    qtest_add_func("/dbus-vnc/password-auth", test_dbus_vnc_password_auth);
    qtest_add_func("/dbus-vnc/sasl-authz-no-sasl",
                   test_dbus_vnc_sasl_authz_no_sasl);
#ifdef CONFIG_VNC_SASL
    qtest_add_func("/dbus-vnc/sasl-server-props",
                   test_dbus_vnc_sasl_server_props);
    qtest_add_func("/dbus-vnc/sasl-auth",
                   test_dbus_vnc_sasl_auth);
    qtest_add_func("/dbus-vnc/sasl-auth-bad-password",
                   test_dbus_vnc_sasl_auth_bad_password);
    qtest_add_func("/dbus-vnc/sasl-authz-denied",
                   test_dbus_vnc_sasl_authz_denied);
#endif
    qtest_add_func("/dbus-vnc/tls-authz-no-creds",
                   test_dbus_vnc_tls_authz_no_creds);
#ifdef CONFIG_TASN1
    qtest_add_func("/dbus-vnc/tls-server-props",
                   test_dbus_vnc_tls_server_props);
    qtest_add_func("/dbus-vnc/tls-authz",
                   test_dbus_vnc_tls_authz);
#endif

    return g_test_run();
}
