/*
 * Standalone VNC server connecting to QEMU via D-Bus display interface.
 * Audio support. Only one audio stream is tracked.
 * Mixing/resampling to be added, if needed.
 *
 * Copyright (C) 2026 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"

#include "qemu/audio.h"
#include "qemu/audio-capture.h"
#include "qemu/sockets.h"
#include "qemu/error-report.h"
#include "ui/dbus-display1.h"
#include "trace.h"
#include "qemu-vnc.h"

struct CaptureVoiceOut {
    struct audsettings as;
    struct audio_capture_ops ops;
    void *opaque;
    QLIST_ENTRY(CaptureVoiceOut) entries;
};

typedef struct AudioOut {
    guint64 id;
    struct audsettings as;
} AudioOut;

static QLIST_HEAD(, CaptureVoiceOut) capture_list =
    QLIST_HEAD_INITIALIZER(capture_list);
static GDBusConnection *audio_listener_conn;
static AudioOut audio_out;

static bool audsettings_eq(const struct audsettings *a,
                           const struct audsettings *b)
{
    return a->freq == b->freq &&
           a->nchannels == b->nchannels &&
           a->fmt == b->fmt &&
           a->big_endian == b->big_endian;
}

static gboolean
on_audio_out_init(QemuDBusDisplay1AudioOutListener *listener,
                  GDBusMethodInvocation *invocation,
                  guint64 id, guchar bits, gboolean is_signed,
                  gboolean is_float, guint freq, guchar nchannels,
                  guint bytes_per_frame, guint bytes_per_second,
                  gboolean be, gpointer user_data)
{
    AudioFormat fmt;

    switch (bits) {
    case 8:
        fmt = is_signed ? AUDIO_FORMAT_S8 : AUDIO_FORMAT_U8;
        break;
    case 16:
        fmt = is_signed ? AUDIO_FORMAT_S16 : AUDIO_FORMAT_U16;
        break;
    case 32:
        fmt = is_float ? AUDIO_FORMAT_F32 :
              is_signed ? AUDIO_FORMAT_S32 : AUDIO_FORMAT_U32;
        break;
    default:
        g_return_val_if_reached(DBUS_METHOD_INVOCATION_HANDLED);
    }

    struct audsettings as = {
        .freq = freq,
        .nchannels = nchannels,
        .fmt = fmt,
        .big_endian = be,
    };
    audio_out = (AudioOut) {
        .id = id,
        .as = as,
    };

    trace_qemu_vnc_audio_out_init(id, freq, nchannels, bits);

    qemu_dbus_display1_audio_out_listener_complete_init(
        listener, invocation);
    return DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
on_audio_out_fini(QemuDBusDisplay1AudioOutListener *listener,
                  GDBusMethodInvocation *invocation,
                  guint64 id, gpointer user_data)
{
    trace_qemu_vnc_audio_out_fini(id);

    qemu_dbus_display1_audio_out_listener_complete_fini(
        listener, invocation);
    return DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
on_audio_out_set_enabled(QemuDBusDisplay1AudioOutListener *listener,
                         GDBusMethodInvocation *invocation,
                         guint64 id, gboolean enabled,
                         gpointer user_data)
{
    CaptureVoiceOut *cap;

    trace_qemu_vnc_audio_out_set_enabled(id, enabled);

    if (id == audio_out.id) {
        QLIST_FOREACH(cap, &capture_list, entries) {
            cap->ops.notify(cap->opaque,
                            enabled ? AUD_CNOTIFY_ENABLE
                                : AUD_CNOTIFY_DISABLE);
        }
    }

    qemu_dbus_display1_audio_out_listener_complete_set_enabled(
        listener, invocation);
    return DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
on_audio_out_set_volume(QemuDBusDisplay1AudioOutListener *listener,
                        GDBusMethodInvocation *invocation,
                        guint64 id, gboolean mute,
                        GVariant *volume, gpointer user_data)
{
    qemu_dbus_display1_audio_out_listener_complete_set_volume(
        listener, invocation);
    return DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
on_audio_out_write(QemuDBusDisplay1AudioOutListener *listener,
                   GDBusMethodInvocation *invocation,
                   guint64 id, GVariant *data,
                   gpointer user_data)
{
    CaptureVoiceOut *cap;
    gsize size;
    const void *buf;

    if (id == audio_out.id) {
        buf = g_variant_get_fixed_array(data, &size, 1);

        trace_qemu_vnc_audio_out_write(id, size);

        QLIST_FOREACH(cap, &capture_list, entries) {
            /* we don't handle audio resampling/format conversion */
            if (audsettings_eq(&cap->as, &audio_out.as)) {
                cap->ops.capture(cap->opaque, buf, size);
            }
        }
    }

    qemu_dbus_display1_audio_out_listener_complete_write(
        listener, invocation);
    return DBUS_METHOD_INVOCATION_HANDLED;
}

CaptureVoiceOut *audio_be_add_capture(
    AudioBackend *be,
    const struct audsettings *as,
    const struct audio_capture_ops *ops,
    void *opaque)
{
    CaptureVoiceOut *cap;

    if (!audio_listener_conn) {
        return NULL;
    }

    cap = g_new0(CaptureVoiceOut, 1);
    cap->ops = *ops;
    cap->opaque = opaque;
    cap->as = *as;
    QLIST_INSERT_HEAD(&capture_list, cap, entries);

    return cap;
}

void audio_be_del_capture(
    AudioBackend *be,
    CaptureVoiceOut *cap,
    void *cb_opaque)
{
    if (!cap) {
        return;
    }

    cap->ops.destroy(cap->opaque);
    QLIST_REMOVE(cap, entries);
    g_free(cap);
}

/*
 * Dummy audio backend — the VNC server only needs a non-NULL pointer
 * so that audio capture registration doesn't bail out.  The pointer
 * is never dereferenced by our code (audio_be_add_capture ignores it).
 */
static AudioBackend dummy_audio_be;

AudioBackend *audio_get_default_audio_be(Error **errp)
{
    return &dummy_audio_be;
}

AudioBackend *audio_be_by_name(const char *name, Error **errp)
{
    return NULL;
}

static void
on_register_audio_listener_finished(GObject *source_object,
                                    GAsyncResult *res,
                                    gpointer user_data)
{
    GThread *thread = user_data;
    g_autoptr(GError) err = NULL;
    g_autoptr(GDBusObjectSkeleton) obj = NULL;
    GDBusObjectManagerServer *server;
    QemuDBusDisplay1AudioOutListener *audio_skel;

    qemu_dbus_display1_audio_call_register_out_listener_finish(
        QEMU_DBUS_DISPLAY1_AUDIO(source_object),
        NULL, res, &err);

    if (err) {
        error_report("RegisterOutListener failed: %s", err->message);
        g_thread_join(thread);
        return;
    }

    audio_listener_conn = g_thread_join(thread);
    if (!audio_listener_conn) {
        return;
    }

    server = g_dbus_object_manager_server_new(DBUS_DISPLAY1_ROOT);
    obj = g_dbus_object_skeleton_new(
        DBUS_DISPLAY1_ROOT "/AudioOutListener");

    audio_skel = qemu_dbus_display1_audio_out_listener_skeleton_new();
    g_object_connect(audio_skel,
                     "signal::handle-init",
                     on_audio_out_init, NULL,
                     "signal::handle-fini",
                     on_audio_out_fini, NULL,
                     "signal::handle-set-enabled",
                     on_audio_out_set_enabled, NULL,
                     "signal::handle-set-volume",
                     on_audio_out_set_volume, NULL,
                     "signal::handle-write",
                     on_audio_out_write, NULL,
                     NULL);
    g_dbus_object_skeleton_add_interface(
        obj, G_DBUS_INTERFACE_SKELETON(audio_skel));

    g_dbus_object_manager_server_export(server, obj);
    g_dbus_object_manager_server_set_connection(
        server, audio_listener_conn);

    g_dbus_connection_start_message_processing(audio_listener_conn);
}

void audio_setup(GDBusObjectManager *manager)
{
    g_autoptr(GError) err = NULL;
    g_autoptr(GUnixFDList) fd_list = NULL;
    g_autoptr(GDBusInterface) iface = NULL;
    GThread *thread;
    int pair[2];
    int idx;

    iface = g_dbus_object_manager_get_interface(
        manager, DBUS_DISPLAY1_ROOT "/Audio",
        "org.qemu.Display1.Audio");
    if (!iface) {
        return;
    }

    if (qemu_socketpair(AF_UNIX, SOCK_STREAM, 0, pair) < 0) {
        error_report("audio socketpair failed: %s", strerror(errno));
        return;
    }

    fd_list = g_unix_fd_list_new();
    idx = g_unix_fd_list_append(fd_list, pair[1], &err);
    close(pair[1]);
    if (idx < 0) {
        close(pair[0]);
        error_report("Failed to append fd: %s", err->message);
        return;
    }

    thread = p2p_dbus_thread_new(pair[0]);

    qemu_dbus_display1_audio_call_register_out_listener(
        QEMU_DBUS_DISPLAY1_AUDIO(iface),
        g_variant_new_handle(idx),
        G_DBUS_CALL_FLAGS_NONE, -1,
        fd_list, NULL,
        on_register_audio_listener_finished,
        thread);
}
