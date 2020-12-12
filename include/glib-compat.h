/*
 * GLIB Compatibility Functions
 *
 * Copyright IBM, Corp. 2013
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *  Michael Tokarev   <mjt@tls.msk.ru>
 *  Paolo Bonzini     <pbonzini@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef QEMU_GLIB_COMPAT_H
#define QEMU_GLIB_COMPAT_H

/* Ask for warnings for anything that was marked deprecated in
 * the defined version, or before. It is a candidate for rewrite.
 */
#define GLIB_VERSION_MIN_REQUIRED GLIB_VERSION_2_48

/* Ask for warnings if code tries to use function that did not
 * exist in the defined version. These risk breaking builds
 */
#define GLIB_VERSION_MAX_ALLOWED GLIB_VERSION_2_48

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <glib.h>
#if defined(G_OS_UNIX)
#include <glib-unix.h>
#include <sys/types.h>
#include <pwd.h>
#endif

/*
 * Note that because of the GLIB_VERSION_MAX_ALLOWED constant above, allowing
 * use of functions from newer GLib via this compat header needs a little
 * trickery to prevent warnings being emitted.
 *
 * Consider a function from newer glib-X.Y that we want to use
 *
 *    int g_foo(const char *wibble)
 *
 * We must define a static inline function with the same signature that does
 * what we need, but with a "_qemu" suffix e.g.
 *
 * static inline void g_foo_qemu(const char *wibble)
 * {
 *     #if GLIB_CHECK_VERSION(X, Y, 0)
 *        g_foo(wibble)
 *     #else
 *        g_something_equivalent_in_older_glib(wibble);
 *     #endif
 * }
 *
 * The #pragma at the top of this file turns off -Wdeprecated-declarations,
 * ensuring this wrapper function impl doesn't trigger the compiler warning
 * about using too new glib APIs. Finally we can do
 *
 *   #define g_foo(a) g_foo_qemu(a)
 *
 * So now the code elsewhere in QEMU, which *does* have the
 * -Wdeprecated-declarations warning active, can call g_foo(...) as normal,
 * without generating warnings.
 */

#if defined(_WIN32) && !GLIB_CHECK_VERSION(2, 50, 0)
/*
 * g_poll has a problem on Windows when using
 * timeouts < 10ms, so use wrapper.
 */
#define g_poll(fds, nfds, timeout) g_poll_fixed(fds, nfds, timeout)
gint g_poll_fixed(GPollFD *fds, guint nfds, gint timeout);
#endif

#if defined(G_OS_UNIX)
/*
 * Note: The fallback implementation is not MT-safe, and it returns a copy of
 * the libc passwd (must be g_free() after use) but not the content. Because of
 * these important differences the caller must be aware of, it's not #define for
 * GLib API substitution.
 */
static inline struct passwd *
g_unix_get_passwd_entry_qemu(const gchar *user_name, GError **error)
{
#if GLIB_CHECK_VERSION(2, 64, 0)
    return g_unix_get_passwd_entry(user_name, error);
#else
    struct passwd *p = getpwnam(user_name);
    if (!p) {
        g_set_error_literal(error, G_UNIX_ERROR, 0, g_strerror(errno));
        return NULL;
    }
    return (struct passwd *)g_memdup(p, sizeof(*p));
#endif
}
#endif /* G_OS_UNIX */

#pragma GCC diagnostic pop

#endif
