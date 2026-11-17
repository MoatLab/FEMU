/*
 * Copyright (C) 2026, Ziyang Zhang <functioner@sjtu.edu.cn>
 *
 * dlcall (Dynamic Linking Call) plugin: lets a linux-user guest invoke host
 * functions by issuing a magic system call. The guest can ask QEMU to dlopen()
 * a host shared library, dlsym() a symbol, and call it with guest-supplied
 * arguments.
 *
 * The plugin intentionally keeps the QEMU side lightweight and prescribes
 * nothing about how a library is thunked. Any toolchain can implement the
 * userspace side. Lorelei is one end-to-end implementation (guest/host
 * runtimes plus a thunk compiler that generates thunks from a library's
 * headers), and how it handles argument marshalling, callbacks and variadic
 * functions can serve as a reference:
 * https://github.com/rover2024/lorelei
 *
 * See docs/about/emulation.rst|Dynamic Linking Call for details and examples.
 *
 * WARNING: trusted guests only. The guest can load arbitrary host libraries
 * and execute arbitrary host code with arbitrary arguments, i.e. full code
 * execution in the QEMU host process. It is NOT a sandbox and provides no
 * isolation; only load it for guests you fully trust.
 *
 * WARNING: requires guest_base == 0, which is qemu-user's default, and a
 * guest whose pointer width and endianness match the host's. Pointer operands
 * are dereferenced as host addresses directly, and the invoked host functions
 * dereference guest pointers with no address translation, so guest and host
 * must share a single address space and agree on how a pointer is stored. A
 * non-zero guest_base (e.g. set via -B/-R) would make every pointer off by
 * guest_base and hit unrelated host memory.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <glib.h>
#include <dlfcn.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/*
 * The magic system call number for dlcall.
 *
 * It defaults to DLCALL_SYSCALL_DEFAULT and can be overridden at load time
 * with the "syscall_num=N" argument. To avoid hijacking a real syscall the
 * guest might issue, N must be at least DLCALL_SYSCALL_MIN, which most Linux
 * ABIs keep their syscall numbers well below.
 *
 * N also has to reach the filter at all, which bounds it from above in a
 * target specific way: arm32 answers anything past ARM_NR_BASE (0xf0000) with
 * ENOSYS or SIGILL before do_syscall() runs, while aarch64 has no such bound.
 *
 * MIPS O32 bases its numbering at 4000, so the default is a real syscall there
 * (getpriority). Raising N does not help either, because O32 rejects numbers
 * its table does not define, again before the filter runs, which leaves no
 * number that is both free and reachable on that ABI. Its N32 and N64 ABIs
 * base at 6000 and 5000 and have no such gate, so they are unaffected.
 */
enum {
    DLCALL_SYSCALL_DEFAULT = 4096,
    DLCALL_SYSCALL_MIN = 4096,
};

static int64_t dlcall_syscall_num = DLCALL_SYSCALL_DEFAULT;

/*
 * dlcall calling convention.
 *
 * The guest issues the magic system call (dlcall_syscall_num). The first
 * argument (a1) is one of the call IDs below; the remaining arguments (a2, a3,
 * a4, ...) are that ID's operands. All pointer operands are guest virtual
 * addresses that the plugin dereferences as host addresses directly (see the
 * guest_base requirement above). Results are written back through
 * caller-provided "out" pointers rather than returned in the syscall value.
 *
 * The syscall return value (*sysret) only reports dispatch status: 0 on a
 * recognised ID, -EINVAL for an unknown one. The actual success/failure of an
 * operation (e.g. a NULL handle from dlopen) is delivered through its out
 * pointer, exactly like the underlying libdl call.
 *
 * Operands per ID:
 *
 *   DLCALL_ID_GET_HOST_ATTRIBUTE
 *     a2  const char *key        in:  attribute name to query
 *     a3  const char **attr_ptr  out: matching value, or NULL if unknown
 *
 *   DLCALL_ID_LOAD_LIBRARY                            (wraps dlopen)
 *     a2  const char *path       in:  library path
 *     a3  int flags              in:  dlopen() flags (e.g. RTLD_NOW)
 *     a4  void **handle_ptr      out: library handle, or NULL on failure
 *
 *   DLCALL_ID_GET_PROC_ADDRESS                        (wraps dlsym)
 *     a2  void *handle           in:  library handle
 *     a3  const char *name       in:  symbol name
 *     a4  void **entry_ptr       out: symbol address, or NULL if not found
 *
 *   DLCALL_ID_FREE_LIBRARY                            (wraps dlclose)
 *     a2  void *handle           in:  library handle
 *     a3  int *ret_ptr           out: dlclose() return value (0 on success)
 *
 *   DLCALL_ID_GET_LIBRARY_ERROR                       (wraps dlerror)
 *     a2  const char **error_ptr out: last libdl error string, or NULL
 *
 *   DLCALL_ID_INVOKE_PROC                             (calls the symbol)
 *     a2  void *proc             in:  function pointer, signature
 *                                     void (*)(void *arg1, void *arg2)
 *     a3  void *arg1             in:  first argument forwarded to proc
 *     a4  void *arg2             in:  second argument forwarded to proc
 */
enum DlcallID {
    DLCALL_ID_GET_HOST_ATTRIBUTE,
    DLCALL_ID_LOAD_LIBRARY,
    DLCALL_ID_GET_PROC_ADDRESS,
    DLCALL_ID_FREE_LIBRARY,
    DLCALL_ID_GET_LIBRARY_ERROR,
    DLCALL_ID_INVOKE_PROC,
};

static inline const char *query_host_attribute(const char *key)
{
    if (strcmp(key, "emu") == 0) {
        return "qemu";
    }
    return NULL;
}

static inline void invoke_proc(void *proc, void *arg1, void *arg2)
{
    typedef void (*Func)(void * /*arg1*/, void * /*arg2*/);
    Func func = (Func) proc;
    func(arg1, arg2);
}

static bool vcpu_syscall_filter(unsigned int vcpu_index,
                                int64_t num, uint64_t a1, uint64_t a2,
                                uint64_t a3, uint64_t a4, uint64_t a5,
                                uint64_t a6, uint64_t a7, uint64_t a8,
                                int64_t *sysret, void *userdata)
{
    if (num == dlcall_syscall_num) {
        switch (a1) {
        /* Query host attribute by a reserved key. */
        case DLCALL_ID_GET_HOST_ATTRIBUTE: {
            const char *key = (const char *) a2;
            const char **attr_ptr = (const char **) a3;
            assert(attr_ptr);
            *attr_ptr = query_host_attribute(key);
            *sysret = 0;
            break;
        }

        /* Load a shared library. */
        case DLCALL_ID_LOAD_LIBRARY: {
            const char *path = (const char *) a2;
            int flags = (int) a3;
            void **handle_ptr = (void **) a4;
            assert(handle_ptr);
            *handle_ptr = dlopen(path, flags);
            *sysret = 0;
            break;
        }

        /* Get the address of a function in a shared library. */
        case DLCALL_ID_GET_PROC_ADDRESS: {
            void *handle = (void *) a2;
            const char *name = (const char *) a3;
            void **entry_ptr = (void **) a4;
            assert(entry_ptr);
            *entry_ptr = dlsym(handle, name);
            *sysret = 0;
            break;
        }

        /* Free a shared library. */
        case DLCALL_ID_FREE_LIBRARY: {
            void *handle = (void *) a2;
            int *ret_ptr = (int *) a3;
            assert(ret_ptr);
            *ret_ptr = dlclose(handle);
            *sysret = 0;
            break;
        }

        /* Get the last error message for a library event. */
        case DLCALL_ID_GET_LIBRARY_ERROR: {
            const char **error_ptr = (const char **) a2;
            assert(error_ptr);
            *error_ptr = dlerror();
            *sysret = 0;
            break;
        }

        /* Invoke a function of a common interface. */
        case DLCALL_ID_INVOKE_PROC: {
            void *proc = (void *) a2;
            void *arg1 = (void *) a3;
            void *arg2 = (void *) a4;
            assert(proc);
            invoke_proc(proc, arg1, arg2);
            *sysret = 0;
            break;
        }

        default:
            *sysret = -EINVAL;
            break;
        }
        return true;
    }
    return false;
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    if (info->system_emulation) {
        fprintf(stderr, "plugin dlcall: only useful for user emulation\n");
        return -1;
    }

    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);
        if (g_strcmp0(tokens[0], "syscall_num") == 0) {
            const char *val = tokens[1];
            char *endptr = NULL;
            guint64 num;
            if (!val || *val == '\0') {
                fprintf(stderr,
                        "plugin dlcall: missing value for syscall_num\n");
                return -1;
            }
            num = g_ascii_strtoull(val, &endptr, 0);
            if (*endptr != '\0' || g_strrstr(val, "-") != NULL) {
                fprintf(stderr,
                        "plugin dlcall: invalid syscall_num '%s'\n", val);
                return -1;
            }
            if (num < DLCALL_SYSCALL_MIN || num > G_MAXINT64) {
                fprintf(stderr,
                        "plugin dlcall: syscall_num %s is out of range; "
                        "it must be >= %d to avoid clashing with a real "
                        "syscall\n", val, DLCALL_SYSCALL_MIN);
                return -1;
            }
            dlcall_syscall_num = (int64_t) num;
        } else {
            fprintf(stderr, "plugin dlcall: unknown option '%s'\n", opt);
            return -1;
        }
    }

    qemu_plugin_register_vcpu_syscall_filter_cb(id, vcpu_syscall_filter, NULL);

    return 0;
}
