/*
 * os-posix-lib.c
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 * Copyright (c) 2010 Red Hat, Inc.
 *
 * QEMU library functions on POSIX which are shared between QEMU and
 * the QEMU tools.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include <termios.h>

#include <glib/gprintf.h>

#include "qemu-common.h"
#include "sysemu/sysemu.h"
#include "trace.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/madvise.h"
#include "qemu/sockets.h"
#include "qemu/thread.h"
#include <libgen.h>
#include "qemu/cutils.h"
#include "qemu/compiler.h"
#include "qemu/units.h"

#ifdef CONFIG_LINUX
#include <sys/syscall.h>
#endif

#ifdef __FreeBSD__
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/thr.h>
#include <libutil.h>
#endif

#ifdef __NetBSD__
#include <sys/sysctl.h>
#include <lwp.h>
#endif

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

#ifdef __HAIKU__
#include <kernel/image.h>
#endif

#include "qemu/mmap-alloc.h"

#ifdef CONFIG_DEBUG_STACK_USAGE
#include "qemu/error-report.h"
#endif

#define MAX_MEM_PREALLOC_THREAD_COUNT 16

struct MemsetThread;

typedef struct MemsetContext {
    bool all_threads_created;
    bool any_thread_failed;
    struct MemsetThread *threads;
    int num_threads;
} MemsetContext;

struct MemsetThread {
    char *addr;
    size_t numpages;
    size_t hpagesize;
    QemuThread pgthread;
    sigjmp_buf env;
    MemsetContext *context;
};
typedef struct MemsetThread MemsetThread;

/* used by sigbus_handler() */
static MemsetContext *sigbus_memset_context;
struct sigaction sigbus_oldact;
static QemuMutex sigbus_mutex;

static QemuMutex page_mutex;
static QemuCond page_cond;

int qemu_get_thread_id(void)
{
#if defined(__linux__)
    return syscall(SYS_gettid);
#elif defined(__FreeBSD__)
    /* thread id is up to INT_MAX */
    long tid;
    thr_self(&tid);
    return (int)tid;
#elif defined(__NetBSD__)
    return _lwp_self();
#elif defined(__OpenBSD__)
    return getthrid();
#else
    return getpid();
#endif
}

int qemu_daemon(int nochdir, int noclose)
{
    return daemon(nochdir, noclose);
}

bool qemu_write_pidfile(const char *path, Error **errp)
{
    int fd;
    char pidstr[32];

    while (1) {
        struct stat a, b;
        struct flock lock = {
            .l_type = F_WRLCK,
            .l_whence = SEEK_SET,
            .l_len = 0,
        };

        fd = qemu_open_old(path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
        if (fd == -1) {
            error_setg_errno(errp, errno, "Cannot open pid file");
            return false;
        }

        if (fstat(fd, &b) < 0) {
            error_setg_errno(errp, errno, "Cannot stat file");
            goto fail_close;
        }

        if (fcntl(fd, F_SETLK, &lock)) {
            error_setg_errno(errp, errno, "Cannot lock pid file");
            goto fail_close;
        }

        /*
         * Now make sure the path we locked is the same one that now
         * exists on the filesystem.
         */
        if (stat(path, &a) < 0) {
            /*
             * PID file disappeared, someone else must be racing with
             * us, so try again.
             */
            close(fd);
            continue;
        }

        if (a.st_ino == b.st_ino) {
            break;
        }

        /*
         * PID file was recreated, someone else must be racing with
         * us, so try again.
         */
        close(fd);
    }

    if (ftruncate(fd, 0) < 0) {
        error_setg_errno(errp, errno, "Failed to truncate pid file");
        goto fail_unlink;
    }

    snprintf(pidstr, sizeof(pidstr), FMT_pid "\n", getpid());
    if (write(fd, pidstr, strlen(pidstr)) != strlen(pidstr)) {
        error_setg(errp, "Failed to write pid file");
        goto fail_unlink;
    }

    return true;

fail_unlink:
    unlink(path);
fail_close:
    close(fd);
    return false;
}

/* alloc shared memory pages */
void *qemu_anon_ram_alloc(size_t size, uint64_t *alignment, bool shared,
                          bool noreserve)
{
    const uint32_t qemu_map_flags = (shared ? QEMU_MAP_SHARED : 0) |
                                    (noreserve ? QEMU_MAP_NORESERVE : 0);
    size_t align = QEMU_VMALLOC_ALIGN;
    void *ptr = qemu_ram_mmap(-1, size, align, qemu_map_flags, 0);

    if (ptr == MAP_FAILED) {
        return NULL;
    }

    if (alignment) {
        *alignment = align;
    }

    trace_qemu_anon_ram_alloc(size, ptr);
    return ptr;
}

void qemu_anon_ram_free(void *ptr, size_t size)
{
    trace_qemu_anon_ram_free(ptr, size);
    qemu_ram_munmap(-1, ptr, size);
}

void qemu_set_block(int fd)
{
    int f;
    f = fcntl(fd, F_GETFL);
    assert(f != -1);
    f = fcntl(fd, F_SETFL, f & ~O_NONBLOCK);
    assert(f != -1);
}

int qemu_try_set_nonblock(int fd)
{
    int f;
    f = fcntl(fd, F_GETFL);
    if (f == -1) {
        return -errno;
    }
    if (fcntl(fd, F_SETFL, f | O_NONBLOCK) == -1) {
        return -errno;
    }
    return 0;
}

void qemu_set_nonblock(int fd)
{
    int f;
    f = qemu_try_set_nonblock(fd);
    assert(f == 0);
}

int socket_set_fast_reuse(int fd)
{
    int val = 1, ret;

    ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                     (const char *)&val, sizeof(val));

    assert(ret == 0);

    return ret;
}

void qemu_set_cloexec(int fd)
{
    int f;
    f = fcntl(fd, F_GETFD);
    assert(f != -1);
    f = fcntl(fd, F_SETFD, f | FD_CLOEXEC);
    assert(f != -1);
}

/*
 * Creates a pipe with FD_CLOEXEC set on both file descriptors
 */
int qemu_pipe(int pipefd[2])
{
    int ret;

#ifdef CONFIG_PIPE2
    ret = pipe2(pipefd, O_CLOEXEC);
    if (ret != -1 || errno != ENOSYS) {
        return ret;
    }
#endif
    ret = pipe(pipefd);
    if (ret == 0) {
        qemu_set_cloexec(pipefd[0]);
        qemu_set_cloexec(pipefd[1]);
    }

    return ret;
}

char *
qemu_get_local_state_pathname(const char *relative_pathname)
{
    g_autofree char *dir = g_strdup_printf("%s/%s",
                                           CONFIG_QEMU_LOCALSTATEDIR,
                                           relative_pathname);
    return get_relocated_path(dir);
}

void qemu_set_tty_echo(int fd, bool echo)
{
    struct termios tty;

    tcgetattr(fd, &tty);

    if (echo) {
        tty.c_lflag |= ECHO | ECHONL | ICANON | IEXTEN;
    } else {
        tty.c_lflag &= ~(ECHO | ECHONL | ICANON | IEXTEN);
    }

    tcsetattr(fd, TCSANOW, &tty);
}

static const char *exec_dir;

void qemu_init_exec_dir(const char *argv0)
{
    char *p = NULL;
    char buf[PATH_MAX];

    if (exec_dir) {
        return;
    }

#if defined(__linux__)
    {
        int len;
        len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
        if (len > 0) {
            buf[len] = 0;
            p = buf;
        }
    }
#elif defined(__FreeBSD__) \
      || (defined(__NetBSD__) && defined(KERN_PROC_PATHNAME))
    {
#if defined(__FreeBSD__)
        static int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1};
#else
        static int mib[4] = {CTL_KERN, KERN_PROC_ARGS, -1, KERN_PROC_PATHNAME};
#endif
        size_t len = sizeof(buf) - 1;

        *buf = '\0';
        if (!sysctl(mib, ARRAY_SIZE(mib), buf, &len, NULL, 0) &&
            *buf) {
            buf[sizeof(buf) - 1] = '\0';
            p = buf;
        }
    }
#elif defined(__APPLE__)
    {
        char fpath[PATH_MAX];
        uint32_t len = sizeof(fpath);
        if (_NSGetExecutablePath(fpath, &len) == 0) {
            p = realpath(fpath, buf);
            if (!p) {
                return;
            }
        }
    }
#elif defined(__HAIKU__)
    {
        image_info ii;
        int32_t c = 0;

        *buf = '\0';
        while (get_next_image_info(0, &c, &ii) == B_OK) {
            if (ii.type == B_APP_IMAGE) {
                strncpy(buf, ii.name, sizeof(buf));
                buf[sizeof(buf) - 1] = 0;
                p = buf;
                break;
            }
        }
    }
#endif
    /* If we don't have any way of figuring out the actual executable
       location then try argv[0].  */
    if (!p && argv0) {
        p = realpath(argv0, buf);
    }
    if (p) {
        exec_dir = g_path_get_dirname(p);
    } else {
        exec_dir = CONFIG_BINDIR;
    }
}

const char *qemu_get_exec_dir(void)
{
    return exec_dir;
}

#ifdef CONFIG_LINUX
static void sigbus_handler(int signal, siginfo_t *siginfo, void *ctx)
#else /* CONFIG_LINUX */
static void sigbus_handler(int signal)
#endif /* CONFIG_LINUX */
{
    int i;

    if (sigbus_memset_context) {
        for (i = 0; i < sigbus_memset_context->num_threads; i++) {
            MemsetThread *thread = &sigbus_memset_context->threads[i];

            if (qemu_thread_is_self(&thread->pgthread)) {
                siglongjmp(thread->env, 1);
            }
        }
    }

#ifdef CONFIG_LINUX
    /*
     * We assume that the MCE SIGBUS handler could have been registered. We
     * should never receive BUS_MCEERR_AO on any of our threads, but only on
     * the main thread registered for PR_MCE_KILL_EARLY. Further, we should not
     * receive BUS_MCEERR_AR triggered by action of other threads on one of
     * our threads. So, no need to check for unrelated SIGBUS when seeing one
     * for our threads.
     *
     * We will forward to the MCE handler, which will either handle the SIGBUS
     * or reinstall the default SIGBUS handler and reraise the SIGBUS. The
     * default SIGBUS handler will crash the process, so we don't care.
     */
    if (sigbus_oldact.sa_flags & SA_SIGINFO) {
        sigbus_oldact.sa_sigaction(signal, siginfo, ctx);
        return;
    }
#endif /* CONFIG_LINUX */
    warn_report("os_mem_prealloc: unrelated SIGBUS detected and ignored");
}

static void *do_touch_pages(void *arg)
{
    MemsetThread *memset_args = (MemsetThread *)arg;
    sigset_t set, oldset;
    int ret = 0;

    /*
     * On Linux, the page faults from the loop below can cause mmap_sem
     * contention with allocation of the thread stacks.  Do not start
     * clearing until all threads have been created.
     */
    qemu_mutex_lock(&page_mutex);
    while (!memset_args->context->all_threads_created) {
        qemu_cond_wait(&page_cond, &page_mutex);
    }
    qemu_mutex_unlock(&page_mutex);

    /* unblock SIGBUS */
    sigemptyset(&set);
    sigaddset(&set, SIGBUS);
    pthread_sigmask(SIG_UNBLOCK, &set, &oldset);

    if (sigsetjmp(memset_args->env, 1)) {
        ret = -EFAULT;
    } else {
        char *addr = memset_args->addr;
        size_t numpages = memset_args->numpages;
        size_t hpagesize = memset_args->hpagesize;
        size_t i;
        for (i = 0; i < numpages; i++) {
            /*
             * Read & write back the same value, so we don't
             * corrupt existing user/app data that might be
             * stored.
             *
             * 'volatile' to stop compiler optimizing this away
             * to a no-op
             */
            *(volatile char *)addr = *addr;
            addr += hpagesize;
        }
    }
    pthread_sigmask(SIG_SETMASK, &oldset, NULL);
    return (void *)(uintptr_t)ret;
}

static void *do_madv_populate_write_pages(void *arg)
{
    MemsetThread *memset_args = (MemsetThread *)arg;
    const size_t size = memset_args->numpages * memset_args->hpagesize;
    char * const addr = memset_args->addr;
    int ret = 0;

    /* See do_touch_pages(). */
    qemu_mutex_lock(&page_mutex);
    while (!memset_args->context->all_threads_created) {
        qemu_cond_wait(&page_cond, &page_mutex);
    }
    qemu_mutex_unlock(&page_mutex);

    if (size && qemu_madvise(addr, size, QEMU_MADV_POPULATE_WRITE)) {
        ret = -errno;
    }
    return (void *)(uintptr_t)ret;
}

static inline int get_memset_num_threads(size_t hpagesize, size_t numpages,
                                         int smp_cpus)
{
    long host_procs = sysconf(_SC_NPROCESSORS_ONLN);
    int ret = 1;

    if (host_procs > 0) {
        ret = MIN(MIN(host_procs, MAX_MEM_PREALLOC_THREAD_COUNT), smp_cpus);
    }

    /* Especially with gigantic pages, don't create more threads than pages. */
    ret = MIN(ret, numpages);
    /* Don't start threads to prealloc comparatively little memory. */
    ret = MIN(ret, MAX(1, hpagesize * numpages / (64 * MiB)));

    /* In case sysconf() fails, we fall back to single threaded */
    return ret;
}

static int touch_all_pages(char *area, size_t hpagesize, size_t numpages,
                           int smp_cpus, bool use_madv_populate_write)
{
    static gsize initialized = 0;
    MemsetContext context = {
        .num_threads = get_memset_num_threads(hpagesize, numpages, smp_cpus),
    };
    size_t numpages_per_thread, leftover;
    void *(*touch_fn)(void *);
    int ret = 0, i = 0;
    char *addr = area;

    if (g_once_init_enter(&initialized)) {
        qemu_mutex_init(&page_mutex);
        qemu_cond_init(&page_cond);
        g_once_init_leave(&initialized, 1);
    }

    if (use_madv_populate_write) {
        /* Avoid creating a single thread for MADV_POPULATE_WRITE */
        if (context.num_threads == 1) {
            if (qemu_madvise(area, hpagesize * numpages,
                             QEMU_MADV_POPULATE_WRITE)) {
                return -errno;
            }
            return 0;
        }
        touch_fn = do_madv_populate_write_pages;
    } else {
        touch_fn = do_touch_pages;
    }

    context.threads = g_new0(MemsetThread, context.num_threads);
    numpages_per_thread = numpages / context.num_threads;
    leftover = numpages % context.num_threads;
    for (i = 0; i < context.num_threads; i++) {
        context.threads[i].addr = addr;
        context.threads[i].numpages = numpages_per_thread + (i < leftover);
        context.threads[i].hpagesize = hpagesize;
        context.threads[i].context = &context;
        qemu_thread_create(&context.threads[i].pgthread, "touch_pages",
                           touch_fn, &context.threads[i],
                           QEMU_THREAD_JOINABLE);
        addr += context.threads[i].numpages * hpagesize;
    }

    if (!use_madv_populate_write) {
        sigbus_memset_context = &context;
    }

    qemu_mutex_lock(&page_mutex);
    context.all_threads_created = true;
    qemu_cond_broadcast(&page_cond);
    qemu_mutex_unlock(&page_mutex);

    for (i = 0; i < context.num_threads; i++) {
        int tmp = (uintptr_t)qemu_thread_join(&context.threads[i].pgthread);

        if (tmp) {
            ret = tmp;
        }
    }

    if (!use_madv_populate_write) {
        sigbus_memset_context = NULL;
    }
    g_free(context.threads);

    return ret;
}

static bool madv_populate_write_possible(char *area, size_t pagesize)
{
    return !qemu_madvise(area, pagesize, QEMU_MADV_POPULATE_WRITE) ||
           errno != EINVAL;
}

void os_mem_prealloc(int fd, char *area, size_t memory, int smp_cpus,
                     Error **errp)
{
    static gsize initialized;
    int ret;
    size_t hpagesize = qemu_fd_getpagesize(fd);
    size_t numpages = DIV_ROUND_UP(memory, hpagesize);
    bool use_madv_populate_write;
    struct sigaction act;

    /*
     * Sense on every invocation, as MADV_POPULATE_WRITE cannot be used for
     * some special mappings, such as mapping /dev/mem.
     */
    use_madv_populate_write = madv_populate_write_possible(area, hpagesize);

    if (!use_madv_populate_write) {
        if (g_once_init_enter(&initialized)) {
            qemu_mutex_init(&sigbus_mutex);
            g_once_init_leave(&initialized, 1);
        }

        qemu_mutex_lock(&sigbus_mutex);
        memset(&act, 0, sizeof(act));
#ifdef CONFIG_LINUX
        act.sa_sigaction = &sigbus_handler;
        act.sa_flags = SA_SIGINFO;
#else /* CONFIG_LINUX */
        act.sa_handler = &sigbus_handler;
        act.sa_flags = 0;
#endif /* CONFIG_LINUX */

        ret = sigaction(SIGBUS, &act, &sigbus_oldact);
        if (ret) {
            qemu_mutex_unlock(&sigbus_mutex);
            error_setg_errno(errp, errno,
                "os_mem_prealloc: failed to install signal handler");
            return;
        }
    }

    /* touch pages simultaneously */
    ret = touch_all_pages(area, hpagesize, numpages, smp_cpus,
                          use_madv_populate_write);
    if (ret) {
        error_setg_errno(errp, -ret,
                         "os_mem_prealloc: preallocating memory failed");
    }

    if (!use_madv_populate_write) {
        ret = sigaction(SIGBUS, &sigbus_oldact, NULL);
        if (ret) {
            /* Terminate QEMU since it can't recover from error */
            perror("os_mem_prealloc: failed to reinstall signal handler");
            exit(1);
        }
        qemu_mutex_unlock(&sigbus_mutex);
    }
}

char *qemu_get_pid_name(pid_t pid)
{
    char *name = NULL;

#if defined(__FreeBSD__)
    /* BSDs don't have /proc, but they provide a nice substitute */
    struct kinfo_proc *proc = kinfo_getproc(pid);

    if (proc) {
        name = g_strdup(proc->ki_comm);
        free(proc);
    }
#else
    /* Assume a system with reasonable procfs */
    char *pid_path;
    size_t len;

    pid_path = g_strdup_printf("/proc/%d/cmdline", pid);
    g_file_get_contents(pid_path, &name, &len, NULL);
    g_free(pid_path);
#endif

    return name;
}


pid_t qemu_fork(Error **errp)
{
    sigset_t oldmask, newmask;
    struct sigaction sig_action;
    int saved_errno;
    pid_t pid;

    /*
     * Need to block signals now, so that child process can safely
     * kill off caller's signal handlers without a race.
     */
    sigfillset(&newmask);
    if (pthread_sigmask(SIG_SETMASK, &newmask, &oldmask) != 0) {
        error_setg_errno(errp, errno,
                         "cannot block signals");
        return -1;
    }

    pid = fork();
    saved_errno = errno;

    if (pid < 0) {
        /* attempt to restore signal mask, but ignore failure, to
         * avoid obscuring the fork failure */
        (void)pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
        error_setg_errno(errp, saved_errno,
                         "cannot fork child process");
        errno = saved_errno;
        return -1;
    } else if (pid) {
        /* parent process */

        /* Restore our original signal mask now that the child is
         * safely running. Only documented failures are EFAULT (not
         * possible, since we are using just-grabbed mask) or EINVAL
         * (not possible, since we are using correct arguments).  */
        (void)pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
    } else {
        /* child process */
        size_t i;

        /* Clear out all signal handlers from parent so nothing
         * unexpected can happen in our child once we unblock
         * signals */
        sig_action.sa_handler = SIG_DFL;
        sig_action.sa_flags = 0;
        sigemptyset(&sig_action.sa_mask);

        for (i = 1; i < NSIG; i++) {
            /* Only possible errors are EFAULT or EINVAL The former
             * won't happen, the latter we expect, so no need to check
             * return value */
            (void)sigaction(i, &sig_action, NULL);
        }

        /* Unmask all signals in child, since we've no idea what the
         * caller's done with their signal mask and don't want to
         * propagate that to children */
        sigemptyset(&newmask);
        if (pthread_sigmask(SIG_SETMASK, &newmask, NULL) != 0) {
            Error *local_err = NULL;
            error_setg_errno(&local_err, errno,
                             "cannot unblock signals");
            error_report_err(local_err);
            _exit(1);
        }
    }
    return pid;
}

void *qemu_alloc_stack(size_t *sz)
{
    void *ptr, *guardpage;
    int flags;
#ifdef CONFIG_DEBUG_STACK_USAGE
    void *ptr2;
#endif
    size_t pagesz = qemu_real_host_page_size;
#ifdef _SC_THREAD_STACK_MIN
    /* avoid stacks smaller than _SC_THREAD_STACK_MIN */
    long min_stack_sz = sysconf(_SC_THREAD_STACK_MIN);
    *sz = MAX(MAX(min_stack_sz, 0), *sz);
#endif
    /* adjust stack size to a multiple of the page size */
    *sz = ROUND_UP(*sz, pagesz);
    /* allocate one extra page for the guard page */
    *sz += pagesz;

    flags = MAP_PRIVATE | MAP_ANONYMOUS;
#if defined(MAP_STACK) && defined(__OpenBSD__)
    /* Only enable MAP_STACK on OpenBSD. Other OS's such as
     * Linux/FreeBSD/NetBSD have a flag with the same name
     * but have differing functionality. OpenBSD will SEGV
     * if it spots execution with a stack pointer pointing
     * at memory that was not allocated with MAP_STACK.
     */
    flags |= MAP_STACK;
#endif

    ptr = mmap(NULL, *sz, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (ptr == MAP_FAILED) {
        perror("failed to allocate memory for stack");
        abort();
    }

#if defined(HOST_IA64)
    /* separate register stack */
    guardpage = ptr + (((*sz - pagesz) / 2) & ~pagesz);
#elif defined(HOST_HPPA)
    /* stack grows up */
    guardpage = ptr + *sz - pagesz;
#else
    /* stack grows down */
    guardpage = ptr;
#endif
    if (mprotect(guardpage, pagesz, PROT_NONE) != 0) {
        perror("failed to set up stack guard page");
        abort();
    }

#ifdef CONFIG_DEBUG_STACK_USAGE
    for (ptr2 = ptr + pagesz; ptr2 < ptr + *sz; ptr2 += sizeof(uint32_t)) {
        *(uint32_t *)ptr2 = 0xdeadbeaf;
    }
#endif

    return ptr;
}

#ifdef CONFIG_DEBUG_STACK_USAGE
static __thread unsigned int max_stack_usage;
#endif

void qemu_free_stack(void *stack, size_t sz)
{
#ifdef CONFIG_DEBUG_STACK_USAGE
    unsigned int usage;
    void *ptr;

    for (ptr = stack + qemu_real_host_page_size; ptr < stack + sz;
         ptr += sizeof(uint32_t)) {
        if (*(uint32_t *)ptr != 0xdeadbeaf) {
            break;
        }
    }
    usage = sz - (uintptr_t) (ptr - stack);
    if (usage > max_stack_usage) {
        error_report("thread %d max stack usage increased from %u to %u",
                     qemu_get_thread_id(), max_stack_usage, usage);
        max_stack_usage = usage;
    }
#endif

    munmap(stack, sz);
}

/*
 * Disable CFI checks.
 * We are going to call a signal hander directly. Such handler may or may not
 * have been defined in our binary, so there's no guarantee that the pointer
 * used to set the handler is a cfi-valid pointer. Since the handlers are
 * stored in kernel memory, changing the handler to an attacker-defined
 * function requires being able to call a sigaction() syscall,
 * which is not as easy as overwriting a pointer in memory.
 */
QEMU_DISABLE_CFI
void sigaction_invoke(struct sigaction *action,
                      struct qemu_signalfd_siginfo *info)
{
    siginfo_t si = {};
    si.si_signo = info->ssi_signo;
    si.si_errno = info->ssi_errno;
    si.si_code = info->ssi_code;

    /* Convert the minimal set of fields defined by POSIX.
     * Positive si_code values are reserved for kernel-generated
     * signals, where the valid siginfo fields are determined by
     * the signal number.  But according to POSIX, it is unspecified
     * whether SI_USER and SI_QUEUE have values less than or equal to
     * zero.
     */
    if (info->ssi_code == SI_USER || info->ssi_code == SI_QUEUE ||
        info->ssi_code <= 0) {
        /* SIGTERM, etc.  */
        si.si_pid = info->ssi_pid;
        si.si_uid = info->ssi_uid;
    } else if (info->ssi_signo == SIGILL || info->ssi_signo == SIGFPE ||
               info->ssi_signo == SIGSEGV || info->ssi_signo == SIGBUS) {
        si.si_addr = (void *)(uintptr_t)info->ssi_addr;
    } else if (info->ssi_signo == SIGCHLD) {
        si.si_pid = info->ssi_pid;
        si.si_status = info->ssi_status;
        si.si_uid = info->ssi_uid;
    }
    action->sa_sigaction(info->ssi_signo, &si, NULL);
}

#ifndef HOST_NAME_MAX
# ifdef _POSIX_HOST_NAME_MAX
#  define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
# else
#  define HOST_NAME_MAX 255
# endif
#endif

char *qemu_get_host_name(Error **errp)
{
    long len = -1;
    g_autofree char *hostname = NULL;

#ifdef _SC_HOST_NAME_MAX
    len = sysconf(_SC_HOST_NAME_MAX);
#endif /* _SC_HOST_NAME_MAX */

    if (len < 0) {
        len = HOST_NAME_MAX;
    }

    /* Unfortunately, gethostname() below does not guarantee a
     * NULL terminated string. Therefore, allocate one byte more
     * to be sure. */
    hostname = g_new0(char, len + 1);

    if (gethostname(hostname, len) < 0) {
        error_setg_errno(errp, errno,
                         "cannot get hostname");
        return NULL;
    }

    return g_steal_pointer(&hostname);
}

size_t qemu_get_host_physmem(void)
{
#ifdef _SC_PHYS_PAGES
    long pages = sysconf(_SC_PHYS_PAGES);
    if (pages > 0) {
        if (pages > SIZE_MAX / qemu_real_host_page_size) {
            return SIZE_MAX;
        } else {
            return pages * qemu_real_host_page_size;
        }
    }
#endif
    return 0;
}
