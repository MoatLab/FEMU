/*
 * Utility function to get the minimum mmap address.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "user/mmap-min-addr.h"
#ifdef __FreeBSD__
#include <sys/sysctl.h>
#include <sys/user.h>
#endif

uintptr_t mmap_min_addr;

static void __attribute__((constructor)) init(void)
{
#ifdef __linux__
    /*
     * We prefer to not make NULL pointers accessible to QEMU.
     * If something goes wrong below, fall back to 1 page.
     */
    size_t min_addr = qemu_real_host_page_size();
    /*
     * Read in mmap_min_addr kernel parameter.  This value is used
     * When loading the ELF image to determine whether guest_base
     * is needed.  It is also used in mmap_find_vma.
     */
    FILE *fp = fopen("/proc/sys/vm/mmap_min_addr", "r");

    if (fp) {
        unsigned long tmp;
        if (fscanf(fp, "%lu", &tmp) == 1 && tmp != 0) {
            min_addr = MAX(min_addr, tmp);
        }
        fclose(fp);
    }
    mmap_min_addr = min_addr;
#elif defined(__FreeBSD__)
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_VM_LAYOUT, getpid() };
    struct kinfo_vm_layout info;
    size_t info_len = sizeof(info);

    mmap_min_addr =
        (sysctl(mib, ARRAY_SIZE(mib), &info, &info_len, NULL, 0) < 0
         ? qemu_real_host_page_size()
         : info.kvm_min_user_addr);
#else
# error
#endif
}
