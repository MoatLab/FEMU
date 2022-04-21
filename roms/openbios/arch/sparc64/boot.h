/* tag: openbios loader prototypes for sparc64
 *
 * Copyright (C) 2004 Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#define INITRD_VIRT_ADDR    0x40c00000
#define IMAGE_VIRT_ADDR     0x40000000

// linux_load.c
int linux_load(struct sys_info *info, const char *file, const char *cmdline);

// boot.c
extern uint64_t kernel_image;
extern uint64_t kernel_size;
extern uint64_t initrd_image;
extern uint64_t initrd_size;
extern uint64_t qemu_cmdline;
extern uint64_t cmdline_size;
extern char *boot_device;
extern void boot(void);

// sys_info.c
extern uint64_t qemu_mem_size;
extern void collect_sys_info(struct sys_info *info);

// console.c
void ob_su_init(uint64_t base, uint64_t offset, int intr);
void cls(void);

// lib.c
void ob_mmu_init(const char *cpuname, uint64_t ram_size);
void prom_debug_handler(void);
