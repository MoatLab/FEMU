/*
 * context switching
 * 2003-10 by SONE Takeshi
 *
 * Residual data portions:
 *     Copyright (c) 2004-2005 Jocelyn Mayer
 */

#include "config.h"
#include "kernel/kernel.h"
#include "context.h"
#include "arch/ppc/processor.h"
#include "arch/ppc/residual.h"
#include "drivers/drivers.h"
#include "libopenbios/bindings.h"
#include "libopenbios/ofmem.h"
#include "libopenbios/initprogram.h"
#include "libopenbios/sys_info.h"
#include "arch/ppc/processor.h"

#define MAIN_STACK_SIZE 16384
#define IMAGE_STACK_SIZE 4096*2

#define debug printk

#ifdef CONFIG_PPC_64BITSUPPORT
  #ifdef __powerpc64__
    #define ULONG_SIZE 8
    #define STACKFRAME_MINSIZE 48
    #define STKOFF STACKFRAME_MINSIZE
    #define SAVE_SPACE 320
  #else
    #define ULONG_SIZE 4
    #define STACKFRAME_MINSIZE 16
    #define STKOFF 8
    #define SAVE_SPACE 144
  #endif
#endif

static void start_main(void); /* forward decl. */
void __exit_context(void); /* assembly routine */

void entry(void);
void of_client_callback(void);

/*
 * Main context structure
 * It is placed at the bottom of our stack, and loaded by assembly routine
 * to start us up.
 */
static struct context main_ctx = {
    .pc = (unsigned long) start_main,
    .return_addr = (unsigned long) __exit_context,
};

/* This is used by assembly routine to load/store the context which
 * it is to switch/switched.  */
struct context * volatile __context = &main_ctx;

/* Client program context */
static struct context *client_ctx;

/* Stack for loaded ELF image */
static uint8_t image_stack[IMAGE_STACK_SIZE];

/* Pointer to startup context (physical address) */
unsigned long __boot_ctx;

/*
 * Main starter
 * This is the C function that runs first.
 */
static void start_main(void)
{
    /* Save startup context, so we can refer to it later.
     * We have to keep it in physical address since we will relocate. */
    __boot_ctx = virt_to_phys(__context);

    /* Set up client context */
    client_ctx = init_context(image_stack, sizeof image_stack, 1);
    __context = client_ctx;
    
    /* Start the real fun */
    entry();

    /* Returning from here should jump to __exit_context */
    __context = boot_ctx;
}

/* Setup a new context using the given stack.
 */
struct context *
init_context(uint8_t *stack, uint32_t stack_size, int num_params)
{
    struct context *ctx;

    ctx = (struct context *)
	(stack + stack_size - (sizeof(*ctx) + num_params*sizeof(unsigned long)));
    memset(ctx, 0, sizeof(*ctx));

    /* Fill in reasonable default for flat memory model */
    ctx->sp = virt_to_phys(SP_LOC(ctx));
    ctx->return_addr = virt_to_phys(__exit_context);
    
    return ctx;
}


/* Build PReP residual data */
static void *
residual_build(uint32_t memsize, uint32_t load_base, uint32_t load_size)
{
    residual_t *res;
    const unsigned char model[] = "IBM PPS Model 6015\0";
    int i;

    res = malloc(sizeof(residual_t));
    if (res == NULL) {
        return NULL;
    }

    res->length = sizeof(residual_t);
    res->version = 1;
    res->revision = 0;
    memcpy(res->vital.model, model, sizeof(model));
    res->vital.version = 1;
    res->vital.revision = 0;
    res->vital.firmware = 0x1D1;
    res->vital.NVRAM_size = 0x2000;
    res->vital.nSIMMslots = 1;
    res->vital.nISAslots = 0;
    res->vital.nPCIslots = 0;
    res->vital.nPCMCIAslots = 0;
    res->vital.nMCAslots = 0;
    res->vital.nEISAslots = 0;
    res->vital.CPUHz = 200 * 1000 * 1000;
    res->vital.busHz = 100 * 1000 * 1000;
    res->vital.PCIHz = 33 * 1000 * 1000;
    res->vital.TBdiv = 1000;
    res->vital.wwidth = 32;
    res->vital.page_size = 4096;
    res->vital.ChBlocSize = 32;
    res->vital.GrSize = 32;
    res->vital.cache_size = 0;
    res->vital.cache_type = 0; /* No cache */
    res->vital.cache_assoc = 8; /* Same as 601 */
    res->vital.cache_lnsize = 32;
    res->vital.Icache_size = 0;
    res->vital.Icache_assoc = 8;
    res->vital.Icache_lnsize = 32;
    res->vital.Dcache_size = 0;
    res->vital.Dcache_assoc = 8;
    res->vital.Dcache_lnsize = 32;
    res->vital.TLB_size = 0;
    res->vital.TLB_type = 0; /* None */
    res->vital.TLB_assoc = 2;
    res->vital.ITLB_size = 0;
    res->vital.ITLB_assoc = 2;
    res->vital.DTLB_size = 0;
    res->vital.DTLB_assoc = 2;
    res->vital.ext_vital = NULL;
    res->nCPUs = 1;
    res->CPUs[0].pvr = mfpvr();
    res->CPUs[0].serial = 0;
    res->CPUs[0].L2_size = 0;
    res->CPUs[0].L2_assoc = 8;
    /* Memory infos */
    res->max_mem = memsize;
    res->good_mem = memsize;
    /* Memory mappings */
    /* First segment: firmware */
    res->maps[0].usage = 0x0007;
    res->maps[0].base  = 0xfff00000;
    res->maps[0].count = 0x00100000 >> 12;
    i = 1;
    /* Boot image */
    load_size = (load_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    res->maps[i].usage = 0x0008;
    res->maps[i].base  = load_base >> 12;
    res->maps[i].count = load_size >> 12;
    i++;
    /* Free memory */
    res->maps[i].usage = 0x0010;
    res->maps[i].base  = (load_base + load_size) >> 12;
    res->maps[i].count = (memsize >> 12) - res->maps[i].base;
    i++;
    /* ISA IO region : 8MB */
    res->maps[i].usage = 0x0040;
    res->maps[i].base  = 0x80000000 >> 12;
    res->maps[i].count = 0x00800000 >> 12;
    i++;
    /* System registers : 8MB */
    res->maps[i].usage = 0x0200;
    res->maps[i].base  = 0xBF800000 >> 12;
    res->maps[i].count = 0x00800000 >> 12;
    i++;
    /* System ROM : 64 kB */
    res->maps[i].usage = 0x2000;
    res->maps[i].base  = 0xFFFF0000 >> 12;
    res->maps[i].count = 0x00010000 >> 12;
    i++;
    res->nmaps = i;
    /* Memory SIMMs */
    res->nmems = 1;
    res->memories[0].size = memsize;
    /* Describe no devices */
    res->ndevices = 0;

    return res;
}

/* init-program */
int
arch_init_program(void)
{
    volatile struct context *ctx = __context;
    ucell entry, param, loadbase, loadsize;
    ofmem_t *ofmem = ofmem_arch_get_private();
    
    /* According to IEEE 1275, PPC bindings:
     *
     *    MSR = FP, ME + (DR|IR)
     *    r1 = stack (32 K + 32 bytes link area above)
     *    r5 = client interface handler
     *    r6 = address of client program arguments (unused)
     *    r7 = length of client program arguments (unused)
     *
     *    Yaboot and Linux use r3 and r4 for initrd address and size
     *    PReP machines use r3 and r4 for residual data and load image
     */

    ctx->regs[REG_R5] = (unsigned long)of_client_callback;
    ctx->regs[REG_R6] = 0;
    ctx->regs[REG_R7] = 0;

    /* Override the stack in the default context: the OpenBSD bootloader
       fails soon after setting up virt to phys mappings with the default
       stack. My best guess is that this is because the malloc() heap
       doesn't have a 1:1 virt to phys mapping. So for the moment we use
       the original (pre-context) location just under the MMU hash table
       (SDR1) which is mapped 1:1 and makes the bootloader happy. */
    ctx->sp = mfsdr1() - 32768 - 65536;

    /* Set param */
    feval("load-state >ls.param @");
    param = POP();
    ctx->param[0] = param;
    
    /* Set entry point */
    feval("load-state >ls.entry @");
    entry = POP();
    ctx->pc = entry;

    /* Residual data for PReP */
    if (!is_apple()) {
        fword("load-base");
        loadbase = POP();
        fword("load-size");
        loadsize = POP();

        ctx->regs[REG_R3] = (uintptr_t)residual_build((uint32_t)ofmem->ramsize,
                                                      loadbase, loadsize);
        ctx->regs[REG_R4] = loadbase;
    }

    return 0;
}

/* Switch to another context. */
struct context *switch_to(struct context *ctx)
{
    volatile struct context *save;
    struct context *ret;
    unsigned int lr;

    debug("switching to new context:\n");
    save = __context;
    __context = ctx;

    asm __volatile__ ("mflr %%r9\n\t"
                      "stw %%r9, %0\n\t"
                      "bl __switch_context\n\t"
                      "lwz %%r9, %0\n\t"
                      "mtlr %%r9\n\t" : "=m" (lr) : "m" (lr) : "%r9" );
    
    ret = __context;
    __context = (struct context *)save;
    return ret;
}

/* Start ELF Boot image */
unsigned int start_elf(void)
{
    volatile struct context *ctx = __context;

    ctx = switch_to((struct context *)ctx);
    return ctx->regs[REG_R3];
}
