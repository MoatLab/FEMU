/*
 * context switching
 * 2003-10 by SONE Takeshi
 */

#include "config.h"
#include "kernel/kernel.h"
#include "context.h"
#include "libopenbios/bindings.h"
#include "libopenbios/initprogram.h"
#include "libopenbios/sys_info.h"
#include "boot.h"
#include "openbios.h"

#define MAIN_STACK_SIZE 16384
#define IMAGE_STACK_SIZE 4096*2

#define debug printk

static void start_main(void); /* forward decl. */
void __exit_context(void); /* assembly routine */

/*
 * Main context structure
 * It is placed at the bottom of our stack, and loaded by assembly routine
 * to start us up.
 */
static struct context main_ctx = {
    .pc = (uint32_t) start_main,
    .npc = (uint32_t) start_main + 4,
    .return_addr = (uint32_t) __exit_context,
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
    openbios();

    /* Returning from here should jump to __exit_context */
    __context = boot_ctx;
}

#define CTX_OFFSET(n) (sizeof(struct context) + n * sizeof(uint32_t))

/* Setup a new context using the given stack.
 */
struct context *
init_context(uint8_t *stack, uint32_t stack_size, int num_params)
{
    struct context *ctx;

    ctx = (struct context *)
	(stack + stack_size - CTX_OFFSET(num_params));
    /* Use valid window state from startup */
    memcpy(ctx, &main_ctx, sizeof(struct context));

    /* Fill in reasonable default for flat memory model */
    ctx->regs[REG_SP] = virt_to_phys(SP_LOC(ctx));
    ctx->return_addr = virt_to_phys(__exit_context);

    return ctx;
}

/* init-program */
int
arch_init_program(void)
{
    volatile struct context *ctx = __context;
    ucell entry;

    ctx->regs[REG_O0] = (unsigned long)romvec;
    ctx->regs[REG_SP] = (unsigned long)malloc(IMAGE_STACK_SIZE) + IMAGE_STACK_SIZE - CTX_OFFSET(1);

    /* Set entry point */
    feval("load-state >ls.entry @");
    entry = POP();
    ctx->pc = entry;

    return 0;
}

/* Switch to another context. */
struct context *switch_to(struct context *ctx)
{
    volatile struct context *save;
    struct context *ret;

    debug("switching to new context:\n");
    save = __context;
    __context = ctx;
    asm __volatile__ ("\n\tcall __switch_context"
                      "\n\tnop" ::: "g1", "g2", "g3", "g4", "g5", "g6", "g7",
                      "o0", "o1", "o2", "o3", "o4", "o5", "o7",
                      "l0", "l1", "l2", "l3", "l4", "l5", "l6", "l7",
                      "i0", "i1", "i2", "i3", "i4", "i5", "i7",
                      "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9",
                      "f10", "f11", "f12", "f13", "f14", "f15", "f16", "f17", "f18", "f19",
                      "f20", "f21", "f22", "f23", "f24", "f25", "f26", "f27", "f28", "f29",
                      "f30", "f31",
                      "memory");
    ret = __context;
    __context = (struct context *)save;
    return ret;
}

/* Start ELF Boot image */
unsigned int start_elf(void)
{
    volatile struct context *ctx = __context;;

    ctx = switch_to((struct context *)ctx);
    return ctx->regs[REG_O0];
}
