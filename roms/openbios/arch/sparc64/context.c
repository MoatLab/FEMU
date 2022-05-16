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
#define IMAGE_STACK_SIZE 4096*4

#define debug printk

static void start_main(void); /* forward decl. */
void __exit_context(void); /* assembly routine */

/*
 * Main context structure
 * It is placed at the bottom of our stack, and loaded by assembly routine
 * to start us up.
 */
static struct context main_ctx = {
    .pc = (uint64_t) start_main,
    .npc = (uint64_t) start_main + 4,
    .return_addr = (uint64_t) __exit_context,
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

/* Pointer to Forth context stack */
void *_fcstack_ptr = &_efcstack;


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

static uint64_t ALIGN_SIZE(uint64_t x, uint64_t a)
{
    return (x + a - 1) & ~(a-1);
}

#define CTX_OFFSET(n) ALIGN_SIZE(sizeof(struct context) + n * sizeof(uint64_t), sizeof(uint64_t))

/* Setup a new context using the given stack.
 */
struct context *
init_context(uint8_t *stack, uint64_t stack_size, int num_params)
{
    struct context *ctx;
    uint8_t *stack_top = stack + stack_size;

    ctx = (struct context *)(stack_top - CTX_OFFSET(num_params));
    /* Use valid window state from startup */
    memcpy(ctx, &main_ctx, sizeof(struct context));

    /* Fill in reasonable default for flat memory model */
    ctx->return_addr = virt_to_phys(__exit_context);

    return ctx;
}

/* init-program */
extern uint64_t sparc64_of_client_interface;

int
arch_init_program(void)
{
    volatile struct context *ctx = __context;
    ucell entry, param;

    ctx->regs[REG_O0] = 0;
    ctx->regs[REG_O0+4] = (uint64_t)&sparc64_of_client_interface;
    ctx->regs[REG_SP] = (uint64_t)malloc(IMAGE_STACK_SIZE) + IMAGE_STACK_SIZE - CTX_OFFSET(0) - STACK_BIAS;

    /* Set param */
    feval("load-state >ls.param @");
    param = POP();
    ctx->param[0] = param;

    /* Set entry point */
    feval("load-state >ls.entry @");
    entry = POP();
    ctx->pc = entry;
    ctx->npc = entry+4;

    return 0;
}

/* Switch to another context. */
struct context *switch_to(struct context *ctx)
{
    volatile struct context *save;
    struct context *ret;

    //debug("switching to new context: entry point %#llx stack 0x%016llx\n", ctx->pc, ctx->regs[REG_SP]);
    save = __context;
    __context = ctx;
    //asm ("pushl %cs; call __switch_context");
    asm ("call __switch_context; nop");
    ret = __context;
    __context = (struct context *)save;
    return ret;
}

/* Start ELF Boot image */
unsigned int start_elf(void)
{
    volatile struct context *ctx = __context;

    ctx = switch_to((struct context *)ctx);

    return 0;
}
