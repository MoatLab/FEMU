#ifndef RTE_ATOMIC_H
#define RTE_ATOMIC_H

/**
 * Compiler barrier.
 *
 * Guarantees that operation reordering does not occur at compile time
 * for operations directly before and after the barrier.
 */
#define	rte_compiler_barrier() do {		\
	asm volatile ("" : : : "memory");	\
} while(0)

#define MPLOCKED        "lock ; "
/*------------------------- 32 bit atomic operations -------------------------*/
static inline int
rte_atomic32_cmpset(volatile uint32_t *dst, uint32_t exp, uint32_t src)
{
    uint8_t res;

    asm volatile(
            MPLOCKED
            "cmpxchgl %[src], %[dst];"
            "sete %[res];"
            : [res] "=a" (res),     /* output */
            [dst] "=m" (*dst)
            : [src] "r" (src),      /* input */
            "a" (exp),
            "m" (*dst)
            : "memory");            /* no-clobber list */
    return res;
}

#define rte_smp_wmb() rte_compiler_barrier()

#define rte_smp_rmb() rte_compiler_barrier()

#endif
