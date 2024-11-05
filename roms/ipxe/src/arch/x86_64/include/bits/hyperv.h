#ifndef _BITS_HYPERV_H
#define _BITS_HYPERV_H

/** @file
 *
 * Hyper-V interface
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stddef.h>
#include <stdint.h>
#include <ipxe/io.h>

/**
 * Issue hypercall
 *
 * @v hv		Hyper-V hypervisor
 * @v code		Call code
 * @v in		Input parameters
 * @v out		Output parameters
 * @ret status		Status code
 */
static inline __attribute__ (( always_inline )) int
hv_call ( struct hv_hypervisor *hv, unsigned int code, const void *in,
	  void *out ) {
	void *hypercall = hv->hypercall;
	register uint64_t rcx asm ( "rcx" );
	register uint64_t rdx asm ( "rdx" );
	register uint64_t r8 asm ( "r8" );
	uint64_t in_phys;
	uint64_t out_phys;
	uint16_t result;

	in_phys = ( ( __builtin_constant_p ( in ) && ( in == NULL ) )
		       ? 0 : virt_to_phys ( in ) );
	out_phys = ( ( __builtin_constant_p ( out ) && ( out == NULL ) )
		       ? 0 : virt_to_phys ( out ) );
	rcx = code;
	rdx = in_phys;
	r8 = out_phys;
	__asm__ __volatile__ ( "call *%4"
			       : "=a" ( result ), "+r" ( rcx ), "+r" ( rdx ),
				 "+r" ( r8 )
			       : "m" ( hypercall )
			       : "r9", "r10", "r11" );
	return result;
}

#endif /* _BITS_HYPERV_H */
