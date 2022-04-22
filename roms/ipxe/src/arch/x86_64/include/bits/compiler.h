#ifndef _BITS_COMPILER_H
#define _BITS_COMPILER_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** Dummy relocation type */
#define RELOC_TYPE_NONE R_X86_64_NONE

#ifndef ASSEMBLY

/** Declare a function with standard calling conventions */
#define __asmcall __attribute__ (( used, regparm(0) ))

/** Declare a function with libgcc implicit linkage */
#define __libgcc

#endif /* ASSEMBLY */

#endif /* _BITS_COMPILER_H */
