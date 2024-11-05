/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/usr/hwpf/hwp/build_winkle_images/p8_slw_build/pore_inline_assembler.c $ */
/*                                                                        */
/* OpenPOWER HostBoot Project                                             */
/*                                                                        */
/* Contributors Listed Below - COPYRIGHT 2012,2014                        */
/* [+] International Business Machines Corp.                              */
/*                                                                        */
/*                                                                        */
/* Licensed under the Apache License, Version 2.0 (the "License");        */
/* you may not use this file except in compliance with the License.       */
/* You may obtain a copy of the License at                                */
/*                                                                        */
/*     http://www.apache.org/licenses/LICENSE-2.0                         */
/*                                                                        */
/* Unless required by applicable law or agreed to in writing, software    */
/* distributed under the License is distributed on an "AS IS" BASIS,      */
/* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or        */
/* implied. See the License for the specific language governing           */
/* permissions and limitations under the License.                         */
/*                                                                        */
/* IBM_PROLOG_END_TAG                                                     */
// $Id: pore_inline_assembler.c,v 1.22 2013/12/11 00:11:14 bcbrock Exp $
// $Source: /afs/awd/projects/eclipz/KnowledgeBase/.cvsroot/eclipz/chips/p8/working/procedures/pore_inline_assembler.c,v $
//-----------------------------------------------------------------------------
// *! (C) Copyright International Business Machines Corp. 2013
// *! All Rights Reserved -- Property of IBM
// *! ***  ***
//-----------------------------------------------------------------------------

// ** WARNING : This file is maintained as part of the OCC firmware.  Do **
// ** not edit this file in the PMX area or the hardware procedure area  **
// ** as any changes will be lost.                                       **

/// \file pore_inline_assembler.c
/// \brief Inline PGAS assembler for PgP/Stage1 PORE
///
/// \page pore_inline_assembler PORE Inline Assembler and Disassembler
///
/// Several procedures targeting the PORE engine require inline assembly and
/// disassembly of PORE code, that is, they require that PORE instructions be
/// assembled/disassembled directly into/from a host memory buffer. This page
/// describes these facilities.  The APIs described here are implemented in
/// the files pore_inline.h, pore_inline_assembler.c and
/// pore_inline_disassembler.c.  Both the inline assembelr and disassembler
/// conform to the PGAS assembly format for PORE.
///
/// Both inline assembly and disassembly make use of a PoreInlineContext
/// structure. This structure represents the state of a memory area being
/// targeted for inline assembly and disassembly.  The context is initialized
/// with the pore_inline_context_create() API, and a pointer to an instance of
/// this structure appears as the first argument of all assembler/disassembler
/// APIs. As assembly/disassembly progresses the PoreInlineContext keeps
/// track of how much host memory area has been filled by assembled code or
/// scanned by the disassebler.
///
/// Assembler/disassembler APIs are predicates that return 0 for success and a
/// non-zero error code for failure.  In the event of failure, the error code
/// (a small integer) is also stored in the \a error field of the context
/// structure.  String forms of the error codes are also available in the
/// global array pore_inline_error_strings[].
///
/// The assembler always produces PORE code in the PORE-native big-endian
/// format.  Likewise, the diassembler assumes the host memory to be
/// disassembled contains PORE code in big-endian format.
///
/// \section Initialization
///
/// Before invoking inline assembly/disassembly APIs, an instance of a
/// PoreInlineContext structure must be initialized using the
/// pore_inline_context_create() API.  For assembly, the context describes the
/// host memory buffer that will contain the assembled code.  For disassembly,
/// the context describes the host memory area that contains the code to be
/// disassembled. Full documentation is available for
/// pore_inline_context_create(), including documentation for options that
/// control assembly and disassembly.  The implementation also provides a
/// 'copy operator' for the context, pore_inline_context_copy().
///
/// An example of initializing a context for inline assembly with parity
/// checking appears below.
///
/// \code 
///
/// PoreInlineContext ctx;
/// uint32_t buf[BUFSIZE];
///
/// rc = pore_inline_context_create(&ctx, buf, BUFSIZE * 4, 0,
///                                 PORE_INLINE_CHECK_PARITY);
/// if (rc) . . . Handle Error
///
/// \endcode
///
/// Applications that reuse the same memory buffer for assembling and
/// processing multiple PORE programs can 'reset' the context between uses by
/// using the pore_inline_context_reset() API.  pore_inline_context_reset()
/// resets the location counter and memory extent to their initial (creation)
/// values, and the context error code is cleared.  Any options specified at
/// creation remain as they were.
///
/// \section Assembler
///
/// The inline assembler implements each PORE/PGAS instruction as individual
/// function calls.  The APIs are consistently named \c pore_\<OPCODE\>, where
/// \c \<OPCODE\> is a PGAS mnemonic in upper case.  The arguments to each
/// opcode appear in the same order that they appear in the source-level
/// assembler, with appropriate C-language types. The supported opcode APIs
/// are defined in pore_inline.h
/// 
/// Since the PORE instruction APIs are effectivly predicates, linear code
/// sequences are easily assembled using the C-language logical OR construct.
/// Any non-0 return code will immediately break the sequence and set the
/// expression value to 1.  The failure code can then be recovered from the \a
/// error field of the context.  This coding technique is illustrated in the
/// following example of assembling a memory-memory copy sequence.
///
/// \code 
///
/// PoreInlineContext ctx;
/// int error;
///
/// . . . // Initialize context
///
/// error =
///     pore_LD(&ctx, D0, 0, A0) ||
///     pore_STD(&ctx, D0, 0, A1);
///
/// if (error) <. . . Handle error based on ctx.error>
///
/// \endcode
///
/// The above example generates code equivalent to
///
/// \code
///
///         ld      D0, 0, A0
///         std     D0, 0, A1
///
/// \endcode
///
/// Again, if an error were to occur during assembly, inline assembly would
/// stop (and the logical OR would terminate) at the point of failure. In
/// particular, the inline assembler will never allow assembled code to exceed
/// the bounds of the memory area defined by the initial call of
/// pore_inline_context_create() that defines the assembler memory space.
///
///
/// \subsection Register Names and Other Mnemonics
///
/// The header file pore_inline.h defines macros for the register mnemonics.
///
/// - D0, D1 : 64-bit data registers
/// - A0, A1 : 32-bit address registers
/// - P0, P1 : 7-bit Pervasive chiplet id registers
/// - CTR : 24-bit ounter register
/// - PC : 48-bit Program Counter
/// - ETR : 64-bit EXE-Trigger Register (Low-order 32 bits are writable)
/// - EMR : The Error Mask Register
/// - IFR : ID/Flags Register
/// - SPRG0 : 32-bit Special-Purpose General Register 0
///
/// Mnemonics for the condition code bits are also defined by pore_inline.h
/// using the PGAS mnemonics.
///
///
/// \subsection Assembling Branches
///
/// Opcodes that implement relative branches require that the branch target be
/// specified as a <em> location counter </em>. Once initialized, the current
/// location counter is available as the \a lc field of the PoreInlineContext
/// object controlling the assembly.  The \a lc field is the only field
/// (besides the error code held in the \a error field) that application code
/// should ever reference. The inline assembler also provides a typedef
/// PoreInlineLocation to use for location counters, as well as the macro
/// PORE_LOCATION() to define a location variable inline with the code flow.
/// 
/// \subsubsection Backward Branches
///
/// Backward branches are straightforward.  For example, the memory-memory
/// copy example from earlier can be converted into a loop as shown below.  The
/// \a loop_target variable is initialized with the location counter of the
/// first instruction of the loop.  The final instruction of the loop then
/// branches back to the \a loop_target.
///
/// \code
///
/// PoreInlineContext ctx;
/// PoreInlineLocation loop_target = 0; // See ** below the example
/// int error;
///
/// . . . // Initialize context
///
/// error =
///     PORE_LOCATION(&ctx, loop_target) ||
///     pore_LD(&ctx, D0, 0, A0)         ||
///     pore_STD(&ctx, D0, 0, A1)      	 ||
///     pore_ADDS(&ctx, A0, A0, 8)     	 ||
///     pore_ADDS(&ctx, A1, A1, 8)     	 ||
///     pore_LOOP(&ctx, loop_target);
///
/// if (error) <. . . Handle error based on ctx.error>
///
/// \endcode
///
/// The above inline assembler sequence is equivalent to the PGAS code
/// sequence:
///
/// \code
///
/// loop_target:
///        ld      D0, 0, A0
///        std     D0, 0, A1
///        adds    A0, A0, 8
///        adds    A1, A1, 8
///        loop    loop_target
///
/// \endcode
///
/// ** Location counters used as loop targets may need to be initialized,
/// otherwise the compiler may issue a warning that the variable "may be used
/// uninitialized", although in well-written code this would never happen.
///
///
/// \subsubsection Forward Branches
///
/// Forward branches are more complex.  Since the target location counter is
/// not known until the target has been assembled, the inline assembler
/// provides the API pore_inline_branch_fixup() to fix up forward branches
/// once the actual target is known.  This is illustrated in the simple code
/// sequence below, where an instruction is conditionally skipped.
///
/// \code
///
/// PoreInlineContext ctx;
/// PoreInlineLocation source = 0, target = 0;
/// int error, rc;
///
/// . . . // Initialize context
///
/// error = 
///     PORE_LOCATION(&ctx, source)  ||
///     pore_BRANZ(&ctx, D0, source) ||
///     pore_ADDS(&ctx, D1, D1, 1)   ||
///     PORE_LOCATION(&ctx, target)  ||
///     pore_LD(&ctx, D0, 0, A0);
///
/// if (error) <. . . Handle assembly error based on ctx->error>
/// rc = pore_inline_branch_fixup(&ctx, source, target);
/// if (rc) <. . . Handle branch fixup error>
///
/// \endcode
///
/// In the above code, the branch instruction is initially assembled as a
/// branch-to-self - the recommended idiom for forward branch source
/// instructions.  Once the entire sequence has been assembled,
/// pore_inline_branch_fixup() reassembles the \c source instruction as a
/// branch to the \c target instruction. The above instruction sequence is
/// equivalent to the PGAS code below:
///
/// \code
///
/// source:
///         branz   D0, target
///         adds    D1, D1, 1
/// target:
///         ld      D0, 0, A0
///
/// \endcode
///
///
/// \subsubsection Absolute Branches
///
/// It is unlikely that a typical application of the PORE inline assembler
/// would ever need to include an absolute branch, since the branch target in
/// this case is a fixed absolute address that must be known at assembly
/// time. However the inline assembler does provide the pore_BRAIA() API for
/// this purpose.  This opcode requires a 16-bit address space constant and a
/// 32-bit absoulte address (offset) within the memory space to specify the
/// branch. 
///
///
/// \section Disassembly
///
/// Inline disassembly is implemented by a single API,
/// pore_inline_disassemble(). The idea is similar to assembly: A host memory
/// context containing PORE code (or data) is described by a PoreInlineContext
/// structure.  Each call of pore_inline_disassemble() disassembles the next
/// instruction (or datum) in the context into a PoreInlineDisassembly
/// structure provided by the caller.  The disassembly object contains both
/// binary and string forms of the disassembled instruction (or data). The
/// next call of pore_inline_disassemble() proceses the next instruction (or
/// datum) and so on.
///
/// \subsection Text (Code) Disassembly
///
/// In the example below the inline disassembler is used to completely
/// disassemble a memory area containing text (code) to \a stdout until an
/// error occurs, assumed to be either due to disassembling the entire memory
/// area or finding an illegal instruction.
///
/// \code
///
/// PoreInlineContext ctx;
/// PoreInlineDisassembly dis;
///
/// . . . // Initialize context
///
/// while (pore_inline_disassemble(&ctx, &dis) == 0) {
///     printf("%s\n", dis.s);
/// }
///
/// \endcode
///
/// To illustrate binary disassembly, the following example uses the
/// disassembler to search for a RET statement in a block of PORE code, in
/// order to extend an inline subroutine with more code.  Note that the field
/// \a dis->ctx contains the context that existed at the time the instruction
/// was assembled.  By copying this context back into the global context,
/// inline assembly will continue by overwriting the RET with new
/// instructions. If the copy had \e not been done, then newly assembled code
/// would have \e followed the RET.
///
/// \code
///
/// PoreInlineContext ctx;
/// PoreInlineDisassembly dis;
///
/// . . . // Initialize context
///
/// while ((pore_inline_disassemble(&ctx, &dis) == 0) &&
///        (dis.opcode != PORE_OPCODE_RET));
/// if (ctx.error != 0) {
///     . . . // Handle error
/// } else {
///     pore_inline_context_copy(&ctx, &dis.ctx);
///     . . . // Continue assembly by overwriting the RET
/// }
///
/// \endcode
///
/// A special type of context reset is available to simplify applications that
/// need to disassemble a just-assembled code sequence, e.g. for debugging.
/// pore_inline_context_reset_excursion() resets the context such that the
/// effective size of the context only covers the just-assembled code,
/// allowing a dissassembly loop to cleanly stop once all code has been
/// disassembled. The use is illustrated below - note that the disassembly
/// stops on the expected error code PORE_INLINE_NO_MEMORY once the
/// (effective) end of the buffer is reached.
///
/// \code
///
/// PoreInlineContext ctx;
/// PoreInlineDisassembly dis;
///
/// . . . // Initialize context
/// . . . // Assemble code into context
///
/// pore_inline_context_reset_excursion(&ctx);
///
/// while (pore_inline_disassemble(&ctx, &dis) == 0) {
///     printf("%s\n", dis.s);
/// }
/// if (ctx.error != PORE_INLINE_NO_MEMORY) {
///     . . . // Handle error
/// }
///
/// \endcode
///
/// \subsection Data Disassembly
///
/// If the PoreInlineContext is created with the flag
/// PORE_INLINE_DISASSEMBLE_DATA, then the context is disassembled as data. If
/// the PoreInlineContext is created with the flag
/// PORE_INLINE_DISASSEMBLE_UNKNOWN then putative data embedded in a text
/// section will be disassembled as data.  For complete information see the
/// documentation for pore_inline_disassemble().


#define __PORE_INLINE_ASSEMBLER_C__
#include "pore_inline.h"
#undef __PORE_INLINE_ASSEMBLER_C__

// Definitions of PORE register classes.  These are predicates that return
// 1 if the register is a member of the class, else 0.

PORE_STATIC int
pore_data(int reg)
{
    return 
	(reg == D0) ||
	(reg == D1);
}


PORE_STATIC int
pore_address(int reg)
{
    return
	(reg == A0) ||
	(reg == A1);
}


PORE_STATIC int
pore_pervasive_chiplet_id(int reg)
{
    return
	(reg == P0) ||
	(reg == P1);
}


PORE_STATIC int
pore_branch_compare_data(int reg)
{
    return 
	(reg == D0) ||
	(reg == D1) ||
	(reg == CTR);
}


PORE_STATIC int
pore_ls_destination(int reg)
{
    return
        (reg == D0) ||
        (reg == D1) ||
        (reg == A0) ||
        (reg == A1) ||
        (reg == P0) ||
        (reg == P1) ||
        (reg == CTR);
}


PORE_STATIC int
pore_li_destination(int reg)
{
    return 
        (reg == D0)   ||
        (reg == D1)   ||
        (reg == A0)   ||
        (reg == A1)   ||
        (reg == P0)   ||
        (reg == P1)   ||
        (reg == CTR);
}


PORE_STATIC int
pore_mr_source(int reg)
{
    return
        (reg == D0)    ||
        (reg == D1)    ||
        (reg == A0)    ||
        (reg == A1)    ||
        (reg == P0)    ||
        (reg == P1)    ||
        (reg == CTR)   ||
        (reg == PC)    ||
        (reg == ETR)   ||
        (reg == SPRG0) ||
        (reg == IFR)   ||
        (reg == EMR);
}

PORE_STATIC int
pore_mr_destination(int reg)
{
    return
        (reg == D0)   ||
        (reg == D1)   ||
        (reg == A0)   ||
        (reg == A1)   ||
        (reg == P0)   ||
        (reg == P1)   ||
        (reg == CTR)  ||
        (reg == PC)   ||
        (reg == SPRG0)||
        (reg == EMR);
}                    


/// Portable store of a 32-bit integer in big-endian format
///
/// The address \a p to receive the data is in the form of an unsigned long.

void
pore_inline_be32(unsigned long p, uint32_t x)
{
    uint8_t *p8 = (uint8_t *)p;
    uint8_t *px = (uint8_t *)(&x);
    int i, j;

    if (!PORE_BIG_ENDIAN) {
	for (i = 0, j = 3; i < 4; i++, j--) {
	    p8[i] = px[j];
	}
    } else {
	*((uint32_t *)p) = x;
    }
}
	
	
/// Portable store of a 64-bit integer in big-endian format
///
/// The address \a p to receive the data is in the form of an unsigned long.

void
pore_inline_be64(unsigned long p, uint64_t x)
{
    uint8_t *p8 = (uint8_t *)p;
    uint8_t *px = (uint8_t *)(&x);
    int i, j;

    if (!PORE_BIG_ENDIAN) {
	for (i = 0, j = 7; i < 8; i++, j--) {
	    p8[i] = px[j];
	}
    } else {
	*((uint64_t *)p) = x;
    }
}


// Portable load of a 32-bit integer in big-endian format

uint32_t
pore_inline_host32(unsigned long p)
{
    uint32_t x;
    uint8_t *p8 = (uint8_t *)p;
    uint8_t *px = (uint8_t *)(&x);
    int i, j;

    if (!PORE_BIG_ENDIAN) {
	for (i = 0, j = 3; i < 4; i++, j--) {
	    px[j] = p8[i];
	}
    } else {
	x = *((uint32_t *)p);
    }

    return x;
}
	
	
// Portable load of a 64-bit integer in big-endian format

uint64_t
pore_inline_host64(unsigned long p)
{
    uint64_t x;
    uint8_t *p8 = (uint8_t *)p;
    uint8_t *px = (uint8_t *)(&x);
    int i, j;

    if (!PORE_BIG_ENDIAN) {
	for (i = 0, j = 7; i < 8; i++, j--) {
	    px[j] = p8[i];
	}
    } else {
	x = *((uint64_t *)p);
    }

    return x;
}


// 32-bit population count
//
// This is a well-known divide-and-conquer algorithm.  The idea is to compute
// sums of adjacent bit segments in parallel, in place.

PORE_STATIC int
pore_popcount32(uint32_t x)
{
    uint32_t m1 = 0x55555555;
    uint32_t m2 = 0x33333333;
    uint32_t m4 = 0x0f0f0f0f;
    x -= (x >> 1) & m1;		   /* Sum pairs of bits */
    x = (x & m2) + ((x >> 2) & m2);/* Sum 4-bit segments */
    x = (x + (x >> 4)) & m4;	   /* Sum 8-bit segments */
    x += x >>  8;		   /* Sum 16-bit segments */
    return (x + (x >> 16)) & 0x3f; /* Final sum */
}


// 64-bit population count

PORE_STATIC int
pore_popcount64(uint64_t x)
{
    return pore_popcount32(x & 0xffffffff) + pore_popcount32(x >> 32);
}


// Compute the parity of a PORE instruction as 0 or 1

int
pore_inline_parity(uint32_t instruction, uint64_t imd64)
{
    return (pore_popcount32(instruction) + pore_popcount64(imd64)) % 2;
}
	
	
/// Reset a PORE inline assembler context to its creation state
///
/// \param ctx A pointer to an initialized (and likely 'used')
/// PoreInlineContext object.
///
/// This API resets a PoreInlineContext object to it's \e creation state, that
/// is, the state it was in after the call of pore_inline_context_create().
/// This API is designed for applications that reuse a memory buffer to
/// assemble multiple PORE code sequences.  After each sequence has been fully
/// assembled and processed, calling pore_inline_context_reset() sets the
/// context back as it was when the context was initially created so that the
/// memory area can be reused.  In particular, this API resets the location
/// counter and memory extent to their initial values, and the error code is
/// cleared.  Any options specified at creation remain as they were.
///
/// For a slightly different type of reset, see
/// pore_inline_context_reset_excursion().  

void
pore_inline_context_reset(PoreInlineContext *ctx)
{
    ctx->lc_address = ctx->memory;
    ctx->remaining = ctx->size;
    ctx->lc = ctx->original_lc;
    ctx->error = 0;
}



/// Reset a PORE inline assembler context to a special state for disassembly
///
/// \param ctx A pointer to an initialized (and almost certainly 'used')
/// PoreInlineContext object.
///
/// This API resets a PoreInlineContext object to it's \e creation state, that
/// is, the state it was in after the call of pore_inline_context_create(), \e
/// except that the effective size of the memory area has been reduced to the
/// size that was actually used during assembly.  This API is designed for
/// applications that assemble into a memory buffer and then want to easily
/// disassemble the code (e.g., for debugging).  After a code sequence has
/// been assembled, calling pore_inline_context_reset_excursion() sets the
/// context back as it was when the context was initially created, but with a
/// (typically) shorter effective length, so that the disassembly will cleanly
/// stop once the entire sequence has been disassembled. Once disassembled,
/// the buffer can be fully resued after a subsequent call of
/// pore_inline_context_reset().  In particular, this API resets the location
/// counter to its initial value, clears the error code, and sets the
/// effective size of the context to the amount of memory currently used.  Any
/// options specified at creation remain as they were.
///
/// For a full context reset see pore_inline_context_reset(). For an example
/// see the \b Disassembly section of \ref pore_inline_assembler.

void
pore_inline_context_reset_excursion(PoreInlineContext *ctx)
{
    ctx->lc_address = ctx->memory;
    ctx->remaining = ctx->size - ctx->remaining;
    ctx->lc = ctx->original_lc;
    ctx->error = 0;
}


/// Create a PORE inline assembler context
///
/// \param ctx A pointer to a PoreInlineContext object to be initialized
/// and used for inline assembly. or disassembly.
///
/// \param memory A pointer to the host memory area to receive the assembled
/// code, or contain the code to disassemble. In general the inline assembler
/// will expect this memory area to be 4-byte aligned. This pointer may be
/// NULL (0) only if the associated \a size is also 0.
///
/// \param size The size (in bytes) of the host memory area. The inline
/// assembler will generate the PORE_INLINE_NO_MEMORY error if an attempt is
/// made to assemble an instruction that would overflow the buffer, or
/// disassemble past the end of the buffer. A 0 size is valid.
///
/// \param lc The initial, bytewise, target location counter for the assembled
/// or disassembled code. This paramater will normally be initialized to 0 for
/// assembling relocatable programs. The parameter would only need to be
/// specified as non-0 for special cases, such as creating a context for
/// disassembly.
///
/// \param options Option flags.  Option flags are OR-ed together to create
/// the final set of options. Valid options are
///
/// - PORE_INLINE_GENERATE_PARITY : Generate the proper parity bit for each
/// instruction during assembly.
///
/// - PORE_INLINE_CHECK_PARITY : Check for correct instruction parity during
/// disassembly.
///
/// - PORE_INLINE_LISTING_MODE : Generate disassembly strings in the form of a
/// listing that contains location counters and encoded instructions as well
/// as their diassembly.  By default the disassembly strings do not contain
/// this information and can be fed back in as source code to a PORE
/// assembler.
///
/// - PORE_INLINE_DISASSEMBLE_DATA : generate disassembly assuming that the
/// context contains data rather than text. Normally data is disassembled as
/// .long directives, however if the context is unaligned or of an odd length
/// then .byte directives may be used as well.  This option can be used in
/// conjunction with PORE_INLINE_LISTING_MODE.
///
/// - PORE_INLINE_8_BYTE_DATA : generate data disassembly using 8-byte values
/// rather than the default 4-byte values.  Normally data is disassembled as
/// .quad directives under this option, however if the context is unaligned or
/// of an odd length then .long and .byte directives may be used as well.
/// This option can be used in conjunction with PORE_INLINE_LISTING_MODE.
///
/// A PoreInlineContext describes a memory area and assembler context for
/// inline assembly and disassembly.  Assembly/disassembly begins at the host
/// memory location and virtual location counter described in the parameters.
/// As instructions are assembled/disassembled the PoreInlineContext keeps
/// track of where in the host memory and virtual PORE memory areas to place
/// new instructions during assembly, or from where to fetch the next
/// instruction to disassemble.
///
/// \retval 0 Success
///
/// \retval PORE_INLINE_INVALID_PARAMETER Either the \a context pointer is
/// NULL (0), the \a memory pointer is NULL (0) with a non-0 size, or the \a
/// options include invalid options.  The error code is also stored as the
/// value of ctx->error, and in the event of an error the ctx->size field is
/// set to 0, effectively preventing the context from being used.

int
pore_inline_context_create(PoreInlineContext *ctx,
			   void *memory, size_t size, 
			   PoreInlineLocation lc, int options)
{
    int rc;

    int valid_options = 
	PORE_INLINE_GENERATE_PARITY  |
	PORE_INLINE_CHECK_PARITY     |
	PORE_INLINE_LISTING_MODE     |
        PORE_INLINE_DISASSEMBLE_DATA |
        PORE_INLINE_8_BYTE_DATA      |
        PORE_INLINE_DISASSEMBLE_UNKNOWN;

    if ((ctx == NULL) || ((memory == NULL) && (size != 0)) ||
	((options & ~valid_options) != 0)) {
	rc = PORE_INLINE_INVALID_PARAMETER;
    } else {
	rc = 0;
	ctx->memory = (unsigned long)memory;
	ctx->size = size;
	ctx->original_lc = lc;
	ctx->options = options;
	pore_inline_context_reset(ctx);
    }

    if (ctx != NULL) {
        ctx->error = rc;
        if (rc) {
            ctx->size = 0;      /* Effectively prevents using the ctx */
        }
    }

    return rc;
}
	
	
/// Copy a PORE inline assembler context
///
/// \param dest A pointer to a PoreInlineContext object to be initialized
/// as a copy of the \a src context.
///
/// \param src A pointer to a PoreInlineContext object to be used as the
/// source of the copy.
///
/// This API copies one PoreInlineContext structure to another.  An example
/// use appears in \ref pore_inline_assembler in the section discussing
/// disassembly.

void
pore_inline_context_copy(PoreInlineContext *dest, PoreInlineContext *src)
{
    *dest = *src;
}


// 'Bump' a context forward by a given number of bytes.  This an internal API
// and the bump is always known to be legal.

void
pore_inline_context_bump(PoreInlineContext *ctx, size_t bytes)
{
    ctx->remaining -= bytes;
    ctx->lc += bytes;
    ctx->lc_address += bytes;
}    


// Allocate space in the inline assembler context
//
// Allocation is specified and implemented in bytes.  Both the physical
// memory and the virtual LC are required to be 4-byte aligned. The allocator
// returns a pointer to the memory area, or 0 if allocation fails.
// Allocation failure sets the context error code to either
// PORE_INLINE_NO_MEMORY or PORE_INLINE_ALIGNMENT_ERROR.

PORE_STATIC unsigned long
pore_inline_allocate(PoreInlineContext *ctx, size_t bytes)
{
    unsigned long p = 0;

    if (((ctx->lc % 4) != 0) || 
	((ctx->lc_address % 4) != 0)) {
	ctx->error = PORE_INLINE_ALIGNMENT_ERROR;

    } else if (bytes > ctx->remaining) {
	ctx->error = PORE_INLINE_NO_MEMORY;

    } else {
	p = ctx->lc_address;
	pore_inline_context_bump(ctx, bytes);
    }
    return p;
}


// Assemble a 1-word instruction
//
// The opcode and operand are assumed to be legal, having come from
// abstractions that check their arguments.  This call may fail with
// PORE_INLINE_NO_MEMORY if there is no more room in the memory buffer. A
// non-zero return indicates failure.

int
pore_inline_instruction1(PoreInlineContext *ctx, int opcode, uint32_t operand)
{
    uint32_t instruction;
    unsigned long p;

    p = pore_inline_allocate(ctx, 4);
    if (p != 0) {

	instruction = (opcode << 25) | operand;
	if (ctx->options & PORE_INLINE_GENERATE_PARITY) {
	    instruction |= (1 - pore_inline_parity(instruction, 0)) << 24;
	}

	pore_inline_be32(p, instruction);
	ctx->error = 0;
    }
    return p == 0;
}
	    

// Assemble a 3-word instruction
//
// The opcode and operand are assumed to be legal, having come from
// abstractions that check their arguments.  This call may fail with
// PORE_INLINE_NO_MEMORY if there is no more room in the memory buffer.  A
// non-zero return indicates failure.

int
pore_inline_instruction3(PoreInlineContext *ctx, int opcode, uint32_t operand,
			 uint64_t immediate)
{
    uint32_t instruction;
    unsigned long p;

    p = pore_inline_allocate(ctx, 12);
    if (p != 0) {

	instruction = (opcode << 25) | operand;
	if (ctx->options & PORE_INLINE_GENERATE_PARITY) {
	    instruction |= (1 - pore_inline_parity(instruction, immediate)) << 24;
	}

	pore_inline_be32(p, instruction);
	pore_inline_be64(p + 4, immediate);
	ctx->error = 0;
    }
    return p == 0;
}


// Assemble WAIT
//
// The cycle count must be an unsigned 24-bit immediate otherwise the error
// PORE_INLINE_UINT24_REQUIRED is signalled.  PGAS requires that HALT be used
// if the intention is to halt 

int
pore_WAITS(PoreInlineContext *ctx, uint32_t cycles)
{
    uint32_t operand;
    int opcode = PGAS_OPCODE_WAITS;

    if (cycles == 0) {
        ctx->error = PORE_INLINE_USE_HALT;
    } else if ((cycles & 0xffffff) != cycles) {
	ctx->error = PORE_INLINE_UINT24_REQUIRED;
    } else {
	operand = cycles;
	pore_inline_instruction1(ctx, opcode, operand);
    }
    return ctx->error;
}


// Assemble HOOKI
//
// The hook index must be an unsigned 24-bit immediate otherwise the error
// PORE_INLINE_UINT24_REQUIRED is signalled.

int
pore_HOOKI(PoreInlineContext *ctx, uint32_t index, uint64_t imm)
{
    uint32_t operand;
    int opcode = PGAS_OPCODE_HOOKI;

    if ((index & 0xffffff) != index) {
	ctx->error = PORE_INLINE_UINT24_REQUIRED;
    } else {
	operand = index;
	pore_inline_instruction3(ctx, opcode, operand, imm);
    }
    return ctx->error;
}


// Assemble BRA, BSR and LOOP
//
// The branch target here is a bytewise location counter.  The target must be
// 4-byte aligned and must be within the legal signed 24-bit word offset of
// the current LC. Unaligned targets cause PORE_INLINE_ALIGNMENT_ERROR.
// Unreachable targets cause PORE_INLINE_UNREACHABLE_TARGET.

int
pore_inline_bra(PoreInlineContext *ctx, int opcode, PoreInlineLocation target)
{
    int32_t offset;
    uint32_t operand;

    if (target % 4) {
	ctx->error = PORE_INLINE_ALIGNMENT_ERROR;
    } else {
	offset = (int32_t)(target - ctx->lc) / 4;
	if ((offset >= (1 << 23)) ||
	    (offset < -(1 << 23))) {
	    ctx->error = PORE_INLINE_UNREACHABLE_TARGET;
	} else {
	    operand = offset & 0xffffff;
	    pore_inline_instruction1(ctx, opcode, operand);
	}
    }
    return ctx->error;
}
	    

// Assemble BRAZ and BRANZ
//
// The branch target here is a bytewise location counter.  The target must be
// 4-byte aligned and must be within the legal signed 20-bit word offset of
// the current LC. Unaligned targets cause PORE_INLINE_ALIGNMENT_ERROR.
// Unreachable targets cause PORE_INLINE_UNREACHABLE_TARGET.  Illegal
// operands cause PORE_INLINE_ILLEGAL_REGISTER.

int
pore_inline_brac(PoreInlineContext *ctx, int opcode, int reg, 
		 PoreInlineLocation target)
{
    int32_t offset;
    uint32_t operand;

    if (target % 4) {
	ctx->error = PORE_INLINE_ALIGNMENT_ERROR;
    } else if (!pore_branch_compare_data(reg)) {
	ctx->error = PORE_INLINE_ILLEGAL_REGISTER;
    } else {
	offset = (int32_t)(target - ctx->lc) / 4;
	if ((offset >= (1 << 20)) ||
	    (offset < -(1 << 20))) {
	    ctx->error = PORE_INLINE_UNREACHABLE_TARGET;
	} else {
	    operand = (offset & 0xfffff) | (reg << 20);
	    pore_inline_instruction1(ctx, opcode, operand);
	}
    }
    return ctx->error;
}


// Assemble CMPIBRAEQ, CMPIBRANE, CMPIBSREQ
//
// The branch target here is a bytewise location counter.  The target must be
// 4-byte aligned and must be within the legal signed 24-bit word offset of
// the current LC. Unaligned targets cause PORE_INLINE_ALIGNMENT_ERROR.
// Unreachable targets cause PORE_INLINE_UNREACHABLE_TARGET. Illegal
// operands cause PORE_INLINE_ILLEGAL_REGISTER.

int
pore_inline_cmpibra(PoreInlineContext *ctx, int opcode, int reg,
                    PoreInlineLocation target, uint64_t imm)
{
    int32_t offset;
    uint32_t operand;

    if (target % 4) {
	ctx->error = PORE_INLINE_ALIGNMENT_ERROR;
    } else if (reg != D0) {
        ctx->error = PORE_INLINE_ILLEGAL_REGISTER;
    } else {
	offset = (int32_t)(target - ctx->lc) / 4;
	if ((offset >= (1 << 23)) ||
	    (offset < -(1 << 23))) {
	    ctx->error = PORE_INLINE_UNREACHABLE_TARGET;
	} else {
	    operand = offset & 0xffffff;
	    pore_inline_instruction3(ctx, opcode, operand, imm);
	}
    }
    return ctx->error;
}


// Assemble BRAD and BSRD
//
// Illegal operands cause PORE_INLINE_ILLEGAL_REGISTER.

int
pore_inline_brad(PoreInlineContext *ctx, int opcode, int reg)
{
    uint32_t operand;

    if (!pore_data(reg)) {
	ctx->error = PORE_INLINE_ILLEGAL_REGISTER;
    } else {
	operand = reg << 20;
	pore_inline_instruction1(ctx, opcode, operand);
    }
    return ctx->error;
}


// Assemble ANDI, ORI, XORI
//
// Source and destination must be of class 'data' otherwise the
// PORE_INLINE_ILLEGAL_REGISTER error is generated.

int
pore_inline_ilogic(PoreInlineContext *ctx, int opcode, 
		   int dest, int src, uint64_t imm)
{
    uint32_t operand;

    if (!pore_data(dest) || !pore_data(src)) {
	ctx->error = PORE_INLINE_ILLEGAL_REGISTER;
    } else {
	operand = (dest << 20) | (src << 16);
	pore_inline_instruction3(ctx, opcode, operand, imm);
    }
    return ctx->error;
}


// Assemble AND, OR, XOR, ADD, SUB
//
// Destination must be of class 'data' otherwise the
// PORE_INLINE_ILLEGAL_REGISTER error is generated.  src1 and src2 must be D0,
// D1 respectively otherwise the PORE_INLINE_ILLEGAL_REGISTER error is
// generated.

int
pore_inline_alurr(PoreInlineContext *ctx, 
                  int opcode, int dest, int src1, int src2)
{
    uint32_t operand;

    if (!pore_data(dest) || (src1 != D0) || (src2 != D1)) {
	ctx->error = PORE_INLINE_ILLEGAL_REGISTER;
    } else {
	operand = (dest << 20);
	pore_inline_instruction1(ctx, opcode, operand);
    }
    return ctx->error;
}


// Assemble ADDS and SUBS
//
// Destination must be of class 'ls_destination' and must be equal to source,
// otherwise the PORE_INLINE_ILLEGAL_REGISTER error is generated.  If the
// immediate is not a signed 16-bit immediate then the
// PORE_INLINE_INT16_REQUIRED error is generated.

int
pore_inline_adds(PoreInlineContext *ctx, 
                 int opcode, int dest, int src, int imm)
{
    uint32_t operand;

    if (!pore_ls_destination(dest) || (dest != src)) {
	ctx->error = PORE_INLINE_ILLEGAL_REGISTER;
    } else {
	if ((imm >= (1 << 15)) ||
	    (imm < -(1 << 15))) {
	    ctx->error = PORE_INLINE_INT16_REQUIRED;
	} else {
	    operand = (dest << 20) | (imm & 0xffff);
	    pore_inline_instruction1(ctx, opcode, operand);
	}
    }
    return ctx->error;
}


// Assemble NEG
//
// Source and destination must be of class 'data' otherwise the
// PORE_INLINE_ILLEGAL_REGISTER error is generated.

int
pore_NEG(PoreInlineContext *ctx, int dest, int src)
{
    uint32_t operand;
    int opcode = PGAS_OPCODE_NEG;

    if (!pore_data(dest) || !pore_data(src)) {
	ctx->error = PORE_INLINE_ILLEGAL_REGISTER;
    } else {
	operand = (dest << 20) | (src << 16);
	pore_inline_instruction1(ctx, opcode, operand);
    }
    return ctx->error;
}


// Assemble MR
//
// The source must be an 'mr_source' and the destination must be an
// 'mr_destination' otherwise the PORE_INLINE_ILLEGAL_REGISTER error is
// generated.

int
pore_MR(PoreInlineContext *ctx, int dest, int src)
{
    uint32_t operand;
    int opcode = PGAS_OPCODE_MR;

    if (!pore_mr_destination(dest) || !pore_mr_source(src)) {
	ctx->error = PORE_INLINE_ILLEGAL_REGISTER;
    } else {
	operand = (dest << 20) | (src << 16);
	pore_inline_instruction1(ctx, opcode, operand);
    }
    return ctx->error;
}

	    

// Assemble ROLS
//
// Source and destination must be of class 'data' otherwise the
// PORE_INLINE_ILLEGAL_REGISTER error is generated.  Illegal shifts yield the
// PORE_INLINE_ILLEGAL_ROTATE error.

int
pore_ROLS(PoreInlineContext *ctx, int dest, int src, int imm)
{
    uint32_t operand;
    int opcode = PGAS_OPCODE_ROLS;
    
    if (!pore_data(dest) || !pore_data(src)) {
	ctx->error = PORE_INLINE_ILLEGAL_REGISTER;
    } else if ((imm != 1) &&
	       (imm != 4) &&
	       (imm != 8) &&
	       (imm != 16) &&
	       (imm != 32)) {
	ctx->error = PORE_INLINE_ILLEGAL_ROTATE;
    } else {
	operand = (dest << 20) | (src << 16) | imm;
	pore_inline_instruction1(ctx, opcode, operand);
    }
    return ctx->error;
}


// Assemble LS
//
// The destination must be an 'ls_destination' otherwise the
// PORE_INLINE_ILLEGAL_REGISTER error is generated.  If the immediate is not
// a signed 20-bit immediate then the PORE_INLINE_INT20_REQUIRED error is
// generated. 

int
pore_LS(PoreInlineContext *ctx, int dest, int imm)
{
    uint32_t operand;
    int opcode = PGAS_OPCODE_LS;
    
    if (!pore_ls_destination(dest)) {
	ctx->error = PORE_INLINE_ILLEGAL_REGISTER;
    } else if ((imm >= (1 << 19)) ||
               (imm < -(1 << 19))) {
        ctx->error = PORE_INLINE_INT20_REQUIRED;
    } else {
	operand = (dest << 20) | (imm & 0xfffff);
	pore_inline_instruction1(ctx, opcode, operand);
    }
    return ctx->error;
}


// Assemble LI
//
// The destination must be an 'li destination' otherwise the
// PORE_INLINE_ILLEGAL_REGISTER error is generated.

int
pore_LI(PoreInlineContext *ctx, int dest, uint64_t imm)
{
    uint32_t operand;
    int opcode = PGAS_OPCODE_LI;
    
    if (!pore_li_destination(dest)) {
	ctx->error = PORE_INLINE_ILLEGAL_REGISTER;
    } else {
	operand = dest << 20;
	pore_inline_instruction3(ctx, opcode, operand, imm);
    }
    return ctx->error;
}


// BSI and BCI are normally redacted as instructions due to HW274735

// LD, LDANDI, STD, STI, BSI, BCI

PORE_STATIC void
pervasive_ima24(PoreInlineContext *ctx, 
                int opcode, uint32_t offset, int base, uint64_t imm)
{
    uint32_t operand;

    if ((offset & 0x80f00000) != 0) {
        ctx->error = PORE_INLINE_ILLEGAL_SCOM_ADDRESS;
    } else {
        operand = ((base % 2) << 22) | (offset & 0xfffff);
        switch (opcode) {
        case PGAS_OPCODE_LD0:
        case PGAS_OPCODE_LD1:
        case PGAS_OPCODE_STD0:
        case PGAS_OPCODE_STD1:
            pore_inline_instruction1(ctx, opcode, operand);
            break;
        default:
            pore_inline_instruction3(ctx, opcode, operand, imm);
            break;
        }
    }
}            
        

PORE_STATIC void
memory_ima24(PoreInlineContext *ctx, 
             int opcode, uint32_t offset, int base, uint64_t imm)
{
    uint32_t operand;

    if ((offset & 0x3fffff) != offset) {
        ctx->error = PORE_INLINE_UINT22_REQUIRED;
    } else if ((offset % 8) != 0) {
        ctx->error = PORE_INLINE_ALIGNMENT_ERROR;
    } else {
        operand = 0x800000 | ((base % 2) << 22) | (offset & 0x3fffff);
        switch (opcode) {
        case PGAS_OPCODE_LD0:
        case PGAS_OPCODE_LD1:
        case PGAS_OPCODE_STD0:
        case PGAS_OPCODE_STD1:
            pore_inline_instruction1(ctx, opcode, operand);
            break;
        default:
            pore_inline_instruction3(ctx, opcode, operand, imm);
            break;
        }
    }
}


PORE_STATIC void
ima24(PoreInlineContext *ctx, 
      int opcode, uint32_t offset, int base, uint64_t imm)
{
    if (pore_pervasive_chiplet_id(base)) {
        pervasive_ima24(ctx, opcode, offset, base, imm);
    } else if (pore_address(base)) {
        memory_ima24(ctx, opcode, offset, base, imm);
    } else {
        ctx->error = PORE_INLINE_ILLEGAL_REGISTER;
    }
}


int
pore_inline_load_store(PoreInlineContext *ctx, 
		       int opcode, int src_dest, int32_t offset, int base,
		       uint64_t imm)
{
    switch (opcode) {

    case PORE_INLINE_PSEUDO_LD:
    case PORE_INLINE_PSEUDO_LDANDI:
    case PORE_INLINE_PSEUDO_STD:

        // These three pick the real opcode based on the dest. register

        if (!pore_data(src_dest)) {
            ctx->error = PORE_INLINE_ILLEGAL_REGISTER;
        } else {
            switch (opcode) {
            case PORE_INLINE_PSEUDO_LD:
                opcode = (src_dest == D0) ? 
                    PGAS_OPCODE_LD0 : PGAS_OPCODE_LD1;
                break;
            case PORE_INLINE_PSEUDO_LDANDI:
                opcode = (src_dest == D0) ? 
                    PGAS_OPCODE_LD0ANDI : PGAS_OPCODE_LD1ANDI;
                break;
            case PORE_INLINE_PSEUDO_STD:
                opcode = (src_dest == D0) ? 
                    PGAS_OPCODE_STD0 : PGAS_OPCODE_STD1;
                break;
            }
        }
        break;

#ifdef IGNORE_HW274735

        // BSI and BCI are normally redacted as instructions due to HW274735
        
        case PGAS_OPCODE_BSI:
        case PGAS_OPCODE_BCI:
        
            if (src_dest != D0) {
                ctx->error = PORE_INLINE_ILLEGAL_REGISTER;
            }
            break;

#endif // IGNORE_HW274735

    case PGAS_OPCODE_STI:
        break;

    default:
        ctx->error = PORE_INLINE_BUG;
    }

    if (ctx->error == 0) {
        ima24(ctx, opcode, offset, base, imm);
    }

    return ctx->error;
}


// Assemble BRAIA

int
pore_BRAIA(PoreInlineContext *ctx,
           uint16_t address_space, uint32_t offset)
{
    int opcode = PGAS_OPCODE_BRAI;
    uint32_t operand = 0;
    uint64_t imm = ((uint64_t)address_space << 32) | offset;

    pore_inline_instruction3(ctx, opcode, operand, imm);

    return ctx->error;
}


// Assemble SCAND

int
pore_SCAND(PoreInlineContext *ctx,
           int update, int capture, uint16_t length, 
           uint32_t select, uint32_t offset)
{
    int opcode = PGAS_OPCODE_SCAND;
    uint32_t operand;
    uint64_t imm = ((uint64_t)select << 32) | offset;

    if ((update < 0) ||
        (update > 1) ||
        (capture < 0) ||
        (capture > 1)) {
        ctx->error = PORE_INLINE_INVALID_PARAMETER;
    } else {
        opcode = PGAS_OPCODE_SCAND;
        operand = (update << 23) | (capture << 22) | length;
        pore_inline_instruction3(ctx, opcode, operand, imm);
    }
    return ctx->error;
}
        

/// Fix up a PORE inline assembler forward branch instruction
///
/// \param ctx A pointer to the initialized PoreInlineContext object
/// controlling inline assembly.
///
/// \param source The PORE inline location counter associated with the source
/// instruction of the forward branch.
///
/// \param target The PORE inline location counter associated with the target
/// instruction of the forward branch.
///
/// For usage examples, see the documentation \ref pore_inline_assembler.
/// Although intended for forward branches, this API could be used to create
/// backward branches as well.  Note however the limitation that the \a source
/// must be in the current context, since the source instruction needs to be
/// reassembled with the branch target. In theory the \a target could be
/// anywhere, as long as the location counter of the target is known.
///
/// \retval 0 Success
///
/// \retval code Failure.  Any non-zero return is the PORE inline assmebler
/// error code. The failure code is also stored in the PoreInlineContext
/// object \a error field.  The most likely causes of failure include a source
/// location that is not in the current context or not associated with a
/// branch instruction.

int
pore_inline_branch_fixup(PoreInlineContext *ctx, 
			 PoreInlineLocation source,
			 PoreInlineLocation target)
{
    uint32_t instruction;
    int32_t distance;
    uint64_t imm;
    int opcode, reg;
    PoreInlineContext source_ctx;

    if ((source < ctx->original_lc) ||
	(source > ctx->lc)) {
	ctx->error = PORE_INLINE_ILLEGAL_SOURCE_LC;
    } else {

	// Create a context as it existed when the source instruction was
	// initially assembled, and then reassemble the instruction in that
	// context with the actual target.

	distance = ctx->lc - source;

	source_ctx = *ctx;
	source_ctx.lc = source;
	source_ctx.remaining += distance;
	source_ctx.lc_address -= distance;
	source_ctx.error = 0;
	
	instruction = pore_inline_host32(source_ctx.lc_address);
	opcode = (instruction >> 25);
	reg = (instruction >> 20) & 0xf;
	
	switch (opcode) {
	case PGAS_OPCODE_BRA:
	    pore_BRA(&source_ctx, target);
	    break;
	case PGAS_OPCODE_BSR:
	    pore_BSR(&source_ctx, target);
	    break;
	case PGAS_OPCODE_LOOP:
	    pore_LOOP(&source_ctx, target);
	    break;
	case PGAS_OPCODE_BRAZ:
	    pore_BRAZ(&source_ctx, reg, target);
	    break;
	case PGAS_OPCODE_BRANZ:
	    pore_BRANZ(&source_ctx, reg, target);
	    break;
	case PGAS_OPCODE_CMPIBRAEQ:
	    imm = pore_inline_host64(source_ctx.lc_address + 4);
	    pore_CMPIBRAEQ(&source_ctx, D0, target, imm);
	    break;
	case PGAS_OPCODE_CMPIBRANE:
	    imm = pore_inline_host64(source_ctx.lc_address + 4);
	    pore_CMPIBRANE(&source_ctx, D0, target, imm);
	    break;
	case PGAS_OPCODE_CMPIBSREQ:
	    imm = pore_inline_host64(source_ctx.lc_address + 4);
	    pore_CMPIBSREQ(&source_ctx, D0, target, imm);
	    break;
	default:
	    source_ctx.error = PORE_INLINE_NOT_A_BRANCH;
	    break;
	}

	ctx->error = source_ctx.error;
    }
    return ctx->error;
}
