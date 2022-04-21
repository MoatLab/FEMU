/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/usr/hwpf/hwp/build_winkle_images/p8_slw_build/pore_inline.h $ */
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
#ifndef __PORE_INLINE_H__
#define __PORE_INLINE_H__

// $Id: pore_inline.h,v 1.20 2013/12/11 00:11:13 bcbrock Exp $
// $Source: /afs/awd/projects/eclipz/KnowledgeBase/.cvsroot/eclipz/chips/p8/working/procedures/pore_inline.h,v $
//-----------------------------------------------------------------------------
// *! (C) Copyright International Business Machines Corp. 2013
// *! All Rights Reserved -- Property of IBM
// *! ***  ***
//-----------------------------------------------------------------------------

// ** WARNING : This file is maintained as part of the OCC firmware.  Do **
// ** not edit this file in the PMX area or the hardware procedure area  **
// ** as any changes will be lost.                                       **

/// \file pore_inline.h
/// \brief Inline assembler for PORE code
///
/// Note that this file defines several short macro symbols for register names
/// and other mnemonics used by inline assembly.  For this reason it would
/// probably be best to only include this header when it was absolutely
/// necessary, i.e., only in C files that explicitly use inline assembly and
/// disassembly.

#ifndef PPC_HYP
#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#endif // PPC_HYP
#include "pgas.h"

#if( defined(__cplusplus) && !defined(PLIC_MODULE) ) 
extern "C" {
#endif
#if 0
} /* So __cplusplus doesn't mess w/auto-indent */
#endif


#ifndef __ASSEMBLER__

// PHYP tools do not support 'static' functions and variables as it interferes
// with their concurrent patch methodology.  So when compiling for PHYP the
// PORE instruction "macros" are simply declared "inline".  This also extends
// into the implementation C files - so under PHYP all previosuly local static
// functions will now be global functions. We retain 'static' to reduce code
// size and improve abstraction for OCC applications.

#ifdef PPC_HYP
#define PORE_STATIC
#include <p8_pore_api_custom.h>
#else
#define PORE_STATIC static
#endif

/// Error code strings from the PORE inline assembler/disassembler
///
/// The PoreInlineContext object stores error codes that occur during
/// assembly as small integers.  The '0' code indicates success. This is a
/// table of strings that describe the codes.  It will be instantiated in
/// pore_inline.c 

extern const char *pore_inline_error_strings[];

#ifdef __PORE_INLINE_ASSEMBLER_C__
const char *pore_inline_error_strings[] = {
    "No error",
    "The inline assembler memory is full, or disassembly has reached the end of the memory area",
    "The instruction requires an ImD24 operand",
    "The LC is not aligned or the instruction requires an aligned operand",
    "The branch target is unreachable (too distant)",
    "A register operand is illegal for the given instruction",
    "The instruction form requires a signed 16-bit immediate",
    "Valid rotate lengths are 1, 4, 8, 16 and 32",
    "The instruction requires a 20-bit signed immediate",
    "The instruction requires a 24-bit unsigned immediate",
    "A parameter to pore_inline_context_create() is invalid",
    "The instruction form requires an unsigned 22-bit immediate",
    "This error is due to a bug in the PORE inline assembler (Please report)",
    "The 'source' label for pore_inline_branch_fixup() is illegal",
    "The 'source' instruction for pore_inline_branch_fixup() is not a branch",
    "The disassembler does not recognize the instruction as a PORE opcode",
    "Instruction parity error during disassembly",
    "The string form of the disassembly is too long to represent (Please report)`",
    "Use HALT instead of WAIT 0 if the intention is to halt.",
    "A putative SCOM address is illegal (has non-0 bits where 0s are expected)."
};
#endif	/* __PORE_INLINE_ASSEMBLER_C__ */

#endif	/* __ASSEMBLER__ */

#define PORE_INLINE_SUCCESS              0
#define PORE_INLINE_NO_MEMORY            1
#define PORE_INLINE_IMD24_ERROR          2
#define PORE_INLINE_ALIGNMENT_ERROR      3
#define PORE_INLINE_UNREACHABLE_TARGET   4
#define PORE_INLINE_ILLEGAL_REGISTER     5
#define PORE_INLINE_INT16_REQUIRED       6
#define PORE_INLINE_ILLEGAL_ROTATE       7
#define PORE_INLINE_INT20_REQUIRED       8
#define PORE_INLINE_UINT24_REQUIRED      9
#define PORE_INLINE_INVALID_PARAMETER    10
#define PORE_INLINE_UINT22_REQUIRED      11
#define PORE_INLINE_BUG                  12
#define PORE_INLINE_ILLEGAL_SOURCE_LC    13
#define PORE_INLINE_NOT_A_BRANCH         14
#define PORE_INLINE_UNKNOWN_OPCODE       15
#define PORE_INLINE_PARITY_ERROR         16
#define PORE_INLINE_DISASSEMBLY_OVERFLOW 17
#define PORE_INLINE_USE_HALT             18
#define PORE_INLINE_ILLEGAL_SCOM_ADDRESS 19


/// Register name strings for the PORE inline assembler/disassembler

extern const char *pore_inline_register_strings[16];

// C++ requires that these arrays of strings be declared 'const' to avoid
// warnings.  But then you get warnings when the strings get stored into
// non-const variables.  The solution is to rename these arrays inside the
// disassembler.  If anyone has a better solution please let me know - Bishop

#ifdef __PORE_INLINE_ASSEMBLER_C__
const char* pore_inline_register_strings[16] = {
    "P0", "P1", "A0", "A1", "CTR", "D0", "D1", "EMR",
    "?", "ETR", "SPRG0", "?", "?", "?", "PC", "IFR"
};
#endif /* __PORE_INLINE_ASSEMBLER_C__ */


// Shorthand forms of constants defined in pgas.h, defined for consistency
// using the assembler-supported names.  These constants are defined as an
// enum to avoid name conflicts with some firmware symbols when the PORE
// inline facility is used to create Host Boot procedures.

enum {

    // Shorthand register mnemonics, defined as an enum to avoid name clashes.

    P0    = PORE_REGISTER_PRV_BASE_ADDR0,
    P1    = PORE_REGISTER_PRV_BASE_ADDR1,
    A0    = PORE_REGISTER_OCI_BASE_ADDR0,
    A1    = PORE_REGISTER_OCI_BASE_ADDR1,
    CTR   = PORE_REGISTER_SCRATCH0,
    D0    = PORE_REGISTER_SCRATCH1,
    D1    = PORE_REGISTER_SCRATCH2,
    EMR   = PORE_REGISTER_ERROR_MASK,
    ETR   = PORE_REGISTER_EXE_TRIGGER,
    SPRG0 = PORE_REGISTER_DATA0,
    PC    = PORE_REGISTER_PC,
    IFR   = PORE_REGISTER_IBUF_ID,

    // PgP IBUF_ID values

    PORE_GPE0 = PORE_ID_GPE0,
    PORE_GPE1 = PORE_ID_GPE1,
    PORE_SLW  = PORE_ID_SLW,
    PORE_SBE  = PORE_ID_SBE,

    // Condition Codes

    CC_UGT = PORE_CC_UGT,
    CC_ULT = PORE_CC_ULT,
    CC_SGT = PORE_CC_SGT,
    CC_SLT = PORE_CC_SLT,
    CC_C   = PORE_CC_C,
    CC_V   = PORE_CC_V,
    CC_N   = PORE_CC_N,
    CC_Z   = PORE_CC_Z,
};

// Pseudo-opcodes for LD/LDANDI/STD

#define PORE_INLINE_PSEUDO_LD     0
#define PORE_INLINE_PSEUDO_LDANDI 1
#define PORE_INLINE_PSEUDO_STD    2


// Private version of _BIG_ENDIAN

#ifndef _BIG_ENDIAN
#define PORE_BIG_ENDIAN 0
#else
#define PORE_BIG_ENDIAN _BIG_ENDIAN
#endif


/// Maximum size of disassembly strings
///
/// This is currently sufficient for PORE_INLINE_LISTING_MODE. We don't want
/// to make this too long since the PoreInlineDisassembly object may be on the
/// stack in embedded applications.
#define PORE_INLINE_DISASSEMBLER_STRING_SIZE 128


/// Generate PORE instruction parity
///
/// This flag is an option to pore_inline_context_create(). If set, PORE
/// inline assembly sets the instruction parity bit for each assembled
/// instruction; otherwise the instruction parity bit is always 0.
#define PORE_INLINE_GENERATE_PARITY 0x01

/// Check PORE instruction parity
///
/// This flag is an option to pore_inline_context_create(). If set, PORE
/// inline disassembly checks the instruction parity bit for each disassembled
/// instruction, failing with PORE_INLINE_PARITY_ERROR if the parify is not
/// correct. Otherwise the instruction parity bit is ignored during
/// disassembly.
#define PORE_INLINE_CHECK_PARITY 0x02

/// Disassemble in listing mode
///
/// This flag is an option to pore_inline_context_create(). If set, then
/// generate disassembly strings in the form of a listing that contains
/// location counters and encoded instructions as well as their diassembly.
/// By default the disassembly strings do not contain this information and can
/// be fed back in as source code to a PORE assembler.
#define PORE_INLINE_LISTING_MODE 0x04

/// Disassemble in data mode
///
/// This flag is an option to pore_inline_context_create().  If set, then
/// generate disassembly assuming that the context contains data rather than
/// text. Normally data is disassembled as .long directives, however if the
/// context is unaligned or of an odd length then .byte directives may be used
/// as well.  This option can be used in conjunction with
/// PORE_INLINE_LISTING_MODE and PORE_INLINE_8_BYTE_DATA.
///
/// Note: An intelligent application can switch between the default text
/// disassembly and data disassembly by manipulating the \a options field of
/// the PoreInlineContext between calls of pore_inline_disassemble().
#define PORE_INLINE_DISASSEMBLE_DATA 0x08

/// Disassemble data in 8-byte format
///
/// This flag is an option to pore_inline_context_create().  If set, then if
/// PORE_INLINE_DISASSEMBLE_DATA is also set then generate data disassembly as
/// 8-byte values rather then the default 4-byte values. Normally data is
/// disassembled as .quad directives under this option, however if the context
/// is unaligned or of an odd length then .long and .byte directives may be
/// used as well.  This option can be used in conjunction with
/// PORE_INLINE_LISTING_MODE.
///
/// Note: An intelligent application can switch between the default text
/// disassembly and data disassembly by manipulating the \a options field of
/// the PoreInlineContext between calls of pore_inline_disassemble().
#define PORE_INLINE_8_BYTE_DATA 0x10

/// Disassemble unrecognized opcodes as 4-byte data
///
/// This flag is an option to pore_inline_context_create().  If set, then
/// any putative instruction with an unrecognized opcode will be silently
/// diassembled as 4-byte data.
///
/// This option was added to allow error-free disassembly of
/// non-parity-protected PORE text sections that contain 0x00000000 alignment
/// padding, and is not guaranteed to produce correct or consistent results in
/// any other case.
#define PORE_INLINE_DISASSEMBLE_UNKNOWN 0x20


#ifndef __ASSEMBLER__

/// The type of location counters for the PORE inline assembler

typedef uint32_t PoreInlineLocation;

/// PORE inline assembler context
///
/// See the documentation page \ref pore_inline_assembler and the function
/// pore_inline_context_create() for futher details.

typedef struct {

    /// The memory area to receive the inline assembly
    ///
    /// This field is never modified, allowing the *reset* APIs to function.
    ///
    /// Note: C++ does not allow arithmetic on void* objects, so we use the
    /// Linux convention of storing memory addresses as type 'unsigned long'. 
    unsigned long memory;

    /// The original size of the memory area to receive the inline assembly
    ///
    /// This field is never modified, allowing the *reset* APIs to function.
    size_t size;

    /// The original Location Counter (associated with \a memory)
    ///
    /// This field is never modified, allowing the *reset* APIs to function.
    PoreInlineLocation original_lc;

    /// The memory address associated with the current LC
    ///
    /// Note: C++ does not allow arithmetic on void* objects, so we use the
    /// Linux convention of storing memory addresses as type 'unsigned long'. 
    unsigned long lc_address;

    /// The remaining size of the memory area to receive the inline assembly
    size_t remaining;

    /// The bytewise Location Counter of the assembled code
    PoreInlineLocation lc;

    /// Inline assembly options
    ///
    /// This field is never modified, allowing the *reset* APIs to function.
    int options;

    /// The last error code generated by the inline assembler
    int error;

} PoreInlineContext;


/// PORE inline disassembler result
///
/// This object holds the disassembly produced by pore_inline_disassemble().
/// See documentation for that function for complete details.

typedef struct {

    /// The context as it existed when the instruction was assembled
    ///
    /// Disassembling an instruction modifies the context provided to
    /// pore_inline_disassemble() to point to the next instruction.  This
    /// structure stores a copy of the context at the initial call of
    /// pore_inline_disassemble(), that is, the context in effect when the
    /// dissassembled instruction was assembled.
    PoreInlineContext ctx;

    /// The first 32 bits of every instruction
    uint32_t instruction;

    /// The opcode; bits 0..6 of the instruction
    int opcode;

    /// A flag - If set the opcode is for a 12-byte instruction
    int long_instruction;

    /// The parity bit; bit 7 of the instruction
    int parity;

    /// The register specifier at bits 8..11 of the instruction
    ///
    /// This register is sometimes called the source, sometimes the target,
    /// depending on the opcode.
    int r0;

    /// The register specifier at bits 12..15 of the instruction
    ///
    /// This register is always called the 'source' but is named generically
    /// here since sometimes the specifier at bits 8..11 is also called a
    /// 'source'.
    int r1;

    /// 'ImD16' is the signed 16-bit immediate for short immediate adds and
    /// subtracts.  For the rotate instruction this field also contains the
    /// rotate count which is either 1, 4, 8, 16 or 32.
    int16_t imd16;

    /// 'ImD20' is the 20-bit signed immediate for the LOAD20 instruction
    int32_t imd20;

    /// 'ImD24' is the 24-bit unsigned immediate for the WAIT instruction
    uint32_t imd24;

    /// 'ImD64' is the 64-bit immediate for data immediates and BRAI.  This
    /// field is only set for 3-word instructions.
    uint64_t imd64;

    /// 'ImPCO20' is a signed, 20-bit word offset for branch instructions
    int32_t impco20;

    /// 'ImPCO24' is a signed, 24-bit word offset for branch instructions
    int32_t impco24;

    /// For imA24 opcodes, this indicates memory/pib (1/0) addressing..
    int memory_space;

    /// This is the base register specifier - either a memory (OCI) base
    /// register or a pervasive base register - for Read/Write operations.
    /// Note that this is a PORE register index, not simply 0/1.
    int base_register;

    /// This is the 22-bit signed offset for memory (OCI) addressing.  This
    /// unsigned offset is added to a memory base register (A0/A1) to form the
    /// final 32-bit address.
    uint32_t memory_offset;

    /// This field contains the port number and local address portions of the
    /// PIB/PCB address for load/store operations that target the PIB/PCB.
    /// Note that bits 0..11 will always be 0 in this address.  Bits 1..7 (the
    /// multicast bit and chiplet id) are sourced from the associated
    /// pervasive base register when the instruction executes.
    uint32_t pib_offset;

    /// The update bit of the SCAND instruction
    int update;

    /// The capture bit of the SCAND instruction
    int capture;

    /// The scan length from a SCAND instruction
    int scan_length;

    /// The scan select from a SCAND instruction
    uint32_t scan_select;

    /// The address offset from a SCAND instruction
    uint32_t scan_offset;

    /// The string form of the disassembly.
    ///
    /// The disassembly string is \e not terminated by a newline.  In listing
    /// mode the disassembly string \e will contain embedded newlines for long
    /// instructions.
    char s[PORE_INLINE_DISASSEMBLER_STRING_SIZE];

    /// The data (for data disassembly)
    ///
    /// This is either 1, 4 or 8 bytes in host byte order.
    uint64_t data;

    /// The size of the disassembled \a data field (for data disassembly)
    size_t data_size;

    /// Was this location disassembled as an instruction (0) or as data (1)
    int is_data;

} PoreInlineDisassembly;


// These are internal APIs - they are not needed by application code.

void
pore_inline_be32(unsigned long p, uint32_t x);

void
pore_inline_be64(unsigned long p, uint64_t x);

uint32_t
pore_inline_host32(unsigned long p);

uint64_t
pore_inline_host64(unsigned long p);

int
pore_inline_parity(uint32_t instruction, uint64_t imd64);

void
pore_inline_context_bump(PoreInlineContext *ctx, size_t bytes);

int
pore_inline_instruction1(PoreInlineContext *ctx, int opcode, uint32_t operand);

int
pore_inline_instruction3(PoreInlineContext *ctx, int opcode, uint32_t operand,
			 uint64_t imm);

int
pore_inline_bra(PoreInlineContext *ctx, 
                int opcode, PoreInlineLocation target);

int
pore_inline_brac(PoreInlineContext *ctx,
		 int opcode, int reg, PoreInlineLocation target);

int
pore_inline_cmpibra(PoreInlineContext *ctx, 
                    int opcode, int reg,
                    PoreInlineLocation target, uint64_t imm);

int
pore_inline_brad(PoreInlineContext *ctx, int opcode, int reg);

int
pore_inline_ilogic(PoreInlineContext *ctx, 
                   int opcode, int dest, int src, uint64_t imm);
int
pore_inline_alurr(PoreInlineContext *ctx, 
                  int opcode, int dest, int src1, int src2);

int
pore_inline_adds(PoreInlineContext *ctx, 
                 int opcode, int dest, int src, int imm);

int
pore_inline_load_store(PoreInlineContext *ctx, 
                       int opcode, int src_dest, int32_t offset, int base,
                       uint64_t imm);


// These are utility APIs that may be required by special-purpose code that
// uses the pore_inline library.

void
pore_inline_decode_instruction(PoreInlineDisassembly* dis, 
                               uint32_t instruction);

void
pore_inline_decode_imd64(PoreInlineDisassembly* dis, uint64_t imd64);


// These are the inline PORE instructions, extended mnemonics and pseudo-ops
// to be used by application code.

/// Set a location counter variable from a context
///
/// This is a macro that sets the \a var (of type PoreInlineLocation) to the
/// current location counter of the \a ctx.  The macro produces an expression
/// that evaluates to 0 so that it can be used in the logical-OR expressions
/// used to define inline assembly sequences.

#define PORE_LOCATION(ctx, var) (((var) = (ctx)->lc), 0)

int
pore_inline_context_create(PoreInlineContext *context,
			   void *memory, 
			   size_t size, 
			   PoreInlineLocation lc, 
			   int options);

void
pore_inline_context_reset(PoreInlineContext *context);

void
pore_inline_context_reset_excursion(PoreInlineContext *context);

void
pore_inline_context_copy(PoreInlineContext *dest, PoreInlineContext *src);


int
pore_inline_branch_fixup(PoreInlineContext *ctx, 
			 PoreInlineLocation source,
			 PoreInlineLocation target);


int
pore_inline_disassemble(PoreInlineContext *ctx, PoreInlineDisassembly *dis);


// Native PORE instruction assembly, using PGAS opcode names and operand
// ordering rules. 

// NOP, TRAP, RET

PORE_STATIC inline int
pore_NOP(PoreInlineContext *ctx) 
{
    return pore_inline_instruction1(ctx, PGAS_OPCODE_NOP, 0);
}


PORE_STATIC inline int
pore_TRAP(PoreInlineContext *ctx) 
{
    return pore_inline_instruction1(ctx, PGAS_OPCODE_TRAP, 0);
}


PORE_STATIC inline int
pore_RET(PoreInlineContext *ctx) 
{
    return pore_inline_instruction1(ctx, PGAS_OPCODE_RET, 0);
}


// WAITS, HALT, HOOKI

int
pore_WAITS(PoreInlineContext *ctx, uint32_t cycles);

PORE_STATIC inline int
pore_HALT(PoreInlineContext *ctx)
{
    return pore_inline_instruction1(ctx, PGAS_OPCODE_WAITS, 0);
}    

int
pore_HOOKI(PoreInlineContext *ctx, uint32_t index, uint64_t imm);


// BRA, BSR, LOOP

PORE_STATIC inline int
pore_BRA(PoreInlineContext *ctx, PoreInlineLocation target)
{
    return pore_inline_bra(ctx, PGAS_OPCODE_BRA, target);
}

PORE_STATIC inline int
pore_BSR(PoreInlineContext *ctx, PoreInlineLocation target)
{
    return pore_inline_bra(ctx, PGAS_OPCODE_BSR, target);
}

PORE_STATIC inline int
pore_LOOP(PoreInlineContext *ctx, PoreInlineLocation target)
{
    return pore_inline_bra(ctx, PGAS_OPCODE_LOOP, target);
}


// BRAZ, BRANZ

PORE_STATIC inline int
pore_BRAZ(PoreInlineContext *ctx, int reg, PoreInlineLocation target)
{
    return pore_inline_brac(ctx, PGAS_OPCODE_BRAZ, reg, target);
}


PORE_STATIC inline int
pore_BRANZ(PoreInlineContext *ctx, int reg, PoreInlineLocation target)
{
    return pore_inline_brac(ctx, PGAS_OPCODE_BRANZ, reg, target);
}


// CMPIBRAEQ, CMPIBRANE, CMPIBSREQ

PORE_STATIC inline int
pore_CMPIBRAEQ(PoreInlineContext *ctx, 
               int reg, PoreInlineLocation target, uint64_t imm)
{
    return pore_inline_cmpibra(ctx, PGAS_OPCODE_CMPIBRAEQ, reg, target, imm);
}


PORE_STATIC inline int
pore_CMPIBRANE(PoreInlineContext *ctx, 
               int reg, PoreInlineLocation target, uint64_t imm)
{
    return pore_inline_cmpibra(ctx, PGAS_OPCODE_CMPIBRANE, reg, target, imm);
}


PORE_STATIC inline int
pore_CMPIBSREQ(PoreInlineContext *ctx, 
               int reg, PoreInlineLocation target, uint64_t imm)
{
    return pore_inline_cmpibra(ctx, PGAS_OPCODE_CMPIBSREQ, reg, target, imm);
}


// BRAD, BSRD

PORE_STATIC inline int
pore_BRAD(PoreInlineContext *ctx, int reg) {
    return pore_inline_brad(ctx, PGAS_OPCODE_BRAD, reg);
}

PORE_STATIC inline int
pore_BSRD(PoreInlineContext *ctx, int reg) {
    return pore_inline_brad(ctx, PGAS_OPCODE_BSRD, reg);
}


// ANDI, ORI, XORI

PORE_STATIC inline int
pore_ANDI(PoreInlineContext *ctx, int dest, int src, uint64_t imm)
{
    return pore_inline_ilogic(ctx, PGAS_OPCODE_ANDI, dest, src, imm);
}

PORE_STATIC inline int
pore_ORI(PoreInlineContext *ctx, int dest, int src, uint64_t imm)
{
    return pore_inline_ilogic(ctx, PGAS_OPCODE_ORI, dest, src, imm);
}

PORE_STATIC inline int
pore_XORI(PoreInlineContext *ctx, int dest, int src, uint64_t imm)
{
    return pore_inline_ilogic(ctx, PGAS_OPCODE_XORI, dest, src, imm);
}


// AND, OR, XOR, ADD, SUB

PORE_STATIC inline int
pore_AND(PoreInlineContext *ctx, int dest, int src1, int src2)
{
    return pore_inline_alurr(ctx, PGAS_OPCODE_AND, dest, src1, src2);
}

PORE_STATIC inline int
pore_OR(PoreInlineContext *ctx, int dest, int src1, int src2)
{
    return pore_inline_alurr(ctx, PGAS_OPCODE_OR, dest, src1, src2);
}

PORE_STATIC inline int
pore_XOR(PoreInlineContext *ctx, int dest, int src1, int src2)
{
    return pore_inline_alurr(ctx, PGAS_OPCODE_XOR, dest, src1, src2);
}

PORE_STATIC inline int
pore_ADD(PoreInlineContext *ctx, int dest, int src1, int src2)
{
    return pore_inline_alurr(ctx, PGAS_OPCODE_ADD, dest, src1, src2);
}

PORE_STATIC inline int
pore_SUB(PoreInlineContext *ctx, int dest, int src1, int src2)
{
    return pore_inline_alurr(ctx, PGAS_OPCODE_SUB, dest, src1, src2);
}


// ADDS, SUBS

PORE_STATIC inline int
pore_ADDS(PoreInlineContext *ctx, int dest, int src, int imm)
{
    return pore_inline_adds(ctx, PGAS_OPCODE_ADDS, dest, src, imm);
}

PORE_STATIC inline int
pore_SUBS(PoreInlineContext *ctx, int dest, int src, int imm)
{
    return pore_inline_adds(ctx, PGAS_OPCODE_SUBS, dest, src, imm);
}


// NEG, MR, ROLS, LS, LI

int
pore_NEG(PoreInlineContext *ctx, int dest, int src);

int
pore_MR(PoreInlineContext *ctx, int dest, int src);

int
pore_ROLS(PoreInlineContext *ctx, int dest, int src, int imm);

int
pore_LS(PoreInlineContext *ctx, int dest, int imm);

int
pore_LI(PoreInlineContext *ctx, int dest, uint64_t imm);


// LD, LDANDI, STD, STI, BSI, BCI

PORE_STATIC inline int
pore_LD(PoreInlineContext *ctx, int dest, int32_t offset, int base) 
{
    return 
	pore_inline_load_store(ctx, 
			       PORE_INLINE_PSEUDO_LD, dest, offset, base, 0);
}

PORE_STATIC inline int
pore_LDANDI(PoreInlineContext *ctx, 
            int dest, int32_t offset, int base, uint64_t imm)
{
    return 
	pore_inline_load_store(ctx, 
			       PORE_INLINE_PSEUDO_LDANDI, 
                               dest, offset, base, imm);
}

PORE_STATIC inline int
pore_STD(PoreInlineContext *ctx, int src, int32_t offset, int base) 
{
    return 
	pore_inline_load_store(ctx, 
			       PORE_INLINE_PSEUDO_STD, src, offset, base, 0);
}

PORE_STATIC inline int
pore_STI(PoreInlineContext *ctx, int32_t offset, int base, uint64_t imm)
{
    return 
	pore_inline_load_store(ctx, 
			       PGAS_OPCODE_STI, 0, offset, base, imm);
}


#ifdef IGNORE_HW274735

// BSI and BCI are redacted as instructions and reimplemented as "macros" due
// to HW274735, unless specifically overridden. Note that the inline assembler
// will allow D1 to be used as scratch here, unlike the underlying hardware
// instruction. 

PORE_STATIC inline int
pore_BSI(PoreInlineContext *ctx, 
         int src, int32_t offset, int base, uint64_t imm) 
{
    return 
	pore_inline_load_store(ctx, 
			       PGAS_OPCODE_BSI, src, offset, base, imm);
}

PORE_STATIC inline int
pore_BCI(PoreInlineContext *ctx, 
         int src, int32_t offset, int base, uint64_t imm) 
{
    return 
	pore_inline_load_store(ctx, 
			       PGAS_OPCODE_BCI, src, offset, base, imm);
}

#else

PORE_STATIC inline int
pore_BSI(PoreInlineContext *ctx, 
         int src, int32_t offset, int base, uint64_t imm) 
{
    return 
        ((pore_LD(ctx, src, offset, base) ||
          pore_ORI(ctx, src, src, imm)    ||
          pore_STD(ctx, src, offset, base)) ? ctx->error : 0);
}

PORE_STATIC inline int
pore_BCI(PoreInlineContext *ctx, 
         int src, int32_t offset, int base, uint64_t imm) 
{
    return 
        ((pore_LDANDI(ctx, src, offset, base, ~imm) ||
          pore_STD(ctx, src, offset, base)) ? ctx->error : 0);
}

#endif // IGNORE_HW274735


// BRAIA

int
pore_BRAIA(PoreInlineContext *ctx,
           uint16_t address_space, uint32_t offset);


// SCAND

int
pore_SCAND(PoreInlineContext *ctx,
           int update, int capture, uint16_t length, 
           uint32_t select, uint32_t offset);

#endif	/* __ASSEMBLER__ */

#if 0
{ /* So __cplusplus doesn't mess w/auto-indent */
#endif
#if( defined(__cplusplus) && !defined(PLIC_MODULE) ) 
}
#endif

#endif	/* __PORE_INLINE_H__ */

