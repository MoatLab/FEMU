/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/usr/hwpf/hwp/build_winkle_images/p8_slw_build/pgas.h $    */
/*                                                                        */
/* OpenPOWER HostBoot Project                                             */
/*                                                                        */
/* COPYRIGHT International Business Machines Corp. 2012,2014              */
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
#ifndef __PGAS_H__
#define __PGAS_H__

#define __PGAS__

// $Id: pgas.h,v 1.21 2013/11/20 14:06:39 bcbrock Exp $

// ** WARNING : This file is maintained as part of the OCC firmware.  Do **
// ** not edit this file in the PMX area, the hardware procedure area,   **
// ** or the PoreVe area as any changes will be lost.                    **

/// \file pgas.h
/// \brief Pore GAS
///
/// PGAS is documented in a separate standalone document entitled <em> PGAS :
/// PORE GAS (GNU Assembler) User's and Reference Manual </em>.
///
/// This file defines support macros for the GNU PORE assembler, and the PORE
/// inline assembler and disassebler which follow the PGAS assembly syntax.
/// If the compile swith PGAS_PPC is defined in the environment then pgas.h
/// includes pgas_ppc.h which transforms a PowerPC assembler into an assembler
/// for PORE.

// These are the opcodes and mnemonics as defined by the PORE hardware
// manual.  Many of them will change names slightly in PGAS.  

#define PORE_OPCODE_NOP     0x0f
#define PORE_OPCODE_WAIT    0x01
#define PORE_OPCODE_TRAP    0x02
#define PORE_OPCODE_HOOK    0x4f

#define PORE_OPCODE_BRA     0x10
#define PORE_OPCODE_BRAZ    0x12
#define PORE_OPCODE_BRANZ   0x13
#define PORE_OPCODE_BRAI    0x51
#define PORE_OPCODE_BSR     0x14
#define PORE_OPCODE_BRAD    0x1c
#define PORE_OPCODE_BSRD    0x1d
#define PORE_OPCODE_RET     0x15
#define PORE_OPCODE_CMPBRA  0x56
#define PORE_OPCODE_CMPNBRA 0x57
#define PORE_OPCODE_CMPBSR  0x58
#define PORE_OPCODE_LOOP    0x1f

#define PORE_OPCODE_ANDI    0x60
#define PORE_OPCODE_ORI     0x61
#define PORE_OPCODE_XORI    0x62
        
#define PORE_OPCODE_AND     0x25
#define PORE_OPCODE_OR      0x26
#define PORE_OPCODE_XOR     0x27
        
#define PORE_OPCODE_ADD     0x23
#define PORE_OPCODE_ADDI    0x24
#define PORE_OPCODE_SUB     0x29
#define PORE_OPCODE_SUBI    0x28
#define PORE_OPCODE_NEG     0x2a

#define PORE_OPCODE_COPY    0x2c
#define PORE_OPCODE_ROL     0x2e

#define PORE_OPCODE_LOAD20  0x30
#define PORE_OPCODE_LOAD64  0x71
#define PORE_OPCODE_SCR1RD  0x32
#define PORE_OPCODE_SCR1RDA 0x73
#define PORE_OPCODE_SCR2RD  0x36
#define PORE_OPCODE_SCR2RDA 0x77
#define PORE_OPCODE_WRI     0x78
#define PORE_OPCODE_BS      0x74
#define PORE_OPCODE_BC      0x75
#define PORE_OPCODE_SCR1WR  0x39
#define PORE_OPCODE_SCR2WR  0x3a
#define PORE_OPCODE_SCAND   0x7c


// These are the PGAS versions of the PORE opcodes used in the legacy PGAS_PPC
// assembler and the current PORE inline assembler/disassembler.

#define PGAS_OPCODE_NOP       PORE_OPCODE_NOP     
#define PGAS_OPCODE_WAITS     PORE_OPCODE_WAIT    
#define PGAS_OPCODE_TRAP      PORE_OPCODE_TRAP    
#define PGAS_OPCODE_HOOKI     PORE_OPCODE_HOOK    

#define PGAS_OPCODE_BRA       PORE_OPCODE_BRA     
#define PGAS_OPCODE_BRAZ      PORE_OPCODE_BRAZ    
#define PGAS_OPCODE_BRANZ     PORE_OPCODE_BRANZ   
#define PGAS_OPCODE_BRAI      PORE_OPCODE_BRAI    
#define PGAS_OPCODE_BSR       PORE_OPCODE_BSR 
#define PGAS_OPCODE_BRAD      PORE_OPCODE_BRAD    
#define PGAS_OPCODE_BSRD      PORE_OPCODE_BSRD    
#define PGAS_OPCODE_RET       PORE_OPCODE_RET     
#define PGAS_OPCODE_CMPIBRAEQ PORE_OPCODE_CMPBRA  
#define PGAS_OPCODE_CMPIBRANE PORE_OPCODE_CMPNBRA 
#define PGAS_OPCODE_CMPIBSREQ PORE_OPCODE_CMPBSR  
#define PGAS_OPCODE_LOOP      PORE_OPCODE_LOOP    

#define PGAS_OPCODE_ANDI      PORE_OPCODE_ANDI    
#define PGAS_OPCODE_ORI       PORE_OPCODE_ORI     
#define PGAS_OPCODE_XORI      PORE_OPCODE_XORI    

#define PGAS_OPCODE_AND       PORE_OPCODE_AND     
#define PGAS_OPCODE_OR        PORE_OPCODE_OR      
#define PGAS_OPCODE_XOR       PORE_OPCODE_XOR     

#define PGAS_OPCODE_ADD       PORE_OPCODE_ADD     
#define PGAS_OPCODE_ADDS      PORE_OPCODE_ADDI    
#define PGAS_OPCODE_SUB       PORE_OPCODE_SUB     
#define PGAS_OPCODE_SUBS      PORE_OPCODE_SUBI    
#define PGAS_OPCODE_NEG       PORE_OPCODE_NEG     

#define PGAS_OPCODE_MR        PORE_OPCODE_COPY    
#define PGAS_OPCODE_ROLS      PORE_OPCODE_ROL     

#define PGAS_OPCODE_LS        PORE_OPCODE_LOAD20  
#define PGAS_OPCODE_LI        PORE_OPCODE_LOAD64  
#define PGAS_OPCODE_LD0       PORE_OPCODE_SCR1RD  /* Used by LD */
#define PGAS_OPCODE_LD0ANDI   PORE_OPCODE_SCR1RDA /* Used by LDANDI */
#define PGAS_OPCODE_LD1       PORE_OPCODE_SCR2RD  /* Used by LD */
#define PGAS_OPCODE_LD1ANDI   PORE_OPCODE_SCR2RDA /* Used by LDANDI */
#define PGAS_OPCODE_STI       PORE_OPCODE_WRI     
#define PGAS_OPCODE_STD0      PORE_OPCODE_SCR1WR  /* Used by STD */
#define PGAS_OPCODE_STD1      PORE_OPCODE_SCR2WR  /* Used by STD */
#define PGAS_OPCODE_SCAND     PORE_OPCODE_SCAND   

#ifdef IGNORE_HW274735

// BSI and BCI are normally redacted due to HW274735. See also pgas.h

#define PGAS_OPCODE_BSI       PORE_OPCODE_BS      
#define PGAS_OPCODE_BCI       PORE_OPCODE_BC      

#endif // IGNORE_HW274735

// These are the programmer-visible register names as defined by the PORE
// hardware manual.  All of these names (except the PC) appear differently in
// the PGAS syntax, in some cases to reduce confusion, in other cases just to
// have more traditional short mnemonics.

#define PORE_REGISTER_PRV_BASE_ADDR0  0x0
#define PORE_REGISTER_PRV_BASE_ADDR1  0x1
#define PORE_REGISTER_OCI_BASE_ADDR0  0x2
#define PORE_REGISTER_OCI_BASE_ADDR1  0x3
#define PORE_REGISTER_SCRATCH0        0x4
#define PORE_REGISTER_SCRATCH1        0x5
#define PORE_REGISTER_SCRATCH2        0x6
#define PORE_REGISTER_ERROR_MASK      0x7
#define PORE_REGISTER_EXE_TRIGGER     0x9
#define PORE_REGISTER_DATA0           0xa
#define PORE_REGISTER_PC              0xe
#define PORE_REGISTER_IBUF_ID         0xf


// PgP IBUF_ID values

#define PORE_ID_GPE0 0x00
#define PORE_ID_GPE1 0x01
#define PORE_ID_SLW  0x08
#define PORE_ID_SBE  0x04


// Condition Codes

#define PORE_CC_UGT 0x8000
#define PORE_CC_ULT 0x4000
#define PORE_CC_SGT 0x2000
#define PORE_CC_SLT 0x1000
#define PORE_CC_C   0x0800
#define PORE_CC_V   0x0400
#define PORE_CC_N   0x0200
#define PORE_CC_Z   0x0100


// Memory Spaces

#define PORE_SPACE_UNDEFINED 0xffff
#define PORE_SPACE_OCI       0x8000
#define PORE_SPACE_PNOR      0x800b
#define PORE_SPACE_OTPROM    0x0001
#define PORE_SPACE_SEEPROM   0x800c
#define PORE_SPACE_PIBMEM    0x0008             


#ifdef __ASSEMBLER__

////////////////////////////////////////////////////////////////////////////
// PGAS Base Assembler Support
////////////////////////////////////////////////////////////////////////////	


        //////////////////////////////////////////////////////////////////////
        // Condition Codes
        //////////////////////////////////////////////////////////////////////

        .set    CC_UGT, PORE_CC_UGT 
        .set    CC_ULT, PORE_CC_ULT 
        .set    CC_SGT, PORE_CC_SGT 
        .set    CC_SLT, PORE_CC_SLT 
        .set    CC_C,   PORE_CC_C   
        .set    CC_V,   PORE_CC_V   
        .set    CC_N,   PORE_CC_N   
        .set    CC_Z,   PORE_CC_Z


	//////////////////////////////////////////////////////////////////////
        // Utility Macros
        //////////////////////////////////////////////////////////////////////

        // 'Undefine' PowerPC mnemonics to trap programming errors

        .macro  ..undefppc1, i
        .ifnc   \i, ignore
	.macro  \i, args:vararg
	.error  "This is a PowerPC opcode - NOT a PGAS opcode or extended mnemonic"
	.endm
        .endif
        .endm

        .macro  .undefppc, i0, i1=ignore, i2=ignore, i3=ignore
        ..undefppc1 \i0
        ..undefppc1 \i1
        ..undefppc1 \i2
        ..undefppc1 \i3
        .endm

      
        //////////////////////////////////////////////////////////////////////
        // Argument Checking Macros
        //////////////////////////////////////////////////////////////////////
	//
	// These macros remain in the final pgas.h file because 1) they are
	// required for some PGAS pseudo-ops, and 2) to support robust
	// assembler macro definitions. 

	 // Check an unsigned immediate for size

	.macro	..checku, x:req, bits:req, err="Unsigned value too large"

	.if	(((\bits) <= 0) || ((\bits) > 63))
	.error	"The number of bits must be in the range 0 < bits < 64"
	.endif

	.iflt	(\x)
	.error  "An unsigned value is required here"
        .endif
	
	.ifgt	((\x) - (0xffffffffffffffff >> (64 - (\bits))))
	.error	"\err"
	.endif

	.endm

        // Check unsigned 16/22-bit immediates for size
        //
        // In general, PGAS can check immediate values for size restrictions,
        // but unfortunately is not able to check address offset immediates for
        // range. 

        .macro  ..check_u16, u16
	..checku (\u16), 16, "Unsigned immediate is larger than 16 bits"
        .endm

        .macro  ..check_u24, u24
	..checku (\u24), 24, "Unsigned immediate is larger than 24 bits"
        .endm

        // Check a 16/20/22-bit signed immediate for size

        .macro  ..check_s16, s16
        .iflt   \s16
        .iflt   \s16 + 0x8000
	.error  "Immediate value too small for a signed 16-bit field"
        .endif
        .else
        .ifgt   \s16 - 0x7fff
	.error  "Immediate value too large for a signed 16-bit field"
        .endif
        .endif
        .endm

        .macro  ..check_s20, s20
        .iflt   \s20
        .iflt   \s20 + 0x80000
	.error  "Immediate value too small for a signed 20-bit field"
        .endif
        .else
        .ifgt   \s20 - 0x7ffff
	.error  "Immediate value too large for a signed 20-bit field"
        .endif
        .endif
        .endm

        .macro  ..check_s22, s22
        .iflt   \s22
        .iflt   \s22 + 0x200000
	.error  "Immediate value too small for a signed 22-bit field"
        .endif
        .else
        .ifgt   \s22 - 0x1fffff
	.error  "Immediate value too large for a signed 22-bit field"
        .endif
        .endif
        .endm

	// Check a putative SCOM address for bits 0 and 8:11 == 0.

	.macro	..check_scom, address
	.if	((\address) & 0x80f00000)
	.error	"Valid SCOM addresses must have bits 0 and 8:11 equal to 0."
	.endif
	.endm

	// A register required to be D0

	.macro	..d0, reg
	.if	(\reg != D0)
	.error	"Data register D0 is required here"
	.endif
	.endm

	// A register pair required to be D0, D1 in order

	.macro	..d0d1, reg1, reg2
	.if	(((\reg1) != D0) && ((\reg2) != D1))
	.error	"Register-Register ALU operations are only defined on the source pair D0, D1"
	.endif
	.endm

	// A register pair required to be D0, D1 in any order
	.macro	..dxdy, reg1, reg2, err="Expecting D0, D1 in either order"
	.if	!((((\reg1) == D0) && ((\reg2) == D1)) || \
		  (((\reg1) == D1) && ((\reg2) == D0)))
	.error "\err"
	.endif
	.endm

	// A register pair required to be A0, A1 in any order
	.macro	..axay, reg1, reg2, err="Expecting A0, A1 in either order"
	.if	!((((\reg1) == A0) && ((\reg2) == A1)) || \
		  (((\reg1) == A1) && ((\reg2) == A0)))
	.error "\err"
	.endif
	.endm

	// A register pair required to be the same register

	.macro	..same, dest, src
	.if	((\dest) != (\src))
	.error	"PGAS requires the src and dest register of ADDS/SUBS to be explicit and identical"
	.endif
	.endm
	
        // A "Data" register	

        .macro  ..data, reg:req, err="Expecting a 'Data' register"
        .if     (\reg != D0)
        .if     (\reg != D1)
        .error  "\err"
        .endif
        .endif
        .endm

        // An "Address" register

        .macro  ..address, reg:req, err=:"Expecting an 'Address' register"
        .if     (\reg != A0)
        .if     (\reg != A1)
        .error  "\err"
        .endif
        .endif
        .endm

        // A "Pervasive Chiplet ID" register

        .macro  ..pervasive_chiplet_id, reg:req, err="Expecting a 'Pervasive Chiplet ID' register"
        .if     (\reg != P0)
        .if     (\reg != P1)
        .error  "\err"
        .endif
        .endif
        .endm

        // A "Branch Compare Data" register

        .macro  ..branch_compare_data, reg
        .if     (\reg != D0)
        .if     (\reg != D1) 
        .if     (\reg != CTR)
        .error  "Expecting a 'Branch Compare Data' register"
        .endif
        .endif
        .endif
        .endm

        // An "LS Destination" register; Also the set for ADDS/SUBS

        .macro  ..ls_destination, reg
        .if     (\reg != D0)
        .if     (\reg != D1)
        .if     (\reg != A0)
        .if     (\reg != A1)
        .if     (\reg != P0)
        .if     (\reg != P1)
        .if     (\reg != CTR)
        .error "Expecting an 'LS Destination' register"
        .endif
        .endif
        .endif
        .endif
        .endif
        .endif
        .endif
        .endm

        // An "LI Destination" register

        .macro  ..li_destination, reg
        .if     (\reg != D0)
        .if     (\reg != D1)
        .if     (\reg != A0)
        .if     (\reg != A1)
        .if     (\reg != CTR)
        .error "Expecting an 'LI Destination' register"
        .endif
        .endif
        .endif
        .endif
        .endif
        .endm

        // An "LIA Destination" register 

        .macro  ..lia_destination, reg
        .if     (\reg != D0)
        .if     (\reg != D1)
        .if     (\reg != A0)
        .if     (\reg != A1)
        .if     (\reg != TBAR)
        .error "Expecting an 'LIA Destination' register"
        .endif
        .endif
        .endif
        .endif
        .endif
        .endm

	// An "MR Source" register

	.macro	..mr_source, reg
        .if     (\reg != D0)
        .if     (\reg != D1)
        .if     (\reg != A0)
        .if     (\reg != A1)
        .if     (\reg != P0)
        .if     (\reg != P1)
        .if     (\reg != CTR)
        .if     (\reg != PC)
        .if     (\reg != ETR)
        .if     (\reg != SPRG0)
        .if     (\reg != IFR)
	.if	(\reg != EMR)
	.error	"Expecting an 'MR Source' register"
	.endif
	.endif
	.endif
	.endif
	.endif
	.endif
	.endif
	.endif
	.endif
	.endif
	.endif
	.endif
	.endm

        // An "MR Destination" register

        .macro  ..mr_destination, reg
        .if     (\reg != D0)
        .if     (\reg != D1)
        .if     (\reg != A0)
        .if     (\reg != A1)
        .if     (\reg != P0)
        .if     (\reg != P1)
        .if     (\reg != CTR)
        .if     (\reg != PC)
        .if     (\reg != ETR)
        .if     (\reg != SPRG0)
	.if	(\reg != EMR)
        .error "Expecting an 'MR Destination' register"
        .endif
        .endif
        .endif
        .endif
        .endif
        .endif
        .endif
        .endif
        .endif
        .endif
        .endif
        .endm


	//////////////////////////////////////////////////////////////////////
        // PORE address spaces
        //////////////////////////////////////////////////////////////////////

        // The ..set_address_space pseudo-op defines the default address
	// space. It must be defined in order to use BRAA, BRAIA, BSR and
	// CMPIBSR.  Pseudo-ops are provided to set the default space of the
	// program.  Note that code assembled for PNOR will also work in the
	// OCI space in the Sleep/Winkle engine.

        .macro  ..set_default_space, s
	..check_u16 (\s)
        .set    _PGAS_DEFAULT_SPACE, (\s)
        .endm

	.macro	..check_default_space
	.if	(_PGAS_DEFAULT_SPACE == PORE_SPACE_UNDEFINED)
	.error	"The PGAS default address space has not been defined"
	.endif
	.endm	

	..set_default_space PORE_SPACE_UNDEFINED

	.macro	.oci
	..set_default_space PORE_SPACE_OCI
	.endm

	.macro	.pnor
	..set_default_space PORE_SPACE_PNOR
	.endm

	.macro	.seeprom
	..set_default_space PORE_SPACE_SEEPROM
	.endm

	.macro	.otprom
	..set_default_space PORE_SPACE_OTPROM
	.endm

	.macro	.pibmem
	..set_default_space PORE_SPACE_PIBMEM
#ifndef PGAS_PPC
	.pibmem_port (PORE_SPACE_PIBMEM & 0xf)
#else
        // NB: PGAS_PPC does not support relocatable PIBMEM addressing
#endif
	.endm


        //////////////////////////////////////////////////////////////////////
        // Address-Generation Pseudo Ops
        //////////////////////////////////////////////////////////////////////

	// .QUADA, .QUADIA

	.macro	.quada, offset:req
	..check_default_space
	.long   _PGAS_DEFAULT_SPACE
	.long	(\offset)
	.endm
	
	.macro	.quadia, space:req, offset:req
	..check_u16 (\space)
	.long	(\space)
	.long	(\offset)
	.endm

        //////////////////////////////////////////////////////////////////////
        // Bug workarounds
        //////////////////////////////////////////////////////////////////////

#ifndef IGNORE_HW274735

        // HW274735 documents that BC and BS are broken for the PORE-GPE0/1
        // pair. This bug is unfixed in POWER8, and by default we require BSI
        // and BCI to be implemented as macros on all engines. For
        // compatibility we continue to require that dx == D0.

        .macro  bsi, dx:req, offset:req, base:req, imm:req
        ..d0    (\dx)
        ld      D0, (\offset), (\base)
        ori     D0, D0, (\imm)
        std     D0, (\offset), (\base)
        .endm

        .macro  bci, dx:req, offset:req, base:req, imm:req
        ..d0    (\dx)
        ldandi  D0, (\offset), (\base), ~(\imm)
        std     D0, (\offset), (\base)
        .endm

#endif // IGNORE_HW274735

	//////////////////////////////////////////////////////////////////////
	// "A"- and "IA"-form Instructions
	//////////////////////////////////////////////////////////////////////

        // BRAA (Branch Address) is a 'long branch' to an address in the
	// default memory space.

	.macro	braa, offset:req
	braia	_PGAS_DEFAULT_SPACE, (\offset)
	.endm

	// LA (Load Address) loads the full address of an address in the
	// default memory space.

	.macro	la, dest:req, offset:req
	lia	(\dest), _PGAS_DEFAULT_SPACE, (\offset)
	.endm

	// STA (Store Address) stores the full address of an address in the
	// default memory space.

	.macro	sta, mem_offset:req, base:req, addr_offset:req
	stia	(\mem_offset), (\base), _PGAS_DEFAULT_SPACE, (\addr_offset)
	.endm

	// BSRIA is a subroutine branch into another memory space.  This has to
	// be emulated by a local subroutine branch and a BRAIA.
	
	.macro	bsria, space:req, offset:req
	bsr	27742f
	bra	27743f
27742:
	braia	(\space), (\offset)
27743:	
	.endm             


////////////////////////////////////////////////////////////////////////////
// Extended Mnemonics, Macros and Special Cases
////////////////////////////////////////////////////////////////////////////

	//////////////////////////////////////////////////////////////////////
	// TFB<c> - Test flags and branch conditionally
	//////////////////////////////////////////////////////////////////////'
	
	.macro	..tfb, dest, target, flags
	..data	(\dest)
	mr	(\dest), IFR
	andi	(\dest), (\dest), (\flags)
	branz	(\dest), (\target)
	.endm	

	.macro	..tfbn dest, target, flags
	..data	(\dest)
	mr	(\dest), IFR
	andi	(\dest), (\dest), (\flags)
	braz	(\dest), (\target)
	.endm	

	.macro	tfbcs, dest:req, target:req
	..tfb	 (\dest), (\target), CC_C
	.endm

	.macro	tfbcc, dest:req, target:req
	..tfbn	(\dest), (\target), CC_C
	.endm

	.macro	tfbvs, dest:req, target:req
	..tfb	 (\dest), (\target), CC_V
	.endm

	.macro	tfbvc, dest:req, target:req
	..tfbn	 (\dest), (\target), CC_V
	.endm

	.macro	tfbns, dest:req, target:req
	..tfb	 (\dest), (\target), CC_N
	.endm

	.macro	tfbnc, dest:req, target:req
	..tfbn	 (\dest), (\target), CC_N
	.endm

	.macro	tfbeq, dest:req, target:req
	..tfb	(\dest), (\target), CC_Z
	.endm

	.macro	tfbne, dest:req, target:req
	..tfbn	(\dest), (\target), CC_Z
	.endm

	.macro	tfbult, dest:req, target:req
	..tfb	(\dest), (\target), CC_ULT
	.endm

	.macro	tfbule, dest:req, target:req
	..tfbn	(\dest), (\target), CC_UGT
	.endm

	.macro	tfbuge, dest:req, target:req
	..tfbn	(\dest), (\target), CC_ULT
	.endm

	.macro	tfbugt, dest:req, target:req
	..tfb	(\dest), (\target), CC_UGT
	.endm

	.macro	tfbslt, dest:req, target:req
	..tfb	(\dest), (\target), CC_SLT
	.endm

	.macro	tfbsle, dest:req, target:req
	..tfbn	(\dest), (\target), CC_SGT
	.endm

	.macro	tfbsge, dest:req, target:req
	..tfbn	(\dest), (\target), CC_SLT
	.endm

	.macro	tfbsgt, dest:req, target:req
	..tfb	(\dest), (\target), CC_SGT
	.endm


	//////////////////////////////////////////////////////////////////////
	// TEB[N]<eng> - Test Engine and branch if [not] engine.
	//////////////////////////////////////////////////////////////////////
	//
	// All but GPE0 use a 1-hot code.
	
	.macro	tebgpe0, dest:req, target:req
	mr	(\dest), IFR
	andi	(\dest), (\dest), 0xf
	braz	(\dest), (\target)
	.endm	

	.macro	tebgpe1, dest:req, target:req
	mr	(\dest), IFR
	andi	(\dest), (\dest), PORE_ID_GPE1
	branz	(\dest), (\target)
	.endm	

	.macro	tebslw, dest:req, target:req
	mr	(\dest), IFR
	andi	(\dest), (\dest), PORE_ID_SLW
	branz	(\dest), (\target)
	.endm	

	.macro	tebsbe, dest:req, target:req
	mr	(\dest), IFR
	andi	(\dest), (\dest), PORE_ID_SBE
	branz	(\dest), (\target)
	.endm	


	.macro	tebngpe0, dest:req, target:req
	mr	(\dest), IFR
	andi	(\dest), (\dest), 0xf
	branz	(\dest), (\target)
	.endm	

	.macro	tebngpe1, dest:req, target:req
	mr	(\dest), IFR
	andi	(\dest), (\dest), PORE_ID_GPE1
	braz	(\dest), (\target)
	.endm	

	.macro	tebnslw, dest:req, target:req
	mr	(\dest), IFR
	andi	(\dest), (\dest), PORE_ID_SLW
	braz	(\dest), (\target)
	.endm	

	.macro	tebnsbe, dest:req, target:req
	mr	(\dest), IFR
	andi	(\dest), (\dest), PORE_ID_SBE
	braz	(\dest), (\target)
	.endm	


        //////////////////////////////////////////////////////////////////////
        // EXTRPRC   - Extract and right-justify the PIB/PCB return code
        // TPRCB[N]Z - Test PIB return code and branch if [not] zero
        // TPRCBGT   - Test PIB return code and branch if greater-than
        // TPRCBLE   - Test PIB return code and branch if less-then or equal
        //////////////////////////////////////////////////////////////////////
        //
        // To support cases where PORE code expects or must explicitly handle
        // non-0 PIB return codes, the PIB return code and parity indication
        // are stored in bits 32 (parity) and 33-35 (return code) of the IFR.
        // These macros extract the four PIB/PCB status bits from the IFR and
        // right-justifies them into the data register provided. For EXTRPRC
        // that is the total function of the macro. The TPRCB[N]Z macros
        // provide a simple non-destructive test and branch for zero (success)
        // and non-zero (potential problem) codes after the extraction.
        //
        // In complex error handling scenarios one would typically compare the
        // PIB return code against an upper-bound, e.g., the offline response
        // (0x2), and then take further action. If the parity error bit is set
        // then this would produce an aggregate "return code" higher than any
        // that one would typically want to ignore. The TPRCBGT/TPRCBLE macros
        // provide this function; however the test destroys the extracted
        // return code so that if further analysis is required the code will
        // need to be a extracted again.
        //////////////////////////////////////////////////////////////////////

        .macro  extrprc, dest:req
        ..data  (\dest)
        mr      (\dest), IFR
        extrdi  (\dest), (\dest), 4, 32             
        .endm

        .macro  tprcbz, dest:req, target:req
        extrprc (\dest)
        braz    (\dest), (\target)
        .endm
        
        .macro  tprcbnz, dest:req, target:req
        extrprc (\dest)
        branz   (\dest), (\target)
        .endm
        
        .macro  tprcbgt, dest:req, target:req, bound:req
        extrprc (\dest)
        subs    (\dest), (\dest), (\bound)
        tfbugt  (\dest), (\target)
        .endm
        
        .macro  tprcble, dest:req, target:req, bound:req
        extrprc (\dest)
        subs    (\dest), (\dest), (\bound)
        tfbule  (\dest), (\target)
        .endm
        
	//////////////////////////////////////////////////////////////////////
	// LPCS - Load Pervasive Chiplet from Scom address
	//////////////////////////////////////////////////////////////////////

	.macro	lpcs, dest:req, scom:req
	..pervasive_chiplet_id (\dest)
	..check_scom (\scom)
	ls	(\dest), (((\scom) >> 24) & 0x7f)
	.endm


        //////////////////////////////////////////////////////////////////////
        // Shift/Mask extended mnemonics
        //////////////////////////////////////////////////////////////////////

        // All of the 'dot-dot' macros assume that error and identity
	// checking has been done on the arguments already.

        // The initial register-register rotate.  If the incoming shift amount
        // is 0 then the instruction generated is a simple MR.

        .macro  ..rotlrr, ra, rs, sh

        .if     (\sh) >= 32
                rols    (\ra), (\rs), 32
                ..rotlr  (\ra), ((\sh) - 32)
        .elseif (\sh) >= 16
                rols    (\ra), (\rs), 16
                ..rotlr  (\ra), ((\sh) - 16)
        .elseif (\sh) >= 8
                rols    (\ra), (\rs), 8
                ..rotlr  (\ra), ((\sh) - 8)
        .elseif (\sh) >= 4
                rols    (\ra), (\rs), 4
                ..rotlr  (\ra), ((\sh) - 4)
        .elseif (\sh) >= 1
                rols    (\ra), (\rs), 1
                ..rotlr  (\ra), ((\sh) - 1)
        .else
                mr      (\ra), (\rs)
        .endif

        .endm


        // Subsequent rotation of the same register.  The SH should never be 0
        // here. 

        .macro  ..rotlr, ra, sh

        .if     (\sh) >= 32
                rols    (\ra), (\ra), 32
                ..rotlr  (\ra), ((\sh) - 32)
        .elseif (\sh) >= 16
                rols    (\ra), (\ra), 16
                ..rotlr  (\ra), ((\sh) - 16)
        .elseif (\sh) >= 8
                rols    (\ra), (\ra), 8
                ..rotlr  (\ra), ((\sh) - 8)
        .elseif (\sh) >= 4
                rols    (\ra), (\ra), 4
                ..rotlr  (\ra), ((\sh) - 4)
        .elseif (\sh) >= 1
                rols    (\ra), (\ra), 1
                ..rotlr  (\ra), ((\sh) - 1)

        .endif

        .endm


        // RLDINM RA, RS, SH, MB, ME
        //
        // Defined as if there were an equivalent PowerPC instruction. The
        // 'word' forms of the PowerPC instructions and extended mnemonics are
        // undefined in order to catch programming typos.

        .undefppc       rlwinm, extrwi, rotlwi, rotrwi
        .undefppc       slwi, srwi

        .macro  rldinm, ra:req, rs:req, sh:req, mb:req, me:req

        .if     ((\sh) < 0) || ((\sh) > 63)
                .error  "SH must be in the range 0..63"
        .endif
        .if     ((\mb) < 0) || ((\mb) > 63)
                .error  "MB must be in the range 0..63"
        .endif
        .if     ((\me) < 0) || ((\me) > 63)
                .error  "ME must be in the range 0..63"
        .endif
        
        .if     (((\mb) == 0) && ((\me) == 63) || ((\me) == ((\mb) - 1)))

                // The mask is effectively 0..63, i.e., no mask. This is a
                // simple rotate.
                
                ..rotlrr (\ra), (\rs), (\sh)
        
        .else
        
                // We need a mask step.  However if SH == 0 and RA == RS we can
                // bypass the rotate step.
                
                .if     ((\sh) != 0) || ((\ra) != (\rs))
                        ..rotlrr (\ra), (\rs), (\sh)
                .endif
                .if     ((\mb) <= (\me))

                        // This is a straightforward masking operation with a
                        // single mask.
                
                        andi    (\ra), (\ra), ((0xffffffffffffffff >> (\mb)) & (0xffffffffffffffff << (63 - (\me))))
                .else
                
                        // This is a wrapped mask.  
                        // It is created as 2 masks OR-ed together - 0-ME and MB-63
                
                        andi    (\ra), (\ra), (((0xffffffffffffffff >> 0) & (0xffffffffffffffff << (63 - (\me)))) | ((0xffffffffffffffff >> (\mb)) & (0xffffffffffffffff << (63 - 63))))
                .endif
        
        .endif
        
        .endm           

        // RLDINM Extended Mnemonics
        //
        // Defined as if they were equivalent to PowerPC 32-bit extended
	// mnemonics

        .macro  extldi, ra:req, rs:req, n:req, b:req
        .if     ((\n) < 0)
                .error  "EXTLDI requires N > 0"
        .endif
         rldinm (\ra), (\rs), (\b), 0, ((\n) - 1)
        .endm

        .macro  extrdi, ra:req, rs:req, n:req, b:req
        .if     ((\n) < 0)
                .error  "EXTRDI requires N > 0"
        .endif
        rldinm  (\ra), (\rs), (((\b) + (\n)) % 64), (64 - (\n)), 63
        .endm

        .macro  rotldi, ra:req, rs:req, n:req
        rldinm  (\ra), (\rs), (\n), 0, 63
        .endm


        .macro  rotrdi, ra:req, rs:req, n:req
        rldinm  (\ra), (\rs), (64 - (\n)), 0, 63
        .endm


        .macro  sldi, ra:req, rs:req, n:req
        rldinm  (\ra), (\rs), (\n), 0, (63 - (\n))
        .endm
        

        .macro  srdi, ra:req, rs:req, n:req
        rldinm  (\ra), (\rs), (64 - (\n)), (\n), 63
        .endm
        

        // RLDIMI RA, RS, SH, MB, ME
        //
        // Defined as if there were an equivalent PowerPC instruction. The
        // 'word' forms of the PowerPC instructions and extended mnemonics are
        // undefined in order to catch programming typos.
        //
        // Note that unlike the PowerPC instructions, here RLDIMI must destroy
        // RS by masking and shifting it, and RA and RS may not be the same
	// register. 

        .undefppc       rlwimi, inslwi, insrwi

        .macro  rldimi, ra:req, rs:req, sh:req, mb:req, me:req

	..dxdy	(\ra), (\rs)

	// SH error checks are done by rldinm
	        
        .if     (((\mb) == 0) && ((\me) == 63) || ((\me) == ((\mb) - 1)))

                // The mask is effectively 0..63, i.e., no mask. This is a
                // simple rotate of RS into RA
                
		rotldi	(\ra), (\rs), (\sh)
        
        .else

		// Rotate RS and AND with mask

		rldinm	(\rs), (\rs), (\sh), (\mb), (\me)

		// Mask out the significant bits of RS, clear that section of
		// RA, and logical OR RS into RA
        
                .if     ((\mb) <= (\me))

                        // This is a straightforward masking operation with a
                        // single mask.
                
                        andi    (\ra), (\ra), \
				 (~((0xffffffffffffffff >> (\mb)) & (0xffffffffffffffff << (63 - (\me)))))
                .else
                
                        // This is a wrapped mask.  
                        // It is created as 2 masks OR-ed together - 0-ME and MB-63
                
                        andi    (\ra), (\ra), \
				(~(((0xffffffffffffffff >> 0) & (0xffffffffffffffff << (63 - (\me)))) | \
		                  ((0xffffffffffffffff >> (\mb)) & (0xffffffffffffffff << (63 - 63)))))
                .endif

		or	(\ra), D0, D1
        
        .endif

        .endm           

	// RLDIMI Extended Mnemonics
        //
        // Defined as if they were equivalent to PowerPC 32-bit extended
	// mnemonics

        .macro  insldi, ra:req, rs:req, n:req, b:req
        .if     ((\n) < 0)
                .error  "INSLDI requires N > 0"
        .endif
	rldimi	 (\ra), (\rs), (64 - (\b)), (\b), ((\b) + (\n) - 1)
        .endm

        .macro  insrdi, ra:req, rs:req, n:req, b:req
        .if     ((\n) < 0)
                .error  "INSRDI requires N > 0"
        .endif
        rldimi  (\ra), (\rs), (64 - (\b) - (\n)), (\b), ((\b) + (\n) - 1)
        .endm


	//////////////////////////////////////////////////////////////////////
        // .HOOK
	//////////////////////////////////////////////////////////////////////

        // The PoreVe (PORE Virtual Environment) is a PORE simulation
        // environment that allows the programmer to embed C/C++ code into the
        // PORE assembler source code, and arranges for the C/C++ code to be
        // executed in-line with the PORE assembly code.  Instances of the
        // .hook macro are inserted into the assembler input by the
        // hook_extractor script, to mark the locations where hooks are
        // present.  The hook reference is a string that combines the source
        // file name with an index number to uniquely identify the hook.
        //
        //     .hook <file name>_<sequence number>
        //
        // The .hook macro marks the location of each hook in the relocatable
        // binaries with special symbols.  The symbol name includes the hook
        // reference, which is used to locate the hook in the HookManager
        // symbol table. Because hooks can be defined in macros, a hook that
        // appears once in a source file may appear multiple times in the
        // final binary.  For this reason each hook must also be tagged with a
        // unique index number to avoid symbol name collisions.  The
        // complexity of the .hook macro is due to the necessity to decode a
        // dynamic symbol value (_PGAS_HOOK_INDEX) into its binary string form
        // to create the unique symbol name.  The final hook symbol has the
        // form:
        //
        // __hook__<unique>_<reference>
        //
        // where <unique> is a binary string. It is then straightforward to
        // locate these symbols in the 'nm' output of the final link and
        // create a map of final addresses to the hook routine to call (the
        // <reference>) before executing the instruction at that address.
        //
        // Note: The maximum nesting depth of the recursive ..hook_helper
        // macro is log2(index), and the assembler supports nesting of at
        // least 32 which is much more than sufficient.

        .set    _PGAS_HOOK_INDEX, 0

        .macro  .hook, reference:req
        .set    _PGAS_HOOK_INDEX, (_PGAS_HOOK_INDEX + 1)
        ..hook_helper _PGAS_HOOK_INDEX, "", \reference
        .endm

        .macro  ..hook_helper, index, unique, reference
        .ifeq   \index
        __hook__\unique\()_\reference\():       
        .elseif (\index % 2)
        ..hook_helper (\index / 2), 1\unique, \reference
        .else
        ..hook_helper (\index / 2), 0\unique, \reference
        .endif
        .endm


////////////////////////////////////////////////////////////////////////////
// Help for Conversion from Old to New PGAS syntax
////////////////////////////////////////////////////////////////////////////

	.macro	loadp, arg:vararg
	.error	"PGAS now implements 'lpcs' rather then 'loadp'"
	.endm

	.macro	loadx, arg:vararg
	.error	"PGAS now implements 'la' rather than 'loadx'"
	.endm

#endif  // __ASSEMBLER__
                    
#ifdef PGAS_PPC
#include "pgas_ppc.h"
#endif

#endif // __PGAS_H__
