/********************************************************************************/
/*										*/
/*			TSS and Application File Utilities			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tssfile.h 1324 2018-08-31 16:36:12Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2015, 2018.					*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

/* This is a semi-public header. The API is subject to change.

   It is useful rapid application development, and as sample code.  It is risky for production code.

*/

#ifndef TSSFILE_H
#define TSSFILE_H

#include <stdio.h>

#include <ibmtss/TPM_Types.h>
#include <ibmtss/tssutils.h>

#ifdef __cplusplus
extern "C" {
#endif

    LIB_EXPORT
    int TSS_File_Open(FILE **file,
		      const char *filename,
		      const char* mode);
    LIB_EXPORT
    TPM_RC TSS_File_ReadBinaryFile(unsigned char **data,
				   size_t *length,
				   const char *filename); 
    LIB_EXPORT 
    TPM_RC TSS_File_WriteBinaryFile(const unsigned char *data,
				    size_t length,
				    const char *filename); 
    
    LIB_EXPORT 
    TPM_RC TSS_File_ReadStructure(void 			*structure,
				  UnmarshalFunction_t 	unmarshalFunction,
				  const char 		*filename);
    LIB_EXPORT 
    TPM_RC TSS_File_ReadStructureFlag(void 			*structure,
				      UnmarshalFunctionFlag_t 	unmarshalFunction,
				      BOOL 			allowNull,
				      const char 		*filename);
    LIB_EXPORT 
    TPM_RC TSS_File_WriteStructure(void 			*structure,
				   MarshalFunction_t 	marshalFunction,
				   const char 		*filename);
    LIB_EXPORT 
    TPM_RC TSS_File_Read2B(TPM2B 		*tpm2b,
			   uint16_t 	targetSize,
			   const char 	*filename);
    LIB_EXPORT 
    TPM_RC TSS_File_DeleteFile(const char *filename); 
    
#ifdef __cplusplus
}
#endif

#endif
