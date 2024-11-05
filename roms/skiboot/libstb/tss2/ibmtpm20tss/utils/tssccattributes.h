/********************************************************************************/
/*										*/
/*			     Command Code Attributes				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2015 - 2019.					*/
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

#ifndef TSSCCATTRIBUTES_H
#define TSSCCATTRIBUTES_H

#include <stdio.h>

#include <ibmtss/TPM_Types.h>
#include "CommandAttributes.h"

typedef uint16_t COMMAND_INDEX;

/* From Global.h */
typedef UINT32          AUTH_ROLE;
#define AUTH_NONE       ((AUTH_ROLE)(0))
#define AUTH_USER       ((AUTH_ROLE)(1))
#define AUTH_ADMIN      ((AUTH_ROLE)(2))
#define AUTH_DUP        ((AUTH_ROLE)(3))

#define UNIMPLEMENTED_COMMAND_INDEX     ((COMMAND_INDEX)(~0))

COMMAND_INDEX CommandCodeToCommandIndex(TPM_CC commandCode)
#ifdef __ULTRAVISOR__
__attribute__ ((const))
#endif
    ;
uint32_t getCommandHandleCount(COMMAND_INDEX index)
#ifdef __ULTRAVISOR__
    __attribute__ ((const))
#endif
    ;
uint32_t getresponseHandleCount(COMMAND_INDEX index)
#ifdef __ULTRAVISOR__
    __attribute__ ((const))
#endif
    ;
int getDecryptSize(COMMAND_INDEX    commandIndex)
#ifdef __ULTRAVISOR__
    __attribute__ ((const))
#endif
    ;
int getEncryptSize(COMMAND_INDEX    commandIndex)
#ifdef __ULTRAVISOR__
    __attribute__ ((const))
#endif
    ;
AUTH_ROLE getCommandAuthRole(COMMAND_INDEX    	commandIndex,
			     size_t		handleIndex)
#ifdef __ULTRAVISOR__
    __attribute__ ((const))
#endif
    ;

#endif
