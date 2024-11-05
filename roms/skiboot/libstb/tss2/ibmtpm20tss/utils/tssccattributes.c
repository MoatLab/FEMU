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

/* NOTE: This is a replica of CommandAttributeData.c, but endian independent.  It must be kept in
   sync with the TPM reference implementation.
   
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "tssccattributes.h"

/* CommandCodeToCommandIndex() returns the index into the s_ccAttr table for the commandCode.
   Returns UNIMPLEMENTED_COMMAND_INDEX if the command is unimplemented.
*/

/* NOTE: Marked as const function in header declaration */

COMMAND_INDEX CommandCodeToCommandIndex(TPM_CC commandCode)
{
    COMMAND_INDEX i;

    /* s_ccAttr has terminating 0x0000 command code and V */
    for (i = 0 ; (s_ccAttr[i].commandCode != 0) || (s_ccAttr[i].V != 0) ; i++) {
	if (s_ccAttr[i].commandCode == commandCode) {
	    return i;
	}
    }
    return UNIMPLEMENTED_COMMAND_INDEX;
}

/* getCommandHandleCount() returns the number of command parameter handles */

/* NOTE: Marked as const function in header declaration */

uint32_t getCommandHandleCount(COMMAND_INDEX index)
{
    return s_ccAttr[index].cHandles;
}

/* getresponseHandleCount() returns the number of command parameter handles */

/* NOTE: Marked as const function in header declaration */

uint32_t getresponseHandleCount(COMMAND_INDEX index)
{
    return s_ccAttr[index].rHandle;
}

/* getDecryptSize() returns 0 if the command does not support command parameter encryption, 2 if the
   command does support command parameter encryption and the size is a uint16_t.  There is an unused
   provision for a 4 for a uint32_t size. */

/* NOTE: Marked as const function in header declaration */

int getDecryptSize(COMMAND_INDEX    commandIndex)
{
    COMMAND_ATTRIBUTES      ca = s_commandAttributes[commandIndex];
    
    if(ca & DECRYPT_2)
	return 2;
    if(ca & DECRYPT_4)
	return 4;
    return 0;
}

/* getEecryptSize() returns 0 if the response does not support response parameter encryption, 2 if
   the command does support response parameter encryption and the size is a uint16_t.  There is an
   unused provision for a 4 for a uint32_t size. */

/* NOTE: Marked as const function in header declaration */

int getEncryptSize(COMMAND_INDEX    commandIndex)
{
    COMMAND_ATTRIBUTES  ca = s_commandAttributes[commandIndex];
    if(ca & ENCRYPT_2)
	return 2;
    if(ca & ENCRYPT_4)
	return 4;
    return 0;
}

/* getCommandAuthRole() returns the authorization role for the handle: user, admin, or dup.

 */

/* NOTE: Marked as const function in header declaration */

AUTH_ROLE getCommandAuthRole(
			     COMMAND_INDEX    	commandIndex,  // IN: command index
			     size_t		handleIndex    // IN: handle index (zero based)
			     )
{
    if(0 == handleIndex )
	{
	    // Any auth role set?
	    COMMAND_ATTRIBUTES  properties = s_commandAttributes[commandIndex];
	    
	    if(properties & HANDLE_1_USER)
		return AUTH_USER;
	    if(properties & HANDLE_1_ADMIN)
		return AUTH_ADMIN;
	    if(properties & HANDLE_1_DUP)
		return AUTH_DUP;
	}
    else if (1 == handleIndex)
	{
	    if(s_commandAttributes[commandIndex] & HANDLE_2_USER)
		return AUTH_USER;
	}
    return AUTH_NONE;
}
