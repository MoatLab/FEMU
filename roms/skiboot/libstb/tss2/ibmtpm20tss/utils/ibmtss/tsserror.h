/********************************************************************************/
/*										*/
/*			     TSS Error Codes					*/
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

/* This is a public header. That defines TSS error codes.

   tss.h includes it for convenience.
*/

#ifndef TSSERROR_H
#define TSSERROR_H

/* the base for these errors is 11 << 16 = 000bxxxx */

#define	TSS_RC_OUT_OF_MEMORY		0x000b0001	/* Out of memory,(malloc failed) */
#define	TSS_RC_ALLOC_INPUT		0x000b0002	/* The input to an allocation is not NULL */
#define	TSS_RC_MALLOC_SIZE		0x000b0003	/* The malloc size is too large or zero */
#define	TSS_RC_INSUFFICIENT_BUFFER	0x000b0004	/* A buffer was insufficient for a copy */
#define TSS_RC_BAD_PROPERTY		0x000b0005	/* The property parameter is out of range */
#define TSS_RC_BAD_PROPERTY_VALUE	0x000b0006	/* The property value is invalid */
#define TSS_RC_INSUPPORTED_INTERFACE	0x000b0007	/* The TPM interface type is not supported */
#define TSS_RC_NO_CONNECTION		0x000b0008	/* Failure connecting to lower layer */
#define TSS_RC_BAD_CONNECTION		0x000b0009	/* Failure communicating with lower layer */
#define TSS_RC_MALFORMED_RESPONSE	0x000b000a	/* A response packet was fundamentally malformed */
#define TSS_RC_NULL_PARAMETER		0x000b000b	/* A required parameter was NULL */
#define TSS_RC_NOT_IMPLEMENTED		0x000b000c	/* TSS function is not implemented */
#define TSS_RC_BAD_READ_VALUE		0x000b000d	/* Actual read value different from expected */
#define	TSS_RC_FILE_OPEN		0x000b0010	/* The file could not be opened */
#define	TSS_RC_FILE_SEEK		0x000b0011	/* A file seek failed */
#define	TSS_RC_FILE_FTELL		0x000b0012	/* A file ftell failed */
#define	TSS_RC_FILE_READ		0x000b0013	/* A file read failed */
#define	TSS_RC_FILE_CLOSE		0x000b0014	/* A file close failed */
#define	TSS_RC_FILE_WRITE		0x000b0015	/* A file write failed */
#define	TSS_RC_FILE_REMOVE		0x000b0016	/* A file remove failed */
#define	TSS_RC_RNG_FAILURE		0x000b0020	/* Random number generator failed */
#define TSS_RC_BAD_PWAP_NONCE		0x000b0030	/* Bad PWAP response nonce */
#define TSS_RC_BAD_PWAP_ATTRIBUTES	0x000b0031	/* Bad PWAP response attributes */
#define	TSS_RC_BAD_PWAP_HMAC		0x000b0032	/* Bad PWAP response HMAC */
#define	TSS_RC_NAME_NOT_IMPLEMENTED	0x000b0040	/* Name calculation not implemented for handle type */
#define	TSS_RC_MALFORMED_NV_PUBLIC	0x000b0041	/* The NV public structure does not match the name */
#define TSS_RC_NAME_FILENAME		0x000b0042	/* The name filename function has inconsistent arguments */
#define TSS_RC_MALFORMED_PUBLIC		0x000b0043	/* The public structure does not match the name */
#define	TSS_RC_DECRYPT_SESSIONS		0x000b0050	/* More than one command decrypt session */
#define	TSS_RC_ENCRYPT_SESSIONS		0x000b0051	/* More than one response encrypt session */
#define	TSS_RC_NO_DECRYPT_PARAMETER	0x000b0052	/* Command has no decrypt parameter */
#define	TSS_RC_NO_ENCRYPT_PARAMETER	0x000b0053	/* Response has no encrypt parameter */
#define	TSS_RC_BAD_DECRYPT_ALGORITHM	0x000b0054	/* Session had an unimplemented decrypt symmetric algorithm */
#define	TSS_RC_BAD_ENCRYPT_ALGORITHM	0x000b0055	/* Session had an unimplemented encrypt symmetric algorithm */
#define	TSS_RC_AES_ENCRYPT_FAILURE	0x000b0056	/* AES encryption failed */
#define	TSS_RC_AES_DECRYPT_FAILURE	0x000b0057	/* AES decryption failed */
#define TSS_RC_BAD_ENCRYPT_SIZE		0x000b0058	/* Parameter encryption size mismatch */
#define TSS_RC_AES_KEYGEN_FAILURE	0x000b0059	/* AES key generation failed */
#define TSS_RC_SESSION_NUMBER		0x000b005a	/* session number out of range */
#define	TSS_RC_BAD_SALT_KEY		0x000b0060	/* tpmKey is unsuitable for salt */
#define	TSS_RC_KDFA_FAILED		0x000b0070	/* KDFa function failed */
#define	TSS_RC_HMAC			0x000b0071	/* An HMAC calculation failed */
#define	TSS_RC_HMAC_SIZE		0x000b0072	/* Response HMAC is the wrong size */
#define	TSS_RC_HMAC_VERIFY		0x000b0073	/* HMAC does not verify */
#define	TSS_RC_BAD_HASH_ALGORITHM	0x000b0074	/* Unimplemented hash algorithm */
#define	TSS_RC_HASH			0x000b0075	/* A hash calculation failed */
#define TSS_RC_RSA_KEY_CONVERT		0x000b0076	/* RSA key conversion failed */
#define TSS_RC_RSA_PADDING		0x000b0077	/* RSA add padding failed */
#define TSS_RC_RSA_ENCRYPT		0x000b0078	/* RSA public encrypt failed */
#define TSS_RC_BIGNUM			0x000b0079	/* BIGNUM operation failed */
#define TSS_RC_RSA_SIGNATURE		0x000b007a	/* RSA signature is bad */
#define TSS_RC_EC_SIGNATURE		0x000b007b	/* EC signature is bad */
#define TSS_RC_EC_KEY_CONVERT		0x000b007c	/* EC key conversion failed */
#define TSS_RC_BAD_SIGNATURE_ALGORITHM	0x000b007d	/* Unimplemented signature algorithm */
#define TSS_RC_X509_ERROR		0x000b007e	/* X509 parse error */
#define TSS_RC_PEM_ERROR		0x000b007f	/* PEM parse error */
#define TSS_RC_COMMAND_UNIMPLEMENTED	0x000b0080	/* Unimplemented command */
#define TSS_RC_IN_PARAMETER		0x000b0081	/* Bad in parameter to TSS_Execute */
#define TSS_RC_OUT_PARAMETER		0x000b0082	/* Bad out parameter to TSS_Execute */
#define TSS_RC_BAD_HANDLE_NUMBER	0x000b0083	/* Bad handle number for this command */
#define TSS_RC_KDFE_FAILED              0x000b0084      /* KDFe function failed */
#define TSS_RC_EC_EPHEMERAL_FAILURE     0x000b0085      /* Failed while making or using EC ephemeral key */
#define TSS_RC_FAIL			0x000b0086	/* TSS internal failure */
#define TSS_RC_NO_SESSION_SLOT		0x000b0090	/* TSS context has no session slot for handle */
#define TSS_RC_NO_OBJECTPUBLIC_SLOT	0x000b0091	/* TSS context has no object public slot for handle */
#define TSS_RC_NO_NVPUBLIC_SLOT		0x000b0092	/* TSS context has no NV public slot for handle */
#endif
