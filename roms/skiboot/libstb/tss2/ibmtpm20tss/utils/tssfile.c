/********************************************************************************/
/*										*/
/*			    TSS and Application File Utilities			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2015 - 2019					*/
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tsserror.h>
#include <ibmtss/tssprint.h>
#include <ibmtss/tssfile.h>

extern int tssVerbose;
extern int tssVverbose;

/* TSS_File_Open() opens the 'filename' for 'mode'
 */

int TSS_File_Open(FILE **file,
		  const char *filename,
		  const char* mode)
{
    int 	rc = 0;
		    
    if (rc == 0) {
	*file = fopen(filename, mode);
	if (*file == NULL) {
	    if (tssVerbose) printf("TSS_File_Open: Error opening %s for %s, %s\n",
				   filename, mode, strerror(errno));
	    rc = TSS_RC_FILE_OPEN;
	}
    }
    return rc;
}

/* TSS_File_ReadBinaryFile() reads 'filename'.  The results are put into 'data', which must be freed
   by the caller.  'length' indicates the number of bytes read.
   
*/

TPM_RC TSS_File_ReadBinaryFile(unsigned char **data,     /* must be freed by caller */
			       size_t *length,
			       const char *filename) 
{
    int		rc = 0;
    long	lrc;
    size_t	src;
    int		irc;
    FILE	*file = NULL;

    *data = NULL;
    *length = 0;
    /* open the file */
    if (rc == 0) {
	rc = TSS_File_Open(&file, filename, "rb");				/* closed @1 */
    }
    /* determine the file length */
    if (rc == 0) {
	irc = fseek(file, 0L, SEEK_END);	/* seek to end of file */
	if (irc == -1L) {
	    if (tssVerbose) printf("TSS_File_ReadBinaryFile: Error seeking to end of %s\n",
				   filename);
	    rc = TSS_RC_FILE_SEEK;
	}
    }
    if (rc == 0) {
	lrc = ftell(file);			/* get position in the stream */
	if (lrc == -1L) {
	    if (tssVerbose) printf("TSS_File_ReadBinaryFile: Error ftell'ing %s\n", filename);
	    rc = TSS_RC_FILE_FTELL;
	}
	else {
	    *length = (size_t)lrc;		/* save the length */
	}
    }
    if (rc == 0) {
	irc = fseek(file, 0L, SEEK_SET);	/* seek back to the beginning of the file */
	if (irc == -1L) {
	    if (tssVerbose) printf("TSS_File_ReadBinaryFile: Error seeking to beginning of %s\n",
				   filename);
	    rc = TSS_RC_FILE_SEEK;
	}
    }
    /* allocate a buffer for the actual data */
    if ((rc == 0) && (*length != 0)) {
	rc = TSS_Malloc(data, *length);
    }
    /* read the contents of the file into the data buffer */
    if ((rc == 0) && *length != 0) {
	src = fread(*data, 1, *length, file);
	if (src != *length) {
	    if (tssVerbose)
		printf("TSS_File_ReadBinaryFile: Error reading %s, %u bytes, got %lu\n",
		       filename, (unsigned int)*length, (unsigned long)src);
	    rc = TSS_RC_FILE_READ;
	}
    }
    if (file != NULL) {
	irc = fclose(file);		/* @1 */
	if (irc != 0) {
	    if (tssVerbose) printf("TSS_File_ReadBinaryFile: Error closing %s\n",
				   filename);
	    rc = TSS_RC_FILE_CLOSE;
	}
    }
    if (rc != 0) {
	if (tssVerbose) printf("TSS_File_ReadBinaryFile: Error reading %s\n", filename);
	free(*data);
	*data = NULL;
    }
    return rc;
}

/* TSS_File_WriteBinaryFile() writes 'data' of 'length' to 'filename'
 */

TPM_RC TSS_File_WriteBinaryFile(const unsigned char *data,
				size_t length,
				const char *filename) 
{
    long	rc = 0;
    size_t	src;
    int		irc;
    FILE	*file = NULL;

    /* open the file */
    if (rc == 0) {
	rc = TSS_File_Open(&file, filename, "wb");	/* closed @1 */
    }
    /* write the contents of the data buffer into the file */
    if (rc == 0) {
	src = fwrite(data, 1, length, file);
	if (src != length) {
	    if (tssVerbose)
		printf("TSS_File_WriteBinaryFile: Error writing %s, %lu bytes, got %lu\n",
		       filename, (unsigned long)length, (unsigned long)src);
	    rc = TSS_RC_FILE_WRITE;
	}
    }
    if (file != NULL) {
	irc = fclose(file);		/* @1 */
	if (irc != 0) {
	    if (tssVerbose) printf("TSS_File_WriteBinaryFile: Error closing %s\n",
				   filename);
	    rc = TSS_RC_FILE_CLOSE;
	}
    }
    return rc;
}

/* TSS_File_ReadStructure() is a general purpose "read a structure" function.
   
   It reads the filename, and then unmarshals the structure using "unmarshalFunction".
*/

TPM_RC TSS_File_ReadStructure(void 			*structure,
			      UnmarshalFunction_t 	unmarshalFunction,
			      const char 		*filename)
{
    TPM_RC 	rc = 0;
    uint8_t	*buffer = NULL;		/* for the free */
    uint8_t	*buffer1 = NULL;	/* for unmarshaling */
    size_t 	length = 0;

    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile(&buffer,     /* freed @1 */
				     &length,
				     filename);
    }
    if (rc == 0) {
	uint32_t ilength = length;
	buffer1 = buffer;
	rc = unmarshalFunction(structure, &buffer1, &ilength);
    }
    free(buffer);	/* @1 */
    return rc;
}

/* TSS_File_ReadStructureFlag() is a general purpose "read a structure" function.

   It reads the filename, and then unmarshals the structure using "unmarshalFunction".

   It is similar to TSS_File_ReadStructure() but is used when the structure unmarshal function
   requires the allowNull flag.
*/

TPM_RC TSS_File_ReadStructureFlag(void 				*structure,
				  UnmarshalFunctionFlag_t 	unmarshalFunction,
				  BOOL 				allowNull,
				  const char 			*filename)
{
    TPM_RC 	rc = 0;
    uint8_t	*buffer = NULL;		/* for the free */
    uint8_t	*buffer1 = NULL;	/* for unmarshaling */
    size_t 	length = 0;

    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile(&buffer,     /* freed @1 */
				     &length,
				     filename);
    }
    if (rc == 0) {
	uint32_t ilength = length;
	buffer1 = buffer;
	rc = unmarshalFunction(structure, &buffer1, &ilength, allowNull);
    }
    free(buffer);	/* @1 */
    return rc;
}

/* TSS_File_WriteStructure() is a general purpose "write a structure" function.
   
   It marshals the structure using "marshalFunction", and then writes it to filename.
*/

TPM_RC TSS_File_WriteStructure(void 			*structure,
			       MarshalFunction_t 	marshalFunction,
			       const char 		*filename)
{
    TPM_RC 	rc = 0;
    uint16_t	written = 0;
    uint8_t	*buffer = NULL;		/* for the free */

    if (rc == 0) {
	rc = TSS_Structure_Marshal(&buffer,	/* freed @1 */
				   &written,
				   structure,
				   marshalFunction);
    }
    if (rc == 0) {
	rc = TSS_File_WriteBinaryFile(buffer,
				      written,
				      filename); 
    }
    free(buffer);	/* @1 */
    return rc;
}

/* TSS_File_Read2B() reads 'filename' and copies the data to 'tpm2b', checking targetSize

 */

TPM_RC TSS_File_Read2B(TPM2B 		*tpm2b,
		       uint16_t 	targetSize,
		       const char 	*filename)
{
    TPM_RC 	rc = 0;
    uint8_t	*buffer = NULL;
    size_t 	length = 0;
    
    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile(&buffer,     /* freed @1 */
				     &length,
				     filename);
    }
    if (rc == 0) {
	if (length > 0xffff) {	/* overflow TPM2B uint16_t */
	    if (tssVerbose) printf("TSS_File_Read2B: size %u greater than 0xffff\n",
				   (unsigned int)length);	
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* copy it into the TPM2B */
    if (rc == 0) {
	rc = TSS_TPM2B_Create(tpm2b, buffer, (uint16_t)length, targetSize);
    }
    free(buffer);	/* @1 */
    return rc;
}

/* FIXME need to add - ignore failure if does not exist */

TPM_RC TSS_File_DeleteFile(const char *filename) 
{
    TPM_RC 	rc = 0;
    int		irc;
    
    if (rc == 0) {
	irc = remove(filename);
	if (irc != 0) {
	    rc = TSS_RC_FILE_REMOVE;
	}
    }
    return rc;
}
