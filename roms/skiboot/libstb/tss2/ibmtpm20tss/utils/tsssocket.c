/********************************************************************************/
/*										*/
/*			   Socket Transmit and Receive Utilities		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tsssocket.c 1304 2018-08-20 18:31:45Z kgoldman $		*/
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#ifndef TPM_NOSOCKET

/* TSS_SOCKET_FD encapsulates the differences between the Posix and Windows socket type */

#ifdef TPM_POSIX
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#endif

#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#include <sys/types.h>
#include <fcntl.h>

#include <ibmtss/Unmarshal_fp.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tsserror.h>
#include <ibmtss/tssprint.h>
#include "tssproperties.h"
#include <ibmtss/tsstransmit.h>

#include "tsssocket.h"

/* local prototypes */

static uint32_t TSS_Socket_Open(TSS_CONTEXT *tssContext, short port);
static uint32_t TSS_Socket_SendCommand(TSS_CONTEXT *tssContext,
				       const uint8_t *buffer, uint16_t length,
				       const char *message);
static uint32_t TSS_Socket_SendPlatform(TSS_SOCKET_FD sock_fd, uint32_t command, const char *message);
static uint32_t TSS_Socket_ReceiveResponse(TSS_CONTEXT *tssContext, uint8_t *buffer, uint32_t *length);
static uint32_t TSS_Socket_ReceivePlatform(TSS_SOCKET_FD sock_fd);
static uint32_t TSS_Socket_ReceiveBytes(TSS_SOCKET_FD sock_fd, uint8_t *buffer, uint32_t nbytes);
static uint32_t TSS_Socket_SendBytes(TSS_SOCKET_FD sock_fd, const uint8_t *buffer, size_t length);

static uint32_t TSS_Socket_GetServerType(TSS_CONTEXT *tssContext,
					 int *mssim,
					 int *rawsingle);
#ifdef TPM_WINDOWS
static void TSS_Socket_PrintError(int err);
#endif
    
extern int tssVverbose;
extern int tssVerbose;

/* TSS_Socket_TransmitPlatform() transmits MS simulator platform administrative commands */

TPM_RC TSS_Socket_TransmitPlatform(TSS_CONTEXT *tssContext,
				   uint32_t command, const char *message)
{
    TPM_RC 	rc = 0;
    int 	mssim;	/* boolean, true for MS simulator packet format, false for raw packet
			   format */
    int 	rawsingle = FALSE;	/* boolean, true for raw format with an open and close per
					   command */
    /* open on first transmit */
    if (tssContext->tssFirstTransmit) {	
	/* detect errors before starting, get the server packet type, MS sim or raw */
	if (rc == 0) {
	    rc = TSS_Socket_GetServerType(tssContext, &mssim, &rawsingle);
	}
	/* the platform administrative commands can only work with the simulator */
	if (rc == 0) {
	    if (!mssim) {
		if (tssVerbose) printf("TSS_Socket_TransmitPlatform: server type %s unsupported\n",
				       tssContext->tssServerType);
		rc = TSS_RC_INSUPPORTED_INTERFACE;	
	    }
	}
	if (rc == 0) {
	    rc = TSS_Socket_Open(tssContext, tssContext->tssPlatformPort);
	}
	if (rc == 0) {
	    tssContext->tssFirstTransmit = FALSE;
	}
    }
    if (rc == 0) {
	rc = TSS_Socket_SendPlatform(tssContext->sock_fd, command, message);
    }
    if (rc == 0) {
	rc = TSS_Socket_ReceivePlatform(tssContext->sock_fd);
    }
    return rc;
}

/* TSS_Socket_TransmitCommand() transmits MS simulator in band administrative commands */

TPM_RC TSS_Socket_TransmitCommand(TSS_CONTEXT *tssContext,
				  uint32_t command, const char *message)
{
    TPM_RC 	rc = 0;
    int 	mssim;	/* boolean, true for MS simulator packet format, false for raw packet
			   format */
    int 	rawsingle = FALSE;	/* boolean, true for raw format with an open and close per
					   command */
    /* open on first transmit */
    if (tssContext->tssFirstTransmit) {	
	/* detect errors before starting, get the server packet type, MS sim or raw */
	if (rc == 0) {
	    rc = TSS_Socket_GetServerType(tssContext, &mssim, &rawsingle);
	}
	/* the platform administrative commands can only work with the simulator */
	if (rc == 0) {
	    if (!mssim) {
		if (tssVerbose) printf("TSS_Socket_TransmitCommand: server type %s unsupported\n",
				       tssContext->tssServerType);
		rc = TSS_RC_INSUPPORTED_INTERFACE;	
	    }
	}
	if (rc == 0) {
	    rc = TSS_Socket_Open(tssContext, tssContext->tssCommandPort);
	}
	if (rc == 0) {
	    tssContext->tssFirstTransmit = FALSE;
	}
    }
    if (message != NULL) {
	if (tssVverbose) printf("TSS_Socket_TransmitCommand: %s\n", message);
    }
    if (rc == 0) {
	uint32_t commandType = htonl(command);	/* command type is network byte order */
	rc = TSS_Socket_SendBytes(tssContext->sock_fd, (uint8_t *)&commandType, sizeof(uint32_t));
    }
    /* FIXME The only command currently supported is TPM_STOP, which has no response */
    return rc;
}

/* TSS_Socket_Transmit() transmits the TPM command and receives the response.

   It can return socket transmit and receive packet errors, but normally returns the TPM response
   code.

*/

TPM_RC TSS_Socket_Transmit(TSS_CONTEXT *tssContext,
			   uint8_t *responseBuffer, uint32_t *read,
			   const uint8_t *commandBuffer, uint32_t written,
			   const char *message)
{
    TPM_RC 	rc = 0;
    int 	mssim;	/* boolean, true for MS simulator packet format, false for raw packet
			   format */
    int 	rawsingle = FALSE;	/* boolean, true for raw packet format requiring an open and
					   close for each command */

    /* open on first transmit */
    if (tssContext->tssFirstTransmit) {	
	/* detect errors before starting, get the server packet type, MS sim or raw */
	if (rc == 0) {
	    rc = TSS_Socket_GetServerType(tssContext, &mssim, &rawsingle);
	}
	if (rc == 0) {
	    rc = TSS_Socket_Open(tssContext, tssContext->tssCommandPort);
	}
	if (rc == 0) {
	    tssContext->tssFirstTransmit = FALSE;
	}
    }
    /* send the command over the socket.  Error if the socket send fails. */
    if (rc == 0) {
	rc = TSS_Socket_SendCommand(tssContext, commandBuffer, written, message);
    }
    /* receive the response over the socket.  Returns socket errors, malformed response errors.
       Else returns the TPM response code. */
    if (rc == 0) {
	rc = TSS_Socket_ReceiveResponse(tssContext, responseBuffer, read);
    }
    /* rawsingle flags a close after each command */
    if (rawsingle) {
	TPM_RC rc1;
	rc1 = TSS_Socket_Close(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
	tssContext->tssFirstTransmit = TRUE;	/* force reopen on next command */
    }
    return rc;
}

/* TSS_Socket_GetServerType() gets the type of server packet format

   Currently, the formats supported are:

   mssim, raw, rawsingle

   mssim TRUE  - the MS simulator packet
   mssim FALSE - raw TPM specification Part 3 packets
   rawsingle is the same as mssim FALSE but forces an open and cose for each command
*/

static uint32_t TSS_Socket_GetServerType(TSS_CONTEXT *tssContext,
					 int *mssim,
					 int *rawsingle)
{
    uint32_t 	rc = 0;
    if (rc == 0) {
	if ((strcmp(tssContext->tssServerType, "mssim") == 0)) {
	    *mssim = TRUE;
	    *rawsingle = FALSE;
	}
	else if ((strcmp(tssContext->tssServerType, "raw") == 0)) {
	    *mssim = FALSE;
	    *rawsingle = FALSE;
	}
	else if ((strcmp(tssContext->tssServerType, "rawsingle") == 0)) {
	    *mssim = FALSE;
	    *rawsingle = TRUE;
	}
	else {
	    if (tssVerbose) printf("TSS_Socket_GetServerType: server type %s unsupported\n",
				   tssContext->tssServerType);
	    rc = TSS_RC_INSUPPORTED_INTERFACE;	
	}
    }
    return rc;
}

/* TSS_Socket_Open() opens the socket to the TPM Host emulation to tssServerName:port

*/

static uint32_t TSS_Socket_Open(TSS_CONTEXT *tssContext, short port)
{
#ifdef TPM_WINDOWS 
    WSADATA 		wsaData;
    int			irc;
#endif
    struct sockaddr_in 	serv_addr;
    struct hostent 	*host = NULL;

    if (tssVverbose) printf("TSS_Socket_Open: Opening %s:%hu-%s\n",
			    tssContext->tssServerName, port, tssContext->tssServerType);
    /* create a socket */
#ifdef TPM_WINDOWS
    if ((irc = WSAStartup(0x202, &wsaData)) != 0) {		/* if not successful */
	if (tssVerbose) printf("TSS_Socket_Open: Error, WSAStartup failed\n");
	WSACleanup();
	return TSS_RC_NO_CONNECTION;
    }
    if ((tssContext->sock_fd = socket(AF_INET,SOCK_STREAM, 0)) == INVALID_SOCKET) {
	if (tssVerbose) printf("TSS_Socket_Open: client socket() error: %u\n", tssContext->sock_fd);
	return TSS_RC_NO_CONNECTION;
    }
#endif 
#ifdef TPM_POSIX
    if ((tssContext->sock_fd = socket(AF_INET,SOCK_STREAM, 0)) < 0) {
	if (tssVerbose) printf("TSS_Socket_Open: client socket error: %d %s\n",
			       errno,strerror(errno));
	return TSS_RC_NO_CONNECTION;
    }
#endif
    memset((char *)&serv_addr,0x0,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    /* the server host name tssServerName came from the default or an environment variable */
    /* first assume server is dotted decimal number and call inet_addr */
    if ((int)(serv_addr.sin_addr.s_addr = inet_addr(tssContext->tssServerName)) == -1) {
	/* if inet_addr fails, assume server is a name and call gethostbyname to look it up */
	/* if gethostbyname also fails */
	if ((host = gethostbyname(tssContext->tssServerName)) == NULL) {
	    if (tssVerbose) printf("TSS_Socket_Open: server name error, name %s\n",
				   tssContext->tssServerName);
	    return TSS_RC_NO_CONNECTION;
	}
	serv_addr.sin_family = host->h_addrtype;
	memcpy(&serv_addr.sin_addr, host->h_addr, host->h_length);
    }
    /* establish the connection to the TPM server */
#ifdef TPM_POSIX
    if (connect(tssContext->sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
	if (tssVerbose) printf("TSS_Socket_Open: Error on connect to %s:%u\n",
			       tssContext->tssServerName, port);
	if (tssVerbose) printf("TSS_Socket_Open: client connect: error %d %s\n",
			       errno,strerror(errno));
	return TSS_RC_NO_CONNECTION;
    }
#endif
#ifdef TPM_WINDOWS
    if (connect(tssContext->sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0) {
	if (tssVerbose) {
	    int err;
	    printf("TSS_Socket_Open: Error on connect to %s:%u\n",
			       tssContext->tssServerName, port);
	    err = WSAGetLastError();
	    printf("TSS_Socket_Open: client connect: error %d\n", err);
	    TSS_Socket_PrintError(err);
	}
	return TSS_RC_NO_CONNECTION;
    }
#endif
    else {
	/*  	printf("TSS_Socket_Open: client connect: success\n"); */
    }
    return 0;
}

/* TSS_Socket_SendCommand() sends the TPM command packet over the socket.

   The MS simulator packet is of the form:

   TPM_SEND_COMMAND
   locality 0
   length
   TPM command packet	(this is the raw packet format)

   Returns an error if the socket send fails.
*/

static uint32_t TSS_Socket_SendCommand(TSS_CONTEXT *tssContext,
				       const uint8_t *buffer, uint16_t length,
				       const char *message)
{
    uint32_t 	rc = 0;
    int 	mssim;	/* boolean, true for MS simulator packet format, false for raw packet
			   format */
    int 	rawsingle;
    
    if (message != NULL) {
	if (tssVverbose) printf("TSS_Socket_SendCommand: %s\n", message);
    }
    /* trace the command packet */
    if ((rc == 0) && tssVverbose) {
	TSS_PrintAll("TSS_Socket_SendCommand",
		     buffer, length);
    }
    /* get the server packet type, MS sim or raw */
    if (rc == 0) {
	rc = TSS_Socket_GetServerType(tssContext, &mssim, &rawsingle);
    }
    /* MS simulator wants a command type, locality, length */
    if ((rc == 0) && mssim) {
	uint32_t commandType = htonl(TPM_SEND_COMMAND);	/* command type is network byte order */
	rc = TSS_Socket_SendBytes(tssContext->sock_fd, (uint8_t *)&commandType, sizeof(uint32_t));
    }
    if ((rc == 0) && mssim) {
	uint8_t locality = 0;
	rc = TSS_Socket_SendBytes(tssContext->sock_fd, &locality, sizeof(uint8_t));
    }
    if ((rc == 0) && mssim) {
	uint32_t lengthNbo = htonl(length);	/* length is network byte order */
	rc = TSS_Socket_SendBytes(tssContext->sock_fd, (uint8_t *)&lengthNbo, sizeof(uint32_t));
    }
    /* all packet formats (types) send the TPM command packet */
    if (rc == 0) {
	rc = TSS_Socket_SendBytes(tssContext->sock_fd, buffer, length);
    }
    return rc;
}

/* TSS_Socket_SendPlatform() transmits MS simulator platform administrative commands.  This function
   should only be called if the TPM supports administrative commands.

   Returns an error if the socket send fails.

*/

static uint32_t TSS_Socket_SendPlatform(TSS_SOCKET_FD sock_fd, uint32_t command, const char *message)
{
    uint32_t rc = 0;

    if (message != NULL) {
	if (tssVverbose) printf("TSS_Socket_SendPlatform: %s\n", message);
    }
    if (tssVverbose) printf("TSS_Socket_SendPlatform: Command %08x\n", command);
    /* MS simulator platform commands */
    if (rc == 0) {
	uint32_t commandNbo = htonl(command);	/* command is network byte order */
	rc = TSS_Socket_SendBytes(sock_fd, (uint8_t *)&commandNbo , sizeof(uint32_t));
    }
    return rc;
}

/* TSS_Socket_SendBytes() is the low level sent function that transmits the buffer over the socket.

   It handles partial writes by looping.

 */

static uint32_t TSS_Socket_SendBytes(TSS_SOCKET_FD sock_fd, const uint8_t *buffer, size_t length)
{
    int nwritten = 0;
    size_t nleft = 0;
    unsigned int offset = 0;

    nleft = length;
    while (nleft > 0) {
#ifdef TPM_POSIX
	nwritten = write(sock_fd, &buffer[offset], nleft);
	if (nwritten < 0) {        /* error */
	    if (tssVerbose) printf("TSS_Socket_SendBytes: write error %d\n", (int)nwritten);
	    return TSS_RC_BAD_CONNECTION;
	}
#endif
#ifdef TPM_WINDOWS
	/* cast for winsock.  Unix uses void * */
	nwritten = send(sock_fd, (char *)(&buffer[offset]), nleft, 0);
	if (nwritten == SOCKET_ERROR) {        /* error */
	    if (tssVerbose) printf("TSS_Socket_SendBytes: write error %d\n", (int)nwritten);
	    return TSS_RC_BAD_CONNECTION;
	}
#endif
	nleft -= nwritten;
	offset += nwritten;
    }
    return 0;
}

/* TSS_Socket_ReceiveResponse() reads a TPM response packet from the socket.  'buffer' must be at
   least MAX_RESPONSE_SIZE bytes.  The bytes read are returned in 'length'.

   The MS simulator packet is of the form:

   length
   TPM response packet		(this is the raw packet format)
   acknowledgement uint32_t zero

   If the receive succeeds, returns TPM packet error code.

   Validates that the packet length and the packet responseSize match 
*/

static uint32_t TSS_Socket_ReceiveResponse(TSS_CONTEXT *tssContext,
					  uint8_t *buffer, uint32_t *length)
{
    uint32_t 	rc = 0;
    uint32_t 	responseSize = 0;
    uint32_t 	responseLength = 0;
    uint8_t 	*bufferPtr = buffer;	/* the moving buffer */
    TPM_RC 	responseCode;
    uint32_t 	size;		/* dummy for unmarshal call */
    int 	mssim;		/* boolean, true for MS simulator packet format, false for raw
				   packet format */
    int		rawsingle;
    TPM_RC 	acknowledgement;	/* MS sim acknowledgement */
    
    /* get the server packet type, MS sim or raw */
    if (rc == 0) {
	rc = TSS_Socket_GetServerType(tssContext, &mssim, &rawsingle);
    }
    /* read the length prepended by the simulator */
    if ((rc == 0) && mssim) {
	rc = TSS_Socket_ReceiveBytes(tssContext->sock_fd,
				     (uint8_t *)&responseLength, sizeof(uint32_t));
	responseLength = ntohl(responseLength);
    }
    /* read the tag and responseSize */
    if (rc == 0) {
	rc = TSS_Socket_ReceiveBytes(tssContext->sock_fd,
				     bufferPtr, sizeof(TPM_ST) + sizeof(uint32_t));
    }
    /* extract the responseSize */
    if (rc == 0) {
	/* skip over tag to responseSize */
	bufferPtr += sizeof(TPM_ST);
	
	size = sizeof(uint32_t);		/* dummy for call */
	rc = TSS_UINT32_Unmarshalu(&responseSize, &bufferPtr, &size);
	*length = responseSize;			/* returned length */

	/* check the response size, see TSS_CONTEXT structure */
	if (responseSize > MAX_RESPONSE_SIZE) {
	    if (tssVerbose)
		printf("TSS_Socket_ReceiveResponse: ERROR: responseSize %u greater than %u\n",
		       responseSize, MAX_RESPONSE_SIZE);
	    rc = TSS_RC_BAD_CONNECTION;
	}
	/* check that MS sim prepended length is the same as the response TPM packet
	   length parameter */
	if (mssim && (responseSize != responseLength)) {
	    if (tssVerbose) printf("TSS_Socket_ReceiveResponse: "
				   "ERROR: responseSize %u not equal to responseLength %u\n",
				   responseSize, responseLength);
	    rc = TSS_RC_BAD_CONNECTION;
	}
    }
    /* read the rest of the packet */
    if (rc == 0) {
	rc = TSS_Socket_ReceiveBytes(tssContext->sock_fd,
				     bufferPtr,
				     responseSize - (sizeof(TPM_ST) + sizeof(uint32_t)));
    }
    if ((rc == 0) && tssVverbose) {
	TSS_PrintAll("TSS_Socket_ReceiveResponse",
		     buffer, responseSize);
    }
    /* read the MS sim acknowledgement */
    if ((rc == 0) && mssim) {
	rc = TSS_Socket_ReceiveBytes(tssContext->sock_fd,
				     (uint8_t *)&acknowledgement, sizeof(uint32_t));
    }
    /* extract the TPM return code from the packet */
    if (rc == 0) {
	/* skip to responseCode */
	bufferPtr = buffer + sizeof(TPM_ST) + sizeof(uint32_t);
	size = sizeof(TPM_RC);		/* dummy for call */
	rc = TSS_UINT32_Unmarshalu(&responseCode, &bufferPtr, &size);
    }
    /* if there is no other (receive or unmarshal) error, return the TPM response code */
    if (rc == 0) {
	rc = responseCode;
    }
    /* if there is no other (TPM response) error, return the MS simulator packet acknowledgement */
    if ((rc == 0) && mssim) {
	  rc = ntohl(acknowledgement);	/* should always be zero */
    }
    return rc;
}

/* TSS_Socket_ReceivePlatform reads MS simulator platform administrative responses.  This function
   should only be called if the TPM supports administrative commands.

   The acknowledgement is a uint32_t zero.

*/

static uint32_t TSS_Socket_ReceivePlatform(TSS_SOCKET_FD sock_fd)
{
    uint32_t 	rc = 0;
    TPM_RC 	acknowledgement;
    
    /* read the MS sim acknowledgement */
    if (rc == 0) {
	rc = TSS_Socket_ReceiveBytes(sock_fd, (uint8_t *)&acknowledgement, sizeof(uint32_t));
    }
    /* if there is no other error, return the MS simulator packet acknowledgement */
    if (rc == 0) {
	rc = ntohl(acknowledgement);	/* should always be zero */
    }
    return rc;
}

/* TSS_Socket_ReceiveBytes() is the low level receive function that reads the buffer over the
   socket.  'buffer' must be atleast 'nbytes'. 

   It handles partial reads by looping.

*/

static uint32_t TSS_Socket_ReceiveBytes(TSS_SOCKET_FD sock_fd,
					uint8_t *buffer,  
					uint32_t nbytes)
{
    int nread = 0;
    int nleft = 0;

    nleft = nbytes;
    while (nleft > 0) {
#ifdef TPM_POSIX
	nread = read(sock_fd, buffer, nleft);
	if (nread < 0) {       /* error */
	    if (tssVerbose)  printf("TSS_Socket_ReceiveBytes: read error %d\n", nread);
	    return TSS_RC_BAD_CONNECTION;
	}
#endif
#ifdef TPM_WINDOWS
	/* cast for winsock.  Unix uses void * */
	nread = recv(sock_fd, (char *)buffer, nleft, 0);
	if (nread == SOCKET_ERROR) {       /* error */
	    if (tssVerbose) printf("TSS_Socket_ReceiveBytes: read error %d\n", nread);
	    return TSS_RC_BAD_CONNECTION;
	}
#endif
	else if (nread == 0) {  /* EOF */
	    if (tssVerbose) printf("TSS_Socket_ReceiveBytes: read EOF\n");
	    return TSS_RC_BAD_CONNECTION;
	}
	nleft -= nread;
	buffer += nread;
    }
    return 0;
}

/* TSS_Socket_Close() closes the socket.

   It sends the TPM_SESSION_END required by the MS simulator.

*/

TPM_RC TSS_Socket_Close(TSS_CONTEXT *tssContext)
{
    uint32_t 	rc = 0;
    int 	mssim;	/* boolean, true for MS simulator packet format, false for raw packet
			   format */
    int		rawsingle = TRUE;	/* boolean, true for raw format with an open and close per
					   command.  Initialized to suppress false gcc -O3
					   warning. */
    
    if (tssVverbose) printf("TSS_Socket_Close: Closing %s-%s\n",
			    tssContext->tssServerName, tssContext->tssServerType);
    /* get the server packet type, MS sim or raw */
    if (rc == 0) {
	rc = TSS_Socket_GetServerType(tssContext, &mssim, &rawsingle);
    }
    /* the MS simulator expects a TPM_SESSION_END command before close */
    if ((rc == 0) && mssim) {
	uint32_t commandType = htonl(TPM_SESSION_END);
	rc = TSS_Socket_SendBytes(tssContext->sock_fd, (uint8_t *)&commandType, sizeof(uint32_t));
    }
#ifdef TPM_POSIX
    /* always attempt a close, even though rawsingle should already have closed the socket */
    if (close(tssContext->sock_fd) != 0) {
	if (!rawsingle) {
	    if (tssVerbose) printf("TSS_Socket_Close: close error\n");
	    rc = TSS_RC_BAD_CONNECTION;
	}
    }
#endif
#ifdef TPM_WINDOWS
    /* gracefully shut down the socket */
    /* always attempt a close, even though rawsingle should already have closed the socket */
    {
	int		irc;
	irc = shutdown(tssContext->sock_fd, SD_SEND);
	if (!rawsingle) {
	    if (irc == SOCKET_ERROR) {       /* error */
		if (tssVerbose) printf("TSS_Socket_Close: shutdown error\n");
		rc = TSS_RC_BAD_CONNECTION;
	    }
	}
    }
    closesocket(tssContext->sock_fd);
    WSACleanup();
#endif
    return rc;
}
#endif 	/* TPM_NOSOCKET */

#ifdef TPM_WINDOWS

/* The Windows equivalent to strerror().  It also traces the error message.
 */

static void TSS_Socket_PrintError(int err)
{
    DWORD rc;
    char *buffer = NULL;
    /* mingw seems to output UTF-8 for FormatMessage().  For Visual Studio, FormatMessage() outputs
       UTF-16, which would require wprintf(). FormatMessageA() outputs UTF-8, permitting printf()
       for both compilers. */
    rc = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,	/* formatting */
			err,
			0,	/* language */
			(LPSTR)&buffer, 
			0, 
			NULL);
    if (rc != 0) {
	printf("%s\n", buffer);
    }
    LocalFree(buffer);
    return;
}
#endif


