/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cfgparse.h>
#include <time.h>
#include <calculatecrc.h>
#include <product.h>
#include "createcrc.h"
#include "crclib.h"

/* file length in bytes */
static uint64_t ui64globalFileSize = 0;
/* space for the file stream >= 4MB + 4bytes */
static unsigned char pucFileStream[4400000];
/* header length in bytes */
static uint64_t ui64globalHeaderSize = 0;
/* flag to filter detect the header in buildDataStream() */
static int iglobalHeaderFlag = 1;

static size_t min(size_t a, size_t b)
{
	return a < b ? a : b;
}

/**
 * Build the file image and store it as Data Stream of bytes
 * calculate a first CRC for the first file and
 * catch the position of this CRC
 */
int
buildDataStream(unsigned char *pucbuf, int size)
{
	if (ui64globalFileSize + size > sizeof(pucFileStream)) {
		printf("Error: File size is too big!\n");
		return -1;
	}

	/* copy the data into the destination buffer */
	memcpy(pucFileStream + ui64globalFileSize, pucbuf, size);
	ui64globalFileSize += size;

	if (iglobalHeaderFlag == 1) {	// catch header

		ui64globalHeaderSize = ui64globalFileSize;
		iglobalHeaderFlag = 0;
	}

	return 0;
}

/**
 * write Header.img
 */
int
createHeaderImage(int notime)
{
	int iCounter;
	uint64_t ui64RomAddr, ui64DataAddr;
	time_t caltime;
	struct tm *tm;
	char *pcVersion;
	char dastr[16] = { 0, };
	unsigned long long da = 0;

	struct stH stHeader = {
		.magic = FLASHFS_MAGIC,
		.platform_name = FLASHFS_PLATFORM_MAGIC,
		.platform_revision = FLASHFS_PLATFORM_REVISION,
		.ui64FileEnd = -1,
	};

	/* read driver info */
	pcVersion = getenv("DRIVER_NAME");
	if (!pcVersion)
		pcVersion = getenv("USER");
	if (!pcVersion)
		pcVersion = "unknown";
	memcpy(stHeader.version, pcVersion,
	       min(strlen(pcVersion), sizeof(stHeader.version)));

	if (!notime) {
		/* read time and write it into data stream */
		if ((caltime = time(NULL)) == -1) {
			printf("time error\n");
		}
		if ((tm = localtime(&caltime)) == NULL) {
			printf("local time error\n");
		}
		// length must be 13 instead 12 because of terminating
		// NUL. Therefore uH.stH.platform_revison must be
		// written later to overwrite the terminating NUL
		if (strftime(dastr, 15, "0x%Y%m%d%H%M", tm) == 0) {
			printf("strftime error\n");
		}
		da = cpu_to_be64(strtoll(dastr, NULL, 16));
	}
	memcpy(stHeader.date, &da, 8);

	/* read address of next file and address of header date, both are 64 bit values */
	ui64RomAddr = 0;
	ui64DataAddr = 0;
	for (iCounter = 0; iCounter < 8; iCounter++) {
		/* addr of next file */
		ui64RomAddr = (ui64RomAddr << 8) + pucFileStream[FLASHFS_ROMADDR + iCounter];
		/* addr of header data */
		ui64DataAddr = (ui64DataAddr << 8) + pucFileStream[FLASHFS_DATADDR + iCounter];
	}

	/* calculate final flash-header-size and flash-file-size */
	/* calculate end addr of header */
	ui64globalHeaderSize = (uint32_t) ui64DataAddr + sizeof(stHeader);
	/* cut 64 bit to place CRC for File-End */
	ui64globalHeaderSize -= 8;
	/* add 64 bit to place CRC behind File-End */
	ui64globalFileSize += 8;

	if (ui64globalHeaderSize >= ui64RomAddr) {
		printf("%s\n", "--- Header File to long");
		return 1;
	}

	/* fill free space in Header with zeros */
	memset(&pucFileStream[ui64DataAddr], 0, (ui64RomAddr - ui64DataAddr));
	/* place data to header */
	memcpy(&pucFileStream[ui64DataAddr], &stHeader, sizeof(stHeader));

	/* insert header length into data stream */
	*(uint64_t *) (pucFileStream + FLASHFS_HEADER_SIZE_ADDR) =
	    cpu_to_be64(ui64globalHeaderSize);

	/* insert flash length into data stream */
	*(uint64_t *) (pucFileStream + ui64DataAddr + FLASHFS_FILE_SIZE_ADDR) =
	    cpu_to_be64(ui64globalFileSize);

	/* insert zeros as placeholder for CRC */
	*(uint64_t *) (pucFileStream + ui64globalHeaderSize - 8) = 0;
	*(uint64_t *) (pucFileStream + ui64globalFileSize - 8) = 0;

	return 0;
}

/**
 *  insert header and file CRC into data stream
 *  do CRC check on header and file
 *  write data stream to disk
 */
int
writeDataStream(int iofd, int notime)
{
	uint64_t ui64FileCRC = 0, ui64HeaderCRC = 0, ui64RegisterMask;
	unsigned int uiRegisterLength;

	if (0 != createHeaderImage(notime)) {
		return 1;
	}

	createCRCParameter(&ui64RegisterMask, &uiRegisterLength);

	/* calculate CRC */
	ui64HeaderCRC = checkCRC(pucFileStream, ui64globalHeaderSize, 0);
	*(uint64_t *) (pucFileStream + ui64globalHeaderSize - 8) =
	    cpu_to_be64(ui64HeaderCRC);

	ui64FileCRC = checkCRC(pucFileStream, ui64globalFileSize, 0);
	*(uint64_t *) (pucFileStream + ui64globalFileSize - 8) =
	    cpu_to_be64(ui64FileCRC);

	/* check CRC-implementation */
	ui64HeaderCRC = calCRCword(pucFileStream, ui64globalHeaderSize, 0);
	ui64FileCRC = calCRCword(pucFileStream, ui64globalFileSize, 0);

	if ((ui64HeaderCRC != 0) || (ui64FileCRC != 0)) {
		printf("\n\n %s \n %s \n\n", "CRCs not correct implemented.",
		       " ---> Data will not be written do disk.");
		return -1;
	}

	/* write file image to disk */
	if (0 < write(iofd, pucFileStream, ui64globalFileSize))
		return 0;

	printf("<< write failed >>\n");
	return -1;
}
