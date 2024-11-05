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
#ifndef CALCULATECRC_H
#define CALCULATECRC_H

#define FLASHFS_DATADDR 0x18		// uint64_t position of pointer to data
#define FLASHFS_FILE_SIZE_ADDR 0x08	// uint64_t pos of total flashimage size value relative to data
#define FLASHFS_HEADER_SIZE_ADDR 0x08	// uint64_t position of total flash header size value

#define FLASHFS_ROMADDR 0x00		// uint64_t position of pointer to next file
#define CRC_METHODE Ethernet_32		// define the CRC genarator (CRC 16 bit to 64 is supported)

//--- header format ---------------------------------
struct stH {
	char magic[8];            // (generic!) headerfile
	uint64_t flashlen;        // dyn
	char version[16];         // $DRIVER_INFO alignment!
	char platform_name[32];   // (hardware)   headerfile
	char date[8];             // BCD encoded creation date (first two bytes unused)
	char mdate[8];            // BCD encoded modification date (first two bytes unused)
	char platform_revision[4];// (hardware)   headerfile
	uint32_t padding;
	uint64_t ui64CRC;         // insert calculated CRC here
	uint64_t ui64FileEnd;     // = 0xFFFF FFFF FFFF FFFF
};

#endif		/* CALCULATECRC_H */

/*--- supported CRC Generators -------------------------
+	Name						length		usage						Generator
+	Tap_16						16 bit		Tape						0x00008005	
+	Floppy_16					16 bit		Floppy						0x00001021
+	Ethernet_32					32 bit		Ethernet					0x04C11DB7
+	SPTrEMBL_64					64 bit		white noise like date		0x0000001B
+	SPTrEMBL_improved_64   		64 bit		DNA code like date			0xAD93D23594C9362D
+	DLT1_64						64 bit		Tape						0x42F0E1EBA9EA3693
+
+	TrEMBL see also	http://www.cs.ud.ac.uk/staff/D.Jones/crcbote.pdf
+	DLT1 se also 	http://www.ecma-international.org/publications/files/ECMA-ST/Ecma-182.pdf
+--------------------------------------------------------*/
