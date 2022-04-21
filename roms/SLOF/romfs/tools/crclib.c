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

#include <stdio.h>
#include <crclib.h>
#include <calculatecrc.h>

uint64_t ui64Generator1;

/**
 * calculate standart ethernet 32 bit CRC
 * generator polynome is 0x104C11DB7
 * this algorithm can be used for encoding and decoding
 */
static unsigned int
calCRCEthernet32(unsigned char *TextPtr, unsigned long int TextLength,
		 unsigned int AccumCRC)
{
	const unsigned int CrcTableHigh[16] = {
		0x00000000, 0x4C11DB70, 0x9823B6E0, 0xD4326D90,
		0x34867077, 0x7897AB07, 0xACA5C697, 0xE0B41DE7,
		0x690CE0EE, 0x251D3B9E, 0xF12F560E, 0xBD3E8D7E,
		0x5D8A9099, 0x119B4BE9, 0xC5A92679, 0x89B8FD09
	};
	const unsigned CrcTableLow[16] = {
		0x00000000, 0x04C11DB7, 0x09823B6E, 0x0D4326D9,
		0x130476DC, 0x17C56B6B, 0x1A864DB2, 0x1E475005,
		0x2608EDB8, 0x22C9F00F, 0x2F8AD6D6, 0x2B4BCB61,
		0x350C9B64, 0x31CD86D3, 0x3C8EA00A, 0x384FBDBD
	};

	unsigned char *Buffer = TextPtr;
	unsigned long int Residual = TextLength;


	while (Residual > 0) {
		unsigned int Temp = ((AccumCRC >> 24) ^ *Buffer) & 0x000000ff;
		AccumCRC <<= 8;
		AccumCRC ^= CrcTableHigh[Temp / 16];
		AccumCRC ^= CrcTableLow[Temp % 16];
		++Buffer;
		--Residual;
	}
	return AccumCRC;
}

/**
 * create CRC Parameter:  CRC Polynome, Shiftregister Mask and length
 *
 *   ui64Generator[0] = 0;
 *   ui64Generator[1] = 0x42F0E1EB;
 *   ui64Generator[1] = (ui64Generator[1] << 32) + 0xA9EA3693;
 *   iRegisterLength = 63;
 *   ui64RegisterMask =  0xffffffff;
 *   ui64RegisterMask = ((ui64RegisterMask) << 32) + 0xffffffff;
 *
 *    ucl=0x00000000ffffffff = Mask for 32 bit LSFR to cut down number of bits
 *    in the variable to get the same length as LFSR
 *
 *    il = length of LSFR = degree of generator polynom reduce il by one to calculate the degree
 *    of the highest register in LSFR
 *
 *    Examples:
 *    CRC-16 for Tap:		x16 + x15 + x2 + 1
 *     generator = 0x8005,	il = 16,	ucl = 0x000000000000FFFF
 *
 *    CRC-16 for Floppy:		x16 + x12 + x5 +1
 *     generator = 0x1021,	il = 16,	ucl = 0x000000000000FFFF
 *
 *    CRC-32 for Ethernet:	x32 + x26 + x23 + x22 + x16 + x12 + x11 + x10 + x8 + x7 + x5 + x4 + x2 + x + 1
 *     generator = 0x04C11DB7,	il = 32,	ucl = 0x00000000FFFFFFFF
 *
 *    CRC-64 SP-TrEMBL	x64 + x4 + x3 + x + 1 (maximal-length LFSR)
 *     generator = 0x1B,	il = 64,	ucl = 0xFFFFFFFFFFFFFFFF
 *
 *    CRC-64 improved
 *     x64 + x63 + x61 + x59 + x58 + x56 + x55 + x52 + x49 + x48 + x47 + x46+ x44 +
 *     x41 + x37 + x36 + x34 + x32 + x31 + x28 + x26 + x23 + x22 + x19 + x16 + x13 +
 *     x12 + x10 + x9 + x6 + x4 + x3 + 1
 *     (see http://www.cs.ud.ac.uk/staff/D.Jones/crcbote.pdf)
 *     generator = 0xAD93D23594C9362D,  il = 64,    ucl = 0xFFFFFFFFFFFFFFFF
 *
 *    CRC-64 DLT1 spec
 *     x64 + x62 + x57 + x55 + x54 + x53 + x52 + x47 + x46 + x45 + x40 + x39 + x38 + x37 +
 *     x35 + x33 + x32 + x31 + x29 + x27 + x24 + x23 + x22 + x21 + x19 + x17 + x13 + x12 +
 *     x10 + x9 + x7 + x4 + x + 1
 *     (see http://www.ecma-international.org/publications/files/ECMA-ST/Ecma-182.pdf  -> page63)
 *     generator = 0x42F0E1EBA9EA3693
 *
 *    CRC-64 from internet G(x)= 1006003C000F0D50B
 */
int
createCRCParameter(uint64_t *ui64RegisterMask, unsigned int *uiRegisterLength)
{
	enum Generators { Tape_16, Floppy_16, Ethernet_32, SPTrEMBL_64,
			  SPTrEMBL_improved_64, DLT1_64 };
	enum Generators Generator;

	Generator = CRC_METHODE;
	switch (Generator) {
	case Tape_16: {
		*ui64RegisterMask = 0x0000ffff;
		ui64Generator1 = 0x00008005;
		*uiRegisterLength = 16;
		break;
	}
	case Floppy_16: {
		*ui64RegisterMask = 0x0000ffff;
		ui64Generator1 = 0x00001021;
		*uiRegisterLength = 16;
		break;
	}
	case Ethernet_32: {
		*ui64RegisterMask = 0xffffffff;
		ui64Generator1 = 0x04C11DB7;
		*uiRegisterLength = 32;
		break;
	}
	case SPTrEMBL_64: {
		*ui64RegisterMask = 0xffffffff;
		*ui64RegisterMask =
			((*ui64RegisterMask) << 32) + 0xffffffff;
		ui64Generator1 = 0x0000001B;
		*uiRegisterLength = 64;
		break;
	}
	case SPTrEMBL_improved_64: {
		*ui64RegisterMask = 0xffffffff;
		*ui64RegisterMask =
			((*ui64RegisterMask) << 32) + 0xffffffff;
		ui64Generator1 = 0xAD93D235;
		ui64Generator1 = (ui64Generator1 << 32) + 0x94C9362D;
		*uiRegisterLength = 64;
		break;
	}
	case DLT1_64: {
		*ui64RegisterMask = 0xffffffff;
		*ui64RegisterMask =
			((*ui64RegisterMask) << 32) + 0xffffffff;
		ui64Generator1 = 0x42F0E1EB;
		ui64Generator1 = (ui64Generator1 << 32) + 0xA9EA3693;
		*uiRegisterLength = 64;
		break;
	}
	}
	(*uiRegisterLength)--;

	return 0;
}

/**
 *  Check CRC by using Linear Feadback Shift Register (LFSR)
 */
static uint64_t
calCRCbyte(unsigned char *cPtr, uint32_t ui32NoWords, uint64_t AccumCRC)
{

	uint64_t ui64Mask, ui64Generator0;
	uint8_t ui8Buffer;
	unsigned int uiRegisterLength;
	int iShift;

	createCRCParameter(&ui64Mask, &uiRegisterLength);

	ui8Buffer = (*cPtr);
	while (ui32NoWords > 0) {
		for (iShift = 7; iShift >= 0; iShift--) {

			ui64Generator0 = (AccumCRC >> uiRegisterLength);
			AccumCRC <<= 1;
			ui64Generator0 &= 0x01;
			ui64Generator0 = (0 - ui64Generator0);
			AccumCRC ^= (ui64Generator1 & ui64Generator0);
		}
		AccumCRC ^= ui8Buffer;
		AccumCRC &= ui64Mask;
		ui32NoWords -= 1;
		cPtr += 1;
		ui8Buffer = (*cPtr);
	}
	return AccumCRC;
}

/**
 *  Check CRC by using Linear Feadback Shift Register (LFSR)
 */
uint64_t
calCRCword(unsigned char *cPtr, uint32_t ui32NoWords, uint64_t AccumCRC)
{

	uint64_t ui64Mask, ui64Generator0;
	uint16_t ui16Buffer;
	unsigned int uiRegisterLength;
	int iShift;

	createCRCParameter(&ui64Mask, &uiRegisterLength);

	if ((ui32NoWords % 2) != 0) {
		/* if Data string does not end at word boundery add one byte */
		ui32NoWords++;
		cPtr[ui32NoWords] = 0;
	}
	ui16Buffer = ((*(cPtr + 0)) * 256) + (*(cPtr + 1));
	while (ui32NoWords > 0) {
		for (iShift = 15; iShift >= 0; iShift--) {
			ui64Generator0 = (AccumCRC >> uiRegisterLength);
			AccumCRC <<= 1;
			ui64Generator0 &= 0x01;
			ui64Generator0 = (0 - ui64Generator0);
			AccumCRC ^= (ui64Generator1 & ui64Generator0);
		}
		AccumCRC ^= ui16Buffer;
		AccumCRC &= ui64Mask;
		ui32NoWords -= 2;
		cPtr += 2;
		ui16Buffer = ((*(cPtr + 0)) * 256) + (*(cPtr + 1));
	}
	return AccumCRC;
}

uint64_t
checkCRC(unsigned char *cPtr, uint32_t ui32NoWords, uint64_t AccumCRC)
{

	enum Generators { Ethernet_32 };
	enum Generators Generator;
	uint64_t ui64Buffer = AccumCRC;

	Generator = CRC_METHODE;

	switch (Generator) {
	case Ethernet_32: {
		/* (ui32NoWords - 4),no need of 4 bytes 0x as
		 * with shift-register method */
		AccumCRC =
			calCRCEthernet32(cPtr, (ui32NoWords - 4), AccumCRC);
		break;
	}
	default: {
		AccumCRC = calCRCword(cPtr, ui32NoWords, AccumCRC);
		break;
	}
	}

	if (calCRCbyte(cPtr, ui32NoWords, ui64Buffer) != AccumCRC) {
		printf("\n --- big Endian - small Endian problem --- \n");
		AccumCRC--;
	}

	return (AccumCRC);
}
