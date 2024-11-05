#ifndef CMD_BOOTA_H
#define CMD_BOOTA_H

#define LENGTHPOS	1
#define CHECKSPOS	2
#define HOSTIDPOS	3
#define NEXTSECPOS	4

#define HEADER_INFO_SIZE	20 /* N. of bytes to skip in a RDB sector to
					have the actual available space */

#define LOAD_OK			0
#define READ_ERROR		1<<16
#define READ_SYNTAX_ERR		2<<16	/* Includes both Checksum and other errors. */

#define UNUSED_BLOCK_ADDRESS 0xffffffff

#define SBL_HIGHEST 256
#define MAX_UNITS 8

#define BOOTLOADER_MAX_BUFFER   (640*1024) /* Maximum size for the second-level bootloader.
					      Used by the netboot functions since we don't
					      know beforehand the size of the file.
					      Someone told me 640K should be enough for
					      everyone. */
//#define NETBOOT_BOOTLOADER_FILENAME  "OS4Bootloader" now it's an unoot var

#endif /* CMD_BOOTA_H */
