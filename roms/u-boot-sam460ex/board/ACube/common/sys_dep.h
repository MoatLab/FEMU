#ifndef SYS_DEP_H
#define SYS_DEP_H

#include <common.h>
#include <command.h>
#include <net.h>
#include <bzlib.h>
#include <part.h>

typedef long            LONG;
typedef unsigned long   ULONG;
typedef short           WORD;
typedef unsigned short  UWORD;
typedef signed char		BYTE;
typedef unsigned char   UBYTE;
typedef char *          STRPTR;
typedef long			BSTR;
typedef short           BOOL;
typedef void *          APTR;
typedef ULONG           CPTR; //For Joerg.
#ifndef _SIZE_T
#define _SIZE_T
typedef unsigned int    size_t;
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define NULL ((void *)0)

//The whole bunch of <devices/hardblocks.h>
struct RigidDiskBlock {
    ULONG   rdb_ID;		/* 4 character identifier */
    ULONG   rdb_SummedLongs;	/* size of this checksummed structure */
    LONG    rdb_ChkSum;		/* block checksum (longword sum to zero) */
    ULONG   rdb_HostID;		/* SCSI Target ID of host */
    ULONG   rdb_BlockBytes;	/* size of disk blocks */
    ULONG   rdb_Flags;		/* see below for defines */
    /* block list heads */
    ULONG   rdb_Obsolete1;	/* No longer used, was optional bad block list */
    ULONG   rdb_PartitionList;	/* optional first partition block */
    ULONG   rdb_FileSysHeaderList; /* optional file system header block */
    ULONG   rdb_DriveInit;	/* optional drive-specific init code */
				/* DriveInit(lun,rdb,ior): "C" stk & d0/a0/a1 */
    ULONG   rdb_BootStrapCode;  /* Secondary bootstrap code. Uses sector type BOOT */
    ULONG   rdb_Reserved1[5];	/* set to $ffffffff */
    /* physical drive characteristics */
    ULONG   rdb_Cylinders;	/* number of drive cylinders */
    ULONG   rdb_Sectors;	/* sectors per track */
    ULONG   rdb_Heads;		/* number of drive heads */
    ULONG   rdb_Interleave;	/* interleave */
    ULONG   rdb_Park;		/* landing zone cylinder */
    ULONG   rdb_Reserved2[3];
    ULONG   rdb_WritePreComp;	/* starting cylinder: write precompensation */
    ULONG   rdb_ReducedWrite;	/* starting cylinder: reduced write current */
    ULONG   rdb_StepRate;	/* drive step rate */
    ULONG   rdb_Reserved3[5];
    /* logical drive characteristics */
    ULONG   rdb_RDBBlocksLo;	/* low block of range reserved for hardblocks */
    ULONG   rdb_RDBBlocksHi;	/* high block of range for these hardblocks */
    ULONG   rdb_LoCylinder;	/* low cylinder of partitionable disk area */
    ULONG   rdb_HiCylinder;	/* high cylinder of partitionable data area */
    ULONG   rdb_CylBlocks;	/* number of blocks available per cylinder */
    ULONG   rdb_AutoParkSeconds; /* zero for no auto park */
    ULONG   rdb_HighRDSKBlock;	/* highest block used by RDSK */
				/* (not including replacement bad blocks) */
    ULONG   rdb_Reserved4;
    /* drive identification */
    char    rdb_DiskVendor[8];
    char    rdb_DiskProduct[16];
    char    rdb_DiskRevision[4];
    char    rdb_ControllerVendor[8];
    char    rdb_ControllerProduct[16];
    char    rdb_ControllerRevision[4];
    char    rdb_DriveInitName[40]; // jdow: Filename for driveinit source
				   // jdow: as a terminated string.
    char    rdb_BootStrapName[108];// avallino: Filename for bootstrapper source
				   // avallino: as a terminated string.
    ULONG   rdb_Reserved5[37];
};

#define	IDNAME_RIGIDDISK	0x5244534B	/* 'RDSK' */

#define	RDB_LOCATION_LIMIT	16

struct PartitionBlock {
    ULONG   pb_ID;		/* 4 character identifier */
    ULONG   pb_SummedLongs;	/* size of this checksummed structure */
    LONG    pb_ChkSum;		/* block checksum (longword sum to zero) */
    ULONG   pb_HostID;		/* SCSI Target ID of host */
    ULONG   pb_Next;		/* block number of the next PartitionBlock */
    ULONG   pb_Flags;		/* see below for defines */
    ULONG   pb_Reserved1[2];
    ULONG   pb_DevFlags;	/* preferred flags for OpenDevice */
    UBYTE   pb_DriveName[32];	/* preferred DOS device name: BSTR form */
				/* (not used if this name is in use) */
    ULONG   pb_Reserved2[15];	/* filler to 32 longwords */
    ULONG   pb_Environment[20];	/* environment vector for this partition */
    ULONG   pb_EReserved[12];	/* reserved for future environment vector */
};

#define	IDNAME_PARTITION	0x50415254	/* 'PART' */

#define	PBFB_BOOTABLE	0	/* this partition is intended to be bootable */
#define	PBFF_BOOTABLE	1L	/*   (expected directories and files exist) */
#define	PBFB_NOMOUNT	1	/* do not mount this partition (e.g. manually */
#define	PBFF_NOMOUNT	2L	/*   mounted, but space reserved here) */

struct BootstrapCodeBlock {
    ULONG   bcb_ID;		/* 4 character identifier */
    ULONG   bcb_SummedLongs;	/* size of this checksummed structure */
    LONG    bcb_ChkSum;		/* block checksum (longword sum to zero) */
    ULONG   bcb_HostID;		/* SCSI Target ID of host */
    ULONG   bcb_Next;		/* block number of the next BootstrapCodeBlock */
    ULONG   bcb_LoadData[123];	/* binary data of the bootstrapper */
    /* note [123] assumes 512 byte blocks */
};
#define	IDNAME_BOOTSTRAPCODE	0x424f4f54 /* 'BOOT' */

#define DE_TABLESIZE	0	/* minimum value is 11 (includes NumBuffers) */
#define DE_SIZEBLOCK	1	/* in longwords: standard value is 128 */
#define DE_SECORG	2	/* not used; must be 0 */
#define DE_NUMHEADS	3	/* # of heads (surfaces). drive specific */
#define DE_SECSPERBLK	4	/* not used; must be 1 */
#define DE_BLKSPERTRACK 5	/* blocks per track. drive specific */
#define DE_RESERVEDBLKS 6	/* unavailable blocks at start.	 usually 2 */
#define DE_PREFAC	7	/* not used; must be 0 */
#define DE_INTERLEAVE	8	/* usually 0 */
#define DE_LOWCYL	9	/* starting cylinder. typically 0 */
#define DE_UPPERCYL	10	/* max cylinder.  drive specific */
#define DE_NUMBUFFERS	11	/* starting # of buffers.  typically 5 */
#define DE_MEMBUFTYPE	12	/* type of mem to allocate for buffers. */
#define DE_BUFMEMTYPE	12	/* same as above, better name
				 * 1 is public, 3 is chip, 5 is fast */
#define DE_MAXTRANSFER	13	/* Max number bytes to transfer at a time */
#define DE_MASK		14	/* Address Mask to block out certain memory */
#define DE_BOOTPRI	15	/* Boot priority for autoboot */
#define DE_DOSTYPE	16	/* ASCII (HEX) string showing filesystem type;
				 * 0X444F5300 is old filesystem,
				 * 0X444F5301 is fast file system */
#define DE_BAUD		17	/* Baud rate for serial handler */
#define DE_CONTROL	18	/* Control word for handler/filesystem */
#define DE_BOOTBLOCKS	19	/* Number of blocks containing boot code */

/* Note well: when the second level bootloader is called, no "system calls" are allowed.
All system interaction is routed through the sbl_callback_context.
*/

//WARNING: the definition below doesn't work under AOS! So if you need to simulate
// an uboot environment, you need to change it radically.

#include "slb/our_lists.h"
#define MinNode mynode

typedef struct uboot_scan_handle
{
  struct MinNode     ush_link;
  UWORD              ush_bustype;
  UWORD              ush_already_scanned;
  block_dev_desc_t   ush_device;
} * SCAN_HANDLE;

typedef struct old_block_dev_desc {
	int           if_type;    /* type of the interface */
	int           dev;        /* device number */
	unsigned char part_type;  /* partition type */
	unsigned char target;			/* target SCSI ID */
	unsigned char lun;				/* target LUN */
	unsigned char type;				/* device type */
	unsigned long lba;        /* number of blocks */
	unsigned long blksz;			/* block size */
	unsigned char vendor[40]; /* IDE model, SCSI Vendor */
	unsigned char product[20];/* IDE Serial no, SCSI product */
	unsigned char revision[4];/* firmware revision */
	SCAN_HANDLE backpointer;
	unsigned char removable;	/* removable device */
	unsigned long (*block_read)(int dev,
				    unsigned long start,
				    unsigned long blkcnt,
				    unsigned long *buffer);
} old_block_dev_desc_t;

typedef struct uboot_old_scan_handle
{
  struct MinNode	ush_link;
  UWORD			ush_bustype;
  UWORD			ush_already_scanned;
  old_block_dev_desc_t	ush_device;
} * OLD_SCAN_HANDLE;

enum bustype
  {
    BUSTYPE_VIA_ATA,
    BUSTYPE_SCSI,
    BUSTYPE_USB,
    BUSTYPE_NET,
    BUSTYPE_FLOPPY,
    BUSTYPE_SIL_PARALLEL,
    BUSTYPE_SIL_SERIAL,
    BUSTYPE_SIL_4_SERIAL,
#ifdef CONFIG_SAM460EX    
    BUSTYPE_SATA2_460,
#endif    
    BUSTYPE_NONE
  };

typedef void *			uboot_dev_impl;
typedef block_dev_desc_t *	internal_uboot_dev_impl;
  
#define get_lowlevel_handler(scan_handle) (&((scan_handle)->ush_device))

struct dev_access_entry
{
  char * dae_identifier;
  block_dev_desc_t * (*dae_get_dev)(int index);
  UBYTE dae_request_type;
  UBYTE dae_max_unitnum;
  UBYTE dae_bustype;
  UBYTE dae_padding_1;
  ULONG dae_padding_2;
};

//extern dev_access_entry * devices_access_table;
extern struct dev_access_entry * find_dae(const char * s);

//These two below are used in dae_request_type and 'type', along with the others
//defined in the uboot includes.

#define DEV_TYPE_NETBOOT   0x81 //Almost a random choice.
#define DEV_TYPE_DUMMY_END 0xff

#ifndef SECOND_LEVEL_BOOTLOADER
extern SCAN_HANDLE start_unit_scan(const void * scan_list, ULONG * const blocksize);
extern SCAN_HANDLE next_unit_scan(SCAN_HANDLE h, ULONG * const blocksize);
extern BOOL open_specific_unit(const SCAN_HANDLE h);
extern void end_unit_scan(SCAN_HANDLE h);
extern void end_global_scan(void);
extern BOOL loadsector(const ULONG sectn, const ULONG sect_size,
	const ULONG numb_sects, void * const dest_buf);

extern void * alloc_mem_for_iobuffers(const unsigned long size);
extern void * alloc_mem_for_kickmodule(const unsigned long size);
extern void * alloc_mem_for_execNG(const unsigned long size);
extern void * alloc_mem_for_anythingelse(const unsigned long size);
extern void * alloc_mem_for_bootloader(const unsigned long size);
//extern void * alloc_mem_for_bootloader_ABS(const unsigned long size, void * addr);
// The above function is no longer used.

extern void free_mem(void * const loc);
extern struct sbl_callback_context * build_callback_context(void *context);
extern void degrade_to_old_frigging_interface(struct sbl_callback_context * c);
extern int my_NetLoop(char * fn, void * buff);
#endif //SECOND_LEVEL_BOOTLOADER

//extern void mycopymem(const char * src, char * dest, unsigned long size);

//#define printf_to_user printf
//#define scanf_from_user scanf

#define CALLBACK_VERSION 4

struct sbl_callback_context	//This is the context structure passed to the
				//second-level bootloader.
				//It's essentially a bunch of callbacks and
				//some data structures.
	{
	  ULONG	ssc_version;	//Version of the callback protocol context.
	  void (* ssc_printf_like)(const char * fmtstring, ...); //printf() like stuff;
	  int (* ssc_getc_like)(void);

	  void * ssc_scan_list; //This is the parameter passed to the functions below as 'scan_list'
	  struct MinList * ssc_devices_list;
	  SCAN_HANDLE ssc_curr_device;

	  SCAN_HANDLE (* ssc_start_unit_scan)(const void * scan_list, ULONG * const blocksize);
	  SCAN_HANDLE (* ssc_next_unit_scan)(SCAN_HANDLE h, ULONG * const blocksize);
	  BOOL (* ssc_open_specific_unit)(const SCAN_HANDLE h);
	  void (* ssc_end_unit_scan)(SCAN_HANDLE h);
	  void (* ssc_end_global_scan)(void);
	  BOOL (* ssc_loadsector)(const ULONG sectn, const ULONG sect_size,
				  const ULONG numb_sects, void * const dest_buf);

	  int (* ssc_my_netloop)(char * filename, void * dump_here);

	  char * (* ssc_getenv)(uchar *);
	  void (* ssc_setenv)(char *, char *);

	  void * (* ssc_alloc_mem_for_iobuffers)(const size_t size);
	  void * (* ssc_alloc_mem_for_kickmodule)(const size_t size);
	  void * (* ssc_alloc_mem_for_execNG)(const size_t size);
	  void * (* ssc_alloc_mem_for_anythingelse)(const size_t size);
	  void * (* ssc_alloc_mem_for_bootloader)(const size_t size);
	  void (* ssc_free_mem)(void * const loc);

	  void * (* ssc_get_board_info)(void);

	int (* ssc_BZ2_bzBuffToBuffDecompress) (
		char*         dest,
		unsigned int* destLen,
		char*         source,
		unsigned int  sourceLen,
		int           small,
		int           verbosity
		);

	//Video functions (silly EGA style character menus and things.)
	void (* ssc_video_clear)(void);
	void (* ssc_video_draw_box)(int style, int attr, char *title, int separate, int x, int y, int w, int h);

	void (* ssc_video_draw_text)(int x, int y, int attr, char *text, int field);

	void (* ssc_video_repeat_char)(int x, int y, int repcnt, int repchar, int attr);

	unsigned short (* ssc_set_partial_scroll_limits)(const short start, const short end);
	void (* ssc_get_partial_scroll_limits)(short * const start, short * const end);
	int (* ssc_video_get_key)(void);

	int (* ssc_do_bootm)(cmd_tbl_t *cmdtp, int flag, int argc, char *argv[]);
	void * (* ssc_memmove)(void * dest,const void *src,size_t count);
	void (* ssc_set_load_addr)(void * const la);

	int (* ssc_tstc)(void);
	void (* ssc_udelay)(unsigned long);
	int (* ssc_sprintf)(char * buf, const char *fmt, ...);
	
	//New to version 4.1 (should be 5....): ext2fs support in uboot.
	int (* ssc_ext2fs_set_blk_dev_full)(block_dev_desc_t * const rbdd, disk_partition_t * const p);
	int (* ssc_ext2fs_open)(char *filename);
	int (* ssc_ext2fs_read)(char *buf, unsigned len);
	int (* ssc_ext2fs_mount)(unsigned part_length);
	int (* ssc_ext2fs_close)(void);
	};


#endif

