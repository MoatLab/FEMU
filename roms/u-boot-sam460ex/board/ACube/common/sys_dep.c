#include <common.h>
#include <command.h>
#include <ext2fs.h>
#include "hvideo.h"
#include "sys_dep.h"
#include "sam_ide.h"

#include "malloc.h"

extern int do_bootm (cmd_tbl_t *, int, int, char *[]);

#ifdef CONFIG_CMD_SCSI
extern block_dev_desc_t * scsi_get_dev(int);
#else
block_dev_desc_t * scsi_get_dev(int a)
{
    return (block_dev_desc_t *)0;
}
#endif

#include <usb.h> // I need usb_stor_get_dev()
#define MAX_USB_UNITNUM USB_MAX_STOR_DEV

//System-dependent support for the A1 first and second level bootloaders.

#define MAX_IDE_UNITNUM CFG_IDE_MAXDEVICE
//#define MAX_SCSI_UNITNUM CFG_SCSI_MAX_DEVICE

#include <fdc.h>

static struct MinList dev_list; //Made out of uboot_scan_handles
static struct MinList old_dev_list; //Made out of old_uboot_scan_handles
static SCAN_HANDLE curr_disk;

struct dev_access_entry * find_dae(const char * s)
{
	static struct dev_access_entry devices_access_table[]={
		{NULL,	NULL,	DEV_TYPE_NETBOOT,	1,					BUSTYPE_NET},
		{NULL,	NULL,	DEV_TYPE_CDROM,		MAX_USB_UNITNUM,	BUSTYPE_USB},
		{NULL,	NULL,	DEV_TYPE_HARDDISK,	MAX_USB_UNITNUM,	BUSTYPE_USB},
		{NULL,	NULL,	DEV_TYPE_HARDDISK,	MAX_S_SII_UNITS,	BUSTYPE_SIL_SERIAL},   
		{NULL,	NULL,	DEV_TYPE_CDROM,		MAX_S_SII_UNITS,	BUSTYPE_SIL_SERIAL},
		{NULL,	NULL,	DEV_TYPE_HARDDISK,	MAX_S_4_SII_UNITS,	BUSTYPE_SIL_4_SERIAL},   
		{NULL,	NULL,	DEV_TYPE_CDROM,		MAX_S_4_SII_UNITS,	BUSTYPE_SIL_4_SERIAL},
		{NULL,	NULL,	DEV_TYPE_HARDDISK,	MAX_P_SII_UNITS,	BUSTYPE_SIL_PARALLEL},
		{NULL,	NULL,	DEV_TYPE_CDROM,		MAX_P_SII_UNITS,	BUSTYPE_SIL_PARALLEL},		  		
#ifdef CONFIG_SAM460EX
		{NULL,	NULL,	DEV_TYPE_HARDDISK,	MAX_SATA2_460_UNITS,BUSTYPE_SATA2_460}, 
#endif
     	{NULL,	NULL,	DEV_TYPE_DUMMY_END, 0,					0}
		//{NULL,	NULL,	DEV_TYPE_CDROM,		MAX_SCSI_UNITNUM,	BUSTYPE_SCSI},
		//{NULL,	NULL,	DEV_TYPE_HARDDISK,	MAX_SCSI_UNITNUM,	BUSTYPE_SCSI},
	};
	
	devices_access_table[0].dae_identifier = "net";
	devices_access_table[1].dae_identifier = "ucdrom";
	devices_access_table[2].dae_identifier = "usb";
	devices_access_table[3].dae_identifier = "ssii";
	devices_access_table[4].dae_identifier = "ssiicdrom";
	devices_access_table[5].dae_identifier = "s4sii";
	devices_access_table[6].dae_identifier = "s4siicdrom";
	devices_access_table[7].dae_identifier = "psii";
	devices_access_table[8].dae_identifier = "psiicdrom";
#ifdef CONFIG_SAM460EX
	devices_access_table[9].dae_identifier = "sata2-460";
	devices_access_table[10].dae_identifier = NULL;
#else
	devices_access_table[9].dae_identifier = NULL;
#endif	
	//devices_access_table[1].dae_identifier = "scdrom";
	//devices_access_table[2].dae_identifier = "scsi";

	struct dev_access_entry * current;

	for(current = devices_access_table;
		current->dae_request_type != DEV_TYPE_DUMMY_END;
		current++)
    {
		if(!strcmp(s, current->dae_identifier))
		{
			/* The get_dev() hooks MUST be assigned at runtime, since uboot is relocated! */
			switch(current->dae_bustype)
			{
				//case BUSTYPE_SCSI:
				//	current->dae_get_dev = scsi_get_dev;
				//	break;

				case BUSTYPE_USB:
					current->dae_get_dev = usb_stor_get_dev;
					break;
	       
				case BUSTYPE_SIL_SERIAL:
					current->dae_get_dev = s_sii_get_dev;
					break;
	       
				case BUSTYPE_SIL_4_SERIAL:
					current->dae_get_dev = s_4_sii_get_dev;
					break;

				case BUSTYPE_SIL_PARALLEL:
					current->dae_get_dev = p_sii_get_dev;
					break;					

#ifdef CONFIG_SAM460EX	       
				case BUSTYPE_SATA2_460:
					current->dae_get_dev = sata2_460_get_dev;
					break;
#endif
						       
				default:
					break;
			}

			//printf("found hook is %08lx\n", current->dae_get_dev);
			return current;
		}
    }

	return NULL;
}

SCAN_HANDLE next_unit_scan(SCAN_HANDLE h, ULONG * const blocksize)
{
	SCAN_HANDLE next = (SCAN_HANDLE)h->ush_link.mln_Succ;

	h->ush_already_scanned = TRUE; //Mark the past handle as already scanned.

	//printf("Entered next_unit_scan\n");
 	if(next->ush_link.mln_Succ) //more to go ?
    {
		*blocksize = next->ush_device.blksz;

		/*
		printf("NUS: returning device with data: interface type %d, devnumber %d, type %u\n",
		curr_disk->ush_device.if_type, curr_disk->ush_device.dev, curr_disk->ush_device.type);
		*/
	
		return (curr_disk = next);
	}
	else
    {
		//printf("NUS: no more units in list\n");
		return NULL;
	}
}

SCAN_HANDLE start_unit_scan(const void * scan_list, ULONG * const blocksize)
{
  const char ** opt_list;
  struct dev_access_entry * dae_found;
  //printf("entered start_unit_scan\n");
  if (!scan_list || !blocksize) return NULL;
  //floppy_like_an_hd.block_read = internal_floppy_block_read;

  /* This routine builds a list of scan handles from the env-vars passed in scan_list. */

  NewList(&dev_list);

  for(opt_list = scan_list;*opt_list;opt_list++) //Iterates till empty string.
    {
      //printf("Now examining boot source '%s'\n", *opt_list);

      dae_found = find_dae(*opt_list);

      //printf("Done find_dae\n");
      if(dae_found)
	{
	  SCAN_HANDLE s_h;
	  block_dev_desc_t * newdev;
	  UBYTE curr_unit;

	  //printf("Found dae matching identifier %s, looping\n", dae_found->dae_identifier);
	  for(curr_unit = 0; curr_unit < dae_found->dae_max_unitnum; curr_unit++)
	    {
	      if(dae_found->dae_bustype == BUSTYPE_NET) //Special case!!
		{
		  //printf("Found special boot type network.\n");
		  s_h = alloc_mem_for_anythingelse(sizeof (struct uboot_scan_handle));

		  memset(s_h, 0, sizeof(struct uboot_scan_handle));

		  s_h->ush_bustype = dae_found->dae_bustype;
		  s_h->ush_device.blksz = 1500; //Fake value.
		  s_h->ush_device.type = DEV_TYPE_NETBOOT;
		  AddTail(&dev_list, &s_h->ush_link);
		  continue;
		}

	      if((newdev = dae_found->dae_get_dev(curr_unit)))
		if((newdev->blksz) && (newdev->type == dae_found->dae_request_type))
		  //uboot sei sempre una merda.
		  {
		    s_h = alloc_mem_for_anythingelse(sizeof (struct uboot_scan_handle));
		    memset(s_h, 0, sizeof(struct uboot_scan_handle));
		    s_h->ush_device = *newdev; //Full structure copy.
		    s_h->ush_bustype = dae_found->dae_bustype;

		    /*
		    printf("SUN: found unit; data as follows: interface type %d, devnumber %d, type %u, device points to %08lx\n",
      			s_h->ush_device.if_type, s_h->ush_device.dev, s_h->ush_device.type, &s_h->ush_device);
		    */
		    
		    AddTail(&dev_list, &s_h->ush_link);
		  }
	    }
	}
    }

  curr_disk = (SCAN_HANDLE)dev_list.mlh_Head;

  if(curr_disk->ush_device.blksz)
    {
      *blocksize = curr_disk->ush_device.blksz;
      //printf("Blocksize for first device is %lu, type %u\n", *blocksize, curr_disk->ush_bustype);
    }
  //printf("Exiting start_unit_scan\n");
  return curr_disk;
}


BOOL open_specific_unit(const SCAN_HANDLE h)
{
  curr_disk = h; //We simply set the current disk to be the one given in.
  /*
  printf("Opening specific unit; data as follows: interface type %d, devnumber %d, type %u\n",
      	curr_disk->ush_device.if_type, curr_disk->ush_device.dev, curr_disk->ush_device.type);
  */
  return TRUE;
}

BOOL old_open_specific_unit(const OLD_SCAN_HANDLE h)
{
  //printf("Old_open_specific unit; real handle to %08lx\n", h->ush_new_reference);
  
  curr_disk = h->ush_device.backpointer; //We simply set the current disk to be the one given in.
  /*
  printf("Opening specific unit; data as follows: interface type %d, devnumber %d, type %u\n",
      	curr_disk->ush_device.if_type, curr_disk->ush_device.dev, curr_disk->ush_device.type);
  */
  return TRUE;
}

void end_unit_scan(SCAN_HANDLE h)
{
  //Nothing: no special resources are opened while scanning
}

void end_global_scan(void)
{
  // Just like a1_end_unit_scan()
}

BOOL loadsector(const ULONG sectn, const ULONG sect_size, const ULONG numb_sects, void * const dest_buf)
{
  block_dev_desc_t * dev = &curr_disk->ush_device;

  //printf("Loadsector: sectornum. %lu, current device %08lx\n", sectn, dev);

  if(sect_size) //Sector size check is only performed when passing a non-zero value
	{
	if(dev->blksz != sect_size)
		{
      //printf("Loadsector: Bad blocksize: current is %lu, supplied is %lu (base structure at %p)\n", dev->blksz, sect_size, &curr_disk);
		return FALSE;
		}
	}

  if(dev->block_read(dev->dev, sectn, numb_sects, dest_buf) != numb_sects)
    {
      printf("Loadsector: error when reading from block %lu\n", sectn);
      return FALSE;
    }
  else return TRUE;
}

void * uboot_4aligned_malloc(const size_t size)
{
  unsigned long temp;

  //printf("Allocating %d bytes, jumping to %08lx\n", size, malloc);
  temp = (unsigned long)malloc(size + 4);
  temp = (temp + 3) & ~3;

//  printf("uboot_4aligned_malloc : asked for memsize %d, returned pointer at %08lx\n", size, (ULONG)temp);
  return (void *)temp;
}

void * alloc_mem_for_iobuffers(const unsigned long size)
{
  return uboot_4aligned_malloc((const size_t)size);
}

void * alloc_mem_for_kickmodule(const unsigned long size)
{
  return uboot_4aligned_malloc((const size_t) size);
}

void * alloc_mem_for_execNG(const unsigned long size)
{
  return uboot_4aligned_malloc((const size_t) size);
}

void * alloc_mem_for_anythingelse(const unsigned long size)
{
  return uboot_4aligned_malloc((const size_t) size);
}

void * alloc_mem_for_bootloader(const unsigned long size)
{
  return uboot_4aligned_malloc((const size_t) size);
}

/*
void * alloc_mem_for_bootloader_ABS(const unsigned long size, void * addr)
{
  return addr; //Yeah, bulldozing anything that comes in the way!
}

//No longer used, since the absolute bulldozing will be done by the ELF loader & relocator.
*/

/*
static int local_get_part_info(int part, disk_partition_t *info)
     //This function will use the file-global curr_disk to get the partition info from uboot
{
  return get_partition_info(curr_disk, part, info);
}
*/

void * get_board_info(void)
{
	DECLARE_GLOBAL_DATA_PTR;
	return (void *)gd->bd;
}

int my_NetLoop(char * fn, void * buff)
{
  //printf("Entering %s\n", __PRETTY_FUNCTION__);
  copy_filename(BootFile, fn, sizeof(BootFile));
  load_addr = (ulong) buff;
  //The cast is necessary because someone was so smart to declare an address
  //as something else than a pointer.

  return NetLoop(TFTP);
}

static void set_load_addr(void * const new_load_addr)
{
load_addr = (ulong)new_load_addr;
}

struct sbl_callback_context * build_callback_context(void * scanopts)
{
  static struct sbl_callback_context context;

  context.ssc_version = CALLBACK_VERSION;
  context.ssc_printf_like = printf;
  context.ssc_getc_like = getc;

  context.ssc_scan_list = scanopts;
  context.ssc_devices_list = &dev_list;
  context.ssc_curr_device = curr_disk;

  context.ssc_start_unit_scan = start_unit_scan;
  context.ssc_next_unit_scan = next_unit_scan;
  context.ssc_open_specific_unit = open_specific_unit;
  context.ssc_end_unit_scan = end_unit_scan;
  context.ssc_end_global_scan = end_global_scan;
  context.ssc_loadsector = loadsector;

  context.ssc_my_netloop = my_NetLoop;

  context.ssc_getenv = getenv;
  context.ssc_setenv = setenv;

  context.ssc_alloc_mem_for_iobuffers =	uboot_4aligned_malloc;
  context.ssc_alloc_mem_for_kickmodule =uboot_4aligned_malloc;
  context.ssc_alloc_mem_for_execNG = 	uboot_4aligned_malloc;
  context.ssc_alloc_mem_for_anythingelse=uboot_4aligned_malloc;
  context.ssc_alloc_mem_for_bootloader =uboot_4aligned_malloc;
  context.ssc_free_mem = free;

  context.ssc_get_board_info = get_board_info;

#ifdef CONFIG_BZIP2
  context.ssc_BZ2_bzBuffToBuffDecompress = BZ2_bzBuffToBuffDecompress;
#endif

  context.ssc_video_clear = video_clear;
  context.ssc_video_draw_box = video_draw_box;
  context.ssc_video_draw_text = video_draw_text;
  context.ssc_video_repeat_char = video_repeat_char;

  context.ssc_set_partial_scroll_limits = set_partial_scroll_limits;
  context.ssc_get_partial_scroll_limits = get_partial_scroll_limits;
  context.ssc_video_get_key = video_get_key;
  
  //printf("Allocation functions pointing at %08lx\n", uboot_4aligned_malloc);

  context.ssc_do_bootm = do_bootm;
  context.ssc_memmove = memmove;

  context.ssc_set_load_addr = set_load_addr;

  context.ssc_tstc = tstc;
  context.ssc_udelay = udelay;
  context.ssc_sprintf = sprintf;

  context.ssc_ext2fs_set_blk_dev_full=ext2fs_set_blk_dev_full;
  context.ssc_ext2fs_open=ext2fs_open;
  context.ssc_ext2fs_read=ext2fs_read;
  context.ssc_ext2fs_mount=ext2fs_mount;
  context.ssc_ext2fs_close=ext2fs_close;
  
  return &context;
}
/*
void degrade_to_old_frigging_interface(struct sbl_callback_context * c)
{
  SCAN_HANDLE actual;
  NewList(&old_dev_list);
  c->ssc_version = 3;
  
  for(actual = (SCAN_HANDLE)c->ssc_devices_list->mlh_Head; actual->ush_link.mln_Succ; actual = (SCAN_HANDLE)actual->ush_link.mln_Succ)
  	{
	OLD_SCAN_HANDLE old_h = alloc_mem_for_anythingelse(sizeof(struct uboot_old_scan_handle));
	
	old_h->ush_bustype = actual->ush_bustype;
	old_h->ush_already_scanned = actual->ush_already_scanned;
	
	old_h->ush_device.if_type	= actual->ush_device.if_type ;
	old_h->ush_device.dev		= actual->ush_device.dev; 
	old_h->ush_device.part_type	= actual->ush_device.part_type;
	old_h->ush_device.target	= actual->ush_device.target;
	old_h->ush_device.lun		= actual->ush_device.lun; 
	old_h->ush_device.type		= actual->ush_device.type;
	old_h->ush_device.lba		= (unsigned long)actual->ush_device.lba;
	old_h->ush_device.blksz		= actual->ush_device.blksz;
	memcpy(&old_h->ush_device.vendor, &actual->ush_device,40);
	memcpy(&old_h->ush_device.product, &actual->ush_device,20);
	memcpy(&old_h->ush_device.revision, &actual->ush_device,4);
        old_h->ush_device.removable	= actual->ush_device.removable;
	old_h->ush_device.block_read	= actual->ush_device.block_read;
	
	old_h->ush_device.backpointer	= actual; //Backpointer used by old_open_specific_unit()
	
	AddTail(&old_dev_list, &old_h->ush_link);
	if(c->ssc_curr_device == actual)
		c->ssc_curr_device = (SCAN_HANDLE)old_h;
	}

  c->ssc_devices_list = &old_dev_list;
  c->ssc_open_specific_unit = old_open_specific_unit;
}
*/
