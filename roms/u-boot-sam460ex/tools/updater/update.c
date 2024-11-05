#include <common.h>
#include <exports.h>
#include "flash_local.h"

extern unsigned long __dummy;
extern flash_info_t  flash_info[]; /* info for FLASH chips */

void do_reset (void);
void do_updater(void);
void flash_print_info(flash_info_t * info);
static ulong flash_get_size(vu_long * addr, flash_info_t * info);

void _main(void)
{
    int i;
    printf("\nU-Boot Firmware Updater\n\n");
    
    printf("****************************************************\n");
	printf("*  ATTENTION!! PLEASE READ THIS NOTICE CAREFULLY!  *\n");
	printf("****************************************************\n\n");
	printf("This program  will update your computer's  firmware.\n");
	printf("Do NOT  remove the disk,  reset the  machine,  or do\n");
	printf("anything that  might disrupt functionality.  If this\n");
    printf("Program fails, your computer  might be unusable, and\n");
	printf("you will  need to return your  board for reflashing.\n");
	printf("If you find this too risky,  remove the diskette and\n");
	printf("switch off your  machine now.  Otherwise  press the \n");
	printf("SPACE key now to start the process\n\n");
	
    do
    {
		char x;
		while (!tstc());
		x = getc();
		if (x == ' ') break;
    } while (1);

    do_updater();

    i = 5;

    printf("\nUpdate done. Please remove the cdrom.\n");
    printf("You can switch off/reset now when the cdrom is removed\n\n");
/*
    printf("The machine will automatically reset in %d seconds\n", i);

    while (i)
    {
		printf("Resetting in %d\r", i);
		udelay(1000000);
		i--;
    }
    do_reset();
*/
    while (1);
}

void do_updater(void)
{
    unsigned long *addr = &__dummy + 65;
    //unsigned long flash_size = flash_init();
    int rc;
    
    flash_get_size(0xfff80000,&flash_info[0]);
    flash_print_info(&flash_info[0]);

    flash_sect_protect(0, 0xFFF80000, 0xFFFFFFFF);

    printf("\nErasing ");
    flash_sect_erase(0xFFF80000, 0xFFFFFFFF);
    printf("Writing ");
    rc = flash_write((uchar *)addr, 0xFFF80000, 0x80000);
    if (rc != 0) printf(" Flashing failed due to error %d\n", rc);
    else printf(" done\n");
    
    flash_sect_protect(1, 0xFFF80000, 0xFFFFFFFF);    
}
