#include <common.h>
#include <exports.h>

DECLARE_GLOBAL_DATA_PTR;

extern unsigned long __dummy;

int do_updater(void);

void _main(void)
{
    char *version = getenv("ver");
    
    if (!version) 
    {
        printf("\nAttention ! You need first to update U-Boot to version 2010.06.02 !!!\n\n");
        return;
    }
    
    if (strcmp(version,"U-Boot 2010.06.02 (Dec 31 2010 - 11:14:01)") != 0)   
    { 
        printf("\nAttention ! You need first to update U-Boot to version 2010.06.02 !!!\n\n");
        return;
    }
          
    printf("\n------ Sam460ex Hardware Configuration Updater -----\n\n");
        
    printf("****************************************************\n");
	printf("*  ATTENTION!! PLEASE READ THIS NOTICE CAREFULLY!  *\n");
	printf("****************************************************\n\n");
	printf("This program  will update your Sam460  configuration\n");
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

    int ret = do_updater();

    if (ret == 0)
    {
        printf("\nUpdate done. Please remove the cdrom.\n");
        printf("You can switch off/reset now when the cdrom is removed\n\n");

        while (1);
    }
    else
    {
        printf("\nUnable to update the hardware configuration\n");
        printf("Please contact support@acube-systems.com to\n");
        printf("correct the problem\n\n");
    }    
}

int do_updater(void)
{
    int ii;
	unsigned char arr[16] = { 0 };
	unsigned char bkp[16] = { 0 };
	unsigned char upd[8] = { 0x86, 0x86, 0xb5, 0x19, 0xb9, 0x85, 0x00, 0x00 }; 
	bd_t *bd = gd->bd;
    
	// read 16 bytes of the boot eeprom --------------------------------------
	
	puts("Now reading hardware configuration registers...\n");
	i2c_read(0x52, 0x00, 1, &arr, 16);
	for (ii=0;ii<16;ii++)
	    printf ("%02x ",arr[ii]);
	puts("\n\n");
	
	// backup 16 bytes of the boot eeprom ------------------------------------
	
	puts("Now creating backup... ");
	i2c_write(0x53, 0x00, 1, &arr, 16);
	udelay(100000);
	puts("Done\n");
	
	// checking backup -------------------------------------------------------
	
	puts("Checking backup... ");
	i2c_read(0x53, 0x00, 1, &bkp, 16);
	udelay(100000);
	for (ii=0;ii<16;ii++)
	{
	    if (arr[ii] != bkp[ii]) break;
	}    
	
	if (ii < 16)
	{
        puts("\nUnable to create a backup... abort\n");
        return 1;
    }    		
	puts("Done\n");
	
	// change config ---------------------------------------------------------
	
	puts("Writing new config... ");
	i2c_write(0x52, 0x00, 1, &upd, 8);  
	puts("Done\n");
	
	// check new config ------------------------------------------------------
	
	puts("Checking new config... ");
	i2c_read(0x52, 0x00, 1, &bkp, 8);
	udelay(100000);
	for (ii=0;ii<8;ii++)
	{
	    if (upd[ii] != bkp[ii]) break;
	}	
	
	if (ii < 8)
	{
        puts("\nError verifing new config... abort\n");
        return 1;
    }    		
	puts("Done\n");
		
	return 0;   
}
